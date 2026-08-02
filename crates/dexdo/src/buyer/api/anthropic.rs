//! Optional Anthropic-compatible endpoint: `POST /v1/messages`,
//! a **local transcode** to the same `CanonRequest`(OpenAI shape) and back `CanonChunk` ->
//! Anthropic-SSE, for Anthropic-native clients. The transcode is off-chain, on the
//! buyer side: the wire(gRPC) and the canonical format are not touched.

use crate::buyer::api::stream::{CanonStreamDriver, CanonStreamNext};
use crate::buyer::api::{
    cap_canon_to_grant, handle_stream_error_policy, ApiDeal, ApiState, ConsumerRequestGuard,
    DeadGatewayAction, DealInitError, RouteBudget, StreamErrorPolicyAction,
};
use crate::buyer::render::{self, AnthropicRequest};
use axum::extract::State;
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use dexdo_core::params::BUYER_UPSTREAM_OPEN_RETRIES;
use dexdo_proto::CanonChunk;
use futures::Stream;
use http::StatusCode;
use std::convert::Infallible;
use std::time::{SystemTime, UNIX_EPOCH};

/// `POST /v1/messages`(B20). Transcodes the request -> `CanonRequest`, opens the same
/// authorized TLS gRPC stream and re-renders `CanonChunk` into Anthropic-SSE
/// (`message_start` -> `content_block_*` -> `message_delta` -> `message_stop`).
pub async fn messages(
    State(state): State<ApiState>,
    Json(req): Json<AnthropicRequest>,
) -> Response {
    // The model is forced by the market(B2/B19) -- the same check as for the OpenAI path.
    if let Err(reason) = state.check_model(req.model.as_deref()) {
        return reject(StatusCode::BAD_REQUEST, &reason);
    }
    let deal = match state.current_deal().await {
        Ok(deal) => deal,
        Err(error) => return deal_init_rejection(&error),
    };
    let mut request_guard = deal.begin_request(message_started_secs());
    // Session-scoped lifecycle: no new request once the local deal is closed.
    if deal.session.is_closed() {
        return reject(StatusCode::GONE, "deal session closed; open a new session");
    }
    if let Err(reason) = deal.session.ensure_open_for_serving().await {
        return reject(StatusCode::BAD_GATEWAY, &reason);
    }
    let stream = req.stream;
    let requested_max_tokens = req.max_tokens;
    // admission RESERVES this request's output cap out of the route's remaining tokens before
    // the model is contacted, so two concurrent requests can never be handed the same remainder. For a
    // subscription it first books any due week boundary through the permissionless path and recomputes
    // from the coherent state that comes back -- an under-used week is never carried across it, and a
    // finished term is never served from a stale positive remainder.
    match deal.admit(requested_max_tokens).await {
        RouteBudget::Admitted(reservation) => {
            request_guard.hold(reservation);
        }
        RouteBudget::Exhausted(reason) => return reject(StatusCode::SERVICE_UNAVAILABLE, &reason),
    }
    // one-per-deal content-identity gate(B8 + B7-full), run ONCE before the first paid stream -- the same
    // gate as the OpenAI path. The inline StreamVerifier only runs B5/B6 + the cheap declared-NAME B7; a seller
    // serving a cheaper model under the correct NAME is caught only here. On a bail the gate closes the deal and
    // attempts policy recovery; a transport error is not cached, so a later request retries.
    // this runs AFTER admission and inside the reservation it granted - verification is paid
    // output on this deal, so an exhausted week must not reach it and what it consumes comes out of
    // the same grant as the answer.
    let verdict = deal
        .content_gate
        .ensure_verified(&state.buyer, &deal, &mut request_guard)
        .await;
    if let Err(reason) = verdict {
        return reject(
            StatusCode::BAD_GATEWAY,
            &format!("model identity verification failed (content check): {reason}"),
        );
    }
    let max_tokens = request_guard.remaining_grant();
    if max_tokens == 0 {
        return reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "the identity verification this deal owed consumed the whole admitted grant; the \
             request was not sent and the next one starts from a verified deal",
        );
    }
    let mut canon = render::anthropic_to_canon(req);
    // the grant may still hold what verification did not spend. The answer is bounded by what
    // was actually asked for, on the wire and on the way back alike.
    let max_tokens = cap_canon_to_grant(&mut canon, max_tokens);
    let id = message_id();
    let model = state.frame_model.clone();
    let reclaim_heartbeat = deal.accepted_output_guard();
    request_guard.arm_upstream_failure();

    let retry_limit = if deal.session.dead_gateway_action() == DeadGatewayAction::RetryThenReclaim {
        BUYER_UPSTREAM_OPEN_RETRIES
    } else {
        0
    };
    let mut retries = 0usize;
    let upstream = loop {
        match state
            .buyer
            .open_canon_stream(
                &deal.route.handover,
                &deal.route.token_contract,
                canon.clone(),
            )
            .await
        {
            Ok(stream) => break Ok(stream),
            Err(error) if retries < retry_limit => {
                retries += 1;
                tracing::warn!(
                    error = %error,
                    token_contract = %deal.route.token_contract,
                    "consumer API: upstream open failed; retrying once per dead_gateway=retry_then_reclaim"
                );
            }
            Err(error) => break Err(error),
        }
    };
    let upstream = match upstream {
        Ok(stream) => stream,
        Err(error) => {
            deal.session
                .settle_dead_gateway("dead-gateway", &reclaim_heartbeat)
                .await;
            let reason = if retries == 0 {
                format!("upstream open failed: {error}")
            } else if retries == 1 {
                format!("upstream open failed after retry: {error}")
            } else {
                format!("upstream open failed after {retries} retries: {error}")
            };
            return reject(StatusCode::BAD_GATEWAY, &reason);
        }
    };

    // Session-scoped: no per-request STOP -- the shared session settles once at session end / on a
    // verification-bail(as in the OpenAI path).
    if stream {
        sse_response(upstream, id, model, max_tokens, deal, request_guard).into_response()
    } else {
        aggregate_response(upstream, id, model, max_tokens, deal, request_guard)
            .await
            .into_response()
    }
}

/// Re-render the canonical stream to Anthropic-SSE(B20, R6). Accounting/verification happen before re-rendering.
fn sse_response(
    upstream: tonic::Streaming<CanonChunk>,
    id: String,
    model: String,
    max_tokens: u64,
    deal: ApiDeal,
    mut request_guard: ConsumerRequestGuard,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let sse = async_stream::stream! {
        let mut driver = CanonStreamDriver::new(
            upstream,
            deal.session.closed_receiver(),
            model.clone(),
            max_tokens,
        );
        let mut capped = false;
        let mut stream_error = None;
        yield Ok(event(render::anthropic_message_start(&id, &model)));
        yield Ok(event(render::anthropic_content_block_start()));
        loop {
            let chunk = match driver.next().await {
                CanonStreamNext::Chunk(c) => c,
                // upstream transport error -- do not pass it off as a clean `end_turn`.
                CanonStreamNext::Errored(e) => {
                    stream_error = Some(e);
                    break;
                }
                CanonStreamNext::Bailed | CanonStreamNext::End => break,
            };
            // the grant is a HARD cap. A chunk that does not fit inside what is left of it
            // is never rendered - the consumer may not be shown tokens no reservation covers.
            // Stopping here is the REQUEST hitting its own cap, not the seller failing.
            if !driver.admits(&chunk) {
                capped = true;
                break;
            }
            // account BEFORE the bytes leave. A consumer that disconnects immediately after
            // an event drops this request's guard, and a reservation released after exposure hands
            // back quota for output the seller has already served. Nothing is exposed before it is
            // paid for - the same rule as the chunk cap above, on the abnormal path too.
            let before = driver.received();
            let reached_cap = driver.account_rendered(&chunk);
            if let Err(error) =
                request_guard.record_delivered(&deal, driver.received().saturating_sub(before))
            {
                stream_error = Some(error);
                break;
            }
            if !chunk.text.is_empty() {
                yield Ok(anthropic_content_event(&deal, &chunk.text));
            }
            if reached_cap {
                break; // request/deal token budget reached
            }
        }
        // Session-scoped: completion / max_tokens / upstream-error do NOT STOP -- only a
        // verification-bail ends the session early(STOP + bail off). `errored` still drives stop_reason below.
        let bailed = driver.bailed();
        let received = driver.received();
        drop(driver);
        if bailed {
            deal.session.settle_verification_bail("verify-bail").await;
        } else if let Some(e) = &stream_error {
            if handle_stream_error_policy(&deal, received, e).await
                == StreamErrorPolicyAction::RequestScoped
            {
                request_guard.complete();
            }
        } else if received == 0 && !capped {
            let heartbeat = deal.accepted_output_guard();
            deal.session
                .settle_empty_stream("empty-stream", &heartbeat)
                .await;
        } else {
            request_guard.complete();
        }
        // stop_reason does NOT pass off a bail/error as an honest `end_turn` -- bail -> `refusal`,
        // transport error -> `error`, otherwise `end_turn`.
        let stop_reason = if bailed {
            "refusal"
        } else if capped && received == 0 {
            // The seller answered; this request's remaining grant could not admit the first chunk.
            "max_tokens"
        } else if stream_error.is_some() || received == 0 {
            "error"
        } else {
            "end_turn"
        };
        yield Ok(event(render::anthropic_content_block_stop()));
        yield Ok(event(render::anthropic_message_delta(stop_reason)));
        yield Ok(event(render::anthropic_message_stop()));
    };
    Sse::new(sse)
}

fn anthropic_content_event(deal: &ApiDeal, text: &str) -> Event {
    deal.record_accepted_output(message_started_secs());
    event(render::anthropic_content_block_delta(text))
}

#[cfg(test)]
pub(super) fn heartbeat_poll_test_stream(deal: ApiDeal) -> impl Stream<Item = Event> {
    async_stream::stream! {
        yield anthropic_content_event(&deal, "content");
    }
}

/// Build an axum SSE `Event` from `(name, JSON data)`(B20). A single source of truth for the
/// frame -- the HTTP layer adds `event:`/`data:`.
fn event((name, data): render::AnthropicEvent) -> Event {
    Event::default().event(name).data(data)
}

/// Non-streaming Anthropic response(B20): a single `message` JSON with aggregated text.
async fn aggregate_response(
    upstream: tonic::Streaming<CanonChunk>,
    id: String,
    model: String,
    max_tokens: u64,
    deal: ApiDeal,
    mut request_guard: ConsumerRequestGuard,
) -> Response {
    let mut content = String::new();
    let mut capped = false;
    let mut driver = CanonStreamDriver::new(
        upstream,
        deal.session.closed_receiver(),
        model.clone(),
        max_tokens,
    );
    let mut stream_error = None;
    loop {
        let chunk = match driver.next().await {
            CanonStreamNext::Chunk(c) => c,
            CanonStreamNext::Errored(e) => {
                stream_error = Some(e);
                break;
            }
            CanonStreamNext::Bailed | CanonStreamNext::End => break,
        };
        // the grant is a HARD cap. A chunk that does not fit inside what is left of it
        // is never rendered - the consumer may not be shown tokens no reservation covers.
        // Stopping here is the REQUEST hitting its own cap, not the seller failing: it must not be
        // mistaken for an empty stream, which is a settlement action against the counterparty.
        if !driver.admits(&chunk) {
            capped = true;
            break;
        }
        // account BEFORE the text joins the answer. The seller has served these tokens
        // whether or not this request ever returns them, so a dropped future must not release the
        // reservation that covers them.
        let before = driver.received();
        let reached_cap = driver.account_rendered(&chunk);
        if let Err(error) =
            request_guard.record_delivered(&deal, driver.received().saturating_sub(before))
        {
            stream_error = Some(error);
            break;
        }
        content.push_str(&chunk.text);
        if reached_cap {
            break;
        }
    }
    // Session-scoped: a clean completion / max_tokens does NOT STOP -- only a verification-bail ends
    // the session early(STOP + bail off).
    let bailed = driver.bailed();
    let received = driver.received();
    drop(driver);
    if bailed {
        deal.session.settle_verification_bail("verify-bail").await;
    } else if let Some(e) = stream_error {
        if handle_stream_error_policy(&deal, received, &e).await
            == StreamErrorPolicyAction::RequestScoped
        {
            request_guard.complete();
        }
        return reject(StatusCode::BAD_GATEWAY, &format!("stream error: {e}"));
    } else if received == 0 && !capped {
        let heartbeat = deal.accepted_output_guard();
        deal.session
            .settle_empty_stream("empty-stream", &heartbeat)
            .await;
        return reject(StatusCode::BAD_GATEWAY, "upstream produced an empty stream");
    }
    request_guard.complete();
    // verification bail -> `refusal`(distinguishable from an honest `end_turn`).
    let stop_reason = if bailed {
        "refusal"
    } else if capped && received == 0 {
        "max_tokens"
    } else {
        "end_turn"
    };
    let body = serde_json::json!({
        "id": id,
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{ "type": "text", "text": content }],
        "stop_reason": stop_reason,
        "stop_sequence": null
    });
    (
        [(http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&body).unwrap(),
    )
        .into_response()
}

fn reject(status: StatusCode, message: &str) -> Response {
    let body = serde_json::json!({ "type": "error", "error": { "type": "invalid_request_error", "message": message } });
    (status, Json(body)).into_response()
}

fn deal_init_rejection(error: &DealInitError) -> Response {
    let mut body = serde_json::json!({
        "type": "error",
        "error": {
            "type": "invalid_request_error",
            "message": error.message()
        }
    });
    if let Some(reconciliation) = error.reconciliation() {
        body["error"]["submit_reconciliation"] = serde_json::json!(reconciliation);
    }
    (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
}

fn message_id() -> String {
    let n = message_started_secs();
    format!("msg-dexdo-{n}")
}

fn message_started_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
