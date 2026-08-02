//! OpenAI-compatible consumer endpoint: the primary unified interface, as in
//! OpenRouter. `POST /v1/chat/completions`(SSE when `stream:true`, otherwise a single JSON) and
//! `GET /v1/models`. The model is forced by the frame; the request's `model` field is not trusted.

use crate::buyer::api::stream::{CanonStreamDriver, CanonStreamNext};
use crate::buyer::api::{
    cap_canon_to_grant, handle_stream_error_policy, ApiDeal, ApiState, ConsumerRequestGuard,
    DeadGatewayAction, DealInitError, RouteBudget, StreamErrorPolicyAction,
};
use crate::buyer::render::{self, OpenAiChatRequest};
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

/// `GET /v1/models`(B19): lists the model id of the buyer's configured frame/market.
pub async fn models(State(state): State<ApiState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "object": "list",
        "data": [{
            "id": state.frame_model,
            "object": "model",
            "owned_by": "dexdo"
        }]
    }))
}

/// `POST /v1/chat/completions`(B19). `stream:true` -> SSE deltas + `[DONE]`; otherwise a single
/// aggregated `chat.completion` JSON.
pub async fn chat_completions(
    State(state): State<ApiState>,
    Json(req): Json<OpenAiChatRequest>,
) -> Response {
    // The model is forced by the market(B2/B19): a request outside the frame -- reject BEFORE opening the stream.
    if let Err(reason) = state.check_model(req.model.as_deref()) {
        return reject(StatusCode::BAD_REQUEST, &reason);
    }
    let deal = match state.current_deal().await {
        Ok(deal) => deal,
        Err(error) => return deal_init_rejection(&error),
    };
    let mut request_guard = deal.begin_request(now_secs());
    // Session-scoped lifecycle: once the local deal is closed (terminal settlement landed or policy
    // recovery is pending) no new request may open a stream on the closed deal.
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
    // one-per-deal content-identity gate(B8 + B7-full), run ONCE before the first paid stream. The inline
    // StreamVerifier below only runs B5/B6 + the cheap declared-NAME B7; a seller declaring the correct model
    // NAME while serving a cheaper model is caught only here. On a bail the gate closes the deal and attempts
    // policy recovery; a transport error is not cached, so a later request retries.
    // this runs AFTER admission and inside the reservation it granted. Verification is paid
    // output on this deal - the seller serves it and claims it like any other - so a request with no
    // quota must not reach it, and the tokens it does consume come out of the same grant as the
    // answer. Anything else lets an exhausted week keep buying probes.
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
    let mut canon = render::openai_to_canon(req);
    // the grant may still hold what verification did not spend. The answer is bounded by what
    // was actually asked for, on the wire and on the way back alike.
    let max_tokens = cap_canon_to_grant(&mut canon, max_tokens);
    let id = completion_id();
    let model = state.frame_model.clone();
    let created = now_secs();
    let reclaim_heartbeat = deal.accepted_output_guard();
    request_guard.arm_upstream_failure();

    // Open an authorized TLS gRPC stream to the(mock) seller with the canonical request(R1).
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

    // Session-scoped: the deal is NOT STOPped at this request's end -- it lives for the next
    // request and is settled once at session end(graceful shutdown) or on a verification-bail. The handler
    // settles the shared session ONLY on a bail(the seller cheated -> end the session, bail off B3/B10).
    if stream {
        sse_response(
            upstream,
            id,
            model,
            created,
            max_tokens,
            deal,
            request_guard,
        )
        .into_response()
    } else {
        aggregate_response(
            upstream,
            id,
            model,
            created,
            max_tokens,
            deal,
            request_guard,
        )
        .await
        .into_response()
    }
}

/// Re-render the canonical stream to OpenAI-SSE(B19, R6): `chat.completion.chunk` deltas ->
/// terminal chunk with `finish_reason` -> `data: [DONE]`. Accounting/verification happen before
/// re-rendering.
fn sse_response(
    upstream: tonic::Streaming<CanonChunk>,
    id: String,
    model: String,
    created: u64,
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
        let mut first = true;
        let mut capped = false;
        let mut stream_error = None;
        loop {
            let chunk = match driver.next().await {
                CanonStreamNext::Chunk(c) => c,
                // upstream transport error -- do NOT pass it off as a clean stop(see finish_reason below).
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
                yield Ok(openai_content_event(&deal, &id, &model, created, &chunk.text, first));
                first = false;
            }
            if reached_cap {
                break; // request/deal token budget reached
            }
        }
        // Session-scoped: completion / max_tokens / upstream-error do NOT STOP -- the deal lives for
        // the next request and is settled once at session end. ONLY a verification-bail ends the session early
        // (the seller cheated -> STOP this deal + bail off, B3/B10). `errored` still drives the finish_reason below.
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
        // the terminal chunk does NOT pass off a bail or an upstream error as a clean `stop` --
        // bail -> `content_filter`, transport error -> `error`, otherwise an honest `stop`.
        let finish_reason = if bailed {
            "content_filter"
        } else if capped && received == 0 {
            // The seller answered; this request's remaining grant could not admit the first chunk.
            "length"
        } else if stream_error.is_some() || received == 0 {
            "error"
        } else {
            "stop"
        };
        yield Ok(Event::default().data(render::openai_final_chunk(&id, &model, created, finish_reason)));
        yield Ok(Event::default().data("[DONE]"));
    };
    Sse::new(sse)
}

fn openai_content_event(
    deal: &ApiDeal,
    id: &str,
    model: &str,
    created: u64,
    text: &str,
    first: bool,
) -> Event {
    deal.record_accepted_output(now_secs());
    Event::default().data(render::openai_delta_chunk(id, model, created, text, first))
}

#[cfg(test)]
pub(super) fn heartbeat_poll_test_stream(deal: ApiDeal) -> impl Stream<Item = Event> {
    async_stream::stream! {
        yield openai_content_event(&deal, "id", "model", 1, "content", true);
    }
}

/// Non-streaming(B19): collect the entire canonical stream into a single `chat.completion`.
async fn aggregate_response(
    upstream: tonic::Streaming<CanonChunk>,
    id: String,
    model: String,
    created: u64,
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
    // Session-scoped: a clean completion / max_tokens does NOT STOP -- the deal lives for the next
    // request. ONLY a verification-bail ends the session early(STOP + bail off, B3/B10).
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
    // verification bail -> `content_filter`, so the consumer can tell an aborted response apart.
    let finish_reason = if bailed {
        "content_filter"
    } else if capped && received == 0 {
        "length"
    } else {
        "stop"
    };
    let body = render::openai_completion(&id, &model, created, &content, finish_reason);
    ([(http::header::CONTENT_TYPE, "application/json")], body).into_response()
}

fn reject(status: StatusCode, message: &str) -> Response {
    let body =
        serde_json::json!({ "error": { "message": message, "type": "invalid_request_error" } });
    (status, Json(body)).into_response()
}

fn deal_init_rejection(error: &DealInitError) -> Response {
    let mut body = serde_json::json!({
        "error": {
            "message": error.message(),
            "type": "invalid_request_error"
        }
    });
    if let Some(reconciliation) = error.reconciliation() {
        body["error"]["submit_reconciliation"] = serde_json::json!(reconciliation);
    }
    (deal_init_error_status(error.message()), Json(body)).into_response()
}

fn deal_init_error_status(reason: &str) -> StatusCode {
    if reason.to_ascii_lowercase().contains("invalid buy ticks") {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn completion_id() -> String {
    format!("chatcmpl-dexdo-{}", now_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_on_demand_buy_ticks_are_bad_request() {
        assert_eq!(
            deal_init_error_status(
                "invalid buy ticks: --ticks 1 is below the 2-tick stream minimum"
            ),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            deal_init_error_status("on-demand purchase timed out before a deal became ready"),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
