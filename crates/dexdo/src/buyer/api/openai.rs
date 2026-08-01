//! OpenAI-compatible consumer endpoint: the primary unified interface, as in
//! OpenRouter. `POST /v1/chat/completions`(SSE when `stream:true`, otherwise a single JSON) and
//! `GET /v1/models`. The model is forced by the frame; the request's `model` field is not trusted.

use crate::buyer::api::stream::{CanonStreamDriver, CanonStreamNext};
use crate::buyer::api::{
    handle_stream_error_policy, request_token_limit, ApiDeal, ApiState, ConsumerRequestGuard,
    DeadGatewayAction, DealInitError, StreamErrorPolicyAction,
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
    if deal.remaining_tokens() == 0 {
        return reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "active deal budget exhausted; waiting for renewal handover",
        );
    }
    if let Err(reason) = deal.session.ensure_open_for_serving().await {
        return reject(StatusCode::BAD_GATEWAY, &reason);
    }
    // one-per-deal content-identity gate(B8 + B7-full), run ONCE before the first paid stream. The inline
    // StreamVerifier below only runs B5/B6 + the cheap declared-NAME B7; a seller declaring the correct model
    // NAME while serving a cheaper model is caught only here. On a bail the gate closes the deal and attempts
    // policy recovery; a transport error is not cached, so a later request retries.
    if let Err(reason) = deal
        .content_gate
        .ensure_verified(&state.buyer, &deal.route, &deal.session)
        .await
    {
        return reject(
            StatusCode::BAD_GATEWAY,
            &format!("model identity verification failed (content check): {reason}"),
        );
    }

    let stream = req.stream;
    let requested_max_tokens = req.max_tokens;
    let canon = render::openai_to_canon(req);
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

    let max_tokens = request_token_limit(requested_max_tokens, deal.remaining_tokens());
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
            if !chunk.text.is_empty() {
                yield Ok(openai_content_event(&deal, &id, &model, created, &chunk.text, first));
                first = false;
            }
            let before = driver.received();
            if driver.account_rendered(&chunk) {
                deal.record_delivered(driver.received().saturating_sub(before));
                break; // request/deal token budget reached
            }
            deal.record_delivered(driver.received().saturating_sub(before));
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
        } else if received == 0 {
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
        content.push_str(&chunk.text);
        if driver.account_rendered(&chunk) {
            break;
        }
    }
    // Session-scoped: a clean completion / max_tokens does NOT STOP -- the deal lives for the next
    // request. ONLY a verification-bail ends the session early(STOP + bail off, B3/B10).
    let bailed = driver.bailed();
    let received = driver.received();
    drop(driver);
    deal.record_delivered(received);
    if bailed {
        deal.session.settle_verification_bail("verify-bail").await;
    } else if let Some(e) = stream_error {
        if handle_stream_error_policy(&deal, received, &e).await
            == StreamErrorPolicyAction::RequestScoped
        {
            request_guard.complete();
        }
        return reject(StatusCode::BAD_GATEWAY, &format!("stream error: {e}"));
    } else if received == 0 {
        let heartbeat = deal.accepted_output_guard();
        deal.session
            .settle_empty_stream("empty-stream", &heartbeat)
            .await;
        return reject(StatusCode::BAD_GATEWAY, "upstream produced an empty stream");
    }
    request_guard.complete();
    // verification bail -> `content_filter`, so the consumer can tell an aborted response apart.
    let finish_reason = if bailed { "content_filter" } else { "stop" };
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
