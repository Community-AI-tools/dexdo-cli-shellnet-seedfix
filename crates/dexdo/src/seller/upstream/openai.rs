//! Real OpenAI-compatible upstream.
//! The gateway connects to an OpenAI-compatible API(by default **Groq**, `qwen/qwen3-32b`),
//! sends the buyer's canonical request(R1), reads the **streaming SSE** and normalizes each
//! delta into a `CanonChunk` incrementally(R6). Monetary accounting is exactly one token per returned
//! logprob record; aggregate final usage and SSE event boundaries never authorize forwarding.
//! The key is taken **from the environment at runtime**([`api_key`]) and is never stored/logged
//! . Without a key the adapter does not start -- the stream
//! closes with `Status::failed_precondition`, which yields a clean skip in e2e.

use super::{
    annotate_seller_config_fault, chunk_with_structured_accounting, resolve_model_output_cap,
    UpstreamEvent,
};
use crate::seller::models::{Capabilities, ModelConfig};
use dexdo_core::params::{
    UPSTREAM_ERROR_BODY_MAX_BYTES, UPSTREAM_ERROR_DETAIL_MAX_BYTES,
    UPSTREAM_ERROR_ECHO_PREFIX_CHARS, UPSTREAM_SSE_FRAME_MAX_BYTES,
};
use dexdo_proto::{CanonChunk, CanonRequest, SignalManifest, TokenLogprobs, TopLogprob};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tonic::Status;

/// Name of the env variable holding the upstream key(Groq OpenAI-compatible API). Creds come from "seahorse".
pub const API_KEY_ENV: &str = "GROQ_API_KEY";

/// Default base of the Groq OpenAI-compatible API.
pub const DEFAULT_BASE_URL: &str = "https://api.groq.com/openai/v1";

/// Default model id -- Qwen 32B on Groq(canonical id from the Groq model list).
pub const DEFAULT_MODEL: &str = "qwen/qwen3-32b";

/// Maximum output length of the built-in demo default([`DEFAULT_MODEL`] on Groq), measured against the live
/// provider: `max_tokens=40960` -> HTTP 200, `max_tokens=40961` -> HTTP 400
/// `` `max_tokens` must be less than or equal to `40960` ``. Only the built-in default carries it;
/// every configured model declares its own `capabilities.max_output_tokens`.
pub const DEFAULT_MAX_OUTPUT_TOKENS: u32 = 40_960;

/// Real upstream configuration. Carries **only** non-confidential parameters (URL/model id/
/// env-key name/tokenizer family/capabilities). The key itself is NOT stored here -- it is read from
/// the environment at request time via [`OpenAiConfig::api_key_env`]. Operationally built from a
/// model config entry; `Default` is the built-in demo default
/// (Groq/qwen) for tests and `live_groq`.
#[derive(Clone, Debug)]
pub struct OpenAiConfig {
    /// Base URL of the OpenAI-compatible API(without the trailing `/chat/completions`).
    pub base_url: String,
    /// Upstream model id(`served_model`; forced by the market R1, the buyer's `model` is not trusted).
    /// Sent to the upstream(Groq); an internal detail, NOT the on-wire declared model.
    pub model: String,
    /// **Canonical market id**(`producer--model--version`, e.g. `qwen--qwen3--32b`) -- the protocol-facing model
    /// identity the buyer paid for(B2) and verifies the declaration against. Declared as
    /// `claimed_model`. It is DISTINCT from [`Self::model`](the upstream slug like `qwen/qwen3-32b`): the buyer's
    /// frame is canonical, so declaring the served slug here would false-trip the substitution check.
    pub frame_model: String,
    /// **Test-only seam:** declare a DIFFERENT `claimed_model` in the
    /// `SignalManifest` while the real upstream still serves [`Self::model`]. `None` (default / production path,
    /// [`Self::from_model`]) -> `claimed_model == frame_model`(honest declaration of the canonical market id).
    /// `Some(name)` -> emit `name` as the declared model while serving `model` -- reproduces a served!=declared
    /// substitution so the buyer's content gate(B8 + B7-full) can be proven against a REAL divergent upstream.
    pub claimed_model_override: Option<String>,
    /// Name of the env variable holding the key -- **per-model/provider**, not a single global one.
    pub api_key_env: String,
    /// Tokenizer family for `SignalManifest` -- from config, not a substring hardcode.
    pub tokenizer_family: String,
    /// Upstream capabilities.
    pub capabilities: Capabilities,
}

impl Default for OpenAiConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            model: DEFAULT_MODEL.to_string(),
            frame_model: DEFAULT_MODEL.to_string(),
            claimed_model_override: None,
            api_key_env: API_KEY_ENV.to_string(),
            tokenizer_family: "qwen".to_string(),
            capabilities: Capabilities {
                logprobs: true,
                top_logprobs: Some(5),
                max_output_tokens: Some(DEFAULT_MAX_OUTPUT_TOKENS),
            },
        }
    }
}

impl OpenAiConfig {
    /// Build from a model config entry -- the operational CLI path(`--model`).
    pub fn from_model(m: &ModelConfig, registry_frame_model: Option<&str>) -> Self {
        Self {
            base_url: m.base_url.clone(),
            model: m.served_model.clone(),
            // The on-wire declared model is the CANONICAL frame(what the buyer paid for / verifies against),
            // not the upstream served slug -- else the buyer's check false-trips a substitution.
            frame_model: registry_frame_model.unwrap_or(&m.frame_model).to_string(),
            // Production path: honest declaration(`claimed_model == frame_model`). The override is test-only.
            claimed_model_override: None,
            api_key_env: m.api_key_env.clone(),
            tokenizer_family: m.tokenizer_family.clone(),
            capabilities: m.capabilities.clone(),
        }
    }
}

/// Read the upstream key from the environment(runtime) by the **env-variable name from the model config**
/// . `None` means no key(the live path is unavailable). The value is never
/// logged and never persisted to disk.
pub fn api_key(env_name: &str) -> Option<String> {
    std::env::var(env_name).ok().filter(|k| !k.is_empty())
}

// --- Request/response shape of OpenAI-compatible chat-completions(subset for the adapter) ---

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<WireMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    /// Always sent and always bounded: `min(buyer request, deal budget, model output cap)`.
    /// Never optional -- an absent/unbounded generation limit is exactly what the provider rejects.
    max_tokens: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    stop: Vec<String>,
    // R2 +: logprobs are requested ONLY if the model supports them
    // . Otherwise the field is NOT sent(`None` -> skip): strict
    // OpenAI-compatible endpoints answer `400` on an unsupported field and drop the stream. Default is off.
    #[serde(skip_serializing_if = "Option::is_none")]
    logprobs: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_logprobs: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning: Option<ReasoningRequest>,
}

#[derive(Serialize)]
struct ReasoningRequest {
    enabled: bool,
    exclude: bool,
}

#[derive(Serialize)]
struct WireMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct StreamChunk {
    #[serde(default)]
    choices: Vec<StreamChoice>,
}

#[derive(Deserialize)]
struct StreamChoice {
    #[serde(default)]
    delta: Delta,
    // Delta logprobs(OpenAI/Groq format): `content[]` with the chosen token + top-k alternatives.
    #[serde(default)]
    logprobs: Option<ChoiceLogprobs>,
}

#[derive(Deserialize, Default)]
struct Delta {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    reasoning: Option<String>,
    #[serde(default)]
    reasoning_content: Option<String>,
    #[serde(default)]
    reasoning_details: Option<Vec<ReasoningDetailWire>>,
}

#[derive(Deserialize, Default)]
struct ReasoningDetailWire {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    summary: Option<String>,
}

#[derive(Deserialize, Default)]
struct ChoiceLogprobs {
    #[serde(default)]
    content: Vec<ContentLogprob>,
}

#[derive(Deserialize)]
struct ContentLogprob {
    logprob: f64,
    #[serde(default)]
    top_logprobs: Vec<TopLogprobWire>,
}

#[derive(Deserialize)]
struct TopLogprobWire {
    #[serde(default)]
    token: String,
    logprob: f64,
}

/// Build the upstream request body from the buyer's canonical request (R1: normalizing the
/// request into the upstream format). `model` is forced by the market from configuration -- the buyer's `model`
/// is absent from `CanonRequest` by design.
/// `model_output_cap` is the model's own maximum output length, already resolved fail-closed by the caller
/// ([`resolve_model_output_cap`]); the outbound generation limit is the minimum of all three bounds.
fn build_request<'a>(
    cfg: &'a OpenAiConfig,
    req: &CanonRequest,
    count: u64,
    model_output_cap: u32,
) -> ChatRequest<'a> {
    let messages = req
        .messages
        .iter()
        .map(|m| WireMessage {
            role: m.role.clone(),
            content: m.content.clone(),
        })
        .collect();
    let (temperature, requested_max_tokens, stop, seed) = match &req.params {
        Some(p) => (
            // `greedy`(B7 spot-check) forcibly sets temp=0(distinct from 0="not set").
            if p.greedy {
                Some(0.0)
            } else {
                (p.temperature != 0.0).then_some(p.temperature)
            },
            (p.max_tokens != 0).then_some(p.max_tokens),
            p.stop.clone(),
            // Groq exposes a random seed even at temperature=0 for some models(notably gpt-oss). Pin the
            // sampled B7 greedy probe so the seller stream and the reference endpoint compare the same run.
            p.greedy.then_some(0),
        ),
        None => (None, None, Vec::new(), None),
    };
    // the outbound limit is bounded by ALL THREE of the buyer's request, the deal budget and the
    // model's own output cap. A missing buyer value is not "unbounded"(it used to become `u32::MAX`) and a
    // deal budget is `ticks * TICK_SIZE` tokens, so without the model cap every provider answered `400`.
    let deal_max_tokens = u32::try_from(count).unwrap_or(u32::MAX);
    let max_tokens = requested_max_tokens
        .unwrap_or(u32::MAX)
        .min(deal_max_tokens)
        .min(model_output_cap)
        .max(1);
    // request logprobs only if the model config declared support(capability-aware) --
    // otherwise don't send the field at all(a strict endpoint must not fail with `400`). Don't fabricate(R3/R4):
    // absence of logprobs -> lower verification weight at the buyer, not invented values.
    let (logprobs, top_logprobs) = if cfg.capabilities.logprobs {
        (Some(true), cfg.capabilities.top_logprobs)
    } else {
        (None, None)
    };
    ChatRequest {
        model: &cfg.model,
        messages,
        stream: true,
        temperature,
        max_tokens,
        stop,
        logprobs,
        top_logprobs,
        seed,
        reasoning: openrouter_qwen_reasoning(cfg).then_some(ReasoningRequest {
            enabled: true,
            exclude: false,
        }),
    }
}

fn openrouter_qwen_reasoning(cfg: &OpenAiConfig) -> bool {
    cfg.base_url.to_ascii_lowercase().contains("openrouter.ai")
        && cfg.model.eq_ignore_ascii_case("qwen/qwen3-32b")
}

/// Run the real upstream: POST `.../chat/completions` with `stream:true`, parse the SSE and
/// normalize deltas into `CanonChunk`, yielding incrementally into `tx`(R6). No more than `count`
/// delivered tokens are requested/forwarded. A canonical request is mandatory
/// . On a missing key/error we
/// close the stream with an error status(the response buffer does not accumulate).
pub async fn run(
    cfg: &OpenAiConfig,
    count: u64,
    req: Option<CanonRequest>,
    tx: mpsc::Sender<Result<UpstreamEvent, Status>>,
) {
    if count == 0 {
        return;
    }
    if !cfg.capabilities.logprobs {
        let _ = tx
            .send(Err(Status::failed_precondition(
                "OpenAI-compatible monetized serving requires authoritative per-token logprobs",
            )))
            .await;
        return;
    }
    // resolve the model's own output cap FIRST -- an unknown cap must fail closed here, before any
    // provider connection, instead of sending an unbounded `max_tokens` and collecting a `400`.
    let model_output_cap = match resolve_model_output_cap(
        cfg.capabilities.max_output_tokens,
        &cfg.frame_model,
        &cfg.model,
    ) {
        Ok(cap) => cap,
        Err(status) => {
            let _ = tx.send(Err(status)).await;
            return;
        }
    };
    let Some(key) = api_key(&cfg.api_key_env) else {
        let _ = tx
            .send(Err(Status::failed_precondition(format!(
                "real upstream key absent ({})",
                cfg.api_key_env
            ))))
            .await;
        return;
    };
    let Some(req) = req else {
        let _ = tx
            .send(Err(Status::invalid_argument(
                "real upstream requires a canonical request",
            )))
            .await;
        return;
    };

    if let Err(status) = stream_upstream(cfg, &key, count, &req, &tx, model_output_cap).await {
        // Send the error into the channel(if the buyer is still listening) -- without leaking the key into the text.
        let _ = tx.send(Err(status)).await;
    }
}

/// Internal stream loop: connect, parse SSE, normalize. Errors are returned as `Status`
/// without confidential data. The `Authorization` header carries the key only at runtime.
async fn stream_upstream(
    cfg: &OpenAiConfig,
    key: &str,
    count: u64,
    req: &CanonRequest,
    tx: &mpsc::Sender<Result<UpstreamEvent, Status>>,
    model_output_cap: u32,
) -> Result<(), Status> {
    use futures::StreamExt;

    let url = format!("{}/chat/completions", cfg.base_url.trim_end_matches('/'));
    let body = build_request(cfg, req, count, model_output_cap);

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .bearer_auth(key)
        .json(&body)
        .send()
        .await
        .map_err(|e| Status::unavailable(format!("upstream connect failed: {e}")))?;

    if !resp.status().is_success() {
        // A `4xx` here rejects a request the SELLER built end to end, so name the served model and the exact
        // generation limit that was sent instead of relaying an opaque provider line to the buyer.
        let http_status = resp.status().as_u16();
        let sent_max_tokens = body.max_tokens;
        return Err(annotate_seller_config_fault(
            upstream_http_error(resp, key, req).await,
            http_status,
            &cfg.model,
            sent_max_tokens,
            model_output_cap,
        ));
    }

    // Incremental SSE parsing over the body's byte stream(R6): accumulate a buffer, split on
    // `\n\n` boundaries, parse `data:` lines. `data: [DONE]` ends the stream.
    let mut byte_stream = resp.bytes_stream();
    let mut buf = String::new();
    let mut seq: u64 = 0;
    let mut sent_tokens: u64 = 0;

    let saw_done = 'provider_stream: loop {
        let Some(item) = byte_stream.next().await else {
            break false;
        };
        let bytes = item.map_err(|e| Status::unavailable(format!("upstream read failed: {e}")))?;
        buf.push_str(&String::from_utf8_lossy(&bytes));

        // Flush complete SSE events(separated by `\n\n`); an unfinished frame must not grow
        // the gateway buffer without bound -- a hostile/broken upstream is untrusted(Y3, R6).
        for event in drain_complete_events(&mut buf)? {
            match parse_event(&event)? {
                ParsedEvent::Done => break 'provider_stream true,
                ParsedEvent::Delta {
                    text,
                    reasoning,
                    logprobs,
                } if !text.is_empty() || !reasoning.is_empty() => {
                    if logprobs.is_empty() {
                        return Err(Status::data_loss(
                            "OpenAI-compatible output delta omitted authoritative token logprobs",
                        ));
                    }
                    let delivered_tokens = u64::try_from(logprobs.len())
                        .map_err(|_| Status::data_loss("logprob count does not fit u64"))?;
                    let next_sent_tokens = sent_tokens
                        .checked_add(delivered_tokens)
                        .ok_or_else(|| Status::data_loss("OpenAI token usage overflow"))?;
                    if next_sent_tokens > count {
                        return Err(Status::data_loss(
                            "OpenAI token usage exceeds the requested token limit",
                        ));
                    }
                    let chunk = CanonChunk {
                        text,
                        reasoning,
                        // R2/R4: Groq chat-completions does not return token-ids in SSE -- do NOT fabricate.
                        token_ids: Vec::new(),
                        seq,
                        // R2: delta logprobs(chosen + top-k) -- normalized without loss.
                        logprobs,
                        manifest: (seq == 0).then(|| SignalManifest {
                            // Family comes from the model config; the buyer matches the profile.
                            tokenizer_family: cfg.tokenizer_family.clone(),
                            has_token_ids: false,
                            has_logprobs: true,
                            // Declare the CANONICAL frame model(what the buyer paid for / verifies, B2/B7), NOT
                            // the upstream served slug -- declaring the slug false-trips. The test-only
                            // override emits a different declared name to prove a real substitution.
                            claimed_model: cfg
                                .claimed_model_override
                                .clone()
                                .unwrap_or_else(|| cfg.frame_model.clone()),
                        }),
                    };
                    seq += 1;
                    let event = chunk_with_structured_accounting(chunk)?;
                    if tx.send(Ok(event)).await.is_err() {
                        return Ok(()); // buyer disconnected(STOP)
                    }
                    sent_tokens = next_sent_tokens;
                    if sent_tokens >= count {
                        return Ok(()); // budget exhausted
                    }
                }
                ParsedEvent::Delta {
                    text,
                    reasoning,
                    logprobs,
                } if text.is_empty() && reasoning.is_empty() && !logprobs.is_empty() => {
                    return Err(Status::data_loss(
                        "OpenAI-compatible logprobs have no output delta",
                    ));
                }
                ParsedEvent::Delta { .. } | ParsedEvent::Other => {}
            }
        }
    };
    if saw_done {
        return Ok(());
    }
    if !buf.is_empty() {
        return Err(Status::data_loss(
            "OpenAI-compatible SSE ended with an unfinished frame",
        ));
    }
    Err(Status::data_loss(
        "OpenAI-compatible SSE ended without [DONE]",
    ))
}

/// Provider errors are untrusted and may echo credentials or request fields. Read only a small
/// prefix and surface either a known JSON error field or a compact text response.
const TRUNCATED_DETAIL_SUFFIX: &str = "... [truncated]";

async fn upstream_http_error(resp: reqwest::Response, key: &str, request: &CanonRequest) -> Status {
    use futures::StreamExt;

    let code = resp.status();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if !is_text_error_body(&content_type) {
        return Status::unavailable(format!(
            "upstream HTTP {code}: non-text response body omitted"
        ));
    }

    let mut body = Vec::new();
    let mut truncated = false;
    let mut stream = resp.bytes_stream();
    while let Some(item) = stream.next().await {
        let bytes = match item {
            Ok(bytes) => bytes,
            Err(_) => {
                return Status::unavailable(format!(
                    "upstream HTTP {code}: provider error body unreadable"
                ));
            }
        };
        let remaining = UPSTREAM_ERROR_BODY_MAX_BYTES.saturating_sub(body.len());
        if bytes.len() > remaining {
            body.extend_from_slice(&bytes[..remaining]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&bytes);
    }

    let Some(detail) = safe_error_detail(&body, &content_type, key, request, truncated) else {
        return Status::unavailable(format!("upstream HTTP {code}"));
    };
    Status::unavailable(format!("upstream HTTP {code}: {detail}"))
}

fn is_text_error_body(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media_type.is_empty()
        || media_type.starts_with("text/")
        || media_type == "application/json"
        || media_type.ends_with("+json")
}

fn safe_error_detail(
    body: &[u8],
    content_type: &str,
    key: &str,
    request: &CanonRequest,
    body_truncated: bool,
) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    if body_truncated {
        return Some(bound_error_detail(
            "provider error body omitted".to_string(),
            true,
        ));
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return Some("non-text response body omitted".to_string());
    };
    let text = text.trim();
    if text.is_empty() {
        return None;
    }

    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let detail = if media_type.ends_with("json")
        || (media_type.is_empty() && (text.starts_with('{') || text.starts_with('[')))
    {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
            return Some("malformed provider error body omitted".to_string());
        };
        json_error_detail(&value).unwrap_or_else(|| "provider error body omitted".to_string())
    } else {
        text.to_string()
    };

    Some(bound_error_detail(
        sanitize_error_detail(&detail, key, request),
        body_truncated,
    ))
}

fn json_error_detail(value: &serde_json::Value) -> Option<String> {
    let error = value.get("error").unwrap_or(value);
    if let Some(detail) = error.as_str() {
        return Some(detail.to_string());
    }
    ["message", "detail", "code", "type"]
        .into_iter()
        .find_map(|field| error.get(field).and_then(|value| value.as_str()))
        .map(ToString::to_string)
}

fn sanitize_error_detail(detail: &str, key: &str, request: &CanonRequest) -> String {
    fn compact_text(text: &str) -> String {
        text.chars()
            .map(|ch| if ch.is_control() { ' ' } else { ch })
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn echoes_request_value(detail: &str, value: &str) -> bool {
        let value = compact_text(value);
        let prefix = value
            .chars()
            .take(UPSTREAM_ERROR_ECHO_PREFIX_CHARS)
            .collect::<String>();
        !value.is_empty()
            && (detail.contains(&value)
                || value.contains(detail)
                || (prefix != value && detail.contains(&prefix)))
    }

    let compact = compact_text(detail);
    let lower = compact.to_ascii_lowercase();
    const SENSITIVE_MARKERS: &[&str] = &[
        "authorization",
        "bearer ",
        "api_key",
        "api-key",
        "apikey",
        "access_token",
        "access-token",
        "client_secret",
        "private_key",
        "password",
        "secret",
        "gsk_",
        "sk-",
    ];
    let echoes_request_secret = request
        .messages
        .iter()
        .any(|message| echoes_request_value(&compact, &message.content))
        || request.params.as_ref().is_some_and(|params| {
            params
                .stop
                .iter()
                .any(|stop| echoes_request_value(&compact, stop))
        });
    if echoes_request_secret
        || (!key.is_empty() && compact.contains(key))
        || SENSITIVE_MARKERS
            .iter()
            .any(|marker| lower.contains(marker))
    {
        return "sensitive provider error detail redacted".to_string();
    }

    compact
}

fn bound_error_detail(mut detail: String, body_truncated: bool) -> String {
    let truncated = body_truncated || detail.len() > UPSTREAM_ERROR_DETAIL_MAX_BYTES;
    if !truncated {
        return detail;
    }
    let limit = UPSTREAM_ERROR_DETAIL_MAX_BYTES - TRUNCATED_DETAIL_SUFFIX.len();
    let mut end = detail.len().min(limit);
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    detail.truncate(end);
    detail.push_str(TRUNCATED_DETAIL_SUFFIX);
    detail
}

/// Cap on an unfinished SSE frame(Y3): a hostile/broken upstream sending bytes without
/// a `\n\n` separator must not grow the gateway buffer without bound. Legitimate events (a text
/// delta + top-k logprobs) are 2-3 orders of magnitude smaller -- 1 MiB does not touch them.
/// Drain complete SSE events(`\n\n`-separated) from the buffer in order. If the REMAINDER
/// (unfinished frame) exceeds the cap -- `resource_exhausted` instead of uncontrolled buffer
/// growth(Y3, R6). Complete events are always drained before the cap check.
// `tonic::Status` is the standard gRPC error type of the whole upstream module; boxing it in a single helper
// would break `?`-propagation into the loop's `Result<_, Status>`. The large Err variant here is deliberate.
#[allow(clippy::result_large_err)]
fn drain_complete_events(buf: &mut String) -> Result<Vec<String>, Status> {
    let mut events = Vec::new();
    while let Some(idx) = buf.find("\n\n") {
        events.push(buf[..idx].to_string());
        buf.drain(..idx + 2);
    }
    if buf.len() > UPSTREAM_SSE_FRAME_MAX_BYTES {
        return Err(Status::resource_exhausted(
            "upstream SSE frame exceeds buffer cap",
        ));
    }
    Ok(events)
}

/// A parsed SSE event.
enum ParsedEvent {
    /// Terminal `data: [DONE]`.
    Done,
    /// `data: {...}` with content/reasoning deltas(possibly empty) and the delta's token logprobs.
    Delta {
        text: String,
        reasoning: String,
        logprobs: Vec<TokenLogprobs>,
    },
    /// Carries no delta(comment, keep-alive, etc.).
    Other,
}

/// Parse a single SSE event: join the `data:` lines, recognize `[DONE]`, otherwise extract
/// `choices[0].delta.content`, provider-separated reasoning, and `choices[0].logprobs.content[]`
/// . A frame without `data:` is `Other`;
/// malformed JSON fails closed. Aggregate provider usage is not an OpenAI accounting source: each
/// output delta must carry its authoritative token logprobs before it can be forwarded.
#[allow(clippy::result_large_err)]
fn parse_event(event: &str) -> Result<ParsedEvent, Status> {
    let mut data = String::new();
    for line in event.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            data.push_str(rest.trim_start());
        }
    }
    if data.is_empty() {
        return Ok(ParsedEvent::Other);
    }
    if data == "[DONE]" {
        return Ok(ParsedEvent::Done);
    }
    let value = serde_json::from_str::<serde_json::Value>(&data)
        .map_err(|e| Status::data_loss(format!("malformed OpenAI-compatible SSE JSON: {e}")))?;
    match serde_json::from_value::<StreamChunk>(value) {
        Ok(chunk) => {
            let Some(choice) = chunk.choices.into_iter().next() else {
                return Ok(ParsedEvent::Other);
            };
            let Delta {
                content,
                reasoning,
                reasoning_content,
                reasoning_details,
            } = choice.delta;
            let text = content.unwrap_or_default();
            let reasoning = collect_reasoning(reasoning, reasoning_content, reasoning_details);
            let logprobs = choice
                .logprobs
                .map(|lp| {
                    lp.content
                        .into_iter()
                        .map(|c| TokenLogprobs {
                            logprob: c.logprob,
                            top: c
                                .top_logprobs
                                .into_iter()
                                .map(|t| TopLogprob {
                                    token: t.token,
                                    logprob: t.logprob,
                                })
                                .collect(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            Ok(ParsedEvent::Delta {
                text,
                reasoning,
                logprobs,
            })
        }
        // A well-formed provider metadata frame that is not a chat delta does not crash the stream.
        Err(_) => Ok(ParsedEvent::Other),
    }
}

fn collect_reasoning(
    reasoning: Option<String>,
    reasoning_content: Option<String>,
    reasoning_details: Option<Vec<ReasoningDetailWire>>,
) -> String {
    let mut parts = Vec::new();
    for value in [reasoning, reasoning_content].into_iter().flatten() {
        if !value.trim().is_empty() {
            parts.push(value);
        }
    }
    for detail in reasoning_details.into_iter().flatten() {
        for value in [detail.text, detail.summary].into_iter().flatten() {
            if !value.trim().is_empty() {
                parts.push(value);
            }
        }
    }
    parts.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> CanonRequest {
        CanonRequest {
            messages: vec![dexdo_proto::ChatMessage {
                role: "user".into(),
                content: "hello".into(),
            }],
            params: None,
        }
    }

    async fn start_test_server(body: String) -> (String, tokio::task::JoinHandle<String>) {
        start_test_server_with_response(body, "200 OK", "text/event-stream").await
    }

    async fn start_test_server_with_response(
        body: String,
        status_line: &'static str,
        content_type: &'static str,
    ) -> (String, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut next = [0_u8; 4096];
            loop {
                let read = socket.read(&mut next).await.unwrap();
                assert_ne!(read, 0, "fake provider received a truncated HTTP request");
                request.extend_from_slice(&next[..read]);
                let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = std::str::from_utf8(&request[..header_end]).unwrap();
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
            let header = format!(
                "HTTP/1.1 {status_line}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(header.as_bytes()).await.unwrap();
            socket.write_all(body.as_bytes()).await.unwrap();
            String::from_utf8(request).unwrap()
        });
        (format!("http://{address}"), server)
    }

    async fn run_test_stream_with_capabilities(
        body: String,
        count: u64,
        capabilities: Capabilities,
    ) -> (Result<(), Status>, Vec<UpstreamEvent>, String) {
        let (base_url, server) = start_test_server(body).await;
        let cfg = OpenAiConfig {
            base_url,
            capabilities,
            ..OpenAiConfig::default()
        };
        let (tx, mut rx) = mpsc::channel(16);
        let model_output_cap =
            resolve_model_output_cap(cfg.capabilities.max_output_tokens, "frame", &cfg.model)
                .expect("test capabilities declare an output cap");
        let result =
            stream_upstream(&cfg, "secret", count, &request(), &tx, model_output_cap).await;
        drop(tx);
        let provider_request = server.await.unwrap();
        let mut events = Vec::new();
        while let Some(event) = rx.recv().await {
            events.push(event.unwrap());
        }
        (result, events, provider_request)
    }

    async fn run_test_stream(body: String, count: u64) -> (Result<(), Status>, Vec<UpstreamEvent>) {
        let (result, events, _) =
            run_test_stream_with_capabilities(body, count, OpenAiConfig::default().capabilities)
                .await;
        (result, events)
    }

    fn no_logprobs() -> Capabilities {
        Capabilities {
            logprobs: false,
            top_logprobs: None,
            max_output_tokens: Some(DEFAULT_MAX_OUTPUT_TOKENS),
        }
    }

    fn sse_frame(text: &str, tokens: usize) -> String {
        let logprobs = (0..tokens)
            .map(|_| r#"{"token":"x","logprob":-0.1,"top_logprobs":[]}"#)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":{}}},\"logprobs\":{{\"content\":[{logprobs}]}}}}]}}\n\n",
            serde_json::to_string(text).unwrap()
        )
    }

    fn unstructured_sse_frame(text: &str) -> String {
        format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":{}}}}}]}}\n\n",
            serde_json::to_string(text).unwrap()
        )
    }

    fn both_usage_frame(tokens: u64) -> String {
        format!(
            "data: {{\"choices\":[{{\"delta\":{{}},\"finish_reason\":\"stop\"}}],\"usage\":{{\"completion_tokens\":{tokens}}},\"x_groq\":{{\"usage\":{{\"completion_tokens\":{tokens}}}}}}}\n\n"
        )
    }

    fn accounted_total(events: Vec<UpstreamEvent>) -> u64 {
        events
            .into_iter()
            .map(|event| match event {
                UpstreamEvent::Chunk {
                    accounted_tokens, ..
                }
                | UpstreamEvent::Accounted(accounted_tokens) => accounted_tokens,
            })
            .sum()
    }

    fn error_response(
        status: reqwest::StatusCode,
        content_type: Option<&str>,
        body: impl Into<Vec<u8>>,
    ) -> reqwest::Response {
        let mut response = http::Response::builder().status(status);
        if let Some(content_type) = content_type {
            response = response.header(reqwest::header::CONTENT_TYPE, content_type);
        }
        response
            .body(body.into())
            .expect("build error response")
            .into()
    }

    async fn error_message(
        status: reqwest::StatusCode,
        content_type: Option<&str>,
        body: impl Into<Vec<u8>>,
        key: &str,
    ) -> String {
        error_message_for_request(
            status,
            content_type,
            body,
            key,
            &CanonRequest {
                messages: vec![],
                params: None,
            },
        )
        .await
    }

    async fn error_message_for_request(
        status: reqwest::StatusCode,
        content_type: Option<&str>,
        body: impl Into<Vec<u8>>,
        key: &str,
        request: &CanonRequest,
    ) -> String {
        upstream_http_error(error_response(status, content_type, body), key, request)
            .await
            .message()
            .to_string()
    }

    #[tokio::test]
    async fn surfaces_http_400_json_error_detail() {
        let message = error_message(
            reqwest::StatusCode::BAD_REQUEST,
            Some("application/json"),
            br#"{"error":{"message":"logprobs are not supported for this model","type":"invalid_request_error"}}"#,
            "unused-key",
        )
        .await;
        assert_eq!(
            message,
            "upstream HTTP 400 Bad Request: logprobs are not supported for this model"
        );
    }

    #[tokio::test]
    async fn content_without_logprobs_fails_before_forwarding_or_counting() {
        let (result, events) = run_test_stream(
            concat!(
                "data: {\"choices\":[{\"delta\":{\"content\":\"uncountable\"}}]}\n\n",
                "data: [DONE]\n\n"
            )
            .to_string(),
            8,
        )
        .await;
        assert_eq!(result.unwrap_err().code(), tonic::Code::DataLoss);
        assert!(
            events.is_empty(),
            "uncountable content must not reach the gateway"
        );
    }

    #[tokio::test]
    async fn n_logprob_records_account_exactly_n_tokens() {
        let mut body = sse_frame("three tokens", 3);
        body.push_str("data: [DONE]\n\n");
        let (result, events) = run_test_stream(body, 8).await;
        result.unwrap();
        assert_eq!(accounted_total(events), 3);
    }

    #[tokio::test]
    async fn logprob_batch_above_remaining_limit_fails_before_forwarding_or_counting() {
        let mut body = sse_frame("oversized final batch", 3);
        body.push_str("data: [DONE]\n\n");
        let (result, events) = run_test_stream(body, 2).await;
        assert_eq!(result.unwrap_err().code(), tonic::Code::DataLoss);
        assert!(
            events.is_empty(),
            "an over-limit chunk must not reach delivery accounting"
        );
    }

    #[tokio::test]
    async fn budget_exhaustion_at_exact_limit_is_clean_without_done() {
        let (result, events) = run_test_stream(sse_frame("exact final batch", 2), 2).await;
        result.unwrap();
        assert_eq!(accounted_total(events), 2);
    }

    #[tokio::test]
    async fn provider_eof_without_done_fails_after_exact_forwarded_accounting() {
        let (result, events) = run_test_stream(sse_frame("truncated", 2), 8).await;
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::DataLoss);
        assert!(status.message().contains("without [DONE]"));
        assert_eq!(
            accounted_total(events),
            2,
            "already-forwarded tokens remain exact, but the request is not clean"
        );
    }

    #[tokio::test]
    async fn provider_eof_with_unfinished_remainder_fails_closed() {
        let mut body = sse_frame("forwarded", 1);
        body.push_str("data: {\"choices\":[");
        let (result, events) = run_test_stream(body, 8).await;
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::DataLoss);
        assert!(status.message().contains("unfinished frame"));
        assert_eq!(
            accounted_total(events),
            1,
            "the incomplete remainder must not create guessed accounting"
        );
    }

    #[tokio::test]
    async fn identical_output_count_is_invariant_to_sse_partitioning() {
        let partitions = [
            vec![("abcd", 4)],
            vec![("ab", 2), ("cd", 2)],
            vec![("a", 1), ("b", 1), ("c", 1), ("d", 1)],
        ];
        for partition in partitions {
            let mut body = String::new();
            for (text, tokens) in partition {
                body.push_str(&sse_frame(text, tokens));
            }
            body.push_str("data: [DONE]\n\n");
            let (result, events) = run_test_stream(body, 8).await;
            result.unwrap();
            assert_eq!(
                accounted_total(events),
                4,
                "one logical four-token output must not depend on frame count"
            );
        }
    }

    #[tokio::test]
    async fn no_logprobs_config_fails_before_provider_contact() {
        const KEY_ENV: &str = "DEXDO_R20_09_NO_LOGPROBS_PREFLIGHT_KEY";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cfg = OpenAiConfig {
            base_url: format!("http://{address}"),
            api_key_env: KEY_ENV.into(),
            capabilities: no_logprobs(),
            ..OpenAiConfig::default()
        };
        std::env::set_var(KEY_ENV, "fake-provider-secret");
        let (tx, mut rx) = mpsc::channel(4);
        run(&cfg, 3, Some(request()), tx).await;
        std::env::remove_var(KEY_ENV);
        let status = match rx.recv().await.unwrap() {
            Err(status) => status,
            Ok(_) => panic!("ineligible OpenAI endpoint produced output"),
        };
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(status.message().contains("per-token logprobs"));
        assert!(rx.recv().await.is_none());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "an ineligible OpenAI endpoint must not be contacted"
        );
    }

    #[tokio::test]
    async fn final_usage_cannot_authorize_output_without_per_token_logprobs() {
        let mut body = unstructured_sse_frame("must not be forwarded");
        body.push_str(&both_usage_frame(3));
        body.push_str("data: [DONE]\n\n");
        let (result, events, _) = run_test_stream_with_capabilities(body, 8, no_logprobs()).await;
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::DataLoss);
        assert!(status
            .message()
            .contains("omitted authoritative token logprobs"));
        assert!(
            events.is_empty(),
            "aggregate final usage must not rescue output"
        );
    }

    #[tokio::test]
    async fn logprob_mode_ignores_terminal_usage_instead_of_double_accounting() {
        let mut body = sse_frame("one", 1);
        body.push_str(&both_usage_frame(1));
        body.push_str("data: [DONE]\n\n");
        let (result, events) = run_test_stream(body, 8).await;
        result.unwrap();
        assert_eq!(events.len(), 1, "no separate Accounted event is emitted");
        assert_eq!(accounted_total(events), 1);
    }

    #[tokio::test]
    async fn surfaces_http_400_text_error_detail() {
        let message = error_message(
            reqwest::StatusCode::BAD_REQUEST,
            Some("text/plain; charset=utf-8"),
            " invalid request\n  detail ",
            "unused-key",
        )
        .await;
        assert_eq!(
            message,
            "upstream HTTP 400 Bad Request: invalid request detail"
        );
    }

    #[tokio::test]
    async fn surfaces_http_404_status_and_detail() {
        let message = error_message(
            reqwest::StatusCode::NOT_FOUND,
            Some("application/problem+json"),
            br#"{"error":{"message":"model not found"}}"#,
            "unused-key",
        )
        .await;
        assert_eq!(message, "upstream HTTP 404 Not Found: model not found");
    }

    #[tokio::test]
    async fn empty_error_body_keeps_status_only() {
        let message = error_message(
            reqwest::StatusCode::BAD_REQUEST,
            Some("text/plain"),
            "",
            "unused-key",
        )
        .await;
        assert_eq!(message, "upstream HTTP 400 Bad Request");
    }

    #[tokio::test]
    async fn malformed_error_body_is_not_echoed() {
        let message = error_message(
            reqwest::StatusCode::BAD_REQUEST,
            Some("application/json"),
            br#"{"error":{"message":"unterminated""#,
            "unused-key",
        )
        .await;
        assert_eq!(
            message,
            "upstream HTTP 400 Bad Request: malformed provider error body omitted"
        );
        assert!(!message.contains("unterminated"));
    }

    #[tokio::test]
    async fn oversized_error_body_is_truncated() {
        let body = format!(
            "{}must-not-appear",
            "x".repeat(UPSTREAM_ERROR_BODY_MAX_BYTES + 256)
        );
        let message = error_message(
            reqwest::StatusCode::BAD_REQUEST,
            Some("text/plain"),
            body,
            "unused-key",
        )
        .await;
        assert!(message.ends_with(TRUNCATED_DETAIL_SUFFIX), "{message}");
        assert!(!message.contains("must-not-appear"), "{message}");
        assert!(
            message.len()
                <= "upstream HTTP 400 Bad Request: ".len() + UPSTREAM_ERROR_DETAIL_MAX_BYTES
        );
    }

    #[tokio::test]
    async fn error_detail_redacts_keys_authorization_and_bearer_credentials() {
        const KEY: &str = "gsk_live_GROQ_API_KEY_value";
        for body in [
            format!(r#"{{"error":{{"message":"provider echoed {KEY}"}}}}"#),
            r#"{"error":{"message":"Authorization: basic-credential"}}"#.to_string(),
            r#"{"error":{"message":"Bearer bearer-credential"}}"#.to_string(),
            r#"{"error":{"message":"api_key=other-provider-key"}}"#.to_string(),
        ] {
            let message = error_message(
                reqwest::StatusCode::BAD_REQUEST,
                Some("application/json"),
                body,
                KEY,
            )
            .await;
            assert!(
                message.ends_with("sensitive provider error detail redacted"),
                "{message}"
            );
            for secret in [
                KEY,
                "basic-credential",
                "bearer-credential",
                "other-provider-key",
            ] {
                assert!(!message.contains(secret), "{message}");
            }
        }
    }

    #[tokio::test]
    async fn truncated_and_partial_request_message_echoes_are_redacted() {
        let request_secret = "A".repeat(UPSTREAM_ERROR_BODY_MAX_BYTES + 512);
        let request = CanonRequest {
            messages: vec![dexdo_proto::ChatMessage {
                role: "user".to_string(),
                content: request_secret.clone(),
            }],
            params: None,
        };
        let truncated = error_message_for_request(
            reqwest::StatusCode::BAD_REQUEST,
            Some("text/plain"),
            request_secret.clone(),
            "unused-key",
            &request,
        )
        .await;
        assert_eq!(
            truncated,
            "upstream HTTP 400 Bad Request: provider error body omitted... [truncated]"
        );
        assert!(!truncated.contains("AAAAAAAA"), "{truncated}");

        let partial = request_secret[..64].to_string();
        let message = error_message_for_request(
            reqwest::StatusCode::BAD_REQUEST,
            Some("text/plain"),
            format!("provider echoed {partial}"),
            "unused-key",
            &request,
        )
        .await;
        assert!(
            message.ends_with("sensitive provider error detail redacted"),
            "{message}"
        );
        assert!(!message.contains(&partial), "{message}");
    }

    #[tokio::test]
    async fn stop_sequence_echo_is_redacted() {
        const STOP: &str = "STOP-PRIVATE-VALUE-4c9";
        let request = CanonRequest {
            messages: vec![],
            params: Some(dexdo_proto::SamplingParams {
                temperature: 0.0,
                max_tokens: 0,
                stop: vec![STOP.to_string()],
                greedy: false,
            }),
        };
        let message = error_message_for_request(
            reqwest::StatusCode::BAD_REQUEST,
            Some("application/json"),
            format!(r#"{{"error":{{"message":"provider rejected stop {STOP}"}}}}"#),
            "unused-key",
            &request,
        )
        .await;
        assert!(
            message.ends_with("sensitive provider error detail redacted"),
            "{message}"
        );
        assert!(!message.contains(STOP), "{message}");
    }

    #[tokio::test]
    async fn non_text_error_body_is_omitted() {
        let message = error_message(
            reqwest::StatusCode::BAD_REQUEST,
            Some("application/octet-stream"),
            b"\0\xffGROQ_API_KEY_VALUE".to_vec(),
            "GROQ_API_KEY_VALUE",
        )
        .await;
        assert_eq!(
            message,
            "upstream HTTP 400 Bad Request: non-text response body omitted"
        );
        assert!(!message.contains("GROQ_API_KEY_VALUE"));
    }

    #[test]
    fn parses_delta_done_and_other() {
        let delta = parse_event("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}").unwrap();
        assert!(
            matches!(delta, ParsedEvent::Delta { text, reasoning, .. } if text == "hi" && reasoning.is_empty())
        );
        assert!(matches!(
            parse_event("data: [DONE]").unwrap(),
            ParsedEvent::Done
        ));
        assert!(matches!(
            parse_event(": keep-alive").unwrap(),
            ParsedEvent::Other
        ));
        // A delta without content(role-only first frame) -> empty string, not accounted.
        let empty = parse_event("data: {\"choices\":[{\"delta\":{}}]}").unwrap();
        assert!(
            matches!(empty, ParsedEvent::Delta { text, reasoning, .. } if text.is_empty() && reasoning.is_empty())
        );
    }

    #[test]
    fn parses_openrouter_reasoning_fields() {
        let raw = parse_event(
            "data: {\"choices\":[{\"delta\":{\"content\":\"391\",\"reasoning\":\"raw \",\"reasoning_content\":\"alias \",\"reasoning_details\":[{\"type\":\"reasoning.text\",\"text\":\"detail text\"},{\"type\":\"reasoning.summary\",\"summary\":\"summary text\"},{\"type\":\"reasoning.encrypted\",\"data\":\"redacted\"}]}}]}",
        )
        .unwrap();
        match raw {
            ParsedEvent::Delta {
                text,
                reasoning,
                logprobs: lp,
                ..
            } => {
                assert_eq!(text, "391");
                assert!(reasoning.contains("raw"));
                assert!(reasoning.contains("alias"));
                assert!(reasoning.contains("detail text"));
                assert!(reasoning.contains("summary text"));
                assert!(!reasoning.contains("redacted"));
                assert!(lp.is_empty());
            }
            _ => panic!("expected OpenRouter reasoning delta"),
        }
    }

    /// Y3(regression): complete events are drained in order, the unfinished tail is preserved.
    #[test]
    fn drain_keeps_partial_frame() {
        let mut buf = String::from("data: a\n\ndata: b\n\ndata: part");
        let events = drain_complete_events(&mut buf).unwrap();
        assert_eq!(events, vec!["data: a".to_string(), "data: b".to_string()]);
        assert_eq!(
            buf, "data: part",
            "unfinished frame preserved under the cap"
        );
    }

    /// Y3(negative): an upstream without a `\n\n` separator does not grow the gateway buffer without bound --
    /// when the cap is exceeded the stream closes with `resource_exhausted`, not OOM.
    #[test]
    fn frame_without_separator_is_capped() {
        let mut buf = "x".repeat(UPSTREAM_SSE_FRAME_MAX_BYTES + 1);
        let err = drain_complete_events(&mut buf).unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }

    #[test]
    fn parses_logprobs_into_canon() {
        // R2: choices[0].logprobs.content[] -> TokenLogprobs(chosen + top-k without loss).
        let ev = parse_event(
            "data: {\"choices\":[{\"delta\":{\"content\":\"x\"},\"logprobs\":{\"content\":[{\"token\":\"x\",\"logprob\":-0.4,\"top_logprobs\":[{\"token\":\"x\",\"logprob\":-0.4},{\"token\":\"y\",\"logprob\":-1.5}]}]}}]}",
        )
        .unwrap();
        match ev {
            ParsedEvent::Delta {
                text: t,
                reasoning: r,
                logprobs: lp,
                ..
            } => {
                assert_eq!(t, "x");
                assert!(r.is_empty());
                assert_eq!(lp.len(), 1);
                assert!((lp[0].logprob - (-0.4)).abs() < 1e-9);
                assert_eq!(lp[0].top.len(), 2);
                assert_eq!(lp[0].top[1].token, "y");
            }
            _ => panic!("expected Delta with logprobs"),
        }
    }

    #[test]
    fn builds_request_forces_model_and_carries_messages() {
        let cfg = OpenAiConfig::default();
        let req = CanonRequest {
            messages: vec![dexdo_proto::ChatMessage {
                role: "user".into(),
                content: "hi".into(),
            }],
            params: Some(dexdo_proto::SamplingParams {
                temperature: 0.0,
                max_tokens: 0,
                stop: vec![],
                greedy: false,
            }),
        };
        let body = build_request(&cfg, &req, 8, DEFAULT_MAX_OUTPUT_TOKENS);
        assert_eq!(body.model, DEFAULT_MODEL);
        assert_eq!(body.messages.len(), 1);
        assert!(body.stream);
        assert!(body.reasoning.is_none());
        // Zero-valued sampling fields keep their defaults, while generation is always bounded by the deal.
        assert!(body.temperature.is_none());
        assert_eq!(body.max_tokens, 8);
    }

    #[test]
    fn build_request_omits_logprobs_when_capability_off() {
        // a model without logprobs -> the field is NOT in the request body(a strict endpoint won't get a 400).
        let cfg = OpenAiConfig {
            capabilities: no_logprobs(),
            ..Default::default()
        };
        let req = CanonRequest {
            messages: vec![],
            params: None,
        };
        let body = build_request(&cfg, &req, 8, DEFAULT_MAX_OUTPUT_TOKENS);
        assert!(body.logprobs.is_none());
        assert!(body.top_logprobs.is_none());
        let json = serde_json::to_string(&body).unwrap();
        assert!(
            !json.contains("logprobs"),
            "logprobs not serialized: {json}"
        );
    }

    #[test]
    fn build_request_sends_logprobs_when_capability_on() {
        // a model with logprobs(default caps Groq/qwen) -> the field is present(B6 signals are collected).
        let cfg = OpenAiConfig::default();
        let req = CanonRequest {
            messages: vec![],
            params: None,
        };
        let body = build_request(&cfg, &req, 8, DEFAULT_MAX_OUTPUT_TOKENS);
        assert_eq!(body.logprobs, Some(true));
        assert_eq!(body.top_logprobs, Some(5));
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"logprobs\":true"), "{json}");
    }

    #[test]
    fn build_request_clamps_generation_to_request_deal_count_and_model_output_cap() {
        // the outbound limit is `min(client request, deal budget, model output cap)` -- the model cap is
        // the bound that used to be missing, which made every real provider answer `400`.
        const CAP: u32 = 40_960;
        let cfg = OpenAiConfig::default();
        let with_request_limit = |max_tokens| CanonRequest {
            messages: vec![],
            params: Some(dexdo_proto::SamplingParams {
                max_tokens,
                ..Default::default()
            }),
        };

        // The deal budget below every other bound wins.
        assert_eq!(
            build_request(&cfg, &with_request_limit(12), 5, CAP).max_tokens,
            5
        );
        // A client value below every other bound passes through unchanged.
        assert_eq!(
            build_request(&cfg, &with_request_limit(3), 5, CAP).max_tokens,
            3
        );
        // No client value, deal below the cap -> the deal budget.
        assert_eq!(build_request(&cfg, &request(), 7, CAP).max_tokens, 7);
        // No client value, a deal budget above the cap -> the model cap, never `u32::MAX`.
        assert_eq!(
            build_request(&cfg, &request(), u64::MAX, CAP).max_tokens,
            CAP
        );
        assert_eq!(
            build_request(&cfg, &request(), 2_000_000, CAP).max_tokens,
            CAP
        );
        // A client value above the cap is clamped to the cap.
        assert_eq!(
            build_request(&cfg, &with_request_limit(100_000), u64::MAX, CAP).max_tokens,
            CAP
        );
        // The cap is the tightest bound only when it is: a smaller cap wins over a smaller deal budget.
        assert_eq!(build_request(&cfg, &request(), 5, CAP).max_tokens, 5);
        assert_eq!(build_request(&cfg, &request(), 5, 2).max_tokens, 2);
        // Never zero(a provider rejects `max_tokens: 0`).
        assert_eq!(build_request(&cfg, &request(), 0, CAP).max_tokens, 1);
    }

    #[tokio::test]
    async fn outbound_request_carries_the_model_capped_generation_limit() {
        // Wire-level: with no client `max_tokens` and a deal budget of a whole tick, the JSON that actually
        // reaches the provider carries the model cap -- not `u32::MAX` and not `ticks * TICK_SIZE`.
        let (_, _, provider_request) = run_test_stream_with_capabilities(
            "data: [DONE]\n\n".to_string(),
            2_000_000,
            OpenAiConfig::default().capabilities,
        )
        .await;
        assert!(
            provider_request.contains(&format!("\"max_tokens\":{DEFAULT_MAX_OUTPUT_TOKENS}")),
            "outbound body must carry the model output cap: {provider_request}"
        );
        assert!(
            !provider_request.contains(&format!("\"max_tokens\":{}", u32::MAX)),
            "an unbounded generation limit must never reach the provider: {provider_request}"
        );
        assert!(
            !provider_request.contains("\"max_tokens\":2000000"),
            "the deal budget must not reach the provider unclamped: {provider_request}"
        );
    }

    #[tokio::test]
    async fn unknown_model_output_cap_refuses_before_contacting_the_provider() {
        // a model whose output cap is unknown must never be served -- and must fail BEFORE any provider
        // connection, so no request is billed, attempted or half-sent.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let unknown_cap = OpenAiConfig {
            base_url: format!("http://{address}"),
            // `PATH` is always set, so the key precondition cannot mask the capability refusal.
            api_key_env: "PATH".to_string(),
            capabilities: Capabilities {
                max_output_tokens: None,
                ..OpenAiConfig::default().capabilities
            },
            ..OpenAiConfig::default()
        };
        let (tx, mut rx) = mpsc::channel(4);
        // Bounded: a regression that only refuses AFTER connecting would otherwise block on a listener that
        // never answers, and a hung test is not a failing test.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run(&unknown_cap, 8, Some(request()), tx),
        )
        .await
        .expect("an unknown output cap must be refused without waiting on the provider");

        let Some(Err(status)) = rx.recv().await else {
            panic!("an unknown output cap must be reported as a refusal");
        };
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        let message = status.message();
        assert!(
            message.contains(DEFAULT_MODEL),
            "names the model: {message}"
        );
        assert!(
            message.contains("max_output_tokens"),
            "names the remediation: {message}"
        );
        assert!(
            message.contains("models config"),
            "names where to set it: {message}"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(250), listener.accept())
                .await
                .is_err(),
            "an unknown output cap must not reach the provider at all"
        );

        // Positive control: the very same setup WITH a declared cap does open a provider connection, so the
        // assertion above is not vacuous.
        let known_cap = OpenAiConfig {
            capabilities: Capabilities {
                max_output_tokens: Some(16),
                ..unknown_cap.capabilities.clone()
            },
            ..unknown_cap
        };
        let (tx, _rx) = mpsc::channel(4);
        let serving = tokio::spawn(async move { run(&known_cap, 8, Some(request()), tx).await });
        let accepted =
            tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept()).await;
        serving.abort();
        assert!(
            accepted.is_ok(),
            "a declared output cap must reach the provider"
        );
    }

    #[tokio::test]
    async fn a_models_config_that_omits_the_output_cap_cannot_serve() {
        // follow-up: the refusal above is asserted on a hand-built config. This one starts from a
        // models **config file** whose `capabilities` block omits `max_output_tokens` -- the shape every live
        // `models.json` fixture had -- and drives it through the production loader, `from_model` and the serve
        // entry, so the whole chain "a config that omits the cap -> a model that cannot deliver a token" is a
        // regression instead of a fact rediscovered on a live run.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let json = format!(
            r#"{{"models":{{"qwen":{{"frame_model":"qwen--qwen3--32b","base_url":"http://{address}",
              "served_model":"qwen/qwen3-32b","api_key_env":"PATH","tokenizer_family":"qwen",
              "price_per_tick":1000000000,"capabilities":{{"logprobs":true,"top_logprobs":5}}}}}}}}"#
        );
        let models = crate::seller::models::ModelsConfig::from_json(&json).expect("fixture parses");
        let cfg = OpenAiConfig::from_model(models.get("qwen").expect("model"), None);
        assert_eq!(
            cfg.capabilities.max_output_tokens, None,
            "an omitted cap is UNKNOWN, never a default"
        );

        let (tx, mut rx) = mpsc::channel(4);
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run(&cfg, 8, Some(request()), tx),
        )
        .await
        .expect("the refusal must not wait on the provider");
        let Some(Err(status)) = rx.recv().await else {
            panic!("a config without an output cap must be refused");
        };
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(
            status.message().contains("max_output_tokens"),
            "{}",
            status.message()
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(250), listener.accept())
                .await
                .is_err(),
            "nothing may reach the provider"
        );
    }

    #[tokio::test]
    async fn provider_request_rejection_names_the_model_and_the_sent_limit() {
        // the provider rejects a request the SELLER built, so the error the buyer relays must name the
        // served model and the generation limit that was sent instead of a bare relayed provider line.
        let (base_url, server) = start_test_server_with_response(
            r#"{"error":{"message":"max_tokens must be less than or equal to 40960"}}"#.to_string(),
            "400 Bad Request",
            "application/json",
        )
        .await;
        let cfg = OpenAiConfig {
            base_url,
            ..OpenAiConfig::default()
        };
        let (tx, _rx) = mpsc::channel(4);
        let status = stream_upstream(
            &cfg,
            "secret",
            u64::MAX,
            &request(),
            &tx,
            DEFAULT_MAX_OUTPUT_TOKENS,
        )
        .await
        .expect_err("a provider 400 fails the stream");
        let _ = server.await;

        let message = status.message();
        // The `upstream HTTP <code>` prefix is preserved: relay policy and the failure classifier parse it.
        assert!(
            message.starts_with("upstream HTTP 400 Bad Request"),
            "{message}"
        );
        assert!(
            message.contains("seller configuration fault"),
            "classified as a seller fault: {message}"
        );
        assert!(
            message.contains(DEFAULT_MODEL),
            "names the model: {message}"
        );
        assert!(
            message.contains(&format!("sent max_tokens={DEFAULT_MAX_OUTPUT_TOKENS}")),
            "names the limit that was sent: {message}"
        );
        assert!(
            message.contains(&format!(
                "capabilities.max_output_tokens={DEFAULT_MAX_OUTPUT_TOKENS}"
            )),
            "names the configured cap to correct: {message}"
        );
        assert!(
            message.contains("max_tokens must be less than or equal to 40960"),
            "keeps the provider's own detail: {message}"
        );
    }

    #[test]
    fn build_request_pins_seed_only_for_greedy_spotcheck() {
        let cfg = OpenAiConfig::default();
        let greedy = CanonRequest {
            messages: vec![],
            params: Some(dexdo_proto::SamplingParams {
                temperature: 0.9,
                max_tokens: 16,
                stop: vec![],
                greedy: true,
            }),
        };
        let body = build_request(&cfg, &greedy, 8, DEFAULT_MAX_OUTPUT_TOKENS);
        assert_eq!(body.temperature, Some(0.0));
        assert_eq!(body.seed, Some(0));
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"seed\":0"), "{json}");

        let regular = CanonRequest {
            messages: vec![],
            params: Some(dexdo_proto::SamplingParams {
                temperature: 0.9,
                max_tokens: 16,
                stop: vec![],
                greedy: false,
            }),
        };
        let body = build_request(&cfg, &regular, 32, DEFAULT_MAX_OUTPUT_TOKENS);
        assert_eq!(body.temperature, Some(0.9));
        assert_eq!(body.seed, None);
    }

    #[test]
    fn build_request_enables_openrouter_qwen_reasoning_only_for_exact_model() {
        let cfg = OpenAiConfig {
            base_url: "https://openrouter.ai/api/v1".to_string(),
            model: "qwen/qwen3-32b".to_string(),
            capabilities: no_logprobs(),
            ..Default::default()
        };
        let body = build_request(
            &cfg,
            &CanonRequest {
                messages: vec![],
                params: None,
            },
            8,
            DEFAULT_MAX_OUTPUT_TOKENS,
        );
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"reasoning\":{\"enabled\":true,\"exclude\":false}"));

        let other_model = OpenAiConfig {
            model: "qwen/qwen3.6-27b".to_string(),
            ..cfg
        };
        let body = build_request(
            &other_model,
            &CanonRequest {
                messages: vec![],
                params: None,
            },
            8,
            DEFAULT_MAX_OUTPUT_TOKENS,
        );
        assert!(body.reasoning.is_none());
    }
}
