//! Gateway upstream token source. Adapters:
//! - [`mock`] -- mock model(`--mock-model`): deterministic fake tokens from the prompt
//! - [`openai`] -- **real OpenAI-compatible upstream**: Groq,
//! streaming SSE -> normalization into `CanonChunk`(R1/R2/R5/R6).
//! - [`anthropic`] -- native Anthropic Messages API, streaming SSE -> the same canon.
//! All branches normalize the upstream output into a single canonical stream(R1). Monetary accounting
//! uses only the adapter's authoritative source: mock token ids, OpenAI-compatible per-token logprob records,
//! and Anthropic cumulative `output_tokens`. `CanonChunk` framing is never itself a token count.

pub mod anthropic;
pub mod mock;
pub mod openai;

use anyhow::{bail, Result};
use dexdo_core::params::{
    UPSTREAM_HEALTH_CHANNEL_CAPACITY, UPSTREAM_HEALTH_PROBE_MAX_TOKENS,
    UPSTREAM_HEALTH_PROBE_PROMPT,
};
use dexdo_proto::{CanonChunk, CanonRequest, ChatMessage, SamplingParams};
use tokio::sync::mpsc;
use tonic::Status;

/// Seller-internal upstream event. Accounting is kept separate from the buyer-facing canon so
/// providers that report authoritative usage without token ids do not have to invent token data.
pub enum UpstreamEvent {
    Chunk {
        chunk: CanonChunk,
        accounted_tokens: u64,
    },
    /// Authoritative usage for preceding successfully delivered chunks whose provider reports token usage
    /// separately from its text frames(the native Anthropic adapter).
    Accounted(u64),
}

/// Attach an exact structured token count to a chunk.
/// Empty/no-signal chunks account zero. If both native sources are present they must agree; choosing the
/// larger value would monetize contradictory metadata.
#[allow(clippy::result_large_err)]
pub fn chunk_with_structured_accounting(chunk: CanonChunk) -> UpstreamResult {
    let token_ids = u64::try_from(chunk.token_ids.len())
        .map_err(|_| Status::data_loss("token-id count does not fit u64"))?;
    let logprobs = u64::try_from(chunk.logprobs.len())
        .map_err(|_| Status::data_loss("logprob count does not fit u64"))?;
    if token_ids != 0 && logprobs != 0 && token_ids != logprobs {
        return Err(Status::data_loss(
            "contradictory authoritative token-id and logprob counts",
        ));
    }
    Ok(UpstreamEvent::Chunk {
        chunk,
        accounted_tokens: token_ids.max(logprobs),
    })
}

pub type UpstreamResult = Result<UpstreamEvent, Status>;

/// Resolve the model's own maximum output length -- the third
/// bound on the outbound generation limit next to the buyer's request and the deal budget.
/// **Fail closed**: an undeclared cap is UNKNOWN, not "unbounded". A deal budget is `ticks * TICK_SIZE`
/// tokens and a request without `max_tokens` used to become `u32::MAX`; both exceed every real provider's
/// output limit, so the provider answered `400` and no delivery ever succeeded. Refusing here happens
/// BEFORE the provider is contacted and names the concrete remediation.
#[allow(clippy::result_large_err)]
pub(crate) fn resolve_model_output_cap(
    declared: Option<u32>,
    frame_model: &str,
    served_model: &str,
) -> Result<u32, Status> {
    match declared {
        Some(cap) if cap > 0 => Ok(cap),
        _ => Err(Status::failed_precondition(format!(
            "model \"{frame_model}\" (served \"{served_model}\") has no known output cap: refusing to \
             send an unbounded max_tokens to the provider; set \"capabilities\": \
             {{ \"max_output_tokens\": <the provider's maximum completion length> }} for this model in \
             the models config (models.json)"
        ))),
    }
}

/// Is this provider HTTP status a **seller-side configuration** fault?
/// The seller constructs the whole upstream request: the market forces the model and the gateway bounds the
/// sampling params, so the buyer cannot shape it. A `4xx` rejection therefore means the seller's own model
/// config/request is wrong, not that the upstream is transiently down. `401/403` keep the dedicated `auth`
/// class and `408/429` are genuinely transient, so both are excluded.
pub(crate) fn is_seller_config_http_status(code: u16) -> bool {
    (400..500).contains(&code) && !matches!(code, 401 | 403 | 408 | 429)
}

/// Annotate a provider `4xx` that is a seller configuration fault with the concrete subject: which model was
/// served and which generation limit was sent. The `Status` code and the `upstream HTTP <code>` prefix
/// are preserved verbatim -- stream-error policy and the failure classifier both parse them -- so this only
/// enriches the message the operator(and the relayed buyer error body) actually reads.
pub(crate) fn annotate_seller_config_fault(
    status: Status,
    http_status: u16,
    served_model: &str,
    sent_max_tokens: u32,
    configured_output_cap: u32,
) -> Status {
    if !is_seller_config_http_status(http_status) {
        return status;
    }
    Status::new(
        status.code(),
        format!(
            "{} [seller configuration fault: model \"{served_model}\" sent max_tokens={sent_max_tokens} \
             at capabilities.max_output_tokens={configured_output_cap}; correct this model's \
             max_output_tokens in the models config]",
            status.message()
        ),
    )
}

/// Gateway upstream choice(`--mock-model` vs the real adapter). Configured at seller startup
/// and **immutable** for the gateway's lifetime. The real branch carries base-url + model id;
/// the key is read from the environment at runtime(see [`openai`]) and is not stored here.
#[derive(Clone)]
pub enum UpstreamConfig {
    /// Mock model: deterministic fake tokens from the prompt.
    Mock,
    /// The same mock model, declaring the exact on-chain registry identity.
    MockWithClaimedModel(String),
    /// Instance scammer: a mock that UNCONDITIONALLY substitutes the model (claims one other than
    /// the frame's) -- a seller that client-side verification(B7) is obligated to catch. For the failover e2e.
    MockScammer,
    /// Real OpenAI-compatible upstream(Groq, etc.): API base + market model id.
    OpenAi(openai::OpenAiConfig),
    /// Native Anthropic Messages API upstream.
    Anthropic(anthropic::AnthropicConfig),
}

impl UpstreamConfig {
    /// Prove that the configured endpoint accepts the configured credentials and exact served
    /// model through the same adapter used for buyer traffic. The caller owns the timeout.
    pub async fn check_health(&self) -> Result<()> {
        if matches!(
            self,
            Self::Mock | Self::MockWithClaimedModel(_) | Self::MockScammer
        ) {
            return Ok(());
        }

        let request = CanonRequest {
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: UPSTREAM_HEALTH_PROBE_PROMPT.to_string(),
            }],
            params: Some(SamplingParams {
                temperature: 0.0,
                max_tokens: UPSTREAM_HEALTH_PROBE_MAX_TOKENS,
                stop: Vec::new(),
                greedy: true,
            }),
        };
        let (tx, mut rx) = mpsc::channel(UPSTREAM_HEALTH_CHANNEL_CAPACITY);
        let run = self.run(
            u64::from(UPSTREAM_HEALTH_PROBE_MAX_TOKENS),
            Some(request),
            tx,
        );
        tokio::pin!(run);

        loop {
            tokio::select! {
                item = rx.recv() => match item {
                    Some(Ok(UpstreamEvent::Chunk { accounted_tokens, .. }))
                        if accounted_tokens > 0 => return Ok(()),
                    Some(Ok(UpstreamEvent::Accounted(tokens))) if tokens > 0 => return Ok(()),
                    Some(Ok(_)) => continue,
                    Some(Err(status)) => {
                        bail!("upstream readiness failed ({:?})", status.code());
                    }
                    None => bail!("upstream readiness produced no authoritative model-token usage"),
                },
                _ = &mut run => {
                    while let Ok(item) = rx.try_recv() {
                        match item {
                            Ok(UpstreamEvent::Chunk { accounted_tokens, .. })
                                if accounted_tokens > 0 => return Ok(()),
                            Ok(UpstreamEvent::Accounted(tokens)) if tokens > 0 => return Ok(()),
                            Ok(_) => {}
                            Err(status) => {
                                bail!("upstream readiness failed ({:?})", status.code());
                            }
                        }
                    }
                    bail!("upstream readiness produced no authoritative model-token usage");
                }
            }
        }
    }

    /// Run the upstream: normalize its output into `CanonChunk` and send it incrementally into
    /// `tx`(R6). `count` is the stream's token budget: no more than `count` delivered tokens. `req` is
    /// the buyer's canonical request(R1). Finishes on upstream
    /// exhaustion, on reaching `count`, or when the buyer disconnected(`tx` closed = STOP).
    pub async fn run(
        &self,
        count: u64,
        req: Option<CanonRequest>,
        tx: mpsc::Sender<UpstreamResult>,
    ) {
        match self {
            UpstreamConfig::Mock => mock::run(count, req.as_ref(), tx, false, None).await,
            UpstreamConfig::MockWithClaimedModel(claimed_model) => {
                mock::run(count, req.as_ref(), tx, false, Some(claimed_model.as_str())).await
            }
            UpstreamConfig::MockScammer => mock::run(count, req.as_ref(), tx, true, None).await,
            UpstreamConfig::OpenAi(cfg) => openai::run(cfg, count, req, tx).await,
            UpstreamConfig::Anthropic(cfg) => anthropic::run(cfg, count, req, tx).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seller::models::{Capabilities, ModelConfig};

    #[test]
    fn seller_runtime_policy_is_owned_by_core_params() {
        use dexdo_core::params::{
            GATEWAY_CLIENT_CHANNEL_CAPACITY, GATEWAY_UPSTREAM_CHANNEL_CAPACITY,
            UPSTREAM_ERROR_BODY_MAX_BYTES, UPSTREAM_ERROR_DETAIL_MAX_BYTES,
            UPSTREAM_ERROR_ECHO_PREFIX_CHARS, UPSTREAM_SSE_FRAME_MAX_BYTES,
        };

        assert_eq!(UPSTREAM_HEALTH_PROBE_PROMPT, "Reply with OK.");
        assert_eq!(UPSTREAM_HEALTH_PROBE_MAX_TOKENS, 1);
        assert_eq!(UPSTREAM_HEALTH_CHANNEL_CAPACITY, 4);
        assert_eq!(GATEWAY_UPSTREAM_CHANNEL_CAPACITY, 16);
        assert_eq!(GATEWAY_CLIENT_CHANNEL_CAPACITY, 16);
        assert_eq!(UPSTREAM_ERROR_BODY_MAX_BYTES, 4_096);
        assert_eq!(UPSTREAM_ERROR_DETAIL_MAX_BYTES, 1_024);
        assert_eq!(UPSTREAM_ERROR_ECHO_PREFIX_CHARS, 32);
        assert_eq!(UPSTREAM_SSE_FRAME_MAX_BYTES, 1_048_576);

        let upstream = include_str!("mod.rs")
            .split_once("#[cfg(test)]\nmod tests")
            .expect("upstream unit-test module boundary")
            .0;
        for name in [
            "UPSTREAM_HEALTH_PROBE_PROMPT",
            "UPSTREAM_HEALTH_PROBE_MAX_TOKENS",
            "UPSTREAM_HEALTH_CHANNEL_CAPACITY",
        ] {
            assert!(
                upstream.contains(name),
                "upstream must consume params::{name}"
            );
        }
        for literal in [
            "content: \"Reply with OK.\"",
            "max_tokens: 1",
            "mpsc::channel(4)",
            "self.run(1,",
        ] {
            assert!(
                !upstream.contains(literal),
                "upstream production policy must not copy {literal}"
            );
        }

        let gateway = include_str!("../gateway.rs")
            .split_once("#[cfg(test)]\nmod tests")
            .expect("gateway unit-test module boundary")
            .0;
        assert!(gateway.contains("GATEWAY_UPSTREAM_CHANNEL_CAPACITY"));
        assert!(gateway.contains("GATEWAY_CLIENT_CHANNEL_CAPACITY"));
        assert!(!gateway.contains("mpsc::channel(16)"));

        let openai = include_str!("openai.rs")
            .split_once("#[cfg(test)]\nmod tests")
            .expect("OpenAI unit-test module boundary")
            .0;
        for name in [
            "UPSTREAM_ERROR_BODY_MAX_BYTES",
            "UPSTREAM_ERROR_DETAIL_MAX_BYTES",
            "UPSTREAM_ERROR_ECHO_PREFIX_CHARS",
            "UPSTREAM_SSE_FRAME_MAX_BYTES",
        ] {
            assert!(openai.contains(name), "OpenAI must consume params::{name}");
        }
        for alias in [
            "MAX_UPSTREAM_ERROR_BODY_BYTES",
            "MAX_UPSTREAM_ERROR_DETAIL_BYTES",
            "PARTIAL_ECHO_PREFIX_CHARS",
            "MAX_SSE_FRAME_BYTES",
        ] {
            assert!(
                !openai.contains(alias),
                "OpenAI must not own local alias {alias}"
            );
        }

        let anthropic = include_str!("anthropic.rs")
            .split_once("#[cfg(test)]\nmod tests")
            .expect("Anthropic unit-test module boundary")
            .0;
        assert!(anthropic.contains("UPSTREAM_SSE_FRAME_MAX_BYTES"));
        assert!(!anthropic.contains("MAX_SSE_FRAME_BYTES"));
    }

    fn model(base_url: &str, served_model: &str) -> ModelConfig {
        ModelConfig {
            frame_model: "qwen--qwen3--32b".to_string(),
            base_url: base_url.to_string(),
            served_model: served_model.to_string(),
            api_key_env: "PROVIDER_API_KEY".to_string(),
            tokenizer_family: "qwen".to_string(),
            price_per_tick: 1,
            capabilities: Capabilities {
                logprobs: true,
                top_logprobs: Some(5),
                max_output_tokens: Some(openai::DEFAULT_MAX_OUTPUT_TOKENS),
            },
            identity_aliases: Vec::new(),
            vocab_size: None,
            fingerprints: Vec::new(),
        }
    }

    #[test]
    fn resolved_registry_name_changes_only_real_upstream_protocol_identity() {
        let exact = "Qwen/Qwen3-32B";

        let openai_model = model("https://provider.example/v1", "qwen/qwen3-32b");
        let openai = openai::OpenAiConfig::from_model(&openai_model, Some(exact));
        assert_eq!(openai.frame_model, exact);
        assert_eq!(openai.model, openai_model.served_model);
        assert_eq!(openai.base_url, openai_model.base_url);
        assert_eq!(openai.api_key_env, openai_model.api_key_env);
        assert_eq!(openai.capabilities, openai_model.capabilities);
        assert_eq!(
            openai::OpenAiConfig::from_model(&openai_model, None).frame_model,
            openai_model.frame_model
        );

        let anthropic_model = model("https://api.anthropic.com", "claude-provider-model");
        let anthropic = anthropic::AnthropicConfig::from_model(&anthropic_model, Some(exact));
        assert_eq!(anthropic.frame_model, exact);
        assert_eq!(anthropic.model, anthropic_model.served_model);
        assert_eq!(anthropic.base_url, anthropic_model.base_url);
        assert_eq!(anthropic.api_key_env, anthropic_model.api_key_env);
        assert_eq!(
            anthropic::AnthropicConfig::from_model(&anthropic_model, None).frame_model,
            anthropic_model.frame_model
        );
    }

    async fn first_claimed_model(upstream: UpstreamConfig) -> String {
        let (tx, mut rx) = mpsc::channel(1);
        upstream.run(1, None, tx).await;
        match rx.recv().await.unwrap().unwrap() {
            UpstreamEvent::Chunk { chunk, .. } => chunk.manifest.unwrap().claimed_model,
            UpstreamEvent::Accounted(_) => panic!("mock must emit a chunk"),
        }
    }

    #[tokio::test]
    async fn registry_enabled_mock_claims_exact_name_and_disabled_mock_stays_legacy() {
        assert_eq!(
            first_claimed_model(UpstreamConfig::MockWithClaimedModel(
                "Qwen/Qwen3-32B".to_string()
            ))
            .await,
            "Qwen/Qwen3-32B"
        );
        assert_eq!(first_claimed_model(UpstreamConfig::Mock).await, "mock");
    }

    #[test]
    fn unknown_model_output_cap_is_refused_with_an_actionable_message() {
        // unknown != unbounded. The refusal names the model, the missing capability and where to set it.
        for declared in [None, Some(0)] {
            let status = resolve_model_output_cap(declared, "qwen--qwen3--32b", "qwen/qwen3-32b")
                .unwrap_err();
            assert_eq!(status.code(), tonic::Code::FailedPrecondition);
            let message = status.message();
            assert!(message.contains("qwen--qwen3--32b"), "{message}");
            assert!(message.contains("qwen/qwen3-32b"), "{message}");
            assert!(message.contains("max_output_tokens"), "{message}");
            assert!(message.contains("models.json"), "{message}");
        }
        assert_eq!(
            resolve_model_output_cap(Some(40_960), "frame", "served").unwrap(),
            40_960
        );
    }

    #[test]
    fn provider_request_rejections_are_seller_configuration_faults() {
        // The seller builds the whole upstream request, so a `4xx` request rejection is its own config fault.
        for code in [400, 404, 413, 422] {
            assert!(is_seller_config_http_status(code), "{code}");
        }
        // `401/403` keep the dedicated auth class; `408/429` and every `5xx` are transient upstream trouble.
        for code in [401, 403, 408, 429, 500, 502, 503] {
            assert!(!is_seller_config_http_status(code), "{code}");
        }
    }

    #[test]
    fn seller_configuration_annotation_keeps_the_parsed_prefix_and_code() {
        let original = Status::unavailable("upstream HTTP 400 Bad Request: max_tokens too large");
        let annotated =
            annotate_seller_config_fault(original, 400, "qwen/qwen3-32b", 40_961, 40_961);
        assert_eq!(annotated.code(), tonic::Code::Unavailable);
        let message = annotated.message();
        assert!(
            message.starts_with("upstream HTTP 400 Bad Request"),
            "the classifier and the buyer stream-error policy parse this prefix: {message}"
        );
        assert!(message.contains("seller configuration fault"), "{message}");
        assert!(message.contains("qwen/qwen3-32b"), "{message}");
        assert!(message.contains("sent max_tokens=40961"), "{message}");
        assert!(
            message.contains("capabilities.max_output_tokens=40961"),
            "{message}"
        );

        // Transient/auth statuses are left byte-for-byte alone.
        for code in [401, 429, 503] {
            let untouched = Status::unavailable("upstream HTTP x");
            assert_eq!(
                annotate_seller_config_fault(untouched, code, "m", 1, 1).message(),
                "upstream HTTP x",
                "{code}"
            );
        }
    }

    #[test]
    fn structured_accounting_rejects_contradictory_signal_lengths() {
        let result = chunk_with_structured_accounting(CanonChunk {
            token_ids: vec![1, 2],
            logprobs: vec![Default::default()],
            ..CanonChunk::default()
        });
        match result {
            Err(status) => assert_eq!(status.code(), tonic::Code::DataLoss),
            Ok(_) => panic!("contradictory token signals must fail closed"),
        }
    }

    #[test]
    fn empty_no_signal_chunk_accounts_zero() {
        match chunk_with_structured_accounting(CanonChunk::default()).unwrap() {
            UpstreamEvent::Chunk {
                accounted_tokens, ..
            } => assert_eq!(accounted_tokens, 0),
            UpstreamEvent::Accounted(_) => panic!("structured chunk became provider usage"),
        }
    }
}
