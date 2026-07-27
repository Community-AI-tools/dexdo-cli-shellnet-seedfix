//! Gateway upstream token source. Adapters:
//! - [`mock`] -- mock model(`--mock-model`): deterministic fake tokens from the prompt
//! - [`openai`] -- **real OpenAI-compatible upstream**: Groq,
//! streaming SSE -> normalization into `CanonChunk`(R1/R2/R5/R6).
//! - [`anthropic`] -- native Anthropic Messages API, streaming SSE -> the same canon.
//! Both branches normalize the upstream output into a single canonical stream(R1). Accounting is
//! done by the gateway from structured token signals(`token_ids`/logprobs) and converted to ticks
//! using the canonical `TICK_SIZE`; `CanonChunk` is only a streaming container.

pub mod anthropic;
pub mod mock;
pub mod openai;

use dexdo_proto::{CanonChunk, CanonRequest};
use tokio::sync::mpsc;
use tonic::Status;

/// Seller-internal upstream event. Accounting is kept separate from the buyer-facing canon so
/// providers that report authoritative usage without token ids do not have to invent token data.
pub enum UpstreamEvent {
    Chunk {
        chunk: CanonChunk,
        accounted_tokens: u64,
    },
    Accounted(u64),
}

pub fn chunk_with_structured_accounting(chunk: CanonChunk) -> UpstreamEvent {
    let accounted_tokens = (chunk.token_ids.len() as u64)
        .max(chunk.logprobs.len() as u64)
        .max(1);
    UpstreamEvent::Chunk {
        chunk,
        accounted_tokens,
    }
}

pub type UpstreamResult = Result<UpstreamEvent, Status>;

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
}
