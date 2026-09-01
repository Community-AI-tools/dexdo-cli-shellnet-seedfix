use super::exhausted_transient_read;
use dexdo_core::{ChainError, CHAIN_READ_EXHAUSTED_MESSAGE_PREFIX};

#[tokio::test(start_paused = true)]
async fn producer_exhaustion_context_arms_seller_classifier() {
    let outcome: anyhow::Result<()> = dexdo_core::chain::retry_transient_read(|| async {
        std::future::pending::<anyhow::Result<()>>().await
    })
    .await;
    let produced = outcome
        .expect_err("a read that never answers must exhaust the retry policy")
        .to_string();

    assert!(
        produced.starts_with(CHAIN_READ_EXHAUSTED_MESSAGE_PREFIX),
        "the producer must identify its exhausted-read result with the shared classification"
    );
    assert!(
        exhausted_transient_read(&ChainError::Chain(format!(
            "coherent snapshot failed: {produced}"
        ))),
        "the seller classifier must recognize the producer's exhausted-read result"
    );
}
