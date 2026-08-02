use crate::buyer::api::accounted_tokens;
use crate::buyer::verify::{StreamVerifier, Verdict};
use dexdo_proto::CanonChunk;
use tokio_stream::StreamExt;

pub(super) enum CanonStreamNext {
    Chunk(CanonChunk),
    End,
    Bailed,
    Errored(String),
}

pub(super) struct CanonStreamDriver {
    upstream: tonic::Streaming<CanonChunk>,
    session_closed: tokio::sync::watch::Receiver<bool>,
    verifier: StreamVerifier,
    received: u64,
    max_tokens: u64,
    bailed: bool,
}

impl CanonStreamDriver {
    pub(super) fn new(
        upstream: tonic::Streaming<CanonChunk>,
        session_closed: tokio::sync::watch::Receiver<bool>,
        expected_model: String,
        max_tokens: u64,
    ) -> Self {
        Self {
            upstream,
            session_closed,
            verifier: StreamVerifier::with_expected_model(expected_model),
            received: 0,
            max_tokens,
            bailed: false,
        }
    }

    pub(super) async fn next(&mut self) -> CanonStreamNext {
        if *self.session_closed.borrow() {
            return CanonStreamNext::Errored(
                "deal session closed after accepted-output deadline".to_string(),
            );
        }
        let next = tokio::select! {
            next = self.upstream.next() => next,
            changed = self.session_closed.changed() => {
                if changed.is_ok() && *self.session_closed.borrow() {
                    return CanonStreamNext::Errored(
                        "deal session closed after accepted-output deadline".to_string(),
                    );
                }
                self.upstream.next().await
            }
        };
        match next {
            Some(Ok(chunk)) => {
                if let Verdict::Bail(reason) = self.verifier.verify(&chunk) {
                    tracing::warn!(%reason, "verify: bail -- bailing off the stream (B10)");
                    self.bailed = true;
                    CanonStreamNext::Bailed
                } else {
                    CanonStreamNext::Chunk(chunk)
                }
            }
            Some(Err(e)) => CanonStreamNext::Errored(e.to_string()),
            None => CanonStreamNext::End,
        }
    }

    /// Whether this chunk fits inside what is left of the grant, asked BEFORE it is rendered.
    /// The grant is the request's reservation against the authoritative weekly ceiling, so it is a
    /// hard cap on what may be shown, not a stopping condition to notice afterwards. A chunk carries
    /// as many tokens as the seller chose to put in it: accounting first and rendering second would
    /// let one fat chunk hand the consumer tokens nobody reserved, and `delivered_tokens` would then
    /// carry an excess the next ceiling never sees. A chunk that does not fit is never exposed at
    /// all - it cannot be split, because a partial render cannot be accounted honestly.
    pub(super) fn admits(&self, chunk: &CanonChunk) -> bool {
        self.received.saturating_add(accounted_tokens(chunk)) <= self.max_tokens
    }

    pub(super) fn account_rendered(&mut self, chunk: &CanonChunk) -> bool {
        self.received = self.received.saturating_add(accounted_tokens(chunk));
        self.received >= self.max_tokens
    }

    pub(super) fn bailed(&self) -> bool {
        self.bailed
    }

    pub(super) fn received(&self) -> u64 {
        self.received
    }
}
