//! Seller gateway: accepting buyer connections, stream-session
//! authorization and incremental yielding of the canonical fake-token stream.

use crate::seller::auth::{challenge_bytes, AuthRegistry, HEALTH_CHALLENGE_TC};
use crate::seller::upstream::UpstreamConfig;
use crate::seller::upstream::UpstreamEvent;
use dexdo_core::note::Signature;
use dexdo_proto::{
    CanonChunk, CanonRequest, Challenge, ChallengeRequest, Gateway, GatewayServer, StreamRequest,
};
use rand::RngCore;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, Stream};
use tonic::{Request, Response, Status};

#[derive(Clone, Debug)]
pub struct UpstreamFailure {
    pub token_contract: String,
    pub error_class: &'static str,
    pub retryable: bool,
    pub grpc_status: String,
    pub http_status: Option<u16>,
    event_sequence: Arc<AtomicU64>,
}

impl UpstreamFailure {
    fn from_status(token_contract: &str, status: &Status, event_sequence: Arc<AtomicU64>) -> Self {
        let http_status = status
            .message()
            .strip_prefix("upstream HTTP ")
            .and_then(|suffix| suffix.split_whitespace().next())
            .and_then(|code| code.parse::<u16>().ok());
        let message = status.message().to_ascii_lowercase();
        let error_class = if matches!(http_status, Some(401 | 403))
            || matches!(
                status.code(),
                tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
            ) {
            "auth"
        } else if status.code() == tonic::Code::DeadlineExceeded
            || message.contains("timeout")
            || message.contains("timed out")
        {
            "timeout"
        } else if message.starts_with("upstream connect failed") {
            "connect"
        } else if http_status.is_some() {
            "http"
        } else {
            "upstream"
        };
        let retryable = error_class != "auth"
            && http_status.map_or_else(
                || {
                    matches!(
                        status.code(),
                        tonic::Code::DeadlineExceeded
                            | tonic::Code::ResourceExhausted
                            | tonic::Code::Aborted
                            | tonic::Code::Unavailable
                    )
                },
                |code| code == 408 || code == 429 || code >= 500,
            );
        Self {
            token_contract: token_contract.to_string(),
            error_class,
            retryable,
            grpc_status: format!("{:?}", status.code()),
            http_status,
            event_sequence,
        }
    }

    pub fn next_event_seq(&self) -> u64 {
        self.event_sequence.fetch_add(1, Ordering::Relaxed) + 1
    }
}

/// Per-deal delivery tracking. `count` is the **cumulative** number of canonical tokens the gateway
/// has delivered to the buyer across ALL of this deal's gRPC streams -- a deal/session serves many sequential
/// requests on one `token_contract`, so each stream's relay adds to the same counter. `done` means **no more
/// tokens will ever arrive for this deal/session** -- it is owned by the buyer **session lifecycle**, NOT
/// by any single stream: one gRPC stream ending is NOT the session ending. The seller's `drive_advance` reads
/// both(Acquire) so finalized ticks never exceed delivered tokens, and only stops waiting once the session is
/// truly `done`(or the deal closes on-chain). A per-stream relay that set `done` would make the driver exit
/// after the first request and under-finalize a sustained session -- so the relay only ever touches `count`.
#[derive(Clone, Default)]
pub struct DealDelivery {
    pub count: Arc<AtomicU64>,
    pub done: Arc<AtomicBool>,
    event_sequence: Arc<AtomicU64>,
    terminal_trail_emitted: Arc<AtomicBool>,
}

impl DealDelivery {
    pub fn next_event_seq(&self) -> u64 {
        self.event_sequence.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn claim_terminal_trail(&self) -> bool {
        self.terminal_trail_emitted
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StreamLimits {
    mock_token_count: u64,
    max_ticks: u64,
    tick_size: u64,
}

/// Gateway state, shared across gRPC calls.
pub struct GatewayState {
    pub auth: AuthRegistry,
    /// Per-deal limits. An empty/zero mock entry = seller no-show in mock mode.
    limits: Mutex<HashMap<String, StreamLimits>>,
    /// Per-deal delivered-token tracking, created on first access.
    delivered: Mutex<HashMap<String, DealDelivery>>,
    /// Startup upstream and per-TC routes selected from the existing models config.
    upstream: UpstreamConfig,
    upstreams: Mutex<HashMap<String, UpstreamConfig>>,
    upstream_failure_tx: mpsc::UnboundedSender<UpstreamFailure>,
    upstream_failure_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<UpstreamFailure>>,
}

impl GatewayState {
    /// Gateway with the mock model.
    pub fn new() -> Self {
        Self::with_upstream(UpstreamConfig::Mock)
    }

    /// Gateway with the chosen upstream.
    pub fn with_upstream(upstream: UpstreamConfig) -> Self {
        let (upstream_failure_tx, upstream_failure_rx) = mpsc::unbounded_channel();
        Self {
            auth: AuthRegistry::new(),
            limits: Mutex::new(HashMap::new()),
            delivered: Mutex::new(HashMap::new()),
            upstream,
            upstreams: Mutex::new(HashMap::new()),
            upstream_failure_tx,
            upstream_failure_rx: tokio::sync::Mutex::new(upstream_failure_rx),
        }
    }

    pub fn route_stream(&self, token_contract: &str, upstream: UpstreamConfig) {
        self.upstreams
            .lock()
            .unwrap()
            .insert(token_contract.to_string(), upstream);
    }

    /// Register a deal: the buyer's pubkey for authorization + the fake-token budget.
    pub fn register_stream(
        &self,
        token_contract: &str,
        buyer_pubkey: dexdo_core::note::NotePubkey,
        mock_token_count: u64,
        max_ticks: u64,
        tick_size: u64,
    ) {
        self.auth.register(token_contract, buyer_pubkey);
        self.limits.lock().unwrap().insert(
            token_contract.to_string(),
            StreamLimits {
                mock_token_count,
                max_ticks,
                tick_size,
            },
        );
    }

    /// Remove only one terminal/failed deal from the shared listener.
    pub fn unregister_stream(&self, token_contract: &str) {
        self.auth.unregister(token_contract);
        self.limits.lock().unwrap().remove(token_contract);
        self.delivered.lock().unwrap().remove(token_contract);
        self.upstreams.lock().unwrap().remove(token_contract);
    }

    fn limits(&self, token_contract: &str) -> Option<StreamLimits> {
        self.limits.lock().unwrap().get(token_contract).copied()
    }

    fn stream_token_limit(
        &self,
        token_contract: &str,
        req: Option<&CanonRequest>,
        mock: bool,
    ) -> u64 {
        let Some(limits) = self.limits(token_contract) else {
            return 0;
        };
        if mock {
            return requested_max_tokens(req)
                .map(|max| limits.mock_token_count.min(max))
                .unwrap_or(limits.mock_token_count);
        }
        let market_cap = limits.max_ticks.saturating_mul(limits.tick_size);
        requested_max_tokens(req)
            .map(|max| market_cap.min(max))
            .unwrap_or(market_cap)
    }

    /// The per-deal [`DealDelivery`] tracker(created on first access, shared across the deal's streams). Each
    /// stream's relay adds delivered tokens to the cumulative `count`; `done` is NOT set here -- it means "no
    /// more tokens will ever arrive for this deal/session" and is owned by the buyer session lifecycle,
    /// never by a single stream. The seller driver reads both to bound finalized ticks by delivered tokens.
    pub fn delivery(&self, token_contract: &str) -> DealDelivery {
        self.delivered
            .lock()
            .unwrap()
            .entry(token_contract.to_string())
            .or_default()
            .clone()
    }

    pub(crate) fn upstream(&self, token_contract: &str) -> UpstreamConfig {
        self.upstreams
            .lock()
            .unwrap()
            .get(token_contract)
            .cloned()
            .unwrap_or_else(|| self.upstream.clone())
    }

    pub async fn recv_upstream_failure(&self) -> Option<UpstreamFailure> {
        self.upstream_failure_rx.lock().await.recv().await
    }
}

fn requested_max_tokens(req: Option<&CanonRequest>) -> Option<u64> {
    req.and_then(|r| r.params.as_ref())
        .and_then(|p| (p.max_tokens != 0).then_some(p.max_tokens as u64))
}

impl Default for GatewayState {
    fn default() -> Self {
        Self::new()
    }
}

/// Relay one gRPC stream's upstream chunks to the buyer while adding delivered canonical tokens to the deal's
/// CUMULATIVE `count`. Only successfully-sent `Ok` chunks count(`count`, Release). It is handed only the
/// counter -- NOT the `DealDelivery` -- by design: a single stream ending is not the deal/session ending, so the
/// relay must never set the deal-level `done`(the buyer session lifecycle owns that, see [`DealDelivery`]).
/// Multiple sequential streams on the same deal all add to the same `count`. Pairs with `drive_advance`'s
/// Acquire reads, which translate delivered tokens to ticks.
async fn relay_counting(
    mut up_rx: mpsc::Receiver<Result<UpstreamEvent, Status>>,
    tx: mpsc::Sender<Result<CanonChunk, Status>>,
    count: Arc<AtomicU64>,
    failure_context: Option<(
        String,
        Arc<AtomicU64>,
        mpsc::UnboundedSender<UpstreamFailure>,
    )>,
) {
    let mut failure_reported = false;
    while let Some(event) = up_rx.recv().await {
        match event {
            Ok(UpstreamEvent::Chunk {
                chunk,
                accounted_tokens,
            }) => {
                if tx.send(Ok(chunk)).await.is_err() {
                    break;
                }
                count.fetch_add(accounted_tokens, Ordering::Release);
            }
            Ok(UpstreamEvent::Accounted(tokens)) => {
                count.fetch_add(tokens, Ordering::Release);
            }
            Err(status) => {
                if !failure_reported {
                    if let Some((token_contract, event_sequence, failure_tx)) = &failure_context {
                        let _ = failure_tx.send(UpstreamFailure::from_status(
                            token_contract,
                            &status,
                            event_sequence.clone(),
                        ));
                    }
                    failure_reported = true;
                }
                if tx.send(Err(status)).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// gRPC implementation of the gateway service.
pub struct GatewayService {
    state: Arc<GatewayState>,
}

impl GatewayService {
    pub fn new(state: Arc<GatewayState>) -> Self {
        Self { state }
    }

    /// Wrap into a tonic server for mounting in `Server::builder`.
    pub fn into_server(self) -> GatewayServer<Self> {
        GatewayServer::new(self)
    }
}

type ChunkStream = Pin<Box<dyn Stream<Item = Result<CanonChunk, Status>> + Send>>;

#[tonic::async_trait]
impl Gateway for GatewayService {
    /// Authorization step 1: issue a nonce bound to the token_contract.
    async fn get_challenge(
        &self,
        request: Request<ChallengeRequest>,
    ) -> Result<Response<Challenge>, Status> {
        let tc = request.into_inner().token_contract;
        let mut nonce = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        self.state.auth.issue_challenge(&tc, nonce.clone());
        if tc == HEALTH_CHALLENGE_TC {
            self.state.auth.discard_challenge(&tc, &nonce);
        }
        Ok(Response::new(Challenge {
            nonce,
            token_contract: tc,
        }))
    }

    type OpenStreamStream = ChunkStream;

    /// Step 2: verify the signature against the pubkey from the contract. Without a valid
    /// signature the connection closes BEFORE forwarding. Otherwise -- an incremental stream(R6).
    async fn open_stream(
        &self,
        request: Request<StreamRequest>,
    ) -> Result<Response<Self::OpenStreamStream>, Status> {
        let req = request.into_inner();
        if req.signature.len() != 64 {
            return Err(Status::unauthenticated("bad signature length"));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&req.signature);
        let signature = Signature(sig);

        // Authorization BEFORE any forwarding: a scan/address leak without a key = rejection.
        if !self
            .state
            .auth
            .verify_response(&req.token_contract, &req.nonce, &signature)
        {
            return Err(Status::unauthenticated("challenge-response failed"));
        }
        // (challenge_bytes is used both here and on the buyer's side -- the same domain.)
        let _ = challenge_bytes(&req.token_contract, &req.nonce);

        let request = req.request;
        let upstream = self.state.upstream(&req.token_contract);
        let mock_upstream = matches!(
            upstream,
            UpstreamConfig::Mock
                | UpstreamConfig::MockWithClaimedModel(_)
                | UpstreamConfig::MockScammer
        );
        let count =
            self.state
                .stream_token_limit(&req.token_contract, request.as_ref(), mock_upstream);
        // R1: the upstream adapts the CANONICAL request that arrived in the opening
        // call alongside authorization. The mock model builds fake output from the prompt; the real
        // provider adapter proxies the request and normalizes the SSE(R1/R5/R6).
        // The per-deal delivery tracker is shared across all of this deal's streams (the gateway map returns
        // the same `DealDelivery`), so `count` accumulates over sequential requests. The relay is handed only
        // the counter -- `done` stays owned by the buyer session lifecycle, never set per-stream.
        let delivery = self.state.delivery(&req.token_contract);
        let delivered = delivery.count.clone();
        // Incremental yielding(R6): without buffering. The upstream feeds an internal channel;
        // `relay_counting` forwards each chunk to the buyer AND adds the delivered token count to the deal's
        // cumulative count, so the seller's `drive_advance` can bill only real delivered ticks.
        let (up_tx, up_rx) = mpsc::channel(16);
        tokio::spawn(async move {
            upstream.run(count, request, up_tx).await;
        });
        let (tx, rx) = mpsc::channel::<Result<CanonChunk, Status>>(16);
        tokio::spawn(relay_counting(
            up_rx,
            tx,
            delivered,
            Some((
                req.token_contract,
                delivery.event_sequence,
                self.state.upstream_failure_tx.clone(),
            )),
        ));

        let stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dexdo_proto::SamplingParams;

    async fn relay_with_failure_seam(
        events: Vec<Result<UpstreamEvent, Status>>,
    ) -> (Vec<Result<CanonChunk, Status>>, Option<UpstreamFailure>) {
        let (up_tx, up_rx) = mpsc::channel(16);
        for event in events {
            up_tx.send(event).await.unwrap();
        }
        drop(up_tx);
        let (tx, mut rx) = mpsc::channel(16);
        let (failure_tx, mut failure_rx) = mpsc::unbounded_channel();
        relay_counting(
            up_rx,
            tx,
            Arc::new(AtomicU64::new(0)),
            Some((
                "0:deal".to_string(),
                Arc::new(AtomicU64::new(0)),
                failure_tx,
            )),
        )
        .await;
        let mut buyer = Vec::new();
        while let Some(item) = rx.recv().await {
            buyer.push(item);
        }
        let failure = failure_rx.try_recv().ok();
        assert!(failure_rx.try_recv().is_err(), "duplicate upstream event");
        (buyer, failure)
    }

    /// Drive one gRPC stream through `relay_counting`: emit `n_ok` `Ok` chunks (and optionally a trailing
    /// `Err`), forward to a sink, and return how many items reached the buyer. Adds delivered tokens to `count`.
    async fn run_one_stream(count: Arc<AtomicU64>, n_ok: usize, trailing_err: bool) -> usize {
        let (up_tx, up_rx) = mpsc::channel(16);
        let (tx, mut rx) = mpsc::channel::<Result<CanonChunk, Status>>(16);
        tokio::spawn(async move {
            for _ in 0..n_ok {
                up_tx
                    .send(Ok(
                        crate::seller::upstream::chunk_with_structured_accounting(CanonChunk {
                            token_ids: vec![42],
                            ..CanonChunk::default()
                        }),
                    ))
                    .await
                    .unwrap();
            }
            if trailing_err {
                up_tx
                    .send(Err(Status::internal("upstream error")))
                    .await
                    .unwrap();
            }
        });
        let relay = tokio::spawn(relay_counting(up_rx, tx, count, None));
        let mut forwarded = 0;
        while rx.recv().await.is_some() {
            forwarded += 1;
        }
        relay.await.unwrap();
        forwarded
    }

    /// the relay adds only delivered(`Ok`, successfully-sent) chunks to the deal `count`, and forwards
    /// every item(incl. errors) to the buyer -- but it MUST NOT mark the deal-level `done`: a single gRPC
    /// stream ending is not the deal/session ending(the buyer session lifecycle owns `done`).
    #[tokio::test]
    async fn relay_counts_delivered_chunks_without_marking_deal_done() {
        let delivery = DealDelivery::default();
        let forwarded = run_one_stream(delivery.count.clone(), 3, true).await;
        assert_eq!(
            delivery.count.load(Ordering::Acquire),
            3,
            "only the 3 Ok chunks count as delivered tokens"
        );
        assert_eq!(
            forwarded, 4,
            "all 4 items (3 Ok + 1 Err) forwarded to the buyer"
        );
        assert!(
            !delivery.done.load(Ordering::Acquire),
            "a single stream ending must NOT mark the deal done (the session lifecycle owns `done`)"
        );
    }

    /// a deal/session serves MANY sequential streams on one `token_contract`. Fetching the
    /// tracker by tc returns the SAME per-deal counter, so `count` accumulates across streams, and no stream may
    /// prematurely mark the deal `done` -- otherwise the seller `drive_advance` would catch up to only the first
    /// request and exit, under-finalizing a sustained by-fact session.
    #[tokio::test]
    async fn two_sequential_streams_accumulate_count_and_never_mark_deal_done() {
        let state = GatewayState::new();
        let tc = "0:deal";
        // First request's stream.
        let d1 = state.delivery(tc);
        run_one_stream(d1.count.clone(), 3, false).await;
        assert_eq!(
            d1.count.load(Ordering::Acquire),
            3,
            "first stream delivered 3"
        );
        assert!(
            !d1.done.load(Ordering::Acquire),
            "deal not done after the first stream"
        );
        // Second request's stream -- fetched by tc anew, as a fresh `open_stream` would: the same tracker,
        // still usable, already carrying the first stream's count.
        let d2 = state.delivery(tc);
        assert_eq!(
            d2.count.load(Ordering::Acquire),
            3,
            "the tracker fetched by tc shares the first stream's count"
        );
        run_one_stream(d2.count.clone(), 2, false).await;
        assert_eq!(
            d2.count.load(Ordering::Acquire),
            5,
            "token count accumulates across streams (3 + 2)"
        );
        assert_eq!(
            d1.count.load(Ordering::Acquire),
            5,
            "both handles observe the shared cumulative count"
        );
        assert!(
            !d2.done.load(Ordering::Acquire),
            "still not done -- only the session lifecycle sets it"
        );
    }

    #[test]
    fn real_upstream_limit_uses_request_and_market_not_mock_fixture() {
        let state = GatewayState::new();
        let tc = "0:deal";
        state.limits.lock().unwrap().insert(
            tc.to_string(),
            StreamLimits {
                mock_token_count: 8,
                max_ticks: 3,
                tick_size: 100,
            },
        );
        let req = CanonRequest {
            messages: Vec::new(),
            params: Some(SamplingParams {
                max_tokens: 256,
                ..SamplingParams::default()
            }),
        };

        assert_eq!(
            state.stream_token_limit(tc, Some(&req), false),
            256,
            "real upstream follows request max_tokens, not --mock-token-count"
        );
        assert_eq!(
            state.stream_token_limit(tc, None, false),
            300,
            "without request max_tokens, real upstream is capped by max_ticks * TICK_SIZE"
        );
        assert_eq!(
            state.stream_token_limit(tc, Some(&req), true),
            8,
            "mock upstream keeps the explicit fake-token fixture"
        );
    }

    #[tokio::test]
    async fn relay_counts_tokens_from_structured_signals_not_chunks() {
        let count = Arc::new(AtomicU64::new(0));
        let (up_tx, up_rx) = mpsc::channel(16);
        let (tx, mut rx) = mpsc::channel::<Result<CanonChunk, Status>>(16);
        tokio::spawn(async move {
            up_tx
                .send(Ok(
                    crate::seller::upstream::chunk_with_structured_accounting(CanonChunk {
                        token_ids: vec![1, 2, 3],
                        ..CanonChunk::default()
                    }),
                ))
                .await
                .unwrap();
            up_tx
                .send(Ok(crate::seller::upstream::chunk_with_structured_accounting(
                    CanonChunk::default(),
                )))
                .await
                .unwrap();
        });
        relay_counting(up_rx, tx, count.clone(), None).await;
        while rx.recv().await.is_some() {}
        assert_eq!(
            count.load(Ordering::Acquire),
            4,
            "one chunk may carry multiple canonical tokens; no signal falls back to one token"
        );
    }

    #[tokio::test]
    async fn relay_uses_authoritative_usage_instead_of_anthropic_delta_count() {
        let count = Arc::new(AtomicU64::new(0));
        let (up_tx, up_rx) = mpsc::channel(16);
        let (tx, mut rx) = mpsc::channel(16);
        tokio::spawn(async move {
            for text in ["Hello", " world"] {
                up_tx
                    .send(Ok(UpstreamEvent::Chunk {
                        chunk: CanonChunk {
                            text: text.into(),
                            ..CanonChunk::default()
                        },
                        accounted_tokens: 0,
                    }))
                    .await
                    .unwrap();
            }
            up_tx.send(Ok(UpstreamEvent::Accounted(5))).await.unwrap();
        });
        relay_counting(up_rx, tx, count.clone(), None).await;
        let mut delivered_chunks = 0;
        while rx.recv().await.is_some() {
            delivered_chunks += 1;
        }
        assert_eq!(delivered_chunks, 2);
        assert_eq!(count.load(Ordering::Acquire), 5);
    }

    #[tokio::test]
    async fn upstream_401_is_forwarded_unchanged_and_reported_once_without_detail() {
        let message = "upstream HTTP 401 Unauthorized: sensitive provider error detail redacted";
        let (buyer, failure) = relay_with_failure_seam(vec![
            Err(Status::unavailable(message)),
            Err(Status::unavailable(message)),
        ])
        .await;

        assert_eq!(buyer.len(), 2);
        assert!(buyer.iter().all(|item| item
            .as_ref()
            .is_err_and(|status| status.message() == message)));
        let failure = failure.unwrap();
        assert_eq!(failure.token_contract, "0:deal");
        assert_eq!(failure.error_class, "auth");
        assert!(!failure.retryable);
        assert_eq!(failure.grpc_status, "Unavailable");
        assert_eq!(failure.http_status, Some(401));
        let safe = format!("{failure:?}");
        assert!(!safe.contains("provider error"), "{safe}");
        assert!(!safe.contains("Authorization"), "{safe}");
    }

    #[tokio::test]
    async fn connect_timeout_and_success_have_distinct_safe_failure_outcomes() {
        let sequence = Arc::new(AtomicU64::new(0));
        let connect = UpstreamFailure::from_status(
            "0:deal",
            &Status::unavailable("upstream connect failed: private.invalid/secret-path"),
            sequence.clone(),
        );
        let timeout = UpstreamFailure::from_status(
            "0:deal",
            &Status::deadline_exceeded("upstream request timed out: private detail"),
            sequence,
        );
        let (buyer, success) = relay_with_failure_seam(vec![Ok(UpstreamEvent::Chunk {
            chunk: CanonChunk::default(),
            accounted_tokens: 0,
        })])
        .await;

        assert_eq!(connect.error_class, "connect");
        assert!(connect.retryable);
        assert_eq!(timeout.error_class, "timeout");
        assert!(timeout.retryable);
        for failure in [&connect, &timeout] {
            let safe = format!("{failure:?}");
            assert!(!safe.contains("secret-path"), "{safe}");
            assert!(!safe.contains("private detail"), "{safe}");
        }
        assert_eq!(buyer.len(), 1);
        assert!(success.is_none(), "success must not emit upstream_failed");
    }
}
