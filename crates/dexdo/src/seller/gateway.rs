//! Seller gateway: accepting buyer connections, stream-session
//! authorization and incremental yielding of the canonical fake-token stream.

use crate::seller::auth::{challenge_bytes, AuthRegistry, HEALTH_CHALLENGE_TC};
use crate::seller::capacity::{
    lock_or_recover, CapacityManager, CapacityReservation, CapacitySnapshot, ReserveError,
    POISONED_LOCK_MESSAGE,
};
use crate::seller::upstream::is_seller_config_http_status;
use crate::seller::upstream::UpstreamConfig;
use crate::seller::upstream::UpstreamEvent;
use anyhow::{anyhow, Result as AnyResult};
use dexdo_core::note::Signature;
use dexdo_core::params::{GATEWAY_CLIENT_CHANNEL_CAPACITY, GATEWAY_UPSTREAM_CHANNEL_CAPACITY};
use dexdo_core::{DealChainState, DealSubscription};
use dexdo_proto::{
    CanonChunk, CanonRequest, Challenge, ChallengeRequest, Gateway, GatewayServer, StreamRequest,
};
use rand::RngCore;
use std::collections::HashMap;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, watch};
use tokio_stream::{wrappers::ReceiverStream, Stream};
use tonic::{Request, Response, Status};

const DELIVERY_UPDATE_LOCK: &str = "seller gateway delivery update";
const GATEWAY_LIMITS_LOCK: &str = "seller gateway limits";
const GATEWAY_DELIVERED_LOCK: &str = "seller gateway delivered";
const GATEWAY_UPSTREAMS_LOCK: &str = "seller gateway upstreams";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ChainUnavailableAction {
    #[default]
    Stop,
    KeepServing,
}

impl ChainUnavailableAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::KeepServing => "keep_serving",
        }
    }

    pub fn from_config(value: &str) -> Option<Self> {
        match value {
            "stop" => Some(Self::Stop),
            "keep_serving" => Some(Self::KeepServing),
            _ => None,
        }
    }

    pub fn supported_values() -> &'static [&'static str] {
        &["stop", "keep_serving"]
    }
}

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
        } else if http_status.is_some_and(is_seller_config_http_status) {
            // the seller builds the whole upstream request, so a `4xx` request rejection is the
            // seller's own configuration fault -- a distinct, never-retryable class, not a generic `http`.
            "seller_config"
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
/// both (Acquire) so finalized ticks never exceed delivered tokens, and only stops waiting once the session is
/// truly `done` (or the deal closes on-chain). A per-stream relay that set `done` would make the driver exit
/// after the first request and under-finalize a sustained session -- so the relay only ever touches `count`.
#[derive(Clone, Default)]
pub struct DealDelivery {
    pub count: Arc<AtomicU64>,
    pub done: Arc<AtomicBool>,
    update_lock: Arc<Mutex<()>>,
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

/// Terminal classification for one request's authoritative delivery accounting.

/// Capacity consumers use this only to reconcile an already-created request reservation. Provider-specific
/// counting remains entirely inside [`crate::seller::upstream`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthoritativeDeliveryFinish {
    /// The upstream ended cleanly and every forwarded output delta has an authoritative count.
    Clean,
    /// The request ended early, but every output delta that was forwarded has an authoritative count.
    Interrupted,
    /// Some non-empty output was forwarded without a valid authoritative count.
    AmbiguousUsage,
}

/// Request-scoped accounting event emitted by the gateway relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthoritativeDeliveryEvent {
    /// A positive authoritative delta. Structured-chunk deltas are emitted after reserving buyer-stream
    /// capacity and before forwarding; separate usage deltas follow their already-forwarded output.
    Delivered(NonZeroU64),
    /// Emitted exactly once when the relay terminates.
    Finished(AuthoritativeDeliveryFinish),
}

/// Narrow seam for consumers that must durably reconcile request reservations with authoritative delivery.

/// Implementations must record each event before returning. A recorder failure terminates the stream
/// fail-closed; the gateway never asks the recorder to derive tokens from text, bytes, words or frames.
#[allow(clippy::result_large_err)]
pub trait AuthoritativeDeliveryRecorder: Send + Sync {
    fn record_authoritative_delivery(
        &self,
        event: AuthoritativeDeliveryEvent,
    ) -> Result<(), Status>;

    /// Authorize a chunk whose authoritative token count can only arrive after it.

    /// The relay calls this BEFORE such a chunk reaches the buyer, so accounting stands on the path
    /// between receiving output and exposing it on the separate-usage branch too, not only on the
    /// structured one. Refusing ends the request; it never truncates the answer silently.
    /// The default recorder holds no reservation, so it has nothing to refuse against.

    /// `min_billable` is the largest authoritative figure this upstream has already charged for one
    /// run of unaccounted output on this stream -- the seller's own recorded number, never a count
    /// derived from text, bytes, words or frames -- and zero before the first one arrives.
    fn authorize_unaccounted_exposure(&self, _min_billable: u64) -> Result<(), Status> {
        Ok(())
    }
}

impl AuthoritativeDeliveryRecorder for DealDelivery {
    fn record_authoritative_delivery(
        &self,
        event: AuthoritativeDeliveryEvent,
    ) -> Result<(), Status> {
        match event {
            AuthoritativeDeliveryEvent::Delivered(tokens) => {
                let _guard = self.update_lock.lock().map_err(|_| {
                    capacity_status(anyhow!(
                        "{POISONED_LOCK_MESSAGE}: {DELIVERY_UPDATE_LOCK}"
                    ))
                })?;
                let next = checked_authoritative_tokens(&self.count, tokens.get())?;
                self.count.store(next, Ordering::Release);
                Ok(())
            }
            AuthoritativeDeliveryEvent::Finished(_) => Ok(()),
        }
    }
}

struct CapacityDeliveryRecorder {
    reservation: CapacityReservation,
    delivery: DealDelivery,
}

impl AuthoritativeDeliveryRecorder for CapacityDeliveryRecorder {
    fn record_authoritative_delivery(
        &self,
        event: AuthoritativeDeliveryEvent,
    ) -> Result<(), Status> {
        match event {
            AuthoritativeDeliveryEvent::Delivered(tokens) => {
                let _guard = self.delivery.update_lock.lock().map_err(|_| {
                    capacity_status(anyhow!(
                        "{POISONED_LOCK_MESSAGE}: {DELIVERY_UPDATE_LOCK}"
                    ))
                })?;
                // The high-water overflow is decided on the FULL delta before anything is recorded,
                // so an overflowing stream still changes no state and exposes no chunk -- a coalesced
                // write would otherwise report nothing durable and skip the check below entirely.
                let _ = checked_authoritative_tokens(&self.delivery.count, tokens.get())?;
                // The counter drives on-chain claims, and `reconcile_deal` rejects a claim that ran
                // beyond DURABLE local delivery, so it may only advance by what actually reached disk.
                // A coalesced write returns 0 here and the remainder at the request terminal below.
                let durable = self
                    .reservation
                    .record_delivered(tokens.get())
                    .map_err(capacity_status)?;
                if durable > 0 {
                    let next = checked_authoritative_tokens(&self.delivery.count, durable)?;
                    self.delivery.count.store(next, Ordering::Release);
                }
                Ok(())
            }
            AuthoritativeDeliveryEvent::Finished(finish) => {
                let durable = match finish {
                    AuthoritativeDeliveryFinish::Clean
                    | AuthoritativeDeliveryFinish::Interrupted => {
                        self.reservation.finish_exact().map_err(capacity_status)?
                    }
                    AuthoritativeDeliveryFinish::AmbiguousUsage => self
                        .reservation
                        .finish_ambiguous()
                        .map_err(capacity_status)?,
                };
                if durable > 0 {
                    let _guard = self.delivery.update_lock.lock().map_err(|_| {
                        capacity_status(anyhow!(
                            "{POISONED_LOCK_MESSAGE}: {DELIVERY_UPDATE_LOCK}"
                        ))
                    })?;
                    let next = checked_authoritative_tokens(&self.delivery.count, durable)?;
                    self.delivery.count.store(next, Ordering::Release);
                }
                Ok(())
            }
        }
    }

    fn authorize_unaccounted_exposure(&self, min_billable: u64) -> Result<(), Status> {
        self.reservation
            .authorize_exposure(min_billable)
            .map_err(reserve_status)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StreamLimits {
    mock_token_count: u64,
    deal: DealSubscription,
}

/// Gateway state, shared across gRPC calls.
pub struct GatewayState {
    pub auth: AuthRegistry,
    /// Per-deal limits. An empty/zero mock entry = seller no-show in mock mode.
    limits: Mutex<HashMap<String, StreamLimits>>,
    /// Per-deal delivered-token tracking, created on first access.
    delivered: Mutex<HashMap<String, DealDelivery>>,
    /// Durable per-TC capacity derived only from strict on-chain deal state.
    capacity: CapacityManager,
    /// Upstream choice (mock model vs the real adapter). Immutable for the gateway's lifetime.
    upstream: UpstreamConfig,
    upstreams: Mutex<HashMap<String, UpstreamConfig>>,
    upstream_failure_tx: mpsc::UnboundedSender<UpstreamFailure>,
    upstream_failure_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<UpstreamFailure>>,
    chain_unavailable: watch::Sender<bool>,
    keep_serving_when_chain_unavailable: AtomicBool,
}

impl GatewayState {
    /// Gateway with the mock model.
    pub fn new() -> Self {
        Self::with_upstream(UpstreamConfig::Mock)
    }

    /// Gateway with the chosen upstream.
    pub fn with_upstream(upstream: UpstreamConfig) -> Self {
        Self::with_capacity(upstream, CapacityManager::in_memory())
    }

    pub fn with_upstream_and_deals_dir(upstream: UpstreamConfig, deals_dir: PathBuf) -> Self {
        Self::with_capacity(upstream, CapacityManager::in_deals_dir(deals_dir))
    }

    fn with_capacity(upstream: UpstreamConfig, capacity: CapacityManager) -> Self {
        let (upstream_failure_tx, upstream_failure_rx) = mpsc::unbounded_channel();
        let (chain_unavailable, _) = watch::channel(false);
        Self {
            auth: AuthRegistry::new(),
            limits: Mutex::new(HashMap::new()),
            delivered: Mutex::new(HashMap::new()),
            capacity,
            upstream,
            upstreams: Mutex::new(HashMap::new()),
            upstream_failure_tx,
            upstream_failure_rx: tokio::sync::Mutex::new(upstream_failure_rx),
            chain_unavailable,
            keep_serving_when_chain_unavailable: AtomicBool::new(false),
        }
    }

    pub fn set_chain_unavailable_action(&self, action: ChainUnavailableAction) {
        self.keep_serving_when_chain_unavailable.store(
            action == ChainUnavailableAction::KeepServing,
            Ordering::Release,
        );
    }

    pub fn report_chain_unavailable(&self, token_contract: &str) {
        if self
            .keep_serving_when_chain_unavailable
            .load(Ordering::Acquire)
        {
            return;
        }
        tracing::error!(
            event = "seller_chain_unavailable",
            token_contract,
            action = "stop",
            "required chain read exhausted its retry budget; stopping seller delivery"
        );
        self.chain_unavailable.send_replace(true);
    }

    fn chain_unavailable(&self) -> bool {
        *self.chain_unavailable.borrow()
    }

    fn subscribe_chain_unavailable(&self) -> watch::Receiver<bool> {
        self.chain_unavailable.subscribe()
    }

    pub fn route_stream(&self, token_contract: &str, upstream: UpstreamConfig) {
        lock_or_recover(&self.upstreams, GATEWAY_UPSTREAMS_LOCK)
            .insert(token_contract.to_string(), upstream);
    }

    /// Register a deal from one coherent strict chain snapshot before exposing it to the buyer.
    pub fn register_stream(
        &self,
        token_contract: &str,
        buyer_pubkey: dexdo_core::note::NotePubkey,
        mock_token_count: u64,
        state: DealChainState,
        deal: DealSubscription,
    ) -> AnyResult<()> {
        let token_contract_display = dexdo_core::address::display_self_dapp(token_contract);
        let snapshot = self
            .capacity
            .reconcile_deal(&token_contract.to_string(), state, deal)?
            .ok_or_else(|| anyhow!("TokenContract {token_contract_display} is terminal"))?;
        let local_delivered =
            u64::try_from(snapshot.local_delivered_after_anchor).map_err(|_| {
                anyhow!(
                "TokenContract {token_contract_display} durable local delivery {} exceeds gateway uint64",
                snapshot.local_delivered_after_anchor
            )
            })?;
        self.limits
            .lock()
            .map_err(|_| anyhow!("{POISONED_LOCK_MESSAGE}: {GATEWAY_LIMITS_LOCK}"))?
            .insert(
                token_contract.to_string(),
                StreamLimits {
                    mock_token_count,
                    deal,
                },
            );
        self.auth.register(token_contract, buyer_pubkey);
        self.delivery(token_contract)
            .count
            .store(local_delivered, Ordering::Release);
        Ok(())
    }

    /// Remove only one terminal/failed deal from the shared listener.
    pub fn unregister_stream(&self, token_contract: &str) {
        if !self.chain_unavailable() {
            self.auth.unregister(token_contract);
        }
        lock_or_recover(&self.limits, GATEWAY_LIMITS_LOCK).remove(token_contract);
        lock_or_recover(&self.delivered, GATEWAY_DELIVERED_LOCK).remove(token_contract);
        lock_or_recover(&self.upstreams, GATEWAY_UPSTREAMS_LOCK).remove(token_contract);
    }

    pub fn reconcile_subscription_capacity(
        &self,
        token_contract: &str,
        state: DealChainState,
        subscription: DealSubscription,
    ) -> AnyResult<Option<CapacitySnapshot>> {
        if !subscription.is_subscription() {
            let token_contract = dexdo_core::address::display_self_dapp(token_contract);
            return Err(anyhow!(
                "TokenContract {token_contract}: subscription keeper observed an ordinary deal shape"
            ));
        }
        self.capacity
            .reconcile_deal(&token_contract.to_string(), state, subscription)
    }

    pub fn reconcile_deal_capacity(
        &self,
        token_contract: &str,
        state: DealChainState,
        deal: DealSubscription,
    ) -> AnyResult<Option<CapacitySnapshot>> {
        self.capacity
            .reconcile_deal(&token_contract.to_string(), state, deal)
    }

    pub fn reconcile_ordinary_capacity(
        &self,
        token_contract: &str,
        state: DealChainState,
    ) -> AnyResult<Option<CapacitySnapshot>> {
        let token_contract_display = dexdo_core::address::display_self_dapp(token_contract);
        let deal = self
            .limits(token_contract)
            .ok_or_else(|| {
                anyhow!("TokenContract {token_contract_display}: deal capacity is not registered")
            })?
            .deal;
        if deal.is_subscription() {
            return Err(anyhow!(
                "TokenContract {token_contract_display}: ordinary claim driver observed a subscription deal shape"
            ));
        }
        self.reconcile_deal_capacity(token_contract, state, deal)
    }

    pub fn mark_subscription_terminal(&self, token_contract: &str) -> AnyResult<()> {
        self.mark_deal_terminal(token_contract)
    }

    pub fn mark_deal_terminal(&self, token_contract: &str) -> AnyResult<()> {
        self.capacity.mark_terminal(&token_contract.to_string())
    }

    #[cfg(test)]
    pub(crate) fn capacity_snapshot(
        &self,
        token_contract: &str,
    ) -> AnyResult<Option<CapacitySnapshot>> {
        self.capacity.snapshot(&token_contract.to_string())
    }

    #[cfg(test)]
    pub(crate) fn poison_limits_for_test(&self, panic_message: &'static str) {
        let _guard = self
            .limits
            .lock()
            .expect("gateway limits lock starts healthy");
        panic!("{panic_message}");
    }

    fn limits(&self, token_contract: &str) -> Option<StreamLimits> {
        lock_or_recover(&self.limits, GATEWAY_LIMITS_LOCK)
            .get(token_contract)
            .copied()
    }

    #[cfg(test)]
    fn stream_token_limit(
        &self,
        token_contract: &str,
        req: Option<&CanonRequest>,
        mock: bool,
    ) -> u64 {
        let Some(limits) = self.limits(token_contract) else {
            return 0;
        };
        Self::registered_stream_token_limit(limits, req, mock)
    }

    fn registered_stream_token_limit(
        limits: StreamLimits,
        req: Option<&CanonRequest>,
        mock: bool,
    ) -> u64 {
        if mock {
            return requested_max_tokens(req)
                .map(|max| limits.mock_token_count.min(max))
                .unwrap_or(limits.mock_token_count);
        }
        requested_max_tokens(req).unwrap_or(u64::MAX)
    }

    /// The per-deal [`DealDelivery`] tracker (created on first access, shared across the deal's streams). Each
    /// stream's relay adds delivered tokens to the cumulative `count`; `done` is NOT set here -- it means "no
    /// more tokens will ever arrive for this deal/session" and is owned by the buyer session lifecycle,
    /// never by a single stream. The seller driver reads both to bound finalized ticks by delivered tokens.
    pub fn delivery(&self, token_contract: &str) -> DealDelivery {
        lock_or_recover(&self.delivered, GATEWAY_DELIVERED_LOCK)
            .entry(token_contract.to_string())
            .or_default()
            .clone()
    }

    pub(crate) fn upstream(&self, token_contract: &str) -> UpstreamConfig {
        lock_or_recover(&self.upstreams, GATEWAY_UPSTREAMS_LOCK)
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

/// Relay one gRPC stream's upstream chunks to the buyer. Structured-accounting deltas are recorded after
/// reserving buyer-stream capacity and before forwarding; separate usage is recorded after its preceding
/// output. The request-scoped recorder receives exactly one terminal classification, but the relay never sets
/// deal-level `done`: one request ending is not the session ending. The default
/// [`DealDelivery`] recorder adds exact deltas to the shared cumulative count consumed by `drive_advance`;
/// capacity-aware recorders may additionally persist reservation reconciliation without deriving provider
/// counts themselves.
#[cfg(test)]
pub(crate) async fn relay_counting<R>(
    up_rx: mpsc::Receiver<Result<UpstreamEvent, Status>>,
    tx: mpsc::Sender<Result<CanonChunk, Status>>,
    recorder: R,
    failure_context: Option<(
        String,
        Arc<AtomicU64>,
        mpsc::UnboundedSender<UpstreamFailure>,
    )>,
) where
    R: AuthoritativeDeliveryRecorder,
{
    relay_counting_with_chain_availability(up_rx, tx, recorder, failure_context, None).await;
}

async fn relay_counting_with_chain_availability<R>(
    mut up_rx: mpsc::Receiver<Result<UpstreamEvent, Status>>,
    tx: mpsc::Sender<Result<CanonChunk, Status>>,
    recorder: R,
    failure_context: Option<(
        String,
        Arc<AtomicU64>,
        mpsc::UnboundedSender<UpstreamFailure>,
    )>,
    mut chain_unavailable: Option<watch::Receiver<bool>>,
) where
    R: AuthoritativeDeliveryRecorder,
{
    let mut awaiting_usage = false;
    // the largest authoritative figure this upstream has already charged for ONE run of
    // unaccounted output on this stream. It is the seller's own recorded number, so using it as the
    // bound on the next run derives nothing from text, bytes, words or frames.
    let mut charged_per_run = 0u64;
    let mut terminal_error = None;
    let finish = loop {
        let event = if let Some(unavailable) = chain_unavailable.as_mut() {
            if *unavailable.borrow() {
                terminal_error = Some(chain_unavailable_status());
                break if awaiting_usage {
                    AuthoritativeDeliveryFinish::AmbiguousUsage
                } else {
                    AuthoritativeDeliveryFinish::Interrupted
                };
            }
            tokio::select! {
                biased;
                changed = unavailable.changed() => {
                    if changed.is_ok() && *unavailable.borrow() {
                        terminal_error = Some(chain_unavailable_status());
                        break if awaiting_usage {
                            AuthoritativeDeliveryFinish::AmbiguousUsage
                        } else {
                            AuthoritativeDeliveryFinish::Interrupted
                        };
                    }
                    if changed.is_err() {
                        up_rx.recv().await
                    } else {
                        continue;
                    }
                }
                event = up_rx.recv() => event,
            }
        } else {
            up_rx.recv().await
        };
        let Some(event) = event else {
            if awaiting_usage {
                terminal_error = Some(Status::data_loss(
                    "delivered output ended without authoritative token usage",
                ));
                break AuthoritativeDeliveryFinish::AmbiguousUsage;
            }
            break AuthoritativeDeliveryFinish::Clean;
        };
        match event {
            Ok(UpstreamEvent::Chunk {
                chunk,
                accounted_tokens,
            }) => {
                if accounted_tokens > 0 && awaiting_usage {
                    terminal_error = Some(Status::data_loss(
                        "upstream mixed separate usage with structured token accounting",
                    ));
                    break AuthoritativeDeliveryFinish::AmbiguousUsage;
                }
                let needs_usage = accounted_tokens == 0
                    && (!chunk.text.is_empty() || !chunk.reasoning.is_empty());
                // on the separate-usage branch the authoritative number arrives after the
                // content, so recording it before forwarding is impossible -- but *checking* the
                // request reservation is not. Ask it before the chunk crosses, so no output is
                // exposed that the seller has already established it could never bill. This runs
                // ahead of the first token, so a request that cannot be paid for is refused whole
                // instead of being answered and then reconciled into a loss. The reservation is asked
                // whether it can still pay what this upstream has already shown a run costs: asking
                // only whether it is non-empty refuses at exactly zero and nowhere else, so a
                // remainder that lands SHORT of the next run rather than on top of it would expose
                // one more run and then have its figure refused.
                if needs_usage {
                    if let Err(status) = recorder.authorize_unaccounted_exposure(charged_per_run) {
                        terminal_error = Some(status);
                        break if awaiting_usage {
                            AuthoritativeDeliveryFinish::AmbiguousUsage
                        } else {
                            AuthoritativeDeliveryFinish::Interrupted
                        };
                    }
                }
                let permit = match tx.reserve().await {
                    Ok(permit) => permit,
                    Err(_) => {
                        break if awaiting_usage {
                            AuthoritativeDeliveryFinish::AmbiguousUsage
                        } else {
                            AuthoritativeDeliveryFinish::Interrupted
                        };
                    }
                };
                if accounted_tokens > 0 {
                    let tokens = NonZeroU64::new(accounted_tokens)
                        .expect("positive branch has nonzero delta");
                    if let Err(status) = recorder.record_authoritative_delivery(
                        AuthoritativeDeliveryEvent::Delivered(tokens),
                    ) {
                        terminal_error = Some(status);
                        break AuthoritativeDeliveryFinish::Interrupted;
                    }
                }
                permit.send(Ok(chunk));
                if needs_usage {
                    awaiting_usage = true;
                }
            }
            Ok(UpstreamEvent::Accounted(tokens)) => {
                if tokens == 0 || !awaiting_usage {
                    terminal_error = Some(Status::data_loss(
                        "authoritative usage has no preceding delivered output",
                    ));
                    break if awaiting_usage {
                        AuthoritativeDeliveryFinish::AmbiguousUsage
                    } else {
                        AuthoritativeDeliveryFinish::Interrupted
                    };
                }
                let tokens = NonZeroU64::new(tokens).expect("positive branch has nonzero delta");
                if let Err(status) = recorder
                    .record_authoritative_delivery(AuthoritativeDeliveryEvent::Delivered(tokens))
                {
                    terminal_error = Some(status);
                    break AuthoritativeDeliveryFinish::AmbiguousUsage;
                }
                charged_per_run = charged_per_run.max(tokens.get());
                awaiting_usage = false;
            }
            Err(status) => {
                if let Some((token_contract, event_sequence, failure_tx)) = &failure_context {
                    let _ = failure_tx.send(UpstreamFailure::from_status(
                        token_contract,
                        &status,
                        event_sequence.clone(),
                    ));
                }
                terminal_error = Some(status);
                break if awaiting_usage {
                    AuthoritativeDeliveryFinish::AmbiguousUsage
                } else {
                    AuthoritativeDeliveryFinish::Interrupted
                };
            }
        }
    };
    if let Err(status) =
        recorder.record_authoritative_delivery(AuthoritativeDeliveryEvent::Finished(finish))
    {
        terminal_error.get_or_insert(status);
    }
    if let Some(status) = terminal_error {
        let _ = tx.send(Err(status)).await;
    }
}

fn chain_unavailable_status() -> Status {
    Status::failed_precondition(
        "SELLER_CHAIN_UNAVAILABLE: required chain read exhausted its retry budget; restore chain access and restart the seller",
    )
}

fn capacity_status(error: impl std::fmt::Display) -> Status {
    Status::data_loss(format!("seller deal capacity persistence failed: {error}"))
}

fn reserve_status(error: ReserveError) -> Status {
    match error {
        ReserveError::Exhausted => {
            Status::resource_exhausted("deal delivery capacity is exhausted")
        }
        ReserveError::UnknownDeal | ReserveError::Terminal => {
            Status::failed_precondition(error.to_string())
        }
        ReserveError::InvalidState(_) => capacity_status(error),
    }
}

#[allow(clippy::result_large_err)]
fn checked_authoritative_tokens(count: &AtomicU64, tokens: u64) -> Result<u64, Status> {
    debug_assert!(tokens > 0);
    count
        .load(Ordering::Acquire)
        .checked_add(tokens)
        .ok_or_else(|| Status::data_loss("authoritative delivered-token high-water overflow"))
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
    /// signature the connection closes BEFORE forwarding. Otherwise -- an incremental stream (R6).
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

        if self.state.chain_unavailable() {
            return Err(chain_unavailable_status());
        }

        let limits = self.state.limits(&req.token_contract).ok_or_else(|| {
            Status::failed_precondition("this deal is not registered on this gateway")
        })?;

        let request = req.request;
        let upstream = self.state.upstream(&req.token_contract);
        let mock_upstream = matches!(
            upstream,
            UpstreamConfig::Mock
                | UpstreamConfig::MockWithClaimedModel(_)
                | UpstreamConfig::MockScammer
        );
        let requested = GatewayState::registered_stream_token_limit(
            limits,
            request.as_ref(),
            mock_upstream,
        );
        // The per-deal reservation is durably committed before the upstream task can observe the request.
        // Both ordinary and subscription limits come only from the matched TC's strict chain snapshot.
        let reservation = if requested > 0 {
            Some(
                self.state
                    .capacity
                    .reserve(&req.token_contract, requested)
                    .map_err(reserve_status)?,
            )
        } else {
            None
        };
        let count = reservation
            .as_ref()
            .map(CapacityReservation::amount)
            .unwrap_or(requested);
        // R1: the upstream adapts the CANONICAL request that arrived in the opening
        // call alongside authorization. The mock model builds fake output from the prompt; the real
        // provider adapter proxies the request and normalizes the SSE (R1/R5/R6).
        // The per-deal delivery tracker is shared across all of this deal's streams (the gateway map returns
        // the same `DealDelivery`), so `count` accumulates over sequential requests. The relay is handed only
        // the counter -- `done` stays owned by the buyer session lifecycle, never set per-stream.
        let delivered = self.state.delivery(&req.token_contract);
        let chain_unavailable = self.state.subscribe_chain_unavailable();
        let failure_context = (
            req.token_contract.clone(),
            delivered.event_sequence.clone(),
            self.state.upstream_failure_tx.clone(),
        );
        // Incremental yielding (R6): without buffering. The upstream feeds an internal channel;
        // `relay_counting` forwards each chunk to the buyer AND adds the delivered token count to the deal's
        // cumulative count, so the seller's `drive_advance` can bill only real delivered ticks.
        let (up_tx, up_rx) = mpsc::channel(GATEWAY_UPSTREAM_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            upstream.run(count, request, up_tx).await;
        });
        let (tx, rx) = mpsc::channel::<Result<CanonChunk, Status>>(GATEWAY_CLIENT_CHANNEL_CAPACITY);
        if let Some(reservation) = reservation {
            tokio::spawn(relay_counting_with_chain_availability(
                up_rx,
                tx,
                CapacityDeliveryRecorder {
                    reservation,
                    delivery: delivered,
                },
                Some(failure_context),
                Some(chain_unavailable),
            ));
        } else {
            tokio::spawn(relay_counting_with_chain_availability(
                up_rx,
                tx,
                delivered,
                Some(failure_context),
                Some(chain_unavailable),
            ));
        }

        let stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dexdo_core::{order_flags, LocalNote, Note, NotePubkey, SUBSCRIPTION_WEEKS, TICK_SIZE};
    use dexdo_proto::SamplingParams;
    use tokio_stream::StreamExt;

    fn recorder(count: Arc<AtomicU64>) -> DealDelivery {
        DealDelivery {
            count,
            ..DealDelivery::default()
        }
    }

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
            recorder(Arc::new(AtomicU64::new(0))),
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

    fn subscription_state(pending: u128) -> DealChainState {
        DealChainState {
            funded: true,
            opened: true,
            probe_accepted: true,
            disputed: false,
            deposit: 1,
            finalized_owed: 0,
            tokens_final: pending,
            tokens_pending: pending,
            probe_tick: 0,
            funded_time: Some(1),
            probe_time: 1,
            last_claim_time: 1,
            dispute_time: 0,
        }
    }

    fn subscription_shape() -> DealSubscription {
        DealSubscription {
            deal_flags: order_flags::SUBSCRIPTION,
            sub_weeks: 4,
            week_index: 0,
            tokens_per_week: 2 * TICK_SIZE,
            funded_tokens: 8 * TICK_SIZE,
            tokens_paid: 0,
            period_start: 1,
            week_base_tokens: 0,
        }
    }

    fn ordinary_shape(funded_tokens: u128) -> DealSubscription {
        DealSubscription {
            deal_flags: 0,
            sub_weeks: 0,
            week_index: 0,
            tokens_per_week: funded_tokens,
            funded_tokens,
            tokens_paid: 0,
            period_start: 0,
            week_base_tokens: 0,
        }
    }

    fn buyer_pubkey() -> NotePubkey {
        NotePubkey {
            x: [1; 32],
            ed: [2; 32],
        }
    }

    #[tokio::test]
    async fn upstream_401_is_forwarded_unchanged_and_reported_once_without_detail() {
        let message = "upstream HTTP 401 Unauthorized: sensitive provider error detail redacted";
        let (buyer, failure) =
            relay_with_failure_seam(vec![Err(Status::unavailable(message))]).await;

        assert_eq!(buyer.len(), 1);
        assert!(buyer[0]
            .as_ref()
            .is_err_and(|status| status.message() == message));
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
    async fn upstream_request_rejection_is_reported_as_a_seller_configuration_fault() {
        // a provider `400` on a request the seller fully built is its own configuration fault -- a
        // distinct, never-retryable class, so the operator sees the cause instead of a generic `http`.
        let message =
            "upstream HTTP 400 Bad Request: max_tokens must be less than or equal to 40960 \
             [seller configuration fault: model \"qwen/qwen3-32b\" sent max_tokens=2000000 at \
             capabilities.max_output_tokens=2000000; correct this model's max_output_tokens in the \
             models config]";
        let (buyer, failure) =
            relay_with_failure_seam(vec![Err(Status::unavailable(message))]).await;

        assert_eq!(buyer.len(), 1);
        assert!(buyer[0]
            .as_ref()
            .is_err_and(|status| status.message() == message));
        let failure = failure.unwrap();
        assert_eq!(failure.error_class, "seller_config");
        assert!(!failure.retryable);
        assert_eq!(failure.http_status, Some(400));

        // Transient provider trouble keeps its existing retryable classes.
        let (_, throttled) = relay_with_failure_seam(vec![Err(Status::unavailable(
            "upstream HTTP 429 Too Many Requests",
        ))])
        .await;
        let throttled = throttled.unwrap();
        assert_eq!(throttled.error_class, "http");
        assert!(throttled.retryable);
    }

    fn authorized_request(
        state: &GatewayState,
        buyer: &LocalNote,
        token_contract: &str,
        max_tokens: u32,
    ) -> Request<StreamRequest> {
        let nonce = vec![9; 32];
        state.auth.issue_challenge(token_contract, nonce.clone());
        let signature = buyer.sign(&challenge_bytes(token_contract, &nonce));
        Request::new(StreamRequest {
            token_contract: token_contract.to_string(),
            nonce,
            signature: signature.0.to_vec(),
            request: Some(CanonRequest {
                messages: Vec::new(),
                params: Some(SamplingParams {
                    max_tokens,
                    ..SamplingParams::default()
                }),
            }),
        })
    }

    #[derive(Clone, Default)]
    struct EventRecorder(Arc<Mutex<Vec<AuthoritativeDeliveryEvent>>>);

    impl AuthoritativeDeliveryRecorder for EventRecorder {
        fn record_authoritative_delivery(
            &self,
            event: AuthoritativeDeliveryEvent,
        ) -> Result<(), Status> {
            self.0.lock().unwrap().push(event);
            Ok(())
        }
    }

    impl EventRecorder {
        fn events(&self) -> Vec<AuthoritativeDeliveryEvent> {
            self.0.lock().unwrap().clone()
        }
    }

    #[derive(Clone, Default)]
    struct RecordingDelivery {
        delivery: DealDelivery,
        events: EventRecorder,
    }

    impl AuthoritativeDeliveryRecorder for RecordingDelivery {
        fn record_authoritative_delivery(
            &self,
            event: AuthoritativeDeliveryEvent,
        ) -> Result<(), Status> {
            self.delivery.record_authoritative_delivery(event)?;
            self.events.record_authoritative_delivery(event)
        }
    }

    async fn run_openai_through_relay(
        body: String,
        key_env: &str,
    ) -> (
        u64,
        Vec<AuthoritativeDeliveryEvent>,
        Vec<Result<CanonChunk, Status>>,
        String,
    ) {
        use crate::seller::upstream::openai::{self, OpenAiConfig};
        use dexdo_proto::ChatMessage;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let provider = tokio::spawn(async move {
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
                "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(header.as_bytes()).await.unwrap();
            socket.write_all(body.as_bytes()).await.unwrap();
            String::from_utf8(request).unwrap()
        });

        std::env::set_var(key_env, "fake-provider-secret");
        let cfg = OpenAiConfig {
            base_url: format!("http://{address}"),
            api_key_env: key_env.to_string(),
            ..OpenAiConfig::default()
        };
        let request = CanonRequest {
            messages: vec![ChatMessage {
                role: "user".into(),
                content: "hello".into(),
            }],
            params: None,
        };
        let (up_tx, up_rx) = mpsc::channel(8);
        let upstream = tokio::spawn(async move {
            openai::run(&cfg, None, 8, Some(request), up_tx).await;
        });
        let (buyer_tx, mut buyer_rx) = mpsc::channel(8);
        let recorder = RecordingDelivery::default();
        relay_counting(up_rx, buyer_tx, recorder.clone(), None).await;
        upstream.await.unwrap();
        std::env::remove_var(key_env);
        let provider_request = provider.await.unwrap();
        let mut buyer_events = Vec::new();
        while let Some(event) = buyer_rx.recv().await {
            buyer_events.push(event);
        }
        (
            recorder.delivery.count.load(Ordering::Acquire),
            recorder.events.events(),
            buyer_events,
            provider_request,
        )
    }

    /// Drive one gRPC stream through `relay_counting`: emit `n_ok` `Ok` chunks (and optionally a trailing
    /// `Err`), forward to a sink, and return how many items reached the buyer. Adds delivered tokens to `count`.
    async fn run_one_stream(count: Arc<AtomicU64>, n_ok: usize, trailing_err: bool) -> usize {
        let (up_tx, up_rx) = mpsc::channel(16);
        let (tx, mut rx) = mpsc::channel::<Result<CanonChunk, Status>>(16);
        tokio::spawn(async move {
            for _ in 0..n_ok {
                up_tx
                    .send(crate::seller::upstream::chunk_with_structured_accounting(
                        CanonChunk {
                            token_ids: vec![42],
                            ..CanonChunk::default()
                        },
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
        let relay = tokio::spawn(relay_counting(up_rx, tx, recorder(count), None));
        let mut forwarded = 0;
        while rx.recv().await.is_some() {
            forwarded += 1;
        }
        relay.await.unwrap();
        forwarded
    }

    /// the relay adds only delivered (`Ok`, successfully-sent) chunks to the deal `count`, and forwards
    /// every item (incl. errors) to the buyer -- but it MUST NOT mark the deal-level `done`: a single gRPC
    /// stream ending is not the deal/session ending (the buyer session lifecycle owns `done`).
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
                deal: ordinary_shape(300),
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
            u64::MAX,
            "without request max_tokens the later authoritative reservation supplies the cap"
        );
        assert_eq!(
            state.stream_token_limit(tc, Some(&req), true),
            8,
            "mock upstream keeps the explicit fake-token fixture"
        );
    }

    #[test]
    fn ordinary_registration_uses_actual_funded_capacity_not_seller_configuration() {
        let state = GatewayState::new();
        let tc = "0:ordinary";
        state
            .register_stream(
                tc,
                buyer_pubkey(),
                u64::MAX,
                subscription_state(TICK_SIZE),
                ordinary_shape(TICK_SIZE + 17),
            )
            .unwrap();
        let snapshot = state.capacity_snapshot(tc).unwrap().unwrap();
        assert_eq!(snapshot.funded_tokens, TICK_SIZE + 17);
        assert_eq!(snapshot.available().unwrap(), 17);
        assert_eq!(state.stream_token_limit(tc, None, false), u64::MAX);
        assert_eq!(
            state
                .capacity
                .reserve(&tc.to_string(), u64::MAX)
                .unwrap()
                .amount(),
            17
        );
    }

    #[test]
    fn ordinary_claim_state_reconciliation_opens_only_the_funded_remainder() {
        let state = GatewayState::new();
        let tc = "0:ordinary-probe-observer";
        let mut pre_probe = subscription_state(0);
        pre_probe.probe_accepted = false;
        state
            .register_stream(
                tc,
                buyer_pubkey(),
                u64::MAX,
                pre_probe,
                ordinary_shape(2 * TICK_SIZE),
            )
            .unwrap();
        let probe = state.capacity.reserve(&tc.to_string(), u64::MAX).unwrap();
        probe.record_delivered(TICK_SIZE as u64).unwrap();
        probe.finish_exact().unwrap();

        let accepted = state
            .reconcile_ordinary_capacity(tc, subscription_state(TICK_SIZE))
            .unwrap()
            .unwrap();
        assert_eq!(accepted.authoritative_cap, 2 * TICK_SIZE);
        assert_eq!(accepted.available().unwrap(), TICK_SIZE);
    }

    /// The counter the claim driver reads must keep counting across requests, including across the
    /// probe. `record_delivered` on a bare reservation moves the capacity ledger only; the request
    /// path goes through `CapacityDeliveryRecorder`, and it is that path which also feeds
    /// `delivery(tc).count` and decides whether a seller bills what it served.
    #[test]
    fn delivery_after_the_probe_reaches_the_counter_the_claim_driver_reads() {
        let directory = tempfile::tempdir().unwrap();
        let state = GatewayState::with_upstream_and_deals_dir(
            UpstreamConfig::Mock,
            directory.path().to_path_buf(),
        );
        let tc = "0:ordinary-two-requests";
        let mut pre_probe = subscription_state(0);
        pre_probe.probe_accepted = false;
        state
            .register_stream(
                tc,
                buyer_pubkey(),
                u64::MAX,
                pre_probe,
                ordinary_shape(4 * TICK_SIZE),
            )
            .unwrap();

        let deliver = |tokens: u128| {
            let recorder = CapacityDeliveryRecorder {
                reservation: state.capacity.reserve(&tc.to_string(), u64::MAX).unwrap(),
                delivery: state.delivery(tc),
            };
            recorder
                .record_authoritative_delivery(AuthoritativeDeliveryEvent::Delivered(
                    NonZeroU64::new(tokens as u64).unwrap(),
                ))
                .unwrap();
            recorder
                .record_authoritative_delivery(AuthoritativeDeliveryEvent::Finished(
                    AuthoritativeDeliveryFinish::Clean,
                ))
                .unwrap();
        };

        deliver(TICK_SIZE);
        assert_eq!(
            state.delivery(tc).count.load(Ordering::Acquire),
            TICK_SIZE as u64,
            "the probe request is visible to the claim driver"
        );

        state
            .reconcile_ordinary_capacity(tc, subscription_state(TICK_SIZE))
            .unwrap()
            .unwrap();

        deliver(2 * TICK_SIZE);
        assert_eq!(
            state.delivery(tc).count.load(Ordering::Acquire),
            (3 * TICK_SIZE) as u64,
            "two ticks served after the probe must reach the counter the claim driver reads, or \
             the seller delivers them and never bills them"
        );
    }

    #[test]
    fn subscription_reservation_uses_authoritative_week_not_advertised_maximum() {
        let state = GatewayState::new();
        let tc = "0:subscription";
        state
            .register_stream(
                tc,
                buyer_pubkey(),
                u64::MAX,
                subscription_state(TICK_SIZE),
                subscription_shape(),
            )
            .unwrap();
        let reservation = state.capacity.reserve(&tc.to_string(), u64::MAX).unwrap();
        assert_eq!(
            reservation.amount(),
            TICK_SIZE as u64,
            "the current week has only one tick left after the accepted probe"
        );
    }

    #[tokio::test]
    async fn missing_anthropic_usage_retains_the_durable_request_reservation() {
        let directory = tempfile::tempdir().unwrap();
        let state = GatewayState::with_upstream_and_deals_dir(
            UpstreamConfig::Mock,
            directory.path().to_path_buf(),
        );
        let tc = "0:anthropic-ambiguous";
        state
            .register_stream(
                tc,
                buyer_pubkey(),
                100,
                subscription_state(TICK_SIZE),
                subscription_shape(),
            )
            .unwrap();
        let reservation = state.capacity.reserve(&tc.to_string(), 100).unwrap();
        let (up_tx, up_rx) = mpsc::channel(1);
        let (tx, mut rx) = mpsc::channel(2);
        up_tx
            .send(Ok(UpstreamEvent::Chunk {
                chunk: CanonChunk {
                    text: "forwarded before usage".into(),
                    ..CanonChunk::default()
                },
                accounted_tokens: 0,
            }))
            .await
            .unwrap();
        drop(up_tx);

        relay_counting(
            up_rx,
            tx,
            CapacityDeliveryRecorder {
                reservation,
                delivery: state.delivery(tc),
            },
            None,
        )
        .await;
        assert!(rx.recv().await.unwrap().is_ok());
        assert_eq!(
            rx.recv().await.unwrap().unwrap_err().code(),
            tonic::Code::DataLoss
        );
        let snapshot = state.capacity_snapshot(tc).unwrap().unwrap();
        assert_eq!(snapshot.local_delivered_after_anchor, 0);
        assert_eq!(snapshot.outstanding_reservation, 100);
        assert_eq!(snapshot.available().unwrap(), TICK_SIZE - 100);
    }

    /// capacity is consulted BEFORE output whose count arrives later crosses to the buyer.

    /// On the separate-usage branch -- the ordinary one, the shape every shipped adapter produces --
    /// `record_authoritative_delivery` runs only when the usage event arrives, so the relay used to
    /// forward content with nothing on the path between receiving it and exposing it. The refusal that
    /// bounds it existed the whole time (`CapacityReservation` refuses a delivery beyond the request
    /// reservation) but ran only after the fact: production never asked it before forwarding, so it
    /// could only convert an already-exposed answer into an error. Here the reservation is fully
    /// consumed by the first usage event, and the output that follows it is output the seller could
    /// never claim: it must not reach the buyer, and the request must be refused with the canonical
    /// request-scoped capacity status rather than answered and reconciled into a loss.
    #[tokio::test]
    async fn output_needing_later_usage_is_refused_once_the_reservation_cannot_bill_it() {
        let state = GatewayState::new();
        let tc = "0:expose-after-exhaustion";
        state
            .register_stream(
                tc,
                buyer_pubkey(),
                100,
                subscription_state(TICK_SIZE),
                subscription_shape(),
            )
            .unwrap();
        let reservation = state.capacity.reserve(&tc.to_string(), 4).unwrap();
        assert_eq!(reservation.amount(), 4);
        let (up_tx, up_rx) = mpsc::channel(4);
        let (tx, mut rx) = mpsc::channel(4);
        for event in [
            Ok(UpstreamEvent::Chunk {
                chunk: CanonChunk {
                    text: "billable".into(),
                    ..CanonChunk::default()
                },
                accounted_tokens: 0,
            }),
            Ok(UpstreamEvent::Accounted(4)),
            Ok(UpstreamEvent::Chunk {
                chunk: CanonChunk {
                    text: "beyond the reservation".into(),
                    ..CanonChunk::default()
                },
                accounted_tokens: 0,
            }),
        ] {
            up_tx.send(event).await.unwrap();
        }
        drop(up_tx);

        relay_counting(
            up_rx,
            tx,
            CapacityDeliveryRecorder {
                reservation,
                delivery: state.delivery(tc),
            },
            None,
        )
        .await;

        let mut buyer = Vec::new();
        while let Some(item) = rx.recv().await {
            buyer.push(item);
        }
        let text = buyer
            .iter()
            .filter_map(|item| item.as_ref().ok().map(|chunk| chunk.text.clone()))
            .collect::<Vec<_>>();
        assert_eq!(
            text,
            vec!["billable".to_string()],
            "output the request reservation can no longer bill must never reach the buyer"
        );
        let refusal = buyer
            .last()
            .expect("the refused request terminates the stream")
            .as_ref()
            .expect_err("the request is refused, not silently truncated");
        assert_eq!(refusal.code(), tonic::Code::ResourceExhausted);
        assert_eq!(
            refusal.message(),
            "deal delivery capacity is exhausted",
            "the refusal must stay the canonical request-scoped capacity status the buyer already \
             treats as backpressure, so it never settles the deal on chain"
        );
        assert_eq!(
            state.delivery(tc).count.load(Ordering::Acquire),
            4,
            "only the authoritatively counted output is billed"
        );
        let snapshot = state.capacity_snapshot(tc).unwrap().unwrap();
        assert_eq!(snapshot.local_delivered_after_anchor, 4);
        assert_eq!(snapshot.outstanding_reservation, 0);
    }

    #[tokio::test]
    async fn provider_error_before_output_releases_subscription_reservation() {
        let state = GatewayState::new();
        let tc = "0:provider-error";
        state
            .register_stream(
                tc,
                buyer_pubkey(),
                100,
                subscription_state(TICK_SIZE),
                subscription_shape(),
            )
            .unwrap();
        let reservation = state.capacity.reserve(&tc.to_string(), 100).unwrap();
        let (up_tx, up_rx) = mpsc::channel(1);
        let (tx, mut rx) = mpsc::channel(1);
        up_tx
            .send(Err(Status::unavailable("provider unavailable")))
            .await
            .unwrap();
        drop(up_tx);
        relay_counting(
            up_rx,
            tx,
            CapacityDeliveryRecorder {
                reservation,
                delivery: state.delivery(tc),
            },
            None,
        )
        .await;
        assert_eq!(
            rx.recv().await.unwrap().unwrap_err().code(),
            tonic::Code::Unavailable
        );
        let snapshot = state.capacity_snapshot(tc).unwrap().unwrap();
        assert_eq!(snapshot.outstanding_reservation, 0);
        assert_eq!(snapshot.available().unwrap(), TICK_SIZE);
    }

    #[tokio::test]
    async fn fat_structured_chunk_is_rejected_before_buyer_exposure() {
        let state = GatewayState::new();
        let tc = "0:fat-structured-chunk";
        state
            .register_stream(
                tc,
                buyer_pubkey(),
                u64::MAX,
                subscription_state(TICK_SIZE),
                ordinary_shape(TICK_SIZE + 2),
            )
            .unwrap();
        let reservation = state.capacity.reserve(&tc.to_string(), u64::MAX).unwrap();
        assert_eq!(reservation.amount(), 2);
        let (up_tx, up_rx) = mpsc::channel(1);
        let (tx, mut rx) = mpsc::channel::<Result<CanonChunk, Status>>(2);
        up_tx
            .send(crate::seller::upstream::chunk_with_structured_accounting(
                CanonChunk {
                    token_ids: vec![1, 2, 3],
                    ..CanonChunk::default()
                },
            ))
            .await
            .unwrap();
        drop(up_tx);

        relay_counting(
            up_rx,
            tx,
            CapacityDeliveryRecorder {
                reservation,
                delivery: state.delivery(tc),
            },
            None,
        )
        .await;
        let status = rx.recv().await.unwrap().unwrap_err();
        assert_eq!(status.code(), tonic::Code::DataLoss);
        assert!(rx.recv().await.is_none(), "the rejected chunk was exposed");
        let snapshot = state.capacity_snapshot(tc).unwrap().unwrap();
        assert_eq!(snapshot.local_delivered_after_anchor, 0);
        assert_eq!(snapshot.outstanding_reservation, 0);
        assert_eq!(snapshot.available().unwrap(), 2);
        assert_eq!(state.delivery(tc).count.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn capacity_recorder_overflow_changes_no_state_and_exposes_no_chunk() {
        let directory = tempfile::tempdir().unwrap();
        let state = GatewayState::with_upstream_and_deals_dir(
            UpstreamConfig::Mock,
            directory.path().to_path_buf(),
        );
        let tc = "0:capacity-recorder-overflow";
        state
            .register_stream(
                tc,
                buyer_pubkey(),
                u64::MAX,
                subscription_state(TICK_SIZE),
                ordinary_shape(TICK_SIZE + 2),
            )
            .unwrap();
        let reservation = state.capacity.reserve(&tc.to_string(), u64::MAX).unwrap();
        assert_eq!(reservation.amount(), 2);
        let delivery = state.delivery(tc);
        delivery.count.store(u64::MAX, Ordering::Relaxed);
        let (up_tx, up_rx) = mpsc::channel(1);
        let (tx, mut rx) = mpsc::channel::<Result<CanonChunk, Status>>(2);
        up_tx
            .send(crate::seller::upstream::chunk_with_structured_accounting(
                CanonChunk {
                    token_ids: vec![1],
                    ..CanonChunk::default()
                },
            ))
            .await
            .unwrap();
        drop(up_tx);

        relay_counting(
            up_rx,
            tx,
            CapacityDeliveryRecorder {
                reservation,
                delivery: delivery.clone(),
            },
            None,
        )
        .await;
        let status = rx.recv().await.unwrap().unwrap_err();
        assert_eq!(status.code(), tonic::Code::DataLoss);
        assert_eq!(
            status.message(),
            "authoritative delivered-token high-water overflow"
        );
        assert!(rx.recv().await.is_none(), "the rejected chunk was exposed");
        let snapshot = state.capacity_snapshot(tc).unwrap().unwrap();
        assert_eq!(snapshot.local_delivered_after_anchor, 0);
        assert_eq!(snapshot.outstanding_reservation, 0);
        assert_eq!(snapshot.available().unwrap(), 2);
        assert_eq!(delivery.count.load(Ordering::Acquire), u64::MAX);
    }

    /// on the real entry point: a run the reservation cannot pay must not reach the buyer.

    /// The separate-usage branch reports its figure AFTER the content it counts, so the seller cannot
    /// know a run's price before exposing it. What stands on the path is the reservation, and asking
    /// it only whether it is non-empty refuses at exactly zero and nowhere else -- so a remainder that
    /// lands SHORT of the next run rather than on top of it still exposed one run and had its figure
    /// refused afterwards, leaving the buyer holding output the seller's own accounting had rejected.
    /// That is the loss describes, and it survived the first fix for it.

    /// The fixture upstream charges four tokens per run and reports each one after its content.
    /// Both halves are driven through `open_stream`, because a test that only proves output is
    /// withheld also passes on a seller that serves nothing:

    /// - six tokens of capacity pay the first run and leave two. Two cannot pay a run of four, so the
    /// second run must never cross, and the two that could not be spent go back to the deal.
    /// - eight pay both runs, so both must still be served in full.

    /// E2E-ROW: E2E-UPS-40/L0
    #[tokio::test]
    async fn a_run_the_reservation_cannot_pay_never_reaches_the_buyer() {
        for (capacity, served, billed) in [(6u128, 1usize, 4u64), (8, 2, 8)] {
            let state = Arc::new(GatewayState::new());
            let buyer = LocalNote::generate();
            let tc = "0:unpayable-run";
            state
                .register_stream(
                    tc,
                    buyer.pubkey(),
                    100,
                    subscription_state(2 * TICK_SIZE - capacity),
                    subscription_shape(),
                )
                .unwrap();
            let mut request = authorized_request(&state, &buyer, tc, 100);
            request.get_mut().request.as_mut().unwrap().messages = vec![dexdo_proto::ChatMessage {
                role: "user".into(),
                content: "DEXDO_FIXTURE_FATCHUNK".into(),
            }];
            let service = GatewayService::new(state.clone());
            let mut stream = service.open_stream(request).await.unwrap().into_inner();

            let mut exposed = Vec::new();
            let mut refusal = None;
            while let Some(item) = stream.next().await {
                match item {
                    Ok(chunk) => exposed.push(chunk),
                    Err(status) => refusal = Some(status),
                }
            }

            assert_eq!(
                exposed.len(),
                served,
                "capacity {capacity}: only runs the reservation can pay may reach the buyer"
            );
            let refusal = refusal.expect("the stream is refused, not silently truncated");
            assert_eq!(refusal.code(), tonic::Code::ResourceExhausted);
            assert_eq!(
                refusal.message(),
                "deal delivery capacity is exhausted",
                "capacity {capacity}: the refusal stays the canonical request-scoped capacity status \
                 the buyer already treats as backpressure, so it never settles the deal on chain"
            );
            assert_eq!(
                state.delivery(tc).count.load(Ordering::Acquire),
                billed,
                "capacity {capacity}: every exposed run is billed and no unexposed one is"
            );
            let snapshot = state.capacity_snapshot(tc).unwrap().unwrap();
            assert_eq!(snapshot.local_delivered_after_anchor, u128::from(billed));
            assert_eq!(
                snapshot.outstanding_reservation, 0,
                "capacity {capacity}: a refused run leaves no reservation stranded"
            );
            assert_eq!(
                snapshot.available().unwrap(),
                capacity - u128::from(billed),
                "capacity {capacity}: what could not be spent returns to the deal"
            );
        }
    }

    #[tokio::test]
    async fn open_stream_clamps_subscription_before_starting_mock_upstream() {
        let state = Arc::new(GatewayState::new());
        let buyer = LocalNote::generate();
        let tc = "0:open-stream-clamp";
        state
            .register_stream(
                tc,
                buyer.pubkey(),
                100,
                subscription_state(2 * TICK_SIZE - 2),
                subscription_shape(),
            )
            .unwrap();
        let service = GatewayService::new(state.clone());
        let response = service
            .open_stream(authorized_request(&state, &buyer, tc, 100))
            .await
            .unwrap();
        let mut stream = response.into_inner();
        let mut chunks = 0;
        while stream.next().await.is_some() {
            chunks += 1;
        }
        assert_eq!(
            chunks, 2,
            "only the authoritative two-token remainder is offered"
        );
        let snapshot = state.capacity_snapshot(tc).unwrap().unwrap();
        assert_eq!(snapshot.local_delivered_after_anchor, 2);
        assert_eq!(snapshot.outstanding_reservation, 0);
        assert_eq!(snapshot.available().unwrap(), 0);
    }

    #[tokio::test]
    async fn exhausted_subscription_rejects_before_upstream_task_creation() {
        let state = Arc::new(GatewayState::new());
        let buyer = LocalNote::generate();
        let tc = "0:open-stream-exhausted";
        state
            .register_stream(
                tc,
                buyer.pubkey(),
                100,
                subscription_state(2 * TICK_SIZE),
                subscription_shape(),
            )
            .unwrap();
        let service = GatewayService::new(state.clone());
        let error = service
            .open_stream(authorized_request(&state, &buyer, tc, 100))
            .await
            .err()
            .expect("zero weekly remainder must be rejected synchronously");
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert_eq!(
            state.delivery(tc).count.load(Ordering::Acquire),
            0,
            "no upstream delivery tracker changed"
        );
    }

    #[tokio::test]
    async fn post_term_subscription_rejects_before_upstream_task_creation() {
        let state = Arc::new(GatewayState::new());
        let buyer = LocalNote::generate();
        let tc = "0:post-term-open-stream";
        let pending = 3 * TICK_SIZE;
        let mut shape = subscription_shape();
        shape.week_index = SUBSCRIPTION_WEEKS;
        shape.tokens_paid = shape.funded_tokens;
        shape.week_base_tokens = pending;
        state
            .register_stream(tc, buyer.pubkey(), 100, subscription_state(pending), shape)
            .unwrap();

        let snapshot = state.capacity_snapshot(tc).unwrap().unwrap();
        assert_eq!(snapshot.authoritative_cap, pending);
        assert_eq!(snapshot.available().unwrap(), 0);
        let service = GatewayService::new(state.clone());
        let error = service
            .open_stream(authorized_request(&state, &buyer, tc, 100))
            .await
            .err()
            .expect("post-term request must be rejected before upstream");
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert_eq!(state.delivery(tc).count.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn relay_counts_tokens_from_structured_signals_not_chunks() {
        let count = Arc::new(AtomicU64::new(0));
        let (up_tx, up_rx) = mpsc::channel(16);
        let (tx, mut rx) = mpsc::channel::<Result<CanonChunk, Status>>(16);
        tokio::spawn(async move {
            up_tx
                .send(crate::seller::upstream::chunk_with_structured_accounting(
                    CanonChunk {
                        token_ids: vec![1, 2, 3],
                        ..CanonChunk::default()
                    },
                ))
                .await
                .unwrap();
            up_tx
                .send(crate::seller::upstream::chunk_with_structured_accounting(
                    CanonChunk::default(),
                ))
                .await
                .unwrap();
        });
        relay_counting(up_rx, tx, recorder(count.clone()), None).await;
        while rx.recv().await.is_some() {}
        assert_eq!(
            count.load(Ordering::Acquire),
            3,
            "one chunk may carry multiple canonical tokens; an empty no-signal chunk contributes zero"
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
        relay_counting(up_rx, tx, recorder(count.clone()), None).await;
        let mut delivered_chunks = 0;
        while rx.recv().await.is_some() {
            delivered_chunks += 1;
        }
        assert_eq!(delivered_chunks, 2);
        assert_eq!(count.load(Ordering::Acquire), 5);
    }

    #[tokio::test]
    async fn buyer_disconnect_before_delivery_does_not_advance_count() {
        let count = Arc::new(AtomicU64::new(0));
        let (up_tx, up_rx) = mpsc::channel(1);
        let (tx, rx) = mpsc::channel::<Result<CanonChunk, Status>>(1);
        drop(rx);
        up_tx
            .send(crate::seller::upstream::chunk_with_structured_accounting(
                CanonChunk {
                    token_ids: vec![1, 2, 3],
                    ..CanonChunk::default()
                },
            ))
            .await
            .unwrap();
        drop(up_tx);

        relay_counting(up_rx, tx, recorder(count.clone()), None).await;
        assert_eq!(
            count.load(Ordering::Acquire),
            0,
            "only a chunk successfully accepted by the buyer stream is billable"
        );
    }

    #[tokio::test]
    async fn high_water_overflow_is_explicit_and_does_not_wrap() {
        let count = Arc::new(AtomicU64::new(u64::MAX));
        let (up_tx, up_rx) = mpsc::channel(1);
        let (tx, mut rx) = mpsc::channel::<Result<CanonChunk, Status>>(2);
        up_tx
            .send(crate::seller::upstream::chunk_with_structured_accounting(
                CanonChunk {
                    token_ids: vec![1],
                    ..CanonChunk::default()
                },
            ))
            .await
            .unwrap();
        drop(up_tx);

        relay_counting(up_rx, tx, recorder(count.clone()), None).await;
        let status = rx.recv().await.unwrap().unwrap_err();
        assert_eq!(status.code(), tonic::Code::DataLoss);
        assert!(rx.recv().await.is_none(), "the rejected chunk was exposed");
        assert_eq!(count.load(Ordering::Acquire), u64::MAX);
    }

    #[tokio::test]
    async fn accepted_structured_chunk_is_forwarded_once_and_recorded_once() {
        let events = EventRecorder::default();
        let (up_tx, up_rx) = mpsc::channel(1);
        let (tx, mut rx) = mpsc::channel::<Result<CanonChunk, Status>>(2);
        up_tx
            .send(crate::seller::upstream::chunk_with_structured_accounting(
                CanonChunk {
                    token_ids: vec![1, 2, 3],
                    ..CanonChunk::default()
                },
            ))
            .await
            .unwrap();
        drop(up_tx);

        relay_counting(up_rx, tx, events.clone(), None).await;
        let chunk = rx.recv().await.unwrap().unwrap();
        assert_eq!(chunk.token_ids, vec![1, 2, 3]);
        assert!(
            rx.recv().await.is_none(),
            "structured chunk was forwarded twice"
        );
        assert_eq!(
            events.events(),
            vec![
                AuthoritativeDeliveryEvent::Delivered(NonZeroU64::new(3).unwrap()),
                AuthoritativeDeliveryEvent::Finished(AuthoritativeDeliveryFinish::Clean),
            ]
        );
    }

    /// E2E-UPS-07: a provider stream that dies before its terminal native usage forwards its output but
    /// records no delivery at all -- the request is never cleanly releasable and never billable.
    #[tokio::test]
    async fn truncated_openai_eof_records_no_delivery_and_never_clean() {
        let events = EventRecorder::default();
        let (up_tx, up_rx) = mpsc::channel(2);
        let (tx, mut rx) = mpsc::channel::<Result<CanonChunk, Status>>(2);
        up_tx
            .send(Ok(UpstreamEvent::Chunk {
                chunk: CanonChunk {
                    text: "forwarded".into(),
                    ..CanonChunk::default()
                },
                accounted_tokens: 0,
            }))
            .await
            .unwrap();
        up_tx
            .send(Err(Status::data_loss(
                "OpenAI-compatible SSE ended without [DONE]",
            )))
            .await
            .unwrap();
        drop(up_tx);

        relay_counting(up_rx, tx, events.clone(), None).await;
        assert!(rx.recv().await.unwrap().is_ok());
        assert_eq!(
            rx.recv().await.unwrap().unwrap_err().code(),
            tonic::Code::DataLoss
        );
        assert_eq!(
            events.events(),
            vec![AuthoritativeDeliveryEvent::Finished(
                AuthoritativeDeliveryFinish::AmbiguousUsage
            )],
            "a truncated provider request is never cleanly releasable and bills nothing"
        );
    }

    #[tokio::test]
    async fn closed_receiver_before_permit_records_no_delivery() {
        let events = EventRecorder::default();
        let (up_tx, up_rx) = mpsc::channel(1);
        let (tx, rx) = mpsc::channel::<Result<CanonChunk, Status>>(1);
        drop(rx);
        up_tx
            .send(crate::seller::upstream::chunk_with_structured_accounting(
                CanonChunk {
                    text: "not accepted".into(),
                    ..CanonChunk::default()
                },
            ))
            .await
            .unwrap();
        drop(up_tx);

        relay_counting(up_rx, tx, events.clone(), None).await;
        assert_eq!(
            events.events(),
            vec![AuthoritativeDeliveryEvent::Finished(
                AuthoritativeDeliveryFinish::Interrupted
            )],
            "buyer disconnect is distinct from provider truncation and records no delivery"
        );
    }

    #[tokio::test]
    async fn separate_usage_after_buyer_disconnect_never_records_delivery() {
        let events = EventRecorder::default();
        let (up_tx, up_rx) = mpsc::channel(2);
        let (tx, rx) = mpsc::channel::<Result<CanonChunk, Status>>(1);
        drop(rx);
        up_tx
            .send(Ok(UpstreamEvent::Chunk {
                chunk: CanonChunk {
                    text: "not accepted".into(),
                    ..CanonChunk::default()
                },
                accounted_tokens: 0,
            }))
            .await
            .unwrap();
        up_tx.send(Ok(UpstreamEvent::Accounted(1))).await.unwrap();
        drop(up_tx);

        relay_counting(up_rx, tx, events.clone(), None).await;
        assert_eq!(
            events.events(),
            vec![AuthoritativeDeliveryEvent::Finished(
                AuthoritativeDeliveryFinish::Interrupted
            )],
            "terminal usage cannot monetize output the buyer channel rejected"
        );
    }

    /// E2E-UPS-01/02 through the whole relay: a provider that returns no optional log-probability data
    /// still serves the buyer, and its terminal native total is the exact delivered amount.
    #[tokio::test]
    async fn openai_terminal_usage_authorizes_text_without_logprobs_through_relay() {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"forwarded\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],",
            "\"x_groq\":{\"usage\":{\"completion_tokens\":3}}}\n\n",
            "data: [DONE]\n\n"
        )
        .to_string();
        let (count, events, buyer_events, provider_request) =
            run_openai_through_relay(body, "DEXDO_861_RELAY_NATIVE_USAGE_KEY").await;

        assert!(provider_request.starts_with("POST "));
        assert!(
            provider_request.contains("\"include_usage\":true"),
            "the seller must ask for the record it bills by: {provider_request}"
        );
        assert_eq!(buyer_events.len(), 1);
        assert_eq!(buyer_events[0].as_ref().unwrap().text, "forwarded");
        assert_eq!(count, 3, "the provider's own total is the delivered amount");
        assert_eq!(
            events,
            vec![
                AuthoritativeDeliveryEvent::Delivered(NonZeroU64::new(3).unwrap()),
                AuthoritativeDeliveryEvent::Finished(AuthoritativeDeliveryFinish::Clean),
            ]
        );
    }

    /// A corrupt complete provider frame kills the request before it can reach a terminal aggregate, so
    /// nothing is delivered and nothing is billable (E2E-UPS-07/18).
    #[tokio::test]
    async fn malformed_complete_openai_sse_is_data_loss_and_bills_nothing() {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"forwarded\"},",
            "\"logprobs\":{\"content\":[{\"token\":\"forwarded\",\"logprob\":-0.1,",
            "\"top_logprobs\":[]}]}}]}\n\n",
            "data: {\"choices\":[\n\n",
            "data: {\"choices\":[],\"usage\":{\"completion_tokens\":3}}\n\n",
            "data: [DONE]\n\n"
        )
        .to_string();
        let (count, events, buyer_events, provider_request) =
            run_openai_through_relay(body, "DEXDO_768_MALFORMED_SSE_KEY").await;

        assert!(provider_request.starts_with("POST "));
        assert_eq!(buyer_events.len(), 2);
        assert_eq!(buyer_events[0].as_ref().unwrap().text, "forwarded");
        let status = buyer_events[1].as_ref().unwrap_err();
        assert_eq!(status.code(), tonic::Code::DataLoss);
        assert!(
            status
                .message()
                .starts_with("malformed OpenAI-compatible SSE JSON:"),
            "{}",
            status.message()
        );
        assert_eq!(
            count, 0,
            "no terminal aggregate was ever reached, so no amount is authorized"
        );
        assert_eq!(
            events,
            vec![AuthoritativeDeliveryEvent::Finished(
                AuthoritativeDeliveryFinish::AmbiguousUsage
            )],
            "a corrupt complete provider frame is never a clean request"
        );
    }

    #[tokio::test]
    async fn separate_usage_missing_after_forward_remains_ambiguous() {
        let events = EventRecorder::default();
        let (up_tx, up_rx) = mpsc::channel(1);
        let (tx, mut rx) = mpsc::channel::<Result<CanonChunk, Status>>(2);
        up_tx
            .send(Ok(UpstreamEvent::Chunk {
                chunk: CanonChunk {
                    text: "forwarded".into(),
                    ..CanonChunk::default()
                },
                accounted_tokens: 0,
            }))
            .await
            .unwrap();
        drop(up_tx);

        relay_counting(up_rx, tx, events.clone(), None).await;
        assert_eq!(rx.recv().await.unwrap().unwrap().text, "forwarded");
        assert_eq!(
            rx.recv().await.unwrap().unwrap_err().code(),
            tonic::Code::DataLoss
        );
        assert_eq!(
            events.events(),
            vec![AuthoritativeDeliveryEvent::Finished(
                AuthoritativeDeliveryFinish::AmbiguousUsage
            )]
        );
    }

    #[tokio::test]
    async fn request_recorder_marks_exact_early_error_interrupted() {
        let events = EventRecorder::default();
        let (up_tx, up_rx) = mpsc::channel(2);
        let (tx, mut rx) = mpsc::channel::<Result<CanonChunk, Status>>(2);
        up_tx
            .send(crate::seller::upstream::chunk_with_structured_accounting(
                CanonChunk {
                    token_ids: vec![1],
                    ..CanonChunk::default()
                },
            ))
            .await
            .unwrap();
        up_tx
            .send(Err(Status::unavailable("provider stopped")))
            .await
            .unwrap();
        drop(up_tx);

        relay_counting(up_rx, tx, events.clone(), None).await;
        while rx.recv().await.is_some() {}
        assert_eq!(
            events.events(),
            vec![
                AuthoritativeDeliveryEvent::Delivered(NonZeroU64::new(1).unwrap()),
                AuthoritativeDeliveryEvent::Finished(AuthoritativeDeliveryFinish::Interrupted),
            ]
        );
    }
}

#[cfg(test)]
#[path = "gateway_1046_tests.rs"]
mod issue_1046_tests;

#[cfg(test)]
#[path = "gateway_1196_tests.rs"]
mod issue_1196_tests;
