//! Seller command handler(Track C13, move-only).

use crate::cli::args::SellerArgs;
use crate::cli::commands::{
    enforce_model_registry_policy, expected_order_book_for_note,
    load_enabled_model_registry_policy, order_book_active_from_contracts,
    resolve_model_registry_target, shellnet_doctor_preflight, BookTarget,
};
#[cfg(feature = "shellnet")]
use crate::cli::commands::{save_runtime_deal_handle, RuntimeDealHandleInput};
use crate::cli::deals;
use crate::cli::policy;
use crate::cli::seller_policy::{
    apply_seller_dispute_policy, apply_seller_terminal_policy, classify_by_fact_advance_failure,
    is_err_not_open, AdvanceFailureDisposition,
};
use crate::cli::support::*;
use anyhow::{bail, Result};
use dexdo::registry::{BuyerMissingBookPolicy, RegistryRole};
use dexdo_core::params::{
    SellerLivenessParams, DEFAULT_MATCH_POLL_INTERVAL, SELLER_TERMINAL_RECEIPT_POLL_INTERVAL,
    SELLER_TERMINAL_RECEIPT_TIMEOUT,
};
use dexdo_core::{DobParams, MatchWatchCursor, SellOfferOutcome};
use futures::{stream::FuturesUnordered, FutureExt as _, StreamExt as _};
use serde_json::json;
use std::future::Future;
use std::io::Write as _;
use std::pin::Pin;
use std::sync::Arc;
use tokio::task::JoinSet;

use crate::operator_shutdown_signal;

struct OrdinaryCapacityObserver {
    gateway: std::sync::Arc<dexdo::seller::gateway::GatewayState>,
}

impl dexdo::seller::ClaimStateObserver for OrdinaryCapacityObserver {
    fn observe(
        &self,
        token_contract: &dexdo_core::TokenContract,
        state: dexdo_core::DealChainState,
    ) -> std::result::Result<(), dexdo_core::ChainError> {
        self.gateway
            .reconcile_ordinary_capacity(token_contract, state)
            .map(|_| ())
            .map_err(|error| {
                dexdo_core::ChainError::Chain(format!(
                    "TokenContract {token_contract}: persist ordinary delivery capacity from claim state: \
                     {error}"
                ))
            })
    }

    fn observe_terminal(
        &self,
        token_contract: &dexdo_core::TokenContract,
    ) -> std::result::Result<(), dexdo_core::ChainError> {
        self.gateway
            .mark_deal_terminal(token_contract)
            .map_err(|error| {
                dexdo_core::ChainError::Chain(format!(
                    "TokenContract {token_contract}: remove terminal ordinary delivery capacity: {error}"
                ))
            })
    }
}

struct SubscriptionCapacityObserver {
    gateway: std::sync::Arc<dexdo::seller::gateway::GatewayState>,
}

#[async_trait::async_trait]
impl dexdo::seller::SubscriptionKeeperObserver for SubscriptionCapacityObserver {
    async fn observe(
        &self,
        token_contract: &dexdo_core::TokenContract,
        snapshot: Option<&dexdo_core::DealChainSnapshot>,
    ) -> std::result::Result<(), dexdo_core::ChainError> {
        let result = match snapshot {
            Some(snapshot) => self
                .gateway
                .reconcile_subscription_capacity(
                    token_contract,
                    snapshot.state,
                    snapshot.subscription,
                )
                .map(|_| ()),
            None => self.gateway.mark_subscription_terminal(token_contract),
        };
        result.map_err(|error| {
            dexdo_core::ChainError::Chain(format!(
                "TokenContract {token_contract}: persist subscription delivery capacity from keeper \
                 snapshot: {error}"
            ))
        })
    }
}

fn seller_offer_outcome_line(outcome: &SellOfferOutcome) -> String {
    match outcome {
        SellOfferOutcome::Rested { order_id } => {
            format!("seller_offer_outcome RESTED order_id={order_id}")
        }
        SellOfferOutcome::Matched => "seller_offer_outcome MATCHED".to_string(),
    }
}

/// The startup announcement printed before `seller_ready` for one prepared pool deal: a fresh post
/// reports its authoritative outcome(`seller_offer_outcome`), an adopted raw resting SELL reports
/// the resume(`seller_offer_resume`), and a startup with no resting or matched fact stays silent.
fn seller_offer_startup_line(startup: &dexdo::seller::SellerOfferStartup) -> Option<String> {
    match startup {
        dexdo::seller::SellerOfferStartup::ResumedResting { order_id } => {
            Some(format!("seller_offer_resume RESTING order_id={order_id}"))
        }
        dexdo::seller::SellerOfferStartup::Posted { outcome } => {
            outcome.as_ref().map(seller_offer_outcome_line)
        }
        dexdo::seller::SellerOfferStartup::ResumedFunded => None,
    }
}

fn seller_ready_line(
    token_contract: &str,
    gateway_advertise: &str,
    gateway_listen: &str,
    startup: &dexdo::seller::SellerOfferStartup,
    identity: Option<&dexdo::seller::liveness::RestingOfferIdentity>,
) -> Option<String> {
    let identity = identity?;
    let readiness = match startup {
        dexdo::seller::SellerOfferStartup::ResumedResting { order_id }
            if *order_id == identity.order_id =>
        {
            "resumed_resting_offer"
        }
        dexdo::seller::SellerOfferStartup::Posted {
            outcome: Some(SellOfferOutcome::Rested { order_id }),
        } if *order_id == identity.order_id => "exact_tc_offer_accepted",
        _ => return None,
    };
    Some(format!(
        "seller_ready token_contract={} gateway={} gateway_listen={} order_id={} readiness={}",
        dexdo_core::address::display(token_contract),
        gateway_advertise,
        gateway_listen,
        identity.order_id,
        readiness
    ))
}

// The JSON lifecycle events keep their published `dexdo.*.event.v1` address representation until the
// machine schemas are versioned together; only the human-readable seller lines carry the canonical form.
fn seller_shutdown_event(token_contract: &str) -> serde_json::Value {
    json!({
        "event": "stopping",
        "role": "seller",
        "token_contract": token_contract,
        "reason": "signal"
    })
}

fn emit_seller_shutdown_event(token_contract: &str) {
    println!("{}", seller_shutdown_event(token_contract));
    let _ = std::io::stdout().flush();
}

const SELLER_EVENT_SCHEMA: &str = "dexdo.seller.event.v1";

fn seller_runtime_event(
    seq: u64,
    event: &'static str,
    token_contract: &str,
    fields: serde_json::Value,
) -> serde_json::Value {
    let mut value = json!({
        "schema": SELLER_EVENT_SCHEMA,
        "seq": seq,
        "ts_unix": deals::now_unix().unwrap_or(0),
        "event": event,
        "role": "seller",
        "token_contract": token_contract,
    });
    if let (Some(target), Some(fields)) = (value.as_object_mut(), fields.as_object()) {
        target.extend(fields.clone());
    }
    value
}

fn emit_seller_runtime_event(event: &serde_json::Value) {
    println!("{event}");
    let _ = std::io::stdout().flush();
}

fn upstream_failure_event(
    seq: u64,
    token_contract: &str,
    error_class: &str,
    retryable: bool,
    grpc_status: &str,
    http_status: Option<u16>,
) -> serde_json::Value {
    seller_runtime_event(
        seq,
        "upstream_failed",
        token_contract,
        json!({
            "error_class": error_class,
            "retryable": retryable,
            "grpc_status": grpc_status,
            "http_status": http_status,
        }),
    )
}

fn emit_upstream_failure(failure: dexdo::seller::gateway::UpstreamFailure) -> serde_json::Value {
    let event = upstream_failure_event(
        failure.next_event_seq(),
        &failure.token_contract,
        failure.error_class,
        failure.retryable,
        &failure.grpc_status,
        failure.http_status,
    );
    emit_seller_runtime_event(&event);
    event
}

fn emit_buyer_stop_terminal_trail(
    token_contract: &str,
    delivery: &dexdo::seller::gateway::DealDelivery,
    (to_seller, refund_to_buyer): (u128, u128),
) -> Vec<serde_json::Value> {
    if !delivery.claim_terminal_trail() {
        return Vec::new();
    }
    let observed = seller_runtime_event(
        delivery.next_event_seq(),
        "buyer_stop_observed",
        token_contract,
        json!({
            "source": "token_contract_event",
            "initiator": "buyer",
            "chain_event": "StreamStopped",
        }),
    );
    let settled = seller_runtime_event(
        delivery.next_event_seq(),
        "settled",
        token_contract,
        json!({
            "source": "token_contract_event",
            "state": "stopped",
            "terminal": true,
            "chain_event": "StreamStopped",
            "outcome": "AmicableSplit",
            "to_seller": to_seller.to_string(),
            "refund_to_buyer": refund_to_buyer.to_string(),
        }),
    );
    let exiting = seller_runtime_event(
        delivery.next_event_seq(),
        "exiting",
        token_contract,
        json!({
            "scope": "deal_worker",
            "reason": "settled",
            "exit_code": 0,
        }),
    );
    let events = vec![observed, settled, exiting];
    for event in &events {
        emit_seller_runtime_event(event);
    }
    events
}

async fn read_buyer_stop_settlement(
    chain: &dyn dexdo_core::ChainBackend,
    token_contract: &dexdo_core::TokenContract,
) -> Option<(u128, u128)> {
    match tokio::time::timeout(SELLER_TERMINAL_RECEIPT_TIMEOUT, async {
        loop {
            if let Ok(Some(settlement)) = chain.buyer_stop_settlement(token_contract).await {
                return settlement;
            }
            tokio::time::sleep(SELLER_TERMINAL_RECEIPT_POLL_INTERVAL).await;
        }
    })
    .await
    {
        Ok(settlement) => Some(settlement),
        Err(_) => {
            tracing::warn!(
                token_contract,
                "buyer STOP settlement event unavailable after bounded receipt wait; no terminal event emitted"
            );
            None
        }
    }
}

fn seller_liveness_event(
    token_contract: &str,
    owner_note: Option<&str>,
    order_id: Option<u128>,
    event: &str,
    component: Option<&str>,
    outcome: &str,
    known_result: Option<&str>,
) -> serde_json::Value {
    json!({
        "event": event,
        "role": "seller",
        "timestamp": deals::now_unix().unwrap_or(0),
        "token_contract": token_contract,
        "owner_note": owner_note,
        "order_id": order_id.map(|value| value.to_string()),
        "component": component,
        "outcome": outcome,
        "known_result": known_result,
    })
}

fn emit_seller_liveness_event(
    token_contract: &str,
    owner_note: Option<&str>,
    order_id: Option<u128>,
    event: &str,
    component: Option<&str>,
    outcome: &str,
    known_result: Option<&str>,
) {
    println!(
        "{}",
        seller_liveness_event(
            token_contract,
            owner_note,
            order_id,
            event,
            component,
            outcome,
            known_result,
        )
    );
    let _ = std::io::stdout().flush();
}

#[cfg(test)]
async fn react_to_seller_shutdown_signal<S>(
    mut shutdown: Pin<&mut S>,
    already_requested: bool,
    token_contract: &str,
) where
    S: Future<Output = ()> + ?Sized,
{
    if !already_requested {
        shutdown.as_mut().await;
    }
    emit_seller_shutdown_event(token_contract);
}

enum SellerGatewayStartup {
    Ready(dexdo::seller::RunningSeller),
    Stopped {
        reason: dexdo::seller::liveness::RestingStopReason,
        disposition: dexdo::seller::liveness::CancellationDisposition,
    },
}

async fn start_seller_gateway_with_liveness<G, S>(
    gateway: G,
    chain: &dyn dexdo_core::ChainBackend,
    cfg: &dexdo::seller::SellerConfig,
    existing_identity: Option<&dexdo::seller::liveness::RestingOfferIdentity>,
    shutdown: S,
) -> Result<SellerGatewayStartup>
where
    G: Future<Output = Result<dexdo::seller::RunningSeller>>,
    S: Future<Output = ()>,
{
    tokio::pin!(gateway);
    tokio::pin!(shutdown);
    let reason = tokio::select! {
        biased;
        _ = &mut shutdown => {
            dexdo::seller::liveness::RestingStopReason::Shutdown
        }
        result = &mut gateway => {
            match result {
                Ok(seller) => return Ok(SellerGatewayStartup::Ready(seller)),
                Err(error) => {
                    if existing_identity.is_none() {
                        return Err(error);
                    }
                    dexdo::seller::liveness::RestingStopReason::Health(
                        dexdo::seller::liveness::HealthFailure::new(
                            dexdo::seller::liveness::HealthComponent::GatewayTask,
                            false,
                            format!("gateway startup failed: {error}"),
                        )
                    )
                }
            }
        }
    };
    let disposition = match existing_identity {
        Some(identity) => dexdo::seller::liveness::cancel_and_confirm(chain, cfg, identity).await,
        None => dexdo::seller::liveness::CancellationDisposition::AlreadyAbsent,
    };
    Ok(SellerGatewayStartup::Stopped {
        reason,
        disposition,
    })
}

fn seller_watch_cursor_path(
    deals_dir: Option<&std::path::Path>,
    token_contract: &str,
) -> Result<std::path::PathBuf> {
    Ok(deals::resolve_deals_dir(deals_dir)?
        .join("seller-watch")
        .join(format!(
            "{}.cursor.json",
            deals::make_token_contract_id(token_contract)
        )))
}

#[cfg(any(test, feature = "shellnet"))]
fn seller_pool_dir(
    deals_dir: Option<&std::path::Path>,
    seller_note: &str,
) -> Result<std::path::PathBuf> {
    let seller_note = dexdo_core::normalize_wallet_address(seller_note)
        .map_err(|error| anyhow::anyhow!("invalid seller note for pool state: {error}"))?;
    Ok(deals::resolve_deals_dir(deals_dir)?
        .join("seller-pool")
        .join(deals::make_token_contract_id(&seller_note)))
}

#[cfg(any(test, feature = "shellnet"))]
fn load_or_create_gateway_tls(
    pool_dir: &std::path::Path,
) -> Result<dexdo::seller::tls::GatewayTls> {
    let path = pool_dir.join("gateway.pem");
    match std::fs::read_to_string(&path) {
        Ok(bundle) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
                if mode != 0o600 {
                    bail!(
                        "seller gateway TLS identity {} must have mode 0600, got {mode:04o}",
                        path.display()
                    );
                }
            }
            dexdo::seller::tls::GatewayTls::from_pem_bundle(bundle).map_err(|error| {
                anyhow::anyhow!("load seller gateway TLS {}: {error}", path.display())
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(pool_dir).map_err(|error| {
                anyhow::anyhow!(
                    "create seller pool directory {}: {error}",
                    pool_dir.display()
                )
            })?;
            let tls = dexdo::seller::tls::GatewayTls::generate()?;
            crate::cli::note::write_private_atomic(&path, tls.pem_bundle().as_bytes())?;
            Ok(tls)
        }
        Err(error) => Err(anyhow::anyhow!(
            "read seller gateway TLS {}: {error}",
            path.display()
        )),
    }
}

#[cfg(feature = "shellnet")]
struct SellerPoolLock {
    file: std::fs::File,
}

#[cfg(feature = "shellnet")]
impl Drop for SellerPoolLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

#[cfg(feature = "shellnet")]
fn acquire_seller_pool_lock(pool_dir: &std::path::Path) -> Result<SellerPoolLock> {
    std::fs::create_dir_all(pool_dir).map_err(|error| {
        anyhow::anyhow!(
            "create seller pool directory {}: {error}",
            pool_dir.display()
        )
    })?;
    let path = pool_dir.join("seller.lock");
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .map_err(|error| anyhow::anyhow!("open seller pool lock {}: {error}", path.display()))?;
    match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => Ok(SellerPoolLock { file }),
        Err(error)
            if error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
                || error.kind() == std::io::ErrorKind::WouldBlock =>
        {
            bail!(
                "seller pool for this note is already running; lock {} is held",
                path.display()
            )
        }
        Err(error) => Err(anyhow::anyhow!(
            "lock seller pool {}: {error}",
            path.display()
        )),
    }
}

#[derive(Clone)]
struct SellerPoolDeal {
    chain: Arc<dyn dexdo_core::ChainBackend>,
    cfg: dexdo::seller::SellerConfig,
    watch: dexdo::seller::SellerMatchWatchConfig,
    upstream: dexdo::seller::UpstreamConfig,
    nonce: u64,
    market: Option<dexdo_core::MarketManifest>,
}

type SellerAdvanceResult = (
    String,
    Arc<dyn dexdo_core::ChainBackend>,
    dexdo::seller::gateway::DealDelivery,
    std::result::Result<u128, dexdo_core::ChainError>,
);

type SellerTerminalReceiptResult = (
    String,
    dexdo::seller::gateway::DealDelivery,
    Option<(u128, u128)>,
);

fn spawn_buyer_stop_receipt_wait(
    tasks: &mut JoinSet<SellerTerminalReceiptResult>,
    token_contract: String,
    chain: Arc<dyn dexdo_core::ChainBackend>,
    delivery: dexdo::seller::gateway::DealDelivery,
) {
    tasks.spawn(async move {
        let settlement = read_buyer_stop_settlement(chain.as_ref(), &token_contract).await;
        (token_contract, delivery, settlement)
    });
}

fn record_terminal_receipt_result(
    joined: std::result::Result<SellerTerminalReceiptResult, tokio::task::JoinError>,
    first_error: &mut Option<anyhow::Error>,
) -> Vec<serde_json::Value> {
    match joined {
        Ok((token_contract, delivery, Some(settlement))) => {
            emit_buyer_stop_terminal_trail(&token_contract, &delivery, settlement)
        }
        Ok((_, _, None)) => Vec::new(),
        Err(error) => {
            first_error.get_or_insert_with(|| {
                anyhow::anyhow!("seller terminal receipt task panicked: {error}")
            });
            Vec::new()
        }
    }
}

async fn record_advance_result(
    seller: &dexdo::seller::RunningSeller,
    joined: std::result::Result<SellerAdvanceResult, tokio::task::JoinError>,
    terminal_receipts: &mut JoinSet<SellerTerminalReceiptResult>,
    seller_policy: &policy::SellerRuntimePolicy,
    first_error: &mut Option<anyhow::Error>,
) {
    match joined {
        Ok((token_contract, chain, delivery, Ok(finalized))) => {
            tracing::info!(
                token_contract,
                finalized,
                "seller pool deal reached terminal by-fact state"
            );
            match chain.deal_state(&token_contract).await {
                Ok(Some(state)) => {
                    if let Err(error) = apply_seller_terminal_policy(
                        &token_contract,
                        seller_policy,
                        finalized,
                        state,
                    ) {
                        first_error.get_or_insert(error);
                    }
                }
                Ok(None) => {
                    first_error.get_or_insert_with(|| {
                        anyhow::anyhow!(
                            "--token-contract {token_contract}: authoritative terminal deal state is unavailable; \
                             refusing to guess buyer_no_show from finalized={finalized}"
                        )
                    });
                }
                Err(error) => {
                    first_error.get_or_insert_with(|| {
                        anyhow::anyhow!(
                            "--token-contract {token_contract}: authoritative terminal deal state is unreadable; \
                             refusing to guess buyer_no_show from finalized={finalized}: {error}"
                        )
                    });
                }
            }
            seller.state.unregister_stream(&token_contract);
            spawn_buyer_stop_receipt_wait(terminal_receipts, token_contract, chain, delivery);
        }
        Ok((token_contract, chain, delivery, Err(error))) => {
            tracing::error!(
                token_contract,
                error = %error,
                "seller pool isolated a failed deal"
            );
            let resolved = if is_err_not_open(&error) {
                match classify_by_fact_advance_failure(chain.as_ref(), &token_contract, &error)
                    .await
                {
                    Ok(AdvanceFailureDisposition::BenignTerminal { reason }) => {
                        tracing::info!(
                            token_contract,
                            %reason,
                            "seller pool retired terminal ERR_NOT_OPEN deal"
                        );
                        true
                    }
                    Ok(AdvanceFailureDisposition::Fault { reason }) => {
                        first_error.get_or_insert_with(|| {
                            anyhow::anyhow!(
                                "--token-contract {token_contract}: by-fact advance failed: \
                                 {error}; ERR_NOT_OPEN terminal check: {reason}"
                            )
                        });
                        false
                    }
                    Err(classify_error) => {
                        first_error.get_or_insert_with(|| {
                            anyhow::anyhow!(
                                "--token-contract {token_contract}: by-fact advance failed: \
                                 {error}; ERR_NOT_OPEN terminal classification failed: \
                                 {classify_error}"
                            )
                        });
                        false
                    }
                }
            } else {
                match apply_seller_dispute_policy(
                    chain.as_ref(),
                    &token_contract,
                    seller_policy,
                    "advance-error",
                )
                .await
                {
                    Ok(resolved) => resolved,
                    Err(policy_error) => {
                        first_error.get_or_insert(policy_error);
                        false
                    }
                }
            };
            if !resolved && first_error.is_none() {
                first_error.replace(anyhow::anyhow!(
                    "--token-contract {token_contract}: by-fact advance failed: {error}"
                ));
            }
            seller.state.unregister_stream(&token_contract);
            if resolved {
                spawn_buyer_stop_receipt_wait(terminal_receipts, token_contract, chain, delivery);
            }
        }
        Err(error) => {
            first_error
                .get_or_insert_with(|| anyhow::anyhow!("seller advance task panicked: {error}"));
        }
    }
}

struct SellerPoolContext<'a> {
    deals_dir: Option<&'a std::path::Path>,
    contracts: &'a std::path::Path,
    note_addr: &'a str,
    frame_model: &'a str,
    gateway_advertise: &'a str,
    /// how a failed `advertised_gateway` self-probe is treated.
    advertise_probe: dexdo::seller::liveness::AdvertiseProbePolicy,
}

fn save_pool_deal_handle(context: &SellerPoolContext<'_>, deal: &SellerPoolDeal) -> Result<()> {
    let Some(market) = deal.market.as_ref() else {
        return Ok(());
    };
    #[cfg(feature = "shellnet")]
    {
        save_runtime_deal_handle(
            RuntimeDealHandleInput {
                role: deals::DealHandleRole::Seller,
                deals_dir: context.deals_dir,
                token_contract: &deal.cfg.token_contract,
                note_addr: context.note_addr,
                frame_model: &market.frame_model,
                market: Some(market),
                market_path: None,
                contracts: context.contracts,
                endpoint: Some(deals::DealEndpointInfo {
                    kind: "gateway".to_string(),
                    value: context.gateway_advertise.to_string(),
                }),
                created_order_ids: Vec::new(),
            },
            true,
        )?;
    }
    #[cfg(not(feature = "shellnet"))]
    {
        let _ = (context.contracts, market);
    }
    Ok(())
}

fn seller_market_handles(
    deals_dir: Option<&std::path::Path>,
    note_addr: &str,
    gateway_advertise: &str,
) -> Result<std::collections::HashMap<String, dexdo_core::MarketManifest>> {
    let mut markets = std::collections::HashMap::new();
    let dir = deals::resolve_deals_dir(deals_dir)?;
    for (path, handle) in deals::list_deal_handles(&dir)? {
        if handle.role != deals::DealHandleRole::Seller
            || deals::normalize_addr(&handle.note_addr) != deals::normalize_addr(note_addr)
        {
            continue;
        }
        let market = handle.market.ok_or_else(|| {
            anyhow::anyhow!(
                "seller deal handle {} for {} has no market manifest; nonce/config cannot be reconstructed",
                path.display(),
                handle.token_contract
            )
        })?;
        assert_market_seller_note(&market.seller_note, note_addr)?;
        if let Some(endpoint) = handle.endpoint.as_ref() {
            if endpoint.kind == "gateway" && endpoint.value != gateway_advertise {
                bail!(
                    "seller deal handle {} requires gateway {}, but this service advertises {}",
                    path.display(),
                    endpoint.value,
                    gateway_advertise
                );
            }
        }
        let key = deals::normalize_addr(&market.token_contract);
        if let Some(existing) = markets.get(&key) {
            if existing != &market {
                bail!(
                    "seller deal handles disagree about market {}",
                    market.token_contract
                );
            }
        } else {
            markets.insert(key, market);
        }
    }
    Ok(markets)
}

async fn load_seller_pool_deals<F>(
    context: &SellerPoolContext<'_>,
    mut initial: SellerPoolDeal,
    mock_token_count: u64,
    mut backend_for_market: F,
) -> Result<Vec<SellerPoolDeal>>
where
    F: FnMut(
        &dexdo_core::MarketManifest,
    ) -> Result<(
        Arc<dyn dexdo_core::ChainBackend>,
        dexdo::seller::UpstreamConfig,
    )>,
{
    let mut markets = seller_market_handles(
        context.deals_dir,
        context.note_addr,
        context.gateway_advertise,
    )?;
    if let Some(market) = initial.market.take() {
        markets.insert(deals::normalize_addr(&market.token_contract), market);
    }

    let initial_key = deals::normalize_addr(&initial.cfg.token_contract);
    if let Some(initial_market) = markets.remove(&initial_key) {
        if (initial_market.price_per_tick, initial_market.max_ticks)
            != (
                u128::from(initial.cfg.price_per_tick),
                u128::from(initial.cfg.max_ticks),
            )
        {
            bail!(
                "initial market manifest terms ({},{}) do not match TokenContract.getDeal ({},{})",
                initial_market.price_per_tick,
                initial_market.max_ticks,
                initial.cfg.price_per_tick,
                initial.cfg.max_ticks
            );
        }
        initial.nonce = initial_market.nonce;
        initial.market = Some(initial_market);
    }
    let subscription = initial.cfg.subscription;
    let mut pool = vec![initial];

    for market in markets.into_values() {
        let price_per_tick = u64::try_from(market.price_per_tick).map_err(|_| {
            anyhow::anyhow!(
                "seller market {} price {} exceeds u64",
                market.token_contract,
                market.price_per_tick
            )
        })?;
        let max_ticks = u64::try_from(market.max_ticks).map_err(|_| {
            anyhow::anyhow!(
                "seller market {} max_ticks {} exceeds u64",
                market.token_contract,
                market.max_ticks
            )
        })?;
        let (chain, upstream) = backend_for_market(&market)?;
        let terms = match chain.sell_offer_terms(&market.token_contract).await {
            Ok(Some(terms)) => terms,
            unavailable => {
                let replaced = dexdo::seller::read_seller_fill_lineage(
                    &seller_watch_cursor_path(context.deals_dir, &market.token_contract)?,
                    &market.token_contract,
                )?
                .and_then(|fill| fill.replacement_token_contract)
                .is_some();
                if replaced {
                    continue;
                }
                match unavailable {
                    Ok(None) if market.network == "mock" => (price_per_tick, max_ticks),
                    Ok(None) => bail!(
                        "seller deal handle TokenContract {} getDeal is unavailable",
                        market.token_contract
                    ),
                    Err(error) => return Err(error.into()),
                    Ok(Some(_)) => unreachable!(),
                }
            }
        };
        if terms != (price_per_tick, max_ticks) {
            bail!(
                "seller market {} terms ({price_per_tick},{max_ticks}) do not match TokenContract.getDeal ({},{})",
                market.token_contract,
                terms.0,
                terms.1
            );
        }
        let cfg = dexdo::seller::SellerConfig {
            token_contract: market.token_contract.clone(),
            price_per_tick,
            max_ticks,
            subscription,
            gateway_advertise: context.gateway_advertise.to_string(),
            mock_token_count,
        };
        pool.push(SellerPoolDeal {
            watch: dexdo::seller::SellerMatchWatchConfig {
                cursor_path: seller_watch_cursor_path(context.deals_dir, &market.token_contract)?,
                poll_interval: DEFAULT_MATCH_POLL_INTERVAL,
            },
            chain,
            cfg,
            upstream,
            nonce: market.nonce,
            market: Some(market),
        });
    }
    Ok(pool)
}

async fn prepare_pool_deal<S>(
    seller: &dexdo::seller::RunningSeller,
    deal: &SellerPoolDeal,
    context: &SellerPoolContext<'_>,
    match_was_observed: bool,
    mut shutdown: Pin<&mut S>,
) -> Result<Option<dexdo::seller::liveness::RestingOfferIdentity>>
where
    S: futures::future::FusedFuture<Output = ()> + ?Sized,
{
    seller
        .state
        .route_stream(&deal.cfg.token_contract, deal.upstream.clone());
    if match_was_observed {
        return Ok(None);
    }
    let inspection = dexdo::seller::inspect_seller_offer(
        deal.chain.as_ref(),
        &deal.cfg,
        Some(context.note_addr),
    )
    .await?;
    let inspected_identity = match inspection {
        dexdo::seller::SellerOfferInspection::Resting { order_id } => {
            Some(dexdo::seller::liveness::RestingOfferIdentity {
                owner_note: context.note_addr.to_string(),
                token_contract: deal.cfg.token_contract.clone(),
                order_id,
            })
        }
        dexdo::seller::SellerOfferInspection::Funded
        | dexdo::seller::SellerOfferInspection::Vacant => None,
    };
    let startup = match dexdo::seller::liveness::prepare_seller_offer_with_liveness(
        seller,
        deal.chain.as_ref(),
        &deal.cfg,
        context.note_addr,
        inspected_identity.as_ref(),
        shutdown.as_mut(),
        context.advertise_probe,
    )
    .await?
    {
        dexdo::seller::liveness::SellerStartupOutcome::Ready(startup) => startup,
        dexdo::seller::liveness::SellerStartupOutcome::Stopped {
            reason,
            disposition,
            ..
        } => {
            return match reason {
                dexdo::seller::liveness::RestingStopReason::Shutdown
                    if !matches!(
                        &disposition,
                        dexdo::seller::liveness::CancellationDisposition::UnknownFailure { .. }
                    ) =>
                {
                    Err(anyhow::anyhow!(
                        "seller pool startup interrupted by shutdown"
                    ))
                }
                reason => Err(anyhow::anyhow!(
                    "seller pool startup stopped for {}: reason={reason:?}; \
                     cancellation_disposition={disposition}",
                    deal.cfg.token_contract
                )),
            };
        }
    };
    if let Some(announcement) = seller_offer_startup_line(&startup) {
        println!("{announcement}");
        let _ = std::io::stdout().flush();
    }
    let identity = match &startup {
        dexdo::seller::SellerOfferStartup::ResumedResting { order_id }
        | dexdo::seller::SellerOfferStartup::Posted {
            outcome: Some(SellOfferOutcome::Rested { order_id }),
        } => Some(dexdo::seller::liveness::RestingOfferIdentity {
            owner_note: context.note_addr.to_string(),
            token_contract: deal.cfg.token_contract.clone(),
            order_id: *order_id,
        }),
        dexdo::seller::SellerOfferStartup::ResumedFunded
        | dexdo::seller::SellerOfferStartup::Posted {
            outcome: Some(SellOfferOutcome::Matched),
        } => None,
        dexdo::seller::SellerOfferStartup::Posted { outcome: None } => {
            bail!(
                "seller offer outcome for TokenContract {} has no exact resting order id or match confirmation",
                deal.cfg.token_contract
            );
        }
    };
    if let Some(ready) = seller_ready_line(
        &deal.cfg.token_contract,
        context.gateway_advertise,
        &seller.listen_addr.to_string(),
        &startup,
        identity.as_ref(),
    ) {
        println!("{ready}");
        let _ = std::io::stdout().flush();
    }
    Ok(identity)
}

async fn watch_pool_deal(
    seller: &dexdo::seller::RunningSeller,
    deal: SellerPoolDeal,
    identity: Option<dexdo::seller::liveness::RestingOfferIdentity>,
    fill_tx: tokio::sync::mpsc::UnboundedSender<SellerPoolDeal>,
    advertise_probe: dexdo::seller::liveness::AdvertiseProbePolicy,
) -> (
    SellerPoolDeal,
    Result<dexdo::seller::liveness::RestingSellerOutcome>,
) {
    let result = async {
        let matched = match identity.as_ref() {
            Some(identity) => match dexdo::seller::liveness::supervise_resting_offer(
                seller,
                deal.chain.as_ref(),
                &deal.cfg,
                &deal.watch,
                identity,
                futures::future::pending(),
                false,
                advertise_probe,
            )
            .await?
            {
                dexdo::seller::liveness::RestingSellerOutcome::Matched(matched) => matched,
                stopped @ dexdo::seller::liveness::RestingSellerOutcome::Stopped { .. } => {
                    return Ok(stopped);
                }
            },
            None => {
                dexdo::seller::wait_for_match(seller, deal.chain.as_ref(), &deal.cfg, &deal.watch)
                    .await?
            }
        };
        fill_tx.send(deal.clone()).map_err(|_| {
            anyhow::anyhow!(
                "seller pool stopped before recording fill for {}",
                deal.cfg.token_contract
            )
        })?;
        dexdo::seller::serve_watched_match(
            seller,
            deal.chain.as_ref(),
            &deal.cfg,
            &deal.watch,
            matched,
        )
        .await
        .map(dexdo::seller::liveness::RestingSellerOutcome::Matched)
    }
    .await;
    (deal, result)
}

/// example 2: an owner fill the pool cannot account for.
/// This finding used to be recorded into `first_error` and, because the owner-fill audit runs
/// BEFORE deal startup, it won the `get_or_insert` race and printed as the process `Error:` while
/// the real root cause(a readiness failure) was only logged. It is now a *cascade note*: it is
/// attached under `secondary` when anything else failed, and is only the reported error when
/// nothing else did.
fn unknown_owner_fill_note(token_contract: &str) -> dexdo_core::DexdoError {
    dexdo_core::DexdoError::new(
        dexdo_core::error_codes::E_POOL_UNKNOWN_OWNER_FILL,
        format!(
            "seller owner fill for TokenContract {token_contract} has no same-note deal \
             handle/manifest; refusing to discard unknown capacity"
        ),
    )
    .with_hint(
        "an \"owner fill\" is a match against THIS note's own resting order; without that deal's \
         handle/market.json the pool cannot account the capacity it just sold. Run the seller from \
         the directory holding that deal's handle, or close the orphaned deal (`dexdo deals`, then \
         `destroy`/`recover`). Attached as `secondary`, it is a CONSEQUENCE of the primary error \
         above -- fix that first and re-run",
    )
}

/// (issue example 2): the reported process error must be the ROOT cause. Consequence findings
/// are attached under `secondary` instead of replacing it.
fn attach_cascade_notes(
    primary: anyhow::Error,
    notes: Vec<dexdo_core::DexdoError>,
) -> anyhow::Error {
    if notes.is_empty() {
        return primary;
    }
    // A primary that is already structured keeps its own code on the headline; anything else is
    // adopted(its message stays the headline, its source chain is preserved, not flattened).
    let structured = match primary.downcast::<dexdo_core::DexdoError>() {
        Ok(structured) => structured,
        Err(primary) => {
            dexdo_core::DexdoError::adopt(dexdo_core::error_codes::E_SELLER_POOL_FAILED, primary)
        }
    };
    anyhow::Error::new(notes.into_iter().fold(structured, |primary, note| {
        primary.with_secondary("pool owner-fill audit", note)
    }))
}

async fn run_seller_pool<S, F, Fut>(
    seller: &dexdo::seller::RunningSeller,
    deals: Vec<SellerPoolDeal>,
    context: SellerPoolContext<'_>,
    seller_policy: &policy::SellerRuntimePolicy,
    provisioner: &mut F,
    mut shutdown: Pin<&mut S>,
) -> Result<()>
where
    S: futures::future::FusedFuture<Output = ()> + ?Sized,
    F: FnMut(String, u64, u64, u64) -> Fut,
    Fut: Future<
        Output = Result<(
            dexdo_core::MarketManifest,
            Arc<dyn dexdo_core::ChainBackend>,
        )>,
    >,
{
    let max_open_deals = usize::try_from(seller_policy.max_open_deals).unwrap_or(usize::MAX);
    if max_open_deals == 0 {
        bail!("seller.max_open_deals must be at least 1");
    }
    let (owner_fill_chain, primary_token_contract) = deals
        .first()
        .map(|deal| (deal.chain.clone(), deal.cfg.token_contract.clone()))
        .ok_or_else(|| anyhow::anyhow!("seller pool has no deals to supervise"))?;
    let mut owner_fill_cursor = MatchWatchCursor::new(0);
    let mut active = JoinSet::<SellerAdvanceResult>::new();
    let mut terminal_receipts = JoinSet::<SellerTerminalReceiptResult>::new();
    let mut watched = FuturesUnordered::new();
    let (fill_tx, mut fill_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut resting = std::collections::HashMap::new();
    let mut pending = std::collections::VecDeque::<SellerPoolDeal>::new();
    let mut known_tcs = std::collections::HashSet::new();
    let mut known_nonces = std::collections::HashMap::new();
    let mut first_error = None;
    // findings that are consequences of another failure. They never win the `first_error`
    // race; they are attached to whatever the primary error turns out to be.
    let mut cascade_notes: Vec<dexdo_core::DexdoError> = Vec::new();
    let mut noted_owner_fills = std::collections::HashSet::new();
    let mut candidates = Vec::new();

    for deal in deals {
        let normalized = deals::normalize_addr(&deal.cfg.token_contract);
        if !known_tcs.insert(normalized) {
            bail!(
                "seller pool has duplicate TokenContract {}",
                deal.cfg.token_contract
            );
        }
        if let Some((tc, price, ticks)) = known_nonces.insert(
            deal.nonce,
            (
                deal.cfg.token_contract.clone(),
                deal.cfg.price_per_tick,
                deal.cfg.max_ticks,
            ),
        ) {
            bail!(
                "seller pool nonce {} maps to both TokenContract {} ({price},{ticks}) and {} ({},{})",
                deal.nonce,
                tc,
                deal.cfg.token_contract,
                deal.cfg.price_per_tick,
                deal.cfg.max_ticks
            );
        }
        let observed = match dexdo::seller::read_seller_fill_lineage(
            &deal.watch.cursor_path,
            &deal.cfg.token_contract,
        ) {
            Ok(fill) => fill.is_some(),
            Err(error) => {
                tracing::error!(
                    token_contract = %deal.cfg.token_contract,
                    %error,
                    "seller pool retired deal with invalid fill cursor"
                );
                first_error.get_or_insert(error);
                continue;
            }
        };
        let state = match deal.chain.deal_state(&deal.cfg.token_contract).await {
            Ok(state) => state,
            Err(error) => {
                tracing::error!(
                    token_contract = %deal.cfg.token_contract,
                    %error,
                    "seller pool isolated deal state read failure"
                );
                first_error.get_or_insert_with(|| {
                    anyhow::anyhow!(
                        "seller deal {} state read failed: {error}",
                        deal.cfg.token_contract
                    )
                });
                continue;
            }
        };
        if state.is_none() && observed {
            tracing::info!(
                token_contract = %deal.cfg.token_contract,
                "seller pool skipped terminal historical deal"
            );
            continue;
        }
        candidates.push((deal, observed));
    }
    if candidates.len() > max_open_deals {
        bail!(
            "seller pool has {} active/resting deals, exceeding policy seller.max_open_deals={max_open_deals}",
            candidates.len()
        );
    }
    match owner_fill_chain
        .poll_seller_fills(seller.note.as_ref(), &mut owner_fill_cursor)
        .await
    {
        Ok(fills) => {
            if let Some(fill) = fills
                .into_iter()
                .find(|fill| !known_tcs.contains(&deals::normalize_addr(&fill.token_contract)))
            {
                if noted_owner_fills.insert(deals::normalize_addr(&fill.token_contract)) {
                    cascade_notes.push(unknown_owner_fill_note(&fill.token_contract));
                }
            }
        }
        Err(error) => {
            tracing::warn!(%error, "seller owner fill discovery failed; retrying");
            first_error.get_or_insert_with(|| {
                anyhow::anyhow!("seller owner fill discovery failed: {error}")
            });
        }
    }
    for (deal, observed) in candidates {
        if let Err(error) = save_pool_deal_handle(&context, &deal) {
            first_error.get_or_insert(error);
            continue;
        }
        let identity =
            match prepare_pool_deal(seller, &deal, &context, observed, shutdown.as_mut()).await {
                Ok(identity) => identity,
                Err(error) => {
                    tracing::error!(
                        token_contract = %deal.cfg.token_contract,
                        %error,
                        "seller pool isolated deal startup failure"
                    );
                    seller.state.unregister_stream(&deal.cfg.token_contract);
                    first_error.get_or_insert(error);
                    continue;
                }
            };
        if let Some(identity) = identity.as_ref() {
            resting.insert(
                deal.cfg.token_contract.clone(),
                (deal.chain.clone(), deal.cfg.clone(), identity.clone()),
            );
        }
        watched.push(watch_pool_deal(
            seller,
            deal,
            identity,
            fill_tx.clone(),
            context.advertise_probe,
        ));
    }

    let mut gateway_poll =
        tokio::time::interval(SellerLivenessParams::canonical().gateway_task_poll);
    gateway_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut owner_fill_poll = tokio::time::interval(DEFAULT_MATCH_POLL_INTERVAL);
    owner_fill_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut stop_error = None;
    let mut stopped_by_operator = false;

    'pool: loop {
        while watched.len() + active.len() < max_open_deals {
            let Some(current) = pending.pop_front() else {
                break;
            };
            let replacement_result: Result<()> = async {
                let fill = dexdo::seller::read_seller_fill_lineage(
                    &current.watch.cursor_path,
                    &current.cfg.token_contract,
                )?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "seller match for {} has no authoritative owner fill lineage; refusing to guess residual capacity",
                        current.cfg.token_contract
                    )
                })?;
                let terms = current
                    .chain
                    .sell_offer_terms(&current.cfg.token_contract)
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "TokenContract {} getDeal is unavailable before residual provision",
                            current.cfg.token_contract
                        )
                    })?;
                if terms != (fill.price_per_tick, fill.offered_ticks) {
                    bail!(
                        "persisted seller fill for {} has N/P ({},{}) but TokenContract.getDeal is ({},{}); refusing residual provision",
                        current.cfg.token_contract,
                        fill.offered_ticks,
                        fill.price_per_tick,
                        terms.1,
                        terms.0
                    );
                }
                let next_nonce = match fill.replacement_nonce {
                    Some(nonce) => nonce,
                    None => {
                        let mut nonce = current.nonce.checked_add(1).ok_or_else(|| {
                            anyhow::anyhow!("seller residual nonce overflow at {}", current.nonce)
                        })?;
                        while known_nonces.contains_key(&nonce) {
                            nonce = nonce.checked_add(1).ok_or_else(|| {
                                anyhow::anyhow!("seller residual nonce overflow at {nonce}")
                            })?;
                        }
                        dexdo::seller::persist_seller_replacement(
                            &current.watch.cursor_path,
                            &current.cfg.token_contract,
                            nonce,
                            None,
                        )?;
                        nonce
                    }
                };
                if let Some((tc, price, ticks)) = known_nonces.get(&next_nonce) {
                    let linked = fill.replacement_token_contract.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "seller residual nonce {next_nonce} is occupied by {tc}, but parent {} has no persisted replacement link",
                            current.cfg.token_contract
                        )
                    })?;
                    if !tc.eq_ignore_ascii_case(linked)
                        || (*price, *ticks)
                            != (current.cfg.price_per_tick, fill.residual_ticks)
                    {
                        bail!(
                            "seller residual nonce {next_nonce} links to {linked}, but known deal is {tc} with ({price},{ticks})"
                        );
                    }
                    return Ok(());
                }
                let frame_model = current
                    .market
                    .as_ref()
                    .map(|market| market.frame_model.clone())
                    .unwrap_or_else(|| context.frame_model.to_string());
                let (market, chain) = provisioner(
                    frame_model.clone(),
                    next_nonce,
                    current.cfg.price_per_tick,
                    fill.residual_ticks,
                )
                .await?;
                market.validate().map_err(|error| {
                    anyhow::anyhow!("residual market manifest is invalid: {error}")
                })?;
                assert_market_seller_note(&market.seller_note, context.note_addr)?;
                if market.nonce != next_nonce
                    || market.frame_model != frame_model
                    || market.price_per_tick != u128::from(current.cfg.price_per_tick)
                    || market.max_ticks != u128::from(fill.residual_ticks)
                {
                    bail!(
                        "residual provision returned inconsistent market: expected frame_model={} nonce={} \
                         price={} max_ticks={}, got frame_model={} nonce={} price={} max_ticks={}",
                        frame_model,
                        next_nonce,
                        current.cfg.price_per_tick,
                        fill.residual_ticks,
                        market.frame_model,
                        market.nonce,
                        market.price_per_tick,
                        market.max_ticks
                    );
                }
                if let Some(linked) = fill.replacement_token_contract.as_deref() {
                    if !linked.eq_ignore_ascii_case(&market.token_contract) {
                        bail!(
                            "seller replacement nonce {next_nonce} returned {}, but cursor links {}",
                            market.token_contract,
                            linked
                        );
                    }
                }
                dexdo::seller::persist_seller_replacement(
                    &current.watch.cursor_path,
                    &current.cfg.token_contract,
                    next_nonce,
                    Some(&market.token_contract),
                )?;
                let (authoritative_price, authoritative_ticks) =
                    match chain.sell_offer_terms(&market.token_contract).await? {
                        Some(terms) => terms,
                        None if market.network == "mock" => {
                            (current.cfg.price_per_tick, fill.residual_ticks)
                        }
                        None => {
                            bail!(
                                "residual TokenContract {} getDeal is unavailable after provision",
                                market.token_contract
                            )
                        }
                    };
                if (authoritative_price, authoritative_ticks)
                    != (current.cfg.price_per_tick, fill.residual_ticks)
                {
                    bail!(
                        "residual TokenContract {} getDeal ({authoritative_price},{authoritative_ticks}) \
                         does not match requested ({},{})",
                        market.token_contract,
                        current.cfg.price_per_tick,
                        fill.residual_ticks
                    );
                }
                let cfg = dexdo::seller::SellerConfig {
                    token_contract: market.token_contract.clone(),
                    price_per_tick: authoritative_price,
                    max_ticks: authoritative_ticks,
                    subscription: current.cfg.subscription,
                    gateway_advertise: current.cfg.gateway_advertise.clone(),
                    mock_token_count: current.cfg.mock_token_count,
                };
                let replacement = SellerPoolDeal {
                    watch: dexdo::seller::SellerMatchWatchConfig {
                        cursor_path: seller_watch_cursor_path(
                            context.deals_dir,
                            &cfg.token_contract,
                        )?,
                        poll_interval: DEFAULT_MATCH_POLL_INTERVAL,
                    },
                    chain,
                    cfg,
                    upstream: current.upstream.clone(),
                    nonce: next_nonce,
                    market: Some(market),
                };
                let normalized = deals::normalize_addr(&replacement.cfg.token_contract);
                if !known_tcs.insert(normalized) {
                    bail!(
                        "seller residual provision returned duplicate TokenContract {}",
                        replacement.cfg.token_contract
                    );
                }
                known_nonces.insert(
                    next_nonce,
                    (
                        replacement.cfg.token_contract.clone(),
                        replacement.cfg.price_per_tick,
                        replacement.cfg.max_ticks,
                    ),
                );
                save_pool_deal_handle(&context, &replacement)?;
                let identity = prepare_pool_deal(
                    seller,
                    &replacement,
                    &context,
                    false,
                    shutdown.as_mut(),
                )
                .await?;
                if let Some(identity) = identity.as_ref() {
                    resting.insert(
                        replacement.cfg.token_contract.clone(),
                        (
                            replacement.chain.clone(),
                            replacement.cfg.clone(),
                            identity.clone(),
                        ),
                    );
                }
                watched.push(watch_pool_deal(
                    seller,
                    replacement,
                    identity,
                    fill_tx.clone(),
                    context.advertise_probe,
                ));
                Ok(())
            }
            .await;
            if let Err(error) = replacement_result {
                tracing::error!(
                    token_contract = %current.cfg.token_contract,
                    %error,
                    "seller pool isolated residual provision failure"
                );
                first_error.get_or_insert(error);
            }
        }

        if watched.is_empty()
            && active.is_empty()
            && terminal_receipts.is_empty()
            && pending.is_empty()
        {
            break;
        }
        tokio::select! {
            biased;
            _ = shutdown.as_mut() => {
                stopped_by_operator = true;
                break 'pool;
            }
            _ = owner_fill_poll.tick() => {
                match owner_fill_chain
                    .poll_seller_fills(seller.note.as_ref(), &mut owner_fill_cursor)
                    .await
                {
                    Ok(fills) => {
                        if let Some(fill) = fills.into_iter().find(|fill| {
                            !known_tcs.contains(&deals::normalize_addr(&fill.token_contract))
                        }) {
                            if noted_owner_fills
                                .insert(deals::normalize_addr(&fill.token_contract))
                            {
                                let note = unknown_owner_fill_note(&fill.token_contract);
                                tracing::error!(
                                    error = %note,
                                    "seller pool isolated unknown owner fill"
                                );
                                cascade_notes.push(note);
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "seller owner fill discovery failed; retrying");
                        first_error.get_or_insert_with(|| {
                            anyhow::anyhow!("seller owner fill discovery failed: {error}")
                        });
                    }
                }
            }
            filled = fill_rx.recv() => {
                let Some(deal) = filled else {
                    continue;
                };
                match dexdo::seller::read_seller_fill_lineage(
                    &deal.watch.cursor_path,
                    &deal.cfg.token_contract,
                ) {
                    Ok(Some(fill)) if fill.residual_ticks >= 2 => pending.push_back(deal),
                    Ok(Some(fill)) if fill.residual_ticks == 1 => {
                        println!(
                            "seller_residual_not_posted token_contract={} offered_ticks={} matched_ticks={} residual_ticks=1 reason=below_contract_minimum",
                            deal.cfg.token_contract,
                            fill.offered_ticks,
                            fill.matched_ticks
                        );
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        first_error.get_or_insert_with(|| anyhow::anyhow!(
                            "seller match for {} has no authoritative owner fill lineage; refusing to guess residual capacity",
                            deal.cfg.token_contract
                        ));
                    }
                    Err(error) => {
                        tracing::error!(
                            token_contract = %deal.cfg.token_contract,
                            %error,
                            "seller pool rejected corrupt fill lineage"
                        );
                        first_error.get_or_insert(error);
                    }
                }
            }
            watched_result = watched.next(), if !watched.is_empty() => {
                let (deal, outcome) =
                    watched_result.expect("watched branch is disabled when empty");
                resting.remove(&deal.cfg.token_contract);
                let outcome = match outcome {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        tracing::error!(
                            token_contract = %deal.cfg.token_contract,
                            %error,
                            "seller pool isolated deal watch/open failure"
                        );
                        seller.state.unregister_stream(&deal.cfg.token_contract);
                        first_error.get_or_insert(error);
                        continue;
                    }
                };
                match outcome {
                    dexdo::seller::liveness::RestingSellerOutcome::Matched(matched) => {
                        println!(
                            "seller_match_opened token_contract={} gateway={} gateway_listen={} cursor={}",
                            dexdo_core::address::display(&matched.token_contract),
                            context.gateway_advertise,
                            seller.listen_addr,
                            deal.watch.cursor_path.display()
                        );
                        let _ = std::io::stdout().flush();
                        if let Err(error) = save_pool_deal_handle(&context, &deal) {
                            seller.state.unregister_stream(&deal.cfg.token_contract);
                            first_error.get_or_insert(error);
                            continue;
                        }
                        match apply_seller_dispute_policy(
                            deal.chain.as_ref(),
                            &deal.cfg.token_contract,
                            seller_policy,
                            "pre-advance",
                        ).await {
                            Ok(false) => {
                              let spawn_result: Result<()> = async {
                                  let bounds = deal
                                      .chain
                                      .deal_claim_bounds(&deal.cfg.token_contract)
                                      .await
                                      .map_err(|error| {
                                          anyhow::anyhow!(
                                              "--token-contract {}: getConfig() claim bounds are \
                                               unreadable, refusing to start by-fact claiming on a \
                                               guessed cadence: {error}",
                                              deal.cfg.token_contract
                                          )
                                      })?;
                                  let snapshot = deal
                                      .chain
                                      .deal_snapshot(&deal.cfg.token_contract)
                                      .await
                                      .map_err(|error| {
                                          anyhow::anyhow!(
                                              "--token-contract {}: strict coherent deal snapshot is \
                                               unreadable, refusing to choose the settlement driver \
                                               from guessed deal shape: {error}",
                                              deal.cfg.token_contract
                                          )
                                      })?
                                      .ok_or_else(|| {
                                          anyhow::anyhow!(
                                              "--token-contract {}: strict coherent deal snapshot \
                                               returned no data after stream open",
                                              deal.cfg.token_contract
                                          )
                                      })?;
                                  let run_subscription_keeper =
                                      snapshot.subscription.is_subscription();
                                  let windows =
                                      dexdo::seller::AdvanceWindows::from_bounds(bounds);
                                  let note = seller.note.clone();
                                  let delivery = seller.state.delivery(&deal.cfg.token_contract);
                                  let token_contract = deal.cfg.token_contract.clone();
                                  let chain = deal.chain.clone();
                                  let gateway = seller.state.clone();
                                  let tick_budget = u128::from(deal.cfg.max_ticks);
                                  let tick_size = dexdo_core::DobParams::canonical().tick_size;
                                  active.spawn(async move {
                                      let result = if !run_subscription_keeper {
                                          let observer = OrdinaryCapacityObserver { gateway };
                                          dexdo::seller::drive_advance_with_observer(
                                              chain.as_ref(),
                                              &token_contract,
                                              note.as_ref(),
                                              windows,
                                              tick_budget,
                                              tick_size,
                                              true,
                                              delivery.count.clone(),
                                              delivery.done.clone(),
                                              &observer,
                                          )
                                          .await
                                      } else {
                                          let advance = dexdo::seller::drive_advance(
                                              chain.as_ref(),
                                              &token_contract,
                                              note.as_ref(),
                                              windows,
                                              tick_budget,
                                              tick_size,
                                              false,
                                              delivery.count.clone(),
                                              delivery.done.clone(),
                                          );
                                          let observer =
                                              SubscriptionCapacityObserver { gateway };
                                          let keeper =
                                              dexdo::seller::drive_subscription_keeper_with_observer(
                                                  chain.as_ref(),
                                                  &token_contract,
                                                  bounds,
                                                  &observer,
                                          );
                                          tokio::pin!(advance);
                                          tokio::pin!(keeper);
                                          async {
                                              tokio::select! {
                                                  finalized = &mut keeper => finalized,
                                                  claimed = &mut advance => {
                                                      let claimed = claimed?;
                                                      let finalized = keeper.await?;
                                                      Ok(claimed.max(finalized))
                                                  }
                                              }
                                          }
                                          .await
                                      };
                                      (token_contract, chain, delivery, result)
                                  });
                                  Ok(())
                              }
                              .await;
                              if let Err(error) = spawn_result {
                                  seller.state.unregister_stream(&deal.cfg.token_contract);
                                  first_error.get_or_insert(error);
                              }
                            }
                            Ok(true) => {
                                seller.state.unregister_stream(&deal.cfg.token_contract);
                            }
                            Err(error) => {
                                seller.state.unregister_stream(&deal.cfg.token_contract);
                                first_error.get_or_insert(error);
                            }
                        }
                    }
                    dexdo::seller::liveness::RestingSellerOutcome::Stopped { reason, disposition } => {
                        seller.state.unregister_stream(&deal.cfg.token_contract);
                        tracing::warn!(
                            token_contract = %deal.cfg.token_contract,
                            ?reason,
                            %disposition,
                            "seller pool retired one stopped resting deal"
                        );
                    }
                }
            }
            failure = seller.state.recv_upstream_failure() => {
                if let Some(failure) = failure {
                    emit_upstream_failure(failure);
                }
            }
            joined = active.join_next(), if !active.is_empty() => {
                if let Some(joined) = joined {
                    let _ = record_advance_result(
                        seller,
                        joined,
                        &mut terminal_receipts,
                        seller_policy,
                        &mut first_error,
                    ).await;
                }
            }
            joined = terminal_receipts.join_next(), if !terminal_receipts.is_empty() => {
                if let Some(joined) = joined {
                    let _ = record_terminal_receipt_result(joined, &mut first_error);
                }
            }
            _ = gateway_poll.tick() => {
                if seller.server_task.is_finished() {
                    stop_error = Some(anyhow::anyhow!(
                        "seller gateway stopped while pool deals were active"
                    ));
                    break 'pool;
                }
            }
        }
    }

    drop(watched);
    for (chain, cfg, identity) in resting.into_values() {
        let disposition =
            dexdo::seller::liveness::cancel_and_confirm(chain.as_ref(), &cfg, &identity).await;
        if matches!(
            disposition,
            dexdo::seller::liveness::CancellationDisposition::UnknownFailure { .. }
        ) {
            first_error.get_or_insert_with(|| {
                anyhow::anyhow!(
                    "seller pool could not confirm cancellation for {}: {disposition}",
                    cfg.token_contract
                )
            });
        }
    }
    seller.server_task.abort();
    if stopped_by_operator && first_error.is_none() && cascade_notes.is_empty() {
        emit_seller_shutdown_event(&primary_token_contract);
        return Ok(());
    }
    // the primary failure is the process error. A cascade note only becomes the process error
    // when it is the ONLY thing that went wrong; otherwise it hangs off the primary as `secondary`.
    match stop_error.or(first_error) {
        Some(error) => Err(attach_cascade_notes(error, cascade_notes)),
        None => match cascade_notes.into_iter().next() {
            Some(note) => Err(anyhow::Error::new(note)),
            None => Ok(()),
        },
    }
}

fn seller_upstream(
    args: &SellerArgs,
    model_name: Option<&str>,
    claimed_frame_model: Option<&str>,
) -> Result<dexdo::seller::UpstreamConfig> {
    if args.mock.mock_model {
        return Ok(match claimed_frame_model {
            Some(frame_model) => {
                dexdo::seller::UpstreamConfig::MockWithClaimedModel(frame_model.to_string())
            }
            None => dexdo::seller::UpstreamConfig::Mock,
        });
    }
    let name = model_name.filter(|name| !name.is_empty()).ok_or_else(|| {
        anyhow::anyhow!("set --model <name from config> (or --mock-model for a mock upstream)")
    })?;
    let models = dexdo::seller::ModelsConfig::load(&args.models)?;
    let model = models.get(name)?;
    model.require_api_key_present()?;
    Ok(if dexdo::seller::AnthropicConfig::supports(model) {
        dexdo::seller::UpstreamConfig::Anthropic(dexdo::seller::AnthropicConfig::from_model(
            model,
            claimed_frame_model,
        ))
    } else {
        dexdo::seller::UpstreamConfig::OpenAi(dexdo::seller::OpenAiConfig::from_model(
            model,
            claimed_frame_model,
        ))
    })
}

pub(crate) async fn run_seller(args: SellerArgs) -> Result<()> {
    // reject an invalid limit SELL price at the command boundary, before any file or chain work.
    super::support::validate_price_step(args.price_per_tick as u128)?;
    // the advertised gateway is what a REMOTE buyer dials out of the handover. Validate it at
    // the command boundary -- before any file, chain or order-book work -- so a non-routable address
    // can never reach `postSellOffer` and leave a resting ask no buyer can connect to.
    let gateway_advertise = args.checked_gateway_advertise_addr()?;
    // Issue: the deal token_contract comes from `--market`(a provision manifest) or `--token-contract`.
    // The manifest's frame_model(if any) is validated against `--model` inside `seller_real_backend`.
    let (mut token_contract, mut market_frame_model, market_nonce) =
        resolve_market_fields(args.market.as_deref(), args.token_contract.as_deref(), None)?;
    let mut startup_market = args.market.as_deref().map(load_market).transpose()?;
    // Review: the deal nonce comes from `--market`(the manifest) or the explicit `--nonce` flag --
    // never both(the manifest is the single source of truth). The real-shellnet seller path requires
    // it(see `seller_real_backend`); the mock path ignores it.
    if args.market.is_some() && args.nonce.is_some() {
        bail!("--market and --nonce are mutually exclusive -- the nonce comes from the manifest");
    }
    let shutdown = operator_shutdown_signal().fuse();
    tokio::pin!(shutdown);
    let mut shutdown_requested = futures::poll!(shutdown.as_mut()).is_ready();
    let seller_policy = if !args.mock.mock_chain {
        policy::load_seller_runtime_policy(args.policy.as_deref())?
    } else {
        policy::SellerRuntimePolicy {
            after_deal_done: policy::SellerAfterDealDoneAction::Retire,
            buyer_no_show: policy::SellerBuyerNoShowAction::RetireGateway,
            dispute_against_me: policy::SellerDisputeAgainstMeAction::Hold,
            max_open_deals: 2,
        }
    };
    tracing::debug!(
        policy_after_deal_done = seller_policy.after_deal_done.as_str(),
        policy_buyer_no_show = seller_policy.buyer_no_show.as_str(),
        policy_dispute_against_me = seller_policy.dispute_against_me.as_str(),
        policy_max_open_deals = seller_policy.max_open_deals,
        "seller policy loaded"
    );
    #[cfg(feature = "shellnet")]
    let (_seller_pool_lock, mut persistent_gateway_tls) = if args.mock.mock_chain {
        (None, None)
    } else {
        let note_addr = args.identity.note_addr.as_deref().ok_or_else(|| {
            anyhow::anyhow!("real shellnet: --note-addr is required for seller pool locking")
        })?;
        let pool_dir = seller_pool_dir(args.deals_dir.as_deref(), note_addr)?;
        (
            Some(acquire_seller_pool_lock(&pool_dir)?),
            Some(load_or_create_gateway_tls(&pool_dir)?),
        )
    };
    #[cfg(not(feature = "shellnet"))]
    let mut persistent_gateway_tls = None;
    // on the real path, the --market manifest's seller_note must be this seller's --note-addr -- else the
    // offer posts a non-canonical TC the InferenceOrderBook won't rest, and the seller never matches.
    if !args.mock.mock_chain {
        if let (Some(manifest), Some(note_addr)) =
            (startup_market.as_ref(), args.identity.note_addr.as_deref())
        {
            assert_market_seller_note(&manifest.seller_note, note_addr)?;
        }
    }
    let mut deal_nonce = market_nonce.or(args.nonce);
    let recovery_frame_model = if args.mock.mock_chain {
        None
    } else {
        let name = args
            .model
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "real shellnet: set --model <name from config> (needed for model_hash)"
                )
            })?;
        Some(match market_frame_model.as_ref() {
            Some(frame_model) => frame_model.clone(),
            None => dexdo::seller::ModelsConfig::load(&args.models)?
                .get(name)?
                .frame_model
                .clone(),
        })
    };
    // The locally selected market/config model is enough to find and cancel a SELL from an
    // earlier run. Fallible registry, credential and note-readiness checks happen after that
    // exact identity is captured.
    let mock_endpoints_file = args
        .mock
        .mock_chain
        .then(|| resolve_endpoints_file(args.endpoints_file.clone()))
        .transpose()?;
    let (mut chain, mut note) = if let Some(endpoints_file) = mock_endpoints_file.as_ref() {
        mock_chain_and_note(endpoints_file.clone(), &args.identity)?
    } else {
        seller_real_backend(
            &args,
            market_frame_model.as_deref(),
            deal_nonce,
            recovery_frame_model.as_deref(),
        )?
    };
    let seller_owner = args.identity.note_addr.clone().unwrap_or_else(|| {
        format!(
            "0:{}",
            note.pubkey()
                .ed
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    });
    let mut resumed_descendant = false;
    // Terms come from the selected TC. If that lineage is already terminal, only its persisted
    // replacement link may redirect startup to a same-note deal handle.
    let mut terms = chain.sell_offer_terms(&token_contract).await;
    let mut unavailable_consumed = false;
    if !matches!(&terms, Ok(Some(_))) {
        let initial_fill = dexdo::seller::read_seller_fill_lineage(
            &seller_watch_cursor_path(args.deals_dir.as_deref(), &token_contract)?,
            &token_contract,
        )?;
        if let Some(mut linked) = initial_fill
            .as_ref()
            .and_then(|fill| fill.replacement_token_contract.clone())
        {
            let markets = seller_market_handles(
                args.deals_dir.as_deref(),
                &seller_owner,
                &gateway_advertise,
            )?;
            let mut ancestor = token_contract.clone();
            let mut visited = std::collections::HashSet::new();
            loop {
                if !visited.insert(deals::normalize_addr(&ancestor)) {
                    bail!("seller replacement lineage contains a cycle at {ancestor}");
                }
                let market = markets
                    .get(&deals::normalize_addr(&linked))
                    .cloned()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "seller replacement lineage links {ancestor} to {linked}, but no same-note deal handle carries its market"
                        )
                    })?;
                let (descendant_chain, descendant_note) =
                    if let Some(endpoints_file) = mock_endpoints_file.as_ref() {
                        let chain: Arc<dyn dexdo_core::ChainBackend> =
                            Arc::new(dexdo_core::MockChainBackend::new(
                                endpoints_file.clone(),
                                dexdo_core::ProtocolConsts::canonical(),
                                DobParams::canonical(),
                            ));
                        (chain, note.clone())
                    } else {
                        seller_real_backend(
                            &args,
                            Some(&market.frame_model),
                            Some(market.nonce),
                            Some(&market.frame_model),
                        )?
                    };
                let descendant_terms = descendant_chain.sell_offer_terms(&linked).await;
                let descendant_fill = if matches!(&descendant_terms, Ok(Some(_))) {
                    None
                } else {
                    dexdo::seller::read_seller_fill_lineage(
                        &seller_watch_cursor_path(args.deals_dir.as_deref(), &linked)?,
                        &linked,
                    )?
                };
                let next = descendant_fill
                    .as_ref()
                    .and_then(|fill| fill.replacement_token_contract.clone());
                let mock_unposted = args.mock.mock_chain
                    && matches!(&descendant_terms, Ok(None))
                    && descendant_fill.is_none();
                if matches!(&descendant_terms, Ok(Some(_))) || mock_unposted {
                    terms = if mock_unposted {
                        Ok(Some((
                            u64::try_from(market.price_per_tick).map_err(|_| {
                                anyhow::anyhow!(
                                    "seller market {} price exceeds u64",
                                    market.token_contract
                                )
                            })?,
                            u64::try_from(market.max_ticks).map_err(|_| {
                                anyhow::anyhow!(
                                    "seller market {} max_ticks exceeds u64",
                                    market.token_contract
                                )
                            })?,
                        )))
                    } else {
                        descendant_terms
                    };
                    token_contract = linked;
                    market_frame_model = Some(market.frame_model.clone());
                    deal_nonce = Some(market.nonce);
                    startup_market = Some(market);
                    chain = descendant_chain;
                    note = descendant_note;
                    resumed_descendant = true;
                    break;
                }
                let Some(next) = next else {
                    terms = descendant_terms;
                    unavailable_consumed = descendant_fill.is_some();
                    break;
                };
                ancestor = linked;
                linked = next;
            }
        } else {
            unavailable_consumed = initial_fill.is_some();
        }
    }
    let (price, ticks) = match terms? {
        Some(terms) => terms,
        None if args.mock.mock_chain && !unavailable_consumed => (args.price_per_tick, 1024),
        None => {
            bail!(
                "seller requires a deployed per-deal TokenContract; selected {} is unavailable \
                 and has no active persisted replacement descendant",
                token_contract
            )
        }
    };
    let (offer_ticks, offer_price) = {
        if !args.mock.mock_chain {
            println!(
                "posting offer: {ticks} ticks (= {} model tokens) at {price} raw ECC[2]/tick \
             (PRICE_STEP 1000000000 = 1 SHELL)",
                (ticks as u128).saturating_mul(DobParams::canonical().tick_size as u128)
            );
        }
        (ticks, price)
    };
    // The real path publishes the TC getter value, not the CLI fallback. Validate the actual
    // write-bound price as well, after read-only term discovery and before postSellOffer.
    super::support::validate_price_step(offer_price as u128)?;
    let mut cfg = dexdo::seller::SellerConfig {
        token_contract: token_contract.clone(),
        price_per_tick: offer_price,
        max_ticks: offer_ticks,
        subscription: args.subscription,
        gateway_advertise: gateway_advertise.clone(),
        mock_token_count: args.mock_token_count,
    };
    let inspection =
        dexdo::seller::inspect_seller_offer(chain.as_ref(), &cfg, Some(&seller_owner)).await?;
    let mut inspected_identity = match inspection {
        dexdo::seller::SellerOfferInspection::Resting { order_id } => {
            Some(dexdo::seller::liveness::RestingOfferIdentity {
                owner_note: seller_owner.clone(),
                token_contract: token_contract.clone(),
                order_id,
            })
        }
        dexdo::seller::SellerOfferInspection::Funded
        | dexdo::seller::SellerOfferInspection::Vacant => None,
    };

    let preflight_result = if shutdown_requested {
        None
    } else {
        let preflight = async {
            #[cfg(test)]
            if std::env::var_os("DEXDO_TEST_668_PENDING_SELLER_PREFLIGHT").is_some() {
                println!("seller-restart-preflight-pending");
                let _ = std::io::stdout().flush();
                std::future::pending::<()>().await;
            }
            let mut registry_frame_model = None;
            if !args.mock.mock_chain {
                shellnet_doctor_preflight(
                    &args.contracts,
                    (!resumed_descendant)
                        .then_some(args.market.as_deref())
                        .flatten(),
                )
                .await?;
                if let Some(policy) = load_enabled_model_registry_policy(
                    RegistryRole::Seller,
                    &args.registry,
                    &args.contracts,
                )? {
                    let name = args
                        .model
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "real shellnet: set --model <name from config> (needed for model registry validation)"
                            )
                        })?;
                    let configured_frame_model = dexdo::seller::ModelsConfig::load(&args.models)?
                        .get(name)?
                        .frame_model
                        .clone();
                    let selected_market = startup_market.clone();
                    let target = resolve_model_registry_target(
                        RegistryRole::Seller,
                        Some(&policy),
                        &args.contracts,
                        &configured_frame_model,
                        BookTarget {
                            frame_model: selected_market
                                .as_ref()
                                .map(|market| market.frame_model.clone())
                                .unwrap_or_else(|| configured_frame_model.clone()),
                            model_hash: selected_market
                                .as_ref()
                                .map(|market| market.model_hash.clone())
                                .unwrap_or_else(|| {
                                    dexdo_core::model_hash_for(&configured_frame_model)
                                }),
                            order_book: selected_market
                                .as_ref()
                                .map(|market| market.inference_order_book.clone()),
                            root_model: selected_market
                                .as_ref()
                                .map(|market| market.root_model.clone()),
                            note_addr: args.identity.note_addr.clone(),
                        },
                    )
                    .await?;
                    let frame_model = target.frame_model;
                    check_market_model_match(market_frame_model.as_deref(), &frame_model, name)?;
                    let expected_order_book = if let Some(order_book) = target.order_book {
                        order_book
                    } else {
                        let note_addr =
                            args.identity.note_addr.as_deref().ok_or_else(|| {
                                anyhow::anyhow!(
                                    "real shellnet: --note-addr is required to derive the seller order book"
                                )
                            })?;
                        expected_order_book_for_note(&args.contracts, note_addr, &frame_model)
                            .await?
                    };
                    let order_book_active =
                        order_book_active_from_contracts(&args.contracts, &expected_order_book)
                            .await?;
                    enforce_model_registry_policy(
                        RegistryRole::Seller,
                        &policy,
                        &args.contracts,
                        &frame_model,
                        &expected_order_book,
                        order_book_active,
                        BuyerMissingBookPolicy::Reject,
                    )
                    .await?;
                    if inspected_identity.is_some()
                        && recovery_frame_model.as_deref() != Some(frame_model.as_str())
                    {
                        bail!(
                            "model registry resolved {frame_model}, but the existing exact SELL \
                             was found under {}; cancelling it before restart",
                            recovery_frame_model.as_deref().unwrap_or("the local model")
                        );
                    }
                    registry_frame_model = Some(frame_model);
                }
            }

            if registry_frame_model.as_deref() != recovery_frame_model.as_deref() {
                if let Some(frame_model) = registry_frame_model.as_deref() {
                    let (resolved_chain, resolved_note) = seller_real_backend(
                        &args,
                        market_frame_model.as_deref(),
                        deal_nonce,
                        Some(frame_model),
                    )?;
                    chain = resolved_chain;
                    note = resolved_note;
                    let inspection = dexdo::seller::inspect_seller_offer(
                        chain.as_ref(),
                        &cfg,
                        Some(&seller_owner),
                    )
                    .await?;
                    inspected_identity = match inspection {
                        dexdo::seller::SellerOfferInspection::Resting { order_id } => {
                            Some(dexdo::seller::liveness::RestingOfferIdentity {
                                owner_note: seller_owner.clone(),
                                token_contract: token_contract.clone(),
                                order_id,
                            })
                        }
                        dexdo::seller::SellerOfferInspection::Funded
                        | dexdo::seller::SellerOfferInspection::Vacant => None,
                    };
                }
            }

            Ok(registry_frame_model)
        };
        tokio::pin!(preflight);
        tokio::select! {
            biased;
            _ = shutdown.as_mut() => {
                shutdown_requested = true;
                None
            },
            result = &mut preflight => Some(result),
        }
    };
    let (registry_frame_model, preflight_error) = match preflight_result {
        Some(Ok(ready)) => (ready, None),
        Some(Err(error)) => (None, Some(error)),
        None => (None, None),
    };
    let seller_frame_model_for_handle = if args.mock.mock_chain {
        None
    } else {
        Some(
            registry_frame_model
                .clone()
                .or_else(|| recovery_frame_model.clone())
                .expect("real seller model was resolved"),
        )
    };
    let seller_deals_dir = deals::resolve_deals_dir(args.deals_dir.as_deref())?;

    let seller = match start_seller_gateway_with_liveness(
        async {
            if let Some(error) = preflight_error {
                return Err(error);
            }
            let upstream = seller_upstream(
                &args,
                args.model.as_deref(),
                registry_frame_model.as_deref(),
            )?;
            // these fallible note readiness reads are protected by the exact
            // restart identity above, before any new seller-chain write is possible.
            chain.assert_note_current().await?;
            chain.assert_note_can_post_sell_offer().await?;
            match persistent_gateway_tls.take() {
                Some(tls) => {
                    dexdo::seller::start_gateway_with_note_tls_and_deals_dir(
                        args.gateway_listen,
                        upstream,
                        note,
                        seller_deals_dir.clone(),
                        tls,
                    )
                    .await
                }
                None => {
                    dexdo::seller::start_gateway_with_note_and_deals_dir(
                        args.gateway_listen,
                        upstream,
                        note,
                        seller_deals_dir.clone(),
                    )
                    .await
                }
            }
        },
        chain.as_ref(),
        &cfg,
        inspected_identity.as_ref(),
        async {
            if !shutdown_requested {
                shutdown.as_mut().await;
            }
        },
    )
    .await?
    {
        SellerGatewayStartup::Ready(seller) => seller,
        SellerGatewayStartup::Stopped {
            reason,
            disposition,
        } => {
            if let dexdo::seller::liveness::RestingStopReason::Health(failure) = &reason {
                emit_seller_liveness_event(
                    &token_contract,
                    inspected_identity
                        .as_ref()
                        .map(|identity| identity.owner_note.as_str())
                        .or(Some(&seller_owner)),
                    inspected_identity
                        .as_ref()
                        .map(|identity| identity.order_id),
                    "seller_health",
                    Some(failure.component.as_str()),
                    if failure.timed_out { "timeout" } else { "fail" },
                    None,
                );
            }
            emit_seller_liveness_event(
                &token_contract,
                inspected_identity
                    .as_ref()
                    .map(|identity| identity.owner_note.as_str())
                    .or(Some(&seller_owner)),
                inspected_identity
                    .as_ref()
                    .map(|identity| identity.order_id),
                "seller_offer_terminal",
                None,
                disposition.as_str(),
                disposition.known_result(),
            );
            return match reason {
                dexdo::seller::liveness::RestingStopReason::Shutdown
                    if matches!(
                        &disposition,
                        dexdo::seller::liveness::CancellationDisposition::Cancelled
                            | dexdo::seller::liveness::CancellationDisposition::AlreadyAbsent
                    ) =>
                {
                    emit_seller_shutdown_event(&token_contract);
                    Ok(())
                }
                dexdo::seller::liveness::RestingStopReason::Shutdown => Err(anyhow::anyhow!(
                    "seller shutdown during gateway startup did not reach a cancellable terminal: \
                     token_contract={token_contract}; cancellation_disposition={disposition}"
                )),
                dexdo::seller::liveness::RestingStopReason::Health(failure) => {
                    Err(anyhow::anyhow!(
                        "seller gateway startup failed while exact SELL rested: {failure}; \
                         cancellation_disposition={disposition}"
                    ))
                }
                dexdo::seller::liveness::RestingStopReason::Watcher(error) => Err(anyhow::anyhow!(
                    "seller gateway startup watcher failed: {error}; \
                     cancellation_disposition={disposition}"
                )),
            };
        }
    };
    // `--gateway-listen <host>:0` asks the OS for a free port, and an advertise inherited from
    // it was resolved before the listener existed, so it still says `:0` -- a port nobody can dial,
    // neither the buyer out of the handover nor this seller's own self-probe. The gateway is bound
    // now, so adopt the real port here: before readiness, before the deal handle and the handover
    // are written, and before any order is posted.
    let gateway_advertise = args.bound_gateway_advertise(gateway_advertise, seller.listen_addr);
    cfg.gateway_advertise.clone_from(&gateway_advertise);
    let watch = dexdo::seller::SellerMatchWatchConfig {
        cursor_path: seller_watch_cursor_path(args.deals_dir.as_deref(), &token_contract)?,
        poll_interval: DEFAULT_MATCH_POLL_INTERVAL,
    };
    let note_addr = args.identity.note_addr.as_deref().unwrap_or(&seller_owner);
    let frame_model = seller_frame_model_for_handle.as_deref().unwrap_or("mock");
    let context = SellerPoolContext {
        deals_dir: args.deals_dir.as_deref(),
        contracts: &args.contracts,
        note_addr,
        frame_model,
        gateway_advertise: &gateway_advertise,
        advertise_probe: args.advertise_probe_policy(),
    };
    let initial = SellerPoolDeal {
        chain,
        cfg,
        watch,
        upstream: seller_upstream(
            &args,
            args.model.as_deref(),
            registry_frame_model.as_deref(),
        )?,
        nonce: deal_nonce.unwrap_or(0),
        market: startup_market,
    };
    let pool = load_seller_pool_deals(&context, initial, args.mock_token_count, |market| {
        if let Some(endpoints_file) = mock_endpoints_file.as_ref() {
            let chain: Arc<dyn dexdo_core::ChainBackend> =
                Arc::new(dexdo_core::MockChainBackend::new(
                    endpoints_file.clone(),
                    dexdo_core::ProtocolConsts::canonical(),
                    DobParams::canonical(),
                ));
            Ok((
                chain,
                seller_upstream(&args, args.model.as_deref(), Some(&market.frame_model))?,
            ))
        } else {
            let (chain, _) = seller_real_backend(
                &args,
                Some(&market.frame_model),
                Some(market.nonce),
                Some(&market.frame_model),
            )?;
            Ok((
                chain,
                seller_upstream(&args, Some(&market.frame_model), Some(&market.frame_model))?,
            ))
        }
    })
    .await?;
    let args_ref = &args;
    let provision_endpoints = mock_endpoints_file.clone();
    let provision_seller = seller_owner.clone();
    let mut provisioner = |frame_model: String, nonce, price_per_tick, max_ticks| {
        let provision_endpoints = provision_endpoints.clone();
        let provision_seller = provision_seller.clone();
        async move {
            if let Some(endpoints_file) = provision_endpoints.as_ref() {
                let identity = format!("{provision_seller}:{frame_model}:{nonce}");
                let token_contract = format!(
                    "0:{}",
                    dexdo_core::model_hash_for(&identity).trim_start_matches("0x")
                );
                let market = dexdo_core::MarketManifest {
                    network: "mock".to_string(),
                    frame_model: frame_model.clone(),
                    model_hash: dexdo_core::model_hash_for(&frame_model),
                    inference_order_book: "mock".to_string(),
                    root_model: "mock".to_string(),
                    token_contract,
                    seller_note: provision_seller.clone(),
                    nonce,
                    price_per_tick: u128::from(price_per_tick),
                    max_ticks: u128::from(max_ticks),
                };
                let chain: Arc<dyn dexdo_core::ChainBackend> =
                    Arc::new(dexdo_core::MockChainBackend::new(
                        endpoints_file.clone(),
                        dexdo_core::ProtocolConsts::canonical(),
                        DobParams::canonical(),
                    ));
                return Ok((market, chain));
            }
            provision_replacement_seller(args_ref, &frame_model, nonce, price_per_tick, max_ticks)
                .await
        }
    };
    let result = run_seller_pool(
        &seller,
        pool,
        context,
        &seller_policy,
        &mut provisioner,
        shutdown.as_mut(),
    )
    .await;
    if result.is_err() {
        seller.server_task.abort();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use dexdo::seller::{
        liveness::RestingOfferIdentity, prepare_seller_offer, SellerConfig, SellerOfferStartup,
    };
    use dexdo_core::{
        ChainBackend, ChainError, DealBuyerBond, DealChainSnapshot, DealChainState, DealSellerBond,
        DealSubscription, DobParams, LocalNote, Match, MatchWatchCursor, MatchedFill,
        MockChainBackend, Note, NotePubkey, OfferListing, ProtocolConsts, SellOffer,
        SellOfferOutcome, Settlement, StreamSnapshot, TokenContract,
    };
    #[cfg(feature = "shellnet")]
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn persisted_gateway_tls_survives_restart_and_pinned_reconnects() {
        let root = tempfile::tempdir().unwrap();
        let note_addr = format!("0:{}", "a".repeat(64));
        let pool_dir = seller_pool_dir(Some(root.path()), &note_addr).unwrap();
        let tls = load_or_create_gateway_tls(&pool_dir).unwrap();
        let fingerprint = tls.fingerprint.clone();
        let note = Arc::new(LocalNote::generate());
        let first = dexdo::seller::start_gateway_with_note_tls(
            "127.0.0.1:0".parse().unwrap(),
            dexdo::seller::UpstreamConfig::Mock,
            note.clone(),
            tls,
        )
        .await
        .unwrap();
        dexdo::buyer::tls::connect_pinned(&format!("https://{}", first.listen_addr), &fingerprint)
            .await
            .expect("first pinned TLS connection");
        first.server_task.abort();
        let _ = first.server_task.await;

        let restored = load_or_create_gateway_tls(&pool_dir).unwrap();
        assert_eq!(restored.fingerprint, fingerprint);
        // shape C: re-binding the first gateway's exact port races whoever the kernel hands it
        // to in between(and the first gateway's own closed connections keep it in TIME_WAIT). What
        // this test proves is that the PERSISTED certificate survives a restart, and the reconnect
        // below already dials `second.listen_addr` -- so the restart takes a fresh ephemeral port.
        let second = dexdo::seller::start_gateway_with_note_tls(
            "127.0.0.1:0".parse().unwrap(),
            dexdo::seller::UpstreamConfig::Mock,
            note,
            restored,
        )
        .await
        .unwrap();
        dexdo::buyer::tls::connect_pinned(&format!("https://{}", second.listen_addr), &fingerprint)
            .await
            .expect("restart must present the certificate pinned in the existing handover");
        second.server_task.abort();
        let _ = second.server_task.await;
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn seller_pool_lock_contention_fails_before_any_chain_write() {
        let root = tempfile::tempdir().unwrap();
        let note_addr = format!("0:{}", "a".repeat(64));
        let deals_dir = root.path().join("deals");
        let pool_dir = seller_pool_dir(Some(&deals_dir), &note_addr).unwrap();
        let _lock = acquire_seller_pool_lock(&pool_dir).unwrap();
        let policy_path = root.path().join("policy.json");
        std::fs::write(
            &policy_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "seller": {
                    "on": {
                        "after_deal_done": "retire",
                        "buyer_no_show": "retire_gateway",
                        "dispute_against_me": "hold"
                    },
                    "max_open_deals": 2
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let endpoints = root.path().join("must-not-be-written.json");
        let error = super::run_seller(crate::cli::args::SellerArgs {
            mock: crate::cli::args::MockFlags {
                mock_model: true,
                mock_chain: false,
            },
            identity: crate::cli::args::IdentityArgs {
                note_key: Some(root.path().join("missing-note.key")),
                note_index: 0,
                note_addr: Some(note_addr),
            },
            registry: crate::cli::args::ModelRegistryValidationArgs::default(),
            gateway_listen: "127.0.0.1:0".parse().unwrap(),
            gateway_advertise: None,
            // this test is about the pool lock, so opt into the loopback advertise explicitly.
            allow_private_advertise: true,
            require_advertise_probe: false,
            endpoints_file: Some(endpoints.clone()),
            deals_dir: Some(deals_dir),
            token_contract: Some(format!("0:{}", "b".repeat(64))),
            market: None,
            nonce: Some(7),
            subscription: false,
            price_per_tick: dexdo_core::PRICE_STEP as u64,
            mock_token_count: 8,
            model: Some("unused".to_string()),
            models: root.path().join("missing-models.json"),
            contracts: root.path().join("missing-contracts.json"),
            policy: Some(policy_path),
        })
        .await
        .expect_err("second seller process for one note must fail on the production lock");
        assert!(error.to_string().contains("already running"), "{error:#}");
        assert!(
            !endpoints.exists(),
            "lock contention must fail before constructing a chain backend or writing endpoints"
        );
    }

    fn signal_test_token_contract() -> String {
        format!("0:{}", "a".repeat(64))
    }

    #[tokio::test]
    async fn subscription_keeper_observer_updates_week_cap_and_removes_terminal_record() {
        let gateway = Arc::new(dexdo::seller::gateway::GatewayState::new());
        let token_contract = "0:subscription-capacity-observer".to_string();
        let buyer = LocalNote::generate();
        let state = dexdo_core::DealChainState {
            funded: true,
            opened: true,
            probe_accepted: true,
            disputed: false,
            deposit: 1,
            finalized_owed: 0,
            tokens_final: dexdo_core::TICK_SIZE,
            tokens_superseded: dexdo_core::TICK_SIZE,
            tokens_pending: dexdo_core::TICK_SIZE,
            probe_tick: 0,
            funded_time: Some(1),
            probe_time: 1,
            prev_claim_time: 1,
            last_claim_time: 1,
            dispute_time: 0,
        };
        let week_zero = dexdo_core::DealSubscription {
            deal_flags: dexdo_core::order_flags::SUBSCRIPTION,
            sub_weeks: dexdo_core::SUBSCRIPTION_WEEKS,
            week_index: 0,
            tokens_per_week: 2 * dexdo_core::TICK_SIZE,
            funded_tokens: u128::from(dexdo_core::SUBSCRIPTION_WEEKS) * 2 * dexdo_core::TICK_SIZE,
            tokens_paid: 0,
            period_start: 1,
            week_base_tokens: 0,
        };
        gateway
            .register_stream(&token_contract, buyer.pubkey(), 100, state, week_zero)
            .unwrap();

        let week_one = dexdo_core::DealSubscription {
            week_index: 1,
            tokens_paid: 2 * dexdo_core::TICK_SIZE,
            week_base_tokens: dexdo_core::TICK_SIZE,
            ..week_zero
        };
        let snapshot = dexdo_core::DealChainSnapshot {
            account_code_hash: "test-code".to_string(),
            account_boc_hash: "test-boc".to_string(),
            state,
            subscription: week_one,
            seller_bond: dexdo_core::DealSellerBond {
                bond_funded: true,
                bond_held: 1,
                bond_required: 1,
            },
            buyer_bond: dexdo_core::DealBuyerBond {
                bond_held: 1,
                bond_required: 1,
            },
        };
        let observer = SubscriptionCapacityObserver {
            gateway: gateway.clone(),
        };
        dexdo::seller::SubscriptionKeeperObserver::observe(
            &observer,
            &token_contract,
            Some(&snapshot),
        )
        .await
        .unwrap();
        assert_eq!(
            gateway
                .reconcile_subscription_capacity(&token_contract, state, week_one)
                .unwrap()
                .unwrap()
                .authoritative_cap,
            3 * dexdo_core::TICK_SIZE
        );

        let final_week = dexdo_core::DealSubscription {
            week_index: dexdo_core::SUBSCRIPTION_WEEKS,
            tokens_paid: week_zero.funded_tokens,
            week_base_tokens: state.tokens_pending,
            ..week_zero
        };
        let final_snapshot = dexdo_core::DealChainSnapshot {
            subscription: final_week,
            ..snapshot.clone()
        };
        dexdo::seller::SubscriptionKeeperObserver::observe(
            &observer,
            &token_contract,
            Some(&final_snapshot),
        )
        .await
        .unwrap();
        let final_capacity = gateway
            .reconcile_subscription_capacity(&token_contract, state, final_week)
            .unwrap()
            .unwrap();
        assert_eq!(final_capacity.authoritative_cap, state.tokens_pending);
        assert_eq!(final_capacity.available().unwrap(), 0);

        dexdo::seller::SubscriptionKeeperObserver::observe(&observer, &token_contract, None)
            .await
            .unwrap();

        let nonce = vec![7; 32];
        gateway.auth.issue_challenge(&token_contract, nonce.clone());
        let signature = buyer.sign(&dexdo::seller::auth::challenge_bytes(
            &token_contract,
            &nonce,
        ));
        let service = dexdo::seller::gateway::GatewayService::new(gateway);
        let error = dexdo_proto::Gateway::open_stream(
            &service,
            tonic::Request::new(dexdo_proto::StreamRequest {
                token_contract,
                nonce,
                signature: signature.0.to_vec(),
                request: Some(dexdo_proto::CanonRequest {
                    messages: Vec::new(),
                    params: Some(dexdo_proto::SamplingParams {
                        max_tokens: 1,
                        ..dexdo_proto::SamplingParams::default()
                    }),
                }),
            }),
        )
        .await
        .err()
        .expect("terminal capacity removal must reject before upstream");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("capacity is not registered"));
    }

    async fn existing_resting_offer(
        name: &str,
        note: Arc<LocalNote>,
        gateway_advertise: String,
    ) -> (
        MockChainBackend,
        SellerConfig,
        RestingOfferIdentity,
        tempfile::TempDir,
    ) {
        let token_contract = signal_test_token_contract();
        // `temp_dir()/dexdo-668-<name>-<pid>` is not unique -- a container's PID namespace
        // hands the test process the same small pid every run, and to both CI pipelines at once --
        // and nothing ever removed it. `tempfile` gives a random name and removes it on drop.
        let root = tempfile::Builder::new()
            .prefix(name)
            .tempdir()
            .expect("seller test directory");
        let root_path = root.path();
        let chain = MockChainBackend::new(
            root_path.join("endpoints.json"),
            ProtocolConsts::canonical(),
            DobParams::canonical(),
        );
        let owner = format!(
            "0:{}",
            note.pubkey()
                .ed
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let config = SellerConfig {
            token_contract: token_contract.clone(),
            price_per_tick: dexdo_core::PRICE_STEP as u64,
            max_ticks: 1024,
            subscription: false,
            gateway_advertise,
            mock_token_count: 8,
        };
        let startup = prepare_seller_offer(note.as_ref(), &chain, &config, Some(&owner))
            .await
            .expect("post existing resting SELL");
        let order_id = match startup {
            SellerOfferStartup::Posted {
                outcome: Some(SellOfferOutcome::Rested { order_id }),
            } => order_id,
            other => panic!("expected one resting SELL, got {other:?}"),
        };
        (
            chain,
            config,
            RestingOfferIdentity {
                owner_note: owner,
                token_contract,
                order_id,
            },
            root,
        )
    }

    #[tokio::test]
    async fn occupied_gateway_startup_cancels_existing_exact_sell_without_repost() {
        let note = Arc::new(LocalNote::generate());
        let (chain, config, identity, _root) =
            existing_resting_offer("occupied-bind", note.clone(), "127.0.0.1:1".to_string()).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let outcome = start_seller_gateway_with_liveness(
            dexdo::seller::start_gateway_with_note(addr, dexdo::seller::UpstreamConfig::Mock, note),
            &chain,
            &config,
            Some(&identity),
            std::future::pending(),
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            SellerGatewayStartup::Stopped {
                reason: dexdo::seller::liveness::RestingStopReason::Health(
                    dexdo::seller::liveness::HealthFailure {
                        component: dexdo::seller::liveness::HealthComponent::GatewayTask,
                        ..
                    }
                ),
                disposition: dexdo::seller::liveness::CancellationDisposition::Cancelled,
            }
        ));
        assert!(chain
            .raw_resting_sell_orders_for_tc(&config.token_contract)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            chain
                .confirm_offer_outcome(&config.token_contract)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn startup_signal_cancels_existing_exact_sell_before_gateway_ready() {
        let note = Arc::new(LocalNote::generate());
        let (chain, config, identity, _root) =
            existing_resting_offer("startup-signal", note, "127.0.0.1:1".to_string()).await;

        let outcome = start_seller_gateway_with_liveness(
            std::future::pending::<anyhow::Result<dexdo::seller::RunningSeller>>(),
            &chain,
            &config,
            Some(&identity),
            std::future::ready(()),
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            SellerGatewayStartup::Stopped {
                reason: dexdo::seller::liveness::RestingStopReason::Shutdown,
                disposition: dexdo::seller::liveness::CancellationDisposition::Cancelled,
            }
        ));
        assert!(chain
            .raw_resting_sell_orders_for_tc(&config.token_contract)
            .await
            .unwrap()
            .is_empty());
    }

    #[test]
    fn unknown_cancellation_event_is_structured_and_preserves_rejection() {
        let event = seller_liveness_event(
            "0:tc",
            Some("0:owner"),
            Some(17),
            "seller_offer_terminal",
            None,
            "unknown_failure",
            Some("cancel_submit=rejected: owner check failed"),
        );

        assert_eq!(event["token_contract"], "0:tc");
        assert_eq!(event["owner_note"], "0:owner");
        assert_eq!(event["order_id"], "17");
        assert_eq!(event["outcome"], "unknown_failure");
        assert_eq!(
            event["known_result"],
            "cancel_submit=rejected: owner check failed"
        );
    }

    #[tokio::test]
    async fn consumed_match_race_shutdown_does_not_require_a_second_signal() {
        let shutdown = std::future::pending::<()>();
        tokio::pin!(shutdown);
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            react_to_seller_shutdown_signal(shutdown.as_mut(), true, "0:tc"),
        )
        .await
        .expect("an already-observed shutdown must complete immediately");
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "subprocess helper for seller signal regression tests"]
    async fn seller_signal_child() {
        if std::env::var_os("DEXDO_SELLER_SIGNAL_CHILD").is_none() {
            return;
        }
        use dexdo::seller::{start_gateway_with_note, SellerMatchWatchConfig, UpstreamConfig};
        use std::time::Duration;

        let token_contract = signal_test_token_contract();
        let note = Arc::new(LocalNote::generate());
        let seller = start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            UpstreamConfig::Mock,
            note.clone(),
        )
        .await
        .expect("start signal-test gateway");
        let (chain, config, identity, root) =
            existing_resting_offer("signal", note, seller.listen_addr.to_string()).await;
        let root = root.path();
        let buyer_note = LocalNote::generate();
        chain
            .place_buy(&token_contract, &buyer_note)
            .await
            .expect("match signal-test SELL before starting the pool");
        let chain = Arc::new(chain);
        let order_id = identity.order_id;
        let contracts = root.join("unused-contracts.json");
        let deal = SellerPoolDeal {
            chain: chain.clone(),
            cfg: config.clone(),
            watch: SellerMatchWatchConfig {
                cursor_path: root.join("seller-watch.json"),
                poll_interval: Duration::from_millis(10),
            },
            upstream: UpstreamConfig::Mock,
            nonce: 1,
            market: None,
        };
        let context = SellerPoolContext {
            deals_dir: Some(root),
            contracts: &contracts,
            note_addr: &identity.owner_note,
            frame_model: "mock",
            gateway_advertise: &config.gateway_advertise,
            advertise_probe: dexdo::seller::liveness::AdvertiseProbePolicy::default(),
        };
        let mut provisioner = |_: String, _: u64, _: u64, _: u64| {
            futures::future::ready(Err::<
                (dexdo_core::MarketManifest, Arc<dyn ChainBackend>),
                anyhow::Error,
            >(anyhow::anyhow!(
                "unexpected residual provision"
            )))
        };
        let shutdown = crate::operator_shutdown_signal().fuse();
        tokio::pin!(shutdown);
        run_seller_pool(
            &seller,
            vec![deal],
            context,
            &pool_test_policy(1),
            &mut provisioner,
            shutdown.as_mut(),
        )
        .await
        .expect("seller pool signal shutdown completes");
        assert!(
            chain
                .raw_resting_sell_orders_for_tc(&token_contract)
                .await
                .expect("reread signal-test book")
                .is_empty(),
            "signal test must leave no resting SELL before process exit"
        );
        println!("seller-signal-order-absent order_id={order_id}");
    }

    #[cfg(unix)]
    fn assert_seller_signal_emits_shutdown_jsonl(signal: &str) {
        use std::io::{BufRead as _, Read as _};
        use std::process::{Command, Stdio};

        let mut child = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "cli::seller::tests::seller_signal_child",
                "--ignored",
                "--nocapture",
            ])
            .env("DEXDO_SELLER_SIGNAL_CHILD", "1")
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn seller signal regression child");
        let stdout = child.stdout.take().expect("capture child stdout");
        let mut stdout = std::io::BufReader::new(stdout);
        let mut output = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(
                stdout.read_line(&mut line).expect("read child readiness"),
                0,
                "seller child exited before readiness; output={output}"
            );
            output.push_str(&line);
            if line.contains("seller_match_opened token_contract=") {
                break;
            }
        }

        let signal = Command::new("kill")
            .args([signal, &child.id().to_string()])
            .status()
            .expect("send signal to seller child");
        assert!(signal.success(), "kill command failed: {signal}");
        stdout
            .read_to_string(&mut output)
            .expect("read seller child output");
        let status = child.wait().expect("wait for seller child");
        assert!(
            status.success(),
            "seller child failed: {status}; output={output}"
        );
        assert!(
            output.contains("seller-signal-order-absent order_id="),
            "seller signal path exited with a resting SELL: {output}"
        );
        assert!(
            output.contains("seller_match_opened token_contract="),
            "seller signal path never entered the live pool loop: {output}"
        );

        let shutdown = output
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|event| event["event"] == "stopping")
            .collect::<Vec<_>>();
        assert_eq!(
            shutdown.len(),
            1,
            "seller pool must emit exactly one stopping event: {output}"
        );
        assert_eq!(
            shutdown[0],
            serde_json::json!({
                "event": "stopping",
                "role": "seller",
                "token_contract": signal_test_token_contract(),
                "reason": "signal"
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn seller_sigint_emits_shutdown_jsonl() {
        assert_seller_signal_emits_shutdown_jsonl("-INT");
    }

    #[cfg(unix)]
    #[test]
    fn seller_sigterm_emits_shutdown_jsonl() {
        assert_seller_signal_emits_shutdown_jsonl("-TERM");
    }

    #[test]
    fn seller_ready_is_emitted_only_for_confirmed_resting_sell() {
        let identity = dexdo::seller::liveness::RestingOfferIdentity {
            owner_note: "0:owner".to_string(),
            token_contract: "0:tc".to_string(),
            order_id: 17,
        };
        let resumed = dexdo::seller::SellerOfferStartup::ResumedResting { order_id: 17 };
        let posted = dexdo::seller::SellerOfferStartup::Posted {
            outcome: Some(SellOfferOutcome::Rested { order_id: 17 }),
        };

        assert!(
            seller_ready_line("0:tc", "gateway", "listen", &resumed, Some(&identity))
                .unwrap()
                .contains("readiness=resumed_resting_offer")
        );
        assert!(
            seller_ready_line("0:tc", "gateway", "listen", &posted, Some(&identity))
                .unwrap()
                .contains("readiness=exact_tc_offer_accepted")
        );
        assert!(seller_ready_line(
            "0:tc",
            "gateway",
            "listen",
            &dexdo::seller::SellerOfferStartup::ResumedFunded,
            None,
        )
        .is_none());
        assert!(seller_ready_line(
            "0:tc",
            "gateway",
            "listen",
            &dexdo::seller::SellerOfferStartup::Posted {
                outcome: Some(SellOfferOutcome::Matched),
            },
            None,
        )
        .is_none());
    }

    #[test]
    fn seller_offer_placed_reports_rested_with_order_id() {
        assert_eq!(
            seller_offer_outcome_line(&SellOfferOutcome::Rested { order_id: 835 }),
            "seller_offer_outcome RESTED order_id=835"
        );
    }

    #[test]
    fn seller_offer_immediate_match_reports_matched() {
        assert_eq!(
            seller_offer_outcome_line(&SellOfferOutcome::Matched),
            "seller_offer_outcome MATCHED"
        );
    }

    #[test]
    fn seller_offer_startup_line_covers_every_resting_startup() {
        assert_eq!(
            seller_offer_startup_line(&dexdo::seller::SellerOfferStartup::Posted {
                outcome: Some(SellOfferOutcome::Rested { order_id: 5 }),
            })
            .as_deref(),
            Some("seller_offer_outcome RESTED order_id=5")
        );
        assert_eq!(
            seller_offer_startup_line(&dexdo::seller::SellerOfferStartup::ResumedResting {
                order_id: 5,
            })
            .as_deref(),
            Some("seller_offer_resume RESTING order_id=5")
        );
        assert_eq!(
            seller_offer_startup_line(&dexdo::seller::SellerOfferStartup::Posted {
                outcome: Some(SellOfferOutcome::Matched),
            })
            .as_deref(),
            Some("seller_offer_outcome MATCHED")
        );
        assert_eq!(
            seller_offer_startup_line(&dexdo::seller::SellerOfferStartup::ResumedFunded),
            None
        );
        assert_eq!(
            seller_offer_startup_line(&dexdo::seller::SellerOfferStartup::Posted { outcome: None }),
            None
        );
    }

    const STARTUP_CHILD_CASE: &str = "DEXDO_TEST_798_STARTUP_CASE";
    const STARTUP_CHILD_DONE: &str = "seller-offer-startup-child-done case=";

    /// regression driver: run the production `prepare_pool_deal` dispatch in a child process so
    /// the assertions read the bytes the seller actually writes to stdout, not a formatter in isolation
    /// (the emitted-nowhere formatter is exactly what made the release gate hang).
    #[tokio::test]
    #[ignore = "subprocess helper for seller offer startup announcement regressions"]
    async fn seller_offer_startup_child() {
        let Some(case) = std::env::var_os(STARTUP_CHILD_CASE) else {
            return;
        };
        use dexdo::seller::{start_gateway_with_note, SellerMatchWatchConfig, UpstreamConfig};
        use std::time::Duration;

        let case = case.to_string_lossy().into_owned();
        let note = Arc::new(LocalNote::generate());
        let seller = start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            UpstreamConfig::Mock,
            note.clone(),
        )
        .await
        .expect("start startup-announcement gateway");
        // `<name>-<pid>` is not unique across containers; `tempfile` is, and it cleans up.
        let root = tempfile::tempdir().expect("seller test directory");
        let root = root.path();
        let chain = MockChainBackend::new(
            root.join("endpoints.json"),
            ProtocolConsts::canonical(),
            DobParams::canonical(),
        );
        let owner = format!(
            "0:{}",
            note.pubkey()
                .ed
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let token_contract = signal_test_token_contract();
        let gateway_advertise = seller.listen_addr.to_string();
        let cfg = SellerConfig {
            token_contract: token_contract.clone(),
            price_per_tick: dexdo_core::PRICE_STEP as u64,
            max_ticks: 1024,
            subscription: false,
            gateway_advertise: gateway_advertise.clone(),
            mock_token_count: 8,
        };
        // Bring the exact TC into the authoritative startup state under test; "fresh" leaves it vacant
        // so the pool itself has to post.
        if case != "fresh" {
            let seeded = prepare_seller_offer(note.as_ref(), &chain, &cfg, Some(&owner))
                .await
                .expect("seed the exact resting SELL");
            assert!(
                matches!(
                    seeded,
                    SellerOfferStartup::Posted {
                        outcome: Some(SellOfferOutcome::Rested { .. }),
                    }
                ),
                "seed must leave one exact resting SELL, got {seeded:?}"
            );
            if case == "funded" {
                chain
                    .place_buy(&token_contract, &LocalNote::generate())
                    .await
                    .expect("match the seeded SELL before the pool prepares it");
            }
        }
        let deal = SellerPoolDeal {
            chain: Arc::new(chain),
            cfg,
            watch: SellerMatchWatchConfig {
                cursor_path: root.join("seller-watch.json"),
                poll_interval: Duration::from_millis(10),
            },
            upstream: UpstreamConfig::Mock,
            nonce: 1,
            market: None,
        };
        let contracts = root.join("unused-contracts.json");
        let context = SellerPoolContext {
            deals_dir: Some(root),
            contracts: &contracts,
            note_addr: &owner,
            frame_model: "mock",
            gateway_advertise: &gateway_advertise,
            advertise_probe: dexdo::seller::liveness::AdvertiseProbePolicy::default(),
        };
        let shutdown = futures::future::pending::<()>();
        tokio::pin!(shutdown);
        let identity = prepare_pool_deal(&seller, &deal, &context, false, shutdown.as_mut())
            .await
            .expect("prepare the pool deal under test");
        match case.as_str() {
            "fresh" | "resume" => assert!(
                identity.is_some(),
                "case {case} must leave one exact resting SELL identity"
            ),
            "funded" => assert!(identity.is_none(), "a funded TC has no resting SELL"),
            other => panic!("unknown startup child case: {other}"),
        }
        seller.server_task.abort();
        println!("{STARTUP_CHILD_DONE}{case}");
        let _ = std::io::stdout().flush();
    }

    fn seller_offer_startup_child_output(case: &str) -> String {
        use std::process::Command;

        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "cli::seller::tests::seller_offer_startup_child",
                "--ignored",
                "--show-output",
            ])
            .env(STARTUP_CHILD_CASE, case)
            .output()
            .expect("spawn seller offer startup child");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "startup child case {case} failed: {text}"
        );
        assert!(
            text.contains(&format!("{STARTUP_CHILD_DONE}{case}")),
            "startup child case {case} never reached the assertion point: {text}"
        );
        text
    }

    /// the fresh post that the chain accepts as resting(`readiness=exact_tc_offer_accepted`)
    /// must print `seller_offer_outcome RESTED order_id=<id>` -- the exact line the two-runner release
    /// gate waits on -- exactly once, before `seller_ready`.
    #[test]
    fn accepted_fresh_offer_prints_seller_offer_outcome_rested_before_ready() {
        let output = seller_offer_startup_child_output("fresh");
        assert_eq!(
            output
                .matches("seller_offer_outcome RESTED order_id=")
                .count(),
            1,
            "the accepted fresh offer must announce its resting order exactly once: {output}"
        );
        let rested = output
            .lines()
            .find(|line| line.starts_with("seller_offer_outcome RESTED order_id="))
            .expect("resting announcement line");
        let order_id = rested
            .trim_end()
            .rsplit_once('=')
            .expect("order id suffix")
            .1
            .to_string();
        assert!(
            order_id.chars().all(|c| c.is_ascii_digit()) && !order_id.is_empty(),
            "the gate parses this order id as decimal digits: {rested}"
        );
        let ready = output
            .lines()
            .find(|line| line.starts_with("seller_ready token_contract="))
            .expect("seller_ready line");
        assert!(
            ready.contains(&format!(
                "order_id={order_id} readiness=exact_tc_offer_accepted"
            )),
            "the announced order must be the one the seller declares ready: {output}"
        );
        assert!(
            output.find(rested).unwrap() < output.find(ready).unwrap(),
            "the gate waits for the resting order before readiness: {output}"
        );
        assert!(
            !output.contains("seller_offer_resume RESTING"),
            "a fresh post is not a resume: {output}"
        );
    }

    /// adopting an existing exact raw resting SELL announces that resting order exactly once too
    /// -- on its own `seller_offer_resume RESTING` contract, which relies on to prove a restart did
    /// not re-post(`seller_offer_outcome RESTED` stays the fresh-post-only marker).
    #[test]
    fn resumed_resting_offer_prints_its_resting_order_exactly_once() {
        let output = seller_offer_startup_child_output("resume");
        assert_eq!(
            output
                .matches("seller_offer_resume RESTING order_id=")
                .count(),
            1,
            "the adopted resting order must be announced exactly once: {output}"
        );
        let resumed = output
            .lines()
            .find(|line| line.starts_with("seller_offer_resume RESTING order_id="))
            .expect("resume announcement line");
        let order_id = resumed.trim_end().rsplit_once('=').expect("order id").1;
        let ready = output
            .lines()
            .find(|line| line.starts_with("seller_ready token_contract="))
            .expect("seller_ready line");
        assert!(
            ready.contains(&format!(
                "order_id={order_id} readiness=resumed_resting_offer"
            )),
            "the resumed order must be the one the seller declares ready: {output}"
        );
        assert!(
            !output.contains("seller_offer_outcome RESTED"),
            ": a resume must stay distinguishable from a fresh post: {output}"
        );
    }

    /// negative: a TC already funded by a matched buyer has no resting SELL, so the seller must
    /// announce no offer outcome at all.
    #[test]
    fn funded_startup_prints_no_offer_announcement() {
        let output = seller_offer_startup_child_output("funded");
        assert!(
            !output.contains("seller_offer_outcome ")
                && !output.contains("seller_offer_resume ")
                && !output.contains("seller_ready "),
            "nothing rested, so nothing may be announced: {output}"
        );
    }

    /// regression: `run_seller` delegates every mock/real deal to the shared pool and never restores
    /// the old bounded one-deal match wait.
    #[test]
    fn seller_run_path_uses_gateway_watcher_not_bounded_read_match() {
        let source = include_str!("seller.rs");
        let start = source
            .find("pub(crate) async fn run_seller")
            .expect("run_seller present");
        let end = source[start..]
            .find("#[cfg(test)]\nmod tests")
            .map(|offset| start + offset)
            .expect("run_seller end marker present");
        let body = &source[start..end];

        assert!(
            body.contains("run_seller_pool"),
            "seller match wait must be owned by the shared pool"
        );
        assert!(
            body.contains("seller_watch_cursor_path"),
            "gateway watcher must persist a cursor"
        );
        assert!(
            body.contains("DEFAULT_MATCH_POLL_INTERVAL"),
            "gateway watcher must use the ~30s default poll interval"
        );
        assert!(
            !body.contains("read_match(&token_contract)"),
            "run_seller must not block on the old read_match loop"
        );
        assert!(
            !body.contains("DEAL_WAIT_SECS"),
            "run_seller must not carry the old 300s seller deadline"
        );
    }

    #[cfg(unix)]
    const RESTART_CHILD_CASE: &str = "DEXDO_TEST_668_RESTART_CASE";
    #[cfg(unix)]
    const RESTART_MISSING_KEY: &str = "DEXDO_TEST_668_MISSING_MODEL_CREDENTIAL";
    #[cfg(unix)]
    const RESTART_NOTE_SEED: [u8; 32] = [0x42; 32];

    #[cfg(unix)]
    async fn exercise_restart_preflight(case: &str) -> Option<String> {
        let note = Arc::new(
            dexdo_core::NoteTree::from_secret_hex(&hex::encode(RESTART_NOTE_SEED))
                .unwrap()
                .node(0)
                .unwrap(),
        );
        let (chain, config, identity, root) =
            existing_resting_offer(case, note.clone(), "127.0.0.1:0".to_string()).await;
        let root = root.path();
        std::fs::write(root.join("note.key"), hex::encode(RESTART_NOTE_SEED)).unwrap();
        std::fs::write(
            root.join("models.json"),
            serde_json::to_vec(&serde_json::json!({
                "models": {"restart-model": {
                    "frame_model": "restart-model",
                    "base_url": "https://example.invalid",
                    "served_model": "restart-model",
                    "api_key_env": RESTART_MISSING_KEY,
                    "tokenizer_family": "test",
                    "price_per_tick": dexdo_core::PRICE_STEP
                }}
            }))
            .unwrap(),
        )
        .unwrap();
        let control = SellerConfig {
            token_contract: format!("0:{}", "b".repeat(64)),
            price_per_tick: config.price_per_tick,
            max_ticks: config.max_ticks,
            subscription: false,
            gateway_advertise: config.gateway_advertise.clone(),
            mock_token_count: config.mock_token_count,
        };
        prepare_seller_offer(note.as_ref(), &chain, &control, Some(&identity.owner_note))
            .await
            .expect("control SELL rests");
        let control_row = chain
            .raw_resting_sell_orders_for_tc(&control.token_contract)
            .await
            .unwrap()
            .remove(0);
        let result = super::run_seller(crate::cli::args::SellerArgs {
            mock: crate::cli::args::MockFlags {
                mock_model: false,
                mock_chain: true,
            },
            identity: crate::cli::args::IdentityArgs {
                note_key: Some(root.join("note.key")),
                note_index: 0,
                note_addr: None,
            },
            registry: crate::cli::args::ModelRegistryValidationArgs::default(),
            gateway_listen: "127.0.0.1:0".parse().unwrap(),
            gateway_advertise: None,
            allow_private_advertise: false,
            require_advertise_probe: false,
            endpoints_file: Some(root.join("endpoints.json")),
            deals_dir: Some(root.join("deals")),
            token_contract: Some(config.token_contract.clone()),
            market: None,
            nonce: None,
            subscription: false,
            price_per_tick: config.price_per_tick,
            mock_token_count: config.mock_token_count,
            model: Some("restart-model".to_string()),
            models: root.join("models.json"),
            contracts: root.join("unused-contracts.json"),
            policy: None,
        })
        .await;
        let error = match case {
            "missing-credential" => {
                let error = format!("{:#}", result.expect_err("missing key must fail"));
                assert!(error.contains(RESTART_MISSING_KEY), "{error}");
                assert!(
                    error.contains("cancellation_disposition=cancelled"),
                    "{error}"
                );
                Some(error)
            }
            "pending-preflight-signal" => {
                result.expect("signal shutdown must terminate cleanly after exact cancellation");
                None
            }
            _ => panic!("unknown restart child case: {case}"),
        };
        let reopened = MockChainBackend::new(
            root.join("endpoints.json"),
            ProtocolConsts::canonical(),
            DobParams::canonical(),
        );
        assert!(reopened
            .raw_resting_sell_orders_for_tc(&identity.token_contract)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            reopened
                .confirm_offer_outcome(&identity.token_contract)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            reopened
                .raw_resting_sell_orders_for_tc(&control.token_contract)
                .await
                .unwrap(),
            vec![control_row]
        );
        error
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "subprocess helper for seller restart/preflight regression"]
    async fn seller_restart_preflight_child() {
        let Some(case) = std::env::var_os(RESTART_CHILD_CASE) else {
            return;
        };
        exercise_restart_preflight(&case.to_string_lossy()).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restart_missing_credentials_and_preflight_signal_use_exact_cancellation_path() {
        use std::io::{BufRead as _, Read as _};
        use std::process::{Command, Stdio};

        assert!(std::env::var_os(RESTART_MISSING_KEY).is_none());
        let error = exercise_restart_preflight("missing-credential")
            .await
            .unwrap();
        assert!(!error.contains(&hex::encode(RESTART_NOTE_SEED)), "{error}");

        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cli::seller::tests::seller_restart_preflight_child",
                "--ignored",
                "--nocapture",
            ])
            .env(RESTART_CHILD_CASE, "pending-preflight-signal")
            .env("DEXDO_TEST_668_PENDING_SELLER_PREFLIGHT", "1")
            .env_remove(RESTART_MISSING_KEY)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut output = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(stdout.read_line(&mut line).unwrap(), 0, "{output}");
            output.push_str(&line);
            if line.contains("seller-restart-preflight-pending") {
                break;
            }
        }
        assert!(Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap()
            .success());
        stdout.read_to_string(&mut output).unwrap();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut output)
            .unwrap();
        assert!(child.wait().unwrap().success(), "{output}");
        assert!(output.contains("\"outcome\":\"cancelled\""), "{output}");
        assert!(output.contains("\"event\":\"stopping\""), "{output}");
        assert!(!output.contains("seller_ready "), "{output}");
        assert!(!output.contains("seller_offer_outcome RESTED"), "{output}");
        assert!(
            !output.contains(&hex::encode(RESTART_NOTE_SEED)),
            "{output}"
        );
    }

    struct PoolTestBackend {
        owner_fills: Arc<Mutex<Vec<(i64, MatchedFill)>>>,
        token_contract: String,
        price_per_tick: u64,
        offered_ticks: u64,
        matched_ticks: u64,
        buyer_pubkey: NotePubkey,
        exists: AtomicBool,
        matched: AtomicBool,
        opened: AtomicBool,
        post_calls: AtomicU64,
        open_calls: AtomicU64,
        open_fail_once: AtomicBool,
        inspection_fail_once: AtomicBool,
        created_at: i64,
    }

    impl PoolTestBackend {
        fn new(
            owner_fills: Arc<Mutex<Vec<(i64, MatchedFill)>>>,
            token_contract: String,
            offered_ticks: u64,
            matched_ticks: u64,
            matched: bool,
            created_at: i64,
        ) -> Self {
            let price_per_tick = 1_000_000_000;
            if matched {
                owner_fills.lock().unwrap().push((
                    created_at,
                    MatchedFill {
                        order_id: u128::from(offered_ticks),
                        token_contract: token_contract.clone(),
                        ticks: u128::from(matched_ticks),
                        price_per_tick: u128::from(price_per_tick),
                    },
                ));
            }
            Self {
                owner_fills,
                token_contract,
                price_per_tick,
                offered_ticks,
                matched_ticks,
                buyer_pubkey: LocalNote::generate().pubkey(),
                exists: AtomicBool::new(true),
                matched: AtomicBool::new(matched),
                opened: AtomicBool::new(false),
                post_calls: AtomicU64::new(0),
                open_calls: AtomicU64::new(0),
                open_fail_once: AtomicBool::new(false),
                inspection_fail_once: AtomicBool::new(false),
                created_at,
            }
        }

        #[cfg(feature = "shellnet")]
        fn with_inspection_failure(self) -> Self {
            self.inspection_fail_once.store(true, Ordering::Relaxed);
            self
        }

        #[cfg(feature = "shellnet")]
        fn with_open_failure(self) -> Self {
            self.open_fail_once.store(true, Ordering::Relaxed);
            self
        }

        fn matched(&self) -> Match {
            Match {
                token_contract: self.token_contract.clone(),
                buyer_pubkey: self.buyer_pubkey.clone(),
                price_per_tick: self.price_per_tick,
            }
        }
    }

    #[async_trait::async_trait]
    impl ChainBackend for PoolTestBackend {
        async fn discover_offers(&self) -> Result<Vec<OfferListing>, ChainError> {
            Ok(Vec::new())
        }

        async fn post_offer(&self, offer: SellOffer, _: &dyn Note) -> Result<(), ChainError> {
            assert_eq!(offer.token_contract, self.token_contract);
            assert_eq!(offer.price_per_tick, self.price_per_tick);
            assert_eq!(offer.max_ticks, self.offered_ticks);
            assert!(!self.matched.swap(true, Ordering::Relaxed));
            self.owner_fills.lock().unwrap().push((
                self.created_at,
                MatchedFill {
                    order_id: u128::from(self.offered_ticks),
                    token_contract: self.token_contract.clone(),
                    ticks: u128::from(self.matched_ticks),
                    price_per_tick: u128::from(self.price_per_tick),
                },
            ));
            self.post_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn confirm_offer_outcome(
            &self,
            _: &TokenContract,
        ) -> Result<Option<SellOfferOutcome>, ChainError> {
            Ok(self
                .matched
                .load(Ordering::Relaxed)
                .then_some(SellOfferOutcome::Matched))
        }

        async fn sell_offer_terms(
            &self,
            _: &TokenContract,
        ) -> Result<Option<(u64, u64)>, ChainError> {
            Ok(Some((self.price_per_tick, self.offered_ticks)))
        }

        async fn read_openable_match_now(
            &self,
            _: &TokenContract,
        ) -> Result<Option<Match>, ChainError> {
            if self.inspection_fail_once.swap(false, Ordering::Relaxed) {
                return Err(ChainError::Transport(
                    "injected restart after provision and before POST".to_string(),
                ));
            }
            Ok(self.matched.load(Ordering::Relaxed).then(|| self.matched()))
        }

        async fn poll_seller_fills(
            &self,
            _: &dyn Note,
            cursor: &mut MatchWatchCursor,
        ) -> Result<Vec<MatchedFill>, ChainError> {
            let mut batch = self
                .owner_fills
                .lock()
                .unwrap()
                .iter()
                .filter(|(created_at, fill)| !cursor.has_seen(*created_at, &fill.token_contract))
                .cloned()
                .collect::<Vec<_>>();
            batch.sort_by(|left, right| {
                left.0
                    .cmp(&right.0)
                    .then_with(|| left.1.token_contract.cmp(&right.1.token_contract))
            });
            cursor.record_seen_batch(
                batch
                    .iter()
                    .map(|(created_at, fill)| (*created_at, fill.token_contract.clone())),
            );
            Ok(batch.into_iter().map(|(_, fill)| fill).collect())
        }

        async fn place_buy(&self, _: &TokenContract, _: &dyn Note) -> Result<(), ChainError> {
            unreachable!("the scripted seller backend matches immediately after post")
        }

        async fn read_match(&self, _: &TokenContract) -> Result<Match, ChainError> {
            Ok(self.matched())
        }

        async fn open_stream(
            &self,
            _: &TokenContract,
            _: Vec<u8>,
            _: &dyn Note,
        ) -> Result<(), ChainError> {
            self.open_calls.fetch_add(1, Ordering::Relaxed);
            if self.open_fail_once.swap(false, Ordering::Relaxed) {
                return Err(ChainError::Transport(
                    "injected per-deal open failure".to_string(),
                ));
            }
            self.opened.store(true, Ordering::Relaxed);
            Ok(())
        }

        async fn read_handover(&self, _: &TokenContract) -> Result<Option<Vec<u8>>, ChainError> {
            Ok(self.opened.load(Ordering::Relaxed).then_some(vec![1]))
        }

        async fn claim_tokens(
            &self,
            _: &TokenContract,
            _: &dyn Note,
            _: u128,
        ) -> Result<(), ChainError> {
            Ok(())
        }

        async fn accept_probe(&self, _: &TokenContract) -> Result<(), ChainError> {
            Ok(())
        }

        async fn stop(&self, _: &TokenContract, _: &dyn Note) -> Result<Settlement, ChainError> {
            unreachable!("the test exits before the fixed probe window")
        }

        async fn deal_state(
            &self,
            _: &TokenContract,
        ) -> Result<Option<DealChainState>, ChainError> {
            Ok(self.exists.load(Ordering::Relaxed).then(|| DealChainState {
                funded: self.matched.load(Ordering::Relaxed),
                opened: self.opened.load(Ordering::Relaxed),
                probe_accepted: false,
                disputed: false,
                deposit: if self.matched.load(Ordering::Relaxed) {
                    u128::from(self.price_per_tick) * u128::from(self.matched_ticks)
                } else {
                    0
                },
                finalized_owed: 0,
                tokens_final: 0,
                tokens_superseded: 0,
                tokens_pending: 0,
                probe_tick: 0,
                funded_time: self.matched.load(Ordering::Relaxed).then_some(1),
                probe_time: 0,
                prev_claim_time: 0,
                last_claim_time: 0,
                dispute_time: 0,
            }))
        }

        async fn deal_snapshot(
            &self,
            _: &TokenContract,
        ) -> Result<Option<DealChainSnapshot>, ChainError> {
            let Some(state) = self.deal_state(&self.token_contract).await? else {
                return Ok(None);
            };
            let funded_tokens = u128::from(self.matched_ticks) * dexdo_core::TICK_SIZE;
            let bond_required = u128::from(self.price_per_tick) * 2;
            Ok(Some(DealChainSnapshot {
                account_code_hash: "pool-test-code".to_string(),
                account_boc_hash: format!("pool-test:{}", self.token_contract),
                state,
                subscription: DealSubscription {
                    deal_flags: 0,
                    sub_weeks: 0,
                    week_index: 0,
                    tokens_per_week: funded_tokens,
                    funded_tokens,
                    tokens_paid: 0,
                    period_start: 0,
                    week_base_tokens: 0,
                },
                seller_bond: DealSellerBond {
                    bond_funded: true,
                    bond_held: bond_required,
                    bond_required,
                },
                buyer_bond: DealBuyerBond {
                    bond_held: 0,
                    bond_required: 0,
                },
            }))
        }

        async fn snapshot(&self, _: &TokenContract) -> Option<StreamSnapshot> {
            None
        }
    }

    #[tokio::test]
    async fn seller_fill_poll_returns_whole_owner_batch_once() {
        let owner_fills = Arc::new(Mutex::new(Vec::new()));
        let first = PoolTestBackend::new(owner_fills.clone(), "0:first".to_string(), 8, 3, true, 2);
        let _second = PoolTestBackend::new(owner_fills, "0:second".to_string(), 5, 2, true, 1);
        let note = LocalNote::generate();
        let mut cursor = MatchWatchCursor::new(0);

        let batch = first.poll_seller_fills(&note, &mut cursor).await.unwrap();
        assert_eq!(
            batch
                .iter()
                .map(|fill| fill.token_contract.as_str())
                .collect::<Vec<_>>(),
            ["0:second", "0:first"]
        );
        assert!(
            first
                .poll_seller_fills(&note, &mut cursor)
                .await
                .unwrap()
                .is_empty(),
            "the owner-wide batch must be consumed exactly once"
        );
    }

    #[cfg(feature = "shellnet")]
    struct PoolTestProvisioner {
        note_addr: String,
        frame_model: String,
        backends: VecDeque<Arc<PoolTestBackend>>,
        calls: Arc<Mutex<Vec<(u64, u64, u64)>>>,
    }

    #[cfg(feature = "shellnet")]
    impl PoolTestProvisioner {
        fn provision(
            &mut self,
            nonce: u64,
            price_per_tick: u64,
            max_ticks: u64,
        ) -> anyhow::Result<(dexdo_core::MarketManifest, Arc<dyn ChainBackend>)> {
            self.calls
                .lock()
                .unwrap()
                .push((nonce, price_per_tick, max_ticks));
            let backend = self
                .backends
                .pop_front()
                .expect("one scripted backend per residual");
            assert_eq!(backend.price_per_tick, price_per_tick);
            assert_eq!(backend.offered_ticks, max_ticks);
            let token_contract = backend.token_contract.clone();
            let market = dexdo_core::MarketManifest {
                network: "shellnet".to_string(),
                frame_model: self.frame_model.clone(),
                model_hash: dexdo_core::model_hash_for(&self.frame_model),
                inference_order_book: format!("0:{}", "d".repeat(64)),
                root_model: format!("0:{}", "e".repeat(64)),
                token_contract,
                seller_note: self.note_addr.clone(),
                nonce,
                price_per_tick: u128::from(price_per_tick),
                max_ticks: u128::from(max_ticks),
            };
            let chain: Arc<dyn ChainBackend> = backend;
            Ok((market, chain))
        }
    }

    fn pool_test_policy(max_open_deals: u64) -> policy::SellerRuntimePolicy {
        policy::SellerRuntimePolicy {
            after_deal_done: policy::SellerAfterDealDoneAction::Retire,
            buyer_no_show: policy::SellerBuyerNoShowAction::RetireGateway,
            dispute_against_me: policy::SellerDisputeAgainstMeAction::ReleaseIfClean,
            max_open_deals,
        }
    }

    fn elapse_mock_probe_window(state_path: &std::path::Path, token_contract: &str) {
        let mut state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(state_path).unwrap()).unwrap();
        let opened_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(ProtocolConsts::canonical().probe_window.as_secs());
        let stream = &mut state["streams"][token_contract];
        stream["probe_time"] = opened_at.into();
        stream["prev_claim_time"] = opened_at.into();
        stream["last_claim_time"] = opened_at.into();
        std::fs::write(state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    }

    async fn record_terminal_for_test(
        seller: &dexdo::seller::RunningSeller,
        chain: Arc<dyn ChainBackend>,
        token_contract: &str,
        delivery: dexdo::seller::gateway::DealDelivery,
        terminal_receipts: &mut tokio::task::JoinSet<SellerTerminalReceiptResult>,
        first_error: &mut Option<anyhow::Error>,
    ) {
        let token_contract = token_contract.to_string();
        record_advance_result(
            seller,
            Ok((token_contract, chain, delivery, Ok(2))),
            terminal_receipts,
            &pool_test_policy(4),
            first_error,
        )
        .await;
    }

    #[tokio::test]
    async fn terminal_policy_dispatch_uses_authoritative_probe_state_at_zero_delivery() {
        let root = tempfile::tempdir().unwrap();
        let chain = Arc::new(MockChainBackend::new(
            root.path().join("endpoints.json"),
            ProtocolConsts::canonical(),
            DobParams::canonical(),
        ));
        let seller_note = Arc::new(LocalNote::generate());
        let buyer_note = LocalNote::generate();
        let mut seller = dexdo::seller::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            dexdo::seller::UpstreamConfig::Mock,
            seller_note.clone(),
        )
        .await
        .unwrap();
        let policy = policy::SellerRuntimePolicy {
            after_deal_done: policy::SellerAfterDealDoneAction::Retire,
            buyer_no_show: policy::SellerBuyerNoShowAction::CleanupAndRetire,
            dispute_against_me: policy::SellerDisputeAgainstMeAction::ReleaseIfClean,
            max_open_deals: 2,
        };
        let mut terminal_receipts = tokio::task::JoinSet::new();

        for (token_contract, probe_accepted) in [
            ("accepted-probe-zero-delivery", true),
            ("true-buyer-no-show", false),
        ] {
            let token_contract = token_contract.to_string();
            chain
                .post_offer(
                    SellOffer {
                        price_per_tick: dexdo_core::PRICE_STEP as u64,
                        max_ticks: 4,
                        token_contract: token_contract.clone(),
                        flags: 0,
                    },
                    seller_note.as_ref(),
                )
                .await
                .unwrap();
            chain.place_buy(&token_contract, &buyer_note).await.unwrap();
            chain
                .open_stream(&token_contract, Vec::new(), seller_note.as_ref())
                .await
                .unwrap();
            if probe_accepted {
                elapse_mock_probe_window(
                    &root.path().join("endpoints.chainstate.json"),
                    &token_contract,
                );
                chain.accept_probe(&token_contract).await.unwrap();
            }
            chain.stop(&token_contract, &buyer_note).await.unwrap();

            let state = chain.deal_state(&token_contract).await.unwrap().unwrap();
            assert_eq!(state.probe_accepted, probe_accepted);
            let delivery = seller.state.delivery(&token_contract);
            assert_eq!(delivery.count.load(Ordering::Acquire), 0);
            let backend: Arc<dyn ChainBackend> = chain.clone();
            let mut first_error = None;
            record_advance_result(
                &seller,
                Ok((token_contract, backend, delivery, Ok(0))),
                &mut terminal_receipts,
                &policy,
                &mut first_error,
            )
            .await;

            if probe_accepted {
                assert!(first_error.is_none(), "{first_error:?}");
            } else {
                let error = first_error.expect("true no-show must use buyer_no_show policy");
                assert!(
                    error.to_string().contains("failure_class=buyer_no_show"),
                    "{error:#}"
                );
            }
        }

        terminal_receipts.abort_all();
        seller.server_task.abort();
        let _ = (&mut seller.server_task).await;
    }

    #[tokio::test(start_paused = true)]
    async fn terminal_worker_emits_exact_order_once_per_tc_without_false_stop() {
        let root = tempfile::tempdir().unwrap();
        let chain = Arc::new(MockChainBackend::new(
            root.path().join("endpoints.json"),
            ProtocolConsts::canonical(),
            DobParams::canonical(),
        ));
        let seller_note = Arc::new(LocalNote::generate());
        let buyer_note = LocalNote::generate();
        for (tc, accept_probe) in [
            ("clean-1", true),
            ("clean-2", true),
            ("probe-stop", false),
            ("disputed", true),
        ] {
            let tc = tc.to_string();
            chain
                .post_offer(
                    SellOffer {
                        price_per_tick: dexdo_core::PRICE_STEP as u64,
                        max_ticks: 4,
                        token_contract: tc.clone(),
                        flags: 0,
                    },
                    seller_note.as_ref(),
                )
                .await
                .unwrap();
            chain.place_buy(&tc, &buyer_note).await.unwrap();
            chain
                .open_stream(&tc, Vec::new(), seller_note.as_ref())
                .await
                .unwrap();
            if accept_probe {
                elapse_mock_probe_window(&root.path().join("endpoints.chainstate.json"), &tc);
                chain.accept_probe(&tc).await.unwrap();
            }
            if tc == "clean-1" {
                // Keep TC-A open so the first production receipt read returns `None`.
            } else if tc == "disputed" {
                chain.dispute(&tc, &buyer_note).await.unwrap();
                chain.release_dispute(&tc).await.unwrap();
            } else {
                chain.stop(&tc, &buyer_note).await.unwrap();
            }
        }
        let chain_state_path = root.path().join("endpoints.chainstate.json");
        let open_chain_state = std::fs::read(&chain_state_path).unwrap();
        let mut seller = dexdo::seller::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            dexdo::seller::UpstreamConfig::Mock,
            seller_note,
        )
        .await
        .unwrap();
        let receipt_chain: Arc<dyn ChainBackend> = chain.clone();
        let mut terminal_receipts = tokio::task::JoinSet::new();
        let mut first_error = None;

        let delivery_a = seller.state.delivery("clean-1");
        record_terminal_for_test(
            &seller,
            receipt_chain.clone(),
            "clean-1",
            delivery_a.clone(),
            &mut terminal_receipts,
            &mut first_error,
        )
        .await;
        record_terminal_for_test(
            &seller,
            receipt_chain.clone(),
            "clean-2",
            seller.state.delivery("clean-2"),
            &mut terminal_receipts,
            &mut first_error,
        )
        .await;

        let joined_b = terminal_receipts
            .join_next()
            .await
            .expect("TC-B receipt task");
        let events_b = record_terminal_receipt_result(joined_b, &mut first_error);
        assert_eq!(events_b[0]["token_contract"], "clean-2");

        std::fs::write(&chain_state_path, b"{").unwrap();
        tokio::time::advance(dexdo_core::params::SELLER_TERMINAL_RECEIPT_POLL_INTERVAL).await;
        tokio::task::yield_now().await;
        tokio::time::advance(dexdo_core::params::SELLER_TERMINAL_RECEIPT_POLL_INTERVAL).await;
        tokio::task::yield_now().await;
        assert!(
            terminal_receipts.try_join_next().is_none(),
            "TC-A must remain pending across transient receipt errors"
        );
        std::fs::write(&chain_state_path, open_chain_state).unwrap();
        chain
            .stop(&"clean-1".to_string(), &buyer_note)
            .await
            .unwrap();
        tokio::time::advance(dexdo_core::params::SELLER_TERMINAL_RECEIPT_POLL_INTERVAL).await;
        let joined_a = terminal_receipts
            .join_next()
            .await
            .expect("TC-A receipt task");
        let events_a = record_terminal_receipt_result(joined_a, &mut first_error);

        for (tc, events) in [("clean-1", events_a), ("clean-2", events_b)] {
            assert_eq!(
                events
                    .iter()
                    .map(|event| event["event"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                ["buyer_stop_observed", "settled", "exiting"]
            );
            for (index, event) in events.iter().enumerate() {
                assert_eq!(event["schema"], SELLER_EVENT_SCHEMA);
                assert_eq!(event["seq"], u64::try_from(index + 1).unwrap());
                assert_eq!(event["role"], "seller");
                assert_eq!(event["token_contract"], tc);
                let line = serde_json::to_string(event).unwrap();
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&line).unwrap(),
                    *event
                );
                assert!(!line.contains("settlement_submitted"));
            }
            assert_eq!(events[1]["outcome"], "AmicableSplit");
            assert_eq!(events[2]["exit_code"], 0);
        }

        record_terminal_for_test(
            &seller,
            receipt_chain.clone(),
            "clean-1",
            delivery_a,
            &mut terminal_receipts,
            &mut first_error,
        )
        .await;
        let replay = terminal_receipts
            .join_next()
            .await
            .expect("replayed TC-A receipt task");
        assert!(
            record_terminal_receipt_result(replay, &mut first_error).is_empty(),
            "replayed terminal read must not duplicate clean-1"
        );

        for tc in ["probe-stop", "disputed"] {
            record_terminal_for_test(
                &seller,
                receipt_chain.clone(),
                tc,
                seller.state.delivery(tc),
                &mut terminal_receipts,
                &mut first_error,
            )
            .await;
        }
        tokio::task::yield_now().await;
        tokio::time::advance(dexdo_core::params::SELLER_TERMINAL_RECEIPT_TIMEOUT).await;
        for tc in ["probe-stop", "disputed"] {
            let joined = terminal_receipts
                .join_next()
                .await
                .expect("generic terminal receipt task");
            assert!(
                record_terminal_receipt_result(joined, &mut first_error).is_empty(),
                "{tc} must not produce a terminal trail"
            );
        }
        assert!(first_error.is_none(), "{first_error:?}");

        record_terminal_for_test(
            &seller,
            receipt_chain,
            "unfunded-generic-terminal",
            seller.state.delivery("unfunded-generic-terminal"),
            &mut terminal_receipts,
            &mut first_error,
        )
        .await;
        let error = first_error.expect("missing authoritative state must fail closed");
        assert!(
            error
                .to_string()
                .contains("refusing to guess buyer_no_show"),
            "{error:#}"
        );
        tokio::task::yield_now().await;
        tokio::time::advance(dexdo_core::params::SELLER_TERMINAL_RECEIPT_TIMEOUT).await;
        let joined = terminal_receipts
            .join_next()
            .await
            .expect("missing-state terminal receipt task");
        assert!(
            record_terminal_receipt_result(joined, &mut None).is_empty(),
            "missing authoritative state must not produce a terminal trail"
        );
        seller.server_task.abort();
        let _ = (&mut seller.server_task).await;
    }

    #[test]
    fn upstream_failure_jsonl_has_stable_safe_schema() {
        let event = upstream_failure_event(7, "0:deal", "auth", false, "Unavailable", Some(401));
        let line = serde_json::to_string(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["schema"], SELLER_EVENT_SCHEMA);
        assert_eq!(parsed["seq"], 7);
        assert_eq!(parsed["event"], "upstream_failed");
        assert_eq!(parsed["role"], "seller");
        assert_eq!(parsed["token_contract"], "0:deal");
        assert_eq!(parsed["error_class"], "auth");
        assert_eq!(parsed["retryable"], false);
        assert_eq!(parsed["grpc_status"], "Unavailable");
        assert_eq!(parsed["http_status"], 401);
        for forbidden in ["Authorization", "prompt", "provider response", "/secret/"] {
            assert!(!line.contains(forbidden), "{line}");
        }
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn seller_pool_recursively_relists_exact_residuals_on_one_gateway() {
        let root = tempfile::tempdir().expect("seller pool test directory");
        let root = root.path();
        let note = Arc::new(LocalNote::generate());
        let note_addr = format!("0:{}", "a".repeat(64));
        let frame_model = "openai/gpt-oss-20b";
        let owner_fills = Arc::new(Mutex::new(Vec::new()));
        let initial = Arc::new(PoolTestBackend::new(
            owner_fills.clone(),
            format!("0:{}", "1".repeat(64)),
            8,
            3,
            true,
            i64::MAX - 4,
        ));
        let independent = Arc::new(PoolTestBackend::new(
            owner_fills.clone(),
            format!("0:{}", "4".repeat(64)),
            4,
            4,
            true,
            i64::MAX - 3,
        ));
        let residual_five = Arc::new(
            PoolTestBackend::new(
                owner_fills.clone(),
                format!("0:{}", "2".repeat(64)),
                5,
                2,
                false,
                i64::MAX - 2,
            )
            .with_inspection_failure()
            .with_open_failure(),
        );
        let residual_three = Arc::new(PoolTestBackend::new(
            owner_fills.clone(),
            format!("0:{}", "3".repeat(64)),
            3,
            2,
            false,
            i64::MAX - 1,
        ));
        let market_for = |backend: &PoolTestBackend, nonce| dexdo_core::MarketManifest {
            network: "shellnet".to_string(),
            frame_model: frame_model.to_string(),
            model_hash: dexdo_core::model_hash_for(frame_model),
            inference_order_book: format!("0:{}", "d".repeat(64)),
            root_model: format!("0:{}", "e".repeat(64)),
            token_contract: backend.token_contract.clone(),
            seller_note: note_addr.clone(),
            nonce,
            price_per_tick: u128::from(backend.price_per_tick),
            max_ticks: u128::from(backend.offered_ticks),
        };
        let mut seller = dexdo::seller::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            dexdo::seller::UpstreamConfig::Mock,
            note.clone(),
        )
        .await
        .unwrap();
        let listen_addr = seller.listen_addr;
        let gateway = seller.listen_addr.to_string();
        let initial_cfg = SellerConfig {
            token_contract: initial.token_contract.clone(),
            price_per_tick: initial.price_per_tick,
            max_ticks: initial.offered_ticks,
            subscription: false,
            gateway_advertise: gateway.clone(),
            mock_token_count: 8,
        };
        let initial_watch = dexdo::seller::SellerMatchWatchConfig {
            cursor_path: root.join("initial.cursor.json"),
            poll_interval: std::time::Duration::from_millis(1),
        };
        let initial_deal = || SellerPoolDeal {
            chain: initial.clone(),
            cfg: initial_cfg.clone(),
            watch: initial_watch.clone(),
            upstream: dexdo::seller::UpstreamConfig::Mock,
            nonce: 10,
            market: Some(market_for(initial.as_ref(), 10)),
        };
        let independent_deal = || SellerPoolDeal {
            chain: independent.clone(),
            cfg: SellerConfig {
                token_contract: independent.token_contract.clone(),
                price_per_tick: independent.price_per_tick,
                max_ticks: independent.offered_ticks,
                subscription: false,
                gateway_advertise: gateway.clone(),
                mock_token_count: 8,
            },
            watch: dexdo::seller::SellerMatchWatchConfig {
                cursor_path: root.join("independent.cursor.json"),
                poll_interval: std::time::Duration::from_millis(1),
            },
            upstream: dexdo::seller::UpstreamConfig::Mock,
            nonce: 20,
            market: Some(market_for(independent.as_ref(), 20)),
        };
        let context = || SellerPoolContext {
            deals_dir: Some(root),
            contracts: std::path::Path::new("contracts/deployed.shellnet.json"),
            note_addr: &note_addr,
            frame_model,
            gateway_advertise: &gateway,
            advertise_probe: dexdo::seller::liveness::AdvertiseProbePolicy::default(),
        };
        let boundary_writes = Arc::new(AtomicU64::new(0));
        let mut boundary_provision = {
            let boundary_writes = boundary_writes.clone();
            move |_: String, _: u64, _: u64, _: u64| {
                boundary_writes.fetch_add(1, Ordering::Relaxed);
                futures::future::ready(Err(anyhow::anyhow!(
                    "max_open_deals must reject before provision"
                )))
            }
        };
        let boundary_shutdown = futures::future::pending::<()>().fuse();
        tokio::pin!(boundary_shutdown);
        let boundary_error = run_seller_pool(
            &seller,
            vec![initial_deal(), independent_deal()],
            context(),
            &pool_test_policy(1),
            &mut boundary_provision,
            boundary_shutdown.as_mut(),
        )
        .await
        .expect_err("two deals must exceed seller.max_open_deals=1");
        assert!(boundary_error.to_string().contains("max_open_deals=1"));
        assert_eq!(boundary_writes.load(Ordering::Relaxed), 0);
        assert_eq!(initial.post_calls.load(Ordering::Relaxed), 0);
        assert_eq!(initial.open_calls.load(Ordering::Relaxed), 0);
        assert_eq!(independent.post_calls.load(Ordering::Relaxed), 0);
        assert_eq!(independent.open_calls.load(Ordering::Relaxed), 0);

        dexdo::seller::poll_match_and_maybe_open(
            &seller,
            initial.as_ref(),
            &initial_cfg,
            &initial_watch.cursor_path,
        )
        .await
        .unwrap()
        .expect("initial partial match");

        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut provisioner = PoolTestProvisioner {
            note_addr: note_addr.clone(),
            frame_model: frame_model.to_string(),
            backends: VecDeque::from([residual_five.clone(), residual_three.clone()]),
            calls: calls.clone(),
        };
        let unknown_tc = format!("0:{}", "9".repeat(64));
        owner_fills.lock().unwrap().push((
            i64::MAX - 5,
            MatchedFill {
                order_id: 999,
                token_contract: unknown_tc.clone(),
                ticks: 2,
                price_per_tick: 1_000_000_000,
            },
        ));
        let independent_for_shutdown = independent.clone();
        let unknown_shutdown = async move {
            while independent_for_shutdown.open_calls.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        }
        .fuse();
        tokio::pin!(unknown_shutdown);
        let unknown_policy = pool_test_policy(2);
        let unknown_error = {
            let mut provision = |model: String, nonce, price, ticks| {
                assert_eq!(model, frame_model);
                futures::future::ready(provisioner.provision(nonce, price, ticks))
            };
            run_seller_pool(
                &seller,
                vec![initial_deal(), independent_deal()],
                context(),
                &unknown_policy,
                &mut provision,
                unknown_shutdown.as_mut(),
            )
            .await
            .expect_err("an owner fill without a handle must fail visibly")
        };
        assert!(
            unknown_error.to_string().contains(&unknown_tc),
            "{unknown_error:#}"
        );
        assert!(
            calls.lock().unwrap().is_empty(),
            "unknown owner capacity must fail before residual provision"
        );
        owner_fills
            .lock()
            .unwrap()
            .retain(|(_, fill)| fill.token_contract != unknown_tc);
        let _ = (&mut seller.server_task).await;
        let mut seller = dexdo::seller::start_gateway_with_note(
            listen_addr,
            dexdo::seller::UpstreamConfig::Mock,
            note.clone(),
        )
        .await
        .unwrap();
        dexdo::seller::poll_match_and_maybe_open(
            &seller,
            initial.as_ref(),
            &initial_cfg,
            &initial_watch.cursor_path,
        )
        .await
        .unwrap()
        .expect("unknown-fill restart restores the initial match");

        let seller_policy = pool_test_policy(4);
        let calls_for_shutdown = calls.clone();
        let interrupted = async move {
            while calls_for_shutdown.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        }
        .fuse();
        tokio::pin!(interrupted);
        let error = {
            let mut provision = |model: String, nonce, price, ticks| {
                assert_eq!(model, frame_model);
                futures::future::ready(provisioner.provision(nonce, price, ticks))
            };
            run_seller_pool(
                &seller,
                vec![initial_deal(), independent_deal()],
                context(),
                &seller_policy,
                &mut provision,
                interrupted.as_mut(),
            )
            .await
            .expect_err("restart window is injected after fill persistence and before POST")
        };
        assert!(error
            .to_string()
            .contains("after provision and before POST"));
        let _ = (&mut seller.server_task).await;
        let mut seller = dexdo::seller::start_gateway_with_note(
            listen_addr,
            dexdo::seller::UpstreamConfig::Mock,
            note.clone(),
        )
        .await
        .unwrap();
        let valid_cursor = std::fs::read(&initial_watch.cursor_path).unwrap();
        let mut corrupt_cursor: serde_json::Value = serde_json::from_slice(&valid_cursor).unwrap();
        corrupt_cursor["fill"]["residual_ticks"] = serde_json::json!(4);
        std::fs::write(
            &initial_watch.cursor_path,
            serde_json::to_vec_pretty(&corrupt_cursor).unwrap(),
        )
        .unwrap();
        let calls_before_corrupt_restart = calls.lock().unwrap().len();
        let corrupt_shutdown = std::future::ready(()).fuse();
        tokio::pin!(corrupt_shutdown);
        let corrupt_error = {
            let mut provision = |model: String, nonce, price, ticks| {
                assert_eq!(model, frame_model);
                futures::future::ready(provisioner.provision(nonce, price, ticks))
            };
            run_seller_pool(
                &seller,
                vec![initial_deal(), independent_deal()],
                context(),
                &seller_policy,
                &mut provision,
                corrupt_shutdown.as_mut(),
            )
            .await
            .expect_err("corrupt residual lineage must fail before replacement provision")
        };
        assert!(
            corrupt_error
                .to_string()
                .contains("invalid seller fill lineage"),
            "{corrupt_error:#}"
        );
        assert_eq!(
            calls.lock().unwrap().len(),
            calls_before_corrupt_restart,
            "corrupt residual lineage must produce zero provision POSTs"
        );
        std::fs::write(&initial_watch.cursor_path, valid_cursor).unwrap();
        seller.server_task.abort();
        let _ = (&mut seller.server_task).await;

        initial.exists.store(false, Ordering::Relaxed);
        let seller = dexdo::seller::start_gateway_with_note(
            listen_addr,
            dexdo::seller::UpstreamConfig::Mock,
            note,
        )
        .await
        .unwrap();
        let restored_pool = load_seller_pool_deals(&context(), initial_deal(), 8, |market| {
            let chain: Arc<dyn ChainBackend> =
                if market.token_contract == independent.token_contract {
                    independent.clone()
                } else if market.token_contract == residual_five.token_contract {
                    residual_five.clone()
                } else {
                    return Err(anyhow::anyhow!(
                        "unexpected restored test TokenContract {}",
                        market.token_contract
                    ));
                };
            Ok((chain, dexdo::seller::UpstreamConfig::Mock))
        })
        .await
        .expect("restart must reconstruct the residual descendant from its existing handle");
        let final_backend = residual_three.clone();
        let shutdown = async move {
            loop {
                if final_backend.open_calls.load(Ordering::Relaxed) == 1 {
                    return;
                }
                tokio::task::yield_now().await;
            }
        }
        .fuse();
        tokio::pin!(shutdown);
        let mut provision = |model: String, nonce, price, ticks| {
            assert_eq!(model, frame_model);
            futures::future::ready(provisioner.provision(nonce, price, ticks))
        };
        let isolated_error = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            run_seller_pool(
                &seller,
                restored_pool,
                context(),
                &seller_policy,
                &mut provision,
                shutdown.as_mut(),
            ),
        )
        .await
        .expect("pool test must not wait for the fixed probe window")
        .expect_err("one failed open is reported after unrelated residual service continues");
        assert!(isolated_error
            .to_string()
            .contains("injected per-deal open failure"));

        assert_eq!(
            *calls.lock().unwrap(),
            vec![(11, 1_000_000_000, 5), (12, 1_000_000_000, 3)]
        );
        assert_eq!(residual_five.post_calls.load(Ordering::Relaxed), 1);
        assert_eq!(residual_three.post_calls.load(Ordering::Relaxed), 1);
        assert_eq!(initial.open_calls.load(Ordering::Relaxed), 1);
        assert_eq!(independent.open_calls.load(Ordering::Relaxed), 1);
        assert_eq!(residual_five.open_calls.load(Ordering::Relaxed), 1);
        assert_eq!(residual_three.open_calls.load(Ordering::Relaxed), 1);
        assert!(!residual_five.opened.load(Ordering::Relaxed));
        assert!(residual_three.opened.load(Ordering::Relaxed));

        let initial_delivery = seller.state.delivery(&initial.token_contract);
        let independent_delivery = seller.state.delivery(&independent.token_contract);
        let five_delivery = seller.state.delivery(&residual_five.token_contract);
        let three_delivery = seller.state.delivery(&residual_three.token_contract);
        initial_delivery.count.store(7, Ordering::Relaxed);
        assert_eq!(five_delivery.count.load(Ordering::Relaxed), 0);
        assert_eq!(three_delivery.count.load(Ordering::Relaxed), 0);
        assert_eq!(independent_delivery.count.load(Ordering::Relaxed), 0);
        assert!(!Arc::ptr_eq(
            &initial_delivery.count,
            &independent_delivery.count
        ));
        assert!(!Arc::ptr_eq(&initial_delivery.count, &five_delivery.count));
        assert!(!Arc::ptr_eq(&five_delivery.count, &three_delivery.count));

        let initial_lineage = dexdo::seller::read_seller_fill_lineage(
            &initial_watch.cursor_path,
            &initial.token_contract,
        )
        .unwrap()
        .unwrap();
        assert_eq!(initial_lineage.replacement_nonce, Some(11));
        assert_eq!(
            initial_lineage.replacement_token_contract.as_deref(),
            Some(residual_five.token_contract.as_str())
        );
        let five_cursor =
            super::seller_watch_cursor_path(Some(root), &residual_five.token_contract).unwrap();
        let five_lineage =
            dexdo::seller::read_seller_fill_lineage(&five_cursor, &residual_five.token_contract)
                .unwrap()
                .unwrap();
        assert_eq!(five_lineage.replacement_nonce, Some(12));
        assert_eq!(
            five_lineage.replacement_token_contract.as_deref(),
            Some(residual_three.token_contract.as_str())
        );
        let final_cursor =
            super::seller_watch_cursor_path(Some(root), &residual_three.token_contract).unwrap();
        let final_fill =
            dexdo::seller::read_seller_fill_lineage(&final_cursor, &residual_three.token_contract)
                .unwrap()
                .unwrap();
        assert_eq!(
            (
                final_fill.offered_ticks,
                final_fill.matched_ticks,
                final_fill.residual_ticks
            ),
            (3, 2, 1)
        );
    }

    /// (issue example 2), driven through the real `run_seller_pool` entry: a deal that cannot
    /// start AND an owner fill the pool cannot
    /// account for, in the same run.
    /// Before this, the owner-fill audit ran first and won the `first_error` race, so the process
    /// printed `Error: seller owner fill... refusing to discard unknown capacity` while the real
    /// root cause was only logged -- which is what produced the wrong "the note is permanently
    /// wedged" conclusion in. The primary must now be on the headline and the owner-fill
    /// finding attached under `secondary`.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn pool_reports_the_startup_failure_and_attaches_the_owner_fill_finding() {
        let root = tempfile::tempdir().expect("seller pool test directory");
        let root = root.path();
        let note = Arc::new(LocalNote::generate());
        let note_addr = format!("0:{}", "a".repeat(64));
        let frame_model = "openai/gpt-oss-20b";
        let owner_fills = Arc::new(Mutex::new(Vec::new()));
        let backend = Arc::new(PoolTestBackend::new(
            owner_fills.clone(),
            format!("0:{}", "1".repeat(64)),
            8,
            3,
            false,
            i64::MAX - 4,
        ));
        // An address nothing listens on: the pinned-TLS self-probe fails, exactly as in. The
        // reservation is HELD for the whole assertion -- a bind-and-drop hands the port
        // straight back to the kernel and something else can answer on it.
        let (_unreachable_hold, unreachable) = crate::test_refusing_endpoint::refusing_endpoint();
        let seller = dexdo::seller::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            dexdo::seller::UpstreamConfig::Mock,
            note.clone(),
        )
        .await
        .unwrap();
        let deal = SellerPoolDeal {
            chain: backend.clone(),
            cfg: SellerConfig {
                token_contract: backend.token_contract.clone(),
                price_per_tick: backend.price_per_tick,
                max_ticks: backend.offered_ticks,
                subscription: false,
                gateway_advertise: unreachable.clone(),
                mock_token_count: 8,
            },
            watch: dexdo::seller::SellerMatchWatchConfig {
                cursor_path: root.join("cascade.cursor.json"),
                poll_interval: std::time::Duration::from_millis(1),
            },
            upstream: dexdo::seller::UpstreamConfig::Mock,
            nonce: 10,
            market: Some(dexdo_core::MarketManifest {
                network: "shellnet".to_string(),
                frame_model: frame_model.to_string(),
                model_hash: dexdo_core::model_hash_for(frame_model),
                inference_order_book: format!("0:{}", "d".repeat(64)),
                root_model: format!("0:{}", "e".repeat(64)),
                token_contract: backend.token_contract.clone(),
                seller_note: note_addr.clone(),
                nonce: 10,
                price_per_tick: u128::from(backend.price_per_tick),
                max_ticks: u128::from(backend.offered_ticks),
            }),
        };
        // An owner fill for a TokenContract this pool has no handle for.
        let unknown_tc = format!("0:{}", "9".repeat(64));
        owner_fills.lock().unwrap().push((
            i64::MAX - 5,
            MatchedFill {
                order_id: 999,
                token_contract: unknown_tc.clone(),
                ticks: 2,
                price_per_tick: 1_000_000_000,
            },
        ));
        let mut provision = |_: String, _: u64, _: u64, _: u64| {
            futures::future::ready(Err(anyhow::anyhow!("no residual provision in this test")))
        };
        let shutdown = futures::future::pending::<()>().fuse();
        tokio::pin!(shutdown);
        let error = run_seller_pool(
            &seller,
            vec![deal],
            SellerPoolContext {
                deals_dir: Some(root),
                contracts: std::path::Path::new("contracts/deployed.shellnet.json"),
                note_addr: &note_addr,
                frame_model,
                gateway_advertise: &unreachable,
                // `unreachable` is a closed loopback port, so it is not public and the
                // production default is still fatal -- the cascade under test is reached.
                advertise_probe: dexdo::seller::liveness::AdvertiseProbePolicy::default(),
            },
            &pool_test_policy(2),
            &mut provision,
            shutdown.as_mut(),
        )
        .await
        .expect_err("a readiness failure plus an unaccounted owner fill must fail visibly");
        let rendered = error.to_string();

        // The PRIMARY is the concrete readiness error itself; the pool never wraps it in another
        // structured error just to attach the cascade note.
        let first_line = rendered.lines().next().unwrap();
        assert!(
            first_line.starts_with("error[E_ADVERTISE_UNREACHABLE] (network): advertised gateway"),
            "{rendered}"
        );
        assert_eq!(
            rendered.matches("error[E_ADVERTISE_UNREACHABLE]").count(),
            1
        );
        assert!(rendered.contains(&unreachable), "{rendered}");
        // The SECONDARY is attached, named, and never on the first line.
        assert!(
            !first_line.contains("unknown capacity"),
            "the cascade masqueraded as the primary: {rendered}"
        );
        assert!(
            rendered.contains(
                "secondary (pool owner-fill audit): error[E_POOL_UNKNOWN_OWNER_FILL] (pool):"
            ),
            "{rendered}"
        );
        assert!(rendered.contains(&unknown_tc), "{rendered}");
        assert!(
            rendered.contains("CONSEQUENCE of the primary error"),
            "{rendered}"
        );
        assert_eq!(backend.post_calls.load(Ordering::Relaxed), 0);
        seller.server_task.abort();
    }

    /// the exact CLI shape the live campaign ran: `--gateway-listen 127.0.0.1:0` with no
    /// `--gateway-advertise`. The advertise is inherited from the listen address at the command
    /// boundary -- before the gateway binds -- so it still carries the placeholder port `0`, which is
    /// not an address anyone can dial. Driven through the real `run_seller` entry: the endpoint a
    /// BUYER decrypts out of the handover must be the port the gateway actually bound, and a client
    /// must be able to connect to it. Without the resolution the buyer is handed `127.0.0.1:0`.
    #[tokio::test]
    async fn inherited_ephemeral_advertise_reaches_the_buyer_as_the_bound_port() {
        let root = tempfile::tempdir().unwrap();
        let seller_seed = [0x63; 32];
        std::fs::write(root.path().join("seller.key"), hex::encode(seller_seed)).unwrap();
        let token_contract = format!("0:{}", "7".repeat(64));
        let chain = MockChainBackend::new(
            root.path().join("endpoints.json"),
            ProtocolConsts::canonical(),
            DobParams::canonical(),
        );
        let buyer = Arc::new(LocalNote::generate());

        let args = crate::cli::args::SellerArgs {
            mock: crate::cli::args::MockFlags {
                mock_model: true,
                mock_chain: true,
            },
            identity: crate::cli::args::IdentityArgs {
                note_key: Some(root.path().join("seller.key")),
                note_index: 0,
                note_addr: None,
            },
            registry: crate::cli::args::ModelRegistryValidationArgs::default(),
            // The live shape: an ephemeral listen port, and no explicit advertise to inherit from.
            gateway_listen: "127.0.0.1:0".parse().unwrap(),
            gateway_advertise: None,
            allow_private_advertise: true,
            require_advertise_probe: false,
            endpoints_file: Some(root.path().join("endpoints.json")),
            deals_dir: Some(root.path().join("deals")),
            token_contract: Some(token_contract.clone()),
            market: None,
            nonce: Some(7),
            subscription: false,
            price_per_tick: dexdo_core::PRICE_STEP as u64,
            mock_token_count: 4,
            model: None,
            models: root.path().join("unused-models.json"),
            contracts: root.path().join("unused-contracts.json"),
            policy: None,
        };
        assert_eq!(
            args.checked_gateway_advertise_addr().unwrap(),
            "127.0.0.1:0",
            "the boundary can only inherit the placeholder; the port is not chosen yet"
        );

        let seller = super::run_seller(args);
        tokio::pin!(seller);
        let scenario = async {
            tokio::time::timeout(std::time::Duration::from_secs(30), async {
                loop {
                    if matches!(
                        chain.confirm_offer_outcome(&token_contract).await,
                        Ok(Some(SellOfferOutcome::Rested { .. }))
                    ) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("run_seller must rest the offer");
            chain
                .place_buy(&token_contract, buyer.as_ref())
                .await
                .unwrap();
            let buyer_client = dexdo::buyer::Buyer::from_note(buyer.clone());
            tokio::time::timeout(std::time::Duration::from_secs(30), async {
                loop {
                    if let Ok(handover) =
                        buyer_client.resolve_endpoint(&chain, &token_contract).await
                    {
                        break handover;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("buyer handover")
        };
        tokio::pin!(scenario);
        let handover = tokio::select! {
            result = &mut seller => panic!("seller exited before the buyer resolved the handover: {result:?}"),
            handover = &mut scenario => handover,
        };

        // By fact: the address the buyer would dial names a real port, and answers.
        let advertised = handover
            .endpoint
            .strip_prefix("https://")
            .expect("gateway endpoint")
            .to_string();
        assert!(
            !advertised.ends_with(":0"),
            "the buyer was handed the unusable placeholder port: {}",
            handover.endpoint
        );
        let advertised: std::net::SocketAddr = advertised.parse().expect("host:port");
        assert_ne!(advertised.port(), 0);
        tokio::net::TcpStream::connect(advertised)
            .await
            .expect("the advertised address must be the gateway the seller actually bound");
    }

    /// Real `dexdo seller` argv, parsed by the real CLI parser -- so a regression proves what the
    /// OPERATOR typed reaches the lifecycle, not what a struct literal asserted.
    fn parsed_seller_args(extra: &[&str]) -> crate::cli::args::SellerArgs {
        use clap::Parser as _;
        let mut argv = vec![
            "dexdo",
            "seller",
            "--note-addr",
            "0:note",
            "--token-contract",
            "0:tc",
            "--model",
            "qwen",
        ];
        argv.extend_from_slice(extra);
        let crate::Command::Seller(args) = crate::Cli::try_parse_from(argv)
            .expect("seller argv parses")
            .command
        else {
            panic!("expected Command::Seller");
        };
        args
    }

    fn advertise_pool_deal(
        backend: Arc<PoolTestBackend>,
        gateway_advertise: &str,
        cursor_path: std::path::PathBuf,
    ) -> SellerPoolDeal {
        SellerPoolDeal {
            cfg: SellerConfig {
                token_contract: backend.token_contract.clone(),
                price_per_tick: backend.price_per_tick,
                max_ticks: backend.offered_ticks,
                subscription: false,
                gateway_advertise: gateway_advertise.to_string(),
                mock_token_count: 4,
            },
            chain: backend,
            watch: dexdo::seller::SellerMatchWatchConfig {
                cursor_path,
                poll_interval: std::time::Duration::from_millis(1),
            },
            upstream: dexdo::seller::UpstreamConfig::Mock,
            nonce: 11,
            market: None,
        }
    }

    #[tokio::test]
    async fn pr795_edge_explicit_zero_gateway_advertise_fails_as_config_and_posts_nothing() {
        let root = tempfile::tempdir().unwrap();
        let endpoints = root.path().join("endpoints.json");
        let endpoints_arg = endpoints.to_string_lossy().into_owned();
        let args = parsed_seller_args(&[
            "--endpoints-file",
            &endpoints_arg,
            "--gateway-advertise",
            "seller.example.net:0",
        ]);

        let error = super::run_seller(args)
            .await
            .expect_err("an explicit advertise port 0 must fail before seller setup")
            .to_string();
        assert_eq!(
            error,
            "error[E_ADVERTISE_NOT_PUBLIC] (config): --gateway-advertise \
             seller.example.net:0 uses port 0, which no remote buyer can dial\n  \
             hint: pass a public host:port reachable from the internet, or run on a public host; \
             for local/LAN testing only, use --allow-private-advertise"
        );
        assert!(
            !endpoints.exists() && !endpoints.with_extension("chainstate.json").exists(),
            "the invalid explicit advertise must fail before any state or SELL can be written"
        );
    }

    /// The real pool boundary must retain the canonical structured error and the concrete I/O
    /// source from the fatal readiness probe; an ask behind that address must never be posted.
    #[tokio::test]
    async fn fatal_private_advertise_reaches_the_pool_boundary_with_its_typed_source() {
        let root = tempfile::tempdir().unwrap();
        let (_reserved, advertise) = crate::test_refusing_endpoint::refusing_endpoint();
        let args = parsed_seller_args(&["--gateway-advertise", &advertise]);
        let boundary = args
            .checked_gateway_advertise_addr()
            .expect_err("without the opt-in a private advertise is refused at the boundary")
            .to_string();
        assert!(
            boundary.contains("error[E_ADVERTISE_NOT_PUBLIC] (config)")
                && boundary.contains(&advertise),
            "{boundary}"
        );
        let seller = dexdo::seller::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            dexdo::seller::UpstreamConfig::Mock,
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();
        let note_addr = format!("0:{}", "b".repeat(64));
        let backend = Arc::new(PoolTestBackend::new(
            Arc::new(Mutex::new(Vec::new())),
            format!("0:{}", "2".repeat(64)),
            8,
            8,
            false,
            i64::MAX - 4,
        ));
        let deal = advertise_pool_deal(
            backend.clone(),
            &advertise,
            root.path().join("no-optin.cursor.json"),
        );
        let mut provision = |_: String, _: u64, _: u64, _: u64| {
            futures::future::ready(Err(anyhow::anyhow!("no residual provision in this test")))
        };
        let shutdown = futures::future::pending::<()>().fuse();
        tokio::pin!(shutdown);
        let error = run_seller_pool(
            &seller,
            vec![deal],
            SellerPoolContext {
                deals_dir: Some(root.path()),
                contracts: std::path::Path::new("contracts/deployed.shellnet.json"),
                note_addr: &note_addr,
                frame_model: "mock",
                gateway_advertise: &advertise,
                advertise_probe: args.advertise_probe_policy(),
            },
            &pool_test_policy(1),
            &mut provision,
            shutdown.as_mut(),
        )
        .await
        .expect_err("a private advertise nobody opted into must still fail closed");
        let structured = error
            .downcast_ref::<dexdo_core::DexdoError>()
            .expect("the pool boundary must expose the concrete DexdoError to main");
        assert_eq!(
            structured.code(),
            dexdo_core::error_codes::E_ADVERTISE_UNREACHABLE.code()
        );
        let first_source = std::error::Error::source(structured)
            .expect("the structured error must own the health failure");
        assert!(
            first_source
                .downcast_ref::<dexdo::seller::liveness::HealthFailure>()
                .is_some(),
            "unexpected first source: {first_source:?}"
        );
        let mut source = Some(first_source);
        let mut saw_io = false;
        while let Some(current) = source {
            saw_io |= current.downcast_ref::<std::io::Error>().is_some();
            source = current.source();
        }
        assert!(saw_io, "the original typed I/O source was flattened away");
        let rendered = structured.to_string();
        assert!(
            rendered.contains("error[E_ADVERTISE_UNREACHABLE] (network)")
                && rendered.contains(&advertise),
            "{rendered}"
        );
        assert_eq!(
            rendered.matches("error[E_ADVERTISE_UNREACHABLE]").count(),
            1
        );
        assert_eq!(rendered.matches("\n  hint: ").count(), 1);
        assert_eq!(
            backend.post_calls.load(Ordering::Relaxed),
            0,
            "nothing may be posted behind a fatal readiness failure"
        );
        seller.server_task.abort();
    }

    /// `--allow-private-advertise` admits a private address CLASS; it never vouches for what is
    /// listening there. An address that ANSWERS with a foreign certificate is proof of the WRONG
    /// endpoint, never a tolerable transport artifact -- so through the real lifecycle, with that
    /// flag passed, readiness stays fatal and the backend records nothing.
    #[tokio::test]
    async fn the_opt_in_still_fails_closed_on_a_wrong_gateway() {
        let root = tempfile::tempdir().unwrap();
        let seller = dexdo::seller::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            dexdo::seller::UpstreamConfig::Mock,
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();
        let foreign = dexdo::seller::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            dexdo::seller::UpstreamConfig::Mock,
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();
        assert_ne!(seller.tls_fingerprint, foreign.tls_fingerprint);
        let advertise = foreign.listen_addr.to_string();
        let args = parsed_seller_args(&[
            "--allow-private-advertise",
            "--gateway-advertise",
            &advertise,
        ]);
        let note_addr = format!("0:{}", "c".repeat(64));
        let backend = Arc::new(PoolTestBackend::new(
            Arc::new(Mutex::new(Vec::new())),
            format!("0:{}", "3".repeat(64)),
            8,
            8,
            false,
            i64::MAX - 4,
        ));
        let deal = advertise_pool_deal(
            backend.clone(),
            &advertise,
            root.path().join("foreign.cursor.json"),
        );
        let mut provision = |_: String, _: u64, _: u64, _: u64| {
            futures::future::ready(Err(anyhow::anyhow!("no residual provision in this test")))
        };
        let shutdown = futures::future::pending::<()>().fuse();
        tokio::pin!(shutdown);
        let error = run_seller_pool(
            &seller,
            vec![deal],
            SellerPoolContext {
                deals_dir: Some(root.path()),
                contracts: std::path::Path::new("contracts/deployed.shellnet.json"),
                note_addr: &note_addr,
                frame_model: "mock",
                gateway_advertise: &advertise,
                advertise_probe: args.advertise_probe_policy(),
            },
            &pool_test_policy(1),
            &mut provision,
            shutdown.as_mut(),
        )
        .await
        .expect_err("a foreign gateway on the advertised address must stay fatal")
        .to_string();
        assert!(
            error.contains("error[E_ADVERTISE_WRONG_GATEWAY] (tls)"),
            "{error}"
        );
        assert_eq!(
            backend.post_calls.load(Ordering::Relaxed),
            0,
            "a wrong-endpoint proof must never post"
        );
        seller.server_task.abort();
        foreign.server_task.abort();
    }

    #[cfg(feature = "shellnet")]
    fn mock_pool_seller_args(
        root: &std::path::Path,
        token_contract: String,
        nonce: u64,
        gateway_listen: std::net::SocketAddr,
    ) -> crate::cli::args::SellerArgs {
        crate::cli::args::SellerArgs {
            mock: crate::cli::args::MockFlags {
                mock_model: true,
                mock_chain: true,
            },
            identity: crate::cli::args::IdentityArgs {
                note_key: Some(root.join("seller.key")),
                note_index: 0,
                note_addr: None,
            },
            registry: crate::cli::args::ModelRegistryValidationArgs::default(),
            gateway_listen,
            gateway_advertise: None,
            allow_private_advertise: false,
            require_advertise_probe: false,
            endpoints_file: Some(root.join("endpoints.json")),
            deals_dir: Some(root.join("deals")),
            token_contract: Some(token_contract),
            market: None,
            nonce: Some(nonce),
            subscription: false,
            price_per_tick: dexdo_core::PRICE_STEP as u64,
            mock_token_count: 4,
            model: None,
            models: root.join("unused-models.json"),
            contracts: root.join("unused-contracts.json"),
            policy: None,
        }
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn run_seller_raw_mock_partial_fill_relists_and_serves_two_buyers() {
        let root = tempfile::tempdir().unwrap();
        let seller_seed = [0x61; 32];
        std::fs::write(root.path().join("seller.key"), hex::encode(seller_seed)).unwrap();
        let seller_note = Arc::new(
            dexdo_core::NoteTree::from_secret_hex(&hex::encode(seller_seed))
                .unwrap()
                .node(0)
                .unwrap(),
        );
        let seller_owner = format!(
            "0:{}",
            seller_note
                .pubkey()
                .ed
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let initial_tc = format!("0:{}", "1".repeat(64));
        let chain = MockChainBackend::new(
            root.path().join("endpoints.json"),
            ProtocolConsts::canonical(),
            DobParams::canonical(),
        );
        // shape B: `run_seller` makes the ONE bind and resolves the inherited `:0` advertise to
        // the port it actually got. Reserving a port here and releasing it before `run_seller`
        // binds hands it back to the kernel for the whole of `prepare_seller_offer` below.
        let gateway: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let cfg = SellerConfig {
            token_contract: initial_tc.clone(),
            price_per_tick: dexdo_core::PRICE_STEP as u64,
            max_ticks: 1024,
            subscription: false,
            gateway_advertise: gateway.to_string(),
            mock_token_count: 4,
        };
        prepare_seller_offer(seller_note.as_ref(), &chain, &cfg, Some(&seller_owner))
            .await
            .unwrap();
        let buyer_a = Arc::new(LocalNote::generate());
        let buyer_b = Arc::new(LocalNote::generate());
        chain
            .place_buy_ticks(&initial_tc, buyer_a.as_ref(), 2)
            .await
            .unwrap();

        let seller = super::run_seller(mock_pool_seller_args(
            root.path(),
            initial_tc.clone(),
            7,
            gateway,
        ));
        tokio::pin!(seller);
        let residual_tc = format!(
            "0:{}",
            dexdo_core::model_hash_for(&format!("{seller_owner}:mock:8")).trim_start_matches("0x")
        );
        let scenario = async {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if matches!(
                        chain.confirm_offer_outcome(&residual_tc).await,
                        Ok(Some(SellOfferOutcome::Rested { .. }))
                    ) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("raw startup must reach the pool and POST exact residual");
            chain
                .place_buy(&residual_tc, buyer_b.as_ref())
                .await
                .unwrap();

            let buyer_a_client = dexdo::buyer::Buyer::from_note(buyer_a.clone());
            let buyer_b_client = dexdo::buyer::Buyer::from_note(buyer_b.clone());
            let handover_a = tokio::time::timeout(std::time::Duration::from_secs(35), async {
                loop {
                    if let Ok(handover) = buyer_a_client.resolve_endpoint(&chain, &initial_tc).await
                    {
                        break handover;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("buyer A handover");
            let handover_b = tokio::time::timeout(std::time::Duration::from_secs(35), async {
                loop {
                    if let Ok(handover) =
                        buyer_b_client.resolve_endpoint(&chain, &residual_tc).await
                    {
                        break handover;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("buyer B handover");
            assert_eq!(
                buyer_a_client
                    .connect_and_stream(&handover_a, &initial_tc, 2)
                    .await
                    .unwrap()
                    .received,
                2
            );
            chain.stop(&initial_tc, buyer_a.as_ref()).await.unwrap();
            assert_eq!(
                buyer_b_client
                    .connect_and_stream(&handover_b, &residual_tc, 2)
                    .await
                    .unwrap()
                    .received,
                2
            );
        };
        tokio::pin!(scenario);
        tokio::select! {
            result = &mut seller => panic!("seller exited before buyer B continued: {result:?}"),
            () = &mut scenario => {}
        }
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn run_seller_terminal_raw_ancestor_resumes_linked_descendant() {
        let root = tempfile::tempdir().unwrap();
        let seller_seed = [0x62; 32];
        std::fs::write(root.path().join("seller.key"), hex::encode(seller_seed)).unwrap();
        let seller_note = Arc::new(
            dexdo_core::NoteTree::from_secret_hex(&hex::encode(seller_seed))
                .unwrap()
                .node(0)
                .unwrap(),
        );
        let seller_owner = format!(
            "0:{}",
            seller_note
                .pubkey()
                .ed
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let ancestor_tc = format!("0:{}", "2".repeat(64));
        let descendant_tc = format!("0:{}", "3".repeat(64));
        let chain = MockChainBackend::new(
            root.path().join("endpoints.json"),
            ProtocolConsts::canonical(),
            DobParams::canonical(),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let gateway = listener.local_addr().unwrap();
        drop(listener);
        let descendant_cfg = SellerConfig {
            token_contract: descendant_tc.clone(),
            price_per_tick: dexdo_core::PRICE_STEP as u64,
            max_ticks: 2,
            subscription: false,
            gateway_advertise: gateway.to_string(),
            mock_token_count: 4,
        };
        prepare_seller_offer(
            seller_note.as_ref(),
            &chain,
            &descendant_cfg,
            Some(&seller_owner),
        )
        .await
        .unwrap();
        let buyer = Arc::new(LocalNote::generate());
        chain
            .place_buy(&descendant_tc, buyer.as_ref())
            .await
            .unwrap();

        let market = dexdo_core::MarketManifest {
            network: "mock".to_string(),
            frame_model: "mock".to_string(),
            model_hash: dexdo_core::model_hash_for("mock"),
            inference_order_book: "mock".to_string(),
            root_model: "mock".to_string(),
            token_contract: descendant_tc.clone(),
            seller_note: seller_owner.clone(),
            nonce: 8,
            price_per_tick: u128::from(descendant_cfg.price_per_tick),
            max_ticks: u128::from(descendant_cfg.max_ticks),
        };
        let deals_dir = root.path().join("deals");
        deals::save_deal_handle(
            &deals_dir,
            &deals::DealHandle {
                version: deals::DEAL_HANDLE_VERSION,
                handle: deals::make_handle_id(&descendant_tc, deals::DealHandleRole::Seller),
                role: deals::DealHandleRole::Seller,
                network: "mock".to_string(),
                token_contract: descendant_tc.clone(),
                note_addr: seller_owner.clone(),
                frame_model: market.frame_model.clone(),
                model_hash: Some(market.model_hash.clone()),
                order_book: Some(market.inference_order_book.clone()),
                root_model: Some(market.root_model.clone()),
                market: Some(market),
                contracts: root
                    .path()
                    .join("unused-contracts.json")
                    .display()
                    .to_string(),
                endpoint: Some(deals::DealEndpointInfo {
                    kind: "gateway".to_string(),
                    value: gateway.to_string(),
                }),
                created_order_ids: Vec::new(),
                created_at_unix: deals::now_unix().unwrap(),
            },
        )
        .unwrap();
        let cursor_path = super::seller_watch_cursor_path(Some(&deals_dir), &ancestor_tc).unwrap();
        std::fs::create_dir_all(cursor_path.parent().unwrap()).unwrap();
        std::fs::write(
            &cursor_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "token_contract": ancestor_tc,
                "source": MatchWatchCursor::new(0),
                "last_polled_unix": null,
                "opened_at_unix": null,
                "fill": dexdo::seller::SellerFillLineage {
                    order_id: 1,
                    offered_ticks: 4,
                    matched_ticks: 2,
                    residual_ticks: 2,
                    price_per_tick: dexdo_core::PRICE_STEP as u64,
                    replacement_nonce: Some(8),
                    replacement_token_contract: Some(descendant_tc.clone()),
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let seller = super::run_seller(mock_pool_seller_args(
            root.path(),
            ancestor_tc.clone(),
            7,
            gateway,
        ));
        tokio::pin!(seller);
        let scenario = async {
            let buyer_client = dexdo::buyer::Buyer::from_note(buyer);
            let handover = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if let Ok(handover) =
                        buyer_client.resolve_endpoint(&chain, &descendant_tc).await
                    {
                        break handover;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("production entry must resume linked descendant");
            assert_eq!(
                buyer_client
                    .connect_and_stream(&handover, &descendant_tc, 2)
                    .await
                    .unwrap()
                    .received,
                2
            );
            assert_eq!(
                chain.confirm_offer_outcome(&ancestor_tc).await.unwrap(),
                None,
                "terminal ancestor must not be reposted"
            );
        };
        tokio::pin!(scenario);
        tokio::select! {
            result = &mut seller => panic!("seller exited before descendant service: {result:?}"),
            () = &mut scenario => {}
        }
    }

    #[test]
    fn policy_seller_fields_dispatch_or_fail_closed_explicitly() {
        let source = include_str!("seller.rs");
        let policy_source = include_str!("policy.rs");
        let seller_policy_source = include_str!("seller_policy.rs");
        let run = source
            .find("pub(crate) async fn run_seller")
            .expect("run_seller present");
        assert!(
            policy_source.contains("fn validate_seller_runtime_capabilities"),
            "seller runtime policy capability validation must remain explicit"
        );
        assert!(
            seller_policy_source.contains("chain.release_dispute(token_contract)"),
            "seller dispute_against_me=release_if_clean must invoke release_dispute"
        );
        assert!(
            seller_policy_source.contains("policy_action_unsupported"),
            "seller unsupported republish/cleanup surfaces must fail closed explicitly"
        );
        assert!(
            seller_policy_source.contains("action=retire_gateway"),
            "seller buyer_no_show=retire_gateway must have an explicit runtime terminal action"
        );

        let end = source[run..]
            .find("#[cfg(test)]\nmod tests")
            .map(|offset| run + offset)
            .expect("run_seller end marker present");
        let body = &source[run..end];
        let validate = body
            .find("load_seller_runtime_policy")
            .expect("shared seller policy validation present");
        let doctor = body
            .find("shellnet_doctor_preflight")
            .expect("real shellnet preflight present");
        let startup = body
            .find("run_seller_pool(")
            .expect("shared seller pool startup seam present");
        assert!(validate < doctor);
        assert!(validate < startup);

        let advance_start = source
            .find("async fn record_advance_result")
            .expect("per-deal result handler present");
        let advance_end = source[advance_start..]
            .find("struct SellerPoolContext")
            .map(|offset| advance_start + offset)
            .expect("per-deal result handler end present");
        let advance = &source[advance_start..advance_end];
        assert!(
            advance.contains("apply_seller_terminal_policy")
                && advance.contains("is_err_not_open(&error)")
                && advance.contains("classify_by_fact_advance_failure")
                && advance.contains("apply_seller_dispute_policy"),
            "ERR_NOT_OPEN must be classified before the seller turns it into a process fault"
        );
        let classify = advance
            .find("classify_by_fact_advance_failure")
            .expect("ERR_NOT_OPEN classifier present");
        let policy = advance
            .find("apply_seller_dispute_policy")
            .expect("non-ERR_NOT_OPEN dispute policy fallback present");
        assert!(
            classify < policy,
            "unsafe ERR_NOT_OPEN must return a money-path fault before generic dispute policy can consume it"
        );
        assert!(body.contains("run_seller_pool"));
    }
}
