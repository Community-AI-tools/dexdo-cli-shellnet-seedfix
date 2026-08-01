use super::{
    inspect_seller_offer, prepare_seller_offer, validate_resting_offer, wait_for_match,
    RunningSeller, SellerConfig, SellerMatchWatchConfig, SellerOfferInspection, SellerOfferStartup,
};
use anyhow::{anyhow, Result};
use dexdo_core::{params::SellerLivenessParams, ChainBackend, Match};
use dexdo_proto::{ChallengeRequest, GatewayClient};
use std::future::Future;
use std::time::Duration;

use crate::seller::auth::HEALTH_CHALLENGE_TC;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthComponent {
    GatewayTask,
    AdvertisedGateway,
    UpstreamModel,
}

impl HealthComponent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GatewayTask => "gateway_task",
            Self::AdvertisedGateway => "advertised_gateway",
            Self::UpstreamModel => "upstream_authentication_and_model",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthFailure {
    pub component: HealthComponent,
    pub timed_out: bool,
    pub detail: String,
}

impl std::fmt::Display for HealthFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} {}: {}",
            self.component.as_str(),
            if self.timed_out {
                "timed out"
            } else {
                "failed"
            },
            self.detail
        )
    }
}

impl std::error::Error for HealthFailure {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestingOfferIdentity {
    pub owner_note: String,
    pub token_contract: String,
    pub order_id: u128,
}

#[derive(Debug)]
pub enum CancellationDisposition {
    Cancelled,
    AlreadyAbsent,
    AlreadyMatched(Match),
    UnknownFailure { known_result: String },
}

impl CancellationDisposition {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::AlreadyAbsent => "already_absent",
            Self::AlreadyMatched(_) => "already_matched",
            Self::UnknownFailure { .. } => "unknown_failure",
        }
    }

    pub fn known_result(&self) -> Option<&str> {
        match self {
            Self::UnknownFailure { known_result } => Some(known_result),
            _ => None,
        }
    }
}

impl std::fmt::Display for CancellationDisposition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())?;
        if let Some(known_result) = self.known_result() {
            write!(formatter, " ({known_result})")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum RestingStopReason {
    Health(HealthFailure),
    Shutdown,
    Watcher(String),
}

#[derive(Debug)]
pub enum RestingSellerOutcome {
    Matched(Match),
    Stopped {
        reason: RestingStopReason,
        disposition: CancellationDisposition,
    },
}

#[derive(Debug)]
pub enum SellerStartupOutcome {
    Ready(SellerOfferStartup),
    Stopped {
        identity: Option<RestingOfferIdentity>,
        reason: RestingStopReason,
        disposition: CancellationDisposition,
    },
}

fn health_failure(
    component: HealthComponent,
    timed_out: bool,
    detail: impl Into<String>,
) -> HealthFailure {
    HealthFailure {
        component,
        timed_out,
        detail: detail.into(),
    }
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn trace_health(
    identity: Option<&RestingOfferIdentity>,
    token_contract: &str,
    component: HealthComponent,
    status: &str,
) {
    tracing::info!(
        event = "seller_health",
        timestamp = unix_timestamp(),
        token_contract,
        owner_note = identity
            .map(|value| value.owner_note.as_str())
            .unwrap_or("pending"),
        order_id = identity.map(|value| value.order_id),
        component = component.as_str(),
        status,
        "seller readiness component checked"
    );
}

async fn probe_advertised_gateway(seller: &RunningSeller, advertised: &str) -> Result<()> {
    let endpoint = format!("https://{advertised}");
    let channel = crate::buyer::tls::connect_pinned(&endpoint, &seller.tls_fingerprint).await?;
    let mut client = GatewayClient::new(channel);
    let challenge = client
        .get_challenge(ChallengeRequest {
            token_contract: HEALTH_CHALLENGE_TC.to_string(),
        })
        .await?
        .into_inner();
    if challenge.token_contract != HEALTH_CHALLENGE_TC || challenge.nonce.len() != 32 {
        return Err(anyhow!(
            "gateway readiness challenge returned an invalid response"
        ));
    }
    Ok(())
}

pub async fn check_readiness(
    seller: &RunningSeller,
    advertised: &str,
    timeout: Duration,
    identity: Option<&RestingOfferIdentity>,
    token_contract: &str,
) -> std::result::Result<(), HealthFailure> {
    let deadline = tokio::time::Instant::now() + timeout;
    if seller.server_task.is_finished() {
        trace_health(
            identity,
            token_contract,
            HealthComponent::GatewayTask,
            "fail",
        );
        return Err(health_failure(
            HealthComponent::GatewayTask,
            false,
            "gateway server task stopped",
        ));
    }
    trace_health(
        identity,
        token_contract,
        HealthComponent::GatewayTask,
        "pass",
    );

    match tokio::time::timeout_at(deadline, probe_advertised_gateway(seller, advertised)).await {
        Ok(Ok(())) => trace_health(
            identity,
            token_contract,
            HealthComponent::AdvertisedGateway,
            "pass",
        ),
        Ok(Err(error)) => {
            trace_health(
                identity,
                token_contract,
                HealthComponent::AdvertisedGateway,
                "fail",
            );
            return Err(health_failure(
                HealthComponent::AdvertisedGateway,
                false,
                error.to_string(),
            ));
        }
        Err(_) => {
            trace_health(
                identity,
                token_contract,
                HealthComponent::AdvertisedGateway,
                "timeout",
            );
            return Err(health_failure(
                HealthComponent::AdvertisedGateway,
                true,
                "bounded gateway probe expired",
            ));
        }
    }

    let upstream = seller.state.upstream(token_contract);
    match tokio::time::timeout_at(deadline, upstream.check_health()).await {
        Ok(Ok(())) => trace_health(
            identity,
            token_contract,
            HealthComponent::UpstreamModel,
            "pass",
        ),
        Ok(Err(error)) => {
            trace_health(
                identity,
                token_contract,
                HealthComponent::UpstreamModel,
                "fail",
            );
            return Err(health_failure(
                HealthComponent::UpstreamModel,
                false,
                error.to_string(),
            ));
        }
        Err(_) => {
            trace_health(
                identity,
                token_contract,
                HealthComponent::UpstreamModel,
                "timeout",
            );
            return Err(health_failure(
                HealthComponent::UpstreamModel,
                true,
                "bounded upstream model probe expired",
            ));
        }
    }

    if seller.server_task.is_finished() {
        trace_health(
            identity,
            token_contract,
            HealthComponent::GatewayTask,
            "fail",
        );
        return Err(health_failure(
            HealthComponent::GatewayTask,
            false,
            "gateway server task stopped during readiness",
        ));
    }
    Ok(())
}

enum TargetState {
    Present,
    Absent,
    Matched(Match),
}

async fn target_state(
    chain: &dyn ChainBackend,
    cfg: &SellerConfig,
    identity: &RestingOfferIdentity,
) -> Result<TargetState> {
    let orders = chain
        .raw_resting_sell_orders_for_tc(&identity.token_contract)
        .await?;
    if let Some(order) = orders
        .iter()
        .find(|order| order.order_id == identity.order_id)
    {
        validate_resting_offer(order, Some(&identity.owner_note), cfg)?;
        return Ok(TargetState::Present);
    }
    if let Some(matched) = chain
        .read_openable_match_now(&identity.token_contract)
        .await?
    {
        return Ok(TargetState::Matched(matched));
    }
    Ok(TargetState::Absent)
}

fn unknown_cancellation(
    identity: &RestingOfferIdentity,
    cycle_timeout: Duration,
    known_result: impl Into<String>,
) -> CancellationDisposition {
    let known_result = format!(
        "{}; budget_ms={}; operator_action=run `dexdo orders <same identity and market options> \
         cancel {}` and verify the book",
        known_result.into(),
        cycle_timeout.as_millis(),
        identity.order_id
    );
    tracing::error!(
        event = "seller_cancel_terminal",
        timestamp = unix_timestamp(),
        owner_note = %identity.owner_note,
        token_contract = %identity.token_contract,
        order_id = identity.order_id,
        disposition = "unknown_failure",
        known_result = %known_result,
        "exact resting SELL cancellation has no terminal authoritative fact"
    );
    CancellationDisposition::UnknownFailure { known_result }
}

async fn cancel_and_confirm_before(
    chain: &dyn ChainBackend,
    cfg: &SellerConfig,
    identity: &RestingOfferIdentity,
    deadline: tokio::time::Instant,
    cycle_timeout: Duration,
    poll_interval: Duration,
) -> CancellationDisposition {
    loop {
        match tokio::time::timeout_at(deadline, target_state(chain, cfg, identity)).await {
            Err(_) => {
                return unknown_cancellation(
                    identity,
                    cycle_timeout,
                    "initial_authoritative_read=timeout",
                );
            }
            Ok(Err(error)) => {
                return unknown_cancellation(
                    identity,
                    cycle_timeout,
                    format!("initial_authoritative_read=failed: {error}"),
                );
            }
            Ok(Ok(TargetState::Present)) => break,
            Ok(Ok(TargetState::Matched(matched))) => {
                tracing::info!(
                    event = "seller_cancel_terminal",
                    timestamp = unix_timestamp(),
                    owner_note = %identity.owner_note,
                    token_contract = %identity.token_contract,
                    order_id = identity.order_id,
                    disposition = "already_matched",
                    "match won before cancellation submit; no order was touched"
                );
                return CancellationDisposition::AlreadyMatched(matched);
            }
            Ok(Ok(TargetState::Absent)) if tokio::time::Instant::now() < deadline => {
                let wake_at = std::cmp::min(tokio::time::Instant::now() + poll_interval, deadline);
                tokio::time::sleep_until(wake_at).await;
                if tokio::time::Instant::now() < deadline {
                    continue;
                }
            }
            Ok(Ok(TargetState::Absent)) => {}
        }
        if tokio::time::Instant::now() >= deadline {
            tracing::info!(
                event = "seller_cancel_terminal",
                timestamp = unix_timestamp(),
                owner_note = %identity.owner_note,
                token_contract = %identity.token_contract,
                order_id = identity.order_id,
                disposition = "already_absent",
                "resting SELL was already authoritatively absent"
            );
            return CancellationDisposition::AlreadyAbsent;
        }
    }

    tracing::info!(
        event = "seller_cancel_submit",
        timestamp = unix_timestamp(),
        owner_note = %identity.owner_note,
        token_contract = %identity.token_contract,
        order_id = identity.order_id,
        "submitting exact resting SELL cancellation"
    );
    let (submit_succeeded, submit_result) = match tokio::time::timeout_at(
        deadline,
        chain.cancel_resting_sell_order(&identity.token_contract, identity.order_id),
    )
    .await
    {
        Ok(Ok(())) => (true, "cancel_submit=accepted".to_string()),
        Ok(Err(error)) => (false, format!("cancel_submit=rejected: {error}")),
        Err(_) => {
            return unknown_cancellation(identity, cycle_timeout, "cancel_submit=timeout");
        }
    };

    let mut authoritative_result = "authoritative_state=present".to_string();
    let mut authoritatively_absent = false;
    loop {
        if tokio::time::Instant::now() >= deadline {
            if authoritatively_absent {
                let disposition = if submit_succeeded {
                    CancellationDisposition::Cancelled
                } else {
                    CancellationDisposition::AlreadyAbsent
                };
                tracing::info!(
                    event = "seller_cancel_terminal",
                    timestamp = unix_timestamp(),
                    owner_note = %identity.owner_note,
                    token_contract = %identity.token_contract,
                    order_id = identity.order_id,
                    disposition = disposition.as_str(),
                    submit_result = %submit_result,
                    "resting SELL remained absent through match propagation reconciliation"
                );
                return disposition;
            }
            return unknown_cancellation(
                identity,
                cycle_timeout,
                format!("{submit_result}; {authoritative_result}"),
            );
        }
        match tokio::time::timeout_at(deadline, target_state(chain, cfg, identity)).await {
            Ok(Ok(TargetState::Absent)) => {
                authoritatively_absent = true;
                authoritative_result = "authoritative_state=absent".to_string();
            }
            Ok(Ok(TargetState::Matched(matched))) => {
                tracing::info!(
                    event = "seller_cancel_terminal",
                    timestamp = unix_timestamp(),
                    owner_note = %identity.owner_note,
                    token_contract = %identity.token_contract,
                    order_id = identity.order_id,
                    disposition = "already_matched",
                    submit_result = %submit_result,
                    "match won the cancel race; no other order was touched"
                );
                return CancellationDisposition::AlreadyMatched(matched);
            }
            Ok(Ok(TargetState::Present)) => {
                authoritatively_absent = false;
                authoritative_result = "authoritative_state=present".to_string();
            }
            Ok(Err(error)) => {
                authoritatively_absent = false;
                authoritative_result = format!("authoritative_read=failed: {error}");
            }
            Err(_) => {
                return unknown_cancellation(
                    identity,
                    cycle_timeout,
                    format!("{submit_result}; authoritative_read=timeout"),
                );
            }
        }

        let wake_at = std::cmp::min(tokio::time::Instant::now() + poll_interval, deadline);
        tokio::time::sleep_until(wake_at).await;
    }
}

async fn cancel_and_confirm_with_timing(
    chain: &dyn ChainBackend,
    cfg: &SellerConfig,
    identity: &RestingOfferIdentity,
    confirm_timeout: Duration,
    poll_interval: Duration,
) -> CancellationDisposition {
    cancel_and_confirm_before(
        chain,
        cfg,
        identity,
        tokio::time::Instant::now() + confirm_timeout,
        confirm_timeout,
        poll_interval,
    )
    .await
}

pub async fn cancel_and_confirm(
    chain: &dyn ChainBackend,
    cfg: &SellerConfig,
    identity: &RestingOfferIdentity,
) -> CancellationDisposition {
    let params = SellerLivenessParams::canonical();
    cancel_and_confirm_with_timing(
        chain,
        cfg,
        identity,
        params.cancel_confirmation_timeout,
        params.cancel_confirmation_poll,
    )
    .await
}

async fn wait_for_gateway_task_stop(seller: &RunningSeller) {
    let poll_interval = SellerLivenessParams::canonical().gateway_task_poll;
    while !seller.server_task.is_finished() {
        tokio::time::sleep(poll_interval).await;
    }
}

fn gateway_task_failure(detail: &str) -> HealthFailure {
    health_failure(HealthComponent::GatewayTask, false, detail)
}

async fn stop_exact_offer(
    seller: &RunningSeller,
    chain: &dyn ChainBackend,
    cfg: &SellerConfig,
    identity: &RestingOfferIdentity,
    reason: RestingStopReason,
    deadline: tokio::time::Instant,
    timing: SupervisionTiming,
) -> Result<SellerStartupOutcome> {
    match cancel_and_confirm_before(
        chain,
        cfg,
        identity,
        deadline,
        timing.cycle_timeout,
        timing.cancel_poll,
    )
    .await
    {
        CancellationDisposition::AlreadyMatched(_) => Ok(SellerStartupOutcome::Ready(
            SellerOfferStartup::ResumedFunded,
        )),
        disposition @ CancellationDisposition::UnknownFailure { .. } => {
            Ok(SellerStartupOutcome::Stopped {
                identity: Some(identity.clone()),
                reason,
                disposition,
            })
        }
        disposition => {
            seller.server_task.abort();
            Ok(SellerStartupOutcome::Stopped {
                identity: Some(identity.clone()),
                reason,
                disposition,
            })
        }
    }
}

async fn reconcile_unresolved_startup(
    chain: &dyn ChainBackend,
    cfg: &SellerConfig,
    expected_owner: &str,
    deadline: tokio::time::Instant,
    poll_interval: Duration,
) -> std::result::Result<SellerOfferInspection, String> {
    let mut known_result = "authoritative_state=vacant".to_string();
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(known_result);
        }
        match tokio::time::timeout_at(
            deadline,
            inspect_seller_offer(chain, cfg, Some(expected_owner)),
        )
        .await
        {
            Ok(Ok(SellerOfferInspection::Vacant)) => {
                known_result = "authoritative_state=vacant".to_string();
            }
            Ok(Ok(inspection)) => return Ok(inspection),
            Ok(Err(error)) => {
                known_result = format!("authoritative_read=failed: {error}");
            }
            Err(_) => return Err("authoritative_read=timeout".to_string()),
        }
        let wake_at = std::cmp::min(tokio::time::Instant::now() + poll_interval, deadline);
        tokio::time::sleep_until(wake_at).await;
    }
}

async fn resolve_interrupted_startup(
    seller: &RunningSeller,
    chain: &dyn ChainBackend,
    cfg: &SellerConfig,
    expected_owner: &str,
    startup: Option<SellerOfferStartup>,
    stop: (RestingStopReason, tokio::time::Instant),
    timing: SupervisionTiming,
) -> Result<SellerStartupOutcome> {
    let (reason, deadline) = stop;
    let inspection = match startup {
        Some(SellerOfferStartup::ResumedFunded)
        | Some(SellerOfferStartup::Posted {
            outcome: Some(dexdo_core::SellOfferOutcome::Matched),
        }) => {
            return Ok(SellerStartupOutcome::Ready(
                SellerOfferStartup::ResumedFunded,
            ))
        }
        Some(SellerOfferStartup::ResumedResting { order_id })
        | Some(SellerOfferStartup::Posted {
            outcome: Some(dexdo_core::SellOfferOutcome::Rested { order_id }),
        }) => SellerOfferInspection::Resting { order_id },
        Some(SellerOfferStartup::Posted { outcome: None }) | None => {
            match reconcile_unresolved_startup(
                chain,
                cfg,
                expected_owner,
                deadline,
                timing.cancel_poll,
            )
            .await
            {
                Ok(inspection) => inspection,
                Err(result) => {
                    let known_result = format!(
                        "fresh_sell_submit=unresolved; {result}; budget_ms={}; \
                         operator_action=run `dexdo orders <same identity and market options> list`, \
                         then cancel the exact resting order with `dexdo orders <same identity and \
                         market options> cancel <ORDER_ID>`",
                        timing.cycle_timeout.as_millis()
                    );
                    tracing::error!(
                        event = "seller_cancel_terminal",
                        timestamp = unix_timestamp(),
                        owner_note = expected_owner,
                        token_contract = %cfg.token_contract,
                        order_id = Option::<u128>::None,
                        disposition = "unknown_failure",
                        known_result = %known_result,
                        "interrupted fresh SELL has no terminal authoritative fact"
                    );
                    return Ok(SellerStartupOutcome::Stopped {
                        identity: None,
                        reason,
                        disposition: CancellationDisposition::UnknownFailure { known_result },
                    });
                }
            }
        }
    };

    match inspection {
        SellerOfferInspection::Funded => Ok(SellerStartupOutcome::Ready(
            SellerOfferStartup::ResumedFunded,
        )),
        SellerOfferInspection::Resting { order_id } => {
            let identity = RestingOfferIdentity {
                owner_note: expected_owner.to_string(),
                token_contract: cfg.token_contract.clone(),
                order_id,
            };
            stop_exact_offer(seller, chain, cfg, &identity, reason, deadline, timing).await
        }
        SellerOfferInspection::Vacant => {
            seller.server_task.abort();
            Ok(SellerStartupOutcome::Stopped {
                identity: None,
                reason,
                disposition: CancellationDisposition::AlreadyAbsent,
            })
        }
    }
}

async fn prepare_seller_offer_with_timing<S>(
    seller: &RunningSeller,
    chain: &dyn ChainBackend,
    cfg: &SellerConfig,
    expected_owner: &str,
    existing_identity: Option<&RestingOfferIdentity>,
    shutdown: S,
    timing: SupervisionTiming,
) -> Result<SellerStartupOutcome>
where
    S: Future<Output = ()>,
{
    let readiness_deadline = tokio::time::Instant::now() + timing.cycle_timeout;
    let readiness = check_readiness(
        seller,
        &cfg.gateway_advertise,
        timing.health_timeout,
        existing_identity,
        &cfg.token_contract,
    );
    let gateway_stopped = wait_for_gateway_task_stop(seller);
    tokio::pin!(readiness);
    tokio::pin!(gateway_stopped);
    tokio::pin!(shutdown);

    let readiness_stop = tokio::select! {
        biased;
        _ = &mut shutdown => Some(RestingStopReason::Shutdown),
        _ = &mut gateway_stopped => Some(RestingStopReason::Health(
            gateway_task_failure("gateway server task stopped during startup readiness")
        )),
        result = &mut readiness => result.err().map(RestingStopReason::Health),
    };
    if let Some(reason) = readiness_stop {
        if let Some(identity) = existing_identity {
            return stop_exact_offer(
                seller,
                chain,
                cfg,
                identity,
                reason,
                readiness_deadline,
                timing,
            )
            .await;
        }
        seller.server_task.abort();
        return match reason {
            RestingStopReason::Shutdown => Ok(SellerStartupOutcome::Stopped {
                identity: None,
                reason,
                disposition: CancellationDisposition::AlreadyAbsent,
            }),
            RestingStopReason::Health(failure) => {
                Err(anyhow!("seller readiness failed before SELL: {failure}"))
            }
            RestingStopReason::Watcher(_) => unreachable!("no watcher exists before SELL"),
        };
    }

    let startup = prepare_seller_offer(seller.note.as_ref(), chain, cfg, Some(expected_owner));
    tokio::pin!(startup);
    let interruption = tokio::select! {
        biased;
        _ = &mut shutdown => Some(RestingStopReason::Shutdown),
        _ = &mut gateway_stopped => Some(RestingStopReason::Health(
            gateway_task_failure("gateway server task stopped during SELL post or confirmation")
        )),
        result = &mut startup => {
            return match result {
                Ok(SellerOfferStartup::Posted { outcome: None }) => {
                    resolve_interrupted_startup(
                        seller,
                        chain,
                        cfg,
                        expected_owner,
                        None,
                        (
                            RestingStopReason::Watcher(
                                "SELL post returned without an exact resting or matched outcome"
                                    .to_string(),
                            ),
                            tokio::time::Instant::now() + timing.cycle_timeout,
                        ),
                        timing,
                    ).await
                }
                Ok(startup @ SellerOfferStartup::Posted {
                    outcome: Some(dexdo_core::SellOfferOutcome::Rested { order_id }),
                }) => {
                    let identity = RestingOfferIdentity {
                        owner_note: expected_owner.to_string(),
                        token_contract: cfg.token_contract.clone(),
                        order_id,
                    };
                    let deadline = tokio::time::Instant::now() + timing.cycle_timeout;
                    let remaining =
                        deadline.saturating_duration_since(tokio::time::Instant::now());
                    let readiness = check_readiness(
                        seller,
                        &cfg.gateway_advertise,
                        std::cmp::min(timing.health_timeout, remaining),
                        Some(&identity),
                        &cfg.token_contract,
                    );
                    tokio::pin!(readiness);
                    let stop = tokio::select! {
                        biased;
                        _ = &mut shutdown => Some(RestingStopReason::Shutdown),
                        _ = &mut gateway_stopped => Some(RestingStopReason::Health(
                            gateway_task_failure(
                                "gateway server task stopped after fresh SELL became resting"
                            )
                        )),
                        result = &mut readiness => result.err().map(RestingStopReason::Health),
                    };
                    match stop {
                        Some(reason) => stop_exact_offer(
                            seller,
                            chain,
                            cfg,
                            &identity,
                            reason,
                            deadline,
                            timing,
                        ).await,
                        None => Ok(SellerStartupOutcome::Ready(startup)),
                    }
                }
                Ok(startup) => Ok(SellerStartupOutcome::Ready(startup)),
                Err(error) => {
                    let reason = RestingStopReason::Watcher(format!(
                        "seller offer post or confirmation failed: {error}"
                    ));
                    resolve_interrupted_startup(
                        seller,
                        chain,
                        cfg,
                        expected_owner,
                        None,
                        (
                            reason,
                            tokio::time::Instant::now() + timing.cycle_timeout,
                        ),
                        timing,
                    ).await
                }
            };
        }
    };

    let reason = interruption.expect("startup select only returns after an interruption");
    let deadline = tokio::time::Instant::now() + timing.cycle_timeout;
    let startup_deadline = std::cmp::min(
        deadline,
        tokio::time::Instant::now() + timing.health_timeout,
    );
    let startup = match tokio::time::timeout_at(startup_deadline, &mut startup).await {
        Ok(Ok(startup)) => Some(startup),
        Ok(Err(error)) => {
            tracing::warn!(
                token_contract = %cfg.token_contract,
                error = %error,
                "seller startup failed after lifecycle interruption; reconciling authoritative state"
            );
            None
        }
        Err(_) => None,
    };
    resolve_interrupted_startup(
        seller,
        chain,
        cfg,
        expected_owner,
        startup,
        (reason, deadline),
        timing,
    )
    .await
}

pub async fn prepare_seller_offer_with_liveness<S>(
    seller: &RunningSeller,
    chain: &dyn ChainBackend,
    cfg: &SellerConfig,
    expected_owner: &str,
    existing_identity: Option<&RestingOfferIdentity>,
    shutdown: S,
) -> Result<SellerStartupOutcome>
where
    S: Future<Output = ()>,
{
    let params = SellerLivenessParams::canonical();
    prepare_seller_offer_with_timing(
        seller,
        chain,
        cfg,
        expected_owner,
        existing_identity,
        shutdown,
        SupervisionTiming {
            health_interval: params.health_interval,
            health_timeout: params.health_check_timeout,
            cycle_timeout: params.health_cycle_timeout,
            cancel_poll: params.cancel_confirmation_poll,
            abort_gateway_on_stop: true,
        },
    )
    .await
}

#[derive(Clone, Copy)]
struct SupervisionTiming {
    health_interval: Duration,
    health_timeout: Duration,
    cycle_timeout: Duration,
    cancel_poll: Duration,
    abort_gateway_on_stop: bool,
}

async fn supervise_with_timing<S>(
    seller: &RunningSeller,
    chain: &dyn ChainBackend,
    cfg: &SellerConfig,
    watch: &SellerMatchWatchConfig,
    identity: &RestingOfferIdentity,
    shutdown: S,
    timing: SupervisionTiming,
) -> Result<RestingSellerOutcome>
where
    S: Future<Output = ()>,
{
    enum Trigger {
        Health(HealthFailure),
        Shutdown,
        Watcher(String),
    }

    let decision = {
        let matched = wait_for_match(seller, chain, cfg, watch);
        tokio::pin!(matched);
        tokio::pin!(shutdown);
        let mut last_healthy = tokio::time::Instant::now();
        let start = tokio::time::Instant::now() + timing.health_interval;
        let mut health = tokio::time::interval_at(start, timing.health_interval);
        health.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                match_result = &mut matched => {
                    break match match_result {
                        Ok(matched) => Ok(matched),
                        Err(error) => Err((
                            Trigger::Watcher(error.to_string()),
                            tokio::time::Instant::now() + timing.cycle_timeout,
                        )),
                    };
                }
                _ = &mut shutdown => break Err((
                    Trigger::Shutdown,
                    tokio::time::Instant::now() + timing.cycle_timeout,
                )),
                _ = health.tick() => {
                    let deadline = last_healthy + timing.cycle_timeout;
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    let check_timeout = std::cmp::min(timing.health_timeout, remaining);
                    if let Err(failure) = check_readiness(
                        seller,
                        &cfg.gateway_advertise,
                        check_timeout,
                        Some(identity),
                        &identity.token_contract,
                    ).await {
                        break Err((Trigger::Health(failure), deadline));
                    }
                    last_healthy = tokio::time::Instant::now();
                }
            }
        }
    };

    let (trigger, deadline) = match decision {
        Ok(matched) => return Ok(RestingSellerOutcome::Matched(matched)),
        Err(trigger) => trigger,
    };

    let disposition = cancel_and_confirm_before(
        chain,
        cfg,
        identity,
        deadline,
        timing.cycle_timeout,
        timing.cancel_poll,
    )
    .await;
    let disposition = match disposition {
        CancellationDisposition::AlreadyMatched(matched) => {
            return Ok(RestingSellerOutcome::Matched(matched));
        }
        disposition => disposition,
    };
    if timing.abort_gateway_on_stop
        && !matches!(&disposition, CancellationDisposition::UnknownFailure { .. })
    {
        seller.server_task.abort();
    }
    Ok(RestingSellerOutcome::Stopped {
        reason: match trigger {
            Trigger::Health(failure) => RestingStopReason::Health(failure),
            Trigger::Shutdown => RestingStopReason::Shutdown,
            Trigger::Watcher(error) => RestingStopReason::Watcher(error),
        },
        disposition,
    })
}

pub async fn supervise_resting_offer<S>(
    seller: &RunningSeller,
    chain: &dyn ChainBackend,
    cfg: &SellerConfig,
    watch: &SellerMatchWatchConfig,
    identity: &RestingOfferIdentity,
    shutdown: S,
    abort_gateway_on_stop: bool,
) -> Result<RestingSellerOutcome>
where
    S: Future<Output = ()>,
{
    let params = SellerLivenessParams::canonical();
    supervise_with_timing(
        seller,
        chain,
        cfg,
        watch,
        identity,
        shutdown,
        SupervisionTiming {
            health_interval: params.health_interval,
            health_timeout: params.health_check_timeout,
            cycle_timeout: params.health_cycle_timeout,
            cancel_poll: params.cancel_confirmation_poll,
            abort_gateway_on_stop,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seller::{Capabilities, OpenAiConfig, UpstreamConfig};
    use dexdo_core::{
        ChainError, DealBuyerBond, DealChainSnapshot, DealChainState, DealSellerBond,
        DealSubscription, LocalNote, Note, NotePubkey, OfferListing, OrderBookOrder, SellOffer,
        SellOfferOutcome, Settlement, StreamSnapshot, TokenContract,
    };
    use futures::{future::FusedFuture as _, FutureExt as _};
    use proptest::prelude::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Clone, Copy)]
    enum CancelBehavior {
        Remove,
        Reject,
        AmbiguousRemove,
        Keep,
        Hang,
    }

    struct CancelBackend {
        orders: Arc<Mutex<Vec<OrderBookOrder>>>,
        matched: Arc<Mutex<Option<Match>>>,
        calls: Mutex<Vec<(TokenContract, u128)>>,
        posts: AtomicU64,
        behavior: CancelBehavior,
        owner: String,
        posted_order_id: u128,
        hang_reads: bool,
        watch_fails: bool,
        confirm_delay: Duration,
        post_visibility_delay: Option<Duration>,
        open_delay: Duration,
        opens: AtomicU64,
    }

    impl CancelBackend {
        fn new(
            orders: Vec<OrderBookOrder>,
            owner: String,
            posted_order_id: u128,
            behavior: CancelBehavior,
        ) -> Self {
            Self {
                orders: Arc::new(Mutex::new(orders)),
                matched: Arc::new(Mutex::new(None)),
                calls: Mutex::new(Vec::new()),
                posts: AtomicU64::new(0),
                behavior,
                owner,
                posted_order_id,
                hang_reads: false,
                watch_fails: false,
                confirm_delay: Duration::ZERO,
                post_visibility_delay: None,
                open_delay: Duration::ZERO,
                opens: AtomicU64::new(0),
            }
        }

        fn with_hanging_reads(mut self) -> Self {
            self.hang_reads = true;
            self
        }

        fn with_watcher_error(mut self) -> Self {
            self.watch_fails = true;
            self
        }

        fn with_confirm_delay(mut self, delay: Duration) -> Self {
            self.confirm_delay = delay;
            self
        }

        fn with_post_visibility_delay(mut self, delay: Duration) -> Self {
            self.post_visibility_delay = Some(delay);
            self
        }

        fn with_open_delay(mut self, delay: Duration) -> Self {
            self.open_delay = delay;
            self
        }

        fn calls(&self) -> Vec<(TokenContract, u128)> {
            self.calls.lock().unwrap().clone()
        }

        fn order_ids(&self) -> Vec<u128> {
            self.orders
                .lock()
                .unwrap()
                .iter()
                .map(|order| order.order_id)
                .collect()
        }
    }

    #[async_trait::async_trait]
    impl ChainBackend for CancelBackend {
        async fn discover_offers(&self) -> Result<Vec<OfferListing>, ChainError> {
            Ok(Vec::new())
        }

        async fn post_offer(&self, offer: SellOffer, _: &dyn Note) -> Result<(), ChainError> {
            self.posts.fetch_add(1, Ordering::Relaxed);
            let posted = order(self.posted_order_id, &self.owner, &offer.token_contract);
            if let Some(delay) = self.post_visibility_delay {
                let orders = self.orders.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    orders.lock().unwrap().push(posted);
                });
                return std::future::pending().await;
            }
            self.orders.lock().unwrap().push(posted);
            Ok(())
        }

        async fn confirm_offer_outcome(
            &self,
            _: &TokenContract,
        ) -> Result<Option<SellOfferOutcome>, ChainError> {
            tokio::time::sleep(self.confirm_delay).await;
            Ok(Some(SellOfferOutcome::Rested {
                order_id: self.posted_order_id,
            }))
        }

        async fn raw_resting_sell_orders_for_tc(
            &self,
            token_contract: &TokenContract,
        ) -> Result<Vec<OrderBookOrder>, ChainError> {
            if self.hang_reads {
                return std::future::pending().await;
            }
            Ok(self
                .orders
                .lock()
                .unwrap()
                .iter()
                .filter(|order| order.token_contract.as_ref() == Some(token_contract))
                .cloned()
                .collect())
        }

        async fn cancel_resting_sell_order(
            &self,
            token_contract: &TokenContract,
            order_id: u128,
        ) -> Result<(), ChainError> {
            self.calls
                .lock()
                .unwrap()
                .push((token_contract.clone(), order_id));
            match self.behavior {
                CancelBehavior::Remove => {
                    self.orders
                        .lock()
                        .unwrap()
                        .retain(|order| order.order_id != order_id);
                    Ok(())
                }
                CancelBehavior::Reject => Err(ChainError::Chain(
                    "cancel rejected by owner check".to_string(),
                )),
                CancelBehavior::AmbiguousRemove => {
                    self.orders
                        .lock()
                        .unwrap()
                        .retain(|order| order.order_id != order_id);
                    Err(ChainError::Transport(
                        "response lost after submit".to_string(),
                    ))
                }
                CancelBehavior::Keep => Ok(()),
                CancelBehavior::Hang => std::future::pending().await,
            }
        }

        async fn poll_seller_fills(
            &self,
            _: &dyn Note,
            _: &mut dexdo_core::MatchWatchCursor,
        ) -> Result<Vec<dexdo_core::MatchedFill>, ChainError> {
            if self.watch_fails {
                return Err(ChainError::Chain(
                    "authoritative match watcher failed".to_string(),
                ));
            }
            Ok(Vec::new())
        }

        async fn read_openable_match_now(
            &self,
            _: &TokenContract,
        ) -> Result<Option<Match>, ChainError> {
            Ok(self.matched.lock().unwrap().clone())
        }

        async fn place_buy(&self, _: &TokenContract, _: &dyn Note) -> Result<(), ChainError> {
            unimplemented!()
        }

        async fn read_match(&self, token_contract: &TokenContract) -> Result<Match, ChainError> {
            self.matched
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| ChainError::NoMatch(token_contract.clone()))
        }

        async fn open_stream(
            &self,
            _: &TokenContract,
            _: Vec<u8>,
            _: &dyn Note,
        ) -> Result<(), ChainError> {
            tokio::time::sleep(self.open_delay).await;
            self.opens.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn read_handover(&self, _: &TokenContract) -> Result<Option<Vec<u8>>, ChainError> {
            Ok(None)
        }

        async fn claim_tokens(
            &self,
            _: &TokenContract,
            _: &dyn Note,
            _: u128,
        ) -> Result<(), ChainError> {
            unimplemented!()
        }

        async fn accept_probe(&self, _: &TokenContract) -> Result<(), ChainError> {
            unimplemented!()
        }

        async fn stop(&self, _: &TokenContract, _: &dyn Note) -> Result<Settlement, ChainError> {
            unimplemented!()
        }

        async fn deal_state(
            &self,
            _: &TokenContract,
        ) -> Result<Option<DealChainState>, ChainError> {
            Ok(Some(DealChainState {
                funded: self.matched.lock().unwrap().is_some(),
                opened: false,
                probe_accepted: false,
                disputed: false,
                deposit: 0,
                finalized_owed: 0,
                tokens_final: 0,
                tokens_superseded: 0,
                tokens_pending: 0,
                probe_tick: 0,
                funded_time: None,
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
            if self.matched.lock().unwrap().is_none() {
                return Ok(None);
            }
            let funded_tokens = 8 * dexdo_core::TICK_SIZE;
            Ok(Some(DealChainSnapshot {
                account_code_hash: "test-code".to_string(),
                account_boc_hash: "test-boc".to_string(),
                state: DealChainState {
                    funded: true,
                    opened: false,
                    probe_accepted: false,
                    disputed: false,
                    deposit: 1_000,
                    finalized_owed: 0,
                    tokens_final: 0,
                    tokens_superseded: 0,
                    tokens_pending: 0,
                    probe_tick: 0,
                    funded_time: Some(1),
                    probe_time: 0,
                    prev_claim_time: 0,
                    last_claim_time: 0,
                    dispute_time: 0,
                },
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
                    bond_held: 1,
                    bond_required: 1,
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

    fn address(digit: char) -> String {
        format!("0:{}", digit.to_string().repeat(64))
    }

    fn cfg(token_contract: &str) -> SellerConfig {
        SellerConfig {
            token_contract: token_contract.to_string(),
            price_per_tick: 1000,
            max_ticks: 8,
            subscription: false,
            gateway_advertise: "127.0.0.1:0".to_string(),
            mock_token_count: 8,
        }
    }

    fn cfg_for_seller(token_contract: &str, seller: &RunningSeller) -> SellerConfig {
        let mut config = cfg(token_contract);
        config.gateway_advertise = seller.listen_addr.to_string();
        config
    }

    fn identity(owner: &str, token_contract: &str, order_id: u128) -> RestingOfferIdentity {
        RestingOfferIdentity {
            owner_note: owner.to_string(),
            token_contract: token_contract.to_string(),
            order_id,
        }
    }

    fn order(order_id: u128, owner: &str, token_contract: &str) -> OrderBookOrder {
        OrderBookOrder {
            order_id,
            owner_note: owner.to_string(),
            token_contract: Some(token_contract.to_string()),
            is_buy: false,
            price_per_tick: 1000,
            ticks: 8,
            escrow: 0,
            deadline: 0,
            flags: 0,
            timestamp: 1,
        }
    }

    fn sample_match(token_contract: &str) -> Match {
        Match {
            token_contract: token_contract.to_string(),
            buyer_pubkey: NotePubkey {
                x: [7; 32],
                ed: [8; 32],
            },
            price_per_tick: 1000,
        }
    }

    fn openai(base_url: String) -> UpstreamConfig {
        UpstreamConfig::OpenAi(OpenAiConfig {
            base_url,
            model: "exact-model".to_string(),
            frame_model: "vendor--exact--v1".to_string(),
            claimed_model_override: None,
            api_key_env: "PATH".to_string(),
            tokenizer_family: "exact".to_string(),
            capabilities: Capabilities {
                logprobs: true,
                top_logprobs: None,
                max_output_tokens: Some(1024),
            },
        })
    }

    async fn http_server(
        status: &'static str,
        body: String,
        delay: Duration,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 8192];
            let _ = socket.read(&mut request).await;
            tokio::time::sleep(delay).await;
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        });
        (format!("http://{addr}"), task)
    }

    fn healthy_sse() -> String {
        "data: {\"choices\":[{\"delta\":{\"content\":\"OK\"},\"logprobs\":{\"content\":[{\"token\":\"OK\",\"logprob\":-0.1,\"top_logprobs\":[]}]}}]}\n\ndata: [DONE]\n\n".to_string()
    }

    fn watch(name: &str) -> SellerMatchWatchConfig {
        SellerMatchWatchConfig {
            cursor_path: std::env::temp_dir().join(format!(
                "dexdo-668-{name}-{}-{}.json",
                std::process::id(),
                unix_timestamp()
            )),
            poll_interval: Duration::from_millis(50),
        }
    }

    fn fast_timing() -> SupervisionTiming {
        SupervisionTiming {
            health_interval: Duration::from_millis(5),
            health_timeout: Duration::from_millis(500),
            cycle_timeout: Duration::from_millis(600),
            cancel_poll: Duration::from_millis(1),
            abort_gateway_on_stop: true,
        }
    }

    #[tokio::test]
    async fn unreachable_advertised_gateway_fails_before_any_sell_post() {
        let unavailable = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let seller = super::super::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            UpstreamConfig::Mock,
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();
        let backend = CancelBackend::new(Vec::new(), address('a'), 1, CancelBehavior::Remove);

        let failure = check_readiness(
            &seller,
            &unavailable.to_string(),
            Duration::from_millis(100),
            None,
            &address('b'),
        )
        .await
        .expect_err("unreachable advertised endpoint");

        assert_eq!(failure.component, HealthComponent::AdvertisedGateway);
        assert_eq!(backend.posts.load(Ordering::Relaxed), 0);
        seller.server_task.abort();
    }

    #[tokio::test]
    async fn upstream_unreachable_rejected_missing_model_and_timeout_fail_closed() {
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let cases = [
            (format!("http://{dead}"), None, Duration::from_secs(1)),
            (
                http_server(
                    "401 Unauthorized",
                    "{\"error\":{\"message\":\"bad credential\"}}".to_string(),
                    Duration::ZERO,
                )
                .await
                .0,
                None,
                Duration::from_secs(1),
            ),
            (
                http_server(
                    "404 Not Found",
                    "{\"error\":{\"message\":\"model absent\"}}".to_string(),
                    Duration::ZERO,
                )
                .await
                .0,
                None,
                Duration::from_secs(1),
            ),
            (
                http_server("200 OK", healthy_sse(), Duration::from_millis(500))
                    .await
                    .0,
                Some(true),
                Duration::from_millis(100),
            ),
        ];

        for (base_url, expect_timeout, timeout) in cases {
            let seller = super::super::start_gateway_with_note(
                "127.0.0.1:0".parse().unwrap(),
                openai(base_url),
                Arc::new(LocalNote::generate()),
            )
            .await
            .unwrap();
            let failure = check_readiness(
                &seller,
                &seller.listen_addr.to_string(),
                timeout,
                None,
                &address('c'),
            )
            .await
            .expect_err("bad upstream must fail readiness");
            assert_eq!(failure.component, HealthComponent::UpstreamModel);
            if expect_timeout.is_some() {
                assert!(failure.timed_out);
            }
            seller.server_task.abort();
        }
    }

    #[tokio::test]
    async fn repeated_health_cycles_leave_no_health_nonces_on_success_or_failure() {
        const BUYER_TC: &str = "0:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let healthy = super::super::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            UpstreamConfig::Mock,
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();
        let buyer = LocalNote::generate();
        let buyer_nonces = [b"buyer-a".as_slice(), b"buyer-b".as_slice()];
        healthy.state.auth.register(BUYER_TC, buyer.pubkey());
        for nonce in buyer_nonces {
            healthy.state.auth.issue_challenge(BUYER_TC, nonce.to_vec());
        }

        for _ in 0..3 {
            check_readiness(
                &healthy,
                &healthy.listen_addr.to_string(),
                Duration::from_secs(1),
                None,
                BUYER_TC,
            )
            .await
            .expect("healthy cycle");
            assert_eq!(
                healthy
                    .state
                    .auth
                    .outstanding_challenge_count(HEALTH_CHALLENGE_TC),
                0,
                "health challenge is discarded after every successful cycle"
            );
            assert_eq!(
                healthy.state.auth.outstanding_challenge_count(BUYER_TC),
                2,
                "health cleanup must not consume concurrent buyer challenges"
            );
        }

        for nonce in buyer_nonces {
            let signature = buyer.sign(&crate::seller::auth::challenge_bytes(BUYER_TC, nonce));
            assert!(
                healthy
                    .state
                    .auth
                    .verify_response(BUYER_TC, nonce, &signature),
                "ordinary buyer challenges retain consume-on-success semantics"
            );
        }
        assert_eq!(healthy.state.auth.outstanding_challenge_count(BUYER_TC), 0);
        healthy.server_task.abort();

        let (base_url, upstream_server) = http_server(
            "401 Unauthorized",
            "{\"error\":{\"message\":\"bad credential\"}}".to_string(),
            Duration::ZERO,
        )
        .await;
        let failing = super::super::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            openai(base_url),
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();
        let failure = check_readiness(
            &failing,
            &failing.listen_addr.to_string(),
            Duration::from_secs(1),
            None,
            BUYER_TC,
        )
        .await
        .expect_err("upstream rejection fails the health cycle");
        assert_eq!(failure.component, HealthComponent::UpstreamModel);
        assert_eq!(
            failing
                .state
                .auth
                .outstanding_challenge_count(HEALTH_CHALLENGE_TC),
            0,
            "health challenge is discarded before a later component fails"
        );
        failing.server_task.abort();
        upstream_server.await.unwrap();
    }

    #[tokio::test]
    async fn healthy_readiness_precedes_exactly_one_sell_post() {
        let seller = super::super::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            UpstreamConfig::Mock,
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();
        let owner = address('d');
        let tc = address('e');
        let backend = CancelBackend::new(Vec::new(), owner.clone(), 91, CancelBehavior::Remove);
        let config = cfg(&tc);

        check_readiness(
            &seller,
            &seller.listen_addr.to_string(),
            Duration::from_secs(1),
            None,
            &tc,
        )
        .await
        .expect("gateway and mock upstream are ready");
        let startup = super::super::prepare_seller_offer(
            seller.note.as_ref(),
            &backend,
            &config,
            Some(&owner),
        )
        .await
        .unwrap();

        assert_eq!(backend.posts.load(Ordering::Relaxed), 1);
        assert_eq!(
            startup,
            super::super::SellerOfferStartup::Posted {
                outcome: Some(SellOfferOutcome::Rested { order_id: 91 })
            }
        );
        seller.server_task.abort();
    }

    #[tokio::test]
    async fn delayed_fresh_resting_confirmation_rechecks_health_before_ready() {
        let (base_url, upstream_server) =
            http_server("200 OK", healthy_sse(), Duration::ZERO).await;
        let owner = address('d');
        let tc = address('e');
        let order_id = 90;
        let backend =
            CancelBackend::new(Vec::new(), owner.clone(), order_id, CancelBehavior::Remove)
                .with_confirm_delay(Duration::from_millis(40));
        let seller = super::super::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            openai(base_url),
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();

        let outcome = prepare_seller_offer_with_timing(
            &seller,
            &backend,
            &cfg_for_seller(&tc, &seller),
            &owner,
            None,
            std::future::pending(),
            SupervisionTiming {
                health_interval: Duration::from_millis(5),
                health_timeout: Duration::from_millis(100),
                cycle_timeout: Duration::from_millis(300),
                cancel_poll: Duration::from_millis(1),
                abort_gateway_on_stop: true,
            },
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            SellerStartupOutcome::Stopped {
                identity: Some(RestingOfferIdentity { order_id: 90, .. }),
                reason: RestingStopReason::Health(HealthFailure {
                    component: HealthComponent::UpstreamModel,
                    ..
                }),
                disposition: CancellationDisposition::Cancelled,
            }
        ));
        assert_eq!(backend.posts.load(Ordering::Relaxed), 1);
        assert_eq!(backend.calls(), vec![(tc, order_id)]);
        assert!(backend.order_ids().is_empty());
        upstream_server.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_during_sell_confirmation_cancels_the_new_exact_order() {
        let owner = address('d');
        let tc = address('e');
        let order_id = 92;
        let backend =
            CancelBackend::new(Vec::new(), owner.clone(), order_id, CancelBehavior::Remove)
                .with_confirm_delay(Duration::from_millis(40));
        let seller = super::super::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            UpstreamConfig::Mock,
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();

        let outcome = prepare_seller_offer_with_timing(
            &seller,
            &backend,
            &cfg_for_seller(&tc, &seller),
            &owner,
            None,
            async {
                while backend.posts.load(Ordering::Relaxed) == 0 {
                    tokio::task::yield_now().await;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            },
            SupervisionTiming {
                health_interval: Duration::from_millis(5),
                health_timeout: Duration::from_secs(1),
                cycle_timeout: Duration::from_secs(2),
                cancel_poll: Duration::from_millis(1),
                abort_gateway_on_stop: true,
            },
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            SellerStartupOutcome::Stopped {
                identity: Some(RestingOfferIdentity { order_id: 92, .. }),
                reason: RestingStopReason::Shutdown,
                disposition: CancellationDisposition::Cancelled,
            }
        ));
        assert_eq!(backend.posts.load(Ordering::Relaxed), 1);
        assert_eq!(backend.calls(), vec![(tc, order_id)]);
        assert!(backend.order_ids().is_empty());
    }

    #[tokio::test]
    async fn gateway_death_during_sell_confirmation_cancels_the_new_exact_order() {
        let owner = address('d');
        let tc = address('f');
        let order_id = 93;
        let backend = Arc::new(
            CancelBackend::new(Vec::new(), owner.clone(), order_id, CancelBehavior::Remove)
                .with_confirm_delay(Duration::from_millis(200)),
        );
        let seller = super::super::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            UpstreamConfig::Mock,
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();
        let abort = seller.server_task.abort_handle();
        let abort_after_post = backend.clone();
        tokio::spawn(async move {
            while abort_after_post.posts.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
            abort.abort();
        });

        let outcome = prepare_seller_offer_with_timing(
            &seller,
            backend.as_ref(),
            &cfg_for_seller(&tc, &seller),
            &owner,
            None,
            std::future::pending(),
            SupervisionTiming {
                health_interval: Duration::from_millis(5),
                health_timeout: Duration::from_secs(1),
                cycle_timeout: Duration::from_secs(2),
                cancel_poll: Duration::from_millis(1),
                abort_gateway_on_stop: true,
            },
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            SellerStartupOutcome::Stopped {
                identity: Some(RestingOfferIdentity { order_id: 93, .. }),
                reason: RestingStopReason::Health(HealthFailure {
                    component: HealthComponent::GatewayTask,
                    ..
                }),
                disposition: CancellationDisposition::Cancelled,
            }
        ));
        assert_eq!(backend.posts.load(Ordering::Relaxed), 1);
        assert_eq!(backend.calls(), vec![(tc, order_id)]);
        assert!(backend.order_ids().is_empty());
    }

    #[tokio::test]
    async fn interrupted_fresh_post_cancels_after_delayed_authoritative_visibility() {
        let owner = address('d');
        let tc = address('9');
        let order_id = 94;
        let backend =
            CancelBackend::new(Vec::new(), owner.clone(), order_id, CancelBehavior::Remove)
                .with_post_visibility_delay(Duration::from_millis(150));
        let seller = super::super::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            UpstreamConfig::Mock,
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();

        let outcome = prepare_seller_offer_with_timing(
            &seller,
            &backend,
            &cfg_for_seller(&tc, &seller),
            &owner,
            None,
            async {
                while backend.posts.load(Ordering::Relaxed) == 0 {
                    tokio::task::yield_now().await;
                }
            },
            SupervisionTiming {
                health_interval: Duration::from_millis(5),
                health_timeout: Duration::from_millis(100),
                cycle_timeout: Duration::from_millis(300),
                cancel_poll: Duration::from_millis(1),
                abort_gateway_on_stop: true,
            },
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            SellerStartupOutcome::Stopped {
                identity: Some(RestingOfferIdentity { order_id: 94, .. }),
                reason: RestingStopReason::Shutdown,
                disposition: CancellationDisposition::Cancelled,
            }
        ));
        assert_eq!(backend.posts.load(Ordering::Relaxed), 1);
        assert_eq!(backend.calls(), vec![(tc, order_id)]);
        assert!(backend.order_ids().is_empty());
    }

    #[tokio::test]
    async fn interrupted_fresh_post_without_terminal_fact_is_unknown_not_absent() {
        let owner = address('d');
        let tc = address('a');
        let backend = CancelBackend::new(Vec::new(), owner.clone(), 95, CancelBehavior::Remove)
            .with_post_visibility_delay(Duration::from_secs(1));
        let seller = super::super::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            UpstreamConfig::Mock,
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();

        let outcome = prepare_seller_offer_with_timing(
            &seller,
            &backend,
            &cfg_for_seller(&tc, &seller),
            &owner,
            None,
            async {
                while backend.posts.load(Ordering::Relaxed) == 0 {
                    tokio::task::yield_now().await;
                }
            },
            SupervisionTiming {
                health_interval: Duration::from_millis(5),
                health_timeout: Duration::from_millis(100),
                cycle_timeout: Duration::from_millis(150),
                cancel_poll: Duration::from_millis(1),
                abort_gateway_on_stop: true,
            },
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            SellerStartupOutcome::Stopped {
                identity: None,
                reason: RestingStopReason::Shutdown,
                disposition: CancellationDisposition::UnknownFailure { ref known_result },
            } if known_result.contains("authoritative_state=vacant")
        ));
        assert!(
            !seller.server_task.is_finished(),
            "unknown fresh-post outcome must not explicitly kill the gateway"
        );
        seller.server_task.abort();
    }

    #[tokio::test]
    async fn gateway_task_death_cancels_within_one_health_cycle() {
        let owner = address('1');
        let tc = address('2');
        let id = identity(&owner, &tc, 101);
        let backend = CancelBackend::new(
            vec![order(id.order_id, &owner, &tc)],
            owner,
            id.order_id,
            CancelBehavior::Remove,
        );
        let seller = super::super::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            UpstreamConfig::Mock,
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();
        seller.server_task.abort();
        tokio::task::yield_now().await;

        let outcome = supervise_with_timing(
            &seller,
            &backend,
            &cfg_for_seller(&tc, &seller),
            &watch("gateway-death"),
            &id,
            std::future::pending(),
            fast_timing(),
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            RestingSellerOutcome::Stopped {
                reason: RestingStopReason::Health(HealthFailure {
                    component: HealthComponent::GatewayTask,
                    ..
                }),
                disposition: CancellationDisposition::Cancelled,
            }
        ));
        assert_eq!(backend.calls(), vec![(tc, id.order_id)]);
    }

    #[tokio::test]
    async fn health_check_and_cancel_share_one_cycle_deadline() {
        let owner = address('1');
        let tc = address('3');
        let id = identity(&owner, &tc, 111);
        let backend = CancelBackend::new(
            vec![order(id.order_id, &owner, &tc)],
            owner,
            id.order_id,
            CancelBehavior::Hang,
        );
        let seller = super::super::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            UpstreamConfig::Mock,
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();
        seller.server_task.abort();
        tokio::task::yield_now().await;
        let started = tokio::time::Instant::now();

        let outcome = supervise_with_timing(
            &seller,
            &backend,
            &cfg_for_seller(&tc, &seller),
            &watch("shared-deadline"),
            &id,
            std::future::pending(),
            SupervisionTiming {
                health_interval: Duration::from_millis(5),
                health_timeout: Duration::from_millis(10),
                cycle_timeout: Duration::from_millis(30),
                cancel_poll: Duration::from_millis(1),
                abort_gateway_on_stop: true,
            },
        )
        .await
        .unwrap();

        assert!(started.elapsed() < Duration::from_millis(80));
        let known_result = match outcome {
            RestingSellerOutcome::Stopped {
                reason:
                    RestingStopReason::Health(HealthFailure {
                        component: HealthComponent::GatewayTask,
                        ..
                    }),
                disposition: CancellationDisposition::UnknownFailure { known_result },
            } => known_result,
            other => panic!("expected structured unknown_failure, got {other:?}"),
        };
        assert!(known_result.contains("budget_ms=30"));
        assert!(known_result.contains("cancel 111"));
        assert!(!known_result.contains("--order-id"));
    }

    #[tokio::test]
    async fn upstream_failure_while_resting_triggers_the_same_exact_cancel() {
        let (base_url, server) = http_server(
            "401 Unauthorized",
            "{\"error\":{\"message\":\"credential rejected\"}}".to_string(),
            Duration::ZERO,
        )
        .await;
        let owner = address('3');
        let tc = address('4');
        let id = identity(&owner, &tc, 102);
        let backend = CancelBackend::new(
            vec![order(id.order_id, &owner, &tc)],
            owner,
            id.order_id,
            CancelBehavior::Remove,
        );
        let seller = super::super::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            openai(base_url),
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();

        let outcome = supervise_with_timing(
            &seller,
            &backend,
            &cfg_for_seller(&tc, &seller),
            &watch("upstream-failure"),
            &id,
            std::future::pending(),
            fast_timing(),
        )
        .await
        .unwrap();

        assert!(
            matches!(
                &outcome,
                RestingSellerOutcome::Stopped {
                    reason: RestingStopReason::Health(HealthFailure {
                        component: HealthComponent::UpstreamModel,
                        ..
                    }),
                    disposition: CancellationDisposition::Cancelled,
                }
            ),
            "unexpected outcome: {outcome:?}"
        );
        assert_eq!(backend.calls(), vec![(tc, id.order_id)]);
        server.abort();
    }

    #[tokio::test]
    async fn failed_restart_readiness_cancels_existing_resting_sell_without_post() {
        let (base_url, upstream_server) = http_server(
            "401 Unauthorized",
            "{\"error\":{\"message\":\"credential rejected\"}}".to_string(),
            Duration::ZERO,
        )
        .await;
        let owner = address('e');
        let tc = address('f');
        let id = identity(&owner, &tc, 107);
        let backend = CancelBackend::new(
            vec![order(id.order_id, &owner, &tc)],
            owner,
            id.order_id,
            CancelBehavior::Remove,
        );
        let seller = super::super::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            openai(base_url),
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();

        let failure = check_readiness(
            &seller,
            &seller.listen_addr.to_string(),
            Duration::from_secs(1),
            Some(&id),
            &tc,
        )
        .await
        .expect_err("restart readiness must fail");
        assert_eq!(failure.component, HealthComponent::UpstreamModel);
        let disposition = cancel_and_confirm_with_timing(
            &backend,
            &cfg(&tc),
            &id,
            Duration::from_millis(20),
            Duration::from_millis(1),
        )
        .await;

        assert!(matches!(disposition, CancellationDisposition::Cancelled));
        assert_eq!(backend.posts.load(Ordering::Relaxed), 0);
        assert!(backend.order_ids().is_empty());
        seller.server_task.abort();
        upstream_server.abort();
    }

    #[tokio::test]
    async fn graceful_shutdown_confirms_cancel_before_return() {
        let owner = address('5');
        let tc = address('6');
        let id = identity(&owner, &tc, 103);
        let backend = CancelBackend::new(
            vec![order(id.order_id, &owner, &tc)],
            owner,
            id.order_id,
            CancelBehavior::Remove,
        );
        let seller = super::super::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            UpstreamConfig::Mock,
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();

        let outcome = supervise_with_timing(
            &seller,
            &backend,
            &cfg_for_seller(&tc, &seller),
            &watch("shutdown"),
            &id,
            std::future::ready(()),
            fast_timing(),
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            RestingSellerOutcome::Stopped {
                reason: RestingStopReason::Shutdown,
                disposition: CancellationDisposition::Cancelled,
            }
        ));
        assert!(backend.order_ids().is_empty());
        tokio::task::yield_now().await;
        assert!(seller.server_task.is_finished());
    }

    #[tokio::test]
    async fn watcher_error_cancels_exact_resting_offer_before_return() {
        let owner = address('5');
        let tc = address('7');
        let id = identity(&owner, &tc, 108);
        let backend = CancelBackend::new(
            vec![order(id.order_id, &owner, &tc)],
            owner,
            id.order_id,
            CancelBehavior::Remove,
        )
        .with_watcher_error();
        let seller = super::super::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            UpstreamConfig::Mock,
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();

        let outcome = supervise_with_timing(
            &seller,
            &backend,
            &cfg_for_seller(&tc, &seller),
            &watch("watcher-error"),
            &id,
            std::future::pending(),
            fast_timing(),
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            RestingSellerOutcome::Stopped {
                reason: RestingStopReason::Watcher(ref error),
                disposition: CancellationDisposition::Cancelled,
            } if error.contains("authoritative match watcher failed")
        ));
        assert_eq!(backend.calls(), vec![(tc, id.order_id)]);
        assert!(backend.order_ids().is_empty());
        tokio::task::yield_now().await;
        assert!(seller.server_task.is_finished());
    }

    #[tokio::test]
    async fn shutdown_match_race_waits_for_delayed_tc_visibility_and_preserves_control() {
        let owner = address('7');
        let tc = address('8');
        let target = identity(&owner, &tc, 104);
        let other_tc = address('9');
        let backend = CancelBackend::new(
            vec![
                order(target.order_id, &owner, &tc),
                order(999, &owner, &other_tc),
            ],
            owner,
            target.order_id,
            CancelBehavior::Remove,
        )
        .with_open_delay(Duration::from_millis(5));
        backend
            .orders
            .lock()
            .unwrap()
            .retain(|order| order.order_id != target.order_id);
        let matched = backend.matched.clone();
        let matched_tc = tc.clone();
        let visibility = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            matched.lock().unwrap().replace(sample_match(&matched_tc));
        });
        let seller = super::super::start_gateway_with_note(
            "127.0.0.1:0".parse().unwrap(),
            UpstreamConfig::Mock,
            Arc::new(LocalNote::generate()),
        )
        .await
        .unwrap();
        let shutdown = std::future::ready(()).fuse();
        tokio::pin!(shutdown);
        let watch = watch("match-cancel-race");
        let cfg = cfg_for_seller(&tc, &seller);

        let outcome = supervise_with_timing(
            &seller,
            &backend,
            &cfg,
            &watch,
            &target,
            shutdown.as_mut(),
            fast_timing(),
        )
        .await
        .unwrap();

        let matched = match outcome {
            RestingSellerOutcome::Matched(matched) => matched,
            stopped => panic!("expected match, got {stopped:?}"),
        };
        assert_eq!(matched.token_contract, tc);
        super::super::serve_watched_match(&seller, &backend, &cfg, &watch, matched)
            .await
            .unwrap();
        assert_eq!(backend.opens.load(Ordering::Relaxed), 1);
        assert!(
            shutdown.is_terminated(),
            "the initiating shutdown must remain observable after handover"
        );
        assert!(backend.calls().is_empty());
        assert_eq!(backend.order_ids(), vec![999]);
        assert!(!seller.server_task.is_finished());
        visibility.await.unwrap();
        seller.server_task.abort();
    }

    #[tokio::test]
    async fn rejected_or_unconfirmed_cancel_never_reports_success() {
        for (behavior, expected_result) in [
            (CancelBehavior::Reject, "cancel rejected by owner check"),
            (CancelBehavior::Keep, "cancel_submit=accepted"),
        ] {
            let owner = address('a');
            let tc = address('b');
            let id = identity(&owner, &tc, 105);
            let backend = CancelBackend::new(
                vec![order(id.order_id, &owner, &tc)],
                owner.clone(),
                id.order_id,
                behavior,
            );

            let disposition = cancel_and_confirm_with_timing(
                &backend,
                &cfg(&tc),
                &id,
                Duration::from_millis(5),
                Duration::from_millis(1),
            )
            .await;
            let known_result = match disposition {
                CancellationDisposition::UnknownFailure { known_result } => known_result,
                other => panic!("present order cannot be reported terminal: {other:?}"),
            };

            assert!(known_result.contains(expected_result));
            assert!(known_result.contains("authoritative_state=present"));
            assert!(known_result.contains("operator_action="));
            assert!(known_result.contains("cancel 105"));
            assert!(!known_result.contains("--order-id"));
            assert_eq!(backend.order_ids(), vec![id.order_id]);
        }
    }

    #[tokio::test]
    async fn cancellation_deadline_bounds_initial_read_and_submit() {
        for (hang_reads, behavior) in [
            (true, CancelBehavior::Remove),
            (false, CancelBehavior::Hang),
        ] {
            let owner = address('a');
            let tc = address('c');
            let id = identity(&owner, &tc, 110);
            let mut backend = CancelBackend::new(
                vec![order(id.order_id, &owner, &tc)],
                owner,
                id.order_id,
                behavior,
            );
            if hang_reads {
                backend = backend.with_hanging_reads();
            }

            let disposition = tokio::time::timeout(
                Duration::from_millis(200),
                cancel_and_confirm_with_timing(
                    &backend,
                    &cfg(&tc),
                    &id,
                    Duration::from_millis(20),
                    Duration::from_millis(1),
                ),
            )
            .await
            .expect("production cancellation must honor its own hard deadline");
            let known_result = match disposition {
                CancellationDisposition::UnknownFailure { known_result } => known_result,
                other => panic!("a hung cancellation cannot report success: {other:?}"),
            };

            assert!(known_result.contains("budget_ms=20"));
            assert!(known_result.contains("operator_action="));
            assert!(known_result.contains("cancel 110"));
            assert!(!known_result.contains("--order-id"));
        }
    }

    #[tokio::test]
    async fn ambiguous_submit_reconciles_by_fact_without_false_failure() {
        let owner = address('c');
        let tc = address('d');
        let id = identity(&owner, &tc, 106);
        let backend = CancelBackend::new(
            vec![order(id.order_id, &owner, &tc)],
            owner,
            id.order_id,
            CancelBehavior::AmbiguousRemove,
        );

        let disposition = cancel_and_confirm_with_timing(
            &backend,
            &cfg(&tc),
            &id,
            Duration::from_millis(20),
            Duration::from_millis(1),
        )
        .await;

        assert!(matches!(
            disposition,
            CancellationDisposition::AlreadyAbsent
        ));
    }

    #[tokio::test]
    async fn upstream_health_diagnostic_never_echoes_secret() {
        let secret = std::env::var("PATH").unwrap();
        let (base_url, server) = http_server(
            "401 Unauthorized",
            format!(
                "{{\"error\":{{\"message\":{}}}}}",
                serde_json::to_string(&secret).unwrap()
            ),
            Duration::ZERO,
        )
        .await;

        let error = openai(base_url)
            .check_health()
            .await
            .expect_err("rejected credential")
            .to_string();

        assert!(!error.contains(&secret));
        server.abort();
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn failed_health_cycle_cancels_the_captured_owner_tc_order_tuple(
            order_id in 1_u128..u128::MAX,
            owner_digit in 1_u8..=9,
            tc_digit in 10_u8..=15,
        ) {
            let owner_char = char::from_digit(u32::from(owner_digit), 16).unwrap();
            let tc_char = char::from_digit(u32::from(tc_digit), 16).unwrap();
            let owner = address(owner_char);
            let tc = address(tc_char);
            let id = identity(&owner, &tc, order_id);
            let backend = CancelBackend::new(
                vec![order(order_id, &owner, &tc)],
                owner.clone(),
                order_id,
                CancelBehavior::Remove,
            );
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            let outcome = runtime.block_on(async {
                let seller = super::super::start_gateway_with_note(
                    "127.0.0.1:0".parse().unwrap(),
                    UpstreamConfig::Mock,
                    Arc::new(LocalNote::generate()),
                )
                .await
                .unwrap();
                seller.server_task.abort();
                tokio::task::yield_now().await;
                supervise_with_timing(
                    &seller,
                    &backend,
                    &cfg_for_seller(&tc, &seller),
                    &watch(&format!("property-{order_id}")),
                    &id,
                    std::future::pending(),
                    fast_timing(),
                )
                .await
                .unwrap()
            });

            let stopped_after_health_failure = matches!(
                outcome,
                RestingSellerOutcome::Stopped {
                    reason: RestingStopReason::Health(HealthFailure {
                        component: HealthComponent::GatewayTask,
                        ..
                    }),
                    disposition: CancellationDisposition::Cancelled,
                }
            );
            prop_assert!(stopped_after_health_failure);
            prop_assert_eq!(backend.calls(), vec![(tc, order_id)]);
            prop_assert!(backend.order_ids().is_empty());
        }
    }
}
