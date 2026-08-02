//! Buyer command handlers, moved out of `commands.rs`(C15, move-only).

use crate::cli::args::*;
#[cfg(any(test, feature = "shellnet"))]
use crate::cli::commands::direct_chain_read_with_timeout;
#[cfg(feature = "shellnet")]
use crate::cli::commands::{
    acquire_pool_write_lock, load_pool_json, model_target_from_config, note_pool_path,
    registry_requested_model, resolve_order_book_target, target_from_market,
    try_acquire_pool_write_lock, with_pool_write_lock, write_pool_private, PoolWriteLock,
};
#[cfg(all(test, feature = "shellnet"))]
use crate::cli::commands::{
    close_hint, is_note_deploy_wallet_busy_error, note_deploy_error,
    note_deploy_fold_state_into_pool, note_deploy_fold_state_into_pool_locked,
    note_deploy_multisig_secret_hex, note_deploy_recovery_pool_guard,
    note_deploy_same_file_pool_guard, note_endpoint_url, persist_pool_recovery_record,
    resolve_persistable_pool_recovery_inputs, resolve_pool_recovery_inputs, retry_executable_read,
    target_from_market_for_model, write_pool_private_via_temp, DealTarget, PoolRecoveryRecord,
};
use crate::cli::commands::{
    enforce_model_registry_policy, expected_order_book_for_note,
    load_enabled_model_registry_policy, mock_orders_from_offers, note_pubkey_id,
    order_book_active_from_contracts, print_book_table, resolve_model_registry_target,
    save_mock_runtime_deal_handle, save_runtime_deal_handle, shellnet_doctor_preflight,
    unix_now_secs, BookRow, BookTarget, RuntimeDealHandleInput,
};
use crate::cli::deals;
use crate::cli::machine;
use crate::cli::policy;
#[cfg(test)]
use crate::cli::seller_policy::{
    apply_seller_dispute_policy, apply_seller_terminal_policy, classify_by_fact_advance_failure,
    is_err_not_open, AdvanceFailureDisposition, SellerTerminalPolicyOutcome,
};
use crate::cli::support::*;
use crate::operator_shutdown_signal;
use anyhow::{anyhow, bail, Result};
#[cfg(feature = "shellnet")]
use dexdo_core::params::BUYER_SUBMIT_RECONCILE_POLL_INTERVAL;
#[cfg(all(test, feature = "shellnet"))]
use dexdo_core::params::EXECUTABLE_READ_BACKOFF;
use dexdo_core::params::{
    BUYER_API_READINESS_TIMEOUT, BUYER_HANDOVER_POLL_INTERVAL,
    BUYER_REPLAY_PROTECTION_BACKOFF_STEP_SECS, BUYER_REPLAY_PROTECTION_MAX_ATTEMPTS,
    CONSUMER_DEMAND_RECENT_SECS, DEAL_WAIT_SECS, RENEWAL_FAILURE_BACKOFF_SECS,
    RESUME_LOOKBACK_SECS, TRANSIENT_QUOTE_ATTEMPTS, TRANSIENT_QUOTE_INITIAL_BACKOFF,
};
#[cfg(not(test))]
use dexdo_core::params::{BUYER_MONITOR_POLL_INTERVAL, BUYER_MONITOR_RECOVERY_BACKOFF};

/// Absolute deadline for a BUY order the client is about to place.
/// The contract permits a zero deadline as GTC. The dexdo CLI deliberately applies a stricter finite-deadline
/// policy: past the deadline anyone may expire the order permissionlessly and the escrow returns, which keeps
/// a stale bid from sitting at an untouched price level forever.
fn buy_order_deadline() -> Result<u64> {
    let now = machine::now_unix()?;
    dexdo_core::default_buy_deadline(now).ok_or_else(|| {
        anyhow!(
            "current unix time {now} plus the canonical BUY lifetime overflows u64; refusing BUY"
        )
    })
}
#[cfg(feature = "shellnet")]
use dexdo::registry::{
    default_model_registry_address, resolve_registered_model_identity, ShellnetModelRegistryReader,
};
use dexdo::registry::{BuyerMissingBookPolicy, RegistryRole};
#[cfg(feature = "shellnet")]
use dexdo_core::{
    check_buy_deposit_headroom, subscription_buy_clearing_refund, DealBuyerBond, DealSellerBond,
    DealSubscription, InferenceSubscriptionPlacement, MatchWatchCursor, MatchedFill,
    OrderBookSnapshot, SHELL_ECC_ID, SUBSCRIPTION_ORDER_RECONCILE_POLL, TICK_SIZE,
};
use dexdo_core::{
    check_matched_token_contract_state, check_subscription_buy_reserve, executable_quote,
    model_hash_for, order_flags as flags, required_escrow_for_buy, submit_safe_single_ask_quote,
    subscription_buy_reserve, ChainBackend, ChainError, DealChainState, ExecutableQuote,
    MatchedTokenContractStatus, OrderBookOrder, Settlement, SubscriptionBuyReserve,
    MATCH_OPEN_TIMEOUT_SECS, SUBSCRIPTION_MAX_TICKS, SUBSCRIPTION_WEEKS,
};
use serde_json::{json, Map, Value};
use std::sync::Arc;

#[cfg(feature = "shellnet")]
#[allow(dead_code)]
struct BuyerMoneyLock {
    note_addr: String,
    path: std::path::PathBuf,
    journal_path: std::path::PathBuf,
    subscriptions_path: std::path::PathBuf,
    lock: Option<PoolWriteLock>,
}
#[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "shellnet", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "shellnet", serde(rename_all = "snake_case"))]
enum BuyerSubmitIntentKind {
    LegacyUnknown,
    Foreground,
    OnDemand,
    PolicyNextSeller,
    ContinuityNextSeller,
    ContinuityRenewal,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "shellnet", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "shellnet", serde(deny_unknown_fields))]
struct BuyerSubmitIntent {
    kind: BuyerSubmitIntentKind,
    predecessor_token_contract: Option<dexdo_core::TokenContract>,
}

#[allow(dead_code)]
impl BuyerSubmitIntent {
    fn foreground() -> Self {
        Self {
            kind: BuyerSubmitIntentKind::Foreground,
            predecessor_token_contract: None,
        }
    }

    fn on_demand() -> Self {
        Self {
            kind: BuyerSubmitIntentKind::OnDemand,
            predecessor_token_contract: None,
        }
    }

    fn after(kind: BuyerSubmitIntentKind, predecessor: &str) -> Self {
        Self {
            kind,
            predecessor_token_contract: Some(predecessor.to_string()),
        }
    }

    #[cfg(feature = "shellnet")]
    fn validate(&self) -> Result<()> {
        let requires_predecessor = matches!(
            self.kind,
            BuyerSubmitIntentKind::PolicyNextSeller
                | BuyerSubmitIntentKind::ContinuityNextSeller
                | BuyerSubmitIntentKind::ContinuityRenewal
        );
        if requires_predecessor != self.predecessor_token_contract.is_some() {
            bail!(
                "buyer submit intent {:?} has invalid predecessor presence",
                self.kind
            );
        }
        if let Some(predecessor) = &self.predecessor_token_contract {
            dexdo_core::Address::parse(predecessor).map_err(|error| {
                anyhow::anyhow!("buyer submit predecessor TokenContract: {error}")
            })?;
        }
        Ok(())
    }
}

#[cfg(feature = "shellnet")]
const BUYER_SUBMIT_JOURNAL_SCHEMA: &str = "dexdo.buyer.submit.v2";
#[cfg(feature = "shellnet")]
const BUYER_SUBMIT_JOURNAL_SCHEMA_V1: &str = "dexdo.buyer.submit.v1";
#[cfg(feature = "shellnet")]
const BUYER_SUBSCRIPTION_SUBMIT_SCHEMA: &str = "dexdo.buyer.subscription.submit.v2";
#[cfg(feature = "shellnet")]
const BUYER_SUBSCRIPTION_STATE_SCHEMA: &str = "dexdo.buyer.subscriptions.v3";
#[cfg(feature = "shellnet")]
const LEGACY_BUYER_SUBSCRIPTION_SUBMIT_SCHEMA: &str = "dexdo.buyer.subscription.submit.v1";
#[cfg(feature = "shellnet")]
const LEGACY_BUYER_SUBSCRIPTION_STATE_SCHEMA: &str = "dexdo.buyer.subscriptions.v1";
#[cfg(feature = "shellnet")]
const LEGACY_BUYER_SUBSCRIPTION_STATE_SCHEMA_V2: &str = "dexdo.buyer.subscriptions.v2";
/// Journal-only representation of an owner-facing fill. The chain event decoder
/// that produces these records is intentionally wired in a later layer.
#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BuyerJournalMatch {
    token_contract: dexdo_core::TokenContract,
    order_id: u128,
    ticks: u128,
    clearing_price: u128,
}

#[cfg(feature = "shellnet")]
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BuyerSubmitJournal {
    schema: String,
    note_addr: String,
    order_book: String,
    intent: BuyerSubmitIntent,
    expected_token_contract: Option<dexdo_core::TokenContract>,
    quoted_order: OrderBookOrder,
    quote: ExecutableQuote,
    cursor: dexdo_core::MatchWatchCursor,
    ticks: u128,
    max_price_per_tick: u128,
    escrow: u128,
    submit_identity: String,
    created_at_unix: u64,
    #[serde(default)]
    resolved_match: Option<BuyerJournalMatch>,
    #[serde(default)]
    resolved_matches: Vec<BuyerJournalMatch>,
}

#[cfg(feature = "shellnet")]
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BuyerSubmitJournalV1 {
    schema: String,
    note_addr: String,
    order_book: String,
    expected_token_contract: Option<dexdo_core::TokenContract>,
    quoted_order: OrderBookOrder,
    quote: ExecutableQuote,
    cursor: dexdo_core::MatchWatchCursor,
    ticks: u128,
    max_price_per_tick: u128,
    escrow: u128,
    submit_identity: String,
    created_at_unix: u64,
    #[serde(default)]
    resolved_match: Option<BuyerJournalMatch>,
}

#[cfg(feature = "shellnet")]
impl From<BuyerSubmitJournalV1> for BuyerSubmitJournal {
    fn from(legacy: BuyerSubmitJournalV1) -> Self {
        let resolved_matches = legacy.resolved_match.clone().into_iter().collect();
        Self {
            schema: BUYER_SUBMIT_JOURNAL_SCHEMA.to_string(),
            note_addr: legacy.note_addr,
            order_book: legacy.order_book,
            intent: BuyerSubmitIntent {
                kind: BuyerSubmitIntentKind::LegacyUnknown,
                predecessor_token_contract: None,
            },
            expected_token_contract: legacy.expected_token_contract,
            quoted_order: legacy.quoted_order,
            quote: legacy.quote,
            cursor: legacy.cursor,
            ticks: legacy.ticks,
            max_price_per_tick: legacy.max_price_per_tick,
            escrow: legacy.escrow,
            submit_identity: legacy.submit_identity,
            created_at_unix: legacy.created_at_unix,
            resolved_match: legacy.resolved_match,
            resolved_matches,
        }
    }
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BuyerSubscriptionSubmitJournal {
    schema: String,
    note_addr: String,
    order_book: String,
    frame_model: String,
    model_hash: String,
    max_price_per_tick: u128,
    ticks: u128,
    #[serde(default)]
    deposit: u128,
    #[serde(default)]
    buyer_bond: u128,
    escrow: u128,
    flags: u8,
    deadline: u64,
    order_id_floor: u128,
    fill_cursor: MatchWatchCursor,
    submit_identity: String,
    created_at_unix: u64,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BuyerSubscriptionState {
    schema: String,
    note_addr: String,
    orders: Vec<BuyerSubscriptionOrderRecord>,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum BuyerSubscriptionPhase {
    Resting,
    Matched,
    Terminal,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BuyerSubscriptionMatch {
    token_contract: dexdo_core::TokenContract,
    order_id: u128,
    ticks: u128,
    clearing_price: u128,
    deal_handle: String,
}

#[cfg(feature = "shellnet")]
impl BuyerSubscriptionMatch {
    fn from_fill(fill: &BuyerJournalMatch) -> Self {
        Self {
            token_contract: fill.token_contract.clone(),
            order_id: fill.order_id,
            ticks: fill.ticks,
            clearing_price: fill.clearing_price,
            deal_handle: deals::make_handle_id(&fill.token_contract, deals::DealHandleRole::Buyer),
        }
    }

    fn as_fill(&self) -> BuyerJournalMatch {
        BuyerJournalMatch {
            token_contract: self.token_contract.clone(),
            order_id: self.order_id,
            ticks: self.ticks,
            clearing_price: self.clearing_price,
        }
    }
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BuyerSubscriptionOrderRecord {
    order_book: String,
    frame_model: String,
    model_hash: String,
    order_id: u128,
    max_price_per_tick: u128,
    ticks: u128,
    #[serde(default)]
    deposit: u128,
    #[serde(default)]
    buyer_bond: u128,
    escrow: u128,
    flags: u8,
    deadline: u64,
    fill_cursor: MatchWatchCursor,
    phase: BuyerSubscriptionPhase,
    matched: Option<BuyerSubscriptionMatch>,
}

#[cfg(feature = "shellnet")]
type PersistSubscriptionHandle<'a> =
    dyn Fn(&BuyerSubscriptionOrderRecord, &BuyerJournalMatch) -> Result<String> + Send + Sync + 'a;

#[cfg(feature = "shellnet")]
#[allow(dead_code)]
#[derive(Debug)]
enum BuyerMoneyJournal {
    Buy(Box<BuyerSubmitJournal>),
    Subscription(Box<BuyerSubscriptionSubmitJournal>),
}

#[cfg(feature = "shellnet")]
#[allow(dead_code)]
impl BuyerSubmitJournal {
    fn validate(&self, expected_note_addr: &str) -> Result<()> {
        if self.schema != BUYER_SUBMIT_JOURNAL_SCHEMA {
            bail!("unsupported buyer submit journal schema {}", self.schema);
        }
        let note_addr = dexdo_core::Address::parse(&self.note_addr)
            .map_err(|error| anyhow::anyhow!("buyer submit journal note_addr: {error}"))?
            .with_workchain();
        if !note_addr.eq_ignore_ascii_case(expected_note_addr) {
            bail!(
                "buyer submit journal belongs to note {}, expected {}",
                note_addr,
                expected_note_addr
            );
        }
        dexdo_core::Address::parse(&self.order_book)
            .map_err(|error| anyhow::anyhow!("buyer submit journal order_book: {error}"))?;
        self.intent.validate()?;
        let quoted_tc =
            self.quoted_order.token_contract.as_deref().ok_or_else(|| {
                anyhow::anyhow!("buyer submit journal quote has no TokenContract")
            })?;
        dexdo_core::Address::parse(quoted_tc).map_err(|error| {
            anyhow::anyhow!("buyer submit journal quoted TokenContract: {error}")
        })?;
        if let Some(expected) = &self.expected_token_contract {
            let expected = dexdo_core::Address::parse(expected)
                .map_err(|error| {
                    anyhow::anyhow!("buyer submit journal expected TokenContract: {error}")
                })?
                .with_workchain();
            if !expected.eq_ignore_ascii_case(quoted_tc) {
                bail!(
                    "buyer submit journal expected TokenContract {} differs from quoted {}",
                    expected,
                    quoted_tc
                );
            }
        }
        if !self.quoted_order.is_resting_ask()
            || self.quoted_order.ticks < self.ticks
            || self.quoted_order.price_per_tick > self.max_price_per_tick
        {
            bail!("buyer submit journal quote is not executable for its recorded request");
        }
        check_buy_deposit_headroom(self.escrow, self.ticks, self.max_price_per_tick)
            .map_err(anyhow::Error::msg)?;
        let quoted_fill = self.quote.fills.as_slice();
        if !self.quote.complete
            || self.quote.filled_ticks != self.ticks
            || quoted_fill.len() != 1
            || quoted_fill[0].order_id != self.quoted_order.order_id
            || !quoted_fill[0]
                .token_contract
                .eq_ignore_ascii_case(quoted_tc)
            || quoted_fill[0].ticks != self.ticks
            || quoted_fill[0].price_per_tick != self.quoted_order.price_per_tick
            || quoted_fill[0].cost_with_fee != self.quote.total_with_fee
        {
            bail!("buyer submit journal executable quote differs from its recorded order/request");
        }
        validate_buyer_submit_identity(&self.submit_identity, "buyer submit journal")?;
        if let Some(resolved) = &self.resolved_match {
            dexdo_core::Address::parse(&resolved.token_contract).map_err(|error| {
                anyhow::anyhow!("buyer submit journal resolved TokenContract: {error}")
            })?;
        }
        let mut resolved_token_contracts = std::collections::BTreeSet::new();
        for resolved in &self.resolved_matches {
            let token_contract = dexdo_core::Address::parse(&resolved.token_contract)
                .map_err(|error| {
                    anyhow::anyhow!("buyer submit journal resolved TokenContract: {error}")
                })?
                .with_workchain();
            if !resolved_token_contracts.insert(token_contract.clone()) {
                bail!("buyer submit journal repeats resolved TokenContract {token_contract}");
            }
        }
        if let (Some(first), Some(resolved)) =
            (self.resolved_matches.first(), self.resolved_match.as_ref())
        {
            if first != resolved {
                bail!("buyer submit journal scalar/vector resolved match disagree");
            }
        }
        Ok(())
    }
}

fn subscription_order_flags() -> u8 {
    flags::AON | flags::SUBSCRIPTION
}

fn validate_subscription_order_terms(
    max_price_per_tick: u128,
    ticks: u128,
    escrow: u128,
    order_flags: u8,
    deadline: u64,
    created_at_unix: u64,
) -> Result<SubscriptionBuyReserve> {
    validate_price_step(max_price_per_tick)?;
    let minimum = u128::from(SUBSCRIPTION_WEEKS);
    if !(minimum..=SUBSCRIPTION_MAX_TICKS).contains(&ticks) || !ticks.is_multiple_of(minimum) {
        bail!(
            "subscription ticks must be {minimum}..={SUBSCRIPTION_MAX_TICKS} and divisible by \
            {SUBSCRIPTION_WEEKS}, got {ticks}"
        );
    }
    let reserve = check_subscription_buy_reserve(escrow, ticks, max_price_per_tick)
        .map_err(anyhow::Error::msg)?;
    let expected_flags = subscription_order_flags();
    if order_flags & flags::SUBSCRIPTION != 0 && order_flags & flags::MARKET != 0 {
        bail!(
            "subscription MARKET orders are unsupported: buyer bond 2P requires a limit price \
             before the money submit"
        );
    }
    if order_flags != expected_flags {
        bail!(
            "subscription flags must be exactly AON|SUBSCRIPTION (0x{expected_flags:02x}), got \
             0x{order_flags:02x}"
        );
    }
    if deadline == 0 || deadline <= created_at_unix {
        bail!(
            "subscription deadline must be a finite absolute unix time after {created_at_unix}, got \
             {deadline}"
        );
    }
    Ok(reserve)
}

#[cfg(feature = "shellnet")]
fn validate_subscription_fund_split(
    deposit: u128,
    buyer_bond: u128,
    reserve: SubscriptionBuyReserve,
    label: &str,
) -> Result<()> {
    if deposit != reserve.deposit || buyer_bond != reserve.buyer_bond {
        bail!(
            "{label} money split conflicts with total escrow: stored deposit={deposit}, \
             buyer_bond={buyer_bond}; expected deposit={}, buyer_bond={}, total_escrow={}",
            reserve.deposit,
            reserve.buyer_bond,
            reserve.total_escrow
        );
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
impl BuyerSubscriptionSubmitJournal {
    fn validate(&self, expected_note_addr: &str) -> Result<()> {
        if self.schema != BUYER_SUBSCRIPTION_SUBMIT_SCHEMA {
            bail!(
                "unsupported buyer subscription submit journal schema {}",
                self.schema
            );
        }
        let note_addr = dexdo_core::Address::parse(&self.note_addr)
            .map_err(|error| anyhow::anyhow!("buyer subscription journal note_addr: {error}"))?
            .with_workchain();
        if !note_addr.eq_ignore_ascii_case(expected_note_addr) {
            bail!(
                "buyer subscription journal belongs to note {}, expected {}",
                note_addr,
                expected_note_addr
            );
        }
        dexdo_core::Address::parse(&self.order_book)
            .map_err(|error| anyhow::anyhow!("buyer subscription journal order_book: {error}"))?;
        if self.frame_model.trim().is_empty()
            || !model_hash_for(&self.frame_model).eq_ignore_ascii_case(&self.model_hash)
        {
            bail!("buyer subscription journal model identity is inconsistent");
        }
        let reserve = validate_subscription_order_terms(
            self.max_price_per_tick,
            self.ticks,
            self.escrow,
            self.flags,
            self.deadline,
            self.created_at_unix,
        )?;
        validate_subscription_fund_split(
            self.deposit,
            self.buyer_bond,
            reserve,
            "buyer subscription journal",
        )?;
        validate_buyer_submit_identity(&self.submit_identity, "buyer subscription submit journal")
    }
}

#[cfg(feature = "shellnet")]
impl BuyerSubscriptionState {
    fn empty(note_addr: &str) -> Result<Self> {
        let note_addr = dexdo_core::Address::parse(note_addr)
            .map_err(|error| anyhow::anyhow!("buyer subscription state note_addr: {error}"))?
            .with_workchain();
        Ok(Self {
            schema: BUYER_SUBSCRIPTION_STATE_SCHEMA.to_string(),
            note_addr,
            orders: Vec::new(),
        })
    }

    fn validate(&self, expected_note_addr: &str) -> Result<()> {
        if self.schema != BUYER_SUBSCRIPTION_STATE_SCHEMA {
            bail!(
                "unsupported buyer subscription state schema {}",
                self.schema
            );
        }
        let note_addr = dexdo_core::Address::parse(&self.note_addr)
            .map_err(|error| anyhow::anyhow!("buyer subscription state note_addr: {error}"))?
            .with_workchain();
        if !note_addr.eq_ignore_ascii_case(expected_note_addr) {
            bail!(
                "buyer subscription state belongs to note {}, expected {}",
                note_addr,
                expected_note_addr
            );
        }
        let mut order_keys = std::collections::BTreeSet::new();
        let mut matched_contracts = std::collections::BTreeSet::new();
        for order in &self.orders {
            let order_book = dexdo_core::Address::parse(&order.order_book)
                .map_err(|error| anyhow::anyhow!("buyer subscription order_book: {error}"))?
                .with_workchain();
            if order.frame_model.trim().is_empty()
                || !model_hash_for(&order.frame_model).eq_ignore_ascii_case(&order.model_hash)
            {
                bail!(
                    "buyer subscription order #{} has inconsistent model identity",
                    order.order_id
                );
            }
            let reserve = validate_subscription_order_terms(
                order.max_price_per_tick,
                order.ticks,
                order.escrow,
                order.flags,
                order.deadline,
                0,
            )?;
            validate_subscription_fund_split(
                order.deposit,
                order.buyer_bond,
                reserve,
                "buyer subscription state",
            )?;
            if !order_keys.insert((order_book, order.order_id)) {
                bail!(
                    "buyer subscription state repeats order #{} in {}",
                    order.order_id,
                    order.order_book
                );
            }
            match (order.phase, order.matched.as_ref()) {
                (BuyerSubscriptionPhase::Resting, None)
                | (BuyerSubscriptionPhase::Matched, Some(_))
                | (BuyerSubscriptionPhase::Terminal, _) => {}
                (BuyerSubscriptionPhase::Resting, Some(_)) => bail!(
                    "buyer subscription order #{} is resting but carries a matched deal",
                    order.order_id
                ),
                (BuyerSubscriptionPhase::Matched, None) => {
                    bail!(
                        "buyer subscription order #{} phase {:?} has no matched deal",
                        order.order_id,
                        order.phase
                    )
                }
            }
            if let Some(matched) = &order.matched {
                validate_subscription_match_record(order, matched)?;
                let token_contract = dexdo_core::Address::parse(&matched.token_contract)
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "buyer subscription matched TokenContract {}: {error}",
                            matched.token_contract
                        )
                    })?
                    .with_workchain();
                if !matched_contracts.insert(token_contract.clone()) {
                    bail!("buyer subscription state repeats TokenContract {token_contract}");
                }
            }
        }
        Ok(())
    }
}

#[cfg(feature = "shellnet")]
fn validate_subscription_match_record(
    order: &BuyerSubscriptionOrderRecord,
    matched: &BuyerSubscriptionMatch,
) -> Result<()> {
    validate_subscription_match(order, &matched.as_fill())?;
    let expected_handle =
        deals::make_handle_id(&matched.token_contract, deals::DealHandleRole::Buyer);
    if matched.deal_handle != expected_handle {
        bail!(
            "subscription order #{} matched deal handle {} is not deterministic for {}",
            order.order_id,
            matched.deal_handle,
            matched.token_contract
        );
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
fn validate_subscription_match(
    order: &BuyerSubscriptionOrderRecord,
    matched: &BuyerJournalMatch,
) -> Result<()> {
    dexdo_core::Address::parse(&matched.token_contract).map_err(|error| {
        anyhow::anyhow!(
            "subscription order #{} matched invalid TokenContract {}: {error}",
            order.order_id,
            matched.token_contract
        )
    })?;
    if matched.order_id != order.order_id {
        bail!(
            "subscription order #{} received fill for order #{}",
            order.order_id,
            matched.order_id
        );
    }
    if matched.ticks != order.ticks {
        bail!(
            "subscription order #{} must fill all {} ticks from one seller, got partial/incorrect \
             fill {}",
            order.order_id,
            order.ticks,
            matched.ticks
        );
    }
    validate_price_step(matched.clearing_price)?;
    if matched.clearing_price > order.max_price_per_tick {
        bail!(
            "subscription order #{} clearing price {} exceeds limit {}",
            order.order_id,
            matched.clearing_price,
            order.max_price_per_tick
        );
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
fn validate_buyer_submit_identity(identity: &str, label: &str) -> Result<()> {
    let digest = identity
        .strip_prefix("boc-sha256:")
        .ok_or_else(|| anyhow::anyhow!("{label} has no BOC identity"))?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} has malformed BOC identity");
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
fn buyer_submit_recovery_anchor(
    order: &OrderBookOrder,
) -> Result<dexdo::buyer::api::BuyerSubmitRecoveryAnchor> {
    let token_contract = order
        .token_contract
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("buyer recovery anchor has no TokenContract"))?;
    let token_contract = dexdo_core::Address::parse(token_contract)
        .map_err(|error| anyhow::anyhow!("buyer recovery anchor TokenContract: {error}"))?
        .with_workchain();
    Ok(dexdo::buyer::api::BuyerSubmitRecoveryAnchor {
        order_id: order.order_id,
        token_contract,
    })
}

#[cfg(feature = "shellnet")]
fn buyer_submit_reconciliation(
    journal: &BuyerSubmitJournal,
    state: dexdo::buyer::api::BuyerSubmitReconciliationState,
    origin: dexdo::buyer::api::BuyerSubmitReconciliationOrigin,
) -> Result<dexdo::buyer::api::BuyerSubmitReconciliation> {
    validate_buyer_submit_identity(&journal.submit_identity, "buyer submit journal")?;
    Ok(dexdo::buyer::api::BuyerSubmitReconciliation {
        submit_identity: journal.submit_identity.clone(),
        recovery_anchor: buyer_submit_recovery_anchor(&journal.quoted_order)?,
        state,
        origin,
    })
}

#[cfg(feature = "shellnet")]
#[allow(dead_code)]
fn buyer_submit_state_dir() -> Result<std::path::PathBuf> {
    #[cfg(test)]
    let path = {
        static PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
        PATH.get_or_init(|| {
            let started_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("test process clock must be after the Unix epoch")
                .as_nanos();
            std::env::temp_dir().join(format!(
                "dexdo-buyer-submits-tests-{}-{started_at}",
                std::process::id()
            ))
        })
        .clone()
    };
    #[cfg(not(test))]
    let path = directories::ProjectDirs::from("ai", "gosh", "dexdo")
        .ok_or_else(|| {
            anyhow::anyhow!("could not determine platform data directory for buyer submit journal")
        })?
        .data_dir()
        .join("buyer-submits");
    std::fs::create_dir_all(&path).map_err(|error| {
        anyhow::anyhow!(
            "create buyer submit journal directory {}: {error}",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                anyhow::anyhow!(
                    "set private buyer submit journal directory {}: {error}",
                    path.display()
                )
            },
        )?;
    }
    Ok(path)
}

#[cfg(feature = "shellnet")]
#[allow(dead_code)]
impl BuyerMoneyLock {
    fn open(note_addr: &str) -> Result<Self> {
        use sha2::{Digest, Sha256};

        let note_addr = dexdo_core::Address::parse(note_addr)
            .map_err(|error| anyhow::anyhow!("buyer note money lock address {note_addr}: {error}"))?
            .with_workchain();
        let digest = Sha256::digest(note_addr.as_bytes());
        let basename = format!("note-{}", hex::encode(digest));
        let state_dir = buyer_submit_state_dir()?;
        let path = crate::cli::note::resolve_private_file_path(
            &state_dir.join(format!("{basename}.money")),
            "buyer note money lock target",
        )?;
        let journal_path = crate::cli::note::resolve_private_file_path(
            &state_dir.join(format!("{basename}.json")),
            "buyer money journal",
        )?;
        let subscriptions_path = crate::cli::note::resolve_private_file_path(
            &state_dir.join(format!("{basename}.subscriptions.json")),
            "buyer subscription state",
        )?;
        Ok(Self {
            note_addr,
            path,
            journal_path,
            subscriptions_path,
            lock: None,
        })
    }

    fn acquire(&mut self) -> Result<()> {
        if self.lock.is_some() {
            bail!(
                "buyer note {} money lock is already acquired",
                self.note_addr
            );
        }
        self.lock = Some(acquire_pool_write_lock(&self.path).map_err(|error| {
            anyhow::anyhow!(
                "acquire buyer note {} money lock {} before submit: {error}",
                self.note_addr,
                self.path.display()
            )
        })?);
        Ok(())
    }

    fn try_acquire(&mut self) -> Result<()> {
        if self.lock.is_some() {
            bail!(
                "buyer note {} money lock is already acquired",
                self.note_addr
            );
        }
        self.lock = Some(try_acquire_pool_write_lock(&self.path).map_err(|error| {
            anyhow::anyhow!(
                "buyer note {} already has another money submission awaiting by-fact reconciliation; no BOC was sent ({}: {error})",
                self.note_addr,
                self.path.display()
            )
        })?);
        Ok(())
    }
}

#[cfg(feature = "shellnet")]
#[allow(dead_code)]
fn read_buyer_private_state(path: &std::path::Path, label: &str) -> Result<Option<Vec<u8>>> {
    let path = crate::cli::note::resolve_private_file_path(path, label)?;
    match std::fs::read(&path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(anyhow::anyhow!("read {label} {}: {error}", path.display())),
    }
}

#[cfg(feature = "shellnet")]
#[allow(dead_code)]
fn load_buyer_money_journal(
    path: &std::path::Path,
    expected_note_addr: &str,
) -> Result<Option<BuyerMoneyJournal>> {
    let Some(bytes) = read_buyer_private_state(path, "buyer money journal")? else {
        return Ok(None);
    };
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "buyer money journal {} is invalid JSON: {error}",
            path.display()
        )
    })?;
    let schema = value
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("buyer money journal {} has no schema", path.display()))?;
    let journal = match schema {
        BUYER_SUBMIT_JOURNAL_SCHEMA => {
            let journal: BuyerSubmitJournal = serde_json::from_value(value).map_err(|error| {
                anyhow::anyhow!(
                    "buyer submit journal {} is invalid: {error}",
                    path.display()
                )
            })?;
            journal.validate(expected_note_addr)?;
            BuyerMoneyJournal::Buy(Box::new(journal))
        }
        BUYER_SUBMIT_JOURNAL_SCHEMA_V1 => {
            let legacy: BuyerSubmitJournalV1 = serde_json::from_value(value).map_err(|error| {
                anyhow::anyhow!(
                    "legacy buyer submit journal {} is invalid: {error}",
                    path.display()
                )
            })?;
            let journal = BuyerSubmitJournal::from(legacy);
            journal.validate(expected_note_addr)?;
            BuyerMoneyJournal::Buy(Box::new(journal))
        }
        BUYER_SUBSCRIPTION_SUBMIT_SCHEMA => {
            let journal: BuyerSubscriptionSubmitJournal =
                serde_json::from_value(value).map_err(|error| {
                    anyhow::anyhow!(
                        "buyer subscription submit journal {} is invalid: {error}",
                        path.display()
                    )
                })?;
            journal.validate(expected_note_addr)?;
            BuyerMoneyJournal::Subscription(Box::new(journal))
        }
        LEGACY_BUYER_SUBSCRIPTION_SUBMIT_SCHEMA => bail!(
            "legacy buyer subscription submit journal schema {} is not compatible with the \
             AON|SUBSCRIPTION order protocol; journal retained and no money action is safe",
            LEGACY_BUYER_SUBSCRIPTION_SUBMIT_SCHEMA
        ),
        other => bail!("unsupported buyer money journal schema {other}"),
    };
    Ok(Some(journal))
}

#[cfg(feature = "shellnet")]
#[allow(dead_code)]
fn load_buyer_submit_journal(
    path: &std::path::Path,
    expected_note_addr: &str,
) -> Result<Option<BuyerSubmitJournal>> {
    match load_buyer_money_journal(path, expected_note_addr)? {
        None => Ok(None),
        Some(BuyerMoneyJournal::Buy(journal)) => Ok(Some(*journal)),
        Some(BuyerMoneyJournal::Subscription(journal)) => bail!(
            "buyer note {} has unresolved subscription submit {} in {}; reconcile it with `dexdo \
             subscription place` before a quote-bound buy",
            journal.note_addr,
            journal.submit_identity,
            journal.order_book
        ),
    }
}

#[cfg(feature = "shellnet")]
#[allow(dead_code)]
fn write_buyer_submit_journal(path: &std::path::Path, journal: &BuyerSubmitJournal) -> Result<()> {
    journal.validate(&journal.note_addr)?;
    let bytes = serde_json::to_vec_pretty(journal)?;
    with_pool_write_lock(path, |path| write_pool_private(path, &bytes))
        .map_err(|error| anyhow::anyhow!("write buyer submit journal {}: {error}", path.display()))
}

#[cfg(feature = "shellnet")]
fn write_buyer_subscription_submit_journal(
    path: &std::path::Path,
    journal: &BuyerSubscriptionSubmitJournal,
) -> Result<()> {
    journal.validate(&journal.note_addr)?;
    let bytes = serde_json::to_vec_pretty(journal)?;
    with_pool_write_lock(path, |path| write_pool_private(path, &bytes)).map_err(|error| {
        anyhow::anyhow!(
            "write buyer subscription submit journal {}: {error}",
            path.display()
        )
    })
}

#[cfg(feature = "shellnet")]
fn load_buyer_subscription_state(
    path: &std::path::Path,
    expected_note_addr: &str,
) -> Result<BuyerSubscriptionState> {
    let Some(bytes) = read_buyer_private_state(path, "buyer subscription state")? else {
        return BuyerSubscriptionState::empty(expected_note_addr);
    };
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "buyer subscription state {} is invalid JSON: {error}",
            path.display()
        )
    })?;
    let schema = value.get("schema").and_then(Value::as_str).ok_or_else(|| {
        anyhow::anyhow!("buyer subscription state {} has no schema", path.display())
    })?;
    if matches!(
        schema,
        LEGACY_BUYER_SUBSCRIPTION_STATE_SCHEMA | LEGACY_BUYER_SUBSCRIPTION_STATE_SCHEMA_V2
    ) {
        bail!(
            "legacy buyer subscription state schema {} is incompatible with the \
             durable single-TC subscription protocol; remove it only after manual reconciliation",
            schema
        );
    }
    if schema != BUYER_SUBSCRIPTION_STATE_SCHEMA {
        bail!("unsupported buyer subscription state schema {schema}");
    }
    let state: BuyerSubscriptionState = serde_json::from_value(value).map_err(|error| {
        anyhow::anyhow!(
            "buyer subscription state {} is invalid: {error}",
            path.display()
        )
    })?;
    state.validate(expected_note_addr)?;
    Ok(state)
}

#[cfg(feature = "shellnet")]
fn write_buyer_subscription_state(
    path: &std::path::Path,
    state: &BuyerSubscriptionState,
) -> Result<()> {
    state.validate(&state.note_addr)?;
    let bytes = serde_json::to_vec_pretty(state)?;
    with_pool_write_lock(path, |path| write_pool_private(path, &bytes)).map_err(|error| {
        anyhow::anyhow!("write buyer subscription state {}: {error}", path.display())
    })
}

/// Retain the durable subscription history after an explicit buyer terminal command has been
/// authoritatively confirmed. Ordinary deals and notes without a v3 subscription store are untouched.
#[cfg(feature = "shellnet")]
pub(crate) fn mark_buyer_subscription_terminal(
    note_addr: &str,
    token_contract: &str,
) -> Result<bool> {
    let mut money_lock = BuyerMoneyLock::open(note_addr)?;
    money_lock.try_acquire()?;
    if !money_lock.subscriptions_path.exists() {
        return Ok(false);
    }
    let token_contract = dexdo_core::Address::parse(token_contract)
        .map_err(|error| anyhow::anyhow!("terminal subscription TokenContract: {error}"))?
        .with_workchain();
    let mut state =
        load_buyer_subscription_state(&money_lock.subscriptions_path, &money_lock.note_addr)?;
    let mut matched = state.orders.iter_mut().filter(|record| {
        record
            .matched
            .as_ref()
            .is_some_and(|matched| matched.token_contract.eq_ignore_ascii_case(&token_contract))
    });
    let Some(record) = matched.next() else {
        return Ok(false);
    };
    if matched.next().is_some() {
        bail!(
            "durable buyer subscription state contains multiple records for TokenContract \
             {token_contract}"
        );
    }
    match record.phase {
        BuyerSubscriptionPhase::Resting => bail!(
            "durable buyer subscription record for TokenContract {token_contract} is resting but \
             carries a match"
        ),
        BuyerSubscriptionPhase::Matched => {
            record.phase = BuyerSubscriptionPhase::Terminal;
            write_buyer_subscription_state(&money_lock.subscriptions_path, &state)?;
            Ok(true)
        }
        BuyerSubscriptionPhase::Terminal => Ok(false),
    }
}

#[cfg(feature = "shellnet")]
fn mark_cancelled_buyer_subscription_terminal(
    path: &std::path::Path,
    note_addr: &str,
    order_book: &str,
    order_id: u128,
) -> Result<bool> {
    let mut state = load_buyer_subscription_state(path, note_addr)?;
    let record =
        subscription_order_record_mut(&mut state, order_book, order_id).ok_or_else(|| {
            anyhow::anyhow!(
            "confirmed subscription cancellation has no durable order #{order_id} in {order_book}"
        )
        })?;
    match (record.phase, record.matched.as_ref()) {
        (BuyerSubscriptionPhase::Resting, None) => {
            record.phase = BuyerSubscriptionPhase::Terminal;
            write_buyer_subscription_state(path, &state)?;
            Ok(true)
        }
        (BuyerSubscriptionPhase::Terminal, None) => Ok(false),
        (_, Some(matched)) => bail!(
            "subscription order #{order_id} cancellation refund contradicts matched TokenContract {}",
            matched.token_contract
        ),
        (BuyerSubscriptionPhase::Matched, None) => bail!(
            "subscription order #{order_id} is matched without a TokenContract"
        ),
    }
}

#[cfg(feature = "shellnet")]
#[allow(dead_code)]
fn clear_buyer_submit_journal(path: &std::path::Path) -> Result<()> {
    with_pool_write_lock(path, |path| match std::fs::remove_file(path) {
        Ok(()) => crate::cli::note::sync_parent_dir(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(anyhow::anyhow!(
            "remove reconciled buyer submit journal {}: {error}",
            path.display()
        )),
    })
}

#[cfg(feature = "shellnet")]
#[allow(dead_code)]
fn buyer_money_lock_for_submit(
    mock_chain: bool,
    note_addr: Option<&str>,
) -> Result<Option<BuyerMoneyLock>> {
    if mock_chain {
        return Ok(None);
    }
    let note_addr = note_addr.ok_or_else(|| {
        anyhow::anyhow!("real shellnet buyer money submit requires --note-addr before locking")
    })?;
    BuyerMoneyLock::open(note_addr).map(Some)
}

#[cfg(feature = "shellnet")]
fn persist_pool_token_contract_for_note(
    pool_path: &std::path::Path,
    note_addr: &str,
    token_contract: &str,
    role: &str,
) -> Result<()> {
    with_pool_write_lock(pool_path, |pool_path| {
        let pool = load_pool_json(pool_path)?;
        let updated = crate::cli::note::pool_with_note_token_contract_recorded(
            pool,
            note_addr,
            token_contract,
            role,
            unix_now_secs(),
        )?;
        let bytes = serde_json::to_vec_pretty(&updated)?;
        write_pool_private(pool_path, &bytes)
    })
}

#[cfg(feature = "shellnet")]
fn preflight_buyer_pool_for_note(note_addr: Option<&str>) -> Result<()> {
    let Some(pool_path) = note_pool_path(None) else {
        bail!(
            "real shellnet buyer money writes require DEXDO_PN_POOL before any escrow POST so a matched \
             TokenContract can be persisted durably; set DEXDO_PN_POOL to the pool containing --note-addr"
        );
    };
    let note_addr = note_addr.ok_or_else(|| {
        anyhow::anyhow!(
            "real shellnet: --note-addr is required to preflight DEXDO_PN_POOL before buying"
        )
    })?;
    with_pool_write_lock(&pool_path, |pool_path| {
        let pool = load_pool_json(pool_path)?;
        crate::cli::note::pool_has_unique_note_entry(&pool, note_addr)?;
        let bytes = serde_json::to_vec_pretty(&pool)?;
        write_pool_private(pool_path, &bytes).map_err(|e| {
            anyhow::anyhow!(
                "preflight DEXDO_PN_POOL {} before buying: pool is not safely updateable: {e}",
                pool_path.display()
            )
        })
    })
}

#[cfg(not(feature = "shellnet"))]
fn preflight_buyer_pool_for_note(_note_addr: Option<&str>) -> Result<()> {
    Ok(())
}

#[allow(dead_code)]
fn preflight_buyer_pool_for_money_move(args: &BuyerArgs) -> Result<()> {
    if args.mock.mock_chain {
        return Ok(());
    }
    preflight_buyer_pool_for_note(args.identity.note_addr.as_deref())
}

async fn place_buy_by_model_after_pool_preflight(
    chain: &dyn ChainBackend,
    buyer: &dexdo::buyer::Buyer,
    preflight_pool: bool,
    pool_note_addr: Option<&str>,
    ticks: u128,
    max_price: u128,
    escrow: u128,
) -> Result<()> {
    if preflight_pool {
        preflight_buyer_pool_for_note(pool_note_addr)?;
    }
    chain
        .place_buy_by_model(
            buyer.note.as_ref(),
            ticks,
            max_price,
            escrow,
            0,
            buy_order_deadline()?,
        )
        .await
        .map_err(|e| anyhow::Error::new(e).context("place model-only buy after pool preflight"))
}

#[cfg(feature = "shellnet")]
fn is_ambiguous_submit_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<ChainError>(),
            Some(ChainError::AmbiguousSubmit(_))
        ) || cause
            .downcast_ref::<dexdo::buyer::api::DealInitError>()
            .is_some_and(|error| error.reconciliation().is_some())
    })
}

#[cfg(feature = "shellnet")]
fn money_submit_error_clears_journal(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<dexdo_core::MoneySubmitError>()
            .is_some_and(dexdo_core::MoneySubmitError::clears_journal)
            || matches!(
                cause.downcast_ref::<ChainError>(),
                Some(ChainError::MoneySubmitPreparation(_) | ChainError::MoneySubmitRejected(_))
            )
    })
}

#[cfg(feature = "shellnet")]
fn journal_match(fill: &dexdo_core::MatchedFill) -> BuyerJournalMatch {
    BuyerJournalMatch {
        token_contract: fill.token_contract.clone(),
        order_id: fill.order_id,
        ticks: fill.ticks,
        clearing_price: fill.price_per_tick,
    }
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SubscriptionDealFacts {
    state: DealChainState,
    subscription: DealSubscription,
    seller_bond: DealSellerBond,
    buyer_bond: DealBuyerBond,
    model_name: String,
    model_hash: String,
    buyer_note: String,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SubscriptionQuotaView {
    claimed_current_week: u128,
    remaining_current_week: u128,
    buyer_locked_total: u128,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SubscriptionRuntimeView {
    ticks: u128,
    order_id: Option<u128>,
    facts: SubscriptionDealFacts,
    quota: SubscriptionQuotaView,
}

/// What a resumed subscription hands the running route.
/// `remaining_current_week` is the allowance of the BOOKED week the deal stands on; `subscription` is
/// the coherent shape it was read from, so the route knows which week that allowance belongs to and
/// when that week runs out - and can go and book the next boundary instead of holding this scalar for
/// the rest of the term.
#[derive(Clone, Copy)]
struct SubscriptionRouteBudget {
    remaining_current_week: u64,
    /// The authoritative state `remaining_current_week` was computed from. The route's live budget
    /// anchors its local counter on this snapshot's `tokensPending`, so the two must be one read
    /// .
    state: dexdo_core::DealChainState,
    subscription: dexdo_core::DealSubscription,
}

fn subscription_oneshot_budget(requested: u64, remaining_current_week: Option<u64>) -> Result<u64> {
    let allowed = remaining_current_week
        .map(|remaining| requested.min(remaining))
        .unwrap_or(requested);
    if allowed == 0 {
        bail!(
            "subscription current-week quota is exhausted; no one-shot request was sent and the \
             subscription remains resumable"
        );
    }
    Ok(allowed)
}

/// The current-week quota this deal stands on, read from the RECORDED weekly books.
/// Both halves come from the same recorded `weekBaseTokens`, so what the status reports as claimed and
/// what it reports as remaining always belong to the same week. How that figure stands to the ceiling
/// the contract applies has three phases - exact, understated, or an upper bound (see
/// [`dexdo_core::subscription_claim_cap_at`]) - and which one holds cannot be read off the books
/// alone. So a caller that needs it to be an authorization books the boundary first and reads again,
/// rather than guessing the phase.
#[cfg(feature = "shellnet")]
fn subscription_quota_view(facts: &SubscriptionDealFacts) -> Result<SubscriptionQuotaView> {
    let buyer_locked_total = facts
        .state
        .deposit
        .checked_add(facts.state.probe_tick)
        .and_then(|held| held.checked_add(facts.buyer_bond.bond_held))
        .ok_or_else(|| anyhow::anyhow!("subscription buyer locked exposure overflows u128"))?;
    if facts.state.disputed || facts.state.is_stopped() {
        return Ok(SubscriptionQuotaView {
            claimed_current_week: 0,
            remaining_current_week: 0,
            buyer_locked_total,
        });
    }
    let claimed_current_week = facts
        .state
        .tokens_pending
        .checked_sub(facts.subscription.week_base_tokens)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "subscription tokensPending {} is below weekBaseTokens {}",
                facts.state.tokens_pending,
                facts.subscription.week_base_tokens
            )
        })?;
    if facts.subscription.is_subscription()
        && facts.subscription.week_index >= facts.subscription.sub_weeks
    {
        return Ok(SubscriptionQuotaView {
            claimed_current_week,
            remaining_current_week: 0,
            buyer_locked_total,
        });
    }
    let remaining_current_week =
        dexdo_core::subscription_current_week_headroom(&facts.state, &facts.subscription)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(SubscriptionQuotaView {
        claimed_current_week,
        remaining_current_week,
        buyer_locked_total,
    })
}

/// Whether a boundary booking must be attempted before this deal's quota may be treated as an
/// allowance.
/// Two triggers, and the second is the one a stale positive remainder hides behind: the recorded week
/// shows nothing left, OR it has run out on the wall clock. Booking only on a zero remainder would
/// serve the previous week's unspent tokens straight across its boundary, which is exactly the
/// roll-over the term does not have.
#[cfg(feature = "shellnet")]
fn subscription_boundary_is_due(facts: &SubscriptionDealFacts) -> bool {
    if facts.subscription.term_is_over() || !facts.subscription.is_subscription() {
        return false;
    }
    let quota_spent =
        dexdo_core::subscription_current_week_headroom(&facts.state, &facts.subscription)
            .map(|headroom| headroom == 0)
            .unwrap_or(true);
    quota_spent || facts.subscription.recorded_week_expires_at() <= unix_now_secs()
}

/// The part of a recorded quota that may actually be handed to a route.
/// After a booking attempt the books are as authoritative as they are going to get. If the week they
/// describe has still run out on the wall clock, no boundary was booked, and what is on record belongs
/// to a week that has ended: report nothing rather than a figure that would resume onto a spent week.
/// The running route reconciles again on its first request and picks the new week up from the chain.
#[cfg(feature = "shellnet")]
fn subscription_authorized_remaining(
    facts: &SubscriptionDealFacts,
    quota: &SubscriptionQuotaView,
) -> u128 {
    if facts.subscription.is_subscription()
        && !facts.subscription.term_is_over()
        && facts.subscription.recorded_week_expires_at() <= unix_now_secs()
    {
        return 0;
    }
    quota.remaining_current_week
}

#[cfg(feature = "shellnet")]
fn validate_subscription_deal_facts(
    expected_note_addr: &str,
    order: &BuyerSubscriptionOrderRecord,
    matched: &BuyerJournalMatch,
    facts: &SubscriptionDealFacts,
) -> Result<SubscriptionQuotaView> {
    validate_subscription_match(order, matched)?;
    if order.flags != subscription_order_flags() {
        bail!(
            "subscription order #{} flags 0x{:02x} are not exact AON|SUBSCRIPTION 0x{:02x}",
            order.order_id,
            order.flags,
            subscription_order_flags()
        );
    }
    if !facts.state.funded {
        bail!(
            "subscription TokenContract {} is not funded",
            matched.token_contract
        );
    }
    if facts.model_name != order.frame_model
        || !facts.model_hash.eq_ignore_ascii_case(&order.model_hash)
        || !model_hash_for(&facts.model_name).eq_ignore_ascii_case(&order.model_hash)
    {
        bail!(
            "subscription TokenContract {} model identity contradicts durable order #{}",
            matched.token_contract,
            order.order_id
        );
    }
    let expected_note = dexdo_core::Address::parse(expected_note_addr)
        .map_err(|error| anyhow::anyhow!("subscription expected buyer note: {error}"))?
        .with_workchain();
    let actual_note = dexdo_core::Address::parse(&facts.buyer_note)
        .map_err(|error| anyhow::anyhow!("subscription TokenContract buyer note: {error}"))?
        .with_workchain();
    if !actual_note.eq_ignore_ascii_case(&expected_note) {
        bail!(
            "subscription TokenContract {} buyer note {} is not durable owner {}",
            matched.token_contract,
            actual_note,
            expected_note
        );
    }
    if !facts.subscription.is_subscription()
        || facts.subscription.sub_weeks != SUBSCRIPTION_WEEKS
        // The book-side identity is exactly AON|SUBSCRIPTION(validated from the durable order).
        // TokenContract deliberately records only the DEAL_MASK slice, so the corresponding exact
        // on-chain identity is SUBSCRIPTION with no TEE bit or other mutation.
        || facts.subscription.deal_flags != flags::SUBSCRIPTION
    {
        bail!(
            "TokenContract {} is not the canonical four-week subscription shape",
            matched.token_contract
        );
    }
    let funded_tokens = order
        .ticks
        .checked_mul(TICK_SIZE)
        .ok_or_else(|| anyhow::anyhow!("subscription funded token volume overflows u128"))?;
    if facts.subscription.funded_tokens != funded_tokens {
        bail!(
            "subscription TokenContract {} fundedTokens {} differs from full AON order volume {}",
            matched.token_contract,
            facts.subscription.funded_tokens,
            funded_tokens
        );
    }
    let matched_reserve = subscription_buy_reserve(order.ticks, matched.clearing_price)
        .map_err(anyhow::Error::msg)?;
    let expected_bond = matched_reserve.buyer_bond;
    if facts.buyer_bond.bond_required != expected_bond {
        bail!(
            "subscription TokenContract {} buyer bondRequired {} differs from canonical 2P {} at \
             clearing price {}",
            matched.token_contract,
            facts.buyer_bond.bond_required,
            expected_bond,
            matched.clearing_price
        );
    }
    if facts.seller_bond.bond_required != expected_bond {
        bail!(
            "subscription TokenContract {} seller bondRequired {} differs from canonical 2P {} at \
             clearing price {}",
            matched.token_contract,
            facts.seller_bond.bond_required,
            expected_bond,
            matched.clearing_price
        );
    }
    if facts.seller_bond.bond_held > expected_bond {
        bail!(
            "subscription TokenContract {} seller bondHeld {} exceeds canonical 2P {}",
            matched.token_contract,
            facts.seller_bond.bond_held,
            expected_bond
        );
    }
    let live = !facts.state.disputed && !facts.state.is_stopped();
    if live && facts.buyer_bond.bond_held != expected_bond {
        bail!(
            "subscription TokenContract {} live buyer bondHeld {} differs from canonical 2P {}",
            matched.token_contract,
            facts.buyer_bond.bond_held,
            expected_bond
        );
    }
    if !facts.seller_bond.bond_funded && facts.seller_bond.bond_held != 0 {
        bail!(
            "subscription TokenContract {} unfunded seller bond unexpectedly holds {}",
            matched.token_contract,
            facts.seller_bond.bond_held
        );
    }
    if facts.state.opened && !facts.seller_bond.bond_funded {
        bail!(
            "subscription TokenContract {} is opened without a funded seller bond",
            matched.token_contract
        );
    }
    if live && facts.seller_bond.bond_funded && facts.seller_bond.bond_held != expected_bond {
        bail!(
            "subscription TokenContract {} live funded seller bondHeld {} differs from canonical \
             2P {}",
            matched.token_contract,
            facts.seller_bond.bond_held,
            expected_bond
        );
    }
    subscription_quota_view(facts)
}

#[cfg(feature = "shellnet")]
async fn classify_subscription_resume_target(
    chain: &dyn ChainBackend,
    expected_note_addr: &str,
    frame_model: &str,
    token_contract: &str,
    historical_fill: Option<&MatchedFill>,
) -> Result<Option<SubscriptionRuntimeView>> {
    let snapshot = chain
        .deal_snapshot(&token_contract.to_string())
        .await
        .map_err(anyhow::Error::new)?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "TokenContract {token_contract}: coherent snapshot is unavailable; refusing to \
                 treat an unknown deal shape as ordinary"
            )
        })?;
    if !snapshot.subscription.is_subscription() {
        return Ok(None);
    }
    if snapshot.state.disputed || snapshot.state.is_stopped() {
        bail!("subscription TokenContract {token_contract} is terminal/disputed and cannot be resumed");
    }

    // The live-target assertion proves buyer ownership plus the exact model/book identity. It is
    // intentionally after the subscription/terminal read: terminal history is reconciled as terminal
    // rather than being misreported as an invalid active target.
    chain
        .assert_model_only_resume_target(&token_contract.to_string())
        .await
        .map_err(anyhow::Error::new)?;

    let ticks = snapshot
        .subscription
        .funded_tokens
        .checked_div(TICK_SIZE)
        .filter(|_| {
            snapshot
                .subscription
                .funded_tokens
                .is_multiple_of(TICK_SIZE)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "subscription TokenContract {token_contract} fundedTokens {} is not an exact \
                 multiple of TICK_SIZE {TICK_SIZE}",
                snapshot.subscription.funded_tokens
            )
        })?;
    let (order_id, clearing_price) = if let Some(fill) = historical_fill {
        if !fill.token_contract.eq_ignore_ascii_case(token_contract) {
            bail!(
                "historical subscription fill names {}, expected {token_contract}",
                fill.token_contract
            );
        }
        if fill.ticks != ticks {
            bail!(
                "historical subscription fill volume {} differs from TokenContract funded volume \
                 {ticks}",
                fill.ticks
            );
        }
        (fill.order_id, fill.price_per_tick)
    } else {
        let required = snapshot.buyer_bond.bond_required;
        if required == 0 || !required.is_multiple_of(2) {
            bail!(
                "subscription TokenContract {token_contract} buyer bondRequired {required} cannot \
                 encode canonical 2P"
            );
        }
        (0, required / 2)
    };
    let reserve = validate_subscription_order_terms(
        clearing_price,
        ticks,
        subscription_buy_reserve(ticks, clearing_price)
            .map_err(anyhow::Error::msg)?
            .total_escrow,
        subscription_order_flags(),
        u64::MAX,
        0,
    )?;
    let order = BuyerSubscriptionOrderRecord {
        order_book: chain
            .model_buy_order_book_identity()
            .unwrap_or_else(|| "authoritative-token-contract".to_string()),
        frame_model: frame_model.to_string(),
        model_hash: model_hash_for(frame_model),
        order_id,
        max_price_per_tick: clearing_price,
        ticks,
        deposit: reserve.deposit,
        buyer_bond: reserve.buyer_bond,
        escrow: reserve.total_escrow,
        flags: subscription_order_flags(),
        deadline: u64::MAX,
        fill_cursor: MatchWatchCursor::new(0),
        phase: BuyerSubscriptionPhase::Matched,
        matched: None,
    };
    let matched = BuyerJournalMatch {
        token_contract: token_contract.to_string(),
        order_id,
        ticks,
        clearing_price,
    };
    let facts = SubscriptionDealFacts {
        state: snapshot.state,
        subscription: snapshot.subscription,
        seller_bond: snapshot.seller_bond,
        buyer_bond: snapshot.buyer_bond,
        // The live-target assertion above proved these exact identities from the TokenContract.
        model_name: frame_model.to_string(),
        model_hash: model_hash_for(frame_model),
        buyer_note: expected_note_addr.to_string(),
    };
    let mut facts = facts;
    let mut quota = validate_subscription_deal_facts(expected_note_addr, &order, &matched, &facts)?;
    // the recorded books are not an authorization. A resume that lands after a boundary and
    // before anyone booked it reads the PREVIOUS week's spent quota, and refusing on that would strand
    // the subscription at zero for the rest of its term.
    if subscription_boundary_is_due(&facts) {
        // The booking's response is not evidence either way: a submission whose response was lost
        // still moved the chain. So attempt it, then ALWAYS re-read and let the booked state decide.
        let _ = chain.settle_week(&token_contract.to_string()).await;
        let booked = chain
            .deal_snapshot(&token_contract.to_string())
            .await
            .map_err(anyhow::Error::new)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "TokenContract {token_contract}: no coherent snapshot after booking the weekly \
                     boundary"
                )
            })?;
        facts.state = booked.state;
        facts.subscription = booked.subscription;
        facts.seller_bond = booked.seller_bond;
        facts.buyer_bond = booked.buyer_bond;
        quota = validate_subscription_deal_facts(expected_note_addr, &order, &matched, &facts)?;
        quota.remaining_current_week = subscription_authorized_remaining(&facts, &quota);
    }
    Ok(Some(SubscriptionRuntimeView {
        ticks,
        order_id: historical_fill.map(|fill| fill.order_id),
        facts,
        quota,
    }))
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait]
trait SubscriptionOrderOps: Send + Sync {
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    async fn submit_subscription_order(
        &self,
        note: &dexdo_core::Address,
        keys: &dexdo_core::KeyPair,
        order_book: &str,
        model_hash: &str,
        max_price_per_tick: u128,
        ticks: u128,
        escrow: u128,
        order_flags: u8,
        deadline: u64,
        fill_cursor: &mut MatchWatchCursor,
        before_post: &mut (dyn FnMut(String, u128, MatchWatchCursor, Vec<(u128, MatchedFill)>) -> Result<()>
                  + Send),
    ) -> Result<Value>;

    async fn subscription_placements(
        &self,
        order_book: &str,
        buyer_note: &str,
        order_id_floor: u128,
        max_price_per_tick: u128,
        ticks: u128,
    ) -> Result<Vec<InferenceSubscriptionPlacement>>;

    async fn attributed_subscription_fills(
        &self,
        order_book: &str,
        buyer_note: &str,
        cursor: &mut MatchWatchCursor,
    ) -> Result<Vec<(u128, MatchedFill)>>;

    async fn subscription_order_active(
        &self,
        order_book: &str,
        order_id: u128,
        buyer_note: &str,
    ) -> Result<bool>;

    async fn subscription_deal_facts(
        &self,
        expected_note_addr: &str,
        order: &BuyerSubscriptionOrderRecord,
        matched: &BuyerJournalMatch,
    ) -> Result<SubscriptionDealFacts>;

    /// Attempt the permissionless weekly boundary booking.
    /// Returns nothing on purpose: the submission's ANSWER is not evidence either way. A booking
    /// whose response was lost still moved the chain, and one the contract refused leaves the books
    /// exactly where they stood - so every caller re-reads the authoritative snapshot afterwards and
    /// decides from the booked state. It is a money path: it charges weeks the term already owes out
    /// of escrow(`_deposit -= pay + fee`), while committing nothing new.
    async fn book_subscription_week(&self, token_contract: &str);
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait]
impl SubscriptionOrderOps for dexdo_core::RealChainBackend {
    async fn submit_subscription_order(
        &self,
        note: &dexdo_core::Address,
        keys: &dexdo_core::KeyPair,
        order_book: &str,
        model_hash: &str,
        max_price_per_tick: u128,
        ticks: u128,
        escrow: u128,
        order_flags: u8,
        deadline: u64,
        fill_cursor: &mut MatchWatchCursor,
        before_post: &mut (dyn FnMut(String, u128, MatchWatchCursor, Vec<(u128, MatchedFill)>) -> Result<()>
                  + Send),
    ) -> Result<Value> {
        if order_flags != subscription_order_flags() {
            bail!(
                "subscription submit requires exact flags 0x{:02x}, got 0x{order_flags:02x}",
                subscription_order_flags()
            );
        }
        check_subscription_buy_reserve(escrow, ticks, max_price_per_tick)
            .map_err(|error| anyhow::anyhow!("subscription submit preflight: {error}"))?;
        let order_book = dexdo_core::Address::parse(order_book)
            .map_err(|error| anyhow::anyhow!("subscription order_book: {error}"))?;
        self.place_inference_buy_with_identity_and_cursors(
            note,
            keys,
            &order_book,
            model_hash,
            max_price_per_tick,
            ticks,
            escrow,
            order_flags,
            deadline,
            fill_cursor,
            before_post,
        )
        .await
    }

    async fn subscription_placements(
        &self,
        order_book: &str,
        buyer_note: &str,
        order_id_floor: u128,
        max_price_per_tick: u128,
        ticks: u128,
    ) -> Result<Vec<InferenceSubscriptionPlacement>> {
        let order_book = dexdo_core::Address::parse(order_book)
            .map_err(|error| anyhow::anyhow!("subscription order_book: {error}"))?;
        let buyer_note = dexdo_core::Address::parse(buyer_note)
            .map_err(|error| anyhow::anyhow!("subscription buyer note: {error}"))?;
        self.inference_subscription_placements_since(
            &order_book,
            &buyer_note,
            order_id_floor,
            max_price_per_tick,
            ticks,
        )
        .await
    }

    async fn attributed_subscription_fills(
        &self,
        order_book: &str,
        buyer_note: &str,
        cursor: &mut MatchWatchCursor,
    ) -> Result<Vec<(u128, MatchedFill)>> {
        let order_book = dexdo_core::Address::parse(order_book)
            .map_err(|error| anyhow::anyhow!("subscription order_book: {error}"))?;
        let buyer_note = dexdo_core::Address::parse(buyer_note)
            .map_err(|error| anyhow::anyhow!("subscription buyer note: {error}"))?;
        self.poll_inference_attributed_fills(&buyer_note, &order_book, cursor)
            .await
    }

    async fn subscription_order_active(
        &self,
        order_book: &str,
        order_id: u128,
        buyer_note: &str,
    ) -> Result<bool> {
        let order_book = dexdo_core::Address::parse(order_book)
            .map_err(|error| anyhow::anyhow!("subscription order_book: {error}"))?;
        self.inference_buyer_order_is_active_for_owner(&order_book, order_id, buyer_note)
            .await
    }

    async fn subscription_deal_facts(
        &self,
        _expected_note_addr: &str,
        _order: &BuyerSubscriptionOrderRecord,
        matched: &BuyerJournalMatch,
    ) -> Result<SubscriptionDealFacts> {
        let tc = dexdo_core::Address::parse(&matched.token_contract).map_err(|error| {
            anyhow::anyhow!(
                "subscription matched TokenContract {}: {error}",
                matched.token_contract
            )
        })?;
        let snapshot = self
            .token_contract_deal_snapshot(&tc)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("TokenContract {tc}: coherent snapshot is unavailable")
            })?;
        let model_name = self.token_contract_model_name(&tc).await?.ok_or_else(|| {
            anyhow::anyhow!("TokenContract {tc}: getModelName() returned no data")
        })?;
        let model_hash = self.token_contract_model_hash(&tc).await?.ok_or_else(|| {
            anyhow::anyhow!("TokenContract {tc}: getModelHash() returned no data")
        })?;
        let buyer_note = self
            .token_contract_buyer_note(&tc)
            .await?
            .ok_or_else(|| anyhow::anyhow!("TokenContract {tc}: getBuyerNote() returned no data"))?
            .with_workchain();
        Ok(SubscriptionDealFacts {
            state: snapshot.state,
            subscription: snapshot.subscription,
            seller_bond: snapshot.seller_bond,
            buyer_bond: snapshot.buyer_bond,
            model_name,
            model_hash,
            buyer_note,
        })
    }

    async fn book_subscription_week(&self, token_contract: &str) {
        if let Ok(tc) = dexdo_core::Address::parse(token_contract) {
            let _ = self.settle_week(&tc).await;
        }
    }
}

#[cfg(feature = "shellnet")]
struct BuyerSubscriptionResumeOps<'a> {
    chain: &'a dyn ChainBackend,
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait]
impl SubscriptionOrderOps for BuyerSubscriptionResumeOps<'_> {
    async fn submit_subscription_order(
        &self,
        _note: &dexdo_core::Address,
        _keys: &dexdo_core::KeyPair,
        _order_book: &str,
        _model_hash: &str,
        _max_price_per_tick: u128,
        _ticks: u128,
        _escrow: u128,
        _order_flags: u8,
        _deadline: u64,
        _fill_cursor: &mut MatchWatchCursor,
        _before_post: &mut (dyn FnMut(String, u128, MatchWatchCursor, Vec<(u128, MatchedFill)>) -> Result<()>
                  + Send),
    ) -> Result<Value> {
        bail!("buyer subscription resume never submits a fresh order")
    }

    async fn subscription_placements(
        &self,
        order_book: &str,
        buyer_note: &str,
        order_id_floor: u128,
        max_price_per_tick: u128,
        ticks: u128,
    ) -> Result<Vec<InferenceSubscriptionPlacement>> {
        self.chain
            .subscription_placements_since(
                order_book,
                buyer_note,
                order_id_floor,
                max_price_per_tick,
                ticks,
            )
            .await
            .map_err(anyhow::Error::new)
    }

    async fn attributed_subscription_fills(
        &self,
        order_book: &str,
        _buyer_note: &str,
        cursor: &mut MatchWatchCursor,
    ) -> Result<Vec<(u128, MatchedFill)>> {
        self.chain
            .poll_attributed_model_buys_for_order_book(order_book, cursor)
            .await
            .map_err(anyhow::Error::new)
    }

    async fn subscription_order_active(
        &self,
        order_book: &str,
        order_id: u128,
        buyer_note: &str,
    ) -> Result<bool> {
        self.chain
            .buyer_order_is_active_for_owner(order_book, order_id, buyer_note)
            .await
            .map_err(anyhow::Error::new)
    }

    async fn subscription_deal_facts(
        &self,
        expected_note_addr: &str,
        order: &BuyerSubscriptionOrderRecord,
        matched: &BuyerJournalMatch,
    ) -> Result<SubscriptionDealFacts> {
        let snapshot = self
            .chain
            .deal_snapshot(&matched.token_contract)
            .await
            .map_err(anyhow::Error::new)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "TokenContract {}: coherent snapshot is unavailable",
                    matched.token_contract
                )
            })?;
        if !snapshot.state.disputed && !snapshot.state.is_stopped() {
            self.chain
                .assert_model_only_resume_target(&matched.token_contract)
                .await
                .map_err(anyhow::Error::new)?;
        }
        Ok(SubscriptionDealFacts {
            state: snapshot.state,
            subscription: snapshot.subscription,
            seller_bond: snapshot.seller_bond,
            buyer_bond: snapshot.buyer_bond,
            // `assert_model_only_resume_target` just proved these three identities from chain getters.
            model_name: order.frame_model.clone(),
            model_hash: order.model_hash.clone(),
            buyer_note: expected_note_addr.to_string(),
        })
    }

    async fn book_subscription_week(&self, token_contract: &str) {
        let _ = self.chain.settle_week(&token_contract.to_string()).await;
    }
}

#[cfg(feature = "shellnet")]
fn subscription_order_record<'a>(
    state: &'a BuyerSubscriptionState,
    order_book: &str,
    order_id: u128,
) -> Option<&'a BuyerSubscriptionOrderRecord> {
    state.orders.iter().find(|record| {
        record.order_id == order_id && record.order_book.eq_ignore_ascii_case(order_book)
    })
}

#[cfg(feature = "shellnet")]
fn subscription_order_record_mut<'a>(
    state: &'a mut BuyerSubscriptionState,
    order_book: &str,
    order_id: u128,
) -> Option<&'a mut BuyerSubscriptionOrderRecord> {
    state.orders.iter_mut().find(|record| {
        record.order_id == order_id && record.order_book.eq_ignore_ascii_case(order_book)
    })
}

#[cfg(feature = "shellnet")]
fn record_subscription_placement(
    state: &mut BuyerSubscriptionState,
    journal: &BuyerSubscriptionSubmitJournal,
    placement: &InferenceSubscriptionPlacement,
) -> Result<BuyerSubscriptionOrderRecord> {
    let owner = dexdo_core::Address::parse(&placement.buyer_note)
        .map_err(|error| anyhow::anyhow!("subscription placement buyer note: {error}"))?
        .with_workchain();
    let created_at = u64::try_from(placement.created_at).map_err(|_| {
        anyhow::anyhow!(
            "subscription placement #{} has negative created_at",
            placement.order_id
        )
    })?;
    if !owner.eq_ignore_ascii_case(&journal.note_addr)
        || placement.order_id < journal.order_id_floor
        || placement.max_price_per_tick != journal.max_price_per_tick
        || placement.ticks != journal.ticks
        || placement.sub_weeks != SUBSCRIPTION_WEEKS
        || placement.deadline != journal.deadline
        || created_at >= journal.deadline
    {
        bail!(
            "subscription placement #{} contradicts the exact durable BOC intent",
            placement.order_id
        );
    }
    let candidate = BuyerSubscriptionOrderRecord {
        order_book: journal.order_book.clone(),
        frame_model: journal.frame_model.clone(),
        model_hash: journal.model_hash.clone(),
        order_id: placement.order_id,
        max_price_per_tick: journal.max_price_per_tick,
        ticks: journal.ticks,
        deposit: journal.deposit,
        buyer_bond: journal.buyer_bond,
        escrow: journal.escrow,
        flags: journal.flags,
        deadline: journal.deadline,
        fill_cursor: journal.fill_cursor.clone(),
        phase: BuyerSubscriptionPhase::Resting,
        matched: None,
    };
    let reserve = validate_subscription_order_terms(
        candidate.max_price_per_tick,
        candidate.ticks,
        candidate.escrow,
        candidate.flags,
        candidate.deadline,
        0,
    )?;
    validate_subscription_fund_split(
        candidate.deposit,
        candidate.buyer_bond,
        reserve,
        "subscription placement",
    )?;
    if let Some(existing) =
        subscription_order_record(state, &candidate.order_book, candidate.order_id)
    {
        let mut comparable = existing.clone();
        comparable.fill_cursor = candidate.fill_cursor.clone();
        comparable.phase = BuyerSubscriptionPhase::Resting;
        comparable.matched = None;
        if comparable != candidate {
            bail!(
                "subscription placement #{} conflicts with durable state",
                placement.order_id
            );
        }
        return Ok(existing.clone());
    }
    state.orders.push(candidate.clone());
    state
        .orders
        .sort_by_key(|record| (record.order_book.clone(), record.order_id));
    Ok(candidate)
}

#[cfg(feature = "shellnet")]
fn coalesce_journal_subscription_placements(
    journal: &BuyerSubscriptionSubmitJournal,
    placements: Vec<InferenceSubscriptionPlacement>,
) -> Result<Vec<InferenceSubscriptionPlacement>> {
    let mut placements = placements
        .into_iter()
        .filter(|placement| placement.order_id >= journal.order_id_floor)
        .map(|mut placement| {
            placement.buyer_note = dexdo_core::Address::parse(&placement.buyer_note)
                .map_err(|error| {
                    anyhow::anyhow!(
                        "subscription placement #{} buyer note {}: {error}",
                        placement.order_id,
                        placement.buyer_note
                    )
                })?
                .with_workchain();
            Ok(placement)
        })
        .collect::<Result<Vec<_>>>()?;
    placements.sort_by(|left, right| {
        left.order_id
            .cmp(&right.order_id)
            .then_with(|| left.created_at.cmp(&right.created_at))
    });
    let mut correlated = Vec::new();
    let mut start = 0;
    while start < placements.len() {
        let order_id = placements[start].order_id;
        let mut end = start + 1;
        while end < placements.len() && placements[end].order_id == order_id {
            end += 1;
        }
        let group = &placements[start..end];
        let has_exact = group.iter().any(|placement| {
            placement
                .buyer_note
                .eq_ignore_ascii_case(&journal.note_addr)
                && placement.max_price_per_tick == journal.max_price_per_tick
                && placement.ticks == journal.ticks
                && placement.sub_weeks == SUBSCRIPTION_WEEKS
                && placement.deadline == journal.deadline
                && u64::try_from(placement.created_at)
                    .is_ok_and(|created_at| created_at < journal.deadline)
        });
        if has_exact {
            let first = &group[0];
            if group.iter().any(|placement| placement != first) {
                bail!(
                    "subscription order #{order_id} has conflicting authenticated placement facts"
                );
            }
            correlated.push(first.clone());
        }
        start = end;
    }
    Ok(correlated)
}

#[cfg(feature = "shellnet")]
async fn sync_subscription_match_once(
    ops: &dyn SubscriptionOrderOps,
    state_path: &std::path::Path,
    note_addr: &str,
    order_book: &str,
    order_id: u128,
    persist_handle: &PersistSubscriptionHandle<'_>,
) -> Result<BuyerSubscriptionOrderRecord> {
    let mut state = load_buyer_subscription_state(state_path, note_addr)?;
    let current = subscription_order_record(&state, order_book, order_id)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!("subscription order #{order_id} is absent from durable state")
        })?;
    let mut cursor = current.fill_cursor.clone();
    let fills = ops
        .attributed_subscription_fills(order_book, note_addr, &mut cursor)
        .await?;
    let mut correlated = Vec::<BuyerJournalMatch>::new();
    for (fill_order_id, fill) in fills {
        if fill_order_id != order_id {
            continue;
        }
        if fill.order_id != fill_order_id {
            bail!(
                "subscription order #{order_id} received an attributed fill whose embedded order \
                 id is {}",
                fill.order_id
            );
        }
        let mut matched = journal_match(&fill);
        matched.order_id = fill_order_id;
        matched.token_contract = dexdo_core::Address::parse(&matched.token_contract)
            .map_err(|error| {
                anyhow::anyhow!(
                    "subscription fill TokenContract {}: {error}",
                    matched.token_contract
                )
            })?
            .with_workchain();
        validate_subscription_match(&current, &matched)?;
        if !correlated.contains(&matched) {
            correlated.push(matched);
        }
    }
    if correlated.len() > 1 {
        bail!(
            "subscription order #{order_id} produced {} distinct seller fills; expected exactly one",
            correlated.len()
        );
    }
    let fresh = correlated.into_iter().next();
    let adopted = match (&current.matched, fresh.as_ref()) {
        (Some(existing), Some(fresh)) => {
            if existing.as_fill() != *fresh {
                bail!(
                    "subscription order #{order_id} already records seller {}, but a contradictory fill \
                     names {}",
                    existing.token_contract,
                    fresh.token_contract
                );
            }
            None
        }
        (None, Some(fresh)) => {
            let facts = ops
                .subscription_deal_facts(note_addr, &current, fresh)
                .await?;
            validate_subscription_deal_facts(note_addr, &current, fresh, &facts)?;
            if facts.state.disputed || facts.state.is_stopped() {
                bail!(
                    "subscription order #{order_id} matched {}, but it is already terminal/disputed",
                    fresh.token_contract
                );
            }
            let handle = persist_handle(&current, fresh)?;
            let mut matched = BuyerSubscriptionMatch::from_fill(fresh);
            if matched.deal_handle != handle {
                bail!(
                    "subscription order #{order_id} handle writer returned {}, expected {}",
                    handle,
                    matched.deal_handle
                );
            }
            matched.deal_handle = handle;
            Some(matched)
        }
        _ => None,
    };
    let record = subscription_order_record_mut(&mut state, order_book, order_id)
        .expect("record was resolved above");
    if let Some(adopted) = adopted {
        record.phase = BuyerSubscriptionPhase::Matched;
        record.matched = Some(adopted);
    }
    record.fill_cursor = cursor;
    let result = record.clone();
    write_buyer_subscription_state(state_path, &state)?;
    Ok(result)
}

#[cfg(feature = "shellnet")]
async fn refresh_subscription_match(
    ops: &dyn SubscriptionOrderOps,
    state_path: &std::path::Path,
    note_addr: &str,
    order_book: &str,
    order_id: u128,
) -> Result<(
    BuyerSubscriptionOrderRecord,
    SubscriptionDealFacts,
    SubscriptionQuotaView,
)> {
    let mut state = load_buyer_subscription_state(state_path, note_addr)?;
    let current = subscription_order_record(&state, order_book, order_id)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!("subscription order #{order_id} is absent from durable state")
        })?;
    let matched = current.matched.as_ref().ok_or_else(|| {
        anyhow::anyhow!("subscription order #{order_id} has no matched TokenContract")
    })?;
    let fill = matched.as_fill();
    let mut facts = ops
        .subscription_deal_facts(note_addr, &current, &fill)
        .await?;
    let mut quota = validate_subscription_deal_facts(note_addr, &current, &fill, &facts)?;
    // the recorded books are not an authorization. A restart that lands after a boundary and
    // before anyone booked it reads the PREVIOUS week's spent quota, and resuming on that would
    // strand the subscription at zero for the rest of its term.
    if subscription_boundary_is_due(&facts) {
        // The booking's response is not evidence: a submission whose response was lost still moved
        // the chain. Attempt it, then ALWAYS re-read and let the booked state decide.
        ops.book_subscription_week(&matched.token_contract).await;
        facts = ops
            .subscription_deal_facts(note_addr, &current, &fill)
            .await?;
        quota = validate_subscription_deal_facts(note_addr, &current, &fill, &facts)?;
        quota.remaining_current_week = subscription_authorized_remaining(&facts, &quota);
    }
    let terminal = facts.state.disputed || facts.state.is_stopped();
    let record = subscription_order_record_mut(&mut state, order_book, order_id)
        .expect("record was resolved above");
    match (record.phase, terminal) {
        (BuyerSubscriptionPhase::Matched, true) => {
            record.phase = BuyerSubscriptionPhase::Terminal;
            write_buyer_subscription_state(state_path, &state)?;
        }
        (BuyerSubscriptionPhase::Terminal, false) => bail!(
            "subscription order #{order_id} is durably terminal but TokenContract {} reports live",
            matched.token_contract
        ),
        (BuyerSubscriptionPhase::Resting, _) => {
            bail!("subscription order #{order_id} carries a match while phase is resting")
        }
        _ => {}
    }
    let state = load_buyer_subscription_state(state_path, note_addr)?;
    let record = subscription_order_record(&state, order_book, order_id)
        .expect("record survived refresh")
        .clone();
    Ok((record, facts, quota))
}

#[cfg(feature = "shellnet")]
async fn reconcile_subscription_submit(
    ops: &dyn SubscriptionOrderOps,
    journal_path: &std::path::Path,
    state_path: &std::path::Path,
    journal: &BuyerSubscriptionSubmitJournal,
    wait: std::time::Duration,
    persist_handle: &PersistSubscriptionHandle<'_>,
) -> Result<BuyerSubscriptionOrderRecord> {
    journal.validate(&journal.note_addr)?;
    let started = std::time::Instant::now();
    loop {
        let placements = ops
            .subscription_placements(
                &journal.order_book,
                &journal.note_addr,
                journal.order_id_floor,
                journal.max_price_per_tick,
                journal.ticks,
            )
            .await
            .map_err(|error| {
                anyhow::Error::new(ChainError::AmbiguousSubmit(format!(
                    "could not read placement facts for durable subscription submit {}; journal \
                     retained and no fresh BOC is safe: {error:#}",
                    journal.submit_identity
                )))
            })?;
        let placements =
            coalesce_journal_subscription_placements(journal, placements).map_err(|error| {
                anyhow::Error::new(ChainError::AmbiguousSubmit(format!(
                    "durable subscription submit {} has contradictory placement facts; journal \
                     retained and no fresh BOC is safe: {error:#}",
                    journal.submit_identity
                )))
            })?;
        if placements.len() > 1 {
            return Err(anyhow::Error::new(ChainError::AmbiguousSubmit(format!(
                "durable subscription submit {} produced {} exact correlated placements; journal \
                 retained and no new BOC is safe",
                journal.submit_identity,
                placements.len()
            ))));
        }
        if let Some(placement) = placements.first() {
            let mut state = load_buyer_subscription_state(state_path, &journal.note_addr)?;
            record_subscription_placement(&mut state, journal, placement)?;
            write_buyer_subscription_state(state_path, &state)?;
            let record = sync_subscription_match_once(
                ops,
                state_path,
                &journal.note_addr,
                &journal.order_book,
                placement.order_id,
                persist_handle,
            )
            .await?;
            let active = ops
                .subscription_order_active(
                    &journal.order_book,
                    placement.order_id,
                    &journal.note_addr,
                )
                .await?;
            match (active, record.matched.is_some()) {
                (true, false) | (false, true) => {
                    clear_buyer_submit_journal(journal_path)?;
                    return Ok(record);
                }
                (true, true) => {
                    return Err(anyhow::Error::new(ChainError::AmbiguousSubmit(format!(
                        "subscription order #{} is simultaneously resting and filled; journal \
                         retained",
                        placement.order_id
                    ))));
                }
                (false, false) => {}
            }
        }
        if started.elapsed() >= wait {
            return Err(anyhow::Error::new(ChainError::AmbiguousSubmit(format!(
                "subscription submit {} is not yet provable as one resting order or one full seller \
                 fill; journal retained and no resubmit is safe",
                journal.submit_identity
            ))));
        }
        tokio::time::sleep(SUBSCRIPTION_ORDER_RECONCILE_POLL).await;
    }
}

#[cfg(feature = "shellnet")]
#[allow(clippy::too_many_arguments)]
async fn submit_subscription_with_journal(
    ops: &dyn SubscriptionOrderOps,
    note: &dexdo_core::Address,
    keys: &dexdo_core::KeyPair,
    order_book: &str,
    frame_model: &str,
    model_hash: &str,
    max_price_per_tick: u128,
    ticks: u128,
    escrow: u128,
    deadline: u64,
    journal_path: &std::path::Path,
    state_path: &std::path::Path,
    wait: std::time::Duration,
    persist_handle: &PersistSubscriptionHandle<'_>,
) -> Result<BuyerSubscriptionOrderRecord> {
    let note_addr = note.with_workchain();
    let created_at_unix = unix_now_secs();
    let order_flags = subscription_order_flags();
    let reserve = validate_subscription_order_terms(
        max_price_per_tick,
        ticks,
        escrow,
        order_flags,
        deadline,
        created_at_unix,
    )?;
    let mut fill_cursor = MatchWatchCursor::new(0);
    let mut before_post = |submit_identity: String,
                           order_id_floor: u128,
                           final_cursor: MatchWatchCursor,
                           _pre_post_fills: Vec<(u128, MatchedFill)>| {
        write_buyer_subscription_submit_journal(
            journal_path,
            &BuyerSubscriptionSubmitJournal {
                schema: BUYER_SUBSCRIPTION_SUBMIT_SCHEMA.to_string(),
                note_addr: note_addr.clone(),
                order_book: order_book.to_string(),
                frame_model: frame_model.to_string(),
                model_hash: model_hash.to_string(),
                max_price_per_tick,
                ticks,
                deposit: reserve.deposit,
                buyer_bond: reserve.buyer_bond,
                escrow,
                flags: order_flags,
                deadline,
                order_id_floor,
                fill_cursor: final_cursor,
                submit_identity,
                created_at_unix,
            },
        )
    };
    let submit_result = ops
        .submit_subscription_order(
            note,
            keys,
            order_book,
            model_hash,
            max_price_per_tick,
            ticks,
            escrow,
            order_flags,
            deadline,
            &mut fill_cursor,
            &mut before_post,
        )
        .await;
    if let Err(error) = &submit_result {
        if money_submit_error_clears_journal(error) {
            clear_buyer_submit_journal(journal_path)?;
            return Err(anyhow::anyhow!("{error:#}"));
        }
    }
    let journal = match load_buyer_money_journal(journal_path, &note_addr)? {
        Some(BuyerMoneyJournal::Subscription(journal)) => *journal,
        Some(BuyerMoneyJournal::Buy(_)) => {
            bail!("subscription submit journal was replaced by an ordinary BUY journal")
        }
        None => {
            bail!("subscription money POST may have landed, but its durable journal disappeared")
        }
    };
    reconcile_subscription_submit(
        ops,
        journal_path,
        state_path,
        &journal,
        wait,
        persist_handle,
    )
    .await
}

#[cfg(feature = "shellnet")]
fn persist_buyer_token_contract_for_note_result(
    note_addr: Option<&str>,
    token_contract: &str,
) -> Result<()> {
    let pool_path = note_pool_path(None)
        .ok_or_else(|| anyhow::anyhow!("DEXDO_PN_POOL disappeared after buyer money moved"))?;
    let note_addr = note_addr
        .ok_or_else(|| anyhow::anyhow!("buyer note address disappeared after buyer money moved"))?;
    persist_pool_token_contract_for_note(&pool_path, note_addr, token_contract, "buyer")
}

#[cfg(feature = "shellnet")]
fn persist_subscription_runtime_handle(
    record: &BuyerSubscriptionOrderRecord,
    matched: &BuyerJournalMatch,
    note_addr: &str,
    deals_dir: Option<&std::path::Path>,
    market_path: Option<&std::path::Path>,
    contracts: &std::path::Path,
) -> Result<String> {
    validate_subscription_match(record, matched)?;
    let handle = deals::make_handle_id(&matched.token_contract, deals::DealHandleRole::Buyer);
    let directory = deals::resolve_deals_dir(deals_dir)?;
    let path = deals::handle_path(&directory, &handle);
    if path.exists() {
        let existing = deals::load_deal_handle(&path)?;
        let same_identity = existing.handle == handle
            && existing.role == deals::DealHandleRole::Buyer
            && existing
                .token_contract
                .eq_ignore_ascii_case(&matched.token_contract)
            && existing.note_addr.eq_ignore_ascii_case(note_addr)
            && existing.frame_model == record.frame_model
            && existing.created_order_ids.contains(&record.order_id);
        if !same_identity {
            bail!(
                "subscription deal handle {} already exists with contradictory identity",
                path.display()
            );
        }
        return Ok(handle);
    }
    let saved = save_runtime_deal_handle(
        RuntimeDealHandleInput {
            role: deals::DealHandleRole::Buyer,
            deals_dir,
            token_contract: &matched.token_contract,
            note_addr,
            frame_model: &record.frame_model,
            market: None,
            market_path,
            contracts,
            endpoint: None,
            created_order_ids: vec![record.order_id],
        },
        false,
    )?;
    if saved.handle != handle {
        bail!(
            "subscription deal handle persistence returned {}, expected {}",
            saved.handle,
            handle
        );
    }
    Ok(handle)
}

#[cfg(feature = "shellnet")]
#[allow(dead_code, clippy::too_many_arguments)]
async fn place_quote_bound_buy_with_journal(
    chain: &dyn ChainBackend,
    buyer: &dexdo::buyer::Buyer,
    intent: &BuyerSubmitIntent,
    expected_token_contract: Option<&str>,
    selection: &BuyerQuoteSelection,
    ticks: u128,
    max_price_per_tick: u128,
    escrow: u128,
    note_addr: &str,
    cursor: &mut dexdo_core::MatchWatchCursor,
    journal_path: &std::path::Path,
    human_model: Option<&str>,
) -> Result<()> {
    let order_book = chain.model_buy_order_book_identity().ok_or_else(|| {
        anyhow::anyhow!(
            "real shellnet backend did not expose its canonical model order-book identity; no BOC was sent"
        )
    })?;
    let quoted_order = selection.quoted_order.clone().ok_or_else(|| {
        anyhow::anyhow!("real shellnet submit requires the exact rendered order row")
    })?;
    let canonical_note = dexdo_core::Address::parse(note_addr)
        .map_err(|error| anyhow::anyhow!("buyer submit journal note address: {error}"))?
        .with_workchain();
    let canonical_expected_token_contract = expected_token_contract
        .map(|address| {
            dexdo_core::Address::parse(address)
                .map(|address| address.with_workchain())
                .map_err(|error| {
                    anyhow::anyhow!("buyer submit journal expected TokenContract: {error}")
                })
        })
        .transpose()?;
    let template = BuyerSubmitJournal {
        schema: BUYER_SUBMIT_JOURNAL_SCHEMA.to_string(),
        note_addr: canonical_note,
        order_book,
        intent: intent.clone(),
        expected_token_contract: canonical_expected_token_contract,
        quoted_order,
        quote: selection.quote.clone(),
        cursor: dexdo_core::MatchWatchCursor::default(),
        ticks,
        max_price_per_tick,
        escrow,
        submit_identity: String::new(),
        created_at_unix: unix_now_secs(),
        resolved_match: None,
        resolved_matches: Vec::new(),
    };
    let mut before_post = |submit_identity: String,
                           final_cursor: dexdo_core::MatchWatchCursor,
                           note_shell_balance: u128| {
        if let Some(frame_model) = human_model {
            println!(
                "{}",
                render_buyer_human_preflight(
                    frame_model,
                    selection,
                    ticks,
                    max_price_per_tick,
                    escrow,
                    note_shell_balance,
                )
            );
        }
        if note_shell_balance < escrow {
            return Err(ChainError::Chain(format!(
                "buyer preflight failed: insufficient Note SHELL balance required={escrow} \
                 available={note_shell_balance}; no escrow was sent"
            )));
        }
        let mut journal = template.clone();
        journal.submit_identity = submit_identity;
        journal.cursor = final_cursor;
        write_buyer_submit_journal(journal_path, &journal).map_err(|error| {
            ChainError::Chain(format!(
                "persist buyer submit journal before POST: {error:#}; no BOC was sent"
            ))
        })
    };
    chain
        .place_buy_by_model_with_submit_identity(
            buyer.note.as_ref(),
            selection.quoted_order.as_ref(),
            ticks,
            max_price_per_tick,
            escrow,
            cursor,
            &mut before_post,
        )
        .await
        .map_err(anyhow::Error::new)
}

#[cfg(feature = "shellnet")]
#[allow(dead_code)]
fn persist_resolved_buyer_submits(
    journal_path: &std::path::Path,
    note_addr: &str,
    matches: &[BuyerJournalMatch],
) -> Result<()> {
    let first = matches
        .first()
        .ok_or_else(|| anyhow::anyhow!("cannot persist an empty buyer submit reconciliation"))?;
    let mut journal = load_buyer_submit_journal(journal_path, note_addr)?.ok_or_else(|| {
        anyhow::anyhow!(
            "buyer submit journal {} disappeared after money moved",
            journal_path.display()
        )
    })?;
    journal.resolved_match = Some(first.clone());
    journal.resolved_matches = matches.to_vec();
    write_buyer_submit_journal(journal_path, &journal)?;
    for matched in matches {
        persist_buyer_token_contract_for_note_result(Some(note_addr), &matched.token_contract)?;
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
#[allow(dead_code, clippy::too_many_arguments)]
async fn complete_buyer_submit_with_journal(
    chain: &dyn ChainBackend,
    quoted_order: Option<&OrderBookOrder>,
    ticks: u128,
    max_price_per_tick: u128,
    submit_result: Result<()>,
    note_addr: &str,
    journal_path: &std::path::Path,
) -> Result<(dexdo_core::TokenContract, MatchedTokenContractStatus)> {
    if let Err(error) = &submit_result {
        if money_submit_error_clears_journal(error) {
            clear_buyer_submit_journal(journal_path)?;
            return submit_result.map(|_| unreachable!());
        }
        if !is_ambiguous_submit_error(error) {
            return Err(anyhow::Error::new(ChainError::AmbiguousSubmit(format!(
                "unclassified money submit outcome; journal retained and no resubmit is safe: {error:#}"
            ))));
        }
    }
    let fill = chain
        .wait_matched_token_contract(0, std::time::Duration::from_secs(DEAL_WAIT_SECS))
        .await
        .map_err(|error| {
            anyhow::Error::new(ChainError::AmbiguousSubmit(format!(
                "buyer money POST may have landed but its MatchedFill is not yet provable; journal retained and no resubmit is safe: {error}"
            )))
        })?
        .ok_or_else(|| {
            anyhow::Error::new(ChainError::AmbiguousSubmit(
                "buyer money POST may have landed but returned no MatchedFill; journal retained"
                    .to_string(),
            ))
        })?;
    let expected = quoted_order.and_then(|order| {
        order
            .token_contract
            .as_ref()
            .map(|token_contract| dexdo_core::QuoteFill {
                order_id: order.order_id,
                token_contract: token_contract.clone(),
                ticks,
                price_per_tick: order.price_per_tick,
                cost_with_fee: 0,
            })
    });
    let token_contract =
        correlated_buy_token_contract(fill.clone(), expected.as_ref(), ticks, max_price_per_tick)
            .map_err(anyhow::Error::new)?;
    let resolved = journal_match(&fill);
    persist_resolved_buyer_submits(journal_path, note_addr, &[resolved])?;
    let status = validate_reported_match_state(chain, &token_contract)
        .await
        .map_err(anyhow::Error::new)?;
    clear_buyer_submit_journal(journal_path)?;
    Ok((token_contract, status))
}

#[cfg(feature = "shellnet")]
#[allow(dead_code)]
async fn reconcile_pending_buyer_submit(
    chain: &dyn ChainBackend,
    note_addr: &str,
    journal_path: &std::path::Path,
    wait: Option<std::time::Duration>,
) -> Result<Option<(dexdo_core::TokenContract, MatchedTokenContractStatus)>> {
    let Some(journal) = load_buyer_submit_journal(journal_path, note_addr)? else {
        return Ok(None);
    };
    let fills = if !journal.resolved_matches.is_empty() {
        journal
            .resolved_matches
            .iter()
            .map(|matched| dexdo_core::MatchedFill {
                order_id: matched.order_id,
                token_contract: matched.token_contract.clone(),
                ticks: matched.ticks,
                price_per_tick: matched.clearing_price,
            })
            .collect::<Vec<_>>()
    } else {
        let mut cursor = journal.cursor.clone();
        let started = std::time::Instant::now();
        loop {
            let fills = chain
                .poll_matched_model_buys_for_order_book(&journal.order_book, &mut cursor)
                .await
                .map_err(|error| match error {
                    ChainError::Transport(_) => anyhow::Error::new(error),
                    _ => anyhow::Error::new(ChainError::AmbiguousSubmit(format!(
                        "could not reconcile durable buyer submit {}; journal retained: {error}",
                        journal.submit_identity
                    ))),
                })?;
            if !fills.is_empty() {
                break fills;
            }
            let Some(timeout) = wait else {
                return Err(anyhow::Error::new(ChainError::AmbiguousSubmit(format!(
                    "durable buyer submit {} is unresolved; journal retained and no BOC was sent",
                    journal.submit_identity
                ))));
            };
            if started.elapsed() >= timeout {
                return Err(anyhow::Error::new(ChainError::AmbiguousSubmit(format!(
                    "timed out reconciling durable buyer submit {}; journal retained",
                    journal.submit_identity
                ))));
            }
            tokio::time::sleep(BUYER_SUBMIT_RECONCILE_POLL_INTERVAL).await;
        }
    };
    let expected = journal.quote.fills.first();
    let matching = fills
        .iter()
        .filter(|fill| {
            correlated_buy_token_contract(
                (*fill).clone(),
                expected,
                journal.ticks,
                journal.max_price_per_tick,
            )
            .is_ok()
        })
        .cloned()
        .collect::<Vec<_>>();
    if !matching.is_empty() {
        let resolved = matching.iter().map(journal_match).collect::<Vec<_>>();
        persist_resolved_buyer_submits(journal_path, note_addr, &resolved)?;
    }
    if matching.len() != 1 {
        return Err(anyhow::Error::new(ChainError::AmbiguousSubmit(format!(
            "durable buyer submit {} produced {} correlated fills; journal retained",
            journal.submit_identity,
            matching.len()
        ))));
    }
    let fill = &matching[0];
    let status = validate_reported_match_state(chain, &fill.token_contract)
        .await
        .map_err(anyhow::Error::new)?;
    Ok(Some((fill.token_contract.clone(), status)))
}

#[cfg(feature = "shellnet")]
#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
enum DurableBuyerSubmitStart {
    Submitted {
        result: Result<()>,
    },
    Reconciled {
        proof: BuyerJournalResumeProof,
        token_contract: dexdo_core::TokenContract,
        status: MatchedTokenContractStatus,
    },
}

#[cfg(feature = "shellnet")]
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct BuyerJournalResumeProof {
    order_book: String,
    submit_identity: String,
    submit_reconciliation: dexdo::buyer::api::BuyerSubmitReconciliation,
    intent: BuyerSubmitIntent,
    expected_token_contract: Option<dexdo_core::TokenContract>,
    quoted_order: OrderBookOrder,
    quote: ExecutableQuote,
    ticks: u128,
    max_price_per_tick: u128,
    escrow: u128,
}

#[cfg(feature = "shellnet")]
impl BuyerJournalResumeProof {
    fn from_journal(journal: &BuyerSubmitJournal) -> Result<Self> {
        Ok(Self {
            order_book: journal.order_book.clone(),
            submit_identity: journal.submit_identity.clone(),
            submit_reconciliation: buyer_submit_reconciliation(
                journal,
                dexdo::buyer::api::BuyerSubmitReconciliationState::RecoveredProven,
                dexdo::buyer::api::BuyerSubmitReconciliationOrigin::DurableJournal,
            )?,
            intent: journal.intent.clone(),
            expected_token_contract: journal.expected_token_contract.clone(),
            quoted_order: journal.quoted_order.clone(),
            quote: journal.quote.clone(),
            ticks: journal.ticks,
            max_price_per_tick: journal.max_price_per_tick,
            escrow: journal.escrow,
        })
    }
}

#[cfg(feature = "shellnet")]
#[derive(Debug)]
struct DurableBuyerSubmitReconciliationError {
    deal_init: dexdo::buyer::api::DealInitError,
    source: ChainError,
}

#[cfg(feature = "shellnet")]
impl std::fmt::Display for DurableBuyerSubmitReconciliationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.deal_init.fmt(formatter)
    }
}

#[cfg(feature = "shellnet")]
impl std::error::Error for DurableBuyerSubmitReconciliationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[cfg(feature = "shellnet")]
fn durable_buyer_submit_reconciliation_error(
    error: anyhow::Error,
    journal: &BuyerSubmitJournal,
) -> anyhow::Error {
    if !is_ambiguous_submit_error(&error) {
        return error;
    }
    let message = format!("{error:#}");
    match buyer_submit_reconciliation(
        journal,
        dexdo::buyer::api::BuyerSubmitReconciliationState::DurableUnresolved,
        dexdo::buyer::api::BuyerSubmitReconciliationOrigin::DurableJournal,
    ) {
        Ok(reconciliation) => anyhow::Error::new(DurableBuyerSubmitReconciliationError {
            deal_init: dexdo::buyer::api::DealInitError::with_reconciliation(
                message.clone(),
                reconciliation,
            ),
            source: ChainError::AmbiguousSubmit(message),
        }),
        Err(reconciliation_error) => error.context(format!(
            "could not preserve durable buyer submit recovery facts: {reconciliation_error:#}"
        )),
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct BuyerQuoteSubmitOutcome {
    token_contract: dexdo_core::TokenContract,
    status: MatchedTokenContractStatus,
    ticks: u128,
    max_price_per_tick: u128,
    escrow: u128,
    submit_reconciliation: Option<dexdo::buyer::api::BuyerSubmitReconciliation>,
}

#[cfg(feature = "shellnet")]
#[allow(clippy::too_many_arguments)]
async fn raise_pending_buyer_money_before_fresh_reads(
    chain: &dyn ChainBackend,
    buyer: &dexdo::buyer::Buyer,
    note_addr: Option<&str>,
    intent: &BuyerSubmitIntent,
    expected_token_contract: Option<&str>,
    ticks: u128,
    max_price_per_tick: u128,
    escrow: u128,
) -> Result<Option<BuyerQuoteSubmitOutcome>> {
    let mut money_lock = buyer_money_lock_for_submit(false, note_addr)?
        .ok_or_else(|| anyhow::anyhow!("real shellnet buyer recovery requires a money lock"))?;
    money_lock.try_acquire()?;
    let journal_note = money_lock.note_addr.clone();
    let journal_path = money_lock.journal_path.clone();
    let Some(journal) = load_buyer_money_journal(&journal_path, &journal_note)? else {
        return Ok(None);
    };
    let pending = match journal {
        BuyerMoneyJournal::Buy(pending) => *pending,
        BuyerMoneyJournal::Subscription(pending) => bail!(
            "buyer note {} has unresolved subscription submit {} in {}; reconcile it with `dexdo \
             subscription place` before a quote-bound buy",
            pending.note_addr,
            pending.submit_identity,
            pending.order_book
        ),
    };
    let selection = BuyerQuoteSelection {
        order_book: if pending.expected_token_contract.is_some() {
            "explicit_token_contract"
        } else {
            "model_order_book"
        },
        escrow: pending.escrow,
        quote: pending.quote.clone(),
        quoted_order: Some(pending.quoted_order.clone()),
    };
    match start_durable_buyer_submit(
        chain,
        buyer,
        intent,
        expected_token_contract,
        &selection,
        ticks,
        max_price_per_tick,
        escrow,
        &journal_note,
        &journal_path,
        None,
    )
    .await?
    {
        DurableBuyerSubmitStart::Reconciled {
            proof,
            token_contract,
            status,
        } => Ok(Some(BuyerQuoteSubmitOutcome {
            token_contract,
            status,
            ticks: proof.ticks,
            max_price_per_tick: proof.max_price_per_tick,
            escrow: proof.escrow,
            submit_reconciliation: Some(proof.submit_reconciliation),
        })),
        DurableBuyerSubmitStart::Submitted { .. } => unreachable!(
            "a durable journal loaded before fresh reads cannot start a second submission"
        ),
    }
}

#[cfg(feature = "shellnet")]
fn clear_adopted_buyer_money_journal(
    note_addr: Option<&str>,
    submit_identity: Option<&str>,
    token_contract: &str,
) -> Result<()> {
    let Some(submit_identity) = submit_identity else {
        return Ok(());
    };
    let mut money_lock = buyer_money_lock_for_submit(false, note_addr)?
        .ok_or_else(|| anyhow::anyhow!("adopted buyer journal requires a money lock"))?;
    money_lock.try_acquire()?;
    let journal = load_buyer_submit_journal(&money_lock.journal_path, &money_lock.note_addr)?
        .ok_or_else(|| anyhow::anyhow!("adopted buyer journal disappeared before service start"))?;
    let resolved = journal
        .resolved_matches
        .iter()
        .chain(journal.resolved_match.iter())
        .any(|matched| matched.token_contract.eq_ignore_ascii_case(token_contract));
    if journal.submit_identity != submit_identity || !resolved {
        bail!("adopted buyer journal changed before service start; refusing to clear it");
    }
    clear_buyer_submit_journal(&money_lock.journal_path)
}

#[cfg(not(feature = "shellnet"))]
fn clear_adopted_buyer_money_journal(
    _note_addr: Option<&str>,
    _submit_identity: Option<&str>,
    _token_contract: &str,
) -> Result<()> {
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
#[allow(clippy::too_many_arguments)]
async fn raise_pending_buyer_money_before_fresh_reads(
    _chain: &dyn ChainBackend,
    _buyer: &dexdo::buyer::Buyer,
    _note_addr: Option<&str>,
    _intent: &BuyerSubmitIntent,
    _expected_token_contract: Option<&str>,
    _ticks: u128,
    _max_price_per_tick: u128,
    _escrow: u128,
) -> Result<Option<BuyerQuoteSubmitOutcome>> {
    Ok(None)
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct BuyerSubmitProgress {
    reconciled_ambiguous_submit: bool,
    submit_reconciliation: Option<dexdo::buyer::api::BuyerSubmitReconciliation>,
}

#[cfg(feature = "shellnet")]
#[allow(dead_code, clippy::too_many_arguments)]
fn ensure_pending_buyer_submit_matches_invocation(
    pending: &BuyerSubmitJournal,
    intent: &BuyerSubmitIntent,
    expected_token_contract: Option<&str>,
    selection: &BuyerQuoteSelection,
    ticks: u128,
    max_price_per_tick: u128,
    escrow: u128,
) -> Result<()> {
    let expected_token_contract = expected_token_contract
        .map(|address| dexdo_core::Address::parse(address).map(|address| address.with_workchain()))
        .transpose()
        .map_err(|error| anyhow::anyhow!("buyer restart expected TokenContract: {error}"))?;
    if pending.intent == *intent
        && pending.expected_token_contract == expected_token_contract
        && selection.quoted_order.as_ref() == Some(&pending.quoted_order)
        && selection.quote == pending.quote
        && selection.escrow == pending.escrow
        && ticks == pending.ticks
        && max_price_per_tick == pending.max_price_per_tick
        && escrow == pending.escrow
    {
        return Ok(());
    }
    Err(anyhow::Error::new(ChainError::AmbiguousSubmit(format!(
        "durable buyer submit {} belongs to a different logical invocation; no new BOC was sent",
        pending.submit_identity
    ))))
}

#[cfg(feature = "shellnet")]
fn render_buyer_human_preflight(
    frame_model: &str,
    selection: &BuyerQuoteSelection,
    ticks: u128,
    max_price_per_tick: u128,
    escrow: u128,
    note_shell_balance: u128,
) -> String {
    let fill = &selection.quote.fills[0];
    let fee = fill
        .cost_with_fee
        .saturating_sub(fill.ticks.saturating_mul(fill.price_per_tick));
    format!(
        "BUYER_PREFLIGHT model={frame_model} requested_ticks={ticks} \
         minimum_ticks={} best_ask={} \
         max_price_per_tick={max_price_per_tick} escrow={escrow} fee={fee} \
         note_shell_balance={note_shell_balance} order_id={} token_contract={} \
         matchable=true balance_sufficient={}",
        dexdo_core::params::MIN_STREAM_BUY_TICKS,
        fill.price_per_tick,
        fill.order_id,
        fill.token_contract,
        note_shell_balance >= escrow
    )
}

#[cfg(feature = "shellnet")]
#[allow(dead_code, clippy::too_many_arguments)]
async fn start_durable_buyer_submit(
    chain: &dyn ChainBackend,
    buyer: &dexdo::buyer::Buyer,
    intent: &BuyerSubmitIntent,
    expected_token_contract: Option<&str>,
    selection: &BuyerQuoteSelection,
    ticks: u128,
    max_price_per_tick: u128,
    escrow: u128,
    note_addr: &str,
    journal_path: &std::path::Path,
    human_model: Option<&str>,
) -> Result<DurableBuyerSubmitStart> {
    intent.validate()?;
    if let Some(pending) = load_buyer_submit_journal(journal_path, note_addr)? {
        if pending.intent.kind == BuyerSubmitIntentKind::LegacyUnknown {
            reconcile_pending_buyer_submit(chain, note_addr, journal_path, None).await?;
            return Err(anyhow::Error::new(ChainError::AmbiguousSubmit(format!(
                "legacy durable buyer submit {} was reconciled for facts but cannot be adopted as a fresh intent; no new BOC was sent",
                pending.submit_identity
            ))));
        }
        let current_order_book = chain.model_buy_order_book_identity().ok_or_else(|| {
            anyhow::anyhow!(
                "real shellnet backend did not expose its canonical model order-book identity; no BOC was sent"
            )
        })?;
        if !pending.order_book.eq_ignore_ascii_case(&current_order_book) {
            return Err(anyhow::Error::new(ChainError::AmbiguousSubmit(format!(
                "durable buyer submit {} belongs to order book {}, current invocation is bound to {}; no chain read or new BOC was performed",
                pending.submit_identity, pending.order_book, current_order_book
            ))));
        }
        ensure_pending_buyer_submit_matches_invocation(
            &pending,
            intent,
            expected_token_contract,
            selection,
            ticks,
            max_price_per_tick,
            escrow,
        )?;
        if let Some((token_contract, status)) =
            reconcile_pending_buyer_submit(chain, note_addr, journal_path, None)
                .await
                .map_err(|error| durable_buyer_submit_reconciliation_error(error, &pending))?
        {
            return Ok(DurableBuyerSubmitStart::Reconciled {
                proof: BuyerJournalResumeProof::from_journal(&pending)?,
                token_contract,
                status,
            });
        }
    }
    preflight_buyer_pool_for_note(Some(note_addr))?;
    let mut cursor = dexdo_core::MatchWatchCursor::default();
    let result = place_quote_bound_buy_with_journal(
        chain,
        buyer,
        intent,
        expected_token_contract,
        selection,
        ticks,
        max_price_per_tick,
        escrow,
        note_addr,
        &mut cursor,
        journal_path,
        human_model,
    )
    .await;
    Ok(DurableBuyerSubmitStart::Submitted { result })
}

#[allow(dead_code, clippy::too_many_arguments)]
async fn execute_buyer_quote_submit<F, Fut>(
    chain: &dyn ChainBackend,
    buyer: &dexdo::buyer::Buyer,
    mock_chain: bool,
    note_addr: Option<&str>,
    intent: &BuyerSubmitIntent,
    expected_token_contract: Option<&str>,
    selection: &BuyerQuoteSelection,
    ticks: u128,
    max_price_per_tick: u128,
    escrow: u128,
    human_model: Option<&str>,
    mut on_submit_observed: F,
) -> Result<BuyerQuoteSubmitOutcome>
where
    F: FnMut(BuyerSubmitProgress) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    #[cfg(not(feature = "shellnet"))]
    let _ = (intent, expected_token_contract, human_model);

    #[cfg(feature = "shellnet")]
    if !mock_chain {
        let mut money_lock = buyer_money_lock_for_submit(false, note_addr)?
            .ok_or_else(|| anyhow::anyhow!("real shellnet buyer submit requires a money lock"))?;
        money_lock.try_acquire()?;
        let journal_note = money_lock.note_addr.clone();
        let journal_path = money_lock.journal_path.clone();
        match start_durable_buyer_submit(
            chain,
            buyer,
            intent,
            expected_token_contract,
            selection,
            ticks,
            max_price_per_tick,
            escrow,
            &journal_note,
            &journal_path,
            human_model,
        )
        .await?
        {
            DurableBuyerSubmitStart::Reconciled {
                proof,
                token_contract,
                status,
            } => {
                on_submit_observed(BuyerSubmitProgress {
                    reconciled_ambiguous_submit: true,
                    submit_reconciliation: Some(proof.submit_reconciliation.clone()),
                })
                .await?;
                return Ok(BuyerQuoteSubmitOutcome {
                    token_contract,
                    status,
                    ticks: proof.ticks,
                    max_price_per_tick: proof.max_price_per_tick,
                    escrow: proof.escrow,
                    submit_reconciliation: Some(proof.submit_reconciliation),
                });
            }
            DurableBuyerSubmitStart::Submitted { result } => {
                let ambiguous_submit = result.as_ref().is_err_and(is_ambiguous_submit_error);
                let submit_reconciliation = if ambiguous_submit {
                    let journal = load_buyer_submit_journal(&journal_path, &journal_note)?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "buyer submit journal {} disappeared after an ambiguous money submit",
                                journal_path.display()
                            )
                        })?;
                    Some(buyer_submit_reconciliation(
                        &journal,
                        dexdo::buyer::api::BuyerSubmitReconciliationState::FreshUnresolved,
                        dexdo::buyer::api::BuyerSubmitReconciliationOrigin::FreshSubmit,
                    )?)
                } else {
                    None
                };
                on_submit_observed(BuyerSubmitProgress {
                    reconciled_ambiguous_submit: ambiguous_submit,
                    submit_reconciliation: submit_reconciliation.clone(),
                })
                .await?;
                if intent.kind == BuyerSubmitIntentKind::OnDemand {
                    if let Some(reconciliation) = submit_reconciliation.clone() {
                        let anchor = &reconciliation.recovery_anchor;
                        return Err(anyhow::Error::new(
                            dexdo::buyer::api::DealInitError::with_reconciliation(
                                format!(
                                    "ambiguous submit {}; recovery anchor order {} / {}; durable journal retained -- resume without creating a fresh BOC",
                                    reconciliation.submit_identity,
                                    anchor.order_id,
                                    anchor.token_contract
                                ),
                                reconciliation,
                            ),
                        ));
                    }
                }
                let (token_contract, status) = complete_buyer_submit_with_journal(
                    chain,
                    selection.quoted_order.as_ref(),
                    ticks,
                    max_price_per_tick,
                    result,
                    &journal_note,
                    &journal_path,
                )
                .await?;
                return Ok(BuyerQuoteSubmitOutcome {
                    token_contract,
                    status,
                    ticks,
                    max_price_per_tick,
                    escrow,
                    submit_reconciliation,
                });
            }
        }
    }

    if let Some(token_contract) = expected_token_contract {
        let token_contract = token_contract.to_string();
        if !mock_chain {
            preflight_buyer_pool_for_note(note_addr)?;
        }
        buyer.place_buy(chain, &token_contract).await?;
        on_submit_observed(BuyerSubmitProgress {
            reconciled_ambiguous_submit: false,
            submit_reconciliation: None,
        })
        .await?;
        let status = validate_reported_match_state(chain, &token_contract).await?;
        return Ok(BuyerQuoteSubmitOutcome {
            token_contract,
            status,
            ticks,
            max_price_per_tick,
            escrow,
            submit_reconciliation: None,
        });
    }

    let since_unix = unix_now_secs() as i64;
    place_buy_by_model_after_pool_preflight(
        chain,
        buyer,
        !mock_chain,
        note_addr,
        ticks,
        max_price_per_tick,
        escrow,
    )
    .await?;
    on_submit_observed(BuyerSubmitProgress {
        reconciled_ambiguous_submit: false,
        submit_reconciliation: None,
    })
    .await?;
    let fill = chain
        .wait_matched_token_contract(since_unix, std::time::Duration::from_secs(DEAL_WAIT_SECS))
        .await?
        .ok_or_else(|| anyhow::anyhow!("buyer fill event returned no match"))?;
    let token_contract = correlated_buy_token_contract(
        fill,
        selection.quote.fills.first(),
        ticks,
        max_price_per_tick,
    )?;
    let status = validate_reported_match_state(chain, &token_contract).await?;
    Ok(BuyerQuoteSubmitOutcome {
        token_contract,
        status,
        ticks,
        max_price_per_tick,
        escrow,
        submit_reconciliation: None,
    })
}

fn record_buyer_token_contract_after_money_move(args: &BuyerArgs, token_contract: &str) {
    if let Err(e) = persist_buyer_token_contract_in_env_pool(args, token_contract) {
        tracing::warn!(
            token_contract = %token_contract,
            error = %e,
            "failed to persist buyer TokenContract recovery metadata after preflight; continuing handover/recovery"
        );
        eprintln!(
            "warning: failed to persist TokenContract recovery metadata in DEXDO_PN_POOL after buy; \
             continuing handover/recovery: {e}"
        );
    }
}

#[cfg(feature = "shellnet")]
fn persist_buyer_token_contract_in_env_pool(args: &BuyerArgs, token_contract: &str) -> Result<()> {
    if args.mock.mock_chain {
        return Ok(());
    }
    let Some(pool_path) = note_pool_path(None) else {
        return Ok(());
    };
    let note_addr = args.identity.note_addr.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "real shellnet: --note-addr is required to persist TokenContract in DEXDO_PN_POOL"
        )
    })?;
    persist_pool_token_contract_for_note(&pool_path, note_addr, token_contract, "buyer")
}

#[cfg(feature = "shellnet")]
fn persist_buyer_token_contract_for_note(note_addr: Option<&str>, token_contract: &str) {
    let Some(note_addr) = note_addr else {
        return;
    };
    let Some(pool_path) = note_pool_path(None) else {
        return;
    };
    if let Err(e) =
        persist_pool_token_contract_for_note(&pool_path, note_addr, token_contract, "buyer")
    {
        tracing::warn!(
            token_contract = %token_contract,
            note_addr,
            pool = %pool_path.display(),
            error = %e,
            "failed to persist buyer TokenContract recovery metadata in DEXDO_PN_POOL"
        );
    }
}

#[cfg(not(feature = "shellnet"))]
fn persist_buyer_token_contract_in_env_pool(
    _args: &BuyerArgs,
    _token_contract: &str,
) -> Result<()> {
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
fn persist_buyer_token_contract_for_note(_note_addr: Option<&str>, _token_contract: &str) {}

fn reject_buyer_raw_token_contract_without_registry_book_proof(
    market: Option<&std::path::Path>,
    token_contract: Option<&str>,
    frame_model: &str,
) -> Result<()> {
    if market.is_none() {
        if let Some(tc) = token_contract {
            bail!(
                "buyer model registry check failed: frame_model {frame_model} raw --token-contract {tc} has no \
                 canonical order-book proof; with buyer.check_model_registry=true, pass --market <manifest> \
                 from the canonical registry book or omit --token-contract for a model-only registry buy/resume"
            );
        }
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
async fn resolve_content_identity_model(
    contracts: &std::path::Path,
    frame_model: &str,
) -> Result<String> {
    let registry_address = default_model_registry_address(contracts).map_err(|e| {
        anyhow!(
            "read default ModelRegistry address from {} for content identity: {e}",
            contracts.display()
        )
    })?;
    let reader = ShellnetModelRegistryReader::from_manifest(contracts, &registry_address)?;
    let identity = resolve_registered_model_identity(
        &reader,
        RegistryRole::Buyer,
        &registry_address,
        frame_model,
    )
    .await?;
    Ok(identity.registry_model)
}

#[cfg(not(feature = "shellnet"))]
async fn resolve_content_identity_model(
    contracts: &std::path::Path,
    frame_model: &str,
) -> Result<String> {
    let _ = (contracts, frame_model);
    bail!("content identity ModelRegistry resolution requires a shellnet build")
}

fn buyer_content_identity_resolution_result(
    frame_model: &str,
    allow_unverified_model: bool,
    result: Result<String>,
) -> Result<Option<String>> {
    match result {
        Ok(identity_model) => Ok(Some(identity_model)),
        Err(error) if allow_unverified_model => {
            tracing::warn!(
                %frame_model,
                error = %error,
                "content identity registry resolution failed; continuing on name-only evidence because --allow-unverified-model was set"
            );
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

async fn resolve_buyer_content_identity_model(
    contracts: &std::path::Path,
    frame_model: &str,
    allow_unverified_model: bool,
) -> Result<Option<String>> {
    buyer_content_identity_resolution_result(
        frame_model,
        allow_unverified_model,
        resolve_content_identity_model(contracts, frame_model).await,
    )
}

async fn build_buyer_content_policy(
    args: &BuyerArgs,
    frame_model: &str,
) -> Result<(
    dexdo::buyer::api::ContentCheck,
    Arc<dexdo::seller::ModelsConfig>,
)> {
    let content_identity_model = if args.mock.mock_chain {
        None
    } else {
        resolve_buyer_content_identity_model(
            &args.contracts,
            frame_model,
            args.allow_unverified_model,
        )
        .await?
    };
    let content_identity_model_ref = content_identity_model.as_deref();
    let content_check_model = content_identity_model_ref.unwrap_or(frame_model);
    let models_cfg = Arc::new(dexdo::seller::ModelsConfig::load_or_empty(&args.models)?);
    let executable_reference_model =
        dexdo::buyer::verify::executable_reference_model_for(content_check_model, &models_cfg);
    if !args.mock.mock_model && !args.allow_unverified_model && executable_reference_model.is_none()
    {
        bail!(
            "model `{frame_model}` has no available exact buyer reference; refusing before \
             backend/quote/buy. Pass --allow-unverified-model to proceed without this preflight"
        );
    }
    let policy_model = executable_reference_model.or(content_identity_model_ref);
    let content_check = dexdo::buyer::api::content_check_policy(
        frame_model,
        policy_model,
        args.mock.mock_model,
        args.allow_unverified_model,
        executable_reference_model.is_some(),
        &models_cfg,
    )
    .map_err(|e| {
        anyhow!(
            "buyer content-identity preflight failed before buy: \
             missing_or_unset=allow_unverified_model_or_models_data; {e}"
        )
    })?;
    Ok((content_check, models_cfg))
}
#[derive(Debug, Clone)]
struct BuyerQuoteSelection {
    order_book: &'static str,
    escrow: u128,
    quote: ExecutableQuote,
    #[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
    quoted_order: Option<OrderBookOrder>,
}

fn shell_arg(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn buyer_read_only_quote_command(
    args: &BuyerArgs,
    frame_model: &str,
    ticks: u128,
    max_price_per_tick: u128,
) -> String {
    let source = if let Some(market) = args.market.as_deref() {
        format!(" --market {}", shell_arg(&market.to_string_lossy()))
    } else if let Some(note_addr) = args.identity.note_addr.as_deref() {
        format!(" --note-addr {}", shell_arg(note_addr))
    } else {
        String::new()
    };
    let mut command = format!(
        "dexdo executable-book {} --ticks {ticks} --max-price-per-tick {max_price_per_tick}{source} \
         --models {} --contracts {}",
        shell_arg(frame_model),
        shell_arg(&args.models.to_string_lossy()),
        shell_arg(&args.contracts.to_string_lossy())
    );
    if let Some(path) = args.registry.model_registry_validation.as_deref() {
        command.push_str(&format!(
            " --model-registry-validation {}",
            shell_arg(&path.to_string_lossy())
        ));
    }
    if let Some(address) = args.registry.model_registry_address.as_deref() {
        command.push_str(&format!(" --model-registry-address {}", shell_arg(address)));
    }
    command
}

fn human_buyer_quote_error(error: anyhow::Error, next_command: &str) -> anyhow::Error {
    let detail = format!("{error:#}");
    let lower = detail.to_ascii_lowercase();
    let reason = if (lower.contains("best ask price")
        && lower.contains("above buyer max_price_per_tick"))
        || (lower.contains("the expected ask exists but is not matchable by this buy:")
            && lower.contains(", price ")
            && lower.contains("buyer max_price_per_tick"))
    {
        "ceiling_below_best_ask"
    } else if lower.contains("the shared model book would match")
        && lower.contains("refusing to send escrow into the wrong deal")
    {
        "wrong_target"
    } else if lower.contains("no_executable_ask")
        || lower.contains("no executable matching ask")
        || lower.contains("no matchable ask")
    {
        "no_executable_ask"
    } else {
        return error;
    };
    anyhow!(
        "BUYER_PREFLIGHT matchable=false reason={reason} detail={detail}\nnext_command={next_command}"
    )
}

#[cfg(feature = "shellnet")]
#[allow(dead_code, clippy::too_many_arguments)]
fn pending_buyer_submit_selection(
    journal_path: &std::path::Path,
    note_addr: &str,
    intent: &BuyerSubmitIntent,
    expected_token_contract: Option<&str>,
    ticks: u128,
    max_price_per_tick: u128,
    escrow: u128,
) -> Result<Option<BuyerQuoteSelection>> {
    let Some(pending) = load_buyer_submit_journal(journal_path, note_addr)? else {
        return Ok(None);
    };
    if pending.intent.kind == BuyerSubmitIntentKind::LegacyUnknown {
        return Err(anyhow::Error::new(ChainError::AmbiguousSubmit(format!(
            "legacy durable buyer submit {} cannot be adopted as a fresh intent; no quote was read and no BOC was sent",
            pending.submit_identity
        ))));
    }
    let selection = BuyerQuoteSelection {
        order_book: if pending.expected_token_contract.is_some() {
            "explicit_token_contract"
        } else {
            "model_order_book"
        },
        escrow: pending.escrow,
        quote: pending.quote.clone(),
        quoted_order: Some(pending.quoted_order.clone()),
    };
    ensure_pending_buyer_submit_matches_invocation(
        &pending,
        intent,
        expected_token_contract,
        &selection,
        ticks,
        max_price_per_tick,
        escrow,
    )?;
    Ok(Some(selection))
}

#[allow(clippy::too_many_arguments)]
async fn buyer_quote_selection_for_submit(
    chain: &dyn ChainBackend,
    mock_chain: bool,
    note_addr: Option<&str>,
    intent: &BuyerSubmitIntent,
    explicit_tc: Option<&str>,
    ticks: u128,
    max_price_per_tick: u128,
    escrow: Option<u128>,
    human_context: Option<(&BuyerArgs, &str)>,
) -> Result<BuyerQuoteSelection> {
    #[cfg(feature = "shellnet")]
    if !mock_chain {
        intent.validate()?;
        preflight_buyer_pool_for_note(note_addr)?;
        let money_lock = buyer_money_lock_for_submit(false, note_addr)?
            .ok_or_else(|| anyhow::anyhow!("real shellnet quote requires a money lock"))?;
        let submitted_escrow =
            escrow.unwrap_or_else(|| required_escrow_for_buy(ticks, max_price_per_tick));
        if let Some(selection) = pending_buyer_submit_selection(
            &money_lock.journal_path,
            &money_lock.note_addr,
            intent,
            explicit_tc,
            ticks,
            max_price_per_tick,
            submitted_escrow,
        )? {
            return Ok(selection);
        }
    }
    #[cfg(not(feature = "shellnet"))]
    let _ = (mock_chain, note_addr, intent);

    buyer_quote_selection(chain, explicit_tc, ticks, max_price_per_tick, escrow)
        .await
        .map_err(|error| {
            let Some((args, frame_model)) = human_context else {
                return error;
            };
            let next_command =
                buyer_read_only_quote_command(args, frame_model, ticks, max_price_per_tick);
            human_buyer_quote_error(error, &next_command)
        })
}

async fn buyer_quote_selection(
    chain: &dyn ChainBackend,
    explicit_tc: Option<&str>,
    ticks: u128,
    max_price_per_tick: u128,
    escrow: Option<u128>,
) -> Result<BuyerQuoteSelection> {
    let mut delay = TRANSIENT_QUOTE_INITIAL_BACKOFF;
    for attempt in 0..TRANSIENT_QUOTE_ATTEMPTS {
        match buyer_quote_selection_once(chain, explicit_tc, ticks, max_price_per_tick, escrow)
            .await
        {
            Err(error)
                if attempt + 1 < TRANSIENT_QUOTE_ATTEMPTS
                    && error.chain().any(|cause| {
                        matches!(
                            cause.downcast_ref::<ChainError>(),
                            Some(ChainError::Transport(_))
                        )
                    }) =>
            {
                eprintln!(
                    "transient quote read failed on attempt {}/{}; retrying after {}ms: {error:#}",
                    attempt + 1,
                    TRANSIENT_QUOTE_ATTEMPTS,
                    delay.as_millis()
                );
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2);
            }
            result => return result,
        }
    }
    unreachable!("quote attempt count is nonzero")
}

async fn buyer_quote_selection_once(
    chain: &dyn ChainBackend,
    explicit_tc: Option<&str>,
    ticks: u128,
    max_price_per_tick: u128,
    escrow: Option<u128>,
) -> Result<BuyerQuoteSelection> {
    let mut explicit_submit_safe_order = None;
    let mut model_submit_safe_order = None;
    if explicit_tc.is_none() {
        model_submit_safe_order = chain
            .submit_safe_model_buy_quote_order(ticks, max_price_per_tick)
            .await
            .map_err(|e| anyhow::Error::new(e).context("buyer model-only quote preflight"))?;
    } else if let Some(tc) = explicit_tc {
        let tc_owned = tc.to_string();
        explicit_submit_safe_order = chain
            .submit_safe_explicit_buy_quote_order(&tc_owned, ticks, max_price_per_tick)
            .await
            .map_err(|e| anyhow::Error::new(e).context("buyer explicit-token quote preflight"))?;
        if explicit_submit_safe_order.is_none() {
            chain
                .assert_explicit_buy_matches_executable_quote(&tc_owned, ticks, max_price_per_tick)
                .await
                .map_err(|e| {
                    anyhow::Error::new(e).context("buyer explicit-token quote preflight")
                })?;
        }
    }
    let explicit_submit_safe_selected = explicit_submit_safe_order.is_some();
    let mut orders = if let Some(order) = explicit_submit_safe_order.or(model_submit_safe_order) {
        vec![order]
    } else {
        mock_orders_from_offers(chain.discover_offers().await?)
    };
    let order_book = if let Some(tc) = explicit_tc {
        if !explicit_submit_safe_selected {
            orders.retain(|o| o.token_contract.as_deref() == Some(tc));
            if orders.is_empty() {
                let tc_owned = tc.to_string();
                if let Some((price_per_tick, max_ticks)) = chain.sell_offer_terms(&tc_owned).await?
                {
                    orders.push(OrderBookOrder {
                        order_id: 1,
                        owner_note: String::new(),
                        token_contract: Some(tc_owned),
                        is_buy: false,
                        price_per_tick: u128::from(price_per_tick),
                        ticks: u128::from(max_ticks),
                        escrow: 0,
                        deadline: 0,
                        flags: 0,
                        timestamp: 0,
                    });
                }
            }
        }
        "explicit_token_contract"
    } else {
        "model_order_book"
    };
    orders.retain(|o| o.price_per_tick <= max_price_per_tick);
    let quote = if chain.requires_submit_safe_single_ask_quote() {
        submit_safe_single_ask_quote(&orders, Some(ticks), None)
    } else {
        executable_quote(&orders, Some(ticks), None)
    }
    .map_err(|e| anyhow::anyhow!("buyer quote: {e}"))?;
    let quoted_order = quote.fills.first().and_then(|fill| {
        orders
            .iter()
            .find(|order| order.order_id == fill.order_id)
            .cloned()
    });
    Ok(BuyerQuoteSelection {
        order_book,
        escrow: escrow.unwrap_or_else(|| required_escrow_for_buy(ticks, max_price_per_tick)),
        quote,
        quoted_order,
    })
}

fn quote_selected_fields(
    frame_model: &str,
    selection: &BuyerQuoteSelection,
    ticks: u128,
    max_price_per_tick: u128,
) -> serde_json::Value {
    let fills = selection
        .quote
        .fills
        .iter()
        .map(|fill| {
            let cost_without_fee = fill.ticks.saturating_mul(fill.price_per_tick);
            json!({
                "order_id": machine::amount(fill.order_id),
                "token_contract": fill.token_contract,
                "ticks": machine::amount(fill.ticks),
                "price_per_tick": machine::amount(fill.price_per_tick),
                "cost_without_fee": machine::amount(cost_without_fee),
                "platform_fee": machine::amount(fill.cost_with_fee.saturating_sub(cost_without_fee)),
                "cost_with_fee": machine::amount(fill.cost_with_fee)
            })
        })
        .collect::<Vec<_>>();
    json!({
        "frame_model": frame_model,
        "model_hash": model_hash_for(frame_model),
        "order_book": selection.order_book,
        "ticks": machine::amount(ticks),
        "max_price_per_tick": machine::amount(max_price_per_tick),
        "escrow": machine::amount(selection.escrow),
        "quote_complete": selection.quote.complete,
        "filled_ticks": machine::amount(selection.quote.filled_ticks),
        "total_with_fee": machine::amount(selection.quote.total_with_fee),
        "fills": fills
    })
}

fn buyer_submit_event_fields(
    frame_model: &str,
    order_book: &str,
    ticks: u128,
    max_price_per_tick: u128,
    escrow: u128,
    progress: BuyerSubmitProgress,
) -> serde_json::Value {
    let mut fields = json!({
        "frame_model": frame_model,
        "order_book": order_book,
        "ticks": machine::amount(ticks),
        "max_price_per_tick": machine::amount(max_price_per_tick),
        "escrow": machine::amount(escrow),
        "reconciled_ambiguous_submit": progress.reconciled_ambiguous_submit
    });
    if let Some(reconciliation) = progress.submit_reconciliation {
        fields["submit_reconciliation"] = json!(reconciliation);
    }
    fields
}

fn recovered_buyer_resume_selected_fields(
    frame_model: &str,
    outcome: &BuyerQuoteSubmitOutcome,
) -> Result<serde_json::Value> {
    let submit_reconciliation = outcome.submit_reconciliation.as_ref().ok_or_else(|| {
        anyhow::anyhow!("recovered buyer resume has no durable submit reconciliation")
    })?;
    let token_contract = dexdo_core::normalize_wallet_address(&outcome.token_contract)
        .map_err(|error| anyhow::anyhow!("recovered buyer TokenContract: {error}"))?;
    Ok(json!({
        "token_contract": token_contract,
        "role": "buyer",
        "source": "durable_journal",
        "deal_handle": deals::make_handle_id(&token_contract, deals::DealHandleRole::Buyer),
        "frame_model": frame_model,
        "submit_reconciliation": submit_reconciliation
    }))
}

fn fail_buyer_quote_selection(
    events: &mut machine::BuyerEventWriter,
    frame_model: &str,
    selection: &BuyerQuoteSelection,
    ticks: u128,
    max_price_per_tick: u128,
    context_fields: Value,
) -> Result<Option<()>> {
    let code = if selection.quote.filled_ticks == 0 {
        machine::ErrorCode::NoLiquidity
    } else if !selection.quote.complete {
        machine::ErrorCode::IncompleteQuote
    } else {
        return Ok(None);
    };
    let mut fields = quote_selected_fields(frame_model, selection, ticks, max_price_per_tick);
    merge_json_fields(&mut fields, context_fields);
    let failure_class = buyer_quote_failure_class(selection, code);
    if let serde_json::Value::Object(obj) = &mut fields {
        obj.insert("failure_class".to_string(), json!(failure_class));
        if failure_class == "no_executable_ask" {
            obj.insert("no_executable_ask".to_string(), json!(true));
        }
    }
    events.error(machine::OP_BUYER_START, code, fields)?;
    Ok(Some(()))
}

fn buyer_quote_failure_class(
    selection: &BuyerQuoteSelection,
    code: machine::ErrorCode,
) -> &'static str {
    if code == machine::ErrorCode::NoLiquidity && selection.order_book == "model_order_book" {
        "no_executable_ask"
    } else if code == machine::ErrorCode::NoLiquidity {
        "no_liquidity"
    } else {
        "incomplete_quote"
    }
}

fn merge_json_fields(base: &mut Value, extra: Value) {
    if let (Value::Object(base), Value::Object(extra)) = (base, extra) {
        for (k, v) in extra {
            base.insert(k, v);
        }
    }
}

/// Render the per-model inference order book before a model-only buy: reads the resting asks
/// (`discover_offers`) and delegates to [`print_book_table`], marking asks executable at
/// `--max-price-per-tick` and appending the buyer's order summary.
async fn render_inference_book(
    chain: &dyn ChainBackend,
    frame_model: &str,
    max_price_per_tick: u128,
    ticks: u128,
) -> Result<()> {
    chain
        .assert_model_buy_matches_executable_quote(ticks, max_price_per_tick)
        .await
        .map_err(|e| {
            anyhow::Error::new(e).context(format!(
                "could not read a submit-safe order book for {frame_model}"
            ))
        })?;
    let offers = chain.discover_offers().await.map_err(|e| {
        anyhow::Error::new(e).context(format!(
            "could not read a trustworthy order book for {frame_model}"
        ))
    })?;
    let rows: Vec<BookRow> = offers
        .iter()
        .map(|o| BookRow {
            price_per_tick: o.price_per_tick as u128,
            max_ticks: o.max_ticks as u128,
            token_contract: o.token_contract.to_string(),
        })
        .collect();
    print_book_table(frame_model, &rows, Some(max_price_per_tick), Some(ticks));
    Ok(())
}

/// After the book is shown, ask the operator for a numeric order parameter (how many ticks / the per-tick
/// price ceiling). On a TTY it prompts -- empty input keeps the `[default]`(the CLI flag). Non-interactive
/// (piped / headless / daemon) returns the default silently, so automated runs keep working from flags.
fn prompt_u128(label: &str, default: u128) -> u128 {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return default;
    }
    loop {
        print!("{label} [{default}]: ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return default;
        }
        let s = line.trim();
        if s.is_empty() {
            return default;
        }
        match s.parse::<u128>() {
            Ok(v) => return v,
            Err(_) => eprintln!("enter an integer (or Enter to keep {default})"),
        }
    }
}

fn buyer_renewal_threshold_tokens() -> u64 {
    const ENV: &str = "DEXDO_BUYER_RENEWAL_THRESHOLD_TOKENS";
    std::env::var(ENV)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or_else(|| {
            dexdo::buyer::continuity::ContinuityConfig::default().renewal_threshold_tokens
        })
}

fn elapsed_since(now_secs: u64, at: Option<u64>) -> u64 {
    at.filter(|v| *v > 0)
        .map(|v| now_secs.saturating_sub(v))
        .unwrap_or(0)
}

async fn validate_reported_match_state(
    chain: &dyn ChainBackend,
    token_contract: &dexdo_core::TokenContract,
) -> Result<MatchedTokenContractStatus, ChainError> {
    let state = chain.deal_state(token_contract).await?.ok_or_else(|| {
        ChainError::Chain(format!(
            "reported match {token_contract} has no readable TokenContract state; refusing to wait for handover"
        ))
    })?;
    check_matched_token_contract_state(
        token_contract,
        state,
        unix_now_secs(),
        MATCH_OPEN_TIMEOUT_SECS,
    )
    .map_err(ChainError::Chain)
}

fn matched_state_summary(
    token_contract: &dexdo_core::TokenContract,
    status: &MatchedTokenContractStatus,
) -> String {
    match status {
        MatchedTokenContractStatus::Opened => {
            format!("matched deal state: token_contract={token_contract} funded=true opened=true")
        }
        MatchedTokenContractStatus::FundedNeverOpened {
            funded_time,
            cleanup_after_unix,
            cleanup_ready,
            remaining_secs,
        } => format!(
            "matched deal state: token_contract={token_contract} funded=true opened=false \
             fundedTime={} cleanup_after={} cleanup_ready={} cleanup_wait_secs={}",
            funded_time
                .map(|v| v.to_string())
                .unwrap_or_else(|| "<missing>".to_string()),
            cleanup_after_unix
                .map(|v| v.to_string())
                .unwrap_or_else(|| "<unknown>".to_string()),
            cleanup_ready,
            remaining_secs
                .map(|v| v.to_string())
                .unwrap_or_else(|| "<unknown>".to_string())
        ),
    }
}

async fn handover_timeout_diagnostic(
    chain: &dyn ChainBackend,
    token_contract: &dexdo_core::TokenContract,
    last_error: &str,
) -> String {
    match validate_reported_match_state(chain, token_contract).await {
        Ok(status @ MatchedTokenContractStatus::FundedNeverOpened { .. }) => format!(
            "buyer: matched TokenContract {token_contract} is funded but the seller did not open/write handover \
             within {DEAL_WAIT_SECS}s. {}. This is a funded-never-opened deal; after MATCH_OPEN_TIMEOUT use \
             `dexdo reclaim --token-contract {token_contract} --note-addr <buyer-note> --note-key <buyer-key>` \
             to streamCleanup. Last handover read error: {last_error}",
            matched_state_summary(token_contract, &status)
        ),
        Ok(status) => format!(
            "buyer: the seller did not open the stream / did not write the handover within {DEAL_WAIT_SECS}s. \
             {}. Last handover read error: {last_error}",
            matched_state_summary(token_contract, &status)
        ),
        Err(state_err) => format!(
            "buyer: the seller did not open the stream / did not write the handover within {DEAL_WAIT_SECS}s, \
             and the post-match TC state check now fails: {state_err}. Last handover read error: {last_error}"
        ),
    }
}

fn is_malformed_handover_error(error: &anyhow::Error) -> bool {
    let msg = format!("{error:#}");
    msg.contains("malformed handover") || msg.contains("handover decrypt failed")
}

async fn apply_malformed_handover_policy(
    chain: &dyn ChainBackend,
    buyer: &dexdo::buyer::Buyer,
    token_contract: &dexdo_core::TokenContract,
    buyer_policy: &policy::BuyerRuntimePolicy,
    preserve_matched_subscription: bool,
    error: &anyhow::Error,
) -> Result<()> {
    if preserve_matched_subscription {
        bail!(
            "buyer: malformed handover for {token_contract}: {error}\n\
             policy_action failure_class=malformed_handover action={} token_contract={token_contract} \
             state=matched/subscription result=subscription_preserved chain_write_submitted=false",
            buyer_policy.malformed_handover.as_str()
        );
    }
    match buyer_policy.malformed_handover {
        policy::MalformedHandoverAction::Reclaim => {
            // A malformed handover means the deal is unusable; STOP recovers the escrow immediately. There
            // is no inactivity gate to wait out any more, and stopping returns everything except the
            // consumption already promoted.
            let settlement = chain.stop(token_contract, buyer.note.as_ref()).await?;
            bail!(
                "buyer: malformed handover for {token_contract}: {error}\n\
                 policy_action failure_class=malformed_handover action=reclaim token_contract={token_contract} \
                 state=funded/opened result=reclaimed settlement={settlement}"
            );
        }
        policy::MalformedHandoverAction::Dispute => {
            let settlement = chain.dispute(token_contract, buyer.note.as_ref()).await?;
            bail!(
                "buyer: malformed handover for {token_contract}: {error}\n\
                 policy_action failure_class=malformed_handover action=dispute token_contract={token_contract} \
                 state=funded/opened/disputed result=dispute_opened settlement={settlement}; \
                 warning=dispute_freezes_this_token_contract_buyer_D_and_seller_bond_until_resolution"
            );
        }
        policy::MalformedHandoverAction::FailClosed => {
            bail!(
                "buyer: malformed handover for {token_contract}: {error}\n\
                 policy_action failure_class=malformed_handover action=fail_closed token_contract={token_contract} \
                 state=funded/opened result=no_recovery_submitted"
            );
        }
    }
}

async fn policy_cleanup_unopened_after_match_timeout(
    chain: &dyn ChainBackend,
    token_contract: &dexdo_core::TokenContract,
    policy_action: policy::NoHandoverAfterMatchAction,
) -> Result<PolicyCleanupOutcome> {
    let status = validate_reported_match_state(chain, token_contract).await?;
    let MatchedTokenContractStatus::FundedNeverOpened {
        cleanup_ready,
        remaining_secs,
        ..
    } = status
    else {
        bail!(
            "policy_action failure_class=no_handover_after_match action={} token_contract={} \
             state={} result=not_cleanup_unopened_state",
            policy_action.as_str(),
            token_contract,
            matched_state_summary(token_contract, &status)
        );
    };
    if !cleanup_ready {
        let wait = remaining_secs
            .unwrap_or(MATCH_OPEN_TIMEOUT_SECS)
            .saturating_add(1);
        println!(
            "policy_action failure_class=no_handover_after_match action={} token_contract={} \
             state=funded/opened result=waiting_cleanup_ready wait_secs={wait}",
            policy_action.as_str(),
            token_contract
        );
        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
        let status = validate_reported_match_state(chain, token_contract).await?;
        match status {
            MatchedTokenContractStatus::Opened => {
                println!(
                    "policy_action failure_class=no_handover_after_match action={} token_contract={} \
                     state=funded/opened result=handover_opened_after_wait",
                    policy_action.as_str(),
                    token_contract
                );
                return Ok(PolicyCleanupOutcome::HandoverOpened);
            }
            MatchedTokenContractStatus::FundedNeverOpened {
                cleanup_ready: true,
                ..
            } => {}
            status => {
                bail!(
                    "policy_action failure_class=no_handover_after_match action={} token_contract={} \
                     state={} result=not_cleanup_unopened_state_after_wait",
                    policy_action.as_str(),
                    token_contract,
                    matched_state_summary(token_contract, &status)
                );
            }
        }
    }
    let settlement = chain.cleanup_unopened(token_contract).await?;
    println!(
        "policy_action failure_class=no_handover_after_match action={} token_contract={} \
         state=funded/opened result=cleanup_unopened_submitted settlement={settlement}",
        policy_action.as_str(),
        token_contract
    );
    Ok(PolicyCleanupOutcome::Cleaned(settlement))
}

enum PolicyCleanupOutcome {
    Cleaned(Settlement),
    HandoverOpened,
}

#[derive(Debug)]
enum NoHandoverPolicyOutcome {
    RetryCurrent,
    RetryNext(dexdo_core::TokenContract),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OneShotStreamPolicyOutcome {
    RetryCurrent,
    TerminalReport(String),
}

fn oneshot_stream_policy_report(
    failure_class: &str,
    action: &str,
    token_contract: &dexdo_core::TokenContract,
    submitted: bool,
) -> String {
    let (result, next_action) = match (failure_class, action, submitted) {
        ("dead_gateway", "retry_then_reclaim", true) => {
            ("reclaim_submitted", "observe_reclaim_status")
        }
        ("dead_gateway", "retry_then_reclaim", false) => (
            "reclaim_not_submitted",
            "retry_reclaim_or_run_dexdo_reclaim_after_timeout",
        ),
        ("dead_gateway", "next_seller", _) => (
            "policy_action_unsupported",
            "recover_current_deal_before_failover",
        ),
        ("dead_gateway", "fail_closed", _) => ("no_recovery_submitted", "operator_decision"),
        ("empty_stream", "reclaim", true) => ("reclaim_submitted", "observe_reclaim_status"),
        ("empty_stream", "reclaim", false) => (
            "reclaim_not_submitted",
            "retry_reclaim_or_run_dexdo_reclaim_after_timeout",
        ),
        ("empty_stream", "next_seller", _) => (
            "policy_action_unsupported",
            "recover_current_deal_before_failover",
        ),
        ("empty_stream", "fail_closed", _) => ("no_recovery_submitted", "operator_decision"),
        _ => ("policy_action_reported", "operator_decision"),
    };
    format!(
        "policy_action failure_class={failure_class} action={action} token_contract={token_contract} \
         state=funded/opened result={result} next_action={next_action}"
    )
}

async fn apply_oneshot_dead_gateway_policy(
    session: &dexdo::buyer::api::SessionSettle,
    token_contract: &dexdo_core::TokenContract,
    buyer_policy: Option<&policy::BuyerRuntimePolicy>,
    attempt: u64,
) -> OneShotStreamPolicyOutcome {
    let action = buyer_policy
        .map(|policy| policy.dead_gateway.as_str())
        .unwrap_or("retry_then_reclaim");
    if action == "retry_then_reclaim" && attempt == 1 {
        println!(
            "policy_action failure_class=dead_gateway action=retry_then_reclaim \
             token_contract={token_contract} state=funded/opened result=retrying_gateway attempt=2"
        );
        return OneShotStreamPolicyOutcome::RetryCurrent;
    }
    let heartbeat =
        dexdo_core::chain::HeartbeatGuard::new(Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let submitted = session
        .settle_dead_gateway("dead-gateway", &heartbeat)
        .await;
    OneShotStreamPolicyOutcome::TerminalReport(oneshot_stream_policy_report(
        "dead_gateway",
        action,
        token_contract,
        submitted,
    ))
}

async fn apply_oneshot_empty_stream_policy(
    session: &dexdo::buyer::api::SessionSettle,
    token_contract: &dexdo_core::TokenContract,
    buyer_policy: Option<&policy::BuyerRuntimePolicy>,
) -> String {
    let action = buyer_policy
        .map(|policy| policy.empty_stream.as_str())
        .unwrap_or("reclaim");
    let heartbeat =
        dexdo_core::chain::HeartbeatGuard::new(Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let submitted = session
        .settle_empty_stream("empty-stream", &heartbeat)
        .await;
    oneshot_stream_policy_report("empty_stream", action, token_contract, submitted)
}

#[allow(clippy::too_many_arguments)]
async fn apply_no_handover_after_match_policy(
    chain: &dyn ChainBackend,
    buyer: &dexdo::buyer::Buyer,
    token_contract: &dexdo_core::TokenContract,
    buyer_policy: &policy::BuyerRuntimePolicy,
    preserve_matched_subscription: bool,
    next_buy: Option<(u128, u128, u128)>,
    attempt: u64,
    diagnostic: &str,
    pool_note_addr: Option<&str>,
) -> Result<NoHandoverPolicyOutcome> {
    if preserve_matched_subscription {
        bail!(
            "{diagnostic}\npolicy_action failure_class=no_handover_after_match action={} \
             token_contract={token_contract} state=matched/subscription \
             result=subscription_preserved chain_write_submitted=false",
            buyer_policy.no_handover_after_match.as_str()
        );
    }
    match buyer_policy.no_handover_after_match {
        policy::NoHandoverAfterMatchAction::FailClosed => {
            bail!(
                "{diagnostic}\npolicy_action failure_class=no_handover_after_match action=fail_closed \
                 token_contract={token_contract} state=funded/opened result=no_recovery_submitted"
            );
        }
        policy::NoHandoverAfterMatchAction::WaitThenReclaim => {
            let outcome = policy_cleanup_unopened_after_match_timeout(
                chain,
                token_contract,
                buyer_policy.no_handover_after_match,
            )
            .await?;
            let PolicyCleanupOutcome::Cleaned(settlement) = outcome else {
                return Ok(NoHandoverPolicyOutcome::RetryCurrent);
            };
            bail!(
                "{diagnostic}\npolicy_action failure_class=no_handover_after_match action=wait_then_reclaim \
                 token_contract={token_contract} state=funded/opened result=money_reclaimed settlement={settlement}"
            );
        }
        policy::NoHandoverAfterMatchAction::NextSeller => {
            if attempt >= buyer_policy.max_sellers_to_try {
                bail!(
                    "{diagnostic}\npolicy_action failure_class=no_handover_after_match action=next_seller \
                     token_contract={token_contract} state=funded/opened result=max_sellers_to_try_reached \
                     max_sellers_to_try={}",
                    buyer_policy.max_sellers_to_try
                );
            }
            let Some((ticks, max_price, escrow)) = next_buy else {
                bail!(
                    "{diagnostic}\npolicy_action failure_class=no_handover_after_match action=next_seller \
                     token_contract={token_contract} state=funded/opened result=no_model_only_routing_context"
                );
            };
            let outcome = policy_cleanup_unopened_after_match_timeout(
                chain,
                token_contract,
                buyer_policy.no_handover_after_match,
            )
            .await?;
            if matches!(outcome, PolicyCleanupOutcome::HandoverOpened) {
                return Ok(NoHandoverPolicyOutcome::RetryCurrent);
            }
            let next_attempt = attempt.saturating_add(1);
            let projected_spend = escrow.saturating_mul(next_attempt as u128);
            if projected_spend > buyer_policy.total_spend_cap_shells as u128 {
                bail!(
                    "{diagnostic}\npolicy_action failure_class=no_handover_after_match action=next_seller \
                     token_contract={token_contract} state=funded/opened result=total_spend_cap_reached \
                     projected_spend_shells={projected_spend} cap_shells={}",
                    buyer_policy.total_spend_cap_shells
                );
            }
            println!(
                "policy_action failure_class=no_handover_after_match action=next_seller \
                 token_contract={token_contract} state=funded/opened result=placing_next_seller \
                 attempt={next_attempt}"
            );
            preflight_buyer_pool_for_note(pool_note_addr)?;
            let next =
                submit_buyer_monitor_next_deal(chain, buyer, ticks, max_price, escrow).await?;
            println!(
                "policy_action failure_class=no_handover_after_match action=next_seller \
                 token_contract={token_contract} state=funded/opened result=next_seller_matched \
                 next_token_contract={next}"
            );
            Ok(NoHandoverPolicyOutcome::RetryNext(next))
        }
    }
}

fn buyer_monitor_current_facts(
    token_contract: dexdo_core::TokenContract,
    remaining_tokens: u64,
    session_settled: bool,
    chain_state: Option<DealChainState>,
    now_secs: u64,
    last_accepted_output_secs: u64,
) -> dexdo::buyer::continuity::DealFacts {
    use dexdo::buyer::continuity::DealFacts;

    if session_settled {
        return DealFacts::closed(token_contract);
    }
    let Some(state) = chain_state else {
        return DealFacts::handover_ready(token_contract, remaining_tokens);
    };
    if state.disputed {
        return DealFacts::closed(token_contract);
    }
    if state.opened {
        let latest_activity = state.last_claim_time.max(last_accepted_output_secs);
        let idle_secs = if latest_activity == 0 {
            0
        } else {
            now_secs.saturating_sub(latest_activity)
        };
        return DealFacts::opened_idle(token_contract, idle_secs);
    }
    // Funded with escrow still held and never opened: the recoverable no-show case. A settled close drains
    // the deposit, which is what tells the two apart now that the probe latch is gone.
    if state.funded && !state.is_stopped() {
        return DealFacts::funded_never_opened(
            token_contract,
            elapsed_since(now_secs, state.funded_time),
        );
    }
    DealFacts::closed(token_contract)
}

type BuyerMonitorRecoveryKind = dexdo::buyer::api::RecoveryKind;

fn buyer_monitor_recovery_is_terminal(
    kind: BuyerMonitorRecoveryKind,
    state: Option<&DealChainState>,
) -> bool {
    match (kind, state) {
        (_, None) => true,
        (BuyerMonitorRecoveryKind::CleanupUnopened, Some(state)) => !state.funded,
        (BuyerMonitorRecoveryKind::ReclaimOpened, Some(state)) => !state.opened && !state.disputed,
    }
}

fn on_demand_monitor_defers_buy(
    enabled: bool,
    action: &dexdo::buyer::continuity::BuyerAction,
) -> bool {
    use dexdo::buyer::continuity::BuyerAction;

    enabled
        && matches!(
            action,
            BuyerAction::PlaceNextDeal { .. } | BuyerAction::PrepareNextDeal { .. }
        )
}

#[cfg(not(test))]
fn buyer_monitor_poll_interval() -> std::time::Duration {
    BUYER_MONITOR_POLL_INTERVAL
}

#[cfg(test)]
fn buyer_monitor_poll_interval() -> std::time::Duration {
    std::time::Duration::from_millis(10)
}

#[cfg(not(test))]
fn buyer_monitor_recovery_backoff() -> std::time::Duration {
    BUYER_MONITOR_RECOVERY_BACKOFF
}

#[cfg(test)]
fn buyer_monitor_recovery_backoff() -> std::time::Duration {
    std::time::Duration::from_millis(200)
}

async fn execute_buyer_monitor_recovery(
    chain: &dyn ChainBackend,
    action: dexdo::buyer::continuity::BuyerAction,
    session: Option<&dexdo::buyer::api::SessionSettle>,
) -> Option<(
    BuyerMonitorRecoveryKind,
    dexdo_core::TokenContract,
    Result<Option<Settlement>, ChainError>,
)> {
    use dexdo::buyer::continuity::BuyerAction;

    match action {
        BuyerAction::CleanupUnopened { token_contract } => {
            let result = match session {
                Some(session) => session.recover_cleanup_unopened(false).await,
                None => chain.cleanup_unopened(&token_contract).await.map(Some),
            };
            Some((
                BuyerMonitorRecoveryKind::CleanupUnopened,
                token_contract,
                result,
            ))
        }
        _ => None,
    }
}

fn correlated_buy_token_contract(
    fill: dexdo_core::MatchedFill,
    expected: Option<&dexdo_core::QuoteFill>,
    ticks: u128,
    max_price_per_tick: u128,
) -> Result<dexdo_core::TokenContract, ChainError> {
    let terms_valid = fill.ticks == ticks && fill.price_per_tick <= max_price_per_tick;
    let exact_match = expected.is_none_or(|expected| {
        fill.token_contract
            .eq_ignore_ascii_case(&expected.token_contract)
            && fill.ticks == expected.ticks
            && fill.price_per_tick == expected.price_per_tick
    });
    if terms_valid && exact_match {
        return Ok(fill.token_contract);
    }
    Err(ChainError::Chain(format!(
        "buyer fill correlation failed closed: got tokenContract {} ticks {} price_per_tick {}, \
         intended tokenContract {} ticks {} price_per_tick {}; refusing wrong-fill attribution",
        fill.token_contract,
        fill.ticks,
        fill.price_per_tick,
        expected
            .map(|fill| fill.token_contract.as_str())
            .unwrap_or("<backend-preflighted>"),
        expected.map(|fill| fill.ticks).unwrap_or(ticks),
        expected
            .map(|fill| fill.price_per_tick)
            .unwrap_or(max_price_per_tick)
    )))
}

async fn submit_buyer_monitor_next_deal(
    chain: &dyn ChainBackend,
    buyer: &dexdo::buyer::Buyer,
    ticks: u128,
    max_price: u128,
    escrow: u128,
) -> Result<dexdo_core::TokenContract, ChainError> {
    let since_unix = unix_now_secs() as i64;
    let deadline = buy_order_deadline().map_err(|e| ChainError::Chain(e.to_string()))?;
    chain
        .place_buy_by_model(buyer.note.as_ref(), ticks, max_price, escrow, 0, deadline)
        .await?;
    let fill = chain
        .wait_matched_token_contract(since_unix, std::time::Duration::from_secs(DEAL_WAIT_SECS))
        .await?
        .ok_or_else(|| ChainError::Chain("buyer fill event returned no match".to_string()))?;
    let token_contract = correlated_buy_token_contract(fill, None, ticks, max_price)?;
    validate_reported_match_state(chain, &token_contract).await?;
    Ok(token_contract)
}

#[allow(clippy::too_many_arguments)]
fn spawn_buyer_service_renewal(
    chain: Arc<dyn ChainBackend>,
    buyer: Arc<dexdo::buyer::Buyer>,
    deals: Arc<dexdo::buyer::api::RouteManager>,
    pool_note_addr: Option<String>,
    ticks: u128,
    max_price: u128,
    escrow: u128,
    continuity_mode: dexdo::buyer::continuity::ContinuityMode,
    content_check: dexdo::buyer::api::ContentCheck,
    models_cfg: Arc<dexdo::seller::ModelsConfig>,
    api_failure_policy: dexdo::buyer::api::BuyerApiFailurePolicy,
) {
    struct PendingRenewal {
        current: dexdo_core::TokenContract,
        next: Option<dexdo_core::TokenContract>,
        matched_at: Option<std::time::Instant>,
    }
    struct PrepareRetry {
        current: dexdo_core::TokenContract,
        retry_at: std::time::Instant,
    }
    struct RecoveryRetry {
        current: dexdo_core::TokenContract,
        kind: BuyerMonitorRecoveryKind,
        retry_at: std::time::Instant,
    }

    let on_demand_recovery =
        continuity_mode == dexdo::buyer::continuity::ContinuityMode::OnDemand && deals.is_lazy();

    tokio::spawn(async move {
        use dexdo::buyer::continuity::{
            BuyerAction, BuyerContinuity, ConsumerDemand, ContinuityConfig, DealFacts,
        };

        let mut planner = BuyerContinuity::default();
        let cfg = ContinuityConfig {
            renewal_threshold_tokens: buyer_renewal_threshold_tokens(),
            ..ContinuityConfig::default()
        };
        let mut pending: Option<PendingRenewal> = None;
        let mut prepare_retry: Option<PrepareRetry> = None;
        let mut recovery_retry: Option<RecoveryRetry> = None;
        loop {
            tokio::time::sleep(buyer_monitor_poll_interval()).await;
            let Some(active) = deals.current().await else {
                continue;
            };
            let current_tc = active.route.token_contract.clone();
            if prepare_retry
                .as_ref()
                .is_some_and(|retry| retry.current != current_tc)
            {
                prepare_retry = None;
            }
            if recovery_retry
                .as_ref()
                .is_some_and(|retry| retry.current != current_tc)
            {
                recovery_retry = None;
            }
            if recovery_retry.is_none() {
                if let Some(kind) = active.session.take_handler_recovery_reconciliation() {
                    recovery_retry = Some(RecoveryRetry {
                        current: current_tc.clone(),
                        kind,
                        retry_at: std::time::Instant::now() + buyer_monitor_recovery_backoff(),
                    });
                }
            }
            if recovery_retry
                .as_ref()
                .is_some_and(|retry| std::time::Instant::now() < retry.retry_at)
            {
                continue;
            }

            let chain_state_read = chain.deal_state(&current_tc).await;
            if let Some(retry) = recovery_retry.as_mut() {
                let recovery_kind = retry.kind;
                match &chain_state_read {
                    Err(error) => {
                        retry.retry_at =
                            std::time::Instant::now() + buyer_monitor_recovery_backoff();
                        tracing::warn!(
                            token_contract = %current_tc,
                            recovery_action = ?retry.kind,
                            error = %error,
                            backoff_ms = buyer_monitor_recovery_backoff().as_millis(),
                            outcome = "chain_state_retry",
                            "buyer continuity: recovery retry needs authoritative fresh deal state"
                        );
                        continue;
                    }
                    Ok(state)
                        if buyer_monitor_recovery_is_terminal(recovery_kind, state.as_ref()) =>
                    {
                        active
                            .session
                            .mark_recovered_serialized("continuity-recovery-observed-terminal")
                            .await;
                        planner.keep_active(&current_tc);
                        pending = None;
                        recovery_retry = None;
                        tracing::warn!(
                            token_contract = %current_tc,
                            recovery_action = ?recovery_kind,
                            outcome = "terminal_by_fact",
                            "buyer continuity: recovery outcome confirmed from fresh chain state"
                        );
                        continue;
                    }
                    Ok(_)
                        if active
                            .session
                            .recovery_submit_may_have_landed(recovery_kind) =>
                    {
                        retry.retry_at =
                            std::time::Instant::now() + buyer_monitor_recovery_backoff();
                        planner.keep_active(&current_tc);
                        tracing::warn!(
                            token_contract = %current_tc,
                            recovery_action = ?recovery_kind,
                            backoff_ms = buyer_monitor_recovery_backoff().as_millis(),
                            outcome = "possibly_landed_waiting_for_terminal_fact",
                            "buyer continuity: fresh state is still non-terminal; automatic recovery resubmit remains suppressed"
                        );
                        continue;
                    }
                    Ok(_) => {
                        planner.keep_active(&current_tc);
                        recovery_retry = None;
                    }
                }
            }

            let chain_state = match chain_state_read {
                Ok(state) => state,
                Err(e) => {
                    tracing::warn!(
                        current = %current_tc,
                        error = %e,
                        "buyer continuity: deal_state read failed; falling back to local session facts"
                    );
                    None
                }
            };
            let now_secs = unix_now_secs();
            let current_facts = buyer_monitor_current_facts(
                current_tc.clone(),
                active.remaining_tokens(),
                active.session.is_settled(),
                chain_state,
                now_secs,
                active.last_accepted_output_unix_secs(),
            );
            let consumer_demand =
                if active.has_active_or_recent_request(now_secs, CONSUMER_DEMAND_RECENT_SECS) {
                    ConsumerDemand::ActiveOrRecent
                } else {
                    ConsumerDemand::Idle
                };

            let mut ready_next = None;
            let mut waiting_for_pending_handover = false;
            if let Some(p) = pending.as_ref().filter(|p| p.current == current_tc) {
                if let Some(next) = p.next.as_ref() {
                    if buyer.resolve_endpoint(chain.as_ref(), next).await.is_ok() {
                        ready_next = Some(DealFacts::handover_ready(
                            next.clone(),
                            consumer_api_token_budget(ticks),
                        ));
                    } else if let Some(matched_at) = p.matched_at {
                        waiting_for_pending_handover = true;
                        let age = matched_at.elapsed().as_secs();
                        let recovery = planner.tick(
                            Some(DealFacts::funded_never_opened(next.clone(), age)),
                            None,
                            cfg,
                        );
                        if let Some((_kind, token_contract, result)) =
                            execute_buyer_monitor_recovery(chain.as_ref(), recovery, None).await
                        {
                            match result {
                                Ok(Some(settlement)) => {
                                    tracing::warn!(
                                        current = %current_tc,
                                        next = %token_contract,
                                        settlement = %settlement,
                                        "buyer continuity: cleaned up renewal deal that never opened"
                                    );
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    tracing::warn!(
                                        current = %current_tc,
                                        next = %token_contract,
                                        error = %e,
                                        "buyer continuity: cleanup_unopened failed"
                                    );
                                }
                            }
                            planner.clear_pending_next(&current_tc);
                            pending = None;
                            continue;
                        }
                    } else {
                        waiting_for_pending_handover = true;
                    }
                }
            } else if pending.is_some() {
                pending = None;
            }
            if waiting_for_pending_handover {
                continue;
            }

            let action = planner.tick_with_mode(
                Some(current_facts),
                ready_next,
                cfg,
                continuity_mode,
                consumer_demand,
            );
            if on_demand_monitor_defers_buy(on_demand_recovery, &action) {
                planner.clear_pending_next(&current_tc);
                tracing::debug!(
                    token_contract = %current_tc,
                    outcome = "defer_buy_until_consumer_request",
                    "buyer continuity: on-demand recovery monitor suppressed fresh BUY"
                );
                continue;
            }
            match action {
                BuyerAction::ServeCurrent { .. }
                | BuyerAction::Noop { .. }
                | BuyerAction::IgnoreStale { .. } => {}
                BuyerAction::FailClosed {
                    token_contract,
                    reason,
                } => {
                    tracing::error!(
                        token_contract = %token_contract,
                        reason,
                        "buyer continuity: fail-closed planner action"
                    );
                }
                action @ BuyerAction::CleanupUnopened { .. } => {
                    if on_demand_recovery && !active.session.is_closed() {
                        planner.keep_active(&current_tc);
                        tracing::debug!(
                            token_contract = %current_tc,
                            outcome = "healthy_session_not_recoverable",
                            "buyer continuity: on-demand recovery waits for a failed local session"
                        );
                        continue;
                    }
                    if let Some((kind, token_contract, result)) = execute_buyer_monitor_recovery(
                        chain.as_ref(),
                        action,
                        Some(active.session.as_ref()),
                    )
                    .await
                    {
                        debug_assert_eq!(kind, BuyerMonitorRecoveryKind::CleanupUnopened);
                        match result {
                            Ok(Some(settlement)) => {
                                tracing::warn!(
                                    token_contract = %token_contract,
                                    settlement = %settlement,
                                    outcome = "terminal",
                                    "buyer continuity: cleaned current funded-never-opened deal"
                                );
                            }
                            Ok(None) => {
                                tracing::debug!(
                                    token_contract = %token_contract,
                                    outcome = "already_terminal",
                                    "buyer continuity: cleanup recovery needed no transaction"
                                );
                            }
                            Err(e) => {
                                if on_demand_recovery {
                                    planner.keep_active(&token_contract);
                                    recovery_retry = Some(RecoveryRetry {
                                        current: token_contract.clone(),
                                        kind,
                                        retry_at: std::time::Instant::now()
                                            + buyer_monitor_recovery_backoff(),
                                    });
                                    tracing::warn!(
                                        token_contract = %token_contract,
                                        error = %e,
                                        backoff_ms = buyer_monitor_recovery_backoff().as_millis(),
                                        outcome = "retry_scheduled",
                                        "buyer continuity: cleanup current funded-never-opened deal failed"
                                    );
                                } else {
                                    tracing::warn!(
                                        token_contract = %token_contract,
                                        error = %e,
                                        "buyer continuity: cleanup current funded-never-opened deal failed"
                                    );
                                }
                            }
                        }
                        pending = None;
                    } else {
                        planner.keep_active(&current_tc);
                    }
                }
                BuyerAction::PlaceNextDeal { reason } => {
                    tracing::info!(reason, "buyer continuity: planner requested a fresh deal");
                    let current = current_tc.clone();
                    if let Some(retry) = prepare_retry.as_ref().filter(|retry| {
                        retry.current == current && std::time::Instant::now() < retry.retry_at
                    }) {
                        planner.clear_pending_next(&current);
                        tracing::debug!(
                            current = %current,
                            retry_after_secs = retry
                                .retry_at
                                .saturating_duration_since(std::time::Instant::now())
                                .as_secs(),
                            "buyer continuity: fresh deal prepare is in retry backoff"
                        );
                        continue;
                    }
                    if let Err(e) = preflight_buyer_pool_for_note(pool_note_addr.as_deref()) {
                        planner.clear_pending_next(&current);
                        pending = None;
                        prepare_retry = Some(PrepareRetry {
                            current: current.clone(),
                            retry_at: std::time::Instant::now()
                                + std::time::Duration::from_secs(RENEWAL_FAILURE_BACKOFF_SECS),
                        });
                        tracing::warn!(
                            current = %current,
                            retry_after_secs = RENEWAL_FAILURE_BACKOFF_SECS,
                            error = %e,
                            "buyer continuity: pool preflight failed before fresh buy submit"
                        );
                        continue;
                    }
                    match submit_buyer_monitor_next_deal(
                        chain.as_ref(),
                        buyer.as_ref(),
                        ticks,
                        max_price,
                        escrow,
                    )
                    .await
                    {
                        Ok(next) => {
                            persist_buyer_token_contract_for_note(pool_note_addr.as_deref(), &next);
                            prepare_retry = None;
                            planner.note_pending_next(current.clone(), next.clone());
                            pending = Some(PendingRenewal {
                                current,
                                next: Some(next.clone()),
                                matched_at: Some(std::time::Instant::now()),
                            });
                            tracing::info!(
                                next = %next,
                                "buyer continuity: fresh buy matched; waiting for handover"
                            );
                        }
                        Err(e) => {
                            planner.clear_pending_next(&current);
                            pending = None;
                            prepare_retry = Some(PrepareRetry {
                                current: current.clone(),
                                retry_at: std::time::Instant::now()
                                    + std::time::Duration::from_secs(RENEWAL_FAILURE_BACKOFF_SECS),
                            });
                            tracing::warn!(
                                current = %current,
                                retry_after_secs = RENEWAL_FAILURE_BACKOFF_SECS,
                                error = %e,
                                "buyer continuity: fresh buy submit/match failed"
                            );
                        }
                    }
                }
                BuyerAction::PrepareNextDeal { current } => {
                    if let Some(retry) = prepare_retry.as_ref().filter(|retry| {
                        retry.current == current && std::time::Instant::now() < retry.retry_at
                    }) {
                        planner.clear_pending_next(&current);
                        tracing::debug!(
                            current = %current,
                            retry_after_secs = retry
                                .retry_at
                                .saturating_duration_since(std::time::Instant::now())
                                .as_secs(),
                            "buyer continuity: renewal prepare is in retry backoff"
                        );
                        continue;
                    }
                    if let Err(e) = preflight_buyer_pool_for_note(pool_note_addr.as_deref()) {
                        planner.clear_pending_next(&current);
                        pending = None;
                        prepare_retry = Some(PrepareRetry {
                            current: current.clone(),
                            retry_at: std::time::Instant::now()
                                + std::time::Duration::from_secs(RENEWAL_FAILURE_BACKOFF_SECS),
                        });
                        tracing::warn!(
                            current = %current,
                            retry_after_secs = RENEWAL_FAILURE_BACKOFF_SECS,
                            error = %e,
                            "buyer continuity: pool preflight failed before renewal buy submit"
                        );
                        continue;
                    }
                    match submit_buyer_monitor_next_deal(
                        chain.as_ref(),
                        buyer.as_ref(),
                        ticks,
                        max_price,
                        escrow,
                    )
                    .await
                    {
                        Ok(next) => {
                            persist_buyer_token_contract_for_note(pool_note_addr.as_deref(), &next);
                            prepare_retry = None;
                            planner.note_pending_next(current.clone(), next.clone());
                            pending = Some(PendingRenewal {
                                current,
                                next: Some(next.clone()),
                                matched_at: Some(std::time::Instant::now()),
                            });
                            tracing::info!(
                                next = %next,
                                "buyer continuity: renewal buy matched; waiting for handover"
                            );
                        }
                        Err(e) => {
                            planner.clear_pending_next(&current);
                            pending = None;
                            prepare_retry = Some(PrepareRetry {
                                current: current.clone(),
                                retry_at: std::time::Instant::now()
                                    + std::time::Duration::from_secs(RENEWAL_FAILURE_BACKOFF_SECS),
                            });
                            tracing::warn!(
                                current = %current,
                                retry_after_secs = RENEWAL_FAILURE_BACKOFF_SECS,
                                error = %e,
                                "buyer continuity: renewal submit/match failed"
                            );
                        }
                    }
                }
                BuyerAction::SwitchToNextDeal { previous, next } => {
                    let handover = match buyer.resolve_endpoint(chain.as_ref(), &next).await {
                        Ok(h) => h,
                        Err(e) => {
                            tracing::warn!(
                                previous = %previous,
                                next = %next,
                                error = %e,
                                "buyer continuity: planner saw next ready but handover reread failed"
                            );
                            continue;
                        }
                    };
                    if let Err(error) = deals
                        .replace_active(
                            || {
                                let session = Arc::new(
                                    dexdo::buyer::api::SessionSettle::new_with_failure_policy(
                                        chain.clone(),
                                        next.clone(),
                                        buyer.note.clone(),
                                        api_failure_policy,
                                    ),
                                );
                                dexdo::buyer::api::ApiDeal::new(
                                    dexdo::buyer::api::Route {
                                        handover,
                                        token_contract: next.clone(),
                                        max_tokens: consumer_api_token_budget(ticks),
                                    },
                                    session,
                                    Arc::new(dexdo::buyer::api::ContentGate::new(
                                        content_check.clone(),
                                        models_cfg.clone(),
                                    )),
                                )
                            },
                            "continuity-renewal",
                        )
                        .await
                    {
                        tracing::error!(
                            previous = %previous,
                            next = %next,
                            error = %error,
                            "buyer continuity: old deal STOP failed; keeping current route and pending renewal"
                        );
                        continue;
                    }
                    pending = None;
                    prepare_retry = None;
                    tracing::info!(
                        previous = %previous,
                        next = %next,
                        "buyer continuity: switched local API to renewed handover"
                    );
                }
            }
        }
    });
}

#[derive(Clone, Copy)]
enum BuyerShellnetPreflight {
    Production,
    #[cfg(all(test, feature = "shellnet"))]
    OfflineTest,
}

impl BuyerShellnetPreflight {
    fn should_run(self) -> bool {
        match self {
            Self::Production => true,
            #[cfg(all(test, feature = "shellnet"))]
            Self::OfflineTest => false,
        }
    }
}

type BuyerShutdownSignal =
    std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>;

struct BuyerCommandRuntime {
    backend: Option<ChainAndNote>,
    shellnet_preflight: BuyerShellnetPreflight,
    shutdown: BuyerShutdownSignal,
}

impl BuyerCommandRuntime {
    fn production() -> Self {
        Self {
            backend: None,
            shellnet_preflight: BuyerShellnetPreflight::Production,
            shutdown: Box::pin(operator_shutdown_signal()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SubscriptionPlacePlan {
    ticks: u128,
    reserve: SubscriptionBuyReserve,
}

fn subscription_place_plan(args: &SubscriptionPlaceArgs) -> Result<SubscriptionPlacePlan> {
    let reserve = subscription_buy_reserve(args.ticks, args.max_price_per_tick)
        .map_err(anyhow::Error::msg)?;
    validate_subscription_order_terms(
        args.max_price_per_tick,
        args.ticks,
        reserve.total_escrow,
        subscription_order_flags(),
        2,
        1,
    )?;
    Ok(SubscriptionPlacePlan {
        ticks: args.ticks,
        reserve,
    })
}

fn subscription_mock_mode(mock: &MockFlags) -> Result<bool> {
    match (mock.mock_model, mock.mock_chain) {
        (false, false) => Ok(false),
        (true, true) => Ok(true),
        _ => bail!(
            "subscription mock mode requires --mock-model and --mock-chain together; omit both \
             flags for real shellnet"
        ),
    }
}

fn mock_subscription_target(args: &SubscriptionArgs) -> Result<(String, String)> {
    if let Some(market_path) = args.market.as_deref() {
        if args.model.is_some() {
            bail!("--market and --model are mutually exclusive for subscription");
        }
        let market = load_market(market_path)?;
        return Ok((market.frame_model, market.inference_order_book));
    }

    let requested_model = args
        .model
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("subscription without --market requires --model"))?;
    let frame_model = if requested_model.contains("--") || requested_model.contains('/') {
        requested_model.to_string()
    } else {
        dexdo::seller::ModelsConfig::load(&args.models)?
            .get(requested_model)?
            .frame_model
            .clone()
    };
    if frame_model.trim().is_empty() {
        bail!("subscription model id must not be empty");
    }
    let model_hash = model_hash_for(&frame_model);
    let order_book = format!(
        "0:{}",
        model_hash
            .strip_prefix("0x")
            .expect("model_hash_for always returns 0x-prefixed hex")
    );
    Ok((frame_model, order_book))
}

fn execute_mock_subscription_command(
    backend: &dexdo_core::MockChainBackend,
    note: &dexdo_core::LocalNote,
    frame_model: &str,
    order_book: &str,
    command: &SubscriptionCommand,
    place_plan: Option<SubscriptionPlacePlan>,
) -> Result<String> {
    match command {
        SubscriptionCommand::Place(place) => {
            let plan = place_plan.expect("place plan is present for subscription place");
            let deadline = buy_order_deadline()?;
            let order = backend.place_subscription_order(
                order_book,
                note,
                place.max_price_per_tick,
                plan.ticks,
                plan.reserve.total_escrow,
                subscription_order_flags(),
                deadline,
            )?;
            Ok(format!(
                "subscription place confirmed network=mock model={frame_model} \
                 order_book={order_book} owner={} order_id={} max_price_per_tick={} ticks={} \
                 deposit={} buyer_bond={} total_escrow={} flags=0x{:02x} deadline={} \
                 resting=true matched_token_contract=-",
                order.owner_note,
                order.order_id,
                order.price_per_tick,
                order.ticks,
                plan.reserve.deposit,
                plan.reserve.buyer_bond,
                order.escrow,
                order.flags,
                order.deadline
            ))
        }
        SubscriptionCommand::Status { order_id } => {
            let order = backend
                .subscription_order(order_book, *order_id, note)?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "mock subscription order {order_id} is absent or owned by another note"
                    )
                })?;
            let reserve = validate_subscription_order_terms(
                order.price_per_tick,
                order.ticks,
                order.escrow,
                order.flags,
                order.deadline,
                order.timestamp,
            )?;
            Ok(format!(
                "subscription network=mock model={frame_model} order_book={order_book} \
                 order_id={} owner={} price_per_tick={} ticks={} deposit={} buyer_bond={} \
                 total_escrow={} flags=0x{:02x} deadline={} resting=true \
                 matched_token_contract=-",
                order.order_id,
                order.owner_note,
                order.price_per_tick,
                order.ticks,
                reserve.deposit,
                reserve.buyer_bond,
                order.escrow,
                order.flags,
                order.deadline
            ))
        }
        SubscriptionCommand::Cancel { order_id } => {
            let order = backend.cancel_subscription_order(order_book, *order_id, note)?;
            Ok(format!(
                "subscription cancel confirmed network=mock model={frame_model} \
                 order_book={order_book} order_id={} owner={} refund={}",
                order.order_id, order.owner_note, order.escrow
            ))
        }
    }
}

fn run_mock_subscription(
    args: &SubscriptionArgs,
    place_plan: Option<SubscriptionPlacePlan>,
) -> Result<()> {
    let endpoints_file = resolve_endpoints_file(args.endpoints_file.clone())?;
    let backend = dexdo_core::MockChainBackend::new(
        endpoints_file,
        dexdo_core::ProtocolConsts::canonical(),
        dexdo_core::DobParams::canonical(),
    );
    let mut identity = args.identity.clone();
    if let SubscriptionCommand::Place(place) = &args.command {
        identity.note_key = match (args.identity.note_key.as_deref(), place.note_key.as_deref()) {
            (Some(parent), Some(child)) if parent != child => {
                bail!(
                    "subscription place: pass --note-key only once; parent and place values differ"
                )
            }
            (Some(parent), _) => Some(parent.to_path_buf()),
            (_, Some(child)) => Some(child.to_path_buf()),
            (None, None) => None,
        };
    }
    let note = load_note_identity(&identity)?;
    let (frame_model, order_book) = mock_subscription_target(args)?;
    let output = execute_mock_subscription_command(
        &backend,
        &note,
        &frame_model,
        &order_book,
        &args.command,
        place_plan,
    )?;
    println!("{output}");
    Ok(())
}

#[cfg(feature = "shellnet")]
fn ensure_subscription_note_balance(
    balance: Option<u128>,
    reserve: SubscriptionBuyReserve,
) -> Result<u128> {
    let balance = balance.ok_or_else(|| {
        anyhow::anyhow!(
            "subscription place cannot prove live account ECC[{SHELL_ECC_ID}] SHELL balance; \
             missing currency is not treated as zero"
        )
    })?;
    if balance < reserve.total_escrow {
        bail!(
            "subscription place requires total escrow {} raw SHELL (= deposit {} + buyer bond {}), \
             but live account ECC[{SHELL_ECC_ID}] balance is {balance}",
            reserve.total_escrow,
            reserve.deposit,
            reserve.buyer_bond
        );
    }
    Ok(balance)
}

#[cfg(feature = "shellnet")]
async fn subscription_note_ecc_balance(
    chain: &dexdo_core::RealChainBackend,
    note: &dexdo_core::Address,
) -> Result<u128> {
    let account = chain
        .client()
        .get_account(note)
        .await?
        .ok_or_else(|| anyhow::anyhow!("PrivateNote {note} account is missing"))?;
    chain.assert_note_balance_private_note_account(note, Some(&account))?;
    account
        .ecc
        .iter()
        .find(|(currency, _)| *currency == SHELL_ECC_ID)
        .map(|(_, balance)| *balance)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "subscription place cannot prove live account ECC[{SHELL_ECC_ID}] SHELL balance; \
                 missing currency is not treated as zero"
            )
        })
}

#[cfg(feature = "shellnet")]
fn subscription_target(args: &SubscriptionArgs) -> Result<BookTarget> {
    if let Some(market) = args.market.as_deref() {
        if args.model.is_some() {
            bail!("--market and --model are mutually exclusive for subscription");
        }
        target_from_market(market)
    } else {
        let note_addr = args.identity.note_addr.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "subscription without --market requires --note-addr to derive the order-book address"
            )
        })?;
        model_target_from_config(
            &args.models,
            args.model
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("subscription without --market requires --model"))?,
            Some(note_addr),
        )
    }
}

#[cfg(feature = "shellnet")]
fn require_subscription_note(args: &SubscriptionArgs, action: &str) -> Result<dexdo_core::Address> {
    let note_addr = args
        .identity
        .note_addr
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("subscription {action} requires --note-addr"))?;
    dexdo_core::Address::parse(note_addr)
        .map_err(|error| anyhow::anyhow!("--note-addr {note_addr}: {error}"))
}

#[cfg(feature = "shellnet")]
fn require_subscription_keys(
    args: &SubscriptionArgs,
    action: &str,
    subcommand_note_key: Option<&std::path::Path>,
) -> Result<dexdo_core::KeyPair> {
    let note_key = match (args.identity.note_key.as_deref(), subcommand_note_key) {
        (Some(parent), Some(child)) if parent != child => {
            bail!(
                "subscription {action}: pass --note-key only once; parent and place values differ"
            )
        }
        (Some(parent), _) => parent,
        (_, Some(child)) => child,
        (None, None) => bail!("subscription {action} requires --note-key"),
    };
    dexdo_core::KeyPair::from_secret_hex(read_secret_hex(note_key, "--note-key")?.trim())
        .map_err(|error| anyhow::anyhow!("--note-key (SDK secret hex): {error:?}"))
}

#[cfg(feature = "shellnet")]
fn order_owned_by_note(order: &OrderBookOrder, note_addr: &str) -> bool {
    let expected = dexdo_core::normalize_wallet_address(note_addr)
        .unwrap_or_else(|_| note_addr.trim().to_string());
    dexdo_core::normalize_wallet_address(&order.owner_note)
        .map(|owner| owner == expected)
        .unwrap_or_else(|_| order.owner_note.eq_ignore_ascii_case(&expected))
}

#[cfg(feature = "shellnet")]
fn validate_subscription_live_order<'a>(
    order_book: &str,
    order: Option<&'a OrderBookOrder>,
    order_id: u128,
    note_addr: &str,
) -> Result<&'a OrderBookOrder> {
    let order = order.ok_or_else(|| {
        anyhow::anyhow!("subscription order {order_id} is not resting in {order_book}")
    })?;
    if order.order_id != order_id {
        bail!(
            "subscription order getter returned #{} while #{} was requested",
            order.order_id,
            order_id
        );
    }
    if !order_owned_by_note(order, note_addr) {
        bail!(
            "subscription order {order_id} is owned by {}, not note {note_addr}",
            order.owner_note
        );
    }
    if !order.is_buy || order.token_contract.is_some() {
        bail!("order {order_id} is not an ordinary resting BUY");
    }
    validate_subscription_order_terms(
        order.price_per_tick,
        order.ticks,
        order.escrow,
        order.flags,
        order.deadline,
        order.timestamp,
    )?;
    Ok(order)
}

#[cfg(feature = "shellnet")]
async fn read_subscription_book_summary(
    chain: &dexdo_core::RealChainBackend,
    target: &BookTarget,
) -> Result<OrderBookSnapshot> {
    let order_book = resolve_order_book_target(chain, target).await?;
    let order_book = dexdo_core::Address::parse(&order_book)
        .map_err(|error| anyhow::anyhow!("order_book {order_book}: {error}"))?;
    chain
        .inference_orderbook_summary(&order_book, &target.frame_model, &target.model_hash)
        .await
}

#[cfg(feature = "shellnet")]
fn ensure_subscription_record_from_order(
    state: &mut BuyerSubscriptionState,
    snapshot: &OrderBookSnapshot,
    order: &OrderBookOrder,
) -> Result<BuyerSubscriptionOrderRecord> {
    if let Some(existing) = subscription_order_record(state, &snapshot.order_book, order.order_id) {
        validate_subscription_record_matches_live_order(existing, snapshot, order)?;
        return Ok(existing.clone());
    }
    let reserve = validate_subscription_order_terms(
        order.price_per_tick,
        order.ticks,
        order.escrow,
        order.flags,
        order.deadline,
        order.timestamp,
    )?;
    let record = BuyerSubscriptionOrderRecord {
        order_book: snapshot.order_book.clone(),
        frame_model: snapshot.frame_model.clone(),
        model_hash: snapshot.model_hash.clone(),
        order_id: order.order_id,
        max_price_per_tick: order.price_per_tick,
        ticks: order.ticks,
        deposit: reserve.deposit,
        buyer_bond: reserve.buyer_bond,
        escrow: order.escrow,
        flags: order.flags,
        deadline: order.deadline,
        fill_cursor: MatchWatchCursor::new(0),
        phase: BuyerSubscriptionPhase::Resting,
        matched: None,
    };
    state.orders.push(record.clone());
    state.validate(&state.note_addr)?;
    Ok(record)
}

#[cfg(feature = "shellnet")]
fn validate_subscription_record_matches_live_order(
    record: &BuyerSubscriptionOrderRecord,
    snapshot: &OrderBookSnapshot,
    order: &OrderBookOrder,
) -> Result<()> {
    let reserve = validate_subscription_order_terms(
        order.price_per_tick,
        order.ticks,
        order.escrow,
        order.flags,
        order.deadline,
        order.timestamp,
    )?;
    if !record.order_book.eq_ignore_ascii_case(&snapshot.order_book)
        || record.frame_model != snapshot.frame_model
        || !record.model_hash.eq_ignore_ascii_case(&snapshot.model_hash)
        || record.order_id != order.order_id
        || record.max_price_per_tick != order.price_per_tick
        || record.ticks != order.ticks
        || record.deposit != reserve.deposit
        || record.buyer_bond != reserve.buyer_bond
        || record.escrow != order.escrow
        || record.flags != order.flags
        || record.deadline != order.deadline
        || record.phase != BuyerSubscriptionPhase::Resting
        || record.matched.is_some()
    {
        bail!(
            "resting subscription order #{} conflicts with durable state",
            order.order_id
        );
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
async fn reconcile_existing_subscription_journal(
    chain: &dexdo_core::RealChainBackend,
    money_lock: &BuyerMoneyLock,
    expected_book: &OrderBookSnapshot,
    wait: std::time::Duration,
    persist_handle: &PersistSubscriptionHandle<'_>,
) -> Result<Option<BuyerSubscriptionOrderRecord>> {
    load_buyer_subscription_state(&money_lock.subscriptions_path, &money_lock.note_addr)?;
    let Some(journal) = load_buyer_money_journal(&money_lock.journal_path, &money_lock.note_addr)?
    else {
        return Ok(None);
    };
    match journal {
        BuyerMoneyJournal::Buy(journal) => bail!(
            "subscription command refused: buyer note {} has unresolved ordinary BUY submit {}",
            money_lock.note_addr,
            journal.submit_identity
        ),
        BuyerMoneyJournal::Subscription(journal) => {
            validate_subscription_journal_target(&journal, expected_book)?;
            reconcile_subscription_submit(
                chain,
                &money_lock.journal_path,
                &money_lock.subscriptions_path,
                &journal,
                wait,
                persist_handle,
            )
            .await
            .map(Some)
        }
    }
}

#[cfg(feature = "shellnet")]
fn validate_subscription_journal_target(
    journal: &BuyerSubscriptionSubmitJournal,
    expected_book: &OrderBookSnapshot,
) -> Result<()> {
    if !journal
        .order_book
        .eq_ignore_ascii_case(&expected_book.order_book)
        || !journal
            .model_hash
            .eq_ignore_ascii_case(&expected_book.model_hash)
        || journal.frame_model != expected_book.frame_model
    {
        bail!(
            "durable subscription submit target {}/{}/{} contradicts the requested canonical book \
             {}/{}/{}; journal retained and no money action is safe",
            journal.frame_model,
            journal.model_hash,
            journal.order_book,
            expected_book.frame_model,
            expected_book.model_hash,
            expected_book.order_book
        );
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone)]
struct BuyerSubscriptionResumeSelection {
    record: BuyerSubscriptionOrderRecord,
    facts: SubscriptionDealFacts,
    quota: SubscriptionQuotaView,
}

enum BuyerSubscriptionResumeCandidate {
    #[cfg(feature = "shellnet")]
    Active(Box<BuyerSubscriptionResumeSelection>),
    None,
}

impl BuyerSubscriptionResumeCandidate {
    fn is_active(&self) -> bool {
        #[cfg(feature = "shellnet")]
        if matches!(self, Self::Active(_)) {
            return true;
        }
        false
    }
}

#[cfg(feature = "shellnet")]
async fn resolve_buyer_subscription_resume(
    chain: &dyn ChainBackend,
    note_addr: &str,
    frame_model: &str,
    expected_token_contract: Option<&str>,
    money_lock: &BuyerMoneyLock,
    wait: std::time::Duration,
    persist_handle: &PersistSubscriptionHandle<'_>,
) -> Result<Option<BuyerSubscriptionResumeSelection>> {
    let ops = BuyerSubscriptionResumeOps { chain };
    let model_hash = model_hash_for(frame_model);
    let order_book = chain.model_buy_order_book_identity().ok_or_else(|| {
        anyhow::anyhow!(
            "buyer subscription resume backend did not expose the canonical model order book"
        )
    })?;

    // Crash recovery is ordered deliberately: replay the money journal before consulting the
    // durable active-record index or the bounded historical event fallback.
    if let Some(journal) = load_buyer_money_journal(&money_lock.journal_path, note_addr)? {
        match journal {
            BuyerMoneyJournal::Buy(_) => return Ok(None),
            BuyerMoneyJournal::Subscription(journal) => {
                validate_subscription_journal_target(
                    &journal,
                    &OrderBookSnapshot {
                        frame_model: frame_model.to_string(),
                        model_hash: model_hash.clone(),
                        order_book: order_book.clone(),
                        stats: None,
                        orders: Vec::new(),
                    },
                )?;
                let record = reconcile_subscription_submit(
                    &ops,
                    &money_lock.journal_path,
                    &money_lock.subscriptions_path,
                    &journal,
                    wait,
                    persist_handle,
                )
                .await?;
                if record.phase == BuyerSubscriptionPhase::Resting {
                    bail!(
                        "subscription order #{} is still resting; resume submitted no BUY and cannot \
                         serve before one full seller match",
                        record.order_id
                    );
                }
                if let Some(expected) = expected_token_contract {
                    let actual = record
                        .matched
                        .as_ref()
                        .map(|matched| matched.token_contract.as_str())
                        .unwrap_or("<missing>");
                    if !actual.eq_ignore_ascii_case(expected) {
                        bail!(
                            "subscription journal reconciled TokenContract {actual}, but explicit \
                             resume requested {expected}"
                        );
                    }
                }
            }
        }
    }

    let state = load_buyer_subscription_state(&money_lock.subscriptions_path, note_addr)?;
    let matching_order_ids = state
        .orders
        .iter()
        .filter(|record| {
            record.frame_model == frame_model
                && record.model_hash.eq_ignore_ascii_case(&model_hash)
                && record.order_book.eq_ignore_ascii_case(&order_book)
        })
        .map(|record| record.order_id)
        .collect::<Vec<_>>();
    for order_id in matching_order_ids.iter().copied() {
        let record = subscription_order_record(&state, &order_book, order_id)
            .expect("matching order id came from this state");
        if record.phase == BuyerSubscriptionPhase::Resting {
            sync_subscription_match_once(
                &ops,
                &money_lock.subscriptions_path,
                note_addr,
                &order_book,
                order_id,
                persist_handle,
            )
            .await?;
        }
    }

    // Reconcile every locally matched candidate against the authoritative TokenContract before
    // deciding whether resume is ambiguous. A stale local `Matched` record must not mask a single
    // genuinely live subscription merely because its deal became disputed/stopped while the CLI
    // was offline.
    let state = load_buyer_subscription_state(&money_lock.subscriptions_path, note_addr)?;
    let matched_order_ids = state
        .orders
        .iter()
        .filter(|record| {
            record.frame_model == frame_model
                && record.model_hash.eq_ignore_ascii_case(&model_hash)
                && record.order_book.eq_ignore_ascii_case(&order_book)
                && record.phase == BuyerSubscriptionPhase::Matched
        })
        .map(|record| record.order_id)
        .collect::<Vec<_>>();
    let mut refreshed_matches = std::collections::BTreeMap::new();
    for order_id in matched_order_ids {
        let refreshed = refresh_subscription_match(
            &ops,
            &money_lock.subscriptions_path,
            note_addr,
            &order_book,
            order_id,
        )
        .await?;
        refreshed_matches.insert(order_id, refreshed);
    }

    let state = load_buyer_subscription_state(&money_lock.subscriptions_path, note_addr)?;
    let matching = state
        .orders
        .iter()
        .filter(|record| {
            record.frame_model == frame_model
                && record.model_hash.eq_ignore_ascii_case(&model_hash)
                && record.order_book.eq_ignore_ascii_case(&order_book)
                && expected_token_contract.is_none_or(|expected| {
                    record.matched.as_ref().is_some_and(|matched| {
                        matched.token_contract.eq_ignore_ascii_case(expected)
                    })
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    let active = matching
        .iter()
        .filter(|record| record.phase == BuyerSubscriptionPhase::Matched)
        .cloned()
        .collect::<Vec<_>>();
    if active.len() > 1 {
        let candidates = active
            .iter()
            .filter_map(|record| record.matched.as_ref())
            .map(|matched| matched.deal_handle.clone())
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "subscription resume is ambiguous for model {frame_model}; candidate handles: {candidates}"
        );
    }
    let candidate = if let Some(candidate) = active.into_iter().next() {
        candidate
    } else if matching
        .iter()
        .any(|record| record.phase == BuyerSubscriptionPhase::Resting)
    {
        let order_ids = matching
            .iter()
            .filter(|record| record.phase == BuyerSubscriptionPhase::Resting)
            .map(|record| record.order_id.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "subscription order(s) {order_ids} are still resting; resume submitted no BUY and \
             did not fall back to historical deal discovery"
        );
    } else if !matching.is_empty() {
        let identities = matching
            .iter()
            .map(|record| {
                record
                    .matched
                    .as_ref()
                    .map(|matched| matched.deal_handle.clone())
                    .unwrap_or_else(|| format!("order#{}", record.order_id))
            })
            .collect::<Vec<_>>()
            .join(", ");
        bail!("subscription(s) {identities} are terminal and cannot be resumed");
    } else {
        return Ok(None);
    };
    let (record, facts, quota) = refreshed_matches
        .remove(&candidate.order_id)
        .expect("every matched candidate was authoritatively refreshed");
    if record.phase != BuyerSubscriptionPhase::Matched {
        bail!(
            "subscription {} is not live and cannot be resumed",
            record
                .matched
                .as_ref()
                .map(|matched| matched.deal_handle.as_str())
                .unwrap_or("<missing-handle>")
        );
    }
    Ok(Some(BuyerSubscriptionResumeSelection {
        record,
        facts,
        quota,
    }))
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum SubscriptionCancelOutcome {
    Refunded { expected_balance: u128 },
    Filled { token_contract: String },
    ContradictoryFill { token_contract: String },
    Unconfirmed { expected_balance: u128 },
}

#[cfg(feature = "shellnet")]
fn subscription_cancel_outcome(
    active: bool,
    balance_before: u128,
    balance_after: u128,
    escrow: u128,
    matched: Option<&BuyerSubscriptionMatch>,
) -> Result<SubscriptionCancelOutcome> {
    let expected_balance = balance_before
        .checked_add(escrow)
        .ok_or_else(|| anyhow::anyhow!("subscription cancel refund balance overflows u128"))?;
    if let Some(matched) = matched {
        return Ok(if active {
            SubscriptionCancelOutcome::ContradictoryFill {
                token_contract: matched.token_contract.clone(),
            }
        } else {
            SubscriptionCancelOutcome::Filled {
                token_contract: matched.token_contract.clone(),
            }
        });
    }
    if !active && balance_after == expected_balance {
        return Ok(SubscriptionCancelOutcome::Refunded { expected_balance });
    }
    Ok(SubscriptionCancelOutcome::Unconfirmed { expected_balance })
}

#[cfg(feature = "shellnet")]
async fn reconcile_subscription_cancel<F, Fut>(
    wait: std::time::Duration,
    balance_before: u128,
    escrow: u128,
    mut observe: F,
) -> Result<SubscriptionCancelOutcome>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(bool, u128, Option<BuyerSubscriptionMatch>)>>,
{
    let started = std::time::Instant::now();
    let mut last_outcome =
        subscription_cancel_outcome(true, balance_before, balance_before, escrow, None)?;
    loop {
        let remaining = wait.saturating_sub(started.elapsed());
        let (active, balance_after, matched) =
            match tokio::time::timeout(remaining, observe()).await {
                Ok(observation) => observation?,
                Err(_) => return Ok(last_outcome),
            };
        let outcome = subscription_cancel_outcome(
            active,
            balance_before,
            balance_after,
            escrow,
            matched.as_ref(),
        )?;
        if matches!(
            outcome,
            SubscriptionCancelOutcome::Refunded { .. } | SubscriptionCancelOutcome::Filled { .. }
        ) {
            return Ok(outcome);
        }
        last_outcome = outcome;
        let elapsed = started.elapsed();
        if elapsed >= wait {
            return Ok(last_outcome);
        }
        tokio::time::sleep(SUBSCRIPTION_ORDER_RECONCILE_POLL.min(wait.saturating_sub(elapsed)))
            .await;
    }
}

#[cfg(feature = "shellnet")]
fn render_subscription_record(
    _snapshot: &OrderBookSnapshot,
    record: &BuyerSubscriptionOrderRecord,
    note_addr: &str,
    resting: bool,
    live: Option<(&SubscriptionDealFacts, &SubscriptionQuotaView)>,
) -> Result<String> {
    let matched = record
        .matched
        .as_ref()
        .map(|matched| matched.token_contract.as_str())
        .unwrap_or("-");
    let price_improvement_refund = record
        .matched
        .as_ref()
        .map(|matched| {
            subscription_buy_clearing_refund(
                record.ticks,
                record.max_price_per_tick,
                matched.clearing_price,
            )
            .map_err(anyhow::Error::msg)
        })
        .transpose()?
        .unwrap_or(0);
    let phase = match record.phase {
        BuyerSubscriptionPhase::Resting => "resting",
        BuyerSubscriptionPhase::Matched => "matched",
        BuyerSubscriptionPhase::Terminal => "terminal",
    };
    let mut rendered = format!(
        "subscription model={} order_book={} order_id={} owner={} price_per_tick={} ticks={} \
         deposit={} buyer_bond={} total_escrow={} price_improvement_refund={} flags=0x{:02x} \
         deadline={} phase={} resting={} matched_token_contract={}",
        record.frame_model,
        record.order_book,
        record.order_id,
        note_addr,
        record.max_price_per_tick,
        record.ticks,
        record.deposit,
        record.buyer_bond,
        record.escrow,
        price_improvement_refund,
        record.flags,
        record.deadline,
        phase,
        resting,
        matched
    );
    if let Some((facts, quota)) = live {
        rendered.push_str(&format!(
            " probe_accepted={} week_index={} week_base_tokens={} tokens_per_week={} \
             tokens_final={} tokens_superseded={} tokens_pending={} used_current_week={} \
             remaining_current_week={} funded_tokens={} tokens_paid={} deposit={} probe_tick={} \
             buyer_bond_held={} buyer_bond_required={} buyer_locked_total={} seller_bond_held={} \
             seller_bond_required={} disputed={} terminal={}",
            facts.state.probe_accepted,
            facts.subscription.week_index,
            facts.subscription.week_base_tokens,
            facts.subscription.tokens_per_week,
            facts.state.tokens_final,
            facts.state.tokens_superseded,
            facts.state.tokens_pending,
            quota.claimed_current_week,
            quota.remaining_current_week,
            facts.subscription.funded_tokens,
            facts.subscription.tokens_paid,
            facts.state.deposit,
            facts.state.probe_tick,
            facts.buyer_bond.bond_held,
            facts.buyer_bond.bond_required,
            quota.buyer_locked_total,
            facts.seller_bond.bond_held,
            facts.seller_bond.bond_required,
            facts.state.disputed,
            facts.state.is_stopped()
        ));
    }
    Ok(rendered)
}

#[cfg(feature = "shellnet")]
pub(crate) async fn run_subscription(args: SubscriptionArgs) -> Result<()> {
    let mock_mode = subscription_mock_mode(&args.mock)?;
    let place_plan = match &args.command {
        SubscriptionCommand::Place(place) => Some(subscription_place_plan(place)?),
        _ => None,
    };
    if mock_mode {
        return run_mock_subscription(&args, place_plan);
    }
    let chain = dexdo_core::RealChainBackend::connect(
        args.contracts
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?,
    )?;
    let note = require_subscription_note(&args, "command")?;
    let note_addr = note.with_workchain();
    let mut money_lock = BuyerMoneyLock::open(&note_addr)?;
    money_lock.try_acquire()?;
    let reconcile_wait = std::time::Duration::from_secs(args.read_timeout.read_timeout_secs);
    let handle_note_addr = note_addr.clone();
    let handle_deals_dir = args.deals_dir.clone();
    let handle_market = args.market.clone();
    let handle_contracts = args.contracts.clone();
    let persist_handle: Arc<PersistSubscriptionHandle<'static>> =
        Arc::new(move |record, matched| {
            persist_subscription_runtime_handle(
                record,
                matched,
                &handle_note_addr,
                handle_deals_dir.as_deref(),
                handle_market.as_deref(),
                &handle_contracts,
            )
        });

    let registry_policy =
        load_enabled_model_registry_policy(RegistryRole::Buyer, &args.registry, &args.contracts)?;
    let initial_target = if registry_policy.is_some() && args.market.is_none() {
        let requested_model = registry_requested_model(
            &args.models,
            args.model
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("subscription without --market requires --model"))?,
        )?;
        BookTarget {
            model_hash: model_hash_for(&requested_model),
            frame_model: requested_model,
            order_book: None,
            root_model: None,
            note_addr: Some(note_addr.clone()),
        }
    } else {
        subscription_target(&args)?
    };
    let requested_model = initial_target.frame_model.clone();
    let (target, snapshot) =
        direct_chain_read_with_timeout(args.read_timeout.read_timeout_secs, async {
            let target = resolve_model_registry_target(
                RegistryRole::Buyer,
                registry_policy.as_ref(),
                &args.contracts,
                &requested_model,
                initial_target,
            )
            .await?;
            let snapshot = read_subscription_book_summary(&chain, &target).await?;
            if matches!(&args.command, SubscriptionCommand::Place(_)) {
                if let Some(policy) = registry_policy.as_ref() {
                    enforce_model_registry_policy(
                        RegistryRole::Buyer,
                        policy,
                        &args.contracts,
                        &target.frame_model,
                        &snapshot.order_book,
                        snapshot.active(),
                        BuyerMissingBookPolicy::Reject,
                    )
                    .await?;
                }
            }
            Ok((target, snapshot))
        })
        .await?;
    if !snapshot.active() {
        bail!(
            "subscription: InferenceOrderBook {} for model {} is not active",
            snapshot.order_book,
            snapshot.frame_model
        );
    }
    let reconciled = reconcile_existing_subscription_journal(
        &chain,
        &money_lock,
        &snapshot,
        reconcile_wait,
        persist_handle.as_ref(),
    )
    .await?;
    if matches!(&args.command, SubscriptionCommand::Place(_)) {
        if let Some(record) = reconciled {
            println!(
                "subscription place reconciled order_id={} order_book={} deposit={} buyer_bond={} \
                 total_escrow={} resting={} matched_token_contract={} no_second_boc=true",
                record.order_id,
                record.order_book,
                record.deposit,
                record.buyer_bond,
                record.escrow,
                record.matched.is_none(),
                record
                    .matched
                    .as_ref()
                    .map(|matched| matched.token_contract.as_str())
                    .unwrap_or("-")
            );
            return Ok(());
        }
    }
    if matches!(
        &args.command,
        SubscriptionCommand::Place(_) | SubscriptionCommand::Cancel { .. }
    ) {
        shellnet_doctor_preflight(&args.contracts, args.market.as_deref()).await?;
    }
    let live_order = match &args.command {
        SubscriptionCommand::Status { order_id } | SubscriptionCommand::Cancel { order_id } => {
            let order_book = dexdo_core::Address::parse(&snapshot.order_book)
                .map_err(|error| anyhow::anyhow!("order_book {}: {error}", snapshot.order_book))?;
            direct_chain_read_with_timeout(
                args.read_timeout.read_timeout_secs,
                chain.inference_orderbook_parsed_order(&order_book, *order_id),
            )
            .await?
        }
        SubscriptionCommand::Place(_) => None,
    };
    match &args.command {
        SubscriptionCommand::Place(place) => {
            let plan = place_plan.expect("place plan was validated before chain reads");
            let keys = require_subscription_keys(&args, "place", place.note_key.as_deref())?;
            preflight_buyer_pool_for_note(Some(&note_addr))?;
            direct_chain_read_with_timeout(args.read_timeout.read_timeout_secs, async {
                chain.assert_seller_note_current(&note).await?;
                chain
                    .assert_note_owner_matches("subscription place", &note, &keys)
                    .await?;
                chain.assert_note_can_place_inference_buy(&note).await?;
                Ok(())
            })
            .await?;
            let balance = direct_chain_read_with_timeout(
                args.read_timeout.read_timeout_secs,
                subscription_note_ecc_balance(&chain, &note),
            )
            .await?;
            ensure_subscription_note_balance(Some(balance), plan.reserve)?;
            let deadline = buy_order_deadline()?;
            let record = submit_subscription_with_journal(
                &chain,
                &note,
                &keys,
                &snapshot.order_book,
                &snapshot.frame_model,
                &target.model_hash,
                place.max_price_per_tick,
                plan.ticks,
                plan.reserve.total_escrow,
                deadline,
                &money_lock.journal_path,
                &money_lock.subscriptions_path,
                reconcile_wait,
                persist_handle.as_ref(),
            )
            .await?;
            println!(
                "subscription place confirmed model={} order_book={} owner={} order_id={} \
                 max_price_per_tick={} ticks={} deposit={} buyer_bond={} total_escrow={} \
                 flags=0x{:02x} deadline={} resting={} matched_token_contract={}",
                snapshot.frame_model,
                snapshot.order_book,
                note_addr,
                record.order_id,
                record.max_price_per_tick,
                record.ticks,
                record.deposit,
                record.buyer_bond,
                record.escrow,
                record.flags,
                record.deadline,
                record.matched.is_none(),
                record
                    .matched
                    .as_ref()
                    .map(|matched| matched.token_contract.as_str())
                    .unwrap_or("-")
            );
        }
        SubscriptionCommand::Status { order_id } => {
            if let Some(live_order) = live_order.as_ref() {
                let order = validate_subscription_live_order(
                    &snapshot.order_book,
                    Some(live_order),
                    *order_id,
                    &note_addr,
                )?;
                let state =
                    load_buyer_subscription_state(&money_lock.subscriptions_path, &note_addr)?;
                let record = if let Some(record) =
                    subscription_order_record(&state, &snapshot.order_book, *order_id)
                {
                    validate_subscription_record_matches_live_order(record, &snapshot, order)?;
                    record.clone()
                } else {
                    let reserve = check_subscription_buy_reserve(
                        order.escrow,
                        order.ticks,
                        order.price_per_tick,
                    )
                    .map_err(anyhow::Error::msg)?;
                    BuyerSubscriptionOrderRecord {
                        order_book: snapshot.order_book.clone(),
                        frame_model: snapshot.frame_model.clone(),
                        model_hash: snapshot.model_hash.clone(),
                        order_id: order.order_id,
                        max_price_per_tick: order.price_per_tick,
                        ticks: order.ticks,
                        deposit: reserve.deposit,
                        buyer_bond: reserve.buyer_bond,
                        escrow: order.escrow,
                        flags: order.flags,
                        deadline: order.deadline,
                        fill_cursor: MatchWatchCursor::new(0),
                        phase: BuyerSubscriptionPhase::Resting,
                        matched: None,
                    }
                };
                println!(
                    "{}",
                    render_subscription_record(&snapshot, &record, &note_addr, true, None)?
                );
            } else {
                let state =
                    load_buyer_subscription_state(&money_lock.subscriptions_path, &note_addr)?;
                subscription_order_record(&state, &snapshot.order_book, *order_id).ok_or_else(
                    || {
                        anyhow::anyhow!(
                            "subscription status cannot prove order #{order_id} belonged to note \
                             {note_addr}: it is absent from both the live book and durable subscription state"
                        )
                    },
                )?;
                let record = sync_subscription_match_once(
                    &chain,
                    &money_lock.subscriptions_path,
                    &note_addr,
                    &snapshot.order_book,
                    *order_id,
                    persist_handle.as_ref(),
                )
                .await?;
                match record.phase {
                    BuyerSubscriptionPhase::Matched => {
                        let (record, facts, quota) = refresh_subscription_match(
                            &chain,
                            &money_lock.subscriptions_path,
                            &note_addr,
                            &snapshot.order_book,
                            *order_id,
                        )
                        .await?;
                        println!(
                            "{}",
                            render_subscription_record(
                                &snapshot,
                                &record,
                                &note_addr,
                                false,
                                Some((&facts, &quota)),
                            )?
                        );
                    }
                    BuyerSubscriptionPhase::Terminal => println!(
                        "{} authoritative_terminal=true",
                        render_subscription_record(&snapshot, &record, &note_addr, false, None)?
                    ),
                    BuyerSubscriptionPhase::Resting => println!(
                        "{} state=absent_without_authenticated_fill",
                        render_subscription_record(&snapshot, &record, &note_addr, false, None)?
                    ),
                }
            }
        }
        SubscriptionCommand::Cancel { order_id } => {
            let order = validate_subscription_live_order(
                &snapshot.order_book,
                live_order.as_ref(),
                *order_id,
                &note_addr,
            )?
            .clone();
            let keys = require_subscription_keys(&args, "cancel", None)?;
            direct_chain_read_with_timeout(args.read_timeout.read_timeout_secs, async {
                chain.assert_seller_note_current(&note).await?;
                chain
                    .assert_note_owner_matches("subscription cancel", &note, &keys)
                    .await
            })
            .await?;
            let mut state =
                load_buyer_subscription_state(&money_lock.subscriptions_path, &note_addr)?;
            ensure_subscription_record_from_order(&mut state, &snapshot, &order)?;
            write_buyer_subscription_state(&money_lock.subscriptions_path, &state)?;
            let balance_before = subscription_note_ecc_balance(&chain, &note).await?;
            let submit = chain
                .cancel_inference_order(&note, &keys, &target.model_hash, *order_id)
                .await;
            let outcome =
                reconcile_subscription_cancel(reconcile_wait, balance_before, order.escrow, || {
                    let chain = &chain;
                    let note = note.clone();
                    let note_addr = note_addr.clone();
                    let order_book = snapshot.order_book.clone();
                    let state_path = money_lock.subscriptions_path.clone();
                    let persist_handle = persist_handle.clone();
                    let order_id = *order_id;
                    async move {
                        let active = chain
                            .inference_buyer_order_is_active_for_owner(
                                &dexdo_core::Address::parse(&order_book)?,
                                order_id,
                                &note_addr,
                            )
                            .await?;
                        let balance_after = subscription_note_ecc_balance(chain, &note).await?;
                        let record = sync_subscription_match_once(
                            chain,
                            &state_path,
                            &note_addr,
                            &order_book,
                            order_id,
                            persist_handle.as_ref(),
                        )
                        .await?;
                        Ok((active, balance_after, record.matched))
                    }
                })
                .await?;
            match outcome {
                SubscriptionCancelOutcome::Refunded { expected_balance } => {
                    mark_cancelled_buyer_subscription_terminal(
                        &money_lock.subscriptions_path,
                        &note_addr,
                        &snapshot.order_book,
                        *order_id,
                    )?;
                    println!(
                        "subscription cancel confirmed model={} order_book={} order_id={} owner={} \
                         refund={} balance_before={} balance_after={}",
                        snapshot.frame_model,
                        snapshot.order_book,
                        order_id,
                        note_addr,
                        order.escrow,
                        balance_before,
                        expected_balance
                    );
                    return Ok(());
                }
                SubscriptionCancelOutcome::Filled { token_contract } => {
                    bail!(
                        "subscription cancel lost the fill race: order #{order_id} matched \
                         {token_contract} in full; no second money action was submitted"
                    );
                }
                SubscriptionCancelOutcome::ContradictoryFill { token_contract } => {
                    return Err(anyhow::Error::new(ChainError::AmbiguousSubmit(format!(
                        "subscription order #{order_id} is simultaneously resting and filled as \
                         {token_contract}; no retry was sent"
                    ))));
                }
                SubscriptionCancelOutcome::Unconfirmed { expected_balance } => {
                    if let Err(error) = submit {
                        return Err(error.context(
                            "subscription cancel was not confirmed by order removal plus exact refund",
                        ));
                    }
                    return Err(anyhow::Error::new(ChainError::AmbiguousSubmit(format!(
                        "subscription cancel submit returned, but order/refund/fill facts remained \
                         unconfirmed through the read timeout; expected balance {expected_balance}; \
                         no retry was sent"
                    ))));
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_subscription(args: SubscriptionArgs) -> Result<()> {
    let mock_mode = subscription_mock_mode(&args.mock)?;
    let place_plan = match &args.command {
        SubscriptionCommand::Place(place) => Some(subscription_place_plan(place)?),
        _ => None,
    };
    if mock_mode {
        return run_mock_subscription(&args, place_plan);
    }
    bail!("subscription unavailable: build with `--features shellnet`")
}

pub(crate) async fn run_buyer(args: BuyerArgs) -> Result<()> {
    let json_mode = args.json;
    let mut machine_events = json_mode.then(machine::BuyerEventWriter::new);
    let mut machine_context = BuyerMachineErrorContext::default();
    let result = run_buyer_inner(
        args,
        &mut machine_events,
        &mut machine_context,
        BuyerCommandRuntime::production(),
    )
    .await;
    if let Err(err) = result {
        if machine::is_printed_error(&err) {
            return Err(err);
        }
        if let Some(events) = machine_events.as_mut() {
            let code = machine::classify_error(machine::OP_BUYER_START, &err);
            if code == machine::ErrorCode::NoLiquidity
                && format!("{err:#}")
                    .to_ascii_lowercase()
                    .contains("no_executable_ask")
            {
                machine_context.failure_class = Some("no_executable_ask".to_string());
            }
            events.error_with_cause(
                machine::OP_BUYER_START,
                code,
                &err,
                machine_context.fields(),
            )?;
            return Err(machine::printed_error());
        }
        return Err(err);
    }
    Ok(())
}

#[derive(Default)]
struct BuyerMachineErrorContext {
    network: Option<String>,
    frame_model: Option<String>,
    order_book: Option<String>,
    token_contract: Option<String>,
    deal_handle: Option<String>,
    failure_class: Option<String>,
    missing_or_unset: Option<String>,
}

impl BuyerMachineErrorContext {
    fn set_token_contract(&mut self, token_contract: &str) {
        self.token_contract = Some(token_contract.to_string());
        self.deal_handle = Some(deals::make_handle_id(
            token_contract,
            deals::DealHandleRole::Buyer,
        ));
    }

    fn fields(&self) -> Value {
        let mut obj = Map::new();
        if let Some(v) = &self.network {
            obj.insert("network".to_string(), json!(v));
        }
        if let Some(v) = &self.frame_model {
            obj.insert("frame_model".to_string(), json!(v));
        }
        if let Some(v) = &self.order_book {
            obj.insert("order_book".to_string(), json!(v));
        }
        if let Some(v) = &self.token_contract {
            obj.insert("token_contract".to_string(), json!(v));
        }
        if let Some(v) = &self.deal_handle {
            obj.insert("deal_handle".to_string(), json!(v));
        }
        if let Some(v) = &self.failure_class {
            obj.insert("failure_class".to_string(), json!(v));
        }
        if let Some(v) = &self.missing_or_unset {
            obj.insert("missing_or_unset".to_string(), json!(v));
        }
        Value::Object(obj)
    }
}

#[cfg(debug_assertions)]
fn buyer_machine_error_fixture_from_env() -> Option<anyhow::Error> {
    let code = std::env::var("DEXDO_BUYER_JSON_ERROR_FIXTURE").ok()?;
    if code == "CHAIN_TRANSPORT" {
        return Some(anyhow::Error::new(ChainError::Transport(
            "shellnet rpc transport fixture".to_string(),
        )));
    }
    let message = match code.as_str() {
        "NO_LIQUIDITY" => "no liquidity fixture",
        "INSUFFICIENT_BALANCE" => "insufficient balance fixture",
        "HANDOVER_TIMEOUT" => "handover within deadline fixture",
        "SETTLEMENT_FAILED" => "settlement streamStop fixture",
        "NOT_RECOVERABLE_YET" => "not recoverable yet fixture",
        "DISPUTED_DEAL" => "deal is disputed fixture",
        _ => return Some(anyhow::anyhow!("invalid fixture code {code}")),
    };
    Some(anyhow::anyhow!(message))
}

fn validate_buyer_runtime_surface_policy(
    policy: &policy::BuyerRuntimePolicy,
    local_listen: Option<std::net::SocketAddr>,
) -> Result<()> {
    if local_listen.is_some() {
        return Ok(());
    }

    let mut unsupported = Vec::new();
    if policy.dead_gateway == policy::DeadGatewayAction::NextSeller {
        unsupported.push("buyer.on.dead_gateway=next_seller");
    }
    if policy.empty_stream == policy::EmptyStreamAction::NextSeller {
        unsupported.push("buyer.on.empty_stream=next_seller");
    }
    if unsupported.is_empty() {
        return Ok(());
    }

    bail!(
        "policy_action failure_class=policy_validation action=fail_closed token_contract=<not-placed> \
         state=pre_order result=unsupported_policy_choice runtime=one-shot unsupported_choices={} \
         diagnostic=one-shot dead_gateway/empty_stream next_seller failover is not implemented; choose \
         dead_gateway=retry_then_reclaim|fail_closed and empty_stream=reclaim|fail_closed",
        unsupported.join(",")
    );
}

type SharedBuyerEvents = Option<Arc<tokio::sync::Mutex<machine::BuyerEventWriter>>>;

async fn emit_shared_buyer_event(
    events: &SharedBuyerEvents,
    event: &'static str,
    operation: &'static str,
    fields: Value,
) -> Result<()> {
    if let Some(events) = events {
        events.lock().await.event(event, operation, fields)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuyerShutdownReport {
    SubscriptionPreserved,
    Settlement {
        action: &'static str,
        state: &'static str,
        submitted: bool,
        outcome: &'static str,
    },
    NoDeal,
}

impl BuyerShutdownReport {
    const fn chain_write_submitted(self) -> bool {
        match self {
            Self::SubscriptionPreserved | Self::NoDeal => false,
            Self::Settlement { submitted, .. } => submitted,
        }
    }
}

fn buyer_shutdown_report(
    session: Option<&dexdo::buyer::api::SessionSettle>,
) -> BuyerShutdownReport {
    let Some(session) = session else {
        return BuyerShutdownReport::NoDeal;
    };
    if let Some(action) = session.terminal_action() {
        let outcome = match action {
            dexdo::buyer::api::SessionTerminalAction::StreamStop
            | dexdo::buyer::api::SessionTerminalAction::StreamCleanup => "settled",
            dexdo::buyer::api::SessionTerminalAction::StreamDispute => "disputed",
            dexdo::buyer::api::SessionTerminalAction::ObservedTerminal => "terminal",
        };
        return BuyerShutdownReport::Settlement {
            action: action.event_action(),
            state: action.event_state(),
            submitted: action.chain_write_submitted(),
            outcome,
        };
    }
    if session.preserves_on_exit() {
        BuyerShutdownReport::SubscriptionPreserved
    } else {
        BuyerShutdownReport::Settlement {
            action: "streamStop",
            state: "unconfirmed",
            submitted: false,
            outcome: "unconfirmed",
        }
    }
}

fn require_complete_buyer_quote(selection: &BuyerQuoteSelection) -> Result<()> {
    if selection.quote.filled_ticks == 0 {
        bail!("buyer quote: no liquidity");
    }
    if !selection.quote.complete {
        bail!(
            "buyer quote: incomplete quote filled_ticks={}",
            selection.quote.filled_ticks
        );
    }
    Ok(())
}

fn require_stream_buy_ticks(ticks: u128) -> Result<()> {
    if ticks >= dexdo_core::params::MIN_STREAM_BUY_TICKS {
        return Ok(());
    }
    let minimum_ticks = dexdo_core::params::MIN_STREAM_BUY_TICKS;
    bail!(
        "invalid buy ticks: --ticks {ticks} is below the {minimum_ticks}-tick stream minimum; \
         TokenContract funding needs the probe tick plus at least one streaming tick. \
         Buy at least {minimum_ticks} ticks or wait for an ask with >= {minimum_ticks} ticks"
    );
}

fn is_replay_protection_error(err: &anyhow::Error) -> bool {
    if err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<ChainError>(),
            Some(ChainError::AmbiguousSubmit(_))
        )
    }) {
        return false;
    }
    let msg = format!("{err:#}").to_ascii_lowercase();
    msg.contains("exit code 52") || msg.contains("replay protection")
}

fn buyer_deal_init_error(err: anyhow::Error) -> dexdo::buyer::api::DealInitError {
    #[cfg(feature = "shellnet")]
    if let Some(error) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<DurableBuyerSubmitReconciliationError>())
    {
        return error.deal_init.clone();
    }
    if let Some(error) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<dexdo::buyer::api::DealInitError>())
    {
        return error.clone();
    }
    dexdo::buyer::api::DealInitError::new(format!("{err:#}"))
}

#[allow(clippy::too_many_arguments)]
async fn prepare_lazy_buyer_api_deal_with_replay_backoff(
    chain: Arc<dyn ChainBackend>,
    buyer: Arc<dexdo::buyer::Buyer>,
    args: Arc<BuyerArgs>,
    explicit_tc: Option<String>,
    frame_model: String,
    content_check: dexdo::buyer::api::ContentCheck,
    models_cfg: Arc<dexdo::seller::ModelsConfig>,
    buyer_policy: Option<policy::BuyerRuntimePolicy>,
    api_failure_policy: dexdo::buyer::api::BuyerApiFailurePolicy,
    events: SharedBuyerEvents,
    raised_money: Option<BuyerQuoteSubmitOutcome>,
    shellnet_preflight: BuyerShellnetPreflight,
) -> std::result::Result<dexdo::buyer::api::ApiDeal, dexdo::buyer::api::DealInitError> {
    let mut attempt = 1u64;
    loop {
        let result = prepare_lazy_buyer_api_deal_once(
            chain.clone(),
            buyer.clone(),
            args.clone(),
            explicit_tc.clone(),
            frame_model.clone(),
            content_check.clone(),
            models_cfg.clone(),
            buyer_policy.clone(),
            api_failure_policy,
            events.clone(),
            raised_money.clone(),
            shellnet_preflight,
        )
        .await;
        match result {
            Ok(deal) => return Ok(deal),
            Err(err)
                if is_replay_protection_error(&err)
                    && attempt < BUYER_REPLAY_PROTECTION_MAX_ATTEMPTS =>
            {
                let backoff_secs =
                    attempt.saturating_mul(BUYER_REPLAY_PROTECTION_BACKOFF_STEP_SECS);
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                attempt = attempt.saturating_add(1);
            }
            Err(err) if is_replay_protection_error(&err) => {
                return Err(dexdo::buyer::api::DealInitError::new(format!(
                    "on-demand purchase failed after replay-protection retries: {err:#}"
                )));
            }
            Err(err) => return Err(buyer_deal_init_error(err)),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn prepare_lazy_buyer_api_deal_once(
    chain: Arc<dyn ChainBackend>,
    buyer: Arc<dexdo::buyer::Buyer>,
    args: Arc<BuyerArgs>,
    explicit_tc: Option<String>,
    frame_model: String,
    content_check: dexdo::buyer::api::ContentCheck,
    models_cfg: Arc<dexdo::seller::ModelsConfig>,
    buyer_policy: Option<policy::BuyerRuntimePolicy>,
    api_failure_policy: dexdo::buyer::api::BuyerApiFailurePolicy,
    events: SharedBuyerEvents,
    raised_money: Option<BuyerQuoteSubmitOutcome>,
    shellnet_preflight: BuyerShellnetPreflight,
) -> Result<dexdo::buyer::api::ApiDeal> {
    let raised_money = if args.mock.mock_chain {
        raised_money
    } else {
        let escrow = args
            .escrow
            .unwrap_or_else(|| required_escrow_for_buy(args.ticks, args.max_price_per_tick));
        raise_pending_buyer_money_before_fresh_reads(
            chain.as_ref(),
            buyer.as_ref(),
            args.identity.note_addr.as_deref(),
            &BuyerSubmitIntent::on_demand(),
            explicit_tc.as_deref(),
            args.ticks,
            args.max_price_per_tick,
            escrow,
        )
        .await?
        .or(raised_money)
    };
    require_stream_buy_ticks(args.ticks)?;
    if !args.mock.mock_chain && shellnet_preflight.should_run() {
        shellnet_doctor_preflight(&args.contracts, args.market.as_deref()).await?;
        if let Some(policy) = load_enabled_model_registry_policy(
            RegistryRole::Buyer,
            &args.registry,
            &args.contracts,
        )? {
            reject_buyer_raw_token_contract_without_registry_book_proof(
                args.market.as_deref(),
                args.token_contract.as_deref(),
                &frame_model,
            )?;
            let expected_order_book = if let Some(market) = args.market.as_deref() {
                load_market(market)?.inference_order_book
            } else {
                let note_addr = args.identity.note_addr.as_deref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "real shellnet: --note-addr is required to derive the buyer order book"
                    )
                })?;
                expected_order_book_for_note(&args.contracts, note_addr, &frame_model).await?
            };
            let order_book_active =
                order_book_active_from_contracts(&args.contracts, &expected_order_book).await?;
            enforce_model_registry_policy(
                RegistryRole::Buyer,
                &policy,
                &args.contracts,
                &frame_model,
                &expected_order_book,
                order_book_active,
                BuyerMissingBookPolicy::Reject,
            )
            .await?;
        }
    }

    let adopted_submit_identity = raised_money
        .as_ref()
        .and_then(|outcome| outcome.submit_reconciliation.as_ref())
        .map(|reconciliation| reconciliation.submit_identity.clone());
    #[cfg(feature = "shellnet")]
    let resumed_from_ordinary_journal = args.resume && raised_money.is_some();
    let mut service_renewal: Option<(u128, u128, u128)> = None;
    let mut buyer_order_id = None;
    #[cfg(feature = "shellnet")]
    let mut subscription_route_budget = None;
    #[cfg(not(feature = "shellnet"))]
    let subscription_route_budget = Option::<SubscriptionRouteBudget>::default();
    #[cfg(feature = "shellnet")]
    let mut preserve_subscription = false;
    #[cfg(not(feature = "shellnet"))]
    let preserve_subscription = false;
    #[cfg(feature = "shellnet")]
    let mut historical_resume_fill = None;
    let (mut token_contract, buy_ticks) = if let Some(outcome) = raised_money {
        if args.resume {
            emit_shared_buyer_event(
                &events,
                "resume_selected",
                machine::OP_BUYER_START,
                recovered_buyer_resume_selected_fields(&frame_model, &outcome)?,
            )
            .await?;
        } else {
            emit_shared_buyer_event(
                &events,
                "buy_submitted",
                machine::OP_BUYER_START,
                buyer_submit_event_fields(
                    &frame_model,
                    if explicit_tc.is_some() {
                        "explicit_token_contract"
                    } else {
                        "model_order_book"
                    },
                    outcome.ticks,
                    outcome.max_price_per_tick,
                    outcome.escrow,
                    BuyerSubmitProgress {
                        reconciled_ambiguous_submit: true,
                        submit_reconciliation: outcome.submit_reconciliation.clone(),
                    },
                ),
            )
            .await?;
        }
        (outcome.token_contract, outcome.ticks)
    } else {
        match explicit_tc.clone() {
            Some(tc) => {
                if args.resume {
                    emit_shared_buyer_event(
                        &events,
                        "resume_selected",
                        machine::OP_BUYER_START,
                        json!({
                            "token_contract": tc.clone(),
                            "role": "buyer",
                            "source": "token_contract",
                            "deal_handle": deals::make_handle_id(&tc, deals::DealHandleRole::Buyer),
                            "frame_model": frame_model.clone()
                        }),
                    )
                    .await?;
                } else {
                    let selection = buyer_quote_selection_for_submit(
                        chain.as_ref(),
                        args.mock.mock_chain,
                        args.identity.note_addr.as_deref(),
                        &BuyerSubmitIntent::on_demand(),
                        Some(&tc),
                        args.ticks,
                        args.max_price_per_tick,
                        args.escrow,
                        events
                            .is_none()
                            .then_some((args.as_ref(), frame_model.as_str())),
                    )
                    .await?;
                    require_complete_buyer_quote(&selection)?;
                    emit_shared_buyer_event(
                        &events,
                        "quote_selected",
                        machine::OP_BUYER_START,
                        quote_selected_fields(
                            &frame_model,
                            &selection,
                            args.ticks,
                            args.max_price_per_tick,
                        ),
                    )
                    .await?;
                    require_stream_buy_ticks(args.ticks)?;
                    let submit_frame_model = frame_model.clone();
                    let outcome = execute_buyer_quote_submit(
                        chain.as_ref(),
                        buyer.as_ref(),
                        args.mock.mock_chain,
                        args.identity.note_addr.as_deref(),
                        &BuyerSubmitIntent::on_demand(),
                        Some(&tc),
                        &selection,
                        args.ticks,
                        args.max_price_per_tick,
                        selection.escrow,
                        events.is_none().then_some(frame_model.as_str()),
                        |progress| {
                            emit_shared_buyer_event(
                                &events,
                                "buy_submitted",
                                machine::OP_BUYER_START,
                                buyer_submit_event_fields(
                                    &submit_frame_model,
                                    "explicit_token_contract",
                                    args.ticks,
                                    args.max_price_per_tick,
                                    selection.escrow,
                                    progress,
                                ),
                            )
                        },
                    )
                    .await?;
                    emit_shared_buyer_event(
                        &events,
                        "matched",
                        machine::OP_BUYER_START,
                        json!({
                            "frame_model": frame_model.clone(),
                            "order_book": "explicit_token_contract",
                            "token_contract": outcome.token_contract.clone()
                        }),
                    )
                    .await?;
                    if !outcome.token_contract.eq_ignore_ascii_case(&tc) {
                        bail!(
                            "explicit on-demand submit matched {}, expected {}",
                            outcome.token_contract,
                            tc
                        );
                    }
                }
                (tc, args.ticks)
            }
            None if args.resume => {
                let since_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0)
                    - RESUME_LOOKBACK_SECS;
                let fill = chain
                    .wait_matched_token_contract(
                        since_unix,
                        std::time::Duration::from_secs(DEAL_WAIT_SECS),
                    )
                    .await?
                    .ok_or_else(|| {
                        ChainError::Chain("buyer fill event returned no match".to_string())
                    })?;
                let tc = fill.token_contract.clone();
                buyer_order_id = Some(fill.order_id);
                #[cfg(feature = "shellnet")]
                {
                    historical_resume_fill = Some(fill.clone());
                }
                emit_shared_buyer_event(
                    &events,
                    "resume_selected",
                    machine::OP_BUYER_START,
                    json!({
                        "token_contract": tc.clone(),
                        "order_id": machine::amount(fill.order_id),
                        "role": "buyer",
                        "source": "note_fill_event",
                        "deal_handle": deals::make_handle_id(&tc, deals::DealHandleRole::Buyer),
                        "frame_model": frame_model.clone()
                    }),
                )
                .await?;
                (tc, fill.ticks)
            }
            None => {
                let ticks = args.ticks;
                let max_price = args.max_price_per_tick;
                let escrow = args
                    .escrow
                    .unwrap_or_else(|| dexdo_core::required_escrow_for_buy(ticks, max_price));
                service_renewal = Some((ticks, max_price, escrow));
                let selection = buyer_quote_selection_for_submit(
                    chain.as_ref(),
                    args.mock.mock_chain,
                    args.identity.note_addr.as_deref(),
                    &BuyerSubmitIntent::on_demand(),
                    None,
                    ticks,
                    max_price,
                    Some(escrow),
                    events
                        .is_none()
                        .then_some((args.as_ref(), frame_model.as_str())),
                )
                .await?;
                require_complete_buyer_quote(&selection)?;
                emit_shared_buyer_event(
                    &events,
                    "quote_selected",
                    machine::OP_BUYER_START,
                    quote_selected_fields(&frame_model, &selection, ticks, max_price),
                )
                .await?;
                require_stream_buy_ticks(ticks)?;
                let submit_frame_model = frame_model.clone();
                let outcome = execute_buyer_quote_submit(
                    chain.as_ref(),
                    buyer.as_ref(),
                    args.mock.mock_chain,
                    args.identity.note_addr.as_deref(),
                    &BuyerSubmitIntent::on_demand(),
                    None,
                    &selection,
                    ticks,
                    max_price,
                    escrow,
                    events.is_none().then_some(frame_model.as_str()),
                    |progress| {
                        emit_shared_buyer_event(
                            &events,
                            "buy_submitted",
                            machine::OP_BUYER_START,
                            buyer_submit_event_fields(
                                &submit_frame_model,
                                "model_order_book",
                                ticks,
                                max_price,
                                escrow,
                                progress,
                            ),
                        )
                    },
                )
                .await?;
                emit_shared_buyer_event(
                    &events,
                    "matched",
                    machine::OP_BUYER_START,
                    json!({
                        "frame_model": frame_model.clone(),
                        "order_book": "model_order_book",
                        "token_contract": outcome.token_contract.clone()
                    }),
                )
                .await?;
                (outcome.token_contract, outcome.ticks)
            }
        }
    };
    #[cfg(feature = "shellnet")]
    let mut buy_ticks = buy_ticks;

    #[cfg(feature = "shellnet")]
    if args.resume && !args.mock.mock_chain && !resumed_from_ordinary_journal {
        let note_addr = args.identity.note_addr.as_deref().ok_or_else(|| {
            anyhow::anyhow!("subscription resume requires --note-addr for ownership validation")
        })?;
        if let Some(subscription) = classify_subscription_resume_target(
            chain.as_ref(),
            note_addr,
            &frame_model,
            &token_contract,
            historical_resume_fill.as_ref(),
        )
        .await?
        {
            buy_ticks = subscription.ticks;
            buyer_order_id = buyer_order_id.or(subscription.order_id);
            subscription_route_budget = Some(SubscriptionRouteBudget {
                remaining_current_week: u64::try_from(subscription.quota.remaining_current_week)
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "subscription remaining weekly quota {} exceeds u64",
                            subscription.quota.remaining_current_week
                        )
                    })?,
                state: subscription.facts.state,
                subscription: subscription.facts.subscription,
            });
            preserve_subscription = true;
            emit_shared_buyer_event(
                &events,
                "subscription_resume_classified",
                machine::OP_BUYER_START,
                json!({
                    "token_contract": token_contract.clone(),
                    "source": if historical_resume_fill.is_some() {
                        "note_fill_event"
                    } else {
                        "explicit_token_contract"
                    },
                    "week_index": subscription.facts.subscription.week_index,
                    "week_base_tokens": machine::amount(
                        subscription.facts.subscription.week_base_tokens
                    ),
                    "remaining_current_week": machine::amount(
                        subscription.quota.remaining_current_week
                    ),
                    "buyer_locked_total": machine::amount(
                        subscription.quota.buyer_locked_total
                    )
                }),
            )
            .await?;
        } else if historical_resume_fill.is_some() {
            chain
                .assert_model_only_resume_target(&token_contract)
                .await?;
        }
    }

    record_buyer_token_contract_after_money_move(args.as_ref(), &token_contract);

    let mut handover_attempt = 1u64;
    let handover = 'handover: loop {
        let hv_deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(DEAL_WAIT_SECS);
        let hv_deadline_unix = machine::now_unix()?.saturating_add(DEAL_WAIT_SECS);
        emit_shared_buyer_event(
            &events,
            "handover_waiting",
            machine::OP_BUYER_START,
            json!({
                "token_contract": token_contract.clone(),
                "deadline_unix": hv_deadline_unix,
                "poll_interval_ms": BUYER_HANDOVER_POLL_INTERVAL.as_millis()
            }),
        )
        .await?;
        loop {
            match buyer
                .resolve_endpoint(chain.as_ref(), &token_contract)
                .await
            {
                Ok(h) => break 'handover h,
                Err(e) => {
                    if is_malformed_handover_error(&e) {
                        if let Some(policy) = buyer_policy.as_ref() {
                            apply_malformed_handover_policy(
                                chain.as_ref(),
                                buyer.as_ref(),
                                &token_contract,
                                policy,
                                preserve_subscription,
                                &e,
                            )
                            .await?;
                        }
                        return Err(
                            e.context(format!("buyer: malformed handover for {token_contract}"))
                        );
                    }
                    if std::time::Instant::now() >= hv_deadline {
                        let last_error = format!("{e:#}");
                        let diagnostic = handover_timeout_diagnostic(
                            chain.as_ref(),
                            &token_contract,
                            &last_error,
                        )
                        .await;
                        if let Some(policy) = buyer_policy.as_ref() {
                            let policy_outcome = apply_no_handover_after_match_policy(
                                chain.as_ref(),
                                buyer.as_ref(),
                                &token_contract,
                                policy,
                                preserve_subscription,
                                service_renewal,
                                handover_attempt,
                                &diagnostic,
                                args.identity.note_addr.as_deref(),
                            )
                            .await;
                            match policy_outcome {
                                Err(policy_err) => {
                                    return Err(e.context(format!("{policy_err:#}")));
                                }
                                Ok(NoHandoverPolicyOutcome::RetryCurrent) => {
                                    continue 'handover;
                                }
                                Ok(NoHandoverPolicyOutcome::RetryNext(next)) => {
                                    token_contract = next;
                                    record_buyer_token_contract_after_money_move(
                                        args.as_ref(),
                                        &token_contract,
                                    );
                                    handover_attempt = handover_attempt.saturating_add(1);
                                    continue 'handover;
                                }
                            }
                        }
                        return Err(e.context(diagnostic));
                    }
                    tokio::time::sleep(BUYER_HANDOVER_POLL_INTERVAL).await;
                }
            }
        }
    };

    let deal_handle = deals::make_handle_id(&token_contract, deals::DealHandleRole::Buyer);
    emit_shared_buyer_event(
        &events,
        "handover_received",
        machine::OP_BUYER_START,
        json!({
            "token_contract": token_contract.clone(),
            "deal_handle": deal_handle.clone(),
            "handover_anchor": {"kind":"token_contract_state","value":"handover_present"}
        }),
    )
    .await?;

    let should_save_handle = !args.mock.mock_chain || events.is_some();
    if should_save_handle {
        let mock_note_addr;
        let note_addr = if args.mock.mock_chain {
            mock_note_addr = format!("mock:{}", note_pubkey_id(&buyer.note.pubkey()));
            mock_note_addr.as_str()
        } else {
            args.identity.note_addr.as_deref().ok_or_else(|| {
                anyhow::anyhow!("real shellnet: --note-addr is required to save the deal handle")
            })?
        };
        let endpoint = args.local_listen.map(|addr| deals::DealEndpointInfo {
            kind: "local-listen".to_string(),
            value: addr.to_string(),
        });
        let input = RuntimeDealHandleInput {
            role: deals::DealHandleRole::Buyer,
            deals_dir: args.deals_dir.as_deref(),
            token_contract: &token_contract,
            note_addr,
            frame_model: &frame_model,
            market: None,
            market_path: args.market.as_deref(),
            contracts: &args.contracts,
            endpoint,
            created_order_ids: buyer_order_id.into_iter().collect(),
        };
        if args.mock.mock_chain {
            save_mock_runtime_deal_handle(input)?;
        } else {
            save_runtime_deal_handle(input, events.is_none())?;
        }
    }

    clear_adopted_buyer_money_journal(
        args.identity.note_addr.as_deref(),
        adopted_submit_identity.as_deref(),
        &token_contract,
    )?;
    let session = Arc::new(
        dexdo::buyer::api::SessionSettle::new_with_failure_policy_and_lifetime(
            chain.clone(),
            token_contract.clone(),
            buyer.note.clone(),
            api_failure_policy,
            if preserve_subscription {
                dexdo::buyer::api::SessionLifetimePolicy::Preserve
            } else {
                dexdo::buyer::api::SessionLifetimePolicy::SettleOnExit
            },
        ),
    );
    let weekly = subscription_weekly_budget(&chain, &token_contract, subscription_route_budget);
    let deal = dexdo::buyer::api::ApiDeal::new(
        dexdo::buyer::api::Route {
            handover,
            token_contract,
            max_tokens: subscription_route_budget
                .map(|budget| budget.remaining_current_week)
                .unwrap_or_else(|| consumer_api_token_budget(buy_ticks)),
        },
        session,
        Arc::new(dexdo::buyer::api::ContentGate::new(
            content_check,
            models_cfg,
        )),
    );
    Ok(match weekly {
        Some(weekly) => deal.with_weekly_budget(weekly),
        None => deal,
    })
}

/// A subscription route's live weekly allowance; `None` for an ordinary by-fact deal, whose
/// funded budget is the whole term's volume and never moves.
fn subscription_weekly_budget(
    chain: &Arc<dyn ChainBackend>,
    token_contract: &str,
    budget: Option<SubscriptionRouteBudget>,
) -> Option<Arc<dexdo::buyer::api::SubscriptionWeeklyBudget>> {
    budget.map(|budget| {
        Arc::new(dexdo::buyer::api::SubscriptionWeeklyBudget::new(
            chain.clone(),
            token_contract.to_string(),
            &budget.state,
            &budget.subscription,
        ))
    })
}

#[allow(clippy::too_many_arguments)]
fn build_on_demand_buyer_api_state(
    chain: Arc<dyn ChainBackend>,
    buyer: Arc<dexdo::buyer::Buyer>,
    args: Arc<BuyerArgs>,
    explicit_tc: Option<String>,
    frame_model: String,
    content_check: dexdo::buyer::api::ContentCheck,
    models_cfg: Arc<dexdo::seller::ModelsConfig>,
    buyer_policy: Option<policy::BuyerRuntimePolicy>,
    api_failure_policy: dexdo::buyer::api::BuyerApiFailurePolicy,
    events: SharedBuyerEvents,
    raised_money: Option<BuyerQuoteSubmitOutcome>,
    shellnet_preflight: BuyerShellnetPreflight,
    pre_adopted_deal: Option<dexdo::buyer::api::ApiDeal>,
    recover_terminal_model_deal: bool,
) -> dexdo::buyer::api::ApiState {
    let raised_money = Arc::new(std::sync::Mutex::new(raised_money));
    let initializer = {
        let chain = chain.clone();
        let buyer = buyer.clone();
        let args = args.clone();
        let explicit_tc = explicit_tc.clone();
        let frame_model = frame_model.clone();
        let content_check = content_check.clone();
        let models_cfg = models_cfg.clone();
        let buyer_policy = buyer_policy.clone();
        let events = events.clone();
        let raised_money = raised_money.clone();
        Arc::new(move || {
            let chain = chain.clone();
            let buyer = buyer.clone();
            let args = args.clone();
            let explicit_tc = explicit_tc.clone();
            let frame_model = frame_model.clone();
            let content_check = content_check.clone();
            let models_cfg = models_cfg.clone();
            let buyer_policy = buyer_policy.clone();
            let events = events.clone();
            let raised_money = raised_money
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            Box::pin(async move {
                prepare_lazy_buyer_api_deal_with_replay_backoff(
                    chain,
                    buyer,
                    args,
                    explicit_tc,
                    frame_model,
                    content_check,
                    models_cfg,
                    buyer_policy,
                    api_failure_policy,
                    events,
                    raised_money,
                    shellnet_preflight,
                )
                .await
            }) as dexdo::buyer::api::DealInitFuture
        }) as dexdo::buyer::api::DealInitializer
    };
    let initializer_timeout = std::time::Duration::from_secs(DEAL_WAIT_SECS);
    match (pre_adopted_deal, recover_terminal_model_deal) {
        (Some(active), true) => dexdo::buyer::api::ApiState::recoverable_lazy_with_active(
            buyer,
            frame_model,
            active,
            initializer,
            initializer_timeout,
        ),
        (Some(active), false) => dexdo::buyer::api::ApiState {
            buyer,
            frame_model,
            deals: Arc::new(dexdo::buyer::api::RouteManager::new(active)),
        },
        (None, true) => dexdo::buyer::api::ApiState::recoverable_lazy(
            buyer,
            frame_model,
            initializer,
            initializer_timeout,
        ),
        (None, false) => {
            dexdo::buyer::api::ApiState::lazy(buyer, frame_model, initializer, initializer_timeout)
        }
    }
}

fn model_only_on_demand_recovery_enabled(
    _mock_chain: bool,
    has_explicit_token_contract: bool,
    has_market_manifest: bool,
) -> bool {
    !has_explicit_token_contract && !has_market_manifest
}

fn render_local_openai_handoff(
    addr: std::net::SocketAddr,
    frame_model: &str,
    continuity_mode: ContinuityModeArg,
) -> Option<String> {
    if !addr.ip().is_loopback() {
        return None;
    }
    let continuity = match continuity_mode {
        ContinuityModeArg::Proactive => {
            "proactive: may keep a warm deal and spend while idle"
        }
        ContinuityModeArg::OnDemand => {
            "on-demand: does not spend while idle, but the first request after idle waits for purchase/handover"
        }
    };
    Some(format!(
        "OPENAI_BASE_URL=http://{addr}/v1\n\
         OPENAI_MODEL={frame_model}\n\
         OPENAI_API_KEY=dexdo-local\n\
         CONTINUITY_MODE={continuity}"
    ))
}

#[allow(clippy::too_many_arguments)]
async fn run_buyer_on_demand_local_api(
    args: BuyerArgs,
    chain: Arc<dyn ChainBackend>,
    buyer: dexdo::buyer::Buyer,
    explicit_tc: Option<String>,
    frame_model: String,
    content_check: dexdo::buyer::api::ContentCheck,
    models_cfg: Arc<dexdo::seller::ModelsConfig>,
    buyer_policy: Option<policy::BuyerRuntimePolicy>,
    api_failure_policy: dexdo::buyer::api::BuyerApiFailurePolicy,
    events: SharedBuyerEvents,
    raised_money: Option<BuyerQuoteSubmitOutcome>,
    shellnet_preflight: BuyerShellnetPreflight,
    shutdown: BuyerShutdownSignal,
) -> Result<()> {
    use dexdo::buyer::api;

    let bind = args
        .local_listen
        .ok_or_else(|| anyhow::anyhow!("on-demand local API requires --local-listen"))?;
    let recover_terminal_model_deal = model_only_on_demand_recovery_enabled(
        args.mock.mock_chain,
        explicit_tc.is_some(),
        args.market.is_some(),
    );
    let buyer = Arc::new(buyer);
    let args = Arc::new(args);
    let pre_adopted_deal = if args.resume {
        Some(
            prepare_lazy_buyer_api_deal_with_replay_backoff(
                chain.clone(),
                buyer.clone(),
                args.clone(),
                explicit_tc.clone(),
                frame_model.clone(),
                content_check.clone(),
                models_cfg.clone(),
                buyer_policy.clone(),
                api_failure_policy,
                events.clone(),
                raised_money.clone(),
                shellnet_preflight,
            )
            .await?,
        )
    } else {
        None
    };
    let endpoint_token_contract = pre_adopted_deal
        .as_ref()
        .map(|deal| deal.route.token_contract.as_str())
        .or(explicit_tc.as_deref())
        .map(|token_contract| {
            dexdo_core::normalize_wallet_address(token_contract)
                .map_err(|error| anyhow::anyhow!("on-demand endpoint TokenContract: {error}"))
        })
        .transpose()?;
    let endpoint_deal_handle = endpoint_token_contract
        .as_deref()
        .map(|token_contract| deals::make_handle_id(token_contract, deals::DealHandleRole::Buyer));
    emit_shared_buyer_event(
        &events,
        "endpoint_binding",
        machine::OP_BUYER_START,
        json!({
            "token_contract": endpoint_token_contract,
            "deal_handle": endpoint_deal_handle,
            "requested_bind_addr": bind.to_string(),
            "allow_port_zero": bind.port() == 0
        }),
    )
    .await?;

    let initializer_args = if pre_adopted_deal.is_some() {
        let mut args = args.as_ref().clone();
        args.resume = false;
        Arc::new(args)
    } else {
        args.clone()
    };
    let initializer_raised_money = if pre_adopted_deal.is_none() {
        raised_money
    } else {
        None
    };
    let state = build_on_demand_buyer_api_state(
        chain.clone(),
        buyer.clone(),
        initializer_args,
        explicit_tc,
        frame_model.clone(),
        content_check.clone(),
        models_cfg.clone(),
        buyer_policy,
        api_failure_policy,
        events.clone(),
        initializer_raised_money,
        shellnet_preflight,
        pre_adopted_deal,
        recover_terminal_model_deal,
    );
    let deals = state.deals.clone();
    if recover_terminal_model_deal {
        let escrow = args
            .escrow
            .unwrap_or_else(|| required_escrow_for_buy(args.ticks, args.max_price_per_tick));
        spawn_buyer_service_renewal(
            chain,
            buyer,
            deals.clone(),
            args.identity.note_addr.clone(),
            args.ticks,
            args.max_price_per_tick,
            escrow,
            dexdo::buyer::continuity::ContinuityMode::OnDemand,
            content_check,
            models_cfg,
            api_failure_policy,
        );
    }
    let (addr, task) = match api::serve(bind, state, args.anthropic_compat, shutdown).await {
        Ok(ok) => ok,
        Err(err) => {
            if let Some(events) = &events {
                let code = machine::classify_error(machine::OP_BUYER_START, &err);
                events.lock().await.error(
                    machine::OP_BUYER_START,
                    code,
                    json!({
                        "network": if args.mock.mock_chain { "mock" } else { "shellnet" },
                        "frame_model": frame_model.clone(),
                        "requested_bind_addr": bind.to_string()
                    }),
                )?;
                return Err(machine::printed_error());
            }
            return Err(err);
        }
    };
    let base_url = format!("http://{addr}/v1");
    let models_url = format!("{base_url}/models");
    let readiness = reqwest::Client::builder()
        .timeout(BUYER_API_READINESS_TIMEOUT)
        .build()?
        .get(&models_url)
        .send()
        .await
        .and_then(|r| r.error_for_status());
    let models: serde_json::Value = match readiness {
        Ok(response) => response.json().await?,
        Err(err) => {
            if let Some(events) = &events {
                events.lock().await.error(
                    machine::OP_BUYER_START,
                    machine::ErrorCode::EndpointReadinessFailed,
                    json!({
                        "network": if args.mock.mock_chain { "mock" } else { "shellnet" },
                        "frame_model": frame_model.clone(),
                        "requested_bind_addr": bind.to_string()
                    }),
                )?;
                return Err(machine::printed_error());
            }
            return Err(anyhow::anyhow!(
                "endpoint readiness /v1/models failed: {err}"
            ));
        }
    };
    let ready = models["data"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item["id"].as_str() == Some(frame_model.as_str()))
    });
    if !ready {
        if let Some(events) = &events {
            events.lock().await.error(
                machine::OP_BUYER_START,
                machine::ErrorCode::EndpointReadinessFailed,
                json!({
                    "network": if args.mock.mock_chain { "mock" } else { "shellnet" },
                    "frame_model": frame_model.clone(),
                    "requested_bind_addr": bind.to_string()
                }),
            )?;
            return Err(machine::printed_error());
        }
        bail!("endpoint readiness /v1/models did not include the selected model");
    }
    emit_shared_buyer_event(
        &events,
        "endpoint_ready",
        machine::OP_BUYER_RUNTIME,
        json!({
            "token_contract": endpoint_token_contract,
            "deal_handle": endpoint_deal_handle,
            "bind_addr": addr.to_string(),
            "base_url": base_url,
            "models_url": models_url,
            "served_models": [frame_model.clone()],
            "anthropic_compat": args.anthropic_compat
        }),
    )
    .await?;
    if events.is_none() {
        if let Some(handoff) = render_local_openai_handoff(addr, &frame_model, args.continuity_mode)
        {
            println!("{handoff}");
        }
    }
    tracing::info!(
        %addr,
        anthropic_compat = args.anthropic_compat,
        "consumer API listening; on-demand purchase will run on first chat request"
    );
    task.await?;

    let active = deals.current().await;
    let shutdown_report = buyer_shutdown_report(active.as_ref().map(|deal| deal.session.as_ref()));
    let (token_contract, deal_handle) = active
        .as_ref()
        .map(|deal| {
            let tc = deal.route.token_contract.clone();
            let handle = deals::make_handle_id(&tc, deals::DealHandleRole::Buyer);
            (tc, handle)
        })
        .or_else(|| endpoint_token_contract.zip(endpoint_deal_handle))
        .unwrap_or_default();
    emit_shared_buyer_event(
        &events,
        "stopping",
        machine::OP_BUYER_SHUTDOWN,
        json!({
            "token_contract": token_contract.clone(),
            "deal_handle": deal_handle.clone(),
            "reason": "signal"
        }),
    )
    .await?;
    match shutdown_report {
        BuyerShutdownReport::SubscriptionPreserved => {
            emit_shared_buyer_event(
                &events,
                "subscription_preserved",
                machine::OP_BUYER_SHUTDOWN,
                json!({
                    "token_contract": token_contract.clone(),
                    "deal_handle": deal_handle.clone(),
                    "role": "buyer",
                    "chain_write_submitted": shutdown_report.chain_write_submitted(),
                    "terminal": false
                }),
            )
            .await?;
        }
        BuyerShutdownReport::Settlement {
            action,
            state,
            submitted,
            ..
        } => {
            emit_shared_buyer_event(
                &events,
                "settlement_submitted",
                machine::OP_BUYER_SHUTDOWN,
                json!({
                    "token_contract": token_contract.clone(),
                    "deal_handle": deal_handle.clone(),
                    "role": "buyer",
                    "action": action,
                    "submitted": submitted
                }),
            )
            .await?;
            emit_shared_buyer_event(
                &events,
                "settled",
                machine::OP_BUYER_SHUTDOWN,
                json!({
                    "token_contract": token_contract.clone(),
                    "deal_handle": deal_handle.clone(),
                    "role": "buyer",
                    "action": action,
                    "state": state,
                    "terminal": false
                }),
            )
            .await?;
        }
        BuyerShutdownReport::NoDeal => {
            emit_shared_buyer_event(
                &events,
                "settlement_submitted",
                machine::OP_BUYER_SHUTDOWN,
                json!({
                    "token_contract": token_contract.clone(),
                    "deal_handle": deal_handle.clone(),
                    "role": "buyer",
                    "action": "streamStop",
                    "submitted": false
                }),
            )
            .await?;
            emit_shared_buyer_event(
                &events,
                "settled",
                machine::OP_BUYER_SHUTDOWN,
                json!({
                    "token_contract": token_contract.clone(),
                    "deal_handle": deal_handle.clone(),
                    "role": "buyer",
                    "action": "streamStop",
                    "state": "no_deal",
                    "terminal": false
                }),
            )
            .await?;
        }
    }
    let outcome = match shutdown_report {
        BuyerShutdownReport::SubscriptionPreserved => "subscription_preserved",
        BuyerShutdownReport::Settlement { outcome, .. } => outcome,
        BuyerShutdownReport::NoDeal => "no_deal",
    };
    emit_shared_buyer_event(
        &events,
        "exiting",
        machine::OP_BUYER_SHUTDOWN,
        json!({
            "token_contract": token_contract,
            "deal_handle": deal_handle,
            "outcome": outcome,
            "exit_code": 0
        }),
    )
    .await?;
    Ok(())
}

async fn run_buyer_inner(
    args: BuyerArgs,
    machine_events: &mut Option<machine::BuyerEventWriter>,
    machine_context: &mut BuyerMachineErrorContext,
    runtime: BuyerCommandRuntime,
) -> Result<()> {
    let BuyerCommandRuntime {
        backend,
        shellnet_preflight,
        shutdown,
    } = runtime;
    // this CLI path submits flags=0(limit BUY), so its max price must be a positive
    // whole multiple of PRICE_STEP(1 SHELL), rejected before any submit/escrow. The contract's
    // separate FLAG_MARKET path is the sole price-less exception; this command does not claim it.
    super::support::validate_price_step(args.max_price_per_tick)?;
    preflight_buyer_pool_for_money_move(&args)?;
    // Issue: token_contract + frame_model come from `--market`(a provision manifest) or the flags.
    // The buyer ignores the deal nonce: it places a buy, it does not post the offer.
    // Model-only buy: with neither
    // `--token-contract` nor `--market`, the buyer derives the per-model book from `--frame-model`, shows the
    // resting asks, places a model-wide buy, and learns the matched deal `TokenContract` from ITS OWN note's
    // `InferenceFilledConfirmed` event -- no seller hand-off. With `--token-contract`/`--market` the explicit
    // deal address is used as before(back-compat).
    let model_only = args.market.is_none() && args.token_contract.is_none();
    let (explicit_tc, requested_frame_model) = if model_only {
        let fm = args.frame_model.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "provide --frame-model (model-only buy: the orderbook is derived from the model name), \
                 or --token-contract / --market for an explicit deal"
            )
        })?;
        (None, fm)
    } else {
        let (tc, fm, _nonce) = resolve_market_fields(
            args.market.as_deref(),
            args.token_contract.as_deref(),
            args.frame_model.as_deref(),
        )?;
        let fm =
            fm.ok_or_else(|| anyhow::anyhow!("provide --frame-model or --market <manifest>"))?;
        (Some(tc), fm)
    };
    let registry_policy = if !args.mock.mock_chain && shellnet_preflight.should_run() {
        load_enabled_model_registry_policy(RegistryRole::Buyer, &args.registry, &args.contracts)?
    } else {
        None
    };
    let frame_model = if let Some(policy) = registry_policy.as_ref() {
        shellnet_doctor_preflight(&args.contracts, args.market.as_deref()).await?;
        reject_buyer_raw_token_contract_without_registry_book_proof(
            args.market.as_deref(),
            args.token_contract.as_deref(),
            &requested_frame_model,
        )?;
        let selected_market = match args.market.as_deref() {
            Some(market) => Some(load_market(market)?),
            None => None,
        };
        let target = resolve_model_registry_target(
            RegistryRole::Buyer,
            Some(policy),
            &args.contracts,
            &requested_frame_model,
            BookTarget {
                frame_model: selected_market
                    .as_ref()
                    .map(|market| market.frame_model.clone())
                    .unwrap_or_else(|| requested_frame_model.clone()),
                model_hash: selected_market
                    .as_ref()
                    .map(|market| market.model_hash.clone())
                    .unwrap_or_else(|| model_hash_for(&requested_frame_model)),
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
        let expected_order_book = if let Some(order_book) = target.order_book {
            order_book
        } else {
            let note_addr = args.identity.note_addr.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "real shellnet: --note-addr is required to derive the buyer order book"
                )
            })?;
            expected_order_book_for_note(&args.contracts, note_addr, &target.frame_model).await?
        };
        let order_book_active =
            order_book_active_from_contracts(&args.contracts, &expected_order_book).await?;
        enforce_model_registry_policy(
            RegistryRole::Buyer,
            policy,
            &args.contracts,
            &target.frame_model,
            &expected_order_book,
            order_book_active,
            BuyerMissingBookPolicy::Reject,
        )
        .await?;
        target.frame_model
    } else {
        requested_frame_model
    };
    // Model-only discovery derives the order-book address from `sha256(frame_model)`, so the id MUST be the
    // canonical `producer--model--version`(else it looks at the wrong book). Only enforce here: on the explicit
    // `--token-contract`/`--market` path the deal address is given directly (frame_model is only B2/B7 there,
    // where `family_of` matches by substring regardless of form), and the mock demo uses `dexdo-mock`.
    if model_only && !args.mock.mock_chain && registry_policy.is_none() {
        dexdo_core::validate_canonical_model_id(&frame_model).map_err(|e| anyhow::anyhow!(e))?;
    }
    machine_context.network = Some(
        if args.mock.mock_chain {
            "mock"
        } else {
            "shellnet"
        }
        .to_string(),
    );
    machine_context.frame_model = Some(frame_model.clone());
    if let Some(tc) = explicit_tc.as_deref() {
        machine_context.order_book = Some("explicit_token_contract".to_string());
        machine_context.set_token_contract(tc);
    } else if !args.resume {
        machine_context.order_book = Some("model_order_book".to_string());
    }
    // Model-only `--resume` is supported (directive: the buyer recovers its deal from ITS OWN note's fill
    // event, never a hand-pasted `--token-contract`): it re-scans `InferenceFilledConfirmed` on this note over
    // a lookback window and connects to the freshly matched deal without placing a new buy. Handled below.
    // fail closed BEFORE the on-chain buy if this is a one-shot real-upstream attempt(promptless) --
    // an actionable client-side error, not a deep gateway `InvalidArgument` after place_buy + handover.
    oneshot_real_upstream_guard(args.local_listen.is_some(), args.mock.mock_model)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if model_only && args.mock.mock_chain {
        bail!(
            "model-only buy (no --token-contract/--market) discovers the book on real shellnet; on --mock-chain \
             pass --token-contract 0:<deal> (the mock has no on-chain orderbook to discover)"
        );
    }
    if let Some(events) = machine_events.as_mut() {
        events.event(
            "starting",
            machine::OP_BUYER_START,
            json!({
                "network": if args.mock.mock_chain { "mock" } else { "shellnet" },
                "frame_model": frame_model.clone(),
                "mode": if args.resume { "resume" } else { "buy" },
                "requested_bind_addr": args.local_listen.map(|a| a.to_string()),
                "anthropic_compat": args.anthropic_compat,
                "continuity_mode": args.continuity_mode.as_str()
            }),
        )?;
    }
    #[cfg(debug_assertions)]
    if let Some(err) = buyer_machine_error_fixture_from_env() {
        return Err(err);
    }
    let buyer_content_policy = if args.local_listen.is_some() {
        match build_buyer_content_policy(&args, &frame_model).await {
            Ok(policy) => Some(policy),
            Err(err) => {
                machine_context.failure_class = Some("content_identity_preflight".to_string());
                machine_context.missing_or_unset =
                    Some("allow_unverified_model_or_models_data".to_string());
                return Err(err);
            }
        }
    } else {
        None
    };
    let buyer_policy = if !args.mock.mock_chain {
        Some(policy::load_buyer_runtime_policy(args.policy.as_deref())?)
    } else {
        None
    };
    let api_failure_policy = buyer_policy
        .as_ref()
        .map(policy::BuyerRuntimePolicy::as_api_failure_policy)
        .unwrap_or_default();
    if let Some(policy) = buyer_policy.as_ref() {
        tracing::debug!(
            policy_no_handover_after_match = policy.no_handover_after_match.as_str(),
            policy_malformed_handover = policy.malformed_handover.as_str(),
            policy_dead_gateway = policy.dead_gateway.as_str(),
            policy_empty_stream = policy.empty_stream.as_str(),
            policy_seller_stalls_mid_stream = policy.seller_stalls_mid_stream.as_str(),
            policy_bad_output_scam = policy.bad_output_scam.as_str(),
            policy_max_sellers_to_try = policy.max_sellers_to_try,
            policy_total_spend_cap_shells = policy.total_spend_cap_shells,
            "buyer policy loaded"
        );
        validate_buyer_runtime_surface_policy(policy, args.local_listen)?;
    }
    // The chain is selected by a flag: `--mock-chain` -> mock(as in D1, also requires `--mock-model`), otherwise
    // real shellnet(per-role buyer backend behind the `shellnet` feature; without the feature -> explicit failure).
    let (chain, note) = if let Some(backend) = backend {
        backend
    } else if args.mock.mock_chain {
        args.mock.require_mock_model()?;
        let endpoints_file = resolve_endpoints_file(args.endpoints_file.clone())?;
        mock_chain_and_note(endpoints_file, &args.identity)?
    } else {
        buyer_real_backend(&args, &frame_model)?
    };
    let buyer = dexdo::buyer::Buyer::from_note(note);
    #[cfg(feature = "shellnet")]
    let mut subscription_resume = BuyerSubscriptionResumeCandidate::None;
    #[cfg(not(feature = "shellnet"))]
    let subscription_resume = BuyerSubscriptionResumeCandidate::None;
    #[cfg(feature = "shellnet")]
    if args.resume && !args.mock.mock_chain {
        let note_addr = args.identity.note_addr.as_deref().ok_or_else(|| {
            anyhow::anyhow!("subscription resume requires --note-addr for durable ownership")
        })?;
        let mut money_lock = BuyerMoneyLock::open(note_addr)?;
        money_lock.try_acquire()?;
        let handle_note_addr = money_lock.note_addr.clone();
        let handle_deals_dir = args.deals_dir.clone();
        let handle_market = args.market.clone();
        let handle_contracts = args.contracts.clone();
        let persist_handle = move |record: &BuyerSubscriptionOrderRecord,
                                   matched: &BuyerJournalMatch| {
            persist_subscription_runtime_handle(
                record,
                matched,
                &handle_note_addr,
                handle_deals_dir.as_deref(),
                handle_market.as_deref(),
                &handle_contracts,
            )
        };
        if let Some(resumed) = resolve_buyer_subscription_resume(
            chain.as_ref(),
            note_addr,
            &frame_model,
            explicit_tc.as_deref(),
            &money_lock,
            std::time::Duration::from_secs(DEAL_WAIT_SECS),
            &persist_handle,
        )
        .await?
        {
            subscription_resume = BuyerSubscriptionResumeCandidate::Active(Box::new(resumed));
        }
    }
    let submit_intent = if args.continuity_mode == ContinuityModeArg::OnDemand {
        BuyerSubmitIntent::on_demand()
    } else {
        BuyerSubmitIntent::foreground()
    };
    let raised_money = if args.mock.mock_chain || subscription_resume.is_active() {
        None
    } else {
        let escrow = args
            .escrow
            .unwrap_or_else(|| required_escrow_for_buy(args.ticks, args.max_price_per_tick));
        raise_pending_buyer_money_before_fresh_reads(
            chain.as_ref(),
            &buyer,
            args.identity.note_addr.as_deref(),
            &submit_intent,
            explicit_tc.as_deref(),
            args.ticks,
            args.max_price_per_tick,
            escrow,
        )
        .await?
    };
    if args.local_listen.is_some()
        && args.continuity_mode == ContinuityModeArg::OnDemand
        && !subscription_resume.is_active()
    {
        let events = machine_events
            .take()
            .map(|writer| Arc::new(tokio::sync::Mutex::new(writer)));
        let (content_check, models_cfg) = buyer_content_policy
            .expect("local-listen buyer content policy is preflighted before on-demand");
        return run_buyer_on_demand_local_api(
            args,
            chain,
            buyer,
            explicit_tc,
            frame_model,
            content_check,
            models_cfg,
            buyer_policy,
            api_failure_policy,
            events,
            raised_money,
            shellnet_preflight,
            shutdown,
        )
        .await;
    }
    if !args.mock.mock_chain && registry_policy.is_none() && shellnet_preflight.should_run() {
        shellnet_doctor_preflight(&args.contracts, args.market.as_deref()).await?;
    }
    // Resolve the deal `TokenContract`: explicit(flag/manifest) or model-only (book -> choose -> buy -> fill
    // event). `buy_ticks` is the chosen volume(the consumer-API token budget tracks it).
    let adopted_submit_identity = raised_money
        .as_ref()
        .and_then(|outcome| outcome.submit_reconciliation.as_ref())
        .map(|reconciliation| reconciliation.submit_identity.clone());
    #[cfg(feature = "shellnet")]
    let resumed_from_ordinary_journal = args.resume && raised_money.is_some();
    let mut service_renewal: Option<(u128, u128, u128)> = None;
    let mut buyer_order_id = None;
    #[cfg(feature = "shellnet")]
    let mut subscription_route_budget = None;
    #[cfg(not(feature = "shellnet"))]
    let subscription_route_budget = Option::<SubscriptionRouteBudget>::default();
    #[cfg(feature = "shellnet")]
    let mut preserve_subscription = false;
    #[cfg(not(feature = "shellnet"))]
    let preserve_subscription = false;
    #[cfg(feature = "shellnet")]
    let mut historical_resume_fill = None;
    let (mut token_contract, buy_ticks) = if let Some(outcome) = raised_money {
        machine_context.set_token_contract(&outcome.token_contract);
        if let Some(events) = machine_events.as_mut() {
            if args.resume {
                events.event(
                    "resume_selected",
                    machine::OP_BUYER_START,
                    recovered_buyer_resume_selected_fields(&frame_model, &outcome)?,
                )?;
            } else {
                events.event(
                    "buy_submitted",
                    machine::OP_BUYER_START,
                    buyer_submit_event_fields(
                        &frame_model,
                        if explicit_tc.is_some() {
                            "explicit_token_contract"
                        } else {
                            "model_order_book"
                        },
                        outcome.ticks,
                        outcome.max_price_per_tick,
                        outcome.escrow,
                        BuyerSubmitProgress {
                            reconciled_ambiguous_submit: true,
                            submit_reconciliation: outcome.submit_reconciliation.clone(),
                        },
                    ),
                )?;
            }
        }
        (outcome.token_contract, outcome.ticks)
    } else if subscription_resume.is_active() {
        #[cfg(feature = "shellnet")]
        {
            let BuyerSubscriptionResumeCandidate::Active(resumed) = std::mem::replace(
                &mut subscription_resume,
                BuyerSubscriptionResumeCandidate::None,
            ) else {
                unreachable!("is_active checked above")
            };
            let matched = resumed
                .record
                .matched
                .as_ref()
                .expect("matched resume record");
            let tc = matched.token_contract.clone();
            buyer_order_id = Some(resumed.record.order_id);
            subscription_route_budget = Some(SubscriptionRouteBudget {
                remaining_current_week: u64::try_from(resumed.quota.remaining_current_week)
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "subscription remaining weekly quota {} exceeds u64",
                            resumed.quota.remaining_current_week
                        )
                    })?,
                state: resumed.facts.state,
                subscription: resumed.facts.subscription,
            });
            preserve_subscription = true;
            machine_context.order_book = Some(resumed.record.order_book.clone());
            machine_context.set_token_contract(&tc);
            if let Some(events) = machine_events.as_mut() {
                events.event(
                    "resume_selected",
                    machine::OP_BUYER_START,
                    json!({
                        "token_contract": tc.clone(),
                        "order_id": machine::amount(resumed.record.order_id),
                        "role": "buyer",
                        "source": "durable_subscription",
                        "deal_handle": matched.deal_handle.clone(),
                        "frame_model": frame_model.clone(),
                        "week_index": resumed.facts.subscription.week_index,
                        "week_base_tokens": machine::amount(
                            resumed.facts.subscription.week_base_tokens
                        ),
                        "remaining_current_week": machine::amount(
                            resumed.quota.remaining_current_week
                        ),
                        "buyer_bond_held": machine::amount(
                            resumed.facts.buyer_bond.bond_held
                        ),
                        "buyer_bond_required": machine::amount(
                            resumed.facts.buyer_bond.bond_required
                        ),
                        "buyer_locked_total": machine::amount(
                            resumed.quota.buyer_locked_total
                        )
                    }),
                )?;
            } else {
                println!(
                    "resuming durable subscription {} without a new BUY/payment",
                    matched.deal_handle
                );
            }
            (tc, resumed.record.ticks)
        }
        #[cfg(not(feature = "shellnet"))]
        unreachable!("subscription resume is only built with shellnet")
    } else {
        match explicit_tc {
            Some(tc) => {
                if args.resume {
                    // Connect to an ALREADY-matched deal -- escrow is already committed; a fresh place_buy would
                    // double-pay. Skip straight to reading the on-chain handover + serving.
                    if let Some(events) = machine_events.as_mut() {
                        events.event(
                            "resume_selected",
                            machine::OP_BUYER_START,
                            json!({
                                "token_contract": tc.clone(),
                                "role": "buyer",
                                "source": "token_contract",
                                "deal_handle": deals::make_handle_id(&tc, deals::DealHandleRole::Buyer),
                                "frame_model": frame_model.clone()
                            }),
                        )?;
                    } else {
                        println!("resuming existing deal {tc} -- connecting without a new buy");
                    }
                } else {
                    require_stream_buy_ticks(args.ticks)?;
                    let selection = buyer_quote_selection_for_submit(
                        chain.as_ref(),
                        args.mock.mock_chain,
                        args.identity.note_addr.as_deref(),
                        &submit_intent,
                        Some(&tc),
                        args.ticks,
                        args.max_price_per_tick,
                        args.escrow,
                        machine_events
                            .is_none()
                            .then_some((&args, frame_model.as_str())),
                    )
                    .await?;
                    if let Some(events) = machine_events.as_mut() {
                        if fail_buyer_quote_selection(
                            events,
                            &frame_model,
                            &selection,
                            args.ticks,
                            args.max_price_per_tick,
                            machine_context.fields(),
                        )?
                        .is_some()
                        {
                            return Err(machine::printed_error());
                        }
                        events.event(
                            "quote_selected",
                            machine::OP_BUYER_START,
                            quote_selected_fields(
                                &frame_model,
                                &selection,
                                args.ticks,
                                args.max_price_per_tick,
                            ),
                        )?;
                    } else {
                        require_complete_buyer_quote(&selection)?;
                    }
                    require_stream_buy_ticks(args.ticks)?;
                    let submitted_escrow = selection.escrow;
                    let submit_frame_model = frame_model.clone();
                    let submit_ticks = args.ticks;
                    let submit_max_price = args.max_price_per_tick;
                    let outcome = execute_buyer_quote_submit(
                        chain.as_ref(),
                        &buyer,
                        args.mock.mock_chain,
                        args.identity.note_addr.as_deref(),
                        &submit_intent,
                        Some(&tc),
                        &selection,
                        args.ticks,
                        args.max_price_per_tick,
                        submitted_escrow,
                        machine_events.is_none().then_some(frame_model.as_str()),
                        |progress| {
                            let result = match machine_events.as_mut() {
                                Some(events) => events.event(
                                    "buy_submitted",
                                    machine::OP_BUYER_START,
                                    buyer_submit_event_fields(
                                        &submit_frame_model,
                                        "explicit_token_contract",
                                        submit_ticks,
                                        submit_max_price,
                                        submitted_escrow,
                                        progress,
                                    ),
                                ),
                                None => Ok(()),
                            };
                            std::future::ready(result)
                        },
                    )
                    .await?;
                    if let Some(events) = machine_events.as_mut() {
                        events.event(
                            "matched",
                            machine::OP_BUYER_START,
                            json!({
                                "frame_model": frame_model.clone(),
                                "order_book": "explicit_token_contract",
                                "token_contract": outcome.token_contract.clone()
                            }),
                        )?;
                    }
                    if !outcome.token_contract.eq_ignore_ascii_case(&tc) {
                        bail!(
                            "explicit buyer submit matched {}, expected {}; journal retained",
                            outcome.token_contract,
                            tc
                        );
                    }
                }
                (tc, args.ticks)
            }
            None if args.resume => {
                // Model-only RESUME: recover the already-matched deal from THIS note's own fill event -- no new buy
                // (escrow is already committed). The book is derived from `--frame-model`; we scan the note's
                // `InferenceFilledConfirmed` ext-out over a lookback window and take the most recent buy match.
                let since_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0)
                    - RESUME_LOOKBACK_SECS;
                if machine_events.is_none() {
                    println!(
                    "resume (model-only): scanning this note's own fill events (last {RESUME_LOOKBACK_SECS}s) \
                     for a matched deal on {frame_model} -- no new buy"
                );
                }
                let fill = chain
                    .wait_matched_token_contract(
                        since_unix,
                        std::time::Duration::from_secs(DEAL_WAIT_SECS),
                    )
                    .await?
                    .ok_or_else(|| {
                        ChainError::Chain("buyer fill event returned no match".to_string())
                    })?;
                let tc = fill.token_contract.clone();
                buyer_order_id = Some(fill.order_id);
                #[cfg(feature = "shellnet")]
                {
                    historical_resume_fill = Some(fill.clone());
                }
                machine_context.order_book = Some("model_order_book".to_string());
                machine_context.set_token_contract(&tc);
                if let Some(events) = machine_events.as_mut() {
                    events.event(
                        "resume_selected",
                        machine::OP_BUYER_START,
                        json!({
                            "token_contract": tc.clone(),
                            "order_id": machine::amount(fill.order_id),
                            "role": "buyer",
                            "source": "note_fill_event",
                            "deal_handle": deals::make_handle_id(&tc, deals::DealHandleRole::Buyer),
                            "frame_model": frame_model.clone()
                        }),
                    )?;
                } else {
                    println!("recovered matched deal TokenContract from note event: {tc}");
                }
                (tc, fill.ticks)
            }
            None => {
                // Show the book, THEN let the buyer choose how many ticks and the per-tick price ceiling
                // (the flags `--ticks`/`--max-price-per-tick` are the defaults / the non-interactive value).
                let (ticks, max_price) = if machine_events.is_none() {
                    render_inference_book(
                        chain.as_ref(),
                        &frame_model,
                        args.max_price_per_tick,
                        args.ticks,
                    )
                    .await?;
                    (
                        prompt_u128("How many ticks to buy", args.ticks),
                        prompt_u128(
                            "Maximum price per tick (raw ECC[2], 1000000000 = 1 SHELL)",
                            args.max_price_per_tick,
                        ),
                    )
                } else {
                    (args.ticks, args.max_price_per_tick)
                };
                super::support::validate_price_step(max_price)?;
                // Escrow: an explicit `--escrow` wins(checked == required downstream); otherwise the exact
                // required for the CHOSEN order.
                let escrow = args
                    .escrow
                    .unwrap_or_else(|| dexdo_core::required_escrow_for_buy(ticks, max_price));
                service_renewal = Some((ticks, max_price, escrow));
                require_stream_buy_ticks(ticks)?;
                if machine_events.is_none() {
                    println!("placing buy: {ticks} ticks at <= {max_price}/tick (escrow {escrow})");
                }
                let selection = buyer_quote_selection_for_submit(
                    chain.as_ref(),
                    args.mock.mock_chain,
                    args.identity.note_addr.as_deref(),
                    &submit_intent,
                    None,
                    ticks,
                    max_price,
                    Some(escrow),
                    machine_events
                        .is_none()
                        .then_some((&args, frame_model.as_str())),
                )
                .await?;
                if let Some(events) = machine_events.as_mut() {
                    if fail_buyer_quote_selection(
                        events,
                        &frame_model,
                        &selection,
                        ticks,
                        max_price,
                        machine_context.fields(),
                    )?
                    .is_some()
                    {
                        return Err(machine::printed_error());
                    }
                    events.event(
                        "quote_selected",
                        machine::OP_BUYER_START,
                        quote_selected_fields(&frame_model, &selection, ticks, max_price),
                    )?;
                } else {
                    require_complete_buyer_quote(&selection)?;
                }
                require_stream_buy_ticks(ticks)?;
                let submit_frame_model = frame_model.clone();
                let outcome = execute_buyer_quote_submit(
                    chain.as_ref(),
                    &buyer,
                    args.mock.mock_chain,
                    args.identity.note_addr.as_deref(),
                    &submit_intent,
                    None,
                    &selection,
                    ticks,
                    max_price,
                    escrow,
                    machine_events.is_none().then_some(frame_model.as_str()),
                    |progress| {
                        let result = match machine_events.as_mut() {
                            Some(events) => events.event(
                                "buy_submitted",
                                machine::OP_BUYER_START,
                                buyer_submit_event_fields(
                                    &submit_frame_model,
                                    "model_order_book",
                                    ticks,
                                    max_price,
                                    escrow,
                                    progress,
                                ),
                            ),
                            None => Ok(()),
                        };
                        std::future::ready(result)
                    },
                )
                .await?;
                tracing::info!("model-only buy placed and matched from the note's fill event");
                machine_context.set_token_contract(&outcome.token_contract);
                if let Some(events) = machine_events.as_mut() {
                    events.event(
                        "matched",
                        machine::OP_BUYER_START,
                        json!({
                            "frame_model": frame_model.clone(),
                            "order_book": "model_order_book",
                            "token_contract": outcome.token_contract.clone()
                        }),
                    )?;
                } else {
                    println!("matched deal TokenContract: {}", outcome.token_contract);
                }
                if machine_events.is_none() {
                    println!(
                        "{}",
                        matched_state_summary(&outcome.token_contract, &outcome.status)
                    );
                }
                (outcome.token_contract, outcome.ticks)
            }
        }
    };
    #[cfg(feature = "shellnet")]
    let mut buy_ticks = buy_ticks;
    #[cfg(feature = "shellnet")]
    if args.resume
        && !args.mock.mock_chain
        && !preserve_subscription
        && !resumed_from_ordinary_journal
    {
        let note_addr = args.identity.note_addr.as_deref().ok_or_else(|| {
            anyhow::anyhow!("subscription resume requires --note-addr for ownership validation")
        })?;
        if let Some(subscription) = classify_subscription_resume_target(
            chain.as_ref(),
            note_addr,
            &frame_model,
            &token_contract,
            historical_resume_fill.as_ref(),
        )
        .await?
        {
            buy_ticks = subscription.ticks;
            buyer_order_id = buyer_order_id.or(subscription.order_id);
            subscription_route_budget = Some(SubscriptionRouteBudget {
                remaining_current_week: u64::try_from(subscription.quota.remaining_current_week)
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "subscription remaining weekly quota {} exceeds u64",
                            subscription.quota.remaining_current_week
                        )
                    })?,
                state: subscription.facts.state,
                subscription: subscription.facts.subscription,
            });
            preserve_subscription = true;
            if let Some(events) = machine_events.as_mut() {
                events.event(
                    "subscription_resume_classified",
                    machine::OP_BUYER_START,
                    json!({
                        "token_contract": token_contract.clone(),
                        "source": if historical_resume_fill.is_some() {
                            "note_fill_event"
                        } else {
                            "explicit_token_contract"
                        },
                        "week_index": subscription.facts.subscription.week_index,
                        "week_base_tokens": machine::amount(
                            subscription.facts.subscription.week_base_tokens
                        ),
                        "remaining_current_week": machine::amount(
                            subscription.quota.remaining_current_week
                        ),
                        "buyer_locked_total": machine::amount(
                            subscription.quota.buyer_locked_total
                        )
                    }),
                )?;
            }
        } else if historical_resume_fill.is_some() {
            chain
                .assert_model_only_resume_target(&token_contract)
                .await?;
        }
    }
    record_buyer_token_contract_after_money_move(&args, &token_contract);
    tracing::info!("buy placed; awaiting handover");
    // Wait for the seller to open the stream and write the handover. Issue: fail-closed on the deadline instead of
    // waiting forever; do not swallow the `resolve_endpoint` error(diagnostics for the operator).
    let mut handover_attempt = 1u64;
    let handover = 'handover: loop {
        let hv_deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(DEAL_WAIT_SECS);
        let hv_deadline_unix = machine::now_unix()?.saturating_add(DEAL_WAIT_SECS);
        if let Some(events) = machine_events.as_mut() {
            events.event(
                "handover_waiting",
                machine::OP_BUYER_START,
                json!({
                    "token_contract": token_contract.clone(),
                    "deadline_unix": hv_deadline_unix,
                    "poll_interval_ms": BUYER_HANDOVER_POLL_INTERVAL.as_millis()
                }),
            )?;
        }
        loop {
            match buyer
                .resolve_endpoint(chain.as_ref(), &token_contract)
                .await
            {
                Ok(h) => break 'handover h,
                Err(e) => {
                    if is_malformed_handover_error(&e) {
                        if let Some(policy) = buyer_policy.as_ref() {
                            apply_malformed_handover_policy(
                                chain.as_ref(),
                                &buyer,
                                &token_contract,
                                policy,
                                preserve_subscription,
                                &e,
                            )
                            .await?;
                        }
                        return Err(
                            e.context(format!("buyer: malformed handover for {token_contract}"))
                        );
                    }
                    if std::time::Instant::now() >= hv_deadline {
                        let last_error = format!("{e:#}");
                        let diagnostic = handover_timeout_diagnostic(
                            chain.as_ref(),
                            &token_contract,
                            &last_error,
                        )
                        .await;
                        if let Some(policy) = buyer_policy.as_ref() {
                            let policy_outcome = apply_no_handover_after_match_policy(
                                chain.as_ref(),
                                &buyer,
                                &token_contract,
                                policy,
                                preserve_subscription,
                                service_renewal,
                                handover_attempt,
                                &diagnostic,
                                args.identity.note_addr.as_deref(),
                            )
                            .await;
                            match policy_outcome {
                                Err(policy_err) => {
                                    return Err(e.context(format!("{policy_err:#}")));
                                }
                                Ok(NoHandoverPolicyOutcome::RetryCurrent) => {
                                    continue 'handover;
                                }
                                Ok(NoHandoverPolicyOutcome::RetryNext(next)) => {
                                    token_contract = next;
                                    record_buyer_token_contract_after_money_move(
                                        &args,
                                        &token_contract,
                                    );
                                    handover_attempt = handover_attempt.saturating_add(1);
                                    continue 'handover;
                                }
                            }
                        }
                        return Err(e.context(diagnostic));
                    }
                    tracing::debug!(error = %e, "buyer: no handover yet -- waiting for the seller's open_stream");
                    tokio::time::sleep(BUYER_HANDOVER_POLL_INTERVAL).await;
                }
            }
        }
    };
    let mut deal_handle = deals::make_handle_id(&token_contract, deals::DealHandleRole::Buyer);
    if let Some(events) = machine_events.as_mut() {
        events.event(
            "handover_received",
            machine::OP_BUYER_START,
            json!({
                "token_contract": token_contract.clone(),
                "deal_handle": deal_handle.clone(),
                "handover_anchor": {"kind":"token_contract_state","value":"handover_present"}
            }),
        )?;
    }
    let should_save_handle = !args.mock.mock_chain || machine_events.is_some();
    if should_save_handle {
        let mock_note_addr;
        let note_addr = if args.mock.mock_chain {
            mock_note_addr = format!("mock:{}", note_pubkey_id(&buyer.note.pubkey()));
            mock_note_addr.as_str()
        } else {
            args.identity.note_addr.as_deref().ok_or_else(|| {
                anyhow::anyhow!("real shellnet: --note-addr is required to save the deal handle")
            })?
        };
        let endpoint = Some(deals::DealEndpointInfo {
            kind: if args.local_listen.is_some() {
                "local-listen".to_string()
            } else {
                "one-shot".to_string()
            },
            value: args
                .local_listen
                .map(|a| a.to_string())
                .unwrap_or_else(|| "promptless-mock-stream".to_string()),
        });
        let input = RuntimeDealHandleInput {
            role: deals::DealHandleRole::Buyer,
            deals_dir: args.deals_dir.as_deref(),
            token_contract: &token_contract,
            note_addr,
            frame_model: &frame_model,
            market: None,
            market_path: args.market.as_deref(),
            contracts: &args.contracts,
            endpoint,
            created_order_ids: buyer_order_id.into_iter().collect(),
        };
        let saved = if args.mock.mock_chain {
            save_mock_runtime_deal_handle(input)?
        } else {
            save_runtime_deal_handle(input, machine_events.is_none())?
        };
        deal_handle = saved.handle;
    }
    clear_adopted_buyer_money_journal(
        args.identity.note_addr.as_deref(),
        adopted_submit_identity.as_deref(),
        &token_contract,
    )?;
    // B19/B20: if `--local-listen` is set, bring up a local interface to
    // the consumer(OpenAI-compatible + optional Anthropic transcoding) and serve requests.
    if let Some(bind) = args.local_listen {
        use dexdo::buyer::api::{self, ApiState, Route};
        let continuity_mode = args.continuity_mode.as_planner_mode();
        tracing::info!(
            continuity_mode = args.continuity_mode.as_str(),
            "buyer continuity mode selected"
        );
        let buyer = Arc::new(buyer);
        // Ordinary deals retain their existing STOP-on-exit lifetime. A durable subscription is explicitly
        // preserved across Ctrl-C, SIGTERM and application restarts.
        let session = Arc::new(api::SessionSettle::new_with_failure_policy_and_lifetime(
            chain.clone(),
            token_contract.clone(),
            buyer.note.clone(),
            api_failure_policy,
            if preserve_subscription {
                api::SessionLifetimePolicy::Preserve
            } else {
                api::SessionLifetimePolicy::SettleOnExit
            },
        ));
        let (content_check, models_cfg) = buyer_content_policy
            .expect("local-listen buyer content policy is preflighted before buy");
        let renewal_content_check = content_check.clone();
        let weekly = subscription_weekly_budget(&chain, &token_contract, subscription_route_budget);
        let deal = dexdo::buyer::api::ApiDeal::new(
            Route {
                handover,
                token_contract: token_contract.clone(),
                max_tokens: subscription_route_budget
                    .map(|budget| budget.remaining_current_week)
                    .unwrap_or_else(|| consumer_api_token_budget(buy_ticks)),
            },
            session.clone(),
            std::sync::Arc::new(dexdo::buyer::api::ContentGate::new(
                content_check,
                models_cfg.clone(),
            )),
        );
        let state = ApiState::single_deal(
            buyer,
            frame_model.clone(),
            match weekly {
                Some(weekly) => deal.with_weekly_budget(weekly),
                None => deal,
            },
        );
        if let Some((ticks, max_price, escrow)) = service_renewal {
            spawn_buyer_service_renewal(
                chain.clone(),
                state.buyer.clone(),
                state.deals.clone(),
                if args.mock.mock_chain {
                    None
                } else {
                    args.identity.note_addr.clone()
                },
                ticks,
                max_price,
                escrow,
                continuity_mode,
                renewal_content_check,
                models_cfg.clone(),
                api_failure_policy,
            );
        }
        // SIGINT/SIGTERM drains in-flight responses and closes the listener. Ordinary deals retain the awaited
        // STOP; a durable subscription performs no chain write and remains resumable.
        if let Some(events) = machine_events.as_mut() {
            events.event(
                "endpoint_binding",
                machine::OP_BUYER_START,
                json!({
                    "token_contract": token_contract.clone(),
                    "deal_handle": deal_handle.clone(),
                    "requested_bind_addr": bind.to_string(),
                    "allow_port_zero": bind.port() == 0
                }),
            )?;
        }
        let (addr, task) = api::serve(bind, state, args.anthropic_compat, shutdown).await?;
        let base_url = format!("http://{addr}/v1");
        let models_url = format!("{base_url}/models");
        let models: serde_json::Value = reqwest::Client::builder()
            .timeout(BUYER_API_READINESS_TIMEOUT)
            .build()?
            .get(&models_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let ready = models["data"].as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| item["id"].as_str() == Some(frame_model.as_str()))
        });
        if !ready {
            anyhow::bail!("endpoint readiness /v1/models did not include the selected model");
        }
        if let Some(events) = machine_events.as_mut() {
            events.event(
                "endpoint_ready",
                machine::OP_BUYER_RUNTIME,
                json!({
                    "token_contract": token_contract.clone(),
                    "deal_handle": deal_handle.clone(),
                    "bind_addr": addr.to_string(),
                    "base_url": base_url,
                    "models_url": models_url,
                    "served_models": [frame_model.clone()],
                    "anthropic_compat": args.anthropic_compat
                }),
            )?;
        } else if let Some(handoff) =
            render_local_openai_handoff(addr, &frame_model, args.continuity_mode)
        {
            println!("{handoff}");
        }
        tracing::info!(%addr, anthropic_compat = args.anthropic_compat, "consumer API listening (loopback)");
        task.await?;
        if let Some(events) = machine_events.as_mut() {
            let shutdown_report = buyer_shutdown_report(Some(session.as_ref()));
            events.event(
                "stopping",
                machine::OP_BUYER_SHUTDOWN,
                json!({
                    "token_contract": token_contract.clone(),
                    "deal_handle": deal_handle.clone(),
                    "reason": "signal"
                }),
            )?;
            match shutdown_report {
                BuyerShutdownReport::SubscriptionPreserved => {
                    events.event(
                        "subscription_preserved",
                        machine::OP_BUYER_SHUTDOWN,
                        json!({
                            "token_contract": token_contract.clone(),
                            "deal_handle": deal_handle.clone(),
                            "role": "buyer",
                            "chain_write_submitted": shutdown_report.chain_write_submitted(),
                            "terminal": false
                        }),
                    )?;
                }
                BuyerShutdownReport::Settlement {
                    action,
                    state,
                    submitted,
                    ..
                } => {
                    events.event(
                        "settlement_submitted",
                        machine::OP_BUYER_SHUTDOWN,
                        json!({
                            "token_contract": token_contract.clone(),
                            "deal_handle": deal_handle.clone(),
                            "role": "buyer",
                            "action": action,
                            "submitted": submitted
                        }),
                    )?;
                    events.event(
                        "settled",
                        machine::OP_BUYER_SHUTDOWN,
                        json!({
                            "token_contract": token_contract.clone(),
                            "deal_handle": deal_handle.clone(),
                            "role": "buyer",
                            "action": action,
                            "state": state,
                            "terminal": false
                        }),
                    )?;
                }
                BuyerShutdownReport::NoDeal => unreachable!("foreground buyer always has a deal"),
            }
            let outcome = match shutdown_report {
                BuyerShutdownReport::SubscriptionPreserved => "subscription_preserved",
                BuyerShutdownReport::Settlement { outcome, .. } => outcome,
                BuyerShutdownReport::NoDeal => unreachable!("foreground buyer always has a deal"),
            };
            events.event(
                "exiting",
                machine::OP_BUYER_SHUTDOWN,
                json!({
                    "token_contract": token_contract.clone(),
                    "deal_handle": deal_handle.clone(),
                    "outcome": outcome,
                    "exit_code": 0
                }),
            )?;
        }
        return Ok(());
    }

    let oneshot_session = dexdo::buyer::api::SessionSettle::new_with_failure_policy_and_lifetime(
        chain.clone(),
        token_contract.clone(),
        buyer.note.clone(),
        api_failure_policy,
        if preserve_subscription {
            dexdo::buyer::api::SessionLifetimePolicy::Preserve
        } else {
            dexdo::buyer::api::SessionLifetimePolicy::SettleOnExit
        },
    );
    // the figure this refuses on is recomputed from the fresh resume snapshot against the clock,
    // never a cached scalar -- a stored `weekBaseTokens` that no boundary has booked yet cannot turn a
    // live subscription into a permanent one-shot refusal.
    let stream_max_tokens = subscription_oneshot_budget(
        args.max_tokens,
        subscription_route_budget.map(|budget| budget.remaining_current_week),
    )?;
    let mut stream_attempt = 1u64;
    let out = loop {
        match buyer
            .connect_and_stream(&handover, &token_contract, stream_max_tokens)
            .await
        {
            Ok(out) => break out,
            Err(e) => match apply_oneshot_dead_gateway_policy(
                &oneshot_session,
                &token_contract,
                buyer_policy.as_ref(),
                stream_attempt,
            )
            .await
            {
                OneShotStreamPolicyOutcome::RetryCurrent => {
                    stream_attempt = stream_attempt.saturating_add(1);
                    continue;
                }
                OneShotStreamPolicyOutcome::TerminalReport(report) => {
                    return Err(e.context(report));
                }
            },
        }
    };
    if out.received == 0 {
        let report = apply_oneshot_empty_stream_policy(
            &oneshot_session,
            &token_contract,
            buyer_policy.as_ref(),
        )
        .await;
        bail!("{report}");
    }
    if preserve_subscription {
        tracing::info!(
            received = out.received,
            "received fake tokens; preserving durable subscription"
        );
    } else {
        tracing::info!(received = out.received, "received fake tokens; STOP");
        settle_completed_oneshot(&oneshot_session).await?;
    }
    Ok(())
}

async fn settle_completed_oneshot(session: &dexdo::buyer::api::SessionSettle) -> Result<()> {
    session
        .settle("one-shot-complete")
        .await
        .map_err(anyhow::Error::new)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "shellnet")]
    use crate::cli::args::{NoteDeployArgs, RecoveryIdentityArgs};

    #[cfg(feature = "shellnet")]
    fn ordinary_gateway_snapshot(
        ticks: u64,
    ) -> (dexdo_core::DealChainState, dexdo_core::DealSubscription) {
        let funded_tokens = u128::from(ticks) * dexdo_core::TICK_SIZE;
        (
            dexdo_core::DealChainState {
                funded: true,
                opened: true,
                probe_accepted: false,
                disputed: false,
                deposit: 1,
                finalized_owed: 0,
                tokens_final: 0,
                tokens_superseded: 0,
                tokens_pending: 0,
                probe_tick: 1,
                funded_time: Some(1),
                probe_time: 1,
                prev_claim_time: 0,
                last_claim_time: 1,
                dispute_time: 0,
            },
            dexdo_core::DealSubscription {
                deal_flags: 0,
                sub_weeks: 0,
                week_index: 0,
                tokens_per_week: funded_tokens,
                funded_tokens,
                tokens_paid: 0,
                period_start: 0,
                week_base_tokens: 0,
            },
        )
    }

    #[tokio::test]
    async fn direct_chain_read_timeout_returns_terminal_retryable_error() {
        let started = std::time::Instant::now();
        let err = super::direct_chain_read_with_timeout(1, async {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .expect_err("slow read must fail at the bounded timeout")
        .to_string();

        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "timeout should be terminal within the configured bound"
        );
        assert!(err.contains("chain read timed out after 1s"), "{err}");
        assert!(err.contains("retry"), "{err}");
        assert!(err.contains("dexdo market-data"), "{err}");
    }

    #[test]
    fn local_openai_handoff_uses_actual_loopback_port_and_literal_fake_key() {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind a dynamic loopback port");
        let addr = listener.local_addr().expect("read bound loopback address");
        assert_ne!(addr.port(), 0);
        for (mode, continuity) in [
            (
                super::ContinuityModeArg::Proactive,
                "proactive: may keep a warm deal and spend while idle",
            ),
            (
                super::ContinuityModeArg::OnDemand,
                "on-demand: does not spend while idle, but the first request after idle waits for purchase/handover",
            ),
        ] {
            let output = super::render_local_openai_handoff(addr, "qwen--qwen3--32b", mode)
                .expect("loopback handoff");
            assert_eq!(
                output,
                format!(
                    "OPENAI_BASE_URL=http://{addr}/v1\nOPENAI_MODEL=qwen--qwen3--32b\n\
                     OPENAI_API_KEY=dexdo-local\nCONTINUITY_MODE={continuity}"
                )
            );
            for secret in ["sk-live-provider-secret", "owner_secret_key_hex"] {
                assert!(!output.contains(secret), "{output}");
            }
        }
        assert!(
            super::render_local_openai_handoff(
                "192.0.2.1:8080".parse().unwrap(),
                "qwen--qwen3--32b",
                super::ContinuityModeArg::Proactive,
            )
            .is_none(),
            "the local placeholder block must not invent an external endpoint"
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn transient_read_retries_with_backoff_not_hard_fail() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let attempts = Arc::new(AtomicUsize::new(0));
        let started = std::time::Instant::now();
        let value = super::retry_executable_read("test executable read", {
            let attempts = attempts.clone();
            move || {
                let attempts = attempts.clone();
                async move {
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        Err(anyhow::anyhow!("request timed out"))
                    } else {
                        Ok("ok")
                    }
                }
            }
        })
        .await
        .expect("transient failure must retry successfully");

        assert_eq!(value, "ok");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert!(started.elapsed() >= super::EXECUTABLE_READ_BACKOFF[0]);
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn seller_open_probe_close_hint_names_current_accept_and_stop_methods() {
        let target = super::DealTarget {
            handle: None,
            token_contract: "0:tc".to_string(),
            role: Some(crate::cli::deals::DealHandleRole::Seller),
            note_addr: Some("0:seller".to_string()),
            market: None,
        };
        let summary = crate::cli::deals::DealStateSummary {
            kind: crate::cli::deals::DealStateKind::Probe,
            funded: true,
            opened: true,
            disputed: false,
            probe_accepted: false,
            deposit: 0,
            probe_tick: 0,
            buyer_bond: 0,
            buyer_bond_required: 0,
            finalized_owed: 0,
            tokens_final: 0,
            tokens_superseded: 0,
            tokens_pending: 0,
            funded_time: Some(1),
            probe_time: 1,
            prev_claim_time: 1,
            last_claim_time: 1,
            dispute_time: 0,
        };

        let hint = super::close_hint(&target, &summary);

        assert!(
            hint.contains("next=seller_wait_delivery_then_accept_probe"),
            "{hint}"
        );
        assert!(hint.contains("first delivered canonical tick"), "{hint}");
        assert!(hint.contains("after PROBE_WINDOW"), "{hint}");
        assert!(hint.contains("TokenContract.acceptProbe()"), "{hint}");
        assert!(hint.contains("TokenContract.sellerStop()"), "{hint}");
        assert!(!hint.contains("advance"), "{hint}");
        assert!(!hint.contains("wait_for_buyer_stop"), "{hint}");
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn seller_streaming_close_hint_names_current_claim_and_settlement_methods() {
        let target = super::DealTarget {
            handle: None,
            token_contract: "0:tc".to_string(),
            role: Some(crate::cli::deals::DealHandleRole::Seller),
            note_addr: Some("0:seller".to_string()),
            market: None,
        };
        let summary = crate::cli::deals::DealStateSummary {
            kind: crate::cli::deals::DealStateKind::Streaming,
            funded: true,
            opened: true,
            disputed: false,
            probe_accepted: true,
            deposit: 0,
            probe_tick: 0,
            buyer_bond: 0,
            buyer_bond_required: 0,
            finalized_owed: 0,
            tokens_final: dexdo_core::TICK_SIZE,
            tokens_superseded: dexdo_core::TICK_SIZE,
            tokens_pending: dexdo_core::TICK_SIZE,
            funded_time: Some(1),
            probe_time: 1,
            prev_claim_time: 1,
            last_claim_time: 1,
            dispute_time: 0,
        };

        let hint = super::close_hint(&target, &summary);

        assert!(
            hint.contains("next=seller_claim_finalize_or_settle_week_or_seller_stop"),
            "{hint}"
        );
        for method in [
            "TokenContract.claimTokens(cumulativeTokens)",
            "TokenContract.finalize()",
            "TokenContract.settleWeek()",
            "TokenContract.sellerStop()",
        ] {
            assert!(hint.contains(method), "missing {method}: {hint}");
        }
        assert!(!hint.contains("advance"), "{hint}");
    }

    #[test]
    fn buyer_renewal_threshold_uses_env_override() {
        let old = std::env::var("DEXDO_BUYER_RENEWAL_THRESHOLD_TOKENS").ok();
        std::env::set_var("DEXDO_BUYER_RENEWAL_THRESHOLD_TOKENS", "999999");
        assert_eq!(super::buyer_renewal_threshold_tokens(), 999_999);
        match old {
            Some(v) => std::env::set_var("DEXDO_BUYER_RENEWAL_THRESHOLD_TOKENS", v),
            None => std::env::remove_var("DEXDO_BUYER_RENEWAL_THRESHOLD_TOKENS"),
        }
    }

    #[derive(Clone, Copy)]
    enum QuotePreflightFailure {
        Transport,
        Contract,
    }

    #[derive(Default)]
    struct QuotePreflightChain {
        offers: Vec<dexdo_core::OfferListing>,
        discover_calls: std::sync::atomic::AtomicUsize,
        model_preflight_error: Option<String>,
        model_preflight_failure: Option<QuotePreflightFailure>,
        model_preflight_calls: std::sync::atomic::AtomicUsize,
        model_preflight_transport_failures: std::sync::atomic::AtomicUsize,
        model_submit_safe_order: Option<dexdo_core::OrderBookOrder>,
        model_pre_submit_order: Option<dexdo_core::OrderBookOrder>,
        model_before_post_calls: std::sync::atomic::AtomicUsize,
        model_money_submit_calls: std::sync::atomic::AtomicUsize,
        model_presubmit_preflight_calls: std::sync::atomic::AtomicUsize,
        model_submit_calls: std::sync::atomic::AtomicUsize,
        explicit_preflight_error: Option<String>,
        explicit_money_submit_calls: std::sync::atomic::AtomicUsize,
        explicit_submit_safe_order: Option<dexdo_core::OrderBookOrder>,
        sell_offer_terms: Option<(u64, u64)>,
        sell_offer_terms_calls: std::sync::atomic::AtomicUsize,
        submit_safe_single_ask_quote: bool,
        note_shell_balance: Option<u128>,
    }

    impl QuotePreflightChain {
        fn consume_transport_failure(counter: &std::sync::atomic::AtomicUsize) -> bool {
            counter
                .fetch_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |remaining| remaining.checked_sub(1),
                )
                .is_ok()
        }

        fn offer(
            token_contract: &str,
            price_per_tick: u64,
            max_ticks: u64,
        ) -> dexdo_core::OfferListing {
            dexdo_core::OfferListing {
                seller_id: "seller".to_string(),
                token_contract: token_contract.to_string(),
                price_per_tick,
                max_ticks,
            }
        }

        fn order(
            order_id: u128,
            token_contract: &str,
            price_per_tick: u128,
            ticks: u128,
        ) -> dexdo_core::OrderBookOrder {
            dexdo_core::OrderBookOrder {
                order_id,
                owner_note: "seller".to_string(),
                token_contract: Some(token_contract.to_string()),
                is_buy: false,
                price_per_tick,
                ticks,
                escrow: 0,
                deadline: 0,
                flags: 0,
                timestamp: 0,
            }
        }
    }

    #[async_trait::async_trait]
    impl dexdo_core::ChainBackend for QuotePreflightChain {
        async fn claim_tokens(
            &self,
            _: &dexdo_core::TokenContract,
            _: &dyn dexdo_core::Note,
            _: u128,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!()
        }

        async fn discover_offers(
            &self,
        ) -> Result<Vec<dexdo_core::OfferListing>, dexdo_core::ChainError> {
            self.discover_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.offers.clone())
        }

        async fn post_offer(
            &self,
            _offer: dexdo_core::SellOffer,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!("not needed by quote preflight tests")
        }

        async fn sell_offer_terms(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<(u64, u64)>, dexdo_core::ChainError> {
            self.sell_offer_terms_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.sell_offer_terms)
        }

        async fn assert_model_buy_matches_executable_quote(
            &self,
            _ticks: u128,
            _max_price_per_tick: u128,
        ) -> Result<(), dexdo_core::ChainError> {
            self.model_preflight_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if Self::consume_transport_failure(&self.model_preflight_transport_failures) {
                return Err(dexdo_core::ChainError::Transport(
                    "injected model preflight transport failure".to_string(),
                ));
            }
            match self.model_preflight_failure {
                Some(QuotePreflightFailure::Transport) => {
                    return Err(dexdo_core::ChainError::Transport(
                        "quote preflight rpc transport cause".to_string(),
                    ));
                }
                Some(QuotePreflightFailure::Contract) => {
                    return Err(dexdo_core::ChainError::Contract(
                        "quote preflight contract revert cause".to_string(),
                    ));
                }
                None => {}
            }
            match &self.model_preflight_error {
                Some(err) => Err(dexdo_core::ChainError::Chain(err.clone())),
                None => Ok(()),
            }
        }

        async fn submit_safe_model_buy_quote_order(
            &self,
            ticks: u128,
            max_price_per_tick: u128,
        ) -> Result<Option<dexdo_core::OrderBookOrder>, dexdo_core::ChainError> {
            self.assert_model_buy_matches_executable_quote(ticks, max_price_per_tick)
                .await?;
            Ok(self.model_submit_safe_order.clone())
        }

        fn model_buy_order_book_identity(&self) -> Option<String> {
            Some(format!("0:{}", "2".repeat(64)))
        }

        async fn place_buy_by_model_with_submit_identity(
            &self,
            _note: &dyn dexdo_core::Note,
            quoted_order: Option<&dexdo_core::OrderBookOrder>,
            _ticks: u128,
            _max_price_per_tick: u128,
            _escrow: u128,
            cursor: &mut dexdo_core::MatchWatchCursor,
            before_post: &mut (dyn FnMut(
                String,
                dexdo_core::MatchWatchCursor,
                u128,
            ) -> Result<(), dexdo_core::ChainError>
                      + Send),
        ) -> Result<(), dexdo_core::ChainError> {
            let selected = self.model_pre_submit_order.as_ref().ok_or_else(|| {
                dexdo_core::ChainError::Chain(
                    "buyer model-only preflight failed: no_executable_ask: rendered ask disappeared; no escrow was sent"
                        .to_string(),
                )
            })?;
            dexdo_core::chain::ensure_pre_submit_quote_unchanged(quoted_order, selected)?;
            *cursor = dexdo_core::MatchWatchCursor::new(67);
            self.model_before_post_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            before_post(
                format!("boc-sha256:{}", "a".repeat(64)),
                cursor.clone(),
                self.note_shell_balance.unwrap_or(u128::MAX),
            )?;
            self.model_money_submit_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn assert_explicit_buy_matches_executable_quote(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _ticks: u128,
            _max_price_per_tick: u128,
        ) -> Result<(), dexdo_core::ChainError> {
            match &self.explicit_preflight_error {
                Some(err) => Err(dexdo_core::ChainError::Chain(err.clone())),
                None => Ok(()),
            }
        }

        async fn submit_safe_explicit_buy_quote_order(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _ticks: u128,
            _max_price_per_tick: u128,
        ) -> Result<Option<dexdo_core::OrderBookOrder>, dexdo_core::ChainError> {
            Ok(self.explicit_submit_safe_order.clone())
        }

        fn requires_submit_safe_single_ask_quote(&self) -> bool {
            self.submit_safe_single_ask_quote
        }

        async fn place_buy(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            self.explicit_money_submit_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn place_buy_by_model(
            &self,
            _note: &dyn dexdo_core::Note,
            _ticks: u128,
            _max_price_per_tick: u128,
            _escrow: u128,
            _flags: u8,
            _deadline: u64,
        ) -> Result<(), dexdo_core::ChainError> {
            self.model_presubmit_preflight_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.model_submit_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn read_match(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Result<dexdo_core::Match, dexdo_core::ChainError> {
            unimplemented!("not needed by quote preflight tests")
        }

        async fn open_stream(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _enc_endpoint: Vec<u8>,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!("not needed by quote preflight tests")
        }

        async fn read_handover(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<Vec<u8>>, dexdo_core::ChainError> {
            unimplemented!("not needed by quote preflight tests")
        }

        async fn stop(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _note: &dyn dexdo_core::Note,
        ) -> Result<dexdo_core::Settlement, dexdo_core::ChainError> {
            unimplemented!("not needed by quote preflight tests")
        }

        async fn snapshot(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Option<dexdo_core::StreamSnapshot> {
            None
        }
    }

    /// the production real-shellnet seam returns one complete matcher row. Selection must retain
    /// every field and must not reconstruct the durable identity through lossy offer discovery.
    #[tokio::test]
    async fn buyer_model_quote_preserves_full_submit_safe_order_without_offer_round_trip() {
        use std::sync::atomic::Ordering;

        let mut real_order =
            QuotePreflightChain::order(154, &format!("0:{}", "3".repeat(64)), 1_000_000, 4);
        real_order.owner_note = format!("0:{}", "4".repeat(64));
        real_order.escrow = 9_999;
        real_order.deadline = 1_234_567;
        real_order.flags = 7;
        real_order.timestamp = 1_234_000;
        let chain = QuotePreflightChain {
            offers: vec![QuotePreflightChain::offer(
                real_order.token_contract.as_deref().unwrap(),
                real_order.price_per_tick as u64,
                real_order.ticks as u64,
            )],
            model_submit_safe_order: Some(real_order.clone()),
            submit_safe_single_ask_quote: true,
            ..Default::default()
        };

        let selection = super::buyer_quote_selection(&chain, None, 2, 1_000_000, None)
            .await
            .expect("canonical real order remains executable");

        assert_eq!(selection.quoted_order.as_ref(), Some(&real_order));
        assert_eq!(selection.quote.fills.len(), 1);
        assert_eq!(selection.quote.fills[0].order_id, real_order.order_id);
        assert_eq!(
            selection.quote.fills[0].token_contract,
            real_order.token_contract.clone().unwrap()
        );
        assert_eq!(
            chain.discover_calls.load(Ordering::SeqCst),
            0,
            "real-shellnet model selection must never call mock_orders_from_offers"
        );
        assert_eq!(
            chain.model_preflight_calls.load(Ordering::SeqCst),
            1,
            "the canonical assertion must perform exactly one row-returning real-shellnet quote read"
        );
    }

    #[test]
    fn buyer_preflight_rejects_below_canonical_tick_minimum_before_chain_work() {
        let minimum_ticks = dexdo_core::params::MIN_STREAM_BUY_TICKS;
        let error = super::require_stream_buy_ticks(minimum_ticks - 1)
            .expect_err("one tick must fail before buyer chain work");
        assert!(
            error
                .to_string()
                .contains(&format!("below the {minimum_ticks}-tick stream minimum")),
            "{error:#}"
        );
        super::require_stream_buy_ticks(minimum_ticks).expect("the canonical minimum is accepted");
    }

    #[tokio::test]
    async fn buyer_quote_failures_show_safe_exact_command_and_zero_money_posts() {
        use clap::Parser;
        use std::sync::atomic::Ordering;

        let note_addr = format!("0:{}", "1".repeat(64));
        let secret_key_path = "/tmp/owner-secret-do-not-print.key";
        let provider_secret_path = "/tmp/provider-secret-do-not-print.json";
        let argv = format!(
            "dexdo buyer --note-key {secret_key_path} --note-addr {note_addr} \
             --endpoints-file {provider_secret_path} --models /tmp/models.json \
             --contracts /tmp/contracts.json"
        );
        let cli = crate::Cli::try_parse_from(argv.split_whitespace()).expect("parse buyer fixture");
        let crate::Command::Buyer(args) = cli.command else {
            panic!("buyer command");
        };
        let command = super::buyer_read_only_quote_command(&args, "qwen--qwen3--32b", 2, 10);

        assert_eq!(
            command,
            format!(
                "dexdo executable-book 'qwen--qwen3--32b' --ticks 2 \
                 --max-price-per-tick 10 --note-addr '{note_addr}' \
                 --models '/tmp/models.json' --contracts '/tmp/contracts.json'"
            )
        );
        for secret in [secret_key_path, provider_secret_path] {
            assert!(!command.contains(secret), "{command}");
        }

        for (detail, reason) in [
            (
                "best ask price 11 is above buyer max_price_per_tick 10",
                "ceiling_below_best_ask",
            ),
            (
                "no_executable_ask: no executable matching ask for InferenceOrderBook 0:book",
                "no_executable_ask",
            ),
        ] {
            let chain = QuotePreflightChain {
                model_preflight_error: Some(detail.to_string()),
                ..Default::default()
            };
            let error = super::buyer_quote_selection_for_submit(
                &chain,
                true,
                None,
                &super::BuyerSubmitIntent::foreground(),
                None,
                2,
                10,
                None,
                Some((&args, "qwen--qwen3--32b")),
            )
            .await
            .expect_err("non-matchable quote must fail before submit");
            let rendered = format!("{error:#}");
            let state = format!("BUYER_PREFLIGHT matchable=false reason={reason}");
            assert!(
                rendered.contains(&state)
                    && rendered.contains(detail)
                    && rendered.contains(&format!("next_command={command}"))
                    && !rendered.contains("handover_timeout")
                    && !rendered.contains("owner-secret"),
                "{rendered}"
            );
            assert_eq!(chain.model_before_post_calls.load(Ordering::SeqCst), 0);
            assert_eq!(chain.model_money_submit_calls.load(Ordering::SeqCst), 0);
        }

        for (detail, reason) in [
            (
                "the expected ask exists but is not matchable by this buy: tokenContract \
                 0:expected, price 11, ticks 2, buyer max_price_per_tick 10, requested ticks 2",
                "ceiling_below_best_ask",
            ),
            (
                "no resting ask for expected tokenContract 0:expected; the shared model book would \
                 match order  tokenContract 0:other (price 9, ticks 2) instead. Refusing to send \
                 escrow into the wrong deal",
                "wrong_target",
            ),
        ] {
            let chain = QuotePreflightChain {
                explicit_preflight_error: Some(detail.to_string()),
                ..Default::default()
            };
            let error = super::buyer_quote_selection_for_submit(
                &chain,
                true,
                None,
                &super::BuyerSubmitIntent::foreground(),
                Some("0:expected"),
                2,
                10,
                None,
                Some((&args, "qwen--qwen3--32b")),
            )
            .await
            .expect_err("explicit non-matchable quote must fail before submit");
            assert_eq!(
                format!("{error:#}"),
                format!(
                    "BUYER_PREFLIGHT matchable=false reason={reason} \
                     detail=buyer explicit-token quote preflight: shellnet: {detail}\n\
                     next_command={command}"
                )
            );
            assert_eq!(
                chain.explicit_money_submit_calls.load(Ordering::SeqCst),
                0
            );
            assert_eq!(chain.model_money_submit_calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn buyer_model_only_quote_selection_surfaces_price_ceiling_preflight() {
        let offers = vec![QuotePreflightChain::offer("0:best", 11, 1)];
        let quote = dexdo_core::executable_quote(
            &super::mock_orders_from_offers(offers.clone()),
            Some(1),
            None,
        )
        .expect("standalone quote accepts the book without the buyer ceiling");
        assert!(quote.complete);
        let chain = QuotePreflightChain {
            offers,
            model_preflight_error: Some(
                "best ask price 11 is above buyer max_price_per_tick 10; requested ticks 1"
                    .to_string(),
            ),
            ..Default::default()
        };

        let err = match super::buyer_quote_selection(&chain, None, 1, 10, None).await {
            Ok(_) => panic!("model-only preflight must reject the quote before quote_selected"),
            Err(err) => format!("{err:#}"),
        };

        assert!(err.contains("buyer model-only quote preflight"), "{err}");
        assert!(err.contains("best ask price 11"), "{err}");
        assert!(err.contains("above buyer max_price_per_tick 10"), "{err}");
    }

    #[tokio::test]
    async fn buyer_quote_preflight_preserves_typed_chain_errors_for_classification() {
        for (failure, expected_code, expected_cause) in [
            (
                QuotePreflightFailure::Transport,
                crate::cli::machine::ErrorCode::ChainTransport,
                "quote preflight rpc transport cause",
            ),
            (
                QuotePreflightFailure::Contract,
                crate::cli::machine::ErrorCode::ChainRevert,
                "quote preflight contract revert cause",
            ),
        ] {
            let chain = QuotePreflightChain {
                model_preflight_failure: Some(failure),
                ..Default::default()
            };
            let err = match super::buyer_quote_selection(&chain, None, 1, 10, None).await {
                Ok(_) => panic!("typed quote preflight failure must propagate"),
                Err(err) => err,
            };

            assert_eq!(
                crate::cli::machine::classify_error(crate::cli::machine::OP_BUYER_START, &err,),
                expected_code
            );
            assert!(
                err.chain().any(|cause| cause
                    .downcast_ref::<dexdo_core::ChainError>()
                    .is_some_and(|chain_error| chain_error.to_string().contains(expected_cause))),
                "typed preflight cause missing from anyhow chain: {err:#}"
            );
        }
    }

    #[tokio::test]
    async fn buyer_quote_to_submit_path_stops_after_exactly_three_transient_preflight_attempts() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let chain = QuotePreflightChain {
            model_preflight_transport_failures: AtomicUsize::new(super::TRANSIENT_QUOTE_ATTEMPTS),
            ..Default::default()
        };

        let note = dexdo_core::LocalNote::from_seed(&[7_u8; 32]);
        let result = async {
            let _selection = super::buyer_quote_selection(&chain, None, 2, 1000, None).await?;
            dexdo_core::ChainBackend::place_buy_by_model(&chain, &note, 2, 1000, 2050, 0, 9_999_999)
                .await
                .map_err(anyhow::Error::new)
        }
        .await;
        let error = match result {
            Ok(()) => panic!("three transient preflight failures must stop before submit"),
            Err(error) => error,
        };

        assert_eq!(
            chain.model_preflight_calls.load(Ordering::SeqCst),
            super::TRANSIENT_QUOTE_ATTEMPTS
        );
        assert_eq!(
            chain.model_presubmit_preflight_calls.load(Ordering::SeqCst),
            0,
            "the pre-submit selection must not run after quote retries are exhausted"
        );
        assert_eq!(
            chain.model_submit_calls.load(Ordering::SeqCst),
            0,
            "the money-moving submit must remain outside retries"
        );
        assert!(error.chain().any(|cause| matches!(
            cause.downcast_ref::<dexdo_core::ChainError>(),
            Some(dexdo_core::ChainError::Transport(message))
                if message.contains("injected model preflight transport failure")
        )));
    }

    #[tokio::test]
    async fn buyer_quote_to_submit_path_recovers_on_third_attempt_and_submits_exactly_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let chain = QuotePreflightChain {
            model_preflight_transport_failures: AtomicUsize::new(2),
            ..Default::default()
        };

        let note = dexdo_core::LocalNote::from_seed(&[7_u8; 32]);
        let _selection = super::buyer_quote_selection(&chain, None, 2, 1000, None)
            .await
            .expect("the third quote-boundary preflight attempt must succeed");
        dexdo_core::ChainBackend::place_buy_by_model(&chain, &note, 2, 1000, 2050, 0, 9_999_999)
            .await
            .expect("the single pre-submit preflight and money submit must succeed");

        assert_eq!(
            chain.model_preflight_calls.load(Ordering::SeqCst),
            super::TRANSIENT_QUOTE_ATTEMPTS,
            "the quote boundary must recover on its third and final attempt"
        );
        assert_eq!(
            chain.model_presubmit_preflight_calls.load(Ordering::SeqCst),
            1,
            "the production-mirroring pre-submit selection must run exactly once"
        );
        assert_eq!(
            chain.model_submit_calls.load(Ordering::SeqCst),
            1,
            "the money-moving submit must happen exactly once"
        );
    }

    #[tokio::test]
    async fn wrapped_model_preflight_chain_marker_classifies_as_no_liquidity() {
        let chain = QuotePreflightChain {
            model_preflight_error: Some(
                "no_executable_ask: no executable matching ask for InferenceOrderBook 0:book"
                    .to_string(),
            ),
            ..Default::default()
        };
        let err = match super::buyer_quote_selection(&chain, None, 1, 10, None).await {
            Ok(_) => panic!("model-only preflight marker must propagate"),
            Err(err) => err,
        };

        assert_eq!(
            crate::cli::machine::classify_error(crate::cli::machine::OP_BUYER_START, &err),
            crate::cli::machine::ErrorCode::NoLiquidity,
            "wrapped no_executable_ask marker was not classified from the full chain: {err:#}"
        );
        assert!(
            err.chain().any(|cause| cause
                .downcast_ref::<dexdo_core::ChainError>()
                .is_some_and(|chain_error| matches!(chain_error, dexdo_core::ChainError::Chain(message) if message.contains("no_executable_ask")))),
            "ChainError::Chain marker missing from production preflight chain: {err:#}"
        );
    }

    #[tokio::test]
    async fn wrapped_explicit_target_chain_marker_classifies_as_chain_revert() {
        let chain = QuotePreflightChain {
            explicit_preflight_error: Some(
                "buyer target preflight failed for InferenceOrderBook 0:book: no resting ask for expected tokenContract 0:dead"
                    .to_string(),
            ),
            ..Default::default()
        };
        let err = match super::buyer_quote_selection(&chain, Some("0:dead"), 1, 10, None).await {
            Ok(_) => panic!("explicit target preflight marker must propagate"),
            Err(err) => err,
        };

        assert_eq!(
            crate::cli::machine::classify_error(crate::cli::machine::OP_BUYER_START, &err),
            crate::cli::machine::ErrorCode::ChainRevert,
            "wrapped buyer target preflight marker was not classified from the full chain: {err:#}"
        );
        assert!(
            err.chain().any(|cause| cause
                .downcast_ref::<dexdo_core::ChainError>()
                .is_some_and(|chain_error| matches!(chain_error, dexdo_core::ChainError::Chain(message) if message.contains("buyer target preflight failed")))),
            "ChainError::Chain marker missing from production explicit preflight chain: {err:#}"
        );
    }

    #[test]
    fn model_only_no_liquidity_failure_class_is_no_executable_ask() {
        let selection = super::BuyerQuoteSelection {
            order_book: "model_order_book",
            escrow: 0,
            quote: dexdo_core::ExecutableQuote {
                filled_ticks: 0,
                total_with_fee: 0,
                complete: false,
                fills: Vec::new(),
            },
            quoted_order: None,
        };

        assert_eq!(
            super::buyer_quote_failure_class(&selection, super::machine::ErrorCode::NoLiquidity),
            "no_executable_ask"
        );
    }

    #[tokio::test]
    async fn buyer_explicit_quote_selection_runs_target_preflight_before_synthetic_terms() {
        let chain = QuotePreflightChain {
            explicit_preflight_error: Some(
                "buyer target preflight failed for InferenceOrderBook 0:book: no resting ask for expected tokenContract 0:dead"
                    .to_string(),
            ),
            sell_offer_terms: Some((11, 1)),
            ..Default::default()
        };

        let err = match super::buyer_quote_selection(&chain, Some("0:dead"), 1, 11, None).await {
            Ok(_) => panic!("explicit target preflight must reject before quote_selected"),
            Err(err) => format!("{err:#}"),
        };

        assert!(
            err.contains("buyer explicit-token quote preflight"),
            "{err}"
        );
        assert!(err.contains("buyer target preflight failed"), "{err}");
        assert_eq!(
            chain
                .sell_offer_terms_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "explicit target preflight must fail before synthetic sell_offer_terms can fabricate quote_selected"
        );
    }

    #[tokio::test]
    async fn buyer_model_only_quote_selection_accepts_partial_head_ask() {
        let chain = QuotePreflightChain {
            offers: vec![QuotePreflightChain::offer("0:big", 1000, 1024)],
            submit_safe_single_ask_quote: true,
            ..Default::default()
        };

        let selection = super::buyer_quote_selection(&chain, None, 1, 1000, None)
            .await
            .expect("selection returns an explicit no-liquidity quote");

        assert_eq!(selection.order_book, "model_order_book");
        assert!(selection.quote.complete);
        assert_eq!(selection.quote.filled_ticks, 1);
        assert_eq!(
            selection.quote.total_with_fee,
            dexdo_core::required_escrow_for_buy(1, 1000)
        );
        assert_eq!(selection.quote.fills.len(), 1);
        assert_eq!(selection.quote.fills[0].ticks, 1);
        assert_eq!(selection.quote.fills[0].token_contract, "0:big");
    }

    #[tokio::test]
    async fn buyer_model_only_quote_selection_preserves_authoritative_on_chain_row() {
        let mut authoritative = QuotePreflightChain::order(7, "0:best", 1000, 1);
        authoritative.timestamp = 1_783_535_201;
        let chain = QuotePreflightChain {
            offers: vec![QuotePreflightChain::offer("0:best", 1000, 1)],
            model_submit_safe_order: Some(authoritative.clone()),
            submit_safe_single_ask_quote: true,
            ..Default::default()
        };

        let selection = super::buyer_quote_selection(&chain, None, 1, 1000, None)
            .await
            .expect("model-only selection uses the authoritative submit-safe row");

        assert_eq!(selection.quoted_order, Some(authoritative));
        assert_eq!(selection.quote.fills[0].order_id, 7);
        assert_eq!(selection.quoted_order.unwrap().timestamp, 1_783_535_201);
    }

    #[tokio::test]
    async fn buyer_explicit_quote_selection_accepts_partial_synthetic_terms() {
        let chain = QuotePreflightChain {
            sell_offer_terms: Some((1000, 1024)),
            submit_safe_single_ask_quote: true,
            ..Default::default()
        };

        let selection = super::buyer_quote_selection(&chain, Some("0:big"), 1, 1000, None)
            .await
            .expect("selection returns an explicit no-liquidity quote");

        assert_eq!(selection.order_book, "explicit_token_contract");
        assert!(selection.quote.complete);
        assert_eq!(selection.quote.filled_ticks, 1);
        assert_eq!(
            selection.quote.total_with_fee,
            dexdo_core::required_escrow_for_buy(1, 1000)
        );
        assert_eq!(selection.quote.fills.len(), 1);
        assert_eq!(selection.quote.fills[0].ticks, 1);
        assert_eq!(selection.quote.fills[0].token_contract, "0:big");
    }

    #[tokio::test]
    async fn buyer_explicit_quote_selection_uses_submit_safe_row_before_synthetic_terms() {
        let chain = QuotePreflightChain {
            explicit_submit_safe_order: Some(QuotePreflightChain::order(7, "0:big", 1000, 1024)),
            submit_safe_single_ask_quote: true,
            ..Default::default()
        };

        let selection = super::buyer_quote_selection(&chain, Some("0:big"), 1, 1000, None)
            .await
            .expect("selection returns an explicit submit-safe quote");

        assert_eq!(selection.order_book, "explicit_token_contract");
        assert!(selection.quote.complete);
        assert_eq!(selection.quote.filled_ticks, 1);
        assert_eq!(selection.quote.fills.len(), 1);
        assert_eq!(selection.quote.fills[0].order_id, 7);
        assert_eq!(selection.quote.fills[0].token_contract, "0:big");
        assert_eq!(
            chain
                .sell_offer_terms_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "explicit submit-safe row should not be replaced by synthetic terms"
        );
    }

    /// Demo(run with `--nocapture`): render the model-only order book through the REAL `render_inference_book`
    /// against a `MockChainBackend` seeded with a few asks -- shows exactly what the buyer sees before choosing.
    #[tokio::test]
    async fn demo_render_inference_book() {
        use dexdo_core::{
            ChainBackend, DobParams, LocalNote, MockChainBackend, ProtocolConsts, SellOffer,
        };
        // this was a FIXED name under the shared temp directory, with no pid and no random
        // component, so two test processes on the same builder used and deleted the same file.
        let dir = tempfile::tempdir().expect("book demo temp dir");
        let path = dir.path().join("endpoints.json");
        let mock = MockChainBackend::new(path, ProtocolConsts::canonical(), DobParams::canonical());
        let note = LocalNote::generate();
        let asks = [
            (
                "0:7c58eff6aa11b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b",
                dexdo_core::PRICE_STEP as u64,
                512u64,
            ),
            (
                "0:18a758c0bb22c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c",
                2 * dexdo_core::PRICE_STEP as u64,
                1024,
            ),
            (
                "0:ab1572e0cc33d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d",
                3 * dexdo_core::PRICE_STEP as u64,
                256,
            ),
        ];
        for (tc, price, ticks) in asks {
            mock.post_offer(
                SellOffer {
                    price_per_tick: price,
                    max_ticks: ticks,
                    token_contract: tc.into(),
                    flags: 0,
                },
                &note,
            )
            .await
            .unwrap();
        }
        assert_eq!(
            mock.discover_offers().await.unwrap().len(),
            3,
            "three asks seeded"
        );
        // The buyer's view: model `qwen/qwen3-32b`, price ceiling 2 SHELL/tick, default 8 ticks.
        super::render_inference_book(&mock, "qwen/qwen3-32b", 2 * dexdo_core::PRICE_STEP, 8)
            .await
            .unwrap();
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn market_manifest_must_match_positional_model() {
        let dir = std::env::temp_dir().join(format!(
            "dexdo-market-model-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());
        let models = dir.join("models.json");
        std::fs::write(
            &models,
            r#"{
              "models": {
                "qwen": {
                  "frame_model": "qwen--qwen3--32b",
                  "base_url": "https://example.invalid/openai/v1",
                  "served_model": "qwen/qwen3-32b",
                  "api_key_env": "QWEN_KEY",
                  "tokenizer_family": "qwen",
                  "price_per_tick": 1000
                },
                "llama": {
                  "frame_model": "llama--llama3--8b",
                  "base_url": "https://example.invalid/openai/v1",
                  "served_model": "llama/llama3-8b",
                  "api_key_env": "LLAMA_KEY",
                  "tokenizer_family": "llama",
                  "price_per_tick": 1000
                }
              }
            }"#,
        )
        .unwrap();
        let manifest = dexdo_core::MarketManifest {
            network: "shellnet".to_string(),
            frame_model: "qwen--qwen3--32b".to_string(),
            model_hash: dexdo_core::model_hash_for("qwen--qwen3--32b"),
            inference_order_book: "0:book".to_string(),
            root_model: "0:root".to_string(),
            token_contract: "0:tc".to_string(),
            seller_note: "0:seller".to_string(),
            nonce: 7,
            price_per_tick: 1000,
            max_ticks: 8,
        };
        let market = dir.join("market.json");
        std::fs::write(&market, manifest.to_json().unwrap()).unwrap();

        assert!(super::target_from_market_for_model(&market, &models, "qwen").is_ok());
        assert!(super::target_from_market_for_model(&market, &models, "qwen--qwen3--32b").is_ok());
        let err = match super::target_from_market_for_model(&market, &models, "llama") {
            Ok(_) => panic!("wrong positional model must fail closed"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("refusing to render the wrong market"), "{err}");
        assert!(err.contains("llama--llama3--8b"), "{err}");
        assert!(err.contains("qwen--qwen3--32b"), "{err}");
    }

    #[test]
    fn seller_offer_path_has_no_exact_tc_id_walk() {
        let backend = include_str!("../../../core/src/shellnet/backends.rs");
        assert!(!backend.contains("ORDERBOOK_EXACT_TC_SCAN_TIMEOUT"));
        assert!(!backend.contains("active_sell_order_ids_for_exact_tc_bounded"));
        assert!(!backend.contains("duplicate active sell order preflight incomplete"));
    }

    #[test]
    fn buyer_registry_gate_precedes_backend_and_money_raise() {
        let source = include_str!("buyer.rs");
        let start = source
            .find("async fn run_buyer_inner")
            .expect("run_buyer_inner present");
        let end = source[start..]
            .find("#[cfg(test)]\nmod tests")
            .map(|offset| start + offset)
            .expect("run_buyer_inner end marker present");
        let body = &source[start..end];

        let policy = body
            .find("let registry_policy =")
            .expect("registry policy load present");
        let doctor = body[policy..]
            .find("shellnet_doctor_preflight(")
            .map(|offset| policy + offset)
            .expect("registry-enabled doctor present");
        let resolve = body[doctor..]
            .find("resolve_model_registry_target(")
            .map(|offset| doctor + offset)
            .expect("exact registry resolution present");
        let enforce = body[resolve..]
            .find("enforce_model_registry_policy(")
            .map(|offset| resolve + offset)
            .expect("registry hash/book enforcement present");
        let shape = body
            .find("validate_canonical_model_id(")
            .expect("legacy shape check present");
        let backend = body
            .find("buyer_real_backend(")
            .expect("real backend construction present");
        let money = body
            .find("raise_pending_buyer_money_before_fresh_reads(")
            .expect("pending money raise present");

        assert!(
            policy < doctor
                && doctor < resolve
                && resolve < enforce
                && enforce < shape
                && shape < backend
                && backend < money,
            "registry membership/hash/book gate must finish before legacy shape, backend construction, or money raise"
        );
    }

    #[test]
    fn subscription_registry_getter_uses_existing_read_timeout_scope() {
        let source = include_str!("buyer.rs");
        let start = source
            .find("pub(crate) async fn run_subscription(args: SubscriptionArgs)")
            .expect("shellnet subscription present");
        let rest = &source[start..];
        let end = rest[1..]
            .find("\n#[cfg(")
            .map(|offset| offset + 1)
            .unwrap_or(rest.len());
        let body = &rest[..end];
        let timeout = body
            .find("direct_chain_read_with_timeout(")
            .expect("subscription read timeout present");
        let resolution = body
            .find("resolve_model_registry_target(")
            .expect("subscription registry resolution present");

        assert!(
            timeout < resolution,
            "subscription registry getter must run inside the existing read timeout"
        );
    }

    #[test]
    fn subscription_reconciles_before_doctor_and_doctor_precedes_fresh_money() {
        let source = include_str!("buyer.rs");
        let start = source
            .find("pub(crate) async fn run_subscription")
            .expect("run_subscription present");
        let end = source[start..]
            .find("#[cfg(not(feature = \"shellnet\"))]")
            .map(|offset| start + offset)
            .expect("shellnet run_subscription end marker present");
        let body = &source[start..end];

        let plan = body
            .find("subscription_place_plan(place)?")
            .expect("checked subscription reserve plan present");
        let backend = body
            .find("RealChainBackend::connect(")
            .expect("subscription backend construction present");
        let reconcile = body
            .find("reconcile_existing_subscription_journal(")
            .expect("durable subscription reconciliation present");
        let doctor = body
            .find("shellnet_doctor_preflight(")
            .expect("subscription money doctor preflight present");
        let exact_order = body
            .find("inference_orderbook_parsed_order(")
            .expect("one exact-order read present");
        let place = body
            .find("submit_subscription_with_journal(")
            .expect("fresh subscription place present");
        let cancel = body
            .find(".cancel_inference_order(")
            .expect("fresh subscription cancel present");

        assert!(
            plan < backend
                && reconcile < doctor
                && doctor < exact_order
                && exact_order < place
                && place < cancel,
            "limit reserve/MARKET rejection must precede backend construction; durable \
             reconciliation must precede doctor; doctor/exact reads must precede every fresh \
             subscription money submit"
        );
    }

    #[test]
    fn subscription_exact_order_lookup_is_independent_of_historical_order_ids() {
        let buyer = include_str!("buyer.rs");
        let start = buyer
            .find("pub(crate) async fn run_subscription")
            .expect("run_subscription present");
        let end = buyer[start..]
            .find("#[cfg(not(feature = \"shellnet\"))]")
            .map(|offset| start + offset)
            .expect("shellnet run_subscription end marker present");
        let command = &buyer[start..end];
        assert!(!command.contains("read_book_target("));
        assert!(!command.contains("inference_orderbook_snapshot("));
        assert_eq!(
            command.matches("inference_orderbook_parsed_order(").count(),
            1
        );

        let backend = include_str!("../../../core/src/shellnet/backends.rs");
        let summary_start = backend
            .find("pub async fn inference_orderbook_summary")
            .expect("constant-cost summary reader present");
        let exact_start = backend[summary_start..]
            .find("pub async fn inference_orderbook_parsed_order")
            .map(|offset| summary_start + offset)
            .expect("constant-cost exact-order reader present");
        let exact_end = backend[exact_start..]
            .find("pub async fn inference_orderbook_snapshot_for_note")
            .map(|offset| exact_start + offset)
            .expect("exact-order reader end marker present");
        let summary = &backend[summary_start..exact_start];
        let exact = &backend[exact_start..exact_end];

        assert_eq!(summary.matches("inference_orderbook_stats(").count(), 1);
        assert!(!summary.contains("next_order_id"));
        assert_eq!(exact.matches("inference_orderbook_order(").count(), 1);
        assert!(!exact.contains("next_order_id"));
        assert!(!exact.contains("for "));
    }

    #[test]
    fn final_interactive_buyer_price_is_validated_before_escrow_and_quote() {
        let step = dexdo_core::PRICE_STEP;
        for invalid in [0, step - 1, step + 1] {
            assert!(
                crate::cli::support::validate_price_step(invalid).is_err(),
                "{invalid} must be rejected"
            );
        }
        for valid in [step, 2 * step] {
            assert!(
                crate::cli::support::validate_price_step(valid).is_ok(),
                "{valid} must be accepted"
            );
        }

        let source = include_str!("buyer.rs");
        let start = source
            .find("// Show the book, THEN let the buyer choose")
            .expect("interactive buyer selection branch");
        let branch = &source[start..];
        let chosen = branch
            .find("let (ticks, max_price) =")
            .expect("final interactive choice");
        let validation = branch
            .find("validate_price_step(max_price)?;")
            .expect("final chosen-price validation");
        let escrow = branch
            .find("let escrow = args")
            .expect("chosen-order escrow calculation");
        let quote = branch
            .find("buyer_quote_selection_for_submit(")
            .expect("chosen-order quote");
        assert!(
            chosen < validation && validation < escrow && escrow < quote,
            "the final chosen buyer price must be validated before escrow, quote, or submit"
        );
    }

    /// PR347 review blocker regression: active-pool validation must stay before both direct and model-only
    /// money-moving buy submissions in lazy and one-shot buyer flows.
    #[test]
    fn buyer_pool_preflight_precedes_money_moving_buy_paths() {
        let source = include_str!("buyer.rs");
        let wrapper_start = source
            .find("async fn place_buy_by_model_after_pool_preflight")
            .expect("model buy wrapper present");
        let wrapper_end = source[wrapper_start..]
            .find("fn record_buyer_token_contract_after_money_move")
            .map(|offset| wrapper_start + offset)
            .expect("model buy wrapper end marker present");
        let wrapper = &source[wrapper_start..wrapper_end];
        let wrapper_preflight = wrapper
            .find("preflight_buyer_pool_for_note(pool_note_addr)?")
            .expect("wrapper pool preflight present");
        let wrapper_submit = wrapper
            .find(".place_buy_by_model(")
            .expect("wrapper model buy submit present");
        assert!(
            wrapper_preflight < wrapper_submit,
            "model buy wrapper must preflight DEXDO_PN_POOL before place_buy_by_model"
        );

        let lazy_start = source
            .find("async fn prepare_lazy_buyer_api_deal_once")
            .expect("lazy buyer helper present");
        let lazy_end = source[lazy_start..]
            .find("async fn run_buyer_on_demand_local_api")
            .map(|offset| lazy_start + offset)
            .expect("lazy buyer helper end marker present");
        let lazy = &source[lazy_start..lazy_end];
        assert_eq!(lazy.matches("execute_buyer_quote_submit(").count(), 2);
        assert!(!lazy.contains("buyer.place_buy(chain.as_ref(), &tc)"));

        let oneshot_start = source
            .find("async fn run_buyer_inner")
            .expect("one-shot buyer helper present");
        let oneshot_end = source[oneshot_start..]
            .find("#[cfg(test)]\nmod tests")
            .map(|offset| oneshot_start + offset)
            .expect("one-shot buyer helper end marker present");
        let oneshot = &source[oneshot_start..oneshot_end];
        assert_eq!(oneshot.matches("execute_buyer_quote_submit(").count(), 2);
        assert!(!oneshot.contains("buyer.place_buy(chain.as_ref(), &tc)"));
    }

    /// regression: under buyer registry validation a raw `--token-contract` does not carry canonical
    /// order-book proof, so it must be rejected before escrow/place_buy. `--market` remains the explicit
    /// trusted path because the manifest carries the book checked by the registry preflight.
    #[test]
    fn buyer_registry_enabled_raw_token_contract_rejected_without_book_proof() {
        let err = super::reject_buyer_raw_token_contract_without_registry_book_proof(
            None,
            Some("0:badtc"),
            "qwen--qwen3--32b",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("raw --token-contract"), "{err}");
        assert!(err.contains("canonical order-book proof"), "{err}");
        assert!(err.contains("buyer.check_model_registry=true"), "{err}");

        let market_path = std::path::Path::new("market.json");
        assert!(
            super::reject_buyer_raw_token_contract_without_registry_book_proof(
                Some(market_path),
                None,
                "qwen--qwen3--32b",
            )
            .is_ok()
        );
        assert!(
            super::reject_buyer_raw_token_contract_without_registry_book_proof(
                None,
                None,
                "qwen--qwen3--32b",
            )
            .is_ok()
        );
    }

    /// released-style binaries must not need
    /// `contracts/compiled/airegistry/ModelRegistry.abi.json` in the current working directory just to
    /// resolve the buyer's content identity. The ABI source is embedded in `registry.rs`; this guard keeps the
    /// CLI from reintroducing the old `abi_path.exists()` bail.
    #[test]
    fn content_identity_resolution_uses_embedded_model_registry_abi() {
        let source = include_str!("buyer.rs");
        let start = source
            .find("async fn resolve_content_identity_model")
            .expect("content identity resolver present");
        let end = source[start..]
            .find("#[cfg(not(feature = \"shellnet\"))]")
            .map(|offset| start + offset)
            .expect("resolver end marker present");
        let body = &source[start..end];

        assert!(
            body.contains(
                "ShellnetModelRegistryReader::from_manifest(contracts, &registry_address)"
            ),
            "resolver must use the embedded-ABI ModelRegistry reader"
        );
        assert!(
            !body.contains("abi_path") && !body.contains(".exists()"),
            "resolver must not depend on a cwd/filesystem ABI path"
        );
        assert!(
            !body.contains("not committed in this branch"),
            "released binaries must not bail because ModelRegistry.abi.json is absent from cwd"
        );
    }

    #[test]
    fn buyer_content_identity_resolution_error_fails_closed_without_allow_flag() {
        let err = super::buyer_content_identity_resolution_result(
            "qwen--qwen3--32b",
            false,
            Err(anyhow::anyhow!("registry unreachable")),
        )
        .expect_err("strict buyer must fail closed on registry resolution failure")
        .to_string();

        assert!(err.contains("registry unreachable"), "{err}");
    }

    #[test]
    fn buyer_allow_unverified_model_degrades_resolution_error_to_name_only() {
        let identity = super::buyer_content_identity_resolution_result(
            "qwen--qwen3--32b",
            true,
            Err(anyhow::anyhow!("registry unreachable")),
        )
        .expect("allow-unverified buyer may continue on name-only evidence");

        assert_eq!(identity, None);
    }

    #[test]
    fn buyer_local_api_content_identity_preflights_before_backend_quote_or_buy() {
        let source = include_str!("buyer.rs");
        let start = source
            .find("let buyer_content_policy = if args.local_listen.is_some()")
            .expect("buyer content preflight present");
        let body = &source[start..];
        let preflight = body
            .find("build_buyer_content_policy")
            .expect("content policy helper called");
        let backend = body
            .find("buyer_real_backend")
            .expect("real buyer backend construction present");
        let pending_money = body
            .find("raise_pending_buyer_money_before_fresh_reads")
            .expect("pending money reconciliation present");
        let on_demand = body
            .find("run_buyer_on_demand_local_api")
            .expect("on-demand branch present");
        let direct_buy = body
            .find("buyer.place_buy(chain.as_ref(), &tc)")
            .expect("direct buy path present");
        let model_buy = body
            .find(".place_buy_by_model(")
            .expect("model-only buy path present");

        assert!(
            preflight < backend && preflight < pending_money,
            "content identity must reject before backend construction or pending-money recovery"
        );
        assert!(
            preflight < on_demand,
            "on-demand buyer must reject missing content-identity inputs before lazy buy/handover"
        );
        assert!(
            preflight < direct_buy && preflight < model_buy,
            "local API buyer must reject missing content-identity inputs before escrow/place_buy"
        );
    }

    #[test]
    fn buyer_content_identity_preflight_error_names_operator_input() {
        let err = dexdo::buyer::api::content_check_policy(
            "qwen--qwen3--32b",
            None,
            false,
            false,
            false,
            &dexdo::seller::ModelsConfig::empty(),
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "buyer content-identity preflight failed before buy: \
                 missing_or_unset=allow_unverified_model_or_models_data; {e}"
            )
        })
        .expect_err("strict name-only content identity must fail closed")
        .to_string();

        assert!(
            err.contains("missing_or_unset=allow_unverified_model_or_models_data"),
            "{err}"
        );
        assert!(err.contains("before buy"), "{err}");
    }

    #[cfg(feature = "shellnet")]
    // This test must serialize the process-global current directory for the full async scenario.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    #[ignore = "live : read-only released-style content identity resolution via embedded ModelRegistry ABI"]
    async fn live_content_identity_resolution_works_without_modelregistry_abi_file_in_cwd() {
        static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _lock = CWD_LOCK.lock().unwrap();

        struct RestoreCwd {
            old: std::path::PathBuf,
            tmp: std::path::PathBuf,
        }

        impl Drop for RestoreCwd {
            fn drop(&mut self) {
                let _ = std::env::set_current_dir(&self.old);
                let _ = std::fs::remove_dir_all(&self.tmp);
            }
        }

        let old = std::env::current_dir().expect("current cwd");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!(
            "dexdo-308-release-cwd-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir(&tmp).expect("create release-style cwd");
        let _restore = RestoreCwd {
            old,
            tmp: tmp.clone(),
        };
        std::env::set_current_dir(&tmp).expect("enter release-style cwd");

        let cwd_abi = tmp.join("contracts/compiled/airegistry/ModelRegistry.abi.json");
        assert!(
            !cwd_abi.exists(),
            "test cwd must not carry the ModelRegistry ABI file"
        );
        let contracts = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/deployed.shellnet.json");
        let identity = super::resolve_content_identity_model(&contracts, "qwen--qwen3--32b")
            .await
            .expect("resolve qwen content identity from embedded ModelRegistry ABI");
        assert_eq!(identity, "Qwen/Qwen3-32B");
        println!(
            "live  evidence: release-style cwd={} cwd_abi_absent=true frame_model=qwen--qwen3--32b identity={identity}",
            tmp.display()
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    #[ignore = "live -carry: bad ModelRegistry manifest fails strict and downgrades only with --allow-unverified-model"]
    async fn live_allow_unverified_model_downgrades_unreachable_registry_to_name_only() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!(
            "dexdo-307-bad-registry-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir(&tmp).expect("create scratch manifest dir");
        let _cleanup = TempDirCleanup(tmp.clone());

        let contracts = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/deployed.shellnet.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&contracts).expect("read contracts manifest"))
                .expect("parse contracts manifest");
        let bad_registry = "0:2222222222222222222222222222222222222222222222222222222222222222";
        manifest["model_registry"] = serde_json::Value::String(bad_registry.to_string());
        let scratch = tmp.join("deployed.bad-registry.json");
        std::fs::write(
            &scratch,
            serde_json::to_vec_pretty(&manifest).expect("serialize scratch manifest"),
        )
        .expect("write scratch manifest");

        let strict =
            super::resolve_buyer_content_identity_model(&scratch, "qwen--qwen3--32b", false)
                .await
                .expect_err("strict buyer must fail closed when ModelRegistry is unreachable")
                .to_string();
        assert!(strict.contains("ModelRegistry"), "{strict}");

        let allowed =
            super::resolve_buyer_content_identity_model(&scratch, "qwen--qwen3--32b", true)
                .await
                .expect("allow-unverified buyer may continue on name-only evidence");
        assert_eq!(allowed, None);
        println!(
            "live -carry evidence: scratch_manifest={} bad_registry={} strict_failed=true allow_unverified_name_only=true",
            scratch.display(),
            bad_registry
        );
    }

    /// machine-mode model-only buy must not emit `quote_selected` from executable discovery alone when
    /// the raw shellnet matcher cannot reach that ask.
    #[test]
    fn buyer_model_only_quote_selection_runs_submit_safe_preflight() {
        let source = include_str!("buyer.rs");
        let quote = source
            .find("async fn buyer_quote_selection")
            .expect("buyer quote helper present");
        let body = &source[quote..];
        let preflight = body
            .find("submit_safe_model_buy_quote_order")
            .expect("model-only quote selection reads the authoritative submit-safe row");
        let discover = body
            .find("chain.discover_offers")
            .expect("buyer quote selection discovers offers");
        assert!(
            preflight < discover,
            "submit-safety preflight must run before executable discovery is rendered as quote_selected"
        );
    }

    /// the model-only buyer must validate the TC state immediately after its fill event and before
    /// waiting for the seller handover.
    #[test]
    fn model_only_buy_validates_match_state_before_handover_wait() {
        let source = include_str!("buyer.rs");
        let executor = source
            .find("async fn execute_buyer_quote_submit")
            .expect("durable buyer executor present");
        let executor_end = source[executor..]
            .find("fn record_buyer_token_contract_after_money_move")
            .map(|offset| executor + offset)
            .unwrap();
        let durable = &source[executor..executor_end];
        let wait_match = durable
            .find("wait_matched_token_contract")
            .expect("model-only buy waits for fill event");
        let validate = durable[wait_match..]
            .find("validate_reported_match_state")
            .map(|offset| wait_match + offset)
            .expect("model-only buy validates matched TC state");
        assert!(wait_match < validate);
        let buy = source.find("async fn run_buyer_inner").unwrap();
        let body = &source[buy..];
        let submit = body.find("execute_buyer_quote_submit(").unwrap();
        let handover = body
            .find("resolve_endpoint(chain.as_ref(), &token_contract)")
            .expect("buyer waits for handover");
        assert!(
            submit < handover,
            "matched TC state must be checked before handover wait"
        );
        assert!(
            body.contains("handover_timeout_diagnostic"),
            "handover timeout must re-read TC state for funded-never-opened recovery diagnostics"
        );
    }

    /// in machine mode, model-only buy submission is its own by-fact event. It must be emitted
    /// immediately after `place_buy_by_model` returns, before the process can block in fill/match polling.
    #[test]
    fn model_only_buy_submitted_is_emitted_before_match_wait_path() {
        let source = include_str!("buyer.rs");
        let executor = source
            .find("async fn execute_buyer_quote_submit")
            .expect("durable buyer executor present");
        let executor_end = source[executor..]
            .find("fn record_buyer_token_contract_after_money_move")
            .map(|offset| executor + offset)
            .unwrap();
        let segment = &source[executor..executor_end];
        let submit = segment.find("start_durable_buyer_submit(").unwrap();
        let buy_event = segment.find("on_submit_observed(").unwrap();
        let wait_match = segment.find("complete_buyer_submit_with_journal(").unwrap();
        assert!(
            submit < buy_event && buy_event < wait_match,
            "model-only buyer must emit buy_submitted after submit returns and before match wait"
        );
    }

    #[test]
    fn policy_cleanup_rechecks_state_after_wait_before_cleanup() {
        let source = include_str!("buyer.rs");
        let start = source
            .find("async fn policy_cleanup_unopened_after_match_timeout")
            .expect("policy cleanup helper present");
        let end = source[start..]
            .find("async fn apply_no_handover_after_match_policy")
            .map(|offset| start + offset)
            .expect("policy cleanup helper end marker present");
        let body = &source[start..end];
        let sleep = body
            .find("tokio::time::sleep")
            .expect("cleanup wait present");
        let recheck = body[sleep..]
            .find("validate_reported_match_state")
            .map(|offset| sleep + offset)
            .expect("state recheck after wait present");
        let cleanup = body
            .find("chain.cleanup_unopened")
            .expect("cleanup lever present");
        assert!(
            sleep < recheck && recheck < cleanup,
            "cleanup must re-read TC state after waiting and before cleanup_unopened"
        );
        assert!(
            body.contains("not_cleanup_unopened_state_after_wait"),
            "unexpected post-wait states must not be cleaned up silently"
        );
        assert!(
            body.contains("handover_opened_after_wait"),
            "late-opened deals must return to the handover path instead of failing cleanup"
        );
    }

    #[test]
    fn policy_buyer_failure_classes_dispatch_runtime_levers() {
        let source = include_str!("buyer.rs");
        let malformed = source
            .find("async fn apply_malformed_handover_policy")
            .expect("malformed handover policy helper present");
        let cleanup = source[malformed..]
            .find("async fn policy_cleanup_unopened_after_match_timeout")
            .map(|offset| malformed + offset)
            .expect("malformed helper end marker present");
        let malformed_body = &source[malformed..cleanup];
        assert!(
            malformed_body.contains("chain.stop(token_contract, buyer.note.as_ref())"),
            "malformed_handover=reclaim must invoke the reclaim lever (a STOP recovers the escrow)"
        );
        assert!(
            malformed_body.contains("chain.dispute(token_contract, buyer.note.as_ref())"),
            "malformed_handover=dispute must invoke stream dispute"
        );

        let buy = source
            .find("pub(crate) async fn run_buyer")
            .expect("run_buyer present");
        let monitor = source[buy..]
            .find("#[cfg(test)]\nmod tests")
            .map(|offset| buy + offset)
            .expect("run_buyer end marker present");
        let body = &source[buy..monitor];
        assert!(
            body.contains("is_malformed_handover_error(&e)")
                && body.contains("apply_malformed_handover_policy"),
            "run_buyer must route malformed/decrypt handovers through policy"
        );
        assert!(
            body.contains("apply_oneshot_dead_gateway_policy"),
            "one-shot buyer stream open/connect errors must route through dead_gateway policy"
        );
        assert!(
            body.contains("apply_oneshot_empty_stream_policy"),
            "one-shot buyer zero-token stream must route through empty_stream policy"
        );
    }

    /// re-review: the secret-bearing pool temp must be exclusive. A pre-created temp path
    /// (file or symlink) is not truncated/clobbered before the final atomic rename.
    #[cfg(feature = "shellnet")]
    #[test]
    fn write_pool_private_refuses_preexisting_temp_path() {
        let dir = std::env::temp_dir().join(format!(
            "dexdo-pool-temp-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());
        let target = dir.join("pn_pool.json");
        let tmp = dir.join(".pn_pool.json.tmp.preexisting");
        std::fs::write(&tmp, b"do-not-clobber").unwrap();

        let err = super::write_pool_private_via_temp(&target, &tmp, b"secret-pool")
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("create temp secret file"),
            "unexpected error: {err}"
        );
        assert_eq!(std::fs::read(&tmp).unwrap(), b"do-not-clobber");
        assert!(
            !target.exists(),
            "target must not be written after temp creation failed"
        );
    }

    /// regression: writers using different symlinks to one pool must share the canonical lock and
    /// target. The second writer re-reads the first result, so neither recovery key is lost.
    #[cfg(all(feature = "shellnet", unix))]
    #[test]
    fn concurrent_note_pool_writers_via_symlinks_preserve_both_notes() {
        fn state(seed_byte: u8, address_byte: char) -> crate::cli::note::OnboardPnState {
            let secret = format!("{seed_byte:02x}").repeat(32);
            let public = crate::cli::note::derive_owner_pubkey_from_secret_hex(&secret).unwrap();
            crate::cli::note::OnboardPnState {
                endpoint: "shellnet.ackinacki.org".into(),
                nominal: "N100".into(),
                token_type: dexdo_core::params::SHELL_CURRENCY_ID,
                raw_value: 100_000_000_000,
                ecc_shell_deposit: 100_000_000_000,
                pn_address: Some(format!("0:{}", address_byte.to_string().repeat(64))),
                deposit_identifier_hash: Some(address_byte.to_string().repeat(64)),
                owner_public_key_hex: Some(public),
                owner_secret_key_hex: Some(secret.into()),
                deployed_at_unix: Some(1_000),
                shell_funded: true,
                sanity_checked: true,
            }
        }

        let dir = std::env::temp_dir().join(format!(
            "dexdo-pool-concurrent-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());
        let pool_path = dir.join("pn_pool.json");
        let wallet = format!("0:{}", "c".repeat(64));
        let initial_state = state(0x1a, 'd');
        let initial_note = crate::cli::note::pn_state_to_pool_note(&initial_state).unwrap();
        let initial_pool = crate::cli::note::pool_with_note_added(
            None,
            &initial_state,
            initial_note,
            1_000,
            &wallet,
        )
        .unwrap();
        std::fs::write(&pool_path, serde_json::to_vec(&initial_pool).unwrap()).unwrap();
        let first_alias = dir.join("first-pool.json");
        let second_alias = dir.join("second-pool.json");
        std::os::unix::fs::symlink(&pool_path, &first_alias).unwrap();
        std::os::unix::fs::symlink(&pool_path, &second_alias).unwrap();
        let first_state = state(0x2a, 'a');
        let second_state = state(0x3a, 'b');

        let (first_read_tx, first_read_rx) = std::sync::mpsc::channel();
        let (release_first_tx, release_first_rx) = std::sync::mpsc::channel();
        let first_pool = first_alias;
        let first_wallet = wallet.clone();
        let first = std::thread::spawn(move || {
            super::with_pool_write_lock(&first_pool, |first_pool| {
                super::note_deploy_fold_state_into_pool_locked(
                    first_pool,
                    &first_state,
                    &first_wallet,
                    || {
                        first_read_tx.send(()).unwrap();
                        release_first_rx.recv().unwrap();
                    },
                )
            })
            .unwrap();
        });
        first_read_rx.recv().unwrap();

        let (second_started_tx, second_started_rx) = std::sync::mpsc::channel();
        let (second_done_tx, second_done_rx) = std::sync::mpsc::channel();
        let second_pool = second_alias;
        let second = std::thread::spawn(move || {
            second_started_tx.send(()).unwrap();
            super::note_deploy_fold_state_into_pool(&second_pool, &second_state, &wallet).unwrap();
            second_done_tx.send(()).unwrap();
        });
        second_started_rx.recv().unwrap();
        let completed_while_first_writer_was_paused = second_done_rx
            .recv_timeout(std::time::Duration::from_millis(250))
            .is_ok();

        release_first_tx.send(()).unwrap();
        first.join().unwrap();
        second.join().unwrap();
        assert!(
            !completed_while_first_writer_was_paused,
            "the second writer entered the pool read-modify-write while the first held the lock"
        );

        let pool = super::load_pool_json(&pool_path).unwrap();
        let addresses = pool["notes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|note| note["address"].as_str().unwrap())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(
            addresses.len(),
            3,
            "both concurrently added notes must survive"
        );
        assert!(addresses.contains(format!("0:{}", "a".repeat(64)).as_str()));
        assert!(addresses.contains(format!("0:{}", "b".repeat(64)).as_str()));
    }

    /// negative regression: pool targets and lock sentinels must be regular files.
    #[cfg(all(feature = "shellnet", unix))]
    #[test]
    fn pool_and_lock_non_regular_sentinels_are_rejected() {
        let dir = std::env::temp_dir().join(format!(
            "dexdo-pool-nonregular-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());

        let pool_directory = dir.join("pool-directory");
        std::fs::create_dir(&pool_directory).unwrap();
        let err = super::with_pool_write_lock(&pool_directory, |_| Ok(()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("regular file"), "{err}");

        let pool = dir.join("pn_pool.json");
        std::fs::write(&pool, br#"{"notes":[]}"#).unwrap();
        let lock = dir.join("pn_pool.json.lock");
        std::os::unix::fs::symlink(&pool, &lock).unwrap();
        let err = super::with_pool_write_lock(&pool, |_| Ok(()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("pool lock"), "{err}");
        assert!(err.contains("regular file"), "{err}");
    }

    /// regression: `DEXDO_PN_POOL=<same existing file> dexdo note deploy --pool <same file>` is the
    /// reported footgun. Refuse before chain work, so a bad append cannot silently poison the active pool.
    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_rejects_same_file_env_pool_append() {
        let dir = std::env::temp_dir().join(format!(
            "dexdo-same-pool-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());
        let pool = dir.join("pn_pool.json");
        let other = dir.join("other_pool.json");
        std::fs::write(&pool, br#"{"notes":[]}"#).unwrap();
        std::fs::write(&other, br#"{"notes":[]}"#).unwrap();

        let err = super::note_deploy_same_file_pool_guard(Some(pool.as_os_str()), &pool)
            .unwrap_err()
            .to_string();

        assert!(err.contains("DEXDO_PN_POOL"), "{err}");
        assert!(err.contains("--pool"), "{err}");
        assert!(err.contains("ERR_INVALID_SENDER 101"), "{err}");
        assert!(err.contains("--pool <new_file>"), "{err}");
        super::note_deploy_same_file_pool_guard(Some(other.as_os_str()), &pool)
            .expect("different existing pool file is allowed");
        super::note_deploy_same_file_pool_guard(None, &pool).expect("unset env pool is allowed");
    }

    /// PR347 review blocker regression: a stale active pool must fail before the money-moving model buy call.
    #[cfg(feature = "shellnet")]
    // This test must serialize process-global DEXDO_PN_POOL for the full async scenario.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn stale_pool_preflight_blocks_model_buy_before_chain_call() {
        use std::sync::atomic::Ordering;

        let _env_lock = dexdo_pn_pool_env_lock().lock().unwrap();
        let dir = std::env::temp_dir().join(format!(
            "dexdo-stale-pool-preflight-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());
        let pool = dir.join("pn_pool.json");
        let stale_note = format!("0:{}", "1".repeat(64));
        let buyer_note = format!("0:{}", "2".repeat(64));
        std::fs::write(
            &pool,
            serde_json::to_vec_pretty(&serde_json::json!({
                "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
                "notes": [{
                    "address": stale_note,
                    "owner_secret_key_hex": "00"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let _env = EnvVarGuard::set("DEXDO_PN_POOL", pool.as_os_str());
        let chain = RecordingRecoveryChain::default();
        let buyer =
            dexdo::buyer::Buyer::from_note(std::sync::Arc::new(dexdo_core::LocalNote::generate()));

        let err = super::place_buy_by_model_after_pool_preflight(
            &chain,
            &buyer,
            true,
            Some(&buyer_note),
            1,
            1,
            1,
        )
        .await
        .unwrap_err()
        .to_string();

        assert!(err.contains("no note entry"), "{err}");
        assert_eq!(
            chain.place_next_calls.load(Ordering::SeqCst),
            0,
            "stale pool must fail before place_buy_by_model moves escrow"
        );
    }

    /// Owner currency regression: the real command entry must reject stale pool metadata before chain use.
    #[cfg(feature = "shellnet")]
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn real_buyer_entry_rejects_bad_pool_currency_before_chain_or_post() {
        use std::sync::atomic::Ordering;

        let _env_lock = dexdo_pn_pool_env_lock().lock().unwrap();
        let dir = std::env::temp_dir().join(format!(
            "dexdo-non-shell-pool-preflight-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());
        let buyer_note = format!("0:{}", "2".repeat(64));
        for (case, pool) in [
            (
                "missing",
                serde_json::json!({
                    "notes": [{"address": buyer_note, "owner_secret_key_hex": "00"}]
                }),
            ),
            (
                "malformed",
                serde_json::json!({
                    "token_type": "2",
                    "notes": [{"address": buyer_note, "owner_secret_key_hex": "00"}]
                }),
            ),
            (
                "non-shell",
                serde_json::json!({
                    "token_type": 1,
                    "notes": [{"address": buyer_note, "owner_secret_key_hex": "00"}]
                }),
            ),
        ] {
            let pool_path = dir.join(format!("{case}.pool.json"));
            std::fs::write(&pool_path, serde_json::to_vec_pretty(&pool).unwrap()).unwrap();
            let _env = EnvVarGuard::set("DEXDO_PN_POOL", pool_path.as_os_str());
            let recording = std::sync::Arc::new(QuotePreflightChain::default());
            let backend: std::sync::Arc<dyn dexdo_core::ChainBackend> = recording.clone();
            let note: std::sync::Arc<dyn dexdo_core::Note> =
                std::sync::Arc::new(dexdo_core::LocalNote::generate());
            let mut machine_events = None;
            let mut machine_context = super::BuyerMachineErrorContext::default();

            let error = super::run_buyer_inner(
                super::BuyerArgs {
                    mock: super::MockFlags {
                        mock_model: false,
                        mock_chain: false,
                    },
                    identity: super::IdentityArgs {
                        note_key: None,
                        note_index: 0,
                        note_addr: Some(buyer_note.clone()),
                    },
                    registry: super::ModelRegistryValidationArgs::default(),
                    endpoints_file: None,
                    deals_dir: Some(dir.join("deals")),
                    token_contract: Some(format!("0:{}", "3".repeat(64))),
                    resume: false,
                    market: None,
                    max_tokens: 1,
                    local_listen: None,
                    continuity_mode: super::ContinuityModeArg::Proactive,
                    json: false,
                    anthropic_compat: false,
                    frame_model: Some("qwen--qwen3--32b".to_string()),
                    allow_unverified_model: true,
                    models: dir.join("models.json"),
                    ticks: 1,
                    max_price_per_tick: dexdo_core::PRICE_STEP,
                    escrow: None,
                    contracts: dir.join("must-not-read-contracts.json"),
                    policy: None,
                },
                &mut machine_events,
                &mut machine_context,
                super::BuyerCommandRuntime {
                    backend: Some((backend, note)),
                    shellnet_preflight: super::BuyerShellnetPreflight::Production,
                    shutdown: Box::pin(std::future::pending()),
                },
            )
            .await
            .unwrap_err()
            .to_string();

            assert!(
                error.contains("DEXDO_PN_POOL token_type"),
                "{case}: {error}"
            );
            assert!(
                error.contains(&format!(
                    "SHELL currency id {}",
                    dexdo_core::params::SHELL_CURRENCY_ID
                )),
                "{case}: {error}"
            );
            assert_eq!(
                recording.discover_calls.load(Ordering::SeqCst)
                    + recording.model_preflight_calls.load(Ordering::SeqCst)
                    + recording
                        .model_presubmit_preflight_calls
                        .load(Ordering::SeqCst)
                    + recording.sell_offer_terms_calls.load(Ordering::SeqCst),
                0,
                "{case}: bad pool currency must produce zero chain reads"
            );
            assert_eq!(
                recording.model_before_post_calls.load(Ordering::SeqCst)
                    + recording.model_money_submit_calls.load(Ordering::SeqCst)
                    + recording.model_submit_calls.load(Ordering::SeqCst),
                0,
                "{case}: bad pool currency must produce zero POSTs"
            );
        }
    }

    /// regression: a direct note identity without DEXDO_PN_POOL must fail before escrow moves.
    #[cfg(feature = "shellnet")]
    // This test must serialize process-global DEXDO_PN_POOL for the full async scenario.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn missing_pool_preflight_blocks_model_buy_before_chain_call() {
        use std::sync::atomic::Ordering;

        let _env_lock = dexdo_pn_pool_env_lock().lock().unwrap();
        let _env = EnvVarGuard::unset("DEXDO_PN_POOL");
        let buyer_note = format!("0:{}", "2".repeat(64));
        let chain = RecordingRecoveryChain::default();
        let buyer =
            dexdo::buyer::Buyer::from_note(std::sync::Arc::new(dexdo_core::LocalNote::generate()));

        let err = super::place_buy_by_model_after_pool_preflight(
            &chain,
            &buyer,
            true,
            Some(&buyer_note),
            1,
            1,
            1,
        )
        .await
        .expect_err("missing pool must fail before model buy")
        .to_string();

        assert!(err.contains("require DEXDO_PN_POOL"), "{err}");
        assert_eq!(
            chain.place_next_calls.load(Ordering::SeqCst),
            0,
            "missing pool must fail before place_buy_by_model moves escrow"
        );
    }

    #[tokio::test]
    async fn model_only_buy_preserves_typed_chain_errors_for_classification() {
        let buyer =
            dexdo::buyer::Buyer::from_note(std::sync::Arc::new(dexdo_core::LocalNote::generate()));

        for (failure, expected_code, expected_cause) in [
            (
                ModelBuyFailure::Transport,
                crate::cli::machine::ErrorCode::ChainTransport,
                "model-only transport cause",
            ),
            (
                ModelBuyFailure::Contract,
                crate::cli::machine::ErrorCode::ChainRevert,
                "model-only contract cause",
            ),
        ] {
            let chain = RecordingRecoveryChain {
                model_buy_failure: Some(failure),
                ..RecordingRecoveryChain::default()
            };
            let err = super::place_buy_by_model_after_pool_preflight(
                &chain, &buyer, false, None, 1, 1, 1,
            )
            .await
            .expect_err("typed model-only buy failure must propagate");

            assert_eq!(
                crate::cli::machine::classify_error(crate::cli::machine::OP_BUYER_START, &err,),
                expected_code
            );
            assert!(
                err.chain().any(|cause| cause
                    .downcast_ref::<dexdo_core::ChainError>()
                    .is_some_and(|chain_error| chain_error.to_string().contains(expected_cause))),
                "typed cause missing from anyhow chain: {err:#}"
            );
        }
    }

    /// residual: recovery/reclaim can be driven from the pool file alone once the buyer has recorded the
    /// matched TokenContract next to the note entry.
    #[cfg(feature = "shellnet")]
    #[test]
    fn recovery_inputs_can_use_pool_only() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}

        let dir = std::env::temp_dir().join(format!(
            "dexdo-recovery-pool-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());
        let pool_path = dir.join("pn_pool.json");
        let note_addr = format!("0:{}", "1".repeat(64));
        let token_contract = format!("0:{}", "2".repeat(64));
        let secret = "2a".repeat(32);
        std::fs::write(
            &pool_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
                "notes": [{
                    "address": note_addr,
                    "owner_secret_key_hex": secret,
                    "token_contract": token_contract,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 99
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        // `pool_record` exists only on the path that persists it, so this is `recover`'s resolver.
        let resolved = super::resolve_persistable_pool_recovery_inputs(
            &RecoveryIdentityArgs {
                note_key: None,
                note_addr: None,
            },
            None,
            None,
            Some(pool_path.as_path()),
        )
        .unwrap();

        assert_eq!(resolved.note_addr, format!("0:{}", "1".repeat(64)));
        assert_eq!(resolved.note_secret_hex.as_str(), "2a".repeat(32));
        assert_eq!(resolved.token_contract, format!("0:{}", "2".repeat(64)));
        assert_zeroize_on_drop(&resolved.note_secret_hex);
        assert_zeroize_on_drop(
            &resolved
                .pool_record
                .as_ref()
                .expect("pool-only recovery record")
                .note_secret_hex,
        );
    }

    /// regression: pool-only recovery must retain the path resolved before STOP even if its symlink alias
    /// is retargeted before the recovery record is persisted.
    #[cfg(all(feature = "shellnet", unix))]
    #[test]
    fn pool_recovery_persists_to_the_initially_resolved_symlink_target() {
        let dir = std::env::temp_dir().join(format!(
            "dexdo-recovery-pool-retarget-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());
        let original_pool = dir.join("original-pool.json");
        let retargeted_pool = dir.join("retargeted-pool.json");
        let pool_alias = dir.join("pn_pool.json");
        let note_addr = format!("0:{}", "1".repeat(64));
        let token_contract = format!("0:{}", "2".repeat(64));
        let secret = "2a".repeat(32);
        let pool_bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
            "notes": [{
                "address": note_addr,
                "owner_secret_key_hex": secret,
                "token_contract": token_contract,
                "token_contract_role": "buyer",
                "token_contract_updated_at_unix": 99
            }]
        }))
        .unwrap();
        std::fs::write(&original_pool, &pool_bytes).unwrap();
        std::fs::write(&retargeted_pool, &pool_bytes).unwrap();
        std::os::unix::fs::symlink(&original_pool, &pool_alias).unwrap();

        let resolved = super::resolve_persistable_pool_recovery_inputs(
            &RecoveryIdentityArgs {
                note_key: None,
                note_addr: None,
            },
            None,
            None,
            Some(pool_alias.as_path()),
        )
        .unwrap();
        let record = resolved.pool_record.unwrap();
        assert_eq!(
            record.pool_path,
            std::fs::canonicalize(&original_pool).unwrap()
        );

        std::fs::remove_file(&pool_alias).unwrap();
        std::os::unix::fs::symlink(&retargeted_pool, &pool_alias).unwrap();
        super::persist_pool_recovery_record(&record).unwrap();

        let original = super::load_pool_json(&original_pool).unwrap();
        assert_ne!(
            original["notes"][0]["token_contract_updated_at_unix"],
            serde_json::json!(99)
        );
        assert_eq!(std::fs::read(&retargeted_pool).unwrap(), pool_bytes);
    }

    /// recovery-key safety: a record changed after resolution must remain byte-for-byte untouched.
    #[cfg(feature = "shellnet")]
    #[test]
    fn pool_recovery_persistence_refuses_a_changed_key_record() {
        let dir = std::env::temp_dir().join(format!(
            "dexdo-recover-key-safety-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());
        let pool_path = dir.join("pn_pool.json");
        let note_addr = format!("0:{}", "1".repeat(64));
        let token_contract = format!("0:{}", "2".repeat(64));
        let bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
            "notes": [{
                "address": note_addr,
                "owner_secret_key_hex": "3b".repeat(32),
                "token_contract": token_contract,
                "token_contract_role": "buyer",
                "token_contract_updated_at_unix": 11
            }]
        }))
        .unwrap();
        std::fs::write(&pool_path, &bytes).unwrap();

        let err = super::persist_pool_recovery_record(&super::PoolRecoveryRecord {
            pool_path: pool_path.clone(),
            note_addr,
            note_secret_hex: "2a".repeat(32).into(),
            token_contract,
            role: "buyer".to_string(),
        })
        .unwrap_err()
        .to_string();

        assert!(err.contains("wrong-key or changed record"), "{err}");
        assert_eq!(std::fs::read(pool_path).unwrap(), bytes);
    }

    /// regression: buyer-only recovery ignores seller records while preserving legacy records without a role.
    #[cfg(feature = "shellnet")]
    #[test]
    fn recovery_inputs_select_buyer_role_and_keep_legacy_unknown() {
        let dir = std::env::temp_dir().join(format!(
            "dexdo-recovery-pool-role-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());
        let pool_path = dir.join("pn_pool.json");
        let note_addr = format!("0:{}", "1".repeat(64));
        let buyer_tc = format!("0:{}", "2".repeat(64));
        let seller_tc = format!("0:{}", "3".repeat(64));
        let secret = "2a".repeat(32);

        for buyer_role in [Some("buyer"), None] {
            let mut buyer_note = serde_json::json!({
                "address": note_addr,
                "owner_secret_key_hex": secret,
                "token_contract": buyer_tc,
            });
            if let Some(role) = buyer_role {
                buyer_note["token_contract_role"] = serde_json::json!(role);
            }
            std::fs::write(
                &pool_path,
                serde_json::to_vec_pretty(&serde_json::json!({
                    "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
                    "notes": [
                        {
                            "address": note_addr,
                            "owner_secret_key_hex": secret,
                            "token_contract": seller_tc,
                            "token_contract_role": "seller"
                        },
                        buyer_note
                    ]
                }))
                .unwrap(),
            )
            .unwrap();

            let resolved = super::resolve_pool_recovery_inputs(
                &RecoveryIdentityArgs {
                    note_key: None,
                    note_addr: None,
                },
                None,
                None,
                Some(pool_path.as_path()),
            )
            .unwrap();
            assert_eq!(resolved.note_addr, note_addr);
            assert_eq!(resolved.token_contract, buyer_tc);
        }
    }

    /// negative: pool-only recovery must not guess when several note entries carry TokenContracts.
    #[cfg(feature = "shellnet")]
    #[test]
    fn recovery_inputs_reject_ambiguous_pool() {
        let dir = std::env::temp_dir().join(format!(
            "dexdo-recovery-pool-ambiguous-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());
        let pool_path = dir.join("pn_pool.json");
        std::fs::write(
            &pool_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
                "notes": [
                    {
                        "address": format!("0:{}", "1".repeat(64)),
                        "owner_secret_key_hex": "2a".repeat(32),
                        "token_contract": format!("0:{}", "2".repeat(64))
                    },
                    {
                        "address": format!("0:{}", "3".repeat(64)),
                        "owner_secret_key_hex": "3a".repeat(32),
                        "token_contract": format!("0:{}", "4".repeat(64))
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        // Not `unwrap_err`: resolved inputs carry a note secret and nothing may render them.
        let err = match super::resolve_pool_recovery_inputs(
            &RecoveryIdentityArgs {
                note_key: None,
                note_addr: None,
            },
            None,
            None,
            Some(pool_path.as_path()),
        ) {
            Ok(_) => panic!("two matching recovery entries must not resolve to one"),
            Err(error) => error.to_string(),
        };

        assert!(err.contains("disambiguate"), "{err}");
    }

    /// regression: the recovery state and final pool are different JSON formats; first-run absent paths
    /// must still reject an accidental same path before any wallet spend.
    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_rejects_same_recovery_and_pool_path() {
        let dir = std::env::temp_dir().join(format!(
            "dexdo-recovery-pool-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());
        let pool = dir.join("pn_pool.json");
        let recovery = dir.join("pn_pool.json.recovery.json");

        let err = super::note_deploy_recovery_pool_guard(&pool, &pool)
            .unwrap_err()
            .to_string();

        assert!(err.contains("--recovery"), "{err}");
        assert!(err.contains("--pool"), "{err}");
        assert!(err.contains("DEXDO_PN_POOL"), "{err}");
        super::note_deploy_recovery_pool_guard(&pool, &recovery)
            .expect("separate recovery and pool paths are allowed");
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_endpoint_url_accepts_bare_host_or_url() {
        assert_eq!(
            super::note_endpoint_url("shellnet.ackinacki.org").unwrap(),
            "https://shellnet.ackinacki.org"
        );
        assert_eq!(
            super::note_endpoint_url("https://shellnet.ackinacki.org/").unwrap(),
            "https://shellnet.ackinacki.org"
        );
        assert!(super::note_endpoint_url("  ").is_err());
    }

    #[cfg(feature = "shellnet")]
    fn note_deploy_args(
        multisig_key: Option<std::path::PathBuf>,
        multisig_seed_file: Option<std::path::PathBuf>,
    ) -> NoteDeployArgs {
        NoteDeployArgs {
            json: false,
            multisig_address: format!("0:{}", "1".repeat(64)),
            multisig_key,
            multisig_seed_file,
            nominal: "N100".into(),
            token_type: "shell".into(),
            endpoint: "shellnet.ackinacki.org".into(),
            contracts: std::path::PathBuf::from("contracts/deployed.shellnet.json"),
            pool: std::path::PathBuf::from("pn_pool.json"),
            recovery: None,
            simulate_interrupt_after_spend_before_pool: false,
            simulate_interrupt_after_deposit_voucher_submit: false,
            simulate_interrupt_after_deposit_voucher_event: false,
            simulate_interrupt_after_shell_voucher_submit: false,
            simulate_interrupt_after_deploy_before_note_record: false,
        }
    }

    #[cfg(feature = "shellnet")]
    fn tvm_tonos_fixture_phrase() -> String {
        const WORD_INDICES: [u16; 12] = [
            1636, 1293, 905, 102, 1057, 1956, 1247, 1750, 597, 881, 1302, 3,
        ];
        WORD_INDICES
            .iter()
            .map(|i| bip39::Language::English.wordlist().get_word((*i).into()))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[cfg(feature = "shellnet")]
    fn pinned_tvm_sdk_default_key(phrase: &str) -> tvm_client::crypto::KeyPair {
        assert_eq!(
            tvm_client::crypto::default_hdkey_derivation_path(),
            dexdo::wallet_seed::TVM_DEFAULT_DERIVATION_PATH
        );
        let context = std::sync::Arc::new(
            tvm_client::ClientContext::new(tvm_client::ClientConfig::default()).unwrap(),
        );
        tvm_client::crypto::mnemonic_derive_sign_keys(
            context,
            tvm_client::crypto::ParamsOfMnemonicDeriveSignKeys {
                phrase: phrase.to_owned(),
                path: None,
                dictionary: None,
                word_count: None,
            },
        )
        .unwrap()
    }

    #[cfg(feature = "shellnet")]
    /// both established credential flags resolve to the same direct funding key.
    #[test]
    fn note_deploy_seed_file_matches_key_file_input() {
        let phrase = tvm_tonos_fixture_phrase();
        let expected_key = pinned_tvm_sdk_default_key(&phrase);
        let dir = std::env::temp_dir().join(format!(
            "dexdo-note-deploy-seed-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());
        let key_path = dir.join("wallet.secret.hex");
        let seed_path = dir.join("wallet.seed");
        std::fs::write(&key_path, &expected_key.secret).unwrap();
        std::fs::write(&seed_path, phrase).unwrap();

        let (key_source, key_secret) =
            super::note_deploy_multisig_secret_hex(&note_deploy_args(Some(key_path), None))
                .unwrap();
        let (seed_source, seed_secret) =
            super::note_deploy_multisig_secret_hex(&note_deploy_args(None, Some(seed_path)))
                .unwrap();

        assert_eq!(key_source, "--multisig-key");
        assert_eq!(seed_source, "--multisig-seed-file");
        assert!(
            key_secret == expected_key.secret,
            "key-file input does not match pinned TVM SDK default secret"
        );
        assert!(
            seed_secret == expected_key.secret,
            "seed-file input does not match pinned TVM SDK default secret"
        );
    }

    #[cfg(feature = "shellnet")]
    /// direct funding credential failures must not disclose seed input.
    #[test]
    fn note_deploy_seed_file_errors_do_not_echo_seed_input() {
        let dir = std::env::temp_dir().join(format!(
            "dexdo-note-deploy-invalid-seed-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());
        let key_path = dir.join("wallet.secret.hex");
        let seed_path = dir.join("wallet.seed");
        let invalid = std::iter::repeat_n("zzzz", 12)
            .collect::<Vec<_>>()
            .join(" ");
        std::fs::write(&key_path, "00").unwrap();
        std::fs::write(&seed_path, &invalid).unwrap();

        let err = super::note_deploy_multisig_secret_hex(&note_deploy_args(
            Some(key_path),
            Some(seed_path.clone()),
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("only one"), "{err}");

        let err = super::note_deploy_multisig_secret_hex(&note_deploy_args(None, Some(seed_path)))
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid seed phrase"), "{err}");
        assert!(!err.contains(&invalid), "{err}");

        let missing = dir.join("missing.seed");
        let err = super::note_deploy_multisig_secret_hex(&note_deploy_args(None, Some(missing)))
            .unwrap_err()
            .to_string();
        assert!(err.contains("read --multisig-seed-file"), "{err}");
    }

    #[test]
    fn buyer_renewal_monitor_uses_planner_and_recovery_actions() {
        let source = include_str!("buyer.rs");
        let start = source
            .find("fn spawn_buyer_service_renewal")
            .expect("renewal task present");
        let end = source[start..]
            .find("pub(crate) async fn run_buyer")
            .map(|offset| start + offset)
            .expect("renewal task end marker present");
        let body = &source[start..end];
        assert!(body.contains("BuyerContinuity"), "{body}");
        assert!(body.contains("planner.tick_with_mode"), "{body}");
        assert!(body.contains("continuity_mode"), "{body}");
        assert!(body.contains("has_active_or_recent_request"), "{body}");
        assert!(body.contains("CONSUMER_DEMAND_RECENT_SECS"), "{body}");
        assert!(body.contains("deal_state"), "{body}");
        assert!(body.contains("cleanup_unopened"), "{body}");
        assert!(body.contains("execute_buyer_monitor_recovery"), "{body}");
        assert!(body.contains("RENEWAL_FAILURE_BACKOFF_SECS"), "{body}");
        assert!(body.contains("prepare_retry"), "{body}");
        assert!(!body.contains("pending_for"), "{body}");
    }

    #[test]
    fn issue_547_recovery_monitor_is_model_only_and_starts_before_serve() {
        assert!(super::model_only_on_demand_recovery_enabled(
            false, false, false
        ));
        assert!(super::model_only_on_demand_recovery_enabled(
            true, false, false
        ));
        assert!(!super::model_only_on_demand_recovery_enabled(
            false, true, false
        ));
        assert!(!super::model_only_on_demand_recovery_enabled(
            false, false, true
        ));

        let source = include_str!("buyer.rs");
        let start = source
            .find("async fn run_buyer_on_demand_local_api")
            .unwrap();
        let end = source[start..]
            .find("async fn run_buyer_inner")
            .map(|offset| start + offset)
            .unwrap();
        let body = &source[start..end];
        assert!(
            body.find("spawn_buyer_service_renewal").unwrap() < body.find("api::serve").unwrap(),
            "model-only recovery monitor must start before the local API serves requests"
        );
    }

    #[derive(Clone, Copy)]
    enum ModelBuyFailure {
        Transport,
        Contract,
    }

    #[derive(Default)]
    struct RecordingRecoveryChain {
        cleanup_calls: std::sync::atomic::AtomicUsize,
        reclaim_calls: std::sync::atomic::AtomicUsize,
        dispute_calls: std::sync::atomic::AtomicUsize,
        release_calls: std::sync::atomic::AtomicUsize,
        stop_calls: std::sync::atomic::AtomicUsize,
        place_next_calls: std::sync::atomic::AtomicUsize,
        wait_match_calls: std::sync::atomic::AtomicUsize,
        deal_state: Option<dexdo_core::DealChainState>,
        snapshot: Option<dexdo_core::StreamSnapshot>,
        next_match: Option<dexdo_core::TokenContract>,
        model_buy_failure: Option<ModelBuyFailure>,
        stop_error: Option<String>,
        heartbeat_during_reclaim_preflight: std::sync::Mutex<Option<dexdo::buyer::api::ApiDeal>>,
        monitor_state_enabled: std::sync::atomic::AtomicBool,
        monitor_deal_state: std::sync::Mutex<Option<dexdo_core::DealChainState>>,
        monitor_deal_state_calls: std::sync::atomic::AtomicUsize,
        cleanup_failures_remaining: std::sync::atomic::AtomicUsize,
        reclaim_failures_remaining: std::sync::atomic::AtomicUsize,
        reclaim_transport_failures_remaining: std::sync::atomic::AtomicUsize,
        reclaim_ambiguous_remaining: std::sync::atomic::AtomicUsize,
        reclaim_ambiguous_stays_open: std::sync::atomic::AtomicBool,
        reclaim_delay_ms: std::sync::atomic::AtomicU64,
    }

    impl RecordingRecoveryChain {
        fn with_deal_state(state: dexdo_core::DealChainState) -> Self {
            Self {
                deal_state: Some(state),
                next_match: Some("tc-next".to_string()),
                ..Self::default()
            }
        }

        fn with_monitor_deal_state(state: dexdo_core::DealChainState) -> Self {
            Self {
                monitor_state_enabled: std::sync::atomic::AtomicBool::new(true),
                monitor_deal_state: std::sync::Mutex::new(Some(state)),
                next_match: Some("tc-fresh".to_string()),
                ..Self::default()
            }
        }

        fn consume_failure(counter: &std::sync::atomic::AtomicUsize) -> bool {
            counter
                .fetch_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |remaining| remaining.checked_sub(1),
                )
                .is_ok()
        }

        fn mark_monitor_reclaimed(&self) {
            if self
                .monitor_state_enabled
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                *self.monitor_deal_state.lock().unwrap() = Some(dexdo_core::DealChainState {
                    funded: false,
                    opened: false,
                    probe_accepted: true,
                    disputed: false,
                    deposit: 1_000,
                    finalized_owed: 0,
                    tokens_final: 0,
                    tokens_superseded: 0,
                    tokens_pending: 0,
                    funded_time: None,
                    probe_tick: 0,
                    probe_time: 0,
                    prev_claim_time: 0,
                    last_claim_time: super::unix_now_secs(),
                    dispute_time: 0,
                });
            }
        }

        fn set_monitor_deal_state(&self, state: dexdo_core::DealChainState) {
            *self.monitor_deal_state.lock().unwrap() = Some(state);
        }

        async fn wait_before_reclaim_result(&self) {
            let delay_ms = self
                .reclaim_delay_ms
                .load(std::sync::atomic::Ordering::SeqCst);
            if delay_ms != 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
        }
    }

    #[async_trait::async_trait]
    impl dexdo_core::ChainBackend for RecordingRecoveryChain {
        async fn stop_if_heartbeat(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _note: &dyn dexdo_core::Note,
            heartbeat: &dexdo_core::chain::HeartbeatGuard,
        ) -> Result<Option<dexdo_core::Settlement>, dexdo_core::ChainError> {
            // Simulate a legitimate claim landing between the decision to exit and the money POST.
            if let Some(deal) = self
                .heartbeat_during_reclaim_preflight
                .lock()
                .expect("preflight heartbeat lock")
                .take()
            {
                deal.record_accepted_output(super::unix_now_secs());
            }
            if !heartbeat.unchanged() {
                return Ok(None);
            }
            self.reclaim_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.wait_before_reclaim_result().await;
            if Self::consume_failure(&self.reclaim_ambiguous_remaining) {
                if !self
                    .reclaim_ambiguous_stays_open
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    self.mark_monitor_reclaimed();
                }
                return Err(dexdo_core::ChainError::AmbiguousSubmit(
                    "injected ambiguous reclaim result".to_string(),
                ));
            }
            if Self::consume_failure(&self.reclaim_failures_remaining) {
                return Err(dexdo_core::ChainError::Contract(
                    "injected early reclaim rejection".to_string(),
                ));
            }
            if Self::consume_failure(&self.reclaim_transport_failures_remaining) {
                return Err(dexdo_core::ChainError::Transport(
                    "injected transient reclaim transport failure".to_string(),
                ));
            }
            self.mark_monitor_reclaimed();
            Ok(Some(dexdo_core::Settlement::SellerNoShow {
                to_buyer_refund: 0,
                seller_bond_returned: 0,
            }))
        }

        async fn claim_tokens(
            &self,
            _: &dexdo_core::TokenContract,
            _: &dyn dexdo_core::Note,
            _: u128,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!()
        }

        async fn discover_offers(
            &self,
        ) -> Result<Vec<dexdo_core::OfferListing>, dexdo_core::ChainError> {
            unimplemented!("not needed by recovery monitor tests")
        }

        async fn post_offer(
            &self,
            _offer: dexdo_core::SellOffer,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!("not needed by recovery monitor tests")
        }

        async fn place_buy(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!("not needed by recovery monitor tests")
        }

        async fn read_match(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Result<dexdo_core::Match, dexdo_core::ChainError> {
            unimplemented!("not needed by recovery monitor tests")
        }

        async fn open_stream(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _enc_endpoint: Vec<u8>,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!("not needed by recovery monitor tests")
        }

        async fn read_handover(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<Vec<u8>>, dexdo_core::ChainError> {
            unimplemented!("not needed by recovery monitor tests")
        }

        async fn stop(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _note: &dyn dexdo_core::Note,
        ) -> Result<dexdo_core::Settlement, dexdo_core::ChainError> {
            self.stop_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(error) = &self.stop_error {
                return Err(dexdo_core::ChainError::Transport(error.clone()));
            }
            Ok(dexdo_core::Settlement::AmicableSplit {
                to_seller_ticks: 0,
                to_buyer_refund: 0,
            })
        }

        async fn dispute(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _note: &dyn dexdo_core::Note,
        ) -> Result<dexdo_core::Settlement, dexdo_core::ChainError> {
            self.dispute_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(dexdo_core::Settlement::AmicableSplit {
                to_seller_ticks: 0,
                to_buyer_refund: 0,
            })
        }

        async fn release_dispute(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Result<dexdo_core::Settlement, dexdo_core::ChainError> {
            self.release_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(dexdo_core::Settlement::AmicableSplit {
                to_seller_ticks: 0,
                to_buyer_refund: 0,
            })
        }

        async fn cleanup_unopened(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Result<dexdo_core::Settlement, dexdo_core::ChainError> {
            self.cleanup_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if Self::consume_failure(&self.cleanup_failures_remaining) {
                return Err(dexdo_core::ChainError::Contract(
                    "injected early cleanup rejection".to_string(),
                ));
            }
            if self
                .monitor_state_enabled
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                *self.monitor_deal_state.lock().unwrap() = None;
            }
            Ok(dexdo_core::Settlement::SellerNoShow {
                to_buyer_refund: 0,
                seller_bond_returned: 0,
            })
        }

        async fn place_buy_by_model(
            &self,
            _note: &dyn dexdo_core::Note,
            _ticks: u128,
            _max_price_per_tick: u128,
            _escrow: u128,
            _flags: u8,
            _deadline: u64,
        ) -> Result<(), dexdo_core::ChainError> {
            self.place_next_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match self.model_buy_failure {
                Some(ModelBuyFailure::Transport) => Err(dexdo_core::ChainError::Transport(
                    "model-only transport cause".to_string(),
                )),
                Some(ModelBuyFailure::Contract) => Err(dexdo_core::ChainError::Contract(
                    "model-only contract cause".to_string(),
                )),
                None => Ok(()),
            }
        }

        async fn wait_matched_token_contract(
            &self,
            _since_unix: i64,
            _timeout: std::time::Duration,
        ) -> Result<Option<dexdo_core::MatchedFill>, dexdo_core::ChainError> {
            self.wait_match_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Some(dexdo_core::MatchedFill {
                order_id: 1,
                token_contract: self
                    .next_match
                    .clone()
                    .unwrap_or_else(|| "tc-next".to_string()),
                ticks: 1,
                price_per_tick: 1,
            }))
        }

        async fn deal_state(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<dexdo_core::DealChainState>, dexdo_core::ChainError> {
            if self
                .monitor_state_enabled
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                self.monitor_deal_state_calls
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if token_contract == "tc-fresh" {
                    return Ok(Some(dexdo_core::DealChainState {
                        funded: true,
                        opened: true,
                        probe_accepted: true,
                        disputed: false,
                        deposit: 1_000,
                        finalized_owed: 0,
                        tokens_final: 0,
                        tokens_superseded: 0,
                        tokens_pending: 0,
                        funded_time: Some(1),
                        probe_tick: 0,
                        probe_time: 0,
                        prev_claim_time: 0,
                        last_claim_time: super::unix_now_secs(),
                        dispute_time: 0,
                    }));
                }
                return Ok(*self.monitor_deal_state.lock().unwrap());
            }
            Ok(self.deal_state)
        }

        async fn snapshot(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Option<dexdo_core::StreamSnapshot> {
            self.snapshot.clone()
        }
    }

    #[tokio::test]
    async fn subscription_shutdown_reports_incident_stop_dispute_and_preserve_truthfully() {
        async fn finish_shutdown(
            chain: std::sync::Arc<RecordingRecoveryChain>,
            lifetime: dexdo::buyer::api::SessionLifetimePolicy,
            action: Option<dexdo::buyer::api::VerificationBailAction>,
        ) -> (
            std::sync::Arc<dexdo::buyer::api::SessionSettle>,
            Option<bool>,
        ) {
            let note = std::sync::Arc::new(dexdo_core::LocalNote::generate());
            let session = std::sync::Arc::new(
                dexdo::buyer::api::SessionSettle::new_with_failure_policy_and_lifetime(
                    chain,
                    "tc-subscription".to_string(),
                    note.clone(),
                    dexdo::buyer::api::BuyerApiFailurePolicy {
                        verification_bail: action
                            .unwrap_or(dexdo::buyer::api::VerificationBailAction::Stop),
                        ..dexdo::buyer::api::BuyerApiFailurePolicy::default()
                    },
                    lifetime,
                ),
            );
            let incident_submitted = match action {
                Some(_) => Some(
                    session
                        .settle_verification_bail("injected-subscription-incident")
                        .await,
                ),
                None => None,
            };
            let state = dexdo::buyer::api::ApiState::single(
                std::sync::Arc::new(dexdo::buyer::Buyer::from_note(note)),
                dexdo::buyer::api::Route {
                    handover: dexdo_core::Handover {
                        endpoint: "https://127.0.0.1:1".to_string(),
                        tls_fingerprint: "00".repeat(32),
                    },
                    token_contract: "tc-subscription".to_string(),
                    max_tokens: 1,
                },
                "qwen--qwen3--32b".to_string(),
                session.clone(),
                std::sync::Arc::new(dexdo::buyer::api::ContentGate::skip()),
            );
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            let (_, task) = dexdo::buyer::api::serve(
                "127.0.0.1:0".parse().unwrap(),
                state,
                false,
                async move {
                    let _ = shutdown_rx.await;
                },
            )
            .await
            .unwrap();
            shutdown_tx.send(()).unwrap();
            task.await.unwrap();
            (session, incident_submitted)
        }

        fn assert_no_terminal_writes(chain: &RecordingRecoveryChain) {
            use std::sync::atomic::Ordering;

            assert_eq!(chain.stop_calls.load(Ordering::SeqCst), 0);
            assert_eq!(chain.dispute_calls.load(Ordering::SeqCst), 0);
            assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 0);
            assert_eq!(chain.cleanup_calls.load(Ordering::SeqCst), 0);
        }

        let stop_chain = std::sync::Arc::new(RecordingRecoveryChain::default());
        let (stop, stop_submitted) = finish_shutdown(
            stop_chain.clone(),
            dexdo::buyer::api::SessionLifetimePolicy::SettleOnExit,
            Some(dexdo::buyer::api::VerificationBailAction::Stop),
        )
        .await;
        assert_eq!(stop_submitted, Some(true));
        let stop_report = super::buyer_shutdown_report(Some(stop.as_ref()));
        assert_eq!(
            stop_report,
            super::BuyerShutdownReport::Settlement {
                action: "streamStop",
                state: "stopped",
                submitted: true,
                outcome: "settled",
            }
        );
        assert!(stop_report.chain_write_submitted());
        assert_eq!(
            stop_chain
                .stop_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        let dispute_chain = std::sync::Arc::new(RecordingRecoveryChain::default());
        let (dispute, dispute_submitted) = finish_shutdown(
            dispute_chain.clone(),
            dexdo::buyer::api::SessionLifetimePolicy::SettleOnExit,
            Some(dexdo::buyer::api::VerificationBailAction::Dispute),
        )
        .await;
        assert_eq!(dispute_submitted, Some(true));
        let dispute_report = super::buyer_shutdown_report(Some(dispute.as_ref()));
        assert_eq!(
            dispute_report,
            super::BuyerShutdownReport::Settlement {
                action: "streamDispute",
                state: "disputed",
                submitted: true,
                outcome: "disputed",
            }
        );
        assert!(dispute_report.chain_write_submitted());
        assert_eq!(
            dispute_chain
                .dispute_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        let preserved_stop_chain = std::sync::Arc::new(RecordingRecoveryChain::default());
        let (preserved_stop, stop_submitted) = finish_shutdown(
            preserved_stop_chain.clone(),
            dexdo::buyer::api::SessionLifetimePolicy::Preserve,
            Some(dexdo::buyer::api::VerificationBailAction::Stop),
        )
        .await;
        assert_eq!(stop_submitted, Some(false));
        assert_eq!(
            super::buyer_shutdown_report(Some(preserved_stop.as_ref())),
            super::BuyerShutdownReport::SubscriptionPreserved
        );
        assert_no_terminal_writes(preserved_stop_chain.as_ref());

        let preserved_dispute_chain = std::sync::Arc::new(RecordingRecoveryChain::default());
        let (preserved_dispute, dispute_submitted) = finish_shutdown(
            preserved_dispute_chain.clone(),
            dexdo::buyer::api::SessionLifetimePolicy::Preserve,
            Some(dexdo::buyer::api::VerificationBailAction::Dispute),
        )
        .await;
        assert_eq!(dispute_submitted, Some(false));
        assert_eq!(
            super::buyer_shutdown_report(Some(preserved_dispute.as_ref())),
            super::BuyerShutdownReport::SubscriptionPreserved
        );
        assert_no_terminal_writes(preserved_dispute_chain.as_ref());

        let preserve_chain = std::sync::Arc::new(RecordingRecoveryChain::default());
        let (preserved, incident_submitted) = finish_shutdown(
            preserve_chain.clone(),
            dexdo::buyer::api::SessionLifetimePolicy::Preserve,
            None,
        )
        .await;
        assert_eq!(incident_submitted, None);
        let preserve_report = super::buyer_shutdown_report(Some(preserved.as_ref()));
        assert_eq!(
            preserve_report,
            super::BuyerShutdownReport::SubscriptionPreserved
        );
        assert!(!preserve_report.chain_write_submitted());
        assert_no_terminal_writes(preserve_chain.as_ref());

        assert!(preserved.settle("explicit-user-stop").await.unwrap());
        assert_eq!(
            super::buyer_shutdown_report(Some(preserved.as_ref())),
            super::BuyerShutdownReport::Settlement {
                action: "streamStop",
                state: "stopped",
                submitted: true,
                outcome: "settled",
            }
        );
        assert_eq!(
            preserve_chain
                .stop_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    fn start_on_demand_recovery_runtime(
        chain: std::sync::Arc<RecordingRecoveryChain>,
        buyer: std::sync::Arc<dexdo::buyer::Buyer>,
        token_contract: &str,
        initial_handover: dexdo_core::Handover,
        fresh_handover: dexdo_core::Handover,
    ) -> (
        dexdo::buyer::api::ApiState,
        std::sync::Arc<dexdo::buyer::api::RouteManager>,
        std::sync::Arc<dexdo::buyer::api::SessionSettle>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let note = buyer.note.clone();
        let policy = dexdo::buyer::api::BuyerApiFailurePolicy {
            dead_gateway: dexdo::buyer::api::DeadGatewayAction::RetryThenReclaim,
            ..dexdo::buyer::api::BuyerApiFailurePolicy::default()
        };
        let session =
            std::sync::Arc::new(dexdo::buyer::api::SessionSettle::new_with_failure_policy(
                chain.clone(),
                token_contract.to_string(),
                note.clone(),
                policy,
            ));
        let active = dexdo::buyer::api::ApiDeal::new(
            dexdo::buyer::api::Route {
                handover: initial_handover,
                token_contract: token_contract.to_string(),
                max_tokens: 100,
            },
            session.clone(),
            std::sync::Arc::new(dexdo::buyer::api::ContentGate::skip()),
        );
        let init_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let init_calls_for_initializer = init_calls.clone();
        let chain_for_initializer = chain.clone();
        let note_for_initializer = note.clone();
        let routes = std::sync::Arc::new(
            dexdo::buyer::api::RouteManager::recoverable_lazy_with_active(
                active,
                std::sync::Arc::new(move || {
                    let init_calls = init_calls_for_initializer.clone();
                    let chain = chain_for_initializer.clone();
                    let note = note_for_initializer.clone();
                    let fresh_handover = fresh_handover.clone();
                    Box::pin(async move {
                        init_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        dexdo_core::ChainBackend::place_buy_by_model(
                            chain.as_ref(),
                            note.as_ref(),
                            2,
                            1,
                            2,
                            0,
                            9_999_999,
                        )
                        .await
                        .map_err(|error| {
                            dexdo::buyer::api::DealInitError::new(error.to_string())
                        })?;
                        let session = std::sync::Arc::new(
                            dexdo::buyer::api::SessionSettle::new_with_failure_policy(
                                chain.clone(),
                                "tc-fresh".to_string(),
                                note,
                                policy,
                            ),
                        );
                        Ok(dexdo::buyer::api::ApiDeal::new(
                            dexdo::buyer::api::Route {
                                handover: fresh_handover,
                                token_contract: "tc-fresh".to_string(),
                                max_tokens: 100,
                            },
                            session,
                            std::sync::Arc::new(dexdo::buyer::api::ContentGate::skip()),
                        ))
                    }) as dexdo::buyer::api::DealInitFuture
                }),
                std::time::Duration::from_secs(1),
            ),
        );
        let state = dexdo::buyer::api::ApiState {
            buyer: buyer.clone(),
            frame_model: "qwen--qwen3--32b".to_string(),
            deals: routes.clone(),
        };
        super::spawn_buyer_service_renewal(
            chain,
            buyer,
            routes.clone(),
            None,
            2,
            1,
            2,
            dexdo::buyer::continuity::ContinuityMode::OnDemand,
            dexdo::buyer::api::ContentCheck::Skip,
            std::sync::Arc::new(dexdo::seller::ModelsConfig::empty()),
            policy,
        );
        (state, routes, session, init_calls)
    }

    fn start_on_demand_recovery_monitor(
        chain: std::sync::Arc<RecordingRecoveryChain>,
        token_contract: &str,
    ) -> (
        std::sync::Arc<dexdo::buyer::api::RouteManager>,
        std::sync::Arc<dexdo::buyer::api::SessionSettle>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let buyer = std::sync::Arc::new(dexdo::buyer::Buyer::generate());
        let (_state, routes, session, init_calls) = start_on_demand_recovery_runtime(
            chain,
            buyer,
            token_contract,
            dexdo_core::Handover {
                endpoint: "https://127.0.0.1:1".to_string(),
                tls_fingerprint: "00".repeat(32),
            },
            dexdo_core::Handover {
                endpoint: "https://127.0.0.1:2".to_string(),
                tls_fingerprint: "11".repeat(32),
            },
        );
        (routes, session, init_calls)
    }

    async fn wait_for_counter(
        counter: &std::sync::atomic::AtomicUsize,
        expected: usize,
        label: &str,
    ) {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while counter.load(std::sync::atomic::Ordering::SeqCst) < expected {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {label}={expected}"));
    }

    #[cfg(feature = "shellnet")]
    #[derive(Clone, Copy)]
    enum Issue547ProviderBehavior {
        HangWithoutOutput,
        FailAfterTwoRequests,
    }

    #[cfg(feature = "shellnet")]
    #[derive(Clone)]
    struct Issue547ProviderState {
        behavior: Issue547ProviderBehavior,
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        failure_barrier: std::sync::Arc<tokio::sync::Barrier>,
    }

    #[cfg(feature = "shellnet")]
    async fn issue_547_provider_response(
        axum::extract::State(state): axum::extract::State<Issue547ProviderState>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;

        state
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match state.behavior {
            Issue547ProviderBehavior::HangWithoutOutput => {
                std::future::pending::<axum::response::Response>().await
            }
            Issue547ProviderBehavior::FailAfterTwoRequests => {
                state.failure_barrier.wait().await;
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "injected provider failure",
                )
                    .into_response()
            }
        }
    }

    #[cfg(feature = "shellnet")]
    async fn start_issue_547_provider(
        behavior: Issue547ProviderBehavior,
    ) -> (
        std::net::SocketAddr,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let state = Issue547ProviderState {
            behavior,
            calls: calls.clone(),
            failure_barrier: std::sync::Arc::new(tokio::sync::Barrier::new(2)),
        };
        let app = axum::Router::new()
            .fallback(axum::routing::any(issue_547_provider_response))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind  provider");
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (addr, calls, task)
    }

    #[cfg(feature = "shellnet")]
    async fn start_issue_547_gateway(
        upstream: dexdo::seller::UpstreamConfig,
        buyer: &dexdo::buyer::Buyer,
        token_contract: &str,
    ) -> (dexdo::seller::RunningSeller, dexdo_core::Handover) {
        // shape B: the gateway makes the ONE bind. Reserving a port here and releasing it
        // before `start_gateway_with` re-binds hands it back to the kernel, and any concurrent
        // `bind(0)` can be given that exact port in between.
        let seller = dexdo::seller::start_gateway_with("127.0.0.1:0".parse().unwrap(), upstream)
            .await
            .expect("start  TLS gateway");
        let addr = seller.listen_addr;
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if tokio::net::TcpStream::connect(addr).await.is_ok() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect(" TLS gateway binds");
        let (state, deal) = ordinary_gateway_snapshot(2);
        seller
            .state
            .register_stream(token_contract, buyer.note.pubkey(), 8, state, deal)
            .expect("register strict ordinary test capacity");
        let handover = dexdo_core::Handover {
            endpoint: format!("https://{addr}"),
            tls_fingerprint: seller.tls_fingerprint.clone(),
        };
        (seller, handover)
    }

    #[cfg(feature = "shellnet")]
    async fn issue_547_http_request(
        client: reqwest::Client,
        api_addr: std::net::SocketAddr,
        anthropic: bool,
        prompt: &'static str,
    ) -> reqwest::Response {
        let (path, body) = if anthropic {
            (
                "/v1/messages",
                serde_json::json!({
                    "model": "qwen--qwen3--32b",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1,
                    "stream": false
                }),
            )
        } else {
            (
                "/v1/chat/completions",
                serde_json::json!({
                    "model": "qwen--qwen3--32b",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1,
                    "stream": false
                }),
            )
        };
        client
            .post(format!("http://{api_addr}{path}"))
            .json(&body)
            .send()
            .await
            .unwrap_or_else(|error| panic!("{path} request failed: {error}"))
    }

    #[cfg(feature = "shellnet")]
    async fn wait_for_issue_547_terminal(session: &dexdo::buyer::api::SessionSettle) {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !session.is_settled() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect(" recovery becomes terminal");
    }

    #[tokio::test]
    async fn issue_547_healthy_paused_on_demand_session_is_not_reclaimed() {
        use std::sync::atomic::Ordering;

        let now = super::unix_now_secs();
        let chain = std::sync::Arc::new(RecordingRecoveryChain::with_monitor_deal_state(
            dexdo_core::DealChainState {
                funded: true,
                opened: true,
                probe_accepted: true,
                disputed: false,
                deposit: 1_000,
                finalized_owed: 0,
                tokens_final: 0,
                tokens_superseded: 0,
                tokens_pending: 0,
                funded_time: Some(1),
                probe_tick: 0,
                probe_time: 0,
                prev_claim_time: 0,
                last_claim_time: now.saturating_sub(10),
                dispute_time: 0,
            },
        ));
        let (_routes, session, init_calls) =
            start_on_demand_recovery_monitor(chain.clone(), "tc-healthy-paused");

        tokio::time::sleep(std::time::Duration::from_millis(75)).await;
        assert!(!session.is_closed());
        assert!(!session.is_settled());
        assert_eq!(
            chain.cleanup_calls.load(Ordering::SeqCst),
            0,
            "healthy on-demand session must not be cleaned up between requests"
        );
        assert_eq!(
            chain.reclaim_calls.load(Ordering::SeqCst),
            0,
            "healthy on-demand session past the old idle threshold must not be STOPped between requests"
        );
        assert_eq!(init_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.place_next_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn issue_547_failed_policy_stop_is_not_retried_from_idle_or_replaced() {
        use std::sync::atomic::Ordering;

        let now = super::unix_now_secs();
        let chain = std::sync::Arc::new(RecordingRecoveryChain::with_monitor_deal_state(
            dexdo_core::DealChainState {
                funded: true,
                opened: true,
                probe_accepted: true,
                disputed: false,
                deposit: 1_000,
                finalized_owed: 0,
                tokens_final: 0,
                tokens_superseded: 0,
                tokens_pending: 0,
                funded_time: Some(1),
                probe_tick: 0,
                probe_time: 0,
                prev_claim_time: 0,
                last_claim_time: now.saturating_sub(10),
                dispute_time: 0,
            },
        ));
        chain.reclaim_failures_remaining.store(1, Ordering::SeqCst);
        let (routes, session, init_calls) =
            start_on_demand_recovery_monitor(chain.clone(), "tc-dead");

        let heartbeat = dexdo_core::chain::HeartbeatGuard::new(std::sync::Arc::new(
            std::sync::atomic::AtomicU64::new(0),
        ));
        assert!(
            !session
                .settle_dead_gateway("dead-gateway", &heartbeat)
                .await
        );
        assert!(session.is_closed());
        assert!(!session.is_settled());
        assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 1);

        wait_for_counter(
            &chain.monitor_deal_state_calls,
            1,
            "policy reconciliation reads",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            chain.reclaim_calls.load(Ordering::SeqCst),
            1,
            "fresh OPEN facts and idle time must not turn a failed policy attempt into another POST"
        );
        assert!(
            chain.monitor_deal_state_calls.load(Ordering::SeqCst) >= 1,
            "the failed policy result must still be reconciled from authoritative fresh facts"
        );
        assert!(session.is_closed());
        assert!(!session.is_settled());
        assert_eq!(
            chain.place_next_calls.load(Ordering::SeqCst),
            0,
            "a closed but nonterminal session must not create a replacement BUY"
        );
        assert_eq!(
            routes.current().await.unwrap().route.token_contract,
            "tc-dead"
        );
        assert_eq!(init_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn issue_547_cleanup_clears_stale_latch_and_retries() {
        use std::sync::atomic::Ordering;

        let funded_time = 1;
        let never_opened_state = dexdo_core::DealChainState {
            funded: true,
            opened: false,
            probe_accepted: false,
            disputed: false,
            deposit: 1_000,
            finalized_owed: 0,
            tokens_final: 0,
            tokens_superseded: 0,
            tokens_pending: 0,
            funded_time: Some(funded_time),
            probe_tick: 0,
            probe_time: 0,
            prev_claim_time: funded_time,
            last_claim_time: funded_time,
            dispute_time: 0,
        };
        assert_eq!(
            (
                never_opened_state.probe_accepted,
                never_opened_state.funded_time,
                never_opened_state.prev_claim_time,
                never_opened_state.last_claim_time,
            ),
            (false, Some(funded_time), funded_time, funded_time),
            "cleanup retry must start from a canonical 4.0.32 funded-never-opened state"
        );
        let mut chain = RecordingRecoveryChain::with_monitor_deal_state(never_opened_state);
        chain.stop_error = Some("injected failed-request STOP".to_string());
        let chain = std::sync::Arc::new(chain);
        chain.cleanup_failures_remaining.store(1, Ordering::SeqCst);
        let (_routes, session, init_calls) =
            start_on_demand_recovery_monitor(chain.clone(), "tc-unopened");

        session
            .settle("failed-request")
            .await
            .expect_err("failed request must leave the local session closed and recoverable");
        assert!(session.is_closed());
        assert!(!session.is_settled());

        wait_for_counter(&chain.cleanup_calls, 1, "cleanup attempts").await;
        assert!(!session.is_settled());
        assert_eq!(chain.place_next_calls.load(Ordering::SeqCst), 0);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            chain.cleanup_calls.load(Ordering::SeqCst),
            1,
            "monitor ticks inside cleanup backoff must not POST"
        );

        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !session.is_settled() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cleanup retry becomes terminal");
        assert_eq!(chain.cleanup_calls.load(Ordering::SeqCst), 2);
        assert!(
            chain.monitor_deal_state_calls.load(Ordering::SeqCst) >= 2,
            "cleanup retry must use fresh chain state"
        );
        assert!(!session.mark_recovered("duplicate-terminal"));
        assert_eq!(init_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.place_next_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn issue_547_ambiguous_reclaim_is_confirmed_without_duplicate_post() {
        use std::sync::atomic::Ordering;

        let now = super::unix_now_secs();
        let chain = std::sync::Arc::new(RecordingRecoveryChain::with_monitor_deal_state(
            dexdo_core::DealChainState {
                funded: true,
                opened: true,
                probe_accepted: true,
                disputed: false,
                deposit: 1_000,
                finalized_owed: 0,
                tokens_final: 0,
                tokens_superseded: 0,
                tokens_pending: 0,
                funded_time: Some(1),
                probe_tick: 0,
                probe_time: 0,
                prev_claim_time: 0,
                last_claim_time: now.saturating_sub(10),
                dispute_time: 0,
            },
        ));
        chain.reclaim_ambiguous_remaining.store(1, Ordering::SeqCst);
        let (_routes, session, init_calls) =
            start_on_demand_recovery_monitor(chain.clone(), "tc-ambiguous");

        let heartbeat = dexdo_core::chain::HeartbeatGuard::new(std::sync::Arc::new(
            std::sync::atomic::AtomicU64::new(0),
        ));
        assert!(
            !session
                .settle_dead_gateway("dead-gateway", &heartbeat)
                .await
        );
        assert!(session.is_closed());
        assert!(!session.is_settled());
        assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 1);

        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !session.is_settled() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("fresh state confirms ambiguous reclaim");
        assert_eq!(
            chain.reclaim_calls.load(Ordering::SeqCst),
            1,
            "terminal by-fact confirmation must not duplicate reclaim"
        );
        assert_eq!(init_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.place_next_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn ambiguous_reclaim_still_open_across_monitor_ticks_never_reposts() {
        use std::sync::atomic::Ordering;

        let now = super::unix_now_secs();
        let opened = dexdo_core::DealChainState {
            funded: true,
            opened: true,
            probe_accepted: true,
            disputed: false,
            deposit: 1_000,
            finalized_owed: 0,
            tokens_final: 0,
            tokens_superseded: 0,
            tokens_pending: 0,
            funded_time: Some(1),
            probe_tick: 0,
            probe_time: 0,
            prev_claim_time: 0,
            last_claim_time: now.saturating_sub(10),
            dispute_time: 0,
        };
        let chain = std::sync::Arc::new(RecordingRecoveryChain::with_monitor_deal_state(opened));
        chain.reclaim_ambiguous_remaining.store(1, Ordering::SeqCst);
        chain
            .reclaim_ambiguous_stays_open
            .store(true, Ordering::SeqCst);
        let (_routes, session, init_calls) =
            start_on_demand_recovery_monitor(chain.clone(), "tc-ambiguous-open");
        let heartbeat = dexdo_core::chain::HeartbeatGuard::new(std::sync::Arc::new(
            std::sync::atomic::AtomicU64::new(0),
        ));

        assert!(
            !session
                .settle_dead_gateway("dead-gateway", &heartbeat)
                .await
        );
        assert!(
            session.recovery_submit_may_have_landed(dexdo::buyer::api::RecoveryKind::ReclaimOpened)
        );
        wait_for_counter(
            &chain.monitor_deal_state_calls,
            2,
            "possibly-landed fresh-state reads",
        )
        .await;
        assert_eq!(
            chain.reclaim_calls.load(Ordering::SeqCst),
            1,
            "fresh still-open facts may remain pending but must never authorize a second STOP"
        );
        assert!(!session.is_settled());

        let mut terminal = opened;
        terminal.funded = false;
        terminal.opened = false;
        terminal.deposit = 0;
        terminal.funded_time = None;
        chain.set_monitor_deal_state(terminal);
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !session.is_settled() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("fresh terminal fact closes possibly-landed recovery");
        assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 1);
        assert_eq!(init_calls.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn issue_547_silent_openai_and_anthropic_requests_do_not_auto_stop_or_replace() {
        use std::sync::atomic::Ordering;

        const KEY_ENV: &str = "DEXDO_ISSUE_547_SILENT_PROVIDER_KEY";
        let _key = EnvVarGuard::set(KEY_ENV, std::ffi::OsStr::new("test-only"));
        let (provider_addr, provider_calls, provider_task) =
            start_issue_547_provider(Issue547ProviderBehavior::HangWithoutOutput).await;
        let upstream = dexdo::seller::OpenAiConfig {
            base_url: format!("http://{provider_addr}/v1"),
            frame_model: "qwen--qwen3--32b".to_string(),
            api_key_env: KEY_ENV.to_string(),
            ..Default::default()
        };

        let buyer = std::sync::Arc::new(dexdo::buyer::Buyer::generate());
        let (dead_seller, dead_handover) = start_issue_547_gateway(
            dexdo::seller::UpstreamConfig::OpenAi(upstream),
            buyer.as_ref(),
            "tc-silent",
        )
        .await;
        let (fresh_seller, fresh_handover) = start_issue_547_gateway(
            dexdo::seller::UpstreamConfig::Mock,
            buyer.as_ref(),
            "tc-fresh",
        )
        .await;

        let now = super::unix_now_secs();
        let chain = std::sync::Arc::new(RecordingRecoveryChain::with_monitor_deal_state(
            dexdo_core::DealChainState {
                funded: true,
                opened: true,
                probe_accepted: true,
                disputed: false,
                deposit: 1_000,
                finalized_owed: 0,
                tokens_final: 0,
                tokens_superseded: 0,
                tokens_pending: 0,
                funded_time: Some(1),
                probe_tick: 0,
                probe_time: 0,
                prev_claim_time: 0,
                last_claim_time: now,
                dispute_time: 0,
            },
        ));
        let (state, _routes, session, init_calls) = start_on_demand_recovery_runtime(
            chain.clone(),
            buyer,
            "tc-silent",
            dead_handover,
            fresh_handover,
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (api_addr, api_task) =
            dexdo::buyer::api::serve("127.0.0.1:0".parse().unwrap(), state, true, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("bind  OpenAI/Anthropic API");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(4))
            .build()
            .unwrap();

        let openai = tokio::spawn(issue_547_http_request(
            client.clone(),
            api_addr,
            false,
            "silent OpenAI request",
        ));
        let anthropic = tokio::spawn(issue_547_http_request(
            client.clone(),
            api_addr,
            true,
            "silent Anthropic request",
        ));
        wait_for_counter(&provider_calls, 2, "silent provider requests").await;
        chain.set_monitor_deal_state(dexdo_core::DealChainState {
            funded: true,
            opened: true,
            probe_accepted: true,
            disputed: false,
            deposit: 1_000,
            finalized_owed: 0,
            tokens_final: 0,
            tokens_superseded: 0,
            tokens_pending: 0,
            funded_time: Some(1),
            probe_tick: 0,
            probe_time: 0,
            prev_claim_time: 0,
            last_claim_time: now.saturating_sub(10),
            dispute_time: 0,
        });

        let reads_before_idle = chain.monitor_deal_state_calls.load(Ordering::SeqCst);
        wait_for_counter(
            &chain.monitor_deal_state_calls,
            reads_before_idle + 3,
            "silent-provider idle reconciliation reads",
        )
        .await;
        assert!(
            !openai.is_finished() && !anthropic.is_finished(),
            "provider silence alone must leave both in-flight requests pending"
        );
        assert!(!session.is_closed());
        assert!(!session.is_settled());
        assert_eq!(
            chain.reclaim_calls.load(Ordering::SeqCst),
            0,
            "provider silence and an old claim timestamp must not trigger automatic STOP"
        );
        assert_eq!(
            chain.stop_calls.load(Ordering::SeqCst),
            0,
            "provider silence must not enter the explicit STOP path"
        );
        assert_eq!(
            init_calls.load(Ordering::SeqCst),
            0,
            "silent in-flight requests must not initialize a replacement deal"
        );
        assert_eq!(chain.place_next_calls.load(Ordering::SeqCst), 0);

        openai.abort();
        anthropic.abort();
        dead_seller.server_task.abort();
        provider_task.abort();
        let _ = shutdown_tx.send(());
        api_task.await.expect(" API joins");
        fresh_seller.server_task.abort();
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn issue_547_handler_ambiguity_is_fact_confirmed_for_concurrent_http_requests() {
        use std::sync::atomic::Ordering;

        assert!(
            super::model_only_on_demand_recovery_enabled(true, false, false),
            "model-only mock-chain runtime must retain recovery and lazy route replacement"
        );
        const KEY_ENV: &str = "DEXDO_ISSUE_547_AMBIGUOUS_PROVIDER_KEY";
        let _key = EnvVarGuard::set(KEY_ENV, std::ffi::OsStr::new("test-only"));
        let (provider_addr, provider_calls, provider_task) =
            start_issue_547_provider(Issue547ProviderBehavior::FailAfterTwoRequests).await;
        let upstream = dexdo::seller::OpenAiConfig {
            base_url: format!("http://{provider_addr}/v1"),
            frame_model: "qwen--qwen3--32b".to_string(),
            api_key_env: KEY_ENV.to_string(),
            ..Default::default()
        };

        let buyer = std::sync::Arc::new(dexdo::buyer::Buyer::generate());
        let (dead_seller, dead_handover) = start_issue_547_gateway(
            dexdo::seller::UpstreamConfig::OpenAi(upstream),
            buyer.as_ref(),
            "tc-handler-ambiguous",
        )
        .await;
        let (fresh_seller, fresh_handover) = start_issue_547_gateway(
            dexdo::seller::UpstreamConfig::Mock,
            buyer.as_ref(),
            "tc-fresh",
        )
        .await;

        let now = super::unix_now_secs();
        let chain = std::sync::Arc::new(RecordingRecoveryChain::with_monitor_deal_state(
            dexdo_core::DealChainState {
                funded: true,
                opened: true,
                probe_accepted: true,
                disputed: false,
                deposit: 1_000,
                finalized_owed: 0,
                tokens_final: 0,
                tokens_superseded: 0,
                tokens_pending: 0,
                funded_time: Some(1),
                probe_tick: 0,
                probe_time: 0,
                prev_claim_time: 0,
                last_claim_time: now,
                dispute_time: 0,
            },
        ));
        chain.reclaim_ambiguous_remaining.store(1, Ordering::SeqCst);
        chain.reclaim_delay_ms.store(100, Ordering::SeqCst);
        let (state, _routes, session, init_calls) = start_on_demand_recovery_runtime(
            chain.clone(),
            buyer,
            "tc-handler-ambiguous",
            dead_handover,
            fresh_handover,
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (api_addr, api_task) =
            dexdo::buyer::api::serve("127.0.0.1:0".parse().unwrap(), state, true, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("bind  ambiguous HTTP API");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(4))
            .build()
            .unwrap();

        let openai = tokio::spawn(issue_547_http_request(
            client.clone(),
            api_addr,
            false,
            "ambiguous OpenAI request",
        ));
        let anthropic = tokio::spawn(issue_547_http_request(
            client.clone(),
            api_addr,
            true,
            "ambiguous Anthropic request",
        ));
        wait_for_counter(&provider_calls, 2, "ambiguous provider requests").await;
        wait_for_counter(&chain.reclaim_calls, 1, "handler reclaim attempt").await;
        chain.set_monitor_deal_state(dexdo_core::DealChainState {
            funded: true,
            opened: true,
            probe_accepted: true,
            disputed: false,
            deposit: 1_000,
            finalized_owed: 0,
            tokens_final: 0,
            tokens_superseded: 0,
            tokens_pending: 0,
            funded_time: Some(1),
            probe_tick: 0,
            probe_time: 0,
            prev_claim_time: 0,
            last_claim_time: now.saturating_sub(10),
            dispute_time: 0,
        });
        let openai = openai.await.unwrap();
        let anthropic = anthropic.await.unwrap();
        assert_eq!(openai.status(), reqwest::StatusCode::BAD_GATEWAY);
        assert_eq!(anthropic.status(), reqwest::StatusCode::BAD_GATEWAY);
        wait_for_issue_547_terminal(session.as_ref()).await;
        assert!(session.is_closed());
        assert_eq!(
            chain.reclaim_calls.load(Ordering::SeqCst),
            1,
            "the recovery episode must latch before the first ambiguous POST awaits"
        );
        assert_eq!(
            chain.cleanup_calls.load(Ordering::SeqCst),
            0,
            "terminal reclaim facts must not be reclassified as unopened cleanup"
        );
        assert!(
            chain.monitor_deal_state_calls.load(Ordering::SeqCst) >= 1,
            "handler ambiguity must reach the monitor's authoritative fact read"
        );
        assert_eq!(init_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.place_next_calls.load(Ordering::SeqCst), 0);

        dead_seller.server_task.abort();
        provider_task.abort();
        let next_openai = tokio::spawn(issue_547_http_request(
            client.clone(),
            api_addr,
            false,
            "replacement OpenAI request",
        ));
        let next_anthropic = tokio::spawn(issue_547_http_request(
            client,
            api_addr,
            true,
            "replacement Anthropic request",
        ));
        assert_eq!(next_openai.await.unwrap().status(), reqwest::StatusCode::OK);
        assert_eq!(
            next_anthropic.await.unwrap().status(),
            reqwest::StatusCode::OK
        );
        assert_eq!(init_calls.load(Ordering::SeqCst), 1);
        assert_eq!(chain.place_next_calls.load(Ordering::SeqCst), 1);

        let _ = shutdown_tx.send(());
        api_task.await.expect(" API joins");
        fresh_seller.server_task.abort();
    }

    #[test]
    fn buyer_fill_caller_rejects_wrong_tc_ticks_and_price() {
        let expected = dexdo_core::QuoteFill {
            order_id: 7,
            token_contract: "tc-intended".to_string(),
            ticks: 2,
            price_per_tick: 700,
            cost_with_fee: 0,
        };
        for fill in [
            dexdo_core::MatchedFill {
                order_id: 7,
                token_contract: "tc-wrong".to_string(),
                ticks: 2,
                price_per_tick: 700,
            },
            dexdo_core::MatchedFill {
                order_id: 7,
                token_contract: "tc-intended".to_string(),
                ticks: 3,
                price_per_tick: 700,
            },
            dexdo_core::MatchedFill {
                order_id: 7,
                token_contract: "tc-intended".to_string(),
                ticks: 2,
                price_per_tick: 701,
            },
        ] {
            let error = super::correlated_buy_token_contract(fill, Some(&expected), 2, 900)
                .expect_err("wrong fill terms must fail closed at the caller");
            assert!(error
                .to_string()
                .contains("refusing wrong-fill attribution"));
        }
    }

    #[tokio::test]
    async fn one_shot_completion_propagates_stop_failure() {
        use std::sync::atomic::Ordering;

        let chain = std::sync::Arc::new(RecordingRecoveryChain {
            stop_error: Some("injected one-shot STOP failure".to_string()),
            ..Default::default()
        });
        let session = dexdo::buyer::api::SessionSettle::new(
            chain.clone(),
            "tc-one-shot".to_string(),
            std::sync::Arc::new(dexdo_core::LocalNote::generate()),
        );

        let error = super::settle_completed_oneshot(&session)
            .await
            .expect_err("one-shot success must not hide a failed STOP");

        assert!(
            error.to_string().contains("one-shot STOP failure"),
            "{error:#}"
        );
        assert!(!session.is_settled());
        assert_eq!(chain.stop_calls.load(Ordering::SeqCst), 1);

        drop(session);
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert_eq!(
            chain.stop_calls.load(Ordering::SeqCst),
            1,
            "one-shot awaited STOP failure must not trigger a detached retry"
        );
    }

    fn err_not_open() -> dexdo_core::ChainError {
        dexdo_core::ChainError::Contract(
            "block manager rejected message code=TVM_ERROR; exit_code=320 \
             (airegistry::ERR_NOT_OPEN) stage=data"
                .to_string(),
        )
    }

    #[test]
    fn err_not_open_recognizes_production_contract_and_legacy_chain_shapes() {
        assert!(super::is_err_not_open(&err_not_open()));
        assert!(super::is_err_not_open(&dexdo_core::ChainError::Chain(
            "exit_code=320 (airegistry::ERR_NOT_OPEN)".to_string()
        )));
        assert!(!super::is_err_not_open(&dexdo_core::ChainError::Transport(
            "exit_code=320".to_string()
        )));
        for message in [
            "exit_code=320.",
            "exit_code=320: stage",
            "exit_code=320!",
            "exit_code=320(x)",
        ] {
            assert!(
                super::is_err_not_open(&dexdo_core::ChainError::Contract(message.to_string())),
                "must classify {message:?} as exact ERR_NOT_OPEN"
            );
        }
        for message in [
            "exit_code=3200",
            "exit_code=3201",
            "exit_code=32",
            "exit_code=320suffix",
            "exit_code=320.5",
            "exit_code=320:5",
            "airegistry::ERR_NOT_OPENED",
            "xairegistry::ERR_NOT_OPEN",
            "exit_code=3200 (airegistry::ERR_NOT_OPEN)",
            "exit_code=321; previous exit_code=320",
            "exit_code=320; code=321; airegistry::ERR_NOT_OPEN",
            "exit_code=320; code=320; airegistry::ERR_NOT_OPEN",
            "code=321; airegistry::ERR_NOT_OPEN",
            "exit code 321; airegistry::ERR_NOT_OPEN",
            "action_result_code=321; airegistry::ERR_NOT_OPEN",
            "exit_code=320; result_code=321; airegistry::ERR_NOT_OPEN",
            "exit_code=320; resultCode=321; airegistry::ERR_NOT_OPEN",
            "exit_code=320; actionResultCode=321; airegistry::ERR_NOT_OPEN",
        ] {
            assert!(
                !super::is_err_not_open(&dexdo_core::ChainError::Contract(message.to_string())),
                "must not classify {message:?} as exact ERR_NOT_OPEN"
            );
        }
        assert!(super::is_err_not_open(&dexdo_core::ChainError::Contract(
            "airegistry::ERR_NOT_OPEN".to_string()
        )));
        assert!(super::is_err_not_open(&dexdo_core::ChainError::Contract(
            "exit_code=320; previous exit_code=320".to_string()
        )));
        assert!(super::is_err_not_open(&dexdo_core::ChainError::Contract(
            "exitCode=320; result_code=0; airegistry::ERR_NOT_OPEN".to_string()
        )));
    }

    fn deal_state(
        funded: bool,
        opened: bool,
        disputed: bool,
        probe_accepted: bool,
    ) -> dexdo_core::DealChainState {
        let funded_time = 100;
        let canonical_never_opened = funded && !opened && !disputed && !probe_accepted;
        dexdo_core::DealChainState {
            funded,
            opened,
            probe_accepted,
            disputed,
            deposit: if probe_accepted { 0 } else { 1_000 },
            finalized_owed: 0,
            tokens_final: 0,
            tokens_superseded: 0,
            tokens_pending: 0,
            funded_time: Some(funded_time),
            probe_tick: 0,
            probe_time: 0,
            prev_claim_time: if canonical_never_opened {
                funded_time
            } else {
                0
            },
            last_claim_time: if canonical_never_opened {
                funded_time
            } else {
                0
            },
            dispute_time: 0,
        }
    }

    #[test]
    fn deal_state_fixture_preserves_probe_and_never_opened_anchors() {
        let never_opened = deal_state(true, false, false, false);
        assert_eq!(
            (
                never_opened.probe_accepted,
                never_opened.funded_time,
                never_opened.prev_claim_time,
                never_opened.last_claim_time,
            ),
            (false, Some(100), 100, 100),
            "funded-never-opened fixture must match the canonical 4.0.32 shape"
        );
        assert!(
            deal_state(true, true, false, true).probe_accepted,
            "the helper must preserve an accepted-probe fixture"
        );
    }

    fn stream_snapshot(
        buyer_locked: u64,
        buyer_lead: u64,
        seller_locked: u64,
        seller_received: u64,
        burned: u64,
    ) -> dexdo_core::StreamSnapshot {
        dexdo_core::StreamSnapshot {
            seller_locked: u128::from(seller_locked),
            buyer_locked: u128::from(buyer_locked),
            buyer_lead: u128::from(buyer_lead),
            tokens_final: 0,
            seller_received: u128::from(seller_received),
            buyer_refunded: 0,
            burned: u128::from(burned),
            closed: false,
        }
    }

    #[tokio::test]
    async fn post_reject_err_not_open_never_opened_no_money_is_terminal() {
        let chain = RecordingRecoveryChain {
            deal_state: Some(deal_state(true, false, false, false)),
            snapshot: Some(stream_snapshot(0, 0, 0, 0, 0)),
            ..Default::default()
        };

        let disposition = super::classify_by_fact_advance_failure(
            &chain,
            &"tc-safe".to_string(),
            &err_not_open(),
        )
        .await
        .expect("classification reads by-fact state");

        match disposition {
            super::AdvanceFailureDisposition::BenignTerminal { reason } => {
                assert!(reason.contains("reason=err_not_open_unopened_no_money"));
                assert!(reason.contains("opened=false"));
                assert!(reason.contains("tokens_final=0"));
                assert!(reason.contains("disputed=false"));
                assert!(reason.contains("buyer_locked=0"));
                assert!(reason.contains("buyer_lead=0"));
                assert!(reason.contains("seller_locked=0"));
                assert!(reason.contains("finalized_owed=0"));
                assert!(reason.contains("burned=0"));
            }
            other => panic!("expected benign terminal ERR_NOT_OPEN, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn err_not_open_opened_probe_disputed_or_money_at_risk_remains_fault() {
        for (name, state) in [
            ("opened_probe", deal_state(true, true, false, false)),
            ("streaming", deal_state(true, true, false, true)),
            ("disputed", deal_state(true, false, true, false)),
        ] {
            let chain = RecordingRecoveryChain {
                deal_state: Some(state),
                snapshot: Some(stream_snapshot(0, 0, 0, 0, 0)),
                ..Default::default()
            };

            let disposition = super::classify_by_fact_advance_failure(
                &chain,
                &format!("tc-{name}"),
                &err_not_open(),
            )
            .await
            .expect("classification reads by-fact state");

            match disposition {
                super::AdvanceFailureDisposition::Fault { reason } => {
                    assert!(
                        reason.contains("reason=unsafe_lifecycle"),
                        "{name}: {reason}"
                    );
                }
                other => panic!("expected {name} ERR_NOT_OPEN to remain fatal, got {other:?}"),
            }
        }

        for (name, snapshot) in [
            ("buyer_locked", stream_snapshot(1, 0, 0, 0, 0)),
            ("buyer_lead", stream_snapshot(0, 1, 0, 0, 0)),
            ("seller_locked", stream_snapshot(0, 0, 1, 0, 0)),
            ("finalized_owed", stream_snapshot(0, 0, 0, 1, 0)),
            ("burned", stream_snapshot(0, 0, 0, 0, 1)),
        ] {
            let chain = RecordingRecoveryChain {
                deal_state: Some(deal_state(true, false, false, false)),
                snapshot: Some(snapshot),
                ..Default::default()
            };
            let disposition = super::classify_by_fact_advance_failure(
                &chain,
                &format!("tc-{name}"),
                &err_not_open(),
            )
            .await
            .expect("classification reads by-fact state");

            match disposition {
                super::AdvanceFailureDisposition::Fault { reason } => {
                    assert!(
                        reason.contains("reason=money_or_locks_present"),
                        "{name}: {reason}"
                    );
                }
                other => panic!("expected {name} ERR_NOT_OPEN to remain fatal, got {other:?}"),
            }
        }
    }

    fn ready_funded_never_opened_state() -> dexdo_core::DealChainState {
        dexdo_core::DealChainState {
            funded: true,
            opened: false,
            probe_accepted: false,
            disputed: false,
            deposit: 1_000,
            finalized_owed: 0,
            tokens_final: 0,
            tokens_superseded: 0,
            tokens_pending: 0,
            funded_time: Some(1),
            probe_tick: 0,
            probe_time: 0,
            prev_claim_time: 1,
            last_claim_time: 1,
            dispute_time: 0,
        }
    }

    fn disputed_deal_state() -> dexdo_core::DealChainState {
        dexdo_core::DealChainState {
            funded: true,
            opened: true,
            probe_accepted: true,
            disputed: true,
            deposit: 1_000,
            finalized_owed: 0,
            tokens_final: 0,
            tokens_superseded: 0,
            tokens_pending: 0,
            funded_time: Some(1),
            probe_tick: 0,
            probe_time: 0,
            prev_claim_time: 0,
            last_claim_time: 100,
            dispute_time: 0,
        }
    }

    fn seller_policy(
        after_deal_done: crate::cli::policy::SellerAfterDealDoneAction,
        buyer_no_show: crate::cli::policy::SellerBuyerNoShowAction,
        dispute_against_me: crate::cli::policy::SellerDisputeAgainstMeAction,
    ) -> crate::cli::policy::SellerRuntimePolicy {
        crate::cli::policy::SellerRuntimePolicy {
            after_deal_done,
            buyer_no_show,
            dispute_against_me,
            max_open_deals: 1,
        }
    }

    fn seller_terminal_policy_state(probe_accepted: bool) -> dexdo_core::DealChainState {
        let accepted_tokens = if probe_accepted {
            dexdo_core::TICK_SIZE
        } else {
            0
        };
        dexdo_core::DealChainState {
            funded: true,
            opened: false,
            probe_accepted,
            disputed: false,
            deposit: 0,
            finalized_owed: 0,
            tokens_final: accepted_tokens,
            tokens_superseded: accepted_tokens,
            tokens_pending: accepted_tokens,
            probe_tick: 0,
            funded_time: Some(1),
            probe_time: 1,
            prev_claim_time: 1,
            last_claim_time: 1,
            dispute_time: 0,
        }
    }

    fn assert_seller_policy_startup_fails_closed(
        policy: crate::cli::policy::SellerRuntimePolicy,
        expected_choice: &str,
    ) {
        let err = crate::cli::policy::validate_seller_runtime_capabilities(&policy)
            .unwrap_err()
            .to_string();

        assert!(err.contains("failure_class=policy_validation"), "{err}");
        assert!(err.contains("action=fail_closed"), "{err}");
        assert!(err.contains("token_contract=<not-posted>"), "{err}");
        assert!(err.contains("state=pre_offer"), "{err}");
        assert!(err.contains("result=unsupported_policy_choice"), "{err}");
        assert!(err.contains("next_action=edit_policy"), "{err}");
        assert!(err.contains(expected_choice), "{err}");
    }

    #[test]
    fn policy_seller_after_done_republish_fails_closed_before_offer() {
        let policy = seller_policy(
            crate::cli::policy::SellerAfterDealDoneAction::Republish,
            crate::cli::policy::SellerBuyerNoShowAction::RetireGateway,
            crate::cli::policy::SellerDisputeAgainstMeAction::ReleaseIfClean,
        );

        assert_seller_policy_startup_fails_closed(policy, "seller.on.after_deal_done=republish");
    }

    #[test]
    fn policy_seller_after_done_republish_with_backoff_fails_closed_before_offer() {
        let policy = seller_policy(
            crate::cli::policy::SellerAfterDealDoneAction::RepublishWithBackoff,
            crate::cli::policy::SellerBuyerNoShowAction::RetireGateway,
            crate::cli::policy::SellerDisputeAgainstMeAction::ReleaseIfClean,
        );

        assert_seller_policy_startup_fails_closed(
            policy,
            "seller.on.after_deal_done=republish_with_backoff",
        );
    }

    #[test]
    fn policy_seller_buyer_no_show_cleanup_and_republish_fails_closed_before_offer() {
        let policy = seller_policy(
            crate::cli::policy::SellerAfterDealDoneAction::Retire,
            crate::cli::policy::SellerBuyerNoShowAction::CleanupAndRepublish,
            crate::cli::policy::SellerDisputeAgainstMeAction::ReleaseIfClean,
        );

        assert_seller_policy_startup_fails_closed(
            policy,
            "seller.on.buyer_no_show=cleanup_and_republish",
        );
    }

    #[test]
    fn policy_seller_buyer_no_show_cleanup_and_retire_fails_closed_before_offer() {
        let policy = seller_policy(
            crate::cli::policy::SellerAfterDealDoneAction::Retire,
            crate::cli::policy::SellerBuyerNoShowAction::CleanupAndRetire,
            crate::cli::policy::SellerDisputeAgainstMeAction::ReleaseIfClean,
        );

        assert_seller_policy_startup_fails_closed(
            policy,
            "seller.on.buyer_no_show=cleanup_and_retire",
        );
    }

    #[test]
    fn policy_seller_complete_supported_policy_passes_startup_before_offer() {
        let policy = seller_policy(
            crate::cli::policy::SellerAfterDealDoneAction::Retire,
            crate::cli::policy::SellerBuyerNoShowAction::RetireGateway,
            crate::cli::policy::SellerDisputeAgainstMeAction::ReleaseIfClean,
        );

        crate::cli::policy::validate_seller_runtime_capabilities(&policy)
            .expect("supported seller policy starts");
    }

    #[tokio::test]
    async fn policy_seller_dispute_release_if_clean_executes_release_dispute_lever() {
        use std::sync::atomic::Ordering;

        let chain = RecordingRecoveryChain::with_deal_state(disputed_deal_state());
        let policy = seller_policy(
            crate::cli::policy::SellerAfterDealDoneAction::Retire,
            crate::cli::policy::SellerBuyerNoShowAction::RetireGateway,
            crate::cli::policy::SellerDisputeAgainstMeAction::ReleaseIfClean,
        );

        let handled =
            super::apply_seller_dispute_policy(&chain, &"tc-disputed".to_string(), &policy, "test")
                .await
                .expect("release dispute succeeds");

        assert!(handled);
        assert_eq!(chain.release_calls.load(Ordering::SeqCst), 1);
        assert_eq!(chain.dispute_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn policy_seller_dispute_hold_fails_closed_without_release() {
        use std::sync::atomic::Ordering;

        let chain = RecordingRecoveryChain::with_deal_state(disputed_deal_state());
        let policy = seller_policy(
            crate::cli::policy::SellerAfterDealDoneAction::Retire,
            crate::cli::policy::SellerBuyerNoShowAction::RetireGateway,
            crate::cli::policy::SellerDisputeAgainstMeAction::Hold,
        );

        let err =
            super::apply_seller_dispute_policy(&chain, &"tc-disputed".to_string(), &policy, "test")
                .await
                .unwrap_err()
                .to_string();

        assert!(err.contains("failure_class=dispute_against_me"), "{err}");
        assert!(err.contains("action=hold"), "{err}");
        assert!(err.contains("result=no_release_submitted"), "{err}");
        assert_eq!(chain.release_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.dispute_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn policy_seller_after_done_retire_stops_serving() {
        let policy = seller_policy(
            crate::cli::policy::SellerAfterDealDoneAction::Retire,
            crate::cli::policy::SellerBuyerNoShowAction::RetireGateway,
            crate::cli::policy::SellerDisputeAgainstMeAction::ReleaseIfClean,
        );

        let outcome = super::apply_seller_terminal_policy(
            &"tc-done".to_string(),
            &policy,
            1,
            seller_terminal_policy_state(true),
        )
        .expect("retire stops serving");

        assert!(matches!(
            outcome,
            super::SellerTerminalPolicyOutcome::StopServing
        ));
    }

    #[test]
    fn policy_seller_zero_delivery_after_accepted_probe_uses_after_done() {
        let policy = seller_policy(
            crate::cli::policy::SellerAfterDealDoneAction::Retire,
            crate::cli::policy::SellerBuyerNoShowAction::CleanupAndRetire,
            crate::cli::policy::SellerDisputeAgainstMeAction::ReleaseIfClean,
        );

        let outcome = super::apply_seller_terminal_policy(
            &"tc-accepted-probe".to_string(),
            &policy,
            0,
            seller_terminal_policy_state(true),
        )
        .expect("an accepted probe is ordinary completed service even with zero later delivery");

        assert!(matches!(
            outcome,
            super::SellerTerminalPolicyOutcome::StopServing
        ));
    }

    #[test]
    fn policy_seller_buyer_no_show_retire_gateway_stops_serving_without_cleanup_claim() {
        let policy = seller_policy(
            crate::cli::policy::SellerAfterDealDoneAction::Retire,
            crate::cli::policy::SellerBuyerNoShowAction::RetireGateway,
            crate::cli::policy::SellerDisputeAgainstMeAction::ReleaseIfClean,
        );

        let outcome = super::apply_seller_terminal_policy(
            &"tc-noshow".to_string(),
            &policy,
            0,
            seller_terminal_policy_state(false),
        )
        .expect("retire_gateway stops serving without cleanup");

        assert!(matches!(
            outcome,
            super::SellerTerminalPolicyOutcome::StopServing
        ));
    }

    #[test]
    fn policy_seller_true_buyer_no_show_cleanup_and_retire_fails_closed_if_bypassed() {
        let policy = seller_policy(
            crate::cli::policy::SellerAfterDealDoneAction::Retire,
            crate::cli::policy::SellerBuyerNoShowAction::CleanupAndRetire,
            crate::cli::policy::SellerDisputeAgainstMeAction::ReleaseIfClean,
        );

        let err = super::apply_seller_terminal_policy(
            &"tc-noshow".to_string(),
            &policy,
            0,
            seller_terminal_policy_state(false),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("failure_class=buyer_no_show"), "{err}");
        assert!(err.contains("action=cleanup_and_retire"), "{err}");
        assert!(err.contains("result=policy_action_unsupported"), "{err}");
    }

    fn buyer_policy(
        no_handover_after_match: crate::cli::policy::NoHandoverAfterMatchAction,
        malformed_handover: crate::cli::policy::MalformedHandoverAction,
        dead_gateway: crate::cli::policy::DeadGatewayAction,
        empty_stream: crate::cli::policy::EmptyStreamAction,
        seller_stalls_mid_stream: crate::cli::policy::SellerStallsMidStreamAction,
        bad_output_scam: crate::cli::policy::BadOutputScamAction,
    ) -> crate::cli::policy::BuyerRuntimePolicy {
        crate::cli::policy::BuyerRuntimePolicy {
            no_handover_after_match,
            malformed_handover,
            dead_gateway,
            empty_stream,
            seller_stalls_mid_stream,
            bad_output_scam,
            max_sellers_to_try: 3,
            total_spend_cap_shells: 1_000_000_000,
        }
    }

    fn policy_for_no_handover(
        action: crate::cli::policy::NoHandoverAfterMatchAction,
    ) -> crate::cli::policy::BuyerRuntimePolicy {
        buyer_policy(
            action,
            crate::cli::policy::MalformedHandoverAction::FailClosed,
            crate::cli::policy::DeadGatewayAction::FailClosed,
            crate::cli::policy::EmptyStreamAction::FailClosed,
            crate::cli::policy::SellerStallsMidStreamAction::AcceptDeliveredThenReclaim,
            crate::cli::policy::BadOutputScamAction::Stop,
        )
    }

    fn policy_for_malformed(
        action: crate::cli::policy::MalformedHandoverAction,
    ) -> crate::cli::policy::BuyerRuntimePolicy {
        buyer_policy(
            crate::cli::policy::NoHandoverAfterMatchAction::FailClosed,
            action,
            crate::cli::policy::DeadGatewayAction::FailClosed,
            crate::cli::policy::EmptyStreamAction::FailClosed,
            crate::cli::policy::SellerStallsMidStreamAction::AcceptDeliveredThenReclaim,
            crate::cli::policy::BadOutputScamAction::Stop,
        )
    }

    fn policy_for_stream_failure(
        dead_gateway: crate::cli::policy::DeadGatewayAction,
        empty_stream: crate::cli::policy::EmptyStreamAction,
    ) -> crate::cli::policy::BuyerRuntimePolicy {
        buyer_policy(
            crate::cli::policy::NoHandoverAfterMatchAction::FailClosed,
            crate::cli::policy::MalformedHandoverAction::FailClosed,
            dead_gateway,
            empty_stream,
            crate::cli::policy::SellerStallsMidStreamAction::AcceptDeliveredThenReclaim,
            crate::cli::policy::BadOutputScamAction::Stop,
        )
    }

    #[test]
    fn policy_oneshot_dead_gateway_next_seller_fails_closed_before_order() {
        let policy = policy_for_stream_failure(
            crate::cli::policy::DeadGatewayAction::NextSeller,
            crate::cli::policy::EmptyStreamAction::Reclaim,
        );

        let err = super::validate_buyer_runtime_surface_policy(&policy, None)
            .unwrap_err()
            .to_string();

        assert!(err.contains("failure_class=policy_validation"), "{err}");
        assert!(err.contains("token_contract=<not-placed>"), "{err}");
        assert!(err.contains("state=pre_order"), "{err}");
        assert!(err.contains("buyer.on.dead_gateway=next_seller"), "{err}");
        assert!(
            err.contains("dead_gateway=retry_then_reclaim|fail_closed"),
            "{err}"
        );
    }

    #[test]
    fn policy_oneshot_empty_stream_next_seller_fails_closed_before_order() {
        let policy = policy_for_stream_failure(
            crate::cli::policy::DeadGatewayAction::RetryThenReclaim,
            crate::cli::policy::EmptyStreamAction::NextSeller,
        );

        let err = super::validate_buyer_runtime_surface_policy(&policy, None)
            .unwrap_err()
            .to_string();

        assert!(err.contains("failure_class=policy_validation"), "{err}");
        assert!(err.contains("token_contract=<not-placed>"), "{err}");
        assert!(err.contains("state=pre_order"), "{err}");
        assert!(err.contains("buyer.on.empty_stream=next_seller"), "{err}");
        assert!(err.contains("empty_stream=reclaim|fail_closed"), "{err}");
    }

    #[test]
    fn policy_local_listen_keeps_next_seller_policy_surface() {
        let policy = policy_for_stream_failure(
            crate::cli::policy::DeadGatewayAction::NextSeller,
            crate::cli::policy::EmptyStreamAction::NextSeller,
        );
        let bind = "127.0.0.1:0".parse().expect("socket addr");

        super::validate_buyer_runtime_surface_policy(&policy, Some(bind))
            .expect("local-listen surface handles unsupported actions at runtime");
    }

    #[tokio::test]
    async fn policy_no_handover_wait_then_reclaim_executes_cleanup_lever() {
        use std::sync::atomic::Ordering;

        let chain = RecordingRecoveryChain::with_deal_state(ready_funded_never_opened_state());
        let buyer =
            dexdo::buyer::Buyer::from_note(std::sync::Arc::new(dexdo_core::LocalNote::generate()));
        let policy =
            policy_for_no_handover(crate::cli::policy::NoHandoverAfterMatchAction::WaitThenReclaim);

        let err = super::apply_no_handover_after_match_policy(
            &chain,
            &buyer,
            &"tc-clean".to_string(),
            &policy,
            false,
            None,
            1,
            "diagnostic",
            None,
        )
        .await
        .unwrap_err()
        .to_string();

        assert!(
            err.contains("failure_class=no_handover_after_match"),
            "{err}"
        );
        assert!(err.contains("action=wait_then_reclaim"), "{err}");
        assert!(err.contains("result=money_reclaimed"), "{err}");
        assert_eq!(chain.cleanup_calls.load(Ordering::SeqCst), 1);
        assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.dispute_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn matched_subscription_handover_failures_submit_no_terminal_writes() {
        use std::sync::atomic::Ordering;

        let chain = RecordingRecoveryChain::with_deal_state(ready_funded_never_opened_state());
        let buyer =
            dexdo::buyer::Buyer::from_note(std::sync::Arc::new(dexdo_core::LocalNote::generate()));
        let no_handover_policy =
            policy_for_no_handover(crate::cli::policy::NoHandoverAfterMatchAction::WaitThenReclaim);

        let no_handover = super::apply_no_handover_after_match_policy(
            &chain,
            &buyer,
            &"tc-subscription".to_string(),
            &no_handover_policy,
            true,
            None,
            1,
            "diagnostic",
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(no_handover.contains("result=subscription_preserved"));
        assert!(no_handover.contains("chain_write_submitted=false"));

        let malformed_policy =
            policy_for_malformed(crate::cli::policy::MalformedHandoverAction::Reclaim);
        let malformed = super::apply_malformed_handover_policy(
            &chain,
            &buyer,
            &"tc-subscription".to_string(),
            &malformed_policy,
            true,
            &anyhow::anyhow!("malformed handover: invalid bytes"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(malformed.contains("result=subscription_preserved"));
        assert!(malformed.contains("chain_write_submitted=false"));

        assert_eq!(chain.cleanup_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.stop_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.dispute_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.place_next_calls.load(Ordering::SeqCst), 0);
    }

    // With shellnet enabled, this test serializes process-global DEXDO_PN_POOL for the full async scenario.
    #[cfg_attr(feature = "shellnet", allow(clippy::await_holding_lock))]
    #[tokio::test]
    async fn policy_no_handover_next_seller_cleans_then_places_next_buy() {
        use std::sync::atomic::Ordering;

        #[cfg(feature = "shellnet")]
        let _env_lock = dexdo_pn_pool_env_lock().lock().unwrap();
        #[cfg(feature = "shellnet")]
        let dir = std::env::temp_dir().join(format!(
            "dexdo-next-seller-pool-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        #[cfg(feature = "shellnet")]
        std::fs::create_dir(&dir).unwrap();
        #[cfg(feature = "shellnet")]
        let _cleanup = TempDirCleanup(dir.clone());
        #[cfg(feature = "shellnet")]
        let pool = dir.join("pn_pool.json");
        #[cfg(feature = "shellnet")]
        let buyer_note = format!("0:{}", "3".repeat(64));
        #[cfg(feature = "shellnet")]
        std::fs::write(
            &pool,
            serde_json::to_vec_pretty(&serde_json::json!({
                "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
                "notes": [{
                    "address": buyer_note,
                    "owner_secret_key_hex": "00"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        #[cfg(feature = "shellnet")]
        let _env = EnvVarGuard::set("DEXDO_PN_POOL", pool.as_os_str());
        #[cfg(feature = "shellnet")]
        let pool_note_addr = Some(buyer_note.as_str());
        #[cfg(not(feature = "shellnet"))]
        let pool_note_addr = None;

        let chain = RecordingRecoveryChain::with_deal_state(ready_funded_never_opened_state());
        let buyer =
            dexdo::buyer::Buyer::from_note(std::sync::Arc::new(dexdo_core::LocalNote::generate()));
        let policy =
            policy_for_no_handover(crate::cli::policy::NoHandoverAfterMatchAction::NextSeller);

        let outcome = super::apply_no_handover_after_match_policy(
            &chain,
            &buyer,
            &"tc-current".to_string(),
            &policy,
            false,
            Some((1, 1, 1)),
            1,
            "diagnostic",
            pool_note_addr,
        )
        .await
        .expect("next_seller dispatch succeeds");

        assert!(matches!(
            outcome,
            super::NoHandoverPolicyOutcome::RetryNext(tc) if tc == "tc-next"
        ));
        assert_eq!(chain.cleanup_calls.load(Ordering::SeqCst), 1);
        assert_eq!(chain.place_next_calls.load(Ordering::SeqCst), 1);
        assert_eq!(chain.wait_match_calls.load(Ordering::SeqCst), 1);
        assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn policy_no_handover_fail_closed_reports_without_recovery_lever() {
        use std::sync::atomic::Ordering;

        let chain = RecordingRecoveryChain::with_deal_state(ready_funded_never_opened_state());
        let buyer =
            dexdo::buyer::Buyer::from_note(std::sync::Arc::new(dexdo_core::LocalNote::generate()));
        let policy =
            policy_for_no_handover(crate::cli::policy::NoHandoverAfterMatchAction::FailClosed);

        let err = super::apply_no_handover_after_match_policy(
            &chain,
            &buyer,
            &"tc-fail".to_string(),
            &policy,
            false,
            None,
            1,
            "diagnostic",
            None,
        )
        .await
        .unwrap_err()
        .to_string();

        assert!(err.contains("action=fail_closed"), "{err}");
        assert!(err.contains("result=no_recovery_submitted"), "{err}");
        assert_eq!(chain.cleanup_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.dispute_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn policy_malformed_handover_reclaim_executes_reclaim_lever() {
        use std::sync::atomic::Ordering;

        let chain = RecordingRecoveryChain::default();
        let buyer =
            dexdo::buyer::Buyer::from_note(std::sync::Arc::new(dexdo_core::LocalNote::generate()));
        let policy = policy_for_malformed(crate::cli::policy::MalformedHandoverAction::Reclaim);
        let handover_error = anyhow::anyhow!("malformed handover: invalid bytes");

        let err = super::apply_malformed_handover_policy(
            &chain,
            &buyer,
            &"tc-malformed".to_string(),
            &policy,
            false,
            &handover_error,
        )
        .await
        .unwrap_err()
        .to_string();

        assert!(err.contains("failure_class=malformed_handover"), "{err}");
        assert!(err.contains("action=reclaim"), "{err}");
        assert!(err.contains("result=reclaimed"), "{err}");
        // The lever is a STOP now: there is no gated reclaim to call, and stopping recovers the escrow
        // immediately rather than after an inactivity window.
        assert_eq!(chain.stop_calls.load(Ordering::SeqCst), 1);
        assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.dispute_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn policy_malformed_handover_dispute_executes_dispute_lever() {
        use std::sync::atomic::Ordering;

        let chain = RecordingRecoveryChain::default();
        let buyer =
            dexdo::buyer::Buyer::from_note(std::sync::Arc::new(dexdo_core::LocalNote::generate()));
        let policy = policy_for_malformed(crate::cli::policy::MalformedHandoverAction::Dispute);
        let handover_error = anyhow::anyhow!("handover decrypt failed: bad key");

        let err = super::apply_malformed_handover_policy(
            &chain,
            &buyer,
            &"tc-dispute".to_string(),
            &policy,
            false,
            &handover_error,
        )
        .await
        .unwrap_err()
        .to_string();

        assert!(err.contains("failure_class=malformed_handover"), "{err}");
        assert!(err.contains("action=dispute"), "{err}");
        assert!(err.contains("result=dispute_opened"), "{err}");
        assert!(
            err.contains(
                "dispute_freezes_this_token_contract_buyer_D_and_seller_bond_until_resolution"
            ),
            "{err}"
        );
        assert!(!err.contains("dispute_locks_buyer_note"), "{err}");
        assert_eq!(chain.dispute_calls.load(Ordering::SeqCst), 1);
        assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn policy_malformed_handover_fail_closed_reports_without_recovery_lever() {
        use std::sync::atomic::Ordering;

        let chain = RecordingRecoveryChain::default();
        let buyer =
            dexdo::buyer::Buyer::from_note(std::sync::Arc::new(dexdo_core::LocalNote::generate()));
        let policy = policy_for_malformed(crate::cli::policy::MalformedHandoverAction::FailClosed);
        let handover_error = anyhow::anyhow!("malformed handover: invalid bytes");

        let err = super::apply_malformed_handover_policy(
            &chain,
            &buyer,
            &"tc-fail".to_string(),
            &policy,
            false,
            &handover_error,
        )
        .await
        .unwrap_err()
        .to_string();

        assert!(err.contains("action=fail_closed"), "{err}");
        assert!(err.contains("result=no_recovery_submitted"), "{err}");
        assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.dispute_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn policy_oneshot_dead_gateway_retry_then_reclaim_retries_once_then_reclaims() {
        use std::sync::atomic::Ordering;

        let chain = std::sync::Arc::new(RecordingRecoveryChain::default());
        let policy = policy_for_stream_failure(
            crate::cli::policy::DeadGatewayAction::RetryThenReclaim,
            crate::cli::policy::EmptyStreamAction::FailClosed,
        );
        let session = dexdo::buyer::api::SessionSettle::new_with_failure_policy(
            chain.clone(),
            "tc-dead".to_string(),
            std::sync::Arc::new(dexdo_core::LocalNote::generate()),
            policy.as_api_failure_policy(),
        );

        assert_eq!(
            super::apply_oneshot_dead_gateway_policy(
                &session,
                &"tc-dead".to_string(),
                Some(&policy),
                1,
            )
            .await,
            super::OneShotStreamPolicyOutcome::RetryCurrent
        );
        assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 0);

        let report = match super::apply_oneshot_dead_gateway_policy(
            &session,
            &"tc-dead".to_string(),
            Some(&policy),
            2,
        )
        .await
        {
            super::OneShotStreamPolicyOutcome::TerminalReport(report) => report,
            other => panic!("expected terminal report, got {other:?}"),
        };

        assert!(report.contains("failure_class=dead_gateway"), "{report}");
        assert!(report.contains("action=retry_then_reclaim"), "{report}");
        assert!(report.contains("result=reclaim_submitted"), "{report}");
        assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 1);
        assert_eq!(chain.stop_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.dispute_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn subscription_oneshot_dead_gateway_preserves_deal() {
        use std::sync::atomic::Ordering;

        let chain = std::sync::Arc::new(RecordingRecoveryChain::default());
        let policy = policy_for_stream_failure(
            crate::cli::policy::DeadGatewayAction::RetryThenReclaim,
            crate::cli::policy::EmptyStreamAction::FailClosed,
        );
        let session = dexdo::buyer::api::SessionSettle::new_with_failure_policy_and_lifetime(
            chain.clone(),
            "tc-subscription-dead".to_string(),
            std::sync::Arc::new(dexdo_core::LocalNote::generate()),
            policy.as_api_failure_policy(),
            dexdo::buyer::api::SessionLifetimePolicy::Preserve,
        );

        assert_eq!(
            super::apply_oneshot_dead_gateway_policy(
                &session,
                &"tc-subscription-dead".to_string(),
                Some(&policy),
                1,
            )
            .await,
            super::OneShotStreamPolicyOutcome::RetryCurrent
        );
        let report = match super::apply_oneshot_dead_gateway_policy(
            &session,
            &"tc-subscription-dead".to_string(),
            Some(&policy),
            2,
        )
        .await
        {
            super::OneShotStreamPolicyOutcome::TerminalReport(report) => report,
            other => panic!("expected terminal report, got {other:?}"),
        };

        assert!(report.contains("result=reclaim_not_submitted"), "{report}");
        drop(session);
        tokio::task::yield_now().await;
        assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.stop_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.dispute_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn policy_oneshot_dead_gateway_fail_closed_reports_without_recovery_lever() {
        use std::sync::atomic::Ordering;

        let chain = std::sync::Arc::new(RecordingRecoveryChain::default());
        let policy = policy_for_stream_failure(
            crate::cli::policy::DeadGatewayAction::FailClosed,
            crate::cli::policy::EmptyStreamAction::FailClosed,
        );
        let session = dexdo::buyer::api::SessionSettle::new_with_failure_policy(
            chain.clone(),
            "tc-dead-fail".to_string(),
            std::sync::Arc::new(dexdo_core::LocalNote::generate()),
            policy.as_api_failure_policy(),
        );

        let report = match super::apply_oneshot_dead_gateway_policy(
            &session,
            &"tc-dead-fail".to_string(),
            Some(&policy),
            1,
        )
        .await
        {
            super::OneShotStreamPolicyOutcome::TerminalReport(report) => report,
            other => panic!("expected terminal report, got {other:?}"),
        };

        assert!(report.contains("action=fail_closed"), "{report}");
        assert!(report.contains("result=no_recovery_submitted"), "{report}");
        assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.stop_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn policy_oneshot_empty_stream_reclaim_executes_reclaim_lever() {
        use std::sync::atomic::Ordering;

        let chain = std::sync::Arc::new(RecordingRecoveryChain::default());
        let policy = policy_for_stream_failure(
            crate::cli::policy::DeadGatewayAction::FailClosed,
            crate::cli::policy::EmptyStreamAction::Reclaim,
        );
        let session = dexdo::buyer::api::SessionSettle::new_with_failure_policy(
            chain.clone(),
            "tc-empty".to_string(),
            std::sync::Arc::new(dexdo_core::LocalNote::generate()),
            policy.as_api_failure_policy(),
        );

        let report = super::apply_oneshot_empty_stream_policy(
            &session,
            &"tc-empty".to_string(),
            Some(&policy),
        )
        .await;

        assert!(report.contains("failure_class=empty_stream"), "{report}");
        assert!(report.contains("action=reclaim"), "{report}");
        assert!(report.contains("result=reclaim_submitted"), "{report}");
        assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 1);
        assert_eq!(chain.stop_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.dispute_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn policy_oneshot_empty_stream_fail_closed_reports_without_recovery_lever() {
        use std::sync::atomic::Ordering;

        let chain = std::sync::Arc::new(RecordingRecoveryChain::default());
        let policy = policy_for_stream_failure(
            crate::cli::policy::DeadGatewayAction::FailClosed,
            crate::cli::policy::EmptyStreamAction::FailClosed,
        );
        let session = dexdo::buyer::api::SessionSettle::new_with_failure_policy(
            chain.clone(),
            "tc-empty-fail".to_string(),
            std::sync::Arc::new(dexdo_core::LocalNote::generate()),
            policy.as_api_failure_policy(),
        );

        let report = super::apply_oneshot_empty_stream_policy(
            &session,
            &"tc-empty-fail".to_string(),
            Some(&policy),
        )
        .await;

        assert!(report.contains("failure_class=empty_stream"), "{report}");
        assert!(report.contains("action=fail_closed"), "{report}");
        assert!(report.contains("result=no_recovery_submitted"), "{report}");
        assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.stop_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.dispute_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn buyer_monitor_idle_opened_never_stops_or_buys_and_cleanup_still_runs() {
        use dexdo::buyer::continuity::{BuyerAction, BuyerContinuity, ContinuityConfig, DealFacts};
        use std::sync::atomic::Ordering;

        let cfg = ContinuityConfig {
            renewal_threshold_tokens: 10,
            match_open_timeout_secs: 600,
        };
        let chain = RecordingRecoveryChain::default();

        for (now, heartbeat) in [(700, 101), (700, 400), (700, 699), (10_000, 0)] {
            let active = super::buyer_monitor_current_facts(
                "tc-active".to_string(),
                100,
                false,
                Some(dexdo_core::DealChainState {
                    funded: true,
                    opened: true,
                    probe_accepted: true,
                    disputed: false,
                    deposit: 1_000,
                    finalized_owed: 0,
                    tokens_final: 0,
                    tokens_superseded: 0,
                    tokens_pending: 0,
                    funded_time: Some(1),
                    probe_tick: 0,
                    probe_time: 0,
                    prev_claim_time: 0,
                    last_claim_time: 100,
                    dispute_time: 0,
                }),
                now,
                heartbeat,
            );
            let action = BuyerContinuity::default().tick(Some(active), None, cfg);
            assert!(
                matches!(action, BuyerAction::ServeCurrent { .. }),
                "OPEN idle facts must remain usable at now={now}, heartbeat={heartbeat}: {action:?}"
            );
            assert!(
                super::execute_buyer_monitor_recovery(&chain, action, None)
                    .await
                    .is_none(),
                "idle alone must not map to a money-moving recovery"
            );
        }
        assert_eq!(chain.reclaim_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.place_next_calls.load(Ordering::SeqCst), 0);

        let funded_time = 100;
        let never_opened_state = dexdo_core::DealChainState {
            funded: true,
            opened: false,
            probe_accepted: false,
            disputed: false,
            deposit: 1_000,
            finalized_owed: 0,
            tokens_final: 0,
            tokens_superseded: 0,
            tokens_pending: 0,
            funded_time: Some(funded_time),
            probe_tick: 0,
            probe_time: 0,
            prev_claim_time: funded_time,
            last_claim_time: funded_time,
            dispute_time: 0,
        };
        assert_eq!(
            (
                never_opened_state.probe_accepted,
                never_opened_state.funded_time,
                never_opened_state.prev_claim_time,
                never_opened_state.last_claim_time,
            ),
            (false, Some(funded_time), funded_time, funded_time),
            "monitor cleanup must use a canonical 4.0.32 funded-never-opened state"
        );
        let never_opened = super::buyer_monitor_current_facts(
            "tc-clean".to_string(),
            100,
            false,
            Some(never_opened_state),
            700,
            0,
        );
        let mut planner = BuyerContinuity::default();
        let action = planner.tick(Some(never_opened), None, cfg);
        assert_eq!(
            action,
            BuyerAction::CleanupUnopened {
                token_contract: "tc-clean".to_string()
            }
        );
        let (kind, tc, result) = super::execute_buyer_monitor_recovery(&chain, action, None)
            .await
            .expect("cleanup action executes");
        assert_eq!(kind, super::BuyerMonitorRecoveryKind::CleanupUnopened);
        assert_eq!(tc, "tc-clean");
        assert!(result.is_ok());
        assert_eq!(chain.cleanup_calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            planner.tick(
                Some(DealFacts::funded_never_opened("tc-clean", 601)),
                None,
                cfg
            ),
            BuyerAction::IgnoreStale { token_contract } if token_contract == "tc-clean"
        ));
        assert_eq!(chain.cleanup_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn legacy_idle_threshold_is_not_a_continuity_parameter_or_action() {
        use dexdo::buyer::continuity::{BuyerAction, BuyerContinuity, ContinuityConfig};
        let source = include_str!("../buyer/continuity.rs");
        assert!(!source.contains("stream_timeout_secs"));
        assert!(!source.contains("ReclaimOpened"));
        assert!(matches!(
            BuyerContinuity::default().tick(
                Some(dexdo::buyer::continuity::DealFacts::opened_idle(
                    "tc-idle",
                    u64::MAX
                )),
                None,
                ContinuityConfig::default(),
            ),
            BuyerAction::ServeCurrent { .. }
        ));
    }

    #[test]
    fn replay_protection_exit_52_is_retryable_for_lazy_buyer_init() {
        let err = anyhow::Error::new(dexdo_core::ChainError::Contract(
            "run_tvm getter getDetails exit code 52: Replay protection exception".to_string(),
        ))
        .context("lazy buyer initialization failed");
        assert!(super::is_replay_protection_error(&err));
    }

    #[test]
    fn ambiguous_submit_is_not_retried_as_replay_protection() {
        let err = anyhow::Error::new(dexdo_core::ChainError::AmbiguousSubmit(
            "replay protection response left submit outcome unknown".to_string(),
        ));
        assert!(!super::is_replay_protection_error(&err));
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn note_deploy_wallet_busy_error_is_actionable() {
        let raw = anyhow::anyhow!(
            "block manager rejected message code=TVM_ERROR; exit_code=52 nonce desynchronized"
        );
        assert!(super::is_note_deploy_wallet_busy_error(&raw));
        let err = super::note_deploy_error("0:wallet", raw).to_string();
        assert!(err.contains("wallet busy/out-of-sync"), "{err}");
        assert!(err.contains("Retry after"), "{err}");
        assert!(!err.contains("TVM_ERROR"), "{err}");
    }

    #[cfg(feature = "shellnet")]
    struct TempDirCleanup(std::path::PathBuf);

    #[cfg(feature = "shellnet")]
    impl Drop for TempDirCleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(feature = "shellnet")]
    fn buyer_journal_test_dir(label: &str) -> (std::path::PathBuf, TempDirCleanup) {
        let dir = std::env::temp_dir().join(format!(
            "dexdo-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        (dir.clone(), TempDirCleanup(dir))
    }

    #[cfg(feature = "shellnet")]
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SubscriptionSubmitCall {
        order_book: String,
        model_hash: String,
        max_price_per_tick: u128,
        ticks: u128,
        escrow: u128,
        flags: u8,
        deadline: u64,
    }

    #[cfg(feature = "shellnet")]
    struct FakeSubscriptionOps {
        calls: std::sync::Mutex<Vec<SubscriptionSubmitCall>>,
        placements: std::sync::Mutex<Vec<dexdo_core::InferenceSubscriptionPlacement>>,
        fills: std::sync::Mutex<Vec<(u128, dexdo_core::MatchedFill)>>,
        facts_override: std::sync::Mutex<Option<super::SubscriptionDealFacts>>,
        active: std::sync::atomic::AtomicBool,
        ambiguous_after_post: std::sync::atomic::AtomicBool,
        order_id_floor: u128,
    }

    #[cfg(feature = "shellnet")]
    impl FakeSubscriptionOps {
        fn new(order_id_floor: u128) -> Self {
            Self {
                calls: std::sync::Mutex::new(Vec::new()),
                placements: std::sync::Mutex::new(Vec::new()),
                fills: std::sync::Mutex::new(Vec::new()),
                facts_override: std::sync::Mutex::new(None),
                active: std::sync::atomic::AtomicBool::new(false),
                ambiguous_after_post: std::sync::atomic::AtomicBool::new(false),
                order_id_floor,
            }
        }
    }

    #[cfg(feature = "shellnet")]
    #[async_trait::async_trait]
    impl super::SubscriptionOrderOps for FakeSubscriptionOps {
        async fn submit_subscription_order(
            &self,
            _note: &dexdo_core::Address,
            _keys: &dexdo_core::KeyPair,
            order_book: &str,
            model_hash: &str,
            max_price_per_tick: u128,
            ticks: u128,
            escrow: u128,
            order_flags: u8,
            deadline: u64,
            fill_cursor: &mut dexdo_core::MatchWatchCursor,
            before_post: &mut (dyn FnMut(
                String,
                u128,
                dexdo_core::MatchWatchCursor,
                Vec<(u128, dexdo_core::MatchedFill)>,
            ) -> anyhow::Result<()>
                      + Send),
        ) -> anyhow::Result<serde_json::Value> {
            *fill_cursor = dexdo_core::MatchWatchCursor::new(1_000);
            before_post(
                format!("boc-sha256:{}", "a".repeat(64)),
                self.order_id_floor,
                fill_cursor.clone(),
                Vec::new(),
            )?;
            self.calls.lock().unwrap().push(SubscriptionSubmitCall {
                order_book: order_book.to_string(),
                model_hash: model_hash.to_string(),
                max_price_per_tick,
                ticks,
                escrow,
                flags: order_flags,
                deadline,
            });
            if self
                .ambiguous_after_post
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return Err(anyhow::Error::new(dexdo_core::ChainError::AmbiguousSubmit(
                    "injected lost money POST response".to_string(),
                )));
            }
            Ok(serde_json::json!({ "accepted": true }))
        }

        async fn subscription_placements(
            &self,
            _order_book: &str,
            _buyer_note: &str,
            _order_id_floor: u128,
            _max_price_per_tick: u128,
            _ticks: u128,
        ) -> anyhow::Result<Vec<dexdo_core::InferenceSubscriptionPlacement>> {
            Ok(self.placements.lock().unwrap().clone())
        }

        async fn attributed_subscription_fills(
            &self,
            _order_book: &str,
            _buyer_note: &str,
            _cursor: &mut dexdo_core::MatchWatchCursor,
        ) -> anyhow::Result<Vec<(u128, dexdo_core::MatchedFill)>> {
            Ok(self.fills.lock().unwrap().clone())
        }

        async fn subscription_order_active(
            &self,
            _order_book: &str,
            _order_id: u128,
            _buyer_note: &str,
        ) -> anyhow::Result<bool> {
            Ok(self.active.load(std::sync::atomic::Ordering::SeqCst))
        }

        async fn subscription_deal_facts(
            &self,
            expected_note_addr: &str,
            order: &super::BuyerSubscriptionOrderRecord,
            _matched: &super::BuyerJournalMatch,
        ) -> anyhow::Result<super::SubscriptionDealFacts> {
            if let Some(facts) = self.facts_override.lock().unwrap().clone() {
                return Ok(facts);
            }
            Ok(subscription_test_facts(order, expected_note_addr))
        }

        /// These fixtures stand inside a recorded week, so no boundary is ever due -- the contract
        /// refuses the booking and the recorded books stand.
        async fn book_subscription_week(&self, _token_contract: &str) {}
    }

    #[cfg(feature = "shellnet")]
    struct SubscriptionResumeChain {
        order_book: String,
        snapshot: dexdo_core::DealChainSnapshot,
        snapshot_overrides:
            std::sync::Mutex<std::collections::BTreeMap<String, dexdo_core::DealChainSnapshot>>,
        reject_target: Option<String>,
        /// Weekly boundaries the CHAIN has crossed and nobody has booked; `settle_week` books them.
        due_boundaries: std::sync::Mutex<u8>,
        settle_bookings: std::sync::atomic::AtomicUsize,
        attributed_fills: std::sync::Mutex<Vec<(u128, dexdo_core::MatchedFill)>>,
        /// BUY submissions only(`place_buy`/`place_buy_by_model`). It says nothing about value
        /// that MOVES: a boundary booking charges weeks the term already owes out of escrow. What
        /// zero here proves is that resume posted no second BUY.
        buy_posts: std::sync::atomic::AtomicUsize,
        lookback_reads: std::sync::atomic::AtomicUsize,
        target_checks: std::sync::atomic::AtomicUsize,
    }

    #[cfg(feature = "shellnet")]
    #[async_trait::async_trait]
    impl dexdo_core::ChainBackend for SubscriptionResumeChain {
        /// The permissionless boundary booking, as the contract implements it: it settles only what
        /// the CHAIN has crossed and refuses when the window is still open.
        async fn settle_week(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<(), dexdo_core::ChainError> {
            let mut due = self.due_boundaries.lock().unwrap();
            let mut overrides = self.snapshot_overrides.lock().unwrap();
            let booked = overrides
                .entry(token_contract.clone())
                .or_insert_with(|| self.snapshot.clone());
            if *due == 0 || booked.subscription.term_is_over() {
                return Err(dexdo_core::ChainError::Chain(
                    "ERR_SETTLE_WINDOW_OPEN".to_string(),
                ));
            }
            while *due > 0 && !booked.subscription.term_is_over() {
                booked.subscription.week_index += 1;
                booked.subscription.tokens_paid = u128::from(booked.subscription.week_index)
                    * booked.subscription.tokens_per_week;
                booked.subscription.week_base_tokens = booked.state.tokens_pending;
                *due -= 1;
            }
            self.settle_bookings
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn discover_offers(
            &self,
        ) -> Result<Vec<dexdo_core::OfferListing>, dexdo_core::ChainError> {
            panic!("durable subscription resume must not perform fresh discovery")
        }

        async fn post_offer(
            &self,
            _offer: dexdo_core::SellOffer,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!("buyer-only test backend")
        }

        async fn place_buy(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            self.buy_posts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            panic!("durable subscription resume attempted a second BUY")
        }

        async fn place_buy_by_model(
            &self,
            _note: &dyn dexdo_core::Note,
            _ticks: u128,
            _max_price_per_tick: u128,
            _escrow: u128,
            _flags: u8,
            _deadline: u64,
        ) -> Result<(), dexdo_core::ChainError> {
            self.buy_posts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            panic!("durable subscription resume attempted a second model BUY")
        }

        fn model_buy_order_book_identity(&self) -> Option<String> {
            Some(self.order_book.clone())
        }

        async fn poll_attributed_model_buys_for_order_book(
            &self,
            _order_book: &str,
            _cursor: &mut dexdo_core::MatchWatchCursor,
        ) -> Result<Vec<(u128, dexdo_core::MatchedFill)>, dexdo_core::ChainError> {
            Ok(self.attributed_fills.lock().unwrap().clone())
        }

        async fn wait_matched_token_contract(
            &self,
            _since_unix: i64,
            _timeout: std::time::Duration,
        ) -> Result<Option<dexdo_core::MatchedFill>, dexdo_core::ChainError> {
            self.lookback_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(dexdo_core::ChainError::Chain(
                "bounded event lookback must not run".to_string(),
            ))
        }

        async fn assert_model_only_resume_target(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<(), dexdo_core::ChainError> {
            self.target_checks
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self
                .reject_target
                .as_ref()
                .is_some_and(|rejected| rejected.eq_ignore_ascii_case(token_contract))
            {
                return Err(dexdo_core::ChainError::Chain(
                    "injected active-target rejection".to_string(),
                ));
            }
            Ok(())
        }

        async fn deal_snapshot(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<dexdo_core::DealChainSnapshot>, dexdo_core::ChainError> {
            Ok(Some(
                self.snapshot_overrides
                    .lock()
                    .unwrap()
                    .get(token_contract)
                    .cloned()
                    .unwrap_or_else(|| self.snapshot.clone()),
            ))
        }

        async fn claim_tokens(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _note: &dyn dexdo_core::Note,
            _cumulative_tokens: u128,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!("resume never claims")
        }

        async fn read_match(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Result<dexdo_core::Match, dexdo_core::ChainError> {
            unimplemented!("buyer resume reads handover later")
        }

        async fn open_stream(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _enc_endpoint: Vec<u8>,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!("buyer resume never opens seller stream")
        }

        async fn read_handover(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<Vec<u8>>, dexdo_core::ChainError> {
            Ok(None)
        }

        async fn stop(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _note: &dyn dexdo_core::Note,
        ) -> Result<dexdo_core::Settlement, dexdo_core::ChainError> {
            panic!("durable subscription resume must not STOP")
        }

        async fn snapshot(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Option<dexdo_core::StreamSnapshot> {
            None
        }
    }

    #[cfg(feature = "shellnet")]
    fn subscription_test_note() -> String {
        format!("0:{}", "1".repeat(64))
    }

    #[cfg(feature = "shellnet")]
    fn subscription_test_book() -> String {
        format!("0:{}", "2".repeat(64))
    }

    #[cfg(feature = "shellnet")]
    fn subscription_test_tc(digit: char) -> String {
        format!("0:{}", digit.to_string().repeat(64))
    }

    #[cfg(feature = "shellnet")]
    fn subscription_test_reserve(
        ticks: u128,
        price_per_tick: u128,
    ) -> dexdo_core::SubscriptionBuyReserve {
        dexdo_core::subscription_buy_reserve(ticks, price_per_tick).unwrap()
    }

    #[cfg(feature = "shellnet")]
    fn persist_subscription_test_handle(
        _order: &super::BuyerSubscriptionOrderRecord,
        matched: &super::BuyerJournalMatch,
    ) -> anyhow::Result<String> {
        Ok(crate::cli::deals::make_handle_id(
            &matched.token_contract,
            crate::cli::deals::DealHandleRole::Buyer,
        ))
    }

    #[cfg(feature = "shellnet")]
    fn subscription_test_facts(
        order: &super::BuyerSubscriptionOrderRecord,
        expected_note_addr: &str,
    ) -> super::SubscriptionDealFacts {
        let funded_tokens = order.ticks.checked_mul(dexdo_core::TICK_SIZE).unwrap();
        let accepted_probe_tokens = dexdo_core::TICK_SIZE;
        let reserve =
            dexdo_core::subscription_buy_reserve(order.ticks, order.max_price_per_tick).unwrap();
        super::SubscriptionDealFacts {
            state: dexdo_core::DealChainState {
                funded: true,
                opened: true,
                probe_accepted: true,
                disputed: false,
                deposit: reserve.deposit,
                finalized_owed: 0,
                tokens_final: accepted_probe_tokens,
                tokens_superseded: accepted_probe_tokens,
                tokens_pending: accepted_probe_tokens,
                probe_tick: 0,
                funded_time: Some(1),
                probe_time: 1,
                prev_claim_time: 1,
                last_claim_time: 1,
                dispute_time: 0,
            },
            subscription: dexdo_core::DealSubscription {
                deal_flags: dexdo_core::order_flags::SUBSCRIPTION,
                sub_weeks: dexdo_core::SUBSCRIPTION_WEEKS,
                week_index: 0,
                tokens_per_week: funded_tokens / u128::from(dexdo_core::SUBSCRIPTION_WEEKS),
                funded_tokens,
                tokens_paid: 0,
                // The weekly clock is anchored at the accepted probe. A subscription fixture must
                // carry a real anchor: the current-week allowance is derived from how far the clock
                // has run past it, so `1` would read as a four-week-old, finished term.
                period_start: super::unix_now_secs(),
                week_base_tokens: 0,
            },
            seller_bond: dexdo_core::DealSellerBond {
                bond_funded: true,
                bond_held: reserve.buyer_bond,
                bond_required: reserve.buyer_bond,
            },
            buyer_bond: dexdo_core::DealBuyerBond {
                bond_held: reserve.buyer_bond,
                bond_required: reserve.buyer_bond,
            },
            model_name: order.frame_model.clone(),
            model_hash: order.model_hash.clone(),
            buyer_note: expected_note_addr.to_string(),
        }
    }

    #[cfg(feature = "shellnet")]
    fn subscription_test_snapshot(
        order: &super::BuyerSubscriptionOrderRecord,
        expected_note_addr: &str,
    ) -> dexdo_core::DealChainSnapshot {
        let facts = subscription_test_facts(order, expected_note_addr);
        dexdo_core::DealChainSnapshot {
            account_code_hash: "code-hash".to_string(),
            account_boc_hash: "boc-hash".to_string(),
            state: facts.state,
            subscription: facts.subscription,
            seller_bond: facts.seller_bond,
            buyer_bond: facts.buyer_bond,
        }
    }

    #[cfg(feature = "shellnet")]
    fn subscription_test_placement(
        order_id: u128,
        deadline: u64,
    ) -> dexdo_core::InferenceSubscriptionPlacement {
        dexdo_core::InferenceSubscriptionPlacement {
            order_id,
            buyer_note: subscription_test_note(),
            max_price_per_tick: dexdo_core::PRICE_STEP,
            ticks: u128::from(dexdo_core::SUBSCRIPTION_WEEKS),
            sub_weeks: dexdo_core::SUBSCRIPTION_WEEKS,
            deadline,
            created_at: i64::try_from(deadline - 1).unwrap(),
        }
    }

    #[cfg(feature = "shellnet")]
    fn subscription_test_journal(
        order_id_floor: u128,
        deadline: u64,
    ) -> super::BuyerSubscriptionSubmitJournal {
        let frame_model = "qwen--qwen3--32b".to_string();
        let ticks = u128::from(dexdo_core::SUBSCRIPTION_WEEKS);
        let reserve = subscription_test_reserve(ticks, dexdo_core::PRICE_STEP);
        super::BuyerSubscriptionSubmitJournal {
            schema: super::BUYER_SUBSCRIPTION_SUBMIT_SCHEMA.to_string(),
            note_addr: subscription_test_note(),
            order_book: subscription_test_book(),
            model_hash: dexdo_core::model_hash_for(&frame_model),
            frame_model,
            max_price_per_tick: dexdo_core::PRICE_STEP,
            ticks,
            deposit: reserve.deposit,
            buyer_bond: reserve.buyer_bond,
            escrow: reserve.total_escrow,
            flags: dexdo_core::order_flags::AON | dexdo_core::order_flags::SUBSCRIPTION,
            deadline,
            order_id_floor,
            fill_cursor: dexdo_core::MatchWatchCursor::new(1_000),
            submit_identity: format!("boc-sha256:{}", "a".repeat(64)),
            created_at_unix: deadline - 10,
        }
    }

    #[cfg(feature = "shellnet")]
    fn subscription_test_record(order_id: u128) -> super::BuyerSubscriptionOrderRecord {
        let deadline = 2_000;
        let journal = subscription_test_journal(order_id, deadline);
        let placement = subscription_test_placement(order_id, deadline);
        let mut state =
            super::BuyerSubscriptionState::empty(&journal.note_addr).expect("empty state");
        super::record_subscription_placement(&mut state, &journal, &placement)
            .expect("canonical placement")
    }

    #[cfg(feature = "shellnet")]
    fn write_test_private_json(path: &std::path::Path, value: &serde_json::Value) {
        let bytes = serde_json::to_vec_pretty(value).unwrap();
        super::write_pool_private(path, &bytes).unwrap();
    }

    #[test]
    fn subscription_mock_flags_are_all_or_nothing() {
        use crate::cli::args::MockFlags;

        assert!(!super::subscription_mock_mode(&MockFlags {
            mock_model: false,
            mock_chain: false,
        })
        .unwrap());
        assert!(super::subscription_mock_mode(&MockFlags {
            mock_model: true,
            mock_chain: true,
        })
        .unwrap());
        for mock in [
            MockFlags {
                mock_model: true,
                mock_chain: false,
            },
            MockFlags {
                mock_model: false,
                mock_chain: true,
            },
        ] {
            let error = super::subscription_mock_mode(&mock)
                .expect_err("half-mock subscription must fail")
                .to_string();
            assert!(error.contains("--mock-model and --mock-chain together"));
        }
    }

    #[test]
    fn mock_subscription_place_status_cancel_persists_exact_reserve() {
        let dir = std::env::temp_dir().join(format!(
            "dexdo-subscription-mock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let endpoints = dir.join("endpoints.json");
        let backend = dexdo_core::MockChainBackend::new(
            endpoints.clone(),
            dexdo_core::ProtocolConsts::canonical(),
            dexdo_core::DobParams::canonical(),
        );
        let note = dexdo_core::LocalNote::from_seed(&[61; 32]);
        let other_note = dexdo_core::LocalNote::from_seed(&[62; 32]);
        let frame_model = "qwen--qwen3--32b";
        let order_book = format!(
            "0:{}",
            dexdo_core::model_hash_for(frame_model)
                .strip_prefix("0x")
                .unwrap()
        );
        let place_args = crate::cli::args::SubscriptionPlaceArgs {
            note_key: None,
            max_price_per_tick: dexdo_core::PRICE_STEP,
            ticks: u128::from(dexdo_core::SUBSCRIPTION_WEEKS),
        };
        let plan = super::subscription_place_plan(&place_args).unwrap();
        assert!(backend
            .place_subscription_order(
                &order_book,
                &note,
                place_args.max_price_per_tick,
                place_args.ticks,
                plan.reserve.total_escrow - 1,
                dexdo_core::order_flags::AON | dexdo_core::order_flags::SUBSCRIPTION,
                super::buy_order_deadline().unwrap(),
            )
            .is_err());
        assert!(backend
            .place_subscription_order(
                &order_book,
                &note,
                place_args.max_price_per_tick,
                place_args.ticks,
                plan.reserve.total_escrow,
                dexdo_core::order_flags::AON
                    | dexdo_core::order_flags::SUBSCRIPTION
                    | dexdo_core::order_flags::MARKET,
                super::buy_order_deadline().unwrap(),
            )
            .is_err());
        let place = crate::cli::args::SubscriptionCommand::Place(place_args);
        let placed = super::execute_mock_subscription_command(
            &backend,
            &note,
            frame_model,
            &order_book,
            &place,
            Some(plan),
        )
        .unwrap();
        assert!(placed.contains("network=mock"));
        assert!(placed.contains("order_id=1"));
        assert!(placed.contains(&format!("deposit={}", plan.reserve.deposit)));
        assert!(placed.contains(&format!("buyer_bond={}", plan.reserve.buyer_bond)));
        assert!(placed.contains(&format!("total_escrow={}", plan.reserve.total_escrow)));

        let reloaded = dexdo_core::MockChainBackend::new(
            endpoints,
            dexdo_core::ProtocolConsts::canonical(),
            dexdo_core::DobParams::canonical(),
        );
        assert!(reloaded
            .subscription_order(&order_book, 1, &other_note)
            .unwrap()
            .is_none());
        assert!(reloaded
            .subscription_order("0:wrong-book", 1, &note)
            .unwrap()
            .is_none());

        let status = crate::cli::args::SubscriptionCommand::Status { order_id: 1 };
        let rendered = super::execute_mock_subscription_command(
            &reloaded,
            &note,
            frame_model,
            &order_book,
            &status,
            None,
        )
        .unwrap();
        assert!(rendered.contains("resting=true"));
        assert!(rendered.contains(&format!("total_escrow={}", plan.reserve.total_escrow)));

        let cancel = crate::cli::args::SubscriptionCommand::Cancel { order_id: 1 };
        let cancelled = super::execute_mock_subscription_command(
            &reloaded,
            &note,
            frame_model,
            &order_book,
            &cancel,
            None,
        )
        .unwrap();
        assert!(cancelled.contains(&format!("refund={}", plan.reserve.total_escrow)));
        assert!(super::execute_mock_subscription_command(
            &reloaded,
            &note,
            frame_model,
            &order_book,
            &status,
            None,
        )
        .is_err());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn subscription_term_and_balance_guards_fail_closed() {
        assert_eq!(super::subscription_order_flags(), 0x60);
        let price = dexdo_core::PRICE_STEP;
        for ticks in [4u128, dexdo_core::SUBSCRIPTION_MAX_TICKS] {
            let args = crate::cli::args::SubscriptionPlaceArgs {
                note_key: None,
                max_price_per_tick: price,
                ticks,
            };
            let plan = super::subscription_place_plan(&args).expect("valid subscription");
            let expected = subscription_test_reserve(ticks, price);
            assert_eq!(plan.reserve, expected);
            assert_eq!(
                plan.reserve.deposit,
                dexdo_core::required_escrow_for_buy(ticks, price),
                "ordinary deposit remains bond-free"
            );
        }
        for ticks in [0u128, 1, 3, 5, dexdo_core::SUBSCRIPTION_MAX_TICKS + 4] {
            let args = crate::cli::args::SubscriptionPlaceArgs {
                note_key: None,
                max_price_per_tick: price,
                ticks,
            };
            assert!(
                super::subscription_place_plan(&args).is_err(),
                "ticks={ticks}"
            );
        }
        for invalid_price in [0, price - 1, price + 1] {
            let args = crate::cli::args::SubscriptionPlaceArgs {
                note_key: None,
                max_price_per_tick: invalid_price,
                ticks: 4,
            };
            assert!(
                super::subscription_place_plan(&args).is_err(),
                "price={invalid_price}"
            );
        }
        let largest_step = u128::MAX - (u128::MAX % price);
        let overflow = crate::cli::args::SubscriptionPlaceArgs {
            note_key: None,
            max_price_per_tick: largest_step,
            ticks: 4,
        };
        assert!(super::subscription_place_plan(&overflow)
            .expect_err("fee multiplication overflow")
            .to_string()
            .contains("overflows u128"));

        let reserve = subscription_test_reserve(4, price);
        assert!(super::ensure_subscription_note_balance(None, reserve).is_err());
        assert!(
            super::ensure_subscription_note_balance(Some(reserve.total_escrow - 1), reserve)
                .is_err()
        );
        assert_eq!(
            super::ensure_subscription_note_balance(Some(reserve.total_escrow), reserve).unwrap(),
            reserve.total_escrow
        );
        assert_eq!(
            super::ensure_subscription_note_balance(Some(reserve.total_escrow + 1), reserve)
                .unwrap(),
            reserve.total_escrow + 1
        );
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn subscription_preflight_requires_exact_total_and_rejects_market_semantics() {
        let price = dexdo_core::PRICE_STEP;
        let ticks = u128::from(dexdo_core::SUBSCRIPTION_WEEKS);
        let reserve = subscription_test_reserve(ticks, price);
        let exact_flags = dexdo_core::order_flags::AON | dexdo_core::order_flags::SUBSCRIPTION;

        assert!(super::validate_subscription_order_terms(
            price,
            ticks,
            reserve.total_escrow,
            exact_flags,
            2,
            1,
        )
        .is_ok());
        assert!(super::validate_subscription_order_terms(
            price,
            ticks,
            reserve.total_escrow - 1,
            exact_flags,
            2,
            1,
        )
        .is_err());
        assert!(super::validate_subscription_order_terms(
            price,
            ticks,
            reserve.total_escrow + 1,
            exact_flags,
            2,
            1,
        )
        .is_err());
        let market_error = super::validate_subscription_order_terms(
            price,
            ticks,
            reserve.total_escrow,
            exact_flags | dexdo_core::order_flags::MARKET,
            2,
            1,
        )
        .unwrap_err();
        assert!(
            market_error
                .to_string()
                .contains("MARKET orders are unsupported"),
            "{market_error:#}"
        );
        assert!(
            dexdo_core::check_buy_deposit_headroom(reserve.deposit, ticks, price).is_ok(),
            "ordinary BUY remains exactly deposit-only"
        );
        assert!(
            dexdo_core::check_subscription_buy_reserve(reserve.deposit, ticks, price).is_err(),
            "the same deposit cannot omit a subscription buyer bond"
        );
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn subscription_journal_rejects_every_money_field_mutation() {
        let journal = subscription_test_journal(30, 2_000);
        assert!(journal.validate(&journal.note_addr).is_ok());

        let mut deposit = journal.clone();
        deposit.deposit += 1;
        let mut buyer_bond = journal.clone();
        buyer_bond.buyer_bond += 1;
        let mut total = journal.clone();
        total.escrow += 1;
        for mutated in [deposit, buyer_bond, total] {
            assert!(mutated.validate(&mutated.note_addr).is_err());
        }
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn subscription_lower_clearing_renders_exact_limit_remainder_refund() {
        let ticks = u128::from(dexdo_core::SUBSCRIPTION_WEEKS);
        let limit = 2 * dexdo_core::PRICE_STEP;
        let clearing = dexdo_core::PRICE_STEP;
        let reserve = subscription_test_reserve(ticks, limit);
        let refund = dexdo_core::subscription_buy_clearing_refund(ticks, limit, clearing).unwrap();
        let frame_model = "qwen--qwen3--32b".to_string();
        let fill = super::BuyerJournalMatch {
            token_contract: subscription_test_tc('3'),
            order_id: 31,
            ticks,
            clearing_price: clearing,
        };
        let record = super::BuyerSubscriptionOrderRecord {
            order_book: subscription_test_book(),
            model_hash: dexdo_core::model_hash_for(&frame_model),
            frame_model,
            order_id: 31,
            max_price_per_tick: limit,
            ticks,
            deposit: reserve.deposit,
            buyer_bond: reserve.buyer_bond,
            escrow: reserve.total_escrow,
            flags: dexdo_core::order_flags::AON | dexdo_core::order_flags::SUBSCRIPTION,
            deadline: 2_000,
            fill_cursor: dexdo_core::MatchWatchCursor::new(0),
            phase: super::BuyerSubscriptionPhase::Matched,
            matched: Some(super::BuyerSubscriptionMatch::from_fill(&fill)),
        };
        let snapshot = dexdo_core::OrderBookSnapshot {
            frame_model: "qwen--qwen3--32b".to_string(),
            model_hash: dexdo_core::model_hash_for("qwen--qwen3--32b"),
            order_book: record.order_book.clone(),
            stats: None,
            orders: Vec::new(),
        };
        let rendered = super::render_subscription_record(
            &snapshot,
            &record,
            &subscription_test_note(),
            false,
            None,
        )
        .unwrap();
        assert!(rendered.contains(&format!("deposit={}", reserve.deposit)));
        assert!(rendered.contains(&format!("buyer_bond={}", reserve.buyer_bond)));
        assert!(rendered.contains(&format!("total_escrow={}", reserve.total_escrow)));
        assert!(rendered.contains(&format!("price_improvement_refund={refund}")));
    }

    #[cfg(feature = "shellnet")]
    proptest::proptest! {
        #[test]
        fn every_accepted_subscription_volume_is_four_equal_weeks(
            ticks_per_week in 1u128..=(
                dexdo_core::SUBSCRIPTION_MAX_TICKS
                    / u128::from(dexdo_core::SUBSCRIPTION_WEEKS)
            ),
        ) {
            let ticks = ticks_per_week * u128::from(dexdo_core::SUBSCRIPTION_WEEKS);
            let escrow = dexdo_core::subscription_buy_reserve(
                ticks,
                dexdo_core::PRICE_STEP,
            ).unwrap().total_escrow;
            proptest::prop_assert!(super::validate_subscription_order_terms(
                dexdo_core::PRICE_STEP,
                ticks,
                escrow,
                dexdo_core::order_flags::AON | dexdo_core::order_flags::SUBSCRIPTION,
                2,
                1,
            ).is_ok());
            let invalid = ticks + 1;
            let invalid_escrow = dexdo_core::subscription_buy_reserve(
                invalid,
                dexdo_core::PRICE_STEP,
            ).unwrap().total_escrow;
            proptest::prop_assert!(super::validate_subscription_order_terms(
                dexdo_core::PRICE_STEP,
                invalid,
                invalid_escrow,
                dexdo_core::order_flags::AON | dexdo_core::order_flags::SUBSCRIPTION,
                2,
                1,
            ).is_err());
        }

        /// The status pair over CONTRACT-REACHABLE books only, proved reachable by the exact getter
        /// decoders rather than asserted to be.
        /// Every figure is derived from one canonical shape: the volume is a whole number of ticks
        /// divisible by `SUB_WEEKS`(`InferenceOrderBook.sol:1309`), `fundedTokens` is exactly
        /// `tokensPerWeek * SUB_WEEKS`, the claim pipeline is monotonic and never below the tick
        /// `acceptProbe` seeded, and the cumulative claim never passes the week's `_claimCap`. A
        /// generator free to violate those relations proves arithmetic about a chain that cannot
        /// exist.
        #[test]
        fn subscription_quota_is_exactly_the_contract_ceiling_minus_pending_inside_the_week(
            weeks_of_ticks in 1u128..=4,
            week_index in 0u8..dexdo_core::SUBSCRIPTION_WEEKS,
            claimed_ticks in 0u128..=4,
            settled_lag in 0u128..=1,
        ) {
            let tick = dexdo_core::TICK_SIZE;
            let weeks = u128::from(dexdo_core::SUBSCRIPTION_WEEKS);
            let tokens_per_week = weeks_of_ticks * tick;
            let funded_tokens = tokens_per_week * weeks;
            // Where the last booked boundary re-based the week: the cumulative claim at that point,
            // which is at least the probe's tick and at most everything the term funds.
            let week_base_tokens =
                (u128::from(week_index) * tokens_per_week).max(tick).min(funded_tokens);
            let cap = (week_base_tokens + tokens_per_week).min(funded_tokens);
            // Consumption inside the recorded week never passes that ceiling.
            let claimed_in_week = (claimed_ticks * tick).min(cap - week_base_tokens);
            let tokens_pending = week_base_tokens + claimed_in_week;
            // The pipeline is monotonic: `tokensFinal <= tokensSuperseded <= tokensPending`.
            let tokens_final = tokens_pending.saturating_sub(settled_lag * tick).max(tick);
            let tokens_superseded = tokens_final
                .max(tokens_pending.saturating_sub(tick))
                .min(tokens_pending);

            let order = subscription_test_record(39);
            let mut facts = subscription_test_facts(&order, &subscription_test_note());
            // Prove the shape decodes through the EXACT production getter decoders before any
            // behaviour is asserted on it.
            facts.state = dexdo_core::DealChainState::decode_getter(&serde_json::json!({
                "funded": true,
                "opened": true,
                "probeAccepted": true,
                "disputed": false,
                "deposit": facts.state.deposit.to_string(),
                "probeTick": "0",
                "finalizedOwed": "0",
                "tokensFinal": tokens_final.to_string(),
                "tokensSuperseded": tokens_superseded.to_string(),
                "tokensPending": tokens_pending.to_string(),
                "probeTime": "1",
                "prevClaimTime": "1",
                "lastClaimTime": "1",
                "disputeTime": "0",
                "fundedTime": "1"
            }))
            .expect("a canonical claim pipeline decodes");
            facts.subscription = dexdo_core::DealSubscription::decode_getter(&serde_json::json!({
                "dealFlags": dexdo_core::order_flags::SUBSCRIPTION.to_string(),
                "subWeeks": dexdo_core::SUBSCRIPTION_WEEKS.to_string(),
                "weekIndex": week_index.to_string(),
                "tokensPerWeek": tokens_per_week.to_string(),
                "fundedTokens": funded_tokens.to_string(),
                "tokensPaid": (u128::from(week_index) * tokens_per_week).max(tick).to_string(),
                "periodStart": "1",
                "weekBaseTokens": week_base_tokens.to_string()
            }))
            .expect("canonical weekly books decode");

            let view = super::subscription_quota_view(&facts).unwrap();
            proptest::prop_assert_eq!(view.claimed_current_week, claimed_in_week);
            proptest::prop_assert_eq!(view.remaining_current_week, cap - tokens_pending);
        }

        /// The same shape with ONE relation broken must fail closed, not compute.
        #[test]
        fn malformed_getter_relations_are_rejected_before_any_quota_is_computed(
            regress in 1u128..=4,
        ) {
            let tick = dexdo_core::TICK_SIZE;
            // `tokensPending` below `tokensFinal` reverses the claim pipeline: the strict decoder
            // must refuse it outright rather than let a quota be derived from it.
            let broken = dexdo_core::DealChainState::decode_getter(&serde_json::json!({
                "funded": true,
                "opened": true,
                "probeAccepted": true,
                "disputed": false,
                "deposit": "1000",
                "probeTick": "0",
                "finalizedOwed": "0",
                "tokensFinal": ((regress + 1) * tick).to_string(),
                "tokensSuperseded": ((regress + 1) * tick).to_string(),
                "tokensPending": (regress * tick).to_string(),
                "probeTime": "1",
                "prevClaimTime": "1",
                "lastClaimTime": "1",
                "disputeTime": "0",
                "fundedTime": "1"
            }));
            proptest::prop_assert!(broken.is_err());
        }

        #[test]
        fn subscription_oneshot_never_exceeds_remaining_week_quota(
            requested in 1u64..=u32::MAX as u64,
            remaining in 1u64..=u32::MAX as u64,
        ) {
            let allowed =
                super::subscription_oneshot_budget(requested, Some(remaining)).unwrap();
            proptest::prop_assert_eq!(allowed, requested.min(remaining));
        }
    }

    #[test]
    fn exhausted_subscription_week_sends_no_oneshot_request() {
        let error = super::subscription_oneshot_budget(64, Some(0)).unwrap_err();
        assert!(error.to_string().contains("quota is exhausted"));
        assert_eq!(super::subscription_oneshot_budget(64, None).unwrap(), 64);
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn subscription_quota_rejects_underflow_over_quota_and_locked_exposure_overflow() {
        let order = subscription_test_record(39);
        let mut facts = subscription_test_facts(&order, &subscription_test_note());
        facts.subscription.week_base_tokens = 20;
        facts.state.tokens_pending = 19;
        assert!(super::subscription_quota_view(&facts)
            .unwrap_err()
            .to_string()
            .contains("below weekBaseTokens"));

        facts.state.tokens_pending = 31;
        facts.state.tokens_final = 31;
        facts.state.tokens_superseded = 31;
        facts.subscription.tokens_per_week = 10;
        assert!(super::subscription_quota_view(&facts)
            .unwrap_err()
            .to_string()
            .contains("exceeds the recorded week claim ceiling"));

        facts.state.tokens_pending = 20;
        facts.state.tokens_final = 20;
        facts.state.tokens_superseded = 20;
        facts.subscription.tokens_per_week = 10;
        facts.state.deposit = u128::MAX;
        facts.buyer_bond.bond_held = 1;
        assert!(super::subscription_quota_view(&facts)
            .unwrap_err()
            .to_string()
            .contains("overflows u128"));
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn terminal_subscription_has_zero_usable_week_quota_but_reports_locked_exposure() {
        let order = subscription_test_record(39);
        let mut facts = subscription_test_facts(&order, &subscription_test_note());
        facts.state.disputed = true;
        facts.state.tokens_pending = u128::MAX;
        facts.subscription.week_base_tokens = 0;
        let view = super::subscription_quota_view(&facts).unwrap();
        assert_eq!(view.claimed_current_week, 0);
        assert_eq!(view.remaining_current_week, 0);
        assert_eq!(
            view.buyer_locked_total,
            facts.state.deposit + facts.state.probe_tick + facts.buyer_bond.bond_held
        );
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn open_subscription_in_final_claim_grace_has_no_additional_week_quota() {
        let order = subscription_test_record(39);
        let mut facts = subscription_test_facts(&order, &subscription_test_note());
        let recorded_base = 2 * dexdo_core::TICK_SIZE;
        let recorded_after_boundary = 123;
        facts.subscription.week_index = facts.subscription.sub_weeks;
        facts.subscription.week_base_tokens = recorded_base;
        facts.state.tokens_pending = recorded_base + recorded_after_boundary;

        let view = super::subscription_quota_view(&facts).unwrap();
        assert_eq!(view.claimed_current_week, recorded_after_boundary);
        assert_eq!(view.remaining_current_week, 0);
        assert_eq!(
            view.buyer_locked_total,
            facts.state.deposit + facts.state.probe_tick + facts.buyer_bond.bond_held
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn subscription_submit_posts_exact_shape_once_and_persists_resting_order() {
        let (dir, _cleanup) = buyer_journal_test_dir("subscription-exact-submit");
        let journal_path = dir.join("submit.json");
        let state_path = dir.join("state.json");
        let note_addr = subscription_test_note();
        let note = dexdo_core::Address::parse(&note_addr).unwrap();
        let keys = dexdo_core::KeyPair::from_secret_hex(&"22".repeat(32)).unwrap();
        let order_id = 40;
        let deadline = super::buy_order_deadline().unwrap();
        let placement = subscription_test_placement(order_id, deadline);
        let ops = FakeSubscriptionOps::new(order_id);
        ops.placements.lock().unwrap().push(placement);
        ops.active.store(true, std::sync::atomic::Ordering::SeqCst);
        let ticks = u128::from(dexdo_core::SUBSCRIPTION_WEEKS);
        let reserve = subscription_test_reserve(ticks, dexdo_core::PRICE_STEP);
        let escrow = reserve.total_escrow;
        let frame_model = "qwen--qwen3--32b";
        let model_hash = dexdo_core::model_hash_for(frame_model);

        let record = super::submit_subscription_with_journal(
            &ops,
            &note,
            &keys,
            &subscription_test_book(),
            frame_model,
            &model_hash,
            dexdo_core::PRICE_STEP,
            ticks,
            escrow,
            deadline,
            &journal_path,
            &state_path,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .expect("one exact resting subscription");

        assert_eq!(record.order_id, order_id);
        assert_eq!(record.deposit, reserve.deposit);
        assert_eq!(record.buyer_bond, reserve.buyer_bond);
        assert_eq!(record.escrow, reserve.total_escrow);
        assert!(record.matched.is_none());
        assert!(
            !journal_path.exists(),
            "proved placement clears submit journal"
        );
        let calls = ops.calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "exactly one money POST");
        assert_eq!(
            calls[0],
            SubscriptionSubmitCall {
                order_book: subscription_test_book(),
                model_hash,
                max_price_per_tick: dexdo_core::PRICE_STEP,
                ticks,
                escrow,
                flags: dexdo_core::order_flags::AON | dexdo_core::order_flags::SUBSCRIPTION,
                deadline,
            }
        );
        let state =
            super::load_buyer_subscription_state(&state_path, &note_addr).expect("v3 state");
        assert_eq!(state.orders, vec![record]);
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn subscription_submit_accepts_one_immediate_full_fill() {
        let (dir, _cleanup) = buyer_journal_test_dir("subscription-immediate-fill");
        let journal_path = dir.join("submit.json");
        let state_path = dir.join("state.json");
        let note_addr = subscription_test_note();
        let note = dexdo_core::Address::parse(&note_addr).unwrap();
        let keys = dexdo_core::KeyPair::from_secret_hex(&"22".repeat(32)).unwrap();
        let order_id = 45;
        let deadline = super::buy_order_deadline().unwrap();
        let ops = FakeSubscriptionOps::new(order_id);
        ops.placements
            .lock()
            .unwrap()
            .push(subscription_test_placement(order_id, deadline));
        let ticks = u128::from(dexdo_core::SUBSCRIPTION_WEEKS);
        ops.fills.lock().unwrap().push((
            order_id,
            dexdo_core::MatchedFill {
                order_id,
                token_contract: subscription_test_tc('3'),
                ticks,
                price_per_tick: dexdo_core::PRICE_STEP,
            },
        ));
        let escrow = subscription_test_reserve(ticks, dexdo_core::PRICE_STEP).total_escrow;
        let model = "qwen--qwen3--32b";
        let record = super::submit_subscription_with_journal(
            &ops,
            &note,
            &keys,
            &subscription_test_book(),
            model,
            &dexdo_core::model_hash_for(model),
            dexdo_core::PRICE_STEP,
            ticks,
            escrow,
            deadline,
            &journal_path,
            &state_path,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .expect("one immediate full seller fill");
        assert_eq!(
            record.matched.unwrap().token_contract,
            subscription_test_tc('3')
        );
        assert_eq!(ops.calls.lock().unwrap().len(), 1);
        assert!(!journal_path.exists());
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn lost_subscription_response_reconciles_without_second_boc() {
        let (dir, _cleanup) = buyer_journal_test_dir("subscription-lost-response");
        let journal_path = dir.join("submit.json");
        let state_path = dir.join("state.json");
        let note_addr = subscription_test_note();
        let note = dexdo_core::Address::parse(&note_addr).unwrap();
        let keys = dexdo_core::KeyPair::from_secret_hex(&"22".repeat(32)).unwrap();
        let order_id = 50;
        let deadline = super::buy_order_deadline().unwrap();
        let ops = FakeSubscriptionOps::new(order_id);
        ops.ambiguous_after_post
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let ticks = u128::from(dexdo_core::SUBSCRIPTION_WEEKS);
        let escrow = subscription_test_reserve(ticks, dexdo_core::PRICE_STEP).total_escrow;
        let frame_model = "qwen--qwen3--32b";
        let model_hash = dexdo_core::model_hash_for(frame_model);

        let error = super::submit_subscription_with_journal(
            &ops,
            &note,
            &keys,
            &subscription_test_book(),
            frame_model,
            &model_hash,
            dexdo_core::PRICE_STEP,
            ticks,
            escrow,
            deadline,
            &journal_path,
            &state_path,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .expect_err("lost response remains ambiguous until a chain fact appears");
        assert!(error.to_string().contains("journal retained"), "{error:#}");
        assert!(journal_path.exists());
        assert_eq!(ops.calls.lock().unwrap().len(), 1);

        ops.placements
            .lock()
            .unwrap()
            .push(subscription_test_placement(order_id, deadline));
        ops.active.store(true, std::sync::atomic::Ordering::SeqCst);
        let journal = match super::load_buyer_money_journal(&journal_path, &note_addr).unwrap() {
            Some(super::BuyerMoneyJournal::Subscription(journal)) => *journal,
            other => panic!("expected retained subscription journal, got {other:?}"),
        };
        let record = super::reconcile_subscription_submit(
            &ops,
            &journal_path,
            &state_path,
            &journal,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .expect("restart proves the original placement");
        assert_eq!(record.order_id, order_id);
        assert_eq!(
            ops.calls.lock().unwrap().len(),
            1,
            "restart must not create a second signed BOC"
        );
        assert!(!journal_path.exists());
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn subscription_submit_reconciliation_coalesces_identical_placement_duplicates() {
        let (dir, _cleanup) = buyer_journal_test_dir("subscription-identical-placements");
        let journal_path = dir.join("submit.json");
        let state_path = dir.join("state.json");
        let order_id = 55;
        let deadline = 2_000;
        let journal = subscription_test_journal(order_id, deadline);
        super::write_buyer_subscription_submit_journal(&journal_path, &journal)
            .expect("durable journal");
        let placement = subscription_test_placement(order_id, deadline);
        let ops = FakeSubscriptionOps::new(order_id);
        ops.placements
            .lock()
            .unwrap()
            .extend([placement.clone(), placement]);
        ops.active.store(true, std::sync::atomic::Ordering::SeqCst);

        let record = super::reconcile_subscription_submit(
            &ops,
            &journal_path,
            &state_path,
            &journal,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .expect("identical deliveries of one authenticated placement coalesce");
        assert_eq!(record.order_id, order_id);
        assert!(!journal_path.exists());
        let state = super::load_buyer_subscription_state(&state_path, &journal.note_addr).unwrap();
        assert_eq!(state.orders.len(), 1);
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn subscription_submit_reconciliation_rejects_conflicting_same_id_and_retains_journal() {
        let (dir, _cleanup) = buyer_journal_test_dir("subscription-conflicting-placements");
        let journal_path = dir.join("submit.json");
        let state_path = dir.join("state.json");
        let order_id = 56;
        let deadline = 2_000;
        let journal = subscription_test_journal(order_id, deadline);
        super::write_buyer_subscription_submit_journal(&journal_path, &journal)
            .expect("durable journal");
        let placement = subscription_test_placement(order_id, deadline);
        let mut conflicting = placement.clone();
        conflicting.deadline += 1;
        let ops = FakeSubscriptionOps::new(order_id);
        ops.placements
            .lock()
            .unwrap()
            .extend([placement, conflicting]);

        let error = super::reconcile_subscription_submit(
            &ops,
            &journal_path,
            &state_path,
            &journal,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .expect_err("same order id with conflicting authenticated facts must fail closed");
        assert!(
            error.to_string().contains("conflicting authenticated"),
            "{error:#}"
        );
        assert!(journal_path.exists(), "contradiction retains the journal");
        assert!(
            !state_path.exists(),
            "contradiction is detected before durable order state changes"
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn subscription_match_crash_after_handle_keeps_journal_and_retry_converges() {
        let (dir, _cleanup) = buyer_journal_test_dir("subscription-match-crash-order");
        let journal_path = dir.join("submit.json");
        let state_path = dir.join("state.json");
        let state_backup = dir.join("state-before-match.json");
        let handle_marker = dir.join("buyer-handle.persisted");
        let order_id = 55;
        let deadline = 2_000;
        let journal = subscription_test_journal(order_id, deadline);
        super::write_buyer_subscription_submit_journal(&journal_path, &journal).unwrap();
        let ops = FakeSubscriptionOps::new(order_id);
        ops.placements
            .lock()
            .unwrap()
            .push(subscription_test_placement(order_id, deadline));
        ops.fills.lock().unwrap().push((
            order_id,
            dexdo_core::MatchedFill {
                order_id,
                token_contract: subscription_test_tc('3'),
                ticks: journal.ticks,
                price_per_tick: journal.max_price_per_tick,
            },
        ));

        let injected = std::sync::atomic::AtomicBool::new(false);
        let crash_after_handle =
            |_order: &super::BuyerSubscriptionOrderRecord, matched: &super::BuyerJournalMatch| {
                std::fs::write(&handle_marker, matched.token_contract.as_bytes()).unwrap();
                if !injected.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    std::fs::rename(&state_path, &state_backup).unwrap();
                    std::fs::create_dir(&state_path).unwrap();
                }
                Ok(crate::cli::deals::make_handle_id(
                    &matched.token_contract,
                    crate::cli::deals::DealHandleRole::Buyer,
                ))
            };
        super::reconcile_subscription_submit(
            &ops,
            &journal_path,
            &state_path,
            &journal,
            std::time::Duration::ZERO,
            &crash_after_handle,
        )
        .await
        .expect_err("injected crash point must prevent state/cursor commit");
        assert!(handle_marker.exists(), "handle persistence happens first");
        assert!(journal_path.exists(), "money journal must remain retained");

        std::fs::remove_dir(&state_path).unwrap();
        std::fs::rename(&state_backup, &state_path).unwrap();
        let before_retry =
            super::load_buyer_subscription_state(&state_path, &journal.note_addr).unwrap();
        assert_eq!(
            before_retry.orders[0].phase,
            super::BuyerSubscriptionPhase::Resting
        );
        assert!(before_retry.orders[0].matched.is_none());

        let resumed = super::reconcile_subscription_submit(
            &ops,
            &journal_path,
            &state_path,
            &journal,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .expect("retry adopts the same TC and handle without another payment");
        assert_eq!(
            resumed.matched.as_ref().unwrap().deal_handle,
            crate::cli::deals::make_handle_id(
                &subscription_test_tc('3'),
                crate::cli::deals::DealHandleRole::Buyer,
            )
        );
        assert_eq!(ops.calls.lock().unwrap().len(), 0, "no submit was retried");
        assert!(
            !journal_path.exists(),
            "journal clears only after atomic state commit"
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn subscription_fill_reconciliation_accepts_one_full_seller_only() {
        let (dir, _cleanup) = buyer_journal_test_dir("subscription-fill-shape");
        let state_path = dir.join("state.json");
        let deadline = 2_000;
        let journal = subscription_test_journal(60, deadline);
        let placement = subscription_test_placement(60, deadline);
        let mut state =
            super::BuyerSubscriptionState::empty(&journal.note_addr).expect("empty state");
        super::record_subscription_placement(&mut state, &journal, &placement).expect("placement");
        super::write_buyer_subscription_state(&state_path, &state).unwrap();
        let full = dexdo_core::MatchedFill {
            order_id: 60,
            token_contract: subscription_test_tc('3'),
            ticks: journal.ticks,
            price_per_tick: journal.max_price_per_tick,
        };
        let ops = FakeSubscriptionOps::new(60);
        ops.fills
            .lock()
            .unwrap()
            .extend([(60, full.clone()), (60, full.clone())]);
        let record = super::sync_subscription_match_once(
            &ops,
            &state_path,
            &journal.note_addr,
            &journal.order_book,
            60,
            &persist_subscription_test_handle,
        )
        .await
        .expect("duplicate delivery of one event is idempotent");
        assert_eq!(record.matched.unwrap().token_contract, full.token_contract);

        for (label, fills) in [
            (
                "partial",
                vec![(
                    60,
                    dexdo_core::MatchedFill {
                        ticks: journal.ticks - 1,
                        ..full.clone()
                    },
                )],
            ),
            (
                "multiple",
                vec![
                    (60, full.clone()),
                    (
                        60,
                        dexdo_core::MatchedFill {
                            token_contract: subscription_test_tc('4'),
                            ..full.clone()
                        },
                    ),
                ],
            ),
        ] {
            let case_path = dir.join(format!("{label}.json"));
            let mut state =
                super::BuyerSubscriptionState::empty(&journal.note_addr).expect("empty state");
            super::record_subscription_placement(&mut state, &journal, &placement)
                .expect("placement");
            super::write_buyer_subscription_state(&case_path, &state).unwrap();
            let case = FakeSubscriptionOps::new(60);
            *case.fills.lock().unwrap() = fills;
            assert!(
                super::sync_subscription_match_once(
                    &case,
                    &case_path,
                    &journal.note_addr,
                    &journal.order_book,
                    60,
                    &persist_subscription_test_handle,
                )
                .await
                .is_err(),
                "{label} fill must fail closed"
            );
        }
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn subscription_fill_rejects_wrong_order_owner_model_flags_and_funded_volume() {
        let (dir, _cleanup) = buyer_journal_test_dir("subscription-fill-facts");
        let deadline = 2_000;
        let journal = subscription_test_journal(61, deadline);
        let placement = subscription_test_placement(61, deadline);
        let full = dexdo_core::MatchedFill {
            order_id: 61,
            token_contract: subscription_test_tc('3'),
            ticks: journal.ticks,
            price_per_tick: journal.max_price_per_tick,
        };

        let wrong_embedded_order_path = dir.join("wrong-embedded-order.json");
        let mut state =
            super::BuyerSubscriptionState::empty(&journal.note_addr).expect("empty state");
        let record = super::record_subscription_placement(&mut state, &journal, &placement)
            .expect("placement");
        super::write_buyer_subscription_state(&wrong_embedded_order_path, &state).unwrap();
        let wrong_order = FakeSubscriptionOps::new(61);
        wrong_order.fills.lock().unwrap().push((
            61,
            dexdo_core::MatchedFill {
                order_id: 62,
                ..full.clone()
            },
        ));
        let error = super::sync_subscription_match_once(
            &wrong_order,
            &wrong_embedded_order_path,
            &journal.note_addr,
            &journal.order_book,
            61,
            &persist_subscription_test_handle,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("embedded order id"), "{error:#}");

        let canonical = subscription_test_facts(&record, &journal.note_addr);
        let mut cases = Vec::new();
        let mut wrong_owner = canonical.clone();
        wrong_owner.buyer_note = subscription_test_tc('8');
        cases.push(("wrong-owner", wrong_owner));
        let mut wrong_model = canonical.clone();
        wrong_model.model_name = "other--model--1".to_string();
        wrong_model.model_hash = dexdo_core::model_hash_for(&wrong_model.model_name);
        cases.push(("wrong-model", wrong_model));
        let mut wrong_flags = canonical.clone();
        wrong_flags.subscription.deal_flags = 0;
        wrong_flags.subscription.sub_weeks = 0;
        cases.push(("wrong-flags", wrong_flags));
        let mut wrong_funded_volume = canonical.clone();
        wrong_funded_volume.subscription.funded_tokens -= 1;
        cases.push(("wrong-funded-volume", wrong_funded_volume));
        let mut wrong_buyer_bond_required = canonical.clone();
        wrong_buyer_bond_required.buyer_bond.bond_required += 1;
        cases.push(("wrong-buyer-bond-required", wrong_buyer_bond_required));
        let mut wrong_buyer_bond_held = canonical.clone();
        wrong_buyer_bond_held.buyer_bond.bond_held -= 1;
        cases.push(("wrong-buyer-bond-held", wrong_buyer_bond_held));
        let mut wrong_seller_bond_required = canonical.clone();
        wrong_seller_bond_required.seller_bond.bond_required += 1;
        cases.push(("wrong-seller-bond-required", wrong_seller_bond_required));
        let mut wrong_seller_bond_held = canonical.clone();
        wrong_seller_bond_held.seller_bond.bond_held -= 1;
        cases.push(("wrong-seller-bond-held", wrong_seller_bond_held));
        let mut unfunded_seller_bond_with_money = canonical.clone();
        unfunded_seller_bond_with_money.seller_bond.bond_funded = false;
        cases.push((
            "unfunded-seller-bond-with-money",
            unfunded_seller_bond_with_money,
        ));

        for (label, facts) in cases {
            let state_path = dir.join(format!("{label}.json"));
            let mut state =
                super::BuyerSubscriptionState::empty(&journal.note_addr).expect("empty state");
            super::record_subscription_placement(&mut state, &journal, &placement)
                .expect("placement");
            super::write_buyer_subscription_state(&state_path, &state).unwrap();
            let ops = FakeSubscriptionOps::new(61);
            ops.fills.lock().unwrap().push((61, full.clone()));
            *ops.facts_override.lock().unwrap() = Some(facts);
            assert!(
                super::sync_subscription_match_once(
                    &ops,
                    &state_path,
                    &journal.note_addr,
                    &journal.order_book,
                    61,
                    &persist_subscription_test_handle,
                )
                .await
                .is_err(),
                "{label} TC facts must fail closed"
            );
        }
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn subscription_deal_identity_requires_exact_order_and_contract_flags() {
        let note_addr = subscription_test_note();
        let canonical_order = subscription_test_record(63);
        let matched = super::BuyerJournalMatch {
            token_contract: subscription_test_tc('3'),
            order_id: canonical_order.order_id,
            ticks: canonical_order.ticks,
            clearing_price: canonical_order.max_price_per_tick,
        };
        let canonical_facts = subscription_test_facts(&canonical_order, &note_addr);
        let expected_order_flags =
            dexdo_core::order_flags::AON | dexdo_core::order_flags::SUBSCRIPTION;

        for order_flags in u8::MIN..=u8::MAX {
            let mut order = canonical_order.clone();
            order.flags = order_flags;
            let accepted = super::validate_subscription_deal_facts(
                &note_addr,
                &order,
                &matched,
                &canonical_facts,
            )
            .is_ok();
            assert_eq!(
                accepted,
                order_flags == expected_order_flags,
                "book-side flags 0x{order_flags:02x}"
            );
        }

        for deal_flags in u8::MIN..=u8::MAX {
            let mut facts = canonical_facts.clone();
            facts.subscription.deal_flags = deal_flags;
            let accepted = super::validate_subscription_deal_facts(
                &note_addr,
                &canonical_order,
                &matched,
                &facts,
            )
            .is_ok();
            assert_eq!(
                accepted,
                deal_flags == dexdo_core::order_flags::SUBSCRIPTION,
                "TokenContract dealFlags 0x{deal_flags:02x}"
            );
        }
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn matched_unopened_subscription_accepts_zero_unfunded_seller_bond() {
        let note_addr = subscription_test_note();
        let order = subscription_test_record(64);
        let matched = super::BuyerJournalMatch {
            token_contract: subscription_test_tc('4'),
            order_id: order.order_id,
            ticks: order.ticks,
            clearing_price: order.max_price_per_tick,
        };
        let mut facts = subscription_test_facts(&order, &note_addr);
        facts.state.opened = false;
        facts.state.probe_accepted = false;
        facts.seller_bond.bond_funded = false;
        facts.seller_bond.bond_held = 0;

        super::validate_subscription_deal_facts(&note_addr, &order, &matched, &facts)
            .expect("matched unopened subscription legitimately has no seller bond yet");
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn explicit_and_historical_subscription_resume_share_quota_and_identity_checks() {
        use std::sync::atomic::Ordering;

        let note_addr = subscription_test_note();
        let record = subscription_test_record(65);
        let token_contract = subscription_test_tc('5');
        let chain = SubscriptionResumeChain {
            order_book: record.order_book.clone(),
            snapshot: subscription_test_snapshot(&record, &note_addr),
            snapshot_overrides: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            reject_target: None,
            due_boundaries: std::sync::Mutex::new(0),
            settle_bookings: std::sync::atomic::AtomicUsize::new(0),
            attributed_fills: std::sync::Mutex::new(Vec::new()),
            buy_posts: std::sync::atomic::AtomicUsize::new(0),
            lookback_reads: std::sync::atomic::AtomicUsize::new(0),
            target_checks: std::sync::atomic::AtomicUsize::new(0),
        };
        let explicit = super::classify_subscription_resume_target(
            &chain,
            &note_addr,
            &record.frame_model,
            &token_contract,
            None,
        )
        .await
        .unwrap()
        .expect("explicit subscription classified");
        let fill = dexdo_core::MatchedFill {
            order_id: record.order_id,
            token_contract: token_contract.clone(),
            ticks: record.ticks,
            price_per_tick: record.max_price_per_tick,
        };
        let historical = super::classify_subscription_resume_target(
            &chain,
            &note_addr,
            &record.frame_model,
            &token_contract,
            Some(&fill),
        )
        .await
        .unwrap()
        .expect("historical subscription classified");

        assert_eq!(explicit.ticks, historical.ticks);
        assert_eq!(explicit.quota, historical.quota);
        assert_eq!(explicit.facts, historical.facts);
        assert_eq!(explicit.order_id, None);
        assert_eq!(historical.order_id, Some(record.order_id));
        assert_eq!(chain.target_checks.load(Ordering::SeqCst), 2);
    }

    /// a restart mid-term must reconstruct the allowance the CONTRACT is on, not the one the
    /// stored getter still remembers. `weekBaseTokens`/`weekIndex` move when a week is BOOKED; a
    /// restart that lands after a boundary and before anyone settles reads week one's books and would
    /// otherwise resume onto a quota that was already spent -- permanently, for the rest of the term.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn restart_after_an_unbooked_boundary_reconstructs_the_new_week_allowance() {
        let (dir, _cleanup) = buyer_journal_test_dir("subscription-restart-weekly-allowance");
        let note_addr = subscription_test_note();
        let mut record = subscription_test_record(84);
        let tc = subscription_test_tc('a');
        record.phase = super::BuyerSubscriptionPhase::Matched;
        record.matched = Some(super::BuyerSubscriptionMatch {
            token_contract: tc.clone(),
            order_id: record.order_id,
            ticks: record.ticks,
            clearing_price: record.max_price_per_tick,
            deal_handle: crate::cli::deals::make_handle_id(
                &tc,
                crate::cli::deals::DealHandleRole::Buyer,
            ),
        });
        let state = super::BuyerSubscriptionState {
            schema: super::BUYER_SUBSCRIPTION_STATE_SCHEMA.to_string(),
            note_addr: note_addr.clone(),
            orders: vec![record.clone()],
        };
        let money_lock = super::BuyerMoneyLock {
            note_addr: note_addr.clone(),
            path: dir.join("money.lock"),
            journal_path: dir.join("money.json"),
            subscriptions_path: dir.join("subscriptions.json"),
            lock: None,
        };
        super::write_buyer_subscription_state(&money_lock.subscriptions_path, &state).unwrap();

        // Week one was drawn down and the seller claimed it. Nobody has booked the boundary the clock
        // has since crossed, so the getter still reports weekIndex=0 / weekBaseTokens=0.
        let mut snapshot = subscription_test_snapshot(&record, &note_addr);
        let weekly_quota = snapshot.subscription.tokens_per_week;
        snapshot.state.tokens_final = weekly_quota;
        snapshot.state.tokens_superseded = weekly_quota;
        snapshot.state.tokens_pending = weekly_quota;
        assert_eq!(snapshot.subscription.week_index, 0);
        assert_eq!(snapshot.subscription.week_base_tokens, 0);

        let chain = SubscriptionResumeChain {
            order_book: record.order_book.clone(),
            snapshot,
            snapshot_overrides: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            reject_target: None,
            // The chain has crossed one boundary; nobody has booked it, which is why the getter the
            // restart reads still reports week one's spent quota.
            due_boundaries: std::sync::Mutex::new(1),
            settle_bookings: std::sync::atomic::AtomicUsize::new(0),
            attributed_fills: std::sync::Mutex::new(Vec::new()),
            buy_posts: std::sync::atomic::AtomicUsize::new(0),
            lookback_reads: std::sync::atomic::AtomicUsize::new(0),
            target_checks: std::sync::atomic::AtomicUsize::new(0),
        };

        let selected = super::resolve_buyer_subscription_resume(
            &chain,
            &note_addr,
            &record.frame_model,
            None,
            &money_lock,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .unwrap()
        .expect("the durable subscription resumes mid-term");

        assert_eq!(
            chain
                .settle_bookings
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the restart must BOOK the due boundary, never predict it from the local clock"
        );
        assert_eq!(
            selected.quota.remaining_current_week, weekly_quota,
            "a restart across an unbooked boundary must resume onto the NEW week's whole quota"
        );
        assert_eq!(
            selected.quota.claimed_current_week, 0,
            "after booking, claimed and remaining must be read from the SAME fresh week base"
        );
        assert_eq!(
            super::subscription_oneshot_budget(
                64,
                Some(u64::try_from(selected.quota.remaining_current_week).unwrap()),
            )
            .unwrap(),
            64,
            "one-shot must not refuse on a stored zero the contract would have accepted"
        );
        assert_eq!(
            chain.buy_posts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "reconstructing an allowance posts no second BUY - which is all this counter can say: \
             the boundary booking it performs DOES move already-escrowed value"
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn historical_subscription_terminal_is_rejected_before_active_target_check() {
        use std::sync::atomic::Ordering;

        let note_addr = subscription_test_note();
        let record = subscription_test_record(66);
        let token_contract = subscription_test_tc('6');
        let mut snapshot = subscription_test_snapshot(&record, &note_addr);
        snapshot.state.disputed = true;
        let chain = SubscriptionResumeChain {
            order_book: record.order_book.clone(),
            snapshot,
            snapshot_overrides: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            reject_target: Some(token_contract.clone()),
            due_boundaries: std::sync::Mutex::new(0),
            settle_bookings: std::sync::atomic::AtomicUsize::new(0),
            attributed_fills: std::sync::Mutex::new(Vec::new()),
            buy_posts: std::sync::atomic::AtomicUsize::new(0),
            lookback_reads: std::sync::atomic::AtomicUsize::new(0),
            target_checks: std::sync::atomic::AtomicUsize::new(0),
        };
        let fill = dexdo_core::MatchedFill {
            order_id: record.order_id,
            token_contract: token_contract.clone(),
            ticks: record.ticks,
            price_per_tick: record.max_price_per_tick,
        };

        let error = super::classify_subscription_resume_target(
            &chain,
            &note_addr,
            &record.frame_model,
            &token_contract,
            Some(&fill),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("terminal/disputed"), "{error:#}");
        assert_eq!(
            chain.target_checks.load(Ordering::SeqCst),
            0,
            "terminal reconciliation must precede every live-target assertion"
        );
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn subscription_status_and_cancel_validate_exact_owned_resting_buy() {
        let owner = subscription_test_note();
        let ticks = u128::from(dexdo_core::SUBSCRIPTION_WEEKS);
        let reserve = subscription_test_reserve(ticks, dexdo_core::PRICE_STEP);
        let mut order = dexdo_core::OrderBookOrder {
            order_id: 70,
            owner_note: owner.clone(),
            token_contract: None,
            is_buy: true,
            price_per_tick: dexdo_core::PRICE_STEP,
            ticks,
            escrow: reserve.total_escrow,
            deadline: 200,
            flags: dexdo_core::order_flags::AON | dexdo_core::order_flags::SUBSCRIPTION,
            timestamp: 100,
        };
        let snapshot = |order: dexdo_core::OrderBookOrder| dexdo_core::OrderBookSnapshot {
            frame_model: "qwen--qwen3--32b".to_string(),
            model_hash: dexdo_core::model_hash_for("qwen--qwen3--32b"),
            order_book: subscription_test_book(),
            stats: Some(dexdo_core::OrderBookStats {
                next_order_id: 71,
                order_count: 1,
                executed_notional: 0,
                executed_ticks: 0,
            }),
            orders: vec![order],
        };
        assert!(super::validate_subscription_live_order(
            &snapshot(order.clone()).order_book,
            Some(&order),
            70,
            &owner
        )
        .is_ok());
        let journal = subscription_test_journal(70, 2_000);
        assert!(
            super::validate_subscription_journal_target(&journal, &snapshot(order.clone())).is_ok()
        );
        let mut wrong_book = snapshot(order.clone());
        wrong_book.order_book = subscription_test_tc('7');
        assert!(
            super::validate_subscription_journal_target(&journal, &wrong_book).is_err(),
            "a retained BOC journal cannot be reconciled against another book"
        );

        order.owner_note = subscription_test_tc('8');
        assert!(super::validate_subscription_live_order(
            &snapshot(order.clone()).order_book,
            Some(&order),
            70,
            &owner
        )
        .is_err());
        order.owner_note = owner.clone();
        order.flags = dexdo_core::order_flags::SUBSCRIPTION;
        assert!(super::validate_subscription_live_order(
            &snapshot(order.clone()).order_book,
            Some(&order),
            70,
            &owner
        )
        .is_err());
        order.flags = dexdo_core::order_flags::AON | dexdo_core::order_flags::SUBSCRIPTION;
        order.deadline = order.timestamp;
        assert!(super::validate_subscription_live_order(
            &snapshot(order.clone()).order_book,
            Some(&order),
            70,
            &owner
        )
        .is_err());
        order.deadline = 200;
        order.is_buy = false;
        order.token_contract = Some(subscription_test_tc('9'));
        assert!(super::validate_subscription_live_order(
            &snapshot(order.clone()).order_book,
            Some(&order),
            70,
            &owner
        )
        .is_err());
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn subscription_status_rejects_durable_terms_that_contradict_live_row() {
        let owner = subscription_test_note();
        let ticks = u128::from(dexdo_core::SUBSCRIPTION_WEEKS);
        let reserve = subscription_test_reserve(ticks, dexdo_core::PRICE_STEP);
        let order = dexdo_core::OrderBookOrder {
            order_id: 71,
            owner_note: owner.clone(),
            token_contract: None,
            is_buy: true,
            price_per_tick: dexdo_core::PRICE_STEP,
            ticks,
            escrow: reserve.total_escrow,
            deadline: 200,
            flags: dexdo_core::order_flags::AON | dexdo_core::order_flags::SUBSCRIPTION,
            timestamp: 100,
        };
        let snapshot = dexdo_core::OrderBookSnapshot {
            frame_model: "qwen--qwen3--32b".to_string(),
            model_hash: dexdo_core::model_hash_for("qwen--qwen3--32b"),
            order_book: subscription_test_book(),
            stats: None,
            orders: vec![order.clone()],
        };
        let mut state = super::BuyerSubscriptionState::empty(&owner).unwrap();
        let durable =
            super::ensure_subscription_record_from_order(&mut state, &snapshot, &order).unwrap();

        let mut contradictions = Vec::new();
        let mut record = durable.clone();
        record.max_price_per_tick += dexdo_core::PRICE_STEP;
        contradictions.push(record);
        let mut record = durable.clone();
        record.ticks += u128::from(dexdo_core::SUBSCRIPTION_WEEKS);
        contradictions.push(record);
        let mut record = durable.clone();
        record.deposit += 1;
        contradictions.push(record);
        let mut record = durable.clone();
        record.buyer_bond += 1;
        contradictions.push(record);
        let mut record = durable.clone();
        record.escrow += 1;
        contradictions.push(record);
        let mut record = durable.clone();
        record.flags = dexdo_core::order_flags::SUBSCRIPTION;
        contradictions.push(record);
        let mut record = durable.clone();
        record.deadline += 1;
        contradictions.push(record);
        let mut record = durable;
        let fill = super::BuyerJournalMatch {
            token_contract: subscription_test_tc('3'),
            order_id: order.order_id,
            ticks: order.ticks,
            clearing_price: order.price_per_tick,
        };
        record.matched = Some(super::BuyerSubscriptionMatch::from_fill(&fill));
        contradictions.push(record);

        for record in contradictions {
            let error =
                super::validate_subscription_record_matches_live_order(&record, &snapshot, &order)
                    .unwrap_err();
            assert!(
                error.to_string().contains("conflicts with durable state"),
                "{error:#}"
            );
        }
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn subscription_cancel_requires_refund_and_fill_race_loses_closed() {
        assert_eq!(
            super::subscription_cancel_outcome(false, 100, 140, 40, None).unwrap(),
            super::SubscriptionCancelOutcome::Refunded {
                expected_balance: 140
            }
        );
        assert!(matches!(
            super::subscription_cancel_outcome(true, 100, 100, 40, None).unwrap(),
            super::SubscriptionCancelOutcome::Unconfirmed { .. }
        ));
        assert!(matches!(
            super::subscription_cancel_outcome(false, 100, 139, 40, None).unwrap(),
            super::SubscriptionCancelOutcome::Unconfirmed { .. }
        ));
        let matched = super::BuyerSubscriptionMatch {
            token_contract: subscription_test_tc('3'),
            order_id: 70,
            ticks: 4,
            clearing_price: dexdo_core::PRICE_STEP,
            deal_handle: crate::cli::deals::make_handle_id(
                &subscription_test_tc('3'),
                crate::cli::deals::DealHandleRole::Buyer,
            ),
        };
        assert!(matches!(
            super::subscription_cancel_outcome(false, 100, 140, 40, Some(&matched)).unwrap(),
            super::SubscriptionCancelOutcome::Filled { .. }
        ));
        assert!(matches!(
            super::subscription_cancel_outcome(true, 100, 100, 40, Some(&matched)).unwrap(),
            super::SubscriptionCancelOutcome::ContradictoryFill { .. }
        ));
        assert!(
            super::subscription_cancel_outcome(false, u128::MAX, 0, 1, None).is_err(),
            "balance arithmetic overflow must fail closed"
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn subscription_cancel_polls_stale_read_until_refund_is_visible() {
        let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_reads = reads.clone();
        let outcome = super::reconcile_subscription_cancel(
            dexdo_core::SUBSCRIPTION_ORDER_RECONCILE_POLL.saturating_mul(2),
            100,
            40,
            move || {
                let read = observed_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    if read == 0 {
                        Ok((true, 100, None))
                    } else {
                        Ok((false, 140, None))
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            super::SubscriptionCancelOutcome::Refunded {
                expected_balance: 140
            }
        );
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn subscription_cancel_polls_stale_read_until_delayed_fill_wins() {
        let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_reads = reads.clone();
        let matched = super::BuyerSubscriptionMatch {
            token_contract: subscription_test_tc('3'),
            order_id: 70,
            ticks: 4,
            clearing_price: dexdo_core::PRICE_STEP,
            deal_handle: crate::cli::deals::make_handle_id(
                &subscription_test_tc('3'),
                crate::cli::deals::DealHandleRole::Buyer,
            ),
        };
        let expected_token_contract = matched.token_contract.clone();
        let outcome = super::reconcile_subscription_cancel(
            dexdo_core::SUBSCRIPTION_ORDER_RECONCILE_POLL.saturating_mul(2),
            100,
            40,
            move || {
                let read = observed_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let matched = matched.clone();
                async move {
                    if read == 0 {
                        Ok((true, 100, None))
                    } else {
                        Ok((false, 100, Some(matched)))
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            super::SubscriptionCancelOutcome::Filled {
                token_contract: expected_token_contract
            }
        );
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn legacy_and_corrupt_subscription_state_are_rejected_explicitly() {
        let (dir, _cleanup) = buyer_journal_test_dir("subscription-state-schemas");
        let state_path = dir.join("state.json");
        let journal_path = dir.join("journal.json");
        let note_addr = subscription_test_note();

        for schema in [
            super::LEGACY_BUYER_SUBSCRIPTION_STATE_SCHEMA,
            super::LEGACY_BUYER_SUBSCRIPTION_STATE_SCHEMA_V2,
        ] {
            write_test_private_json(
                &state_path,
                &serde_json::json!({
                    "schema": schema
                }),
            );
            let error = super::load_buyer_subscription_state(&state_path, &note_addr).unwrap_err();
            assert!(error.to_string().contains("legacy"), "{error:#}");
            assert!(
                error.to_string().contains("manual reconciliation"),
                "{error:#}"
            );
        }

        write_test_private_json(
            &journal_path,
            &serde_json::json!({
                "schema": super::LEGACY_BUYER_SUBSCRIPTION_SUBMIT_SCHEMA
            }),
        );
        let error = super::load_buyer_money_journal(&journal_path, &note_addr).unwrap_err();
        assert!(error.to_string().contains("legacy"), "{error:#}");

        let mut state = super::BuyerSubscriptionState::empty(&note_addr).unwrap();
        state.schema = super::BUYER_SUBSCRIPTION_STATE_SCHEMA.to_string();
        let mut value = serde_json::to_value(state).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::json!(true));
        write_test_private_json(&state_path, &value);
        let error = super::load_buyer_subscription_state(&state_path, &note_addr).unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error:#}");
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn explicit_terminal_confirmation_marks_durable_subscription_exactly_once() {
        let note_addr = format!("0:{}", "a".repeat(64));
        let tc = subscription_test_tc('b');
        let money_lock = super::BuyerMoneyLock::open(&note_addr).unwrap();
        let _ = std::fs::remove_file(&money_lock.subscriptions_path);
        let mut record = subscription_test_record(79);
        record.phase = super::BuyerSubscriptionPhase::Matched;
        record.matched = Some(super::BuyerSubscriptionMatch {
            token_contract: tc.clone(),
            order_id: record.order_id,
            ticks: record.ticks,
            clearing_price: record.max_price_per_tick,
            deal_handle: crate::cli::deals::make_handle_id(
                &tc,
                crate::cli::deals::DealHandleRole::Buyer,
            ),
        });
        let state = super::BuyerSubscriptionState {
            schema: super::BUYER_SUBSCRIPTION_STATE_SCHEMA.to_string(),
            note_addr: note_addr.clone(),
            orders: vec![record],
        };
        super::write_buyer_subscription_state(&money_lock.subscriptions_path, &state).unwrap();

        assert!(super::mark_buyer_subscription_terminal(&note_addr, &tc).unwrap());
        assert!(!super::mark_buyer_subscription_terminal(&note_addr, &tc).unwrap());
        let stored =
            super::load_buyer_subscription_state(&money_lock.subscriptions_path, &note_addr)
                .unwrap();
        assert_eq!(
            stored.orders[0].phase,
            super::BuyerSubscriptionPhase::Terminal
        );
        let _ = std::fs::remove_file(&money_lock.subscriptions_path);
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn subscription_confirmed_pre_match_cancel_becomes_terminal_without_fallback_or_payment()
    {
        use std::sync::atomic::Ordering;

        let (dir, _cleanup) = buyer_journal_test_dir("subscription-cancel-terminal");
        let note_addr = subscription_test_note();
        let record = subscription_test_record(84);
        let state = super::BuyerSubscriptionState {
            schema: super::BUYER_SUBSCRIPTION_STATE_SCHEMA.to_string(),
            note_addr: note_addr.clone(),
            orders: vec![record.clone()],
        };
        let money_lock = super::BuyerMoneyLock {
            note_addr: note_addr.clone(),
            path: dir.join("money.lock"),
            journal_path: dir.join("money.json"),
            subscriptions_path: dir.join("subscriptions.json"),
            lock: None,
        };
        super::write_buyer_subscription_state(&money_lock.subscriptions_path, &state).unwrap();

        assert!(super::mark_cancelled_buyer_subscription_terminal(
            &money_lock.subscriptions_path,
            &note_addr,
            &record.order_book,
            record.order_id,
        )
        .unwrap());
        assert!(!super::mark_cancelled_buyer_subscription_terminal(
            &money_lock.subscriptions_path,
            &note_addr,
            &record.order_book,
            record.order_id,
        )
        .unwrap());
        let stored =
            super::load_buyer_subscription_state(&money_lock.subscriptions_path, &note_addr)
                .unwrap();
        assert_eq!(
            stored.orders[0].phase,
            super::BuyerSubscriptionPhase::Terminal
        );
        assert!(stored.orders[0].matched.is_none());

        let chain = SubscriptionResumeChain {
            order_book: record.order_book.clone(),
            snapshot: subscription_test_snapshot(&record, &note_addr),
            snapshot_overrides: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            reject_target: None,
            due_boundaries: std::sync::Mutex::new(0),
            settle_bookings: std::sync::atomic::AtomicUsize::new(0),
            attributed_fills: std::sync::Mutex::new(Vec::new()),
            buy_posts: std::sync::atomic::AtomicUsize::new(0),
            lookback_reads: std::sync::atomic::AtomicUsize::new(0),
            target_checks: std::sync::atomic::AtomicUsize::new(0),
        };
        let error = super::resolve_buyer_subscription_resume(
            &chain,
            &note_addr,
            &record.frame_model,
            None,
            &money_lock,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("terminal"), "{message}");
        assert!(
            message.contains(&format!("order#{}", record.order_id)),
            "{message}"
        );
        assert_eq!(chain.buy_posts.load(Ordering::SeqCst), 0);
        assert_eq!(chain.lookback_reads.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn durable_subscription_resume_precedes_lookback_and_never_pays_again() {
        use std::sync::atomic::Ordering;

        let (dir, _cleanup) = buyer_journal_test_dir("subscription-durable-resume");
        let note_addr = subscription_test_note();
        let mut record = subscription_test_record(80);
        let tc = subscription_test_tc('3');
        record.phase = super::BuyerSubscriptionPhase::Matched;
        record.matched = Some(super::BuyerSubscriptionMatch {
            token_contract: tc.clone(),
            order_id: record.order_id,
            ticks: record.ticks,
            clearing_price: record.max_price_per_tick,
            deal_handle: crate::cli::deals::make_handle_id(
                &tc,
                crate::cli::deals::DealHandleRole::Buyer,
            ),
        });
        let state = super::BuyerSubscriptionState {
            schema: super::BUYER_SUBSCRIPTION_STATE_SCHEMA.to_string(),
            note_addr: note_addr.clone(),
            orders: vec![record.clone()],
        };
        let money_lock = super::BuyerMoneyLock {
            note_addr: note_addr.clone(),
            path: dir.join("money.lock"),
            journal_path: dir.join("money.json"),
            subscriptions_path: dir.join("subscriptions.json"),
            lock: None,
        };
        super::write_buyer_subscription_state(&money_lock.subscriptions_path, &state).unwrap();
        let chain = SubscriptionResumeChain {
            order_book: record.order_book.clone(),
            snapshot: subscription_test_snapshot(&record, &note_addr),
            snapshot_overrides: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            reject_target: None,
            due_boundaries: std::sync::Mutex::new(0),
            settle_bookings: std::sync::atomic::AtomicUsize::new(0),
            attributed_fills: std::sync::Mutex::new(Vec::new()),
            buy_posts: std::sync::atomic::AtomicUsize::new(0),
            lookback_reads: std::sync::atomic::AtomicUsize::new(0),
            target_checks: std::sync::atomic::AtomicUsize::new(0),
        };

        for _ in 0..2 {
            let selected = super::resolve_buyer_subscription_resume(
                &chain,
                &note_addr,
                &record.frame_model,
                None,
                &money_lock,
                std::time::Duration::ZERO,
                &persist_subscription_test_handle,
            )
            .await
            .unwrap()
            .expect("durable subscription selected");
            assert_eq!(selected.record.matched.as_ref().unwrap().token_contract, tc);
            assert_eq!(
                selected.record.matched.as_ref().unwrap().deal_handle,
                record.matched.as_ref().unwrap().deal_handle
            );
        }
        assert_eq!(chain.buy_posts.load(Ordering::SeqCst), 0);
        assert_eq!(
            chain.lookback_reads.load(Ordering::SeqCst),
            0,
            "persisted TC must win even beyond RESUME_LOOKBACK_SECS"
        );
        // Two candidates, each read twice: once for the recorded books and once for the state
        // the boundary-booking attempt published. The booking's response is not evidence, so the
        // second read is not optional.
        assert_eq!(chain.target_checks.load(Ordering::SeqCst), 4);

        let mut terminal = state.clone();
        terminal.orders[0].phase = super::BuyerSubscriptionPhase::Terminal;
        super::write_buyer_subscription_state(&money_lock.subscriptions_path, &terminal).unwrap();
        let error = super::resolve_buyer_subscription_resume(
            &chain,
            &note_addr,
            &record.frame_model,
            None,
            &money_lock,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("terminal"), "{error:#}");
        assert_eq!(chain.buy_posts.load(Ordering::SeqCst), 0);
        assert_eq!(chain.lookback_reads.load(Ordering::SeqCst), 0);

        let mut active = subscription_test_record(83);
        let active_tc = subscription_test_tc('4');
        active.phase = super::BuyerSubscriptionPhase::Matched;
        active.matched = Some(super::BuyerSubscriptionMatch {
            token_contract: active_tc.clone(),
            order_id: active.order_id,
            ticks: active.ticks,
            clearing_price: active.max_price_per_tick,
            deal_handle: crate::cli::deals::make_handle_id(
                &active_tc,
                crate::cli::deals::DealHandleRole::Buyer,
            ),
        });
        terminal.orders.push(active);
        super::write_buyer_subscription_state(&money_lock.subscriptions_path, &terminal).unwrap();
        let selected = super::resolve_buyer_subscription_resume(
            &chain,
            &note_addr,
            &record.frame_model,
            None,
            &money_lock,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .unwrap()
        .expect("one active subscription must win over retained terminal history");
        assert_eq!(
            selected.record.matched.as_ref().unwrap().token_contract,
            active_tc
        );
        assert_eq!(chain.buy_posts.load(Ordering::SeqCst), 0);
        assert_eq!(chain.lookback_reads.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn durable_subscription_resume_never_falls_back_while_order_is_resting() {
        use std::sync::atomic::Ordering;

        let (dir, _cleanup) = buyer_journal_test_dir("subscription-resting-resume");
        let note_addr = subscription_test_note();
        let record = subscription_test_record(81);
        let state = super::BuyerSubscriptionState {
            schema: super::BUYER_SUBSCRIPTION_STATE_SCHEMA.to_string(),
            note_addr: note_addr.clone(),
            orders: vec![record.clone()],
        };
        let money_lock = super::BuyerMoneyLock {
            note_addr: note_addr.clone(),
            path: dir.join("money.lock"),
            journal_path: dir.join("money.json"),
            subscriptions_path: dir.join("subscriptions.json"),
            lock: None,
        };
        super::write_buyer_subscription_state(&money_lock.subscriptions_path, &state).unwrap();
        let chain = SubscriptionResumeChain {
            order_book: record.order_book.clone(),
            snapshot: subscription_test_snapshot(&record, &note_addr),
            snapshot_overrides: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            reject_target: None,
            due_boundaries: std::sync::Mutex::new(0),
            settle_bookings: std::sync::atomic::AtomicUsize::new(0),
            attributed_fills: std::sync::Mutex::new(Vec::new()),
            buy_posts: std::sync::atomic::AtomicUsize::new(0),
            lookback_reads: std::sync::atomic::AtomicUsize::new(0),
            target_checks: std::sync::atomic::AtomicUsize::new(0),
        };

        let error = super::resolve_buyer_subscription_resume(
            &chain,
            &note_addr,
            &record.frame_model,
            None,
            &money_lock,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("still resting"), "{error:#}");
        assert_eq!(chain.buy_posts.load(Ordering::SeqCst), 0);
        assert_eq!(
            chain.lookback_reads.load(Ordering::SeqCst),
            0,
            "durable resting state must block the legacy event fallback"
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn durable_subscription_resume_rejects_ambiguous_candidate_handles() {
        let (dir, _cleanup) = buyer_journal_test_dir("subscription-ambiguous-resume");
        let note_addr = subscription_test_note();
        let mut first = subscription_test_record(81);
        let mut second = subscription_test_record(82);
        for (record, tc) in [
            (&mut first, subscription_test_tc('3')),
            (&mut second, subscription_test_tc('4')),
        ] {
            record.phase = super::BuyerSubscriptionPhase::Matched;
            record.matched = Some(super::BuyerSubscriptionMatch {
                token_contract: tc.clone(),
                order_id: record.order_id,
                ticks: record.ticks,
                clearing_price: record.max_price_per_tick,
                deal_handle: crate::cli::deals::make_handle_id(
                    &tc,
                    crate::cli::deals::DealHandleRole::Buyer,
                ),
            });
        }
        let state = super::BuyerSubscriptionState {
            schema: super::BUYER_SUBSCRIPTION_STATE_SCHEMA.to_string(),
            note_addr: note_addr.clone(),
            orders: vec![first.clone(), second.clone()],
        };
        let money_lock = super::BuyerMoneyLock {
            note_addr: note_addr.clone(),
            path: dir.join("money.lock"),
            journal_path: dir.join("money.json"),
            subscriptions_path: dir.join("subscriptions.json"),
            lock: None,
        };
        super::write_buyer_subscription_state(&money_lock.subscriptions_path, &state).unwrap();
        let chain = SubscriptionResumeChain {
            order_book: first.order_book.clone(),
            snapshot: subscription_test_snapshot(&first, &note_addr),
            snapshot_overrides: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            reject_target: None,
            due_boundaries: std::sync::Mutex::new(0),
            settle_bookings: std::sync::atomic::AtomicUsize::new(0),
            attributed_fills: std::sync::Mutex::new(Vec::new()),
            buy_posts: std::sync::atomic::AtomicUsize::new(0),
            lookback_reads: std::sync::atomic::AtomicUsize::new(0),
            target_checks: std::sync::atomic::AtomicUsize::new(0),
        };
        let error = super::resolve_buyer_subscription_resume(
            &chain,
            &note_addr,
            &first.frame_model,
            None,
            &money_lock,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("ambiguous"), "{message}");
        assert!(
            message.contains(&first.matched.as_ref().unwrap().deal_handle),
            "{message}"
        );
        assert!(
            message.contains(&second.matched.as_ref().unwrap().deal_handle),
            "{message}"
        );

        let selected = super::resolve_buyer_subscription_resume(
            &chain,
            &note_addr,
            &first.frame_model,
            Some(&second.matched.as_ref().unwrap().token_contract),
            &money_lock,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .unwrap()
        .expect("explicit TokenContract selects its exact durable subscription");
        assert_eq!(
            selected.record.matched.as_ref().unwrap().token_contract,
            second.matched.as_ref().unwrap().token_contract
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn durable_subscription_resume_refreshes_all_matches_before_ambiguity() {
        use std::sync::atomic::Ordering;

        let (dir, _cleanup) = buyer_journal_test_dir("subscription-refresh-before-ambiguity");
        let note_addr = subscription_test_note();
        let mut stale = subscription_test_record(85);
        let mut live = subscription_test_record(86);
        let stale_tc = subscription_test_tc('5');
        let live_tc = subscription_test_tc('6');
        for (record, tc) in [(&mut stale, &stale_tc), (&mut live, &live_tc)] {
            record.phase = super::BuyerSubscriptionPhase::Matched;
            record.matched = Some(super::BuyerSubscriptionMatch {
                token_contract: tc.clone(),
                order_id: record.order_id,
                ticks: record.ticks,
                clearing_price: record.max_price_per_tick,
                deal_handle: crate::cli::deals::make_handle_id(
                    tc,
                    crate::cli::deals::DealHandleRole::Buyer,
                ),
            });
        }
        let state = super::BuyerSubscriptionState {
            schema: super::BUYER_SUBSCRIPTION_STATE_SCHEMA.to_string(),
            note_addr: note_addr.clone(),
            orders: vec![stale.clone(), live.clone()],
        };
        let money_lock = super::BuyerMoneyLock {
            note_addr: note_addr.clone(),
            path: dir.join("money.lock"),
            journal_path: dir.join("money.json"),
            subscriptions_path: dir.join("subscriptions.json"),
            lock: None,
        };
        super::write_buyer_subscription_state(&money_lock.subscriptions_path, &state).unwrap();

        let mut stale_snapshot = subscription_test_snapshot(&stale, &note_addr);
        stale_snapshot.state.disputed = true;
        let live_snapshot = subscription_test_snapshot(&live, &note_addr);
        let chain = SubscriptionResumeChain {
            order_book: live.order_book.clone(),
            snapshot: live_snapshot,
            snapshot_overrides: std::sync::Mutex::new(std::collections::BTreeMap::from([(
                stale_tc.clone(),
                stale_snapshot,
            )])),
            // A terminal deal can fail every active-target check; resume must first observe its
            // authoritative terminal snapshot and must not run that live-only assertion.
            reject_target: Some(stale_tc.clone()),
            due_boundaries: std::sync::Mutex::new(0),
            settle_bookings: std::sync::atomic::AtomicUsize::new(0),
            attributed_fills: std::sync::Mutex::new(Vec::new()),
            buy_posts: std::sync::atomic::AtomicUsize::new(0),
            lookback_reads: std::sync::atomic::AtomicUsize::new(0),
            target_checks: std::sync::atomic::AtomicUsize::new(0),
        };

        let selected = super::resolve_buyer_subscription_resume(
            &chain,
            &note_addr,
            &live.frame_model,
            None,
            &money_lock,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .unwrap()
        .expect("the sole authoritatively live subscription must be selected");
        assert_eq!(
            selected.record.matched.as_ref().unwrap().token_contract,
            live_tc
        );
        assert_eq!(
            chain.target_checks.load(Ordering::SeqCst),
            2,
            "only the live candidate receives the active-target assertion - twice, because its books \
             are re-read after the boundary-booking attempt, and never the terminal one"
        );

        let refreshed =
            super::load_buyer_subscription_state(&money_lock.subscriptions_path, &note_addr)
                .unwrap();
        assert_eq!(
            refreshed
                .orders
                .iter()
                .find(|record| record.order_id == stale.order_id)
                .unwrap()
                .phase,
            super::BuyerSubscriptionPhase::Terminal
        );
        assert_eq!(
            refreshed
                .orders
                .iter()
                .find(|record| record.order_id == live.order_id)
                .unwrap()
                .phase,
            super::BuyerSubscriptionPhase::Matched
        );
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn subscription_terminal_wiring_exposes_no_removed_reclaim_selector_or_state() {
        let recover = include_str!("recover.rs");
        let close = include_str!("close.rs");
        for (name, source) in [("recover", recover), ("close", close)] {
            for removed in [
                "streamReclaim",
                "reclaimOnTimeout",
                "pokeSubscription",
                "lastAdvance",
                "\"prepaid\"",
                "\"frozen\"",
            ] {
                assert!(
                    !source.contains(removed),
                    "{name} mutation source must not expose removed {removed}"
                );
            }
        }
        let reclaim_start = recover
            .find("pub(crate) async fn run_reclaim(args:")
            .expect("current reclaim command");
        let reclaim_end = recover[reclaim_start..]
            .find("#[cfg(not(feature = \"shellnet\"))]")
            .map(|offset| reclaim_start + offset)
            .expect("end current reclaim command");
        let reclaim = &recover[reclaim_start..reclaim_end];
        for removed in ["streamReclaim", "reclaimOnTimeout", "lastAdvance"] {
            assert!(
                !reclaim.contains(removed),
                "current reclaim mutation path must not expose removed {removed}"
            );
        }
        assert!(!reclaim.contains("stream_stop"));
        assert!(reclaim.contains("stream_cleanup"));
        assert!(reclaim.contains("mark_buyer_subscription_terminal"));

        let buyer = include_str!("buyer.rs");
        let resume_start = buyer
            .find("async fn resolve_buyer_subscription_resume")
            .expect("durable subscription resume");
        let resume_end = buyer[resume_start..]
            .find("enum SubscriptionCancelOutcome")
            .map(|offset| resume_start + offset)
            .expect("end durable subscription resume");
        let resume = &buyer[resume_start..resume_end];
        for removed in [
            "streamReclaim",
            "reclaimOnTimeout",
            "pokeSubscription",
            "lastAdvance",
            "\"prepaid\"",
            "\"frozen\"",
        ] {
            assert!(
                !resume.contains(removed),
                "subscription resume must not make removed {removed} reachable"
            );
        }
    }

    #[test]
    fn durable_subscription_selection_precedes_all_fresh_money_and_event_lookback() {
        let source = include_str!("buyer.rs");
        let run_start = source
            .find("async fn run_buyer_inner")
            .expect("buyer entry point");
        let run_tail = &source[run_start..];
        let run_end = run_tail
            .find("\n#[cfg(test)]\nmod tests")
            .expect("end buyer runtime");
        let run = &run_tail[..run_end];
        let durable = run
            .find("resolve_buyer_subscription_resume(")
            .expect("durable subscription selector");
        let fresh_money = run
            .find("raise_pending_buyer_money_before_fresh_reads(")
            .expect("ordinary fresh-money path");
        let lookback = run
            .find(".wait_matched_token_contract(")
            .expect("legacy bounded event fallback");
        assert!(
            durable < fresh_money,
            "journal/state replay must happen first"
        );
        assert!(fresh_money < lookback);
        assert!(
            run.contains("if args.mock.mock_chain || subscription_resume.is_active()"),
            "an active durable subscription must suppress every fresh buyer money action"
        );
        assert!(
            run.contains("if args.resume && !args.mock.mock_chain {"),
            "durable subscription resolution must run for model-only, --token-contract and --market resume"
        );
        assert!(
            !run.contains("if args.resume && model_only && !args.mock.mock_chain"),
            "explicit resume must not bypass durable subscription state"
        );
        let durable_selection = run
            .find("} else if subscription_resume.is_active()")
            .expect("durable subscription selection branch");
        let explicit_selection = run
            .find("match explicit_tc")
            .expect("explicit TokenContract selection branch");
        assert!(
            durable_selection < explicit_selection,
            "a durable subscription must win before explicit/historical ordinary resume routing"
        );
    }

    #[test]
    fn subscription_resume_semantics_are_wired_into_foreground_and_lazy_paths() {
        let source = include_str!("buyer.rs");
        let lazy_start = source
            .find("async fn prepare_lazy_buyer_api_deal_once")
            .expect("lazy buyer initializer");
        let lazy_end = source[lazy_start..]
            .find("fn build_on_demand_buyer_api_state")
            .map(|offset| lazy_start + offset)
            .expect("end lazy buyer initializer");
        let lazy = &source[lazy_start..lazy_end];
        for required in [
            "classify_subscription_resume_target(",
            "subscription_route_budget",
            "SessionLifetimePolicy::Preserve",
            "historical_resume_fill",
        ] {
            assert!(
                lazy.contains(required),
                "lazy explicit/historical resume is missing {required}"
            );
        }

        let foreground_start = source
            .find("async fn run_buyer_inner")
            .expect("foreground buyer entry");
        let foreground_tail = &source[foreground_start..];
        let foreground_end = foreground_tail
            .find("\n#[cfg(test)]\nmod tests")
            .expect("end foreground buyer runtime");
        let foreground = &foreground_tail[..foreground_end];
        for required in [
            "classify_subscription_resume_target(",
            "subscription_route_budget",
            "SessionLifetimePolicy::Preserve",
            "historical_resume_fill",
        ] {
            assert!(
                foreground.contains(required),
                "foreground explicit/historical resume is missing {required}"
            );
        }
        assert!(
            !foreground.contains("if !preserve_subscription"),
            "subscription preservation may gate graceful shutdown only, never incident recovery"
        );

        let on_demand_start = source
            .find("async fn run_buyer_on_demand_local_api")
            .expect("on-demand buyer API");
        let on_demand_end = source[on_demand_start..]
            .find("async fn run_buyer_inner")
            .map(|offset| on_demand_start + offset)
            .expect("end on-demand buyer API");
        let on_demand = &source[on_demand_start..on_demand_end];
        for required in [
            "buyer_shutdown_report(active.as_ref()",
            "BuyerShutdownReport::SubscriptionPreserved",
            "BuyerShutdownReport::Settlement",
            "\"subscription_preserved\"",
            "\"chain_write_submitted\": shutdown_report.chain_write_submitted()",
        ] {
            assert!(
                on_demand.contains(required),
                "on-demand subscription shutdown reporting is missing {required}"
            );
        }
    }

    #[cfg(feature = "shellnet")]
    fn buyer_submit_test_journal() -> super::BuyerSubmitJournal {
        let note_addr = format!("0:{}", "1".repeat(64));
        let order_book = format!("0:{}", "2".repeat(64));
        let token_contract = format!("0:{}", "3".repeat(64));
        let ticks = 2;
        let price_per_tick = 1_000_000;
        let escrow = dexdo_core::required_escrow_for_buy(ticks, price_per_tick);
        super::BuyerSubmitJournal {
            schema: super::BUYER_SUBMIT_JOURNAL_SCHEMA.to_string(),
            note_addr,
            order_book,
            intent: super::BuyerSubmitIntent::foreground(),
            expected_token_contract: Some(token_contract.clone()),
            quoted_order: dexdo_core::OrderBookOrder {
                order_id: 7,
                owner_note: format!("0:{}", "4".repeat(64)),
                token_contract: Some(token_contract.clone()),
                is_buy: false,
                price_per_tick,
                ticks,
                escrow: 0,
                deadline: 0,
                flags: 0,
                timestamp: 0,
            },
            quote: dexdo_core::ExecutableQuote {
                filled_ticks: ticks,
                total_with_fee: escrow,
                complete: true,
                fills: vec![dexdo_core::QuoteFill {
                    order_id: 7,
                    token_contract,
                    ticks,
                    price_per_tick,
                    cost_with_fee: escrow,
                }],
            },
            cursor: dexdo_core::MatchWatchCursor::new(1_000),
            ticks,
            max_price_per_tick: price_per_tick,
            escrow,
            submit_identity: format!("boc-sha256:{}", "a".repeat(64)),
            created_at_unix: 1_000,
            resolved_match: None,
            resolved_matches: Vec::new(),
        }
    }

    #[cfg(feature = "shellnet")]
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PreviousBuyerSubmitJournalV2 {
        schema: String,
        note_addr: String,
        order_book: String,
        intent: super::BuyerSubmitIntent,
        expected_token_contract: Option<dexdo_core::TokenContract>,
        quoted_order: dexdo_core::OrderBookOrder,
        quote: dexdo_core::ExecutableQuote,
        cursor: dexdo_core::MatchWatchCursor,
        ticks: u128,
        max_price_per_tick: u128,
        escrow: u128,
        submit_identity: String,
        created_at_unix: u64,
        #[serde(default)]
        resolved_match: Option<super::BuyerJournalMatch>,
        #[serde(default)]
        resolved_matches: Vec<super::BuyerJournalMatch>,
    }

    #[cfg(feature = "shellnet")]
    impl From<&super::BuyerSubmitJournal> for PreviousBuyerSubmitJournalV2 {
        fn from(journal: &super::BuyerSubmitJournal) -> Self {
            Self {
                schema: journal.schema.clone(),
                note_addr: journal.note_addr.clone(),
                order_book: journal.order_book.clone(),
                intent: journal.intent.clone(),
                expected_token_contract: journal.expected_token_contract.clone(),
                quoted_order: journal.quoted_order.clone(),
                quote: journal.quote.clone(),
                cursor: journal.cursor.clone(),
                ticks: journal.ticks,
                max_price_per_tick: journal.max_price_per_tick,
                escrow: journal.escrow,
                submit_identity: journal.submit_identity.clone(),
                created_at_unix: journal.created_at_unix,
                resolved_match: journal.resolved_match.clone(),
                resolved_matches: journal.resolved_matches.clone(),
            }
        }
    }

    #[cfg(feature = "shellnet")]
    fn issue67_real_like_order() -> dexdo_core::OrderBookOrder {
        dexdo_core::OrderBookOrder {
            order_id: 154,
            owner_note: format!("0:{}", "4".repeat(64)),
            token_contract: Some(format!("0:{}", "3".repeat(64))),
            is_buy: false,
            price_per_tick: 1_000_000,
            ticks: 4,
            escrow: 9_999,
            deadline: 1_234_567,
            flags: 7,
            timestamp: 1_234_000,
        }
    }

    #[cfg(feature = "shellnet")]
    fn issue67_pipeline_chain(
        quoted_order: &dexdo_core::OrderBookOrder,
        fresh_order: Option<dexdo_core::OrderBookOrder>,
    ) -> QuotePreflightChain {
        QuotePreflightChain {
            offers: vec![QuotePreflightChain::offer(
                quoted_order.token_contract.as_deref().unwrap(),
                quoted_order.price_per_tick as u64,
                quoted_order.ticks as u64,
            )],
            model_submit_safe_order: Some(quoted_order.clone()),
            model_pre_submit_order: fresh_order,
            submit_safe_single_ask_quote: true,
            ..Default::default()
        }
    }

    #[cfg(feature = "shellnet")]
    async fn issue67_select_and_submit(
        chain: &QuotePreflightChain,
        journal_path: &std::path::Path,
        human_model: Option<&str>,
    ) -> anyhow::Result<super::BuyerQuoteSelection> {
        let ticks = 2;
        let max_price_per_tick = chain
            .model_submit_safe_order
            .as_ref()
            .unwrap()
            .price_per_tick;
        let escrow = dexdo_core::required_escrow_for_buy(ticks, max_price_per_tick);
        let selection =
            super::buyer_quote_selection(chain, None, ticks, max_price_per_tick, Some(escrow))
                .await?;
        let buyer = dexdo::buyer::Buyer::generate();
        let mut cursor = dexdo_core::MatchWatchCursor::default();
        super::place_quote_bound_buy_with_journal(
            chain,
            &buyer,
            &super::BuyerSubmitIntent::foreground(),
            None,
            &selection,
            ticks,
            max_price_per_tick,
            escrow,
            &format!("0:{}", "1".repeat(64)),
            &mut cursor,
            journal_path,
            human_model,
        )
        .await?;
        Ok(selection)
    }

    /// an unchanged real matcher row is rendered, persisted before POST, and submitted exactly once
    /// without ever entering the mock offer-reconstruction path.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn buyer_real_quote_identity_reaches_journal_and_money_submit_once() {
        use std::sync::atomic::Ordering;

        let order = issue67_real_like_order();
        let mut chain = issue67_pipeline_chain(&order, Some(order.clone()));
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-issue-67-unchanged");
        let journal_path = dir.join("submit.json");
        let note_shell_balance = dexdo_core::required_escrow_for_buy(2, order.price_per_tick) + 7;
        chain.note_shell_balance = Some(note_shell_balance);

        let selection = issue67_select_and_submit(&chain, &journal_path, Some("qwen--qwen3--32b"))
            .await
            .expect("unchanged real matcher row submits");
        let line = super::render_buyer_human_preflight(
            "qwen--qwen3--32b",
            &selection,
            2,
            order.price_per_tick,
            selection.escrow,
            note_shell_balance,
        );
        let fee = selection.quote.fills[0].cost_with_fee
            - selection.quote.fills[0].ticks * selection.quote.fills[0].price_per_tick;
        assert_eq!(
            line,
            format!(
                "BUYER_PREFLIGHT model=qwen--qwen3--32b requested_ticks=2 minimum_ticks={} \
                 best_ask={} max_price_per_tick={} escrow={} fee={fee} \
                 note_shell_balance={note_shell_balance} order_id={} token_contract={} \
                 matchable=true balance_sufficient=true",
                dexdo_core::params::MIN_STREAM_BUY_TICKS,
                order.price_per_tick,
                order.price_per_tick,
                selection.escrow,
                order.order_id,
                order.token_contract.as_deref().unwrap()
            )
        );
        assert_eq!(selection.quoted_order.as_ref(), Some(&order));
        assert_eq!(selection.quote.fills[0].order_id, order.order_id);
        assert_eq!(
            selection.quote.fills[0].token_contract,
            order.token_contract.clone().unwrap()
        );
        let journal: super::BuyerSubmitJournal =
            serde_json::from_slice(&std::fs::read(&journal_path).unwrap()).unwrap();
        assert_eq!(journal.quoted_order, order);
        assert_eq!(journal.quote, selection.quote);
        assert_eq!(chain.discover_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.model_before_post_calls.load(Ordering::SeqCst), 1);
        assert_eq!(chain.model_money_submit_calls.load(Ordering::SeqCst), 1);
        let available = selection.escrow - 1;
        let mut insufficient = issue67_pipeline_chain(&order, Some(order.clone()));
        insufficient.note_shell_balance = Some(available);
        let insufficient_journal = dir.join("insufficient.json");
        let error = issue67_select_and_submit(
            &insufficient,
            &insufficient_journal,
            Some("qwen--qwen3--32b"),
        )
        .await
        .expect_err("insufficient live Note balance must block escrow POST");
        assert!(
            error.to_string().contains(&format!(
                "required={} available={available}",
                selection.escrow
            )),
            "{error:#}"
        );
        assert!(!insufficient_journal.exists());
        assert_eq!(
            insufficient.model_before_post_calls.load(Ordering::SeqCst),
            1
        );
        assert_eq!(
            insufficient.model_money_submit_calls.load(Ordering::SeqCst),
            0
        );
    }

    /// a benign metadata difference on the fresh non-atomic book read preserves the quoted
    /// order identity/terms and reaches escrow submission.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn buyer_valid_quote_with_benign_reread_diff_reaches_money_submit() {
        use std::sync::atomic::Ordering;

        let mut quoted = issue67_real_like_order();
        quoted.order_id = 489;
        quoted.token_contract =
            Some("0:03d8b19ead1b4efce30066813b244de7d92e07ea87cc20f8e0ec9c4ebf552cfb".to_string());
        quoted.price_per_tick = 1;
        quoted.ticks = 2;
        let mut fresh = quoted.clone();
        fresh.timestamp += 1;

        let old_guard_error = (quoted != fresh).then_some(
            "buyer pre-submit matcher head differs from the rendered quote; no escrow was sent",
        );
        assert_eq!(
            old_guard_error,
            Some(
                "buyer pre-submit matcher head differs from the rendered quote; no escrow was sent"
            ),
            "the old whole-object guard must reproduce the exact  pre-submit rejection"
        );

        let chain = issue67_pipeline_chain(&quoted, Some(fresh));
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-issue-95-benign-reread");
        let journal_path = dir.join("submit.json");

        let selection = issue67_select_and_submit(&chain, &journal_path, None)
            .await
            .expect("the new identity-and-terms guard accepts the benign reread");
        assert_eq!(selection.quoted_order.as_ref(), Some(&quoted));
        assert!(journal_path.exists());
        assert_eq!(chain.model_before_post_calls.load(Ordering::SeqCst), 1);
        assert_eq!(chain.model_money_submit_calls.load(Ordering::SeqCst), 1);
    }

    /// negative: every matcher-relevant quote-to-submit mutation fails before durable journal POST
    /// and before the money submit.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn buyer_real_quote_identity_change_fails_before_journal_and_escrow() {
        use std::sync::atomic::Ordering;

        let quoted = issue67_real_like_order();
        let mut mutations = Vec::new();
        let mut changed = quoted.clone();
        changed.order_id += 1;
        mutations.push(("order-id", changed));
        let mut changed = quoted.clone();
        changed.token_contract = Some(format!("0:{}", "5".repeat(64)));
        mutations.push(("token-contract", changed));
        let mut changed = quoted.clone();
        changed.price_per_tick += 1;
        mutations.push(("price", changed));
        let mut changed = quoted.clone();
        changed.ticks -= 1;
        mutations.push(("ticks", changed));

        for (label, changed) in mutations {
            let chain = issue67_pipeline_chain(&quoted, Some(changed));
            let (dir, _cleanup) =
                buyer_journal_test_dir(&format!("buyer-issue-67-changed-{label}"));
            let journal_path = dir.join("submit.json");
            let error = issue67_select_and_submit(&chain, &journal_path, None)
                .await
                .expect_err("changed matcher head must fail before escrow");
            assert!(
                error.to_string().contains(
                    "buyer pre-submit matcher head differs from the rendered quote; no escrow was sent"
                ),
                "{label}: {error:#}"
            );
            assert!(
                !journal_path.exists(),
                "{label}: no journal may claim a POST"
            );
            assert_eq!(chain.discover_calls.load(Ordering::SeqCst), 0, "{label}");
            assert_eq!(
                chain.model_before_post_calls.load(Ordering::SeqCst),
                0,
                "{label}"
            );
            assert_eq!(
                chain.model_money_submit_calls.load(Ordering::SeqCst),
                0,
                "{label}"
            );
        }
    }

    /// negative: a quote that disappears or becomes non-executable on the fresh pre-submit read
    /// cannot create a journal or attempt escrow.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn buyer_disappeared_real_quote_fails_before_journal_and_escrow() {
        use std::sync::atomic::Ordering;

        let quoted = issue67_real_like_order();
        let chain = issue67_pipeline_chain(&quoted, None);
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-issue-67-disappeared");
        let journal_path = dir.join("submit.json");
        let error = issue67_select_and_submit(&chain, &journal_path, None)
            .await
            .expect_err("disappeared ask must fail before escrow");

        assert!(error.to_string().contains("no_executable_ask"), "{error:#}");
        assert!(
            error.to_string().contains("no escrow was sent"),
            "{error:#}"
        );
        assert!(!journal_path.exists());
        assert_eq!(chain.discover_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.model_before_post_calls.load(Ordering::SeqCst), 0);
        assert_eq!(chain.model_money_submit_calls.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "shellnet")]
    struct JournalPipelineChain {
        submit_error: Option<&'static str>,
        fill: Option<dexdo_core::MatchedFill>,
        expected_journal_path: std::path::PathBuf,
        sequence: std::sync::Mutex<Vec<&'static str>>,
        post_count: std::sync::atomic::AtomicUsize,
        poll_count: std::sync::atomic::AtomicUsize,
    }

    #[cfg(feature = "shellnet")]
    #[async_trait::async_trait]
    impl dexdo_core::ChainBackend for JournalPipelineChain {
        async fn claim_tokens(
            &self,
            _: &dexdo_core::TokenContract,
            _: &dyn dexdo_core::Note,
            _: u128,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!()
        }

        async fn discover_offers(
            &self,
        ) -> Result<Vec<dexdo_core::OfferListing>, dexdo_core::ChainError> {
            self.sequence.lock().unwrap().push("fresh_read");
            Ok(vec![dexdo_core::OfferListing {
                seller_id: format!("0:{}", "4".repeat(64)),
                token_contract: format!("0:{}", "3".repeat(64)),
                price_per_tick: 1_000_000,
                max_ticks: 2,
            }])
        }

        async fn stop(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _note: &dyn dexdo_core::Note,
        ) -> Result<dexdo_core::Settlement, dexdo_core::ChainError> {
            unimplemented!()
        }

        async fn post_offer(
            &self,
            _offer: dexdo_core::SellOffer,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!()
        }

        async fn place_buy(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!()
        }

        fn model_buy_order_book_identity(&self) -> Option<String> {
            Some(format!("0:{}", "2".repeat(64)))
        }

        async fn place_buy_by_model_with_submit_identity(
            &self,
            _note: &dyn dexdo_core::Note,
            _quoted_order: Option<&dexdo_core::OrderBookOrder>,
            _ticks: u128,
            _max_price_per_tick: u128,
            _escrow: u128,
            cursor: &mut dexdo_core::MatchWatchCursor,
            before_post: &mut (dyn FnMut(
                String,
                dexdo_core::MatchWatchCursor,
                u128,
            ) -> Result<(), dexdo_core::ChainError>
                      + Send),
        ) -> Result<(), dexdo_core::ChainError> {
            *cursor = dexdo_core::MatchWatchCursor::new(77);
            before_post(
                format!("boc-sha256:{}", "a".repeat(64)),
                cursor.clone(),
                u128::MAX,
            )?;
            assert!(
                self.expected_journal_path.exists(),
                "journal callback must finish before the POST seam"
            );
            self.sequence.lock().unwrap().push("post");
            self.post_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match self.submit_error {
                Some("ambiguous") => Err(dexdo_core::ChainError::AmbiguousSubmit(
                    "injected ambiguous POST".to_string(),
                )),
                Some("rejected") => Err(dexdo_core::ChainError::MoneySubmitRejected(
                    "injected clean rejection".to_string(),
                )),
                Some("preparation") => Err(dexdo_core::ChainError::MoneySubmitPreparation(
                    "injected pre-POST failure".to_string(),
                )),
                _ => Ok(()),
            }
        }

        async fn wait_matched_token_contract(
            &self,
            _since_unix: i64,
            _timeout: std::time::Duration,
        ) -> Result<Option<dexdo_core::MatchedFill>, dexdo_core::ChainError> {
            match &self.fill {
                Some(fill) => Ok(Some(fill.clone())),
                None => Err(dexdo_core::ChainError::Transport(
                    "injected unresolved fill".to_string(),
                )),
            }
        }

        async fn poll_matched_model_buys_for_order_book(
            &self,
            _order_book: &str,
            _cursor: &mut dexdo_core::MatchWatchCursor,
        ) -> Result<Vec<dexdo_core::MatchedFill>, dexdo_core::ChainError> {
            let poll = self
                .poll_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.submit_error == Some("replay_once") && poll == 0 {
                self.sequence.lock().unwrap().push("replay_protection");
                return Err(dexdo_core::ChainError::Transport(
                    "injected replay protection exit code 52".to_string(),
                ));
            }
            self.sequence.lock().unwrap().push("reconcile");
            Ok(self.fill.clone().into_iter().collect())
        }

        async fn read_match(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Result<dexdo_core::Match, dexdo_core::ChainError> {
            unimplemented!()
        }

        async fn open_stream(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _enc_endpoint: Vec<u8>,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!()
        }

        async fn read_handover(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<Vec<u8>>, dexdo_core::ChainError> {
            unimplemented!()
        }

        async fn deal_state(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<dexdo_core::DealChainState>, dexdo_core::ChainError> {
            Ok(Some(deal_state(true, false, false, false)))
        }

        async fn snapshot(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Option<dexdo_core::StreamSnapshot> {
            None
        }
    }

    #[cfg(feature = "shellnet")]
    struct ResumeCommandChain {
        fill: dexdo_core::MatchedFill,
        handover: Vec<u8>,
        post_count: std::sync::atomic::AtomicUsize,
        poll_count: std::sync::atomic::AtomicUsize,
        stop_count: std::sync::atomic::AtomicUsize,
        deal_state_count: std::sync::atomic::AtomicUsize,
    }

    #[cfg(feature = "shellnet")]
    #[async_trait::async_trait]
    impl dexdo_core::ChainBackend for ResumeCommandChain {
        async fn claim_tokens(
            &self,
            _: &dexdo_core::TokenContract,
            _: &dyn dexdo_core::Note,
            _: u128,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!()
        }

        async fn discover_offers(
            &self,
        ) -> Result<Vec<dexdo_core::OfferListing>, dexdo_core::ChainError> {
            panic!("retained-journal resume must not perform fresh offer discovery")
        }

        async fn post_offer(
            &self,
            _offer: dexdo_core::SellOffer,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!("not used by buyer resume")
        }

        async fn place_buy(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            self.post_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(dexdo_core::ChainError::Chain(
                "resume attempted a forbidden second money POST".to_string(),
            ))
        }

        fn model_buy_order_book_identity(&self) -> Option<String> {
            Some(format!("0:{}", "2".repeat(64)))
        }

        async fn place_buy_by_model_with_submit_identity(
            &self,
            _note: &dyn dexdo_core::Note,
            _quoted_order: Option<&dexdo_core::OrderBookOrder>,
            _ticks: u128,
            _max_price_per_tick: u128,
            _escrow: u128,
            _cursor: &mut dexdo_core::MatchWatchCursor,
            _before_post: &mut (dyn FnMut(
                String,
                dexdo_core::MatchWatchCursor,
                u128,
            ) -> Result<(), dexdo_core::ChainError>
                      + Send),
        ) -> Result<(), dexdo_core::ChainError> {
            self.post_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(dexdo_core::ChainError::Chain(
                "resume attempted a forbidden second money POST".to_string(),
            ))
        }

        async fn poll_matched_model_buys_for_order_book(
            &self,
            _order_book: &str,
            _cursor: &mut dexdo_core::MatchWatchCursor,
        ) -> Result<Vec<dexdo_core::MatchedFill>, dexdo_core::ChainError> {
            self.poll_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![self.fill.clone()])
        }

        async fn read_match(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Result<dexdo_core::Match, dexdo_core::ChainError> {
            unimplemented!("not used by retained-journal resume")
        }

        async fn open_stream(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _enc_endpoint: Vec<u8>,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!("handover is already authoritative")
        }

        async fn read_handover(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<Vec<u8>>, dexdo_core::ChainError> {
            assert_eq!(token_contract, &self.fill.token_contract);
            Ok(Some(self.handover.clone()))
        }

        async fn stop(
            &self,
            token_contract: &dexdo_core::TokenContract,
            _note: &dyn dexdo_core::Note,
        ) -> Result<dexdo_core::Settlement, dexdo_core::ChainError> {
            assert_eq!(token_contract, &self.fill.token_contract);
            self.stop_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(dexdo_core::Settlement::AmicableSplit {
                to_seller_ticks: 1,
                to_buyer_refund: 1,
            })
        }

        async fn deal_state(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<dexdo_core::DealChainState>, dexdo_core::ChainError> {
            assert_eq!(token_contract, &self.fill.token_contract);
            self.deal_state_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Some(deal_state(true, true, false, true)))
        }

        async fn snapshot(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Option<dexdo_core::StreamSnapshot> {
            None
        }
    }

    #[cfg(feature = "shellnet")]
    struct SubscriptionResumeCommandChain {
        order_book: String,
        placement: dexdo_core::InferenceSubscriptionPlacement,
        fill: dexdo_core::MatchedFill,
        snapshot: dexdo_core::DealChainSnapshot,
        handover: Vec<u8>,
        money_posts: std::sync::atomic::AtomicUsize,
        placement_reads: std::sync::atomic::AtomicUsize,
        fill_reads: std::sync::atomic::AtomicUsize,
        lookback_reads: std::sync::atomic::AtomicUsize,
        target_checks: std::sync::atomic::AtomicUsize,
        stop_count: std::sync::atomic::AtomicUsize,
        dispute_count: std::sync::atomic::AtomicUsize,
        cleanup_count: std::sync::atomic::AtomicUsize,
        deal_state_count: std::sync::atomic::AtomicUsize,
    }

    #[cfg(feature = "shellnet")]
    #[async_trait::async_trait]
    impl dexdo_core::ChainBackend for SubscriptionResumeCommandChain {
        async fn claim_tokens(
            &self,
            _: &dexdo_core::TokenContract,
            _: &dyn dexdo_core::Note,
            _: u128,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!("buyer subscription resume never claims seller tokens")
        }

        async fn discover_offers(
            &self,
        ) -> Result<Vec<dexdo_core::OfferListing>, dexdo_core::ChainError> {
            panic!("durable subscription resume must not perform fresh offer discovery")
        }

        async fn post_offer(
            &self,
            _offer: dexdo_core::SellOffer,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!("buyer-only test backend")
        }

        async fn place_buy(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            self.money_posts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(dexdo_core::ChainError::Chain(
                "durable subscription resume attempted a second BUY".to_string(),
            ))
        }

        async fn place_buy_by_model(
            &self,
            _note: &dyn dexdo_core::Note,
            _ticks: u128,
            _max_price_per_tick: u128,
            _escrow: u128,
            _flags: u8,
            _deadline: u64,
        ) -> Result<(), dexdo_core::ChainError> {
            self.money_posts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(dexdo_core::ChainError::Chain(
                "durable subscription resume attempted a second model BUY".to_string(),
            ))
        }

        async fn place_buy_by_model_with_submit_identity(
            &self,
            _note: &dyn dexdo_core::Note,
            _quoted_order: Option<&dexdo_core::OrderBookOrder>,
            _ticks: u128,
            _max_price_per_tick: u128,
            _escrow: u128,
            _cursor: &mut dexdo_core::MatchWatchCursor,
            _before_post: &mut (dyn FnMut(
                String,
                dexdo_core::MatchWatchCursor,
                u128,
            ) -> Result<(), dexdo_core::ChainError>
                      + Send),
        ) -> Result<(), dexdo_core::ChainError> {
            self.money_posts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(dexdo_core::ChainError::Chain(
                "durable subscription resume attempted a second model BUY".to_string(),
            ))
        }

        fn model_buy_order_book_identity(&self) -> Option<String> {
            Some(self.order_book.clone())
        }

        async fn poll_attributed_model_buys_for_order_book(
            &self,
            order_book: &str,
            _cursor: &mut dexdo_core::MatchWatchCursor,
        ) -> Result<Vec<(u128, dexdo_core::MatchedFill)>, dexdo_core::ChainError> {
            assert_eq!(order_book, self.order_book);
            self.fill_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![(self.placement.order_id, self.fill.clone())])
        }

        async fn subscription_placements_since(
            &self,
            order_book: &str,
            buyer_note: &str,
            order_id_floor: u128,
            max_price_per_tick: u128,
            ticks: u128,
        ) -> Result<Vec<dexdo_core::InferenceSubscriptionPlacement>, dexdo_core::ChainError>
        {
            assert_eq!(order_book, self.order_book);
            assert_eq!(buyer_note, self.placement.buyer_note);
            assert_eq!(order_id_floor, self.placement.order_id);
            assert_eq!(max_price_per_tick, self.placement.max_price_per_tick);
            assert_eq!(ticks, self.placement.ticks);
            self.placement_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![self.placement.clone()])
        }

        async fn buyer_order_is_active_for_owner(
            &self,
            order_book: &str,
            order_id: u128,
            buyer_note: &str,
        ) -> Result<bool, dexdo_core::ChainError> {
            assert_eq!(order_book, self.order_book);
            assert_eq!(order_id, self.placement.order_id);
            assert_eq!(buyer_note, self.placement.buyer_note);
            Ok(false)
        }

        async fn wait_matched_token_contract(
            &self,
            _since_unix: i64,
            _timeout: std::time::Duration,
        ) -> Result<Option<dexdo_core::MatchedFill>, dexdo_core::ChainError> {
            self.lookback_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(dexdo_core::ChainError::Chain(
                "durable subscription resume must precede historical lookback".to_string(),
            ))
        }

        async fn assert_model_only_resume_target(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<(), dexdo_core::ChainError> {
            assert_eq!(token_contract, &self.fill.token_contract);
            self.target_checks
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn deal_snapshot(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<dexdo_core::DealChainSnapshot>, dexdo_core::ChainError> {
            assert_eq!(token_contract, &self.fill.token_contract);
            Ok(Some(self.snapshot.clone()))
        }

        async fn read_match(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Result<dexdo_core::Match, dexdo_core::ChainError> {
            unimplemented!("buyer subscription resume reads the handover")
        }

        async fn open_stream(
            &self,
            _token_contract: &dexdo_core::TokenContract,
            _enc_endpoint: Vec<u8>,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            unimplemented!("buyer subscription resume never opens a seller stream")
        }

        async fn read_handover(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<Vec<u8>>, dexdo_core::ChainError> {
            assert_eq!(token_contract, &self.fill.token_contract);
            Ok(Some(self.handover.clone()))
        }

        async fn stop(
            &self,
            token_contract: &dexdo_core::TokenContract,
            _note: &dyn dexdo_core::Note,
        ) -> Result<dexdo_core::Settlement, dexdo_core::ChainError> {
            assert_eq!(token_contract, &self.fill.token_contract);
            self.stop_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(dexdo_core::Settlement::AmicableSplit {
                to_seller_ticks: 0,
                to_buyer_refund: 0,
            })
        }

        async fn dispute(
            &self,
            token_contract: &dexdo_core::TokenContract,
            _note: &dyn dexdo_core::Note,
        ) -> Result<dexdo_core::Settlement, dexdo_core::ChainError> {
            assert_eq!(token_contract, &self.fill.token_contract);
            self.dispute_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(dexdo_core::Settlement::AmicableSplit {
                to_seller_ticks: 0,
                to_buyer_refund: 0,
            })
        }

        async fn cleanup_unopened(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<dexdo_core::Settlement, dexdo_core::ChainError> {
            assert_eq!(token_contract, &self.fill.token_contract);
            self.cleanup_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(dexdo_core::Settlement::SellerNoShow {
                to_buyer_refund: 0,
                seller_bond_returned: 0,
            })
        }

        async fn deal_state(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<dexdo_core::DealChainState>, dexdo_core::ChainError> {
            assert_eq!(token_contract, &self.fill.token_contract);
            self.deal_state_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Some(self.snapshot.state))
        }

        async fn deal_subscription(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<dexdo_core::DealSubscription>, dexdo_core::ChainError> {
            assert_eq!(token_contract, &self.fill.token_contract);
            Ok(Some(self.snapshot.subscription))
        }

        async fn snapshot(
            &self,
            _token_contract: &dexdo_core::TokenContract,
        ) -> Option<dexdo_core::StreamSnapshot> {
            None
        }
    }

    #[cfg(feature = "shellnet")]
    struct SameTcMockSubscriptionChain {
        chain: std::sync::Arc<dexdo_core::MockChainBackend>,
        buyer_note: std::sync::Arc<dexdo_core::LocalNote>,
        token_contract: dexdo_core::TokenContract,
        order_book: String,
        order_id: std::sync::Mutex<Option<u128>>,
        money_posts: std::sync::atomic::AtomicUsize,
        placement_reads: std::sync::atomic::AtomicUsize,
        fill_reads: std::sync::atomic::AtomicUsize,
        lookback_reads: std::sync::atomic::AtomicUsize,
        target_checks: std::sync::atomic::AtomicUsize,
        claim_posts: std::sync::atomic::AtomicUsize,
        finalize_posts: std::sync::atomic::AtomicUsize,
        settle_week_posts: std::sync::atomic::AtomicUsize,
        stop_posts: std::sync::atomic::AtomicUsize,
        receipt_reads: std::sync::atomic::AtomicUsize,
    }

    #[cfg(feature = "shellnet")]
    impl SameTcMockSubscriptionChain {
        fn new(
            chain: std::sync::Arc<dexdo_core::MockChainBackend>,
            buyer_note: std::sync::Arc<dexdo_core::LocalNote>,
            token_contract: dexdo_core::TokenContract,
            order_book: String,
            order_id: Option<u128>,
        ) -> Self {
            Self {
                chain,
                buyer_note,
                token_contract,
                order_book,
                order_id: std::sync::Mutex::new(order_id),
                money_posts: std::sync::atomic::AtomicUsize::new(0),
                placement_reads: std::sync::atomic::AtomicUsize::new(0),
                fill_reads: std::sync::atomic::AtomicUsize::new(0),
                lookback_reads: std::sync::atomic::AtomicUsize::new(0),
                target_checks: std::sync::atomic::AtomicUsize::new(0),
                claim_posts: std::sync::atomic::AtomicUsize::new(0),
                finalize_posts: std::sync::atomic::AtomicUsize::new(0),
                settle_week_posts: std::sync::atomic::AtomicUsize::new(0),
                stop_posts: std::sync::atomic::AtomicUsize::new(0),
                receipt_reads: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn buyer_note_addr(&self) -> String {
            let pubkey = dexdo_core::Note::pubkey(self.buyer_note.as_ref());
            let owner = pubkey
                .ed
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("0:{owner}")
        }

        fn recorded_order_id(&self) -> Result<u128, dexdo_core::ChainError> {
            self.order_id
                .lock()
                .unwrap()
                .as_ref()
                .copied()
                .ok_or_else(|| {
                    dexdo_core::ChainError::Chain(
                        "mock subscription has no persisted order id".to_string(),
                    )
                })
        }

        fn placement(
            &self,
        ) -> Result<dexdo_core::InferenceSubscriptionPlacement, dexdo_core::ChainError> {
            let order_id = self.recorded_order_id()?;
            let order = self
                .chain
                .subscription_order(&self.order_book, order_id, self.buyer_note.as_ref())?
                .ok_or_else(|| {
                    dexdo_core::ChainError::Chain(format!(
                        "mock subscription order {order_id} disappeared from persisted state"
                    ))
                })?;
            Ok(dexdo_core::InferenceSubscriptionPlacement {
                order_id,
                buyer_note: order.owner_note,
                max_price_per_tick: order.price_per_tick,
                ticks: order.ticks,
                sub_weeks: dexdo_core::SUBSCRIPTION_WEEKS,
                deadline: order.deadline,
                created_at: i64::try_from(order.timestamp).map_err(|_| {
                    dexdo_core::ChainError::Chain(
                        "mock subscription placement timestamp exceeds int64".to_string(),
                    )
                })?,
            })
        }

        async fn fill(&self) -> Result<dexdo_core::MatchedFill, dexdo_core::ChainError> {
            let order_id = self.recorded_order_id()?;
            let matched =
                dexdo_core::ChainBackend::read_match(self.chain.as_ref(), &self.token_contract)
                    .await?;
            if matched.token_contract != self.token_contract
                || matched.buyer_pubkey != dexdo_core::Note::pubkey(self.buyer_note.as_ref())
            {
                return Err(dexdo_core::ChainError::Chain(format!(
                    "mock fill identity for {} is not the persisted buyer match",
                    self.token_contract
                )));
            }
            let deal = dexdo_core::ChainBackend::deal_subscription(
                self.chain.as_ref(),
                &self.token_contract,
            )
            .await?
            .ok_or_else(|| {
                dexdo_core::ChainError::Chain(format!(
                    "mock TokenContract {} has no persisted deal shape",
                    self.token_contract
                ))
            })?;
            let ticks = deal
                .funded_tokens
                .checked_div(dexdo_core::TICK_SIZE)
                .filter(|_| deal.funded_tokens.is_multiple_of(dexdo_core::TICK_SIZE))
                .ok_or_else(|| {
                    dexdo_core::ChainError::Chain(format!(
                        "mock TokenContract {} fundedTokens is not whole ticks",
                        self.token_contract
                    ))
                })?;
            Ok(dexdo_core::MatchedFill {
                order_id,
                token_contract: matched.token_contract,
                ticks,
                price_per_tick: u128::from(matched.price_per_tick),
            })
        }

        async fn assert_same_target(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<(), dexdo_core::ChainError> {
            if !token_contract.eq_ignore_ascii_case(&self.token_contract) {
                return Err(dexdo_core::ChainError::Chain(format!(
                    "resume requested TokenContract {token_contract}, but the persisted mock fill is {}",
                    self.token_contract
                )));
            }
            let fill = self.fill().await?;
            if !fill.token_contract.eq_ignore_ascii_case(token_contract) {
                return Err(dexdo_core::ChainError::Chain(format!(
                    "mock fill names {}, expected {token_contract}",
                    fill.token_contract
                )));
            }
            Ok(())
        }
    }

    #[cfg(feature = "shellnet")]
    #[async_trait::async_trait]
    impl super::SubscriptionOrderOps for SameTcMockSubscriptionChain {
        async fn submit_subscription_order(
            &self,
            note: &dexdo_core::Address,
            _keys: &dexdo_core::KeyPair,
            order_book: &str,
            _model_hash: &str,
            max_price_per_tick: u128,
            ticks: u128,
            escrow: u128,
            order_flags: u8,
            deadline: u64,
            fill_cursor: &mut dexdo_core::MatchWatchCursor,
            before_post: &mut (dyn FnMut(
                String,
                u128,
                dexdo_core::MatchWatchCursor,
                Vec<(u128, dexdo_core::MatchedFill)>,
            ) -> anyhow::Result<()>
                      + Send),
        ) -> anyhow::Result<serde_json::Value> {
            anyhow::ensure!(
                note.with_workchain()
                    .eq_ignore_ascii_case(&self.buyer_note_addr()),
                "subscription submit note is not the mock buyer"
            );
            anyhow::ensure!(
                order_book.eq_ignore_ascii_case(&self.order_book),
                "subscription submit order book changed"
            );
            *fill_cursor = dexdo_core::MatchWatchCursor::new(0);
            let order_id_floor = self.order_id.lock().unwrap().unwrap_or(1);
            before_post(
                format!("boc-sha256:{}", "a".repeat(64)),
                order_id_floor,
                fill_cursor.clone(),
                Vec::new(),
            )?;

            self.money_posts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let order = self.chain.place_subscription_order(
                order_book,
                self.buyer_note.as_ref(),
                max_price_per_tick,
                ticks,
                escrow,
                order_flags,
                deadline,
            )?;
            *self.order_id.lock().unwrap() = Some(order.order_id);
            self.chain
                .place_buy_ticks(
                    &self.token_contract,
                    self.buyer_note.as_ref(),
                    u64::try_from(ticks)?,
                )
                .await?;
            Ok(serde_json::json!({ "accepted": true, "order_id": order.order_id }))
        }

        async fn subscription_placements(
            &self,
            order_book: &str,
            buyer_note: &str,
            order_id_floor: u128,
            max_price_per_tick: u128,
            ticks: u128,
        ) -> anyhow::Result<Vec<dexdo_core::InferenceSubscriptionPlacement>> {
            anyhow::ensure!(order_book.eq_ignore_ascii_case(&self.order_book));
            anyhow::ensure!(buyer_note.eq_ignore_ascii_case(&self.buyer_note_addr()));
            let placement = self.placement()?;
            anyhow::ensure!(placement.order_id >= order_id_floor);
            anyhow::ensure!(placement.max_price_per_tick == max_price_per_tick);
            anyhow::ensure!(placement.ticks == ticks);
            self.placement_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![placement])
        }

        async fn attributed_subscription_fills(
            &self,
            order_book: &str,
            buyer_note: &str,
            _cursor: &mut dexdo_core::MatchWatchCursor,
        ) -> anyhow::Result<Vec<(u128, dexdo_core::MatchedFill)>> {
            anyhow::ensure!(order_book.eq_ignore_ascii_case(&self.order_book));
            anyhow::ensure!(buyer_note.eq_ignore_ascii_case(&self.buyer_note_addr()));
            let fill = self.fill().await?;
            self.fill_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![(fill.order_id, fill)])
        }

        async fn subscription_order_active(
            &self,
            order_book: &str,
            order_id: u128,
            buyer_note: &str,
        ) -> anyhow::Result<bool> {
            anyhow::ensure!(order_book.eq_ignore_ascii_case(&self.order_book));
            anyhow::ensure!(buyer_note.eq_ignore_ascii_case(&self.buyer_note_addr()));
            anyhow::ensure!(order_id == self.recorded_order_id()?);
            self.fill().await?;
            Ok(false)
        }

        async fn subscription_deal_facts(
            &self,
            expected_note_addr: &str,
            order: &super::BuyerSubscriptionOrderRecord,
            matched: &super::BuyerJournalMatch,
        ) -> anyhow::Result<super::SubscriptionDealFacts> {
            dexdo_core::ChainBackend::assert_model_only_resume_target(
                self,
                &matched.token_contract,
            )
            .await?;
            let snapshot = dexdo_core::ChainBackend::deal_snapshot(
                self.chain.as_ref(),
                &matched.token_contract,
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("matched mock TokenContract has no snapshot"))?;
            Ok(super::SubscriptionDealFacts {
                state: snapshot.state,
                subscription: snapshot.subscription,
                seller_bond: snapshot.seller_bond,
                buyer_bond: snapshot.buyer_bond,
                model_name: order.frame_model.clone(),
                model_hash: order.model_hash.clone(),
                buyer_note: expected_note_addr.to_string(),
            })
        }

        /// Through this mock's own counted `settle_week`, so a booking the resume submits is
        /// indistinguishable from any other and shows up in `settle_week_posts`.
        async fn book_subscription_week(&self, token_contract: &str) {
            let _ = dexdo_core::ChainBackend::settle_week(self, &token_contract.to_string()).await;
        }
    }

    #[cfg(feature = "shellnet")]
    #[async_trait::async_trait]
    impl dexdo_core::ChainBackend for SameTcMockSubscriptionChain {
        async fn discover_offers(
            &self,
        ) -> Result<Vec<dexdo_core::OfferListing>, dexdo_core::ChainError> {
            dexdo_core::ChainBackend::discover_offers(self.chain.as_ref()).await
        }

        async fn post_offer(
            &self,
            offer: dexdo_core::SellOffer,
            note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            dexdo_core::ChainBackend::post_offer(self.chain.as_ref(), offer, note).await
        }

        async fn place_buy(
            &self,
            token_contract: &dexdo_core::TokenContract,
            _note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            self.money_posts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(dexdo_core::ChainError::Chain(format!(
                "durable subscription resume attempted a second BUY for {token_contract}"
            )))
        }

        async fn place_buy_by_model(
            &self,
            _note: &dyn dexdo_core::Note,
            _ticks: u128,
            _max_price_per_tick: u128,
            _escrow: u128,
            _flags: u8,
            _deadline: u64,
        ) -> Result<(), dexdo_core::ChainError> {
            self.money_posts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(dexdo_core::ChainError::Chain(
                "durable subscription resume attempted a second model BUY".to_string(),
            ))
        }

        fn model_buy_order_book_identity(&self) -> Option<String> {
            Some(self.order_book.clone())
        }

        async fn poll_attributed_model_buys_for_order_book(
            &self,
            order_book: &str,
            cursor: &mut dexdo_core::MatchWatchCursor,
        ) -> Result<Vec<(u128, dexdo_core::MatchedFill)>, dexdo_core::ChainError> {
            super::SubscriptionOrderOps::attributed_subscription_fills(
                self,
                order_book,
                &self.buyer_note_addr(),
                cursor,
            )
            .await
            .map_err(|error| dexdo_core::ChainError::Chain(error.to_string()))
        }

        async fn subscription_placements_since(
            &self,
            order_book: &str,
            buyer_note: &str,
            order_id_floor: u128,
            max_price_per_tick: u128,
            ticks: u128,
        ) -> Result<Vec<dexdo_core::InferenceSubscriptionPlacement>, dexdo_core::ChainError>
        {
            super::SubscriptionOrderOps::subscription_placements(
                self,
                order_book,
                buyer_note,
                order_id_floor,
                max_price_per_tick,
                ticks,
            )
            .await
            .map_err(|error| dexdo_core::ChainError::Chain(error.to_string()))
        }

        async fn buyer_order_is_active_for_owner(
            &self,
            order_book: &str,
            order_id: u128,
            buyer_note: &str,
        ) -> Result<bool, dexdo_core::ChainError> {
            super::SubscriptionOrderOps::subscription_order_active(
                self, order_book, order_id, buyer_note,
            )
            .await
            .map_err(|error| dexdo_core::ChainError::Chain(error.to_string()))
        }

        async fn wait_matched_token_contract(
            &self,
            _since_unix: i64,
            _timeout: std::time::Duration,
        ) -> Result<Option<dexdo_core::MatchedFill>, dexdo_core::ChainError> {
            self.lookback_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(dexdo_core::ChainError::Chain(
                "durable subscription must not fall back to event lookback".to_string(),
            ))
        }

        async fn assert_model_only_resume_target(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<(), dexdo_core::ChainError> {
            self.target_checks
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.assert_same_target(token_contract).await
        }

        async fn read_match(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<dexdo_core::Match, dexdo_core::ChainError> {
            dexdo_core::ChainBackend::read_match(self.chain.as_ref(), token_contract).await
        }

        async fn open_stream(
            &self,
            token_contract: &dexdo_core::TokenContract,
            enc_endpoint: Vec<u8>,
            note: &dyn dexdo_core::Note,
        ) -> Result<(), dexdo_core::ChainError> {
            dexdo_core::ChainBackend::open_stream(
                self.chain.as_ref(),
                token_contract,
                enc_endpoint,
                note,
            )
            .await
        }

        async fn read_handover(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<Vec<u8>>, dexdo_core::ChainError> {
            dexdo_core::ChainBackend::read_handover(self.chain.as_ref(), token_contract).await
        }

        async fn accept_probe(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<(), dexdo_core::ChainError> {
            dexdo_core::ChainBackend::accept_probe(self.chain.as_ref(), token_contract).await
        }

        async fn claim_tokens(
            &self,
            token_contract: &dexdo_core::TokenContract,
            note: &dyn dexdo_core::Note,
            cumulative_tokens: u128,
        ) -> Result<(), dexdo_core::ChainError> {
            self.claim_posts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            dexdo_core::ChainBackend::claim_tokens(
                self.chain.as_ref(),
                token_contract,
                note,
                cumulative_tokens,
            )
            .await
        }

        async fn finalize(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<(), dexdo_core::ChainError> {
            self.finalize_posts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            dexdo_core::ChainBackend::finalize(self.chain.as_ref(), token_contract).await
        }

        async fn settle_week(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<(), dexdo_core::ChainError> {
            self.settle_week_posts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            dexdo_core::ChainBackend::settle_week(self.chain.as_ref(), token_contract).await
        }

        async fn stop(
            &self,
            token_contract: &dexdo_core::TokenContract,
            note: &dyn dexdo_core::Note,
        ) -> Result<dexdo_core::Settlement, dexdo_core::ChainError> {
            self.stop_posts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            dexdo_core::ChainBackend::stop(self.chain.as_ref(), token_contract, note).await
        }

        async fn buyer_stop_settlement(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<(u128, u128)>, dexdo_core::ChainError> {
            self.receipt_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            dexdo_core::ChainBackend::buyer_stop_settlement(self.chain.as_ref(), token_contract)
                .await
        }

        async fn deal_state(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<dexdo_core::DealChainState>, dexdo_core::ChainError> {
            dexdo_core::ChainBackend::deal_state(self.chain.as_ref(), token_contract).await
        }

        async fn deal_subscription(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<dexdo_core::DealSubscription>, dexdo_core::ChainError> {
            dexdo_core::ChainBackend::deal_subscription(self.chain.as_ref(), token_contract).await
        }

        async fn deal_snapshot(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Result<Option<dexdo_core::DealChainSnapshot>, dexdo_core::ChainError> {
            dexdo_core::ChainBackend::deal_snapshot(self.chain.as_ref(), token_contract).await
        }

        async fn snapshot(
            &self,
            token_contract: &dexdo_core::TokenContract,
        ) -> Option<dexdo_core::StreamSnapshot> {
            dexdo_core::ChainBackend::snapshot(self.chain.as_ref(), token_contract).await
        }
    }

    #[cfg(feature = "shellnet")]
    fn journal_pipeline_selection() -> super::BuyerQuoteSelection {
        let journal = buyer_submit_test_journal();
        super::BuyerQuoteSelection {
            order_book: "model_order_book",
            escrow: journal.escrow,
            quote: journal.quote,
            quoted_order: Some(journal.quoted_order),
        }
    }

    #[cfg(feature = "shellnet")]
    async fn journal_pipeline_place(
        chain: &JournalPipelineChain,
        journal_path: &std::path::Path,
    ) -> (String, super::BuyerQuoteSelection, anyhow::Result<()>) {
        let journal = buyer_submit_test_journal();
        let note_addr = journal.note_addr;
        let selection = journal_pipeline_selection();
        let mut cursor = dexdo_core::MatchWatchCursor::default();
        let result = super::place_quote_bound_buy_with_journal(
            chain,
            &dexdo::buyer::Buyer::generate(),
            &super::BuyerSubmitIntent::foreground(),
            None,
            &selection,
            2,
            1_000_000,
            selection.escrow,
            &note_addr,
            &mut cursor,
            journal_path,
            None,
        )
        .await;
        (note_addr, selection, result)
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn durable_buy_journals_before_single_post_and_retains_ambiguity() {
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-pipeline-ambiguous");
        let journal_path = dir.join("journal.json");
        let chain = JournalPipelineChain {
            submit_error: Some("ambiguous"),
            fill: None,
            expected_journal_path: journal_path.clone(),
            sequence: std::sync::Mutex::new(Vec::new()),
            post_count: std::sync::atomic::AtomicUsize::new(0),
            poll_count: std::sync::atomic::AtomicUsize::new(0),
        };
        let (note_addr, selection, result) = journal_pipeline_place(&chain, &journal_path).await;
        assert!(result.as_ref().is_err_and(super::is_ambiguous_submit_error));
        assert!(
            journal_path.exists(),
            "callback must durably write before POST"
        );
        assert_eq!(chain.sequence.lock().unwrap().as_slice(), &["post"]);
        let error = super::complete_buyer_submit_with_journal(
            &chain,
            selection.quoted_order.as_ref(),
            2,
            1_000_000,
            result,
            &note_addr,
            &journal_path,
        )
        .await
        .expect_err("changed quoted row must fail closed");
        assert!(super::is_ambiguous_submit_error(&error));
        assert!(journal_path.exists());
        assert_eq!(
            chain.post_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "reconciliation must never resubmit"
        );
    }

    #[cfg(feature = "shellnet")]
    // This test must serialize process-global DEXDO_PN_POOL for the full async scenario.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn on_demand_production_initializer_two_requests_return_fresh_then_durable_typed_503_without_second_post(
    ) {
        let _env_lock = dexdo_pn_pool_env_lock().lock().unwrap();
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-issue-61-http-ambiguous");
        let pool_path = dir.join("pool.json");
        let mut fixture = buyer_submit_test_journal();
        fixture.intent = super::BuyerSubmitIntent::on_demand();
        fixture.expected_token_contract = None;
        std::fs::write(
            &pool_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
                "notes": [{
                    "address": fixture.note_addr,
                    "owner_secret_key_hex": "00"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let _env = EnvVarGuard::set("DEXDO_PN_POOL", pool_path.as_os_str());
        let money_lock = super::BuyerMoneyLock::open(&fixture.note_addr).unwrap();
        let _ = std::fs::remove_file(&money_lock.journal_path);
        let chain = std::sync::Arc::new(JournalPipelineChain {
            submit_error: Some("ambiguous"),
            fill: None,
            expected_journal_path: money_lock.journal_path.clone(),
            sequence: std::sync::Mutex::new(Vec::new()),
            post_count: std::sync::atomic::AtomicUsize::new(0),
            poll_count: std::sync::atomic::AtomicUsize::new(0),
        });
        let buyer = std::sync::Arc::new(dexdo::buyer::Buyer::generate());
        let args = std::sync::Arc::new(super::BuyerArgs {
            mock: super::MockFlags {
                mock_model: false,
                mock_chain: false,
            },
            identity: super::IdentityArgs {
                note_key: None,
                note_index: 0,
                note_addr: Some(fixture.note_addr.clone()),
            },
            registry: super::ModelRegistryValidationArgs::default(),
            endpoints_file: None,
            deals_dir: Some(dir.join("deals")),
            token_contract: None,
            resume: false,
            market: None,
            max_tokens: 8,
            local_listen: None,
            continuity_mode: super::ContinuityModeArg::OnDemand,
            json: false,
            anthropic_compat: false,
            frame_model: Some("qwen--qwen3--32b".to_string()),
            allow_unverified_model: true,
            models: dir.join("models.json"),
            ticks: fixture.ticks,
            max_price_per_tick: fixture.max_price_per_tick,
            escrow: Some(fixture.escrow),
            contracts: dir.join("offline-contracts.json"),
            policy: None,
        });
        let state = super::build_on_demand_buyer_api_state(
            chain.clone(),
            buyer,
            args,
            None,
            "qwen--qwen3--32b".to_string(),
            dexdo::buyer::api::ContentCheck::Skip,
            std::sync::Arc::new(dexdo::seller::ModelsConfig::empty()),
            None,
            dexdo::buyer::api::BuyerApiFailurePolicy::default(),
            None,
            None,
            super::BuyerShellnetPreflight::OfflineTest,
            None,
            true,
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (addr, task) =
            dexdo::buyer::api::serve("127.0.0.1:0".parse().unwrap(), state, false, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("bind real lazy Axum API");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        for (request, expected_state, expected_origin) in [
            (1, "fresh_unresolved", "fresh_submit"),
            (2, "durable_unresolved", "durable_journal"),
        ] {
            let started = std::time::Instant::now();
            let response = client
                .post(format!("http://{addr}/v1/chat/completions"))
                .json(&serde_json::json!({
                    "model": "qwen--qwen3--32b",
                    "messages": [{"role": "user", "content": format!("issue 61 request {request}")}],
                    "max_tokens": 1,
                    "stream": false
                }))
                .send()
                .await
                .unwrap_or_else(|error| panic!("request {request} must return before timeout: {error}"));
            assert!(
                started.elapsed() < std::time::Duration::from_secs(2),
                "request {request} must return before the outer initializer timeout"
            );
            assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
            let body = response.bytes().await.expect("503 body must be readable");
            assert!(!body.is_empty(), "request {request} 503 must carry JSON");
            let body: serde_json::Value =
                serde_json::from_slice(&body).expect("503 body must be JSON");
            let recovery = &body["error"]["submit_reconciliation"];
            assert!(
                !recovery.is_null(),
                "request {request} lost typed reconciliation: {body}"
            );
            assert_eq!(
                recovery["submit_identity"],
                serde_json::json!(fixture.submit_identity)
            );
            assert_eq!(recovery["recovery_anchor"]["order_id"], "1");
            assert_eq!(
                recovery["recovery_anchor"]["token_contract"],
                serde_json::json!(fixture.quoted_order.token_contract)
            );
            assert_eq!(recovery["state"], expected_state);
            assert_eq!(recovery["origin"], expected_origin);
        }

        let stored = super::load_buyer_submit_journal(&money_lock.journal_path, &fixture.note_addr)
            .unwrap()
            .expect("ambiguous on-demand submit must retain its durable journal");
        assert_eq!(stored.submit_identity, fixture.submit_identity);
        let serialized: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&money_lock.journal_path).unwrap()).unwrap();
        assert!(
            serialized.get("reconciled_submit_identity").is_none(),
            "v2 journal shape must not grow a recovery field"
        );
        assert_eq!(
            chain.post_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the durable second request must not send a second BOC"
        );
        let _ = shutdown_tx.send(());
        task.await.expect("real lazy Axum API joins");
    }

    #[tokio::test]
    async fn anthropic_real_router_preserves_typed_submit_reconciliation() {
        let reconciliation = dexdo::buyer::api::BuyerSubmitReconciliation {
            submit_identity: format!("boc-sha256:{}", "a".repeat(64)),
            recovery_anchor: dexdo::buyer::api::BuyerSubmitRecoveryAnchor {
                order_id: 7,
                token_contract: format!("0:{}", "3".repeat(64)),
            },
            state: dexdo::buyer::api::BuyerSubmitReconciliationState::DurableUnresolved,
            origin: dexdo::buyer::api::BuyerSubmitReconciliationOrigin::DurableJournal,
        };
        let expected = reconciliation.clone();
        let state = dexdo::buyer::api::ApiState::lazy(
            std::sync::Arc::new(dexdo::buyer::Buyer::generate()),
            "qwen--qwen3--32b".to_string(),
            std::sync::Arc::new(move || {
                let reconciliation = reconciliation.clone();
                Box::pin(async move {
                    Err(dexdo::buyer::api::DealInitError::with_reconciliation(
                        "durable submit remains unresolved",
                        reconciliation,
                    ))
                }) as dexdo::buyer::api::DealInitFuture
            }),
            std::time::Duration::from_secs(2),
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (addr, task) =
            dexdo::buyer::api::serve("127.0.0.1:0".parse().unwrap(), state, true, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("bind Anthropic-compatible router");

        let response = reqwest::Client::new()
            .post(format!("http://{addr}/v1/messages"))
            .json(&serde_json::json!({
                "model": "qwen--qwen3--32b",
                "messages": [{"role": "user", "content": "resume"}],
                "max_tokens": 1,
                "stream": false
            }))
            .send()
            .await
            .expect("Anthropic request returns");
        assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        let body: serde_json::Value = response.json().await.expect("typed Anthropic JSON");
        assert_eq!(body["type"], "error");
        assert_eq!(
            body["error"]["submit_reconciliation"]["submit_identity"],
            expected.submit_identity
        );
        assert_eq!(
            body["error"]["submit_reconciliation"]["recovery_anchor"]["order_id"],
            "7"
        );
        assert_eq!(
            body["error"]["submit_reconciliation"]["recovery_anchor"]["token_contract"],
            expected.recovery_anchor.token_contract
        );
        assert_eq!(
            body["error"]["submit_reconciliation"]["state"],
            "durable_unresolved"
        );
        assert_eq!(
            body["error"]["submit_reconciliation"]["origin"],
            "durable_journal"
        );

        let _ = shutdown_tx.send(());
        task.await.expect("Anthropic router joins");
    }

    #[cfg(feature = "shellnet")]
    // This test must serialize process-global DEXDO_PN_POOL for the full async scenario.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn issue_547_buyer_recovered_on_demand_resume_starts_monitor_without_second_money_post() {
        let _env_lock = dexdo_pn_pool_env_lock().lock().unwrap();
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-issue-61-resume");
        let pool_path = dir.join("pool.json");
        let mut fixture = buyer_submit_test_journal();
        (fixture.max_price_per_tick, fixture.escrow) = (
            dexdo_core::PRICE_STEP,
            dexdo_core::required_escrow_for_buy(fixture.ticks, dexdo_core::PRICE_STEP),
        );
        fixture.intent = super::BuyerSubmitIntent::on_demand();
        fixture.expected_token_contract = None;
        std::fs::write(
            &pool_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
                "notes": [{
                    "address": fixture.note_addr,
                    "owner_secret_key_hex": "00"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let _env = EnvVarGuard::set("DEXDO_PN_POOL", pool_path.as_os_str());
        let money_lock = super::BuyerMoneyLock::open(&fixture.note_addr).unwrap();
        let _ = std::fs::remove_file(&money_lock.journal_path);
        let selection = journal_pipeline_selection();
        let first = JournalPipelineChain {
            submit_error: Some("ambiguous"),
            fill: None,
            expected_journal_path: money_lock.journal_path.clone(),
            sequence: std::sync::Mutex::new(Vec::new()),
            post_count: std::sync::atomic::AtomicUsize::new(0),
            poll_count: std::sync::atomic::AtomicUsize::new(0),
        };
        let buyer = dexdo::buyer::Buyer::generate();
        let error = super::execute_buyer_quote_submit(
            &first,
            &buyer,
            false,
            Some(&fixture.note_addr),
            &fixture.intent,
            None,
            &selection,
            fixture.ticks,
            fixture.max_price_per_tick,
            fixture.escrow,
            None,
            |_| std::future::ready(Ok(())),
        )
        .await
        .expect_err("first submit is intentionally ambiguous");
        assert!(super::is_ambiguous_submit_error(&error), "{error:#}");
        assert_eq!(
            first.post_count.load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        let fill = dexdo_core::MatchedFill {
            order_id: fixture.quoted_order.order_id,
            token_contract: fixture.quoted_order.token_contract.clone().unwrap(),
            ticks: fixture.ticks,
            price_per_tick: fixture.quoted_order.price_per_tick,
        };
        let buyer_note = std::sync::Arc::new(dexdo_core::LocalNote::generate());
        // shape B: the gateway makes the ONE bind, and reports the port it actually got.
        let seller = dexdo::seller::start_gateway("127.0.0.1:0".parse().unwrap())
            .await
            .expect("start TLS mock-token gateway");
        let gateway_addr = seller.listen_addr;
        let mut gateway_ready = false;
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(gateway_addr).await.is_ok() {
                gateway_ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(gateway_ready, "TLS mock-token gateway must bind");
        let buyer_pubkey = dexdo_core::Note::pubkey(buyer_note.as_ref());
        let (state, deal) = ordinary_gateway_snapshot(fixture.ticks as u64);
        seller
            .state
            .register_stream(&fill.token_contract, buyer_pubkey.clone(), 2, state, deal)
            .expect("register strict ordinary resumed capacity");
        let handover = dexdo_core::Handover {
            endpoint: format!("https://{gateway_addr}"),
            tls_fingerprint: seller.tls_fingerprint.clone(),
        };
        let encrypted_handover = seller.note.encrypt_to(&buyer_pubkey, &handover.to_bytes());
        let resumed = std::sync::Arc::new(ResumeCommandChain {
            fill: fill.clone(),
            handover: encrypted_handover,
            post_count: std::sync::atomic::AtomicUsize::new(0),
            poll_count: std::sync::atomic::AtomicUsize::new(0),
            stop_count: std::sync::atomic::AtomicUsize::new(0),
            deal_state_count: std::sync::atomic::AtomicUsize::new(0),
        });

        let policy_path = dir.join("policy.json");
        std::fs::write(
            &policy_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "buyer": {
                    "on": {
                        "no_handover_after_match": "fail_closed",
                        "malformed_handover": "fail_closed",
                        "dead_gateway": "fail_closed",
                        "empty_stream": "fail_closed",
                        "seller_stalls_mid_stream": "accept_delivered_then_reclaim",
                        "bad_output_scam": "stop"
                    },
                    "failover": {
                        "max_sellers_to_try": 1,
                        "total_spend_cap_shells": 1000000000
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let args = super::BuyerArgs {
            mock: super::MockFlags {
                mock_model: false,
                mock_chain: false,
            },
            identity: super::IdentityArgs {
                note_key: None,
                note_index: 0,
                note_addr: Some(fixture.note_addr.clone()),
            },
            registry: super::ModelRegistryValidationArgs::default(),
            endpoints_file: None,
            deals_dir: Some(dir.join("deals")),
            token_contract: None,
            resume: true,
            market: None,
            max_tokens: 8,
            local_listen: Some("127.0.0.1:0".parse().unwrap()),
            continuity_mode: super::ContinuityModeArg::OnDemand,
            json: true,
            anthropic_compat: false,
            frame_model: Some("qwen--qwen3--32b".to_string()),
            allow_unverified_model: true,
            models: dir.join("models.json"),
            ticks: fixture.ticks,
            max_price_per_tick: fixture.max_price_per_tick,
            escrow: Some(fixture.escrow),
            contracts: dir.join("offline-contracts.json"),
            policy: Some(policy_path),
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let command_chain: std::sync::Arc<dyn dexdo_core::ChainBackend> = resumed.clone();
        let command_note: std::sync::Arc<dyn dexdo_core::Note> = buyer_note;
        let (machine_writer, captured_machine_events) =
            crate::cli::machine::BuyerEventWriter::capturing();
        let command = tokio::spawn(async move {
            let mut machine_events = Some(machine_writer);
            let mut machine_context = super::BuyerMachineErrorContext::default();
            super::run_buyer_inner(
                args,
                &mut machine_events,
                &mut machine_context,
                super::BuyerCommandRuntime {
                    backend: Some((command_chain, command_note)),
                    shellnet_preflight: super::BuyerShellnetPreflight::OfflineTest,
                    shutdown: Box::pin(async move {
                        let _ = shutdown_rx.await;
                    }),
                },
            )
            .await
        });
        // shape B: production makes the ONE bind. Reserving a port here and releasing it
        // before `run_buyer_inner` re-binds hands it back to the kernel, and any concurrent
        // `bind(0)` can be given that exact port in between. `--local-listen 127.0.0.1:0` lets the
        // kernel choose, and `endpoint_ready.bind_addr` is where production reports what it got.
        let mut bound = None;
        for _ in 0..100 {
            bound = captured_machine_events
                .lock()
                .expect("captured buyer events lock poisoned")
                .iter()
                .find(|event| event["event"] == "endpoint_ready")
                .and_then(|event| event["bind_addr"].as_str())
                .map(str::to_string);
            if bound.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let api_addr = bound.expect("run_buyer_inner must report the local API it bound");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let models_url = format!("http://{api_addr}/v1/models");
        let mut ready = false;
        for _ in 0..100 {
            if client
                .get(&models_url)
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(ready, "run_buyer_inner must bind the real local API");
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while resumed
                .deal_state_count
                .load(std::sync::atomic::Ordering::SeqCst)
                == 0
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("model-only on-demand recovery monitor starts before the first chat request");
        assert_eq!(
            resumed.post_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "startup recovery monitoring must not submit a BUY while idle"
        );
        let response = client
            .post(format!("http://{api_addr}/v1/chat/completions"))
            .json(&serde_json::json!({
                "model": "qwen--qwen3--32b",
                "messages": [{"role": "user", "content": "resume through the real command"}],
                "max_tokens": 1,
                "stream": true
            }))
            .send()
            .await
            .expect("resumed local request reaches the gateway stream");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let stream = response.text().await.expect("SSE response body");
        assert!(stream.contains("data:"), "{stream}");
        assert!(stream.contains("[DONE]"), "{stream}");

        let _ = shutdown_tx.send(());
        command
            .await
            .expect("run_buyer_inner task joins")
            .expect("run_buyer_inner resume completes through settlement");
        assert_eq!(
            resumed.post_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "run_buyer_inner --resume must not send a second money POST"
        );
        assert_eq!(
            resumed.poll_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "run_buyer_inner must reconcile the retained journal exactly once"
        );
        assert_eq!(
            resumed.stop_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "graceful command shutdown must submit one terminal AmicableSplit STOP"
        );
        assert!(
            super::load_buyer_submit_journal(&money_lock.journal_path, &fixture.note_addr)
                .unwrap()
                .is_none(),
            "authoritatively matched journal must clear only after handover is adopted"
        );
        let captured = captured_machine_events
            .lock()
            .expect("captured buyer events lock poisoned");
        let event_names = captured
            .iter()
            .filter_map(|event| event["event"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            event_names,
            [
                "starting",
                "resume_selected",
                "handover_waiting",
                "handover_received",
                "endpoint_binding",
                "endpoint_ready",
                "stopping",
                "settlement_submitted",
                "settled",
                "exiting",
            ],
            "recovered on-demand resume must emit only the complete canonical stream"
        );
        let canonical_token_contract = dexdo_core::Address::parse(&fill.token_contract)
            .unwrap()
            .with_workchain();
        let canonical_deal_handle = super::deals::make_handle_id(
            &canonical_token_contract,
            super::deals::DealHandleRole::Buyer,
        );
        for event in captured.iter().filter(|event| {
            matches!(
                event["event"].as_str(),
                Some(
                    "resume_selected"
                        | "handover_waiting"
                        | "handover_received"
                        | "endpoint_binding"
                        | "endpoint_ready"
                        | "stopping"
                        | "settlement_submitted"
                        | "settled"
                        | "exiting"
                )
            )
        }) {
            assert_eq!(
                event["token_contract"], canonical_token_contract,
                "every deal-bound event must carry the real normalized TokenContract: {event}"
            );
            assert!(
                !event.to_string().contains("pending:"),
                "canonical stream must reject pending placeholders: {event}"
            );
        }
        for event_name in [
            "resume_selected",
            "handover_received",
            "endpoint_binding",
            "endpoint_ready",
            "stopping",
            "settlement_submitted",
            "settled",
            "exiting",
        ] {
            let event = captured
                .iter()
                .find(|event| event["event"] == event_name)
                .unwrap_or_else(|| panic!("missing {event_name} event"));
            assert_eq!(
                event["deal_handle"], canonical_deal_handle,
                "{event_name} must carry the deal handle derived from the real TokenContract"
            );
        }
        assert_eq!(
            &event_names[..6],
            [
                "starting",
                "resume_selected",
                "handover_waiting",
                "handover_received",
                "endpoint_binding",
                "endpoint_ready",
            ],
            "{event_names:?}"
        );
        let resume = captured
            .iter()
            .find(|event| event["event"] == "resume_selected")
            .expect("resume_selected object");
        assert_eq!(resume["source"], "durable_journal");
        assert_eq!(
            resume["token_contract"],
            serde_json::json!(canonical_token_contract)
        );
        assert_eq!(
            resume["submit_reconciliation"]["submit_identity"],
            fixture.submit_identity
        );
        assert_eq!(
            resume["submit_reconciliation"]["recovery_anchor"]["order_id"],
            fixture.quoted_order.order_id.to_string()
        );
        assert_eq!(
            resume["submit_reconciliation"]["recovery_anchor"]["token_contract"],
            serde_json::json!(canonical_token_contract)
        );
        seller.server_task.abort();
    }

    #[cfg(feature = "shellnet")]
    // This test must serialize process-global DEXDO_PN_POOL for the full async scenario.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn durable_subscription_resume_streams_and_preserves_without_second_buy_or_auto_terminal_write(
    ) {
        let _env_lock = dexdo_pn_pool_env_lock().lock().unwrap();
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-durable-subscription-command-resume");
        let pool_path = dir.join("pool.json");
        let order_id = 1_001;
        let deadline = super::unix_now_secs().saturating_add(3_600);
        let mut journal = subscription_test_journal(order_id, deadline);
        journal.ticks = u128::from(dexdo_core::SUBSCRIPTION_WEEKS) * 2;
        let reserve = subscription_test_reserve(journal.ticks, journal.max_price_per_tick);
        journal.deposit = reserve.deposit;
        journal.buyer_bond = reserve.buyer_bond;
        journal.escrow = reserve.total_escrow;
        let mut placement = subscription_test_placement(order_id, deadline);
        placement.ticks = journal.ticks;
        std::fs::write(
            &pool_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
                "notes": [{
                    "address": journal.note_addr,
                    "owner_secret_key_hex": "00"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let _env = EnvVarGuard::set("DEXDO_PN_POOL", pool_path.as_os_str());
        let money_lock = super::BuyerMoneyLock::open(&journal.note_addr).unwrap();
        let _ = std::fs::remove_file(&money_lock.journal_path);
        let _ = std::fs::remove_file(&money_lock.subscriptions_path);
        super::write_buyer_subscription_submit_journal(&money_lock.journal_path, &journal).unwrap();

        let mut expected_state =
            super::BuyerSubscriptionState::empty(&journal.note_addr).expect("empty state");
        let expected_record =
            super::record_subscription_placement(&mut expected_state, &journal, &placement)
                .expect("canonical durable placement");
        let fill = dexdo_core::MatchedFill {
            order_id,
            token_contract: subscription_test_tc('7'),
            ticks: journal.ticks,
            price_per_tick: journal.max_price_per_tick,
        };
        let snapshot = subscription_test_snapshot(&expected_record, &journal.note_addr);
        let buyer_note = std::sync::Arc::new(dexdo_core::LocalNote::generate());
        // shape B: the gateway makes the ONE bind, and reports the port it actually got.
        let seller = dexdo::seller::start_gateway("127.0.0.1:0".parse().unwrap())
            .await
            .expect("start TLS mock-token gateway");
        let gateway_addr = seller.listen_addr;
        let mut gateway_ready = false;
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(gateway_addr).await.is_ok() {
                gateway_ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(gateway_ready, "TLS mock-token gateway must bind");
        let buyer_pubkey = dexdo_core::Note::pubkey(buyer_note.as_ref());
        seller
            .state
            .register_stream(
                &fill.token_contract,
                buyer_pubkey.clone(),
                2,
                snapshot.state,
                snapshot.subscription,
            )
            .unwrap();
        let handover = dexdo_core::Handover {
            endpoint: format!("https://{gateway_addr}"),
            tls_fingerprint: seller.tls_fingerprint.clone(),
        };
        let encrypted_handover = seller.note.encrypt_to(&buyer_pubkey, &handover.to_bytes());
        let resumed = std::sync::Arc::new(SubscriptionResumeCommandChain {
            order_book: journal.order_book.clone(),
            placement,
            fill: fill.clone(),
            snapshot,
            handover: encrypted_handover,
            money_posts: std::sync::atomic::AtomicUsize::new(0),
            placement_reads: std::sync::atomic::AtomicUsize::new(0),
            fill_reads: std::sync::atomic::AtomicUsize::new(0),
            lookback_reads: std::sync::atomic::AtomicUsize::new(0),
            target_checks: std::sync::atomic::AtomicUsize::new(0),
            stop_count: std::sync::atomic::AtomicUsize::new(0),
            dispute_count: std::sync::atomic::AtomicUsize::new(0),
            cleanup_count: std::sync::atomic::AtomicUsize::new(0),
            deal_state_count: std::sync::atomic::AtomicUsize::new(0),
        });

        let policy_path = dir.join("policy.json");
        std::fs::write(
            &policy_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "buyer": {
                    "on": {
                        "no_handover_after_match": "fail_closed",
                        "malformed_handover": "fail_closed",
                        "dead_gateway": "fail_closed",
                        "empty_stream": "fail_closed",
                        "seller_stalls_mid_stream": "accept_delivered_then_reclaim",
                        "bad_output_scam": "stop"
                    },
                    "failover": {
                        "max_sellers_to_try": 1,
                        "total_spend_cap_shells": 1000000000
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let args = super::BuyerArgs {
            mock: super::MockFlags {
                mock_model: false,
                mock_chain: false,
            },
            identity: super::IdentityArgs {
                note_key: None,
                note_index: 0,
                note_addr: Some(journal.note_addr.clone()),
            },
            registry: super::ModelRegistryValidationArgs::default(),
            endpoints_file: None,
            deals_dir: Some(dir.join("deals")),
            token_contract: None,
            resume: true,
            market: None,
            max_tokens: 8,
            local_listen: Some("127.0.0.1:0".parse().unwrap()),
            continuity_mode: super::ContinuityModeArg::OnDemand,
            json: true,
            anthropic_compat: false,
            frame_model: Some(journal.frame_model.clone()),
            allow_unverified_model: true,
            models: dir.join("models.json"),
            ticks: journal.ticks,
            max_price_per_tick: journal.max_price_per_tick,
            escrow: Some(journal.escrow),
            contracts: dir.join("offline-contracts.json"),
            policy: Some(policy_path),
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let command_chain: std::sync::Arc<dyn dexdo_core::ChainBackend> = resumed.clone();
        let command_note: std::sync::Arc<dyn dexdo_core::Note> = buyer_note;
        let (machine_writer, captured_machine_events) =
            crate::cli::machine::BuyerEventWriter::capturing();
        let command = tokio::spawn(async move {
            let mut machine_events = Some(machine_writer);
            let mut machine_context = super::BuyerMachineErrorContext::default();
            super::run_buyer_inner(
                args,
                &mut machine_events,
                &mut machine_context,
                super::BuyerCommandRuntime {
                    backend: Some((command_chain, command_note)),
                    shellnet_preflight: super::BuyerShellnetPreflight::OfflineTest,
                    shutdown: Box::pin(async move {
                        let _ = shutdown_rx.await;
                    }),
                },
            )
            .await
        });
        // shape B: production makes the ONE bind. Reserving a port here and releasing it
        // before `run_buyer_inner` re-binds hands it back to the kernel, and any concurrent
        // `bind(0)` can be given that exact port in between. `--local-listen 127.0.0.1:0` lets the
        // kernel choose, and `endpoint_ready.bind_addr` is where production reports what it got.
        let mut bound = None;
        for _ in 0..100 {
            bound = captured_machine_events
                .lock()
                .expect("captured buyer events lock poisoned")
                .iter()
                .find(|event| event["event"] == "endpoint_ready")
                .and_then(|event| event["bind_addr"].as_str())
                .map(str::to_string);
            if bound.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let api_addr = bound.expect("run_buyer_inner must report the local API it bound");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let models_url = format!("http://{api_addr}/v1/models");
        let mut ready = false;
        for _ in 0..100 {
            if client
                .get(&models_url)
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        if !ready {
            let _ = shutdown_tx.send(());
            let result = command.await.expect("run_buyer_inner task joins");
            panic!("run_buyer_inner must bind the real local API: {result:#?}");
        }
        let response = client
            .post(format!("http://{api_addr}/v1/chat/completions"))
            .json(&serde_json::json!({
                "model": journal.frame_model,
                "messages": [{
                    "role": "user",
                    "content": "resume the durable subscription through the TLS gateway"
                }],
                "max_tokens": 1,
                "stream": true
            }))
            .send()
            .await
            .expect("resumed subscription request reaches the gateway stream");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let stream = response.text().await.expect("SSE response body");
        assert!(stream.contains("data:"), "{stream}");
        assert!(stream.contains("[DONE]"), "{stream}");

        let _ = shutdown_tx.send(());
        command
            .await
            .expect("run_buyer_inner task joins")
            .expect("durable subscription resume preserves the live deal");
        assert_eq!(
            resumed
                .money_posts
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "durable subscription resume must never submit a second BUY"
        );
        assert_eq!(
            resumed
                .placement_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the exact durable placement must reconcile once"
        );
        assert_eq!(
            resumed.fill_reads.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the durable placement must resolve through its attributable seller fill"
        );
        assert_eq!(
            resumed
                .lookback_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "durable subscription facts must precede and suppress historical lookback"
        );
        assert_eq!(
            resumed
                .target_checks
                .load(std::sync::atomic::Ordering::SeqCst),
            2,
            "match adoption and active resume must each prove ownership and model identity"
        );
        assert!(
            resumed
                .deal_state_count
                .load(std::sync::atomic::Ordering::SeqCst)
                > 0,
            "the streamed response must pass the production by-fact open-deal gate"
        );
        assert_eq!(
            resumed.stop_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "graceful subscription shutdown must not auto-STOP"
        );
        assert_eq!(
            resumed
                .dispute_count
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "successful subscription streaming must not dispute"
        );
        assert_eq!(
            resumed
                .cleanup_count
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "an opened subscription must not run automatic reclaim/cleanup"
        );
        assert!(
            super::load_buyer_money_journal(&money_lock.journal_path, &journal.note_addr)
                .unwrap()
                .is_none(),
            "authoritatively matched subscription journal must clear"
        );
        let stored = super::load_buyer_subscription_state(
            &money_lock.subscriptions_path,
            &journal.note_addr,
        )
        .unwrap();
        assert_eq!(stored.orders.len(), 1);
        assert_eq!(
            stored.orders[0].phase,
            super::BuyerSubscriptionPhase::Matched,
            "graceful application shutdown preserves the durable subscription as resumable"
        );
        let stored_match = stored.orders[0]
            .matched
            .as_ref()
            .expect("durable subscription keeps its matched seller");
        assert_eq!(stored_match.token_contract, fill.token_contract);

        let captured = captured_machine_events
            .lock()
            .expect("captured buyer events lock poisoned");
        let event_names = captured
            .iter()
            .filter_map(|event| event["event"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            event_names,
            [
                "starting",
                "resume_selected",
                "handover_waiting",
                "handover_received",
                "endpoint_binding",
                "endpoint_ready",
                "stopping",
                "subscription_preserved",
                "exiting",
            ],
            "subscription resume must emit preservation, never implicit settlement"
        );
        assert!(
            !captured.iter().any(|event| matches!(
                event["event"].as_str(),
                Some("buy_submitted" | "settlement_submitted" | "settled")
            )),
            "subscription resume must not report a second BUY or terminal chain write"
        );
        let canonical_token_contract = dexdo_core::Address::parse(&fill.token_contract)
            .unwrap()
            .with_workchain();
        let canonical_deal_handle = super::deals::make_handle_id(
            &canonical_token_contract,
            super::deals::DealHandleRole::Buyer,
        );
        let resume = captured
            .iter()
            .find(|event| event["event"] == "resume_selected")
            .expect("resume_selected object");
        assert_eq!(resume["source"], "durable_subscription");
        assert_eq!(resume["order_id"], order_id.to_string());
        assert_eq!(resume["token_contract"], canonical_token_contract);
        assert_eq!(resume["deal_handle"], canonical_deal_handle);
        let preserved = captured
            .iter()
            .find(|event| event["event"] == "subscription_preserved")
            .expect("subscription_preserved object");
        assert_eq!(preserved["token_contract"], canonical_token_contract);
        assert_eq!(preserved["deal_handle"], canonical_deal_handle);
        assert_eq!(preserved["chain_write_submitted"], false);
        assert_eq!(preserved["terminal"], false);
        let exiting = captured
            .iter()
            .find(|event| event["event"] == "exiting")
            .expect("exiting object");
        assert_eq!(exiting["outcome"], "subscription_preserved");
        assert_eq!(exiting["exit_code"], 0);
        seller.server_task.abort();
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn one_mock_subscription_tc_reaches_restart_gateway_claim_finalize_and_stop_receipt() {
        use std::sync::atomic::Ordering;

        let (dir, _cleanup) = buyer_journal_test_dir("one-mock-subscription-tc-e2e");
        let endpoints_path = dir.join("endpoints.json");
        let test_consts = dexdo_core::ProtocolConsts {
            min_claim_interval: std::time::Duration::from_millis(1),
            min_seconds_per_tick: std::time::Duration::ZERO,
            claim_promote_window: std::time::Duration::from_millis(1),
            probe_window: std::time::Duration::ZERO,
            ..dexdo_core::ProtocolConsts::canonical()
        };
        let keeper_bounds = dexdo_core::ClaimBounds {
            min_claim_interval: test_consts.min_claim_interval,
            min_seconds_per_tick: test_consts.min_seconds_per_tick,
            promote_window: test_consts.claim_promote_window,
            probe_window: test_consts.probe_window,
            dispute_window: test_consts.dispute_window,
        };
        let chain = std::sync::Arc::new(dexdo_core::MockChainBackend::new(
            endpoints_path.clone(),
            test_consts,
            dexdo_core::DobParams::canonical(),
        ));
        let buyer_note = std::sync::Arc::new(dexdo_core::LocalNote::generate());
        let token_contract = subscription_test_tc('7');
        let order_book = subscription_test_book();
        let frame_model = "qwen--qwen3--32b";
        let model_hash = dexdo_core::model_hash_for(frame_model);
        let initial = SameTcMockSubscriptionChain::new(
            chain,
            buyer_note.clone(),
            token_contract.clone(),
            order_book.clone(),
            None,
        );
        let seller = dexdo::seller::start_gateway("127.0.0.1:0".parse().unwrap())
            .await
            .expect("start explicit mock-model gateway");
        let ticks = u128::from(dexdo_core::SUBSCRIPTION_WEEKS) * 2;
        let price = dexdo_core::PRICE_STEP;
        let cfg = dexdo::seller::SellerConfig {
            token_contract: token_contract.clone(),
            price_per_tick: u64::try_from(price).unwrap(),
            max_ticks: u64::try_from(ticks).unwrap(),
            subscription: true,
            gateway_advertise: seller.listen_addr.to_string(),
            mock_token_count: 2,
        };
        dexdo::seller::post_offer(&seller, &initial, &cfg)
            .await
            .expect("one subscription SELL rests on the mock chain");

        let note_addr = dexdo_core::Address::parse(&initial.buyer_note_addr()).unwrap();
        let keys = dexdo_core::KeyPair::from_secret_hex(&"22".repeat(32)).unwrap();
        let reserve = subscription_test_reserve(ticks, price);
        let deadline = super::buy_order_deadline().unwrap();
        let money_lock = super::BuyerMoneyLock {
            note_addr: note_addr.with_workchain(),
            path: dir.join("money.lock"),
            journal_path: dir.join("money.json"),
            subscriptions_path: dir.join("subscriptions.json"),
            lock: None,
        };
        let placed = super::submit_subscription_with_journal(
            &initial,
            &note_addr,
            &keys,
            &order_book,
            frame_model,
            &model_hash,
            price,
            ticks,
            reserve.total_escrow,
            deadline,
            &money_lock.journal_path,
            &money_lock.subscriptions_path,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .expect("the production journal adopts the actual mock-chain fill");
        let matched = placed.matched.as_ref().expect("one full seller fill");
        assert_eq!(matched.token_contract, token_contract);
        assert_eq!(initial.money_posts.load(Ordering::SeqCst), 1);
        assert_eq!(initial.placement_reads.load(Ordering::SeqCst), 1);
        assert_eq!(initial.fill_reads.load(Ordering::SeqCst), 1);
        assert!(
            !money_lock.journal_path.exists(),
            "the submit journal clears only after the actual match is durable"
        );

        let canonical_state = super::load_buyer_subscription_state(
            &money_lock.subscriptions_path,
            &note_addr.with_workchain(),
        )
        .unwrap();
        let restarted_chain = std::sync::Arc::new(dexdo_core::MockChainBackend::new(
            endpoints_path.clone(),
            test_consts,
            dexdo_core::DobParams::canonical(),
        ));
        let restarted = SameTcMockSubscriptionChain::new(
            restarted_chain,
            buyer_note.clone(),
            token_contract.clone(),
            order_book.clone(),
            Some(placed.order_id),
        );

        let foreign_tc = subscription_test_tc('8');
        let mut corrupted = canonical_state.clone();
        let corrupted_match = corrupted.orders[0]
            .matched
            .as_mut()
            .expect("canonical durable match");
        corrupted_match.token_contract = foreign_tc.clone();
        corrupted_match.deal_handle = crate::cli::deals::make_handle_id(
            &foreign_tc,
            crate::cli::deals::DealHandleRole::Buyer,
        );
        super::write_buyer_subscription_state(&money_lock.subscriptions_path, &corrupted).unwrap();
        let error = super::resolve_buyer_subscription_resume(
            &restarted,
            &note_addr.with_workchain(),
            frame_model,
            None,
            &money_lock,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .expect_err("restart must not splice an unrelated durable TC onto the live mock deal");
        assert!(
            error
                .to_string()
                .contains("coherent snapshot is unavailable"),
            "{error:#}"
        );
        assert_eq!(restarted.money_posts.load(Ordering::SeqCst), 0);
        super::write_buyer_subscription_state(&money_lock.subscriptions_path, &canonical_state)
            .unwrap();

        let resumed = super::resolve_buyer_subscription_resume(
            &restarted,
            &note_addr.with_workchain(),
            frame_model,
            Some(&token_contract),
            &money_lock,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .expect("restart reads the persisted mock chain and durable buyer state")
        .expect("the exact matched subscription remains active");
        assert_eq!(
            resumed.record.matched.as_ref().unwrap().token_contract,
            token_contract
        );
        assert_eq!(
            resumed.facts.subscription.funded_tokens,
            ticks * dexdo_core::TICK_SIZE
        );
        assert_eq!(restarted.money_posts.load(Ordering::SeqCst), 0);
        assert_eq!(restarted.lookback_reads.load(Ordering::SeqCst), 0);

        dexdo::seller::serve_match(&seller, &restarted, &cfg)
            .await
            .expect("the same restarted TC opens and registers gateway capacity");
        let capacity_source =
            dexdo_core::ChainBackend::deal_snapshot(restarted.chain.as_ref(), &token_contract)
                .await
                .unwrap()
                .expect("same-TC capacity source");
        let before_stream = seller
            .state
            .reconcile_subscription_capacity(
                &token_contract,
                capacity_source.state,
                capacity_source.subscription,
            )
            .unwrap()
            .expect("same-TC capacity entry");
        assert_eq!(before_stream.funded_tokens, ticks * dexdo_core::TICK_SIZE);
        assert_eq!(before_stream.local_delivered_after_anchor, 0);

        let buyer: dexdo::buyer::Buyer = dexdo::buyer::Buyer::from_note(buyer_note.clone());
        let handover = buyer
            .resolve_endpoint(&restarted, &token_contract)
            .await
            .expect("the restarted buyer decrypts this TC's handover");
        let output = buyer
            .connect_and_stream(&handover, &token_contract, 2)
            .await
            .expect("the exact matched buyer reaches the same gateway capacity slot");
        assert_eq!(output.received, 2);
        let mut after_stream = None;
        for _ in 0..100 {
            let snapshot = seller
                .state
                .reconcile_subscription_capacity(
                    &token_contract,
                    capacity_source.state,
                    capacity_source.subscription,
                )
                .unwrap();
            if snapshot.is_some_and(|snapshot| snapshot.outstanding_reservation == 0) {
                after_stream = snapshot;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let after_stream = after_stream.expect("gateway finishes the same-TC reservation");
        assert_eq!(after_stream.local_delivered_after_anchor, 2);
        assert_eq!(
            seller
                .state
                .delivery(&token_contract)
                .count
                .load(Ordering::SeqCst),
            2
        );

        dexdo_core::ChainBackend::accept_probe(&restarted, &token_contract)
            .await
            .expect("accept same-TC probe");
        let cumulative_tokens = dexdo_core::TICK_SIZE + 2;
        dexdo_core::ChainBackend::claim_tokens(
            &restarted,
            &token_contract,
            seller.note.as_ref(),
            cumulative_tokens,
        )
        .await
        .expect("claim the same gateway's two raw provider tokens");

        let state_path = endpoints_path.with_extension("chainstate.json");
        let mut persisted: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        let period_start = persisted["deal_subscriptions"][&token_contract]["period_start"]
            .as_u64()
            .expect("same-TC subscription periodStart");
        persisted["deal_subscriptions"][&token_contract]["period_start"] =
            serde_json::json!(period_start
                .checked_sub(dexdo_core::SUB_WEEK_LEN.as_secs())
                .expect("test subscription crosses exactly one weekly boundary"));
        std::fs::write(&state_path, serde_json::to_vec(&persisted).unwrap()).unwrap();

        let keeper =
            dexdo::seller::drive_subscription_keeper(&restarted, &token_contract, keeper_bounds);
        let settle_then_stop = async {
            loop {
                if restarted.settle_week_posts.load(Ordering::SeqCst) == 1 {
                    let snapshot =
                        dexdo_core::ChainBackend::deal_snapshot(&restarted, &token_contract)
                            .await
                            .unwrap()
                            .expect("same TC remains readable after keeper settlement");
                    if snapshot.subscription.week_index == 1
                        && snapshot.state.tokens_final == cumulative_tokens
                    {
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            assert_eq!(restarted.settle_week_posts.load(Ordering::SeqCst), 1);
            dexdo_core::ChainBackend::stop(&restarted, &token_contract, buyer.note.as_ref())
                .await
                .expect("the matched buyer settles the same TC")
        };
        let (keeper_result, settlement) =
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::join!(keeper, settle_then_stop)
            })
            .await
            .expect("production subscription keeper must cross one weekly boundary");
        assert_eq!(keeper_result.unwrap(), cumulative_tokens);
        assert!(
            matches!(settlement, dexdo_core::Settlement::AmicableSplit { .. }),
            "{settlement:?}"
        );
        let receipt = dexdo_core::ChainBackend::buyer_stop_settlement(&restarted, &token_contract)
            .await
            .unwrap()
            .expect("same-TC mock StreamStopped receipt");
        let terminal = dexdo_core::ChainBackend::deal_snapshot(&restarted, &token_contract)
            .await
            .unwrap()
            .expect("terminal same-TC snapshot");
        assert!(terminal.state.is_stopped());
        assert_eq!(receipt.0, terminal.state.finalized_owed);
        let stream = dexdo_core::ChainBackend::snapshot(&restarted, &token_contract)
            .await
            .expect("terminal accounting snapshot");
        assert_eq!(receipt.1, stream.buyer_refunded);
        assert_eq!(restarted.claim_posts.load(Ordering::SeqCst), 1);
        assert_eq!(restarted.finalize_posts.load(Ordering::SeqCst), 1);
        assert_eq!(restarted.settle_week_posts.load(Ordering::SeqCst), 1);
        assert_eq!(restarted.stop_posts.load(Ordering::SeqCst), 1);
        assert_eq!(restarted.receipt_reads.load(Ordering::SeqCst), 1);

        let terminal_resume = super::resolve_buyer_subscription_resume(
            &restarted,
            &note_addr.with_workchain(),
            frame_model,
            Some(&token_contract),
            &money_lock,
            std::time::Duration::ZERO,
            &persist_subscription_test_handle,
        )
        .await
        .expect_err("a later restart must reject the terminal same-TC subscription");
        assert!(
            terminal_resume.to_string().contains("terminal"),
            "{terminal_resume:#}"
        );
        assert_eq!(restarted.money_posts.load(Ordering::SeqCst), 0);
        assert_eq!(restarted.stop_posts.load(Ordering::SeqCst), 1);
        seller.server_task.abort();
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn durable_buy_clean_rejection_clears_journal() {
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-pipeline-rejected");
        let journal_path = dir.join("journal.json");
        let chain = JournalPipelineChain {
            submit_error: Some("rejected"),
            fill: None,
            expected_journal_path: journal_path.clone(),
            sequence: std::sync::Mutex::new(Vec::new()),
            post_count: std::sync::atomic::AtomicUsize::new(0),
            poll_count: std::sync::atomic::AtomicUsize::new(0),
        };
        let (note_addr, selection, result) = journal_pipeline_place(&chain, &journal_path).await;
        assert!(journal_path.exists());
        super::complete_buyer_submit_with_journal(
            &chain,
            selection.quoted_order.as_ref(),
            2,
            1_000_000,
            result,
            &note_addr,
            &journal_path,
        )
        .await
        .expect_err("changed executable quote must fail closed");
        assert!(!journal_path.exists());
        assert_eq!(
            chain.post_count.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn durable_buy_pre_post_failure_clears_but_unclassified_failure_retains() {
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-pipeline-preparation");
        let journal_path = dir.join("journal.json");
        let chain = JournalPipelineChain {
            submit_error: Some("preparation"),
            fill: None,
            expected_journal_path: journal_path.clone(),
            sequence: std::sync::Mutex::new(Vec::new()),
            post_count: std::sync::atomic::AtomicUsize::new(0),
            poll_count: std::sync::atomic::AtomicUsize::new(0),
        };
        let (note_addr, selection, result) = journal_pipeline_place(&chain, &journal_path).await;
        super::complete_buyer_submit_with_journal(
            &chain,
            selection.quoted_order.as_ref(),
            2,
            1_000_000,
            result,
            &note_addr,
            &journal_path,
        )
        .await
        .expect_err("pre-POST failure must propagate");
        assert!(!journal_path.exists());

        super::write_buyer_submit_journal(&journal_path, &buyer_submit_test_journal()).unwrap();
        let error = super::complete_buyer_submit_with_journal(
            &chain,
            selection.quoted_order.as_ref(),
            2,
            1_000_000,
            Err(anyhow::anyhow!("unclassified submit failure")),
            &note_addr,
            &journal_path,
        )
        .await
        .expect_err("unclassified outcome must fail closed");
        assert!(super::is_ambiguous_submit_error(&error), "{error:#}");
        assert!(journal_path.exists());
    }

    #[cfg(feature = "shellnet")]
    // This test must serialize process-global DEXDO_PN_POOL for the full async scenario.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn durable_buy_reconcile_matches_pending_without_second_post() {
        let _env_lock = dexdo_pn_pool_env_lock().lock().unwrap();
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-pipeline-reconcile");
        let journal_path = dir.join("journal.json");
        let pool_path = dir.join("pool.json");
        let fixture = buyer_submit_test_journal();
        std::fs::write(
            &pool_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
                "notes": [{
                    "address": fixture.note_addr,
                    "owner_secret_key_hex": "00"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let _env = EnvVarGuard::set("DEXDO_PN_POOL", pool_path.as_os_str());
        let fill = dexdo_core::MatchedFill {
            order_id: fixture.quoted_order.order_id,
            token_contract: fixture.quoted_order.token_contract.clone().unwrap(),
            ticks: fixture.ticks,
            price_per_tick: fixture.quoted_order.price_per_tick,
        };
        let chain = JournalPipelineChain {
            submit_error: Some("ambiguous"),
            fill: Some(fill.clone()),
            expected_journal_path: journal_path.clone(),
            sequence: std::sync::Mutex::new(Vec::new()),
            post_count: std::sync::atomic::AtomicUsize::new(0),
            poll_count: std::sync::atomic::AtomicUsize::new(0),
        };
        let (note_addr, _selection, result) = journal_pipeline_place(&chain, &journal_path).await;
        assert!(result.as_ref().is_err_and(super::is_ambiguous_submit_error));
        let reconciled =
            super::reconcile_pending_buyer_submit(&chain, &note_addr, &journal_path, None)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(reconciled.0, fill.token_contract);
        let stored = super::load_buyer_submit_journal(&journal_path, &note_addr)
            .unwrap()
            .unwrap();
        assert_eq!(stored.resolved_matches.len(), 1);
        assert_eq!(
            chain.post_count.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[cfg(feature = "shellnet")]
    // This test must serialize process-global DEXDO_PN_POOL for the full async scenario.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn real_entry_raise_reconciles_before_fresh_reads_and_uses_journal_budget() {
        let _env_lock = dexdo_pn_pool_env_lock().lock().unwrap();
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-entry-raise");
        let pool_path = dir.join("pool.json");
        let fixture = buyer_submit_test_journal();
        std::fs::write(
            &pool_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
                "notes": [{
                    "address": fixture.note_addr,
                    "owner_secret_key_hex": "00"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let _env = EnvVarGuard::set("DEXDO_PN_POOL", pool_path.as_os_str());
        let money_lock = super::BuyerMoneyLock::open(&fixture.note_addr).unwrap();
        let _ = std::fs::remove_file(&money_lock.journal_path);
        super::write_buyer_submit_journal(&money_lock.journal_path, &fixture).unwrap();
        let fill = dexdo_core::MatchedFill {
            order_id: fixture.quoted_order.order_id,
            token_contract: fixture.quoted_order.token_contract.clone().unwrap(),
            ticks: fixture.ticks,
            price_per_tick: fixture.quoted_order.price_per_tick,
        };
        let chain = JournalPipelineChain {
            submit_error: None,
            fill: Some(fill.clone()),
            expected_journal_path: money_lock.journal_path.clone(),
            sequence: std::sync::Mutex::new(Vec::new()),
            post_count: std::sync::atomic::AtomicUsize::new(0),
            poll_count: std::sync::atomic::AtomicUsize::new(0),
        };
        let buyer = dexdo::buyer::Buyer::generate();
        let outcome = super::raise_pending_buyer_money_before_fresh_reads(
            &chain,
            &buyer,
            Some(&fixture.note_addr),
            &fixture.intent,
            fixture.expected_token_contract.as_deref(),
            fixture.ticks,
            fixture.max_price_per_tick,
            fixture.escrow,
        )
        .await
        .unwrap()
        .expect("matching durable submit must be raised at the entry seam");
        dexdo_core::ChainBackend::discover_offers(&chain)
            .await
            .unwrap();
        assert_eq!(
            chain.sequence.lock().unwrap().as_slice(),
            &["reconcile", "fresh_read"],
            "durable money reconciliation must precede every fresh book read"
        );
        assert_eq!(outcome.token_contract, fill.token_contract);
        assert_eq!(outcome.ticks, fixture.ticks);
        assert_eq!(
            super::consumer_api_token_budget(outcome.ticks),
            super::consumer_api_token_budget(fixture.ticks),
            "served budget must use journal ticks"
        );
        assert_ne!(
            super::consumer_api_token_budget(outcome.ticks),
            super::consumer_api_token_budget(fixture.ticks + 6),
            "a restarted --ticks value must not expand service"
        );
        assert_eq!(
            chain.post_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "raising an existing submit must never POST again"
        );

        let polls_before = chain.poll_count.load(std::sync::atomic::Ordering::SeqCst);
        let error = super::raise_pending_buyer_money_before_fresh_reads(
            &chain,
            &buyer,
            Some(&fixture.note_addr),
            &fixture.intent,
            fixture.expected_token_contract.as_deref(),
            fixture.ticks + 6,
            fixture.max_price_per_tick,
            fixture.escrow,
        )
        .await
        .expect_err("changed restart terms must fail closed");
        assert!(error.to_string().contains("different logical invocation"));
        assert_eq!(
            chain.poll_count.load(std::sync::atomic::Ordering::SeqCst),
            polls_before,
            "changed terms must fail before another chain read"
        );
        assert_eq!(
            chain.post_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "changed terms must never POST"
        );
        for (label, expected_tc, ticks, max_price, escrow) in [
            (
                "max_price_per_tick",
                fixture.expected_token_contract.as_deref(),
                fixture.ticks,
                fixture.max_price_per_tick + 1,
                fixture.escrow,
            ),
            (
                "escrow",
                fixture.expected_token_contract.as_deref(),
                fixture.ticks,
                fixture.max_price_per_tick,
                fixture.escrow + 1,
            ),
            (
                "expected_token_contract",
                Some("0:9999999999999999999999999999999999999999999999999999999999999999"),
                fixture.ticks,
                fixture.max_price_per_tick,
                fixture.escrow,
            ),
        ] {
            let error = super::raise_pending_buyer_money_before_fresh_reads(
                &chain,
                &buyer,
                Some(&fixture.note_addr),
                &fixture.intent,
                expected_tc,
                ticks,
                max_price,
                escrow,
            )
            .await
            .unwrap_err();
            assert!(
                error.to_string().contains("different logical invocation"),
                "{label}: {error:#}"
            );
        }
        let mut changed_row = journal_pipeline_selection();
        changed_row.quoted_order.as_mut().unwrap().order_id += 1;
        let error = super::start_durable_buyer_submit(
            &chain,
            &buyer,
            &fixture.intent,
            fixture.expected_token_contract.as_deref(),
            &changed_row,
            fixture.ticks,
            fixture.max_price_per_tick,
            fixture.escrow,
            &fixture.note_addr,
            &money_lock.journal_path,
            None,
        )
        .await
        .err()
        .expect("changed quoted row must fail closed");
        assert!(error.to_string().contains("different logical invocation"));
        let mut changed_quote = journal_pipeline_selection();
        changed_quote.quote.total_with_fee += 1;
        let error = super::start_durable_buyer_submit(
            &chain,
            &buyer,
            &fixture.intent,
            fixture.expected_token_contract.as_deref(),
            &changed_quote,
            fixture.ticks,
            fixture.max_price_per_tick,
            fixture.escrow,
            &fixture.note_addr,
            &money_lock.journal_path,
            None,
        )
        .await
        .err()
        .expect("changed executable quote must fail closed");
        assert!(error.to_string().contains("different logical invocation"));
        assert_eq!(
            chain.poll_count.load(std::sync::atomic::Ordering::SeqCst),
            polls_before,
            "every durable-term mismatch must fail before reconciliation reads"
        );
        super::clear_adopted_buyer_money_journal(
            Some(&fixture.note_addr),
            outcome
                .submit_reconciliation
                .as_ref()
                .map(|reconciliation| reconciliation.submit_identity.as_str()),
            &outcome.token_contract,
        )
        .unwrap();
    }

    #[cfg(feature = "shellnet")]
    // This test must serialize process-global DEXDO_PN_POOL for the full async scenario.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn foreground_and_on_demand_entry_modes_raise_before_fresh_book_reads() {
        let _env_lock = dexdo_pn_pool_env_lock().lock().unwrap();
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-entry-modes");
        let pool_path = dir.join("pool.json");
        let base = buyer_submit_test_journal();
        std::fs::write(
            &pool_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
                "notes": [{
                    "address": base.note_addr,
                    "owner_secret_key_hex": "00"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let _env = EnvVarGuard::set("DEXDO_PN_POOL", pool_path.as_os_str());
        let money_lock = super::BuyerMoneyLock::open(&base.note_addr).unwrap();
        let buyer = dexdo::buyer::Buyer::generate();

        for (label, intent, explicit) in [
            (
                "foreground-model-only",
                super::BuyerSubmitIntent::foreground(),
                false,
            ),
            (
                "foreground-explicit-token-contract",
                super::BuyerSubmitIntent::foreground(),
                true,
            ),
            (
                "on-demand-model-only",
                super::BuyerSubmitIntent::on_demand(),
                false,
            ),
            (
                "on-demand-explicit-token-contract",
                super::BuyerSubmitIntent::on_demand(),
                true,
            ),
        ] {
            let mut fixture = base.clone();
            fixture.intent = intent.clone();
            if !explicit {
                fixture.expected_token_contract = None;
            }
            let _ = std::fs::remove_file(&money_lock.journal_path);
            super::write_buyer_submit_journal(&money_lock.journal_path, &fixture).unwrap();
            let fill = dexdo_core::MatchedFill {
                order_id: fixture.quoted_order.order_id,
                token_contract: fixture.quoted_order.token_contract.clone().unwrap(),
                ticks: fixture.ticks,
                price_per_tick: fixture.quoted_order.price_per_tick,
            };
            let chain = JournalPipelineChain {
                submit_error: None,
                fill: Some(fill),
                expected_journal_path: money_lock.journal_path.clone(),
                sequence: std::sync::Mutex::new(Vec::new()),
                post_count: std::sync::atomic::AtomicUsize::new(0),
                poll_count: std::sync::atomic::AtomicUsize::new(0),
            };
            let outcome = super::raise_pending_buyer_money_before_fresh_reads(
                &chain,
                &buyer,
                Some(&fixture.note_addr),
                &intent,
                fixture.expected_token_contract.as_deref(),
                fixture.ticks,
                fixture.max_price_per_tick,
                fixture.escrow,
            )
            .await
            .unwrap()
            .unwrap();
            dexdo_core::ChainBackend::discover_offers(&chain)
                .await
                .unwrap();
            assert_eq!(
                chain.sequence.lock().unwrap().as_slice(),
                &["reconcile", "fresh_read"],
                "{label} must raise durable money before a fresh book read"
            );
            assert_eq!(
                chain.post_count.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "{label} must adopt without a second POST"
            );
            assert_eq!(outcome.ticks, fixture.ticks, "{label} journal budget");
            super::clear_adopted_buyer_money_journal(
                Some(&fixture.note_addr),
                outcome
                    .submit_reconciliation
                    .as_ref()
                    .map(|reconciliation| reconciliation.submit_identity.as_str()),
                &outcome.token_contract,
            )
            .unwrap();
        }
    }

    #[cfg(feature = "shellnet")]
    // This test must serialize process-global DEXDO_PN_POOL for the full async scenario.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn on_demand_attempt_two_reconciles_before_failing_fresh_preflight() {
        // run_buyer_inner constructs its real backend at the command boundary. Its coverage is
        // intentionally deferred to the live shellnet proof; do not replace it with a fake
        // command-boundary test.
        let _env_lock = dexdo_pn_pool_env_lock().lock().unwrap();
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-on-demand-attempt-two");
        let pool_path = dir.join("pool.json");
        let mut fixture = buyer_submit_test_journal();
        fixture.intent = super::BuyerSubmitIntent::on_demand();
        std::fs::write(
            &pool_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
                "notes": [{
                    "address": fixture.note_addr,
                    "owner_secret_key_hex": "00"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let _env = EnvVarGuard::set("DEXDO_PN_POOL", pool_path.as_os_str());
        let money_lock = super::BuyerMoneyLock::open(&fixture.note_addr).unwrap();
        let _ = std::fs::remove_file(&money_lock.journal_path);
        super::write_buyer_submit_journal(&money_lock.journal_path, &fixture).unwrap();
        let fill = dexdo_core::MatchedFill {
            order_id: fixture.quoted_order.order_id,
            token_contract: fixture.quoted_order.token_contract.clone().unwrap(),
            ticks: fixture.ticks,
            price_per_tick: fixture.quoted_order.price_per_tick,
        };
        let chain = std::sync::Arc::new(JournalPipelineChain {
            submit_error: Some("replay_once"),
            fill: Some(fill),
            expected_journal_path: money_lock.journal_path.clone(),
            sequence: std::sync::Mutex::new(Vec::new()),
            post_count: std::sync::atomic::AtomicUsize::new(0),
            poll_count: std::sync::atomic::AtomicUsize::new(0),
        });
        let missing_contracts = dir.join("missing-contracts.json");
        let args = std::sync::Arc::new(super::BuyerArgs {
            mock: super::MockFlags {
                mock_model: false,
                mock_chain: false,
            },
            identity: super::IdentityArgs {
                note_key: None,
                note_index: 0,
                note_addr: Some(fixture.note_addr.clone()),
            },
            registry: super::ModelRegistryValidationArgs::default(),
            endpoints_file: None,
            deals_dir: None,
            token_contract: fixture.expected_token_contract.clone(),
            resume: false,
            market: None,
            max_tokens: 8,
            local_listen: None,
            continuity_mode: super::ContinuityModeArg::OnDemand,
            json: false,
            anthropic_compat: false,
            frame_model: Some("qwen--qwen3--32b".to_string()),
            allow_unverified_model: true,
            models: dir.join("models.json"),
            ticks: fixture.ticks,
            max_price_per_tick: fixture.max_price_per_tick,
            escrow: Some(fixture.escrow),
            contracts: missing_contracts.clone(),
            policy: None,
        });
        let error = super::prepare_lazy_buyer_api_deal_with_replay_backoff(
            chain.clone(),
            std::sync::Arc::new(dexdo::buyer::Buyer::generate()),
            args,
            fixture.expected_token_contract.clone(),
            "qwen--qwen3--32b".to_string(),
            dexdo::buyer::api::ContentCheck::Skip,
            std::sync::Arc::new(dexdo::seller::ModelsConfig::empty()),
            None,
            dexdo::buyer::api::BuyerApiFailurePolicy::default(),
            None,
            None,
            super::BuyerShellnetPreflight::Production,
        )
        .await
        .err()
        .expect("the real retry wrapper must reach the deliberately failing fresh preflight");
        assert!(
            error
                .message()
                .contains(&missing_contracts.display().to_string())
                || error.message().contains("No such file"),
            "{error}"
        );
        assert_eq!(
            chain.sequence.lock().unwrap().as_slice(),
            &["replay_protection", "reconcile"],
            "attempt one must trigger retry and attempt two must reconcile before the fresh doctor read fails"
        );
        assert_eq!(
            chain.poll_count.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the real retry wrapper must call the protected journal path on both attempts"
        );
        let reconciled =
            super::load_buyer_submit_journal(&money_lock.journal_path, &fixture.note_addr)
                .unwrap()
                .expect("the attempt-two journal must remain available after the fresh read fails");
        assert_eq!(
            reconciled.resolved_matches.len(),
            1,
            "attempt two must persist reconciliation before the fresh doctor read fires"
        );
        assert_eq!(
            chain.post_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "attempt two must not POST while adopting the retained journal"
        );
    }

    #[cfg(feature = "shellnet")]
    // This test must serialize process-global DEXDO_PN_POOL for the full async scenario.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn legacy_v1_reconciles_and_persists_facts_but_is_not_adopted() {
        let _env_lock = dexdo_pn_pool_env_lock().lock().unwrap();
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-v1-fact-reconcile");
        let journal_path = dir.join("journal.json");
        let pool_path = dir.join("pool.json");
        let fixture = buyer_submit_test_journal();
        std::fs::write(
            &pool_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
                "notes": [{
                    "address": fixture.note_addr,
                    "owner_secret_key_hex": "00"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let _env = EnvVarGuard::set("DEXDO_PN_POOL", pool_path.as_os_str());
        let fill = dexdo_core::MatchedFill {
            order_id: fixture.quoted_order.order_id,
            token_contract: fixture.quoted_order.token_contract.clone().unwrap(),
            ticks: fixture.ticks,
            price_per_tick: fixture.quoted_order.price_per_tick,
        };
        let legacy = super::BuyerSubmitJournalV1 {
            schema: super::BUYER_SUBMIT_JOURNAL_SCHEMA_V1.to_string(),
            note_addr: fixture.note_addr.clone(),
            order_book: fixture.order_book.clone(),
            expected_token_contract: fixture.expected_token_contract.clone(),
            quoted_order: fixture.quoted_order.clone(),
            quote: fixture.quote.clone(),
            cursor: fixture.cursor.clone(),
            ticks: fixture.ticks,
            max_price_per_tick: fixture.max_price_per_tick,
            escrow: fixture.escrow,
            submit_identity: fixture.submit_identity.clone(),
            created_at_unix: fixture.created_at_unix,
            resolved_match: Some(super::journal_match(&fill)),
        };
        let bytes = serde_json::to_vec_pretty(&legacy).unwrap();
        super::with_pool_write_lock(&journal_path, |path| {
            super::write_pool_private(path, &bytes)
        })
        .unwrap();
        let chain = JournalPipelineChain {
            submit_error: None,
            fill: None,
            expected_journal_path: journal_path.clone(),
            sequence: std::sync::Mutex::new(Vec::new()),
            post_count: std::sync::atomic::AtomicUsize::new(0),
            poll_count: std::sync::atomic::AtomicUsize::new(0),
        };
        let selection = journal_pipeline_selection();
        let error = super::start_durable_buyer_submit(
            &chain,
            &dexdo::buyer::Buyer::generate(),
            &super::BuyerSubmitIntent::foreground(),
            fixture.expected_token_contract.as_deref(),
            &selection,
            fixture.ticks,
            fixture.max_price_per_tick,
            fixture.escrow,
            &fixture.note_addr,
            &journal_path,
            None,
        )
        .await
        .err()
        .expect("legacy journal must not be adopted");
        assert!(error
            .to_string()
            .contains("cannot be adopted as a fresh intent"));
        assert_eq!(
            chain.poll_count.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            chain.post_count.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        let stored = super::load_buyer_submit_journal(&journal_path, &fixture.note_addr)
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.intent.kind,
            super::BuyerSubmitIntentKind::LegacyUnknown
        );
        assert_eq!(stored.resolved_matches.len(), 1);
        assert_eq!(
            stored.resolved_matches[0].token_contract,
            fill.token_contract
        );
        let pool = std::fs::read_to_string(&pool_path).unwrap();
        assert!(pool.contains(&fill.token_contract));
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn durable_recovery_rejects_cross_kind_before_chain_read_or_post() {
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-cross-kind");
        let journal_path = dir.join("journal.json");
        let fixture = buyer_submit_test_journal();
        super::write_buyer_submit_journal(&journal_path, &fixture).unwrap();
        let chain = JournalPipelineChain {
            submit_error: None,
            fill: None,
            expected_journal_path: journal_path.clone(),
            sequence: std::sync::Mutex::new(Vec::new()),
            post_count: std::sync::atomic::AtomicUsize::new(0),
            poll_count: std::sync::atomic::AtomicUsize::new(0),
        };
        let selection = journal_pipeline_selection();
        let error = super::start_durable_buyer_submit(
            &chain,
            &dexdo::buyer::Buyer::generate(),
            &super::BuyerSubmitIntent::on_demand(),
            fixture.expected_token_contract.as_deref(),
            &selection,
            fixture.ticks,
            fixture.max_price_per_tick,
            fixture.escrow,
            &fixture.note_addr,
            &journal_path,
            None,
        )
        .await
        .err()
        .expect("cross-kind recovery must fail closed");
        assert!(error.to_string().contains("different logical invocation"));
        assert_eq!(
            chain.poll_count.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            chain.post_count.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn durable_recovery_rejects_wrong_continuity_generation_before_chain_read_or_post() {
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-wrong-generation");
        let journal_path = dir.join("journal.json");
        let mut fixture = buyer_submit_test_journal();
        let predecessor = format!("0:{}", "5".repeat(64));
        fixture.intent = super::BuyerSubmitIntent::after(
            super::BuyerSubmitIntentKind::ContinuityRenewal,
            &predecessor,
        );
        super::write_buyer_submit_journal(&journal_path, &fixture).unwrap();
        let chain = JournalPipelineChain {
            submit_error: None,
            fill: None,
            expected_journal_path: journal_path.clone(),
            sequence: std::sync::Mutex::new(Vec::new()),
            post_count: std::sync::atomic::AtomicUsize::new(0),
            poll_count: std::sync::atomic::AtomicUsize::new(0),
        };
        let selection = journal_pipeline_selection();
        let wrong_predecessor = format!("0:{}", "6".repeat(64));
        let intent = super::BuyerSubmitIntent::after(
            super::BuyerSubmitIntentKind::ContinuityRenewal,
            &wrong_predecessor,
        );
        let error = super::start_durable_buyer_submit(
            &chain,
            &dexdo::buyer::Buyer::generate(),
            &intent,
            fixture.expected_token_contract.as_deref(),
            &selection,
            fixture.ticks,
            fixture.max_price_per_tick,
            fixture.escrow,
            &fixture.note_addr,
            &journal_path,
            None,
        )
        .await
        .err()
        .expect("wrong continuity generation must fail closed");
        assert!(error.to_string().contains("different logical invocation"));
        assert_eq!(
            chain.poll_count.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            chain.post_count.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn buyer_money_journal_schema_first_load_dispatches_v1_and_v2() {
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-journal-schema");
        let v2_path = dir.join("v2.json");
        let v1_path = dir.join("v1.json");
        let journal = buyer_submit_test_journal();

        super::write_buyer_submit_journal(&v2_path, &journal).unwrap();
        let loaded = super::load_buyer_money_journal(&v2_path, &journal.note_addr)
            .unwrap()
            .unwrap();
        let super::BuyerMoneyJournal::Buy(loaded) = loaded else {
            panic!("v2 schema must dispatch to a buy journal");
        };
        assert_eq!(*loaded, journal);

        let legacy = super::BuyerSubmitJournalV1 {
            schema: super::BUYER_SUBMIT_JOURNAL_SCHEMA_V1.to_string(),
            note_addr: journal.note_addr.clone(),
            order_book: journal.order_book.clone(),
            expected_token_contract: journal.expected_token_contract.clone(),
            quoted_order: journal.quoted_order.clone(),
            quote: journal.quote.clone(),
            cursor: journal.cursor.clone(),
            ticks: journal.ticks,
            max_price_per_tick: journal.max_price_per_tick,
            escrow: journal.escrow,
            submit_identity: journal.submit_identity.clone(),
            created_at_unix: journal.created_at_unix,
            resolved_match: None,
        };
        let bytes = serde_json::to_vec_pretty(&legacy).unwrap();
        super::with_pool_write_lock(&v1_path, |path| super::write_pool_private(path, &bytes))
            .unwrap();
        let loaded = super::load_buyer_money_journal(&v1_path, &journal.note_addr)
            .unwrap()
            .unwrap();
        let super::BuyerMoneyJournal::Buy(loaded) = loaded else {
            panic!("v1 schema must dispatch to a buy journal");
        };
        assert_eq!(loaded.schema, super::BUYER_SUBMIT_JOURNAL_SCHEMA);
        assert_eq!(
            loaded.intent.kind,
            super::BuyerSubmitIntentKind::LegacyUnknown
        );
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn buyer_submit_journal_v1_conversion_marks_legacy_unknown() {
        let journal = buyer_submit_test_journal();
        let legacy = super::BuyerSubmitJournalV1 {
            schema: super::BUYER_SUBMIT_JOURNAL_SCHEMA_V1.to_string(),
            note_addr: journal.note_addr,
            order_book: journal.order_book,
            expected_token_contract: journal.expected_token_contract,
            quoted_order: journal.quoted_order,
            quote: journal.quote,
            cursor: journal.cursor,
            ticks: journal.ticks,
            max_price_per_tick: journal.max_price_per_tick,
            escrow: journal.escrow,
            submit_identity: journal.submit_identity,
            created_at_unix: journal.created_at_unix,
            resolved_match: None,
        };
        let converted = super::BuyerSubmitJournal::from(legacy);
        assert_eq!(
            converted.intent.kind,
            super::BuyerSubmitIntentKind::LegacyUnknown
        );
        assert!(converted.intent.predecessor_token_contract.is_none());
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn buyer_submit_journal_round_trip_write_load() {
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-journal-roundtrip");
        let path = dir.join("journal.json");
        let journal = buyer_submit_test_journal();
        super::write_buyer_submit_journal(&path, &journal).unwrap();
        let loaded = super::load_buyer_submit_journal(&path, &journal.note_addr)
            .unwrap()
            .unwrap();
        assert_eq!(loaded, journal);
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn buyer_submit_journal_v2_previous_and_current_readers_are_bidirectionally_compatible() {
        let journal = buyer_submit_test_journal();

        let previous_writer = PreviousBuyerSubmitJournalV2::from(&journal);
        let previous_bytes = serde_json::to_vec_pretty(&previous_writer).unwrap();
        let loaded_current: super::BuyerSubmitJournal = serde_json::from_slice(&previous_bytes)
            .expect("previous v2 journal loads on this head");
        assert_eq!(loaded_current, journal);

        let current_bytes = serde_json::to_vec_pretty(&journal).unwrap();
        let loaded_previous: PreviousBuyerSubmitJournalV2 = serde_json::from_slice(&current_bytes)
            .expect(
                "journal written by this head remains readable by the previous strict v2 reader",
            );
        assert_eq!(loaded_previous.schema, super::BUYER_SUBMIT_JOURNAL_SCHEMA);
        assert_eq!(loaded_previous.submit_identity, journal.submit_identity);

        let current_shape = serde_json::to_value(&journal).unwrap();
        let previous_shape = serde_json::to_value(previous_writer).unwrap();
        assert_eq!(
            current_shape
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            previous_shape
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            "schema v2 field names must remain byte-shape compatible"
        );
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn buyer_money_lock_acquire_and_try_acquire_serialize() {
        use sha2::Digest;

        let note_addr = format!(
            "0:{}",
            hex::encode(sha2::Sha256::digest(
                format!(
                    "{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                )
                .as_bytes()
            ))
        );
        let mut first = super::BuyerMoneyLock::open(&note_addr).unwrap();
        let mut second = super::BuyerMoneyLock::open(&note_addr).unwrap();
        first.acquire().unwrap();
        let error = second.try_acquire().unwrap_err().to_string();
        assert!(error.contains("another money submission"), "{error}");
        assert!(error.contains("no BOC was sent"), "{error}");
        drop(first);
        second.try_acquire().unwrap();
    }

    #[cfg(all(feature = "shellnet", unix))]
    #[test]
    fn non_regular_buyer_journal_path_is_rejected() {
        let (dir, _cleanup) = buyer_journal_test_dir("buyer-journal-nonregular");
        let journal_dir = dir.join("journal.json");
        std::fs::create_dir(&journal_dir).unwrap();
        let note_addr = format!("0:{}", "1".repeat(64));
        let error = super::load_buyer_money_journal(&journal_dir, &note_addr)
            .unwrap_err()
            .to_string();
        assert!(error.contains("regular file"), "{error}");
    }

    #[cfg(feature = "shellnet")]
    fn dexdo_pn_pool_env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    #[cfg(feature = "shellnet")]
    struct EnvVarGuard {
        key: &'static str,
        old: Option<std::ffi::OsString>,
    }

    #[cfg(feature = "shellnet")]
    impl EnvVarGuard {
        fn set(key: &'static str, value: &std::ffi::OsStr) -> Self {
            let old = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, old }
        }

        fn unset(key: &'static str) -> Self {
            let old = std::env::var_os(key);
            std::env::remove_var(key);
            Self { key, old }
        }
    }

    #[cfg(feature = "shellnet")]
    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.old.take() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}
