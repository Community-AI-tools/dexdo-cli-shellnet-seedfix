use super::backends::{is_canonical_zero_address, note_owner_mismatch_reason};
use super::book_events::{read_book_event_fold, BookEventFold};
use super::contracts_provision::*;
use crate::chain::{
    check_seller_pubkey, check_subscription_buy_reserve, flags, DealBuyerBond, DealChainSnapshot,
    DealChainState, DealSellerBond, DealSubscription, InferenceSubscriptionPlacement,
    MatchWatchCursor, MatchedFill, SettlementAction, SettlementActionBondState,
    SettlementActionEvent, SettlementActionPostState, SettlementActionReceipt,
};
use crate::manifest::{model_hash_for, MarketManifest};
use crate::onchain_diagnostics::{validate_onchain_submit_response, OnchainSubmitError};
use crate::oracle_manifest::OracleMarketManifest;
use crate::params::TICK_SIZE;
use crate::params::{
    SellerLivenessParams, DEAL_SNAPSHOT_MAX_ATTEMPTS, PRICE_STEP, SUBSCRIPTION_MAX_TICKS,
    SUBSCRIPTION_WEEKS,
};
use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use gosh_ackinacki::airegistry::calls::encode_external_call;
use gosh_ackinacki::airegistry::deploy::{build_deploy, local_context};
use gosh_ackinacki::config::AiRegistryConfig;
use gosh_ackinacki::sdk::{Account, Address, ChainClient, ChainLiveness, KeyPair};
use gosh_ackinacki::wallet::query::{dest_account_id_hex, fetch_dapp_id};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use tvm_block::Deserializable;

const FIXED_SUPERROOT_ACCOUNT_ID: &str =
    "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
const MIN_PMP_INITIAL_STAKE: u128 = 10_000_000;
/// Pinned `tvm_client` default signed-message lifetime(`message_expiration_timeout`).
const SDK_MESSAGE_EXPIRY_SECS: u64 = 40;
/// Strict contract window: `block.timestamp < expireAt < block.timestamp + 300`.
const CONTRACT_MESSAGE_WINDOW_SECS: u64 = 300;
const MAX_CLOCK_BEHIND_SECS: u64 =
    SDK_MESSAGE_EXPIRY_SECS - crate::params::SHELLNET_CLOCK_SKEW_SAFETY_MARGIN_SECS;
const MAX_CLOCK_AHEAD_SECS: u64 = CONTRACT_MESSAGE_WINDOW_SECS
    - SDK_MESSAGE_EXPIRY_SECS
    - crate::params::SHELLNET_CLOCK_SKEW_SAFETY_MARGIN_SECS;

fn money_submit_identity(signed_boc: &str) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(signed_boc.as_bytes());
    format!(
        "boc-sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

/// Stage-aware failure from a non-idempotent money write.
#[derive(Debug, thiserror::Error)]
pub enum MoneySubmitError {
    #[error("money write failed before any message POST: {source}")]
    Preparation {
        #[source]
        source: anyhow::Error,
    },
    #[error("money message POST outcome is ambiguous: {source}")]
    Ambiguous {
        #[source]
        source: anyhow::Error,
    },
    #[error("money message POST was rejected: {source}")]
    Rejected {
        #[source]
        source: anyhow::Error,
    },
}

/// The message POST received an HTTP success response, but its response body could not be decoded.
/// This is deliberately stage-specific: the signed message has already left the process, so callers that
/// submit a cumulative claim must reconcile the authoritative claim cursor before deciding whether to retry.
#[derive(Debug, thiserror::Error)]
#[error(
    "message POST received HTTP {status}, but its response JSON could not be decoded: {source}"
)]
pub(super) struct MessagePostResponseDecodeError {
    status: reqwest::StatusCode,
    #[source]
    source: reqwest::Error,
}

impl MoneySubmitError {
    pub fn is_ambiguous(&self) -> bool {
        matches!(self, Self::Ambiguous { .. })
    }

    /// Clearing an exactly-once journal is safe only when no POST was attempted or when the
    /// protocol returned a decoded rejection. Every other outcome may have landed.
    pub fn clears_journal(&self) -> bool {
        matches!(self, Self::Preparation { .. } | Self::Rejected { .. })
    }
}

#[allow(dead_code)]
fn consume_new_fill_batch(
    cursor: &mut MatchWatchCursor,
    mut fills: Vec<(i64, MatchedFill)>,
) -> Vec<MatchedFill> {
    fills.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.token_contract.cmp(&b.1.token_contract))
            .then_with(|| a.1.ticks.cmp(&b.1.ticks))
            .then_with(|| a.1.price_per_tick.cmp(&b.1.price_per_tick))
    });
    let mut out = Vec::new();
    let mut consumed = Vec::new();
    let mut unique_new = BTreeSet::new();
    for (created_at, fill) in fills {
        if cursor.has_seen(created_at, &fill.token_contract) {
            continue;
        }
        if unique_new.insert((
            created_at,
            fill.token_contract.clone(),
            fill.ticks,
            fill.price_per_tick,
        )) {
            consumed.push((created_at, fill.token_contract.clone()));
            out.push(fill);
        }
    }
    cursor.record_seen_batch(consumed);
    out
}

fn correlate_fill_batch(
    expected: Option<&MatchedFill>,
    fills: &[MatchedFill],
) -> Result<Option<MatchedFill>> {
    let Some(expected) = expected else {
        return Ok(fills.last().cloned());
    };
    if let Some(fill) = fills.iter().find(|fill| {
        fill.token_contract == expected.token_contract
            && fill.ticks == expected.ticks
            && fill.price_per_tick == expected.price_per_tick
    }) {
        return Ok(Some(fill.clone()));
    }
    let Some(fill) = fills.first() else {
        return Ok(None);
    };
    Err(anyhow!(
        "buyer fill correlation failed: expected tokenContract {} ticks {} price_per_tick {}, \
         got tokenContract {} ticks {} price_per_tick {}; refusing wrong-fill attribution",
        expected.token_contract,
        expected.ticks,
        expected.price_per_tick,
        fill.token_contract,
        fill.ticks,
        fill.price_per_tick
    ))
}

#[async_trait::async_trait]
pub(super) trait InferenceFillPoller: Send + Sync {
    async fn poll(&self, cursor: &mut MatchWatchCursor) -> Result<Vec<MatchedFill>>;
}

struct RealInferenceFillPoller<'a> {
    chain: &'a RealChainBackend,
    note: &'a Address,
    order_book: &'a Address,
}

#[async_trait::async_trait]
impl InferenceFillPoller for RealInferenceFillPoller<'_> {
    async fn poll(&self, cursor: &mut MatchWatchCursor) -> Result<Vec<MatchedFill>> {
        self.chain
            .poll_inference_filled_tcs(self.note, self.order_book, true, cursor)
            .await
    }
}

pub(super) async fn wait_correlated_inference_fill(
    poller: &dyn InferenceFillPoller,
    cursor: &mut MatchWatchCursor,
    expected: Option<&MatchedFill>,
    timeout: std::time::Duration,
    poll_interval: std::time::Duration,
    timeout_context: &str,
) -> Result<MatchedFill> {
    let start = std::time::Instant::now();
    loop {
        let fills = poller.poll(cursor).await?;
        if let Some(fill) = correlate_fill_batch(expected, &fills)? {
            return Ok(fill);
        }
        if start.elapsed() >= timeout {
            return Err(anyhow!(timeout_context.to_string()));
        }
        tokio::time::sleep(poll_interval).await;
    }
}

#[cfg(feature = "test-giver")]
#[path = "test_giver.rs"]
mod test_giver;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellnetDoctorStatus {
    Pass,
    Fail,
    Skip,
}

impl ShellnetDoctorStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellnetDoctorCheck {
    pub name: String,
    pub status: ShellnetDoctorStatus,
    pub address: Option<String>,
    pub expected: Option<String>,
    pub actual: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellnetDoctorReport {
    pub network: String,
    pub versions: Vec<(String, String)>,
    pub checks: Vec<ShellnetDoctorCheck>,
}

impl ShellnetDoctorReport {
    pub fn is_ok(&self) -> bool {
        self.checks
            .iter()
            .all(|c| c.status != ShellnetDoctorStatus::Fail)
    }

    pub fn fail_summary(&self) -> String {
        self.checks
            .iter()
            .filter(|c| c.status == ShellnetDoctorStatus::Fail)
            .map(|c| format!("{}: {}", c.name, c.message))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

fn getter_u128(v: &Value, key: &str) -> Option<u128> {
    let raw = &v[key];
    if let Some(n) = raw.as_u64() {
        return Some(u128::from(n));
    }
    let s = raw.as_str()?.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u128>().ok()
    }
}

fn subscription_order_is_active_for_owner(
    order_id: u128,
    order: &Value,
    owner_note: &str,
) -> Result<bool> {
    let amount = getter_u128(order, "amount")
        .ok_or_else(|| anyhow!("getOrder({order_id}) has no amount: {order}"))?;
    let canonical_empty = amount == 0
        && order
            .get("note")
            .and_then(Value::as_str)
            .is_some_and(is_canonical_zero_address)
        && order
            .get("tokenContract")
            .and_then(Value::as_str)
            .is_some_and(is_canonical_zero_address)
        && ["price", "escrow", "deadline", "flags", "ts"]
            .iter()
            .all(|field| getter_u128(order, field) == Some(0))
        && getter_bool(order, "isBuy") == Some(false);
    if canonical_empty {
        return Ok(false);
    }
    if amount == 0 {
        return Err(anyhow!(
            "getOrder({order_id}) has non-canonical zero-amount row: {order}"
        ));
    }
    let Some(note) = order.get("note").and_then(Value::as_str) else {
        return Err(anyhow!("getOrder({order_id}) has no owner note: {order}"));
    };
    let note = Address::parse(note)
        .map_err(|error| anyhow!("getOrder({order_id}) owner note {note}: {error}"))?
        .with_workchain();
    let owner_note = Address::parse(owner_note)
        .map_err(|error| anyhow!("expected owner note {owner_note}: {error}"))?
        .with_workchain();
    let is_buy = getter_bool(order, "isBuy")
        .ok_or_else(|| anyhow!("getOrder({order_id}) has no isBuy: {order}"))?;
    if !note.eq_ignore_ascii_case(&owner_note) {
        return Err(anyhow!(
            "getOrder({order_id}) owner {note} contradicts expected subscription owner \
             {owner_note}: {order}"
        ));
    }
    if !is_buy {
        return Err(anyhow!(
            "getOrder({order_id}) is a SELL, not the expected subscription BUY: {order}"
        ));
    }
    let token_contract = order
        .get("tokenContract")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("getOrder({order_id}) has no tokenContract: {order}"))?;
    if !is_canonical_zero_address(token_contract) {
        return Err(anyhow!(
            "getOrder({order_id}) subscription BUY has non-zero tokenContract \
             {token_contract}: {order}"
        ));
    }
    let price = getter_u128(order, "price")
        .ok_or_else(|| anyhow!("getOrder({order_id}) has no price: {order}"))?;
    if price == 0 || !price.is_multiple_of(PRICE_STEP) {
        return Err(anyhow!(
            "getOrder({order_id}) subscription price {price} is not a positive PRICE_STEP \
             multiple: {order}"
        ));
    }
    let minimum_ticks = u128::from(SUBSCRIPTION_WEEKS);
    if !(minimum_ticks..=SUBSCRIPTION_MAX_TICKS).contains(&amount)
        || !amount.is_multiple_of(minimum_ticks)
    {
        return Err(anyhow!(
            "getOrder({order_id}) subscription amount {amount} is outside the canonical \
             four-week shape: {order}"
        ));
    }
    let escrow = getter_u128(order, "escrow")
        .ok_or_else(|| anyhow!("getOrder({order_id}) has no escrow: {order}"))?;
    check_subscription_buy_reserve(escrow, amount, price)
        .map_err(|error| anyhow!("getOrder({order_id}) subscription reserve: {error}; {order}"))?;
    let order_flags = getter_u128(order, "flags")
        .ok_or_else(|| anyhow!("getOrder({order_id}) has no flags: {order}"))?;
    let expected_flags = u128::from(flags::AON | flags::SUBSCRIPTION);
    if order_flags != expected_flags {
        return Err(anyhow!(
            "getOrder({order_id}) flags 0x{order_flags:02x} contradict exact \
             AON|SUBSCRIPTION flags 0x{expected_flags:02x}: {order}"
        ));
    }
    let deadline = getter_u128(order, "deadline")
        .ok_or_else(|| anyhow!("getOrder({order_id}) has no deadline: {order}"))?;
    let timestamp = getter_u128(order, "ts")
        .ok_or_else(|| anyhow!("getOrder({order_id}) has no ts: {order}"))?;
    if deadline == 0 || deadline <= timestamp || deadline > u128::from(u64::MAX) {
        return Err(anyhow!(
            "getOrder({order_id}) subscription deadline {deadline} is invalid for timestamp \
             {timestamp}: {order}"
        ));
    }
    Ok(true)
}

fn coalesce_correlated_subscription_placements(
    mut placements: Vec<InferenceSubscriptionPlacement>,
    expected_owner: &str,
    expected_price_per_tick: u128,
    expected_ticks: u128,
) -> Result<Vec<InferenceSubscriptionPlacement>> {
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
        let has_expected = group.iter().any(|placement| {
            placement.buyer_note.eq_ignore_ascii_case(expected_owner)
                && placement.max_price_per_tick == expected_price_per_tick
                && placement.ticks == expected_ticks
        });
        if has_expected {
            let first = &group[0];
            if group.iter().any(|placement| placement != first) {
                return Err(anyhow!(
                    "InferenceSubscriptionPlaced order #{order_id} has conflicting authenticated \
                     placement facts: {group:?}"
                ));
            }
            correlated.push(first.clone());
        }
        start = end;
    }
    Ok(correlated)
}

fn getter_bool(v: &Value, key: &str) -> Option<bool> {
    let raw = &v[key];
    if let Some(b) = raw.as_bool() {
        return Some(b);
    }
    let s = raw.as_str()?.trim();
    match s.to_ascii_lowercase().as_str() {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

#[cfg(feature = "test-giver")]
fn successful_inbound_call(node: &Value) -> bool {
    let transaction = &node["dst_transaction"];
    if transaction.is_null() || transaction["aborted"].as_bool() != Some(false) {
        return false;
    }
    let stage_succeeded = |stage: &Value, code: &str| {
        if stage.is_null() {
            return false;
        }
        let success = stage["success"].as_bool();
        let exit_code = getter_u128(stage, code);
        success != Some(false)
            && exit_code.is_none_or(|value| value == 0)
            && (success == Some(true) || exit_code == Some(0))
    };
    stage_succeeded(&transaction["compute"], "exit_code")
        && stage_succeeded(&transaction["action"], "result_code")
}

fn details_has_withdrawn(details: &Value) -> Option<bool> {
    getter_bool(details, "hasWithdrawn")
}

fn note_withdrawn_sell_offer_message(note: &Address) -> String {
    format!(
        "seller post_offer aborted: this note has withdrawn and can no longer post sell offers -- deploy/use a \
         fresh note, re-provision the market, and retry. note={note}; postSellOffer would revert \
         ERR_INVALID_STATE 151 because PrivateNote._hasWithdrawn=true."
    )
}

fn note_withdrawn_buy_message(note: &Address) -> String {
    format!(
        "buyer place aborted: this note has withdrawn and can no longer place buys (deploy/use a fresh note); \
         the chain rejects it with ERR_INVALID_STATE 151 because PrivateNote._hasWithdrawn=true. note={note}"
    )
}

fn buyer_note_withdrawn_guard(note: &Address, details: Option<&Value>) -> Result<()> {
    match details.and_then(details_has_withdrawn) {
        Some(true) => Err(anyhow!(note_withdrawn_buy_message(note))),
        Some(false) => Ok(()),
        None => {
            eprintln!(
                "buyer place preflight note: PrivateNote.getDetails for note {note} did not expose \
                 hasWithdrawn; continuing without the withdrawn-state guard"
            );
            Ok(())
        }
    }
}

fn seller_note_withdrawn_check(note: &Address, actual: Option<bool>) -> ShellnetDoctorCheck {
    let (status, actual, message) = match actual {
        Some(false) => (
            ShellnetDoctorStatus::Pass,
            Some("hasWithdrawn=false".to_string()),
            "seller note has not withdrawn; postSellOffer is not blocked by _hasWithdrawn".to_string(),
        ),
        Some(true) => (
            ShellnetDoctorStatus::Fail,
            Some("hasWithdrawn=true".to_string()),
            note_withdrawn_sell_offer_message(note),
        ),
        None => (
            ShellnetDoctorStatus::Fail,
            Some("hasWithdrawn=<missing>".to_string()),
            "PrivateNote.getDetails did not expose hasWithdrawn; refusing to prove postSellOffer safety"
                .to_string(),
        ),
    };
    ShellnetDoctorCheck {
        name: "seller PrivateNote withdrawn state".to_string(),
        status,
        address: Some(note.with_workchain()),
        expected: Some("hasWithdrawn=false".to_string()),
        actual,
        message,
    }
}

pub(super) fn code_hash_check(
    name: &str,
    address: Option<&Address>,
    expected: &str,
    actual: Option<&str>,
) -> ShellnetDoctorCheck {
    let expected = normalize_code_hash(expected).unwrap_or_else(|| expected.to_string());
    let actual = actual.and_then(normalize_code_hash);
    let (status, message) = match actual.as_deref() {
        Some(a) if a == expected => (
            ShellnetDoctorStatus::Pass,
            "binary pin matches live shellnet".to_string(),
        ),
        Some(a) => (
            ShellnetDoctorStatus::Fail,
            format!(
                "dexdo build is STALE vs live shellnet - binary pins {expected}, live is {a}; rebuild from dev HEAD"
            ),
        ),
        None => (
            ShellnetDoctorStatus::Fail,
            "live account is missing, inactive, or exposes no code_hash".to_string(),
        ),
    };
    ShellnetDoctorCheck {
        name: name.to_string(),
        status,
        address: address.map(|a| a.with_workchain()),
        expected: Some(expected),
        actual,
        message,
    }
}

fn account_id_eq(addr: &Address, account_id: &str) -> bool {
    let addr = addr.with_workchain();
    let addr = addr.strip_prefix("0:").unwrap_or(&addr);
    addr.eq_ignore_ascii_case(account_id)
}

pub(super) fn active_check(name: &str, address: &Address, active: bool) -> ShellnetDoctorCheck {
    ShellnetDoctorCheck {
        name: name.to_string(),
        status: if active {
            ShellnetDoctorStatus::Pass
        } else {
            ShellnetDoctorStatus::Fail
        },
        address: Some(address.with_workchain()),
        expected: None,
        actual: Some(if active { "active" } else { "inactive" }.to_string()),
        message: if active {
            "account is active".to_string()
        } else {
            "manifest points at an inactive/undeployed account".to_string()
        },
    }
}

fn pass_check(name: &str, message: &str) -> ShellnetDoctorCheck {
    ShellnetDoctorCheck {
        name: name.to_string(),
        status: ShellnetDoctorStatus::Pass,
        address: None,
        expected: None,
        actual: None,
        message: message.to_string(),
    }
}

fn skipped_check(name: &str, message: &str) -> ShellnetDoctorCheck {
    ShellnetDoctorCheck {
        name: name.to_string(),
        status: ShellnetDoctorStatus::Skip,
        address: None,
        expected: None,
        actual: None,
        message: message.to_string(),
    }
}

fn clock_skew_check(local_unix: u64, chain_unix: u64) -> ShellnetDoctorCheck {
    let (skew_secs, direction, permitted_secs) = if local_unix >= chain_unix {
        (local_unix - chain_unix, "ahead of", MAX_CLOCK_AHEAD_SECS)
    } else {
        (chain_unix - local_unix, "behind", MAX_CLOCK_BEHIND_SECS)
    };
    let status = if skew_secs <= permitted_secs {
        ShellnetDoctorStatus::Pass
    } else {
        ShellnetDoctorStatus::Fail
    };
    let message = if status == ShellnetDoctorStatus::Pass {
        format!(
            "local clock is within the signed-message safety threshold (skew={skew_secs}s, \
             local_unix={local_unix}, chain_unix={chain_unix})"
        )
    } else {
        format!(
            "CLOCK_SKEW: local clock is {skew_secs}s {direction} chain time \
             (local_unix={local_unix}, chain_unix={chain_unix}); refusing signed writes before \
             submit: the pinned SDK gives signed messages {SDK_MESSAGE_EXPIRY_SECS}s to expire and \
             contracts strictly require block.timestamp < expireAt < block.timestamp + \
             {CONTRACT_MESSAGE_WINDOW_SECS}. Fix system time / NTP and retry."
        )
    };
    ShellnetDoctorCheck {
        name: "local clock vs chain time".to_string(),
        status,
        address: None,
        expected: Some(format!(
            "behind<={MAX_CLOCK_BEHIND_SECS}s, ahead<={MAX_CLOCK_AHEAD_SECS}s"
        )),
        actual: Some(format!(
            "skew={skew_secs}s local_unix={local_unix} chain_unix={chain_unix}"
        )),
        message,
    }
}

fn local_unix_secs() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("local system clock is before the Unix epoch")?
        .as_secs())
}

async fn fetch_chain_time_secs(http: &reqwest::Client, endpoint: &str) -> Result<u64> {
    let (graphql_url, _) = endpoint_urls(endpoint)?;
    let body = json!({
        "query": "{ blockchain { blocks(last:1){ edges { node { gen_utime } } } } }"
    });
    let response: Value = http
        .post(&graphql_url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {graphql_url} for chain time"))?
        .error_for_status()?
        .json()
        .await
        .context("parse GraphQL chain-time response")?;
    if let Some(errors) = response.get("errors").filter(|errors| !errors.is_null()) {
        return Err(anyhow!("GraphQL chain-time errors: {errors}"));
    }
    response
        .pointer("/data/blockchain/blocks/edges/0/node/gen_utime")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("chain time: latest block is missing gen_utime"))
}

/// Fail closed before a signed SDK write when the operator clock is unsafe for the contracts'
/// five-minute `expireAt` window.
pub async fn shellnet_clock_skew_preflight(endpoint: &str) -> Result<()> {
    let http = reqwest::Client::builder().user_agent(BROWSER_UA).build()?;
    let check = clock_skew_check(
        local_unix_secs()?,
        fetch_chain_time_secs(&http, endpoint).await?,
    );
    if check.status == ShellnetDoctorStatus::Fail {
        return Err(anyhow!(check.message));
    }
    Ok(())
}

fn dense_string_map(labels: &[String]) -> Value {
    let mut m = serde_json::Map::new();
    for (i, name) in labels.iter().enumerate() {
        m.insert(i.to_string(), Value::String(name.clone()));
    }
    Value::Object(m)
}

fn u128_array(values: &[u128]) -> Vec<String> {
    values.iter().map(u128::to_string).collect()
}

fn pubkey_uint256(keys: &KeyPair) -> String {
    format!("0x{}", keys.public_hex().trim_start_matches("0x"))
}

fn decimal_to_hex(dec: &str) -> Option<String> {
    let mut digits = dec
        .trim_start_matches('0')
        .bytes()
        .map(|b| b.checked_sub(b'0'))
        .collect::<Option<Vec<_>>>()?;
    if digits.is_empty() {
        return Some("0".to_string());
    }
    let mut out = Vec::new();
    while !digits.is_empty() {
        let mut next = Vec::new();
        let mut rem = 0u8;
        for d in digits {
            let n = rem as u16 * 10 + d as u16;
            let q = (n / 16) as u8;
            rem = (n % 16) as u8;
            if q != 0 || !next.is_empty() {
                next.push(q);
            }
        }
        out.push(b"0123456789abcdef"[rem as usize] as char);
        digits = next;
    }
    Some(out.into_iter().rev().collect())
}

fn normalize_uint256_hex(raw: &str) -> Result<String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(anyhow!("empty uint256"));
    }
    let hex = if let Some(h) = s.strip_prefix("0x") {
        h.to_string()
    } else if s.bytes().all(|b| b.is_ascii_hexdigit()) && s.bytes().any(|b| b.is_ascii_alphabetic())
    {
        s.to_string()
    } else if s.bytes().all(|b| b.is_ascii_digit()) {
        decimal_to_hex(s).ok_or_else(|| anyhow!("invalid uint256 decimal `{s}`"))?
    } else {
        return Err(anyhow!("invalid uint256 `{s}`"));
    };
    if hex.is_empty() || hex.len() > 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("invalid uint256 `{s}`"));
    }
    Ok(format!("0x{hex:0>64}").to_lowercase())
}

fn value_to_uint256_hex(v: &Value) -> Option<String> {
    v.as_str()
        .and_then(|s| normalize_uint256_hex(s).ok())
        .or_else(|| {
            v.as_u64()
                .and_then(|n| normalize_uint256_hex(&n.to_string()).ok())
        })
}

fn requested_bounds_to_uint256_hex(bounds: &[String]) -> Result<Vec<String>> {
    bounds.iter().map(|b| normalize_uint256_hex(b)).collect()
}

fn range_bounds_to_uint256_hex(bounds: &Value) -> Option<Vec<String>> {
    bounds
        .as_array()?
        .iter()
        .map(value_to_uint256_hex)
        .collect()
}

fn normalize_addr(raw: &str) -> Result<String> {
    Ok(Address::parse(raw)?.with_workchain().to_ascii_lowercase())
}

fn value_u64(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
}

fn parse_u128_literal(raw: &str) -> Option<u128> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if hex.is_empty() {
            return None;
        }
        return u128::from_str_radix(hex, 16).ok();
    }
    s.parse::<u128>().ok()
}

fn value_u128(v: &Value) -> Option<u128> {
    v.as_u64()
        .map(u128::from)
        .or_else(|| v.as_str().and_then(parse_u128_literal))
}

fn field<'a>(value: &'a Value, camel: &str, snake: &str) -> &'a Value {
    value
        .get(camel)
        .or_else(|| value.get(snake))
        .unwrap_or(&Value::Null)
}

fn outcome_names_match(value: &Value, expected: &[String]) -> bool {
    if let Some(obj) = value.as_object() {
        return obj.len() == expected.len()
            && expected
                .iter()
                .enumerate()
                .all(|(i, want)| obj.get(&i.to_string()).and_then(Value::as_str) == Some(want));
    }
    if let Some(arr) = value.as_array() {
        let mut got = vec![None; expected.len()];
        let mut count = 0usize;
        for item in arr {
            if let Some(obj) = item.as_object() {
                let key = obj
                    .get("key")
                    .or_else(|| obj.get("0"))
                    .and_then(value_u64)
                    .map(|v| v as usize);
                let val = obj
                    .get("value")
                    .or_else(|| obj.get("1"))
                    .and_then(Value::as_str);
                if let (Some(k), Some(v)) = (key, val) {
                    if let Some(slot) = got.get_mut(k) {
                        if slot.is_some() {
                            return false;
                        }
                        *slot = Some(v);
                        count += 1;
                    } else {
                        return false;
                    }
                }
            }
        }
        return count == expected.len()
            && got
                .iter()
                .zip(expected)
                .all(|(got, want)| got == &Some(want.as_str()));
    }
    false
}

fn event_matches(
    event: &Value,
    event_name: &str,
    deadline: u64,
    describe: &str,
    outcome_names: &[String],
) -> bool {
    field(event, "eventName", "event_name").as_str() == Some(event_name)
        && event["describe"].as_str() == Some(describe)
        && value_u64(&event["deadline"]) == Some(deadline)
        && outcome_names_match(field(event, "outcomeNames", "outcome_names"), outcome_names)
}

fn find_event_id_in_getter_output(
    output: &Value,
    event_name: &str,
    deadline: u64,
    describe: &str,
    outcome_names: &[String],
) -> Option<String> {
    let events = output.get("_events").unwrap_or(output);
    if let Some(obj) = events.as_object() {
        for (key, event) in obj {
            if event_matches(event, event_name, deadline, describe, outcome_names) {
                if let Ok(id) = normalize_uint256_hex(key) {
                    return Some(id);
                }
            }
        }
    }
    if let Some(arr) = events.as_array() {
        for item in arr {
            if let Some(obj) = item.as_object() {
                let key = obj.get("key").or_else(|| obj.get("0"));
                let event = obj.get("value").or_else(|| obj.get("1"));
                if let (Some(key), Some(event)) = (key, event) {
                    if event_matches(event, event_name, deadline, describe, outcome_names) {
                        if let Some(id) = value_to_uint256_hex(key) {
                            return Some(id);
                        }
                    }
                }
            } else if let Some(pair) = item.as_array() {
                if pair.len() == 2
                    && event_matches(&pair[1], event_name, deadline, describe, outcome_names)
                {
                    if let Some(id) = value_to_uint256_hex(&pair[0]) {
                        return Some(id);
                    }
                }
            }
        }
    }
    None
}

fn event_from_getter_output<'a>(output: &'a Value, event_id: &str) -> Option<&'a Value> {
    let wanted = normalize_uint256_hex(event_id).ok()?;
    let events = output.get("_events").unwrap_or(output);
    if let Some(obj) = events.as_object() {
        return obj.iter().find_map(|(key, event)| {
            (normalize_uint256_hex(key).ok().as_deref() == Some(wanted.as_str())).then_some(event)
        });
    }
    events.as_array()?.iter().find_map(|item| {
        if let Some(obj) = item.as_object() {
            let key = obj.get("key").or_else(|| obj.get("0"))?;
            let event = obj.get("value").or_else(|| obj.get("1"))?;
            return (value_to_uint256_hex(key).as_deref() == Some(wanted.as_str()))
                .then_some(event);
        }
        let pair = item.as_array()?;
        (pair.len() == 2 && value_to_uint256_hex(&pair[0]).as_deref() == Some(wanted.as_str()))
            .then(|| &pair[1])
    })
}

fn oracle_event_list_storage_fields(account_boc: &str) -> Result<Value> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(account_boc)
        .map_err(|error| anyhow!("decode account BOC base64: {error}"))?;
    let cell = tvm_types::read_single_root_boc(&bytes)
        .map_err(|error| anyhow!("read account BOC: {error}"))?;
    let account = tvm_block::Account::construct_from_cell(cell)
        .map_err(|error| anyhow!("decode account: {error}"))?;
    let data = account
        .get_data()
        .ok_or_else(|| anyhow!("active account exposes no data cell"))?;
    let contract = tvm_abi::Contract::load(ORACLEEVENTLIST_ABI.as_bytes())
        .map_err(|error| anyhow!("load OracleEventList ABI: {error}"))?;
    let tokens = contract
        .decode_storage_fields(
            tvm_types::SliceData::load_cell(data)
                .map_err(|error| anyhow!("load account data slice: {error}"))?,
            true,
        )
        .map_err(|error| anyhow!("decode account storage: {error}"))?;
    tvm_abi::token::Detokenizer::detokenize_to_json_value(&tokens)
        .map_err(|error| anyhow!("detokenize account storage: {error}"))
}

fn oracle_pmp_confirmation_is_active(
    fields: &Value,
    pmp: &Address,
    event_id: &str,
) -> Result<bool> {
    let Some(confirmed_event) = fields["_pmpConfirmed"]
        .as_object()
        .ok_or_else(|| anyhow!("OracleEventList storage exposes no _pmpConfirmed map"))?
        .get(&format!("0x{}", pmp.bare()))
    else {
        return Ok(false);
    };
    if value_to_uint256_hex(confirmed_event).as_deref()
        != Some(normalize_uint256_hex(event_id)?.as_str())
    {
        return Err(anyhow!(
            "OracleEventList _pmpConfirmed entry for PMP {pmp} belongs to another event"
        ));
    }
    Ok(true)
}

fn validate_oracle_event_list_identity(
    fields: &Value,
    manifest: &OracleMarketManifest,
    signer: &KeyPair,
) -> Result<u128> {
    let live_oracle = fields["_oracle"]
        .as_str()
        .ok_or_else(|| anyhow!("OracleEventList storage exposes no _oracle"))?;
    if normalize_addr(live_oracle)? != normalize_addr(&manifest.oracle)? {
        return Err(anyhow!(
            "OracleEventList belongs to {live_oracle}, not manifest oracle {}",
            manifest.oracle
        ));
    }
    let index = getter_u128(fields, "_index")
        .ok_or_else(|| anyhow!("OracleEventList storage exposes no _index"))?;
    let live_key = value_to_uint256_hex(&fields["_oraclePubkey"])
        .ok_or_else(|| anyhow!("OracleEventList storage exposes no _oraclePubkey"))?;
    if live_key != normalize_uint256_hex(signer.public_hex())? {
        return Err(anyhow!(
            "oracle signer {} does not own OracleEventList",
            signer.public_hex()
        ));
    }
    Ok(index)
}

fn validate_pmp_manifest(details: &Value, manifest: &OracleMarketManifest) -> Result<()> {
    let event_id = value_to_uint256_hex(&details["eventId"])
        .ok_or_else(|| anyhow!("PMP getDetails exposes no eventId"))?;
    if event_id != normalize_uint256_hex(&manifest.event_id)? {
        return Err(anyhow!("PMP eventId does not match the manifest"));
    }
    let list_hash = value_to_uint256_hex(&details["oracleListHash"])
        .ok_or_else(|| anyhow!("PMP getDetails exposes no oracleListHash"))?;
    if list_hash != normalize_uint256_hex(&manifest.oracle_list_hash)? {
        return Err(anyhow!("PMP oracleListHash does not match the manifest"));
    }
    if getter_u128(details, "tokenType") != Some(u128::from(manifest.token_type)) {
        return Err(anyhow!("PMP tokenType does not match the manifest"));
    }
    Ok(())
}

fn pmp_deployer(details: &Value) -> Result<Address> {
    let raw = details["deployer"]
        .as_str()
        .ok_or_else(|| anyhow!("PMP getDetails exposes no deployer"))?;
    Address::parse(raw).context("PMP getDetails deployer")
}

fn validate_salted_pmp_identity(
    pmp: &Address,
    actual_pmp_code_hash: Option<&str>,
    deployer: &Address,
    deployer_account: Option<&Account>,
    pmp_code: Option<&Value>,
) -> Result<()> {
    let deployer_account = deployer_account.ok_or_else(|| {
        anyhow!("PrivateNote account {deployer} is not Active/not found (account snapshot absent)")
    })?;
    if deployer_account.address != *deployer {
        return Err(anyhow!(
            "PMP deployer account snapshot belongs to {} instead of {deployer}",
            deployer_account.address
        ));
    }
    note_balance_private_note_account(deployer, Some(deployer_account))?;
    let pmp_code =
        pmp_code.ok_or_else(|| anyhow!("PrivateNote {deployer} getPMPCode unavailable"))?;
    let expected = value_to_uint256_hex(&pmp_code["pmpCodeHash"])
        .and_then(|hash| normalize_code_hash(&hash))
        .ok_or_else(|| anyhow!("PrivateNote {deployer} getPMPCode exposes no pmpCodeHash"))?;
    let actual = actual_pmp_code_hash
        .and_then(normalize_code_hash)
        .ok_or_else(|| anyhow!("PMP {pmp} exposes no code hash"))?;
    if actual != expected {
        return Err(anyhow!(
            "PMP {pmp} code hash does not match PrivateNote {deployer} getPMPCode"
        ));
    }
    Ok(())
}

fn validate_oracle_event_manifest(
    event: &Value,
    range: &Value,
    manifest: &OracleMarketManifest,
) -> Result<()> {
    if event["eventName"].as_str() != Some(manifest.event_name.as_str())
        || getter_u128(event, "deadline") != Some(u128::from(manifest.deadline))
        || !outcome_names_match(&event["outcomeNames"], &manifest.outcome_names)
    {
        return Err(anyhow!(
            "OracleEventList event identity does not match the manifest"
        ));
    }
    if getter_bool(range, "exists") != Some(true)
        || range["ob"].as_str().map(normalize_addr).transpose()?
            != Some(normalize_addr(&manifest.inference_order_book)?)
        || range_bounds_to_uint256_hex(&range["bounds"])
            != Some(requested_bounds_to_uint256_hex(&manifest.bounds)?)
    {
        return Err(anyhow!(
            "OracleEventList range identity does not match the manifest"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod oracle_getter_tests {
    use super::*;

    #[test]
    fn normalizes_uint256_getter_shapes() {
        assert_eq!(
            normalize_uint256_hex("15").unwrap(),
            "0x000000000000000000000000000000000000000000000000000000000000000f"
        );
        assert_eq!(
            normalize_uint256_hex("0xabc").unwrap(),
            "0x0000000000000000000000000000000000000000000000000000000000000abc"
        );
        assert!(normalize_uint256_hex("0xnothex").is_err());
    }

    #[test]
    fn parses_u128_getter_numbers_and_hex_strings() {
        assert_eq!(value_u128(&json!(10_000u64)), Some(10_000));
        assert_eq!(value_u128(&json!("10000")), Some(10_000));
        assert_eq!(
            value_u128(&json!(
                "0x0000000000000000000000000000000000000000000000000000000000002710"
            )),
            Some(10_000)
        );
        assert_eq!(value_u128(&json!("0xnothex")), None);
    }

    #[test]
    fn normalizes_range_bounds_for_idempotent_event_checks() {
        let live = json!(["0x0000000000000000000000000000000000000000000000000000000000002711"]);
        assert_eq!(
            range_bounds_to_uint256_hex(&live).unwrap(),
            requested_bounds_to_uint256_hex(&["10001".to_string()]).unwrap()
        );
        assert_ne!(
            range_bounds_to_uint256_hex(&live).unwrap(),
            requested_bounds_to_uint256_hex(&["10002".to_string()]).unwrap()
        );
        assert!(range_bounds_to_uint256_hex(&json!(["0xnothex"])).is_none());
    }

    #[test]
    fn finds_range_event_from_legacy_and_snake_getters() {
        let outcomes = vec!["below".to_string(), "above".to_string()];
        let legacy = json!({
            "_events": {
                "15": {
                    "eventName": "weekly",
                    "deadline": "1900000000",
                    "describe": "qwen",
                    "outcomeNames": {"0": "below", "1": "above"}
                }
            }
        });
        assert_eq!(
            find_event_id_in_getter_output(&legacy, "weekly", 1_900_000_000, "qwen", &outcomes)
                .unwrap(),
            "0x000000000000000000000000000000000000000000000000000000000000000f"
        );

        let snake = json!({
            "_events": [{
                "key": "0x10",
                "value": {
                    "event_name": "weekly",
                    "deadline": 1900000000u64,
                    "describe": "qwen",
                    "outcome_names": [
                        {"key": 0, "value": "below"},
                        {"key": 1, "value": "above"}
                    ]
                }
            }]
        });
        assert_eq!(
            find_event_id_in_getter_output(&snake, "weekly", 1_900_000_000, "qwen", &outcomes)
                .unwrap(),
            "0x0000000000000000000000000000000000000000000000000000000000000010"
        );
    }

    #[test]
    fn rejects_sparse_or_extra_outcome_getters() {
        let outcomes = vec!["below".to_string(), "above".to_string()];
        let extra = json!({
            "_events": {
                "15": {
                    "eventName": "weekly",
                    "deadline": "1900000000",
                    "describe": "qwen",
                    "outcomeNames": {"0": "below", "1": "above", "2": "extra"}
                }
            }
        });
        assert!(
            find_event_id_in_getter_output(&extra, "weekly", 1_900_000_000, "qwen", &outcomes)
                .is_none()
        );

        let sparse = json!({
            "_events": [{
                "key": "15",
                "value": {
                    "eventName": "weekly",
                    "deadline": "1900000000",
                    "describe": "qwen",
                    "outcomeNames": [
                        {"key": 0, "value": "below"},
                        {"key": 2, "value": "above"}
                    ]
                }
            }]
        });
        assert!(find_event_id_in_getter_output(
            &sparse,
            "weekly",
            1_900_000_000,
            "qwen",
            &outcomes
        )
        .is_none());
    }

    #[test]
    fn finds_exact_event_by_normalized_id() {
        let output = json!({
            "_events": [{
                "key": "15",
                "value": {"eventName": "weekly", "count": "2"}
            }]
        });
        let event = event_from_getter_output(&output, "0x0f").expect("event by id");
        assert_eq!(event["eventName"], "weekly");
        assert_eq!(getter_u128(event, "count"), Some(2));
        assert!(event_from_getter_output(&output, "0x10").is_none());
    }

    #[test]
    fn finds_only_the_exact_pmp_confirmation_in_oel_storage() {
        let pmp = Address::parse(&format!("0:{}", "1".repeat(64))).unwrap();
        let other_pmp = Address::parse(&format!("0:{}", "2".repeat(64))).unwrap();
        let mut confirmations = serde_json::Map::new();
        confirmations.insert(format!("0x{}", pmp.bare()), json!("0x16"));
        let fields = json!({"_pmpConfirmed": confirmations});

        assert!(oracle_pmp_confirmation_is_active(&fields, &pmp, "0x16").unwrap());
        assert!(!oracle_pmp_confirmation_is_active(&fields, &other_pmp, "0x16").unwrap());
        assert!(oracle_pmp_confirmation_is_active(&fields, &pmp, "0x17").is_err());
    }

    #[test]
    fn oracle_identity_validators_reject_wrong_signer_and_manifest() {
        let addr = |digit: char| format!("0:{}", digit.to_string().repeat(64));
        let manifest = OracleMarketManifest {
            network: "shellnet".into(),
            root_oracle: addr('1'),
            oracle: addr('2'),
            oracle_event_list: addr('3'),
            oracle_list_hash: "0x15".into(),
            event_id: "0x16".into(),
            event_name: "event".into(),
            pmp: addr('4'),
            token_type: 1,
            inference_order_book: addr('5'),
            frame_model: "model".into(),
            deadline: 1_000,
            bounds: vec!["10".into()],
            outcome_names: vec!["below".into(), "above".into()],
        };
        let signer = KeyPair::from_secret_hex(&"22".repeat(32)).unwrap();
        let fields = json!({
            "_oracle": manifest.oracle,
            "_index": "7",
            "_oraclePubkey": signer.public_hex(),
        });
        assert_eq!(
            validate_oracle_event_list_identity(&fields, &manifest, &signer).unwrap(),
            7
        );
        assert!(validate_oracle_event_list_identity(
            &fields,
            &manifest,
            &KeyPair::from_secret_hex(&"33".repeat(32)).unwrap()
        )
        .is_err());

        let details = json!({
            "eventId": manifest.event_id,
            "oracleListHash": manifest.oracle_list_hash,
            "tokenType": "1",
        });
        assert!(validate_pmp_manifest(&details, &manifest).is_ok());
        assert!(validate_pmp_manifest(
            &json!({"eventId": "0x17", "oracleListHash": "0x15", "tokenType": "1"}),
            &manifest
        )
        .is_err());

        let event = json!({
            "eventName": manifest.event_name,
            "deadline": "1000",
            "outcomeNames": {"0": "below", "1": "above"},
        });
        let range = json!({"exists": true, "ob": manifest.inference_order_book, "bounds": ["10"]});
        assert!(validate_oracle_event_manifest(&event, &range, &manifest).is_ok());
        assert!(validate_oracle_event_manifest(
            &event,
            &json!({"exists": true, "ob": addr('6'), "bounds": ["10"]}),
            &manifest
        )
        .is_err());
    }

    #[test]
    fn salted_pmp_identity_validator_is_fail_closed() {
        const SALTED: &str = "893599247dee107d493507399985a0bb5a4396580b8693f03f62aa36a25737f3";
        const BASE: &str = "fbc1fb4fa83a623bed6f224ba9d9d0f0904012f5f98a94937ea79ff27ce679fb";

        let pmp = Address::parse(&format!("0:{}", "1".repeat(64))).unwrap();
        let deployer = Address::parse(&format!("0:{}", "2".repeat(64))).unwrap();
        let other = Address::parse(&format!("0:{}", "3".repeat(64))).unwrap();
        let cases = [
            ("canonical salted", 0),
            ("unsalted base", 1),
            ("wrong salt", 2),
            ("wrong deployer", 3),
            ("inactive deployer", 4),
            ("non-PrivateNote", 5),
            ("missing getter", 6),
        ];

        for (name, case) in cases {
            let mut actual = SALTED;
            let mut account_address = &deployer;
            let mut status = "Active";
            let mut code_hash = PRIVATENOTE_PINNED_CODE_HASH;
            let mut getter = Some(SALTED);
            match case {
                1 => actual = BASE,
                2 => getter = Some(BASE),
                3 => account_address = &other,
                4 => {
                    status = "Uninit";
                    getter = None;
                }
                5 => code_hash = BASE,
                6 => getter = None,
                _ => {}
            }
            let account = Account {
                address: account_address.clone(),
                status: status.into(),
                balance: 0,
                ecc: Vec::new(),
                code_hash: Some(code_hash.into()),
                boc: None,
            };
            let getter = getter.map(|hash| json!({"pmpCodeHash": format!("0x{hash}")}));
            let result = validate_salted_pmp_identity(
                &pmp,
                Some(actual),
                &deployer,
                Some(&account),
                getter.as_ref(),
            );
            assert_eq!(result.is_ok(), case == 0, "{name}");
        }
    }
}

/// Manifest of the deployed shellnet contracts(`contracts/deployed.shellnet.json`).
/// The address source for the adapter and e2e. `InferenceOrderBook`(per-model) and
/// `TokenContract`(per-deal) are derived/discovered on the fly, so they are not pinned here.
#[derive(Debug, Clone, Deserialize)]
pub struct Deployed {
    /// Network label(for shellnet, `"shellnet"`).
    pub network: String,
    /// `SuperRoot` airegistry -- the derivation point for `RootModel`/`InferenceOrderBook`.
    pub superroot: String,
    /// `DappConfig`(a DApp with unlimited credit for deploys).
    pub dapp_config: String,
    /// `dapp_id`(= account_id of `SuperRoot`).
    pub dapp_id: String,
    /// Optional Block Manager endpoint. `graphql` is accepted for deployed-manifest compatibility.
    #[serde(default, alias = "graphql")]
    pub endpoint: Option<String>,
    /// Exact live code hashes used by destructive lifecycle preflights.
    #[serde(default)]
    pub contract_hashes: BTreeMap<String, String>,
}

impl Deployed {
    /// Read the manifest from a file(`contracts/deployed.shellnet.json`).
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path.as_ref())?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

/// Normalize a Block Manager host or URL to the base used by GraphQL and REST reads.
pub fn normalize_endpoint(endpoint: &str) -> anyhow::Result<String> {
    let endpoint = endpoint.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        anyhow::bail!("endpoint must not be empty");
    }
    let endpoint = endpoint.strip_suffix("/graphql").unwrap_or(endpoint);
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        Ok(endpoint.to_string())
    } else {
        Ok(format!("https://{endpoint}"))
    }
}

pub fn endpoint_urls(endpoint: &str) -> anyhow::Result<(String, String)> {
    let endpoint = normalize_endpoint(endpoint)?;
    Ok((
        format!("{endpoint}/graphql"),
        format!("{endpoint}/v2/account"),
    ))
}

pub fn resolve_endpoint(explicit: Option<&str>, manifest: &Deployed) -> anyhow::Result<String> {
    normalize_endpoint(
        explicit
            .or(manifest.endpoint.as_deref())
            .unwrap_or(crate::params::DEFAULT_SHELLNET_ENDPOINT),
    )
}

/// Real on-chain backend on top of `gosh.ackinacki` `ChainClient`.
/// Carries a live connection to shellnet and the root addresses from the manifest.
pub struct RealChainBackend {
    client: ChainClient,
    /// Browser-UA http client for reads, with reqwest's default redirect behavior.
    pub(super) http: reqwest::Client,
    /// Browser-UA client used only for one-shot money POSTs to `/v2/messages`.
    money_post_http: reqwest::Client,
    superroot: Address,
    deployed: Deployed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DealAccountIdentity {
    code_hash: String,
    boc_hash: String,
}

fn account_boc_hash(boc: &str) -> String {
    use sha2::{Digest, Sha256};

    Sha256::digest(boc.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[async_trait::async_trait]
trait DealSnapshotSource {
    async fn account_identity(&mut self) -> Result<Option<DealAccountIdentity>>;
    async fn state(&mut self) -> Result<Option<DealChainState>>;
    async fn subscription(&mut self) -> Result<Option<DealSubscription>>;
    async fn seller_bond(&mut self) -> Result<Option<DealSellerBond>>;
    async fn buyer_bond(&mut self) -> Result<Option<DealBuyerBond>>;
}

struct LiveDealSnapshotSource<'a> {
    chain: &'a RealChainBackend,
    token_contract: &'a Address,
}

#[async_trait::async_trait]
impl DealSnapshotSource for LiveDealSnapshotSource<'_> {
    async fn account_identity(&mut self) -> Result<Option<DealAccountIdentity>> {
        let Some(account) = self.chain.client.get_account(self.token_contract).await? else {
            return Ok(None);
        };
        if !account.is_active() {
            return Ok(None);
        }
        let code_hash = account
            .code_hash
            .as_deref()
            .and_then(normalize_code_hash)
            .ok_or_else(|| {
                anyhow!(
                    "TokenContract {} is active but has no code hash",
                    self.token_contract
                )
            })?;
        let boc = account.boc.as_deref().ok_or_else(|| {
            anyhow!(
                "TokenContract {} is active but has no account BOC",
                self.token_contract
            )
        })?;
        Ok(Some(DealAccountIdentity {
            code_hash,
            boc_hash: account_boc_hash(boc),
        }))
    }

    async fn state(&mut self) -> Result<Option<DealChainState>> {
        self.chain
            .token_contract_deal_state(self.token_contract)
            .await
    }

    async fn subscription(&mut self) -> Result<Option<DealSubscription>> {
        self.chain
            .token_contract_subscription(self.token_contract)
            .await
    }

    async fn seller_bond(&mut self) -> Result<Option<DealSellerBond>> {
        self.chain
            .token_contract_deal_seller_bond(self.token_contract)
            .await
    }

    async fn buyer_bond(&mut self) -> Result<Option<DealBuyerBond>> {
        self.chain
            .token_contract_deal_buyer_bond(self.token_contract)
            .await
    }
}

async fn read_deal_snapshot_round<S: DealSnapshotSource + Send>(
    source: &mut S,
) -> Result<Option<DealChainSnapshot>> {
    let Some(before) = source.account_identity().await? else {
        return Ok(None);
    };
    let state = source.state().await?;
    let subscription = source.subscription().await?;
    let seller_bond = source.seller_bond().await?;
    let buyer_bond = source.buyer_bond().await?;
    let after = source.account_identity().await?;

    if after.as_ref() != Some(&before) {
        return Err(anyhow!(
            "TokenContract changed or was destroyed while its accounting getters were read"
        ));
    }

    let state =
        state.ok_or_else(|| anyhow!("getState() returned no data for an active contract"))?;
    let subscription = subscription
        .ok_or_else(|| anyhow!("getSubscription() returned no data for an active contract"))?;
    let seller_bond = seller_bond
        .ok_or_else(|| anyhow!("getSellerBond() returned no data for an active contract"))?;
    let buyer_bond = buyer_bond
        .ok_or_else(|| anyhow!("getBuyerBond() returned no data for an active contract"))?;
    let snapshot = DealChainSnapshot {
        account_code_hash: before.code_hash,
        account_boc_hash: before.boc_hash,
        state,
        subscription,
        seller_bond,
        buyer_bond,
    };
    snapshot
        .validate_cross_getter_invariants()
        .map_err(anyhow::Error::msg)?;
    Ok(Some(snapshot))
}

async fn read_coherent_deal_snapshot<S: DealSnapshotSource + Send>(
    source: &mut S,
) -> Result<Option<DealChainSnapshot>> {
    let mut last_reason = "no snapshot attempt completed".to_string();
    for attempt in 1..=DEAL_SNAPSHOT_MAX_ATTEMPTS {
        match read_deal_snapshot_round(source).await {
            Ok(snapshot) => return Ok(snapshot),
            Err(error) => {
                last_reason = format!("attempt {attempt}: bracketed read failed: {error}");
            }
        }
    }
    Err(anyhow!(
        "could not obtain a coherent TokenContract snapshot after \
         {DEAL_SNAPSHOT_MAX_ATTEMPTS} attempts: {last_reason}"
    ))
}

#[cfg(test)]
mod coherent_deal_snapshot_tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum Script {
        Stable,
        DestroyAfter(usize),
        MutateAfter(usize),
        MutateEveryRound,
    }

    struct ScriptSource {
        script: Script,
        calls: usize,
    }

    impl ScriptSource {
        fn new(script: Script) -> Self {
            Self { script, calls: 0 }
        }

        fn observe(&mut self) -> (bool, u64) {
            self.calls += 1;
            match self.script {
                Script::Stable => (true, 0),
                Script::DestroyAfter(last_alive) => (self.calls <= last_alive, 0),
                Script::MutateAfter(last_old) => (true, u64::from(self.calls > last_old)),
                Script::MutateEveryRound => (true, ((self.calls - 1) / 5) as u64),
            }
        }

        fn state(generation: u64) -> DealChainState {
            DealChainState {
                funded: true,
                opened: true,
                probe_accepted: true,
                disputed: false,
                deposit: 100 + u128::from(generation),
                finalized_owed: 3,
                tokens_final: 10,
                tokens_superseded: 20,
                tokens_pending: 30,
                probe_tick: 2,
                funded_time: Some(70),
                probe_time: 40,
                prev_claim_time: 50,
                last_claim_time: 60,
                dispute_time: 0,
            }
        }

        fn subscription(generation: u64) -> DealSubscription {
            let funded_tokens = 2 * crate::params::TICK_SIZE + u128::from(generation);
            DealSubscription {
                deal_flags: 0,
                sub_weeks: 0,
                week_index: 0,
                tokens_per_week: funded_tokens,
                funded_tokens,
                tokens_paid: 0,
                period_start: 70,
                week_base_tokens: 0,
            }
        }
    }

    #[async_trait::async_trait]
    impl DealSnapshotSource for ScriptSource {
        async fn account_identity(&mut self) -> Result<Option<DealAccountIdentity>> {
            let (alive, generation) = self.observe();
            Ok(alive.then(|| DealAccountIdentity {
                code_hash: "code".to_string(),
                boc_hash: format!("boc-{generation}"),
            }))
        }

        async fn state(&mut self) -> Result<Option<DealChainState>> {
            let (alive, generation) = self.observe();
            Ok(alive.then(|| Self::state(generation)))
        }

        async fn subscription(&mut self) -> Result<Option<DealSubscription>> {
            let (alive, generation) = self.observe();
            Ok(alive.then(|| Self::subscription(generation)))
        }

        async fn seller_bond(&mut self) -> Result<Option<DealSellerBond>> {
            let (alive, generation) = self.observe();
            Ok(alive.then(|| DealSellerBond {
                bond_funded: true,
                bond_held: 200 + u128::from(generation),
                bond_required: 200 + u128::from(generation),
            }))
        }

        async fn buyer_bond(&mut self) -> Result<Option<DealBuyerBond>> {
            let (alive, _) = self.observe();
            Ok(alive.then_some(DealBuyerBond {
                bond_held: 0,
                bond_required: 0,
            }))
        }
    }

    struct FixedSource {
        snapshot: DealChainSnapshot,
    }

    #[async_trait::async_trait]
    impl DealSnapshotSource for FixedSource {
        async fn account_identity(&mut self) -> Result<Option<DealAccountIdentity>> {
            Ok(Some(DealAccountIdentity {
                code_hash: self.snapshot.account_code_hash.clone(),
                boc_hash: self.snapshot.account_boc_hash.clone(),
            }))
        }

        async fn state(&mut self) -> Result<Option<DealChainState>> {
            Ok(Some(self.snapshot.state))
        }

        async fn subscription(&mut self) -> Result<Option<DealSubscription>> {
            Ok(Some(self.snapshot.subscription))
        }

        async fn seller_bond(&mut self) -> Result<Option<DealSellerBond>> {
            Ok(Some(self.snapshot.seller_bond))
        }

        async fn buyer_bond(&mut self) -> Result<Option<DealBuyerBond>> {
            Ok(Some(self.snapshot.buyer_bond))
        }
    }

    fn valid_subscription_snapshot() -> DealChainSnapshot {
        DealChainSnapshot {
            account_code_hash: "code".to_string(),
            account_boc_hash: "boc".to_string(),
            state: ScriptSource::state(0),
            subscription: DealSubscription {
                deal_flags: flags::SUBSCRIPTION,
                sub_weeks: SUBSCRIPTION_WEEKS,
                week_index: 0,
                tokens_per_week: crate::params::TICK_SIZE,
                funded_tokens: u128::from(SUBSCRIPTION_WEEKS) * crate::params::TICK_SIZE,
                tokens_paid: 0,
                period_start: 70,
                week_base_tokens: 0,
            },
            seller_bond: DealSellerBond {
                bond_funded: true,
                bond_held: 200,
                bond_required: 200,
            },
            buyer_bond: DealBuyerBond {
                bond_held: 200,
                bond_required: 200,
            },
        }
    }

    #[tokio::test]
    async fn coherent_snapshot_accepts_one_complete_boc_bracketed_round() {
        let mut source = ScriptSource::new(Script::Stable);
        let snapshot = read_coherent_deal_snapshot(&mut source)
            .await
            .expect("stable snapshot")
            .expect("active contract");
        assert_eq!(source.calls, 6);
        assert_eq!(snapshot.buyer_locked().unwrap(), 102);
    }

    #[tokio::test]
    async fn one_round_rejects_destroy_between_every_getter_boundary() {
        // Calls are: account-before, state, subscription, seller bond, buyer
        // bond, account-after. Destroy after any of the first five must never
        // produce an active mixed snapshot.
        for boundary in 1..=5 {
            let mut source = ScriptSource::new(Script::DestroyAfter(boundary));
            assert!(
                read_deal_snapshot_round(&mut source).await.is_err(),
                "destroy after call {boundary} must fail the complete round"
            );
        }
    }

    #[tokio::test]
    async fn one_round_rejects_mutation_between_every_getter_boundary() {
        for boundary in 1..=5 {
            let mut source = ScriptSource::new(Script::MutateAfter(boundary));
            assert!(
                read_deal_snapshot_round(&mut source).await.is_err(),
                "mutation after call {boundary} must fail the complete round"
            );
        }
    }

    #[tokio::test]
    async fn coherent_reader_retries_one_bracketed_round_after_each_mutation() {
        let mut source = ScriptSource::new(Script::MutateEveryRound);
        let error = read_coherent_deal_snapshot(&mut source)
            .await
            .expect_err("every bracketed round mutates");
        assert_eq!(source.calls, DEAL_SNAPSHOT_MAX_ATTEMPTS * 6);
        assert!(error
            .to_string()
            .contains("could not obtain a coherent TokenContract snapshot"));
    }

    #[tokio::test]
    async fn coherent_snapshot_rejects_each_bond_tuple_contradiction() {
        let valid = valid_subscription_snapshot();
        let mut cases = Vec::new();

        let mut snapshot = valid.clone();
        snapshot.seller_bond.bond_held = 201;
        cases.push(("seller held above required", snapshot, "getSellerBond()"));

        let mut snapshot = valid.clone();
        snapshot.seller_bond.bond_funded = false;
        cases.push((
            "unfunded seller reports held value",
            snapshot,
            "bondFunded=false",
        ));

        let mut snapshot = valid.clone();
        snapshot.state.funded = false;
        cases.push((
            "opened state is not funded",
            snapshot,
            "opened=true with funded=false",
        ));

        let mut snapshot = valid.clone();
        snapshot.seller_bond.bond_funded = false;
        snapshot.seller_bond.bond_held = 0;
        cases.push((
            "opened seller bond is not funded",
            snapshot,
            "fully funded non-zero seller bond",
        ));

        let mut snapshot = valid.clone();
        snapshot.seller_bond.bond_held = 199;
        cases.push((
            "opened seller bond is under-held",
            snapshot,
            "fully funded non-zero seller bond",
        ));

        let mut snapshot = valid.clone();
        snapshot.buyer_bond.bond_held = 201;
        cases.push(("buyer held above required", snapshot, "getBuyerBond()"));

        let mut snapshot = valid.clone();
        snapshot.buyer_bond.bond_held = 199;
        cases.push((
            "live subscription buyer bond is under-held",
            snapshot,
            "fully held non-zero buyer bond",
        ));

        let mut snapshot = valid.clone();
        snapshot.buyer_bond.bond_held = 199;
        snapshot.buyer_bond.bond_required = 199;
        cases.push((
            "subscription required bonds differ",
            snapshot,
            "bondRequired mismatch",
        ));

        let mut snapshot = valid.clone();
        snapshot.subscription = ScriptSource::subscription(0);
        snapshot.buyer_bond = DealBuyerBond {
            bond_held: 1,
            bond_required: 1,
        };
        cases.push((
            "ordinary deal exposes buyer bond",
            snapshot,
            "ordinary-deal shape",
        ));

        let mut snapshot = valid;
        snapshot.state.opened = false;
        snapshot.state.probe_accepted = false;
        snapshot.seller_bond = DealSellerBond {
            bond_funded: false,
            bond_held: 0,
            bond_required: 0,
        };
        snapshot.buyer_bond = DealBuyerBond {
            bond_held: 0,
            bond_required: 0,
        };
        cases.push((
            "live funded subscription has zero buyer bond",
            snapshot,
            "fully held non-zero buyer bond",
        ));

        for (name, snapshot, expected) in cases {
            let mut source = FixedSource { snapshot };
            let error = read_deal_snapshot_round(&mut source).await.expect_err(name);
            assert!(
                error.to_string().contains(expected),
                "{name}: expected `{expected}`, got `{error}`"
            );
        }
    }

    #[tokio::test]
    async fn coherent_snapshot_rejects_funded_ordinary_volume_below_two_ticks() {
        for funded_tokens in [0, crate::params::TICK_SIZE] {
            let mut snapshot = valid_subscription_snapshot();
            snapshot.subscription = DealSubscription {
                deal_flags: 0,
                sub_weeks: 0,
                week_index: 0,
                tokens_per_week: funded_tokens,
                funded_tokens,
                tokens_paid: 0,
                period_start: 0,
                week_base_tokens: 0,
            };
            snapshot.buyer_bond = DealBuyerBond {
                bond_held: 0,
                bond_required: 0,
            };

            let mut source = FixedSource { snapshot };
            let error = read_deal_snapshot_round(&mut source)
                .await
                .expect_err("funded ordinary deal below two ticks must fail closed");
            assert!(
                error.to_string().contains("requires at least two ticks"),
                "unexpected error for fundedTokens={funded_tokens}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn coherent_snapshot_allows_terminal_subscription_with_released_bonds() {
        let mut snapshot = valid_subscription_snapshot();
        snapshot.state.opened = false;
        snapshot.state.deposit = 0;
        snapshot.state.probe_tick = 0;
        snapshot.seller_bond.bond_held = 0;
        snapshot.buyer_bond.bond_held = 0;
        assert!(snapshot.state.is_stopped());

        let mut source = FixedSource { snapshot };
        let observed = read_deal_snapshot_round(&mut source)
            .await
            .expect("terminal subscription is coherent")
            .expect("active terminal contract");
        assert_eq!(observed.buyer_bond.bond_held, 0);
        assert_eq!(observed.buyer_bond.bond_required, 200);
    }
}

/// True iff `e` is the BK REST `/v2/account` lookup 404 -- the destination account is not yet in the
/// block-manager index(a **funded-uninit deploy target**). Matched on the specific endpoint **and**
/// status, NOT a blanket "contains 404": a 404 from any other URL/cause still propagates as a real
/// error, and this only ever flips routing for a deploy-message send (`submit_once(.., deploy=true)`)..
pub(super) fn is_uninit_account_404(e: &str) -> bool {
    e.contains("/v2/account") && e.contains("404")
}

fn bare_hex(s: &str) -> String {
    s.trim()
        .trim_start_matches("0:")
        .trim_start_matches("0x")
        .to_lowercase()
}

fn submit_message_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("dexdo-{}-{nanos}", std::process::id())
}

fn submit_failure_is_clock_related(payload: &Value) -> bool {
    const GIVER_ADDRESS: &str =
        "0:1111111111111111111111111111111111111111111111111111111111111111";

    fn contains_string(value: &Value, wanted: &str) -> bool {
        match value {
            Value::String(value) => value == wanted,
            Value::Array(items) => items.iter().any(|item| contains_string(item, wanted)),
            Value::Object(fields) => fields.values().any(|value| contains_string(value, wanted)),
            _ => false,
        }
    }

    fn contains_exit_code(value: &Value, wanted: impl Fn(u64) -> bool + Copy) -> bool {
        match value {
            Value::Array(items) => items.iter().any(|item| contains_exit_code(item, wanted)),
            Value::Object(fields) => fields.iter().any(|(key, value)| {
                (matches!(
                    key.as_str(),
                    "exit_code" | "exitCode" | "vm_exit_code" | "vmExitCode"
                ) && value.as_u64().is_some_and(wanted))
                    || contains_exit_code(value, wanted)
            }),
            _ => false,
        }
    }

    contains_exit_code(payload, |code| matches!(code, 401 | 402))
        || (contains_string(payload, GIVER_ADDRESS)
            && contains_exit_code(payload, |code| matches!(code, 102 | 103)))
}

fn checked_submit_response(resp: Value) -> Result<Value> {
    validate_onchain_submit_response(resp).map_err(|e| {
        tracing::debug!(
            payload = %e.sanitized_payload(),
            "shellnet submit failure payload"
        );
        let clock_related = submit_failure_is_clock_related(e.sanitized_payload());
        let error = anyhow!(e);
        if clock_related {
            error.context(
                "signed-write expiry/replay rejection: verify the operator clock/NTP; a preflight observation may have raced or gone stale",
            )
        } else {
            error
        }
    })
}

fn external_message_hash(boc_base64: &str) -> Result<String> {
    use base64::Engine;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(boc_base64)
        .context("decode signed external-message BOC")?;
    let cell = tvm_types::read_single_root_boc(&bytes)
        .map_err(|error| anyhow!("decode signed external-message cell: {error}"))?;
    Ok(cell.repr_hash().to_hex_string())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CorrelatedActionReceipt {
    message_hash: String,
    transaction_hash: Option<String>,
    aborted: Option<bool>,
    compute_exit_code: Option<i64>,
    action_success: Option<bool>,
    result_code: Option<i64>,
    no_funds: Option<bool>,
    outmsg_count: Option<u64>,
    account_latest_transaction_hash: Option<String>,
    account_ecc_balances: Option<Vec<(u32, u128)>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteDeployWalletActionObservation {
    pub transaction_hash: String,
    pub aborted: bool,
    pub action_result_code: i64,
    pub outmsg_count: u64,
    pub wallet_ecc_balances: Option<Vec<(u32, u128)>>,
}

const EXACT_MESSAGE_RECEIPT_QUERY: &str = r#"
    query($hash: String!, $accountId: String!, $dappId: String!) {
      blockchain {
        message(hash: $hash) {
          id dst
          dst_transaction {
            id status aborted account_addr outmsg_cnt
            compute { exit_code success }
            action { result_code success no_funds }
          }
        }
        account(account_id: $accountId, dapp_id: $dappId) {
          info {
            id dapp_id
            balance_other { currency value }
          }
          transactions(last: 1) {
            edges { node { id } }
          }
        }
      }
    }
"#;

fn fund_deploy_shell_receipt_error(
    submit_error: anyhow::Error,
    expected_message_hash: &str,
    receipt: Option<&CorrelatedActionReceipt>,
) -> anyhow::Error {
    match receipt {
        Some(receipt)
            if bare_hex(&receipt.message_hash) == bare_hex(expected_message_hash)
                && receipt.transaction_hash.is_some()
                && receipt.aborted == Some(true)
                && receipt.action_success == Some(false)
                && receipt.result_code == Some(38)
                && receipt.no_funds == Some(true) =>
        {
            submit_error.context(format!(
                "fundDeployShell failed: insufficient ECC[2]/SHELL for note_fund_deploy_shell; \
                 correlated finalized receipt message_hash={} transaction_hash={} \
                 aborted=true action_success=false action_result_code=38 no_funds=true",
                expected_message_hash,
                receipt
                    .transaction_hash
                    .as_deref()
                    .expect("guard requires a transaction hash"),
            ))
        }
        Some(receipt) => submit_error.context(format!(
            "fundDeployShell aborted; correlated receipt message_hash={} transaction_hash={} \
             aborted={} action_success={} action_result_code={} no_funds={}; ECC[2] cause not proven",
            expected_message_hash,
            receipt
                .transaction_hash
                .as_deref()
                .unwrap_or("<unavailable>"),
            receipt
                .aborted
                .map_or_else(|| "<unavailable>".to_string(), |value| value.to_string()),
            receipt
                .action_success
                .map_or_else(|| "<unavailable>".to_string(), |value| value.to_string()),
            receipt
                .result_code
                .map_or_else(|| "<unavailable>".to_string(), |value| value.to_string()),
            receipt
                .no_funds
                .map_or_else(|| "<unavailable>".to_string(), |value| value.to_string()),
        )),
        None => submit_error.context(format!(
            "fundDeployShell aborted; no finalized destination receipt matched external \
             message_hash={expected_message_hash}; ECC[2] cause not proven"
        )),
    }
}

fn build_money_post_http_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(BROWSER_UA)
        .redirect(reqwest::redirect::Policy::none())
        // A signed BOC expires after this existing SDK window. Do not let a lost HTTP response
        // hold the caller forever; the settlement path reconciles the possibly-landed BOC from
        // immutable event history and never submits it again.
        .timeout(std::time::Duration::from_secs(SDK_MESSAGE_EXPIRY_SECS))
        .build()
}

async fn send_message_checked(
    http: &reqwest::Client,
    money_post_http: &reqwest::Client,
    endpoint: &str,
    boc_base64: &str,
) -> Result<Value> {
    let account_id = dest_account_id_hex(boc_base64)?;
    let dapp_id = fetch_dapp_id(http, endpoint, &account_id).await?;
    send_message_routed_checked(
        money_post_http,
        endpoint,
        boc_base64,
        &account_id,
        &dapp_id,
        None,
    )
    .await
}

pub(super) async fn send_message_routed_checked(
    http: &reqwest::Client,
    endpoint: &str,
    boc_base64: &str,
    account_id: &str,
    dapp_id: &str,
    thread_id: Option<&str>,
) -> Result<Value> {
    let mut item = json!({
        "id": submit_message_id(),
        "body": boc_base64,
        "account_id": bare_hex(account_id),
        "dapp_id": bare_hex(dapp_id),
    });
    if let Some(thread_id) = thread_id {
        item["thread_id"] = json!(bare_hex(thread_id));
    }
    let response = http
        .post(format!("{}/v2/messages", endpoint.trim_end_matches('/')))
        .header("Content-Type", "application/json")
        .json(&json!([item]))
        .send()
        .await?;
    if response.status().is_redirection() {
        return Err(anyhow!(
            "shellnet submit refused HTTP redirect {}",
            response.status()
        ));
    }
    let response = response.error_for_status()?;
    let status = response.status();
    let resp = response
        .json::<Value>()
        .await
        .map_err(|source| MessagePostResponseDecodeError { status, source })?;
    checked_submit_response(resp)
}

async fn send_message_routed_money_once(
    http: &reqwest::Client,
    endpoint: &str,
    boc_base64: &str,
    account_id: &str,
    dapp_id: &str,
) -> Result<Value> {
    let item = json!({
        "id": submit_message_id(),
        "body": boc_base64,
        "account_id": bare_hex(account_id),
        "dapp_id": bare_hex(dapp_id),
    });
    let response = http
        .post(format!("{}/v2/messages", endpoint.trim_end_matches('/')))
        .header("Content-Type", "application/json")
        .json(&json!([item]))
        .send()
        .await
        .map_err(|source| {
            let source = anyhow::Error::new(source);
            let before_post = source
                .downcast_ref::<reqwest::Error>()
                .is_some_and(|error| error.is_builder() || error.is_connect());
            anyhow::Error::new(if before_post {
                MoneySubmitError::Preparation { source }
            } else {
                MoneySubmitError::Ambiguous { source }
            })
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(anyhow::Error::new(MoneySubmitError::Ambiguous {
            source: anyhow!(
                "money POST returned unvalidated HTTP status {status}; redirects are disabled and no fresh BOC is safe"
            ),
        }));
    }
    let response = response.json::<Value>().await.map_err(|source| {
        anyhow::Error::new(MoneySubmitError::Ambiguous {
            source: anyhow::Error::new(source),
        })
    })?;
    checked_submit_response(response)
        .map_err(|source| anyhow::Error::new(MoneySubmitError::Rejected { source }))
}

fn is_queue_overflow_submit(error: &anyhow::Error) -> bool {
    let message = format!("{error:#}").to_ascii_lowercase();
    message.contains("queue_overflow")
        || message.contains("queue overflow")
        || message.contains("message queue is full")
}

/// Submit an explicit buyer STOP exactly once. A decoded queue-overflow response is still
/// outcome-ambiguous for this non-idempotent signed message and must never trigger a fresh POST.
async fn send_explicit_stop_money_once(
    http: &reqwest::Client,
    endpoint: &str,
    boc_base64: &str,
    account_id: &str,
    dapp_id: &str,
) -> Result<Value> {
    match send_message_routed_money_once(http, endpoint, boc_base64, account_id, dapp_id).await {
        Err(error) if is_queue_overflow_submit(&error) => {
            Err(anyhow::Error::new(MoneySubmitError::Ambiguous {
                source: error,
            }))
        }
        result => result,
    }
}

#[cfg(test)]
async fn prepare_policy_stop_money_post_if<P, F, Fut>(
    prepare: P,
    before_post: &mut (dyn FnMut() -> bool + Send),
    send: F,
) -> Result<Option<Value>>
where
    P: std::future::Future<Output = Result<(String, String, String, String)>>,
    F: FnOnce((String, String, String, String)) -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    let prepared = prepare.await?;
    if !before_post() {
        return Ok(None);
    }
    send(prepared).await.map(Some)
}

async fn query_exact_destination_receipt(
    http: &reqwest::Client,
    endpoint: &str,
    account_id: &str,
    dapp_id: &str,
    expected_message_hash: &str,
) -> Result<Value> {
    let gql = format!("{}/graphql", endpoint.trim_end_matches('/'));
    let response: Value = http
        .post(&gql)
        .json(&json!({
            "query": EXACT_MESSAGE_RECEIPT_QUERY,
            "variables": {
                "hash": bare_hex(expected_message_hash),
                "accountId": bare_hex(account_id),
                "dappId": bare_hex(dapp_id),
            },
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(response)
}

fn parse_exact_destination_receipt(
    response: &Value,
    expected_account_id: &str,
    expected_dapp_id: &str,
    expected_message_hash: &str,
) -> Result<Option<CorrelatedActionReceipt>> {
    let node = response
        .pointer("/data/blockchain/message")
        .ok_or_else(|| anyhow!("fundDeployShell receipt GraphQL response shape changed"))?;
    if node.is_null() {
        return Ok(None);
    }
    let message_hash = node["id"]
        .as_str()
        .ok_or_else(|| anyhow!("fundDeployShell exact-hash receipt has no message id"))?;
    if bare_hex(message_hash) != bare_hex(expected_message_hash) {
        return Err(anyhow!(
            "fundDeployShell exact-hash lookup returned mismatched message id"
        ));
    }
    let transaction = &node["dst_transaction"];
    if transaction.is_null() {
        return Ok(None);
    }
    let finalized = transaction["status"].as_i64() == Some(3)
        || transaction["status"].as_str() == Some("Finalized");
    if !finalized {
        return Ok(None);
    }

    let expected_account = bare_hex(expected_account_id);
    let destination = node["dst"]
        .as_str()
        .ok_or_else(|| anyhow!("fundDeployShell exact-hash receipt has no destination"))?;
    let transaction_account = transaction["account_addr"]
        .as_str()
        .ok_or_else(|| anyhow!("fundDeployShell destination transaction has no account"))?;
    let account = response
        .pointer("/data/blockchain/account/info")
        .ok_or_else(|| anyhow!("fundDeployShell receipt has no target account/dapp proof"))?;
    let account_id = account["id"]
        .as_str()
        .ok_or_else(|| anyhow!("fundDeployShell receipt target account has no id"))?;
    let account_dapp = account["dapp_id"]
        .as_str()
        .ok_or_else(|| anyhow!("fundDeployShell receipt target account has no dapp_id"))?;
    if bare_hex(destination) != expected_account
        || bare_hex(transaction_account) != expected_account
        || bare_hex(account_id) != expected_account
        || bare_hex(account_dapp) != bare_hex(expected_dapp_id)
    {
        return Err(anyhow!(
            "fundDeployShell exact-hash receipt destination/account/dapp mismatch"
        ));
    }
    let transaction_hash = transaction["id"]
        .as_str()
        .ok_or_else(|| anyhow!("fundDeployShell finalized destination transaction has no id"))?;
    let aborted = transaction["aborted"].as_bool().ok_or_else(|| {
        anyhow!("fundDeployShell finalized destination transaction has no aborted fact")
    })?;
    let compute_exit_code = transaction["compute"]["exit_code"].as_i64();
    let action_success = transaction["action"]["success"].as_bool();
    let result_code = transaction["action"]["result_code"].as_i64();
    let no_funds = transaction["action"]["no_funds"].as_bool();
    let account_ecc_balances = account["balance_other"].as_array().and_then(|balances| {
        balances
            .iter()
            .map(|balance| {
                let currency = u32::try_from(value_u128(&balance["currency"])?).ok()?;
                let value = value_u128(&balance["value"])?;
                Some((currency, value))
            })
            .collect()
    });
    let account_latest_transaction_hash = response
        .pointer("/data/blockchain/account/transactions/edges/0/node/id")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(Some(CorrelatedActionReceipt {
        message_hash: message_hash.to_string(),
        transaction_hash: Some(transaction_hash.to_string()),
        aborted: Some(aborted),
        compute_exit_code,
        action_success,
        result_code,
        no_funds,
        outmsg_count: value_u64(&transaction["outmsg_cnt"]),
        account_latest_transaction_hash,
        account_ecc_balances,
    }))
}

async fn poll_finalized_destination_receipt(
    http: &reqwest::Client,
    endpoint: &str,
    account_id: &str,
    dapp_id: &str,
    expected_message_hash: &str,
) -> Result<Option<CorrelatedActionReceipt>> {
    poll_finalized_destination_receipt_with(
        account_id,
        dapp_id,
        expected_message_hash,
        || {
            query_exact_destination_receipt(
                http,
                endpoint,
                account_id,
                dapp_id,
                expected_message_hash,
            )
        },
        crate::params::FINALIZED_DESTINATION_RECEIPT_POLL_INTERVAL,
    )
    .await
}

async fn poll_finalized_destination_receipt_with<F, Fut>(
    account_id: &str,
    dapp_id: &str,
    expected_message_hash: &str,
    mut query: F,
    retry_delay: std::time::Duration,
) -> Result<Option<CorrelatedActionReceipt>>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    for attempt in 0..crate::params::FINALIZED_DESTINATION_RECEIPT_MAX_ATTEMPTS {
        let response = query().await?;
        if let Some(errors) = response.get("errors") {
            return Err(anyhow!("fundDeployShell receipt GraphQL errors: {errors}"));
        }
        if let Some(receipt) =
            parse_exact_destination_receipt(&response, account_id, dapp_id, expected_message_hash)?
        {
            return Ok(Some(receipt));
        }
        if attempt + 1 < crate::params::FINALIZED_DESTINATION_RECEIPT_MAX_ATTEMPTS {
            tokio::time::sleep(retry_delay).await;
        }
    }
    Ok(None)
}

pub async fn observe_note_deploy_wallet_action(
    http: &reqwest::Client,
    endpoint: &str,
    boc_base64: &str,
    account_id: &str,
    dapp_id: &str,
) -> Result<Option<NoteDeployWalletActionObservation>> {
    let message_hash = external_message_hash(boc_base64)?;
    let Some(receipt) =
        poll_finalized_destination_receipt(http, endpoint, account_id, dapp_id, &message_hash)
            .await?
    else {
        return Ok(None);
    };
    note_deploy_wallet_action_observation(receipt).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteDeployRootPnActionObservation {
    pub transaction_hash: String,
    pub compute_exit_code: i64,
    pub aborted: bool,
    pub action_result_code: Option<i64>,
}

pub async fn observe_note_deploy_rootpn_action(
    http: &reqwest::Client,
    endpoint: &str,
    boc_base64: &str,
    account_id: &str,
    dapp_id: &str,
) -> Result<Option<NoteDeployRootPnActionObservation>> {
    let message_hash = external_message_hash(boc_base64)?;
    let Some(receipt) =
        poll_finalized_destination_receipt(http, endpoint, account_id, dapp_id, &message_hash)
            .await?
    else {
        return Ok(None);
    };
    note_deploy_rootpn_action_observation(receipt).map(Some)
}

fn note_deploy_rootpn_action_observation(
    receipt: CorrelatedActionReceipt,
) -> Result<NoteDeployRootPnActionObservation> {
    Ok(NoteDeployRootPnActionObservation {
        transaction_hash: receipt.transaction_hash.ok_or_else(|| {
            anyhow!("finalized note-deploy RootPN receipt has no transaction hash")
        })?,
        compute_exit_code: receipt.compute_exit_code.ok_or_else(|| {
            anyhow!("finalized note-deploy RootPN receipt has no compute exit code")
        })?,
        aborted: receipt
            .aborted
            .ok_or_else(|| anyhow!("finalized note-deploy RootPN receipt has no aborted fact"))?,
        action_result_code: receipt.result_code,
    })
}

fn note_deploy_wallet_action_observation(
    receipt: CorrelatedActionReceipt,
) -> Result<NoteDeployWalletActionObservation> {
    let transaction_hash = receipt
        .transaction_hash
        .ok_or_else(|| anyhow!("finalized note-deploy wallet receipt has no transaction hash"))?;
    let aborted = receipt
        .aborted
        .ok_or_else(|| anyhow!("finalized note-deploy wallet receipt has no aborted fact"))?;
    let result_code = receipt
        .result_code
        .ok_or_else(|| anyhow!("finalized note-deploy wallet receipt has no action result code"))?;
    let account_latest_transaction_hash =
        receipt.account_latest_transaction_hash.ok_or_else(|| {
            anyhow!("finalized note-deploy wallet receipt has no latest wallet transaction hash")
        })?;
    if bare_hex(&account_latest_transaction_hash) != bare_hex(&transaction_hash) {
        return Err(anyhow!(
            "note-deploy wallet state is stale or advanced: observed transaction hash={}, \
             latest wallet transaction hash={account_latest_transaction_hash}",
            transaction_hash
        ));
    }
    let outmsg_count = receipt.outmsg_count.ok_or_else(|| {
        anyhow!("finalized note-deploy wallet receipt has no outbound-message count")
    })?;
    Ok(NoteDeployWalletActionObservation {
        transaction_hash,
        aborted,
        action_result_code: result_code,
        outmsg_count,
        wallet_ecc_balances: receipt.account_ecc_balances,
    })
}

pub(super) fn previous_page_cursor(
    context: &str,
    page: &Value,
    before: Option<&str>,
) -> Result<Option<String>> {
    let page_info = page
        .get("pageInfo")
        .ok_or_else(|| anyhow!("{context} pageInfo missing"))?;
    let has_previous = page_info["hasPreviousPage"]
        .as_bool()
        .ok_or_else(|| anyhow!("{context} hasPreviousPage missing/invalid"))?;
    if !has_previous {
        return Ok(None);
    }
    let next = page_info["startCursor"]
        .as_str()
        .filter(|cursor| Some(*cursor) != before)
        .ok_or_else(|| anyhow!("{context} pagination made no progress"))?;
    Ok(Some(next.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExtOutMessage {
    pub id: String,
    pub created_at: u64,
    pub cursor: String,
    pub body: String,
}

#[derive(Debug)]
pub(super) struct ExtOutPage {
    pub messages: Vec<ExtOutMessage>,
    pub previous_cursor: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct SellerOfferEvents {
    pub placed_order_id: Option<u128>,
    pub matched: bool,
    pub placement_value_returned: bool,
}

/// One successful owner-signed `PrivateNote.placeInferenceBuy` transaction, decoded from the note's
/// external-in message and backed by a non-aborted destination transaction.
#[cfg(feature = "test-giver")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceInferenceBuyReceipt {
    pub message_id: String,
    pub created_at: u64,
    pub max_price_per_tick: u128,
    pub ticks: u128,
    pub escrow: u128,
}

/// One ordered lifecycle/settlement event emitted by a `TokenContract`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenContractSettlementReceipt {
    pub message_id: String,
    pub created_at: u64,
    pub cursor: String,
    pub event: TokenContractSettlementEvent,
}

/// Exact ABI payload of a known `TokenContract` lifecycle/settlement event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenContractSettlementEvent {
    ProbeAccepted {
        buyer: String,
        to_seller: u128,
        bond_returned: u128,
    },
    ProbeBurned {
        buyer: String,
        burned_probe: u128,
        burned_bond: u128,
        refund_to_buyer: u128,
    },
    TickFinalized {
        finalized_owed: u128,
        deposit: u128,
    },
    TicksClaimed {
        trusted: u128,
        claimed: u128,
    },
    StreamStopped {
        buyer: String,
        to_seller: u128,
        refund_to_buyer: u128,
    },
    StreamDisputed {
        buyer: String,
        at: u64,
    },
    DisputeResolved {
        to_seller: u128,
        refund_to_buyer: u128,
        released: bool,
    },
}

/// Ordered lifecycle and settlement receipts emitted by one `TokenContract`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenContractSettlementReceipts {
    pub events: Vec<TokenContractSettlementReceipt>,
}

pub(super) async fn fetch_ext_out_page(
    http: &reqwest::Client,
    endpoint: &str,
    account_id: &str,
    dapp_id: &str,
    page_size: u32,
    before: Option<&str>,
) -> Result<ExtOutPage> {
    let gql = format!("{}/graphql", endpoint.trim_end_matches('/'));
    let query = r#"
        query($accountId: String!, $dappId: String!, $last: Int!, $before: String) {
          blockchain {
            account(account_id: $accountId, dapp_id: $dappId) {
              messages(msg_type: [ExtOut], last: $last, before: $before) {
                pageInfo { startCursor hasPreviousPage }
                edges { cursor node { id body created_at } }
              }
            }
          }
        }
    "#;
    let response: Value = http
        .post(&gql)
        .json(&json!({
            "query": query,
            "variables": {
                "accountId": bare_hex(account_id),
                "dappId": bare_hex(dapp_id),
                "last": page_size,
                "before": before,
            },
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if let Some(errors) = response.get("errors") {
        return Err(anyhow!(
            "account {account_id} ext-out GraphQL errors: {errors}"
        ));
    }
    let page = response
        .pointer("/data/blockchain/account/messages")
        .ok_or_else(|| anyhow!("account {account_id} ext-out GraphQL shape changed: {response}"))?;
    let edges = page["edges"]
        .as_array()
        .ok_or_else(|| anyhow!("account {account_id} ext-out GraphQL edges missing: {response}"))?;
    let mut messages = Vec::with_capacity(edges.len());
    for edge in edges {
        let cursor = edge["cursor"]
            .as_str()
            .ok_or_else(|| anyhow!("account {account_id} ext-out event has no cursor"))?;
        let node = &edge["node"];
        let id = node["id"].as_str().ok_or_else(|| {
            anyhow!("account {account_id} ext-out event at cursor {cursor} has no message id")
        })?;
        let body = node["body"]
            .as_str()
            .ok_or_else(|| anyhow!("account {account_id} ext-out event {id} has no body"))?;
        let created_at = node["created_at"]
            .as_u64()
            .or_else(|| {
                node["created_at"]
                    .as_str()
                    .and_then(|value| value.parse().ok())
            })
            .ok_or_else(|| anyhow!("account {account_id} ext-out event has no created_at"))?;
        messages.push(ExtOutMessage {
            id: id.to_string(),
            created_at,
            cursor: cursor.to_string(),
            body: body.to_string(),
        });
    }
    Ok(ExtOutPage {
        messages,
        previous_cursor: previous_page_cursor(
            &format!("account {account_id} ext-out"),
            page,
            before,
        )?,
    })
}

async fn fetch_all_ext_out_messages(
    http: &reqwest::Client,
    endpoint: &str,
    account_id: &str,
) -> Result<Vec<ExtOutMessage>> {
    let dapp_id = fetch_dapp_id(http, endpoint, account_id).await?;
    fetch_all_ext_out_messages_routed(http, endpoint, account_id, &dapp_id).await
}

async fn fetch_all_ext_out_messages_routed(
    http: &reqwest::Client,
    endpoint: &str,
    account_id: &str,
    dapp_id: &str,
) -> Result<Vec<ExtOutMessage>> {
    // Existing PR689 reader bound. R20-10 reuses the reader rather than defining a second pager.
    let mut before: Option<String> = None;
    let mut pages = Vec::new();
    loop {
        let page = fetch_ext_out_page(
            http,
            endpoint,
            account_id,
            dapp_id,
            crate::params::EXT_OUT_PAGE_SIZE,
            before.as_deref(),
        )
        .await?;
        pages.push(page.messages);
        let Some(next) = page.previous_cursor else {
            break;
        };
        before = Some(next);
    }
    // Pages are fetched newest first; edges inside each page already carry chain order. Reverse
    // pages only. Message ids/cursors stay byte-for-byte opaque and are never parsed or sorted.
    dedupe_ext_out_messages_in_order(pages.into_iter().rev().flat_map(|page| page.into_iter()))
}

fn dedupe_ext_out_messages_in_order(
    messages: impl IntoIterator<Item = ExtOutMessage>,
) -> Result<Vec<ExtOutMessage>> {
    let mut by_id = BTreeMap::<String, ExtOutMessage>::new();
    let mut ordered = Vec::new();
    for message in messages {
        if let Some(previous) = by_id.get(&message.id) {
            if previous != &message {
                return Err(anyhow!(
                    "ext-out message {} changed across overlapping pages",
                    message.id
                ));
            }
            continue;
        }
        by_id.insert(message.id.clone(), message.clone());
        ordered.push(message);
    }
    Ok(ordered)
}

fn decode_token_contract_settlement_receipts(
    messages: Vec<ExtOutMessage>,
) -> Result<TokenContractSettlementReceipts> {
    let messages = dedupe_ext_out_messages_in_order(messages)?;
    let mut receipts = TokenContractSettlementReceipts::default();
    for message in messages {
        let Some(event) = decode_token_contract_settlement_event(&message.body)
            .with_context(|| format!("decode TokenContract event {}", message.id))?
        else {
            continue;
        };
        receipts.events.push(TokenContractSettlementReceipt {
            message_id: message.id,
            created_at: message.created_at,
            cursor: message.cursor,
            event,
        });
    }
    Ok(receipts)
}

fn decode_token_contract_settlement_event(
    body_b64: &str,
) -> Result<Option<TokenContractSettlementEvent>> {
    let bytes = match base64::engine::general_purpose::STANDARD.decode(body_b64.trim()) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    let cell = match tvm_types::read_single_root_boc(&bytes) {
        Ok(cell) => cell,
        Err(_) => return Ok(None),
    };
    let slice = match tvm_types::SliceData::load_cell(cell) {
        Ok(slice) => slice,
        Err(_) => return Ok(None),
    };
    let id = match tvm_abi::Event::decode_id(slice.clone()) {
        Ok(id) => id,
        Err(_) => return Ok(None),
    };
    let contract = tvm_abi::Contract::load(TOKENCONTRACT_ABI.as_bytes())
        .map_err(|error| anyhow!("load TokenContract ABI: {error}"))?;
    let event = match contract.event_by_id(id) {
        Ok(event) => event,
        Err(_) => return Ok(None),
    };
    let name = event.name.clone();
    let tokens = event
        .decode_input(slice, true)
        .map_err(|error| anyhow!("decode {name} body: {error}"))?;
    let required_u128 = |field| {
        decoded_u128(&tokens, field)
            .ok_or_else(|| anyhow!("{name} body missing or invalid {field}"))
    };
    let required_u64 = |field| {
        decoded_u64(&tokens, field).ok_or_else(|| anyhow!("{name} body missing or invalid {field}"))
    };
    let required_address = |field| {
        decoded_address(&tokens, field)
            .ok_or_else(|| anyhow!("{name} body missing or invalid {field}"))
    };
    let required_bool = |field| {
        decoded_bool(&tokens, field)
            .ok_or_else(|| anyhow!("{name} body missing or invalid {field}"))
    };
    Ok(Some(match name.as_str() {
        "ProbeAccepted" => TokenContractSettlementEvent::ProbeAccepted {
            buyer: required_address("buyer")?,
            to_seller: required_u128("toSeller")?,
            bond_returned: required_u128("bondReturned")?,
        },
        "ProbeBurned" => TokenContractSettlementEvent::ProbeBurned {
            buyer: required_address("buyer")?,
            burned_probe: required_u128("burnedProbe")?,
            burned_bond: required_u128("burnedBond")?,
            refund_to_buyer: required_u128("refundToBuyer")?,
        },
        "TickFinalized" => TokenContractSettlementEvent::TickFinalized {
            finalized_owed: required_u128("finalizedOwed")?,
            deposit: required_u128("deposit")?,
        },
        "TicksClaimed" => TokenContractSettlementEvent::TicksClaimed {
            trusted: required_u128("trusted")?,
            claimed: required_u128("claimed")?,
        },
        "StreamStopped" => TokenContractSettlementEvent::StreamStopped {
            buyer: required_address("buyer")?,
            to_seller: required_u128("toSeller")?,
            refund_to_buyer: required_u128("refundToBuyer")?,
        },
        "StreamDisputed" => TokenContractSettlementEvent::StreamDisputed {
            buyer: required_address("buyer")?,
            at: required_u64("at")?,
        },
        "DisputeResolved" => TokenContractSettlementEvent::DisputeResolved {
            to_seller: required_u128("toSeller")?,
            refund_to_buyer: required_u128("refundToBuyer")?,
            released: required_bool("released")?,
        },
        _ => return Ok(None),
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedSettlementEvent {
    BuyerStop,
    ProbeBurned,
    StreamStopped,
    StreamDisputed,
    DisputeResolved { released: bool },
}

impl ExpectedSettlementEvent {
    fn resolve(self, pre_state: DealChainState) -> Self {
        match self {
            Self::BuyerStop if pre_state.on_probe() => Self::ProbeBurned,
            Self::BuyerStop => Self::StreamStopped,
            exact => exact,
        }
    }
}

fn settlement_action_event_kind(event: &TokenContractSettlementEvent) -> Option<&'static str> {
    match event {
        TokenContractSettlementEvent::ProbeBurned { .. } => Some("ProbeBurned"),
        TokenContractSettlementEvent::StreamStopped { .. } => Some("StreamStopped"),
        TokenContractSettlementEvent::StreamDisputed { .. } => Some("StreamDisputed"),
        TokenContractSettlementEvent::DisputeResolved { released: true, .. } => {
            Some("DisputeResolved(released=true)")
        }
        TokenContractSettlementEvent::DisputeResolved {
            released: false, ..
        } => Some("DisputeResolved(released=false)"),
        TokenContractSettlementEvent::ProbeAccepted { .. }
        | TokenContractSettlementEvent::TickFinalized { .. }
        | TokenContractSettlementEvent::TicksClaimed { .. } => None,
    }
}

fn reject_prior_settlement_action(
    token_contract: &str,
    action: SettlementAction,
    expected_buyer: Option<&str>,
    receipts: &TokenContractSettlementReceipts,
) -> Result<()> {
    let actions = receipts
        .events
        .iter()
        .filter(|receipt| settlement_action_event_kind(&receipt.event).is_some())
        .collect::<Vec<_>>();

    let resolutions = actions
        .iter()
        .copied()
        .filter(|receipt| {
            matches!(
                receipt.event,
                TokenContractSettlementEvent::DisputeResolved { .. }
            )
        })
        .collect::<Vec<_>>();
    let disputes = actions
        .iter()
        .copied()
        .filter(|receipt| {
            matches!(
                receipt.event,
                TokenContractSettlementEvent::StreamDisputed { .. }
            )
        })
        .collect::<Vec<_>>();
    let stops = actions
        .iter()
        .copied()
        .filter(|receipt| {
            matches!(
                receipt.event,
                TokenContractSettlementEvent::ProbeBurned { .. }
                    | TokenContractSettlementEvent::StreamStopped { .. }
            )
        })
        .collect::<Vec<_>>();

    if matches!(
        action,
        SettlementAction::ReleaseDispute | SettlementAction::ResolveDisputeTimeout
    ) {
        let canonical_open_dispute =
            actions.len() == 1 && disputes.len() == 1 && resolutions.is_empty() && stops.is_empty();
        let canonical_resolution = actions.len() == 2
            && disputes.len() == 1
            && resolutions.len() == 1
            && stops.is_empty()
            && matches!(
                actions[0].event,
                TokenContractSettlementEvent::StreamDisputed { .. }
            )
            && matches!(
                actions[1].event,
                TokenContractSettlementEvent::DisputeResolved { .. }
            );
        if !canonical_open_dispute && !canonical_resolution {
            return Err(anyhow!(
                "TokenContract {token_contract} action {action} has invalid prior settlement-action \
                 history: expected exactly StreamDisputed, optionally followed by one \
                 DisputeResolved in canonical chain order; refusing before any money POST"
            ));
        }
    }

    let ambiguous = resolutions.len() > 1
        || disputes.len() > 1
        || stops.len() > 1
        || (!matches!(
            action,
            SettlementAction::ReleaseDispute | SettlementAction::ResolveDisputeTimeout
        ) && actions.len() > 1);
    if ambiguous {
        return Err(anyhow!(
            "TokenContract {token_contract} has more than one prior settlement-action receipt; \
             refusing action {action} before any money POST"
        ));
    }

    let exact = match action {
        SettlementAction::BuyerStop => stops.first().copied(),
        SettlementAction::SellerStop => stops.first().copied().filter(|receipt| {
            matches!(
                receipt.event,
                TokenContractSettlementEvent::StreamStopped { .. }
            )
        }),
        SettlementAction::Dispute => {
            if stops.is_empty() && resolutions.is_empty() {
                disputes.first().copied()
            } else {
                None
            }
        }
        SettlementAction::ReleaseDispute => resolutions.first().copied().filter(|receipt| {
            matches!(
                receipt.event,
                TokenContractSettlementEvent::DisputeResolved { released: true, .. }
            )
        }),
        SettlementAction::ResolveDisputeTimeout => resolutions.first().copied().filter(|receipt| {
            matches!(
                receipt.event,
                TokenContractSettlementEvent::DisputeResolved {
                    released: false,
                    ..
                }
            )
        }),
    };

    if let Some(receipt) = exact {
        if let Some(expected_buyer) = expected_buyer {
            let observed_buyer = match &receipt.event {
                TokenContractSettlementEvent::ProbeBurned { buyer, .. }
                | TokenContractSettlementEvent::StreamStopped { buyer, .. }
                | TokenContractSettlementEvent::StreamDisputed { buyer, .. } => Some(buyer),
                TokenContractSettlementEvent::DisputeResolved { .. }
                | TokenContractSettlementEvent::ProbeAccepted { .. }
                | TokenContractSettlementEvent::TickFinalized { .. }
                | TokenContractSettlementEvent::TicksClaimed { .. } => None,
            };
            if let Some(observed_buyer) = observed_buyer {
                let expected = normalize_addr(expected_buyer)?;
                let observed = normalize_addr(observed_buyer)?;
                if expected != observed {
                    return Err(anyhow!(
                        "TokenContract {token_contract} has prior action {action} receipt with buyer \
                         actor {observed}, expected {expected}; refusing before any money POST"
                    ));
                }
            }
        }
        let kind = settlement_action_event_kind(&receipt.event)
            .expect("exact prior action is a settlement-action event");
        return Err(anyhow!(
            "TokenContract {token_contract} action {action} is already recorded by exact {kind} \
             receipt message_id={} created_at={}; treating this retry as an idempotent no-op and \
             refusing a duplicate money POST",
            receipt.message_id,
            receipt.created_at
        ));
    }

    let incompatible = match action {
        SettlementAction::ReleaseDispute | SettlementAction::ResolveDisputeTimeout
            if resolutions.is_empty() && stops.is_empty() =>
        {
            None
        }
        _ => actions.last().copied(),
    };
    if let Some(receipt) = incompatible {
        let kind = settlement_action_event_kind(&receipt.event)
            .expect("incompatible prior action is a settlement-action event");
        return Err(anyhow!(
            "TokenContract {token_contract} action {action} has incompatible prior {kind} receipt \
             message_id={} created_at={}; refusing before any money POST",
            receipt.message_id,
            receipt.created_at
        ));
    }

    Ok(())
}

fn validate_buyer_stop_pre_state(
    token_contract: &str,
    pre: Option<&DealChainSnapshot>,
    receipts: &TokenContractSettlementReceipts,
) -> Result<()> {
    // Immutable action history wins over a potentially stale-open getter. Checking the getter first
    // would let a restarted process POST a second STOP after the terminal event had already landed.
    reject_prior_settlement_action(token_contract, SettlementAction::BuyerStop, None, receipts)?;

    if pre.is_some_and(|snapshot| snapshot.state.opened && !snapshot.state.disputed) {
        return Ok(());
    }

    match pre {
        None => Err(anyhow!(
            "TokenContract {token_contract} is inactive and has no exact terminal receipt; \
             refusing buyer STOP before any money POST"
        )),
        Some(snapshot) if snapshot.state.disputed => Err(anyhow!(
            "TokenContract {token_contract} is disputed; refusing buyer STOP before any money POST"
        )),
        Some(snapshot) => Err(anyhow!(
            "TokenContract {token_contract} is not an open, undisputed stream \
             (funded={} opened={} disputed={} deposit={} probeTick={}); refusing buyer STOP before \
             any money POST",
            snapshot.state.funded,
            snapshot.state.opened,
            snapshot.state.disputed,
            snapshot.state.deposit,
            snapshot.state.probe_tick
        )),
    }
}

/*
 * Keep settlement replay classification centralized above. Every caller performs it both before
 * signing/preparing a money message and again immediately before the coherent state/actor reads.
 */

fn settlement_confirmation_delay(
    elapsed: std::time::Duration,
    confirmation_timeout: std::time::Duration,
    confirmation_poll: std::time::Duration,
) -> Option<std::time::Duration> {
    let remaining = confirmation_timeout.checked_sub(elapsed)?;
    (!remaining.is_zero()).then(|| remaining.min(confirmation_poll))
}

fn validate_settlement_facts(token_contract: &str, facts: &DealChainSnapshot) -> Result<()> {
    if facts.seller_bond.bond_held > facts.seller_bond.bond_required {
        return Err(anyhow!(
            "TokenContract {token_contract} getSellerBond contradiction: held {} exceeds required {}",
            facts.seller_bond.bond_held,
            facts.seller_bond.bond_required
        ));
    }
    if facts.buyer_bond.bond_held > facts.buyer_bond.bond_required {
        return Err(anyhow!(
            "TokenContract {token_contract} getBuyerBond contradiction: held {} exceeds required {}",
            facts.buyer_bond.bond_held,
            facts.buyer_bond.bond_required
        ));
    }
    if !facts.subscription.is_subscription()
        && (facts.buyer_bond.bond_held != 0 || facts.buyer_bond.bond_required != 0)
    {
        return Err(anyhow!(
            "ordinary TokenContract {token_contract} exposes non-zero buyer bond: held={} required={}",
            facts.buyer_bond.bond_held,
            facts.buyer_bond.bond_required
        ));
    }
    if facts.subscription.is_subscription() && facts.buyer_bond.bond_required == 0 {
        return Err(anyhow!(
            "subscription TokenContract {token_contract} exposes zero buyer bond requirement"
        ));
    }
    Ok(())
}

fn settlement_bond_state(facts: &DealChainSnapshot) -> SettlementActionBondState {
    SettlementActionBondState {
        seller_bond_held: facts.seller_bond.bond_held.into(),
        seller_bond_required: facts.seller_bond.bond_required.into(),
        buyer_bond_held: facts.buyer_bond.bond_held.into(),
        buyer_bond_required: facts.buyer_bond.bond_required.into(),
    }
}

fn settlement_action_post_state(
    token_contract: &str,
    pre: &DealChainSnapshot,
    post: &DealChainSnapshot,
    event: &TokenContractSettlementEvent,
) -> Result<SettlementActionPostState> {
    validate_settlement_facts(token_contract, post)?;
    if pre.subscription.is_subscription() != post.subscription.is_subscription()
        || pre.seller_bond.bond_required != post.seller_bond.bond_required
        || pre.buyer_bond.bond_required != post.buyer_bond.bond_required
    {
        return Err(anyhow!(
            "TokenContract {token_contract} immutable deal/bond shape changed across settlement action"
        ));
    }

    let terminal = !matches!(event, TokenContractSettlementEvent::StreamDisputed { .. });
    if terminal {
        if !post.state.is_stopped() {
            return Err(anyhow!(
                "TokenContract {token_contract} terminal event contradicts post-state: funded={} \
                 opened={} disputed={} deposit={} probeTick={}",
                post.state.funded,
                post.state.opened,
                post.state.disputed,
                post.state.deposit,
                post.state.probe_tick
            ));
        }
        if post.seller_bond.bond_held != 0 || post.buyer_bond.bond_held != 0 {
            return Err(anyhow!(
                "TokenContract {token_contract} terminal event contradicts held collateral: sellerBondHeld={} buyerBondHeld={}",
                post.seller_bond.bond_held,
                post.buyer_bond.bond_held
            ));
        }
    } else if !post.state.opened || !post.state.disputed {
        return Err(anyhow!(
            "TokenContract {token_contract} StreamDisputed contradicts post-state: opened={} disputed={}",
            post.state.opened,
            post.state.disputed
        ));
    }

    match event {
        TokenContractSettlementEvent::StreamStopped { to_seller, .. }
        | TokenContractSettlementEvent::DisputeResolved { to_seller, .. }
            if *to_seller != post.state.finalized_owed =>
        {
            return Err(anyhow!(
                "TokenContract {token_contract} event/getter contradiction: toSeller={to_seller} finalizedOwed={}",
                post.state.finalized_owed
            ));
        }
        TokenContractSettlementEvent::StreamDisputed { at, .. } => {
            let mut expected_state = pre.state;
            expected_state.disputed = true;
            expected_state.dispute_time = *at;
            if post.state != expected_state
                || post.subscription != pre.subscription
                || post.seller_bond != pre.seller_bond
                || post.buyer_bond != pre.buyer_bond
            {
                return Err(anyhow!(
                    "TokenContract {token_contract} StreamDisputed changed settlement money, \
                     token pipeline, subscription, or held bonds; only disputed/disputeTime may change"
                ));
            }
        }
        _ => {}
    }

    Ok(SettlementActionPostState {
        tokens_final: post.state.tokens_final.into(),
        tokens_superseded: post.state.tokens_superseded.into(),
        tokens_pending: post.state.tokens_pending.into(),
        seller_bond_held: post.seller_bond.bond_held.into(),
        seller_bond_required: post.seller_bond.bond_required.into(),
        buyer_bond_held: post.buyer_bond.bond_held.into(),
        buyer_bond_required: post.buyer_bond.bond_required.into(),
        opened: post.state.opened,
        disputed: post.state.disputed,
    })
}

fn attach_settlement_post_snapshot(
    token_contract: &str,
    receipt: &mut SettlementActionReceipt,
    pre: &DealChainSnapshot,
    event: &TokenContractSettlementEvent,
    post: Option<&DealChainSnapshot>,
) -> Result<()> {
    match post {
        Some(post) => {
            receipt.post_state = Some(settlement_action_post_state(
                token_contract,
                pre,
                post,
                event,
            )?);
        }
        None if matches!(event, TokenContractSettlementEvent::StreamDisputed { .. }) => {
            return Err(anyhow!(
                "TokenContract {token_contract} was inactive after non-terminal StreamDisputed"
            ));
        }
        None => {
            receipt.post_state = None;
        }
    }
    Ok(())
}

fn select_new_settlement_action_receipt(
    token_contract: &str,
    action: SettlementAction,
    expected: ExpectedSettlementEvent,
    expected_buyer: Option<&str>,
    observed: &TokenContractSettlementReceipts,
    pre_bonds: SettlementActionBondState,
) -> Result<Option<SettlementActionReceipt>> {
    let action_events = observed
        .events
        .iter()
        .filter(|receipt| {
            matches!(
                receipt.event,
                TokenContractSettlementEvent::ProbeBurned { .. }
                    | TokenContractSettlementEvent::StreamStopped { .. }
                    | TokenContractSettlementEvent::StreamDisputed { .. }
                    | TokenContractSettlementEvent::DisputeResolved { .. }
            )
        })
        .collect::<Vec<_>>();
    if action_events.is_empty() {
        return Ok(None);
    }
    if action_events.len() != 1 {
        return Err(anyhow!(
            "TokenContract {token_contract} action {action} produced {} distinct new action events: {}",
            action_events.len(),
            action_events
                .iter()
                .map(|receipt| receipt.message_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let receipt = action_events[0];
    let preserve_buyer = |observed_buyer: &str| -> Result<String> {
        let expected_buyer = expected_buyer.ok_or_else(|| {
            anyhow!(
                "TokenContract {token_contract} action {action} has no independently known buyer actor"
            )
        })?;
        let observed = normalize_addr(observed_buyer).with_context(|| {
            format!(
                "TokenContract {token_contract} action {action} emitted malformed buyer actor {observed_buyer}"
            )
        })?;
        let expected = normalize_addr(expected_buyer).with_context(|| {
            format!(
                "TokenContract {token_contract} action {action} has malformed expected buyer actor {expected_buyer}"
            )
        })?;
        if observed != expected {
            return Err(anyhow!(
                "TokenContract {token_contract} action {action} emitted wrong buyer actor {observed}; expected {expected}"
            ));
        }
        Ok(observed_buyer.to_string())
    };
    let event = match (&expected, &receipt.event) {
        (
            ExpectedSettlementEvent::ProbeBurned,
            TokenContractSettlementEvent::ProbeBurned {
                buyer,
                burned_probe,
                burned_bond,
                refund_to_buyer,
            },
        ) => SettlementActionEvent::ProbeBurned {
            buyer: preserve_buyer(buyer)?,
            burned_probe: (*burned_probe).into(),
            burned_bond: (*burned_bond).into(),
            refund_to_buyer: (*refund_to_buyer).into(),
        },
        (
            ExpectedSettlementEvent::StreamStopped,
            TokenContractSettlementEvent::StreamStopped {
                buyer,
                to_seller,
                refund_to_buyer,
            },
        ) => SettlementActionEvent::StreamStopped {
            buyer: preserve_buyer(buyer)?,
            to_seller: (*to_seller).into(),
            refund_to_buyer: (*refund_to_buyer).into(),
        },
        (
            ExpectedSettlementEvent::StreamDisputed,
            TokenContractSettlementEvent::StreamDisputed { buyer, at },
        ) => SettlementActionEvent::StreamDisputed {
            buyer: preserve_buyer(buyer)?,
            at: *at,
        },
        (
            ExpectedSettlementEvent::DisputeResolved { released: expected },
            TokenContractSettlementEvent::DisputeResolved {
                to_seller,
                refund_to_buyer,
                released,
            },
        ) if released == expected => SettlementActionEvent::DisputeResolved {
            to_seller: (*to_seller).into(),
            refund_to_buyer: (*refund_to_buyer).into(),
            released: *released,
        },
        (ExpectedSettlementEvent::BuyerStop, _) => {
            return Err(anyhow!(
                "TokenContract {token_contract} action {action} retained unresolved buyer-stop event expectation"
            ));
        }
        _ => {
            return Err(anyhow!(
                "TokenContract {token_contract} action {action} observed incompatible new event {:?}; \
                 expected {expected:?}",
                receipt.event
            ));
        }
    };
    Ok(Some(SettlementActionReceipt {
        token_contract: token_contract.to_string(),
        action,
        message_id: receipt.message_id.clone(),
        created_at: receipt.created_at,
        event,
        pre_bonds,
        post_state: None,
    }))
}

fn settlement_receipts_after_snapshot(
    before: &TokenContractSettlementReceipts,
    current: TokenContractSettlementReceipts,
) -> Result<TokenContractSettlementReceipts> {
    if current.events.len() < before.events.len() {
        return Err(anyhow!(
            "post-submit TokenContract history changed and is not an append-only extension: \
             pre-submit history had {} events but the current history has {}",
            before.events.len(),
            current.events.len()
        ));
    }
    for (index, (previous, observed)) in before.events.iter().zip(&current.events).enumerate() {
        if previous != observed {
            return Err(anyhow!(
                "post-submit TokenContract history changed and is not an append-only extension at event \
                 {index}: expected pre-submit identity {}, observed {}",
                previous.message_id,
                observed.message_id
            ));
        }
    }
    Ok(TokenContractSettlementReceipts {
        events: current
            .events
            .into_iter()
            .skip(before.events.len())
            .collect(),
    })
}

fn ambiguous_settlement_action(
    token_contract: &str,
    action: SettlementAction,
    source: anyhow::Error,
) -> anyhow::Error {
    anyhow::Error::new(MoneySubmitError::Ambiguous {
        source: source.context(format!(
            "TokenContract {token_contract} action {action} may have landed; the BOC was not resubmitted"
        )),
    })
}

fn explicit_money_submit_outcome(error: &anyhow::Error) -> Option<&MoneySubmitError> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<MoneySubmitError>())
}

#[allow(clippy::too_many_arguments)]
async fn reconcile_settlement_action_after_post<
    Submit,
    SubmitFuture,
    Observe,
    ObserveFuture,
    ReadPost,
    ReadPostFuture,
>(
    token_contract: &str,
    action: SettlementAction,
    expected: ExpectedSettlementEvent,
    expected_buyer: Option<&str>,
    before: &TokenContractSettlementReceipts,
    pre: &DealChainSnapshot,
    confirmation_timeout: std::time::Duration,
    confirmation_poll: std::time::Duration,
    post_timeout: std::time::Duration,
    submit: Submit,
    mut observe: Observe,
    read_post: ReadPost,
) -> Result<SettlementActionReceipt>
where
    Submit: FnOnce() -> SubmitFuture,
    SubmitFuture: std::future::Future<Output = Result<()>>,
    Observe: FnMut() -> ObserveFuture,
    ObserveFuture: std::future::Future<Output = Result<TokenContractSettlementReceipts>>,
    ReadPost: FnOnce() -> ReadPostFuture,
    ReadPostFuture: std::future::Future<Output = Result<Option<DealChainSnapshot>>>,
{
    // This is deliberately before the one POST await. Both a response and every subsequent fact
    // read share one finite budget.
    let started = std::time::Instant::now();
    let submit_note = match tokio::time::timeout(post_timeout.min(confirmation_timeout), submit())
        .await
    {
        Ok(Ok(())) => None,
        Ok(Err(error))
            if matches!(
                explicit_money_submit_outcome(&error),
                Some(MoneySubmitError::Preparation { .. } | MoneySubmitError::Rejected { .. })
            ) =>
        {
            return Err(error);
        }
        Ok(Err(error)) => Some(format!("{error:#}")),
        Err(_) => Some(format!(
            "one-shot money POST response exceeded the existing signed-message expiry bound {post_timeout:?}"
        )),
    };

    let pending_error = || {
        ambiguous_settlement_action(
            token_contract,
            action,
            anyhow!(
                "no compatible immutable event became provable inside the canonical \
                 confirmation budget; {}",
                submit_note
                    .as_deref()
                    .unwrap_or("the POST response was accepted")
            ),
        )
    };
    loop {
        let Some(remaining) = confirmation_timeout.checked_sub(started.elapsed()) else {
            return Err(pending_error());
        };
        if remaining.is_zero() {
            return Err(pending_error());
        }
        let current = match tokio::time::timeout(remaining, observe()).await {
            Ok(Ok(current)) => current,
            Ok(Err(error)) => {
                return Err(ambiguous_settlement_action(
                    token_contract,
                    action,
                    error.context("post-submit TokenContract event read/decode failed"),
                ));
            }
            Err(_) => return Err(pending_error()),
        };
        let observed = settlement_receipts_after_snapshot(before, current).map_err(|error| {
            ambiguous_settlement_action(
                token_contract,
                action,
                error.context("post-submit TokenContract event snapshot contradicted its baseline"),
            )
        })?;
        let selected = select_new_settlement_action_receipt(
            token_contract,
            action,
            expected,
            expected_buyer,
            &observed,
            settlement_bond_state(pre),
        )
        .map_err(|error| {
            ambiguous_settlement_action(
                token_contract,
                action,
                error.context("post-submit action event was incompatible"),
            )
        })?;
        if let Some(mut receipt) = selected {
            let observed_event = observed
                .events
                .iter()
                .find(|event| event.message_id == receipt.message_id)
                .expect("selected receipt came from this observed event set")
                .event
                .clone();
            let remaining = confirmation_timeout
                .checked_sub(started.elapsed())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(&pending_error)?;
            let post = match tokio::time::timeout(remaining, read_post()).await {
                Ok(Ok(post)) => post,
                Ok(Err(error)) => {
                    return Err(ambiguous_settlement_action(
                        token_contract,
                        action,
                        error.context("post-submit coherent TokenContract snapshot failed"),
                    ));
                }
                Err(_) => return Err(pending_error()),
            };
            attach_settlement_post_snapshot(
                token_contract,
                &mut receipt,
                pre,
                &observed_event,
                post.as_ref(),
            )
            .map_err(|error| {
                ambiguous_settlement_action(
                    token_contract,
                    action,
                    error.context("post-submit event/getter facts contradicted"),
                )
            })?;
            return Ok(receipt);
        }
        let delay = settlement_confirmation_delay(
            started.elapsed(),
            confirmation_timeout,
            confirmation_poll,
        )
        .ok_or_else(&pending_error)?;
        tokio::time::sleep(delay).await;
    }
}

#[cfg(feature = "test-giver")]
fn decode_external_abi_message(
    body_b64: &str,
    abi: &str,
    input: bool,
) -> Option<tvm_abi::contract::DecodedMessage> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(body_b64.trim())
        .ok()?;
    let cell = tvm_types::read_single_root_boc(&bytes).ok()?;
    let slice = tvm_types::SliceData::load_cell(cell).ok()?;
    let contract = tvm_abi::Contract::load(abi.as_bytes()).ok()?;
    if input {
        contract.decode_input(slice, false, true).ok()
    } else {
        contract.decode_output(slice, false, true).ok()
    }
}

#[cfg(feature = "test-giver")]
fn decode_external_abi_message_boc(
    message_b64: &str,
    abi: &str,
    input: bool,
) -> Option<tvm_abi::contract::DecodedMessage> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(message_b64.trim())
        .ok()?;
    let cell = tvm_types::read_single_root_boc(&bytes).ok()?;
    let message = tvm_block::Message::construct_from_cell(cell).ok()?;
    let body = message.body()?;
    let contract = tvm_abi::Contract::load(abi.as_bytes()).ok()?;
    if input {
        contract.decode_input(body, false, true).ok()
    } else {
        contract.decode_output(body, false, true).ok()
    }
}

fn decoded_u128(tokens: &[tvm_abi::Token], name: &str) -> Option<u128> {
    tokens.iter().find_map(|token| {
        if token.name != name {
            return None;
        }
        match &token.value {
            tvm_abi::token::TokenValue::Uint(value) => value.number.to_string().parse().ok(),
            _ => None,
        }
    })
}

fn decoded_address(tokens: &[tvm_abi::Token], name: &str) -> Option<String> {
    tokens.iter().find_map(|token| {
        if token.name != name {
            return None;
        }
        match &token.value {
            tvm_abi::token::TokenValue::Address(value) => Some(format!("{value}")),
            _ => None,
        }
    })
}

fn decoded_u64(tokens: &[tvm_abi::Token], name: &str) -> Option<u64> {
    tokens.iter().find_map(|token| {
        if token.name != name {
            return None;
        }
        match &token.value {
            tvm_abi::token::TokenValue::Uint(value) => value.number.to_string().parse().ok(),
            _ => None,
        }
    })
}

fn decoded_bool(tokens: &[tvm_abi::Token], name: &str) -> Option<bool> {
    tokens.iter().find_map(|token| {
        if token.name != name {
            return None;
        }
        match &token.value {
            tvm_abi::token::TokenValue::Bool(value) => Some(*value),
            _ => None,
        }
    })
}

impl RealChainBackend {
    /// Connect using an optional manifest endpoint, falling back to the canonical shellnet endpoint.
    pub fn connect(manifest_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::connect_with_endpoint(manifest_path, None)
    }

    /// Connect with an explicit endpoint override, then manifest endpoint, then the shellnet default.
    pub fn connect_with_endpoint(
        manifest_path: impl AsRef<Path>,
        endpoint: Option<&str>,
    ) -> anyhow::Result<Self> {
        let deployed = Deployed::load(manifest_path)?;
        let endpoint = resolve_endpoint(endpoint, &deployed)?;
        let client = ChainClient::connect_with_config(&endpoint, AiRegistryConfig::shellnet())?;
        let http = reqwest::Client::builder().user_agent(BROWSER_UA).build()?;
        let money_post_http = build_money_post_http_client()?;
        let superroot = Address::parse(&deployed.superroot)?;
        Ok(Self {
            client,
            http,
            money_post_http,
            superroot,
            deployed,
        })
    }

    /// Fold authoritative live orders from one `InferenceOrderBook` ext-out stream.
    pub async fn fold_order_book_events(
        &self,
        order_book: &str,
        previous: BookEventFold,
    ) -> Result<BookEventFold> {
        read_book_event_fold(&self.http, self.client.endpoint(), order_book, previous).await
    }

    /// Low-level chain client(for the trait adapter in the next step).
    pub fn client(&self) -> &ChainClient {
        &self.client
    }

    /// The `SuperRoot` address -- the derivation point for `RootModel`/`InferenceOrderBook`.
    pub fn superroot(&self) -> &Address {
        &self.superroot
    }

    /// Chain liveness check -- confirms a working connection to shellnet.
    pub async fn liveness(&self) -> Result<ChainLiveness> {
        self.client.chain_liveness().await
    }

    async fn clock_skew_preflight(&self) -> Result<()> {
        let check = clock_skew_check(
            local_unix_secs()?,
            fetch_chain_time_secs(&self.http, self.client.endpoint()).await?,
        );
        if check.status == ShellnetDoctorStatus::Fail {
            return Err(anyhow!(check.message));
        }
        Ok(())
    }

    pub async fn observed_chain_timestamp(&self) -> Result<u64> {
        fetch_chain_time_secs(&self.http, self.client.endpoint()).await
    }

    pub async fn account_active_code_hash(&self, addr: &Address) -> Result<(bool, Option<String>)> {
        let Some(acc) = self.client.get_account(addr).await? else {
            return Ok((false, None));
        };
        Ok((
            acc.is_active(),
            acc.code_hash.as_deref().and_then(normalize_code_hash),
        ))
    }

    async fn code_hash_account_check(
        &self,
        name: &str,
        addr: &Address,
        expected: &str,
    ) -> Result<ShellnetDoctorCheck> {
        let (active, hash) = self.account_active_code_hash(addr).await?;
        if !active {
            return Ok(code_hash_check(name, Some(addr), expected, None));
        }
        Ok(code_hash_check(name, Some(addr), expected, hash.as_deref()))
    }

    async fn seller_note_withdrawn_check(&self, note: &Address) -> Result<ShellnetDoctorCheck> {
        match self.private_note_details(note).await {
            Ok(Some(details)) => Ok(seller_note_withdrawn_check(
                note,
                details_has_withdrawn(&details),
            )),
            Ok(None) => Ok(ShellnetDoctorCheck {
                name: "seller PrivateNote withdrawn state".to_string(),
                status: ShellnetDoctorStatus::Fail,
                address: Some(note.with_workchain()),
                expected: Some("hasWithdrawn=false".to_string()),
                actual: Some("getDetails=<none>".to_string()),
                message: "seller note returned no PrivateNote.getDetails; it is not active/current enough to prove postSellOffer safety"
                    .to_string(),
            }),
            Err(e) => Ok(ShellnetDoctorCheck {
                name: "seller PrivateNote withdrawn state".to_string(),
                status: ShellnetDoctorStatus::Fail,
                address: Some(note.with_workchain()),
                expected: Some("hasWithdrawn=false".to_string()),
                actual: Some("getDetails=<error>".to_string()),
                message: format!(
                    "cannot read PrivateNote.getDetails.hasWithdrawn before seller postSellOffer: {e}"
                ),
            }),
        }
    }

    async fn version_of(&self, addr: &Address, abi: &str) -> Result<Option<String>> {
        let Some(v) = self
            .client
            .run_getter(addr, abi, "getVersion", json!({}))
            .await?
        else {
            return Ok(None);
        };
        let left = v["value0"].as_str().unwrap_or("").trim();
        let right = v["value1"].as_str().unwrap_or("").trim();
        Ok(match (left.is_empty(), right.is_empty()) {
            (true, true) => None,
            (false, true) => Some(left.to_string()),
            (true, false) => Some(right.to_string()),
            (false, false) => Some(format!("{left} {right}")),
        })
    }

    /// Read-only shellnet readiness report: compare this binary's embedded/pinned contract images against
    /// live shellnet and, when supplied, verify that a market manifest still points at active IOB/TC accounts.
    pub async fn doctor(&self, market: Option<&MarketManifest>) -> Result<ShellnetDoctorReport> {
        let mut checks = Vec::new();
        self.liveness().await?;
        checks.push(pass_check("shellnet endpoint", "reachable"));
        checks.push(clock_skew_check(
            local_unix_secs()?,
            fetch_chain_time_secs(&self.http, self.client.endpoint()).await?,
        ));

        if account_id_eq(&self.superroot, FIXED_SUPERROOT_ACCOUNT_ID) {
            checks.push(skipped_check(
                "SuperRoot code hash",
                "fixed-superroot shellnet redeploy uses the 0:0c0c... zerostate anchor; old code-derived accounts are intentionally gone",
            ));
        } else {
            let superroot_hash = code_hash(SUPERROOT_TVC)?;
            checks.push(
                self.code_hash_account_check(
                    "SuperRoot code hash",
                    &self.superroot,
                    &superroot_hash,
                )
                .await?,
            );
        }

        if self.deployed.dapp_config.trim().is_empty() {
            checks.push(skipped_check(
                "DappConfig account",
                "fixed-superroot shellnet redeploy has no legacy DappConfig manifest account",
            ));
        } else {
            let dapp_config = Address::parse(&self.deployed.dapp_config)?;
            let (dapp_active, _) = self.account_active_code_hash(&dapp_config).await?;
            checks.push(active_check(
                "DappConfig account",
                &dapp_config,
                dapp_active,
            ));
        }

        let rootpn = Address::parse(ROOTPN_ADDR)?;
        checks.push(
            self.code_hash_account_check("RootPN code hash", &rootpn, SHELLNET_ROOTPN_V1_CODE_HASH)
                .await?,
        );
        let rootoracle = Address::parse(ROOTORACLE_ADDR)?;
        checks.push(
            self.code_hash_account_check(
                "RootOracle code hash",
                &rootoracle,
                &code_hash(ROOTORACLE_TVC)?,
            )
            .await?,
        );

        let rootpn_details = self
            .client
            .run_getter(&rootpn, ROOTPN_ABI, "getDetails", json!({}))
            .await?
            .ok_or_else(|| anyhow!("RootPN is not active"))?;
        checks.push(code_hash_check(
            "PrivateNote code hash (RootPN pin)",
            None,
            &code_hash(PRIVATENOTE_TVC)?,
            rootpn_details["privateNoteCodeHash"].as_str(),
        ));

        if let Some(market) = market {
            let rm = Address::parse(&market.root_model)?;
            checks.push(
                self.code_hash_account_check(
                    "RootModel code hash",
                    &rm,
                    SUPERROOT_PINNED_RM_CODE_HASH,
                )
                .await?,
            );
            let ob = Address::parse(&market.inference_order_book)?;
            checks.push(
                self.code_hash_account_check(
                    "InferenceOrderBook code hash",
                    &ob,
                    &code_hash(INFERENCE_ORDERBOOK_TVC)?,
                )
                .await?,
            );
            let tc = Address::parse(&market.token_contract)?;
            checks.push(
                self.code_hash_account_check(
                    "TokenContract code hash",
                    &tc,
                    ROOTMODEL_PINNED_TC_CODE_HASH,
                )
                .await?,
            );
            checks.push(active_check(
                "market TokenContract state",
                &tc,
                self.token_contract_state(&tc).await?.is_some(),
            ));
            let seller_note = Address::parse(&market.seller_note)?;
            checks.push(self.seller_note_withdrawn_check(&seller_note).await?);
        } else {
            checks.push(skipped_check(
                "RootModel code hash",
                "pass --market <manifest> to check the seller's deployed RootModel",
            ));
            checks.push(skipped_check(
                "InferenceOrderBook code hash",
                "pass --market <manifest> to check a deployed order book",
            ));
            checks.push(skipped_check(
                "TokenContract code hash",
                "pass --market <manifest> to check a deployed TokenContract",
            ));
            checks.push(skipped_check(
                "market TokenContract state",
                "pass --market <manifest> to check manifest freshness",
            ));
            checks.push(skipped_check(
                "seller PrivateNote withdrawn state",
                "pass --market <manifest> to check the seller note's hasWithdrawn flag",
            ));
        }

        let mut versions = Vec::new();
        if let Some(v) = self.version_of(&self.superroot, SUPERROOT_ABI).await? {
            versions.push(("SuperRoot".to_string(), v));
        }
        if let Some(v) = self.version_of(&rootpn, ROOTPN_ABI).await? {
            versions.push(("RootPN".to_string(), v));
        }
        if let Some(v) = self.version_of(&rootoracle, ROOTORACLE_ABI).await? {
            versions.push(("RootOracle".to_string(), v));
        }
        Ok(ShellnetDoctorReport {
            network: self.deployed.network.clone(),
            versions,
            checks,
        })
    }

    /// The `SuperRoot` owner pubkey(on-chain getter `getOwnerPubkey`).
    pub async fn superroot_owner_pubkey(&self) -> Result<Value> {
        let v = self
            .client
            .run_getter(&self.superroot, SUPERROOT_ABI, "getOwnerPubkey", json!({}))
            .await?
            .ok_or_else(|| anyhow!("SuperRoot is not active"))?;
        Ok(v["value0"].clone())
    }

    /// The `RootModel` address for a given owner pubkey -- the deterministic SuperRoot on-chain getter
    /// `getRootModelAddress(ownerPubkey)`. RootModel is per-owner: for the seller(model owner)
    /// it is derived from their pubkey(see [`Self::deploy_root_model`]).
    pub async fn root_model_address_for(&self, owner_pubkey: &Value) -> Result<Address> {
        let v = self
            .client
            .run_getter(
                &self.superroot,
                SUPERROOT_ABI,
                "getRootModelAddress",
                json!({ "ownerPubkey": owner_pubkey }),
            )
            .await?
            .ok_or_else(|| anyhow!("SuperRoot is not active"))?;
        Address::parse(v["value0"].as_str().ok_or_else(|| anyhow!("no address"))?)
    }

    /// Derive the `RootModel` address of the `SuperRoot` owner(part of address resolution for `ChainBackend`).
    pub async fn resolve_root_model(&self) -> Result<Address> {
        let owner = self.superroot_owner_pubkey().await?;
        self.root_model_address_for(&owner).await
    }

    async fn root_model_deploy_msg(&self, owner: &KeyPair) -> Result<(Address, String)> {
        let ctx = local_context()?;
        let tc_code = code_boc_b64(TOKENCONTRACT_TVC)?;
        let init_data = json!({
            "_ownerPubkey": format!("0x{}", owner.public_hex()),
            "_superRootAddress": self.superroot.with_workchain(),
        });
        let ctor = json!({ "tokenContractCode": tc_code });
        let msg = build_deploy(
            &ctx,
            ROOTMODEL_ABI,
            ROOTMODEL_TVC,
            init_data,
            ctor,
            owner.public_hex(),
            owner.secret_hex(),
        )
        .await?;
        Ok((Address::parse(&msg.address)?, msg.message_boc_b64))
    }

    /// Derive the per-deal `TokenContract` address from `RootModel`(`getTokenContractAddress`)
    /// by the seller's pubkey and the deal nonce -- a deterministic on-chain getter.
    pub async fn resolve_token_contract(
        &self,
        root_model: &Address,
        seller_pubkey: &Value,
        nonce: u64,
    ) -> Result<Address> {
        let v = self
            .client
            .run_getter(
                root_model,
                ROOTMODEL_ABI,
                "getTokenContractAddress",
                json!({ "sellerPubkey": seller_pubkey, "nonce": nonce }),
            )
            .await?
            .ok_or_else(|| anyhow!("RootModel is not active"))?;
        Address::parse(v["value0"].as_str().ok_or_else(|| anyhow!("no address"))?)
    }

    /// Derive the per-deal `TokenContract` address from the deploy **INIT-DATA(stateInit)** -- the
    /// getter-free, offline counterpart to [`resolve_token_contract`](Self::resolve_token_contract).
    /// `provision_market`'s idempotency check must NOT depend on the RootModel `getTokenContractAddress`
    /// network getter: on a fresh provision the RootModel deploy was just sent but is not yet `Active`, so the
    /// getter 404s and `resolve_token_contract`'s `"RootModel is not active"` error would abort the **entire**
    /// idempotent provision -- exactly the case the check exists to handle. The TC address is `hash(stateInit)`
    /// over `{code, varInit {_sellerPubkey,_rootModelAddress,_nonce,_pubkey}}`; it needs no RootModel account,
    /// no network, and cannot 404. (Bit-for-bit the address the deploy creates -- cross-checked against the
    /// getter only on the idempotent-skip branch, where the RootModel is guaranteed `Active`.)
    #[allow(clippy::too_many_arguments)]
    pub async fn token_contract_deploy_address(
        &self,
        seller: &KeyPair,
        root_model: &Address,
        nonce: u64,
        model_name: &str,
        _tick_size: u128,
        price_per_tick: u128,
        max_ticks: u128,
        seller_note: &Address,
    ) -> Result<Address> {
        Ok(self
            .token_contract_deploy_msg(
                seller,
                root_model,
                nonce,
                model_name,
                price_per_tick,
                max_ticks,
                seller_note,
            )
            .await?
            .0)
    }

    /// Read the endpoint ciphertext from `TokenContract` -- getter
    /// `getEndpointCipher`. The same `Handover` format as in (the buyer
    /// decrypts with the note key). `None` if the contract is not active or the endpoint is not yet written.
    pub async fn read_handover(&self, token_contract: &Address) -> Result<Option<Vec<u8>>> {
        let Some(v) = self
            .client
            .run_getter(
                token_contract,
                TOKENCONTRACT_ABI,
                "getEndpointCipher",
                json!({}),
            )
            .await?
        else {
            return Ok(None);
        };
        let hex = v["value0"].as_str().unwrap_or("");
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        if hex.is_empty() {
            return Ok(None);
        }
        Ok(Some(decode_hex(hex)?))
    }

    /// The deployed TC's stored `_modelHash` (4.0.6 `getModelHash() = sha256(modelName)`), normalized to
    /// `0x` + 64 lowercase hex. Used to assert the deal TC is for the SAME model as the order book
    /// (`model_hash`) before posting -- the 4.0.6 end-to-end model-name invariant.
    pub async fn token_contract_model_hash(&self, tc: &Address) -> Result<Option<String>> {
        let Some(v) = self
            .client
            .run_getter(tc, TOKENCONTRACT_ABI, "getModelHash", json!({}))
            .await?
        else {
            return Ok(None);
        };
        let raw = v["value0"].as_str().unwrap_or("");
        let hex = raw.strip_prefix("0x").unwrap_or(raw);
        if hex.is_empty() {
            return Ok(None);
        }
        Ok(Some(format!("0x{}", format!("{hex:0>64}").to_lowercase())))
    }

    /// The TC's on-chain **model display name** (`getModelName() -> string`, 4.0.6) -- the authoritative name
    /// for the accounting view: the manifest's `frame_model` is operator-supplied and must NOT be
    /// trusted as chain truth. `None` if the TC is not active or the name is empty.
    pub async fn token_contract_model_name(&self, tc: &Address) -> Result<Option<String>> {
        let Some(v) = self
            .client
            .run_getter(tc, TOKENCONTRACT_ABI, "getModelName", json!({}))
            .await?
        else {
            return Ok(None);
        };
        let name = v["value0"].as_str().unwrap_or("");
        if name.is_empty() {
            return Ok(None);
        }
        Ok(Some(name.to_string()))
    }

    /// The TC's on-chain **price per tick** (`getDeal() ->(tickSize, pricePerTick, maxTicks)`, 4.0.6) -- the
    /// authoritative deal price for the accounting view, NOT the operator-supplied manifest value.
    /// `uint128` decimal string. `None` if the TC is not active.
    pub async fn token_contract_price_per_tick(&self, tc: &Address) -> Result<Option<u128>> {
        let Some(v) = self
            .client
            .run_getter(tc, TOKENCONTRACT_ABI, "getDeal", json!({}))
            .await?
        else {
            return Ok(None);
        };
        Ok(getter_u128(&v, "pricePerTick"))
    }

    /// The TC's authoritative deal terms (`getDeal() -> tickSize, pricePerTick, maxTicks`).
    /// These are the values the seller must advertise in `postSellOffer`; CLI prompt/default values are not
    /// allowed to drift from this already-deployed per-deal contract.
    pub async fn token_contract_deal_terms(
        &self,
        tc: &Address,
    ) -> Result<Option<(u128, u128, u128)>> {
        let Some(v) = self
            .client
            .run_getter(tc, TOKENCONTRACT_ABI, "getDeal", json!({}))
            .await?
        else {
            return Ok(None);
        };
        let Some(tick_size) = getter_u128(&v, "tickSize") else {
            return Ok(None);
        };
        let Some(price_per_tick) = getter_u128(&v, "pricePerTick") else {
            return Ok(None);
        };
        let Some(max_ticks) = getter_u128(&v, "maxTicks") else {
            return Ok(None);
        };
        Ok(Some((tick_size, price_per_tick, max_ticks)))
    }

    /// Read the **buyer's ed25519 pubkey** from `TokenContract`(`getBuyerPubkey`, uint256) -- the book
    /// records it on a match(`placeInferenceBuy`). From it the seller **reconstructs the x25519 handover**
    /// and encrypts the endpoint to
    /// the recovered pubkey -- no separate x25519 channel is needed. `None` if the TC is not active or the buyer
    /// is not yet recorded(zero pubkey). The pubkey round-trips as `0x`-hex(like `getOwnerPubkey`).
    pub async fn token_contract_buyer_pubkey(&self, tc: &Address) -> Result<Option<[u8; 32]>> {
        let Some(v) = self
            .client
            .run_getter(tc, TOKENCONTRACT_ABI, "getBuyerPubkey", json!({}))
            .await?
        else {
            return Ok(None);
        };
        let raw = v["value0"].as_str().unwrap_or("");
        let hex = raw.strip_prefix("0x").unwrap_or(raw);
        if hex.is_empty() {
            return Ok(None);
        }
        // uint256 -> 32 bytes BE(the pubkey may have arrived without leading zeros -- left-pad to 64 hex).
        let bytes = decode_hex(&format!("{hex:0>64}"))?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "getBuyerPubkey: expected 32 bytes of ed25519, got {}",
                bytes.len()
            ));
        }
        if bytes.iter().all(|&b| b == 0) {
            return Ok(None); // buyer not yet recorded
        }
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&bytes);
        Ok(Some(ed))
    }

    /// Read the buyer note address from `TokenContract.getParties()`. `None` means the TC is inactive
    /// or has not recorded a buyer yet.
    pub async fn token_contract_buyer_note(&self, tc: &Address) -> Result<Option<Address>> {
        let Some(v) = self
            .client
            .run_getter(tc, TOKENCONTRACT_ABI, "getParties", json!({}))
            .await?
        else {
            return Ok(None);
        };
        let raw = v["buyer"].as_str().unwrap_or("");
        if raw.is_empty() {
            return Ok(None);
        }
        let addr = Address::parse(raw)?;
        if addr
            .with_workchain()
            .ends_with(":0000000000000000000000000000000000000000000000000000000000000000")
        {
            return Ok(None);
        }
        Ok(Some(addr))
    }

    /// Read the seller pubkey from `TokenContract.getSeller()`. Returned as normalized bare lowercase hex
    /// (no `0x`, left-padding is not significant for the key comparison). `None` means the TC is inactive or
    /// the getter returned an empty/zero pubkey.
    pub async fn token_contract_seller_pubkey(&self, tc: &Address) -> Result<Option<String>> {
        let Some(v) = self
            .client
            .run_getter(tc, TOKENCONTRACT_ABI, "getSeller", json!({}))
            .await?
        else {
            return Ok(None);
        };
        let raw = v["sellerPubkey"]
            .as_str()
            .or_else(|| v["value0"].as_str())
            .unwrap_or("");
        let hex = raw
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .to_ascii_lowercase();
        let hex = hex.trim_start_matches('0').to_string();
        if hex.is_empty() {
            return Ok(None);
        }
        Ok(Some(hex))
    }

    /// The `InferenceOrderBook` code-cell as base64-BOC -- the `code` argument for
    /// `deployInferenceOrderBook`/`getInferenceOrderBookAddress`. Extracted from the embedded
    /// `.tvc`(StateInit -> `.code`), like `airegistry::abi::Contract::code_boc_b64` in the SDK.
    pub fn inference_orderbook_code_b64() -> Result<String> {
        code_boc_b64(INFERENCE_ORDERBOOK_TVC)
    }

    pub fn canonical_inference_orderbook_address(model_hash: &str) -> Result<Address> {
        inference_orderbook_address_from_model_hash(model_hash)
    }

    /// Deterministic `InferenceOrderBook` address for(model, tick size) -- the note's on-chain getter
    /// `getInferenceOrderBookAddress(code, modelHash, tickSize)`. Success = the note has this
    /// method(meaning it is an inference note). `model_hash` is `0x...` uint256, `tick_size` is uint128.
    pub async fn inference_orderbook_address(
        &self,
        note: &Address,
        model_hash: &str,
        tick_size: u128,
    ) -> Result<Address> {
        let code = Self::inference_orderbook_code_b64()?;
        let v = self
            .client
            .run_getter(
                note,
                PRIVATENOTE_ABI,
                "getInferenceOrderBookAddress",
                json!({
                    "inferenceOrderBookCode": code,
                    "modelHash": model_hash,
                    "tickSize": tick_size.to_string(),
                }),
            )
            .await?
            .ok_or_else(|| anyhow!("note is not active"))?;
        Address::parse(v["value0"].as_str().ok_or_else(|| anyhow!("no address"))?)
    }

    /// Parameters of the deployed `InferenceOrderBook` -- getter `getParams` (`modelHash`, `tickSize`,
    /// `platformFeeBps`). Confirms that the book came up with the expected parameters. `None` if
    /// the book is not yet active.
    pub async fn inference_orderbook_params(&self, ob: &Address) -> Result<Option<Value>> {
        self.client
            .run_getter(ob, INFERENCE_ORDERBOOK_ABI, "getParams", json!({}))
            .await
    }

    /// A signed external contract call(write) through the backend's **browser-UA** http
    /// client: `encode_external_call`(the same codec as `ChainClient::call`) -> submit to
    /// `/v2/messages`. The ChainClient is not used for writes -- its default UA is blocked by
    /// Cloudflare(getters through it work fine). Returns the submit response.
    async fn encode_signed_call_boc(
        addr: &Address,
        abi_json: &str,
        method: &str,
        args: Value,
        keys: &KeyPair,
    ) -> Result<String> {
        let ctx = local_context()?;
        encode_external_call(
            &ctx,
            abi_json,
            &addr.with_workchain(),
            method,
            args,
            keys.public_hex(),
            keys.secret_hex(),
        )
        .await
    }

    async fn submit(
        &self,
        addr: &Address,
        abi_json: &str,
        method: &str,
        args: Value,
        keys: &KeyPair,
    ) -> Result<Value> {
        let boc = Self::encode_signed_call_boc(addr, abi_json, method, args, keys).await?;
        self.send_with_retry(&boc).await
    }

    async fn prepare_money_post(
        &self,
        addr: &Address,
        abi_json: &str,
        method: &str,
        args: Value,
        keys: &KeyPair,
    ) -> Result<(String, String, String, String)> {
        self.clock_skew_preflight()
            .await
            .map_err(|source| anyhow::Error::new(MoneySubmitError::Preparation { source }))?;
        let boc = Self::encode_signed_call_boc(addr, abi_json, method, args, keys)
            .await
            .map_err(|source| anyhow::Error::new(MoneySubmitError::Preparation { source }))?;
        let endpoint = self.client.endpoint().to_string();
        let account_id = dest_account_id_hex(&boc)
            .map_err(|source| anyhow::Error::new(MoneySubmitError::Preparation { source }))?;
        let dapp_id = fetch_dapp_id(&self.http, &endpoint, &account_id)
            .await
            .map_err(|source| anyhow::Error::new(MoneySubmitError::Preparation { source }))?;
        Ok((endpoint, boc, account_id, dapp_id))
    }

    /// Submit `boc` to `/v2/messages`. `deploy` selects the routing:
    /// - `false` -- a regular write to an **existing** contract(call/fund): `send_message`, which
    /// reads the real `dapp_id` via the BK REST `/v2/account`. A 404 there is a real error -> propagates.
    /// - `true` -- a **deploy-message send** whose destination is a not-yet-deployed self-dapp address:
    /// read the real `dapp_id`, but on the **specific `/v2/account` uninit-404**([`is_uninit_account_404`])
    /// fall back to `dapp_id = account_id`(self-dapp) and submit via `send_message_routed` (which skips
    /// the `/v2/account` read). This lets one `dexdo provision` land a fresh deploy in a SINGLE shot
    /// instead of dying on the first attempt and forcing a cumulative re-funded retry.
    /// **Scoped:** only the deploy/fund submit sites pass `deploy = true`; every regular write keeps the
    /// unchanged `send_message` path. Any non-`/v2/account` 404(or other error) still propagates.
    async fn submit_once(&self, boc: &str, deploy: bool) -> Result<Value> {
        let endpoint = self.client.endpoint();
        if !deploy {
            return send_message_checked(&self.http, &self.money_post_http, endpoint, boc).await;
        }
        let account_id = dest_account_id_hex(boc)?;
        let dapp_id = match fetch_dapp_id(&self.http, endpoint, &account_id).await {
            Ok(d) => d,
            Err(e) if is_uninit_account_404(&e.to_string()) => account_id.clone(),
            Err(e) => return Err(e),
        };
        send_message_routed_checked(
            &self.money_post_http,
            endpoint,
            boc,
            &account_id,
            &dapp_id,
            None,
        )
        .await
    }

    /// Submit a message to shellnet with retry on **transient** infrastructure failures:
    /// (1) overflow of the block manager's write queue(`QUEUE_OVERFLOW` -- "message queue is full");
    /// (2) **transient gateway 5xx** (`502 Bad Gateway` / `503` / `504` from the reverse proxy, when
    /// the backend is briefly unavailable -- observed to flicker on shellnet under load). The node is alive and moving
    /// blocks; we wait(exponential backoff, cap 8s) and retry -- this is resilience to a real network,
    /// not a test crutch. Other(logical) errors propagate immediately. `deploy` is threaded to
    /// [`submit_once`] so only deploy-message sends get the funded-uninit `/v2/account` 404 tolerance.
    async fn retry_submit(&self, boc: &str, deploy: bool) -> Result<Value> {
        self.clock_skew_preflight().await?;
        // Transient marker: the queue is full OR a temporary gateway failure(5xx) that clears on its own.
        fn is_transient(msg: &str) -> bool {
            msg.contains("QUEUE_OVERFLOW")
                || msg.contains("502")
                || msg.contains("503")
                || msg.contains("504")
                || msg.contains("Bad Gateway")
                || msg.contains("Service Unavailable")
                || msg.contains("Gateway Time")
        }
        let mut delay = crate::params::TRANSIENT_SUBMIT_INITIAL_BACKOFF;
        for attempt in 1..=crate::params::TRANSIENT_SUBMIT_RETRIES_BEFORE_FINAL {
            match self.submit_once(boc, deploy).await {
                Ok(v) => return Ok(v),
                Err(e) if is_transient(&e.to_string()) => {
                    eprintln!(
                        "shellnet transient submit error (attempt {attempt}): {e}; waiting {delay:?} then retrying"
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * crate::params::TRANSIENT_SUBMIT_BACKOFF_MULTIPLIER)
                        .min(crate::params::TRANSIENT_SUBMIT_MAX_BACKOFF);
                }
                Err(e) => return Err(e),
            }
        }
        // Final attempt -- pass the result through as-is(Ok or the final error).
        self.submit_once(boc, deploy).await
    }

    /// Regular write to an **existing** contract(call/fund) -- unchanged `send_message` routing.
    pub(super) async fn send_with_retry(&self, boc: &str) -> Result<Value> {
        self.retry_submit(boc, false).await
    }

    /// A **deploy-message** send(its destination is a not-yet-deployed self-dapp address): tolerates
    /// the funded-uninit `/v2/account` 404 via self-dapp routing. Use ONLY for deploy submits.
    async fn send_deploy_with_retry(&self, boc: &str) -> Result<Value> {
        self.retry_submit(boc, true).await
    }

    /// The owner note deploys `InferenceOrderBook` (`deployInferenceOrderBook(code, modelHash,
    /// tickSize)`, signed with the note's owner key). The book is deployed by the note itself: it passes its
    /// `depositIdentifierHash`, and the book's ctor checks that the deployer is a genuine note. Returns
    /// the submit result; wait for book activation by polling `inference_orderbook_address`.
    pub async fn deploy_inference_orderbook(
        &self,
        note: &Address,
        owner_keys: &KeyPair,
        model_hash: &str,
        model_name: &str,
        tick_size: u128,
    ) -> Result<Value> {
        let code = Self::inference_orderbook_code_b64()?;
        // 4.0.6: the book's ctor verifies `sha256(modelName) == modelHash`, so `model_hash` MUST be
        // `sha256(model_name)`(the canonical preimage). `inferenceOrderBookCode`/`tickSize` are not in
        // the 2-arg ABI(the OB code is stored on the note) -- harmless extra keys, the encoder ignores them.
        self.submit(
            note,
            PRIVATENOTE_ABI,
            "deployInferenceOrderBook",
            json!({
                "inferenceOrderBookCode": code,
                "modelHash": model_hash,
                "modelName": model_name,
                "tickSize": tick_size.to_string(),
            }),
            owner_keys,
        )
        .await
    }

    /// The book's `getBestBidAsk` getter(`hasBid`, `bid`, `hasAsk`, `ask`) -- a check that the offer landed
    /// in the order book as an ask. `None` if the book is not active.
    pub async fn inference_orderbook_best_bid_ask(&self, ob: &Address) -> Result<Option<Value>> {
        self.client
            .run_getter(ob, INFERENCE_ORDERBOOK_ABI, "getBestBidAsk", json!({}))
            .await
    }

    /// Poll THIS note's owner-facing `InferenceFilledConfirmed` ext-out
    /// and advance a durable cursor. The side is owner-relative: `want_is_buy=true` for the buyer's note,
    /// `false` for the seller's note. The caller decides whether/how long to sleep between polls.
    pub async fn poll_inference_filled_tcs(
        &self,
        note: &Address,
        order_book: &Address,
        want_is_buy: bool,
        cursor: &mut MatchWatchCursor,
    ) -> Result<Vec<MatchedFill>> {
        let acct = note.with_workchain();
        let account_id = acct.strip_prefix("0:").unwrap_or(&acct).to_string();
        let want_ob = Address::parse(&order_book.with_workchain())
            .map(|a| a.with_workchain())
            .unwrap_or_else(|_| order_book.with_workchain());
        let endpoint = self.client.endpoint();
        let gql = format!("{}/graphql", endpoint.trim_end_matches('/'));
        let dapp_id = fetch_dapp_id(&self.http, endpoint, &account_id).await?;
        let query = r#"
            query($accountId: String!, $dappId: String!, $last: Int!) {
              blockchain {
                account(account_id: $accountId, dapp_id: $dappId) {
                  messages(msg_type: [ExtOut], last: $last) {
                    edges { node { body created_at } }
                  }
                }
              }
            }
        "#;
        let resp: Value = self
            .http
            .post(&gql)
            .json(&json!({
                "query": query,
                "variables": { "accountId": account_id, "dappId": dapp_id, "last": 200 },
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let edges = resp["data"]["blockchain"]["account"]["messages"]["edges"]
            .as_array()
            .ok_or_else(|| anyhow!("note ext-out GraphQL shape changed: {resp}"))?;
        let mut matches = Vec::<(i64, MatchedFill)>::new();
        for edge in edges {
            let node = &edge["node"];
            let created = node["created_at"]
                .as_i64()
                .or_else(|| node["created_at"].as_str().and_then(|s| s.parse().ok()));
            let Some(body) = node["body"].as_str() else {
                continue;
            };
            match super::note_events::decode_inference_filled(body) {
                Ok(Some(fill)) => {
                    if fill.is_buy != want_is_buy {
                        continue;
                    }
                    let got_ob = Address::parse(&fill.order_book)
                        .map(|a| a.with_workchain())
                        .unwrap_or(fill.order_book.clone());
                    if got_ob != want_ob {
                        continue;
                    }
                    let created_at = created.ok_or_else(|| {
                        anyhow!(
                            "InferenceFilledConfirmed ext-out on note {account_id} has no created_at cursor"
                        )
                    })?;
                    let tc = Address::parse(&fill.token_contract)
                        .map_err(|e| {
                            anyhow!(
                                "InferenceFilledConfirmed tokenContract {}: {e}",
                                fill.token_contract
                            )
                        })?
                        .with_workchain();
                    matches.push((
                        created_at,
                        MatchedFill {
                            order_id: fill.order_id,
                            token_contract: tc,
                            ticks: fill.ticks,
                            price_per_tick: fill.price_per_tick,
                        },
                    ));
                }
                Ok(None) => {}
                Err(e) => {
                    return Err(anyhow!(
                        "decode InferenceFilledConfirmed ext-out on note {account_id}: {e}"
                    ));
                }
            }
        }
        Ok(consume_new_fill_batch(cursor, matches))
    }

    pub(super) async fn seller_offer_events_since(
        &self,
        note: &Address,
        order_book: &Address,
        token_contract: &Address,
        since: u64,
    ) -> Result<SellerOfferEvents> {
        let acct = note.with_workchain();
        let account_id = acct.strip_prefix("0:").unwrap_or(&acct).to_string();
        let want_ob = order_book.with_workchain();
        let want_tc = token_contract.with_workchain();
        let endpoint = self.client.endpoint();
        let gql = format!("{}/graphql", endpoint.trim_end_matches('/'));
        let dapp_id = fetch_dapp_id(&self.http, endpoint, &account_id).await?;
        let query = r#"
            query($accountId: String!, $dappId: String!, $last: Int!) {
              blockchain {
                account(account_id: $accountId, dapp_id: $dappId) {
                  messages(msg_type: [ExtOut, IntIn], last: $last) {
                    edges { node { body src value created_at } }
                  }
                }
              }
            }
        "#;
        let response: Value = self
            .http
            .post(&gql)
            .json(&json!({
                "query": query,
                "variables": { "accountId": account_id, "dappId": dapp_id, "last": 200 },
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let edges = response["data"]["blockchain"]["account"]["messages"]["edges"]
            .as_array()
            .ok_or_else(|| anyhow!("seller offer outcome GraphQL shape changed: {response}"))?;
        let mut outcome = SellerOfferEvents::default();
        for edge in edges {
            let node = &edge["node"];
            let created_at = node["created_at"].as_u64().or_else(|| {
                node["created_at"]
                    .as_str()
                    .and_then(|value| value.parse().ok())
            });
            if created_at.is_none_or(|created_at| created_at < since) {
                continue;
            }
            if let Some(body) = node["body"].as_str().filter(|body| !body.is_empty()) {
                if let Some(placed) = super::note_events::decode_inference_placed(body)? {
                    if !placed.is_buy
                        && placed.order_book.eq_ignore_ascii_case(&want_ob)
                        && placed.token_contract.eq_ignore_ascii_case(&want_tc)
                    {
                        outcome.placed_order_id = Some(placed.order_id);
                    }
                }
                if let Some(fill) = super::note_events::decode_inference_filled(body)? {
                    if !fill.is_buy
                        && fill.order_book.eq_ignore_ascii_case(&want_ob)
                        && fill.token_contract.eq_ignore_ascii_case(&want_tc)
                    {
                        outcome.matched = true;
                    }
                }
            }
            let source_matches = node["src"]
                .as_str()
                .is_some_and(|source| source.eq_ignore_ascii_case(&want_ob));
            let empty_body = node["body"].as_str().is_none_or(str::is_empty);
            if source_matches && empty_body && value_u128(&node["value"]) == Some(1_000_000_000) {
                outcome.placement_value_returned = true;
            }
        }
        Ok(outcome)
    }

    /// Scan paginated fill history with order-id attribution for the inert subscription journal.
    pub async fn poll_inference_attributed_fills(
        &self,
        note: &Address,
        order_book: &Address,
        cursor: &mut MatchWatchCursor,
    ) -> Result<Vec<(u128, MatchedFill)>> {
        let acct = note.with_workchain();
        let account_id = acct.strip_prefix("0:").unwrap_or(&acct).to_string();
        let want_ob = Address::parse(&order_book.with_workchain())
            .map(|a| a.with_workchain())
            .unwrap_or_else(|_| order_book.with_workchain());
        let messages =
            fetch_all_ext_out_messages(&self.http, self.client.endpoint(), &account_id).await?;
        let mut matches = Vec::<(i64, u128, MatchedFill)>::new();
        for message in messages {
            match super::note_events::decode_attributed_inference_filled(&message.body) {
                Ok(Some(fill)) => {
                    if !fill.is_buy {
                        continue;
                    }
                    let got_ob = Address::parse(&fill.order_book)
                        .map(|a| a.with_workchain())
                        .unwrap_or(fill.order_book.clone());
                    if got_ob != want_ob {
                        continue;
                    }
                    let created_at = message.created_at.try_into().map_err(|_| {
                        anyhow!("InferenceFilledConfirmed ext-out on note {account_id} has created_at above i64")
                    })?;
                    let tc = Address::parse(&fill.token_contract)
                        .map_err(|e| {
                            anyhow!(
                                "InferenceFilledConfirmed tokenContract {}: {e}",
                                fill.token_contract
                            )
                        })?
                        .with_workchain();
                    matches.push((
                        created_at,
                        fill.order_id,
                        MatchedFill {
                            order_id: fill.order_id,
                            token_contract: tc,
                            ticks: fill.ticks,
                            price_per_tick: fill.price_per_tick,
                        },
                    ));
                }
                Ok(None) => {}
                Err(e) => {
                    return Err(anyhow!(
                        "decode InferenceFilledConfirmed ext-out on note {account_id}: {e}"
                    ));
                }
            }
        }
        matches.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.2.token_contract.cmp(&right.2.token_contract))
                .then_with(|| left.1.cmp(&right.1))
        });
        let mut out = Vec::new();
        let mut consumed = Vec::new();
        let mut unique_new = BTreeSet::new();
        for (created_at, order_id, fill) in matches {
            if cursor.has_seen(created_at, &fill.token_contract) {
                continue;
            }
            if unique_new.insert((created_at, fill.token_contract.clone(), order_id)) {
                consumed.push((created_at, fill.token_contract.clone()));
                out.push((order_id, fill));
            }
        }
        cursor.record_seen_batch(consumed);
        Ok(out)
    }

    /// Wait for THIS note's owner-facing `InferenceFilledConfirmed` ext-out
    /// and return the matched per-deal `TokenContract`. The buyer learns its deal from JUST its own note --
    /// no shared-book index. Polls the note's ext-out via the chain GraphQL (the same `messages(ExtOut)`
    /// surface the live giver diag uses), decodes each body, and returns the first fill that is this note's
    /// BUY side on the derived `order_book`, ignoring events older than `since_unix` (a note may carry a
    /// prior deal's fill). Fails closed on timeout -- never a silent empty.
    pub async fn wait_inference_filled_tc(
        &self,
        note: &Address,
        order_book: &Address,
        _since_unix: i64,
        timeout: std::time::Duration,
        cursor: &mut MatchWatchCursor,
        expected: Option<&MatchedFill>,
    ) -> Result<MatchedFill> {
        let acct = note.with_workchain();
        let account_id = acct.strip_prefix("0:").unwrap_or(&acct).to_string();
        let want_ob = Address::parse(&order_book.with_workchain())
            .map(|a| a.with_workchain())
            .unwrap_or_else(|_| order_book.with_workchain());
        let timeout_context = format!(
            "timed out waiting for InferenceFilledConfirmed on note {account_id} (no buy match \
             on book {want_ob} yet for tokenContract {} ticks {} price_per_tick {}) -- the seller's offer \
             may not be resting, or the match didn't go through",
            expected
                .map(|fill| fill.token_contract.as_str())
                .unwrap_or("<resume-any>"),
            expected.map(|fill| fill.ticks).unwrap_or(0),
            expected.map(|fill| fill.price_per_tick).unwrap_or(0)
        );
        wait_correlated_inference_fill(
            &RealInferenceFillPoller {
                chain: self,
                note,
                order_book,
            },
            cursor,
            expected,
            timeout,
            crate::params::INFERENCE_FILL_POLL_INTERVAL,
            &timeout_context,
        )
        .await
    }

    /// The book's `getStats` getter(`nextOrderId`, `orderCount`, `executedNotional`, `executedTicks`).
    pub async fn inference_orderbook_stats(&self, ob: &Address) -> Result<Option<Value>> {
        self.client
            .run_getter(ob, INFERENCE_ORDERBOOK_ABI, "getStats", json!({}))
            .await
    }

    /// Reconcile accepted subscription placements at or above a pre-POST order-id floor.
    /// A subscription is an ordinary flagged BUY order now, so the identifying terms are the order's own
    /// price and volume; there are no cycle budgets or auto-renewal to match on any more. The term is not
    /// matched either -- it is [`SUBSCRIPTION_WEEKS`] for every subscription in the protocol.
    pub async fn inference_subscription_placements_since(
        &self,
        ob: &Address,
        buyer_note: &Address,
        order_id_floor: u128,
        max_price_per_tick: u128,
        ticks: u128,
    ) -> Result<Vec<InferenceSubscriptionPlacement>> {
        let account_id = ob.bare().to_string();
        let messages =
            fetch_all_ext_out_messages(&self.http, self.client.endpoint(), &account_id).await?;
        let buyer_note = buyer_note.with_workchain();
        let mut placements = Vec::new();
        for message in messages {
            let Some(mut placement) =
                super::order_events::decode_subscription_placement(&message.body)?
            else {
                continue;
            };
            let owner = Address::parse(&placement.buyer_note)
                .map_err(|error| {
                    anyhow!(
                        "InferenceSubscriptionPlaced buyerNote {}: {error}",
                        placement.buyer_note
                    )
                })?
                .with_workchain();
            if placement.order_id < order_id_floor {
                continue;
            }
            placement.buyer_note = owner;
            placement.created_at = message.created_at.try_into().map_err(|_| {
                anyhow!(
                    "InferenceSubscriptionPlaced order #{} created_at exceeds i64",
                    placement.order_id
                )
            })?;
            placements.push(placement);
        }
        coalesce_correlated_subscription_placements(
            placements,
            &buyer_note,
            max_price_per_tick,
            ticks,
        )
    }

    /// The book's `getWeeklyMedianPrice` getter. `None` means the book is inactive; a live active
    /// book with no matched volume returns the contract's `ERR_NO_LIQUIDITY` through the TVM getter error.
    pub async fn inference_orderbook_weekly_median_price(
        &self,
        ob: &Address,
    ) -> Result<Option<u128>> {
        let Some(v) = self
            .client
            .run_getter(
                ob,
                INFERENCE_ORDERBOOK_ABI,
                "getWeeklyMedianPrice",
                json!({}),
            )
            .await?
        else {
            return Ok(None);
        };
        let raw = v
            .get("price")
            .or_else(|| v.get("value0"))
            .ok_or_else(|| anyhow!("getWeeklyMedianPrice returned unexpected shape: {v:?}"))?;
        value_u128(raw)
            .ok_or_else(|| anyhow!("getWeeklyMedianPrice returned non-u128 price: {v:?}"))
            .map(Some)
    }

    /// The book's `getOrder(id)` getter -- resolves a specific order/offer(note, `tokenContract`, price...).
    pub async fn inference_orderbook_order(&self, ob: &Address, id: u128) -> Result<Option<Value>> {
        self.client
            .run_getter(
                ob,
                INFERENCE_ORDERBOOK_ABI,
                "getOrder",
                json!({ "id": id.to_string() }),
            )
            .await
    }

    pub async fn inference_buyer_order_is_active_for_owner(
        &self,
        ob: &Address,
        order_id: u128,
        owner_note: &str,
    ) -> Result<bool> {
        let Some(order) = self.inference_orderbook_order(ob, order_id).await? else {
            return Err(anyhow!(
                "getOrder({order_id}) returned no fixed-id row; only an explicit all-zero \
                 tombstone proves that the expected subscription order is absent"
            ));
        };
        subscription_order_is_active_for_owner(order_id, &order, owner_note)
    }

    /// The deal's `getSubscription()` getter on the `TokenContract`.
    /// A subscription is no longer a book-side primitive with cycles and auto-renewal: the book matches a
    /// flagged AON buy order and the resulting deal carries the whole term. So the authoritative
    /// subscription state lives on the per-deal TC, and `sub_weeks == 0` simply means an ordinary deal.
    pub async fn token_contract_subscription(
        &self,
        tc: &Address,
    ) -> Result<Option<DealSubscription>> {
        let Some(v) = self
            .client
            .run_getter(tc, TOKENCONTRACT_ABI, "getSubscription", json!({}))
            .await?
        else {
            return Ok(None);
        };
        DealSubscription::decode_getter(&v)
            .map(Some)
            .map_err(|reason| anyhow!("TokenContract {tc}: {reason}"))
    }

    /// Permissionlessly clear an order whose deadline has passed, refunding its escrow.
    /// SELL deadlines are contract-mandatory; BUY deadline 0/GTC is contract-permitted, while the dexdo CLI
    /// deliberately enforces a finite BUY deadline. Lazy expiry-on-match cannot reach an order that never
    /// crosses, so a stale order at an untouched price level needs this external sweep to leave the book at
    /// all. The deployed book owns the time and refund semantics; the caller supplies only the order id and
    /// is not paid for the work.
    pub async fn expire_inference_order(&self, ob: &Address, order_id: u128) -> Result<Value> {
        self.submit(
            ob,
            INFERENCE_ORDERBOOK_ABI,
            "expireOrder",
            json!({ "orderId": order_id.to_string() }),
            &KeyPair::generate(),
        )
        .await
    }

    /// The seller submits exactly one owner-signed external call to the note:
    /// `postSellOffer(flags, nonce, ttl)`. In 4.0.26 the note derives the canonical per-deal
    /// `TokenContract`, and the TC supplies its constructor-bound model, price, maximum ticks,
    /// and seller note when it posts the ask internally. `flags=0` is a plain resting limit.
    /// `ttl` is the offer's lifetime in SECONDS and is MANDATORY: a sell offer
    /// commits no collateral at post time, so it must auto-expire. The note rejects `ttl == 0`
    /// (no GTC asks) and `ttl > MAX_SELL_TTL`(1 hour) with `ERR_SELL_DEADLINE_TOO_LONG`, then
    /// converts it to an absolute deadline anchored at the seller's call -- so time spent reaching
    /// the book counts against the offer's life rather than extending it.
    pub async fn post_sell_offer(
        &self,
        note: &Address,
        owner_keys: &KeyPair,
        flags: u8,
        nonce: u64,
        ttl: u64,
    ) -> Result<Value> {
        self.submit(
            note,
            PRIVATENOTE_ABI,
            "postSellOffer",
            json!({
                "flags": flags,
                "nonce": nonce.to_string(),
                "ttl": ttl.to_string(),
            }),
            owner_keys,
        )
        .await
    }

    /// The buyer(note) places a limit buy for inference -- `placeInferenceBuy(modelHash,
    /// maxPricePerTick, ticks, escrow, flags, deadline)`(signed with the note's owner key). The
    /// escrow is ECC SHELL(currency 2): the note moves `escrow` from its ECC balance into the book.
    /// If `maxPricePerTick` >= the resting ask -- a match happens immediately (the book calls
    /// `fundFromOrderBook` on the TC).
    /// `deadline` is an absolute unix timestamp. The contract permits zero as GTC, but the dexdo CLI applies
    /// a stricter policy and always submits a finite future deadline. Past it the order is expirable by anyone
    /// (`expire_inference_order`), which refunds the escrow.
    /// `flags::SUBSCRIPTION` selects the fixed four-week take-or-pay term. The book also requires
    /// `flags::AON` plus a volume divisible by that term -- a subscription must come whole from a single
    /// seller, since a half-filled reservation reserves nothing.
    #[allow(clippy::too_many_arguments)]
    pub async fn place_inference_buy(
        &self,
        note: &Address,
        owner_keys: &KeyPair,
        model_hash: &str,
        max_price_per_tick: u128,
        ticks: u128,
        escrow: u128,
        flags: u8,
        deadline: u64,
    ) -> Result<Value> {
        self.submit(
            note,
            PRIVATENOTE_ABI,
            "placeInferenceBuy",
            place_inference_buy_payload(
                model_hash,
                max_price_per_tick,
                ticks,
                escrow,
                flags,
                deadline,
            ),
            owner_keys,
        )
        .await
    }

    /// Prepare the exact signed buy BOC and route, prime the owner-fill cursor, persist its
    /// identity through `before_post`, then use the existing no-redirect money client once.
    #[allow(clippy::too_many_arguments)]
    pub async fn place_inference_buy_with_submit_identity(
        &self,
        note: &Address,
        owner_keys: &KeyPair,
        order_book: &Address,
        model_hash: &str,
        max_price_per_tick: u128,
        ticks: u128,
        escrow: u128,
        flags: u8,
        deadline: u64,
        cursor: &mut MatchWatchCursor,
        before_post: &mut (dyn FnMut(String, MatchWatchCursor, u128) -> Result<()> + Send),
    ) -> Result<Value> {
        let (endpoint, boc, account_id, dapp_id) = self
            .prepare_money_post(
                note,
                PRIVATENOTE_ABI,
                "placeInferenceBuy",
                place_inference_buy_payload(
                    model_hash,
                    max_price_per_tick,
                    ticks,
                    escrow,
                    flags,
                    deadline,
                ),
                owner_keys,
            )
            .await?;
        let mut final_cursor = MatchWatchCursor::new(0);
        self.poll_inference_filled_tcs(note, order_book, true, &mut final_cursor)
            .await
            .map_err(|source| anyhow::Error::new(MoneySubmitError::Preparation { source }))?;
        *cursor = final_cursor;
        let account = self
            .client
            .get_account(note)
            .await
            .map_err(|source| anyhow::Error::new(MoneySubmitError::Preparation { source }))?;
        note_balance_private_note_account(note, account.as_ref())
            .map_err(|source| anyhow::Error::new(MoneySubmitError::Preparation { source }))?;
        let note_shell_balance = account
            .expect("validated PrivateNote account must be present")
            .ecc_balance(2);
        before_post(
            money_submit_identity(&boc),
            cursor.clone(),
            note_shell_balance,
        )
        .map_err(|source| anyhow::Error::new(MoneySubmitError::Preparation { source }))?;
        send_message_routed_money_once(
            &self.money_post_http,
            &endpoint,
            &boc,
            &account_id,
            &dapp_id,
        )
        .await
    }

    /// Prepare one BUY money message, anchor its placement/fill cursors,
    /// persist its identity through `before_post`, then POST exactly once.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub async fn place_inference_buy_with_identity_and_cursors(
        &self,
        note: &Address,
        owner_keys: &KeyPair,
        order_book: &Address,
        model_hash: &str,
        max_price_per_tick: u128,
        ticks: u128,
        escrow: u128,
        flags: u8,
        deadline: u64,
        fill_cursor: &mut MatchWatchCursor,
        before_post: &mut (dyn FnMut(String, u128, MatchWatchCursor, Vec<(u128, MatchedFill)>) -> Result<()>
                  + Send),
    ) -> Result<Value> {
        if flags & crate::chain::flags::SUBSCRIPTION != 0 {
            check_subscription_buy_reserve(escrow, ticks, max_price_per_tick)
                .map_err(|error| anyhow!("subscription money preflight: {error}"))?;
            let weeks = u128::from(SUBSCRIPTION_WEEKS);
            if ticks == 0 || !ticks.is_multiple_of(weeks) {
                return Err(anyhow!(
                    "subscription volume {ticks} ticks must be a non-zero multiple of \
                     {SUBSCRIPTION_WEEKS} weeks -- pick e.g. {} or {} ticks",
                    ticks.next_multiple_of(weeks).max(weeks),
                    (ticks / weeks).max(1) * weeks,
                ));
            }
        }
        let (endpoint, boc, account_id, dapp_id) = self
            .prepare_money_post(
                note,
                PRIVATENOTE_ABI,
                "placeInferenceBuy",
                place_inference_buy_payload(
                    model_hash,
                    max_price_per_tick,
                    ticks,
                    escrow,
                    flags,
                    deadline,
                ),
                owner_keys,
            )
            .await?;
        let stats = self
            .inference_orderbook_stats(order_book)
            .await
            .map_err(|source| anyhow::Error::new(MoneySubmitError::Preparation { source }))?
            .ok_or_else(|| {
                anyhow::Error::new(MoneySubmitError::Preparation {
                    source: anyhow!(
                        "InferenceOrderBook {} is not active before subscription POST",
                        order_book.with_workchain()
                    ),
                })
            })?;
        let order_id_floor = stats
            .get("nextOrderId")
            .and_then(value_u128)
            .ok_or_else(|| {
                anyhow::Error::new(MoneySubmitError::Preparation {
                    source: anyhow!("getStats returned no valid nextOrderId: {stats}"),
                })
            })?;
        let pre_post_fills = self
            .poll_inference_attributed_fills(note, order_book, fill_cursor)
            .await
            .map_err(|source| anyhow::Error::new(MoneySubmitError::Preparation { source }))?;
        before_post(
            money_submit_identity(&boc),
            order_id_floor,
            fill_cursor.clone(),
            pre_post_fills,
        )
        .map_err(|source| anyhow::Error::new(MoneySubmitError::Preparation { source }))?;
        send_message_routed_money_once(
            &self.money_post_http,
            &endpoint,
            &boc,
            &account_id,
            &dapp_id,
        )
        .await
    }

    /// Cancel one resting inference order owned by `note` through `PrivateNote.cancelInferenceOrder`.
    pub async fn cancel_inference_order(
        &self,
        note: &Address,
        owner_keys: &KeyPair,
        model_hash: &str,
        order_id: u128,
    ) -> Result<Value> {
        self.submit(
            note,
            PRIVATENOTE_ABI,
            "cancelInferenceOrder",
            json!({
                "modelHash": model_hash,
                "orderId": order_id.to_string(),
            }),
            owner_keys,
        )
        .await
    }

    /// Cancel all resting inference orders owned by `note` for one model through the note owner method.
    pub async fn cancel_all_inference_orders(
        &self,
        note: &Address,
        owner_keys: &KeyPair,
        model_hash: &str,
    ) -> Result<Value> {
        self.submit(
            note,
            PRIVATENOTE_ABI,
            "cancelAllInferenceOrders",
            json!({ "modelHash": model_hash }),
            owner_keys,
        )
        .await
    }

    /// The raw `getState` getter of the `TokenContract`. Production lifecycle consumers must use
    /// [`Self::token_contract_deal_state`] so malformed or incomplete ABI output cannot silently become
    /// an ordinary zero-valued deal.
    pub async fn token_contract_state(&self, tc: &Address) -> Result<Option<Value>> {
        self.client
            .run_getter(tc, TOKENCONTRACT_ABI, "getState", json!({}))
            .await
    }

    /// Strict typed `getState` read.
    pub async fn token_contract_deal_state(&self, tc: &Address) -> Result<Option<DealChainState>> {
        let Some(value) = self.token_contract_state(tc).await? else {
            return Ok(None);
        };
        DealChainState::decode_getter(&value)
            .map(Some)
            .map_err(|reason| anyhow!("TokenContract {tc}: {reason}"))
    }

    /// The raw `getSellerBond` getter of the deal. Production lifecycle consumers must use
    /// [`Self::token_contract_deal_seller_bond`].
    pub async fn token_contract_seller_bond(&self, tc: &Address) -> Result<Option<Value>> {
        self.client
            .run_getter(tc, TOKENCONTRACT_ABI, "getSellerBond", json!({}))
            .await
    }

    /// Strict typed `getSellerBond` read.
    pub async fn token_contract_deal_seller_bond(
        &self,
        tc: &Address,
    ) -> Result<Option<DealSellerBond>> {
        let Some(value) = self.token_contract_seller_bond(tc).await? else {
            return Ok(None);
        };
        DealSellerBond::decode_getter(&value)
            .map(Some)
            .map_err(|reason| anyhow!("TokenContract {tc}: {reason}"))
    }

    /// The raw `getBuyerBond` getter of the deal. Production accounting consumers must use
    /// [`Self::token_contract_deal_buyer_bond`].
    pub async fn token_contract_buyer_bond(&self, tc: &Address) -> Result<Option<Value>> {
        self.client
            .run_getter(tc, TOKENCONTRACT_ABI, "getBuyerBond", json!({}))
            .await
    }

    /// Strict typed `getBuyerBond` read.
    pub async fn token_contract_deal_buyer_bond(
        &self,
        tc: &Address,
    ) -> Result<Option<DealBuyerBond>> {
        let Some(value) = self.token_contract_buyer_bond(tc).await? else {
            return Ok(None);
        };
        DealBuyerBond::decode_getter(&value)
            .map(Some)
            .map_err(|reason| anyhow!("TokenContract {tc}: {reason}"))
    }

    /// Read one coherent strict accounting/lifecycle snapshot.
    /// Each bounded attempt reads one complete four-getter set bracketed by the
    /// account BOC identity. A mutation or destroy between any getters rejects
    /// that attempt; only a new bracketed attempt may be retried, and missing
    /// fields are never filled with defaults.
    pub async fn token_contract_deal_snapshot(
        &self,
        tc: &Address,
    ) -> Result<Option<DealChainSnapshot>> {
        let mut source = LiveDealSnapshotSource {
            chain: self,
            token_contract: tc,
        };
        read_coherent_deal_snapshot(&mut source)
            .await
            .map_err(|error| anyhow!("TokenContract {tc}: {error}"))
    }
    /// The `getConfig` getter of the deal(`TokenContract`, 4.0.31 `view`):
    /// `platformFeeBps`, `minClaimInterval`, `minSecondsPerTick`, and `disputeWindow`.
    /// The seller claim driver reads the two claim cadence bounds per deal; the fixed probe and claim
    /// promotion windows are not returned here. `None` if the TC is not active.
    pub async fn token_contract_config(&self, tc: &Address) -> Result<Option<Value>> {
        self.client
            .run_getter(tc, TOKENCONTRACT_ABI, "getConfig", json!({}))
            .await
    }

    /// Read-only `PrivateNote.getDetails()`: public balance/lock maps and metadata, no key and no signed call.
    pub async fn private_note_details(&self, note: &Address) -> Result<Option<Value>> {
        self.client
            .run_getter(note, PRIVATENOTE_ABI, "getDetails", json!({}))
            .await
    }

    /// Read every successful owner-signed `placeInferenceBuy` receipt for one note. This is intended
    /// for live by-fact verification: it counts destination transactions, not CLI log events. The
    /// shellnet indexer can omit `body` for external-in messages, so decode the authoritative full
    /// message BOC when that projection is absent.
    #[cfg(feature = "test-giver")]
    pub async fn successful_place_inference_buy_receipts(
        &self,
        note: &Address,
    ) -> Result<Vec<PlaceInferenceBuyReceipt>> {
        const PAGE_SIZE: u32 = 1_000;
        let account_id = note.bare().to_string();
        let endpoint = self.client.endpoint().trim_end_matches('/');
        let dapp_id = fetch_dapp_id(&self.http, endpoint, &account_id).await?;
        let gql = format!("{endpoint}/graphql");
        let query = r#"
            query($accountId: String!, $dappId: String!, $last: Int!, $before: String) {
              blockchain {
                account(account_id: $accountId, dapp_id: $dappId) {
                  messages(msg_type: [ExtIn], last: $last, before: $before) {
                    pageInfo { startCursor hasPreviousPage }
                    edges {
                      cursor
                      node {
                        id boc body created_at
                        dst_transaction {
                          aborted
                          compute { exit_code success }
                          action { result_code success }
                        }
                      }
                    }
                  }
                }
              }
            }
        "#;
        let mut before: Option<String> = None;
        let mut seen = BTreeSet::new();
        let mut receipts = Vec::new();
        loop {
            let response: Value = self
                .http
                .post(&gql)
                .json(&json!({
                    "query": query,
                    "variables": {
                        "accountId": account_id.as_str(),
                        "dappId": dapp_id.as_str(),
                        "last": PAGE_SIZE,
                        "before": before.as_deref(),
                    },
                }))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if let Some(errors) = response.get("errors") {
                return Err(anyhow!(
                    "PrivateNote {note} owner-call GraphQL errors: {errors}"
                ));
            }
            let messages = response
                .pointer("/data/blockchain/account/messages")
                .ok_or_else(|| {
                    anyhow!("PrivateNote {note} owner-call GraphQL shape changed: {response}")
                })?;
            let edges = messages["edges"].as_array().ok_or_else(|| {
                anyhow!("PrivateNote {note} owner-call GraphQL edges missing: {response}")
            })?;
            for edge in edges {
                let cursor = edge["cursor"]
                    .as_str()
                    .ok_or_else(|| anyhow!("PrivateNote {note} owner call has no cursor"))?;
                let node = &edge["node"];
                let message_id = node["id"].as_str().unwrap_or(cursor);
                if !seen.insert(message_id.to_string()) || !successful_inbound_call(node) {
                    continue;
                }
                let decoded = node["body"]
                    .as_str()
                    .and_then(|body| decode_external_abi_message(body, PRIVATENOTE_ABI, true))
                    .or_else(|| {
                        node["boc"].as_str().and_then(|boc| {
                            decode_external_abi_message_boc(boc, PRIVATENOTE_ABI, true)
                        })
                    });
                let Some(decoded) = decoded else {
                    continue;
                };
                if decoded.function_name != "placeInferenceBuy" {
                    continue;
                }
                let created_at = node["created_at"]
                    .as_u64()
                    .or_else(|| {
                        node["created_at"]
                            .as_str()
                            .and_then(|value| value.parse().ok())
                    })
                    .ok_or_else(|| {
                        anyhow!("successful PrivateNote placeInferenceBuy has no created_at")
                    })?;
                receipts.push(PlaceInferenceBuyReceipt {
                    message_id: message_id.to_string(),
                    created_at,
                    max_price_per_tick: decoded_u128(&decoded.tokens, "maxPricePerTick")
                        .ok_or_else(|| {
                            anyhow!("placeInferenceBuy receipt has no maxPricePerTick")
                        })?,
                    ticks: decoded_u128(&decoded.tokens, "ticks")
                        .ok_or_else(|| anyhow!("placeInferenceBuy receipt has no ticks"))?,
                    escrow: decoded_u128(&decoded.tokens, "escrow")
                        .ok_or_else(|| anyhow!("placeInferenceBuy receipt has no escrow"))?,
                });
            }
            let Some(next) = previous_page_cursor(
                &format!("PrivateNote {note} owner-call"),
                messages,
                before.as_deref(),
            )?
            else {
                break;
            };
            before = Some(next);
        }
        receipts.sort_by(|left, right| {
            (left.created_at, &left.message_id).cmp(&(right.created_at, &right.message_id))
        });
        Ok(receipts)
    }

    /// Read ordered lifecycle receipts for one deal. `StreamStopped` proves the clean
    /// post-probe-accept split; `ProbeBurned` proves the mutually exclusive probe-burn path.
    pub async fn token_contract_settlement_receipts(
        &self,
        token_contract: &Address,
    ) -> Result<TokenContractSettlementReceipts> {
        let account_id = token_contract.bare().to_string();
        // A TokenContract is its own dapp. Its immutable ext-out history remains queryable after
        // terminal withdrawal destroys the account and `/v2/account` starts returning 404.
        let dapp_id = match fetch_dapp_id(&self.http, self.client.endpoint(), &account_id).await {
            Ok(dapp_id) => dapp_id,
            Err(error) if is_uninit_account_404(&error.to_string()) => account_id.clone(),
            Err(error) => return Err(error),
        };
        let messages = fetch_all_ext_out_messages_routed(
            &self.http,
            self.client.endpoint(),
            &account_id,
            &dapp_id,
        )
        .await?;
        decode_token_contract_settlement_receipts(messages)
    }

    async fn reject_prior_settlement_action_before_prepare(
        &self,
        token_contract: &Address,
        action: SettlementAction,
        buyer_actor: Option<&Address>,
    ) -> Result<()> {
        let confirmation_timeout = SellerLivenessParams::canonical().cancel_confirmation_timeout;
        let receipts = tokio::time::timeout(
            confirmation_timeout,
            self.token_contract_settlement_receipts(token_contract),
        )
        .await
        .map_err(|_| {
            anyhow!(
                "TokenContract {token_contract} pre-prepare event snapshot exceeded the existing \
                 canonical confirmation/read timeout"
            )
        })??;
        let buyer_actor = buyer_actor.map(Address::with_workchain);
        reject_prior_settlement_action(
            &token_contract.with_workchain(),
            action,
            buyer_actor.as_deref(),
            &receipts,
        )
    }

    async fn submit_settlement_action_once(
        &self,
        token_contract: &Address,
        action: SettlementAction,
        expected: ExpectedSettlementEvent,
        buyer_actor: Option<&Address>,
        prepared: (String, String, String, String),
    ) -> Result<SettlementActionReceipt> {
        let mut unconditional = || true;
        self.submit_settlement_action_once_if(
            token_contract,
            action,
            expected,
            buyer_actor,
            prepared,
            &mut unconditional,
        )
        .await?
        .ok_or_else(|| anyhow!("unconditional settlement action was unexpectedly cancelled"))
    }

    async fn submit_settlement_action_once_if(
        &self,
        token_contract: &Address,
        action: SettlementAction,
        expected: ExpectedSettlementEvent,
        buyer_actor: Option<&Address>,
        prepared: (String, String, String, String),
        before_post: &mut (dyn FnMut() -> bool + Send),
    ) -> Result<Option<SettlementActionReceipt>> {
        let timing = SellerLivenessParams::canonical();
        let confirmation_timeout = timing.cancel_confirmation_timeout;
        let confirmation_poll = timing.cancel_confirmation_poll;
        let before = tokio::time::timeout(
            confirmation_timeout,
            self.token_contract_settlement_receipts(token_contract),
        )
        .await
        .map_err(|_| {
            anyhow!(
                "TokenContract {token_contract} pre-submit event snapshot exceeded the existing \
                 canonical confirmation/read timeout"
            )
        })??;
        let buyer_actor_string = buyer_actor.map(Address::with_workchain);
        reject_prior_settlement_action(
            &token_contract.with_workchain(),
            action,
            buyer_actor_string.as_deref(),
            &before,
        )?;
        let pre = tokio::time::timeout(
            confirmation_timeout,
            self.token_contract_deal_snapshot(token_contract),
        )
        .await
        .map_err(|_| {
            anyhow!(
                "TokenContract {token_contract} pre-submit coherent snapshot exceeded the existing \
                 canonical confirmation/read timeout"
            )
        })??;
        if action == SettlementAction::BuyerStop {
            validate_buyer_stop_pre_state(&token_contract.with_workchain(), pre.as_ref(), &before)?;
        }
        let pre = pre.ok_or_else(|| {
            anyhow!("TokenContract {token_contract} was inactive before the settlement action POST")
        })?;
        validate_settlement_facts(&token_contract.with_workchain(), &pre)?;
        let expected = expected.resolve(pre.state);
        let expected_buyer = if matches!(
            action,
            SettlementAction::BuyerStop | SettlementAction::SellerStop | SettlementAction::Dispute
        ) {
            let recorded = tokio::time::timeout(
                confirmation_timeout,
                self.token_contract_buyer_note(token_contract),
            )
            .await
            .map_err(|_| {
                anyhow!(
                    "TokenContract {token_contract} buyer-actor preflight exceeded the existing \
                     canonical confirmation/read timeout"
                )
            })??
            .ok_or_else(|| {
                anyhow!(
                    "TokenContract {token_contract} has no authoritative buyer actor in getParties; \
                     refusing settlement action before any money POST"
                )
            })?;
            if let Some(actor) = buyer_actor {
                let recorded = normalize_addr(&recorded.with_workchain())?;
                let actor = normalize_addr(&actor.with_workchain())?;
                if recorded != actor {
                    return Err(anyhow!(
                        "TokenContract {token_contract} recorded buyer actor {recorded} does not match \
                         requested buyer note {actor}; refusing settlement action before any money POST"
                    ));
                }
            }
            Some(recorded.with_workchain())
        } else {
            None
        };

        let (endpoint, boc, account_id, dapp_id) = prepared;
        if !before_post() {
            return Ok(None);
        }
        reconcile_settlement_action_after_post(
            &token_contract.with_workchain(),
            action,
            expected,
            expected_buyer.as_deref(),
            &before,
            &pre,
            confirmation_timeout,
            confirmation_poll,
            std::time::Duration::from_secs(SDK_MESSAGE_EXPIRY_SECS),
            || async {
                let submitted = if action == SettlementAction::BuyerStop {
                    send_explicit_stop_money_once(
                        &self.money_post_http,
                        &endpoint,
                        &boc,
                        &account_id,
                        &dapp_id,
                    )
                    .await
                } else {
                    send_message_routed_money_once(
                        &self.money_post_http,
                        &endpoint,
                        &boc,
                        &account_id,
                        &dapp_id,
                    )
                    .await
                };
                submitted.map(|_| ())
            },
            || self.token_contract_settlement_receipts(token_contract),
            || self.token_contract_deal_snapshot(token_contract),
        )
        .await
        .map(Some)
    }

    /// Read-only buyer preflight for the final-withdrawal latch. A withdrawn PrivateNote cannot call
    /// `placeInferenceBuy`; detect that state before any money write and return the actionable chain
    /// refusal instead of the raw exit code. Read errors are retried because a transient getter failure
    /// is not evidence that the note withdrew. Older contract generations without `hasWithdrawn` remain
    /// usable: the guard records that it could not inspect the latch and fails open.
    pub async fn assert_note_can_place_inference_buy(&self, note: &Address) -> Result<()> {
        let mut delay = crate::params::BUYER_NOTE_PREFLIGHT_INITIAL_BACKOFF;
        let mut details = None;
        for attempt in 1..=crate::params::BUYER_NOTE_PREFLIGHT_MAX_ATTEMPTS {
            match self.private_note_details(note).await {
                Ok(value) => {
                    details = Some(value);
                    break;
                }
                Err(error) if attempt < crate::params::BUYER_NOTE_PREFLIGHT_MAX_ATTEMPTS => {
                    eprintln!(
                        "buyer place preflight getDetails read failed (attempt {attempt}/{}): \
                         {error}; retrying after {delay:?}",
                        crate::params::BUYER_NOTE_PREFLIGHT_MAX_ATTEMPTS
                    );
                    tokio::time::sleep(delay).await;
                    delay *= crate::params::BUYER_NOTE_PREFLIGHT_BACKOFF_MULTIPLIER;
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "buyer place preflight could not read PrivateNote.getDetails for note {note} \
                             after {} attempts",
                            crate::params::BUYER_NOTE_PREFLIGHT_MAX_ATTEMPTS
                        )
                    });
                }
            }
        }
        let details =
            details.expect("buyer note details retry loop must return or record a result");
        buyer_note_withdrawn_guard(note, details.as_ref())
    }

    /// read-only seller preflight for the contract's final-withdrawal latch. `withdrawTokens` sets
    /// `_hasWithdrawn=true`; after that `PrivateNote.postSellOffer` is permanently blocked by
    /// `ERR_INVALID_STATE` 151. Keep that semantics and fail before any seller write.
    pub async fn assert_note_can_post_sell_offer(&self, note: &Address) -> Result<()> {
        let details = self.private_note_details(note).await?.ok_or_else(|| {
            anyhow!(
                "seller post_offer aborted: note {note} returned no PrivateNote.getDetails; cannot read \
                 hasWithdrawn before postSellOffer. Re-mint/deploy a fresh note against the current contracts."
            )
        })?;
        let withdrawn = details_has_withdrawn(&details).ok_or_else(|| {
            anyhow!(
                "seller post_offer aborted: PrivateNote.getDetails for note {note} has no hasWithdrawn field; \
                 refusing to submit postSellOffer without proving the note is not withdrawn"
            )
        })?;
        if withdrawn {
            return Err(anyhow!(note_withdrawn_sell_offer_message(note)));
        }
        Ok(())
    }

    /// Directive -- the note pre-funds its own RootModel + TC **uninit deploy addresses** from its ECC[2],
    /// via the `PrivateNote` owner-method `fundDeployShell(nonce, rootModelShell, tcShell)`(4.0.7). The note
    /// derives both targets internally from `(ephemeralPubkey, nonce)`, so no caller-supplied address -- this
    /// replaces the operator multisig's [`fund_deploy_from_wallet_ecc`](Self::fund_deploy_from_wallet_ecc) on the
    /// operate path. The RootModel/TC *deploys* stay external seller-signed; this call only pre-funds. The call is
    /// an external owner-signed message to the note, exactly like [`deploy_inference_orderbook`](Self::deploy_inference_orderbook).
    pub async fn note_fund_deploy_shell(
        &self,
        note: &Address,
        owner_keys: &KeyPair,
        nonce: u64,
        root_model_shell: u128,
        tc_shell: u128,
    ) -> Result<Value> {
        let boc = Self::encode_signed_call_boc(
            note,
            PRIVATENOTE_ABI,
            "fundDeployShell",
            json!({
                "nonce": nonce.to_string(),
                "rootModelShell": root_model_shell.to_string(),
                "tcShell": tc_shell.to_string(),
            }),
            owner_keys,
        )
        .await?;
        let message_hash = external_message_hash(&boc)?;
        let endpoint = self.client.endpoint();
        let account_id = dest_account_id_hex(&boc)?;
        let dapp_id = fetch_dapp_id(&self.http, endpoint, &account_id).await?;
        match self.send_with_retry(&boc).await {
            Ok(value) => Ok(value),
            Err(error) => {
                let aborted = error
                    .downcast_ref::<OnchainSubmitError>()
                    .and_then(|submit| submit.sanitized_payload().pointer("/result/aborted"))
                    .and_then(Value::as_bool)
                    == Some(true);
                if !aborted {
                    return Err(error);
                }
                let receipt = match poll_finalized_destination_receipt(
                    &self.http,
                    endpoint,
                    &account_id,
                    &dapp_id,
                    &message_hash,
                )
                .await
                {
                    Ok(receipt) => receipt,
                    Err(receipt_error) => {
                        return Err(error.context(format!(
                            "fundDeployShell aborted; failed to resolve finalized destination receipt \
                             for message_hash={message_hash}: {receipt_error}; ECC[2] cause not proven"
                        )));
                    }
                };
                Err(fund_deploy_shell_receipt_error(
                    error,
                    &message_hash,
                    receipt.as_ref(),
                ))
            }
        }
    }

    pub(super) async fn active_native_balance(&self, addr: &Address) -> Result<u128> {
        let account = self
            .client
            .get_account(addr)
            .await?
            .ok_or_else(|| anyhow!("contract {addr} is missing; cannot gas-health check"))?;
        if !account.is_active() {
            return Err(anyhow!(
                "contract {addr} is {}, not Active; cannot gas-health check",
                account.status
            ));
        }
        Ok(account.balance)
    }

    async fn wait_native_balance_at_least(&self, addr: &Address, min: u128) -> Result<()> {
        for _ in 0..crate::params::GAS_BALANCE_CONFIRM_MAX_READS {
            if self.active_native_balance(addr).await? > min {
                return Ok(());
            }
            tokio::time::sleep(crate::params::GAS_BALANCE_CONFIRM_POLL_INTERVAL).await;
        }
        let balance = self.active_native_balance(addr).await?;
        Err(anyhow!(
            "contract {addr} native balance {balance} did not rise above gas-health floor {min}"
        ))
    }

    async fn account_snapshot(&self, addr: &Address) -> String {
        match self.client.get_account(addr).await {
            Ok(Some(a)) => format!(
                "status={} native={} ecc2={} code_hash={}",
                a.status,
                a.balance,
                a.ecc_balance(2),
                a.code_hash.as_deref().unwrap_or("<none>")
            ),
            Ok(None) => "not found".to_string(),
            Err(e) => format!("query error: {e}"),
        }
    }

    async fn log_deploy_prefund_snapshot(
        &self,
        stage: &str,
        note: &Address,
        rm: &Address,
        tc: &Address,
    ) {
        eprintln!(
            "deploy-prefund {stage}: note {note} [{}]; RootModel {rm} [{}]; TokenContract {tc} [{}]",
            self.account_snapshot(note).await,
            self.account_snapshot(rm).await,
            self.account_snapshot(tc).await,
        );
    }

    /// before an active RootModel / per-deal TC write, ensure the contract still has native
    /// vmshell gas. `fundDeployShell` is seller-note-owned and derives both targets from
    /// `(seller pubkey, nonce)`, so only call this from paths that hold the seller note/key/nonce.
    pub async fn ensure_deal_contract_gas(
        &self,
        note: &Address,
        owner_keys: &KeyPair,
        nonce: u64,
        root_model: Option<&Address>,
        token_contract: Option<&Address>,
    ) -> Result<()> {
        let mut rm_top_up = 0;
        let mut tc_top_up = 0;

        if let Some(rm) = root_model {
            let balance = self.active_native_balance(rm).await?;
            rm_top_up = gas_health_top_up_amount(
                balance,
                crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL,
                crate::params::ACTIVE_CONTRACT_GAS_HEALTH_TARGET_NANOVMSHELL,
            )
            .unwrap_or(0);
        }
        if let Some(tc) = token_contract {
            let balance = self.active_native_balance(tc).await?;
            tc_top_up = gas_health_top_up_amount(
                balance,
                crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL,
                crate::params::ACTIVE_CONTRACT_GAS_HEALTH_TARGET_NANOVMSHELL,
            )
            .unwrap_or(0);
        }

        if rm_top_up == 0 && tc_top_up == 0 {
            return Ok(());
        }

        eprintln!(
            "gas-health: topping up RootModel {rm_top_up} + TokenContract {tc_top_up} native nanotokens via note fundDeployShell"
        );
        self.note_fund_deploy_shell(note, owner_keys, nonce, rm_top_up, tc_top_up)
            .await?;

        if rm_top_up > 0 {
            if let Some(rm) = root_model {
                self.wait_native_balance_at_least(
                    rm,
                    crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL,
                )
                .await?;
            }
        }
        if tc_top_up > 0 {
            if let Some(tc) = token_contract {
                self.wait_native_balance_at_least(
                    tc,
                    crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL,
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Directive -- the note posts the exact `2P` seller bond to the nonce-derived `TokenContract` from its own
    /// ECC[2], via the `PrivateNote` owner-method `postSellerBond(nonce, amount)`(4.0.7) -- replaces the
    /// operator multisig's [`fund_seller_bond`](Self::fund_seller_bond). External owner-signed message.
    pub async fn note_post_seller_bond(
        &self,
        note: &Address,
        owner_keys: &KeyPair,
        nonce: u64,
        amount: u128,
    ) -> Result<Value> {
        self.submit(
            note,
            PRIVATENOTE_ABI,
            "postSellerBond",
            json!({
                "nonce": nonce.to_string(),
                "amount": amount.to_string(),
            }),
            owner_keys,
        )
        .await
    }

    /// The seller opens a stream session: `open(endpointCipher)`(external signature `_sellerPubkey`).
    /// Freezes a probe tick from the deposit
    /// and writes the endpoint cipher -- handover(`RealNote::encrypt_to` to the buyer's x25519 pubkey).
    pub async fn open_stream(
        &self,
        tc: &Address,
        seller_keys: &KeyPair,
        endpoint_cipher: &[u8],
    ) -> Result<Value> {
        self.submit(
            tc,
            TOKENCONTRACT_ABI,
            "open",
            json!({ "endpointCipher": encode_hex(endpoint_cipher) }),
            seller_keys,
        )
        .await
    }

    /// Seller-only: `acceptProbe()` on the TC. Requires `block.timestamp >= probeTime + PROBE_WINDOW` and an
    /// unaccepted probe. Credits the trial tick to the seller, takes its fee by-fact, and only then does the
    /// deal become claimable at all.
    pub async fn accept_probe(&self, tc: &Address, seller_keys: &KeyPair) -> Result<Value> {
        self.submit(tc, TOKENCONTRACT_ABI, "acceptProbe", json!({}), seller_keys)
            .await
    }

    /// The seller claims CUMULATIVE consumption: `claimTokens(cumulativeTokens)` (external signature
    /// `_sellerPubkey`).
    /// The value is an absolute running total in tokens, never a delta. The contract REJECTS rather than
    /// trims a claim that breaks any of its bounds, so the caller must pre-clamp:
    /// - not below the previous claim(cumulative, never decreasing);
    /// - not above the claim cap (`getSubscription`: whole volume for an ordinary deal, one weekly quota
    /// per started week for a subscription);
    /// - at least `minClaimInterval` since the previous claim;
    /// - within the rate bound `delta * minSecondsPerTick <= elapsed * TICK_SIZE`;
    /// - and no larger than the hard per-call `MAX_CLAIM_DELTA == TICK_SIZE`, regardless of elapsed time.
    /// Landing a claim promotes the PREVIOUS one to trusted -- nobody contested it, since an open dispute
    /// blocks this path entirely -- so the newest claim always remains contestable.
    pub async fn claim_tokens(
        &self,
        tc: &Address,
        seller_keys: &KeyPair,
        cumulative_tokens: u128,
    ) -> Result<Value> {
        self.submit(
            tc,
            TOKENCONTRACT_ABI,
            "claimTokens",
            json!({ "cumulativeTokens": cumulative_tokens.to_string() }),
            seller_keys,
        )
        .await
    }

    /// Permissionless: `finalize()` promotes the pending claims once `CLAIM_PROMOTE_WINDOW` has passed with
    /// no dispute, and settles/closes an ordinary deal whose funded volume is exhausted.
    /// This is what makes the LAST claim of a deal payable at all -- nothing supersedes it, so without the
    /// window it would stay contestable forever. Unsigned-equivalent(a throwaway key): the contract takes
    /// no caller-chosen parameters and pays the caller nothing.
    pub async fn finalize_claims(&self, tc: &Address) -> Result<Value> {
        self.submit(
            tc,
            TOKENCONTRACT_ABI,
            "finalize",
            json!({}),
            &KeyPair::generate(),
        )
        .await
    }

    /// Permissionless: `settleWeek()` credits the seller ONE crossed subscription week at the full weekly
    /// quota, take-or-pay -- independently of how much the buyer actually drew, because a subscription buys
    /// reserved availability rather than delivered volume. Idempotent per boundary; the final week closes
    /// the deal.
    pub async fn settle_week(&self, tc: &Address) -> Result<Value> {
        self.submit(
            tc,
            TOKENCONTRACT_ABI,
            "settleWeek",
            json!({}),
            &KeyPair::generate(),
        )
        .await
    }

    /// The seller abandons the deal: `sellerStop()`(external signature `_sellerPubkey`). Settles by FACT on
    /// every deal shape -- a seller who walks out mid-week has stopped reserving capacity, so take-or-pay
    /// does not apply to him and the buyer keeps the remaining escrow. He forfeits the pending tail exactly
    /// as the buyer would, so quitting never pays better than delivering.
    pub async fn seller_stop(
        &self,
        tc: &Address,
        seller_keys: &KeyPair,
    ) -> Result<SettlementActionReceipt> {
        self.reject_prior_settlement_action_before_prepare(tc, SettlementAction::SellerStop, None)
            .await?;
        let prepared = self
            .prepare_money_post(tc, TOKENCONTRACT_ABI, "sellerStop", json!({}), seller_keys)
            .await?;
        self.submit_settlement_action_once(
            tc,
            SettlementAction::SellerStop,
            ExpectedSettlementEvent::StreamStopped,
            None,
            prepared,
        )
        .await
    }

    /// the seller CLOSES a STOPped deal's `TokenContract`. `destroy(payoutAddress)` is
    /// `onlyOwnerPubkey(_sellerPubkey)`, gated `!_opened && !_disputed` (the buyer's `stop()` clears
    /// `_opened` on close), and calls `selfdestruct(payoutAddress)`(`contracts/airegistry/TokenContract.sol:651`).
    /// External call, signed by the seller owner key(matches `_sellerPubkey`).
    /// **DESTRUCTIVE / BURNS(by-fact, 4.0.7):** the held ~`MIN_BALANCE` reserve does NOT recover to `payout`
    /// when `payout` is the cross-dapp note -- the note balance does not increase(reproduced x2). The deploy
    /// *funding* crossed dapps via `fundDeployShell` flag:16(credited); the raw `selfdestruct` *return* crossing
    /// the boundary is not credited -> the reserve is **burned at destroy**. So this closes the TC; reclaiming the
    /// reserve to the note would need a `TokenContract` flag:16/dapp-credit return fix(contract-side).
    /// NOT the dex/PMP oracle lifecycle.
    pub async fn destroy_token_contract(
        &self,
        tc: &Address,
        payout: &Address,
        seller_keys: &KeyPair,
    ) -> Result<Value> {
        let seller_pubkey = self.token_contract_seller_pubkey(tc).await?;
        check_seller_pubkey(
            "destroy",
            seller_pubkey.as_deref(),
            seller_keys.public_hex(),
        )
        .map_err(anyhow::Error::msg)?;
        self.submit(
            tc,
            TOKENCONTRACT_ABI,
            "destroy",
            json!({ "payoutAddress": payout.with_workchain() }),
            seller_keys,
        )
        .await
    }

    /// The seller **concedes the dispute** through `releaseDispute()`
    /// (`onlyOwnerPubkey(_sellerPubkey)`). The exact terminal movement is reported only by the
    /// resulting `DisputeResolved(released=true)` event and strict getters. In the current
    /// subscription contract the buyer's stake and the unearned disputed-week remainder burn;
    /// no client-side amount is reconstructed.
    pub async fn release_dispute(
        &self,
        tc: &Address,
        seller_keys: &KeyPair,
    ) -> Result<SettlementActionReceipt> {
        self.reject_prior_settlement_action_before_prepare(
            tc,
            SettlementAction::ReleaseDispute,
            None,
        )
        .await?;
        let prepared = self
            .prepare_money_post(
                tc,
                TOKENCONTRACT_ABI,
                "releaseDispute",
                json!({}),
                seller_keys,
            )
            .await?;
        self.submit_settlement_action_once(
            tc,
            SettlementAction::ReleaseDispute,
            ExpectedSettlementEvent::DisputeResolved { released: true },
            None,
            prepared,
        )
        .await
    }

    /// Permissionless expiry resolution for an already-disputed deal. The caller does not choose
    /// payouts; `TokenContract.resolveDisputeTimeout()` applies the deployed settlement rules.
    pub async fn resolve_dispute_timeout(&self, tc: &Address) -> Result<SettlementActionReceipt> {
        self.reject_prior_settlement_action_before_prepare(
            tc,
            SettlementAction::ResolveDisputeTimeout,
            None,
        )
        .await?;
        let prepared = self
            .prepare_money_post(
                tc,
                TOKENCONTRACT_ABI,
                "resolveDisputeTimeout",
                json!({}),
                &KeyPair::generate(),
            )
            .await?;
        self.submit_settlement_action_once(
            tc,
            SettlementAction::ResolveDisputeTimeout,
            ExpectedSettlementEvent::DisputeResolved { released: false },
            None,
            prepared,
        )
        .await
    }

    /// Withdraw finalized seller SHELL from a closed or still-open deal balance. This moves only the
    /// already-finalized `_finalizedOwed`; it is separate from `destroy`, which closes/selfdestructs the TC.
    pub async fn withdraw_shell(
        &self,
        tc: &Address,
        amount: u128,
        recipient: &Address,
        seller_keys: &KeyPair,
    ) -> Result<Value> {
        self.submit(
            tc,
            TOKENCONTRACT_ABI,
            "withdrawShell",
            json!({
                "amount": amount.to_string(),
                "recipient": recipient.with_workchain(),
            }),
            seller_keys,
        )
        .await
    }

    /// Submit owner-signed `PrivateNote.withdrawTokens(destWalletAddr, dapp_id)` for a note's available token
    /// balances. `dapp_id` is event metadata only(surfaced in `TokensWithdrawn`, drives no logic) -- taken from
    /// the deployed manifest. Returns the submit result. Do not treat this helper as proof that every
    /// native/ECC balance is fully retired
    /// without by-fact evidence on the current deployed contract.
    pub async fn withdraw_note_tokens(
        &self,
        note: &Address,
        keys: &KeyPair,
        dest_wallet: &Address,
    ) -> Result<Value> {
        // One-shot guard: `withdrawTokens` sets `_hasWithdrawn=true` and reverts `ERR_INVALID_STATE` on a
        // re-call. Read `getDetails().hasWithdrawn` and fail
        // LOUD with a clear reason instead of the opaque `TVM_ERROR(compute phase)` the revert would produce.
        if let Some(d) = self
            .client
            .run_getter(note, PRIVATENOTE_ABI, "getDetails", json!({}))
            .await?
        {
            let already = details_has_withdrawn(&d).unwrap_or(false);
            if already {
                return Err(anyhow!(
                    "note {note} was already withdrawn -- `withdrawTokens` is one-shot per note. Re-check the \
                     note/wallet on-chain before assuming any remaining balance is withdrawable."
                ));
            }
        }
        let dapp_id = format!("0x{}", self.deployed.dapp_id.trim_start_matches("0x"));
        self.submit(
            note,
            PRIVATENOTE_ABI,
            "withdrawTokens",
            withdraw_note_tokens_payload(dest_wallet, &dapp_id),
            keys,
        )
        .await
    }

    /// The buyer stops the stream via their note: `streamStop(tokenContract)` -> `TC.stop()`
    /// (the TC checks `msg.sender == _buyer`). On the probe(before accept), buyer and seller each burn `P`,
    /// the remaining seller-bond `P` and buyer deposit return; in Streaming -- a standard split.
    pub async fn stream_stop(
        &self,
        buyer_note: &Address,
        buyer_keys: &KeyPair,
        tc: &Address,
    ) -> Result<SettlementActionReceipt> {
        self.reject_prior_settlement_action_before_prepare(
            tc,
            SettlementAction::BuyerStop,
            Some(buyer_note),
        )
        .await?;
        let prepared = self
            .prepare_money_post(
                buyer_note,
                PRIVATENOTE_ABI,
                "streamStop",
                json!({ "tokenContract": tc.with_workchain() }),
                buyer_keys,
            )
            .await?;
        self.submit_settlement_action_once(
            tc,
            SettlementAction::BuyerStop,
            ExpectedSettlementEvent::BuyerStop,
            Some(buyer_note),
            prepared,
        )
        .await
    }

    /// The buyer **opens a dispute** via their note: `streamDispute(tokenContract)` -> `TC.dispute()`
    /// (the TC checks `msg.sender == _buyer`). This produces only `StreamDisputed`: funds remain
    /// frozen and there is no terminal split to project. A later concession or timeout has its own
    /// authoritative `DisputeResolved` receipt.
    pub async fn stream_dispute(
        &self,
        buyer_note: &Address,
        buyer_keys: &KeyPair,
        tc: &Address,
    ) -> Result<SettlementActionReceipt> {
        self.reject_prior_settlement_action_before_prepare(
            tc,
            SettlementAction::Dispute,
            Some(buyer_note),
        )
        .await?;
        let prepared = self
            .prepare_money_post(
                buyer_note,
                PRIVATENOTE_ABI,
                "streamDispute",
                json!({ "tokenContract": tc.with_workchain() }),
                buyer_keys,
            )
            .await?;
        self.submit_settlement_action_once(
            tc,
            SettlementAction::Dispute,
            ExpectedSettlementEvent::StreamDisputed,
            Some(buyer_note),
            prepared,
        )
        .await
    }

    /// Prepare an automatic/inactivity-policy buyer STOP and its route before synchronously checking whether
    /// accepted output changed. A changed heartbeat cancels before the single money POST.
    /// Explicit operator/user STOP uses [`Self::stream_stop`] and remains unconditional after its normal
    /// actor/state/dispute preflight. This seam is only for a configured automatic failure policy: output
    /// resuming while its signed message is prepared cancels that stale policy decision.
    pub async fn stop_if_heartbeat(
        &self,
        buyer_note: &Address,
        buyer_keys: &KeyPair,
        tc: &Address,
        before_post: &mut (dyn FnMut() -> bool + Send),
    ) -> Result<Option<SettlementActionReceipt>> {
        self.reject_prior_settlement_action_before_prepare(
            tc,
            SettlementAction::BuyerStop,
            Some(buyer_note),
        )
        .await?;
        let prepared = self
            .prepare_money_post(
                buyer_note,
                PRIVATENOTE_ABI,
                "streamStop",
                json!({ "tokenContract": tc.with_workchain() }),
                buyer_keys,
            )
            .await?;
        self.submit_settlement_action_once_if(
            tc,
            SettlementAction::BuyerStop,
            ExpectedSettlementEvent::BuyerStop,
            Some(buyer_note),
            prepared,
            before_post,
        )
        .await
    }

    /// The buyer cleans up a funded-but-never-opened deal via their note:
    /// `streamCleanup(tokenContract)` -> `TC.cleanupUnopened()`. Requires
    /// `block.timestamp >= _fundedTime + MATCH_OPEN_TIMEOUT` and `!_opened`.
    pub async fn stream_cleanup(
        &self,
        buyer_note: &Address,
        buyer_keys: &KeyPair,
        tc: &Address,
    ) -> Result<Value> {
        self.submit(
            buyer_note,
            PRIVATENOTE_ABI,
            "streamCleanup",
            json!({ "tokenContract": tc.with_workchain() }),
            buyer_keys,
        )
        .await
    }

    /// Directive -- `RootModel` deploy on the **note-funded** path: builds the same deploy message as
    /// [`deploy_root_model_from_wallet`](Self::deploy_root_model_from_wallet) but assumes the note has already
    /// pre-funded the uninit address with ECC[2] (via [`note_fund_deploy_shell`](Self::note_fund_deploy_shell));
    /// it only sends the external seller-signed deploy and waits for `Active`. No operator wallet.
    pub async fn deploy_root_model_note_funded(&self, owner: &KeyPair) -> Result<Address> {
        let (addr, message_boc_b64) = self.root_model_deploy_msg(owner).await?;
        // The note already pre-funded the uninit address(`fundDeployShell`); just send the deploy + wait.
        // Deploy-message send -> `send_deploy_with_retry` tolerates the funded-uninit `/v2/account` 404.
        let submit_err = self.send_deploy_with_retry(&message_boc_b64).await.err();
        if self
            .wait_active(&addr, crate::params::ACCOUNT_ACTIVATION_MAX_ATTEMPTS)
            .await
        {
            if let Some(e) = submit_err {
                eprintln!(
                    "deploy {addr} became Active after submit returned an error (treating as landed): {e}"
                );
            }
            Ok(addr)
        } else if let Some(e) = submit_err {
            Err(e)
        } else {
            Err(anyhow!(
                "deploy {addr} did not activate within the allotted time (note-funded)"
            ))
        }
    }

    /// Build the per-deal `TokenContract` deploy message **and its INIT-DATA(stateInit) address** -- offline,
    /// no send (`build_deploy` + `local_context()`). The single source of the per-deal TC derivation, shared by
    /// [`token_contract_deploy_address`](Self::token_contract_deploy_address) (the getter-free idempotency
    /// address,) and [`deploy_token_contract_note_funded`](Self::deploy_token_contract_note_funded) (the
    /// actual deploy) -- so the address checked for idempotency is bit-for-bit the one the deploy creates. The
    /// address is `hash(stateInit)` over `{code, varInit {_sellerPubkey,_rootModelAddress,_nonce,_pubkey}}`;
    /// the ctor args do **not** enter the address but `build_deploy` needs them to encode the message body.
    #[allow(clippy::too_many_arguments)]
    async fn token_contract_deploy_msg(
        &self,
        seller: &KeyPair,
        root_model: &Address,
        nonce: u64,
        model_name: &str,
        price_per_tick: u128,
        max_ticks: u128,
        seller_note: &Address,
    ) -> Result<(Address, String)> {
        let ctx = local_context()?;
        let init_data = json!({
            "_sellerPubkey": format!("0x{}", seller.public_hex()),
            "_rootModelAddress": root_model.with_workchain(),
            "_nonce": nonce.to_string(),
        });
        let ctor = json!({
            "modelName": model_name,
            "modelHash": model_hash_for(model_name),
            "pricePerTick": price_per_tick.to_string(),
            "maxTicks": max_ticks.to_string(),
            "sellerNote": seller_note.with_workchain(),
        });
        let msg = build_deploy(
            &ctx,
            TOKENCONTRACT_ABI,
            TOKENCONTRACT_TVC,
            init_data,
            ctor,
            seller.public_hex(),
            seller.secret_hex(),
        )
        .await?;
        Ok((Address::parse(&msg.address)?, msg.message_boc_b64))
    }

    /// Directive -- per-deal `TokenContract` deploy on the **note-funded** path: builds the deploy message
    /// (the note pre-funded the uninit address via `fundDeployShell`) and sends it, waiting for `Active`. No
    /// wallet. Shares [`token_contract_deploy_msg`](Self::token_contract_deploy_msg) with the idempotency
    /// derivation, so the deployed address equals the pre-derived one by construction.
    #[allow(clippy::too_many_arguments)]
    pub async fn deploy_token_contract_note_funded(
        &self,
        seller: &KeyPair,
        root_model: &Address,
        nonce: u64,
        model_name: &str,
        _tick_size: u128,
        price_per_tick: u128,
        max_ticks: u128,
        seller_note: &Address,
    ) -> Result<Address> {
        let (addr, message_boc_b64) = self
            .token_contract_deploy_msg(
                seller,
                root_model,
                nonce,
                model_name,
                price_per_tick,
                max_ticks,
                seller_note,
            )
            .await?;
        // The note already pre-funded the uninit address(`fundDeployShell`); just send the deploy + wait.
        // Deploy-message send -> `send_deploy_with_retry` tolerates the funded-uninit `/v2/account` 404.
        let submit_err = self.send_deploy_with_retry(&message_boc_b64).await.err();
        if self
            .wait_active(&addr, crate::params::ACCOUNT_ACTIVATION_MAX_ATTEMPTS)
            .await
        {
            if let Some(e) = submit_err {
                eprintln!(
                    "deploy {addr} became Active after submit returned an error (treating as landed): {e}"
                );
            }
            Ok(addr)
        } else if let Some(e) = submit_err {
            Err(e)
        } else {
            Err(anyhow!(
                "deploy {addr} did not activate within the allotted time (note-funded)"
            ))
        }
    }

    /// Provision a per-deal market for the seller (issue; **note-funded,** -- NO operator wallet, NO
    /// giver in the operate path): deploy-if-absent the per-model `InferenceOrderBook`, the per-owner
    /// `RootModel`, and the per-deal `TokenContract`, **all funded from the seller note's own ECC[2]**. Returns a
    /// [`MarketManifest`] whose `token_contract` is the **active** deployed address.
    /// The per-deal `TokenContract`(and `RootModel`) is a self-dapp contract whose uninit cross-dapp deploy
    /// address cannot be funded with privileged native gas(the 404). Instead the note pre-funds each uninit
    /// deploy address with **ECC[2] SHELL** via [`note_fund_deploy_shell`](Self::note_fund_deploy_shell)
    /// (`PrivateNote.fundDeployShell`, a single `flag:16` send so the ECC lands as spendable native balance), and
    /// the external seller-signed deploy then activates it -- the permission-free mechanism, no privileged giver,
    /// no separate operational wallet(the funding source is the anonymous note itself). `gas` is the ECC[2]
    /// SHELL pre-funded per uninit deploy address.
    #[allow(clippy::too_many_arguments)]
    pub async fn provision_market(
        &self,
        seed_keys: &KeyPair,
        note: &Address,
        frame_model: &str,
        nonce: u64,
        price_per_tick: u128,
        max_ticks: u128,
        gas: u128,
    ) -> Result<crate::MarketManifest> {
        // fail-closed up front if the seller note is orphaned by a contract redeploy -- a clear
        // "re-mint" error instead of a downstream bare TVM_ERROR(stale note) or "note is not active".
        self.assert_seller_note_current(note).await?;
        // 1) Per-model InferenceOrderBook -- note-funded(owner-method). Deploy-if-absent.
        let model_hash = model_hash_for(frame_model);
        let ob = self
            .inference_orderbook_address(note, &model_hash, TICK_SIZE)
            .await?;
        if !self
            .wait_active(&ob, crate::params::ACCOUNT_ACTIVE_SINGLE_CHECK_ATTEMPTS)
            .await
        {
            self.deploy_inference_orderbook(note, seed_keys, &model_hash, frame_model, TICK_SIZE)
                .await?;
            if !self
                .wait_active(&ob, crate::params::ACCOUNT_ACTIVATION_MAX_ATTEMPTS)
                .await
            {
                return Err(anyhow!("InferenceOrderBook {ob} did not activate"));
            }
        }
        // 2) RootModel + per-deal TokenContract -- NOTE-FUNDED: no operator multisig. The note pre-funds
        // each uninit deploy address from its own ECC[2] (`fundDeployShell`, the note derives the targets from
        // `(ephemeralPubkey, nonce)`), then the external seller-signed deploy activates it. ORDER MATTERS: the
        // RootModel is deployed first so the per-deal TC registers into it in its ctor; the TC address itself is
        // derived **locally from the deploy INIT-DATA**, NOT by querying
        // the RootModel `getTokenContractAddress` getter -- so neither a fixed-superroot shellnet restart nor
        // a not-yet-`Active` RootModel can 404 the idempotency check. The getter is used only as a post-`Active`
        // cross-check below.
        let seller_pubkey = json!(format!("0x{}", seed_keys.public_hex()));
        let (rm, _) = self.root_model_deploy_msg(seed_keys).await?;
        let tc = self
            .token_contract_deploy_address(
                seed_keys,
                &rm,
                nonce,
                frame_model,
                TICK_SIZE,
                price_per_tick,
                max_ticks,
                note,
            )
            .await?;
        let rm_absent = !self
            .wait_active(&rm, crate::params::ACCOUNT_ACTIVE_SINGLE_CHECK_ATTEMPTS)
            .await;
        if rm_absent {
            // Pre-fund the RootModel's(and the TC's -- same nonce) uninit deploy addresses, then deploy the RM.
            self.log_deploy_prefund_snapshot("before fundDeployShell", note, &rm, &tc)
                .await;
            self.note_fund_deploy_shell(note, seed_keys, nonce, gas, gas)
                .await
                .context("note-funded provision: fundDeployShell ECC[2]/SHELL funding failed")?;
            self.log_deploy_prefund_snapshot("after fundDeployShell", note, &rm, &tc)
                .await;
            // Do not hard-gate on a visible balance at the uninit deploy address. On shellnet an uninit
            // pre-funded account can still read as absent/zero through account queries; the reliable proof is
            // fund -> deploy -> wait Active. If funding did not land, the deploy wait below fails with the
            // snapshots above in stderr.
            self.deploy_root_model_note_funded(seed_keys).await?;
        }
        self.ensure_deal_contract_gas(note, seed_keys, nonce, Some(&rm), None)
            .await?;
        // The per-deal TC address is derived from the deploy INIT-DATA(stateInit), NOT the RootModel
        // `getTokenContractAddress` network getter: on a fresh provision the RootModel deploy was just
        // sent(step above) but is not yet `Active`, so the getter would 404 and abort this idempotent check.
        if self
            .wait_active(&tc, crate::params::ACCOUNT_ACTIVE_SINGLE_CHECK_ATTEMPTS)
            .await
        {
            // Idempotent skip: the TC is already `Active` => the RootModel is guaranteed `Active`, so the getter
            // is safe here -- cross-check it agrees with the INIT-DATA derivation (catch a code-hash/derivation
            // divergence between the embedded TC image and the deployed RootModel).
            let getter_tc = self
                .resolve_token_contract(&rm, &seller_pubkey, nonce)
                .await?;
            if getter_tc.with_workchain() != tc.with_workchain() {
                return Err(anyhow!(
                    "RootModel getTokenContractAddress {getter_tc} != INIT-DATA-derived {tc} (TC derivation diverged)"
                ));
            }
        } else {
            // Deploy-if-absent. If the RootModel was already active(idempotent re-run), the TC was not
            // pre-funded above.
            if !rm_absent {
                self.log_deploy_prefund_snapshot("before fundDeployShell", note, &rm, &tc)
                    .await;
                self.note_fund_deploy_shell(note, seed_keys, nonce, 0, gas)
                    .await
                    .context(
                        "note-funded provision: fundDeployShell ECC[2]/SHELL funding failed",
                    )?;
                self.log_deploy_prefund_snapshot("after fundDeployShell", note, &rm, &tc)
                    .await;
            }
            let deployed = self
                .deploy_token_contract_note_funded(
                    seed_keys,
                    &rm,
                    nonce,
                    frame_model,
                    TICK_SIZE,
                    price_per_tick,
                    max_ticks,
                    note,
                )
                .await?;
            // Post-deploy convergence guard: the deployed address must equal the INIT-DATA-derived one.
            if deployed.with_workchain() != tc.with_workchain() {
                return Err(anyhow!(
                    "deployed TC {deployed} != INIT-DATA-derived {tc} (derivation diverged)"
                ));
            }
        }
        self.ensure_deal_contract_gas(note, seed_keys, nonce, Some(&rm), Some(&tc))
            .await?;
        Ok(crate::MarketManifest {
            network: "shellnet".to_string(),
            frame_model: frame_model.to_string(),
            model_hash,
            inference_order_book: ob.with_workchain(),
            root_model: rm.with_workchain(),
            token_contract: tc.with_workchain(),
            seller_note: note.with_workchain(),
            nonce,
            price_per_tick,
            max_ticks,
        })
    }

    pub async fn root_oracle_address(&self) -> Result<Address> {
        Address::parse(ROOTORACLE_ADDR)
    }

    pub async fn root_pn_address(&self) -> Result<Address> {
        Address::parse(ROOTPN_ADDR)
    }

    pub async fn oracle_address(&self, oracle_name: &str) -> Result<Address> {
        let root = self.root_oracle_address().await?;
        let v = self
            .client
            .run_getter(
                &root,
                ROOTORACLE_ABI,
                "getOracleAddress",
                json!({ "name": oracle_name }),
            )
            .await?
            .ok_or_else(|| anyhow!("RootOracle is not active"))?;
        Address::parse(
            v["oracleAddress"]
                .as_str()
                .ok_or_else(|| anyhow!("no address"))?,
        )
    }

    pub async fn deploy_oracle(&self, oracle_keys: &KeyPair, oracle_name: &str) -> Result<Value> {
        let root = self.root_oracle_address().await?;
        self.submit(
            &root,
            ROOTORACLE_ABI,
            "deployOracle",
            json!({
                "oraclePubkey": pubkey_uint256(oracle_keys),
                "oracleName": oracle_name,
            }),
            oracle_keys,
        )
        .await
    }

    pub async fn oracle_event_list_address(
        &self,
        oracle: &Address,
        index: u128,
    ) -> Result<Address> {
        let v = self
            .client
            .run_getter(
                oracle,
                ORACLE_ABI,
                "getEventListAddress",
                json!({ "index": index.to_string() }),
            )
            .await?
            .ok_or_else(|| anyhow!("Oracle is not active"))?;
        Address::parse(v["value0"].as_str().ok_or_else(|| anyhow!("no address"))?)
    }

    pub async fn deploy_oracle_event_list(
        &self,
        oracle: &Address,
        oracle_keys: &KeyPair,
        index: u128,
        description: &str,
    ) -> Result<Value> {
        self.submit(
            oracle,
            ORACLE_ABI,
            "deployEventList",
            json!({
                "index": index.to_string(),
                "description": description,
            }),
            oracle_keys,
        )
        .await
    }

    pub async fn oracle_event_list_events(&self, oel: &Address) -> Result<Option<Value>> {
        self.client
            .run_getter(oel, ORACLEEVENTLIST_ABI, "_events", json!({}))
            .await
    }

    pub async fn oracle_event_info(&self, oel: &Address, event_id: &str) -> Result<Option<Value>> {
        let events = self
            .oracle_event_list_events(oel)
            .await?
            .ok_or_else(|| anyhow!("OracleEventList {oel} _events getter unavailable"))?;
        Ok(event_from_getter_output(&events, event_id).cloned())
    }

    pub async fn oracle_range_data(&self, oel: &Address, event_id: &str) -> Result<Option<Value>> {
        self.client
            .run_getter(
                oel,
                ORACLEEVENTLIST_ABI,
                "getRangeData",
                json!({ "eventId": normalize_uint256_hex(event_id)? }),
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn add_range_event(
        &self,
        oel: &Address,
        oracle_keys: &KeyPair,
        event_name: &str,
        oracle_fee: u128,
        deadline: u64,
        describe: &str,
        bounds: &[String],
        outcome_names: &[String],
        order_book: &Address,
    ) -> Result<Value> {
        self.submit(
            oel,
            ORACLEEVENTLIST_ABI,
            "addRangeEvent",
            json!({
                "eventName": event_name,
                "oracleFee": oracle_fee.to_string(),
                "deadline": deadline.to_string(),
                "describe": describe,
                "bounds": bounds,
                "outcomeNames": dense_string_map(outcome_names),
                "ob": order_book.with_workchain(),
            }),
            oracle_keys,
        )
        .await
    }

    pub async fn pmp_address(
        &self,
        event_id: &str,
        oracle_names: &[String],
        token_type: u32,
    ) -> Result<Address> {
        let root = self.root_pn_address().await?;
        let v = self
            .client
            .run_getter(
                &root,
                ROOTPN_ABI,
                "getPMPAddress",
                json!({
                    "eventId": normalize_uint256_hex(event_id)?,
                    "names": oracle_names,
                    "tokenType": token_type,
                }),
            )
            .await?
            .ok_or_else(|| anyhow!("RootPN is not active"))?;
        Address::parse(
            v["pmpAddress"]
                .as_str()
                .ok_or_else(|| anyhow!("no address"))?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn deploy_pmp(
        &self,
        note: &Address,
        note_keys: &KeyPair,
        event_id: &str,
        oracle_fees: &[u128],
        token_type: u32,
        oracle_names: &[String],
        oracle_indexes: &[u128],
        initial_stakes: &[u128],
    ) -> Result<Value> {
        self.submit(
            note,
            PRIVATENOTE_ABI,
            "deployPMP",
            json!({
                "eventId": normalize_uint256_hex(event_id)?,
                "oracleFee": u128_array(oracle_fees),
                "tokenType": token_type,
                "names": oracle_names,
                "index": u128_array(oracle_indexes),
                "initialStakes": u128_array(initial_stakes),
            }),
            note_keys,
        )
        .await
    }

    pub async fn pmp_details(&self, pmp: &Address) -> Result<Option<Value>> {
        self.client
            .run_getter(pmp, PMP_ABI, "getDetails", json!({}))
            .await
    }

    /// Fail-closed OEL/signer/event identity preflight. It intentionally does not require a live
    /// PMP, because a deletable event outlives the PMP that released its confirmation.
    pub async fn assert_oracle_event_identity(
        &self,
        manifest: &OracleMarketManifest,
        signer: &KeyPair,
    ) -> Result<(Address, Value)> {
        manifest.validate().map_err(anyhow::Error::msg)?;
        let oel = Address::parse(&manifest.oracle_event_list)
            .context("oracle manifest oracle_event_list")?;
        let oracle = Address::parse(&manifest.oracle).context("oracle manifest oracle")?;

        let oel_account = self
            .client
            .get_account(&oel)
            .await?
            .filter(Account::is_active)
            .ok_or_else(|| anyhow!("OracleEventList {oel} is not Active"))?;
        let expected_oel_hash = self
            .deployed
            .contract_hashes
            .get("OracleEventList")
            .and_then(|hash| normalize_code_hash(hash))
            .ok_or_else(|| anyhow!("deployed manifest exposes no OracleEventList code hash"))?;
        let actual_oel_hash = oel_account
            .code_hash
            .as_deref()
            .and_then(normalize_code_hash)
            .ok_or_else(|| anyhow!("OracleEventList {oel} exposes no code hash"))?;
        if actual_oel_hash != expected_oel_hash {
            return Err(anyhow!(
                "OracleEventList {oel} code hash does not match the deployed manifest"
            ));
        }
        let oel_fields = oracle_event_list_storage_fields(
            oel_account
                .boc
                .as_deref()
                .ok_or_else(|| anyhow!("OracleEventList {oel} account BOC is unavailable"))?,
        )?;
        let index = validate_oracle_event_list_identity(&oel_fields, manifest, signer)?;
        let canonical_oel = self.oracle_event_list_address(&oracle, index).await?;
        if canonical_oel.with_workchain() != oel.with_workchain() {
            return Err(anyhow!(
                "OracleEventList {oel} is not canonical oracle {} index {index}",
                manifest.oracle
            ));
        }
        let event = self
            .oracle_event_info(&oel, &manifest.event_id)
            .await?
            .ok_or_else(|| anyhow!("event {} is absent from {oel}", manifest.event_id))?;
        let range = self
            .oracle_range_data(&oel, &manifest.event_id)
            .await?
            .ok_or_else(|| anyhow!("event {} has no range data", manifest.event_id))?;
        validate_oracle_event_manifest(&event, &range, manifest)?;
        Ok((oel, event))
    }

    /// Full fail-closed identity preflight for PMP cancellation.
    pub async fn assert_oracle_market_identity(
        &self,
        manifest: &OracleMarketManifest,
        signer: &KeyPair,
    ) -> Result<(Address, Address, Value, Value)> {
        let (oel, event) = self.assert_oracle_event_identity(manifest, signer).await?;
        let pmp = Address::parse(&manifest.pmp).context("oracle manifest pmp")?;
        let pmp_account = self
            .client
            .get_account(&pmp)
            .await?
            .filter(Account::is_active)
            .ok_or_else(|| anyhow!("PMP {pmp} is not Active"))?;
        let details = self
            .pmp_details(&pmp)
            .await?
            .ok_or_else(|| anyhow!("PMP {pmp} getDetails unavailable"))?;
        validate_pmp_manifest(&details, manifest)?;
        let deployer = pmp_deployer(&details)?;
        let deployer_account = self.client.get_account(&deployer).await?;
        note_balance_private_note_account(&deployer, deployer_account.as_ref())?;
        let pmp_code = self
            .client
            .run_getter(&deployer, PRIVATENOTE_ABI, "getPMPCode", json!({}))
            .await?;
        validate_salted_pmp_identity(
            &pmp,
            pmp_account.code_hash.as_deref(),
            &deployer,
            deployer_account.as_ref(),
            pmp_code.as_ref(),
        )?;
        if !self
            .oracle_event_list_has_pmp_confirmation(&oel, &pmp, &manifest.event_id)
            .await?
        {
            return Err(anyhow!(
                "PMP {pmp} has no active confirmation for event {}",
                manifest.event_id
            ));
        }
        Ok((oel, pmp, details, event))
    }

    pub async fn oracle_event_list_has_pmp_confirmation(
        &self,
        oel: &Address,
        pmp: &Address,
        event_id: &str,
    ) -> Result<bool> {
        let account = self
            .client
            .get_account(oel)
            .await?
            .filter(Account::is_active)
            .ok_or_else(|| anyhow!("OracleEventList {oel} is not Active"))?;
        let fields = oracle_event_list_storage_fields(
            account
                .boc
                .as_deref()
                .ok_or_else(|| anyhow!("OracleEventList {oel} account BOC is unavailable"))?,
        )?;
        oracle_pmp_confirmation_is_active(&fields, pmp, event_id)
    }

    pub async fn submit_pmp_cancel_event(
        &self,
        pmp: &Address,
        oracle_keys: &KeyPair,
    ) -> Result<Value> {
        self.submit(pmp, PMP_ABI, "submitCancelEvent", json!({}), oracle_keys)
            .await
    }

    pub async fn delete_oracle_event(
        &self,
        oel: &Address,
        oracle_keys: &KeyPair,
        event_id: &str,
    ) -> Result<Value> {
        self.submit(
            oel,
            ORACLEEVENTLIST_ABI,
            "deleteEvent",
            json!({ "eventId": normalize_uint256_hex(event_id)? }),
            oracle_keys,
        )
        .await
    }

    pub async fn pmp_order_book_address(&self, pmp: &Address) -> Result<Option<Address>> {
        let Some(v) = self
            .client
            .run_getter(pmp, PMP_ABI, "getOrderBookAddress", json!({}))
            .await?
        else {
            return Ok(None);
        };
        let raw = v["orderBookAddress"]
            .as_str()
            .or_else(|| v["value0"].as_str());
        raw.map(Address::parse).transpose()
    }

    pub async fn resolve_oracle_range(
        &self,
        oel: &Address,
        signer: &KeyPair,
        event_id: &str,
        oracle_list_hash: &str,
        token_type: u32,
    ) -> Result<Value> {
        self.submit(
            oel,
            ORACLEEVENTLIST_ABI,
            "resolveRange",
            json!({
                "eventId": normalize_uint256_hex(event_id)?,
                "oracleListHash": normalize_uint256_hex(oracle_list_hash)?,
                "tokenType": token_type,
            }),
            signer,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn provision_oracle_market(
        &self,
        note_keys: &KeyPair,
        note: &Address,
        oracle_keys: &KeyPair,
        oracle_name: &str,
        event_list_index: u128,
        event_list_description: &str,
        event_name: &str,
        oracle_fee: u128,
        deadline: u64,
        describe: &str,
        bounds: &[String],
        outcome_names: &[String],
        market: &MarketManifest,
        token_type: u32,
        initial_stakes: &[u128],
    ) -> Result<OracleMarketManifest> {
        if oracle_name.trim().is_empty() {
            return Err(anyhow!("oracle_name is empty"));
        }
        if initial_stakes.len() != outcome_names.len() {
            return Err(anyhow!(
                "initial_stakes must cover every outcome (got {}, expected {})",
                initial_stakes.len(),
                outcome_names.len()
            ));
        }
        if let Some((i, _)) = initial_stakes
            .iter()
            .enumerate()
            .find(|(_, v)| **v < MIN_PMP_INITIAL_STAKE)
        {
            return Err(anyhow!(
                "initial_stakes[{i}] is below the contract minimum {MIN_PMP_INITIAL_STAKE}"
            ));
        }

        self.assert_seller_note_current(note).await?;
        self.assert_note_owner_matches("oracle provision", note, note_keys)
            .await?;

        let order_book = Address::parse(&market.inference_order_book)?;
        let oracle = self.oracle_address(oracle_name).await?;
        if !self
            .wait_active(&oracle, crate::params::ACCOUNT_ACTIVE_SINGLE_CHECK_ATTEMPTS)
            .await
        {
            self.deploy_oracle(oracle_keys, oracle_name).await?;
            if !self
                .wait_active(&oracle, crate::params::ACCOUNT_ACTIVATION_MAX_ATTEMPTS)
                .await
            {
                return Err(anyhow!("Oracle {oracle} did not activate"));
            }
        }

        let oel = self
            .oracle_event_list_address(&oracle, event_list_index)
            .await?;
        if !self
            .wait_active(&oel, crate::params::ACCOUNT_ACTIVE_SINGLE_CHECK_ATTEMPTS)
            .await
        {
            self.deploy_oracle_event_list(
                &oracle,
                oracle_keys,
                event_list_index,
                event_list_description,
            )
            .await?;
            if !self
                .wait_active(&oel, crate::params::ACCOUNT_ACTIVATION_MAX_ATTEMPTS)
                .await
            {
                return Err(anyhow!("OracleEventList {oel} did not activate"));
            }
        }

        let event_id = match self
            .find_oracle_event_id(&oel, event_name, deadline, describe, outcome_names)
            .await?
        {
            Some(id) => id,
            None => {
                self.add_range_event(
                    &oel,
                    oracle_keys,
                    event_name,
                    oracle_fee,
                    deadline,
                    describe,
                    bounds,
                    outcome_names,
                    &order_book,
                )
                .await?;
                self.wait_oracle_event_id(&oel, event_name, deadline, describe, outcome_names)
                    .await?
            }
        };

        let oracle_names = vec![oracle_name.to_string()];
        let oracle_indexes = vec![event_list_index];
        let oracle_fees = vec![oracle_fee];
        let pmp = self
            .pmp_address(&event_id, &oracle_names, token_type)
            .await?;
        if !self
            .wait_active(&pmp, crate::params::ACCOUNT_ACTIVE_SINGLE_CHECK_ATTEMPTS)
            .await
        {
            self.deploy_pmp(
                note,
                note_keys,
                &event_id,
                &oracle_fees,
                token_type,
                &oracle_names,
                &oracle_indexes,
                initial_stakes,
            )
            .await?;
            if !self
                .wait_active(&pmp, crate::params::ACCOUNT_ACTIVATION_MAX_ATTEMPTS)
                .await
            {
                return Err(anyhow!("PMP {pmp} did not activate"));
            }
        }

        let details = self.wait_pmp_approved(&pmp).await?;
        let oracle_list_hash = value_to_uint256_hex(&details["oracleListHash"])
            .ok_or_else(|| anyhow!("PMP getDetails returned no oracleListHash"))?;
        let range = self
            .oracle_range_data(&oel, &event_id)
            .await?
            .ok_or_else(|| anyhow!("OracleEventList {oel} returned no range data"))?;
        if !range["exists"].as_bool().unwrap_or(false) {
            return Err(anyhow!(
                "OracleEventList {oel} has no range data for event {event_id}"
            ));
        }
        let range_ob = range["ob"].as_str().unwrap_or("");
        if normalize_addr(range_ob)? != normalize_addr(&market.inference_order_book)? {
            return Err(anyhow!(
                "range event OB {range_ob} != market inference_order_book {}",
                market.inference_order_book
            ));
        }
        let on_chain_bounds = range_bounds_to_uint256_hex(&range["bounds"]).ok_or_else(|| {
            anyhow!("OracleEventList {oel} returned invalid bounds for event {event_id}: {range:?}")
        })?;
        let requested_bounds = requested_bounds_to_uint256_hex(bounds)?;
        if on_chain_bounds != requested_bounds {
            return Err(anyhow!(
                "range event bounds {:?} != requested {:?} for event {event_id}",
                on_chain_bounds,
                requested_bounds
            ));
        }

        let manifest = OracleMarketManifest {
            network: self.deployed.network.clone(),
            root_oracle: self.root_oracle_address().await?.with_workchain(),
            oracle: oracle.with_workchain(),
            oracle_event_list: oel.with_workchain(),
            oracle_list_hash,
            event_id,
            event_name: event_name.to_string(),
            pmp: pmp.with_workchain(),
            token_type,
            inference_order_book: market.inference_order_book.clone(),
            frame_model: market.frame_model.clone(),
            deadline,
            bounds: bounds.to_vec(),
            outcome_names: outcome_names.to_vec(),
        };
        manifest
            .validate()
            .map_err(|e| anyhow!("oracle market manifest: {e}"))?;
        Ok(manifest)
    }

    async fn find_oracle_event_id(
        &self,
        oel: &Address,
        event_name: &str,
        deadline: u64,
        describe: &str,
        outcome_names: &[String],
    ) -> Result<Option<String>> {
        let Some(events) = self.oracle_event_list_events(oel).await? else {
            return Ok(None);
        };
        Ok(find_event_id_in_getter_output(
            &events,
            event_name,
            deadline,
            describe,
            outcome_names,
        ))
    }

    async fn wait_oracle_event_id(
        &self,
        oel: &Address,
        event_name: &str,
        deadline: u64,
        describe: &str,
        outcome_names: &[String],
    ) -> Result<String> {
        for i in 0..crate::params::ORACLE_EVENT_ID_MAX_READS {
            if let Some(id) = self
                .find_oracle_event_id(oel, event_name, deadline, describe, outcome_names)
                .await?
            {
                return Ok(id);
            }
            if i + 1 < crate::params::ORACLE_EVENT_ID_MAX_READS {
                tokio::time::sleep(crate::params::ORACLE_EVENT_ID_POLL_INTERVAL).await;
            }
        }
        Err(anyhow!(
            "range event `{event_name}` did not appear in OracleEventList {oel}"
        ))
    }

    async fn wait_pmp_approved(&self, pmp: &Address) -> Result<Value> {
        for i in 0..crate::params::PMP_APPROVAL_MAX_READS {
            if let Some(details) = self.pmp_details(pmp).await? {
                if details["approved"].as_bool().unwrap_or(false) {
                    return Ok(details);
                }
            }
            if i + 1 < crate::params::PMP_APPROVAL_MAX_READS {
                tokio::time::sleep(crate::params::PMP_APPROVAL_POLL_INTERVAL).await;
            }
        }
        let details = self.pmp_details(pmp).await?;
        Err(anyhow!(
            "PMP {pmp} did not become approved by oracle; last getDetails={details:?}"
        ))
    }

    /// fail-closed pre-flight: the seller note must be Active on-chain AND carry the **current**
    /// `PrivateNote` code(the embedded `PRIVATENOTE_TVC` hash). A `pn_pool` minted before a SuperRoot /
    /// PrivateNote redeploy is orphaned -- the note is either gone (a later getter 404s as "note is not
    /// active") or runs stale code whose deploy/registration into the rotated SuperRoot throws a bare
    /// `TVM_ERROR` in the compute phase. Catch both here with an actionable "re-mint your pool" message
    /// instead of letting provision fail opaquely downstream.
    pub async fn assert_seller_note_current(&self, note: &Address) -> Result<()> {
        let account = self.client.get_account(note).await?;
        seller_note_account_current(note, account.as_ref())
    }

    /// Validate the account snapshot read by `dexdo note balance`.
    pub fn assert_note_balance_private_note_account(
        &self,
        note: &Address,
        account: Option<&Account>,
    ) -> Result<()> {
        note_balance_private_note_account(note, account)
    }

    /// Fund-safety guard for `note withdraw`. A PrivateNote deployed by a
    /// PREVIOUS contract generation -- its on-chain `code_hash` != the current
    /// `PRIVATENOTE_PINNED_CODE_HASH` -- still accepts the current-generation `withdrawTokens`
    /// message: it ZEROES the note's balance but does NOT credit the destination wallet, so the
    /// SHELL is lost. Refuse the withdraw BEFORE any on-chain write when the note is not the current
    /// generation. This does not recover funds already lost; it prevents zeroing a still-funded
    /// previous-generation note.
    pub async fn assert_note_withdraw_generation(&self, note: &Address) -> Result<()> {
        let acc = self
            .client
            .get_account(note)
            .await?
            .ok_or_else(|| anyhow!("note {note} is not on-chain; cannot withdraw"))?;
        if !acc.is_active() {
            return Err(anyhow!(
                "note {note} is {}, not Active; cannot withdraw",
                acc.status
            ));
        }
        note_withdraw_generation_ok(note, acc.code_hash.as_deref())
    }

    /// read the note's on-chain owner key (`getDetails().ephemeralPubkey`) and fail closed if it does not
    /// match the key the client will sign the owner-authenticated write with -- turning the opaque pre-accept
    /// `onlyOwnerPubkey` revert(branch 3: a non-conforming/orphaned note) into an actionable error. The buyer's
    /// `place_buy` calls it before `placeInferenceBuy`; the seller's `post_offer` before `postSellOffer`. An
    /// absent/empty `getDetails`(uninit/orphaned note) is itself a fail-closed re-mint case.
    pub async fn assert_note_owner_matches(
        &self,
        role: &str,
        note: &Address,
        signing_keys: &KeyPair,
    ) -> Result<()> {
        let details = self
            .client
            .run_getter(note, PRIVATENOTE_ABI, "getDetails", json!({}))
            .await?
            .ok_or_else(|| {
                anyhow!(
                    "{role} aborted: note {note} returned no getDetails (not on-chain/active) -- the pn_pool is \
                     likely orphaned by a contract redeploy. Re-mint against the current contracts \
                     (`mint_pn_pool`) and point DEXDO_PN_POOL at the fresh pool."
                )
            })?;
        match note_owner_mismatch_reason(
            role,
            note,
            details["ephemeralPubkey"].as_str(),
            signing_keys.public_hex(),
        ) {
            Some(reason) => Err(anyhow!(reason)),
            None => Ok(()),
        }
    }

    /// Poll `get_account(addr).is_active()` up to `tries` times(3s apart; `tries=1` = a single check).
    /// A query error or a not-yet-existent account(e.g. a self-dapp uninit address that 404s) counts
    /// as "not active" -- the caller then deploys or fails with a clear message.
    async fn wait_active(&self, addr: &Address, tries: u32) -> bool {
        for i in 0..tries {
            if let Ok(Some(a)) = self.client.get_account(addr).await {
                if a.is_active() {
                    return true;
                }
            }
            if i + 1 < tries {
                tokio::time::sleep(crate::params::ACCOUNT_ACTIVATION_POLL_INTERVAL).await;
            }
        }
        false
    }
}

fn withdraw_note_tokens_payload(dest_wallet: &Address, dapp_id: &str) -> Value {
    json!({
        "destWalletAddr": dest_wallet.with_workchain(),
        "dapp_id": dapp_id,
    })
}

/// One shape for every `PrivateNote.placeInferenceBuy` payload -- ordinary buys and subscriptions alike,
/// since they are the same on-chain call and differ only in `flags`. Keeping the encoding in one place is
/// what stops the plain and subscription paths from drifting into two argument orders.
fn place_inference_buy_payload(
    model_hash: &str,
    max_price_per_tick: u128,
    ticks: u128,
    escrow: u128,
    flags: u8,
    deadline: u64,
) -> Value {
    json!({
        "modelHash": model_hash,
        "maxPricePerTick": max_price_per_tick.to_string(),
        "ticks": ticks.to_string(),
        "escrow": escrow.to_string(),
        "flags": flags,
        "deadline": deadline.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn zero_address() -> String {
        format!("0:{}", "0".repeat(64))
    }

    fn valid_subscription_order(owner: &str) -> Value {
        let ticks = u128::from(SUBSCRIPTION_WEEKS);
        let reserve = crate::chain::subscription_buy_reserve(ticks, PRICE_STEP)
            .expect("canonical subscription reserve");
        json!({
            "note": owner,
            "tokenContract": zero_address(),
            "price": PRICE_STEP.to_string(),
            "amount": ticks.to_string(),
            "escrow": reserve.total_escrow.to_string(),
            "deadline": "200",
            "flags": (flags::AON | flags::SUBSCRIPTION).to_string(),
            "ts": "100",
            "isBuy": true
        })
    }

    fn subscription_placement(order_id: u128, owner: &str) -> InferenceSubscriptionPlacement {
        InferenceSubscriptionPlacement {
            order_id,
            buyer_note: owner.to_string(),
            max_price_per_tick: PRICE_STEP,
            ticks: u128::from(SUBSCRIPTION_WEEKS),
            sub_weeks: SUBSCRIPTION_WEEKS,
            deadline: 200,
            created_at: 100,
        }
    }

    #[test]
    fn subscription_history_treats_cancelled_empty_order_as_absent() {
        let owner = format!("0:{}", "1".repeat(64));
        let tombstone = json!({
            "note": zero_address(),
            "tokenContract": zero_address(),
            "price": "0",
            "amount": "0",
            "escrow": "0",
            "deadline": "0",
            "flags": "0",
            "ts": "0",
            "isBuy": false
        });

        assert!(
            !subscription_order_is_active_for_owner(1, &tombstone, &owner)
                .expect("canonical cancelled tombstone is absent")
        );

        for field in ["note", "tokenContract"] {
            for malformed in ["x", ":", "0x"] {
                let mut mutated = tombstone.clone();
                mutated[field] = json!(malformed);
                let error = subscription_order_is_active_for_owner(1, &mutated, &owner)
                    .expect_err("strip-only pseudo-zero address must fail closed");
                assert!(
                    error.to_string().contains("non-canonical zero-amount"),
                    "{field}={malformed:?}: {error:#}"
                );
            }
        }
    }

    #[test]
    fn subscription_history_rejects_non_empty_order_without_owner() {
        let owner = format!("0:{}", "1".repeat(64));
        let malformed = json!({
            "note": "",
            "amount": "1",
            "isBuy": true
        });

        let error = subscription_order_is_active_for_owner(2, &malformed, &owner)
            .expect_err("non-empty ownerless order must fail closed");
        assert!(error.to_string().contains("owner note"), "{error:#}");
    }

    #[test]
    fn subscription_history_rejects_nonempty_zero_amount_row() {
        let owner = format!("0:{}", "1".repeat(64));
        let malformed = json!({
            "note": owner.clone(),
            "tokenContract": zero_address(),
            "price": "0",
            "amount": "0",
            "escrow": "0",
            "deadline": "0",
            "flags": "0",
            "ts": "0",
            "isBuy": true
        });

        let error = subscription_order_is_active_for_owner(3, &malformed, &owner)
            .expect_err("zero amount alone must not classify a non-empty row as absent");
        assert!(
            error.to_string().contains("non-canonical zero-amount"),
            "{error:#}"
        );
    }

    #[test]
    fn subscription_placement_history_coalesces_only_identical_duplicates() {
        let owner = format!("0:{}", "1".repeat(64));
        let placement = subscription_placement(9, &owner);
        let placements = coalesce_correlated_subscription_placements(
            vec![placement.clone(), placement.clone()],
            &owner,
            PRICE_STEP,
            u128::from(SUBSCRIPTION_WEEKS),
        )
        .expect("byte-for-byte semantic duplicates coalesce");
        assert_eq!(placements, vec![placement]);
    }

    #[test]
    fn subscription_placement_history_rejects_conflicting_duplicate_order_id() {
        let owner = format!("0:{}", "1".repeat(64));
        let placement = subscription_placement(9, &owner);
        let mut conflicting = placement.clone();
        conflicting.deadline += 1;
        let error = coalesce_correlated_subscription_placements(
            vec![placement, conflicting],
            &owner,
            PRICE_STEP,
            u128::from(SUBSCRIPTION_WEEKS),
        )
        .expect_err("same order id with conflicting authenticated facts must fail closed");
        assert!(
            error.to_string().contains("conflicting authenticated"),
            "{error:#}"
        );
    }

    #[test]
    fn subscription_cancel_race_rejects_every_nonempty_fixed_id_mutation() {
        let owner = format!("0:{}", "1".repeat(64));
        let valid = valid_subscription_order(&owner);
        assert!(subscription_order_is_active_for_owner(10, &valid, &owner)
            .expect("canonical live subscription is active"));

        let reserve =
            crate::chain::subscription_buy_reserve(u128::from(SUBSCRIPTION_WEEKS), PRICE_STEP)
                .expect("canonical subscription reserve");
        let mut mutations = Vec::new();

        let mut wrong_owner = valid.clone();
        wrong_owner["note"] = json!(format!("0:{}", "2".repeat(64)));
        mutations.push(("owner", wrong_owner));

        let mut wrong_side = valid.clone();
        wrong_side["isBuy"] = json!(false);
        mutations.push(("side", wrong_side));

        let mut wrong_flags = valid.clone();
        wrong_flags["flags"] = json!(flags::SUBSCRIPTION.to_string());
        mutations.push(("flags", wrong_flags));

        let mut wrong_token_contract = valid.clone();
        wrong_token_contract["tokenContract"] = json!(format!("0:{}", "3".repeat(64)));
        mutations.push(("tokenContract", wrong_token_contract));

        let mut zero_amount = valid.clone();
        zero_amount["amount"] = json!("0");
        mutations.push(("zero amount", zero_amount));

        let mut wrong_amount = valid.clone();
        wrong_amount["amount"] = json!("3");
        mutations.push(("amount shape", wrong_amount));

        let mut wrong_escrow = valid.clone();
        wrong_escrow["escrow"] = json!((reserve.total_escrow + 1).to_string());
        mutations.push(("escrow", wrong_escrow));

        let mut wrong_price = valid.clone();
        wrong_price["price"] = json!("1");
        mutations.push(("price", wrong_price));

        let mut wrong_deadline = valid.clone();
        wrong_deadline["deadline"] = json!("100");
        mutations.push(("deadline", wrong_deadline));

        let mut missing_shape = valid;
        missing_shape
            .as_object_mut()
            .expect("fixture is object")
            .remove("flags");
        mutations.push(("missing shape", missing_shape));

        for (label, mutation) in mutations {
            assert!(
                subscription_order_is_active_for_owner(10, &mutation, &owner).is_err(),
                "{label} mutation must be a contradiction, never inactive: {mutation}"
            );
        }

        let valid = valid_subscription_order(&owner);
        for field in ["note", "tokenContract"] {
            for malformed in ["x", ":", "0x"] {
                let mut mutation = valid.clone();
                mutation[field] = json!(malformed);
                assert!(
                    subscription_order_is_active_for_owner(10, &mutation, &owner).is_err(),
                    "{field}={malformed:?} must be a contradiction, never inactive: {mutation}"
                );
            }
        }
    }

    #[tokio::test]
    async fn fetch_ext_out_page_sends_bare_graphql_ids() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind GraphQL fixture");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept GraphQL request");
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 4096];
                let read = socket.read(&mut chunk).await.expect("read GraphQL request");
                request.extend_from_slice(&chunk[..read]);
                let Some(headers_end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let headers_end = headers_end + 4;
                let headers = String::from_utf8_lossy(&request[..headers_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(str::trim)
                            .and_then(|value| value.parse::<usize>().ok())
                    })
                    .expect("GraphQL request content length");
                if request.len() < headers_end + content_length {
                    continue;
                }
                let body: Value =
                    serde_json::from_slice(&request[headers_end..headers_end + content_length])
                        .expect("GraphQL request JSON");
                assert_eq!(
                    body["variables"]["accountId"],
                    "1111111111111111111111111111111111111111111111111111111111111111"
                );
                assert_eq!(
                    body["variables"]["dappId"],
                    "2222222222222222222222222222222222222222222222222222222222222222"
                );
                let response_body = json!({
                    "data": {"blockchain": {"account": {"messages": {
                        "pageInfo": {"startCursor": null, "hasPreviousPage": false},
                        "edges": []
                    }}}}
                })
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                socket
                    .write_all(response.as_bytes())
                    .await
                    .expect("write GraphQL response");
                break;
            }
        });

        let page = fetch_ext_out_page(
            &reqwest::Client::new(),
            &endpoint,
            &format!("0:{}", "1".repeat(64)),
            &format!("0:{}", "2".repeat(64)),
            100,
            None,
        )
        .await
        .expect("fetch ext-out page");
        assert!(page.messages.is_empty());
        assert_eq!(page.previous_cursor, None);
        task.await.expect("GraphQL fixture task");
    }

    #[tokio::test]
    async fn settlement_receipts_fail_closed_when_message_id_is_missing() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind GraphQL fixture");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept GraphQL request");
            let _ = read_fixture_http_request(&mut socket).await;
            let response_body = json!({
                "data": {"blockchain": {"account": {"messages": {
                    "pageInfo": {"startCursor": null, "hasPreviousPage": false},
                    "edges": [{
                        "cursor": "opaque-cursor",
                        "node": {"body": "ignored", "created_at": 1}
                    }]
                }}}}
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write GraphQL response");
        });

        let error = fetch_ext_out_page(
            &reqwest::Client::new(),
            &endpoint,
            &format!("0:{}", "1".repeat(64)),
            &format!("0:{}", "2".repeat(64)),
            100,
            None,
        )
        .await
        .expect_err("cursor must never stand in for a missing message id");
        task.await.expect("GraphQL fixture task");
        let message = format!("{error:#}");
        assert!(message.contains("no message id"), "{message}");
        assert!(message.contains("opaque-cursor"), "{message}");
    }

    #[test]
    fn clock_skew_within_threshold_passes() {
        for local in [999_990, 1_000_030] {
            assert_eq!(
                clock_skew_check(local, 1_000_000).status,
                ShellnetDoctorStatus::Pass
            );
        }
    }

    #[test]
    fn clock_skew_real_boundaries_fail_closed_with_actionable_message() {
        for behind in [41, 60] {
            let check = clock_skew_check(1_000_000 - behind, 1_000_000);
            assert_eq!(check.status, ShellnetDoctorStatus::Fail);
            assert!(check.message.contains("CLOCK_SKEW"));
            assert!(check
                .message
                .contains(&format!("{behind}s behind chain time")));
        }
        let check = clock_skew_check(1_000_000 + MAX_CLOCK_AHEAD_SECS + 1, 1_000_000);
        assert_eq!(check.status, ShellnetDoctorStatus::Fail);
        assert!(check.message.contains("CLOCK_SKEW"));
        assert!(check.message.contains("251s ahead of chain time"));
        assert!(check.message.contains("Fix system time / NTP and retry"));

        let report = ShellnetDoctorReport {
            network: "shellnet".to_string(),
            versions: Vec::new(),
            checks: vec![check],
        };
        assert!(!report.is_ok(), "write preflight must fail closed");
        assert!(report.fail_summary().contains("CLOCK_SKEW"));
    }

    #[test]
    fn signed_write_expiry_codes_get_clock_hint_without_hiding_dex_errors() {
        let error = checked_submit_response(json!({
            "error": {
                "code": "TVM_ERROR",
                "message": "Failed to execute the message. Error occurred during the compute phase.",
                "exit_code": 103,
                "address": "0:1111111111111111111111111111111111111111111111111111111111111111"
            }
        }))
        .expect_err("nested giver replay rejection");
        assert!(format!("{error:#}").contains("verify the operator clock/NTP"));

        for (code, diagnosis) in [
            (102, "dex::ERR_LOW_VALUE"),
            (103, "dex::ERR_ALREADY_RESOLVED"),
        ] {
            let error = checked_submit_response(json!({
                "result": {
                    "exit_code": code,
                    "address": "0:2222222222222222222222222222222222222222222222222222222222222222"
                }
            }))
            .expect_err("ordinary dex rejection");
            let displayed = format!("{error:#}");
            assert!(displayed.contains(diagnosis), "{displayed}");
            assert!(!displayed.contains("operator clock"), "{displayed}");
        }

        for code in [401, 402] {
            let error = checked_submit_response(json!({"result": {"exit_code": code}}))
                .expect_err("dex expiry/replay rejection");
            assert!(format!("{error:#}").contains("verify the operator clock/NTP"));
        }
        let error = checked_submit_response(json!({"result": {"exit_code": 151}}))
            .expect_err("other rejection");
        assert!(!format!("{error:#}").contains("operator clock"));
    }

    async fn skew_fixture_backend(
        chain_offset: i64,
    ) -> (
        RealChainBackend,
        Arc<AtomicUsize>,
        Arc<Mutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let posts = Arc::new(AtomicUsize::new(0));
        let server_posts = Arc::clone(&posts);
        let posted_bocs = Arc::new(Mutex::new(Vec::new()));
        let server_bocs = Arc::clone(&posted_bocs);
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_fixture_http_request(&mut socket).await;
                if request.starts_with("POST /v2/messages ") {
                    server_posts.fetch_add(1, Ordering::SeqCst);
                    let body = request.split_once("\r\n\r\n").unwrap().1;
                    let payload: Value = serde_json::from_str(body).unwrap();
                    server_bocs
                        .lock()
                        .unwrap()
                        .push(payload[0]["body"].as_str().unwrap().to_string());
                }
                let local = local_unix_secs().unwrap() as i64;
                let chain = (local + chain_offset) as u64;
                let body = json!({"data":{"blockchain":{"blocks":{"edges":[{"node":{"gen_utime":chain}}]}}}}).to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let deployed = deployed("");
        let backend = RealChainBackend {
            client: ChainClient::connect(&endpoint).unwrap(),
            http: reqwest::Client::new(),
            money_post_http: build_money_post_http_client().unwrap(),
            superroot: Address::parse(&deployed.superroot).unwrap(),
            deployed,
        };
        (backend, posts, posted_bocs, task)
    }

    #[tokio::test]
    async fn unsafe_clock_produces_zero_posts_in_regular_and_money_paths() {
        for chain_offset in [60, -300] {
            let (backend, posts, _, task) = skew_fixture_backend(chain_offset).await;
            let regular = backend.retry_submit("not-posted", false).await.unwrap_err();
            assert!(format!("{regular:#}").contains("CLOCK_SKEW"));

            let address = Address::parse(&format!("0:{}", "1".repeat(64))).unwrap();
            let keys = KeyPair::from_secret_hex(&"3a".repeat(32)).unwrap();
            let money = backend
                .prepare_money_post(&address, "{}", "unused", json!({}), &keys)
                .await
                .unwrap_err();
            assert!(format!("{money:#}").contains("CLOCK_SKEW"));
            assert_eq!(
                posts.load(Ordering::SeqCst),
                0,
                "no message POST is permitted"
            );
            task.abort();
        }
    }

    fn aborted_submit_error() -> anyhow::Error {
        checked_submit_response(json!({
            "result": {
                "exit_code": 0,
                "aborted": true
            }
        }))
        .expect_err("aborted submit must fail")
    }

    #[test]
    fn fund_deploy_shell_correlated_no_funds_receipt_adds_ecc2_context() {
        let contextual = fund_deploy_shell_receipt_error(
            aborted_submit_error(),
            "abcd",
            Some(&CorrelatedActionReceipt {
                message_hash: "abcd".to_string(),
                transaction_hash: Some("tx38".to_string()),
                aborted: Some(true),
                action_success: Some(false),
                result_code: Some(38),
                no_funds: Some(true),
                ..Default::default()
            }),
        );
        let displayed = format!("{contextual:#}");
        assert!(
            displayed.contains("insufficient ECC[2]/SHELL"),
            "{displayed}"
        );
        assert!(displayed.contains("note_fund_deploy_shell"), "{displayed}");
        assert!(displayed.contains("aborted=true"), "{displayed}");
        assert!(displayed.contains("action_success=false"), "{displayed}");
        assert!(displayed.contains("action_result_code=38"), "{displayed}");
        assert!(displayed.contains("no_funds=true"), "{displayed}");
    }

    #[test]
    fn fund_deploy_shell_non_38_receipt_is_factual_without_ecc2_claim() {
        let contextual = fund_deploy_shell_receipt_error(
            aborted_submit_error(),
            "abcd",
            Some(&CorrelatedActionReceipt {
                message_hash: "abcd".to_string(),
                transaction_hash: Some("tx401".to_string()),
                aborted: Some(true),
                action_success: Some(false),
                result_code: Some(401),
                no_funds: Some(false),
                ..Default::default()
            }),
        );
        let displayed = format!("{contextual:#}");
        assert!(!displayed.contains("insufficient ECC[2]"), "{displayed}");
        assert!(displayed.contains("action_result_code=401"), "{displayed}");
        assert!(displayed.contains("aborted=true"), "{displayed}");
        assert!(displayed.contains("ECC[2] cause not proven"), "{displayed}");
    }

    #[test]
    fn fund_deploy_shell_missing_or_mismatched_receipt_fails_closed() {
        let missing = fund_deploy_shell_receipt_error(aborted_submit_error(), "abcd", None);
        let missing = format!("{missing:#}");
        assert!(!missing.contains("insufficient ECC[2]"), "{missing}");
        assert!(
            missing.contains("no finalized destination receipt matched"),
            "{missing}"
        );

        let mismatched = fund_deploy_shell_receipt_error(
            aborted_submit_error(),
            "abcd",
            Some(&CorrelatedActionReceipt {
                message_hash: "ffff".to_string(),
                transaction_hash: Some("tx38".to_string()),
                aborted: Some(true),
                action_success: Some(false),
                result_code: Some(38),
                no_funds: Some(true),
                ..Default::default()
            }),
        );
        let mismatched = format!("{mismatched:#}");
        assert!(!mismatched.contains("insufficient ECC[2]"), "{mismatched}");
        assert!(
            mismatched.contains("ECC[2] cause not proven"),
            "{mismatched}"
        );
    }

    #[test]
    fn fund_deploy_shell_incomplete_or_inconsistent_38_receipt_fails_closed() {
        for (case, receipt) in [
            (
                "action success",
                CorrelatedActionReceipt {
                    message_hash: "abcd".to_string(),
                    transaction_hash: Some("tx38".to_string()),
                    aborted: Some(true),
                    action_success: Some(true),
                    result_code: Some(38),
                    no_funds: Some(true),
                    ..Default::default()
                },
            ),
            (
                "missing no_funds",
                CorrelatedActionReceipt {
                    message_hash: "abcd".to_string(),
                    transaction_hash: Some("tx38".to_string()),
                    aborted: Some(true),
                    action_success: Some(false),
                    result_code: Some(38),
                    no_funds: None,
                    ..Default::default()
                },
            ),
            (
                "missing aborted",
                CorrelatedActionReceipt {
                    message_hash: "abcd".to_string(),
                    transaction_hash: Some("tx38".to_string()),
                    aborted: None,
                    action_success: Some(false),
                    result_code: Some(38),
                    no_funds: Some(true),
                    ..Default::default()
                },
            ),
            (
                "missing transaction id",
                CorrelatedActionReceipt {
                    message_hash: "abcd".to_string(),
                    transaction_hash: None,
                    aborted: Some(true),
                    action_success: Some(false),
                    result_code: Some(38),
                    no_funds: Some(true),
                    ..Default::default()
                },
            ),
        ] {
            let contextual =
                fund_deploy_shell_receipt_error(aborted_submit_error(), "abcd", Some(&receipt));
            let displayed = format!("{contextual:#}");
            assert!(
                !displayed.contains("insufficient ECC[2]"),
                "{case}: {displayed}"
            );
            assert!(
                displayed.contains("ECC[2] cause not proven"),
                "{case}: {displayed}"
            );
            assert!(
                displayed.contains("action_result_code=38"),
                "{case}: {displayed}"
            );
        }
    }

    #[test]
    fn exact_message_receipt_keeps_polling_without_destination_transaction() {
        let raw = json!({
            "data": {"blockchain": {
                "message": {
                    "id": "abcd",
                    "dst": "11",
                    "dst_transaction": null
                },
                "account": {"info": null}
            }}
        });

        assert_eq!(
            parse_exact_destination_receipt(&raw, "11", "04", "abcd")
                .expect("pending exact message must not fail"),
            None
        );
    }

    #[test]
    fn exact_message_receipt_keeps_polling_non_finalized_destination_transaction() {
        let raw = json!({
            "data": {"blockchain": {
                "message": {
                    "id": "abcd",
                    "dst": "11",
                    "dst_transaction": {"status": 1}
                },
                "account": {"info": null}
            }}
        });

        assert_eq!(
            parse_exact_destination_receipt(&raw, "11", "04", "abcd")
                .expect("non-finalized destination transaction must not fail"),
            None
        );
    }

    #[test]
    fn exact_message_receipt_rejects_malformed_finalized_destination_transaction() {
        let raw = json!({
            "data": {"blockchain": {
                "message": {
                    "id": "abcd",
                    "dst": "11",
                    "dst_transaction": {"status": 3}
                },
                "account": {"info": {"id": "11", "dapp_id": "04"}}
            }}
        });

        let error = parse_exact_destination_receipt(&raw, "11", "04", "abcd")
            .expect_err("malformed finalized receipt must fail closed");
        assert!(
            error.to_string().contains("has no account"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn exact_message_receipt_query_and_raw_shape_ignore_unrelated_newer_messages() {
        const TARGET: &str = "1111111111111111111111111111111111111111111111111111111111111111";
        const DAPP: &str = "04";
        const HASH: &str = "abcd";
        assert!(
            EXACT_MESSAGE_RECEIPT_QUERY.contains("message(hash: $hash)"),
            "receipt lookup must address the submitted message directly"
        );
        assert!(
            !EXACT_MESSAGE_RECEIPT_QUERY.contains("messages("),
            "receipt lookup must not scan a bounded account-message window"
        );
        assert!(
            !EXACT_MESSAGE_RECEIPT_QUERY.contains("last_trans_lt"),
            "wallet freshness must use exact transaction identity, not incompatible LT encodings"
        );
        for field in ["outmsg_cnt", "balance_other", "transactions(last: 1)"] {
            assert!(
                EXACT_MESSAGE_RECEIPT_QUERY.contains(field),
                "receipt lookup must include {field}"
            );
        }

        let raw = json!({
            "data": {"blockchain": {
                "message": {
                    "id": HASH,
                    "dst": format!("0:{TARGET}"),
                    "dst_transaction": {
                        "id": "tx38",
                        "status": 3,
                        "aborted": true,
                        "account_addr": TARGET,
                        "lt": "0x62b9b6",
                        "outmsg_cnt": 0,
                        "compute": {"exit_code": 0, "success": true},
                        "action": {"result_code": 38, "success": false, "no_funds": true}
                    }
                },
                "account": {"info": {
                    "id": TARGET,
                    "dapp_id": DAPP,
                    "last_trans_lt": "0x62b9b7",
                    "balance_other": [
                        {"currency": 1, "value": "0x64"},
                        {"currency": 2, "value": "0xc8"}
                    ]
                }, "transactions": {"edges": [{"node": {"id": "tx38"}}]}},
                "messages": {"edges": [{"node": {
                    "id": "unrelated-newer-message",
                    "dst": format!("0:{TARGET}")
                }}]}
            }}
        });
        let receipt = parse_exact_destination_receipt(&raw, TARGET, DAPP, HASH)
            .expect("raw exact-hash GraphQL shape")
            .expect("finalized destination receipt");
        assert_eq!(receipt.message_hash, HASH);
        assert_eq!(receipt.transaction_hash.as_deref(), Some("tx38"));
        assert_eq!(receipt.compute_exit_code, Some(0));
        assert_eq!(receipt.result_code, Some(38));
        assert_eq!(receipt.no_funds, Some(true));
        assert_eq!(receipt.outmsg_count, Some(0));
        assert_eq!(
            receipt.account_latest_transaction_hash.as_deref(),
            Some("tx38")
        );
        assert_eq!(receipt.account_ecc_balances, Some(vec![(1, 100), (2, 200)]));
        assert_eq!(
            note_deploy_wallet_action_observation(receipt)
                .expect("exact current wallet state must be usable"),
            NoteDeployWalletActionObservation {
                transaction_hash: "tx38".to_string(),
                aborted: true,
                action_result_code: 38,
                outmsg_count: 0,
                wallet_ecc_balances: Some(vec![(1, 100), (2, 200)]),
            }
        );
    }

    #[test]
    fn note_deploy_wallet_receipt_rejects_absent_or_stale_effect_state() {
        let complete = CorrelatedActionReceipt {
            message_hash: "abcd".to_string(),
            transaction_hash: Some("tx38".to_string()),
            aborted: Some(true),
            compute_exit_code: Some(0),
            action_success: Some(false),
            result_code: Some(38),
            no_funds: Some(true),
            outmsg_count: Some(0),
            account_latest_transaction_hash: Some("tx38".to_string()),
            account_ecc_balances: Some(vec![(1, 100), (2, 200)]),
        };
        let mut missing_latest_transaction = complete.clone();
        missing_latest_transaction.account_latest_transaction_hash = None;
        let mut advanced_account = complete.clone();
        advanced_account.account_latest_transaction_hash = Some("tx39".to_string());
        let mut missing_outmsg_count = complete.clone();
        missing_outmsg_count.outmsg_count = None;
        for (case, receipt, expected) in [
            (
                "missing latest transaction",
                missing_latest_transaction,
                "no latest wallet transaction hash",
            ),
            ("advanced account", advanced_account, "stale or advanced"),
            (
                "missing outmsg count",
                missing_outmsg_count,
                "no outbound-message count",
            ),
        ] {
            let error = note_deploy_wallet_action_observation(receipt)
                .expect_err("incomplete or non-current effect state must fail closed");
            assert!(error.to_string().contains(expected), "{case}: {error:#}");
        }
    }

    #[test]
    fn note_deploy_rootpn_receipt_surfaces_exact_compute_403_without_action_phase() {
        let receipt = note_deploy_rootpn_action_observation(CorrelatedActionReceipt {
            message_hash: "abcd".to_string(),
            transaction_hash: Some("tx403".to_string()),
            aborted: Some(true),
            compute_exit_code: Some(403),
            ..Default::default()
        })
        .expect("compute abort is an exact finalized RootPN observation");

        assert_eq!(
            receipt,
            NoteDeployRootPnActionObservation {
                transaction_hash: "tx403".to_string(),
                compute_exit_code: 403,
                aborted: true,
                action_result_code: None,
            }
        );
    }

    #[test]
    fn note_deploy_success_observation_allows_eventually_indexed_ecc_state() {
        let receipt = CorrelatedActionReceipt {
            message_hash: "abcd".to_string(),
            transaction_hash: Some("tx38".to_string()),
            aborted: Some(false),
            compute_exit_code: Some(0),
            action_success: Some(true),
            result_code: Some(0),
            no_funds: Some(false),
            outmsg_count: Some(3),
            account_latest_transaction_hash: Some("tx38".to_string()),
            account_ecc_balances: None,
        };
        let observation = note_deploy_wallet_action_observation(receipt)
            .expect("successful action continues to downstream VoucherGenerated confirmation");

        assert_eq!(observation.transaction_hash, "tx38");
        assert_eq!(observation.wallet_ecc_balances, None);
    }

    #[test]
    fn exact_message_receipt_rejects_wrong_destination_account_or_dapp() {
        const TARGET: &str = "1111111111111111111111111111111111111111111111111111111111111111";
        let base = json!({
            "data": {"blockchain": {
                "message": {
                    "id": "abcd",
                    "dst": TARGET,
                    "dst_transaction": {
                        "id": "tx38", "status": 3, "aborted": true,
                        "account_addr": TARGET,
                        "compute": {"exit_code": 0, "success": true},
                        "action": {"result_code": 38, "success": false, "no_funds": true}
                    }
                },
                "account": {"info": {"id": TARGET, "dapp_id": "04"}}
            }}
        });
        for (case, mut raw) in [
            ("destination", base.clone()),
            ("transaction account", base.clone()),
            ("account", base.clone()),
            ("dapp", base),
        ] {
            let replacement = Value::String("22".repeat(32));
            match case {
                "destination" => raw["data"]["blockchain"]["message"]["dst"] = replacement,
                "transaction account" => {
                    raw["data"]["blockchain"]["message"]["dst_transaction"]["account_addr"] =
                        replacement
                }
                "account" => raw["data"]["blockchain"]["account"]["info"]["id"] = replacement,
                "dapp" => {
                    raw["data"]["blockchain"]["account"]["info"]["dapp_id"] =
                        Value::String("05".to_string())
                }
                _ => unreachable!(),
            }
            let error = parse_exact_destination_receipt(&raw, TARGET, "04", "abcd")
                .expect_err("mismatched receipt must fail closed");
            assert!(error.to_string().contains("mismatch"), "{case}: {error:#}");
        }
    }

    #[tokio::test]
    async fn exact_message_receipt_poller_crosses_pending_states_to_one_final_receipt() {
        use std::collections::VecDeque;
        use std::sync::{Arc, Mutex};

        const TARGET: &str = "1111111111111111111111111111111111111111111111111111111111111111";
        const DAPP: &str = "04";
        const HASH: &str = "abcd";
        let responses = Arc::new(Mutex::new(VecDeque::from([
            json!({"data": {"blockchain": {
                "message": {"id": HASH, "dst": TARGET, "dst_transaction": null},
                "account": {"info": null}
            }}}),
            json!({"data": {"blockchain": {
                "message": {
                    "id": HASH, "dst": TARGET,
                    "dst_transaction": {"status": 1}
                },
                "account": {"info": null}
            }}}),
            json!({"data": {"blockchain": {
                "message": {
                    "id": HASH,
                    "dst": TARGET,
                    "dst_transaction": {
                        "id": "tx38", "status": 3, "aborted": true,
                        "account_addr": TARGET,
                        "compute": {"exit_code": 0, "success": true},
                        "action": {"result_code": 38, "success": false, "no_funds": true}
                    }
                },
                "account": {"info": {"id": TARGET, "dapp_id": DAPP}}
            }}}),
        ])));
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let query = {
            let responses = Arc::clone(&responses);
            let reads = Arc::clone(&reads);
            move || {
                let responses = Arc::clone(&responses);
                let reads = Arc::clone(&reads);
                async move {
                    reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(responses
                        .lock()
                        .expect("scripted response lock")
                        .pop_front()
                        .expect("poller must not exceed the three scripted reads"))
                }
            }
        };

        let receipt = poll_finalized_destination_receipt_with(
            TARGET,
            DAPP,
            HASH,
            query,
            std::time::Duration::ZERO,
        )
        .await
        .expect("pending reads must not abort the poller")
        .expect("third read must return the finalized correlated receipt");

        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert!(responses.lock().expect("scripted response lock").is_empty());
        assert_eq!(
            receipt,
            CorrelatedActionReceipt {
                message_hash: HASH.to_string(),
                transaction_hash: Some("tx38".to_string()),
                aborted: Some(true),
                compute_exit_code: Some(0),
                action_success: Some(false),
                result_code: Some(38),
                no_funds: Some(true),
                ..Default::default()
            }
        );
    }

    #[tokio::test]
    async fn exact_message_receipt_poller_does_not_retry_malformed_finalized_receipt() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let reads = Arc::new(AtomicUsize::new(0));
        let query = {
            let reads = Arc::clone(&reads);
            move || {
                let reads = Arc::clone(&reads);
                async move {
                    reads.fetch_add(1, Ordering::SeqCst);
                    Ok(json!({"data": {"blockchain": {
                        "message": {
                            "id": "abcd", "dst": "11",
                            "dst_transaction": {"status": 3}
                        },
                        "account": {"info": {"id": "11", "dapp_id": "04"}}
                    }}}))
                }
            }
        };

        let error = poll_finalized_destination_receipt_with(
            "11",
            "04",
            "abcd",
            query,
            std::time::Duration::ZERO,
        )
        .await
        .expect_err("malformed finalized receipt must terminate fail-closed");

        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert!(error.to_string().contains("has no account"), "{error:#}");
    }

    fn encode_token_contract_event(name: &str, fields: Value) -> String {
        use tvm_abi::token::Tokenizer;
        use tvm_abi::{Contract, TokenValue};
        use tvm_types::{BuilderData, IBitstring as _};

        let contract =
            Contract::load(TOKENCONTRACT_ABI.as_bytes()).expect("load TokenContract ABI");
        let event = contract.event(name).expect("TokenContract event by name");
        let tokens =
            Tokenizer::tokenize_all_params(&event.inputs, &fields).expect("tokenize event");
        let mut prefix = BuilderData::new();
        prefix.append_u32(event.get_id()).expect("event selector");
        let builder =
            TokenValue::pack_values_into_chain(&tokens, vec![prefix.into()], &event.abi_version)
                .expect("encode event body");
        let cell = builder.into_cell().expect("event cell");
        base64::engine::general_purpose::STANDARD
            .encode(tvm_types::write_boc(&cell).expect("event BOC"))
    }

    fn encode_event_selector_only(name: &str) -> String {
        use tvm_abi::Contract;
        use tvm_types::{BuilderData, IBitstring as _};

        let contract =
            Contract::load(TOKENCONTRACT_ABI.as_bytes()).expect("load TokenContract ABI");
        let event = contract.event(name).expect("TokenContract event by name");
        let mut body = BuilderData::new();
        body.append_u32(event.get_id()).expect("event selector");
        base64::engine::general_purpose::STANDARD.encode(
            tvm_types::write_boc(&body.into_cell().expect("event cell")).expect("event BOC"),
        )
    }

    fn encode_unknown_event() -> String {
        use tvm_abi::Contract;
        use tvm_types::{BuilderData, IBitstring as _};

        let contract =
            Contract::load(TOKENCONTRACT_ABI.as_bytes()).expect("load TokenContract ABI");
        let id = (0..u32::MAX)
            .find(|id| contract.event_by_id(*id).is_err())
            .expect("an unknown event id");
        let mut body = BuilderData::new();
        body.append_u32(id).expect("unknown event selector");
        base64::engine::general_purpose::STANDARD.encode(
            tvm_types::write_boc(&body.into_cell().expect("event cell")).expect("event BOC"),
        )
    }

    fn deployed(endpoint_field: &str) -> Deployed {
        serde_json::from_str(&format!(
            r#"{{
                "network": "shellnet",
                "superroot": "0:{zeros}",
                "dapp_config": "0:{zeros}",
                "dapp_id": "{zeros}"
                {endpoint_field}
            }}"#,
            zeros = "0".repeat(64),
        ))
        .unwrap()
    }

    #[test]
    fn endpoint_default_is_shellnet_when_unset() {
        let endpoint = resolve_endpoint(None, &deployed("")).unwrap();
        assert_eq!(endpoint, crate::params::DEFAULT_SHELLNET_ENDPOINT);
        assert_eq!(
            endpoint_urls(&endpoint).unwrap(),
            (
                "https://shellnet.ackinacki.org/graphql".into(),
                "https://shellnet.ackinacki.org/v2/account".into(),
            )
        );
    }

    #[cfg(feature = "test-giver")]
    #[tokio::test]
    async fn full_ext_in_boc_decodes_place_inference_buy_when_body_projection_is_absent() {
        let note =
            Address::parse("0:1111111111111111111111111111111111111111111111111111111111111111")
                .expect("note");
        let keys = KeyPair::from_secret_hex(&"22".repeat(32)).expect("owner key");
        let boc = RealChainBackend::encode_signed_call_boc(
            &note,
            PRIVATENOTE_ABI,
            "placeInferenceBuy",
            json!({
                "modelHash": format!("0x{}", "33".repeat(32)),
                "maxPricePerTick": "7",
                "ticks": "2",
                "escrow": "14",
                "flags": 0,
                "deadline": "0",
            }),
            &keys,
        )
        .await
        .expect("encode owner-signed placeInferenceBuy");

        let decoded = decode_external_abi_message_boc(&boc, PRIVATENOTE_ABI, true)
            .expect("decode placeInferenceBuy from the full indexed message BOC");
        assert_eq!(decoded.function_name, "placeInferenceBuy");
        assert_eq!(decoded_u128(&decoded.tokens, "maxPricePerTick"), Some(7));
        assert_eq!(decoded_u128(&decoded.tokens, "ticks"), Some(2));
        assert_eq!(decoded_u128(&decoded.tokens, "escrow"), Some(14));
    }

    async fn read_fixture_http_request(socket: &mut tokio::net::TcpStream) -> String {
        let mut request = Vec::new();
        loop {
            socket.read_buf(&mut request).await.unwrap();
            let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                continue;
            };
            let content_length = String::from_utf8_lossy(&request[..header_end])
                .to_ascii_lowercase()
                .lines()
                .find_map(|line| line.strip_prefix("content-length:")?.trim().parse().ok())
                .unwrap_or(0);
            if request.len() >= header_end + 4 + content_length {
                break;
            }
        }
        String::from_utf8(request).unwrap()
    }

    #[cfg(feature = "test-giver")]
    #[tokio::test]
    async fn live_acceptance_submit_payloads_match_vendored_abis_exactly() {
        let address =
            Address::parse("0:1111111111111111111111111111111111111111111111111111111111111111")
                .expect("address");
        let keys = KeyPair::from_secret_hex(&"22".repeat(32)).expect("signer");
        let (backend, posts, posted_bocs, server) = skew_fixture_backend(0).await;

        backend.resolve_dispute_timeout(&address).await.unwrap();
        backend
            .submit_pmp_cancel_event(&address, &keys)
            .await
            .unwrap();
        backend
            .delete_oracle_event(&address, &keys, "22")
            .await
            .unwrap();

        assert_eq!(posts.load(Ordering::SeqCst), 3);
        let posted_bocs = posted_bocs.lock().unwrap().clone();
        assert_eq!(posted_bocs.len(), 3, "one POST per production method");
        for (boc, (abi, method, expected_field)) in posted_bocs.iter().zip([
            (TOKENCONTRACT_ABI, "resolveDisputeTimeout", None),
            (PMP_ABI, "submitCancelEvent", None),
            (ORACLEEVENTLIST_ABI, "deleteEvent", Some(("eventId", 22))),
        ]) {
            let decoded = decode_external_abi_message_boc(&boc, abi, true)
                .unwrap_or_else(|| panic!("decode {method}"));
            assert_eq!(decoded.function_name, method);
            if let Some((field, value)) = expected_field {
                assert_eq!(decoded_u128(&decoded.tokens, field), Some(value));
            } else {
                assert!(decoded.tokens.is_empty(), "{method} must have no inputs");
            }
        }
        assert!(backend.oracle_event_info(&address, "22").await.is_err());
        server.abort();
    }

    #[test]
    fn settlement_receipts_decode_current_ordinary_claim_sequence_in_chain_order() {
        let buyer = format!("0:{}", "44".repeat(32));
        let message = |id: &str, created_at: u64, event: &str, fields: Value| ExtOutMessage {
            id: id.to_string(),
            created_at,
            cursor: format!("opaque-{id}"),
            body: encode_token_contract_event(event, fields),
        };
        let receipts = decode_token_contract_settlement_receipts(vec![
            message(
                "accepted",
                10,
                "ProbeAccepted",
                json!({
                    "buyer": buyer,
                    "toSeller": "1",
                    "bondReturned": "0",
                }),
            ),
            message(
                "claim-z",
                20,
                "TicksClaimed",
                json!({"trusted": "1", "claimed": "2"}),
            ),
            // Same-second events deliberately use lexically descending opaque cursors. Their
            // supplied chain order must survive unchanged.
            message(
                "claim-a",
                20,
                "TicksClaimed",
                json!({"trusted": "1", "claimed": "3"}),
            ),
            message(
                "stop",
                40,
                "StreamStopped",
                json!({
                    "buyer": buyer,
                    "toSeller": "0",
                    "refundToBuyer": "0",
                }),
            ),
        ])
        .expect("decode exact settlement lifecycle");

        assert_eq!(
            receipts.events,
            vec![
                TokenContractSettlementReceipt {
                    message_id: "accepted".to_string(),
                    created_at: 10,
                    cursor: "opaque-accepted".to_string(),
                    event: TokenContractSettlementEvent::ProbeAccepted {
                        buyer: buyer.clone(),
                        to_seller: 1,
                        bond_returned: 0,
                    },
                },
                TokenContractSettlementReceipt {
                    message_id: "claim-z".to_string(),
                    created_at: 20,
                    cursor: "opaque-claim-z".to_string(),
                    event: TokenContractSettlementEvent::TicksClaimed {
                        trusted: 1,
                        claimed: 2,
                    },
                },
                TokenContractSettlementReceipt {
                    message_id: "claim-a".to_string(),
                    created_at: 20,
                    cursor: "opaque-claim-a".to_string(),
                    event: TokenContractSettlementEvent::TicksClaimed {
                        trusted: 1,
                        claimed: 3,
                    },
                },
                TokenContractSettlementReceipt {
                    message_id: "stop".to_string(),
                    created_at: 40,
                    cursor: "opaque-stop".to_string(),
                    event: TokenContractSettlementEvent::StreamStopped {
                        buyer,
                        to_seller: 0,
                        refund_to_buyer: 0,
                    },
                },
            ]
        );
    }

    fn test_action_receipt(
        id: &str,
        created_at: u64,
        event: TokenContractSettlementEvent,
    ) -> TokenContractSettlementReceipt {
        TokenContractSettlementReceipt {
            message_id: id.to_string(),
            created_at,
            cursor: format!("opaque-{id}"),
            event,
        }
    }

    fn test_pre_bonds() -> SettlementActionBondState {
        SettlementActionBondState {
            seller_bond_held: 20u128.into(),
            seller_bond_required: 20u128.into(),
            buyer_bond_held: 0u128.into(),
            buyer_bond_required: 0u128.into(),
        }
    }

    #[test]
    fn action_selector_accepts_each_exact_action_event_and_rejects_other_action_events() {
        let buyer = format!("0:{}", "44".repeat(32));
        let candidates = [
            TokenContractSettlementEvent::ProbeBurned {
                buyer: buyer.clone(),
                burned_probe: 1,
                burned_bond: 2,
                refund_to_buyer: 3,
            },
            TokenContractSettlementEvent::StreamStopped {
                buyer: buyer.clone(),
                to_seller: 4,
                refund_to_buyer: 5,
            },
            TokenContractSettlementEvent::StreamDisputed {
                buyer: buyer.clone(),
                at: 6,
            },
            TokenContractSettlementEvent::DisputeResolved {
                to_seller: 7,
                refund_to_buyer: 8,
                released: true,
            },
            TokenContractSettlementEvent::DisputeResolved {
                to_seller: 9,
                refund_to_buyer: 10,
                released: false,
            },
        ];
        let cases = [
            (
                SettlementAction::BuyerStop,
                ExpectedSettlementEvent::ProbeBurned,
                0,
            ),
            (
                SettlementAction::BuyerStop,
                ExpectedSettlementEvent::StreamStopped,
                1,
            ),
            (
                SettlementAction::SellerStop,
                ExpectedSettlementEvent::StreamStopped,
                1,
            ),
            (
                SettlementAction::Dispute,
                ExpectedSettlementEvent::StreamDisputed,
                2,
            ),
            (
                SettlementAction::ReleaseDispute,
                ExpectedSettlementEvent::DisputeResolved { released: true },
                3,
            ),
            (
                SettlementAction::ResolveDisputeTimeout,
                ExpectedSettlementEvent::DisputeResolved { released: false },
                4,
            ),
        ];

        for (action, expected, accepted_index) in cases {
            for (candidate_index, candidate) in candidates.iter().cloned().enumerate() {
                let observed = TokenContractSettlementReceipts {
                    events: vec![test_action_receipt("new-action", 1, candidate)],
                };
                let selected = select_new_settlement_action_receipt(
                    "0:tc",
                    action,
                    expected,
                    matches!(
                        action,
                        SettlementAction::BuyerStop
                            | SettlementAction::SellerStop
                            | SettlementAction::Dispute
                    )
                    .then_some(buyer.as_str()),
                    &observed,
                    test_pre_bonds(),
                );
                if candidate_index == accepted_index {
                    let receipt = selected
                        .unwrap_or_else(|error| panic!("{action}: {error:#}"))
                        .unwrap();
                    assert_eq!(receipt.message_id, "new-action");
                    assert_eq!(receipt.pre_bonds, test_pre_bonds());
                    match &receipt.event {
                        SettlementActionEvent::ProbeBurned { buyer: actor, .. }
                        | SettlementActionEvent::StreamStopped { buyer: actor, .. }
                        | SettlementActionEvent::StreamDisputed { buyer: actor, .. } => {
                            assert_eq!(actor, &buyer, "receipt must preserve the decoded actor")
                        }
                        SettlementActionEvent::DisputeResolved { .. } => {}
                    }
                } else {
                    assert!(
                        selected.is_err(),
                        "{action} must reject incompatible action event {candidate_index}"
                    );
                }
            }
        }
    }

    #[test]
    fn action_selector_rejects_wrong_buyer_actor_for_every_actor_event() {
        let buyer = format!("0:{}", "44".repeat(32));
        let wrong = format!("0:{}", "55".repeat(32));
        let cases = [
            (
                SettlementAction::BuyerStop,
                ExpectedSettlementEvent::ProbeBurned,
                TokenContractSettlementEvent::ProbeBurned {
                    buyer: wrong.clone(),
                    burned_probe: 1,
                    burned_bond: 2,
                    refund_to_buyer: 3,
                },
            ),
            (
                SettlementAction::BuyerStop,
                ExpectedSettlementEvent::StreamStopped,
                TokenContractSettlementEvent::StreamStopped {
                    buyer: wrong.clone(),
                    to_seller: 4,
                    refund_to_buyer: 5,
                },
            ),
            (
                SettlementAction::SellerStop,
                ExpectedSettlementEvent::StreamStopped,
                TokenContractSettlementEvent::StreamStopped {
                    buyer: wrong.clone(),
                    to_seller: 6,
                    refund_to_buyer: 7,
                },
            ),
            (
                SettlementAction::Dispute,
                ExpectedSettlementEvent::StreamDisputed,
                TokenContractSettlementEvent::StreamDisputed {
                    buyer: wrong,
                    at: 8,
                },
            ),
        ];

        for (action, expected, event) in cases {
            let error = select_new_settlement_action_receipt(
                "0:tc",
                action,
                expected,
                Some(&buyer),
                &TokenContractSettlementReceipts {
                    events: vec![test_action_receipt("wrong-actor", 1, event)],
                },
                test_pre_bonds(),
            )
            .expect_err("wrong buyer actor must fail closed before receipt success");
            assert!(
                error.to_string().contains("wrong buyer actor"),
                "{action}: {error:#}"
            );
        }
    }

    #[test]
    fn action_selector_allows_ordered_auxiliary_tick_before_one_terminal_event() {
        let buyer = format!("0:{}", "44".repeat(32));
        let observed = TokenContractSettlementReceipts {
            events: vec![
                test_action_receipt(
                    "tick",
                    1,
                    TokenContractSettlementEvent::TickFinalized {
                        finalized_owed: 11,
                        deposit: 12,
                    },
                ),
                test_action_receipt(
                    "stop",
                    2,
                    TokenContractSettlementEvent::StreamStopped {
                        buyer: buyer.clone(),
                        to_seller: 11,
                        refund_to_buyer: 12,
                    },
                ),
            ],
        };
        let receipt = select_new_settlement_action_receipt(
            "0:tc",
            SettlementAction::BuyerStop,
            ExpectedSettlementEvent::StreamStopped,
            Some(&buyer),
            &observed,
            test_pre_bonds(),
        )
        .expect("auxiliary event is allowed")
        .expect("one exact action event");
        assert_eq!(receipt.message_id, "stop");
    }

    #[test]
    fn action_selector_rejects_concurrent_duplicate_or_conflicting_action_events() {
        let buyer = format!("0:{}", "44".repeat(32));
        for second in [
            TokenContractSettlementEvent::StreamStopped {
                buyer: buyer.clone(),
                to_seller: 1,
                refund_to_buyer: 2,
            },
            TokenContractSettlementEvent::DisputeResolved {
                to_seller: 1,
                refund_to_buyer: 2,
                released: true,
            },
        ] {
            let observed = TokenContractSettlementReceipts {
                events: vec![
                    test_action_receipt(
                        "stop-one",
                        1,
                        TokenContractSettlementEvent::StreamStopped {
                            buyer: buyer.clone(),
                            to_seller: 1,
                            refund_to_buyer: 2,
                        },
                    ),
                    test_action_receipt("action-two", 2, second),
                ],
            };
            let error = select_new_settlement_action_receipt(
                "0:tc",
                SettlementAction::BuyerStop,
                ExpectedSettlementEvent::StreamStopped,
                Some(&buyer),
                &observed,
                test_pre_bonds(),
            )
            .expect_err("two new action events are ambiguous");
            assert!(error.to_string().contains("2 distinct new action events"));
        }
    }

    #[test]
    fn receipt_snapshot_excludes_old_terminal_and_keeps_new_chain_order() {
        let buyer = "0:buyer".to_string();
        let old = test_action_receipt(
            "old-stop",
            1,
            TokenContractSettlementEvent::StreamStopped {
                buyer: buyer.clone(),
                to_seller: 1,
                refund_to_buyer: 2,
            },
        );
        let tick = test_action_receipt(
            "tick",
            2,
            TokenContractSettlementEvent::TickFinalized {
                finalized_owed: 3,
                deposit: 4,
            },
        );
        let new = test_action_receipt(
            "new-stop",
            3,
            TokenContractSettlementEvent::StreamStopped {
                buyer,
                to_seller: 3,
                refund_to_buyer: 4,
            },
        );
        let after = settlement_receipts_after_snapshot(
            &TokenContractSettlementReceipts {
                events: vec![old.clone()],
            },
            TokenContractSettlementReceipts {
                events: vec![old, tick.clone(), new.clone()],
            },
        )
        .expect("immutable pre-submit identities exclude old events");
        assert_eq!(after.events, vec![tick, new]);
    }

    #[test]
    fn receipt_snapshot_rejects_changed_pre_submit_identity() {
        let before = test_action_receipt(
            "same-id",
            1,
            TokenContractSettlementEvent::TickFinalized {
                finalized_owed: 1,
                deposit: 2,
            },
        );
        let mut changed = before.clone();
        changed.cursor = "changed-opaque-cursor".to_string();
        let error = settlement_receipts_after_snapshot(
            &TokenContractSettlementReceipts {
                events: vec![before],
            },
            TokenContractSettlementReceipts {
                events: vec![changed],
            },
        )
        .expect_err("an old event identity cannot mutate across the POST");
        assert!(error.to_string().contains("changed"));
    }

    #[test]
    fn receipt_snapshot_rejects_disappearance_reorder_and_late_old_event() {
        let buyer = "0:buyer".to_string();
        let first = test_action_receipt(
            "baseline-first",
            10,
            TokenContractSettlementEvent::TickFinalized {
                finalized_owed: 1,
                deposit: 2,
            },
        );
        let second = test_action_receipt(
            "baseline-second",
            11,
            TokenContractSettlementEvent::ProbeAccepted {
                buyer: buyer.clone(),
                to_seller: 1,
                bond_returned: 2,
            },
        );
        let late_old = test_action_receipt(
            "late-indexed-old-stop",
            1,
            TokenContractSettlementEvent::StreamStopped {
                buyer,
                to_seller: 1,
                refund_to_buyer: 2,
            },
        );
        let before = TokenContractSettlementReceipts {
            events: vec![first.clone(), second.clone()],
        };

        for (case, current) in [
            ("disappearance", vec![first.clone()]),
            ("reorder", vec![second.clone(), first.clone()]),
            (
                "late-old insertion",
                vec![late_old, first.clone(), second.clone()],
            ),
        ] {
            let error = settlement_receipts_after_snapshot(
                &before,
                TokenContractSettlementReceipts { events: current },
            )
            .expect_err("post history must preserve the exact baseline as its prefix");
            assert!(
                error.to_string().contains("append-only extension"),
                "{case} escaped append-only history validation: {error:#}"
            );
        }
    }

    #[test]
    fn confirmation_delay_never_exceeds_the_shared_remaining_budget() {
        let timeout = std::time::Duration::from_secs(5);
        let poll = std::time::Duration::from_secs(2);
        assert_eq!(
            settlement_confirmation_delay(std::time::Duration::ZERO, timeout, poll),
            Some(std::time::Duration::from_secs(2))
        );
        assert_eq!(
            settlement_confirmation_delay(std::time::Duration::from_secs(2), timeout, poll),
            Some(std::time::Duration::from_secs(2))
        );
        assert_eq!(
            settlement_confirmation_delay(std::time::Duration::from_secs(4), timeout, poll),
            Some(std::time::Duration::from_secs(1))
        );
        assert_eq!(
            settlement_confirmation_delay(std::time::Duration::from_secs(5), timeout, poll),
            None
        );
        assert_eq!(
            settlement_confirmation_delay(std::time::Duration::from_secs(6), timeout, poll),
            None
        );
    }

    #[test]
    fn settlement_receipts_fail_closed_on_malformed_known_event_and_skip_unknown() {
        let error = decode_token_contract_settlement_receipts(vec![ExtOutMessage {
            id: "malformed-stop".to_string(),
            created_at: 1,
            cursor: "cursor-malformed".to_string(),
            body: encode_event_selector_only("StreamStopped"),
        }])
        .expect_err("known selector with malformed payload must fail closed");
        let message = format!("{error:#}");
        assert!(message.contains("StreamStopped"), "{message}");
        assert!(message.contains("malformed-stop"), "{message}");

        let receipts = decode_token_contract_settlement_receipts(vec![
            ExtOutMessage {
                id: "unknown".to_string(),
                created_at: 1,
                cursor: "cursor-unknown".to_string(),
                body: encode_unknown_event(),
            },
            ExtOutMessage {
                id: "not-an-event".to_string(),
                created_at: 2,
                cursor: "cursor-other".to_string(),
                body: "not-base64".to_string(),
            },
        ])
        .expect("unknown/non-event bodies are not lifecycle claims");
        assert!(receipts.events.is_empty());
    }

    #[test]
    fn settlement_receipts_deduplicate_identical_overlap_and_reject_conflict() {
        let buyer = format!("0:{}", "44".repeat(32));
        let message = ExtOutMessage {
            id: "same-message".to_string(),
            created_at: 1,
            cursor: "same-cursor".to_string(),
            body: encode_token_contract_event(
                "StreamStopped",
                json!({"buyer": buyer, "toSeller": "1", "refundToBuyer": "2"}),
            ),
        };
        let receipts =
            decode_token_contract_settlement_receipts(vec![message.clone(), message.clone()])
                .expect("identical overlapping pages deduplicate");
        assert_eq!(receipts.events.len(), 1);

        let mut conflicting = message.clone();
        conflicting.cursor = "different-cursor".to_string();
        let error = decode_token_contract_settlement_receipts(vec![message, conflicting])
            .expect_err("same id with changed order/body must fail closed");
        assert!(
            error
                .to_string()
                .contains("changed across overlapping pages"),
            "{error:#}"
        );
    }

    fn test_deal_state(opened: bool, disputed: bool, finalized_owed: u128) -> DealChainState {
        DealChainState {
            funded: true,
            opened,
            probe_accepted: true,
            disputed,
            deposit: if opened { 100 } else { 0 },
            finalized_owed,
            tokens_final: 1_000_001,
            tokens_superseded: 1_000_002,
            tokens_pending: 1_000_003,
            probe_tick: 0,
            funded_time: Some(1),
            probe_time: 2,
            prev_claim_time: 3,
            last_claim_time: 4,
            dispute_time: if disputed { 5 } else { 0 },
        }
    }

    fn test_subscription(is_subscription: bool) -> DealSubscription {
        DealSubscription {
            deal_flags: if is_subscription {
                crate::chain::flags::SUBSCRIPTION
            } else {
                0
            },
            sub_weeks: if is_subscription {
                SUBSCRIPTION_WEEKS
            } else {
                0
            },
            week_index: 0,
            tokens_per_week: 4_000_000,
            funded_tokens: 4_000_000,
            tokens_paid: 0,
            period_start: 1,
            week_base_tokens: 0,
        }
    }

    fn test_deal_snapshot(
        boc: &str,
        opened: bool,
        disputed: bool,
        finalized_owed: u128,
        seller_bond_held: u128,
    ) -> DealChainSnapshot {
        test_deal_snapshot_with_buyer_bond(
            boc,
            opened,
            disputed,
            finalized_owed,
            seller_bond_held,
            0,
            0,
        )
    }

    fn test_deal_snapshot_with_buyer_bond(
        boc: &str,
        opened: bool,
        disputed: bool,
        finalized_owed: u128,
        seller_bond_held: u128,
        buyer_bond_held: u128,
        buyer_bond_required: u128,
    ) -> DealChainSnapshot {
        DealChainSnapshot {
            account_code_hash: "code".to_string(),
            account_boc_hash: boc.to_string(),
            state: test_deal_state(opened, disputed, finalized_owed),
            subscription: test_subscription(buyer_bond_required != 0),
            seller_bond: DealSellerBond {
                bond_funded: true,
                bond_held: seller_bond_held,
                bond_required: 20,
            },
            buyer_bond: DealBuyerBond {
                bond_held: buyer_bond_held,
                bond_required: buyer_bond_required,
            },
        }
    }

    #[test]
    fn action_post_state_rejects_event_getter_contradiction_and_preserves_raw_tokens() {
        let pre = test_deal_snapshot("pre", true, false, 0, 20);
        let post = test_deal_snapshot("post", false, false, u64::MAX as u128 + 1, 0);
        let contradiction = TokenContractSettlementEvent::StreamStopped {
            buyer: "0:buyer".to_string(),
            to_seller: u64::MAX as u128 + 2,
            refund_to_buyer: u128::MAX,
        };
        let error = settlement_action_post_state("0:tc", &pre, &post, &contradiction)
            .expect_err("event/getter mismatch fails closed");
        assert!(error.to_string().contains("event/getter contradiction"));

        let exact = TokenContractSettlementEvent::StreamStopped {
            buyer: "0:buyer".to_string(),
            to_seller: u64::MAX as u128 + 1,
            refund_to_buyer: u128::MAX,
        };
        let state = settlement_action_post_state("0:tc", &pre, &post, &exact)
            .expect("exact raw uint128 facts agree");
        assert_eq!(state.tokens_final.0, 1_000_001);
    }

    #[test]
    fn terminal_post_state_rejects_funded_deposit_and_probe_mutations() {
        let pre = test_deal_snapshot("pre", true, false, 0, 20);
        let post = test_deal_snapshot("post", false, false, 7, 0);
        let stopped = TokenContractSettlementEvent::StreamStopped {
            buyer: "0:buyer".to_string(),
            to_seller: 7,
            refund_to_buyer: 8,
        };
        settlement_action_post_state("0:tc", &pre, &post, &stopped)
            .expect("canonical active terminal getter state is stopped");

        let mut mutations = Vec::new();
        let mut changed = post.clone();
        changed.state.funded = false;
        mutations.push(("funded", changed));
        let mut changed = post.clone();
        changed.state.deposit = 1;
        mutations.push(("deposit", changed));
        let mut changed = post;
        changed.state.probe_tick = 1;
        mutations.push(("probeTick", changed));

        for (field, changed) in mutations {
            let error = settlement_action_post_state("0:tc", &pre, &changed, &stopped).unwrap_err();
            assert!(
                error.to_string().contains("terminal event contradicts"),
                "{field} mutation escaped: {error:#}"
            );
        }
    }

    #[test]
    fn stream_disputed_proves_all_money_tokens_and_separate_bonds_unchanged() {
        let pre = test_deal_snapshot_with_buyer_bond("pre", true, false, 17, 20, 20, 20);
        let post = test_deal_snapshot_with_buyer_bond("post", true, true, 17, 20, 20, 20);
        let disputed = TokenContractSettlementEvent::StreamDisputed {
            buyer: "0:buyer".to_string(),
            at: 5,
        };
        settlement_action_post_state("0:tc", &pre, &post, &disputed)
            .expect("only disputed/disputeTime changed");

        let mut mutations = Vec::new();
        let mut changed = post.clone();
        changed.state.deposit += 1;
        mutations.push(("deposit", changed));
        let mut changed = post.clone();
        changed.state.finalized_owed += 1;
        mutations.push(("finalizedOwed", changed));
        let mut changed = post.clone();
        changed.state.tokens_final += 1;
        mutations.push(("tokensFinal", changed));
        let mut changed = post.clone();
        changed.state.tokens_superseded += 1;
        mutations.push(("tokensSuperseded", changed));
        let mut changed = post.clone();
        changed.state.tokens_pending += 1;
        mutations.push(("tokensPending", changed));
        let mut changed = post.clone();
        changed.seller_bond.bond_held -= 1;
        mutations.push(("sellerBondHeld", changed));
        let mut changed = post.clone();
        changed.buyer_bond.bond_held -= 1;
        mutations.push(("buyerBondHeld", changed));
        let mut changed = post.clone();
        changed.subscription.tokens_paid += 1;
        mutations.push(("subscription", changed));

        for (field, changed) in mutations {
            let error =
                settlement_action_post_state("0:tc", &pre, &changed, &disputed).unwrap_err();
            assert!(
                error.to_string().contains("only disputed/disputeTime"),
                "{field} mutation escaped: {error:#}"
            );
        }
    }

    #[tokio::test]
    async fn lost_post_response_reconciles_one_landed_event_without_second_post() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let posts = Arc::new(AtomicUsize::new(0));
        let posts_for_submit = posts.clone();
        let pre = test_deal_snapshot("pre", true, false, 0, 20);
        let post = test_deal_snapshot("post", false, false, 7, 0);
        let observed = TokenContractSettlementReceipts {
            events: vec![test_action_receipt(
                "landed-stop",
                7,
                TokenContractSettlementEvent::StreamStopped {
                    buyer: format!("0:{}", "44".repeat(32)),
                    to_seller: 7,
                    refund_to_buyer: 8,
                },
            )],
        };
        let observed_for_read = observed.clone();
        let post_for_read = post.clone();

        let receipt = reconcile_settlement_action_after_post(
            "0:tc",
            SettlementAction::BuyerStop,
            ExpectedSettlementEvent::StreamStopped,
            Some(&format!("0:{}", "44".repeat(32))),
            &TokenContractSettlementReceipts::default(),
            &pre,
            std::time::Duration::from_millis(100),
            std::time::Duration::from_millis(1),
            std::time::Duration::from_millis(5),
            move || async move {
                posts_for_submit.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                Ok(())
            },
            move || {
                let observed = observed_for_read.clone();
                async move { Ok(observed) }
            },
            move || async move { Ok(Some(post_for_read)) },
        )
        .await
        .expect("lost response must reconcile the landed event");
        assert_eq!(receipt.message_id, "landed-stop");
        assert_eq!(posts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn no_event_until_confirmation_budget_is_ambiguous_and_posts_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let posts = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(AtomicUsize::new(0));
        let posts_for_submit = posts.clone();
        let reads_for_observe = reads.clone();
        let pre = test_deal_snapshot("pre", true, false, 0, 20);
        let error = reconcile_settlement_action_after_post(
            "0:tc",
            SettlementAction::BuyerStop,
            ExpectedSettlementEvent::StreamStopped,
            Some(&format!("0:{}", "44".repeat(32))),
            &TokenContractSettlementReceipts::default(),
            &pre,
            std::time::Duration::from_millis(25),
            std::time::Duration::from_millis(2),
            std::time::Duration::from_millis(5),
            move || async move {
                posts_for_submit.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            move || {
                reads_for_observe.fetch_add(1, Ordering::SeqCst);
                async { Ok(TokenContractSettlementReceipts::default()) }
            },
            || async { Ok(None) },
        )
        .await
        .expect_err("absence inside the bounded wait is never success");
        assert!(matches!(
            explicit_money_submit_outcome(&error),
            Some(MoneySubmitError::Ambiguous { .. })
        ));
        assert_eq!(posts.load(Ordering::SeqCst), 1);
        assert!(reads.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn post_event_read_wrong_or_multiple_event_is_ambiguous_and_never_reposts() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        async fn assert_ambiguous(
            observed: Result<TokenContractSettlementReceipts>,
            expected_error: &str,
        ) {
            let posts = Arc::new(AtomicUsize::new(0));
            let posts_for_submit = posts.clone();
            let pre = test_deal_snapshot("pre", true, false, 0, 20);
            let mut observed = Some(observed);
            let error = reconcile_settlement_action_after_post(
                "0:tc",
                SettlementAction::BuyerStop,
                ExpectedSettlementEvent::StreamStopped,
                Some(&format!("0:{}", "44".repeat(32))),
                &TokenContractSettlementReceipts::default(),
                &pre,
                std::time::Duration::from_millis(100),
                std::time::Duration::from_millis(1),
                std::time::Duration::from_millis(5),
                move || async move {
                    posts_for_submit.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                move || {
                    let observed = observed
                        .take()
                        .expect("failure must stop after one event read");
                    async move { observed }
                },
                || async { Ok(None) },
            )
            .await
            .expect_err("post-submit fact failure cannot be a successful receipt");
            assert!(matches!(
                explicit_money_submit_outcome(&error),
                Some(MoneySubmitError::Ambiguous { .. })
            ));
            assert_eq!(posts.load(Ordering::SeqCst), 1);
            assert!(
                format!("{error:#}").contains(expected_error),
                "missing {expected_error:?} in {error:#}"
            );
        }

        assert_ambiguous(
            Err(anyhow!("malformed TokenContract ext-out")),
            "event read/decode failed",
        )
        .await;
        assert_ambiguous(
            Ok(TokenContractSettlementReceipts {
                events: vec![test_action_receipt(
                    "wrong",
                    1,
                    TokenContractSettlementEvent::StreamDisputed {
                        buyer: "0:buyer".to_string(),
                        at: 1,
                    },
                )],
            }),
            "incompatible",
        )
        .await;
        assert_ambiguous(
            Ok(TokenContractSettlementReceipts {
                events: vec![
                    test_action_receipt(
                        "first",
                        1,
                        TokenContractSettlementEvent::StreamStopped {
                            buyer: "0:buyer".to_string(),
                            to_seller: 1,
                            refund_to_buyer: 2,
                        },
                    ),
                    test_action_receipt(
                        "second",
                        2,
                        TokenContractSettlementEvent::StreamStopped {
                            buyer: "0:buyer".to_string(),
                            to_seller: 1,
                            refund_to_buyer: 2,
                        },
                    ),
                ],
            }),
            "2 distinct new action events",
        )
        .await;
    }

    #[tokio::test]
    async fn wrong_buyer_actor_never_becomes_success_or_reaches_post_state_read() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let buyer = format!("0:{}", "44".repeat(32));
        let wrong = format!("0:{}", "55".repeat(32));
        let cases = [
            (
                SettlementAction::BuyerStop,
                ExpectedSettlementEvent::ProbeBurned,
                TokenContractSettlementEvent::ProbeBurned {
                    buyer: wrong.clone(),
                    burned_probe: 1,
                    burned_bond: 2,
                    refund_to_buyer: 3,
                },
            ),
            (
                SettlementAction::BuyerStop,
                ExpectedSettlementEvent::StreamStopped,
                TokenContractSettlementEvent::StreamStopped {
                    buyer: wrong.clone(),
                    to_seller: 4,
                    refund_to_buyer: 5,
                },
            ),
            (
                SettlementAction::SellerStop,
                ExpectedSettlementEvent::StreamStopped,
                TokenContractSettlementEvent::StreamStopped {
                    buyer: wrong.clone(),
                    to_seller: 6,
                    refund_to_buyer: 7,
                },
            ),
            (
                SettlementAction::Dispute,
                ExpectedSettlementEvent::StreamDisputed,
                TokenContractSettlementEvent::StreamDisputed {
                    buyer: wrong,
                    at: 8,
                },
            ),
        ];

        for (action, expected, event) in cases {
            let observed = TokenContractSettlementReceipts {
                events: vec![test_action_receipt("wrong-actor", 1, event)],
            };
            let observed_for_read = observed.clone();
            let post_reads = Arc::new(AtomicUsize::new(0));
            let post_reads_for_read = post_reads.clone();
            let pre = test_deal_snapshot("pre", true, false, 0, 20);
            let error = reconcile_settlement_action_after_post(
                "0:tc",
                action,
                expected,
                Some(&buyer),
                &TokenContractSettlementReceipts::default(),
                &pre,
                std::time::Duration::from_millis(100),
                std::time::Duration::from_millis(1),
                std::time::Duration::from_millis(5),
                || async { Ok(()) },
                move || {
                    let observed = observed_for_read.clone();
                    async move { Ok(observed) }
                },
                move || async move {
                    post_reads_for_read.fetch_add(1, Ordering::SeqCst);
                    Ok(None)
                },
            )
            .await
            .expect_err("wrong actor cannot produce an authoritative receipt");
            assert!(matches!(
                explicit_money_submit_outcome(&error),
                Some(MoneySubmitError::Ambiguous { .. })
            ));
            assert!(format!("{error:#}").contains("wrong buyer actor"));
            assert_eq!(
                post_reads.load(Ordering::SeqCst),
                0,
                "{action}: selector must fail before any post-state read"
            );
        }
    }

    #[tokio::test]
    async fn terminal_post_state_contradiction_is_ambiguous_and_never_reposts() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let posts = Arc::new(AtomicUsize::new(0));
        let posts_for_submit = posts.clone();
        let pre = test_deal_snapshot("pre", true, false, 0, 20);
        let mut contradicted = test_deal_snapshot("post", false, false, 7, 0);
        contradicted.state.deposit = 1;
        let observed = TokenContractSettlementReceipts {
            events: vec![test_action_receipt(
                "stop",
                5,
                TokenContractSettlementEvent::StreamStopped {
                    buyer: format!("0:{}", "44".repeat(32)),
                    to_seller: 7,
                    refund_to_buyer: 8,
                },
            )],
        };
        let observed_for_read = observed.clone();

        let error = reconcile_settlement_action_after_post(
            "0:tc",
            SettlementAction::BuyerStop,
            ExpectedSettlementEvent::StreamStopped,
            Some(&format!("0:{}", "44".repeat(32))),
            &TokenContractSettlementReceipts::default(),
            &pre,
            std::time::Duration::from_millis(100),
            std::time::Duration::from_millis(1),
            std::time::Duration::from_millis(5),
            move || async move {
                posts_for_submit.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            move || {
                let observed = observed_for_read.clone();
                async move { Ok(observed) }
            },
            move || async move { Ok(Some(contradicted)) },
        )
        .await
        .expect_err("active terminal account with retained deposit must fail closed");
        assert!(matches!(
            explicit_money_submit_outcome(&error),
            Some(MoneySubmitError::Ambiguous { .. })
        ));
        assert_eq!(posts.load(Ordering::SeqCst), 1);
        assert!(format!("{error:#}").contains("terminal event contradicts"));
    }

    #[tokio::test]
    async fn post_event_getter_contradiction_is_ambiguous_and_never_reposts() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let posts = Arc::new(AtomicUsize::new(0));
        let posts_for_submit = posts.clone();
        let pre = test_deal_snapshot_with_buyer_bond("pre", true, false, 17, 20, 20, 20);
        let mut contradicted =
            test_deal_snapshot_with_buyer_bond("post", true, true, 17, 20, 20, 20);
        contradicted.buyer_bond.bond_held = 19;
        let observed = TokenContractSettlementReceipts {
            events: vec![test_action_receipt(
                "dispute",
                5,
                TokenContractSettlementEvent::StreamDisputed {
                    buyer: format!("0:{}", "44".repeat(32)),
                    at: 5,
                },
            )],
        };
        let observed_for_read = observed.clone();

        let error = reconcile_settlement_action_after_post(
            "0:tc",
            SettlementAction::Dispute,
            ExpectedSettlementEvent::StreamDisputed,
            Some(&format!("0:{}", "44".repeat(32))),
            &TokenContractSettlementReceipts::default(),
            &pre,
            std::time::Duration::from_millis(100),
            std::time::Duration::from_millis(1),
            std::time::Duration::from_millis(5),
            move || async move {
                posts_for_submit.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            move || {
                let observed = observed_for_read.clone();
                async move { Ok(observed) }
            },
            move || async move { Ok(Some(contradicted)) },
        )
        .await
        .expect_err("changed subscription buyer bond must fail closed");
        assert!(matches!(
            explicit_money_submit_outcome(&error),
            Some(MoneySubmitError::Ambiguous { .. })
        ));
        assert_eq!(posts.load(Ordering::SeqCst), 1);
        assert!(format!("{error:#}").contains("only disputed/disputeTime"));
    }

    #[test]
    fn terminal_destroy_keeps_event_receipt_but_dispute_requires_active_snapshot() {
        let pre = test_deal_snapshot("pre", true, false, 0, 20);
        let stopped = TokenContractSettlementEvent::StreamStopped {
            buyer: "0:buyer".to_string(),
            to_seller: 7,
            refund_to_buyer: 8,
        };
        let mut receipt = select_new_settlement_action_receipt(
            "0:tc",
            SettlementAction::BuyerStop,
            ExpectedSettlementEvent::StreamStopped,
            Some(&format!("0:{}", "44".repeat(32))),
            &TokenContractSettlementReceipts {
                events: vec![test_action_receipt(
                    "stop",
                    1,
                    TokenContractSettlementEvent::StreamStopped {
                        buyer: format!("0:{}", "44".repeat(32)),
                        to_seller: 7,
                        refund_to_buyer: 8,
                    },
                )],
            },
            test_pre_bonds(),
        )
        .unwrap()
        .unwrap();
        attach_settlement_post_snapshot("0:tc", &mut receipt, &pre, &stopped, None)
            .expect("terminal event remains authoritative after account destruction");
        assert_eq!(receipt.post_state, None);
        assert!(matches!(
            receipt.event,
            SettlementActionEvent::StreamStopped { .. }
        ));

        let disputed = TokenContractSettlementEvent::StreamDisputed {
            buyer: "0:buyer".to_string(),
            at: 5,
        };
        let error = attach_settlement_post_snapshot("0:tc", &mut receipt, &pre, &disputed, None)
            .expect_err("non-terminal dispute cannot destroy its TokenContract");
        assert!(error.to_string().contains("inactive after non-terminal"));
    }

    #[test]
    fn explicit_endpoint_flag_overrides_default() {
        let endpoint = resolve_endpoint(Some("some-host"), &deployed("")).unwrap();
        assert_eq!(
            endpoint_urls(&endpoint).unwrap(),
            (
                "https://some-host/graphql".into(),
                "https://some-host/v2/account".into(),
            )
        );
    }

    #[test]
    fn manifest_graphql_field_supplies_endpoint() {
        let manifest = deployed(r#", "graphql": "https://manifest-host/graphql/""#);
        assert_eq!(
            resolve_endpoint(None, &manifest).unwrap(),
            "https://manifest-host"
        );
        assert_eq!(
            resolve_endpoint(Some("explicit-host"), &manifest).unwrap(),
            "https://explicit-host"
        );
    }

    #[test]
    fn endpoint_url_normalization() {
        let expected = (
            "https://host/graphql".to_string(),
            "https://host/v2/account".to_string(),
        );
        for endpoint in ["host", "https://host", "https://host/"] {
            assert_eq!(endpoint_urls(endpoint).unwrap(), expected);
        }
    }

    fn fill(token_contract: &str, ticks: u128, price_per_tick: u128) -> MatchedFill {
        MatchedFill {
            order_id: 1,
            token_contract: token_contract.to_string(),
            ticks,
            price_per_tick,
        }
    }

    struct CountingFillSource {
        batches: Mutex<VecDeque<Vec<(i64, MatchedFill)>>>,
    }

    impl CountingFillSource {
        fn new(batches: Vec<Vec<(i64, MatchedFill)>>) -> Self {
            Self {
                batches: Mutex::new(batches.into()),
            }
        }
    }

    #[async_trait::async_trait]
    impl InferenceFillPoller for CountingFillSource {
        async fn poll(&self, cursor: &mut MatchWatchCursor) -> Result<Vec<MatchedFill>> {
            let batch = self
                .batches
                .lock()
                .expect("fill batches lock")
                .pop_front()
                .unwrap_or_default();
            Ok(consume_new_fill_batch(cursor, batch))
        }
    }

    async fn wait_for_test_fill(
        source: &CountingFillSource,
        cursor: &mut MatchWatchCursor,
        expected: &MatchedFill,
    ) -> Result<MatchedFill> {
        wait_correlated_inference_fill(
            source,
            cursor,
            Some(expected),
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
            "test fill timeout",
        )
        .await
    }

    fn money_submit_stage(error: &anyhow::Error) -> &MoneySubmitError {
        error
            .chain()
            .find_map(|cause| cause.downcast_ref::<MoneySubmitError>())
            .expect("stage-aware money submit error")
    }

    async fn serve_money_post_response(
        status: &str,
        body: &str,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind money POST fixture");
        let address = listener.local_addr().expect("money POST fixture address");
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept money POST");
            let mut request = [0_u8; 4096];
            let _ = socket.read(&mut request).await.expect("read money POST");
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write money POST response");
        });
        (format!("http://{address}"), task)
    }

    async fn serve_counted_money_post_response(
        status: &str,
        body: &str,
    ) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind counted money POST fixture");
        let address = listener
            .local_addr()
            .expect("counted money POST fixture address");
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let posts = Arc::new(AtomicUsize::new(0));
        let task_posts = Arc::clone(&posts);
        let task = tokio::spawn(async move {
            loop {
                let wait = if task_posts.load(Ordering::SeqCst) == 0 {
                    std::time::Duration::from_secs(1)
                } else {
                    std::time::Duration::from_millis(150)
                };
                let Ok(Ok((mut socket, _))) = tokio::time::timeout(wait, listener.accept()).await
                else {
                    break;
                };
                task_posts.fetch_add(1, Ordering::SeqCst);
                let mut request = [0_u8; 4096];
                let _ = socket.read(&mut request).await.expect("read money POST");
                socket
                    .write_all(response.as_bytes())
                    .await
                    .expect("write counted money POST response");
            }
        });
        (format!("http://{address}"), posts, task)
    }

    #[tokio::test]
    async fn money_post_outcomes_only_clear_for_preparation_or_decoded_rejection() {
        let account = "1".repeat(64);
        let client = build_money_post_http_client().expect("money POST client");

        for status in ["408 Request Timeout", "409 Conflict"] {
            let (endpoint, task) =
                serve_money_post_response(status, r#"{"error":"fixture"}"#).await;
            let error = send_message_routed_money_once(
                &client,
                &endpoint,
                "signed-boc",
                &account,
                &account,
            )
            .await
            .expect_err("unvalidated HTTP status must be ambiguous");
            assert!(matches!(
                money_submit_stage(&error),
                MoneySubmitError::Ambiguous { .. }
            ));
            assert!(!money_submit_stage(&error).clears_journal());
            task.await.expect("money POST fixture task");
        }

        let (endpoint, task) = serve_money_post_response("200 OK", "not-json").await;
        let error =
            send_message_routed_money_once(&client, &endpoint, "signed-boc", &account, &account)
                .await
                .expect_err("undecodable response must be ambiguous");
        assert!(matches!(
            money_submit_stage(&error),
            MoneySubmitError::Ambiguous { .. }
        ));
        assert!(!money_submit_stage(&error).clears_journal());
        task.await.expect("invalid-body fixture task");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind transport-after-send fixture");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept money POST");
            let mut request = [0_u8; 4096];
            let _ = socket.read(&mut request).await.expect("read money POST");
            drop(socket);
        });
        let error =
            send_message_routed_money_once(&client, &endpoint, "signed-boc", &account, &account)
                .await
                .expect_err("transport failure after send must be ambiguous");
        assert!(matches!(
            money_submit_stage(&error),
            MoneySubmitError::Ambiguous { .. }
        ));
        assert!(!money_submit_stage(&error).clears_journal());
        task.await.expect("transport-after-send fixture task");

        let (endpoint, task) =
            serve_money_post_response("200 OK", r#"{"result":{"exit_code":151}}"#).await;
        let error =
            send_message_routed_money_once(&client, &endpoint, "signed-boc", &account, &account)
                .await
                .expect_err("decoded contract rejection must be terminal");
        assert!(matches!(
            money_submit_stage(&error),
            MoneySubmitError::Rejected { .. }
        ));
        assert!(money_submit_stage(&error).clears_journal());
        assert!(format!("{error:#}").contains("exit_code=151"));
        task.await.expect("contract rejection fixture task");

        let error = send_message_routed_money_once(
            &client,
            "not a valid URL",
            "signed-boc",
            &account,
            &account,
        )
        .await
        .expect_err("request builder failure must be pre-POST");
        assert!(matches!(
            money_submit_stage(&error),
            MoneySubmitError::Preparation { .. }
        ));
        assert!(money_submit_stage(&error).clears_journal());
    }

    #[tokio::test]
    async fn explicit_stop_posts_once_for_gateway_queue_and_ambiguous_outcomes() {
        let account = "1".repeat(64);
        let client = build_money_post_http_client().expect("money POST client");
        for (status, body) in [
            ("502 Bad Gateway", r#"{"error":"gateway"}"#),
            ("503 Service Unavailable", r#"{"error":"service"}"#),
            ("504 Gateway Timeout", r#"{"error":"timeout"}"#),
            (
                "200 OK",
                r#"{"error":"QUEUE_OVERFLOW: message queue is full"}"#,
            ),
            ("200 OK", "not-json"),
        ] {
            let (endpoint, posts, task) = serve_counted_money_post_response(status, body).await;
            let error = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                send_explicit_stop_money_once(&client, &endpoint, "signed-boc", &account, &account),
            )
            .await
            .expect("explicit STOP must not enter a retry/backoff loop")
            .expect_err("fixture response is not a confirmed submit");
            assert!(
                matches!(
                    money_submit_stage(&error),
                    MoneySubmitError::Ambiguous { .. }
                ),
                "{status}: {error:#}"
            );
            task.await.expect("counted money POST fixture task");
            assert_eq!(
                posts.load(Ordering::SeqCst),
                1,
                "{status} must not resend the signed STOP BOC"
            );
        }
    }

    #[test]
    fn explicit_stream_stop_uses_the_authoritative_one_shot_receipt_path() {
        let source = include_str!("client.rs");
        let start = source
            .find("pub async fn stream_stop(")
            .expect("explicit stream_stop implementation");
        let end = source[start..]
            .find("pub async fn stream_dispute(")
            .map(|offset| start + offset)
            .expect("method after explicit stream_stop");
        let body = &source[start..end];

        assert!(body.contains(".prepare_money_post("));
        assert!(body.contains("self.submit_settlement_action_once("));
        assert!(body.contains("SettlementAction::BuyerStop"));
        assert!(body.contains("ExpectedSettlementEvent::BuyerStop"));
        assert!(!body.contains("send_explicit_stop_money_once("));
        assert!(!body.contains("self.submit("));
        assert!(!body.contains("send_with_retry("));
    }

    #[test]
    fn restart_after_exact_stream_stopped_is_an_idempotent_no_post() {
        let receipts = TokenContractSettlementReceipts {
            events: vec![TokenContractSettlementReceipt {
                message_id: "receipt-stop".to_string(),
                created_at: 77,
                cursor: "cursor-stop".to_string(),
                event: TokenContractSettlementEvent::StreamStopped {
                    buyer: "0:buyer".to_string(),
                    to_seller: 10,
                    refund_to_buyer: 90,
                },
            }],
        };
        let closed = test_deal_snapshot("closed", false, false, 10, 0);
        let mut simulated_posts = 0;

        for pre in [Some(&closed), None] {
            let result = validate_buyer_stop_pre_state("0:tc", pre, &receipts);
            if result.is_ok() {
                simulated_posts += 1;
            }
            let message = result.expect_err("terminal retry must not reach the money POST");
            let message = message.to_string();
            assert!(message.contains("exact StreamStopped receipt"), "{message}");
            assert!(message.contains("message_id=receipt-stop"), "{message}");
            assert!(message.contains("idempotent no-op"), "{message}");
        }
        assert_eq!(
            simulated_posts, 0,
            "active-closed and destroyed restart retries must issue no money POST"
        );

        let live = test_deal_snapshot("live", true, false, 0, 20);
        validate_buyer_stop_pre_state(
            "0:tc",
            Some(&live),
            &TokenContractSettlementReceipts::default(),
        )
        .expect("one open undisputed stream may proceed to its first STOP");
    }

    #[test]
    fn destroyed_prior_terminal_receipt_wins_before_state_actor_or_post() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let receipts = TokenContractSettlementReceipts {
            events: vec![TokenContractSettlementReceipt {
                message_id: "destroyed-stop".to_string(),
                created_at: 77,
                cursor: "destroyed-cursor".to_string(),
                event: TokenContractSettlementEvent::StreamStopped {
                    buyer: "0:buyer".to_string(),
                    to_seller: 10,
                    refund_to_buyer: 90,
                },
            }],
        };
        let state_reads = AtomicUsize::new(0);
        let actor_reads = AtomicUsize::new(0);
        let posts = AtomicUsize::new(0);
        let result = (|| -> Result<()> {
            reject_prior_settlement_action("0:tc", SettlementAction::BuyerStop, None, &receipts)?;
            state_reads.fetch_add(1, Ordering::SeqCst);
            actor_reads.fetch_add(1, Ordering::SeqCst);
            posts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })();
        let message = result
            .expect_err("destroyed terminal retry must stop at immutable history")
            .to_string();
        assert!(message.contains("exact StreamStopped receipt"), "{message}");
        assert_eq!(state_reads.load(Ordering::SeqCst), 0);
        assert_eq!(actor_reads.load(Ordering::SeqCst), 0);
        assert_eq!(posts.load(Ordering::SeqCst), 0);

        let source = include_str!("client.rs");
        let start = source
            .find("async fn submit_settlement_action_once_if(")
            .expect("settlement submit helper");
        let end = source[start..]
            .find("/// Read-only buyer preflight")
            .map(|offset| start + offset)
            .expect("method after settlement submit helper");
        let body = &source[start..end];
        let history = body
            .find("self.token_contract_settlement_receipts(")
            .expect("immutable event snapshot");
        let terminal = body
            .find("reject_prior_settlement_action(")
            .expect("prior terminal guard");
        let state = body
            .find("self.token_contract_deal_snapshot(")
            .expect("live state getter");
        let actor = body
            .find("self.token_contract_buyer_note(")
            .expect("live actor getter");
        let post = body.find("if !before_post()").expect("only POST guard");
        assert!(history < terminal && terminal < state && state < actor && actor < post);
    }

    #[test]
    fn every_settlement_action_retry_is_classified_before_getters_or_second_money() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let buyer = format!("0:{}", "44".repeat(32));
        let disputed = || TokenContractSettlementEvent::StreamDisputed {
            buyer: buyer.clone(),
            at: 70,
        };
        let exact_cases = vec![
            (
                SettlementAction::BuyerStop,
                vec![TokenContractSettlementEvent::StreamStopped {
                    buyer: buyer.clone(),
                    to_seller: 10,
                    refund_to_buyer: 90,
                }],
                "StreamStopped",
            ),
            (
                SettlementAction::SellerStop,
                vec![TokenContractSettlementEvent::StreamStopped {
                    buyer: buyer.clone(),
                    to_seller: 10,
                    refund_to_buyer: 90,
                }],
                "StreamStopped",
            ),
            (
                SettlementAction::Dispute,
                vec![disputed()],
                "StreamDisputed",
            ),
            (
                SettlementAction::ReleaseDispute,
                vec![
                    disputed(),
                    TokenContractSettlementEvent::DisputeResolved {
                        to_seller: 10,
                        refund_to_buyer: 90,
                        released: true,
                    },
                ],
                "DisputeResolved(released=true)",
            ),
            (
                SettlementAction::ResolveDisputeTimeout,
                vec![
                    disputed(),
                    TokenContractSettlementEvent::DisputeResolved {
                        to_seller: 10,
                        refund_to_buyer: 90,
                        released: false,
                    },
                ],
                "DisputeResolved(released=false)",
            ),
        ];

        for (action, events, expected_kind) in exact_cases {
            let receipts = TokenContractSettlementReceipts {
                events: events
                    .into_iter()
                    .enumerate()
                    .map(|(index, event)| {
                        test_action_receipt(
                            &format!("prior-{action}-{index}"),
                            77 + index as u64,
                            event,
                        )
                    })
                    .collect(),
            };
            let state_reads = AtomicUsize::new(0);
            let actor_reads = AtomicUsize::new(0);
            let prepares = AtomicUsize::new(0);
            let posts = AtomicUsize::new(0);
            let expected_buyer = matches!(
                action,
                SettlementAction::BuyerStop | SettlementAction::Dispute
            )
            .then_some(buyer.as_str());
            let result = (|| -> Result<()> {
                reject_prior_settlement_action("0:tc", action, expected_buyer, &receipts)?;
                state_reads.fetch_add(1, Ordering::SeqCst);
                actor_reads.fetch_add(1, Ordering::SeqCst);
                prepares.fetch_add(1, Ordering::SeqCst);
                posts.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })();
            let message = result
                .expect_err("an exact prior action must classify the retry without live state")
                .to_string();
            assert!(message.contains(expected_kind), "{action}: {message}");
            assert!(message.contains("idempotent no-op"), "{action}: {message}");
            assert_eq!(state_reads.load(Ordering::SeqCst), 0, "{action}");
            assert_eq!(actor_reads.load(Ordering::SeqCst), 0, "{action}");
            assert_eq!(prepares.load(Ordering::SeqCst), 0, "{action}");
            assert_eq!(posts.load(Ordering::SeqCst), 0, "{action}");
        }
    }

    #[test]
    fn every_settlement_action_rejects_incompatible_history_before_second_money() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let buyer = format!("0:{}", "44".repeat(32));
        let disputed = || TokenContractSettlementEvent::StreamDisputed {
            buyer: buyer.clone(),
            at: 70,
        };
        let mismatch_cases = vec![
            (SettlementAction::BuyerStop, vec![disputed()]),
            (
                SettlementAction::SellerStop,
                vec![TokenContractSettlementEvent::ProbeBurned {
                    buyer: buyer.clone(),
                    burned_probe: 1,
                    burned_bond: 1,
                    refund_to_buyer: 98,
                }],
            ),
            (
                SettlementAction::Dispute,
                vec![TokenContractSettlementEvent::StreamStopped {
                    buyer: buyer.clone(),
                    to_seller: 10,
                    refund_to_buyer: 90,
                }],
            ),
            (
                SettlementAction::ReleaseDispute,
                vec![
                    disputed(),
                    TokenContractSettlementEvent::DisputeResolved {
                        to_seller: 10,
                        refund_to_buyer: 90,
                        released: false,
                    },
                ],
            ),
            (
                SettlementAction::ResolveDisputeTimeout,
                vec![
                    disputed(),
                    TokenContractSettlementEvent::DisputeResolved {
                        to_seller: 10,
                        refund_to_buyer: 90,
                        released: true,
                    },
                ],
            ),
        ];

        for (action, events) in mismatch_cases {
            let receipts = TokenContractSettlementReceipts {
                events: events
                    .into_iter()
                    .enumerate()
                    .map(|(index, event)| {
                        test_action_receipt(
                            &format!("wrong-{action}-{index}"),
                            77 + index as u64,
                            event,
                        )
                    })
                    .collect(),
            };
            let prepares = AtomicUsize::new(0);
            let posts = AtomicUsize::new(0);
            let result = (|| -> Result<()> {
                reject_prior_settlement_action("0:tc", action, None, &receipts)?;
                prepares.fetch_add(1, Ordering::SeqCst);
                posts.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })();
            let message = result
                .expect_err("incompatible old action history must fail closed")
                .to_string();
            assert!(
                message.contains("incompatible prior"),
                "{action}: {message}"
            );
            assert!(
                message.contains("before any money POST"),
                "{action}: {message}"
            );
            assert_eq!(prepares.load(Ordering::SeqCst), 0, "{action}");
            assert_eq!(posts.load(Ordering::SeqCst), 0, "{action}");
        }
    }

    #[test]
    fn dispute_resolution_replays_require_canonical_event_order_and_shape() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let buyer = format!("0:{}", "44".repeat(32));
        for action in [
            SettlementAction::ReleaseDispute,
            SettlementAction::ResolveDisputeTimeout,
        ] {
            let released = action == SettlementAction::ReleaseDispute;
            let dispute = || TokenContractSettlementEvent::StreamDisputed {
                buyer: buyer.clone(),
                at: 70,
            };
            let resolution = || TokenContractSettlementEvent::DisputeResolved {
                to_seller: 10,
                refund_to_buyer: 90,
                released,
            };
            let stop = || TokenContractSettlementEvent::StreamStopped {
                buyer: buyer.clone(),
                to_seller: 10,
                refund_to_buyer: 90,
            };
            for (label, events) in [
                ("lone resolution", vec![resolution()]),
                ("reversed order", vec![resolution(), dispute()]),
                ("extra terminal", vec![dispute(), resolution(), stop()]),
            ] {
                let receipts = TokenContractSettlementReceipts {
                    events: events
                        .into_iter()
                        .enumerate()
                        .map(|(index, event)| {
                            test_action_receipt(
                                &format!("tampered-{action}-{index}"),
                                77 + index as u64,
                                event,
                            )
                        })
                        .collect(),
                };
                let state_reads = AtomicUsize::new(0);
                let prepares = AtomicUsize::new(0);
                let posts = AtomicUsize::new(0);
                let result = (|| -> Result<()> {
                    reject_prior_settlement_action("0:tc", action, None, &receipts)?;
                    state_reads.fetch_add(1, Ordering::SeqCst);
                    prepares.fetch_add(1, Ordering::SeqCst);
                    posts.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })();
                let message = result
                    .expect_err("tampered resolution history must fail before live state or money")
                    .to_string();
                assert!(
                    message.contains("invalid prior settlement-action history"),
                    "{action}/{label}: {message}"
                );
                assert!(
                    message.contains("canonical chain order"),
                    "{action}/{label}: {message}"
                );
                assert_eq!(state_reads.load(Ordering::SeqCst), 0, "{action}/{label}");
                assert_eq!(prepares.load(Ordering::SeqCst), 0, "{action}/{label}");
                assert_eq!(posts.load(Ordering::SeqCst), 0, "{action}/{label}");
            }
        }
    }

    #[test]
    fn every_public_settlement_action_checks_history_before_money_preparation() {
        let source = include_str!("client.rs");
        for (method, next_method) in [
            (
                "pub async fn seller_stop(",
                "pub async fn destroy_token_contract(",
            ),
            (
                "pub async fn release_dispute(",
                "pub async fn resolve_dispute_timeout(",
            ),
            (
                "pub async fn resolve_dispute_timeout(",
                "pub async fn withdraw_shell(",
            ),
            ("pub async fn stream_stop(", "pub async fn stream_dispute("),
            (
                "pub async fn stream_dispute(",
                "pub async fn stop_if_heartbeat(",
            ),
            (
                "pub async fn stop_if_heartbeat(",
                "pub async fn stream_cleanup(",
            ),
        ] {
            let start = source
                .find(method)
                .unwrap_or_else(|| panic!("missing {method}"));
            let end = source[start..]
                .find(next_method)
                .map(|offset| start + offset)
                .unwrap_or_else(|| panic!("missing {next_method}"));
            let body = &source[start..end];
            let history = body
                .find("reject_prior_settlement_action_before_prepare(")
                .unwrap_or_else(|| panic!("{method} lacks immutable-history preflight"));
            let prepare = body
                .find(".prepare_money_post(")
                .unwrap_or_else(|| panic!("{method} lacks money preparation"));
            assert!(
                history < prepare,
                "{method} prepares money before replay classification"
            );
        }
    }

    #[test]
    fn stale_open_getter_never_overrides_prior_terminal_receipt() {
        let live = test_deal_snapshot("stale-open", true, false, 0, 20);
        let terminal_events = [
            (
                "ProbeBurned",
                TokenContractSettlementEvent::ProbeBurned {
                    buyer: "0:buyer".to_string(),
                    burned_probe: 1,
                    burned_bond: 1,
                    refund_to_buyer: 98,
                },
            ),
            (
                "StreamStopped",
                TokenContractSettlementEvent::StreamStopped {
                    buyer: "0:buyer".to_string(),
                    to_seller: 10,
                    refund_to_buyer: 90,
                },
            ),
            (
                "DisputeResolved",
                TokenContractSettlementEvent::DisputeResolved {
                    to_seller: 10,
                    refund_to_buyer: 90,
                    released: true,
                },
            ),
        ];
        let mut simulated_posts = 0;

        for (kind, event) in terminal_events {
            let receipts = TokenContractSettlementReceipts {
                events: vec![TokenContractSettlementReceipt {
                    message_id: format!("receipt-{kind}"),
                    created_at: 77,
                    cursor: format!("cursor-{kind}"),
                    event,
                }],
            };
            let result = validate_buyer_stop_pre_state("0:tc", Some(&live), &receipts);
            if result.is_ok() {
                simulated_posts += 1;
            }
            let message =
                result.expect_err("immutable terminal history must beat stale-open state");
            assert!(message.to_string().contains(kind), "{message}");
        }
        assert_eq!(
            simulated_posts, 0,
            "no prior terminal receipt may reach a duplicate STOP POST"
        );
    }

    #[test]
    fn probe_stop_restart_is_an_idempotent_no_post() {
        let receipts = TokenContractSettlementReceipts {
            events: vec![TokenContractSettlementReceipt {
                message_id: "receipt-probe-burn".to_string(),
                created_at: 77,
                cursor: "cursor-probe-burn".to_string(),
                event: TokenContractSettlementEvent::ProbeBurned {
                    buyer: "0:buyer".to_string(),
                    burned_probe: 1,
                    burned_bond: 1,
                    refund_to_buyer: 98,
                },
            }],
        };
        let closed = test_deal_snapshot("closed-probe", false, false, 0, 0);
        for pre in [Some(&closed), None] {
            let message = validate_buyer_stop_pre_state("0:tc", pre, &receipts)
                .expect_err("probe STOP retry must not reach a second POST")
                .to_string();
            assert!(message.contains("exact ProbeBurned receipt"), "{message}");
            assert!(message.contains("idempotent no-op"), "{message}");
        }
    }

    #[test]
    fn illegal_buyer_stop_state_without_exact_receipt_fails_before_post() {
        for (label, pre) in [
            (
                "closed without receipt",
                Some(test_deal_snapshot("closed", false, false, 10, 0)),
            ),
            (
                "disputed",
                Some(test_deal_snapshot("disputed", true, true, 0, 20)),
            ),
        ] {
            let error = validate_buyer_stop_pre_state(
                "0:tc",
                pre.as_ref(),
                &TokenContractSettlementReceipts::default(),
            )
            .expect_err(label);
            assert!(
                error.to_string().contains("before any money POST"),
                "{error}"
            );
        }

        let live = test_deal_snapshot("live", true, false, 0, 20);
        let disputed = TokenContractSettlementReceipts {
            events: vec![TokenContractSettlementReceipt {
                message_id: "receipt-disputed".to_string(),
                created_at: 77,
                cursor: "cursor-disputed".to_string(),
                event: TokenContractSettlementEvent::StreamDisputed {
                    buyer: "0:buyer".to_string(),
                    at: 76,
                },
            }],
        };
        let error = validate_buyer_stop_pre_state("0:tc", Some(&live), &disputed)
            .expect_err("prior dispute receipt must beat a stale-undisputed getter");
        assert!(error.to_string().contains("StreamDisputed"), "{error}");

        let mut multiple = disputed;
        multiple.events.push(TokenContractSettlementReceipt {
            message_id: "receipt-resolved".to_string(),
            created_at: 78,
            cursor: "cursor-resolved".to_string(),
            event: TokenContractSettlementEvent::DisputeResolved {
                to_seller: 10,
                refund_to_buyer: 90,
                released: false,
            },
        });
        let error = validate_buyer_stop_pre_state("0:tc", Some(&live), &multiple)
            .expect_err("multiple prior action receipts must fail closed");
        assert!(
            error
                .to_string()
                .contains("more than one prior settlement-action receipt"),
            "{error}"
        );
    }

    #[test]
    fn policy_stop_checks_heartbeat_after_receipt_preflight_and_before_the_only_post() {
        let source = include_str!("client.rs");
        let start = source
            .find("async fn submit_settlement_action_once_if(")
            .expect("guarded settlement helper");
        let end = source[start..]
            .find("/// Read-only buyer preflight")
            .map(|offset| start + offset)
            .expect("method after guarded settlement helper");
        let body = &source[start..end];
        let legality = body
            .find("validate_buyer_stop_pre_state(")
            .expect("strict buyer STOP legality gate");
        let pre_snapshot = body
            .find("validate_settlement_facts(")
            .expect("authoritative pre-submit validation");
        let guard = body
            .find("if !before_post()")
            .expect("final heartbeat guard");
        let reconcile = body
            .find("reconcile_settlement_action_after_post(")
            .expect("one-shot receipt reconciliation");
        let after_guard = &body[guard..reconcile];

        assert!(legality < pre_snapshot && pre_snapshot < guard && guard < reconcile);
        assert!(
            !after_guard.contains(".await"),
            "no async gap may reopen the heartbeat race before the only POST"
        );
        assert!(body.contains("send_explicit_stop_money_once("));
    }

    #[tokio::test]
    async fn policy_stop_heartbeat_change_after_prepare_skips_money_post() {
        use std::sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering},
            Arc,
        };

        let generation = Arc::new(AtomicU64::new(7));
        let heartbeat = crate::chain::HeartbeatGuard::new(Arc::clone(&generation));
        let sends = Arc::new(AtomicUsize::new(0));
        let prepare_generation = Arc::clone(&generation);
        let send_counter = Arc::clone(&sends);
        let mut before_post = || heartbeat.unchanged();

        let result = prepare_policy_stop_money_post_if(
            async move {
                prepare_generation.fetch_add(1, Ordering::SeqCst);
                Ok((
                    "endpoint".to_string(),
                    "signed-boc".to_string(),
                    "account".to_string(),
                    "dapp".to_string(),
                ))
            },
            &mut before_post,
            move |_| async move {
                send_counter.fetch_add(1, Ordering::SeqCst);
                Ok(json!({"ok": true}))
            },
        )
        .await
        .expect("changed heartbeat must cancel without a send");

        assert!(result.is_none());
        assert_eq!(sends.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn wait_reconciliation_logic_ignores_stale_rejects_wrong_and_selects_intended() {
        let expected = fill("0:intended", 2, 700);
        let stale = fill("0:stale", 9, 999);
        let unrelated = fill("0:unrelated", 3, 701);

        let wrong_source = CountingFillSource::new(vec![
            vec![(100, stale.clone())],
            vec![(100, stale.clone()), (101, unrelated.clone())],
        ]);
        let mut wrong_cursor = MatchWatchCursor::new(0);
        wrong_source
            .poll(&mut wrong_cursor)
            .await
            .expect("prime cursor past stale fill");
        let error = wait_for_test_fill(&wrong_source, &mut wrong_cursor, &expected)
            .await
            .expect_err("post-submit unrelated fill must fail closed");
        assert!(error
            .to_string()
            .contains("refusing wrong-fill attribution"));

        let intended_source = CountingFillSource::new(vec![
            vec![(100, stale.clone())],
            vec![(100, stale), (101, unrelated), (101, expected.clone())],
        ]);
        let mut intended_cursor = MatchWatchCursor::new(0);
        intended_source
            .poll(&mut intended_cursor)
            .await
            .expect("prime cursor past stale fill");
        let selected = wait_for_test_fill(&intended_source, &mut intended_cursor, &expected)
            .await
            .expect("intended fill must let the deal proceed");
        assert_eq!(selected, expected);
    }

    #[tokio::test]
    async fn money_post_refuses_307_without_replaying_signed_boc() {
        let redirect_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redirect server");
        let redirect_addr = redirect_listener.local_addr().expect("redirect address");
        let redirect_task = tokio::spawn(async move {
            let (mut socket, _) = redirect_listener.accept().await.expect("redirect request");
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await.expect("read money POST");
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{redirect_addr}/replayed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .expect("write redirect");
            match tokio::time::timeout(
                std::time::Duration::from_millis(100),
                redirect_listener.accept(),
            )
            .await
            {
                Ok(Ok((mut replay, _))) => {
                    let _ = replay.read(&mut request).await.expect("read replayed POST");
                    replay
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]",
                        )
                        .await
                        .expect("write replay response");
                    true
                }
                _ => false,
            }
        });

        let client = build_money_post_http_client().expect("money POST client");
        let error = send_message_routed_checked(
            &client,
            &format!("http://{redirect_addr}"),
            "signed-boc",
            "0:11",
            "0:22",
            None,
        )
        .await
        .expect_err("307 must fail instead of replaying the signed BOC");

        let replayed = redirect_task.await.expect("redirect server task");
        assert!(
            error.to_string().contains("refused HTTP redirect 307"),
            "{error:#}"
        );
        assert!(!replayed, "signed BOC was replayed at redirect target");

        let redirect_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind money redirect server");
        let redirect_addr = redirect_listener.local_addr().expect("redirect address");
        let redirect_task = tokio::spawn(async move {
            let (mut socket, _) = redirect_listener.accept().await.expect("redirect request");
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await.expect("read money POST");
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{redirect_addr}/replayed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .expect("write redirect");
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                redirect_listener.accept(),
            )
            .await
            .is_ok()
        });
        let error = send_message_routed_money_once(
            &client,
            &format!("http://{redirect_addr}"),
            "signed-boc",
            "0:11",
            "0:22",
        )
        .await
        .expect_err("money redirect must remain ambiguous");
        assert!(matches!(
            money_submit_stage(&error),
            MoneySubmitError::Ambiguous { .. }
        ));
        assert!(!money_submit_stage(&error).clears_journal());
        assert!(!redirect_task.await.expect("money redirect task"));
    }

    #[test]
    fn details_has_withdrawn_accepts_bool_and_string_forms() {
        assert_eq!(
            details_has_withdrawn(&json!({"hasWithdrawn": false})),
            Some(false)
        );
        assert_eq!(
            details_has_withdrawn(&json!({"hasWithdrawn": true})),
            Some(true)
        );
        assert_eq!(
            details_has_withdrawn(&json!({"hasWithdrawn": "0"})),
            Some(false)
        );
        assert_eq!(
            details_has_withdrawn(&json!({"hasWithdrawn": "true"})),
            Some(true)
        );
        assert_eq!(details_has_withdrawn(&json!({"hasWithdrawn": "wat"})), None);
    }

    #[test]
    fn seller_note_withdrawn_check_fails_with_actionable_message() {
        let note =
            Address::parse("0:1111111111111111111111111111111111111111111111111111111111111111")
                .expect("address");
        let check = seller_note_withdrawn_check(&note, Some(true));
        assert_eq!(check.status, ShellnetDoctorStatus::Fail);
        assert_eq!(check.expected.as_deref(), Some("hasWithdrawn=false"));
        assert_eq!(check.actual.as_deref(), Some("hasWithdrawn=true"));
        assert!(
            check.message.contains("this note has withdrawn"),
            "{}",
            check.message
        );
        assert!(
            check.message.contains("can no longer post sell offers"),
            "{}",
            check.message
        );
        assert!(
            check.message.contains("ERR_INVALID_STATE 151"),
            "{}",
            check.message
        );
        assert!(!check.message.contains("TVM_ERROR"), "{}", check.message);
    }

    #[test]
    fn buyer_note_withdrawn_guard_aborts_with_actionable_message() {
        let note =
            Address::parse("0:2222222222222222222222222222222222222222222222222222222222222222")
                .expect("address");
        let error = buyer_note_withdrawn_guard(&note, Some(&json!({"hasWithdrawn": true})))
            .expect_err("a withdrawn buyer note must be rejected before submit");
        let message = error.to_string();
        assert!(message.contains("buyer place aborted"), "{message}");
        assert!(message.contains("can no longer place buys"), "{message}");
        assert!(message.contains("deploy/use a fresh note"), "{message}");
        assert!(message.contains("ERR_INVALID_STATE 151"), "{message}");
        assert!(
            message.contains("PrivateNote._hasWithdrawn=true"),
            "{message}"
        );
        assert!(!message.contains("CHAIN_TRANSPORT"), "{message}");
    }

    #[test]
    fn buyer_note_withdrawn_guard_allows_not_withdrawn_note() {
        let note =
            Address::parse("0:2222222222222222222222222222222222222222222222222222222222222222")
                .expect("address");
        buyer_note_withdrawn_guard(&note, Some(&json!({"hasWithdrawn": false})))
            .expect("a note that has not withdrawn must not be blocked");
    }

    #[test]
    fn buyer_note_withdrawn_guard_fails_open_when_field_is_missing() {
        let note =
            Address::parse("0:2222222222222222222222222222222222222222222222222222222222222222")
                .expect("address");
        buyer_note_withdrawn_guard(&note, Some(&json!({"ephemeralPubkey": "0x1234"})))
            .expect("a contract generation without hasWithdrawn must remain usable");
        buyer_note_withdrawn_guard(&note, None)
            .expect("an empty getter result must not be reported as withdrawn");
    }

    #[test]
    fn lock_history_requires_typed_complete_pagination_metadata() {
        for page_info in [
            None,
            Some(json!({"startCursor": "c1"})),
            Some(json!({"startCursor": "c1", "hasPreviousPage": "false"})),
            Some(json!({"hasPreviousPage": true})),
        ] {
            let mut page = json!({"edges": []});
            if let Some(page_info) = page_info {
                page["pageInfo"] = page_info;
            }
            let error = previous_page_cursor("PrivateNote fixture inbound-message", &page, None)
                .expect_err("truncated lock-history pagination must fail closed");
            assert!(error.to_string().contains("inbound-message"), "{error:#}");
        }

        let complete = json!({
            "pageInfo": {"startCursor": null, "hasPreviousPage": false},
            "edges": []
        });
        assert_eq!(
            previous_page_cursor("PrivateNote fixture inbound-message", &complete, None).unwrap(),
            None
        );
    }

    #[test]
    fn withdraw_note_tokens_payload_shape_is_pinned() {
        let dest =
            Address::parse("0:1111111111111111111111111111111111111111111111111111111111111111")
                .expect("address");
        let payload = withdraw_note_tokens_payload(&dest, "0x0");
        assert_eq!(
            payload,
            json!({
                "destWalletAddr": "0:1111111111111111111111111111111111111111111111111111111111111111",
                "dapp_id": "0x0",
            })
        );
    }

    #[test]
    fn submit_path_has_no_raw_debug_console_output() {
        let source = include_str!("client.rs");
        assert!(!source.contains(concat!("DEXDO-SUBMIT", "-DBG")));
        assert!(!source.contains(concat!("deploy-prefund", " submit:")));
    }
}
