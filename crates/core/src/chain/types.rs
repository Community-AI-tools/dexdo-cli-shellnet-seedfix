//! `chain` data types -- offers/match, deal/stream snapshots, accounting tallies, errors(PR4 move-only).
use crate::note::NotePubkey;
use crate::params::{Shell, SUBSCRIPTION_WEEKS};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

fn getter_exact_object<'a>(
    value: &'a Value,
    getter: &str,
    expected_fields: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{getter} returned a non-object JSON value"))?;
    let missing = expected_fields
        .iter()
        .filter(|field| !object.contains_key(**field))
        .copied()
        .collect::<Vec<_>>();
    let mut unexpected = object
        .keys()
        .filter(|field| !expected_fields.contains(&field.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    unexpected.sort();
    if !missing.is_empty() || !unexpected.is_empty() || object.len() != expected_fields.len() {
        return Err(format!(
            "{getter} returned {} fields, expected exactly {}{}{}",
            object.len(),
            expected_fields.len(),
            if missing.is_empty() {
                String::new()
            } else {
                format!("; missing fields: {}", missing.join(", "))
            },
            if unexpected.is_empty() {
                String::new()
            } else {
                format!("; unexpected fields: {}", unexpected.join(", "))
            }
        ));
    }
    Ok(object)
}

fn getter_field<'a>(value: &'a Value, getter: &str, field: &str) -> Result<&'a Value, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{getter} returned a non-object JSON value"))?
        .get(field)
        .ok_or_else(|| format!("{getter}.{field} is missing"))
}

fn getter_bool(value: &Value, getter: &str, field: &str) -> Result<bool, String> {
    getter_field(value, getter, field)?
        .as_bool()
        .ok_or_else(|| format!("{getter}.{field} is not a bool"))
}

fn getter_decimal<'a>(value: &'a Value, getter: &str, field: &str) -> Result<&'a str, String> {
    let raw = getter_field(value, getter, field)?
        .as_str()
        .ok_or_else(|| format!("{getter}.{field} is not a decimal string"))?;
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "{getter}.{field} value {raw:?} is not an unsigned decimal integer"
        ));
    }
    Ok(raw)
}

fn getter_u8(value: &Value, getter: &str, field: &str) -> Result<u8, String> {
    let raw = getter_decimal(value, getter, field)?;
    raw.parse::<u8>()
        .map_err(|error| format!("{getter}.{field} value {raw:?} exceeds uint8: {error}"))
}

fn getter_u64(value: &Value, getter: &str, field: &str) -> Result<u64, String> {
    let raw = getter_decimal(value, getter, field)?;
    raw.parse::<u64>()
        .map_err(|error| format!("{getter}.{field} value {raw:?} exceeds uint64: {error}"))
}

fn getter_u128(value: &Value, getter: &str, field: &str) -> Result<u128, String> {
    let raw = getter_decimal(value, getter, field)?;
    raw.parse::<u128>()
        .map_err(|error| format!("{getter}.{field} value {raw:?} exceeds uint128: {error}"))
}

/// `token_contract` address. In the mock -- an identifier string.
pub type TokenContract = String;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SellOfferOutcome {
    Rested { order_id: u128 },
    Matched,
}

/// Sell offer in the book: the endpoint is NOT published.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SellOffer {
    pub price_per_tick: Shell,
    pub max_ticks: u64,
    pub token_contract: TokenContract,
    /// Deal-shape flags passed to `PrivateNote.postSellOffer`.
    #[serde(default)]
    pub flags: u8,
}

/// Book discovery item: offer + **seller identifier**(note) -- for
/// ranking and the blacklist(B16). In the mock `seller_id` = hex of the seller's note ed-pubkey; on the
/// real chain -- the seller from the `InferenceOrderBook` order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferListing {
    pub seller_id: String,
    pub token_contract: TokenContract,
    pub price_per_tick: Shell,
    pub max_ticks: u64,
}

/// One active order in an `InferenceOrderBook`.
/// Sell offers have `is_buy = false` and a non-empty `token_contract`. Resting buy orders have
/// `is_buy = true`, no target `token_contract`, and carry their still-held `escrow`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderBookOrder {
    pub order_id: u128,
    pub owner_note: String,
    pub token_contract: Option<TokenContract>,
    pub is_buy: bool,
    pub price_per_tick: u128,
    pub ticks: u128,
    pub escrow: u128,
    pub deadline: u64,
    pub flags: u8,
    pub timestamp: u64,
}

impl OrderBookOrder {
    pub fn is_resting_ask(&self) -> bool {
        !self.is_buy && self.token_contract.is_some() && self.ticks > 0
    }
}

/// Fail closed unless the fresh matcher head has the order identity and executable terms rendered
/// to the buyer.
pub fn ensure_pre_submit_quote_unchanged(
    quoted_order: Option<&OrderBookOrder>,
    selected: &OrderBookOrder,
) -> Result<(), ChainError> {
    if quoted_order.is_some_and(|quoted| {
        quoted.order_id == selected.order_id
            && quoted.token_contract == selected.token_contract
            && quoted.price_per_tick == selected.price_per_tick
            && quoted.ticks == selected.ticks
    }) {
        return Ok(());
    }
    Err(ChainError::Chain(
        "buyer pre-submit matcher head differs from the rendered quote; no escrow was sent"
            .to_string(),
    ))
}

/// Parsed `InferenceOrderBook.getStats()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderBookStats {
    pub next_order_id: u128,
    pub order_count: u128,
    pub executed_notional: u128,
    pub executed_ticks: u128,
}

/// Read-only snapshot of one model's `InferenceOrderBook`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderBookSnapshot {
    pub frame_model: String,
    pub model_hash: String,
    pub order_book: String,
    pub stats: Option<OrderBookStats>,
    pub orders: Vec<OrderBookOrder>,
}

impl OrderBookSnapshot {
    pub fn active(&self) -> bool {
        self.stats.is_some()
    }

    pub fn resting_asks(&self) -> impl Iterator<Item = &OrderBookOrder> {
        self.orders.iter().filter(|o| o.is_resting_ask())
    }
}

/// Order flags accepted by `InferenceOrderBook`(`SUPPORTED_FLAGS`).
/// The low bits select taker behaviour and are mutually exclusive with resting; the high bits describe the
/// SHAPE of the resulting deal and are forwarded verbatim into the `TokenContract`(`DEAL_FLAGS_MASK`).
pub mod flags {
    /// Immediate-or-cancel: fill what crosses now, refund the rest.
    pub const IOC: u8 = 0x01;
    /// Fill-or-kill: all of it now, from any number of counterparties, or nothing.
    pub const FOK: u8 = 0x02;
    /// Market order: no price limit.
    pub const MARKET: u8 = 0x04;
    /// Never take -- reject the order if it would cross on arrival.
    pub const POST_ONLY: u8 = 0x08;
    /// Deal shape: the seller attests a trusted-execution endpoint.
    pub const TEE: u8 = 0x10;
    /// All-or-none from a SINGLE counterparty. Unlike [`FOK`] an AON order may rest until one
    /// counterparty can take the whole size.
    pub const AON: u8 = 0x20;
    /// Deal shape: take-or-pay subscription. Requires [`AON`] and a non-zero week count, because a
    /// subscription reserves capacity from exactly one seller for its whole term.
    pub const SUBSCRIPTION: u8 = 0x40;

    /// Flags forwarded into the `TokenContract` as the deal shape.
    pub const DEAL_MASK: u8 = TEE | SUBSCRIPTION;
}

/// Parsed `TokenContract.getSubscription()` -- the deal SHAPE, not a book-side subscription.
/// `sub_weeks == 0` marks an ordinary by-fact deal, in which case the weekly fields carry no meaning
/// beyond `tokens_per_week == fundedTokens`(the whole volume, available from the start).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DealSubscription {
    /// Raw deal-shape flags(`flags::DEAL_MASK`) as recorded at funding.
    pub deal_flags: u8,
    /// Term in weeks; zero for an ordinary deal.
    pub sub_weeks: u8,
    /// Weeks already settled take-or-pay.
    pub week_index: u8,
    /// Per-week allowance. Does not roll forward: unused volume is forfeited at the boundary.
    pub tokens_per_week: u128,
    /// Whole funded volume of the deal.
    pub funded_tokens: u128,
    /// Cumulative tokens already paid for(whole quotas for settled weeks).
    pub tokens_paid: u128,
    /// When the weekly clock started -- accepted-probe time for a subscription.
    pub period_start: u64,
    /// Cumulative consumption recorded at the start of the current week. This is the authoritative
    /// no-rollover base used by the contract; it cannot be reconstructed from wall-clock time or
    /// `tokens_paid`.
    pub week_base_tokens: u128,
}

impl DealSubscription {
    /// Strictly decode the exact `TokenContract.getSubscription()` ABI.
    /// Getter integers are ABI decimal strings. Missing fields, alternate JSON kinds, non-decimal
    /// values, width overflow, unknown deal-shape bits and contradictory ordinary/subscription
    /// shapes are rejected rather than being interpreted as an ordinary zero-valued deal.
    pub fn decode_getter(value: &Value) -> Result<Self, String> {
        const GETTER: &str = "getSubscription()";
        getter_exact_object(
            value,
            GETTER,
            &[
                "dealFlags",
                "subWeeks",
                "weekIndex",
                "tokensPerWeek",
                "fundedTokens",
                "tokensPaid",
                "periodStart",
                "weekBaseTokens",
            ],
        )?;

        let decoded = Self {
            deal_flags: getter_u8(value, GETTER, "dealFlags")?,
            sub_weeks: getter_u8(value, GETTER, "subWeeks")?,
            week_index: getter_u8(value, GETTER, "weekIndex")?,
            tokens_per_week: getter_u128(value, GETTER, "tokensPerWeek")?,
            funded_tokens: getter_u128(value, GETTER, "fundedTokens")?,
            tokens_paid: getter_u128(value, GETTER, "tokensPaid")?,
            period_start: getter_u64(value, GETTER, "periodStart")?,
            week_base_tokens: getter_u128(value, GETTER, "weekBaseTokens")?,
        };

        let unknown = decoded.deal_flags & !flags::DEAL_MASK;
        if unknown != 0 {
            return Err(format!(
                "{GETTER}.dealFlags contains unknown deal-shape bits 0x{unknown:02x}"
            ));
        }

        let subscription_flag = decoded.deal_flags & flags::SUBSCRIPTION != 0;
        if subscription_flag != (decoded.sub_weeks != 0) {
            return Err(format!(
                "{GETTER} has contradictory subscription flag/subWeeks shape: dealFlags=0x{:02x}, subWeeks={}",
                decoded.deal_flags, decoded.sub_weeks
            ));
        }
        if decoded.week_index > decoded.sub_weeks {
            return Err(format!(
                "{GETTER}.weekIndex {} exceeds subWeeks {}",
                decoded.week_index, decoded.sub_weeks
            ));
        }
        if decoded.tokens_paid > decoded.funded_tokens {
            return Err(format!(
                "{GETTER}.tokensPaid {} exceeds fundedTokens {}",
                decoded.tokens_paid, decoded.funded_tokens
            ));
        }
        if decoded.week_base_tokens > decoded.funded_tokens {
            return Err(format!(
                "{GETTER}.weekBaseTokens {} exceeds fundedTokens {}",
                decoded.week_base_tokens, decoded.funded_tokens
            ));
        }

        if subscription_flag {
            if decoded.sub_weeks != SUBSCRIPTION_WEEKS {
                return Err(format!(
                    "{GETTER}.subWeeks {} does not equal the canonical {}-week term",
                    decoded.sub_weeks, SUBSCRIPTION_WEEKS
                ));
            }
            let expected = decoded
                .tokens_per_week
                .checked_mul(u128::from(decoded.sub_weeks))
                .ok_or_else(|| format!("{GETTER}.tokensPerWeek x subWeeks overflows uint128"))?;
            if expected != decoded.funded_tokens {
                return Err(format!(
                    "{GETTER} subscription quota {} x {} does not equal fundedTokens {}",
                    decoded.tokens_per_week, decoded.sub_weeks, decoded.funded_tokens
                ));
            }
        } else if decoded.week_index != 0
            || decoded.tokens_per_week != decoded.funded_tokens
            || decoded.week_base_tokens != 0
        {
            return Err(format!(
                "{GETTER} ordinary deal has contradictory weekly state: weekIndex={}, tokensPerWeek={}, \
                 fundedTokens={}, weekBaseTokens={}",
                decoded.week_index,
                decoded.tokens_per_week,
                decoded.funded_tokens,
                decoded.week_base_tokens
            ));
        }

        Ok(decoded)
    }

    pub fn is_subscription(&self) -> bool {
        self.sub_weeks != 0
    }

    pub fn is_tee(&self) -> bool {
        self.deal_flags & flags::TEE != 0
    }

    /// Whole weeks not yet settled. These are the only ones a buyer `stop()` refunds -- the week in
    /// progress is charged in full(take-or-pay).
    pub fn weeks_remaining(&self) -> u8 {
        self.sub_weeks.saturating_sub(self.week_index)
    }
}

/// A single maker order consumed by an executable quote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteFill {
    pub order_id: u128,
    pub token_contract: TokenContract,
    pub ticks: u128,
    pub price_per_tick: u128,
    pub cost_with_fee: u128,
}

/// Buyer-visible fill details returned after a model-only buy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedFill {
    /// The receiving owner's authoritative order id from `InferenceFilledConfirmed`:
    /// `buyerOrderId` for the buyer event and `sellerOrderId` for the seller event.
    pub order_id: u128,
    pub token_contract: TokenContract,
    pub ticks: u128,
    pub price_per_tick: u128,
}

/// Accepted subscription placement fact from the model order book.
/// A subscription is no longer a distinct book primitive: it is an ordinary BUY order carrying
/// `flags::AON | flags::SUBSCRIPTION` plus a week count, so this is reconciled from the same
/// `InferenceOrderPlaced` fact as any other buy. The order id is the durable correlation key for later
/// owner-facing fills.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceSubscriptionPlacement {
    pub order_id: u128,
    pub buyer_note: String,
    pub max_price_per_tick: u128,
    /// Whole term volume in ticks. Divides evenly by `sub_weeks` -- the book enforces it.
    pub ticks: u128,
    /// Term in weeks; always [`SUBSCRIPTION_WEEKS`] under the current protocol.
    pub sub_weeks: u8,
    /// Mandatory order deadline: an unmatched subscription is expirable by anyone afterwards.
    pub deadline: u64,
    pub created_at: i64,
}

/// Read-only quote result over current resting asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableQuote {
    pub filled_ticks: u128,
    pub total_with_fee: u128,
    pub complete: bool,
    pub fills: Vec<QuoteFill>,
}

/// Match result: the seller sees the buyer's recorded pubkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    pub token_contract: TokenContract,
    pub buyer_pubkey: NotePubkey,
    pub price_per_tick: Shell,
}

/// Durable source cursor for a seller gateway match watcher.
/// The concrete source may be note ext-out events(real shellnet) or an equivalent
/// authoritative state source(mock / direct TC state). The cursor is intentionally
/// small and secret-free so the CLI can persist it next to local deal handles.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchWatchCursor {
    /// Ignore source events older than this wall-clock timestamp.
    pub since_unix: i64,
    /// Highest `created_at` timestamp already consumed from the source.
    pub last_seen_created_at: Option<i64>,
    /// TokenContracts consumed at `last_seen_created_at`, for same-second events.
    #[serde(default)]
    pub seen_token_contracts_at_last_seen: Vec<TokenContract>,
}

impl MatchWatchCursor {
    pub fn new(since_unix: i64) -> Self {
        Self {
            since_unix,
            last_seen_created_at: None,
            seen_token_contracts_at_last_seen: Vec::new(),
        }
    }

    pub fn has_seen(&self, created_at: i64, token_contract: &str) -> bool {
        if created_at < self.since_unix {
            return true;
        }
        match self.last_seen_created_at {
            Some(last) if created_at < last => true,
            Some(last) if created_at == last => self
                .seen_token_contracts_at_last_seen
                .iter()
                .any(|tc| tc.eq_ignore_ascii_case(token_contract)),
            _ => false,
        }
    }

    pub fn record_seen_batch<I>(&mut self, events: I)
    where
        I: IntoIterator<Item = (i64, TokenContract)>,
    {
        let mut max_seen = self.last_seen_created_at;
        let mut at_max = if max_seen.is_some() {
            self.seen_token_contracts_at_last_seen.clone()
        } else {
            Vec::new()
        };
        for (created_at, token_contract) in events {
            if created_at < self.since_unix {
                continue;
            }
            match max_seen {
                Some(max) if created_at < max => {}
                Some(max) if created_at == max => {
                    if !at_max
                        .iter()
                        .any(|tc| tc.eq_ignore_ascii_case(&token_contract))
                    {
                        at_max.push(token_contract);
                    }
                }
                _ => {
                    max_seen = Some(created_at);
                    at_max.clear();
                    at_max.push(token_contract);
                }
            }
        }
        if let Some(max) = max_seen {
            self.last_seen_created_at = Some(max);
            at_max.sort();
            at_max.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
            self.seen_token_contracts_at_last_seen = at_max;
        }
    }
}

/// Backend errors.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("no match for token_contract {0}")]
    NoMatch(TokenContract),
    #[error("no stream open for {0}")]
    NoStream(TokenContract),
    #[error("endpoints file: {0}")]
    EndpointsFile(String),
    /// Error from the real on-chain adapter: submit/getter/shellnet provisioning.
    #[error("shellnet: {0}")]
    Chain(String),
    /// The RPC/HTTP transport failed before a by-fact chain result was available.
    #[error("shellnet transport: {0}")]
    Transport(String),
    /// The chain returned a contract-level refusal/revert.
    #[error("shellnet contract: {0}")]
    Contract(String),
    /// The order book returned the seller placement value because this TC already has a resting SELL.
    #[error("{0}")]
    DuplicateSell(String),
    /// A non-idempotent money POST may have reached the chain, but its result is not yet provable.
    #[error("shellnet ambiguous submit: {0}")]
    AmbiguousSubmit(String),
    /// A non-idempotent money write failed before its POST was attempted.
    #[error("shellnet money submit was not posted: {0}")]
    MoneySubmitPreparation(String),
    /// A non-idempotent money POST returned a decoded protocol/contract rejection.
    #[error("shellnet money submit was rejected: {0}")]
    MoneySubmitRejected(String),
    /// The agreed deal limit was exceeded(e.g. the offer's `max_ticks`). The real TC bounds it
    /// by deposit; the mock holds the same invariant with a guard.
    #[error("deal limit exceeded: {0}")]
    Limit(String),
    /// A claim retry found that the authoritative cumulative high-water has already advanced beyond
    /// the value this process intended to submit. The seller driver must resynchronise to `on_chain`
    /// instead of treating the stale local value as applied.
    #[error(
        "claim high-water advanced on-chain to {on_chain}, beyond attempted cumulative {attempted}"
    )]
    ClaimHighWaterResync { attempted: u128, on_chain: u128 },
}

/// Snapshot of the stream's state in the mock(for e2e acceptance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSnapshot {
    /// Seller bond held by this TokenContract.
    pub seller_locked: u128,
    /// Total buyer funds still held(`deposit + probe_tick + subscription buyer bond`).
    pub buyer_locked: u128,
    /// The buyer's at-risk lead: an unaccepted probe plus the monetary value of the unpromoted claim tail.
    /// This is distinct from `buyer_locked`, which also carries unspent escrow for the rest of the deal.
    pub buyer_lead: u128,
    /// Authoritative immutable count of finalized model tokens delivered by this TokenContract.
    pub tokens_final: u128,
    /// SHELL owed or paid to the seller. This is money, not delivered-token volume.
    pub seller_received: u128,
    /// Refunded to the buyer.
    pub buyer_refunded: u128,
    /// Total SHELL burned for the contract.
    pub burned: u128,
    /// Stream terminal/STOPped according to the TokenContract lifecycle.
    /// This is not `!opened`: funded-but-never-opened and disputed TCs can hold escrow while still active.
    pub closed: bool,
}

/// Exact typed by-fact lifecycle read for a live `TokenContract`.
/// This mirrors every field of the current 15-field `getState()` ABI so no consumer has to inspect raw JSON
/// or reconstruct a missing claim stage or timeout anchor.
/// The claim pipeline is three-stage by contract design(`TokenContract.claimTokens`): `tokens_final` is
/// promoted and irrevocably the seller's, while `tokens_superseded` and `tokens_pending` are the older and
/// newest contestable cumulative claims. Each pending stage has its own timestamp, so orchestrators must
/// never collapse either stage or treat `tokens_pending` as earned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DealChainState {
    pub funded: bool,
    pub opened: bool,
    /// The probe tick has been accepted, which is what makes the deal claimable at all. Before this the
    /// seller cannot claim anything and a buyer STOP burns the trial tick on both sides.
    pub probe_accepted: bool,
    pub disputed: bool,
    /// Buyer escrow still held by the deal. Zeroed by every terminal path, which is what distinguishes a
    /// settled close from funded-but-never-opened(both have `opened=false`).
    pub deposit: u128,
    /// Withdrawable SHELL already credited to the seller.
    pub finalized_owed: u128,
    /// Promoted cumulative consumption -- the only figure money is computed from.
    pub tokens_final: u128,
    /// Older pending cumulative claim, with its own contest window.
    pub tokens_superseded: u128,
    /// Newest claimed cumulative consumption, still inside its contest window.
    pub tokens_pending: u128,
    /// SHELL held as the unaccepted probe. Owed to nobody: it either becomes the seller's on acceptance, or
    /// burns with a mirror slice of the bond if the buyer walks away from the trial, or returns to the escrow
    /// on any other close.
    pub probe_tick: u128,
    pub funded_time: Option<u64>,
    /// When the probe was frozen (at `open()`); anchors `PROBE_WINDOW`.
    pub probe_time: u64,
    /// Landing time of `tokens_superseded`; its contest window is independent of the newest claim.
    pub prev_claim_time: u64,
    /// Anchor for both claim bounds(`MIN_CLAIM_INTERVAL`) and permissionless promotion
    /// (`CLAIM_PROMOTE_WINDOW`). Set at `open()`, then at every accepted claim.
    pub last_claim_time: u64,
    /// When the buyer opened a dispute; anchors `DISPUTE_WINDOW` for `resolveDisputeTimeout`.
    pub dispute_time: u64,
}

impl DealChainState {
    /// Strictly decode the exact 15-field `TokenContract.getState()` ABI.
    pub fn decode_getter(value: &Value) -> Result<Self, String> {
        const GETTER: &str = "getState()";
        getter_exact_object(
            value,
            GETTER,
            &[
                "funded",
                "opened",
                "probeAccepted",
                "disputed",
                "deposit",
                "probeTick",
                "finalizedOwed",
                "tokensFinal",
                "tokensSuperseded",
                "tokensPending",
                "probeTime",
                "prevClaimTime",
                "lastClaimTime",
                "disputeTime",
                "fundedTime",
            ],
        )?;

        let funded_time = getter_u64(value, GETTER, "fundedTime")?;
        let decoded = Self {
            funded: getter_bool(value, GETTER, "funded")?,
            opened: getter_bool(value, GETTER, "opened")?,
            probe_accepted: getter_bool(value, GETTER, "probeAccepted")?,
            disputed: getter_bool(value, GETTER, "disputed")?,
            deposit: getter_u128(value, GETTER, "deposit")?,
            probe_tick: getter_u128(value, GETTER, "probeTick")?,
            finalized_owed: getter_u128(value, GETTER, "finalizedOwed")?,
            tokens_final: getter_u128(value, GETTER, "tokensFinal")?,
            tokens_superseded: getter_u128(value, GETTER, "tokensSuperseded")?,
            tokens_pending: getter_u128(value, GETTER, "tokensPending")?,
            probe_time: getter_u64(value, GETTER, "probeTime")?,
            prev_claim_time: getter_u64(value, GETTER, "prevClaimTime")?,
            last_claim_time: getter_u64(value, GETTER, "lastClaimTime")?,
            dispute_time: getter_u64(value, GETTER, "disputeTime")?,
            funded_time: (funded_time != 0).then_some(funded_time),
        };

        if decoded.tokens_final > decoded.tokens_superseded
            || decoded.tokens_superseded > decoded.tokens_pending
        {
            return Err(format!(
                "{GETTER} claim pipeline is not monotonic: tokensFinal={} tokensSuperseded={} \
                 tokensPending={}",
                decoded.tokens_final, decoded.tokens_superseded, decoded.tokens_pending
            ));
        }
        Ok(decoded)
    }

    /// Full unpromoted claim tail(`pending - final`) for monitoring exposure. The contract computes the
    /// actual bounded dispute stake separately; callers must not treat this token count as that SHELL amount.
    pub fn contested_tokens(self) -> u128 {
        self.tokens_pending.saturating_sub(self.tokens_final)
    }

    /// Whether the deal is still on the probe: opened but not yet accepted, so nothing is claimable and a
    /// buyer STOP burns the trial tick rather than settling by fact.
    pub fn on_probe(self) -> bool {
        self.opened && !self.probe_accepted
    }

    /// Match `dexdo status` lifecycle semantics for a STOPped/settled deal.
    /// `opened=false` alone is not terminal: a matched buyer can leave the TC in
    /// funded-but-never-opened, and a dispute can also hold escrow without being
    /// a clean closed settlement. Every terminal path zeroes both the deposit and the probe, while a
    /// funded-but-never-opened deal still holds the buyer's whole escrow -- so a drained escrow is what tells
    /// the two apart.
    pub fn is_stopped(self) -> bool {
        self.funded && !self.opened && !self.disputed && self.deposit == 0 && self.probe_tick == 0
    }
}

/// Strictly decoded `TokenContract.getSellerBond()` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DealSellerBond {
    pub bond_funded: bool,
    pub bond_held: u128,
    pub bond_required: u128,
}

impl DealSellerBond {
    pub fn decode_getter(value: &Value) -> Result<Self, String> {
        const GETTER: &str = "getSellerBond()";
        getter_exact_object(value, GETTER, &["bondFunded", "bondHeld", "bondRequired"])?;
        Ok(Self {
            bond_funded: getter_bool(value, GETTER, "bondFunded")?,
            bond_held: getter_u128(value, GETTER, "bondHeld")?,
            bond_required: getter_u128(value, GETTER, "bondRequired")?,
        })
    }
}

/// Strictly decoded `TokenContract.getBuyerBond()` state.
/// The buyer bond is held apart from ordinary escrow on subscription deals.
/// Ordinary deals must expose the canonical zero/zero shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DealBuyerBond {
    pub bond_held: u128,
    pub bond_required: u128,
}

impl DealBuyerBond {
    pub fn decode_getter(value: &Value) -> Result<Self, String> {
        const GETTER: &str = "getBuyerBond()";
        getter_exact_object(value, GETTER, &["bondHeld", "bondRequired"])?;
        Ok(Self {
            bond_held: getter_u128(value, GETTER, "bondHeld")?,
            bond_required: getter_u128(value, GETTER, "bondRequired")?,
        })
    }
}

/// One coherent live accounting/lifecycle view of a `TokenContract`.
/// The account BOC identity brackets all four getters in every bounded read
/// attempt. A changed or destroyed identity rejects that attempt, so consumers
/// never combine fields from different contract revisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DealChainSnapshot {
    pub account_code_hash: String,
    pub account_boc_hash: String,
    pub state: DealChainState,
    pub subscription: DealSubscription,
    pub seller_bond: DealSellerBond,
    pub buyer_bond: DealBuyerBond,
}

impl DealChainSnapshot {
    /// Validate only relationships exposed authoritatively by the four getters
    /// in this same account revision.
    #[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
    pub(crate) fn validate_cross_getter_invariants(&self) -> Result<(), String> {
        if self.state.funded {
            let minimum_funded_tokens = crate::params::TICK_SIZE * 2;
            if self.subscription.funded_tokens < minimum_funded_tokens {
                return Err(format!(
                    "funded deal requires at least two ticks ({minimum_funded_tokens} tokens) in \
                     getSubscription().fundedTokens, got {}",
                    self.subscription.funded_tokens
                ));
            }
        }

        let seller = self.seller_bond;
        if seller.bond_held > seller.bond_required {
            return Err(format!(
                "getSellerBond() bondHeld {} exceeds bondRequired {}",
                seller.bond_held, seller.bond_required
            ));
        }
        if !seller.bond_funded && seller.bond_held != 0 {
            return Err(format!(
                "getSellerBond() reports bondFunded=false with non-zero bondHeld {}",
                seller.bond_held
            ));
        }
        if self.state.opened {
            if !self.state.funded {
                return Err("getState() reports opened=true with funded=false".to_string());
            }
            if !seller.bond_funded
                || seller.bond_required == 0
                || seller.bond_held != seller.bond_required
            {
                return Err(format!(
                    "opened deal requires a fully funded non-zero seller bond, got \
                     bondFunded={} bondHeld={} bondRequired={}",
                    seller.bond_funded, seller.bond_held, seller.bond_required
                ));
            }
        }

        let buyer = self.buyer_bond;
        if buyer.bond_held > buyer.bond_required {
            return Err(format!(
                "getBuyerBond() bondHeld {} exceeds bondRequired {}",
                buyer.bond_held, buyer.bond_required
            ));
        }
        if !self.subscription.is_subscription() {
            if buyer.bond_held != 0 || buyer.bond_required != 0 {
                return Err(format!(
                    "getBuyerBond() ordinary-deal shape must be bondHeld=0 and bondRequired=0, got \
                     bondHeld={} bondRequired={}",
                    buyer.bond_held, buyer.bond_required
                ));
            }
            return Ok(());
        }

        if buyer.bond_required != seller.bond_required {
            return Err(format!(
                "subscription seller/buyer bondRequired mismatch: seller={} buyer={}",
                seller.bond_required, buyer.bond_required
            ));
        }
        let live_funded = self.state.funded && !self.state.is_stopped();
        if live_funded && (buyer.bond_required == 0 || buyer.bond_held != buyer.bond_required) {
            return Err(format!(
                "live funded subscription requires a fully held non-zero buyer bond, got \
                 bondHeld={} bondRequired={}",
                buyer.bond_held, buyer.bond_required
            ));
        }
        Ok(())
    }

    pub fn buyer_locked(&self) -> Result<u128, String> {
        self.state
            .deposit
            .checked_add(self.state.probe_tick)
            .and_then(|total| total.checked_add(self.buyer_bond.bond_held))
            .ok_or_else(|| {
                "getState().deposit + getState().probeTick + getBuyerBond().bondHeld exceeds uint128"
                    .to_string()
            })
    }
}

/// One exact raw `uint128` value. JSON uses a decimal string so values above `u64::MAX`
/// remain lossless for machine consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RawUint128(pub u128);

impl From<u128> for RawUint128 {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl fmt::Display for RawUint128 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for RawUint128 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for RawUint128 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        raw.parse::<u128>()
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// The exact write requested by a production settlement action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementAction {
    BuyerStop,
    SellerStop,
    Dispute,
    ReleaseDispute,
    ResolveDisputeTimeout,
}

impl fmt::Display for SettlementAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::BuyerStop => "buyer_stop",
            Self::SellerStop => "seller_stop",
            Self::Dispute => "dispute",
            Self::ReleaseDispute => "release_dispute",
            Self::ResolveDisputeTimeout => "resolve_dispute_timeout",
        };
        formatter.write_str(value)
    }
}

/// Authoritative event payload accepted for one production settlement action.
/// Literal contract field names are retained. In particular `toSeller` includes returned
/// collateral where the contract says so and is never relabelled as earned model payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event_kind", rename_all = "snake_case")]
pub enum SettlementActionEvent {
    ProbeBurned {
        buyer: String,
        #[serde(rename = "burnedProbe")]
        burned_probe: RawUint128,
        #[serde(rename = "burnedBond")]
        burned_bond: RawUint128,
        #[serde(rename = "refundToBuyer")]
        refund_to_buyer: RawUint128,
    },
    StreamStopped {
        buyer: String,
        #[serde(rename = "toSeller")]
        to_seller: RawUint128,
        #[serde(rename = "refundToBuyer")]
        refund_to_buyer: RawUint128,
    },
    StreamDisputed {
        buyer: String,
        at: u64,
    },
    DisputeResolved {
        #[serde(rename = "toSeller")]
        to_seller: RawUint128,
        #[serde(rename = "refundToBuyer")]
        refund_to_buyer: RawUint128,
        released: bool,
    },
}

/// Strict collateral facts captured immediately before the one action POST.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementActionBondState {
    #[serde(rename = "sellerBondHeld")]
    pub seller_bond_held: RawUint128,
    #[serde(rename = "sellerBondRequired")]
    pub seller_bond_required: RawUint128,
    #[serde(rename = "buyerBondHeld")]
    pub buyer_bond_held: RawUint128,
    #[serde(rename = "buyerBondRequired")]
    pub buyer_bond_required: RawUint128,
}

/// Strict getter facts read after the event from an active `TokenContract`.
/// `None` on [`SettlementActionReceipt::post_state`] means the account was already destroyed;
/// immutable event history remains authoritative, but getter-only fields are deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementActionPostState {
    #[serde(rename = "tokensFinal")]
    pub tokens_final: RawUint128,
    #[serde(rename = "tokensSuperseded")]
    pub tokens_superseded: RawUint128,
    #[serde(rename = "tokensPending")]
    pub tokens_pending: RawUint128,
    #[serde(rename = "sellerBondHeld")]
    pub seller_bond_held: RawUint128,
    #[serde(rename = "sellerBondRequired")]
    pub seller_bond_required: RawUint128,
    #[serde(rename = "buyerBondHeld")]
    pub buyer_bond_held: RawUint128,
    #[serde(rename = "buyerBondRequired")]
    pub buyer_bond_required: RawUint128,
    pub opened: bool,
    pub disputed: bool,
}

/// Small by-fact result returned by one real settlement write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementActionReceipt {
    pub token_contract: TokenContract,
    pub action: SettlementAction,
    pub message_id: String,
    pub created_at: u64,
    #[serde(flatten)]
    pub event: SettlementActionEvent,
    pub pre_bonds: SettlementActionBondState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_state: Option<SettlementActionPostState>,
}

impl fmt::Display for SettlementActionReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "token_contract={} action={} message_id={} created_at={}",
            self.token_contract, self.action, self.message_id, self.created_at
        )?;
        match &self.event {
            SettlementActionEvent::ProbeBurned {
                buyer,
                burned_probe,
                burned_bond,
                refund_to_buyer,
            } => write!(
                formatter,
                " event_kind=probe_burned buyer={buyer} burnedProbe={burned_probe} burnedBond={burned_bond} \
                 refundToBuyer={refund_to_buyer}"
            )?,
            SettlementActionEvent::StreamStopped {
                buyer,
                to_seller,
                refund_to_buyer,
            } => write!(
                formatter,
                " event_kind=stream_stopped buyer={buyer} toSeller={to_seller} \
                 refundToBuyer={refund_to_buyer}"
            )?,
            SettlementActionEvent::StreamDisputed { buyer, at } => {
                write!(formatter, " event_kind=stream_disputed buyer={buyer} at={at}")?
            }
            SettlementActionEvent::DisputeResolved {
                to_seller,
                refund_to_buyer,
                released,
            } => write!(
                formatter,
                " event_kind=dispute_resolved toSeller={to_seller} \
                 refundToBuyer={refund_to_buyer} released={released}"
            )?,
        }
        write!(
            formatter,
            " preSellerBondHeld={} preSellerBondRequired={} preBuyerBondHeld={} \
             preBuyerBondRequired={}",
            self.pre_bonds.seller_bond_held,
            self.pre_bonds.seller_bond_required,
            self.pre_bonds.buyer_bond_held,
            self.pre_bonds.buyer_bond_required
        )?;
        match &self.post_state {
            Some(state) => write!(
                formatter,
                " tokensFinal={} tokensSuperseded={} tokensPending={} sellerBondHeld={} \
                 sellerBondRequired={} buyerBondHeld={} buyerBondRequired={} opened={} disputed={}",
                state.tokens_final,
                state.tokens_superseded,
                state.tokens_pending,
                state.seller_bond_held,
                state.seller_bond_required,
                state.buyer_bond_held,
                state.buyer_bond_required,
                state.opened,
                state.disputed
            ),
            None => formatter.write_str(" post_state=unavailable"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        flags, DealBuyerBond, DealChainState, DealSellerBond, DealSubscription, SettlementAction,
        SettlementActionBondState, SettlementActionEvent, SettlementActionPostState,
        SettlementActionReceipt, SUBSCRIPTION_WEEKS,
    };
    use proptest::prelude::*;
    use serde_json::{json, Value};

    /// `deposit` carries the lifecycle distinction now: still-held escrow means the deal is live,
    /// a drained deposit means a terminal path already settled it.
    fn state(funded: bool, opened: bool, disputed: bool, deposit: u128) -> DealChainState {
        DealChainState {
            funded,
            opened,
            probe_accepted: true,
            disputed,
            deposit,
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
        }
    }

    /// monitor CLOSED semantics must match `dexdo status`: funded-never-opened,
    /// streaming, and disputed deals are active; only STOPped/settled is terminal.
    #[test]
    fn chain_state_stopped_semantics_match_status() {
        assert!(
            !state(true, false, false, 1_000).is_stopped(),
            "funded-but-never-opened still holds the whole escrow, so it is active"
        );
        assert!(
            !state(true, true, false, 1_000).is_stopped(),
            "an opened stream is active"
        );
        assert!(
            !state(true, true, false, 0).is_stopped(),
            "still opened is active even once the escrow is fully consumed"
        );
        assert!(
            !state(true, false, true, 1_000).is_stopped(),
            "disputed escrow is active, not cleanly closed"
        );
        assert!(
            !state(false, false, false, 0).is_stopped(),
            "unfunded/readable state is not a settled close"
        );
        assert!(
            state(true, false, false, 0).is_stopped(),
            "settled close drained the deposit -> status=stopped"
        );
    }

    /// A dispute is only ever about the tail the buyer has not yet had the window to accept.
    #[test]
    fn contested_tokens_is_the_unpromoted_tail() {
        let mut s = state(true, true, false, 1_000);
        s.tokens_final = 500;
        s.tokens_pending = 800;
        assert_eq!(
            s.contested_tokens(),
            300,
            "only claimed-minus-trusted is at stake"
        );

        s.tokens_pending = 500;
        assert_eq!(
            s.contested_tokens(),
            0,
            "nothing pending -> nothing to dispute"
        );

        // Terminal paths reset pending down to final; the tail must never read negative.
        s.tokens_pending = 400;
        assert_eq!(
            s.contested_tokens(),
            0,
            "a reset pending slot saturates at zero"
        );
    }

    fn exact_state() -> Value {
        json!({
            "funded": true,
            "opened": true,
            "probeAccepted": true,
            "disputed": false,
            "deposit": "100",
            "probeTick": "2",
            "finalizedOwed": "3",
            "tokensFinal": "10",
            "tokensSuperseded": "20",
            "tokensPending": "30",
            "probeTime": "40",
            "prevClaimTime": "50",
            "lastClaimTime": "60",
            "disputeTime": "0",
            "fundedTime": "70"
        })
    }

    fn exact_subscription() -> Value {
        json!({
            "dealFlags": flags::SUBSCRIPTION.to_string(),
            "subWeeks": SUBSCRIPTION_WEEKS.to_string(),
            "weekIndex": "1",
            "tokensPerWeek": "100",
            "fundedTokens": "400",
            "tokensPaid": "100",
            "periodStart": "70",
            "weekBaseTokens": "80"
        })
    }

    fn exact_ordinary_subscription() -> Value {
        json!({
            "dealFlags": "0",
            "subWeeks": "0",
            "weekIndex": "0",
            "tokensPerWeek": "400",
            "fundedTokens": "400",
            "tokensPaid": "0",
            "periodStart": "70",
            "weekBaseTokens": "0"
        })
    }

    fn exact_bond() -> Value {
        json!({
            "bondFunded": true,
            "bondHeld": "200",
            "bondRequired": "200"
        })
    }

    fn exact_buyer_bond() -> Value {
        json!({
            "bondHeld": "200",
            "bondRequired": "200"
        })
    }

    fn set_field(value: &mut Value, field: &str, replacement: Value) {
        value
            .as_object_mut()
            .expect("fixture object")
            .insert(field.to_string(), replacement);
    }

    #[test]
    fn get_state_decoder_accepts_exact_fifteen_field_abi() {
        let state = DealChainState::decode_getter(&exact_state()).expect("exact getState ABI");
        assert_eq!(state.finalized_owed, 3);
        assert_eq!(state.tokens_final, 10);
        assert_eq!(state.tokens_superseded, 20);
        assert_eq!(state.tokens_pending, 30);
        assert_eq!(state.prev_claim_time, 50);
        assert_eq!(state.funded_time, Some(70));
    }

    #[test]
    fn buyer_bond_decoder_accepts_exact_two_field_abi_and_preserves_width() {
        let mut value = exact_buyer_bond();
        set_field(&mut value, "bondHeld", json!(u128::MAX.to_string()));
        let decoded = DealBuyerBond::decode_getter(&value).expect("exact getBuyerBond ABI");
        assert_eq!(decoded.bond_held, u128::MAX);
        assert_eq!(decoded.bond_required, 200);
    }

    #[test]
    fn buyer_bond_decoder_rejects_every_field_mutation_missing_and_extra() {
        for field in ["bondHeld", "bondRequired"] {
            let mut missing = exact_buyer_bond();
            missing
                .as_object_mut()
                .expect("fixture object")
                .remove(field);
            assert!(
                DealBuyerBond::decode_getter(&missing).is_err(),
                "missing {field} must fail closed"
            );

            for replacement in [
                Value::Null,
                json!(1),
                json!("-1"),
                json!("0x1"),
                json!(""),
                json!("340282366920938463463374607431768211456"),
            ] {
                let mut mutated = exact_buyer_bond();
                set_field(&mut mutated, field, replacement);
                assert!(
                    DealBuyerBond::decode_getter(&mutated).is_err(),
                    "mutated {field} must fail closed"
                );
            }
        }

        let mut extra = exact_buyer_bond();
        set_field(&mut extra, "bondFunded", json!(true));
        assert!(DealBuyerBond::decode_getter(&extra).is_err());
    }

    #[test]
    fn get_state_decoder_rejects_every_missing_null_and_wrong_kind_field() {
        let bool_fields = ["funded", "opened", "probeAccepted", "disputed"];
        let numeric_fields = [
            "deposit",
            "probeTick",
            "finalizedOwed",
            "tokensFinal",
            "tokensSuperseded",
            "tokensPending",
            "probeTime",
            "prevClaimTime",
            "lastClaimTime",
            "disputeTime",
            "fundedTime",
        ];
        for field in bool_fields.into_iter().chain(numeric_fields) {
            let mut missing = exact_state();
            missing
                .as_object_mut()
                .expect("fixture object")
                .remove(field);
            assert!(
                DealChainState::decode_getter(&missing).is_err(),
                "missing {field} must fail closed"
            );

            let mut null = exact_state();
            set_field(&mut null, field, Value::Null);
            assert!(
                DealChainState::decode_getter(&null).is_err(),
                "null {field} must fail closed"
            );

            let mut wrong_kind = exact_state();
            set_field(
                &mut wrong_kind,
                field,
                if bool_fields.contains(&field) {
                    json!("false")
                } else {
                    json!(1)
                },
            );
            assert!(
                DealChainState::decode_getter(&wrong_kind).is_err(),
                "wrong JSON kind for {field} must fail closed"
            );
        }
    }

    #[test]
    fn get_state_decoder_rejects_non_decimal_overflow_and_extra_fields() {
        for field in [
            "deposit",
            "probeTick",
            "finalizedOwed",
            "tokensFinal",
            "tokensSuperseded",
            "tokensPending",
            "probeTime",
            "prevClaimTime",
            "lastClaimTime",
            "disputeTime",
            "fundedTime",
        ] {
            for bad in ["-1", "0x1", "", "+1", " 1"] {
                let mut state = exact_state();
                set_field(&mut state, field, json!(bad));
                assert!(
                    DealChainState::decode_getter(&state).is_err(),
                    "{field}={bad:?} must fail closed"
                );
            }
        }

        for field in [
            "deposit",
            "probeTick",
            "finalizedOwed",
            "tokensFinal",
            "tokensSuperseded",
            "tokensPending",
        ] {
            let mut state = exact_state();
            set_field(
                &mut state,
                field,
                json!("340282366920938463463374607431768211456"),
            );
            assert!(
                DealChainState::decode_getter(&state).is_err(),
                "uint128 overflow in {field} must fail closed"
            );
        }
        for field in [
            "probeTime",
            "prevClaimTime",
            "lastClaimTime",
            "disputeTime",
            "fundedTime",
        ] {
            let mut state = exact_state();
            set_field(&mut state, field, json!("18446744073709551616"));
            assert!(
                DealChainState::decode_getter(&state).is_err(),
                "uint64 overflow in {field} must fail closed"
            );
        }

        let mut extra = exact_state();
        set_field(&mut extra, "legacy", json!("0"));
        assert!(DealChainState::decode_getter(&extra).is_err());
    }

    #[test]
    fn get_state_decoder_rejects_non_monotonic_claim_pipeline_boundaries() {
        for (final_tokens, superseded, pending) in [(11, 10, 30), (10, 31, 30)] {
            let mut state = exact_state();
            set_field(&mut state, "tokensFinal", json!(final_tokens.to_string()));
            set_field(
                &mut state,
                "tokensSuperseded",
                json!(superseded.to_string()),
            );
            set_field(&mut state, "tokensPending", json!(pending.to_string()));
            assert!(DealChainState::decode_getter(&state).is_err());
        }

        let mut equal = exact_state();
        for field in ["tokensFinal", "tokensSuperseded", "tokensPending"] {
            set_field(&mut equal, field, json!("10"));
        }
        assert!(DealChainState::decode_getter(&equal).is_ok());
    }

    proptest! {
        #[test]
        fn get_state_decoder_preserves_monotonic_claim_pipeline(
            final_tokens in any::<u64>(),
            first_delta in any::<u32>(),
            second_delta in any::<u32>(),
        ) {
            let superseded = u128::from(final_tokens) + u128::from(first_delta);
            let pending = superseded + u128::from(second_delta);
            let mut state = exact_state();
            set_field(&mut state, "tokensFinal", json!(final_tokens.to_string()));
            set_field(&mut state, "tokensSuperseded", json!(superseded.to_string()));
            set_field(&mut state, "tokensPending", json!(pending.to_string()));
            let decoded = DealChainState::decode_getter(&state).expect("monotonic pipeline");
            prop_assert!(decoded.tokens_final <= decoded.tokens_superseded);
            prop_assert!(decoded.tokens_superseded <= decoded.tokens_pending);
        }
    }

    #[test]
    fn subscription_decoder_accepts_exact_new_state_and_ordinary_shape() {
        let subscription =
            DealSubscription::decode_getter(&exact_subscription()).expect("subscription getter");
        assert!(subscription.is_subscription());
        assert_eq!(subscription.week_base_tokens, 80);

        assert!(
            !DealSubscription::decode_getter(&exact_ordinary_subscription())
                .expect("ordinary getter")
                .is_subscription()
        );
    }

    #[test]
    fn subscription_decoder_rejects_contradictory_ordinary_weekly_fields() {
        for (field, value) in [
            ("tokensPerWeek", "401"),
            ("fundedTokens", "401"),
            ("weekBaseTokens", "1"),
        ] {
            let mut ordinary = exact_ordinary_subscription();
            set_field(&mut ordinary, field, json!(value));
            assert!(
                DealSubscription::decode_getter(&ordinary).is_err(),
                "ordinary getSubscription() with {field}={value} must fail closed"
            );
        }
    }

    #[test]
    fn subscription_decoder_rejects_all_field_mutations_and_shape_drift() {
        let fields = [
            "dealFlags",
            "subWeeks",
            "weekIndex",
            "tokensPerWeek",
            "fundedTokens",
            "tokensPaid",
            "periodStart",
            "weekBaseTokens",
        ];
        for field in fields {
            let mut missing = exact_subscription();
            missing
                .as_object_mut()
                .expect("fixture object")
                .remove(field);
            assert!(DealSubscription::decode_getter(&missing).is_err());

            for replacement in [Value::Null, json!(1), json!("-1"), json!("0x1")] {
                let mut mutated = exact_subscription();
                set_field(&mut mutated, field, replacement);
                assert!(
                    DealSubscription::decode_getter(&mutated).is_err(),
                    "mutated {field} must fail closed"
                );
            }
        }

        for (field, value) in [
            ("dealFlags", "256"),
            ("subWeeks", "256"),
            ("weekIndex", "256"),
        ] {
            let mut mutated = exact_subscription();
            set_field(&mut mutated, field, json!(value));
            assert!(DealSubscription::decode_getter(&mutated).is_err());
        }
        for field in [
            "tokensPerWeek",
            "fundedTokens",
            "tokensPaid",
            "weekBaseTokens",
        ] {
            let mut mutated = exact_subscription();
            set_field(
                &mut mutated,
                field,
                json!("340282366920938463463374607431768211456"),
            );
            assert!(DealSubscription::decode_getter(&mutated).is_err());
        }
        let mut time_overflow = exact_subscription();
        set_field(
            &mut time_overflow,
            "periodStart",
            json!("18446744073709551616"),
        );
        assert!(DealSubscription::decode_getter(&time_overflow).is_err());

        for (field, value) in [
            ("dealFlags", "128"),
            ("dealFlags", "0"),
            ("subWeeks", "3"),
            ("weekIndex", "5"),
            ("fundedTokens", "401"),
            ("tokensPaid", "401"),
            ("weekBaseTokens", "401"),
        ] {
            let mut mutated = exact_subscription();
            set_field(&mut mutated, field, json!(value));
            assert!(
                DealSubscription::decode_getter(&mutated).is_err(),
                "contradictory {field}={value} must fail closed"
            );
        }

        let mut extra = exact_subscription();
        set_field(&mut extra, "claimCap", json!("0"));
        assert!(DealSubscription::decode_getter(&extra).is_err());
    }

    #[test]
    fn seller_bond_decoder_rejects_missing_wrong_kind_non_decimal_and_overflow() {
        let bond = DealSellerBond::decode_getter(&exact_bond()).expect("exact bond getter");
        assert!(bond.bond_funded);
        assert_eq!(bond.bond_held, 200);
        assert_eq!(bond.bond_required, 200);

        for field in ["bondFunded", "bondHeld", "bondRequired"] {
            let mut missing = exact_bond();
            missing
                .as_object_mut()
                .expect("fixture object")
                .remove(field);
            assert!(DealSellerBond::decode_getter(&missing).is_err());

            let mut null = exact_bond();
            set_field(&mut null, field, Value::Null);
            assert!(DealSellerBond::decode_getter(&null).is_err());
        }
        for field in ["bondHeld", "bondRequired"] {
            for value in [json!(1), json!("-1"), json!("0x1")] {
                let mut mutated = exact_bond();
                set_field(&mut mutated, field, value);
                assert!(DealSellerBond::decode_getter(&mutated).is_err());
            }
            let mut overflow = exact_bond();
            set_field(
                &mut overflow,
                field,
                json!("340282366920938463463374607431768211456"),
            );
            assert!(DealSellerBond::decode_getter(&overflow).is_err());
        }
        let mut wrong_bool = exact_bond();
        set_field(&mut wrong_bool, "bondFunded", json!("true"));
        assert!(DealSellerBond::decode_getter(&wrong_bool).is_err());

        let mut extra = exact_bond();
        set_field(&mut extra, "legacy", json!("0"));
        assert!(DealSellerBond::decode_getter(&extra).is_err());
    }

    #[test]
    fn authoritative_receipt_json_and_text_preserve_raw_precision_without_tick_flooring() {
        let receipt = SettlementActionReceipt {
            token_contract: "0:tc".to_string(),
            action: SettlementAction::BuyerStop,
            message_id: "message-id".to_string(),
            created_at: 42,
            event: SettlementActionEvent::StreamStopped {
                buyer: format!("0:{}", "44".repeat(32)),
                to_seller: u128::MAX.into(),
                refund_to_buyer: (u64::MAX as u128 + 1).into(),
            },
            pre_bonds: SettlementActionBondState {
                seller_bond_held: 2_000_000_000u128.into(),
                seller_bond_required: 2_000_000_000u128.into(),
                buyer_bond_held: 2_000_000_000u128.into(),
                buyer_bond_required: 2_000_000_000u128.into(),
            },
            post_state: Some(SettlementActionPostState {
                tokens_final: 1_000_001u128.into(),
                tokens_superseded: 2_000_003u128.into(),
                tokens_pending: u128::MAX.into(),
                seller_bond_held: 0u128.into(),
                seller_bond_required: 2_000_000_000u128.into(),
                buyer_bond_held: 0u128.into(),
                buyer_bond_required: 2_000_000_000u128.into(),
                opened: false,
                disputed: false,
            }),
        };

        let encoded = serde_json::to_value(&receipt).unwrap();
        assert_eq!(encoded["buyer"], json!(format!("0:{}", "44".repeat(32))));
        assert_eq!(encoded["toSeller"], json!(u128::MAX.to_string()));
        assert_eq!(
            encoded["refundToBuyer"],
            json!((u64::MAX as u128 + 1).to_string())
        );
        assert_eq!(encoded["post_state"]["tokensFinal"], json!("1000001"));
        assert!(encoded.pointer("/post_state/toSellerTicks").is_none());
        assert!(encoded.get("cursor").is_none());
        assert!(encoded.get("post_account_active").is_none());
        assert!(encoded.pointer("/post_state/finalizedOwed").is_none());
        assert!(encoded.pointer("/post_state/deposit").is_none());
        let round_trip: SettlementActionReceipt = serde_json::from_value(encoded).unwrap();
        assert_eq!(round_trip, receipt);

        let text = receipt.to_string();
        assert!(text.contains(&format!("buyer=0:{}", "44".repeat(32))));
        assert!(text.contains(&format!("toSeller={}", u128::MAX)));
        assert!(text.contains("tokensFinal=1000001"));
        assert!(!text.contains("ticks="));
    }

    #[test]
    fn dispute_opened_has_no_projected_money_and_destroyed_terminal_omits_getters() {
        let dispute = SettlementActionReceipt {
            token_contract: "0:tc".to_string(),
            action: SettlementAction::Dispute,
            message_id: "dispute-message".to_string(),
            created_at: 43,
            event: SettlementActionEvent::StreamDisputed {
                buyer: format!("0:{}", "44".repeat(32)),
                at: 43,
            },
            pre_bonds: SettlementActionBondState {
                seller_bond_held: 2_000_000_000u128.into(),
                seller_bond_required: 2_000_000_000u128.into(),
                buyer_bond_held: 0u128.into(),
                buyer_bond_required: 0u128.into(),
            },
            post_state: Some(SettlementActionPostState {
                tokens_final: 1u128.into(),
                tokens_superseded: 0u128.into(),
                tokens_pending: 1u128.into(),
                seller_bond_held: 2_000_000_000u128.into(),
                seller_bond_required: 2_000_000_000u128.into(),
                buyer_bond_held: 0u128.into(),
                buyer_bond_required: 0u128.into(),
                opened: true,
                disputed: true,
            }),
        };
        let encoded = serde_json::to_value(&dispute).unwrap();
        assert_eq!(encoded["event_kind"], json!("stream_disputed"));
        assert_eq!(encoded["at"], json!(43));
        assert!(encoded.get("toSeller").is_none());
        assert!(encoded.get("refundToBuyer").is_none());

        let terminal = SettlementActionReceipt {
            token_contract: "0:tc".to_string(),
            action: SettlementAction::ReleaseDispute,
            message_id: "resolve-message".to_string(),
            created_at: 44,
            event: SettlementActionEvent::DisputeResolved {
                to_seller: 7u128.into(),
                refund_to_buyer: 8u128.into(),
                released: true,
            },
            pre_bonds: dispute.pre_bonds,
            post_state: None,
        };
        let terminal_json = serde_json::to_value(&terminal).unwrap();
        assert!(terminal_json.get("post_state").is_none());
        assert!(terminal.to_string().contains("post_state=unavailable"));
    }

    #[test]
    fn canonical_getter_decoders_have_no_silent_default_path() {
        let production = include_str!("types.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source before tests");
        for forbidden in ["unwrap_or(", "unwrap_or_default(", ".unwrap_or_else("] {
            assert!(
                !production.contains(forbidden),
                "strict getter decoder source must not contain silent default path {forbidden}"
            );
        }
    }

    #[test]
    fn production_consumers_never_read_deleted_state_fields() {
        let sources = [
            ("core chain", include_str!("mod.rs")),
            (
                "core shellnet backend",
                include_str!("../shellnet/backends.rs"),
            ),
            (
                "core shellnet client",
                include_str!("../shellnet/client.rs"),
            ),
            ("CLI deals", include_str!("../../../dexdo/src/cli/deals.rs")),
            ("CLI audit", include_str!("../../../dexdo/src/cli/audit.rs")),
            (
                "CLI dashboard",
                include_str!("../../../dexdo/src/cli/dashboard.rs"),
            ),
            (
                "CLI reports",
                include_str!("../../../dexdo/src/cli/reports.rs"),
            ),
            (
                "CLI machine schema",
                include_str!("../../../dexdo/src/cli/machine.rs"),
            ),
            ("CLI close", include_str!("../../../dexdo/src/cli/close.rs")),
            (
                "CLI recover",
                include_str!("../../../dexdo/src/cli/recover.rs"),
            ),
            ("CLI args", include_str!("../../../dexdo/src/cli/args.rs")),
            ("CLI main help", include_str!("../../../dexdo/src/main.rs")),
        ];
        for (source_name, source) in sources {
            for (line_index, line) in source.lines().enumerate() {
                let names_deleted_field = ["prepaid", "frozen", "lastAdvance"]
                    .iter()
                    .any(|field| line.contains(field));
                let reads_field = line.contains(".get(")
                    || line.contains("[\"")
                    || line.contains("u128_field")
                    || line.contains("u64_field")
                    || line.contains(".prepaid")
                    || line.contains(".frozen")
                    || line.contains(".last_advance");
                let renders_deleted_field = line.contains("\"lastAdvance\"")
                    || line.contains("last_advance")
                    || line.contains("\"prepaid\"")
                    || line.contains(".prepaid")
                    || line.contains(" prepaid:")
                    || line.contains("prepaid=")
                    || line.contains("\"frozen\"")
                    || line.contains(".frozen")
                    || line.contains(" frozen:")
                    || line.contains("frozen=");
                let advertises_deleted_reclaim = line.contains("streamReclaim")
                    || line.contains("reclaimOnTimeout")
                    || line.contains("STREAM_TIMEOUT");
                assert!(
                    !(names_deleted_field && reads_field)
                        && !(source_name.starts_with("CLI")
                            && (renders_deleted_field || advertises_deleted_reclaim)),
                    "{source_name}:{} still reads/renders a deleted field or reclaim path: {}",
                    line_index + 1,
                    line.trim()
                );
            }
        }
    }
}

/// Post-fill state of a `TokenContract` reported by a model-only buyer match event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchedTokenContractStatus {
    Opened,
    FundedNeverOpened {
        funded_time: Option<u64>,
        cleanup_after_unix: Option<u64>,
        cleanup_ready: bool,
        remaining_secs: Option<u64>,
    },
}

/// The note's role in a deal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DealRole {
    Buyer,
    Seller,
}

/// View of one of the note's deals for the monitor: contract, role, **anonymous**
/// counterparty, tick price and the by-fact settlement(`StreamSnapshot`).
#[derive(Debug, Clone)]
pub struct DealView {
    pub token_contract: TokenContract,
    pub role: DealRole,
    /// The counterparty's anonymous note pubkey(hex), if a match has already happened.
    pub counterparty: Option<String>,
    pub price_per_tick: Shell,
    /// The deal's served frame model id. `None` when the source cannot
    /// name it -- the mock book does not track a per-deal model, so it resolves on the real-chain reader
    /// (the `TokenContract`'s `RootModel` -> model name). The breakdown buckets `None` as `(unknown)`.
    pub model: Option<String>,
    /// The by-fact settlement(ticks/tokens/burn/closed), if the stream is open.
    pub snapshot: Option<StreamSnapshot>,
}

/// Snapshot of the note's state for observability: own orders in the book,
/// deals(role + anonymous counterparty + by-fact), total exposure(at risk). "From whom"
/// = the note's anonymous pubkey. Read only -- the monitor moves nothing.
#[derive(Debug, Clone)]
pub struct NoteSnapshot {
    /// The note's own anonymous pubkey(hex).
    pub note_id: String,
    /// Own offers in the book(the seller's orders).
    pub offers: Vec<OfferListing>,
    /// Deals where the note is the seller or the buyer.
    pub deals: Vec<DealView>,
    /// At risk: the role-side funds held in this note's open(not closed) deal TCs.
    pub exposure: Shell,
}

/// Aggregated snapshot of **the entire note tree** of a single identity: the monitor
/// shows the state across ALL(sub)notes under the root key, not only the root. We fold the
/// per-note snapshots(`ChainBackend::note_snapshot` for each pubkey from `NoteTree::node_pubkeys`):
/// offers and deals are concatenated(each lives on its own subnote), exposure is summed.
/// "From whom" remains the counterparty note's anonymous pubkey. Read only.
#[derive(Debug, Clone)]
pub struct TreeSnapshot {
    /// Anonymous pubkeys of all the tree's(sub)notes that were aggregated over(hex).
    pub note_ids: Vec<String>,
    /// All the tree's offers in the book(across all subnotes).
    pub offers: Vec<OfferListing>,
    /// All the tree's deals(across all subnotes), role + anonymous counterparty + by-fact.
    pub deals: Vec<DealView>,
    /// The tree's total exposure: role-side funds held across all open deal TCs of all subnotes.
    pub exposure: Shell,
}

/// Placeholder model id for a deal whose served model is unknown to the source: the mock book
/// tracks no per-deal model, so its deals bucket here until the real-chain reader resolves real names.
pub const UNKNOWN_MODEL: &str = "(unknown)";

/// One counterparty's by-fact tally inside a model bucket: the anonymous counterparty note
/// pubkey and the by-fact figures summed across that counterparty's deals for one role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterpartyTally {
    /// The counterparty's anonymous note pubkey(hex); `None` if no match happened yet.
    pub counterparty: Option<String>,
    /// Finalized ticks settled by-fact, summed: authoritative `tokens_final / TICK_SIZE`.
    pub tokens: u64,
    /// SHELL settled by-fact(seller: received; buyer: paid out of escrow) -- `seller_received`, summed.
    pub money: Shell,
    /// SHELL still frozen for this role(seller: `seller_locked`; buyer: `buyer_locked`), summed.
    pub locked: Shell,
    /// SHELL burned(net fee / dispute), summed.
    pub burned: Shell,
}

/// Per-model by-fact breakdown for ONE role: the note's deals grouped by served model, then by
/// anonymous counterparty, summing tokens / money / lock / burn. Pure(no network) -- the offline core of the
/// seller/buyer accounting view. The roll-up fields are the model's totals across all its counterparties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelBreakdown {
    /// The served model id, or [`UNKNOWN_MODEL`] for deals with no known model.
    pub model: String,
    pub role: DealRole,
    /// Per-counterparty tallies, in first-seen order(deterministic).
    pub counterparties: Vec<CounterpartyTally>,
    pub tokens: u64,
    pub money: Shell,
    pub locked: Shell,
    pub burned: Shell,
}

/// A by-fact accounting anomaly on a deal: a-class problem the accounting view must
/// **surface** rather than paper over(the lead's acceptance: "show the mismatch", "highlight orphaned lock").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DealAnomaly {
    /// SHELL is locked but no counterparty matched -- an **orphaned lock**: funds frozen with no deal.
    LockedNoMatch { locked: Shell },
    /// The deal is **closed**(STOP/settled) yet SHELL is still locked -- STOP should have moved it to
    /// received/refunded, not left it frozen.
    LockedAfterClose { locked: Shell },
    /// The buyer's at-risk **lead**(`prepaid + frozen`) exceeds the **two-tick invariant** ceiling (: the
    /// seller may be at most ~2 ticks ahead of finalized) -- `buyer_lead > 2 x _unit(price_per_tick)`, where the
    /// per-tick unit **includes the book fee** (`_unit(p) = p + pxFEE_BPS/10000`,).: this bounds the
    /// LEAD, not the total `buyer_locked` (which carries the unspent `deposit` for a multi-tick deal's remaining
    /// ticks) -- comparing the total false-flagged every legitimate `maxTicks > 2` deal.
    BuyerLockExceedsTwoTicks { buyer_lead: Shell, ceiling: Shell },
}
