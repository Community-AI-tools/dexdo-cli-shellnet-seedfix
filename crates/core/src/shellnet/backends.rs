#[cfg(test)]
use super::client::{
    active_check, code_hash_check, is_uninit_account_404, ShellnetDoctorStatus,
    TokenContractSettlementReceipt,
};
use super::client::{
    MessagePostResponseDecodeError, RealChainBackend, SellerOfferEvents,
    TokenContractSettlementEvent, TokenContractSettlementReceipts,
};
use super::contracts_provision::*;
use crate::chain::{
    check_buy_deposit_headroom, coalesce_equivalent_resting_asks, validate_seller_resume_state,
    ChainBackend, ChainError, ClaimBounds, DealChainSnapshot, DealChainState, DealRole,
    DealSellerBond, DealSubscription, DealView, ExecutableQuote, Match, MatchWatchCursor,
    MatchedFill, OrderBookOrder, OrderBookSnapshot, OrderBookStats, SellOffer, SellOfferOutcome,
    StreamSnapshot, TokenContract,
};
use crate::machine::Settlement;
use crate::manifest::model_hash_for;
use crate::note::{LocalNote, Note, NoteError, NotePubkey, Signature};
#[cfg(test)]
use crate::params::SUBSCRIPTION_WEEKS;
use crate::params::{
    cli_buy_deadline_is_valid, default_buy_deadline, ClaimConfirmationParams, Shell,
    MATCH_OPEN_TIMEOUT_SECS, OFFER_ACCEPTANCE_TIMEOUT, POST_SELL_OFFER_SUBMIT_TIMEOUT,
    SELLER_READ_BACKOFF, TICK_SIZE,
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
#[cfg(test)]
use gosh_ackinacki::airegistry::deploy::{build_deploy, local_context};
use gosh_ackinacki::sdk::{Address, KeyPair};
use serde_json::{json, Value};

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn buy_deadline_now_secs() -> Result<u64, ChainError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| {
            ChainError::Chain(format!(
                "cannot derive a finite BUY deadline from the system clock: {error}"
            ))
        })
}

fn canonical_cli_buy_deadline(context: &str) -> Result<u64, ChainError> {
    let now = buy_deadline_now_secs()?;
    default_buy_deadline(now).ok_or_else(|| {
        ChainError::Chain(format!(
            "{context}: current unix time {now} plus the canonical BUY lifetime overflows u64"
        ))
    })
}

fn validate_cli_buy_deadline_at(context: &str, deadline: u64, now: u64) -> Result<(), ChainError> {
    if cli_buy_deadline_is_valid(deadline, now) {
        return Ok(());
    }
    if deadline == 0 {
        return Err(ChainError::Chain(format!(
            "{context}: deadline 0 requests GTC, which the contract permits but the strict dexdo CLI \
             policy forbids; provide a finite future deadline"
        )));
    }
    Err(ChainError::Chain(format!(
        "{context}: BUY deadline {deadline} must be strictly later than current unix time {now}"
    )))
}

fn validate_cli_buy_deadline(context: &str, deadline: u64) -> Result<(), ChainError> {
    validate_cli_buy_deadline_at(context, deadline, buy_deadline_now_secs()?)
}

#[cfg(test)]
mod buy_deadline_policy_tests {
    use super::*;

    fn method_body<'a>(source: &'a str, adapter: &str, method: &str) -> &'a str {
        let marker = format!("impl ChainBackend for {adapter} {{");
        let implementation = source
            .split_once(&marker)
            .unwrap_or_else(|| panic!("missing {adapter} implementation"))
            .1;
        let marker = format!("    async fn {method}");
        let method = implementation
            .split_once(&marker)
            .unwrap_or_else(|| panic!("missing {adapter}::{method}"))
            .1;
        method
            .split_once("\n    async fn ")
            .map_or(method, |(body, _)| body)
    }

    #[test]
    fn strict_cli_policy_rejects_gtc_present_and_past_deadlines() {
        let now = 1_900_000_000;
        for deadline in [0, now - 1, now] {
            assert!(
                validate_cli_buy_deadline_at("test buyer", deadline, now).is_err(),
                "deadline {deadline} must fail before a money write"
            );
        }
        assert!(validate_cli_buy_deadline_at("test buyer", now + 1, now).is_ok());
        let gtc = validate_cli_buy_deadline_at("test buyer", 0, now)
            .expect_err("strict client policy must reject GTC")
            .to_string();
        assert!(gtc.contains("contract permits"), "{gtc}");
        assert!(gtc.contains("dexdo CLI"), "{gtc}");
    }

    #[test]
    fn every_real_buy_submit_has_a_finite_deadline_guard_before_the_money_write() {
        let source = include_str!("backends.rs");
        for (adapter, method, submit) in [
            ("RealDealBackend", "place_buy(", ".place_inference_buy("),
            ("RealBuyerBackend", "place_buy(", ".place_inference_buy("),
            (
                "RealBuyerBackend",
                "place_buy_by_model_with_submit_identity(",
                ".place_inference_buy_with_submit_identity(",
            ),
        ] {
            let body = method_body(source, adapter, method);
            let deadline = body
                .find("canonical_cli_buy_deadline(")
                .unwrap_or_else(|| panic!("{adapter}::{method} lacks a canonical finite deadline"));
            let submit = body
                .find(submit)
                .unwrap_or_else(|| panic!("{adapter}::{method} lacks its money submit"));
            assert!(
                deadline < submit,
                "{adapter}::{method} must derive its finite deadline before the money submit"
            );
        }

        let model = method_body(source, "RealBuyerBackend", "place_buy_by_model(");
        let validation = model
            .find("validate_cli_buy_deadline(")
            .expect("caller deadline validation");
        let submit = model
            .find(".place_inference_buy(")
            .expect("model-only money submit");
        assert!(
            validation < submit,
            "caller-provided deadline must be validated before the model-only money submit"
        );
    }
}

const DUPLICATE_SELL_MESSAGE: &str = "this TokenContract already has a live resting SELL";

fn classify_seller_offer_outcome(
    events: SellerOfferEvents,
    matched_state: bool,
) -> Result<Option<SellOfferOutcome>, ChainError> {
    if events.matched || matched_state {
        return Ok(Some(SellOfferOutcome::Matched));
    }
    if let Some(order_id) = events.placed_order_id {
        return Ok(Some(SellOfferOutcome::Rested { order_id }));
    }
    if events.placement_value_returned {
        return Err(ChainError::DuplicateSell(
            DUPLICATE_SELL_MESSAGE.to_string(),
        ));
    }
    Ok(None)
}

fn normalized_hash_eq(left: &str, right: &str) -> bool {
    let norm = |s: &str| {
        s.trim()
            .strip_prefix("0x")
            .or_else(|| s.trim().strip_prefix("0X"))
            .unwrap_or(s.trim())
            .to_ascii_lowercase()
    };
    norm(left) == norm(right)
}

struct ModelOnlyResumeFacts<'a> {
    state: Option<DealChainState>,
    model_name: Option<&'a str>,
    model_hash: Option<&'a str>,
    buyer_note: Option<&'a str>,
    buyer_pubkey: Option<&'a [u8; 32]>,
    order_book: Option<&'a str>,
}

fn validate_model_only_resume_facts(
    token_contract: &str,
    facts: ModelOnlyResumeFacts<'_>,
    expected_model_hash: &str,
    expected_buyer_note: &str,
    expected_buyer_pubkey: &[u8; 32],
    now: u64,
) -> Result<(), ChainError> {
    let state = facts.state.ok_or_else(|| {
        ChainError::Chain(format!(
            "model-only resume: TokenContract {token_contract} is not active on-chain"
        ))
    })?;
    if !state.funded {
        return Err(ChainError::Chain(format!(
            "model-only resume: TokenContract {token_contract} is not funded by-fact (funded=false)"
        )));
    }
    if state.disputed {
        return Err(ChainError::Chain(format!(
            "model-only resume: TokenContract {token_contract} is disputed by-fact"
        )));
    }
    // funded + !opened is either "the seller has not opened yet"(resumable) or "it already ran and
    // settled". Every terminal path drains the deposit, so a zeroed deposit on a funded deal means the
    // latter and there is nothing left to resume.
    if state.is_stopped() {
        return Err(ChainError::Chain(format!(
            "model-only resume: TokenContract {token_contract} is funded with opened=false and the \
             deposit already drained (tokensFinal={}) -- it was opened and settled earlier",
            state.tokens_final
        )));
    }
    if !state.opened {
        let funded_time = state.funded_time.ok_or_else(|| {
            ChainError::Chain(format!(
                "model-only resume: TokenContract {token_contract} is funded but getState has no fundedTime"
            ))
        })?;
        let cleanup_at = funded_time.saturating_add(MATCH_OPEN_TIMEOUT_SECS);
        if now >= cleanup_at {
            return Err(ChainError::Chain(format!(
                "model-only resume: TokenContract {token_contract} is stale never-opened by-fact \
                 (fundedTime {funded_time} + MATCH_OPEN_TIMEOUT {MATCH_OPEN_TIMEOUT_SECS} <= now {now}); \
                 run buyer recovery/cleanup instead of waiting for handover"
            )));
        }
    }

    let model_name = facts.model_name.ok_or_else(|| {
        ChainError::Chain(format!(
            "model-only resume: TokenContract {token_contract} exposes no on-chain model name"
        ))
    })?;
    if !normalized_hash_eq(&model_hash_for(model_name), expected_model_hash) {
        return Err(ChainError::Chain(format!(
            "model-only resume: TokenContract {token_contract} is for wrong model `{model_name}`"
        )));
    }
    let model_hash = facts.model_hash.ok_or_else(|| {
        ChainError::Chain(format!(
            "model-only resume: TokenContract {token_contract} exposes no on-chain model hash"
        ))
    })?;
    if !normalized_hash_eq(model_hash, expected_model_hash) {
        return Err(ChainError::Chain(format!(
            "model-only resume: TokenContract {token_contract} model_hash {model_hash} does not match \
             expected {expected_model_hash}"
        )));
    }

    let buyer_note = facts.buyer_note.ok_or_else(|| {
        ChainError::Chain(format!(
            "model-only resume: TokenContract {token_contract} has no recorded buyer note"
        ))
    })?;
    let norm =
        |s: &str| crate::normalize_wallet_address(s).unwrap_or_else(|_| s.trim().to_string());
    if norm(buyer_note) != norm(expected_buyer_note) {
        return Err(ChainError::Chain(format!(
            "model-only resume: TokenContract {token_contract} buyer note {buyer_note} is not this buyer note \
             {expected_buyer_note}"
        )));
    }
    let buyer_pubkey = facts.buyer_pubkey.ok_or_else(|| {
        ChainError::Chain(format!(
            "model-only resume: TokenContract {token_contract} has no recorded buyer pubkey"
        ))
    })?;
    if buyer_pubkey != expected_buyer_pubkey {
        return Err(ChainError::Chain(format!(
            "model-only resume: TokenContract {token_contract} buyer pubkey is not this buyer key"
        )));
    }
    if facts.order_book.is_none() {
        return Err(ChainError::Chain(format!(
            "model-only resume: current model order book is not active for TokenContract {token_contract}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod model_only_resume_tests {
    use super::*;

    fn open_state() -> DealChainState {
        DealChainState {
            funded: true,
            opened: true,
            probe_accepted: true,
            disputed: false,
            deposit: 1_000,
            finalized_owed: 0,
            tokens_final: 0,
            tokens_superseded: 0,
            tokens_pending: 0,
            funded_time: Some(1_000),
            probe_tick: 0,
            probe_time: 0,
            prev_claim_time: 0,
            last_claim_time: 1_010,
            dispute_time: 0,
        }
    }

    fn facts<'a>(
        state: Option<DealChainState>,
        model_name: &'a str,
        model_hash: &'a str,
        buyer_note: &'a str,
        buyer_pubkey: &'a [u8; 32],
    ) -> ModelOnlyResumeFacts<'a> {
        ModelOnlyResumeFacts {
            state,
            model_name: Some(model_name),
            model_hash: Some(model_hash),
            buyer_note: Some(buyer_note),
            buyer_pubkey: Some(buyer_pubkey),
            order_book: Some("0:book"),
        }
    }

    #[test]
    fn model_only_resume_rejects_wrong_model() {
        let pk = [7u8; 32];
        let expected_hash = model_hash_for("qwen--qwen3--32b");
        let wrong_hash = model_hash_for("llama--llama3--8b");

        let err = validate_model_only_resume_facts(
            "0:tc",
            facts(
                Some(open_state()),
                "llama--llama3--8b",
                &wrong_hash,
                "0:buyer",
                &pk,
            ),
            &expected_hash,
            "0:buyer",
            &pk,
            1_100,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("wrong model"), "{err}");
    }

    #[test]
    fn model_only_resume_rejects_wrong_market_buyer_note() {
        let pk = [7u8; 32];
        let expected_hash = model_hash_for("qwen--qwen3--32b");

        let err = validate_model_only_resume_facts(
            "0:tc",
            facts(
                Some(open_state()),
                "qwen--qwen3--32b",
                &expected_hash,
                "0:other",
                &pk,
            ),
            &expected_hash,
            "0:buyer",
            &pk,
            1_100,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("buyer note"), "{err}");
        assert!(err.contains("not this buyer note"), "{err}");
    }

    #[test]
    fn model_only_resume_rejects_wrong_token_contract_state() {
        let pk = [7u8; 32];
        let expected_hash = model_hash_for("qwen--qwen3--32b");
        let mut unfunded = open_state();
        unfunded.funded = false;

        let err = validate_model_only_resume_facts(
            "0:tc",
            facts(
                Some(unfunded),
                "qwen--qwen3--32b",
                &expected_hash,
                "0:buyer",
                &pk,
            ),
            &expected_hash,
            "0:buyer",
            &pk,
            1_100,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("funded=false"), "{err}");
    }

    #[test]
    fn model_only_resume_rejects_stale_never_opened_match() {
        let pk = [7u8; 32];
        let expected_hash = model_hash_for("qwen--qwen3--32b");
        let mut stale = open_state();
        stale.opened = false;
        stale.funded_time = Some(1_000);

        let err = validate_model_only_resume_facts(
            "0:tc",
            facts(
                Some(stale),
                "qwen--qwen3--32b",
                &expected_hash,
                "0:buyer",
                &pk,
            ),
            &expected_hash,
            "0:buyer",
            &pk,
            1_000 + MATCH_OPEN_TIMEOUT_SECS,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("stale never-opened"), "{err}");
    }
}

/// A note on top of `gosh.ackinacki`. The **ed25519 signature** of the chain/challenge -- from
/// the SDK [`KeyPair`] (the same pubkey is registered on-chain as `buyerPubkey`, against which the gateway checks
/// the signature). The **x25519 handover** -- on the dexdo crypto of([`LocalNote`]): the SDK
/// by-design does not expose X25519(the agent's root identity is a different layer). `pubkey()` carries both pubkeys, as in the mock.
pub struct RealNote {
    handover: LocalNote,
    keypair: KeyPair,
}

impl RealNote {
    /// A fresh note: ed25519 SDK `KeyPair`(signature/chain) + x25519 handover, **derived from
    /// it**(see `from_keypair`). A freshly generated `KeyPair` always carries a valid
    /// 32-byte ed25519 seed(the `KeyPair::generate` invariant), so the reconstruction does not fail.
    pub fn generate() -> Self {
        Self::from_keypair(KeyPair::generate())
            .expect("freshly generated SDK KeyPair carries a valid 32-byte ed25519 seed")
    }

    /// A note on a given ed25519 key(an on-chain actor).: the x25519 handover **is derived from
    /// ed25519**(Montgomery form), so that the seller reconstructs the buyer's pubkey from on-chain
    /// `getBuyerPubkey`(ed25519) -- no separate x25519 channel is needed. Requires a standard ed25519 seed
    /// for the SDK key(the invariant is pinned by the test `realnote_x25519_handover_derives_from_ed25519`).
    /// This is the **production path**(the actor loads the key from `--note-key`): the external secret may be malformed,
    /// so we return a typed [`NoteError::BadKey`] rather than panic.
    pub fn from_keypair(keypair: KeyPair) -> Result<Self, NoteError> {
        let secret = keypair.secret_hex();
        let bytes = decode_hex(secret.trim_start_matches("0x")).map_err(|_| NoteError::BadKey)?;
        if bytes.len() < 32 {
            return Err(NoteError::BadKey);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[..32]);
        let handover =
            LocalNote::from_ed25519_signing(ed25519_dalek::SigningKey::from_bytes(&seed));
        Ok(Self { handover, keypair })
    }

    /// A note from an SDK key's hex secret -- a convenience constructor for the CLI: the actor loads the owner key
    /// of the minted `PrivateNote` from `--note-key`. Builds a `KeyPair` from hex and derives the handover from ed25519.
    /// Malformed hex / non-ed25519 seed -> a typed [`NoteError::BadKey`](not a panic).
    pub fn from_secret_hex(secret_hex: &str) -> Result<Self, NoteError> {
        let keypair = KeyPair::from_secret_hex(secret_hex.trim()).map_err(|_| NoteError::BadKey)?;
        Self::from_keypair(keypair)
    }
}

impl Note for RealNote {
    fn pubkey(&self) -> NotePubkey {
        let bytes = decode_hex(self.keypair.public_hex().trim_start_matches("0x"))
            .expect("ed25519 public hex from SDK");
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&bytes);
        NotePubkey {
            x: self.handover.pubkey().x,
            ed,
        }
    }

    fn encrypt_to(&self, peer: &NotePubkey, msg: &[u8]) -> Vec<u8> {
        self.handover.encrypt_to(peer, msg)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, NoteError> {
        self.handover.decrypt(ciphertext)
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        let sig = self.keypair.sign(msg).expect("ed25519 sign");
        let bytes = decode_hex(sig.hex().trim_start_matches("0x")).expect("signature hex from SDK");
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Signature(arr)
    }
}

/// The context of a SINGLE deal on the real chain for the [`RealDealBackend`] adapter: everything not present in
/// the mock form of the `ChainBackend` trait -- the book address, the actors' notes+keys(+ nonce), the buyer's
/// x25519 pubkey and the deal terms. The seller side is **note-funded**: the exact `2P` seller bond is posted by
/// the seller note itself(`postSellerBond` from its own ECC[2]) -- no operator wallet. Provisioned ahead of
/// time by [`RealChainBackend::provision_market`](note-funded), then placed here.
pub struct DealContext {
    pub order_book: Address,
    /// `modelHash`(uint256 hex) - buyer placement, book deployment, and getters use it.
    /// The 4.0.26 seller note instead derives the model and book from its runtime fields.
    pub model_hash: String,
    /// The seller's deal nonce: the `_nonce` static the per-deal `TokenContract` is deployed with and the
    /// only deal identifier forwarded by the client in 4.0.26 `note.postSellOffer(flags, nonce)`.
    pub nonce: u64,
    pub seller_note: Address,
    pub seller_keys: KeyPair,
    pub buyer_note: Address,
    pub buyer_keys: KeyPair,
    pub buyer_pubkey: NotePubkey,
    pub price_per_tick: u128,
    pub max_ticks: u128,
    /// How many ticks the buyer buys(budget/escrow for `placeInferenceBuy`).
    pub ticks: u128,
    pub escrow: u128,
}

/// A `ChainBackend` trait adapter on top of [`RealChainBackend`] for a SINGLE deal on shellnet
/// . The trait `token_contract: String` = the on-chain `TokenContract` address.
/// **Impedance**:
/// - `Shell`(u64) <- the raw on-chain value(testnet magnitudes fit);
/// - `Settlement`(`stop`/`seller_timeout`) is computed from the TC state **before** the call -- without events;
/// - `snapshot.burned`/`buyer_refunded` are not in `getState`(payout/burn are outside the getter) -- `0` in the snapshot;
/// the actual magnitudes are carried by `Settlement` from `stop`/`seller_timeout`.
pub struct RealDealBackend {
    chain: RealChainBackend,
    ctx: DealContext,
}

impl RealDealBackend {
    /// Assemble the adapter from an(already connected) low-level backend and a provisioned deal context.
    pub fn new(chain: RealChainBackend, ctx: DealContext) -> Self {
        Self { chain, ctx }
    }

    /// Wait for a boolean TC state flag. `submit` is asynchronous(the contract executes across blocks),
    /// so the trait's transition methods wait for the effect to be applied before returning(the trait's synchronous semantics).
    async fn wait_state_bool(&self, tc: &Address, key: &str, want: bool) -> Result<(), ChainError> {
        wait_tc_bool(&self.chain, tc, key, want).await
    }

    async fn ensure_tc_gas(&self, tc: &Address) -> Result<(), ChainError> {
        self.chain
            .ensure_deal_contract_gas(
                &self.ctx.seller_note,
                &self.ctx.seller_keys,
                self.ctx.nonce,
                None,
                Some(tc),
            )
            .await
            .map_err(map_err)
    }
}

/// Pre-settlement view of a deal(`getState` + `getSellerBond`) -- enough to validate a terminal write
/// and project its outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcSettleState {
    opened: bool,
    /// The trial tick has been accepted, so the deal is claimable and settles by fact. While false a STOP
    /// burns the probe on both sides instead.
    probe_accepted: bool,
    /// SHELL held as the unaccepted probe -- owed to nobody.
    probe_tick: u128,
    /// Promoted consumption: irrevocably the seller's.
    tokens_final: u128,
    /// Newest claim, still contestable. `tokens_pending - tokens_final` is the contested tail.
    tokens_pending: u128,
    /// Buyer escrow still held.
    deposit: u128,
    /// Seller bond still held.
    seller_bond: u128,
}

impl TcSettleState {
    /// The contested tail -- the only value a dispute puts at stake.
    #[cfg(test)]
    fn contested_tokens(&self) -> u128 {
        self.tokens_pending.saturating_sub(self.tokens_final)
    }

    /// Whole ticks of promoted consumption, i.e. what the seller has actually earned so far.
    #[cfg(test)]
    fn trusted_ticks(&self) -> u64 {
        u64::try_from(self.tokens_final / crate::params::TICK_SIZE).unwrap_or(u64::MAX)
    }
}

/// Read the pre-settlement view from the TC -- for computing `Settlement`/the snapshot.
async fn tc_settle_state(chain: &RealChainBackend, tc: &Address) -> Result<TcSettleState> {
    let snapshot = chain
        .token_contract_deal_snapshot(tc)
        .await?
        .ok_or_else(|| anyhow!("TC is not active"))?;
    let st = snapshot.state;
    Ok(TcSettleState {
        opened: st.opened,
        probe_accepted: st.probe_accepted,
        probe_tick: st.probe_tick,
        tokens_final: st.tokens_final,
        tokens_pending: st.tokens_pending,
        deposit: st.deposit,
        seller_bond: snapshot.seller_bond.bond_held,
    })
}

/// Strict pre-STOP read: every field a settlement depends on must be present and well-formed, or the
/// client refuses to send rather than letting the contract revert mid-money-path.
#[cfg(test)]
fn tc_stop_settle_state_from_json(
    tc: &str,
    state: &Value,
    bond: Option<&Value>,
) -> Result<TcSettleState> {
    let state = DealChainState::decode_getter(state).map_err(|reason| {
        anyhow!("TokenContract {tc}: {reason}; refusing STOP before money moves")
    })?;
    let bond = bond.ok_or_else(|| {
        anyhow!(
            "TokenContract {tc}: getSellerBond() returned no data; refusing STOP before money moves"
        )
    })?;
    let bond = DealSellerBond::decode_getter(bond).map_err(|reason| {
        anyhow!("TokenContract {tc}: {reason}; refusing STOP before money moves")
    })?;
    Ok(TcSettleState {
        opened: state.opened,
        probe_accepted: state.probe_accepted,
        probe_tick: state.probe_tick,
        tokens_final: state.tokens_final,
        tokens_pending: state.tokens_pending,
        deposit: state.deposit,
        seller_bond: bond.bond_held,
    })
}

fn reqwest_error_is_transport(error: &reqwest::Error) -> bool {
    error.is_connect()
        || error.is_timeout()
        || error.is_body()
        || error
            .status()
            .is_some_and(|status| status.is_server_error() || status.as_u16() == 429)
}

fn message_is_contract_failure(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    let has_exit_code = lower.contains("exit_code=")
        || lower.contains("exit_code ")
        || lower.contains("exit code:")
        || lower.contains("exit code ");
    let block_manager_compute_revert = lower.contains("block manager rejected message")
        && (lower.contains("tvm_error") || lower.contains("compute phase"));
    let explicit_onchain_failure = lower.contains("on-chain revert")
        || lower.contains("on-chain submit failed")
        || lower.contains("action_result_code=");

    // Some SDK paths expose only the named contract error. Do not turn our own fail-closed
    // preflight explanations(which describe what *would* revert) into chain results.
    let named_contract_error = message.contains("ERR_")
        && !lower.contains("would revert")
        && !lower.contains("would fail")
        && !lower.contains("pre-accept")
        && !lower.contains("refusing")
        && (lower.trim_start().starts_with("err_")
            || lower.contains("revert")
            || lower.contains("rejected")
            || lower.contains("failed"));

    has_exit_code
        || block_manager_compute_revert
        || explicit_onchain_failure
        || named_contract_error
}

fn map_err(error: anyhow::Error) -> ChainError {
    // Alternate Display preserves every anyhow context and source, including the reqwest
    // cause or the contract exit code, in the user-visible machine error.
    let message = format!("{error:#}");
    if let Some(outcome) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<crate::MoneySubmitError>())
    {
        return match outcome {
            crate::MoneySubmitError::Preparation { .. } => {
                ChainError::MoneySubmitPreparation(message)
            }
            crate::MoneySubmitError::Ambiguous { .. } => ChainError::AmbiguousSubmit(format!(
                "{message}; the BOC was not retried; reconcile from chain facts before any resubmit"
            )),
            crate::MoneySubmitError::Rejected { .. } => ChainError::MoneySubmitRejected(message),
        };
    }
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<reqwest::Error>()
            .is_some_and(reqwest_error_is_transport)
    }) {
        ChainError::Transport(message)
    } else if message_is_contract_failure(&message) {
        ChainError::Contract(message)
    } else {
        ChainError::Chain(message)
    }
}

fn map_claim_submit_err(error: anyhow::Error) -> ChainError {
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<MessagePostResponseDecodeError>()
            .is_some()
    }) {
        return ChainError::AmbiguousSubmit(format!(
            "{error:#}; claim message POST received HTTP success, but its response was unusable; \
             reconcile tokensPending before any resubmit"
        ));
    }
    map_err(error)
}

async fn retry_seller_read<T, F, Fut>(label: &str, mut read: F) -> Result<T, ChainError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, ChainError>>,
{
    for (attempt, delay) in SELLER_READ_BACKOFF.iter().enumerate() {
        match read().await {
            Ok(value) => return Ok(value),
            Err(ChainError::Transport(error)) => {
                tracing::warn!(
                    read = label,
                    attempt = attempt + 1,
                    backoff_ms = delay.as_millis(),
                    error,
                    "transient seller chain read failed; retrying"
                );
                tokio::time::sleep(*delay).await;
            }
            Err(error) => return Err(error),
        }
    }
    read().await
}

#[cfg(test)]
mod shellnet_error_mapping_tests {
    use super::*;

    fn http_status_error(status: reqwest::StatusCode) -> anyhow::Error {
        let response: reqwest::Response = http::Response::builder()
            .status(status)
            .body(Vec::<u8>::new())
            .expect("build HTTP response")
            .into();
        anyhow::Error::new(
            response
                .error_for_status()
                .expect_err("status must produce reqwest error"),
        )
    }

    #[test]
    fn buyer_adapter_preserves_transport_and_contract_causes() {
        for status in [
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let mapped = map_err(http_status_error(status));
            let ChainError::Transport(cause) = mapped else {
                panic!("HTTP {status} must map to ChainError::Transport");
            };
            assert!(cause.contains(status.as_str()), "{cause}");
            assert!(!cause.contains("CHAIN_TRANSPORT"), "{cause}");
        }

        let submit_error = crate::onchain_diagnostics::validate_onchain_submit_response(json!({
            "error": {
                "code": "TVM_ERROR",
                "message": "compute phase failed",
                "data": { "exit_code": 321 }
            }
        }))
        .expect_err("contract revert must fail submit validation");
        let mapped = map_err(anyhow::Error::new(submit_error));
        let ChainError::Contract(cause) = mapped else {
            panic!("contract revert must map to ChainError::Contract");
        };
        assert!(cause.contains("compute phase failed"), "{cause}");
        assert!(cause.contains("exit_code=321"), "{cause}");
        assert!(cause.contains("ERR_ALREADY_OPEN"), "{cause}");

        let unknown = map_err(anyhow!("buyer adapter invariant failed"));
        assert!(matches!(unknown, ChainError::Chain(_)));

        let preflight = map_err(anyhow!(
            "buyer aborted pre-accept: placeInferenceBuy would revert ERR_INVALID_SENDER 101"
        ));
        assert!(matches!(preflight, ChainError::Chain(_)));
    }
}

fn parse_tc(tc: &TokenContract) -> Result<Address, ChainError> {
    Address::parse(tc).map_err(|e| ChainError::Chain(format!("bad token_contract {tc}: {e}")))
}

fn required_subscription_week_index(
    token_contract: &TokenContract,
    phase: &str,
    subscription: Option<DealSubscription>,
) -> Result<u8, ChainError> {
    subscription.map(|state| state.week_index).ok_or_else(|| {
        ChainError::Chain(format!(
            "TC {token_contract}: getSubscription() returned no data {phase}"
        ))
    })
}

fn settle_week_post_confirmed(
    token_contract: &TokenContract,
    pre_week_index: u8,
    subscription: Option<DealSubscription>,
    token_contract_active: bool,
) -> Result<bool, ChainError> {
    match subscription {
        Some(state) => Ok(state.week_index > pre_week_index),
        None if !token_contract_active => Ok(true),
        None => Err(ChainError::Chain(format!(
            "TC {token_contract}: getSubscription() returned no data after settleWeek while the \
             TokenContract is still active"
        ))),
    }
}

#[cfg(test)]
mod settle_week_fail_closed_tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn missing_subscription_is_fail_closed_before_submit() {
        let tc = "0:tc".to_string();
        let gas_calls = Cell::new(0);
        let write_calls = Cell::new(0);
        let preflight_then_submit = || -> Result<(), ChainError> {
            required_subscription_week_index(&tc, "before settleWeek", None)?;
            gas_calls.set(gas_calls.get() + 1);
            write_calls.set(write_calls.get() + 1);
            Ok(())
        };
        let pre_error = preflight_then_submit().expect_err("missing pre-read must fail");
        assert!(pre_error.to_string().contains("before settleWeek"));
        assert_eq!(gas_calls.get(), 0);
        assert_eq!(write_calls.get(), 0);
    }

    #[test]
    fn missing_subscription_after_submit_requires_terminal_account_evidence() {
        let tc = "0:tc".to_string();
        let active_error = settle_week_post_confirmed(&tc, 3, None, true)
            .expect_err("missing getter on an active TC must fail");
        assert!(active_error.to_string().contains("still active"));
        assert!(settle_week_post_confirmed(&tc, 3, None, false)
            .expect("an inactive account proves the final transition"));
    }

    #[test]
    fn both_real_settle_week_paths_preflight_before_gas_and_write() {
        let source = include_str!("backends.rs");
        for adapter in ["RealDealBackend", "RealSellerBackend"] {
            let marker = format!("impl ChainBackend for {adapter} {{");
            let implementation = source
                .split_once(&marker)
                .unwrap_or_else(|| panic!("missing {adapter}"))
                .1;
            let function = implementation
                .split_once("    async fn settle_week(")
                .unwrap_or_else(|| panic!("missing settle_week in {adapter}"))
                .1;
            let body = function
                .split_once("\n    async fn ")
                .map(|(body, _)| body)
                .expect("next adapter method");
            let pre = body.find("required_subscription_week_index(").unwrap();
            let gas = body.find("self.ensure_tc_gas(&tc)").unwrap();
            let write = body.find("self.chain.settle_week(&tc)").unwrap();
            let post = body[write + 1..]
                .find("settle_week_post_confirmed(")
                .map(|index| write + 1 + index)
                .expect("strict post-read");
            assert!(
                pre < gas && gas < write && write < post,
                "{adapter} must read strictly before gas/write and after the write"
            );
            assert!(!body.contains("unwrap_or(0)"));
            assert!(body.contains("ClaimConfirmationParams::canonical()"));
            assert!(body.contains("confirmation.max_reads"));
            assert!(body.contains("confirmation.poll_interval"));
            assert!(!body.contains("0..40"));
            assert!(!body.contains("Duration::from_secs(3)"));
        }
    }
}

fn seller_bond_prewrite_state(
    token_contract: &TokenContract,
    bond: &Value,
    price_per_tick: u128,
) -> Result<(bool, u128), ChainError> {
    let bond = DealSellerBond::decode_getter(bond).map_err(|reason| {
        ChainError::Chain(format!(
            "TokenContract {token_contract}: strict getSellerBond() decode failed: {reason}; \
             refusing seller-bond/open writes before money moves because a malformed or missing \
             contract getter value must not be inferred as 0"
        ))
    })?;
    let funded = bond.bond_funded;
    let held = bond.bond_held;
    let required = bond.bond_required;
    let expected = price_per_tick.checked_mul(2).ok_or_else(|| {
        ChainError::Chain(format!(
            "TokenContract {token_contract}: pricePerTick {price_per_tick} cannot form the exact seller bond 2P \
             without overflowing u128; refusing seller-bond/open writes before money moves"
        ))
    })?;
    if required != expected {
        return Err(ChainError::Chain(format!(
            "TokenContract {token_contract}: getSellerBond().bondRequired {required} does not equal the \
             canonical seller bond 2P = {expected} for pricePerTick {price_per_tick}; refusing \
             seller-bond/open writes before money moves"
        )));
    }
    let consistent = if funded { held == required } else { held == 0 };
    if !consistent {
        return Err(ChainError::Chain(format!(
            "TokenContract {token_contract}: getSellerBond() tuple is inconsistent: bondFunded={funded}, \
             bondHeld={held}, bondRequired={required}; expected bondHeld=bondRequired when funded and \
             bondHeld=0 when unfunded; refusing seller-bond/open writes before money moves"
        )));
    }
    Ok((funded, required))
}

fn seller_bond_not_funded_after_post_reason(
    token_contract: &TokenContract,
    seller_note: &Address,
    post_amount: u128,
    note_physical_shell: u128,
    state: Option<&Value>,
    bond: Option<&Value>,
) -> String {
    format!(
        "TokenContract {token_contract}: postSellerBond submitted but getSellerBond().bondFunded stayed false; \
         refusing TokenContract.open because open() would revert with airegistry::ERR_BOND_NOT_FUNDED (332). \
         seller note {seller_note} physical ECC[2] SHELL after submit={note_physical_shell}, \
         exact_seller_bond_2P={post_amount}, state={state:?}, seller_bond={bond:?}. \
         Re-mint/fund the seller note with physical SHELL ECC[2] (`mint_pn_pool --deposit-shells ...` / current \
         onboarding)."
    )
}

async fn seller_note_physical_shell(
    chain: &RealChainBackend,
    seller_note: &Address,
) -> Result<u128, ChainError> {
    let acc = chain
        .client()
        .get_account(seller_note)
        .await
        .map_err(map_err)?
        .ok_or_else(|| {
            ChainError::Chain(format!(
                "seller note {seller_note} disappeared before postSellerBond"
            ))
        })?;
    Ok(acc.ecc_balance(2))
}

fn validate_seller_bond_note_reserve(
    token_contract: &TokenContract,
    seller_note: &Address,
    note_physical_shell: u128,
    post_amount: u128,
    tc_native_balance: u128,
) -> Result<u128, ChainError> {
    let pending_tc_top_up = gas_health_top_up_amount(
        tc_native_balance,
        crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL,
        crate::params::ACTIVE_CONTRACT_GAS_HEALTH_TARGET_NANOVMSHELL,
    )
    .unwrap_or(0);
    let required = post_amount.checked_add(pending_tc_top_up).ok_or_else(|| {
        ChainError::Chain(format!(
            "seller note {seller_note}: exact seller bond 2P {post_amount} plus pending TokenContract \
             gas top-up {pending_tc_top_up} overflows uint128; refusing seller-bond/open writes before \
             money moves for TokenContract {token_contract}"
        ))
    })?;
    if note_physical_shell < required {
        return Err(ChainError::Chain(format!(
            "seller note {seller_note} has physical ECC[2] SHELL raw units {note_physical_shell}, below \
             the combined pre-write reserve {required} for TokenContract {token_contract}: exact seller \
             bond 2P = {post_amount} plus pending TokenContract gas top-up = {pending_tc_top_up}. \
             Refusing gas top-up and postSellerBond before money moves. Re-mint/fund the seller note with \
             physical SHELL ECC[2] (`mint_pn_pool` / current onboarding) and keep provision \
             --deposit-shells low enough to leave this combined reserve."
        )));
    }
    Ok(pending_tc_top_up)
}

async fn post_seller_bond_and_wait(
    chain: &RealChainBackend,
    seller_note: &Address,
    seller_keys: &KeyPair,
    nonce: u64,
    token_contract: &TokenContract,
    tc: &Address,
) -> Result<(), ChainError> {
    let bond_before = chain
        .token_contract_seller_bond(tc)
        .await
        .map_err(map_err)?
        .ok_or_else(|| {
            ChainError::Chain(format!(
                "TokenContract {token_contract}: getSellerBond() returned no data before postSellerBond"
            ))
        })?;
    let price_per_tick = chain
        .token_contract_price_per_tick(tc)
        .await
        .map_err(map_err)?
        .ok_or_else(|| {
            ChainError::Chain(format!(
                "TokenContract {token_contract}: getDeal().pricePerTick returned no data; refusing \
                 postSellerBond before money moves because the exact seller bond 2P cannot be derived"
            ))
        })?;
    let (bond_funded, post_amount) =
        seller_bond_prewrite_state(token_contract, &bond_before, price_per_tick)?;
    if bond_funded {
        return Ok(());
    }

    let tc_native_balance = chain.active_native_balance(tc).await.map_err(map_err)?;
    let note_physical_shell = seller_note_physical_shell(chain, seller_note).await?;
    validate_seller_bond_note_reserve(
        token_contract,
        seller_note,
        note_physical_shell,
        post_amount,
        tc_native_balance,
    )?;

    chain
        .ensure_deal_contract_gas(seller_note, seller_keys, nonce, None, Some(tc))
        .await
        .map_err(map_err)?;
    let note_physical_shell = seller_note_physical_shell(chain, seller_note).await?;
    if note_physical_shell < post_amount {
        return Err(ChainError::Chain(format!(
            "seller note {seller_note} has physical ECC[2] SHELL raw units {note_physical_shell} after \
             the TokenContract gas-health step, below required seller bond 2P = {post_amount} for \
             TokenContract {token_contract}; refusing postSellerBond"
        )));
    }
    chain
        .note_post_seller_bond(seller_note, seller_keys, nonce, post_amount)
        .await
        .map_err(map_err)?;
    for _ in 0..crate::params::SELLER_BOND_CONFIRM_MAX_READS {
        if chain
            .token_contract_deal_seller_bond(tc)
            .await
            .map_err(map_err)?
            .is_some_and(|bond| bond.bond_funded)
        {
            return Ok(());
        }
        tokio::time::sleep(crate::params::SELLER_BOND_CONFIRM_POLL_INTERVAL).await;
    }

    let state = chain.token_contract_state(tc).await.map_err(map_err)?;
    let bond = chain
        .token_contract_seller_bond(tc)
        .await
        .map_err(map_err)?;
    let note_physical_shell = seller_note_physical_shell(chain, seller_note)
        .await
        .unwrap_or(0);
    Err(ChainError::Chain(seller_bond_not_funded_after_post_reason(
        token_contract,
        seller_note,
        post_amount,
        note_physical_shell,
        state.as_ref(),
        bond.as_ref(),
    )))
}

#[cfg(test)]
mod seller_bond_open_guard_tests {
    use super::*;

    fn assert_prewrite_rejection_precedes_all_money_writes() {
        let source = include_str!("backends.rs");
        let start = source
            .find("async fn post_seller_bond_and_wait(")
            .expect("seller-bond pre-write path");
        let end = source[start..]
            .find("\n#[cfg(test)]")
            .map(|offset| start + offset)
            .expect("end of seller-bond pre-write path");
        let body = &source[start..end];
        let validation = body
            .find("seller_bond_prewrite_state(")
            .expect("strict tuple validation");
        let validation_error_return = body[validation..]
            .find("?;")
            .map(|offset| validation + offset)
            .expect("tuple validation propagates errors");

        for write in ["ensure_deal_contract_gas(", "note_post_seller_bond("] {
            let write = body.find(write).expect("seller-bond money write");
            assert!(
                validation < validation_error_return && validation_error_return < write,
                "malformed/inconsistent getSellerBond tuples must return before {write}"
            );
        }
    }

    fn assert_combined_reserve_and_recheck_precede_money_writes() {
        let source = include_str!("backends.rs");
        let start = source
            .find("async fn post_seller_bond_and_wait(")
            .expect("seller-bond pre-write path");
        let end = source[start..]
            .find("\n#[cfg(test)]")
            .map(|offset| start + offset)
            .expect("end of seller-bond pre-write path");
        let body = &source[start..end];
        let reserve = body
            .find("validate_seller_bond_note_reserve(")
            .expect("combined seller-note reserve validation");
        let gas_write = body
            .find("ensure_deal_contract_gas(")
            .expect("TokenContract gas top-up write");
        let recheck = body[gas_write..]
            .find("seller_note_physical_shell(")
            .map(|offset| gas_write + offset)
            .expect("seller-note reserve recheck after gas top-up");
        let bond_write = body
            .find("note_post_seller_bond(")
            .expect("seller-bond post write");
        assert!(
            reserve < gas_write && gas_write < recheck && recheck < bond_write,
            "combined 2P+top-up reserve must precede either write, and the 2P reserve must be \
             rechecked before postSellerBond"
        );
    }

    #[test]
    fn seller_bond_reserve_rejects_exact_two_p_when_tc_needs_top_up_before_writes() {
        assert_combined_reserve_and_recheck_precede_money_writes();
        let post_amount = 50;
        let tc_native_balance = crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL - 1;
        let pending_top_up =
            crate::params::ACTIVE_CONTRACT_GAS_HEALTH_TARGET_NANOVMSHELL - tc_native_balance;
        let note =
            Address::parse("0:9754c903354dfba45c66898e5fcb840c23a892e0829906bea1b554c15b6d7c8c")
                .unwrap();
        for balance in [post_amount, post_amount + pending_top_up - 1] {
            let err = validate_seller_bond_note_reserve(
                &"0:tc".to_string(),
                &note,
                balance,
                post_amount,
                tc_native_balance,
            )
            .expect_err("anything below exact 2P plus top-up is insufficient");
            let reason = err.to_string();
            assert!(reason.contains("combined pre-write reserve"), "{reason}");
            assert!(
                reason.contains("Refusing gas top-up and postSellerBond"),
                "{reason}"
            );
        }
    }

    #[test]
    fn seller_bond_reserve_accepts_exact_two_p_plus_pending_top_up_boundary() {
        let post_amount = 50;
        let tc_native_balance = crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL - 1;
        let pending_top_up =
            crate::params::ACTIVE_CONTRACT_GAS_HEALTH_TARGET_NANOVMSHELL - tc_native_balance;
        assert_eq!(
            validate_seller_bond_note_reserve(
                &"0:tc".to_string(),
                &Address::parse(
                    "0:9754c903354dfba45c66898e5fcb840c23a892e0829906bea1b554c15b6d7c8c"
                )
                .unwrap(),
                post_amount + pending_top_up,
                post_amount,
                tc_native_balance,
            )
            .unwrap(),
            pending_top_up
        );
    }

    #[test]
    fn seller_bond_prewrite_state_accepts_consistent_exact_two_p_tuples() {
        let unfunded = json!({
            "bondFunded": false,
            "bondHeld": "0",
            "bondRequired": "50"
        });
        assert_eq!(
            seller_bond_prewrite_state(&"0:tc".to_string(), &unfunded, 25).unwrap(),
            (false, 50)
        );

        let funded = json!({
            "bondFunded": true,
            "bondHeld": "50",
            "bondRequired": "50"
        });
        assert_eq!(
            seller_bond_prewrite_state(&"0:tc".to_string(), &funded, 25).unwrap(),
            (true, 50)
        );
    }

    #[test]
    fn seller_bond_prewrite_state_requires_exact_two_p() {
        let tc = "0:9754c903354dfba45c66898e5fcb840c23a892e0829906bea1b554c15b6d7c8c".to_string();
        let bond = json!({
            "bondFunded": false,
            "bondHeld": "0",
            "bondRequired": "50"
        });

        assert_eq!(
            seller_bond_prewrite_state(&tc, &bond, 25).expect("contract getter equals 2P"),
            (false, 50)
        );
        let err =
            seller_bond_prewrite_state(&tc, &bond, 24).expect_err("contract getter is not 2P");
        let reason = err.to_string();
        assert!(reason.contains("bondRequired 50"), "{reason}");
        assert!(reason.contains("seller bond 2P = 48"), "{reason}");
        assert!(reason.contains("before money moves"), "{reason}");
    }

    #[test]
    fn seller_bond_prewrite_state_fails_closed_when_required_missing() {
        let tc = "0:9754c903354dfba45c66898e5fcb840c23a892e0829906bea1b554c15b6d7c8c".to_string();
        let bond = json!({
            "bondFunded": false,
            "bondHeld": "0"
        });

        let err = seller_bond_prewrite_state(&tc, &bond, 25).expect_err("missing seller bond");
        let reason = err.to_string();
        assert!(reason.contains("missing fields: bondRequired"), "{reason}");
        assert!(reason.contains("must not be inferred as 0"), "{reason}");
        assert!(reason.contains("before money moves"), "{reason}");
    }

    #[test]
    fn seller_bond_prewrite_state_fails_closed_when_required_non_string() {
        let tc = "0:9754c903354dfba45c66898e5fcb840c23a892e0829906bea1b554c15b6d7c8c".to_string();
        let bond = json!({
            "bondFunded": false,
            "bondHeld": "0",
            "bondRequired": 25
        });

        let err = seller_bond_prewrite_state(&tc, &bond, 25).expect_err("non-string seller bond");
        let reason = err.to_string();
        assert!(
            reason.contains("bondRequired is not a decimal string"),
            "{reason}"
        );
        assert!(reason.contains("must not be inferred as 0"), "{reason}");
        assert!(reason.contains("before money moves"), "{reason}");
    }

    #[test]
    fn seller_bond_prewrite_state_fails_closed_when_required_malformed() {
        let tc = "0:9754c903354dfba45c66898e5fcb840c23a892e0829906bea1b554c15b6d7c8c".to_string();
        let bond = json!({
            "bondFunded": false,
            "bondHeld": "0",
            "bondRequired": "not-a-number"
        });

        let err = seller_bond_prewrite_state(&tc, &bond, 25).expect_err("malformed seller bond");
        let reason = err.to_string();
        assert!(reason.contains("bondRequired value"), "{reason}");
        assert!(reason.contains("malformed"), "{reason}");
        assert!(reason.contains("must not be inferred as 0"), "{reason}");
        assert!(reason.contains("before money moves"), "{reason}");
    }

    #[test]
    fn seller_bond_prewrite_state_rejects_malformed_funded_and_held_before_writes() {
        assert_prewrite_rejection_precedes_all_money_writes();
        let tc = "0:9754c903354dfba45c66898e5fcb840c23a892e0829906bea1b554c15b6d7c8c".to_string();
        for (label, bond, field) in [
            (
                "missing bondFunded",
                json!({"bondHeld": "0", "bondRequired": "50"}),
                "bondFunded",
            ),
            (
                "non-bool bondFunded",
                json!({"bondFunded": "false", "bondHeld": "0", "bondRequired": "50"}),
                "bondFunded",
            ),
            (
                "missing bondHeld",
                json!({"bondFunded": false, "bondRequired": "50"}),
                "bondHeld",
            ),
            (
                "non-string bondHeld",
                json!({"bondFunded": false, "bondHeld": 0, "bondRequired": "50"}),
                "bondHeld",
            ),
            (
                "malformed bondHeld",
                json!({"bondFunded": false, "bondHeld": "bad", "bondRequired": "50"}),
                "bondHeld",
            ),
        ] {
            let err = seller_bond_prewrite_state(&tc, &bond, 25).expect_err(label);
            let reason = err.to_string();
            assert!(reason.contains(field), "{label}: {reason}");
            assert!(reason.contains("before money moves"), "{label}: {reason}");
        }
    }

    #[test]
    fn seller_bond_prewrite_state_rejects_inconsistent_tuple_before_writes() {
        assert_prewrite_rejection_precedes_all_money_writes();
        let tc = "0:9754c903354dfba45c66898e5fcb840c23a892e0829906bea1b554c15b6d7c8c".to_string();
        for (label, bond) in [
            (
                "funded without held bond",
                json!({"bondFunded": true, "bondHeld": "0", "bondRequired": "50"}),
            ),
            (
                "funded with partial held bond",
                json!({"bondFunded": true, "bondHeld": "49", "bondRequired": "50"}),
            ),
            (
                "unfunded with held bond",
                json!({"bondFunded": false, "bondHeld": "50", "bondRequired": "50"}),
            ),
        ] {
            let err = seller_bond_prewrite_state(&tc, &bond, 25).expect_err(label);
            let reason = err.to_string();
            assert!(
                reason.contains("tuple is inconsistent"),
                "{label}: {reason}"
            );
            assert!(reason.contains("before money moves"), "{label}: {reason}");
        }
    }

    #[test]
    fn seller_bond_not_funded_reason_names_open_revert_code() {
        let seller_note =
            Address::parse("0:d154e18f92f422b3879ee860842f3bbe634fc95be8e595bce009de00acdb61d2")
                .expect("seller note");
        let state = json!({
            "funded": true,
            "opened": false,
            "deposit": "2050"
        });
        let bond = json!({
            "bondFunded": false,
            "bondHeld": "0",
            "bondRequired": "25"
        });
        let reason = seller_bond_not_funded_after_post_reason(
            &"0:9754c903354dfba45c66898e5fcb840c23a892e0829906bea1b554c15b6d7c8c".to_string(),
            &seller_note,
            1_000_000,
            0,
            Some(&state),
            Some(&bond),
        );
        assert!(reason.contains("ERR_BOND_NOT_FUNDED (332)"), "{reason}");
        assert!(reason.contains("bondFunded"), "{reason}");
        assert!(
            reason.contains("physical ECC[2] SHELL after submit=0"),
            "{reason}"
        );
    }
}

fn parse_order_u128(s: &str) -> Option<u128> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u128>().ok()
    }
}

fn order_u128(order: &Value, keys: &[&str]) -> Option<u128> {
    keys.iter().find_map(|k| {
        order[*k]
            .as_str()
            .and_then(parse_order_u128)
            .or_else(|| order[*k].as_u64().map(u128::from))
    })
}

fn order_u64(order: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|k| {
        order[*k]
            .as_str()
            .and_then(|s| parse_order_u128(s).and_then(|v| v.try_into().ok()))
            .or_else(|| order[*k].as_u64())
    })
}

pub(super) fn is_canonical_zero_address(addr: &str) -> bool {
    let Some(account_id) = addr.strip_prefix("0:") else {
        return false;
    };
    account_id.len() == 64 && account_id.bytes().all(|byte| byte == b'0')
}

enum Uint256ToU128 {
    Value(u128),
    ExceedsU128,
    Invalid,
}

fn parse_uint256_to_u128(value: &str) -> Uint256ToU128 {
    const U256_MAX_DECIMAL: &str =
        "115792089237316195423570985008687907853269984665640564039457584007913129639935";

    let value = value.trim();
    let (digits, radix, max_digits) = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        (hex, 16, 64)
    } else {
        (value, 10, U256_MAX_DECIMAL.len())
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return Uint256ToU128::Invalid;
    }

    let significant = digits.trim_start_matches('0');
    let significant = if significant.is_empty() {
        "0"
    } else {
        significant
    };
    let within_uint256 = if significant.len() < max_digits {
        true
    } else if significant.len() > max_digits {
        false
    } else if radix == 16 {
        true
    } else {
        significant <= U256_MAX_DECIMAL
    };
    if !within_uint256 {
        return Uint256ToU128::Invalid;
    }

    match u128::from_str_radix(significant, radix) {
        Ok(value) => Uint256ToU128::Value(value),
        Err(_) => Uint256ToU128::ExceedsU128,
    }
}

fn orderbook_order_from_getter(order_id: u128, order: &Value) -> Result<Option<OrderBookOrder>> {
    let ticks = order_u128(order, &["amount"])
        .ok_or_else(|| anyhow!("getOrder({order_id}) missing/invalid amount: {order}"))?;
    // A zero-tick slot is not a live, matchable order: either a cleanly removed slot
    // (`_removeFromBook` -> `delete _orders[id]`, all fields zero) or an order filled /
    // consumed to zero remaining ticks but not yet swept from the book (its owner note can
    // linger until a `cancelInferenceOrder`). Neither can be matched, so skip it rather than
    // letting a strict parse of a lingering filled order abort the whole book scan.
    if ticks == 0 {
        return Ok(None);
    }
    let owner_note = order["note"]
        .as_str()
        .filter(|note| !note.trim().is_empty())
        .ok_or_else(|| anyhow!("getOrder({order_id}) missing/invalid note: {order}"))?
        .to_string();
    // A non-zero amount with a zero/absent owner note is genuinely malformed (ticks with no
    // owner) -- keep it fail-loud.
    if is_canonical_zero_address(&owner_note) {
        return Err(anyhow!(
            "getOrder({order_id}) malformed: non-zero amount with zero owner note: {order}"
        ));
    }
    let is_buy = order["isBuy"]
        .as_bool()
        .ok_or_else(|| anyhow!("getOrder({order_id}) missing/invalid isBuy: {order}"))?;
    let token_contract = order["tokenContract"]
        .as_str()
        .filter(|token_contract| !token_contract.trim().is_empty())
        .ok_or_else(|| anyhow!("getOrder({order_id}) missing/invalid tokenContract: {order}"))?;
    let token_contract = if is_canonical_zero_address(token_contract) {
        None
    } else {
        Some(token_contract.to_string())
    };
    let price_per_tick = match order["price"].as_str() {
        Some(price) => match parse_uint256_to_u128(price) {
            Uint256ToU128::Value(price) => price,
            Uint256ToU128::ExceedsU128 => {
                return Err(anyhow!(
                    "getOrder({order_id}) price exceeds downstream u128: {order}"
                ));
            }
            Uint256ToU128::Invalid => {
                return Err(anyhow!(
                    "getOrder({order_id}) missing/invalid price: {order}"
                ));
            }
        },
        None => order["price"]
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| anyhow!("getOrder({order_id}) missing/invalid price: {order}"))?,
    };
    let escrow = order_u128(order, &["escrow"])
        .ok_or_else(|| anyhow!("getOrder({order_id}) missing/invalid escrow: {order}"))?;
    let deadline = order_u64(order, &["deadline"])
        .ok_or_else(|| anyhow!("getOrder({order_id}) missing/invalid deadline: {order}"))?;
    let flags = order_u64(order, &["flags"])
        .ok_or_else(|| anyhow!("getOrder({order_id}) missing/invalid flags: {order}"))?
        .try_into()
        .map_err(|_| anyhow!("getOrder({order_id}) flags exceed uint8: {order}"))?;
    let timestamp = order_u64(order, &["ts"])
        .ok_or_else(|| anyhow!("getOrder({order_id}) missing/invalid ts: {order}"))?;
    Ok(Some(OrderBookOrder {
        order_id,
        owner_note,
        token_contract,
        is_buy,
        price_per_tick,
        ticks,
        escrow,
        deadline,
        flags,
        timestamp,
    }))
}

/// Parse one already-correlated order id. Unlike a whole-book scan, a fixed-id read may classify
/// the row as absent only when the getter returns the contract's complete all-zero tombstone.
fn expected_orderbook_order_from_getter(
    order_id: u128,
    order: &Value,
) -> Result<Option<OrderBookOrder>> {
    let canonical_tombstone = order
        .get("note")
        .and_then(Value::as_str)
        .is_some_and(is_canonical_zero_address)
        && order
            .get("tokenContract")
            .and_then(Value::as_str)
            .is_some_and(is_canonical_zero_address)
        && ["price", "amount", "escrow", "deadline", "flags", "ts"]
            .iter()
            .all(|field| order_u128(order, &[*field]) == Some(0))
        && order.get("isBuy").and_then(Value::as_bool) == Some(false);
    if canonical_tombstone {
        return Ok(None);
    }
    if order_u128(order, &["amount"]) == Some(0) {
        return Err(anyhow!(
            "getOrder({order_id}) returned a non-canonical zero-amount row for the expected \
             fixed order id: {order}"
        ));
    }
    let Some(parsed) = orderbook_order_from_getter(order_id, order)? else {
        return Err(anyhow!(
            "getOrder({order_id}) did not return either a live order or an all-zero tombstone: \
             {order}"
        ));
    };
    Address::parse(&parsed.owner_note).map_err(|error| {
        anyhow!(
            "getOrder({order_id}) has malformed owner note {}: {error}",
            parsed.owner_note
        )
    })?;
    if let Some(token_contract) = &parsed.token_contract {
        Address::parse(token_contract).map_err(|error| {
            anyhow!("getOrder({order_id}) has malformed tokenContract {token_contract}: {error}")
        })?;
    }
    Ok(Some(parsed))
}

/// Build the live-order list from raw per-id `getOrder` reads, skipping empty/filled slots
/// (`Ok(None)`) and lingering/unparseable slots(`Err`, logged) so one non-live or corrupt
/// order never blinds the whole book scan. Transport/chain read errors are surfaced by
/// the caller before the raw values reach here.
fn collect_live_orders(raw: impl IntoIterator<Item = (u128, Value)>) -> Vec<OrderBookOrder> {
    let mut orders = Vec::new();
    for (id, order) in raw {
        match orderbook_order_from_getter(id, &order) {
            Ok(Some(parsed)) => orders.push(parsed),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(order_id = id, error = %format!("{error:#}"), "skipping unparseable order in book scan");
            }
        }
    }
    orders
}

#[cfg(test)]
fn resting_ask_from_order(order_id: u128, order: &Value) -> Option<OrderBookOrder> {
    orderbook_order_from_getter(order_id, order)
        .expect("valid getOrder fixture")
        .filter(|o| o.is_resting_ask())
}

fn next_matching_ask(
    asks: &[OrderBookOrder],
    max_price_per_tick: u128,
    _ticks: u128,
) -> Option<&OrderBookOrder> {
    asks.iter()
        .filter(|ask| ask.price_per_tick <= max_price_per_tick)
        .min_by_key(|ask| (ask.price_per_tick, ask.order_id))
}

fn no_matching_ask_reason(
    asks: &[OrderBookOrder],
    max_price_per_tick: u128,
    ticks: u128,
) -> String {
    match asks.iter().min_by_key(|ask| (ask.price_per_tick, ask.order_id)) {
        Some(best) if best.price_per_tick > max_price_per_tick => format!(
            "best ask price {} is above buyer max_price_per_tick {max_price_per_tick}; requested ticks {ticks}. \
             Raise --max-price-per-tick to at least {} or wait for a cheaper ask",
            best.price_per_tick, best.price_per_tick
        ),
        Some(best) => format!(
            "no matchable ask for max_price_per_tick {max_price_per_tick}, requested ticks {ticks}. \
             Best ask is order #{} tokenContract {} (price {}, ticks {})",
            best.order_id,
            best.token_contract.as_deref().unwrap_or("<none>"),
            best.price_per_tick,
            best.ticks
        ),
        None => format!(
            "no resting asks in this model book for max_price_per_tick {max_price_per_tick}, requested ticks {ticks}"
        ),
    }
}

fn check_single_head_capacity(ask: &OrderBookOrder, ticks: u128) -> Result<(), String> {
    if ask.ticks >= ticks {
        return Ok(());
    }
    Err(format!(
        "refusing multi-ask fill: order #{} tokenContract {} has only {} ticks, buyer requested {ticks}. \
         Current shellnet submit is accepted only when the price/time head ask alone covers the request.",
        ask.order_id,
        ask.token_contract.as_deref().unwrap_or("<none>"),
        ask.ticks,
    ))
}

#[cfg(test)]
fn check_model_buy_full_fill(
    asks: &[OrderBookOrder],
    max_price_per_tick: u128,
    ticks: u128,
) -> Result<(), String> {
    selected_model_buy_ask(asks, max_price_per_tick, ticks).map(|_| ())
}

fn selected_model_buy_ask(
    asks: &[OrderBookOrder],
    max_price_per_tick: u128,
    ticks: u128,
) -> Result<OrderBookOrder, String> {
    let asks = coalesce_equivalent_resting_asks(asks)?;
    let Some(best) = next_matching_ask(&asks, max_price_per_tick, ticks) else {
        return Err(no_matching_ask_reason(&asks, max_price_per_tick, ticks));
    };
    check_single_head_capacity(best, ticks)?;
    Ok(best.clone())
}

fn describe_buy_ask(ask: &OrderBookOrder) -> String {
    format!(
        "order #{} tokenContract {} (price {}, ticks {})",
        ask.order_id,
        ask.token_contract.as_deref().unwrap_or("<none>"),
        ask.price_per_tick,
        ask.ticks
    )
}

fn selected_model_buy_ask_matching_executable_depth(
    raw_asks: &[OrderBookOrder],
    executable_asks: &[OrderBookOrder],
    max_price_per_tick: u128,
    ticks: u128,
) -> Result<OrderBookOrder, String> {
    let raw_asks = coalesce_equivalent_resting_asks(raw_asks)?;
    let raw_selected = selected_model_buy_ask(&raw_asks, max_price_per_tick, ticks).map_err(|e| {
        format!(
            "raw order-book matcher has no submit-safe ask: {e}. Retry after the seller posts a fresh ask with enough ticks, \
             or clean/cancel stale order-book rows if you operate this market"
        )
    })?;
    let executable_selected =
        selected_model_buy_ask(executable_asks, max_price_per_tick, ticks).map_err(|e| {
            format!(
                "raw order-book matcher would select {}, but executable-depth check has no matching ask: {e}. \
                 Refusing to send escrow while stale/unreadable rows block the real matcher",
                describe_buy_ask(&raw_selected)
            )
        })?;
    let same_tc = raw_selected
        .token_contract
        .as_deref()
        .zip(executable_selected.token_contract.as_deref())
        .is_some_and(|(raw, executable)| raw.eq_ignore_ascii_case(executable));
    if !same_tc || raw_selected.order_id != executable_selected.order_id {
        return Err(format!(
            "raw order-book matcher would select {}, but executable quote selected {}. \
             Refusing to send escrow while stale/unreadable rows block the real matcher",
            describe_buy_ask(&raw_selected),
            describe_buy_ask(&executable_selected)
        ));
    }
    Ok(executable_selected)
}

fn same_token_contract(left: &OrderBookOrder, right: &OrderBookOrder) -> bool {
    left.token_contract
        .as_deref()
        .zip(right.token_contract.as_deref())
        .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn submit_safe_executable_book_asks(
    raw_asks: &[OrderBookOrder],
    executable_asks: &[OrderBookOrder],
    max_price_per_tick: u128,
    ticks: u128,
) -> Result<(Vec<OrderBookOrder>, Option<String>), String> {
    enum ListingBlocker {
        NonExecutable(OrderBookOrder),
        InsufficientHead(OrderBookOrder),
    }

    let raw_asks = coalesce_equivalent_resting_asks(raw_asks)?;
    let executable_asks = coalesce_equivalent_resting_asks(executable_asks)?;
    let mut rows = Vec::new();
    let mut blocker = None;

    for raw in raw_asks
        .iter()
        .filter(|ask| ask.price_per_tick <= max_price_per_tick)
    {
        let Some(executable) = executable_asks
            .iter()
            .find(|executable| same_token_contract(raw, executable))
        else {
            blocker = Some(ListingBlocker::NonExecutable(raw.clone()));
            break;
        };
        if executable.ticks >= ticks {
            rows.push(executable.clone());
        } else {
            blocker = Some(ListingBlocker::InsufficientHead(executable.clone()));
            break;
        }
    }

    if !rows.is_empty() {
        return Ok((rows, None));
    }

    let reason = if let Some(blocker) = blocker {
        match blocker {
            ListingBlocker::NonExecutable(blocker) => format!(
                "raw order-book matcher would hit non-executable {} before any later executable ask. \
                 Refusing to list stale/unreadable-blocked rows",
                describe_buy_ask(&blocker)
            ),
            ListingBlocker::InsufficientHead(blocker) => {
                let capacity = check_single_head_capacity(&blocker, ticks)
                    .expect_err("insufficient head blocker was checked before listing");
                format!(
                    "raw order-book matcher would hit executable but insufficient head {} before any later \
                     executable ask: {capacity}. Refusing to list rows the model-wide matcher cannot reach",
                    describe_buy_ask(&blocker)
                )
            }
        }
    } else if raw_asks
        .iter()
        .all(|ask| ask.price_per_tick > max_price_per_tick)
    {
        no_matching_ask_reason(&raw_asks, max_price_per_tick, ticks)
    } else if let Some(best) = executable_asks
        .iter()
        .filter(|ask| ask.price_per_tick <= max_price_per_tick)
        .min_by_key(|ask| (ask.price_per_tick, ask.order_id))
    {
        format!(
            "no executable ask has at least requested ticks {ticks}. Best executable ask is {}",
            describe_buy_ask(best)
        )
    } else {
        format!(
            "no executable matching ask for max_price_per_tick {max_price_per_tick}, requested ticks {ticks}. \
             The raw book has crossing rows, but none are live, funded, fresh, and unblocked"
        )
    };
    Ok((Vec::new(), Some(reason)))
}

fn orderbook_stats_for_error(snapshot: &OrderBookSnapshot) -> String {
    snapshot
        .stats
        .as_ref()
        .map(|s| format!("{s:?}"))
        .unwrap_or_else(|| "<book not active>".to_string())
}

fn check_expected_buy_target(
    asks: &[OrderBookOrder],
    expected_tc_lower: &str,
    max_price_per_tick: u128,
    ticks: u128,
) -> Result<(), String> {
    let asks = coalesce_equivalent_resting_asks(asks)?;
    let expected = asks.iter().find(|ask| {
        ask.token_contract
            .as_deref()
            .is_some_and(|tc| tc.eq_ignore_ascii_case(expected_tc_lower))
    });
    let Some(best) = next_matching_ask(&asks, max_price_per_tick, ticks) else {
        return Err(match expected {
            Some(ask) => format!(
                "the expected ask exists but is not matchable by this buy: tokenContract {}, price {}, ticks {}, \
                 buyer max_price_per_tick {max_price_per_tick}, requested ticks {ticks}",
                ask.token_contract.as_deref().unwrap_or("<none>"), ask.price_per_tick, ask.ticks,
            ),
            None => format!(
                "no resting ask for expected tokenContract {expected_tc_lower}, and no matchable ask for \
                 max_price_per_tick {max_price_per_tick}, requested ticks {ticks}"
            ),
        });
    };
    if best
        .token_contract
        .as_deref()
        .is_some_and(|tc| tc.eq_ignore_ascii_case(expected_tc_lower))
    {
        check_single_head_capacity(best, ticks)?;
        return Ok(());
    }
    Err(match expected {
        Some(ask) => format!(
            "placeInferenceBuy cannot target a TokenContract; the shared model book would match order #{} \
             tokenContract {} (price {}, ticks {}) before expected tokenContract {} (order #{}, price {}, ticks {}). \
             Refusing to send escrow into the wrong deal; buy the best matching market or clear/cancel the \
             earlier ask first",
            best.order_id,
            best.token_contract.as_deref().unwrap_or("<none>"),
            best.price_per_tick,
            best.ticks,
            ask.token_contract.as_deref().unwrap_or("<none>"),
            ask.order_id,
            ask.price_per_tick,
            ask.ticks,
        ),
        None => format!(
            "no resting ask for expected tokenContract {expected_tc_lower}; the shared model book would match \
             order #{} tokenContract {} (price {}, ticks {}) instead. Refusing to send escrow into the wrong deal",
            best.order_id, best.token_contract.as_deref().unwrap_or("<none>"), best.price_per_tick, best.ticks,
        ),
    })
}

#[allow(clippy::too_many_arguments)]
fn seller_post_sell_offer_timeout_message(
    ob: &Address,
    token_contract: &str,
    model_hash: &str,
    nonce: u64,
    seller_note: &Address,
    timeout: std::time::Duration,
    canonical_evidence: &str,
    tc_state_evidence: &str,
) -> String {
    format!(
        "seller postSellOffer submit timed out after {}s before shellnet returned an accepted/rejected \
         /v2/messages response; no message_hash/tx_hash is available. InferenceOrderBook {ob} model_hash={model_hash} \
         nonce={nonce} seller_note={seller_note} token_contract={token_contract}. {canonical_evidence}. \
         {tc_state_evidence}. This is  submit-timeout evidence; retry may be safe only after checking \
         whether the chain later shows a matching message/order for this exact TC.",
        timeout.as_secs()
    )
}

fn orderbook_stats_from_getter(stats: &Value) -> OrderBookStats {
    OrderBookStats {
        next_order_id: order_u128(stats, &["nextOrderId"]).unwrap_or(0),
        order_count: order_u128(stats, &["orderCount"]).unwrap_or(0),
        executed_notional: order_u128(stats, &["executedNotional"]).unwrap_or(0),
        executed_ticks: order_u128(stats, &["executedTicks"]).unwrap_or(0),
    }
}

#[cfg(test)]
mod offer_rested_match_tests {
    use super::{
        check_expected_buy_target, check_model_buy_full_fill, collect_live_orders,
        executable_resting_asks_by_state, expected_orderbook_order_from_getter, next_matching_ask,
        orderbook_order_from_getter, resting_ask_from_order, selected_model_buy_ask,
        selected_model_buy_ask_matching_executable_depth, submit_safe_executable_book_asks,
    };
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    fn zero_address() -> String {
        format!("0:{}", "0".repeat(64))
    }

    fn parsed_ask(
        order_id: u128,
        token_contract: &str,
        price: u128,
        amount: u128,
    ) -> crate::chain::OrderBookOrder {
        resting_ask_from_order(
            order_id,
            &json!({
                "note": "0:seller",
                "tokenContract": token_contract,
                "price": price.to_string(),
                "amount": amount.to_string(),
                "escrow": "0",
                "deadline": "0",
                "flags": "0",
                "ts": "0",
                "isBuy": false
            }),
        )
        .unwrap()
    }

    fn fresh_tc_state() -> Value {
        super::test_get_state(false, false, false, false, 0, 0, 0)
    }

    fn used_tc_state() -> Value {
        super::test_get_state(true, false, false, false, 104_448, 0, 0)
    }

    #[test]
    fn order_parser_decodes_every_complete_get_order_abi_field() {
        let order = orderbook_order_from_getter(
            7,
            &json!({
                "note": "0:seller",
                "tokenContract": "0:tc",
                "price": "1000",
                "amount": "1024",
                "escrow": "2048",
                "deadline": "1712345678",
                "flags": "3",
                "ts": "1712000000",
                "isBuy": false
            }),
        )
        .expect("complete getOrder ABI fixture should decode")
        .expect("complete order should be present");
        assert_eq!(order.order_id, 7);
        assert_eq!(order.owner_note, "0:seller");
        assert_eq!(order.token_contract.as_deref(), Some("0:tc"));
        assert!(!order.is_buy);
        assert_eq!(order.price_per_tick, 1000);
        assert_eq!(order.ticks, 1024);
        assert_eq!(order.escrow, 2048);
        assert_eq!(order.deadline, 1_712_345_678);
        assert_eq!(order.flags, 3);
        assert_eq!(order.timestamp, 1_712_000_000);
    }

    #[test]
    fn order_parser_accepts_live_hex_numeric_getter_values() {
        let ask = resting_ask_from_order(
            8,
            &json!({
                "note": "0:seller",
                "tokenContract": "0:tc",
                "price": "0x2710",
                "amount": "0x400",
                "escrow": "0x0",
                "deadline": "0x0",
                "flags": "0x0",
                "ts": "0x0",
                "isBuy": false
            }),
        )
        .expect("live getter hex numeric fields should parse");
        assert_eq!(ask.price_per_tick, 10_000);
        assert_eq!(ask.ticks, 1024);
    }

    #[test]
    fn generic_order_parser_keeps_resting_buy_orders_for_orders_cli() {
        let order = orderbook_order_from_getter(
            11,
            &json!({
                "note": "0:buyer",
                "tokenContract": zero_address(),
                "price": "1000",
                "amount": "3",
                "escrow": "3075",
                "deadline": "0",
                "flags": "0",
                "ts": "0",
                "isBuy": true
            }),
        )
        .expect("valid getOrder ABI fields")
        .expect("resting buy order should parse");
        assert_eq!(order.owner_note, "0:buyer");
        assert!(order.token_contract.is_none());
        assert!(order.is_buy);
        assert!(!order.is_resting_ask());
        assert_eq!(order.escrow, 3075);
    }

    #[test]
    fn order_parser_rejects_each_missing_required_get_order_abi_field() {
        let valid = json!({
            "note": "0:seller",
            "tokenContract": "0:tc",
            "price": "1",
            "amount": "1",
            "escrow": "0",
            "deadline": "0",
            "flags": "0",
            "ts": "0",
            "isBuy": false
        });

        for field in [
            "isBuy",
            "note",
            "tokenContract",
            "amount",
            "price",
            "escrow",
            "deadline",
            "flags",
            "ts",
        ] {
            let mut malformed = valid.clone();
            malformed
                .as_object_mut()
                .expect("order fixture is an object")
                .remove(field);
            let error = orderbook_order_from_getter(382, &malformed)
                .expect_err("required getOrder ABI field must fail closed");
            assert!(error.to_string().contains(field), "{error:#}");
        }

        let mut legacy_timestamp_only = valid.clone();
        legacy_timestamp_only
            .as_object_mut()
            .expect("order fixture is an object")
            .remove("ts");
        legacy_timestamp_only["timestamp"] = json!(0);
        let error = orderbook_order_from_getter(382, &legacy_timestamp_only)
            .expect_err("legacy timestamp alias must not replace deployed ts field");
        assert!(error.to_string().contains("ts"), "{error:#}");

        let mut wide_flags = valid.clone();
        wide_flags["flags"] = json!("256");
        let error = orderbook_order_from_getter(382, &wide_flags)
            .expect_err("flags wider than uint8 must fail closed");
        assert!(
            error.to_string().contains("flags exceed uint8"),
            "{error:#}"
        );

        let mut wide_price = valid;
        wide_price["price"] =
            json!("115792089237316195423570985008687907853269984665640564039457584007913129639935");
        let error = orderbook_order_from_getter(382, &wide_price)
            .expect_err("uint256 price wider than downstream u128 must fail closed");
        assert!(
            error.to_string().contains("price exceeds downstream u128"),
            "{error:#}"
        );
    }

    #[test]
    fn order_parser_skips_buy_cancelled_and_zero_tc_orders() {
        assert!(resting_ask_from_order(
            1,
            &json!({
                "note": "0:buyer", "tokenContract": "0:tc", "price": "1", "amount": "1",
                "escrow": "1", "deadline": "0", "flags": "0", "ts": "0", "isBuy": true
            })
        )
        .is_none());
        assert!(orderbook_order_from_getter(
            2,
            &json!({
                "note": zero_address(), "tokenContract": zero_address(), "price": "0", "amount": "0",
                "escrow": "0", "deadline": "0", "flags": "0", "ts": "0", "isBuy": false
            })
        )
        .expect("complete empty getOrder sentinel should decode")
        .is_none());
        assert!(resting_ask_from_order(
            3,
            &json!({
                "note": "0:seller", "tokenContract": zero_address(), "price": "1", "amount": "1",
                "escrow": "0", "deadline": "0", "flags": "0", "ts": "0", "isBuy": false
            })
        )
        .is_none());
    }

    #[test]
    fn order_parser_skips_filled_zero_tick_order_and_rejects_ownerless_amount() {
        // a filled / consumed order lingers in the book as a real owner note with ZERO
        // remaining ticks until a `cancelInferenceOrder` sweeps it. It is not matchable, so the
        // parser SKIPS it (Ok(None)) instead of erroring -- otherwise a single filled order at a
        // low id would abort the whole book scan before it reaches the live orders behind it.
        let filled_zero_tick = json!({
            "note": "0:seller", "tokenContract": "0:tc", "price": "1", "amount": "0",
            "escrow": "0", "deadline": "0", "flags": "0", "ts": "0", "isBuy": false
        });
        assert!(
            orderbook_order_from_getter(382, &filled_zero_tick)
                .expect("a filled zero-tick order is skipped, not an error")
                .is_none(),
            "a filled (zero-tick) order must be skipped so the scan reaches the live orders"
        );

        // A non-zero amount with a zero owner note is genuinely malformed(ticks with no owner)
        // and stays fail-loud.
        let ownerless_amount = json!({
            "note": zero_address(), "tokenContract": "0:tc", "price": "1", "amount": "1",
            "escrow": "0", "deadline": "0", "flags": "0", "ts": "0", "isBuy": false
        });
        let error = orderbook_order_from_getter(382, &ownerless_amount)
            .expect_err("nonzero amount with zero owner note is malformed, not absent");
        assert!(error.to_string().contains("zero owner note"), "{error:#}");
    }

    #[test]
    fn fixed_id_parser_accepts_only_complete_all_zero_tombstone_as_absent() {
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
        assert!(expected_orderbook_order_from_getter(382, &tombstone)
            .expect("complete all-zero fixed-id tombstone")
            .is_none());

        let mut mutated = tombstone.clone();
        mutated["note"] = json!("0:buyer");
        let error = expected_orderbook_order_from_getter(382, &mutated)
            .expect_err("a nonempty zero-amount fixed-id row is contradictory");
        assert!(
            error.to_string().contains("non-canonical zero-amount"),
            "{error:#}"
        );

        for field in ["note", "tokenContract"] {
            for malformed in ["x", ":", "0x"] {
                let mut mutated = tombstone.clone();
                mutated[field] = json!(malformed);
                let error = expected_orderbook_order_from_getter(382, &mutated).expect_err(
                    "malformed nonempty fixed-id address must not be accepted as a zero tombstone",
                );
                assert!(
                    error.to_string().contains("non-canonical zero-amount"),
                    "{field}={malformed:?}: {error:#}"
                );
            }
        }

        let live = json!({
            "note": format!("0:{}", "1".repeat(64)),
            "tokenContract": zero_address(),
            "price": "1000",
            "amount": "4",
            "escrow": "6100",
            "deadline": "200",
            "flags": "96",
            "ts": "100",
            "isBuy": true
        });
        assert!(expected_orderbook_order_from_getter(383, &live)
            .expect("valid fixed-id row")
            .is_some());
        for field in ["note", "tokenContract"] {
            for malformed in ["x", ":", "0x"] {
                let mut mutated = live.clone();
                mutated[field] = json!(malformed);
                let error = expected_orderbook_order_from_getter(383, &mutated)
                    .expect_err("malformed nonempty live fixed-id address must fail closed");
                assert!(
                    error.to_string().contains("malformed"),
                    "{field}={malformed:?}: {error:#}"
                );
            }
        }
    }

    #[test]
    fn book_scan_skips_filled_and_unparseable_orders_and_keeps_live_ones() {
        // end to end at the scan layer: a book with a filled order at id 1 and an
        // unparseable/corrupt slot at id 2 must still surface the live order at id 3, in order,
        // rather than aborting on the first non-live id.
        let raw = vec![
            (
                1u128,
                json!({
                    "note": "0:seller", "tokenContract": "0:tc1", "price": "1", "amount": "0",
                    "escrow": "0", "deadline": "0", "flags": "0", "ts": "0", "isBuy": false
                }),
            ),
            (
                2u128,
                json!({
                    "note": zero_address(), "tokenContract": "0:tc2", "price": "1", "amount": "5",
                    "escrow": "0", "deadline": "0", "flags": "0", "ts": "0", "isBuy": false
                }),
            ),
            (
                3u128,
                json!({
                    "note": "0:seller", "tokenContract": "0:tc3", "price": "7", "amount": "9",
                    "escrow": "0", "deadline": "0", "flags": "0", "ts": "0", "isBuy": false
                }),
            ),
        ];
        let live = collect_live_orders(raw);
        assert_eq!(
            live.len(),
            1,
            "only the live order should survive: {live:?}"
        );
        assert_eq!(live[0].order_id, 3);
        assert_eq!(live[0].ticks, 9);
    }

    #[test]
    fn buyer_target_preflight_accepts_expected_best_ask() {
        let asks = vec![
            parsed_ask(1, "0:expected", 1000, 2),
            parsed_ask(2, "0:later", 1200, 10),
        ];
        assert_eq!(
            next_matching_ask(&asks, 1000, 2)
                .unwrap()
                .token_contract
                .as_deref(),
            Some("0:expected")
        );
        assert!(check_expected_buy_target(&asks, "0:expected", 1000, 2).is_ok());
    }

    #[test]
    fn buyer_target_preflight_accepts_expected_partial_fill() {
        let asks = vec![parsed_ask(1, "0:expected", 1000, 10)];
        assert!(check_expected_buy_target(&asks, "0:expected", 1000, 2).is_ok());
    }

    #[test]
    fn model_only_preflight_accepts_partial_fill_before_submit() {
        let asks = vec![parsed_ask(1, "0:best", 1000, 2)];
        assert!(check_model_buy_full_fill(&asks, 1000, 1).is_ok());
    }

    #[test]
    fn model_only_preflight_accepts_whole_best_ask() {
        let asks = vec![parsed_ask(1, "0:best", 1000, 1)];
        assert!(check_model_buy_full_fill(&asks, 1000, 1).is_ok());
    }

    #[test]
    fn model_only_preflight_reports_price_ceiling_below_best_ask() {
        let asks = vec![parsed_ask(199, "0:best", 11, 1)];
        let quote = crate::chain::executable_quote(&asks, Some(1), None)
            .expect("the same book is quoteable without the buyer ceiling");
        assert!(quote.complete);

        let err = check_model_buy_full_fill(&asks, 10, 1).unwrap_err();

        assert!(err.contains("best ask price 11"), "{err}");
        assert!(err.contains("above buyer max_price_per_tick 10"), "{err}");
        assert!(
            err.contains("Raise --max-price-per-tick to at least 11"),
            "{err}"
        );
    }

    #[test]
    fn model_only_preflight_accepts_equivalent_duplicate_active_tc_asks() {
        let asks = vec![
            parsed_ask(2, "0:DUP", 1000, 1),
            parsed_ask(1, "0:dup", 1000, 1),
        ];
        assert!(check_model_buy_full_fill(&asks, 1000, 1).is_ok());
        let selected = selected_model_buy_ask(&asks, 1000, 1).expect("selected representative ask");
        assert_eq!(selected.order_id, 1);
        assert_eq!(selected.token_contract.as_deref(), Some("0:dup"));
    }

    #[test]
    fn model_only_preflight_rejects_conflicting_duplicate_active_tc_asks() {
        let asks = vec![
            parsed_ask(1, "0:dup", 900, 1),
            parsed_ask(2, "0:DUP", 1000, 1),
        ];
        let err = check_model_buy_full_fill(&asks, 1000, 1).unwrap_err();
        assert!(err.contains("conflicting terms/state"), "{err}");
        assert!(err.contains("0:dup"), "{err}");
    }

    #[test]
    fn executable_filter_skips_closed_duplicate_head() {
        let closed = "0:5701d680491b6ff787c18db8e3a2ecde799e039c595bee495d14c1a78cb4de57";
        let live = "0:7969d680491b6ff787c18db8e3a2ecde799e039c595bee495d14c1a78cb44704";
        let asks = vec![
            parsed_ask(14, closed, 100, 1024),
            parsed_ask(15, closed, 100, 1024),
            parsed_ask(19, live, 100, 1024),
        ];
        let mut states = BTreeMap::new();
        states.insert(live.to_ascii_lowercase(), fresh_tc_state());

        let executable =
            executable_resting_asks_by_state(&asks, |tc| states.get(&tc.to_ascii_lowercase()))
                .expect("equivalent stale duplicates are safe to filter");
        assert_eq!(executable.len(), 1);
        assert_eq!(executable[0].order_id, 19);
        assert_eq!(executable[0].token_contract.as_deref(), Some(live));

        let q = crate::chain::executable_quote(&executable, Some(1024), None)
            .expect("later live ask should remain executable despite stale head");
        assert!(q.complete);
        assert_eq!(q.filled_ticks, 1024);
        assert_eq!(q.fills.len(), 1);
        assert_eq!(q.fills[0].order_id, 19);
    }

    #[test]
    fn executable_filter_keeps_live_prefix_before_stale_tail() {
        let live = "0:7969c6c6012dce3575c0547857ce83bf8001e3deedd7ea0425af3b13d5b24704";
        let stale = "0:5701d680491b6ff787c18db8e3a2ecde799e039c595bee495d14c1a78cb4de57";
        let after = "0:236cd482607c8ca4690d15cbd95b511f84a8e68bf7eb81cbc0dbe3362bd4c688";
        let asks = vec![
            parsed_ask(35, live, 100, 1024),
            parsed_ask(36, stale, 101, 1024),
            parsed_ask(37, after, 102, 1024),
        ];
        let mut states = BTreeMap::new();
        states.insert(live.to_ascii_lowercase(), fresh_tc_state());
        states.insert(stale.to_ascii_lowercase(), used_tc_state());
        states.insert(after.to_ascii_lowercase(), fresh_tc_state());

        let executable =
            executable_resting_asks_by_state(&asks, |tc| states.get(&tc.to_ascii_lowercase()))
                .expect("live prefix before a stale tail remains executable");
        assert_eq!(executable.len(), 2);
        assert_eq!(executable[0].order_id, 35);
        assert_eq!(executable[0].token_contract.as_deref(), Some(live));
        assert_eq!(executable[1].order_id, 37);
        assert_eq!(executable[1].token_contract.as_deref(), Some(after));
    }

    #[test]
    fn model_only_buy_preflight_rejects_live_ask_after_stale_head() {
        let closed = "0:5701d680491b6ff787c18db8e3a2ecde799e039c595bee495d14c1a78cb4de57";
        let live = "0:7969c6c6012dce3575c0547857ce83bf8001e3deedd7ea0425af3b13d5b24704";
        let asks = vec![
            parsed_ask(14, closed, 100, 1024),
            parsed_ask(15, closed, 100, 1024),
            parsed_ask(35, live, 100, 1024),
        ];
        let mut states = BTreeMap::new();
        states.insert(live.to_ascii_lowercase(), fresh_tc_state());
        let executable =
            executable_resting_asks_by_state(&asks, |tc| states.get(&tc.to_ascii_lowercase()))
                .expect("stale raw rows are skipped in executable depth");
        assert_eq!(executable.len(), 1);
        assert_eq!(executable[0].order_id, 35);
        let q = crate::chain::executable_quote(&executable, Some(1024), None)
            .expect("later live ask should quote");
        assert!(q.complete);
        assert_eq!(q.fills.len(), 1);
        assert_eq!(q.fills[0].order_id, 35);

        let err = selected_model_buy_ask_matching_executable_depth(&asks, &executable, 100, 1024)
            .expect_err("raw head blocks later executable ask for submit");
        assert!(err.contains("raw order-book matcher would select"), "{err}");
        assert!(err.contains("order "), "{err}");
        assert!(err.contains("executable quote selected order "), "{err}");
        assert!(err.contains("Refusing to send escrow"), "{err}");
    }

    #[test]
    fn executable_filter_skips_unreadable_raw_row_but_preflight_rejects_mismatch() {
        let unreadable = "0:1111000000000000000000000000000000000000000000000000000000000000";
        let live = "0:2222000000000000000000000000000000000000000000000000000000000000";
        let raw_asks = vec![
            parsed_ask(10, unreadable, 100, 1024),
            parsed_ask(11, live, 100, 1024),
        ];
        let raw_depth_ticks: u128 = raw_asks.iter().map(|ask| ask.ticks).sum();
        assert_eq!(raw_asks.len(), 2);
        assert_eq!(raw_depth_ticks, 2048);

        let mut states = BTreeMap::new();
        states.insert(live.to_ascii_lowercase(), fresh_tc_state());
        let executable =
            executable_resting_asks_by_state(&raw_asks, |tc| states.get(&tc.to_ascii_lowercase()))
                .expect("unreadable raw rows are skipped in quote executable depth");
        assert_eq!(executable.len(), 1);
        assert_eq!(executable[0].order_id, 11);
        assert_eq!(executable[0].token_contract.as_deref(), Some(live));

        let quote = crate::chain::executable_quote(&executable, Some(1024), None)
            .expect("quote still fills the later live ask");
        assert!(quote.complete);
        assert_eq!(quote.filled_ticks, 1024);
        assert_eq!(quote.fills.len(), 1);
        assert_eq!(quote.fills[0].order_id, 11);
        assert_eq!(quote.fills[0].token_contract, live);

        let err =
            selected_model_buy_ask_matching_executable_depth(&raw_asks, &executable, 100, 1024)
                .expect_err("raw unreadable head blocks later executable ask for submit");
        assert!(err.contains("raw order-book matcher would select"), "{err}");
        assert!(err.contains("order "), "{err}");
        assert!(err.contains("executable quote selected order "), "{err}");
    }

    #[test]
    fn model_only_buy_preflight_rejects_skip_only_later_quote_selection() {
        let closed = "0:5701d680491b6ff787c18db8e3a2ecde799e039c595bee495d14c1a78cb4de57";
        let live = "0:7969c6c6012dce3575c0547857ce83bf8001e3deedd7ea0425af3b13d5b24704";
        let asks = vec![
            parsed_ask(14, closed, 100, 1024),
            parsed_ask(15, closed, 100, 1024),
            parsed_ask(35, live, 100, 1024),
        ];
        let skip_only_executable = vec![parsed_ask(35, live, 100, 1024)];

        let err = selected_model_buy_ask_matching_executable_depth(
            &asks,
            &skip_only_executable,
            100,
            1024,
        )
        .expect_err("model-only preflight must not follow skip-only executable depth");
        assert!(err.contains("raw order-book matcher would select"), "{err}");
        assert!(err.contains("order "), "{err}");
        assert!(err.contains("executable quote selected order "), "{err}");
    }

    #[test]
    fn model_only_buy_preflight_accepts_when_raw_head_matches_quote() {
        let live = "0:7969c6c6012dce3575c0547857ce83bf8001e3deedd7ea0425af3b13d5b24704";
        let asks = vec![parsed_ask(35, live, 100, 1024)];
        let mut states = BTreeMap::new();
        states.insert(live.to_ascii_lowercase(), fresh_tc_state());
        let executable =
            executable_resting_asks_by_state(&asks, |tc| states.get(&tc.to_ascii_lowercase()))
                .expect("fresh ask remains executable");

        let selected =
            selected_model_buy_ask_matching_executable_depth(&asks, &executable, 100, 1024)
                .expect("raw matcher and executable quote select the same ask");
        assert_eq!(selected.order_id, 35);
        assert_eq!(selected.token_contract.as_deref(), Some(live));
    }

    #[test]
    fn executable_book_listing_returns_multiple_fresh_rows() {
        let first = "0:1111000000000000000000000000000000000000000000000000000000000000";
        let second = "0:2222000000000000000000000000000000000000000000000000000000000000";
        let asks = vec![
            parsed_ask(11, first, 100, 10),
            parsed_ask(12, second, 101, 12),
        ];

        let (rows, reason) =
            submit_safe_executable_book_asks(&asks, &asks, 101, 8).expect("listing is safe");

        assert!(reason.is_none(), "{reason:?}");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].token_contract.as_deref(), Some(first));
        assert_eq!(rows[1].token_contract.as_deref(), Some(second));
    }

    #[test]
    fn executable_book_listing_hides_rows_after_stale_cheaper_blocker() {
        let stale = "0:1111000000000000000000000000000000000000000000000000000000000000";
        let live = "0:2222000000000000000000000000000000000000000000000000000000000000";
        let raw_asks = vec![
            parsed_ask(11, stale, 100, 10),
            parsed_ask(12, live, 101, 12),
        ];
        let executable_asks = vec![parsed_ask(12, live, 101, 12)];

        let (rows, reason) = submit_safe_executable_book_asks(&raw_asks, &executable_asks, 101, 8)
            .expect("stale blocker is an empty executable book, not a duplicate-book error");

        assert!(rows.is_empty(), "{rows:?}");
        let reason = reason.expect("empty stale-blocked list carries reason");
        assert!(reason.contains("non-executable order "), "{reason}");
        assert!(reason.contains("Refusing to list"), "{reason}");
    }

    #[test]
    fn executable_book_listing_keeps_safe_prefix_before_stale_tail() {
        let first = "0:1111000000000000000000000000000000000000000000000000000000000000";
        let stale = "0:2222000000000000000000000000000000000000000000000000000000000000";
        let hidden = "0:3333000000000000000000000000000000000000000000000000000000000000";
        let raw_asks = vec![
            parsed_ask(11, first, 100, 10),
            parsed_ask(12, stale, 101, 12),
            parsed_ask(13, hidden, 102, 12),
        ];
        let executable_asks = vec![
            parsed_ask(11, first, 100, 10),
            parsed_ask(13, hidden, 102, 12),
        ];

        let (rows, reason) = submit_safe_executable_book_asks(&raw_asks, &executable_asks, 102, 8)
            .expect("safe prefix can still be listed");

        assert!(reason.is_none(), "{reason:?}");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].token_contract.as_deref(), Some(first));
    }

    #[test]
    fn executable_book_listing_blocks_later_rows_after_insufficient_head() {
        let short_head = "0:1111000000000000000000000000000000000000000000000000000000000000";
        let hidden = "0:2222000000000000000000000000000000000000000000000000000000000000";
        let asks = vec![
            parsed_ask(11, short_head, 100, 1),
            parsed_ask(12, hidden, 101, 8),
        ];

        let (rows, reason) =
            submit_safe_executable_book_asks(&asks, &asks, 101, 8).expect("listing is safe");

        assert!(
            rows.is_empty(),
            "later row must not be listed because model-wide matcher fails on the insufficient head: {rows:?}"
        );
        let reason = reason.expect("empty insufficient-head-blocked list carries reason");
        assert!(reason.contains("insufficient head"), "{reason}");
        assert!(reason.contains("refusing multi-ask fill"), "{reason}");
        assert!(reason.contains("order "), "{reason}");
    }

    #[test]
    fn model_only_buy_preflight_preserves_conflicting_duplicate_fail_closed() {
        let dup = "0:5701d680491b6ff787c18db8e3a2ecde799e039c595bee495d14c1a78cb4de57";
        let asks = vec![
            parsed_ask(14, dup, 100, 1024),
            parsed_ask(15, dup, 101, 1024),
        ];
        let err = selected_model_buy_ask_matching_executable_depth(&asks, &[], 101, 1024)
            .expect_err("conflicting duplicates fail before executable-depth fallback");
        assert!(err.contains("conflicting terms/state"), "{err}");
        assert!(err.contains("order_ids [14,15]"), "{err}");
    }

    #[test]
    fn executable_filter_skips_used_duplicate_head() {
        let used = "0:1111000000000000000000000000000000000000000000000000000000000000";
        let live = "0:2222000000000000000000000000000000000000000000000000000000000000";
        let asks = vec![
            parsed_ask(1, used, 100, 1024),
            parsed_ask(2, used, 100, 1024),
            parsed_ask(3, live, 101, 1024),
        ];
        let mut states = BTreeMap::new();
        states.insert(used.to_ascii_lowercase(), used_tc_state());
        states.insert(live.to_ascii_lowercase(), fresh_tc_state());

        let executable =
            executable_resting_asks_by_state(&asks, |tc| states.get(&tc.to_ascii_lowercase()))
                .expect("used duplicate rows are non-executable depth");
        assert_eq!(executable.len(), 1);
        assert_eq!(executable[0].order_id, 3);
        assert_eq!(executable[0].token_contract.as_deref(), Some(live));
    }

    #[test]
    fn executable_filter_rejects_conflicting_duplicate_before_state_skip() {
        let closed = "0:5701d680491b6ff787c18db8e3a2ecde799e039c595bee495d14c1a78cb4de57";
        let live = "0:7969d680491b6ff787c18db8e3a2ecde799e039c595bee495d14c1a78cb44704";
        let asks = vec![
            parsed_ask(14, closed, 100, 1024),
            parsed_ask(15, closed, 101, 1024),
            parsed_ask(19, live, 100, 1024),
        ];
        let mut states = BTreeMap::new();
        states.insert(live.to_ascii_lowercase(), fresh_tc_state());

        let err =
            executable_resting_asks_by_state(&asks, |tc| states.get(&tc.to_ascii_lowercase()))
                .expect_err("conflicting duplicates must fail closed even if their TC is stale");
        assert!(err.contains("conflicting terms/state"), "{err}");
        assert!(err.contains("order_ids [14,15]"), "{err}");
    }

    #[test]
    fn buyer_target_preflight_rejects_foreign_better_ask() {
        let asks = vec![
            parsed_ask(1, "0:foreign", 900, 10),
            parsed_ask(2, "0:expected", 1000, 10),
        ];
        let err = check_expected_buy_target(&asks, "0:expected", 1000, 2).unwrap_err();
        assert!(err.contains("would match order "), "{err}");
        assert!(
            err.contains("before expected tokenContract 0:expected"),
            "{err}"
        );
    }

    #[test]
    fn buyer_target_preflight_rejects_foreign_partial_fill_before_expected() {
        let asks = vec![
            parsed_ask(1, "0:foreign", 900, 1),
            parsed_ask(2, "0:expected", 1000, 10),
        ];
        let err = check_expected_buy_target(&asks, "0:expected", 1000, 2).unwrap_err();
        assert!(err.contains("would match order "), "{err}");
        assert!(err.contains("tokenContract 0:foreign"), "{err}");
    }

    #[test]
    fn buyer_target_preflight_rejects_missing_expected_ask() {
        let asks = vec![parsed_ask(4, "0:foreign", 1000, 10)];
        let err = check_expected_buy_target(&asks, "0:expected", 1000, 2).unwrap_err();
        assert!(
            err.contains("no resting ask for expected tokenContract 0:expected"),
            "{err}"
        );
        assert!(err.contains("would match"), "{err}");
    }

    #[test]
    fn buyer_target_preflight_rejects_unmatchable_expected_ask() {
        let asks = vec![parsed_ask(5, "0:expected", 1000, 1)];
        let err = check_expected_buy_target(&asks, "0:expected", 1000, 2).unwrap_err();
        assert!(err.contains("refusing multi-ask fill"), "{err}");
        assert!(err.contains("has only 1 ticks"), "{err}");
    }

    #[test]
    fn buyer_target_preflight_accepts_equivalent_duplicate_active_tc_asks() {
        let asks = vec![
            parsed_ask(1, "0:expected", 1000, 2),
            parsed_ask(2, "0:EXPECTED", 1000, 2),
        ];
        assert!(check_expected_buy_target(&asks, "0:expected", 1000, 2).is_ok());
    }

    #[test]
    fn buyer_target_preflight_rejects_conflicting_duplicate_active_tc_asks() {
        let asks = vec![
            parsed_ask(1, "0:expected", 1000, 2),
            parsed_ask(2, "0:EXPECTED", 1000, 3),
        ];
        let err = check_expected_buy_target(&asks, "0:expected", 1000, 2).unwrap_err();
        assert!(err.contains("conflicting terms/state"), "{err}");
    }
}

/// (pure, offline-testable): is a per-deal `TokenContract` already USED(not fresh/reusable)? A fresh
/// active TC is unfunded/unopened -- all `getState` flags false, all amounts 0 -> `None`. Any of
/// `opened`/`funded`/`disputed`/`probeAccepted`, or authoritative non-zero escrow/probe/claim/owed state,
/// means a prior deal used this `(sellerPubkey, nonce)` TC; resting a new ask reverts the seller's pre-stream
/// steps(`fundSellerBond`/`open`) with a raw `TVM_ERROR`(`ERR_ALREADY_OPEN` 321 and kin). Returns
/// `Some(reason)`(the offending flags/amounts) when used. A malformed getter is an error, never a fresh TC.
fn token_contract_used_reason(state: DealChainState) -> Option<String> {
    let mut used = Vec::new();
    if state.opened {
        used.push("opened".to_string());
    }
    if state.funded {
        used.push("funded".to_string());
    }
    if state.disputed {
        used.push("disputed".to_string());
    }
    if state.probe_accepted {
        used.push("probeAccepted".to_string());
    }
    for (field, v) in [
        ("deposit", state.deposit),
        ("probeTick", state.probe_tick),
        ("finalizedOwed", state.finalized_owed),
        ("tokensFinal", state.tokens_final),
        ("tokensSuperseded", state.tokens_superseded),
        ("tokensPending", state.tokens_pending),
    ] {
        if v > 0 {
            used.push(format!("{field}={v}"));
        }
    }
    if let Some(funded_time) = state.funded_time {
        used.push(format!("fundedTime={funded_time}"));
    }
    for (field, value) in [
        ("probeTime", state.probe_time),
        ("prevClaimTime", state.prev_claim_time),
        ("lastClaimTime", state.last_claim_time),
        ("disputeTime", state.dispute_time),
    ] {
        if value > 0 {
            used.push(format!("{field}={value}"));
        }
    }
    (!used.is_empty()).then(|| used.join(", "))
}

fn check_selected_token_contract_unused(
    token_contract: &str,
    state: Option<DealChainState>,
) -> Result<(), String> {
    if let Some(reason) = token_contract_non_executable_reason(state) {
        return Err(format!(
            "selected TokenContract {token_contract} is {reason}; refusing to move escrow"
        ));
    }
    Ok(())
}

fn token_contract_non_executable_reason(state: Option<DealChainState>) -> Option<String> {
    let Some(state) = state else {
        return Some("not readable by getState".to_string());
    };
    token_contract_used_reason(state)
        .map(|reason| format!("already used by chain state ({reason})"))
}

#[cfg(test)]
fn test_get_state(
    funded: bool,
    opened: bool,
    probe_accepted: bool,
    disputed: bool,
    deposit: u128,
    probe_tick: u128,
    finalized_owed: u128,
) -> Value {
    json!({
        "funded": funded,
        "opened": opened,
        "probeAccepted": probe_accepted,
        "disputed": disputed,
        "deposit": deposit.to_string(),
        "probeTick": probe_tick.to_string(),
        "finalizedOwed": finalized_owed.to_string(),
        "tokensFinal": "0",
        "tokensSuperseded": "0",
        "tokensPending": "0",
        "probeTime": "0",
        "prevClaimTime": "0",
        "lastClaimTime": "0",
        "disputeTime": "0",
        "fundedTime": "0"
    })
}

#[cfg(test)]
fn executable_resting_asks_by_state<'a, F>(
    orders: &[OrderBookOrder],
    mut state_for_tc: F,
) -> Result<Vec<OrderBookOrder>, String>
where
    F: FnMut(&str) -> Option<&'a Value>,
{
    let asks = coalesce_equivalent_resting_asks(orders)?;
    let mut executable = Vec::new();
    for ask in asks {
        let Some(tc) = ask.token_contract.as_deref() else {
            continue;
        };
        let state = state_for_tc(tc)
            .map(DealChainState::decode_getter)
            .transpose()?;
        if token_contract_non_executable_reason(state).is_some() {
            continue;
        }
        executable.push(ask);
    }
    Ok(executable)
}

/// (pure, offline-testable): the note's on-chain owner key (`getDetails().ephemeralPubkey` -- what the
/// `onlyOwnerPubkey(_ephemeralPubkey)` gate checks `msg.pubkey()` against) must equal the key the client signs
/// the owner-authenticated write(`placeInferenceBuy` / `postSellOffer`) with. If the note's `_ephemeralPubkey`
/// was rotated(`changeOwner`, `PrivateNote.sol:381`) or the pool records a different/orphaned owner, that gate
/// rejects the write PRE-accept(`ERR_INVALID_SENDER` 101, dex table -- `contracts/dex/modifiers/errors.sol`) ->
/// no tx commits -> the buyer silently 300s-times out in `read_match`.
/// Returns the actionable fail-closed reason, or `None` when they match. Both keys are normalized
/// (lower-case, strip `0x`) before comparing -- the getter returns `0x...`(possibly upper-case), `public_hex()`
/// has no prefix. This is the branch-3(non-conforming/orphaned note) guard; the async
/// [`RealChainBackend::assert_note_owner_matches`] wraps it with the on-chain `getDetails` read.
pub(super) fn note_owner_mismatch_reason(
    role: &str,
    note: &Address,
    ephemeral_onchain: Option<&str>,
    signing_pubkey_hex: &str,
) -> Option<String> {
    let norm = |s: &str| s.to_ascii_lowercase().trim_start_matches("0x").to_string();
    let signing = norm(signing_pubkey_hex);
    let onchain = ephemeral_onchain.unwrap_or("<none>");
    if !signing.is_empty() && norm(onchain) == signing {
        return None;
    }
    Some(format!(
        "{role} aborted: --note-key pubkey 0x{signing} does not match note {note}'s on-chain owner key \
         _ephemeralPubkey {onchain} (ownership rotated via changeOwner, or a stale/wrong/orphaned pool). The \
         note's onlyOwnerPubkey gate rejects msg.pubkey() pre-accept (ERR_INVALID_SENDER 101, dex table) -- the \
         write never commits (no order rests; the buyer then 300s-times out in read_match). Re-mint the note \
         against the current contracts (`mint_pn_pool`) and point DEXDO_PN_POOL at the fresh pool, or use the \
         correct --note-key."
    ))
}

// --- Shared helpers for the per-role CLI backends ---------------------------------------
// Free functions reused by `RealSellerBackend`/`RealBuyerBackend`. `RealDealBackend`
// (the in-process form of D2) is intentionally NOT touched(a 10/10 do-not-break) -- it has its own inline bodies; the small
// duplication of formulas here is the deliberate price of "leaving D2 as is".

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimHighWaterRead {
    Behind(u128),
    Equal,
    Ahead(u128),
}

/// Read the claim cursor without inventing a zero for absent/malformed state. A guessed cursor can make the
/// seller resubmit an old cumulative value or skip delivered tokens, so every reconciliation is fail-closed.
fn claim_high_water_read(
    tc: &str,
    state: Option<&Value>,
    attempted: u128,
) -> Result<ClaimHighWaterRead, ChainError> {
    let state = state.ok_or_else(|| {
        ChainError::Chain(format!(
            "TC {tc}: getState() returned no data while reconciling claimTokens({attempted})"
        ))
    })?;
    let raw = state
        .get("tokensPending")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ChainError::Chain(format!(
                "TC {tc}: getState().tokensPending is missing or not a string while reconciling \
                 claimTokens({attempted})"
            ))
        })?;
    let on_chain = raw.parse::<u128>().map_err(|error| {
        ChainError::Chain(format!(
            "TC {tc}: getState().tokensPending value {raw:?} is malformed while reconciling \
             claimTokens({attempted}): {error}"
        ))
    })?;
    Ok(match on_chain.cmp(&attempted) {
        std::cmp::Ordering::Less => ClaimHighWaterRead::Behind(on_chain),
        std::cmp::Ordering::Equal => ClaimHighWaterRead::Equal,
        std::cmp::Ordering::Greater => ClaimHighWaterRead::Ahead(on_chain),
    })
}

async fn submit_claim_confirmed_with<Read, ReadFuture, Submit, SubmitFuture, Pause, PauseFuture>(
    tc: &str,
    cumulative_tokens: u128,
    mut read: Read,
    mut submit: Submit,
    mut pause: Pause,
) -> Result<(), ChainError>
where
    Read: FnMut() -> ReadFuture,
    ReadFuture: std::future::Future<Output = Result<Option<Value>, ChainError>>,
    Submit: FnMut() -> SubmitFuture,
    SubmitFuture: std::future::Future<Output = Result<(), ChainError>>,
    Pause: FnMut() -> PauseFuture,
    PauseFuture: std::future::Future<Output = ()>,
{
    match claim_high_water_read(tc, read().await?.as_ref(), cumulative_tokens)? {
        ClaimHighWaterRead::Equal => return Ok(()),
        ClaimHighWaterRead::Ahead(on_chain) => {
            return Err(ChainError::ClaimHighWaterResync {
                attempted: cumulative_tokens,
                on_chain,
            });
        }
        ClaimHighWaterRead::Behind(_) => {}
    }

    // A transport failure can mean only that the submit RESPONSE was lost. Reconcile by authoritative state
    // before deciding: equality proves the write landed, a higher value asks the driver to resynchronise, and
    // an unchanged lower value remains a fail-closed error.
    let submit_error = match submit().await {
        Ok(()) => None,
        Err(error @ (ChainError::Transport(_) | ChainError::AmbiguousSubmit(_))) => Some(error),
        Err(error) => return Err(error),
    };
    let mut last_observed = None;
    let confirmation = ClaimConfirmationParams::canonical();
    for attempt in 0..confirmation.max_reads {
        match claim_high_water_read(tc, read().await?.as_ref(), cumulative_tokens)? {
            ClaimHighWaterRead::Equal => return Ok(()),
            ClaimHighWaterRead::Ahead(on_chain) => {
                return Err(ChainError::ClaimHighWaterResync {
                    attempted: cumulative_tokens,
                    on_chain,
                });
            }
            ClaimHighWaterRead::Behind(on_chain) => last_observed = Some(on_chain),
        }
        if attempt + 1 < confirmation.max_reads {
            pause().await;
        }
    }

    let lost_response = submit_error
        .map(|error| format!(" after ambiguous submit ({error})"))
        .unwrap_or_default();
    Err(ChainError::Chain(format!(
        "TC {tc}: claimTokens({cumulative_tokens}) did not apply{lost_response}; authoritative \
         tokensPending remained below it at {}",
        last_observed.unwrap_or(0)
    )))
}

/// Submit a cumulative consumption claim and confirm BY FACT that it landed.
/// A successful POST is not proof: the contract REJECTS an out-of-bounds claim(cap, rate, interval) rather
/// than trimming it, and treating a rejection as success would march the driver's local cursor past what the
/// chain actually owes -- silently forfeiting the difference. So this waits for `tokensPending` to reach the
/// asserted total. An exactly already-recorded total is a no-op; a higher one is returned as an explicit
/// resynchronisation, while a lower/malformed read never counts as success.
async fn submit_claim_confirmed(
    chain: &RealChainBackend,
    tc: &Address,
    seller_keys: &KeyPair,
    cumulative_tokens: u128,
) -> Result<(), ChainError> {
    submit_claim_confirmed_with(
        &tc.to_string(),
        cumulative_tokens,
        || async { chain.token_contract_state(tc).await.map_err(map_err) },
        || async {
            chain
                .claim_tokens(tc, seller_keys, cumulative_tokens)
                .await
                .map_err(map_claim_submit_err)
                .map(|_| ())
        },
        || tokio::time::sleep(ClaimConfirmationParams::canonical().poll_interval),
    )
    .await
}

#[cfg(test)]
mod claim_confirmation_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn state(tokens_pending: Value) -> Option<Value> {
        Some(json!({ "tokensPending": tokens_pending }))
    }

    async fn accepted_post_decode_error(posts_received: Arc<AtomicUsize>) -> ChainError {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind claim submit endpoint");
        let address = listener.local_addr().expect("claim submit address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept claim POST");
            let mut request = [0u8; 8192];
            let read = socket.read(&mut request).await.expect("read claim POST");
            assert!(read > 0, "the claim POST must reach the endpoint");
            posts_received.fetch_add(1, Ordering::Relaxed);
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 8\r\nConnection: close\r\n\r\nnot-json",
                )
                .await
                .expect("write invalid success response");
        });

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("claim submit client");
        let error = super::super::client::send_message_routed_checked(
            &client,
            &format!("http://{address}"),
            "signed-claim-boc",
            "0:11",
            "0:22",
            None,
        )
        .await
        .expect_err("invalid JSON after HTTP 200 must fail");
        server.await.expect("claim submit server");
        map_claim_submit_err(error)
    }

    async fn reconcile_accepted_decode(
        reads: impl IntoIterator<Item = Option<Value>>,
    ) -> (Result<(), ChainError>, usize) {
        let reads = Arc::new(Mutex::new(VecDeque::from_iter(reads)));
        let last_read = Arc::new(Mutex::new(None));
        let posts = Arc::new(AtomicUsize::new(0));
        let result = submit_claim_confirmed_with(
            "0:tc",
            2_000_000,
            {
                let reads = Arc::clone(&reads);
                let last_read = Arc::clone(&last_read);
                move || {
                    let reads = Arc::clone(&reads);
                    let last_read = Arc::clone(&last_read);
                    async move {
                        let next = reads
                            .lock()
                            .expect("reads")
                            .pop_front()
                            .or_else(|| last_read.lock().expect("last read").clone())
                            .expect("at least one scripted state");
                        *last_read.lock().expect("last read") = Some(next.clone());
                        Ok(next)
                    }
                }
            },
            {
                let posts = Arc::clone(&posts);
                move || {
                    let posts = Arc::clone(&posts);
                    async move { Err(accepted_post_decode_error(posts).await) }
                }
            },
            || async {},
        )
        .await;
        (result, posts.load(Ordering::Relaxed))
    }

    #[test]
    fn claim_readback_distinguishes_equal_higher_and_lower() {
        assert_eq!(
            claim_high_water_read("0:tc", state(json!("2000000")).as_ref(), 2_000_000)
                .expect("equal"),
            ClaimHighWaterRead::Equal
        );
        assert_eq!(
            claim_high_water_read("0:tc", state(json!("3000000")).as_ref(), 2_000_000)
                .expect("higher"),
            ClaimHighWaterRead::Ahead(3_000_000)
        );
        assert_eq!(
            claim_high_water_read("0:tc", state(json!("1000000")).as_ref(), 2_000_000)
                .expect("lower"),
            ClaimHighWaterRead::Behind(1_000_000)
        );
    }

    #[test]
    fn claim_readback_rejects_missing_or_malformed_high_water() {
        for malformed in [
            None,
            Some(json!({})),
            state(json!(1_000_000)),
            state(json!("not-a-number")),
        ] {
            let error = claim_high_water_read("0:tc", malformed.as_ref(), 2_000_000)
                .expect_err("malformed claim state must fail closed");
            assert!(error.to_string().contains("tokensPending") || malformed.is_none());
        }
    }

    #[tokio::test]
    async fn lost_submit_response_is_confirmed_only_by_equal_onchain_value() {
        let reads = Arc::new(Mutex::new(VecDeque::from([
            state(json!("1000000")),
            state(json!("2000000")),
        ])));
        let submits = Arc::new(AtomicUsize::new(0));
        submit_claim_confirmed_with(
            "0:tc",
            2_000_000,
            {
                let reads = Arc::clone(&reads);
                move || {
                    let reads = Arc::clone(&reads);
                    async move {
                        Ok(reads
                            .lock()
                            .expect("reads")
                            .pop_front()
                            .expect("scripted state"))
                    }
                }
            },
            {
                let submits = Arc::clone(&submits);
                move || {
                    let submits = Arc::clone(&submits);
                    async move {
                        submits.fetch_add(1, Ordering::Relaxed);
                        Err(ChainError::Transport("submit response lost".to_string()))
                    }
                }
            },
            || async {},
        )
        .await
        .expect("equal readback proves the lost-response submit landed");
        assert_eq!(submits.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn accepted_post_decode_failure_uses_strict_authoritative_readback() {
        let (equal, posts) =
            reconcile_accepted_decode([state(json!("1000000")), state(json!("2000000"))]).await;
        equal.expect("exact readback proves the accepted POST landed");
        assert_eq!(posts, 1);

        let (ahead, posts) =
            reconcile_accepted_decode([state(json!("1000000")), state(json!("3000000"))]).await;
        assert!(matches!(
            ahead,
            Err(ChainError::ClaimHighWaterResync {
                attempted: 2_000_000,
                on_chain: 3_000_000
            })
        ));
        assert_eq!(posts, 1);

        let (behind, posts) =
            reconcile_accepted_decode([state(json!("1000000")), state(json!("1000000"))]).await;
        let behind = behind.expect_err("a lower cursor must fail closed");
        assert!(behind.to_string().contains("remained below"), "{behind}");
        assert_eq!(posts, 1);

        let (malformed, posts) =
            reconcile_accepted_decode([state(json!("1000000")), Some(json!({}))]).await;
        let malformed = malformed.expect_err("malformed state must fail closed");
        assert!(
            malformed.to_string().contains("tokensPending"),
            "{malformed}"
        );
        assert_eq!(posts, 1);
    }

    #[tokio::test]
    async fn higher_onchain_value_requests_explicit_resync_without_submit() {
        let submits = Arc::new(AtomicUsize::new(0));
        let error = submit_claim_confirmed_with(
            "0:tc",
            2_000_000,
            || async { Ok(state(json!("3000000"))) },
            {
                let submits = Arc::clone(&submits);
                move || {
                    let submits = Arc::clone(&submits);
                    async move {
                        submits.fetch_add(1, Ordering::Relaxed);
                        Ok(())
                    }
                }
            },
            || async {},
        )
        .await
        .expect_err("higher chain cursor must request resync");
        assert!(matches!(
            error,
            ChainError::ClaimHighWaterResync {
                attempted: 2_000_000,
                on_chain: 3_000_000
            }
        ));
        assert_eq!(submits.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn lower_readback_never_confirms_a_claim() {
        let reads = Arc::new(AtomicUsize::new(0));
        let pauses = Arc::new(AtomicUsize::new(0));
        let error = submit_claim_confirmed_with(
            "0:tc",
            2_000_000,
            {
                let reads = Arc::clone(&reads);
                move || {
                    let reads = Arc::clone(&reads);
                    async move {
                        reads.fetch_add(1, Ordering::Relaxed);
                        Ok(state(json!("1000000")))
                    }
                }
            },
            || async { Ok(()) },
            {
                let pauses = Arc::clone(&pauses);
                move || {
                    let pauses = Arc::clone(&pauses);
                    async move {
                        pauses.fetch_add(1, Ordering::Relaxed);
                    }
                }
            },
        )
        .await
        .expect_err("lower state must fail closed");
        assert!(error.to_string().contains("remained below"), "{error}");

        let confirmation = ClaimConfirmationParams::canonical();
        assert_eq!(
            reads.load(Ordering::Relaxed),
            confirmation.max_reads + 1,
            "one pre-submit read is followed by the canonical confirmation reads"
        );
        assert_eq!(
            pauses.load(Ordering::Relaxed),
            confirmation.max_reads - 1,
            "the immediate first confirmation read leaves exactly N-1 poll waits"
        );
        assert_eq!(
            confirmation.poll_interval * u32::try_from(pauses.load(Ordering::Relaxed)).unwrap(),
            confirmation.max_elapsed()
        );
    }
}

fn finalize_post_confirmed(
    token_contract: &TokenContract,
    before_tokens_final: u128,
    state: Option<DealChainState>,
    token_contract_active: bool,
) -> Result<bool, ChainError> {
    match state {
        Some(state) if state.tokens_final < before_tokens_final => Err(ChainError::Chain(format!(
            "TC {token_contract}: tokensFinal regressed from {before_tokens_final} to {} after finalize",
            state.tokens_final
        ))),
        Some(state) if state.is_stopped() => Ok(true),
        Some(state) if state.disputed => Err(ChainError::Chain(format!(
            "TC {token_contract}: deal became disputed while reconciling finalize"
        ))),
        Some(state) => Ok(state.tokens_final > before_tokens_final),
        None if !token_contract_active => Ok(true),
        None => Err(ChainError::Chain(format!(
            "TC {token_contract}: getState() returned no data after finalize while the \
             TokenContract is still active"
        ))),
    }
}

/// Promote the due claim slot(s) permissionlessly and confirm at least one promotion landed.
/// `TokenContract` 4.0.31 judges the older and newest slots independently. The older slot may become
/// final while the newer slot is still inside its own window, so confirmation must observe a strict
/// `tokensFinal` increase from the pre-state -- never equality with the full `tokensPending` value.
async fn submit_finalize_confirmed(
    chain: &RealChainBackend,
    tc: &Address,
    token_contract: &TokenContract,
    before: DealChainState,
) -> Result<(), ChainError> {
    let submit_error = match chain.finalize_claims(tc).await.map_err(map_err) {
        Ok(_) => None,
        Err(error @ (ChainError::Transport(_) | ChainError::AmbiguousSubmit(_))) => Some(error),
        Err(error) => return Err(error),
    };
    let confirmation = ClaimConfirmationParams::canonical();
    let mut last_tokens_final = before.tokens_final;
    for attempt in 0..confirmation.max_reads {
        let state = chain.token_contract_deal_state(tc).await.map_err(map_err)?;
        let active = if state.is_none() {
            chain.account_active_code_hash(tc).await.map_err(map_err)?.0
        } else {
            true
        };
        if finalize_post_confirmed(token_contract, before.tokens_final, state, active)? {
            return Ok(());
        }
        last_tokens_final = state.map_or(last_tokens_final, |state| state.tokens_final);
        if attempt + 1 < confirmation.max_reads {
            tokio::time::sleep(confirmation.poll_interval).await;
        }
    }
    let lost_response = submit_error
        .map(|error| format!(" after ambiguous submit ({error})"))
        .unwrap_or_default();
    Err(ChainError::Chain(format!(
        "TC {token_contract}: finalize did not advance tokensFinal past {}{lost_response}; \
         authoritative tokensFinal remained at {last_tokens_final}",
        before.tokens_final
    )))
}

#[cfg(test)]
mod finalize_confirmation_tests {
    use super::*;
    use crate::params::TICK_SIZE;

    fn state(tokens_final: u128, tokens_superseded: u128, tokens_pending: u128) -> DealChainState {
        DealChainState {
            funded: true,
            opened: true,
            probe_accepted: true,
            disputed: false,
            deposit: 1,
            finalized_owed: 0,
            tokens_final,
            tokens_superseded,
            tokens_pending,
            probe_tick: 0,
            funded_time: Some(1),
            probe_time: 1,
            prev_claim_time: 2,
            last_claim_time: 3,
            dispute_time: 0,
        }
    }

    #[test]
    fn older_slot_promotion_is_confirmed_without_waiting_for_full_pending() {
        let token_contract = "0:tc".to_string();
        let before = state(TICK_SIZE, 2 * TICK_SIZE, 3 * TICK_SIZE);
        let after = state(2 * TICK_SIZE, 3 * TICK_SIZE, 3 * TICK_SIZE);

        assert!(
            after.tokens_final < after.tokens_pending,
            "fixture must retain the newest slot inside its own window"
        );
        assert!(
            finalize_post_confirmed(&token_contract, before.tokens_final, Some(after), true)
                .expect("strict partial promotion")
        );
    }

    #[test]
    fn finalize_confirmation_rejects_no_transition_and_regression() {
        let token_contract = "0:tc".to_string();
        let before = state(TICK_SIZE, 2 * TICK_SIZE, 3 * TICK_SIZE);

        assert!(
            !finalize_post_confirmed(&token_contract, before.tokens_final, Some(before), true)
                .expect("unchanged state is not confirmation")
        );

        let regressed = state(0, 2 * TICK_SIZE, 3 * TICK_SIZE);
        let error =
            finalize_post_confirmed(&token_contract, before.tokens_final, Some(regressed), true)
                .expect_err("regression must fail closed");
        assert!(error.to_string().contains("regressed"), "{error}");
    }

    #[test]
    fn finalize_confirmation_accepts_only_proven_terminal_absence_or_stop() {
        let token_contract = "0:tc".to_string();
        let before = state(TICK_SIZE, 2 * TICK_SIZE, 3 * TICK_SIZE);

        let active_error =
            finalize_post_confirmed(&token_contract, before.tokens_final, None, true)
                .expect_err("missing active getter must fail closed");
        assert!(active_error.to_string().contains("still active"));
        assert!(
            finalize_post_confirmed(&token_contract, before.tokens_final, None, false)
                .expect("inactive account proves a terminal race")
        );

        let mut stopped = before;
        stopped.opened = false;
        stopped.deposit = 0;
        assert!(
            finalize_post_confirmed(&token_contract, before.tokens_final, Some(stopped), true)
                .expect("strict stopped state proves a terminal race")
        );
    }
}

async fn wait_tc_bool(
    chain: &RealChainBackend,
    tc: &Address,
    key: &str,
    want: bool,
) -> Result<(), ChainError> {
    for _ in 0..crate::params::TC_BOOL_CONFIRM_MAX_READS {
        if let Some(st) = chain.token_contract_deal_state(tc).await.map_err(map_err)? {
            let actual = match key {
                "funded" => st.funded,
                "opened" => st.opened,
                "probeAccepted" => st.probe_accepted,
                "disputed" => st.disputed,
                _ => {
                    return Err(ChainError::Chain(format!(
                        "TC {tc}: unsupported typed getState bool field {key}"
                    )));
                }
            };
            if actual == want {
                return Ok(());
            }
        }
        tokio::time::sleep(crate::params::TC_BOOL_CONFIRM_POLL_INTERVAL).await;
    }
    Err(ChainError::Chain(format!(
        "TC {tc}: field {key} != {want} within the allotted time"
    )))
}

fn checked_shell(parts: &[u128], field: &str) -> Result<Shell, ChainError> {
    let total = parts.iter().try_fold(0u128, |sum, part| {
        sum.checked_add(*part).ok_or_else(|| {
            ChainError::Chain(format!("TokenContract {field} exceeds uint128 range"))
        })
    })?;
    total.try_into().map_err(|_| {
        ChainError::Chain(format!(
            "TokenContract {field} {total} exceeds CLI Shell range"
        ))
    })
}

fn snapshot_total(parts: &[u128]) -> Option<u128> {
    parts
        .iter()
        .try_fold(0u128, |sum, part| sum.checked_add(*part))
}

fn token_value_floor(tokens: u128, price_per_tick: u128, tick_size: u128) -> Option<u128> {
    if tick_size == 0 {
        return None;
    }
    let whole_ticks = tokens / tick_size;
    let remainder = tokens % tick_size;
    whole_ticks
        .checked_mul(price_per_tick)?
        .checked_add(remainder.checked_mul(price_per_tick)? / tick_size)
}

/// A snapshot of the locks/burned amounts for a TC -- the same reads as in `RealDealBackend::snapshot`.
async fn real_tc_snapshot(
    chain: &RealChainBackend,
    token_contract: &TokenContract,
) -> Option<StreamSnapshot> {
    let tc = Address::parse(token_contract).ok()?;
    let snapshot = chain.token_contract_deal_snapshot(&tc).await.ok()??;
    let state = snapshot.state;
    let (tick_size, price_per_tick, _) = chain.token_contract_deal_terms(&tc).await.ok()??;
    let pending_exposure = token_value_floor(state.contested_tokens(), price_per_tick, tick_size)?;
    Some(StreamSnapshot {
        seller_locked: snapshot.seller_bond.bond_held,
        buyer_locked: snapshot.buyer_locked().ok()?,
        buyer_lead: snapshot_total(&[state.probe_tick, pending_exposure])?,
        tokens_final: state.tokens_final,
        seller_received: state.finalized_owed,
        buyer_refunded: 0,
        burned: 0,
        closed: state.is_stopped(),
    })
}

fn exact_buyer_stop_settlement(
    receipts: TokenContractSettlementReceipts,
) -> Result<Option<(u128, u128)>, ChainError> {
    let mut found = None;
    for receipt in receipts.events {
        let (to_seller, refund_to_buyer) = match receipt.event {
            TokenContractSettlementEvent::StreamStopped {
                to_seller,
                refund_to_buyer,
                ..
            } => (to_seller, refund_to_buyer),
            // ProbeBurned is also emitted by dispute-timeout resolution, so the
            // event alone does not prove a buyer-owned STOP.
            TokenContractSettlementEvent::ProbeAccepted { .. }
            | TokenContractSettlementEvent::ProbeBurned { .. }
            | TokenContractSettlementEvent::StreamDisputed { .. }
            | TokenContractSettlementEvent::DisputeResolved { .. }
            | TokenContractSettlementEvent::TickFinalized { .. }
            | TokenContractSettlementEvent::TicksClaimed { .. } => continue,
        };
        if found.is_some() {
            return Err(ChainError::Chain(
                "TokenContract emitted more than one buyer STOP terminal event".to_string(),
            ));
        }
        found = Some((to_seller, refund_to_buyer));
    }
    Ok(found)
}

/// Read one market's deal into a monitor [`DealView`] from the **authoritative on-chain getters** (issue,
/// real-chain reader). The operator's [`crate::MarketManifest`] supplies only the `TokenContract` ADDRESS to
/// read + the `model_hash` to integrity-check against; every accounting field comes from the CHAIN -- model from
/// `getModelName`, price from `getDeal().pricePerTick`, by-fact from `getState`/`getSellerBond`, counterparty from
/// `getBuyerPubkey`. The manifest is operator-supplied and is NOT trusted as chain truth: this **fails loud**
/// rather than rendering a stale/hand-edited manifest or hiding a broken/undeployed TC as empty data. Errors on:
/// a `token_contract` that does not parse; an undeployed/inactive TC(no `getState`); unreadable
/// `getModelName`/`getDeal`; or an on-chain `getModelHash` that does NOT match the manifest's `model_hash` (the
/// manifest points at a TC for a different model). The operator is the SELLER of their own market, so
/// `role = Seller`. The view feeds `print_tree_snapshot` + `deal_anomalies` like the mock path. (Refund/burn are
/// not live-readable -- `real_tc_snapshot` leaves them `0`.) The caller adds the `--market <path>` context.
pub async fn real_market_deal_view(
    chain: &RealChainBackend,
    manifest: &crate::MarketManifest,
) -> Result<DealView> {
    let tc = manifest.token_contract.as_str();
    let addr =
        Address::parse(tc).map_err(|e| anyhow!("token_contract {tc}: invalid address: {e}"))?;
    // Fail loud: an undeployed / inactive TC is NOT a valid accounting row -- never render it as empty data.
    let snapshot = real_tc_snapshot(chain, &manifest.token_contract)
        .await
        .ok_or_else(|| {
            anyhow!("TokenContract {tc} is not readable (undeployed/inactive/getState failed)")
        })?;
    // Model: authoritative on-chain getModelName(NOT the manifest's frame_model).
    let model = chain
        .token_contract_model_name(&addr)
        .await?
        .ok_or_else(|| anyhow!("TokenContract {tc}: getModelName empty/unreadable"))?;
    // Integrity: the on-chain modelHash MUST match the manifest's -- else the manifest points at the wrong TC.
    let on_chain_hash = chain
        .token_contract_model_hash(&addr)
        .await?
        .ok_or_else(|| anyhow!("TokenContract {tc}: getModelHash empty/unreadable"))?;
    if on_chain_hash != manifest.model_hash {
        return Err(anyhow!(
            "TokenContract {tc}: on-chain modelHash {on_chain_hash} != manifest model_hash {} \
             (the manifest points at a TC for a different model)",
            manifest.model_hash
        ));
    }
    // Price: authoritative on-chain getDeal().pricePerTick(NOT the manifest's).
    let price = chain
        .token_contract_price_per_tick(&addr)
        .await?
        .ok_or_else(|| anyhow!("TokenContract {tc}: getDeal/pricePerTick unreadable"))?;
    // Counterparty: the matched buyer's anonymous pubkey(none before a match).
    let counterparty = chain
        .token_contract_buyer_pubkey(&addr)
        .await?
        .map(|pk| pk.iter().map(|b| format!("{b:02x}")).collect::<String>());
    Ok(DealView {
        token_contract: manifest.token_contract.clone(),
        role: DealRole::Seller,
        counterparty,
        // SHELL price fits u64 for any real market; saturate rather than silently wrap a bogus huge value.
        price_per_tick: price.min(Shell::MAX as u128) as Shell,
        model: Some(model),
        snapshot: Some(snapshot),
    })
}

/// The STOP outcome from the TC state BEFORE the call: on the probe -- `BurnBoth`, otherwise `AmicableSplit`.
/// Project the outcome of a buyer STOP from the pre-call state.
/// After probe acceptance a STOP settles BY FACT: the seller keeps the consumption he had
/// promoted, and the rest of the escrow returns. Before acceptance, the probe and its seller-bond
/// mirror burn while the remaining escrow and held buyer bond return.
/// The figures are a PROJECTION, not the settled amounts, and deliberately bound the buyer's expectation
/// from the optimistic side: on-chain `stop()` first runs `_promoteDue()`, which may promote a pending claim
/// whose window has just elapsed, and on a subscription `_chargeCurrentWeek()` bills the week in progress in
/// full(take-or-pay). Both move value from the refund to the seller. Reproducing that arithmetic here would
/// duplicate contract logic that has already drifted once. The sole R20-12 arithmetic is the
/// checked addition of the authoritative held buyer bond to the clean STOP refund; R20-10 owns the
/// authoritative terminal receipt.
#[cfg(test)]
fn settle_stop(snapshot: &DealChainSnapshot) -> Result<Settlement, ChainError> {
    if !snapshot.state.opened {
        return Err(ChainError::Chain(
            "TokenContract is not OPEN; refusing repeated STOP before money moves".to_string(),
        ));
    }
    snapshot
        .validate_cross_getter_invariants()
        .map_err(|reason| {
            ChainError::Chain(format!(
                "TokenContract STOP snapshot violates coherent accounting invariants: {reason}; \
                 refusing STOP before money moves"
            ))
        })?;
    let buyer_refund = snapshot
        .state
        .deposit
        .checked_add(snapshot.buyer_bond.bond_held)
        .ok_or_else(|| {
            ChainError::Chain(
                "TokenContract STOP projection overflows uint128 while adding held buyer bond; \
                 refusing STOP before money moves"
                    .to_string(),
            )
        })?;
    if !snapshot.state.probe_accepted {
        // Walking away from the TRIAL tick: it burns with a mirror tick of the bond. No week is
        // charged and no fee is taken on a tick nobody was paid for, so the rest of the escrow returns.
        let probe = Shell::try_from(snapshot.state.probe_tick).map_err(|_| {
            ChainError::Chain(format!(
                "probe STOP probe tick {} exceeds the client settlement range",
                snapshot.state.probe_tick
            ))
        })?;
        let bond = Shell::try_from(snapshot.seller_bond.bond_held).map_err(|_| {
            ChainError::Chain(format!(
                "probe STOP seller bond {} exceeds the client settlement range",
                snapshot.seller_bond.bond_held
            ))
        })?;
        let mut outcome = crate::settle::probe_burn(probe, bond);
        outcome.buyer_refund = buyer_refund;
        return Ok(Settlement::BurnBoth(outcome));
    }
    Ok(Settlement::AmicableSplit {
        to_seller_ticks: u64::try_from(snapshot.state.tokens_final / crate::params::TICK_SIZE)
            .unwrap_or(u64::MAX),
        to_buyer_refund: buyer_refund,
    })
}

#[derive(Debug, Clone, Default)]
enum ExplicitStopSlotState {
    #[default]
    Idle,
    Pending {
        submit_error: String,
    },
    Terminal(Settlement),
}

type ExplicitStopSlot = std::sync::Arc<tokio::sync::Mutex<ExplicitStopSlotState>>;

fn explicit_stop_slot(token_contract: &str) -> Result<ExplicitStopSlot, ChainError> {
    static SLOTS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, ExplicitStopSlot>>,
    > = std::sync::OnceLock::new();
    let slots = SLOTS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut slots = slots.lock().map_err(|_| {
        ChainError::Chain("explicit STOP serialization registry lock poisoned".to_string())
    })?;
    Ok(slots
        .entry(token_contract.trim().to_ascii_lowercase())
        .or_insert_with(|| {
            std::sync::Arc::new(tokio::sync::Mutex::new(ExplicitStopSlotState::Idle))
        })
        .clone())
}

fn pending_explicit_stop_error(token_contract: &str, submit_error: &str) -> ChainError {
    ChainError::AmbiguousSubmit(format!(
        "{submit_error}; exactly one explicit STOP POST was attempted for TokenContract \
         {token_contract}; no authoritative settlement receipt was observed, so every later caller \
         remains latched and the signed STOP BOC is not resubmitted"
    ))
}

async fn explicit_buyer_stop_with<BeforeSubmit, BeforeSubmitFuture>(
    chain: &RealChainBackend,
    buyer_note: &Address,
    buyer_keys: &KeyPair,
    tc: &Address,
    before_submit: BeforeSubmit,
) -> Result<Settlement, ChainError>
where
    BeforeSubmit: FnOnce() -> BeforeSubmitFuture,
    BeforeSubmitFuture: std::future::Future<Output = Result<(), ChainError>>,
{
    let token_contract = tc.with_workchain();
    let slot = explicit_stop_slot(&token_contract)?;
    let mut slot = slot.lock().await;

    match slot.clone() {
        ExplicitStopSlotState::Terminal(settlement) => return Ok(settlement),
        ExplicitStopSlotState::Pending { submit_error } => {
            return Err(pending_explicit_stop_error(&token_contract, &submit_error));
        }
        ExplicitStopSlotState::Idle => {}
    }

    before_submit().await?;
    let receipt = match chain
        .stream_stop(buyer_note, buyer_keys, tc)
        .await
        .map_err(map_err)
    {
        Ok(receipt) => receipt,
        Err(ChainError::AmbiguousSubmit(error)) => {
            *slot = ExplicitStopSlotState::Pending {
                submit_error: error.clone(),
            };
            return Err(pending_explicit_stop_error(&token_contract, &error));
        }
        Err(error) => return Err(error),
    };
    let settlement = Settlement::AuthoritativeReceipt(Box::new(receipt));
    *slot = ExplicitStopSlotState::Terminal(settlement.clone());
    Ok(settlement)
}

impl RealChainBackend {
    /// Unconditional explicit buyer STOP shared by API, close and recover surfaces.
    /// The signed BOC is posted once under a process-wide TokenContract slot. Accepted or ambiguous
    /// outcomes are resolved only through fresh coherent reads; a pending slot never submits again.
    pub async fn explicit_buyer_stop(
        &self,
        buyer_note: &Address,
        buyer_keys: &KeyPair,
        tc: &Address,
    ) -> Result<Settlement, ChainError> {
        explicit_buyer_stop_with(self, buyer_note, buyer_keys, tc, || async { Ok(()) }).await
    }
}

#[cfg(test)]
mod stop_settlement_tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn only_exact_stream_stopped_is_a_buyer_stop_settlement() {
        let buyer = "0:buyer".to_string();
        let classify = |event| {
            exact_buyer_stop_settlement(TokenContractSettlementReceipts {
                events: vec![TokenContractSettlementReceipt {
                    message_id: "receipt".to_string(),
                    created_at: 7,
                    cursor: "cursor".to_string(),
                    event,
                }],
            })
            .unwrap()
        };
        assert_eq!(
            classify(TokenContractSettlementEvent::ProbeBurned {
                buyer: buyer.clone(),
                burned_probe: 1,
                burned_bond: 1,
                refund_to_buyer: 2,
            }),
            None,
            "ProbeBurned also represents dispute-timeout, not authoritative buyer STOP"
        );
        let stopped = classify(TokenContractSettlementEvent::StreamStopped {
            buyer: buyer.clone(),
            to_seller: 3,
            refund_to_buyer: 4,
        })
        .unwrap();
        assert_eq!(stopped, (3, 4));
    }

    fn valid_stop_state() -> Value {
        json!({
            "funded": true,
            "opened": true,
            "probeAccepted": true,
            "disputed": false,
            "deposit": "3000000000",
            "probeTick": "0",
            "finalizedOwed": "2000000000",
            "tokensFinal": "2000000",
            "tokensSuperseded": "2000000",
            "tokensPending": "3000000",
            "probeTime": "1",
            "prevClaimTime": "2",
            "lastClaimTime": "3",
            "disputeTime": "0",
            "fundedTime": "1"
        })
    }

    fn valid_stop_bond() -> Value {
        json!({
            "bondFunded": true,
            "bondHeld": "2000000000",
            "bondRequired": "2000000000"
        })
    }

    fn stop_snapshot(
        state: TcSettleState,
        is_subscription: bool,
        buyer_bond_held: u128,
        buyer_bond_required: u128,
    ) -> DealChainSnapshot {
        let sub_weeks = if is_subscription {
            SUBSCRIPTION_WEEKS
        } else {
            0
        };
        DealChainSnapshot {
            account_code_hash: "code".to_string(),
            account_boc_hash: "boc".to_string(),
            state: DealChainState {
                funded: true,
                opened: state.opened,
                probe_accepted: state.probe_accepted,
                disputed: false,
                deposit: state.deposit,
                finalized_owed: 0,
                tokens_final: state.tokens_final,
                tokens_superseded: state.tokens_final,
                tokens_pending: state.tokens_pending,
                probe_tick: state.probe_tick,
                funded_time: Some(1),
                probe_time: 1,
                prev_claim_time: 2,
                last_claim_time: 3,
                dispute_time: 0,
            },
            subscription: DealSubscription {
                deal_flags: if is_subscription {
                    crate::chain::flags::SUBSCRIPTION
                } else {
                    0
                },
                sub_weeks,
                week_index: 0,
                tokens_per_week: if is_subscription {
                    crate::params::TICK_SIZE
                } else {
                    2 * crate::params::TICK_SIZE
                },
                funded_tokens: if is_subscription {
                    4 * crate::params::TICK_SIZE
                } else {
                    2 * crate::params::TICK_SIZE
                },
                tokens_paid: 0,
                period_start: 1,
                week_base_tokens: 0,
            },
            seller_bond: DealSellerBond {
                bond_funded: true,
                bond_held: state.seller_bond,
                bond_required: state.seller_bond,
            },
            buyer_bond: crate::chain::DealBuyerBond {
                bond_held: buyer_bond_held,
                bond_required: buyer_bond_required,
            },
        }
    }

    #[test]
    fn stop_getters_accept_complete_strict_shape() {
        assert_eq!(
            tc_stop_settle_state_from_json("0:tc", &valid_stop_state(), Some(&valid_stop_bond()))
                .unwrap(),
            TcSettleState {
                opened: true,
                probe_accepted: true,
                probe_tick: 0,
                tokens_final: 2_000_000,
                tokens_pending: 3_000_000,
                deposit: 3_000_000_000,
                seller_bond: 2_000_000_000,
            }
        );
    }

    /// Every field a settlement depends on must be present and well-formed, or the client refuses to send.
    /// A malformed read must never be silently defaulted to zero: that would understate what the seller is
    /// owed and move real money on a guess.
    #[test]
    fn stop_getters_fail_closed_on_missing_wrong_type_or_malformed_required_fields() {
        for field in ["tokensFinal", "tokensPending", "deposit", "probeTick"] {
            for (label, replacement) in [
                ("missing", None),
                ("wrong-type", Some(json!(1))),
                ("malformed", Some(json!("bad"))),
            ] {
                let mut state = valid_stop_state();
                match replacement {
                    Some(value) => state[field] = value,
                    None => {
                        state.as_object_mut().unwrap().remove(field);
                    }
                }
                let error =
                    tc_stop_settle_state_from_json("0:tc", &state, Some(&valid_stop_bond()))
                        .expect_err(label);
                let reason = error.to_string();
                assert!(reason.contains(field), "{label} {field}: {reason}");
                assert!(
                    reason.contains("refusing STOP before money moves"),
                    "{label} {field}: {reason}"
                );
            }
        }

        // `opened` is a bool and is equally required.
        let mut state = valid_stop_state();
        state.as_object_mut().unwrap().remove("opened");
        let error = tc_stop_settle_state_from_json("0:tc", &state, Some(&valid_stop_bond()))
            .expect_err("missing opened");
        assert!(error.to_string().contains("opened"));

        for (label, replacement) in [
            ("missing", None),
            ("wrong-type", Some(json!(2))),
            ("malformed", Some(json!("bad"))),
        ] {
            let mut bond = valid_stop_bond();
            match replacement {
                Some(value) => bond["bondHeld"] = value,
                None => {
                    bond.as_object_mut().unwrap().remove("bondHeld");
                }
            }
            let error = tc_stop_settle_state_from_json("0:tc", &valid_stop_state(), Some(&bond))
                .expect_err(label);
            let reason = error.to_string();
            assert!(reason.contains("bondHeld"), "{label}: {reason}");
            assert!(reason.contains("refusing STOP before money moves"));
        }

        let error = tc_stop_settle_state_from_json("0:tc", &valid_stop_state(), None)
            .expect_err("missing getSellerBond response");
        assert!(error
            .to_string()
            .contains("getSellerBond() returned no data"));
    }

    /// The claim pipeline cannot run backwards. A read where the newest claim is BELOW the promoted total is
    /// incoherent, and settling on it would credit or refund an amount neither side agreed to.
    #[test]
    fn stop_getters_reject_a_pipeline_that_runs_backwards() {
        let mut state = valid_stop_state();
        state["tokensPending"] = json!("1000000"); // below tokensFinal
        let error = tc_stop_settle_state_from_json("0:tc", &state, Some(&valid_stop_bond()))
            .expect_err("inverted pipeline");
        let reason = error.to_string();
        assert!(reason.contains("not monotonic"), "{reason}");
        assert!(reason.contains("before money moves"), "{reason}");
    }

    /// A STOP settles BY FACT: the promoted consumption is credited and the rest of the escrow returns.
    /// There is no probe and therefore no burn on this path at all.
    #[test]
    fn stop_settles_by_fact_and_never_burns() {
        let state =
            tc_stop_settle_state_from_json("0:tc", &valid_stop_state(), Some(&valid_stop_bond()))
                .unwrap();
        let snapshot = stop_snapshot(state, false, 0, 0);
        assert_eq!(
            settle_stop(&snapshot).unwrap(),
            Settlement::AmicableSplit {
                to_seller_ticks: 2,
                to_buyer_refund: 3_000_000_000,
            },
            "two promoted ticks are paid; the contested third is not"
        );
    }

    /// An exhausted deal(nothing claimed, nothing left) is still a valid STOP: it simply moves nothing.
    #[test]
    fn stop_on_an_empty_deal_moves_nothing() {
        let mut raw = valid_stop_state();
        raw["tokensFinal"] = json!("0");
        raw["tokensSuperseded"] = json!("0");
        raw["tokensPending"] = json!("0");
        raw["deposit"] = json!("0");
        let state = tc_stop_settle_state_from_json("0:tc", &raw, Some(&valid_stop_bond())).unwrap();
        let snapshot = stop_snapshot(state, false, 0, 0);
        assert_eq!(
            settle_stop(&snapshot).unwrap(),
            Settlement::AmicableSplit {
                to_seller_ticks: 0,
                to_buyer_refund: 0,
            }
        );
    }

    /// A repeated STOP on a closed deal must be refused before it costs gas.
    #[test]
    fn stop_on_a_closed_deal_is_refused() {
        let mut raw = valid_stop_state();
        raw["opened"] = json!(false);
        let state = tc_stop_settle_state_from_json("0:tc", &raw, Some(&valid_stop_bond())).unwrap();
        let snapshot = stop_snapshot(state, false, 0, 0);
        let error = settle_stop(&snapshot).expect_err("closed deal");
        assert!(error.to_string().contains("not OPEN"));
    }

    /// The contested tail is exactly what a dispute puts at stake, and it never reads negative.
    #[test]
    fn contested_tail_is_the_unpromoted_remainder() {
        let state =
            tc_stop_settle_state_from_json("0:tc", &valid_stop_state(), Some(&valid_stop_bond()))
                .unwrap();
        assert_eq!(state.contested_tokens(), 1_000_000, "one tick contested");
        assert_eq!(state.trusted_ticks(), 2);
    }

    #[test]
    fn clean_stop_refunds_held_buyer_bond_pre_and_post_probe_only_for_subscriptions() {
        for probe_accepted in [false, true] {
            for (shape, is_subscription, held, required, expected_refund) in [
                ("ordinary", false, 0, 0, 3_000_000_000),
                (
                    "subscription",
                    true,
                    2_000_000_000,
                    2_000_000_000,
                    5_000_000_000,
                ),
            ] {
                let state = TcSettleState {
                    opened: true,
                    probe_accepted,
                    probe_tick: if probe_accepted { 0 } else { 1_000_000_000 },
                    tokens_final: 2 * crate::params::TICK_SIZE,
                    tokens_pending: 3 * crate::params::TICK_SIZE,
                    deposit: 3_000_000_000,
                    seller_bond: 2_000_000_000,
                };
                let snapshot = stop_snapshot(state, is_subscription, held, required);
                let settlement = settle_stop(&snapshot).unwrap();
                let refund = match settlement {
                    Settlement::BurnBoth(outcome) => {
                        assert!(!probe_accepted, "{shape} post-probe STOP must not burn");
                        outcome.buyer_refund
                    }
                    Settlement::AmicableSplit {
                        to_buyer_refund, ..
                    } => {
                        assert!(probe_accepted, "{shape} pre-probe STOP must burn");
                        to_buyer_refund
                    }
                    other => panic!("{shape} unexpected STOP projection: {other:?}"),
                };
                assert_eq!(
                    refund, expected_refund,
                    "{shape} probeAccepted={probe_accepted}"
                );
            }
        }
    }

    #[test]
    fn stop_rejects_invalid_buyer_bond_shapes_and_refund_overflow() {
        let state = TcSettleState {
            opened: true,
            probe_accepted: true,
            probe_tick: 0,
            tokens_final: 0,
            tokens_pending: 0,
            deposit: 1,
            seller_bond: 1,
        };
        for (label, snapshot, expected) in [
            (
                "held above required",
                stop_snapshot(state, true, 2, 1),
                "exceeds bondRequired",
            ),
            (
                "subscription buyer bond does not match seller requirement",
                stop_snapshot(state, true, 0, 0),
                "seller/buyer bondRequired mismatch",
            ),
            (
                "ordinary with a bond",
                stop_snapshot(state, false, 1, 1),
                "ordinary-deal shape",
            ),
        ] {
            let reason = settle_stop(&snapshot).expect_err(label).to_string();
            assert!(reason.contains(expected), "{label}: {reason}");
            assert!(
                reason.contains("refusing STOP before money moves"),
                "{label}: {reason}"
            );
        }

        let overflow = stop_snapshot(
            TcSettleState {
                deposit: u128::MAX,
                ..state
            },
            true,
            1,
            1,
        );
        let reason = settle_stop(&overflow)
            .expect_err("buyer refund overflow")
            .to_string();
        assert!(reason.contains("overflows uint128"), "{reason}");
    }

    #[test]
    fn live_snapshot_includes_held_buyer_bond_and_terminal_snapshot_clears_it() {
        let live = stop_snapshot(
            TcSettleState {
                opened: true,
                probe_accepted: true,
                probe_tick: 0,
                tokens_final: 0,
                tokens_pending: 0,
                deposit: 3_000_000_000,
                seller_bond: 2_000_000_000,
            },
            true,
            2_000_000_000,
            2_000_000_000,
        );
        assert_eq!(live.buyer_locked().unwrap(), 5_000_000_000);
        assert!(matches!(
            settle_stop(&live).unwrap(),
            Settlement::AmicableSplit {
                to_buyer_refund: 5_000_000_000,
                ..
            }
        ));

        let terminal = stop_snapshot(
            TcSettleState {
                opened: false,
                probe_accepted: true,
                probe_tick: 0,
                tokens_final: 0,
                tokens_pending: 0,
                deposit: 0,
                seller_bond: 0,
            },
            true,
            0,
            2_000_000_000,
        );
        assert_eq!(terminal.buyer_locked().unwrap(), 0);
    }

    #[test]
    fn settlement_reader_uses_only_the_coherent_deal_snapshot() {
        let source = include_str!("backends.rs");
        let start = source
            .find("async fn tc_settle_state(")
            .expect("strict settlement reader");
        let end = source[start..]
            .find("fn reqwest_error_is_transport(")
            .map(|offset| start + offset)
            .expect("function after strict STOP reader");
        let body = &source[start..end];

        assert_eq!(body.matches(".token_contract_deal_snapshot(").count(), 1);
        for forbidden in [
            ".token_contract_state(",
            ".token_contract_seller_bond(",
            ".token_contract_buyer_bond(",
        ] {
            assert!(
                !body.contains(forbidden),
                "STOP reader must not sample {forbidden} independently"
            );
        }
    }

    #[tokio::test]
    async fn independently_constructed_callers_share_one_tc_serialization_slot() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let first = explicit_stop_slot("0:ABCDEF").unwrap();
        let second = explicit_stop_slot(" 0:abcdef ").unwrap();
        assert!(
            Arc::ptr_eq(&first, &second),
            "normalized TokenContract identity must select one shared slot"
        );

        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let run = |slot: ExplicitStopSlot| {
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            tokio::spawn(async move {
                let _slot = slot.lock().await;
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                active.fetch_sub(1, Ordering::SeqCst);
            })
        };
        let one = run(first);
        let two = run(second);
        one.await.unwrap();
        two.await.unwrap();
        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "independent callers for one TC must never overlap explicit STOP work"
        );
    }

    #[test]
    fn pending_ambiguous_stop_remains_ambiguous_and_forbids_resubmit() {
        let error = pending_explicit_stop_error("0:pending", "HTTP 503 outcome ambiguous");
        let ChainError::AmbiguousSubmit(message) = error else {
            panic!("pending ambiguous STOP must retain ambiguous classification");
        };
        assert!(message.contains("exactly one explicit STOP POST"));
        assert!(message.contains("no authoritative settlement receipt was observed"));

        let source = include_str!("backends.rs");
        let start = source
            .find("async fn explicit_buyer_stop_with<")
            .expect("shared explicit STOP implementation");
        let end = source[start..]
            .find("impl RealChainBackend {")
            .map(|offset| start + offset)
            .expect("end of shared explicit STOP implementation");
        let shared = &source[start..end];
        let pending = shared
            .find("ExplicitStopSlotState::Pending {")
            .expect("pending explicit STOP branch");
        let idle = shared[pending..]
            .find("ExplicitStopSlotState::Idle")
            .map(|offset| pending + offset)
            .expect("idle explicit STOP branch");
        let pending_body = &shared[pending..idle];
        assert!(
            !pending_body.contains(".stream_stop("),
            "a caller that observes an ambiguous pending STOP must not resubmit"
        );
    }

    proptest! {
        /// However the pipeline stands, a STOP credits ONLY promoted consumption. The contested tail is never
        /// converted into seller revenue by this path -- that is the property which makes an inflated final
        /// claim worthless, and it must hold for every reachable state.
        #[test]
        fn stop_never_pays_for_the_contested_tail(
            trusted_ticks in 0u128..1_000,
            contested_ticks in 0u128..1_000,
            deposit in 0u128..u64::MAX as u128,
            buyer_bond in 1u128..u64::MAX as u128,
        ) {
            let state = TcSettleState {
                opened: true,
                probe_accepted: true,
                probe_tick: 0,
                tokens_final: trusted_ticks * crate::params::TICK_SIZE,
                tokens_pending: (trusted_ticks + contested_ticks) * crate::params::TICK_SIZE,
                deposit,
                seller_bond: buyer_bond,
            };
            let snapshot = stop_snapshot(state, true, buyer_bond, buyer_bond);
            match settle_stop(&snapshot).unwrap() {
                Settlement::AmicableSplit { to_seller_ticks, to_buyer_refund } => {
                    prop_assert_eq!(
                        u128::from(to_seller_ticks), trusted_ticks,
                        "only promoted ticks are credited"
                    );
                    prop_assert_eq!(to_buyer_refund, deposit + buyer_bond);
                }
                other => prop_assert!(false, "a STOP must settle by fact, got {:?}", other),
            }
        }

        /// A strict read either yields a coherent state or an error -- it must never panic or silently
        /// invent values, whatever the getter returns.
        #[test]
        fn strict_read_is_total_over_arbitrary_numeric_strings(
            final_raw in "[0-9]{1,20}",
            pending_raw in "[0-9]{1,20}",
            deposit_raw in "[0-9]{1,20}",
        ) {
            let raw = json!({
                "funded": true,
                "opened": true,
                "probeAccepted": true,
                "disputed": false,
                "deposit": deposit_raw,
                "probeTick": "0",
                "finalizedOwed": "0",
                "tokensFinal": final_raw,
                "tokensSuperseded": pending_raw.clone(),
                "tokensPending": pending_raw,
                "probeTime": "1",
                "prevClaimTime": "2",
                "lastClaimTime": "3",
                "disputeTime": "0",
                "fundedTime": "1"
            });
            match tc_stop_settle_state_from_json("0:tc", &raw, Some(&valid_stop_bond())) {
                Ok(state) => {
                    prop_assert!(
                        state.tokens_pending >= state.tokens_final,
                        "an accepted read is always a coherent pipeline"
                    );
                }
                Err(error) => {
                    let reason = error.to_string();
                    prop_assert!(
                        reason.contains("before money moves") || reason.contains("malformed"),
                        "a rejection must say why: {reason}"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod checked_shell_tests {
    use super::*;

    #[test]
    fn checked_shell_rejects_conversion_and_addition_overflow() {
        assert_eq!(
            checked_shell(&[Shell::MAX as u128], "test").unwrap(),
            Shell::MAX
        );
        assert!(checked_shell(&[Shell::MAX as u128 + 1], "test").is_err());
        assert!(checked_shell(&[u128::MAX, 1], "test").is_err());
    }

    #[test]
    fn snapshot_total_preserves_uint128_and_rejects_addition_overflow() {
        let above_shell = Shell::MAX as u128 + 1;
        assert_eq!(snapshot_total(&[above_shell]), Some(above_shell));
        assert_eq!(snapshot_total(&[u128::MAX, 1]), None);
    }
}

/// A "wrong role" error: a counterparty's method was called on a per-role backend.
fn wrong_role(method: &str, want: &str) -> ChainError {
    ChainError::Chain(format!(
        "{method}: a `{want}` role action on a backend of a different role -- run `dexdo {want}`"
    ))
}

fn cleanup_unopened_confirmed(state: Option<DealChainState>) -> bool {
    state.is_none_or(|state| !state.funded)
}

async fn wait_cleanup_unopened_with<Read, ReadFuture, Pause, PauseFuture>(
    tc: &str,
    mut read: Read,
    mut pause: Pause,
) -> Result<(), ChainError>
where
    Read: FnMut() -> ReadFuture,
    ReadFuture: std::future::Future<Output = Result<Option<DealChainState>, ChainError>>,
    Pause: FnMut() -> PauseFuture,
    PauseFuture: std::future::Future<Output = ()>,
{
    for _ in 0..crate::params::CLEANUP_UNOPENED_CONFIRM_MAX_READS {
        let state = read().await?;
        if cleanup_unopened_confirmed(state) {
            return Ok(());
        }
        pause().await;
    }
    Err(ChainError::Chain(format!(
        "TC {tc}: cleanupUnopened outcome is bounded-ambiguous; state remained unchanged at funded=true through the observation window"
    )))
}

impl RealChainBackend {
    /// Bounded read-only confirmation for an already-submitted `streamCleanup`.
    pub async fn wait_cleanup_unopened(&self, tc: &Address) -> Result<(), ChainError> {
        wait_cleanup_unopened_with(
            &tc.to_string(),
            || async { self.token_contract_deal_state(tc).await.map_err(map_err) },
            || tokio::time::sleep(crate::params::CLEANUP_UNOPENED_CONFIRM_POLL_INTERVAL),
        )
        .await
    }

    async fn raw_resting_sell_orders_for_tc(
        &self,
        order_book: &Address,
        token_contract: &Address,
    ) -> Result<Vec<OrderBookOrder>> {
        let Some(stats) = self.inference_orderbook_stats(order_book).await? else {
            return Ok(Vec::new());
        };
        let next_order_id = order_u128(&stats, &["nextOrderId"]).ok_or_else(|| {
            anyhow!("InferenceOrderBook {order_book} getStats missing/invalid nextOrderId: {stats}")
        })?;
        let wanted = token_contract.with_workchain();
        let mut orders = Vec::new();
        for order_id in 1..next_order_id {
            let Some(raw) = self.inference_orderbook_order(order_book, order_id).await? else {
                continue;
            };
            let ticks = order_u128(&raw, &["amount"]).ok_or_else(|| {
                anyhow!(
                    "InferenceOrderBook {order_book} getOrder({order_id}) missing/invalid amount; \
                     cannot prove whether TokenContract {wanted} already has a resting SELL: {raw}"
                )
            })?;
            if ticks == 0 {
                continue;
            }
            let is_buy = raw["isBuy"].as_bool().ok_or_else(|| {
                anyhow!(
                    "InferenceOrderBook {order_book} getOrder({order_id}) missing/invalid isBuy; \
                     cannot prove whether TokenContract {wanted} already has a resting SELL: {raw}"
                )
            })?;
            if is_buy {
                continue;
            }
            let raw_tc = raw["tokenContract"]
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    anyhow!(
                        "InferenceOrderBook {order_book} active SELL getOrder({order_id}) has no \
                         tokenContract; cannot prove uniqueness for TokenContract {wanted}: {raw}"
                    )
                })?;
            let parsed_tc = Address::parse(raw_tc).map_err(|error| {
                anyhow!(
                    "InferenceOrderBook {order_book} active SELL getOrder({order_id}) has invalid \
                     tokenContract {raw_tc}: {error}"
                )
            })?;
            if !parsed_tc.with_workchain().eq_ignore_ascii_case(&wanted) {
                continue;
            }
            let parsed = orderbook_order_from_getter(order_id, &raw)
                .map_err(|error| {
                    anyhow!(
                        "InferenceOrderBook {order_book} raw SELL for TokenContract {wanted} is \
                         incomplete: {error}"
                    )
                })?
                .ok_or_else(|| {
                    anyhow!(
                        "InferenceOrderBook {order_book} raw SELL for TokenContract {wanted} \
                         disappeared while being classified"
                    )
                })?;
            if !parsed.is_resting_ask() {
                return Err(anyhow!(
                    "InferenceOrderBook {order_book} getOrder({order_id}) for TokenContract {wanted} \
                     is not an active unmatched SELL"
                ));
            }
            orders.push(parsed);
        }
        Ok(orders)
    }

    pub async fn inference_orderbook_snapshot(
        &self,
        order_book: &Address,
        frame_model: &str,
        model_hash: &str,
    ) -> Result<OrderBookSnapshot> {
        let Some(stats_value) = self.inference_orderbook_stats(order_book).await? else {
            return Ok(OrderBookSnapshot {
                frame_model: frame_model.to_string(),
                model_hash: model_hash.to_string(),
                order_book: order_book.with_workchain(),
                stats: None,
                orders: Vec::new(),
            });
        };
        let stats = orderbook_stats_from_getter(&stats_value);
        let mut raw = Vec::new();
        for id in 1..stats.next_order_id {
            // A per-id transport/chain read failure is a real error and surfaces here; a
            // `None` is an absent slot. Parsing (and the skip of filled/unparseable
            // orders) happens in `collect_live_orders`.
            if let Some(order) = self.inference_orderbook_order(order_book, id).await? {
                raw.push((id, order));
            }
        }
        let orders = collect_live_orders(raw);
        Ok(OrderBookSnapshot {
            frame_model: frame_model.to_string(),
            model_hash: model_hash.to_string(),
            order_book: order_book.with_workchain(),
            stats: Some(stats),
            orders,
        })
    }

    /// Read book identity/activity/counters without walking historical order ids.
    pub async fn inference_orderbook_summary(
        &self,
        order_book: &Address,
        frame_model: &str,
        model_hash: &str,
    ) -> Result<OrderBookSnapshot> {
        let stats = self
            .inference_orderbook_stats(order_book)
            .await?
            .map(|stats| orderbook_stats_from_getter(&stats));
        Ok(OrderBookSnapshot {
            frame_model: frame_model.to_string(),
            model_hash: model_hash.to_string(),
            order_book: order_book.with_workchain(),
            stats,
            orders: Vec::new(),
        })
    }

    /// Read and parse exactly one order id without scanning earlier deleted ids.
    pub async fn inference_orderbook_parsed_order(
        &self,
        order_book: &Address,
        order_id: u128,
    ) -> Result<Option<OrderBookOrder>> {
        let Some(order) = self.inference_orderbook_order(order_book, order_id).await? else {
            return Err(anyhow!(
                "getOrder({order_id}) returned no fixed-id row; only an explicit all-zero \
                 tombstone proves absence"
            ));
        };
        expected_orderbook_order_from_getter(order_id, &order)
    }

    pub async fn inference_orderbook_snapshot_for_note(
        &self,
        note: &Address,
        frame_model: &str,
        model_hash: &str,
        tick_size: u128,
    ) -> Result<OrderBookSnapshot> {
        let order_book = self
            .inference_orderbook_address(note, model_hash, tick_size)
            .await?;
        self.inference_orderbook_snapshot(&order_book, frame_model, model_hash)
            .await
    }

    pub async fn executable_resting_asks(
        &self,
        snapshot: &OrderBookSnapshot,
    ) -> Result<Vec<OrderBookOrder>> {
        let asks = coalesce_equivalent_resting_asks(&snapshot.orders).map_err(|e| {
            anyhow!(
                "InferenceOrderBook {} exposes unsafe duplicate active sell orders: {e}",
                snapshot.order_book
            )
        })?;
        let mut executable = Vec::with_capacity(asks.len());
        for ask in asks {
            let Some(token_contract) = ask.token_contract.as_deref() else {
                continue;
            };
            let Ok(tc) = Address::parse(token_contract) else {
                continue;
            };
            let state = self.token_contract_deal_state(&tc).await?;
            let non_executable = token_contract_non_executable_reason(state);
            if non_executable.is_none() {
                let balance = self.active_native_balance(&tc).await?;
                if balance > crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL {
                    executable.push(ask);
                }
            }
        }
        Ok(executable)
    }

    pub async fn submit_safe_single_ask_quote(
        &self,
        snapshot: &OrderBookSnapshot,
        wanted_ticks: Option<u128>,
        budget: Option<u128>,
    ) -> Result<ExecutableQuote> {
        let asks = coalesce_equivalent_resting_asks(&snapshot.orders).map_err(|e| {
            anyhow!(
                "InferenceOrderBook {} exposes unsafe duplicate active sell orders: {e}",
                snapshot.order_book
            )
        })?;
        let quote = crate::chain::submit_safe_single_ask_quote(&asks, wanted_ticks, budget)
            .map_err(|e| anyhow!("quote: {e}"))?;
        if !quote.complete {
            return Ok(quote);
        }
        for fill in &quote.fills {
            let Ok(tc) = Address::parse(&fill.token_contract) else {
                return Ok(ExecutableQuote {
                    filled_ticks: 0,
                    total_with_fee: 0,
                    complete: false,
                    fills: Vec::new(),
                });
            };
            let state = self.token_contract_deal_state(&tc).await?;
            let non_executable = token_contract_non_executable_reason(state);
            if non_executable.is_some() {
                return Ok(ExecutableQuote {
                    filled_ticks: 0,
                    total_with_fee: 0,
                    complete: false,
                    fills: Vec::new(),
                });
            }
            if self.active_native_balance(&tc).await?
                <= crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL
            {
                return Ok(ExecutableQuote {
                    filled_ticks: 0,
                    total_with_fee: 0,
                    complete: false,
                    fills: Vec::new(),
                });
            }
        }
        Ok(quote)
    }

    pub async fn submit_safe_model_buy_ask(
        &self,
        snapshot: &OrderBookSnapshot,
        ticks: u128,
        max_price_per_tick: u128,
    ) -> Result<OrderBookOrder> {
        let raw_asks: Vec<OrderBookOrder> = snapshot.resting_asks().cloned().collect();
        let executable_asks = self.executable_resting_asks(snapshot).await?;
        selected_model_buy_ask_matching_executable_depth(
            &raw_asks,
            &executable_asks,
            max_price_per_tick,
            ticks,
        )
        .map_err(|e| {
            anyhow!(
                "no_executable_ask: no executable matching ask for InferenceOrderBook {} at max_price_per_tick {}, \
                 requested ticks {}: {e}. IOB stats {}",
                snapshot.order_book,
                max_price_per_tick,
                ticks,
                orderbook_stats_for_error(snapshot)
            )
        })
    }

    pub async fn submit_safe_executable_book_asks(
        &self,
        snapshot: &OrderBookSnapshot,
        ticks: u128,
        max_price_per_tick: u128,
    ) -> Result<(Vec<OrderBookOrder>, Option<String>)> {
        let raw_asks: Vec<OrderBookOrder> = snapshot.resting_asks().cloned().collect();
        let executable_asks = self.executable_resting_asks(snapshot).await?;
        submit_safe_executable_book_asks(&raw_asks, &executable_asks, max_price_per_tick, ticks)
            .map_err(|e| {
                anyhow!(
                    "InferenceOrderBook {} exposes unsafe executable-book depth: {e}",
                    snapshot.order_book
                )
            })
    }
}

#[async_trait]
impl ChainBackend for RealDealBackend {
    async fn discover_offers(&self) -> Result<Vec<crate::chain::OfferListing>, ChainError> {
        // The adapter is configured for a SINGLE deal: book discovery (many offers,
        // B1) is a read of `InferenceOrderBook` via the low-level `RealChainBackend`
        // (getStats/getOrder), not the job of the single-deal wrapper. Here -- empty.
        Ok(Vec::new())
    }

    async fn post_offer(&self, offer: SellOffer, _note: &dyn Note) -> Result<(), ChainError> {
        // One seller call. PrivateNote.postSellOffer(flags, nonce, ttl) derives the canonical per-deal
        // TokenContract locally and hands it the baked InferenceOrderBook hash; the TC posts its own resting
        // ask(msg.sender == TC). No RootPN round-trip.
        // The ttl is MANDATORY -- an ask commits no collateral, so it must auto-expire. Requesting
        // the contract's maximum keeps the offer alive as long as the protocol permits.
        self.chain
            .post_sell_offer(
                &self.ctx.seller_note,
                &self.ctx.seller_keys,
                offer.flags,
                self.ctx.nonce,
                crate::params::MAX_SELL_TTL.as_secs(),
            )
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn place_buy(
        &self,
        _token_contract: &TokenContract,
        _note: &dyn Note,
    ) -> Result<(), ChainError> {
        // the shared order book may contain valid asks from many sellers, each with its own canonical TC.
        // The IOB itself enforces `tokenContract == _tokenContractAddr(sellerPubkey, nonce)` at
        // `placeSellOffer`, so a client-side scan against this buyer's single expected TC is both redundant and
        // wrong for shared books.
        let deadline = canonical_cli_buy_deadline("deal buyer place_buy")?;
        self.chain
            .place_inference_buy(
                &self.ctx.buyer_note,
                &self.ctx.buyer_keys,
                &self.ctx.model_hash,
                self.ctx.price_per_tick,
                self.ctx.ticks,
                self.ctx.escrow,
                0,
                deadline,
            )
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn read_match(&self, token_contract: &TokenContract) -> Result<Match, ChainError> {
        let tc = parse_tc(token_contract)?;
        for _ in 0..crate::params::MATCH_CONFIRM_MAX_READS {
            let state = self
                .chain
                .token_contract_deal_state(&tc)
                .await
                .map_err(map_err)?;
            if let Some(state) = state.filter(|state| state.funded) {
                let (_tick_size, price_per_tick, _max_ticks) = self
                    .chain
                    .token_contract_deal_terms(&tc)
                    .await
                    .map_err(map_err)?
                    .ok_or_else(|| {
                        ChainError::Chain(format!(
                            "TokenContract {token_contract} getDeal unavailable after match"
                        ))
                    })?;
                let price_per_tick = checked_shell(&[price_per_tick], "pricePerTick")?;
                validate_seller_resume_state(token_contract, state, price_per_tick)?;
                return Ok(Match {
                    token_contract: token_contract.clone(),
                    buyer_pubkey: self.ctx.buyer_pubkey.clone(),
                    price_per_tick,
                });
            }
            tokio::time::sleep(crate::params::MATCH_CONFIRM_POLL_INTERVAL).await;
        }
        Err(ChainError::NoMatch(token_contract.clone()))
    }

    async fn open_stream(
        &self,
        token_contract: &TokenContract,
        enc_endpoint: Vec<u8>,
        _note: &dyn Note,
    ) -> Result<(), ChainError> {
        let tc = parse_tc(token_contract)?;
        // +: the note posts the exact `2P` seller bond to the nonce-derived TC from its own ECC[2]
        // (`postSellerBond`) -- no operator wallet.
        post_seller_bond_and_wait(
            &self.chain,
            &self.ctx.seller_note,
            &self.ctx.seller_keys,
            self.ctx.nonce,
            token_contract,
            &tc,
        )
        .await?;
        // the enc endpoint(handover) is written to the TC. Wait for open() to apply(opened==true).
        self.ensure_tc_gas(&tc).await?;
        self.chain
            .open_stream(&tc, &self.ctx.seller_keys, &enc_endpoint)
            .await
            .map_err(map_err)?;
        self.wait_state_bool(&tc, "opened", true).await
    }

    async fn read_handover(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<Vec<u8>>, ChainError> {
        let tc = parse_tc(token_contract)?;
        self.chain.read_handover(&tc).await.map_err(map_err)
    }

    async fn accept_probe(&self, token_contract: &TokenContract) -> Result<(), ChainError> {
        let tc = parse_tc(token_contract)?;
        self.ensure_tc_gas(&tc).await?;
        self.chain
            .accept_probe(&tc, &self.ctx.seller_keys)
            .await
            .map_err(map_err)?;
        self.wait_state_bool(&tc, "probeAccepted", true).await
    }

    async fn claim_tokens(
        &self,
        token_contract: &TokenContract,
        _note: &dyn Note,
        cumulative_tokens: u128,
    ) -> Result<(), ChainError> {
        let tc = parse_tc(token_contract)?;
        self.ensure_tc_gas(&tc).await?;
        submit_claim_confirmed(&self.chain, &tc, &self.ctx.seller_keys, cumulative_tokens).await
    }

    async fn finalize(&self, token_contract: &TokenContract) -> Result<(), ChainError> {
        let tc = parse_tc(token_contract)?;
        let before = self
            .chain
            .token_contract_deal_state(&tc)
            .await
            .map_err(map_err)?
            .ok_or_else(|| ChainError::Chain(format!("TC {tc}: getState() returned no data")))?;
        if before.tokens_final >= before.tokens_pending {
            return Ok(()); // nothing pending to promote
        }
        self.ensure_tc_gas(&tc).await?;
        submit_finalize_confirmed(&self.chain, &tc, token_contract, before).await
    }

    async fn settle_week(&self, token_contract: &TokenContract) -> Result<(), ChainError> {
        let tc = parse_tc(token_contract)?;
        let pre = required_subscription_week_index(
            token_contract,
            "before settleWeek",
            self.chain
                .token_contract_subscription(&tc)
                .await
                .map_err(map_err)?,
        )?;
        self.ensure_tc_gas(&tc).await?;
        self.chain.settle_week(&tc).await.map_err(map_err)?;
        let confirmation = ClaimConfirmationParams::canonical();
        for _ in 0..confirmation.max_reads {
            let post = self
                .chain
                .token_contract_subscription(&tc)
                .await
                .map_err(map_err)?;
            let active = if post.is_none() {
                self.chain
                    .account_active_code_hash(&tc)
                    .await
                    .map_err(map_err)?
                    .0
            } else {
                true
            };
            if settle_week_post_confirmed(token_contract, pre, post, active)? {
                return Ok(());
            }
            tokio::time::sleep(confirmation.poll_interval).await;
        }
        Err(ChainError::Chain(format!(
            "TC {tc}: settleWeek did not advance weekIndex past {pre}"
        )))
    }

    async fn deal_snapshot(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<DealChainSnapshot>, ChainError> {
        let tc = parse_tc(token_contract)?;
        self.chain
            .token_contract_deal_snapshot(&tc)
            .await
            .map_err(map_err)
    }

    async fn deal_subscription(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<DealSubscription>, ChainError> {
        Ok(self
            .deal_snapshot(token_contract)
            .await?
            .map(|snapshot| snapshot.subscription))
    }

    async fn stop(
        &self,
        token_contract: &TokenContract,
        _note: &dyn Note,
    ) -> Result<Settlement, ChainError> {
        let tc = parse_tc(token_contract)?;
        explicit_buyer_stop_with(
            &self.chain,
            &self.ctx.buyer_note,
            &self.ctx.buyer_keys,
            &tc,
            || self.ensure_tc_gas(&tc),
        )
        .await
    }

    async fn stop_if_heartbeat(
        &self,
        token_contract: &TokenContract,
        _note: &dyn Note,
        heartbeat: &crate::chain::HeartbeatGuard,
    ) -> Result<Option<Settlement>, ChainError> {
        let tc = parse_tc(token_contract)?;
        self.ensure_tc_gas(&tc).await?;
        let mut heartbeat_unchanged = || heartbeat.unchanged();
        let receipt = self
            .chain
            .stop_if_heartbeat(
                &self.ctx.buyer_note,
                &self.ctx.buyer_keys,
                &tc,
                &mut heartbeat_unchanged,
            )
            .await
            .map_err(map_err)?;
        Ok(receipt.map(|receipt| Settlement::AuthoritativeReceipt(Box::new(receipt))))
    }

    async fn dispute(
        &self,
        token_contract: &TokenContract,
        _note: &dyn Note,
    ) -> Result<Settlement, ChainError> {
        let tc = parse_tc(token_contract)?;
        self.ensure_tc_gas(&tc).await?;
        let receipt = self
            .chain
            .stream_dispute(&self.ctx.buyer_note, &self.ctx.buyer_keys, &tc)
            .await
            .map_err(map_err)?;
        Ok(Settlement::AuthoritativeReceipt(Box::new(receipt)))
    }

    async fn release_dispute(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Settlement, ChainError> {
        let tc = parse_tc(token_contract)?;
        self.ensure_tc_gas(&tc).await?;
        let receipt = self
            .chain
            .release_dispute(&tc, &self.ctx.seller_keys)
            .await
            .map_err(map_err)?;
        Ok(Settlement::AuthoritativeReceipt(Box::new(receipt)))
    }

    async fn cleanup_unopened(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Settlement, ChainError> {
        let tc = parse_tc(token_contract)?;
        let state = tc_settle_state(&self.chain, &tc).await.map_err(map_err)?;
        self.ensure_tc_gas(&tc).await?;
        self.chain
            .stream_cleanup(&self.ctx.buyer_note, &self.ctx.buyer_keys, &tc)
            .await
            .map_err(map_err)?;
        self.chain.wait_cleanup_unopened(&tc).await?;
        // Nothing was delivered, so there is no fee and no penalty: the buyer's whole deposit
        // and the seller's whole bond go back.
        Ok(Settlement::SellerNoShow {
            to_buyer_refund: state.deposit,
            seller_bond_returned: state.seller_bond,
        })
    }

    async fn deal_state(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<DealChainState>, ChainError> {
        Ok(self
            .deal_snapshot(token_contract)
            .await?
            .map(|snapshot| snapshot.state))
    }

    async fn snapshot(&self, token_contract: &TokenContract) -> Option<StreamSnapshot> {
        real_tc_snapshot(&self.chain, token_contract).await
    }
}

/// The per-role CLI backend of the **SELLER**: the `ChainBackend` trait for the `dexdo seller` process. Unlike
/// [`RealDealBackend`](both sides in-process, D2) it holds ONLY the seller's identity (note+keys +
/// `model_hash` from) and **reads the counterparty/state from the chain** -- the buyer's
/// pubkey is taken from on-chain `getBuyerPubkey` after the match(F1), not from arguments. The seller side is
/// **note-funded**: no operator wallet -- the note self-funds the deploy pre-fund + exact `2P` seller bond from
/// its own ECC[2]. It reuses [`RealChainBackend`] helpers(deploy OB/offer/bond/advance) -- it does not duplicate
/// submit/provisioning. Provisioning(note/keys) is NOT here: the backend only reads/signs.
pub struct RealSellerBackend {
    chain: RealChainBackend,
    note: Address,
    keys: KeyPair,
    model_hash: String,
    /// Canonical model name(4.0.6): forwarded into `deployInferenceOrderBook(modelHash, modelName)`
    /// so the book verifies `sha256(modelName)==modelHash`(`ERR_BAD_MODEL_NAME`).
    model_name: String,
    /// Deal nonce for the per-deal `TokenContract`: the `_nonce` static the TC is deployed with and the
    /// nonce passed to the 4.0.26 `note.postSellOffer(flags, nonce)` call.
    nonce: u64,
    tick_size: u128,
    offer_post_started_at: std::sync::Mutex<Option<u64>>,
}

impl RealSellerBackend {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: RealChainBackend,
        note: Address,
        keys: KeyPair,
        model_hash: String,
        model_name: String,
        nonce: u64,
        tick_size: u128,
    ) -> Self {
        Self {
            chain,
            note,
            keys,
            model_hash,
            model_name,
            nonce,
            tick_size,
            offer_post_started_at: std::sync::Mutex::new(None),
        }
    }

    /// Assemble the seller backend and the seller's note from the `--note-key` seed. Directive: the
    /// seller has **no operator multisig** -- the note self-funds its seller side (RootModel/TC deploy pre-fund
    /// via `fundDeployShell`, exact `2P` seller bond via `postSellerBond`) from its own ECC[2], so there is no
    /// wallet to derive. The note address `note_addr` is mint-specific(`depositIdentifier`), not derivable, so
    /// it is passed in. dexdo does NOT create keys and does NOT fund from
    /// the giver. `model_hash` -- from `frame_model`. Returns the backend + a
    /// `RealNote` for the gateway. All SDK types stay in the core -- the CLI passes strings.
    pub fn from_provisioned(
        manifest_path: &str,
        note_addr: &str,
        note_secret_hex: &str,
        frame_model: &str,
        nonce: u64,
    ) -> Result<(Self, RealNote)> {
        let chain = RealChainBackend::connect(manifest_path)?;
        let note =
            Address::parse(note_addr).map_err(|e| anyhow!("--note-addr {note_addr}: {e}"))?;
        let keys = KeyPair::from_secret_hex(note_secret_hex.trim())
            .map_err(|e| anyhow!("--note-key (SDK secret hex): {e:?}"))?;
        let rn = RealNote::from_secret_hex(note_secret_hex)
            .map_err(|e| anyhow!("--note-key invalid ed25519 seed: {e}"))?;
        let backend = Self::new(
            chain,
            note,
            keys,
            model_hash_for(frame_model),
            frame_model.to_string(),
            nonce,
            TICK_SIZE,
        );
        Ok((backend, rn))
    }

    async fn ensure_tc_gas(&self, tc: &Address) -> Result<(), ChainError> {
        self.chain
            .ensure_deal_contract_gas(&self.note, &self.keys, self.nonce, None, Some(tc))
            .await
            .map_err(map_err)
    }

    async fn read_openable_match_once(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<Match>, ChainError> {
        let tc = parse_tc(token_contract)?;
        let Some(state) = self
            .chain
            .token_contract_deal_state(&tc)
            .await
            .map_err(map_err)?
        else {
            return Ok(None);
        };
        if !state.funded {
            return Ok(None);
        }
        let price_per_tick = self
            .sell_offer_terms(token_contract)
            .await?
            .map(|(price, _ticks)| price)
            .ok_or_else(|| {
                ChainError::Chain(format!(
                    "TokenContract {token_contract} getDeal unavailable after match"
                ))
            })?;
        validate_seller_resume_state(token_contract, state, price_per_tick)?;
        // F1: the buyer's pubkey is FROM THE CHAIN(`getBuyerPubkey`, ed25519),
        // not from arguments. Reconstruct the x25519 handover key from it.
        let ed = self
            .chain
            .token_contract_buyer_pubkey(&tc)
            .await
            .map_err(map_err)?
            .ok_or_else(|| {
                ChainError::Chain(format!("TC {tc}: funded, but buyerPubkey is empty"))
            })?;
        let x = crate::note::x25519_pub_from_ed25519_pub(&ed).ok_or_else(|| {
            ChainError::Chain(format!("TC {tc}: buyerPubkey is an invalid ed25519 point"))
        })?;
        Ok(Some(Match {
            token_contract: token_contract.clone(),
            buyer_pubkey: NotePubkey { x, ed },
            price_per_tick,
        }))
    }

    async fn post_offer_failure_evidence(&self, tc: &Address) -> (String, String) {
        let tc_state_evidence = match retry_seller_read("seller failure TC state", || async {
            self.chain.token_contract_state(tc).await.map_err(map_err)
        })
        .await
        {
            Ok(Some(_)) => format!(
                "TokenContract {} state evidence: Active/getState readable",
                tc.with_workchain()
            ),
            Ok(None) => format!(
                "TokenContract {} state evidence: not Active or getState unreadable",
                tc.with_workchain()
            ),
            Err(e) => format!(
                "TokenContract {} state evidence: getState error: {e}",
                tc.with_workchain()
            ),
        };
        let seller_pubkey = json!(format!("0x{}", self.keys.public_hex()));
        let canonical_evidence = match retry_seller_read("seller failure RootModel", || async {
            self.chain
                .root_model_address_for(&seller_pubkey)
                .await
                .map_err(map_err)
        })
        .await
        {
            Ok(root_model) => match retry_seller_read("seller failure canonical TC", || async {
                self.chain
                    .resolve_token_contract(&root_model, &seller_pubkey, self.nonce)
                    .await
                    .map_err(map_err)
            })
            .await
            {
                Ok(expected) => format!(
                    "RootModel expected TokenContract for (sellerPubkey, nonce) is {} and offered token_contract is {}; match={}",
                    expected.with_workchain(),
                    tc.with_workchain(),
                    expected.with_workchain().eq_ignore_ascii_case(&tc.with_workchain())
                ),
                Err(e) => format!(
                    "RootModel expected TokenContract for (sellerPubkey, nonce) could not be read from {root_model}: {e}"
                ),
            },
            Err(e) => format!(
                "RootModel address for sellerPubkey could not be read from SuperRoot: {e}"
            ),
        };
        (canonical_evidence, tc_state_evidence)
    }
}

#[async_trait]
impl ChainBackend for RealSellerBackend {
    /// the seller daemon publishes offers without `provision_market`'s note-current gate; enforce it here
    /// so a note orphaned by a contract redeploy(stale code_hash) fails closed with an actionable "re-mint"
    /// message instead of a raw `TVM_ERROR` from `postSellOffer`.
    async fn assert_note_current(&self) -> Result<(), ChainError> {
        retry_seller_read("seller note code", || async {
            self.chain
                .assert_seller_note_current(&self.note)
                .await
                .map_err(map_err)
        })
        .await
    }
    /// `PrivateNote._hasWithdrawn=true` permanently blocks `postSellOffer`. Read it before seller writes
    /// so users get the fresh-note action instead of raw `ERR_INVALID_STATE` 151.
    async fn assert_note_can_post_sell_offer(&self) -> Result<(), ChainError> {
        retry_seller_read("seller note post eligibility", || async {
            self.chain
                .assert_note_can_post_sell_offer(&self.note)
                .await
                .map_err(map_err)
        })
        .await
    }
    /// the per-deal TC(sellerPubkey + nonce) is single-use; before resting an ask, fail closed if it is
    /// already USED(a prior deal opened/funded/disputed it or left residual), so the operator gets an
    /// actionable message instead of a raw `TVM_ERROR`(`ERR_ALREADY_OPEN` 321) from the pre-stream steps. A
    /// not-yet-active(undeployed) TC is not "used" -- let the deploy path handle it.
    async fn assert_token_contract_fresh(&self, tc: &TokenContract) -> Result<(), ChainError> {
        let addr = parse_tc(tc)?;
        let Some(state) = retry_seller_read("seller TokenContract freshness", || async {
            self.chain
                .token_contract_deal_state(&addr)
                .await
                .map_err(map_err)
        })
        .await?
        else {
            return Ok(());
        };
        if let Some(reason) = token_contract_used_reason(state) {
            return Err(ChainError::Chain(format!(
                "deal TokenContract {tc} is already USED ({reason}) -- a per-deal TC (sellerPubkey + nonce) is \
                 single-use, not reusable capacity. Use a fresh --nonce / fresh --market, or close the prior \
                 deal (`dexdo recover` as the buyer, then `dexdo destroy` as the seller) before re-offering ()."
            )));
        }
        Ok(())
    }
    async fn discover_offers(&self) -> Result<Vec<crate::chain::OfferListing>, ChainError> {
        // Book discovery is the buyer's/monitor's job; the seller does not scan the listing.
        Ok(Vec::new())
    }

    async fn post_offer(&self, offer: SellOffer, _note: &dyn Note) -> Result<(), ChainError> {
        let tc = parse_tc(&offer.token_contract)?;
        self.assert_note_can_post_sell_offer().await?;
        // (symmetric branch-3 guard): fail closed if this note's on-chain owner key
        // (`getDetails().ephemeralPubkey`) is not the key we sign `postSellOffer` with -- otherwise
        // `onlyOwnerPubkey` reverts pre-accept(ERR_INVALID_SENDER 101) and the ask never rests (only an
        // opaque TVM_ERROR). Run it before the IOB deploy / offer write.
        retry_seller_read("seller note owner", || async {
            self.chain
                .assert_note_owner_matches("seller post_offer", &self.note, &self.keys)
                .await
                .map_err(map_err)
        })
        .await?;
        // An operate exception: if the per-model `InferenceOrderBook` is not yet deployed --
        // deploy it(model listing; the address is derived from `model_hash`). This is operate, NOT actor provisioning.
        let ob = retry_seller_read("seller order-book address", || async {
            self.chain
                .inference_orderbook_address(&self.note, &self.model_hash, self.tick_size)
                .await
                .map_err(map_err)
        })
        .await?;
        if retry_seller_read("seller order-book state", || async {
            self.chain
                .inference_orderbook_stats(&ob)
                .await
                .map_err(map_err)
        })
        .await?
        .is_none()
        {
            self.chain
                .deploy_inference_orderbook(
                    &self.note,
                    &self.keys,
                    &self.model_hash,
                    &self.model_name,
                    self.tick_size,
                )
                .await
                .map_err(map_err)?;
        }
        let (price_per_tick, max_ticks) = self
            .sell_offer_terms(&offer.token_contract)
            .await?
            .ok_or_else(|| {
                ChainError::Chain(format!(
                    "TokenContract {} getDeal unavailable: run `dexdo provision` for a deployed per-deal TC \
                     or pass --market for the provisioned manifest",
                    offer.token_contract
                ))
        })?;
        if offer.price_per_tick != price_per_tick || offer.max_ticks != max_ticks {
            eprintln!(
                "seller offer terms are bound to TokenContract.getDeal; ignoring drifted CLI values: \
                 token_contract={} requested_price_per_tick={} requested_max_ticks={} \
                 onchain_price_per_tick={} onchain_max_ticks={}",
                offer.token_contract,
                offer.price_per_tick,
                offer.max_ticks,
                price_per_tick,
                max_ticks
            );
        }
        *self.offer_post_started_at.lock().map_err(|_| {
            ChainError::Chain("seller offer submission marker lock poisoned".to_string())
        })? = Some(now_secs().saturating_sub(crate::params::SELLER_OFFER_EVENT_LOOKBACK_SECS));
        match tokio::time::timeout(
            POST_SELL_OFFER_SUBMIT_TIMEOUT,
            // One seller call: postSellOffer(flags, nonce, ttl). The note derives the canonical TC and
            // hands it the baked book hash; the TC posts its own ask. The on-chain terms read + drift check
            // above stay as a pre-post sanity check. The ttl is mandatory; ask for the maximum the
            // contract allows so the offer is not cut short by our own default.
            self.chain.post_sell_offer(
                &self.note,
                &self.keys,
                offer.flags,
                self.nonce,
                crate::params::MAX_SELL_TTL.as_secs(),
            ),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(map_err(e)),
            Err(_) => {
                let (canonical_evidence, tc_state_evidence) =
                    self.post_offer_failure_evidence(&tc).await;
                return Err(ChainError::Chain(seller_post_sell_offer_timeout_message(
                    &ob,
                    &offer.token_contract,
                    &self.model_hash,
                    self.nonce,
                    &self.note,
                    POST_SELL_OFFER_SUBMIT_TIMEOUT,
                    &canonical_evidence,
                    &tc_state_evidence,
                )));
            }
        }
        Ok(())
    }

    async fn confirm_offer_outcome(
        &self,
        tc: &TokenContract,
    ) -> Result<Option<SellOfferOutcome>, ChainError> {
        let ob = retry_seller_read("seller outcome order-book address", || async {
            self.chain
                .inference_orderbook_address(&self.note, &self.model_hash, self.tick_size)
                .await
                .map_err(map_err)
        })
        .await?;
        let tc_addr = parse_tc(tc)?;
        let since = self
            .offer_post_started_at
            .lock()
            .map_err(|_| {
                ChainError::Chain("seller offer submission marker lock poisoned".to_string())
            })?
            .ok_or_else(|| {
                ChainError::Chain("seller offer submission marker is missing".to_string())
            })?;
        let started = std::time::Instant::now();
        while started.elapsed() < OFFER_ACCEPTANCE_TIMEOUT {
            let events = retry_seller_read("seller offer outcome events", || async {
                self.chain
                    .seller_offer_events_since(&self.note, &ob, &tc_addr, since)
                    .await
                    .map_err(map_err)
            })
            .await?;
            let matched_state = retry_seller_read("seller immediate-match state", || async {
                self.read_openable_match_once(tc).await
            })
            .await?
            .is_some();
            if let Some(outcome) = classify_seller_offer_outcome(events, matched_state)? {
                return Ok(Some(outcome));
            }
            tokio::time::sleep(crate::params::SELLER_OFFER_OUTCOME_POLL_INTERVAL).await;
        }
        Err(ChainError::Chain(format!(
            "seller postSellOffer outcome is not yet confirmed for TokenContract {tc}; no placement, match, or returned placement value was observed"
        )))
    }

    async fn sell_offer_terms(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<(Shell, u64)>, ChainError> {
        let tc = parse_tc(token_contract)?;
        let Some((tick_size, price_per_tick, max_ticks)) =
            retry_seller_read("seller TokenContract terms", || async {
                self.chain
                    .token_contract_deal_terms(&tc)
                    .await
                    .map_err(map_err)
            })
            .await?
        else {
            return Ok(None);
        };
        if tick_size != self.tick_size {
            return Err(ChainError::Chain(format!(
                "TokenContract {token_contract} tickSize {tick_size} != canonical {}",
                self.tick_size
            )));
        }
        let price = price_per_tick.try_into().map_err(|_| {
            ChainError::Chain(format!(
                "TokenContract {token_contract} pricePerTick {price_per_tick} exceeds CLI Shell range"
            ))
        })?;
        let ticks = max_ticks.try_into().map_err(|_| {
            ChainError::Chain(format!(
                "TokenContract {token_contract} maxTicks {max_ticks} exceeds CLI range"
            ))
        })?;
        Ok(Some((price, ticks)))
    }

    async fn raw_resting_sell_orders_for_tc(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Vec<OrderBookOrder>, ChainError> {
        let tc = parse_tc(token_contract)?;
        let order_book = retry_seller_read("seller raw order-book address", || async {
            self.chain
                .inference_orderbook_address(&self.note, &self.model_hash, self.tick_size)
                .await
                .map_err(map_err)
        })
        .await?;
        retry_seller_read("seller raw exact-TC SELL rows", || async {
            self.chain
                .raw_resting_sell_orders_for_tc(&order_book, &tc)
                .await
                .map_err(map_err)
        })
        .await
    }

    async fn cancel_resting_sell_order(
        &self,
        token_contract: &TokenContract,
        order_id: u128,
    ) -> Result<(), ChainError> {
        let tc = parse_tc(token_contract)?;
        let orders = self.raw_resting_sell_orders_for_tc(token_contract).await?;
        if !orders.iter().any(|order| order.order_id == order_id) {
            return Err(ChainError::Chain(format!(
                "resting SELL {order_id} is absent for TokenContract {}",
                tc.with_workchain()
            )));
        }
        self.chain
            .cancel_inference_order(&self.note, &self.keys, &self.model_hash, order_id)
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn read_openable_match_now(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<Match>, ChainError> {
        retry_seller_read("seller existing-match preflight", || async {
            self.read_openable_match_once(token_contract).await
        })
        .await
    }

    async fn poll_seller_fills(
        &self,
        _note: &dyn Note,
        cursor: &mut MatchWatchCursor,
    ) -> Result<Vec<MatchedFill>, ChainError> {
        let order_book = self
            .chain
            .inference_orderbook_address(&self.note, &self.model_hash, self.tick_size)
            .await
            .map_err(map_err)?;
        self.chain
            .poll_inference_filled_tcs(&self.note, &order_book, false, cursor)
            .await
            .map_err(map_err)
    }

    async fn place_buy(&self, tc: &TokenContract, _note: &dyn Note) -> Result<(), ChainError> {
        let _ = tc;
        Err(wrong_role("place_buy", "buyer"))
    }

    async fn read_match(&self, token_contract: &TokenContract) -> Result<Match, ChainError> {
        self.read_openable_match_once(token_contract)
            .await?
            .ok_or_else(|| ChainError::NoMatch(token_contract.clone()))
    }

    async fn open_stream(
        &self,
        token_contract: &TokenContract,
        enc_endpoint: Vec<u8>,
        _note: &dyn Note,
    ) -> Result<(), ChainError> {
        let tc = parse_tc(token_contract)?;
        // +: the note posts the exact `2P` seller bond to the nonce-derived TC from its own ECC[2]
        // (`postSellerBond`) -- no operator wallet.
        post_seller_bond_and_wait(
            &self.chain,
            &self.note,
            &self.keys,
            self.nonce,
            token_contract,
            &tc,
        )
        .await?;
        self.ensure_tc_gas(&tc).await?;
        self.chain
            .open_stream(&tc, &self.keys, &enc_endpoint)
            .await
            .map_err(map_err)?;
        wait_tc_bool(&self.chain, &tc, "opened", true).await
    }

    async fn read_handover(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<Vec<u8>>, ChainError> {
        let tc = parse_tc(token_contract)?;
        self.chain.read_handover(&tc).await.map_err(map_err)
    }

    async fn accept_probe(&self, token_contract: &TokenContract) -> Result<(), ChainError> {
        let tc = parse_tc(token_contract)?;
        self.ensure_tc_gas(&tc).await?;
        self.chain
            .accept_probe(&tc, &self.keys)
            .await
            .map_err(map_err)?;
        // Confirm by FACT: the contract refuses acceptance before PROBE_WINDOW, and reporting success on a
        // refused call would start the claim loop against a deal that still rejects every claim.
        wait_tc_bool(&self.chain, &tc, "probeAccepted", true).await
    }

    async fn claim_tokens(
        &self,
        token_contract: &TokenContract,
        _note: &dyn Note,
        cumulative_tokens: u128,
    ) -> Result<(), ChainError> {
        let tc = parse_tc(token_contract)?;
        self.ensure_tc_gas(&tc).await?;
        submit_claim_confirmed(&self.chain, &tc, &self.keys, cumulative_tokens).await
    }

    async fn finalize(&self, token_contract: &TokenContract) -> Result<(), ChainError> {
        let tc = parse_tc(token_contract)?;
        let before = self
            .chain
            .token_contract_deal_state(&tc)
            .await
            .map_err(map_err)?
            .ok_or_else(|| ChainError::Chain(format!("TC {tc}: getState() returned no data")))?;
        if before.tokens_final >= before.tokens_pending {
            return Ok(()); // nothing pending to promote
        }
        self.ensure_tc_gas(&tc).await?;
        submit_finalize_confirmed(&self.chain, &tc, token_contract, before).await
    }

    async fn settle_week(&self, token_contract: &TokenContract) -> Result<(), ChainError> {
        let tc = parse_tc(token_contract)?;
        let pre = required_subscription_week_index(
            token_contract,
            "before settleWeek",
            self.chain
                .token_contract_subscription(&tc)
                .await
                .map_err(map_err)?,
        )?;
        self.ensure_tc_gas(&tc).await?;
        self.chain.settle_week(&tc).await.map_err(map_err)?;
        let confirmation = ClaimConfirmationParams::canonical();
        for _ in 0..confirmation.max_reads {
            let post = self
                .chain
                .token_contract_subscription(&tc)
                .await
                .map_err(map_err)?;
            let active = if post.is_none() {
                self.chain
                    .account_active_code_hash(&tc)
                    .await
                    .map_err(map_err)?
                    .0
            } else {
                true
            };
            if settle_week_post_confirmed(token_contract, pre, post, active)? {
                return Ok(());
            }
            tokio::time::sleep(confirmation.poll_interval).await;
        }
        Err(ChainError::Chain(format!(
            "TC {tc}: settleWeek did not advance weekIndex past {pre}"
        )))
    }

    async fn seller_stop(&self, token_contract: &TokenContract) -> Result<Settlement, ChainError> {
        let tc = parse_tc(token_contract)?;
        let state = tc_settle_state(&self.chain, &tc).await.map_err(map_err)?;
        if !state.opened {
            return Err(ChainError::Chain(format!(
                "TC {tc} is not OPEN; refusing sellerStop before money moves"
            )));
        }
        self.ensure_tc_gas(&tc).await?;
        self.chain
            .seller_stop(&tc, &self.keys)
            .await
            .map(|receipt| Settlement::AuthoritativeReceipt(Box::new(receipt)))
            .map_err(map_err)
    }

    async fn deal_snapshot(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<DealChainSnapshot>, ChainError> {
        let tc = parse_tc(token_contract)?;
        self.chain
            .token_contract_deal_snapshot(&tc)
            .await
            .map_err(map_err)
    }

    async fn deal_subscription(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<DealSubscription>, ChainError> {
        Ok(self
            .deal_snapshot(token_contract)
            .await?
            .map(|snapshot| snapshot.subscription))
    }

    /// Per-deal claim bounds from the deal's own `getConfig()`, so a redeployed contract with different
    /// bounds cannot desync the seller's claim loop from what the chain will actually accept.
    async fn deal_claim_bounds(
        &self,
        token_contract: &TokenContract,
    ) -> Result<ClaimBounds, ChainError> {
        let tc = parse_tc(token_contract)?;
        let cfg = self
            .chain
            .token_contract_config(&tc)
            .await
            .map_err(map_err)?
            .ok_or_else(|| {
                ChainError::Chain(format!(
                    "TC {tc}: getConfig() returned no data for claim bounds"
                ))
            })?;
        let field = |name: &str| -> Result<u64, ChainError> {
            cfg[name]
                .as_str()
                .and_then(|x| x.parse::<u64>().ok())
                .ok_or_else(|| {
                    ChainError::Chain(format!(
                        "TC {tc}: getConfig().{name} is missing or malformed; refusing to guess the \
                         claim cadence"
                    ))
                })
        };
        Ok(ClaimBounds::from_config(
            field("minClaimInterval")?,
            field("minSecondsPerTick")?,
            field("disputeWindow")?,
        ))
    }

    async fn stop(
        &self,
        token_contract: &TokenContract,
        _note: &dyn Note,
    ) -> Result<Settlement, ChainError> {
        let _ = token_contract;
        Err(wrong_role("stop", "buyer"))
    }

    async fn buyer_stop_settlement(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<(u128, u128)>, ChainError> {
        let tc = parse_tc(token_contract)?;
        let receipts = self
            .chain
            .token_contract_settlement_receipts(&tc)
            .await
            .map_err(map_err)?;
        exact_buyer_stop_settlement(receipts)
    }

    async fn release_dispute(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Settlement, ChainError> {
        let tc = parse_tc(token_contract)?;
        self.ensure_tc_gas(&tc).await?;
        let receipt = self
            .chain
            .release_dispute(&tc, &self.keys)
            .await
            .map_err(map_err)?;
        Ok(Settlement::AuthoritativeReceipt(Box::new(receipt)))
    }

    async fn deal_state(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<DealChainState>, ChainError> {
        Ok(self
            .deal_snapshot(token_contract)
            .await?
            .map(|snapshot| snapshot.state))
    }

    async fn snapshot(&self, token_contract: &TokenContract) -> Option<StreamSnapshot> {
        real_tc_snapshot(&self.chain, token_contract).await
    }
}

/// The per-role CLI backend of the **BUYER**: the `ChainBackend` trait for the `dexdo buyer` process. It holds
/// the buyer's identity and **reads
/// the book/state from the chain**(`discover_offers` scans `InferenceOrderBook`). Seller actions
/// (`post_offer`/`read_match`/`open_stream`/`accept_probe`/`claim_tokens`/`release_dispute`) are an explicit error;
/// permissionless claim promotion is `finalize`, not a seller advance operation.
pub struct RealBuyerBackend {
    chain: RealChainBackend,
    note: Address,
    keys: KeyPair,
    model_hash: String,
    tick_size: u128,
    max_price_per_tick: u128,
    ticks: u128,
    escrow: u128,
    pending_fill: std::sync::Mutex<Option<PendingBuyerFill>>,
}

#[derive(Debug, Clone)]
struct PendingBuyerFill {
    cursor: MatchWatchCursor,
    expected: MatchedFill,
}

impl RealBuyerBackend {
    fn set_pending_fill(&self, pending: Option<PendingBuyerFill>) -> Result<(), ChainError> {
        *self.pending_fill.lock().map_err(|_| {
            ChainError::Chain("buyer fill reconciliation state lock poisoned".to_string())
        })? = pending;
        Ok(())
    }

    fn take_pending_fill(&self) -> Result<Option<PendingBuyerFill>, ChainError> {
        Ok(self
            .pending_fill
            .lock()
            .map_err(|_| {
                ChainError::Chain("buyer fill reconciliation state lock poisoned".to_string())
            })?
            .take())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: RealChainBackend,
        note: Address,
        keys: KeyPair,
        model_hash: String,
        tick_size: u128,
        max_price_per_tick: u128,
        ticks: u128,
        escrow: u128,
    ) -> Self {
        Self {
            chain,
            note,
            keys,
            model_hash,
            tick_size,
            max_price_per_tick,
            ticks,
            escrow,
            pending_fill: std::sync::Mutex::new(None),
        }
    }

    /// Assemble the buyer backend + the buyer's note from an **already provisioned** actor: a minted
    /// `PrivateNote`(`note_addr` + owner key). The buyer needs no wallet(the escrow is the note's ECC).
    /// `model_hash` is derived from `frame_model`. Returns the backend and a `RealNote`(handover decryption).
    #[allow(clippy::too_many_arguments)]
    pub fn from_provisioned(
        manifest_path: &str,
        note_addr: &str,
        note_secret_hex: &str,
        frame_model: &str,
        max_price_per_tick: u128,
        ticks: u128,
        escrow: u128,
    ) -> Result<(Self, RealNote)> {
        // Issue(track 1): reject an insufficient escrow BEFORE any network call -- otherwise the book
        // accepts the SHELL and orphans it(no match, no bid, no refund). Fail-fast instead of a silent loss.
        check_buy_deposit_headroom(escrow, ticks, max_price_per_tick)
            .map_err(|e| anyhow!("{e}"))?;
        let chain = RealChainBackend::connect(manifest_path)?;
        let note =
            Address::parse(note_addr).map_err(|e| anyhow!("--note-addr {note_addr}: {e}"))?;
        let keys = KeyPair::from_secret_hex(note_secret_hex.trim())
            .map_err(|e| anyhow!("--note-key (SDK secret hex): {e:?}"))?;
        let rn = RealNote::from_secret_hex(note_secret_hex)
            .map_err(|e| anyhow!("--note-key invalid ed25519 seed: {e}"))?;
        let backend = Self::new(
            chain,
            note,
            keys,
            model_hash_for(frame_model),
            TICK_SIZE,
            max_price_per_tick,
            ticks,
            escrow,
        );
        Ok((backend, rn))
    }

    async fn require_tc_gas(&self, tc: &Address) -> Result<(), ChainError> {
        let balance = self
            .chain
            .active_native_balance(tc)
            .await
            .map_err(map_err)?;
        if balance <= crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL {
            return Err(ChainError::Chain(format!(
                "TokenContract {tc} native balance {balance} is at/below gas-health floor \
                 {}; seller-side top-up is required before this buyer-only write",
                crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL
            )));
        }
        Ok(())
    }

    async fn orderbook_snapshot(&self) -> Result<OrderBookSnapshot, ChainError> {
        self.chain
            .inference_orderbook_snapshot_for_note(
                &self.note,
                &self.model_hash,
                &self.model_hash,
                self.tick_size,
            )
            .await
            .map_err(map_err)
    }

    /// One complete model-buy read/preflight attempt. Retry ownership belongs to the CLI's
    /// `buyer_quote_selection` boundary; this backend seam must never add another retry loop.
    async fn model_buy_preflight_selection_once(
        &self,
        ticks: u128,
        max_price_per_tick: u128,
    ) -> Result<(String, OrderBookOrder), ChainError> {
        let snapshot = self.orderbook_snapshot().await?;
        let selected = self
            .chain
            .submit_safe_model_buy_ask(&snapshot, ticks, max_price_per_tick)
            .await
            .map_err(map_err)?;
        Ok((snapshot.order_book, selected))
    }

    async fn assert_expected_buy_target(
        &self,
        tc: &Address,
        ticks: u128,
        max_price_per_tick: u128,
    ) -> Result<String, ChainError> {
        let snapshot = self.orderbook_snapshot().await?;
        let asks: Vec<OrderBookOrder> = snapshot.resting_asks().cloned().collect();
        let want = tc.with_workchain().to_ascii_lowercase();
        check_expected_buy_target(&asks, &want, max_price_per_tick, ticks).map_err(|e| {
            ChainError::Chain(format!(
                "buyer target preflight failed for InferenceOrderBook {}: {e}. IOB stats {}",
                snapshot.order_book,
                snapshot
                    .stats
                    .map(|s| format!("{s:?}"))
                    .unwrap_or_else(|| "<book not active>".to_string())
            ))
        })?;
        Ok(snapshot.order_book)
    }

    async fn assert_selected_tc_unused(
        &self,
        token_contract: &str,
        order_book: &str,
    ) -> Result<(), ChainError> {
        let tc = parse_tc(&token_contract.to_string())?;
        let state = self
            .chain
            .token_contract_deal_state(&tc)
            .await
            .map_err(map_err)?;
        check_selected_token_contract_unused(token_contract, state).map_err(|e| {
            ChainError::Chain(format!(
                "buyer selected-TC preflight failed for InferenceOrderBook {order_book}: {e}"
            ))
        })
    }
}

#[async_trait]
impl ChainBackend for RealBuyerBackend {
    async fn deal_snapshot(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<DealChainSnapshot>, ChainError> {
        let tc = parse_tc(token_contract)?;
        self.chain
            .token_contract_deal_snapshot(&tc)
            .await
            .map_err(map_err)
    }

    fn model_buy_order_book_identity(&self) -> Option<String> {
        RealChainBackend::canonical_inference_orderbook_address(&self.model_hash)
            .ok()
            .map(|address| address.with_workchain())
    }

    async fn discover_offers(&self) -> Result<Vec<crate::chain::OfferListing>, ChainError> {
        // Reading the per-model book from the chain: the address is derived from `model_hash`,
        // each offer carries its own `tokenContract`. The book is not active -> no offers.
        let snapshot = self.orderbook_snapshot().await?;
        let asks = self
            .chain
            .executable_resting_asks(&snapshot)
            .await
            .map_err(map_err)?;
        Ok(asks
            .iter()
            .map(|ask| crate::chain::OfferListing {
                seller_id: ask.owner_note.clone(),
                token_contract: ask.token_contract.clone().unwrap_or_default(),
                price_per_tick: ask.price_per_tick.min(Shell::MAX as u128) as Shell,
                max_ticks: ask.ticks.min(u64::MAX as u128) as u64,
            })
            .collect())
    }

    async fn post_offer(&self, offer: SellOffer, _note: &dyn Note) -> Result<(), ChainError> {
        Err(wrong_role("post_offer", "seller"))
            .map_err(|e| ChainError::Chain(format!("{e} (TC {})", offer.token_contract)))
    }

    async fn place_buy(
        &self,
        token_contract: &TokenContract,
        _note: &dyn Note,
    ) -> Result<(), ChainError> {
        let expected = parse_tc(token_contract)?;
        self.require_tc_gas(&expected).await?;
        // (branch-3 guard): fail closed if this note's on-chain owner key (`getDetails().ephemeralPubkey`)
        // is not the `--note-key` we sign `placeInferenceBuy` with -- otherwise `onlyOwnerPubkey` reverts
        // pre-accept(ERR_INVALID_SENDER 101) and the buyer silently 300s-times out in `read_match`.
        self.chain
            .assert_note_owner_matches("buyer place_buy", &self.note, &self.keys)
            .await
            .map_err(map_err)?;
        self.chain
            .assert_note_can_place_inference_buy(&self.note)
            .await
            .map_err(map_err)?;
        // `placeInferenceBuy` is model-book-wide and cannot name a target TC. Fail before moving escrow
        // unless the book's price->time matcher would fund the TC from this market manifest.
        let order_book = self
            .assert_expected_buy_target(&expected, self.ticks, self.max_price_per_tick)
            .await?;
        let expected_tc = expected.with_workchain();
        self.assert_selected_tc_unused(&expected_tc, &order_book)
            .await?;
        let deadline = canonical_cli_buy_deadline("buyer place_buy")?;
        // A limit buy by `model_hash`; the book matches the preflighted ask and funds the seller's TC
        // (`fundFromOrderBook`).
        self.chain
            .place_inference_buy(
                &self.note,
                &self.keys,
                &self.model_hash,
                self.max_price_per_tick,
                self.ticks,
                self.escrow,
                0,
                deadline,
            )
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn assert_model_buy_matches_executable_quote(
        &self,
        ticks: u128,
        max_price_per_tick: u128,
    ) -> Result<(), ChainError> {
        self.model_buy_preflight_selection_once(ticks, max_price_per_tick)
            .await
            .map(|_| ())
    }

    async fn submit_safe_model_buy_quote_order(
        &self,
        ticks: u128,
        max_price_per_tick: u128,
    ) -> Result<Option<OrderBookOrder>, ChainError> {
        self.model_buy_preflight_selection_once(ticks, max_price_per_tick)
            .await
            .map(|(_, selected)| Some(selected))
    }

    async fn assert_explicit_buy_matches_executable_quote(
        &self,
        token_contract: &TokenContract,
        ticks: u128,
        max_price_per_tick: u128,
    ) -> Result<(), ChainError> {
        let expected = parse_tc(token_contract)?;
        self.require_tc_gas(&expected).await?;
        self.chain
            .assert_note_owner_matches(
                "buyer explicit-token quote preflight",
                &self.note,
                &self.keys,
            )
            .await
            .map_err(map_err)?;
        let order_book = self
            .assert_expected_buy_target(&expected, ticks, max_price_per_tick)
            .await?;
        let expected_tc = expected.with_workchain();
        self.assert_selected_tc_unused(&expected_tc, &order_book)
            .await
    }

    async fn submit_safe_explicit_buy_quote_order(
        &self,
        token_contract: &TokenContract,
        ticks: u128,
        max_price_per_tick: u128,
    ) -> Result<Option<OrderBookOrder>, ChainError> {
        let expected = parse_tc(token_contract)?;
        self.require_tc_gas(&expected).await?;
        self.chain
            .assert_note_owner_matches(
                "buyer explicit-token quote preflight",
                &self.note,
                &self.keys,
            )
            .await
            .map_err(map_err)?;
        let snapshot = self.orderbook_snapshot().await?;
        let asks: Vec<OrderBookOrder> = snapshot.resting_asks().cloned().collect();
        let expected_tc = expected.with_workchain();
        let want = expected_tc.to_ascii_lowercase();
        check_expected_buy_target(&asks, &want, max_price_per_tick, ticks).map_err(|e| {
            ChainError::Chain(format!(
                "buyer target preflight failed for InferenceOrderBook {}: {e}. IOB stats {}",
                snapshot.order_book,
                orderbook_stats_for_error(&snapshot)
            ))
        })?;
        let selected = self
            .chain
            .submit_safe_model_buy_ask(&snapshot, ticks, max_price_per_tick)
            .await
            .map_err(map_err)?;
        if !selected
            .token_contract
            .as_deref()
            .is_some_and(|tc| tc.eq_ignore_ascii_case(&expected_tc))
        {
            return Err(ChainError::Chain(format!(
                "buyer target preflight failed for InferenceOrderBook {}: submit-safe executable quote selected {}, \
                 not expected tokenContract {}. IOB stats {}",
                snapshot.order_book,
                describe_buy_ask(&selected),
                expected_tc,
                orderbook_stats_for_error(&snapshot)
            )));
        }
        self.assert_selected_tc_unused(&expected_tc, &snapshot.order_book)
            .await?;
        Ok(Some(selected))
    }

    fn requires_submit_safe_single_ask_quote(&self) -> bool {
        true
    }

    /// Model-only buy(no pre-known TC): the buyer derives the book from `--frame-model` and places a limit
    /// buy by `model_hash`, accepting whatever resting ask the book's price->time matcher fills. The matched
    /// per-deal `TokenContract` is learned afterwards from this note's own fill event
    /// ([`Self::wait_matched_token_contract`]) -- so the buyer needs only the model name, no seller hand-off.
    async fn place_buy_by_model(
        &self,
        _note: &dyn Note,
        ticks: u128,
        max_price_per_tick: u128,
        escrow: u128,
        flags: u8,
        deadline: u64,
    ) -> Result<(), ChainError> {
        // The contract intentionally permits `deadline == 0` as GTC. The dexdo CLI is stricter: reject GTC,
        // present, and past deadlines before any money-moving POST.
        validate_cli_buy_deadline("buyer place_buy_by_model", deadline)?;
        check_buy_deposit_headroom(escrow, ticks, max_price_per_tick).map_err(ChainError::Chain)?;
        // Same owner-key guard as `place_buy`: the on-chain note owner must be the `--note-key` we sign
        // `placeInferenceBuy` with, else `onlyOwnerPubkey` reverts pre-accept(ERR_INVALID_SENDER 101).
        self.chain
            .assert_note_owner_matches("buyer place_buy_by_model", &self.note, &self.keys)
            .await
            .map_err(map_err)?;
        self.chain
            .assert_note_can_place_inference_buy(&self.note)
            .await
            .map_err(map_err)?;
        // This fresh pre-submit safety check is one attempt only. In particular it must not
        // multiply the CLI's bounded quote retry, and the money-moving call below is never retried.
        let (order_book, selected) = self
            .model_buy_preflight_selection_once(ticks, max_price_per_tick)
            .await?;
        let selected_tc = selected.token_contract.as_deref().ok_or_else(|| {
            ChainError::Chain(format!(
                "buyer model-only preflight failed for InferenceOrderBook {}: selected order #{} has no TokenContract",
                order_book, selected.order_id
            ))
        })?;
        self.assert_selected_tc_unused(selected_tc, &order_book)
            .await?;
        let expected = MatchedFill {
            order_id: selected.order_id,
            token_contract: parse_tc(&selected_tc.to_string())?.with_workchain(),
            ticks,
            price_per_tick: selected.price_per_tick,
        };
        let ob = Address::parse(&order_book).map_err(|e| {
            ChainError::Chain(format!(
                "buyer model-only preflight returned invalid InferenceOrderBook {order_book}: {e}"
            ))
        })?;
        // Prime the durable cursor immediately before the one money-moving submit. This consumes every
        // already-visible fill, including stale fills created in the same wall-clock second.
        let mut cursor = MatchWatchCursor::new(0);
        self.chain
            .poll_inference_filled_tcs(&self.note, &ob, true, &mut cursor)
            .await
            .map_err(map_err)?;
        self.set_pending_fill(Some(PendingBuyerFill { cursor, expected }))?;
        // The order the buyer chose after seeing the book -- NOT the backend's construction-time defaults.
        let submit = self
            .chain
            .place_inference_buy(
                &self.note,
                &self.keys,
                &self.model_hash,
                max_price_per_tick,
                ticks,
                escrow,
                flags,
                deadline,
            )
            .await
            .map_err(map_err);
        if submit.is_err() {
            self.set_pending_fill(None)?;
        }
        submit?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn place_buy_by_model_with_submit_identity(
        &self,
        _note: &dyn Note,
        quoted_order: Option<&OrderBookOrder>,
        ticks: u128,
        max_price_per_tick: u128,
        escrow: u128,
        cursor: &mut MatchWatchCursor,
        before_post: &mut (dyn FnMut(String, MatchWatchCursor, u128) -> Result<(), ChainError>
                  + Send),
    ) -> Result<(), ChainError> {
        check_buy_deposit_headroom(escrow, ticks, max_price_per_tick).map_err(ChainError::Chain)?;
        self.chain
            .assert_note_owner_matches("buyer place_buy_by_model", &self.note, &self.keys)
            .await
            .map_err(map_err)?;
        self.chain
            .assert_note_can_place_inference_buy(&self.note)
            .await
            .map_err(map_err)?;
        let (order_book, selected) = self
            .model_buy_preflight_selection_once(ticks, max_price_per_tick)
            .await?;
        crate::chain::ensure_pre_submit_quote_unchanged(quoted_order, &selected)?;
        let selected_tc = selected.token_contract.as_deref().ok_or_else(|| {
            ChainError::Chain(format!(
                "buyer model-only preflight failed for InferenceOrderBook {order_book}: selected order #{} has no TokenContract",
                selected.order_id
            ))
        })?;
        self.assert_selected_tc_unused(selected_tc, &order_book)
            .await?;
        let expected = MatchedFill {
            order_id: selected.order_id,
            token_contract: parse_tc(&selected_tc.to_string())?.with_workchain(),
            ticks,
            price_per_tick: selected.price_per_tick,
        };
        let expected_for_callback = expected.clone();
        let order_book = Address::parse(&order_book).map_err(|error| {
            ChainError::Chain(format!(
                "buyer model-only preflight returned invalid InferenceOrderBook {order_book}: {error}"
            ))
        })?;
        self.set_pending_fill(Some(PendingBuyerFill {
            cursor: MatchWatchCursor::default(),
            expected,
        }))?;
        let mut callback =
            |identity: String, final_cursor: MatchWatchCursor, note_shell_balance: u128| {
                self.set_pending_fill(Some(PendingBuyerFill {
                    cursor: final_cursor.clone(),
                    expected: expected_for_callback.clone(),
                }))?;
                before_post(identity, final_cursor, note_shell_balance).map_err(anyhow::Error::new)
            };
        let deadline = canonical_cli_buy_deadline("durable buyer place_buy_by_model")?;
        let result = self
            .chain
            .place_inference_buy_with_submit_identity(
                &self.note,
                &self.keys,
                &order_book,
                &self.model_hash,
                max_price_per_tick,
                ticks,
                escrow,
                0,
                deadline,
                cursor,
                &mut callback,
            )
            .await
            .map_err(map_err);
        if result
            .as_ref()
            .is_err_and(|error| !matches!(error, ChainError::AmbiguousSubmit(_)))
        {
            self.set_pending_fill(None)?;
        }
        result.map(|_| ())
    }

    async fn poll_matched_model_buys_for_order_book(
        &self,
        order_book: &str,
        cursor: &mut MatchWatchCursor,
    ) -> Result<Vec<MatchedFill>, ChainError> {
        let order_book = Address::parse(order_book).map_err(|error| {
            ChainError::Chain(format!(
                "buyer recovery has invalid InferenceOrderBook address {order_book}: {error}"
            ))
        })?;
        self.chain
            .poll_inference_filled_tcs(&self.note, &order_book, true, cursor)
            .await
            .map_err(map_err)
    }

    async fn poll_attributed_model_buys_for_order_book(
        &self,
        order_book: &str,
        cursor: &mut MatchWatchCursor,
    ) -> Result<Vec<(u128, MatchedFill)>, ChainError> {
        let order_book = Address::parse(order_book).map_err(|error| {
            ChainError::Chain(format!(
                "subscription recovery has invalid InferenceOrderBook address {order_book}: {error}"
            ))
        })?;
        self.chain
            .poll_inference_attributed_fills(&self.note, &order_book, cursor)
            .await
            .map_err(map_err)
    }

    async fn accept_probe(&self, token_contract: &TokenContract) -> Result<(), ChainError> {
        // `acceptProbe` is `onlyOwnerPubkey(_sellerPubkey)`.
        let _ = token_contract;
        Err(wrong_role("accept_probe", "seller"))
    }

    async fn claim_tokens(
        &self,
        token_contract: &TokenContract,
        _note: &dyn Note,
        _cumulative_tokens: u128,
    ) -> Result<(), ChainError> {
        // `claimTokens` is `onlyOwnerPubkey(_sellerPubkey)` -- a buyer cannot assert consumption.
        let _ = token_contract;
        Err(wrong_role("claim_tokens", "seller"))
    }

    async fn subscription_placements_since(
        &self,
        order_book: &str,
        buyer_note: &str,
        order_id_floor: u128,
        max_price_per_tick: u128,
        ticks: u128,
    ) -> Result<Vec<crate::chain::InferenceSubscriptionPlacement>, ChainError> {
        let order_book = Address::parse(order_book).map_err(|error| {
            ChainError::Chain(format!(
                "subscription recovery has invalid InferenceOrderBook address {order_book}: {error}"
            ))
        })?;
        let buyer_note = Address::parse(buyer_note).map_err(|error| {
            ChainError::Chain(format!(
                "subscription recovery has invalid buyer note address {buyer_note}: {error}"
            ))
        })?;
        self.chain
            .inference_subscription_placements_since(
                &order_book,
                &buyer_note,
                order_id_floor,
                max_price_per_tick,
                ticks,
            )
            .await
            .map_err(map_err)
    }

    async fn buyer_order_is_active_for_owner(
        &self,
        order_book: &str,
        order_id: u128,
        buyer_note: &str,
    ) -> Result<bool, ChainError> {
        let order_book = Address::parse(order_book).map_err(|error| {
            ChainError::Chain(format!(
                "buyer order recovery has invalid InferenceOrderBook address {order_book}: {error}"
            ))
        })?;
        self.chain
            .inference_buyer_order_is_active_for_owner(&order_book, order_id, buyer_note)
            .await
            .map_err(map_err)
    }

    /// Learn the matched per-deal `TokenContract` from THIS note's owner-facing `InferenceFilledConfirmed`
    /// ext-out: derive the per-model book from `model_hash`, then read the note's own
    /// fill event for this book's BUY side. No shared-book index.
    async fn wait_matched_token_contract(
        &self,
        since_unix: i64,
        timeout: std::time::Duration,
    ) -> Result<Option<MatchedFill>, ChainError> {
        let ob = self
            .chain
            .inference_orderbook_address(&self.note, &self.model_hash, self.tick_size)
            .await
            .map_err(map_err)?;
        let pending = self.take_pending_fill()?;
        let mut cursor = pending
            .as_ref()
            .map(|pending| pending.cursor.clone())
            .unwrap_or_else(|| MatchWatchCursor::new(since_unix));
        let fill = self
            .chain
            .wait_inference_filled_tc(
                &self.note,
                &ob,
                since_unix,
                timeout,
                &mut cursor,
                pending.as_ref().map(|pending| &pending.expected),
            )
            .await
            .map_err(map_err)?;
        Ok(Some(fill))
    }

    async fn assert_model_only_resume_target(
        &self,
        token_contract: &TokenContract,
    ) -> Result<(), ChainError> {
        let tc = parse_tc(token_contract)?;
        let snapshot = self.orderbook_snapshot().await?;
        let state = self
            .chain
            .token_contract_deal_state(&tc)
            .await
            .map_err(map_err)?;
        let model_name = self
            .chain
            .token_contract_model_name(&tc)
            .await
            .map_err(map_err)?;
        let model_hash = self
            .chain
            .token_contract_model_hash(&tc)
            .await
            .map_err(map_err)?;
        let buyer_note = self
            .chain
            .token_contract_buyer_note(&tc)
            .await
            .map_err(map_err)?
            .map(|a| a.with_workchain());
        let buyer_pubkey = self
            .chain
            .token_contract_buyer_pubkey(&tc)
            .await
            .map_err(map_err)?;
        let active_order_book = snapshot.active().then_some(snapshot.order_book.as_str());
        let expected_buyer_pubkey = keypair_ed_pubkey(&self.keys).map_err(map_err)?;
        validate_model_only_resume_facts(
            token_contract,
            ModelOnlyResumeFacts {
                state,
                model_name: model_name.as_deref(),
                model_hash: model_hash.as_deref(),
                buyer_note: buyer_note.as_deref(),
                buyer_pubkey: buyer_pubkey.as_ref(),
                order_book: active_order_book,
            },
            &self.model_hash,
            &self.note.with_workchain(),
            &expected_buyer_pubkey,
            now_secs(),
        )
    }

    async fn read_match(&self, token_contract: &TokenContract) -> Result<Match, ChainError> {
        let _ = token_contract;
        Err(wrong_role("read_match", "seller"))
    }

    async fn open_stream(
        &self,
        token_contract: &TokenContract,
        _enc_endpoint: Vec<u8>,
        _note: &dyn Note,
    ) -> Result<(), ChainError> {
        let _ = token_contract;
        Err(wrong_role("open_stream", "seller"))
    }

    async fn read_handover(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<Vec<u8>>, ChainError> {
        let tc = parse_tc(token_contract)?;
        self.chain.read_handover(&tc).await.map_err(map_err)
    }

    async fn stop(
        &self,
        token_contract: &TokenContract,
        _note: &dyn Note,
    ) -> Result<Settlement, ChainError> {
        let tc = parse_tc(token_contract)?;
        explicit_buyer_stop_with(&self.chain, &self.note, &self.keys, &tc, || {
            self.require_tc_gas(&tc)
        })
        .await
    }

    async fn stop_if_heartbeat(
        &self,
        token_contract: &TokenContract,
        _note: &dyn Note,
        heartbeat: &crate::chain::HeartbeatGuard,
    ) -> Result<Option<Settlement>, ChainError> {
        let tc = parse_tc(token_contract)?;
        self.require_tc_gas(&tc).await?;
        let mut heartbeat_unchanged = || heartbeat.unchanged();
        let receipt = self
            .chain
            .stop_if_heartbeat(&self.note, &self.keys, &tc, &mut heartbeat_unchanged)
            .await
            .map_err(map_err)?;
        Ok(receipt.map(|receipt| Settlement::AuthoritativeReceipt(Box::new(receipt))))
    }

    async fn dispute(
        &self,
        token_contract: &TokenContract,
        _note: &dyn Note,
    ) -> Result<Settlement, ChainError> {
        let tc = parse_tc(token_contract)?;
        self.require_tc_gas(&tc).await?;
        let receipt = self
            .chain
            .stream_dispute(&self.note, &self.keys, &tc)
            .await
            .map_err(map_err)?;
        Ok(Settlement::AuthoritativeReceipt(Box::new(receipt)))
    }

    async fn release_dispute(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Settlement, ChainError> {
        let _ = token_contract;
        Err(wrong_role("release_dispute", "seller"))
    }

    async fn cleanup_unopened(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Settlement, ChainError> {
        let tc = parse_tc(token_contract)?;
        let state = tc_settle_state(&self.chain, &tc).await.map_err(map_err)?;
        self.require_tc_gas(&tc).await?;
        self.chain
            .stream_cleanup(&self.note, &self.keys, &tc)
            .await
            .map_err(map_err)?;
        for _ in 0..crate::params::CLEANUP_UNOPENED_CONFIRM_MAX_READS {
            match self
                .chain
                .token_contract_deal_state(&tc)
                .await
                .map_err(map_err)?
            {
                None => {
                    return Ok(Settlement::SellerNoShow {
                        to_buyer_refund: state.deposit,
                        seller_bond_returned: state.seller_bond,
                    });
                }
                Some(st) if !st.funded => {
                    return Ok(Settlement::SellerNoShow {
                        to_buyer_refund: state.deposit,
                        seller_bond_returned: state.seller_bond,
                    });
                }
                Some(_) => {
                    tokio::time::sleep(crate::params::CLEANUP_UNOPENED_CONFIRM_POLL_INTERVAL).await
                }
            }
        }
        Err(ChainError::Chain(format!(
            "TC {tc}: cleanupUnopened did not clear funded state within the allotted time"
        )))
    }

    async fn deal_state(
        &self,
        token_contract: &TokenContract,
    ) -> Result<Option<DealChainState>, ChainError> {
        Ok(self
            .deal_snapshot(token_contract)
            .await?
            .map(|snapshot| snapshot.state))
    }

    async fn snapshot(&self, token_contract: &TokenContract) -> Option<StreamSnapshot> {
        real_tc_snapshot(&self.chain, token_contract).await
    }
}

#[cfg(test)]
mod cleanup_observer_tests {
    use super::*;

    #[tokio::test]
    async fn delayed_cleanup_visibility_accepts_absent_or_unfunded_after_present_read() {
        let decoded =
            |value: Value| DealChainState::decode_getter(&value).expect("exact test state");
        let terminals: [Option<DealChainState>; 2] = [
            None,
            Some(decoded(test_get_state(false, false, false, false, 0, 0, 0))),
        ];
        for terminal in terminals {
            let mut reads: std::array::IntoIter<Option<DealChainState>, 2> = [
                Some(decoded(test_get_state(true, false, false, false, 10, 0, 0))),
                terminal,
            ]
            .into_iter();
            let outcome = wait_cleanup_unopened_with(
                "test-tc",
                || std::future::ready(Ok(reads.next().expect("observer read"))),
                || std::future::ready(()),
            )
            .await;
            assert!(outcome.is_ok(), "terminal cleanup state must succeed");
        }
    }

    #[tokio::test]
    async fn bounded_still_funded_window_is_ambiguous_instead_of_success_or_hang() {
        let state =
            DealChainState::decode_getter(&test_get_state(true, false, false, false, 10, 0, 0))
                .expect("exact test state");
        let mut reads = std::iter::repeat_n(Some(state), 40);
        let outcome = wait_cleanup_unopened_with(
            "test-tc",
            || std::future::ready(Ok(reads.next().expect("observer read"))),
            || std::future::ready(()),
        )
        .await;
        let error = outcome.expect_err("40 funded reads must not report cleanup success");
        assert!(
            error.to_string().contains("bounded-ambiguous"),
            "observer must return the explicit bounded-ambiguous outcome: {error}"
        );
    }
}

#[cfg(test)]
mod note_tests {
    use super::*;
    use crate::note::verify;

    /// Offline(no chain/keys): the SDK `KeyPair`(ed25519) signature is verified by dexdo `verify`
    /// and the x25519 handover round-trips.
    #[test]
    fn real_note_sign_verifies_and_handover_roundtrips() {
        let note = RealNote::generate();
        let msg = b"stream-session-challenge";
        let sig = note.sign(msg);
        assert!(
            verify(&note.pubkey(), msg, &sig),
            "the SDK KeyPair ed25519 signature is verified by dexdo-verify"
        );

        let buyer = RealNote::generate();
        let ct = note.encrypt_to(&buyer.pubkey(), b"https://gw:443|fingerprint");
        assert_eq!(buyer.decrypt(&ct).unwrap(), b"https://gw:443|fingerprint");
    }
}

#[cfg(test)]
mod codecell_tests {
    use super::*;

    /// Offline(no network): extracting the code-cell from the embedded `.tvc` works -- `InferenceOrderBook`
    /// yields a non-empty base64-BOC(the `code` argument for deploying the book) and a stable 32-byte
    /// code-hash; `PrivateNote.tvc` also parses. Meaning a book deploy will not hit the chain codec.
    #[test]
    fn tvc_code_cell_extraction() {
        let ob_code = RealChainBackend::inference_orderbook_code_b64().expect("OB code b64");
        assert!(!ob_code.is_empty(), "OB code-cell base64 is non-empty");
        let ob_hash = code_hash(INFERENCE_ORDERBOOK_TVC).expect("OB code hash");
        assert_eq!(ob_hash.len(), 64, "code-hash -- 32 bytes in hex");
        let pn_hash = code_hash(PRIVATENOTE_TVC).expect("PN code hash");
        assert_eq!(pn_hash.len(), 64);
        println!("InferenceOrderBook code_hash = {ob_hash}");
        println!("PrivateNote        code_hash = {pn_hash}");
    }

    /// pure regression: stale binary pins fail loud with actionable text, while matching pins pass.
    #[test]
    fn doctor_code_hash_compare_flags_stale_binary() {
        let ok = code_hash_check(
            "TokenContract code hash",
            None,
            ROOTMODEL_PINNED_TC_CODE_HASH,
            Some(ROOTMODEL_PINNED_TC_CODE_HASH),
        );
        assert_eq!(ok.status, ShellnetDoctorStatus::Pass);

        let stale = code_hash_check(
            "TokenContract code hash",
            None,
            ROOTMODEL_PINNED_TC_CODE_HASH,
            Some("0000000000000000000000000000000000000000000000000000000000000001"),
        );
        assert_eq!(stale.status, ShellnetDoctorStatus::Fail);
        assert!(stale.message.contains("STALE"), "{}", stale.message);
        assert!(
            stale.message.contains("rebuild from dev HEAD"),
            "{}",
            stale.message
        );
    }

    /// pure regression: manifest freshness is a fail-closed active-account check.
    #[test]
    fn doctor_manifest_active_check_fails_stale_manifest() {
        let addr =
            Address::parse("0:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .expect("addr");
        let fresh = active_check("market TokenContract state", &addr, true);
        assert_eq!(fresh.status, ShellnetDoctorStatus::Pass);
        let stale = active_check("market TokenContract state", &addr, false);
        assert_eq!(stale.status, ShellnetDoctorStatus::Fail);
        assert!(stale.message.contains("inactive"), "{}", stale.message);
    }

    /// regression: the deploy-send 404 tolerance is SPECIFIC to the BK `/v2/account` lookup (a
    /// funded-uninit deploy target), NOT a blanket "contains 404". A 404 from any other URL/cause, or
    /// any non-404 error, must classify as NOT-uninit so it propagates as a real error -- and so the
    /// self-dapp fallback can only ever flip routing for the funded-uninit deploy case.
    #[test]
    fn uninit_account_404_is_specific() {
        // The exact reqwest error `fetch_dapp_id` produces on a funded-uninit deploy target -> uninit.
        assert!(is_uninit_account_404(
            "HTTP status client error (404 Not Found) for url \
             (https://shellnet.ackinacki.org/v2/account?account_id=6606&dapp_id=6606)"
        ));
        // A 404 from a DIFFERENT endpoint is NOT the uninit-account case -> must propagate.
        assert!(!is_uninit_account_404(
            "HTTP status client error (404 Not Found) for url (https://shellnet.ackinacki.org/v2/messages)"
        ));
        // A non-404 error on `/v2/account`(transport/5xx) is NOT uninit -> must propagate.
        assert!(!is_uninit_account_404(
            "HTTP status server error (502 Bad Gateway) for url \
             (https://shellnet.ackinacki.org/v2/account?account_id=x&dapp_id=x)"
        ));
        assert!(!is_uninit_account_404(
            "transport error: connection refused"
        ));
        assert!(!is_uninit_account_404(""));
    }

    /// regression: an active contract at or below the gas-health floor must get topped up before the
    /// next RootModel/TC poke; above the floor it is left alone.
    #[test]
    fn gas_health_top_up_is_thresholded_and_targets_working_level() {
        assert_eq!(
            gas_health_top_up_amount(
                crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL - 1,
                crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL,
                crate::params::ACTIVE_CONTRACT_GAS_HEALTH_TARGET_NANOVMSHELL,
            ),
            Some(
                crate::params::ACTIVE_CONTRACT_GAS_HEALTH_TARGET_NANOVMSHELL
                    - (crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL - 1)
            )
        );
        assert_eq!(
            gas_health_top_up_amount(
                crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL,
                crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL,
                crate::params::ACTIVE_CONTRACT_GAS_HEALTH_TARGET_NANOVMSHELL,
            ),
            Some(
                crate::params::ACTIVE_CONTRACT_GAS_HEALTH_TARGET_NANOVMSHELL
                    - crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL
            )
        );
        assert_eq!(
            gas_health_top_up_amount(
                crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL + 1,
                crate::params::ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL,
                crate::params::ACTIVE_CONTRACT_GAS_HEALTH_TARGET_NANOVMSHELL,
            ),
            None
        );
    }

    /// (offline): the `RealNote` x25519 handover is derived from its ed25519 -- the seller **reconstructs
    /// the buyer's pubkey from on-chain `getBuyerPubkey`(ed25519)**, no separate x25519 channel is needed.
    /// This removes the per-role blocker: the seller encrypts the handover to the pubkey recovered from the chain.
    #[test]
    fn realnote_x25519_handover_derives_from_ed25519() {
        use crate::note::{verify, x25519_pub_from_ed25519_pub, NotePubkey};
        // F2: pin the SDK-seed INVARIANT -- `from_keypair` slices
        // `secret_hex()[..32]`, assuming it is the ed25519 seed. If the SDK changes the secret format,
        // the handover derivation from ed will become silently incorrect. So we check explicitly that
        // `SigningKey::from_bytes(seed).verifying_key() == public_hex()` BEFORE building the note --
        // the invariant must survive any refactor of the test.
        let keypair = KeyPair::generate();
        let seed_bytes =
            decode_hex(keypair.secret_hex().trim_start_matches("0x")).expect("secret hex");
        assert!(seed_bytes.len() >= 32, "SDK ed25519 secret >= 32 bytes");
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes[..32]);
        let sdk_pub =
            decode_hex(keypair.public_hex().trim_start_matches("0x")).expect("public hex");
        assert_eq!(
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes()[..],
            sdk_pub[..],
            "SDK invariant: secret_hex()[..32] is the ed25519 seed (its verifying_key == public_hex())"
        );

        let note = RealNote::from_keypair(keypair).expect("real note from valid SDK keypair");
        let pk = note.pubkey();
        // The handover's x25519 == Montgomery(ed25519) -> reconstructible from on-chain ed25519.
        assert_eq!(
            x25519_pub_from_ed25519_pub(&pk.ed),
            Some(pk.x),
            "x25519 is derived from the note's ed25519"
        );
        // Round-trip through the pubkey RECONSTRUCTED from ed(the seller's path from getBuyerPubkey):
        let recon_x = x25519_pub_from_ed25519_pub(&pk.ed).unwrap();
        let seller = RealNote::generate();
        let ct = seller.encrypt_to(
            &NotePubkey {
                x: recon_x,
                ed: pk.ed,
            },
            b"endpoint|fp",
        );
        assert_eq!(
            note.decrypt(&ct).unwrap(),
            b"endpoint|fp",
            "round-trip through the x25519 reconstructed from ed25519"
        );
        // The challenge on the same ed25519 note key -- the signature verifies.
        let sig = note.sign(b"challenge");
        assert!(
            verify(&pk, b"challenge", &sig),
            "the note's ed25519 signature"
        );
    }

    /// Offline guard for step 2: the embedded `TokenContract.tvc` code-hash matches the
    /// `RootModel.TOKEN_CONTRACT_CODE_HASH` pin. Otherwise the TC deploy is useless -- RootModel rejects
    /// the deal registration(the derived address won't match `msg.sender`). Catches a desync between the
    /// embedded image and the RootModel deployed on shellnet BEFORE any write.
    #[test]
    fn token_contract_code_hash_matches_rootmodel_pin() {
        let tc_hash = code_hash(TOKENCONTRACT_TVC).expect("TC code hash");
        println!("TokenContract code_hash = {tc_hash}");
        println!("RootModel pinned        = {ROOTMODEL_PINNED_TC_CODE_HASH}");
        assert_eq!(
            tc_hash, ROOTMODEL_PINNED_TC_CODE_HASH,
            "TokenContract.tvc code-hash must == RootModel.TOKEN_CONTRACT_CODE_HASH"
        );

        // RootModel.tvc code-hash == SuperRoot.ROOT_MODEL_CODE_HASH -- otherwise SuperRoot rejects
        // registerRoot and the seller cannot provision their RootModel.
        let rm_hash = code_hash(ROOTMODEL_TVC).expect("RM code hash");
        println!("RootModel code_hash = {rm_hash}");
        println!("SuperRoot pinned    = {SUPERROOT_PINNED_RM_CODE_HASH}");
        assert_eq!(
            rm_hash, SUPERROOT_PINNED_RM_CODE_HASH,
            "RootModel.tvc code-hash must == SuperRoot.ROOT_MODEL_CODE_HASH"
        );
    }

    /// offline guard for `assert_seller_note_current`: the embedded `PrivateNote.tvc` code-hash matches
    /// the deployed 4.0.28 PrivateNote. The runtime guard rejects a note whose on-chain `code_hash` !=
    /// `code_hash(PRIVATENOTE_TVC)`; if the embedded image drifted from the deployed code this pin breaks,
    /// warning that the guard would false-reject valid fresh notes. Keeps the guard's baseline honest.
    #[test]
    fn private_note_code_hash_matches_deployed_pin() {
        let pn_hash = code_hash(PRIVATENOTE_TVC).expect("PN code hash");
        println!("PrivateNote code_hash = {pn_hash}");
        println!("deployed pinned       = {PRIVATENOTE_PINNED_CODE_HASH}");
        assert_eq!(
            pn_hash, PRIVATENOTE_PINNED_CODE_HASH,
            "embedded PrivateNote.tvc code-hash must == deployed 4.0.28 PrivateNote (else the  guard false-rejects)"
        );
    }

    /// the offline code_hash gate behind `assert_seller_note_current` (now also enforced
    /// on the seller-daemon offer-publish path via `RealSellerBackend::assert_note_current`). A note whose
    /// on-chain code_hash != the pinned current PrivateNote -- orphaned by a redeploy, e.g. the live `00028b50...`
    /// 4.0.8-era note probed for -- is rejected with an actionable "re-mint" message; the current pin passes.
    #[test]
    fn note_code_hash_current_rejects_stale_with_remint() {
        let note =
            Address::parse("0:988322d9cbffc133b491ef09885d3811ce03a54ef5ae8ac94019bddea4d3736e")
                .expect("parse note address");
        let err = note_code_hash_current(
            &note,
            Some("00028b507121895f02de742cf6aa966af106e0e430f20a75b288f62aa068a8f6"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("Re-mint"), "{err}");
        assert!(err.contains("code_hash"), "{err}");
        // A missing code_hash(uninit/none) is also rejected fail-closed.
        assert!(note_code_hash_current(&note, None).is_err());
        // The current pinned hash passes.
        assert!(note_code_hash_current(&note, Some(PRIVATENOTE_PINNED_CODE_HASH)).is_ok());
    }

    /// the per-deal TC freshness gate behind `RealSellerBackend::assert_token_contract_fresh`.
    /// A fresh active-but-unfunded TC(all flags false, all amounts "0") is reusable -> `None`; a TC already used
    /// by a prior deal -- opened(the live 321 case) / funded / disputed / residual deposit/prepaid/frozen/finalized
    /// -- is rejected with the offending reason so the seller fails closed before `postSellOffer`.
    #[test]
    fn token_contract_used_reason_flags_used_states() {
        let decoded = |value: Value| DealChainState::decode_getter(&value).expect("exact state");
        let fresh = decoded(test_get_state(false, false, false, false, 0, 0, 0));
        assert_eq!(token_contract_used_reason(fresh), None);
        assert!(check_selected_token_contract_unused("0:fresh", Some(fresh)).is_ok());
        let unreadable = check_selected_token_contract_unused("0:missing", None)
            .expect_err("unreadable selected TC must fail closed");
        assert!(
            unreadable.contains("not readable by getState"),
            "{unreadable}"
        );
        // The live case: opened(+ funded + a held probe tick) -> used, reason names each.
        let opened = decoded(test_get_state(true, true, false, false, 0, 1_000, 0));
        let r = token_contract_used_reason(opened).expect("opened TC must be flagged used");
        assert!(r.contains("opened"), "{r}");
        assert!(r.contains("funded"), "{r}");
        assert!(r.contains("probeTick=1000"), "{r}");
        let selected = check_selected_token_contract_unused("0:used", Some(opened))
            .expect_err("used selected TC must fail closed");
        assert!(
            selected.contains("already used by chain state"),
            "{selected}"
        );
        assert!(selected.contains("funded"), "{selected}");
        // Residual deposit alone(a closed-but-not-destroyed deal) -> used.
        assert_eq!(
            token_contract_used_reason(decoded(test_get_state(
                false, false, false, false, 500, 0, 0
            )))
            .as_deref(),
            Some("deposit=500")
        );
        let mut malformed = test_get_state(false, false, false, false, 500, 0, 0);
        malformed["deposit"] = json!("0x1f4");
        assert!(check_selected_token_contract_unused(
            "0:residual",
            Some(decoded(test_get_state(
                false, false, false, false, 500, 0, 0
            )))
        )
        .expect_err("residual selected TC must fail closed")
        .contains("deposit=500"));
        assert!(
            DealChainState::decode_getter(&malformed).is_err(),
            "hex getter value must fail before selected-TC preflight"
        );
        // Disputed alone -> used.
        assert!(token_contract_used_reason(decoded(test_get_state(
            false, false, false, true, 0, 0, 0
        )))
        .unwrap()
        .contains("disputed"));

        let mut timestamp_only = fresh;
        timestamp_only.last_claim_time = 7;
        assert_eq!(
            token_contract_used_reason(timestamp_only).as_deref(),
            Some("lastClaimTime=7"),
            "a residual authoritative timestamp is evidence that the per-deal TC was used"
        );
    }

    /// resume regression: seller resume may skip `postSellOffer` for an openable funded
    /// pre-stream TC and for an active already-opened stream. Terminal, disputed, and underfunded states block.
    #[test]
    fn validate_seller_resume_state_rejects_used_stream_state() {
        let token_contract = "0:resume-state".to_string();
        let decoded = |value: Value| DealChainState::decode_getter(&value).expect("exact state");
        let pre_open = decoded(test_get_state(true, false, false, false, 10_000, 0, 0));
        assert!(validate_seller_resume_state(&token_contract, pre_open, 1000).is_ok());

        let reported_terminal = decoded(test_get_state(true, false, false, false, 0, 0, 0));
        for price_per_tick in [1, 2] {
            let r =
                validate_seller_resume_state(&token_contract, reported_terminal, price_per_tick)
                    .expect_err("terminal zero-deposit TC blocks resume")
                    .to_string();
            assert!(r.contains("deposit=0"), "{r}");
            assert!(
                r.contains(&format!("price_per_tick={price_per_tick}")),
                "{r}"
            );
            assert!(r.contains("cannot be opened"), "{r}");
        }

        let below_boundary = decoded(test_get_state(true, false, false, false, 1, 0, 0));
        assert!(
            validate_seller_resume_state(&token_contract, below_boundary, 2)
                .expect_err("deposit below price blocks resume")
                .to_string()
                .contains("deposit=1, price_per_tick=2")
        );
        assert!(validate_seller_resume_state(&token_contract, below_boundary, 1).is_ok());

        let opened = decoded(test_get_state(true, true, false, false, 0, 1_000, 0));
        assert!(validate_seller_resume_state(&token_contract, opened, 1000).is_ok());

        let stopped = decoded(test_get_state(true, false, true, false, 0, 0, 2_000));
        let r = validate_seller_resume_state(&token_contract, stopped, 1000)
            .expect_err("stopped state blocks resume")
            .to_string();
        assert!(r.contains("probeAccepted without opened"), "{r}");

        let disputed = decoded(test_get_state(true, true, false, true, 0, 1_000, 0));
        let r = validate_seller_resume_state(&token_contract, disputed, 1000)
            .expect_err("disputed state blocks resume")
            .to_string();
        assert!(r.contains("disputed"), "{r}");
    }

    #[test]
    fn outcome_confirmation_distinguishes_rested_matched_and_duplicate() {
        let rested = classify_seller_offer_outcome(
            SellerOfferEvents {
                placed_order_id: Some(835),
                ..Default::default()
            },
            false,
        )
        .expect("rested outcome");
        assert_eq!(rested, Some(SellOfferOutcome::Rested { order_id: 835 }));

        let matched = classify_seller_offer_outcome(SellerOfferEvents::default(), true)
            .expect("matched outcome");
        assert_eq!(matched, Some(SellOfferOutcome::Matched));

        let duplicate = classify_seller_offer_outcome(
            SellerOfferEvents {
                placement_value_returned: true,
                ..Default::default()
            },
            false,
        )
        .expect_err("returned placement value is a duplicate");
        assert_eq!(duplicate.to_string(), DUPLICATE_SELL_MESSAGE);
        assert!(!duplicate.to_string().contains("CHAIN_TRANSPORT"));
    }

    #[tokio::test]
    async fn transient_read_failure_retries_with_backoff() {
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let started = std::time::Instant::now();
        let outcome = retry_seller_read("test seller outcome", {
            let attempts = attempts.clone();
            move || {
                let attempt = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    if attempt == 0 {
                        Err(ChainError::Transport("timed out".to_string()))
                    } else {
                        Ok(Some(SellOfferOutcome::Rested { order_id: 7 }))
                    }
                }
            }
        })
        .await
        .expect("second read succeeds");
        assert_eq!(outcome, Some(SellOfferOutcome::Rested { order_id: 7 }));
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert!(started.elapsed() >= SELLER_READ_BACKOFF[0]);
    }

    #[tokio::test]
    async fn empty_book_slow_read_does_not_report_duplicate_tc() {
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let result = retry_seller_read("empty order book", {
            let attempts = attempts.clone();
            move || {
                let attempt = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    if attempt == 0 {
                        Err(ChainError::Transport("slow read timed out".to_string()))
                    } else {
                        Ok(SellerOfferEvents {
                            placed_order_id: Some(1),
                            ..Default::default()
                        })
                    }
                }
            }
        })
        .await
        .and_then(|events| classify_seller_offer_outcome(events, false));
        assert_eq!(
            result.unwrap(),
            Some(SellOfferOutcome::Rested { order_id: 1 })
        );
    }

    /// negative regression: a shellnet submit stall must not leave `dexdo seller` hanging forever or
    /// pretend a message hash exists. The operator gets exact TC/book context and the by-fact derivation state.
    #[test]
    fn seller_post_sell_offer_timeout_message_is_precise_and_hash_free() {
        let ob =
            Address::parse("0:6330b82c9d866f68e989d4f71c79e6f4757602c065933b7e63179b00acd9aa0e")
                .expect("ob");
        let note =
            Address::parse("0:c60ff3783e78ce3feba2236b35403639a2a434ba9f3c6c351813a87ab98c9331")
                .expect("note");
        let tc = "0:9aff5b8520caf32dbb91390134a946fc9c2896830d96b86cb0f1fbd2262dbe36";
        let msg = seller_post_sell_offer_timeout_message(
            &ob,
            tc,
            "0xe3cc0b0b5cdadfaee3d9b9adf50b489a09f2d7540cb9436ef15423fe27b91a09",
            1783558097,
            &note,
            std::time::Duration::from_secs(120),
            "RootModel expected TokenContract for (sellerPubkey, nonce) is 0:9aff5b8520caf32dbb91390134a946fc9c2896830d96b86cb0f1fbd2262dbe36 and offered token_contract is 0:9aff5b8520caf32dbb91390134a946fc9c2896830d96b86cb0f1fbd2262dbe36; match=true",
            "TokenContract 0:9aff5b8520caf32dbb91390134a946fc9c2896830d96b86cb0f1fbd2262dbe36 state evidence: Active/getState readable",
        );
        assert!(msg.contains("timed out after 120s"), "{msg}");
        assert!(
            msg.contains("no message_hash/tx_hash is available"),
            "{msg}"
        );
        assert!(msg.contains(tc), "{msg}");
        assert!(msg.contains("nonce=1783558097"), "{msg}");
        assert!(msg.contains("match=true"), "{msg}");
        assert!(msg.contains("Active/getState readable"), "{msg}");
        assert!(!msg.contains("seller offer did not rest"), "{msg}");
    }

    #[test]
    fn token_contract_abi_pins_buyer_bond_and_subscription_shape() {
        let abi: Value = serde_json::from_str(TOKENCONTRACT_ABI).expect("parse TokenContract ABI");
        let functions = abi["functions"]
            .as_array()
            .expect("TokenContract functions[]");
        let outputs = |name: &str| {
            functions
                .iter()
                .find(|function| function["name"] == name)
                .unwrap_or_else(|| panic!("TokenContract.{name} present"))["outputs"]
                .as_array()
                .unwrap_or_else(|| panic!("TokenContract.{name} outputs[]"))
                .iter()
                .map(|output| {
                    (
                        output["name"].as_str().unwrap_or(""),
                        output["type"].as_str().unwrap_or(""),
                    )
                })
                .collect::<Vec<_>>()
        };

        assert_eq!(
            outputs("getBuyerBond"),
            vec![("bondHeld", "uint128"), ("bondRequired", "uint128"),]
        );
        assert_eq!(
            outputs("getSubscription"),
            vec![
                ("dealFlags", "uint8"),
                ("subWeeks", "uint8"),
                ("weekIndex", "uint8"),
                ("tokensPerWeek", "uint128"),
                ("fundedTokens", "uint128"),
                ("tokensPaid", "uint128"),
                ("periodStart", "uint64"),
                ("weekBaseTokens", "uint128"),
            ]
        );
    }

    /// the buyer/seller pre-write owner-key gate behind `assert_note_owner_matches`. A note
    /// whose on-chain `_ephemeralPubkey` equals the client's signing pubkey (case- and `0x`-insensitive -- the
    /// getter returns `0x...`, `public_hex()` has no prefix) passes; a rotated/orphaned note (different or absent
    /// `ephemeralPubkey`) is rejected fail-closed with an actionable re-mint message naming both keys and the
    /// pre-accept `ERR_INVALID_SENDER 101` cause -- instead of the opaque pre-accept revert + silent 300s
    /// `read_match` timeout. Pure/offline(no chain, no giver).
    #[test]
    fn note_owner_mismatch_reason_flags_rotated_note() {
        let note =
            Address::parse("0:988322d9cbffc133b491ef09885d3811ce03a54ef5ae8ac94019bddea4d3736e")
                .expect("parse note address");
        let signing = "10b129e8000000000000000000000000000000000000000000000000000006a9";
        // A healthy note: the match is case- and `0x`-insensitive(getter yields `0x...`, possibly upper-case).
        let onchain_match = "0x10B129E8000000000000000000000000000000000000000000000000000006A9";
        assert_eq!(
            note_owner_mismatch_reason("buyer place_buy", &note, Some(onchain_match), signing),
            None
        );
        // A rotated/wrong owner key -> rejected fail-closed, naming both keys + the pre-accept cause + remedy.
        let rotated = "0xdeadbeef00000000000000000000000000000000000000000000000000000000";
        let err = note_owner_mismatch_reason("buyer place_buy", &note, Some(rotated), signing)
            .expect("a rotated note must be flagged");
        assert!(err.contains("Re-mint"), "{err}");
        assert!(err.contains("ERR_INVALID_SENDER 101"), "{err}");
        assert!(err.contains("_ephemeralPubkey"), "{err}");
        assert!(err.contains(signing), "{err}");
        // An absent on-chain `ephemeralPubkey`(uninit/orphaned note) is rejected fail-closed too, by role.
        let none = note_owner_mismatch_reason("seller post_offer", &note, None, signing)
            .expect("an absent ephemeralPubkey must be flagged");
        assert!(none.contains("<none>"), "{none}");
        assert!(none.contains("seller post_offer"), "{none}");
    }

    /// Offline regression for ****: the per-deal TC address is derived from the deploy INIT-DATA
    /// (stateInit), NOT the RootModel `getTokenContractAddress` getter -- so `provision_market`'s idempotency
    /// check works on a fresh provision where the RootModel is still uninit (the getter would 404 and abort
    /// the whole provision). No network, no giver. Two properties, exactly:
    /// **(a)** `token_contract_deploy_address` == `build_deploy(...).address` bit-for-bit (it IS the address the
    /// deploy creates); **(b)** it returns `Ok` against a RootModel address whose account does **not** exist
    /// on-chain -- proving the getter(and any account query) is never called.
    #[tokio::test]
    async fn token_contract_deploy_address_is_init_data_derived_and_getter_free() {
        let manifest = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/deployed.shellnet.json"
        );
        // `connect` is offline: it loads the manifest + builds client config -- no network call.
        let be = RealChainBackend::connect(manifest)
            .expect("offline connect (manifest load, no network)");
        let seller = KeyPair::generate();
        // (b) A RootModel address whose account does NOT exist on-chain -- the derivation must NOT query it.
        let never_deployed_rm =
            Address::parse("0:00000000000000000000000000000000000000000000000000000000deadbeef")
                .expect("rm addr");
        let note =
            Address::parse("0:1111111111111111111111111111111111111111111111111111111111111111")
                .expect("note addr");
        let nonce = 68u64;
        let model = "dexdo-d68-init-data-derivation";
        let (tick, price, max_ticks) = (1000u128, 100u128, 10u128);
        let abi: Value = serde_json::from_str(TOKENCONTRACT_ABI).expect("parse TokenContract ABI");
        let constructor = abi["functions"]
            .as_array()
            .expect("TokenContract functions[]")
            .iter()
            .find(|f| f["name"] == "constructor")
            .expect("TokenContract constructor present");
        let inputs: Vec<(&str, &str)> = constructor["inputs"]
            .as_array()
            .expect("constructor inputs[]")
            .iter()
            .map(|i| {
                (
                    i["name"].as_str().unwrap_or(""),
                    i["type"].as_str().unwrap_or(""),
                )
            })
            .collect();
        assert_eq!(
            inputs,
            vec![
                ("modelName", "string"),
                ("modelHash", "uint256"),
                ("pricePerTick", "uint128"),
                ("maxTicks", "uint128"),
                ("sellerNote", "address"),
            ],
            "4.0.18 TokenContract constructor is 5-arg; tickSize is a fixed getDeal() constant"
        );

        // (b) getter-free / 404-proof: succeeds against a never-deployed RootModel(no account query).
        let derived = be
            .token_contract_deploy_address(
                &seller,
                &never_deployed_rm,
                nonce,
                model,
                tick,
                price,
                max_ticks,
                &note,
            )
            .await
            .expect("Ok -- INIT-DATA derivation needs no RootModel account, no network, cannot 404");

        // (a) bit-for-bit == build_deploy(...).address -- the exact address the deploy will create.
        let ctx = local_context().expect("local ctx");
        let init_data = json!({
            "_sellerPubkey": format!("0x{}", seller.public_hex()),
            "_rootModelAddress": never_deployed_rm.with_workchain(),
            "_nonce": nonce.to_string(),
        });
        let ctor = json!({
            "modelName": model,
            "modelHash": model_hash_for(model),
            "pricePerTick": price.to_string(),
            "maxTicks": max_ticks.to_string(),
            "sellerNote": note.with_workchain(),
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
        .await
        .expect("build_deploy");
        assert_eq!(
            derived.with_workchain(),
            Address::parse(&msg.address).expect("addr").with_workchain(),
            "token_contract_deploy_address is bit-for-bit the deploy stateInit address"
        );
    }

    /// Offline selector-agreement guard. The seller posts its deal in ONE call:
    /// `PrivateNote.postSellOffer(flags, nonce, ttl)`. The note derives the canonical per-deal
    /// `TokenContract` locally and hands it the baked `InferenceOrderBook` hash via
    /// `TokenContract.postFromNote`; the TC posts the resting ask itself via
    /// `InferenceOrderBook.placeSellOffer(...)` (`msg.sender == TC`, so the book proves canonical-TC
    /// ownership without a caller-supplied `tokenContract`). No RootPN round-trip.
    /// `ttl` is the offer's mandatory lifetime: an ask commits no collateral at post time, so it
    /// must auto-expire. This guard pins the selector -- name + ordered input types, which is what the TVM
    /// function ID is derived from -- so the Rust client's `post_sell_offer` submit cannot silently drift from
    /// the deployed ABI, and asserts the superseded `confirmDeal` is gone.
    #[test]
    fn post_sell_offer_abi_selector_is_flags_nonce_ttl() {
        let abi: Value = serde_json::from_str(PRIVATENOTE_ABI).expect("parse PrivateNote ABI");
        let funcs = abi["functions"].as_array().expect("functions[]");
        let func = funcs
            .iter()
            .find(|f| f["name"] == "postSellOffer")
            .expect("postSellOffer present in the PrivateNote ABI");
        let inputs: Vec<(&str, &str)> = func["inputs"]
            .as_array()
            .expect("inputs[]")
            .iter()
            .map(|i| {
                (
                    i["name"].as_str().unwrap_or(""),
                    i["type"].as_str().unwrap_or(""),
                )
            })
            .collect();
        assert_eq!(
            inputs,
            vec![("flags", "uint8"), ("nonce", "uint64"), ("ttl", "uint64")],
            "PrivateNote.postSellOffer takes (flags, nonce, ttl); the TC posts the offer itself"
        );
        assert!(
            funcs.iter().all(|f| f["name"] != "confirmDeal"),
            "confirmDeal must be gone from the 4.0.25 PrivateNote ABI (superseded by postSellOffer + TC.postFromNote)"
        );
    }

    #[test]
    fn post_sell_offer_client_emits_only_the_single_note_call() {
        let source = include_str!("client.rs");
        let start = source
            .find("pub async fn post_sell_offer(")
            .expect("post_sell_offer client helper present");
        let body = &source[start
            ..source[start..]
                .find("/// The buyer (note) places a limit buy")
                .map(|offset| start + offset)
                .expect("post_sell_offer helper boundary present")];

        assert_eq!(
            body.matches("self.submit(").count(),
            1,
            "one external submit"
        );
        assert!(
            body.contains("self.submit(\n            note,"),
            "target is the seller note"
        );
        assert!(
            body.contains("\"postSellOffer\""),
            "target method is postSellOffer"
        );
        assert!(
            body.contains("\"flags\": flags"),
            "flags argument is emitted"
        );
        assert!(
            body.contains("\"nonce\": nonce.to_string()"),
            "nonce argument is emitted"
        );
        assert!(
            body.contains("\"ttl\": ttl.to_string()"),
            "ttl argument is emitted in seconds"
        );
        for obsolete in [
            "\"modelHash\"",
            "\"pricePerTick\"",
            "\"maxTicks\"",
            "\"tokenContract\"",
            "confirmDeal",
            "placeSellOffer",
            "postFromNote",
        ] {
            assert!(
                !body.contains(obsolete),
                "seller client must not emit obsolete submission field or handshake: {obsolete}"
            );
        }
    }

    /// offline selector guard: the live 4.0.14 client path depends on the note-level
    /// `streamCleanup(address)` wrapper and `TokenContract.getState().fundedTime` timer field.
    #[test]
    fn never_opened_cleanup_abi_surface_is_present() {
        let note_abi: Value = serde_json::from_str(PRIVATENOTE_ABI).expect("parse PrivateNote ABI");
        let cleanup = note_abi["functions"]
            .as_array()
            .expect("PrivateNote functions[]")
            .iter()
            .find(|f| f["name"] == "streamCleanup")
            .expect("PrivateNote.streamCleanup present");
        let inputs: Vec<(&str, &str)> = cleanup["inputs"]
            .as_array()
            .expect("streamCleanup inputs[]")
            .iter()
            .map(|i| {
                (
                    i["name"].as_str().unwrap_or(""),
                    i["type"].as_str().unwrap_or(""),
                )
            })
            .collect();
        assert_eq!(
            inputs,
            vec![("tokenContract", "address")],
            "PrivateNote.streamCleanup selector must stay tokenContract-only"
        );

        let tc_abi: Value =
            serde_json::from_str(TOKENCONTRACT_ABI).expect("parse TokenContract ABI");
        let cleanup = tc_abi["functions"]
            .as_array()
            .expect("TokenContract functions[]")
            .iter()
            .find(|f| f["name"] == "cleanupUnopened")
            .expect("TokenContract.cleanupUnopened present");
        assert!(
            cleanup["inputs"]
                .as_array()
                .expect("cleanupUnopened inputs[]")
                .is_empty(),
            "cleanupUnopened must have no caller-chosen payout argument"
        );
        let state = tc_abi["functions"]
            .as_array()
            .expect("TokenContract functions[]")
            .iter()
            .find(|f| f["name"] == "getState")
            .expect("TokenContract.getState present");
        let outputs: Vec<(&str, &str)> = state["outputs"]
            .as_array()
            .expect("getState outputs[]")
            .iter()
            .map(|o| {
                (
                    o["name"].as_str().unwrap_or(""),
                    o["type"].as_str().unwrap_or(""),
                )
            })
            .collect();
        assert!(
            outputs.contains(&("fundedTime", "uint64")),
            "getState must expose fundedTime for the MATCH_OPEN_TIMEOUT preflight"
        );
    }

    /// review regression: a model-only buyer chooses ticks/price after seeing the book. The real backend must
    /// re-run the escrow invariant on that final tuple immediately before the shellnet write.
    #[test]
    fn model_only_buy_revalidates_chosen_escrow_before_submit() {
        let source = include_str!("backends.rs");
        let model_only = source
            .find("async fn place_buy_by_model")
            .expect("model-only buy implementation present");
        let body = &source[model_only..];
        let check = body
            .find("check_buy_deposit_headroom(escrow, ticks, max_price_per_tick)")
            .expect("final chosen escrow is checked");
        let submit = body
            .find(".place_inference_buy(")
            .expect("model-only buy submits placeInferenceBuy");
        assert!(
            check < submit,
            "final chosen escrow/headroom must be validated before placeInferenceBuy"
        );
    }

    #[test]
    fn buyer_withdrawn_preflight_precedes_every_place_inference_buy_write() {
        let source = include_str!("backends.rs");
        let buyer_impl = source
            .find("impl ChainBackend for RealBuyerBackend")
            .expect("real buyer implementation present");
        let buyer = &source[buyer_impl..];

        for (method, submit) in [
            ("async fn place_buy(", ".place_inference_buy("),
            ("async fn place_buy_by_model(", ".place_inference_buy("),
            (
                "async fn place_buy_by_model_with_submit_identity(",
                ".place_inference_buy_with_submit_identity(",
            ),
        ] {
            let start = buyer.find(method).expect("buyer submit method present");
            let body = &buyer[start..];
            let guard = body
                .find(".assert_note_can_place_inference_buy(&self.note)")
                .expect("buyer withdrawn-state preflight present");
            let write = body.find(submit).expect("buyer money write present");
            assert!(
                guard < write,
                "{method} must reject a withdrawn note before {submit}"
            );
        }
    }

    #[test]
    fn model_buy_preflight_selection_once_performs_one_underlying_preflight() {
        let source = include_str!("backends.rs");
        let start = source
            .find("async fn model_buy_preflight_selection_once")
            .expect("model preflight seam present");
        let body = &source[start..];
        let end = body
            .find("async fn assert_expected_buy_target")
            .expect("next backend method present");
        let body = &body[..end];

        assert_eq!(body.matches("self.orderbook_snapshot().await").count(), 1);
        assert_eq!(body.matches(".submit_safe_model_buy_ask(").count(), 1);
        assert!(
            !body.contains("for ") && !body.contains("while "),
            "the one-shot backend seam must not contain an inner retry loop"
        );
    }

    /// review regression: after duplicate-TC coalescing chooses one representative ask, the real buyer must
    /// read that TC's state and fail closed on funded/opened/disputed/residual states before moving escrow.
    #[test]
    fn buyer_checks_selected_tc_state_before_submit() {
        let source = include_str!("backends.rs");
        let buyer_impl = source
            .find("impl ChainBackend for RealBuyerBackend")
            .expect("real buyer impl present");
        let buyer = &source[buyer_impl..];

        let explicit = buyer
            .find("async fn place_buy(")
            .expect("explicit TC buy implementation present");
        let explicit_body = &buyer[explicit..];
        let explicit_guard = explicit_body
            .find("assert_selected_tc_unused")
            .expect("explicit TC buy checks selected TC state");
        let explicit_submit = explicit_body
            .find(".place_inference_buy(")
            .expect("explicit TC buy submits placeInferenceBuy");
        assert!(
            explicit_guard < explicit_submit,
            "explicit TC buy must check selected TC state before placeInferenceBuy"
        );

        let model_only = buyer
            .find("async fn place_buy_by_model")
            .expect("model-only buy implementation present");
        let model_body = &buyer[model_only..];
        let selected = model_body
            .find("model_buy_preflight_selection_once")
            .expect("model-only buy records a submit-safe selected representative ask");
        let model_guard = model_body
            .find("assert_selected_tc_unused")
            .expect("model-only buy checks selected TC state");
        let model_submit = model_body
            .find(".place_inference_buy(")
            .expect("model-only buy submits placeInferenceBuy");
        assert!(
            selected < model_guard && model_guard < model_submit,
            "model-only buy must check the selected representative TC state before placeInferenceBuy"
        );
    }

    /// review regression: seller offers must be bound to the deployed TC's `getDeal` terms, not interactive
    /// or stale CLI defaults, so advertised IOB terms cannot diverge from settlement config.
    #[test]
    fn real_seller_post_offer_uses_onchain_deal_terms() {
        let source = include_str!("backends.rs");
        let seller_impl = source
            .find("impl ChainBackend for RealSellerBackend")
            .expect("real seller impl present");
        let seller = &source[seller_impl..];
        let post_offer = seller
            .find("async fn post_offer(&self, offer: SellOffer")
            .expect("real seller post_offer present");
        let body = &seller[post_offer..];
        let withdrawn = body
            .find("assert_note_can_post_sell_offer")
            .expect("post_offer checks PrivateNote hasWithdrawn");
        let terms = body
            .find("sell_offer_terms(&offer.token_contract)")
            .expect("post_offer reads on-chain deal terms");
        let submit = body
            .find(".post_sell_offer(")
            .expect("post_offer submits to shellnet");
        assert!(
            withdrawn < submit,
            "PrivateNote.hasWithdrawn must be checked before postSellOffer"
        );
        assert!(
            terms < submit,
            "TokenContract.getDeal terms must be read before postSellOffer"
        );
        assert!(
            body.contains("seller offer terms are bound to TokenContract.getDeal"),
            "drifted CLI terms must be visibly ignored"
        );
    }

    #[test]
    fn real_seller_backends_forward_sell_offer_flags() {
        let source = include_str!("backends.rs");
        let deal_start = source
            .find("impl ChainBackend for RealDealBackend")
            .expect("real deal impl present");
        let seller_start = source
            .find("impl ChainBackend for RealSellerBackend")
            .expect("real seller impl present");
        let buyer_start = source
            .find("impl ChainBackend for RealBuyerBackend")
            .expect("real buyer impl present");

        for (label, backend) in [
            ("RealDealBackend", &source[deal_start..seller_start]),
            ("RealSellerBackend", &source[seller_start..buyer_start]),
        ] {
            let post = backend
                .find("async fn post_offer(&self, offer: SellOffer")
                .unwrap_or_else(|| panic!("{label} post_offer present"));
            let post = &backend[post..];
            let end = post[1..]
                .find("\n    async fn ")
                .map(|offset| offset + 1)
                .unwrap_or(post.len());
            let post = &post[..end];
            assert!(
                post.contains(".post_sell_offer("),
                "{label} must call the real PrivateNote post path"
            );
            assert!(
                post.contains("\n                offer.flags,\n"),
                "{label} must pass the exact SellOffer flags argument to post_sell_offer"
            );
        }
    }

    /// live regression: the gateway-owned seller watcher calls `read_handover` while provisioning
    /// or restoring a match. Real seller backends must read the TC handover instead of failing as the buyer role.
    #[test]
    fn real_seller_backend_allows_handover_read_for_watcher_resume() {
        let source = include_str!("backends.rs");
        let seller_impl = source
            .find("impl ChainBackend for RealSellerBackend")
            .expect("real seller impl present");
        let seller = &source[seller_impl..];
        let read_handover = seller
            .find("async fn read_handover(")
            .expect("real seller read_handover present");
        let claim_tokens = seller[read_handover..]
            .find("async fn claim_tokens(")
            .map(|offset| read_handover + offset)
            .expect("next real seller method present");
        let body = &seller[read_handover..claim_tokens];

        assert!(
            body.contains("self.chain.read_handover(&tc).await.map_err(map_err)"),
            "real seller watcher must read existing TC handover for idempotent provisioning"
        );
        assert!(
            !body.contains("wrong_role(\"read_handover\""),
            "real seller read_handover must not fail as a buyer-only action"
        );
    }

    #[test]
    fn real_seller_backend_exposes_deal_state_for_policy_watcher() {
        let source = include_str!("backends.rs");
        let seller_impl = source
            .find("impl ChainBackend for RealSellerBackend")
            .expect("real seller impl present");
        let seller = &source[seller_impl..];
        let deal_state = seller
            .find("async fn deal_state(")
            .expect("real seller deal_state present");
        let snapshot = seller[deal_state..]
            .find("async fn snapshot(")
            .map(|offset| deal_state + offset)
            .expect("next real seller method present");
        let body = &seller[deal_state..snapshot];

        assert!(
            body.contains(".deal_snapshot(token_contract)"),
            "real seller policy watcher must project state from the coherent strict snapshot"
        );
    }

    #[test]
    fn real_open_paths_post_validated_seller_bond_before_open() {
        let source = include_str!("backends.rs");
        let deal_start = source
            .find("impl ChainBackend for RealDealBackend")
            .expect("real deal adapter");
        let seller_struct = source
            .find("pub struct RealSellerBackend")
            .expect("real seller adapter");
        let seller_start = source
            .find("impl ChainBackend for RealSellerBackend")
            .expect("real seller implementation");
        let buyer_struct = source
            .find("pub struct RealBuyerBackend")
            .expect("real buyer adapter");

        for (label, implementation) in [
            ("RealDealBackend", &source[deal_start..seller_struct]),
            ("RealSellerBackend", &source[seller_start..buyer_struct]),
        ] {
            let open = implementation
                .find("async fn open_stream(")
                .expect("open_stream implementation");
            let body = &implementation[open..];
            let bond = body
                .find("post_seller_bond_and_wait(")
                .expect("validated seller bond path");
            let submit = body
                .find(".open_stream(")
                .expect("TokenContract open submit");
            assert!(
                bond < submit,
                "{label} must post the validated exact 2P seller bond before open"
            );
        }
        let obsolete_field = ["probe", "shell"].join("_");
        let obsolete_flag = ["--probe", "shell"].join("-");
        assert!(!source.contains(&obsolete_field));
        assert!(!source.contains(&obsolete_flag));
    }

    #[test]
    fn real_stop_paths_never_substitute_local_projection_for_action_receipt() {
        let source = include_str!("backends.rs");
        let shared_start = source
            .find("async fn explicit_buyer_stop_with<")
            .expect("shared explicit STOP implementation");
        let shared_end = source[shared_start..]
            .find("impl RealChainBackend {")
            .map(|offset| shared_start + offset)
            .expect("end of shared explicit STOP implementation");
        let shared = &source[shared_start..shared_end];
        let gas = shared
            .find("before_submit().await?")
            .expect("caller-specific gas preflight");
        let submit = shared
            .find(".stream_stop(buyer_note, buyer_keys, tc)")
            .expect("one-shot explicit STOP submit");
        let receipt = shared
            .find("Settlement::AuthoritativeReceipt")
            .expect("authoritative STOP receipt");
        assert_eq!(shared.matches(".stream_stop(").count(), 1);
        assert!(
            gas < submit && submit < receipt,
            "shared explicit STOP must complete gas preflight before its only receipt-confirming POST"
        );
        assert!(!shared.contains("settle_stop("));
        assert!(!shared.contains("reconcile_explicit_stop("));

        let deal_start = source
            .find("impl ChainBackend for RealDealBackend")
            .expect("real deal adapter");
        let seller_struct = source
            .find("pub struct RealSellerBackend")
            .expect("real seller adapter");
        let buyer_start = source
            .find("impl ChainBackend for RealBuyerBackend")
            .expect("real buyer implementation");

        for (label, implementation) in [
            ("RealDealBackend", &source[deal_start..seller_struct]),
            ("RealBuyerBackend", &source[buyer_start..]),
        ] {
            let stop = implementation
                .find("async fn stop(")
                .expect("stop implementation");
            let body = &implementation[stop..];
            let dispute = body
                .find("async fn dispute(")
                .expect("method after stop implementation");
            let body = &body[..dispute];
            assert_eq!(
                body.matches("explicit_buyer_stop_with(").count(),
                1,
                "{label} must route through the shared explicit STOP transaction"
            );
            assert!(!body.contains("settle_stop("), "{label} projected STOP");
            assert!(
                body.contains(if label == "RealDealBackend" {
                    "|| self.ensure_tc_gas(&tc)"
                } else {
                    "self.require_tc_gas(&tc)"
                }),
                "{label} must supply its existing gas preflight to the shared transaction"
            );
            assert!(!body.contains(".stream_stop("));
        }
    }

    #[test]
    fn automatic_policy_stop_uses_final_guard_while_explicit_stop_stays_unconditional() {
        let source = include_str!("backends.rs");
        let deal_start = source
            .find("impl ChainBackend for RealDealBackend")
            .expect("real deal adapter");
        let seller_struct = source
            .find("pub struct RealSellerBackend")
            .expect("real seller adapter");
        let buyer_start = source
            .find("impl ChainBackend for RealBuyerBackend")
            .expect("real buyer implementation");

        for (label, implementation) in [
            ("RealDealBackend", &source[deal_start..seller_struct]),
            ("RealBuyerBackend", &source[buyer_start..]),
        ] {
            let explicit_start = implementation
                .find("async fn stop(")
                .expect("explicit STOP implementation");
            let guarded_start = implementation[explicit_start..]
                .find("async fn stop_if_heartbeat(")
                .map(|offset| explicit_start + offset)
                .expect("automatic policy STOP implementation");
            let dispute_start = implementation[guarded_start..]
                .find("async fn dispute(")
                .map(|offset| guarded_start + offset)
                .expect("method after guarded STOP");
            let explicit = &implementation[explicit_start..guarded_start];
            let guarded = &implementation[guarded_start..dispute_start];

            assert_eq!(
                explicit.matches("explicit_buyer_stop_with(").count(),
                1,
                "{label} explicit STOP must enter the shared unconditional transaction"
            );
            assert!(
                !explicit.contains("stop_if_heartbeat("),
                "{label} explicit operator/user STOP must not be heartbeat-vetoed"
            );

            let gas = guarded
                .find(if label == "RealDealBackend" {
                    "self.ensure_tc_gas("
                } else {
                    "self.require_tc_gas("
                })
                .expect("guarded gas preflight");
            let heartbeat = guarded
                .find("let mut heartbeat_unchanged = || heartbeat.unchanged();")
                .expect("guard snapshot comparison callback");
            let submit = guarded
                .find(".stop_if_heartbeat(")
                .expect("final guarded money submit seam");
            let receipt = guarded
                .find("Settlement::AuthoritativeReceipt")
                .expect("guarded action receipt");
            assert_eq!(
                guarded.matches(".stop_if_heartbeat(").count(),
                1,
                "{label} automatic policy STOP must have exactly one submit seam"
            );
            assert!(
                gas < heartbeat && heartbeat < submit && submit < receipt,
                "{label} must finish gas preflight before the heartbeat-aware, receipt-confirming submit"
            );
            assert!(!guarded.contains("settle_stop("));
            assert!(!guarded.contains("wait_state_bool("));
            assert!(!guarded.contains("wait_tc_bool("));
        }
    }
}

// the live shellnet tests drive the giver(test faucet), which is gated behind `test-giver`.
// Run with `--features shellnet,test-giver -- --ignored`. Without `test-giver` they are compiled out,
// so a default/`shellnet` build(and its test compile) contains no giver.
