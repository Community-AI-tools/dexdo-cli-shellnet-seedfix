//! Seller-driven consumption-claim orchestrator.
//! The seller is paid only for consumption he CLAIMS, and each claim promotes the previous one to trusted.
//! Without this loop nothing is ever claimed, so a buyer STOP settles at zero and the delivered work is
//! unpaid. `claimTokens()` is **seller-only** on-chain (`onlyOwnerPubkey(_sellerPubkey)`), so the seller
//! process owns the loop; the buyer's role is to stay silent(no dispute) through the promotion window.
//! Nothing is claimable until the PROBE is accepted. `open()` freezes one tick as a trial owed to nobody,
//! and only after `PROBE_WINDOW` of buyer silence may the seller take it and start claiming -- a deal whose
//! probe is never accepted pays the seller nothing at all, so this loop drives that step first.
//! Three things bound a claim, and the driver must respect all of them because the contract REJECTS rather than
//! trims an out-of-bounds claim:
//! - `MIN_CLAIM_INTERVAL` between claims;
//! - the physical rate -- `delta * MIN_SECONDS_PER_TICK <= elapsed * TICK_SIZE`, i.e. no more output than
//! the elapsed time could have produced;
//! - hard per-call `MAX_CLAIM_DELTA == TICK_SIZE`. Waiting longer can satisfy the rate inequality but
//! never permits a multi-tick single call; backlog is split across later claims.
//! The last claim of a deal needs `finalize()`: nothing supersedes it, so without the permissionless
//! promotion window it would stay contestable forever and never be paid.
//! Bounds are read per-deal from `TokenContract.getConfig()` so a redeployed contract cannot desync the
//! driver from what the chain will accept; tests inject short bounds.

use dexdo_core::params::{MAX_CLAIM_DELTA, SELLER_TERMINAL_RECEIPT_POLL_INTERVAL};
use dexdo_core::{
    ChainBackend, ChainError, ClaimBounds, DealChainState, Note, TokenContract, TICK_SIZE,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Per-deal claim cadence, mirrored from `TokenContract.getConfig()`.
#[derive(Debug, Clone, Copy)]
pub struct AdvanceWindows {
    /// Minimum gap between accepted claims(`minClaimInterval`).
    pub claim_interval: Duration,
    /// Generation floor per tick(`minSecondsPerTick`): bounds how large a claim may be for a given wait.
    pub seconds_per_tick: Duration,
    /// Silence after which a pending claim is promotable by anyone(`finalize`).
    pub promote: Duration,
    /// Buyer silence required before the probe tick may be accepted(`PROBE_WINDOW`).
    pub probe: Duration,
}

impl AdvanceWindows {
    /// Build from per-deal [`ClaimBounds`] read off the chain.
    pub fn from_bounds(bounds: ClaimBounds) -> Self {
        Self {
            claim_interval: bounds.min_claim_interval,
            seconds_per_tick: bounds.min_seconds_per_tick,
            promote: bounds.promote_window,
            probe: bounds.probe_window,
        }
    }

    /// Canonical bounds, for tests and for backends that expose no per-deal config.
    pub fn canonical() -> Self {
        Self::from_bounds(ClaimBounds::canonical())
    }

    /// Largest cumulative increment claimable after `elapsed`, mirroring both the on-chain rate bound and
    /// hard per-call `MAX_CLAIM_DELTA`. Claims above this are rejected outright, so the driver clamps before
    /// the money call.
    pub fn max_claim_delta(&self, elapsed: Duration) -> u128 {
        dexdo_core::params::claim_delta_limit(elapsed, self.seconds_per_tick)
    }
}

/// Observes the strict claim states already read by the ordinary-deal driver.
/// The observer never polls or submits independently. Returning an error stops the driver before its next
/// decision/write, which lets capacity persistence fail closed.
pub trait ClaimStateObserver: Send + Sync {
    fn observe(
        &self,
        token_contract: &TokenContract,
        state: DealChainState,
    ) -> Result<(), ChainError>;

    fn observe_terminal(&self, _token_contract: &TokenContract) -> Result<(), ChainError> {
        Ok(())
    }
}

impl ClaimStateObserver for () {
    fn observe(
        &self,
        _token_contract: &TokenContract,
        _state: DealChainState,
    ) -> Result<(), ChainError> {
        Ok(())
    }
}

async fn required_claim_state(
    chain: &dyn ChainBackend,
    token_contract: &TokenContract,
    observer: &dyn ClaimStateObserver,
) -> Result<DealChainState, ChainError> {
    let state = chain.deal_state(token_contract).await?.ok_or_else(|| {
        ChainError::Chain(format!(
            "TokenContract {token_contract}: getState returned no data while reconciling the \
             cumulative claim high-water"
        ))
    })?;
    observer.observe(token_contract, state)?;
    Ok(state)
}

fn validated_claim_high_water(
    token_contract: &TokenContract,
    state: DealChainState,
    token_budget: u128,
) -> Result<u128, ChainError> {
    if !state.opened || state.disputed || !state.probe_accepted {
        return Err(ChainError::Chain(format!(
            "TokenContract {token_contract}: claim high-water is not actionable \
             (opened={}, disputed={}, probeAccepted={})",
            state.opened, state.disputed, state.probe_accepted
        )));
    }
    if state.tokens_pending < TICK_SIZE {
        return Err(ChainError::Chain(format!(
            "TokenContract {token_contract}: accepted probe reports tokensPending {} below canonical \
             TICK_SIZE {TICK_SIZE}; refusing to reset the cumulative high-water to zero",
            state.tokens_pending
        )));
    }
    if state.tokens_final > state.tokens_pending {
        return Err(ChainError::Chain(format!(
            "TokenContract {token_contract}: tokensFinal {} exceeds tokensPending {}; refusing a \
             regressing claim pipeline",
            state.tokens_final, state.tokens_pending
        )));
    }
    if state.tokens_pending > token_budget {
        return Err(ChainError::Chain(format!(
            "TokenContract {token_contract}: on-chain claim high-water {} exceeds the configured token \
             budget {token_budget}",
            state.tokens_pending
        )));
    }
    Ok(state.tokens_pending)
}

/// Drive one deal's claim loop: repeatedly claim the CUMULATIVE tokens actually delivered, then `finalize()`
/// so the final claim becomes payable. Returns the cumulative tokens successfully claimed.
/// After the paid probe seeds the first full tick, later claims never exceed delivered output: a
/// timer firing does not entitle the seller to consumption the buyer never received. They are additionally
/// clamped to the on-chain rate bound, because the contract rejects an over-rate claim outright -- an
/// unclamped driver would lose the whole batch instead of claiming the permitted part of it.
/// The loop ends on a clean external close(buyer STOP / self-destruct), on the deal's ceiling
/// (`ChainError::Limit`), or once delivery is complete and everything delivered has been claimed and
/// promoted. Any other failure is a genuine fault and MUST propagate -- never report success.
/// Seller-only: `seller_note` authorizes the on-chain `claimTokens()`.
/// `finalize_last_claim` is false only when the subscription keeper is running for this same deal;
/// that keeper then remains the sole permissionless `finalize()` writer.
#[allow(clippy::too_many_arguments)]
pub async fn drive_advance(
    chain: &dyn ChainBackend,
    token_contract: &TokenContract,
    seller_note: &dyn Note,
    windows: AdvanceWindows,
    tick_budget: u128,
    tick_size: u64,
    finalize_last_claim: bool,
    delivered: Arc<AtomicU64>,
    delivery_done: Arc<AtomicBool>,
) -> Result<u128, ChainError> {
    drive_advance_with_observer(
        chain,
        token_contract,
        seller_note,
        windows,
        tick_budget,
        tick_size,
        finalize_last_claim,
        delivered,
        delivery_done,
        &(),
    )
    .await
}

/// Drive an ordinary deal while exposing only the state reads the driver already performs.
#[allow(clippy::too_many_arguments)]
pub async fn drive_advance_with_observer(
    chain: &dyn ChainBackend,
    token_contract: &TokenContract,
    seller_note: &dyn Note,
    windows: AdvanceWindows,
    tick_budget: u128,
    tick_size: u64,
    finalize_last_claim: bool,
    delivered: Arc<AtomicU64>,
    delivery_done: Arc<AtomicBool>,
    observer: &dyn ClaimStateObserver,
) -> Result<u128, ChainError> {
    assert!(tick_size > 0, "tick_size must be non-zero");
    // Ceiling in TOKENS. The deal's budget is expressed in ticks, so convert once; consumption itself is
    // claimed and disputed in raw tokens, which is why no rounding to whole ticks happens anywhere here.
    let token_budget = tick_budget.saturating_mul(u128::from(tick_size));
    let mut waiting_event_emitted = false;

    if deal_closed_observed(chain, token_contract, observer).await? {
        return Ok(0);
    }

    // A restarted seller may find the probe and later claims already applied. Read first so restart never
    // repeats `acceptProbe`, then seed the local cumulative cursor from the authoritative on-chain value.
    let before_probe = required_claim_state(chain, token_contract, observer).await?;
    let resumed_after_probe = before_probe.probe_accepted;
    if !resumed_after_probe {
        if !before_probe.opened || before_probe.disputed || before_probe.tokens_pending != 0 {
            return Err(ChainError::Chain(format!(
                "TokenContract {token_contract}: malformed pre-probe claim state \
                 (opened={}, disputed={}, tokensPending={})",
                before_probe.opened, before_probe.disputed, before_probe.tokens_pending
            )));
        }

        // The probe gates everything: wait out the buyer's silence, then take the trial tick. A submit
        // response can race a state update, so the state below -- not the response alone -- decides.
        tokio::time::sleep(windows.probe).await;
        if deal_closed_observed(chain, token_contract, observer).await? {
            return Ok(0);
        }
        let accept_error = chain.accept_probe(token_contract).await.err();
        let after_accept = required_claim_state(chain, token_contract, observer).await?;
        if !after_accept.probe_accepted {
            if deal_closed_observed(chain, token_contract, observer).await? {
                // The buyer walked away from the trial before it could be accepted: the probe burned on both
                // sides and there is nothing left to claim. Not a fault of ours.
                return Ok(0);
            }
            return Err(accept_error.unwrap_or_else(|| {
                ChainError::Chain(format!(
                    "TokenContract {token_contract}: acceptProbe returned but probeAccepted stayed false"
                ))
            }));
        }
    }

    let claim_state = required_claim_state(chain, token_contract, observer).await?;
    let mut claimed = validated_claim_high_water(token_contract, claim_state, token_budget)?;
    let delivery_base = if resumed_after_probe { claimed } else { 0 };
    let mut needs_finalize = claim_state.tokens_pending > claim_state.tokens_final;
    if claimed > TICK_SIZE {
        tracing::info!(
            event = "seller_claim_high_water_resynced",
            token_contract = %token_contract,
            on_chain_tokens = claimed,
            "seller resumed from the authoritative cumulative claim high-water"
        );
    }

    loop {
        if claimed >= token_budget {
            break;
        }
        if deal_closed_observed(chain, token_contract, observer).await? {
            break; // closed externally(e.g. buyer STOP) -- nothing more to claim
        }

        // Acquire ordering: the producer publishes `delivered` then `delivery_done` with Release, so a
        // `done` observed here implies the matching `delivered` count is visible(no stale under-read).
        let target = delivery_base
            .saturating_add(u128::from(delivered.load(Ordering::Acquire)))
            .min(token_budget);
        if claimed >= target {
            if delivery_done.load(Ordering::Acquire) {
                // Re-read after observing `done`: tokens delivered just before it must still be claimed.
                let refreshed = delivery_base
                    .saturating_add(u128::from(delivered.load(Ordering::Acquire)))
                    .min(token_budget);
                if claimed >= refreshed {
                    break;
                }
            } else {
                if !waiting_event_emitted {
                    tracing::info!(
                        event = "seller_waiting_for_delivered_tokens",
                        token_contract = %token_contract,
                        claimed_tokens = claimed,
                        "seller waiting for delivered tokens to claim"
                    );
                    waiting_event_emitted = true;
                }
                if wait_claim_or_closed(chain, token_contract, windows.claim_interval).await {
                    break;
                }
                continue;
            }
        }

        // Wait out the minimum interval, which is also what accrues the rate allowance.
        tokio::time::sleep(windows.claim_interval).await;
        let target = delivery_base
            .saturating_add(u128::from(delivered.load(Ordering::Acquire)))
            .min(token_budget);
        // Claim as much of the delivered backlog as BOTH the elapsed-time rate and hard per-call cap permit.
        // Anything above the combined allowance stays for the next round rather than being asserted and
        // rejected.
        // A zero interval is the deterministic test seam: it bypasses only the elapsed-time rate calculation,
        // never the contract's hard one-tick-per-call bound.
        let allowance = if windows.claim_interval.is_zero() {
            MAX_CLAIM_DELTA
        } else {
            windows.max_claim_delta(windows.claim_interval)
        };
        let next = target.min(claimed.saturating_add(allowance));
        if next <= claimed {
            continue;
        }
        match chain.claim_tokens(token_contract, seller_note, next).await {
            Ok(()) => {
                claimed = next;
                needs_finalize = true;
            }
            Err(ChainError::ClaimHighWaterResync {
                attempted,
                on_chain,
            }) => {
                if attempted != next
                    || on_chain <= next
                    || on_chain > target
                    || on_chain > token_budget
                {
                    return Err(ChainError::Chain(format!(
                        "TokenContract {token_contract}: invalid claim resync \
                         (attempted={attempted}, expected={next}, onChain={on_chain}, \
                         deliveryTarget={target}, budget={token_budget})"
                    )));
                }
                tracing::info!(
                    event = "seller_claim_high_water_resynced",
                    token_contract = %token_contract,
                    attempted_tokens = next,
                    on_chain_tokens = on_chain,
                    "a concurrent or lost-response claim advanced the chain; resynchronising explicitly"
                );
                claimed = on_chain;
                needs_finalize = true;
            }
            Err(ChainError::Limit(_)) => break, // deal ceiling -- expected exhaustion
            Err(e) => {
                // A close can race the claim(buyer STOP between the snapshot and the call); re-check
                // before surfacing. Otherwise propagate the real error -- do NOT claim success.
                if deal_closed_observed(chain, token_contract, observer).await? {
                    break;
                }
                return Err(e);
            }
        }
    }

    // The newest claim is still contestable and nothing will supersede it, so without this the last batch
    // would never be paid. A close may legitimately race the permissionless call; otherwise a failed final
    // promotion must propagate so the ordinary seller never reports terminal success with a contestable tail.
    if needs_finalize && finalize_last_claim {
        tokio::time::sleep(windows.promote).await;
        if let Err(error) = chain.finalize(token_contract).await {
            if deal_closed_observed(chain, token_contract, observer).await? {
                return Ok(claimed);
            }
            tracing::warn!(
                event = "seller_finalize_pending_claim_failed",
                token_contract = %token_contract,
                claimed_tokens = claimed,
                %error,
                "the last claim stays contestable until finalize succeeds"
            );
            return Err(error);
        }
    }
    Ok(claimed)
}

async fn wait_claim_or_closed(
    chain: &dyn ChainBackend,
    token_contract: &TokenContract,
    window: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return false;
        }
        tokio::time::sleep(SELLER_TERMINAL_RECEIPT_POLL_INTERVAL.min(deadline.duration_since(now)))
            .await;
        if deal_closed(chain, token_contract).await {
            return true;
        }
    }
}

/// Whether the deal's stream is closed(settled / self-destructed) -- an expected, non-error terminal
/// condition for the advance loop. A **missing** snapshot is treated as *not* a clean close(`false`), so
/// a `claim_tokens` failure with no observable close still propagates as a real error.
async fn deal_closed(chain: &dyn ChainBackend, token_contract: &TokenContract) -> bool {
    chain
        .snapshot(token_contract)
        .await
        .map(|s| s.closed)
        .unwrap_or(false)
}

async fn deal_closed_observed(
    chain: &dyn ChainBackend,
    token_contract: &TokenContract,
    observer: &dyn ClaimStateObserver,
) -> Result<bool, ChainError> {
    let closed = deal_closed(chain, token_contract).await;
    if closed {
        observer.observe_terminal(token_contract)?;
    }
    Ok(closed)
}
#[cfg(test)]
mod tests {
    use super::*;
    use dexdo_core::{
        LocalNote, Match, OfferListing, SellOffer, Settlement, StreamSnapshot, TICK_SIZE,
    };

    fn claim_state(
        probe_accepted: bool,
        tokens_final: u128,
        tokens_pending: u128,
    ) -> DealChainState {
        DealChainState {
            funded: true,
            opened: true,
            probe_accepted,
            disputed: false,
            deposit: 10_000,
            finalized_owed: 0,
            tokens_final,
            tokens_superseded: tokens_final,
            tokens_pending,
            probe_tick: if probe_accepted { 0 } else { 1_000 },
            funded_time: Some(1),
            probe_time: 1,
            prev_claim_time: 1,
            last_claim_time: 1,
            dispute_time: 0,
        }
    }

    /// Canonical bounds: one tick per minute, claims spaced a minute apart, promotion after two.
    #[test]
    fn canonical_bounds_allow_exactly_one_tick_per_minute() {
        let w = AdvanceWindows::canonical();
        assert_eq!(w.claim_interval, Duration::from_secs(60));
        assert_eq!(w.seconds_per_tick, Duration::from_secs(60));
        assert_eq!(
            w.promote,
            Duration::from_secs(120),
            "promotion window is 2 * MIN_SECONDS_PER_TICK"
        );
        assert_eq!(
            w.max_claim_delta(Duration::from_secs(60)),
            TICK_SIZE,
            "a minute of generation is worth exactly one tick"
        );
    }

    /// Regression forR20-09: elapsed rate allowance can grow, but the contract's independent
    /// `MAX_CLAIM_DELTA` never permits a multi-tick single call.
    #[test]
    fn waiting_longer_never_exceeds_the_per_call_cap() {
        let w = AdvanceWindows::canonical();
        assert_eq!(w.max_claim_delta(Duration::from_secs(600)), TICK_SIZE);
        assert_eq!(
            w.max_claim_delta(Duration::from_secs(30)),
            TICK_SIZE / 2,
            "half a minute is worth half a tick"
        );
        assert_eq!(w.max_claim_delta(Duration::ZERO), 0);
    }

    /// Bounds come from the deal, so a redeployment with a different rate floor changes both the claim size
    /// and the derived promotion window.
    #[test]
    fn bounds_are_taken_from_the_deal() {
        let w = AdvanceWindows::from_bounds(dexdo_core::ClaimBounds::from_config(30, 120, 600));
        assert_eq!(w.claim_interval, Duration::from_secs(30));
        assert_eq!(w.seconds_per_tick, Duration::from_secs(120));
        assert_eq!(
            w.promote,
            Duration::from_secs(240),
            "promote window follows the deal's rate floor"
        );
        assert_eq!(
            w.max_claim_delta(Duration::from_secs(120)),
            TICK_SIZE,
            "a slower floor means a minute buys less"
        );
    }

    /// Zero windows for tests: no sleeping, and no rate clamp to deadlock against.
    fn instant() -> AdvanceWindows {
        AdvanceWindows {
            claim_interval: Duration::ZERO,
            seconds_per_tick: Duration::from_secs(60),
            promote: Duration::ZERO,
            probe: Duration::ZERO,
        }
    }

    /// A fake backend whose `claim_tokens` fails with a **real** chain error(not a terminal condition),
    /// used to prove `drive_advance` propagates it instead of reporting a successful loop ( money-path
    /// safety). The stream reports no snapshot, so the failure cannot be mistaken for a close.
    struct ExplodingBackend;

    #[async_trait::async_trait]
    impl ChainBackend for ExplodingBackend {
        async fn discover_offers(&self) -> Result<Vec<OfferListing>, ChainError> {
            unimplemented!()
        }
        async fn post_offer(&self, _: SellOffer, _: &dyn Note) -> Result<(), ChainError> {
            unimplemented!()
        }
        async fn place_buy(&self, _: &TokenContract, _: &dyn Note) -> Result<(), ChainError> {
            unimplemented!()
        }
        async fn read_match(&self, _: &TokenContract) -> Result<Match, ChainError> {
            unimplemented!()
        }
        async fn open_stream(
            &self,
            _: &TokenContract,
            _: Vec<u8>,
            _: &dyn Note,
        ) -> Result<(), ChainError> {
            unimplemented!()
        }
        async fn read_handover(&self, _: &TokenContract) -> Result<Option<Vec<u8>>, ChainError> {
            unimplemented!()
        }
        async fn accept_probe(&self, _: &TokenContract) -> Result<(), ChainError> {
            Ok(())
        }

        async fn claim_tokens(
            &self,
            _: &TokenContract,
            _: &dyn Note,
            _: u128,
        ) -> Result<(), ChainError> {
            Err(ChainError::Chain("boom".to_string()))
        }
        async fn deal_state(
            &self,
            _: &TokenContract,
        ) -> Result<Option<DealChainState>, ChainError> {
            Ok(Some(claim_state(true, TICK_SIZE, TICK_SIZE)))
        }
        async fn stop(&self, _: &TokenContract, _: &dyn Note) -> Result<Settlement, ChainError> {
            unimplemented!()
        }
        async fn snapshot(&self, _: &TokenContract) -> Option<StreamSnapshot> {
            None
        }
    }

    /// A real `claim_tokens` failure must propagate -- NOT be swallowed as a clean terminal condition.
    /// Otherwise the seller path would report claimed consumption that the chain never recorded.
    #[tokio::test]
    async fn drive_advance_propagates_real_claim_error() {
        let backend = ExplodingBackend;
        let note = LocalNote::generate();
        let res = drive_advance(
            &backend,
            &"tc-boom".to_string(),
            &note,
            instant(),
            4,
            TICK_SIZE as u64,
            true,
            Arc::new(AtomicU64::new(4)),
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        match res {
            Err(ChainError::Chain(msg)) => assert_eq!(msg, "boom"),
            other => panic!("expected propagated Chain(\"boom\"), got {other:?}"),
        }
    }

    /// A backend that records every claimed total and succeeds -- used to prove the driver never claims more
    /// than was delivered, and that what it claims is CUMULATIVE.
    struct RecordingBackend {
        attempts: std::sync::Mutex<Vec<u128>>,
        claims: std::sync::Mutex<Vec<u128>>,
        finalized: AtomicU64,
        fail_finalize: AtomicBool,
        close_before_finalize_error: AtomicBool,
        accepts: AtomicU64,
        closed: AtomicBool,
        state: std::sync::Mutex<DealChainState>,
        resync_to: std::sync::Mutex<Option<u128>>,
    }
    impl RecordingBackend {
        fn new() -> Self {
            Self {
                attempts: std::sync::Mutex::new(Vec::new()),
                claims: std::sync::Mutex::new(Vec::new()),
                finalized: AtomicU64::new(0),
                fail_finalize: AtomicBool::new(false),
                close_before_finalize_error: AtomicBool::new(false),
                accepts: AtomicU64::new(0),
                closed: AtomicBool::new(false),
                state: std::sync::Mutex::new(claim_state(false, 0, 0)),
                resync_to: std::sync::Mutex::new(None),
            }
        }
        fn resumed(tokens_final: u128, tokens_pending: u128) -> Self {
            Self {
                attempts: std::sync::Mutex::new(Vec::new()),
                claims: std::sync::Mutex::new(Vec::new()),
                finalized: AtomicU64::new(0),
                fail_finalize: AtomicBool::new(false),
                close_before_finalize_error: AtomicBool::new(false),
                accepts: AtomicU64::new(0),
                closed: AtomicBool::new(false),
                state: std::sync::Mutex::new(claim_state(true, tokens_final, tokens_pending)),
                resync_to: std::sync::Mutex::new(None),
            }
        }
        fn resyncing(on_chain: u128) -> Self {
            let backend = Self::new();
            *backend.resync_to.lock().unwrap() = Some(on_chain);
            backend
        }
        fn closed() -> Self {
            let backend = Self::new();
            backend.closed.store(true, Ordering::Relaxed);
            backend
        }
        fn failing_finalize() -> Self {
            let backend = Self::new();
            backend.fail_finalize.store(true, Ordering::Relaxed);
            backend
        }
        fn closed_before_finalize_error() -> Self {
            let backend = Self::failing_finalize();
            backend
                .close_before_finalize_error
                .store(true, Ordering::Relaxed);
            backend
        }
        fn claims(&self) -> Vec<u128> {
            self.claims.lock().unwrap().clone()
        }
        fn attempts(&self) -> Vec<u128> {
            self.attempts.lock().unwrap().clone()
        }
    }
    #[async_trait::async_trait]
    impl ChainBackend for RecordingBackend {
        async fn discover_offers(&self) -> Result<Vec<OfferListing>, ChainError> {
            unimplemented!()
        }
        async fn post_offer(&self, _: SellOffer, _: &dyn Note) -> Result<(), ChainError> {
            unimplemented!()
        }
        async fn place_buy(&self, _: &TokenContract, _: &dyn Note) -> Result<(), ChainError> {
            unimplemented!()
        }
        async fn read_match(&self, _: &TokenContract) -> Result<Match, ChainError> {
            unimplemented!()
        }
        async fn open_stream(
            &self,
            _: &TokenContract,
            _: Vec<u8>,
            _: &dyn Note,
        ) -> Result<(), ChainError> {
            unimplemented!()
        }
        async fn read_handover(&self, _: &TokenContract) -> Result<Option<Vec<u8>>, ChainError> {
            unimplemented!()
        }
        async fn accept_probe(&self, _: &TokenContract) -> Result<(), ChainError> {
            self.accepts.fetch_add(1, Ordering::Relaxed);
            let mut state = self.state.lock().unwrap();
            state.probe_accepted = true;
            state.probe_tick = 0;
            state.tokens_final = TICK_SIZE;
            state.tokens_pending = TICK_SIZE;
            Ok(())
        }

        async fn claim_tokens(
            &self,
            _: &TokenContract,
            _: &dyn Note,
            cumulative: u128,
        ) -> Result<(), ChainError> {
            self.attempts.lock().unwrap().push(cumulative);
            if let Some(on_chain) = self.resync_to.lock().unwrap().take() {
                self.state.lock().unwrap().tokens_pending = on_chain;
                return Err(ChainError::ClaimHighWaterResync {
                    attempted: cumulative,
                    on_chain,
                });
            }
            self.claims.lock().unwrap().push(cumulative);
            self.state.lock().unwrap().tokens_pending = cumulative;
            Ok(())
        }
        async fn finalize(&self, _: &TokenContract) -> Result<(), ChainError> {
            self.finalized.fetch_add(1, Ordering::Relaxed);
            if self.fail_finalize.load(Ordering::Relaxed) {
                if self.close_before_finalize_error.load(Ordering::Relaxed) {
                    self.closed.store(true, Ordering::Release);
                }
                return Err(ChainError::Chain("finalize boom".to_string()));
            }
            let mut state = self.state.lock().unwrap();
            state.tokens_final = state.tokens_pending;
            Ok(())
        }
        async fn deal_state(
            &self,
            _: &TokenContract,
        ) -> Result<Option<DealChainState>, ChainError> {
            Ok(Some(*self.state.lock().unwrap()))
        }
        async fn stop(&self, _: &TokenContract, _: &dyn Note) -> Result<Settlement, ChainError> {
            unimplemented!()
        }
        async fn snapshot(&self, _: &TokenContract) -> Option<StreamSnapshot> {
            self.closed
                .load(Ordering::Relaxed)
                .then_some(StreamSnapshot {
                    seller_locked: 0,
                    buyer_locked: 0,
                    buyer_lead: 0,
                    tokens_final: self.state.lock().unwrap().tokens_final,
                    seller_received: 0,
                    buyer_refunded: 0,
                    burned: 0,
                    closed: true,
                })
        }
    }

    async fn drive_recording(
        backend: &RecordingBackend,
        windows: AdvanceWindows,
        tick_budget: u128,
        delivered: u64,
    ) -> u128 {
        drive_advance(
            backend,
            &"tc".to_string(),
            &LocalNote::generate(),
            windows,
            tick_budget,
            TICK_SIZE as u64,
            true,
            Arc::new(AtomicU64::new(delivered)),
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .unwrap()
    }

    /// A failed final promotion with no authoritative terminal chain fact must remain a failed deal driver.
    /// Returning the claimed cursor here would let the ordinary seller unregister while its newest claim is
    /// still contestable.
    #[tokio::test]
    async fn drive_advance_propagates_finalize_error_without_terminal_chain_fact() {
        let backend = RecordingBackend::failing_finalize();
        let error = drive_advance(
            &backend,
            &"tc-finalize-boom".to_string(),
            &LocalNote::generate(),
            instant(),
            4,
            TICK_SIZE as u64,
            true,
            Arc::new(AtomicU64::new((TICK_SIZE + 5) as u64)),
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .expect_err("a non-terminal finalize failure must propagate");

        assert!(error.to_string().contains("finalize boom"), "{error}");
        assert_eq!(backend.finalized.load(Ordering::Relaxed), 1);
        let state = *backend.state.lock().unwrap();
        assert_eq!(state.tokens_final, TICK_SIZE);
        assert_eq!(state.tokens_pending, TICK_SIZE + 5);
    }

    /// A lost finalize response may race an independently completed close. The immediate authoritative
    /// reread is the only case where the submit error is terminal success rather than a propagated fault.
    #[tokio::test]
    async fn drive_advance_accepts_finalize_error_after_authoritative_close() {
        let backend = RecordingBackend::closed_before_finalize_error();
        let claimed = drive_advance(
            &backend,
            &"tc-finalize-closed".to_string(),
            &LocalNote::generate(),
            instant(),
            4,
            TICK_SIZE as u64,
            true,
            Arc::new(AtomicU64::new((TICK_SIZE + 5) as u64)),
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .expect("the authoritative close reconciles the finalize response error");

        assert_eq!(claimed, TICK_SIZE + 5);
        assert!(backend.closed.load(Ordering::Acquire));
        assert_eq!(backend.finalized.load(Ordering::Relaxed), 1);
    }

    #[derive(Default)]
    struct RecordingStateObserver {
        states: std::sync::Mutex<Vec<DealChainState>>,
        terminals: AtomicU64,
    }

    impl ClaimStateObserver for RecordingStateObserver {
        fn observe(&self, _: &TokenContract, state: DealChainState) -> Result<(), ChainError> {
            self.states.lock().unwrap().push(state);
            Ok(())
        }

        fn observe_terminal(&self, _: &TokenContract) -> Result<(), ChainError> {
            self.terminals.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn accepted_probe_state_is_observed_before_ordinary_driver_continues() {
        let backend = RecordingBackend::new();
        let observer = RecordingStateObserver::default();
        let claimed = drive_advance_with_observer(
            &backend,
            &"tc-observed".to_string(),
            &LocalNote::generate(),
            instant(),
            2,
            TICK_SIZE as u64,
            true,
            Arc::new(AtomicU64::new(TICK_SIZE as u64)),
            Arc::new(AtomicBool::new(true)),
            &observer,
        )
        .await
        .unwrap();

        assert_eq!(claimed, TICK_SIZE);
        let states = observer.states.lock().unwrap();
        assert!(!states.first().unwrap().probe_accepted);
        assert!(
            states.iter().skip(1).any(|state| state.probe_accepted),
            "the post-accept state must reach capacity reconciliation"
        );
    }

    struct RejectingStateObserver;

    impl ClaimStateObserver for RejectingStateObserver {
        fn observe(&self, _: &TokenContract, _: DealChainState) -> Result<(), ChainError> {
            Err(ChainError::Chain(
                "injected capacity persistence failure".to_string(),
            ))
        }
    }

    #[tokio::test]
    async fn capacity_observer_failure_stops_before_the_next_money_write() {
        let backend = RecordingBackend::new();
        let error = drive_advance_with_observer(
            &backend,
            &"tc-observer-failure".to_string(),
            &LocalNote::generate(),
            instant(),
            2,
            TICK_SIZE as u64,
            true,
            Arc::new(AtomicU64::new(TICK_SIZE as u64)),
            Arc::new(AtomicBool::new(true)),
            &RejectingStateObserver,
        )
        .await
        .expect_err("capacity persistence failure must stop the claim driver");

        assert!(
            error
                .to_string()
                .contains("injected capacity persistence failure"),
            "{error}"
        );
        assert_eq!(
            backend.accepts.load(Ordering::Relaxed),
            0,
            "no acceptProbe write may happen after observer failure"
        );
        assert!(backend.claims().is_empty());
    }

    #[tokio::test]
    async fn terminal_chain_fact_is_observed_before_ordinary_driver_returns() {
        let backend = RecordingBackend::closed();
        let observer = RecordingStateObserver::default();
        let claimed = drive_advance_with_observer(
            &backend,
            &"tc-terminal-observer".to_string(),
            &LocalNote::generate(),
            instant(),
            2,
            TICK_SIZE as u64,
            true,
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicBool::new(false)),
            &observer,
        )
        .await
        .unwrap();

        assert_eq!(claimed, 0);
        assert_eq!(observer.terminals.load(Ordering::Relaxed), 1);
        assert!(observer.states.lock().unwrap().is_empty());
        assert_eq!(backend.accepts.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn buyer_stop_interrupts_claim_wait() {
        let backend = Arc::new(RecordingBackend::new());
        let driver_backend = backend.clone();
        let driver = tokio::spawn(async move {
            drive_advance(
                driver_backend.as_ref(),
                &"tc-stop".to_string(),
                &LocalNote::generate(),
                AdvanceWindows {
                    claim_interval: Duration::from_secs(1_200),
                    seconds_per_tick: Duration::from_secs(1),
                    promote: Duration::ZERO,
                    probe: Duration::ZERO,
                },
                4,
                TICK_SIZE as u64,
                true,
                Arc::new(AtomicU64::new(TICK_SIZE as u64)),
                Arc::new(AtomicBool::new(false)),
            )
            .await
        });

        while backend.accepts.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
        tokio::task::yield_now().await;
        backend.closed.store(true, Ordering::Release);
        tokio::time::advance(SELLER_TERMINAL_RECEIPT_POLL_INTERVAL).await;
        tokio::task::yield_now().await;

        assert!(driver.is_finished());
        assert_eq!(driver.await.unwrap().unwrap(), TICK_SIZE);
        assert!(backend.claims().is_empty());
        assert_eq!(backend.finalized.load(Ordering::Relaxed), 0);
    }

    /// R20-03: a short response must never walk the cumulative cursor below the already-accepted full probe.
    #[tokio::test]
    async fn response_below_tick_keeps_probe_seeded_high_water() {
        let b = RecordingBackend::new();
        let claimed = drive_recording(&b, instant(), 4, (TICK_SIZE - 1) as u64).await;
        assert_eq!(claimed, TICK_SIZE);
        assert!(
            b.claims().is_empty(),
            "no claim may regress below the probe"
        );
        assert_eq!(b.accepts.load(Ordering::Relaxed), 1);
        assert_eq!(b.finalized.load(Ordering::Relaxed), 0);
    }

    /// R20-03: exactly one delivered tick is the accepted probe itself, not a second delta claim.
    #[tokio::test]
    async fn exactly_one_tick_is_not_claimed_twice() {
        let b = RecordingBackend::new();
        let claimed = drive_recording(&b, instant(), 4, TICK_SIZE as u64).await;
        assert_eq!(claimed, TICK_SIZE);
        assert!(b.claims().is_empty(), "the probe must not be re-stated");
    }

    /// Consumption beyond the probe stays in raw tokens: a partial next tick is not rounded up.
    #[tokio::test]
    async fn claims_cumulative_raw_tokens_after_the_probe() {
        let b = RecordingBackend::new();
        let claimed = drive_recording(&b, instant(), 4, (TICK_SIZE + 5) as u64).await;
        assert_eq!(claimed, TICK_SIZE + 5);
        assert_eq!(b.claims(), vec![TICK_SIZE + 5]);
        assert_eq!(b.finalized.load(Ordering::Relaxed), 1);
    }

    /// R20-03 ceiling equality: a claim may land exactly on the funded ceiling, with no extra attempt.
    #[tokio::test]
    async fn exact_ceiling_is_claimed_once() {
        let b = RecordingBackend::new();
        let claimed = drive_recording(&b, instant(), 2, (2 * TICK_SIZE) as u64).await;
        assert_eq!(claimed, 2 * TICK_SIZE);
        assert_eq!(b.claims(), vec![2 * TICK_SIZE]);
    }

    /// Tokens delivered just before `delivery_done` must still be claimed: the driver re-reads `delivered`
    /// after observing `done`, so the last raw-token remainder is never dropped by the load/load race.
    #[tokio::test]
    async fn claims_tokens_delivered_up_to_done() {
        let b = RecordingBackend::new();
        let delivered = Arc::new(AtomicU64::new(TICK_SIZE as u64));
        let done = Arc::new(AtomicBool::new(false));
        delivered.store((TICK_SIZE + 7) as u64, Ordering::Release);
        done.store(true, Ordering::Release);
        let claimed = drive_advance(
            &b,
            &"tc".to_string(),
            &LocalNote::generate(),
            instant(),
            4,
            TICK_SIZE as u64,
            true,
            delivered,
            done,
        )
        .await
        .unwrap();
        assert_eq!(claimed, TICK_SIZE + 7);
        assert_eq!(b.claims(), vec![TICK_SIZE + 7]);
    }

    /// R20-03/R20-09: backlog is a sequence of cumulative one-tick-or-smaller claims, never one oversized
    /// delta.
    #[tokio::test]
    async fn backlog_over_one_tick_is_split_across_later_claims() {
        let b = RecordingBackend::new();
        let windows = AdvanceWindows {
            claim_interval: Duration::from_secs(1),
            seconds_per_tick: Duration::from_secs(1),
            promote: Duration::ZERO,
            probe: Duration::ZERO,
        };
        let claimed = drive_recording(&b, windows, 4, (3 * TICK_SIZE) as u64).await;
        assert_eq!(claimed, 3 * TICK_SIZE);
        assert_eq!(
            b.claims(),
            vec![2 * TICK_SIZE, 3 * TICK_SIZE],
            "the probe seeds one tick; each later cumulative delta is exactly one tick"
        );
    }

    /// Combined R20-03/R20-09 restart regression: an already-accepted high-water H is the local base, newly
    /// delivered N is added exactly once, and even a backlog above one tick is submitted as one-tick-or-smaller
    /// cumulative increments.
    #[tokio::test]
    async fn restart_at_h_plus_delivered_n_preserves_the_per_call_cap() {
        let b = RecordingBackend::resumed(TICK_SIZE, 2 * TICK_SIZE);
        let claimed = drive_recording(&b, instant(), 4, (TICK_SIZE + 17) as u64).await;
        assert_eq!(claimed, 3 * TICK_SIZE + 17);
        assert_eq!(b.claims(), vec![3 * TICK_SIZE, 3 * TICK_SIZE + 17]);
        assert_eq!(b.attempts(), b.claims());
        let mut previous = 2 * TICK_SIZE;
        for cumulative in b.attempts() {
            assert!(
                cumulative - previous <= MAX_CLAIM_DELTA,
                "restart claim delta exceeded the contract hard cap"
            );
            previous = cumulative;
        }
        assert_eq!(b.accepts.load(Ordering::Relaxed), 0);
    }

    /// Combined lost-response regression: the submitted call advances by one tick, while an authoritative
    /// H+k readback at exact delivery-target equality may move the local cursor farther without another
    /// oversized submission.
    #[tokio::test]
    async fn lost_claim_response_h_plus_k_keeps_the_submitted_delta_capped() {
        let b = RecordingBackend::resyncing(3 * TICK_SIZE);
        let claimed = drive_recording(&b, instant(), 4, (3 * TICK_SIZE) as u64).await;
        assert_eq!(claimed, 3 * TICK_SIZE);
        assert_eq!(
            b.attempts(),
            vec![2 * TICK_SIZE],
            "the only submitted delta is one tick above the probe-seeded high-water"
        );
        assert_eq!(b.attempts()[0] - TICK_SIZE, MAX_CLAIM_DELTA);
        assert!(
            b.claims().is_empty(),
            "the lost-response claim was reconciled, not recorded as a fresh success"
        );
    }

    /// A concurrent/stale on-chain cursor is not delivery evidence for this process. Even when it stays
    /// within the funded budget, a cursor beyond the current authoritative delivery target must fail closed
    /// and must never reach finalization.
    #[tokio::test]
    async fn higher_claim_readback_beyond_delivery_target_fails_closed() {
        let b = RecordingBackend::resyncing(3 * TICK_SIZE);
        let error = drive_advance(
            &b,
            &"tc".to_string(),
            &LocalNote::generate(),
            instant(),
            4,
            TICK_SIZE as u64,
            true,
            Arc::new(AtomicU64::new((2 * TICK_SIZE) as u64)),
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .expect_err("an on-chain cursor beyond delivered tokens must fail closed");

        assert!(
            error.to_string().contains("invalid claim resync"),
            "{error}"
        );
        assert!(
            b.claims().is_empty(),
            "the stale lower claim was not recorded"
        );
        assert_eq!(
            b.attempts(),
            vec![2 * TICK_SIZE],
            "the rejected resync still originated from a one-tick submitted delta"
        );
        assert_eq!(
            b.finalized.load(Ordering::Relaxed),
            0,
            "an unproven high-water must never be finalized"
        );
    }

    /// Boundary timing: a ready backlog is not submitted before the configured interval, while equality at
    /// the boundary is allowed. The canonical test above pins that interval to exactly 60 seconds; this uses
    /// a one-second injected deal bound to keep the focused suite fast.
    #[tokio::test]
    async fn claim_waits_until_interval_boundary() {
        let b = RecordingBackend::new();
        let windows = AdvanceWindows {
            claim_interval: Duration::from_secs(1),
            seconds_per_tick: Duration::from_secs(1),
            promote: Duration::ZERO,
            probe: Duration::ZERO,
        };
        let started = tokio::time::Instant::now();
        let claimed = drive_recording(&b, windows, 4, (2 * TICK_SIZE) as u64).await;
        assert_eq!(claimed, 2 * TICK_SIZE);
        assert!(
            started.elapsed() >= Duration::from_secs(1),
            "claim landed before MIN_CLAIM_INTERVAL"
        );
        assert_eq!(b.claims(), vec![2 * TICK_SIZE]);
    }
}
