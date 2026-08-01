//! Stream state machine and the contested-tail invariant. Pure, no network -- fit for `proptest`.
//! States: `Opening` -> `Streaming` -> `Stopping`/`Disputed` -> `Closed`.
//! Opening a stream moves NO money beyond freezing the probe. Once accepted, that probe is both paid and
//! seeded as the first trusted tick of the cumulative claim pipeline; every later claim therefore includes
//! it instead of adding another first tick on top.
//! INVARIANT: the buyer's at-risk amount is exactly the CONTESTED TAIL -- the newest claim minus what is
//! already trusted. Trusted value is settled and no longer at risk; the tail is what a dispute puts at
//! stake. Unlike the old fixed `2*P` bound this is not a constant, because the seller may batch a larger
//! claim after a longer silence; what bounds it is the on-chain rate limit plus the buyer's own attention.
//! Every transition checks that the tail never goes negative and that trusted consumption never regresses.

use crate::chain::SettlementActionReceipt;
use crate::params::{DobParams, Shell};
use crate::settle::{contested_burn, probe_burn, ContestedBurn};
use serde::{Deserialize, Serialize};
use std::fmt;

/// One tick: index and price in SHELL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tick {
    pub index: u64,
    pub price: Shell,
}

/// Stream state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamState {
    /// The seller has not posted the endpoint yet; nothing is claimable.
    Opening,
    /// Trial tick frozen out of the escrow and owed to NOBODY. Nothing is claimable until the
    /// seller accepts it after `PROBE_WINDOW` of buyer silence; a stop here burns it on both sides.
    Probe { tick: Tick },
    /// The stream is open. Consumption is tracked in TICKS of value: `trusted` is promoted and
    /// irrevocably the seller's, `pending` is the newest claim and still contestable.
    Streaming {
        /// Promoted cumulative consumption -- the only figure money is computed from.
        trusted: u64,
        /// Newest claimed cumulative consumption; `pending >= trusted` always.
        pending: u64,
    },
    /// The buyer issued STOP -> settle by fact.
    Stopping,
    /// Dispute: the contested tail and a mirroring slice of the seller bond are frozen.
    Disputed {
        /// Trusted consumption at the moment of the dispute -- never at stake.
        trusted: u64,
        /// The contested tail the dispute is about.
        contested: u64,
    },
    /// Self-destruction of `token_contract`.
    Closed,
}

/// Settlement on completion/stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settlement {
    /// A production shellnet action proved by one new immutable TokenContract event plus a strict
    /// post-read. The pure state-machine variants below remain mock-only projections.
    AuthoritativeReceipt(Box<SettlementActionReceipt>),
    /// An unresolved dispute timed out: the contested value burns on both sides, so a claim nobody
    /// can defend profits neither party. Trusted value and the unspent deposit are unaffected.
    BurnBoth(ContestedBurn),
    /// Settlement BY FACT -- the shape of every clean terminal path: buyer `stop()`, seller
    /// `sellerStop()`, `finalize()` on an exhausted deal, and a conceded dispute. Trusted consumption goes
    /// to the seller, everything else returns to the buyer, and the bond comes back whole.
    /// The contested tail is NOT paid here: it never had its window, and the party leaving is precisely the
    /// one who would have had to defend or accept it.
    AmicableSplit {
        /// Ticks credited to the seller(trusted consumption, plus whole take-or-pay weeks).
        to_seller_ticks: u64,
        /// Refunded to the buyer(unspent escrow).
        to_buyer_refund: u128,
    },
    /// The seller never opened the deal: the buyer's whole deposit returns and the seller's bond returns
    /// too -- nothing was delivered, so there is no fee and no penalty. A no-show is not slashed.
    SellerNoShow {
        /// Refund to the buyer(the whole deposit).
        to_buyer_refund: u128,
        /// Return of the seller's bond(not burned on a no-show).
        seller_bond_returned: u128,
    },
}

impl fmt::Display for Settlement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthoritativeReceipt(receipt) => receipt.fmt(formatter),
            mock_projection => write!(formatter, "{mock_projection:?}"),
        }
    }
}

/// Error for an invariant violation / disallowed transition.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("stream machine invariant violation: {0}")]
pub struct InvariantError(pub &'static str);

/// Stream state machine. The tick price `P` is fixed at stream open.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamMachine {
    state: StreamState,
    price: Shell,
    /// Seller mirror bond `2P`, locked from `open()` until a terminal state.
    seller_bond: u128,
}

impl StreamMachine {
    /// Open a stream: the seller posted the `2P` mirror bond and the endpoint, and ONE tick is frozen
    /// out of the escrow as the probe. That tick is owed to nobody yet -- the seller earns it only by
    /// surviving `PROBE_WINDOW` of buyer silence, and nothing can be claimed before then.
    pub fn open(price: Shell, _params: &DobParams) -> Self {
        Self {
            state: StreamState::Probe {
                tick: Tick { index: 0, price },
            },
            price,
            seller_bond: u128::from(price) * 2,
        }
    }

    /// The probe survived `PROBE_WINDOW` without the buyer objecting: silence on a live endpoint is consent
    /// . The trial tick becomes the seller's and the deal becomes claimable. It is also the first
    /// trusted tick in the cumulative claim pipeline, so the next claim starts above one rather than
    /// re-stating an already-paid probe.
    pub fn on_probe_accepted(&mut self) -> Result<(), InvariantError> {
        match &self.state {
            StreamState::Probe { .. } => {
                self.state = StreamState::Streaming {
                    trusted: 1,
                    pending: 1,
                };
                Ok(())
            }
            _ => Err(InvariantError("on_probe_accepted requires the probe state")),
        }
    }

    /// Whether the deal is still on the trial tick, i.e. nothing is claimable yet.
    pub fn on_probe(&self) -> bool {
        matches!(self.state, StreamState::Probe { .. })
    }

    /// The current state.
    pub fn state(&self) -> &StreamState {
        &self.state
    }

    /// The tick price `P`.
    pub fn price(&self) -> Shell {
        self.price
    }

    /// Promoted(trusted) consumption in ticks -- what the seller has actually earned.
    pub fn trusted_ticks(&self) -> u64 {
        match &self.state {
            StreamState::Streaming { trusted, .. } | StreamState::Disputed { trusted, .. } => {
                *trusted
            }
            _ => 0,
        }
    }

    /// The seller claims a new CUMULATIVE consumption total. Landing a claim promotes the previous one:
    /// nobody contested it, and an open dispute blocks this path entirely.
    /// Rejects a regressing total -- claims are cumulative by contract, and a decreasing figure would let a
    /// seller retract a claim the buyer had already accepted.
    pub fn on_claim(&mut self, cumulative: u64) -> Result<(), InvariantError> {
        match &self.state {
            StreamState::Streaming { pending, .. } => {
                if cumulative < *pending {
                    return Err(InvariantError("claims are cumulative and cannot decrease"));
                }
                self.state = StreamState::Streaming {
                    trusted: *pending,
                    pending: cumulative,
                };
                self.check_invariant()?;
                Ok(())
            }
            _ => Err(InvariantError("on_claim requires an open stream")),
        }
    }

    /// The promotion window elapsed with no dispute: the newest claim becomes trusted(`finalize`).
    pub fn on_promote(&mut self) -> Result<(), InvariantError> {
        match &self.state {
            StreamState::Streaming { pending, .. } => {
                self.state = StreamState::Streaming {
                    trusted: *pending,
                    pending: *pending,
                };
                self.check_invariant()?;
                Ok(())
            }
            _ => Err(InvariantError("on_promote requires an open stream")),
        }
    }

    /// Buyer STOP.
    /// On the PROBE the buyer is walking away from the trial itself, so the tick burns together with a mirror
    /// tick of the bond: a seller who meant to take the first tick and vanish collects nothing and
    /// pays a tick for the attempt. After acceptance it settles by fact -- trusted consumption to the
    /// seller, the rest refunded, and the contested tail dropped, since walking away IS the statement that it
    /// is disputed.
    pub fn buyer_stop(&mut self) -> Settlement {
        let settlement = match &self.state {
            StreamState::Probe { tick } => {
                let price = tick.price;
                let bond = Shell::try_from(self.seller_bond).unwrap_or(Shell::MAX);
                Settlement::BurnBoth(probe_burn(price, bond))
            }
            _ => Settlement::AmicableSplit {
                to_seller_ticks: self.trusted_ticks(),
                to_buyer_refund: 0,
            },
        };
        self.state = StreamState::Stopping;
        settlement
    }

    /// The seller abandons the deal(`sellerStop`). Identical settlement shape to a buyer stop: pay the
    /// trusted consumption, refund the rest. He forfeits the pending tail exactly as the buyer would, so
    /// quitting never pays better than delivering.
    pub fn seller_stop(&mut self) -> Settlement {
        let settlement = Settlement::AmicableSplit {
            to_seller_ticks: self.trusted_ticks(),
            to_buyer_refund: 0,
        };
        self.state = StreamState::Stopping;
        settlement
    }

    /// The seller never opened the deal(`cleanupUnopened`): full refund both ways, no burn.
    pub fn seller_no_show(&mut self) -> Settlement {
        let settlement = Settlement::SellerNoShow {
            to_buyer_refund: 0,
            seller_bond_returned: self.seller_bond,
        };
        self.state = StreamState::Closed;
        settlement
    }

    /// The buyer opened a dispute: the contested tail and a mirroring slice of the bond freeze.
    pub fn buyer_dispute(&mut self) {
        let (trusted, pending) = match &self.state {
            StreamState::Streaming { trusted, pending } => (*trusted, *pending),
            StreamState::Disputed { trusted, contested } => (*trusted, *trusted + *contested),
            _ => (0, 0),
        };
        self.state = StreamState::Disputed {
            trusted,
            contested: pending.saturating_sub(trusted),
        };
    }

    /// The seller CONCEDES the dispute(`releaseDispute`): the contested tail is dropped, the bond returns
    /// in full and nothing burns. Everything already trusted stays his -- it was never in dispute.
    pub fn release_dispute(&mut self) -> Settlement {
        let settlement = Settlement::AmicableSplit {
            to_seller_ticks: self.trusted_ticks(),
            to_buyer_refund: 0,
        };
        self.state = StreamState::Closed;
        settlement
    }

    /// `DISPUTE_WINDOW` passed with nobody conceding(`resolveDisputeTimeout`): the seller's whole bond burns
    /// and an equal amount of the buyer's escrow with it. Trusted value is untouched.
    /// The burn is FIXED at the bond, not scaled to what was claimed -- a claim-sized burn would be asymmetric,
    /// since the rate allowance lets one claim assert far more than the bond covers.
    pub fn resolve_dispute_timeout(&mut self) -> Settlement {
        let bond = Shell::try_from(self.seller_bond).unwrap_or(Shell::MAX);
        // The pure machine carries no separate deposit, so adapters re-clamp the buyer's side against the
        // real escrow.
        let settlement = Settlement::BurnBoth(contested_burn(bond, bond));
        self.state = StreamState::Closed;
        settlement
    }

    /// Clean close after a stop/split: `token_contract` self-destructs.
    pub fn close(&mut self) {
        self.state = StreamState::Closed;
    }

    /// The buyer's at-risk value in the current state: the contested tail, valued at the tick price.
    /// Trusted consumption is already settled and therefore not a loss; the unspent escrow is refundable at
    /// any moment via `stop()`. So what the buyer can still lose to a dishonest counterparty is exactly the
    /// claim that has not yet been through its window.
    pub fn max_buyer_loss(&self) -> u128 {
        let tail = match &self.state {
            StreamState::Opening | StreamState::Closed => 0,
            // On the probe the risk is exactly the trial tick: it burns if the buyer walks away.
            StreamState::Probe { .. } => 1,
            StreamState::Streaming { trusted, pending } => pending.saturating_sub(*trusted),
            StreamState::Disputed { contested, .. } => *contested,
            // A stop settles by fact and drops the tail: nothing further is at risk.
            StreamState::Stopping => 0,
        };
        u128::from(tail).saturating_mul(u128::from(self.price))
    }

    /// Check the claim-pipeline invariant. Every transition must hold it.
    fn check_invariant(&self) -> Result<(), InvariantError> {
        if let StreamState::Streaming { trusted, pending } = &self.state {
            if pending < trusted {
                return Err(InvariantError(
                    "the newest claim cannot be below trusted consumption",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> DobParams {
        DobParams::canonical()
    }

    /// Opening freezes the TRIAL tick and nothing else: it is owed to nobody, so the buyer's exposure is
    /// exactly that one tick and the seller has earned nothing.
    #[test]
    fn open_starts_on_the_probe_with_one_tick_at_risk() {
        let m = StreamMachine::open(1000, &params());
        assert!(m.on_probe(), "a fresh deal is on the trial tick");
        assert_eq!(m.max_buyer_loss(), 1000, "exactly the probe is at risk");
        assert_eq!(m.trusted_ticks(), 0, "the probe is not earned yet");
    }

    /// Accepting the probe makes the deal claimable and seeds it as the first trusted cumulative tick.
    #[test]
    fn accepting_the_probe_seeds_the_cumulative_pipeline() {
        let mut m = StreamMachine::open(1000, &params());
        m.on_probe_accepted().unwrap();
        assert!(!m.on_probe());
        assert!(matches!(
            m.state(),
            StreamState::Streaming {
                trusted: 1,
                pending: 1
            }
        ));
        assert_eq!(
            m.max_buyer_loss(),
            0,
            "nothing claimed yet -> nothing at risk"
        );
    }

    /// Nothing is claimable while the probe stands -- the contract rejects such a claim outright.
    #[test]
    fn claims_are_refused_while_on_the_probe() {
        let mut m = StreamMachine::open(1000, &params());
        assert_eq!(
            m.on_claim(1),
            Err(InvariantError("on_claim requires an open stream"))
        );
    }

    /// Walking away from the trial burns it on both sides, and the rest of the bond returns.
    #[test]
    fn stop_on_the_probe_burns_the_trial_tick() {
        let mut m = StreamMachine::open(1000, &params());
        match m.buyer_stop() {
            Settlement::BurnBoth(b) => {
                assert_eq!(b.buyer, 1000, "the trial tick is destroyed");
                assert_eq!(b.seller, 1000, "a mirror tick of the bond goes with it");
                assert_eq!(b.seller_refund, 1000, "the rest of the 2P bond returns");
            }
            other => panic!("a probe stop must burn, got {other:?}"),
        }
    }

    /// The first claim is contestable; the second promotes the first. That lag is the whole safety
    /// property -- the seller can never cash a figure the buyer had no window to challenge.
    #[test]
    fn a_claim_promotes_only_the_previous_one() {
        let mut m = StreamMachine::open(1000, &params());
        m.on_probe_accepted().unwrap();
        m.on_claim(3).unwrap();
        assert_eq!(
            m.trusted_ticks(),
            1,
            "only the already-paid probe is trusted"
        );
        assert_eq!(
            m.max_buyer_loss(),
            2000,
            "only consumption beyond the trusted probe is contestable"
        );

        m.on_claim(5).unwrap();
        assert_eq!(m.trusted_ticks(), 3, "the superseded claim became trusted");
        assert_eq!(m.max_buyer_loss(), 2000, "only the new delta is at risk");
    }

    /// `finalize()` is what makes the LAST claim payable: nothing supersedes it.
    #[test]
    fn promote_drains_the_tail() {
        let mut m = StreamMachine::open(1000, &params());
        m.on_probe_accepted().unwrap();
        m.on_claim(4).unwrap();
        m.on_promote().unwrap();
        assert_eq!(m.trusted_ticks(), 4);
        assert_eq!(m.max_buyer_loss(), 0, "nothing left to contest");
    }

    /// Cumulative means cumulative: a seller must not be able to walk a claim back.
    #[test]
    fn claims_cannot_regress() {
        let mut m = StreamMachine::open(1000, &params());
        m.on_probe_accepted().unwrap();
        m.on_claim(7).unwrap();
        assert_eq!(
            m.on_claim(6),
            Err(InvariantError("claims are cumulative and cannot decrease"))
        );
    }

    /// A stop settles by FACT -- trusted only. The pending tail is forfeited, not paid.
    #[test]
    fn stop_pays_trusted_and_drops_the_tail() {
        let mut m = StreamMachine::open(1000, &params());
        m.on_probe_accepted().unwrap();
        m.on_claim(2).unwrap();
        m.on_claim(9).unwrap(); // trusted=2, pending=9
        assert_eq!(
            m.buyer_stop(),
            Settlement::AmicableSplit {
                to_seller_ticks: 2,
                to_buyer_refund: 0
            }
        );
        assert_eq!(m.max_buyer_loss(), 0);
    }

    /// A seller who quits is settled exactly like a buyer stop, so quitting never beats delivering.
    #[test]
    fn seller_stop_matches_buyer_stop() {
        let mut a = StreamMachine::open(1000, &params());
        a.on_probe_accepted().unwrap();
        a.on_claim(2).unwrap();
        a.on_claim(9).unwrap();
        let mut b = a.clone();
        assert_eq!(a.buyer_stop(), b.seller_stop());
    }

    /// A no-show is not slashed: the full bond returns.
    #[test]
    fn seller_noshow_returns_the_whole_bond() {
        let mut m = StreamMachine::open(1000, &params());
        assert_eq!(
            m.seller_no_show(),
            Settlement::SellerNoShow {
                to_buyer_refund: 0,
                seller_bond_returned: 2000,
            }
        );
    }

    /// Conceding costs the seller only the tail he could not defend -- and no burn.
    #[test]
    fn release_dispute_keeps_trusted_and_burns_nothing() {
        let mut m = StreamMachine::open(1000, &params());
        m.on_probe_accepted().unwrap();
        m.on_claim(2).unwrap();
        m.on_claim(9).unwrap();
        m.buyer_dispute();
        assert!(matches!(
            m.state(),
            StreamState::Disputed {
                trusted: 2,
                contested: 7
            }
        ));
        assert_eq!(
            m.release_dispute(),
            Settlement::AmicableSplit {
                to_seller_ticks: 2,
                to_buyer_refund: 0
            }
        );
    }

    /// An unresolved dispute costs each side the SAME: the seller's whole bond, mirrored on the buyer's
    /// side. Equal cost is what stops either party from preferring deadlock.
    #[test]
    fn dispute_timeout_burns_the_whole_bond_symmetrically() {
        let mut m = StreamMachine::open(1000, &params());
        m.on_probe_accepted().unwrap();
        m.on_claim(1).unwrap();
        m.on_claim(2).unwrap();
        m.buyer_dispute();
        match m.resolve_dispute_timeout() {
            Settlement::BurnBoth(b) => {
                assert_eq!(b.seller, 2000, "the whole 2P bond is destroyed");
                assert_eq!(b.seller_refund, 0, "nobody conceded -> none of it returns");
                assert_eq!(b.buyer, 2000, "an equal amount of the buyer's escrow burns");
                assert_eq!(b.total(), 4000);
            }
            other => panic!("expected BurnBoth, got {other:?}"),
        }
    }

    /// The burn does not scale with the claim: a wildly inflated claim costs the seller exactly the same as
    /// a small one, so the size of the lie does not shift the balance of the argument.
    #[test]
    fn dispute_burn_does_not_scale_with_the_claim() {
        let mut small = StreamMachine::open(1000, &params());
        small.on_probe_accepted().unwrap();
        small.on_claim(1).unwrap();
        small.buyer_dispute();

        let mut huge = StreamMachine::open(1000, &params());
        huge.on_probe_accepted().unwrap();
        huge.on_claim(5_000).unwrap();
        huge.buyer_dispute();

        assert_eq!(
            small.resolve_dispute_timeout(),
            huge.resolve_dispute_timeout()
        );
    }

    /// A dispute must not INCREASE the buyer's exposure -- it only freezes what was already contested.
    #[test]
    fn dispute_does_not_grow_exposure() {
        let mut m = StreamMachine::open(1000, &params());
        m.on_probe_accepted().unwrap();
        m.on_claim(2).unwrap();
        m.on_claim(5).unwrap();
        let before = m.max_buyer_loss();
        m.buyer_dispute();
        assert_eq!(m.max_buyer_loss(), before);
        assert_eq!(before, 3000);
    }

    /// A high but valid price must not overflow the bond or the exposure arithmetic.
    #[test]
    fn high_valid_price_preserves_exact_two_p_bond() {
        let step = u64::try_from(crate::params::PRICE_STEP).unwrap();
        let price = u64::MAX - (u64::MAX % step);
        assert!(price > u64::MAX / 2);

        let mut m = StreamMachine::open(price, &params());
        m.on_probe_accepted().unwrap();
        m.on_claim(2).unwrap();
        assert_eq!(m.max_buyer_loss(), u128::from(price));

        let mut unopened = StreamMachine::open(price, &params());
        assert_eq!(
            unopened.seller_no_show(),
            Settlement::SellerNoShow {
                to_buyer_refund: 0,
                seller_bond_returned: u128::from(price) * 2,
            }
        );
    }
}
