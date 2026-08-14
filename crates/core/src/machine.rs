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

use crate::chain::{BuyerStopTerminalReceipt, SettlementActionReceipt};
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
    /// A terminal chain event observed by a buyer STOP path, carrying the exact attribution fact
    /// proved for this invocation.
    BuyerStopTerminal(Box<BuyerStopTerminalReceipt>),
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
            Self::BuyerStopTerminal(receipt) => receipt.fmt(formatter),
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

    /// Refuse a transition the current state has no room for, leaving that state untouched.
    /// `Opening` was never opened and `Stopping`/`Closed` are ends, so a terminal transition taken from one
    /// of them would mint a SECOND terminal record for one deal -- and, with `trusted_ticks()` reading 0
    /// there, one whose zero amounts are indistinguishable from a legitimate clean close. The
    /// contract refuses the same calls outright: `stop`, `sellerStop` and `releaseDispute` each open with
    /// `require(_opened, ERR_NOT_OPEN)`(`contracts/airegistry/TokenContract.sol`), so refusing here keeps
    /// the projection on the contract's own footing instead of answering where the chain would revert.
    /// It panics rather than returning an error because these transitions answer with `Settlement`, not
    /// `Result`: there is no settlement to hand back, and a well-formed zero-amount one is precisely the
    /// fail-open being closed. It is the same refusal the machine's own `Result` guards
    /// (`on_probe_accepted`, `on_claim`, `on_promote`) already express for the non-terminal steps.
    fn refuse_when_not_live(&self, transition: &'static str) -> ! {
        panic!(
            "{transition} is not a transition of a deal in state {:?}",
            self.state
        )
    }

    /// Buyer STOP.
    /// On the PROBE the buyer is walking away from the trial itself, so the tick burns together with a mirror
    /// tick of the bond: a seller who meant to take the first tick and vanish collects nothing and
    /// pays a tick for the attempt. After acceptance it settles by fact -- trusted consumption to the
    /// seller, the rest refunded, and the contested tail dropped, since walking away IS the statement that it
    /// is disputed. From a state that is not a live deal it is refused(see `refuse_when_not_live`).
    pub fn buyer_stop(&mut self) -> Settlement {
        let settlement = match &self.state {
            StreamState::Probe { tick } => {
                let price = tick.price;
                let bond = Shell::try_from(self.seller_bond).unwrap_or(Shell::MAX);
                Settlement::BurnBoth(probe_burn(price, bond))
            }
            StreamState::Streaming { .. } | StreamState::Disputed { .. } => {
                Settlement::AmicableSplit {
                    to_seller_ticks: self.trusted_ticks(),
                    to_buyer_refund: 0,
                }
            }
            StreamState::Opening | StreamState::Stopping | StreamState::Closed => {
                self.refuse_when_not_live("buyer_stop")
            }
        };
        self.state = StreamState::Stopping;
        settlement
    }

    /// The seller abandons the deal(`sellerStop`). Pay the trusted consumption, refund the rest. He
    /// forfeits the pending tail exactly as the buyer would, so quitting never pays better than delivering,
    /// and from a state that is not a live deal it is refused just like a buyer stop.
    /// On the PROBE the settlement shape stays this one and does NOT mirror the buyer's `BurnBoth`. The
    /// walk-out still costs the seller the same one tick -- the contract burns it out of his bond
    /// (`sellerStop`, `bondBurn = min(P, _sellerBond)`) -- but the trial tick itself is the buyer's until
    /// acceptance and he is not the one ending the deal, so it is released back into the escrow and refunded
    /// whole: spec, design and matrix row `E2E-TERM-03` (`contracts/test-specification.md`:
    /// `AmicableSplit { to_seller_ticks: 0, to_buyer_refund: escrow }`, `burned == P`) all state it that
    /// way, against `E2E-TERM-02`'s `burned == 2P` for the buyer's stop. The seller's bond burn is a chain
    /// fact; this variant carries no field for it, which is why the projection reports the split.
    pub fn seller_stop(&mut self) -> Settlement {
        let settlement = match &self.state {
            StreamState::Probe { .. }
            | StreamState::Streaming { .. }
            | StreamState::Disputed { .. } => Settlement::AmicableSplit {
                to_seller_ticks: self.trusted_ticks(),
                to_buyer_refund: 0,
            },
            StreamState::Opening | StreamState::Stopping | StreamState::Closed => {
                self.refuse_when_not_live("seller_stop")
            }
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
    /// in full and nothing burns. Everything already trusted stays his -- it was never in dispute. From a
    /// state that is not a live deal it is refused(see `refuse_when_not_live`).
    pub fn release_dispute(&mut self) -> Settlement {
        let settlement = match &self.state {
            StreamState::Probe { .. }
            | StreamState::Streaming { .. }
            | StreamState::Disputed { .. } => Settlement::AmicableSplit {
                to_seller_ticks: self.trusted_ticks(),
                to_buyer_refund: 0,
            },
            StreamState::Opening | StreamState::Stopping | StreamState::Closed => {
                self.refuse_when_not_live("release_dispute")
            }
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
