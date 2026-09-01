//! Settlement: fee, rebate, net burn, probe burn.

//! Pure formulas, no network. Covered by golden tests against table A.5.

use crate::params::{ProtocolConsts, Shell};

/// Platform fee by-fact, on the buyer's side.
/// `delivered_ticks` -- the ticks actually delivered, `p` -- the tick price.
pub fn fee(delivered_ticks: u64, p: Shell, c: &ProtocolConsts) -> Shell {
    mul_bps(c.platform_fee_bps, delivered_ticks, p)
}

/// Rebate rate in bps: `min(REBATE_MAX_BPS, SLOPE * n)`.
pub fn rebate_rate_bps(n_clean_ticks: u64, c: &ProtocolConsts) -> u32 {
    let slope = (c.rebate_slope_bps as u64).saturating_mul(n_clean_ticks);
    (slope.min(c.rebate_max_bps as u64)) as u32
}

/// Rebate to the seller -- only after a clean close without a dispute.
/// `0` on dispute/under-delivery (the caller simply does not invoke this function).
pub fn rebate(n_clean_ticks: u64, p: Shell, c: &ProtocolConsts) -> Shell {
    mul_bps(rebate_rate_bps(n_clean_ticks, c), n_clean_ticks, p)
}

/// Net burn `= (fee_rate - rebate_rate) * n * P`. Always `> 0` when `n > 0` on the canonical
/// constants. `saturating_sub`
/// `ProtocolConsts` fields are public and constructed directly (adapters/tests) -- on
/// a pathological `rebate_max_bps >= platform_fee_bps` we return `0` instead of panic(debug)/wrap(release).
pub fn net_burn(n_clean_ticks: u64, p: Shell, c: &ProtocolConsts) -> Shell {
    let rate = c
        .platform_fee_bps
        .saturating_sub(rebate_rate_bps(n_clean_ticks, c));
    mul_bps(rate, n_clean_ticks, p)
}

/// Resolution of an unresolved dispute: the seller's whole bond burns and an equal amount of
/// the buyer's escrow with it, while everything already trusted and the remaining deposit are paid out
/// normally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContestedBurn {
    /// The buyer's mirrored slice of the escrow -- burned.
    pub buyer: Shell,
    /// The buyer's remaining, unspent deposit -- refunded.
    pub buyer_refund: u128,
    /// The seller's bond -- burned in full.
    pub seller: Shell,
    /// Remainder of the seller's bond returned to him. Always zero on this path: nobody conceded, so the
    /// whole collateral is destroyed.
    pub seller_refund: Shell,
}

impl ContestedBurn {
    /// Total SHELL burned.
    pub fn total(&self) -> u128 {
        u128::from(self.buyer) + u128::from(self.seller)
    }
}

/// `contested_burn`: when `DISPUTE_WINDOW` passes with nobody conceding, the seller's WHOLE bond is
/// destroyed and an equal amount of the buyer's escrow with it.

/// The burn is deliberately FIXED at the bond rather than scaled to the disputed amount. Scaling it broke
/// symmetry: the rate allowance lets a single claim assert far more than the bond covers, so a claim-sized
/// burn would take a large slice of the buyer's escrow against a bond-sized slice of the seller's -- the
/// buyer would pay more than the seller for refusing to settle. At bond size, refusing costs exactly the
/// same on either side of the argument, which is what makes an unresolved dispute nobody's win.

/// The buyer's side is still clamped to what he actually holds, so a deposit smaller than the bond cannot
/// make the settlement underflow and brick the escrow. The pure stream machine has no separate deposit, so
/// real adapters fill `buyer_refund` from the pre-settlement contract state.
pub fn contested_burn(deposit: Shell, seller_bond: Shell) -> ContestedBurn {
    ContestedBurn {
        buyer: seller_bond.min(deposit),
        buyer_refund: 0,
        seller: seller_bond,
        seller_refund: 0,
    }
}

/// `probe_burn`: a buyer who walks away from the TRIAL tick destroys it, and a mirror tick of the
/// seller's bond with it. Neither side keeps it.

/// This is a different shape from [`contested_burn`], and deliberately so. Here the argument is about one
/// trial tick, so the stake is one tick on each side and the REST of the bond goes back -- a seller who set
/// out to take the first tick and vanish collects nothing and pays a tick for the attempt, but a seller whose
/// endpoint merely went down briefly is not wiped out. A dispute, by contrast, is about the deal as a whole,
/// and there the whole bond is at stake.

/// The seller's side is clamped to the bond he holds. The pure stream machine has no separate deposit, so
/// real adapters fill `buyer_refund` from the pre-settlement contract state.
pub fn probe_burn(probe_tick: Shell, seller_bond: Shell) -> ContestedBurn {
    let seller = probe_tick.min(seller_bond);
    ContestedBurn {
        buyer: probe_tick,
        buyer_refund: 0,
        seller,
        seller_refund: seller_bond - seller,
    }
}

/// `bps / 10000 * n * value`, in whole SHELL (rounded down).
fn mul_bps(bps: u32, n: u64, value: Shell) -> Shell {
    ((bps as u128) * (n as u128) * (value as u128) / 10_000u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden table A.5: REBATE_MAX_BPS=200, REBATE_SLOPE_BPS=4, P normalized to 10000
    // (so fractions like 0.25*P etc. are whole numbers). Then P = 10000 -> 1.0*P = 10000.
    const P: Shell = 10_000;

    fn c() -> ProtocolConsts {
        ProtocolConsts::canonical()
    }

    #[test]
    fn rebate_table_a5() {
        let c = c();
        // n=50: rate 2.00% (cap reached), rebate 1.0*P, net burn 0.25*P
        assert_eq!(rebate_rate_bps(50, &c), 200);
        assert_eq!(rebate(50, P, &c), P); // 1.0*P
        assert_eq!(net_burn(50, P, &c), P / 4); // 0.25*P

        // n=100: rebate 2.0*P, net burn 0.50*P (threshold N*)
        assert_eq!(rebate(100, P, &c), 2 * P);
        assert_eq!(net_burn(100, P, &c), P / 2);

        // n=150: rebate 3.0*P, net burn 0.75*P
        assert_eq!(rebate(150, P, &c), 3 * P);
        assert_eq!(net_burn(150, P, &c), 3 * P / 4);

        // n=1000: rebate 20*P, net burn 5*P
        assert_eq!(rebate(1000, P, &c), 20 * P);
        assert_eq!(net_burn(1000, P, &c), 5 * P);
    }

    #[test]
    fn rebate_strictly_below_fee_always() {
        let c = c();
        for n in 1u64..=2000 {
            assert!(
                rebate_rate_bps(n, &c) < c.platform_fee_bps,
                "rebate rate must stay strictly below platform fee"
            );
            assert!(net_burn(n, P, &c) > 0, "net burn must be positive for n>0");
        }
    }

    /// (regression): `ProtocolConsts` fields are public and can be constructed directly
    /// (adapters/tests) with a pathological `rebate_max_bps >= platform_fee_bps`. `net_burn`
    /// then saturates to 0, instead of panicking (debug) / wrapping (release).
    #[test]
    fn net_burn_saturates_on_pathological_consts() {
        let mut c = c();
        c.rebate_max_bps = c.platform_fee_bps + 100; // rebate may exceed the fee
                                                     // Large n: the rebate rate reaches the cap (>= fee) -> net rate = 0.
        assert_eq!(
            net_burn(1_000_000, P, &c),
            0,
            "saturating_sub: burn=0 instead of underflow"
        );
    }

    /// an unresolved dispute costs each side the SAME -- the seller's whole bond, mirrored out of the
    /// buyer's escrow. Equal cost is what stops either party from preferring deadlock.
    #[test]
    fn dispute_timeout_burn_is_bond_sized_and_symmetric() {
        let bond = 2 * P;
        let b = contested_burn(10 * P, bond);
        assert_eq!(b.seller, bond, "the whole bond is destroyed");
        assert_eq!(b.seller_refund, 0, "nobody conceded, so none of it returns");
        assert_eq!(b.buyer, bond, "an equal amount of the buyer's escrow burns");
        assert_eq!(b.total(), u128::from(bond) * 2);
    }

    /// The burn does not scale with what was claimed -- the claim is not even an input here. Whatever the
    /// seller asserted, refusing to settle costs him the bond and the buyer the same amount, so the size of
    /// the disputed figure cannot shift the balance of the argument.
    #[test]
    fn dispute_timeout_burn_does_not_depend_on_the_claim() {
        let bond = 2 * P;
        // Same deposit, any claim history: one and only one outcome.
        assert_eq!(contested_burn(10 * P, bond), contested_burn(10 * P, bond));
        // And it is bond-sized on both sides whenever the buyer can cover it.
        let b = contested_burn(10 * P, bond);
        assert_eq!(u128::from(b.buyer), u128::from(b.seller));
    }

    /// A buyer holding less than the bond burns only what he has, so the settlement cannot underflow and
    /// permanently brick the escrow.
    #[test]
    fn dispute_timeout_burn_clamps_to_the_buyers_deposit() {
        let b = contested_burn(P / 2, 2 * P);
        assert_eq!(b.buyer, P / 2, "clamped to what the buyer actually holds");
        assert_eq!(b.seller, 2 * P, "the seller still loses the whole bond");
    }

    /// walking away from the TRIAL tick stakes one tick per side -- not the whole bond. The rest of
    /// the collateral returns, so a brief outage is not punished like a scam.
    #[test]
    fn probe_burn_stakes_one_tick_per_side_and_returns_the_rest() {
        let b = probe_burn(P, 2 * P);
        assert_eq!(b.buyer, P, "the trial tick is destroyed");
        assert_eq!(b.seller, P, "a mirror tick of the bond goes with it");
        assert_eq!(
            b.seller_refund, P,
            "the remaining bond returns to the seller"
        );
        assert_eq!(b.total(), u128::from(P) * 2);
    }

    /// A probe burn is strictly cheaper for the seller than a lost dispute -- otherwise the cheap resolution
    /// would not be the attractive one.
    #[test]
    fn probe_burn_costs_the_seller_less_than_a_lost_dispute() {
        let bond = 2 * P;
        assert!(probe_burn(P, bond).seller < contested_burn(10 * P, bond).seller);
    }
}
