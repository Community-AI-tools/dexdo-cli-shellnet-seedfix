//! - the live withdrawal proof must assert ARRIVAL, and these are its negative controls.

//! Measured on the test chain, 2026-08-20. The only live test of `withdrawTokens` sent SHELL to the
//! hardcoded ASCII constant `0:3335333533353335...` -- the bytes are literally the character "5"
//! repeated -- and asserted nothing about where it landed. That account carries
//! `44 850 000 000 000` raw ECC[2] (44 850 SHELL), `acc_type 0`, no code hash and no key: read back
//! directly, it is uninit, so every one of its 45 transactions aborted while the currency stuck.

//! The point of these cases is that the check FAILS on the shapes that actually happen. A wrong
//! destination looks exactly like a correct one from the sender's side: the note flips to
//! `hasWithdrawn` either way. Only the destination's own balance can tell them apart.

use super::{check_withdrawal_arrival, NoteWithdrawalArrival};

/// The real shape: both note planes land at the multisig, to the unit.
#[test]
fn both_note_planes_arriving_at_the_destination_is_the_only_pass() {
    let arrival = NoteWithdrawalArrival {
        note_trading_record: 950_000_000_000,
        note_ecc_pocket: 50_000_000_000,
        destination_before: 950_000_000_000,
        destination_after: 1_950_000_000_000,
    };
    assert_eq!(check_withdrawal_arrival(&arrival), Ok(1_000_000_000_000));
}

/// THE DEFECT, as a control. The withdrawal went to an account that cannot receive on our
/// behalf, so the destination we actually watch never moves. The note still flipped to
/// `hasWithdrawn`, which is exactly why the old assertion stayed green.
#[test]
fn a_destination_that_never_moved_is_refused() {
    let arrival = NoteWithdrawalArrival {
        note_trading_record: 996_000_000_000,
        note_ecc_pocket: 4_000_000_000,
        destination_before: 950_000_000_000,
        destination_after: 950_000_000_000,
    };
    let error = check_withdrawal_arrival(&arrival).expect_err("a silent send must not pass");
    assert!(
        error.contains("gained 0 raw"),
        "the reading must say the destination gained nothing: {error}"
    );
    assert!(
        error.contains("1000000000000"),
        "and must name what was expected: {error}"
    );
}

/// Only the trading record arrived and the physical pocket did not -- the failure a reader who knows
/// about one plane and not the other would call success.
#[test]
fn one_plane_arriving_without_the_other_is_refused() {
    let arrival = NoteWithdrawalArrival {
        note_trading_record: 996_000_000_000,
        note_ecc_pocket: 4_000_000_000,
        destination_before: 0,
        destination_after: 996_000_000_000,
    };
    assert!(check_withdrawal_arrival(&arrival).is_err());
}

/// A shortfall is a FINDING, not a tolerance. If something on the RootPN path ever takes a cut, this
/// must fail and be reported rather than be absorbed by loosening the comparison to `>=`.
#[test]
fn a_one_unit_shortfall_still_fails() {
    let arrival = NoteWithdrawalArrival {
        note_trading_record: 1_000_000_000_000,
        note_ecc_pocket: 0,
        destination_before: 0,
        destination_after: 999_999_999_999,
    };
    assert!(check_withdrawal_arrival(&arrival).is_err());
}

/// A surplus means the window caught somebody else's credit, so the measurement is not about this
/// withdrawal and must not be reported as if it were.
#[test]
fn a_surplus_is_refused_because_the_reading_is_no_longer_about_this_withdrawal() {
    let arrival = NoteWithdrawalArrival {
        note_trading_record: 1_000_000_000_000,
        note_ecc_pocket: 0,
        destination_before: 0,
        destination_after: 1_000_000_000_001,
    };
    assert!(check_withdrawal_arrival(&arrival).is_err());
}

/// A destination that went DOWN is not a small arrival; it is a reading that cannot mean what the
/// caller thinks, and it says so instead of wrapping.
#[test]
fn a_destination_that_fell_is_named_rather_than_wrapping() {
    let arrival = NoteWithdrawalArrival {
        note_trading_record: 1,
        note_ecc_pocket: 0,
        destination_before: 10,
        destination_after: 9,
    };
    let error = check_withdrawal_arrival(&arrival).expect_err("a fall must not wrap");
    assert!(error.contains("FELL"), "{error}");
}

/// Overflow on the note side is a mis-read, not a rich note.
#[test]
fn an_overflowing_expectation_is_refused() {
    let arrival = NoteWithdrawalArrival {
        note_trading_record: u128::MAX,
        note_ecc_pocket: 1,
        destination_before: 0,
        destination_after: 0,
    };
    assert!(check_withdrawal_arrival(&arrival).is_err());
}
