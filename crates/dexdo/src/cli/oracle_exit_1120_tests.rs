use super::{
    oracle_fee_expected_after, oracle_fee_postread_confirmed, pmp_exit_postread_confirmed,
    validate_pmp_exit_preflight, PmpExitAction, PmpExitObservation,
};

/// `getDetails.resultEnd` -- the chain's own `_resultStart + GRACE_PERIOD`. The fixed
/// `CancelStake` preflight reads it instead of keeping a second copy of GRACE_PERIOD.
const RESULT_END: u64 = 1_787_246_775;
/// One second inside the result window: every pre-existing case in this file is a case where the
/// grace period has NOT passed, so they keep meaning exactly what they meant before.
const BEFORE_GRACE_END: u64 = RESULT_END - 1;

fn observation() -> PmpExitObservation {
    PmpExitObservation {
        stake_present: true,
        candidate_amount: 0,
        amount_slots: 2,
        open_orders: 0,
        busy_address: None,
        has_withdrawn: false,
        note_balance: 10,
        coupons_value: 0,
    }
}

fn cancelled_pmp() -> serde_json::Value {
    serde_json::json!({
        "approved": true,
        "resultEnd": RESULT_END.to_string(),
        "resolvedOutcome": null,
        "isCancelled": true,
        "frozen": true,
        "numOutcomes": "2",
    })
}

fn resolved_pmp() -> serde_json::Value {
    serde_json::json!({
        "approved": true,
        "resultEnd": RESULT_END.to_string(),
        "resolvedOutcome": "1",
        "isCancelled": false,
        "frozen": true,
        "numOutcomes": "2",
    })
}

fn shutdown(done: bool) -> serde_json::Value {
    serde_json::json!({
        "orderBookDone": done,
        "shutdownTriggered": done,
    })
}

#[test]
fn issue_1120_cancel_stake_preflight_rejects_each_visible_contract_refusal() {
    assert!(validate_pmp_exit_preflight(
        PmpExitAction::CancelStake,
        &cancelled_pmp(),
        &shutdown(true),
        &observation(),
        BEFORE_GRACE_END,
    )
    .is_ok());

    let mut state = observation();
    state.stake_present = false;
    assert!(validate_pmp_exit_preflight(
        PmpExitAction::CancelStake,
        &cancelled_pmp(),
        &shutdown(true),
        &state,
        BEFORE_GRACE_END,
    )
    .unwrap_err()
    .to_string()
    .contains("no stake"));

    let mut state = observation();
    state.has_withdrawn = true;
    assert!(validate_pmp_exit_preflight(
        PmpExitAction::CancelStake,
        &cancelled_pmp(),
        &shutdown(true),
        &state,
        BEFORE_GRACE_END,
    )
    .unwrap_err()
    .to_string()
    .contains("withdrawn"));

    let mut state = observation();
    state.busy_address = Some("0:busy".into());
    assert!(validate_pmp_exit_preflight(
        PmpExitAction::CancelStake,
        &cancelled_pmp(),
        &shutdown(true),
        &state,
        BEFORE_GRACE_END,
    )
    .unwrap_err()
    .to_string()
    .contains("busy"));

    let mut state = observation();
    state.open_orders = 1;
    assert!(validate_pmp_exit_preflight(
        PmpExitAction::CancelStake,
        &cancelled_pmp(),
        &shutdown(true),
        &state,
        BEFORE_GRACE_END,
    )
    .unwrap_err()
    .to_string()
    .contains("open order"));

    let mut state = observation();
    state.candidate_amount = 1;
    assert!(validate_pmp_exit_preflight(
        PmpExitAction::CancelStake,
        &cancelled_pmp(),
        &shutdown(true),
        &state,
        BEFORE_GRACE_END,
    )
    .unwrap_err()
    .to_string()
    .contains("candidate"));

    let mut active = cancelled_pmp();
    active["isCancelled"] = serde_json::json!(false);
    assert!(validate_pmp_exit_preflight(
        PmpExitAction::CancelStake,
        &active,
        &shutdown(true),
        &observation(),
        BEFORE_GRACE_END,
    )
    .unwrap_err()
    .to_string()
    // CHANGED THIS ASSERTION ON PURPOSE. "not cancelled" alone was the whole old condition
    // and it refused the self-cancelling call the contract provides. The refusal is still here --
    // this PMP is inside its result window -- but it now names WHICH half is missing.
    .contains("grace period has not passed"));

    assert!(validate_pmp_exit_preflight(
        PmpExitAction::CancelStake,
        &cancelled_pmp(),
        &shutdown(false),
        &observation(),
        BEFORE_GRACE_END,
    )
    .unwrap_err()
    .to_string()
    .contains("OrderBook"));
}

#[test]
fn issue_1120_claim_preflight_requires_resolution_shutdown_and_exact_stake_width() {
    assert!(validate_pmp_exit_preflight(
        PmpExitAction::Claim,
        &resolved_pmp(),
        &shutdown(true),
        &observation(),
        BEFORE_GRACE_END,
    )
    .is_ok());

    let mut unapproved = resolved_pmp();
    unapproved["approved"] = serde_json::json!(false);
    assert!(validate_pmp_exit_preflight(
        PmpExitAction::Claim,
        &unapproved,
        &shutdown(true),
        &observation(),
        BEFORE_GRACE_END,
    )
    .is_err());

    let mut unresolved = resolved_pmp();
    unresolved["resolvedOutcome"] = serde_json::Value::Null;
    assert!(validate_pmp_exit_preflight(
        PmpExitAction::Claim,
        &unresolved,
        &shutdown(true),
        &observation(),
        BEFORE_GRACE_END,
    )
    .unwrap_err()
    .to_string()
    .contains("resolved outcome"));

    assert!(validate_pmp_exit_preflight(
        PmpExitAction::Claim,
        &resolved_pmp(),
        &shutdown(false),
        &observation(),
        BEFORE_GRACE_END,
    )
    .unwrap_err()
    .to_string()
    .contains("OrderBook"));

    let mut wrong_width = observation();
    wrong_width.amount_slots = 1;
    assert!(validate_pmp_exit_preflight(
        PmpExitAction::Claim,
        &resolved_pmp(),
        &shutdown(true),
        &wrong_width,
        BEFORE_GRACE_END,
    )
    .unwrap_err()
    .to_string()
    .contains("outcome"));
}

#[test]
fn issue_1120_postread_requires_the_callback_effect_not_only_a_successful_post() {
    let mut state = observation();
    assert!(!pmp_exit_postread_confirmed(&state));
    state.stake_present = false;
    state.busy_address = Some("0:pmp".into());
    assert!(!pmp_exit_postread_confirmed(&state));
    state.busy_address = None;
    assert!(pmp_exit_postread_confirmed(&state));
}

#[test]
fn issue_1120_fee_withdrawal_rejects_zero_overspend_and_unconfirmed_balance() {
    assert!(oracle_fee_expected_after(100, 0)
        .unwrap_err()
        .to_string()
        .contains("greater than zero"));
    assert!(oracle_fee_expected_after(100, 101)
        .unwrap_err()
        .to_string()
        .contains("exceeds"));
    assert_eq!(oracle_fee_expected_after(100, 40).unwrap(), 60);
    assert!(oracle_fee_postread_confirmed(60, 60));
    assert!(!oracle_fee_postread_confirmed(60, 100));
    assert!(!oracle_fee_postread_confirmed(60, 59));
}
