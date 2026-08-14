use super::*;
use crate::seller::gateway::GatewayState;
use dexdo_core::note::NotePubkey;
use std::any::Any;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;

const ENTRIES_POISON_PANIC: &str = " intentional capacity-entries poison";
const REQUEST_POISON_PANIC: &str = " intentional capacity-request poison";
const LIMITS_POISON_PANIC: &str = " intentional gateway-limits poison";

fn panic_text(payload: &(dyn Any + Send)) -> Option<&str> {
    payload
        .downcast_ref::<&'static str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
}

fn pre_probe_state() -> DealChainState {
    DealChainState {
        funded: true,
        opened: true,
        probe_accepted: false,
        disputed: false,
        deposit: 1,
        finalized_owed: 0,
        tokens_final: 0,
        tokens_pending: 0,
        probe_tick: 0,
        funded_time: Some(1),
        probe_time: 1,
        last_claim_time: 1,
        dispute_time: 0,
    }
}

fn one_token_ordinary_deal() -> DealSubscription {
    DealSubscription {
        deal_flags: 0,
        sub_weeks: 0,
        week_index: 0,
        tokens_per_week: 1,
        funded_tokens: 1,
        tokens_paid: 0,
        period_start: 0,
        week_base_tokens: 0,
    }
}

fn buyer_pubkey() -> NotePubkey {
    NotePubkey {
        x: [1; 32],
        ed: [2; 32],
    }
}

#[test]
fn issue_1157_capacity_snapshot_returns_a_named_error_after_lock_poison() {
    let manager = Arc::new(CapacityManager::in_memory());
    let poison_target = Arc::clone(&manager);
    let first_failure = std::thread::spawn(move || {
        let _guard = poison_target
            .entries
            .lock()
            .expect("capacity entries lock starts healthy");
        panic!("{ENTRIES_POISON_PANIC}");
    })
    .join()
    .expect_err("the first lock-holder failure must remain a real panic");
    assert_eq!(
        panic_text(first_failure.as_ref()),
        Some(ENTRIES_POISON_PANIC),
        "the first panic must remain observable and attributable"
    );

    let token_contract = "tc-1157-capacity".to_string();
    let snapshot = panic::catch_unwind(AssertUnwindSafe(|| manager.snapshot(&token_contract)))
        .expect("snapshot must return an error instead of panicking");
    let error = snapshot.expect_err("a poisoned capacity lock must return an error");
    assert!(
        error
            .to_string()
            .contains("seller runtime lock poisoned: seller capacity entries"),
        "the propagated error must name the poisoned lock: {error:#}"
    );
}

#[test]
fn issue_1157_authorize_exposure_returns_a_named_invalid_state_after_lock_poison() {
    let manager = CapacityManager::in_memory();
    let token_contract = "tc-1157-authorize".to_string();
    manager
        .reconcile_deal(
            &token_contract,
            pre_probe_state(),
            one_token_ordinary_deal(),
        )
        .expect("capacity setup must succeed");
    let reservation = Arc::new(
        manager
            .reserve(&token_contract, 1)
            .expect("one token must be reservable"),
    );
    let poison_target = Arc::clone(&reservation);
    let first_failure = std::thread::spawn(move || {
        let _guard = poison_target
            .request
            .lock()
            .expect("capacity request lock starts healthy");
        panic!("{REQUEST_POISON_PANIC}");
    })
    .join()
    .expect_err("the first lock-holder failure must remain a real panic");
    assert_eq!(
        panic_text(first_failure.as_ref()),
        Some(REQUEST_POISON_PANIC),
        "the first panic must remain observable and attributable"
    );

    let authorization = panic::catch_unwind(AssertUnwindSafe(|| reservation.authorize_exposure(1)))
        .expect("authorize_exposure must return an error instead of panicking");
    let error = authorization.expect_err("poison must refuse exposure");
    assert!(
        matches!(error, ReserveError::InvalidState(_)),
        "poison must use the invalid-state channel: {error}"
    );
    assert!(
        error
            .to_string()
            .contains("seller runtime lock poisoned: seller capacity reservation request"),
        "the propagated error must name the poisoned lock: {error}"
    );
}

#[test]
fn issue_1157_register_stream_returns_a_named_error_after_limits_lock_poison() {
    let state = Arc::new(GatewayState::new());
    let poison_target = Arc::clone(&state);
    let first_failure = std::thread::spawn(move || {
        poison_target.poison_limits_for_test(LIMITS_POISON_PANIC);
    })
    .join()
    .expect_err("the first lock-holder failure must remain a real panic");
    assert_eq!(
        panic_text(first_failure.as_ref()),
        Some(LIMITS_POISON_PANIC),
        "the first panic must remain observable and attributable"
    );

    let registration = panic::catch_unwind(AssertUnwindSafe(|| {
        state.register_stream(
            "tc-1157-register",
            buyer_pubkey(),
            1,
            pre_probe_state(),
            one_token_ordinary_deal(),
        )
    }))
    .expect("register_stream must return an error instead of panicking");
    let error = registration.expect_err("poisoned limits must refuse registration");
    assert!(
        error
            .to_string()
            .contains("seller runtime lock poisoned: seller gateway limits"),
        "the propagated error must name the poisoned lock: {error:#}"
    );
}
