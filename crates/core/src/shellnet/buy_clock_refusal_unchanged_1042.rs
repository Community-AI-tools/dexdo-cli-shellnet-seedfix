use super::*;

fn time_before_unix_epoch() -> std::time::SystemTime {
    std::time::UNIX_EPOCH
        .checked_sub(std::time::Duration::from_secs(1))
        .expect("one second before the Unix epoch is representable")
}

#[test]
fn buy_clock_fault_1042_keeps_the_existing_refusal() {
    let error = buy_deadline_now_secs_at(time_before_unix_epoch())
        .expect_err("the BUY deadline clock must refuse a pre-epoch time");

    assert!(matches!(&error, ChainError::Chain(_)), "{error:?}");
    assert!(
        error
            .to_string()
            .contains("cannot derive a finite BUY deadline from the system clock:"),
        "{error}"
    );
}
