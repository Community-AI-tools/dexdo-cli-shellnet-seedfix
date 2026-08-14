use super::*;

fn time_before_unix_epoch() -> std::time::SystemTime {
    std::time::UNIX_EPOCH
        .checked_sub(std::time::Duration::from_secs(1))
        .expect("one second before the Unix epoch is representable")
}

#[test]
fn render_clock_fault_1042_refuses_and_names_the_system_clock() {
    let error = match now_secs_at(time_before_unix_epoch()) {
        Ok(timestamp) => panic!("an unreadable render clock became timestamp {timestamp}"),
        Err(error) => error,
    };

    assert!(matches!(&error, ChainError::Chain(_)), "{error:?}");
    assert!(error.to_string().contains("system clock"), "{error}");
}
