use super::*;
use crate::cli::machine::MachineFundingNotice;

const NOTICE: &str = "Hot wallet funding request submitted.";

#[test]
fn ackinacki_notice_is_yellow_only_for_a_terminal_without_no_color() {
    assert_eq!(
        render_ackinacki_funding_notice(NOTICE, true, false),
        format!("\x1b[33m{NOTICE}\x1b[0m")
    );
    assert_eq!(
        render_ackinacki_funding_notice(NOTICE, false, false),
        NOTICE
    );
    assert_eq!(render_ackinacki_funding_notice(NOTICE, true, true), NOTICE);
}

#[test]
fn every_funding_notice_has_one_stable_secret_free_machine_event() {
    let evidence = FundingEvidence {
        verdict: "executed".to_string(),
        source: "secret-looking-provider-response".to_string(),
        observed_at_unix: Some(7),
        detail: "owner_secret_key_hex=must-not-leak".to_string(),
        delivery_message_id: None,
    };
    let cases = [
        (FundingNotice::AlreadyFunded, "already_funded"),
        (FundingNotice::RequestSubmitted, "request_submitted"),
        (
            FundingNotice::RequestAlreadyPending,
            "request_already_pending",
        ),
        (
            FundingNotice::RequestExecuted { evidence },
            "request_executed",
        ),
        (
            FundingNotice::RequestIndeterminate {
                reason: "private_key=must-not-leak".to_string(),
            },
            "request_indeterminate",
        ),
        (
            FundingNotice::ManualTopUpRequested,
            "manual_top_up_requested",
        ),
    ];

    for (notice, expected) in cases {
        let machine: MachineFundingNotice = notice.machine_notice();
        let encoded = serde_json::to_string(&machine).expect("serialize machine notice");
        assert_eq!(encoded.lines().count(), 1);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encoded).unwrap(),
            serde_json::json!({ "event": expected })
        );
        assert!(!encoded.contains("secret") && !encoded.contains("private_key"));
    }
}
