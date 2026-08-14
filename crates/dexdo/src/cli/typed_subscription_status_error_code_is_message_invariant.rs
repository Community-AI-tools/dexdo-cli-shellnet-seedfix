use super::*;

fn status_order_not_found(message: &str) -> anyhow::Error {
    anyhow::Error::new(SubscriptionStatusOrderNotFound::new(message))
}

#[test]
fn rewording_the_typed_status_failure_does_not_change_its_code_or_scope() {
    for message in [
        "mock subscription order 41 is absent or owned by another note",
        "the named subscription is not resting for this note",
    ] {
        let error = status_order_not_found(message);
        assert_eq!(
            classify_error(OP_SUBSCRIPTION_STATUS, &error),
            ErrorCode::OrderNotFound,
            "status classification moved when the carrier text changed: {message}"
        );
        assert_eq!(
            classify_error(OP_SUBSCRIPTION_CANCEL, &error),
            ErrorCode::Internal,
            "the status-only carrier leaked into mock cancel: {message}"
        );
    }
}

#[test]
fn removing_shadowed_chain_revert_clauses_keeps_their_inputs_no_liquidity() {
    for message in [
        "placeInferenceBuy cannot target a TokenContract",
        "refusing to send escrow into the wrong deal",
    ] {
        let error = anyhow::anyhow!(message);
        assert_eq!(
            classify_error(OP_BUYER_START, &error),
            ErrorCode::NoLiquidity,
            "the earlier NO_LIQUIDITY arm stopped shadowing: {message}"
        );
    }
}
