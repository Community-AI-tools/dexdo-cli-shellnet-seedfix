//! mainnet reports its own connection-pool limit as HTTP **200** with the failure in the
//! body, and the read retry declined it.

//! Measured on head `ce0641c6`: `dexdo provision` against `https://net-b.example` failed
//! three times out of three -- once after ninety seconds of complete silence, so it was not caller
//! burst -- always on the chain-time preflight, always with the body reproduced below. Nothing was
//! ever sent; the refusal was correct, it just never retried.

//! The retry was already wrapped around that read (`retry_transient_read`). What declined it was
//! the predicate: `is_transient_transport_failure` inspects an HTTP status or a `reqwest` transport
//! error, and this response carries neither.

//! # Why the fix is a SECOND predicate and not a wider first one

//! `is_transient_transport_failure` also feeds `is_transient_submit_failure`, which gates the money
//! submit retry. Widening it would have widened **write** retry on the money path. Repeating a read
//! is safe because nothing was sent; repeating a submit is a different question, and this change
//! deliberately does not touch it. `the_submit_predicate_is_not_widened` is the guard on that.

use super::{is_transient_read_failure, is_transient_transport_failure, GraphQlBodyError};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The body mainnet actually returned, verbatim from the run that could not start.
fn pool_timeout_errors() -> serde_json::Value {
    json!([{
        "message": "pool timed out while waiting for an open connection",
        "locations": [{ "line": 1, "column": 16 }],
        "path": ["blockchain", "blocks"]
    }])
}

/// Built the way `fetch_chain_time_secs` builds it, context and all, so the test reads the error the
/// retry loop really receives rather than one composed for the occasion.
fn chain_time_failure(errors: &serde_json::Value) -> anyhow::Error {
    anyhow::Error::new(GraphQlBodyError::from_errors(errors)).context("GraphQL chain-time errors")
}

/// The defect, stated as the retry loop sees it.
#[tokio::test]
async fn a_pool_timeout_in_a_200_body_is_retried_and_then_succeeds() {
    let calls = AtomicUsize::new(0);
    let outcome: anyhow::Result<u64> = super::retry_transient_read(|| async {
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(chain_time_failure(&pool_timeout_errors()));
        }
        Ok(1_787_000_000)
    })
    .await;

    assert_eq!(
        outcome.expect("a pool timeout is transient, so the read must be repeated"),
        1_787_000_000
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "exactly one repeat: the first attempt failed transiently, the second answered"
    );
}

/// The predicate directly, so a failure here names the decision rather than the loop around it.
#[test]
fn the_read_predicate_recognises_the_pool_timeout() {
    assert!(is_transient_read_failure(&chain_time_failure(
        &pool_timeout_errors()
    )));
}

/// Narrowness. A body error that is not pool exhaustion is a real answer from the server and must
/// stay permanent -- a predicate that retried every `errors` entry would hammer deliberate refusals.
#[test]
fn another_error_in_the_same_body_shape_stays_permanent() {
    let refused = json!([{
        "message": "field 'nope' does not exist on type 'Query'",
        "path": ["blockchain", "blocks"]
    }]);
    assert!(!is_transient_read_failure(&chain_time_failure(&refused)));
}

/// THE guard on blast radius: the predicate that feeds the money-submit retry must not have moved.
/// If this ever passes, write retry has been widened by a change that was only asked to widen reads.
#[test]
fn the_submit_predicate_is_not_widened() {
    assert!(
        !is_transient_transport_failure(&chain_time_failure(&pool_timeout_errors())),
        "is_transient_transport_failure also gates the money submit retry and must not see this"
    );
}

/// The rendered message is unchanged, so anything reading the text -- logs, an operator, a grep --
/// sees exactly what it saw before the error grew a type.
#[test]
fn the_operator_facing_text_is_byte_identical_to_the_flattened_form() {
    let errors = pool_timeout_errors();
    let rendered = format!("{:#}", chain_time_failure(&errors));
    assert_eq!(rendered, format!("GraphQL chain-time errors: {errors}"));
}
