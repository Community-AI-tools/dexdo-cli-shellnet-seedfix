//! mutant guard: moving the empty-pool refusal out of the shared resolver must not drop it for
//! the two commands that still need it.

//! `reclaim` drives every recorded deal, so a pool that records none is a complete answer for it.
//! `recover` and `dispute` act on exactly ONE deal, so for them zero deals is still a refusal -- and
//! after that refusal lives in `resolve_recovery_inputs` rather than in `pool_recovery_plan`.
//! Nothing asserted it: a grep for the refusal text across the tree finds only the production site.

//! WHAT THIS TEST IS, AND WHAT IT IS NOT. It is NOT a red-then-green regression, and claiming so
//! would be false: before the same words came out of `pool_recovery_plan`, so this test passes
//! on the pre-change tree too. What it kills is the MUTANT -- delete the new `bail!` in
//! `resolve_recovery_inputs` and, without this file, no test in the repository turns red while
//! `recover` and `dispute` silently stop refusing an empty pool. That is the half of which
//! preserves behaviour, and preserved behaviour is exactly what drifts unnoticed.

use crate::cli::args::RecoveryIdentityArgs;

/// A pool holding real note entries and no `token_contract` recovery metadata at all -- the shape a
/// pool has when its notes never bought, which is what `fresh` and `neg335` look like on every run.
fn pool_with_no_recorded_deal(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "dexdo-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create the fixture directory");
    let pool_path = dir.join("pn_pool.json");
    crate::cli::support::write_owner_only_key_fixture(
        &pool_path,
        &serde_json::to_string_pretty(&serde_json::json!({
            "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
            "notes": [
                { "address": format!("0:{}", "1".repeat(64)), "owner_secret_key_hex": "2a".repeat(32) },
                { "address": format!("0:{}", "3".repeat(64)), "owner_secret_key_hex": "4b".repeat(32) },
            ],
        }))
        .expect("serialise the fixture pool"),
    );
    (dir, pool_path)
}

fn no_explicit_identity() -> RecoveryIdentityArgs {
    RecoveryIdentityArgs {
        note_key: None,
        note_addr: None,
    }
}

/// `dispute` acts on one deal. A pool that records none cannot name it, and saying so is the whole
/// of the refusal: the operator is told what to run instead, in the same words as before.
#[test]
fn dispute_still_refuses_a_pool_that_records_no_deal() {
    let (dir, pool_path) = pool_with_no_recorded_deal("dispute-empty-pool");
    // `expect_err` would demand `Debug` on the Ok type, and deriving it on `PoolRecoveryInputs`
    // (which carries `PoolRecoveryRecord`) would widen a test's need into a production change. The
    // match asks the same question and asks it of this file alone.
    let error = match super::resolve_pool_recovery_inputs(
        &no_explicit_identity(),
        None,
        None,
        Some(pool_path.as_path()),
    ) {
        Ok(_) => panic!("dispute acts on one deal, so a pool recording none must refuse"),
        Err(error) => error.to_string(),
    };
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        error.starts_with("dispute: DEXDO_PN_POOL "),
        "the refusal names the command that raised it: {error}"
    );
    assert!(
        error.contains("has no matching note entry with token_contract recovery metadata"),
        "the wording is the one operators already know: {error}"
    );
    assert!(
        error.contains("--note-addr/--note-key/--token-contract"),
        "and it still names the way out: {error}"
    );
}

/// `recover` is the other single-deal command, and it takes a different route into the same resolver
/// (`persists_pool_record = true`). Asserting only `dispute` would leave that route uncovered.
#[test]
fn recover_still_refuses_a_pool_that_records_no_deal() {
    let (dir, pool_path) = pool_with_no_recorded_deal("recover-empty-pool");
    // `expect_err` would demand `Debug` on the Ok type, and deriving it on `PoolRecoveryInputs`
    // (which carries `PoolRecoveryRecord`) would widen a test's need into a production change. The
    // match asks the same question and asks it of this file alone.
    let error = match super::resolve_persistable_pool_recovery_inputs(
        &no_explicit_identity(),
        None,
        None,
        Some(pool_path.as_path()),
    ) {
        Ok(_) => panic!("recover acts on one deal, so a pool recording none must refuse"),
        Err(error) => error.to_string(),
    };
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        error.starts_with("recover: DEXDO_PN_POOL "),
        "the refusal names the command that raised it: {error}"
    );
    assert!(
        error.contains("has no matching note entry with token_contract recovery metadata"),
        "the wording is the one operators already know: {error}"
    );
}
