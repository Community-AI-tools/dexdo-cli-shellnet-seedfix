//! the advice a stake-locked owner reads must not tell them the money is unrecoverable.

//! The shipped wording said the run's artefacts were "the only key" and that `_stakes` has "no
//! getter". An owner whose artefact is gone reads the first as a verdict and writes the balance off
//! -- at the moment this very module is holding two thirds of the key it says does not exist:
//! `read_gate` has already decoded `fields["_stakes"]` into a map and taken only its LENGTH
//! (`storage_map_len`), while each `StakeInfo` in it carries `tokenType` and `oracleListHash`
//! (`contracts/dex/modifiers/modifiers.sol:367-370`).

//! # Why these are tokens and one negative

//! The positives are single words (`oracleListHash`, `tokenType`, `NAME`) because the rendered line
//! is wrapped further out and a multi-word fragment can straddle a break. The negative -- "only
//! key" -- is asserted as ABSENT, which no wrap can fake in either direction: a phrase that is not
//! in the string cannot be split into it.

//! Asserted through `withdraw_gate_line`, not `next_step` alone, because the operator reads the
//! rendered line and that is where a future change would have to keep the promise.

use super::{withdraw_gate_line, NoteWithdrawGate, WithdrawGate};

fn stake_advice() -> String {
    withdraw_gate_line(&NoteWithdrawGate::Held(WithdrawGate::Stakes { count: 1 }))
}

/// The half that costs money. "The only key" is a verdict, and it is false: the key is recoverable
/// from the chain, so an owner who still has the note and its key has a path.
#[test]
fn the_stake_advice_never_calls_the_run_artefacts_the_only_key() {
    let line = stake_advice();
    assert!(
        !line.contains("only key"),
        "an owner who reads `the only key` and has no artefact writes the balance off: {line}"
    );
}

/// The second false half, and the one that is false inside this very file: the shipped ABI exposes
/// `_stakes` with zero inputs, and `read_gate` decodes the whole map before reporting its length.
#[test]
fn the_stake_advice_does_not_claim_the_record_cannot_be_read() {
    let line = stake_advice();
    assert!(
        !line.contains("no getter"),
        "this module decodes `_stakes` to count it, so `no getter` is contradicted by its own \
         caller: {line}"
    );
}

/// What the note already carries. Both are fields of `StakeInfo`, so an owner told these two are in
/// hand knows they are looking for one value and not three.
#[test]
fn the_stake_advice_names_the_two_thirds_the_record_already_carries() {
    let line = stake_advice();
    assert!(line.contains("oracleListHash"), "{line}");
    assert!(line.contains("tokenType"), "{line}");
}

/// And the one thing that is genuinely external. Naming it as a NAME is the whole difference between
/// a recoverable situation and a 256-bit search: an owner can remember or look up an oracle name.
#[test]
fn the_stake_advice_names_the_one_input_the_owner_must_supply() {
    let line = stake_advice();
    assert!(
        line.contains("NAME"),
        "the advice must say the remaining input is a name, not a hash: {line}"
    );
}

/// Kept from regressing while the wording changes: the command itself is still named, and the line
/// still carries the code the chain returned, so this remains actionable rather than merely honest.
#[test]
fn the_stake_advice_still_names_the_command_and_the_code() {
    let line = stake_advice();
    assert!(line.contains("cancel-stake"), "{line}");
    assert!(line.contains("121"), "{line}");
}
