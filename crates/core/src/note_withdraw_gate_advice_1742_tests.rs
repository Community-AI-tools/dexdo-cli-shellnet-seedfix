//! the advice for a WITHDRAWN note must not answer for the contract out of an inventory of
//! our own commands.

//! The line that stood here read "the note is spent; no command re-opens it and nothing further can
//! be withdrawn". The first two clauses are about this client and are true. The third is about the
//! CONTRACT and is false: `PrivateNote.sweepShell` requires `_hasWithdrawn` and moves the note's
//! physical ECC[2], so SHELL that lands after the withdrawal is out of reach from here rather than
//! gone. An owner who reads a verdict writes the balance off -- the same failure fixed one
//! entry down in this very enum. The doc comment above the match had already reasoned about this
//! exact class ("saying `retry` there would be the same lie in the other direction") and fell into
//! it anyway, because it looked at the client and wrote about the note.

//! # Why these are not a check for words

//! A test that asserts a phrase is absent is green tomorrow on any other false claim, so the
//! expected content here is COMPUTED FROM THE CONTRACT -- the idiom `params.rs` already uses for
//! this, where "the oracle is the vendored contract source, which knows nothing about our
//! constant". The vendored `PrivateNote.sol` names every owner-gated method that requires
//! `_hasWithdrawn == true`, and the advice has to name each one. Drop `sweepShell` from the
//! contract and these go red; add a second such method and they go red until the advice says so;
//! restore the old wording and they go red because it names none. None of that depends on which
//! words the advice chooses.

use super::WithdrawGate;

/// The vendored contract source, the same oracle `params.rs` derives its gas expectations from.
const PRIVATE_NOTE_SOL: &str = include_str!("../../../contracts/dex/PrivateNote.sol");

/// What a deployed note actually exposes, which is a different question from what the source says.
const PRIVATE_NOTE_ABI: &str = include_str!("../../../contracts/compiled/dex/PrivateNote.abi.json");

/// The methods that refuse a spent note, used as the must-MISS input below. Each carries the
/// NEGATED form of the same field, which is the only thing separating them from the set collected
/// here.
const REFUSE_A_SPENT_NOTE: [&str; 4] = [
    "withdrawTokens",
    "initTransfer",
    "setStake",
    "postSellOffer",
];

/// Every owner-gated method whose body requires `_hasWithdrawn == TRUE` -- that is, every method
/// the contract still offers a note that has already withdrawn.

/// The POSITIVE form only. A dozen methods carry `require(!_hasWithdrawn,...)`, and a scan for the
/// bare field name would collect all of them and report that a spent note has a dozen doors. The
/// `!` is the whole distinction, which is why the anchor carries it.

/// Attribution walks BACKWARD to the nearest member header, because a `require` inside a body
/// always has its own function's header as the closest one above it. A forward scan for the closing
/// brace would not: `withdrawTokens` closes on a tab rather than four spaces, so a forward reader
/// runs one function long and credits the next method with this one's requires.
fn methods_the_contract_offers_a_withdrawn_note() -> Vec<&'static str> {
    const ANCHOR: &str = "require(_hasWithdrawn,";
    const HEADER: &str = "\n    function ";

    let mut found: Vec<&'static str> = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = PRIVATE_NOTE_SOL[from..].find(ANCHOR) {
        let at = from + rel;
        from = at + ANCHOR.len();

        let head = PRIVATE_NOTE_SOL[..at]
            .rfind(HEADER)
            .expect("a require sits below some function header");
        let after = &PRIVATE_NOTE_SOL[head + HEADER.len()..];
        let signature = &after[..after.find('{').expect("a function header opens a body")];
        let name = signature
            .split('(')
            .next()
            .expect("a function header names its function")
            .trim();

        assert!(
            signature.contains("onlyOwnerPubkey"),
            "`{name}` requires `_hasWithdrawn` but its header is not owner-gated -- this scan \
             credits a require to the nearest `function` above it, so a require inside a member \
             that is not one (`onBounce`, `receive`) would land on the wrong name"
        );
        if !found.contains(&name) {
            found.push(name);
        }
    }
    found
}

/// The scan can find anything at all, and what it finds is the method this issue is about.

/// Asserted first and separately: every claim below is built on this set, and a scan that quietly
/// stopped matching would make all of them vacuously green -- an emptiness that reads exactly like
/// a pass.
#[test]
fn the_contract_still_offers_a_withdrawn_note_a_method_of_its_own() {
    let offered = methods_the_contract_offers_a_withdrawn_note();
    assert!(
        !offered.is_empty(),
        "no owner-gated method in the vendored PrivateNote requires `_hasWithdrawn`; if that is \
         genuinely so, the advice must stop naming one -- but far more likely this scan stopped \
         matching and every assertion resting on it is now green for no reason"
    );
    assert!(
        offered.contains(&"sweepShell"),
        "`sweepShell` is the contract's door for a spent note and the scan no longer sees it: \
         {offered:?}"
    );
}

/// The must-MISS half, run on inputs that must not match.

/// `withdrawTokens` names the same field under a negation. A scan that collected it would report
/// that a spent note can withdraw again -- the opposite error, and one that would keep this file
/// green while the advice lied in the other direction.
#[test]
fn the_scan_does_not_collect_the_methods_that_refuse_a_spent_note() {
    let offered = methods_the_contract_offers_a_withdrawn_note();
    for refused in REFUSE_A_SPENT_NOTE {
        assert!(
            PRIVATE_NOTE_SOL.contains(&format!("function {refused}(")),
            "`{refused}` is no longer in the vendored contract, so feeding it to the scan proves \
             nothing about what the scan rejects"
        );
        assert!(
            !offered.contains(&refused),
            "`{refused}` carries `require(!_hasWithdrawn, ...)` and refuses a spent note, yet the \
             scan collected it: {offered:?}"
        );
    }
}

/// The class property. Whatever the contract still offers a withdrawn note, the advice names it.

/// This is what the old wording failed, and it fails it for the reason that generalises: it named
/// nothing, so it could not have named this. A future advice that invents some other false verdict
/// fails here too, without anyone having to guess its words in advance.
#[test]
fn the_withdrawn_advice_names_every_method_the_contract_still_offers() {
    let step = WithdrawGate::HasWithdrawn.next_step();
    for method in methods_the_contract_offers_a_withdrawn_note() {
        assert!(
            step.contains(method),
            "the contract offers a withdrawn note `{method}` and the advice does not name it, so \
             the owner is told less than the chain will do for them: {step}"
        );
    }
}

/// The other direction, because either alone passes on the opposite mistake: an advice that
/// promises a method the DEPLOYED note does not expose sends the owner at a door that is not there.

/// A different oracle on purpose. The source says what the advice must name; the compiled ABI says
/// whether a note actually carries it, and a generation that drops the method moves one and not the
/// other.
#[test]
fn every_method_the_advice_promises_is_carried_by_the_shipped_abi() {
    let abi: serde_json::Value =
        serde_json::from_str(PRIVATE_NOTE_ABI).expect("the compiled PrivateNote ABI parses");
    let exposed: Vec<&str> = abi["functions"]
        .as_array()
        .expect("the compiled ABI lists functions")
        .iter()
        .filter_map(|function| function["name"].as_str())
        .collect();
    assert!(
        exposed.len() > 1,
        "the compiled ABI exposed {} functions, so this comparison has nothing to refuse",
        exposed.len()
    );
    for method in methods_the_contract_offers_a_withdrawn_note() {
        assert!(
            exposed.contains(&method),
            "the advice is told to name `{method}` by the source, but the shipped ABI does not \
             carry it -- a deployed note would answer that call with nothing"
        );
    }
}

/// PART TWO retires this arm's status as the exception, and this test records the handover.

/// Part one redirected a whitelist marker in `note_withdraw_gate_1515_tests.rs` to
/// `"this client has no command"`, because this arm was then the one gate that named none. Part two
/// built `dexdo note sweep`, so the arm names a command like every other commanded gate and is
/// admitted by the `"dexdo "` marker on its own merits.

/// The arm must now NAME the command, or the advice has gone back to reporting a gap that is
/// closed -- the same substitution as the original defect, running the other way.

/// The redirected marker was REMOVED from that whitelist in this change, on the lead's decision:
/// once the arm names a command it is admitted by the general `"dexdo "` marker like every other
/// commanded gate, so the special entry matched nothing. A guard written for a gap dies the day the
/// gap is closed, and it does not go red when it dies -- it just stops meaning anything. The test
/// that made its deadness visible went with it, being an instance of the same thing.
#[test]
fn the_withdrawn_arm_names_the_command_that_closed_its_gap() {
    let step = WithdrawGate::HasWithdrawn.next_step();
    assert!(
        step.contains("dexdo note sweep"),
        "part two shipped the command; an arm that does not name it tells the owner a gap is open \
         that is closed: {step}"
    );
    // The contract method stays named beside the command. The command is what the operator runs;
    // the method is what they can go and read, and exists because the two were confused.
    assert!(step.contains("sweepShell"), "{step}");
}
