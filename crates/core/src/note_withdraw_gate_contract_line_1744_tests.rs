//! the contract line each gate points at is DERIVED from the vendored contract, not typed.

//! `contract_line()` shipped eleven numbers and all eleven were wrong -- every one short by exactly
//! 181, because `PrivateNote.sol` grew that much above `withdrawTokens` and nothing was watching.
//! A uniform drift is the tell: the table was right when it was written and rotted as one, so no
//! amount of care over the individual values would have caught it.

//! What the operator got was worse than a missing pointer. `_liveDeals` said `PrivateNote.sol:2502`
//! and line 2502 is a doc comment about `eccAmount` on a different function -- prose that reads
//! like an answer, so a reader who follows it does not learn that they were misdirected.

//! # Why the old guard did not see it

//! `the_line_points_at_the_require_in_the_contract` asserted the rendered string contains
//! `PrivateNote.sol:2502`, which is the same number the table returns. It checked that the renderer
//! CARRIES the number, never that the number is RIGHT -- so it was green against the table's own
//! value, and would have stayed green for any drift at all. Worth keeping as a plumbing check; it
//! was simply never the correctness check its name suggests.

//! # The rule, and why it is one rule for eleven gates

//! Each gate names a storage field (`WITHDRAW_GATE_FIELDS`, in contract order). Inside
//! `withdrawTokens`, find the first line that mentions that field as a whole token, then the first
//! `require(` at or after it. For ten gates the mention IS the require. The eleventh,
//! `_lockedInOrders`, is required inside a loop over itself -- `require(locked == 0,...)`, which
//! does not name the field at all -- and the same rule reaches it by walking forward from the
//! `for`. One rule, no special case, and the contract is the only source of the answer.

use super::{WithdrawGate, WITHDRAW_GATE_FIELDS};

/// The vendored contract, the same oracle `params.rs` and the advice tests read.
const PRIVATE_NOTE_SOL: &str = include_str!("../../../contracts/dex/PrivateNote.sol");

/// The member whose `require`s these gates are, spelled as the contract opens it.
const WITHDRAW_TOKENS: &str = "    function withdrawTokens(";

/// The eleven gates in the order `withdrawTokens` evaluates them, which is the order
/// [`WITHDRAW_GATE_FIELDS`] is written in.
fn gates_in_contract_order() -> [WithdrawGate; 11] {
    [
        WithdrawGate::HasWithdrawn,
        WithdrawGate::Busy {
            with: "0:1".to_string(),
        },
        WithdrawGate::Stakes { count: 1 },
        WithdrawGate::Debt { raw: 1 },
        WithdrawGate::LockedInOrders {
            token_type: 2,
            locked: 1,
        },
        WithdrawGate::PendingPlaceBuyLock { raw: 1 },
        WithdrawGate::PendingBatchBuyLock { raw: 1 },
        WithdrawGate::OpenOrders { count: 1 },
        WithdrawGate::RestingInference { count: 1 },
        WithdrawGate::PendingInference { count: 1 },
        WithdrawGate::LiveDeals { count: 1 },
    ]
}

/// Does `line` mention `field` as a whole identifier?

/// A plain substring test would read `_busyOpNonce` as `_busy` and point the busy gate at whatever
/// line clears the nonce. The character after the name is the whole distinction, so it is checked,
/// and `the_token_rule_refuses_a_longer_identifier` feeds this the inputs that must not match.
fn mentions_field(line: &str, field: &str) -> bool {
    let mut from = 0usize;
    while let Some(rel) = line[from..].find(field) {
        let at = from + rel;
        let after = line[at + field.len()..].chars().next();
        if !after.is_some_and(|c| c.is_alphanumeric() || c == '_') {
            return true;
        }
        from = at + field.len();
    }
    false
}

/// The 1-based line of `withdrawTokens`'s `require` for `field`, read out of the vendored contract.
fn derived_contract_line(field: &str) -> u32 {
    let lines: Vec<&str> = PRIVATE_NOTE_SOL.split('\n').collect();
    let start = lines
        .iter()
        .position(|line| line.starts_with(WITHDRAW_TOKENS))
        .expect("the vendored contract still declares `withdrawTokens`");
    // Bounded by the next member, so a field named again further down the contract cannot answer
    // for this function. `withdrawTokens` closes on a TAB rather than four spaces, which is exactly
    // why the bound is the next `function` and not the next closing brace.
    let end = lines
        .iter()
        .skip(start + 1)
        .position(|line| line.starts_with("    function "))
        .map(|offset| start + 1 + offset)
        .expect("some member follows `withdrawTokens`");

    let mention = (start..end)
        .find(|&i| mentions_field(lines[i], field))
        .unwrap_or_else(|| panic!("`withdrawTokens` no longer mentions `{field}`"));
    let require = (mention..end)
        .find(|&i| lines[i].contains("require("))
        .unwrap_or_else(|| panic!("no `require(` at or after the `{field}` mention"));
    u32::try_from(require + 1).expect("a contract line number fits in u32")
}

/// The class property: every gate points at the line the contract actually writes it on.

/// The expected value is computed from the vendored source, so this is not eleven numbers checked
/// against eleven numbers. Move the contract and it goes red naming the gate, the number shipped
/// and the number found.
#[test]
fn every_gate_points_at_its_own_require_in_the_vendored_contract() {
    for (gate, field) in gates_in_contract_order().iter().zip(WITHDRAW_GATE_FIELDS) {
        assert_eq!(
            gate.field(),
            field,
            "the gate order here has drifted from WITHDRAW_GATE_FIELDS"
        );
        let derived = derived_contract_line(field);
        assert_eq!(
            gate.contract_line(),
            derived,
            "`{field}` is written on PrivateNote.sol:{derived}, but this gate sends the operator to \
             :{}. A pointer that is merely near is worse than none -- the line it names is real \
             code, so nothing about following it says it was wrong",
            gate.contract_line()
        );
    }
}

/// Anti-vacuity, and it is not the same claim as the test above.

/// The derivation could in principle answer with one line for every field and still satisfy an
/// equality check, if the table were equally collapsed. The gates are evaluated in order and the
/// contract writes them in order, so the derived lines must be STRICTLY increasing; that is a fact
/// about the contract no agreement between two tables can fake.
#[test]
fn the_derived_lines_are_strictly_increasing_as_the_contract_evaluates_them() {
    let derived: Vec<u32> = WITHDRAW_GATE_FIELDS
        .iter()
        .map(|field| derived_contract_line(field))
        .collect();
    assert_eq!(derived.len(), 11, "{derived:?}");
    for (index, pair) in derived.windows(2).enumerate() {
        assert!(
            pair[1] > pair[0],
            "{} is derived at :{} and {} at :{}, so the two are out of contract order: {derived:?}",
            WITHDRAW_GATE_FIELDS[index],
            pair[0],
            WITHDRAW_GATE_FIELDS[index + 1],
            pair[1]
        );
    }
}

/// The must-MISS half of the token rule, on inputs that must not match.

/// `_busy` inside `_busyOpNonce` is the live example: `withdrawTokens` does not clear that nonce,
/// but the same file does, and a substring rule pointed at the wrong line would still be a number
/// that looks right. A rule only ever seen matching is untested in the direction that matters.
#[test]
fn the_token_rule_refuses_a_longer_identifier() {
    for (line, field) in [
        ("        _busyOpNonce = 0;", "_busy"),
        ("        _pendingInfo = 1;", "_pendingInf"),
        ("        _stakesByOwner.clear();", "_stakes"),
        ("        _debtTokenType = 0;", "_debt"),
    ] {
        assert!(
            !mentions_field(line, field),
            "`{field}` matched a longer identifier in {line:?}"
        );
    }
    // And the same rule must still find the real thing, or the refusals above prove nothing.
    for (line, field) in [
        (
            "        require(!_busy.hasValue(), ERR_NOTE_BUSY);",
            "_busy",
        ),
        ("        require(_debt == 0, ERR_DEBT_NON_ZERO);", "_debt"),
        (
            "        for ((uint32 tt, uint128 locked) : _lockedInOrders) {",
            "_lockedInOrders",
        ),
    ] {
        assert!(
            mentions_field(line, field),
            "`{field}` was not found in {line:?}"
        );
    }
}

/// The line the operator is sent to is a `require`, not merely a line number that exists.

/// Checked against the contract text rather than the table, so it also states what kind of place
/// the pointer is expected to land: the eleventh gate lands on `require(locked == 0,...)`, which
/// names no field, and that is the one the uniform rule had to reach by walking.
#[test]
fn every_derived_line_is_a_require_the_reader_can_read() {
    let lines: Vec<&str> = PRIVATE_NOTE_SOL.split('\n').collect();
    for field in WITHDRAW_GATE_FIELDS {
        let derived = derived_contract_line(field);
        let text = lines[derived as usize - 1];
        assert!(
            text.contains("require("),
            "`{field}` points at PrivateNote.sol:{derived}, which is not a require: {text:?}"
        );
    }
}
