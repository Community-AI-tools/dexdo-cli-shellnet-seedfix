//! (1 of 3): the seller's note-identity fail-closed guard, driven through its normaliser.

//! `assert_market_seller_note` answers a MONEY question -- is the note this seller is about to post
//! an offer from the note the market was provisioned for? -- and it answers it with
//! `normalize_wallet_address(s).unwrap_or_else(|_| s.trim().to_string())`. The normaliser is
//! `CanonicalAddress::parse`, which exists so that ONE note written in two spellings compares EQUAL.

//! Nothing reached it. The one existing test feeds 4- and 6-hex values, which `parse` refuses, so
//! both of its assertions run through the `unwrap_or_else` fallback and compare raw strings. Measured
//! under: with `normalize_wallet_address` deleted from that closure,
//! `cargo test --workspace --locked` stayed at 1902 passed / 0 failed.

//! These fixtures are real 64-hex accounts, so `parse` succeeds and the normaliser is what decides.
//! Every assertion is made on whitespace-delimited TOKENS rather than on substrings, because the
//! refusal is prose that a later edit may re-wrap, and a substring check silently follows the wrap.

use super::assert_market_seller_note;

/// A real account id: exactly 64 hex, the length `is_hex64` requires. Both constants are checked for
/// length by `the_fixtures_are_addresses_the_parser_accepts` below rather than by eye -- a hand-typed
/// 65th character is exactly the error a negative control caught in this file's own survey.
const ACCOUNT: &str = "3f0a9c5d81e2b47600fd1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f";
/// A DIFFERENT account, for the direction the guard must REFUSE.
const OTHER: &str = "c1d2e3f405162738495a6b7c8d9e0f10213243546576879809aabbccddeeff01";

fn legacy(account: &str) -> String {
    format!("0:{account}")
}

fn canonical(account: &str) -> String {
    format!("{}::{account}", dexdo_core::DEXDO_DAPP_ID)
}

/// The canonical form the refusal renders an address in: `dexdo_core::address::display`.
fn rendered(account: &str) -> String {
    format!("{}::{account}", dexdo_core::DEXDO_DAPP_ID)
}

/// Whitespace-delimited tokens, with trailing sentence punctuation removed.

/// The refusal writes one address immediately before a `:` and its issue reference inside
/// parentheses, so raw tokens carry that punctuation -- the first run of this file failed on exactly
/// that, `).` against ``, which is the check doing its job. Trimming punctuation keeps this
/// on a TOKEN -- a whole whitespace-delimited word -- instead of letting it degrade into a substring
/// search that would also match a longer address ending in these characters.
fn tokens(message: &str) -> Vec<&str> {
    message
        .split_whitespace()
        .map(|token| token.trim_matches([':', ',', '.', ';', '(', ')']))
        .collect()
}

/// The guard on the guard. If either fixture stopped being a parseable address, every test below
/// would still pass -- through the fallback -- and prove nothing, which is the exact defect
/// records. So the premise is asserted, not assumed.
#[test]
fn the_fixtures_are_addresses_the_parser_accepts() {
    for account in [ACCOUNT, OTHER] {
        assert_eq!(account.len(), 64, "an account id is 64 hex: {account}");
        assert!(
            dexdo_core::CanonicalAddress::parse(&legacy(account)).is_ok(),
            "the fixture must be an address the normaliser accepts: {account}"
        );
    }
    assert_ne!(ACCOUNT, OTHER, "the refusal direction needs two accounts");
    // And the two spellings really are different strings, so admitting both is a statement about
    // the normaliser rather than about string equality.
    assert_ne!(legacy(ACCOUNT), canonical(ACCOUNT));
}

/// One note, either spelling on either side, is the same note. This is what the normaliser is for,
/// and it is the half that a raw string comparison gets wrong.
#[test]
fn one_note_in_two_spellings_is_the_same_note() {
    for (manifest, note) in [
        (legacy(ACCOUNT), legacy(ACCOUNT)),
        (legacy(ACCOUNT), canonical(ACCOUNT)),
        (canonical(ACCOUNT), legacy(ACCOUNT)),
        (canonical(ACCOUNT), canonical(ACCOUNT)),
    ] {
        assert_market_seller_note(&manifest, &note).unwrap_or_else(|error| {
            panic!("manifest {manifest} and --note-addr {note} name one account: {error}")
        });
    }
}

/// The direction that must REFUSE -- the negative control, and the reason the guard exists. Two
/// different accounts are two different notes in every combination of spellings.
#[test]
fn two_different_notes_are_refused_in_every_spelling() {
    for (manifest, note) in [
        (legacy(ACCOUNT), legacy(OTHER)),
        (legacy(ACCOUNT), canonical(OTHER)),
        (canonical(ACCOUNT), legacy(OTHER)),
        (canonical(ACCOUNT), canonical(OTHER)),
    ] {
        assert_market_seller_note(&manifest, &note).expect_err(&format!(
            "manifest {manifest} and --note-addr {note} are different accounts and must fail closed"
        ));
    }
}

/// The refusal names BOTH accounts, canonically, as tokens -- and names only those two.
#[test]
fn the_refusal_names_both_accounts_as_tokens_and_no_third() {
    let error = assert_market_seller_note(&legacy(ACCOUNT), &canonical(OTHER))
        .expect_err("different accounts fail closed")
        .to_string();
    let tokens = tokens(&error);

    for expected in [rendered(ACCOUNT), rendered(OTHER)] {
        assert!(
            tokens.contains(&expected.as_str()),
            "the refusal does not name {expected} as a token: {error}"
        );
    }
    // Negative control on the token check itself: an account that is not part of this decision must
    // not be found. Without this the assertion above is untested in the direction that matters -- a
    // check that has only ever succeeded has not been shown able to miss.
    let absent = rendered(&"9".repeat(64));
    assert!(
        !tokens.contains(&absent.as_str()),
        "the token check matches an address that is not in the refusal: {error}"
    );
    // And the guard cites the issue that pays for it, as a token rather than a substring.
    assert!(tokens.contains(&""), "{error}");
}
