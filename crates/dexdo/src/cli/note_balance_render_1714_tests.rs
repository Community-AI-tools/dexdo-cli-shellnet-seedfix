//! (2 of 3): the note-balance header renders its address canonically.

//! `render_note_balance` writes `PrivateNote {}` through `dexdo_core::address::display`, which
//! REWRITES a real `0:<64 hex>` into `<dapp_id>::<account_id>` and passes a non-address through
//! untouched. The existing test asserts `PrivateNote 0:abc` -- a line production cannot produce for
//! any real note, and one that is satisfied whether the renderer canonicalises or not.

//! Measured under: with `address::display` removed from that line,
//! `cargo test --workspace --locked` stayed at 1902 passed / 0 failed.

//! Assertions are on whitespace-delimited TOKENS. A substring check for the account id alone would
//! pass on `0:<account>` and on `<dapp>::<account>` equally, which is the distinction under test.

use super::{
    build_note_balance_view, render_note_balance, NoteAccountSnapshot, NoteBalanceMap,
    NoteGetterBalanceMaps,
};

const ACCOUNT: &str = "3f0a9c5d81e2b47600fd1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f";

fn legacy() -> String {
    format!("0:{ACCOUNT}")
}

/// What `dexdo_core::address::display` yields for a shared-DApp account: the legacy form carries no
/// DApp, so `CanonicalAddress::parse` fills in `DEXDO_DAPP_ID`.
fn canonical() -> String {
    format!("{}::{ACCOUNT}", dexdo_core::DEXDO_DAPP_ID)
}

fn tokens(rendered: &str) -> Vec<&str> {
    rendered.split_whitespace().collect()
}

fn view_for(address: &str) -> String {
    let view = build_note_balance_view(
        address,
        Some(NoteAccountSnapshot {
            address: address.to_string(),
            status: "Active".into(),
            native_raw: 5_000_000_123,
            ecc: vec![(2, 1_234_567_890)],
            code_hash: Some("cafe".into()),
        }),
        NoteGetterBalanceMaps {
            balance: NoteBalanceMap::Known(vec![(2, 2_000_000_001)]),
            locked_in_orders: NoteBalanceMap::Unknown("getter unavailable".into()),
        },
    )
    .expect("a present account builds a view");
    render_note_balance(&view)
}

/// The premise: this fixture is an address the renderer would actually rewrite. Without it every
/// assertion below would hold on a value that passes through untouched -- the defect records.
#[test]
fn the_fixture_is_an_address_the_renderer_rewrites() {
    assert_eq!(ACCOUNT.len(), 64);
    assert_eq!(
        dexdo_core::address::display(&legacy()),
        canonical(),
        "the renderer must change this fixture, or the test proves nothing"
    );
    assert_ne!(legacy(), canonical());
}

/// The header names the note in the canonical form, as a token.
#[test]
fn the_header_names_the_note_canonically_as_a_token() {
    let out = view_for(&legacy());
    let tokens = tokens(&out);

    assert!(
        tokens.contains(&canonical().as_str()),
        "the header does not carry the canonical address as a token: {out}"
    );
    // The negative control, and the whole point: the spelling the caller HANDED IN must not be what
    // is printed. A substring check for the bare account id would pass on both and see nothing.
    assert!(
        !tokens.contains(&legacy().as_str()),
        "the header printed the legacy spelling the renderer is supposed to rewrite: {out}"
    );
    // And the label is still the label, so this cannot pass by printing nothing.
    assert!(tokens.contains(&"PrivateNote"), "{out}");
}

/// An address handed in ALREADY canonical survives unchanged -- the renderer normalises, it does not
/// re-wrap what is already normal. Both directions, so a renderer that simply always prepended a
/// DApp id would fail this one.
#[test]
fn an_already_canonical_address_is_not_rewritten_again() {
    let out = view_for(&canonical());
    let tokens = tokens(&out);
    assert!(tokens.contains(&canonical().as_str()), "{out}");
    let doubled = format!("{}::{}", dexdo_core::DEXDO_DAPP_ID, canonical());
    assert!(
        !tokens.contains(&doubled.as_str()),
        "the renderer re-wrapped an address that was already canonical: {out}"
    );
}
