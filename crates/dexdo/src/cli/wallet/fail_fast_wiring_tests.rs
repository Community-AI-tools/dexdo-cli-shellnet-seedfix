//! what `note deploy` and `note topup` do about the wallet, before they touch the chain.
//! The resolver takes the store rather than reading the process-wide data directory, so every case
//! below is decided by a directory this test created -- never by whatever the machine running the
//! suite happens to have bound.

use super::{
    resolve_funding_wallet, FundingWallet, WalletBinding, WalletNetwork, WalletProvider,
    WalletStore, BINDING_VERSION,
};
use crate::Cli;
use clap::Parser as _;
use std::path::PathBuf;

const HOT: &str = "dd::11";
const BOUND_KEY: &str = "/secrets/bound-hot.key";

fn bound(store: &WalletStore, mutate: impl FnOnce(&mut WalletBinding)) {
    let mut binding = WalletBinding {
        version: BINDING_VERSION,
        id: "0123456789abcdef0123456789abcdef".to_string(),
        provider: WalletProvider::Manual,
        network: WalletNetwork::Shellnet,
        hot_address: HOT.to_string(),
        vault_address: None,
        hot_key_file: Some(PathBuf::from(BOUND_KEY)),
        vault_key_file: None,
        hot_seed_file: None,
        push_profile_address: None,
    };
    mutate(&mut binding);
    // The secrets directory the id names. A real binding always has one -- `open_draft` creates it
    // before any key exists -- and since the reader refuses a record whose id names nothing,
    // so a fixture without it stands for state no onboarding can produce.
    std::fs::create_dir_all(store.bindings_dir().join(&binding.id))
        .expect("create the binding's secrets directory");
    store.commit_active(&binding).expect("commit the binding");
}

fn is_wallet_not_configured(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<dexdo_core::DexdoError>()
            .is_some_and(|dexdo| {
                dexdo.code() == dexdo_core::error_codes::E_WALLET_NOT_CONFIGURED.code()
            })
    })
}

/// The fail-fast itself. No wallet was passed and none is bound, so there is nothing to spend from
/// and the command must say so with the stable code rather than as a missing argument.
#[test]
fn no_flags_and_no_binding_is_e_wallet_not_configured() {
    let dir = tempfile::tempdir().unwrap();
    let store = WalletStore::at(dir.path().join("wallet"));
    let error = resolve_funding_wallet(&store, WalletNetwork::Shellnet, None, &None, &None)
        .expect_err("a command that spends the Hot cannot proceed without one");
    assert!(
        is_wallet_not_configured(&error),
        "the refusal must carry E_WALLET_NOT_CONFIGURED: {error:#}"
    );
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("dexdo wallet onboard"),
        "the refusal must name the setup command, not just the problem: {rendered}"
    );
}

/// Without flags, the bound Hot and its recorded secret file are what the command spends from.
#[test]
fn without_flags_the_active_binding_supplies_the_wallet() {
    let dir = tempfile::tempdir().unwrap();
    let store = WalletStore::at(dir.path().join("wallet"));
    bound(&store, |_| {});
    let resolved = resolve_funding_wallet(&store, WalletNetwork::Shellnet, None, &None, &None).expect("the binding answers");
    assert_eq!(
        resolved,
        FundingWallet {
            address: HOT.to_string(),
            key: Some(PathBuf::from(BOUND_KEY)),
            seed_file: None,
        }
    );
}

/// The case the re-pointed parse test cannot cover, and the one that keeps every existing script
/// working: a passed-in wallet WINS. Binding a wallet must never silently move where an explicit
/// command spends from.
#[test]
fn an_explicit_multisig_address_wins_over_the_active_binding() {
    let dir = tempfile::tempdir().unwrap();
    let store = WalletStore::at(dir.path().join("wallet"));
    bound(&store, |_| {});
    let resolved = resolve_funding_wallet(
        &store,
        WalletNetwork::Shellnet,
        Some("0:explicit"),
        &Some(PathBuf::from("explicit.key")),
        &None,
    )
    .expect("an explicit wallet needs no binding");
    assert_eq!(
        resolved,
        FundingWallet {
            address: "0:explicit".to_string(),
            key: Some(PathBuf::from("explicit.key")),
            seed_file: None,
        },
        "neither the bound address nor the bound key file may leak into an explicit run"
    );
    assert_ne!(resolved.address, HOT);
    assert_ne!(resolved.key, Some(PathBuf::from(BOUND_KEY)));
}

/// An explicit wallet must not even READ the binding, so a corrupt one cannot break a run that
/// never needed it.
#[test]
fn an_explicit_wallet_is_unaffected_by_an_unreadable_binding() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wallet");
    let store = WalletStore::at(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("binding.json"), b"{ this is not json").unwrap();
    let resolved = resolve_funding_wallet(
        &store,
        WalletNetwork::Shellnet,
        Some("0:explicit"),
        &Some(PathBuf::from("explicit.key")),
        &None,
    )
    .expect("an explicit wallet does not consult the binding at all");
    assert_eq!(resolved.address, "0:explicit");
}

/// A binding that exists but cannot be read is NOT "no wallet". Reporting it as the fail-fast would
/// send the operator into onboarding while a real Hot, possibly holding funds, is already bound --
/// and `wallet onboard` refuses when a binding exists, so they would be stuck between two refusals.
#[test]
fn an_unparseable_binding_is_an_error_and_not_a_silent_no_wallet() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wallet");
    let store = WalletStore::at(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("binding.json"), b"{ this is not json").unwrap();

    let error = resolve_funding_wallet(&store, WalletNetwork::Shellnet, None, &None, &None)
        .expect_err("a binding that cannot be read must not be treated as absent");
    assert!(
        !is_wallet_not_configured(&error),
        "an unreadable binding is a different problem from an absent one: {error:#}"
    );
    assert!(
        format!("{error:#}").contains("parse wallet binding"),
        "the error must say the binding could not be read: {error:#}"
    );
}

/// The same rule for a binding from a version this build does not read: refused, not ignored.
#[test]
fn a_future_version_binding_is_refused_rather_than_treated_as_absent() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wallet");
    let store = WalletStore::at(&root);
    bound(&store, |_| {});
    let path = store.binding_path(WalletNetwork::Shellnet);
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["version"] = serde_json::json!(BINDING_VERSION + 1);
    std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    let error = resolve_funding_wallet(&store, WalletNetwork::Shellnet, None, &None, &None)
        .expect_err("a newer binding must not be read with fields this build ignores");
    assert!(!is_wallet_not_configured(&error), "{error:#}");
}

/// A binding with no local secret cannot sign. That is its own refusal: the operator's next move is
/// to re-bind or pass a key for this run, not to onboard from scratch.
#[test]
fn a_binding_with_no_local_secret_is_refused_as_itself() {
    let dir = tempfile::tempdir().unwrap();
    let store = WalletStore::at(dir.path().join("wallet"));
    bound(&store, |binding| {
        binding.hot_key_file = None;
        binding.hot_seed_file = None;
    });
    let error = resolve_funding_wallet(&store, WalletNetwork::Shellnet, None, &None, &None)
        .expect_err("a binding with no secret cannot fund a spend");
    assert!(!is_wallet_not_configured(&error), "{error:#}");
    assert!(
        format!("{error:#}").contains("cannot sign a spend"),
        "{error:#}"
    );
}

/// A seed-file binding resolves to the seed input, not the key input.
#[test]
fn a_seed_file_binding_resolves_to_the_seed_input() {
    let dir = tempfile::tempdir().unwrap();
    let store = WalletStore::at(dir.path().join("wallet"));
    bound(&store, |binding| {
        binding.hot_key_file = None;
        binding.hot_seed_file = Some(PathBuf::from("/secrets/hot.seed"));
    });
    let resolved = resolve_funding_wallet(&store, WalletNetwork::Shellnet, None, &None, &None).unwrap();
    assert_eq!(resolved.key, None);
    assert_eq!(resolved.seed_file, Some(PathBuf::from("/secrets/hot.seed")));
}

/// The parser half of the same change: omitting the wallet is now a RUN-TIME question for the
/// binding to answer, so it has to reach the command instead of being rejected by clap. The pairing
/// rules that were there before are unchanged, which is why the existing parse test keeps all four
/// of its rejections.
#[test]
fn omitting_the_wallet_parses_while_every_previous_pairing_rule_still_rejects() {
    for command in [
        vec![
            "dexdo", "note", "deploy", "--nominal", "N100", "--pool", "p.json",
        ],
        vec![
            "dexdo", "note", "topup", "--note-addr", "0:note", "--to-raw", "1",
        ],
    ] {
        Cli::try_parse_from(command.clone())
            .unwrap_or_else(|error| panic!("{command:?} must reach the binding: {error}"));
    }
    for command in [
        // A key with no wallet to spend from names no wallet at all.
        vec![
            "dexdo",
            "note",
            "deploy",
            "--multisig-key",
            "w.keys.json",
            "--nominal",
            "N100",
            "--pool",
            "p.json",
        ],
        // A wallet with no key cannot sign.
        vec![
            "dexdo",
            "note",
            "deploy",
            "--multisig-address",
            "0:wallet",
            "--nominal",
            "N100",
            "--pool",
            "p.json",
        ],
        vec![
            "dexdo",
            "note",
            "topup",
            "--note-addr",
            "0:note",
            "--to-raw",
            "1",
            "--multisig-key",
            "w.keys.json",
        ],
        vec![
            "dexdo",
            "note",
            "topup",
            "--note-addr",
            "0:note",
            "--to-raw",
            "1",
            "--multisig-address",
            "0:wallet",
        ],
    ] {
        assert!(
            Cli::try_parse_from(command.clone()).is_err(),
            "{command:?} must still be rejected by the parser"
        );
    }
}
