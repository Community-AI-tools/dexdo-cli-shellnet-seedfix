//! audit item 3: a wallet bound on one network never funds a spend on another.
//! The shipped code kept ONE `wallet/binding.json` and `resolve_funding_wallet` was never told
//! which chain the command was running on. A Hot bound on shellnet was therefore the wallet a
//! mainnet `note deploy` or `note topup` resolved and spent from -- real money, out of a wallet the
//! operator bound for a test chain, with nothing anywhere that could notice.
//! Two independent guarantees are asserted here, because each covers what the other cannot.
//! The PATH is keyed by network, so a mainnet command does not name the shellnet record at all.
//! That is what stops the ordinary case, where nothing is corrupt and the operator simply has one
//! binding and two chains.
//! And the RECORD is checked against the network that was asked for, so a file that arrived in the
//! wrong slot -- copied, restored from a backup, hand-edited -- is refused rather than spent. That is
//! what stops the case the path alone cannot see.
//! Every case drives the real writer(`commit_active`) and the real reader
//! (`resolve_funding_wallet`), never a hand-placed end state, so what is proved is what a command
//! actually does.

use super::{
    resolve_funding_wallet, WalletBinding, WalletNetwork, WalletProvider, WalletStore,
    BINDING_VERSION,
};
use std::path::{Path, PathBuf};

const SHELLNET_HOT: &str = "4::5he11";
const MAINNET_HOT: &str = "0::4a12e7";
const SHELLNET_KEY: &str = "/secrets/shellnet-hot.key";
const MAINNET_KEY: &str = "/secrets/mainnet-hot.key";

const SHELLNET_ID: &str = "0123456789abcdef0123456789abcdef";
const MAINNET_ID: &str = "fedcba9876543210fedcba9876543210";

fn binding(id: &str, network: WalletNetwork, hot: &str, key: &str) -> WalletBinding {
    WalletBinding {
        version: BINDING_VERSION,
        id: id.to_string(),
        provider: WalletProvider::Manual,
        network,
        hot_address: hot.to_string(),
        vault_address: None,
        hot_key_file: Some(PathBuf::from(key)),
        vault_key_file: None,
        hot_seed_file: None,
        push_profile_address: None,
    }
}

fn shellnet_binding() -> WalletBinding {
    binding(
        SHELLNET_ID,
        WalletNetwork::Shellnet,
        SHELLNET_HOT,
        SHELLNET_KEY,
    )
}

fn mainnet_binding() -> WalletBinding {
    binding(MAINNET_ID, WalletNetwork::Mainnet, MAINNET_HOT, MAINNET_KEY)
}

/// The secrets directory the id names. `open_draft` creates one before any key exists and the
/// reader refuses a record whose id names nothing, so a fixture without it would stand for
/// state no onboarding can produce and would fail for the wrong reason.
fn secrets_dir_for(root: &Path, binding: &WalletBinding) {
    std::fs::create_dir_all(root.join("bindings").join(&binding.id))
        .expect("create the binding's secrets directory");
}

fn store_with(root: &Path, bindings: &[WalletBinding]) -> WalletStore {
    let store = WalletStore::at(root);
    for binding in bindings {
        secrets_dir_for(root, binding);
        store.commit_active(binding).expect("commit the binding");
    }
    store
}

/// Write a `wallet/binding.json` exactly where the shipped global-binding code kept it. The name is
/// spelled out rather than asked of the store, because the point is the file an operator already
/// has on disk today.
fn write_legacy(root: &Path, binding: &WalletBinding) -> PathBuf {
    std::fs::create_dir_all(root).expect("create the wallet root");
    secrets_dir_for(root, binding);
    let path = root.join("binding.json");
    let mut json = serde_json::to_vec_pretty(binding).expect("serialize");
    json.push(b'\n');
    std::fs::write(&path, json).expect("write the legacy binding");
    path
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

/// THE defect. A shellnet binding is the only one on this machine, and a command running on mainnet
/// asks for a wallet. It must not get the shellnet one.
/// The assertion is on the resolved VALUE and not only on the error: what made this a money-safety
/// blocker is that the shellnet Hot address and its key file were handed to a mainnet spend, so the
/// test refuses to pass if either ever appears in a mainnet answer.
#[test]
fn a_mainnet_command_refuses_the_shellnet_binding_instead_of_spending_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wallet");
    let store = store_with(&root, &[shellnet_binding()]);

    let error = resolve_funding_wallet(&store, WalletNetwork::Mainnet, None, &None, &None)
        .expect_err("a wallet bound on shellnet must never fund a mainnet spend");

    let rendered = format!("{error:#}");
    assert!(
        !rendered.contains(SHELLNET_HOT),
        "the shellnet Hot must not be offered to a mainnet command: {rendered}"
    );
    assert!(
        !rendered.contains(SHELLNET_KEY),
        "the shellnet signing key must not be offered to a mainnet command: {rendered}"
    );
    assert!(
        rendered.contains("mainnet"),
        "the refusal must name the network the command is running on: {rendered}"
    );
}

/// The mirror image, so the refusal above is not simply "mainnet never resolves".
#[test]
fn a_shellnet_command_refuses_the_mainnet_binding_instead_of_spending_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wallet");
    let store = store_with(&root, &[mainnet_binding()]);

    let error = resolve_funding_wallet(&store, WalletNetwork::Shellnet, None, &None, &None)
        .expect_err("a wallet bound on mainnet must never fund a shellnet spend");
    let rendered = format!("{error:#}");
    assert!(
        !rendered.contains(MAINNET_HOT),
        "the mainnet Hot must not be offered to a shellnet command: {rendered}"
    );
}

/// The other half of the contract: when the networks DO agree the binding answers, exactly as
/// before. A refusal that also blocked the matching case would be a different bug, not a fix.
#[test]
fn a_matching_network_resolves_the_binding_it_is_bound_to() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wallet");
    let store = store_with(&root, &[shellnet_binding()]);

    let resolved = resolve_funding_wallet(&store, WalletNetwork::Shellnet, None, &None, &None)
        .expect("a shellnet command resolves the shellnet binding");
    assert_eq!(resolved.address, SHELLNET_HOT);
    assert_eq!(resolved.key, Some(PathBuf::from(SHELLNET_KEY)));
}

/// Both networks bound at once, which is the state the per-network layout exists to allow. Each
/// command gets ITS wallet, and committing the second never replaced the first.
#[test]
fn two_networks_are_bound_side_by_side_and_each_resolves_its_own_wallet() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wallet");
    let store = store_with(&root, &[shellnet_binding(), mainnet_binding()]);

    let shellnet = resolve_funding_wallet(&store, WalletNetwork::Shellnet, None, &None, &None)
        .expect("the shellnet binding survived the mainnet commit");
    let mainnet = resolve_funding_wallet(&store, WalletNetwork::Mainnet, None, &None, &None)
        .expect("the mainnet binding resolves on mainnet");

    assert_eq!(shellnet.address, SHELLNET_HOT);
    assert_eq!(mainnet.address, MAINNET_HOT);
    assert_ne!(
        shellnet.address, mainnet.address,
        "each network must resolve its own Hot, never one shared record"
    );
    assert_eq!(
        store.binding_path(WalletNetwork::Shellnet).exists(),
        store.binding_path(WalletNetwork::Mainnet).exists(),
        "both active files must exist: binding one network must not replace the other"
    );
}

/// No binding for THIS network is the ordinary fail-fast, with the stable code -- not the other
/// network's wallet, and not a bare "wrong network" error either.
#[test]
fn a_network_with_no_binding_of_its_own_is_the_ordinary_fail_fast() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wallet");
    let store = WalletStore::at(&root);

    let error = resolve_funding_wallet(&store, WalletNetwork::Mainnet, None, &None, &None)
        .expect_err("no binding at all is still no binding");
    assert!(
        is_wallet_not_configured(&error),
        "an empty store must still raise E_WALLET_NOT_CONFIGURED: {error:#}"
    );
}

/// The record found under one network SAYS another. Only a copy, a restore or a hand edit produces
/// this, and it is exactly the state the network-keyed path cannot see by itself: the file is in
/// the right place and lies about itself.
/// It is refused rather than obeyed. Following the record's own field would mean the command spends
/// on the chain the FILE chose instead of the chain the operator pointed it at.
#[test]
fn a_record_sitting_in_the_wrong_networks_slot_is_refused_and_not_obeyed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wallet");
    let store = store_with(&root, &[shellnet_binding()]);

    // Copy the shellnet record verbatim into the mainnet slot, the way restoring a backup or
    // copying a data directory between machines would.
    std::fs::copy(
        store.binding_path(WalletNetwork::Shellnet),
        store.binding_path(WalletNetwork::Mainnet),
    )
    .expect("copy the record into the other network's slot");

    let error = resolve_funding_wallet(&store, WalletNetwork::Mainnet, None, &None, &None)
        .expect_err("a record that says shellnet must not fund a mainnet spend from a mainnet slot");
    let rendered = format!("{error:#}");
    assert!(
        !rendered.contains(SHELLNET_HOT),
        "the Hot in a mismatched record must not reach a mainnet spend: {rendered}"
    );
    assert!(
        rendered.contains("shellnet") && rendered.contains("mainnet"),
        "the refusal must name both the binding's network and the command's: {rendered}"
    );
}

/// An explicit `--multisig-address` still wins on either network and the binding is never read, so
/// no existing script changes behaviour because of any of this.
#[test]
fn an_explicit_wallet_still_wins_and_is_unaffected_by_the_network() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wallet");
    let store = store_with(&root, &[shellnet_binding()]);

    for network in [WalletNetwork::Shellnet, WalletNetwork::Mainnet] {
        let resolved = resolve_funding_wallet(
            &store,
            network,
            Some("0:explicit"),
            &Some(PathBuf::from("explicit.key")),
            &None,
        )
        .expect("an explicit wallet needs no binding on any network");
        assert_eq!(resolved.address, "0:explicit");
        assert_eq!(resolved.key, Some(PathBuf::from("explicit.key")));
    }
}

/// The new `active/` level is owner-only, and so is the wallet root above it. The write this
/// replaced hardened the root directly, so a change that created only the leaf would quietly relax
/// the directory holding `bindings/` and `archive/`.
#[cfg(unix)]
#[test]
fn the_active_directory_and_the_wallet_root_are_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wallet");
    store_with(&root, &[shellnet_binding()]);

    for path in [root.clone(), root.join("active")] {
        let mode = std::fs::metadata(&path)
            .unwrap_or_else(|error| panic!("metadata {}: {error}", path.display()))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "{} must be owner-only", path.display());
    }
}

// --- the legacy `wallet/binding.json` an operator already has -------------------------------

/// MIGRATION, and the one rule it follows: the destination comes from the record's OWN `network`.
/// The legacy file is a shellnet binding and the command asking is a MAINNET one. The record must
/// land in the shellnet slot, and the mainnet command must still be refused. Migrating it into
/// whichever network happened to ask would be the original defect with a longer path.
#[test]
fn a_legacy_binding_migrates_by_its_own_network_and_not_by_the_asking_one() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wallet");
    let legacy_path = write_legacy(&root, &shellnet_binding());
    let store = WalletStore::at(&root);

    let error = resolve_funding_wallet(&store, WalletNetwork::Mainnet, None, &None, &None)
        .expect_err("a legacy shellnet binding must not answer a mainnet command");
    assert!(
        !format!("{error:#}").contains(SHELLNET_HOT),
        "the legacy shellnet Hot must not reach a mainnet spend: {error:#}"
    );

    assert!(
        store.binding_path(WalletNetwork::Shellnet).exists(),
        "the legacy record must be migrated into the slot its own network names"
    );
    assert!(
        !store.binding_path(WalletNetwork::Mainnet).exists(),
        "it must NOT be migrated into the slot of the network that happened to ask"
    );
    assert!(
        !legacy_path.exists(),
        "the global binding must not survive the move: two records of one Hot would diverge"
    );

    // And it is still the operator's wallet on the network it was bound for.
    let resolved = resolve_funding_wallet(&store, WalletNetwork::Shellnet, None, &None, &None)
        .expect("the migrated binding still funds shellnet");
    assert_eq!(resolved.address, SHELLNET_HOT);
    assert_eq!(resolved.key, Some(PathBuf::from(SHELLNET_KEY)));
}

/// The ordinary upgrade: the operator's legacy binding is for the network they use, and the first
/// command after the upgrade simply works. Nothing is re-onboarded and no wallet is re-bound.
#[test]
fn a_legacy_binding_keeps_working_on_the_network_it_was_bound_for() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wallet");
    let legacy_path = write_legacy(&root, &shellnet_binding());
    let store = WalletStore::at(&root);

    let resolved = resolve_funding_wallet(&store, WalletNetwork::Shellnet, None, &None, &None)
        .expect("an existing operator is not locked out by the upgrade");
    assert_eq!(resolved.address, SHELLNET_HOT);
    assert!(!legacy_path.exists());
    assert!(store.binding_path(WalletNetwork::Shellnet).exists());
}

/// Migration runs once and is safe to repeat: the second read finds no legacy file and the same
/// wallet answers.
#[test]
fn migrating_twice_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wallet");
    write_legacy(&root, &shellnet_binding());
    let store = WalletStore::at(&root);

    let first = resolve_funding_wallet(&store, WalletNetwork::Shellnet, None, &None, &None)
        .expect("first read migrates");
    let second = resolve_funding_wallet(&store, WalletNetwork::Shellnet, None, &None, &None)
        .expect("second read finds the migrated record");
    assert_eq!(first, second);
}

/// A crash between the write and the removal leaves both files holding the SAME record. Finishing
/// the move loses nothing, so it is finished rather than reported.
#[test]
fn an_interrupted_migration_is_completed_rather_than_reported() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wallet");
    let record = shellnet_binding();
    let store = store_with(&root, &[record.clone()]);
    let legacy_path = write_legacy(&root, &record);

    let resolved = resolve_funding_wallet(&store, WalletNetwork::Shellnet, None, &None, &None)
        .expect("identical records are not a conflict");
    assert_eq!(resolved.address, SHELLNET_HOT);
    assert!(!legacy_path.exists(), "the duplicate must be cleared");
}

/// A legacy file and a network-scoped file that DISAGREE are never ranked or merged. Choosing one
/// would be a guess about which Hot the operator's money comes from, so nothing is read and both
/// are named.
#[test]
fn a_legacy_binding_that_disagrees_with_a_migrated_one_refuses_rather_than_picking() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wallet");
    let store = store_with(&root, &[shellnet_binding()]);
    let other = binding(
        MAINNET_ID,
        WalletNetwork::Shellnet,
        "4::a-different-hot",
        "/secrets/other.key",
    );
    let legacy_path = write_legacy(&root, &other);

    let error = resolve_funding_wallet(&store, WalletNetwork::Shellnet, None, &None, &None)
        .expect_err("two different records for one network must not be silently ranked");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("4::a-different-hot") && rendered.contains(SHELLNET_HOT),
        "the operator must be told about both wallets: {rendered}"
    );
    assert!(
        legacy_path.exists(),
        "nothing may be deleted while the two disagree"
    );
}

/// A legacy file this build cannot parse is an error, not a silent "no wallet" -- the same rule the
/// network-scoped files follow, applied where an operator's only record still lives.
#[test]
fn an_unparseable_legacy_binding_is_refused_rather_than_treated_as_absent() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wallet");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("binding.json"), b"{ this is not json").unwrap();
    let store = WalletStore::at(&root);

    let error = resolve_funding_wallet(&store, WalletNetwork::Shellnet, None, &None, &None)
        .expect_err("a legacy record that cannot be read must not be treated as absent");
    assert!(
        !is_wallet_not_configured(&error),
        "an unreadable binding is a different problem from an absent one: {error:#}"
    );
    assert!(
        format!("{error:#}").contains("parse wallet binding"),
        "the error must say the binding could not be read: {error:#}"
    );
}

// --- where the command's network comes from ------------------------------------------------

/// The manifest field `note deploy` and `note topup` already read for the funding-wallet lock is
/// the only source of the command's network, so the wallet that is resolved and the wallet whose
/// turn is taken can never be decided on different chains.
#[test]
fn the_manifest_network_label_maps_to_the_binding_network() {
    assert_eq!(
        WalletNetwork::from_manifest_label("shellnet").expect("shellnet is known"),
        WalletNetwork::Shellnet
    );
    assert_eq!(
        WalletNetwork::from_manifest_label("mainnet").expect("mainnet is known"),
        WalletNetwork::Mainnet
    );
}

/// An unrecognised manifest label REFUSES. Defaulting to shellnet would mean a manifest this build
/// does not understand quietly resolving the shellnet wallet, which is the cross-network spend
/// being prevented.
#[test]
fn an_unknown_manifest_network_refuses_rather_than_defaulting() {
    let error = WalletNetwork::from_manifest_label("devnet")
        .expect_err("an unknown network must not resolve a wallet");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("devnet"), "{rendered}");
    assert!(
        rendered.contains("shellnet") && rendered.contains("mainnet"),
        "the refusal must name the networks this build does know: {rendered}"
    );
}

/// The two deployed manifests in this repository are what production actually reads, so the labels
/// they carry must be the ones the mapping accepts. A rename on either side would otherwise turn
/// every money command into the refusal above.
/// `Deployed` is re-exported from `dexdo_core` only under `shellnet`, and the manifest is only ever
/// read by the two shellnet-gated money commands, so this pin is gated the same way. The rest of
/// this module deliberately is not: it must run in CI's default-feature build too.
#[cfg(feature = "shellnet")]
#[test]
fn the_repository_manifests_carry_labels_this_build_accepts() {
    for (path, expected) in [
        ("contracts/deployed.shellnet.json", WalletNetwork::Shellnet),
        ("contracts/deployed.mainnet.json", WalletNetwork::Mainnet),
    ] {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path);
        let deployed = dexdo_core::Deployed::load(&manifest)
            .unwrap_or_else(|error| panic!("load {}: {error}", manifest.display()));
        assert_eq!(
            WalletNetwork::from_manifest_label(&deployed.network)
                .unwrap_or_else(|error| panic!("{path} declares a network this build refuses: {error}")),
            expected,
        );
    }
}
