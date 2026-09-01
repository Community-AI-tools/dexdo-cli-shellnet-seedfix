//! A manifest's `network` label keys a file inside the instance, and it may not name a path.

//! replaced the closed pair of network labels with the manifest's own string, because which
//! chains exist is not this client's to know. That is the right direction and it is not in question
//! here. What came with it is: the label is interpolated into a FILE NAME
//! (`store.rs:111`, `active_dir().join(format!("{label}.json"))`), and `Path::join` does not treat
//! its argument as one component. An absolute argument REPLACES the base outright, and `..`
//! segments walk out of it -- so before this file, a manifest could put the wallet binding anywhere
//! on the disk the process could write.

//! What that binding holds is the point: the paths to the Hot key and the recovery-phrase file, and
//! which address funds the spends. A record written outside `--data-dir` is also unreadable back --
//! `bound_networks` (`store.rs:118`) enumerates `active/*.json` and nothing else, so `wallet show`
//! would answer "No wallet bound" with the record sitting on disk. That is the exact failure its
//! own doc comment says it exists to prevent.

//! The manifest is not operator-typed input the way a flag is: `dexdo-install` tells the user to
//! download it, and `doctor`'s refusal calls it "a manifest you downloaded". The closed enum used
//! to make this unreachable; the check has to move with the type.

use super::{WalletNetwork, WalletStore};

/// Labels that are not file names. Each is a real shape, not a synthetic one:
/// an absolute path (`join` discards the base), a walk-out, a nested walk-out that looks harmless
/// until it is joined, and a bare separator.
const NOT_FILE_NAMES: &[&str] = &[
    "/tmp/dexdo-elsewhere",
    "../../../../tmp/dexdo-elsewhere",
    "net-a/../../../tmp/dexdo-elsewhere",
    "net-a/nested",
    "..",
    // The trailing-separator family, and it is the reason this list grew. `Path::components`
    // NORMALIZES these away, so each yields exactly one `Normal` component and the first version of
    // this guard accepted all four. The label is stored raw, so the binding becomes
    // `wallet/active/net-a/.json` -- a file in a directory nothing creates, and the write is the
    // last step of onboarding, after the multisig is deployed and the gas is spent.
    "net-a/",
    "net-a/.",
    "net-a//",
    "net-a/./",
];

/// A label that names a path is refused, and the refusal says which label and why.
#[test]
fn a_label_that_is_a_path_is_refused_before_it_becomes_one() {
    for label in NOT_FILE_NAMES {
        let refused = WalletNetwork::from_manifest_label(label);

        let error = match refused {
            Err(error) => error,
            Ok(accepted) => panic!(
                "the label {label:?} was accepted and would key the binding file \
                 `{}.json` -- `Path::join` does not keep that inside the instance",
                accepted.as_str()
            ),
        };

        let said = error.to_string();
        assert!(
            said.contains(label.trim()) || said.contains("network"),
            "the refusal has to name what it refused: {said}"
        );
    }
}

/// The ordinary label still passes, so the check above is a boundary and not a wall.

/// Without this, a refusal of everything would satisfy the test above and break every run.
#[test]
fn an_ordinary_label_is_still_accepted_and_stays_inside_the_instance() {
    let network = WalletNetwork::from_manifest_label("net-a")
        .expect("an ordinary label is a file name and stays one");

    let root = std::path::Path::new("/instance/wallet");
    let path = WalletStore::at(root).binding_path(&network);

    assert!(
        path.starts_with(root),
        "the binding for an ordinary label belongs under the instance: {}",
        path.display()
    );
    assert!(
        path.ends_with("net-a.json"),
        "and it is keyed by the label: {}",
        path.display()
    );
}

/// The empty label keeps its own refusal -- this file must not swallow it into a vaguer one.
#[test]
fn the_empty_label_is_still_refused_by_its_own_message() {
    let said = WalletNetwork::from_manifest_label("   ")
        .expect_err("an empty label names no network")
        .to_string();

    assert!(
        said.contains("empty"),
        "the empty case keeps naming itself: {said}"
    );
}
