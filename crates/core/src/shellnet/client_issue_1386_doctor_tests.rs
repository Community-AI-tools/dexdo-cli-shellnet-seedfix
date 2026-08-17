//! Issue, reporting half: `doctor` must not print a network it is not on.
//! The money half of made the client prove the manifest's declared `network` against the
//! endpoint it dials. This half is the same mislabel one layer up, in what the operator READS:
//! `doctor` is the first thing run to answer "am I where I think I am", and on mainnet it printed
//! the word `shellnet` in its check list. A confident wrong answer to that question precedes
//! spending real money.
//! These drive a real mainnet-configured client -- built from the committed
//! `contracts/deployed.mainnet.json`, the same file mainnet money flows through -- and assert the
//! lines it produces, not that some constant went unused.

use super::RealChainBackend;

/// Path of the committed deployment manifests.
fn contracts_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts")
}

/// A client configured exactly as a mainnet operator's is. `connect_with_endpoint` performs no
/// chain I/O -- it reads the manifest and builds the HTTP clients -- so the lines `doctor` prints
/// are reachable offline, while everything about the client's identity is real.
fn mainnet_client() -> RealChainBackend {
    let backend = RealChainBackend::connect(contracts_dir().join("deployed.mainnet.json"))
        .expect("the committed mainnet manifest must build a client");
    assert_eq!(
        backend.network(),
        crate::params::NETWORK_MAINNET,
        "the fixture must be a mainnet client, or this file proves nothing"
    );
    backend
}

/// THE DEFECT: the endpoint line named `shellnet` on every network.
/// The check is correct -- the endpoint really is reachable -- and that is exactly what makes the
/// label dangerous: the operator gets a PASS naming a chain the client never dialled.
#[test]
fn issue_1386_the_endpoint_check_names_the_network_the_client_dialled() {
    let check = mainnet_client().endpoint_reachable_check();

    assert_eq!(
        check.name, "mainnet endpoint",
        "a mainnet client must name mainnet in the line the operator reads: {} - {}",
        check.name, check.message
    );
    assert!(
        !format!("{} {}", check.name, check.message).contains(crate::params::NETWORK_SHELLNET),
        "no part of a mainnet client's endpoint check may say `shellnet`: {} - {}",
        check.name,
        check.message
    );
}

/// The shellnet operator's line is unchanged by the fix -- the label was only ever right there.
#[test]
fn issue_1386_a_shellnet_client_still_reads_exactly_as_before() {
    let backend = RealChainBackend::connect(contracts_dir().join("deployed.shellnet.json"))
        .expect("the committed shellnet manifest must build a client");
    let check = backend.endpoint_reachable_check();

    assert_eq!(check.name, "shellnet endpoint");
    assert_eq!(check.message, "reachable");
}

/// The pin verdicts are the other thing `doctor` prints, thirteen times over on a mainnet run.
/// The pinned code hashes are GENERATION pins -- one 4.0.35 build, matched on both chains -- so a
/// verdict that names a network is claiming something the comparison never established. It named
/// `shellnet` unconditionally, which on mainnet is simply false. The actionable half of the stale
/// message must survive: it is what tells the operator what to do.
#[test]
fn issue_1386_a_pin_verdict_never_names_a_network_the_run_is_not_on() {
    let address = super::Address::parse(&format!("0:{}", "0c".repeat(32))).expect("address");
    let elsewhere = "00000000000000000000000000000000000000000000000000000000000000ff";

    let matched =
        super::superroot_generation_check(&address, Some(super::SHELLNET_SUPERROOT_CODE_HASH));
    assert_eq!(matched.status, super::ShellnetDoctorStatus::Pass);
    assert!(
        !matched.message.contains(crate::params::NETWORK_SHELLNET),
        "a matching pin must not report the chain as `shellnet` on a mainnet run: {}",
        matched.message
    );

    let stale = super::superroot_generation_check(&address, Some(elsewhere));
    assert_eq!(stale.status, super::ShellnetDoctorStatus::Fail);
    assert!(
        !stale.message.contains(crate::params::NETWORK_SHELLNET),
        "a stale pin must not report the chain as `shellnet` on a mainnet run: {}",
        stale.message
    );
    assert!(
        stale.message.contains("STALE") && stale.message.contains("rebuild from dev HEAD"),
        "the operator still has to be told what to do about it: {}",
        stale.message
    );
}

/// The report header already sourced its label from the manifest; this holds that line still.
#[test]
fn issue_1386_the_report_header_label_is_the_manifest_network() {
    assert_eq!(mainnet_client().network(), "mainnet");
}
