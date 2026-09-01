//! The defect class named, held where it now lives: a network's NAME is never an address.

//! `network_label_not_address_1438.rs` held this class against the compiled-in table of networks.
//! removed the table, and with it every assertion that file could make -- `known_network`,
//! `network_for_endpoint` and the two label constants are all gone. The class did not go with them.
//! It only moved: the endpoint is now the manifest's own field, and the question is whether a run
//! that has one reads it, and a run that has none is told so instead of being sent at a host named
//! after its chain.

//! Both halves are regressions that already happened once each, in opposite directions:

//! - the label became a host. `doctor` substituted the network name for the endpoint whenever the
//! name was not one particular literal, so asking for another network dialled a machine named
//! after it, died in DNS, and never looked at the endpoint the manifest was carrying;
//! - the manifest stopped being read. The fall-through was resolved FIRST, with `?`, back when it
//! returned a table lookup that usually succeeded. Once the table went, that line refused every
//! run before `deployed.endpoint` was consulted, so `doctor` could reach no chain at all -- on
//! every manifest in the tree, all of which carry an endpoint.

//! The second is what this file would have caught: it is a one-line ordering change with no
//! compiler error and no failing test, and the branch carried it for a while.

use super::{doctor_endpoint_source, no_endpoint_in_manifest};

/// A placeholder label that is also a plausible hostname, so a test that passed by accident would
/// be indistinguishable from one that passed because the code is right.

/// It is a placeholder and not a real chain's name ON PURPOSE: acceptance check (a) of counts
/// network names in `crates/**/*.rs`, and the first draft of this file put one here -- in the file
/// whose own header says the name does not belong in a source file.
const LABEL: &str = "net-a";
const MANIFEST_ENDPOINT: &str = "https://dd-net-a.example.invalid";
const EXPLICIT_ENDPOINT: &str = "https://explicit.example.invalid";

/// The manifest carries an endpoint and nothing else names one: that endpoint is what gets dialled.

/// This is the ordinary case for every manifest this tree ships, and the one the fall-through
/// broke: resolved first, it refused here before the manifest was ever read.
#[test]
fn a_manifest_that_names_an_endpoint_is_what_doctor_dials() {
    let chosen = doctor_endpoint_source(LABEL, None, Some(MANIFEST_ENDPOINT))
        .expect("a manifest carrying an endpoint is dialable");

    assert_eq!(
        chosen, MANIFEST_ENDPOINT,
        "the manifest's own endpoint is the address, and nothing else was consulted"
    );
}

/// An explicit endpoint outranks the manifest's -- the preflight path supplies one.

/// Pinned because the ordering reads as dead code from `run_doctor` alone, which passes `None`:
/// the other caller (`manifest_preflight_endpoint`) passes `Some`, and a "simplification" that
/// dropped the parameter would silently send that path to the manifest's endpoint instead.
#[test]
fn an_explicit_endpoint_outranks_the_manifests() {
    let chosen = doctor_endpoint_source(LABEL, Some(EXPLICIT_ENDPOINT), Some(MANIFEST_ENDPOINT))
        .expect("an explicit endpoint is dialable");

    assert_eq!(chosen, EXPLICIT_ENDPOINT, "explicit outranks the manifest");
}

/// With no endpoint anywhere, the run is REFUSED -- the label is not turned into one.

/// The assertion is on what the refusal does NOT contain as an address, because the defect's
/// signature was a host assembled from the chain's name.
#[test]
fn a_label_alone_yields_no_address_at_all() {
    let refusal = doctor_endpoint_source(LABEL, None, None)
        .expect_err("a manifest with no endpoint has nothing to dial");
    let said = refusal.to_string();

    assert!(
        !said.contains(&format!("https://{LABEL}")) && !said.contains(&format!("//{LABEL}")),
        "no address may be assembled from the label; the refusal said: {said}"
    );
    assert!(
        said.contains(LABEL),
        "the refusal still has to NAME the network it is talking about: {said}"
    );
    assert!(
        said.contains("endpoint"),
        "and it has to name the field to add: {said}"
    );
}

/// The refusal says what to do about it, and says it in the manifest's terms.

/// A refusal that only states the absence leaves the operator to guess whether the fix is a flag,
/// a variable or a file. There is no flag and no variable left: the answer is a field.
#[test]
fn the_refusal_names_the_field_to_add_rather_than_a_flag_that_no_longer_exists() {
    let said = no_endpoint_in_manifest(LABEL)
        .expect_err("this helper only ever refuses")
        .to_string();

    assert!(
        said.contains("Add an `endpoint` field to the manifest"),
        "the refusal has to name the repair: {said}"
    );
    assert!(
        !said.contains("--endpoint") && !said.contains("--network"),
        "neither flag exists any more, so neither may be suggested: {said}"
    );
}
