//! `note deploy` proves the manifest's `network` against its endpoint before it spends.
//! Everywhere else the cross-check rides on `RealChainBackend::connect*`, which refuses before a
//! chain client exists. `note deploy` is the exception that needs its own call: it funds the Hot
//! wallet through a plain `ChainClient` and hands `funding_network` straight to that funding call,
//! several minutes before it builds the manifest-checked backend. On that path a connect-time check
//! would arrive one wallet spend too late.
//! The field is also the sole discriminator of the funding-wallet lock
//! whose key is `sha256(network || 0x1f || wallet)`. That key
//! is sound only while the label is true: two manifests naming different networks but pointing at
//! ONE endpoint hash to two different locks for one wallet on one chain, and both spenders proceed
//! past the turn the lock exists to enforce. `funding_wallet_lock_key_separates_networks_and_joins_address_forms_1291`
//! pins that divergence as intended behaviour for two real chains; nothing pinned the premise it
//! rests on, which is what this file adds.

use dexdo_core::params;

fn contracts(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts")
        .join(name)
}

/// The combination `note deploy` reaches with NOTHING typed wrong by the operator.
/// `--endpoint` defaults to [`params::DEFAULT_NOTE_DEPLOY_ENDPOINT`], which is a shellnet host, so
/// a `note deploy` given the committed MAINNET manifest and no endpoint of its own dials shellnet
/// while every address it carries is mainnet. That has to be a refusal, and the refusal has to say
/// which two things disagree -- the operator's fix is to supply the endpoint, and a message that
/// does not name it does not lead them there.
#[test]
fn note_deploy_default_endpoint_contradicts_a_mainnet_manifest_1386() {
    let manifest = contracts("deployed.mainnet.json");
    let declared = dexdo_core::Deployed::load(&manifest)
        .expect("load the committed mainnet manifest")
        .network;
    assert_eq!(declared, params::NETWORK_MAINNET);

    let error = params::verify_declared_network_matches_endpoint(
        &declared,
        params::DEFAULT_NOTE_DEPLOY_ENDPOINT,
        &manifest.display().to_string(),
    )
    .expect_err("the shellnet default endpoint must not silently drive a mainnet manifest");

    assert!(error.contains(params::NETWORK_MAINNET), "{error}");
    assert!(error.contains(params::NETWORK_SHELLNET), "{error}");
    assert!(
        error.contains(params::DEFAULT_NOTE_DEPLOY_ENDPOINT),
        "the refusal must name the endpoint the operator has to override: {error}"
    );
    assert!(
        error.contains("deployed.mainnet.json"),
        "the refusal must name the manifest file to correct: {error}"
    );
}

/// The mislabelled manifest of itself: mainnet endpoint, `network: "shellnet"`.
/// This is the pair that both defeats the lock key and feeds the gas guard a shellnet measurement
/// for mainnet money.
#[test]
fn mainnet_endpoint_under_a_shellnet_label_is_refused_before_the_wallet_is_spent_1386() {
    let error = params::verify_declared_network_matches_endpoint(
        params::NETWORK_SHELLNET,
        params::WALLET_ONBOARD_MAINNET_ENDPOINT,
        "mn-seller/contracts/deployed.shellnet.json",
    )
    .expect_err("mainnet endpoint under a shellnet label must be refused");

    assert!(error.contains(params::NETWORK_SHELLNET), "{error}");
    assert!(error.contains(params::NETWORK_MAINNET), "{error}");
    assert!(
        error.contains("mn-seller/contracts/deployed.shellnet.json"),
        "{error}"
    );
}

/// And the honest deploy keeps working: the shellnet manifest with the shellnet default.
#[test]
fn the_honest_note_deploy_pairing_is_untouched_1386() {
    let declared = dexdo_core::Deployed::load(contracts("deployed.shellnet.json"))
        .expect("load the committed shellnet manifest")
        .network;

    params::verify_declared_network_matches_endpoint(
        &declared,
        params::DEFAULT_NOTE_DEPLOY_ENDPOINT,
        "contracts/deployed.shellnet.json",
    )
    .expect("the shipped shellnet pairing must keep deploying");
}
