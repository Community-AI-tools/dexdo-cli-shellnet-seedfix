//! Issue: the declared `network` must be provable against the endpoint the client dials.
//! `Deployed.network` is what `RealChainBackend::network()` returns, and that string is the only
//! input to [`crate::params::resolve_deal_gas_overhead_raw`] -- the guard that decides whether a
//! measured gas overhead may fund a deal. Its own refusal text names the loss it prevents: a
//! `TokenContract` stalled permanently with both bonds inside. Until this test existed, nothing
//! checked the label against the chain being dialled, so a manifest carrying MAINNET roots while
//! labelled `shellnet` made that guard approve a shellnet measurement for mainnet money.
//! These drive the real entry ordering -- `connect_client_from_manifest_with`, the single chokepoint
//! every `RealChainBackend::connect*` goes through -- rather than the predicate alone, and assert
//! that the connector is never reached on a contradiction.

use std::cell::Cell;

/// Path of the committed deployment manifests.
fn contracts_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts")
}

/// The committed mainnet manifest as raw JSON, so a field can be tampered with while every other
/// value -- the four mainnet roots, the dapp id, the code hashes -- stays exactly as deployed.
fn committed_mainnet_json() -> serde_json::Value {
    let bytes = std::fs::read(contracts_dir().join("deployed.mainnet.json"))
        .expect("read committed mainnet manifest");
    serde_json::from_slice(&bytes).expect("parse committed mainnet manifest as JSON")
}

fn write_manifest(dir: &std::path::Path, name: &str, manifest: &serde_json::Value) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(manifest).expect("serialize tampered manifest"),
    )
    .expect("write tampered manifest");
    path
}

/// THE DEFECT: mainnet roots, `network: "shellnet"`, dialled at the mainnet endpoint.
/// Every address in this manifest is the real mainnet deployment; only the label lies. The client
/// must refuse before it connects, because everything downstream -- the SDK profile and the gas
/// guard alike -- trusts that label.
#[test]
fn issue_1386_mainnet_roots_labelled_shellnet_are_refused_at_the_mainnet_endpoint() {
    let mut manifest = committed_mainnet_json();
    manifest["network"] = serde_json::Value::String("shellnet".to_string());
    let dir = tempfile::tempdir().expect("manifest fixture directory");
    let path = write_manifest(dir.path(), "deployed.mislabelled.json", &manifest);
    let connector_called = Cell::new(false);

    let error = super::connect_client_from_manifest_with(&path, None, |_, _| {
        connector_called.set(true);
        Ok(())
    })
    .expect_err("mainnet roots labelled `shellnet` must be refused at the mainnet endpoint");
    let error = format!("{error:#}");

    assert!(
        !connector_called.get(),
        "no connection attempt is allowed once the label contradicts the endpoint: {error}"
    );
    // An operator must be able to act on this without reading the source: both values, and
    // the file that has to be corrected.
    assert!(
        error.contains("shellnet"),
        "the refusal must name the DECLARED network: {error}"
    );
    assert!(
        error.contains("mainnet"),
        "the refusal must name the OBSERVED network: {error}"
    );
    assert!(
        error.contains(crate::params::WALLET_ONBOARD_MAINNET_ENDPOINT),
        "the refusal must name the endpoint host it derived the observed network from: {error}"
    );
    assert!(
        error.contains("deployed.mislabelled.json"),
        "the refusal must name the manifest file it read: {error}"
    );
}

/// The same lie, told through `--endpoint` instead of the manifest's own field.
/// The override wins in `resolve_endpoint`, so a check that only read `manifest.endpoint` would
/// pass this and still dial mainnet.
#[test]
fn issue_1386_endpoint_override_to_mainnet_is_refused_for_a_shellnet_manifest() {
    let mut manifest = committed_mainnet_json();
    manifest["network"] = serde_json::Value::String("shellnet".to_string());
    manifest
        .as_object_mut()
        .expect("deployment manifest is an object")
        .remove("endpoint");
    let dir = tempfile::tempdir().expect("manifest fixture directory");
    let path = write_manifest(dir.path(), "deployed.override.json", &manifest);
    let connector_called = Cell::new(false);

    let error = super::connect_client_from_manifest_with(
        &path,
        Some("https://dd-mainnet.ackinacki.org/graphql"),
        |_, _| {
            connector_called.set(true);
            Ok(())
        },
    )
    .expect_err("an override that dials mainnet must be refused by a `shellnet` manifest");
    let error = format!("{error:#}");

    assert!(
        !connector_called.get(),
        "no connection attempt is allowed once the override contradicts the label: {error}"
    );
    assert!(
        error.contains("mainnet") && error.contains("shellnet"),
        "the refusal must name both networks: {error}"
    );
}

/// The mirror case: shellnet roots labelled `mainnet`. The check is not one-directional.
#[test]
fn issue_1386_shellnet_endpoint_is_refused_for_a_mainnet_labelled_manifest() {
    let mut manifest = committed_mainnet_json();
    manifest["endpoint"] =
        serde_json::Value::String(crate::params::DEFAULT_SHELLNET_ENDPOINT.to_string());
    let dir = tempfile::tempdir().expect("manifest fixture directory");
    let path = write_manifest(dir.path(), "deployed.reversed.json", &manifest);
    let connector_called = Cell::new(false);

    let error = super::connect_client_from_manifest_with(&path, None, |_, _| {
        connector_called.set(true);
        Ok(())
    })
    .expect_err("a `mainnet` manifest pointed at the shellnet endpoint must be refused");

    assert!(!connector_called.get(), "{error:#}");
}

/// THE HONEST CASE MUST KEEP WORKING, UNCHANGED.
/// `contracts/deployed.mainnet.json` declares `mainnet` and carries the mainnet endpoint; it is the
/// file real mainnet money flows through and this change must be invisible to it.
#[test]
fn issue_1386_committed_mainnet_manifest_still_connects_unchanged() {
    let path = contracts_dir().join("deployed.mainnet.json");
    let connector_called = Cell::new(false);

    let (deployed, ()) = super::connect_client_from_manifest_with(&path, None, |endpoint, _| {
        connector_called.set(true);
        assert_eq!(endpoint, "https://dd-mainnet.ackinacki.org");
        Ok(())
    })
    .expect("the committed mainnet manifest must keep connecting");

    assert!(connector_called.get(), "the connector must be reached");
    assert_eq!(deployed.network, "mainnet");
}

/// And the committed shellnet manifest, which carries no `endpoint` at all and so falls back to
/// [`crate::params::DEFAULT_SHELLNET_ENDPOINT`].
#[test]
fn issue_1386_committed_shellnet_manifest_still_connects_unchanged() {
    let path = contracts_dir().join("deployed.shellnet.json");
    let connector_called = Cell::new(false);

    let (deployed, ()) = super::connect_client_from_manifest_with(&path, None, |endpoint, _| {
        connector_called.set(true);
        assert_eq!(endpoint, crate::params::DEFAULT_SHELLNET_ENDPOINT);
        Ok(())
    })
    .expect("the committed shellnet manifest must keep connecting");

    assert!(connector_called.get(), "the connector must be reached");
    assert_eq!(deployed.network, "shellnet");
}

/// AN UNRECOGNIZED HOST IS NOT A CONTRADICTION.
/// A local harness, a private gateway or a proxy is not evidence of any network, and refusing what
/// cannot be disproved offline would break every such setup while preventing nothing: the loss in
/// needs a host that IS mainnet. Only a host this tree can NAME, disagreeing with the label,
/// is a refusal.
#[test]
fn issue_1386_unrecognized_endpoint_host_is_not_a_contradiction() {
    let path = contracts_dir().join("deployed.shellnet.json");
    let connector_called = Cell::new(false);

    super::connect_client_from_manifest_with(&path, Some("http://127.0.0.1:8080"), |_, _| {
        connector_called.set(true);
        Ok(())
    })
    .expect("a host this tree cannot name must not be treated as a contradiction");

    assert!(connector_called.get(), "the connector must be reached");
}
