//! `wallet onboard gosh-ai` could not resolve an endpoint at all, and said the wrong thing about it.

//! The path read its endpoint from `GoshAiOnboardOptions::contracts`, and the single site that
//! builds those options passed `None` -- because the `--contracts` flag it used to carry was removed
//! and nothing replaced it. So `wallet_read_endpoint` was handed `None` on every run, took
//! the no-endpoint branch, and refused. **Not for some inputs: for all of them.** The manifest could
//! name an endpoint, `DEXDO_MANIFEST` could point at it, `doctor` could pass against the same file,
//! and the answer was the same.

//! Two things go wrong there, and only one of them is the missing manifest.

//! The refusal says `the manifest names no `endpoint`` for THREE different situations: nobody named
//! a manifest, the named manifest could not be read, and the manifest was read and has no endpoint.
//! An operator who is told the third while living in the first edits a file that is already correct.
//! Measured on the acceptance stand: the message arrives AFTER the recovery phrase and the
//! onboarding draft are on disk, so it reads as "your manifest is broken" at the exact moment the
//! operator has most reason to believe their setup is fine.

//! What these hold, therefore: that the gosh-ai path takes the manifest the client itself reads --
//! the same seam the manual path already uses -- and that each of the three situations is refused in
//! its own words, with the action the operator can take.

use super::*;

/// The production source of the gosh-ai onboarding path, read as text.

/// A source guard rather than a behavioural one, and the reason is the seam: proving this by running
/// `run_wallet_onboard_goshai` would need a Gosh.ai activation, a deployed Hot and a chain to read
/// it from. What the defect is about is WHERE the endpoint comes from, and that is decided in one
/// line of that function.
fn goshai_source() -> &'static str {
    include_str!("../wallet_goshai.rs")
}

/// The manual onboarding path, the reference this one has to match.
fn manual_source() -> &'static str {
    include_str!("../wallet_manual.rs")
}

/// Every production caller of `wallet_read_endpoint`, found by walking the crate's sources.

/// Derived rather than listed. A hardcoded four-file array holds today's callers and nothing else:
/// a fifth one, in a file added next month, passes the guard by not being in the array -- which is
/// the shape of guard that reads as coverage and is not.

/// `*_tests.rs` is dropped because those files drive the `None` branch ON PURPOSE. A call inside a
/// `#[cfg(test)]` block within a production file is still read as production; that direction is a
/// false red, never a false green, and a false red is one comment away from being understood.
fn every_caller() -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut stack = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read a source directory") {
            let path = entry.expect("read a source entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().map(|ext| ext != "rs").unwrap_or(true) {
                continue;
            }
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_default();
            if name.ends_with("_tests.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read a source file");
            if text.contains("wallet_read_endpoint(") {
                found.push((name, text));
            }
        }
    }
    found
}

/// The declaration this guard anchors on.

/// `source_probe` requires the anchor to start a line after trimming, so the visibility is part of
/// it: both of these items are indented, and an anchor without `pub(crate)` matches text that is
/// not the declaration. Written inline, unlike an earlier draft that assembled these with `format!`
/// to avoid a self-match -- the probe reads `wallet_goshai.rs` and `wallet_manual.rs` and never
/// this file, so no literal here could ever be matched, and the doc block explaining the hazard
/// described one that does not exist.
const GOSHAI_SIGNATURE: &str = "pub(crate) async fn run_wallet_onboard_goshai";

/// The manual path's entry is named `run`, not `run_wallet_onboard_manual`.

/// Written down because it is not guessable and because guessing it is how this guard first failed:
/// the anchor has to be the declaration as it stands, and the declaration is generic. It is unique
/// in that file, and the guard asserts that rather than trusting it -- `source_probe` takes the
/// FIRST match, so a second `pub(crate) async fn run` appearing there would silently move the guard
/// onto a different function.
const MANUAL_SIGNATURE: &str = "pub(crate) async fn run(";

/// THE DEFECT: the gosh-ai path resolves its endpoint from the manifest the client reads.

/// Held by shape rather than by name: what must be true is that the endpoint call in that function
/// is handed `manifest_path()`, the same way the manual path does it. Before it was handed
/// `options.contracts`, a field the only caller filled with `None`.

/// Comments are stripped first (`code_of`): this file's own prose names `options.contracts` several
/// times, and a guard that matched commented-out text would pass on a change that only moved the
/// call into a comment.
#[test]
fn the_goshai_path_takes_its_endpoint_from_the_manifest_the_client_reads() {
    let body = crate::cli::source_probe::code_of(goshai_source(), GOSHAI_SIGNATURE);

    assert!(
        body.contains("wallet_read_endpoint("),
        "the gosh-ai path no longer resolves an endpoint at all"
    );
    // Adjacency, not co-presence. Asserting that both strings appear SOMEWHERE in the body passes
    // on the defect reintroduced under a new name: add `manifest: Option<PathBuf>` to the options,
    // hand `options.manifest.as_deref()` to the call, and mention `manifest_path()` in a hint line
    // -- both substrings present, `options.contracts` absent, endpoint back to a field whose only
    // writer passes None. So the manifest argument itself is what is read.
    let argument = body
        .split_once("wallet_read_endpoint(")
        .map(|(_, rest)| rest.trim_start().chars().take(80).collect::<String>())
        .unwrap_or_default();
    assert!(
        argument.contains("manifest_path()"),
        "the gosh-ai path does not resolve its endpoint from the manifest the client reads; it \
         refuses on every input when whatever it reads instead is empty. Argument: `{argument}`"
    );
    assert!(
        !body.contains("options.contracts"),
        "the gosh-ai path still reads `options.contracts`, the field whose only writer passes None"
    );
}

/// The manual path is the reference, so it must still BE the reference.

/// Without this the check above passes on the day somebody breaks the manual path the same way: two
/// paths agreeing is worth nothing when they agree on being wrong.
#[test]
fn the_manual_path_resolves_it_the_same_way_and_is_the_reference() {
    let signature = MANUAL_SIGNATURE;
    assert_eq!(
        manual_source()
            .lines()
            .filter(|line| line.trim_start().starts_with(signature))
            .count(),
        1,
        "`{signature}` is no longer unique in the manual path, so this guard may be reading a different function than it names"
    );

    let body = crate::cli::source_probe::code_of(manual_source(), signature);
    let argument = body
        .split_once("wallet_read_endpoint(")
        .map(|(_, rest)| rest.trim_start().chars().take(80).collect::<String>())
        .unwrap_or_default();
    assert!(
        argument.contains("manifest_path()"),
        "the manual path no longer reads the manifest, so it cannot be what the gosh-ai path is \
         held to. Argument: `{argument}`"
    );
}

/// A manifest nobody named is refused in its own words, not as a manifest with a missing field.

/// This is the situation the gosh-ai path was permanently in, and the message it produced sent every
/// operator to edit a file that was already correct.
#[test]
fn no_manifest_named_is_refused_as_no_manifest_named() {
    let error = wallet_read_endpoint(None, crate::cli::wallet::test_network_a())
        .expect_err("with no manifest there is nothing to read an endpoint from");
    let said = error.to_string();
    assert!(
        said.contains("no manifest"),
        "the refusal blames the manifest's contents when no manifest was named at all: {said}"
    );
    assert!(
        !said.contains("Add an `endpoint` field"),
        "the refusal tells the operator to edit a file that was never named: {said}"
    );
    assert!(
        said.contains("DEXDO_MANIFEST"),
        "the refusal does not name what the operator can set: {said}"
    );
}

/// A manifest that cannot be read is refused as unreadable, and names the path.

/// It used to be swallowed: the loader's error went into `.ok()` and the caller reported a missing
/// field. An operator with a truncated or mistyped file was told to add a field it may already have.
#[test]
fn an_unreadable_manifest_is_refused_as_unreadable_and_names_the_file() {
    // Namespaced by pid, like `endpoint_tests::manifest_with` beside it: a fixed name in the shared
    // temp directory is one path for the lib target, the bin target and any concurrent run, and a
    // failing assertion below skips the cleanup, so the file survives into the next run.
    let dir = std::env::temp_dir().join(format!("dexdo-1839-not-json-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create the manifest directory");
    let path = dir.join("deployed.test.json");
    std::fs::write(&path, "this is not json").expect("write the broken manifest");

    let error = wallet_read_endpoint(Some(&path), crate::cli::wallet::test_network_a())
        .expect_err("a manifest that does not parse cannot answer for an endpoint");
    let said = error.to_string();
    assert!(
        said.contains("dexdo-1839-not-json"),
        "the refusal does not name the file it could not read: {said}"
    );
    assert!(
        !said.contains("Add an `endpoint` field"),
        "an unreadable manifest is reported as a manifest missing a field: {said}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// And the third situation keeps its own words: read, but carrying no endpoint.

/// Both directions on the same seam. Without this the two above are satisfied by a refusal that
/// stopped distinguishing anything and simply says less.
#[test]
fn a_manifest_without_an_endpoint_is_still_refused_for_that_reason() {
    // A manifest that PARSES and simply carries no `endpoint`. Written in full on purpose: the
    // first draft of this fixture was `{"network":"net-a"}`, which the loader rejects for a missing
    // `superroot` -- so it exercised the unreadable branch and said nothing about this one. A
    // fixture that lands in the wrong branch reads exactly like a passing test.
    let dir = std::env::temp_dir().join(format!("dexdo-1839-no-endpoint-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create the manifest directory");
    let path = dir.join("deployed.test.json");
    std::fs::write(
        &path,
        serde_json::json!({
            "network": "net-a",
            "version": "endpoint-absent-fixture",
            "superroot": "0:0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "dapp_config": "",
            "dapp_id": "0000000000000000000000000000000000000000000000000000000000000004",
        })
        .to_string(),
    )
    .expect("write the endpoint-less manifest");

    let error = wallet_read_endpoint(Some(&path), crate::cli::wallet::test_network_a())
        .expect_err("a manifest with no endpoint cannot answer for one");
    let said = error.to_string();
    assert!(
        said.contains("`endpoint`"),
        "the refusal does not say which field is missing: {said}"
    );
    assert!(
        !said.contains("no manifest was named"),
        "a manifest that WAS read is reported as one that was never named: {said}"
    );
    assert!(
        !said.contains("could not be read"),
        "a manifest that parsed is reported as unreadable: {said}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// No caller may hand `None` where the manifest goes -- not even conditionally.

/// `wallet_read_endpoint` refuses `None` with "no manifest was named", and that sentence is only
/// true when nobody named one. Two callers used to pass `manifest_agrees.then_some(path)`: a
/// manifest describing ANOTHER network became `None`, so an operator with `DEXDO_MANIFEST` set and
/// pointing at a perfectly good file was told they had named no manifest at all. That is the same
/// wrong-situation-wrong-message shape is about, arriving from the other side -- and it was
/// introduced by the very change that split the refusals.

/// A network the manifest does not describe is its own situation and belongs to the CALLER, which
/// is the only place that knows which network was expected. `hot_balance_for` already refuses it in
/// its own words; this holds the other callers to that.

/// Line comments are dropped before scanning, which is what these files use; a call buried in a
/// block comment would be read as code, and no file here has one.
#[test]
fn no_caller_hands_the_manifest_in_as_a_maybe() {
    let callers = every_caller();
    assert!(
        callers.len() >= 4,
        "the scan found {} files calling wallet_read_endpoint; four are known to. A scan that \
         matches nothing reports exactly what a clean tree reports",
        callers.len()
    );
    for (name, source) in callers {
        let code = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for call in code.split("wallet_read_endpoint(").skip(1) {
            let argument = call.trim_start();
            // The declaration is `fn wallet_read_endpoint(` followed by its parameter list; every
            // call passes an expression. Skipping by name would skip the calls too.
            if argument.starts_with("manifest: Option") {
                continue;
            }
            assert!(
                argument.starts_with("Some("),
                "{name} calls wallet_read_endpoint with a manifest that may be absent: `{}`. A \
                 manifest that disagrees about the network is not a manifest nobody named, and the \
                 refusal for the second is a lie about the operator's environment",
                argument.chars().take(60).collect::<String>()
            );
        }
    }
}

/// The caller-side refusal says which network the manifest is for and which one was expected.

/// Held by message, not only by the guard above: the guard proves the manifest is handed over as
/// `Some`, and says nothing about what the caller does with a manifest for another chain.
#[test]
fn a_manifest_for_another_network_is_refused_as_that() {
    let error = crate::cli::wallet::refuse_a_manifest_for_another_network(
        "net-b",
        &crate::cli::wallet::test_network_a(),
    )
    .expect_err("a manifest for another chain cannot say how to reach this one");
    let said = error.to_string();
    assert!(
        said.contains("net-b") && said.contains("net-a"),
        "the refusal names both the manifest's network and the expected one: {said}"
    );
    assert!(
        !said.contains("no manifest was named"),
        "a manifest that WAS named is reported as one that was not: {said}"
    );
}

/// THE DEFECT: a label that only differs by surrounding whitespace is the SAME network.

/// The label reaches every other part of the client through `WalletNetwork::from_manifest_label`,
/// which trims. Comparing the manifest's raw string against the trimmed one makes ` net-a ` a
/// different chain from `net-a`, and the only refusal that comparison can ever produce contradicts
/// itself in its own sentence: "names net-a, and this archived binding is on net-a". An operator
/// reading that has no move -- the two names it prints are the same name.
#[test]
fn a_padded_label_is_not_a_different_network() {
    crate::cli::wallet::refuse_a_manifest_for_another_network(
        " net-a\n",
        &crate::cli::wallet::test_network_a(),
    )
    .expect("a label that differs only by surrounding whitespace is the same network");
}
