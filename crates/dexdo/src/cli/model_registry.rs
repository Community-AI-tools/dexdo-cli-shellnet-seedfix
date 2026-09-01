//! `dexdo model-registry`: the on-chain model registry, read out and written down.

//! Read-only in the strong sense. One account is read, every answer comes from running the
//! contract's own getters against that snapshot, and nothing is submitted. The command exists
//! because there was no way to ask the registry what it holds: `has(name)` answers about a name you
//! already have, and the only enumerable copy of the catalogue was a file in the client's sources,
//! which the chain can outgrow without telling anyone.

//! **Why a file and not just stdout.** The registry is ten thousand names. An operator does not
//! read that; they search it, diff it against yesterday's, and feed the part they need into
//! `models.json`. So the whole answer goes to `--output` as JSON, and what reaches the screen is
//! the verdict: which registry, on which network, how many names, and where they were written.

use anyhow::{bail, Result};

use crate::cli::args::ModelRegistryArgs;

/// What the export writes, and what `--json` prints.

/// The names are the registry's own strings, in the order the decoder sorted them -- by bytes, so
/// two exports of an unchanged registry are the same file and `diff` says nothing. The address and
/// the network are carried beside them because a name list with no chain attached is a list of
/// words: the same name means a different order book on a different network.
#[derive(Debug, serde::Serialize)]
struct ModelRegistryExport<'a> {
    schema: &'a str,
    network: &'a str,
    registry: &'a str,
    /// What `count()` states, and what the decoded map holds. Equal, or the command has refused.
    count: u32,
    models: &'a [String],
}

/// The export, or a refusal: the registry's two answers about itself have to agree.

/// `count()` is a field the contract maintains as it writes; the names come from decoding the map
/// itself. Two answers with different derivations, which is what makes a disagreement evidence
/// rather than noise -- and the operator's next move depends on the direction: a count ahead of the
/// map is names lost, a map ahead of the count is names never counted.

/// **What the refusal must NOT claim.** Both numbers are decoded from the same account snapshot by
/// the same client, so a disagreement is not evidence about the CONTRACT specifically: this client
/// is equally a candidate, and it has a known way to produce one -- the `dedup()` in
/// `registry::model_registry_names_from_storage_fields` shortens the list if a duplicate value ever
/// reaches it. Naming a cause that has not been isolated is the defect is about, so
/// the refusal states the disagreement and where to look, and stops there.
fn agreed_export<'a>(
    network: &'a str,
    registry: &'a str,
    count: u32,
    models: &'a [String],
) -> Result<ModelRegistryExport<'a>> {
    if usize::try_from(count)
        .map(|stated| stated != models.len())
        .unwrap_or(true)
    {
        bail!(
            "the model registry {registry} on {network} answered two different numbers about \
             itself: count() says {count}, and the stored map decoded to {} name(s). Nothing was \
             written. Read the account to see which is right -- both numbers came from the same \
             snapshot, so this says the pair disagrees, not which half is at fault.",
            models.len(),
        );
    }
    Ok(ModelRegistryExport {
        schema: crate::cli::machine::MODEL_REGISTRY_SCHEMA,
        network,
        registry,
        count,
        models,
    })
}

/// Write the export so a reader never sees half of it.

/// Temporary file beside the target, then rename -- the idiom this tree already uses for state it
/// cannot afford to truncate (`cli::note`, `cli::deals`, `seller::mod`). `fs::write` is fine for a
/// small manifest a command owns; this is a 320 KB document the operator diffs against yesterday's,
/// and an interrupted write leaves a shorter one that reads as "the registry shrank".
fn write_atomically(path: &std::path::Path, contents: &str) -> Result<()> {
    use anyhow::Context as _;

    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let partial = format!(".{name}.partial");
    let temporary = match path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(directory) => directory.join(partial),
        None => std::path::PathBuf::from(partial),
    };
    std::fs::write(&temporary, contents)
        .with_context(|| format!("write {}", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("put {} in place as {}", temporary.display(), path.display()))
}

pub(crate) async fn run_model_registry(args: ModelRegistryArgs) -> Result<()> {
    use anyhow::Context as _;
    use dexdo::registry::ModelRegistryReader as _;

    let manifest_path = crate::cli::commands::manifest_path()?;
    let registry_address = match args.registry.model_registry_address.as_deref() {
        Some(named) => named.to_string(),
        None => dexdo::registry::default_model_registry_address(&manifest_path)?,
    };
    let backend = dexdo_core::RealChainBackend::connect(&manifest_path)
        .with_context(|| format!("connect using {}", manifest_path.display()))?;
    let network = backend.network().to_string();

    let reader = dexdo::registry::ChainModelRegistryReader::from_manifest(
        &manifest_path,
        &registry_address,
    )?;
    // Bounded together, not one after the other: both answers come from a single account
    // snapshot, so the pair is one chain operation, and a bound on half of it would leave the other
    // half open for as long as the node felt like it.
    let (models, count) = crate::cli::commands::direct_chain_read_with_timeout(
        args.read_timeout.read_timeout_secs,
        async {
            let models = reader
                .registered_model_names()
                .await
                .with_context(|| format!("read the model registry {registry_address}"))?;
            let count = reader.declared_model_count().await?;
            Ok::<_, anyhow::Error>((models, count))
        },
    )
    .await?;

    let export = agreed_export(&network, &registry_address, count, &models)?;

    if let Some(path) = args.output.as_deref() {
        // Pretty, with a trailing newline: the file is read by a person with `less` and by `jq`
        // alike, and a ten-thousand-name array on one line serves neither.
        let mut json = serde_json::to_string_pretty(&export)?;
        json.push('\n');
        write_atomically(path, &json)?;
    }

    if args.json {
        crate::cli::machine::print_json(&export)?;
        return Ok(());
    }

    println!("model registry {registry_address} on {network}: {count} model(s)");
    match args.output.as_deref() {
        Some(path) => println!("written -> {}", path.display()),
        None => println!(
            "nothing was written: pass --output <file> to keep the list, or --json to print it"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGISTRY: &str = "0:0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d";

    /// The agreeing case, and it is asserted for the same reason as the refusing one: a guard
    /// proven only where it refuses is a guard that might refuse everything.
    #[test]
    fn a_registry_that_agrees_with_itself_is_exported_whole() {
        let models = vec!["a-model".to_string(), "b-model".to_string()];
        let export = agreed_export("net-a", REGISTRY, 2, &models).expect("two names, count two");

        let value = serde_json::to_value(&export).expect("the export serialises");
        assert_eq!(value["schema"], crate::cli::machine::MODEL_REGISTRY_SCHEMA);
        assert_eq!(value["network"], "net-a");
        assert_eq!(value["registry"], REGISTRY);
        assert_eq!(value["count"], 2);
        assert_eq!(value["models"], serde_json::json!(["a-model", "b-model"]));
    }

    /// BOTH directions, because a comparison written the wrong way round still refuses one of them.

    /// The refusal carries both numbers: the operator's next move depends on which is larger -- a
    /// count ahead of the map is names lost, a map ahead of the count is names never counted.
    #[test]
    fn either_number_running_ahead_of_the_other_is_refused_and_both_are_named() {
        let one = vec!["a-model".to_string()];
        let three = vec![
            "a-model".to_string(),
            "b-model".to_string(),
            "c-model".to_string(),
        ];

        for (count, models, stated, decoded) in [
            (7_u32, &one, "count() says 7", "decoded to 1 name"),
            (1, &three, "count() says 1", "decoded to 3 name"),
        ] {
            let refusal = agreed_export("net-a", REGISTRY, count, models)
                .expect_err("a disagreeing pair must refuse")
                .to_string();
            assert!(refusal.contains(stated), "{refusal}");
            assert!(refusal.contains(decoded), "{refusal}");
            assert!(refusal.contains(REGISTRY), "{refusal}");
            assert!(refusal.contains("Nothing was written"), "{refusal}");
        }
    }

    /// The refusal must not name a culprit it cannot isolate (679).

    /// Both numbers come from one snapshot decoded by one client, and this client has a way to
    /// shorten the list on its own -- so "the contract lost track of itself" would be an assertion
    /// about a half that was never separated from the other.
    #[test]
    fn the_refusal_names_the_disagreement_and_not_a_culprit() {
        let refusal = agreed_export("net-a", REGISTRY, 7, &["a-model".to_string()])
            .expect_err("a disagreeing pair must refuse")
            .to_string();
        assert!(
            !refusal.contains("wrong at the contract"),
            "the refusal blames the contract for a disagreement it did not isolate: {refusal}"
        );
        assert!(refusal.contains("same snapshot"), "{refusal}");
    }

    /// An empty registry is a fact, not a failure: nothing has been seeded yet, and `0 == 0` holds.

    /// Safe only because an unreadable map is an ERROR rather than an empty list -- see
    /// `registry::model_registry_names_from_storage_fields`. Were it to return empty on failure,
    /// this very test would be the hole: `0 == 0` would approve a registry nobody managed to read.
    #[test]
    fn an_empty_registry_is_a_fact_and_not_a_disagreement() {
        let none: Vec<String> = Vec::new();
        let export = agreed_export("net-a", REGISTRY, 0, &none).expect("zero against zero");
        assert_eq!(export.count, 0);
        assert!(export.models.is_empty());
    }

    /// The write happens AFTER the guard, and that ordering is the whole of "Nothing was written".

    /// Asserted against this file's own source, because the run path needs a chain: an edit that
    /// moved `write_atomically` above `agreed_export` would leave every other test here green while
    /// the refusal started lying.

    /// Both markers are searched for AFTER the run function's signature, and the tests below use
    /// `agreed_export` too -- they sit later in the file, so the first occurrence past the
    /// signature is the one in the run path. No brace matching, and so nothing to get wrong.
    #[test]
    fn nothing_is_written_before_the_two_numbers_agree() {
        let source = include_str!("model_registry.rs");
        let run = source
            .find("pub(crate) async fn run_model_registry(args: ModelRegistryArgs)")
            .expect("the chain-capable run path is still declared here");
        let body = &source[run..];

        let guard = body
            .find("agreed_export(")
            .expect("the run path still settles the two numbers before anything else");
        let write = body
            .find("write_atomically(")
            .expect("the run path still writes the export through the atomic helper");
        assert!(
            guard < write,
            "the export is written at byte {write} of the run path and the guard is at {guard}: \
             a refusal that says \"Nothing was written\" would be false"
        );
    }
}
