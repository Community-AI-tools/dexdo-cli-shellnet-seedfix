//! `dexdo oracle` command handlers(provision/state/resolve), extracted from `commands.rs`
//! (move-only / behavior-identical, anti-entropy refactor Track C1).

use crate::cli::args::OracleArgs;
use anyhow::{bail, Result};

#[cfg(feature = "shellnet")]
use crate::cli::args::{OracleCommand, OracleProvisionArgs, OracleResolveArgs, OracleStateArgs};
#[cfg(feature = "shellnet")]
use crate::cli::commands::{now_unix_secs, shellnet_doctor_preflight};
#[cfg(feature = "shellnet")]
use crate::cli::support::{load_market, read_secret_hex};

#[cfg(feature = "shellnet")]
const ORACLE_MIN_RESULT_GAP_SECS: u64 = 120;

#[cfg(feature = "shellnet")]
fn load_oracle_market_manifest(path: &std::path::Path) -> Result<dexdo_core::OracleMarketManifest> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read --manifest {}: {e}", path.display()))?;
    let manifest = dexdo_core::OracleMarketManifest::from_json(&json)
        .map_err(|e| anyhow::anyhow!("parse --manifest {}: {e}", path.display()))?;
    manifest
        .validate()
        .map_err(|e| anyhow::anyhow!("--manifest {}: {e}", path.display()))?;
    Ok(manifest)
}

#[cfg(feature = "shellnet")]
fn pmp_resolved_outcome(details: &serde_json::Value) -> Option<String> {
    let v = &details["resolvedOutcome"];
    if v.is_null() {
        return None;
    }
    v.as_str()
        .map(str::to_string)
        .or_else(|| v.as_u64().map(|n| n.to_string()))
        .or_else(|| {
            v.as_object()
                .and_then(|o| o.get("value").or_else(|| o.get("0")))
                .and_then(|x| {
                    x.as_str()
                        .map(str::to_string)
                        .or_else(|| x.as_u64().map(|n| n.to_string()))
                })
        })
}

#[cfg(feature = "shellnet")]
fn validate_oracle_deadline(deadline: u64, now: u64) -> Result<()> {
    let min_deadline = now.saturating_add(ORACLE_MIN_RESULT_GAP_SECS);
    if deadline < min_deadline {
        bail!(
            "oracle provision: --deadline {deadline} must be at least {ORACLE_MIN_RESULT_GAP_SECS}s \
             in the future for OracleEventList.addRangeEvent (now={now}, min={min_deadline})"
        );
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
pub(crate) async fn run_oracle(args: OracleArgs) -> Result<()> {
    match args.command {
        OracleCommand::Provision(p) => run_oracle_provision(*p).await,
        OracleCommand::State(s) => run_oracle_state(s).await,
        OracleCommand::Resolve(r) => run_oracle_resolve(r).await,
        OracleCommand::Cancel(c) => run_oracle_cancel(c).await,
        OracleCommand::Delete(d) => run_oracle_delete(d).await,
    }
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_oracle(_args: OracleArgs) -> Result<()> {
    bail!("oracle unavailable: build with `--features shellnet`")
}

#[cfg(feature = "shellnet")]
async fn run_oracle_provision(args: OracleProvisionArgs) -> Result<()> {
    use dexdo_core::{Address, KeyPair, RealChainBackend};
    if args.outcome_names.len() != args.bounds.len() + 1 {
        bail!(
            "oracle provision: pass exactly bounds.len()+1 --outcome values (got {}, expected {})",
            args.outcome_names.len(),
            args.bounds.len() + 1
        );
    }
    if args.initial_stakes.len() != args.outcome_names.len() {
        bail!(
            "oracle provision: pass exactly one --initial-stake per outcome (got {}, expected {})",
            args.initial_stakes.len(),
            args.outcome_names.len()
        );
    }
    validate_oracle_deadline(args.deadline, now_unix_secs()?)?;
    shellnet_doctor_preflight(&args.contracts, Some(args.market.as_path())).await?;

    let note_addr = args.identity.note_addr.clone().ok_or_else(|| {
        anyhow::anyhow!("oracle provision: --note-addr (PMP deployer PrivateNote) is required")
    })?;
    let note_key = args.identity.note_key.as_deref().ok_or_else(|| {
        anyhow::anyhow!("oracle provision: --note-key (PMP deployer note owner key) is required")
    })?;
    let contracts = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let market = load_market(&args.market)?;
    let note_seed = read_secret_hex(note_key, "--note-key")?;
    let oracle_seed = read_secret_hex(&args.oracle_key, "--oracle-key")?;
    let note_keys = KeyPair::from_secret_hex(note_seed.trim())
        .map_err(|e| anyhow::anyhow!("--note-key (SDK secret hex): {e:?}"))?;
    let oracle_keys = KeyPair::from_secret_hex(oracle_seed.trim())
        .map_err(|e| anyhow::anyhow!("--oracle-key (SDK secret hex): {e:?}"))?;
    let note =
        Address::parse(&note_addr).map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
    let chain = RealChainBackend::connect(contracts)?;
    let manifest = chain
        .provision_oracle_market(
            &note_keys,
            &note,
            &oracle_keys,
            &args.oracle_name,
            args.event_list_index,
            &args.event_list_description,
            &args.event_name,
            args.oracle_fee,
            args.deadline,
            &args.describe,
            &args.bounds,
            &args.outcome_names,
            &market,
            args.token_type,
            &args.initial_stakes,
        )
        .await?;
    let json = manifest.to_json()?;
    std::fs::write(&args.output, &json)
        .map_err(|e| anyhow::anyhow!("write --output {}: {e}", args.output.display()))?;
    println!("oracle market provisioned -> {}", args.output.display());
    println!("{json}");
    Ok(())
}

#[cfg(feature = "shellnet")]
async fn run_oracle_state(args: OracleStateArgs) -> Result<()> {
    use dexdo_core::{Address, RealChainBackend};
    shellnet_doctor_preflight(&args.contracts, None).await?;
    let manifest = load_oracle_market_manifest(&args.manifest)?;
    let contracts = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let chain = RealChainBackend::connect(contracts)?;
    let oel = Address::parse(&manifest.oracle_event_list)
        .map_err(|e| anyhow::anyhow!("oracle_event_list {}: {e}", manifest.oracle_event_list))?;
    let pmp =
        Address::parse(&manifest.pmp).map_err(|e| anyhow::anyhow!("pmp {}: {e}", manifest.pmp))?;
    let range = chain.oracle_range_data(&oel, &manifest.event_id).await?;
    let details = chain.pmp_details(&pmp).await?;
    let pmp_ob = chain.pmp_order_book_address(&pmp).await?;
    println!(
        "oracle_state event={} pmp={} token_type={} deadline={} frame_model={} inference_ob={}",
        manifest.event_id,
        manifest.pmp,
        manifest.token_type,
        manifest.deadline,
        manifest.frame_model,
        manifest.inference_order_book
    );
    match range {
        Some(r) => println!("range_data={}", serde_json::to_string(&r)?),
        None => println!("range_data=<inactive-or-missing>"),
    }
    match details {
        Some(d) => {
            let resolved = pmp_resolved_outcome(&d).unwrap_or_else(|| "none".to_string());
            println!(
                "pmp_details approved={} approved_oracles={}/{} resolved_outcome={} raw={}",
                d["approved"].as_bool().unwrap_or(false),
                d["approvedOracleEvents"].as_str().unwrap_or("0"),
                d["numberOfOracleEvents"].as_str().unwrap_or("0"),
                resolved,
                serde_json::to_string(&d)?
            );
        }
        None => println!("pmp_details=<inactive-or-missing>"),
    }
    if let Some(ob) = pmp_ob {
        println!("pmp_order_book={}", ob.with_workchain());
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
async fn run_oracle_resolve(args: OracleResolveArgs) -> Result<()> {
    use dexdo_core::{Address, KeyPair, RealChainBackend};
    let manifest = load_oracle_market_manifest(&args.manifest)?;
    let now = now_unix_secs()?;
    if now < manifest.deadline {
        bail!(
            "oracle resolve: deadline not reached (deadline={}, now={now})",
            manifest.deadline
        );
    }
    shellnet_doctor_preflight(&args.contracts, None).await?;
    let contracts = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let chain = RealChainBackend::connect(contracts)?;
    let oel = Address::parse(&manifest.oracle_event_list)
        .map_err(|e| anyhow::anyhow!("oracle_event_list {}: {e}", manifest.oracle_event_list))?;
    let pmp =
        Address::parse(&manifest.pmp).map_err(|e| anyhow::anyhow!("pmp {}: {e}", manifest.pmp))?;
    let oracle_seed = read_secret_hex(&args.oracle_key, "--oracle-key")?;
    let oracle_keys = KeyPair::from_secret_hex(oracle_seed.trim())
        .map_err(|e| anyhow::anyhow!("--oracle-key (SDK secret hex): {e:?}"))?;
    chain
        .resolve_oracle_range(
            &oel,
            &oracle_keys,
            &manifest.event_id,
            &manifest.oracle_list_hash,
            manifest.token_type,
        )
        .await?;
    println!(
        "resolveRange submitted event={} oracle_list_hash={} pmp={}",
        manifest.event_id, manifest.oracle_list_hash, manifest.pmp
    );
    let mut last_details_error = None;
    for i in 0..60 {
        match chain.pmp_details(&pmp).await {
            Ok(Some(details)) => {
                if let Some(outcome) = pmp_resolved_outcome(&details) {
                    println!(
                        "pmp resolved event={} outcome={} pmp={}",
                        manifest.event_id, outcome, manifest.pmp
                    );
                    return Ok(());
                }
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("pmp details poll failed (will retry): {e}");
                last_details_error = Some(e.to_string());
            }
        }
        if i + 1 < 60 {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    }
    let last_details_error = last_details_error
        .map(|e| format!(" Last transient pmp_details error while polling: {e}."))
        .unwrap_or_default();
    bail!(
        "resolveRange was submitted but PMP {} did not expose resolvedOutcome within 180s. \
         If the bound InferenceOrderBook has no MIN_LIQUIDITY, requestWeeklyMedian reverts under bounce:false \
         and onWeeklyMedian never arrives; this is the  no-liquidity stuck case, not a CLI success.{}",
        manifest.pmp,
        last_details_error
    )
}

#[cfg(feature = "shellnet")]
fn oracle_u128(value: &serde_json::Value, field: &str) -> Option<u128> {
    value[field].as_u64().map(u128::from).or_else(|| {
        value[field]
            .as_str()
            .and_then(|raw| raw.parse::<u128>().ok())
    })
}

#[cfg(feature = "shellnet")]
fn validate_oracle_cancel_preflight(
    before_pmp: &serde_json::Value,
    before_event: &serde_json::Value,
) -> Result<u128> {
    if before_pmp["approved"].as_bool() != Some(true) {
        bail!("oracle cancel: PMP is not approved");
    }
    if before_pmp["isCancelled"].as_bool() == Some(true) {
        bail!("oracle cancel: PMP is already cancelled");
    }
    if pmp_resolved_outcome(before_pmp).is_some() {
        bail!("oracle cancel: PMP is already resolved");
    }
    let before_count = oracle_u128(before_event, "count")
        .ok_or_else(|| anyhow::anyhow!("oracle cancel: event getter exposes no count"))?;
    if before_count == 0 {
        bail!("oracle cancel: event confirmation count is already zero");
    }
    Ok(before_count)
}

#[cfg(feature = "shellnet")]
fn validate_oracle_cancel_postread(
    before_count: u128,
    after_pmp: Option<&serde_json::Value>,
    after_event: Option<&serde_json::Value>,
    exact_confirmation_active: bool,
) -> Result<(bool, Option<u128>)> {
    let (Some(after_pmp), Some(after_event)) = (after_pmp, after_event) else {
        return Ok((false, None));
    };
    let cancelled = after_pmp["isCancelled"]
        .as_bool()
        .ok_or_else(|| anyhow::anyhow!("oracle cancel: post-read exposes no isCancelled"))?;
    if !cancelled && pmp_resolved_outcome(after_pmp).is_some() {
        bail!("oracle cancel: contradictory post-read reports a resolved PMP");
    }
    let after_count = oracle_u128(after_event, "count")
        .ok_or_else(|| anyhow::anyhow!("oracle cancel: post-read exposes no event count"))?;
    let expected = before_count
        .checked_sub(1)
        .ok_or_else(|| anyhow::anyhow!("oracle cancel: pre-read count was already zero"))?;
    if !(expected..=before_count).contains(&after_count) {
        bail!(
            "oracle cancel: contradictory post-read confirmation count {after_count}; expected {expected}..={before_count}"
        );
    }
    Ok((
        cancelled && after_count == expected && !exact_confirmation_active,
        Some(after_count),
    ))
}

#[cfg(feature = "shellnet")]
fn validate_oracle_delete_preflight(event: &serde_json::Value, now: u64) -> Result<()> {
    let count = oracle_u128(event, "count")
        .ok_or_else(|| anyhow::anyhow!("oracle delete: event getter exposes no count"))?;
    if count != 0 {
        bail!("oracle delete: event still has {count} active PMP confirmation(s)");
    }
    let deadline = oracle_u128(event, "deadline")
        .ok_or_else(|| anyhow::anyhow!("oracle delete: event getter exposes no deadline"))?;
    if deadline >= u128::from(now) {
        bail!("oracle delete: deadline not passed (deadline={deadline}, now={now})");
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
fn validate_oracle_delete_postread(
    before_event: &serde_json::Value,
    after_event: Option<&serde_json::Value>,
) -> Result<bool> {
    let Some(after_event) = after_event else {
        return Ok(true);
    };
    if oracle_u128(after_event, "count") != Some(0)
        || oracle_u128(after_event, "deadline") != oracle_u128(before_event, "deadline")
    {
        bail!("oracle delete: contradictory post-read event state");
    }
    Ok(false)
}

#[cfg(feature = "shellnet")]
async fn submit_oracle_cancel_after_validation(
    preflight: Result<u128>,
    submit: impl std::future::Future<Output = Result<serde_json::Value>>,
) -> Result<u128> {
    let before_count = preflight?;
    submit.await?;
    Ok(before_count)
}

#[cfg(feature = "shellnet")]
async fn submit_oracle_delete_after_validation(
    preflight: Result<()>,
    submit: impl std::future::Future<Output = Result<serde_json::Value>>,
) -> Result<()> {
    preflight?;
    submit.await?;
    Ok(())
}

#[cfg(feature = "shellnet")]
fn load_oracle_signer(path: &std::path::Path) -> Result<dexdo_core::KeyPair> {
    let secret = read_secret_hex(path, "--oracle-key")?;
    dexdo_core::KeyPair::from_secret_hex(secret.trim())
        .map_err(|e| anyhow::anyhow!("--oracle-key (SDK secret hex): {e:?}"))
}

#[cfg(feature = "shellnet")]
async fn run_oracle_cancel(args: OracleResolveArgs) -> Result<()> {
    let manifest = load_oracle_market_manifest(&args.manifest)?;
    shellnet_doctor_preflight(&args.contracts, None).await?;
    let chain = dexdo_core::RealChainBackend::connect(
        args.contracts
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?,
    )?;
    let signer = load_oracle_signer(&args.oracle_key)?;
    let (oel, pmp, before_pmp, before_event) = chain
        .assert_oracle_market_identity(&manifest, &signer)
        .await?;
    let before_count = submit_oracle_cancel_after_validation(
        validate_oracle_cancel_preflight(&before_pmp, &before_event),
        chain.submit_pmp_cancel_event(&pmp, &signer),
    )
    .await?;
    let after_pmp = chain.pmp_details(&pmp).await?;
    let after_event = chain.oracle_event_info(&oel, &manifest.event_id).await?;
    let exact_confirmation_active = chain
        .oracle_event_list_has_pmp_confirmation(&oel, &pmp, &manifest.event_id)
        .await?;
    let (confirmed, after_count) = validate_oracle_cancel_postread(
        before_count,
        after_pmp.as_ref(),
        after_event.as_ref(),
        exact_confirmation_active,
    )?;
    let cancelled = after_pmp
        .as_ref()
        .and_then(|details| details["isCancelled"].as_bool())
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unavailable".to_string());
    let after_count = after_count
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unavailable".to_string());
    println!(
        "oracle cancel submitted event={} pmp={} post_read_is_cancelled={} confirmations={before_count}->{after_count} exact_confirmation_active={exact_confirmation_active} status={}",
        manifest.event_id,
        manifest.pmp,
        cancelled,
        if confirmed { "confirmed" } else { "pending" }
    );
    Ok(())
}

#[cfg(feature = "shellnet")]
async fn run_oracle_delete(args: OracleResolveArgs) -> Result<()> {
    let manifest = load_oracle_market_manifest(&args.manifest)?;
    shellnet_doctor_preflight(&args.contracts, None).await?;
    let chain = dexdo_core::RealChainBackend::connect(
        args.contracts
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?,
    )?;
    let signer = load_oracle_signer(&args.oracle_key)?;
    let (oel, event) = chain
        .assert_oracle_event_identity(&manifest, &signer)
        .await?;
    submit_oracle_delete_after_validation(
        validate_oracle_delete_preflight(&event, chain.observed_chain_timestamp().await?),
        chain.delete_oracle_event(&oel, &signer, &manifest.event_id),
    )
    .await?;
    let after_event = chain.oracle_event_info(&oel, &manifest.event_id).await?;
    let confirmed = validate_oracle_delete_postread(&event, after_event.as_ref())?;
    println!(
        "oracle delete submitted event={} oracle_event_list={} post_read_exists={} status={}",
        manifest.event_id,
        manifest.oracle_event_list,
        after_event.is_some(),
        if confirmed { "confirmed" } else { "pending" }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "shellnet")]
    #[test]
    fn oracle_deadline_enforces_contract_result_gap() {
        let now = 1_900_000_000;
        assert!(super::validate_oracle_deadline(now + 119, now).is_err());
        assert!(super::validate_oracle_deadline(now + 120, now).is_ok());
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn oracle_cancel_validation_checks_direct_pre_and_post_reads() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let before_pmp =
            serde_json::json!({"approved": true, "isCancelled": false, "resolvedOutcome": null});
        let after_pmp =
            serde_json::json!({"approved": true, "isCancelled": true, "resolvedOutcome": null});
        let before_event = serde_json::json!({"count": "2"});
        let after_event = serde_json::json!({"count": "1"});

        let before = super::validate_oracle_cancel_preflight(&before_pmp, &before_event).unwrap();
        let postread = |pmp, event, exact_active| {
            super::validate_oracle_cancel_postread(before, Some(pmp), Some(event), exact_active)
                .unwrap()
        };
        assert_eq!(before, 2);
        assert_eq!(postread(&after_pmp, &after_event, false), (true, Some(1)));
        assert_eq!(postread(&before_pmp, &before_event, true), (false, Some(2)));
        assert_eq!(
            postread(&after_pmp, &after_event, true),
            (false, Some(1)),
            "an unrelated decrement must not confirm this PMP while its exact OEL entry remains"
        );

        assert!(super::validate_oracle_cancel_preflight(
            &serde_json::json!({"approved": true, "isCancelled": true, "resolvedOutcome": null}),
            &before_event
        )
        .is_err());
        assert!(super::validate_oracle_cancel_preflight(
            &before_pmp,
            &serde_json::json!({"count": "0"})
        )
        .is_err());
        assert!(super::validate_oracle_cancel_postread(
            before,
            Some(&serde_json::json!({
                "approved": true,
                "isCancelled": false,
                "resolvedOutcome": "1"
            })),
            Some(&before_event),
            true
        )
        .is_err());
        let cancel_posts = AtomicUsize::new(0);
        let cancel_post = || async {
            cancel_posts.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({}))
        };
        assert!(super::submit_oracle_cancel_after_validation(
            super::validate_oracle_cancel_preflight(
                &before_pmp,
                &serde_json::json!({"count": "0"}),
            ),
            cancel_post(),
        )
        .await
        .is_err());
        assert_eq!(cancel_posts.load(Ordering::SeqCst), 0);

        let count = super::submit_oracle_cancel_after_validation(
            super::validate_oracle_cancel_preflight(&before_pmp, &before_event),
            cancel_post(),
        )
        .await
        .unwrap();
        assert_eq!(cancel_posts.load(Ordering::SeqCst), 1);
        assert_eq!(count, 2);
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn oracle_delete_validation_requires_zero_count_deadline_and_absence() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let deletable = serde_json::json!({"count": "0", "deadline": "1000"});
        assert!(super::validate_oracle_delete_preflight(&deletable, 1_001).is_ok());
        assert!(super::validate_oracle_delete_preflight(&deletable, 1_000).is_err());
        assert!(super::validate_oracle_delete_preflight(
            &serde_json::json!({"count": "1", "deadline": "1000"}),
            1_001
        )
        .is_err());
        assert!(super::validate_oracle_delete_postread(&deletable, None).unwrap());
        assert!(!super::validate_oracle_delete_postread(&deletable, Some(&deletable)).unwrap());
        assert!(super::validate_oracle_delete_postread(
            &deletable,
            Some(&serde_json::json!({"count": "1", "deadline": "1000"}))
        )
        .is_err());

        let delete_posts = AtomicUsize::new(0);
        let delete_post = || async {
            delete_posts.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({}))
        };
        assert!(super::submit_oracle_delete_after_validation(
            super::validate_oracle_delete_preflight(&deletable, 1_000),
            delete_post(),
        )
        .await
        .is_err());
        assert_eq!(delete_posts.load(Ordering::SeqCst), 0);

        super::submit_oracle_delete_after_validation(
            super::validate_oracle_delete_preflight(&deletable, 1_001),
            delete_post(),
        )
        .await
        .unwrap();
        assert_eq!(delete_posts.load(Ordering::SeqCst), 1);
    }
}
