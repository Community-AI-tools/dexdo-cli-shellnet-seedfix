//! Market/pool lifecycle administration command handlers.

use crate::cli::args::{DestroyArgs, MarketDeployArgs, ProvisionArgs};
#[cfg(feature = "shellnet")]
use crate::cli::commands::{
    enforce_model_registry_policy, enforce_model_registry_policy_with_endpoint,
    load_enabled_model_registry_policy, order_book_active,
    preload_default_model_registry_with_endpoint, preload_model_registry_policy,
    preload_model_registry_policy_with_endpoint, resolve_model_registry_target,
    resolve_model_registry_target_with_endpoint, resolve_registry_content_identity,
    shellnet_doctor_preflight, BookTarget,
};
use crate::cli::policy;
#[cfg(feature = "shellnet")]
use crate::cli::support::{
    default_deposit_shells, deposit_per_deploy, deposit_per_deploy_with_overhead,
    ensure_provision_deposit_covered, prompt_deposit_shells, read_secret_hex,
    require_provision_nonce, resolve_market_fields, validate_price_step, SHELL_UNIT,
};
#[cfg(not(feature = "shellnet"))]
use anyhow::bail;
use anyhow::Result;
#[cfg(feature = "shellnet")]
use dexdo::registry::{BuyerMissingBookPolicy, RegistryRole};
#[cfg(feature = "shellnet")]
use dexdo_core::params::{
    MARKET_DEPLOY_ACTIVATION_MAX_READS, MARKET_DEPLOY_ACTIVATION_POLL_INTERVAL,
};

/// refuse a provision whose model name the buyer's registry lookup would reject.
/// The market a provision brings up is only useful if a buyer can find it, and the buyer finds it by
/// resolving the model name in the ModelRegistry. When that resolution fails the buyer refuses --
/// fail-closed and correct -- but by then the seller has already paid for an order book, a RootModel
/// and a TokenContract that will sit there and never trade.
/// So the answer is taken here, from the same resolver, before the first deploy. The error the
/// operator sees is the resolver's own, which is the buyer's: the same candidate list, the same
/// registry address, so a typo in `--frame-model` is distinguishable from a correct name at the
/// moment it is cheap to fix.
/// `--allow-unverified-model` is the opt-out, and it is deliberately the buyer's flag rather than a
/// new one: the defect reports is that one identity rule had two different defaults on its two
/// sides. Matching the buyer means matching its default AND its escape hatch.
#[cfg(feature = "shellnet")]
async fn ensure_provision_model_resolves(
    contracts: &std::path::Path,
    endpoint: Option<&str>,
    requested_model: &str,
    allow_unverified_model: bool,
) -> Result<()> {
    let resolved =
        resolve_registry_content_identity(
            RegistryRole::Seller,
            contracts,
            endpoint,
            requested_model,
        )
        .await;
    provision_model_resolution_result(requested_model, allow_unverified_model, resolved).map(drop)
}

/// The decision the resolution feeds, split out so it is exercised without a node -- the shape
/// `cli::buyer` uses for the same call.
#[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
fn provision_model_resolution_result(
    requested_model: &str,
    allow_unverified_model: bool,
    resolved: Result<String>,
) -> Result<Option<String>> {
    match resolved {
        Ok(registry_model) => Ok(Some(registry_model)),
        Err(error) if allow_unverified_model => {
            tracing::warn!(
                frame_model = %requested_model,
                error = %error,
                "provision: model name does not resolve in the ModelRegistry; deploying anyway \
                 because --allow-unverified-model was set. No buyer whose content-identity check is \
                 on can resolve this market"
            );
            Ok(None)
        }
        Err(error) => Err(error.context(format!(
            "provision refuses before deploying anything for `{requested_model}`: this is the \
             resolution every buyer performs, so a market provisioned under this name could not be \
             bought and the order book, RootModel and TokenContract would be paid for and never \
             trade. Fix the --frame-model name, or pass --allow-unverified-model to provision it \
             anyway"
        ))),
    }
}

/// Provision a per-deal market: the seller note brings up the
/// `InferenceOrderBook`(`deployInferenceOrderBook`), asks `SuperRoot` for the `RootModel`
/// (`deployRootModel` -- SuperRoot deploys it and carries its own value), and pre-funds + deploys the
/// per-deal `TokenContract` from its own ECC[2](`fundDeployShell` -> external seller-signed deploy),
/// **no operator multisig and no giver in the operate path** (giver is the one-time mint faucet only,
/// ). Emits a `MarketManifest` whose `token_contract` is the deployed, active address.
#[cfg(feature = "shellnet")]
pub(crate) async fn run_provision(args: ProvisionArgs) -> Result<()> {
    run_provision_with_deal_gas_overhead(args, None).await
}

#[cfg(feature = "shellnet")]
pub(crate) async fn run_provision_with_deal_gas_overhead(
    args: ProvisionArgs,
    supplied_deal_gas_overhead_raw: Option<u128>,
) -> Result<()> {
    use dexdo_core::{KeyPair, RealChainBackend};
    // A3: reject an invalid limit price at the command boundary, before any key/file/network read or write.
    validate_price_step(args.price_per_tick)?;
    policy::load_seller_runtime_policy(args.policy.as_deref())?;
    let note_addr = args.identity.note_addr.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "real shellnet provisioning: --note-addr (provisioned note address) is required"
        )
    })?;
    let note_key = args.identity.note_key.as_deref().ok_or_else(|| {
        anyhow::anyhow!("real shellnet provisioning: --note-key (note seed) is required")
    })?;
    let manifest = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let registry_policy =
        load_enabled_model_registry_policy(RegistryRole::Seller, &args.registry, &args.contracts)?;
    let requested_model = args.frame_model.clone();
    if registry_policy.is_none() {
        dexdo_core::validate_canonical_model_id(&requested_model)
            .map_err(|e| anyhow::anyhow!(e))?;
    }
    // Prime the buyer-equivalent content registry now; its existing strict/opt-out decision below
    // still owns how a cached read failure is reported.
    let _ = preload_default_model_registry_with_endpoint(
        &args.contracts,
        args.endpoint.as_deref(),
    )
    .await;
    preload_model_registry_policy_with_endpoint(
        RegistryRole::Seller,
        registry_policy.as_ref(),
        &args.contracts,
        args.endpoint.as_deref(),
    )
    .await?;
    crate::cli::commands::shellnet_doctor_preflight_with_endpoint(
        &args.contracts,
        args.endpoint.as_deref(),
        None,
    )
    .await?;
    // ASK THE BUYER'S QUESTION, HERE, BEFORE ANYTHING IS SPENT.
    // Everything below this line costs money -- the order book, the RootModel and the per-deal
    // TokenContract are deployed and paid for out of the note. The buyer resolves the model name
    // against the ModelRegistry unconditionally and refuses when it does not resolve, so a name that
    // fails that resolution produces a complete market no buyer can ever reach: the operator finds
    // out only if someone happens to tell them, and the spend repeats per nonce.
    // The seller's own registry check exists, but it lives behind `--model-registry-validation` and
    // is off by default -- the guard was reachable and, on the default path, nothing called it. This
    // asks the SAME question the buyer asks, using the same resolver, and asks it first.
    ensure_provision_model_resolves(
        &args.contracts,
        args.endpoint.as_deref(),
        &requested_model,
        args.allow_unverified_model,
    )
    .await?;
    let target = resolve_model_registry_target_with_endpoint(
        RegistryRole::Seller,
        registry_policy.as_ref(),
        &args.contracts,
        args.endpoint.as_deref(),
        &requested_model,
        BookTarget {
            frame_model: requested_model.clone(),
            model_hash: dexdo_core::model_hash_for(&requested_model),
            order_book: None,
            root_model: None,
            note_addr: Some(note_addr.clone()),
        },
    )
    .await?;
    let frame_model = target.frame_model;
    let seed = read_secret_hex(note_key, "--note-key")?;
    let chain = RealChainBackend::connect_with_endpoint(manifest, args.endpoint.as_deref())?;
    let deal_gas_overhead_raw = dexdo_core::params::resolve_deal_gas_overhead_raw(
        chain.network(),
        supplied_deal_gas_overhead_raw,
    )
    .map_err(anyhow::Error::msg)?;
    let keys = KeyPair::from_secret_hex(seed.trim())
        .map_err(|e| anyhow::anyhow!("--note-key (SDK secret hex): {e:?}"))?;
    let note = dexdo_core::address::parse_chain_address(&note_addr)
        .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
    if let Some(policy) = registry_policy.as_ref() {
        let expected_order_book = chain
            .inference_orderbook_address(&note, &target.model_hash, dexdo_core::TICK_SIZE)
            .await?
            .with_workchain();
        let order_book_active = order_book_active(&chain, &expected_order_book).await?;
        enforce_model_registry_policy_with_endpoint(
            RegistryRole::Seller,
            policy,
            &args.contracts,
            args.endpoint.as_deref(),
            &frame_model,
            &expected_order_book,
            order_book_active,
            BuyerMissingBookPolicy::Reject,
        )
        .await?;
    }
    // REQUIRE an explicit, deal-unique nonce BEFORE any deposit/deploy -- the per-deal TokenContract derives
    // from(sellerPubkey, nonce); the old `--nonce 0` default silently reused(overwrote) a prior deal's TC.
    let nonce = require_provision_nonce(args.nonce)?;
    // the note deposit is a user-chosen provision parameter(default >=100 SHELL), framed by deal volume --
    // NOT a MIN_BALANCE-anchored per-op gas knob. 1 SHELL = 1e9 raw ECC[2]. The deposit is split across the
    // RootModel + per-deal `TokenContract` deploys, funded from the note's own ECC[2].
    // the deposit follows THIS deal. `max_ticks` is what sets it -- the deal's `TokenContract`
    // pays its own compute and `MAX_CLAIM_DELTA = TICK_SIZE` caps a claim at one tick, so a deal of
    // `max_ticks` ticks takes `max_ticks` claims and its lifetime gas is linear in them.
    let default_deposit_shells = if supplied_deal_gas_overhead_raw.is_none() {
        default_deposit_shells(args.max_ticks)
    } else {
        dexdo_core::params::min_deploy_shells_with_overhead(args.max_ticks, deal_gas_overhead_raw)
    };
    let deposit_shells = match args.deposit_shells {
        Some(n) => n,
        None => prompt_deposit_shells()?.unwrap_or(default_deposit_shells),
    };
    // Fail-closed: overflow and a below-floor deposit are explicit errors, not a silent clamp/warn.
    let per_deploy = if supplied_deal_gas_overhead_raw.is_none() {
        deposit_per_deploy(deposit_shells, args.max_ticks)?
    } else {
        deposit_per_deploy_with_overhead(
            deposit_shells,
            args.max_ticks,
            Some(deal_gas_overhead_raw),
        )?
    };
    eprintln!(
        "note deposit: {deposit_shells} SHELL ECC[2] (1 SHELL = 1e9 raw); ~{} SHELL for the per-deal TokenContract \
         deploy after fundDeployShell (the RootModel is deployed by SuperRoot and needs no note funding). This \
         {}-tick deal needs {} raw nanovmshell over its whole life, so its floor is {} SHELL. Unused deploy \
         remainder burns at destroy.",
        per_deploy / SHELL_UNIT,
        args.max_ticks,
        dexdo_core::params::deal_gas_requirement_raw_with_overhead(
            args.max_ticks,
            deal_gas_overhead_raw,
        ),
        dexdo_core::params::min_deploy_shells_with_overhead(
            args.max_ticks,
            deal_gas_overhead_raw,
        ),
    );
    // Run the stale/orphaned-note check BEFORE reading ECC balance. After a shellnet redeploy, old notes may be
    // absent/inactive/stale-code; reporting that as "0 SHELL" would mask the actionable re-mint reason.
    chain.assert_seller_note_current(&note).await?;
    // Fail-LOUD if the note's ECC[2] SHELL cannot cover the exact deploy deposit. Do not add guessed runtime
    // headroom here: section 6 requires any gas/SHELL threshold beyond the deploy amount to come from
    // contract constants/receipts, not a drifting reserve.
    let note_ecc = chain
        .client()
        .get_account(&note)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "seller note {} disappeared after current-note preflight",
                dexdo_core::address::display(&note.with_workchain())
            )
        })?
        .ecc_balance(2);
    let note_spendable = chain.private_note_shell_balance(&note).await?;
    ensure_provision_deposit_covered(
        note_ecc,
        note_spendable,
        deposit_shells,
        args.price_per_tick,
    )?;
    let m = if supplied_deal_gas_overhead_raw.is_none() {
        chain
            .provision_market(
                &keys,
                &note,
                &frame_model,
                nonce,
                args.price_per_tick,
                args.max_ticks,
                per_deploy,
            )
            .await?
    } else {
        chain
            .provision_market_with_deal_gas_overhead(
                &keys,
                &note,
                &frame_model,
                nonce,
                args.price_per_tick,
                args.max_ticks,
                per_deploy,
                deal_gas_overhead_raw,
            )
            .await?
    };
    let json = m.to_json()?;
    std::fs::write(&args.output, &json)
        .map_err(|e| anyhow::anyhow!("write --output {}: {e}", args.output.display()))?;
    println!("provisioned market -> {}", args.output.display());
    println!("{json}");
    Ok(())
}

#[cfg(all(test, feature = "shellnet"))]
mod tests {
    use super::*;
    use crate::cli::args::{IdentityArgs, ModelRegistryValidationArgs};

    /// - DISPATCH, not the guard.
    /// The resolver was never the problem: `resolve_registered_model_identity` has always been able
    /// to say that `qwen--qwen3.6--27b-e2check` resolves to nothing. The problem was that on the
    /// default seller path nothing asked it -- `resolve_model_registry_target` returns its target
    /// untouched when no `--model-registry-validation` config is given, so the seller reached
    /// `provision_market` having asked no question at all.
    /// So this reads the call order out of `run_provision` itself. A test that only exercised the
    /// decision function would have passed just as happily while the production path skipped it,
    /// which is precisely the failure being fixed.
    #[test]
    fn provision_asks_the_registry_before_it_spends_anything() {
        let source = include_str!("admin.rs");
        let body = source
            .split_once("fn run_provision_with_deal_gas_overhead")
            .expect("provision implementation present")
            .1
            .split_once("#[cfg(all(test, feature = \"shellnet\"))]")
            .expect("provision implementation ends before its tests")
            .0;
        let gate = body
            .find("ensure_provision_model_resolves(")
            .expect("provision must resolve the model name");
        for spend in [
            // the money: every deploy the provision pays for, and the note reads that precede them
            "provision_market(",
            "deposit_per_deploy(",
            "ensure_provision_deposit_covered(",
        ] {
            let at = body
                .find(spend)
                .unwrap_or_else(|| panic!("run_provision still calls {spend}"));
            assert!(
                gate < at,
                "`{spend}` runs at {at} but the registry resolution only at {gate};  is that a \
                 market is paid for before anyone asks whether a buyer could resolve its name"
            );
        }
    }

    #[test]
    fn provision_passes_explicit_endpoint_to_every_registry_read() {
        let source = include_str!("admin.rs");
        let body = source
            .split_once("fn run_provision_with_deal_gas_overhead")
            .expect("provision implementation present")
            .1
            .split_once("#[cfg(all(test, feature = \"shellnet\"))]")
            .expect("provision implementation ends before its tests")
            .0;

        for call in [
            "preload_default_model_registry_with_endpoint(",
            "preload_model_registry_policy_with_endpoint(",
            "ensure_provision_model_resolves(",
            "resolve_model_registry_target_with_endpoint(",
            "enforce_model_registry_policy_with_endpoint(",
        ] {
            let call = body
                .split_once(call)
                .unwrap_or_else(|| panic!("provision must call {call}"))
                .1;
            let arguments = &call[..call.len().min(400)];
            assert!(
                arguments.contains("args.endpoint.as_deref()"),
                "{call} must receive the explicit provision endpoint"
            );
        }
    }

    /// The refusal must be the buyer's answer, not a second opinion -- same resolver, so the operator
    /// reads the same candidate list at provision time that a buyer would read later.
    #[test]
    fn provision_refuses_an_unresolvable_name_and_names_the_cost() {
        let error = super::provision_model_resolution_result(
            "qwen--qwen3.6--27b-e2check",
            false,
            Err(anyhow::anyhow!(
                "buyer content identity registry check failed: claimed model \
                 qwen--qwen3.6--27b-e2check does not resolve to a registered ModelRegistry \
                 0:0d0d identity; tried [\"qwen--qwen3.6--27b-e2check\"]"
            )),
        )
        .expect_err("an unresolvable name must be refused, not warned about");
        let message = format!("{error:#}");
        assert!(message.contains("does not resolve"), "{message}");
        assert!(
            message.contains("refuses before deploying anything"),
            "the refusal must say it happened before the spend: {message}"
        );
        assert!(
            message.contains("--allow-unverified-model"),
            "an operator who means it needs to be told the opt-out: {message}"
        );
    }

    /// A resolvable name is unaffected, and the opt-out still works -- a gate that refused everything,
    /// or that could not be opted out of, would trade one broken default for another.
    #[test]
    fn a_resolvable_name_passes_and_the_opt_out_downgrades_to_a_warning() {
        let resolved = super::provision_model_resolution_result(
            "qwen--qwen3--32b",
            false,
            Ok("Qwen/Qwen3-32B".to_string()),
        )
        .expect("a resolvable name provisions");
        assert_eq!(resolved.as_deref(), Some("Qwen/Qwen3-32B"));

        let allowed = super::provision_model_resolution_result(
            "qwen--qwen3.6--27b-e2check",
            true,
            Err(anyhow::anyhow!("does not resolve")),
        )
        .expect("--allow-unverified-model provisions anyway");
        assert_eq!(allowed, None);
    }

    /// The resolved registry name is an ANSWER, not a rename. Substituting it would move the derived
    /// `model_hash` and the order book with it -- the canonicalisation question own -- so
    /// `run_provision` must keep deploying under the name the operator gave.
    #[test]
    fn provision_keeps_the_operator_s_name_after_resolving_it() {
        let source = include_str!("admin.rs");
        let body = source
            .split_once("fn run_provision_with_deal_gas_overhead")
            .expect("provision implementation present")
            .1
            .split_once("#[cfg(all(test, feature = \"shellnet\"))]")
            .expect("provision implementation ends before its tests")
            .0;
        let gate = body
            .find("ensure_provision_model_resolves(")
            .expect("resolution call present");
        let first_spend = body
            .find("deposit_per_deploy(")
            .expect("provision still computes its first spend");
        assert!(
            gate < first_spend,
            "the registry resolution must remain before the first spend"
        );
        let gate_line = body
            .lines()
            .find(|line| line.contains("ensure_provision_model_resolves("))
            .expect("resolution call present");
        assert!(
            !gate_line.contains('='),
            "the resolution is a gate, not an assignment: binding its result here is how a rename \
             sneaks in -- `{gate_line}`"
        );
    }

    #[tokio::test]
    async fn provision_rejects_bad_price_before_identity_or_network_side_effects() {
        let args = ProvisionArgs {
            identity: IdentityArgs {
                note_key: None,
                note_index: 0,
                note_addr: None,
            },
            registry: ModelRegistryValidationArgs::default(),
            frame_model: "not-even-a-canonical-model".to_string(),
            allow_unverified_model: false,
            contracts: "missing-contracts-manifest.json".into(),
            endpoint: None,
            nonce: None,
            price_per_tick: dexdo_core::PRICE_STEP - 1,
            max_ticks: 1,
            deposit_shells: None,
            output: "must-not-be-written.json".into(),
            policy: None,
        };

        let error = run_provision(args)
            .await
            .expect_err("invalid price must fail at the command boundary");
        let message = error.to_string();
        assert!(message.contains("PRICE_STEP"), "{message}");
        assert!(message.contains(&(dexdo_core::PRICE_STEP - 1).to_string()));
        assert!(!message.contains("--note-addr"), "{message}");
        assert!(!message.contains("missing-contracts-manifest"), "{message}");
    }
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_provision(args: ProvisionArgs) -> Result<()> {
    policy::load_seller_runtime_policy(args.policy.as_deref())?;
    bail!("real shellnet provisioning unavailable: build with `--features shellnet`")
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_provision_with_deal_gas_overhead(
    args: ProvisionArgs,
    _deal_gas_overhead_raw: Option<u128>,
) -> Result<()> {
    run_provision(args).await
}

/// `dexdo deploy-market`: deploy the per-model `InferenceOrderBook`(the shared market for a model) if it is
/// not yet on-chain -- note-funded, the explicit "list this model" step a seller runs before posting
/// offers. The book address is deterministic from `model_hash`, so this is idempotent (already-deployed ->
/// no-op). Same lazy deploy the seller's `post_offer` does, surfaced as a first-class operate command.
#[cfg(feature = "shellnet")]
pub(crate) async fn run_market_deploy(args: MarketDeployArgs) -> Result<()> {
    use dexdo_core::{model_hash_for, KeyPair, RealChainBackend, TICK_SIZE};
    let note_addr = args.identity.note_addr.clone().ok_or_else(|| {
        anyhow::anyhow!("real shellnet: --note-addr (active inference note) is required")
    })?;
    let note_key =
        args.identity.note_key.as_deref().ok_or_else(|| {
            anyhow::anyhow!("real shellnet: --note-key (note owner key) is required")
        })?;
    let manifest = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    // Fail-closed on a stale binary / live-network skew BEFORE the on-chain deploy -- same gate `provision`/
    // `seller` run. Without it, deploy-market would silently deploy an order book on outdated contract code
    // against a re-deployed network(a live run caught exactly this: live PrivateNote ahead of the binary pin).
    let registry_policy =
        load_enabled_model_registry_policy(RegistryRole::Seller, &args.registry, &args.contracts)?;
    let requested_model = args.frame_model.clone();
    if registry_policy.is_none() {
        dexdo_core::validate_canonical_model_id(&requested_model)
            .map_err(|e| anyhow::anyhow!(e))?;
    }
    preload_model_registry_policy(
        RegistryRole::Seller,
        registry_policy.as_ref(),
        &args.contracts,
    )
    .await?;
    shellnet_doctor_preflight(&args.contracts, None).await?;
    let target = resolve_model_registry_target(
        RegistryRole::Seller,
        registry_policy.as_ref(),
        &args.contracts,
        &requested_model,
        BookTarget {
            frame_model: requested_model.clone(),
            model_hash: model_hash_for(&requested_model),
            order_book: None,
            root_model: None,
            note_addr: Some(note_addr.clone()),
        },
    )
    .await?;
    let frame_model = target.frame_model;
    let model_hash = target.model_hash;
    let seed = read_secret_hex(note_key, "--note-key")?;
    let chain = RealChainBackend::connect(manifest)?;
    let keys = KeyPair::from_secret_hex(seed.trim())
        .map_err(|e| anyhow::anyhow!("--note-key (SDK secret hex): {e:?}"))?;
    let note = dexdo_core::address::parse_chain_address(&note_addr)
        .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
    let tick_size = TICK_SIZE;
    let ob = chain
        .inference_orderbook_address(&note, &model_hash, tick_size)
        .await?;
    let expected_order_book = ob.with_workchain();
    let book_active = chain.inference_orderbook_stats(&ob).await?.is_some();
    if let Some(policy) = registry_policy.as_ref() {
        enforce_model_registry_policy(
            RegistryRole::Seller,
            policy,
            &args.contracts,
            &frame_model,
            &expected_order_book,
            book_active,
            BuyerMissingBookPolicy::Reject,
        )
        .await?;
    }
    if book_active {
        println!(
            "inference market already deployed for {} -- order book {}",
            frame_model,
            dexdo_core::address::display(&ob.with_workchain())
        );
        return Ok(());
    }
    println!(
        "deploying inference market (order book) for {} ...",
        frame_model
    );
    chain
        .deploy_inference_orderbook(&note, &keys, &model_hash, &frame_model, tick_size)
        .await?;
    // Wait for activation so a follow-up `post_offer` doesn't race the deploy(the book getter returns once active).
    for _ in 0..MARKET_DEPLOY_ACTIVATION_MAX_READS {
        if chain.inference_orderbook_stats(&ob).await?.is_some() {
            break;
        }
        tokio::time::sleep(MARKET_DEPLOY_ACTIVATION_POLL_INTERVAL).await;
    }
    println!(
        "deployed inference market for {} -- order book {}",
        frame_model,
        dexdo_core::address::display(&ob.with_workchain())
    );
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_market_deploy(_args: MarketDeployArgs) -> Result<()> {
    bail!("real shellnet market deploy unavailable: build with `--features shellnet`")
}

/// the seller CLOSES a STOPped deal's per-deal `TokenContract` via `TokenContract::destroy()`
/// (`onlyOwnerPubkey(_sellerPubkey)`, gated `!_opened && !_disputed && !_offerPosted`) -> `selfdestruct` to the
/// deal's own stored `_sellerNote`(`contracts/airegistry/TokenContract.sol:1844`). **The payee is not an
/// argument(4.0.33, Task O):** `--note-addr` names the operator's note for the messages below, it does not
/// choose where the deal pays.
/// **DESTRUCTIVE:** it selfdestructs the TC; the held leftover burns cross-dapp (the raw `selfdestruct` return is
/// not credited back to the cross-dapp note). At the right-sized ~10/deploy funding ( -- MIN_BALANCE gates
/// nothing) that leftover is ~a few vmshell(negligible), so the old fail-closed `--acknowledge-burn` for ~110 is
/// overkill -- it is optional now(kept for back-compat).
#[cfg(feature = "shellnet")]
pub(crate) async fn run_destroy(args: DestroyArgs) -> Result<()> {
    let manifest = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let chain = dexdo_core::RealChainBackend::connect(manifest)?;
    run_destroy_with_chain(args, &chain).await
}

/// The reads and the submit `destroy` needs, behind a seam so the command's own decisions are
/// exercised without a node. Mirrors `RecoverChain`/`ReclaimChain` in `cli::recover`.
#[cfg(feature = "shellnet")]
#[async_trait::async_trait]
trait DestroyChain: Sync {
    /// The deal's coherent lifecycle snapshot. `None` is the *account* fact -- the `TokenContract` is not
    /// active, i.e. it already selfdestructed -- and never an empty field of a live contract.
    async fn state(&self, tc: &dexdo_core::Address) -> Result<Option<dexdo_core::DealChainState>>;
    async fn destroy(
        &self,
        tc: &dexdo_core::Address,
        note: &dexdo_core::Address,
        keys: &dexdo_core::KeyPair,
    ) -> Result<()>;
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait]
impl DestroyChain for dexdo_core::RealChainBackend {
    async fn state(&self, tc: &dexdo_core::Address) -> Result<Option<dexdo_core::DealChainState>> {
        Ok(self
            .token_contract_deal_snapshot(tc)
            .await?
            .map(|snapshot| snapshot.state))
    }

    async fn destroy(
        &self,
        tc: &dexdo_core::Address,
        note: &dexdo_core::Address,
        keys: &dexdo_core::KeyPair,
    ) -> Result<()> {
        self.destroy_token_contract(tc, note, keys).await.map(drop)
    }
}

#[cfg(feature = "shellnet")]
async fn run_destroy_with_chain(args: DestroyArgs, chain: &dyn DestroyChain) -> Result<()> {
    use dexdo_core::{Address, KeyPair};
    let _ = args.acknowledge_burn; // Accepted and ignored for existing-script compatibility; does not gate destroy.
    eprintln!(
        "dexdo destroy: selfdestructs the TokenContract; the held leftover (~a few vmshell at the right-sized \
         ~10/deploy funding, ) burns cross-dapp (not credited back to the note) -- negligible."
    );
    let note_addr = crate::cli::support::require_note_addr(
        &args.identity,
        "destroy",
        "the seller note this deal belongs to",
    )?;
    let note_key =
        crate::cli::support::require_note_key(&args.identity, "destroy", "seller owner key")?;
    // The TC comes from --token-contract OR --market(single source of truth, fail-loud).
    let (tc_str, _frame, _nonce) =
        resolve_market_fields(args.market.as_deref(), args.token_contract.as_deref(), None)?;
    let seed = read_secret_hex(note_key, "--note-key")?;
    let keys = KeyPair::from_secret_hex(seed.trim())
        .map_err(|e| anyhow::anyhow!("--note-key (SDK secret hex): {e:?}"))?;
    let note = dexdo_core::address::parse_chain_address(&note_addr)
        .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
    let tc =
        Address::parse(&tc_str).map_err(|e| anyhow::anyhow!("token_contract {tc_str}: {e}"))?;
    let tc_display = dexdo_core::address::display_self_dapp(&tc.with_workchain());
    let note_display = dexdo_core::address::display(&note.with_workchain());
    // cleanup is idempotent. An inactive account IS the finished job, so a repeat run reports it and
    // exits 0 instead of submitting a `destroy` that only reaches `getSeller`-returned-nothing. The account
    // fact is read here -- `token_contract_seller_pubkey` collapses "TC gone" and "empty pubkey" into the
    // same `None`, so the seller-key gate downstream cannot tell an already-closed deal from a broken one.
    // Same shape as the seller branch of `dexdo close`(`cli::close`, `already_closed`).
    if chain.state(&tc).await?.is_none() {
        println!("destroy noop: TokenContract {tc_display} is inactive/closed");
        return Ok(());
    }
    eprintln!(
        "destroy {tc_display}: selfdestructs the TokenContract; under right-sized funding the remaining few vmshell \
         burn cross-dapp (not credited back to the note {note_display}). Seller-signed; requires the deal STOPped \
         (!_opened && !_disputed)."
    );
    chain.destroy(&tc, &note, &keys).await?;
    println!(
        "destroy submitted -> TokenContract {tc_display} selfdestructs; remaining cross-dapp gas is not credited to note {note_display}"
    );
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_destroy(_args: DestroyArgs) -> Result<()> {
    bail!("destroy unavailable: build with `--features shellnet`")
}

#[cfg(all(test, feature = "shellnet"))]
mod destroy_tests {
    use super::{run_destroy_with_chain, DestroyChain};
    use crate::cli::args::{DestroyArgs, IdentityArgs};
    use anyhow::Result;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TC: &str = "0:9999999999999999999999999999999999999999999999999999999999999999";
    const NOTE: &str = "0:1111111111111111111111111111111111111111111111111111111111111111";

    /// One deal, modelled the way the 4.0.33 contract behaves for the two facts `destroy` reads.
    /// `state = None` is a **destroyed account**: no code, so every getter returns nothing --
    /// `getState` and `getSeller` alike. The submit reproduces the exact production failure
    /// reported, by driving the same shared gate production drives: `token_contract_seller_pubkey`
    /// hands `check_seller_pubkey` a `None` it cannot distinguish from a live contract with an
    /// empty pubkey, and the operator gets a hard error for a job that is already done.
    struct FakeDeal {
        state: Option<dexdo_core::DealChainState>,
        submits: AtomicUsize,
    }

    impl FakeDeal {
        fn destroyed() -> Self {
            Self {
                state: None,
                submits: AtomicUsize::new(0),
            }
        }

        fn stopped() -> Self {
            Self {
                state: Some(dexdo_core::DealChainState {
                    funded: false,
                    opened: false,
                    probe_accepted: false,
                    disputed: false,
                    deposit: 0,
                    finalized_owed: 0,
                    tokens_final: 0,
                    tokens_pending: 0,
                    probe_tick: 0,
                    funded_time: None,
                    probe_time: 0,
                    last_claim_time: 0,
                    dispute_time: 0,
                }),
                submits: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl DestroyChain for FakeDeal {
        async fn state(
            &self,
            _tc: &dexdo_core::Address,
        ) -> Result<Option<dexdo_core::DealChainState>> {
            Ok(self.state.clone())
        }

        async fn destroy(
            &self,
            _tc: &dexdo_core::Address,
            _note: &dexdo_core::Address,
            keys: &dexdo_core::KeyPair,
        ) -> Result<()> {
            self.submits.fetch_add(1, Ordering::SeqCst);
            // `RealChainBackend::destroy_token_contract` gates on the seller pubkey read BEFORE it
            // submits; on a destroyed account that read is `None`, and the shared gate -- the same
            // one production calls -- is the error the operator saw.
            let seller_key =
                dexdo_core::KeyPair::from_secret_hex(SELLER_SECRET).expect("modelled seller key");
            let seller = self
                .state
                .as_ref()
                .map(|_| seller_key.public_hex().to_string());
            dexdo_core::check_seller_pubkey("destroy", seller.as_deref(), keys.public_hex())
                .map_err(anyhow::Error::msg)?;
            Ok(())
        }
    }

    /// The seller's own key: the modelled `onlyOwnerPubkey(_sellerPubkey)` accepts it on a live
    /// deal, so the positive control really submits rather than failing the gate for another reason.
    const SELLER_SECRET: &str = "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a";

    fn destroy_args(key_file: &std::path::Path) -> DestroyArgs {
        DestroyArgs {
            identity: IdentityArgs {
                note_key: Some(key_file.to_path_buf()),
                note_index: 0,
                note_addr: Some(NOTE.to_string()),
            },
            token_contract: Some(TC.to_string()),
            market: None,
            acknowledge_burn: false,
            contracts: std::path::PathBuf::from("unused-contracts.json"),
        }
    }

    fn seller_key_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let path = dir.path().join("note.secret.hex");
        std::fs::write(&path, SELLER_SECRET).expect("write seller key");
        path
    }

    /// cleanup must be idempotent. The operator re-runs `dexdo destroy` on a deal that already
    /// selfdestructed(the normal case after a settled purchase) and must be told the job is done --
    /// exit 0, no submit -- instead of `destroy: TokenContract exposes no seller pubkey`.
    #[tokio::test]
    async fn repeated_destroy_on_a_selfdestructed_deal_is_a_noop_not_a_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_file = seller_key_file(&dir);
        let chain = FakeDeal::destroyed();

        run_destroy_with_chain(destroy_args(&key_file), &chain)
            .await
            .expect("an already destroyed TokenContract is a finished job, not an error");

        assert_eq!(
            chain.submits.load(Ordering::SeqCst),
            0,
            "a destroyed account must not be sent another destroy"
        );
    }

    /// The idempotency guard must not swallow the real work: a live STOPped deal still submits.
    #[tokio::test]
    async fn a_live_stopped_deal_still_submits_destroy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_file = seller_key_file(&dir);
        let chain = FakeDeal::stopped();

        run_destroy_with_chain(destroy_args(&key_file), &chain)
            .await
            .expect("a live STOPped deal is destroyable");

        assert_eq!(
            chain.submits.load(Ordering::SeqCst),
            1,
            "the live deal must still be destroyed exactly once"
        );
    }
}
