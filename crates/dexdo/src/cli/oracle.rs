//! `dexdo oracle` command handlers(provision/state/resolve), extracted from `commands.rs`
//! (move-only / behavior-identical, anti-entropy refactor Track C1).

use crate::cli::args::OracleArgs;
use anyhow::{bail, Result};
#[cfg(feature = "shellnet")]
use dexdo_core::params::{
    ORACLE_FEE_WITHDRAW_CONFIRM_MAX_READS, ORACLE_FEE_WITHDRAW_CONFIRM_POLL_INTERVAL,
    ORACLE_RESOLUTION_MAX_READS, ORACLE_RESOLUTION_POLL_INTERVAL, PMP_EXIT_CONFIRM_MAX_READS,
    PMP_EXIT_CONFIRM_POLL_INTERVAL, SHELL_CURRENCY_ID,
};

#[cfg(feature = "shellnet")]
use crate::cli::args::{
    OracleAddressArgs, OracleBookArgs, OracleBookCommand, OracleBookOrderArgs,
    OracleBookOrdersArgs, OracleBookStatusArgs, OracleCommand, OracleEventListAddressArgs,
    OracleEventListArgs, OracleEventListCommand, OracleEventListEventsArgs, OraclePmpAddressArgs,
    OraclePmpArgs, OraclePmpCommand, OraclePmpExitArgs, OraclePmpStatusArgs, OracleProvisionArgs,
    OracleResolveArgs, OracleStateArgs, OracleWithdrawFeesArgs,
};
#[cfg(feature = "shellnet")]
use crate::cli::commands::{now_unix_secs, shellnet_doctor_preflight};
#[cfg(feature = "shellnet")]
use crate::cli::support::{load_market, read_secret_hex, require_note_addr, require_note_key};

#[cfg(test)]
#[path = "oracle_exit_1120_tests.rs"]
mod oracle_exit_1120_tests;

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
    if manifest.token_type != SHELL_CURRENCY_ID {
        bail!(
            "--manifest {}: token_type {} is unsupported; dexdo markets require SHELL currency id {}",
            path.display(),
            manifest.token_type,
            SHELL_CURRENCY_ID
        );
    }
    Ok(manifest)
}

#[cfg(any(feature = "shellnet", test))]
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

#[cfg(any(feature = "shellnet", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PmpExitAction {
    CancelStake,
    Claim,
}

#[cfg(any(feature = "shellnet", test))]
impl PmpExitAction {
    fn command(self) -> &'static str {
        match self {
            Self::CancelStake => "oracle cancel-stake",
            Self::Claim => "oracle claim",
        }
    }
}

#[cfg(any(feature = "shellnet", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct PmpExitObservation {
    stake_present: bool,
    candidate_amount: u128,
    amount_slots: usize,
    open_orders: u32,
    busy_address: Option<String>,
    has_withdrawn: bool,
    note_balance: u128,
    coupons_value: u128,
}

#[cfg(feature = "shellnet")]
fn parse_pmp_exit_observation(value: &serde_json::Value) -> Result<PmpExitObservation> {
    let required_bool = |field: &str| {
        value[field]
            .as_bool()
            .ok_or_else(|| anyhow::anyhow!("PrivateNote exit snapshot exposes no boolean {field}"))
    };
    let required_u128 = |field: &str| {
        oracle_u128(value, field)
            .ok_or_else(|| anyhow::anyhow!("PrivateNote exit snapshot exposes no uint {field}"))
    };
    Ok(PmpExitObservation {
        stake_present: required_bool("stake_present")?,
        candidate_amount: required_u128("candidate_amount")?,
        amount_slots: usize::try_from(required_u128("amount_slots")?)
            .map_err(|_| anyhow::anyhow!("PrivateNote exit snapshot amount_slots exceeds usize"))?,
        open_orders: u32::try_from(required_u128("open_orders")?)
            .map_err(|_| anyhow::anyhow!("PrivateNote exit snapshot open_orders exceeds uint32"))?,
        busy_address: value["busy_address"]
            .as_str()
            .filter(|address| !address.trim().is_empty())
            .map(|address| address.trim().to_string()),
        has_withdrawn: required_bool("has_withdrawn")?,
        note_balance: required_u128("note_balance")?,
        coupons_value: required_u128("coupons_value")?,
    })
}

#[cfg(any(feature = "shellnet", test))]
fn oracle_bool(value: &serde_json::Value, field: &str) -> Option<bool> {
    value[field]
        .as_bool()
        .or_else(|| match value[field].as_str()? {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => None,
        })
}

#[cfg(any(feature = "shellnet", test))]
fn validate_pmp_exit_preflight(
    action: PmpExitAction,
    pmp: &serde_json::Value,
    shutdown: &serde_json::Value,
    note: &PmpExitObservation,
) -> Result<()> {
    let command = action.command();
    if !note.stake_present {
        bail!("{command}: this note has no stake for the manifest PMP tuple");
    }
    if note.has_withdrawn {
        bail!("{command}: the PrivateNote is withdrawn");
    }
    if let Some(busy) = note.busy_address.as_deref() {
        bail!("{command}: the PrivateNote is busy with {busy}");
    }
    if note.open_orders != 0 {
        bail!(
            "{command}: the PrivateNote still has {} open order(s) for this event",
            note.open_orders
        );
    }
    if note.candidate_amount != 0 {
        bail!(
            "{command}: the PrivateNote stake has pending candidate amount {}",
            note.candidate_amount
        );
    }

    let order_book_done = oracle_bool(shutdown, "orderBookDone").ok_or_else(|| {
        anyhow::anyhow!("{command}: PMP getShutdownState exposes no orderBookDone")
    })?;
    match action {
        PmpExitAction::CancelStake => {
            if oracle_bool(pmp, "isCancelled") != Some(true) {
                bail!("{command}: PMP is not cancelled");
            }
            let frozen = oracle_bool(pmp, "frozen")
                .ok_or_else(|| anyhow::anyhow!("{command}: PMP getDetails exposes no frozen"))?;
            if frozen && !order_book_done {
                bail!("{command}: PMP OrderBook shutdown is not complete");
            }
        }
        PmpExitAction::Claim => {
            if oracle_bool(pmp, "approved") != Some(true) {
                bail!("{command}: PMP is not approved");
            }
            if !order_book_done {
                bail!("{command}: PMP OrderBook shutdown is not complete");
            }
            if pmp_resolved_outcome(pmp).is_none() {
                bail!("{command}: PMP exposes no resolved outcome");
            }
            let outcomes = oracle_u128(pmp, "numOutcomes").ok_or_else(|| {
                anyhow::anyhow!("{command}: PMP getDetails exposes no numOutcomes")
            })?;
            if u128::try_from(note.amount_slots).ok() != Some(outcomes) {
                bail!(
                    "{command}: note stake has {} outcome slots but PMP declares {outcomes}",
                    note.amount_slots
                );
            }
        }
    }
    Ok(())
}

#[cfg(any(feature = "shellnet", test))]
fn pmp_exit_postread_confirmed(note: &PmpExitObservation) -> bool {
    !note.stake_present && note.busy_address.is_none()
}

#[cfg(any(feature = "shellnet", test))]
fn oracle_fee_expected_after(before: u128, amount: u128) -> Result<u128> {
    if amount == 0 {
        bail!("oracle withdraw-fees: --amount must be greater than zero");
    }
    before.checked_sub(amount).ok_or_else(|| {
        anyhow::anyhow!(
            "oracle withdraw-fees: --amount {amount} exceeds live Oracle fee balance {before} raw ECC[2] SHELL"
        )
    })
}

#[cfg(any(feature = "shellnet", test))]
fn oracle_fee_postread_confirmed(expected: u128, observed: u128) -> bool {
    observed == expected
}

#[cfg(feature = "shellnet")]
pub(crate) async fn run_oracle(args: OracleArgs) -> Result<()> {
    match args.command {
        OracleCommand::Address(a) => run_oracle_address(a).await,
        OracleCommand::EventList(e) => run_oracle_event_list(e).await,
        OracleCommand::Pmp(p) => run_oracle_pmp(p).await,
        OracleCommand::Book(b) => run_oracle_book(b).await,
        OracleCommand::Provision(p) => run_oracle_provision(*p).await,
        OracleCommand::State(s) => run_oracle_state(s).await,
        OracleCommand::Resolve(r) => run_oracle_resolve(r).await,
        OracleCommand::Cancel(c) => run_oracle_cancel(c).await,
        OracleCommand::Delete(d) => run_oracle_delete(d).await,
        OracleCommand::CancelStake(c) => run_oracle_pmp_exit(c, PmpExitAction::CancelStake).await,
        OracleCommand::Claim(c) => run_oracle_pmp_exit(c, PmpExitAction::Claim).await,
        OracleCommand::WithdrawFees(w) => run_oracle_withdraw_fees(w).await,
    }
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_oracle(_args: OracleArgs) -> Result<()> {
    bail!("oracle unavailable: build with `--features shellnet`")
}

#[cfg(feature = "shellnet")]
fn parse_oracle_read_address(flag: &str, raw: &str) -> Result<dexdo_core::Address> {
    dexdo_core::Address::parse(raw).map_err(|e| anyhow::anyhow!("{flag} {raw}: {e}"))
}

#[cfg(feature = "shellnet")]
fn oracle_read_chain(contracts: &std::path::Path) -> Result<dexdo_core::RealChainBackend> {
    dexdo_core::RealChainBackend::connect(
        contracts
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?,
    )
}

#[cfg(feature = "shellnet")]
fn required_oracle_getter(
    value: Option<serde_json::Value>,
    kind: &str,
    address: &dexdo_core::Address,
    getter: &str,
) -> Result<serde_json::Value> {
    value.ok_or_else(|| {
        anyhow::anyhow!(
            "{kind} {} {getter} unavailable (inactive or missing)",
            dexdo_core::address::display(&address.with_workchain())
        )
    })
}

#[cfg(feature = "shellnet")]
fn print_oracle_json(value: serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}

#[cfg(feature = "shellnet")]
async fn bound_order_book(
    chain: &dexdo_core::RealChainBackend,
    pmp: &dexdo_core::Address,
) -> Result<dexdo_core::Address> {
    let order_book = chain.pmp_order_book_address(pmp).await?.ok_or_else(|| {
        anyhow::anyhow!(
            "PMP {} exposes no bound OrderBook",
            dexdo_core::address::display(&pmp.with_workchain())
        )
    })?;
    if order_book.bare().bytes().all(|byte| byte == b'0') {
        bail!(
            "PMP {} exposes no bound OrderBook",
            dexdo_core::address::display(&pmp.with_workchain())
        );
    }
    chain
        .assert_order_book_read_identity(pmp, &order_book)
        .await?;
    Ok(order_book)
}

#[cfg(feature = "shellnet")]
async fn run_oracle_address(args: OracleAddressArgs) -> Result<()> {
    let chain = oracle_read_chain(&args.contracts)?;
    chain.assert_root_oracle_read_identity().await?;
    let oracle = chain.oracle_address(&args.oracle_name).await?;
    print_oracle_json(serde_json::json!({
        "kind": "oracle_address",
        "oracle_name": args.oracle_name,
        "oracle": dexdo_core::address::display(&oracle.with_workchain()),
    }))
}

#[cfg(feature = "shellnet")]
async fn run_oracle_event_list(args: OracleEventListArgs) -> Result<()> {
    match args.command {
        OracleEventListCommand::Address(a) => run_oracle_event_list_address(a).await,
        OracleEventListCommand::Events(e) => run_oracle_event_list_events(e).await,
    }
}

#[cfg(feature = "shellnet")]
async fn run_oracle_event_list_address(args: OracleEventListAddressArgs) -> Result<()> {
    let oracle = parse_oracle_read_address("--oracle", &args.oracle)?;
    let chain = oracle_read_chain(&args.contracts)?;
    chain.assert_oracle_read_identity(&oracle).await?;
    let event_list = chain.oracle_event_list_address(&oracle, args.index).await?;
    print_oracle_json(serde_json::json!({
        "kind": "oracle_event_list_address",
        "oracle": dexdo_core::address::display(&oracle.with_workchain()),
        "index": args.index.to_string(),
        "event_list": dexdo_core::address::display(&event_list.with_workchain()),
    }))
}

#[cfg(feature = "shellnet")]
async fn run_oracle_event_list_events(args: OracleEventListEventsArgs) -> Result<()> {
    let event_list = parse_oracle_read_address("--event-list", &args.event_list)?;
    let chain = oracle_read_chain(&args.contracts)?;
    chain
        .assert_oracle_event_list_read_identity(&event_list)
        .await?;
    let raw = required_oracle_getter(
        chain.oracle_event_list_events(&event_list).await?,
        "OracleEventList",
        &event_list,
        "_events",
    )?;
    let events = raw.get("_events").cloned().unwrap_or(raw);
    print_oracle_json(serde_json::json!({
        "kind": "oracle_events",
        "event_list": dexdo_core::address::display(&event_list.with_workchain()),
        "events": events,
    }))
}

#[cfg(feature = "shellnet")]
async fn run_oracle_pmp(args: OraclePmpArgs) -> Result<()> {
    match args.command {
        OraclePmpCommand::Address(a) => run_oracle_pmp_address(a).await,
        OraclePmpCommand::Status(s) => run_oracle_pmp_status(s).await,
    }
}

#[cfg(feature = "shellnet")]
async fn run_oracle_pmp_address(args: OraclePmpAddressArgs) -> Result<()> {
    let chain = oracle_read_chain(&args.contracts)?;
    chain.assert_root_pn_read_identity().await?;
    let pmp = chain
        .pmp_address(&args.event_id, &args.oracle_names, args.token_type)
        .await?;
    print_oracle_json(serde_json::json!({
        "kind": "pmp_address",
        "event_id": args.event_id,
        "oracle_names": args.oracle_names,
        "token_type": args.token_type,
        "pmp": dexdo_core::address::display(&pmp.with_workchain()),
    }))
}

#[cfg(feature = "shellnet")]
async fn run_oracle_pmp_status(args: OraclePmpStatusArgs) -> Result<()> {
    let pmp = parse_oracle_read_address("--pmp", &args.pmp)?;
    let chain = oracle_read_chain(&args.contracts)?;
    chain.assert_pmp_read_identity(&pmp).await?;
    let details =
        required_oracle_getter(chain.pmp_details(&pmp).await?, "PMP", &pmp, "getDetails")?;
    let shutdown_state = required_oracle_getter(
        chain.pmp_shutdown_state(&pmp).await?,
        "PMP",
        &pmp,
        "getShutdownState",
    )?;
    let unclaimed = required_oracle_getter(
        chain.pmp_unclaimed_balance(&pmp).await?,
        "PMP",
        &pmp,
        "getUnclaimedBalance",
    )?;
    let unclaimed_balance = unclaimed
        .get("value0")
        .and_then(|value| {
            value
                .as_str()
                .map(str::to_string)
                .or_else(|| value.as_u64().map(|value| value.to_string()))
        })
        .ok_or_else(|| anyhow::anyhow!("PMP getUnclaimedBalance exposes no uint128 value0"))?;
    let version =
        required_oracle_getter(chain.pmp_version(&pmp).await?, "PMP", &pmp, "getVersion")?;
    let order_book = chain
        .pmp_order_book_address(&pmp)
        .await?
        .and_then(|address| {
            (!address.bare().bytes().all(|byte| byte == b'0'))
                .then(|| dexdo_core::address::display(&address.with_workchain()))
        });
    print_oracle_json(serde_json::json!({
        "kind": "pmp_status",
        "pmp": dexdo_core::address::display(&pmp.with_workchain()),
        "details": details,
        "shutdown_state": shutdown_state,
        "unclaimed_balance": unclaimed_balance,
        "version": version,
        "order_book": order_book,
    }))
}

#[cfg(feature = "shellnet")]
async fn run_oracle_book(args: OracleBookArgs) -> Result<()> {
    match args.command {
        OracleBookCommand::Status(s) => run_oracle_book_status(s).await,
        OracleBookCommand::Order(o) => run_oracle_book_order(o).await,
        OracleBookCommand::Orders(o) => run_oracle_book_orders(o).await,
    }
}

#[cfg(feature = "shellnet")]
async fn run_oracle_book_status(args: OracleBookStatusArgs) -> Result<()> {
    let pmp = parse_oracle_read_address("--pmp", &args.pmp)?;
    let chain = oracle_read_chain(&args.contracts)?;
    let order_book = bound_order_book(&chain, &pmp).await?;
    let details = required_oracle_getter(
        chain.order_book_details(&order_book).await?,
        "OrderBook",
        &order_book,
        "getDetails",
    )?;
    let queue_size = required_oracle_getter(
        chain.order_book_queue_size(&order_book).await?,
        "OrderBook",
        &order_book,
        "getQueueSize",
    )?;
    let shutdown_state = required_oracle_getter(
        chain.order_book_shutdown_state(&order_book).await?,
        "OrderBook",
        &order_book,
        "getShutdownState",
    )?;
    let version = required_oracle_getter(
        chain.order_book_version(&order_book).await?,
        "OrderBook",
        &order_book,
        "getVersion",
    )?;
    print_oracle_json(serde_json::json!({
        "kind": "order_book_status",
        "pmp": dexdo_core::address::display(&pmp.with_workchain()),
        "order_book": dexdo_core::address::display(&order_book.with_workchain()),
        "details": details,
        "queue_size": queue_size,
        "shutdown_state": shutdown_state,
        "version": version,
    }))
}

#[cfg(feature = "shellnet")]
async fn run_oracle_book_order(args: OracleBookOrderArgs) -> Result<()> {
    let pmp = parse_oracle_read_address("--pmp", &args.pmp)?;
    let chain = oracle_read_chain(&args.contracts)?;
    let order_book = bound_order_book(&chain, &pmp).await?;
    let order = required_oracle_getter(
        chain.order_book_order(&order_book, args.order_id).await?,
        "OrderBook",
        &order_book,
        "getOrder",
    )?;
    print_oracle_json(serde_json::json!({
        "kind": "order_book_order",
        "pmp": dexdo_core::address::display(&pmp.with_workchain()),
        "order_book": dexdo_core::address::display(&order_book.with_workchain()),
        "order_id": args.order_id.to_string(),
        "order": order,
    }))
}

#[cfg(feature = "shellnet")]
async fn run_oracle_book_orders(args: OracleBookOrdersArgs) -> Result<()> {
    let pmp = parse_oracle_read_address("--pmp", &args.pmp)?;
    let chain = oracle_read_chain(&args.contracts)?;
    let order_book = bound_order_book(&chain, &pmp).await?;
    let orders = required_oracle_getter(
        chain
            .order_book_orders_by_owner(&order_book, &args.deposit_hash)
            .await?,
        "OrderBook",
        &order_book,
        "getOrdersByOwner",
    )?;
    print_oracle_json(serde_json::json!({
        "kind": "order_book_orders_by_owner",
        "pmp": dexdo_core::address::display(&pmp.with_workchain()),
        "order_book": dexdo_core::address::display(&order_book.with_workchain()),
        "deposit_hash": args.deposit_hash,
        "orders": orders,
    }))
}

#[cfg(feature = "shellnet")]
async fn run_oracle_provision(args: OracleProvisionArgs) -> Result<()> {
    use dexdo_core::{KeyPair, RealChainBackend};
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
    let note = dexdo_core::address::parse_chain_address(&note_addr)
        .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
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
    let manifest = load_oracle_market_manifest(&args.manifest)?;
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
    let pmp_display = dexdo_core::address::display(&manifest.pmp);
    let inference_ob_display = dexdo_core::address::display(&manifest.inference_order_book);
    let range = chain.oracle_range_data(&oel, &manifest.event_id).await?;
    let details = chain.pmp_details(&pmp).await?;
    let pmp_ob = chain.pmp_order_book_address(&pmp).await?;
    println!(
        "oracle_state event={} pmp={} token_type={} deadline={} frame_model={} inference_ob={}",
        manifest.event_id,
        pmp_display,
        manifest.token_type,
        manifest.deadline,
        manifest.frame_model,
        inference_ob_display
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
        println!(
            "pmp_order_book={}",
            dexdo_core::address::display(&ob.with_workchain())
        );
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
    let pmp_display = dexdo_core::address::display(&manifest.pmp);
    let oracle_seed = read_secret_hex(&args.oracle_key, "--oracle-key")?;
    let oracle_keys = KeyPair::from_secret_hex(oracle_seed.trim())
        .map_err(|e| anyhow::anyhow!("--oracle-key (SDK secret hex): {e:?}"))?;
    // Liquidity preflight. `resolveRange` makes the PMP ask its bound InferenceOrderBook for the
    // weekly median, and that book answers through `requestWeeklyMedian`
    // (`contracts/airegistry/InferenceOrderBook.sol:1759`) with `bounce: false`. Its
    // `_weeklyMedian()` reverts with `ERR_NO_LIQUIDITY = 334` (`:1738`, the constant declared at
    // `:116`) while the week's matched volume is below `MIN_LIQUIDITY`(`:237`), and under
    // `bounce: false` that revert never comes back: the resolve is paid for and the PMP stays
    // unresolved. `getWeeklyMedianPrice()`(`:1749`) is the same `_weeklyMedian()` exposed as a
    // public getter, so read it first and send nothing at all when it does not answer.
    let order_book = chain.pmp_order_book_address(&pmp).await?.ok_or_else(|| {
        anyhow::anyhow!(
            "oracle resolve: refusing to submit resolveRange -- PMP {} exposes no bound \
             InferenceOrderBook, so whether it has liquidity for a weekly median cannot be read",
            pmp_display
        )
    })?;
    let order_book_s = dexdo_core::address::display(&order_book.with_workchain());
    validate_oracle_resolve_liquidity(
        &order_book_s,
        chain
            .inference_orderbook_weekly_median_price(&order_book)
            .await,
    )?;
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
        manifest.event_id, manifest.oracle_list_hash, pmp_display
    );
    let mut last_details_error = None;
    for i in 0..ORACLE_RESOLUTION_MAX_READS {
        match chain.pmp_details(&pmp).await {
            Ok(Some(details)) => {
                if let Some(outcome) = pmp_resolved_outcome(&details) {
                    println!(
                        "pmp resolved event={} outcome={} pmp={}",
                        manifest.event_id, outcome, pmp_display
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
        if i + 1 < ORACLE_RESOLUTION_MAX_READS {
            tokio::time::sleep(ORACLE_RESOLUTION_POLL_INTERVAL).await;
        }
    }
    let resolution_timeout_secs = (ORACLE_RESOLUTION_MAX_READS as u64)
        .saturating_mul(ORACLE_RESOLUTION_POLL_INTERVAL.as_secs());
    let last_details_error = last_details_error
        .map(|e| format!(" Last transient pmp_details error while polling: {e}."))
        .unwrap_or_default();
    bail!(
        "resolveRange was submitted but PMP {} did not expose resolvedOutcome within {resolution_timeout_secs}s. \
         If the bound InferenceOrderBook has no MIN_LIQUIDITY, requestWeeklyMedian reverts under bounce:false \
         and onWeeklyMedian never arrives; this is the  no-liquidity stuck case, not a CLI success.{}",
        pmp_display,
        last_details_error
    )
}

#[cfg(any(feature = "shellnet", test))]
fn oracle_u128(value: &serde_json::Value, field: &str) -> Option<u128> {
    value[field].as_u64().map(u128::from).or_else(|| {
        value[field]
            .as_str()
            .and_then(|raw| raw.parse::<u128>().ok())
    })
}

/// The book's own answer to `getWeeklyMedianPrice`, decided the way the contract decides it: an
/// answer at all means `_weeklyMedian()` cleared `require(totalVol >= MIN_LIQUIDITY,
/// ERR_NO_LIQUIDITY)`(`contracts/airegistry/InferenceOrderBook.sol:1738`), and no answer means it
/// did not. Money path, so anything that is not an answer refuses the resolve rather than paying
/// for one that cannot complete; the getter error is reported verbatim so the exit code the book
/// actually returned is on the operator's screen next to the constant it belongs to.
#[cfg(feature = "shellnet")]
fn validate_oracle_resolve_liquidity(
    order_book: &str,
    weekly_median: Result<Option<u128>>,
) -> Result<u128> {
    let order_book = dexdo_core::address::display(order_book);
    match weekly_median {
        Ok(Some(price)) => Ok(price),
        Ok(None) => bail!(
            "oracle resolve: refusing to submit resolveRange -- InferenceOrderBook {order_book} is \
             not Active, so no liquidity and no weekly median can be read from it \
             (contracts/airegistry/InferenceOrderBook.sol:1749 getWeeklyMedianPrice)"
        ),
        Err(e) => bail!(
            "oracle resolve: refusing to submit resolveRange -- InferenceOrderBook {order_book} \
             reports no liquidity: getWeeklyMedianPrice \
             (contracts/airegistry/InferenceOrderBook.sol:1749) did not answer, which is how \
             `_weeklyMedian()` reports ERR_NO_LIQUIDITY = 334 (declared at :116, required at \
             :1738 as totalVol >= MIN_LIQUIDITY). resolveRange would make the PMP call \
             requestWeeklyMedian (:1759) under bounce:false, so that revert would never return \
             and the PMP would stay unresolved. Getter error: {e:#}"
        ),
    }
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
        dexdo_core::address::display(&manifest.pmp),
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
        dexdo_core::address::display(&manifest.oracle_event_list),
        after_event.is_some(),
        if confirmed { "confirmed" } else { "pending" }
    );
    Ok(())
}

#[cfg(feature = "shellnet")]
fn is_ambiguous_money_submit(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<dexdo_core::MoneySubmitError>()
            .is_some_and(dexdo_core::MoneySubmitError::is_ambiguous)
    })
}

#[cfg(feature = "shellnet")]
async fn read_pmp_unclaimed_balance(
    chain: &dexdo_core::RealChainBackend,
    pmp: &dexdo_core::Address,
) -> Result<Option<u128>> {
    chain
        .pmp_unclaimed_balance(pmp)
        .await?
        .map(|value| {
            oracle_u128(&value, "value0")
                .ok_or_else(|| anyhow::anyhow!("PMP getUnclaimedBalance exposes no uint128 value0"))
        })
        .transpose()
}

#[cfg(feature = "shellnet")]
async fn wait_pmp_exit_postread(
    chain: &dexdo_core::RealChainBackend,
    note: &dexdo_core::Address,
    manifest: &dexdo_core::OracleMarketManifest,
    action: PmpExitAction,
) -> Result<PmpExitObservation> {
    let mut last_state = None;
    let mut last_error = None;
    for read in 0..PMP_EXIT_CONFIRM_MAX_READS {
        match chain
            .private_note_pmp_exit_state(
                note,
                &manifest.event_id,
                &manifest.oracle_list_hash,
                manifest.token_type,
            )
            .await
            .and_then(|value| parse_pmp_exit_observation(&value))
        {
            Ok(state) if pmp_exit_postread_confirmed(&state) => return Ok(state),
            Ok(state) => last_state = Some(state),
            Err(error) => last_error = Some(format!("{error:#}")),
        }
        if read + 1 < PMP_EXIT_CONFIRM_MAX_READS {
            tokio::time::sleep(PMP_EXIT_CONFIRM_POLL_INTERVAL).await;
        }
    }
    bail!(
        "{}: callback was not confirmed after {} reads; last_state={last_state:?}; last_read_error={last_error:?}",
        action.command(),
        PMP_EXIT_CONFIRM_MAX_READS
    )
}

#[cfg(feature = "shellnet")]
async fn run_oracle_pmp_exit(args: OraclePmpExitArgs, action: PmpExitAction) -> Result<()> {
    use dexdo_core::{KeyPair, RealChainBackend};

    let manifest = load_oracle_market_manifest(&args.manifest)?;
    let note_addr = require_note_addr(
        &args.identity,
        action.command(),
        "PMP participant PrivateNote",
    )?;
    let note_key = require_note_key(
        &args.identity,
        action.command(),
        "PMP participant note owner key",
    )?;
    let note = dexdo_core::address::parse_chain_address(&note_addr)
        .map_err(|error| anyhow::anyhow!("--note-addr {note_addr}: {error}"))?;
    let note_secret = read_secret_hex(note_key, "--note-key")?;
    let note_keys = KeyPair::from_secret_hex(note_secret.trim())
        .map_err(|error| anyhow::anyhow!("--note-key (SDK secret hex): {error:?}"))?;
    shellnet_doctor_preflight(&args.contracts, None).await?;
    let chain = RealChainBackend::connect(
        args.contracts
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?,
    )?;
    chain
        .assert_note_owner_matches(action.command(), &note, &note_keys)
        .await?;
    let (pmp, pmp_details) = chain.assert_pmp_market_identity(&manifest).await?;
    let shutdown = required_oracle_getter(
        chain.pmp_shutdown_state(&pmp).await?,
        "PMP",
        &pmp,
        "getShutdownState",
    )?;
    let before = parse_pmp_exit_observation(
        &chain
            .private_note_pmp_exit_state(
                &note,
                &manifest.event_id,
                &manifest.oracle_list_hash,
                manifest.token_type,
            )
            .await?,
    )?;
    validate_pmp_exit_preflight(action, &pmp_details, &shutdown, &before)?;
    let before_unclaimed = read_pmp_unclaimed_balance(&chain, &pmp)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("PMP {pmp} getUnclaimedBalance unavailable before submit")
        })?;

    let submit = match action {
        PmpExitAction::CancelStake => {
            chain
                .cancel_pmp_stake(
                    &note,
                    &note_keys,
                    &manifest.event_id,
                    &manifest.oracle_list_hash,
                    manifest.token_type,
                )
                .await
        }
        PmpExitAction::Claim => {
            chain
                .claim_pmp_stake(
                    &note,
                    &note_keys,
                    &manifest.event_id,
                    &manifest.oracle_list_hash,
                    manifest.token_type,
                )
                .await
        }
    };
    let submit_status = match submit {
        Ok(_) => "accepted",
        Err(error) if is_ambiguous_money_submit(&error) => "ambiguous-reconciled",
        Err(error) => return Err(error),
    };
    let after = wait_pmp_exit_postread(&chain, &note, &manifest, action).await?;
    let after_unclaimed = read_pmp_unclaimed_balance(&chain, &pmp).await?;
    let after_unclaimed = after_unclaimed
        .map(|value| value.to_string())
        .unwrap_or_else(|| "inactive-or-missing".to_string());
    println!(
        "{} submitted event={} oracle_list_hash={} token_type={} pmp={} note={} \
         pmp_unclaimed={before_unclaimed}->{after_unclaimed} note_balance={}->{} \
         coupons={}->{} submit_status={submit_status} status=confirmed",
        action.command(),
        manifest.event_id,
        manifest.oracle_list_hash,
        manifest.token_type,
        pmp.with_workchain(),
        note.with_workchain(),
        before.note_balance,
        after.note_balance,
        before.coupons_value,
        after.coupons_value,
    );
    Ok(())
}

#[cfg(feature = "shellnet")]
async fn wait_oracle_fee_balance(
    chain: &dexdo_core::RealChainBackend,
    oracle: &dexdo_core::Address,
    signer: &dexdo_core::KeyPair,
    expected: u128,
) -> Result<u128> {
    let mut last_balance = None;
    let mut last_error = None;
    for read in 0..ORACLE_FEE_WITHDRAW_CONFIRM_MAX_READS {
        match chain.oracle_fee_balance_for_owner(oracle, signer).await {
            Ok(balance) if oracle_fee_postread_confirmed(expected, balance) => return Ok(balance),
            Ok(balance) => last_balance = Some(balance),
            Err(error) => last_error = Some(format!("{error:#}")),
        }
        if read + 1 < ORACLE_FEE_WITHDRAW_CONFIRM_MAX_READS {
            tokio::time::sleep(ORACLE_FEE_WITHDRAW_CONFIRM_POLL_INTERVAL).await;
        }
    }
    bail!(
        "oracle withdraw-fees: account ECC[2] balance did not reach expected {expected} after {} reads; \
         last_balance={last_balance:?}; last_read_error={last_error:?}",
        ORACLE_FEE_WITHDRAW_CONFIRM_MAX_READS
    )
}

#[cfg(feature = "shellnet")]
async fn run_oracle_withdraw_fees(args: OracleWithdrawFeesArgs) -> Result<()> {
    let oracle = parse_oracle_read_address("--oracle", &args.oracle)?;
    let to = parse_oracle_read_address("--to", &args.to)?;
    if oracle.with_workchain() == to.with_workchain() {
        bail!("oracle withdraw-fees: --to must not be the Oracle itself");
    }
    let signer = load_oracle_signer(&args.oracle_key)?;
    shellnet_doctor_preflight(&args.contracts, None).await?;
    let chain = oracle_read_chain(&args.contracts)?;
    let before = chain.oracle_fee_balance_for_owner(&oracle, &signer).await?;
    let expected = oracle_fee_expected_after(before, args.amount)?;
    let submit = chain
        .withdraw_oracle_fees(&oracle, &signer, &to, args.amount)
        .await;
    let submit_status = match submit {
        Ok(_) => "accepted",
        Err(error) if is_ambiguous_money_submit(&error) => "ambiguous-reconciled",
        Err(error) => return Err(error),
    };
    let after = wait_oracle_fee_balance(&chain, &oracle, &signer, expected).await?;
    println!(
        "oracle withdraw-fees submitted oracle={} to={} amount={} raw_ecc2_balance={before}->{after} \
         submit_status={submit_status} status=confirmed",
        oracle.with_workchain(),
        to.with_workchain(),
        args.amount,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "shellnet")]
    fn oracle_manifest(token_type: u32) -> dexdo_core::OracleMarketManifest {
        dexdo_core::OracleMarketManifest {
            network: "shellnet".into(),
            root_oracle: "0:root".into(),
            oracle: "0:oracle".into(),
            oracle_event_list: "0:list".into(),
            oracle_list_hash: "1".into(),
            event_id: "2".into(),
            event_name: "event".into(),
            pmp: "0:pmp".into(),
            token_type,
            inference_order_book: "0:book".into(),
            frame_model: "model".into(),
            deadline: 1,
            bounds: vec!["100".into()],
            outcome_names: vec!["below".into(), "above".into()],
        }
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn oracle_manifest_rejects_non_shell_before_chain_use() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oracle-market.json");
        std::fs::write(&path, oracle_manifest(1).to_json().unwrap()).unwrap();

        let error = super::load_oracle_market_manifest(&path)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains(&format!(
                "require SHELL currency id {}",
                super::SHELL_CURRENCY_ID
            )),
            "{error}"
        );
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn oracle_state_rejects_non_shell_before_doctor_or_backend() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("oracle-market.json");
        std::fs::write(&manifest, oracle_manifest(1).to_json().unwrap()).unwrap();

        let error = super::run_oracle_state(super::OracleStateArgs {
            manifest,
            contracts: dir.path().join("must-not-read-contracts.json"),
        })
        .await
        .unwrap_err()
        .to_string();

        assert!(
            error.contains(&format!(
                "require SHELL currency id {}",
                super::SHELL_CURRENCY_ID
            )),
            "{error}"
        );
        assert!(!error.contains("must-not-read-contracts"), "{error}");
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn oracle_deadline_enforces_contract_result_gap() {
        let now = 1_900_000_000;
        assert!(super::validate_oracle_deadline(now + 119, now).is_err());
        assert!(super::validate_oracle_deadline(now + 120, now).is_ok());
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn oracle_resolve_refuses_without_weekly_median_liquidity() {
        assert_eq!(
            super::validate_oracle_resolve_liquidity("0:book", Ok(Some(7))).unwrap(),
            7,
            "an answered getWeeklyMedianPrice is the contract's own proof of liquidity"
        );

        for refusal in [
            super::validate_oracle_resolve_liquidity("0:book", Ok(None)),
            super::validate_oracle_resolve_liquidity(
                "0:book",
                Err(anyhow::anyhow!(
                    "run_tvm getter getWeeklyMedianPrice: Contract execution was terminated with \
                     error: exit code: 334"
                )),
            ),
        ] {
            let error = refusal.unwrap_err().to_string();
            assert!(
                error.to_ascii_lowercase().contains("no liquidity"),
                "the refusal must name the condition in the words the operator reads: {error}"
            );
            assert!(
                error.contains("refusing to submit resolveRange"),
                "the refusal must say that nothing was submitted: {error}"
            );
        }

        let exit_code = super::validate_oracle_resolve_liquidity(
            "0:book",
            Err(anyhow::anyhow!("run_tvm getter getWeeklyMedianPrice")),
        )
        .unwrap_err()
        .to_string();
        assert!(
            exit_code.contains("ERR_NO_LIQUIDITY = 334"),
            "the refusal must carry the exact contract exit code: {exit_code}"
        );
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
