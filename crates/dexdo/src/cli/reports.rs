//! Read-only reporting/view command handlers, extracted from `commands.rs`
//! (move-only / behavior-identical, anti-entropy refactor Track C4).

#[cfg(feature = "shellnet")]
use crate::cli::args::ExportFormatArg;
use crate::cli::args::{DashboardArgs, DealsArgs, ExportArgs, HistoryArgs, StatusArgs};
#[cfg(feature = "shellnet")]
use crate::cli::commands::{
    close_hint, deal_contracts_path, load_deal_target, shellnet_doctor_preflight_market,
};
use crate::cli::commands::{mock_chain_for_machine, resolve_mock_deal_target, role_arg_str};
use crate::cli::{audit, dashboard, deals, machine};
use crate::operator_shutdown_signal;
#[cfg(not(feature = "shellnet"))]
use anyhow::bail;
use anyhow::Result;
use dexdo_core::address as addr;
use dexdo_core::ChainBackend;

pub(crate) async fn run_deals(args: DealsArgs) -> Result<()> {
    let dir = deals::resolve_deals_dir(args.deals_dir.as_deref())?;
    let handles = deals::list_deal_handles(&dir)?;
    if handles.is_empty() {
        println!("deals dir={} none=true", dir.display());
        return Ok(());
    }
    for (path, h) in handles {
        println!(
            "handle={} role={} network={} note={} model={} token_contract={} order_book={} path={}",
            h.handle,
            h.role.as_str(),
            h.network,
            addr::display(&h.note_addr),
            h.frame_model,
            addr::display_self_dapp(&h.token_contract),
            addr::display_opt(h.order_book.as_deref(), "-"),
            path.display()
        );
    }
    Ok(())
}

pub(crate) async fn run_history(args: HistoryArgs) -> Result<()> {
    let dir = deals::resolve_deals_dir(args.deals_dir.as_deref())?;
    let handles = deals::list_deal_handles(&dir)?;
    let mut shown = 0usize;
    for (path, h) in handles {
        if !audit::history_handle_matches(&h, args.note.as_deref(), args.model.as_deref()) {
            continue;
        }
        shown += 1;
        println!(
            "history handle={} role={} network={} note={} model={} model_hash={} token_contract={} order_book={} created_at={} order_ids={} path={}",
            h.handle,
            h.role.as_str(),
            h.network,
            addr::display(&h.note_addr),
            h.frame_model,
            h.model_hash.as_deref().unwrap_or("-"),
            addr::display_self_dapp(&h.token_contract),
            addr::display_opt(h.order_book.as_deref(), "-"),
            h.created_at_unix,
            if h.created_order_ids.is_empty() {
                "-".to_string()
            } else {
                h.created_order_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            },
            path.display()
        );
    }
    if shown == 0 {
        println!(
            "history dir={} none=true note={} model={}",
            dir.display(),
            args.note.as_deref().unwrap_or("-"),
            args.model.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

pub(crate) async fn run_dashboard(args: DashboardArgs) -> Result<()> {
    dashboard::ensure_loopback(args.listen)?;
    let dir = deals::resolve_deals_dir(args.deals_dir.as_deref())?;
    #[cfg(feature = "shellnet")]
    let state = dashboard::DashboardAppState::shellnet(dir);
    #[cfg(not(feature = "shellnet"))]
    let state = dashboard::DashboardAppState::local(dir);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let addr = dashboard::bind_dashboard(args.listen, state, async move {
        let _ = shutdown_rx.await;
    })
    .await?;
    println!(
        "dashboard_url=http://{addr}/ json=http://{addr}{} read_only=true",
        dashboard::DASHBOARD_JSON_PATH
    );
    operator_shutdown_signal().await;
    let _ = shutdown_tx.send(());
    Ok(())
}

fn status_next_for(
    role: Option<&str>,
    state: &str,
    funded: bool,
    opened: bool,
    probe_accepted: bool,
) -> machine::StatusNext {
    let action = match (role, state, funded, opened, probe_accepted) {
        (_, "closed", _, _, _) => "none",
        (Some("seller"), "stopped", _, _, _) => "destroy",
        (Some("seller"), _, _, true, false) => "seller_wait_delivery_then_accept_probe",
        (Some("seller"), _, _, true, true) => "seller_claim_finalize_or_settle_week_or_seller_stop",
        (Some("seller"), _, true, false, false) => "buyer_cleanup_after_timeout",
        (Some("buyer"), "stopped", _, _, _) => "none",
        (Some("buyer"), _, _, true, _) => "stream_stop",
        (Some("buyer"), _, true, false, false) => "cleanup_unopened_after_timeout",
        (Some("buyer"), _, _, _, _) => "cancel_resting_bid_or_wait_match",
        _ => "unknown_role",
    };
    machine::StatusNext {
        action: action.to_string(),
        retryable_after_unix: None,
        command: if action == "none" {
            "none".to_string()
        } else if matches!(
            action,
            "seller_wait_delivery_then_accept_probe"
                | "seller_claim_finalize_or_settle_week_or_seller_stop"
        ) {
            "seller".to_string()
        } else {
            "close".to_string()
        },
    }
}

/// render an address the way the versioned machine schemas are pinned to carry it.
/// `runtime-machine-contract.md` fixes `dexdo.status.v2` and the `dexdo.*.event.v1` payloads to the
/// legacy `0:<account_id>` shape until a coordinated version bump, because every parent process
/// parses that form. Human output and files keep the canonical `<dapp_id>::<account_id>`; only this
/// boundary converts.
/// An address that does not parse is passed through unchanged. This function's job is the SHAPE of
/// a well-formed address, and swallowing an unparseable one into an empty string or a panic would
/// replace a visible oddity with an invisible one; the reader downstream still sees exactly what
/// the command was given.
/// The conversion is `address::to_chain_param`, the crate's own seam for exactly this direction, and
/// not `parse_chain_address`: the latter is `#[cfg(feature = "shellnet")]`, so calling it from here
/// broke the default-feature build of the whole workspace -- the shape this boundary converts is
/// decided by the schema, not by whether the chain client is compiled in. That is also why there is
/// ONE function here and not a pair split by the feature: a default build that passed the address
/// through would answer `dexdo.status.v2` in the unpinned shape, which is the defect reports.
fn pinned_schema_address(address: &str) -> String {
    dexdo_core::address::to_chain_param(address).unwrap_or_else(|_| address.to_string())
}

#[allow(clippy::too_many_arguments)]
fn status_response_from_summary(
    network: &str,
    handle: Option<String>,
    role: Option<String>,
    token_contract: String,
    frame_model: Option<String>,
    state: &str,
    active: bool,
    s: &deals::DealStateSummary,
) -> Result<machine::StatusResponse> {
    Ok(machine::StatusResponse {
        schema: machine::STATUS_SCHEMA,
        network: network.to_string(),
        generated_at_unix: machine::now_unix()?,
        handle,
        role: role.clone(),
        // `dexdo.status.v2` is pinned to `0:<account_id>` by `runtime-machine-contract.md`,
        // and this field used to be whatever reached the command -- the argv string, or the
        // spelling the deal handle happens to store. Both can be canonical, and then a schema the
        // whole parent process reads answers in a form it does not accept.
        // Measured, not deduced: the two-runner release gate refused with
        // asked about 97256735...::97256735..., status answered '97256735...::97256735...'
        // -- the SAME account, so the identity half of the check passed and the shape half did not.
        // That gate had been red since 2026-08-10 and v0.0.22 shipped over it.
        // Normalising here, at the one place the machine schema is built, rather than at each of
        // the callers: a caller that forgets is exactly how this arrived.
        token_contract: pinned_schema_address(&token_contract),
        frame_model,
        state: state.to_string(),
        active,
        funded: s.funded,
        opened: s.opened,
        disputed: s.disputed,
        probe_accepted: s.probe_accepted,
        accounting: machine::StatusAccounting {
            finalized_owed: machine::amount(s.finalized_owed),
            buyer_locked: machine::amount(s.buyer_locked()?),
            deposit: machine::amount(s.deposit),
            probe_tick: machine::amount(s.probe_tick),
            buyer_bond: machine::amount(s.buyer_bond),
            buyer_bond_required: machine::amount(s.buyer_bond_required),
            tokens_final: machine::amount(s.tokens_final),
            tokens_pending: machine::amount(s.tokens_pending),
            probe_time_unix: Some(s.probe_time).filter(|v| *v != 0),
            last_claim_time_unix: Some(s.last_claim_time).filter(|v| *v != 0),
            dispute_time_unix: Some(s.dispute_time).filter(|v| *v != 0),
            funded_time_unix: s.funded_time,
        },
        next: status_next_for(role.as_deref(), state, s.funded, s.opened, s.probe_accepted),
    })
}

fn closed_status_response(
    network: &str,
    handle: Option<String>,
    role: Option<String>,
    token_contract: String,
    frame_model: Option<String>,
) -> Result<machine::StatusResponse> {
    let s = deals::DealStateSummary {
        kind: deals::DealStateKind::Stopped,
        funded: false,
        opened: false,
        disputed: false,
        probe_accepted: false,
        deposit: 0,
        probe_tick: 0,
        buyer_bond: 0,
        buyer_bond_required: 0,
        finalized_owed: 0,
        tokens_final: 0,
        tokens_pending: 0,
        funded_time: None,
        probe_time: 0,
        last_claim_time: 0,
        dispute_time: 0,
    };
    status_response_from_summary(
        network,
        handle,
        role,
        token_contract,
        frame_model,
        "closed",
        false,
        &s,
    )
}

fn mock_summary_from_snapshot(snapshot: &dexdo_core::StreamSnapshot) -> deals::DealStateSummary {
    let kind = if snapshot.closed {
        deals::DealStateKind::Stopped
    } else if snapshot.seller_received > 0 {
        deals::DealStateKind::Streaming
    } else {
        deals::DealStateKind::Probe
    };
    deals::DealStateSummary {
        kind,
        funded: !snapshot.closed,
        opened: !snapshot.closed,
        disputed: false,
        probe_accepted: snapshot.seller_received > 0,
        deposit: snapshot.buyer_locked,
        probe_tick: 0,
        buyer_bond: 0,
        buyer_bond_required: 0,
        finalized_owed: snapshot.seller_received,
        tokens_final: 0,
        tokens_pending: 0,
        funded_time: None,
        probe_time: 0,
        last_claim_time: 0,
        dispute_time: 0,
    }
}

async fn run_status_mock(args: StatusArgs) -> Result<()> {
    let chain = mock_chain_for_machine(args.endpoints_file)?;
    let target = resolve_mock_deal_target(&args.deal, args.deals_dir.as_deref(), None, None)?;
    let handle = target.handle.as_ref().map(|h| h.handle.clone());
    let role = target.role.map(|r| role_arg_str(r).to_string());
    let frame_model = target.frame_model.clone();
    let snapshot = chain.snapshot(&target.token_contract).await;
    if args.json {
        let response = match snapshot {
            Some(snapshot) if !snapshot.closed => {
                let s = mock_summary_from_snapshot(&snapshot);
                let state = s.kind.as_str();
                status_response_from_summary(
                    "mock",
                    handle,
                    role,
                    target.token_contract,
                    frame_model,
                    state,
                    true,
                    &s,
                )?
            }
            _ => closed_status_response("mock", handle, role, target.token_contract, frame_model)?,
        };
        return machine::print_json(&response);
    }
    match snapshot {
        Some(snapshot) if !snapshot.closed => {
            let s = mock_summary_from_snapshot(&snapshot);
            println!(
                "status handle=(raw) role=unknown token_contract={} state={} active=true funded={} opened={} disputed=false probe_accepted={}",
                addr::display_self_dapp(&target.token_contract),
                s.kind.as_str(),
                s.funded,
                s.opened,
                s.probe_accepted
            );
        }
        _ => println!(
            "status handle=(raw) role=unknown token_contract={} state=closed active=false",
            addr::display_self_dapp(&target.token_contract)
        ),
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
pub(crate) async fn run_status(args: StatusArgs) -> Result<()> {
    if args.mock_chain {
        return run_status_mock(args).await;
    }
    use dexdo_core::RealChainBackend;
    let target = load_deal_target(&args.deal, args.deals_dir.as_deref(), None, None)?;
    let contracts_path = deal_contracts_path(args.contracts.as_deref(), &target);
    let contracts = args
        .contracts
        .as_deref()
        .unwrap_or(&contracts_path)
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let chain = RealChainBackend::connect(contracts)?;
    let tc = dexdo_core::address::parse_chain_address(&target.token_contract)
        .map_err(|e| anyhow::anyhow!("token_contract {}: {e}", target.token_contract))?;
    // Read the deal BEFORE the market preflight, because a destroyed TokenContract is this
    // command's expected terminal state and not a fault. A seller handle carries a `market`, that
    // manifest pins the deal's TokenContract, and on 4.0.33 the STOP destroys that account in the
    // same transaction -- so `shellnet_doctor_preflight_market` reports it "inactive/undeployed"
    // and a seller could never read the status of his own completed deal, getting INTERNAL instead
    // of the reading canon mandates: "If the TokenContract is absent, status returns
    // `state="closed"` and `active=false`; that is not an error" (`runtime-machine-contract.md`
    // ). The closed branch below already produces exactly that; it was simply unreachable.
    // Nothing else is relaxed. The preflight still runs, unchanged, whenever the deal's account is
    // LIVE -- so a wrong code hash on a live account, a malformed manifest or a bad pin still fail
    // here exactly as before -- and an unreachable endpoint fails on this very read rather than
    // being mistaken for a closed deal. Only `status` reorders: `run_export` and every command that
    // is about to move money keep the preflight ahead of everything.
    let deal_snapshot = chain.token_contract_deal_snapshot(&tc).await?;
    if deal_snapshot.is_some() {
        shellnet_doctor_preflight_market(&contracts_path, target.market.as_ref()).await?;
    }
    let Some(snapshot) = deal_snapshot else {
        if args.json {
            return machine::print_json(&closed_status_response(
                chain.network(),
                target.handle.as_ref().map(|h| h.handle.clone()),
                target.role.map(|r| r.as_str().to_string()),
                target.token_contract,
                target.handle.as_ref().map(|h| h.frame_model.clone()),
            )?);
        }
        println!(
            "status handle={} role={} token_contract={} state=closed active=false",
            target
                .handle
                .as_ref()
                .map(|h| h.handle.as_str())
                .unwrap_or("(raw)"),
            target.role.map(|r| r.as_str()).unwrap_or("unknown"),
            addr::display_self_dapp(&target.token_contract)
        );
        return Ok(());
    };
    let s = deals::summarize_deal_snapshot(&snapshot);
    if args.json {
        return machine::print_json(&status_response_from_summary(
            chain.network(),
            target.handle.as_ref().map(|h| h.handle.clone()),
            target.role.map(|r| r.as_str().to_string()),
            target.token_contract.clone(),
            target.handle.as_ref().map(|h| h.frame_model.clone()),
            s.kind.as_str(),
            true,
            &s,
        )?);
    }
    println!(
        "status handle={} role={} token_contract={} state={} active=true funded={} opened={} disputed={} probe_accepted={}",
        target
            .handle
            .as_ref()
            .map(|h| h.handle.as_str())
            .unwrap_or("(raw)"),
        target.role.map(|r| r.as_str()).unwrap_or("unknown"),
        addr::display_self_dapp(&target.token_contract),
        s.kind.as_str(),
        s.funded,
        s.opened,
        s.disputed,
        s.probe_accepted
    );
    if let Some(h) = &target.handle {
        println!(
            "context network={} note={} model={} order_book={} root_model={}",
            h.network,
            addr::display(&h.note_addr),
            h.frame_model,
            addr::display_opt(h.order_book.as_deref(), "-"),
            addr::display_opt(h.root_model.as_deref(), "-")
        );
    }
    println!(
        "accounting finalized_owed={} buyer_locked={} deposit={} probe_tick={} buyer_bond={} \
         buyer_bond_required={} tokens_final={} \
         tokens_pending={} probe_time={} last_claim_time={} \
         dispute_time={} funded_time={}",
        s.finalized_owed,
        s.buyer_locked()?,
        s.deposit,
        s.probe_tick,
        s.buyer_bond,
        s.buyer_bond_required,
        s.tokens_final,
        s.tokens_pending,
        s.probe_time,
        s.last_claim_time,
        s.dispute_time,
        s.funded_time
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    println!(
        "{}",
        close_hint(
            &target,
            &s,
            args.deals_dir.as_deref(),
            Some(&contracts_path)
        )
    );
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_status(args: StatusArgs) -> Result<()> {
    if args.mock_chain {
        return run_status_mock(args).await;
    }
    bail!("status unavailable: build with `--features shellnet`")
}

#[cfg(feature = "shellnet")]
pub(crate) async fn run_export(args: ExportArgs) -> Result<()> {
    use dexdo_core::RealChainBackend;
    let target = load_deal_target(&args.deal, args.deals_dir.as_deref(), None, None)?;
    let contracts_path = deal_contracts_path(args.contracts.as_deref(), &target);
    shellnet_doctor_preflight_market(&contracts_path, target.market.as_ref()).await?;
    let contracts = contracts_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let chain = RealChainBackend::connect(contracts)?;
    let tc = dexdo_core::address::parse_chain_address(&target.token_contract)
        .map_err(|e| anyhow::anyhow!("token_contract {}: {e}", target.token_contract))?;
    let snapshot = chain.token_contract_deal_snapshot(&tc).await?;
    let active = snapshot.is_some();
    let state = snapshot
        .as_ref()
        .map(|snapshot| deals::deal_state_getter_json(snapshot.state));
    let summary = snapshot.as_ref().map(deals::summarize_deal_snapshot);
    let (onchain_model, onchain_model_hash, onchain_buyer_note, deal_terms) = if active {
        let model = chain.token_contract_model_name(&tc).await?;
        let model_hash = chain.token_contract_model_hash(&tc).await?;
        let buyer_note = chain
            .token_contract_buyer_note(&tc)
            .await?
            .map(|a| a.with_workchain());
        let terms = chain.token_contract_deal_terms(&tc).await?.map(
            |(tick_size, price_per_tick, max_ticks)| audit::DealTermsAudit {
                tick_size,
                price_per_tick,
                max_ticks,
            },
        );
        (model, model_hash, buyer_note, terms)
    } else {
        (None, None, None, None)
    };
    let generated_at_unix = deals::now_unix()?;
    let export = audit::build_deal_audit(audit::DealAuditBuild {
        generated_at_unix,
        handle: target.handle.clone(),
        role: target.role,
        token_contract: target.token_contract.clone(),
        note_addr: target.note_addr.clone(),
        contracts: contracts_path.display().to_string(),
        active,
        state,
        summary,
        onchain_model,
        onchain_model_hash,
        onchain_buyer_note,
        deal_terms,
    })?;
    match args.format {
        ExportFormatArg::Json => println!("{}", serde_json::to_string_pretty(&export)?),
        ExportFormatArg::Md => print!("{}", audit::render_markdown(&export)),
    }
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_export(_args: ExportArgs) -> Result<()> {
    bail!("export unavailable: build with `--features shellnet`")
}

#[cfg(test)]
mod tests {
    /// A seller handle whose market TokenContract is GONE must report the terminal deal, not fail.
    /// The seller's handle carries a `market`, that manifest pins the deal's TokenContract, and a
    /// clean close destroys that account in the same transaction. While `status` ran
    /// `shellnet_doctor_preflight_market` first, the preflight reported the pinned account
    /// "inactive/undeployed" and the command exited `INTERNAL` -- so a seller could not read the
    /// status of his own completed deal, and the `state="closed" active=false` branch canon
    /// mandates was unreachable.
    /// The oracle is the ORDER: the deal snapshot is read first, the preflight is gated on the
    /// account still being live, and the closed branch is what an absent snapshot reaches. This is
    /// a source-structure regression because the behaviour it guards is `feature = "shellnet"` and
    /// needs a live chain to exercise; the behavioural proof is the live run of
    /// `live_67_model_buyer_preserves_resting_order_identity_through_settle`.
    #[test]
    fn status_reports_a_destroyed_token_contract_as_closed_instead_of_failing_its_preflight() {
        let source = include_str!("reports.rs");
        let start = source
            .find("pub(crate) async fn run_status(args: StatusArgs)")
            .expect("shellnet run_status present");
        let end = source[start..]
            .find("#[cfg(not(feature = \"shellnet\"))]")
            .map(|offset| start + offset)
            .expect("run_status end marker present");
        let body = &source[start..end];

        let snapshot_read = body
            .find("let deal_snapshot = chain.token_contract_deal_snapshot(&tc).await?;")
            .expect("status must read the deal snapshot itself");
        let preflight = body
            .find(
                "shellnet_doctor_preflight_market(&contracts_path, target.market.as_ref()).await?",
            )
            .expect("status must still run the market preflight");
        assert!(
            snapshot_read < preflight,
            "status must read the deal BEFORE the market preflight, or a destroyed TokenContract \
             fails the preflight and the terminal reading is never reached"
        );
        assert!(
            body[snapshot_read..preflight].contains("if deal_snapshot.is_some() {"),
            "the market preflight must be gated on the deal's account still being LIVE -- it stays \
             mandatory for every live deal, and a wrong pin on a live account must still fail"
        );
        assert!(
            body.contains("let Some(snapshot) = deal_snapshot else {")
                && body.contains("state=closed active=false"),
            "an absent snapshot must fall through to the EXISTING closed branch, not a second one"
        );
        assert!(
            !body.contains(
                "shellnet_doctor_preflight_market(&contracts_path, target.market.as_ref()).await;"
            ),
            "the preflight result must stay fatal where it runs; it is gated, never ignored"
        );

        // The relaxation is scoped to `status`. Every other command keeps the preflight ahead of
        // everything it does, because there an inactive TokenContract IS a failure.
        let export = source
            .find("pub(crate) async fn run_export(args: ExportArgs)")
            .expect("shellnet run_export present");
        let export_end = source[export..]
            .find("#[cfg(not(feature = \"shellnet\"))]")
            .map(|offset| export + offset)
            .expect("run_export end marker present");
        let export_body = &source[export..export_end];
        let export_preflight = export_body
            .find("shellnet_doctor_preflight_market(")
            .expect("export keeps its market preflight");
        assert!(
            !export_body[..export_preflight].contains("token_contract_deal_snapshot"),
            "run_export must keep the market preflight ahead of its chain reads"
        );
    }

    #[test]
    fn seller_open_probe_status_waits_for_delivery_then_window() {
        let summary = crate::cli::deals::DealStateSummary {
            kind: crate::cli::deals::DealStateKind::Probe,
            funded: true,
            opened: true,
            disputed: false,
            probe_accepted: false,
            deposit: 0,
            probe_tick: 0,
            buyer_bond: 0,
            buyer_bond_required: 0,
            finalized_owed: 0,
            tokens_final: 0,
            tokens_pending: 0,
            funded_time: Some(1),
            probe_time: 1,
            last_claim_time: 1,
            dispute_time: 0,
        };
        let status = super::status_response_from_summary(
            "shellnet",
            Some("deal-seller".to_string()),
            Some("seller".to_string()),
            "0:tc".to_string(),
            Some("model".to_string()),
            "probe",
            true,
            &summary,
        )
        .expect("format seller Probe status");

        assert_eq!(status.next.action, "seller_wait_delivery_then_accept_probe");
        assert_eq!(status.next.command, "seller");
    }

    #[test]
    fn seller_streaming_status_names_current_claim_and_settlement_actions() {
        let next = super::status_next_for(Some("seller"), "streaming", true, true, true);

        assert_eq!(
            next.action,
            "seller_claim_finalize_or_settle_week_or_seller_stop"
        );
        assert_eq!(next.command, "seller");
    }

    #[test]
    fn buyer_terminal_status_does_not_recommend_cleanup() {
        let next = super::status_next_for(Some("buyer"), "stopped", true, false, false);

        assert_eq!(next.action, "none");
        assert_eq!(next.command, "none");
    }
}

/// the versioned machine schemas answer in the shape they are pinned to.
/// Ungated on purpose. The conversion it exercises has no feature of its own, so these rows run in
/// the default build too -- which is the build whose regression would otherwise be checked by
/// nothing at all.
#[cfg(test)]
mod pinned_schema_address_1419 {
    use super::pinned_schema_address;

    /// The shape that shipped the defect. `market.json` stores the canonical form, a deal handle
    /// stores whatever it was written with, and either can reach the schema builder; before this,
    /// whatever arrived was printed verbatim.
    /// Measured on the two-runner release gate, which had been red since 2026-08-10:
    /// ```text
    /// asked about 97256735...::97256735..., status answered '97256735...::97256735...'
    /// ```
    /// The same account -- so the check's identity half passed and its shape half did not.
    /// Asserted through `status_response_from_summary`, the place that BUILDS the schema, not
    /// through the helper alone: a helper that exists but is not wired in leaves the defect exactly
    /// where it was, and a test of the helper alone passes either way. (It did, on the first
    /// draft of this module.)
    #[test]
    fn the_status_schema_answers_in_the_pinned_legacy_shape_1419() {
        let account = "97256735ac843277affcb10bb22c5d3dbb415e7f2d7c199825c9d584b34aef85";
        let canonical = format!("{account}::{account}");
        let response = super::status_response_from_summary(
            "mainnet",
            None,
            Some("seller".to_string()),
            canonical,
            None,
            "closed",
            false,
            &crate::cli::deals::DealStateSummary {
                kind: crate::cli::deals::DealStateKind::Stopped,
                funded: false,
                opened: false,
                disputed: false,
                probe_accepted: false,
                deposit: 0,
                probe_tick: 0,
                buyer_bond: 0,
                buyer_bond_required: 0,
                finalized_owed: 0,
                tokens_final: 0,
                tokens_pending: 0,
                funded_time: None,
                probe_time: 0,
                last_claim_time: 0,
                dispute_time: 0,
            },
        )
        .expect("the schema is built");
        assert_eq!(
            response.token_contract,
            format!("0:{account}"),
            "`dexdo.status.v2` must answer in `0:<account_id>`, whatever form reached the command"
        );
    }

    /// Already pinned: unchanged, and in particular not double-prefixed.
    #[test]
    fn the_pinned_shape_survives_unchanged_1419() {
        let legacy = format!("0:{}", "a".repeat(64));
        assert_eq!(pinned_schema_address(&legacy), legacy);
    }

    /// The accepted forms are the two the canonical parser takes, and a bare account id is not one
    /// of them: it names no workchain and no DApp. Every production call site feeds
    /// `target.token_contract`, written canonical or legacy, so a bare id cannot reach this
    /// boundary -- and if one ever does, it stays visible rather than being coerced into an address
    /// that would name a different account than the caller meant.
    #[test]
    fn a_bare_account_id_is_not_an_accepted_form_1419() {
        let account = "b".repeat(64);
        assert_eq!(pinned_schema_address(&account), account);
    }

    /// Not an address at all: passed through, because replacing a visible oddity with an empty
    /// field or a panic hides it from the reader who has to diagnose it.
    #[test]
    fn an_unparseable_value_is_passed_through_1419() {
        assert_eq!(pinned_schema_address("not-an-address"), "not-an-address");
    }
}
