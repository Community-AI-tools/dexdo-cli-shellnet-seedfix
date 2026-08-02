//! Deal-close command handlers(Track C7, move-only).

use crate::cli::args::{CloseArgs, DealRoleArg};
#[cfg(feature = "shellnet")]
use crate::cli::commands::{
    close_hint, deal_contracts_path, load_deal_target, shellnet_doctor_preflight_market,
};
use crate::cli::commands::{mock_chain_for_machine, resolve_mock_deal_target, role_arg_str};
#[cfg(feature = "shellnet")]
use crate::cli::deals;
use crate::cli::machine;
#[cfg(feature = "shellnet")]
use crate::cli::recover::check_reclaimable_state;
#[cfg(feature = "shellnet")]
use crate::cli::support::read_secret_hex;
use anyhow::{bail, Result};
use dexdo_core::ChainBackend;

#[cfg(feature = "shellnet")]
async fn submit_then_observe_cleanup<S, SF, O, OF>(submit: S, observe: O) -> Result<()>
where
    S: FnOnce() -> SF,
    SF: std::future::Future<Output = Result<()>>,
    O: FnOnce() -> OF,
    OF: std::future::Future<Output = Result<()>>,
{
    submit().await?;
    observe().await
}

#[allow(clippy::too_many_arguments)]
fn close_response(
    network: &str,
    handle: Option<String>,
    role: &str,
    token_contract: String,
    action: &str,
    submitted: bool,
    terminal: bool,
    reason: Option<&str>,
    state_before: &str,
    state_after: &str,
) -> Result<machine::CloseResponse> {
    Ok(machine::CloseResponse {
        schema: machine::CLOSE_SCHEMA,
        network: network.to_string(),
        generated_at_unix: machine::now_unix()?,
        handle,
        role: role.to_string(),
        token_contract,
        action: action.to_string(),
        submitted,
        terminal,
        reason: reason.map(str::to_string),
        state_before: state_before.to_string(),
        state_after: state_after.to_string(),
        tx: None,
    })
}

fn confirmed_buyer_stop_response(
    network: &str,
    handle: Option<String>,
    role: &str,
    token_contract: String,
    state_before: &str,
    receipt: Option<&dexdo_core::SettlementActionReceipt>,
) -> Result<machine::CloseResponse> {
    let mut response = close_response(
        network,
        handle,
        role,
        token_contract,
        "streamStop",
        true,
        true,
        None,
        state_before,
        "stopped",
    )?;
    response.tx = receipt.map(serde_json::to_value).transpose()?;
    Ok(response)
}

#[cfg(feature = "shellnet")]
fn confirmed_buyer_stop_followup_error(
    step: &str,
    receipt: &dexdo_core::SettlementActionReceipt,
    error: anyhow::Error,
) -> anyhow::Error {
    anyhow::anyhow!(
        "buyer STOP is already confirmed on-chain; authoritative receipt={receipt}; \
         ancillary {step} failed after the receipt was rendered: {error:#}"
    )
}

#[cfg(feature = "shellnet")]
fn apply_confirmed_buyer_stop_marker<T>(
    receipt: &dexdo_core::SettlementActionReceipt,
    marker: impl FnOnce() -> Result<T>,
) -> Result<T> {
    marker().map_err(|error| {
        confirmed_buyer_stop_followup_error("local subscription marker", receipt, error)
    })
}

#[cfg(feature = "shellnet")]
fn apply_prior_stop_marker<T>(confirmation: &str, marker: impl FnOnce() -> Result<T>) -> Result<T> {
    marker().map_err(|error| {
        anyhow::anyhow!(
            "{confirmation}; local subscription marker failed during idempotent reconciliation: \
             {error:#}"
        )
    })
}

#[cfg(feature = "shellnet")]
fn confirmed_seller_stop_response(
    network: &str,
    handle: Option<String>,
    token_contract: String,
    state_before: &str,
    receipt: &dexdo_core::SettlementActionReceipt,
) -> Result<machine::CloseResponse> {
    let mut response = close_response(
        network,
        handle,
        "seller",
        token_contract,
        "sellerStop",
        true,
        true,
        None,
        state_before,
        "stopped",
    )?;
    response.tx = Some(serde_json::to_value(receipt)?);
    Ok(response)
}

#[cfg(feature = "shellnet")]
fn confirmed_seller_stop_text(
    handle: Option<&str>,
    token_contract: &str,
    note: &dexdo_core::Address,
    receipt: &dexdo_core::SettlementActionReceipt,
) -> String {
    format!(
        "close confirmed role=seller action=sellerStop handle={} token_contract={token_contract} \
         note={note} receipt={receipt}",
        handle.unwrap_or("raw-token-contract")
    )
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait]
trait SellerStopChain: Sync {
    async fn seller_pubkey(&self, token_contract: &dexdo_core::Address) -> Result<Option<String>>;

    async fn seller_stop(
        &self,
        token_contract: &dexdo_core::Address,
        seller_keys: &dexdo_core::KeyPair,
    ) -> Result<dexdo_core::SettlementActionReceipt>;
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait]
impl SellerStopChain for dexdo_core::RealChainBackend {
    async fn seller_pubkey(&self, token_contract: &dexdo_core::Address) -> Result<Option<String>> {
        Ok(self.token_contract_seller_pubkey(token_contract).await?)
    }

    async fn seller_stop(
        &self,
        token_contract: &dexdo_core::Address,
        seller_keys: &dexdo_core::KeyPair,
    ) -> Result<dexdo_core::SettlementActionReceipt> {
        Ok(dexdo_core::RealChainBackend::seller_stop(self, token_contract, seller_keys).await?)
    }
}

#[cfg(feature = "shellnet")]
async fn submit_seller_stop(
    chain: &dyn SellerStopChain,
    role: deals::DealHandleRole,
    state: dexdo_core::DealChainState,
    token_contract: &dexdo_core::Address,
    seller_keys: &dexdo_core::KeyPair,
) -> Result<dexdo_core::SettlementActionReceipt> {
    if role != deals::DealHandleRole::Seller {
        bail!(
            "close sellerStop requires seller role, got {}; refusing before any money POST",
            role.as_str()
        );
    }
    if state.disputed {
        bail!(
            "close: seller deal {token_contract} is disputed; use `dexdo release-dispute` instead of sellerStop"
        );
    }
    if !state.opened {
        bail!(
            "close: sellerStop requires an OPEN deal; TokenContract {token_contract} is not OPEN; refusing before any money POST"
        );
    }

    let seller_pubkey = chain.seller_pubkey(token_contract).await?;
    dexdo_core::check_seller_pubkey(
        "close sellerStop",
        seller_pubkey.as_deref(),
        seller_keys.public_hex(),
    )
    .map_err(anyhow::Error::msg)?;

    let receipt = chain.seller_stop(token_contract, seller_keys).await?;
    if receipt.action != dexdo_core::SettlementAction::SellerStop {
        bail!(
            "close sellerStop returned an authoritative receipt for wrong action {}",
            receipt.action
        );
    }
    let receipt_token_contract = dexdo_core::normalize_wallet_address(&receipt.token_contract)
        .map_err(anyhow::Error::msg)?;
    let expected_token_contract =
        dexdo_core::normalize_wallet_address(&token_contract.with_workchain())
            .map_err(anyhow::Error::msg)?;
    if receipt_token_contract != expected_token_contract {
        bail!(
            "close sellerStop returned an authoritative receipt for TokenContract {}, expected {}",
            receipt.token_contract,
            token_contract
        );
    }
    if !matches!(
        &receipt.event,
        dexdo_core::SettlementActionEvent::StreamStopped { .. }
    ) {
        bail!(
            "close sellerStop returned an authoritative receipt without StreamStopped: {:?}",
            receipt.event
        );
    }
    Ok(receipt)
}

async fn run_close_mock(args: CloseArgs) -> Result<()> {
    let target = resolve_mock_deal_target(
        &args.deal,
        args.deals_dir.as_deref(),
        args.role,
        args.note_addr.clone(),
    )?;
    let role = target.role.ok_or_else(|| {
        anyhow::anyhow!(
            "close: `{}` is not a local handle; pass --role buyer|seller with a raw TokenContract",
            args.deal
        )
    })?;
    if target.note_addr.is_none() {
        bail!(
            "close: `{}` is not a local handle; pass --note-addr with a raw TokenContract",
            args.deal
        );
    }
    let role_s = role_arg_str(role);
    let handle = target.handle.as_ref().map(|h| h.handle.clone());
    let chain = mock_chain_for_machine(args.endpoints_file)?;
    let snapshot = chain.checked_snapshot(&target.token_contract).await?;
    match snapshot {
        None => {
            let response = close_response(
                "mock",
                handle,
                role_s,
                target.token_contract,
                "noop",
                false,
                true,
                Some("already_closed"),
                "closed",
                "closed",
            )?;
            if args.json {
                return machine::print_json(&response);
            }
            println!(
                "close noop: TokenContract {} is inactive/closed",
                response.token_contract
            );
            Ok(())
        }
        Some(snapshot) if snapshot.closed => {
            let response = close_response(
                "mock",
                handle,
                role_s,
                target.token_contract,
                "noop",
                false,
                true,
                Some("already_stopped"),
                "stopped",
                "stopped",
            )?;
            if args.json {
                return machine::print_json(&response);
            }
            println!(
                "close noop: {} side already STOPped for {}",
                role_s, response.token_contract
            );
            Ok(())
        }
        Some(snapshot) => {
            let state_before = if snapshot.seller_received > 0 {
                "streaming"
            } else {
                "probe"
            };
            match role {
                DealRoleArg::Buyer => {
                    let note_addr = target.note_addr.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "close: `{}` has no persisted buyer note identity",
                            args.deal
                        )
                    })?;
                    chain
                        .stop_by_buyer_note_addr(&target.token_contract, note_addr)
                        .await?;
                    let response = confirmed_buyer_stop_response(
                        "mock",
                        handle,
                        role_s,
                        target.token_contract,
                        state_before,
                        None,
                    )?;
                    if args.json {
                        return machine::print_json(&response);
                    }
                    println!(
                        "close submitted role=buyer action=streamStop token_contract={}",
                        response.token_contract
                    );
                    Ok(())
                }
                DealRoleArg::Seller => {
                    let state = chain
                        .deal_state(&target.token_contract)
                        .await?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "close: sellerStop requires an OPEN deal; TokenContract {} has no authoritative mock state",
                                target.token_contract
                            )
                        })?;
                    if state.disputed {
                        bail!(
                            "close: seller deal {} is disputed; use `dexdo release-dispute` instead of sellerStop",
                            target.token_contract
                        );
                    }
                    if !state.opened {
                        bail!(
                            "close: sellerStop requires an OPEN deal; TokenContract {} is not OPEN",
                            target.token_contract
                        );
                    }

                    let settlement = chain.seller_stop(&target.token_contract).await?;
                    let response = close_response(
                        "mock",
                        handle,
                        role_s,
                        target.token_contract,
                        "sellerStop",
                        true,
                        true,
                        None,
                        state_before,
                        "stopped",
                    )?;
                    if args.json {
                        return machine::print_json(&response);
                    }
                    println!(
                        "close confirmed role=seller action=sellerStop token_contract={} mock_settlement={settlement}",
                        response.token_contract
                    );
                    Ok(())
                }
            }
        }
    }
}

#[cfg(feature = "shellnet")]
pub(crate) async fn run_close(args: CloseArgs) -> Result<()> {
    if args.mock_chain {
        return run_close_mock(args).await;
    }
    use dexdo_core::{check_recoverable, keypair_ed_pubkey, KeyPair, RealChainBackend};
    let target = load_deal_target(
        &args.deal,
        args.deals_dir.as_deref(),
        args.role,
        args.note_addr.clone(),
    )?;
    let role = target.role.ok_or_else(|| {
        anyhow::anyhow!(
            "close: `{}` is not a local handle; pass --role buyer|seller with a raw TokenContract",
            args.deal
        )
    })?;
    let note_addr = target.note_addr.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "close: `{}` is not a local handle; pass --note-addr with a raw TokenContract",
            args.deal
        )
    })?;
    let contracts_path = deal_contracts_path(args.contracts.as_deref(), &target);
    shellnet_doctor_preflight_market(&contracts_path, target.market.as_ref()).await?;
    let contracts = args
        .contracts
        .as_deref()
        .unwrap_or(&contracts_path)
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let chain = RealChainBackend::connect(contracts)?;
    let tc = dexdo_core::address::parse_chain_address(&target.token_contract)
        .map_err(|e| anyhow::anyhow!("token_contract {}: {e}", target.token_contract))?;
    if role == deals::DealHandleRole::Buyer {
        let note = dexdo_core::address::parse_chain_address(&note_addr)
            .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
        let receipts = chain.token_contract_settlement_receipts(&tc).await?;
        if let Some(receipt) =
            super::recover::exact_prior_stop_receipt(&receipts, &note.with_workchain())?
        {
            let confirmation =
                super::recover::prior_stop_confirmation("close", &tc, &note, &receipt);
            if args.json {
                let mut response = close_response(
                    "shellnet",
                    target.handle.as_ref().map(|h| h.handle.clone()),
                    role.as_str(),
                    target.token_contract.clone(),
                    "noop",
                    false,
                    true,
                    Some("already_terminal_receipt"),
                    "closed",
                    "closed",
                )?;
                response.tx = Some(super::recover::prior_stop_receipt_json(&tc, &receipt));
                machine::print_json(&response)?;
            } else {
                println!("{confirmation}");
            }
            apply_prior_stop_marker(&confirmation, || {
                super::buyer::mark_buyer_subscription_terminal(
                    &note.with_workchain(),
                    &tc.with_workchain(),
                )
            })?;
            return Ok(());
        }
    }
    let Some(snapshot) = chain.token_contract_deal_snapshot(&tc).await? else {
        if args.json {
            return machine::print_json(&close_response(
                "shellnet",
                target.handle.as_ref().map(|h| h.handle.clone()),
                role.as_str(),
                target.token_contract,
                "noop",
                false,
                true,
                Some("already_closed"),
                "closed",
                "closed",
            )?);
        }
        println!(
            "close noop: TokenContract {} is inactive/closed",
            target.token_contract
        );
        return Ok(());
    };
    let s = deals::summarize_deal_snapshot(&snapshot);
    match role {
        deals::DealHandleRole::Seller => {
            if s.disputed {
                bail!(
                    "close: seller deal {} is disputed. Next command: `dexdo release-dispute \
                     --token-contract {}`.",
                    target.token_contract,
                    target.token_contract
                );
            }
            if s.opened {
                let note_key = args.note_key.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("close seller requires --note-key to sign sellerStop")
                })?;
                let keys =
                    KeyPair::from_secret_hex(read_secret_hex(note_key, "--note-key")?.trim())
                        .map_err(|e| anyhow::anyhow!("--note-key (SDK secret hex): {e:?}"))?;
                let note = dexdo_core::address::parse_chain_address(&note_addr)
                    .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
                let receipt = submit_seller_stop(&chain, role, snapshot.state, &tc, &keys).await?;
                let handle = target.handle.as_ref().map(|h| h.handle.clone());
                if args.json {
                    return machine::print_json(&confirmed_seller_stop_response(
                        "shellnet",
                        handle,
                        target.token_contract.clone(),
                        s.kind.as_str(),
                        &receipt,
                    )?);
                }
                println!(
                    "{}",
                    confirmed_seller_stop_text(
                        handle.as_deref(),
                        &target.token_contract,
                        &note,
                        &receipt,
                    )
                );
                return Ok(());
            }
            if s.kind != deals::DealStateKind::Stopped {
                bail!("{}", close_hint(&target, &s));
            }
            let note_key = args.note_key.as_deref().ok_or_else(|| {
                anyhow::anyhow!("close seller requires --note-key to sign destroy")
            })?;
            let keys = KeyPair::from_secret_hex(read_secret_hex(note_key, "--note-key")?.trim())
                .map_err(|e| anyhow::anyhow!("--note-key (SDK secret hex): {e:?}"))?;
            let note = dexdo_core::address::parse_chain_address(&note_addr)
                .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
            chain.destroy_token_contract(&tc, &note, &keys).await?;
            if args.json {
                return machine::print_json(&close_response(
                    "shellnet",
                    target.handle.as_ref().map(|h| h.handle.clone()),
                    role.as_str(),
                    target.token_contract.clone(),
                    "destroy",
                    true,
                    true,
                    None,
                    s.kind.as_str(),
                    "closed",
                )?);
            }
            println!(
                "close submitted role=seller action=destroy token_contract={} note={}",
                target.token_contract, note
            );
        }
        deals::DealHandleRole::Buyer => {
            if s.disputed {
                super::buyer::mark_buyer_subscription_terminal(&note_addr, &tc.with_workchain())?;
                bail!(
                    "close: buyer deal {} is disputed; wait for seller release/arbitration (), then re-run status.",
                    target.token_contract
                );
            }
            if s.kind == deals::DealStateKind::Stopped {
                super::buyer::mark_buyer_subscription_terminal(&note_addr, &tc.with_workchain())?;
                if args.json {
                    return machine::print_json(&close_response(
                        "shellnet",
                        target.handle.as_ref().map(|h| h.handle.clone()),
                        role.as_str(),
                        target.token_contract.clone(),
                        "noop",
                        false,
                        true,
                        Some("already_stopped"),
                        "stopped",
                        "stopped",
                    )?);
                }
                println!(
                    "close noop: buyer side already STOPped for {}. Next: seller runs `dexdo close <seller-handle> --note-key <seller-key>`.",
                    target.token_contract
                );
                return Ok(());
            }
            let note_key = args.note_key.as_deref().ok_or_else(|| {
                anyhow::anyhow!("close buyer requires --note-key to sign note owner method")
            })?;
            let keys = KeyPair::from_secret_hex(read_secret_hex(note_key, "--note-key")?.trim())
                .map_err(|e| anyhow::anyhow!("--note-key (SDK secret hex): {e:?}"))?;
            let note = dexdo_core::address::parse_chain_address(&note_addr)
                .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
            let buyer_note = chain.token_contract_buyer_note(&tc).await?;
            let buyer_note_s = buyer_note.as_ref().map(|a| a.with_workchain());
            let buyer_pubkey = chain.token_contract_buyer_pubkey(&tc).await?;
            let note_ed = keypair_ed_pubkey(&keys)?;
            if s.opened {
                check_recoverable(
                    s.opened,
                    s.disputed,
                    buyer_note_s.as_deref(),
                    &note.with_workchain(),
                    buyer_pubkey.as_ref(),
                    &note_ed,
                )
                .map_err(anyhow::Error::msg)?;
                let settlement = chain.explicit_buyer_stop(&note, &keys, &tc).await?;
                let receipt = match settlement {
                    dexdo_core::Settlement::AuthoritativeReceipt(receipt) => *receipt,
                    projected => {
                        bail!(
                            "close buyer STOP returned non-authoritative settlement projection: {projected:?}"
                        )
                    }
                };
                if args.json {
                    machine::print_json(&confirmed_buyer_stop_response(
                        "shellnet",
                        target.handle.as_ref().map(|h| h.handle.clone()),
                        role.as_str(),
                        target.token_contract.clone(),
                        s.kind.as_str(),
                        Some(&receipt),
                    )?)?;
                } else {
                    println!(
                        "close confirmed role=buyer action=streamStop token_contract={} note={} receipt={receipt}",
                        target.token_contract, note,
                    );
                }

                apply_confirmed_buyer_stop_marker(&receipt, || {
                    super::buyer::mark_buyer_subscription_terminal(
                        &note.with_workchain(),
                        &tc.with_workchain(),
                    )
                })?;
                return Ok(());
            }
            if s.funded && !s.probe_accepted {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| anyhow::anyhow!("system clock before epoch: {e}"))?
                    .as_secs();
                check_reclaimable_state(
                    snapshot.state,
                    buyer_note_s.as_deref(),
                    &note.with_workchain(),
                    buyer_pubkey.as_ref(),
                    &note_ed,
                    now,
                )
                .map_err(|e| {
                    anyhow::anyhow!(
                        "{e}. Next: re-run `dexdo close {}` after MATCH_OPEN_TIMEOUT, or inspect with `dexdo status {}`.",
                        args.deal,
                        args.deal
                    )
                })?;
                submit_then_observe_cleanup(
                    || async {
                        chain.stream_cleanup(&note, &keys, &tc).await?;
                        Ok(())
                    },
                    || async { chain.wait_cleanup_unopened(&tc).await.map_err(Into::into) },
                )
                .await?;
                super::buyer::mark_buyer_subscription_terminal(
                    &note.with_workchain(),
                    &tc.with_workchain(),
                )?;
                if args.json {
                    return machine::print_json(&close_response(
                        "shellnet",
                        target.handle.as_ref().map(|h| h.handle.clone()),
                        role.as_str(),
                        target.token_contract.clone(),
                        "streamCleanup",
                        true,
                        true,
                        None,
                        s.kind.as_str(),
                        "closed",
                    )?);
                }
                println!(
                    "close confirmed role=buyer action=streamCleanup token_contract={} note={}",
                    target.token_contract, note
                );
                return Ok(());
            }
            bail!("{}", close_hint(&target, &s));
        }
    }
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_close(args: CloseArgs) -> Result<()> {
    if args.mock_chain {
        return run_close_mock(args).await;
    }
    bail!("close unavailable: build with `--features shellnet`")
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "shellnet")]
    fn seller_stop_receipt(token_contract: &str) -> dexdo_core::SettlementActionReceipt {
        dexdo_core::SettlementActionReceipt {
            token_contract: token_contract.to_string(),
            action: dexdo_core::SettlementAction::SellerStop,
            message_id: "seller-stop-message".to_string(),
            created_at: 43,
            event: dexdo_core::SettlementActionEvent::StreamStopped {
                buyer: format!("0:{}", "44".repeat(32)),
                to_seller: 7u128.into(),
                refund_to_buyer: 11u128.into(),
            },
            pre_bonds: dexdo_core::SettlementActionBondState {
                seller_bond_held: 2u128.into(),
                seller_bond_required: 2u128.into(),
                buyer_bond_held: 0u128.into(),
                buyer_bond_required: 0u128.into(),
            },
            post_state: Some(dexdo_core::SettlementActionPostState {
                tokens_final: 3u128.into(),
                tokens_superseded: 4u128.into(),
                tokens_pending: 5u128.into(),
                seller_bond_held: 0u128.into(),
                seller_bond_required: 2u128.into(),
                buyer_bond_held: 0u128.into(),
                buyer_bond_required: 0u128.into(),
                opened: false,
                disputed: false,
            }),
        }
    }

    #[cfg(feature = "shellnet")]
    fn deal_state(opened: bool, disputed: bool) -> dexdo_core::DealChainState {
        dexdo_core::DealChainState {
            funded: true,
            opened,
            probe_accepted: opened,
            disputed,
            deposit: 12,
            finalized_owed: 0,
            tokens_final: 3,
            tokens_superseded: 4,
            tokens_pending: 5,
            probe_tick: 0,
            funded_time: Some(1),
            probe_time: 2,
            prev_claim_time: 3,
            last_claim_time: 4,
            dispute_time: if disputed { 5 } else { 0 },
        }
    }

    #[cfg(feature = "shellnet")]
    struct FakeSellerStopChain {
        seller_pubkey: Option<String>,
        receipt: dexdo_core::SettlementActionReceipt,
        pubkey_reads: std::sync::atomic::AtomicUsize,
        submits: std::sync::atomic::AtomicUsize,
    }

    #[cfg(feature = "shellnet")]
    impl FakeSellerStopChain {
        fn new(
            seller_pubkey: Option<String>,
            receipt: dexdo_core::SettlementActionReceipt,
        ) -> Self {
            Self {
                seller_pubkey,
                receipt,
                pubkey_reads: std::sync::atomic::AtomicUsize::new(0),
                submits: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    #[cfg(feature = "shellnet")]
    #[async_trait::async_trait]
    impl super::SellerStopChain for FakeSellerStopChain {
        async fn seller_pubkey(
            &self,
            _token_contract: &dexdo_core::Address,
        ) -> anyhow::Result<Option<String>> {
            self.pubkey_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.seller_pubkey.clone())
        }

        async fn seller_stop(
            &self,
            _token_contract: &dexdo_core::Address,
            _seller_keys: &dexdo_core::KeyPair,
        ) -> anyhow::Result<dexdo_core::SettlementActionReceipt> {
            self.submits
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.receipt.clone())
        }
    }

    #[test]
    fn confirmed_buyer_stop_json_contains_the_authoritative_receipt() {
        let receipt = dexdo_core::SettlementActionReceipt {
            token_contract: "0:tc".to_string(),
            action: dexdo_core::SettlementAction::BuyerStop,
            message_id: "stop-message".to_string(),
            created_at: 42,
            event: dexdo_core::SettlementActionEvent::StreamStopped {
                buyer: format!("0:{}", "44".repeat(32)),
                to_seller: u128::MAX.into(),
                refund_to_buyer: (u64::MAX as u128 + 1).into(),
            },
            pre_bonds: dexdo_core::SettlementActionBondState {
                seller_bond_held: 2u128.into(),
                seller_bond_required: 2u128.into(),
                buyer_bond_held: 0u128.into(),
                buyer_bond_required: 0u128.into(),
            },
            post_state: Some(dexdo_core::SettlementActionPostState {
                tokens_final: 3u128.into(),
                tokens_superseded: 4u128.into(),
                tokens_pending: 5u128.into(),
                seller_bond_held: 0u128.into(),
                seller_bond_required: 2u128.into(),
                buyer_bond_held: 0u128.into(),
                buyer_bond_required: 0u128.into(),
                opened: false,
                disputed: false,
            }),
        };
        let response = super::confirmed_buyer_stop_response(
            "shellnet",
            Some("buyer-1".to_string()),
            "buyer",
            "0:tc".to_string(),
            "streaming",
            Some(&receipt),
        )
        .unwrap();
        assert_eq!(response.action, "streamStop");
        assert!(response.submitted);
        assert!(response.terminal);
        assert_eq!(response.state_before, "streaming");
        assert_eq!(response.state_after, "stopped");
        let tx = response.tx.expect("authoritative receipt in tx");
        assert_eq!(tx["action"], serde_json::json!("buyer_stop"));
        assert_eq!(tx["message_id"], serde_json::json!("stop-message"));
        assert_eq!(tx["created_at"], serde_json::json!(42));
        assert_eq!(tx["toSeller"], serde_json::json!(u128::MAX.to_string()));
        assert_eq!(
            tx["refundToBuyer"],
            serde_json::json!((u64::MAX as u128 + 1).to_string())
        );
        assert_eq!(tx["post_state"]["tokensFinal"], serde_json::json!("3"));
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn seller_stop_rejects_wrong_role_key_and_non_open_state_before_submit() {
        use std::sync::atomic::Ordering;

        let token_contract =
            dexdo_core::Address::parse(&format!("0:{}", "33".repeat(32))).expect("token contract");
        let keys = dexdo_core::KeyPair::generate();
        let receipt = seller_stop_receipt(&token_contract.with_workchain());

        let right_key_chain =
            FakeSellerStopChain::new(Some(keys.public_hex().to_string()), receipt.clone());
        let wrong_role = super::submit_seller_stop(
            &right_key_chain,
            crate::cli::deals::DealHandleRole::Buyer,
            deal_state(true, false),
            &token_contract,
            &keys,
        )
        .await
        .expect_err("buyer role must never reach sellerStop");
        assert!(wrong_role.to_string().contains("requires seller role"));
        assert_eq!(right_key_chain.pubkey_reads.load(Ordering::SeqCst), 0);
        assert_eq!(right_key_chain.submits.load(Ordering::SeqCst), 0);

        for (state, expected) in [
            (deal_state(false, false), "requires an OPEN deal"),
            (deal_state(true, true), "is disputed"),
        ] {
            let error = super::submit_seller_stop(
                &right_key_chain,
                crate::cli::deals::DealHandleRole::Seller,
                state,
                &token_contract,
                &keys,
            )
            .await
            .expect_err("invalid sellerStop state must fail before submit");
            assert!(error.to_string().contains(expected), "{error:#}");
        }
        assert_eq!(right_key_chain.pubkey_reads.load(Ordering::SeqCst), 0);
        assert_eq!(right_key_chain.submits.load(Ordering::SeqCst), 0);

        let wrong_key_chain = FakeSellerStopChain::new(
            Some(dexdo_core::KeyPair::generate().public_hex().to_string()),
            receipt,
        );
        let wrong_key = super::submit_seller_stop(
            &wrong_key_chain,
            crate::cli::deals::DealHandleRole::Seller,
            deal_state(true, false),
            &token_contract,
            &keys,
        )
        .await
        .expect_err("wrong seller key must fail before submit");
        assert!(
            wrong_key
                .to_string()
                .contains("is not the deal's seller key"),
            "{wrong_key:#}"
        );
        assert_eq!(wrong_key_chain.pubkey_reads.load(Ordering::SeqCst), 1);
        assert_eq!(wrong_key_chain.submits.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn seller_close_submits_exact_selector_and_renders_authoritative_receipt() {
        use std::sync::atomic::Ordering;

        let token_contract =
            dexdo_core::Address::parse(&format!("0:{}", "33".repeat(32))).expect("token contract");
        let seller_note =
            dexdo_core::Address::parse(&format!("0:{}", "55".repeat(32))).expect("seller note");
        let keys = dexdo_core::KeyPair::generate();
        let chain = FakeSellerStopChain::new(
            Some(keys.public_hex().to_string()),
            seller_stop_receipt(&token_contract.with_workchain()),
        );
        let receipt = super::submit_seller_stop(
            &chain,
            crate::cli::deals::DealHandleRole::Seller,
            deal_state(true, false),
            &token_contract,
            &keys,
        )
        .await
        .expect("sellerStop");
        assert_eq!(chain.pubkey_reads.load(Ordering::SeqCst), 1);
        assert_eq!(chain.submits.load(Ordering::SeqCst), 1);
        assert_eq!(receipt.action, dexdo_core::SettlementAction::SellerStop);

        let response = super::confirmed_seller_stop_response(
            "shellnet",
            Some("deal-seller-1".to_string()),
            token_contract.with_workchain(),
            "streaming",
            &receipt,
        )
        .expect("JSON response");
        assert_eq!(response.handle.as_deref(), Some("deal-seller-1"));
        assert_eq!(response.role, "seller");
        assert_eq!(response.action, "sellerStop");
        assert!(response.submitted);
        assert!(response.terminal);
        assert_eq!(response.state_before, "streaming");
        assert_eq!(response.state_after, "stopped");
        let tx = response.tx.expect("authoritative receipt in tx");
        assert_eq!(tx["action"], serde_json::json!("seller_stop"));
        assert_eq!(tx["message_id"], serde_json::json!("seller-stop-message"));
        assert_eq!(tx["event_kind"], serde_json::json!("stream_stopped"));
        assert_eq!(tx["toSeller"], serde_json::json!("7"));
        assert_eq!(tx["refundToBuyer"], serde_json::json!("11"));

        let text = super::confirmed_seller_stop_text(
            Some("deal-seller-1"),
            &token_contract.with_workchain(),
            &seller_note,
            &receipt,
        );
        assert!(text.contains("role=seller action=sellerStop"), "{text}");
        assert!(text.contains("handle=deal-seller-1"), "{text}");
        assert!(
            text.contains(&format!(
                "token_contract={}",
                token_contract.with_workchain()
            )),
            "{text}"
        );
        assert!(text.contains("action=seller_stop"), "{text}");
        assert!(text.contains("event_kind=stream_stopped"), "{text}");
        assert!(text.contains("toSeller=7 refundToBuyer=11"), "{text}");
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn production_seller_close_routes_through_existing_seller_stop_selector() {
        let source = include_str!("close.rs");
        let seller = source
            .find("deals::DealHandleRole::Seller =>")
            .expect("seller close branch");
        let buyer = source[seller..]
            .find("deals::DealHandleRole::Buyer =>")
            .map(|offset| seller + offset)
            .expect("buyer close branch");
        let body = &source[seller..buyer];
        assert!(
            body.contains("submit_seller_stop(&chain, role, snapshot.state, &tc, &keys).await?")
        );
        assert!(!body.contains("seller cannot destroy opened deal"));
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn destroyed_after_stop_still_attempts_the_terminal_marker_and_preserves_receipt_on_error() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let receipt = dexdo_core::SettlementActionReceipt {
            token_contract: "0:tc".to_string(),
            action: dexdo_core::SettlementAction::BuyerStop,
            message_id: "landed-stop-message".to_string(),
            created_at: 77,
            event: dexdo_core::SettlementActionEvent::ProbeBurned {
                buyer: format!("0:{}", "55".repeat(32)),
                burned_probe: 11u128.into(),
                burned_bond: 12u128.into(),
                refund_to_buyer: 22u128.into(),
            },
            pre_bonds: dexdo_core::SettlementActionBondState {
                seller_bond_held: 2u128.into(),
                seller_bond_required: 2u128.into(),
                buyer_bond_held: 0u128.into(),
                buyer_bond_required: 0u128.into(),
            },
            post_state: None,
        };
        let marker_calls = AtomicUsize::new(0);
        let error = super::apply_confirmed_buyer_stop_marker(&receipt, || {
            marker_calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(anyhow::anyhow!("durable marker write failed"))
        })
        .expect_err("destroyed TC must not suppress the receipt-driven marker")
        .to_string();
        assert_eq!(marker_calls.load(Ordering::SeqCst), 1);
        for fact in [
            "already confirmed on-chain",
            "action=buyer_stop",
            "message_id=landed-stop-message",
            "created_at=77",
            "burnedProbe=11",
            "burnedBond=12",
            "refundToBuyer=22",
            "local subscription marker",
            "durable marker write failed",
        ] {
            assert!(error.contains(fact), "missing {fact:?} in {error}");
        }

        let source = include_str!("close.rs");
        let stop = source
            .find(".explicit_buyer_stop(&note, &keys, &tc)")
            .expect("buyer STOP submission");
        let tail = &source[stop..];
        let render = tail
            .find("confirmed_buyer_stop_response(")
            .expect("authoritative receipt renderer");
        let marker = tail
            .find("apply_confirmed_buyer_stop_marker(")
            .expect("receipt-driven terminal marker");
        assert!(
            render < marker,
            "the authoritative receipt must render before the fallible local marker"
        );
        assert!(
            !tail[..marker].contains(".token_contract_deal_snapshot(&tc)"),
            "no redundant post-receipt getter may gate the terminal marker"
        );
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn destroyed_close_retry_reconciles_marker_without_a_second_stop() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let buyer = format!("0:{}", "55".repeat(32));
        let landed = dexdo_core::SettlementActionReceipt {
            token_contract: format!("0:{}", "22".repeat(32)),
            action: dexdo_core::SettlementAction::BuyerStop,
            message_id: "landed-stop".to_string(),
            created_at: 77,
            event: dexdo_core::SettlementActionEvent::StreamStopped {
                buyer: buyer.clone(),
                to_seller: 11u128.into(),
                refund_to_buyer: 22u128.into(),
            },
            pre_bonds: dexdo_core::SettlementActionBondState {
                seller_bond_held: 2u128.into(),
                seller_bond_required: 2u128.into(),
                buyer_bond_held: 0u128.into(),
                buyer_bond_required: 0u128.into(),
            },
            post_state: None,
        };
        let stop_calls = AtomicUsize::new(1);
        let marker_calls = AtomicUsize::new(0);
        let first = super::apply_confirmed_buyer_stop_marker(&landed, || {
            marker_calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(anyhow::anyhow!("first marker failure"))
        })
        .expect_err("the initial post-receipt marker fails");
        assert!(first.to_string().contains("landed-stop"));

        let receipts = dexdo_core::TokenContractSettlementReceipts {
            events: vec![dexdo_core::TokenContractSettlementReceipt {
                message_id: "landed-stop".to_string(),
                created_at: 77,
                cursor: "landed-stop-cursor".to_string(),
                event: dexdo_core::TokenContractSettlementEvent::StreamStopped {
                    buyer,
                    to_seller: 11,
                    refund_to_buyer: 22,
                },
            }],
        };
        let prior = crate::cli::recover::exact_prior_stop_receipt(
            &receipts,
            &format!("0:{}", "55".repeat(32)),
        )
        .unwrap()
        .expect("immutable STOP survives TokenContract destruction");
        let tc = dexdo_core::Address::parse(&landed.token_contract).unwrap();
        let note = dexdo_core::Address::parse(&format!("0:{}", "55".repeat(32))).unwrap();
        let confirmation =
            crate::cli::recover::prior_stop_confirmation("close", &tc, &note, &prior);
        super::apply_prior_stop_marker(&confirmation, || {
            marker_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .expect("retry performs only local reconciliation");
        assert_eq!(stop_calls.load(Ordering::SeqCst), 1);
        assert_eq!(marker_calls.load(Ordering::SeqCst), 2);
        assert!(confirmation.contains("no second STOP was submitted"));
        let json = crate::cli::recover::prior_stop_receipt_json(&tc, &prior);
        assert_eq!(json["action"], "terminal_stop_reconciliation");
        assert_eq!(json["message_id"], "landed-stop");
        assert_eq!(json["event_kind"], "stream_stopped");
        assert_eq!(json["buyer"], format!("0:{}", "55".repeat(32)));
        assert_eq!(json["toSeller"], "11");
        assert_eq!(json["refundToBuyer"], "22");
        assert!(
            json.get("event").is_none(),
            "Debug event strings are forbidden"
        );

        let source = include_str!("close.rs");
        let retry = source
            .find("if role == deals::DealHandleRole::Buyer {")
            .expect("buyer immutable-receipt retry path");
        let tail = &source[retry..];
        let history = tail
            .find("token_contract_settlement_receipts(&tc)")
            .expect("immutable history read");
        let marker = tail
            .find("apply_prior_stop_marker(")
            .expect("local marker retry");
        let state = tail
            .find("token_contract_deal_snapshot(&tc)")
            .expect("live state read");
        assert!(history < marker && marker < state);
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn shellnet_buyer_close_routes_through_shared_explicit_stop() {
        let source = include_str!("close.rs");
        let buyer = source
            .find("deals::DealHandleRole::Buyer =>")
            .expect("buyer close branch");
        let end = source[buyer..]
            .find("#[cfg(not(feature = \"shellnet\"))]")
            .map(|offset| buyer + offset)
            .expect("end of shellnet close implementation");
        let body = &source[buyer..end];
        assert!(body.contains(".explicit_buyer_stop(&note, &keys, &tc)"));
        assert!(!body.contains("chain.stream_stop(&note, &keys, &tc)"));
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn stream_cleanup_submits_exactly_once_while_confirmation_only_observes() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let submits = AtomicUsize::new(0);
        let observations = AtomicUsize::new(0);
        super::submit_then_observe_cleanup(
            || async {
                submits.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            || async {
                observations.fetch_add(3, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(submits.load(Ordering::SeqCst), 1);
        assert_eq!(observations.load(Ordering::SeqCst), 3);
    }
}
