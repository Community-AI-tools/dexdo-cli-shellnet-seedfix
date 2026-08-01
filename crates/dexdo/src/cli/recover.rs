//! `dexdo` pool-recovery command handlers(`recover`/`dispute`/`reclaim`/`release-dispute`/`withdraw-shell`),
//! extracted from `commands.rs`(move-only / behavior-identical, anti-entropy refactor Track C2).

use crate::cli::args::{
    DisputeArgs, ReclaimArgs, RecoverArgs, ReleaseDisputeArgs, ResolveDisputeTimeoutArgs,
    WithdrawShellArgs,
};
use anyhow::Result;

#[cfg(feature = "shellnet")]
use crate::cli::commands::{persist_pool_recovery_record, resolve_pool_recovery_inputs};
#[cfg(feature = "shellnet")]
use crate::cli::support::{load_market, read_secret_hex, resolve_market_fields};
#[cfg(not(feature = "shellnet"))]
use anyhow::bail;
#[cfg(feature = "shellnet")]
use serde_json::Value;

/// recover an orphaned OPEN deal. The buyer process died mid-stream but the buyer note/key are intact,
/// so no one sent STOP and the deal hangs OPEN(the seller cannot `destroy` an `_opened` deal). `recover`
/// signs the **normal buyer-STOP** (`streamStop(tokenContract)` -> `TokenContract.stop()`, standard
/// split) from the buyer note -- it does NOT place a new buy -- after which the seller `destroy`s the TC.
/// Fails closed(before sending STOP) if the deal is not `_opened`, is `_disputed`, or the note is not the
/// deal's recorded buyer; the on-chain `TC.stop()` also enforces `msg.sender == _buyer`.
#[cfg(feature = "shellnet")]
#[async_trait::async_trait]
trait RecoverChain: Sync {
    async fn state(&self, tc: &dexdo_core::Address) -> Result<Option<dexdo_core::DealChainState>>;
    async fn buyer_note(&self, tc: &dexdo_core::Address) -> Result<Option<dexdo_core::Address>>;
    async fn buyer_pubkey(&self, tc: &dexdo_core::Address) -> Result<Option<[u8; 32]>>;
    async fn stop(
        &self,
        note: &dexdo_core::Address,
        keys: &dexdo_core::KeyPair,
        tc: &dexdo_core::Address,
    ) -> Result<dexdo_core::SettlementActionReceipt>;
    async fn settlement_receipts(
        &self,
        tc: &dexdo_core::Address,
    ) -> Result<dexdo_core::TokenContractSettlementReceipts>;
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait]
impl RecoverChain for dexdo_core::RealChainBackend {
    async fn state(&self, tc: &dexdo_core::Address) -> Result<Option<dexdo_core::DealChainState>> {
        Ok(self
            .token_contract_deal_snapshot(tc)
            .await?
            .map(|snapshot| snapshot.state))
    }

    async fn buyer_note(&self, tc: &dexdo_core::Address) -> Result<Option<dexdo_core::Address>> {
        Ok(self.token_contract_buyer_note(tc).await?)
    }

    async fn buyer_pubkey(&self, tc: &dexdo_core::Address) -> Result<Option<[u8; 32]>> {
        Ok(self.token_contract_buyer_pubkey(tc).await?)
    }

    async fn stop(
        &self,
        note: &dexdo_core::Address,
        keys: &dexdo_core::KeyPair,
        tc: &dexdo_core::Address,
    ) -> Result<dexdo_core::SettlementActionReceipt> {
        match self.explicit_buyer_stop(note, keys, tc).await? {
            dexdo_core::Settlement::AuthoritativeReceipt(receipt) => Ok(*receipt),
            settlement => Err(anyhow::anyhow!(
                "recover STOP returned non-authoritative settlement projection: {settlement:?}"
            )),
        }
    }

    async fn settlement_receipts(
        &self,
        tc: &dexdo_core::Address,
    ) -> Result<dexdo_core::TokenContractSettlementReceipts> {
        Ok(self.token_contract_settlement_receipts(tc).await?)
    }
}

#[cfg(feature = "shellnet")]
pub(crate) fn exact_prior_stop_receipt(
    receipts: &dexdo_core::TokenContractSettlementReceipts,
    expected_buyer: &str,
) -> Result<Option<dexdo_core::TokenContractSettlementReceipt>> {
    // Historical settlement events prove terminality, not necessarily who submitted the action.
    // In particular, `StreamStopped.buyer` is the settlement beneficiary for both `stop()` and
    // `sellerStop()`; it must never be interpreted as the action actor.
    let actions = receipts
        .events
        .iter()
        .filter(|receipt| {
            matches!(
                receipt.event,
                dexdo_core::TokenContractSettlementEvent::ProbeBurned { .. }
                    | dexdo_core::TokenContractSettlementEvent::StreamStopped { .. }
                    | dexdo_core::TokenContractSettlementEvent::StreamDisputed { .. }
                    | dexdo_core::TokenContractSettlementEvent::DisputeResolved { .. }
            )
        })
        .collect::<Vec<_>>();
    let stops = actions
        .iter()
        .filter(|receipt| {
            matches!(
                receipt.event,
                dexdo_core::TokenContractSettlementEvent::ProbeBurned { .. }
                    | dexdo_core::TokenContractSettlementEvent::StreamStopped { .. }
            )
        })
        .collect::<Vec<_>>();
    if stops.is_empty() {
        return Ok(None);
    }
    if actions.len() != 1 || stops.len() != 1 {
        anyhow::bail!(
            "prior settlement history contains a STOP mixed with another action; refusing local \
             terminal reconciliation"
        );
    }
    let observed_beneficiary = match &stops[0].event {
        dexdo_core::TokenContractSettlementEvent::ProbeBurned { buyer, .. }
        | dexdo_core::TokenContractSettlementEvent::StreamStopped { buyer, .. } => buyer,
        _ => unreachable!("stops contains only buyer-bearing STOP events"),
    };
    let observed = dexdo_core::normalize_wallet_address(observed_beneficiary)
        .map_err(|error| anyhow::anyhow!("prior terminal receipt beneficiary: {error}"))?;
    let expected = dexdo_core::normalize_wallet_address(expected_buyer)
        .map_err(|error| anyhow::anyhow!("local buyer note: {error}"))?;
    if observed != expected {
        anyhow::bail!(
            "prior terminal receipt beneficiary {observed} does not match local buyer note {expected}; \
             refusing local reconciliation"
        );
    }
    Ok(Some((*stops[0]).clone()))
}

#[cfg(feature = "shellnet")]
pub(crate) fn prior_stop_receipt_json(
    tc: &dexdo_core::Address,
    receipt: &dexdo_core::TokenContractSettlementReceipt,
) -> serde_json::Value {
    let mut value = serde_json::json!({
        "token_contract": tc.with_workchain(),
        "action": "terminal_stop_reconciliation",
        "message_id": receipt.message_id,
        "created_at": receipt.created_at,
    });
    let fields = match &receipt.event {
        dexdo_core::TokenContractSettlementEvent::ProbeBurned {
            buyer,
            burned_probe,
            burned_bond,
            refund_to_buyer,
        } => serde_json::json!({
            "event_kind": "probe_burned",
            "action_attribution": "buyer_stop",
            "buyer": buyer,
            "burnedProbe": burned_probe.to_string(),
            "burnedBond": burned_bond.to_string(),
            "refundToBuyer": refund_to_buyer.to_string(),
        }),
        dexdo_core::TokenContractSettlementEvent::StreamStopped {
            buyer,
            to_seller,
            refund_to_buyer,
        } => serde_json::json!({
            "event_kind": "stream_stopped",
            "action_attribution": "unknown_buyer_stop_or_seller_stop",
            "buyer": buyer,
            "toSeller": to_seller.to_string(),
            "refundToBuyer": refund_to_buyer.to_string(),
        }),
        _ => unreachable!("prior_stop_receipt_json receives only exact STOP receipts"),
    };
    value
        .as_object_mut()
        .expect("receipt JSON object")
        .extend(fields.as_object().expect("event JSON object").clone());
    value
}

#[cfg(feature = "shellnet")]
pub(crate) fn prior_stop_confirmation(
    command: &str,
    tc: &dexdo_core::Address,
    note: &dexdo_core::Address,
    receipt: &dexdo_core::TokenContractSettlementReceipt,
) -> String {
    let attribution = match &receipt.event {
        dexdo_core::TokenContractSettlementEvent::ProbeBurned { .. } => {
            "action=buyer_stop (ProbeBurned-specific)"
        }
        dexdo_core::TokenContractSettlementEvent::StreamStopped { .. } => {
            "action=unknown (StreamStopped records the buyer beneficiary, not whether buyer stop or sellerStop submitted it)"
        }
        _ => unreachable!("prior_stop_confirmation receives only exact STOP receipts"),
    };
    format!(
        "{command} noop: TokenContract {tc} is already terminal by immutable receipt \
         message_id={} created_at={} event={:?}; {attribution}; buyer note {note}; no second STOP was submitted",
        receipt.message_id, receipt.created_at, receipt.event,
    )
}

#[cfg(feature = "shellnet")]
fn recover_confirmation(
    tc: &dexdo_core::Address,
    note: &dexdo_core::Address,
    receipt: &dexdo_core::SettlementActionReceipt,
) -> String {
    format!(
        "recover confirmed -> streamStop(TokenContract {tc}) from buyer note {note}; \
         receipt={receipt}; the deal STOPs. Next: the seller runs `dexdo destroy` to close \
         (selfdestruct) the TokenContract."
    )
}

#[cfg(feature = "shellnet")]
fn apply_recover_terminal_marker<T>(
    confirmation: &str,
    marker: impl FnOnce() -> Result<T>,
) -> Result<T> {
    marker().map_err(|error| {
        anyhow::anyhow!(
            "{confirmation}; local subscription marker failed after the authoritative receipt \
             was rendered: {error:#}"
        )
    })
}

#[cfg(feature = "shellnet")]
async fn run_recover_with_chain(args: RecoverArgs, chain: &dyn RecoverChain) -> Result<()> {
    run_recover_with_chain_and_marker(args, chain, &|note_addr, token_contract| {
        super::buyer::mark_buyer_subscription_terminal(note_addr, token_contract)
    })
    .await
}

#[cfg(feature = "shellnet")]
async fn run_recover_with_chain_and_marker(
    args: RecoverArgs,
    chain: &dyn RecoverChain,
    marker: &(dyn Fn(&str, &str) -> Result<bool> + Sync),
) -> Result<()> {
    use dexdo_core::{check_recoverable, keypair_ed_pubkey, Address, KeyPair};
    let resolved = resolve_pool_recovery_inputs(
        "recover",
        &args.identity,
        args.market.as_deref(),
        args.token_contract.as_deref(),
        args.pool.as_deref(),
    )?;
    let pool_record = resolved.pool_record;
    let note_addr = resolved.note_addr;
    let tc_str = resolved.token_contract;
    let seed = resolved.note_secret_hex;
    let keys = KeyPair::from_secret_hex(seed.trim())
        .map_err(|e| anyhow::anyhow!("--note-key (SDK secret hex): {e:?}"))?;
    let note =
        Address::parse(&note_addr).map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
    let tc =
        Address::parse(&tc_str).map_err(|e| anyhow::anyhow!("token_contract {tc_str}: {e}"))?;

    let prior_receipts = chain.settlement_receipts(&tc).await?;
    if let Some(receipt) = exact_prior_stop_receipt(&prior_receipts, &note.with_workchain())? {
        let confirmation = prior_stop_confirmation("recover", &tc, &note, &receipt);
        println!("{confirmation}");
        apply_recover_terminal_marker(&confirmation, || marker(&note.with_workchain(), &tc_str))?;
        if let Some(record) = pool_record.as_ref() {
            persist_pool_recovery_record(record).map_err(|error| {
                anyhow::anyhow!(
                    "{confirmation}; local pool persistence failed during idempotent reconciliation: \
                     {error:#}"
                )
            })?;
        }
        return Ok(());
    }

    let state = chain.state(&tc).await?.ok_or_else(|| {
        anyhow::anyhow!("recover: TokenContract {tc} is not active (undeployed/closed)")
    })?;
    let buyer_note = chain.buyer_note(&tc).await?;
    let buyer_note_s = buyer_note.as_ref().map(|a| a.with_workchain());
    let note_s = note.with_workchain();
    let buyer_pubkey = chain.buyer_pubkey(&tc).await?;
    let note_ed = keypair_ed_pubkey(&keys)?;
    check_recoverable(
        state.opened,
        state.disputed,
        buyer_note_s.as_deref(),
        &note_s,
        buyer_pubkey.as_ref(),
        &note_ed,
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    eprintln!(
        "recover {tc}: buyer-signed STOP of an OPEN deal (streamStop -> TokenContract.stop(), standard \
         split). No new buy is placed. After this, the seller closes it: `dexdo destroy --token-contract {tc}`."
    );
    let receipt = chain.stop(&note, &keys, &tc).await?;
    let confirmation = recover_confirmation(&tc, &note, &receipt);
    println!("{confirmation}");
    apply_recover_terminal_marker(&confirmation, || marker(&note_s, &tc.with_workchain()))?;
    if let Some(record) = pool_record.as_ref() {
        persist_pool_recovery_record(record).map_err(|error| {
            anyhow::anyhow!(
                "{confirmation}; local pool persistence failed after the authoritative receipt \
                 was rendered: {error:#}"
            )
        })?;
    }
    Ok(())
}

#[cfg(feature = "shellnet")]
pub(crate) async fn run_recover(args: RecoverArgs) -> Result<()> {
    use dexdo_core::RealChainBackend;
    let manifest = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let chain = RealChainBackend::connect(manifest)?;
    run_recover_with_chain(args, &chain).await
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_recover(_args: RecoverArgs) -> Result<()> {
    bail!("recover unavailable: build with `--features shellnet`")
}

#[cfg(feature = "shellnet")]
pub(crate) async fn run_dispute(args: DisputeArgs) -> Result<()> {
    use dexdo_core::{check_disputable, keypair_ed_pubkey, Address, KeyPair, RealChainBackend};
    let manifest = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let resolved = resolve_pool_recovery_inputs(
        "dispute",
        &args.identity,
        args.market.as_deref(),
        args.token_contract.as_deref(),
        args.pool.as_deref(),
    )?;
    let note_addr = resolved.note_addr;
    let tc_str = resolved.token_contract;
    let seed = resolved.note_secret_hex;
    let chain = RealChainBackend::connect(manifest)?;
    let keys = KeyPair::from_secret_hex(seed.trim())
        .map_err(|e| anyhow::anyhow!("--note-key (SDK secret hex): {e:?}"))?;
    let note =
        Address::parse(&note_addr).map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
    let tc =
        Address::parse(&tc_str).map_err(|e| anyhow::anyhow!("token_contract {tc_str}: {e}"))?;

    // Fail-loud pre-flight: only an OPEN, undisputed deal owned by THIS buyer note/key can be disputed.
    let state = chain
        .token_contract_deal_snapshot(&tc)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("dispute: TokenContract {tc} is not active (undeployed/closed)")
        })?
        .state;
    let buyer_note = chain.token_contract_buyer_note(&tc).await?;
    let buyer_note_s = buyer_note.as_ref().map(|a| a.with_workchain());
    let note_s = note.with_workchain();
    let buyer_pubkey = chain.token_contract_buyer_pubkey(&tc).await?;
    let note_ed = keypair_ed_pubkey(&keys)?;
    check_disputable(
        state.opened,
        state.disputed,
        buyer_note_s.as_deref(),
        &note_s,
        buyer_pubkey.as_ref(),
        &note_ed,
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    eprintln!(
        "dispute {tc}: buyer-signed streamDispute -> TokenContract.dispute() () -- freezes this TC's \
         contested amount and seller bond until resolution. Stronger than `recover` (which still pays the \
         seller for delivered ticks); both whole notes remain usable for independent deals."
    );
    let receipt = chain.stream_dispute(&note, &keys, &tc).await?;
    println!(
        "dispute_opened -> streamDispute(TokenContract {tc}) from buyer note {note}; receipt={receipt}; \
         no terminal payment/refund split exists yet"
    );
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_dispute(_args: DisputeArgs) -> Result<()> {
    bail!("dispute unavailable: build with `--features shellnet`")
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(feature = "shellnet"), allow(dead_code))]
pub(crate) fn check_reclaimable_state(
    state: dexdo_core::DealChainState,
    buyer_note: Option<&str>,
    note_addr: &str,
    buyer_pubkey: Option<&[u8; 32]>,
    note_ed_pubkey: &[u8; 32],
    now: u64,
) -> Result<dexdo_core::ReclaimAction, String> {
    dexdo_core::check_reclaimable(
        state,
        buyer_note,
        note_addr,
        buyer_pubkey,
        note_ed_pubkey,
        now,
        dexdo_core::MATCH_OPEN_TIMEOUT_SECS,
    )
}

#[cfg(feature = "shellnet")]
pub(crate) async fn run_reclaim(args: ReclaimArgs) -> Result<()> {
    use dexdo_core::{
        keypair_ed_pubkey, Address, KeyPair, RealChainBackend, ReclaimAction,
        MATCH_OPEN_TIMEOUT_SECS,
    };
    let manifest = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let resolved = resolve_pool_recovery_inputs(
        "reclaim",
        &args.identity,
        args.market.as_deref(),
        args.token_contract.as_deref(),
        args.pool.as_deref(),
    )?;
    let note_addr = resolved.note_addr;
    let tc_str = resolved.token_contract;
    let seed = resolved.note_secret_hex;
    let chain = RealChainBackend::connect(manifest)?;
    let keys = KeyPair::from_secret_hex(seed.trim())
        .map_err(|e| anyhow::anyhow!("--note-key (SDK secret hex): {e:?}"))?;
    let note =
        Address::parse(&note_addr).map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
    let tc =
        Address::parse(&tc_str).map_err(|e| anyhow::anyhow!("token_contract {tc_str}: {e}"))?;

    // This command owns only the strictly decoded never-opened cleanup. An OPEN deal is stopped
    // explicitly through `dexdo close` or `dexdo recover`, never rewritten from this legacy name.
    let state = chain
        .token_contract_deal_snapshot(&tc)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("reclaim: TokenContract {tc} is not active (undeployed/closed)")
        })?
        .state;
    let buyer_note = chain.token_contract_buyer_note(&tc).await?;
    let buyer_note_s = buyer_note.as_ref().map(|a| a.with_workchain());
    let note_s = note.with_workchain();
    let buyer_pubkey = chain.token_contract_buyer_pubkey(&tc).await?;
    let note_ed = keypair_ed_pubkey(&keys)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock before epoch: {e}"))?
        .as_secs();
    if state.opened {
        anyhow::bail!(
            "reclaim: OPEN deal {tc} must use the explicit buyer STOP path (`dexdo close` or `dexdo recover`)"
        );
    }
    if state.probe_accepted {
        anyhow::bail!(
            "reclaim: deal is not OPEN and probeAccepted=true; it is not a never-opened cleanup candidate"
        );
    }
    let action = check_reclaimable_state(
        state,
        buyer_note_s.as_deref(),
        &note_s,
        buyer_pubkey.as_ref(),
        &note_ed,
        now,
    )
    .map_err(anyhow::Error::msg)?;
    if action != ReclaimAction::StreamCleanup {
        anyhow::bail!("reclaim: strict never-opened preflight selected an unexpected action");
    }

    let funded_time = state
        .funded_time
        .expect("successful never-opened preflight requires fundedTime");
    eprintln!(
        "reclaim {tc}: buyer-signed streamCleanup -> TokenContract.cleanupUnopened() (never-opened refund). \
         MATCH_OPEN_TIMEOUT met: fundedTime {funded_time} + matchOpenTimeout {MATCH_OPEN_TIMEOUT_SECS} <= \
         now {now}."
    );
    chain.stream_cleanup(&note, &keys, &tc).await?;
    chain.wait_cleanup_unopened(&tc).await.map_err(|error| {
        anyhow::anyhow!(
            "reclaim submitted -> streamCleanup(TokenContract {tc}); bounded cleanup \
                 confirmation failed: {error}; settlement is not confirmed"
        )
    })?;
    super::buyer::mark_buyer_subscription_terminal(&note.with_workchain(), &tc.with_workchain())?;
    println!(
        "reclaim confirmed -> streamCleanup(TokenContract {tc}); bounded on-chain observation \
         found the TokenContract absent or no longer funded."
    );
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_reclaim(_args: ReclaimArgs) -> Result<()> {
    bail!("reclaim unavailable: build with `--features shellnet`")
}

#[cfg(feature = "shellnet")]
pub(crate) async fn run_release_dispute(args: ReleaseDisputeArgs) -> Result<()> {
    use dexdo_core::{
        check_release_disputable, check_seller_pubkey, Address, KeyPair, RealChainBackend,
    };
    let note_addr =
        args.identity.note_addr.clone().ok_or_else(|| {
            anyhow::anyhow!("release-dispute: --note-addr (seller note) is required")
        })?;
    let note_key = args.identity.note_key.as_deref().ok_or_else(|| {
        anyhow::anyhow!("release-dispute: --note-key (seller owner key) is required")
    })?;
    let manifest = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let (tc_str, _frame, _nonce) =
        resolve_market_fields(args.market.as_deref(), args.token_contract.as_deref(), None)?;
    let seed = read_secret_hex(note_key, "--note-key")?;
    let chain = RealChainBackend::connect(manifest)?;
    let keys = KeyPair::from_secret_hex(seed.trim())
        .map_err(|e| anyhow::anyhow!("--note-key (SDK secret hex): {e:?}"))?;
    let note =
        Address::parse(&note_addr).map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
    let tc =
        Address::parse(&tc_str).map_err(|e| anyhow::anyhow!("token_contract {tc_str}: {e}"))?;

    let state = chain
        .token_contract_deal_snapshot(&tc)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("release-dispute: TokenContract {tc} is not active (undeployed/closed)")
        })?
        .state;
    check_release_disputable(state.disputed).map_err(anyhow::Error::msg)?;
    let seller = chain.token_contract_seller_pubkey(&tc).await?;
    check_seller_pubkey("release-dispute", seller.as_deref(), keys.public_hex())
        .map_err(|e| anyhow::anyhow!(e))?;

    eprintln!(
        "release-dispute {tc}: seller-signed TokenContract.releaseDispute() from note {note}; \
         exact burns, returns and seller payout will be reported only by DisputeResolved and strict getters."
    );
    let receipt = chain.release_dispute(&tc, &keys).await?;
    println!("release-dispute confirmed -> TokenContract {tc}; receipt={receipt}");
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_release_dispute(_args: ReleaseDisputeArgs) -> Result<()> {
    bail!("release-dispute unavailable: build with `--features shellnet`")
}

#[cfg(feature = "shellnet")]
fn required_u64(value: &Value, field: &str, context: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .or_else(|| value[field].as_str().and_then(|raw| raw.parse().ok()))
        .ok_or_else(|| anyhow::anyhow!("{context}: getter exposes no {field}"))
}

#[cfg(feature = "shellnet")]
fn validate_dispute_timeout(
    state: dexdo_core::DealChainState,
    config: &Value,
    now: u64,
) -> Result<u64> {
    if !state.disputed {
        anyhow::bail!("resolve-dispute-timeout: deal is not DISPUTED -- nothing to resolve");
    }
    let dispute_time = state.dispute_time;
    if dispute_time == 0 {
        anyhow::bail!("resolve-dispute-timeout: disputed deal has zero disputeTime");
    }
    let dispute_window =
        required_u64(config, "disputeWindow", "resolve-dispute-timeout getConfig")?;
    let deadline = dispute_time.saturating_add(dispute_window);
    if now < deadline {
        anyhow::bail!(
            "resolve-dispute-timeout: too early -- disputeTime {dispute_time} + disputeWindow \
             {dispute_window} = {deadline} > now {now} ({} s remaining)",
            deadline - now
        );
    }
    Ok(deadline)
}

#[cfg(feature = "shellnet")]
async fn submit_dispute_timeout_after_validation<T>(
    preflight: Result<u64>,
    submit: impl std::future::Future<Output = Result<T>>,
) -> Result<(u64, T)> {
    let deadline = preflight?;
    let receipt = submit.await?;
    Ok((deadline, receipt))
}

#[cfg(feature = "shellnet")]
pub(crate) async fn run_resolve_dispute_timeout(args: ResolveDisputeTimeoutArgs) -> Result<()> {
    use dexdo_core::{Address, Deployed, RealChainBackend};

    let contracts = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let chain = RealChainBackend::connect(contracts)?;
    let now = chain.observed_chain_timestamp().await?;
    let (tc_str, _frame, _nonce) =
        resolve_market_fields(args.market.as_deref(), args.token_contract.as_deref(), None)?;
    let tc =
        Address::parse(&tc_str).map_err(|e| anyhow::anyhow!("token_contract {tc_str}: {e}"))?;
    let deployed = Deployed::load(&args.contracts)?;
    let expected_hash = deployed
        .contract_hashes
        .get("TokenContract")
        .ok_or_else(|| anyhow::anyhow!("deployed manifest has no TokenContract code hash"))?;
    let (active, code_hash) = chain.account_active_code_hash(&tc).await?;
    let mut identity_ok =
        active && code_hash.as_deref() == Some(expected_hash.trim_start_matches("0x"));
    if let Some(path) = args.market.as_deref() {
        let market = load_market(path)?;
        let seller = chain
            .token_contract_seller_pubkey(&tc)
            .await?
            .ok_or_else(|| anyhow::anyhow!("TokenContract {tc} getSeller unavailable"))?;
        let seller = serde_json::json!(format!("0x{seller:0>64}"));
        let root = Address::parse(&market.root_model)?;
        identity_ok &= chain.token_contract_model_hash(&tc).await?.as_deref()
            == Some(market.model_hash.as_str())
            && chain
                .root_model_address_for(&seller)
                .await?
                .with_workchain()
                == root.with_workchain()
            && chain
                .resolve_token_contract(&root, &seller, market.nonce)
                .await?
                .with_workchain()
                == tc.with_workchain();
    }
    let before = chain
        .token_contract_deal_snapshot(&tc)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "resolve-dispute-timeout: TokenContract {tc} is not active (undeployed/closed)"
            )
        })?
        .state;
    let config = chain.token_contract_config(&tc).await?.ok_or_else(|| {
        anyhow::anyhow!("resolve-dispute-timeout: TokenContract {tc} getConfig unavailable")
    })?;
    let preflight = if identity_ok {
        validate_dispute_timeout(before, &config, now)
    } else {
        Err(anyhow::anyhow!(
            "resolve-dispute-timeout: wrong TokenContract identity"
        ))
    };
    let (deadline, receipt) =
        submit_dispute_timeout_after_validation(preflight, chain.resolve_dispute_timeout(&tc))
            .await?;
    println!(
        "resolve-dispute-timeout confirmed token_contract={tc} deadline={deadline} receipt={receipt}"
    );
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_resolve_dispute_timeout(_args: ResolveDisputeTimeoutArgs) -> Result<()> {
    bail!("resolve-dispute-timeout unavailable: build with `--features shellnet`")
}

#[cfg(any(feature = "shellnet", test))]
const WITHDRAW_SHELL_GUIDANCE: &str =
    "This withdraws finalized seller proceeds. If this drains the last finalized proceeds from a funded, closed, undisputed deal with no live offer, the TC also selfdestructs; otherwise it remains active.";

#[cfg(feature = "shellnet")]
pub(crate) async fn run_withdraw_shell(args: WithdrawShellArgs) -> Result<()> {
    use dexdo_core::{
        check_seller_pubkey, check_withdrawable_shell, Address, KeyPair, RealChainBackend,
    };
    let note_addr =
        args.identity.note_addr.clone().ok_or_else(|| {
            anyhow::anyhow!("withdraw-shell: --note-addr (seller note) is required")
        })?;
    let note_key = args.identity.note_key.as_deref().ok_or_else(|| {
        anyhow::anyhow!("withdraw-shell: --note-key (seller owner key) is required")
    })?;
    let recipient_addr = args.recipient.clone().unwrap_or_else(|| note_addr.clone());
    let manifest = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let (tc_str, _frame, _nonce) =
        resolve_market_fields(args.market.as_deref(), args.token_contract.as_deref(), None)?;
    let seed = read_secret_hex(note_key, "--note-key")?;
    let chain = RealChainBackend::connect(manifest)?;
    let keys = KeyPair::from_secret_hex(seed.trim())
        .map_err(|e| anyhow::anyhow!("--note-key (SDK secret hex): {e:?}"))?;
    let tc =
        Address::parse(&tc_str).map_err(|e| anyhow::anyhow!("token_contract {tc_str}: {e}"))?;
    let recipient = Address::parse(&recipient_addr)
        .map_err(|e| anyhow::anyhow!("--recipient/--note-addr {recipient_addr}: {e}"))?;

    let state = chain
        .token_contract_deal_snapshot(&tc)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("withdraw-shell: TokenContract {tc} is not active (undeployed/closed)")
        })?
        .state;
    let amount =
        check_withdrawable_shell(state.finalized_owed, args.amount).map_err(anyhow::Error::msg)?;
    let seller = chain.token_contract_seller_pubkey(&tc).await?;
    check_seller_pubkey("withdraw-shell", seller.as_deref(), keys.public_hex())
        .map_err(|e| anyhow::anyhow!(e))?;

    eprintln!(
        "withdraw-shell {tc}: seller-signed TokenContract.withdrawShell(amount={amount}, recipient={recipient}). \
         {WITHDRAW_SHELL_GUIDANCE}"
    );
    chain.withdraw_shell(&tc, amount, &recipient, &keys).await?;
    println!(
        "withdraw-shell submitted -> {amount} finalized SHELL from TokenContract {tc} to {recipient}"
    );
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_withdraw_shell(_args: WithdrawShellArgs) -> Result<()> {
    bail!("withdraw-shell unavailable: build with `--features shellnet`")
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "shellnet")]
    use crate::cli::args::{IdentityArgs, RecoverArgs};

    #[cfg(feature = "shellnet")]
    #[test]
    fn recover_uses_shared_explicit_stop_while_legacy_reclaim_rejects_open() {
        let source = include_str!("recover.rs");
        let end = source
            .find("#[cfg(test)]")
            .expect("production/test boundary");
        let production = &source[..end];
        assert_eq!(
            production.matches(".explicit_buyer_stop(").count(),
            1,
            "recover must use the shared explicit STOP path"
        );
        assert!(!production.contains(".stream_stop("));
        assert!(production.contains(
            "OPEN deal {tc} must use the explicit buyer STOP path (`dexdo close` or `dexdo recover`)"
        ));
    }

    fn chain_state(
        funded: bool,
        opened: bool,
        probe_accepted: bool,
        disputed: bool,
        deposit: u128,
    ) -> dexdo_core::DealChainState {
        dexdo_core::DealChainState {
            funded,
            opened,
            probe_accepted,
            disputed,
            deposit,
            finalized_owed: 0,
            tokens_final: 0,
            tokens_superseded: 0,
            tokens_pending: 0,
            probe_tick: 0,
            funded_time: Some(1),
            probe_time: 0,
            prev_claim_time: 1,
            last_claim_time: 1,
            dispute_time: if disputed { 100 } else { 0 },
        }
    }

    /// A stale funded read after submission is not success: reclaim uses the existing bounded
    /// observer and marks local state only after that observer confirms absent/unfunded state.
    #[cfg(feature = "shellnet")]
    #[test]
    fn reclaim_requires_bounded_cleanup_confirmation_before_success() {
        let source = include_str!("recover.rs");
        let end = source
            .find("#[cfg(test)]")
            .expect("production/test boundary");
        let production = &source[..end];
        let submit = production
            .find("chain.stream_cleanup(&note, &keys, &tc).await?")
            .expect("cleanup submit");
        let tail = &production[submit..];
        let observe = tail
            .find(".wait_cleanup_unopened(&tc)")
            .expect("bounded cleanup observer");
        let marker = tail
            .find("mark_buyer_subscription_terminal(")
            .expect("terminal marker");
        let success = tail
            .find("reclaim confirmed -> streamCleanup")
            .expect("success rendering");
        assert!(observe < marker && marker < success);
        assert!(
            !tail.contains("single post-read"),
            "one pending/stale read must never be reported as a successful reclaim"
        );
    }

    #[test]
    fn real_never_opened_state_selects_one_cleanup_but_terminal_prior_open_selects_no_write() {
        let me = [7u8; 32];
        let mut state = chain_state(true, false, false, false, 100);
        state.funded_time = Some(1);
        state.prev_claim_time = 1;
        state.last_claim_time = 1;
        let cleanup = super::check_reclaimable_state(
            state,
            Some("0:buyer"),
            "0:buyer",
            Some(&me),
            &me,
            1_000,
        );
        assert_eq!(usize::from(cleanup.is_ok()), 1, "cleanup POST count");
        assert_eq!(cleanup.unwrap(), dexdo_core::ReclaimAction::StreamCleanup);

        state.deposit = 0;
        state.last_claim_time = 2;
        let preflight = super::check_reclaimable_state(
            state,
            Some("0:buyer"),
            "0:buyer",
            Some(&me),
            &me,
            1_000,
        );
        let money_writes = usize::from(preflight.is_ok());
        assert_eq!(money_writes, 0);
        assert!(preflight.unwrap_err().contains("terminal/drained"));
    }

    #[cfg(feature = "shellnet")]
    struct TempDirCleanup(std::path::PathBuf);

    #[cfg(feature = "shellnet")]
    impl Drop for TempDirCleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(feature = "shellnet")]
    struct PoolRecoverChain {
        buyer_note: dexdo_core::Address,
        buyer_pubkey: [u8; 32],
        stop_calls: std::sync::atomic::AtomicUsize,
        terminal: std::sync::atomic::AtomicBool,
        poison_pool_after_stop: Option<std::path::PathBuf>,
    }

    #[cfg(feature = "shellnet")]
    fn test_stop_receipt(tc: &dexdo_core::Address) -> dexdo_core::SettlementActionReceipt {
        dexdo_core::SettlementActionReceipt {
            token_contract: tc.with_workchain(),
            action: dexdo_core::SettlementAction::BuyerStop,
            message_id: "test-stop-message".to_string(),
            created_at: 1,
            event: dexdo_core::SettlementActionEvent::StreamStopped {
                buyer: format!("0:{}", "1".repeat(64)),
                to_seller: 1u128.into(),
                refund_to_buyer: 2u128.into(),
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
    #[test]
    fn recover_confirmation_renders_the_authoritative_stop_receipt() {
        let tc = dexdo_core::Address::parse(&format!("0:{}", "2".repeat(64))).unwrap();
        let note = dexdo_core::Address::parse(&format!("0:{}", "1".repeat(64))).unwrap();
        let rendered = super::recover_confirmation(&tc, &note, &test_stop_receipt(&tc));
        for fact in [
            "action=buyer_stop",
            "message_id=test-stop-message",
            "created_at=1",
            "buyer=0:1111111111111111111111111111111111111111111111111111111111111111",
            "toSeller=1",
            "refundToBuyer=2",
            "tokensFinal=3",
            "tokensSuperseded=4",
            "tokensPending=5",
        ] {
            assert!(rendered.contains(fact), "missing {fact:?} in {rendered}");
        }
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn foreign_stop_receipt_never_reconciles_local_state_or_submits_money() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let expected = format!("0:{}", "11".repeat(32));
        let foreign = format!("0:{}", "22".repeat(32));
        for event in [
            dexdo_core::TokenContractSettlementEvent::ProbeBurned {
                buyer: foreign.clone(),
                burned_probe: 1,
                burned_bond: 2,
                refund_to_buyer: 3,
            },
            dexdo_core::TokenContractSettlementEvent::StreamStopped {
                buyer: foreign.clone(),
                to_seller: 4,
                refund_to_buyer: 5,
            },
        ] {
            let receipts = dexdo_core::TokenContractSettlementReceipts {
                events: vec![dexdo_core::TokenContractSettlementReceipt {
                    message_id: "foreign-stop".to_string(),
                    created_at: 7,
                    cursor: "foreign-stop-cursor".to_string(),
                    event,
                }],
            };
            let marker_calls = AtomicUsize::new(0);
            let stop_calls = AtomicUsize::new(0);
            let result = (|| -> anyhow::Result<()> {
                super::exact_prior_stop_receipt(&receipts, &expected)?;
                marker_calls.fetch_add(1, Ordering::SeqCst);
                stop_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })();
            let message = result
                .expect_err("foreign buyer receipt must fail before local reconciliation")
                .to_string();
            assert!(
                message.contains("does not match local buyer note"),
                "{message}"
            );
            assert_eq!(marker_calls.load(Ordering::SeqCst), 0);
            assert_eq!(stop_calls.load(Ordering::SeqCst), 0);
        }
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn seller_stop_shape_with_local_beneficiary_is_only_actor_unknown_terminal() {
        let beneficiary = format!("0:{}", "11".repeat(32));
        let receipts = dexdo_core::TokenContractSettlementReceipts {
            events: vec![dexdo_core::TokenContractSettlementReceipt {
                message_id: "seller-stop-shaped".to_string(),
                created_at: 9,
                cursor: "seller-stop-shaped-cursor".to_string(),
                event: dexdo_core::TokenContractSettlementEvent::StreamStopped {
                    buyer: beneficiary.clone(),
                    to_seller: 4,
                    refund_to_buyer: 5,
                },
            }],
        };
        let receipt = super::exact_prior_stop_receipt(&receipts, &beneficiary)
            .unwrap()
            .expect("StreamStopped proves terminality for the local beneficiary");
        let tc = dexdo_core::Address::parse(&format!("0:{}", "22".repeat(32))).unwrap();
        let note = dexdo_core::Address::parse(&beneficiary).unwrap();
        let json = super::prior_stop_receipt_json(&tc, &receipt);
        assert_eq!(json["action"], "terminal_stop_reconciliation");
        assert_eq!(
            json["action_attribution"],
            "unknown_buyer_stop_or_seller_stop"
        );
        assert_ne!(json["action_attribution"], "buyer_stop");

        let confirmation = super::prior_stop_confirmation("recover", &tc, &note, &receipt);
        for fact in [
            "action=unknown",
            "buyer beneficiary",
            "buyer stop or sellerStop",
            "no second STOP was submitted",
        ] {
            assert!(
                confirmation.contains(fact),
                "missing {fact:?} in {confirmation}"
            );
        }
        assert!(
            !confirmation.contains("action=buyer_stop"),
            "sellerStop-shaped receipt must not be attributed to buyer STOP: {confirmation}"
        );
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn recover_marks_subscription_or_noops_for_ordinary_deal_after_rendering_receipt() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let tc = dexdo_core::Address::parse(&format!("0:{}", "2".repeat(64))).unwrap();
        let note = dexdo_core::Address::parse(&format!("0:{}", "1".repeat(64))).unwrap();
        let receipt = test_stop_receipt(&tc);
        let confirmation = super::recover_confirmation(&tc, &note, &receipt);
        let calls = AtomicUsize::new(0);

        let marked = super::apply_recover_terminal_marker(&confirmation, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        })
        .unwrap();
        assert!(marked, "matched subscription must become terminal");
        let ordinary = super::apply_recover_terminal_marker(&confirmation, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(false)
        })
        .unwrap();
        assert!(
            !ordinary,
            "ordinary deal without a subscription sidecar is a no-op"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let error = super::apply_recover_terminal_marker(&confirmation, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(anyhow::anyhow!("marker disk failure"))
        })
        .expect_err("marker failure must remain explicit after the landed receipt")
        .to_string();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        for fact in [
            "local subscription marker failed",
            "action=buyer_stop",
            "message_id=test-stop-message",
            "created_at=1",
            "toSeller=1",
            "refundToBuyer=2",
            "marker disk failure",
        ] {
            assert!(error.contains(fact), "missing {fact:?} in {error}");
        }

        let source = include_str!("recover.rs");
        let stop = source
            .find("let receipt = chain.stop(")
            .expect("recover STOP");
        let tail = &source[stop..];
        let render = tail
            .find("println!(\"{confirmation}\")")
            .expect("receipt render");
        let marker = tail
            .find("apply_recover_terminal_marker(")
            .expect("receipt-driven terminal marker");
        let pool = tail
            .find("persist_pool_recovery_record(")
            .expect("pool recovery persistence");
        assert!(render < marker && marker < pool);
    }

    #[cfg(feature = "shellnet")]
    #[async_trait::async_trait]
    impl super::RecoverChain for PoolRecoverChain {
        async fn state(
            &self,
            _tc: &dexdo_core::Address,
        ) -> anyhow::Result<Option<dexdo_core::DealChainState>> {
            Ok((!self.terminal.load(std::sync::atomic::Ordering::SeqCst))
                .then(|| chain_state(true, true, true, false, 100)))
        }

        async fn buyer_note(
            &self,
            _tc: &dexdo_core::Address,
        ) -> anyhow::Result<Option<dexdo_core::Address>> {
            Ok(Some(self.buyer_note.clone()))
        }

        async fn buyer_pubkey(
            &self,
            _tc: &dexdo_core::Address,
        ) -> anyhow::Result<Option<[u8; 32]>> {
            Ok(Some(self.buyer_pubkey))
        }

        async fn stop(
            &self,
            note: &dexdo_core::Address,
            _keys: &dexdo_core::KeyPair,
            tc: &dexdo_core::Address,
        ) -> anyhow::Result<dexdo_core::SettlementActionReceipt> {
            assert_eq!(note.with_workchain(), self.buyer_note.with_workchain());
            self.stop_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.terminal
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(path) = &self.poison_pool_after_stop {
                std::fs::write(path, b"{")?;
            }
            Ok(test_stop_receipt(tc))
        }

        async fn settlement_receipts(
            &self,
            _tc: &dexdo_core::Address,
        ) -> anyhow::Result<dexdo_core::TokenContractSettlementReceipts> {
            if !self.terminal.load(std::sync::atomic::Ordering::SeqCst) {
                return Ok(dexdo_core::TokenContractSettlementReceipts::default());
            }
            Ok(dexdo_core::TokenContractSettlementReceipts {
                events: vec![dexdo_core::TokenContractSettlementReceipt {
                    message_id: "test-stop-message".to_string(),
                    created_at: 1,
                    cursor: "test-stop-cursor".to_string(),
                    event: dexdo_core::TokenContractSettlementEvent::StreamStopped {
                        buyer: self.buyer_note.with_workchain(),
                        to_seller: 1,
                        refund_to_buyer: 2,
                    },
                }],
            })
        }
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn dispute_timeout_validation_matches_deployed_boundary() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let disputed = chain_state(true, false, true, true, 100);
        let mut terminal = chain_state(true, false, true, false, 0);
        terminal.dispute_time = 100;
        let config = serde_json::json!({"disputeWindow": "600"});

        assert_eq!(
            super::validate_dispute_timeout(disputed, &config, 700).unwrap(),
            700
        );
        assert!(super::validate_dispute_timeout(disputed, &config, 699)
            .unwrap_err()
            .to_string()
            .contains("too early"));
        assert!(super::validate_dispute_timeout(terminal, &config, 700)
            .unwrap_err()
            .to_string()
            .contains("not DISPUTED"));

        let posts = AtomicUsize::new(0);
        let post = || async {
            posts.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({}))
        };
        for preflight in [
            Err(anyhow::anyhow!("wrong TokenContract identity")),
            super::validate_dispute_timeout(disputed, &config, 699),
        ] {
            assert!(
                super::submit_dispute_timeout_after_validation(preflight, post())
                    .await
                    .is_err()
            );
        }
        assert_eq!(posts.load(Ordering::SeqCst), 0);

        let (deadline, receipt) = super::submit_dispute_timeout_after_validation(
            super::validate_dispute_timeout(disputed, &config, 700),
            post(),
        )
        .await
        .unwrap();
        assert_eq!(posts.load(Ordering::SeqCst), 1);
        assert_eq!(deadline, 700);
        assert_eq!(receipt, serde_json::json!({}));
    }

    /// primary regression: the production recover flow must atomically write the selected pool-only buyer
    /// record after STOP, so a fresh pool load observes it as a durable buyer recovery record.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn run_recover_persists_pool_only_record_across_reload() {
        use std::sync::atomic::Ordering;

        let dir = std::env::temp_dir().join(format!(
            "dexdo-run-recover-persist-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());
        let pool_path = dir.join("pn_pool.json");
        let note_addr = format!("0:{}", "1".repeat(64));
        let token_contract = format!("0:{}", "2".repeat(64));
        let seller_tc = format!("0:{}", "3".repeat(64));
        let secret = "2a".repeat(32);
        std::fs::write(
            &pool_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
                "notes": [
                    {
                        "address": note_addr,
                        "owner_secret_key_hex": secret,
                        "token_contract": seller_tc,
                        "token_contract_role": "seller",
                        "token_contract_updated_at_unix": 7
                    },
                    {
                        "address": note_addr,
                        "owner_secret_key_hex": secret,
                        "token_contract": token_contract
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let keys = dexdo_core::KeyPair::from_secret_hex(&secret).unwrap();
        let chain = PoolRecoverChain {
            buyer_note: dexdo_core::Address::parse(&note_addr).unwrap(),
            buyer_pubkey: dexdo_core::keypair_ed_pubkey(&keys).unwrap(),
            stop_calls: std::sync::atomic::AtomicUsize::new(0),
            terminal: std::sync::atomic::AtomicBool::new(false),
            poison_pool_after_stop: None,
        };
        super::run_recover_with_chain(
            RecoverArgs {
                identity: IdentityArgs {
                    note_key: None,
                    note_index: 0,
                    note_addr: None,
                },
                token_contract: None,
                market: None,
                pool: Some(pool_path.clone()),
                contracts: dir.join("unused-contracts.json"),
            },
            &chain,
        )
        .await
        .unwrap();

        assert_eq!(chain.stop_calls.load(Ordering::SeqCst), 1);
        let reloaded = crate::cli::commands::load_pool_json(&pool_path).unwrap();
        let notes = reloaded["notes"].as_array().unwrap();
        let seller = notes
            .iter()
            .find(|note| note["token_contract"] == seller_tc)
            .expect("different seller record must remain present");
        assert_eq!(seller["token_contract_role"], "seller");
        assert_eq!(seller["token_contract_updated_at_unix"], 7);
        let recovered = notes
            .iter()
            .find(|note| note["token_contract"] == token_contract)
            .expect("recovered buyer record must survive pool reload");
        assert_eq!(recovered["owner_secret_key_hex"], secret);
        assert_eq!(recovered["token_contract_role"], "buyer");
        assert!(recovered["token_contract_updated_at_unix"]
            .as_u64()
            .is_some());
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn recover_retry_reconciles_local_state_without_a_second_stop() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = std::env::temp_dir().join(format!(
            "dexdo-run-recover-retry-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());
        let pool_path = dir.join("pn_pool.json");
        let note_addr = format!("0:{}", "1".repeat(64));
        let token_contract = format!("0:{}", "2".repeat(64));
        let secret = "2a".repeat(32);
        std::fs::write(
            &pool_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
                "notes": [{
                    "address": note_addr,
                    "owner_secret_key_hex": secret,
                    "token_contract": token_contract
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let keys = dexdo_core::KeyPair::from_secret_hex(&secret).unwrap();
        let chain = PoolRecoverChain {
            buyer_note: dexdo_core::Address::parse(&note_addr).unwrap(),
            buyer_pubkey: dexdo_core::keypair_ed_pubkey(&keys).unwrap(),
            stop_calls: AtomicUsize::new(0),
            terminal: std::sync::atomic::AtomicBool::new(false),
            poison_pool_after_stop: None,
        };
        let marker_calls = AtomicUsize::new(0);
        let marker = |_: &str, _: &str| {
            let call = marker_calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                anyhow::bail!("transient marker failure")
            }
            Ok(true)
        };
        let args = || RecoverArgs {
            identity: IdentityArgs {
                note_key: None,
                note_index: 0,
                note_addr: None,
            },
            token_contract: None,
            market: None,
            pool: Some(pool_path.clone()),
            contracts: dir.join("unused-contracts.json"),
        };

        let first = super::run_recover_with_chain_and_marker(args(), &chain, &marker)
            .await
            .expect_err("first local marker attempt fails after the landed STOP")
            .to_string();
        assert!(first.contains("test-stop-message"), "{first}");
        assert!(first.contains("transient marker failure"), "{first}");
        assert_eq!(chain.stop_calls.load(Ordering::SeqCst), 1);

        super::run_recover_with_chain_and_marker(args(), &chain, &marker)
            .await
            .expect("retry reconciles immutable receipt without a second STOP");
        assert_eq!(chain.stop_calls.load(Ordering::SeqCst), 1);
        assert_eq!(marker_calls.load(Ordering::SeqCst), 2);
        let reloaded = crate::cli::commands::load_pool_json(&pool_path).unwrap();
        assert_eq!(reloaded["notes"][0]["token_contract_role"], "buyer");
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn pool_write_failure_after_stop_preserves_the_authoritative_receipt() {
        use std::sync::atomic::Ordering;

        let dir = std::env::temp_dir().join(format!(
            "dexdo-run-recover-write-failure-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _cleanup = TempDirCleanup(dir.clone());
        let pool_path = dir.join("pn_pool.json");
        let note_addr = format!("0:{}", "1".repeat(64));
        let token_contract = format!("0:{}", "2".repeat(64));
        let secret = "2a".repeat(32);
        std::fs::write(
            &pool_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
                "notes": [{
                    "address": note_addr,
                    "owner_secret_key_hex": secret,
                    "token_contract": token_contract
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let keys = dexdo_core::KeyPair::from_secret_hex(&secret).unwrap();
        let chain = PoolRecoverChain {
            buyer_note: dexdo_core::Address::parse(&note_addr).unwrap(),
            buyer_pubkey: dexdo_core::keypair_ed_pubkey(&keys).unwrap(),
            stop_calls: std::sync::atomic::AtomicUsize::new(0),
            terminal: std::sync::atomic::AtomicBool::new(false),
            poison_pool_after_stop: Some(pool_path.clone()),
        };
        let error = super::run_recover_with_chain(
            RecoverArgs {
                identity: IdentityArgs {
                    note_key: None,
                    note_index: 0,
                    note_addr: None,
                },
                token_contract: None,
                market: None,
                pool: Some(pool_path),
                contracts: dir.join("unused-contracts.json"),
            },
            &chain,
        )
        .await
        .expect_err("a poisoned pool must fail only after the confirmed STOP is reported")
        .to_string();

        assert_eq!(chain.stop_calls.load(Ordering::SeqCst), 1);
        for fact in [
            "local pool persistence failed",
            "action=buyer_stop",
            "message_id=test-stop-message",
            "created_at=1",
            "toSeller=1",
            "refundToBuyer=2",
        ] {
            assert!(error.contains(fact), "missing {fact:?} in {error}");
        }
    }

    #[test]
    fn withdraw_shell_guidance_describes_conditional_selfdestruct() {
        assert_eq!(
            super::WITHDRAW_SHELL_GUIDANCE,
            "This withdraws finalized seller proceeds. If this drains the last finalized proceeds from a funded, closed, undisputed deal with no live offer, the TC also selfdestructs; otherwise it remains active."
        );
    }
}
