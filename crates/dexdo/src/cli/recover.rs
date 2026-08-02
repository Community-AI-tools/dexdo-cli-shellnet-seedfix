//! `dexdo` pool-recovery command handlers(`recover`/`dispute`/`reclaim`/`release-dispute`/`withdraw-shell`),
//! extracted from `commands.rs`(move-only / behavior-identical, anti-entropy refactor Track C2).

use crate::cli::args::{
    DisputeArgs, ReclaimArgs, RecoverArgs, ReleaseDisputeArgs, ResolveDisputeTimeoutArgs,
    WithdrawShellArgs,
};
use anyhow::Result;

#[cfg(feature = "shellnet")]
use crate::cli::commands::{
    persist_pool_recovery_record, resolve_persistable_pool_recovery_inputs,
    resolve_pool_recovery_inputs, resolve_pool_recovery_plan, PoolRecoveryPlan, PoolRecoveryTarget,
};
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
fn apply_recover_terminal_marker(
    confirmation: &str,
    marker: impl FnOnce() -> Result<()>,
) -> Result<()> {
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
        // `recover` needs the marker to have run, not whether it changed a record: an ordinary deal
        // without a durable subscription sidecar is an expected no-op here.
        super::buyer::mark_buyer_subscription_terminal(note_addr, token_contract).map(drop)
    })
    .await
}

#[cfg(feature = "shellnet")]
async fn run_recover_with_chain_and_marker(
    args: RecoverArgs,
    chain: &dyn RecoverChain,
    marker: &(dyn Fn(&str, &str) -> Result<()> + Sync),
) -> Result<()> {
    use dexdo_core::{check_recoverable, keypair_ed_pubkey, Address, KeyPair};
    let resolved = resolve_persistable_pool_recovery_inputs(
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
    let note = dexdo_core::address::parse_chain_address(&note_addr)
        .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
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
    let note = dexdo_core::address::parse_chain_address(&note_addr)
        .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
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

#[cfg(any(feature = "shellnet", test))]
pub(crate) fn check_reclaimable_state(
    state: dexdo_core::DealChainState,
    buyer_note: Option<&str>,
    note_addr: &str,
    buyer_pubkey: Option<&[u8; 32]>,
    note_ed_pubkey: &[u8; 32],
    now: u64,
) -> Result<(), String> {
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

/// `reclaim` recovers never-opened deals **from recorded pool metadata alone**, because after a
/// crash the pool file is all the operator has. The pool ordinarily records one entry per deal the notes
/// took part in, so more than one recoverable entry is the normal case, not an error: every recorded deal
/// is driven as its own separately decided, individually idempotent reclaim.
#[cfg(feature = "shellnet")]
pub(crate) async fn run_reclaim(args: ReclaimArgs) -> Result<()> {
    use dexdo_core::RealChainBackend;
    let plan = resolve_pool_recovery_plan(
        &args.identity,
        args.market.as_deref(),
        args.token_contract.as_deref(),
        args.pool.as_deref(),
    )?;
    let manifest = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let chain = RealChainBackend::connect(manifest)?;
    drive_reclaim_plan(plan, &chain, &|note_addr, token_contract| {
        super::buyer::mark_buyer_subscription_terminal(note_addr, token_contract)
    })
    .await
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait]
trait ReclaimChain: Sync {
    async fn state(&self, tc: &dexdo_core::Address) -> Result<Option<dexdo_core::DealChainState>>;
    async fn buyer_note(&self, tc: &dexdo_core::Address) -> Result<Option<dexdo_core::Address>>;
    async fn buyer_pubkey(&self, tc: &dexdo_core::Address) -> Result<Option<[u8; 32]>>;
    async fn submit_cleanup(
        &self,
        note: &dexdo_core::Address,
        keys: &dexdo_core::KeyPair,
        tc: &dexdo_core::Address,
    ) -> Result<()>;
    async fn confirm_cleanup(&self, tc: &dexdo_core::Address) -> Result<()>;
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait]
impl ReclaimChain for dexdo_core::RealChainBackend {
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

    async fn submit_cleanup(
        &self,
        note: &dexdo_core::Address,
        keys: &dexdo_core::KeyPair,
        tc: &dexdo_core::Address,
    ) -> Result<()> {
        self.stream_cleanup(note, keys, tc).await?;
        Ok(())
    }

    async fn confirm_cleanup(&self, tc: &dexdo_core::Address) -> Result<()> {
        Ok(self.wait_cleanup_unopened(tc).await?)
    }
}

/// What one recorded entry turned into. There is no third case: either this invocation moved that deal's
/// money, or the chain itself proved there was nothing for `reclaim` to move.
#[cfg(feature = "shellnet")]
enum ReclaimEntryOutcome {
    /// `cleanupUnopened` was submitted **and** confirmed by the bounded observer in this invocation.
    Reclaimed,
    /// No money was moved for this entry, with the chain-decoded reason why.
    NotActionable(String),
}

/// A deal the chain proves is gone or unfunded moves no money -- and it is also exactly the state a
/// confirmed `cleanupUnopened` leaves behind, so this is where a durable subscription marker that failed
/// after an earlier confirmed cleanup gets repaired. The marker is idempotent and reports whether it
/// actually changed anything; a marker that still fails keeps the entry loud rather than leaving local
/// state permanently stale.
#[cfg(feature = "shellnet")]
fn terminal_entry(
    reason: String,
    note_s: &str,
    tc: &dexdo_core::Address,
    marker: &(dyn Fn(&str, &str) -> Result<bool> + Sync),
) -> Result<ReclaimEntryOutcome> {
    let repaired = marker(note_s, &tc.with_workchain())?;
    Ok(ReclaimEntryOutcome::NotActionable(if repaired {
        format!("{reason}; repaired the stale durable buyer subscription record for this deal")
    } else {
        reason
    }))
}

/// One recorded deal's reclaim. This is the whole money path, and it is idempotent by construction: the
/// strict never-opened preflight is re-decoded from the chain on every attempt, and a deal that was
/// already reclaimed is no longer active/funded, so it can only come back `NotActionable`.
#[cfg(feature = "shellnet")]
async fn reclaim_one(
    chain: &dyn ReclaimChain,
    target: &PoolRecoveryTarget,
    now: u64,
    marker: &(dyn Fn(&str, &str) -> Result<bool> + Sync),
) -> Result<ReclaimEntryOutcome> {
    use dexdo_core::{keypair_ed_pubkey, Address, KeyPair, MATCH_OPEN_TIMEOUT_SECS};
    let note_addr = &target.note_addr;
    let tc_str = &target.token_contract;
    let keys = KeyPair::from_secret_hex(target.note_secret_hex.trim())
        .map_err(|e| anyhow::anyhow!("--note-key (SDK secret hex): {e:?}"))?;
    let note = dexdo_core::address::parse_chain_address(note_addr)
        .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
    let tc = Address::parse(tc_str).map_err(|e| anyhow::anyhow!("token_contract {tc_str}: {e}"))?;
    let note_s = note.with_workchain();

    // This command owns only the strictly decoded never-opened cleanup. An OPEN deal is stopped
    // explicitly through `dexdo close` or `dexdo recover`, never rewritten from this legacy name.
    let Some(state) = chain.state(&tc).await? else {
        return terminal_entry(
            format!("reclaim: TokenContract {tc} is not active (undeployed/closed)"),
            &note_s,
            &tc,
            marker,
        );
    };
    let buyer_note = chain.buyer_note(&tc).await?;
    let buyer_note_s = buyer_note.as_ref().map(|a| a.with_workchain());
    let buyer_pubkey = chain.buyer_pubkey(&tc).await?;
    let note_ed = keypair_ed_pubkey(&keys)?;
    // A deal that exists and names a *different* buyer note or key is not a decided chain no-op: the
    // pool claims this note owns the deal and the chain contradicts it. That is a corrupt or forged
    // recovery record, so it fails loudly(and submits nothing) instead of being counted as "nothing to
    // do". `check_reclaimable_state` below re-checks the same ownership as the admission gate; this
    // decides how severe a mismatch is, not whether the cleanup may be submitted.
    if let Some(buyer) = buyer_note_s.as_deref() {
        if buyer != note_s {
            anyhow::bail!(
                "reclaim: the recovery record claims note {note_s} owns TokenContract {tc}, but the \
                 deal's buyer note is {buyer}; refusing to treat a contradicted recovery record as a \
                 decided no-op (nothing was submitted)"
            );
        }
    }
    if let Some(buyer_pubkey) = buyer_pubkey.as_ref() {
        if buyer_pubkey != &note_ed {
            anyhow::bail!(
                "reclaim: the owner key recorded for note {note_s} is not the buyer key of \
                 TokenContract {tc}; refusing to treat a contradicted recovery record as a decided \
                 no-op (nothing was submitted)"
            );
        }
    }
    if state.opened {
        return Ok(ReclaimEntryOutcome::NotActionable(format!(
            "reclaim: OPEN deal {tc} must use the explicit buyer STOP path (`dexdo close` or `dexdo recover`)"
        )));
    }
    if state.probe_accepted {
        return Ok(ReclaimEntryOutcome::NotActionable(
            "reclaim: deal is not OPEN and probeAccepted=true; it is not a never-opened cleanup candidate"
                .to_string(),
        ));
    }
    if let Err(reason) = check_reclaimable_state(
        state,
        buyer_note_s.as_deref(),
        &note_s,
        buyer_pubkey.as_ref(),
        &note_ed,
        now,
    ) {
        // An unfunded deal is the other shape a confirmed cleanup can leave behind, so it repairs a
        // stale marker too; every other refusal is a plain decided no-op.
        return if !state.funded {
            terminal_entry(reason, &note_s, &tc, marker)
        } else {
            Ok(ReclaimEntryOutcome::NotActionable(reason))
        };
    }

    let funded_time = state
        .funded_time
        .expect("successful never-opened preflight requires fundedTime");
    eprintln!(
        "reclaim {tc}: buyer-signed streamCleanup -> TokenContract.cleanupUnopened() (never-opened refund). \
         MATCH_OPEN_TIMEOUT met: fundedTime {funded_time} + matchOpenTimeout {MATCH_OPEN_TIMEOUT_SECS} <= \
         now {now}."
    );
    if let Err(submit) = chain.submit_cleanup(&note, &keys, &tc).await {
        // A failed submit is not proof that nothing landed: the action may have been delivered and only
        // its response lost. This code drives no further cleanup for it -- the outcome is resolved with
        // the same bounded observation that confirms an ordinary cleanup, and reported by fact.
        // The guarantee is no second **money move**, not no second POST: the submit transport retries a
        // BOC on transient errors, and the operator may re-run the command. Neither can pay twice,
        // because `TokenContract.cleanupUnopened()` requires a funded, never-opened deal and destroys it
        // as it refunds, so every later delivery of the same action finds nothing to move.
        return match chain.confirm_cleanup(&tc).await {
            Ok(()) => {
                let marked = marker(&note_s, &tc.with_workchain())?;
                println!(
                    "reclaim confirmed -> streamCleanup(TokenContract {tc}) after an outcome-ambiguous \
                     submit ({submit}); bounded on-chain observation found the TokenContract absent or no \
                     longer funded, so the cleanup landed; this run drove no further cleanup for it, and \
                     the destroyed deal cannot be paid out twice; subscription_marked={marked}"
                );
                Ok(ReclaimEntryOutcome::Reclaimed)
            }
            Err(observation) => Err(anyhow::anyhow!(
                "reclaim: streamCleanup(TokenContract {tc}) submit failed and its outcome is \
                 unresolved: {submit}; the bounded observation did not find the TokenContract absent \
                 or unfunded either: {observation}; this run drove no further cleanup for it -- re-run \
                 to re-decide this deal from the chain, which cannot pay it out twice because \
                 cleanupUnopened only accepts a funded, never-opened deal"
            )),
        };
    }
    chain.confirm_cleanup(&tc).await.map_err(|error| {
        anyhow::anyhow!(
            "reclaim submitted -> streamCleanup(TokenContract {tc}); bounded cleanup \
                 confirmation failed: {error}; settlement is not confirmed"
        )
    })?;
    let marked = marker(&note_s, &tc.with_workchain())?;
    println!(
        "reclaim confirmed -> streamCleanup(TokenContract {tc}); bounded on-chain observation \
         found the TokenContract absent or no longer funded; subscription_marked={marked}"
    );
    Ok(ReclaimEntryOutcome::Reclaimed)
}

/// Drive every planned entry as its own reclaim, one at a time, reporting each by fact.
/// Exactly-once per deal never depends on this loop, and it is a guarantee about **money moves**, not
/// about network submissions: the transport retries a BOC and the operator may re-run the command, but
/// `TokenContract.cleanupUnopened()` requires a funded, never-opened deal and destroys it as it refunds,
/// so only the first delivery can pay. On top of that the strict never-opened preflight is re-decoded
/// from the chain for every entry on every attempt. A mid-sequence failure therefore loses nothing: the
/// remaining entries are still driven, the failed one is reported, and the command exits non-zero so a
/// retry re-decides every entry from the chain.
/// Authorization is a separate axis, and the two levels are not the same. `cleanupUnopened()` is
/// permissionless on chain with fixed payouts -- refund to the recorded buyer, bond back to the seller
/// note -- so no signature of ours decides where the money goes. What is owner-gated is the CLI's wrapper
/// path, `PrivateNote.streamCleanup`: this client only ever submits it from the deal's own buyer
/// note key, which is why a contradicted ownership record is refused rather than driven.
#[cfg(feature = "shellnet")]
async fn drive_reclaim_plan(
    plan: PoolRecoveryPlan,
    chain: &dyn ReclaimChain,
    marker: &(dyn Fn(&str, &str) -> Result<bool> + Sync),
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock before epoch: {e}"))?
        .as_secs();
    if plan.targets.len() == 1 && plan.refused.is_empty() {
        // One recorded deal: "this deal cannot be reclaimed" is the answer to the operator's question,
        // so it stays exactly the loud failure it has always been.
        return match reclaim_one(chain, &plan.targets[0], now, marker).await? {
            ReclaimEntryOutcome::Reclaimed => Ok(()),
            ReclaimEntryOutcome::NotActionable(reason) => Err(anyhow::anyhow!("{reason}")),
        };
    }

    for refusal in &plan.refused {
        println!(
            "reclaim refused note={} token_contract={}: {}; no money was moved for it",
            refusal.note_addr, refusal.token_contract, refusal.reason
        );
    }
    let planned = plan.targets.len();
    let mut reclaimed = 0usize;
    let mut noop = 0usize;
    let mut failed = Vec::new();
    for (index, target) in plan.targets.iter().enumerate() {
        let position = index + 1;
        let note_addr = &target.note_addr;
        let token_contract = &target.token_contract;
        let recorded_at = target
            .recorded_at_unix
            .map_or_else(|| "unrecorded".to_string(), |at| at.to_string());
        eprintln!(
            "reclaim entry {position}/{planned}: note {note_addr} TokenContract {token_contract} \
             recorded_at_unix={recorded_at}; each recorded deal is decided on its own chain state."
        );
        match reclaim_one(chain, target, now, marker).await {
            Ok(ReclaimEntryOutcome::Reclaimed) => {
                reclaimed += 1;
                println!(
                    "reclaim entry {position}/{planned} reclaimed note={note_addr} \
                     token_contract={token_contract}"
                );
            }
            Ok(ReclaimEntryOutcome::NotActionable(reason)) => {
                noop += 1;
                println!(
                    "reclaim entry {position}/{planned} noop note={note_addr} \
                     token_contract={token_contract}: {reason}; no money was moved for it"
                );
            }
            Err(error) => {
                println!(
                    "reclaim entry {position}/{planned} failed note={note_addr} \
                     token_contract={token_contract}: {error:#}"
                );
                failed.push(format!(
                    "note={note_addr} token_contract={token_contract}: {error:#}"
                ));
            }
        }
    }
    println!(
        "reclaim summary: planned={planned} reclaimed={reclaimed} noop={noop} failed={} refused={}",
        failed.len(),
        plan.refused.len()
    );
    if !failed.is_empty() || !plan.refused.is_empty() {
        // The error itself carries every reason: a caller that only sees the failure must still learn
        // which recorded deals were left undecided and why.
        anyhow::bail!(
            "reclaim: {} of {} recorded entries were not decided ({} refused as contradictory); \
             re-run after fixing them -- every entry is re-decided from the chain, so nothing is \
             reclaimed twice. Refused: [{}]. Failures: [{}]",
            failed.len() + plan.refused.len(),
            planned + plan.refused.len(),
            plan.refused.len(),
            plan.refused
                .iter()
                .map(|refusal| format!(
                    "note={} token_contract={}: {}",
                    refusal.note_addr, refusal.token_contract, refusal.reason
                ))
                .collect::<Vec<_>>()
                .join("; "),
            failed.join("; ")
        );
    }
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
    let note = dexdo_core::address::parse_chain_address(&note_addr)
        .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
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
        let root = dexdo_core::address::parse_chain_address(&market.root_model)?;
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
    use crate::cli::args::{RecoverArgs, RecoveryIdentityArgs};

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
            .find("chain.submit_cleanup(&note, &keys, &tc).await")
            .expect("cleanup submit");
        let tail = &production[submit..];
        let observe = tail
            .find("chain.confirm_cleanup(&tc)")
            .expect("bounded cleanup observer");
        let marker = tail.find("marker(&note_s,").expect("terminal marker");
        let success = tail
            .find("reclaim confirmed -> streamCleanup")
            .expect("success rendering");
        assert!(observe < marker && marker < success);
        assert!(
            !tail.contains("single post-read"),
            "one pending/stale read must never be reported as a successful reclaim"
        );
        // Scope note: this pins one submit **call site** -- that the reconciliation path does not drive
        // a second cleanup itself. It is NOT a claim that the action is POSTed at most once: the submit
        // transport retries a BOC, and a re-run submits again. The money guarantee is proved by fact in
        // `a_duplicated_cleanup_post_moves_the_deals_money_only_once`.
        assert_eq!(
            production.matches("chain.submit_cleanup(").count(),
            1,
            "the ambiguous-outcome path must reconcile, not drive a second cleanup"
        );
        // The injected marker seam exists for the offline regressions only: the production command
        // must still mark the durable buyer subscription terminal, and the real chain must still
        // submit `streamCleanup` and wait on the bounded `cleanupUnopened` observer.
        assert!(production.contains(
            "drive_reclaim_plan(plan, &chain, &|note_addr, token_contract| {\n        super::buyer::mark_buyer_subscription_terminal(note_addr, token_contract)\n    })"
        ));
        assert!(production.contains("self.stream_cleanup(note, keys, tc).await?"));
        assert!(production.contains("self.wait_cleanup_unopened(tc).await?"));
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
        cleanup.expect("the exact never-opened shape past MATCH_OPEN_TIMEOUT is admissible");

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

        // `recover` consumes only "the marker ran without failing": a matched subscription and an
        // ordinary deal without a sidecar are both a plain success here.
        super::apply_recover_terminal_marker(&confirmation, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .expect("a marked subscription is a success");
        super::apply_recover_terminal_marker(&confirmation, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .expect("an ordinary deal without a subscription sidecar is a success too");
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let error = super::apply_recover_terminal_marker(&confirmation, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(anyhow::anyhow!("marker disk failure"))
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
                identity: RecoveryIdentityArgs {
                    note_key: None,
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
            Ok(())
        };
        let args = || RecoverArgs {
            identity: RecoveryIdentityArgs {
                note_key: None,
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
                identity: RecoveryIdentityArgs {
                    note_key: None,
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

    // ----: pool-only reclaim drives every recorded deal, exactly once each ----

    /// One fake never-opened deal: the chain facts `reclaim` decodes, plus the submission outcomes a
    /// real node can produce -- a clean failure, an **outcome-ambiguous** failure (the action landed and
    /// only the response was lost), and a bounded observation that stays stale.
    #[cfg(feature = "shellnet")]
    struct PoolReclaimDeal {
        buyer_note: String,
        buyer_pubkey: [u8; 32],
        state: Option<dexdo_core::DealChainState>,
        fail_submits: usize,
        ambiguous_submits: usize,
        deferred_submits: usize,
        duplicate_posts: usize,
        fail_confirms: usize,
    }

    /// A fake chain keyed by TokenContract. `cleanupUnopened` is modelled exactly as the contract
    /// behaves: it destroys the TC, so a second attempt on the same deal can find nothing to move.
    #[cfg(feature = "shellnet")]
    #[derive(Default)]
    struct PoolReclaimChain {
        deals: std::sync::Mutex<std::collections::BTreeMap<String, PoolReclaimDeal>>,
        /// Deliveries of the cleanup action, including transport retries of the same BOC.
        posts: std::sync::Mutex<Vec<String>>,
        /// Deliveries the modelled contract actually paid out -- the money moves.
        cleanups: std::sync::Mutex<Vec<String>>,
    }

    #[cfg(feature = "shellnet")]
    impl PoolReclaimChain {
        fn key(tc: &dexdo_core::Address) -> String {
            tc.with_workchain()
        }

        fn with_deal(
            self,
            token_contract: &str,
            buyer_note: &str,
            secret_hex: &str,
            state: Option<dexdo_core::DealChainState>,
            fail_submits: usize,
        ) -> Self {
            let keys = dexdo_core::KeyPair::from_secret_hex(secret_hex).unwrap();
            self.deals.lock().unwrap().insert(
                dexdo_core::Address::parse(token_contract)
                    .unwrap()
                    .with_workchain(),
                PoolReclaimDeal {
                    buyer_note: dexdo_core::Address::parse(buyer_note)
                        .unwrap()
                        .with_workchain(),
                    buyer_pubkey: dexdo_core::keypair_ed_pubkey(&keys).unwrap(),
                    state,
                    fail_submits,
                    ambiguous_submits: 0,
                    deferred_submits: 0,
                    duplicate_posts: 0,
                    fail_confirms: 0,
                },
            );
            self
        }

        fn patch(self, token_contract: &str, patch: impl FnOnce(&mut PoolReclaimDeal)) -> Self {
            let key = dexdo_core::Address::parse(token_contract)
                .unwrap()
                .with_workchain();
            patch(
                self.deals
                    .lock()
                    .unwrap()
                    .get_mut(&key)
                    .expect("known deal"),
            );
            self
        }

        /// The submit applies the cleanup on chain and then fails: the CLI cannot tell whether it landed.
        fn with_ambiguous_submit(self, token_contract: &str) -> Self {
            self.patch(token_contract, |deal| deal.ambiguous_submits = 1)
        }

        /// The bounded observation window stays stale for the first attempt.
        fn with_stale_observation(self, token_contract: &str) -> Self {
            self.patch(token_contract, |deal| deal.fail_confirms = 1)
        }

        /// `send_with_retry` delivers the same BOC a second time on a transient error.
        fn with_duplicate_post(self, token_contract: &str) -> Self {
            self.patch(token_contract, |deal| deal.duplicate_posts = 1)
        }

        /// The submission goes out and then errors, and its BOC has not been applied yet: the outcome is
        /// genuinely unknown to the client and the action can still land at any later moment.
        fn with_deferred_submit(self, token_contract: &str) -> Self {
            self.patch(token_contract, |deal| deal.deferred_submits = 1)
        }

        /// One delivery of `cleanupUnopened`, gated exactly as the contract gates it: it pays only a
        /// funded, never-opened deal, and destroys it as it refunds. Every later delivery of the same
        /// action therefore finds nothing to move.
        fn deliver(
            &self,
            deals: &mut std::collections::BTreeMap<String, PoolReclaimDeal>,
            key: &str,
        ) {
            self.posts.lock().unwrap().push(key.to_string());
            let deal = deals.get_mut(key).expect("delivery to a known deal");
            if deal
                .state
                .is_some_and(|state| state.funded && !state.opened)
            {
                self.cleanups.lock().unwrap().push(key.to_string());
                deal.state = None;
            }
        }

        /// A submission whose response was lost lands later, out of band, exactly like a retried BOC.
        fn deliver_pending(&self, token_contract: &str) {
            let key = dexdo_core::Address::parse(token_contract)
                .unwrap()
                .with_workchain();
            let mut deals = self.deals.lock().unwrap();
            self.deliver(&mut deals, &key);
        }

        fn posts(&self) -> Vec<String> {
            self.posts.lock().unwrap().clone()
        }

        /// The deal is really owned by a different buyer note(a corrupt/forged recovery record).
        fn owned_by_note(self, token_contract: &str, buyer_note: &str) -> Self {
            let buyer_note = dexdo_core::Address::parse(buyer_note)
                .unwrap()
                .with_workchain();
            self.patch(token_contract, move |deal| deal.buyer_note = buyer_note)
        }

        /// The deal is really owned by a different buyer key.
        fn owned_by_key(self, token_contract: &str, secret_hex: &str) -> Self {
            let keys = dexdo_core::KeyPair::from_secret_hex(secret_hex).unwrap();
            let buyer_pubkey = dexdo_core::keypair_ed_pubkey(&keys).unwrap();
            self.patch(token_contract, move |deal| deal.buyer_pubkey = buyer_pubkey)
        }

        fn cleanups(&self) -> Vec<String> {
            self.cleanups.lock().unwrap().clone()
        }
    }

    #[cfg(feature = "shellnet")]
    #[async_trait::async_trait]
    impl super::ReclaimChain for PoolReclaimChain {
        async fn state(
            &self,
            tc: &dexdo_core::Address,
        ) -> anyhow::Result<Option<dexdo_core::DealChainState>> {
            Ok(self
                .deals
                .lock()
                .unwrap()
                .get(&Self::key(tc))
                .and_then(|deal| deal.state))
        }

        async fn buyer_note(
            &self,
            tc: &dexdo_core::Address,
        ) -> anyhow::Result<Option<dexdo_core::Address>> {
            Ok(self
                .deals
                .lock()
                .unwrap()
                .get(&Self::key(tc))
                .map(|deal| dexdo_core::Address::parse(&deal.buyer_note).unwrap()))
        }

        async fn buyer_pubkey(&self, tc: &dexdo_core::Address) -> anyhow::Result<Option<[u8; 32]>> {
            Ok(self
                .deals
                .lock()
                .unwrap()
                .get(&Self::key(tc))
                .map(|deal| deal.buyer_pubkey))
        }

        async fn submit_cleanup(
            &self,
            note: &dexdo_core::Address,
            keys: &dexdo_core::KeyPair,
            tc: &dexdo_core::Address,
        ) -> anyhow::Result<()> {
            let key = Self::key(tc);
            let mut deals = self.deals.lock().unwrap();
            let deal = deals
                .get_mut(&key)
                .expect("cleanup is only ever submitted for a deal the chain knows");
            assert_eq!(
                note.with_workchain(),
                deal.buyer_note,
                "each entry must be signed by its own recorded note"
            );
            assert_eq!(
                dexdo_core::keypair_ed_pubkey(keys).unwrap(),
                deal.buyer_pubkey,
                "each entry must be signed by its own recorded owner key"
            );
            if deal.fail_submits > 0 {
                deal.fail_submits -= 1;
                anyhow::bail!("simulated cleanupUnopened submit failure for {key}");
            }
            if deal.ambiguous_submits > 0 {
                deal.ambiguous_submits -= 1;
                self.deliver(&mut deals, &key);
                anyhow::bail!("simulated lost response after cleanupUnopened landed for {key}");
            }
            if deal.deferred_submits > 0 {
                deal.deferred_submits -= 1;
                // The BOC is out -- recorded as a delivery attempt -- but has not been applied yet.
                self.posts.lock().unwrap().push(key.clone());
                anyhow::bail!("simulated submission of {key} whose outcome is still unknown");
            }
            let retries = deal.duplicate_posts;
            self.deliver(&mut deals, &key);
            for _ in 0..retries {
                self.deliver(&mut deals, &key);
            }
            Ok(())
        }

        async fn confirm_cleanup(&self, tc: &dexdo_core::Address) -> anyhow::Result<()> {
            let key = Self::key(tc);
            let mut deals = self.deals.lock().unwrap();
            let deal = deals.get_mut(&key).expect("observation of a known deal");
            if deal.fail_confirms > 0 {
                deal.fail_confirms -= 1;
                anyhow::bail!("simulated stale observation window for {key}");
            }
            // The real observer polls until the TokenContract is absent or no longer funded, and errors
            // out otherwise; it never reports a still-funded deal as a confirmed cleanup.
            match &deal.state {
                None => Ok(()),
                Some(state) if !state.funded => Ok(()),
                Some(_) => {
                    anyhow::bail!("simulated observation: TokenContract {key} is still funded")
                }
            }
        }
    }

    #[cfg(feature = "shellnet")]
    fn reclaim_test_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dexdo-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    #[cfg(feature = "shellnet")]
    fn write_reclaim_pool(dir: &std::path::Path, notes: serde_json::Value) -> std::path::PathBuf {
        let pool_path = dir.join("pn_pool.json");
        std::fs::write(
            &pool_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "token_type": dexdo_core::params::SHELL_CURRENCY_ID,
                "notes": notes,
            }))
            .unwrap(),
        )
        .unwrap();
        pool_path
    }

    /// The production entry point of `dexdo reclaim --pool <file>`: the real plan resolver over the real
    /// pool file, then the real driver. Only the chain and the durable subscription marker are faked.
    #[cfg(feature = "shellnet")]
    async fn run_pool_only_reclaim(
        pool_path: &std::path::Path,
        chain: &PoolReclaimChain,
    ) -> anyhow::Result<()> {
        // `Ok(false)`: these fixtures carry no durable subscription record, so there is nothing to mark.
        run_pool_only_reclaim_with_marker(pool_path, chain, &|_note, _tc| Ok(false)).await
    }

    #[cfg(feature = "shellnet")]
    async fn run_pool_only_reclaim_with_marker(
        pool_path: &std::path::Path,
        chain: &PoolReclaimChain,
        marker: &(dyn Fn(&str, &str) -> anyhow::Result<bool> + Sync),
    ) -> anyhow::Result<()> {
        let plan = crate::cli::commands::resolve_pool_recovery_plan(
            &RecoveryIdentityArgs {
                note_key: None,
                note_addr: None,
            },
            None,
            None,
            Some(pool_path),
        )?;
        super::drive_reclaim_plan(plan, chain, marker).await
    }

    #[cfg(feature = "shellnet")]
    fn never_opened_state() -> dexdo_core::DealChainState {
        chain_state(true, false, false, false, 100)
    }

    #[cfg(feature = "shellnet")]
    fn note_a() -> (String, String, String) {
        (
            format!("0:{}", "1".repeat(64)),
            "2a".repeat(32),
            format!("0:{}", "2".repeat(64)),
        )
    }

    #[cfg(feature = "shellnet")]
    fn note_b() -> (String, String, String) {
        (
            format!("0:{}", "3".repeat(64)),
            "3b".repeat(32),
            format!("0:{}", "4".repeat(64)),
        )
    }

    /// One recorded pool row, exactly as the buyer writes it.
    #[cfg(feature = "shellnet")]
    fn recorded_row(
        note_addr: &str,
        secret: &str,
        token_contract: &str,
        recorded_at_unix: u64,
    ) -> serde_json::Value {
        recorded_row_as(note_addr, secret, token_contract, recorded_at_unix, "buyer")
    }

    #[cfg(feature = "shellnet")]
    fn recorded_row_as(
        note_addr: &str,
        secret: &str,
        token_contract: &str,
        recorded_at_unix: u64,
        role: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "address": note_addr,
            "owner_secret_key_hex": secret,
            "token_contract": token_contract,
            "token_contract_role": role,
            "token_contract_updated_at_unix": recorded_at_unix,
        })
    }

    /// primary regression: an ordinary pool holding two recoverable entries is driven from pool
    /// metadata alone -- no `--note-addr`, no `--token-contract` -- and the order comes from each entry's
    /// own recorded `token_contract_updated_at_unix`, not from its position in the file.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn pool_only_reclaim_drives_every_recorded_entry_in_recorded_order() {
        let dir = reclaim_test_dir("reclaim-two-entries");
        let _cleanup = TempDirCleanup(dir.clone());
        let (note_a, secret_a, tc_a) = note_a();
        let (note_b, secret_b, tc_b) = note_b();
        // The later-recorded deal is written first, so file order and recorded order disagree.
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([
                {
                    "address": note_a,
                    "owner_secret_key_hex": secret_a,
                    "token_contract": tc_a,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 200
                },
                {
                    "address": note_b,
                    "owner_secret_key_hex": secret_b,
                    "token_contract": tc_b,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 100
                }
            ]),
        );
        let chain = PoolReclaimChain::default()
            .with_deal(&tc_a, &note_a, &secret_a, Some(never_opened_state()), 0)
            .with_deal(&tc_b, &note_b, &secret_b, Some(never_opened_state()), 0);

        run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect("pool metadata alone must be enough to reclaim every recorded deal");

        let tc_a = dexdo_core::Address::parse(&tc_a).unwrap().with_workchain();
        let tc_b = dexdo_core::Address::parse(&tc_b).unwrap().with_workchain();
        assert_eq!(
            chain.cleanups(),
            vec![tc_b, tc_a],
            "both recorded deals are reclaimed, earliest recorded first"
        );
    }

    /// Restart/idempotence: the very same invocation, run twice, moves no deal's money twice.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn pool_only_reclaim_repeated_invocation_moves_no_money_twice() {
        let dir = reclaim_test_dir("reclaim-repeat");
        let _cleanup = TempDirCleanup(dir.clone());
        let (note_a, secret_a, tc_a) = note_a();
        let (note_b, secret_b, tc_b) = note_b();
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([
                {
                    "address": note_a,
                    "owner_secret_key_hex": secret_a,
                    "token_contract": tc_a,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 100
                },
                {
                    "address": note_b,
                    "owner_secret_key_hex": secret_b,
                    "token_contract": tc_b,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 200
                }
            ]),
        );
        let chain = PoolReclaimChain::default()
            .with_deal(&tc_a, &note_a, &secret_a, Some(never_opened_state()), 0)
            .with_deal(&tc_b, &note_b, &secret_b, Some(never_opened_state()), 0);

        run_pool_only_reclaim(&pool_path, &chain).await.unwrap();
        let after_first = chain.cleanups();
        assert_eq!(after_first.len(), 2);

        run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect("re-running the identical command is a decided no-op, not a failure");
        assert_eq!(
            chain.cleanups(),
            after_first,
            "an already-reclaimed deal must never be moved a second time"
        );
    }

    /// An entry that was already reclaimed(its TokenContract is gone) and an entry that was never funded
    /// are both decided as no-ops, while the one live recoverable entry is still recovered.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn pool_only_reclaim_skips_already_reclaimed_entries_without_a_second_move() {
        let dir = reclaim_test_dir("reclaim-already-done");
        let _cleanup = TempDirCleanup(dir.clone());
        let (note_a, secret_a, tc_a) = note_a();
        let (note_b, secret_b, tc_b) = note_b();
        let note_c = format!("0:{}", "5".repeat(64));
        let secret_c = "4c".repeat(32);
        let tc_c = format!("0:{}", "6".repeat(64));
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([
                {
                    "address": note_a,
                    "owner_secret_key_hex": secret_a,
                    "token_contract": tc_a,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 100
                },
                {
                    "address": note_b,
                    "owner_secret_key_hex": secret_b,
                    "token_contract": tc_b,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 200
                },
                {
                    "address": note_c,
                    "owner_secret_key_hex": secret_c,
                    "token_contract": tc_c,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 300
                }
            ]),
        );
        let chain = PoolReclaimChain::default()
            // already reclaimed: the TokenContract selfdestructed
            .with_deal(&tc_a, &note_a, &secret_a, None, 0)
            // never funded: nothing to reclaim
            .with_deal(
                &tc_b,
                &note_b,
                &secret_b,
                Some(chain_state(false, false, false, false, 0)),
                0,
            )
            .with_deal(&tc_c, &note_c, &secret_c, Some(never_opened_state()), 0);

        run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect("decided no-ops must not fail the recovery of the other entries");
        assert_eq!(
            chain.cleanups(),
            vec![dexdo_core::Address::parse(&tc_c).unwrap().with_workchain()],
            "only the one live never-opened deal may move money"
        );
    }

    /// Contradictory records still fail closed: a note recorded against two different TokenContracts, and
    /// one TokenContract recorded against two different notes, are both refused outright -- the pool is
    /// never guessed at -- while an unambiguous entry alongside them is still recovered.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn pool_only_reclaim_fails_closed_on_contradictory_records() {
        let dir = reclaim_test_dir("reclaim-contradictory");
        let _cleanup = TempDirCleanup(dir.clone());
        let (note_a, secret_a, tc_a) = note_a();
        let (note_b, secret_b, tc_b) = note_b();
        let contradicting_tc = format!("0:{}", "7".repeat(64));
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([
                {
                    "address": note_a,
                    "owner_secret_key_hex": secret_a,
                    "token_contract": tc_a,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 100
                },
                {
                    "address": note_a,
                    "owner_secret_key_hex": secret_a,
                    "token_contract": contradicting_tc,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 150
                },
                {
                    "address": note_b,
                    "owner_secret_key_hex": secret_b,
                    "token_contract": tc_b,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 200
                }
            ]),
        );
        let chain = PoolReclaimChain::default()
            .with_deal(&tc_a, &note_a, &secret_a, Some(never_opened_state()), 0)
            .with_deal(
                &contradicting_tc,
                &note_a,
                &secret_a,
                Some(never_opened_state()),
                0,
            )
            .with_deal(&tc_b, &note_b, &secret_b, Some(never_opened_state()), 0);

        let error = run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect_err("a contradictory record must keep the command failing closed")
            .to_string();
        assert!(
            error.contains("2 of 3 recorded entries were not decided (2 refused as contradictory)"),
            "{error}"
        );
        assert_eq!(
            chain.cleanups(),
            vec![dexdo_core::Address::parse(&tc_b).unwrap().with_workchain()],
            "neither TokenContract of the contradictory note may be touched"
        );
    }

    /// The same fail-closed rule for the mirror-image contradiction: two notes recorded as the buyer of
    /// one TokenContract.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn pool_only_reclaim_fails_closed_when_two_notes_claim_one_deal() {
        let dir = reclaim_test_dir("reclaim-two-notes-one-tc");
        let _cleanup = TempDirCleanup(dir.clone());
        let (note_a, secret_a, tc_a) = note_a();
        let (note_b, secret_b, ..) = note_b();
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([
                {
                    "address": note_a,
                    "owner_secret_key_hex": secret_a,
                    "token_contract": tc_a,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 100
                },
                {
                    "address": note_b,
                    "owner_secret_key_hex": secret_b,
                    "token_contract": tc_a,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 200
                }
            ]),
        );
        let chain = PoolReclaimChain::default().with_deal(
            &tc_a,
            &note_a,
            &secret_a,
            Some(never_opened_state()),
            0,
        );

        let error = run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect_err("two notes claiming one deal must fail closed")
            .to_string();
        assert!(error.contains("2 refused as contradictory"), "{error}");
        assert!(chain.cleanups().is_empty(), "no money may move");
    }

    /// A single recorded entry keeps its pre- behaviour exactly: it is reclaimed when it is
    /// reclaimable, and a deal this command cannot move stays a loud, non-zero failure.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn single_recorded_entry_keeps_the_unchanged_loud_failure() {
        let dir = reclaim_test_dir("reclaim-single");
        let _cleanup = TempDirCleanup(dir.clone());
        let (note_a, secret_a, tc_a) = note_a();
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([{
                "address": note_a,
                "owner_secret_key_hex": secret_a,
                "token_contract": tc_a,
                "token_contract_role": "buyer",
                "token_contract_updated_at_unix": 100
            }]),
        );

        let gone = PoolReclaimChain::default().with_deal(&tc_a, &note_a, &secret_a, None, 0);
        let error = run_pool_only_reclaim(&pool_path, &gone)
            .await
            .expect_err("a single unreclaimable entry stays a loud failure")
            .to_string();
        assert_eq!(
            error,
            format!(
                "reclaim: TokenContract {} is not active (undeployed/closed)",
                dexdo_core::Address::parse(&tc_a).unwrap()
            )
        );
        assert!(gone.cleanups().is_empty());

        let open = PoolReclaimChain::default().with_deal(
            &tc_a,
            &note_a,
            &secret_a,
            Some(chain_state(true, true, false, false, 100)),
            0,
        );
        let error = run_pool_only_reclaim(&pool_path, &open)
            .await
            .expect_err("an OPEN deal still refuses the never-opened cleanup")
            .to_string();
        assert!(
            error.contains("must use the explicit buyer STOP path"),
            "{error}"
        );
        assert!(open.cleanups().is_empty());

        let live = PoolReclaimChain::default().with_deal(
            &tc_a,
            &note_a,
            &secret_a,
            Some(never_opened_state()),
            0,
        );
        run_pool_only_reclaim(&pool_path, &live)
            .await
            .expect("a single reclaimable entry is reclaimed as before");
        assert_eq!(live.cleanups().len(), 1);
    }

    /// Option(1)'s own risk: a failure part-way through the sequence must neither lose the remaining
    /// entries nor let a retry drive an already-reclaimed one a second time.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn pool_only_reclaim_partial_failure_neither_loses_nor_double_drives_the_rest() {
        let dir = reclaim_test_dir("reclaim-partial-failure");
        let _cleanup = TempDirCleanup(dir.clone());
        let (note_a, secret_a, tc_a) = note_a();
        let (note_b, secret_b, tc_b) = note_b();
        let note_c = format!("0:{}", "5".repeat(64));
        let secret_c = "4c".repeat(32);
        let tc_c = format!("0:{}", "6".repeat(64));
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([
                {
                    "address": note_a,
                    "owner_secret_key_hex": secret_a,
                    "token_contract": tc_a,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 100
                },
                {
                    "address": note_b,
                    "owner_secret_key_hex": secret_b,
                    "token_contract": tc_b,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 200
                },
                {
                    "address": note_c,
                    "owner_secret_key_hex": secret_c,
                    "token_contract": tc_c,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 300
                }
            ]),
        );
        // The middle entry's submit fails once, exactly as a transient submission failure would.
        let chain = PoolReclaimChain::default()
            .with_deal(&tc_a, &note_a, &secret_a, Some(never_opened_state()), 0)
            .with_deal(&tc_b, &note_b, &secret_b, Some(never_opened_state()), 1)
            .with_deal(&tc_c, &note_c, &secret_c, Some(never_opened_state()), 0);

        let tc_a = dexdo_core::Address::parse(&tc_a).unwrap().with_workchain();
        let tc_b = dexdo_core::Address::parse(&tc_b).unwrap().with_workchain();
        let tc_c = dexdo_core::Address::parse(&tc_c).unwrap().with_workchain();

        let error = run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect_err("a failed entry must surface as a non-zero exit")
            .to_string();
        assert!(
            error.contains("simulated cleanupUnopened submit failure"),
            "{error}"
        );
        assert_eq!(
            chain.cleanups(),
            vec![tc_a.clone(), tc_c.clone()],
            "the entries after the failure are still driven"
        );

        run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect("the retry recovers the remaining entry");
        assert_eq!(
            chain.cleanups(),
            vec![tc_a, tc_c, tc_b],
            "the retry moves only the entry that was never reclaimed"
        );
    }

    /// `--note-key` names one note's owner key: applying it to several recorded notes is an ambiguous
    /// instruction on a money path, so it fails closed instead of guessing.
    #[cfg(feature = "shellnet")]
    #[test]
    fn note_key_with_several_recorded_entries_fails_closed() {
        let dir = reclaim_test_dir("reclaim-note-key-ambiguous");
        let _cleanup = TempDirCleanup(dir.clone());
        let (note_a, secret_a, tc_a) = note_a();
        let (note_b, secret_b, tc_b) = note_b();
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([
                {
                    "address": note_a,
                    "owner_secret_key_hex": secret_a,
                    "token_contract": tc_a,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 100
                },
                {
                    "address": note_b,
                    "owner_secret_key_hex": secret_b,
                    "token_contract": tc_b,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 200
                }
            ]),
        );
        let key_path = dir.join("note.key");
        std::fs::write(&key_path, &secret_a).unwrap();

        // Not `expect_err`: a plan carries note secrets, and nothing on this path may render them.
        let error = match crate::cli::commands::resolve_pool_recovery_plan(
            &RecoveryIdentityArgs {
                note_key: Some(key_path),
                note_addr: None,
            },
            None,
            None,
            Some(&pool_path),
        ) {
            Ok(_) => panic!("one key cannot stand for several recorded notes"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("--note-key names a single"), "{error}");
    }

    /// A recorded entry the chain contradicts on ownership is a corrupt or forged recovery record, not a
    /// decided no-op: it must never be counted as a clean "nothing to do" beside a valid sibling.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn contradicted_buyer_note_or_key_fails_loud_with_no_submit() {
        let (note_a, secret_a, tc_a) = note_a();
        let (note_b, secret_b, tc_b) = note_b();
        let foreign_note = format!("0:{}", "9".repeat(64));
        let foreign_secret = "5d".repeat(32);

        for (name, expected) in [
            ("wrong-note", "the deal's buyer note is"),
            ("wrong-key", "is not the buyer key of"),
        ] {
            let dir = reclaim_test_dir(&format!("reclaim-contradicted-{name}"));
            let _cleanup = TempDirCleanup(dir.clone());
            let pool_path = write_reclaim_pool(
                &dir,
                serde_json::json!([
                    recorded_row(&note_a, &secret_a, &tc_a, 100),
                    recorded_row(&note_b, &secret_b, &tc_b, 200),
                ]),
            );
            let chain = PoolReclaimChain::default()
                .with_deal(&tc_a, &note_a, &secret_a, Some(never_opened_state()), 0)
                .with_deal(&tc_b, &note_b, &secret_b, Some(never_opened_state()), 0);
            let chain = if name == "wrong-note" {
                chain.owned_by_note(&tc_a, &foreign_note)
            } else {
                chain.owned_by_key(&tc_a, &foreign_secret)
            };

            let error = run_pool_only_reclaim(&pool_path, &chain)
                .await
                .expect_err("a contradicted ownership record must not exit 0")
                .to_string();
            assert!(error.contains(expected), "{name}: {error}");
            assert!(error.contains("nothing was submitted"), "{name}: {error}");
            assert_eq!(
                chain.cleanups(),
                vec![dexdo_core::Address::parse(&tc_b).unwrap().with_workchain()],
                "{name}: the contradicted entry must move no money while its valid sibling still does"
            );
        }
    }

    /// A submit whose outcome is ambiguous(the action landed, the response was lost) is reconciled by
    /// the same bounded observation, never by submitting the money action again.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn ambiguous_submit_is_reconciled_by_observation_without_a_second_submit() {
        let dir = reclaim_test_dir("reclaim-ambiguous-submit");
        let _cleanup = TempDirCleanup(dir.clone());
        let (note_a, secret_a, tc_a) = note_a();
        let (note_b, secret_b, tc_b) = note_b();
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([
                recorded_row(&note_a, &secret_a, &tc_a, 100),
                recorded_row(&note_b, &secret_b, &tc_b, 200),
            ]),
        );
        let chain = PoolReclaimChain::default()
            .with_deal(&tc_a, &note_a, &secret_a, Some(never_opened_state()), 0)
            .with_deal(&tc_b, &note_b, &secret_b, Some(never_opened_state()), 0)
            .with_ambiguous_submit(&tc_a);

        run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect("a cleanup proven landed by observation is a success, not a failure");
        let tc_a_key = dexdo_core::Address::parse(&tc_a).unwrap().with_workchain();
        let tc_b_key = dexdo_core::Address::parse(&tc_b).unwrap().with_workchain();
        assert_eq!(chain.cleanups(), vec![tc_a_key.clone(), tc_b_key.clone()]);

        // Restart: the reconciled deal is already terminal, so nothing is submitted for it again.
        run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect("the restart is a decided no-op");
        assert_eq!(chain.cleanups(), vec![tc_a_key, tc_b_key]);
    }

    /// A submit that fails while the observation window stays stale is genuinely unresolved: it must be
    /// loud, must not be re-submitted, and must still be recoverable on a later run.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn unresolved_submit_outcome_is_loud_and_still_reclaimable_later() {
        let dir = reclaim_test_dir("reclaim-unresolved-submit");
        let _cleanup = TempDirCleanup(dir.clone());
        let (note_a, secret_a, tc_a) = note_a();
        let (note_b, secret_b, tc_b) = note_b();
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([
                recorded_row(&note_a, &secret_a, &tc_a, 100),
                recorded_row(&note_b, &secret_b, &tc_b, 200),
            ]),
        );
        let chain = PoolReclaimChain::default()
            .with_deal(&tc_a, &note_a, &secret_a, Some(never_opened_state()), 1)
            .with_deal(&tc_b, &note_b, &secret_b, Some(never_opened_state()), 0);
        let tc_a_key = dexdo_core::Address::parse(&tc_a).unwrap().with_workchain();
        let tc_b_key = dexdo_core::Address::parse(&tc_b).unwrap().with_workchain();

        let error = run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect_err("an unresolved submit outcome must exit non-zero")
            .to_string();
        assert!(error.contains("its outcome is unresolved"), "{error}");
        assert!(
            error.contains("this run drove no further cleanup for it"),
            "{error}"
        );
        assert_eq!(chain.cleanups(), vec![tc_b_key.clone()]);

        run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect("the retry recovers the entry whose submit had failed");
        assert_eq!(chain.cleanups(), vec![tc_b_key, tc_a_key]);
    }

    /// The guarantee actually needs, stated and tested as itself: **no second money move**. The
    /// transport may deliver the same cleanup BOC more than once, and an operator may re-run the command
    /// after an unresolved outcome -- neither can pay the deal out twice, because `cleanupUnopened` only
    /// accepts a funded, never-opened deal and destroys it as it refunds.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn a_duplicated_cleanup_post_moves_the_deals_money_only_once() {
        let (note_a, secret_a, tc_a) = note_a();
        let tc_a_key = dexdo_core::Address::parse(&tc_a).unwrap().with_workchain();

        // 1. The transport retries the same BOC: two deliveries, one payout.
        let dir = reclaim_test_dir("reclaim-duplicate-post");
        let _cleanup = TempDirCleanup(dir.clone());
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([recorded_row(&note_a, &secret_a, &tc_a, 100)]),
        );
        let chain = PoolReclaimChain::default()
            .with_deal(&tc_a, &note_a, &secret_a, Some(never_opened_state()), 0)
            .with_duplicate_post(&tc_a);

        run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect("a retried delivery is still one successful reclaim");
        assert_eq!(
            chain.posts(),
            vec![tc_a_key.clone(), tc_a_key.clone()],
            "the transport delivered the action twice"
        );
        assert_eq!(
            chain.cleanups(),
            vec![tc_a_key.clone()],
            "the contract paid the deal exactly once"
        );

        // 2. An unresolved submit that lands out of band BEFORE the operator re-runs: the re-run finds
        // the deal already settled, so it submits nothing at all and no second payout is possible.
        let dir = reclaim_test_dir("reclaim-late-landing");
        let _cleanup = TempDirCleanup(dir.clone());
        let (note_b, secret_b, tc_b) = note_b();
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([
                recorded_row(&note_a, &secret_a, &tc_a, 100),
                recorded_row(&note_b, &secret_b, &tc_b, 200),
            ]),
        );
        let chain = PoolReclaimChain::default()
            .with_deal(&tc_a, &note_a, &secret_a, Some(never_opened_state()), 1)
            .with_deal(&tc_b, &note_b, &secret_b, Some(never_opened_state()), 0);
        let tc_b_key = dexdo_core::Address::parse(&tc_b).unwrap().with_workchain();

        let error = run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect_err("the first run cannot resolve the submitted outcome")
            .to_string();
        assert!(error.contains("its outcome is unresolved"), "{error}");
        assert!(error.contains("cannot pay it out twice"), "{error}");
        assert_eq!(chain.cleanups(), vec![tc_b_key.clone()]);

        // The lost submission lands out of band, exactly like a retried BOC would.
        chain.deliver_pending(&tc_a);
        assert_eq!(chain.cleanups(), vec![tc_b_key.clone(), tc_a_key.clone()]);
        let posts_before_rerun = chain.posts();

        run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect("the re-run finds both deals settled");
        assert_eq!(
            chain.posts(),
            posts_before_rerun,
            "a deal already settled on chain is not submitted again at all"
        );
        assert_eq!(
            chain.cleanups(),
            vec![tc_b_key, tc_a_key.clone()],
            "the landed submission paid once and the re-run added nothing"
        );

        // 3. The case the guarantee is really about: the first run's BOC is still in flight when the
        // operator re-runs, so the deal still looks funded and the re-run DOES submit a second time.
        // Then the first submission lands too -- three deliveries of the same action, one payout.
        let dir = reclaim_test_dir("reclaim-inflight-rerun");
        let _cleanup = TempDirCleanup(dir.clone());
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([recorded_row(&note_a, &secret_a, &tc_a, 100)]),
        );
        let chain = PoolReclaimChain::default()
            .with_deal(&tc_a, &note_a, &secret_a, Some(never_opened_state()), 0)
            .with_deferred_submit(&tc_a);

        let error = run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect_err("an in-flight submission is an unresolved outcome")
            .to_string();
        assert!(error.contains("its outcome is unresolved"), "{error}");
        assert_eq!(chain.posts(), vec![tc_a_key.clone()], "one delivery so far");
        assert!(chain.cleanups().is_empty(), "nothing has been paid yet");

        run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect("the re-run drives the still-funded deal");
        assert_eq!(
            chain.posts(),
            vec![tc_a_key.clone(), tc_a_key.clone()],
            "the re-run submitted the same action a second time"
        );

        // The first, in-flight submission finally lands on top of the settled deal.
        chain.deliver_pending(&tc_a);
        assert_eq!(
            chain.posts(),
            vec![tc_a_key.clone(), tc_a_key.clone(), tc_a_key.clone()],
            "three deliveries of the same cleanup action"
        );
        assert_eq!(
            chain.cleanups(),
            vec![tc_a_key],
            "the contract paid the deal exactly once across all three"
        );
    }

    /// The other ambiguous shape: the submit is accepted but the bounded observation window stays
    /// stale. That is not a settled cleanup, so it must be loud -- and the retry must not submit again.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn accepted_submit_with_a_stale_observation_is_never_reported_as_settled() {
        let dir = reclaim_test_dir("reclaim-stale-observation");
        let _cleanup = TempDirCleanup(dir.clone());
        let (note_a, secret_a, tc_a) = note_a();
        let (note_b, secret_b, tc_b) = note_b();
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([
                recorded_row(&note_a, &secret_a, &tc_a, 100),
                recorded_row(&note_b, &secret_b, &tc_b, 200),
            ]),
        );
        let chain = PoolReclaimChain::default()
            .with_deal(&tc_a, &note_a, &secret_a, Some(never_opened_state()), 0)
            .with_deal(&tc_b, &note_b, &secret_b, Some(never_opened_state()), 0)
            .with_stale_observation(&tc_a);
        let tc_a_key = dexdo_core::Address::parse(&tc_a).unwrap().with_workchain();
        let tc_b_key = dexdo_core::Address::parse(&tc_b).unwrap().with_workchain();

        let error = run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect_err("an unconfirmed cleanup must never be reported as settled")
            .to_string();
        assert!(error.contains("settlement is not confirmed"), "{error}");
        assert_eq!(chain.cleanups(), vec![tc_a_key.clone(), tc_b_key.clone()]);

        run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect("the retry observes the settled deal and moves nothing");
        assert_eq!(chain.cleanups(), vec![tc_a_key, tc_b_key]);
    }

    /// A confirmed cleanup whose local marker failed leaves durable subscription state stale. The next
    /// run must repair it -- with zero submits -- instead of walking past it forever.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn failed_subscription_marker_is_repaired_on_the_next_run_without_a_second_submit() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = reclaim_test_dir("reclaim-marker-repair");
        let _cleanup = TempDirCleanup(dir.clone());
        let (note_a, secret_a, tc_a) = note_a();
        let (note_b, secret_b, tc_b) = note_b();
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([
                recorded_row(&note_a, &secret_a, &tc_a, 100),
                recorded_row(&note_b, &secret_b, &tc_b, 200),
            ]),
        );
        let chain = PoolReclaimChain::default()
            .with_deal(&tc_a, &note_a, &secret_a, Some(never_opened_state()), 0)
            // The sibling is already terminal; only the marker keeps it interesting.
            .with_deal(&tc_b, &note_b, &secret_b, None, 0);
        let marker_calls = AtomicUsize::new(0);
        let marker = |_note: &str, _tc: &str| {
            if marker_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                anyhow::bail!("simulated durable subscription write failure");
            }
            Ok(true)
        };

        let error = run_pool_only_reclaim_with_marker(&pool_path, &chain, &marker)
            .await
            .expect_err("a failed marker after a confirmed money move must be loud")
            .to_string();
        assert!(
            error.contains("simulated durable subscription write failure"),
            "{error}"
        );
        let tc_a_key = dexdo_core::Address::parse(&tc_a).unwrap().with_workchain();
        assert_eq!(chain.cleanups(), vec![tc_a_key.clone()]);

        run_pool_only_reclaim_with_marker(&pool_path, &chain, &marker)
            .await
            .expect("the repair run succeeds");
        assert_eq!(
            chain.cleanups(),
            vec![tc_a_key],
            "the repair must not move money again"
        );
        assert_eq!(
            marker_calls.load(Ordering::SeqCst),
            4,
            "run 1 marks the reclaimed deal (failing) and the terminal sibling; run 2 re-marks both, \
             which is what repairs the record the first run could not write"
        );
    }

    /// A pool row that claims recovery metadata but is missing or mistyping part of it is refused before
    /// any chain contact -- never silently dropped from the plan while its escrow stays stranded.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn malformed_recovery_metadata_is_refused_before_any_chain_contact() {
        let (note_a, secret_a, tc_a) = note_a();
        let (note_b, secret_b, tc_b) = note_b();
        for (name, malformed, expected) in [
            (
                "no-secret",
                serde_json::json!({
                    "address": note_b,
                    "token_contract": tc_b,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 200
                }),
                "no string owner_secret_key_hex",
            ),
            (
                "no-address",
                serde_json::json!({
                    "owner_secret_key_hex": secret_b,
                    "token_contract": tc_b,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": 200
                }),
                "no string address",
            ),
            (
                "non-string-tc",
                serde_json::json!({
                    "address": note_b,
                    "owner_secret_key_hex": secret_b,
                    "token_contract": 7,
                    "token_contract_role": "buyer"
                }),
                "token_contract is present but is not a string",
            ),
            (
                "malformed-timestamp",
                serde_json::json!({
                    "address": note_b,
                    "owner_secret_key_hex": secret_b,
                    "token_contract": tc_b,
                    "token_contract_role": "buyer",
                    "token_contract_updated_at_unix": "yesterday"
                }),
                "token_contract_updated_at_unix is not a unix second count",
            ),
        ] {
            let dir = reclaim_test_dir(&format!("reclaim-malformed-{name}"));
            let _cleanup = TempDirCleanup(dir.clone());
            let pool_path = write_reclaim_pool(
                &dir,
                serde_json::json!([recorded_row(&note_a, &secret_a, &tc_a, 100), malformed]),
            );
            let chain = PoolReclaimChain::default().with_deal(
                &tc_a,
                &note_a,
                &secret_a,
                Some(never_opened_state()),
                0,
            );

            let error = run_pool_only_reclaim(&pool_path, &chain)
                .await
                .expect_err("malformed recovery metadata must be refused")
                .to_string();
            assert!(error.contains(expected), "{name}: {error}");
            assert!(
                chain.cleanups().is_empty(),
                "{name}: the refusal must happen before any chain contact"
            );
        }
    }

    /// The documented duplicate rule: rows for one recorded deal collapse only when every recorded fact
    /// agrees. Exact duplicates are one deal; rows that disagree on the role or the recorded time are a
    /// contradiction. Either way the outcome cannot depend on the order of rows in the file.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn rows_for_one_deal_collapse_only_when_every_recorded_fact_agrees() {
        let (note_a, secret_a, tc_a) = note_a();
        let (note_b, secret_b, tc_b) = note_b();
        let tc_a_key = dexdo_core::Address::parse(&tc_a).unwrap().with_workchain();
        let tc_b_key = dexdo_core::Address::parse(&tc_b).unwrap().with_workchain();

        // Exact duplicate rows are one deal recorded twice: one money move, in both file orders.
        for (name, rows) in [
            (
                "duplicate-first",
                serde_json::json!([
                    recorded_row(&note_a, &secret_a, &tc_a, 100),
                    recorded_row(&note_a, &secret_a, &tc_a, 100),
                    recorded_row(&note_b, &secret_b, &tc_b, 200),
                ]),
            ),
            (
                "duplicate-last",
                serde_json::json!([
                    recorded_row(&note_b, &secret_b, &tc_b, 200),
                    recorded_row(&note_a, &secret_a, &tc_a, 100),
                    recorded_row(&note_a, &secret_a, &tc_a, 100),
                ]),
            ),
        ] {
            let dir = reclaim_test_dir(&format!("reclaim-{name}"));
            let _cleanup = TempDirCleanup(dir.clone());
            let pool_path = write_reclaim_pool(&dir, rows);
            let chain = PoolReclaimChain::default()
                .with_deal(&tc_a, &note_a, &secret_a, Some(never_opened_state()), 0)
                .with_deal(&tc_b, &note_b, &secret_b, Some(never_opened_state()), 0);

            run_pool_only_reclaim(&pool_path, &chain)
                .await
                .expect("exact duplicate rows are one deal, not a contradiction");
            assert_eq!(
                chain.cleanups(),
                vec![tc_a_key.clone(), tc_b_key.clone()],
                "{name}: one move per recorded deal, ordered by the recorded facts"
            );
        }

        // Rows that agree on the deal but disagree on a recorded fact are refused, in either order.
        let disagreeing_role = serde_json::json!({
            "address": note_a,
            "owner_secret_key_hex": secret_a,
            "token_contract": tc_a,
            "token_contract_role": "unknown",
            "token_contract_updated_at_unix": 100
        });
        let disagreeing_time = recorded_row(&note_a, &secret_a, &tc_a, 101);
        for (name, rows) in [
            (
                "role",
                serde_json::json!([
                    recorded_row(&note_a, &secret_a, &tc_a, 100),
                    disagreeing_role,
                    recorded_row(&note_b, &secret_b, &tc_b, 200),
                ]),
            ),
            (
                "time",
                serde_json::json!([
                    recorded_row(&note_b, &secret_b, &tc_b, 200),
                    disagreeing_time,
                    recorded_row(&note_a, &secret_a, &tc_a, 100),
                ]),
            ),
        ] {
            let dir = reclaim_test_dir(&format!("reclaim-disagreeing-{name}"));
            let _cleanup = TempDirCleanup(dir.clone());
            let pool_path = write_reclaim_pool(&dir, rows);
            let chain = PoolReclaimChain::default()
                .with_deal(&tc_a, &note_a, &secret_a, Some(never_opened_state()), 0)
                .with_deal(&tc_b, &note_b, &secret_b, Some(never_opened_state()), 0);

            let error = run_pool_only_reclaim(&pool_path, &chain)
                .await
                .expect_err("rows that disagree on a recorded fact must fail closed")
                .to_string();
            assert!(
                error.contains("whose recorded facts disagree"),
                "{name}: {error}"
            );
            assert_eq!(
                chain.cleanups(),
                vec![tc_b_key.clone()],
                "{name}: the contradicted deal must move no money"
            );
        }
    }

    /// A generated pool of recorded entries, with an index-derived identity per entry so every note,
    /// key and TokenContract is distinct.
    #[cfg(feature = "shellnet")]
    fn generated_entry(index: usize) -> (String, String, String) {
        let byte = format!("{:02x}", index as u8 + 1);
        (
            format!("0:{}", byte.repeat(32)),
            format!("{:02x}", index as u8 + 128).repeat(32),
            format!("0:{}", format!("{:02x}", index as u8 + 64).repeat(32)),
        )
    }

    /// What the generated entry's deal looks like on chain.
    #[cfg(feature = "shellnet")]
    #[derive(Clone, Debug)]
    enum GeneratedDeal {
        Reclaimable,
        Gone,
        Unfunded,
    }

    #[cfg(feature = "shellnet")]
    fn generated_plan_run(
        specs: &[(GeneratedDeal, u64, bool, bool)],
        rotation: usize,
    ) -> (Vec<String>, bool) {
        let dir = reclaim_test_dir("reclaim-proptest");
        let _cleanup = TempDirCleanup(dir.clone());
        let mut rows = Vec::new();
        let chain = PoolReclaimChain::default();
        let mut chain = chain;
        for (index, (deal, recorded_at, fail_once, duplicated)) in specs.iter().enumerate() {
            let (note, secret, tc) = generated_entry(index);
            rows.push(recorded_row(&note, &secret, &tc, *recorded_at));
            if *duplicated {
                rows.push(recorded_row(&note, &secret, &tc, *recorded_at));
            }
            let state = match deal {
                GeneratedDeal::Reclaimable => Some(never_opened_state()),
                GeneratedDeal::Gone => None,
                GeneratedDeal::Unfunded => Some(chain_state(false, false, false, false, 0)),
            };
            chain = chain.with_deal(&tc, &note, &secret, state, usize::from(*fail_once));
        }
        let rotate_by = rotation % rows.len().max(1);
        rows.rotate_right(rotate_by);
        let pool_path = write_reclaim_pool(&dir, serde_json::Value::Array(rows));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime");
        let first = runtime.block_on(run_pool_only_reclaim(&pool_path, &chain));
        // Restart twice more: neither may move any deal a second time.
        let second = runtime.block_on(run_pool_only_reclaim(&pool_path, &chain));
        let after_second = chain.cleanups();
        runtime
            .block_on(run_pool_only_reclaim(&pool_path, &chain))
            .expect("a settled pool is a decided no-op");
        assert_eq!(
            chain.cleanups(),
            after_second,
            "a settled pool must move nothing further"
        );
        assert!(
            second.is_ok(),
            "the retry after a transient submit failure must settle: {second:?}"
        );
        (chain.cleanups(), first.is_ok())
    }

    #[cfg(feature = "shellnet")]
    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(24))]

        /// invariant, over arbitrary pools: pool-only reclaim moves **each** recoverable deal
        /// exactly once and no other deal at all, keeps going past a failing entry, exits non-zero
        /// exactly when an entry failed, and never moves a deal again on a restart. Duplicate rows are
        /// one deal, and the whole outcome is independent of the row order in the file.
        /// Sizes start at two recorded deals on purpose: a pool holding exactly one recorded entry keeps
        /// its deliberately different pre- contract, where a deal this command cannot move stays a
        /// loud failure -- `single_recorded_entry_keeps_the_unchanged_loud_failure` owns that case.
        #[test]
        fn pool_only_reclaim_moves_each_recoverable_deal_exactly_once(
            specs in proptest::collection::vec(
                (
                    proptest::prop_oneof![
                        proptest::strategy::Just(GeneratedDeal::Reclaimable),
                        proptest::strategy::Just(GeneratedDeal::Gone),
                        proptest::strategy::Just(GeneratedDeal::Unfunded),
                    ],
                    0u64..4,
                    proptest::bool::ANY,
                    proptest::bool::ANY,
                ),
                2..5,
            ),
            rotation in 0usize..8,
        ) {
            let (cleanups, first_ok) = generated_plan_run(&specs, 0);
            let expected: std::collections::BTreeSet<String> = specs
                .iter()
                .enumerate()
                .filter(|(_, (deal, ..))| matches!(deal, GeneratedDeal::Reclaimable))
                .map(|(index, _)| {
                    let (_, _, tc) = generated_entry(index);
                    dexdo_core::Address::parse(&tc).unwrap().with_workchain()
                })
                .collect();
            let moved: std::collections::BTreeSet<String> = cleanups.iter().cloned().collect();
            proptest::prop_assert_eq!(&moved, &expected, "every recoverable deal moves, nothing else does");
            proptest::prop_assert_eq!(
                cleanups.len(),
                moved.len(),
                "no deal may be moved twice across restarts"
            );
            let failed_first = specs
                .iter()
                .any(|(deal, _, fail_once, _)| matches!(deal, GeneratedDeal::Reclaimable) && *fail_once);
            proptest::prop_assert_eq!(
                first_ok,
                !failed_first,
                "the first run exits non-zero exactly when an entry failed"
            );

            // The same pool in a rotated row order settles on exactly the same moves, in the same order.
            let (rotated, rotated_ok) = generated_plan_run(&specs, rotation);
            proptest::prop_assert_eq!(&rotated, &cleanups, "row order must not change what runs");
            proptest::prop_assert_eq!(rotated_ok, first_ok, "row order must not change the exit status");
        }
    }

    /// re-review item 1: a contradicted deal must refuse every deal it touches. Counting the
    /// note/TokenContract collisions only among the groups that survived contradiction removal let the
    /// contradiction quietly clear the way for its own sibling, which then moved money.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn a_contradicted_deal_also_refuses_the_deals_it_collides_with() {
        let (note_a, secret_a, tc_1) = generated_entry(0);
        let (note_b, secret_b, tc_2) = generated_entry(1);
        let (note_c, secret_c, tc_3) = generated_entry(2);
        let other_secret = "5d".repeat(32);
        let key = |tc: &str| dexdo_core::Address::parse(tc).unwrap().with_workchain();

        // Same note, two recorded deals, one of them internally contradicted.
        let dir = reclaim_test_dir("reclaim-contradiction-poisons-note");
        let _cleanup = TempDirCleanup(dir.clone());
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([
                recorded_row(&note_a, &secret_a, &tc_1, 100),
                recorded_row(&note_a, &other_secret, &tc_1, 100),
                recorded_row(&note_a, &secret_a, &tc_2, 110),
                recorded_row(&note_c, &secret_c, &tc_3, 120),
            ]),
        );
        let chain = PoolReclaimChain::default()
            .with_deal(&tc_1, &note_a, &secret_a, Some(never_opened_state()), 0)
            .with_deal(&tc_2, &note_a, &secret_a, Some(never_opened_state()), 0)
            .with_deal(&tc_3, &note_c, &secret_c, Some(never_opened_state()), 0);

        let error = run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect_err("a contradicted note must not reclaim its other deal either")
            .to_string();
        assert!(error.contains("refused as contradictory"), "{error}");
        assert_eq!(
            chain.cleanups(),
            vec![key(&tc_3)],
            "only the unrelated note's deal may move money"
        );

        // Mirror image: one TokenContract recorded by two notes, one of those records contradicted.
        let dir = reclaim_test_dir("reclaim-contradiction-poisons-tc");
        let _cleanup = TempDirCleanup(dir.clone());
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([
                recorded_row(&note_a, &secret_a, &tc_1, 100),
                recorded_row(&note_a, &other_secret, &tc_1, 100),
                recorded_row(&note_b, &secret_b, &tc_1, 110),
                recorded_row(&note_c, &secret_c, &tc_3, 120),
            ]),
        );
        let chain = PoolReclaimChain::default()
            .with_deal(&tc_1, &note_b, &secret_b, Some(never_opened_state()), 0)
            .with_deal(&tc_3, &note_c, &secret_c, Some(never_opened_state()), 0);

        let error = run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect_err("a contested TokenContract must not be reclaimed by the surviving claimant")
            .to_string();
        assert!(error.contains("refused as contradictory"), "{error}");
        assert_eq!(
            chain.cleanups(),
            vec![key(&tc_3)],
            "the contested TokenContract must move no money"
        );
    }

    /// re-review item 2: one deal recorded as both buyer and seller is a contradiction about that
    /// deal. The buyer-only pre-filter used to drop the seller row before anything could compare them.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn a_deal_recorded_as_both_buyer_and_seller_fails_closed() {
        let dir = reclaim_test_dir("reclaim-role-contradiction");
        let _cleanup = TempDirCleanup(dir.clone());
        let (note_a, secret_a, tc_1) = generated_entry(0);
        let (note_b, secret_b, tc_2) = generated_entry(1);
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([
                recorded_row_as(&note_a, &secret_a, &tc_1, 100, "buyer"),
                recorded_row_as(&note_a, &secret_a, &tc_1, 100, "seller"),
                recorded_row(&note_b, &secret_b, &tc_2, 110),
            ]),
        );
        let chain = PoolReclaimChain::default()
            .with_deal(&tc_1, &note_a, &secret_a, Some(never_opened_state()), 0)
            .with_deal(&tc_2, &note_b, &secret_b, Some(never_opened_state()), 0);

        let error = run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect_err("a same-deal role contradiction must fail closed")
            .to_string();
        assert!(error.contains("whose recorded facts disagree"), "{error}");
        assert_eq!(
            chain.cleanups(),
            vec![dexdo_core::Address::parse(&tc_2).unwrap().with_workchain()],
            "the contradicted deal must move no money"
        );
    }

    /// The other half of the same rule, and the shape of every real pool: a note that sold one deal and
    /// bought another is ordinary. Its seller record must neither join the buyer plan nor block it, and
    /// a seller record for the deal another note bought must not look like two claimants.
    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn unrelated_seller_records_stay_outside_the_buyer_plan() {
        let dir = reclaim_test_dir("reclaim-seller-records");
        let _cleanup = TempDirCleanup(dir.clone());
        let (note_a, secret_a, tc_1) = generated_entry(0);
        let (_, _, tc_2) = generated_entry(1);
        let (note_b, secret_b, tc_3) = generated_entry(2);
        let (note_c, secret_c, _) = generated_entry(3);
        let pool_path = write_reclaim_pool(
            &dir,
            serde_json::json!([
                // note A sold tc_1 and bought tc_2
                recorded_row_as(&note_a, &secret_a, &tc_1, 100, "seller"),
                recorded_row_as(&note_a, &secret_a, &tc_2, 110, "buyer"),
                // note B sold tc_3, which note C bought -- both sides of one deal in one pool
                recorded_row_as(&note_b, &secret_b, &tc_3, 120, "seller"),
                recorded_row_as(&note_c, &secret_c, &tc_3, 130, "buyer"),
            ]),
        );
        let chain = PoolReclaimChain::default()
            .with_deal(&tc_2, &note_a, &secret_a, Some(never_opened_state()), 0)
            .with_deal(&tc_3, &note_c, &secret_c, Some(never_opened_state()), 0);

        run_pool_only_reclaim(&pool_path, &chain)
            .await
            .expect("seller records are not contradictions");
        assert_eq!(
            chain.cleanups(),
            vec![
                dexdo_core::Address::parse(&tc_2).unwrap().with_workchain(),
                dexdo_core::Address::parse(&tc_3).unwrap().with_workchain(),
            ],
            "both bought deals are reclaimed, in recorded order"
        );
    }
}
