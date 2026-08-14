use super::args::SettlementReceiptArgs;
use anyhow::Result;

#[cfg(feature = "shellnet")]
use anyhow::Context;
#[cfg(feature = "shellnet")]
use dexdo_core::{
    Deployed, RealChainBackend, TokenContractCurrentFacts, TokenContractReceiptChainData,
    TokenContractSettlementEvent, TokenContractSettlementReceipt,
};
#[cfg(feature = "shellnet")]
use serde::Serialize;
#[cfg(feature = "shellnet")]
use serde_json::{json, Value};
#[cfg(feature = "shellnet")]
use std::collections::BTreeSet;
#[cfg(feature = "shellnet")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "shellnet")]
const RECEIPT_SCHEMA: &str = "dexdo.settlement-receipt.v1";
#[cfg(feature = "shellnet")]
const PROOF_LEVEL: &str = "chain_event_observed";
#[cfg(feature = "shellnet")]
const REWARDS_SCHEMA: &str = "dexdo.note-rewards.v1";
#[cfg(feature = "shellnet")]
const REWARDS_SOURCE: &str = "dexdo-points-rewards";
#[cfg(feature = "shellnet")]
const REWARDS_SEMANTICS: &str = "note_season_aggregate_not_per_deal";

#[cfg(feature = "shellnet")]
#[derive(Debug, Serialize)]
struct SettlementReceiptV1 {
    schema: &'static str,
    generated_at: u64,
    proof_level: &'static str,
    network: NetworkReceipt,
    token_contract: TokenContractIdentity,
    parties: PartiesReceipt,
    deal: DealReceipt,
    current: Option<CurrentReceipt>,
    terminal: TerminalReceipt,
    settlement_sequence: Vec<EventReceipt>,
    withdrawal: WithdrawalReceipt,
    rewards: RewardsJoinReceipt,
    consistency_issues: Vec<String>,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Serialize)]
struct NetworkReceipt {
    name: String,
    chain_endpoint: String,
    contracts_generation: Option<String>,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Serialize)]
struct TokenContractIdentity {
    address: String,
    account_status: &'static str,
    contract_version: Option<ContractVersionReceipt>,
    code_identity: CodeIdentityReceipt,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, Serialize)]
struct ContractVersionReceipt {
    version: String,
    contract: String,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Serialize)]
struct CodeIdentityReceipt {
    actual_code_hash: Option<String>,
    manifest_expected_code_hash: Option<String>,
    matches_manifest: Option<bool>,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Serialize)]
struct PartiesReceipt {
    buyer_note: PartyReceipt,
    seller_note: PartyReceipt,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Serialize)]
struct PartyReceipt {
    role: &'static str,
    address: Option<String>,
    source: Option<&'static str>,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Serialize)]
struct DealReceipt {
    terms: Option<DealTermsReceipt>,
    asset: AssetReceipt,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, Serialize)]
struct DealTermsReceipt {
    tick_size: String,
    price_per_tick: String,
    max_ticks: String,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Serialize)]
struct AssetReceipt {
    symbol: &'static str,
    ecc_id: u8,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Serialize)]
struct CurrentReceipt {
    state: CurrentStateReceipt,
    fees: CurrentFeesReceipt,
    seller: CurrentSellerReceipt,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, Serialize)]
struct CurrentStateReceipt {
    funded: bool,
    opened: bool,
    probe_accepted: bool,
    disputed: bool,
    deposit: String,
    prepaid: String,
    frozen: String,
    finalized_owed: String,
    prepaid_time: u64,
    last_advance: u64,
    dispute_time: u64,
    funded_time: u64,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, Serialize)]
struct CurrentFeesReceipt {
    fee_accrued: String,
    ticks_finalized: String,
    ever_disputed: bool,
    rebate_max_bps: u64,
    rebate_slope_bps: u64,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, Serialize)]
struct CurrentSellerReceipt {
    seller_pubkey: String,
    root_model_address: String,
    nonce: u64,
}

#[cfg(feature = "shellnet")]
#[derive(Debug)]
struct ParsedCurrent {
    receipt: CurrentReceipt,
    deal: DealTermsReceipt,
    buyer_note: Option<String>,
    seller_note: String,
    version: ContractVersionReceipt,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, Serialize)]
struct IndexerOrderReceipt {
    created_at: u64,
    cursor: String,
    message_id: String,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, Serialize)]
struct EventReceipt {
    kind: &'static str,
    payload: Value,
    message_id: String,
    created_at: u64,
    indexer_order: IndexerOrderReceipt,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Serialize)]
struct TerminalReceipt {
    status: &'static str,
    kind: Option<&'static str>,
    payload: Option<Value>,
    message_id: Option<String>,
    created_at: Option<u64>,
    indexer_order: Option<IndexerOrderReceipt>,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Serialize)]
struct WithdrawalReceipt {
    status: &'static str,
    events: Vec<EventReceipt>,
    observed_amount: String,
    finalized_owed: Option<String>,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Serialize)]
struct RewardsJoinReceipt {
    schema: &'static str,
    source: &'static str,
    requested_season: Option<u32>,
    semantics: &'static str,
    queries: Vec<RewardsQueryReceipt>,
}

#[cfg(feature = "shellnet")]
#[derive(Debug, Serialize)]
struct RewardsQueryReceipt {
    role: &'static str,
    participant_note: Option<String>,
    query_path: Option<String>,
}

#[cfg(feature = "shellnet")]
struct ReceiptContext {
    generated_at: u64,
    network: String,
    chain_endpoint: String,
    contracts_generation: Option<String>,
    expected_code_hash: Option<String>,
    token_contract: String,
    season: Option<u32>,
}

#[cfg(feature = "shellnet")]
fn normalized_code_hash(value: &str) -> Option<String> {
    let value = value
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    (!value.is_empty()).then(|| value.to_ascii_lowercase())
}

#[cfg(feature = "shellnet")]
fn decimal_u128(value: &Value, field: &str) -> Option<String> {
    let raw = value.get(field)?;
    let parsed = match raw {
        Value::String(value) => value.parse::<u128>().ok()?,
        Value::Number(value) => value.to_string().parse::<u128>().ok()?,
        _ => return None,
    };
    Some(parsed.to_string())
}

#[cfg(feature = "shellnet")]
fn integer_u64(value: &Value, field: &str) -> Option<u64> {
    let raw = value.get(field)?;
    match raw {
        Value::String(value) => value.parse().ok(),
        Value::Number(value) => value.as_u64(),
        _ => None,
    }
}

#[cfg(feature = "shellnet")]
fn boolean(value: &Value, field: &str) -> Option<bool> {
    value.get(field)?.as_bool()
}

#[cfg(feature = "shellnet")]
fn string(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)?
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(feature = "shellnet")]
fn normalized_address(value: &str) -> Option<String> {
    dexdo_core::Address::parse(value)
        .ok()
        .map(|address| address.with_workchain())
}

#[cfg(feature = "shellnet")]
fn optional_nonzero_address(value: &Value, field: &str) -> Option<Option<String>> {
    let raw = value.get(field)?.as_str()?.trim();
    if raw.is_empty() {
        return Some(None);
    }
    let address = normalized_address(raw)?;
    let bare = address
        .split_once(':')
        .map(|(_, bare)| bare)
        .unwrap_or(address.as_str());
    Some((!bare.chars().all(|character| character == '0')).then_some(address))
}

#[cfg(feature = "shellnet")]
fn parse_current(current: &TokenContractCurrentFacts) -> Option<ParsedCurrent> {
    let state = CurrentStateReceipt {
        funded: boolean(&current.state, "funded")?,
        opened: boolean(&current.state, "opened")?,
        probe_accepted: boolean(&current.state, "probeAccepted")?,
        disputed: boolean(&current.state, "disputed")?,
        deposit: decimal_u128(&current.state, "deposit")?,
        prepaid: decimal_u128(&current.state, "prepaid")?,
        frozen: decimal_u128(&current.state, "frozen")?,
        finalized_owed: decimal_u128(&current.state, "finalizedOwed")?,
        prepaid_time: integer_u64(&current.state, "prepaidTime")?,
        last_advance: integer_u64(&current.state, "lastAdvance")?,
        dispute_time: integer_u64(&current.state, "disputeTime")?,
        funded_time: integer_u64(&current.state, "fundedTime")?,
    };
    let fees = CurrentFeesReceipt {
        fee_accrued: decimal_u128(&current.fees, "feeAccrued")?,
        ticks_finalized: decimal_u128(&current.fees, "ticksFinalized")?,
        ever_disputed: boolean(&current.fees, "everDisputed")?,
        rebate_max_bps: integer_u64(&current.fees, "rebateMaxBps")?,
        rebate_slope_bps: integer_u64(&current.fees, "rebateSlopeBps")?,
    };
    let deal = DealTermsReceipt {
        tick_size: decimal_u128(&current.deal, "tickSize")?,
        price_per_tick: decimal_u128(&current.deal, "pricePerTick")?,
        max_ticks: decimal_u128(&current.deal, "maxTicks")?,
    };
    let buyer_note = optional_nonzero_address(&current.parties, "buyer")?;
    let seller_note = normalized_address(current.parties.get("sellerNote")?.as_str()?)?;
    let seller = CurrentSellerReceipt {
        seller_pubkey: string(&current.seller, "sellerPubkey")
            .or_else(|| string(&current.seller, "value0"))?,
        root_model_address: normalized_address(current.seller.get("rootModelAddress")?.as_str()?)?,
        nonce: integer_u64(&current.seller, "nonce")?,
    };
    let version = ContractVersionReceipt {
        version: string(&current.version, "value0")?,
        contract: string(&current.version, "value1")?,
    };
    Some(ParsedCurrent {
        receipt: CurrentReceipt {
            state,
            fees,
            seller,
        },
        deal,
        buyer_note,
        seller_note,
        version,
    })
}

#[cfg(feature = "shellnet")]
fn event_kind_payload(event: &TokenContractSettlementEvent) -> (&'static str, Value) {
    match event {
        TokenContractSettlementEvent::ContractDeployed { token_contract } => {
            ("ContractDeployed", json!({"self": token_contract}))
        }
        TokenContractSettlementEvent::StreamFunded { buyer, deposit } => (
            "StreamFunded",
            json!({"buyer": buyer, "deposit": deposit.to_string()}),
        ),
        TokenContractSettlementEvent::SellerBondFunded { amount } => {
            ("SellerBondFunded", json!({"amount": amount.to_string()}))
        }
        TokenContractSettlementEvent::StreamOpened {
            buyer,
            price_per_tick,
        } => (
            "StreamOpened",
            json!({"buyer": buyer, "pricePerTick": price_per_tick.to_string()}),
        ),
        TokenContractSettlementEvent::ProbeAccepted {
            buyer,
            to_seller,
            bond_returned,
        } => (
            "ProbeAccepted",
            json!({
                "buyer": buyer,
                "toSeller": to_seller.to_string(),
                "bondReturned": bond_returned.to_string(),
            }),
        ),
        TokenContractSettlementEvent::ProbeBurned {
            buyer,
            burned_probe,
            burned_bond,
            refund_to_buyer,
        } => (
            "ProbeBurned",
            json!({
                "buyer": buyer,
                "burnedProbe": burned_probe.to_string(),
                "burnedBond": burned_bond.to_string(),
                "refundToBuyer": refund_to_buyer.to_string(),
            }),
        ),
        TokenContractSettlementEvent::TickFinalized {
            finalized_owed,
            deposit,
        } => (
            "TickFinalized",
            json!({
                "finalizedOwed": finalized_owed.to_string(),
                "deposit": deposit.to_string(),
            }),
        ),
        TokenContractSettlementEvent::TicksClaimed { trusted, claimed } => (
            "TicksClaimed",
            json!({
                "trusted": trusted.to_string(),
                "claimed": claimed.to_string(),
            }),
        ),
        TokenContractSettlementEvent::StreamStopped {
            buyer,
            to_seller,
            refund_to_buyer,
        } => (
            "StreamStopped",
            json!({
                "buyer": buyer,
                "toSeller": to_seller.to_string(),
                "refundToBuyer": refund_to_buyer.to_string(),
            }),
        ),
        TokenContractSettlementEvent::StreamDisputed { buyer, at } => {
            ("StreamDisputed", json!({"buyer": buyer, "at": at}))
        }
        TokenContractSettlementEvent::DisputeResolved {
            to_seller,
            refund_to_buyer,
            released,
        } => (
            "DisputeResolved",
            json!({
                "toSeller": to_seller.to_string(),
                "refundToBuyer": refund_to_buyer.to_string(),
                "released": released,
            }),
        ),
        TokenContractSettlementEvent::StreamReclaimed {
            buyer,
            refund_to_buyer,
        } => (
            "StreamReclaimed",
            json!({
                "buyer": buyer,
                "refundToBuyer": refund_to_buyer.to_string(),
            }),
        ),
        TokenContractSettlementEvent::ShellWithdrawn { recipient, amount } => (
            "ShellWithdrawn",
            json!({"recipient": recipient, "amount": amount.to_string()}),
        ),
        TokenContractSettlementEvent::ContractDestroyed { token_contract } => {
            ("ContractDestroyed", json!({"self": token_contract}))
        }
    }
}

#[cfg(feature = "shellnet")]
fn rendered_event(receipt: &TokenContractSettlementReceipt) -> EventReceipt {
    let (kind, payload) = event_kind_payload(&receipt.event);
    let indexer_order = IndexerOrderReceipt {
        created_at: receipt.created_at,
        cursor: receipt.cursor.clone(),
        message_id: receipt.message_id.clone(),
    };
    EventReceipt {
        kind,
        payload,
        message_id: receipt.message_id.clone(),
        created_at: receipt.created_at,
        indexer_order,
    }
}

#[cfg(feature = "shellnet")]
fn is_terminal(event: &TokenContractSettlementEvent) -> bool {
    matches!(
        event,
        TokenContractSettlementEvent::ProbeBurned { .. }
            | TokenContractSettlementEvent::StreamStopped { .. }
            | TokenContractSettlementEvent::DisputeResolved { .. }
            | TokenContractSettlementEvent::StreamReclaimed { .. }
    )
}

#[cfg(feature = "shellnet")]
fn event_buyer(event: &TokenContractSettlementEvent) -> Option<&str> {
    match event {
        TokenContractSettlementEvent::StreamFunded { buyer, .. }
        | TokenContractSettlementEvent::StreamOpened { buyer, .. }
        | TokenContractSettlementEvent::ProbeAccepted { buyer, .. }
        | TokenContractSettlementEvent::ProbeBurned { buyer, .. }
        | TokenContractSettlementEvent::StreamStopped { buyer, .. }
        | TokenContractSettlementEvent::StreamDisputed { buyer, .. }
        | TokenContractSettlementEvent::StreamReclaimed { buyer, .. } => Some(buyer),
        _ => None,
    }
}

#[cfg(feature = "shellnet")]
fn event_contract(event: &TokenContractSettlementEvent) -> Option<&str> {
    match event {
        TokenContractSettlementEvent::ContractDeployed { token_contract }
        | TokenContractSettlementEvent::ContractDestroyed { token_contract } => {
            Some(token_contract)
        }
        _ => None,
    }
}

#[cfg(feature = "shellnet")]
fn rewards_query(
    role: &'static str,
    participant_note: Option<String>,
    season: Option<u32>,
) -> RewardsQueryReceipt {
    let query_path = participant_note.as_ref().map(|note| match season {
        Some(season) => format!("/v1/notes/{note}?season={season}"),
        None => format!("/v1/notes/{note}"),
    });
    RewardsQueryReceipt {
        role,
        participant_note,
        query_path,
    }
}

#[cfg(feature = "shellnet")]
fn unavailable_receipt(context: ReceiptContext) -> SettlementReceiptV1 {
    let buyer_note = PartyReceipt {
        role: "buyer",
        address: None,
        source: None,
    };
    let seller_note = PartyReceipt {
        role: "seller",
        address: None,
        source: None,
    };
    SettlementReceiptV1 {
        schema: RECEIPT_SCHEMA,
        generated_at: context.generated_at,
        proof_level: PROOF_LEVEL,
        network: NetworkReceipt {
            name: context.network,
            chain_endpoint: context.chain_endpoint,
            contracts_generation: context.contracts_generation,
        },
        token_contract: TokenContractIdentity {
            address: context.token_contract,
            account_status: "unavailable",
            contract_version: None,
            code_identity: CodeIdentityReceipt {
                actual_code_hash: None,
                manifest_expected_code_hash: context.expected_code_hash,
                matches_manifest: None,
            },
        },
        parties: PartiesReceipt {
            buyer_note,
            seller_note,
        },
        deal: DealReceipt {
            terms: None,
            asset: AssetReceipt {
                symbol: "SHELL",
                ecc_id: 2,
            },
        },
        current: None,
        terminal: TerminalReceipt {
            status: "unavailable",
            kind: None,
            payload: None,
            message_id: None,
            created_at: None,
            indexer_order: None,
        },
        settlement_sequence: Vec::new(),
        withdrawal: WithdrawalReceipt {
            status: "not_applicable",
            events: Vec::new(),
            observed_amount: "0".to_string(),
            finalized_owed: None,
        },
        rewards: RewardsJoinReceipt {
            schema: REWARDS_SCHEMA,
            source: REWARDS_SOURCE,
            requested_season: context.season,
            semantics: REWARDS_SEMANTICS,
            queries: vec![
                rewards_query("buyer", None, context.season),
                rewards_query("seller", None, context.season),
            ],
        },
        consistency_issues: vec!["chain_read_unavailable".to_string()],
    }
}

#[cfg(feature = "shellnet")]
fn reader_error_is_unavailable(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<reqwest::Error>().is_some_and(|error| {
            error.is_connect()
                || error.is_timeout()
                || error.is_body()
                || error.status().is_some_and(|status| {
                    status == reqwest::StatusCode::NOT_FOUND || status.is_server_error()
                })
        })
    })
}

#[cfg(feature = "shellnet")]
fn receipt_from_chain_result(
    context: ReceiptContext,
    result: Result<TokenContractReceiptChainData>,
) -> Result<SettlementReceiptV1> {
    match result {
        Ok(chain) => Ok(build_receipt(context, &chain)),
        Err(error) if reader_error_is_unavailable(&error) => Ok(unavailable_receipt(context)),
        Err(error) => Err(error.context("read TokenContract settlement receipt")),
    }
}

#[cfg(feature = "shellnet")]
fn build_receipt(
    context: ReceiptContext,
    chain: &TokenContractReceiptChainData,
) -> SettlementReceiptV1 {
    let mut issues = Vec::<String>::new();
    if chain.account_id != context.token_contract {
        issues.push("reader_account_mismatch".to_string());
    }

    let expected_code_hash = context.expected_code_hash;
    let actual_code_hash = chain.code_hash.as_deref().and_then(normalized_code_hash);
    let matches_manifest = match (actual_code_hash.as_ref(), expected_code_hash.as_ref()) {
        (Some(actual), Some(expected)) => {
            let matches = actual == expected;
            if !matches {
                issues.push("token_contract_code_hash_mismatch".to_string());
            }
            Some(matches)
        }
        _ => None,
    };
    if expected_code_hash.is_none() {
        issues.push("manifest_token_contract_code_hash_missing".to_string());
    }
    if chain.account_active && actual_code_hash.is_none() {
        issues.push("active_token_contract_code_hash_missing".to_string());
    }

    let parsed_current = match (&chain.current, chain.account_active) {
        (Some(current), true) => match parse_current(current) {
            Some(parsed) => Some(parsed),
            None => {
                issues.push("current_getter_shape_invalid".to_string());
                None
            }
        },
        (None, true) => {
            issues.push("active_token_contract_getters_missing".to_string());
            None
        }
        (Some(_), false) => {
            issues.push("inactive_token_contract_has_current_getters".to_string());
            None
        }
        (None, false) => None,
    };
    if parsed_current
        .as_ref()
        .is_some_and(|current| current.version.contract != "TokenContract")
    {
        issues.push("get_version_contract_identity_mismatch".to_string());
    }
    if parsed_current.as_ref().is_some_and(|current| {
        current.deal.tick_size
            != u128::from(dexdo_core::DobParams::canonical().tick_size).to_string()
    }) {
        issues.push("deal_tick_size_mismatch".to_string());
    }

    let events = &chain.receipts.events;
    if !events
        .windows(2)
        .all(|pair| (pair[0].created_at, &pair[0].cursor) <= (pair[1].created_at, &pair[1].cursor))
    {
        issues.push("settlement_sequence_not_ordered".to_string());
    }
    let mut message_ids = BTreeSet::new();
    if events
        .iter()
        .any(|event| !message_ids.insert(event.message_id.as_str()))
    {
        issues.push("duplicate_event_message_id".to_string());
    }

    let mut observed_buyers = BTreeSet::new();
    for event in events {
        if let Some(buyer) = event_buyer(&event.event) {
            match normalized_address(buyer) {
                Some(buyer) => {
                    observed_buyers.insert(buyer);
                }
                None => issues.push("event_buyer_address_invalid".to_string()),
            }
        }
        if let Some(token_contract) = event_contract(&event.event) {
            if normalized_address(token_contract).as_deref()
                != Some(context.token_contract.as_str())
            {
                issues.push("event_token_contract_mismatch".to_string());
            }
        }
    }
    if observed_buyers.len() > 1 {
        issues.push("event_buyer_party_mismatch".to_string());
    }
    let observed_buyer = observed_buyers.first().cloned();
    if let (Some(current), Some(observed)) = (&parsed_current, &observed_buyer) {
        match current.buyer_note.as_ref() {
            Some(current_buyer) if current_buyer != observed => {
                issues.push("event_getter_buyer_mismatch".to_string())
            }
            None => issues.push("current_buyer_missing_for_observed_lifecycle".to_string()),
            _ => {}
        }
    }

    let terminal_events = events
        .iter()
        .filter(|event| is_terminal(&event.event))
        .collect::<Vec<_>>();
    if terminal_events.len() > 1 {
        issues.push("multiple_terminal_events".to_string());
    }
    let destroyed = events
        .iter()
        .enumerate()
        .filter(|(_, event)| {
            matches!(
                event.event,
                TokenContractSettlementEvent::ContractDestroyed { .. }
            )
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if destroyed.len() > 1 {
        issues.push("multiple_contract_destroyed_events".to_string());
    }
    if destroyed
        .first()
        .is_some_and(|index| *index + 1 != events.len())
    {
        issues.push("event_after_contract_destroyed".to_string());
    }
    if chain.account_active && !destroyed.is_empty() {
        issues.push("destroyed_event_with_active_account".to_string());
    }

    if let (Some(terminal), Some(current)) = (terminal_events.first(), &parsed_current) {
        let state = &current.receipt.state;
        if state.opened
            || state.disputed
            || state.deposit != "0"
            || state.prepaid != "0"
            || state.frozen != "0"
        {
            issues.push("terminal_event_current_state_mismatch".to_string());
        }
        match terminal.event {
            TokenContractSettlementEvent::ProbeBurned { .. } if state.probe_accepted => {
                issues.push("probe_burned_getter_probe_accepted".to_string())
            }
            TokenContractSettlementEvent::StreamStopped { .. } if !state.probe_accepted => {
                issues.push("stream_stopped_getter_probe_not_accepted".to_string())
            }
            _ => {}
        }
    }

    let withdrawal_receipts = events
        .iter()
        .filter(|event| {
            matches!(
                event.event,
                TokenContractSettlementEvent::ShellWithdrawn { .. }
            )
        })
        .collect::<Vec<_>>();
    let mut observed_amount = 0u128;
    for event in &withdrawal_receipts {
        let TokenContractSettlementEvent::ShellWithdrawn { amount, .. } = event.event else {
            unreachable!("filtered ShellWithdrawn")
        };
        if amount == 0 {
            issues.push("zero_shell_withdrawal".to_string());
        }
        match observed_amount.checked_add(amount) {
            Some(total) => observed_amount = total,
            None => issues.push("shell_withdrawal_total_overflow".to_string()),
        }
    }

    issues.sort();
    issues.dedup();
    let has_chain_evidence = chain.account_active || !events.is_empty();
    let terminal_status = if !issues.is_empty() {
        "inconsistent"
    } else if terminal_events.len() == 1 {
        "terminal"
    } else if has_chain_evidence {
        "not_final"
    } else {
        "unavailable"
    };
    let terminal = terminal_events.first().map(|event| rendered_event(event));
    let terminal_receipt = TerminalReceipt {
        status: terminal_status,
        kind: terminal.as_ref().map(|event| event.kind),
        payload: terminal.as_ref().map(|event| event.payload.clone()),
        message_id: terminal.as_ref().map(|event| event.message_id.clone()),
        created_at: terminal.as_ref().map(|event| event.created_at),
        indexer_order: terminal.as_ref().map(|event| event.indexer_order.clone()),
    };

    let withdrawal_status = if !issues.is_empty() {
        "inconsistent"
    } else if !withdrawal_receipts.is_empty() {
        "observed"
    } else if terminal_status == "terminal" {
        "not_observed"
    } else {
        "not_applicable"
    };
    let finalized_owed = parsed_current
        .as_ref()
        .map(|current| current.receipt.state.finalized_owed.clone());
    let buyer_address = parsed_current
        .as_ref()
        .and_then(|current| current.buyer_note.clone())
        .or(observed_buyer);
    let buyer_source = if parsed_current
        .as_ref()
        .and_then(|current| current.buyer_note.as_ref())
        .is_some()
    {
        Some("current_getter")
    } else if buyer_address.is_some() {
        Some("chain_event")
    } else {
        None
    };
    let seller_address = parsed_current
        .as_ref()
        .map(|current| current.seller_note.clone());
    let seller_source = seller_address.as_ref().map(|_| "current_getter");

    SettlementReceiptV1 {
        schema: RECEIPT_SCHEMA,
        generated_at: context.generated_at,
        proof_level: PROOF_LEVEL,
        network: NetworkReceipt {
            name: context.network,
            chain_endpoint: context.chain_endpoint,
            contracts_generation: context.contracts_generation,
        },
        token_contract: TokenContractIdentity {
            address: context.token_contract,
            account_status: if chain.account_active {
                "active"
            } else {
                "inactive"
            },
            contract_version: parsed_current
                .as_ref()
                .map(|current| current.version.clone()),
            code_identity: CodeIdentityReceipt {
                actual_code_hash,
                manifest_expected_code_hash: expected_code_hash,
                matches_manifest,
            },
        },
        parties: PartiesReceipt {
            buyer_note: PartyReceipt {
                role: "buyer",
                address: buyer_address.clone(),
                source: buyer_source,
            },
            seller_note: PartyReceipt {
                role: "seller",
                address: seller_address.clone(),
                source: seller_source,
            },
        },
        deal: DealReceipt {
            terms: parsed_current.as_ref().map(|current| current.deal.clone()),
            asset: AssetReceipt {
                symbol: "SHELL",
                ecc_id: 2,
            },
        },
        current: parsed_current.map(|current| current.receipt),
        terminal: terminal_receipt,
        settlement_sequence: events.iter().map(rendered_event).collect(),
        withdrawal: WithdrawalReceipt {
            status: withdrawal_status,
            events: withdrawal_receipts
                .into_iter()
                .map(rendered_event)
                .collect(),
            observed_amount: observed_amount.to_string(),
            finalized_owed,
        },
        rewards: RewardsJoinReceipt {
            schema: REWARDS_SCHEMA,
            source: REWARDS_SOURCE,
            requested_season: context.season,
            semantics: REWARDS_SEMANTICS,
            queries: vec![
                rewards_query("buyer", buyer_address, context.season),
                rewards_query("seller", seller_address, context.season),
            ],
        },
        consistency_issues: issues,
    }
}

#[cfg(feature = "shellnet")]
pub(crate) async fn run_settlement_receipt(args: SettlementReceiptArgs) -> Result<()> {
    debug_assert!(args.json, "--json is required by clap");
    let token_contract = dexdo_core::Address::parse(&args.token_contract)
        .map_err(|error| anyhow::anyhow!("TOKEN_CONTRACT {}: {error}", args.token_contract))?;
    let token_contract_text = token_contract.with_workchain();
    let deployed = Deployed::load(&args.contracts)
        .with_context(|| format!("load {}", args.contracts.display()))?;
    let endpoint = dexdo_core::resolve_endpoint(None, &deployed)?;
    let expected_code_hash = deployed
        .contract_hashes
        .get("TokenContract")
        .and_then(|value| normalized_code_hash(value));
    let backend = RealChainBackend::connect(&args.contracts)?;
    let generated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();
    let context = ReceiptContext {
        generated_at,
        network: deployed.network,
        chain_endpoint: endpoint,
        contracts_generation: deployed.version,
        expected_code_hash,
        token_contract: token_contract_text,
        season: args.season,
    };
    let receipt = receipt_from_chain_result(
        context,
        backend
            .token_contract_receipt_chain_data(&token_contract)
            .await,
    )?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_settlement_receipt(_args: SettlementReceiptArgs) -> Result<()> {
    anyhow::bail!("settlement-receipt unavailable: build with `--features shellnet`")
}

#[cfg(all(test, feature = "shellnet"))]
mod tests {
    use super::*;
    use dexdo_core::{TokenContractSettlementEvent::*, TokenContractSettlementReceipts};

    fn address(character: char) -> String {
        format!("0:{}", character.to_string().repeat(64))
    }

    fn context(token_contract: &str) -> ReceiptContext {
        ReceiptContext {
            generated_at: 1_700_000_000,
            network: "shellnet".to_string(),
            chain_endpoint: "https://shellnet.example".to_string(),
            contracts_generation: Some("4.0.29".to_string()),
            expected_code_hash: Some("ab".repeat(32)),
            token_contract: token_contract.to_string(),
            season: Some(7),
        }
    }

    #[tokio::test]
    async fn settlement_receipt_command_classifies_not_found_but_propagates_integrity_errors() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let token_contract = address('a');
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind 404 fixture");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept 404 request");
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await.expect("read 404 request");
            socket
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write 404 response");
        });
        let not_found = reqwest::Client::new()
            .get(endpoint)
            .send()
            .await
            .expect("receive 404 response")
            .error_for_status()
            .expect_err("404 must be an error");
        server.await.expect("404 fixture task");
        let unavailable =
            receipt_from_chain_result(context(&token_contract), Err(not_found.into()))
                .expect("not-found reader result remains unavailable");
        assert_eq!(unavailable.terminal.status, "unavailable");

        let error = receipt_from_chain_result(
            context(&token_contract),
            Err(anyhow::anyhow!(
                "malformed known TokenContract event payload"
            )),
        )
        .expect_err("integrity/decode errors must fail closed");
        let message = format!("{error:#}");
        assert!(
            message.contains("read TokenContract settlement receipt"),
            "{message}"
        );
        assert!(message.contains("malformed known"), "{message}");
    }

    fn current_facts(
        buyer: Option<&str>,
        seller: &str,
        opened: bool,
        probe_accepted: bool,
        disputed: bool,
        finalized_owed: u128,
    ) -> TokenContractCurrentFacts {
        TokenContractCurrentFacts {
            state: json!({
                "funded": buyer.is_some(),
                "opened": opened,
                "probeAccepted": probe_accepted,
                "disputed": disputed,
                "deposit": if opened { "25" } else { "0" },
                "prepaid": if opened { "10" } else { "0" },
                "frozen": if opened { "10" } else { "0" },
                "finalizedOwed": finalized_owed.to_string(),
                "prepaidTime": "100",
                "lastAdvance": "101",
                "disputeTime": "0",
                "fundedTime": "90",
            }),
            fees: json!({
                "feeAccrued": "0",
                "ticksFinalized": if probe_accepted { "3" } else { "0" },
                "everDisputed": disputed,
                "rebateMaxBps": "5000",
                "rebateSlopeBps": "100",
            }),
            deal: json!({
                "tickSize": "1000000",
                "pricePerTick": "10",
                "maxTicks": "1024",
            }),
            parties: json!({
                "buyer": buyer.unwrap_or(""),
                "sellerNote": seller,
            }),
            seller: json!({
                "sellerPubkey": "0x1234",
                "rootModelAddress": address('d'),
                "nonce": "42",
            }),
            version: json!({
                "value0": "4.0.29",
                "value1": "TokenContract",
            }),
        }
    }

    fn event(
        message_id: &str,
        created_at: u64,
        event: TokenContractSettlementEvent,
    ) -> TokenContractSettlementReceipt {
        TokenContractSettlementReceipt {
            message_id: message_id.to_string(),
            created_at,
            cursor: format!("{created_at:04}-{message_id}"),
            event,
        }
    }

    fn chain(
        token_contract: &str,
        current: Option<TokenContractCurrentFacts>,
        events: Vec<TokenContractSettlementReceipt>,
    ) -> TokenContractReceiptChainData {
        TokenContractReceiptChainData {
            account_id: token_contract.to_string(),
            account_active: current.is_some(),
            code_hash: current.as_ref().map(|_| "ab".repeat(32)),
            current,
            receipts: TokenContractSettlementReceipts { events },
        }
    }

    fn as_value(receipt: &SettlementReceiptV1) -> Value {
        serde_json::to_value(receipt).expect("serialize receipt")
    }

    #[test]
    fn unopened_and_open_deals_without_terminal_event_are_not_final() {
        let token_contract = address('a');
        let seller = address('b');
        let buyer = address('c');

        let unopened = build_receipt(
            context(&token_contract),
            &chain(
                &token_contract,
                Some(current_facts(None, &seller, false, false, false, 0)),
                vec![event(
                    "deployed",
                    1,
                    ContractDeployed {
                        token_contract: token_contract.clone(),
                    },
                )],
            ),
        );
        assert_eq!(unopened.terminal.status, "not_final");
        assert_eq!(unopened.withdrawal.status, "not_applicable");

        let opened = build_receipt(
            context(&token_contract),
            &chain(
                &token_contract,
                Some(current_facts(Some(&buyer), &seller, true, false, false, 0)),
                vec![
                    event(
                        "funded",
                        1,
                        StreamFunded {
                            buyer: buyer.clone(),
                            deposit: 45,
                        },
                    ),
                    event(
                        "opened",
                        2,
                        StreamOpened {
                            buyer,
                            price_per_tick: 10,
                        },
                    ),
                ],
            ),
        );
        assert_eq!(opened.terminal.status, "not_final");
        assert!(opened.consistency_issues.is_empty());
    }

    #[test]
    fn every_terminal_kind_is_machine_visible_with_exact_payload() {
        let token_contract = address('a');
        let seller = address('b');
        let buyer = address('c');
        let cases = [
            (
                ProbeBurned {
                    buyer: buyer.clone(),
                    burned_probe: 1,
                    burned_bond: 2,
                    refund_to_buyer: 3,
                },
                "ProbeBurned",
                json!({
                    "buyer": buyer,
                    "burnedProbe": "1",
                    "burnedBond": "2",
                    "refundToBuyer": "3",
                }),
                false,
            ),
            (
                StreamStopped {
                    buyer: buyer.clone(),
                    to_seller: 4,
                    refund_to_buyer: 5,
                },
                "StreamStopped",
                json!({"buyer": buyer, "toSeller": "4", "refundToBuyer": "5"}),
                true,
            ),
            (
                DisputeResolved {
                    to_seller: 6,
                    refund_to_buyer: 7,
                    released: true,
                },
                "DisputeResolved",
                json!({"toSeller": "6", "refundToBuyer": "7", "released": true}),
                true,
            ),
            (
                StreamReclaimed {
                    buyer: buyer.clone(),
                    refund_to_buyer: 8,
                },
                "StreamReclaimed",
                json!({"buyer": buyer, "refundToBuyer": "8"}),
                true,
            ),
        ];

        for (terminal, kind, payload, probe_accepted) in cases {
            let receipt = build_receipt(
                context(&token_contract),
                &chain(
                    &token_contract,
                    Some(current_facts(
                        Some(&buyer),
                        &seller,
                        false,
                        probe_accepted,
                        false,
                        9,
                    )),
                    vec![event("terminal", 1, terminal)],
                ),
            );
            assert_eq!(receipt.terminal.status, "terminal", "{kind}");
            assert_eq!(receipt.terminal.kind, Some(kind), "{kind}");
            assert_eq!(receipt.terminal.payload, Some(payload), "{kind}");
            assert_eq!(
                receipt
                    .terminal
                    .indexer_order
                    .as_ref()
                    .map(|order| order.cursor.as_str()),
                Some("0001-terminal")
            );
        }
    }

    #[test]
    fn withdrawal_distinguishes_not_observed_observed_and_partial() {
        let token_contract = address('a');
        let seller = address('b');
        let buyer = address('c');
        let stopped = event(
            "stopped",
            1,
            StreamStopped {
                buyer: buyer.clone(),
                to_seller: 10,
                refund_to_buyer: 0,
            },
        );
        let current = current_facts(Some(&buyer), &seller, false, true, false, 7);
        let not_observed = build_receipt(
            context(&token_contract),
            &chain(
                &token_contract,
                Some(current.clone()),
                vec![stopped.clone()],
            ),
        );
        assert_eq!(not_observed.withdrawal.status, "not_observed");
        assert_eq!(not_observed.withdrawal.observed_amount, "0");
        let pre_withdrawal = as_value(&not_observed);
        assert_eq!(pre_withdrawal["parties"]["buyer_note"]["address"], buyer);
        assert_eq!(pre_withdrawal["parties"]["seller_note"]["address"], seller);
        assert!(pre_withdrawal["deal"]["terms"].is_object());
        let pre_buyer_rewards_path = pre_withdrawal["rewards"]["queries"][0]["query_path"]
            .as_str()
            .expect("pre-withdraw buyer rewards path")
            .to_string();
        let pre_seller_rewards_path = pre_withdrawal["rewards"]["queries"][1]["query_path"]
            .as_str()
            .expect("pre-withdraw seller rewards path")
            .to_string();

        let observed = build_receipt(
            context(&token_contract),
            &chain(
                &token_contract,
                Some(current),
                vec![
                    stopped.clone(),
                    event(
                        "withdrawn",
                        2,
                        ShellWithdrawn {
                            recipient: seller.clone(),
                            amount: 3,
                        },
                    ),
                ],
            ),
        );
        assert_eq!(observed.withdrawal.status, "observed");
        assert_eq!(observed.withdrawal.observed_amount, "3");
        assert_eq!(observed.withdrawal.finalized_owed.as_deref(), Some("7"));
        assert_eq!(observed.withdrawal.events.len(), 1);
        assert!(
            as_value(&observed)["withdrawal"].get("complete").is_none(),
            "an observed partial withdrawal must not be named complete"
        );

        let post_destroy = build_receipt(
            context(&token_contract),
            &chain(
                &token_contract,
                None,
                vec![
                    stopped,
                    event(
                        "withdrawn",
                        2,
                        ShellWithdrawn {
                            recipient: seller,
                            amount: 3,
                        },
                    ),
                    event(
                        "destroyed",
                        3,
                        ContractDestroyed {
                            token_contract: token_contract.clone(),
                        },
                    ),
                ],
            ),
        );
        let post_destroy = as_value(&post_destroy);
        assert_eq!(post_destroy["terminal"]["status"], "terminal");
        assert_eq!(post_destroy["terminal"]["message_id"], "stopped");
        assert_eq!(post_destroy["withdrawal"]["status"], "observed");
        assert_eq!(post_destroy["withdrawal"]["observed_amount"], "3");
        assert!(post_destroy["current"].is_null());
        assert!(post_destroy["deal"]["terms"].is_null());
        assert!(post_destroy["parties"]["seller_note"]["address"].is_null());
        assert!(post_destroy["parties"]["seller_note"]["source"].is_null());
        assert!(post_destroy["rewards"]["queries"][1]["participant_note"].is_null());
        assert!(post_destroy["rewards"]["queries"][1]["query_path"].is_null());
        assert_eq!(
            post_destroy["rewards"]["queries"][0]["query_path"],
            pre_buyer_rewards_path
        );
        assert!(
            pre_seller_rewards_path.contains(&address('b')),
            "the retained pre-withdraw receipt supplies the seller rewards path"
        );
    }

    #[test]
    fn contract_destroyed_without_terminal_event_is_not_settlement() {
        let token_contract = address('a');
        let receipt = build_receipt(
            context(&token_contract),
            &chain(
                &token_contract,
                None,
                vec![event(
                    "destroyed",
                    1,
                    ContractDestroyed {
                        token_contract: token_contract.clone(),
                    },
                )],
            ),
        );
        assert_eq!(receipt.terminal.status, "not_final");
        assert_eq!(receipt.terminal.kind, None);
        assert_eq!(receipt.withdrawal.status, "not_applicable");
        assert!(receipt.current.is_none());
    }

    #[test]
    fn wrong_tc_and_event_getter_contradiction_are_inconsistent() {
        let token_contract = address('a');
        let wrong_contract = address('f');
        let seller = address('b');
        let buyer = address('c');
        let terminal = StreamStopped {
            buyer: buyer.clone(),
            to_seller: 1,
            refund_to_buyer: 2,
        };

        let wrong_reader = build_receipt(
            context(&token_contract),
            &chain(
                &wrong_contract,
                Some(current_facts(Some(&buyer), &seller, false, true, false, 3)),
                vec![event("terminal", 1, terminal.clone())],
            ),
        );
        assert_eq!(wrong_reader.terminal.status, "inconsistent");
        assert!(wrong_reader
            .consistency_issues
            .contains(&"reader_account_mismatch".to_string()));

        let contradictory = build_receipt(
            context(&token_contract),
            &chain(
                &token_contract,
                Some(current_facts(Some(&buyer), &seller, true, true, false, 3)),
                vec![event("terminal", 1, terminal)],
            ),
        );
        assert_eq!(contradictory.terminal.status, "inconsistent");
        assert!(contradictory
            .consistency_issues
            .contains(&"terminal_event_current_state_mismatch".to_string()));
    }

    #[test]
    fn events_from_two_token_contracts_cannot_mix() {
        let first = address('a');
        let second = address('e');
        let first_receipt = build_receipt(
            context(&first),
            &chain(
                &first,
                None,
                vec![event(
                    "first-destroyed",
                    1,
                    ContractDestroyed {
                        token_contract: first.clone(),
                    },
                )],
            ),
        );
        let second_receipt = build_receipt(
            context(&second),
            &chain(
                &second,
                None,
                vec![event(
                    "second-destroyed",
                    1,
                    ContractDestroyed {
                        token_contract: second.clone(),
                    },
                )],
            ),
        );
        assert_eq!(first_receipt.settlement_sequence[0].payload["self"], first);
        assert_eq!(
            second_receipt.settlement_sequence[0].payload["self"],
            second
        );

        let mixed = build_receipt(
            context(&first),
            &chain(
                &first,
                None,
                vec![event(
                    "foreign-destroyed",
                    1,
                    ContractDestroyed {
                        token_contract: second,
                    },
                )],
            ),
        );
        assert_eq!(mixed.terminal.status, "inconsistent");
        assert!(mixed
            .consistency_issues
            .contains(&"event_token_contract_mismatch".to_string()));
    }

    #[test]
    fn receipt_fixture_is_stable_and_contains_no_private_local_material() {
        let receipt = unavailable_receipt(context(&address('a')));
        let actual = as_value(&receipt);
        let expected: Value =
            serde_json::from_str(include_str!("settlement_receipt_v1.fixture.json"))
                .expect("parse settlement receipt fixture");
        assert_eq!(actual, expected);

        let serialized = serde_json::to_string(&receipt).expect("serialize receipt");
        for forbidden in [
            "wallet_key",
            "note_secret",
            "owner_secret",
            "endpoint_cipher",
            "prompt",
            "model_output",
            "deal_history",
        ] {
            assert!(!serialized.contains(forbidden), "leaked {forbidden}");
        }
    }

    #[test]
    fn rewards_join_is_two_note_season_aggregate_and_never_per_deal_points() {
        let token_contract = address('a');
        let seller = address('b');
        let buyer = address('c');
        let receipt = build_receipt(
            context(&token_contract),
            &chain(
                &token_contract,
                Some(current_facts(Some(&buyer), &seller, true, false, false, 0)),
                Vec::new(),
            ),
        );
        let rewards = &as_value(&receipt)["rewards"];
        assert_eq!(rewards["schema"], REWARDS_SCHEMA);
        assert_eq!(rewards["source"], REWARDS_SOURCE);
        assert_eq!(rewards["requested_season"], 7);
        assert_eq!(rewards["semantics"], REWARDS_SEMANTICS);
        assert_eq!(rewards["queries"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            rewards["queries"][0]["query_path"],
            format!("/v1/notes/{buyer}?season=7")
        );
        assert_eq!(
            rewards["queries"][1]["query_path"],
            format!("/v1/notes/{seller}?season=7")
        );
        assert!(rewards.get("points").is_none());
        assert!(rewards.get("token_contract").is_none());
    }
}
