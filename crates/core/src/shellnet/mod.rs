//! Real shellnet backend -- an on-chain adapter on top of the **`gosh.ackinacki`
//! SDK**(`gosh_ackinacki::sdk`). The wallet/keys/chain interaction are not rewritten -- they are
//! taken from the SDK.
//! This module covers **step 1 of the START signal**:
//! connecting to the manifest-selected Block Manager endpoint and reading the deployed contracts
//! (`contracts/deployed.shellnet.json`). The `ChainBackend` trait implementation
//! (offer/match in `InferenceOrderBook`, probe/`advance`/`stop`/burn in `TokenContract`, notes in
//! `PrivateNote`) is layered on top of this `ChainClient` in the next step -- its money choreography
//! is verified against the real on-chain(funded keys required), so no trait
//! stubs are introduced here.

mod backends;
mod book_events;
mod client;
mod contracts_provision;
#[cfg(all(test, feature = "test-giver"))]
#[path = "legacy_giver.rs"]
mod live_tests;
mod note_events;
mod order_events;

pub use crate::params::DEFAULT_SHELLNET_ENDPOINT;
pub use backends::{
    real_market_deal_view, DealContext, RealBuyerBackend, RealDealBackend, RealNote,
    RealSellerBackend,
};
pub use book_events::{
    fold_book_event_pages, BookEventFold, BookEventMessage, BookEventPage, BookFillCandidate,
    LiveBookOrder,
};
#[cfg(feature = "test-giver")]
pub use client::{PlaceInferenceBuyReceipt, TokenContractInboundCall};
pub use client::{decode_tokens_withdrawn_event, TokensWithdrawnEvent};
pub use client::{
    chain_time_secs, decode_multisig_queue_event, parse_message_destination,
    parse_source_transaction_out_messages, prove_multisig_delivery_message,
    read_multisig_queue_history, sole_delivery_sibling, MultisigQueueEvent, MultisigQueueRecord,
};
pub use client::{retry_transient_read, RetryingReads};
pub use client::{
    endpoint_urls, normalize_endpoint, note_transfer_amount_refusal, BookFillCandidateRefusal,
    BookFillCandidateReport,
    note_transfer_deposit_identifier_hash, note_transfer_dest_refusal, note_transfer_sender_refusal,
    note_transfer_submit_hint, observe_note_deploy_rootpn_action,
    observe_note_deploy_wallet_action, resolve_endpoint, shellnet_clock_skew_preflight,
    shellnet_http_client, Deployed, MoneySubmitError, NoteDeployRootPnActionObservation,
    NoteDeployWalletActionObservation, NoteTransferRefusal, OutstandingDealLead,
    OutstandingDealLeadRefusal, PrivateNoteOutstandingReport, RealChainBackend,
    ShellnetDoctorCheck, ShellnetDoctorReport, ShellnetDoctorStatus, TokenContractCurrentFacts,
    TokenContractReceiptChainData, TokenContractSettlementEvent, TokenContractSettlementReceipt,
    TokenContractSettlementReceipts,
};
pub use contracts_provision::keypair_ed_pubkey;
