//! `dexdo-core` -- shared types, protocol parameters, the stream state machine, the crypto note,
//! and an on-chain abstraction with a mock implementation. Pure logic without networking (state
//! machine/formulas), plus real local note cryptography and `MockChainBackend`.
//! Canon: `dexdo-cli.md`-, `private-inference-market-design.md`-,, Appx. A.

pub mod chain;
pub mod handover;
pub mod machine;
pub mod note;
pub mod onchain_diagnostics;
pub mod params;
pub mod settle;
// issue: market-provisioning output manifest(pure data; consumed by seller/buyer).
pub mod manifest;
// issue: oracle/PMP prediction-market provisioning manifest(pure data).
pub mod oracle_manifest;
// wallet-address parse/normalize(`half1::half2` -> `0:<half2>`), fail-loud. Non-gated so
// the format logic is offline-tested; consumed by the real money path(`shellnet`) and the seed-wallet CLI.
pub mod wallet;
// real shellnet backend on top of the gosh.ackinacki SDK(behind the `shellnet` feature).
#[cfg(feature = "shellnet")]
pub mod canonical_multisig;
#[cfg(feature = "shellnet")]
pub mod shellnet;

/// SDK shellnet types -- re-exported behind `shellnet` for the live harness and the production CLI note-deploy
/// path. Wallet custody stays external. `note deploy` generates the PrivateNote owner key and persists it in
/// operator-owned recovery/pool files; subsequent commands read wallet/note secrets from explicit files.
#[cfg(feature = "shellnet")]
pub use gosh_ackinacki::{
    airegistry, private_note,
    sdk::{Address, ChainClient, KeyPair},
};
#[cfg(feature = "shellnet")]
pub mod ackinacki_wallet {
    pub use gosh_ackinacki::wallet::query;
}
#[cfg(feature = "test-giver")]
pub use shellnet::PlaceInferenceBuyReceipt;
#[cfg(feature = "shellnet")]
pub use shellnet::{
    endpoint_urls, keypair_ed_pubkey, normalize_endpoint, real_market_deal_view, resolve_endpoint,
    shellnet_clock_skew_preflight, DealContext, Deployed, MoneySubmitError, RealBuyerBackend,
    RealChainBackend, RealDealBackend, RealNote, RealSellerBackend, ShellnetDoctorCheck,
    ShellnetDoctorReport, ShellnetDoctorStatus, TokenContractSettlementEvent,
    TokenContractSettlementReceipt, TokenContractSettlementReceipts, DEFAULT_SHELLNET_ENDPOINT,
};

pub use chain::flags as order_flags;
pub use chain::{
    aggregate_tree, check_buy_deposit_headroom, check_disputable,
    check_matched_token_contract_state, check_reclaimable, check_recoverable,
    check_release_disputable, check_seller_pubkey, check_subscription_buy_reserve,
    check_withdrawable_shell, deal_anomalies, executable_quote, per_model_breakdown,
    required_escrow_for_buy, submit_safe_single_ask_quote, subscription_buy_clearing_refund,
    subscription_buy_reserve, validate_seller_resume_state, ChainBackend, ChainError, ClaimBounds,
    CounterpartyTally, DealAnomaly, DealBuyerBond, DealChainSnapshot, DealChainState, DealRole,
    DealSellerBond, DealSubscription, DealView, ExecutableQuote, InferenceSubscriptionPlacement,
    Match, MatchWatchCursor, MatchedFill, MatchedTokenContractStatus, MockChainBackend,
    ModelBreakdown, NoteSnapshot, OfferListing, OrderBookOrder, OrderBookSnapshot, OrderBookStats,
    QuoteFill, RawUint128, ReclaimAction, SellOffer, SellOfferOutcome, SettlementAction,
    SettlementActionBondState, SettlementActionEvent, SettlementActionPostState,
    SettlementActionReceipt, StreamSnapshot, SubscriptionBuyReserve, TokenContract, TreeSnapshot,
    UNKNOWN_MODEL,
};
pub use handover::Handover;
pub use machine::{InvariantError, Settlement, StreamMachine, StreamState, Tick};
pub use manifest::{
    model_hash_for, resolve_model_name, validate_canonical_model_id, MarketManifest,
};
pub use note::{verify, LocalNote, Note, NoteError, NotePubkey, NoteTree, Signature};
pub use onchain_diagnostics::{
    contract_error_names, sanitize_onchain_submit_payload, validate_onchain_submit_response,
    OnchainSubmitError,
};
pub use oracle_manifest::OracleMarketManifest;
pub use params::{
    cli_buy_deadline_is_valid, default_buy_deadline, probe_seed_owed, DobParams, ProtocolConsts,
    Shell, DEAL_SNAPSHOT_MAX_ATTEMPTS, DEFAULT_BUY_TTL, MATCH_OPEN_TIMEOUT,
    MATCH_OPEN_TIMEOUT_SECS, MAX_SELL_TTL, MIN_STREAM_BUY_TICKS, PLATFORM_FEE_BPS, PRICE_STEP,
    PROBE_SEED_TOKENS, SELLER_TERMINAL_RECEIPT_POLL_INTERVAL, SELLER_TERMINAL_RECEIPT_TIMEOUT,
    SHELL_ECC_ID, SUBSCRIPTION_BUYER_BOND_TICKS, SUBSCRIPTION_MAX_TICKS,
    SUBSCRIPTION_ORDER_RECONCILE_POLL, SUBSCRIPTION_WEEKS, SUB_TICKS_PER_WEEK, SUB_WEEK_LEN,
    TICK_SIZE,
};
pub use settle::{
    contested_burn, fee, net_burn, probe_burn, rebate, rebate_rate_bps, ContestedBurn,
};
pub use wallet::normalize_wallet_address;
