//! Protocol parameters. Fixed constants and order book deploy parameters.
//! These are pure types without networking. Values are taken from the spec.

use std::time::Duration;

/// SHELL -- the system's settlement unit. Integer count of minimal units.
pub type Shell = u64;

/// Canonical ECC currency id used by every dexdo market-money path.
pub const SHELL_CURRENCY_ID: u32 = 2;

/// Canonical CLI label for the market settlement currency.
pub const SHELL_CURRENCY_LABEL: &str = "shell";

/// Canonical order-book price quantum: `1e9` raw ECC[2] units = 1 SHELL.
pub const PRICE_STEP: u128 = 1_000_000_000;

/// Minimum buy size, in ticks, needed for the probe tick plus one streaming tick.
pub const MIN_STREAM_BUY_TICKS: u128 = 2;

/// Currency collection id used by Acki Nacki for SHELL balances.
pub const SHELL_ECC_ID: u32 = 2;

/// Canonical tick: the billing quantum, in tokens. Consumption is claimed and disputed in raw tokens;
/// only value is computed per tick(`TICK_SIZE = 1_000_000`).
pub const TICK_SIZE: u128 = 1_000_000;

/// Cumulative consumption an accepted probe credits, in tokens: exactly one canonical tick.
/// THE RULE, in one place, because consumers keep inventing their own reading of it: accepting the probe is
/// ONE atomic credit-and-pay event -- exactly one tick is delivered-credited AND exactly one tick is paid.
/// `TokenContract.acceptProbe()`(`contracts/airegistry/TokenContract.sol`) does both in the same
/// transaction: `_finalizedOwed += _probeTick` (:674, and `_probeTick == _pricePerTick` since `open()`
/// 640) pays it, while `_tokensPaid = TICK_SIZE`(:690) and `_tokensFinal = _tokensPend1 = _tokensPend2 =
/// TICK_SIZE`(:697-699) credit it. Claims are cumulative from zero and the probe is their first tick, not
/// something claimed on top.
/// So the seed is NEVER an unbacked delivery advance for a capacity observer to refuse -- the buyer
/// bought the trial tick whatever the model actually produced for it -- and NEVER "nothing paid yet".
pub const PROBE_SEED_TOKENS: u128 = TICK_SIZE;

/// The money face of [`PROBE_SEED_TOKENS`]: what an accepted probe alone has put into `finalizedOwed`, at
/// the deal price, before any later claim.
/// Zero while the probe is not accepted -- until then the trial tick is the buyer's, and `stop()` burns it
/// (`TokenContract.sol`:1157). This is the probe's own contribution only: a TERMINAL `finalizedOwed`
/// additionally carries the returned seller bond(:1089,:1166) and the rebate(:346), so it is a
/// floor there rather than the whole figure.
pub const fn probe_seed_owed(probe_accepted: bool, price_per_tick: u128) -> u128 {
    if probe_accepted {
        price_per_tick
    } else {
        0
    }
}

/// Canonical platform fee charged to the buyer, in basis points(`250 = 2.5%`).
pub const PLATFORM_FEE_BPS: u32 = 250;

/// Hard per-call consumption-claim increment accepted by `TokenContract.claimTokens`.
/// This is distinct from the physical rate allowance: waiting longer may make the rate inequality
/// permit more than one tick, but one call may still add at most one canonical tick.
pub const MAX_CLAIM_DELTA: u128 = TICK_SIZE;

/// One subscription week(`SUB_WEEK_LEN = 604_800s`).
pub const SUB_WEEK_LEN: Duration = Duration::from_secs(604_800);

/// Fixed subscription term, in weeks.
pub const SUBSCRIPTION_WEEKS: u8 = 4;

/// Maximum physically deliverable ticks in one subscription week.
pub const SUB_TICKS_PER_WEEK: u128 = 10_080;

/// Maximum ticks across the fixed four-week subscription term.
pub const SUBSCRIPTION_MAX_TICKS: u128 = SUB_TICKS_PER_WEEK * SUBSCRIPTION_WEEKS as u128;

/// Refundable buyer bond carried by a subscription BUY, measured in ticks at the deal price.
/// The book reserves it at the BUY limit price and forwards it at the clearing price. Ordinary BUYs
/// carry no buyer bond.
pub const SUBSCRIPTION_BUYER_BOND_TICKS: u128 = 2;

/// Funded-but-unopened cleanup timeout.
pub const MATCH_OPEN_TIMEOUT: Duration = Duration::from_secs(600);
/// Seconds representation for contract timestamps and serialized runtime state.
pub const MATCH_OPEN_TIMEOUT_SECS: u64 = MATCH_OPEN_TIMEOUT.as_secs();

/// Probe-acceptance window.
/// A FIXED constant, deliberately absent from `TokenContract.getConfig()`. `open()` freezes one tick as the
/// probe -- owed to nobody -- and only after this much buyer silence may the seller accept it and begin
/// claiming. Silence on a live endpoint is consent; a buyer who finds nothing there stops instead, and the
/// probe burns on both sides.
pub const PROBE_WINDOW: Duration = Duration::from_secs(180);

/// Default lifetime the client requests for a BUY order.
/// The on-chain order book intentionally accepts an absolute deadline of zero as GTC. The dexdo CLI is
/// stricter: every BUY it submits has a finite future deadline so stale escrow cannot remain at an untouched
/// price level indefinitely.
pub const DEFAULT_BUY_TTL: Duration = Duration::from_secs(3600);

/// Derive the strict dexdo CLI BUY deadline from the current unix time.
/// Overflow fails closed instead of silently turning the requested lifetime into another value.
pub const fn default_buy_deadline(now_unix_secs: u64) -> Option<u64> {
    now_unix_secs.checked_add(DEFAULT_BUY_TTL.as_secs())
}

/// Whether an absolute BUY deadline satisfies the strict dexdo CLI policy.
/// The contract permits `deadline == 0` as GTC; the client deliberately forbids it and any deadline that is
/// not strictly in the future.
pub const fn cli_buy_deadline_is_valid(deadline: u64, now_unix_secs: u64) -> bool {
    deadline != 0 && deadline > now_unix_secs
}

/// Poll interval while reconciling one subscription-order money action.
pub const SUBSCRIPTION_ORDER_RECONCILE_POLL: Duration = Duration::from_secs(2);

/// Longest lifetime a sell offer may request.
/// A sell offer commits no collateral at post time, so it must auto-expire -- there are no GTC asks. The note
/// rejects both `ttl == 0` and `ttl > MAX_SELL_TTL`, and anchors the resulting deadline at the seller's call,
/// so time spent reaching the book counts against the offer's life rather than extending it.
pub const MAX_SELL_TTL: Duration = Duration::from_secs(3600);

/// Exact byte length of the pinned Hermez K19 SRS used by `dexdo note deploy`.
pub const HERMEZ_SRS_SIZE_BYTES: u64 = 67_109_124;

/// Maximum HTTP attempts for one resumable Hermez SRS download invocation.
pub const HERMEZ_SRS_MAX_ATTEMPTS: usize = 5;

/// Initial retry delay for transient Hermez SRS download failures.
pub const HERMEZ_SRS_RETRY_INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Maximum one-based history-proof layer used by `dexdo note deploy` re-proof.
pub const NOTE_DEPLOY_PROOF_LAYER_MAX: u8 = 3;

/// Maximum attempts to obtain one internally coherent live `TokenContract`
/// accounting snapshot. Every attempt is one account-BOC-bracketed getter set.
pub const DEAL_SNAPSHOT_MAX_ATTEMPTS: usize = 3;

/// Maximum fresh coherent reads after the one allowed explicit buyer-STOP POST.
pub const EXPLICIT_STOP_CONFIRM_MAX_ATTEMPTS: usize = 40;

/// Delay between fresh coherent reads while confirming an explicit buyer STOP by fact.
pub const EXPLICIT_STOP_CONFIRM_POLL: Duration = Duration::from_secs(3);

/// Maximum wait for the authoritative buyer-owned `StreamStopped` receipt.
pub const SELLER_TERMINAL_RECEIPT_TIMEOUT: Duration = Duration::from_secs(120);
/// Poll interval while the exact `StreamStopped` receipt is not yet visible.
pub const SELLER_TERMINAL_RECEIPT_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Maximum seconds the CLI waits for a matched deal and its encrypted handover.
pub const DEAL_WAIT_SECS: u64 = 300;

/// Signed seconds scanned backwards when model-only resume reconstructs the newest owned fill.
pub const RESUME_LOOKBACK_SECS: i64 = 1_800;

/// Maximum attempts for a transient executable-quote read.
pub const TRANSIENT_QUOTE_ATTEMPTS: usize = 3;

/// Initial delay before retrying a transient executable-quote read.
pub const TRANSIENT_QUOTE_INITIAL_BACKOFF: Duration = Duration::from_millis(250);

/// Delays between bounded executable-book read attempts.
pub const EXECUTABLE_READ_BACKOFF: [Duration; 2] =
    [Duration::from_millis(250), Duration::from_millis(500)];

/// Maximum time spent waiting for another process to release the private-note pool lock.
pub const POOL_LOCK_TIMEOUT_SECS: u64 = 30;

/// Interval between private-note pool lock acquisition attempts.
pub const POOL_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Production interval between buyer continuity-monitor iterations.
pub const BUYER_MONITOR_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Production delay before retrying a failed buyer recovery action.
pub const BUYER_MONITOR_RECOVERY_BACKOFF: Duration = Duration::from_secs(30);

/// Delay before retrying a failed proactive subscription renewal.
pub const RENEWAL_FAILURE_BACKOFF_SECS: u64 = 30;

/// Seconds for which consumer traffic counts as recent renewal demand.
pub const CONSUMER_DEMAND_RECENT_SECS: u64 = 30;

/// Interval between reads while waiting for a seller handover.
pub const BUYER_HANDOVER_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Maximum wait for a seller's `postSellOffer` submit response.
pub const POST_SELL_OFFER_SUBMIT_TIMEOUT: Duration = Duration::from_secs(120);

/// Maximum readback window for proving that a submitted SELL rested or matched.
pub const OFFER_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(45);

/// Delays between bounded transient seller chain reads.
pub const SELLER_READ_BACKOFF: [Duration; 4] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
];

/// Default interval between seller match-watch reads.
pub const DEFAULT_MATCH_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum reads used to establish the seller's authoritative open-state precondition.
pub const SELLER_OPEN_STATE_READ_ATTEMPTS: usize = 3;

/// Initial linear backoff between seller open-state reads.
pub const SELLER_OPEN_STATE_INITIAL_BACKOFF: Duration = Duration::from_millis(100);

/// Default buyer reaction when stream verification detects a substitution.
pub const DEFAULT_BUYER_VERIFICATION_BAIL_ACTION: &str = "stop";

/// Default buyer reaction when the selected seller gateway cannot be opened.
pub const DEFAULT_BUYER_DEAD_GATEWAY_ACTION: &str = "retry_then_reclaim";

/// Default buyer reaction when a seller stream closes without delivering tokens.
pub const DEFAULT_BUYER_EMPTY_STREAM_ACTION: &str = "reclaim";

/// Default buyer reaction when a seller stalls after delivering some tokens.
pub const DEFAULT_BUYER_STALLS_MID_STREAM_ACTION: &str = "accept_delivered_then_reclaim";

/// Additional upstream-open attempts after the first buyer request fails.
pub const BUYER_UPSTREAM_OPEN_RETRIES: usize = 1;

/// Maximum canonical tokens requested by one content-identity probe.
pub const CONTENT_PROBE_MAX_TOKENS: u64 = 64;

/// Default subscription-continuity strategy exposed by the CLI.
pub const DEFAULT_CONTINUITY_MODE: &str = "proactive";

/// Remaining-token threshold at which proactive renewal starts.
pub const BUYER_RENEWAL_THRESHOLD_TOKENS: u64 = 64;

/// Default probability of a full buyer reference spot-check per request.
pub const DEFAULT_SPOT_CHECK_RATE: f64 = 0.03;

/// Spot-check multiplier applied to sellers with unknown or non-positive local scores.
pub const SPOT_CHECK_UNKNOWN_SCORE_MULTIPLIER: f64 = 4.0;

/// Decay coefficient applied per positive local seller-score point.
pub const SPOT_CHECK_POSITIVE_SCORE_DECAY: f64 = 0.5;

/// Local seller-score increment after a successful verification.
pub const SELLER_SCORE_PASS_DELTA: i64 = 1;

/// Local seller-score decrement after a verification bail or no-show.
pub const SELLER_SCORE_BAIL_DELTA: i64 = -1;

/// Absolute tolerance used by buyer log-probability validation.
pub const LOGPROB_VALIDATION_EPSILON: f64 = 1e-6;

/// Default minimum reference-prefix agreement accepted by a buyer spot-check.
pub const DEFAULT_SPOTCHECK_THRESHOLD: f64 = 0.7;

/// Default deterministic prompt used for buyer reference spot-checks.
pub const DEFAULT_SPOTCHECK_PROBE: &str = "What is 17 times 23? Show your step-by-step reasoning.";

/// Prompt used to prove that a configured seller upstream is ready.
pub const UPSTREAM_HEALTH_PROBE_PROMPT: &str = "Reply with OK.";

/// Token budget for one seller upstream readiness probe.
pub const UPSTREAM_HEALTH_PROBE_MAX_TOKENS: u32 = 1;

/// Buffered event capacity used by a seller upstream readiness probe.
pub const UPSTREAM_HEALTH_CHANNEL_CAPACITY: usize = 4;

/// Buffered upstream-event capacity for one seller gateway stream.
pub const GATEWAY_UPSTREAM_CHANNEL_CAPACITY: usize = 16;

/// Buffered buyer-facing chunk capacity for one seller gateway stream.
pub const GATEWAY_CLIENT_CHANNEL_CAPACITY: usize = 16;

/// Maximum upstream error-response body retained for safe parsing.
pub const UPSTREAM_ERROR_BODY_MAX_BYTES: usize = 4_096;

/// Maximum sanitized upstream error detail exposed to callers.
pub const UPSTREAM_ERROR_DETAIL_MAX_BYTES: usize = 1_024;

/// Maximum Unicode-scalar prefix retained when detecting echoed secrets.
pub const UPSTREAM_ERROR_ECHO_PREFIX_CHARS: usize = 32;

/// Maximum buffered incomplete upstream SSE frame.
pub const UPSTREAM_SSE_FRAME_MAX_BYTES: usize = 1_048_576;

/// GraphQL history page size for order-book event reads.
pub const BOOK_EVENT_PAGE_SIZE: u32 = 50;

/// Delays between transient order-book event-history read attempts.
pub const BOOK_EVENT_READ_BACKOFFS: [Duration; 4] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
];

/// Balance floor that triggers an active-contract gas top-up, in nanovmshell.
pub const ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL: u128 = 5_000_000_000;

/// Active-contract balance targeted by a gas top-up, in nanovmshell.
pub const ACTIVE_CONTRACT_GAS_HEALTH_TARGET_NANOVMSHELL: u128 = 10_000_000_000;

/// Client-side safety margin applied to shellnet clock-skew validation.
pub const SHELLNET_CLOCK_SKEW_SAFETY_MARGIN_SECS: u64 = 10;

/// Default shellnet GraphQL endpoint used when the operator supplies none.
pub const DEFAULT_SHELLNET_ENDPOINT: &str = "https://shellnet.ackinacki.org";

/// Maximum reads used to locate one finalized destination receipt.
pub const FINALIZED_DESTINATION_RECEIPT_MAX_ATTEMPTS: u32 = 12;

/// Interval between finalized destination-receipt reads.
pub const FINALIZED_DESTINATION_RECEIPT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// GraphQL page size for external-outbound message history.
pub const EXT_OUT_PAGE_SIZE: u32 = 1_000;

/// Transient submit retries performed before one final unslept attempt.
pub const TRANSIENT_SUBMIT_RETRIES_BEFORE_FINAL: u32 = 8;

/// Initial delay after a transient shellnet submit failure.
pub const TRANSIENT_SUBMIT_INITIAL_BACKOFF: Duration = Duration::from_secs(2);

/// Maximum delay between transient shellnet submit attempts.
pub const TRANSIENT_SUBMIT_MAX_BACKOFF: Duration = Duration::from_secs(8);

/// Multiplier applied to transient shellnet submit backoff.
pub const TRANSIENT_SUBMIT_BACKOFF_MULTIPLIER: u32 = 2;

/// Interval between reads while locating the correlated inference fill.
pub const INFERENCE_FILL_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Maximum reads used by the buyer-note shellnet preflight.
pub const BUYER_NOTE_PREFLIGHT_MAX_ATTEMPTS: u32 = 3;

/// Initial delay between transient buyer-note preflight reads.
pub const BUYER_NOTE_PREFLIGHT_INITIAL_BACKOFF: Duration = Duration::from_millis(250);

/// Multiplier applied to buyer-note preflight backoff.
pub const BUYER_NOTE_PREFLIGHT_BACKOFF_MULTIPLIER: u32 = 2;

/// Maximum balance reads used to confirm a gas top-up.
pub const GAS_BALANCE_CONFIRM_MAX_READS: usize = 20;

/// Interval between gas-balance confirmation reads.
pub const GAS_BALANCE_CONFIRM_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Read budget for a single non-waiting account-active probe.
pub const ACCOUNT_ACTIVE_SINGLE_CHECK_ATTEMPTS: u32 = 1;

/// Maximum reads used to confirm account activation after deployment.
pub const ACCOUNT_ACTIVATION_MAX_ATTEMPTS: u32 = 40;

/// Interval between account-activation confirmation reads.
pub const ACCOUNT_ACTIVATION_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Maximum reads used to resolve a newly created oracle event id.
pub const ORACLE_EVENT_ID_MAX_READS: usize = 20;

/// Interval between oracle event-id visibility reads.
pub const ORACLE_EVENT_ID_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Maximum reads used to confirm private-marketplace approval.
pub const PMP_APPROVAL_MAX_READS: usize = 30;

/// Interval between private-marketplace approval reads.
pub const PMP_APPROVAL_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Maximum reads used by the real backend to confirm a seller bond.
pub const SELLER_BOND_CONFIRM_MAX_READS: usize = 20;

/// Interval between real-backend seller-bond confirmation reads.
pub const SELLER_BOND_CONFIRM_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Maximum reads used to confirm a TokenContract boolean state transition.
pub const TC_BOOL_CONFIRM_MAX_READS: usize = 40;

/// Interval between TokenContract boolean-state confirmation reads.
pub const TC_BOOL_CONFIRM_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Maximum reads used to confirm cleanup of a funded-but-unopened deal.
pub const CLEANUP_UNOPENED_CONFIRM_MAX_READS: usize = 40;

/// Interval between cleanup-unopened confirmation reads.
pub const CLEANUP_UNOPENED_CONFIRM_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Maximum reads used by the real backend to confirm a matched deal.
pub const MATCH_CONFIRM_MAX_READS: usize = 40;

/// Interval between real-backend match confirmation reads.
pub const MATCH_CONFIRM_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Same-second lookback margin before scanning for seller-offer outcome events.
pub const SELLER_OFFER_EVENT_LOOKBACK_SECS: u64 = 1;

/// Interval between seller-offer outcome reads.
pub const SELLER_OFFER_OUTCOME_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Inclusive lower bound accepted by CLI arguments that require a positive `u64`.
pub const CLI_POSITIVE_U64_MIN: u64 = 1;

/// Default timeout for direct shellnet getter reads, in seconds.
pub const DEFAULT_CHAIN_READ_TIMEOUT_SECS: u64 = 30;

/// Default actor sub-note index selected by the CLI.
pub const DEFAULT_NOTE_INDEX: u32 = 0;

/// Default local seller gateway listen address.
pub const DEFAULT_SELLER_GATEWAY_LISTEN: &str = "127.0.0.1:8443";

/// Default fake-token count served by the explicit mock-model mode.
pub const DEFAULT_SELLER_MOCK_TOKEN_COUNT: u64 = 8;

/// Default models-registry configuration path.
pub const DEFAULT_MODELS_PATH: &str = "models.json";

/// Default deployed shellnet contracts-manifest path.
pub const DEFAULT_CONTRACTS_PATH: &str = "contracts/deployed.shellnet.json";

/// Default one-shot buyer receive cap, in tokens.
pub const DEFAULT_BUYER_MAX_TOKENS: u64 = 8;

/// Default ordinary buyer purchase size, in ticks.
pub const DEFAULT_BUYER_TICKS: u128 = 8;

/// Default number of deterministic sub-notes inspected by the monitor.
pub const DEFAULT_MONITOR_TREE_WIDTH: u32 = 8;

/// Default network selector used by `dexdo doctor`.
pub const DEFAULT_DOCTOR_NETWORK: &str = "shellnet";

/// Default role spelling used by `dexdo policy init`.
pub const DEFAULT_POLICY_ROLE: &str = "both";

/// Default maximum tick capacity for a provisioned deal.
pub const DEFAULT_PROVISION_MAX_TICKS: u128 = 1_024;

/// Default output path for a provisioned market manifest.
pub const DEFAULT_MARKET_MANIFEST_OUTPUT_PATH: &str = "market.json";

/// Default frame model shown by mock-chain market discovery.
pub const DEFAULT_MARKETS_FRAME_MODEL: &str = "dexdo-mock";

/// Default desired tick count for executable-book reads.
pub const DEFAULT_EXECUTABLE_BOOK_TICKS: u128 = 8;

/// Default market-data output format spelling.
pub const DEFAULT_MARKET_DATA_OUTPUT: &str = "table";

/// Default market-data indexer request timeout, in milliseconds.
pub const DEFAULT_MARKET_DATA_TIMEOUT_MS: u64 = 10_000;

/// Inclusive lower bound for market-data list page sizes.
pub const MARKET_DATA_LIST_LIMIT_MIN: u32 = 1;

/// Inclusive upper bound for market-data list page sizes.
pub const MARKET_DATA_LIST_LIMIT_MAX: u32 = 200;

/// Inclusive lower bound for market-data depth levels per side.
pub const MARKET_DATA_DEPTH_LIMIT_MIN: u32 = 1;

/// Inclusive upper bound for market-data depth levels per side.
pub const MARKET_DATA_DEPTH_LIMIT_MAX: u32 = 1_000;

/// Default loopback listen address for the local dashboard.
pub const DEFAULT_DASHBOARD_LISTEN: &str = "127.0.0.1:8765";

/// Default deal-audit export format spelling.
pub const DEFAULT_EXPORT_FORMAT: &str = "json";

/// Default hostname used by `dexdo note deploy` for shellnet.
pub const DEFAULT_NOTE_DEPLOY_ENDPOINT: &str = "shellnet.ackinacki.org";

/// Default OracleEventList index used by oracle provisioning.
pub const DEFAULT_ORACLE_EVENT_LIST_INDEX: u128 = 0;

/// Default human-readable OracleEventList description.
pub const DEFAULT_ORACLE_EVENT_LIST_DESCRIPTION: &str = "";

/// Default event description passed into private-marketplace approval.
pub const DEFAULT_ORACLE_PMP_DESCRIPTION: &str = "";

/// Default oracle fee paid by a provisioned private marketplace.
pub const DEFAULT_ORACLE_FEE: u128 = 0;

/// Default output path for an oracle-market manifest.
pub const DEFAULT_ORACLE_MARKET_OUTPUT_PATH: &str = "oracle-market.json";

/// Interval between reads while reconciling a durable buyer submit journal.
pub const BUYER_SUBMIT_RECONCILE_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Maximum on-demand buyer attempts after replay-protection failures.
pub const BUYER_REPLAY_PROTECTION_MAX_ATTEMPTS: u64 = 3;

/// Linear replay-protection retry delay per attempt, in seconds.
pub const BUYER_REPLAY_PROTECTION_BACKOFF_STEP_SECS: u64 = 2;

/// HTTP timeout for proving that the local buyer API is ready.
pub const BUYER_API_READINESS_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum reads used to confirm a newly deployed inference order book.
pub const MARKET_DEPLOY_ACTIVATION_MAX_READS: usize = 30;

/// Interval between inference-order-book activation reads.
pub const MARKET_DEPLOY_ACTIVATION_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Maximum reads used to observe a resolved private marketplace.
pub const ORACLE_RESOLUTION_MAX_READS: usize = 60;

/// Interval between private-marketplace resolution reads.
pub const ORACLE_RESOLUTION_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Timeout for the indexer fast-path before direct chain fallback.
pub const INDEXER_FAST_TIMEOUT: Duration = Duration::from_secs(2);

/// Default Dodex inference market-data indexer base URL.
pub const DEFAULT_INDEXER_URL: &str = "http://dodex-dev.ackinacki.org:8080";

/// Maximum compact indexer error-response body exposed to operators.
pub const INDEXER_ERROR_BODY_MAX_BYTES: usize = 2_048;

/// Browser dashboard refresh cadence, in milliseconds.
pub const DASHBOARD_REFRESH_INTERVAL_MS: u64 = 5_000;

/// Maximum local wait for another note-deploy operation using the same wallet, in seconds.
pub const NOTE_DEPLOY_LOCK_TIMEOUT_SECS: u64 = 3_600;

/// Interval between funding-wallet lock acquisition attempts.
pub const NOTE_DEPLOY_WALLET_LOCK_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Interval between prover-cache lock acquisition attempts.
pub const NOTE_DEPLOY_PROVER_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Raw native value attached to a note-deploy multisig voucher submit.
pub const NOTE_DEPLOY_SUBMIT_NATIVE_VALUE: u128 = 2_000_000_000;

/// Maximum wait for the submitted voucher's `VoucherGenerated` event.
pub const NOTE_DEPLOY_VOUCHER_EVENT_TIMEOUT: Duration = Duration::from_secs(480);

/// Maximum wallet-submit attempts after busy or out-of-sync errors.
pub const NOTE_DEPLOY_WALLET_BUSY_MAX_ATTEMPTS: u64 = 3;

/// Linear wallet-busy retry delay per attempt, in seconds.
pub const NOTE_DEPLOY_WALLET_BUSY_BACKOFF_STEP_SECS: u64 = 10;

/// Maximum wait for a deployed PrivateNote to become active.
pub const NOTE_DEPLOY_ACTIVE_TIMEOUT: Duration = Duration::from_secs(120);

/// Recovery-time probe window for already-applied PrivateNote SHELL funding.
pub const NOTE_DEPLOY_EXISTING_SHELL_FUNDING_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum wait for SHELL funding after submitting it to a PrivateNote.
pub const NOTE_DEPLOY_SHELL_FUNDING_TIMEOUT: Duration = Duration::from_secs(180);

/// Interval between PrivateNote SHELL-funding reads.
pub const NOTE_DEPLOY_SHELL_FUNDING_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Interval between PrivateNote account-activation reads.
pub const NOTE_DEPLOY_ACTIVE_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Read-buffer size used while hashing the pinned Hermez SRS.
pub const HERMEZ_SRS_HASH_BUFFER_BYTES: usize = 64 * 1_024;

/// Minimum percentage-point advance between Hermez SRS progress reports.
pub const HERMEZ_SRS_PROGRESS_STEP_PERCENT: u64 = 5;

/// HTTP timeout for one Hermez SRS download request.
pub const HERMEZ_SRS_HTTP_TIMEOUT: Duration = Duration::from_secs(120);

/// Minimum whole-SHELL funding accepted per note-funded contract deployment.
pub const MIN_DEPLOY_SHELLS: u128 = 10;

/// Default whole-SHELL allocation split across the two provisioned contracts.
pub const DEFAULT_DEPOSIT_SHELLS: u128 = 20;

/// Fixed protocol constants.
/// These mirror `TokenContract.getConfig()` plus `getFees()`. The former per-deal price-scaled windows
/// (`settleWindow`/`streamTimeout`) are gone: consumption is now claimed in tokens under two flat bounds,
/// and the buyer's exit is `stop()` at any time rather than a gated inactivity reclaim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolConsts {
    /// Platform fee, bps(on the buyer side, by-fact). `PLATFORM_FEE_BPS = 250`.
    pub platform_fee_bps: u32,
    /// Minimum spacing between consumption claims. `MIN_CLAIM_INTERVAL = 60s`.
    pub min_claim_interval: Duration,
    /// Physical floor on generation: `TICK_SIZE` tokens cannot be produced faster than this, so a claim
    /// asserting more output than the elapsed time allows is rejected. `MIN_SECONDS_PER_TICK = 60s`.
    pub min_seconds_per_tick: Duration,
    /// Silence after which the newest claim may be promoted to trusted. `CLAIM_PROMOTE_WINDOW = 120s`.
    pub claim_promote_window: Duration,
    /// Buyer silence after which the seller may accept the probe tick. `PROBE_WINDOW = 180s`.
    pub probe_window: Duration,
    /// Dispute window; timeout burns the contested amount on both sides. `DISPUTE_WINDOW = 600s`.
    pub dispute_window: Duration,
    /// Rebate rate cap, bps; strictly < `platform_fee_bps`. `REBATE_MAX_BPS = 200`.
    pub rebate_max_bps: u32,
    /// Rebate rate slope, bps per tick. `REBATE_SLOPE_BPS = 4`.
    pub rebate_slope_bps: u32,
}

impl ProtocolConsts {
    /// Canonical values from / A.1.
    /// The invariant `rebate_max_bps < platform_fee_bps` is checked here:
    /// otherwise the net burn could become non-positive.
    pub const fn canonical() -> Self {
        let c = Self {
            platform_fee_bps: PLATFORM_FEE_BPS,
            min_claim_interval: Duration::from_secs(60),
            min_seconds_per_tick: Duration::from_secs(60),
            claim_promote_window: Duration::from_secs(120),
            probe_window: PROBE_WINDOW,
            dispute_window: Duration::from_secs(600),
            rebate_max_bps: 200,
            rebate_slope_bps: 4,
        };
        assert!(
            c.rebate_max_bps < c.platform_fee_bps,
            "anti-wash invariant: REBATE_MAX_BPS must be strictly < PLATFORM_FEE_BPS"
        );
        c
    }

    /// Largest cumulative increment one claim may assert after `elapsed`.
    /// The contract applies both the physical rate inequality and the independent hard per-call
    /// [`MAX_CLAIM_DELTA`]. Waiting can satisfy the rate inequality for a later claim, but never turns one
    /// call into a multi-tick claim; backlog must be submitted as later one-tick-or-smaller calls.
    pub const fn max_claim_delta(&self, elapsed: Duration) -> u128 {
        claim_delta_limit(elapsed, self.min_seconds_per_tick)
    }
}

/// Combined client-side claim limit matching both `claimTokens` inequalities.
/// A zero rate floor is treated as "no physical-rate restriction" for deterministic mock/test
/// configurations; the hard per-call limit still applies.
pub const fn claim_delta_limit(elapsed: Duration, min_seconds_per_tick: Duration) -> u128 {
    let floor = min_seconds_per_tick.as_secs() as u128;
    let rate_limit = if floor == 0 {
        MAX_CLAIM_DELTA
    } else {
        (elapsed.as_secs() as u128) * TICK_SIZE / floor
    };
    if rate_limit < MAX_CLAIM_DELTA {
        rate_limit
    } else {
        MAX_CLAIM_DELTA
    }
}

impl Default for ProtocolConsts {
    fn default() -> Self {
        Self::canonical()
    }
}

/// Seller CLI liveness timings for a resting SELL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SellerLivenessParams {
    /// Time between complete gateway/upstream health cycles.
    pub health_interval: Duration,
    /// Per-cycle budget for gateway and exact-model upstream readiness.
    pub health_check_timeout: Duration,
    /// Maximum time from a completed failed health cycle to a terminal order fact.
    pub health_cycle_timeout: Duration,
    /// Standalone graceful-shutdown cancellation confirmation budget.
    pub cancel_confirmation_timeout: Duration,
    /// Poll interval while reconciling exact order state.
    pub cancel_confirmation_poll: Duration,
    /// Poll interval used only to notice a terminated gateway task.
    pub gateway_task_poll: Duration,
}

impl SellerLivenessParams {
    /// Canonical values from.
    pub const fn canonical() -> Self {
        Self {
            health_interval: Duration::from_secs(20),
            health_check_timeout: Duration::from_secs(20),
            health_cycle_timeout: Duration::from_secs(60),
            cancel_confirmation_timeout: Duration::from_secs(60),
            cancel_confirmation_poll: Duration::from_secs(2),
            gateway_task_poll: Duration::from_millis(100),
        }
    }
}

impl Default for SellerLivenessParams {
    fn default() -> Self {
        Self::canonical()
    }
}

/// Seller claim confirmation timings for authoritative `tokensPending` readback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimConfirmationParams {
    /// Maximum authoritative post-submit state reads, including the immediate first read.
    pub max_reads: usize,
    /// Time between post-submit state reads.
    pub poll_interval: Duration,
}

impl ClaimConfirmationParams {
    /// Canonical claim confirmation schedule: forty reads, with three seconds between consecutive reads.
    pub const fn canonical() -> Self {
        Self {
            max_reads: 40,
            poll_interval: Duration::from_secs(3),
        }
    }

    /// Maximum elapsed polling time, excluding RPC duration. The first read is immediate, so `N` reads
    /// contain exactly `N - 1` poll intervals.
    pub fn max_elapsed(self) -> Duration {
        assert!(
            !self.poll_interval.is_zero(),
            "claim confirmation poll interval must be non-zero"
        );
        assert!(
            self.max_reads > 0,
            "claim confirmation must perform at least one read"
        );
        self.poll_interval
            * u32::try_from(self.max_reads - 1)
                .expect("claim confirmation poll-interval count must fit u32")
    }
}

impl Default for ClaimConfirmationParams {
    fn default() -> Self {
        Self::canonical()
    }
}
/// Order book deploy parameters. In they are filled by a mock; in production they are read from on-chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DobParams {
    /// Tick size in tokens; reference value 1M.
    pub tick_size: u64,
}

impl DobParams {
    /// Canonical reference for: `TICK_SIZE = 1M`.
    pub const fn canonical() -> Self {
        Self {
            tick_size: TICK_SIZE as u64,
        }
    }
}

impl Default for DobParams {
    fn default() -> Self {
        Self::canonical()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        cli_buy_deadline_is_valid, default_buy_deadline, probe_seed_owed, ClaimConfirmationParams,
        DobParams, ProtocolConsts, SellerLivenessParams, DEAL_SNAPSHOT_MAX_ATTEMPTS,
        DEFAULT_BUY_TTL, EXPLICIT_STOP_CONFIRM_MAX_ATTEMPTS, EXPLICIT_STOP_CONFIRM_POLL,
        HERMEZ_SRS_MAX_ATTEMPTS, HERMEZ_SRS_RETRY_INITIAL_BACKOFF, HERMEZ_SRS_SIZE_BYTES,
        MATCH_OPEN_TIMEOUT, MATCH_OPEN_TIMEOUT_SECS, MAX_CLAIM_DELTA, MIN_STREAM_BUY_TICKS,
        PLATFORM_FEE_BPS, PRICE_STEP, PROBE_SEED_TOKENS, SELLER_TERMINAL_RECEIPT_POLL_INTERVAL,
        SELLER_TERMINAL_RECEIPT_TIMEOUT, SUBSCRIPTION_MAX_TICKS, SUBSCRIPTION_WEEKS,
        SUB_TICKS_PER_WEEK, TICK_SIZE,
    };
    use proptest::prelude::*;
    use std::time::Duration;

    #[test]
    fn an_accepted_probe_is_exactly_one_tick_credited_and_one_tick_paid() {
        // The two faces of one rule must never drift apart: whatever a consumer reads the probe seed to
        // credit, it reads the same single tick to have been paid.
        assert_eq!(PROBE_SEED_TOKENS, TICK_SIZE);
        assert_eq!(probe_seed_owed(true, PRICE_STEP), PRICE_STEP);
        assert_eq!(probe_seed_owed(false, PRICE_STEP), 0);
        assert_eq!(
            probe_seed_owed(true, PRICE_STEP) / PRICE_STEP,
            PROBE_SEED_TOKENS / TICK_SIZE
        );
    }

    #[test]
    fn claim_limit_clamps_rate_allowance_to_the_hard_per_call_cap() {
        let params = ProtocolConsts::canonical();
        assert_eq!(params.max_claim_delta(Duration::ZERO), 0);
        assert_eq!(
            params.max_claim_delta(Duration::from_secs(59)),
            59 * TICK_SIZE / 60
        );
        assert_eq!(
            params.max_claim_delta(Duration::from_secs(60)),
            MAX_CLAIM_DELTA
        );
        assert_eq!(
            params.max_claim_delta(Duration::from_secs(600)),
            MAX_CLAIM_DELTA,
            "ten minutes of rate allowance still permits only one tick in one call"
        );
    }

    proptest! {
        #[test]
        fn claim_limit_never_exceeds_rate_or_hard_contract_bound(elapsed in 0_u64..=86_400) {
            let params = ProtocolConsts::canonical();
            let limit = params.max_claim_delta(Duration::from_secs(elapsed));
            let rate_limit = u128::from(elapsed) * TICK_SIZE
                / u128::from(params.min_seconds_per_tick.as_secs());

            prop_assert!(limit <= rate_limit);
            prop_assert!(limit <= MAX_CLAIM_DELTA);
            if elapsed >= params.min_seconds_per_tick.as_secs() {
                prop_assert_eq!(limit, MAX_CLAIM_DELTA);
            }
        }
    }

    #[test]
    fn seller_liveness_parameters_match_directive_668() {
        let params = SellerLivenessParams::canonical();
        assert_eq!(params.health_interval, Duration::from_secs(20));
        assert_eq!(params.health_check_timeout, Duration::from_secs(20));
        assert_eq!(params.health_cycle_timeout, Duration::from_secs(60));
        assert_eq!(params.cancel_confirmation_timeout, Duration::from_secs(60));
        assert_eq!(params.cancel_confirmation_poll, Duration::from_secs(2));
        assert_eq!(params.gateway_task_poll, Duration::from_millis(100));
    }

    #[test]
    fn claim_confirmation_parameters_define_one_canonical_budget() {
        let params = ClaimConfirmationParams::canonical();
        assert_eq!(params.max_reads, 40);
        assert_eq!(params.poll_interval, Duration::from_secs(3));
        assert_eq!(
            params.max_elapsed(),
            Duration::from_secs(117),
            "the first read is immediate, so forty reads contain exactly thirty-nine waits"
        );
    }

    #[test]
    fn subscription_and_match_timeout_parameters_are_canonical() {
        assert_eq!(SUBSCRIPTION_WEEKS, 4);
        assert_eq!(SUB_TICKS_PER_WEEK, 10_080);
        assert_eq!(SUBSCRIPTION_MAX_TICKS, 40_320);
        assert_eq!(MATCH_OPEN_TIMEOUT, Duration::from_secs(600));
        assert_eq!(MATCH_OPEN_TIMEOUT_SECS, 600);
    }

    #[test]
    fn default_buy_deadline_is_finite_future_and_overflow_fails_closed() {
        let now = 1_900_000_000;
        let deadline = default_buy_deadline(now).expect("ordinary unix time must fit");
        assert_eq!(deadline, now + DEFAULT_BUY_TTL.as_secs());
        assert!(cli_buy_deadline_is_valid(deadline, now));
        assert_eq!(default_buy_deadline(u64::MAX), None);
    }

    #[test]
    fn cli_buy_deadline_policy_rejects_gtc_present_and_past() {
        let now = 1_900_000_000;
        assert!(!cli_buy_deadline_is_valid(0, now));
        assert!(!cli_buy_deadline_is_valid(now, now));
        assert!(!cli_buy_deadline_is_valid(now - 1, now));
        assert!(cli_buy_deadline_is_valid(now + 1, now));
    }

    #[test]
    fn hermez_srs_download_parameters_match_the_directive() {
        assert_eq!(HERMEZ_SRS_SIZE_BYTES, 67_109_124);
        assert_eq!(HERMEZ_SRS_MAX_ATTEMPTS, 5);
        assert_eq!(HERMEZ_SRS_RETRY_INITIAL_BACKOFF, Duration::from_secs(1));
    }

    #[test]
    fn coherent_deal_snapshot_attempt_bound_is_canonical() {
        assert_eq!(DEAL_SNAPSHOT_MAX_ATTEMPTS, 3);
    }

    #[test]
    fn explicit_stop_confirmation_budget_is_canonical() {
        assert_eq!(EXPLICIT_STOP_CONFIRM_MAX_ATTEMPTS, 40);
        assert_eq!(EXPLICIT_STOP_CONFIRM_POLL, Duration::from_secs(3));
    }

    #[test]
    fn stream_buy_and_seller_terminal_receipt_parameters_are_canonical() {
        assert_eq!(MIN_STREAM_BUY_TICKS, 2);
        assert_eq!(SELLER_TERMINAL_RECEIPT_TIMEOUT, Duration::from_secs(120));
        assert_eq!(
            SELLER_TERMINAL_RECEIPT_POLL_INTERVAL,
            Duration::from_secs(3)
        );
    }

    #[test]
    fn tick_size_and_platform_fee_have_one_canonical_value_source() {
        assert_eq!(u128::from(DobParams::canonical().tick_size), TICK_SIZE);
        assert_eq!(
            ProtocolConsts::canonical().platform_fee_bps,
            PLATFORM_FEE_BPS
        );

        let consumers = [
            ("chain/accounting.rs", include_str!("chain/accounting.rs")),
            ("lib.rs", include_str!("lib.rs")),
            ("shellnet/backends.rs", include_str!("shellnet/backends.rs")),
            ("shellnet/client.rs", include_str!("shellnet/client.rs")),
            (
                "shellnet/legacy_giver.rs",
                include_str!("shellnet/legacy_giver.rs"),
            ),
            ("shellnet/mod.rs", include_str!("shellnet/mod.rs")),
            (
                "dexdo/cli/admin.rs",
                include_str!("../../dexdo/src/cli/admin.rs"),
            ),
            (
                "dexdo/cli/commands.rs",
                include_str!("../../dexdo/src/cli/commands.rs"),
            ),
            (
                "dexdo/cli/support.rs",
                include_str!("../../dexdo/src/cli/support.rs"),
            ),
            (
                "dexdo/tests/live_cli.rs",
                include_str!("../../dexdo/tests/live_cli.rs"),
            ),
            (
                "ci/two_runner_shellnet_receipts.rs",
                include_str!("../../../ci/two_runner_shellnet_receipts.rs"),
            ),
        ];
        for legacy_alias in [
            concat!("MODEL_", "TICK_SIZE"),
            concat!("ORDERBOOK_", "FEE_BPS"),
        ] {
            for (path, source) in consumers {
                assert!(
                    !source.contains(legacy_alias),
                    "{path} must consume params.rs directly instead of {legacy_alias}"
                );
            }
        }
    }

    #[test]
    fn cli_runtime_parameters_have_exactly_one_source_owner() {
        let owner = include_str!("params.rs");
        let consumers = [
            ("shellnet/backends.rs", include_str!("shellnet/backends.rs")),
            (
                "dexdo/cli/commands.rs",
                include_str!("../../dexdo/src/cli/commands.rs"),
            ),
            (
                "dexdo/cli/buyer.rs",
                include_str!("../../dexdo/src/cli/buyer.rs"),
            ),
            (
                "dexdo/cli/seller.rs",
                include_str!("../../dexdo/src/cli/seller.rs"),
            ),
            (
                "dexdo/seller/mod.rs",
                include_str!("../../dexdo/src/seller/mod.rs"),
            ),
        ];
        let names = [
            "DEAL_WAIT_SECS",
            "RESUME_LOOKBACK_SECS",
            "TRANSIENT_QUOTE_ATTEMPTS",
            "TRANSIENT_QUOTE_INITIAL_BACKOFF",
            "EXECUTABLE_READ_BACKOFF",
            "POOL_LOCK_TIMEOUT_SECS",
            "POOL_LOCK_POLL_INTERVAL",
            "BUYER_MONITOR_POLL_INTERVAL",
            "BUYER_MONITOR_RECOVERY_BACKOFF",
            "RENEWAL_FAILURE_BACKOFF_SECS",
            "CONSUMER_DEMAND_RECENT_SECS",
            "BUYER_HANDOVER_POLL_INTERVAL",
            "POST_SELL_OFFER_SUBMIT_TIMEOUT",
            "OFFER_ACCEPTANCE_TIMEOUT",
            "SELLER_READ_BACKOFF",
            "DEFAULT_MATCH_POLL_INTERVAL",
            "SELLER_OPEN_STATE_READ_ATTEMPTS",
            "SELLER_OPEN_STATE_INITIAL_BACKOFF",
        ];

        for name in names {
            let declaration = format!("pub const {name}");
            assert_eq!(
                owner.matches(&declaration).count(),
                1,
                "params.rs must define {name} exactly once"
            );
            let local_declaration = format!("const {name}");
            for (path, source) in consumers {
                assert!(
                    !source.contains(&local_declaration),
                    "{path} must consume params::{name} directly instead of owning an alias"
                );
            }
        }

        let buyer = include_str!("../../dexdo/src/cli/buyer.rs");
        let buyer_production = buyer
            .split_once("#[cfg(test)]\nmod tests")
            .expect("buyer unit-test module boundary")
            .0;
        for literal in [
            "Duration::from_millis(500)",
            "Duration::from_secs(1)",
            "Duration::from_secs(30)",
            "\"poll_interval_ms\": 500",
        ] {
            assert!(
                !buyer_production.contains(literal),
                "buyer production policy must use params.rs instead of {literal}"
            );
        }

        let commands = include_str!("../../dexdo/src/cli/commands.rs");
        assert!(!commands.contains("Duration::from_millis(10)"));

        let seller = include_str!("../../dexdo/src/seller/mod.rs");
        let seller_production = seller
            .split_once("#[cfg(test)]\nmod tests")
            .expect("seller unit-test module boundary")
            .0;
        assert!(!seller_production.contains("Duration::from_secs(30)"));
        assert!(!seller_production.contains("Duration::from_millis(100)"));
    }
}
