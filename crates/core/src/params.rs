//! Protocol parameters. Fixed constants and order book deploy parameters.
//! These are pure types without networking. Values are taken from the spec.

use std::time::Duration;

/// SHELL -- the system's settlement unit. Integer count of minimal units.
pub type Shell = u64;

/// Canonical ECC currency id used by every dexdo market-money path.
pub const SHELL_CURRENCY_ID: u32 = 2;

/// Canonical CLI label for the market settlement currency.
pub const SHELL_CURRENCY_LABEL: &str = "shell";

/// The smallest SHELL figure `PrivateNote` will move between two notes, in raw ECC[2] units.
/// `initTransfer` requires `amount >= minStakeValue(tokenType)` and reverts `ERR_LOW_VALUE`(102)
/// below it; for SHELL that resolves to `MIN_VALUE_SHELL` in
/// `contracts/dex/modifiers/modifiers.sol`. Carried here as a constant rather than discovered by a
/// failed submit, because the refusal happens AFTER `tvm.accept()` -- a transfer sized under it does
/// not bounce off cheaply, it burns the sending note's gas to be told no. The value is checked
/// against the contract source by a regression rather than trusted.
pub const MIN_NOTE_TRANSFER_SHELL_RAW: u128 = 10_000_000;

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
/// The book reserves it at the BUY limit price and forwards it at the clearing price.
/// **The size is still 2; the SCOPE of this comment stopped being true at contracts 4.0.35.** It used
/// to end "Ordinary BUYs carry no buyer bond", and that sentence is now false about the chain:
/// `PrivateNote` posts `fundBuyerBond(2 * clearingPrice)` on EVERY buy fill, gated on `isBuy` and on
/// nothing else, and `TokenContract.fundBuyerBond` accepts it on any deal. An ordinary funded deal
/// therefore holds `2P`, and `getBuyerBond()` reports it as `(2P, 0)` -- held, with a required of zero,
/// because that getter's `bondRequired` is `_isSubscription() ? _bondAmount(): 0`.
/// The ordinary BUY preflight rule now lives in `chain::accounting::ordinary_buy_reserve`. It has
/// its own ordinary-named entry point while delegating to the same checked reserve implementation
/// and current two-tick value as subscriptions; a test pins their equality so any future policy
/// split must change that boundary explicitly.
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

/// Tail of `ProtocolConsts::claim_promote_window` an explicit buyer STOP must not spend, so the
/// POST reaches the chain while the last claim is still contested and stays unpaid. Submitting
/// later races the contract's own `_promoteDue`, which would promote that claim and pay it.
pub const STOP_SUBMIT_MARGIN: Duration = Duration::from_secs(20);

/// Maximum wait for the authoritative buyer-owned `StreamStopped` receipt.
pub const SELLER_TERMINAL_RECEIPT_TIMEOUT: Duration = Duration::from_secs(120);
/// Poll interval while the exact `StreamStopped` receipt is not yet visible.
pub const SELLER_TERMINAL_RECEIPT_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Maximum seconds the CLI waits for a buy to match into a `TokenContract`.
pub const DEAL_WAIT_SECS: u64 = 300;

/// Seconds a buyer waits for the seller to open a funded deal and write the handover.
/// The contract's window, not ours: a funded-but-unopened `TokenContract` stands for
/// [`MATCH_OPEN_TIMEOUT`] before anyone may `cleanupUnopened()` it, and until then the
/// seller may still legitimately open it. A buyer that gives up earlier settles a deal the market
/// still considers live, and pays the exit for a service it stopped waiting for.
pub const BUYER_HANDOVER_WAIT_SECS: u64 = MATCH_OPEN_TIMEOUT_SECS;

/// Seconds an on-demand purchase may take end to end: the match, and then the handover.
/// The sum, because they happen in sequence and each has its own budget. Bounding the pair by the
/// match's budget alone let the outer wait fire while the inner one still had time it had been
/// granted -- and how much it lost depended on how long the match had taken.
pub const BUYER_ON_DEMAND_PURCHASE_SECS: u64 = DEAL_WAIT_SECS + BUYER_HANDOVER_WAIT_SECS;

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

/// The exact phrase a buy refusal leads with when the only asks this buy crosses are past their
/// own deadline(E2E-ORD-02).
/// The operator must read "the counterparty's ask ran out", never "there is nothing here" -- a
/// higher `--max-price-per-tick` cannot help and only the seller reposting can. Every layer that
/// re-wraps the refusal keys its own classification off this one literal, so it lives here rather
/// than being spelled out again in each crate.
pub const EXPIRED_COUNTERPARTY_ASK_REASON: &str = "counterparty ask expired at";

/// Machine failure class carried by the refusal `EXPIRED_COUNTERPARTY_ASK_REASON` names.
/// Deliberately NOT `no_executable_ask`: that class means the book holds nothing this buy can
/// cross, and reporting it here would tell the operator to raise a ceiling that is already high
/// enough.
pub const EXPIRED_COUNTERPARTY_ASK_CLASS: &str = "expired_counterparty_ask";

/// Machine failure class for a book that holds no ask this buy can cross at all.
pub const NO_EXECUTABLE_ASK_CLASS: &str = "no_executable_ask";

/// Machine failure class for a model book with no resting ask in it whatsoever.
/// requires the buyer preflight to separate the four states a buy is refused in, because the
/// operator's next step differs in each. Split out of `NO_EXECUTABLE_ASK_CLASS`, which covers a
/// book that HAS rows this buy cannot cross -- there the answer is a higher ceiling or a cleanup;
/// here there is nothing to cross and only a seller posting an ask changes it.
pub const EMPTY_MODEL_BOOK_CLASS: &str = "empty_model_book";

/// The exact phrase a buy refusal leads with when the head ask this buy crosses is live, funded and
/// priced inside the ceiling, and only its SIZE is short of the requested ticks.
/// Both buy preflights produce it -- the model-only one and the explicit-TokenContract one -- and it
/// means the same thing on either, so every layer keys its own classification off this one literal
/// rather than spelling it out again.
pub const INSUFFICIENT_HEAD_ASK_REASON: &str = "refusing multi-ask fill:";

/// Machine failure class for a head ask this buy crosses that is smaller than the requested ticks.
/// Also split out of `NO_EXECUTABLE_ASK_CLASS` for: raising `--max-price-per-tick` does nothing
/// for it, and the step that works is fewer `--ticks` (shellnet submits only when the head ask alone
/// covers the request).
pub const INSUFFICIENT_HEAD_ASK_CLASS: &str = "insufficient_head_ask";

/// The exact phrase an empty-book refusal names the state with -- one literal, used by the producer
/// and by `book_refusal_class`, so a reworded message cannot silently demote the class back to the
/// generic no-match.
pub const EMPTY_MODEL_BOOK_REASON: &str = "no resting asks in this model book";

/// The wrapper the RAW side of the raw/executable cross-check leads with.
/// `EMPTY_MODEL_BOOK_REASON` is produced against whichever ask set was searched, and the executable
/// set can be empty while the raw book is full of rows -- that state is "nothing here is executable",
/// not "nothing is here", and it keeps the generic class. Only the raw side can report an empty
/// book, and it is the only side that carries this wrapper.
pub const RAW_MATCHER_NO_SUBMIT_SAFE_ASK: &str = "raw order-book matcher has no submit-safe ask";

/// The exact phrase the `executable-book` listing leads with when every row crossing this buy is
/// out of the book by its own deadline.
/// It is the listing surface's spelling of the state `EXPIRED_COUNTERPARTY_ASK_REASON` names on the
/// buy preflight, and `book_refusal_class` maps both onto `EXPIRED_COUNTERPARTY_ASK_CLASS` so the
/// two surfaces cannot answer differently for one book.
pub const LAPSED_MODEL_BOOK_REASON: &str = "no live asks in this model book";

/// Every phrase that names a book state this buy simply cannot cross, without saying which of the
/// states it is. Recognising them is what separates "the book refused this buy" from "the read
/// failed"; the arms above then decide which of the four classes it belongs to.
const GENERIC_NO_MATCH_REASONS: &[&str] = &[
    "no executable matching ask",
    "no submit-safe ask",
    "best ask price",
    "no resting asks",
    "no matchable ask",
    "raw order-book matcher",
    "refusing multi-ask fill",
];

/// The machine class an already-built refusal belongs to, or `None` when the text is not a book
/// state at all(a chain read that failed, a malformed manifest, anything else).
/// This is the ONE classifier every buy surface reads. `crossing_expired_ask_reason` is the only
/// producer that names an expiry, and it leads with `EXPIRED_COUNTERPARTY_ASK_REASON`; every wrapper
/// between it and the CLI carries the reason verbatim, so that one literal is what distinguishes
/// "the crossing ask ran out" from "this book has nothing to cross" after the two have been folded
/// into the same `String`. splits two more states out of the generic class the same way,
/// because each sends the operator somewhere else: an empty book is waited on, an undersized head is
/// bought smaller, and only what is left over is the "rows exist, none of them are usable" case
/// `NO_EXECUTABLE_ASK_CLASS` names.
/// `dexdo executable-book` reads the same verdict from here rather than hardcoding the
/// generic class into its line. Two classifiers that must agree are the defect, not the fix -- the
/// buyer preflight and the listing describe the same book at the same ceiling, so they answer from
/// one function.
pub fn book_refusal_class(reason: &str) -> Option<&'static str> {
    let reason = reason.to_ascii_lowercase();
    if reason.contains(EXPIRED_COUNTERPARTY_ASK_REASON) || reason.contains(LAPSED_MODEL_BOOK_REASON)
    {
        Some(EXPIRED_COUNTERPARTY_ASK_CLASS)
    } else if reason.contains(INSUFFICIENT_HEAD_ASK_REASON) {
        Some(INSUFFICIENT_HEAD_ASK_CLASS)
    } else if reason.contains(EMPTY_MODEL_BOOK_REASON)
        && reason.contains(RAW_MATCHER_NO_SUBMIT_SAFE_ASK)
    {
        Some(EMPTY_MODEL_BOOK_CLASS)
    } else if GENERIC_NO_MATCH_REASONS
        .iter()
        .any(|phrase| reason.contains(phrase))
    {
        Some(NO_EXECUTABLE_ASK_CLASS)
    } else {
        None
    }
}

/// The class a refusal that is already known to be one is reported under.
/// Callers that reached this from a selection failure know the text names a book state even when no
/// literal above matched it, so an unrecognised phrase stays the generic class rather than being
/// dropped.
pub fn buy_refusal_class(reason: &str) -> &'static str {
    book_refusal_class(reason).unwrap_or(NO_EXECUTABLE_ASK_CLASS)
}

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

/// Default minimum reference-prefix agreement accepted by a buyer spot-check.
/// calibrated against measurement, not against an assumed determinism. A provider does NOT
/// promise a byte-identical greedy generation: with an identical body (`temperature=0`, `seed=0`,
/// `max_tokens` = [`CONTENT_PROBE_MAX_TOKENS`]) the same Groq model returns one of a small set of
/// outputs that share a long opening and then branch. Measured on the real
/// [`DEFAULT_SPOTCHECK_PROBE`] over 62 greedy runs of 5 models: an HONEST seller (the same model on
/// both legs) scored as low as **0.41** (`qwen/qwen3-32b`, branching at word 21 of 51;
/// `llama-3.3-70b` 0.53), and 6 of those 62 runs landed under the old `0.7` -- i.e. the old value was
/// unreachable by construction and refused honest sellers. A SUBSTITUTING seller (6 different models
/// answering the same probe) never exceeded **0.02**, branching at word 0 or 1. The threshold sits
/// between the two measured populations: 12x above the substitution ceiling, below the honest floor.
pub const DEFAULT_SPOTCHECK_THRESHOLD: f64 = 0.25;

/// Default deterministic prompt used for buyer reference spot-checks.
pub const DEFAULT_SPOTCHECK_PROBE: &str = "What is 17 times 23? Show your step-by-step reasoning.";

/// Prompt used to prove that a configured seller upstream is ready.
pub const UPSTREAM_HEALTH_PROBE_PROMPT: &str = "Reply with OK.";

/// Token budget for one seller upstream readiness probe.
/// - why this is NOT 1. A reasoning model spends its budget inside the reasoning channel
/// before it emits anything, so a one-token probe buys a stream that carries a positive terminal
/// `usage.completion_tokens` and NOT ONE delta of any kind. Measured live on 2026-08-12,
/// `openai/gpt-oss-20b` at `max_tokens: 1` with this exact prompt: four frames, `content` present
/// once and empty, `reasoning` absent entirely, `completion_tokens = 1`. The seller then reads
/// "billed without delivery"(UPS-28), readiness fails, and the whole `gpt-oss` family becomes
/// unsellable -- with no offer ever posted.
/// The refusal it tripped is correct and stays: a provider that bills without delivering must be
/// refused. What was wrong is the QUESTION -- "can you deliver?" asked in one token of a model that
/// thinks first is unanswerable, and the answer was read as a provider fault. The same capture at
/// `max_tokens: 16` carries thirteen `reasoning` deltas that the adapter consumes and bills
/// normally, so the budget only has to be large enough for a thinking model to say something.
/// It is the buyer's canonical content-probe budget, not a new number: both ask a provider to prove
/// it can produce output, and one probe of this size is negligible next to the seller's own traffic.
pub const UPSTREAM_HEALTH_PROBE_MAX_TOKENS: u32 = CONTENT_PROBE_MAX_TOKENS as u32;

/// Prompt used to prove a DECLARED capability(`--tools`), as distinct from readiness.
/// Two questions, two prompts. [`UPSTREAM_HEALTH_PROBE_PROMPT`] asks "can you deliver at all?";
/// this one asks "can you call a tool?".
/// # Why the readiness prompt cannot ask this question
/// The reason is not a model list and not a provider. A capability probe forces the call through
/// `tool_choice`, so sending "Reply with OK." **makes the request contradict itself**: the prompt
/// instructs the model to answer in text while `tool_choice` requires it to answer with a tool
/// call. Only one of those can be obeyed. Which one a given model picks is its own business -- what
/// is ours is that we asked for both, and a self-contradictory request has no correct answer on any
/// provider, present or future. Nothing about this argument is specific to a vendor, and it is the
/// one part of that will still be true when every model in the table below is retired.
/// A provider that resolves the contradiction in the prompt's favour then reports the model's own
/// refusal, which reads as "this model cannot use tools" and is really "we asked it not to".
/// # Evidence(a snapshot, not the reason)
/// Groq, 2026-08-12, `tools` + a forced `tool_choice` naming the probe tool, one variable changed
/// at a time, every other byte of the request identical. These figures date; the argument above
/// does not.
/// | model | "Reply with OK." | this prompt |
/// |---|---|---|
/// | `openai/gpt-oss-20b` | no | CALLS |
/// | `openai/gpt-oss-120b` | no | CALLS |
/// | `qwen/qwen3-32b` | no | CALLS |
/// | `qwen/qwen3.6-27b` | no | CALLS |
/// | `llama-3.3-70b-versatile` | CALLS | CALLS |
/// | `llama-3.1-8b-instant` | CALLS | CALLS |
/// The contradiction is visible in the transcript: `openai/gpt-oss-20b` streamed
/// `reasoning: 'The user says: "Reply with OK." So we just reply "OK".'` then `content: 'OK'`,
/// after which Groq closed the stream with
/// `"Tool choice is required, but model did not call a tool"`. The model read our prompt, obeyed
/// it, and was reported as incapable for doing so.
/// That run also killed the two rival explanations: the `tools`/`tool_choice` JSON is byte-identical
/// between the failing and passing cells, and every model honours a forced `tool_choice` once asked
/// coherently. It was our request.
/// # Only for a probe that actually OFFERS the tool
/// `tools`/`tool_choice` are built from `requirements.tools` alone, so a `--think`-only market
/// sends a body with no tool in it. Asking THAT body to call a tool is the same self-contradiction
/// in the other direction -- naming a tool the request does not carry -- so that branch keeps
/// [`UPSTREAM_HEALTH_PROBE_PROMPT`]. See `seller::upstream::UpstreamConfig::probe`.
/// **The wording is an existence proof, not a tuned choice.** It is the first coherent prompt that
/// worked; no prompt search was run, and a shorter or clearer one may serve as well. What must be
/// preserved is the coherence, not the sentence.
pub const CAPABILITY_PROBE_PROMPT: &str = "Call the dexdo_capability_probe tool with an empty object.";

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
/// Generic. A per-deal `TokenContract` is held to its OWN floor([`deal_gas_health_floor_raw`]),
/// because a deal's gas need follows from its `maxTicks` and a flat floor closes the cheap end of
/// the market while under-funding the expensive end.
pub const ACTIVE_CONTRACT_GAS_HEALTH_MIN_NANOVMSHELL: u128 = 5_000_000_000;

/// Active-contract balance targeted by a gas top-up, in nanovmshell.
/// Generic. A per-deal `TokenContract` is topped up to [`deal_gas_health_target_raw`] instead.
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

/// Attempts for one chain READ that got no answer: a dropped connection, a server that failed
/// before answering, or a rate limit. Submits have their own budget above; this is the read side.
pub const TRANSIENT_READ_ATTEMPTS: usize = 5;

/// Initial delay after a chain read that got no answer.
pub const TRANSIENT_READ_INITIAL_BACKOFF: Duration = Duration::from_millis(500);

/// Maximum delay between chain read attempts.
pub const TRANSIENT_READ_MAX_BACKOFF: Duration = Duration::from_secs(8);

/// Total wall-clock budget for one chain read including every retry. Without it a server that
/// accepts and never answers keeps the first attempt alive forever and the second never happens.
pub const TRANSIENT_READ_TOTAL_BUDGET: Duration = Duration::from_secs(45);

/// Per-attempt ceiling for one chain read. The pinned SDK builds its HTTP client with no timeout
/// of its own, so the bound has to be applied here or nowhere.
pub const TRANSIENT_READ_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(20);

/// Longest `Retry-After` a rate-limited read will honour before giving up instead of sleeping.
/// Waiting what the server asked for is the point; waiting an hour inside one command is not.
pub const TRANSIENT_READ_MAX_RETRY_AFTER: Duration = Duration::from_secs(30);

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

/// Maximum PrivateNote state reads used to confirm a PMP cancel/claim callback.
pub const PMP_EXIT_CONFIRM_MAX_READS: usize = 30;

/// Interval between PrivateNote state reads while confirming a PMP cancel/claim callback.
pub const PMP_EXIT_CONFIRM_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Maximum Oracle account reads used to confirm an owner fee withdrawal.
pub const ORACLE_FEE_WITHDRAW_CONFIRM_MAX_READS: usize = 20;

/// Interval between Oracle account reads while confirming an owner fee withdrawal.
pub const ORACLE_FEE_WITHDRAW_CONFIRM_POLL_INTERVAL: Duration = Duration::from_secs(2);

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

/// Maximum reads used to confirm that a deal contract is GONE -- the account no longer answers
/// `getState` because `selfdestruct` took it. Distinct from the cleanup-unopened confirm
/// above, whose predicate(`!funded`) is already true for a deal that was never sold and therefore
/// proves nothing about a destruct.
pub const DEAL_DESTROY_CONFIRM_MAX_READS: usize = 40;

/// Interval between deal-destruct confirmation reads.
pub const DEAL_DESTROY_CONFIRM_POLL_INTERVAL: Duration = Duration::from_secs(3);

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

/// Default bound on waiting for a Vault -> Hot top-up to become visible in the Hot's on-chain
/// balances. The wallet specification fixes this default at ten minutes and makes
/// `--funding-timeout <duration>` the only way to change it.
/// This bounds the WAIT and nothing else. Crossing it is a local fact, so it never closes a funding
/// journal record and never cancels a Vault transaction the user may still confirm: the operator is
/// told what is pending and re-runs the same command.
pub const HOT_FUNDING_TIMEOUT: Duration = Duration::from_secs(600);

/// How often the Hot-funding wait re-reads the Hot's on-chain balances, matching the five-second
/// cadence the wallet specification already fixes for waiting on a Hot to come up.
pub const HOT_FUNDING_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum local wait for another process holding the same Hot, in seconds.
/// Deliberately the SAME value as the incumbent per-wallet note-deploy lock rather than a second
/// number: both serialize spends of one wallet, and when the two locks are unified there must be
/// nothing to reconcile.
pub const HOT_FUNDING_LOCK_TIMEOUT_SECS: u64 = NOTE_DEPLOY_LOCK_TIMEOUT_SECS;

/// Interval between Hot-lock acquisition attempts - the incumbent wallet-lock cadence, for the same
/// reason.
pub const HOT_FUNDING_LOCK_POLL_INTERVAL: Duration = NOTE_DEPLOY_WALLET_LOCK_POLL_INTERVAL;

/// Raw native value attached to a note-deploy multisig voucher submit.
/// A non-zero value is mandatory and is not a matter of taste: `RootPN.generateVoucher` places
/// `tvm.accept()` AFTER its guards(`contracts/dex/RootPN.sol`), so everything up to that point is
/// paid for by the incoming message and a zero-value call dies before reaching any check.
/// The SIZE is the protocol's own call value into the RootPN dapp, taken from the contracts rather
/// than measured by us. Every in-protocol sender that calls a RootPN entry attaches `0.1 vmshell`,
/// most directly `OrderBook` on `RootPN.collectProtocolFee`(`contracts/dex/OrderBook.sol`), and the
/// same figure carries the `PrivateNote` callbacks and the sends in `PMP`, `Nullifier` and
/// `OracleEventList`. One vmshell is 1_000_000_000 raw native units, so `0.1 vmshell` is the value
/// below. This is deliberately NOT a number derived from a receipt: pricing gas from one
/// observation reintroduces the attached value on both sides of the division, which is how the
/// previous derivation ended up denominated in the very 2 VMSHELL literal it replaced.
/// The citation bounds the value rather than merely matching a habit, because `collectProtocolFee`
/// is the HARDER of the two calls. It carries `senderIs(...)` above its `accept`, and that guard is
/// a three-code-cell address derivation billed entirely to the incoming message -- funded, by the
/// protocol itself, out of this same `0.1 vmshell`. `generateVoucher` charges its caller strictly
/// less before its own accept: parse the currency map, compare the type, compare against
/// `GAS_DEPOSIT`, one subtraction and one `> 0` require. Nothing on that path derives an address.
/// The margin is named by the contracts too. `DAPP_MSG_VALUE`
/// (`contracts/airegistry/TokenContract.sol`) is `0.01 vmshell`, the smallest value anything in this
/// protocol attaches to an internal call; the 4.0.34 work records that at that value a pre-accept
/// derivation "did not always reach the guard" and moved the accepts to compensate. This
/// constant is ten times that floor.
/// 4.0.34 therefore confirms the figure instead of moving it: it swaps `accept` ABOVE the `senderIs`
/// guards on `collectProtocolFee` and `reportDealWriteOff`, which only reduces the caller-funded
/// part of those entries, and it leaves `generateVoucher` untouched. The same value is at least as
/// sufficient on 4.0.34 as on 4.0.33.
/// Both note-deploy legs -- the deposit voucher(`isFee=false`, SHELL nominal + `GAS_DEPOSIT`) and
/// the gas voucher(`isFee=true`) -- are single-currency SHELL sends, so both take the one-leg branch
/// and differ only by its compare-and-subtract. That is why this is ONE value and not two.
pub const NOTE_DEPLOY_SUBMIT_NATIVE_VALUE: u128 = 100_000_000;

/// Native gas consumed by one accumulator wallet outgoing operation, measured from the mainnet
/// operator-wallet receipt reviewed for.
pub const ACCUMULATOR_WALLET_MESSAGE_GAS_RAW: u128 = 16_888_658;

/// Raw NATIVE balance the canonical operator wallet must hold before `note wallet` submits its
/// state-init -- stage ONE of the funding recipe, and a FLAT figure no nominal moves.
/// SHELL sent to an uninit address with the non-bounceable `flag: 16` form becomes that account's
/// NATIVE vmshell and never its ECC[2]: read the account back on-chain with `balance` in full
/// and `balance_other[2]` present and zero. Native vmshell is GAS -- it can never be spent as
/// currency again -- so every raw unit this figure asks for is money the user converts into gas
/// permanently, and on mainnet that conversion is not reversible. This is therefore sized to what
/// deploying the wallet actually costs and to nothing else.
/// It used to be `nominal + GAS_DEPOSIT`: 350 SHELL on N100 and 1_000_250 SHELL on N1000000. The
/// nominal has no bearing on it. The state-init this balance pays for is built with
/// `value: 0, minBalance: 0, targetBalance: 0` and never mentions the nominal
/// (`shellnet::operator_wallet::prepare_operational_multisig_deploy`), so the old figure burned a
/// nominal-sized amount of real money into gas forever for no chain reason.
/// # The measurement
/// Live shellnet, 2026-08-12, from `crates/dexdo/tests/live_cli.rs`. Two fresh addresses funded by
/// two different routes, each read immediately before and immediately after its deploy, with the
/// test asserting that exactly ONE transaction separates the two reads:
/// | test | Uninit before | Active after | delta |
/// |-----------------------------------------------------------|------------------:|------------------:|-------------:|
/// | `live_1173_operator_wallet_funds_from_an_ordinary_wallet` | 1_250_000_000_000 | 1_249_846_499_000 | 153_501_000 |
/// | `live_961_operator_wallet_deploys_after_external_funding` | 1_250_000_000_000 | 1_249_846_499_000 | 153_501_000 |
/// One canonical operator-wallet deploy costs `153_501_000` raw -- `0.153501 vmshell` -- and the two
/// runs agree to the raw unit.
/// That reading counts a second way, against a figure this repository already recorded from an
/// earlier proof. `.claude/skills/dexdo-sell-model/SKILL.md` states that "deploying from a 1,250
/// SHELL predeploy balance consumed `156 222 000` raw native". Both runs above continue past the
/// deploy to the first inbound ECC[2] transfer and read `1_249_843_778_000`, so that transfer cost
/// `2_721_000`, and `153_501_000 + 2_721_000 = 156_222_000` exactly. The recorded figure is the
/// deploy PLUS the first inbound message, measured before an intermediate read existed to separate
/// them; it decomposes into these two to the raw unit. The deploy alone is the smaller half.
/// # The budget this covers
/// A wallet that deploys and then cannot send is useless, so the figure also carries the sends
/// `note deploy` makes FROM this wallet. There are exactly two -- the deposit voucher
/// (`isFee = false`) and the SHELL gas voucher(`isFee = true`), both built by
/// `note_cmd::note_deploy_build_voucher_submit_boc` -- and each costs the wallet two things:
/// - the value it ATTACHES, [`NOTE_DEPLOY_SUBMIT_NATIVE_VALUE`], which is native and leaves the
/// wallet: `2 * 100_000_000 = 200_000_000`;
/// - the fee its own transaction charges. That is bounded above by the deploy measured here: a
/// `submitTransaction` installs no state-init, runs no constructor and grows no code cell, so it
/// cannot cost more than the one transaction that does all three. `2 * 153_501_000 = 307_002_000`.
/// puts real compute at about `0.07 vmshell` per operation from receipts, so this
/// bound is roughly 2.2x the project's own measured per-operation rate.
/// `153_501_000 + 200_000_000 + 307_002_000 = 660_503_000` raw. This constant is the next whole
/// vmshell above that budget -- a 1.51x margin on it, and 6.5x the deploy alone.
/// What it does NOT claim to cover is storage rent across a long idle life. The only reading that
/// contains any rent is the `2_721_000` raw above, and its two wallets were nine seconds old, so it
/// cannot be split into rent and message processing. A wallet left idle for months may need topping
/// up before it can send again, and `note wallet` reports that shortfall by fact rather than
/// pre-paying for it here.
pub const OPERATOR_WALLET_PREDEPLOY_NATIVE_VALUE: u128 = 1_000_000_000;

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

/// Maximum wait for ONE note-deploy halo2 voucher proof, its layer-boundary chain wait included.
/// The proof is CPU-bound; the history layer it proves against is WALL-CLOCK. Layer 0 spans
/// `W = 128` blocks, about two minutes of chain, and once the chain has moved past that boundary the
/// layer-0 witness can no longer be exported -- the prover falls through to layer 1, whose boundary is
/// `W^2 = 16384` blocks away. Measured on one machine minting a pool with the shipped CLI:
/// | conditions | proof time | outcome |
/// |-------------------------------------|-----------:|--------------------------------|
/// | one deploy at a time | 104 s | lands at layer 0 |
/// | three concurrent, separate caches | 157 s | window missed, falls to layer 1|
/// The layer-1 target measured there was +10366 blocks, roughly 54 minutes of waiting for a single
/// note against about 4 on the layer-0 path -- and the SDK waits for it without printing a verdict.
/// This bound sits between the two: about four times the slowest measured honest proof, and far
/// short of any layer-1 boundary wait. Crossing it is not a transport hiccup -- it means the layer-0
/// window is gone and the attempt has become the expensive one, which is the moment the operator has
/// a choice to make and must be told. Raise it with `DEXDO_NOTE_DEPLOY_PROOF_TIMEOUT_SECS`, or set
/// that to `0` to wait however long the escalated layer takes.
pub const NOTE_DEPLOY_PROOF_TIMEOUT: Duration = Duration::from_secs(600);

/// Read-buffer size used while hashing the pinned Hermez SRS.
pub const HERMEZ_SRS_HASH_BUFFER_BYTES: usize = 64 * 1_024;

/// Minimum percentage-point advance between Hermez SRS progress reports.
pub const HERMEZ_SRS_PROGRESS_STEP_PERCENT: u64 = 5;

/// HTTP timeout for one Hermez SRS download request.
pub const HERMEZ_SRS_HTTP_TIMEOUT: Duration = Duration::from_secs(120);

/// One SHELL in raw ECC[2] units, and one vmshell in raw native units -- both are `1e9`.
/// The two are the same number here because `PrivateNote.fundDeployShell` moves ECC[2] under flag:16
/// and the deal receives it as native gas one-for-one. That is what lets a SHELL deposit be compared
/// against a vmshell requirement at all.
pub const SHELL_UNIT: u128 = 1_000_000_000;

// ---------------------------------------------------------------------------
// Shell Accumulator - SHELL <-> eccUSDC exchange, contract v1.0.2.
// Every constant below mirrors a `constant` in the deployed accumulator, and is carried here rather
// than discovered by a failed submit: the sell path validates AFTER `tvm.accept()`, so a wrongly
// sized deposit does not bounce off cheaply. Citations are to
// `contracts/accumulator/modifiers/modifiers.sol` in `ackinacki/ackinacki` at contract version
// 1.0.2, cross-checked against the live roots on both networks by `getVersion()`.
// ---------------------------------------------------------------------------

/// ECC currency id of eccUSDC(`USDC_ECC_ID`, modifiers.sol:20).
/// Distinct from [`SHELL_CURRENCY_ID`] in id AND in scale: eccUSDC carries SIX decimals against
/// SHELL's nine, so the two raw figures are never interchangeable. Established from the chain, not
/// assumed: the live roots hold this currency in `balance_other`, and the official shellnet faucet
/// table publishes `ecc` key 3 / decimals 6.
pub const USDC_CURRENCY_ID: u32 = 3;

/// Canonical CLI label for eccUSDC.
pub const USDC_CURRENCY_LABEL: &str = "usdc";

/// One whole eccUSDC in raw micro-units(`USDC_DECIMALS_FACTOR`, modifiers.sol:10).
/// A buy is refused unless it is a whole multiple of this(`ERR_NOT_WHOLE_USDC`, 203).
pub const USDC_UNIT: u128 = 1_000_000;

/// Raw ECC[2] SHELL that buys exactly one whole eccUSDC(`SHELL_PER_USDC`, modifiers.sol:9).
/// The accumulator's rate is this constant and nothing else - no oracle, no curve, no spread, and
/// the same figure in both directions. 100 SHELL = 1 eccUSDC.
pub const ACCUMULATOR_SHELL_PER_USDC_RAW: u128 = 100 * SHELL_UNIT;

/// The only sell-lot sizes the accumulator will accept, in whole eccUSDC, largest first
/// (`DENOM_1000`/`DENOM_100`/`DENOM_10`/`DENOM_1`, modifiers.sol:12-15).
/// Ordered largest-first because that is both the contract's own matching order and the order that
/// decomposes a balance into the fewest lots. There are no partial lots: an amount that is a whole
/// number of eccUSDC but not one of these four is refused outright(`ERR_INVALID_DENOM`, 200)
/// rather than split, so the client does the splitting.
pub const ACCUMULATOR_DENOMS: [u16; 4] = [1000, 100, 10, 1];

/// Fixed zerostate address of `ShellAccumulatorRootUSDC`, identical on every Acki Nacki network.
/// This is not a deployment choice we could re-point: the root is premined into the zerostate
/// (`contracts/scripts/generate_zerostate.py` `ACCUMULATOR_ROOT_ADDRESS`) and the Exchange/USDCBridge
/// contracts hard-code the same literal (`contracts/exchange/modifiers/modifiers.sol`
/// `ACCUMULATOR_ADDRESS`), so it cannot move without a new network. Read back Active at this address
/// on both shellnet and mainnet.
pub const ACCUMULATOR_ROOT_ADDRESS: &str =
    "0:3535353535353535353535353535353535353535353535353535353535353535";

/// DApp id the accumulator root and its lots live in.
/// Asked of the chain rather than inferred from which shard answered: the root reports
/// `info.dapp_id == 0x..01` on both networks even when queried through another shard. The reference
/// off-chain client calls the same DApp `SystemDapp::MobileVerifiers`. Reads against any other DApp
/// return null, so this id is required to see the account at all.
pub const ACCUMULATOR_DAPP_ID: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";

/// `getVersion()` pair the accumulator root must answer before this client will spend into it.
/// A version string does not identify a build - the two live roots share "1.0.2" while serving
/// DIFFERENT code hashes - so this is a fail-closed identity floor, not a build pin: it proves the
/// address really is an accumulator root of the generation whose ABI we carry.
pub const ACCUMULATOR_ROOT_VERSION: (&str, &str) = ("1.0.2", "ShellAccumulatorRootUSDC");

/// `getVersion()` pair a `ShellSellOrderLot` must answer before this client will claim from it.
pub const ACCUMULATOR_LOT_VERSION: (&str, &str) = ("1.0.2", "ShellSellOrderLot");

/// A raw gas measurement together with the network on which receipts established it.
/// Keeping the fields in one named constant prevents the measured value from losing its provenance.
/// Callers that select the default must compare [`Self::network`] with their runtime network first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkMeasuredRaw {
    /// Measured raw nanovmshell value.
    pub value: u128,
    /// Deployment-manifest network label on which the value was measured.
    pub network: &'static str,
}

// Preserve the existing inline arithmetic/diagnostic invariants without making bare measurement
// arithmetic part of the production API.
#[cfg(test)]
impl std::fmt::Display for NetworkMeasuredRaw {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(formatter)
    }
}

#[cfg(test)]
impl std::ops::Add<u128> for NetworkMeasuredRaw {
    type Output = u128;

    fn add(self, other: u128) -> Self::Output {
        self.value + other
    }
}

/// Raw nanovmshell one per-deal `TokenContract` spends on its own compute and message fees over a
/// whole life, EXCLUDING both the claims and the `value:` it attaches to its outgoing calls.
/// The published 4.0.34 lifetime budget is `0.215` for everything except the claims (,
/// @SeHor05): deployment `0.100`, close `0.045`, `postFromNote` `0.025`, `fundFromOrderBook` `0.020`,
/// probe acceptance `0.015`, open `0.015`, `fundDeal` `0.010` and the `registerTokenContract` leg
/// `0.005` -- eleven transactions measured at `0.23684` in total. Of that, the deal's eight outgoing
/// sends carry `0.08` in attached value, and the CONTRACT declares those. What is left --
/// `0.215 - 0.08` -- is the part only a measurement can supply, and it is the one figure here taken
/// on trust. Deployment dominates it and is not compute: `19_462` gas against `97` million of fee,
/// because an external message carrying the whole code pays for its SIZE. A deal is expensive to be
/// born and cheap for the rest of its life.
/// Splitting the budget this way is what keeps it honest across generations: the attached values are
/// read back off the vendored source in [`DEAL_GAS_FIXED_RAW`], so when the contracts change what
/// they attach, the requirement changes with them instead of quietly describing a generation that is
/// no longer there. The fixed total was subsequently confirmed on live shellnet 4.0.35, so
/// the measured remainder and its `shellnet` provenance stay together below.
pub const DEAL_GAS_OVERHEAD_RAW: NetworkMeasuredRaw = NetworkMeasuredRaw {
    value: 135_000_000,
    network: "shellnet",
};

/// Select the measured remainder for `network`, or accept an operator's measurement verbatim.
/// Only the absence of an override consults [`DEAL_GAS_OVERHEAD_RAW`]. A supplied value is not
/// compared with or clamped to the shellnet measurement: the operator is asserting that it came
/// from the runtime network's receipts.
pub fn resolve_deal_gas_overhead_raw(
    network: &str,
    supplied_raw: Option<u128>,
) -> Result<u128, String> {
    if let Some(supplied_raw) = supplied_raw {
        return Ok(supplied_raw);
    }
    if network == DEAL_GAS_OVERHEAD_RAW.network {
        return Ok(DEAL_GAS_OVERHEAD_RAW.value);
    }
    Err(format!(
        "refusing to fund a deal: DEAL_GAS_OVERHEAD_RAW was measured on network `{}`, but the client is on network `{network}`. Proceeding blind can leave a TokenContract stalled permanently with both bonds inside. Supply --deal-gas-overhead-raw only after measuring this network",
        DEAL_GAS_OVERHEAD_RAW.network,
    ))
}

/// Raw nanovmshell one per-deal `TokenContract` spends on everything that is NOT a consumption
/// claim: [`DEAL_GAS_OVERHEAD_RAW`] plus the `value:` its own source declares on its outgoing calls.
/// **DERIVED FROM THE VENDORED SOURCE, NOT COPIED FROM A MEASUREMENT.** The deal declares eight
/// outgoing sends and this tree's `contracts/airegistry/TokenContract.sol` attaches
/// `DAPP_MSG_VALUE = 0.01 vmshell` to every one of them -- `registerTokenContract`, the two
/// `onDealClosed` legs, `creditFromDeal`, `reportFinalized`, `placeSellOffer` and the two remaining
/// sends. So what a deal hands out before a single claim is
/// ```text
/// 8 sends x DAPP_MSG_VALUE = 8 x 0.01 vmshell = 8 x 10_000_000 raw = 80_000_000 raw
/// DEAL_GAS_OVERHEAD_RAW = 135_000_000 raw
/// ------------
/// DEAL_GAS_FIXED_RAW = 215_000_000 raw
/// ```
/// which is the published 4.0.34 fixed part of `0.215` exactly -- not because that figure was copied
/// here, but because the sends this source declares are the sends that figure assumes. The overhead
/// term is the one measured input and it stays attributable: it is `0.215` MINUS those eight sends,
/// and `deal_gas_fixed_matches_the_values_this_tree_s_deal_declares` states that equality too.
/// **THIS FIGURE WAS WRONG UNTIL THE TEST SAID SO.** It stood at `2_195_000_000` -- the 4.0.33 shape,
/// where `reportFinalized` and `placeSellOffer` still attached `1 vmshell` and the outgoing alone
/// came to `2.06`. That was the right value for the source this branch was cut against, and
/// it stopped being right the moment dev re-vendored the real 4.0.34 contracts underneath it. No
/// version string could have caught that: the manifest read `4.0.34` on both sides of the change.
/// The test below did, on the first run after the merge, exactly as its own comment promised -- "the
/// re-vendor cannot land without moving the funding figure with it". The tripwire fired; this is the
/// figure it was holding out for, and the funding requirement moved with the contracts as designed.
pub const DEAL_GAS_FIXED_RAW: u128 = 215_000_000;

/// Raw nanovmshell the FIRST `claimTokens` costs.
/// The first claim is measurably cheaper than every later one -- `0.00790` against `0.01435` -- and is
/// the only one that emits no outgoing message. This is a step with a shelf, not a curve: from the
/// second claim on the price sits at [`DEAL_GAS_CLAIM_RAW`] and stays there (three consecutive
/// claims, three percent spread). The plausible reading that each claim costs more because it
/// promotes its predecessor was measured and did not hold.
pub const DEAL_GAS_FIRST_CLAIM_RAW: u128 = 10_000_000;

/// Raw nanovmshell every `claimTokens` after the first costs.
pub const DEAL_GAS_CLAIM_RAW: u128 = 15_000_000;

/// Raw nanovmshell a deal of `max_ticks` ticks needs for its whole life.
/// **THE COUNT OF CLAIMS IS NOT A POLICY -- IT IS A CEILING IN THE CONTRACT.**
/// `TokenContract.claimTokens` requires `delta <= MAX_CLAIM_DELTA`, and
/// `MAX_CLAIM_DELTA = TICK_SIZE`(`contracts/airegistry/TokenContract.sol`), so one call advances at
/// most one tick and a deal of `max_ticks` ticks takes `max_ticks` calls. There is nothing to batch:
/// a longer silence is claimed as a SEQUENCE, not as one larger claim.
/// **THE DEAL PAYS, NOT THE SELLER.** `claimTokens` is declared
/// `onlyOwnerPubkey(_sellerPubkey) accept` -- the `accept` is in the modifier list, so it runs before
/// the body and the compute is billed to the contract's own balance. The seller only signs. That is
/// why volume converts directly into the deal's gas budget.
/// **AND THE DEAL CANNOT REFILL ITSELF.** It is the one contract in this tree deployed by an external
/// message into its own dapp, which has no config, so `gosh.mintshellq` has nothing to draw on.
/// Under-funding here is not "more expensive" -- it is a permanent stop with the bond inside.
/// Absolute figures carry network provenance. What transfers between networks is the SHAPE -- the
/// shares between calls, "the first claim is cheaper, then a shelf", linearity in volume with a tick
/// as the step -- not the numbers. [`resolve_deal_gas_overhead_raw`] refuses to reuse the
/// measured remainder on a different runtime network without an operator-supplied measurement.
pub fn deal_gas_requirement_raw_with_overhead(
    max_ticks: u128,
    deal_gas_overhead_raw: u128,
) -> u128 {
    // A deal below two ticks cannot exist (`require(maxTicks >= 2)` in the ctor), but the arithmetic
    // must not underflow for a caller that has not validated yet.
    let claims = max_ticks.max(1);
    let contract_declared_raw = DEAL_GAS_FIXED_RAW.saturating_sub(DEAL_GAS_OVERHEAD_RAW.value);
    contract_declared_raw
        .saturating_add(deal_gas_overhead_raw)
        .saturating_add(DEAL_GAS_FIRST_CLAIM_RAW)
        .saturating_add(DEAL_GAS_CLAIM_RAW.saturating_mul(claims - 1))
}

/// Raw nanovmshell needed by a shellnet deal using the receipt-backed default measurement.
pub fn deal_gas_requirement_raw(max_ticks: u128) -> u128 {
    deal_gas_requirement_raw_with_overhead(max_ticks, DEAL_GAS_OVERHEAD_RAW.value)
}

/// Minimum whole-SHELL funding accepted for the one contract the note funds, **for THIS deal**.
/// This used to be a flat `10`, and a flat floor prices a market out of existence rather than merely
/// wasting a little: a deal of eight ticks at one SHELL each is worth eight SHELL in total, so a
/// ten-SHELL floor means no seller can list a model that cheap however good it is or however much
/// demand there is. Nobody chose that floor; it was the residue of a term that no longer
/// exists -- the justification was `REGISTER_FORWARD_VALUE = 5 vmshell` for the deal's registration
/// message, and the `TokenContract` sends that message with `DAPP_MSG_VALUE = 0.01 vmshell`.
/// The floor is now [`deal_gas_requirement_raw`] rounded UP to the whole SHELL that
/// `--deposit-shells` is denominated in. The rounding is the entire margin and it is not a number
/// anyone picked -- the CLI unit forces it.
/// It moves the floor in BOTH directions against the old constant, and the direction it raises is the
/// dangerous one: a deal of a thousand ticks needs more than ten and the flat `10` under-funded it.
pub fn min_deploy_shells(max_ticks: u128) -> u128 {
    min_deploy_shells_with_overhead(max_ticks, DEAL_GAS_OVERHEAD_RAW.value)
}

/// Minimum whole-SHELL funding for a deal using the selected measured remainder.
pub fn min_deploy_shells_with_overhead(max_ticks: u128, deal_gas_overhead_raw: u128) -> u128 {
    deal_gas_requirement_raw_with_overhead(max_ticks, deal_gas_overhead_raw)
        .div_ceil(SHELL_UNIT)
        .max(1)
}

/// Default whole-SHELL allocation for the one contract the note still funds, for THIS deal.
/// **ONE DEPLOY SINCE 4.0.34, NOT TWO.** This was `2 x MIN_DEPLOY_SHELLS`, split evenly between the
/// `RootModel` and the per-deal `TokenContract`. `SuperRoot` deploys the RootModel now and attaches
/// `ROOT_MODEL_DEPLOY_VALUE = 5 vmshell` itself(`contracts/airegistry/SuperRoot.sol:58`), and
/// `PrivateNote.fundDeployShell` no longer even has a leg pointed at it
/// (`contracts/dex/PrivateNote.sol:1143`), so the RootModel half was reserving ECC[2] that nothing
/// could spend and that burns at `destroy`.
/// The default has always been the floor itself, and it still is -- what changed is that the floor is
/// now the deal's own requirement rather than one number for every deal.
pub fn default_deposit_shells(max_ticks: u128) -> u128 {
    min_deploy_shells(max_ticks)
}

/// Balance at or below which a per-deal `TokenContract` must be topped up, in raw nanovmshell.
/// The deposit floor alone changes nothing observable: the gas-health step refills the deal from the
/// note, so a flat `5`/`10` here simply moves the same ten SHELL out of the deposit and into the
/// top-up, and the cheap deal burns it anyway. The floor a deal is held to is the figure it was
/// funded against.
pub fn deal_gas_health_floor_raw(max_ticks: u128) -> u128 {
    deal_gas_health_floor_raw_with_overhead(max_ticks, DEAL_GAS_OVERHEAD_RAW.value)
}

/// Gas-health floor using the measured remainder selected for the runtime network.
pub fn deal_gas_health_floor_raw_with_overhead(
    max_ticks: u128,
    deal_gas_overhead_raw: u128,
) -> u128 {
    deal_gas_requirement_raw_with_overhead(max_ticks, deal_gas_overhead_raw)
}

/// Balance a per-deal `TokenContract` top-up targets, in raw nanovmshell -- the whole-SHELL floor, so
/// a refill lands where a fresh provision would have funded it.
pub fn deal_gas_health_target_raw(max_ticks: u128) -> u128 {
    deal_gas_health_target_raw_with_overhead(max_ticks, DEAL_GAS_OVERHEAD_RAW.value)
}

/// Gas-health top-up target using the measured remainder selected for the runtime network.
pub fn deal_gas_health_target_raw_with_overhead(
    max_ticks: u128,
    deal_gas_overhead_raw: u128,
) -> u128 {
    min_deploy_shells_with_overhead(max_ticks, deal_gas_overhead_raw).saturating_mul(SHELL_UNIT)
}
/// Canonical wallet-onboarding session and polling limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletOnboardingParams {
    /// Lifetime of the ordinary bee connect invitation.
    pub session_ttl: Duration,
    /// Maximum canonical `wallet_hello` polling attempts.
    pub hello_poll_attempts: u32,
    /// Delay between `wallet_hello` polling attempts.
    pub hello_poll_interval: Duration,
    /// Maximum durable `agent_wallets_response` polling attempts.
    pub response_poll_attempts: u32,
    /// Delay between response polling attempts.
    pub response_poll_interval: Duration,
    /// Maximum number of bee context events read in one reconciliation pass.
    pub context_event_limit: u32,
    /// Allowed positive clock skew for signed/encrypted bee messages.
    pub timestamp_future_skew: Duration,
    /// Maximum user-visible agent-name length.
    pub agent_name_max_chars: usize,
    /// Exact number of pubkey custodians each half of the agreed Acki Nacki agent wallet pair
    /// carries: the two human keys the wallet deploys with, plus the agent's own key.
    pub agent_wallet_custodians: usize,
    /// `requiredTxnConfirms` of the agreed Vault: the agent may submit, a human must confirm.
    pub vault_required_txn_confirms: u8,
    /// `requiredTxnConfirms` of the agreed Hot: the agent spends unattended.
    pub hot_required_txn_confirms: u8,
    /// `requiredDataConfirms` both agreed halves carry, so custodian rotation always needs two.
    pub agent_wallet_required_data_confirms: u8,
}

impl WalletOnboardingParams {
    /// Frozen values from the released wallet reference and directive.
    /// The wallet shape is the answer recorded on(2026-08-12): owners are
    /// `[K0, K1, matching_agent_key]`, Vault/Hot transaction confirms `2`/`1`, and data confirms
    /// `2` on both halves. They are money-safety invariants, not preferences: a Hot that needs
    /// fewer confirmations than agreed, or that carries a custodian nobody intended, is a wallet
    /// somebody else can spend from.
    pub const fn canonical() -> Self {
        Self {
            session_ttl: Duration::from_secs(3_600),
            hello_poll_attempts: 240,
            hello_poll_interval: Duration::from_secs(5),
            response_poll_attempts: 120,
            response_poll_interval: Duration::from_secs(5),
            context_event_limit: 50,
            timestamp_future_skew: Duration::from_secs(30),
            agent_name_max_chars: 64,
            agent_wallet_custodians: 3,
            vault_required_txn_confirms: 2,
            hot_required_txn_confirms: 1,
            agent_wallet_required_data_confirms: 2,
        }
    }
}

impl Default for WalletOnboardingParams {
    fn default() -> Self {
        Self::canonical()
    }
}

/// Default bee/chain endpoint selected by the `--network shellnet` onboarding flag.
pub const WALLET_ONBOARD_SHELLNET_ENDPOINT: &str = "shellnet.ackinacki.org";

/// Default bee/chain endpoint selected by the `--network mainnet` onboarding flag.
pub const WALLET_ONBOARD_MAINNET_ENDPOINT: &str = "dd-mainnet.ackinacki.org";

/// The agent name `dexdo wallet onboard ackinacki-wallet` sends when `--agent-name` is not given
/// .
/// It exists so the provider can also be chosen from the interactive menu, which carries no command
/// line to supply one. A CONSTANT and not the hostname or a random token: the durable bee session
/// pins the agent name and refuses to resume under a different one, so a default that varied between
/// runs would make every menu-started onboarding unresumable. It is also the label a human reads
/// inside the wallet app when approving, so it names the tool rather than the machine.
pub const WALLET_ONBOARD_DEFAULT_AGENT_NAME: &str = "dexdo";

/// Canonical default for `--state`, the durable bee session of `wallet onboard ackinacki-wallet`
/// . This is a filename, not a shared storage path: when the flag is absent, the wallet
/// dispatcher resolves it inside the binding draft directory reserved for this exact attempt.
pub const DEFAULT_WALLET_ONBOARD_STATE_PATH: &str = "onboarding.json";

/// Canonical default for `--hot-key`, the generated Hot secret of the same command.
/// It is a path to a PRIVATE KEY, so the command creates its directory owner-only and writes the
/// file 0600 -- which is exactly why it needs a default at all: the alternative was making every
/// operator invent a location for a secret, and making the interactive menu, which cannot ask for
/// one, a dead end.
pub const DEFAULT_WALLET_ONBOARD_HOT_KEY_PATH: &str = "hot.key";

/// How long the gosh-ai provider of `dexdo wallet onboard` waits for the pasted Hot to become
/// `Active`.
/// This is a bound on somebody else's asynchronous deploy, not another local timer: Gosh.ai creates
/// the sub-wallet after the user copies the string, so the account legitimately reports
/// `NotFound`/`NonExist`/`Uninit` for a while. Ten minutes is the figure the wallet-team spec fixes
/// for this wait; the provider subcommand's `--activation-timeout` overrides it for automation.
pub const GOSHAI_HOT_ACTIVATION_TIMEOUT: Duration = Duration::from_secs(600);

/// Spacing between the account reads that wait for the Gosh.ai Hot, per the same spec.
pub const GOSHAI_HOT_ACTIVATION_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum wait for an external top-up of the bound Hot wallet to appear on chain.
/// The wallet specification fixes it at ten minutes for every provider, so it is one bound shared by
/// the funding flows rather than a per-provider timer. It reuses
/// [`NOTE_DEPLOY_SHELL_FUNDING_POLL_INTERVAL`] as its read cadence: both poll one address for SHELL
/// that some other party is sending, so a second interval would only be the same number twice.
pub const WALLET_HOT_FUNDING_TIMEOUT: Duration = Duration::from_secs(600);

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
    /// Silence after which the one pending claim may be promoted to trusted.
    /// `CLAIM_PROMOTE_WINDOW = 60s`.
    /// Contracts 4.0.35 halved it from 120s to `MIN_SECONDS_PER_TICK`, which makes it EQUAL to
    /// `min_claim_interval`(`contracts/airegistry/modifiers/modifiers.sol:51-62`), and the equality
    /// is load-bearing rather than incidental: `claimTokens` requires `MIN_CLAIM_INTERVAL` to have
    /// elapsed and then requires the pending slot to be promoted, and both comparisons are `>=`
    /// against the same anchor -- so the next claim can never arrive before the previous one is ripe,
    /// which is what leaves exactly one unpromoted tick and let the third claim slot be deleted.
    /// A client still carrying 120 here waits twice as long as the chain does to finalize, and
    /// refuses a claim the contract would accept.
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
            claim_promote_window: Duration::from_secs(60),
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

/// Maximum total attempts for one timed-out periodic upstream health probe.
/// Two attempts absorb one isolated stall while extending only that timeout path by one health-check timeout.
pub const SELLER_UPSTREAM_HEALTH_TIMEOUT_MAX_ATTEMPTS: u32 = 2;

/// Seller CLI liveness timings for a resting SELL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SellerLivenessParams {
    /// Time between complete gateway/upstream health cycles.
    pub health_interval: Duration,
    /// Per-cycle budget for gateway and exact-model upstream readiness.
    pub health_check_timeout: Duration,
    /// Maximum time from the last healthy instant through the initial exact-order read and cancel
    /// preparation/submit. An accepted cancel is watched without a client clock until the chain
    /// answers.
    pub health_cycle_timeout: Duration,
    /// Standalone budget for the initial exact-order read and cancel submit. It does not bound the
    /// authoritative watch after the cancel has been accepted.
    pub cancel_confirmation_timeout: Duration,
    /// Poll interval while reconciling exact order state.
    pub cancel_confirmation_poll: Duration,
    /// Poll interval used only to notice a terminated gateway task.
    pub gateway_task_poll: Duration,
    /// time between authoritative re-reads of the supervised order's own deadline.
    /// A resting SELL dies at a wall-clock instant nobody announces, so supervision has to go and
    /// look. This is the worst-case lag between the deadline passing and the seller admitting it,
    /// which is why it is much tighter than the health cycle: readiness must imply `now < deadline`,
    /// and every second of lag is a second the seller claims an offer no buyer can reach.
    pub offer_expiry_poll: Duration,
    /// the whole budget for proving one expired offer was reaped, before any successor is posted.
    /// The reap is a submit plus a read-back of three authoritative facts (the order is gone, the
    /// deal's offer latch is released, the deal is still unsold). Every one of them lands through an
    /// asynchronous contract callback, so the budget is a real wait -- but it is a BOUNDED one: an
    /// unproven reap must fail closed with a terminal diagnostic instead of retrying forever, because
    /// a seller that keeps trying to relist is the one that eventually posts twice.
    pub offer_reap_timeout: Duration,
    /// poll interval while confirming the reap. Transient read failures inside
    /// [`Self::offer_reap_timeout`] are retried at this cadence; deterministic refusals never are.
    pub offer_reap_poll: Duration,
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
            offer_expiry_poll: Duration::from_secs(5),
            offer_reap_timeout: Duration::from_secs(60),
            offer_reap_poll: Duration::from_secs(2),
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
        deal_gas_health_floor_raw, deal_gas_health_target_raw, deal_gas_requirement_raw,
        default_deposit_shells, min_deploy_shells, DEAL_GAS_CLAIM_RAW, DEAL_GAS_FIRST_CLAIM_RAW,
        DEAL_GAS_FIXED_RAW, DEAL_GAS_OVERHEAD_RAW, HERMEZ_SRS_MAX_ATTEMPTS,
        HERMEZ_SRS_RETRY_INITIAL_BACKOFF, HERMEZ_SRS_SIZE_BYTES, MATCH_OPEN_TIMEOUT,
        MATCH_OPEN_TIMEOUT_SECS, MAX_CLAIM_DELTA, MIN_STREAM_BUY_TICKS,
        BUYER_HANDOVER_WAIT_SECS, BUYER_ON_DEMAND_PURCHASE_SECS, DEAL_WAIT_SECS,
        NOTE_DEPLOY_SUBMIT_NATIVE_VALUE, PLATFORM_FEE_BPS, PRICE_STEP, PROBE_SEED_TOKENS,
        SELLER_TERMINAL_RECEIPT_POLL_INTERVAL, SELLER_TERMINAL_RECEIPT_TIMEOUT, SHELL_UNIT,
        STOP_SUBMIT_MARGIN, SUBSCRIPTION_MAX_TICKS, SUBSCRIPTION_WEEKS, SUB_TICKS_PER_WEEK,
        TICK_SIZE, WalletOnboardingParams, WALLET_ONBOARD_MAINNET_ENDPOINT,
        WALLET_ONBOARD_SHELLNET_ENDPOINT,
    };
    use proptest::prelude::*;
    use std::time::Duration;

    #[test]
    fn shellnet_keeps_the_exact_existing_requirement_and_floor() {
        let measurement = super::DEAL_GAS_OVERHEAD_RAW;
        assert_eq!(measurement.network, "shellnet");
        let selected = super::resolve_deal_gas_overhead_raw(measurement.network, None)
            .expect("the measurement is valid on its own network");
        assert_eq!(selected, measurement.value);

        for max_ticks in [2_u128, 8, 53, 1_024] {
            assert_eq!(
                super::deal_gas_requirement_raw_with_overhead(max_ticks, selected),
                super::deal_gas_requirement_raw(max_ticks),
                "shellnet's raw TokenContract lifetime requirement must not move"
            );
            assert_eq!(
                super::min_deploy_shells_with_overhead(max_ticks, selected),
                super::min_deploy_shells(max_ticks),
                "shellnet's whole-SHELL deposit floor must not move"
            );
        }
    }

    #[test]
    fn another_network_refuses_with_the_measurement_and_money_consequence() {
        let measurement = super::DEAL_GAS_OVERHEAD_RAW;
        let other_network = "other-network";
        let error = super::resolve_deal_gas_overhead_raw(other_network, None)
            .expect_err("a measurement from another network must never be spent silently");

        for fact in [
            "DEAL_GAS_OVERHEAD_RAW",
            measurement.network,
            other_network,
            "TokenContract",
            "stalled",
            "bonds inside",
        ] {
            assert!(
                error.contains(fact),
                "the refusal is missing `{fact}`: {error}"
            );
        }
    }

    #[test]
    fn operator_measurement_below_shellnet_is_used_as_given() {
        let measurement = super::DEAL_GAS_OVERHEAD_RAW;
        let supplied = measurement.value / 2;
        assert!(supplied < measurement.value);
        let selected = super::resolve_deal_gas_overhead_raw("other-network", Some(supplied))
            .expect("an explicit measurement authorizes that network");
        assert_eq!(selected, supplied, "the override must not be clamped");

        let max_ticks = 53;
        let local_requirement = super::deal_gas_requirement_raw(max_ticks);
        let supplied_requirement =
            super::deal_gas_requirement_raw_with_overhead(max_ticks, selected);
        assert_eq!(
            local_requirement - supplied_requirement,
            measurement.value - supplied,
            "only the measured remainder changes; the contract-derived and claim terms stay fixed"
        );
        assert!(
            super::min_deploy_shells_with_overhead(max_ticks, selected)
                < super::min_deploy_shells(max_ticks),
            "the lower measured value must reach the whole-SHELL floor rather than being clamped"
        );
    }

    /// One vmshell in the raw native units a wallet message carries. The contracts write their call
    /// values in `vmshell`; the wallet writes the same quantity as an integer.
    const NATIVE_PER_VMSHELL: u128 = 1_000_000_000;

    /// `0.1 vmshell` -> `100_000_000`. Exact: the literal is scaled by its own denominator before
    /// the division, so no decimal ever becomes a float.
    fn vmshell_literal_to_native(lit: &str) -> u128 {
        let (whole, frac) = lit.split_once('.').unwrap_or((lit, ""));
        let scale = 10u128.pow(u32::try_from(frac.len()).expect("short vmshell literal"));
        let whole: u128 = if whole.is_empty() {
            0
        } else {
            whole.parse().expect("integer part of a vmshell literal")
        };
        let frac: u128 = if frac.is_empty() {
            0
        } else {
            frac.parse().expect("fractional part of a vmshell literal")
        };
        (whole * scale + frac) * NATIVE_PER_VMSHELL / scale
    }

    /// The `value:` a vendored contract attaches to one named call, in raw native units.
    /// `anchor` is the callee including its opening brace, so this reads the option block of THAT
    /// call rather than whichever `value:` happens to appear nearby.
    fn attached_call_value_native(src: &str, anchor: &str) -> u128 {
        let at = src
            .find(anchor)
            .unwrap_or_else(|| panic!("the vendored contract source still contains `{anchor}`"));
        let tail = &src[at + anchor.len()..];
        let opts = &tail[..tail
            .find('}')
            .unwrap_or_else(|| panic!("`{anchor}` option block closes"))];
        let after_value = opts
            .split_once("value:")
            .unwrap_or_else(|| panic!("`{anchor}` attaches an explicit value"))
            .1
            .trim_start();
        let lit = after_value
            .split_whitespace()
            .next()
            .unwrap_or_else(|| panic!("`{anchor}` value literal"));
        assert!(
            after_value[lit.len()..].trim_start().starts_with("vmshell"),
            "`{anchor}` states its value in vmshell; got `{after_value}`"
        );
        vmshell_literal_to_native(lit)
    }

    /// The value of a `... constant NAME = <n> vmshell;` declaration, in raw native units.
    fn named_vmshell_constant(src: &str, name: &str) -> u128 {
        let decl = format!("constant {name} =");
        let at = src
            .find(&decl)
            .unwrap_or_else(|| panic!("the vendored contract source still declares `{name}`"));
        let rest = src[at + decl.len()..].trim_start();
        let lit = rest
            .split_whitespace()
            .next()
            .unwrap_or_else(|| panic!("`{name}` literal"));
        assert!(
            rest[lit.len()..].trim_start().starts_with("vmshell"),
            "`{name}` is declared in vmshell; got `{rest}`"
        );
        vmshell_literal_to_native(lit)
    }

    /// The right-hand side of a `... constant NAME = <token>;` declaration, verbatim.
    /// Verbatim rather than evaluated on purpose: `MAX_CLAIM_DELTA = TICK_SIZE` is the fact worth
    /// pinning -- the contract ties the two together -- and a helper that resolved the alias would
    /// happily keep passing after someone replaced it with a number that merely happens to agree.
    fn named_uint_constant<'a>(src: &'a str, name: &str) -> &'a str {
        let decl = format!("constant {name} =");
        let at = src
            .find(&decl)
            .unwrap_or_else(|| panic!("the vendored contract source still declares `{name}`"));
        src[at + decl.len()..]
            .split(';')
            .next()
            .unwrap_or_else(|| panic!("`{name}` declaration terminates"))
            .trim()
    }

    /// The floor for the voucher submit is stated by the contracts, so this test reads it from them.
    /// Two earlier pins were circular in the same way and both looked green. The first compared the
    /// encoded wallet-message `value` with the constant that produced it. The second compared it
    /// against a "measured cost" of `84_368 * 2_000_000_000 / 33_591_296` -- the gas priced at the
    /// rate implied by the very 2 VMSHELL literal being replaced, so the claimed 19x margin cleared
    /// only against a floor denominated in the retired value. Neither could go red for a
    /// wrong value, because in both the floor moved with the thing under test.
    /// A receipt cannot fix that: `gas_used * value / gas_limit` puts the attached value on both
    /// sides of the division, and the two observations we have are not even proportional -- 20x less
    /// attached value bought about 30.95x less `gas_limit`, so a fixed per-message deduction sits
    /// between them and no single-point division recovers it.
    /// So the oracle here is the vendored contract source, which knows nothing about our constant:
    /// what the protocol itself pays to call a RootPN entry, and the smallest call value it uses
    /// anywhere. Change `NOTE_DEPLOY_SUBMIT_NATIVE_VALUE` and this goes red; change what the
    /// contracts attach and it goes red too, which is the direction the old pins could not see.
    #[test]
    fn the_voucher_submit_value_is_the_protocol_call_value_into_the_root_pn_dapp() {
        const ORDER_BOOK_SOL: &str = include_str!("../../../contracts/dex/OrderBook.sol");
        const TOKEN_CONTRACT_SOL: &str =
            include_str!("../../../contracts/airegistry/TokenContract.sol");

        // `RootPN.collectProtocolFee` is the strongest available comparison, not merely a nearby
        // one: it is a RootPN entry whose `senderIs` guard -- a three-code-cell address derivation --
        // sits above its `accept` and is therefore billed to the caller in full. `generateVoucher`
        // charges its caller less than that: a currency-map parse, comparisons, one subtraction.
        let protocol_call_value = attached_call_value_native(ORDER_BOOK_SOL, "collectProtocolFee{");
        assert_eq!(
            NOTE_DEPLOY_SUBMIT_NATIVE_VALUE, protocol_call_value,
            "a note-deploy voucher submit attaches {NOTE_DEPLOY_SUBMIT_NATIVE_VALUE} native, but \
             the protocol funds its own call into a RootPN entry with {protocol_call_value}; \
             RootPN.generateVoucher accepts only after its guards, so an under-funded submit dies \
             before any of them and the deploy hangs waiting for a VoucherGenerated that was never \
             emitted, while an over-funded one is donated to the root -- generateVoucher is `view` \
             and never returns the remainder"
        );

        // The floor and the margin, both named by the contracts rather than by us.
        let smallest_call_value = named_vmshell_constant(TOKEN_CONTRACT_SOL, "DAPP_MSG_VALUE");
        assert_eq!(
            NOTE_DEPLOY_SUBMIT_NATIVE_VALUE,
            smallest_call_value * 10,
            "the attached value is documented as ten times DAPP_MSG_VALUE ({smallest_call_value}), \
             the smallest value anything in this protocol attaches to an internal call and the one \
             4.0.34 records as too tight to reach a pre-accept guard; that multiple is the margin, \
             so it cannot drift silently"
        );
    }

    /// The count of claims a deal needs is stated by the CONTRACT, not chosen by us -- so the
    /// per-tick term in [`deal_gas_requirement_raw`] is per-TICK because `TokenContract` says a claim
    /// carries at most a tick, and for no other reason.
    /// This is the half of's floor that can go red on its own. If a later generation lets one
    /// claim carry two ticks, the requirement is overstated twofold and this says so; if it caps a
    /// claim below a tick, the requirement is UNDERSTATED and a funded deal stops mid-stream with its
    /// bond inside. Neither shows up in a test that prices the requirement with the requirement
    /// the oracle has to be the vendored source, which knows nothing about our figures.
    #[test]
    fn one_claim_carries_one_tick_because_the_deal_contract_caps_it_there() {
        const TOKEN_CONTRACT_SOL: &str =
            include_str!("../../../contracts/airegistry/TokenContract.sol");

        let cap = named_uint_constant(TOKEN_CONTRACT_SOL, "MAX_CLAIM_DELTA");
        let tick = named_uint_constant(TOKEN_CONTRACT_SOL, "TICK_SIZE");
        assert_eq!(
            cap, "TICK_SIZE",
            "the deal caps one claim at `{cap}`, not at a tick; `deal_gas_requirement_raw` counts one \
             claim per tick and is wrong the moment that stops being what the contract enforces"
        );
        assert_eq!(
            tick.replace('_', "").parse::<u128>().expect("TICK_SIZE"),
            TICK_SIZE,
            "the deal's TICK_SIZE and ours disagree, so `max_ticks` does not count the same thing on \
             both sides of the funding decision"
        );
        assert!(
            TOKEN_CONTRACT_SOL.contains(
                "function claimTokens(uint128 cumulativeTokens) public onlyOwnerPubkey(_sellerPubkey) accept"
            ),
            "`claimTokens` accepts in its modifier list, i.e. BEFORE its body: that is what makes \
             every claim the DEAL's compute rather than the seller's, and it is why volume converts \
             into the deal's gas budget at all"
        );
    }

    /// The fixed part of the requirement is the measured overhead PLUS what the deal's own source
    /// says it hands out. The second half is read off the vendored contract, which knows nothing
    /// about our figures -- so this cannot go green for a wrong value the way a pin that priced the
    /// requirement with the requirement did.
    /// It goes red in both directions that matter: move `DEAL_GAS_FIXED_RAW` and the sum stops
    /// matching; re-vendor `TokenContract.sol` with different attached values and it stops matching
    /// too -- the case a version string cannot catch. That second direction is not hypothetical: this
    /// test is what caught `DEAL_GAS_FIXED_RAW` still holding the 4.0.33 book-call values (`2.06`
    /// outgoing) after dev re-vendored the real 4.0.34 contracts underneath this branch, with the
    /// manifest reading `4.0.34` on both sides of that change.
    #[test]
    fn deal_gas_fixed_matches_the_values_this_tree_s_deal_declares() {
        const TOKEN_CONTRACT_SOL: &str =
            include_str!("../../../contracts/airegistry/TokenContract.sol");

        let dapp_msg_value = named_vmshell_constant(TOKEN_CONTRACT_SOL, "DAPP_MSG_VALUE");
        let small_sends = TOKEN_CONTRACT_SOL.matches("value: DAPP_MSG_VALUE").count() as u128;
        let book_sends = TOKEN_CONTRACT_SOL.matches("value: 1 vmshell").count() as u128;
        assert_eq!(
            small_sends + book_sends,
            8,
            "the published lifetime budget counts EIGHT outgoing sends from a deal; this source \
             declares {small_sends} at DAPP_MSG_VALUE and {book_sends} at one vmshell. A send that \
             appeared or disappeared changes what a deal must be funded with, and neither the version \
             string nor the measurement can tell you it happened"
        );

        let declared = dapp_msg_value.saturating_mul(small_sends)
            + NATIVE_PER_VMSHELL.saturating_mul(book_sends);
        assert_eq!(
            DEAL_GAS_FIXED_RAW,
            DEAL_GAS_OVERHEAD_RAW + declared,
            "a deal on THIS source hands out {declared} raw before a single claim, so its fixed \
             requirement is that plus the measured {DEAL_GAS_OVERHEAD_RAW} of compute and message \
             fees. A deal funded below what it hands out strands on its own send, and it cannot mint \
             its way out: deployed by an external message into a dapp with no config, \
             `gosh.mintshellq` has nothing to draw on, so the stop is permanent with the bond inside"
        );

        // The overhead term is the published 4.0.34 figure MINUS the sends that figure assumes, not
        // a number anyone here picked. State that, so the one measured input stays attributable.
        const PUBLISHED_4034_FIXED_RAW: u128 = 215_000_000;
        assert_eq!(
            DEAL_GAS_OVERHEAD_RAW + dapp_msg_value * 8,
            PUBLISHED_4034_FIXED_RAW,
            "the published 4.0.34 fixed part is {PUBLISHED_4034_FIXED_RAW} raw with all eight sends \
             at DAPP_MSG_VALUE; our overhead term has to be exactly that minus those sends, or it is \
             a figure of our own"
        );
    }

    /// the market property: a deal must be able to fund itself out of what it is worth.
    /// The worked example from the issue -- eight ticks at one SHELL each, so eight SHELL of service
    /// in total -- had to clear a flat ten-SHELL floor. That is not waste at the margin but a segment
    /// that cannot exist: any model priced low enough is unsellable however good it is. The
    /// assertions are PROPERTIES, not the numbers, so they survive the measurements moving and go red
    /// if the floor is ever re-pinned above what a small deal earns.
    #[test]
    fn a_deal_s_floor_stays_under_what_the_deal_is_worth() {
        const OLD_FLAT_FLOOR_SHELLS: u128 = 10;
        let price_per_tick = PRICE_STEP; // one SHELL per tick, the issue's example

        let issue_ticks = 8;
        let issue_value_shells = issue_ticks * price_per_tick / SHELL_UNIT;
        assert!(
            min_deploy_shells(issue_ticks) < issue_value_shells,
            "an {issue_ticks}-tick deal at one SHELL per tick is worth {issue_value_shells} SHELL and \
             its floor is {} SHELL; a floor at or above the deal's value closes that price point to \
             every seller however good the model is",
            min_deploy_shells(issue_ticks)
        );
        assert!(
            min_deploy_shells(issue_ticks) < OLD_FLAT_FLOOR_SHELLS,
            "the flat {OLD_FLAT_FLOOR_SHELLS}-SHELL floor is what  reports; a fix that lands back \
             on it fixes nothing"
        );

        // And the direction the flat floor was too LOW. The requirement grows with the deal, so a
        // long deal must be asked for MORE than the old constant, not less -- under-funding it is the
        // permanent stop, not the tolerable waste.
        assert!(
            min_deploy_shells(1_000) > OLD_FLAT_FLOOR_SHELLS,
            "a thousand-tick deal needs {} raw -- the flat {OLD_FLAT_FLOOR_SHELLS} SHELL under-funded \
             it, and a deal that runs out cannot refill itself",
            deal_gas_requirement_raw(1_000)
        );

        // WHERE THE FLOOR STILL BITES, stated rather than assumed.
        // THE BOUND: the smallest deal that funds itself at one SHELL per tick is the smallest deal
        // the CONTRACT will accept at all. `TokenContract`'s constructor refuses anything shorter --
        // `require(maxTicks >= 2, ERR_BAD_PARAM)`, `contracts/airegistry/TokenContract.sol` -- so a
        // boundary sitting exactly there means the funding floor excludes NO deal that is allowed to
        // exist. That is discharged, and it is the strongest form this property can take.
        // THE SOURCE OF `2`: that constructor requirement, and nothing else. It is not the figure
        // this arithmetic happens to produce. The two are independent -- one is read off the deal's
        // vendored source, the other is computed from the gas schedule -- and the assertion is that
        // they meet.
        // WHAT WOULD MOVE IT: re-vendoring a `TokenContract.sol` that attaches more than
        // `DAPP_MSG_VALUE` to any of its eight sends. The 4.0.33 shape did exactly that on its two
        // book calls, `1 vmshell` each and `2.07` in sends alone, which pushed this boundary
        // out to four ticks and priced the smallest deals out of existence. If it ever rises above
        // the contract minimum again, the deal's declared outgoing values moved and has
        // regressed -- which is the failure this assertion exists to catch.
        const CONTRACT_MIN_TICKS: u128 = 2;
        let smallest_self_funding = (CONTRACT_MIN_TICKS..=64)
            .find(|&ticks| min_deploy_shells(ticks) < ticks * price_per_tick / SHELL_UNIT)
            .expect("some deal length funds itself at one SHELL per tick");
        assert_eq!(
            smallest_self_funding, CONTRACT_MIN_TICKS,
            "the smallest deal that funds itself at one SHELL per tick is {smallest_self_funding} \
             ticks, against a contract minimum of {CONTRACT_MIN_TICKS} (`require(maxTicks >= 2)` in \
             the TokenContract constructor); any figure above that minimum means the funding floor \
             shuts out deals the contract itself would accept, which is "
        );

        // With the published 4.0.34 sends(all eight at DAPP_MSG_VALUE, so 0.08) the fixed part is
        // 0.215 and the issue's deal needs 0.33 -- the figure quotes.
        let published_4034_requirement =
            215_000_000 + DEAL_GAS_FIRST_CLAIM_RAW + DEAL_GAS_CLAIM_RAW * (issue_ticks - 1);
        assert_eq!(
            published_4034_requirement, 330_000_000,
            " states an eight-tick deal needs ~0.33 vmshell on 4.0.34; the schedule here must \
             reproduce that figure, or it is describing a different contract"
        );
    }

    /// One requirement used in three places. If the deposit floor and the gas-health floor ever
    /// disagree, the note refills the deal to a different number than it funded it at, and the
    /// deposit decision stops meaning anything.
    #[test]
    fn one_requirement_governs_the_deposit_the_default_and_the_top_up() {
        for max_ticks in [2_u128, 8, 53, 1_000] {
            assert_eq!(default_deposit_shells(max_ticks), min_deploy_shells(max_ticks));
            assert_eq!(
                deal_gas_health_floor_raw(max_ticks),
                deal_gas_requirement_raw(max_ticks),
                "a deal held to a floor other than the one it was funded against is topped up to \
                 someone else's number"
            );
            assert_eq!(
                deal_gas_health_target_raw(max_ticks),
                min_deploy_shells(max_ticks) * SHELL_UNIT,
                "a refill must land where a fresh provision would have funded it"
            );
            assert!(deal_gas_health_target_raw(max_ticks) >= deal_gas_health_floor_raw(max_ticks));
        }

        // The shape of the schedule: fixed part, a cheaper first claim, then a shelf.
        assert_eq!(
            deal_gas_requirement_raw(1),
            DEAL_GAS_FIXED_RAW + DEAL_GAS_FIRST_CLAIM_RAW
        );
        assert_eq!(
            deal_gas_requirement_raw(3) - deal_gas_requirement_raw(2),
            DEAL_GAS_CLAIM_RAW
        );
        assert!(DEAL_GAS_FIRST_CLAIM_RAW < DEAL_GAS_CLAIM_RAW);
        // Saturating, never wrapping: this figure funds a live contract.
        assert!(deal_gas_requirement_raw(u128::MAX) > 0);
        assert!(min_deploy_shells(0) >= 1);
    }

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
    fn a_buyer_never_gives_up_on_a_deal_the_contract_still_holds_open() {
        // The seller's window belongs to the contract. A buyer whose handover wait is shorter than
        // `MATCH_OPEN_TIMEOUT` abandons and settles deals that are still openable, and the shorter
        // it is the more of them: measured on shellnet, a handover wait carved out of the match's
        // budget was left 7 seconds of its nominal 300.
        assert!(
            BUYER_HANDOVER_WAIT_SECS >= MATCH_OPEN_TIMEOUT_SECS,
            "handover wait {BUYER_HANDOVER_WAIT_SECS}s is shorter than the contract's \
             {MATCH_OPEN_TIMEOUT_SECS}s cleanup window"
        );
        // The purchase is the match and then the handover, so its budget is theirs together. Any
        // less and the outer wait cuts an inner one short.
        assert!(
            BUYER_ON_DEMAND_PURCHASE_SECS >= DEAL_WAIT_SECS + BUYER_HANDOVER_WAIT_SECS,
            "on-demand purchase budget {BUYER_ON_DEMAND_PURCHASE_SECS}s cannot hold a \
             {DEAL_WAIT_SECS}s match followed by a {BUYER_HANDOVER_WAIT_SECS}s handover"
        );
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
        assert_eq!(STOP_SUBMIT_MARGIN, Duration::from_secs(20));
        // The margin is a tail of the promotion window, so it only means anything strictly inside
        // it: at or above the window there is no instant left at which STOP leaves a claim
        // contested, which is the whole state the two-runner gate settles.
        assert!(STOP_SUBMIT_MARGIN < ProtocolConsts::canonical().claim_promote_window);
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

    /// One classifier, one answer per state. Every buy surface -- the preflight refusal and
    /// the `executable-book` listing -- reads its class from here, so this is the truth table both
    /// of them are held to.
    #[test]
    fn book_refusal_class_separates_the_four_states() {
        for (reason, expected) in [
            (
                format!(
                    "{}: {} for max_price_per_tick 10, requested ticks 8",
                    super::RAW_MATCHER_NO_SUBMIT_SAFE_ASK,
                    super::EMPTY_MODEL_BOOK_REASON
                ),
                super::EMPTY_MODEL_BOOK_CLASS,
            ),
            (
                format!("{} 1785678525: nearest ask is gone", super::EXPIRED_COUNTERPARTY_ASK_REASON),
                super::EXPIRED_COUNTERPARTY_ASK_CLASS,
            ),
            (
                format!("{} for max_price_per_tick 10", super::LAPSED_MODEL_BOOK_REASON),
                super::EXPIRED_COUNTERPARTY_ASK_CLASS,
            ),
            (
                format!("{} order  has only 1 ticks", super::INSUFFICIENT_HEAD_ASK_REASON),
                super::INSUFFICIENT_HEAD_ASK_CLASS,
            ),
            (
                "no executable matching ask for max_price_per_tick 10".to_string(),
                super::NO_EXECUTABLE_ASK_CLASS,
            ),
            (
                "best ask price 11 is above buyer max_price_per_tick 10".to_string(),
                super::NO_EXECUTABLE_ASK_CLASS,
            ),
            // The empty phrase WITHOUT the raw-side wrapper is an empty EXECUTABLE set over a book
            // that has rows: "nothing here is usable", not "nothing is here".
            (
                format!(
                    "raw order-book matcher would select order , but executable-depth check has \
                     no matching ask: {}",
                    super::EMPTY_MODEL_BOOK_REASON
                ),
                super::NO_EXECUTABLE_ASK_CLASS,
            ),
        ] {
            assert_eq!(super::book_refusal_class(&reason), Some(expected), "{reason}");
            assert_eq!(super::buy_refusal_class(&reason), expected, "{reason}");
        }

        // A failure to READ the book is not a state OF the book, and must stay an error.
        for reason in [
            "shellnet: GraphQL request failed: 502 Bad Gateway",
            "InferenceOrderBook 0:book is not active",
        ] {
            assert_eq!(super::book_refusal_class(reason), None, "{reason}");
            assert_eq!(
                super::buy_refusal_class(reason),
                super::NO_EXECUTABLE_ASK_CLASS,
                "{reason}"
            );
        }
    }

    #[test]
    fn wallet_onboarding_parameters_match_the_frozen_wallet_reference() {
        let params = WalletOnboardingParams::canonical();
        assert_eq!(params.session_ttl, Duration::from_secs(3_600));
        assert_eq!(params.hello_poll_attempts, 240);
        assert_eq!(params.hello_poll_interval, Duration::from_secs(5));
        assert_eq!(params.response_poll_attempts, 120);
        assert_eq!(params.response_poll_interval, Duration::from_secs(5));
        assert_eq!(params.context_event_limit, 50);
        assert_eq!(params.timestamp_future_skew, Duration::from_secs(30));
        assert_eq!(params.agent_name_max_chars, 64);
        assert_eq!(WALLET_ONBOARD_SHELLNET_ENDPOINT, "shellnet.ackinacki.org");
        assert_eq!(WALLET_ONBOARD_MAINNET_ENDPOINT, "dd-mainnet.ackinacki.org");
    }
}
