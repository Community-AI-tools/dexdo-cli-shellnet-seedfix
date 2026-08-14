//! The shared Hot check-and-fund mechanism and its durable funding journal.
//! Checking the Hot's balance and asking the Vault for a top-up is not `note deploy`'s business, or
//! `wallet onboard`'s: every operation that spends Hot funds directly needs the same eight steps, so
//! they live here once. The specification names the entry point `ensure_hot_funded(binding,
//! requirements, operation)` and that is [`ensure_hot_funded`].
//! Two commands spend a Hot directly - `note deploy` and `note topup`. Everything else in dexdo is
//! note-funded. Those two are therefore the callers this is built for, and both of them reach this
//! module through [`ensure_hot_funded_with_turn`] while already holding the funding-wallet lock they
//! have shared since.
//! What this module owns:
//! - the preflight read of the Hot's on-chain balances and the per-currency shortfall;
//! - the bounded wait for those balances to reach the required level;
//! - the re-check immediately before the caller spends, serialized per Hot;
//! - the durable journal that stops a repeat of the command from creating a second Vault request.
//! What this module does NOT own: how any particular provider gets money into the Hot. That is
//! [`HotFundingProvider`], one implementation per provider, in [`providers`]. The specification is
//! explicit that a provider's own answer is never proof of funding - in the Gosh.ai flow there is no
//! answer at all - so the only thing this module will accept as proof is the Hot's observed
//! on-chain balance.
//! # The binding this reads
//! [`HotFundingBinding`] is a VIEW of the production binding in [`crate::cli::wallet`], built by
//! [`HotFundingBinding::from_active`], and [`WalletProvider`] IS the production enum re-exported.
//! There is no second binding schema and no second provider enum: a funding flow chosen from a
//! provider this module invented for itself would be a funding flow the operator never bound.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Result};
use dexdo_core::CanonicalAddress;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The provider model is the production one. A funding flow is selected from the binding the
/// operator committed, never from a parallel enum that could drift from it.
pub(crate) use crate::cli::wallet::WalletProvider;

/// Journal schema version. Bumped only when an older file can no longer be read safely.
/// Version 2 adds the request generation, the immutable transfer fingerprint and the `executed` /
/// `expired` states. A version-1 record cannot be upgraded in place by guessing those fields: its
/// fingerprint is exactly what a repeat needs in order to recognise a request already on chain, and
/// inventing one would make an unrecognisable request look absent - the single state that authorizes
/// a second transfer out of a cold Vault. A version-1 file is therefore REFUSED, loudly, rather than
/// migrated.
const FUNDING_JOURNAL_VERSION: u32 = 2;

// ---------------------------------------------------------------------------------------------
// The shape of a Vault -> Hot transfer
// ---------------------------------------------------------------------------------------------

/// `sendFlags` for the Vault -> Hot transfer.
/// Flag 1 pays the message's fees from the Vault's balance rather than out of the amount being
/// sent, so the Hot receives exactly the figure the operator confirmed in the wallet application.
/// Flag 16 - the one the uninit-deploy funding path uses - would collapse the ECC[2] SHELL into the
/// destination's NATIVE balance, and a Hot holding gas where it needs currency is a Hot that still
/// cannot pay for a note. `note topup` sends to a PrivateNote with flag 1 for the same reason
/// (`note_cmd.rs`), and this is the same kind of transfer to a different account.
pub(crate) const VAULT_TO_HOT_SEND_FLAGS: u16 = 1;

/// `bounce` for the Vault -> Hot transfer: the message carries money, so on any refusal it comes
/// home to the Vault instead of resting on an address that did not take it.
pub(crate) const VAULT_TO_HOT_BOUNCE: bool = true;

/// The payload of the Vault -> Hot transfer: empty.
/// An empty body is what makes this a plain currency transfer - the Hot sees no function to run, so
/// its `receive()` takes the message and the ECC[2] stays ECC[2].
pub(crate) const VAULT_TO_HOT_PAYLOAD: &str = "";

// ---------------------------------------------------------------------------------------------
// The binding view
// ---------------------------------------------------------------------------------------------

/// The four facts the shared funding mechanism needs from the active binding.
/// Derived from [`crate::cli::wallet::WalletBinding`] and never assembled from anywhere else. It is
/// a view rather than the binding itself because everything else the binding carries - its id, its
/// schema version, the PATHS to owner-only secret files - is either irrelevant to the decision made
/// here or must not travel into a journal record that is non-secret by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HotFundingBinding {
    /// Recorded at binding time, never guessed afterwards.
    pub(crate) provider: WalletProvider,
    /// The network the addresses below are on. It is part of the journal key, so a Hot address that
    /// happens to repeat across networks does not collide.
    pub(crate) network: String,
    /// The full canonical `<dapp_id>::<account_id>` Hot address.
    pub(crate) hot_address: String,
    /// The full canonical Vault address, when the provider has one. Gosh.ai and manual do not.
    pub(crate) vault_address: Option<String>,
}

/// The name the mechanism and its tests have always used for the view above.
pub(crate) type WalletBinding = HotFundingBinding;

impl HotFundingBinding {
    /// The view of the binding the operator actually committed.
    #[cfg(any(feature = "shellnet", test))]
    pub(crate) fn from_active(binding: &crate::cli::wallet::WalletBinding) -> Self {
        Self {
            provider: binding.provider,
            network: binding.network.as_str().to_string(),
            hot_address: binding.hot_address.clone(),
            vault_address: binding.vault_address.clone(),
        }
    }

    /// The Hot as a parsed canonical address.
    /// Parsing is not a formality here: the DApp id half is what a Vault -> Hot transfer has to be
    /// addressed into, and it is only available because the binding stores the canonical form
    /// rather than the legacy `0:<account_id>` one.
    pub(crate) fn hot(&self) -> Result<CanonicalAddress> {
        CanonicalAddress::parse(&self.hot_address)
            .map_err(|e| anyhow!("wallet binding hot_address is not a canonical address: {e}"))
    }

    /// The Vault as a parsed canonical address, when the provider has one.
    pub(crate) fn vault(&self) -> Result<Option<CanonicalAddress>> {
        self.vault_address
            .as_deref()
            .map(|vault| {
                CanonicalAddress::parse(vault).map_err(|e| {
                    anyhow!("wallet binding vault_address is not a canonical address: {e}")
                })
            })
            .transpose()
    }
}

impl WalletProvider {
    /// Whether this provider can put a durable funding request on chain.
    /// Only the Acki Nacki Wallet flow can: it has a Vault, and a `submitTransaction` sitting in
    /// that Vault's queue with one signature IS the request. Gosh.ai and manual have no server-side
    /// request to create, so for them there is nothing that a repeat of the command could
    /// duplicate.
    pub(crate) fn creates_vault_request(self) -> bool {
        matches!(self, Self::AckinackiWallet)
    }
}

// ---------------------------------------------------------------------------------------------
// Requirements and balances
// ---------------------------------------------------------------------------------------------

/// What the calling operation needs the Hot to hold, per currency, at the moment it spends.
/// These are required FINAL balances, not deltas: the specification asks the caller to compute "the
/// exact need per currency", and a final balance is the only form of that which stays correct while
/// the balance is moving underneath the wait.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FundingRequirements {
    /// Currency id -> required total balance.
    pub(crate) required: BTreeMap<u32, u128>,
}

impl FundingRequirements {
    pub(crate) fn new(required: impl IntoIterator<Item = (u32, u128)>) -> Self {
        Self {
            required: required.into_iter().collect(),
        }
    }

    /// Per-currency shortfall against `balances`. Empty means the requirement is met.
    pub(crate) fn shortfall(&self, balances: &HotBalances) -> BTreeMap<u32, u128> {
        self.required
            .iter()
            .filter_map(|(currency, required)| {
                let missing = required.saturating_sub(balances.get(*currency));
                (missing > 0).then_some((*currency, missing))
            })
            .collect()
    }

    /// Whether `balances` satisfies every requirement.
    pub(crate) fn met_by(&self, balances: &HotBalances) -> bool {
        self.shortfall(balances).is_empty()
    }
}

/// A Hot's observed on-chain balances, per currency.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HotBalances {
    pub(crate) balances: BTreeMap<u32, u128>,
}

impl HotBalances {
    pub(crate) fn new(balances: impl IntoIterator<Item = (u32, u128)>) -> Self {
        Self {
            balances: balances.into_iter().collect(),
        }
    }

    pub(crate) fn get(&self, currency: u32) -> u128 {
        self.balances.get(&currency).copied().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------------------------
// The seams
// ---------------------------------------------------------------------------------------------

/// Reads a Hot's balances from the chain.
/// A read failure must surface as `Err`. It must never be reported as a zero balance: a zero
/// balance is a fact that keeps the wait going, whereas an unreadable chain is the state in which
/// nothing may be concluded and nothing may be submitted.
#[async_trait::async_trait(?Send)]
pub(crate) trait HotBalanceReader {
    async fn hot_balances(&self, hot: &CanonicalAddress) -> Result<HotBalances>;
}

/// Everything a provider needs to recognise or create one funding request.
/// The recognition fields are exactly the ones the specification names: destination address,
/// creator public key, and the exact currencies and amounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FundingRequest {
    pub(crate) provider: WalletProvider,
    pub(crate) network: String,
    /// Full canonical Vault address, when the provider has one.
    pub(crate) vault_address: Option<String>,
    /// Full canonical Hot address - the destination.
    pub(crate) hot_address: String,
    /// The DApp half of the Hot's canonical address.
    /// A Vault -> Hot transfer is addressed with this, NOT with the dexdo DApp. The canonical
    /// multisig `submitTransaction`/`sendTransaction` parameter builders in
    /// `crates/core/src/canonical_multisig.rs` hard-code `dapp_id = ROOT_PN_DAPP_ID`("4"), which is
    /// right for every caller they have today - all of them address a dexdo contract (RootPN, a
    /// PrivateNote), and dexdo contracts all live in DApp 4. A Hot does not: it is a self-DApp
    /// multisig, so its DApp half equals its own account id. Carrying the Hot's own DApp id on the
    /// request is what keeps a provider from inheriting the constant by accident.
    pub(crate) hot_dapp_id: String,
    /// Public key of the agent that creates the Vault request, as recorded and matched later.
    pub(crate) creator_pubkey: String,
    /// The required final balances this request is meant to reach.
    pub(crate) required: BTreeMap<u32, u128>,
    /// The shortfall computed when the request was prepared.
    pub(crate) shortfall: BTreeMap<u32, u128>,
}

/// The immutable identity of ONE Vault -> Hot transfer.
/// Every field the specification names, and they are DERIVED from the request rather than chosen
/// separately: `FundingFingerprint::of(&request)` is what the journal records and it is also what
/// the provider builds its `submitTransaction` parameters from. One derivation feeding both is the
/// only arrangement in which the request that went on the wire and the request the journal claims
/// went on the wire cannot disagree - and a fingerprint that does not describe the real transfer
/// would fail to recognise it in the queue, which reads as absence, which authorizes a second
/// transfer out of a cold Vault.
/// Frozen for one GENERATION. A later run whose shortfall has moved does not edit these fields; it
/// keeps looking for THIS transfer until the chain proves what became of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FundingFingerprint {
    /// `creator.owner_pubkey` as the Vault's queue reports it.
    pub(crate) creator: String,
    /// `dest` - the full canonical Hot address.
    pub(crate) dest: String,
    /// `dapp_id` - the Hot's own DApp half.
    pub(crate) dapp_id: String,
    /// `value` - the native part of the transfer.
    pub(crate) value: u128,
    /// `cc` - the extra-currency part, currency id -> amount.
    pub(crate) cc: BTreeMap<u32, u128>,
    pub(crate) send_flags: u16,
    pub(crate) bounce: bool,
    /// sha256 of the transfer's payload. The payload is empty for a plain currency transfer, so
    /// this is a constant today - and it is recorded rather than assumed so that a client which
    /// ever attaches a body cannot silently match a request that carried a different one.
    pub(crate) payload_hash: String,
}

impl FundingFingerprint {
    /// The fingerprint of the transfer `request` describes.
    pub(crate) fn of(request: &FundingRequest, native_value: u128) -> Self {
        Self {
            creator: request.creator_pubkey.clone(),
            dest: request.hot_address.clone(),
            dapp_id: request.hot_dapp_id.clone(),
            value: native_value,
            cc: request.shortfall.clone(),
            send_flags: VAULT_TO_HOT_SEND_FLAGS,
            bounce: VAULT_TO_HOT_BOUNCE,
            payload_hash: payload_hash(VAULT_TO_HOT_PAYLOAD),
        }
    }
}

impl FundingFingerprint {
    /// The payload to put on the wire for this fingerprint.
    /// Checked rather than assumed: the wire payload and the recorded `payload_hash` describe the
    /// same transfer, and a client that sent a body its own record did not describe would create a
    /// request no later run could recognise - which reads as absence, which authorizes a second
    /// transfer out of a cold Vault.
    pub(crate) fn payload_for_wire(&self) -> Result<&'static str> {
        if self.payload_hash != payload_hash(VAULT_TO_HOT_PAYLOAD) {
            bail!(
                "the recorded funding request carries payload hash {} but this client only sends \
                 the empty payload; refusing to submit a transfer that does not match the request \
                 it is recorded as",
                self.payload_hash
            );
        }
        Ok(VAULT_TO_HOT_PAYLOAD)
    }
}

/// sha256 of a transfer payload, hex.
pub(crate) fn payload_hash(payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}

/// What the chain proved about a request that is no longer in the Vault's queue.
/// Recorded so the conclusion can be audited later: "the client decided this had executed" is not
/// the same claim as "the chain showed this executed, here is what it showed".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FundingEvidence {
    /// What the evidence establishes, in one word, for the record and for the operator.
    pub(crate) verdict: String,
    /// Where it came from - the finalized message or transaction that carried it.
    pub(crate) source: String,
    /// The chain time the evidence was observed at, when the source carries one.
    pub(crate) observed_at_unix: Option<u64>,
    /// A human-readable rendering of the fact itself.
    pub(crate) detail: String,
}

/// Whether a funding request matching [`FundingRequest`] is on chain.
/// These are not two answers plus an error. Both `Unknown` and the two disappearance verdicts are
/// load-bearing: the specification says a chain read failure means "unknown" and forbids a repeat
/// submit, and it says that a request leaving the live queue proves nothing on its own - only
/// finalized history can say whether it executed or expired, and those two are opposite in money
/// terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RequestPresence {
    /// Proven present in the Vault's queue. Carries whatever identifiers the queue exposed.
    Present {
        transaction_hash: Option<String>,
        pending_transaction_id: Option<String>,
    },
    /// Gone from the queue, and finalized history proves it EXECUTED. The money left the Vault.
    /// Never permits a submit: a second one here is the double transfer.
    Executed { evidence: FundingEvidence },
    /// Gone from the queue, and finalized history proves it expired WITHOUT executing. The money
    /// never left the Vault, so a fresh request is the only way the Hot is ever funded.
    ExpiredUnexecuted { evidence: FundingEvidence },
    /// Proven absent, with nothing of ours ever having been in the queue. This and
    /// [`RequestPresence::ExpiredUnexecuted`] are the only answers that permit a submit.
    Absent,
    /// Could not be established. Never permits a submit.
    Unknown { reason: String },
}

/// The result of asking a provider to create the funding request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SubmitOutcome {
    /// The request is proven to be on chain, with whatever identifiers were returned.
    Accepted {
        transaction_hash: Option<String>,
        pending_transaction_id: Option<String>,
    },
    /// The submit's result could not be established. The journal stays at `prepared` and no second
    /// submit is made; the next run reconciles.
    Indeterminate { reason: String },
}

/// A provider's half of the funding flow.
#[async_trait::async_trait(?Send)]
pub(crate) trait HotFundingProvider {
    /// Which provider this is. Checked against the journal so a run cannot continue a request that
    /// a different provider created.
    fn provider(&self) -> WalletProvider;

    /// Keep the provider's chain probe aligned with the journal the mechanism just read.
    /// Normally this is the same record supplied when the production provider is constructed. A
    /// request may also be created while one command is waiting, though, so the provider must see
    /// that newly written queue id before the final balance observation is allowed to retire it.
    fn refresh_recorded_request(&self, _recorded: Option<RecordedRequest>) {}

    /// Prove whether a request matching `request` is already on chain.
    /// Only called for a provider whose [`WalletProvider::creates_vault_request`] is true.
    /// Returning `Absent` is a claim that the queue was read, that nothing of ours is in it AND
    /// that nothing of ours was ever there; a request that HAS been there and is now gone must come
    /// back as `Executed`, `ExpiredUnexecuted` or `Unknown`, never as `Absent`.
    /// What an earlier run recorded - the frozen fingerprint and, once the chain has ever reported
    /// one, the pending transaction id that is the primary key from then on - reaches a provider
    /// through its constructor as a [`RecordedRequest`], not through this call. The production
    /// caller reads the journal under the same held turn this runs under, so the two readings
    /// cannot disagree.
    async fn probe_existing_request(&self, request: &FundingRequest) -> Result<RequestPresence>;

    /// Create the request on chain.
    async fn create_request(&self, request: &FundingRequest) -> Result<SubmitOutcome>;

    /// What to tell the operator when there is no request to create - the Gosh.ai link, or the
    /// manual shortfall and Hot address.
    fn manual_instruction(&self, request: &FundingRequest) -> String;
}

/// What an earlier run recorded about the request it may have put on chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordedRequest {
    /// The generation this request belongs to.
    pub(crate) generation: u32,
    /// The frozen transfer identity.
    pub(crate) fingerprint: FundingFingerprint,
    /// The queue id, once the chain has ever reported one. From that moment it is the primary key
    /// and the fingerprint is the corroboration, exactly as the specification fixes it.
    pub(crate) pending_transaction_id: Option<String>,
    /// The transaction hash of our own submit, when its receipt was seen.
    pub(crate) transaction_hash: Option<String>,
    /// When the record was opened, in local unix seconds. Diagnostic only: no decision is taken
    /// from it, because a local clock is not chain evidence.
    pub(crate) created_at_unix: u64,
}

// ---------------------------------------------------------------------------------------------
// The durable journal
// ---------------------------------------------------------------------------------------------

/// The states one funding request moves through.
/// `Prepared` is written and flushed BEFORE any `submitTransaction`, and that ordering is the whole
/// basis of repeat safety - see [`ensure_hot_funded`]. For a provider that never creates a request
/// it degenerates to "an open funding need for this Hot", which is a superset of the same meaning
/// and keeps one state machine instead of two.
/// `Executed` and `Expired` are the two ways a request leaves the Vault's queue, and they are
/// opposite in money terms: `Executed` means the transfer left the Vault and a second one would be
/// a double transfer; `Expired` means it never left, so the Hot will not be funded unless a fresh
/// request is made. Neither is ever concluded from the request's absence - only from finalized
/// chain evidence, which is retained on the record as [`FundingEvidence`].
/// `Satisfied` is reached from any of the others and only ever by an observed Hot balance that
/// meets the requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum FundingState {
    Prepared,
    Submitted,
    Executed,
    Expired,
    Satisfied,
}

/// One Hot's funding record. Non-secret by construction: addresses, a public key, amounts, states
/// and timestamps. No key material and no seed phrase ever reaches this file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FundingJournalRecord {
    pub(crate) version: u32,
    /// Which attempt at funding this Hot the record describes.
    /// A generation is the unit over which the shortfall and the fingerprint are frozen. It is
    /// incremented in exactly one circumstance: the previous generation was PROVEN to have expired
    /// without executing. It is never incremented because the shortfall was recomputed, because a
    /// wait timed out, or because the request is no longer visible - each of those would let a
    /// recomputed amount create a second live request while the first is still confirmable.
    pub(crate) generation: u32,
    pub(crate) provider: WalletProvider,
    pub(crate) network: String,
    pub(crate) vault_address: Option<String>,
    pub(crate) hot_address: String,
    pub(crate) creator_pubkey: String,
    pub(crate) required: BTreeMap<u32, u128>,
    pub(crate) shortfall: BTreeMap<u32, u128>,
    /// The frozen identity of this generation's transfer.
    pub(crate) fingerprint: FundingFingerprint,
    pub(crate) state: FundingState,
    pub(crate) transaction_hash: Option<String>,
    pub(crate) pending_transaction_id: Option<String>,
    /// What the chain showed about this request leaving the queue, when it has left it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) evidence: Option<FundingEvidence>,
    pub(crate) created_at_unix: u64,
    /// When the Hot's balances were last read against this record. A local timeout does not move
    /// it: it records reconciliation with the chain, not the passage of time.
    pub(crate) last_checked_at_unix: Option<u64>,
    /// The balances that closed the record. Present only in `Satisfied`, and only ever the
    /// balances that were actually read.
    pub(crate) satisfied_balances: Option<BTreeMap<u32, u128>>,
}

impl FundingJournalRecord {
    fn open(request: &FundingRequest, now: u64) -> Self {
        Self::open_generation(request, now, 1)
    }

    fn open_generation(request: &FundingRequest, now: u64, generation: u32) -> Self {
        Self {
            version: FUNDING_JOURNAL_VERSION,
            generation,
            provider: request.provider,
            network: request.network.clone(),
            vault_address: request.vault_address.clone(),
            hot_address: request.hot_address.clone(),
            creator_pubkey: request.creator_pubkey.clone(),
            required: request.required.clone(),
            shortfall: request.shortfall.clone(),
            fingerprint: FundingFingerprint::of(request, vault_to_hot_native_value()),
            state: FundingState::Prepared,
            transaction_hash: None,
            pending_transaction_id: None,
            evidence: None,
            created_at_unix: now,
            last_checked_at_unix: None,
            satisfied_balances: None,
        }
    }

    pub(crate) fn is_open(&self) -> bool {
        !matches!(self.state, FundingState::Satisfied)
    }

    /// A Vault-created generation may be retired only after finalized history proves how it left
    /// the queue. The submit may have reached the Vault even when its queue id was never observed.
    fn needs_reconciliation_before_close(&self) -> bool {
        if !self.provider.creates_vault_request() {
            return false;
        }
        match self.state {
            // Neither state is a finalized verdict. In particular, an earlier conservative
            // fallback must never make a now-visible submitted request safe to retire.
            FundingState::Prepared | FundingState::Submitted => true,
            // An execution match with no parseable id can come from a generation-invariant history
            // fallback. It may forbid a submit, but cannot prove this generation safe to forget.
            FundingState::Executed => {
                self.pending_transaction_id
                    .as_deref()
                    .and_then(|id| id.parse::<u64>().ok())
                    .is_none()
                    || self.evidence.is_none()
            }
            FundingState::Expired | FundingState::Satisfied => false,
        }
    }

    /// Whether this record still describes a request that may yet move money.
    /// `Prepared` and `Submitted` both do - a prepared record is the trace of a submit whose result
    /// was never observed, which is precisely the request that may be sitting in the queue. Only a
    /// proven expiry retires a generation.
    pub(crate) fn generation_may_still_execute(&self) -> bool {
        matches!(
            self.state,
            FundingState::Prepared | FundingState::Submitted | FundingState::Executed
        )
    }

    /// What an earlier run recorded, for the probe.
    pub(crate) fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            generation: self.generation,
            fingerprint: self.fingerprint.clone(),
            pending_transaction_id: self.pending_transaction_id.clone(),
            transaction_hash: self.transaction_hash.clone(),
            created_at_unix: self.created_at_unix,
        }
    }

    /// The request this record describes, for probing the queue on a later run.
    /// A repeat must look for the request the EARLIER run may have created, which is this one - not
    /// for whatever today's shortfall happens to be. That is precisely what the journal is for:
    /// without it the destination, creator key and exact amounts of the earlier request are not
    /// recoverable, and an unrecognisable request cannot be de-duplicated.
    pub(crate) fn recorded_funding_request(&self, hot_dapp_id: String) -> FundingRequest {
        FundingRequest {
            provider: self.provider,
            network: self.network.clone(),
            vault_address: self.vault_address.clone(),
            hot_address: self.hot_address.clone(),
            hot_dapp_id,
            creator_pubkey: self.creator_pubkey.clone(),
            required: self.required.clone(),
            shortfall: self.shortfall.clone(),
        }
    }
}

/// The native value one Vault -> Hot transfer carries.
/// The specification fixes that a single `submitTransaction` carries both halves of the shortfall -
/// native in `value`, SHELL in `cc[2]`. The commands this module serves compute their need in
/// ECC[2] only, so the native leg is not a shortfall figure but the transfer's own gas: the same
/// `NOTE_DEPLOY_SUBMIT_NATIVE_VALUE` every other multisig transfer in this client attaches, which
/// arrives in the Hot's native balance and is what the Hot then spends to act.
pub(crate) fn vault_to_hot_native_value() -> u128 {
    dexdo_core::params::NOTE_DEPLOY_SUBMIT_NATIVE_VALUE
}

/// The journal file name for one Hot: `sha256(network, hot_address)` in hex.
/// The specification writes the key as `sha256(network + hot_address)`. The two INPUTS are what it
/// fixes; a bare concatenation of them is not injective, because a network name may end in hex and
/// a canonical address begins with it, so two different(network, Hot) pairs could in principle
/// share a file. A NUL separator cannot occur in either input and makes the encoding injective,
/// which is the property the key is relied on for: one file per Hot, and never one file for two.
pub(crate) fn funding_journal_key(network: &str, hot_address: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(network.as_bytes());
    hasher.update([0u8]);
    hasher.update(hot_address.as_bytes());
    hex::encode(hasher.finalize())
}

/// `<data-dir>/wallet/funding-requests`.
pub(crate) fn funding_requests_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("wallet").join("funding-requests")
}

/// `<data-dir>/wallet/funding-requests/<key>.json`.
pub(crate) fn funding_journal_path(data_dir: &Path, network: &str, hot_address: &str) -> PathBuf {
    funding_requests_dir(data_dir).join(format!(
        "{}.json",
        funding_journal_key(network, hot_address)
    ))
}

/// Create the journal directory tree with owner-only permissions.
pub(crate) fn ensure_funding_requests_dir(data_dir: &Path) -> Result<PathBuf> {
    let dir = funding_requests_dir(data_dir);
    std::fs::create_dir_all(&dir)
        .map_err(|e| anyhow!("create funding journal directory {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [data_dir.join("wallet"), dir.clone()] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| anyhow!("restrict funding journal directory {}: {e}", path.display()),
            )?;
        }
    }
    Ok(dir)
}

/// Read the record for one Hot, if any.
pub(crate) fn load_funding_journal(
    data_dir: &Path,
    network: &str,
    hot_address: &str,
) -> Result<Option<FundingJournalRecord>> {
    let path = funding_journal_path(data_dir, network, hot_address);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => bail!("read funding journal {}: {e}", path.display()),
    };
    // The version is read BEFORE the rest, and that order matters. A record written by a newer
    // client will not have this client's shape, so deserializing first turns "a version I do not
    // understand" into "corrupt JSON" - and a record that looks corrupt invites deleting it, which
    // is precisely the record that may be the only trace of a Vault request already on chain.
    let version = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|value| value.get("version").and_then(serde_json::Value::as_u64));
    match version {
        Some(version) if version == u64::from(FUNDING_JOURNAL_VERSION) => {}
        Some(version) => bail!(
            "funding journal {} has version {version} but this client understands {}; refusing to \
             act on a record it cannot read. Do not delete it: it may be the only local trace of a \
             funding request that is already on chain.",
            path.display(),
            FUNDING_JOURNAL_VERSION
        ),
        None => bail!(
            "funding journal {} has no readable version field; refusing to act on it. Do not \
             delete it: it may be the only local trace of a funding request that is already on \
             chain.",
            path.display()
        ),
    }
    let record: FundingJournalRecord = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow!("funding journal {} is not valid JSON: {e}", path.display()))?;
    Ok(Some(record))
}

/// Write the record atomically, owner-only.
/// Atomic and flushed, both load-bearing: a `prepared` record that a crash could lose would break
/// the ordering that repeat safety rests on, and a half-written record would be unreadable exactly
/// when it is needed most.
pub(crate) fn store_funding_journal(data_dir: &Path, record: &FundingJournalRecord) -> Result<()> {
    ensure_funding_requests_dir(data_dir)?;
    let path = funding_journal_path(data_dir, &record.network, &record.hot_address);
    let bytes = serde_json::to_vec_pretty(record)
        .map_err(|e| anyhow!("serialize funding journal record: {e}"))?;
    crate::cli::note::write_private_atomic(&path, &bytes)
}

// ---------------------------------------------------------------------------------------------
// The per-Hot lock
// ---------------------------------------------------------------------------------------------

/// Serializes the final balance check and the spend that follows it, per Hot.
/// Without it two commands read the same sufficient balance at the same moment and both go on to
/// spend it.
/// In PRODUCTION this lock is not taken here. `note deploy` and `note topup` have shared one
/// funding-wallet lock since, taken before either reads anything, and they reach this module
/// through [`ensure_hot_funded_with_turn`] with [`HotTurn::AlreadyHeldByCaller`]. A second lock
/// around the same spend would serialize nothing the first does not and would deadlock the moment
/// the two keys were ever unified. The acquisition below is what a caller that holds no turn of its
/// own uses.
/// Mechanism. An OS advisory lock(`fs2`), the same call `acquire_seller_pool_lock`, the pool write
/// lock and the note-deploy prover lock already use. Advisory rather than a `create_new`
/// sentinel because of the cancel requirement: the kernel releases an advisory lock when the holder
/// dies however it died, including under SIGKILL where no `Drop` runs, so an interrupted run cannot
/// leave behind a lock that changes what the next run does. The lock FILE is left in place on
/// release, deliberately - an unlocked file carries no meaning and re-creating it costs a syscall
/// that would only add a window in which two processes both think they created it.
// Exercised by this module's own tests, not by production: both money commands reach the mechanism
// with the funding-wallet turn of already held, so nothing in production takes this second
// lock. It is kept because it is the only turn a caller that holds none of its own can take.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
pub(crate) struct HotLock {
    path: PathBuf,
    file: std::fs::File,
}

impl HotLock {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for HotLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

/// `<data-dir>/wallet/funding-requests/<key>.lock` - the journal's key, so the two name one Hot.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn hot_lock_path(data_dir: &Path, network: &str, hot_address: &str) -> PathBuf {
    funding_requests_dir(data_dir).join(format!(
        "{}.lock",
        funding_journal_key(network, hot_address)
    ))
}

fn hot_lock_is_contended(error: &std::io::Error) -> bool {
    error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
}

/// Take the per-Hot lock, waiting up to `timeout`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn acquire_hot_lock(
    data_dir: &Path,
    network: &str,
    hot_address: &str,
    timeout: Duration,
    poll: Duration,
) -> Result<HotLock> {
    ensure_funding_requests_dir(data_dir)?;
    let path = hot_lock_path(data_dir, network, hot_address);
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .map_err(|e| anyhow!("open hot wallet lock {}: {e}", path.display()))?;
    let started = std::time::Instant::now();
    let mut announced = false;
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Ok(HotLock { path, file }),
            Err(e) if hot_lock_is_contended(&e) => {
                if started.elapsed() >= timeout {
                    bail!(
                        "hot wallet busy: another dexdo command is spending from Hot \
                         {hot_address}; waited {}s for {}. Retry after that command reaches a \
                         terminal state.",
                        started.elapsed().as_secs(),
                        path.display()
                    );
                }
                if !announced {
                    eprintln!(
                        "hot funding: Hot {hot_address} is already in use locally; waiting for {} \
                         (timeout {}s)",
                        path.display(),
                        timeout.as_secs()
                    );
                    announced = true;
                }
                let remaining = timeout.saturating_sub(started.elapsed());
                std::thread::sleep(poll.min(remaining).max(Duration::from_millis(1)));
            }
            Err(e) => bail!("try lock hot wallet {}: {e}", path.display()),
        }
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------------------------
// ensure_hot_funded
// ---------------------------------------------------------------------------------------------

/// What the mechanism did about the shortfall, for the caller's output.
/// Returned rather than printed so a machine-readable caller can put it in a structured field and
/// leave stdout alone; the human line this module writes goes to stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FundingNotice {
    /// The Hot already held enough. No request, no wait.
    AlreadyFunded,
    /// A Vault request was created and is proven to be in the queue.
    RequestSubmitted,
    /// A request created by an earlier run is still in the queue. No second one was created.
    RequestAlreadyPending,
    /// An earlier request is proven to have EXECUTED. The transfer left the Vault; nothing was
    /// submitted, because a second one here would be the double transfer.
    RequestExecuted { evidence: FundingEvidence },
    /// An earlier submit's result cannot be established, so nothing was submitted. The operator is
    /// asked to re-run for reconciliation.
    RequestIndeterminate { reason: String },
    /// This provider has no request to create; the operator tops the Hot up themselves.
    ManualTopUpRequested,
}

/// Bounds for the wait. Separate from the call so a test can drive Tokio's monotonic clock.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FundingWaitBounds {
    pub(crate) timeout: Duration,
    pub(crate) poll: Duration,
    pub(crate) lock_timeout: Duration,
    pub(crate) lock_poll: Duration,
}

impl Default for FundingWaitBounds {
    fn default() -> Self {
        Self {
            timeout: dexdo_core::params::HOT_FUNDING_TIMEOUT,
            poll: dexdo_core::params::HOT_FUNDING_POLL_INTERVAL,
            lock_timeout: Duration::from_secs(dexdo_core::params::HOT_FUNDING_LOCK_TIMEOUT_SECS),
            lock_poll: dexdo_core::params::HOT_FUNDING_LOCK_POLL_INTERVAL,
        }
    }
}

/// Who holds the Hot's turn while this runs.
/// The specification requires the final balance check and the spend that follows it to be
/// serialized per Hot. It does not require that THIS module be the thing that serializes them, and
/// in production it is not: both money commands take the funding-wallet lock they have shared since
/// before they read anything at all, so the turn is already held by the time the funding flow
/// starts. Passing that fact in - rather than taking a second lock on a second key - is what keeps
/// one Hot under one turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HotTurn {
    /// Take the per-Hot lock here and hold it inside the returned [`FundedHot`].
    #[cfg_attr(not(test), allow(dead_code))]
    AcquireOwn,
    /// The caller already holds it. Nothing is locked here, and the caller must keep holding it
    /// until after it has spent.
    AlreadyHeldByCaller,
}

/// Everything one call to [`ensure_hot_funded`] needs about the caller.
/// The specification writes the entry point as `ensure_hot_funded(binding, requirements,
/// operation)`; the other three - who is asking on chain, where its durable state lives, and how
/// long it may wait - are the same for the whole call and travel together rather than as loose
/// positional arguments a caller could transpose.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HotFundingContext<'a> {
    /// The active wallet binding. Its `provider` selects the funding flow and is never guessed.
    pub(crate) binding: &'a WalletBinding,
    /// The exact need, per currency, computed by the calling operation.
    pub(crate) requirements: &'a FundingRequirements,
    /// The operation's name, for the operator-facing messages("note deploy", "note topup").
    pub(crate) operation: &'a str,
    /// The public key of the agent that creates a Vault request, recorded in the journal so a later
    /// run can recognise its own request in the queue.
    pub(crate) creator_pubkey: &'a str,
    /// The effective data directory. The journal and the per-Hot lock live under it.
    pub(crate) data_dir: &'a Path,
    pub(crate) bounds: FundingWaitBounds,
}

/// A Hot proven to hold enough, with the per-Hot turn still held.
/// When this module took the lock, it is inside on purpose. The specification asks for the final
/// check AND the spend to be serialized; handing back a value that proves the check while releasing
/// the lock would serialize only the check, and two commands would still spend the same balance.
/// The caller spends while it holds this and drops it afterwards. When the CALLER already held the
/// turn there is nothing here to hold, and the same rule falls on the caller's own lock.
#[derive(Debug)]
pub(crate) struct FundedHot {
    _lock: Option<HotLock>,
    /// The balances the final check actually read.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) observed: HotBalances,
    /// What was done about the shortfall on the way here.
    pub(crate) notice: FundingNotice,
}

/// Ensure the Hot holds `requirements`, taking the Hot's turn here.
/// Production does not use this form - see [`HotLock`] - and reaches
/// [`ensure_hot_funded_with_turn`] holding the turn it already took.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn ensure_hot_funded<R, P>(
    context: &HotFundingContext<'_>,
    reader: &R,
    provider: &P,
) -> Result<FundedHot>
where
    R: HotBalanceReader,
    P: HotFundingProvider,
{
    ensure_hot_funded_with_turn(context, HotTurn::AcquireOwn, reader, provider).await
}

/// Ensure the Hot holds `requirements`, arranging a top-up through the binding's provider if not.
/// The eight steps of the specification, in order: the caller has computed its exact need; this
/// reads the Hot's balances; if they suffice it returns; otherwise it selects the flow by
/// `binding.provider`, creates a provider-supported request or points the operator at a manual
/// top-up, waits for the balances to reach the required level, re-checks immediately before the
/// caller spends, and only then returns.
/// # The invariant a repeat rests on
/// **A funding request is created only from a state that PROVES no earlier request of ours can
/// still move money.** Three things establish that, and all three are needed:
/// 1. the `prepared` record is written and flushed BEFORE the submit, so a spend that lands while
/// this client never learns it did always leaves a record at least as advanced as `prepared` -
/// there is no window in which money moved and the journal is silent;
/// 2. from any open record, a submit needs [`RequestPresence::Absent`] or
/// [`RequestPresence::ExpiredUnexecuted`], both of which are positive facts read off the chain.
/// `Unknown` - any read failure - is neither, and forbids the submit;
/// 3. a request that has LEFT the Vault's queue is never read as absence. The specification is
/// explicit that queue disappearance alone must never authorize another submit, because
/// "executed" and "expired" look identical from the queue and are opposite in money terms. Only
/// finalized history separates them, and the verdict it gave is retained on the record.
/// The record is also what makes the probe possible at all: it carries the frozen fingerprint - the
/// creator key, destination, DApp, value, currencies, flags, bounce and payload hash - of the
/// request an earlier run may have created, and without those the request in the queue is not
/// recognisable as ours.
/// The path is pinned too. An open record carries the provider that opened it; if the binding now
/// names a different one, this refuses rather than resuming down the other provider's flow, because
/// a request the first provider created may still be pending and this run cannot reason about it.
/// # What closes the journal
/// Only an observed on-chain balance that meets every requirement. Not a timeout, not a `Ctrl-C`,
/// not a provider's own answer, and not a chain read that failed.
pub(crate) async fn ensure_hot_funded_with_turn<R, P>(
    context: &HotFundingContext<'_>,
    turn: HotTurn,
    reader: &R,
    provider: &P,
) -> Result<FundedHot>
where
    R: HotBalanceReader,
    P: HotFundingProvider,
{
    let HotFundingContext {
        binding,
        requirements,
        operation,
        creator_pubkey,
        data_dir,
        bounds,
    } = *context;

    if provider.provider() != binding.provider {
        bail!(
            "wallet funding provider mismatch: the binding names {} but the funding flow supplied \
             is {}; refusing to fund Hot {} through a provider it is not bound to",
            binding.provider.as_str(),
            provider.provider().as_str(),
            binding.hot_address
        );
    }
    let hot = binding.hot()?;
    let hot_address = hot.to_string();
    let network = binding.network.clone();
    let vault_address = binding
        .vault()?
        .map(|vault| vault.to_string())
        .or_else(|| binding.vault_address.clone());

    let started = tokio::time::Instant::now();
    let mut arranged = false;
    let mut notice = FundingNotice::AlreadyFunded;

    loop {
        // Everything that reads the balance for a decision, and everything that writes the journal,
        // happens while the Hot's turn is held. Taking it only around the spend would leave the
        // check itself unserialized, which is the race it exists to close.
        let lock = match turn {
            HotTurn::AcquireOwn => Some(acquire_hot_lock(
                data_dir,
                &network,
                &hot_address,
                bounds.lock_timeout,
                bounds.lock_poll,
            )?),
            HotTurn::AlreadyHeldByCaller => None,
        };

        let observed = reader.hot_balances(&hot).await?;
        if requirements.met_by(&observed) {
            // A sufficient balance proves the command can spend; it says nothing about a Vault
            // request that is still confirmable. Probe a recorded queue id before retiring it. If
            // finalized history proves execution or expiry, `arrange_funding` records that evidence
            // and this closes immediately. Present/unknown stays evidence-free and the close below
            // refuses, naming the request the operator must settle from the Vault's pending list.
            if let Some(record) = load_funding_journal(data_dir, &network, &hot_address)?
                .filter(FundingJournalRecord::is_open)
                .filter(FundingJournalRecord::needs_reconciliation_before_close)
            {
                if let Err(error) = arrange_funding(
                    binding,
                    requirements,
                    &observed,
                    operation,
                    creator_pubkey,
                    &hot,
                    vault_address.clone(),
                    data_dir,
                    provider,
                )
                .await
                {
                    let pending = record
                        .pending_transaction_id
                        .as_deref()
                        .unwrap_or("unknown");
                    bail!(
                        "{operation}: could not reconcile Vault -> Hot queue transaction {pending} \
                         for generation {} before retiring it ({error}). Refusing to continue while \
                         that transfer may still be confirmable. Settle it from the Vault pending \
                         list, then re-run the same command.",
                        record.generation
                    );
                }
            }
            // The only thing that ever closes a record: a read that proves the target was reached,
            // after every recorded live queue id has a finalized verdict.
            close_journal_if_open(data_dir, &network, &hot_address, &observed)?;
            return Ok(FundedHot {
                _lock: lock,
                observed,
                notice,
            });
        }

        if !arranged {
            notice = arrange_funding(
                binding,
                requirements,
                &observed,
                operation,
                creator_pubkey,
                &hot,
                vault_address.clone(),
                data_dir,
                provider,
            )
            .await?;
            arranged = true;
        }

        drop(lock);

        // Checked AFTER a full check-and-arrange pass, so a zero budget still performs one check
        // and an already-funded Hot never fails on a timeout.
        if started.elapsed() >= bounds.timeout {
            let shortfall = requirements.shortfall(&observed);
            bail!(
                "{operation}: timed out after {}s waiting for Hot {hot_address} to reach the \
                 required balance (still missing {}). Nothing was cancelled: any Vault transfer you \
                 have already confirmed stays on chain, the wallet binding, its keys and every \
                 recovery file are untouched, and the funding journal keeps what is pending. Top the \
                 Hot up and re-run the same command - it re-checks the balance and continues.",
                bounds.timeout.as_secs(),
                render_currency_amounts(&shortfall)
            );
        }
        tokio::time::sleep(bounds.poll).await;
    }
}

/// Close an open record, and only ever with the balances that were actually read.
fn close_journal_if_open(
    data_dir: &Path,
    network: &str,
    hot_address: &str,
    observed: &HotBalances,
) -> Result<()> {
    let Some(mut record) = load_funding_journal(data_dir, network, hot_address)? else {
        return Ok(());
    };
    if !record.is_open() {
        return Ok(());
    }
    if record.needs_reconciliation_before_close() {
        if let Some(pending) = record.pending_transaction_id.as_deref() {
            bail!(
                "refusing to retire funding generation {} while Vault queue transaction {pending} \
                 may still execute: the Hot balance now meets the requirement, but finalized \
                 history has not proved whether that pending transfer executed or expired. Settle \
                 it from the Vault pending list, then re-run the same command",
                record.generation
            );
        }
        // A receipt-less submit may have reached the Vault without leaving this client a queue id.
        // Keep that generation visible so a later shortfall probes it instead of signing another
        // transfer. Unlike a known live queue entry there is nothing concrete to settle from the
        // pending list, so a sufficient balance may still let the command continue; it just cannot
        // erase the unresolved generation.
        return Ok(());
    }
    record.state = FundingState::Satisfied;
    record.last_checked_at_unix = Some(unix_now_secs());
    record.satisfied_balances = Some(observed.balances.clone());
    store_funding_journal(data_dir, &record)
}

#[allow(clippy::too_many_arguments)]
async fn arrange_funding<P>(
    binding: &WalletBinding,
    requirements: &FundingRequirements,
    observed: &HotBalances,
    operation: &str,
    creator_pubkey: &str,
    hot: &CanonicalAddress,
    vault_address: Option<String>,
    data_dir: &Path,
    provider: &P,
) -> Result<FundingNotice>
where
    P: HotFundingProvider,
{
    let hot_address = hot.to_string();
    let shortfall = requirements.shortfall(observed);
    let today = FundingRequest {
        provider: binding.provider,
        network: binding.network.clone(),
        vault_address,
        hot_address: hot_address.clone(),
        // Finding(2): the Hot's own DApp, never the dexdo constant. See `FundingRequest`.
        hot_dapp_id: hot.dapp_id().to_string(),
        creator_pubkey: creator_pubkey.to_string(),
        required: requirements.required.clone(),
        shortfall: shortfall.clone(),
    };

    let existing = load_funding_journal(data_dir, &binding.network, &hot_address)?;
    let open = existing.filter(FundingJournalRecord::is_open);
    provider.refresh_recorded_request(open.as_ref().map(FundingJournalRecord::recorded_request));

    if let Some(open) = &open {
        if open.provider != binding.provider {
            bail!(
                "{operation}: the funding journal for Hot {hot_address} has an open {} request but \
                 the wallet binding now names {}. A request created by the first provider may still \
                 be pending; refusing to continue down a different provider's flow. Resolve the \
                 pending request, or re-bind after it is settled.",
                open.provider.as_str(),
                binding.provider.as_str()
            );
        }
    }

    if !binding.provider.creates_vault_request() {
        // Nothing on chain to duplicate. Record the open need so the wait and a later run share the
        // same shortfall and the same reconciliation timestamp, then point the operator at the
        // provider's own top-up.
        let record = open.unwrap_or_else(|| FundingJournalRecord::open(&today, unix_now_secs()));
        store_funding_journal(data_dir, &record)?;
        eprintln!("{}", provider.manual_instruction(&today));
        return Ok(FundingNotice::ManualTopUpRequested);
    }

    // A provider that CAN create a request. Whatever an earlier run may have put on chain is
    // described by the open record, so that is what gets probed - not today's shortfall.
    let probe_for = open
        .as_ref()
        .map(|record| record.recorded_funding_request(hot.dapp_id().to_string()))
        .unwrap_or_else(|| today.clone());
    match provider.probe_existing_request(&probe_for).await? {
        RequestPresence::Present {
            transaction_hash,
            pending_transaction_id,
        } => {
            let mut record =
                open.unwrap_or_else(|| FundingJournalRecord::open(&probe_for, unix_now_secs()));
            record.state = FundingState::Submitted;
            // `Present` is the live-queue verdict. Discard any conservative no-id `Executed`
            // fallback from an earlier read; it was allowed to forbid a submit, never to describe
            // this now-identified queue entry as finalized.
            record.evidence = None;
            record.transaction_hash = transaction_hash.or(record.transaction_hash);
            record.pending_transaction_id = pending_transaction_id.or(record.pending_transaction_id);
            record.last_checked_at_unix = Some(unix_now_secs());
            store_funding_journal(data_dir, &record)?;
            eprintln!(
                "Hot wallet funding request is pending. Confirm the pending Vault -> Hot \
                 transaction in your wallet application."
            );
            Ok(FundingNotice::RequestAlreadyPending)
        }
        RequestPresence::Executed { evidence } => {
            // The transfer LEFT the Vault. A second request here is the double transfer the whole
            // journal exists to prevent, so nothing is submitted: the money is on its way and the
            // wait is what observes it arriving.
            let mut record =
                open.unwrap_or_else(|| FundingJournalRecord::open(&probe_for, unix_now_secs()));
            record.state = FundingState::Executed;
            record.evidence = Some(evidence.clone());
            record.last_checked_at_unix = Some(unix_now_secs());
            store_funding_journal(data_dir, &record)?;
            if requirements.met_by(observed) {
                eprintln!(
                    "{operation}: the earlier Vault -> Hot funding request for {hot_address} \
                     EXECUTED ({}), and the Hot balance already reflects enough funding. No second \
                     request was created.",
                    evidence.detail
                );
            } else {
                eprintln!(
                    "{operation}: the earlier Vault -> Hot funding request for {hot_address} is no \
                     longer queued because it EXECUTED ({}). No second request was created. Waiting \
                     for the transferred balance to appear on the Hot.",
                    evidence.detail
                );
            }
            Ok(FundingNotice::RequestExecuted { evidence })
        }
        RequestPresence::ExpiredUnexecuted { evidence } => {
            // Proven to have left the queue WITHOUT moving money. This is the one circumstance in
            // which a new generation may be opened: the previous one can no longer execute, so a
            // fresh request cannot be a second transfer. The retired generation's verdict is kept
            // on the way past, then the new generation is written `prepared` and flushed before the
            // submit, exactly as the first one was.
            let retired = open.as_ref().map_or(1, |record| record.generation);
            if let Some(record) = &open {
                let mut closing = record.clone();
                closing.state = FundingState::Expired;
                closing.evidence = Some(evidence.clone());
                closing.last_checked_at_unix = Some(unix_now_secs());
                store_funding_journal(data_dir, &closing)?;
            }
            if requirements.met_by(observed) {
                eprintln!(
                    "{operation}: the earlier Vault -> Hot funding request for {hot_address} \
                     expired without executing ({}), but the Hot balance already meets this \
                     command's requirement. No fresh request was created.",
                    evidence.detail
                );
                return Ok(FundingNotice::AlreadyFunded);
            }
            eprintln!(
                "{operation}: the earlier Vault -> Hot funding request for {hot_address} expired \
                 without executing ({}). No money left the Vault, so a fresh request is being \
                 created.",
                evidence.detail
            );
            submit_new_request(data_dir, &today, operation, &hot_address, retired + 1, provider)
                .await
        }
        RequestPresence::Unknown { reason } => {
            // Not proven absent, so not submittable. The record keeps whatever state the chain last
            // proved; nothing here advances it.
            eprintln!(
                "{operation}: cannot establish whether an earlier Vault -> Hot funding request for \
                 {hot_address} exists ({reason}). Not submitting another one. Re-run the same \
                 command to reconcile once the chain is readable."
            );
            Ok(FundingNotice::RequestIndeterminate { reason })
        }
        RequestPresence::Absent => {
            // Proven absent, and nothing of ours was ever queued. A generation that could still
            // execute must never be overwritten from here: `Absent` for a record already carrying a
            // request would be the provider contradicting itself, and the safe reading of a
            // contradiction is "unknown".
            if let Some(record) = &open {
                if record.generation_may_still_execute() && record.pending_transaction_id.is_some() {
                    let reason = format!(
                        "the queue reports no request while the journal holds pending transaction \
                         {} for generation {}",
                        record
                            .pending_transaction_id
                            .as_deref()
                            .unwrap_or("<unknown>"),
                        record.generation
                    );
                    eprintln!(
                        "{operation}: refusing to create a second Vault -> Hot funding request for \
                         {hot_address}: {reason}. A request that has been in the queue and is no \
                         longer there must be proven executed or expired from finalized history, \
                         never read as absence. Re-run the same command to reconcile."
                    );
                    return Ok(FundingNotice::RequestIndeterminate { reason });
                }
            }
            if requirements.met_by(observed) {
                return Ok(FundingNotice::AlreadyFunded);
            }
            let generation = open.as_ref().map_or(1, |record| record.generation);
            submit_new_request(data_dir, &today, operation, &hot_address, generation, provider).await
        }
    }
}

/// Write `prepared` for `generation`, flush it, and only then submit.
/// From the moment the record is on disk, a submit whose result is never observed still leaves a
/// trace - which is what the next run reconciles against. Nothing about this ordering is negotiable:
/// it is the only thing standing between "the client crashed mid-submit" and "the client has no idea
/// a transfer is queued".
async fn submit_new_request<P>(
    data_dir: &Path,
    request: &FundingRequest,
    operation: &str,
    hot_address: &str,
    generation: u32,
    provider: &P,
) -> Result<FundingNotice>
where
    P: HotFundingProvider,
{
    let record = FundingJournalRecord::open_generation(request, unix_now_secs(), generation);
    store_funding_journal(data_dir, &record)?;
    match provider.create_request(request).await? {
        SubmitOutcome::Accepted {
            transaction_hash,
            pending_transaction_id,
        } => {
            let mut record = record;
            record.state = FundingState::Submitted;
            record.transaction_hash = transaction_hash;
            record.pending_transaction_id = pending_transaction_id;
            record.last_checked_at_unix = Some(unix_now_secs());
            store_funding_journal(data_dir, &record)?;
            eprintln!(
                "Hot wallet funding request submitted. Confirm the pending Vault -> Hot \
                 transaction in Acki Nacki Wallet."
            );
            Ok(FundingNotice::RequestSubmitted)
        }
        SubmitOutcome::Indeterminate { reason } => {
            // Left at `prepared` on purpose. The next run probes before it submits, which is
            // exactly what an unresolved submit needs.
            eprintln!(
                "{operation}: the Vault -> Hot funding request for {hot_address} was sent but its \
                 result could not be established ({reason}). It is recorded as prepared and no \
                 second request will be created. Re-run the same command to reconcile."
            );
            Ok(FundingNotice::RequestIndeterminate { reason })
        }
    }
}

fn render_currency_amounts(amounts: &BTreeMap<u32, u128>) -> String {
    if amounts.is_empty() {
        return "nothing".to_string();
    }
    amounts
        .iter()
        .map(|(currency, amount)| format!("{amount} of currency {currency}"))
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------------------------
// The real chain reader
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "shellnet")]
#[async_trait::async_trait(?Send)]
impl HotBalanceReader for dexdo_core::ChainClient {
    async fn hot_balances(&self, hot: &CanonicalAddress) -> Result<HotBalances> {
        let address = dexdo_core::Address::parse(&hot.legacy())
            .map_err(|e| anyhow!("Hot {hot} is not a chain address: {e:?}"))?;
        let account = self
            .get_account(&address)
            .await
            .map_err(|e| anyhow!("read Hot {hot} balances: {e}"))?
            .ok_or_else(|| anyhow!("Hot {hot} not found on chain"))?;
        if !account.is_active() {
            bail!("Hot {hot} is not Active (acc_type={})", account.status);
        }
        Ok(HotBalances::new(account.ecc))
    }
}

/// The production providers: one per `WalletProvider`.
pub(crate) mod providers;

// ---------------------------------------------------------------------------------------------
// The entry point the money commands call
// ---------------------------------------------------------------------------------------------

/// Ensure the bound Hot can pay for `operation`, arranging a top-up through its provider if not.
/// This is what `note deploy` and `note topup` call. Three things about its shape are deliberate.
/// **It is a no-op without a binding.** `--multisig-address` wins over the binding and is used
/// exactly as given(`resolve_funding_wallet`), so a wallet passed on the command line has no
/// recorded provider - and the specification forbids inferring one, because different providers hand
/// out the same canonical contract. With nothing to infer from there is no funding flow to choose,
/// so the command keeps the insufficient-balance refusal it has always had. `Ok(None)` is that case.
/// **The Hot's turn is already held.** Both callers take the funding-wallet lock they have shared
/// since before they read anything, so the check and the spend are already serialized under
/// one key. Taking a second lock here would serialize nothing the first does not.
/// **It does not do the final check.** Step 7 of the specification - re-read the balance immediately
/// before sending - is the caller's own preflight, which runs next and still refuses on its own
/// terms. This returns once the balance HAS been observed to meet the requirement; the caller then
/// proves it again against the figure it is about to spend.
#[cfg(feature = "shellnet")]
pub(crate) async fn fund_hot_for_money_command(
    client: &dexdo_core::ChainClient,
    endpoint: &str,
    binding: Option<&crate::cli::wallet::WalletBinding>,
    requirements: FundingRequirements,
    operation: &str,
    funding_timeout: Option<Duration>,
) -> Result<Option<FundingNotice>> {
    use providers::{AckinackiVaultProvider, DirectTopUpProvider, RealVaultChain};

    let Some(active) = binding else {
        return Ok(None);
    };
    let view = HotFundingBinding::from_active(active);
    let hot_address = view.hot()?.to_string();
    let data_dir = crate::cli::data_dir::effective()?;
    let bounds = FundingWaitBounds {
        timeout: funding_timeout.unwrap_or(dexdo_core::params::HOT_FUNDING_TIMEOUT),
        ..FundingWaitBounds::default()
    };

    // What an earlier run recorded, read under the turn this runs under, so the record the provider
    // reconciles against and the record the mechanism writes cannot be two different readings.
    let recorded = load_funding_journal(&data_dir, &view.network, &hot_address)?
        .filter(FundingJournalRecord::is_open)
        .map(|record| record.recorded_request());

    if !active.provider.creates_vault_request() {
        // No Vault, so no request and no creator: the operator tops the Hot up and the wait
        // observes it. The journal still records the open need, which is what keeps one shortfall
        // and one reconciliation timestamp across a repeat of the command.
        let provider = DirectTopUpProvider::new(active.provider)?;
        let funded = ensure_hot_funded_with_turn(
            &HotFundingContext {
                binding: &view,
                requirements: &requirements,
                operation,
                creator_pubkey: "",
                data_dir: &data_dir,
                bounds,
            },
            HotTurn::AlreadyHeldByCaller,
            client,
            &provider,
        )
        .await?;
        return Ok(Some(funded.notice));
    }

    let vault = view.vault()?.ok_or_else(|| {
        anyhow!(
            "wallet binding {} names provider `{}` but records no Vault address, so there is \
             nothing to ask for a Hot top-up. Re-bind with `dexdo wallet rebind ackinacki-wallet`.",
            active.id,
            active.provider
        )
    })?;
    // The custodian key the Vault request is signed with. A separately generated `--vault-key` is
    // preferred when the binding retained one; otherwise it is the Hot key, which is exactly what
    // onboarding validated the Vault's custodian set against when no separate Vault key was given.
    let vault_key = active
        .vault_key_file
        .clone()
        .or_else(|| active.hot_key_file.clone());
    let vault_seed = if active.vault_key_file.is_some() {
        None
    } else {
        active.hot_seed_file.clone()
    };
    if vault_key.is_none() && vault_seed.is_none() {
        bail!(
            "wallet binding {} (provider `{}`) records no local key for Vault {vault}, so this \
             instance cannot sign the Vault -> Hot top-up request. Re-bind with a provider flow \
             that stores one.",
            active.id,
            active.provider
        );
    }
    let (source, secret_hex) = crate::cli::commands::multisig_secret_hex(&vault_key, &vault_seed)?;
    let keys = dexdo_core::KeyPair::from_secret_hex(secret_hex.trim())
        .map_err(|e| anyhow!("{source} (SDK secret hex): {e:?}"))?;
    let creator_pubkey = keys.public_hex().to_string();
    let chain = RealVaultChain::new(client, endpoint, vault, keys)?;
    let provider = AckinackiVaultProvider::new(chain, recorded);
    let funded = ensure_hot_funded_with_turn(
        &HotFundingContext {
            binding: &view,
            requirements: &requirements,
            operation,
            creator_pubkey: &creator_pubkey,
            data_dir: &data_dir,
            bounds,
        },
        HotTurn::AlreadyHeldByCaller,
        client,
        &provider,
    )
    .await?;
    Ok(Some(funded.notice))
}

#[cfg(test)]
mod tests;

/// the states a request leaves the Vault queue through, and what may follow each.
#[cfg(test)]
mod reconciliation_tests;
