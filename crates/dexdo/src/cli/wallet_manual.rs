//! Manual wallet provider: bind a Hot multisig the operator already has.
//! # Origin is recorded, never inferred
//! A wallet's provider cannot be read back off the chain -- Acki Nacki Wallet, Gosh.ai and an
//! operator's own deploy all produce the same canonical multisig. So the provider is written down
//! once, at an explicit onboarding, and never guessed afterwards. The rule that keeps it honest is
//! structural rather than a convention: [`save_active_binding`] is private to this module and takes
//! a [`VerifiedManualWallet`], which only [`verify_manual_hot_wallet`] can build. No other module
//! can name either. A working command that happens to receive `--multisig-address` and a key file
//! therefore cannot turn those flags into a binding, whatever it does with them.
//! # What is verified before anything is written
//! In this order, so the first thing an operator is told is the first thing that is wrong:
//! 1. the supplied address parses(canonical `<dapp_id>::<account_id>`, or legacy `0:<64 hex>`);
//! 2. the account exists and is `Active`;
//! 3. its `code_hash` is one of the supported multisig spending code hashes;
//! 4. `getParameters().requiredTxnConfirms == 1`;
//! 5. the public key derived from the supplied secret file is one of `getCustodians()`.
//! A binding naming a wallet we cannot sign for is worse than no binding, so all five must pass
//! before the file exists at all.
//! # What the binding stores, and what it only references
//! Stored: schema version, binding id, provider, network, and the full canonical Hot address.
//! Referenced: the absolute path of the operator's owner-only secret file, under `hot_key_file` or
//! `hot_seed_file` depending on which one it is. Never stored: the secret. The file is written
//! through the existing atomic private-write helper, so it lands 0600 by rename or not at all.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::cli::args::WalletOnboardManualArgs;

use crate::cli::wallet::BINDING_VERSION;

/// Directory holding every durable wallet artifact under the effective data dir.
const WALLET_DIR: &str = "wallet";

/// The one active binding. Replaced atomically; never merged.
const BINDING_FILE: &str = "binding.json";

// the provider vocabulary and the binding schema are PR1287's, imported rather than
// redefined. This module shipped its own copies before that type existed and its author expected
// the integrator to replace them: two shapes over one `<data-dir>/wallet/binding.json` is a file
// two types disagree about, and `network` as a free string is a binding that can claim a chain
// nothing validated.
pub(crate) use crate::cli::wallet::{WalletBinding, WalletNetwork, WalletProvider};

/// Which of the two accepted secret files the operator pointed at.
/// The distinction survives into the binding because the two are read differently: a raw 32-byte
/// secret, or a phrase that has to go through TVM derivation first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManualSecretKind {
    /// A file holding the wallet's 32-byte secret hex.
    Key,
    /// A file holding the wallet's seed phrase.
    SeedPhrase,
}

impl ManualSecretKind {
    const fn flag(self) -> &'static str {
        match self {
            Self::Key => "--multisig-key",
            Self::SeedPhrase => "--multisig-seed-file",
        }
    }
}

/// The operator's secret file: which kind it is and where it lives. The contents never enter here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ManualSecretRef {
    pub(crate) kind: ManualSecretKind,
    pub(crate) path: PathBuf,
}

/// The multisig facts one on-chain read pass yields, separated from how they were read.
/// Keeping them a plain value is what lets the whole decision below be exercised without a chain:
/// the shellnet layer only fills this in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ObservedHotWallet {
    /// `acc_type` as the account reader reports it.
    pub(crate) status: String,
    /// The deployed code hash, absent on an account that has none yet.
    pub(crate) code_hash: Option<String>,
    /// `getParameters().requiredTxnConfirms`.
    pub(crate) required_txn_confirms: u8,
    /// `getCustodians().custodians[].owner_pubkey`, as rendered by the getter.
    pub(crate) custodian_pubkeys: Vec<String>,
}

/// A Hot that passed every check in the module header, and the binding that describes it.
/// The field is private and the type is only ever produced by [`verify_manual_hot_wallet`], so
/// [`save_active_binding`] cannot be reached with an unverified wallet from anywhere.
#[derive(Debug)]
pub(crate) struct VerifiedManualWallet {
    binding: WalletBinding,
}

impl VerifiedManualWallet {
    pub(crate) fn binding(&self) -> &WalletBinding {
        &self.binding
    }
}

/// `<data-dir>/wallet/binding.json`.
pub(crate) fn active_binding_path(data_dir: &Path) -> PathBuf {
    data_dir.join(WALLET_DIR).join(BINDING_FILE)
}

/// Read the active binding, if one has been onboarded.
/// A present but unreadable binding is an error, not a `None`: silently behaving as "no wallet
/// configured" would send a working command down the fail-fast path while the operator's real Hot
/// sits recorded on disk.
pub(crate) fn load_active_binding(data_dir: &Path) -> Result<Option<WalletBinding>> {
    let path = active_binding_path(data_dir);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => bail!("read wallet binding {}: {error}", path.display()),
    };
    let binding: WalletBinding = serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("parse wallet binding {}: {error}", path.display()))?;
    if binding.version != BINDING_VERSION {
        bail!(
            "wallet binding {} has version {}, this build understands version {BINDING_VERSION}",
            path.display(),
            binding.version
        );
    }
    Ok(Some(binding))
}

/// Decide, from the facts of one read pass, whether this Hot may be bound.
/// Every rejection names what was expected and states that nothing was written, because the
/// operator's next action differs per cause: a wrong address is retyped, a wrong threshold means a
/// Vault was passed where a Hot was wanted, and a non-custodian key means the wrong file.
pub(crate) fn verify_manual_hot_wallet(
    hot_address: &str,
    network: WalletNetwork,
    secret: ManualSecretRef,
    signer_pubkey: &str,
    observed: &ObservedHotWallet,
    binding_id: String,
) -> Result<VerifiedManualWallet> {
    let address = dexdo_core::CanonicalAddress::parse(hot_address)
        .map_err(|error| anyhow::anyhow!("--multisig-address: {error}; nothing was written"))?;
    let hot = address.to_string();

    if !observed.status.eq_ignore_ascii_case("Active") {
        bail!(
            "Hot wallet {hot} is not Active (acc_type={}); an address with no deployed multisig \
             behind it cannot be bound. Deploy or fund it first, then run this command again; \
             nothing was written",
            observed.status
        );
    }

    let code_hash = observed
        .code_hash
        .as_deref()
        .map(str::trim)
        .map(|hash| {
            hash.strip_prefix("0x")
                .or_else(|| hash.strip_prefix("0X"))
                .unwrap_or(hash)
                .to_ascii_lowercase()
        })
        .ok_or_else(|| {
            anyhow::anyhow!("Hot wallet {hot} is Active but has no code_hash; nothing was written")
        })?;
    if !dexdo_core::canonical_multisig::is_supported_spending_code_hash(&code_hash) {
        bail!(
            "Hot wallet {hot} has code_hash {code_hash}, which is not a supported multisig; dexdo \
             spends only from code_hash {} or {}. Nothing was written",
            dexdo_core::canonical_multisig::LEGACY_SPENDING_CODE_HASH,
            dexdo_core::canonical_multisig::CODE_HASH,
        );
    }

    if observed.required_txn_confirms != 1 {
        bail!(
            "Hot wallet {hot} requires {} transaction confirmations; a bound Hot must have \
             reqConfirms=1, because dexdo signs its spends alone. A wallet with a higher threshold \
             is a Vault: bind the Hot it funds instead. Nothing was written",
            observed.required_txn_confirms
        );
    }

    let signer = dexdo_core::normalize_multisig_pubkey(signer_pubkey).ok_or_else(|| {
        anyhow::anyhow!(
            "{} does not yield a usable public key for Hot wallet {hot}; nothing was written",
            secret.kind.flag()
        )
    })?;
    let custodians: Vec<String> = observed
        .custodian_pubkeys
        .iter()
        .filter_map(|pubkey| dexdo_core::normalize_multisig_pubkey(pubkey))
        .collect();
    if custodians.is_empty() {
        bail!(
            "Hot wallet {hot} reports no pubkey custodians, so no local key can sign for it; \
             nothing was written"
        );
    }
    if !custodians.contains(&signer) {
        bail!(
            "the key in {} is not a custodian of Hot wallet {hot}; binding a wallet dexdo cannot \
             sign for would fail at the first spend, so nothing was written. Point {} at the \
             wallet's own custodian secret, or bind the address that key does own",
            secret.path.display(),
            secret.kind.flag()
        );
    }

    let (hot_key_file, hot_seed_file) = match secret.kind {
        ManualSecretKind::Key => (Some(secret.path.clone()), None),
        ManualSecretKind::SeedPhrase => (None, secret.path.clone().into()),
    };
    Ok(VerifiedManualWallet {
        binding: WalletBinding {
            version: BINDING_VERSION,
            id: binding_id,
            provider: WalletProvider::Manual,
            network,
            hot_address: hot,
            // Gosh.ai and manual have no Vault, and a field naming one would be a lie a later
            // funding flow could act on.
            vault_address: None,
            hot_key_file,
            vault_key_file: None,
            hot_seed_file,
            push_profile_address: None,
        },
    })
}

fn display_path(path: &Path) -> Result<String> {
    path.to_str().map(str::to_string).ok_or_else(|| {
        anyhow::anyhow!(
            "secret file path {} is not printable text, so it cannot be recorded in the binding",
            path.display()
        )
    })
}

// The binding id is NOT minted here. `wallet::WalletStore::open_draft` reserves one before any
// onboarding runs and creates the secrets directory named after it, and that is the id this flow
// must record. A second one minted at this point produced a `binding.json` naming a directory that
// did not exist while the reserved directory was referenced by nothing -- see `wallet::manual_flow`.

/// Currency and amount one operation needs the bound Hot to hold before it may spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HotFundingRequirement {
    pub(crate) currency_id: u32,
    pub(crate) required_raw: u128,
}

/// How a manual funding wait ended, with the balance the last read actually saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManualFundingOutcome {
    /// The requirement was already met, or was met while waiting.
    Funded { available_raw: u128 },
    /// The wait ran out. Nothing was submitted and nothing was written.
    TimedOut { available_raw: u128 },
}

/// The one chain fact the manual funding flow needs. Read-only on purpose: the manual provider has
/// no request to create, so it is given no way to write.
#[async_trait::async_trait(?Send)]
pub(crate) trait HotEccReader {
    async fn read_hot_ecc_raw(&self, currency_id: u32) -> Result<u128>;
}

fn ecc_label(currency_id: u32) -> String {
    if currency_id == dexdo_core::params::SHELL_CURRENCY_ID {
        "SHELL ECC[2]".to_string()
    } else {
        format!("ECC[{currency_id}]")
    }
}

/// What the operator is shown when the bound Hot is short.
/// It carries the exact figures and the full canonical address, and nothing else: the manual
/// provider creates no Vault request and points at no external service, so naming one here would
/// promise an action that does not happen.
pub(crate) fn render_manual_funding_shortfall(
    hot_address: &str,
    operation: &str,
    requirement: HotFundingRequirement,
    available_raw: u128,
    timeout: Duration,
) -> String {
    let missing_raw = requirement.required_raw.saturating_sub(available_raw);
    let currency = ecc_label(requirement.currency_id);
    format!(
        "{operation} needs {} raw {currency} in Hot wallet {hot_address}, which holds \
         {available_raw} raw: missing {missing_raw} raw.\nSend {missing_raw} raw {currency} to \
         {hot_address} yourself. This wallet is bound as provider `manual`, so dexdo creates no \
         funding request and opens no external service on your behalf; the only thing it watches \
         is the on-chain balance of that address.\nWaiting up to {} seconds for the top-up. \
         Nothing has been submitted.",
        requirement.required_raw,
        timeout.as_secs(),
    )
}

/// What the operator is shown when the wait ran out.
/// It has to say two things without either being inferable from the other: nothing was left behind,
/// and the fix is the same command again.
pub(crate) fn render_manual_funding_timeout(
    hot_address: &str,
    operation: &str,
    requirement: HotFundingRequirement,
    available_raw: u128,
    timeout: Duration,
) -> String {
    let missing_raw = requirement.required_raw.saturating_sub(available_raw);
    let currency = ecc_label(requirement.currency_id);
    format!(
        "no top-up of Hot wallet {hot_address} arrived within {} seconds; it holds {available_raw} \
         raw {currency} and {operation} needs {} raw, so {missing_raw} raw is still missing. \
         Nothing was submitted and no local state was written, so run the same command again once \
         the transfer lands -- it reads the balance from the chain again from scratch",
        timeout.as_secs(),
        requirement.required_raw,
    )
}

/// Wait for the bound Hot to hold what the operation needs.
/// Reads first and reads last: the balance decides, never a timer and never a message from a
/// wallet application. Writes nothing at any point, which is what makes the timeout safe -- a
/// second run starts from exactly the state the first one did and re-reads the chain.
pub(crate) async fn wait_for_manual_hot_funding(
    reader: &dyn HotEccReader,
    requirement: HotFundingRequirement,
    timeout: Duration,
    poll: Duration,
) -> Result<ManualFundingOutcome> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let available_raw = reader.read_hot_ecc_raw(requirement.currency_id).await?;
        if available_raw >= requirement.required_raw {
            return Ok(ManualFundingOutcome::Funded { available_raw });
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(ManualFundingOutcome::TimedOut { available_raw });
        }
        tokio::time::sleep(poll.min(deadline.duration_since(now))).await;
    }
}

/// The manual provider's half of the shared "make sure Hot can pay for this" step.
/// Success means the requirement was observed met on chain, not that a wait completed. The human
/// text goes to stderr so a machine-readable stdout stays clean.
pub(crate) async fn ensure_manual_hot_funded(
    reader: &dyn HotEccReader,
    hot_address: &str,
    operation: &str,
    requirement: HotFundingRequirement,
    timeout: Duration,
    poll: Duration,
) -> Result<u128> {
    let available_raw = reader.read_hot_ecc_raw(requirement.currency_id).await?;
    if available_raw >= requirement.required_raw {
        return Ok(available_raw);
    }
    eprintln!(
        "{}",
        render_manual_funding_shortfall(
            hot_address,
            operation,
            requirement,
            available_raw,
            timeout
        )
    );
    match wait_for_manual_hot_funding(reader, requirement, timeout, poll).await? {
        ManualFundingOutcome::Funded { available_raw } => Ok(available_raw),
        ManualFundingOutcome::TimedOut { available_raw } => bail!(
            "{}",
            render_manual_funding_timeout(
                hot_address,
                operation,
                requirement,
                available_raw,
                timeout
            )
        ),
    }
}

/// The manual provider's entry point for an operation that is about to spend the bound Hot.
/// This is the shape the shared provider-aware funding step calls: the timeout is the specification's
/// one common bound rather than a manual-only timer, and the read cadence is the one this tree
/// already uses to watch SHELL arrive at an address. An operator override(`--funding-timeout`)
/// belongs to the spending command, which passes it to [`ensure_manual_hot_funded`] directly.
pub(crate) async fn ensure_manual_hot_funded_with_defaults(
    reader: &dyn HotEccReader,
    hot_address: &str,
    operation: &str,
    requirement: HotFundingRequirement,
) -> Result<u128> {
    ensure_manual_hot_funded(
        reader,
        hot_address,
        operation,
        requirement,
        dexdo_core::params::WALLET_HOT_FUNDING_TIMEOUT,
        dexdo_core::params::NOTE_DEPLOY_SHELL_FUNDING_POLL_INTERVAL,
    )
    .await
}

/// Tell the two accepted secret files apart by what they contain.
/// Only the interactive form needs this: the automation forms say which one they mean with the
/// flag they use. It is deliberately strict rather than best-effort, because feeding a seed phrase
/// to the raw-secret reader yields a valid-looking key for a wallet nobody owns.
pub(crate) fn classify_manual_secret_file(contents: &str) -> Result<ManualSecretKind> {
    let words: Vec<&str> = contents.split_whitespace().collect();
    match words.as_slice() {
        [single]
            if single.len() == 64 && single.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            Ok(ManualSecretKind::Key)
        }
        _ if matches!(words.len(), 12 | 15 | 18 | 21 | 24)
            && words
                .iter()
                .all(|word| word.bytes().all(|byte| byte.is_ascii_alphabetic())) =>
        {
            Ok(ManualSecretKind::SeedPhrase)
        }
        _ => bail!(
            "cannot tell whether that file holds a 32-byte secret hex or a seed phrase; pass \
             --multisig-key or --multisig-seed-file to say which it is"
        ),
    }
}

/// Ask for one non-secret line on a terminal. Refuses to read when stdin is not a terminal, so an
/// automated run gets the flag list instead of blocking on a pipe.
fn prompt_line(prompt: &str, missing: &str) -> Result<String> {
    use std::io::{BufRead as _, IsTerminal as _, Write as _};
    if !std::io::stdin().is_terminal() {
        bail!(
            "`dexdo wallet onboard manual` needs {missing} when stdin is not a terminal: pass \
             --multisig-address <address> and one of --multisig-key <path> / --multisig-seed-file \
             <path>"
        );
    }
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line)? == 0 {
        bail!("{missing} was not supplied; nothing was written");
    }
    let line = line.trim().to_string();
    if line.is_empty() {
        bail!("{missing} was not supplied; nothing was written");
    }
    Ok(line)
}

/// Resolve the address either from the flag or, on a terminal, by asking.
fn resolve_manual_address(flag: Option<&str>) -> Result<String> {
    match flag {
        Some(address) => Ok(address.trim().to_string()),
        None => prompt_line(
            "Hot wallet address (<dapp_id>::<account_id>): ",
            "an address",
        ),
    }
}

#[cfg(any(feature = "shellnet", test))]
mod persist {
    use super::{
        active_binding_path, VerifiedManualWallet, WalletBinding, WALLET_DIR,
    };
    use anyhow::Result;
    use slot::EmptyBindingSlot;
    use std::path::{Path, PathBuf};

    /// The already-bound refusal, and the only place the proof that it ran can come from.
    /// [`EmptyBindingSlot`]'s field is private and this module has no child modules, so nothing
    /// outside these few lines can build one -- not `persist`, not `wallet_manual`, not a test.
    /// The writer takes one by value, which turns "every write is preceded by the already-bound
    /// refusal" into an argument the compiler will not let a caller skip. It is the same shape
    /// [`VerifiedManualWallet`] already uses for the verification half, applied to the half that
    /// decides whether the slot may be written at all.
    /// This replaces counting the writer's name in the source as the guarantee. That count read
    /// `save_active_binding` followed immediately by `(`, so a second call site written with one
    /// space before the paren contributed nothing to it and the count stayed at 2 while three
    /// places wrote the binding. A guard a space walks past is worse than none, because it reads as
    /// a guarantee in review.
    mod slot {
        use super::{already_bound, WalletBinding};
        use anyhow::Result;
        use std::path::Path;

        /// A data dir whose active-binding slot was observed empty.
        /// It carries the path rather than sitting beside it, so a caller cannot prove one
        /// directory empty and then write into another.
        pub(super) struct EmptyBindingSlot<'a>(&'a Path);

        impl<'a> EmptyBindingSlot<'a> {
            /// The directory the emptiness was observed in, and the only one it licenses.
            pub(super) fn data_dir(&self) -> &'a Path {
                self.0
            }
        }

        /// Refuse an operator who is already bound, or yield the proof that the slot is free.
        pub(super) fn refuse_if_bound<'a>(
            data_dir: &'a Path,
            existing: Option<&WalletBinding>,
        ) -> Result<EmptyBindingSlot<'a>> {
            match existing {
                Some(existing) => Err(already_bound(existing)),
                None => Ok(EmptyBindingSlot(data_dir)),
            }
        }
    }

    /// Write the one active binding, atomically and owner-only.
    /// Both arguments are proofs rather than data: a [`VerifiedManualWallet`] says the wallet
    /// passed every check, an [`EmptyBindingSlot`] says the refusal ran and found nothing to
    /// protect. Neither can be constructed by a would-be second writer, so the single call site
    /// below is a fact the compiler keeps -- widening this function's visibility would not hand
    /// another module a way to call it, because it would still have no way to build the arguments.
    fn save_active_binding(
        data_dir: EmptyBindingSlot<'_>,
        verified: &VerifiedManualWallet,
    ) -> Result<PathBuf> {
        let data_dir = data_dir.data_dir();
        let dir = data_dir.join(WALLET_DIR);
        create_owner_only_dir(&dir)?;
        let path = active_binding_path(data_dir);
        let mut bytes = serde_json::to_vec_pretty(verified.binding())
            .map_err(|error| anyhow::anyhow!("render wallet binding: {error}"))?;
        bytes.push(b'\n');
        crate::cli::note::write_private_atomic(&path, &bytes)?;
        Ok(path)
    }

    fn create_owner_only_dir(dir: &Path) -> Result<()> {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder
            .create(dir)
            .or_else(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists && dir.is_dir() {
                    Ok(())
                } else {
                    Err(error)
                }
            })
            .map_err(|error| {
                anyhow::anyhow!("create wallet directory {}: {error}", dir.display())
            })
    }

    /// The one refusal an already-bound operator gets, worded once.
    /// It is raised twice on purpose: at the top of onboarding, so no chain read or prompt is spent
    /// on a command that was never going to write, and again here, so the check that guards the
    /// write is the write's own.
    pub(crate) fn already_bound(existing: &WalletBinding) -> anyhow::Error {
        // The wallet specification points the operator at a rebind command here. It is another
        // agent's half of and does not exist yet, and this tree rejects a printed command line
        // its own parser cannot run -- rightly, since a name that does not resolve is a dead end.
        // So the replacement is described rather than named until that command ships.
        anyhow::anyhow!(
            "a wallet is already bound: provider `{}`, Hot {}. Onboarding never replaces an active \
             binding, because the old Hot may still hold funds; replacing it is a separate, \
             explicit rebind operation. Nothing was written",
            existing.provider.as_str(),
            existing.hot_address
        )
    }

    /// Refuse to replace an existing binding, then save the verified one.
    /// The refusal is not a step this function is trusted to remember: it is where the writer's
    /// argument comes from, so a version of this that forgot it would not compile.
    pub(crate) fn onboard_manual_binding(
        data_dir: &Path,
        existing: Option<&WalletBinding>,
        verified: &VerifiedManualWallet,
    ) -> Result<PathBuf> {
        let data_dir = slot::refuse_if_bound(data_dir, existing)?;
        save_active_binding(data_dir, verified)
    }
}

#[cfg(any(feature = "shellnet", test))]
pub(crate) use persist::onboard_manual_binding;

#[cfg(feature = "shellnet")]
mod shellnet {
    use super::{
        classify_manual_secret_file, prompt_line, resolve_manual_address, verify_manual_hot_wallet,
        ManualSecretKind, ManualSecretRef, ObservedHotWallet, WalletBinding, WalletNetwork,
        WalletOnboardManualArgs,
    };
    use anyhow::{bail, Result};
    use dexdo_core::shellnet::RetryingReads as _;
    use std::path::PathBuf;

    /// Read every fact the decision needs from one Active multisig.
    async fn observe_hot_wallet(
        client: &dexdo_core::ChainClient,
        address: &dexdo_core::Address,
    ) -> Result<ObservedHotWallet> {
        let rendered = address.with_workchain();
        let account = client
            .get_account_retrying(address)
            .await
            .map_err(|error| anyhow::anyhow!("read Hot wallet {rendered}: {error}"))?;
        let Some(account) = account else {
            return Ok(ObservedHotWallet {
                status: "NotFound".to_string(),
                code_hash: None,
                required_txn_confirms: 0,
                custodian_pubkeys: Vec::new(),
            });
        };
        if !account.is_active() {
            return Ok(ObservedHotWallet {
                status: account.status,
                code_hash: account.code_hash,
                required_txn_confirms: 0,
                custodian_pubkeys: Vec::new(),
            });
        }
        let custodians = client
            .run_getter_retrying(
                address,
                dexdo_core::canonical_multisig::MULTISIG_ABI_JSON,
                "getCustodians",
                serde_json::json!({}),
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!("read custodians of Hot wallet {rendered}: {error}")
            })?;
        let parameters = client
            .run_getter_retrying(
                address,
                dexdo_core::canonical_multisig::MULTISIG_ABI_JSON,
                "getParameters",
                serde_json::json!({}),
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!("read transaction threshold of Hot wallet {rendered}: {error}")
            })?;
        let required_txn_confirms = parameters
            .as_ref()
            .and_then(|output| output.get("requiredTxnConfirms"))
            .and_then(|value| {
                value
                    .as_u64()
                    .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
            })
            .and_then(|value| u8::try_from(value).ok())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Hot wallet {rendered} is Active, but getParameters returned no usable \
                     requiredTxnConfirms (ABI/getter output mismatch); nothing was written"
                )
            })?;
        let custodian_pubkeys = custodians
            .as_ref()
            .and_then(|output| output.get("custodians"))
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Hot wallet {rendered} is Active, but getCustodians returned no `custodians` \
                     array (ABI/getter output mismatch); nothing was written"
                )
            })?
            .iter()
            .filter_map(|custodian| custodian.get("owner_pubkey"))
            .filter_map(serde_json::Value::as_str)
            .map(str::to_string)
            .collect();
        Ok(ObservedHotWallet {
            status: account.status,
            code_hash: account.code_hash,
            required_txn_confirms,
            custodian_pubkeys,
        })
    }

    /// Pick the secret file from the flags, or ask for one and read what kind it is.
    fn resolve_manual_secret(args: &WalletOnboardManualArgs) -> Result<ManualSecretRef> {
        let path = match (&args.multisig_key, &args.multisig_seed_file) {
            (Some(_), Some(_)) => bail!("use only one of --multisig-key or --multisig-seed-file"),
            (Some(path), None) => {
                return Ok(ManualSecretRef {
                    kind: ManualSecretKind::Key,
                    path: path.clone(),
                })
            }
            (None, Some(path)) => {
                return Ok(ManualSecretRef {
                    kind: ManualSecretKind::SeedPhrase,
                    path: path.clone(),
                })
            }
            (None, None) => PathBuf::from(prompt_line(
                "Path to the wallet secret file (32-byte secret hex, or a seed phrase): ",
                "a secret file path",
            )?),
        };
        let contents = std::fs::read_to_string(&path)
            .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
        let kind = classify_manual_secret_file(&contents)?;
        Ok(ManualSecretRef { kind, path })
    }

    /// Render the address the way the binding will store it: the DApp id comes from the chain, not
    /// from an assumption, because a wallet does not have to live in the dexdo DApp.
    async fn canonical_hot_address(
        chain: &dexdo_core::ChainClient,
        address: &dexdo_core::Address,
        supplied: &str,
    ) -> Result<String> {
        if supplied.contains("::") {
            return dexdo_core::CanonicalAddress::parse(supplied)
                .map(|address| address.to_string())
                .map_err(|error| anyhow::anyhow!("--multisig-address: {error}"));
        }
        crate::cli::note_cmd::operator_wallet_canonical_address(chain, address)
            .await
            .map(|address| address.to_string())
    }

    /// Verify the operator's Hot and return the binding it proved. It does NOT write.
    /// `run_selected` already refuses an existing binding before this is reached, and commits what
    /// this returns through `WalletStore`, which archives whatever it replaces. This module's own
    /// `persist` half keeps its tests and its single-call-site guarantee; production simply no
    /// longer has a second writer of `<data-dir>/wallet/binding.json`, because two writers is how
    /// the only local record of a Hot that still holds funds gets renamed away.
    /// `binding_id` is the id `WalletStore::open_draft` reserved for this attempt, and it is
    /// recorded verbatim. It is a parameter rather than something minted here so that the id in
    /// `binding.json` is the same one the reserved secrets directory is named after.
    pub(crate) async fn run(
        args: WalletOnboardManualArgs,
        binding_id: &str,
    ) -> Result<WalletBinding> {
        let supplied_address = resolve_manual_address(args.multisig_address.as_deref())?;
        let secret = resolve_manual_secret(&args)?;
        let (key_file, seed_file) = match secret.kind {
            ManualSecretKind::Key => (Some(secret.path.clone()), None),
            ManualSecretKind::SeedPhrase => (None, Some(secret.path.clone())),
        };
        let (_, secret_hex) = crate::cli::commands::multisig_secret_hex(&key_file, &seed_file)?;
        let keys = dexdo_core::KeyPair::from_secret_hex(secret_hex.trim())
            .map_err(|error| anyhow::anyhow!("{}: {error:?}", secret.kind.flag()))?;

        // Verification is three read-only account queries against the selected network, and the
        // deployed-contracts manifest names none of the accounts they read: the Hot's address comes
        // from the operator and its DApp id from the chain. So the endpoint is the whole input, the
        // same one `wallet onboard ackinacki-wallet` connects with.
        let endpoint =
            crate::cli::wallet::wallet_read_endpoint(args.endpoint.as_deref(), args.network.into())?;
        let chain = dexdo_core::ChainClient::connect(&endpoint)
            .map_err(|error| anyhow::anyhow!("connect verification endpoint {endpoint}: {error}"))?;
        let address = dexdo_core::address::parse_chain_address(&supplied_address)?;
        let observed = observe_hot_wallet(&chain, &address).await?;
        let hot_address = canonical_hot_address(&chain, &address, &supplied_address).await?;

        let secret_path = crate::cli::note::resolve_private_file_path(&secret.path, "secret file")?;
        let verified = verify_manual_hot_wallet(
            &hot_address,
            match args.network {
                crate::cli::args::WalletNetworkArg::Shellnet => WalletNetwork::Shellnet,
                crate::cli::args::WalletNetworkArg::Mainnet => WalletNetwork::Mainnet,
            },
            ManualSecretRef {
                kind: secret.kind,
                path: secret_path,
            },
            keys.public_hex(),
            &observed,
            binding_id.to_string(),
        )?;
        println!(
            "secret file (referenced, never copied): {}",
            verified
                .binding()
                .hot_key_file
                .as_deref()
                .or(verified.binding().hot_seed_file.as_deref())
                .unwrap_or(std::path::Path::new("-"))
                .display()
        );
        Ok(verified.binding().clone())
    }

}

/// The ECC reader the manual funding wait uses against a real Hot.
#[cfg(feature = "shellnet")]
pub(crate) struct ChainHotEccReader<'a> {
    client: &'a dexdo_core::ChainClient,
    address: dexdo_core::Address,
}

#[cfg(feature = "shellnet")]
impl<'a> ChainHotEccReader<'a> {
    pub(crate) fn new(client: &'a dexdo_core::ChainClient, address: dexdo_core::Address) -> Self {
        Self { client, address }
    }
}

#[cfg(feature = "shellnet")]
#[async_trait::async_trait(?Send)]
impl HotEccReader for ChainHotEccReader<'_> {
    async fn read_hot_ecc_raw(&self, currency_id: u32) -> Result<u128> {
        use dexdo_core::shellnet::RetryingReads as _;

        let rendered = self.address.with_workchain();
        let account = self
            .client
            .get_account_retrying(&self.address)
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "read {} of Hot wallet {rendered}: {error}",
                    ecc_label(currency_id)
                )
            })?
            .ok_or_else(|| anyhow::anyhow!("Hot wallet {rendered} not found"))?;
        Ok(account.ecc_balance(currency_id))
    }
}

#[cfg(feature = "shellnet")]
pub(crate) async fn run_wallet_onboard_manual(
    args: WalletOnboardManualArgs,
    binding_id: &str,
) -> Result<WalletBinding> {
    shellnet::run(args, binding_id).await
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_wallet_onboard_manual(
    _args: WalletOnboardManualArgs,
    _binding_id: &str,
) -> Result<WalletBinding> {
    bail!("wallet onboard manual requires the `shellnet` feature")
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOT: &str = "0000000000000000000000000000000000000000000000000000000000000004::\
                       1111111111111111111111111111111111111111111111111111111111111111";
    const OWNER_PUBKEY: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const STRANGER_PUBKEY: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SECRET_HEX: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn supported_wallet() -> ObservedHotWallet {
        ObservedHotWallet {
            status: "Active".to_string(),
            code_hash: Some(dexdo_core::canonical_multisig::CODE_HASH.to_string()),
            required_txn_confirms: 1,
            custodian_pubkeys: vec![format!("0x{OWNER_PUBKEY}")],
        }
    }

    fn key_file(dir: &Path) -> ManualSecretRef {
        let path = dir.join("hot.key");
        std::fs::write(&path, SECRET_HEX).expect("write test key file");
        ManualSecretRef {
            kind: ManualSecretKind::Key,
            path,
        }
    }

    fn bind(
        data_dir: &Path,
        secret: ManualSecretRef,
        signer: &str,
        observed: &ObservedHotWallet,
    ) -> Result<PathBuf> {
        let verified = verify_manual_hot_wallet(
            HOT,
            WalletNetwork::Shellnet,
            secret,
            signer,
            observed,
            "0123456789abcdef0123456789abcdef".to_string(),
        )?;
        onboard_manual_binding(data_dir, load_active_binding(data_dir)?.as_ref(), &verified)
    }

    /// The positive control for every "nothing was saved" case below, and the shape the binding
    /// promises: the address plus a reference, with the secret only ever on the operator's disk.
    #[test]
    fn a_verified_wallet_is_bound_by_address_and_secret_file_reference() {
        let temp = tempfile::tempdir().expect("temp root");
        let secret = key_file(temp.path());
        let path = bind(temp.path(), secret.clone(), OWNER_PUBKEY, &supported_wallet())
            .expect("a verified manual wallet binds");

        let raw = std::fs::read_to_string(&path).expect("read binding");
        let binding: WalletBinding = serde_json::from_str(&raw).expect("parse binding");
        assert_eq!(binding.provider, WalletProvider::Manual);
        assert_eq!(binding.version, 1);
        assert_eq!(binding.network, WalletNetwork::Shellnet);
        assert_eq!(binding.hot_address, HOT);
        assert_eq!(
            binding.hot_key_file.as_deref(),
            secret.path.to_str().map(std::path::Path::new),
            "the binding must reference the operator's own secret file"
        );
        assert_eq!(binding.hot_seed_file, None);
        assert_eq!(load_active_binding(temp.path()).expect("reload"), Some(binding));
    }

    /// The secret is the one thing that must never travel into the binding, so assert on the raw
    /// bytes rather than on the parsed fields: a future field would not be caught by the latter.
    #[test]
    fn the_secret_never_appears_inside_the_binding_file() {
        let temp = tempfile::tempdir().expect("temp root");
        let secret = key_file(temp.path());
        let path = bind(temp.path(), secret, OWNER_PUBKEY, &supported_wallet()).expect("bind");
        let raw = std::fs::read_to_string(&path).expect("read binding");
        assert!(
            !raw.contains(SECRET_HEX),
            "the binding copied the secret instead of referencing its file:\n{raw}"
        );
        assert!(
            raw.contains("hot.key"),
            "the binding must still reference the file:\n{raw}"
        );
    }

    /// The check the whole provider exists for: a key that does not own the wallet is refused, and
    /// the refusal leaves no binding for a later command to trust.
    #[test]
    fn a_key_that_does_not_belong_is_refused_and_nothing_is_saved() {
        let temp = tempfile::tempdir().expect("temp root");
        let secret = key_file(temp.path());
        let error = bind(
            temp.path(),
            secret,
            STRANGER_PUBKEY,
            &supported_wallet(),
        )
        .expect_err("a non-custodian key must be refused");
        let message = format!("{error}");
        assert!(
            message.contains("is not a custodian"),
            "unexpected refusal: {message}"
        );
        assert!(
            message.contains("nothing was written"),
            "the refusal must say nothing was written: {message}"
        );
        assert!(!active_binding_path(temp.path()).exists());
        assert!(!temp.path().join("wallet").exists());
        assert_eq!(load_active_binding(temp.path()).expect("reload"), None);
    }

    /// A wallet with no pubkey custodians can never be signed for, so it is refused before the
    /// signer is even compared.
    #[test]
    fn a_wallet_without_pubkey_custodians_is_refused() {
        let temp = tempfile::tempdir().expect("temp root");
        let secret = key_file(temp.path());
        let mut observed = supported_wallet();
        observed.custodian_pubkeys = vec!["not-a-key".to_string()];
        let error = bind(temp.path(), secret, OWNER_PUBKEY, &observed).expect_err("refused");
        assert!(format!("{error}").contains("no pubkey custodians"));
        assert!(!active_binding_path(temp.path()).exists());
    }

    /// A higher threshold means a Vault was handed over where a Hot was wanted; dexdo signs alone,
    /// so binding it would record a wallet no dexdo command can spend from.
    #[test]
    fn a_threshold_above_one_is_refused_and_nothing_is_saved() {
        let temp = tempfile::tempdir().expect("temp root");
        let secret = key_file(temp.path());
        let mut observed = supported_wallet();
        observed.required_txn_confirms = 2;
        let error = bind(temp.path(), secret, OWNER_PUBKEY, &observed).expect_err("refused");
        let message = format!("{error}");
        assert!(message.contains("reqConfirms=1"), "{message}");
        assert!(!active_binding_path(temp.path()).exists());
    }

    /// An unsupported family is refused by code hash, naming both accepted hashes so the operator
    /// can tell which wallet they actually have.
    #[test]
    fn an_unsupported_multisig_is_refused_and_nothing_is_saved() {
        let temp = tempfile::tempdir().expect("temp root");
        let secret = key_file(temp.path());
        let mut observed = supported_wallet();
        observed.code_hash = Some("3a7a53248ff39fde936a4274eab143b5fac94feac0d8e2e2748aac5e74538d5f".to_string());
        let error = bind(temp.path(), secret, OWNER_PUBKEY, &observed).expect_err("refused");
        let message = format!("{error}");
        assert!(message.contains("not a supported multisig"), "{message}");
        assert!(message.contains(dexdo_core::canonical_multisig::CODE_HASH), "{message}");
        assert!(!active_binding_path(temp.path()).exists());
    }

    /// A legacy spending hash is one of the two dexdo actually spends from, so it must bind.
    #[test]
    fn the_legacy_spending_code_hash_is_accepted() {
        let temp = tempfile::tempdir().expect("temp root");
        let secret = key_file(temp.path());
        let mut observed = supported_wallet();
        observed.code_hash =
            Some(dexdo_core::canonical_multisig::LEGACY_SPENDING_CODE_HASH.to_string());
        bind(temp.path(), secret, OWNER_PUBKEY, &observed).expect("legacy spending hash binds");
    }

    /// An address that is not Active is refused before its getters are trusted.
    #[test]
    fn a_wallet_that_is_not_active_is_refused() {
        let temp = tempfile::tempdir().expect("temp root");
        let secret = key_file(temp.path());
        for status in ["NotFound", "Uninit", "NonExist", "Frozen"] {
            let observed = ObservedHotWallet {
                status: status.to_string(),
                code_hash: None,
                required_txn_confirms: 0,
                custodian_pubkeys: Vec::new(),
            };
            let error = bind(temp.path(), secret.clone(), OWNER_PUBKEY, &observed)
                .expect_err("a non-Active account must be refused");
            assert!(format!("{error}").contains("is not Active"), "{error}");
        }
        assert!(!active_binding_path(temp.path()).exists());
    }

    /// The order is a contract of its own: an operator handed several problems at once must be told
    /// about the earliest one, because that is the one whose fix changes what the rest report.
    #[test]
    fn checks_run_in_the_documented_order() {
        let temp = tempfile::tempdir().expect("temp root");
        let secret = key_file(temp.path());
        // Every check below the first one is also broken here.
        let all_broken = ObservedHotWallet {
            status: "Uninit".to_string(),
            code_hash: Some("00".repeat(32)),
            required_txn_confirms: 7,
            custodian_pubkeys: vec![STRANGER_PUBKEY.to_string()],
        };
        let bad_address = verify_manual_hot_wallet(
            "not-an-address",
            WalletNetwork::Shellnet,
            secret.clone(),
            OWNER_PUBKEY,
            &all_broken,
            "id".to_string(),
        )
        .expect_err("address first");
        assert!(format!("{bad_address}").contains("--multisig-address"));

        let inactive = bind(temp.path(), secret.clone(), OWNER_PUBKEY, &all_broken)
            .expect_err("status before code hash");
        assert!(format!("{inactive}").contains("is not Active"), "{inactive}");

        let mut active = all_broken.clone();
        active.status = "Active".to_string();
        let bad_hash =
            bind(temp.path(), secret.clone(), OWNER_PUBKEY, &active).expect_err("code hash next");
        assert!(
            format!("{bad_hash}").contains("not a supported multisig"),
            "{bad_hash}"
        );

        let mut supported = active.clone();
        supported.code_hash = Some(dexdo_core::canonical_multisig::CODE_HASH.to_string());
        let bad_threshold = bind(temp.path(), secret.clone(), OWNER_PUBKEY, &supported)
            .expect_err("threshold next");
        assert!(format!("{bad_threshold}").contains("reqConfirms=1"), "{bad_threshold}");

        let mut threshold_ok = supported.clone();
        threshold_ok.required_txn_confirms = 1;
        let bad_custodian =
            bind(temp.path(), secret, OWNER_PUBKEY, &threshold_ok).expect_err("custodian last");
        assert!(
            format!("{bad_custodian}").contains("is not a custodian"),
            "{bad_custodian}"
        );
        assert!(!active_binding_path(temp.path()).exists());
    }

    /// An already-bound Hot may still hold funds, so onboarding never overwrites it.
    #[test]
    fn an_existing_binding_is_never_replaced_by_onboarding() {
        let temp = tempfile::tempdir().expect("temp root");
        let secret = key_file(temp.path());
        let path = bind(temp.path(), secret.clone(), OWNER_PUBKEY, &supported_wallet())
            .expect("first bind");
        let first = std::fs::read_to_string(&path).expect("read binding");

        let error = bind(temp.path(), secret, OWNER_PUBKEY, &supported_wallet())
            .expect_err("a second onboarding must be refused");
        let message = format!("{error}");
        assert!(message.contains("already bound"), "{message}");
        assert!(message.contains("rebind"), "{message}");
        assert_eq!(
            std::fs::read_to_string(&path).expect("re-read binding"),
            first,
            "the refused onboarding rewrote the active binding"
        );
    }

    /// The secret file is owner-only, and so is the binding beside it.
    #[cfg(unix)]
    #[test]
    fn the_binding_is_written_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = tempfile::tempdir().expect("temp root");
        let secret = key_file(temp.path());
        let path = bind(temp.path(), secret, OWNER_PUBKEY, &supported_wallet()).expect("bind");
        let mode = std::fs::metadata(&path)
            .expect("binding metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the binding must be owner-only");
        let dir_mode = std::fs::metadata(temp.path().join("wallet"))
            .expect("wallet dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "the wallet directory must be owner-only");
    }

    /// Only the interactive form has to tell the two files apart, and it does so strictly: a file
    /// that is neither is refused rather than fed to the wrong reader.
    #[test]
    fn secret_files_are_classified_or_refused() {
        assert_eq!(
            classify_manual_secret_file(&format!("  {SECRET_HEX}\n")).expect("key"),
            ManualSecretKind::Key
        );
        let phrase = "abandon ".repeat(11) + "about";
        assert_eq!(
            classify_manual_secret_file(&phrase).expect("phrase"),
            ManualSecretKind::SeedPhrase
        );
        for ambiguous in [
            "",
            "short",
            "dead beef",
            &"abandon ".repeat(13),
            &format!("{SECRET_HEX} {SECRET_HEX}"),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ab0ut",
        ] {
            assert!(
                classify_manual_secret_file(ambiguous).is_err(),
                "{ambiguous:?} must be refused rather than guessed"
            );
        }
    }

    /// A reader that reports a fixed sequence of balances and counts how often it was asked.
    struct ScriptedBalances {
        readings: std::cell::RefCell<std::vec::IntoIter<u128>>,
        last: std::cell::Cell<u128>,
        reads: std::cell::Cell<usize>,
    }

    impl ScriptedBalances {
        fn new(readings: Vec<u128>) -> Self {
            Self {
                readings: std::cell::RefCell::new(readings.into_iter()),
                last: std::cell::Cell::new(0),
                reads: std::cell::Cell::new(0),
            }
        }
    }

    #[async_trait::async_trait(?Send)]
    impl HotEccReader for ScriptedBalances {
        async fn read_hot_ecc_raw(&self, _currency_id: u32) -> Result<u128> {
            self.reads.set(self.reads.get() + 1);
            let next = self.readings.borrow_mut().next();
            let value = next.unwrap_or_else(|| self.last.get());
            self.last.set(value);
            Ok(value)
        }
    }

    const REQUIREMENT: HotFundingRequirement = HotFundingRequirement {
        currency_id: dexdo_core::params::SHELL_CURRENCY_ID,
        required_raw: 1_000,
    };

    /// The shortfall the operator acts on has to be exact and has to name the address in full;
    /// "not enough SHELL" sends money to the wrong place or not at all.
    #[test]
    fn the_shortfall_message_carries_the_exact_amount_and_the_full_address() {
        let text = render_manual_funding_shortfall(
            HOT,
            "note deploy",
            REQUIREMENT,
            250,
            Duration::from_secs(600),
        );
        assert!(text.contains(HOT), "the full canonical address must appear:\n{text}");
        assert!(text.contains("missing 750 raw"), "{text}");
        assert!(text.contains("1000 raw SHELL ECC[2]"), "{text}");
        assert!(text.contains("holds 250 raw"), "{text}");
        assert!(text.contains("600 seconds"), "{text}");
        // The manual provider has no request to create and no service to send anyone to.
        for forbidden in ["Vault", "vault", "http", "gosh.ai", "Gosh.ai"] {
            assert!(
                !text.contains(forbidden),
                "the manual shortfall must not mention {forbidden}:\n{text}"
            );
        }
    }

    /// The timeout message is the other half: it has to state that nothing was left behind, and
    /// that the same command is the way forward.
    #[test]
    fn the_timeout_message_states_that_nothing_was_written() {
        let text = render_manual_funding_timeout(
            HOT,
            "note topup",
            REQUIREMENT,
            250,
            Duration::from_secs(600),
        );
        assert!(text.contains(HOT), "{text}");
        assert!(text.contains("750 raw is still missing"), "{text}");
        assert!(text.contains("no local state was written"), "{text}");
        assert!(text.contains("run the same command again"), "{text}");
        for forbidden in ["Vault", "vault", "http", "gosh.ai"] {
            assert!(!text.contains(forbidden), "{text}");
        }
    }

    /// Enough already there means no wait at all, and exactly one read.
    #[tokio::test(start_paused = true)]
    async fn a_funded_hot_is_not_waited_for() {
        let reader = ScriptedBalances::new(vec![1_000]);
        let available = ensure_manual_hot_funded(
            &reader,
            HOT,
            "note deploy",
            REQUIREMENT,
            Duration::from_secs(600),
            Duration::from_secs(5),
        )
        .await
        .expect("already funded");
        assert_eq!(available, 1_000);
        assert_eq!(reader.reads.get(), 1);
    }

    /// A top-up that lands during the wait is picked up by the balance, not by any notification.
    #[tokio::test(start_paused = true)]
    async fn a_top_up_that_lands_during_the_wait_is_observed() {
        let reader = ScriptedBalances::new(vec![0, 0, 250, 1_000]);
        let available = ensure_manual_hot_funded(
            &reader,
            HOT,
            "note deploy",
            REQUIREMENT,
            Duration::from_secs(600),
            Duration::from_secs(5),
        )
        .await
        .expect("funded while waiting");
        assert_eq!(available, 1_000);
        assert_eq!(reader.reads.get(), 4);
    }

    /// The property the retry depends on: a timeout writes nothing, so a second run starts from the
    /// state the first one did and re-reads the chain rather than resuming a different path.
    #[tokio::test(start_paused = true)]
    async fn a_timeout_writes_nothing_and_the_rerun_rechecks_the_balance() {
        let temp = tempfile::tempdir().expect("temp root");
        let before = snapshot_dir(temp.path());

        let reader = ScriptedBalances::new(vec![0; 8]);
        let error = ensure_manual_hot_funded(
            &reader,
            HOT,
            "note deploy",
            REQUIREMENT,
            Duration::from_secs(20),
            Duration::from_secs(5),
        )
        .await
        .expect_err("the wait must run out");
        assert!(format!("{error}").contains("run the same command again"), "{error}");
        let first_run_reads = reader.reads.get();
        assert!(first_run_reads >= 2, "the wait must poll: {first_run_reads}");
        assert_eq!(
            snapshot_dir(temp.path()),
            before,
            "the timed-out wait left state behind"
        );

        // The rerun: the same code path, a chain that has since been funded. It must reach the same
        // first read, not skip it because a previous run already decided the balance was short.
        let rerun = ScriptedBalances::new(vec![1_000]);
        let available = ensure_manual_hot_funded(
            &rerun,
            HOT,
            "note deploy",
            REQUIREMENT,
            Duration::from_secs(20),
            Duration::from_secs(5),
        )
        .await
        .expect("the rerun sees the funded balance");
        assert_eq!(available, 1_000);
        assert_eq!(rerun.reads.get(), 1, "the rerun must re-read the balance");
        assert_eq!(snapshot_dir(temp.path()), before);
    }

    /// The defaults the shared funding step will use are the specification's, and they are pinned
    /// here: ten minutes, read every five seconds. A wait that silently became a different length
    /// is the difference between an operator's transfer landing in time and not.
    #[tokio::test(start_paused = true)]
    async fn the_default_wait_is_ten_minutes_polled_every_five_seconds() {
        assert_eq!(
            dexdo_core::params::WALLET_HOT_FUNDING_TIMEOUT,
            Duration::from_secs(600)
        );
        assert_eq!(
            dexdo_core::params::NOTE_DEPLOY_SHELL_FUNDING_POLL_INTERVAL,
            Duration::from_secs(5)
        );
        let started = tokio::time::Instant::now();
        let reader = ScriptedBalances::new(vec![0; 4096]);
        let error =
            ensure_manual_hot_funded_with_defaults(&reader, HOT, "note deploy", REQUIREMENT)
                .await
                .expect_err("an unfunded Hot must time out");
        assert!(format!("{error}").contains("within 600 seconds"), "{error}");
        assert_eq!(
            tokio::time::Instant::now().duration_since(started),
            Duration::from_secs(600)
        );
        assert_eq!(
            reader.reads.get(),
            122,
            "the read that opened the wait, then one every 5s through the 600s deadline inclusive"
        );
    }

    /// The wait is bounded by the timeout it was given, not by the poll interval dividing it.
    #[tokio::test(start_paused = true)]
    async fn the_wait_stops_at_the_timeout() {
        let started = tokio::time::Instant::now();
        let reader = ScriptedBalances::new(vec![0; 64]);
        let outcome = wait_for_manual_hot_funding(
            &reader,
            REQUIREMENT,
            Duration::from_secs(22),
            Duration::from_secs(5),
        )
        .await
        .expect("the wait completes");
        assert_eq!(outcome, ManualFundingOutcome::TimedOut { available_raw: 0 });
        let elapsed = tokio::time::Instant::now().duration_since(started);
        assert_eq!(
            elapsed,
            Duration::from_secs(22),
            "the wait must end exactly at its deadline"
        );
    }

    fn snapshot_dir(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(bytes) = std::fs::read(&path) {
                    out.push((path, bytes));
                }
            }
        }
        out.sort();
        out
    }

    /// Property 1, at the level a test can reach inside one crate: the only way to a saved binding
    /// runs through verification, and the writer is unreachable from any other module.
    /// `save_active_binding` is private to `persist` and takes a `VerifiedManualWallet` whose field
    /// is private, so no working command can construct the argument even if it could name the
    /// function. This pins the one thing a refactor could quietly undo: that the writer has exactly
    /// one call site, inside the onboarding entry.
    #[test]
    fn the_binding_writer_has_exactly_one_call_site_and_it_is_onboarding() {
        let source = include_str!("wallet_manual.rs");
        let production = source
            .split_once("\n#[cfg(test)]\nmod tests {")
            .expect("unit-test module boundary")
            .0;
        assert_eq!(
            production.matches("save_active_binding(").count(),
            2,
            "save_active_binding must be defined once and called once, both inside this module"
        );
        assert!(
            production.contains("fn onboard_manual_binding(")
                && production
                    .split_once("fn onboard_manual_binding(")
                    .expect("onboarding entry")
                    .1
                    .contains("save_active_binding(data_dir, verified)"),
            "the single call site must be the onboarding entry"
        );
        assert!(
            !production.contains("pub(crate) fn save_active_binding"),
            "the writer must not be reachable from another module"
        );
    }
}

/// the single-writer rule, held by the compiler and by a count a space cannot defeat.
#[cfg(test)]
#[path = "wallet_manual_single_writer_1313.rs"]
mod wallet_manual_single_writer_1313;
