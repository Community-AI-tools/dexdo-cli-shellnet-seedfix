//! `dexdo wallet`: the wallet PROVIDER model and the durable active binding.
//! Three things live here, and deliberately nothing else.
//! **The provider is a subcommand, never a flag and never a default.** `ackinacki-wallet`,
//! `gosh-ai` and `manual` can all hand over the *same* canonical multisig contract, so an address,
//! a code hash or an on-chain parameter cannot tell them apart afterwards. The origin is therefore
//! recorded once, at bind time, and never re-derived. A guess here picks the wrong funding flow for
//! real money, which is why `dexdo wallet onboard` with no provider is an ERROR outside a terminal
//! rather than a menu nobody can answer or a default nobody chose.
//! **The binding is one atomic commit point.** `<data-dir>/wallet/binding.json` names the single
//! active binding. Per-binding secrets live under `<data-dir>/wallet/bindings/<binding-id>/`, and
//! the `binding-id` is minted BEFORE any key exists so re-binding the same provider writes beside
//! the previous binding's secrets instead of over them. A replaced binding is ARCHIVED, never
//! deleted: funds can still sit in the old Hot.
//! **A wallet-dependent command with no binding fails fast**, before any chain write, with
//! [`dexdo_core::error_codes::E_WALLET_NOT_CONFIGURED`] and a remediation naming the providers.

use crate::cli::args::{WalletArgs, WalletCommand, WalletProviderCommand};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{BufRead, IsTerminal as _, Write};

/// Which of the two setup commands is running. Both select a provider the same way; they differ in
/// what they require of the state that already exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WalletAction {
    /// First binding for this instance. Refuses to touch an existing one.
    Onboard,
    /// Replace the active binding. Requires one to exist, and archives it.
    Rebind,
}

impl WalletAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Onboard => "onboard",
            Self::Rebind => "rebind",
        }
    }
}

impl fmt::Display for WalletAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Where the funding(Hot) wallet came from. Written into the binding at bind time and read back
/// from that field only -- never inferred.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WalletProvider {
    /// The Acki Nacki Wallet app, which provides a Vault/Hot pair.
    AckinackiWallet,
    /// The Gosh.ai service, which provides a Hot only.
    GoshAi,
    /// A Hot the operator already controls, connected by address plus a local secret file.
    Manual,
}

impl WalletProvider {
    /// The closed set, in the order the interactive menu numbers them.
    pub(crate) const ALL: [Self; 3] = [Self::AckinackiWallet, Self::GoshAi, Self::Manual];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AckinackiWallet => "ackinacki-wallet",
            Self::GoshAi => "gosh-ai",
            Self::Manual => "manual",
        }
    }
}

impl fmt::Display for WalletProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl From<&WalletProviderCommand> for WalletProvider {
    fn from(command: &WalletProviderCommand) -> Self {
        match command {
            // The payload is the onboarding request, not part of the provider's identity.
            WalletProviderCommand::AckinackiWallet(_) => Self::AckinackiWallet,
            WalletProviderCommand::GoshAi(_) => Self::GoshAi,
            WalletProviderCommand::Manual(_) => Self::Manual,
        }
    }
}

/// The chain a binding is valid on. A Hot bound on one network must never be spent on the other,
/// so the network is part of the binding rather than of whichever endpoint flag a later command
/// happens to carry.
/// The binding schema is compiled on the same gate as the [`store`] that writes it: every provider
/// flow proves the wallet on chain before it is bound, so a build with no chain backend has nothing
/// that could produce a binding to describe.
#[cfg(any(feature = "shellnet", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum WalletNetwork {
    Shellnet,
    Mainnet,
}

#[cfg(any(feature = "shellnet", test))]
impl WalletNetwork {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Shellnet => "shellnet",
            Self::Mainnet => "mainnet",
        }
    }

    /// The network a money command is running on, read from the `network` field of the deployed
    /// contracts manifest it was pointed at.
    /// This is the SAME field `note deploy` and `note topup` already read to key the funding-wallet
    /// lock, and it is deliberately the only source: the manifest is what decides which chain the
    /// command's addresses and endpoint belong to, so it is what decides which wallet may fund it.
    /// A second source of truth here -- a flag, an endpoint guess, the binding's own field -- would
    /// be a way for the two answers to differ, and the whole guarantee is that they cannot.
    /// An unrecognised label is a refusal and never a default. Falling back to shellnet would mean
    /// a manifest this build does not understand silently resolving the shellnet wallet, which is
    /// exactly the cross-network spend being prevented.
    pub(crate) fn from_manifest_label(label: &str) -> Result<Self> {
        match label {
            "shellnet" => Ok(Self::Shellnet),
            "mainnet" => Ok(Self::Mainnet),
            other => bail!(
                "the deployed contracts manifest declares network `{other}`, which this build does \
                 not know. Wallet bindings are kept per network and a spend is only ever funded by \
                 the wallet bound to the network it runs on, so no wallet was resolved rather than \
                 one being guessed. Known networks: `{}`, `{}`",
                Self::Shellnet.as_str(),
                Self::Mainnet.as_str(),
            ),
        }
    }
}

/// The network an onboarding command was pointed at. Same closed set, so this cannot drift.
#[cfg(any(feature = "shellnet", test))]
impl From<crate::cli::args::WalletNetworkArg> for WalletNetwork {
    fn from(arg: crate::cli::args::WalletNetworkArg) -> Self {
        match arg {
            crate::cli::args::WalletNetworkArg::Shellnet => Self::Shellnet,
            crate::cli::args::WalletNetworkArg::Mainnet => Self::Mainnet,
        }
    }
}

#[cfg(any(feature = "shellnet", test))]
impl fmt::Display for WalletNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Schema version of `binding.json`. A binary refuses a version it was not written against rather
/// than reading a newer file with fields it does not know it is ignoring.
#[cfg(any(feature = "shellnet", test))]
pub(crate) const BINDING_VERSION: u32 = 1;

/// The active wallet binding: non-secret parameters plus PATHS to owner-only secret files.
/// No key, seed phrase or recovery phrase is a field of this type, so no code path can write one
/// into `binding.json` -- the file is deliberately not where secrets live. `provider` has no serde
/// default: a binding that does not say where its wallet came from is refused rather than guessed.
#[cfg(any(feature = "shellnet", test))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WalletBinding {
    pub(crate) version: u32,
    pub(crate) id: String,
    pub(crate) provider: WalletProvider,
    pub(crate) network: WalletNetwork,
    /// Canonical `<dapp_id>::<account_id>` address of the Hot wallet that funds spends.
    pub(crate) hot_address: String,
    /// Canonical address of the Vault, for the providers that supply one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) vault_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) hot_key_file: Option<std::path::PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) vault_key_file: Option<std::path::PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) hot_seed_file: Option<std::path::PathBuf>,
    /// Reserved non-secret metadata already obtained from an authenticated `wallet_hello`. Nothing
    /// reads it yet; it is stored so it is not lost when onboarding completes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) push_profile_address: Option<String>,
}

/// The one entry point behind `dexdo wallet`.
pub(crate) async fn run_wallet(args: WalletArgs) -> Result<()> {
    let (action, explicit) = match &args.command {
        WalletCommand::Onboard(onboard) => (WalletAction::Onboard, onboard.provider.as_ref()),
        WalletCommand::Rebind(rebind) => (WalletAction::Rebind, rebind.provider.as_ref()),
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let interactive = stdin.is_terminal() && stdout.is_terminal();
    let provider = resolve_provider(
        action,
        explicit,
        interactive,
        &mut stdin.lock(),
        &mut stdout.lock(),
    )?;
    run_selected(action, provider, explicit).await
}

/// Pick the provider: the subcommand when one was given, the terminal menu when there is a terminal
/// to show it in, and otherwise an error that names every valid subcommand.
/// `interactive` is passed in rather than probed here so the three outcomes are testable without a
/// pty. It must be true only when BOTH stdin and stdout are terminals: a redirected stdout would
/// bury the menu in a file, and a closed stdin has no answer to give.
pub(crate) fn resolve_provider<R: BufRead, W: Write>(
    action: WalletAction,
    explicit: Option<&WalletProviderCommand>,
    interactive: bool,
    reader: &mut R,
    writer: &mut W,
) -> Result<WalletProvider> {
    if let Some(command) = explicit {
        return Ok(WalletProvider::from(command));
    }
    if !interactive {
        bail!(non_interactive_provider_message(action));
    }
    prompt_for_provider(action, reader, writer)
}

/// The refusal a script, a CI job or a headless server sees. It lists the whole closed set, because
/// the operator has to type one of them, and it names `manual` for the headless case: a remote
/// seller has no terminal, no browser and no camera, so a QR-based provider cannot reach it.
fn non_interactive_provider_message(action: WalletAction) -> String {
    let mut message = format!(
        "dexdo wallet {action} needs a provider subcommand in a non-interactive environment: \
         no provider is ever chosen for you. Run one of:"
    );
    for provider in WalletProvider::ALL {
        message.push_str(&format!("\n  dexdo wallet {action} {provider}"));
    }
    message.push_str(
        "\nOn a headless host with no TTY, no browser and no camera, use `manual`: its whole \
         input is a plain printed address, so it needs neither a QR nor an interactive prompt.",
    );
    message
}

/// The terminal menu. Numbered exactly as the providers are ordered, and it also accepts the
/// provider name, because that is what the error above tells operators to type.
fn prompt_for_provider<R: BufRead, W: Write>(
    action: WalletAction,
    reader: &mut R,
    writer: &mut W,
) -> Result<WalletProvider> {
    writeln!(
        writer,
        "Select a wallet provider for dexdo wallet {action}:"
    )?;
    for (index, provider) in WalletProvider::ALL.iter().enumerate() {
        writeln!(writer, "{}. {provider}", index + 1)?;
    }
    write!(writer, "> ")?;
    writer.flush()?;
    let mut answer = String::new();
    if reader.read_line(&mut answer)? == 0 {
        bail!(
            "no provider was selected for dexdo wallet {action} (input ended); \
             re-run with an explicit provider subcommand"
        );
    }
    provider_from_answer(answer.trim()).ok_or_else(|| {
        anyhow::anyhow!(
            "`{}` is not a wallet provider; answer with 1, 2 or 3, or with {}",
            answer.trim(),
            WalletProvider::ALL
                .iter()
                .map(|provider| format!("`{provider}`"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

/// One menu answer to one provider. Position or name; nothing else, and no fuzzy match -- a wrong
/// provider is a wrong funding flow.
fn provider_from_answer(answer: &str) -> Option<WalletProvider> {
    WalletProvider::ALL
        .iter()
        .enumerate()
        .find(|(index, provider)| answer == (index + 1).to_string() || answer == provider.as_str())
        .map(|(_, provider)| *provider)
}

/// The durable half. It is compiled on the same gate as [`crate::cli::note`], whose
/// `write_private_atomic` is the single atomic owner-only write this module commits through. Every
/// provider flow proves the wallet on chain before it is bound, so a build with no chain backend
/// has nothing that could produce a binding to store.
#[cfg(any(feature = "shellnet", test))]
mod store;

#[cfg(any(feature = "shellnet", test))]
pub(crate) use store::{BindingDraft, WalletStore};

/// The funding(Hot) wallet a money command will actually spend from, and where its signing secret
/// is read from.
#[cfg(any(feature = "shellnet", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FundingWallet {
    pub(crate) address: String,
    pub(crate) key: Option<std::path::PathBuf>,
    pub(crate) seed_file: Option<std::path::PathBuf>,
}

/// Decide which Hot a money command spends from, before it reaches the chain.
/// `network` is the chain the command is ACTUALLY running on, taken from the deployed contracts
/// manifest it was pointed at. It is a parameter and not something read from the binding, because
/// it is the question: the binding says which network it belongs to, the manifest says which
/// network is being spent on, and a spend is only funded when the two agree.
/// Three outcomes, in this order and no other:
/// 1. `--multisig-address` was passed -- it WINS, is used exactly as given, and the binding is not
/// even read. Every existing invocation and script therefore behaves identically, and a machine
/// that binds a wallet later cannot change where an explicit command spends from.
/// 2. No address, and a binding exists FOR THIS NETWORK -- the bound Hot and its recorded secret
/// file are used.
/// 3. No address and no binding for this network -- [`E_WALLET_NOT_CONFIGURED`], raised here rather
/// than as a clap "missing argument", because the operator's next move is a setup command and
/// not a different flag.
/// A binding for the OTHER network is none of the three and is never outcome 2. Bindings are stored
/// per network, so a mainnet command does not even name the shellnet record; and a record that is
/// somehow in the wrong slot is refused by [`WalletStore::load_active`] rather than followed. Both
/// halves exist because the failure they prevent is a real spend from a wallet the operator bound
/// for a different chain -- the shipped code kept one global binding and had neither (, audit
/// item 3).
/// A binding file that EXISTS but does not parse is none of the three either: it propagates as the
/// read error [`WalletStore::load_active`] raises. Treating it as "no wallet" would send the
/// operator into onboarding while a real Hot, possibly holding funds, is already bound.
/// [`E_WALLET_NOT_CONFIGURED`]: dexdo_core::error_codes::E_WALLET_NOT_CONFIGURED
#[cfg(any(feature = "shellnet", test))]
pub(crate) fn resolve_funding_wallet(
    store: &WalletStore,
    network: WalletNetwork,
    explicit_address: Option<&str>,
    explicit_key: &Option<std::path::PathBuf>,
    explicit_seed_file: &Option<std::path::PathBuf>,
) -> Result<FundingWallet> {
    if let Some(address) = explicit_address {
        return Ok(FundingWallet {
            address: address.to_string(),
            key: explicit_key.clone(),
            seed_file: explicit_seed_file.clone(),
        });
    }
    let binding = store.require_active(network)?;
    if binding.hot_key_file.is_none() && binding.hot_seed_file.is_none() {
        bail!(
            "wallet binding {} (provider `{}`, Hot {}) records no local Hot key or seed file, so \
             this instance cannot sign a spend from it; re-bind it with a provider flow that \
             stores one, or pass `--multisig-address` and `--multisig-key` for this run",
            binding.id,
            binding.provider,
            binding.hot_address,
        );
    }
    Ok(FundingWallet {
        address: binding.hot_address,
        key: binding.hot_key_file,
        seed_file: binding.hot_seed_file,
    })
}

/// The network the onboarding attempt is for, read from the provider subcommand's own `--network`.
/// A provider chosen from the interactive menu carries no arguments at all, and every flow that can
/// run that way already applies `shellnet` as its default; this repeats that default rather than
/// inventing a second one, so the network the store is asked about is the network the flow will
/// record in the binding it builds.
/// It is also the network a resumable draft has to match, for the same reason: an attempt started
/// against one chain must not be continued by a command pointed at the other.
#[cfg(any(feature = "shellnet", test))]
fn selected_network(explicit: Option<&WalletProviderCommand>) -> WalletNetwork {
    match explicit {
        Some(WalletProviderCommand::AckinackiWallet(args)) => args.network.into(),
        Some(WalletProviderCommand::GoshAi(args)) => args.network.into(),
        Some(WalletProviderCommand::Manual(args)) => args.network.into(),
        None => WalletNetwork::Shellnet,
    }
}

#[cfg(any(feature = "shellnet", test))]
async fn run_selected(
    action: WalletAction,
    provider: WalletProvider,
    explicit: Option<&WalletProviderCommand>,
) -> Result<()> {
    let store = WalletStore::open()?;
    // Which network this attempt is binding, from the provider's own `--network`. Bindings are kept
    // per network, so "already bound" and "nothing to replace" are questions about THIS network:
    // a shellnet binding must not block onboarding a mainnet wallet, and rebinding one must not
    // require the other to exist. The default matches the one each provider flow already applies to
    // an interactive selection carrying no arguments.
    let network = selected_network(explicit);
    match action {
        // Both arms ask whether a RECORD is there, not whether it validates. A binding whose id
        // names nothing still occupies the active file, so onboarding must still refuse to write
        // over it, and rebind -- the remediation the validation refusal names -- must still be able
        // to replace it. Validation belongs on the path that RESOLVES a binding into money
        // decisions, which is `resolve_funding_wallet`.
        WalletAction::Onboard => {
            if let Some(active) = store.read_active_record(network)? {
                bail!(
                    "this instance is already bound to provider `{}` on {network} (binding {}, \
                     Hot {}); `dexdo wallet onboard` changes nothing on purpose. To replace it, \
                     run `dexdo wallet rebind` with the {provider} provider -- the current binding \
                     is archived, not deleted, because funds can still sit in the old Hot.",
                    active.provider,
                    active.id,
                    active.hot_address,
                );
            }
        }
        // Nothing to replace is not "start from scratch": it is the same missing-binding state
        // every wallet-dependent command reports, with the same code and the same remediation.
        WalletAction::Rebind => {
            store.require_active_record(network)?;
        }
    }

    let draft = match resumable_binding_id(action, provider, &store, explicit) {
        Some(id) => store.adopt_draft(&id)?,
        None => store.open_draft()?,
    };
    let outcome = provider_flow(provider, &draft, explicit).await;
    if outcome.is_err() {
        draft.discard_if_empty();
    }
    let binding = outcome?;

    let archived = commit_onboarded(&store, &draft, &binding)?;
    // The attempt is finished, so it is no longer an attempt anything may resume. Retiring the
    // draft here rather than inside the flow means it happens exactly once, and only after the
    // binding it describes is actually the active one.
    retire_resumable_draft(provider, &draft);
    // The paths are printed, never their contents: the operator does not have to know the platform
    // data directory to find the binding, and nothing here reveals a secret.
    println!(
        "active wallet binding: {} (provider {}, Hot {} on {})",
        store.binding_path(binding.network).display(),
        binding.provider,
        binding.hot_address,
        binding.network
    );
    println!(
        "binding {} secrets directory: {}",
        draft.id(),
        draft.dir().display()
    );
    if let Some(path) = archived {
        println!(
            "previous binding archived at {} -- its secrets are kept, not deleted",
            path.display()
        );
    }
    Ok(())
}

/// The id of an unfinished attempt this command may continue, when there is one.
/// # Why this decides here and not inside the provider flow
/// The store reserves the id BEFORE the flow runs, and `commit_onboarded` refuses any binding that
/// comes back carrying a different one. So "resume" cannot be a decision the flow makes privately:
/// by the time it has read its own draft, the id it must commit under is already fixed. Asking here
/// is what lets a resumed attempt end in a committed binding instead of a refusal.
/// Restricted to `onboard`, and to the one provider that writes a draft:
/// - `rebind` exists to bind a DIFFERENT wallet, so silently continuing a wait the operator started
/// earlier -- possibly for a Hot they have since abandoned -- would be the opposite of what they
/// asked for. It mints a fresh id, as it always has.
/// - `ackinacki-wallet` has its own durable session file and resumes through that; `manual` stores
/// no secret of its own and has nothing to resume.
#[cfg(any(feature = "shellnet", test))]
fn resumable_binding_id(
    action: WalletAction,
    provider: WalletProvider,
    store: &WalletStore,
    explicit: Option<&WalletProviderCommand>,
) -> Option<String> {
    if action != WalletAction::Onboard || provider != WalletProvider::GoshAi {
        return None;
    }
    crate::cli::wallet_goshai::files::find_resumable(store.root(), selected_network(explicit))
}

/// Retire the finished attempt's resume marker. See [`resumable_binding_id`] for who writes one.
#[cfg(any(feature = "shellnet", test))]
fn retire_resumable_draft(provider: WalletProvider, draft: &BindingDraft) {
    if provider == WalletProvider::GoshAi {
        crate::cli::wallet_goshai::files::discard_draft_in(draft.dir());
    }
}

/// Commit the binding this attempt proved, under the identity the store RESERVED for it.
/// The reserved id is the name of the secrets directory `open_draft` created, so a binding that
/// carries a different id is not a cosmetic mismatch: `binding.json` would name a directory that
/// does not exist, while the directory holding the attempt's key material would be referenced by
/// nothing. The operator's Hot would then be unreachable through the active binding -- money-path
/// damage, written silently. Refusing keeps the previous binding active and leaves the reserved
/// directory and everything in it exactly where a retry can find them.
/// This is a single point rather than a rule each provider flow is trusted to follow: the flows
/// build the binding, and one of them minting its own id is precisely how this went wrong.
#[cfg(any(feature = "shellnet", test))]
fn commit_onboarded(
    store: &WalletStore,
    draft: &BindingDraft,
    binding: &WalletBinding,
) -> Result<Option<std::path::PathBuf>> {
    if binding.id != draft.id() {
        bail!(
            "the `{}` onboarding flow returned binding id {} while this attempt reserved {}, whose \
             secrets directory is {}. Recording the first would leave the active binding naming a \
             directory that does not exist and the reserved one referenced by nothing, so nothing \
             was written and the previous binding, if any, is untouched",
            binding.provider,
            binding.id,
            draft.id(),
            draft.dir().display(),
        );
    }
    store.commit_active(binding)
}

/// Run one provider's onboarding and return the binding it proved.
/// is delivered in stages. `gosh-ai` is wired; `ackinacki-wallet` and `manual` are not, and
/// their refusal names what still works today so nobody is left without a funding path.
/// The flow BUILDS a binding and never writes `wallet/binding.json`: the caller commits it through
/// [`WalletStore::commit_active`], which archives whatever it replaces. Two writers would mean the
/// second one renaming over the only local record of a Hot that can still hold funds.
#[cfg(any(feature = "shellnet", test))]
async fn provider_flow(
    provider: WalletProvider,
    draft: &BindingDraft,
    explicit: Option<&WalletProviderCommand>,
) -> Result<WalletBinding> {
    match provider {
        WalletProvider::GoshAi => goshai_flow(draft, explicit).await,
        WalletProvider::Manual => manual_flow(draft, explicit).await,
        WalletProvider::AckinackiWallet => ackinacki_flow(draft, explicit).await,
    }
}

/// Translate the clap surface into what the Gosh.ai flow takes, and run it.
/// The binding id is the one the STORE reserved for this attempt, not a fresh one: the store
/// created the owner-only directory under that id and discards it when the attempt writes nothing,
/// so a second id would leave that directory empty and put the recovery phrase somewhere the store
/// does not know about.
/// A provider chosen from the interactive menu carries no payload, so the defaults are used -- the
/// same ones clap would have applied.
/// The Acki Nacki Wallet provider: the bee session, the QR, and the validated Vault/Hot pair.
/// This used to be reached by its own dispatch arm in `main.rs`, which meant it never passed through
/// `run_selected` and therefore never produced a binding -- the flow ran to completion and left the
/// operator exactly as unconfigured as before. Routing it here is the specification's step 9: all
/// three providers reach one `provider_flow`, one writer and one archive path.
/// The binding id is the store's, as it is for gosh-ai: the store reserved a directory under it and
/// discards it when the attempt writes nothing.
/// Every argument now has a default, so this provider is reachable from the interactive menu like
/// the other two. It used to refuse there, because an agent name and two owner-only paths had to be
/// typed and a menu has no command line to carry them -- which made choosing `ackinacki-wallet` from
/// the menu a dead end that only told the operator to start again. The paths default into the
/// secrets directory the store reserved for this attempt, exactly where the gosh-ai provider writes
/// its own secret, and the agent name defaults to the constant the durable session can be resumed
/// under.
#[cfg(feature = "shellnet")]
async fn ackinacki_flow(
    draft: &BindingDraft,
    explicit: Option<&WalletProviderCommand>,
) -> Result<WalletBinding> {
    crate::cli::wallet_onboarding::run_wallet_onboard(
        ackinacki_onboard_args(explicit, draft.dir()),
        draft.id(),
    )
    .await
}

/// The onboarding request this provider makes, as a pure function of the command line.
/// # Why this is separated from [`ackinacki_flow`]
/// So that the MENU path can be asserted by what it PRODUCES. `ackinacki_flow` itself cannot be
/// driven from a test that runs under the features CI uses: it is `shellnet`-only, it is `async`,
/// and it reaches a chain. That left the source text as the only thing a test could inspect, and an
/// assertion that some refusal phrase is *absent* from a file is satisfied by rewording it, by
/// respacing it, or by moving it one module over -- it proves the string is gone, never that the
/// operator gets a runnable request.
/// `explicit` is `None` exactly when the provider came from the interactive provider menu, which
/// carries no command line at all. That arm is the whole subject of follow-up item 6: it must
/// produce the same request the bare subcommand makes -- every clap default, including the two
/// canonical filenames resolved inside this attempt's binding draft.
#[cfg(any(feature = "shellnet", test))]
fn ackinacki_onboard_args(
    explicit: Option<&WalletProviderCommand>,
    binding_dir: &std::path::Path,
) -> crate::cli::args::WalletOnboardArgs {
    match explicit {
        Some(WalletProviderCommand::AckinackiWallet(args)) => crate::cli::args::WalletOnboardArgs {
            agent_name: args.agent_name.clone(),
            network: args.network,
            endpoint: args.endpoint.clone(),
            state: Some(args.state.clone().unwrap_or_else(|| {
                binding_dir.join(dexdo_core::params::DEFAULT_WALLET_ONBOARD_STATE_PATH)
            })),
            hot_key: Some(args.hot_key.clone().unwrap_or_else(|| {
                binding_dir.join(dexdo_core::params::DEFAULT_WALLET_ONBOARD_HOT_KEY_PATH)
            })),
            vault_key: args.vault_key.clone(),
            qr_file: args.qr_file.clone(),
            terminal_qr: args.terminal_qr,
        },
        // The menu carries no payload, so this is the same request the bare subcommand makes:
        // every default, including the two canonical paths the flow resolves under the effective
        // data directory.
        _ => crate::cli::args::WalletOnboardArgs {
            agent_name: dexdo_core::params::WALLET_ONBOARD_DEFAULT_AGENT_NAME.to_string(),
            network: crate::cli::args::WalletNetworkArg::Shellnet,
            endpoint: None,
            state: Some(binding_dir.join(dexdo_core::params::DEFAULT_WALLET_ONBOARD_STATE_PATH)),
            hot_key: Some(binding_dir.join(dexdo_core::params::DEFAULT_WALLET_ONBOARD_HOT_KEY_PATH)),
            vault_key: None,
            qr_file: None,
            terminal_qr: false,
        },
    }
}

/// follow-up item 6: the owner-only defaults, and the menu path they unblock.
#[cfg(test)]
mod ackinacki_defaults_tests;

#[cfg(all(not(feature = "shellnet"), test))]
async fn ackinacki_flow(
    draft: &BindingDraft,
    explicit: Option<&WalletProviderCommand>,
) -> Result<WalletBinding> {
    let _ = (draft, explicit);
    bail!(
        "dexdo wallet onboard ackinacki-wallet needs a shellnet build: the Vault/Hot pair is bound \
         only after it is validated on chain, and this build has no chain backend"
    )
}

/// The manual provider: an existing Hot, connected by address plus a local secret file.
/// Like the Gosh.ai arm it BUILDS a binding and never writes one -- `run_selected` commits it
/// through `WalletStore`, which archives what it replaces.
/// The binding id is the STORE's, exactly as it is for the other two providers. This flow used to
/// mint a second one of its own, on the reasoning that it generates no key material and so strands
/// no secret. That reasoning was wrong about the file it does not write and silent about the file
/// it does: the store had already reserved an id and created a directory under it, the command
/// printed THAT id as the binding's, and `binding.json` then recorded the other one. The active
/// binding named a directory that did not exist, so the operator's funded Hot could not be reached
/// through it -- which is the guarantee the reserve-before-any-key rule exists to give.
/// A provider chosen from the interactive menu carries no payload; the manual flow's arguments are
/// all optional by design and it asks on a terminal, so the defaults are exactly right there.
#[cfg(feature = "shellnet")]
async fn manual_flow(
    draft: &BindingDraft,
    explicit: Option<&WalletProviderCommand>,
) -> Result<WalletBinding> {
    let args = match explicit {
        Some(WalletProviderCommand::Manual(args)) => crate::cli::args::WalletOnboardManualArgs {
            multisig_address: args.multisig_address.clone(),
            multisig_key: args.multisig_key.clone(),
            multisig_seed_file: args.multisig_seed_file.clone(),
            network: args.network,
            endpoint: args.endpoint.clone(),
            contracts: args.contracts.clone(),
        },
        _ => crate::cli::args::WalletOnboardManualArgs {
            multisig_address: None,
            multisig_key: None,
            multisig_seed_file: None,
            network: crate::cli::args::WalletNetworkArg::Shellnet,
            endpoint: None,
            contracts: std::path::PathBuf::from(dexdo_core::params::DEFAULT_CONTRACTS_PATH),
        },
    };
    crate::cli::wallet_manual::run_wallet_onboard_manual(args, draft.id()).await
}

#[cfg(all(not(feature = "shellnet"), test))]
async fn manual_flow(
    draft: &BindingDraft,
    explicit: Option<&WalletProviderCommand>,
) -> Result<WalletBinding> {
    let _ = (draft, explicit);
    bail!(
        "dexdo wallet onboard manual needs a shellnet build: the Hot is bound only after its \
         contract, threshold and custodian key are validated on chain, and this build has no chain \
         backend"
    )
}

/// The Gosh.ai flow proves the Hot on chain before it binds, so it exists only where there is a
/// chain backend. In a default build the provider is still selectable -- that is argument parsing --
/// and refuses here for the same reason every other money path does.
#[cfg(all(not(feature = "shellnet"), test))]
async fn goshai_flow(
    draft: &BindingDraft,
    explicit: Option<&WalletProviderCommand>,
) -> Result<WalletBinding> {
    let _ = (draft, explicit);
    bail!(
        "dexdo wallet onboard gosh-ai needs a shellnet build: the Hot is bound only after its \
         contract, threshold and custodian key are validated on chain, and this build has no chain \
         backend"
    )
}

#[cfg(feature = "shellnet")]
async fn goshai_flow(
    draft: &BindingDraft,
    explicit: Option<&WalletProviderCommand>,
) -> Result<WalletBinding> {
    use crate::cli::wallet_goshai::{run_wallet_onboard_goshai, GoshAiOnboardOptions};

    let args = match explicit {
        Some(WalletProviderCommand::GoshAi(args)) => Some(args.clone()),
        _ => None,
    };
    let network = args
        .as_ref()
        .map_or(crate::cli::args::WalletNetworkArg::Shellnet, |a| a.network);
    let contracts = args.as_ref().map_or_else(
        || std::path::PathBuf::from(dexdo_core::params::DEFAULT_CONTRACTS_PATH),
        |a| a.contracts.clone(),
    );
    run_wallet_onboard_goshai(GoshAiOnboardOptions {
        network: WalletNetwork::from(network),
        binding_id: draft.id().to_string(),
        endpoint: args.as_ref().and_then(|a| a.endpoint.clone()),
        contracts,
        activation_timeout: args
            .as_ref()
            .and_then(|a| a.activation_timeout)
            .unwrap_or(GoshAiOnboardOptions::DEFAULT_ACTIVATION_TIMEOUT),
        data_dir: crate::cli::data_dir::effective()?,
    })
    .await
}

#[cfg(not(any(feature = "shellnet", test)))]
async fn run_selected(
    action: WalletAction,
    provider: WalletProvider,
    explicit: Option<&WalletProviderCommand>,
) -> Result<()> {
    let _ = explicit;
    bail!(
        "dexdo wallet {action} {provider} needs a shellnet build: a wallet is bound only after \
         its contract is validated on chain, and this build has no chain backend"
    )
}

#[cfg(test)]
mod wallet_334_tests;

/// the id in `binding.json` is the id the store reserved, and its secrets are reachable
/// through it.
#[cfg(test)]
mod reserved_binding_id_tests;

/// the fail-fast as `note deploy` and `note topup` actually reach it.
#[cfg(test)]
mod fail_fast_wiring_tests;

/// the reader validates the id, so a record naming nothing never resolves as the wallet.
#[cfg(test)]
mod binding_load_validation_tests;

/// audit item 3: the binding is kept per network, and a command running on one network never
/// resolves -- and never spends -- a wallet bound on another.
#[cfg(test)]
mod per_network_binding_tests;
