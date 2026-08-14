//! `dexdo` CLI: `seller` and `buyer` subcommands, each with first-class flags
//! `--mock-model` and `--mock-chain`.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::IsTerminal as _;

mod cli;
#[cfg(test)]
mod test_refusing_endpoint;
use cli::args::*;
use cli::buyer::{run_buyer, run_subscription};
use cli::commands::*;
use cli::machine;
use cli::policy;

#[derive(Parser)]
#[command(
    name = "dexdo",
    version,
    about = "dexdo -- private inference market: seller and buyer clients"
)]
struct Cli {
    /// Root for this instance's automatically resolved state and configuration paths. Explicit
    /// path flags still override it. Without this flag, the legacy platform/cwd defaults remain.
    #[arg(long, global = true, value_name = "DIR")]
    data_dir: Option<std::path::PathBuf>,
    /// Measured non-contract-declared TokenContract lifetime gas remainder, in raw nanovmshell.
    /// Required when `provision` or `seller` funds a deal on a network other than the measurement's
    /// provenance; the value is used exactly as supplied.
    #[arg(long, global = true, value_name = "RAW_NANOVMSHELL")]
    deal_gas_overhead_raw: Option<u128>,
    #[command(subcommand)]
    command: Command,
}

#[cfg(test)]
#[path = "cli/accumulator_1323_tests.rs"]
mod accumulator_1323_tests;

#[cfg(test)]
#[path = "cli/wallet_334_cli_tests.rs"]
mod wallet_334_cli_tests;

mod wallet_onboard_cli_tests {
    use super::*;

    #[test]
    fn wallet_onboard_is_one_explicit_nested_command_with_explicit_local_files() {
        let cli = Cli::try_parse_from([
            "dexdo",
            "wallet",
            "onboard",
            "ackinacki-wallet",
            "--agent-name",
            "build-agent",
            "--network",
            "mainnet",
            "--endpoint",
            "mainnet.example",
            "--state",
            "session.json",
            "--hot-key",
            "hot.key",
            "--vault-key",
            "vault.key",
            "--qr-file",
            "invite.svg",
            "--terminal-qr",
        ])
        .unwrap();
        let Command::Wallet(WalletArgs {
            command:
                WalletCommand::Onboard(WalletBindArgs {
                    provider: Some(WalletProviderCommand::AckinackiWallet(args)),
                }),
        }) = cli.command
        else {
            panic!("expected wallet onboard ackinacki-wallet");
        };
        assert_eq!(args.agent_name, "build-agent");
        assert_eq!(args.network, WalletNetworkArg::Mainnet);
        assert_eq!(args.endpoint.as_deref(), Some("mainnet.example"));
        assert_eq!(args.state, Some(std::path::PathBuf::from("session.json")));
        assert_eq!(args.hot_key, Some(std::path::PathBuf::from("hot.key")));
        assert_eq!(args.vault_key, Some(std::path::PathBuf::from("vault.key")));
        assert_eq!(args.qr_file, Some(std::path::PathBuf::from("invite.svg")));
        assert!(args.terminal_qr);
    }

    #[test]
    fn wallet_onboarding_routes_logs_to_stderr() {
        let cli = Cli::try_parse_from([
            "dexdo", "wallet", "onboard", "ackinacki-wallet", "--agent-name", "agent",
            "--state", "session.json", "--hot-key", "hot.key",
        ])
        .unwrap();
        assert!(logs_to_stderr(&cli.command));

        let other = Cli::try_parse_from(["dexdo", "doctor"]).unwrap();
        assert!(!logs_to_stderr(&other.command));
    }

    /// follow-up item 6. The successor to `wallet_onboard_requires_agent_state_and_hot_key`,
    /// which asserted that omitting `--state` or `--hot-key` was a parse error.
    /// That requirement is what made the provider unreachable from the interactive menu: a menu
    /// carries no command line, so a required path is a dead end there. Both flags now have
    /// canonical defaults. This pins clap's two sentinel filenames; the wallet dispatcher's tests
    /// pin that each sentinel lands in the distinct binding draft reserved for the attempt.
    /// `--agent-name` is deliberately still required HERE and keeps its own case below: it is the
    /// label a human reads in the wallet app when approving, so on a command line the operator
    /// chooses it. Only the menu, which cannot ask, falls back to a constant.
    #[test]
    fn wallet_onboard_state_and_hot_key_have_canonical_sentinels() {
        let parsed = Cli::try_parse_from([
            "dexdo",
            "wallet",
            "onboard",
            "ackinacki-wallet",
            "--agent-name",
            "agent",
        ])
        .expect("--state and --hot-key must be optional, or the menu path is a dead end");
        let Command::Wallet(wallet) = &parsed.command else {
            panic!("expected the wallet command");
        };
        let cli::args::WalletCommand::Onboard(onboard) = &wallet.command else {
            panic!("expected `wallet onboard`");
        };
        let Some(cli::args::WalletProviderCommand::AckinackiWallet(args)) = onboard.provider.as_ref()
        else {
            panic!("expected the ackinacki-wallet provider");
        };
        assert_eq!(
            args.state,
            None
        );
        assert_eq!(
            args.hot_key,
            None
        );

    }

    /// `--agent-name` is still required on the subcommand. Kept from the predecessor test, because
    /// it is the one argument item 6 did NOT give a command-line default.
    #[test]
    fn wallet_onboard_still_requires_an_agent_name_on_the_command_line() {
        assert!(Cli::try_parse_from([
            "dexdo",
            "wallet",
            "onboard",
            "ackinacki-wallet",
            "--state",
            "session.json",
            "--hot-key",
            "hot.key",
        ])
        .is_err());
    }
}

fn logs_to_stderr(command: &Command) -> bool {
    command.machine_operation().is_some()
        || matches!(
            command,
            Command::Wallet(WalletArgs {
                command: WalletCommand::Onboard(_) | WalletCommand::Rebind(_),
            })
        )
}

#[derive(Subcommand)]
enum Command {
    /// Seller client: gateway, authorization, stream handover(headless, R12).
    Seller(SellerArgs),
    /// Buyer client: endpoint decryption, challenge signing, stream reception.
    Buyer(BuyerArgs),
    /// Monitor(R14): human-readable state view **from the loaded note** --
    /// own offers, deals, by-fact tokens, exposure. Read-only, moves nothing.
    Monitor(MonitorArgs),
    /// Doctor: read-only shellnet version/pin and market freshness checks. Alias: `health`.
    #[command(alias = "health")]
    Doctor(DoctorArgs),
    /// Check a decrypted seller gateway endpoint without a note, deal, chain call, or inference.
    #[command(name = "gateway-check")]
    GatewayCheck(GatewayCheckArgs),
    /// Provision: bring up the InferenceOrderBook + RootModel + per-deal TokenContract for a
    /// market -- **all note-funded** from the seller note's own ECC[2] (directive, no operator wallet,
    /// no giver in the operate path) -- and write the manifest with the deployed, active TC address.
    Provision(ProvisionArgs),
    /// Deploy-market: deploy the per-model `InferenceOrderBook`(the shared market for a model) if absent --
    /// note-funded, the explicit "list this model" step before a seller posts offers. Idempotent
    /// (the book address is deterministic from `model_hash`; already-deployed -> no-op).
    #[command(name = "deploy-market")]
    DeployMarket(MarketDeployArgs),
    /// Destroy: the seller CLOSES a STOPped deal's per-deal `TokenContract` --
    /// `TokenContract::destroy()` -> `selfdestruct`. **The payee is not an argument(4.0.33):** the deal
    /// pays the seller note it stored at construction, so nothing the caller passes decides where the
    /// money lands. **DESTRUCTIVE / BURNS:** after the 4.0.8 fund-10 sizing, the unrecovered deploy
    /// remainder is expected to be negligible; `--acknowledge-burn` is accepted and ignored so existing
    /// scripts keep running, and it does not gate `destroy` or change its behavior. Run after the deal STOPs
    /// (`!_opened && !_disputed`); seller-signed. Re-running it on an already destroyed deal is an
    /// idempotent no-op, not a failure.
    Destroy(DestroyArgs),
    /// Recover: the BUYER signs **STOP** on an orphaned OPEN deal (its buyer process died, but the
    /// note/key are intact) -- the normal buyer-STOP split, **without** placing a new buy -- so a stuck
    /// deal can be closed and the seller can then `destroy` it. Buyer-signed; fails closed if the deal is
    /// not OPEN / is disputed / the note is not the deal's buyer.
    Recover(RecoverArgs),
    /// Dispute: the BUYER opens an on-chain dispute on an OPEN deal -- `streamDispute` -> `TC.dispute()`
    /// freezes this TC's contested amount and seller bond until resolution. The anti-scam lever for an observed
    /// substitution/fraud -- strictly stronger than `recover`'s STOP (which still pays for delivered
    /// ticks). Buyer-signed; fails closed if the deal is not OPEN / already disputed / the note isn't the buyer.
    Dispute(DisputeArgs),
    /// Reclaim: recover buyer escrow after seller no-show. OPEN deals use the explicit
    /// `close`/`recover` STOP path; funded-but-never-opened deals use `streamCleanup` after
    /// `MATCH_OPEN_TIMEOUT`. Buyer-signed; fails closed locally on state, ownership, and the cleanup timer.
    /// with `--pool`/DEXDO_PN_POOL and no `--note-addr`/`--token-contract` it drives EVERY recorded
    /// recovery entry, each as its own reclaim -- so one invocation can move money for several deals, one
    /// per still-reclaimable recorded deal -- and refuses contradictory records instead of guessing.
    Reclaim(ReclaimArgs),
    /// ReleaseDispute: the SELLER concedes a disputed deal -- `TokenContract.releaseDispute()` returns
    /// this TC's contested amount to the buyer and the seller bond. Seller-signed; fails closed if the deal
    /// is not disputed or the signing key is not the TC seller.
    ReleaseDispute(ReleaseDisputeArgs),
    /// Resolve a disputed deal after the deployed dispute window. Permissionless; the contract computes and
    /// applies settlement, while the CLI rejects known-early or already-terminal calls before submit.
    #[command(name = "resolve-dispute-timeout")]
    ResolveDisputeTimeout(ResolveDisputeTimeoutArgs),
    /// WithdrawShell: the SELLER withdraws finalized `_finalizedOwed` SHELL from a deal TC. This moves
    /// seller proceeds; `destroy` remains the close/selfdestruct path.
    WithdrawShell(WithdrawShellArgs),
    /// Read-only chain-derived terminal settlement and withdrawal receipt for one TokenContract.
    #[command(name = "settlement-receipt")]
    SettlementReceipt(SettlementReceiptArgs),
    /// Markets: read-only discovery of active model order books and depth.
    Markets(MarketsArgs),
    /// Market: render ONE model's order book as the human-readable box table, for the model named below.
    Market(MarketArgs),
    /// Executable-book: list current buyer-executable asks for one model book.
    #[command(name = "executable-book")]
    ExecutableBook(ExecutableBookArgs),
    /// Quote: compute an executable quote over current order-book depth.
    Quote(QuoteArgs),
    /// Market-data: read-only Dodex indexer discovery/cache for inference model books.
    #[command(name = "market-data", alias = "indexer")]
    MarketData(MarketDataArgs),
    /// Orders: list/show/cancel this note's resting inference orders.
    Orders(OrdersArgs),
    /// Place, inspect, or cancel one pre-match single-seller subscription BUY.
    Subscription(SubscriptionArgs),
    /// Deals: list durable local deal handles saved by seller/buyer flows.
    Deals(DealsArgs),
    /// History: secret-free local trading history, filterable by note/model.
    History(HistoryArgs),
    /// Dashboard: loopback-only read view of local buyer/seller streams.
    Dashboard(DashboardArgs),
    /// Status: read current state for a local deal handle or raw TokenContract.
    Status(StatusArgs),
    /// Close: role-aware close/recovery action for a local deal handle or raw TokenContract.
    /// Seller closes an OPEN deal with `sellerStop`; a STOPped seller deal proceeds to `destroy`.
    Close(CloseArgs),
    /// Export: secret-free JSON/Markdown evidence for one local deal handle or raw TokenContract.
    Export(ExportArgs),
    /// Wallet: bind this instance, once and explicitly, to the funding(Hot) wallet its
    /// spending commands draw on. The provider is a subcommand and is never guessed later.
    Wallet(WalletArgs),
    /// Note: manage the actor's shellnet `PrivateNote`s. `note deploy` mints a wallet-funded PN
    /// in-process through `gosh.ackinacki` and folds it into a `DEXDO_PN_POOL` the `seller`/`buyer` consume.
    Note(NoteArgs),
    /// Oracle: deploy OracleEventList-backed range PMPs tied to inference order books and resolve them.
    Oracle(OracleArgs),
    /// Persistent failure policy for real buyer/seller startup and runtime recovery choices.
    Policy(PolicyArgs),
    /// Accumulator: exchange SHELL <-> eccUSDC from the operator multisig, in both
    /// directions, at the network's fixed 100 SHELL = 1 eccUSDC rate.
    Accumulator(AccumulatorArgs),
}

impl Command {
    fn machine_operation(&self) -> Option<&'static str> {
        match self {
            Command::Markets(args) if args.json => Some(machine::OP_MARKETS),
            Command::Quote(args) if args.json => Some(machine::OP_QUOTE),
            Command::Status(args) if args.json => Some(machine::OP_STATUS),
            Command::Close(args) if args.json => Some(machine::OP_CLOSE),
            Command::SettlementReceipt(args) if args.json => Some(machine::OP_SETTLEMENT_RECEIPT),
            Command::Note(args) if matches!(&args.command, NoteCommand::Deploy(args) if args.json) => {
                Some(machine::OP_NOTE_DEPLOY)
            }
            Command::Buyer(args) if args.json => Some(machine::OP_BUYER_START),
            Command::Subscription(args) if args.json => {
                Some(subscription_machine_operation(&args.command))
            }
            _ => None,
        }
    }

    fn apply_data_dir_defaults(&mut self) {
        use dexdo_core::params::{
            DEFAULT_CONTRACTS_PATH, DEFAULT_MARKET_MANIFEST_OUTPUT_PATH, DEFAULT_MODELS_PATH,
            DEFAULT_ORACLE_MARKET_OUTPUT_PATH,
        };

        let contracts = |path: &mut std::path::PathBuf| {
            cli::data_dir::rebase_default(path, DEFAULT_CONTRACTS_PATH)
        };
        let models = |path: &mut std::path::PathBuf| {
            cli::data_dir::rebase_default(path, DEFAULT_MODELS_PATH)
        };
        match self {
            Command::Seller(args) => {
                models(&mut args.models);
                contracts(&mut args.contracts);
            }
            Command::Buyer(args) => {
                models(&mut args.models);
                contracts(&mut args.contracts);
            }
            Command::Monitor(args) => contracts(&mut args.contracts),
            Command::Doctor(args) => contracts(&mut args.contracts),
            // Takes no `--contracts`/`--models` path: its whole input is the decrypted
            // endpoint and fingerprint, so there is nothing to rebase onto the data dir.
            Command::GatewayCheck(_) => {}
            Command::Provision(args) => {
                contracts(&mut args.contracts);
                cli::data_dir::rebase_default(
                    &mut args.output,
                    DEFAULT_MARKET_MANIFEST_OUTPUT_PATH,
                );
            }
            Command::DeployMarket(args) => contracts(&mut args.contracts),
            Command::Destroy(args) => contracts(&mut args.contracts),
            Command::Recover(args) => contracts(&mut args.contracts),
            Command::Dispute(args) => contracts(&mut args.contracts),
            Command::Reclaim(args) => contracts(&mut args.contracts),
            Command::ReleaseDispute(args) => contracts(&mut args.contracts),
            Command::ResolveDisputeTimeout(args) => contracts(&mut args.contracts),
            Command::WithdrawShell(args) => contracts(&mut args.contracts),
            Command::SettlementReceipt(args) => contracts(&mut args.contracts),
            Command::Markets(args) => {
                models(&mut args.models);
                contracts(&mut args.contracts);
            }
            Command::Market(args) => {
                models(&mut args.models);
                contracts(&mut args.contracts);
            }
            Command::ExecutableBook(args) => {
                models(&mut args.models);
                contracts(&mut args.contracts);
            }
            Command::Quote(args) => {
                models(&mut args.models);
                contracts(&mut args.contracts);
            }
            Command::MarketData(_) => {}
            Command::Orders(args) => {
                models(&mut args.models);
                contracts(&mut args.contracts);
            }
            Command::Subscription(args) => {
                models(&mut args.models);
                contracts(&mut args.contracts);
            }
            Command::Deals(_)
            | Command::History(_)
            | Command::Dashboard(_)
            | Command::Policy(_) => {}
// onboarding state/key paths are explicit arguments, not data-dir defaults. The two
            // providers that read the chain take the shared contracts manifest, so those are rebased.
            Command::Wallet(args) => {
                let provider = match &mut args.command {
                    WalletCommand::Onboard(bind) | WalletCommand::Rebind(bind) => {
                        bind.provider.as_mut()
                    }
                };
                match provider {
                    Some(WalletProviderCommand::Manual(manual)) => contracts(&mut manual.contracts),
                    Some(WalletProviderCommand::GoshAi(goshai)) => contracts(&mut goshai.contracts),
                    Some(WalletProviderCommand::AckinackiWallet(_)) | None => {}
                }
            }
            Command::Status(_) | Command::Close(_) | Command::Export(_) => {
                // Optional explicit manifests remain exact overrides. Their no-handle fallback goes
                // through `deal_contracts_path`, which uses the configured data root.
            }
            Command::Note(args) => match &mut args.command {
                NoteCommand::Wallet(args) => contracts(&mut args.contracts),
                NoteCommand::Balance(args) => contracts(&mut args.contracts),
                NoteCommand::Outstanding(args) => contracts(&mut args.contracts),
                NoteCommand::Deploy(args) => contracts(&mut args.contracts),
                NoteCommand::Recover(_) => {}
                NoteCommand::Topup(args) => contracts(&mut args.contracts),
                NoteCommand::Transfer(args) => contracts(&mut args.contracts),
                NoteCommand::Withdraw(args) => contracts(&mut args.contracts),
            },
            Command::Accumulator(args) => match &mut args.command {
                AccumulatorCommand::Status(args) => contracts(&mut args.contracts),
                AccumulatorCommand::Sell(args) => contracts(&mut args.contracts),
                AccumulatorCommand::Buy(args) => contracts(&mut args.contracts),
                AccumulatorCommand::Lots(args) => contracts(&mut args.contracts),
                AccumulatorCommand::Claim(args) => contracts(&mut args.contracts),
            },
            Command::Oracle(args) => match &mut args.command {
                OracleCommand::Address(args) => contracts(&mut args.contracts),
                OracleCommand::EventList(args) => match &mut args.command {
                    OracleEventListCommand::Address(args) => contracts(&mut args.contracts),
                    OracleEventListCommand::Events(args) => contracts(&mut args.contracts),
                },
                OracleCommand::Pmp(args) => match &mut args.command {
                    OraclePmpCommand::Address(args) => contracts(&mut args.contracts),
                    OraclePmpCommand::Status(args) => contracts(&mut args.contracts),
                },
                OracleCommand::Book(args) => match &mut args.command {
                    OracleBookCommand::Status(args) => contracts(&mut args.contracts),
                    OracleBookCommand::Order(args) => contracts(&mut args.contracts),
                    OracleBookCommand::Orders(args) => contracts(&mut args.contracts),
                },
                OracleCommand::Provision(args) => {
                    contracts(&mut args.contracts);
                    cli::data_dir::rebase_default(
                        &mut args.output,
                        DEFAULT_ORACLE_MARKET_OUTPUT_PATH,
                    );
                }
                OracleCommand::State(args) => contracts(&mut args.contracts),
                OracleCommand::Resolve(args)
                | OracleCommand::Cancel(args)
                | OracleCommand::Delete(args) => contracts(&mut args.contracts),
                OracleCommand::CancelStake(args) | OracleCommand::Claim(args) => {
                    contracts(&mut args.contracts)
                }
                OracleCommand::WithdrawFees(args) => contracts(&mut args.contracts),
            },
        }
    }

    fn instance_lock_request(&self) -> Option<(cli::data_dir::InstanceRole, bool)> {
        match self {
            Command::Seller(args) => Some((
                cli::data_dir::InstanceRole::Seller,
                args.deals_dir.is_none()
                    || (args.mock.mock_chain && args.endpoints_file.is_none()),
            )),
            Command::Buyer(args) => Some((
                cli::data_dir::InstanceRole::Buyer,
                args.endpoints_file.is_none()
                    || args.deals_dir.is_none()
                    || (cfg!(feature = "shellnet") && !args.mock.mock_chain),
            )),
            _ => None,
        }
    }
}

/// One operation name per subscription subcommand, so a failure is attributed to the move
/// that failed rather than to the command group.
fn subscription_machine_operation(command: &SubscriptionCommand) -> &'static str {
    match command {
        SubscriptionCommand::Place(_) => machine::OP_SUBSCRIPTION_PLACE,
        SubscriptionCommand::Status { .. } => machine::OP_SUBSCRIPTION_STATUS,
        SubscriptionCommand::Cancel { .. } => machine::OP_SUBSCRIPTION_CANCEL,
    }
}

fn raw_machine_operation(args: &[std::ffi::OsString]) -> Option<&'static str> {
    for (idx, arg) in args.iter().enumerate().skip(1) {
        let op = match arg.to_str()? {
            "markets" => machine::OP_MARKETS,
            "quote" => machine::OP_QUOTE,
            "buyer" => machine::OP_BUYER_START,
            "status" => machine::OP_STATUS,
            "close" => machine::OP_CLOSE,
            "settlement-receipt" => machine::OP_SETTLEMENT_RECEIPT,
            "note" if args.get(idx + 1).and_then(|a| a.to_str()) == Some("deploy") => {
                machine::OP_NOTE_DEPLOY
            }
            // the subcommand may sit anywhere after `subscription`, because the group's own
            // flags are accepted on either side of it. The first one that appears names the
            // operation; a command line with none of them is a parse failure with no operation to
            // attribute, and falls through to clap's own error.
            "subscription" => args.iter().skip(idx + 1).find_map(|a| match a.to_str() {
                Some("place") => Some(machine::OP_SUBSCRIPTION_PLACE),
                Some("status") => Some(machine::OP_SUBSCRIPTION_STATUS),
                Some("cancel") => Some(machine::OP_SUBSCRIPTION_CANCEL),
                _ => None,
            })?,
            _ => continue,
        };
        if args
            .iter()
            .skip(idx + 1)
            .any(|a| a.to_str() == Some("--json"))
        {
            return Some(op);
        }
        return None;
    }
    None
}

/// The operator close signal for `dexdo buyer` with `--local-listen`: SIGINT(Ctrl-C) **and** SIGTERM
/// (systemd/container/operator). `serve()` runs graceful shutdown on it, then awaits `session.settle("shutdown")`
/// -- so a `SIGTERM` does NOT bypass the awaited funds-safety terminal into best-effort `Drop`. Non-Unix: Ctrl-C.
#[cfg(unix)]
pub(crate) async fn operator_shutdown_signal() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
}

#[cfg(not(unix))]
pub(crate) async fn operator_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() -> Result<()> {
    let raw_args = std::env::args_os().collect::<Vec<_>>();
    let mut cli = match Cli::try_parse_from(raw_args.clone()) {
        Ok(cli) => cli,
        Err(err) => {
            if let Some(operation) = raw_machine_operation(&raw_args) {
                if operation == machine::OP_BUYER_START {
                    let mut events = machine::BuyerEventWriter::new();
                    events.error(
                        machine::OP_BUYER_START,
                        machine::ErrorCode::InvalidArgument,
                        serde_json::json!({}),
                    )?;
                } else {
                    machine::print_short_error(operation, machine::ErrorCode::InvalidArgument)?;
                }
                std::process::exit(err.exit_code());
            }
            err.exit();
        }
    };
    let deal_gas_overhead_raw = cli.deal_gas_overhead_raw;
    let deal_gas_override_on_non_funding_command = deal_gas_overhead_raw.is_some()
        && !matches!(&cli.command, Command::Provision(_) | Command::Seller(_));
    let machine_operation = cli.command.machine_operation();
    let env_filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if logs_to_stderr(&cli.command) {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(std::io::stderr)
            .with_ansi(std::io::stderr().is_terminal() && !cli::no_color_requested())
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_ansi(std::io::stdout().is_terminal() && !cli::no_color_requested())
            .init();
    }

    let instance_lock = cli::data_dir::configure(cli.data_dir.take()).and_then(|()| {
        cli.command.apply_data_dir_defaults();
        cli.command
            .instance_lock_request()
            .map(|(role, legacy_uses_shared_defaults)| {
                cli::data_dir::acquire_instance_lock(role, legacy_uses_shared_defaults)
            })
            .unwrap_or(Ok(None))
    });

    let result = match instance_lock {
        Err(error) => Err(error),
        Ok(_instance_lock) if deal_gas_override_on_non_funding_command => Err(anyhow::anyhow!(
            "--deal-gas-overhead-raw is only valid with `dexdo provision` or `dexdo seller`, the commands that fund per-deal TokenContracts"
        )),
        Ok(_instance_lock) => match cli.command {
            Command::Seller(args) if deal_gas_overhead_raw.is_some() => {
                run_seller_with_deal_gas_overhead(args, deal_gas_overhead_raw).await
            }
            Command::Seller(args) => run_seller(args).await,
            Command::Buyer(args) => run_buyer(args).await,
            Command::Monitor(args) => run_monitor(args).await,
            Command::Doctor(args) => run_doctor(args).await,
            Command::GatewayCheck(args) => run_gateway_check(args).await,
            Command::Provision(args) if deal_gas_overhead_raw.is_some() => {
                run_provision_with_deal_gas_overhead(args, deal_gas_overhead_raw).await
            }
            Command::Provision(args) => run_provision(args).await,
            Command::DeployMarket(args) => run_market_deploy(args).await,
            Command::Destroy(args) => run_destroy(args).await,
            Command::Recover(args) => run_recover(args).await,
            Command::Dispute(args) => run_dispute(args).await,
            Command::Reclaim(args) => run_reclaim(args).await,
            Command::ReleaseDispute(args) => run_release_dispute(args).await,
            Command::ResolveDisputeTimeout(args) => run_resolve_dispute_timeout(args).await,
            Command::WithdrawShell(args) => run_withdraw_shell(args).await,
            Command::SettlementReceipt(args) => run_settlement_receipt(args).await,
            Command::Markets(args) => run_markets(args).await,
            Command::Market(args) => run_market(args).await,
            Command::ExecutableBook(args) => run_executable_book(args).await,
            Command::Quote(args) => run_quote(args).await,
            Command::MarketData(args) => run_market_data(args).await,
            Command::Orders(args) => run_orders(args).await,
            Command::Subscription(args) => run_subscription(args).await,
            Command::Deals(args) => run_deals(args).await,
            Command::History(args) => run_history(args).await,
            Command::Dashboard(args) => run_dashboard(args).await,
            Command::Status(args) => run_status(args).await,
            Command::Close(args) => run_close(args).await,
            Command::Export(args) => run_export(args).await,
            // step 9: ONE dispatcher for every wallet shape. `ackinacki-wallet` used to have
            // its own arm here, which meant it bypassed `run_selected` and so produced no binding
            // at all -- the flow succeeded and left the operator unconfigured. All three providers
            // now reach `provider_flow`, and the store is the single writer of the binding.
            Command::Wallet(args) => cli::wallet::run_wallet(args).await,
            Command::Note(args) => match args.command {
                NoteCommand::Wallet(w) => run_note_wallet(w).await,
                NoteCommand::Balance(b) => run_note_balance(b).await,
                NoteCommand::Outstanding(o) => run_note_outstanding(o).await,
                NoteCommand::Deploy(d) => run_note_deploy(d).await,
                NoteCommand::Recover(r) => run_note_recover(r).await,
                NoteCommand::Topup(t) => run_note_topup(t).await,
                NoteCommand::Transfer(t) => run_note_transfer(t).await,
                NoteCommand::Withdraw(w) => run_note_withdraw(w).await,
            },
            Command::Oracle(args) => run_oracle(args).await,
            Command::Policy(args) => policy::run_policy(args),
            Command::Accumulator(args) => run_accumulator(args).await,
        },
    };
    if let Err(err) = result {
        if machine::is_printed_error(&err) {
            std::process::exit(1);
        }
        if let Some(operation) = machine_operation {
            let code = machine::classify_error(operation, &err);
            machine::print_error(operation, code, &err)?;
            std::process::exit(1);
        }
        // a structured error renders itself -- code, kind, message, the preserved `cause:`
        // chain, any `secondary:` consequence, and the `hint:`. Printing it through `anyhow`'s
        // `Debug` on top of that would repeat every cause under a second `Caused by:` block.
        if let Some(structured) = err.downcast_ref::<dexdo_core::DexdoError>() {
            eprintln!("{structured}");
            std::process::exit(1);
        }
        return Err(err);
    }
    Ok(())
}

#[cfg(test)]
mod buyer_mode_tests {
    use crate::cli::support::oneshot_real_upstream_guard;
    use serde_json::json;

    /// one-shot `dexdo buyer`(no `--local-listen`) is promptless -- it must fail closed
    /// against a real seller(no `--mock-model`) with an actionable error, instead of a deep gateway
    /// `InvalidArgument`. `--local-listen`(consumer API supplies the prompt) and `--mock-model` both pass.
    #[test]
    fn oneshot_real_upstream_rejected_promptless() {
        let err = oneshot_real_upstream_guard(false, false).unwrap_err();
        assert!(err.contains("--local-listen"), "{err}");
        assert!(err.contains(""), "{err}");
        // one-shot + --mock-model -> OK(the mock seller synthesizes tokens for the promptless stream).
        assert!(oneshot_real_upstream_guard(false, true).is_ok());
        // --local-listen(consumer API supplies the prompt per request) -> OK regardless of --mock-model.
        assert!(oneshot_real_upstream_guard(true, false).is_ok());
        assert!(oneshot_real_upstream_guard(true, true).is_ok());
    }

    #[test]
    fn user_visible_onchain_error_contains_numeric_exit_code() {
        let err = dexdo_core::validate_onchain_submit_response(json!({
            "result": {"exit_code": 321, "aborted": true}
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("exit_code=321"), "{err}");
        assert!(err.contains("ERR_ALREADY_OPEN"), "{err}");
    }
}

#[cfg(test)]
mod recovery_cli_tests {
    use super::{Cli, Command};
    use clap::Parser;

    /// `dexdo dispute` and `dexdo reclaim` parse as buyer-signed subcommands, accepting `--market` (the
    /// single TC source, mirroring `recover`) and `--token-contract` as the alternative.
    #[test]
    fn dispute_reclaim_subcommands_parse() {
        let c = Cli::try_parse_from([
            "dexdo",
            "dispute",
            "--market",
            "m.json",
            "--note-addr",
            "0:b",
        ])
        .expect("dispute --market parses");
        assert!(matches!(c.command, Command::Dispute(_)));
        let c = Cli::try_parse_from([
            "dexdo",
            "reclaim",
            "--market",
            "m.json",
            "--note-addr",
            "0:b",
        ])
        .expect("reclaim --market parses");
        assert!(matches!(c.command, Command::Reclaim(_)));
        assert!(Cli::try_parse_from(["dexdo", "dispute", "--token-contract", "0:tc"]).is_ok());
        assert!(Cli::try_parse_from(["dexdo", "reclaim", "--token-contract", "0:tc"]).is_ok());
    }

    /// seller-side dispute/payout commands parse with either a market manifest or explicit TC.
    #[test]
    fn seller_dispute_payout_subcommands_parse() {
        let c = Cli::try_parse_from([
            "dexdo",
            "release-dispute",
            "--market",
            "m.json",
            "--note-addr",
            "0:s",
        ])
        .expect("release-dispute --market parses");
        assert!(matches!(c.command, Command::ReleaseDispute(_)));
        let c = Cli::try_parse_from([
            "dexdo",
            "withdraw-shell",
            "--token-contract",
            "0:tc",
            "--note-addr",
            "0:s",
            "--amount",
            "100",
        ])
        .expect("withdraw-shell --token-contract parses");
        assert!(matches!(c.command, Command::WithdrawShell(_)));
    }

    #[test]
    fn withdraw_shell_rejects_recipient_as_unknown_argument() {
        let error = match Cli::try_parse_from([
            "dexdo",
            "withdraw-shell",
            "--token-contract",
            "0:tc",
            "--note-addr",
            "0:s",
            "--recipient",
            "0:other",
        ]) {
            Ok(_) => panic!("withdraw-shell must not accept the removed --recipient flag"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn permissionless_dispute_timeout_subcommand_parses_without_identity() {
        let c = Cli::try_parse_from([
            "dexdo",
            "resolve-dispute-timeout",
            "--token-contract",
            "0:tc",
        ])
        .expect("permissionless timeout command parses");
        assert!(matches!(c.command, Command::ResolveDisputeTimeout(_)));
    }
}

#[cfg(test)]
mod note_cli_tests {
    use super::{Cli, Command};
    use crate::cli::args::NoteCommand;
    #[cfg(feature = "shellnet")]
    use crate::cli::args::{IdentityArgs, NoteWithdrawArgs};
    use clap::Parser;
    use std::path::PathBuf;

    const NOTE: &str = "0:2222222222222222222222222222222222222222222222222222222222222222";
    const DEST_HALF_1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const DEST_HALF_2: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    /// the existing passed-in multisig contract remains the `note deploy` default:
    /// address plus exactly one key source, with the established deploy defaults.: the
    /// deposit nominal is now one of the required flags, never a silent default.
    #[test]
    fn note_deploy_subcommand_parses() {
        let c = Cli::try_parse_from([
            "dexdo",
            "note",
            "deploy",
            "--json",
            "--multisig-address",
            "0:wallet",
            "--multisig-key",
            "w.keys.json",
            "--nominal",
            "N100",
            "--pool",
            "pn_pool.json",
        ])
        .expect("note deploy parses with required flags + defaults");
        let Command::Note(n) = c.command else {
            panic!("expected Command::Note");
        };
        let NoteCommand::Deploy(d) = n.command else {
            panic!("expected NoteCommand::Deploy");
        };
        assert_eq!(d.nominal, "N100");
        assert_eq!(d.token_type, "shell");
        assert_eq!(d.endpoint, "shellnet.ackinacki.org");
        assert_eq!(
            d.contracts,
            PathBuf::from("contracts/deployed.shellnet.json")
        );
        assert_eq!(d.multisig_address, Some("0:wallet".to_string()));
        assert_eq!(d.multisig_key, Some(PathBuf::from("w.keys.json")));
        assert_eq!(d.multisig_seed_file, None);
        assert_eq!(d.pool, PathBuf::from("pn_pool.json"));
        assert_eq!(d.recovery, None);
        assert!(d.json);
        assert!(!d.simulate_interrupt_after_spend_before_pool);
        let c = Cli::try_parse_from([
            "dexdo",
            "note",
            "deploy",
            "--multisig-address",
            "0:wallet",
            "--multisig-seed-file",
            r"C:\Users\operator\wallet.seed",
            "--nominal",
            "N100",
            "--pool",
            "pn_pool.json",
            "--recovery",
            "pn_pool.json.recovery.json",
        ])
        .expect("note deploy parses seed-file path");
        let Command::Note(n) = c.command else {
            panic!("expected Command::Note");
        };
        let NoteCommand::Deploy(d) = n.command else {
            panic!("expected NoteCommand::Deploy");
        };
        assert_eq!(d.multisig_address, Some("0:wallet".to_string()));
        assert_eq!(d.multisig_key, None);
        assert_eq!(
            d.multisig_seed_file,
            Some(PathBuf::from(r"C:\Users\operator\wallet.seed"))
        );
        assert_eq!(
            d.recovery,
            Some(PathBuf::from("pn_pool.json.recovery.json"))
        );
        assert!(!d.json);
        // The passed-in wallet address and one key input remain independently required. Each of
        // these supplies `--nominal` so the rejection is provably the flag under test, not the
        // newly required nominal.
        assert!(Cli::try_parse_from([
            "dexdo",
            "note",
            "deploy",
            "--multisig-key",
            "w.keys.json",
            "--nominal",
            "N100",
            "--pool",
            "p.json",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "dexdo",
            "note",
            "deploy",
            "--multisig-address",
            "0:wallet",
            "--nominal",
            "N100",
            "--pool",
            "p.json",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "dexdo",
            "note",
            "deploy",
            "--multisig-address",
            "0:wallet",
            "--multisig-key",
            "w.keys.json",
            "--multisig-seed-file",
            "wallet.seed",
            "--nominal",
            "N100",
            "--pool",
            "pn_pool.json",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "dexdo",
            "note",
            "deploy",
            "--multisig-address",
            "0:wallet",
            "--multisig-key",
            "w.keys.json",
            "--nominal",
            "N100",
            "--pool",
            "pn_pool.json",
            "--onboard-bin",
            "/bin/onboard_user_shellnet",
        ])
        .is_err());
    }

    /// `dexdo note recover` finalizes from the crash-safe state without wallet credentials.
    #[test]
    fn note_recover_subcommand_parses() {
        let c = Cli::try_parse_from([
            "dexdo",
            "note",
            "recover",
            "--recovery",
            "pn_pool.json.recovery.json",
            "--pool",
            "pn_pool.json",
        ])
        .expect("note recover parses");
        let Command::Note(n) = c.command else {
            panic!("expected Command::Note");
        };
        let NoteCommand::Recover(r) = n.command else {
            panic!("expected NoteCommand::Recover");
        };
        assert_eq!(r.recovery, PathBuf::from("pn_pool.json.recovery.json"));
        assert_eq!(r.pool, PathBuf::from("pn_pool.json"));
        assert!(Cli::try_parse_from(["dexdo", "note", "recover", "--pool", "p.json"]).is_err());
        assert!(
            Cli::try_parse_from(["dexdo", "note", "recover", "--recovery", "state.json"]).is_err()
        );
    }

    /// `dexdo note withdraw` is owner-signed money movement, so the parser surface and destination
    /// normalization contract are pinned separately from the live shellnet submit.
    #[test]
    fn note_withdraw_subcommand_parses_and_requires_destination() {
        let to = format!("{DEST_HALF_1}::{DEST_HALF_2}");
        let c = Cli::try_parse_from([
            "dexdo",
            "note",
            "withdraw",
            "--note-addr",
            NOTE,
            "--note-key",
            "note.key",
            "--to",
            &to,
            "--contracts",
            "contracts/custom.json",
        ])
        .expect("note withdraw parses");
        let Command::Note(n) = c.command else {
            panic!("expected Command::Note");
        };
        let NoteCommand::Withdraw(w) = n.command else {
            panic!("expected NoteCommand::Withdraw");
        };
        assert_eq!(w.identity.note_addr.as_deref(), Some(NOTE));
        assert_eq!(w.identity.note_key, Some(PathBuf::from("note.key")));
        assert_eq!(w.to, to);
        assert_eq!(w.contracts, PathBuf::from("contracts/custom.json"));
        assert!(Cli::try_parse_from([
            "dexdo",
            "note",
            "withdraw",
            "--note-addr",
            NOTE,
            "--note-key",
            "note.key",
        ])
        .is_err());

        let normalized =
            dexdo_core::normalize_wallet_address(&format!("{DEST_HALF_1}::{DEST_HALF_2}"))
                .expect("half1::half2 normalizes");
        assert_eq!(normalized, format!("0:{DEST_HALF_2}"));
        assert!(dexdo_core::normalize_wallet_address("not-a-wallet").is_err());
    }

    /// `dexdo note balance` is address-only and read-only at the parser surface.
    #[test]
    fn note_balance_subcommand_parses_and_requires_note_addr() {
        let c = Cli::try_parse_from([
            "dexdo",
            "note",
            "balance",
            "--note-addr",
            NOTE,
            "--contracts",
            "contracts/custom.json",
            "--endpoint",
            "new-shellnet.example",
        ])
        .expect("note balance parses");
        let Command::Note(n) = c.command else {
            panic!("expected Command::Note");
        };
        let NoteCommand::Balance(b) = n.command else {
            panic!("expected NoteCommand::Balance");
        };
        assert_eq!(b.note_addr, NOTE);
        assert_eq!(b.contracts, PathBuf::from("contracts/custom.json"));
        assert_eq!(b.endpoint.as_deref(), Some("new-shellnet.example"));
        assert!(Cli::try_parse_from(["dexdo", "note", "balance"]).is_err());
        assert!(Cli::try_parse_from([
            "dexdo",
            "note",
            "balance",
            "--note-addr",
            NOTE,
            "--note-key",
            "note.key",
        ])
        .is_err());
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn note_withdraw_runtime_guards_fail_before_chain() {
        let err = crate::cli::commands::run_note_withdraw(NoteWithdrawArgs {
            identity: IdentityArgs {
                note_key: Some(PathBuf::from("note.key")),
                note_index: 0,
                note_addr: None,
            },
            to: format!("{DEST_HALF_1}::{DEST_HALF_2}"),
            contracts: PathBuf::from("contracts/deployed.shellnet.json"),
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("--note-addr"), "{err}");

        let err = crate::cli::commands::run_note_withdraw(NoteWithdrawArgs {
            identity: IdentityArgs {
                note_key: None,
                note_index: 0,
                note_addr: Some(NOTE.to_string()),
            },
            to: format!("{DEST_HALF_1}::{DEST_HALF_2}"),
            contracts: PathBuf::from("contracts/deployed.shellnet.json"),
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("--note-key"), "{err}");

        let err = crate::cli::commands::run_note_withdraw(NoteWithdrawArgs {
            identity: IdentityArgs {
                note_key: Some(PathBuf::from("missing-note.key")),
                note_index: 0,
                note_addr: Some(NOTE.to_string()),
            },
            to: "not-a-wallet".to_string(),
            contracts: PathBuf::from("contracts/deployed.shellnet.json"),
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("--to"), "{err}");
    }
}

#[cfg(test)]
mod doctor_cli_tests {
    use super::{Cli, Command};
    use clap::Parser;

    /// `dexdo doctor` is the read-only shellnet health guard; `health` is kept as an alias.
    #[test]
    fn doctor_subcommand_parses() {
        let c = Cli::try_parse_from(["dexdo", "doctor"]).expect("doctor parses");
        assert!(matches!(c.command, Command::Doctor(_)));
        let c = Cli::try_parse_from(["dexdo", "health", "--market", "m.json"])
            .expect("health alias parses");
        assert!(matches!(c.command, Command::Doctor(_)));
    }

    #[test]
    fn doctor_accepts_non_shellnet_endpoint() {
        let c = Cli::try_parse_from([
            "dexdo",
            "doctor",
            "--network",
            "https://new-shellnet.example/",
        ])
        .expect("doctor accepts an endpoint through --network");
        let Command::Doctor(args) = c.command else {
            panic!("expected Command::Doctor");
        };
        assert_eq!(args.network, "https://new-shellnet.example/");
    }
}

#[cfg(test)]
mod market_orders_cli_tests {
    use super::{machine, raw_machine_operation, Cli, Command};
    use crate::cli::args::{
        MarketDataCommand, MarketDataOutput, OrdersCommand, SubscriptionCommand,
    };
    use clap::Parser;
    use dexdo_core::params::DEFAULT_CHAIN_READ_TIMEOUT_SECS;
    use std::path::PathBuf;

    /// Every CLI argument that becomes an InferenceOrderBook price accepts the contract's exact
    /// uint128 maximum and rejects the adjacent out-of-range decimal in clap, before dispatch can
    /// construct a backend. Treating one surface as uint64 is the adversary because it rejects a
    /// contract-valid price at the command boundary.
    /// E2E-PLACE-04, `tests/e2e/test-specification.md`.
    /// E2E-ROW: E2E-PLACE-04/L0
    #[ignore = "EXPECTED TO FAIL until every applicable CLI price surface uses the contract's uint128 range"]
    #[test]
    fn place_04_every_price_argument_rejects_only_above_uint128() {
        let max = u128::MAX.to_string();
        let above = "340282366920938463463374607431768211456";
        let command_lines = vec![
            vec!["dexdo", "seller", "--price-per-tick", "VALUE"],
            vec!["dexdo", "buyer", "--max-price-per-tick", "VALUE"],
            vec![
                "dexdo",
                "provision",
                "--frame-model",
                "model",
                "--price-per-tick",
                "VALUE",
            ],
            vec![
                "dexdo",
                "executable-book",
                "model",
                "--max-price-per-tick",
                "VALUE",
            ],
            vec![
                "dexdo",
                "subscription",
                "--model",
                "model",
                "place",
                "--max-price-per-tick",
                "VALUE",
                "--ticks",
                "4",
            ],
        ];

        let exact_max_accepted = command_lines.iter().all(|args| {
            Cli::try_parse_from(
                args.iter()
                    .map(|arg| if *arg == "VALUE" { max.as_str() } else { arg }),
            )
            .is_ok()
        });
        let above_max_rejected = command_lines.iter().all(|args| {
            Cli::try_parse_from(
                args.iter()
                    .map(|arg| if *arg == "VALUE" { above } else { arg }),
            )
            .is_err()
        });

        assert!(
            exact_max_accepted && above_max_rejected,
            "E2E-PLACE-04 missing capability: CLI price parsing diverges from the uint128 contract boundary"
        );
    }

    /// market discovery and executable quote commands parse the intended read-only surfaces.
    #[test]
    fn markets_and_quote_subcommands_parse() {
        let c = Cli::try_parse_from([
            "dexdo", "markets", "--market", "m1.json", "--market", "m2.json",
        ])
        .expect("markets with manifests parses");
        let Command::Markets(m) = c.command else {
            panic!("expected Command::Markets");
        };
        assert_eq!(
            m.market,
            vec![PathBuf::from("m1.json"), PathBuf::from("m2.json")]
        );
        assert_eq!(
            m.read_timeout.read_timeout_secs,
            DEFAULT_CHAIN_READ_TIMEOUT_SECS
        );

        let c = Cli::try_parse_from(["dexdo", "quote", "--market", "m.json", "--ticks", "3"])
            .expect("quote by ticks parses");
        let Command::Quote(q) = c.command else {
            panic!("expected Command::Quote");
        };
        assert_eq!(q.market, Some(PathBuf::from("m.json")));
        assert_eq!(q.ticks, Some(3));
        assert_eq!(q.budget, None);
        assert_eq!(
            q.read_timeout.read_timeout_secs,
            DEFAULT_CHAIN_READ_TIMEOUT_SECS
        );

        let c = Cli::try_parse_from([
            "dexdo",
            "quote",
            "--market",
            "m.json",
            "--read-timeout-secs",
            "7",
            "--ticks",
            "3",
            "--model-registry-validation",
            "registry.json",
            "--model-registry-address",
            "0:9999999999999999999999999999999999999999999999999999999999999999",
        ])
        .expect("quote registry validation flags parse");
        let Command::Quote(q) = c.command else {
            panic!("expected Command::Quote");
        };
        assert_eq!(
            q.registry.model_registry_validation,
            Some(PathBuf::from("registry.json"))
        );
        assert_eq!(
            q.registry.model_registry_address.as_deref(),
            Some("0:9999999999999999999999999999999999999999999999999999999999999999")
        );
        assert_eq!(q.read_timeout.read_timeout_secs, 7);

        let c = Cli::try_parse_from([
            "dexdo",
            "quote",
            "--model",
            "qwen",
            "--note-addr",
            "0:note",
            "--budget",
            "100000",
        ])
        .expect("quote by budget parses");
        assert!(matches!(c.command, Command::Quote(_)));

        let c = Cli::try_parse_from([
            "dexdo",
            "market",
            "--read-timeout-secs",
            "9",
            "--note-addr",
            "0:note",
            "qwen",
        ])
        .expect("market read timeout parses");
        let Command::Market(m) = c.command else {
            panic!("expected Command::Market");
        };
        assert_eq!(m.read_timeout.read_timeout_secs, 9);
        assert!(Cli::try_parse_from([
            "dexdo",
            "market",
            "--read-timeout-secs",
            "0",
            "--note-addr",
            "0:note",
            "qwen",
        ])
        .is_err());

        let c = Cli::try_parse_from([
            "dexdo",
            "executable-book",
            "--market",
            "m.json",
            "--ticks",
            "8",
            "--max-price-per-tick",
            "1000",
            "--read-timeout-secs",
            "11",
            "qwen",
        ])
        .expect("executable-book parses");
        let Command::ExecutableBook(b) = c.command else {
            panic!("expected Command::ExecutableBook");
        };
        assert_eq!(b.market, Some(PathBuf::from("m.json")));
        assert_eq!(b.ticks, 8);
        assert_eq!(b.max_price_per_tick, 1000);
        assert_eq!(b.read_timeout.read_timeout_secs, 11);
    }

    /// read-only Dodex indexer discovery parses independently of shellnet signing flags.
    #[test]
    fn market_data_subcommands_parse() {
        let c = Cli::try_parse_from([
            "dexdo",
            "market-data",
            "--indexer-url",
            "http://dodex-dev.ackinacki.org:8080",
            "--output",
            "json",
            "--contracts",
            "contracts/custom.json",
            "--endpoint",
            "new-shellnet.example",
            "list",
            "--producer",
            "qwen",
            "--status",
            "TRADING",
            "--cursor",
            "MTc4Mjg4NDY0MTAwMDAwMDo0",
            "--limit",
            "50",
        ])
        .expect("market-data list parses");
        let Command::MarketData(args) = c.command else {
            panic!("expected Command::MarketData");
        };
        assert_eq!(
            args.indexer_url.as_deref(),
            Some("http://dodex-dev.ackinacki.org:8080")
        );
        assert_eq!(args.output, MarketDataOutput::Json);
        assert_eq!(args.contracts, Some(PathBuf::from("contracts/custom.json")));
        assert_eq!(args.endpoint.as_deref(), Some("new-shellnet.example"));
        assert_eq!(args.timeout_ms, 10_000);
        let MarketDataCommand::List {
            producer,
            status,
            cursor,
            limit,
        } = args.command
        else {
            panic!("expected list");
        };
        assert_eq!(producer.as_deref(), Some("qwen"));
        assert_eq!(status.as_deref(), Some("TRADING"));
        assert_eq!(cursor.as_deref(), Some("MTc4Mjg4NDY0MTAwMDAwMDo0"));
        assert_eq!(limit, Some(50));

        let c = Cli::try_parse_from([
            "dexdo",
            "market-data",
            "list",
            "--output",
            "json",
            "--timeout-ms",
            "10000",
            "--limit",
            "1",
        ])
        .expect("market-data list accepts shared flags after subcommand");
        let Command::MarketData(args) = c.command else {
            panic!("expected Command::MarketData");
        };
        assert_eq!(args.output, MarketDataOutput::Json);
        assert_eq!(args.timeout_ms, 10_000);
        assert_eq!(args.contracts, None);
        assert!(matches!(
            args.command,
            MarketDataCommand::List { limit: Some(1), .. }
        ));

        let c = Cli::try_parse_from([
            "dexdo",
            "market-data",
            "list",
            "--contracts",
            "contracts/after-subcommand.json",
        ])
        .expect("market-data list accepts compatibility --contracts after subcommand");
        let Command::MarketData(args) = c.command else {
            panic!("expected Command::MarketData");
        };
        assert_eq!(
            args.contracts,
            Some(PathBuf::from("contracts/after-subcommand.json"))
        );

        let c = Cli::try_parse_from([
            "dexdo",
            "indexer",
            "show",
            "0:4a04daaf8aff55a23c8dd5edabf7c81eeb300c7b5d70ad0c6fa955c25eab0b76",
            "--output",
            "json",
        ])
        .expect("indexer alias show parses");
        assert!(matches!(
            c.command,
            Command::MarketData(crate::cli::args::MarketDataArgs {
                output: MarketDataOutput::Json,
                command: MarketDataCommand::Show { .. },
                ..
            })
        ));

        let c = Cli::try_parse_from([
            "dexdo",
            "market-data",
            "depth",
            "0:4a04daaf8aff55a23c8dd5edabf7c81eeb300c7b5d70ad0c6fa955c25eab0b76",
            "--output",
            "json",
            "--limit",
            "5",
        ])
        .expect("market-data depth parses");
        assert!(matches!(
            c.command,
            Command::MarketData(crate::cli::args::MarketDataArgs {
                output: MarketDataOutput::Json,
                command: MarketDataCommand::Depth { limit: Some(5), .. },
                ..
            })
        ));

        assert!(Cli::try_parse_from(["dexdo", "market-data", "list", "--limit", "0"]).is_err());
        assert!(Cli::try_parse_from([
            "dexdo",
            "market-data",
            "depth",
            "0:4a04daaf8aff55a23c8dd5edabf7c81eeb300c7b5d70ad0c6fa955c25eab0b76",
            "--limit",
            "1001",
        ])
        .is_err());
    }

    /// own-order lifecycle commands parse as one note-scoped surface.
    #[test]
    fn orders_subcommands_parse() {
        let c = Cli::try_parse_from([
            "dexdo",
            "orders",
            "--note-addr",
            "0:note",
            "--market",
            "m.json",
            "list",
        ])
        .expect("orders list parses");
        let Command::Orders(o) = c.command else {
            panic!("expected Command::Orders");
        };
        assert!(matches!(o.command, OrdersCommand::List));
        assert_eq!(
            o.read_timeout.read_timeout_secs,
            DEFAULT_CHAIN_READ_TIMEOUT_SECS
        );

        let c = Cli::try_parse_from([
            "dexdo",
            "orders",
            "--note-addr",
            "0:note",
            "--read-timeout-secs",
            "11",
            "--model",
            "qwen",
            "show",
            "7",
        ])
        .expect("orders show parses");
        let Command::Orders(o) = c.command else {
            panic!("expected Command::Orders");
        };
        assert!(matches!(o.command, OrdersCommand::Show { order_id: 7 }));
        assert_eq!(o.read_timeout.read_timeout_secs, 11);

        let c = Cli::try_parse_from([
            "dexdo",
            "orders",
            "--note-addr",
            "0:note",
            "--note-key",
            "note.secret",
            "--market",
            "m.json",
            "cancel",
            "7",
        ])
        .expect("orders cancel parses");
        assert!(matches!(
            c.command,
            Command::Orders(crate::cli::args::OrdersArgs {
                command: OrdersCommand::Cancel { order_id: 7 },
                ..
            })
        ));

        let c = Cli::try_parse_from([
            "dexdo",
            "orders",
            "--note-addr",
            "0:note",
            "--note-key",
            "note.secret",
            "--market",
            "m.json",
            "cancel-all",
        ])
        .expect("orders cancel-all parses");
        assert!(matches!(
            c.command,
            Command::Orders(crate::cli::args::OrdersArgs {
                command: OrdersCommand::CancelAll,
                ..
            })
        ));
    }

    /// subscription lifecycle commands parse the note-scoped inference surface.
    #[test]
    fn subscription_subcommands_parse() {
        let c = Cli::try_parse_from([
            "dexdo",
            "subscription",
            "--note-addr",
            "0:note",
            "--note-key",
            "note.secret",
            "--market",
            "m.json",
            "place",
            "--max-price-per-tick",
            "1000000000",
            "--ticks",
            "4",
        ])
        .expect("subscription place parses");
        let Command::Subscription(s) = c.command else {
            panic!("expected Command::Subscription");
        };
        let SubscriptionCommand::Place(p) = s.command else {
            panic!("expected subscription place");
        };
        assert_eq!(s.market, Some(PathBuf::from("m.json")));
        assert_eq!(
            s.read_timeout.read_timeout_secs,
            DEFAULT_CHAIN_READ_TIMEOUT_SECS
        );
        assert_eq!(p.max_price_per_tick, dexdo_core::PRICE_STEP);
        assert_eq!(p.ticks, 4);

        let c = Cli::try_parse_from([
            "dexdo",
            "subscription",
            "--note-addr",
            "0:note",
            "--market",
            "m.json",
            "place",
            "--note-key",
            "note.secret",
            "--max-price-per-tick",
            "1000000000",
            "--ticks",
            "4",
        ])
        .expect("subscription place accepts --note-key after place");
        let Command::Subscription(s) = c.command else {
            panic!("expected Command::Subscription");
        };
        let SubscriptionCommand::Place(p) = s.command else {
            panic!("expected subscription place");
        };
        assert_eq!(s.identity.note_key, None);
        assert_eq!(p.note_key, Some(PathBuf::from("note.secret")));

        let c = Cli::try_parse_from([
            "dexdo",
            "subscription",
            "--note-addr",
            "0:note",
            "--read-timeout-secs",
            "12",
            "--model",
            "qwen",
            "status",
            "7",
        ])
        .expect("subscription status parses");
        assert!(matches!(
            c.command,
            Command::Subscription(crate::cli::args::SubscriptionArgs {
                command: SubscriptionCommand::Status { order_id: 7, .. },
                read_timeout: crate::cli::args::ChainReadTimeoutArgs {
                    read_timeout_secs: 12
                },
                ..
            })
        ));

        let c = Cli::try_parse_from([
            "dexdo",
            "subscription",
            "--note-addr",
            "0:note",
            "--note-key",
            "note.secret",
            "--market",
            "m.json",
            "cancel",
            "7",
        ])
        .expect("subscription cancel parses");
        assert!(matches!(
            c.command,
            Command::Subscription(crate::cli::args::SubscriptionArgs {
                command: SubscriptionCommand::Cancel { order_id: 7 },
                ..
            })
        ));

        let c = Cli::try_parse_from([
            "dexdo",
            "subscription",
            "--mock-model",
            "--mock-chain",
            "--endpoints-file",
            "mock-endpoints.json",
            "--model",
            "qwen--qwen3--32b",
            "status",
            "7",
        ])
        .expect("explicit mock subscription flags parse");
        let Command::Subscription(s) = c.command else {
            panic!("expected mock subscription");
        };
        assert!(s.mock.mock_model);
        assert!(s.mock.mock_chain);
        assert_eq!(
            s.endpoints_file,
            Some(std::path::PathBuf::from("mock-endpoints.json"))
        );

        assert!(Cli::try_parse_from([
            "dexdo",
            "subscription",
            "--note-addr",
            "0:note",
            "--market",
            "m.json",
            "place",
            "--max-price-per-tick",
            "1000000000",
            "--ticks",
            "4",
            "--budget",
            "4100",
        ])
        .is_err());
    }

    /// `--json` is accepted on all three subscription subcommands, before or after the
    /// subcommand word, and each one names its own machine operation so a failure is attributed to
    /// the move that failed. Without the flag there is no machine operation and human output stands.
    #[test]
    fn subscription_json_is_accepted_and_names_one_operation_per_subcommand() {
        let place = |json_first: bool| {
            let mut argv = vec!["dexdo", "subscription", "--note-addr", "0:note", "--market", "m.json"];
            if json_first {
                argv.push("--json");
            }
            argv.extend(["place", "--max-price-per-tick", "1000000000", "--ticks", "4"]);
            if !json_first {
                argv.push("--json");
            }
            argv
        };
        for json_first in [true, false] {
            let argv = place(json_first);
            let c = Cli::try_parse_from(&argv).expect("subscription place --json parses");
            let Command::Subscription(ref s) = c.command else {
                panic!("expected Command::Subscription");
            };
            assert!(s.json, "--json position must not change the parse");
            assert_eq!(
                c.command.machine_operation(),
                Some(machine::OP_SUBSCRIPTION_PLACE)
            );
        }

        for (argv, operation) in [
            (
                vec![
                    "dexdo", "subscription", "--note-addr", "0:note", "--model", "qwen", "status",
                    "7", "--json",
                ],
                machine::OP_SUBSCRIPTION_STATUS,
            ),
            (
                vec![
                    "dexdo", "subscription", "--json", "--note-addr", "0:note", "--model", "qwen",
                    "cancel", "7",
                ],
                machine::OP_SUBSCRIPTION_CANCEL,
            ),
        ] {
            let c = Cli::try_parse_from(&argv).expect("subscription --json parses");
            assert_eq!(c.command.machine_operation(), Some(operation));
            // The same command line, machine mode off, stays a human command.
            let human = argv
                .iter()
                .copied()
                .filter(|a| *a != "--json")
                .collect::<Vec<_>>();
            let c = Cli::try_parse_from(&human).expect("human form still parses");
            assert_eq!(c.command.machine_operation(), None);
        }
    }

    /// a subscription command line that fails to parse still has to answer in JSON, so the
    /// raw scan must recognise the subcommand before clap ever builds the args.
    #[test]
    fn raw_machine_operation_reads_the_subscription_subcommand_before_clap() {
        fn raw(args: &[&str]) -> Vec<std::ffi::OsString> {
            args.iter().map(std::ffi::OsString::from).collect()
        }
        let cases: [(Vec<&str>, Option<&'static str>); 5] = [
            (
                vec!["dexdo", "subscription", "--json", "place", "--ticks"],
                Some(machine::OP_SUBSCRIPTION_PLACE),
            ),
            (
                vec!["dexdo", "subscription", "status", "--json"],
                Some(machine::OP_SUBSCRIPTION_STATUS),
            ),
            (
                vec!["dexdo", "subscription", "cancel", "--json", "nope"],
                Some(machine::OP_SUBSCRIPTION_CANCEL),
            ),
            // No `--json`: clap's own error stands and nothing is printed on stdout.
            (vec!["dexdo", "subscription", "place"], None),
            // No subcommand to attribute the failure to.
            (vec!["dexdo", "subscription", "--json"], None),
        ];
        for (args, expected) in cases {
            assert_eq!(raw_machine_operation(&raw(&args)), expected, "{args:?}");
        }
    }
}

#[cfg(test)]
mod deal_handle_cli_tests {
    use super::{Cli, Command};
    use crate::cli::args::{ContinuityModeArg, DealRoleArg, ExportFormatArg};
    use clap::Parser;
    use std::path::PathBuf;

    /// durable local deal-handle commands parse without low-level address reassembly for the handle path,
    /// while raw TokenContract close can still be made explicit with role/note.
    #[test]
    fn deal_handle_subcommands_parse() {
        let c =
            Cli::try_parse_from(["dexdo", "deals", "--deals-dir", "deals"]).expect("deals parses");
        let Command::Deals(d) = c.command else {
            panic!("expected Command::Deals");
        };
        assert_eq!(d.deals_dir, Some(PathBuf::from("deals")));

        let c = Cli::try_parse_from(["dexdo", "status", "deal-0-abc"]).expect("status parses");
        let Command::Status(status) = c.command else {
            panic!("expected Command::Status");
        };
        assert_eq!(status.contracts, None);

        let c = Cli::try_parse_from([
            "dexdo",
            "status",
            "deal-0-abc",
            "--contracts",
            "contracts/custom.json",
        ])
        .expect("status --contracts parses");
        let Command::Status(status) = c.command else {
            panic!("expected Command::Status");
        };
        assert_eq!(
            status.contracts,
            Some(PathBuf::from("contracts/custom.json"))
        );

        let c = Cli::try_parse_from([
            "dexdo",
            "close",
            "0:tc",
            "--role",
            "buyer",
            "--note-addr",
            "0:note",
            "--note-key",
            "note.secret",
        ])
        .expect("close raw token contract parses");
        let Command::Close(close) = c.command else {
            panic!("expected Command::Close");
        };
        assert_eq!(close.role, Some(DealRoleArg::Buyer));
        assert_eq!(close.note_addr.as_deref(), Some("0:note"));
        assert_eq!(close.contracts, None);

        let c = Cli::try_parse_from([
            "dexdo",
            "history",
            "--deals-dir",
            "deals",
            "--note",
            "0:note",
            "--model",
            "qwen/qwen3-32b",
        ])
        .expect("history parses");
        let Command::History(history) = c.command else {
            panic!("expected Command::History");
        };
        assert_eq!(history.deals_dir, Some(PathBuf::from("deals")));
        assert_eq!(history.note.as_deref(), Some("0:note"));
        assert_eq!(history.model.as_deref(), Some("qwen/qwen3-32b"));

        let c = Cli::try_parse_from([
            "dexdo",
            "dashboard",
            "--listen",
            "127.0.0.1:0",
            "--deals-dir",
            "deals",
        ])
        .expect("dashboard parses");
        let Command::Dashboard(dashboard) = c.command else {
            panic!("expected Command::Dashboard");
        };
        assert_eq!(dashboard.listen.to_string(), "127.0.0.1:0");
        assert_eq!(dashboard.deals_dir, Some(PathBuf::from("deals")));

        let c = Cli::try_parse_from([
            "dexdo",
            "export",
            "--deal",
            "deal-0-abc",
            "--format",
            "md",
            "--contracts",
            "contracts/custom.json",
        ])
        .expect("export parses");
        let Command::Export(export) = c.command else {
            panic!("expected Command::Export");
        };
        assert_eq!(export.deal, "deal-0-abc");
        assert_eq!(export.format, ExportFormatArg::Md);
        assert_eq!(
            export.contracts,
            Some(PathBuf::from("contracts/custom.json"))
        );
    }

    /// PR212: explicit `buyer --resume` remains a no-new-buy connect path; model-only resume is covered
    /// by the shellnet resume validation tests.
    #[test]
    fn buyer_resume_explicit_deal_parses() {
        let c = Cli::try_parse_from([
            "dexdo",
            "buyer",
            "--resume",
            "--token-contract",
            "0:tc",
            "--frame-model",
            "qwen--qwen3--32b",
        ])
        .expect("buyer --resume parses with an explicit deal");
        let Command::Buyer(buyer) = c.command else {
            panic!("expected Command::Buyer");
        };
        assert!(buyer.resume);
        assert_eq!(buyer.token_contract.as_deref(), Some("0:tc"));
        assert_eq!(buyer.frame_model.as_deref(), Some("qwen--qwen3--32b"));
    }

    #[test]
    fn buyer_model_alias_and_models_config_parse() {
        let c = Cli::try_parse_from([
            "dexdo",
            "buyer",
            "--mock-model",
            "--mock-chain",
            "--token-contract",
            "0:tc",
            "--model",
            "qwen--qwen3--32b",
            "--models",
            "custom-models.json",
        ])
        .expect("buyer accepts --model alias plus --models config path");
        let Command::Buyer(buyer) = c.command else {
            panic!("expected Command::Buyer");
        };
        assert_eq!(buyer.frame_model.as_deref(), Some("qwen--qwen3--32b"));
        assert_eq!(buyer.models, PathBuf::from("custom-models.json"));
    }

    #[test]
    fn buyer_continuity_mode_parses_defaults_and_rejects_unknown_values() {
        let c = Cli::try_parse_from([
            "dexdo",
            "buyer",
            "--resume",
            "--token-contract",
            "0:tc",
            "--frame-model",
            "qwen--qwen3--32b",
        ])
        .expect("buyer default continuity mode parses");
        let Command::Buyer(buyer) = c.command else {
            panic!("expected Command::Buyer");
        };
        assert_eq!(buyer.continuity_mode, ContinuityModeArg::Proactive);

        let c = Cli::try_parse_from([
            "dexdo",
            "buyer",
            "--resume",
            "--token-contract",
            "0:tc",
            "--frame-model",
            "qwen--qwen3--32b",
            "--continuity-mode",
            "on-demand",
        ])
        .expect("buyer on-demand continuity mode parses");
        let Command::Buyer(buyer) = c.command else {
            panic!("expected Command::Buyer");
        };
        assert_eq!(buyer.continuity_mode, ContinuityModeArg::OnDemand);

        let c = Cli::try_parse_from([
            "dexdo",
            "buyer",
            "--resume",
            "--token-contract",
            "0:tc",
            "--frame-model",
            "qwen--qwen3--32b",
            "--continuity-mode",
            "proactive",
        ])
        .expect("buyer proactive continuity mode parses");
        let Command::Buyer(buyer) = c.command else {
            panic!("expected Command::Buyer");
        };
        assert_eq!(buyer.continuity_mode, ContinuityModeArg::Proactive);

        assert!(Cli::try_parse_from([
            "dexdo",
            "buyer",
            "--resume",
            "--token-contract",
            "0:tc",
            "--frame-model",
            "qwen--qwen3--32b",
            "--continuity-mode",
            "automatic",
        ])
        .is_err());
    }

    #[test]
    fn seller_gateway_advertise_defaults_to_listen() {
        let c = Cli::try_parse_from([
            "dexdo",
            "seller",
            "--mock-chain",
            "--mock-model",
            "--token-contract",
            "0:tc",
            "--gateway-listen",
            "0.0.0.0:8443",
        ])
        .expect("seller parses with gateway-listen only");
        let Command::Seller(seller) = c.command else {
            panic!("expected Command::Seller");
        };
        assert_eq!(seller.gateway_listen.to_string(), "0.0.0.0:8443");
        assert_eq!(seller.gateway_advertise_addr(), "0.0.0.0:8443");
        // a `--mock-chain` demo never posts to a real order book, so the local default stays usable.
        assert_eq!(
            seller.checked_gateway_advertise_addr().unwrap(),
            "0.0.0.0:8443"
        );
    }

    fn seller_args(extra: &[&str]) -> crate::SellerArgs {
        let mut argv = vec![
            "dexdo",
            "seller",
            "--note-addr",
            "0:note",
            "--token-contract",
            "0:tc",
            "--model",
            "qwen",
        ];
        argv.extend_from_slice(extra);
        let parsed = Cli::try_parse_from(argv).expect("seller parses");
        let Command::Seller(seller) = parsed.command else {
            panic!("expected Command::Seller");
        };
        seller
    }

    #[test]
    fn seller_rejects_a_non_routable_advertise_on_the_real_path() {
        // the silent advertise:= listen fallback, named as such in the message.
        let error = seller_args(&[])
            .checked_gateway_advertise_addr()
            .expect_err("the listen default must not be advertised to remote buyers");
        let structured = error.downcast_ref::<dexdo_core::DexdoError>().expect(
            "the SellerArgs anyhow boundary must preserve DexdoError for top-level rendering",
        );
        assert_eq!(
            structured.code(),
            dexdo_core::error_codes::E_ADVERTISE_NOT_PUBLIC.code()
        );
        assert_eq!(
            error.to_string(),
            "error[E_ADVERTISE_NOT_PUBLIC] (config): --gateway-advertise defaulted to \
             --gateway-listen 127.0.0.1:8443, which is not reachable by remote buyers (loopback)\n  \
             hint: pass a public host:port reachable from the internet, or run on a public host; \
             for local/LAN testing only, use --allow-private-advertise"
        );
        // The bind-all listen socket reports as the footgun.
        let error = seller_args(&["--gateway-listen", "0.0.0.0:8443"])
            .checked_gateway_advertise_addr()
            .expect_err("a bind-all wildcard is not a connect target");
        assert_eq!(
            error.to_string(),
            "error[E_ADVERTISE_NOT_PUBLIC] (config): --gateway-advertise defaulted to \
             --gateway-listen 0.0.0.0:8443, which is not reachable by remote buyers \
             (bind-all wildcard)\n  \
             hint: pass a public host:port reachable from the internet, or run on a public host; \
             for local/LAN testing only, use --allow-private-advertise"
        );

        for advertise in [
            "127.0.0.1:8443",
            "192.168.1.10:8443",
            "10.0.0.5:8443",
            "169.254.1.1:8443",
            "100.64.0.1:8443",
            "localhost:8443",
            "[::1]:8443",
        ] {
            let error = seller_args(&["--gateway-advertise", advertise])
                .checked_gateway_advertise_addr()
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("error[E_ADVERTISE_NOT_PUBLIC] (config)")
                    && error.contains(advertise)
                    && error.contains("--allow-private-advertise"),
                "{advertise}: {error}"
            );
        }
    }

    #[test]
    fn seller_accepts_a_public_advertise_or_the_explicit_private_opt_in() {
        assert_eq!(
            seller_args(&["--gateway-advertise", "seller.example.net:443"])
                .checked_gateway_advertise_addr()
                .unwrap(),
            "seller.example.net:443"
        );
        assert_eq!(
            seller_args(&["--gateway-advertise", "94.156.178.14:8443"])
                .checked_gateway_advertise_addr()
                .unwrap(),
            "94.156.178.14:8443"
        );
        assert_eq!(
            seller_args(&[
                "--allow-private-advertise",
                "--gateway-listen",
                "127.0.0.1:8443"
            ])
            .checked_gateway_advertise_addr()
            .unwrap(),
            "127.0.0.1:8443"
        );
    }

    #[test]
    fn seller_advertise_probe_policy_follows_the_flag() {
        use dexdo::seller::liveness::AdvertiseProbePolicy;
        assert_eq!(
            seller_args(&[]).advertise_probe_policy(),
            AdvertiseProbePolicy::TolerateTunneledTransportFailure
        );
        assert_eq!(
            seller_args(&["--require-advertise-probe"]).advertise_probe_policy(),
            AdvertiseProbePolicy::Required
        );
    }

    #[test]
    fn seller_subscription_mode_is_explicit_and_off_by_default() {
        let ordinary = Cli::try_parse_from(["dexdo", "seller"]).expect("ordinary seller parses");
        let Command::Seller(ordinary) = ordinary.command else {
            panic!("expected Command::Seller");
        };
        assert!(
            !ordinary.subscription,
            "ordinary seller must not set the subscription flag"
        );

        let subscription = Cli::try_parse_from(["dexdo", "seller", "--subscription"])
            .expect("subscription seller parses");
        let Command::Seller(subscription) = subscription.command else {
            panic!("expected Command::Seller");
        };
        assert!(subscription.subscription);
    }

    #[test]
    fn seller_gateway_advertise_accepts_public_host_port() {
        let c = Cli::try_parse_from([
            "dexdo",
            "seller",
            "--mock-chain",
            "--mock-model",
            "--token-contract",
            "0:tc",
            "--gateway-listen",
            "127.0.0.1:8443",
            "--gateway-advertise",
            "seller.example.net:443",
        ])
        .expect("seller parses public advertise host:port");
        let Command::Seller(seller) = c.command else {
            panic!("expected Command::Seller");
        };
        assert_eq!(seller.gateway_listen.to_string(), "127.0.0.1:8443");
        assert_eq!(seller.gateway_advertise_addr(), "seller.example.net:443");
    }

    #[test]
    fn seller_gateway_advertise_rejects_malformed_host_port() {
        assert!(Cli::try_parse_from([
            "dexdo",
            "seller",
            "--mock-chain",
            "--mock-model",
            "--token-contract",
            "0:tc",
            "--gateway-advertise",
            "seller.example.net",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "dexdo",
            "seller",
            "--mock-chain",
            "--mock-model",
            "--token-contract",
            "0:tc",
            "--gateway-advertise",
            "seller.example.net:notaport",
        ])
        .is_err());
    }
}

#[cfg(test)]
mod oracle_cli_tests {
    use super::{Cli, Command};
    use crate::cli::args::{OracleCommand, OracleProvisionArgs};
    use clap::Parser;
    use std::path::PathBuf;

    /// oracle/PMP lifecycle commands parse as a single shellnet surface.
    #[test]
    fn oracle_subcommands_parse() {
        let c = Cli::try_parse_from([
            "dexdo",
            "oracle",
            "provision",
            "--note-key",
            "note.key",
            "--note-addr",
            "0:note",
            "--oracle-key",
            "oracle.key",
            "--oracle-name",
            "weekly-qwen",
            "--market",
            "market.json",
            "--event-name",
            "qwen-weekly-price",
            "--deadline",
            "1900000000",
            "--bound",
            "100",
            "--bound",
            "200",
            "--outcome",
            "below",
            "--outcome",
            "middle",
            "--outcome",
            "above",
            "--initial-stake",
            "10000000",
            "--initial-stake",
            "10000000",
            "--initial-stake",
            "10000000",
            "--output",
            "oracle-market.json",
        ])
        .expect("oracle provision parses");
        let Command::Oracle(args) = c.command else {
            panic!("expected oracle command");
        };
        let OracleCommand::Provision(p) = args.command else {
            panic!("expected oracle provision");
        };
        let OracleProvisionArgs {
            oracle_name,
            bounds,
            outcome_names,
            initial_stakes,
            token_type,
            output,
            ..
        } = *p;
        assert_eq!(oracle_name, "weekly-qwen");
        assert_eq!(bounds, ["100", "200"]);
        assert_eq!(outcome_names, ["below", "middle", "above"]);
        assert_eq!(initial_stakes, [10_000_000, 10_000_000, 10_000_000]);
        assert_eq!(token_type, dexdo_core::params::SHELL_CURRENCY_ID);
        assert_eq!(output, PathBuf::from("oracle-market.json"));

        let c = Cli::try_parse_from(["dexdo", "oracle", "state", "--manifest", "oracle.json"])
            .expect("oracle state parses");
        assert!(matches!(
            c.command,
            Command::Oracle(crate::cli::args::OracleArgs {
                command: OracleCommand::State(_)
            })
        ));

        let c = Cli::try_parse_from([
            "dexdo",
            "oracle",
            "resolve",
            "--manifest",
            "oracle.json",
            "--oracle-key",
            "oracle.key",
        ])
        .expect("oracle resolve parses");
        assert!(matches!(
            c.command,
            Command::Oracle(crate::cli::args::OracleArgs {
                command: OracleCommand::Resolve(_)
            })
        ));

        for subcommand in ["cancel", "delete"] {
            let c = Cli::try_parse_from([
                "dexdo",
                "oracle",
                subcommand,
                "--manifest",
                "oracle.json",
                "--oracle-key",
                "oracle.key",
            ])
            .unwrap_or_else(|error| panic!("oracle {subcommand} parses: {error}"));
            assert!(matches!(
                c.command,
                Command::Oracle(crate::cli::args::OracleArgs {
                    command: OracleCommand::Cancel(_) | OracleCommand::Delete(_)
                })
            ));
        }
    }
}

#[cfg(test)]
mod deposit_tests {
    use crate::cli::support::{
        default_deposit_shells, deposit_per_deploy, ensure_provision_deposit_covered,
        min_deploy_shells, SHELL_UNIT,
    };

    /// The deal these deposit cases are written against: the worked example in, eight ticks at
    /// one SHELL each, so eight SHELL of service in total against a flat ten-SHELL floor.
    const ISSUE999_TICKS: u128 = 8;

    #[test]
    fn shellnet_deposit_validation_message_is_byte_identical() {
        let legacy = deposit_per_deploy(0, 53)
            .expect_err("zero is below the deal floor")
            .to_string();
        let network_aware = crate::cli::support::deposit_per_deploy_with_overhead(0, 53, None)
            .expect_err("zero is below the same deal floor")
            .to_string();
        let requirement = dexdo_core::params::deal_gas_requirement_raw(53);
        let floor = dexdo_core::params::min_deploy_shells(53);
        let before_1236 = format!(
            "--deposit-shells 0 -> ~0 SHELL/deploy is below the {floor} SHELL/deploy floor \
             for a 53-tick deal (that deal's TokenContract spends {requirement} raw nanovmshell over its life: the \
             values it declares on its own outgoing calls, plus one claim per tick, because MAX_CLAIM_DELTA = \
             TICK_SIZE caps a claim at one tick and claimTokens accepts before its body so the DEAL pays -- \
             contract-declared values and the published 4.0.34 measurement, not bisected). Below it the deal \
             under-funds, and it cannot refill itself: deployed by an external message into a dapp with no config, \
             gosh.mintshellq has nothing to draw on, so the stop is permanent with the bond inside. \
             Raise --deposit-shells to >={floor} (default for this deal: {floor}).",
        );
        assert_eq!(legacy.as_bytes(), before_1236.as_bytes());
        assert_eq!(network_aware.as_bytes(), before_1236.as_bytes());
    }

    #[test]
    fn below_shellnet_operator_measurement_is_not_clamped_by_deposit_validation() {
        let measurement = dexdo_core::params::DEAL_GAS_OVERHEAD_RAW;
        let supplied = measurement.value / 2;
        assert!(
            deposit_per_deploy(1, 53).is_err(),
            "the existing shellnet measurement needs two whole SHELL at this boundary"
        );
        assert_eq!(
            crate::cli::support::deposit_per_deploy_with_overhead(1, 53, Some(supplied))
                .expect("the supplied measurement puts this boundary below one whole SHELL"),
            dexdo_core::params::SHELL_UNIT
        );
    }

    /// ONE NOTE-FUNDED DEPLOY SINCE 4.0.34, so the whole deposit is that deploy's allocation.
    /// This asserted `deposit/2` while the note pre-funded the `RootModel`'s uninit address as well as
    /// the deal's. `SuperRoot` deploys the RootModel now and carries its own value
    /// (`contracts/airegistry/SuperRoot.sol:58`), and `PrivateNote.fundDeployShell` has no leg pointed
    /// at it any more(`contracts/dex/PrivateNote.sol:1143`) -- so the halved reservation was ECC[2] no
    /// message could spend, and it burns at `destroy`.
    /// The default is still exactly one deploy at the floor; what moved is that the floor is now this
    /// deal's own requirement rather than one figure for every deal.
    #[test]
    fn default_deposit_clears_the_floor() {
        let default_shells = default_deposit_shells(ISSUE999_TICKS);
        let pd = deposit_per_deploy(default_shells, ISSUE999_TICKS)
            .expect("default deposit must be valid");
        assert_eq!(pd, default_shells * SHELL_UNIT);
        assert!(pd >= min_deploy_shells(ISSUE999_TICKS) * SHELL_UNIT);
        assert_eq!(
            default_shells,
            min_deploy_shells(ISSUE999_TICKS),
            "the default is exactly one deploy at the floor -- the RootModel half is not reserved"
        );
    }

    /// as the CLI sees it: the SAME deposit is accepted for one deal and refused for a longer
    /// one, because the floor is the deal's. A guard that answers the same for both is the flat
    /// constant again, whatever it is called.
    #[test]
    fn the_deposit_floor_is_this_deal_s_and_not_one_figure_for_every_deal() {
        let short_floor = min_deploy_shells(ISSUE999_TICKS);
        let long_floor = min_deploy_shells(1_000);
        assert!(
            short_floor < long_floor,
            "an {ISSUE999_TICKS}-tick deal floors at {short_floor} SHELL and a 1000-tick deal at \
             {long_floor}; a floor that does not follow the deal prices the cheap end out and \
             under-funds the expensive end"
        );
        assert!(
            deposit_per_deploy(short_floor, ISSUE999_TICKS).is_ok(),
            "the short deal's own floor must be accepted for the short deal"
        );
        let refused = deposit_per_deploy(short_floor, 1_000)
            .expect_err("the short deal's floor cannot fund a thousand-tick deal");
        let msg = refused.to_string();
        assert!(msg.contains("1000-tick deal"), "{msg}");
        assert!(
            msg.contains("MAX_CLAIM_DELTA = TICK_SIZE"),
            "the refusal must say WHY the requirement grows -- one claim per tick, capped by the \
             contract: {msg}"
        );
    }

    #[test]
    fn below_floor_deposit_is_rejected_fail_closed() {
        // A deposit below the deal's derived floor must error, not silently proceed into an
        // under-funded deploy. Asserted relative to the floor so it survives a re-sizing.
        let floor = min_deploy_shells(ISSUE999_TICKS);
        assert!(
            deposit_per_deploy(floor - 1, ISSUE999_TICKS).is_err(),
            "one SHELL below the floor -- must be rejected"
        );
        assert!(
            deposit_per_deploy(0, ISSUE999_TICKS).is_err(),
            "an empty deposit funds nothing -- must be rejected"
        );
        // Exactly at the floor is the minimum accepted.
        assert!(deposit_per_deploy(floor, ISSUE999_TICKS).is_ok());
    }

    #[test]
    fn overflow_deposit_errors_not_silently_clamps() {
        assert!(
            deposit_per_deploy(u128::MAX, ISSUE999_TICKS).is_err(),
            "overflow must error, not saturate"
        );
    }

    #[test]
    fn provision_deposit_guard_checks_exact_deploy_amount_without_magic_reserve() {
        let default_shells = default_deposit_shells(ISSUE999_TICKS);
        let need = default_shells * SHELL_UNIT;
        assert!(
            ensure_provision_deposit_covered(need, 0, default_shells, 0).is_ok(),
            "zero-price deals have no seller bond"
        );
        assert!(ensure_provision_deposit_covered(need - 1, u128::MAX, default_shells, 0).is_err());
        assert!(ensure_provision_deposit_covered(need + 1, 0, default_shells, 0,).is_ok());
    }

    #[test]
    fn provision_deposit_guard_reserves_contract_seller_bond() {
        let default_shells = default_deposit_shells(ISSUE999_TICKS);
        let deploy_need = default_shells * SHELL_UNIT;
        let price_per_tick = 1000;
        let seller_bond = 2 * price_per_tick; // the mirror bond is 2P
        let err = ensure_provision_deposit_covered(
            deploy_need,
            seller_bond - 1,
            default_shells,
            price_per_tick,
        )
        .expect_err("deploy gas cannot substitute for the seller bond");
        let msg = err.to_string();
        assert!(msg.contains("seller bond"), "{msg}");
        assert!(msg.contains("price_per_tick=1000"), "{msg}");
        assert!(ensure_provision_deposit_covered(
            deploy_need,
            seller_bond,
            default_shells,
            price_per_tick,
        )
        .is_ok());
    }

    #[test]
    fn provision_script_serializes_every_full_live_suite_command() {
        let sources = [
            (
                "provision-shellnet-actor.sh",
                include_str!("../../../provision-shellnet-actor.sh"),
            ),
            ("README.md", include_str!("../../../README.md")),
            ("live_cli.rs", include_str!("../tests/live_cli.rs")),
        ];
        let commands: Vec<_> = sources
            .iter()
            .flat_map(|(source, text)| {
                text.lines().filter_map(move |line| {
                    let is_full_ignored_suite = line.contains("cargo test")
                        && line.contains("-- --ignored")
                        && (line.contains("--test live_cli") || line.contains("-p dexdo-core"));
                    is_full_ignored_suite.then_some((*source, line))
                })
            })
            .collect();
        assert!(
            !commands.is_empty(),
            "full live-suite command must remain documented"
        );
        for (source, command) in commands {
            assert!(
                command.contains("--test-threads=1"),
                "unserialized full ignored shellnet-suite command in {source}: {command}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::support::{
        check_market_model_match, consumer_api_token_budget, default_endpoints_path,
        resolve_endpoints_file, resolve_market_fields,
    };
    use clap::{CommandFactory, Parser, ValueEnum};

    fn subcommand_long_help(name: &str) -> String {
        let mut command = Cli::command();
        command
            .find_subcommand_mut(name)
            .expect("subcommand exists")
            .render_long_help()
            .to_string()
    }

    fn nested_subcommand_long_help(path: &[&str]) -> String {
        let mut command = Cli::command();
        let mut current = &mut command;
        for name in path {
            current = current
                .find_subcommand_mut(name)
                .expect("nested subcommand exists");
        }
        current.render_long_help().to_string()
    }

    #[test]
    fn deal_gas_overhead_override_is_one_flag_for_every_deal_funding_command() {
        let measured_raw = dexdo_core::params::DEAL_GAS_OVERHEAD_RAW.value.to_string();
        for (command, model_flag) in [("provision", "--frame-model"), ("seller", "--model")] {
            let cli = Cli::try_parse_from([
                "dexdo",
                command,
                "--deal-gas-overhead-raw",
                measured_raw.as_str(),
                model_flag,
                "qwen--qwen3--32b",
            ])
            .expect("deal-funding command accepts the measured raw overhead");
            assert_eq!(
                cli.deal_gas_overhead_raw,
                Some(dexdo_core::params::DEAL_GAS_OVERHEAD_RAW.value)
            );
            assert!(matches!(
                cli.command,
                Command::Provision(_) | Command::Seller(_)
            ));
        }
    }

    /// a pool run of `reclaim` can move money for more than one deal in a single invocation,
    /// so the user-facing contract has to say so where an operator actually reads it.
    #[test]
    fn reclaim_help_states_that_a_pool_run_drives_every_recorded_entry() {
        let help = subcommand_long_help("reclaim");
        for fact in [
            "EVERY recorded",
            "one per still-reclaimable recorded deal",
            "refuses contradictory records",
        ] {
            assert!(
                help.contains(fact),
                "missing {fact:?} in reclaim help:\n{help}"
            );
        }
        assert!(
            help.contains("drives EVERY recorded recovery entry as its own reclaim"),
            "--pool must document the fan-out where the flag is described:\n{help}"
        );
        assert!(
            !help.contains("last matched TokenContract"),
            "the singular pool contract must not survive the  fan-out:\n{help}"
        );
    }

    /// Every `method(arg,...)` shape the given help renders for `method`, normalized to the argument
    /// NAMES(`uint128 amount` -> `amount`), so a rendered signature can be held against the compiled
    /// ABI's declared input list.
    fn rendered_call_arguments(help: &str, method: &str) -> Vec<Vec<String>> {
        let needle = format!("{method}(");
        let mut calls = Vec::new();
        let mut rest = help;
        while let Some(at) = rest.find(&needle) {
            let after = &rest[at + needle.len()..];
            let Some(end) = after.find(')') else { break };
            calls.push(
                after[..end]
                    .split(',')
                    .filter_map(|argument| {
                        argument.split_whitespace().last().map(|name| {
                            name.trim_matches(|c: char| !c.is_alphanumeric() && c != '_')
                                .to_string()
                        })
                    })
                    .filter(|name| !name.is_empty())
                    .collect(),
            );
            rest = &after[end..];
        }
        calls
    }

    /// `--help` is where an operator learns a contract call's shape, so a signature the CLI
    /// renders must be the deployed one. 4.0.33(Task O) took the caller-named payee off the
    /// TokenContract's terminal doors -- `destroy(payoutAddress)` -> `destroy()`,
    /// `withdrawShell(amount, recipient)` -> `withdrawShell(amount)`, `close(payoutAddress)` ->
    /// `close()` -- while the help went on promising the old shapes. A function id derives from the
    /// whole signature, so that promise pointed the operator at methods this generation does not
    /// have. Parse every terminal signature the CLI renders and hold it against the compiled ABI.
    #[test]
    fn rendered_token_contract_signatures_match_the_compiled_abi() {
        let abi: serde_json::Value = serde_json::from_str(include_str!(
            "../../../contracts/compiled/airegistry/TokenContract.abi.json"
        ))
        .expect("compiled TokenContract ABI parses");
        let declared_inputs = |method: &str| -> Vec<String> {
            abi["functions"]
                .as_array()
                .expect("compiled ABI declares functions")
                .iter()
                .find(|function| function["name"] == method)
                .unwrap_or_else(|| panic!("compiled ABI declares {method}"))["inputs"]
                .as_array()
                .expect("declared inputs")
                .iter()
                .map(|input| {
                    input["name"]
                        .as_str()
                        .expect("declared input name")
                        .to_string()
                })
                .collect()
        };

        let mut command = Cli::command();
        let names: Vec<String> = command
            .get_subcommands()
            .map(|sub| sub.get_name().to_string())
            .collect();
        let mut helps = vec![command.render_long_help().to_string()];
        helps.extend(names.iter().map(|name| subcommand_long_help(name)));

        for method in ["destroy", "withdrawShell", "close"] {
            let declared = declared_inputs(method);
            for help in &helps {
                for rendered in rendered_call_arguments(help, method) {
                    assert_eq!(
                        rendered,
                        declared,
                        "the CLI renders TokenContract.{method}({}) but the compiled 4.0.33 ABI \
                         declares ({}); help must describe the deployed signature:\n{help}",
                        rendered.join(", "),
                        declared.join(", ")
                    );
                }
            }
        }
    }

    /// The pool-recovery commands act on a deal already recorded on chain and in the pool: there is no
    /// sub-note to derive, so `--note-index` is not part of their surface and must be rejected rather
    /// than accepted and ignored.
    #[test]
    fn pool_recovery_commands_reject_note_index_but_keep_their_identity_flags() {
        for command in ["reclaim", "recover", "dispute"] {
            let error = match Cli::try_parse_from(["dexdo", command, "--note-index", "3"]) {
                Ok(_) => panic!("{command} must not accept --note-index"),
                Err(error) => error,
            };
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::UnknownArgument,
                "{command}: {error}"
            );
            assert!(Cli::try_parse_from(["dexdo", command, "--note-addr", "0:b"]).is_ok());
            assert!(Cli::try_parse_from(["dexdo", command, "--note-key", "k.hex"]).is_ok());
        }
    }

    #[test]
    fn root_version_flag_is_available_for_release_smoke() {
        let err = Cli::command()
            .try_get_matches_from(["dexdo", "--version"])
            .expect_err("--version should render the package version");
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(err.to_string().contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn cli_defaults_parse_from_canonical_params() {
        use dexdo_core::params as p;
        use std::path::Path;

        let seller = Cli::try_parse_from(["dexdo", "seller"]).expect("seller defaults parse");
        let Command::Seller(seller) = seller.command else {
            panic!("seller command")
        };
        assert_eq!(seller.identity.note_index, p::DEFAULT_NOTE_INDEX);
        assert_eq!(
            seller.gateway_listen.to_string(),
            p::DEFAULT_SELLER_GATEWAY_LISTEN
        );
        assert_eq!(seller.mock_token_count, p::DEFAULT_SELLER_MOCK_TOKEN_COUNT);
        assert_eq!(seller.models, Path::new(p::DEFAULT_MODELS_PATH));
        assert_eq!(seller.contracts, Path::new(p::DEFAULT_CONTRACTS_PATH));

        let buyer = Cli::try_parse_from(["dexdo", "buyer"]).expect("buyer defaults parse");
        let Command::Buyer(buyer) = buyer.command else {
            panic!("buyer command")
        };
        assert_eq!(buyer.max_tokens, p::DEFAULT_BUYER_MAX_TOKENS);
        assert_eq!(buyer.continuity_mode.as_str(), p::DEFAULT_CONTINUITY_MODE);
        assert_eq!(buyer.ticks, p::DEFAULT_BUYER_TICKS);
        assert!(!buyer.wait_for_seller);
        assert_eq!(buyer.models, Path::new(p::DEFAULT_MODELS_PATH));
        assert_eq!(buyer.contracts, Path::new(p::DEFAULT_CONTRACTS_PATH));

        let monitor = Cli::try_parse_from(["dexdo", "monitor"]).expect("monitor defaults parse");
        let Command::Monitor(monitor) = monitor.command else {
            panic!("monitor command")
        };
        assert_eq!(monitor.tree_width, p::DEFAULT_MONITOR_TREE_WIDTH);
        assert_eq!(monitor.contracts, Path::new(p::DEFAULT_CONTRACTS_PATH));

        let doctor = Cli::try_parse_from(["dexdo", "doctor"]).expect("doctor defaults parse");
        let Command::Doctor(doctor) = doctor.command else {
            panic!("doctor command")
        };
        assert_eq!(doctor.network, p::DEFAULT_DOCTOR_NETWORK);
        assert_eq!(doctor.contracts, Path::new(p::DEFAULT_CONTRACTS_PATH));

        let policy =
            Cli::try_parse_from(["dexdo", "policy", "init"]).expect("policy defaults parse");
        let Command::Policy(policy) = policy.command else {
            panic!("policy command")
        };
        let PolicyCommand::Init(policy) = policy.command else {
            panic!("policy init")
        };
        assert_eq!(
            policy.role.to_possible_value().unwrap().get_name(),
            p::DEFAULT_POLICY_ROLE
        );

        let provision =
            Cli::try_parse_from(["dexdo", "provision", "--frame-model", "qwen--qwen3--32b"])
                .expect("provision defaults parse");
        let Command::Provision(provision) = provision.command else {
            panic!("provision command")
        };
        assert_eq!(provision.max_ticks, p::DEFAULT_PROVISION_MAX_TICKS);
        assert_eq!(
            provision.output,
            Path::new(p::DEFAULT_MARKET_MANIFEST_OUTPUT_PATH)
        );

        let markets = Cli::try_parse_from(["dexdo", "markets"]).expect("markets defaults parse");
        let Command::Markets(markets) = markets.command else {
            panic!("markets command")
        };
        assert_eq!(markets.frame_model, p::DEFAULT_MARKETS_FRAME_MODEL);
        assert_eq!(markets.models, Path::new(p::DEFAULT_MODELS_PATH));
        assert_eq!(
            markets.read_timeout.read_timeout_secs,
            p::DEFAULT_CHAIN_READ_TIMEOUT_SECS
        );

        let executable = Cli::try_parse_from(["dexdo", "executable-book", "qwen--qwen3--32b"])
            .expect("executable-book defaults parse");
        let Command::ExecutableBook(executable) = executable.command else {
            panic!("executable-book command")
        };
        assert_eq!(executable.ticks, p::DEFAULT_EXECUTABLE_BOOK_TICKS);
        assert_eq!(executable.models, Path::new(p::DEFAULT_MODELS_PATH));

        let market_data =
            Cli::try_parse_from(["dexdo", "market-data", "list"]).expect("market-data defaults");
        let Command::MarketData(market_data) = market_data.command else {
            panic!("market-data command")
        };
        assert_eq!(
            market_data.output.to_possible_value().unwrap().get_name(),
            p::DEFAULT_MARKET_DATA_OUTPUT
        );
        assert_eq!(market_data.timeout_ms, p::DEFAULT_MARKET_DATA_TIMEOUT_MS);

        let dashboard =
            Cli::try_parse_from(["dexdo", "dashboard"]).expect("dashboard defaults parse");
        let Command::Dashboard(dashboard) = dashboard.command else {
            panic!("dashboard command")
        };
        assert_eq!(dashboard.listen.to_string(), p::DEFAULT_DASHBOARD_LISTEN);

        let export = Cli::try_parse_from(["dexdo", "export", "--deal", "deal-1"])
            .expect("export defaults parse");
        let Command::Export(export) = export.command else {
            panic!("export command")
        };
        assert_eq!(
            export.format.to_possible_value().unwrap().get_name(),
            p::DEFAULT_EXPORT_FORMAT
        );

        let note = Cli::try_parse_from([
            "dexdo",
            "note",
            "deploy",
            "--multisig-address",
            "0:wallet",
            "--multisig-key",
            "wallet.key",
            "--nominal",
            "N10000",
            "--pool",
            "pn_pool.json",
        ])
        .expect("note deploy defaults parse");
        let Command::Note(note) = note.command else {
            panic!("note command")
        };
        let NoteCommand::Deploy(note) = note.command else {
            panic!("note deploy")
        };
        assert_eq!(note.endpoint, p::DEFAULT_NOTE_DEPLOY_ENDPOINT);
        assert_eq!(note.contracts, Path::new(p::DEFAULT_CONTRACTS_PATH));

        let oracle = Cli::try_parse_from([
            "dexdo",
            "oracle",
            "provision",
            "--oracle-key",
            "oracle.key",
            "--oracle-name",
            "weekly-qwen",
            "--market",
            "market.json",
            "--event-name",
            "weekly-price",
            "--deadline",
            "1900000000",
        ])
        .expect("oracle defaults parse");
        let Command::Oracle(oracle) = oracle.command else {
            panic!("oracle command")
        };
        let OracleCommand::Provision(oracle) = oracle.command else {
            panic!("oracle provision")
        };
        assert_eq!(oracle.event_list_index, p::DEFAULT_ORACLE_EVENT_LIST_INDEX);
        assert_eq!(
            oracle.event_list_description,
            p::DEFAULT_ORACLE_EVENT_LIST_DESCRIPTION
        );
        assert_eq!(oracle.describe, p::DEFAULT_ORACLE_PMP_DESCRIPTION);
        assert_eq!(oracle.oracle_fee, p::DEFAULT_ORACLE_FEE);
        assert_eq!(
            oracle.output,
            Path::new(p::DEFAULT_ORACLE_MARKET_OUTPUT_PATH)
        );
    }

    #[test]
    fn buyer_wait_for_seller_is_explicit() {
        let parsed = Cli::try_parse_from([
            "dexdo",
            "buyer",
            "--wait-for-seller",
            "--frame-model",
            "qwen--qwen3--32b",
        ])
        .expect("buyer --wait-for-seller parses");
        let Command::Buyer(buyer) = parsed.command else {
            panic!("buyer command")
        };
        assert!(buyer.wait_for_seller);
    }

    #[test]
    fn active_limit_price_defaults_use_the_canonical_price_step() {
        let seller = Cli::try_parse_from(["dexdo", "seller"]).expect("seller defaults parse");
        let Command::Seller(seller) = seller.command else {
            panic!("seller command")
        };
        assert_eq!(
            seller.price_per_tick as u128,
            dexdo_core::PRICE_STEP,
            "seller default must be one exact PRICE_STEP"
        );

        let buyer = Cli::try_parse_from(["dexdo", "buyer"]).expect("buyer defaults parse");
        let Command::Buyer(buyer) = buyer.command else {
            panic!("buyer command")
        };
        assert_eq!(buyer.max_price_per_tick, dexdo_core::PRICE_STEP);

        let provision =
            Cli::try_parse_from(["dexdo", "provision", "--frame-model", "qwen--qwen3--32b"])
                .expect("provision defaults parse");
        let Command::Provision(provision) = provision.command else {
            panic!("provision command")
        };
        assert_eq!(provision.price_per_tick, dexdo_core::PRICE_STEP);

        let book = Cli::try_parse_from(["dexdo", "executable-book", "qwen--qwen3--32b"])
            .expect("executable-book defaults parse");
        let Command::ExecutableBook(book) = book.command else {
            panic!("executable-book command")
        };
        assert_eq!(book.max_price_per_tick, dexdo_core::PRICE_STEP);
    }

    #[test]
    fn subscription_surface_is_only_place_status_cancel() {
        let price = dexdo_core::PRICE_STEP.to_string();
        let placed = Cli::try_parse_from([
            "dexdo",
            "subscription",
            "--note-addr",
            "0:1111111111111111111111111111111111111111111111111111111111111111",
            "--model",
            "qwen--qwen3--32b",
            "place",
            "--note-key",
            "buyer.key",
            "--max-price-per-tick",
            &price,
            "--ticks",
            "4",
        ])
        .expect("subscription place parses");
        let Command::Subscription(args) = placed.command else {
            panic!("subscription command")
        };
        let SubscriptionCommand::Place(place) = args.command else {
            panic!("subscription place")
        };
        assert_eq!(place.max_price_per_tick, dexdo_core::PRICE_STEP);
        assert_eq!(place.ticks, u128::from(dexdo_core::SUBSCRIPTION_WEEKS));

        for command in ["status", "cancel"] {
            assert!(
                Cli::try_parse_from([
                    "dexdo",
                    "subscription",
                    "--note-addr",
                    "0:1111111111111111111111111111111111111111111111111111111111111111",
                    "--model",
                    "qwen--qwen3--32b",
                    command,
                    "7",
                ])
                .is_ok(),
                "{command} must parse"
            );
        }
        for obsolete in ["poke", "auto-renew", "advance-tick", "place-dedicated"] {
            assert!(
                Cli::try_parse_from(["dexdo", "subscription", obsolete]).is_err(),
                "legacy subscription surface {obsolete} must stay absent"
            );
        }
    }

    #[tokio::test]
    async fn subscription_mock_cli_roundtrip_uses_persisted_note_and_chain_state() {
        let dir = std::env::temp_dir().join(format!(
            "dexdo-subscription-cli-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let endpoints = dir.join("endpoints.json");
        let note_key = dir.join("buyer.key");
        std::fs::write(&note_key, "11".repeat(32)).unwrap();
        let endpoints_arg = endpoints.to_str().unwrap();
        let note_key_arg = note_key.to_str().unwrap();
        let price = dexdo_core::PRICE_STEP.to_string();

        let place = Cli::try_parse_from([
            "dexdo",
            "subscription",
            "--mock-model",
            "--mock-chain",
            "--endpoints-file",
            endpoints_arg,
            "--model",
            "qwen--qwen3--32b",
            "place",
            "--note-key",
            note_key_arg,
            "--max-price-per-tick",
            &price,
            "--ticks",
            "4",
        ])
        .unwrap();
        let Command::Subscription(place) = place.command else {
            panic!("subscription place")
        };
        run_subscription(place).await.unwrap();

        for command in ["status", "cancel"] {
            let parsed = Cli::try_parse_from([
                "dexdo",
                "subscription",
                "--mock-model",
                "--mock-chain",
                "--note-key",
                note_key_arg,
                "--endpoints-file",
                endpoints_arg,
                "--model",
                "qwen--qwen3--32b",
                command,
                "1",
            ])
            .unwrap();
            let Command::Subscription(args) = parsed.command else {
                panic!("subscription {command}")
            };
            run_subscription(args).await.unwrap();
        }

        let status_after_cancel = Cli::try_parse_from([
            "dexdo",
            "subscription",
            "--mock-model",
            "--mock-chain",
            "--note-key",
            note_key_arg,
            "--endpoints-file",
            endpoints_arg,
            "--model",
            "qwen--qwen3--32b",
            "status",
            "1",
        ])
        .unwrap();
        let Command::Subscription(status_after_cancel) = status_after_cancel.command else {
            panic!("subscription status")
        };
        // CHANGED CONTRACT: this leg used to require an ERROR here. Its name states the
        // claim that matters -- the order must no longer be RESTING -- and that claim is now checked
        // against the book itself rather than through a refusal to answer. Reading a terminal is
        // how an orchestrator reconciles against it, so the read succeeds; what it must not do is
        // still show the order in the book.
        run_subscription(status_after_cancel)
            .await
            .expect("a cancelled mock subscription stays readable");
        let chain_state = std::fs::read(dir.join("endpoints.chainstate.json"))
            .expect("mock chain state was written by the roundtrip");
        let chain_state: serde_json::Value =
            serde_json::from_slice(&chain_state).expect("mock chain state is JSON");
        assert_eq!(chain_state["subscription_orders"]["1"], serde_json::Value::Null);
        assert_eq!(
            chain_state["subscription_terminal_orders"]["1"]["reason"],
            "cancelled"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn seller_help_has_no_obsolete_probe_shell_surface() {
        let help = subcommand_long_help("seller");
        assert!(!help.contains("--probe-shell"), "{help}");
        assert!(help.contains("[default: 1000000000]"), "{help}");
        assert!(help.contains("positive multiple of PRICE_STEP"), "{help}");
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    async fn money_command_paths_reject_bad_price_before_backend_or_file_work() {
        let invalid = (dexdo_core::PRICE_STEP - 1).to_string();

        let seller = Cli::try_parse_from(["dexdo", "seller", "--price-per-tick", invalid.as_str()])
            .expect("seller parses");
        let Command::Seller(seller) = seller.command else {
            panic!("seller command")
        };
        let error = run_seller(seller)
            .await
            .expect_err("seller must reject before resolving a market")
            .to_string();
        assert!(error.contains("PRICE_STEP"), "{error}");
        assert!(!error.contains("--token-contract"), "{error}");

        let buyer =
            Cli::try_parse_from(["dexdo", "buyer", "--max-price-per-tick", invalid.as_str()])
                .expect("buyer parses");
        let Command::Buyer(buyer) = buyer.command else {
            panic!("buyer command")
        };
        let error = run_buyer(buyer)
            .await
            .expect_err("buyer must reject before model/book setup")
            .to_string();
        assert!(error.contains("PRICE_STEP"), "{error}");
        assert!(!error.contains("--frame-model"), "{error}");

        let zero_limit = Cli::try_parse_from(["dexdo", "buyer", "--max-price-per-tick", "0"])
            .expect("zero limit parses before semantic validation");
        let Command::Buyer(zero_limit) = zero_limit.command else {
            panic!("buyer command")
        };
        let error = run_buyer(zero_limit)
            .await
            .expect_err("this CLI path is a limit BUY and must reject zero")
            .to_string();
        assert!(error.contains("PRICE_STEP"), "{error}");
    }

    #[test]
    fn explicit_endpoints_file_used_and_parent_created() {
        // D6: an explicit path is used as is, and a missing parent directory is created
        // (otherwise the mock write of `endpoints`/`*.chainstate.json` would fail on a fresh machine).
        let base = tempfile::tempdir().expect("endpoints test dir");
        let nested = base.path().join("sub").join("eps.json");
        let got = resolve_endpoints_file(Some(nested.clone())).expect("resolve explicit");
        assert_eq!(got, nested, "explicit path is not rewritten");
        assert!(
            nested.parent().unwrap().is_dir(),
            "parent directory created"
        );
    }

    #[test]
    fn policy_subcommands_parse() {
        let c = Cli::try_parse_from([
            "dexdo",
            "policy",
            "init",
            "--role",
            "buyer",
            "--path",
            "policy.json",
        ])
        .expect("policy init parses");
        assert!(matches!(c.command, Command::Policy(_)));
        let c = Cli::try_parse_from(["dexdo", "policy", "show"]).expect("policy show parses");
        assert!(matches!(c.command, Command::Policy(_)));
        let c = Cli::try_parse_from(["dexdo", "policy", "edit"]).expect("policy edit parses");
        assert!(matches!(c.command, Command::Policy(_)));
        let c = Cli::try_parse_from([
            "dexdo",
            "policy",
            "validate",
            "--role",
            "seller",
            "--path",
            "policy.json",
        ])
        .expect("seller policy validation parses");
        assert!(matches!(c.command, Command::Policy(_)));
        let c = Cli::try_parse_from([
            "dexdo",
            "provision",
            "--frame-model",
            "qwen--qwen3--32b",
            "--policy",
            "policy.json",
        ])
        .expect("provision --policy parses");
        let Command::Provision(args) = c.command else {
            panic!("provision command expected");
        };
        assert_eq!(
            args.policy.as_deref(),
            Some(std::path::Path::new("policy.json"))
        );
    }

    #[test]
    fn default_endpoints_path_is_under_platform_app_dir() {
        // Pure function(no directory creation) -- no side effects in the test.
        // ProjectDirs == None only without a home directory; otherwise the path is under dexdo/endpoints.json.
        if let Ok(p) = default_endpoints_path() {
            assert!(
                p.ends_with("endpoints.json"),
                "ends with endpoints.json: {p:?}"
            );
            assert!(
                p.to_string_lossy().to_lowercase().contains("dexdo"),
                "path contains the dexdo app segment: {p:?}"
            );
        }
    }

    #[test]
    fn seller_model_help_matches_real_shellnet_requirement() {
        let help = subcommand_long_help("seller");
        assert!(
            help.contains("Required on real shellnet even with `--mock-model`"),
            "{help}"
        );
        assert!(
            help.contains("optional only for the `--mock-chain --mock-model` demo"),
            "{help}"
        );
        assert!(!help.contains("Not needed with `--mock-model`"), "{help}");
    }

    #[test]
    fn seller_gateway_advertise_help_documents_public_host_port() {
        let help = subcommand_long_help("seller");
        assert!(help.contains("--gateway-advertise <HOST:PORT>"), "{help}");
        assert!(help.contains("Defaults to --gateway-listen"), "{help}");
    }

    #[test]
    fn seller_help_documents_the_advertise_reachability_flags() {
        let help = subcommand_long_help("seller");
        assert!(help.contains("--allow-private-advertise"), "{help}");
        assert!(help.contains("--require-advertise-probe"), "{help}");
        assert!(
            help.contains("must be reachable by a REMOTE buyer"),
            "{help}"
        );
    }

    #[test]
    fn listen_help_documents_seller_buyer_equivalence() {
        let seller = subcommand_long_help("seller");
        assert!(
            seller.contains("equivalent of buyer --local-listen"),
            "{seller}"
        );
        let buyer = subcommand_long_help("buyer");
        assert!(
            buyer.contains("equivalent of seller --gateway-listen"),
            "{buyer}"
        );
    }

    #[test]
    fn buyer_model_alias_is_visible_in_help() {
        let help = subcommand_long_help("buyer");
        assert!(help.contains("--frame-model <FRAME_MODEL>"), "{help}");
        assert!(help.contains("Alias: --model"), "{help}");
        assert!(help.contains("[aliases: --model]"), "{help}");
    }

    #[test]
    fn note_deploy_token_type_help_lists_values() {
        let help = nested_subcommand_long_help(&["note", "deploy"]);
        assert!(help.contains("--token-type <TOKEN_TYPE>"), "{help}");
        assert!(help.contains("[possible values: shell]"), "{help}");
        assert!(!help.to_ascii_lowercase().contains("nackl"), "{help}");
        assert!(!help.to_ascii_lowercase().contains("usdc"), "{help}");
    }

    #[test]
    fn note_deploy_rejects_non_shell_token_types() {
        for token_type in ["nackl", "usdc"] {
            let parsed = Cli::try_parse_from([
                "dexdo",
                "note",
                "deploy",
                "--multisig-address",
                "0:wallet",
                "--multisig-key",
                "w.keys.json",
                "--nominal",
                "N100",
                "--pool",
                "pn_pool.json",
                "--token-type",
                token_type,
            ]);
            assert!(parsed.is_err(), "{token_type} must be rejected");
        }
    }

    /// the deposit is a spend from the funding wallet, so `note deploy` must never pick a
    /// denomination on the operator's behalf. Without `--nominal` it fails at parse time, before
    /// any wallet transaction is submitted.
    #[test]
    fn note_deploy_requires_an_explicit_nominal() {
        let Err(err) = Cli::try_parse_from([
            "dexdo",
            "note",
            "deploy",
            "--multisig-address",
            "0:wallet",
            "--multisig-key",
            "w.keys.json",
            "--pool",
            "pn_pool.json",
        ]) else {
            panic!("note deploy without an explicit nominal must be rejected");
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        assert!(err.to_string().contains("--nominal"), "{err}");

        let help = nested_subcommand_long_help(&["note", "deploy"]);
        assert!(!help.contains("[default: N100]"), "{help}");
    }

    /// The onboarding docs published with the release binary. `release/build-public-tree.sh`
    /// allow-lists exactly these three skill directories, so they are what a new user reads.
    const PUBLISHED_ONBOARDING_DOCS: [(&str, &str); 3] = [
        (
            ".claude/skills/dexdo-install/SKILL.md",
            include_str!("../../../.claude/skills/dexdo-install/SKILL.md"),
        ),
        (
            ".claude/skills/dexdo-buy-model/SKILL.md",
            include_str!("../../../.claude/skills/dexdo-buy-model/SKILL.md"),
        ),
        (
            ".claude/skills/dexdo-sell-model/SKILL.md",
            include_str!("../../../.claude/skills/dexdo-sell-model/SKILL.md"),
        ),
    ];

    /// Values a doc tells the reader to pass to `flag`, in `--flag value` or `--flag=value` form,
    /// anywhere in the prose or in a fenced command block. Backticks are markdown, not argv.
    fn documented_flag_values(doc: &str, flag: &str) -> Vec<String> {
        let unquote = |t: &str| {
            t.trim_matches(|c| c == '`' || c == '"' || c == '\'')
                .to_string()
        };
        let inline = format!("{flag}=");
        let tokens: Vec<&str> = doc.split_whitespace().collect();
        let mut values = Vec::new();
        for (i, raw) in tokens.iter().enumerate() {
            let token = unquote(raw);
            if let Some(value) = token.strip_prefix(&inline) {
                values.push(value.to_string());
            } else if token == flag {
                if let Some(next) = tokens.get(i + 1) {
                    values.push(unquote(next));
                }
            }
        }
        values
    }

    /// Shell structure that ends the command's own argv in a documented line: a redirection with
    /// its target, a pipeline, a list operator, or a trailing comment. A published `dexdo note
    /// deploy` procedure that ends by sending its JSON to a file is normal, correct usage, and the
    /// argv the reader's shell hands `dexdo` stops at the redirection operator.
    /// Matched as a **whole token**, which is what keeps this away from the docs' placeholder
    /// convention: `>` and `|` stand alone, while `0:<WALLET>` and `cancel <ID>` are single tokens a
    /// reader substitutes and must stay in the argv the parser checks. That convention is exactly
    /// what a *printed* command line may not use -- the binary's own output is meant to be pasted,
    /// not edited -- which is why this guard and `printed_commands::shell_split` judge angle
    /// brackets differently, on purpose.
    /// Whole-token matching also means an attached form such as `>/dev/null` is *not* recognised.
    /// No swept doc uses one on a `dexdo` line today, and if one appears the guard fails loudly
    /// with the parser's own complaint rather than quietly accepting a truncated argv -- which is
    /// the side to fail on.
    fn ends_documented_argv(token: &str) -> bool {
        matches!(
            token,
            ">" | ">>" | "<" | "<<" | "<>" | ">|" | "|" | "||" | "&&" | ";" | "&"
        ) || token.starts_with('#')
    }

    /// Command lines a doc tells the reader to run, joined across `\` continuations and split into
    /// argv. Only lines that start with the bare binary name count; prose mentions such as
    /// `` `dexdo note deploy` funds a note `` start with a backtick and are skipped.
    fn documented_commands(doc: &str, subcommand: &[&str]) -> Vec<Vec<String>> {
        let lines: Vec<&str> = doc.lines().collect();
        let mut commands = Vec::new();
        let mut index = 0;
        while index < lines.len() {
            if !lines[index].trim_start().starts_with("dexdo ") {
                index += 1;
                continue;
            }
            let mut joined = String::new();
            loop {
                let line = lines[index].trim();
                let continued = line.ends_with('\\');
                joined.push_str(line.trim_end_matches('\\').trim_end());
                joined.push(' ');
                index += 1;
                if !continued || index >= lines.len() {
                    break;
                }
            }
            let argv: Vec<String> = joined
                .split_whitespace()
                .take_while(|token| !ends_documented_argv(token))
                .map(str::to_string)
                .collect();
            let matches_subcommand = subcommand
                .iter()
                .enumerate()
                .all(|(offset, name)| argv.get(offset + 1).map(String::as_str) == Some(*name));
            if matches_subcommand {
                commands.push(argv);
            }
        }
        commands
    }

    /// The value set the shipped parser itself enforces for a `note deploy` flag -- read off the
    /// clap command, never a second copy of the list that could drift from the `value_parser`.
    fn note_deploy_possible_values(command: &clap::Command, arg_id: &str) -> Vec<String> {
        command
            .find_subcommand("note")
            .expect("note subcommand exists")
            .find_subcommand("deploy")
            .expect("note deploy subcommand exists")
            .get_arguments()
            .find(|arg| arg.get_id() == arg_id)
            .unwrap_or_else(|| panic!("note deploy has a {arg_id} argument"))
            .get_possible_values()
            .iter()
            .map(|value| value.get_name().to_string())
            .collect()
    }

    /// Recurrence guard. v0.0.20 published onboarding skills that told a new user to pass a
    /// `--token-type` value the shipped binary's own `value_parser` rejects, so their first money
    /// command was a hard parse error. Any documented value for a restricted flag must be one the
    /// parser accepts.
    #[test]
    fn published_docs_only_document_accepted_flag_values() {
        let accepted = note_deploy_possible_values(&Cli::command(), "token_type");
        assert!(
            !accepted.is_empty(),
            "--token-type must keep a restricted value set for this guard to mean anything"
        );
        for (path, body) in PUBLISHED_ONBOARDING_DOCS {
            for value in documented_flag_values(body, "--token-type") {
                assert!(
                    accepted.contains(&value),
                    "{path} tells users to pass `--token-type {value}`, which the CLI rejects; \
                     accepted values: {accepted:?}"
                );
            }
        }
    }

    /// Recurrence guard, the whole-command half: every `dexdo note deploy` invocation the
    /// published docs hand a user must parse with the shipped parser, so neither a rejected flag
    /// value nor a missing required flag(such as `--nominal`) can reach a release again.
    #[test]
    fn published_docs_note_deploy_commands_parse() {
        for (path, body) in PUBLISHED_ONBOARDING_DOCS {
            let commands = documented_commands(body, &["note", "deploy"]);
            assert!(
                !commands.is_empty(),
                "{path} no longer shows a runnable `dexdo note deploy` command"
            );
            for argv in commands {
                if let Err(err) = Cli::try_parse_from(&argv) {
                    let rendered = argv.join(" ");
                    panic!("{path} documents a command the CLI rejects:\n  {rendered}\n{err}");
                }
            }
        }
    }

    /// The machinery of the lint below, checked against the shapes it has to handle before it is
    /// trusted on the real tree: a line split by a source-line continuation, placeholders standing
    /// in for values, prose naming only a command, a line that leaves the binary name implicit, a
    /// command that no longer exists, and -- the defect this exists to stop -- a printed line
    /// missing something the parser requires. It also pins the two properties the lint's own
    /// counting depends on: a span inside a string literal is what the binary can print, and a
    /// span in a comment is not. The fixtures spell their backticks `\u{60}` so this test is not
    /// itself a printed command in the swept sources.
    #[test]
    fn printed_command_machinery_finds_and_judges_the_shapes_it_meets() {
        use crate::cli::support::printed_commands::{
            classify, runs, shell_split, top_level_subcommands, Origin, PrintedRun,
        };
        let subcommands = top_level_subcommands();
        assert!(
            subcommands.iter().any(|name| name == "note"),
            "{subcommands:?}"
        );

        let continued = "bail!(\n    \"finalize it with \u{60}dexdo note recover --recovery {} \\\n     --pool {}\u{60} to avoid re-spending\"\n);\n";
        let found = runs(continued, &subcommands);
        assert_eq!(
            found
                .iter()
                .map(|run| run.text.as_str())
                .collect::<Vec<_>>(),
            vec!["dexdo note recover --recovery {} --pool {}"],
            "a line split by a source-line continuation must be recovered as one line"
        );
        assert_eq!(
            found[0].line, 2,
            "the reported line must be where it starts"
        );
        assert_eq!(found[0].origin, Origin::Literal);
        assert_eq!(classify(&found[0].text), Ok(PrintedRun::Invocation));

        // Provenance, which the coverage floor depends on: the same span is printable in a string
        // literal and mere commentary in a doc comment.
        let mixed = "/// see \u{60}dexdo note deploy --pool p.json\u{60}\nlet s = \"run \u{60}dexdo note deploy --pool p.json\u{60}\";\n";
        let found = runs(mixed, &subcommands);
        assert_eq!(
            found.iter().map(|run| run.origin).collect::<Vec<_>>(),
            vec![Origin::Commentary, Origin::Literal]
        );

        let broken = "\u{60}dexdo note deploy --recovery r.json --pool p.json\u{60}";
        let err = classify(&runs(broken, &subcommands)[0].text)
            .expect_err("a printed line missing a required flag must be rejected");
        assert!(err.contains("--nominal"), "{err}");

        // A line whose only argument is a positional is still a line to run: it is parsed, and a
        // truncation that drops the positional is caught.
        assert_eq!(
            classify("dexdo executable-book qwen--qwen3--32b"),
            Ok(PrintedRun::Invocation)
        );
        let err = classify("dexdo close --note-key k.json")
            .expect_err("close without its deal positional must be rejected");
        assert!(err.contains("<DEAL>"), "{err}");

        // the defect this lint exists to stop: an angle-bracket template is not the argv it
        // looks like. The lint is routed through `shell_split`, so it sees what the shell sees --
        // a redirection consumed before `dexdo` runs -- instead of accepting `<buyer-key>` as a
        // value. Before this, these classified as ordinary invocations and shipped.
        for template in [
            "dexdo executable-book <model>",
            "dexdo reclaim --token-contract 0:33 --note-addr <buyer-note> --note-key <buyer-key>",
            "dexdo market <canonical-model>",
        ] {
            let err = classify(template)
                .expect_err("an angle-bracket template is a redirection, not a printable command");
            assert!(
                err.contains("shell operator"),
                "{template} must be rejected as a shell operator, not something else: {err}"
            );
        }

        let implicit =
            "\u{60}note deploy --recovery r.json\u{60} and prose \u{60}note deploy\u{60}";
        let found = runs(implicit, &subcommands);
        assert_eq!(
            found.iter().map(|run| run.text.as_str()).collect::<Vec<_>>(),
            vec!["note deploy --recovery r.json"],
            "a printed line may leave the binary name implicit, but bare prose is not a line to run"
        );
        assert!(classify(&found[0].text).is_err());

        assert_eq!(
            classify("dexdo note deploy"),
            Ok(PrintedRun::Reference),
            "prose naming only the command is a reference, not a line to run"
        );
        assert_eq!(
            classify("dexdo {want}"),
            Ok(PrintedRun::Dynamic),
            "a command filled in at run time cannot be checked here"
        );
        let err = classify("dexdo note redeploy")
            .expect_err("a command that no longer exists must be rejected");
        assert!(err.contains("redeploy"), "{err}");
        let err = classify("dexdo frobnicate --now")
            .expect_err("a top-level command that does not exist must be rejected");
        assert_eq!(
            err,
            "names `frobnicate`, which is not a subcommand of this CLI"
        );

        // Redirections and pipelines are structure, not defects(PR687): a published procedure that
        // sends output to a file is correct usage, and the argv is the command before the operator.
        // Each expectation below was checked against `/bin/sh -n` first -- the model follows the
        // shell, the shell does not follow the model.
        for (line, expected) in [
            (
                "dexdo note deploy --nominal 1 > /tmp/out.json",
                vec!["dexdo", "note", "deploy", "--nominal", "1"],
            ),
            (
                "dexdo note deploy --nominal 1 >> '/tmp/my out.json'",
                vec!["dexdo", "note", "deploy", "--nominal", "1"],
            ),
            (
                "dexdo note deploy --nominal 1 2> /tmp/err.log",
                vec!["dexdo", "note", "deploy", "--nominal", "1"],
            ),
            (
                "dexdo market qwen | jq .",
                vec!["dexdo", "market", "qwen"],
            ),
            (
                "dexdo market qwen && dexdo quote --ticks 1",
                vec!["dexdo", "market", "qwen"],
            ),
            (
                "dexdo note recover --recovery r.json < /tmp/in",
                vec!["dexdo", "note", "recover", "--recovery", "r.json"],
            ),
        ] {
            assert_eq!(
                shell_split(line).unwrap_or_else(|why| panic!("{line}: {why}")),
                expected,
                "the argv is the command; the redirect or pipeline is the shell's: {line}"
            );
        }
        // And the reason this does not soften the template check: a real shell rejects a trailing
        // redirection with no target, which is exactly what an angle-bracket placeholder leaves.
        let err = shell_split("dexdo status <deal>")
            .expect_err("a redirection with no target is a syntax error, not an argument");
        assert!(err.contains("shell operator"), "{err}");

        // The shell split has to undo exactly what `shell_arg` produces, or an emitted line with a
        // space or a quote in it would look fine to a test and break for the operator.
        for value in [
            "/tmp/pn pool/r.json",
            "it's here",
            "a\"b",
            "x;rm -rf /",
            "<pool>",
        ] {
            assert_eq!(
                shell_split(&crate::cli::support::shell_arg(value))
                    .expect("what `shell_arg` quotes must be a line a shell accepts"),
                vec![value.to_string()],
                "quoting round-trip for {value}"
            );
        }
    }

    /// naming a command is only half of what name-only guidance owes the operator. The other
    /// half is stating the inputs they have to supply, and it is asserted rather than assumed --
    /// guidance that names `dexdo close` but silently stopped stating the `--note-key` its handler
    /// demands is a dead end, and must fail the check that claims to cover it.
    #[test]
    #[should_panic(expected = "--note-key")]
    fn name_only_guidance_that_drops_a_required_input_fails() {
        crate::cli::support::printed_commands::assert_emitted_commands_name_only(
            "stop the deal with `dexdo close`",
            "guidance that forgot its inputs",
            &["--note-key"],
        );
    }

    /// Recurrence lint: the binary's own counterpart to the doc guard above. That one sweeps
    /// the published docs; this one reads this crate's and `dexdo-core`'s sources and rejects any
    /// backticked command line the shipped parser will not accept -- errors, recovery guidance,
    /// machine-readable next-step hints and `--help` text alike. A printed `note deploy` resume
    /// line that left out the newly required `--nominal` is what it catches.
    /// It is a lint over source text, not a proof about output: it sees `{path}` where the user
    /// sees a real path, so the argv a builder actually composes is checked separately, next to
    /// each builder, through `assert_emitted_commands_parse`. Its blind spots are stated in the
    /// pull request rather than implied away: a command embedded inside a longer backticked span,
    /// output that does not use backticks, a span that is exactly a command path (indistinguishable
    /// from prose), and the run-time value behind `dexdo {want}`.
    #[test]
    fn no_command_line_in_these_sources_is_rejected_by_the_parser() {
        use crate::cli::support::printed_commands::{
            classify, runs, top_level_subcommands, Origin, PrintedRun,
        };
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let subcommands = top_level_subcommands();
        let (mut files, mut printable_invocations, mut printable_references) = (0, 0, 0);
        let (mut commentary, mut dynamic) = (0, 0);
        let mut rejected = Vec::new();
        let mut literal_sites = std::collections::BTreeSet::new();
        for root in [crate_root.join("src"), crate_root.join("../core/src")] {
            for path in rust_sources(&root) {
                files += 1;
                let relative = path
                    .strip_prefix(&root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                let raw = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                for run in runs(&raw, &subcommands) {
                    // Commentary inside a `#[cfg(test)]` item is printed by nothing: the one
                    // reason to scan commentary at all is clap building `--help` from a doc
                    // comment, and a `#[cfg(test)]` item builds no clap command. Rejecting it
                    // made this guard say "the CLI prints..." about a `///` describing a test.
                    if run.origin == Origin::TestCommentary {
                        commentary += 1;
                        continue;
                    }
                    let printable = run.origin == Origin::Literal;
                    match (classify(&run.text), printable) {
                        (Ok(PrintedRun::Invocation), true) => {
                            printable_invocations += 1;
                            literal_sites.insert(relative.clone());
                        }
                        (Ok(PrintedRun::Reference), true) => {
                            printable_references += 1;
                            literal_sites.insert(relative.clone());
                        }
                        (Ok(PrintedRun::Dynamic), _) => dynamic += 1,
                        (Ok(_), false) => commentary += 1,
                        (Err(why), _) => {
                            let (file, line) = (path.display(), run.line);
                            rejected.push(format!("{file}:{line}\n    `{}`\n    {why}", run.text));
                        }
                    }
                }
            }
        }
        assert!(
            rejected.is_empty(),
            "the CLI prints {} command line(s) it cannot run; print a line that parses, or drop \
             the arguments and describe the action instead:\n{}",
            rejected.len(),
            rejected.join("\n")
        );
        // Anti-vacuity. A bare count is the wrong shape here whatever its value, and this is the
        // second attempt: the previous floor counted every span the sweep met, and 103 spans on
        // comment lines alone cleared it -- so it would have stayed green with every runtime
        // message in the tree deleted. Raising the number does not fix that. The sweep finds only
        // ~44 single-line production spans across ~15 files, so any threshold low enough to be
        // stable against ordinary edits is also low enough to be met by lines no operator sees.
        // So the requirement is named rather than numeric: each of these files must still
        // contribute at least one `Origin::Literal` span -- a command the shipped binary prints
        // from a string literal it actually compiles. A doc comment is `Commentary` and a
        // `#[cfg(test)]` fixture is `TestGated`, so neither can satisfy this by construction, and
        // the only way to keep it green is for that file's runtime guidance to still be there.
        // Each name is a distinct place an operator is left with no next step if its guidance goes:
        // the audit export, the close path, note deploy and its recovery, the policy scaffold, and
        // the seller's resting-order cleanup.
        let required_literal_sites = [
            "cli/audit.rs",
            "cli/close.rs",
            "cli/note.rs",
            "cli/note_cmd.rs",
            "cli/policy.rs",
            "seller/liveness.rs",
        ];
        let missing: Vec<&str> = required_literal_sites
            .iter()
            .copied()
            .filter(|name| !literal_sites.contains(*name))
            .collect();
        assert!(
            missing.is_empty(),
            "these files no longer print a single command the shipped binary can emit, so this \
             lint would now pass with their operator guidance gone: {missing:?}\nfiles that do \
             print one: {literal_sites:?}"
        );
        // The sweep itself must still be reading the tree; this is a wiring check, not a floor on
        // guidance, and the named requirement above is what makes the lint non-vacuous.
        assert!(
            files >= 40,
            "the sweep covered only {files} files, so it is not reading this tree: \
             {printable_invocations} printable invocations, {printable_references} printable \
             references, {commentary} commentary spans, {dynamic} run-time-named"
        );
    }

    /// Every `.rs` file under `root`, so a source file added later is linted without being listed
    /// anywhere.
    fn rust_sources(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut stack = vec![root.to_path_buf()];
        let mut files = Vec::new();
        while let Some(dir) = stack.pop() {
            let entries =
                std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
            for entry in entries {
                let path = entry.expect("directory entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    files.push(path);
                }
            }
        }
        files.sort();
        files
    }

    #[test]
    fn buyer_continuity_mode_help_documents_operator_tradeoff() {
        let help = subcommand_long_help("buyer");
        assert!(help.contains("--continuity-mode <MODE>"), "{help}");
        assert!(help.contains("[default: proactive]"), "{help}");
        assert!(
            help.contains("[possible values: proactive, on-demand]"),
            "{help}"
        );
        assert!(
            help.contains("proactive keeps a warm next deal ready"),
            "{help}"
        );
        assert!(help.contains("may pre-buy while idle"), "{help}");
        assert!(
            help.contains("on-demand buys only after active/recent consumer traffic"),
            "{help}"
        );
        assert!(help.contains("first request after idle may wait"), "{help}");
    }

    #[test]
    fn provision_deposit_help_is_short_and_unit_explicit() {
        let help = subcommand_long_help("provision");
        assert!(help.contains("whole SHELL"), "{help}");
        assert!(help.contains("1 SHELL = 1e9 raw"), "{help}");
        assert!(help.contains("not raw nano/vmshell"), "{help}");
        assert!(
            help.contains("Unused deploy remainder burns at `destroy`"),
            "{help}"
        );
        assert!(!help.contains("fund-10"), "{help}");
        assert!(!help.contains("MIN_BALANCE"), "{help}");
        assert!(!help.contains("REGISTER_FORWARD_VALUE"), "{help}");
    }

    #[test]
    fn consumer_api_budget_is_ticks_times_canonical_tick_size() {
        assert_eq!(
            consumer_api_token_budget(8),
            8 * dexdo_core::DobParams::canonical().tick_size
        );
        assert_eq!(consumer_api_token_budget(u128::MAX), u64::MAX);
    }

    /// Issue: `--market` feeds `token_contract` + `frame_model` from a provision manifest verbatim
    /// (no hand-editing), and the explicit flags are used when `--market` is absent.
    #[test]
    fn market_loader_resolves_fields() {
        let valid = dexdo_core::MarketManifest {
            network: "shellnet".into(),
            frame_model: "qwen/qwen3-32b".into(),
            model_hash: dexdo_core::model_hash_for("qwen/qwen3-32b"),
            inference_order_book: "0:ob".into(),
            root_model: "0:rm".into(),
            token_contract: "0:tc".into(),
            seller_note: "0:n".into(),
            nonce: 1,
            price_per_tick: 1000,
            max_ticks: 8,
        };
        let dir = tempfile::tempdir().expect("market manifest test dir");
        let dir = dir.path();
        let write = |name: &str, m: &dexdo_core::MarketManifest| {
            let p = dir.join(name);
            std::fs::write(&p, m.to_json().unwrap()).unwrap();
            p
        };

        // --market provides token_contract, frame_model AND the deal nonce, verbatim.
        let p = write("ok.json", &valid);
        let (tc, fm, nonce) = resolve_market_fields(Some(&p), None, None).unwrap();
        assert_eq!(tc, "0:tc");
        assert_eq!(fm.as_deref(), Some("qwen/qwen3-32b"));
        assert_eq!(
            nonce,
            Some(1),
            "--market must preserve the manifest's deal nonce for the seller"
        );

        // Flags path: token_contract + optional frame_model(the seller passes None for frame_model).
        // The explicit path carries no nonce -- the seller must supply it via `--nonce`.
        let (tc, fm, nonce) = resolve_market_fields(None, Some("0:flag"), Some("m")).unwrap();
        assert_eq!((tc.as_str(), fm.as_deref()), ("0:flag", Some("m")));
        assert!(
            nonce.is_none(),
            "explicit --token-contract path yields no nonce (the seller needs --nonce)"
        );
        let (tc, fm, _nonce) = resolve_market_fields(None, Some("0:flag"), None).unwrap();
        assert_eq!((tc.as_str(), fm), ("0:flag", None));

        // Neither --market nor --token-contract -> explicit error.
        assert!(resolve_market_fields(None, None, None).is_err());

        // Fail-loud: --market is mutually exclusive with the explicit flags(no silent precedence).
        assert!(resolve_market_fields(Some(&p), Some("0:other"), None).is_err());
        assert!(resolve_market_fields(Some(&p), None, Some("other")).is_err());

        // Corrupt manifest(model_hash inconsistent with frame_model) is rejected by load.
        let mut bad = valid.clone();
        bad.model_hash = "0xdeadbeef".into();
        let pb = write("bad.json", &bad);
        assert!(resolve_market_fields(Some(&pb), None, None).is_err());

        // Empty token_contract is rejected.
        let mut empty = valid.clone();
        empty.token_contract = String::new();
        let pe = write("empty.json", &empty);
        assert!(resolve_market_fields(Some(&pe), None, None).is_err());
    }

    /// Issue(review): the seller fails closed when the `--market` manifest's model does not match
    /// the `--model` it would serve(no posting the manifest's TC into the wrong order book).
    #[test]
    fn market_model_match_fails_closed() {
        // No manifest model(flags path) or a matching one -- OK.
        assert!(check_market_model_match(None, "qwen/qwen3-32b", "qwen").is_ok());
        assert!(check_market_model_match(Some("qwen/qwen3-32b"), "qwen/qwen3-32b", "qwen").is_ok());
        // Mismatch -- fail closed.
        let err = check_market_model_match(Some("qwen/qwen3-32b"), "llama/llama-3", "llama")
            .unwrap_err()
            .to_string();
        assert!(err.contains("wrong model"), "{err}");
    }
}
