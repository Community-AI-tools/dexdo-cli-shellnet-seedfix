//! `dexdo` CLI surface, split out of `main.rs`(PR3, move-only / behavior-stable, `refactoring-plan.md`).
//! `main.rs` keeps parse + logging + shutdown signal + dispatch; the subcommand argument structs, helpers,
//! and command handlers live here.

/// The standard `NO_COLOR` override: any non-empty value disables terminal styling.
pub(crate) fn no_color_requested() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty())
}

pub(crate) mod accumulator;
pub(crate) mod admin;
pub(crate) mod args;
pub(crate) mod audit;
pub(crate) mod buyer;
pub(crate) mod close;
pub(crate) mod commands;
pub(crate) mod dashboard;
pub(crate) mod data_dir;
pub(crate) mod deals;
pub(crate) mod indexer;
pub(crate) mod machine;
pub(crate) mod market_views;
pub(crate) mod markets;
pub(crate) mod monitor;
// pure schema/adapter half of `note deploy`. Every non-test consumer (`note_cmd`, `commands`,
// `buyer`) is behind `shellnet`, so the module only exists there and under test.
#[cfg(any(feature = "shellnet", test))]
pub(crate) mod note;
pub(crate) mod note_cmd;
pub(crate) mod oracle;
pub(crate) mod orders;
pub(crate) mod policy;
// shared provenance vocabulary for chain-backed book views and indexer depth.
pub(crate) mod provenance;
// QR-as-image: the probe-reply parsing, the protocol decision and the encoders are pure and
// compile under every test build(the `wallet_manual` pattern); the terminal I/O and the `qrcode`
// entry point sit behind `shellnet` inside the module, next to its only callers.
#[cfg(any(feature = "shellnet", test))]
pub(crate) mod qr_display;
pub(crate) mod recover;
pub(crate) mod reports;
pub(crate) mod seller;
pub(crate) mod seller_policy;
pub(crate) mod settlement_receipt;
pub(crate) mod support;
// the wallet provider model, the durable active binding, and the fail-fast.
pub(crate) mod wallet;
// the shared Hot check-and-fund mechanism and its durable journal. Its only callers are the
// two commands that spend a Hot(`note deploy`, `note topup`), both behind `shellnet`, so the
// module exists there and under test - the same boundary `note` uses.
#[cfg(any(feature = "shellnet", test))]
pub(crate) mod wallet_funding;
// re-audit items 4 and 8: how the funding wait treats a read that got no answer, and what its
// failure hands a machine consumer. Declared beside the two modules it drives - `wallet_funding`
// and `machine` - rather than inside either, so reverting one of them leaves the regression
// compiled and failing instead of silently uncollected.
#[cfg(test)]
mod wallet_funding_wait_failures_334;
// Gosh.ai onboarding, reached from `wallet onboard gosh-ai` through `wallet::provider_flow`.
// The `allow(dead_code)` that used to sit here is gone with the wiring it was waiting for.
#[cfg(any(feature = "shellnet", test))]
pub(crate) mod wallet_goshai;
// the manual provider, reached from `wallet onboard manual` through `wallet::provider_flow`.
// Its decision, binding and funding-wait halves are pure, so they compile and are tested under CI's
// default features while only the chain reads sit behind `shellnet`. The funding half still has no
// caller in either build, until the shared provider-aware funding step is wired into `note deploy`
// `note topup`; it is covered by this module's own tests.
// Compiled where the binding schema it shares with PR1287 is: `shellnet`, plus every test build,
// which is what CI runs.
#[allow(dead_code)]
#[cfg(any(feature = "shellnet", test))]
pub(crate) mod wallet_manual;
// (rymkapro, 2026-08-17): `wallet remove-archived` deletes the only local keys to a Hot, so it
// must hold the funding wallet's turn across BOTH observations the deletion rests on. Declared here
// rather than inside `wallet`, because it pins a property shared by `wallet` and `note_cmd` - the
// lock's key - and a regression living in one of them would go uncollected the moment that module
// was reverted.
#[cfg(test)]
mod wallet_remove_archived_lock_334;
// the gas floor a funding wallet's own outgoing messages need, and the rule that the client
// states it before it commits a spend. Declared here rather than inside one of the modules it pins
// because it pins THREE - `wallet_funding`'s floor, `accumulator`'s sell and `note_cmd`'s top-up
// preflight - and a regression living in any one of them would be uncollected the moment that
// module was reverted.
#[cfg(test)]
mod wallet_gas_floor_1392;
// (PR715): the authenticated bee-session onboarding the `ackinacki-wallet` provider runs.
pub(crate) mod wallet_onboarding;
#[cfg(windows)]
pub(crate) mod windows_secret_file;
