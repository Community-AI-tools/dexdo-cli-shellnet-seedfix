//! `dexdo` -- a binary with `seller`/`buyer` subcommands(clap) and the shared library of their logic.
//! Mock mode(`--mock-model`, `--mock-chain`) is a standard mode in production code.

#[cfg(test)]
mod test_refusing_endpoint;

pub mod buyer;
pub mod registry;
pub mod runtime_events;
pub mod seller;
pub mod wallet_seed;
