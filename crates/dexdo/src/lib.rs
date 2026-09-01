//! `dexdo` -- a binary with `seller`/`buyer` subcommands (clap) and the shared library of their logic.
//! Mock mode (`--mock-model`, `--mock-chain`) is a standard mode in production code.

#[cfg(test)]
mod test_refusing_endpoint;

// Shared with the binary's `cli::source_probe` -- same file, declared in both targets. See the
// comment there.
#[cfg(test)]
pub(crate) mod source_probe;
// the deal's `_balance` must be disposed of on every path to `selfdestruct`. Declared at the
// crate root because it guards a CONTRACT, not any one Rust module, and because `code_of` lives here.
#[cfg(test)]
mod token_contract_die_disposal_1786;
/// Put SIGPIPE back to "ignored" for a process that is about to SERVE.

/// `main` restores the default disposition at process entry so that a one-shot printer whose
/// reader has gone away ends like every other Unix tool instead of panicking with exit 101. That is
/// right for a command that prints and exits, and WRONG for a process that serves: SIGPIPE is
/// process-wide, and this binary's socket writes go out through a bare `writev(2)` -- there is no
/// `MSG_NOSIGNAL` anywhere in the mio/tokio/hyper stack it uses, and no `SO_NOSIGPIPE` is set. Under
/// the default disposition, a consumer that hangs up mid-answer would therefore not give the server
/// an `EPIPE` to handle: it would kill the process, mid-stream, on the money path.

/// So the serving modes ask for the ignored disposition back, explicitly, at the point where they
/// begin to serve. This is deliberately NOT deduplicated away into `main`: the entry policy and the
/// serving policy are two different decisions about two different kinds of process, and collapsing
/// them into one is exactly how the serving half would get lost.

/// Closing the risk by construction rather than by a lucky run: a probe that fails to make a gateway
/// die proves nothing, because the absence of a signal in one run is not the absence of the signal.
#[cfg(unix)]
pub fn serving_process_ignores_sigpipe() {
    // SAFETY: sets a process-wide signal disposition to SIG_IGN, which is the disposition Rust's own
    // runtime installs before `main`. Idempotent, and safe to call from any thread.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

/// Non-unix builds never changed the disposition, so there is nothing to put back.
#[cfg(not(unix))]
pub fn serving_process_ignores_sigpipe() {}

pub mod buyer;
pub mod registry;
pub mod runtime_events;
pub mod seller;
pub mod wallet_seed;
