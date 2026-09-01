//! Whether this run may ask the operator anything.

//! One answer for the whole process, decided once from the command line and the destination, so the
//! rule cannot come out differently in two places. A command that asks a question the caller cannot
//! answer does not fail -- it hangs, holding a lock and, on the money paths, an escrow.

//! `--non-interactive` states it outright. Without the flag it is the destination that decides:
//! both stdin and stderr must be a terminal, because a question is read from one and drawn on the
//! other.

//! WHETHER a question is already answered is a different question with a different source, and it
//! lives in [`super::command_line`]: this module decides if anyone can answer, that one decides if
//! anyone already has.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

/// Set by `--non-interactive`, read everywhere.
static REFUSED: AtomicBool = AtomicBool::new(false);

/// Set when this run answers to a machine (`--json`), which never has a person behind it.
static MACHINE: AtomicBool = AtomicBool::new(false);

/// Whether the operator's own screen was a terminal, latched before anything can redirect it.
static SCREEN_IS_TERMINAL: OnceLock<bool> = OnceLock::new();

/// Record what the command line said, and what the operator's screen was. Called once, from `main`,
/// before any command runs.

/// The screen is latched HERE and not read on demand, because descriptor 2 does not stay the
/// operator's for the whole run: `note deploy` points it at a pipe while the prover talks, so the
/// prover's own lines can be folded into the status display instead of scrolling past
/// (`progress_capture`). Asked afterwards, `stderr().is_terminal()` answers about that pipe -- so a
/// command that HAD an operator in front of it decided it did not, and refused to ask. Measured:
/// with the fold installed, `note deploy` could never reach the onboarding it exists to offer, in
/// any configuration.
/// `machine` is `--json`: the run's stdout is one NDJSON stream and its reader is a program. Such a
/// run must never ask, and the terminal test cannot tell: an orchestrator that pipes only stdout
/// leaves stdin and stderr terminals, so `may_ask` said yes and the client drew an arrow-key menu
/// into a session nobody was watching -- a hang holding a lock and, on the money paths, an escrow.
pub(crate) fn configure(non_interactive: bool, machine: bool) {
    REFUSED.store(non_interactive, Ordering::Relaxed);
    MACHINE.store(machine, Ordering::Relaxed);
    let _ = SCREEN_IS_TERMINAL.set(screen_now());
}

fn screen_now() -> bool {
    use std::io::IsTerminal as _;

    std::io::stderr().is_terminal()
}

/// Is there an operator's screen to draw a question on?

/// The latched answer, or -- for the unit tests in this binary, where `configure` never ran -- what
/// the stream says now, which under `cargo test` is "no".
pub(crate) fn screen_is_terminal() -> bool {
    *SCREEN_IS_TERMINAL.get_or_init(screen_now)
}

/// May this run ask the operator a question?
pub(crate) fn may_ask() -> bool {
    use std::io::IsTerminal as _;

    !REFUSED.load(Ordering::Relaxed)
        && !MACHINE.load(Ordering::Relaxed)
        && std::io::stdin().is_terminal()
        && screen_is_terminal()
}

/// The refusal a question turns into when nobody can answer it. `flag` is what carries the answer
/// instead -- an operator reading this in a CI log needs the argument, not an apology.
pub(crate) fn cannot_ask(what: &str, flag: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{what} has to be chosen, and this run cannot ask: pass {flag}. (A run asks only on a \
         terminal, and never with --non-interactive.)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// `REFUSED` and `MACHINE` are one pair of flags for the one process a command runs in. The
    /// suite runs its tests as threads of that same process, so two of these configuring at once
    /// each see the other's answer -- a race in the test harness, not in the client, and this is
    /// what keeps it out of the results.

    /// Measured before this existed, on bare `origin/dev`: run the two tests below together and
    /// `a_machine_run_never_asks` fails at its own assertion, because its neighbour's closing
    /// `configure(false, false)` lands between its `configure(false, true)` and its `assert`. A
    /// full run usually orders them apart, so the suite was green by luck; adding tests elsewhere
    /// changed the order and the mine went off. `progress.rs` guards its own shared slot the same
    /// way, for the same reason.
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    fn alone() -> std::sync::MutexGuard<'static, ()> {
        ONE_AT_A_TIME
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Under `cargo test` neither stream is a terminal, which is the same state a script is in: the
    /// answer must be no, with or without the flag.
    #[test]
    fn a_captured_run_never_asks() {
        let _alone = alone();
        configure(false, false);
        assert!(!may_ask());
        configure(true, false);
        assert!(!may_ask());
        configure(false, false);
    }

    /// A machine run never asks, whatever the streams say. It is the one case the terminal test
    /// cannot see: piping only stdout leaves stdin and stderr terminals.
    #[test]
    fn a_machine_run_never_asks() {
        let _alone = alone();
        configure(false, true);
        assert!(!may_ask());
        assert!(
            MACHINE.load(Ordering::Relaxed),
            "the flag has to be what decides it, not the captured streams this test runs under"
        );
        configure(false, false);
    }

    /// The refusal has to name the argument that replaces the question, or a CI log says only that
    /// something was impossible.
    #[test]
    fn the_refusal_names_the_flag_that_answers_it() {
        let refusal = cannot_ask("the note to spend from", "--note-addr").to_string();
        assert!(refusal.contains("--note-addr"), "{refusal}");
        assert!(refusal.contains("--non-interactive"), "{refusal}");
    }
}
