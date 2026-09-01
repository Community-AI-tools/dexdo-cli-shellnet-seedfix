//! a command's status display is its own, not the process's.

//! `progress::step` and the rest are free functions: they find the display of the command that is
//! running rather than being handed one, because the layers that call them -- a funding wait three
//! modules down from `note deploy` -- have nothing to do with displaying anything. What they find
//! it in used to be one slot for the whole process, which is a true description of the client and
//! a false one of this test binary, where 872 commands' worth of code runs in threads of a single
//! process. Whichever command registered last then answered for all of them, and the module's own
//! tests failed on it 47 times over 200 runs of the suite at `--test-threads=64`.

//! Declared here rather than inside `progress`, so that the regression is not carried away by a
//! revert of the module it guards.

use std::sync::{Arc, Barrier};

use crate::cli::progress::{lock, step, Status};

/// Two commands running at once each step their OWN display.

/// Both displays exist before either steps, which is the interleaving a per-process slot cannot
/// survive: the second registration covers the first, and the first command's step lands on the
/// second command's line. On one slot per thread each command finds what it built.
#[test]
fn two_displays_at_once_do_not_step_each_other() {
    // Both built before either steps. Without this the two lifetimes need not overlap at all, and
    // the test would pass on the very mechanism it is here to reject.
    let both_built = Arc::new(Barrier::new(2));
    let commands: Vec<_> = ["one", "two"]
        .into_iter()
        .map(|name| {
            let both_built = Arc::clone(&both_built);
            std::thread::spawn(move || {
                let status = Status::new(name);
                let shared = status.shared();
                both_built.wait();
                step(format!("{name} stepped"));
                let label = lock(&shared).label.clone();
                drop(status);
                label
            })
        })
        .collect();

    for (name, command) in ["one", "two"].into_iter().zip(commands) {
        let label = command.join().expect("the command thread must not panic");
        assert_eq!(
            label,
            format!("{name} stepped"),
            "the free step must reach the display this command built, not another command's"
        );
    }
}

/// A thread that built no display reaches none -- not somebody else's.

/// The free entry points are documented as silent when the running command has no display. On one
/// slot per process that silence was a lie the moment any other command in the process had one:
/// the step went to that command's line instead, which is how a `[1/3] checked` from one test
/// landed in the middle of another's output.
#[test]
fn a_thread_with_no_display_reaches_no_one_elses() {
    let display_built = Arc::new(Barrier::new(2));
    let step_attempted = Arc::new(Barrier::new(2));
    let holder = {
        let display_built = Arc::clone(&display_built);
        let step_attempted = Arc::clone(&step_attempted);
        std::thread::spawn(move || {
            let status = Status::new("held");
            let shared = status.shared();
            display_built.wait();
            step_attempted.wait();
            let label = lock(&shared).label.clone();
            drop(status);
            label
        })
    };

    display_built.wait();
    // This thread never built a display. Nothing it says may appear on a display that another
    // command is showing.
    step("from a thread with no display of its own");
    step_attempted.wait();

    let label = holder.join().expect("the holding thread must not panic");
    assert_eq!(
        label, "held",
        "a step from a thread with no display must go nowhere, not onto another command's line"
    );
}
