//! Build-time version stamp: embed the git short-SHA and the HEAD commit
//! timestamp into the binary so `dexdo --version` identifies the exact tree a build
//! came from -- instead of the bare `CARGO_PKG_VERSION`, which is identical across
//! every commit until someone hand-edits `Cargo.toml`.

//! There is deliberately no dirty-tree flag. The `rerun-if-changed` triggers below
//! are what keep the stamp fresh and they are scoped to this package, while
//! `git status` answers for the whole repository -- so an edit that leaves HEAD
//! where it is (here or in another crate) does not re-run this script, and the
//! binary would name a clean commit it was not built from. The sha and the date
//! carry no such risk: HEAD moving is exactly what the triggers watch.

//! std-only and best-effort: outside a git checkout (a source tarball, a docker
//! image without `.git`, or with no `git` on PATH) every probe fails and we stamp
//! an explicit `unknown`, which distinguishes a no-provenance build from one built
//! cleanly from a tag rather than silently omitting the suffix.

use std::process::Command;

fn main() {
    // Re-run when HEAD moves (new commit, checkout, reset) so the stamp never goes
    // stale. `--absolute-git-dir` resolves the real dir even from a linked worktree.
    if let Some(git_dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        println!("cargo:rerun-if-changed={git_dir}/HEAD");
        println!("cargo:rerun-if-changed={git_dir}/logs/HEAD");
    }
    println!("cargo:rerun-if-changed=build.rs");

    let pkg = env!("CARGO_PKG_VERSION");
    let stamp = match git(&["rev-parse", "--short=8", "HEAD"]) {
        Some(sha) => match git(&["show", "-s", "--format=%cI", "HEAD"]) {
            Some(when) => format!("{pkg} ({sha}, {when})"),
            None => format!("{pkg} ({sha})"),
        },
        None => format!("{pkg} (unknown)"),
    };
    println!("cargo:rustc-env=DEXDO_LONG_VERSION={stamp}");
}

/// Run `git <args>` and return trimmed stdout, or `None` if git is absent, the
/// command fails, or the output is empty. Never panics: a build outside a git
/// checkout must still succeed.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}
