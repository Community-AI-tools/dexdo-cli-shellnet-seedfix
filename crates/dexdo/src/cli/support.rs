//! `dexdo` CLI helpers(backends, resolvers, deposit sizing, render), split out of `main.rs` (PR3,
//! move-only). Behavior-identical to the pre-split functions.

use crate::cli::args::*;
use anyhow::{bail, Result};
use dexdo_core::{
    deal_anomalies, per_model_breakdown, ChainBackend, DealAnomaly, DealRole, DobParams, LocalNote,
    MockChainBackend, ModelBreakdown, Note, NoteTree, ProtocolConsts, TreeSnapshot,
};
use std::path::PathBuf;
use std::sync::Arc;

/// The shell an operator pastes a printed command line into. dexdo ships for Linux, macOS **and**
/// Windows(`PLATFORMS.md`), and those do not share one quoting syntax, so a line is rendered for
/// the shell of the host that prints it instead of assuming POSIX everywhere.
/// `cmd.exe` is deliberately not a target and dexdo does not render for it: it has no quoting that
/// survives `%` expansion, and a process cannot tell which of the two Windows shells its output is
/// being read in. Windows therefore gets PowerShell syntax -- the default shell of a supported
/// Windows install, and the one `PLATFORMS.md` names.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum PastedShell {
    /// `sh`/`bash`/`zsh` on Linux and macOS: single quotes protect everything, and an embedded
    /// apostrophe is closed, escaped and reopened(`'\''`).
    Posix,
    /// Windows PowerShell / `pwsh`: single quotes protect everything, and an embedded apostrophe
    /// is **doubled**(`''`). The POSIX `'\''` sequence is not an escape here -- it would close
    /// the string and leave a stray backslash in the value.
    PowerShell,
}

impl PastedShell {
    /// The shell of the host running this binary, which is the shell its output is read in.
    pub(crate) fn host() -> Self {
        if cfg!(windows) {
            Self::PowerShell
        } else {
            Self::Posix
        }
    }

    /// `value` as exactly one argument of a command line for this shell. An operator pastes such a
    /// line into a shell, so an unquoted `/tmp/my notes/r.json` would arrive as two arguments and
    /// an unquoted `<pool>` would be a redirection the shell acts on before `dexdo` ever starts.
    pub(crate) fn quote(self, value: &str) -> String {
        match self {
            Self::Posix => format!("'{}'", value.replace('\'', "'\"'\"'")),
            Self::PowerShell => format!("'{}'", value.replace('\'', "''")),
        }
    }
}

/// A value the CLI drops into a command line it prints, quoted for the host's shell.
pub(crate) fn shell_arg(value: &str) -> String {
    PastedShell::host().quote(value)
}

/// Options a printed follow-up has to repeat because this run did **not** use the defaults:
/// an explicit `--contracts` manifest, or a `--deals-dir` a handle was resolved from. Without
/// them the follow-up parses and then reads a different deployment or fails to find the deal.
/// When the run used the defaults there is nothing to state -- the follow-up resolves the same way.
/// The result is prose appended *outside* the backticks that name a command, so none of it is
/// claimed to be a line to run.
pub(crate) fn stated_options(options: &[(&str, Option<&std::path::Path>)]) -> String {
    let stated: Vec<String> = options
        .iter()
        .filter_map(|(flag, path)| {
            path.map(|path| format!("{flag} {}", shell_arg(&path.display().to_string())))
        })
        .collect();
    if stated.is_empty() {
        String::new()
    } else {
        format!(", plus {}", stated.join(" and "))
    }
}

/// The actor note a settlement command needs *below* clap. Clap accepts `--note-addr` as
/// optional because most read-only commands do not need it; the handlers that move money do, and
/// enforce it here. Printed instructions are checked against these same functions, so a command
/// line the CLI hands an operator cannot omit an input its handler will demand.
#[cfg(any(feature = "shellnet", test))]
pub(crate) fn require_note_addr(
    identity: &IdentityArgs,
    command: &str,
    what: &str,
) -> Result<String> {
    identity
        .note_addr
        .clone()
        .ok_or_else(|| anyhow::anyhow!("{command}: --note-addr ({what}) is required"))
}

/// The owner key the same commands need below clap, for the same reason.
#[cfg(any(feature = "shellnet", test))]
pub(crate) fn require_note_key<'a>(
    identity: &'a IdentityArgs,
    command: &str,
    what: &str,
) -> Result<&'a std::path::Path> {
    identity
        .note_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("{command}: --note-key ({what}) is required"))
}

/// The `dexdo release-dispute` follow-up, as guidance rather than as an argv template.
/// This site knows the deal and the manifest this run resolved. It does **not** know the seller's
/// note address or owner key, and it must not invent them: a template such as
/// `--note-addr <seller-note>` is not argv at all -- a POSIX shell reads `<seller-note>` as an
/// input redirection and never hands that token to `dexdo`, so the line an operator pastes is not
/// the line that was printed. asks for a runnable line where one can be rendered and truthful
/// prose where one cannot; the seller's identity is not available here, so the command is named
/// and the inputs it needs are stated around it.
#[cfg(any(feature = "shellnet", test))]
pub(crate) fn release_dispute_guidance(
    token_contract: &str,
    contracts: Option<&std::path::Path>,
) -> String {
    let token_contract = dexdo_core::address::display_self_dapp(token_contract);
    format!(
        "the seller resolves it by running `dexdo release-dispute` with --token-contract {}, the \
         seller --note-addr and the seller --note-key{}",
        shell_arg(&token_contract),
        stated_options(&[("--contracts", contracts)])
    )
}

/// The `dexdo destroy` follow-up, as guidance for the same reason: `run_destroy` demands the
/// seller note and the seller owner key below clap, and neither is known where this is printed.
/// The note is named the way `run_destroy` names it(4.0.33 Task O): it identifies the operator,
/// it does not choose the payee -- the deal pays the `_sellerNote` it stored at construction.
#[cfg(any(feature = "shellnet", test))]
pub(crate) fn destroy_guidance(
    token_contract: &str,
    contracts: Option<&std::path::Path>,
) -> String {
    let token_contract = dexdo_core::address::display_self_dapp(token_contract);
    format!(
        "the seller closes it by running `dexdo destroy` with --token-contract {}, the seller \
         --note-addr (the seller note this deal belongs to) and the seller --note-key{}",
        shell_arg(&token_contract),
        stated_options(&[("--contracts", contracts)])
    )
}

/// Machinery shared by the guards. Two different things are checked with it: the source lint
/// in `main.rs`, which reads this crate's `.rs` files, and the argv checks next to each builder
/// that composes a command line, which read what the builder just rendered. Only the second kind
/// sees the values a user actually gets, which is why both exist.
#[cfg(test)]
pub(crate) mod printed_commands {
    use super::PastedShell;
    use clap::{CommandFactory, Parser};

    /// What one backticked `dexdo...` span is telling the reader.
    #[derive(PartialEq, Debug)]
    pub(crate) enum PrintedRun {
        /// It carries something beyond the command path -- a flag, a value, a placeholder -- so it
        /// is a line the reader is expected to run and the shipped parser must accept it.
        Invocation,
        /// It is exactly a command path, so it is prose naming a command.
        Reference,
        /// The command itself is filled in at run time, so there is no line here to check.
        Dynamic,
    }

    /// Where a span was found, which decides whether it may satisfy a coverage floor.
    /// Only `Literal` is text the **shipped binary** can print. `TestGated` is a string literal
    /// that exists solely inside a `#[cfg(test)]` item -- real text, compiled only into the test
    /// binary, so a test fixture must never stand in for production guidance that disappeared.
    /// `Commentary` is everything else(doc comments, identifiers); still worth checking, because
    /// clap builds `--help` out of doc comments, but not printable output either.
    /// `TestCommentary` is commentary inside a `#[cfg(test)]` item. It is split out because the
    /// one reason to check commentary at all -- clap turning a doc comment into `--help` -- cannot
    /// apply there: a `#[cfg(test)]` item builds no clap command, so nothing in it is printed by
    /// anything. Rejecting it made the guard report "the CLI prints..." about a `///` line
    /// describing a test, which is a false statement about its own subject; a guard with a known
    /// false-positive class trains people to route around it.
    #[derive(Clone, Copy, PartialEq, Debug)]
    pub(crate) enum Origin {
        Literal,
        TestGated,
        Commentary,
        TestCommentary,
    }

    /// One `dexdo...` span, with the source line and whether the binary can print it.
    pub(crate) struct Run {
        pub(crate) line: usize,
        pub(crate) text: String,
        pub(crate) origin: Origin,
    }

    /// Rust source reduced to what a reader of the output would see, keeping for every character
    /// its source line, whether it sits inside a string literal, and whether it sits inside an
    /// item that only the test binary compiles. Line continuations are closed up and `\n` becomes
    /// a space, so a message split over several source lines is recovered as the single line a
    /// user reads; char literals collapse to blanks so a stray quote or backtick inside one cannot
    /// pair with real text.
    #[derive(Default)]
    struct Flattened {
        text: Vec<char>,
        line: Vec<usize>,
        literal: Vec<bool>,
        test_gated: Vec<bool>,
    }

    impl Flattened {
        fn push(&mut self, c: char, line: usize, literal: bool, test_gated: bool) {
            self.text.push(c);
            self.line.push(line);
            self.literal.push(literal);
            self.test_gated.push(test_gated);
        }
    }

    enum Lex {
        Code,
        LineComment,
        BlockComment(usize),
        Str,
        RawStr(usize),
    }

    /// The comma-separated items of a `cfg` predicate list, ignoring commas nested in `(...)`.
    fn cfg_items(inner: &str) -> Vec<&str> {
        let (mut depth, mut start) = (0usize, 0usize);
        let mut items = Vec::new();
        for (index, c) in inner.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    items.push(&inner[start..index]);
                    start = index + 1;
                }
                _ => {}
            }
        }
        items.push(&inner[start..]);
        items
    }

    /// Whether a `cfg` attribute makes its item exist **only** in a test binary: `#[cfg(test)]`, or
    /// an `all(...)` that requires `test`. `#[cfg(any(feature = "shellnet", test))]` is not one of
    /// these -- it ships -- so it is deliberately not matched.
    fn is_test_only_cfg(attribute: &str) -> bool {
        let compact: String = attribute.chars().filter(|c| !c.is_whitespace()).collect();
        let Some(predicate) = compact
            .strip_prefix("#[cfg(")
            .and_then(|rest| rest.strip_suffix(")]"))
        else {
            return false;
        };
        if predicate == "test" {
            return true;
        }
        predicate
            .strip_prefix("all(")
            .and_then(|rest| rest.strip_suffix(')'))
            .is_some_and(|inner| cfg_items(inner).iter().any(|item| *item == "test"))
    }

    /// The `#[cfg(...)]` attribute starting at `index`, if there is one. Attributes in this tree
    /// never contain a `)` immediately followed by `]` inside the predicate, so the first `)]` is
    /// the end.
    fn cfg_attribute_at(src: &[char], index: usize) -> Option<String> {
        let head: String = src.iter().skip(index).take(6).collect();
        if head != "#[cfg(" {
            return None;
        }
        let mut end = index + 6;
        while end + 1 < src.len() {
            if src[end] == ')' && src[end + 1] == ']' {
                return Some(src[index..=end + 1].iter().collect());
            }
            end += 1;
        }
        None
    }

    fn flatten(raw: &str) -> Flattened {
        let src: Vec<char> = raw.chars().collect();
        let mut out = Flattened::default();
        let mut lex = Lex::Code;
        let mut line = 1usize;
        let mut i = 0usize;
        // `#[cfg(test)]` region tracking, in code only: the attribute arms `pending`, the item's
        // opening brace records the depth it was opened at, and the matching closing brace ends
        // the region. An attribute on a braceless item (`#[cfg(test)] use x;`) is disarmed by its
        // `;`. A nested `#[cfg(test)]` inside a region is ignored so the inner item's closing
        // brace cannot end the outer region early.
        let (mut brace_depth, mut pending_test, mut test_depth) = (0usize, false, None::<usize>);
        while i < src.len() {
            let c = src[i];
            let next = src.get(i + 1).copied();
            let mut gated = test_depth.is_some();
            match lex {
                Lex::Code => {
                    match c {
                        '{' => {
                            brace_depth += 1;
                            if pending_test {
                                pending_test = false;
                                test_depth = Some(brace_depth - 1);
                            }
                        }
                        '}' => {
                            brace_depth = brace_depth.saturating_sub(1);
                            if test_depth.is_some_and(|depth| brace_depth <= depth) {
                                test_depth = None;
                            }
                        }
                        ';' => pending_test = false,
                        '#' if test_depth.is_none() => {
                            if let Some(attribute) = cfg_attribute_at(&src, i) {
                                pending_test = is_test_only_cfg(&attribute);
                            }
                        }
                        _ => {}
                    }
                    gated = test_depth.is_some();
                    if c == '/' && next == Some('/') {
                        lex = Lex::LineComment;
                    } else if c == '/' && next == Some('*') {
                        lex = Lex::BlockComment(1);
                        out.push(c, line, false, gated);
                        out.push('*', line, false, gated);
                        i += 2;
                        continue;
                    } else if c == '"' {
                        lex = Lex::Str;
                        out.push(c, line, false, gated);
                        i += 1;
                        continue;
                    } else if c == 'r' && matches!(next, Some('"') | Some('#')) {
                        let mut hashes = 0usize;
                        let mut j = i + 1;
                        while src.get(j) == Some(&'#') {
                            hashes += 1;
                            j += 1;
                        }
                        if src.get(j) == Some(&'"') {
                            for _ in i..=j {
                                out.push(' ', line, false, gated);
                            }
                            lex = Lex::RawStr(hashes);
                            i = j + 1;
                            continue;
                        }
                    } else if c == '\'' {
                        // A char literal(`'a'`, `'\''`, `'"'`) collapses to blanks; a lifetime is
                        // an ordinary character.
                        let width = if next == Some('\\') {
                            src.iter()
                                .skip(i + 2)
                                .position(|&c| c == '\'')
                                .map(|p| p + 3)
                        } else if src.get(i + 2) == Some(&'\'') {
                            Some(3)
                        } else {
                            None
                        };
                        if let Some(width) = width {
                            for _ in 0..width {
                                out.push(' ', line, false, gated);
                            }
                            i += width;
                            continue;
                        }
                    }
                }
                Lex::LineComment => {
                    if c == '\n' {
                        lex = Lex::Code;
                    }
                }
                Lex::BlockComment(depth) => {
                    if c == '/' && next == Some('*') {
                        lex = Lex::BlockComment(depth + 1);
                        out.push(c, line, false, gated);
                        out.push('*', line, false, gated);
                        i += 2;
                        continue;
                    }
                    if c == '*' && next == Some('/') {
                        lex = if depth == 1 {
                            Lex::Code
                        } else {
                            Lex::BlockComment(depth - 1)
                        };
                        out.push(c, line, false, gated);
                        out.push('/', line, false, gated);
                        i += 2;
                        continue;
                    }
                }
                Lex::Str => {
                    if c == '\\' {
                        match next {
                            Some('\n') => {
                                i += 2;
                                line += 1;
                                while matches!(src.get(i), Some(' ') | Some('\t')) {
                                    i += 1;
                                }
                                continue;
                            }
                            Some('n') => {
                                out.push(' ', line, true, gated);
                                i += 2;
                                continue;
                            }
                            Some(escaped) => {
                                out.push(c, line, true, gated);
                                out.push(escaped, line, true, gated);
                                i += 2;
                                continue;
                            }
                            None => {}
                        }
                    }
                    if c == '"' {
                        lex = Lex::Code;
                        out.push(c, line, false, gated);
                        i += 1;
                        continue;
                    }
                }
                Lex::RawStr(hashes) => {
                    if c == '"' && (0..hashes).all(|offset| src.get(i + 1 + offset) == Some(&'#')) {
                        lex = Lex::Code;
                        for _ in 0..=hashes {
                            out.push(' ', line, false, gated);
                        }
                        i += hashes + 1;
                        continue;
                    }
                }
            }
            out.push(c, line, matches!(lex, Lex::Str | Lex::RawStr(_)), gated);
            if c == '\n' {
                line += 1;
            }
            i += 1;
        }
        out
    }

    /// The CLI's top-level subcommand names, read off the shipped parser.
    pub(crate) fn top_level_subcommands() -> Vec<String> {
        crate::Cli::command()
            .get_subcommands()
            .map(|sub| sub.get_name().to_string())
            .collect()
    }

    /// The command spans a text hands the reader in backticks -- the convention every message,
    /// error and help string in this tree follows to say "this is the command". A span that drops
    /// the binary name but names a subcommand and a flag counts too: the reader still types it.
    pub(crate) fn runs(raw: &str, subcommands: &[String]) -> Vec<Run> {
        let flat = flatten(raw);
        let text = &flat.text;
        let mut found = Vec::new();
        let mut index = 0usize;
        while index < text.len() {
            if text[index] != '`' {
                index += 1;
                continue;
            }
            let start = index + 1;
            let mut end = start;
            while end < text.len() && text[end] != '`' && text[end] != '\n' {
                end += 1;
            }
            if end >= text.len() || text[end] != '`' {
                index = start;
                continue;
            }
            let span: String = text[start..end].iter().collect();
            let argv: Vec<&str> = span.split_whitespace().collect();
            let named_binary = span.starts_with("dexdo ");
            let named_subcommand_and_flag = argv
                .first()
                .is_some_and(|head| subcommands.iter().any(|name| name == head))
                && argv.iter().any(|token| token.starts_with("--"));
            if named_binary || named_subcommand_and_flag {
                found.push(Run {
                    line: flat.line[start],
                    origin: match (flat.literal[start], flat.test_gated[start]) {
                        (true, false) => Origin::Literal,
                        (true, true) => Origin::TestGated,
                        (false, false) => Origin::Commentary,
                        (false, true) => Origin::TestCommentary,
                    },
                    text: span,
                });
            }
            index = end + 1;
        }
        found
    }

    /// A bare command name -- not a placeholder such as `{path}` or `<pool>`, not a flag.
    fn is_plain_command_name(token: &str) -> bool {
        !token.is_empty()
            && !token.starts_with('-')
            && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    }

    /// How many leading tokens of `argv`(after the binary name) are subcommand names.
    fn command_path_len(argv: &[&str]) -> usize {
        let mut command = crate::Cli::command();
        let mut depth = 0usize;
        for token in argv.iter().skip(1) {
            if command.get_subcommands().next().is_none() || !is_plain_command_name(token) {
                break;
            }
            match command.find_subcommand(token).cloned() {
                Some(next) => {
                    command = next;
                    depth += 1;
                }
                None => break,
            }
        }
        depth
    }

    /// Judge one command line against the shipped parser. Anything carrying more than the command
    /// path is a line to run and must parse -- including a command whose only argument is a
    /// positional, which is why this does not look for flags. A line that left the binary name
    /// implicit is judged as the reader would have to type it.
    /// A token standing in for a value the operator substitutes: `{path}` in a format string, or a
    /// `<name>` that reached here **quoted**, so the shell delivered it as a single argument. An
    /// *unquoted* `<name>` never gets this far -- `shell_split` rejects it as the redirection a
    /// shell actually makes of it -- which is why this may treat what it sees as a value.
    fn is_placeholder(token: &str) -> bool {
        (token.starts_with('{') && token.ends_with('}'))
            || (token.starts_with('<') && token.ends_with('>'))
    }

    fn classify_argv(argv: &[String]) -> Result<PrintedRun, String> {
        let mut written: Vec<&str> = argv.iter().map(String::as_str).collect();
        if written.first() != Some(&"dexdo") {
            written.insert(0, "dexdo");
        }
        let Some(head) = written.get(1) else {
            return Err("names no subcommand at all".to_string());
        };
        if !is_plain_command_name(head) {
            return Ok(PrintedRun::Dynamic);
        }
        // A placeholder stands for a value, so it is checked as one: `1` is accepted by every
        // argument type the CLI uses(numbers, strings, paths), which keeps the check on the
        // *shape* of the line -- does it carry the arguments the parser demands -- rather than on
        // the placeholder text. The values themselves are only meaningful once a builder has
        // filled them in, which is what the emitted-argv checks next to each builder cover.
        let substituted: Vec<String> = written
            .iter()
            .map(|token| {
                if is_placeholder(token) {
                    "1".to_string()
                } else {
                    (*token).to_string()
                }
            })
            .collect();
        let typed: Vec<&str> = substituted.iter().map(String::as_str).collect();
        let depth = command_path_len(&typed);
        if depth == 0 {
            return Err(format!(
                "names `{head}`, which is not a subcommand of this CLI"
            ));
        }
        if typed.len() == depth + 1 {
            return Ok(PrintedRun::Reference);
        }
        match crate::Cli::try_parse_from(&typed) {
            Ok(_) => Ok(PrintedRun::Invocation),
            Err(err) => Err(format!(
                "carries arguments, so it reads as a line to run, and the shipped parser rejects \
                 it: {err}"
            )),
        }
    }

    /// The same judgement on a span as written -- but split the way the operator's shell splits
    /// it, not on whitespace. Routing the source lint through `shell_split` is what makes it see
    /// the defect is about: `--note-key <buyer-key>` is not the argv it looks like, because a
    /// POSIX shell consumes `<buyer-key>` as a redirection before `dexdo` ever runs. Splitting on
    /// whitespace hid exactly that, by handing `classify_argv` a token no shell delivers -- so a
    /// printed template passed the lint and then failed for the operator. There is one rule in
    /// this module for what a shell does with a printed line, and both the source lint and the
    /// emitted-argv check are answerable to it.
    pub(crate) fn classify(span: &str) -> Result<PrintedRun, String> {
        classify_in(PastedShell::host(), span)
    }

    fn classify_in(shell: PastedShell, span: &str) -> Result<PrintedRun, String> {
        classify_argv(&shell_split_in(shell, span)?)
    }

    /// Characters a POSIX shell acts on *before* the command runs when they are not quoted:
    /// redirections, list/pipeline operators, subshells and expansions. An emitted line containing
    /// any of them unquoted does not reach `dexdo` as the argv that was printed -- `<seller-note>`
    /// is the redirection `< seller-note`, not an argument -- so splitting it into argv would prove
    /// a command the operator never runs.
    /// Characters a POSIX shell acts on *before* the command runs, which this model refuses rather
    /// than approximates: subshells, expansions and line continuations. Redirections and list
    /// operators are **not** here -- they are structure a real command line is allowed to have, and
    /// are interpreted below instead of rejected.
    const POSIX_REFUSED: &[char] = &['(', ')', '$', '`', '\\', '\n'];

    /// Operators that redirect a stream. Each takes the word after it as its target, and neither
    /// the operator nor the target is part of the command's argv.
    const POSIX_REDIRECTIONS: &[&str] = &[">>", "<<", "<>", ">|", "<", ">"];

    /// Operators that end this command and begin another. Everything after one belongs to a
    /// different command, so the argv being judged is what came before it.
    const POSIX_LIST_OPERATORS: &[&str] = &["||", "&&", "|", ";", "&"];

    /// One lexed piece of a command line.
    enum Tok {
        /// A word, with quotes already removed.
        Word(String),
        /// An operator, and whether whitespace separated it from what came before. `2>` is a file
        /// descriptor bound to the redirection; `1 >` is the argument `1` and then a redirection,
        /// and only the gap tells them apart.
        Op(&'static str, bool),
    }

    /// Split a rendered command line into the argv a POSIX shell would build from it. This is the
    /// only way a quoting mistake in an emitted path is visible to a test, so it is deliberately
    /// **fail-closed**: an unmatched quote is an error here, exactly as `bash -n` rejects one.
    /// Redirections and pipelines are *structure*, not defects. A `dexdo note deploy` line that
    /// ends by sending its output to a file is normal, correct usage, and a guard that rejected it
    /// would be wrong about what a command line is; the argv is the command, and the shell keeps
    /// the rest. So the operator and its target are interpreted and dropped, and a list operator
    /// ends the argv being judged.
    /// That does **not** soften the check an angle-bracket template fails, because a real shell
    /// does not soften it either. `dexdo executable-book` followed by an angle-bracketed model
    /// placeholder lexes as an input redirection whose target is the placeholder text, and then a
    /// closing angle bracket with no target at all, which `/bin/sh -n` rejects outright -- so it is
    /// still an error here, now for the reason the shell actually gives rather than a blanket ban
    /// on the character.
    /// `shell_split` models the host shell. Tests that need to prove another supported shell can
    /// select it explicitly through `shell_split_in`.
    pub(crate) fn shell_split(line: &str) -> Result<Vec<String>, String> {
        shell_split_in(PastedShell::host(), line)
    }

    pub(crate) fn shell_split_in(
        shell: PastedShell,
        line: &str,
    ) -> Result<Vec<String>, String> {
        let toks = shell_lex(shell, line)?;
        let mut argv: Vec<String> = Vec::new();
        let mut index = 0usize;
        while index < toks.len() {
            match &toks[index] {
                Tok::Word(word) => {
                    argv.push(word.clone());
                    index += 1;
                }
                Tok::Op(op, _) if POSIX_LIST_OPERATORS.contains(op) => break,
                Tok::Op(op, spaced) => {
                    // A file descriptor written directly against the operator(`2>`) belongs to the
                    // redirection, not to the argv. What decides that is the gap between the word
                    // and the operator, not the gap before the word: `--nominal 1 2> log` passes
                    // `1` to the command and redirects fd 2.
                    if !spaced {
                        if let Some(fd) = argv.last() {
                            if !fd.is_empty() && fd.chars().all(|c| c.is_ascii_digit()) {
                                argv.pop();
                            }
                        }
                    }
                    match toks.get(index + 1) {
                        Some(Tok::Word(_)) => index += 2,
                        _ => {
                            return Err(format!(
                                "unquoted `{op}` is a shell operator with no target, so the shell \
                                 rejects this line before the command runs and it is not the argv \
                                 it appears to be: {line}"
                            ))
                        }
                    }
                }
            }
        }
        Ok(argv)
    }

    /// Words and operators of one command line, with quotes removed.
    fn shell_lex(shell: PastedShell, line: &str) -> Result<Vec<Tok>, String> {
        let chars: Vec<char> = line.chars().collect();
        let mut toks = Vec::new();
        let mut current = String::new();
        let (mut single, mut double, mut started) = (false, false, false);
        let mut index = 0usize;
        let flush = |current: &mut String, started: &mut bool, toks: &mut Vec<Tok>| {
            if *started {
                toks.push(Tok::Word(std::mem::take(current)));
                *started = false;
            }
        };
        while index < chars.len() {
            let c = chars[index];
            if c == '\'' && !double {
                if single
                    && shell == PastedShell::PowerShell
                    && chars.get(index + 1) == Some(&'\'')
                {
                    current.push('\'');
                    started = true;
                    index += 2;
                    continue;
                }
                single = !single;
                started = true;
                index += 1;
                continue;
            }
            if c == '"' && !single {
                double = !double;
                started = true;
                index += 1;
                continue;
            }
            if !single && !double {
                if POSIX_REFUSED.contains(&c) {
                    return Err(format!(
                        "unquoted `{c}` is a shell operator, so the shell acts on it before the \
                         command runs and this line is not the argv it appears to be: {line}"
                    ));
                }
                if c == '#' && !started {
                    return Err(format!(
                        "unquoted `#` starts a shell comment, so the rest of this line never \
                         reaches the command: {line}"
                    ));
                }
                if let Some(op) = POSIX_REDIRECTIONS
                    .iter()
                    .chain(POSIX_LIST_OPERATORS.iter())
                    .find(|op| chars[index..].starts_with(&op.chars().collect::<Vec<_>>()[..]))
                {
                    // The operator is "spaced" when nothing of a word ran into it.
                    let adjacent = started;
                    flush(&mut current, &mut started, &mut toks);
                    toks.push(Tok::Op(op, !adjacent));
                    index += op.chars().count();
                    continue;
                }
                if c.is_whitespace() {
                    flush(&mut current, &mut started, &mut toks);
                    index += 1;
                    continue;
                }
            }
            current.push(c);
            started = true;
            index += 1;
        }
        if single || double {
            return Err(format!(
                "unmatched {} quote, which a shell rejects outright: {line}",
                if single { "single" } else { "double" }
            ));
        }
        flush(&mut current, &mut started, &mut toks);
        Ok(toks)
    }

    /// The argv a **real** shell builds from `line`, obtained by defining a shell function named
    /// `dexdo` that echoes what it was actually handed and then letting the shell parse and run
    /// the line. This is the check `shell_split` cannot be: it is the operator's own shell doing
    /// quote removal, word splitting and redirection, so a line that only *looks* runnable fails
    /// here. `Err` is what the operator would see instead of the command running.
    /// Each supported platform is probed in the shell `PastedShell::host()` renders for, so a
    /// Linux/macOS run exercises `/bin/sh` and a Windows run exercises PowerShell. The returned
    /// argv includes the command name, so it lines up with `shell_split`.
    #[cfg(unix)]
    pub(crate) fn host_shell_argv(line: &str) -> Result<Vec<String>, String> {
        // `printf '%s\0'` keeps an argument containing spaces or a newline distinguishable.
        let script = format!("dexdo() {{ printf '%s\\0' dexdo \"$@\"; }}\n{line}\n");
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .output()
            .map_err(|e| format!("run /bin/sh: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "the shell refused the line before `dexdo` ran (status {:?}): {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let stdout = String::from_utf8(output.stdout).map_err(|e| format!("shell output: {e}"))?;
        let mut argv: Vec<String> = stdout.split('\0').map(str::to_string).collect();
        argv.pop(); // the empty piece after the trailing NUL
        Ok(argv)
    }

    /// The Windows half of the same probe: PowerShell is the shell `PastedShell::PowerShell`
    /// renders for. Arguments are separated by newlines rather than NULs, which is sound because
    /// no line this CLI emits carries a newline inside an argument.
    #[cfg(windows)]
    pub(crate) fn host_shell_argv(line: &str) -> Result<Vec<String>, String> {
        let script =
            format!("function dexdo {{ 'dexdo'; foreach ($a in $args) {{ $a }} }}\r\n{line}\r\n");
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .map_err(|e| format!("run powershell.exe: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "the shell refused the line before `dexdo` ran (status {:?}): {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let stdout = String::from_utf8(output.stdout).map_err(|e| format!("shell output: {e}"))?;
        Ok(stdout
            .lines()
            .map(|piece| piece.trim_end_matches('\r').to_string())
            .collect())
    }

    /// Beyond clap: the inputs a handler demands *after* parsing, for the commands whose
    /// printed lines this crate composes. Every rule here is the handler's own function, not a
    /// restatement of it, so a printed line cannot satisfy this check and then fail for the
    /// operator. Commands whose handlers were not read are checked at the parser level only --
    /// stated rather than silently assumed.
    fn assert_handler_requirements(argv: &[String], context: &str, raw_close_target: bool) {
        use super::{require_note_addr, require_note_key};
        // Fail-closed: a parse failure here is not "someone else's report", it is a printed line
        // that does not reach its handler at all.
        let parsed = crate::Cli::try_parse_from(argv)
            .unwrap_or_else(|e| panic!("{context}: the shipped parser rejects {argv:?}: {e}"));
        match parsed.command {
            crate::Command::Close(args) => {
                assert!(
                    args.note_key.is_some(),
                    "{context}: `close` signs with the note owner key: {argv:?}"
                );
                // A stored handle carries the role and note; a raw TokenContract does not, so the
                // caller states which mode it rendered rather than this guessing from the string.
                if raw_close_target {
                    crate::cli::commands::require_close_target_identity(
                        &args.deal,
                        // `require_close_target_identity` is generic over the role, so the
                        // handler's own rule is applied to the `--role` clap parsed, without
                        // widening a production mapper's visibility for this check.
                        args.role,
                        args.note_addr.as_deref(),
                    )
                    .unwrap_or_else(|e| panic!("{context}: {e}: {argv:?}"));
                }
            }
            crate::Command::ReleaseDispute(args) => {
                require_note_addr(&args.identity, "release-dispute", "seller note")
                    .unwrap_or_else(|e| panic!("{context}: {e}: {argv:?}"));
                require_note_key(&args.identity, "release-dispute", "seller owner key")
                    .unwrap_or_else(|e| panic!("{context}: {e}: {argv:?}"));
            }
            crate::Command::WithdrawShell(args) => {
                require_note_addr(&args.identity, "withdraw-shell", "seller note")
                    .unwrap_or_else(|e| panic!("{context}: {e}: {argv:?}"));
                require_note_key(&args.identity, "withdraw-shell", "seller owner key")
                    .unwrap_or_else(|e| panic!("{context}: {e}: {argv:?}"));
            }
            crate::Command::Destroy(args) => {
                require_note_addr(&args.identity, "destroy", "seller note = payout")
                    .unwrap_or_else(|e| panic!("{context}: {e}: {argv:?}"));
                require_note_key(&args.identity, "destroy", "seller owner key")
                    .unwrap_or_else(|e| panic!("{context}: {e}: {argv:?}"));
            }
            _ => {}
        }
    }

    /// The argv guarantee, asserted on what a builder just rendered rather than on a source
    /// literal: every command span in `rendered` must be a **runnable invocation** -- it survives a
    /// shell as the argv that was printed, the shipped parser accepts it, and its handler's own
    /// below-clap requirements are met.
    /// Fail-closed in three ways, because each hole let a regressed builder pass silently before:
    /// no span at all is a failure, a `Reference` or `Dynamic` span is a failure (a builder that
    /// decayed to a bare `dexdo close` is not a runnable line), and a shell that refuses the line
    /// is a failure rather than a fallback to a synthetic split. Use
    /// `assert_emitted_commands_name_only` for guidance that deliberately names a command instead
    /// of handing over a line to run.
    pub(crate) fn assert_emitted_commands_parse(
        rendered: &str,
        context: &str,
        raw_close_target: bool,
    ) {
        assert_emitted_commands_parse_in(
            PastedShell::host(),
            rendered,
            context,
            raw_close_target,
        )
    }

    fn assert_emitted_commands_parse_in(
        shell: PastedShell,
        rendered: &str,
        context: &str,
        raw_close_target: bool,
    ) {
        let subcommands = top_level_subcommands();
        let found = runs(rendered, &subcommands);
        assert!(
            !found.is_empty(),
            "{context}: no command line found to check in:\n{rendered}"
        );
        for run in found {
            let argv = shell_split_in(shell, &run.text).unwrap_or_else(|why| {
                panic!(
                    "{context}: the CLI prints a line a shell does not hand to the command:\n  \
                     {}\n{why}",
                    run.text
                )
            });
            match classify_argv(&argv) {
                Ok(PrintedRun::Invocation) => {}
                Ok(other) => panic!(
                    "{context}: this site claims to emit a runnable line, but the span is \
                     {other:?}, not an invocation:\n  {}\nargv a shell would build: {argv:?}",
                    run.text
                ),
                Err(why) => panic!(
                    "{context}: the CLI prints a command line the shell and the parser disagree \
                     about:\n  {}\nargv a shell would build: {argv:?}\n{why}",
                    run.text
                ),
            }
            // The operator's own shell has the final say on what argv the printed line becomes.
            // Only a span that names the binary can be handed to the probe function; a span that
            // left `dexdo` implicit is judged by the parser alone.
            #[cfg(any(unix, windows))]
            if run.text.starts_with("dexdo ") {
                let real = host_shell_argv(&run.text).unwrap_or_else(|why| {
                    panic!(
                        "{context}: the host shell does not deliver this printed line:\n  {}\n{why}",
                        run.text
                    )
                });
                assert_eq!(
                    real, argv,
                    "{context}: the argv the host shell builds differs from the argv this line \
                     appears to carry:\n  {}",
                    run.text
                );
            }
            // Parsing is necessary and not sufficient: identity is enforced below clap.
            let substituted: Vec<String> = argv
                .iter()
                .map(|token| {
                    if is_placeholder(token) {
                        "0:0000000000000000000000000000000000000000000000000000000000000001"
                            .to_string()
                    } else {
                        token.clone()
                    }
                })
                .collect();
            assert_handler_requirements(&substituted, context, raw_close_target);
        }
    }

    /// The counterpart guarantee for guidance that deliberately does **not** hand over a line to
    /// run: every command span in `rendered` must be exactly a command path -- prose naming a
    /// command, with the inputs stated around it in text a shell never sees. This is what a site
    /// that does not hold the seller note, the owner key or the funding wallet must emit under
    /// and asserting it is what stops such a site from quietly growing an argv template
    /// again: an added `--note-addr <seller-note>` makes the span an `Invocation` and fails here.
    /// Naming the command is only half of the guarantee, and on its own it is the weaker half: a
    /// bare command name that does not say what the operator has to supply is not guidance, it is
    /// a dead end. So `required_inputs` are the things this particular site is claiming to state --
    /// the `--note-key` its handler demands below clap, the `--contracts` manifest this run
    /// resolved -- and each must literally appear in the prose. That is what stops a site from
    /// silently dropping "the seller `--note-addr` / `--note-key`" and still passing, and it is
    /// enforced here rather than at each call site so a call site added later cannot forget it.
    pub(crate) fn assert_emitted_commands_name_only(
        rendered: &str,
        context: &str,
        required_inputs: &[&str],
    ) {
        let subcommands = top_level_subcommands();
        let found = runs(rendered, &subcommands);
        assert!(
            !found.is_empty(),
            "{context}: no command span found to check in:\n{rendered}"
        );
        for input in required_inputs {
            assert!(
                rendered.contains(input),
                "{context}: this guidance names a command the operator cannot complete without \
                 `{input}`, and does not state it:\n{rendered}"
            );
        }
        for run in found {
            match classify(&run.text) {
                Ok(PrintedRun::Reference) => {}
                Ok(other) => panic!(
                    "{context}: this guidance names a command it cannot complete, so the span must \
                     be a command path, not {other:?}:\n  `{}`\nin:\n{rendered}",
                    run.text
                ),
                Err(why) => panic!(
                    "{context}: the CLI names a command that is not this CLI's:\n  `{}`\n{why}",
                    run.text
                ),
            }
        }
    }
}

#[cfg(test)]
#[path = "shell_split_host_aware_tests.rs"]
mod shell_split_host_aware_tests;

/// Load the identity's **note tree** from `--note-key`. dexdo only **reads** the key,
/// never writes or rotates it. No path -> an ephemeral tree(degenerate to a single note) with
/// a warning(mock-demo). An invalid/inaccessible path is an explicit failure, not a silent `generate()`.
pub(crate) fn load_note_tree(note_key: Option<&std::path::Path>) -> Result<NoteTree> {
    match note_key {
        Some(path) => {
            let hex = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("read --note-key {}: {e}", path.display()))?;
            NoteTree::from_secret_hex(&hex)
                .map_err(|e| anyhow::anyhow!("parse --note-key {}: {e}", path.display()))
        }
        None => {
            tracing::warn!(
                "ephemeral note (no --note-key): identity will NOT persist between runs -- \
                 mock-demo only. Production path: set --note-key <path>."
            );
            Ok(NoteTree::new(LocalNote::generate()))
        }
    }
}

/// Load the specific identity(sub)note(tree + index from `--note-index`) that
/// `seller`/`buyer` operates on. Index outside the tree -> explicit failure.
pub(crate) fn load_note_identity(identity: &IdentityArgs) -> Result<LocalNote> {
    let tree = load_note_tree(identity.note_key.as_deref())?;
    tree.node(identity.note_index).ok_or_else(|| {
        anyhow::anyhow!(
            "--note-index {} outside the tree (an ephemeral note has only index 0)",
            identity.note_index
        )
    })
}

/// Chain backend + note, selected by `--mock-chain`/the `shellnet` feature. Behind the common
/// `ChainBackend`/`Note` trait the `seller`/`buyer` flow does not depend on the choice -- only construction changes.
pub(crate) type ChainAndNote = (Arc<dyn ChainBackend>, Arc<dyn Note>);

/// Mock backend + a loaded(or ephemeral) `LocalNote` -- the standard mock path.
pub(crate) fn mock_chain_and_note(
    endpoints_file: PathBuf,
    identity: &IdentityArgs,
) -> Result<ChainAndNote> {
    let chain: Arc<dyn ChainBackend> = Arc::new(MockChainBackend::new(
        endpoints_file,
        ProtocolConsts::canonical(),
        DobParams::canonical(),
    ));
    let note: Arc<dyn Note> = Arc::new(load_note_identity(identity)?);
    Ok((chain, note))
}

/// Read the key's hex secret from a file. The contents are **not logged**(secret).
#[cfg(feature = "shellnet")]
pub(crate) fn read_secret_hex(path: &std::path::Path, what: &str) -> Result<String> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read {what} {}: {e}", path.display()))?;
    let s = s.trim().to_string();
    if s.is_empty() {
        bail!("{what} {} is empty", path.display());
    }
    Ok(s)
}

/// Real seller backend + the seller's `RealNote`: from the `--note-key` seed + `--note-addr` (the
/// mint-specific address of the provisioned note) and `model_hash` from `--model`. Directive: the note
/// self-funds deploy gas from ECC[2] and its bond from the balance record -- no operator wallet.
#[cfg(feature = "shellnet")]
pub(crate) fn seller_real_backend_with_deal_gas_overhead(
    args: &SellerArgs,
    market_frame_model: Option<&str>,
    market_nonce: Option<u64>,
    registry_frame_model: Option<&str>,
    deal_gas_overhead_raw: Option<u128>,
) -> Result<ChainAndNote> {
    let name = args
        .model
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("real shellnet: set --model <name from config> (needed for model_hash)")
        })?;
    let configured_frame_model = dexdo::seller::ModelsConfig::load(&args.models)?
        .get(name)?
        .frame_model
        .clone();
    let frame_model = registry_frame_model.unwrap_or(&configured_frame_model);
    if registry_frame_model.is_none() {
        // Without registry authority, preserve the legacy canonical market shape.
        dexdo_core::validate_canonical_model_id(frame_model).map_err(|e| anyhow::anyhow!(e))?;
    }
    check_market_model_match(market_frame_model, frame_model, name)?;
    let note_addr = args.identity.note_addr.clone().ok_or_else(|| {
        anyhow::anyhow!("real shellnet: --note-addr (provisioned note address) is required")
    })?;
    let note_key =
        args.identity.note_key.as_deref().ok_or_else(|| {
            anyhow::anyhow!("real shellnet: --note-key (note root seed) is required")
        })?;
    let manifest = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    // Review: the deal nonce binds the offer to the canonical per-deal TokenContract. The IOB
    // rejects any offer whose `tokenContract` does not derive from `(sellerPubkey, nonce)`, so the
    // real seller MUST have it -- from `--market`(manifest) or the explicit `--nonce` flag.
    let nonce = market_nonce.ok_or_else(|| {
        anyhow::anyhow!(
            "real shellnet: pass --nonce <n> (or --market <manifest>) -- the deal nonce binds the \
             offer to the canonical TokenContract (IOB rejects a mismatched tokenContract)"
        )
    })?;
    let (backend, rn) = dexdo_core::RealSellerBackend::from_provisioned_with_deal_gas_overhead(
        manifest,
        &note_addr,
        &read_secret_hex(note_key, "--note-key")?,
        frame_model,
        nonce,
        deal_gas_overhead_raw,
    )?;
    let chain: Arc<dyn ChainBackend> = Arc::new(backend);
    let note: Arc<dyn Note> = Arc::new(rn);
    Ok((chain, note))
}

#[cfg(feature = "shellnet")]
pub(crate) async fn provision_replacement_seller_with_deal_gas_overhead(
    args: &SellerArgs,
    frame_model: &str,
    nonce: u64,
    price_per_tick: u64,
    max_ticks: u64,
    supplied_deal_gas_overhead_raw: Option<u128>,
) -> Result<(dexdo_core::MarketManifest, Arc<dyn ChainBackend>)> {
    use dexdo_core::{KeyPair, RealChainBackend, RealSellerBackend, TICK_SIZE};

    let note_addr = args.identity.note_addr.as_deref().ok_or_else(|| {
        anyhow::anyhow!("real shellnet: --note-addr is required for residual provisioning")
    })?;
    let note_key = args.identity.note_key.as_deref().ok_or_else(|| {
        anyhow::anyhow!("real shellnet: --note-key is required for residual provisioning")
    })?;
    let manifest_path = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let secret = read_secret_hex(note_key, "--note-key")?;
    let chain = RealChainBackend::connect(manifest_path)?;
    let deal_gas_overhead_raw = dexdo_core::params::resolve_deal_gas_overhead_raw(
        chain.network(),
        supplied_deal_gas_overhead_raw,
    )
    .map_err(anyhow::Error::msg)?;
    let keys = KeyPair::from_secret_hex(secret.trim())
        .map_err(|e| anyhow::anyhow!("--note-key (SDK secret hex): {e:?}"))?;
    let note = dexdo_core::address::parse_chain_address(note_addr)
        .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
    let max_ticks = u128::from(max_ticks);
    let deposit_shells = if supplied_deal_gas_overhead_raw.is_none() {
        default_deposit_shells(max_ticks)
    } else {
        dexdo_core::params::min_deploy_shells_with_overhead(max_ticks, deal_gas_overhead_raw)
    };
    let per_deploy = if supplied_deal_gas_overhead_raw.is_none() {
        deposit_per_deploy(deposit_shells, max_ticks)?
    } else {
        deposit_per_deploy_with_overhead(deposit_shells, max_ticks, Some(deal_gas_overhead_raw))?
    };
    chain.assert_seller_note_current(&note).await?;
    let note_ecc = chain
        .client()
        .get_account(&note)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "seller note {} disappeared before residual provision",
                dexdo_core::address::display(&note.with_workchain())
            )
        })?
        .ecc_balance(2);
    let note_spendable = chain.private_note_shell_balance(&note).await?;
    ensure_provision_deposit_covered(
        note_ecc,
        note_spendable,
        deposit_shells,
        u128::from(price_per_tick),
    )?;
    let market = if supplied_deal_gas_overhead_raw.is_none() {
        chain
            .provision_market(
                &keys,
                &note,
                frame_model,
                nonce,
                u128::from(price_per_tick),
                max_ticks,
                per_deploy,
            )
            .await?
    } else {
        chain
            .provision_market_with_deal_gas_overhead(
                &keys,
                &note,
                frame_model,
                nonce,
                u128::from(price_per_tick),
                max_ticks,
                per_deploy,
                deal_gas_overhead_raw,
            )
            .await?
    };
    let backend: Arc<dyn ChainBackend> = Arc::new(RealSellerBackend::new_with_deal_gas_overhead(
        chain,
        // The seller note is a shared-DApp account and the backend holds the chain address it reads
        // and writes with, so only the chain half is handed over.
        note.into_chain(),
        keys,
        dexdo_core::model_hash_for(frame_model),
        frame_model.to_string(),
        nonce,
        TICK_SIZE,
        supplied_deal_gas_overhead_raw,
    ));
    Ok((market, backend))
}

#[cfg(not(feature = "shellnet"))]
pub(crate) fn seller_real_backend_with_deal_gas_overhead(
    _args: &SellerArgs,
    _market_frame_model: Option<&str>,
    _market_nonce: Option<u64>,
    _registry_frame_model: Option<&str>,
    _deal_gas_overhead_raw: Option<u128>,
) -> Result<ChainAndNote> {
    bail!(
        "real shellnet backend unavailable: build with `--features shellnet` or pass --mock-chain"
    )
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn provision_replacement_seller_with_deal_gas_overhead(
    _args: &SellerArgs,
    _frame_model: &str,
    _nonce: u64,
    _price_per_tick: u64,
    _max_ticks: u64,
    _deal_gas_overhead_raw: Option<u128>,
) -> Result<(dexdo_core::MarketManifest, Arc<dyn ChainBackend>)> {
    bail!("real shellnet backend unavailable: residual provisioning requires --features shellnet")
}

/// Real buyer backend + the buyer's `RealNote`: from a provisioned note(`--note-key`/`--note-addr`)
/// and `model_hash` from `--frame-model`. The price limit is `--max-price-per-tick`(>= ask); the escrow must
/// cover `ticks x limit x(1 + 2.5 % book fee)` (issue -- otherwise the escrow is orphaned in the book;
/// `from_provisioned` checks the invariant ahead of time via `check_buy_deposit_headroom`).
#[cfg(feature = "shellnet")]
pub(crate) fn buyer_real_backend(args: &BuyerArgs, frame_model: &str) -> Result<ChainAndNote> {
    let note_addr = args.identity.note_addr.clone().ok_or_else(|| {
        anyhow::anyhow!("real shellnet: --note-addr (provisioned note address) is required")
    })?;
    let note_key = args.identity.note_key.as_deref().ok_or_else(|| {
        anyhow::anyhow!("real shellnet: --note-key (owner key of the provisioned note) is required")
    })?;
    let manifest = args
        .contracts
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?;
    let max_price_per_tick = args.max_price_per_tick;
    let (backend, rn) = dexdo_core::RealBuyerBackend::from_provisioned(
        manifest,
        &note_addr,
        &read_secret_hex(note_key, "--note-key")?,
        frame_model,
        max_price_per_tick,
        args.ticks,
        // default to EXACTLY the required escrow(no over-funding); an explicit value is checked
        // == required by `check_buy_deposit_headroom` in `from_provisioned`.
        args.escrow
            .unwrap_or_else(|| dexdo_core::required_escrow_for_buy(args.ticks, max_price_per_tick)),
    )?;
    let backend = backend.with_wait_for_seller(args.wait_for_seller);
    let chain: Arc<dyn ChainBackend> = Arc::new(backend);
    let note: Arc<dyn Note> = Arc::new(rn);
    Ok((chain, note))
}

#[cfg(not(feature = "shellnet"))]
pub(crate) fn buyer_real_backend(_args: &BuyerArgs, _frame_model: &str) -> Result<ChainAndNote> {
    bail!(
        "real shellnet backend unavailable: build with `--features shellnet` or pass --mock-chain"
    )
}

/// Default endpoints file under the selected instance root, or under the legacy platform data
/// directory when `--data-dir` is absent.
pub(crate) fn default_endpoints_path() -> Result<PathBuf> {
    crate::cli::data_dir::automatic("endpoints.json")
}

/// Resolve the endpoints file path: an explicit `--endpoints-file` takes priority, otherwise the
/// configured instance default. The parent directory is created (the mock writes
/// `*.chainstate.json` alongside it).
pub(crate) fn resolve_endpoints_file(explicit: Option<PathBuf>) -> Result<PathBuf> {
    let path = match explicit {
        Some(p) => p,
        None => default_endpoints_path()?,
    };
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("create directory {}: {e}", parent.display()))?;
        }
    }
    Ok(path)
}

/// Issue: load + integrity-check a `dexdo provision` market manifest(`--market`). A corrupt or
/// hand-edited manifest(empty fields, `model_hash` not matching `frame_model`) is rejected, not silently
/// trusted by a real-money CLI.
pub(crate) fn load_market(path: &std::path::Path) -> Result<dexdo_core::MarketManifest> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read --market {}: {e}", path.display()))?;
    let m = dexdo_core::MarketManifest::from_json(&s)
        .map_err(|e| anyhow::anyhow!("parse --market {}: {e}", path.display()))?;
    m.validate()
        .map_err(|e| anyhow::anyhow!("--market {}: {e}", path.display()))?;
    Ok(m)
}

/// on `dexdo seller` with `--market`, the seller note(`--note-addr`) MUST be the one the market was provisioned
/// for. The per-deal `TokenContract` is derived from `(sellerPubkey, nonce)`; posting an offer from a different
/// note/key than the manifest's `seller_note` makes the `InferenceOrderBook` reject the ask (canonical-TC
/// mismatch) -- it never rests, the seller never matches, and the buyer times out. Fail closed BEFORE posting.
/// Pure(offline-testable): compares the manifest `seller_note` to `--note-addr`, both wallet-normalized.
pub(crate) fn assert_market_seller_note(manifest_seller_note: &str, note_addr: &str) -> Result<()> {
    let norm =
        |s: &str| dexdo_core::normalize_wallet_address(s).unwrap_or_else(|_| s.trim().to_string());
    if norm(manifest_seller_note) != norm(note_addr) {
        bail!(
            "--market manifest seller_note {} != --note-addr {}: the seller note \
             must be the one the market was provisioned for. The per-deal TokenContract is derived from \
             (sellerPubkey, nonce), so an offer from a different note/key is rejected by the InferenceOrderBook \
             (canonical-TC mismatch) -- the ask never rests and the buyer never matches (). Use the \
             provisioned note, or re-provision a market for this note.",
            dexdo_core::address::display(manifest_seller_note),
            dexdo_core::address::display(note_addr)
        );
    }
    Ok(())
}

#[cfg(test)]
mod seller_note_tests {
    use super::*;

    /// `dexdo seller` with `--market` must fail closed if the manifest's `seller_note` isn't this seller's
    /// `--note-addr` -- a mismatched note posts a non-canonical TC the IOB won't rest, so the seller never
    /// matches and the buyer times out. The same note passes.
    #[test]
    fn market_seller_note_mismatch_fails_closed() {
        assert!(assert_market_seller_note("0:abc123", "0:abc123").is_ok());
        let err = assert_market_seller_note("0:aaaa", "0:bbbb")
            .unwrap_err()
            .to_string();
        assert!(err.contains(""), "{err}");
        assert!(err.contains("seller note"), "{err}");
    }
}

/// Resolve `(token_contract, frame_model, nonce)` for seller/buyer from `--market`(if set) or the
/// explicit flags: a produced provisioning record feeds the CLI without hand-editing.
/// `frame_model` is returned as `Option` -- the seller passes `None` (it validates the manifest model
/// against `--model`). `nonce` is the deal nonce from the manifest -- `Some` only on the
/// `--market` path; on the explicit `--token-contract` path it is `None` (the seller supplies it via
/// `--nonce`, the buyer ignores it).
/// **Fail-loud(real-money CLI):** `--market` is the single source of truth -- combining it with an
/// explicit `--token-contract`/`--frame-model` is rejected rather than silently taking one of them.
pub(crate) fn resolve_market_fields(
    market: Option<&std::path::Path>,
    token_contract: Option<&str>,
    frame_model: Option<&str>,
) -> Result<(String, Option<String>, Option<u64>)> {
    if let Some(p) = market {
        if token_contract.is_some() {
            bail!("--market and --token-contract are mutually exclusive -- pass only one");
        }
        if frame_model.is_some() {
            bail!("--market and --frame-model are mutually exclusive -- pass only one");
        }
        let m = load_market(p)?;
        Ok((m.token_contract, Some(m.frame_model), Some(m.nonce)))
    } else {
        let tc = token_contract
            .ok_or_else(|| anyhow::anyhow!("provide --token-contract or --market <manifest>"))?;
        Ok((tc.to_string(), frame_model.map(str::to_string), None))
    }
}

/// `dexdo provision` REQUIRES an explicit, deal-unique `--nonce`. The per-deal `TokenContract` derives
/// from `(sellerPubkey, nonce)`, so a reused/default nonce collides -- a second provisioned deal overwrites the
/// first deal's TC. The old `--nonce 0` default silently reused it; this fails loud and forces a distinct nonce
/// per deal. Pure.
#[cfg(any(feature = "shellnet", test))]
pub(crate) fn require_provision_nonce(nonce: Option<u64>) -> Result<u64> {
    nonce.ok_or_else(|| {
        anyhow::anyhow!(
            "--nonce <n> is required and must be UNIQUE per deal: the per-deal TokenContract derives from \
             (sellerPubkey, nonce), so a reused/default nonce collides -- overwriting a prior deal's TC. Pass a \
             distinct --nonce for each provisioned deal (e.g. an incrementing counter)."
        )
    })
}

#[cfg(test)]
mod provision_nonce_tests {
    use super::require_provision_nonce;

    /// `provision` refuses an absent `--nonce`(the old unsafe `0` default -> collision across deals)
    /// and accepts an explicit deal-unique value.
    #[test]
    fn provision_nonce_required_and_explicit() {
        assert_eq!(require_provision_nonce(Some(7)).unwrap(), 7);
        let err = require_provision_nonce(None).unwrap_err().to_string();
        assert!(err.contains("UNIQUE per deal"), "{err}");
        assert!(err.contains("--nonce"), "{err}");
    }
}

/// Issue(review): the served `--model` must resolve to the model a `--market` manifest was
/// provisioned for, else the seller posts the manifest's `token_contract` into the wrong order book
/// while a buyer using the same manifest derives another model(fields drift). Fail closed on mismatch.
/// (Only the real-shellnet seller path calls it; kept non-gated so the offline regression exercises it.)
pub(crate) fn check_market_model_match(
    market_frame_model: Option<&str>,
    configured_frame_model: &str,
    model_name: &str,
) -> Result<()> {
    if let Some(mfm) = market_frame_model {
        if mfm != configured_frame_model {
            bail!(
                "--market manifest is for frame_model `{mfm}`, but --model `{model_name}` resolves to \
                 `{configured_frame_model}` -- refusing to serve the wrong model into the manifest's order book"
            );
        }
    }
    Ok(())
}

pub(crate) fn consumer_api_token_budget(ticks: u128) -> u64 {
    let tick_size = dexdo_core::DobParams::canonical().tick_size as u128;
    ticks.saturating_mul(tick_size).min(u64::MAX as u128) as u64
}

/// the one-shot `dexdo buyer` path(no `--local-listen`) opens the seller stream with NO canonical
/// request -- it is promptless by design(`connect_and_stream` sends `None`). A **real** seller upstream
/// cannot serve a prompt-less stream(`"real upstream requires a canonical request"`), and fabricating a
/// default prompt would run+bill a synthetic inference the buyer never asked for(money-safety). So one-shot
/// only drives a `--mock-model` seller; real-provider inference must go through `--local-listen` + the consumer
/// API, which supplies the prompt per request. Fail closed EARLY
/// (before the on-chain buy) with an actionable error instead of a deep gateway `InvalidArgument`.
pub(crate) fn oneshot_real_upstream_guard(
    local_listen_set: bool,
    mock_model: bool,
) -> Result<(), String> {
    if !local_listen_set && !mock_model {
        return Err(
            "real-provider inference requires `--local-listen <addr>` + a `/v1/chat/completions` request \
             (the consumer API supplies the prompt,/G); one-shot `dexdo buyer` (no prompt) only drives a \
             `--mock-model` seller. Add `--local-listen` and POST your prompt there, or pass `--mock-model` for \
             the mock path ()."
                .to_string(),
        );
    }
    Ok(())
}

/// 1 SHELL = 1e9 raw ECC[2] nano(the note-side unit; `--deposit-shells N` = N **SHELL**, not vmshell).
#[cfg(any(feature = "shellnet", test))] // used by the shellnet `provision` path + the deposit-validation tests
pub(crate) use dexdo_core::params::SHELL_UNIT;
/// the default note deposit is THIS deal's own requirement, not one figure for every deal. It
/// has always been the floor itself and still is; what changed is that the floor follows the deal.
#[cfg(any(feature = "shellnet", test))]
pub(crate) use dexdo_core::params::default_deposit_shells;
/// per-deploy **SHELL allocation** floor(note-side), sized to what THIS deal's `TokenContract`
/// spends over its whole life -- derived from the values the contract declares plus the published
/// 4.0.34 measurement.
/// It used to be a flat `10`, justified by the cross-dapp `REGISTER_FORWARD_VALUE`(5 vmshell) the
/// deal's registration message was thought to carry; the `TokenContract` sends it with
/// `DAPP_MSG_VALUE = 0.01` instead. A flat floor priced out every model whose whole deal is worth
/// less than it, and under-funded every deal longer than it. `fundDeployShell` converts SHELL->vmshell
/// 1:1(flag:16), which is what lets a SHELL deposit be compared to a vmshell need.
#[cfg(test)]
pub(crate) use dexdo_core::params::min_deploy_shells;
/// resolve the per-deploy ECC[2] funding(raw) from the user's note deposit(SHELL) -- **fail-closed** for a
/// value that controls live on-chain spending. Errors on `u128` overflow and on a **below-floor** deposit (a known
/// funded-uninit / fund-burn outcome on-chain), instead of silently clamping or proceeding into a live spend. For
/// this checkpoint the deposit is a **per-deploy allocation** -- since 4.0.34 there is exactly one
/// note-funded deploy, the per-deal `TokenContract`, so the allocation is the whole deposit -- not yet the
/// full "N deals per note" budget model.
/// the floor is THIS deal's, from `max_ticks`. The deal's `TokenContract` pays its own compute
/// and one claim carries at most one tick(`MAX_CLAIM_DELTA = TICK_SIZE`), so its lifetime need
/// follows from the deal's own terms; a flat floor either prices a cheap model out of the market or
/// under-funds a long one, and it did both.
#[cfg(any(feature = "shellnet", test))]
pub(crate) fn deposit_per_deploy(deposit_shells: u128, max_ticks: u128) -> Result<u128> {
    deposit_per_deploy_with_overhead(deposit_shells, max_ticks, None)
}

/// Resolve one deal's deploy allocation against an optional operator measurement.
#[cfg(any(feature = "shellnet", test))]
pub(crate) fn deposit_per_deploy_with_overhead(
    deposit_shells: u128,
    max_ticks: u128,
    supplied_deal_gas_overhead_raw: Option<u128>,
) -> Result<u128> {
    let deal_gas_overhead_raw =
        supplied_deal_gas_overhead_raw.unwrap_or(dexdo_core::params::DEAL_GAS_OVERHEAD_RAW.value);
    let measurement_source = if supplied_deal_gas_overhead_raw.is_some() {
        "the operator-supplied network measurement"
    } else {
        "the published 4.0.34 measurement"
    };
    let deposit_raw = deposit_shells.checked_mul(SHELL_UNIT).ok_or_else(|| {
        anyhow::anyhow!("--deposit-shells {deposit_shells}: overflows the u128 ECC[2] raw range")
    })?;
    // ONE NOTE-FUNDED DEPLOY, so the whole deposit is that deploy's. It used to be `deposit_raw / 2`,
    // because the note pre-funded the `RootModel`'s uninit address as well as the deal's. 4.0.34 has
    // `SuperRoot` deploy the RootModel with its own value(`contracts/airegistry/SuperRoot.sol:58`) and
    // removed the note's funding leg for it entirely(`contracts/dex/PrivateNote.sol:1143`), so halving
    // here reserved ECC[2] that no message could spend and that burns at `destroy`.
    let per_deploy = deposit_raw; // per-deal TokenContract -- the only note-funded deploy left
    let floor_shells =
        dexdo_core::params::min_deploy_shells_with_overhead(max_ticks, deal_gas_overhead_raw);
    if per_deploy < floor_shells.saturating_mul(SHELL_UNIT) {
        anyhow::bail!(
            "--deposit-shells {deposit_shells} -> ~{} SHELL/deploy is below the {floor_shells} SHELL/deploy floor \
             for a {max_ticks}-tick deal (that deal's TokenContract spends {} raw nanovmshell over its life: the \
             values it declares on its own outgoing calls, plus one claim per tick, because MAX_CLAIM_DELTA = \
             TICK_SIZE caps a claim at one tick and claimTokens accepts before its body so the DEAL pays -- \
             contract-declared values and {measurement_source}, not bisected). Below it the deal \
             under-funds, and it cannot refill itself: deployed by an external message into a dapp with no config, \
             gosh.mintshellq has nothing to draw on, so the stop is permanent with the bond inside. \
             Raise --deposit-shells to >={floor_shells} (default for this deal: {}).",
            per_deploy / SHELL_UNIT,
            dexdo_core::params::deal_gas_requirement_raw_with_overhead(
                max_ticks,
                deal_gas_overhead_raw,
            ),
            floor_shells,
        );
    }
    Ok(per_deploy)
}

/// Seller mirror bond from `TokenContract._bondRequired()`: the seller
/// posts `2P` -- two ticks, mirroring the buyer's maximum contested `D = 2P`.
#[cfg(any(feature = "shellnet", test))]
pub(crate) fn seller_bond_for_price(price_per_tick: u128) -> Result<u128> {
    price_per_tick.checked_mul(2).ok_or_else(|| {
        anyhow::anyhow!("price_per_tick {price_per_tick}: seller bond (2P) overflows u128")
    })
}

/// Shared client preflight for every limit price(limit SELL, limit BUY, subscription): the price
/// must be a positive whole multiple of `PRICE_STEP`(1 SHELL). Rejects BEFORE any write / escrow
/// action; the error names the value and step in both raw and SHELL units. Market BUY (no limit
/// price) is the single explicit exception and does not call this.
pub(crate) fn validate_price_step(price_per_tick: u128) -> Result<()> {
    let price_step = dexdo_core::PRICE_STEP;
    if price_per_tick == 0 {
        anyhow::bail!(
            "price 0 raw (0 SHELL) is invalid: must be a positive multiple of PRICE_STEP = \
             {price_step} raw (1 SHELL)"
        );
    }
    if !price_per_tick.is_multiple_of(price_step) {
        anyhow::bail!(
            "price {price_per_tick} raw ({}.{:09} SHELL) is not a whole multiple of PRICE_STEP = \
             {price_step} raw (1 SHELL); use a whole number of SHELL per tick",
            price_per_tick / price_step,
            price_per_tick % price_step,
        );
    }
    Ok(())
}

#[cfg(test)]
mod price_step_tests {
    use super::validate_price_step;
    use dexdo_core::PRICE_STEP;

    #[test]
    fn price_step_boundaries() {
        // reject: zero, sub-step, and non-multiple non-zero values
        assert!(validate_price_step(0).is_err());
        assert!(validate_price_step(PRICE_STEP - 1).is_err());
        assert!(validate_price_step(PRICE_STEP + 1).is_err());
        assert!(validate_price_step(3 * PRICE_STEP / 2).is_err());
        // accept: exactly 1 SHELL and whole multiples
        assert!(validate_price_step(PRICE_STEP).is_ok());
        assert!(validate_price_step(2 * PRICE_STEP).is_ok());
        assert!(validate_price_step(1000 * PRICE_STEP).is_ok());
    }
}

/// provision may fail early if the note cannot cover the exact deploy deposit plus the contract-derived
/// seller mirror bond. This is not guessed runtime headroom: `TokenContract.open()` hard-requires
/// `fundDeal(amount)` first, and the amount is `2P` (`_bondAmount()`) of `price_per_tick`.
#[cfg(any(feature = "shellnet", test))]
pub(crate) fn ensure_provision_deposit_covered(
    note_ecc_raw: u128,
    note_spendable_raw: u128,
    deposit_shells: u128,
    price_per_tick: u128,
) -> Result<()> {
    let deploy_need = deposit_shells.checked_mul(SHELL_UNIT).ok_or_else(|| {
        anyhow::anyhow!("--deposit-shells {deposit_shells}: overflows the u128 ECC[2] raw range")
    })?;
    let bond_need = seller_bond_for_price(price_per_tick)?;
    if note_ecc_raw < deploy_need {
        anyhow::bail!(
            "provision: note ECC[2] SHELL = {note_ecc_raw} raw (~{} SHELL), but --deposit-shells \
             {deposit_shells} needs {deploy_need} raw (~{deposit_shells} SHELL) for the per-deal \
             TokenContract deploy gas. Lower --deposit-shells (the default is this deal's own floor) \
             or mint a note with enough physical ECC[2] gas.",
            note_ecc_raw / SHELL_UNIT,
        );
    }
    if note_spendable_raw < bond_need {
        anyhow::bail!(
            "provision: PrivateNote.getDetails().balance[2] = {note_spendable_raw} raw, but seller \
             bond (2P) needs {bond_need} raw at price_per_tick={price_per_tick}. Mint a note with \
             enough nominal SHELL; physical ECC[2] gas cannot fund the bond."
        );
    }
    Ok(())
}

/// interactively ask the operator for the note deposit(SHELL). `Ok(None)` = empty line / non-interactive
/// stdin(caller uses [`DEFAULT_DEPOSIT_SHELLS`]); `Ok(Some)` = a valid amount; **`Err` = a non-empty unparseable
/// line** -- fail-closed: a typo must NOT silently fall back to the default for a live-spend input.
#[cfg(feature = "shellnet")]
pub(crate) fn prompt_deposit_shells() -> Result<Option<u128>> {
    use std::io::{IsTerminal as _, Write as _};
    if !std::io::stdin().is_terminal() {
        return Ok(None);
    }
    eprint!(
        "Note ECC[2] allocation in SHELL (1 SHELL = 1e9 raw; funds the one per-deal TokenContract deploy) \
         [empty = this deal's own floor]: "
    );
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let t = line.trim();
    if t.is_empty() {
        return Ok(None);
    }
    let n = t
        .parse::<u128>()
        .map_err(|e| anyhow::anyhow!("note deposit '{t}': not a valid whole SHELL amount ({e})"))?;
    Ok(Some(n))
}

/// Human-readable view of the identity's **note tree** snapshot(R14): state across all sub-notes under
/// the key. "From whom" = the counterparty note's anonymous public key.
pub(crate) fn print_tree_snapshot(s: &TreeSnapshot) {
    print!("{}", render_tree_snapshot(s));
}

pub(crate) fn render_tree_snapshot(s: &TreeSnapshot) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    writeln!(
        &mut out,
        "identity note tree ({} sub-notes polled):",
        s.note_ids.len()
    )
    .unwrap();
    for id in &s.note_ids {
        writeln!(&mut out, "  * {id}").unwrap();
    }
    writeln!(
        &mut out,
        "tree exposure (at risk): {} raw ECC[2]",
        s.exposure
    )
    .unwrap();
    writeln!(&mut out, "offers in book: {}", s.offers.len()).unwrap();
    for o in &s.offers {
        writeln!(
            &mut out,
            "  * {} -- {} raw ECC[2]/tick x {} ticks",
            o.token_contract, o.price_per_tick, o.max_ticks
        )
        .unwrap();
    }
    writeln!(&mut out, "deals: {}", s.deals.len()).unwrap();
    for d in &s.deals {
        let role = match d.role {
            DealRole::Buyer => "buyer",
            DealRole::Seller => "seller",
        };
        let cp = d.counterparty.as_deref().unwrap_or("--(no match)");
        let by_fact = match &d.snapshot {
            Some(snap) => format!(
                "by-fact raw ECC[2]: to seller {} / refund {} / held-in-TC(buyer {}, \
                 seller-bond {}) / burn {}{}",
                snap.seller_received,
                snap.buyer_refunded,
                snap.buyer_locked,
                snap.seller_locked,
                snap.burned,
                if snap.closed { " * CLOSED" } else { "" }
            ),
            None => "stream not opened".to_string(),
        };
        writeln!(
            &mut out,
            "  * {} [{}] counterparty {} * {} raw ECC[2]/tick * {}",
            d.token_contract, role, cp, d.price_per_tick, by_fact
        )
        .unwrap();
        // Surface by-fact anomalies: an orphaned lock / a lock that survived a STOP / a buyer lock
        // past the two-tick invariant must be HIGHLIGHTED, not hidden behind a clean number.
        for a in deal_anomalies(d) {
            let msg = match a {
                DealAnomaly::LockedNoMatch { locked } => {
                    format!(
                        "orphaned lock -- {locked} raw ECC[2] locked with no matched counterparty ()"
                    )
                }
                DealAnomaly::LockedAfterClose { locked } => {
                    format!(
                        "settlement mismatch -- {locked} raw ECC[2] still locked after the deal closed ()"
                    )
                }
                DealAnomaly::BuyerLockExceedsTwoTicks {
                    buyer_lead,
                    ceiling,
                } => format!(
                    "two-tick invariant -- buyer lead {buyer_lead} raw ECC[2] exceeds the {ceiling} \
                     raw ECC[2] ceiling ()"
                ),
            };
            writeln!(&mut out, "      ! ANOMALY: {msg}").unwrap();
        }
    }
    // Per-model by-fact accounting, per role: the same deals, grouped by served model and
    // counterparty, with tokens(finalized ticks) / SHELL settled / locked / burned.
    write_role_breakdown(
        &mut out,
        "seller",
        "recv",
        &per_model_breakdown(&s.deals, DealRole::Seller),
    );
    write_role_breakdown(
        &mut out,
        "buyer",
        "paid",
        &per_model_breakdown(&s.deals, DealRole::Buyer),
    );
    out
}

fn write_role_breakdown(
    out: &mut String,
    role_label: &str,
    money_label: &str,
    models: &[ModelBreakdown],
) {
    use std::fmt::Write as _;

    if models.is_empty() {
        return;
    }
    writeln!(out, "{role_label} accounting (by model):").unwrap();
    for m in models {
        writeln!(
            out,
            "  > model {} -- tokens {} * {} {} raw ECC[2] * locked {} raw ECC[2] * burned {} raw ECC[2]",
            m.model, m.tokens, money_label, m.money, m.locked, m.burned
        )
        .unwrap();
        for c in &m.counterparties {
            let cp = c.counterparty.as_deref().unwrap_or("--(no match)");
            writeln!(
                out,
                "      -> {} -- tokens {} * {} {} raw ECC[2] * locked {} raw ECC[2] * burned {} raw ECC[2]",
                cp, c.tokens, money_label, c.money, c.locked, c.burned
            )
            .unwrap();
        }
    }
}

#[cfg(test)]
mod monitor_render_tests {
    use super::render_tree_snapshot;
    use dexdo_core::{DealChainState, DealRole, DealView, StreamSnapshot, TreeSnapshot, TICK_SIZE};

    /// `settled` marks a deal whose terminal path already drained the escrow -- the signal that replaced
    /// the probe latch for telling a settled close from funded-but-never-opened.
    fn state(funded: bool, opened: bool, disputed: bool, settled: bool) -> DealChainState {
        DealChainState {
            funded,
            opened,
            probe_accepted: true,
            disputed,
            deposit: if settled { 0 } else { 1_000 },
            finalized_owed: 0,
            tokens_final: 0,
            tokens_pending: 0,
            funded_time: None,
            probe_tick: 0,
            probe_time: 0,
            last_claim_time: 0,
            dispute_time: 0,
        }
    }

    fn snapshot_from_state(
        state: DealChainState,
        seller_received: u64,
        buyer_locked: u64,
        seller_locked: u64,
    ) -> StreamSnapshot {
        StreamSnapshot {
            seller_locked: u128::from(seller_locked),
            buyer_locked: u128::from(buyer_locked),
            buyer_lead: 0,
            tokens_final: state.tokens_final,
            seller_received: u128::from(seller_received),
            buyer_refunded: 0,
            burned: 0,
            closed: state.is_stopped(),
        }
    }

    fn rendered_market_monitor(token_contract: &str, snapshot: StreamSnapshot) -> String {
        let exposure = if snapshot.closed {
            0
        } else {
            u64::try_from(snapshot.seller_locked).unwrap_or(u64::MAX)
        };
        let tree = TreeSnapshot {
            note_ids: vec!["seller-note".to_string()],
            offers: Vec::new(),
            deals: vec![DealView {
                token_contract: token_contract.to_string(),
                role: DealRole::Seller,
                counterparty: Some("buyer-pubkey".to_string()),
                price_per_tick: 400,
                model: Some("qwen--qwen3--32b".to_string()),
                snapshot: Some(snapshot),
            }],
            exposure,
        };
        render_tree_snapshot(&tree)
    }

    #[test]
    fn funded_never_opened_market_snapshot_is_active_without_false_18() {
        let rendered = rendered_market_monitor(
            "tc-funded-never-opened",
            snapshot_from_state(state(true, false, false, false), 0, 3075, 10),
        );
        let expected = "\
identity note tree (1 sub-notes polled):
  * seller-note
tree exposure (at risk): 10 raw ECC[2]
offers in book: 0
deals: 1
  * tc-funded-never-opened [seller] counterparty buyer-pubkey * 400 raw ECC[2]/tick * by-fact raw ECC[2]: to seller 0 / refund 0 / held-in-TC(buyer 3075, seller-bond 10) / burn 0
seller accounting (by model):
  > model qwen--qwen3--32b -- tokens 0 * recv 0 raw ECC[2] * locked 10 raw ECC[2] * burned 0 raw ECC[2]
      -> buyer-pubkey -- tokens 0 * recv 0 raw ECC[2] * locked 10 raw ECC[2] * burned 0 raw ECC[2]
";
        assert_eq!(rendered, expected);
        assert!(!rendered.contains("CLOSED"), "{rendered}");
        assert!(!rendered.contains("settlement mismatch"), "{rendered}");
    }

    #[test]
    fn opened_probe_market_snapshot_is_active_without_false_18() {
        let rendered = rendered_market_monitor(
            "tc-opened-probe",
            snapshot_from_state(state(true, true, false, false), 0, 4100, 10),
        );
        let expected = "\
identity note tree (1 sub-notes polled):
  * seller-note
tree exposure (at risk): 10 raw ECC[2]
offers in book: 0
deals: 1
  * tc-opened-probe [seller] counterparty buyer-pubkey * 400 raw ECC[2]/tick * by-fact raw ECC[2]: to seller 0 / refund 0 / held-in-TC(buyer 4100, seller-bond 10) / burn 0
seller accounting (by model):
  > model qwen--qwen3--32b -- tokens 0 * recv 0 raw ECC[2] * locked 10 raw ECC[2] * burned 0 raw ECC[2]
      -> buyer-pubkey -- tokens 0 * recv 0 raw ECC[2] * locked 10 raw ECC[2] * burned 0 raw ECC[2]
";
        assert_eq!(rendered, expected);
        assert!(!rendered.contains("CLOSED"), "{rendered}");
        assert!(!rendered.contains("settlement mismatch"), "{rendered}");
    }

    #[test]
    fn stopped_market_snapshot_with_locked_escrow_still_flags_18() {
        let mut stopped = state(true, false, false, true);
        stopped.tokens_final = 2 * TICK_SIZE;
        let rendered = rendered_market_monitor(
            "tc-stopped-locked",
            snapshot_from_state(stopped, 810, 4100, 10),
        );
        let expected = "\
identity note tree (1 sub-notes polled):
  * seller-note
tree exposure (at risk): 0 raw ECC[2]
offers in book: 0
deals: 1
  * tc-stopped-locked [seller] counterparty buyer-pubkey * 400 raw ECC[2]/tick * by-fact raw ECC[2]: to seller 810 / refund 0 / held-in-TC(buyer 4100, seller-bond 10) / burn 0 * CLOSED
      ! ANOMALY: settlement mismatch -- 4110 raw ECC[2] still locked after the deal closed ()
seller accounting (by model):
  > model qwen--qwen3--32b -- tokens 2 * recv 810 raw ECC[2] * locked 10 raw ECC[2] * burned 0 raw ECC[2]
      -> buyer-pubkey -- tokens 2 * recv 810 raw ECC[2] * locked 10 raw ECC[2] * burned 0 raw ECC[2]
";
        assert_eq!(rendered, expected);
    }
}

#[cfg(all(test, feature = "shellnet"))]
mod buyer_backend_settle_week_tests {
    use super::*;

    /// `settleWeek()` is permissionless, and a buyer needs it to book his own crossed subscription
    /// boundary -- otherwise the weekly quota can never advance under a running buyer.
    /// The regression drives the PRODUCTION selection path: `buyer_real_backend` is exactly what
    /// `run_buyer_inner` calls to build the real chain backend, and the assertion is made through the
    /// returned `Arc<dyn ChainBackend>` -- i.e. through the same dynamic dispatch production uses, not
    /// against a concrete `RealBuyerBackend`/`RealChainBackend` handle. Before the fix the selected backend
    /// inherited the `ChainBackend::settle_week` default and answered `settle_week not supported`.
    /// It stays offline and deterministic: `from_provisioned`/`connect` only load the manifest, and the
    /// deliberately unparsable `token_contract` fails in the adapter's own `parse_tc` preflight -- the very
    /// first statement of the override -- so no network read is ever attempted. The two assertions pin both
    /// directions: the trait default is gone, AND control actually reached the buyer's own implementation.
    #[tokio::test]
    async fn buyer_real_backend_selection_supports_settle_week() {
        let dir = tempfile::tempdir().expect("temp dir");
        let note_key = dir.path().join("note.key");
        // Throwaway test-only ed25519 secret: never used to sign, the call fails before any submit.
        std::fs::write(
            &note_key,
            "3d1c8f5b2a704e6913c85af0d27b64e8915caf3072d6be4189305f7ac2b1de60",
        )
        .expect("write note key");

        let args = BuyerArgs {
            mock: MockFlags {
                mock_model: false,
                mock_chain: false,
            },
            identity: IdentityArgs {
                note_key: Some(note_key),
                note_index: 0,
                note_addr: Some(
                    "0:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                ),
            },
            registry: ModelRegistryValidationArgs::default(),
            endpoints_file: None,
            deals_dir: None,
            token_contract: None,
            resume: false,
            preserve_deal_on_exit: false,
            wait_for_seller: false,
            market: None,
            max_tokens: 8,
            local_listen: None,
            continuity_mode: ContinuityModeArg::OnDemand,
            json: false,
            anthropic_compat: false,
            frame_model: Some("qwen--qwen3--32b".to_string()),
            allow_unverified_model: true,
            models: dir.path().join("models.json"),
            ticks: 1,
            max_price_per_tick: dexdo_core::PRICE_STEP,
            // `None` => EXACTLY the required escrow, so the headroom preflight passes offline.
            escrow: None,
            contracts: PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../contracts/deployed.shellnet.json"
            )),
            policy: None,
        };

        let (chain, _note) = buyer_real_backend(&args, "qwen--qwen3--32b")
            .expect("production buyer backend selection (offline manifest load)");

        let error = chain
            .settle_week(&"not-a-token-contract".to_string())
            .await
            .expect_err("an unparsable token_contract must fail in the adapter's own preflight");
        let error = error.to_string();
        assert!(
            !error.contains("settle_week not supported"),
            "the backend `dexdo buyer` selects must implement settle_week, not inherit the \
             ChainBackend default: {error}"
        );
        assert!(
            error.contains("bad token_contract not-a-token-contract"),
            "the failure must come from the buyer adapter's own parse_tc preflight: {error}"
        );
    }
}
