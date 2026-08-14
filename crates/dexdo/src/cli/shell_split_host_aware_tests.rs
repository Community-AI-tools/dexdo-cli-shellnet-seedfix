use super::{printed_commands::shell_split_in, PastedShell};

#[test]
fn shell_split_round_trips_hostile_values_for_both_explicit_shells() {
    for shell in [PastedShell::Posix, PastedShell::PowerShell] {
        for value in [
            "/tmp/pn pool/r.json",
            "it's here",
            "a\"b",
            "x;rm -rf /",
            "<pool>",
        ] {
            let rendered = shell.quote(value);
            assert_eq!(
                shell_split_in(shell, &rendered)
                    .unwrap_or_else(|why| panic!("{shell:?} rejected {rendered:?}: {why}")),
                vec![value.to_string()],
                "{shell:?} quoting round-trip for {value:?}: {rendered:?}"
            );
        }
    }
}
