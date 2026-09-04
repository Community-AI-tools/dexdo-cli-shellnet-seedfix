//! a label is separated from its value whatever the label's length.

//! The subject of every assertion here is ONE character -- the gap that follows the label -- so the
//! assertions are made on that token and never on a whole rendered phrase. A phrase match cannot
//! see this defect: `generationmanifest 4.0.36` and `generation manifest 4.0.36` share every
//! substring the first one has, so any `contains("generation")` or `contains("manifest")` check
//! passes on the broken output as happily as on the fixed one. What separates them is the byte
//! immediately after the name, and that is what is read below.

use super::{field, Palette, Role, VALUE_COLUMN};

/// The visible text of a rendered line.

/// Padding counts bytes and an escape sequence is bytes nobody sees, so a test about columns has to
/// look at what reaches the screen rather than at what reaches the pipe.
fn visible(line: &str) -> String {
    let mut out = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for skip in chars.by_ref() {
                if skip == 'm' {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// Shorter than the label field, exactly its width, exactly the width the label used to be padded
/// to, and past it. The last two are the broken cases: before the fix the label was padded to
/// `VALUE_COLUMN - INDENT` with nothing after it, so a name of exactly that length consumed the
/// separator and a longer one ran straight into the value.
const LABELS: [&str; 6] = [
    "net",
    "endpoint",
    "SuperRoot",
    "generation",
    "RootOracle",
    "AnElevenPlusCharacterName",
];

/// Every palette, because the padding is widened by the length of the label's own escapes and a fix
/// that forgot that would separate the plain line and not the painted one.
const PALETTES: [Palette; 3] = [Palette::None, Palette::Ansi256, Palette::TrueColor];

#[test]
fn every_label_is_separated_from_its_value_whatever_its_length() {
    for label in LABELS {
        for palette in PALETTES {
            let rendered = visible(&field(palette, label, "VALUE", Role::Bold));
            let body = rendered
                .strip_prefix("  ")
                .unwrap_or_else(|| panic!("a field row is indented two: {rendered:?}"));
            let rest = body.strip_prefix(label).unwrap_or_else(|| {
                panic!("a field row opens with its own label {label:?}: {rendered:?}")
            });
            assert!(
                rest.starts_with(' '),
                "the value must not touch the label: {label:?} ({} chars, {palette:?}) rendered \
                 {rendered:?}, and the character after the name is {:?}",
                label.chars().count(),
                rest.chars().next(),
            );
            assert_eq!(
                rest.trim_start(),
                "VALUE",
                "the gap is the only thing added; the value itself is untouched: {rendered:?}"
            );
        }
    }
}

/// The fix narrows the label's field by the gap instead of moving the grid, so every row that reads
/// correctly today reads identically after it. Without this, a later "fix" that simply appended a
/// space would shift every value in the client one column right and this would catch it.
#[test]
fn a_label_that_fits_keeps_the_column_its_value_has_always_started_in() {
    for label in ["net", "network", "endpoint", "SuperRoot"] {
        let rendered = visible(&field(Palette::None, label, "VALUE", Role::Bold));
        assert_eq!(
            rendered.find("VALUE"),
            Some(VALUE_COLUMN),
            "a label of {} chars still puts its value in column {VALUE_COLUMN}: {rendered:?}",
            label.chars().count(),
        );
    }
}

/// The row from the report itself, asserted as the two tokens that tell the states apart.
#[test]
fn the_reported_doctor_row_no_longer_runs_its_name_into_its_value() {
    let rendered = visible(&field(
        Palette::None,
        "generation",
        "manifest 4.0.36, chain 4.0.36",
        Role::Bold,
    ));
    assert!(
        !rendered.contains("generationmanifest"),
        "the reported collision: {rendered:?}"
    );
    assert!(
        rendered.contains("generation manifest"),
        "the name and the value are separated: {rendered:?}"
    );
}
