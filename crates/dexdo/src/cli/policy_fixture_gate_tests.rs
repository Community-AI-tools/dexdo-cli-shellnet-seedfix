use super::{
    field_valid, seller_chain_unavailable_field, PolicyField, BUYER_FIELDS, SELLER_FIELDS,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Default)]
struct ScanSummary {
    files_scanned: usize,
    field_literals: usize,
    errors: Vec<String>,
}

fn schema_fields() -> impl Iterator<Item = PolicyField> {
    BUYER_FIELDS
        .iter()
        .chain(SELLER_FIELDS.iter())
        .copied()
        .chain(std::iter::once(seller_chain_unavailable_field()))
}

fn skip_whitespace(source: &str, mut offset: usize) -> usize {
    while let Some(ch) = source[offset..].chars().next() {
        if !ch.is_whitespace() {
            break;
        }
        offset += ch.len_utf8();
    }
    offset
}

fn line_number(source: &str, offset: usize) -> usize {
    source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn literal_after_key(source: &str, key_end: usize) -> Option<Value> {
    let colon = skip_whitespace(source, key_end);
    if source.as_bytes().get(colon) != Some(&b':') {
        return None;
    }
    let value_start = skip_whitespace(source, colon + 1);
    serde_json::Deserializer::from_str(&source[value_start..])
        .into_iter::<Value>()
        .next()?
        .ok()
}

fn scan_source(path: &Path, source: &str) -> ScanSummary {
    let mut result = ScanSummary {
        files_scanned: 1,
        ..ScanSummary::default()
    };

    for field in schema_fields() {
        let key = field.path.rsplit('.').next().expect("policy field leaf");
        let needle = format!("\"{key}\"");
        for (offset, _) in source.match_indices(&needle) {
            let Some(value) = literal_after_key(source, offset + needle.len()) else {
                continue;
            };
            result.field_literals += 1;
            if !field_valid(Some(&value), field.kind) {
                result.errors.push(format!(
                    "{}:{}: invalid policy literal key={} value={}; allowed={}",
                    path.display(),
                    line_number(source, offset),
                    field.path,
                    value,
                    field.kind.allowed()
                ));
            }
        }
    }

    result
}

fn collect_test_sources(dir: &Path, inside_test_tree: bool, files: &mut Vec<PathBuf>) {
    let mut entries = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read test tree {}: {error}", dir.display()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("read test tree entry {}: {error}", dir.display()));
    entries.sort_by_key(std::fs::DirEntry::path);

    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .unwrap_or_else(|error| panic!("inspect test tree {}: {error}", path.display()));
        if file_type.is_dir() {
            let name = entry.file_name();
            if name == ".git" || name == "target" {
                continue;
            }
            collect_test_sources(&path, inside_test_tree || name == "tests", files);
        } else if inside_test_tree
            && matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("rs" | "json")
            )
        {
            files.push(path);
        }
    }
}

fn scan_test_tree() -> ScanSummary {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("dexdo crate lives under workspace/crates");
    let mut files = Vec::new();
    collect_test_sources(workspace, false, &mut files);

    let mut result = ScanSummary::default();
    for path in files {
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read test source {}: {error}", path.display()));
        let relative = path.strip_prefix(workspace).unwrap_or(&path);
        let scanned = scan_source(relative, &source);
        result.files_scanned += scanned.files_scanned;
        result.field_literals += scanned.field_literals;
        result.errors.extend(scanned.errors);
    }
    result
}

#[test]
fn historical_seller_stall_value_names_file_key_and_value() {
    let source = r#"
        let policy = serde_json::json!({
            "version": 1,
            "buyer": {
                "on": {
                    "seller_stalls_mid_stream": "fail_closed"
                }
            }
        });
    "#;

    let result = scan_source(Path::new("crates/dexdo/tests/live_cli.rs"), source);
    assert_eq!(result.field_literals, 1);
    assert_eq!(result.errors.len(), 1);
    let error = &result.errors[0];
    assert!(error.contains("crates/dexdo/tests/live_cli.rs"));
    assert!(error.contains("buyer.on.seller_stalls_mid_stream"));
    assert!(error.contains("fail_closed"));
}

#[test]
fn test_tree_policy_literals_match_the_shipped_schema() {
    let fields = schema_fields().collect::<Vec<_>>();
    let unique_leaves = fields
        .iter()
        .map(|field| field.path.rsplit('.').next().expect("policy field leaf"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        unique_leaves.len(),
        fields.len(),
        "the source scanner needs unambiguous policy field leaf names"
    );

    let result = scan_test_tree();
    assert!(
        result.field_literals > 0,
        "policy fixture gate found no literals in {} test source files",
        result.files_scanned
    );
    assert!(
        result.errors.is_empty(),
        "test-tree policy literals rejected by the shipped validator:\n{}",
        result.errors.join("\n")
    );
    eprintln!(
        "policy fixture gate validated {} literals across {} test source files",
        result.field_literals, result.files_scanned
    );
}
