//! one stale deal handle must not make every handle-reading command unusable.

//! Measured live on the 4.0.36 gate: a seller handle written on 1 August, for a deal the run had
//! nothing to do with, aborted `dexdo seller` at "bringing the gateway up" --

//! ```text
//! parse deal handle ~/.local/share/dexdo/deals/deal-0-2727e1f8...-seller.json:
//! price_per_tick 2000000000 SHELL a tick is above the largest note that exists
//! ```

//! -- and took `live_cli_deal_flow_handover` and `live_cli_late_buyer_handover` down with it. The
//! deals directory accumulates across generations, so "every file in it must parse" is a condition
//! that only gets harder to satisfy with time.

//! The split these pin: a handle the caller NAMED still fails loudly, a handle the sweep merely
//! came across is skipped and its path is printed.

use super::*;

fn good_handle(token_contract: &str, created_at_unix: u64) -> DealHandle {
    DealHandle {
        version: DEAL_HANDLE_VERSION,
        handle: make_handle_id(token_contract, DealHandleRole::Seller),
        role: DealHandleRole::Seller,
        network: "net-a".into(),
        token_contract: token_contract.into(),
        note_addr: "0:44".into(),
        frame_model: "qwen/qwen3-32b".into(),
        model_hash: Some(dexdo_core::model_hash_for("qwen/qwen3-32b")),
        order_book: Some("0:11".into()),
        root_model: Some("0:22".into()),
        market: None,
        contracts: "manifest/deployed.manifest.json".into(),
        endpoint: None,
        created_order_ids: vec![],
        created_at_unix,
    }
}

/// Not valid JSON at all.
fn write_malformed(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("deal-0-malformed-seller.json");
    std::fs::write(&path, b"{ this is not json").expect("write malformed handle");
    path
}

/// Valid JSON that this client REFUSES -- the live shape: a record another generation wrote.

/// repointed this fixture, values only. It used to carry `version: DEAL_HANDLE_VERSION + 997`,
/// which is a schema from the FUTURE -- the one refusal class the sweep may not skip, because
/// `load_deal_record` answers it with a typed `DealHandleSchemaTooNew` and requires that to
/// reach the operator. Standing in for with it made these tests assert the opposite of
/// 's, on the same code path.

/// So the fixture is now the shape of the incident was actually written for, quoted in this
/// file's own header: a market whose `price_per_tick` is in the raw ECC[2] units of an older
/// generation. Read as whole SHELL that is three billion a tick -- above `MAX_NOTE_NOMINAL_SHELL`,
/// so `params::serde_price_shell::deserialize` refuses it by name during the full parse, as a plain
/// `parse deal handle...` error carrying no typed cause. An older generation's record is skipped;
/// a future generation's is not. Both test names below stay true.
fn write_refused_generation(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("deal-0-fromthefuture-seller.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({
            "version": DEAL_HANDLE_VERSION,
            "handle": "deal-0-fromthefuture-seller",
            "role": "seller",
            "network": "net-a",
            "token_contract": "0:99",
            "note_addr": "0:44",
            "frame_model": "qwen/qwen3-32b",
            "market": {
                "network": "net-a",
                "frame_model": "qwen/qwen3-32b",
                "model_hash": dexdo_core::model_hash_for("qwen/qwen3-32b"),
                "inference_order_book": "0:11",
                "root_model": "0:22",
                "token_contract": "0:99",
                "seller_note": "0:44",
                "nonce": 7,
                // Three SHELL a tick in the raw ECC[2] units this field used to hold. Read as whole
                // SHELL it is three billion, which no note can pay for one tick of.
                "price_per_tick": 3_000_000_000u64,
                "max_ticks": 1024
            },
            "contracts": "manifest/deployed.manifest.json",
            "created_order_ids": [],
            "created_at_unix": 7
        }))
        .expect("serialize refused handle"),
    )
    .expect("write refused handle");
    path
}

#[test]
fn a_malformed_handle_is_skipped_and_the_good_one_survives() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let good = good_handle("0:33", 1);
    let good_path = save_deal_handle(dir, &good).unwrap();
    write_malformed(dir);

    let listed = list_deal_handles(dir).expect("a broken neighbour must not abort the sweep");
    assert_eq!(
        listed.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>(),
        vec![good_path],
        "only the readable handle is returned"
    );
}

#[test]
fn a_handle_from_another_generation_is_skipped_too() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let good_path = save_deal_handle(dir, &good_handle("0:33", 1)).unwrap();
    write_refused_generation(dir);

    let listed = list_deal_handles(dir).expect("a refused generation must not abort the sweep");
    assert_eq!(
        listed.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>(),
        vec![good_path],
        "a record this client refuses is skipped, not fatal"
    );
}

/// The naming is the point: a silent skip turns a stale record into one nobody can find.
#[test]
fn the_skip_warning_names_the_file_and_the_reason() {
    let temp = tempfile::tempdir().unwrap();
    let path = write_malformed(temp.path());
    let error = load_deal_handle(&path).expect_err("this fixture must not parse");

    let rendered = skipped_handle_warning(&path, &error);
    assert!(
        rendered.contains(&path.display().to_string()),
        "the warning must name the file: {rendered}"
    );
    assert!(
        rendered.starts_with("warning: skipping unreadable deal handle "),
        "the warning must say what it did: {rendered}"
    );
    assert!(
        rendered.contains("deal-0-malformed-seller.json"),
        "the file name itself must be readable in the line: {rendered}"
    );
}

/// Over-skipping guard: asking for the broken handle BY NAME must still fail.
#[test]
fn an_explicitly_named_broken_handle_still_fails() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    save_deal_handle(dir, &good_handle("0:33", 1)).unwrap();
    let broken = write_malformed(dir);

    let by_path = resolve_deal_ref(&broken.display().to_string(), dir, None, None);
    assert!(
        by_path.is_err(),
        "a handle named by path must not be silently skipped"
    );

    let by_id = resolve_deal_ref("deal-0-malformed-seller", dir, None, None);
    assert!(
        by_id.is_err(),
        "a handle named by id must not be silently skipped"
    );
}

/// The `status <raw TokenContract>` path: the address still resolves with a broken neighbour there.
#[test]
fn a_raw_token_contract_resolves_past_a_broken_neighbour() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let good_path = save_deal_handle(dir, &good_handle("0:33", 1)).unwrap();
    write_malformed(dir);
    write_refused_generation(dir);

    let (path, handle) = resolve_deal_ref("0:33", dir, None, None)
        .expect("a broken neighbour must not abort resolution")
        .expect("the raw TokenContract must still find its handle");
    assert_eq!(path, good_path);
    assert_eq!(handle.token_contract, "0:33");
}

/// Negative control: the broken files must change NOTHING a clean directory would have done.
#[test]
fn a_broken_file_changes_nothing_a_clean_directory_would_do() {
    let clean = tempfile::tempdir().unwrap();
    let dirty = tempfile::tempdir().unwrap();
    for dir in [clean.path(), dirty.path()] {
        save_deal_handle(dir, &good_handle("0:33", 1)).unwrap();
        save_deal_handle(dir, &good_handle("0:34", 2)).unwrap();
    }
    write_malformed(dirty.path());
    write_refused_generation(dirty.path());

    let names = |dir: &std::path::Path| {
        list_deal_handles(dir)
            .expect("sweep")
            .into_iter()
            .map(|(p, h)| {
                (
                    p.file_name().expect("name").to_string_lossy().into_owned(),
                    h.token_contract,
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(dirty.path()),
        names(clean.path()),
        "a directory with stale files must list exactly what a clean one lists"
    );

    let resolved = |dir: &std::path::Path| {
        resolve_deal_ref("0:34", dir, None, None)
            .expect("resolve")
            .map(|(p, _)| p.file_name().expect("name").to_string_lossy().into_owned())
    };
    assert_eq!(resolved(dirty.path()), resolved(clean.path()));
}
