use super::{oracle_withdraw_fees_payload, pmp_stake_key, private_note_pmp_exit_payload};

fn function<'a>(abi: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    abi["functions"]
        .as_array()
        .expect("compiled ABI functions")
        .iter()
        .find(|function| function["name"] == name)
        .unwrap_or_else(|| panic!("compiled ABI declares {name}"))
}

fn input_shape(function: &serde_json::Value) -> Vec<(&str, &str)> {
    function["inputs"]
        .as_array()
        .expect("compiled ABI inputs")
        .iter()
        .map(|input| {
            (
                input["name"].as_str().expect("input name"),
                input["type"].as_str().expect("input type"),
            )
        })
        .collect()
}

#[test]
fn issue_1120_exit_payloads_match_the_compiled_owner_authenticated_abis() {
    let private_note: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/compiled/dex/PrivateNote.abi.json"
    )))
    .expect("PrivateNote ABI JSON");
    let oracle: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/compiled/dex/Oracle.abi.json"
    )))
    .expect("Oracle ABI JSON");

    for method in ["cancelStake", "claim"] {
        assert_eq!(
            input_shape(function(&private_note, method)),
            vec![
                ("eventId", "uint256"),
                ("oracleListHash", "uint256"),
                ("tokenType", "uint32"),
            ]
        );
        assert_eq!(
            private_note_pmp_exit_payload("1", "0x2", 2).unwrap(),
            serde_json::json!({
                "eventId": "0x0000000000000000000000000000000000000000000000000000000000000001",
                "oracleListHash": "0x0000000000000000000000000000000000000000000000000000000000000002",
                "tokenType": 2,
            })
        );
    }

    assert_eq!(
        input_shape(function(&oracle, "withdrawFees")),
        vec![("to", "address"), ("amount", "uint128")]
    );
    assert_eq!(
        oracle_withdraw_fees_payload("0:1111", 40),
        serde_json::json!({"to": "0:1111", "amount": "40"})
    );
}

#[test]
fn issue_1120_stake_key_is_the_abi_encoded_full_market_tuple() {
    let decimal = pmp_stake_key("1", "2", 2).unwrap();
    let hexadecimal = pmp_stake_key("0x1", "0x2", 2).unwrap();
    assert_eq!(decimal, hexadecimal);
    assert_eq!(decimal.len(), 66);
    assert!(decimal.starts_with("0x"));
    assert_ne!(decimal, pmp_stake_key("2", "2", 2).unwrap());
    assert_ne!(decimal, pmp_stake_key("1", "3", 2).unwrap());
    assert_ne!(decimal, pmp_stake_key("1", "2", 3).unwrap());
}
