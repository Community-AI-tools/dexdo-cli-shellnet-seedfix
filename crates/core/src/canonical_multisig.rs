//! Canonical dexdo funding wallet artifact.
//! Source: `gosh-sh/acki-nacki`
//! `44fe02ea01e4bb31d431ed57d1f9b3dc3dd88a18`.

use serde_json::{Map, Value};

pub use crate::canonical_multisig_allowlist::{
    is_supported_spending_code_hash, CODE_HASH, CONTRACT_NAME, LEGACY_SPENDING_CODE_HASH,
    SUPPORTED_SPENDING_CODE_HASHES, VERSION,
};

pub const ROOT_PN_DAPP_ID: &str = "4";

pub const MULTISIG_ABI_JSON: &str =
    include_str!("../contracts/msig/UpdateCustodianMultisigWallet_v2.abi.json");
pub const MULTISIG_TVC: &[u8] =
    include_bytes!("../contracts/msig/UpdateCustodianMultisigWallet_v2.tvc");

pub fn send_transaction_params(
    dest: String,
    value: u128,
    cc: Map<String, Value>,
    bounce: bool,
    flags: u8,
    payload: String,
) -> Value {
    serde_json::json!({
        "dest": dest,
        "value": value.to_string(),
        "cc": Value::Object(cc),
        "bounce": bounce,
        "flags": flags,
        "payload": payload,
        "dapp_id": ROOT_PN_DAPP_ID,
    })
}

pub fn submit_transaction_params(
    dest: String,
    value: u128,
    cc: Map<String, Value>,
    bounce: bool,
    flag: u8,
    payload: String,
) -> Value {
    submit_transaction_params_in_dapp(dest, value, cc, bounce, flag, payload, ROOT_PN_DAPP_ID)
}

/// `submitTransaction` params for a recipient that does NOT live in the RootPN DApp.
/// The wallet's `dapp_id` argument is reported, not routed: the contract passes only
/// `(value, bounce, flags, payload, cc)` to `dest.transfer(...)` and its own comment records that
/// "network-level dest_dapp_id addressing is not wired yet, dapp_id is used only for reading account
/// state on the client"(`UpdateCustodianMultisigWallet_v2.sol`). So this argument cannot misroute
/// money and cannot make a transfer fail -- but it IS emitted in `TransactionSent`, and an event
/// that names DApp 4 for a recipient living in DApp 1 tells every off-chain subscriber something
/// untrue. Callers outside DApp 4 pass the recipient's real DApp id so the receipt is honest.
pub fn submit_transaction_params_in_dapp(
    dest: String,
    value: u128,
    cc: Map<String, Value>,
    bounce: bool,
    flag: u8,
    payload: String,
    dapp_id: &str,
) -> Value {
    serde_json::json!({
        "dest": dest,
        "value": value.to_string(),
        "cc": Value::Object(cc),
        "bounce": bounce,
        "flag": flag,
        "payload": payload,
        "dapp_id": dapp_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use tvm_block::Deserializable;

    const ABI_SHA256: &str = "e7573b233667cf50d8edc9ab0ce235f8ac88674ae9610c77d426bec22070f581";
    const TVC_SHA256: &str = "b0d72acbbdc6af309823e74b96b0b3ffb0f871a5b98316b6e89affdfb56c5c9d";

    fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn function<'a>(abi: &'a Value, name: &str) -> &'a Value {
        abi["functions"]
            .as_array()
            .expect("ABI functions")
            .iter()
            .find(|function| function["name"] == name)
            .unwrap_or_else(|| panic!("{name} function"))
    }

    #[test]
    fn canonical_v2_4_0_artifacts_match_acki_nacki_source() {
        assert_eq!(sha256_hex(MULTISIG_ABI_JSON.as_bytes()), ABI_SHA256);
        assert_eq!(sha256_hex(MULTISIG_TVC), TVC_SHA256);

        let state_init = tvm_block::StateInit::construct_from_cell(
            tvm_types::read_single_root_boc(MULTISIG_TVC).expect("read v2 TVC"),
        )
        .expect("decode v2 StateInit");
        let code_hash = state_init
            .code
            .expect("v2 StateInit code")
            .repr_hash()
            .to_hex_string();
        assert_eq!(code_hash, CODE_HASH);
        assert!(
            MULTISIG_TVC
                .windows(VERSION.len())
                .any(|window| window == VERSION.as_bytes()),
            "v2 TVC must contain the getVersion version literal"
        );
        assert!(
            MULTISIG_TVC
                .windows(CONTRACT_NAME.len())
                .any(|window| window == CONTRACT_NAME.as_bytes()),
            "v2 TVC must contain the getVersion contract-name literal"
        );
    }

    #[test]
    fn canonical_v2_abi_has_exact_transaction_and_getter_shapes() {
        assert_eq!(ROOT_PN_DAPP_ID, "4");
        let abi: Value = serde_json::from_str(MULTISIG_ABI_JSON).expect("parse v2 ABI");
        assert_eq!(abi["version"], "2.4");

        assert_eq!(
            function(&abi, "sendTransaction")["inputs"],
            serde_json::json!([
                { "name": "dest", "type": "address" },
                { "name": "value", "type": "uint128" },
                { "name": "cc", "type": "map(uint32,varuint32)" },
                { "name": "bounce", "type": "bool" },
                { "name": "flags", "type": "uint8" },
                { "name": "payload", "type": "cell" },
                { "name": "dapp_id", "type": "uint256" }
            ])
        );
        assert_eq!(
            function(&abi, "submitTransaction")["inputs"],
            serde_json::json!([
                { "name": "dest", "type": "address" },
                { "name": "value", "type": "uint128" },
                { "name": "cc", "type": "map(uint32,varuint32)" },
                { "name": "bounce", "type": "bool" },
                { "name": "flag", "type": "uint8" },
                { "name": "payload", "type": "cell" },
                { "name": "dapp_id", "type": "uint256" }
            ])
        );
        assert_eq!(
            function(&abi, "getCustodians")["inputs"],
            serde_json::json!([])
        );
        assert_eq!(
            function(&abi, "getVersion")["inputs"],
            serde_json::json!([])
        );
        assert_eq!(
            function(&abi, "getVersion")["outputs"],
            serde_json::json!([
                { "name": "value0", "type": "string" },
                { "name": "value1", "type": "string" }
            ])
        );
    }
}
