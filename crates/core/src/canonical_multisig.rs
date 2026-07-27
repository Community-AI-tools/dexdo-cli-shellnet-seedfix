//! Canonical dexdo funding wallet artifact.
//! Source: `gosh-sh/acki-nacki` dev
//! `6ad89549a0b845ed70094b24b23fad3223cdd5e8`.

use serde_json::{Map, Value};

pub const CONTRACT_NAME: &str = "UpdateCustodianMultisigWallet_v2";
pub const VERSION: &str = "2.2.0";
pub const CODE_HASH: &str = "09f596d5bb4f63d7f2b18020ee0b7c9e88114dc90010389cc594c67954655ded";
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

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use tvm_block::Deserializable;

    const ABI_SHA256: &str = "28312c9773b1231623998a2d09d6285a8afc272e10af6b595bfabcddb320e45e";
    const TVC_SHA256: &str = "535e180e85ee019c23631c6046449fa2a5536d88f55b26d64e026d671e82d520";

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
    fn canonical_v2_artifacts_match_ackinacki_dev() {
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
