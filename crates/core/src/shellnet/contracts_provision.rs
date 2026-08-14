use anyhow::{anyhow, Result};
use base64::Engine as _;
use gosh_ackinacki::sdk::{Account, Address, KeyPair};
use tvm_block::{Deserializable, Serializable, StateInit};

/// The HTTP `User-Agent` every shellnet request carries. **Load-bearing, not decoration -- do not
/// delete it and do not let the header fall back to the library default.**
/// them). It does *not* test the header for browser-ness, so an explicit User-Agent of any kind is
/// sufficient and we send an honest one instead of impersonating a browser. Established against
/// that edge on 2026-08-02(@SeHor05, PR990): `curl` -> 200, `urllib` with its default UA -> 403,
/// `urllib` with an explicit UA -> 200. The Acki Nacki side sends its own `acki-...` identifier for
/// the same reason, recorded as mandatory in their `tests/helper/common.py`.
/// The version is taken from the crate so this identifier cannot go stale.
pub(super) const DEXDO_USER_AGENT: &str = concat!("dexdo/", env!("CARGO_PKG_VERSION"));

pub(super) fn gas_health_top_up_amount(balance: u128, min: u128, target: u128) -> Option<u128> {
    debug_assert!(target >= min);
    if balance <= min {
        let amount = target.saturating_sub(balance);
        (amount > 0).then_some(amount)
    } else {
        None
    }
}

/// ABI of the deployed contracts(`contracts/compiled`), embedded for on-chain getters.
pub(super) const SUPERROOT_ABI: &str =
    include_str!("../../../../contracts/compiled/airegistry/SuperRoot.abi.json");
pub(super) const ROOTPN_ABI: &str =
    include_str!("../../../../contracts/compiled/dex/RootPN.abi.json");
pub(super) const ROOTORACLE_ABI: &str =
    include_str!("../../../../contracts/compiled/dex/RootOracle.abi.json");
pub(super) const ORACLE_ABI: &str =
    include_str!("../../../../contracts/compiled/dex/Oracle.abi.json");
pub(super) const ORACLEEVENTLIST_ABI: &str =
    include_str!("../../../../contracts/compiled/dex/OracleEventList.abi.json");
pub(super) const PMP_ABI: &str = include_str!("../../../../contracts/compiled/dex/PMP.abi.json");
pub(super) const ORDERBOOK_ABI: &str =
    include_str!("../../../../contracts/compiled/dex/OrderBook.abi.json");
pub(super) const PMP_TVC: &[u8] = include_bytes!("../../../../contracts/compiled/dex/PMP.tvc");
pub(super) const ORDERBOOK_TVC: &[u8] =
    include_bytes!("../../../../contracts/compiled/dex/OrderBook.tvc");
pub(super) const ROOTMODEL_ABI: &str =
    include_str!("../../../../contracts/compiled/airegistry/RootModel.abi.json");
pub(super) const TOKENCONTRACT_ABI: &str =
    include_str!("../../../../contracts/compiled/airegistry/TokenContract.abi.json");
/// `PrivateNote`(zk-note) -- ABI of the deal's owner methods (`deployInferenceOrderBook`,
/// `postSellOffer`, `placeInferenceBuy`, `streamStop`, getter `getInferenceOrderBookAddress`).
/// Minted via RootPN(gosh-dexdo `mint_pn_pool`); the signatures of these 5 methods match the
/// deployed code byte-for-byte -- the note accepts our calls(see the live test).
pub(super) const PRIVATENOTE_ABI: &str =
    include_str!("../../../../contracts/compiled/dex/PrivateNote.abi.json");
/// `PrivateNote` StateInit(`.tvc`), test-only. The CLI never deploys `PrivateNote` -- RootPN does,
/// from the code installed by `setPrivateNoteCode` -- and no production path may treat this vendored
/// image as evidence about the live chain.
#[cfg(test)]
pub(super) const PRIVATENOTE_TVC: &[u8] =
    include_bytes!("../../../../contracts/compiled/dex/PrivateNote.tvc");

// The 4.0.33 generation `doctor` holds the chain to. It compares the chain against THESE, never
// against a vendored `.tvc`: an embedded image travels in the same vendoring commit as the constant
// beside it, so comparing the two proves only that they were committed together and stays green when
// the chain moves away from both.
// One `Fail` makes `ShellnetDoctorReport::is_ok` false and `shellnet_doctor_preflight` turns that
// into a `bail!` ahead of provision, seller, buyer, `note deploy` and `note withdraw` -- so a pin
// left behind here refuses a valid current note before any note guard is consulted. They are
// maintained by hand, on the same cadence as `contracts/deployed.shellnet.json`, and a redeploy that
// moves any of them must move it here in the same change.

/// `SuperRoot` at `0:0c0c...`.
pub(super) const SHELLNET_SUPERROOT_CODE_HASH: &str =
    "7591c2b58646b793d01965e123603c879f125d875f47da8d612224ea0589b1ea";
/// `RootPN` at `0:1010...`. Compiled with `sold_old`(v1 ext-out), which preserves the
/// `VoucherGenerated` format consumed by the voucher prover. Several images answer the same
/// `getVersion()`, so this hash rather than the version getter identifies the generation. Like
/// `PRIVATENOTE_PINNED_CODE_HASH` it is a statement about the chain and NOT a property of any
/// vendored image -- the CLI never deploys RootPN and this tree carries no RootPN `.tvc`, so it
/// moves on its own.
pub(super) const SHELLNET_ROOTPN_V1_CODE_HASH: &str =
    "8ee7225d4e928296e92c76b0d00efc181a4d7f47ba2ce8825d5fb935658f9703";
/// `RootOracle` at `0:1515...`.
pub(super) const SHELLNET_ROOTORACLE_CODE_HASH: &str =
    "7876890031636ab669fd488e12009e43a3cc8cadb3dce975e11b18bfb8e7e84d";
/// The per-model `InferenceOrderBook`, which RootPN deploys from the code installed by
/// `setInferenceOrderBookCode`.
pub(super) const SHELLNET_INFERENCE_ORDERBOOK_CODE_HASH: &str =
    "2fa52109d6f38fc3640f35febcb73300a9f96a7a3558bb4ae6b4e00374420016";
/// `TokenContract` StateInit(`.tvc`) -- deployed via `build_deploy` (step 2: the seller provisions
/// the per-deal TC). Its code-hash == the `RootModel.TOKEN_CONTRACT_CODE_HASH` pin(offline guard), so
/// the derived address matches `RootModel.getTokenContractAddress` and registration is accepted.
pub(super) const TOKENCONTRACT_TVC: &[u8] =
    include_bytes!("../../../../contracts/compiled/airegistry/TokenContract.tvc");
/// `RootModel` StateInit(`.tvc`).
/// **NOBODY DEPLOYS THIS FROM HERE ANY MORE.** The comment used to read "the seller(model owner)
/// deploys their own RootModel under SuperRoot themselves (self-register: the ctor calls
/// `SuperRoot.registerRoot`)", and both halves of that are gone: `SuperRoot.deployRootModel` performs
/// the deploy from the code SuperRoot itself pins(`contracts/airegistry/SuperRoot.sol:189`), and
/// `registerRoot` -- the announcement a self-deployed root made -- was removed along with the interface
/// that declared it. An external deploy of this image is refused, `ERR_INVALID_SENDER = 302`
/// (`contracts/airegistry/RootModel.sol:67`).
/// The image is kept as the offline counterpart of [`SUPERROOT_PINNED_RM_CODE_HASH`]: hashing it is
/// what proves the RootModel artifact in this tree is the one SuperRoot's pin names. It is no longer
/// deployment input.
/// `#[allow(dead_code)]` because the CLI does not deploy this contract: the image has no production
/// reader and only the offline pin regression hashes it.
#[allow(dead_code)]
pub(super) const ROOTMODEL_TVC: &[u8] =
    include_bytes!("../../../../contracts/compiled/airegistry/RootModel.tvc");
/// The `TOKEN_CONTRACT_CODE_HASH` pin from `contracts/airegistry/RootModel.sol` -- against it RootModel
/// checks the TC code when registering a deal. The embedded `TokenContract.tvc` must yield this hash.
pub(super) const ROOTMODEL_PINNED_TC_CODE_HASH: &str =
    "a67e1ae0a748f902b248a035eabbcfc6393b3154fed7d7002e0defae8b6d685d";
/// The `ROOT_MODEL_CODE_HASH` pin from `contracts/airegistry/SuperRoot.sol` -- the hash SuperRoot's own
/// `_rootModelCode` must carry, and therefore the hash of the code `deployRootModel` puts on chain. The
/// embedded `RootModel.tvc` must yield it, otherwise this tree's idea of a RootModel is not the one the
/// live SuperRoot deploys and every address derived from it is wrong.
/// It used to say SuperRoot "checks the RootModel code at `registerRoot`". There is no such check and
/// no such entry: `registerRoot` verified a self-deployed root's *address*, and it was removed when
/// SuperRoot took over the deploy.
pub(super) const SUPERROOT_PINNED_RM_CODE_HASH: &str =
    "287831837ad23d5216956ccca347c65eecb31b56eb95e7ce0fe3bbf9f2edcff4";
/// The code-hash of the `PrivateNote` that `RootPN` mints for the 4.0.34 generation. The
/// orphaned-note guard(`assert_seller_note_current`) requires the seller note's on-chain
/// `code_hash` to equal this, so a value that lags the chain makes the binary refuse every NEWLY
/// minted note.
/// What this constant is about is the chain, NOT a property of the `PRIVATENOTE_TVC` vendored here:
/// the CLI never deploys `PrivateNote` (RootPN does, from the code installed by
/// `setPrivateNoteCode`), so the embedded image may legitimately lag. Tying this constant to that
/// image is what let 4.0.33 go live unnoticed -- a test that hashed the vendored `.tvc` and compared
/// it to the constant beside it stayed green while both drifted away from the chain together.
/// `doctor_compares_every_generation_pin_and_never_a_vendored_image` pins the real relationship
/// instead: `doctor` compares this constant against RootPN's on-chain pin, and nothing in production
/// hashes an image.
/// Update on every PrivateNote redeploy.
pub(super) const PRIVATENOTE_PINNED_CODE_HASH: &str =
    "57e85fa67cc90284b907ea7e9d8c6d35830c02d14bd04d4be6ec884b5748ca0c";

pub(super) fn normalize_code_hash(raw: &str) -> Option<String> {
    let h = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
    if h.is_empty() || h.len() > 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("{h:0>64}").to_lowercase())
}

/// (pure, offline-testable): an account must carry the current pinned `PrivateNote`
/// code. The async seller guard and read-only note balance command share this identity check.
fn private_note_code_hash_is_current(code_hash: Option<&str>) -> bool {
    code_hash
        .and_then(normalize_code_hash)
        .is_some_and(|hash| hash == PRIVATENOTE_PINNED_CODE_HASH)
}

pub(super) fn note_code_hash_current(note: &Address, code_hash: Option<&str>) -> Result<()> {
    let note = crate::address::display(&note.to_string());
    if private_note_code_hash_is_current(code_hash) {
        Ok(())
    } else {
        Err(anyhow!(
            "seller note {note} code_hash {} != the current PrivateNote code {PRIVATENOTE_PINNED_CODE_HASH} \
             -- the pn_pool predates a contract redeploy (orphaned). Re-mint against the current contracts \
             (`mint_pn_pool`) and point DEXDO_PN_POOL at the fresh pool.",
            code_hash.unwrap_or("<none>")
        ))
    }
}

pub(super) fn seller_note_account_current(note: &Address, account: Option<&Account>) -> Result<()> {
    let note_display = crate::address::display(&note.to_string());
    let account = account.ok_or_else(|| {
        anyhow!(
            "seller note {note_display} is not on-chain -- the pn_pool is likely orphaned by a contract redeploy \
             (SuperRoot/PrivateNote rotation). Re-mint against the current contracts (`mint_pn_pool`) and \
             point DEXDO_PN_POOL at the fresh pool."
        )
    })?;
    if !account.is_active() {
        return Err(anyhow!(
            "seller note {note_display} is {}, not Active -- re-mint the pn_pool against the current contracts \
             (`mint_pn_pool`); a pool minted before a SuperRoot redeploy is orphaned.",
            account.status
        ));
    }
    note_code_hash_current(note, account.code_hash.as_deref())
}

pub(super) fn note_balance_private_note_account(
    note: &Address,
    account: Option<&Account>,
) -> Result<()> {
    let note_display = crate::address::display(&note.to_string());
    let account = account.ok_or_else(|| {
        anyhow!("PrivateNote account {note_display} is not Active/not found (account snapshot absent)")
    })?;
    if !account.is_active() {
        return Err(anyhow!(
            "PrivateNote account {note_display} is not Active/not found (status: {})",
            account.status
        ));
    }
    if !private_note_code_hash_is_current(account.code_hash.as_deref()) {
        return Err(anyhow!(
            "note {note_display} is not current PrivateNote: actual code_hash {}, expected code_hash \
             {PRIVATENOTE_PINNED_CODE_HASH}",
            account.code_hash.as_deref().unwrap_or("<none>")
        ));
    }
    Ok(())
}

/// Fund-safety guard for `note withdraw`: pure code-hash generation check.
/// A note whose on-chain `code_hash` is not the current `PRIVATENOTE_PINNED_CODE_HASH` was deployed
/// by a previous contract generation; the current-generation `withdrawTokens` zeroes it without
/// crediting the destination, so the SHELL is lost. Refuse before any on-chain write.
pub(super) fn note_withdraw_generation_ok(note: &Address, code_hash: Option<&str>) -> Result<()> {
    let note = crate::address::display(&note.to_string());
    match code_hash {
        Some(h) if h == PRIVATENOTE_PINNED_CODE_HASH => Ok(()),
        other => Err(anyhow!(
            "REFUSING to withdraw from note {note}: it was deployed by a PREVIOUS contract generation \
             (code_hash {}, current is {PRIVATENOTE_PINNED_CODE_HASH}). Withdrawing from a \
             previous-generation note with this CLI zeroes the note WITHOUT crediting the destination \
             -- the SHELL is lost (dexdo-cli). This CLI will not submit the withdraw.",
            other.unwrap_or("<none>")
        )),
    }
}

#[cfg(test)]
mod withdraw_generation_tests {
    use super::*;

    fn any_note() -> Address {
        Address::parse(&format!("0:{}", "1".repeat(64))).unwrap()
    }

    #[test]
    fn withdraw_allows_current_generation_note() {
        assert!(
            note_withdraw_generation_ok(&any_note(), Some(PRIVATENOTE_PINNED_CODE_HASH)).is_ok()
        );
    }

    #[test]
    fn withdraw_refuses_previous_generation_note() {
        // The two previous-generation hashes from dexdo-cli that zeroed notes without crediting.
        for stale in [
            "210add370000000000000000000000000000000000000000000000000000000a",
            "76acd39200000000000000000000000000000000000000000000000000000007",
        ] {
            let err = note_withdraw_generation_ok(&any_note(), Some(stale))
                .unwrap_err()
                .to_string();
            assert!(err.contains("REFUSING to withdraw"), "message: {err}");
            assert!(err.contains(stale), "must name the stale hash: {err}");
            assert!(
                err.contains(PRIVATENOTE_PINNED_CODE_HASH),
                "must name the current hash: {err}"
            );
        }
    }

    #[test]
    fn withdraw_refuses_note_with_no_code_hash() {
        assert!(note_withdraw_generation_ok(&any_note(), None).is_err());
    }
}

#[cfg(test)]
mod note_balance_identity_tests {
    use super::*;

    fn note() -> Address {
        Address::parse(&format!("0:{}", "2".repeat(64))).unwrap()
    }

    /// The same note in the canonical `<dapp_id>::<account_id>` form the diagnostics render:
    /// a `PrivateNote` is a system contract of the shared dexdo DApp.
    fn canonical_note() -> String {
        format!("{}::{}", crate::address::DEXDO_DAPP_ID, "2".repeat(64))
    }

    fn account(
        status: &str,
        code_hash: Option<&str>,
        balance: u128,
        ecc: Vec<(u32, u128)>,
    ) -> Account {
        Account {
            address: note(),
            status: status.to_string(),
            balance,
            ecc,
            code_hash: code_hash.map(str::to_string),
            boc: None,
        }
    }

    #[test]
    fn missing_and_inactive_accounts_are_not_private_notes() {
        let note = note();
        let missing = note_balance_private_note_account(&note, None)
            .unwrap_err()
            .to_string();
        assert!(missing.contains(&canonical_note()), "{missing}");
        assert!(missing.contains("not Active/not found"), "{missing}");

        for status in ["NonExist", "Uninit"] {
            let account = account(status, None, 0, Vec::new());
            let error = note_balance_private_note_account(&note, Some(&account))
                .unwrap_err()
                .to_string();
            assert!(error.contains(&canonical_note()), "{error}");
            assert!(error.contains("not Active/not found"), "{error}");
            assert!(error.contains(status), "{error}");
        }
    }

    #[test]
    fn active_wrong_code_hash_names_actual_and_expected_identity() {
        let note = note();
        let actual = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let account = account("Active", Some(actual), 0, Vec::new());
        let error = note_balance_private_note_account(&note, Some(&account))
            .unwrap_err()
            .to_string();
        assert!(error.contains(&canonical_note()), "{error}");
        assert!(error.contains("not current PrivateNote"), "{error}");
        assert!(error.contains(actual), "{error}");
        assert!(error.contains(PRIVATENOTE_PINNED_CODE_HASH), "{error}");
    }

    #[test]
    fn current_private_note_accepts_zero_and_funded_balances() {
        let note = note();
        for account in [
            account("Active", Some(PRIVATENOTE_PINNED_CODE_HASH), 0, Vec::new()),
            account(
                "Active",
                Some(&format!(
                    "0x{}",
                    PRIVATENOTE_PINNED_CODE_HASH.to_uppercase()
                )),
                5_000_000_123,
                vec![(2, 1_234_567_890)],
            ),
        ] {
            note_balance_private_note_account(&note, Some(&account)).unwrap();
        }
    }

    #[test]
    fn seller_missing_and_inactive_keep_orphan_remint_diagnostics() {
        let address = note();
        // the diagnostic names the note canonically; every other byte of it is unchanged.
        let note = canonical_note();
        let missing = seller_note_account_current(&address, None)
            .unwrap_err()
            .to_string();
        assert_eq!(
            missing,
            format!(
                "seller note {note} is not on-chain -- the pn_pool is likely orphaned by a contract redeploy \
                 (SuperRoot/PrivateNote rotation). Re-mint against the current contracts (`mint_pn_pool`) and \
                 point DEXDO_PN_POOL at the fresh pool."
            )
        );

        let account = account("Uninit", None, 0, Vec::new());
        let inactive = seller_note_account_current(&address, Some(&account))
            .unwrap_err()
            .to_string();
        assert_eq!(
            inactive,
            format!(
                "seller note {note} is Uninit, not Active -- re-mint the pn_pool against the current contracts \
                 (`mint_pn_pool`); a pool minted before a SuperRoot redeploy is orphaned."
            )
        );
    }
}

/// `InferenceOrderBook` -- ABI of the on-chain offer/order book.
pub(super) const INFERENCE_ORDERBOOK_ABI: &str =
    include_str!("../../../../contracts/compiled/airegistry/InferenceOrderBook.abi.json");
/// `InferenceOrderBook` StateInit(`.tvc`) -- the **code-cell** is extracted from it, which the note
/// passes to `deployInferenceOrderBook(code,...)`(the book address is deterministic from code+params).
pub(super) const INFERENCE_ORDERBOOK_TVC: &[u8] =
    include_bytes!("../../../../contracts/compiled/airegistry/InferenceOrderBook.tvc");
pub(super) const ROOTPN_ADDR: &str =
    "0:1010101010101010101010101010101010101010101010101010101010101010";
pub(super) const ROOTORACLE_ADDR: &str =
    "0:1515151515151515151515151515151515151515151515151515151515151515";
/// Decode a hex string(TVM ABI `bytes` output) without an external dependency.
pub(super) fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(anyhow!("odd hex length"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
        .collect()
}

/// Derive a note's ed25519 public key(`[u8; 32]`) from its owner [`KeyPair`] -- the same derivation
/// `RealNote::pubkey` uses(`KeyPair::public_hex` -> bytes). Used by `dexdo recover` to verify the
/// recover note is the deal's recorded buyer(`getBuyerPubkey`) before signing STOP.
pub fn keypair_ed_pubkey(keys: &KeyPair) -> Result<[u8; 32]> {
    let bytes = decode_hex(keys.public_hex().trim_start_matches("0x"))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "ed25519 public key: expected 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut ed = [0u8; 32];
    ed.copy_from_slice(&bytes);
    Ok(ed)
}

/// Encode bytes to hex(a TVM ABI `bytes` argument, e.g. `endpointCipher`; and code-hash comparison).
/// `write!` directly into the buffer -- without allocating a `String` per byte.
pub(super) fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Extract the **code-cell** from a `.tvc`(StateInit BOC) -- the same logic as
/// `airegistry::abi::Contract::code_cell` in the SDK: `read_single_root_boc` -> `StateInit` -> `.code`.
pub(super) fn code_cell(tvc: &[u8]) -> Result<tvm_types::Cell> {
    let cell = tvm_types::read_single_root_boc(tvc).map_err(|e| anyhow!("read tvc BOC: {e}"))?;
    let state_init =
        StateInit::construct_from_cell(cell).map_err(|e| anyhow!("parse StateInit: {e}"))?;
    state_init
        .code
        .ok_or_else(|| anyhow!("no code-cell in StateInit"))
}

/// The `.tvc` code-cell as base64-BOC -- the encoding of a `cell` argument in TVM ABI(`call`/`run_getter`).
pub(super) fn code_boc_b64(tvc: &[u8]) -> Result<String> {
    let boc = tvm_types::write_boc(&code_cell(tvc)?).map_err(|e| anyhow!("write code BOC: {e}"))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(boc))
}

/// Hex `tvm.hash` of a `.tvc` code-cell. Test-only: `doctor` compares the chain against the live
/// generation pins, never against a vendored image, so nothing in production hashes a `.tvc`.
#[cfg(test)]
pub(super) fn code_hash(tvc: &[u8]) -> Result<String> {
    Ok(encode_hex(code_cell(tvc)?.repr_hash().as_slice()))
}

/// Derive the canonical per-model order-book address from the pinned TVC and model hash.
pub(super) fn inference_orderbook_address_from_model_hash(model_hash: &str) -> Result<Address> {
    let hash = model_hash
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    if hash.len() != 64 || !hash.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(anyhow!("model hash must be exactly 32 bytes of hex"));
    }
    let root = tvm_types::read_single_root_boc(INFERENCE_ORDERBOOK_TVC)
        .map_err(|error| anyhow!("read InferenceOrderBook TVC: {error}"))?;
    let mut state_init = StateInit::construct_from_cell(root)
        .map_err(|error| anyhow!("parse InferenceOrderBook StateInit: {error}"))?;
    let fields = serde_json::json!({
        "_pubkey": "0x0",
        "_modelHash": format!("0x{hash}"),
    });
    let data = tvm_abi::json_abi::encode_storage_fields(
        INFERENCE_ORDERBOOK_ABI,
        Some(&fields.to_string()),
    )
    .map_err(|error| anyhow!("encode InferenceOrderBook static fields: {error}"))?
    .into_cell()
    .map_err(|error| anyhow!("build InferenceOrderBook data cell: {error}"))?;
    state_init.data = Some(data);
    let state_init = state_init
        .serialize()
        .map_err(|error| anyhow!("serialize InferenceOrderBook StateInit: {error}"))?;
    Address::parse(&format!(
        "0:{}",
        encode_hex(state_init.repr_hash().as_slice())
    ))
}
