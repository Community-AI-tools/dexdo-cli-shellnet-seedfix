use super::*;
use std::cell::RefCell;
use std::collections::BTreeMap;

const FLEET_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OUTLIER_HASH: &str = "2222222222222222222222222222222222222222222222222222222222222222";

#[derive(Clone)]
struct FakeWallet {
    account: Option<WalletRefillAccountObservation>,
    custodians: std::result::Result<Vec<String>, String>,
}

#[derive(Default)]
struct FakeWalletRefillChain {
    wallets: RefCell<BTreeMap<String, FakeWallet>>,
    sends: RefCell<Vec<(String, u128)>>,
}

impl FakeWalletRefillChain {
    fn insert(
        &self,
        address: &Address,
        active: bool,
        ecc2: u128,
        code_hash: &str,
        custodian_pubkey: &str,
    ) {
        self.wallets.borrow_mut().insert(
            address.with_workchain(),
            FakeWallet {
                account: Some(WalletRefillAccountObservation {
                    active,
                    ecc2,
                    code_hash: Some(code_hash.to_owned()),
                }),
                custodians: Ok(vec![
                    normalize_wallet_pubkey(custodian_pubkey).expect("fixture pubkey")
                ]),
            },
        );
    }
}

#[async_trait::async_trait(?Send)]
impl WalletRefillChain for FakeWalletRefillChain {
    async fn wallet_account(
        &self,
        address: &Address,
    ) -> Result<Option<WalletRefillAccountObservation>> {
        Ok(self
            .wallets
            .borrow()
            .get(&address.with_workchain())
            .and_then(|wallet| wallet.account.clone()))
    }

    async fn wallet_custodian_pubkeys(&self, address: &Address) -> Result<Vec<String>> {
        self.wallets
            .borrow()
            .get(&address.with_workchain())
            .expect("fixture wallet")
            .custodians
            .clone()
            .map_err(|error| anyhow!(error))
    }

    async fn deploy_wallet(&self, _keys: &KeyPair) -> Result<Address> {
        Err(anyhow!("test did not expect a wallet deploy"))
    }

    async fn send_shell(&self, address: &Address, amount: u128) -> Result<()> {
        let key = address.with_workchain();
        let mut wallets = self.wallets.borrow_mut();
        let account = wallets
            .get_mut(&key)
            .and_then(|wallet| wallet.account.as_mut())
            .expect("funded fixture account");
        account.ecc2 = account
            .ecc2
            .checked_add(amount)
            .expect("fixture balance overflow");
        self.sends.borrow_mut().push((key, amount));
        Ok(())
    }
}

fn prepared_wallet(index: usize, address_number: u64) -> (PreparedWalletRefill, String) {
    let keys = KeyPair::generate();
    let pubkey = keys.public_hex().to_owned();
    let address =
        Address::parse(&format!("0:{address_number:064x}")).expect("deterministic fixture address");
    (
        PreparedWalletRefill {
            wallet_file: PathBuf::from("wallets.json"),
            wallet_index: index,
            address,
            keys,
            newly_added: false,
            before_active: false,
            before_ecc2: 0,
            sent_ecc2: 0,
        },
        pubkey,
    )
}

#[cfg(unix)]
#[tokio::test]
async fn active_fleet_wallet_is_not_rejected_for_noncanonical_address_derivation() {
    let directory = tempfile::tempdir().expect("private tempdir");
    let wallet_file = directory.path().join("wallets.json");
    let evidence_file = directory.path().join("evidence.json");
    let recorded_keys = KeyPair::generate();
    let differently_derived_keys = KeyPair::generate();
    let recorded_address = RealChainBackend::multisig_address(&differently_derived_keys)
        .await
        .expect("derive a different valid wallet address");
    let canonical_for_recorded_key = RealChainBackend::multisig_address(&recorded_keys)
        .await
        .expect("derive the recorded key's canonical v2 address");
    assert_ne!(
        recorded_address.with_workchain(),
        canonical_for_recorded_key.with_workchain(),
        "fixture must reproduce the noncanonical-address case"
    );

    write_private_json(
        &wallet_file,
        &WalletRefillFile {
            wallets: vec![WalletRefillRecord {
                address: recorded_address.with_workchain(),
                secret_hex: recorded_keys.secret_hex().to_owned(),
            }],
        },
    )
    .expect("write mode-0600 wallet fixture");
    let plan = WalletRefillPlan {
        wallet_files: vec![wallet_file],
        evidence_file,
        add_wallets: 0,
        add_wallet_file: None,
    };

    let (wallets, pending) = prepare_wallet_refill_plan(&plan)
        .await
        .expect("the recorded address must reach chain-backed validation");
    assert_eq!(wallets.len(), 1);
    assert!(pending.is_none());

    let chain = FakeWalletRefillChain::default();
    chain.insert(
        &recorded_address,
        true,
        WALLET_REFILL_TARGET_RAW,
        FLEET_HASH,
        recorded_keys.public_hex(),
    );
    let validation = validate_wallet_refill_fleet(&chain, wallets)
        .await
        .expect("read the fleet identity from the fake chain");
    assert_eq!(validation.fleet_code_hash, FLEET_HASH);
    assert_eq!(validation.wallets.len(), 1);
    assert!(validation.skipped.is_empty());
}

#[tokio::test]
async fn bad_entries_are_named_and_skipped_while_the_rest_are_funded_then_run_fails() {
    let (good_a, good_a_pubkey) = prepared_wallet(0, 1);
    let (bad_hash, bad_hash_pubkey) = prepared_wallet(1, 2);
    let (bad_key, _bad_key_pubkey) = prepared_wallet(2, 3);
    let (good_b, good_b_pubkey) = prepared_wallet(3, 4);
    let good_a_address = good_a.address.with_workchain();
    let bad_hash_address = bad_hash.address.with_workchain();
    let bad_key_address = bad_key.address.with_workchain();
    let good_b_address = good_b.address.with_workchain();
    let chain = FakeWalletRefillChain::default();
    chain.insert(
        &good_a.address,
        true,
        WALLET_REFILL_TARGET_RAW - 10,
        FLEET_HASH,
        &good_a_pubkey,
    );
    chain.insert(&bad_hash.address, true, 0, OUTLIER_HASH, &bad_hash_pubkey);
    chain.insert(
        &bad_key.address,
        true,
        0,
        FLEET_HASH,
        KeyPair::generate().public_hex(),
    );
    chain.insert(
        &good_b.address,
        true,
        WALLET_REFILL_TARGET_RAW - 20,
        FLEET_HASH,
        &good_b_pubkey,
    );

    let validation = validate_wallet_refill_fleet(&chain, vec![good_a, bad_hash, bad_key, good_b])
        .await
        .expect("the majority fleet identity is unambiguous");
    assert_eq!(validation.fleet_code_hash, FLEET_HASH);
    assert_eq!(validation.wallets.len(), 2);
    assert_eq!(validation.skipped.len(), 2);
    assert_eq!(validation.skipped[0].wallet_index, 1);
    assert_eq!(validation.skipped[0].address, bad_hash_address);
    assert!(validation.skipped[0].reason.contains("does not match"));
    assert_eq!(validation.skipped[1].wallet_index, 2);
    assert_eq!(validation.skipped[1].address, bad_key_address);
    assert!(validation.skipped[1]
        .reason
        .contains("not an on-chain custodian"));

    let WalletRefillValidation {
        mut wallets,
        skipped,
        ..
    } = validation;
    fund_wallet_refills(&chain, &mut wallets)
        .await
        .expect("valid fleet entries are still funded");
    assert_eq!(
        chain.sends.borrow().as_slice(),
        &[(good_a_address, 10), (good_b_address, 20)]
    );

    let error = fail_if_wallets_skipped(&skipped)
        .expect_err("a partial refill must end non-zero")
        .to_string();
    assert!(error.contains("skipped 2 wallet(s)"), "{error}");
    assert!(error.contains("wallets.json[1]"), "{error}");
    assert!(error.contains("wallets.json[2]"), "{error}");
    assert!(error.contains(&bad_hash_address), "{error}");
    assert!(error.contains(&bad_key_address), "{error}");
}
