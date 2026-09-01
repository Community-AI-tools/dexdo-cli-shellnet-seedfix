use super::*;
use crate::canonical_multisig;
use crate::params::{ACCOUNT_ACTIVATION_MAX_ATTEMPTS, ACCOUNT_ACTIVATION_POLL_INTERVAL};
use gosh_ackinacki::airegistry::deploy::DeployMessage;

const OPERATIONAL_WALLET_REQ_CONFIRMS: u8 = 1;

impl RealChainBackend {
    /// The deterministic current-canonical operational-wallet address for `keys`, without a chain
    /// write. uses one `--note-key` seed for both the note and its 1-of-1 operational wallet.
    pub async fn multisig_address(keys: &KeyPair) -> Result<Address> {
        let prepared = prepare_operational_multisig_deploy(keys).await?;
        let derived = Address::parse(&prepared.address)?;
        if let Ok(env_addr) = std::env::var("DEXDO_WALLET_ADDRESS") {
            let want =
                crate::wallet::normalize_wallet_address(&env_addr).map_err(|e| anyhow!(e))?;
            if want != derived.with_workchain().to_ascii_lowercase() {
                return Err(anyhow!(
                    "DEXDO_WALLET_ADDRESS {} does not match the seed-derived operator wallet {} \
                     (one --note-key seed controls both the note and the wallet -- the addresses must agree)",
                    crate::address::display_self_dapp(&want),
                    crate::address::display_self_dapp(&derived.with_workchain())
                ));
            }
        }
        Ok(derived)
    }

    /// Deploy the canonical 1-of-1 operator wallet after its deterministic address has been funded
    /// externally. Production has no giver: this submits only the prepared state-init and waits for
    /// the pre-funded account to become active.
    pub async fn deploy_multisig_self_funded(&self, keys: &KeyPair) -> Result<Address> {
        let prepared = prepare_operational_multisig_deploy(keys).await?;
        let addr = Address::parse(&prepared.address)?;
        self.send_deploy_with_retry(&prepared.message_boc_b64)
            .await?;
        for _ in 0..ACCOUNT_ACTIVATION_MAX_ATTEMPTS {
            if let Some(account) = self.client.get_account(&addr).await? {
                if account.is_active() {
                    return Ok(addr);
                }
            }
            tokio::time::sleep(ACCOUNT_ACTIVATION_POLL_INTERVAL).await;
        }
        Err(anyhow!(
            "multisig {} did not activate -- is it funded? (operator funds the wallet externally)",
            crate::address::display_self_dapp(&addr.with_workchain())
        ))
    }
}

/// Build the sole current-canonical operational wallet with one pubkey custodian and one required
/// confirmation. Preparing it is deterministic and performs no chain write.
pub(super) async fn prepare_operational_multisig_deploy(keys: &KeyPair) -> Result<DeployMessage> {
    let ctx = local_context()?;
    let owner = format!("0x{}", keys.public_hex());
    build_deploy(
        &ctx,
        canonical_multisig::MULTISIG_ABI_JSON,
        canonical_multisig::MULTISIG_TVC,
        json!({}),
        json!({
            "owners_pubkey": [owner],
            "owners_address": [],
            "reqConfirms": OPERATIONAL_WALLET_REQ_CONFIRMS,
            "reqConfirmsData": OPERATIONAL_WALLET_REQ_CONFIRMS,
            "value": "0",
            "minBalance": "0",
            "targetBalance": "0",
        }),
        keys.public_hex(),
        keys.secret_hex(),
    )
    .await
}
