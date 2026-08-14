use super::operator_wallet::prepare_operational_multisig_deploy;
use super::*;
use crate::canonical_multisig;
use gosh_ackinacki::airegistry::calls::encode_internal_payload;
use gosh_ackinacki::config::AiRegistryConfig;
use gosh_ackinacki::wallet::giver::GiverClient;

impl RealChainBackend {
    /// Provision an operational multisig wallet(1-of-1) for a key: deterministic deploy address
    /// -> giver fund -> submit -> `Active`. Needed to send INTERNAL calls with ECC -- e.g. the deal's
    /// funding door requires SHELL in `msg.currencies`(an external message cannot attach currency).
    pub async fn deploy_multisig(&self, keys: &KeyPair) -> Result<Address> {
        let prepared = prepare_operational_multisig_deploy(keys).await?;
        self.fund_deploy_wait(&prepared.address, &prepared.message_boc_b64)
            .await
    }

    /// The seller posts the exact `2P` seller bond: the canonical v2 wallet sends an INTERNAL
    /// `fundDeal(amount)` to the TC with `shell_ecc` SHELL(ECC[2]) via direct `sendTransaction`.
    /// Excess SHELL over the required seller bond is returned.
    /// Contracts 4.0.33 renamed `fundSellerBond()` to `fundDeal(uint128 amount)` and made the bond a
    /// figure on the call instead of the attached `msg.currencies[SHELL_ECC_ID]`; the attached ECC
    /// now only pays the deal's gas. The name and the argument are moved here so this legacy giver
    /// keeps encoding against the deployed ABI. **This wallet path is not the production path and
    /// does not settle on either generation:** both `fundSellerBond`(4.0.32) and `fundDeal`(4.0.33)
    /// require `msg.sender == _sellerNote`, and a multisig is not the seller note -- the live seller
    /// bond goes through [`RealChainBackend::note_fund_deal`].
    pub async fn fund_seller_bond(
        &self,
        wallet: &Address,
        wallet_keys: &KeyPair,
        tc: &Address,
        shell_ecc: u128,
    ) -> Result<Value> {
        let ctx = local_context()?;
        let payload = encode_internal_payload(
            &ctx,
            TOKENCONTRACT_ABI,
            DEAL_FUND_DEAL_METHOD,
            deal_fund_deal_params(shell_ecc),
        )
        .await?;
        let mut cc = serde_json::Map::new();
        cc.insert("2".to_string(), json!(shell_ecc.to_string()));
        let msg = encode_external_call(
            &ctx,
            canonical_multisig::MULTISIG_ABI_JSON,
            &wallet.with_workchain(),
            "sendTransaction",
            canonical_multisig::send_transaction_params(
                tc.with_workchain(),
                1_000_000_000,
                cc,
                false,
                1,
                payload,
            ),
            wallet_keys.public_hex(),
            wallet_keys.secret_hex(),
        )
        .await?;
        self.send_with_retry(&msg).await
    }

    /// Fund a deploy address from the shellnet giver(test SHELL) -- self-provisioning of
    /// deal contracts(directive: "the executor provisions gas/keys ITSELF"). The same giver
    /// (`AiRegistryConfig::shellnet`) and `DEXDO_USER_AGENT` path as in wallet self-provisioning.
    pub async fn giver_fund(&self, address: &str, amount: u128) -> Result<()> {
        self.giver_client()?
            .fund_deploy_address(address, amount)
            .await
    }

    /// Send an active account additional **ECC[2] SHELL** from the giver(flag 1). `fund_deploy_address` gives
    /// native gas to an uninit address, but NOT ECC[2]; a wallet that sends SHELL in internal calls
    /// (e.g. `fundDeal`) needs ECC[2] sent separately, after activation.
    pub async fn giver_send_shell(&self, address: &str, amount: u128) -> Result<()> {
        self.giver_client()?.send_shell(address, amount).await
    }

    /// Construct the shellnet giver's `GiverClient`(keys from `AiRegistryConfig::shellnet`),
    /// on top of the backend's `DEXDO_USER_AGENT` http client.
    fn giver_client(&self) -> Result<GiverClient> {
        let ctx = local_context()?;
        let cfg = AiRegistryConfig::shellnet();
        Ok(GiverClient::new(
            ctx,
            cfg.giver_address
                .as_deref()
                .ok_or_else(|| anyhow!("no giver_address in config"))?,
            cfg.giver_pubkey
                .as_deref()
                .ok_or_else(|| anyhow!("no giver_pubkey"))?,
            cfg.giver_secret
                .as_deref()
                .ok_or_else(|| anyhow!("no giver_secret"))?,
            self.client.endpoint(),
            self.http.clone(),
        ))
    }

    /// The seller provisions a per-deal `TokenContract`: `build_deploy` (varInit
    /// `{_sellerPubkey,_rootModelAddress,_nonce}` + ctor `{modelName,modelHash,pricePerTick,maxTicks,
    /// sellerNote}`, signed with the note's owner key) -> giver-fund the address -> submit -> wait for `Active`. The address
    /// is deterministic and matches `RootModel.getTokenContractAddress(sellerPubkey,nonce)`; in its ctor the TC
    /// registers itself in RootModel. Returns the address of the active `TokenContract`.
    #[allow(clippy::too_many_arguments)]
    pub async fn deploy_token_contract(
        &self,
        seller: &KeyPair,
        root_model: &Address,
        nonce: u64,
        model_name: &str,
        _tick_size: u128,
        price_per_tick: u128,
        max_ticks: u128,
        seller_note: &Address,
    ) -> Result<Address> {
        let ctx = local_context()?;
        let init_data = json!({
            "_sellerPubkey": format!("0x{}", seller.public_hex()),
            "_rootModelAddress": root_model.with_workchain(),
            "_nonce": nonce.to_string(),
        });
        let ctor = json!({
            "modelName": model_name,
            "modelHash": model_hash_for(model_name),
            "pricePerTick": price_per_tick.to_string(),
            "maxTicks": max_ticks.to_string(),
            "sellerNote": seller_note.with_workchain(),
        });
        let msg = build_deploy(
            &ctx,
            TOKENCONTRACT_ABI,
            TOKENCONTRACT_TVC,
            init_data,
            ctor,
            seller.public_hex(),
            seller.secret_hex(),
        )
        .await?;
        self.fund_deploy_wait(&msg.address, &msg.message_boc_b64)
            .await
    }

    /// Fund a deploy address from the giver, send the deploy message and wait for `Active`.
    /// The common tail of deal-contract provisioning(RootModel/TokenContract).
    async fn fund_deploy_wait(&self, address: &str, message_boc_b64: &str) -> Result<Address> {
        let addr = Address::parse(address)?;
        self.giver_fund(address, 200_000_000_000).await?;
        // Deploy-message send: tolerate the funded-uninit `/v2/account` 404.
        self.send_deploy_with_retry(message_boc_b64).await?;
        for _ in 0..40 {
            if let Some(a) = self.client.get_account(&addr).await? {
                if a.is_active() {
                    return Ok(addr);
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
        Err(anyhow!(
            "deploy {addr} did not activate within the allotted time"
        ))
    }

    /// Operator-path **ECC[2]-funded** deploy: funds an uninit deploy address with **ECC[2]
    /// SHELL** from the operator wallet, NOT native gas. This is the fix for the cross-dapp per-deal
    /// `TokenContract`: native funding of an uninit **cross-dapp** address is privileged (only the giver
    /// can -- the prior `404`), but ECC[2] is
    /// permission-free. Mirrors the SDK giver `fund_deploy_address` (`sendCurrencyWithFlag` flag 16 then
    /// 2, attaching `ecc:{2:amount}`) but from the one-custodian canonical v2 wallet via direct
    /// `sendTransaction` carrying `cc:{2: shell_ecc}`. Then send the deploy message and wait for `Active`.
    async fn fund_deploy_from_wallet_ecc(
        &self,
        wallet: &Address,
        wallet_keys: &KeyPair,
        address: &str,
        message_boc_b64: &str,
        shell_ecc: u128,
    ) -> Result<Address> {
        let ctx = local_context()?;
        let mut cc = serde_json::Map::new();
        cc.insert("2".to_string(), json!(shell_ecc.to_string()));
        // Mirror the giver `fund_deploy_address`: two ECC[2] sends to the uninit address, flags 16 then 2.
        for flags in [16u8, 2u8] {
            let fund = encode_external_call(
                &ctx,
                canonical_multisig::MULTISIG_ABI_JSON,
                &wallet.with_workchain(),
                "sendTransaction",
                canonical_multisig::send_transaction_params(
                    address.to_string(),
                    shell_ecc,
                    cc.clone(),
                    false,
                    flags,
                    String::new(),
                ),
                wallet_keys.public_hex(),
                wallet_keys.secret_hex(),
            )
            .await?;
            self.send_with_retry(&fund).await?;
        }
        // Deploy-message send: tolerate the funded-uninit `/v2/account` 404.
        self.send_deploy_with_retry(message_boc_b64).await?;
        let addr = Address::parse(address)?;
        for _ in 0..40 {
            if let Some(a) = self.client.get_account(&addr).await? {
                if a.is_active() {
                    return Ok(addr);
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
        Err(anyhow!(
            "deploy {addr} did not activate within the allotted time (ECC-funded)"
        ))
    }

    /// Operator-path `RootModel` deploy -- **this operation no longer exists.**
    /// It funded the RootModel's uninit deploy address from the operator multisig and then sent an
    /// external seller-signed deploy. 4.0.34 refuses that deploy outright: `RootModel`'s constructor
    /// opens with `require(msg.sender == _superRootAddress, ERR_INVALID_SENDER)`
    /// (`contracts/airegistry/RootModel.sol:67`, 302), so no amount of funding from any wallet makes it
    /// land. Funding it anyway would place ECC[2] at an address that will never activate.
    /// Refused here rather than silently redirected to [`deploy_root_model`](Self::deploy_root_model):
    /// the caller supplied a wallet and a gas figure, and quietly ignoring both while performing a
    /// different, unfunded operation would report success for a spend that never happened.
    pub async fn deploy_root_model_from_wallet(
        &self,
        _owner: &KeyPair,
        wallet: &Address,
        _wallet_keys: &KeyPair,
        gas: u128,
    ) -> Result<Address> {
        Err(anyhow!(
            "operator-wallet RootModel deploy is not available on contracts 4.0.34: an external \
             RootModel deploy is refused with ERR_INVALID_SENDER = 302 \
             (contracts/airegistry/RootModel.sol:67), so funding its uninit address from wallet \
             {wallet} with {gas} raw ECC[2] would strand the value at an address that never \
             activates. SuperRoot deploys the RootModel and carries its own \
             ROOT_MODEL_DEPLOY_VALUE = 5 vmshell (contracts/airegistry/SuperRoot.sol:58) -- use \
             deploy_root_model, which needs no wallet and no gas."
        ))
    }

    /// Operator-path per-deal `TokenContract` deploy: same message as
    /// [`deploy_token_contract`](Self::deploy_token_contract) but funded by the operator multisig.
    /// **Known limitation(live-verified):** the per-deal `TokenContract` is a *self-dapp* contract, and
    /// a multisig `sendTransaction` is dapp-bound -- it funds same-dapp contracts(e.g. `RootModel`) but
    /// NOT the cross-dapp TC, so this path does not yet activate the TC. The giver works only because it
    /// is privileged(`fund_deploy_address` routes cross-dapp). Operator-funded TC deploy is pending a
    /// cross-dapp funding mechanism; the same funding pattern is otherwise verified by
    /// [`deploy_root_model_from_wallet`](Self::deploy_root_model_from_wallet).
    #[allow(clippy::too_many_arguments)]
    pub async fn deploy_token_contract_from_wallet(
        &self,
        seller: &KeyPair,
        root_model: &Address,
        nonce: u64,
        model_name: &str,
        _tick_size: u128,
        price_per_tick: u128,
        max_ticks: u128,
        seller_note: &Address,
        wallet: &Address,
        wallet_keys: &KeyPair,
        shell_ecc: u128,
    ) -> Result<Address> {
        let ctx = local_context()?;
        let init_data = json!({
            "_sellerPubkey": format!("0x{}", seller.public_hex()),
            "_rootModelAddress": root_model.with_workchain(),
            "_nonce": nonce.to_string(),
        });
        let ctor = json!({
            "modelName": model_name,
            "modelHash": model_hash_for(model_name),
            "pricePerTick": price_per_tick.to_string(),
            "maxTicks": max_ticks.to_string(),
            "sellerNote": seller_note.with_workchain(),
        });
        let msg = build_deploy(
            &ctx,
            TOKENCONTRACT_ABI,
            TOKENCONTRACT_TVC,
            init_data,
            ctor,
            seller.public_hex(),
            seller.secret_hex(),
        )
        .await?;
        // fix(lead): the per-deal TC is cross-dapp -- fund its deploy with ECC[2] SHELL from the
        // operator wallet, not native gas(native to an uninit cross-dapp address needs the giver).
        self.fund_deploy_from_wallet_ecc(
            wallet,
            wallet_keys,
            &msg.address,
            &msg.message_boc_b64,
            shell_ecc,
        )
        .await
    }

    /// The seller(model owner) provisions their `RootModel` under SuperRoot.
    /// **THE GIVER HAS NO PART IN THIS ANY MORE.** It used to be `build_deploy` (varInit
    /// `{_ownerPubkey,_superRootAddress}` + ctor `{tokenContractCode}`, signed with the owner key) ->
    /// giver-fund -> submit -> `Active`, and the newborn announced itself to SuperRoot via `registerRoot`.
    /// In 4.0.34 that shape is refused, not merely obsolete: `RootModel`'s constructor opens with
    /// `require(msg.sender == _superRootAddress, ERR_INVALID_SENDER)`
    /// (`contracts/airegistry/RootModel.sol:67`, 302), and an external message has no sender.
    /// `SuperRoot.deployRootModel` performs the deploy and carries its own value, so there is nothing to
    /// fund and nothing to sign for. This now delegates to the production path -- the same call the
    /// seller makes -- and the giver-funded variant is not reachable for a RootModel at all.
    pub async fn deploy_root_model(&self, owner: &KeyPair) -> Result<Address> {
        self.deploy_root_model_note_funded(owner).await
    }
}

#[cfg(test)]
mod operational_multisig_deploy_tests {
    use super::*;

    #[tokio::test]
    async fn canonical_multisig_v2_deploy_is_deterministic() {
        let keys = KeyPair::generate();
        let first = prepare_operational_multisig_deploy(&keys)
            .await
            .expect("first canonical v2 deploy");
        let second = prepare_operational_multisig_deploy(&keys)
            .await
            .expect("second canonical v2 deploy");

        assert_eq!(first.address, second.address);
        assert!(!first.message_boc_b64.is_empty());
    }
}
