//! a Hot short of native gas ONLY must be told the native figure, never "nothing".

//! A live mainnet `note deploy` printed, verbatim:

//! ```text
//! Hot wallet 426c59b2...2838fe::426c59b2...2838fe is short nothing. Send it to that address; this
//! command continues by itself as soon as the balance arrives on chain.
//! ```

//! and then blocked for good on a transfer no message had ever sized. The shortfall is TWO disjoint
//! values - native vmshell gas and the ECC currency map - and the instruction rendered only the map.
//! A wallet rich in ECC[2] and low on gas is exactly the state in which that map is empty, so the
//! operator was told the sum of a missing balance was "nothing" while the gate that blocks on it
//! reads BOTH values.

//! The figures here are the live ones: the Hot held 14_022_000 raw native against this money path's
//! 507_002_000 native floor, leaving it 492_980_000 short.

use anyhow::{bail, Result};

use super::*;
use crate::cli::wallet_funding::{FundingRequirements, HotBalances};

/// The native balance the live Hot actually held.
const LIVE_NATIVE_BALANCE: u128 = 14_022_000;

/// The native floor the money path required of it.
const LIVE_NATIVE_FLOOR: u128 = 507_002_000;

/// The figure the operator was never shown, and could therefore never send.
const LIVE_NATIVE_SHORTFALL: u128 = 492_980_000;

/// What the live Hot both needed and held in ECC[2]. Equal on purpose: the currency map is empty
/// because the ECC requirement is MET, which is the whole shape of the defect.
const LIVE_SHELL_HELD: u128 = 1_000_000_000;

fn hex64(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn hot_address() -> String {
    format!("{}::{}", hex64(0x42), hex64(0x42))
}

/// The live shape, computed by the production requirement rather than asserted into being.

/// The empty currency map and the non-zero native shortfall both come out of
/// [`FundingRequirements`] against a real balance, so this reproduces the state a real run reaches
/// instead of hand-building a request that merely looks like it.
fn live_native_only_shortfall(provider: WalletProvider) -> FundingRequest {
    let shell = dexdo_core::params::SHELL_CURRENCY_ID;
    let requirements = FundingRequirements::new([(shell, LIVE_SHELL_HELD)]);
    assert_eq!(
        requirements.required_native, LIVE_NATIVE_FLOOR,
        "this regression is pinned to the native floor the live run was measured against"
    );

    let observed = HotBalances::new(LIVE_NATIVE_BALANCE, [(shell, LIVE_SHELL_HELD)]);
    let shortfall = requirements.shortfall(&observed);
    let native_shortfall = requirements.native_shortfall(&observed);

    assert!(
        shortfall.is_empty(),
        "the live Hot met every ECC requirement, which is why the map it was described by was \
         empty: {shortfall:?}"
    );
    assert_eq!(
        native_shortfall, LIVE_NATIVE_SHORTFALL,
        "the live Hot was short exactly this much native vmshell"
    );
    assert!(
        !requirements.met_by(&observed),
        "the gate blocks on this Hot, so the instruction it prints is a real funding instruction"
    );

    FundingRequest {
        provider,
        network: "net-a".to_string(),
        vault_address: (provider == WalletProvider::AckinackiWallet)
            .then(|| format!("{}::{}", hex64(0x11), hex64(0x11))),
        hot_address: hot_address(),
        hot_dapp_id: hex64(0x42),
        creator_pubkey: hex64(0xc3),
        required: requirements.required.clone(),
        required_native: requirements.required_native,
        shortfall,
        native_shortfall,
    }
}

/// A Vault that answers nothing, because rendering an instruction reads no chain.
struct SilentVault;

#[async_trait::async_trait(?Send)]
impl VaultChain for SilentVault {
    async fn queue(&self) -> Result<Vec<QueuedTransfer>> {
        bail!("rendering a funding instruction must not read the Vault queue")
    }

    async fn history(&self) -> Result<Vec<VaultQueueEvent>> {
        bail!("rendering a funding instruction must not read the Vault history")
    }

    async fn delivery_message_id(
        &self,
        _sent_event_message_id: &str,
        _destination: &str,
        _destination_dapp_id: &str,
    ) -> Result<Option<String>> {
        bail!("rendering a funding instruction must not read a Vault delivery")
    }

    async fn submit(&self, _fingerprint: &FundingFingerprint) -> Result<SubmitOutcome> {
        bail!("rendering a funding instruction must not submit anything")
    }
}

/// What an instruction has to survive to be actionable: it names the missing amount, and it never
/// tells the operator that what is missing is "nothing".
fn assert_names_the_native_shortfall(instruction: &str) {
    assert!(
        instruction.contains(&LIVE_NATIVE_SHORTFALL.to_string()),
        "an operator can only send a figure they were given: {instruction}"
    );
    assert!(
        instruction.contains("native vmshell"),
        "native gas is not an ECC currency and has to be named as its own unit: {instruction}"
    );
    assert!(
        !instruction.contains("nothing"),
        ": a Hot the gate is blocking on is never short nothing: {instruction}"
    );
}

/// The direct top-up shape - `manual` and `gosh-ai`, the one the live run printed.
#[test]
fn a_direct_top_up_instruction_names_a_native_only_shortfall() {
    for provider_kind in [WalletProvider::Manual, WalletProvider::GoshAi] {
        let provider = DirectTopUpProvider::new(provider_kind).expect("provider");
        let request = live_native_only_shortfall(provider_kind);
        let instruction = provider.manual_instruction(&request);
        assert!(instruction.contains(&hot_address()), "{instruction}");
        assert_names_the_native_shortfall(&instruction);
    }
}

/// The Vault shape. The human confirms a transfer in the wallet application, and they need the same
/// figure to check it against.
#[test]
fn the_vault_instruction_names_a_native_only_shortfall() {
    let provider = AckinackiVaultProvider::new(SilentVault, None);
    let request = live_native_only_shortfall(WalletProvider::AckinackiWallet);
    let instruction = provider.manual_instruction(&request);
    assert!(instruction.contains(&hot_address()), "{instruction}");
    assert_names_the_native_shortfall(&instruction);
}

/// Both halves are disjoint balances, so a Hot short of both is told both - and the ECC half keeps
/// the wording it already had.
#[test]
fn a_shortfall_in_both_balances_names_both() {
    let shell = dexdo_core::params::SHELL_CURRENCY_ID;
    let mut request = live_native_only_shortfall(WalletProvider::Manual);
    request.shortfall.insert(shell, 600);

    let provider = DirectTopUpProvider::new(WalletProvider::Manual).expect("provider");
    let instruction = provider.manual_instruction(&request);
    assert_names_the_native_shortfall(&instruction);
    assert!(
        instruction.contains("0.0000006 SHELL"),
        "the ECC half is unchanged: {instruction}"
    );
    assert!(
        instruction.contains(&format!(
            "{LIVE_NATIVE_SHORTFALL} raw native vmshell and 0.0000006 SHELL"
        )),
        "both disjoint balances are named, in one list: {instruction}"
    );
}
