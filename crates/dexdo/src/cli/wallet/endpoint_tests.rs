//! Every wallet command reads through a URL, not through whatever string arrived.
//! `wallet_read_endpoint` is the one place all three of them resolve it: `wallet onboard manual`
//! and `wallet onboard gosh-ai` prove a Hot through it, `wallet remove-archived` proves one empty.
//! If the endpoint reaches the HTTP client without a scheme, every read through it fails for a
//! transport reason. Removal then refuses with "read every balance... nothing was removed" -- the
//! same words an operator sees when the Hot really does hold funds, so an empty Hot becomes as
//! unremovable as a funded one; onboarding spends its whole activation timeout on "the chain read
//! failed; retrying", measured at 600 s on the acceptance stand.
//! Measured on shellnet before the fix, with the acceptance suite's own endpoint form:
//! ```text
//! $ dexdo wallet remove-archived --binding-id ee20df7c... --endpoint dd-shellnet.ackinacki.org
//! Error: read every balance of archived binding ee20df7c... Hot 3675cd98...: read Hot... balances:
//! POST dd-shellnet.ackinacki.org/graphql; nothing was removed
//! $ dexdo wallet remove-archived --binding-id ee20df7c... --endpoint https://dd-shellnet.ackinacki.org
//! Error: archived binding ee20df7c... Hot 3675cd98... still holds native=338236924000 and
//! ECC[2]=4100000000000; refusing permanent removal
//! ```

use super::*;

#[test]
fn bare_host_endpoint_becomes_a_url() {
    let resolved = wallet_read_endpoint(
        Some("dd-shellnet.ackinacki.org"),
        WalletNetwork::Shellnet,
    )
    .expect("a bare host is a valid endpoint");
    assert_eq!(resolved, "https://dd-shellnet.ackinacki.org");
}

#[test]
fn explicit_url_is_kept_as_given() {
    let resolved =
        wallet_read_endpoint(Some("https://dd-shellnet.ackinacki.org"), WalletNetwork::Shellnet)
            .expect("an explicit URL is a valid endpoint");
    assert_eq!(resolved, "https://dd-shellnet.ackinacki.org");
}

#[test]
fn each_network_falls_back_to_its_own_default() {
    for network in [WalletNetwork::Shellnet, WalletNetwork::Mainnet] {
        let resolved = wallet_read_endpoint(None, network).expect("default endpoint");
        assert!(
            resolved.starts_with("https://"),
            "{network} default endpoint {resolved} is not a URL"
        );
    }
}

#[test]
fn an_empty_endpoint_names_the_flag_that_carried_it() {
    let error = wallet_read_endpoint(Some("   "), WalletNetwork::Shellnet)
        .expect_err("an empty endpoint cannot be read from");
    assert!(
        error.to_string().contains("--endpoint"),
        "the refusal names the flag the operator passed: {error}"
    );
}

// The other half of that message -- the wording used when no `--endpoint` was passed -- has no test
// here: both network defaults are constants and both are valid URLs, so the branch is unreachable
// without replacing them. `each_network_falls_back_to_its_own_default` proves that.
