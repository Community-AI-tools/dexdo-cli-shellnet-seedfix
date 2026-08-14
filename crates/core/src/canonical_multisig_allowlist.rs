/// The canonical funding-wallet identity, as `getVersion()` reports it.
/// These two live beside the code-hash allowlist rather than in `canonical_multisig`, which is
/// `shellnet`-gated because it embeds the ABI and the TVC: the identity a client REFUSES on is plain
/// text, so a wallet check that only compiles in the shellnet build is a check the default-features
/// test run cannot exercise. `canonical_multisig` re-exports both under either feature, so
/// `canonical_multisig::VERSION` keeps naming exactly one value.
pub const CONTRACT_NAME: &str = "UpdateCustodianMultisigWallet_v2";
pub const VERSION: &str = "2.4.0";

pub const CODE_HASH: &str = "cfcaac10d43c8dc062298cb48df097be67cddec52b9cfd558309a7549f01c1f1";
pub const LEGACY_SPENDING_CODE_HASH: &str =
    "09f596d5bb4f63d7f2b18020ee0b7c9e88114dc90010389cc594c67954655ded";
pub const SUPPORTED_SPENDING_CODE_HASHES: [&str; 2] = [LEGACY_SPENDING_CODE_HASH, CODE_HASH];

pub fn is_supported_spending_code_hash(code_hash: &str) -> bool {
    SUPPORTED_SPENDING_CODE_HASHES.contains(&code_hash)
}
