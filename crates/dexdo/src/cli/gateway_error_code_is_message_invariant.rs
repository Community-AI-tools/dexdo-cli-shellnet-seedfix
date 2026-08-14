use super::*;

#[derive(Debug)]
struct InvalidCertificateSource;

impl std::fmt::Display for InvalidCertificateSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid peer certificate: application verification failure")
    }
}

impl std::error::Error for InvalidCertificateSource {}

#[test]
fn typed_gateway_codes_are_message_invariant() {
    let cases = [
        (
            dexdo_core::error_codes::E_GATEWAY_WRONG_ENDPOINT,
            ErrorCode::GatewayAuthFailed,
            [
                "seller gateway answered but its certificate did not match the handover pin",
                "the responding peer has a different identity",
            ],
        ),
        (
            dexdo_core::error_codes::E_GATEWAY_UNREACHABLE,
            ErrorCode::GatewayConnectFailed,
            [
                "decrypted seller gateway could not be reached",
                "the peer never completed the pinned dial",
            ],
        ),
    ];

    for (code, expected, messages) in cases {
        for message in messages {
            let error = anyhow::Error::new(
                dexdo_core::DexdoError::new(code, message).with_source(InvalidCertificateSource),
            );
            assert!(format!("{error:#}").contains("invalid peer certificate"));
            assert_eq!(
                classify_error(OP_BUYER_START, &error),
                expected,
                "typed gateway classification moved with its rendered message: {message}"
            );
        }
    }
}
