#[cfg(test)]
mod endpoint_and_resume_tests {
    use super::*;
    use crate::cli::args::WalletNetworkArg;

    fn limits() -> SessionLimits {
        session_limits(WalletOnboardingParams::canonical())
    }

    fn args_in(dir: &Path, network: WalletNetworkArg) -> WalletOnboardArgs {
        WalletOnboardArgs {
            agent_name: "fixture-agent".to_string(),
            network,
            endpoint: None,
            state: Some(dir.join("session.json")),
            hot_key: Some(dir.join("hot.key")),
            vault_key: None,
            qr_file: None,
            terminal_qr: false,
        }
    }

    /// The shape a session file has after a real `wallet_hello` was verified and the request was
    /// prepared but never published: phase `request_prepared`, and -- because the endpoint used to
    /// be recorded exactly as it arrived from `params.rs` -- an endpoint with no scheme.
    /// Modelled field by field on the operator's real pre-fix session file. The bee material is
    /// generated per run and none of it is copied from that file: a session's signing secret and DH
    /// secrets must never enter the repository.
    /// The clock is read through `std` rather than the onboarding crate's own helper: naming that
    /// crate outside `wallet_onboarding.rs` is what `ci/check-single-sdk.sh` exists to forbid, and
    /// this file is a separate path even though it compiles into that module.
    fn scheme_less_request_prepared_state(hot_pubkey: &str, endpoint: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let filler = |byte: char| byte.to_string().repeat(64);
        serde_json::to_string_pretty(&serde_json::json!({
            "file_version": 1,
            "agent_name": "fixture-agent",
            "network": "mainnet",
            "endpoint": endpoint,
            "hot_pubkey": hot_pubkey,
            "phase": {
                "name": "request_prepared",
                "request": {
                    "profile_address": format!("0:{}", filler('f')),
                    "session_id": "fixture-session-id",
                    "hello_event_id": filler('7'),
                    "context_created_at_from": now - 60,
                    "envelope_json": "{\"v\":\"bee_connect.msg/1\",\"type\":\"agent_onboard_request\"}",
                    "session_state": {
                        "encryption_root": filler('1'),
                        "my_dh_secret": filler('2'),
                        "peer_dh_public": filler('3'),
                        "signing_public": filler('4'),
                        "signing_secret": filler('5'),
                        "created_at": now - 120,
                        "expires_at": now + 3600,
                        "last_seen_seq": 1,
                        "last_sent_seq": 2,
                    },
                },
            },
        }))
        .unwrap()
    }

    /// A session file whose Hot public key matches a Hot key file written beside it, so
    /// `load_or_create_session` gets all the way past its key check to the endpoint comparison.
    fn resumable_state(dir: &Path, endpoint: &str) -> WalletOnboardArgs {
        let args = args_in(dir, WalletNetworkArg::Mainnet);
        let hot = KeyPair::generate();
        write_private_atomic(args.hot_key.as_deref().unwrap(), hot.secret_hex().as_bytes()).unwrap();
        write_private_atomic(
            args.state.as_deref().unwrap(),
            scheme_less_request_prepared_state(hot.public_hex(), endpoint).as_bytes(),
        )
        .unwrap();
        args
    }

    /// The seam the live mainnet failure came through: what `CanonicalBeeSessionIo` is handed.
    /// Not a test of `normalize_endpoint`, which was always correct and always passed -- the defect
    /// was that nothing called it before the write. So this asserts the boundary's output for the
    /// endpoints an operator can actually supply, and that the raw default is refused by the write
    /// path itself, which is what makes a bare host unable to arrive by any other route.
    #[test]
    fn the_boundary_hands_the_write_path_an_absolute_endpoint() {
        let dir = tempfile::tempdir().unwrap();

        for (network, supplied, expected) in [
            (
                WalletNetworkArg::Mainnet,
                None,
                "https://dd-mainnet.ackinacki.org",
            ),
            (WalletNetworkArg::Shellnet, None, "https://shellnet.ackinacki.org"),
            (
                WalletNetworkArg::Shellnet,
                Some("shellnet.ackinacki.org".to_string()),
                "https://shellnet.ackinacki.org",
            ),
            (
                WalletNetworkArg::Mainnet,
                Some("  dd-mainnet.ackinacki.org  ".to_string()),
                "https://dd-mainnet.ackinacki.org",
            ),
        ] {
            let args = WalletOnboardArgs {
                endpoint: supplied.clone(),
                ..args_in(dir.path(), network)
            };
            assert_eq!(
                onboarding_endpoint(&args).unwrap(),
                expected,
                "--endpoint {supplied:?} on {} must be absolute before anything downstream sees it",
                network.as_str()
            );
        }

        // A bare host must not reach the AuthProfile write: the SDK picks the `/v2/messages`
        // scheme from the configured endpoint, and a scheme-less one posts over plain http.
        for network in [WalletNetworkArg::Mainnet, WalletNetworkArg::Shellnet] {
            let raw = network.default_endpoint();
            assert!(
                CanonicalBeeSessionIo::new(raw).is_err(),
                "`{raw}` is a bare host and must be refused by the write path"
            );
        }

        // And the value the boundary produced is what durable state records, and is one the write
        // path accepts.
        let args = args_in(dir.path(), WalletNetworkArg::Mainnet);
        let state = resolve_private_file_path(args.state.as_deref().unwrap(), "state").unwrap();
        let endpoint = onboarding_endpoint(&args).unwrap();
        let (session, _keys, created) =
            load_or_create_session(&args, &endpoint, &state, limits()).unwrap();

        assert!(created);
        assert_eq!(
            session.endpoint, endpoint,
            "durable state must record the same absolute endpoint the write path is given"
        );
        assert!(
            CanonicalBeeSessionIo::new(&session.endpoint).is_ok(),
            "the endpoint the boundary produced must be accepted by the write path"
        );
    }

    #[test]
    fn a_session_holding_a_scheme_less_endpoint_still_resumes() {
        let dir = tempfile::tempdir().unwrap();
        let args = resumable_state(dir.path(), "dd-mainnet.ackinacki.org");
        let state = resolve_private_file_path(args.state.as_deref().unwrap(), "state").unwrap();
        let endpoint = onboarding_endpoint(&args).unwrap();

        let (session, _keys, created) = load_or_create_session(&args, &endpoint, &state, limits())
            .expect("a session written before the endpoint was normalised must still resume");

        assert!(!created, "resume must not create a second bee session");
        assert_eq!(
            session.phase_name(),
            "request_prepared",
            "the prepared request must survive the resume untouched"
        );
    }

    #[test]
    fn resume_still_refuses_a_genuinely_different_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let args = resumable_state(dir.path(), "dd-mainnet.ackinacki.org");
        let state = resolve_private_file_path(args.state.as_deref().unwrap(), "state").unwrap();

        // Accepting a scheme difference must not become accepting a host or a downgrade.
        for other in [
            "https://shellnet.ackinacki.org",
            "https://mainnet.example.invalid",
            "http://dd-mainnet.ackinacki.org",
        ] {
            let error = load_or_create_session(&args, other, &state, limits())
                .err()
                .map(|error| error.to_string())
                .unwrap_or_else(|| {
                    panic!("`{other}` is not the endpoint this session was built on")
                });
            assert!(
                error.contains("does not match durable onboarding state"),
                "{error}"
            );
        }
    }
}
