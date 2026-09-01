/// `recover` must not send the buyer after a step that does not exist.

/// Both exits of `TokenContract.stop()` selfdestruct the deal, so nothing follows a successful
/// `recover`. The line that used to be printed here named `dexdo destroy` -- the SELLER's cleanup of
/// a deployed-but-unfunded contract, a different situation reached by a different path -- and it was
/// printed unconditionally on success, so it read as an instruction rather than as background. A
/// buyer following it goes looking for the seller's key, which on a real market they will never have.

/// Asserted against the ACTION the text sends the reader to, not against its wording: the prose
/// stays free to improve, what may not come back is a second step and somebody else's key.
mod destroy_advice_1523 {
    #[test]
    fn recover_confirmation_names_no_follow_up_command_and_no_other_partys_key() {
        let tc = dexdo_core::Address::parse(&format!("0:{}", "3".repeat(64)))
            .expect("token contract address");
        let note = dexdo_core::Address::parse(&format!("0:{}", "4".repeat(64)))
            .expect("buyer note address");
        let confirmation =
            super::super::recover_confirmation(&tc, &note, &super::test_stop_receipt(&tc));

        assert!(
            !confirmation.contains("destroy"),
            "recover must not name a follow-up command: {confirmation}"
        );
        assert!(
            !confirmation.contains("seller --note-key") && !confirmation.contains("seller closes"),
            "recover must not send the buyer after the seller's key: {confirmation}"
        );
        // And it still reports what it did -- the removal took the advice, not the result.
        assert!(
            confirmation.contains("recover confirmed") && confirmation.contains("the deal STOPs"),
            "the confirmation still states the outcome: {confirmation}"
        );
    }

    /// The same rule as the test above, enforced one layer lower and WITHOUT the removed chain feature.

    /// This matters because of where the two run. `recover_confirmation` is declared
    /// `#[cfg(feature = "net-a")]`, so the behavioural test above compiles in the daily gates but
    /// EXECUTES only where that feature is on -- in practice, the live campaign. A user-path fix must
    /// not depend on somebody running a campaign, so this guard reads the source instead and runs in
    /// every default build.

    /// Coarser on purpose: it cannot say what is printed, only that the call is not back. That is
    /// exactly why it survives things the behavioural test does not.

    /// Same idiom as `recover_uses_shared_explicit_stop_while_legacy_reclaim_rejects_open` below,
    /// which slices the production half of this file the same way.
    #[test]
    fn no_destroy_guidance_call_returns_to_the_recover_path() {
        let source = include_str!("../recover.rs");
        let end = source
            .find("#[cfg(test)]")
            .expect("production/test boundary");
        let production = &source[..end];
        assert_eq!(
            production.matches("destroy_guidance(").count(),
            0,
            "`recover` names a follow-up command again: both exits of TokenContract.stop() \
             selfdestruct the deal, so there is no second step, and `dexdo destroy` needs the \
             seller's key which the buyer does not have"
        );
    }
}
