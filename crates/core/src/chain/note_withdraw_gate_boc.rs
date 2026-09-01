//! the `withdrawTokens` gate reading taken from a note's own account BOC.

//! The decision logic is `crate::note_withdraw_gate`, which is feature-independent on purpose: the
//! eleven-gate regression the money directive asks for has to run in the DEFAULT build, or it joins
//! the feature-gated tier that rots without CI noticing. Only the DECODE needs the chain
//! ABI machinery, so only the decode lives here.

use crate::note_withdraw_gate::{note_withdraw_gate_from_storage, NoteWithdrawGate};

/// The first unclosed `withdrawTokens` gate, read from a note's own account snapshot.

/// The caller passes the account it already holds: `dexdo note balance` fetches that account to
/// report status and balances, so naming the gate costs it no extra chain read at all. That is the
/// point -- a diagnostic that cost a second round trip is one an operator learns to skip.
pub fn note_withdraw_gate_from_account_boc(account_boc: &str) -> anyhow::Result<NoteWithdrawGate> {
    let fields = super::client::RealChainBackend::decode_account_storage_fields(
        account_boc,
        super::contracts_provision::PRIVATENOTE_ABI,
        "PrivateNote",
    )?;
    Ok(note_withdraw_gate_from_storage(&fields))
}
