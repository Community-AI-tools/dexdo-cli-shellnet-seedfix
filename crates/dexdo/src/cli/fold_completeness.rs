//! an event fold is FAST, not COMPLETE -- so an empty one settles nothing.

//! The book's order rows can be read two ways. Folding its ext-out events is cheap and carries
//! provenance, and it is what `orders` and the executable market view read first. Decoding the
//! book's own `_orders` out of one account snapshot is the state itself.

//! **A reader of events cannot prove it saw them all.** History is kept in a WINDOW: a node holds
//! blocks from here to there and everything older is gone, so "there were no events" and "the
//! events are outside what I can see" arrive at this code identically. Establishing which one it is
//! would take a source outside the window -- which is exactly what the storage read is. We have paid
//! for that distinction twice already: (the book was destroyed) and (the window is
//! shorter than the proof it must cover).

//! So the rule, and it is one rule rather than three call sites agreeing:

//! > An empty fold gives no right to refuse and no right to confirm. Before either, ask storage.

//! **The order is the tree's canon, not an invention here.** `crates/dexdo/src/cli/buyer.rs:7776`
//! sets it for crash recovery, in its own words: "replay the money journal before consulting the
//! durable active-record index or the bounded historical event fallback" -- authoritative state
//! first, bounded history last. and the two sites beside it had that order backwards: they
//! consulted storage only when the fold *errored*, so a fold that succeeded and saw nothing was
//! taken for the truth. This module puts the canon where those three can share it.

use anyhow::Result;
use dexdo_core::OrderBookOrder;
use std::future::Future;

/// Which source the returned rows came from, in the vocabulary `provenance` already prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowSource {
    /// The fold answered with rows, so it stands on its own.
    Fold,
    /// The fold answered with nothing, so the book's own storage was asked and its answer is used.
    Storage,
}

impl RowSource {
    pub(crate) fn provenance(self) -> &'static str {
        match self {
            Self::Fold => crate::cli::provenance::ROWS_CHAIN_EVENTS,
            Self::Storage => crate::cli::provenance::ROWS_CHAIN_GETTERS,
        }
    }
}

/// An answer to act on, with an empty fold never taken at its word.

/// A fold that answered with something is kept as-is: this is not a second opinion on a positive
/// answer, only a refusal to treat SILENCE as a fact. A fold that answered with nothing is replaced
/// by whatever the book's storage holds -- which may also be nothing, and then the emptiness is a
/// measured one rather than an assumed one.

/// Generic over the answer because the two callers hold different shapes of the same thing -- one a
/// row list, one a whole snapshot -- and splitting the rule in two so each could have its own
/// signature is exactly how the three sites came to disagree in the first place.
pub(crate) async fn answer_or_storage_when_empty<T, E, F, Fut>(
    fold_answer: T,
    is_empty: E,
    storage_read: F,
) -> Result<(T, RowSource)>
where
    E: FnOnce(&T) -> bool,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    if !is_empty(&fold_answer) {
        return Ok((fold_answer, RowSource::Fold));
    }
    Ok((storage_read().await?, RowSource::Storage))
}

/// The row-list spelling of [`answer_or_storage_when_empty`], for the caller that holds rows.
pub(crate) async fn rows_or_storage_when_empty<F, Fut>(
    fold_rows: Vec<OrderBookOrder>,
    storage_read: F,
) -> Result<(Vec<OrderBookOrder>, RowSource)>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Vec<OrderBookOrder>>>,
{
    answer_or_storage_when_empty(fold_rows, |rows| rows.is_empty(), storage_read).await
}

/// Is an order's absence from the fold a FACT about the book, or only about the window?

/// The same rule pointed the other way. `orders reconcile` reads "not in the fold" as "the book
/// removed it", which is the opposite direction from a refusal and the same mistake: a conclusion
/// drawn from silence. Storage decides.

/// Returns `true` only when the book's own rows agree the order is gone.
pub(crate) async fn absence_is_confirmed_by_storage<F, Fut>(
    order_id: u128,
    mut storage_read: F,
) -> Result<bool>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Vec<OrderBookOrder>>>,
{
    let rows = storage_read().await?;
    Ok(!rows.iter().any(|row| row.order_id == order_id))
}

#[cfg(test)]
#[path = "fold_completeness_1659_tests.rs"]
mod fold_completeness_1659_tests;
