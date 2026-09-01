//! - the rule itself: a fold is fast, not complete, so an empty one settles nothing.

//! These cover the shared function. The per-site tests live beside their sites, because a rule
//! asserted only here would be an assertion about the rule and not about the paths that apply it --
//! which is exactly how three call sites came to disagree while each looked correct on its own.

use super::{absence_is_confirmed_by_storage, answer_or_storage_when_empty, RowSource};
use dexdo_core::OrderBookOrder;

fn row(order_id: u128) -> OrderBookOrder {
    OrderBookOrder {
        order_id,
        owner_note: "0:owner".to_string(),
        token_contract: None,
        is_buy: false,
        price_per_tick: 1_000_000_000,
        ticks: 2,
        escrow: 0,
        deadline: 1_786_185_607,
        flags: 0,
        timestamp: 0,
    }
}

/// Silence is not an answer: the storage read decides, and says so.
#[tokio::test]
async fn an_empty_answer_is_replaced_by_storage() {
    let (rows, source) = answer_or_storage_when_empty(
        Vec::<OrderBookOrder>::new(),
        |rows| rows.is_empty(),
        || async { Ok(vec![row(3)]) },
    )
    .await
    .expect("storage answers");

    assert_eq!(rows.len(), 1);
    assert_eq!(source, RowSource::Storage);
}

/// A positive answer stands on its own -- this is a refusal to believe SILENCE, not a second opinion
/// on everything. Storage must not even be read.
#[tokio::test]
async fn a_non_empty_answer_is_kept_and_costs_no_storage_read() {
    let reads = std::cell::Cell::new(0u32);
    let (rows, source) = answer_or_storage_when_empty(
        vec![row(7)],
        |rows| rows.is_empty(),
        || {
            reads.set(reads.get() + 1);
            async { Ok(Vec::new()) }
        },
    )
    .await
    .expect("the fold answered");

    assert_eq!(rows.len(), 1);
    assert_eq!(source, RowSource::Fold);
    assert_eq!(reads.get(), 0);
}

/// An emptiness storage confirms is a measured one, and must remain reportable -- otherwise the rule
/// could only ever say "keep looking" and no command could ever act.
#[tokio::test]
async fn a_confirmed_emptiness_is_still_an_answer() {
    let (rows, source) = answer_or_storage_when_empty(
        Vec::<OrderBookOrder>::new(),
        |rows| rows.is_empty(),
        || async { Ok(Vec::new()) },
    )
    .await
    .expect("storage confirms");

    assert!(rows.is_empty());
    assert_eq!(source, RowSource::Storage);
}

/// The same rule pointed the other way: "not in the fold" may not become "the book removed it"
/// until the book agrees.
#[tokio::test]
async fn an_absence_is_only_a_removal_once_storage_agrees() {
    assert!(
        absence_is_confirmed_by_storage(3, || async { Ok(Vec::new()) })
            .await
            .expect("storage answers"),
        "storage holds no such row, so the absence is real"
    );
    assert!(
        !absence_is_confirmed_by_storage(3, || async { Ok(vec![row(3)]) })
            .await
            .expect("storage answers"),
        "the book still holds it, so reporting a removal would invent one"
    );
}
