//! Order-book display command handler(Track C6, move-only).

use crate::cli::args::OrdersArgs;
#[cfg(feature = "shellnet")]
use crate::cli::args::OrdersCommand;
#[cfg(feature = "shellnet")]
use crate::cli::commands::{
    direct_chain_read_with_timeout, fold_snapshot_from_orders, model_target_from_config,
    read_book_target, resolve_order_book_target, retry_executable_read, target_from_market,
    BookTarget,
};
#[cfg(feature = "shellnet")]
use crate::cli::support::read_secret_hex;
use anyhow::{bail, Result};
#[cfg(feature = "shellnet")]
use dexdo_core::address as addr;
#[cfg(feature = "shellnet")]
use dexdo_core::shellnet::BookEventFold;
#[cfg(feature = "shellnet")]
use dexdo_core::{OrderBookOrder, OrderBookSnapshot};

/// An `orders` snapshot together with its provenance: which read path produced the rows and
/// the freshness marker that came with them.
#[cfg(feature = "shellnet")]
struct OrdersView {
    snapshot: OrderBookSnapshot,
    rows: &'static str,
    last_update_id: String,
}

#[cfg(feature = "shellnet")]
async fn read_live_order_snapshot(
    chain: &dexdo_core::RealChainBackend,
    target: &BookTarget,
    order_book: &str,
) -> Result<OrdersView> {
    match retry_executable_read("order-book event fold", || async {
        let fold = chain
            .fold_order_book_events(order_book, BookEventFold::default())
            .await?;
        let last_update_id = fold.last_seen_id().unwrap_or("-").to_string();
        Ok((
            fold_snapshot_from_orders(target, order_book, fold.live_orders()),
            last_update_id,
        ))
    })
    .await
    {
        Ok((snapshot, last_update_id)) => Ok(OrdersView {
            snapshot,
            rows: crate::cli::provenance::ROWS_CHAIN_EVENTS,
            last_update_id,
        }),
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "order-book event fold unavailable; using legacy chain fallback");
            let snapshot = retry_executable_read("legacy order-book fallback", || {
                read_book_target(chain, target)
            })
            .await?;
            Ok(OrdersView {
                snapshot,
                rows: crate::cli::provenance::ROWS_CHAIN_GETTERS,
                last_update_id: "-".to_string(),
            })
        }
    }
}

/// say where these rows came from and how fresh they are, in the same vocabulary
/// `dexdo market` uses, so the two views can be compared key for key instead of reading as
/// contradictory truth. `orders` never consults the indexer, so `source` is always `chain`.
#[cfg(feature = "shellnet")]
fn render_orders_context(view: &OrdersView, as_of: u64, owner: &str) -> String {
    format!(
        "orders {} owner={owner}",
        crate::cli::provenance::render(
            "chain",
            &view.last_update_id,
            as_of,
            view.rows,
            crate::cli::provenance::SCOPE_OWNER_RESTING,
        )
    )
}

#[cfg(feature = "shellnet")]
fn own_orders<'a>(snapshot: &'a OrderBookSnapshot, note_addr: &str) -> Vec<&'a OrderBookOrder> {
    let want = dexdo_core::normalize_wallet_address(note_addr)
        .unwrap_or_else(|_| note_addr.trim().to_string());
    snapshot
        .orders
        .iter()
        .filter(|o| {
            dexdo_core::normalize_wallet_address(&o.owner_note)
                .map(|owner| owner == want)
                .unwrap_or_else(|_| o.owner_note.eq_ignore_ascii_case(&want))
        })
        .collect()
}

#[cfg(feature = "shellnet")]
fn render_order_line(order: &OrderBookOrder) -> String {
    let side = if order.is_buy { "buy" } else { "sell" };
    let tc = order.token_contract.as_deref().unwrap_or("-");
    format!(
        "order_id={} side={} owner={} token_contract={} price_per_tick={} ticks={} deadline={}",
        order.order_id,
        side,
        addr::display(&order.owner_note),
        addr::display(tc),
        order.price_per_tick,
        order.ticks,
        order.deadline
    )
}

#[cfg(feature = "shellnet")]
pub(crate) async fn run_orders(args: OrdersArgs) -> Result<()> {
    let note_addr = args.identity.note_addr.as_deref().ok_or_else(|| {
        anyhow::anyhow!("orders requires --note-addr (the owner PrivateNote to filter/cancel)")
    })?;
    let chain = dexdo_core::RealChainBackend::connect(
        args.contracts
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("--contracts: non-printable path"))?,
    )?;
    let target = if let Some(market) = args.market.as_deref() {
        if args.model.is_some() {
            bail!("--market and --model are mutually exclusive for orders");
        }
        target_from_market(market)?
    } else {
        model_target_from_config(
            &args.models,
            args.model
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("orders without --market requires --model"))?,
            Some(note_addr.to_string()),
        )?
    };
    let view = direct_chain_read_with_timeout(args.read_timeout.read_timeout_secs, async {
        let order_book = resolve_order_book_target(&chain, &target).await?;
        read_live_order_snapshot(&chain, &target, &order_book).await
    })
    .await?;
    let as_of = crate::cli::provenance::now_unix();
    let snapshot = &view.snapshot;
    let own = own_orders(snapshot, note_addr);
    match args.command {
        OrdersCommand::List => {
            // the provenance line comes FIRST, so a divergence from `dexdo market` is read
            // as a different source/scope before the rows are compared.
            println!("{}", render_orders_context(&view, as_of, note_addr));
            if own.is_empty() {
                println!(
                    "orders model={} order_book={} owner={} none=true",
                    snapshot.frame_model,
                    addr::display(&snapshot.order_book),
                    addr::display(note_addr)
                );
            } else {
                for order in own {
                    println!("{}", render_order_line(order));
                }
            }
        }
        OrdersCommand::Show { order_id } => {
            let order = own
                .into_iter()
                .find(|o| o.order_id == order_id)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "order {order_id} is not a resting order owned by note {note_addr} in {}",
                        snapshot.order_book
                    )
                })?;
            println!("{}", render_orders_context(&view, as_of, note_addr));
            println!("{}", render_order_line(order));
        }
        OrdersCommand::Cancel { order_id } => {
            let order = own
                .into_iter()
                .find(|o| o.order_id == order_id)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "refusing to cancel: order {order_id} is not owned by note {note_addr} in {}",
                        snapshot.order_book
                    )
                })?;
            let note_key = args.identity.note_key.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "orders cancel requires --note-key to sign the PrivateNote owner method"
                )
            })?;
            let note = dexdo_core::Address::parse(note_addr)
                .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
            let keys = dexdo_core::KeyPair::from_secret_hex(
                read_secret_hex(note_key, "--note-key")?.trim(),
            )
            .map_err(|e| anyhow::anyhow!("--note-key (SDK secret hex): {e:?}"))?;
            direct_chain_read_with_timeout(
                args.read_timeout.read_timeout_secs,
                chain.assert_note_owner_matches("orders cancel", &note, &keys),
            )
            .await?;
            chain
                .cancel_inference_order(&note, &keys, &target.model_hash, order.order_id)
                .await?;
            println!(
                "cancel submitted model={} order_book={} order_id={} owner={}",
                snapshot.frame_model, snapshot.order_book, order.order_id, note_addr
            );
        }
        OrdersCommand::CancelAll => {
            if own.is_empty() {
                bail!(
                    "refusing to cancel-all: note {note_addr} has no resting orders in {}",
                    snapshot.order_book
                );
            }
            let note_key = args.identity.note_key.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "orders cancel-all requires --note-key to sign the PrivateNote owner method"
                )
            })?;
            let note = dexdo_core::Address::parse(note_addr)
                .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
            let keys = dexdo_core::KeyPair::from_secret_hex(
                read_secret_hex(note_key, "--note-key")?.trim(),
            )
            .map_err(|e| anyhow::anyhow!("--note-key (SDK secret hex): {e:?}"))?;
            direct_chain_read_with_timeout(
                args.read_timeout.read_timeout_secs,
                chain.assert_note_owner_matches("orders cancel-all", &note, &keys),
            )
            .await?;
            chain
                .cancel_all_inference_orders(&note, &keys, &target.model_hash)
                .await?;
            println!(
                "cancel-all submitted model={} order_book={} owner={} order_count={}",
                snapshot.frame_model,
                addr::display(&snapshot.order_book),
                addr::display(note_addr),
                own.len()
            );
        }
    }
    Ok(())
}

#[cfg(not(feature = "shellnet"))]
pub(crate) async fn run_orders(_args: OrdersArgs) -> Result<()> {
    bail!("orders unavailable: build with `--features shellnet`")
}

#[cfg(all(test, feature = "shellnet"))]
mod tests {
    use super::*;

    fn view(rows: &'static str, last_update_id: &str) -> OrdersView {
        OrdersView {
            snapshot: OrderBookSnapshot {
                frame_model: "openai/gpt-oss-20b".to_string(),
                model_hash: dexdo_core::model_hash_for("openai/gpt-oss-20b"),
                order_book: format!("0:{}", "d".repeat(64)),
                orders: Vec::new(),
                stats: None,
            },
            rows,
            last_update_id: last_update_id.to_string(),
        }
    }

    /// third motivating example: `orders list` and `market` must both say where their rows
    /// came from, how fresh they are, and WHICH subset of the book they show -- in the same
    /// vocabulary -- so a divergence reads as indexer lag / a different scope, not as two
    /// contradictory truths.
    #[test]
    fn orders_annotates_its_source_freshness_and_scope() {
        let owner = format!("0:{}", "a".repeat(64));
        assert_eq!(
            render_orders_context(
                &view(crate::cli::provenance::ROWS_CHAIN_EVENTS, "fold-13"),
                1_754_006_400,
                &owner
            ),
            format!(
                "orders source=chain lastUpdateId=fold-13 as_of=1754006400 \
                 rows=chain:order-book-events scope=owner-resting-orders owner={owner}"
            )
        );
        // The legacy getter fallback is a DIFFERENT source and says so.
        assert_eq!(
            render_orders_context(
                &view(crate::cli::provenance::ROWS_CHAIN_GETTERS, "-"),
                1_754_006_400,
                &owner
            ),
            format!(
                "orders source=chain lastUpdateId=- as_of=1754006400 rows=chain:getters \
                 scope=owner-resting-orders owner={owner}"
            )
        );
    }

    /// The two views must be diffable key for key -- the same keys, in the same order.
    #[test]
    fn orders_and_market_annotations_share_one_vocabulary() {
        let owner = format!("0:{}", "a".repeat(64));
        let orders = render_orders_context(
            &view(crate::cli::provenance::ROWS_CHAIN_EVENTS, "fold-13"),
            1_754_006_400,
            &owner,
        );
        let market = crate::cli::provenance::render(
            "indexer",
            "indexer-77",
            1_754_006_400,
            crate::cli::provenance::ROWS_CHAIN_EVENTS,
            crate::cli::provenance::SCOPE_EXECUTABLE_ASKS,
        );
        let keys = |line: &str| {
            line.split_whitespace()
                .filter_map(|pair| pair.split_once('='))
                .map(|(key, _)| key.to_string())
                .collect::<Vec<_>>()
        };
        // `orders` adds `owner=`; the shared prefix is identical.
        let orders_keys = keys(&orders);
        assert_eq!(orders_keys[..5], keys(&market)[..]);
        assert_eq!(orders_keys.last().map(String::as_str), Some("owner"));
        // Same scope key, different value -- the reason the row sets differ.
        assert!(orders.contains("scope=owner-resting-orders"), "{orders}");
        assert!(market.contains("scope=executable-asks"), "{market}");
    }
}
