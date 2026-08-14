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
    /// The order ids the book's own `InferenceOrderExpired` named on this read.
    /// The fold computes this and then loses it: `LiveBookOrder::expired_by_event` has no
    /// counterpart on `OrderBookOrder`, so `fold_snapshot_from_orders` cannot carry it and the
    /// rendered row never saw it. It travels beside the snapshot rather than inside it because the
    /// snapshot is the shape BOTH read paths produce, and only one of them can know this.
    swept_order_ids: std::collections::BTreeSet<u128>,
}

/// What one read path can honestly say about the escrow behind one row.
/// Three states, not two. The two `orders` read paths do not know the same things. `getOrder`
/// returns the stored `Order`, whose `escrow` is the SHELL a bid is holding
/// (`contracts/airegistry/InferenceOrderBook.sol:259`, "BUY: SHELL budget held; SELL: 0"), and the
/// parser refuses a record that lacks it. The event fold has no such number to fold:
/// `InferenceOrderPlaced(orderId, isBuy, price, ticks, note, tokenContract, deadline, flags)`
/// (`:371`) never carries escrow, so `LiveBookOrder` has no escrow field and
/// `fold_snapshot_from_orders` fills the struct with a zero that must never reach an operator as a
/// quantity.
/// But "the fold cannot tell you the amount" was answering two different questions with one `-`
/// . For an order past its deadline the owner's question is not "how much" -- it is "is the
/// book still holding it?", and those are opposite actions: still held means run `dexdo orders
/// expire <id>` and get the money back, already swept means there is nothing to do. The fold knows
/// which, through the `InferenceOrderExpired` it deliberately treats as non-terminal, and until now
/// that knowledge stopped one layer below the row that needed it.
#[cfg(feature = "shellnet")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscrowRead {
    /// `getOrder` answered, so the number on the row is the book's own. A record the getter returned
    /// is by construction still in the book: the sweep removes it.
    Authoritative,
    /// The event fold, order still in the book: the amount is unknowable on this path, and saying so
    /// is not the same as reporting the filler zero.
    HeldAmountUnknown,
    /// The event fold, and the book's own `InferenceOrderExpired` named this order id: the book has
    /// removed it and refunded a bid's escrow(`InferenceOrderBook.sol`, the expiry sweep). A SELL
    /// commits none in the first place, so on either side the answer to "is the book holding my
    /// money for this order" is now no.
    Returned,
}

#[cfg(feature = "shellnet")]
impl OrdersView {
    /// Everything the fold read path derives from one folded book, in ONE place.
    /// `read_live_order_snapshot` reads the book and then does nothing else with what it got: the
    /// rows both read paths share come out of `fold_snapshot_from_orders`, and the one thing only
    /// this path can know -- which ids the book's own `InferenceOrderExpired` named -- is derived
    /// here, beside the `ROWS_CHAIN_EVENTS` marker that makes [`OrdersView::escrow_read`] consult
    /// it at all. Those two belong together: the marker without the ids renders every fold row as
    /// an authoritative `escrow=0`, which is the filler zero exists to keep off the row.
    /// It is a function rather than three expressions inline in the read closure because a
    /// regression that restates the derivation beside the code proves the carry the TEST performs,
    /// not the carry the read path performs -- and stays green while the read path stops carrying
    /// anything at all, which is exactly the state reported.
    fn from_fold(
        target: &BookTarget,
        order_book: &str,
        orders: &[&dexdo_core::shellnet::LiveBookOrder],
        last_update_id: String,
    ) -> Self {
        OrdersView {
            snapshot: fold_snapshot_from_orders(target, order_book, orders.iter().copied()),
            rows: crate::cli::provenance::ROWS_CHAIN_EVENTS,
            last_update_id,
            // WHICH of the visible rows the book has already swept is carried out with them.
            // The fold keeps a swept row deliberately, so the row itself has to say whether
            // the escrow behind it is still in the book or already back at the note -- the two
            // states call for opposite actions and rendered identically until this.
            swept_order_ids: orders
                .iter()
                .filter(|order| order.expired_by_event)
                .map(|order| order.order_id)
                .collect(),
        }
    }

    /// What this read can say about one row's escrow.
    fn escrow_read(&self, order: &OrderBookOrder) -> EscrowRead {
        if self.rows == crate::cli::provenance::ROWS_CHAIN_GETTERS {
            return EscrowRead::Authoritative;
        }
        if self.swept_order_ids.contains(&order.order_id) {
            return EscrowRead::Returned;
        }
        EscrowRead::HeldAmountUnknown
    }
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
        // explicit non-goal: an expired order is NOT filtered out of the owner's own list --
        // not by the deadline predicate and not by consuming `InferenceOrderExpired`. Expiry is lazy
        // on chain, so a lapsed order can sit in the book holding escrow indefinitely; hiding it
        // loses the operator's money from view. It is shown, and marked `expired=yes`.
        let orders = fold.all_orders().collect::<Vec<_>>();
        Ok(OrdersView::from_fold(
            target,
            order_book,
            &orders,
            last_update_id,
        ))
    })
    .await
    {
        Ok(view) => Ok(view),
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
                // The getters never announce a sweep; they simply stop returning the record. Every
                // row on this path is one the book still holds, and its escrow is a real number.
                swept_order_ids: std::collections::BTreeSet::new(),
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

/// `deadline` as a UTC date-time: the raw stamp stays for machines, the rendering is for the
/// operator who has to decide whether the order is still worth anything.
/// Rendered in place rather than pulled in from a date library: the workspace carries no date
/// dependency(its manifests say so deliberately for the HTTP and TLS stacks alike), `std` has no
/// calendar, and the civil-date conversion is a dozen lines pinned by tests below.
#[cfg(feature = "shellnet")]
fn render_unix_utc(seconds: u64) -> String {
    if seconds == 0 {
        // No deadline was set. The epoch would be a lie in both directions: a GTC bid never expires,
        // and a zero-deadline SELL is malformed rather than long dead.
        return "-".to_string();
    }
    // days-from-civil, inverted(Howard Hinnant's algorithm, the one every date library implements):
    // shift the era to start on 0000-03-01 so the leap day lands at the end of the 400-year cycle.
    let days = (seconds / 86_400) as i64;
    let time_of_day = seconds % 86_400;
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u64;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u64;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time_of_day / 3_600,
        (time_of_day % 3_600) / 60,
        time_of_day % 60
    )
}

/// The escrow cell, which is where an owner asks "is the book still holding my money?".
/// Never a zero stand-in. `escrow=0` is a real and meaningful reading -- every SELL rests with it --
/// so a filler zero is indistinguishable from the book saying "nothing is held here", and on a bid
/// it reads as "your money is already back" over an order that is still holding it.
/// `returned` is a word rather than a number for the same reason: the fold still has no amount to
/// report, and the one thing it does know is that the amount is no longer the book's to hold.
#[cfg(feature = "shellnet")]
fn render_escrow(order: &OrderBookOrder, escrow: EscrowRead) -> String {
    match escrow {
        EscrowRead::Authoritative => order.escrow.to_string(),
        EscrowRead::HeldAmountUnknown => "-".to_string(),
        EscrowRead::Returned => "returned".to_string(),
    }
}

#[cfg(feature = "shellnet")]
fn render_order_line(order: &OrderBookOrder, as_of: u64, escrow: EscrowRead) -> String {
    let side = if order.is_buy { "buy" } else { "sell" };
    // A bid has no deal contract to name: the book stores a BUY with `tokenContract: address(0)`
    // (`contracts/airegistry/InferenceOrderBook.sol:254,1185` -- "SELL: seller's deal contract;
    // BUY: 0"), so `-` here is the chain's own answer, not a lookup this client failed to do.
    let tc = order.token_contract.as_deref().unwrap_or("-");
    // ONE deadline predicate for every fold-backed view. `market` uses it to drop a row from
    // the executable scope; here the same verdict is a label, against the very `as_of` the context
    // line above already printed -- so the two views can be reconciled instead of second-guessed.
    // `expired` is the CLOCK's verdict and nothing more -- it is true both while the book is
    // still holding the escrow and after the book has swept it and given it back. The escrow cell is
    // what separates those two, which is why this stayed a `yes|no` deadline label.
    let expired = !dexdo_core::order_deadline_is_live(order.is_buy, order.deadline, as_of);
    // `flags` is printed unconditionally, with no authoritative/filler distinction, because
    // BOTH `orders` read paths really carry it -- `getOrder` returns the stored `Order.flags` and
    // `InferenceOrderPlaced` declares `flags` as a `uint8` the fold decodes. That is precisely what
    // separates it from `escrow` on the line above: the number is the book's, on either path.
    format!(
        "order_id={} side={} owner={} token_contract={} price_per_tick={} ticks={} escrow={} flags={} deadline={} deadline_utc={} expired={}",
        order.order_id,
        side,
        addr::display(&order.owner_note),
        addr::display_self_dapp(tc),
        order.price_per_tick,
        order.ticks,
        render_escrow(order, escrow),
        order.flags,
        order.deadline,
        render_unix_utc(order.deadline),
        if expired { "yes" } else { "no" }
    )
}

/// What `dexdo orders expire` may do about one named order id, decided before any message is sent.
#[cfg(feature = "shellnet")]
#[derive(Debug, PartialEq, Eq)]
enum ExpireAction {
    /// Nothing rests under this id for this note. The chain agrees: `expireOrder` on a gone order
    /// is a silent no-op, so this client says so and stops rather than sending a message that
    /// could only be a no-op too.
    NotResting,
    /// The book still holds it and its own deadline has not passed. `_isExpired` is
    /// `deadline != 0 && block.timestamp >= deadline`, so the sweep would do nothing -- and a client
    /// that sent it anyway would let the operator read "expired" over an order still holding money.
    StillLive { deadline: u64 },
    /// Past its own deadline and still in the book: one permissionless sweep is the whole action.
    Sweep,
}

/// The deadline verdict is [`dexdo_core::order_deadline_is_live`] -- the ONE predicate `market` and
/// `render_order_line` already use -- so the `expired=` column an operator just read and the action
/// this command takes can never disagree.
#[cfg(feature = "shellnet")]
fn expire_action(order: Option<&OrderBookOrder>, as_of: u64) -> ExpireAction {
    let Some(order) = order else {
        return ExpireAction::NotResting;
    };
    if dexdo_core::order_deadline_is_live(order.is_buy, order.deadline, as_of) {
        return ExpireAction::StillLive {
            deadline: order.deadline,
        };
    }
    ExpireAction::Sweep
}

/// Name the deadline that makes the sweep premature, so the operator learns WHEN this becomes
/// possible instead of only that it is not possible now.
#[cfg(feature = "shellnet")]
fn expire_too_early(order_id: u128, deadline: u64, as_of: u64) -> String {
    let until = if deadline == 0 {
        // A BUY may rest with deadline 0(contract-permitted GTC). Nothing will ever expire it, so
        // saying "wait" would be a lie; cancel is the only exit.
        "carries deadline 0, which never expires".to_string()
    } else {
        format!(
            "is live until unix {deadline} ({}), {} seconds after this read at unix {as_of}",
            render_unix_utc(deadline),
            deadline.saturating_sub(as_of)
        )
    };
    format!(
        "refusing to expire: order {order_id} {until}. The book sweeps an order only once its own \
         deadline has passed, so no message was sent and no escrow moved; wait for that deadline \
         or release the escrow now with `dexdo orders cancel {order_id}`"
    )
}

/// Has the book said this order left it?
/// ONE question for both removals, because two predicates that must agree are two predicates that
/// can drift. The book announces the two removals differently and the fold treats them
/// differently, and this is the single place that knows it:
/// * `InferenceOrderCancelled` is TERMINAL -- the fold drops the row
/// (`crates/core/src/shellnet/book_events.rs`), so absence IS the announcement.
/// * `InferenceOrderExpired` is deliberately NOT terminal -- it sets `expired_by_event` and the
/// row STAYS, because `dexdo orders list` must keep showing an owner a row that may still be
/// sitting in the book holding escrow.
/// So absence alone is right for one and waits forever for the other, over money that is already
/// back in the note. Both shapes together are the honest answer for either.
#[cfg(feature = "shellnet")]
fn order_has_left_the_book<'a>(
    orders: impl IntoIterator<Item = &'a dexdo_core::shellnet::LiveBookOrder>,
    order_id: u128,
) -> bool {
    orders
        .into_iter()
        .find(|order| order.order_id == order_id)
        .is_none_or(|order| order.expired_by_event)
}

/// Confirm one removal the way `subscription cancel` confirms its own: poll the authoritative book,
/// bounded by the read timeout, and read the note's spendable balance on either side of it.
/// Shared by `cancel` and `expire` -- the two differ in who may ask and in what a replay means, not
/// in what "the book removed it and the money came back" looks like.
/// The signal is the book's OWN announcement, via [`order_has_left_the_book`]. Absence from the
/// owner's row list is deliberately not asked directly: for an expiry that list keeps the row on
/// purpose, and waiting for it to disappear waits forever.
/// The credit reported is one this client OBSERVED. It is never derived from the row's `escrow`
/// field, which the event-fold read path does not carry at all(`escrow=-`) -- computing a refund
/// from a number the book did not hand us is exactly the invented money E2E-CXL-14 forbids.
/// `InferenceOrderCancelled` does carry a `refunded` field; it is deliberately NOT used as the
/// figure here, so that one command cannot report a refund a different way from the other.
#[cfg(feature = "shellnet")]
async fn reconcile_order_removal(
    chain: &dexdo_core::RealChainBackend,
    order_book: &str,
    note: &dexdo_core::Address,
    order_id: u128,
    balance_before: u128,
    wait: std::time::Duration,
) -> Result<Option<(u128, u128)>> {
    let started = std::time::Instant::now();
    loop {
        let remaining = wait.saturating_sub(started.elapsed());
        let observe = async {
            let fold = chain
                .fold_order_book_events(order_book, BookEventFold::default())
                .await?;
            let removed = order_has_left_the_book(fold.all_orders(), order_id);
            let balance = chain.private_note_shell_balance(note).await?;
            Ok::<_, anyhow::Error>((removed, balance))
        };
        let (removed, balance_after) = match tokio::time::timeout(remaining, observe).await {
            Ok(observation) => observation?,
            Err(_) => return Ok(None),
        };
        if removed {
            return Ok(Some((
                balance_after.saturating_sub(balance_before),
                balance_after,
            )));
        }
        let elapsed = started.elapsed();
        if elapsed >= wait {
            return Ok(None);
        }
        tokio::time::sleep(
            dexdo_core::SUBSCRIPTION_ORDER_RECONCILE_POLL.min(wait.saturating_sub(elapsed)),
        )
        .await;
    }
}

/// Render the book's fill history for one note as candidates and refusals.
/// The wording is part of the safety surface. This command exists for an operator whose client died
/// holding a funded deal, and the two ways it can mislead are opposite: presenting a candidate as a
/// recovered deal invites acting on money that may already be settled, and presenting an empty list
/// as "you have no deal" hides a fill the book really emitted. So the header states what was found
/// before anything is listed, every refusal is printed with the TokenContract's own reason, and the
/// caveat says plainly that absence here is not proof.
/// Pure `&Report -> String`: no clock, no chain, no IO, so the exact operator text is testable.
#[cfg(feature = "shellnet")]
fn render_orders_fills(
    frame_model: &str,
    order_book: &str,
    note_addr: &str,
    report: &dexdo_core::shellnet::BookFillCandidateReport,
) -> String {
    let mut rendered = format!(
        "orders fills model={frame_model} order_book={} owner={} fills_named={}\n",
        addr::display(order_book),
        addr::display(note_addr),
        report.fills_named()
    );
    rendered.push_str(
        "Caveat: these are book fill candidates, not recovered deals. InferenceFilled is emitted \
         in the match transaction itself, so it proves the book named this note -- not that the \
         deal is funded now, and not that it still exists. Every address below was re-checked \
         against that TokenContract's own getParties/getState. An empty report is not proof that \
         no deal exists: it can only see the ext-out history this endpoint still serves.\n",
    );
    if report.candidates.is_empty() {
        rendered.push_str("Verified funded fill candidates: none\n");
    } else {
        for candidate in &report.candidates {
            rendered.push_str(&format!(
                "Verified funded fill candidate: {}\n",
                render_fill_identity(candidate)
            ));
        }
    }
    for refusal in &report.refusals {
        rendered.push_str(&format!(
            "Refused InferenceFilled deal pointer: {} reason={}\n",
            render_fill_identity(&refusal.candidate),
            refusal.reason
        ));
    }
    rendered
}

/// The identity half of one fill, shared by the confirmed and refused lines.
/// Both lines carry it because a refused fill is exactly the case an operator has to reconcile by
/// hand, and `sellerTC`/`sellerNote`/the order ids are what is about not losing.
#[cfg(feature = "shellnet")]
fn render_fill_identity(candidate: &dexdo_core::shellnet::BookFillCandidate) -> String {
    format!(
        "token_contract={} seller_note={} maker_id={} taker_id={} ticks={} clearing_price={}",
        addr::display(&candidate.seller_token_contract),
        addr::display(&candidate.seller_note),
        candidate.maker_id,
        candidate.taker_id,
        candidate.ticks,
        candidate.clearing_price
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
    if matches!(&args.command, OrdersCommand::Journal) {
        return direct_chain_read_with_timeout(
            args.read_timeout.read_timeout_secs,
            crate::cli::buyer::run_buyer_submit_journal(&chain, note_addr),
        )
        .await;
    }
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
    // this is the one `orders` subcommand that is NOT about resting rows, so it returns
    // before the fold. A matched order is gone from the book; the evidence it left is the fill
    // event, and folding the resting projection first would pay a full history walk to produce
    // rows this command never reads.
    if matches!(&args.command, OrdersCommand::Fills) {
        return direct_chain_read_with_timeout(args.read_timeout.read_timeout_secs, async {
            let order_book = resolve_order_book_target(&chain, &target).await?;
            let book = dexdo_core::Address::parse(&order_book)
                .map_err(|error| anyhow::anyhow!("order_book {order_book}: {error}"))?;
            let note = dexdo_core::Address::parse(note_addr)
                .map_err(|error| anyhow::anyhow!("--note-addr {note_addr}: {error}"))?;
            let report = chain.verified_book_fill_candidates(&book, &note).await?;
            print!(
                "{}",
                render_orders_fills(&target.frame_model, &order_book, note_addr, &report)
            );
            Ok(())
        })
        .await;
    }
    let view = direct_chain_read_with_timeout(args.read_timeout.read_timeout_secs, async {
        let order_book = resolve_order_book_target(&chain, &target).await?;
        read_live_order_snapshot(&chain, &target, &order_book).await
    })
    .await?;
    let as_of = crate::cli::provenance::now_unix()?;
    let snapshot = &view.snapshot;
    let own = own_orders(snapshot, note_addr);
    match args.command {
        OrdersCommand::Journal => unreachable!("journal returns before resolving a model book"),
        // Handled above, before the resting-order fold: `fills` reads the book's fill history, not
        // the rows this projection carries.
        OrdersCommand::Fills => {}
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
                    println!(
                        "{}",
                        render_order_line(order, as_of, view.escrow_read(order))
                    );
                }
            }
        }
        OrdersCommand::Show { order_id } => {
            let order = own
                .into_iter()
                .find(|o| o.order_id == order_id)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "order {order_id} is not a resting order owned by note {} in {}",
                        addr::display(note_addr),
                        addr::display(&snapshot.order_book)
                    )
                })?;
            println!("{}", render_orders_context(&view, as_of, note_addr));
            println!(
                "{}",
                render_order_line(order, as_of, view.escrow_read(order))
            );
        }
        OrdersCommand::Cancel { order_id } => {
            let order = own
                .into_iter()
                .find(|o| o.order_id == order_id)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "refusing to cancel: order {order_id} is not owned by note {} in {}",
                        addr::display(note_addr),
                        addr::display(&snapshot.order_book)
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
            let balance_before = direct_chain_read_with_timeout(
                args.read_timeout.read_timeout_secs,
                chain.private_note_shell_balance(&note),
            )
            .await?;
            chain
                .cancel_inference_order(&note, &keys, &target.model_hash, order.order_id)
                .await?;
            println!(
                "cancel submitted model={} order_book={} order_id={} owner={}",
                snapshot.frame_model,
                addr::display(&snapshot.order_book),
                order.order_id,
                addr::display(note_addr)
            );
            let confirmed = reconcile_order_removal(
                &chain,
                &snapshot.order_book,
                &note,
                order.order_id,
                balance_before,
                std::time::Duration::from_secs(args.read_timeout.read_timeout_secs),
            )
            .await?;
            let Some((refund, balance_after)) = confirmed else {
                // A cancel can also be REFUSED by the book -- a foreign owner or an order already
                // gone raises `InferenceOrderCancelRejected`, and a full queue means "ask again"
                // with the order still alive(`InferenceOrderBook.sol:1178-1183,218-221`). This
                // client cannot yet tell those apart from a slow read, so it claims neither a
                // removal nor a refund, and sends nothing a second time.
                bail!(
                    "cancel submitted for order {}, but its removal was not confirmed through the \
                     read timeout; no refund figure is claimed and no retry was sent",
                    order.order_id
                );
            };
            println!(
                "cancel confirmed model={} order_book={} order_id={} owner={} refund={refund} balance_before={balance_before} balance_after={balance_after}",
                snapshot.frame_model,
                addr::display(&snapshot.order_book),
                order.order_id,
                addr::display(note_addr)
            );
        }
        OrdersCommand::Expire { order_id } => {
            // Permissionless: `expireOrder` accepts its own external message and is not owner-
            // authenticated(`contracts/airegistry/InferenceOrderBook.sol:1686`), so unlike
            // `cancel` this action signs nothing and needs no `--note-key`.
            match expire_action(own.iter().find(|o| o.order_id == order_id).copied(), as_of) {
                ExpireAction::NotResting => {
                    println!(
                        "expire noop model={} order_book={} order_id={order_id} owner={} resting=false submitted=false",
                        snapshot.frame_model,
                        addr::display(&snapshot.order_book),
                        addr::display(note_addr)
                    );
                }
                ExpireAction::StillLive { deadline } => {
                    bail!("{}", expire_too_early(order_id, deadline, as_of))
                }
                ExpireAction::Sweep => {
                    let note = dexdo_core::Address::parse(note_addr)
                        .map_err(|e| anyhow::anyhow!("--note-addr {note_addr}: {e}"))?;
                    let book = dexdo_core::Address::parse(&snapshot.order_book)
                        .map_err(|e| anyhow::anyhow!("order book {}: {e}", snapshot.order_book))?;
                    let frame_model = snapshot.frame_model.clone();
                    let order_book = snapshot.order_book.clone();
                    let balance_before = direct_chain_read_with_timeout(
                        args.read_timeout.read_timeout_secs,
                        chain.private_note_shell_balance(&note),
                    )
                    .await?;
                    chain.expire_inference_order(&book, order_id).await?;
                    println!(
                        "expire submitted model={frame_model} order_book={} order_id={order_id} owner={}",
                        addr::display(&order_book),
                        addr::display(note_addr)
                    );
                    let confirmed = reconcile_order_removal(
                        &chain,
                        &order_book,
                        &note,
                        order_id,
                        balance_before,
                        std::time::Duration::from_secs(args.read_timeout.read_timeout_secs),
                    )
                    .await?;
                    let Some((refund, balance_after)) = confirmed else {
                        bail!(
                            "expire submitted for order {order_id}, but its removal was not \
                             confirmed through the read timeout; no refund figure is claimed and \
                             no retry was sent"
                        );
                    };
                    println!(
                        "expire confirmed model={frame_model} order_book={} order_id={order_id} owner={} refund={refund} balance_before={balance_before} balance_after={balance_after}",
                        addr::display(&order_book),
                        addr::display(note_addr)
                    );
                }
            }
        }
        OrdersCommand::CancelAll => {
            if own.is_empty() {
                bail!(
                    "refusing to cancel-all: note {} has no resting orders in {}",
                    addr::display(note_addr),
                    addr::display(&snapshot.order_book)
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

    /// The incident, to the second: SELL 11's deadline and the moment the operator read the
    /// book 779 seconds later, still being shown 956 ticks of liquidity no buyer could reach.
    const PAST_DEADLINE: u64 = 1_785_678_525;
    const AS_OF: u64 = 1_785_679_304;

    fn owner_note() -> String {
        format!("0:{}", "a".repeat(64))
    }

    fn folded_order(
        order_id: u128,
        is_buy: bool,
        deadline: u64,
    ) -> dexdo_core::shellnet::LiveBookOrder {
        dexdo_core::shellnet::LiveBookOrder {
            order_id,
            is_buy,
            price: 5_000_000_000,
            ticks_remaining: 956,
            note: owner_note(),
            token_contract: format!("0:{}", "b".repeat(64)),
            deadline,
            flags: 0,
            expired_by_event: false,
        }
    }

    fn owner_rows(orders: &[dexdo_core::shellnet::LiveBookOrder]) -> Vec<String> {
        let target = BookTarget {
            frame_model: "qwen--qwen3--32b".to_string(),
            model_hash: "model-hash".to_string(),
            order_book: Some(format!("0:{}", "d".repeat(64))),
            root_model: None,
            note_addr: None,
        };
        let snapshot = fold_snapshot_from_orders(&target, &format!("0:{}", "d".repeat(64)), orders);
        // The production fold path, assembled the way `read_live_order_snapshot` assembles it: the
        // snapshot carries no escrow and the swept ids travel beside it, so these rows go through
        // the very `OrdersView::escrow_read` verdict `ROWS_CHAIN_EVENTS` reaches in production.
        let view = OrdersView {
            snapshot,
            rows: crate::cli::provenance::ROWS_CHAIN_EVENTS,
            last_update_id: "fold-13".to_string(),
            swept_order_ids: orders
                .iter()
                .filter(|order| order.expired_by_event)
                .map(|order| order.order_id)
                .collect(),
        };
        own_orders(&view.snapshot, &owner_note())
            .into_iter()
            .map(|order| render_order_line(order, AS_OF, view.escrow_read(order)))
            .collect()
    }

    fn fields(line: &str) -> std::collections::BTreeMap<&str, &str> {
        line.split_whitespace()
            .filter_map(|pair| pair.split_once('='))
            .collect()
    }

    /// the row carries `flags=`, and carries the fold's own value on the fold-backed path.
    /// The whole point of the field is that it distinguishes orders that are otherwise identical, so
    /// the assertion is that two rows differing ONLY in flags render differently. A `flags=` column
    /// that always printed the same number would satisfy "the field is present" and still tell the
    /// operator nothing -- that is the shape reports, a placement value replaced by a constant.
    /// Rendered through `owner_rows`, which is the fold path with an unswept `EscrowRead`:
    /// escrow is unknowable there and stays `-`, while flags is known and prints a number. Both
    /// halves are asserted so the two fields cannot be conflated back together.
    #[test]
    fn order_line_carries_the_folded_flags() {
        let shaped = dexdo_core::order_flags::AON | dexdo_core::order_flags::SUBSCRIPTION;
        let rows = owner_rows(&[
            dexdo_core::shellnet::LiveBookOrder {
                flags: shaped,
                ..folded_order(11, false, AS_OF + 3_600)
            },
            folded_order(12, false, AS_OF + 3_600),
        ]);

        let by_id = |want: &str| {
            rows.iter()
                .map(|row| fields(row))
                .find(|row| row.get("order_id") == Some(&want))
                .unwrap_or_else(|| panic!("row for order {want}: {rows:?}"))
        };
        assert_eq!(by_id("11").get("flags"), Some(&shaped.to_string().as_str()));
        assert_eq!(by_id("12").get("flags"), Some(&"0"));
        // The fold still cannot report escrow, and saying so is not the same as reporting a zero.
        assert_eq!(by_id("11").get("escrow"), Some(&"-"));
    }

    /// requirements 2 and 3: the operator cannot read `deadline=1785678280`. The row carries a
    /// date-time and says outright whether the order is past it, judged against the same `as_of` the
    /// context line prints.
    #[test]
    fn order_line_renders_a_human_deadline_and_the_expired_flag() {
        let expired = owner_rows(&[folded_order(11, false, PAST_DEADLINE)]);
        let expired = fields(&expired[0]);
        assert_eq!(expired.get("deadline"), Some(&"1785678525"));
        assert_eq!(expired.get("deadline_utc"), Some(&"2026-08-02T13:48:45Z"));
        assert_eq!(expired.get("expired"), Some(&"yes"));

        let live = owner_rows(&[folded_order(12, false, AS_OF + 3_600)]);
        let live = fields(&live[0]);
        assert_eq!(live.get("deadline_utc"), Some(&"2026-08-02T15:01:44Z"));
        assert_eq!(live.get("expired"), Some(&"no"));
    }

    /// 's explicit non-goal, and the deliberate opposite of what `market` does with the same
    /// row: an expired order may still be holding escrow, so the owner's own list keeps showing it.
    /// Hiding it would take the operator's money out of view.
    #[test]
    fn an_expired_order_stays_in_the_owner_list_flagged() {
        let rows = owner_rows(&[
            folded_order(11, false, PAST_DEADLINE),
            folded_order(13, false, AS_OF + 3_600),
        ]);

        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(fields(&rows[0]).get("order_id"), Some(&"11"));
        assert_eq!(fields(&rows[0]).get("expired"), Some(&"yes"));
        assert_eq!(fields(&rows[1]).get("expired"), Some(&"no"));
    }

    /// regression: "the book is still holding your money" and "your money is already back"
    /// stop rendering identically.
    /// Observed live on order_id=2: the row read `escrow=-... expired=yes` while the book had
    /// already swept it and the refund had landed at the note -- the same row a bid still holding its
    /// escrow renders. The two states call for OPPOSITE actions (`dexdo orders expire` on that
    /// order id versus nothing at all), and `expired=yes` is true in both because it is the clock's
    /// verdict, not the book's.
    /// The fold's own answer is what closes it: `InferenceOrderExpired` sets `expired_by_event`, and
    /// E2E-ORD-08 keep the row visible precisely BECAUSE the money may still be locked. Both
    /// halves are asserted together here, so a later change cannot buy the distinction back by
    /// dropping the swept row -- which would take the operator's money out of view for the case where
    /// it was never returned.
    #[test]
    fn an_expired_row_says_whether_the_book_still_holds_the_escrow() {
        let rows = owner_rows(&[
            // Past its deadline, nobody has swept it: the book is still holding this bid's escrow.
            folded_order(2, true, PAST_DEADLINE),
            // The book announced the sweep for this one; the escrow went back to the note.
            dexdo_core::shellnet::LiveBookOrder {
                expired_by_event: true,
                ..folded_order(3, true, PAST_DEADLINE)
            },
        ]);

        assert_eq!(
            rows.len(),
            2,
            "the swept row stays visible (): {rows:?}"
        );
        let by_id = |want: &str| {
            rows.iter()
                .map(|row| fields(row))
                .find(|row| row.get("order_id") == Some(&want))
                .unwrap_or_else(|| panic!("row for order {want}: {rows:?}"))
        };

        // The clock says the same thing about both, which is exactly why it cannot be the signal.
        assert_eq!(by_id("2").get("expired"), Some(&"yes"));
        assert_eq!(by_id("3").get("expired"), Some(&"yes"));

        // The escrow cell is where the owner's question is answered, and now it answers it.
        assert_eq!(
            by_id("2").get("escrow"),
            Some(&"-"),
            "an unswept row must still say the amount is unknown on this path, never `0`: {rows:?}"
        );
        assert_eq!(
            by_id("3").get("escrow"),
            Some(&"returned"),
            "a row the book swept must say the escrow is no longer held: {rows:?}"
        );
        assert_ne!(
            by_id("2"),
            by_id("3"),
            "locked and returned may not render as the same row: {rows:?}"
        );

        // ... and the verdict is the fold's, not the deadline's: a row the book has NOT swept never
        // claims the money came back, whatever the clock says.
        let live = owner_rows(&[folded_order(4, true, AS_OF + 3_600)]);
        assert_eq!(fields(&live[0]).get("escrow"), Some(&"-"), "{live:?}");
    }

    /// at the seam the report named: the fold's verdict reaches the row through the READ
    /// PATH's own carry, not through one restated beside it.
    /// `owner_rows` assembles an `OrdersView` field by field, `swept_order_ids` included, so
    /// everything built on it pins the renderer and only the renderer. Empty that set where
    /// `read_live_order_snapshot` derives it and every one of those tests stays green while the
    /// shipped command renders a swept bid exactly like a bid the book is still holding -- the whole
    /// of, back, and unobserved. So this drives `OrdersView::from_fold`, the one derivation
    /// the fold read path has, with the two rows the report is about: order 2 past its deadline
    /// with nobody having swept it, and one the book announced it swept.
    /// Both states, because either alone is satisfiable by a constant.
    #[test]
    fn the_read_paths_own_carry_separates_a_locked_row_from_a_returned_one() {
        let locked = folded_order(2, true, PAST_DEADLINE);
        let swept = dexdo_core::shellnet::LiveBookOrder {
            expired_by_event: true,
            ..folded_order(3, true, PAST_DEADLINE)
        };
        let order_book = format!("0:{}", "d".repeat(64));
        let target = BookTarget {
            frame_model: "qwen--qwen3--32b".to_string(),
            model_hash: "model-hash".to_string(),
            order_book: Some(order_book.clone()),
            root_model: None,
            note_addr: None,
        };

        let view = OrdersView::from_fold(
            &target,
            &order_book,
            &[&locked, &swept],
            "fold-13".to_string(),
        );
        let rows = own_orders(&view.snapshot, &owner_note())
            .into_iter()
            .map(|order| render_order_line(order, AS_OF, view.escrow_read(order)))
            .collect::<Vec<_>>();

        assert_eq!(rows.len(), 2, "the swept row stays visible (): {rows:?}");
        let by_id = |want: &str| {
            rows.iter()
                .map(|row| fields(row))
                .find(|row| row.get("order_id") == Some(&want))
                .unwrap_or_else(|| panic!("row for order {want}: {rows:?}"))
        };

        // The clock says the same of both, which is why it cannot be the signal.
        assert_eq!(by_id("2").get("expired"), Some(&"yes"), "{rows:?}");
        assert_eq!(by_id("3").get("expired"), Some(&"yes"), "{rows:?}");

        // The book is still holding this one: the owner's action is `dexdo orders expire 2`. `-`
        // also pins that this path stayed marked as the fold -- an authoritative marker over rows the
        // fold produced would print the filler `escrow=0` here, which reads as "nothing is held".
        assert_eq!(
            by_id("2").get("escrow"),
            Some(&"-"),
            "the read path must still say the amount is unknown on a row it holds: {rows:?}"
        );
        // The book announced the sweep for this one: the money is already back, nothing to do.
        assert_eq!(
            by_id("3").get("escrow"),
            Some(&"returned"),
            "the read path must carry the book's own sweep onto the row: {rows:?}"
        );
        assert_ne!(
            by_id("2"),
            by_id("3"),
            "locked and returned may not render as the same row: {rows:?}"
        );
    }

    /// The authoritative read path can never report a sweep, and must not stop reporting the number.
    /// `getOrder` has no expiry announcement to relay -- it simply stops returning a record the book
    /// removed -- so every row it produces is one the book still holds. `escrow=returned` there would
    /// be this client inventing a removal out of a read that cannot observe one.
    #[test]
    fn the_getter_path_never_reports_a_sweep() {
        let mut bid = order(9, 10_000, 3, "0:deal");
        bid.is_buy = true;
        bid.escrow = 30_744;
        let getters = view(crate::cli::provenance::ROWS_CHAIN_GETTERS, "-");
        assert_eq!(getters.escrow_read(&bid), EscrowRead::Authoritative);
        let row = render_order_line(&bid, AS_OF, getters.escrow_read(&bid));
        assert_eq!(fields(&row).get("escrow"), Some(&"30744"), "{row}");

        // Same row id, same read path, with a swept id recorded: the path still decides, because a
        // getter that returned the record has already proved the book holds it.
        let mut with_sweep = view(crate::cli::provenance::ROWS_CHAIN_GETTERS, "-");
        with_sweep.swept_order_ids.insert(9);
        assert_eq!(with_sweep.escrow_read(&bid), EscrowRead::Authoritative);
    }

    /// One predicate for both views: a SELL with no deadline is malformed, never immortal
    /// liquidity, while a zero-deadline BUY is the contract's GTC bid and is not expired.
    #[test]
    fn a_zero_deadline_reads_by_side() {
        let sell = owner_rows(&[folded_order(14, false, 0)]);
        let sell = fields(&sell[0]);
        assert_eq!(sell.get("deadline"), Some(&"0"));
        assert_eq!(sell.get("deadline_utc"), Some(&"-"));
        assert_eq!(sell.get("expired"), Some(&"yes"));

        let buy = owner_rows(&[folded_order(15, true, 0)]);
        assert_eq!(fields(&buy[0]).get("expired"), Some(&"no"));
    }

    /// `dexdo orders expire` decides what it may do BEFORE it sends anything, and it decides with
    /// the same deadline predicate the `expired=` column an operator just read was rendered from.
    /// The premature arm is the money-relevant one: an order whose deadline has not passed is
    /// still holding escrow the book will not release, so the refusal names the deadline -- the
    /// operator learns WHEN this becomes possible, and that `cancel` is the way out before then.
    #[test]
    fn expire_refuses_before_the_deadline_and_names_it() {
        let mut live = order(21, 10_000, 3, "0:deal");
        live.deadline = AS_OF + 3_600;

        assert_eq!(
            expire_action(Some(&live), AS_OF),
            ExpireAction::StillLive {
                deadline: AS_OF + 3_600
            }
        );

        let refusal = expire_too_early(21, live.deadline, AS_OF);
        assert!(
            refusal.contains("order 21 is live until unix 1785682904")
                && refusal.contains("2026-08-02T15:01:44Z")
                && refusal.contains("3600 seconds after this read at unix 1785679304"),
            "the refusal must name the deadline that makes the sweep premature: {refusal}"
        );
        assert!(
            refusal.contains("no message was sent and no escrow moved")
                && refusal.contains("dexdo orders cancel 21"),
            "the refusal must say nothing moved and name the way out: {refusal}"
        );

        // A BUY may rest with the contract's GTC deadline 0. Nothing will ever sweep it, so
        // telling the operator to wait would be a lie.
        let mut gtc = live.clone();
        gtc.is_buy = true;
        gtc.deadline = 0;
        assert_eq!(
            expire_action(Some(&gtc), AS_OF),
            ExpireAction::StillLive { deadline: 0 }
        );
        let gtc_refusal = expire_too_early(21, 0, AS_OF);
        assert!(
            gtc_refusal.contains("carries deadline 0, which never expires")
                && !gtc_refusal.contains("live until"),
            "a GTC bid must not be described as merely not-yet-expired: {gtc_refusal}"
        );
    }

    /// `expireOrder` is permissionless and idempotent on chain -- a gone order is a silent no-op
    /// there -- so a replayed `dexdo orders expire` must read the same way. Reporting an error would
    /// make a safe repeat look like a failure; reporting a removal or a refund would invent a
    /// second one. Only an order past its deadline and still in the book is swept.
    #[test]
    fn expire_is_a_no_op_for_an_order_that_is_not_resting() {
        assert_eq!(expire_action(None, AS_OF), ExpireAction::NotResting);

        let mut swept = order(22, 10_000, 3, "0:deal");
        swept.deadline = PAST_DEADLINE;
        assert_eq!(expire_action(Some(&swept), AS_OF), ExpireAction::Sweep);

        // The boundary the contract draws: `_isExpired` is `block.timestamp >= deadline`, so the
        // deadline second itself is already past, and one second earlier is not.
        assert_eq!(
            expire_action(Some(&swept), PAST_DEADLINE),
            ExpireAction::Sweep
        );
        assert_eq!(
            expire_action(Some(&swept), PAST_DEADLINE - 1),
            ExpireAction::StillLive {
                deadline: PAST_DEADLINE
            }
        );
    }

    /// The live defect this pins, by fact: on 2026-08-05 the shipped sweep removed order 2 and
    /// refunded its escrow -- book tx `now=1785963432` `exit_code:0` with four out-messages, two
    /// buyer-note transactions in the same second, and a replay that emitted nothing because
    /// `_doExpire` took its "already gone" branch -- and `dexdo orders expire` still reported the
    /// removal unconfirmed, because it waited for the row to vanish from the owner's list.
    /// That row is designed never to vanish. `InferenceOrderExpired` sets `expired_by_event` and
    /// leaves it in place, so absence alone is the wrong question: the right one
    /// is whether the BOOK said the order left it, which is true of an announced-expired row that
    /// is still listed.
    /// `cancel` and `expire` share this one oracle precisely because the answer is asymmetric and
    /// two predicates that must agree are two predicates that can drift. `InferenceOrderCancelled`
    /// IS terminal -- the fold drops the row -- so for a cancel absence is the announcement; for an
    /// expiry it never comes. Both arms are asserted below against the same function.
    #[test]
    fn a_removal_is_confirmed_by_the_books_announcement_not_by_the_row_disappearing() {
        let announced = dexdo_core::shellnet::LiveBookOrder {
            expired_by_event: true,
            ..folded_order(2, true, PAST_DEADLINE)
        };
        let merely_past_its_deadline = folded_order(2, true, PAST_DEADLINE);

        // The cancel arm: `InferenceOrderCancelled` is terminal, so the fold no longer holds it.
        assert!(
            order_has_left_the_book(std::iter::empty(), 2),
            "an order the fold no longer holds has left the book"
        );
        // The expiry arm: still listed, and still gone from the book.
        assert!(
            order_has_left_the_book(std::iter::once(&announced), 2),
            "the book announced this order expired; still being listed does not un-say it"
        );
        assert!(
            !order_has_left_the_book(std::iter::once(&merely_past_its_deadline), 2),
            "a row past its deadline that nobody swept is still in the book holding escrow"
        );
        // The verdict is about ONE order id: a book still holding an unrelated live row says
        // nothing about ours, and ours is gone.
        let unrelated = folded_order(3, true, PAST_DEADLINE);
        assert!(
            order_has_left_the_book(std::iter::once(&unrelated), 2),
            "another owner's row must not keep our swept order alive"
        );
        assert!(
            !order_has_left_the_book([&merely_past_its_deadline, &unrelated], 2),
            "our unswept row must still be found among others"
        );
    }

    /// regression, re-armed: the order row carries `escrow`, and it carries it honestly.
    /// `cdd7d313` dropped `escrow=` from this formatter on 2026-07-12; `4cb8f496` restored it on
    /// 2026-08-02 but never landed on this branch, so the row shipped without it again. The first
    /// half below is that lost assertion, back on the real formatter.
    /// The second half is why the plain restore is not enough. `4cb8f496` printed `order.escrow`
    /// unconditionally, and the default read path is the event fold, which has no escrow to fold --
    /// `fold_snapshot_from_orders` fills a zero. Unconditional rendering therefore prints
    /// `escrow=0` over a bid that is really holding SHELL, which is worse than printing nothing:
    /// `0` is a legitimate reading(every SELL rests with it), so the operator cannot tell the
    /// filler from the fact. The fold path must say `-`.
    /// E2E-ROW: E2E-ORD-07/L0
    #[test]
    fn order_row_carries_escrow_and_never_prints_a_filler_zero_for_it() {
        // Getter path: `getOrder` returned the stored `Order`, so the number is the book's.
        let mut bid = order(7, 10_000, 3, "0:deal");
        bid.is_buy = true;
        bid.escrow = 30_744;
        let from_getters = render_order_line(&bid, AS_OF, EscrowRead::Authoritative);
        assert_eq!(
            fields(&from_getters).get("escrow"),
            Some(&"30744"),
            "an authoritative read must show the escrow the bid is holding: {from_getters}"
        );

        // Fold path: same resting bid, read through the events, which never carried its escrow.
        // The struct's zero is a filler and must not be rendered as a quantity.
        let mut unknown = bid.clone();
        unknown.escrow = 0;
        let from_fold = render_order_line(&unknown, AS_OF, EscrowRead::HeldAmountUnknown);
        assert_eq!(
            fields(&from_fold).get("escrow"),
            Some(&"-"),
            "the event fold carries no escrow; it must not report the filler zero: {from_fold}"
        );

        // The live `orders list` default is exactly that fold path, so this is what an operator
        // sees today -- not a number, and specifically not `0`.
        assert_eq!(
            owner_rows(&[folded_order(7, true, 1_785_678_525)])
                .first()
                .map(|row| fields(row).get("escrow").copied()),
            Some(Some("-")),
            "the production fold-backed owner list must render escrow as unknown, not as zero"
        );
    }

    #[test]
    fn unix_utc_rendering_pins_known_instants() {
        assert_eq!(render_unix_utc(1), "1970-01-01T00:00:01Z");
        assert_eq!(render_unix_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(render_unix_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(render_unix_utc(1_785_678_525), "2026-08-02T13:48:45Z");
        assert_eq!(render_unix_utc(2_147_483_647), "2038-01-19T03:14:07Z");
    }

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
            swept_order_ids: std::collections::BTreeSet::new(),
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

    fn order(order_id: u128, price_per_tick: u128, ticks: u128, tc: &str) -> OrderBookOrder {
        OrderBookOrder {
            order_id,
            owner_note: format!("0:{}", "a".repeat(64)),
            token_contract: Some(tc.to_string()),
            is_buy: false,
            price_per_tick,
            ticks,
            escrow: 0,
            deadline: 1_785_678_280,
            flags: 0,
            timestamp: 0,
        }
    }

    /// The client renders one resting sell offer as one row carrying its whole identity tuple --
    /// order id, side, price, size, deadline and deal -- bound together rather than as independent
    /// substrings satisfiable across two different offers.
    /// E2E-ORD-01, tests/e2e/test-specification.md
    /// Partial: the row's L0 half -- the posted order appearing in the book getter with that exact
    /// tuple, and the seller's readiness bound to it -- needs the live book and is not observed
    /// here, and the adversary half (folding an unknown, stale or duplicated identity from the same
    /// snapshot) is not covered.
    #[test]
    fn one_resting_ask_renders_as_one_row_carrying_its_whole_tuple() {
        // Split one rendered row into whole key/value pairs. Comparing values as units is what
        // anchors every assertion below: as text, `order_id=11` sits inside `order_id=110` and
        // `ticks=956` sits inside `ticks=9560`, so a substring check cannot tell an offer from a
        // different offer whose fields merely start the same way.
        fn fields(line: &str) -> std::collections::BTreeMap<&str, &str> {
            line.split_whitespace()
                .filter_map(|pair| pair.split_once('='))
                .collect()
        }

        let tc_a_account = "1".repeat(64);
        let tc_a = format!("0:{tc_a_account}");
        let tc_b = format!("0:{}", "2".repeat(64));
        // Offer 11 holds the identifier; offer 12 holds the price and the size. Offer 110 is the
        // near-miss: same deal, same side, same deadline, and every one of its numbers extends the
        // matching number of offer 11 -- so it satisfies every loose substring an unanchored check
        // would look for, and only whole values tell the two apart.
        let first = order(11, 700, 956, &tc_a);
        let second = order(12, 900, 4, &tc_b);
        let near_miss = order(110, 7001, 9560, &tc_a);

        // The moment the book is observed. This row is about identity, not about time, so the
        // three offers are read while they are all still RESTING -- the same fixed observation stamp
        // the context-line tests in this module use, a year before the fixture deadline. A wall-clock
        // `now` would make the row's verdict, and this whole-row comparison, drift by the day.
        let as_of = 1_754_006_400_u64;
        // Getter-shaped rows: `getOrder` returns the stored `Order`, so their escrow is the book's.
        let lines = [
            render_order_line(&first, as_of, EscrowRead::Authoritative),
            render_order_line(&second, as_of, EscrowRead::Authoritative),
            render_order_line(&near_miss, as_of, EscrowRead::Authoritative),
        ];
        let rows: Vec<_> = lines.iter().map(|line| fields(line)).collect();

        // One comparison of the whole row: every value of the tuple is proven to belong to this
        // one record, in the rendered form, with nothing else on the row.
        // widened the row with the human deadline and the as_of-bound verdict, and restored
        // `flags`; all three belong to this record and are therefore part of the one whole-row
        // comparison, unchanged in kind. `flags=0` is this fixture's own recorded value, not a
        // placeholder -- `order_line_carries_the_folded_flags` is what proves a set value renders.
        // `owner` is a PrivateNote, a contract of the shared dexdo DApp; `token_contract` is a
        // per-deal TokenContract, a self-DApp account whose DApp half is its own account id.
        let expected = format!(
            "order_id=11 side=sell owner={} token_contract={tc_a_account}::{tc_a_account} \
             price_per_tick=700 ticks=956 escrow=0 flags=0 deadline=1785678280 \
             deadline_utc=2026-08-02T13:44:40Z expired=no",
            addr::display(&first.owner_note),
        );
        assert_eq!(
            lines[0], expected,
            "the whole tuple must be carried by one row, field for field"
        );
        let want = fields(&expected);

        // The near-miss row really is the trap this row exists to catch: its values contain offer
        // 11's without being them, so the equality above is doing work a `contains` would not.
        let near_miss_row = &rows[2];
        for key in ["order_id", "price_per_tick", "ticks"] {
            assert!(
                near_miss_row[key].starts_with(want[key]) && near_miss_row[key] != want[key],
                "the near-miss row must extend offer 11's {key} without equalling it: \
                 {} vs {}",
                near_miss_row[key],
                want[key]
            );
        }
        assert!(
            !rows[1..].iter().any(|row| *row == want),
            "exactly one row carries this tuple: {}",
            lines.join("\n")
        );

        // The mixed-up combination is satisfied by the OUTPUT and by no single ROW.
        let mixed = [
            ("order_id", "11"),
            ("price_per_tick", "900"),
            ("ticks", "4"),
        ];
        assert!(
            mixed
                .iter()
                .all(|(key, value)| rows.iter().any(|row| row.get(*key) == Some(value))),
            "the mixed tuple must be reachable across the output, or this assertion proves nothing"
        );
        assert!(
            !rows.iter().any(|row| mixed
                .iter()
                .all(|(key, value)| row.get(*key) == Some(value))),
            "no single row may satisfy the mixed tuple: {}",
            lines.join("\n")
        );
    }

    /// `orders list` renders deadline as a human date-time and computes `expired=yes|no` against
    /// the exact `as_of` value in its context line. Zero, expired, future, and maximal/malformed
    /// boundary inputs may not masquerade as one another after field parsing.
    /// E2E-ORD-07, `tests/e2e/test-specification.md`.
    /// E2E-ROW: E2E-ORD-07/L0
    #[ignore = "EXPECTED TO FAIL until order rows render a human expiry and an as_of-bound expired field"]
    #[test]
    fn ord_07_order_rows_render_human_expiry_and_expired_field() {
        let as_of = 1_754_006_400_u64;
        let owner = format!("0:{}", "a".repeat(64));
        let context = render_orders_context(
            &view(crate::cli::provenance::ROWS_CHAIN_EVENTS, "fold-13"),
            as_of,
            &owner,
        );
        let mut expired = order(701, 700, 4, "0:expired");
        expired.deadline = as_of - 1;
        let mut live = order(702, 700, 4, "0:live");
        live.deadline = as_of + 1;
        let mut zero = order(703, 700, 4, "0:zero");
        zero.deadline = 0;
        let mut maximal = order(704, 700, 4, "0:max");
        maximal.deadline = u64::MAX;

        let rendered = [expired, live, zero, maximal]
            .iter()
            .map(|order| render_order_line(order, as_of, EscrowRead::HeldAmountUnknown))
            .collect::<Vec<_>>();
        let parsed = rendered
            .iter()
            .map(|line| {
                line.split_whitespace()
                    .filter_map(|field| field.split_once('='))
                    .collect::<std::collections::BTreeMap<_, _>>()
            })
            .collect::<Vec<_>>();
        let human_dates = parsed.iter().all(|row| {
            row.get("expires_at")
                .is_some_and(|value| value.contains('T') && value.contains('-'))
        });
        let expiry_flags = parsed[0].get("expired") == Some(&"yes")
            && parsed[1].get("expired") == Some(&"no")
            && parsed[2].get("expired") == Some(&"yes")
            && parsed[3].get("expired") == Some(&"no");

        assert!(
            context.contains(&format!("as_of={as_of}")) && human_dates && expiry_flags,
            "E2E-ORD-07 missing capability: orders output lacks as_of-bound human expiry fields"
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
