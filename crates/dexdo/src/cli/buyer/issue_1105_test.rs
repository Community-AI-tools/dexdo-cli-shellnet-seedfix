fn issue_1105_order() -> dexdo_core::OrderBookOrder {
    let mut order = issue67_real_like_order();
    order.deadline = super::unix_now_secs()
        .checked_add(3_600)
        .expect("test clock headroom");
    order
}

fn assert_issue_1105_no_submit(chain: &QuotePreflightChain, journal_path: &std::path::Path) {
    assert!(
        !journal_path.exists(),
        "a refused BUY must not create a journal"
    );
    assert_eq!(
        chain
            .model_before_post_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the refusal must run at the production callback immediately before POST"
    );
    assert_eq!(
        chain
            .model_money_submit_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a refused BUY must not submit money"
    );
    assert_eq!(
        chain
            .model_debit_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a refused BUY must not debit the note"
    );
    assert!(
        chain.model_submitted_orders.lock().unwrap().is_empty(),
        "a refused BUY must not create an order"
    );
}

#[tokio::test]
async fn issue_1105_exact_escrow_plus_limit_price_bond_reaches_one_submit() {
    let order = issue_1105_order();
    let ticks = 2;
    let escrow = dexdo_core::required_escrow_for_buy(ticks, order.price_per_tick);
    let buyer_bond = 2 * order.price_per_tick;
    let required = escrow + buyer_bond;
    let mut chain = issue67_pipeline_chain(&order, Some(order.clone()));
    chain.note_shell_balance = Some(required);
    let (dir, _cleanup) = buyer_journal_test_dir("issue-1105-exact-reserve");
    let journal_path = dir.join("submit.json");

    issue67_select_and_submit(&chain, &journal_path, None)
        .await
        .expect("a note holding exactly escrow plus the limit-priced buyer bond must submit");

    assert!(journal_path.exists(), "the accepted BUY is journalled");
    assert_eq!(
        chain
            .model_before_post_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        chain
            .model_money_submit_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        chain
            .model_debit_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        chain.model_submitted_orders.lock().unwrap().as_slice(),
        &[(
            order.order_id,
            order.token_contract.clone().unwrap(),
            escrow,
        )]
    );
}

#[tokio::test]
async fn issue_1105_one_below_escrow_plus_limit_price_bond_refuses_before_submit() {
    let order = issue_1105_order();
    let ticks = 2;
    let escrow = dexdo_core::required_escrow_for_buy(ticks, order.price_per_tick);
    let buyer_bond = 2 * order.price_per_tick;
    let required = escrow + buyer_bond;
    let available = required - 1;
    let mut chain = issue67_pipeline_chain(&order, Some(order.clone()));
    chain.note_shell_balance = Some(available);
    let (dir, _cleanup) = buyer_journal_test_dir("issue-1105-one-below-reserve");
    let journal_path = dir.join("submit.json");

    let error = issue67_select_and_submit(&chain, &journal_path, None)
        .await
        .expect_err("one raw unit below escrow plus bond must refuse");
    let message = format!("{error:#}");
    assert!(
        message.contains(&format!("available={} SHELL", dexdo_core::shell_amount(available))),
        "{message}"
    );
    assert!(
        message.contains(&format!("required={} SHELL", dexdo_core::shell_amount(required))),
        "{message}"
    );
    assert!(
        message.contains(&format!("buyer bond {} SHELL", dexdo_core::shell_amount(buyer_bond))),
        "{message}"
    );
    assert!(message.contains("--max-price-per-tick"), "{message}");
    assert_issue_1105_no_submit(&chain, &journal_path);
}

#[tokio::test]
async fn issue_1105_escrow_only_refuses_before_submit() {
    let order = issue_1105_order();
    let ticks = 2;
    let escrow = dexdo_core::required_escrow_for_buy(ticks, order.price_per_tick);
    let required = escrow + 2 * order.price_per_tick;
    let mut chain = issue67_pipeline_chain(&order, Some(order.clone()));
    chain.note_shell_balance = Some(escrow);
    let (dir, _cleanup) = buyer_journal_test_dir("issue-1105-escrow-only");
    let journal_path = dir.join("submit.json");

    let error = issue67_select_and_submit(&chain, &journal_path, None)
        .await
        .expect_err("the issue case, a note holding only escrow, must refuse");
    let message = format!("{error:#}");
    assert!(
        message.contains(&format!("available={} SHELL", dexdo_core::shell_amount(escrow))),
        "{message}"
    );
    assert!(
        message.contains(&format!("required={} SHELL", dexdo_core::shell_amount(required))),
        "{message}"
    );
    assert_issue_1105_no_submit(&chain, &journal_path);
}

#[tokio::test]
async fn issue_1105_reserve_overflow_refuses_instead_of_saturating_into_submit() {
    let ticks = 2;
    let max_price_per_tick = u128::MAX;
    let escrow = u128::MAX;
    let mut order = issue_1105_order();
    order.price_per_tick = max_price_per_tick;
    let mut chain = issue67_pipeline_chain(&order, Some(order.clone()));
    chain.note_shell_balance = Some(u128::MAX);
    let selection = super::BuyerQuoteSelection {
        order_book: "model_order_book",
        escrow,
        quote: dexdo_core::ExecutableQuote {
            filled_ticks: ticks,
            total_with_fee: escrow,
            complete: true,
            fills: vec![dexdo_core::QuoteFill {
                order_id: order.order_id,
                token_contract: order.token_contract.clone().unwrap(),
                ticks,
                price_per_tick: max_price_per_tick,
                cost_with_fee: escrow,
            }],
        },
        resting_buy: false,
        quoted_order: Some(order),
    };
    let (dir, _cleanup) = buyer_journal_test_dir("issue-1105-overflow");
    let journal_path = dir.join("submit.json");
    let mut cursor = dexdo_core::MatchWatchCursor::default();

    let error = super::place_quote_bound_buy_with_journal(
        &chain,
        &dexdo::buyer::Buyer::generate(),
        &super::BuyerSubmitIntent::foreground(),
        None,
        &selection,
        ticks,
        max_price_per_tick,
        escrow,
        &format!("0:{}", "1".repeat(64)),
        &mut cursor,
        &journal_path,
        None,
    )
    .await
    .expect_err("an unprovable reserve must fail closed before POST");
    let message = format!("{error:#}");
    assert!(message.contains("overflows u128"), "{message}");
    assert!(message.contains("--max-price-per-tick"), "{message}");
    assert_issue_1105_no_submit(&chain, &journal_path);
}
