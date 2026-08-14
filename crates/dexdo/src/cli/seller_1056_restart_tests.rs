const ISSUE_1056_RESTART_CASE: &str = "DEXDO_TEST_1056_RESTART_CASE";

fn issue_1056_parent_token_contract() -> String {
    format!("0:{}", "1".repeat(64))
}

fn issue_1056_fresh_token_contract() -> String {
    format!("0:{}", "8".repeat(64))
}

fn issue_1056_seller_owner(seed: [u8; 32]) -> String {
    let note = dexdo_core::NoteTree::from_secret_hex(&hex::encode(seed))
        .expect(" seller note tree")
        .node(0)
        .expect(" seller note");
    format!(
        "0:{}",
        note.pubkey()
            .ed
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn issue_1056_successor_token_contract(seller_owner: &str) -> String {
    let identity = format!("{seller_owner}:mock:5");
    format!(
        "0:{}",
        dexdo_core::model_hash_for(&identity).trim_start_matches("0x")
    )
}

async fn issue_1056_persist_fill(
    deals_dir: &std::path::Path,
    parent_token_contract: &str,
    matched_ticks: u64,
) {
    let owner_fills = Arc::new(Mutex::new(Vec::new()));
    let parent = Arc::new(PoolTestBackend::new(
        owner_fills,
        parent_token_contract.to_string(),
        98,
        matched_ticks,
        true,
        i64::MAX - 4,
    ));
    let seller = dexdo::seller::start_gateway_with_note(
        "127.0.0.1:0".parse().expect(" seed gateway address"),
        dexdo::seller::UpstreamConfig::Mock,
        Arc::new(LocalNote::generate()),
    )
    .await
    .expect(" seed gateway");
    let cfg = SellerConfig {
        token_contract: parent.token_contract.clone(),
        price_per_tick: parent.price_per_tick,
        max_ticks: parent.offered_ticks,
        subscription: false,
        gateway_advertise: seller.listen_addr.to_string(),
        mock_token_count: 98,
    };
    let cursor = seller_watch_cursor_path(Some(deals_dir), parent_token_contract)
        .expect(" parent cursor path");
    dexdo::seller::poll_match_and_maybe_open(&seller, parent.as_ref(), &cfg, &cursor)
        .await
        .expect(" authoritative fill poll")
        .expect(" parent match");
    let fill = dexdo::seller::read_seller_fill_lineage(&cursor, &parent.token_contract)
        .expect(" persisted lineage read")
        .expect(" persisted lineage");
    assert_eq!(
        (
            fill.offered_ticks,
            fill.matched_ticks,
            fill.residual_ticks,
            fill.price_per_tick,
        ),
        (98, matched_ticks, 98 - matched_ticks, parent.price_per_tick,)
    );

    // The process goes down after the fill is durable. The next process uses a fresh mock backend,
    // where this parent has no account, no getDeal answer and no in-memory fill notification.
    parent.exists.store(false, Ordering::Relaxed);
    parent.settle_and_lose_getdeal();
    seller.server_task.abort();
    let _ = seller.server_task.await;
}

fn issue_1056_save_parent_handle(
    deals_dir: &std::path::Path,
    contracts: &std::path::Path,
    seller_owner: &str,
    parent_token_contract: &str,
) {
    let market = dexdo_core::MarketManifest {
        // A real persisted parent is not eligible for the mock-only missing-getDeal fallback.
        network: "shellnet".to_string(),
        frame_model: "mock".to_string(),
        model_hash: dexdo_core::model_hash_for("mock"),
        inference_order_book: "mock".to_string(),
        root_model: "mock".to_string(),
        token_contract: parent_token_contract.to_string(),
        seller_note: seller_owner.to_string(),
        nonce: 4,
        price_per_tick: dexdo_core::PRICE_STEP,
        max_ticks: 98,
    };
    deals::save_deal_handle(
        deals_dir,
        &deals::DealHandle {
            version: deals::DEAL_HANDLE_VERSION,
            handle: deals::make_handle_id(parent_token_contract, deals::DealHandleRole::Seller),
            role: deals::DealHandleRole::Seller,
            network: "shellnet".to_string(),
            token_contract: parent_token_contract.to_string(),
            note_addr: seller_owner.to_string(),
            frame_model: market.frame_model.clone(),
            model_hash: Some(market.model_hash.clone()),
            order_book: Some(market.inference_order_book.clone()),
            root_model: Some(market.root_model.clone()),
            market: Some(market),
            contracts: contracts.display().to_string(),
            endpoint: Some(deals::DealEndpointInfo {
                kind: "gateway".to_string(),
                value: "127.0.0.1:1".to_string(),
            }),
            created_order_ids: Vec::new(),
            created_at_unix: deals::now_unix().expect(" handle timestamp"),
        },
    )
    .expect(" persisted parent handle");
}

fn issue_1056_seller_args(
    root: &std::path::Path,
    deals_dir: std::path::PathBuf,
    endpoints_file: std::path::PathBuf,
    contracts: std::path::PathBuf,
) -> crate::cli::args::SellerArgs {
    crate::cli::args::SellerArgs {
        mock: crate::cli::args::MockFlags {
            mock_model: true,
            mock_chain: true,
        },
        identity: crate::cli::args::IdentityArgs {
            note_key: Some(root.join("seller.key")),
            note_index: 0,
            note_addr: None,
        },
        registry: crate::cli::args::ModelRegistryValidationArgs::default(),
        gateway_listen: "127.0.0.1:0"
            .parse()
            .expect(" restart gateway address"),
        gateway_advertise: None,
        allow_private_advertise: true,
        require_advertise_probe: false,
        endpoints_file: Some(endpoints_file),
        deals_dir: Some(deals_dir),
        token_contract: Some(issue_1056_fresh_token_contract()),
        market: None,
        nonce: Some(8),
        subscription: false,
        price_per_tick: dexdo_core::PRICE_STEP as u64,
        mock_token_count: 98,
        model: None,
        models: root.join("unused-models.json"),
        contracts,
        policy: None,
    }
}

#[tokio::test]
#[ignore = "subprocess carrier used by the  stdout contract tests"]
async fn issue_1056_restart_child() {
    let case = std::env::var(ISSUE_1056_RESTART_CASE).expect(" child case");
    let matched_ticks = match case.as_str() {
        "partial" => 2,
        "full" => 98,
        other => panic!("unknown  child case {other}"),
    };
    let residual_ticks = 98 - matched_ticks;
    let root = tempfile::tempdir().expect(" restart directory");
    let seller_seed = [0x56; 32];
    std::fs::write(root.path().join("seller.key"), hex::encode(seller_seed))
        .expect(" seller key");
    let seller_owner = issue_1056_seller_owner(seller_seed);
    let parent_token_contract = issue_1056_parent_token_contract();
    let successor_token_contract = issue_1056_successor_token_contract(&seller_owner);
    let deals_dir = root.path().join("deals");
    let endpoints_file = root.path().join("endpoints.json");
    let contracts = root.path().join("unused-contracts.json");

    issue_1056_persist_fill(&deals_dir, &parent_token_contract, matched_ticks).await;
    issue_1056_save_parent_handle(
        &deals_dir,
        &contracts,
        &seller_owner,
        &parent_token_contract,
    );

    let chain = MockChainBackend::new(
        endpoints_file.clone(),
        ProtocolConsts::canonical(),
        DobParams::canonical(),
    );
    assert_eq!(
        chain
            .sell_offer_terms(&parent_token_contract)
            .await
            .expect(" restart parent getDeal"),
        None,
        "the restarted process must see the settled parent as absent"
    );

    let seller = super::run_seller(issue_1056_seller_args(
        root.path(),
        deals_dir.clone(),
        endpoints_file,
        contracts,
    ));
    tokio::pin!(seller);
    let observe = async {
        let fresh = issue_1056_fresh_token_contract();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut fresh_rested = false;
        let mut successor_rested = false;
        let mut fresh_seen_at = None;
        while std::time::Instant::now() < deadline {
            fresh_rested |= matches!(
                chain.confirm_offer_outcome(&fresh).await,
                Ok(Some(SellOfferOutcome::Rested { .. }))
            );
            if fresh_rested && fresh_seen_at.is_none() {
                fresh_seen_at = Some(std::time::Instant::now());
            }
            successor_rested |= matches!(
                chain.confirm_offer_outcome(&successor_token_contract).await,
                Ok(Some(SellOfferOutcome::Rested { .. }))
            );
            if successor_rested
                || fresh_seen_at
                    .is_some_and(|seen| seen.elapsed() >= std::time::Duration::from_millis(500))
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        (fresh_rested, successor_rested)
    };
    tokio::pin!(observe);
    let (fresh_rested, successor_rested) = tokio::select! {
        result = &mut seller => panic!(" seller exited during restart recovery: {result:?}"),
        observed = &mut observe => observed,
    };
    let fill = dexdo::seller::read_seller_fill_lineage(
        &seller_watch_cursor_path(Some(&deals_dir), &parent_token_contract)
            .expect(" restart cursor path"),
        &parent_token_contract,
    )
    .expect(" restart lineage read")
    .expect(" restart lineage");
    println!(
        "issue_1056_restart_observation case={case} token_contract={parent_token_contract} residual_ticks={residual_ticks} fresh_rested={fresh_rested} successor_token_contract={successor_token_contract} successor_rested={successor_rested} replacement_nonce={:?} replacement_token_contract={:?}",
        fill.replacement_nonce,
        fill.replacement_token_contract,
    );
}

fn issue_1056_child_output(case: &str) -> String {
    let output =
        std::process::Command::new(std::env::current_exe().expect(" current test executable"))
            .args([
                "--exact",
                "cli::seller::tests::issue_1056_restart_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ISSUE_1056_RESTART_CASE, case)
            .output()
            .expect(" restart child process");
    let mut rendered = String::from_utf8_lossy(&output.stdout).into_owned();
    rendered.push_str(&String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        " {case} restart child failed: {rendered}"
    );
    rendered
}

#[test]
fn issue_1056_restart_after_terminal_settlement_queues_exact_residual_and_names_it() {
    let output = issue_1056_child_output("partial");
    // the operator channel names a per-deal TokenContract canonically, and a TokenContract is a
    // self-DApp account, so its DApp half is its own account id. The fixture holds the chain form.
    let parent_chain_form = issue_1056_parent_token_contract();
    let parent_account = parent_chain_form.strip_prefix("0:").expect(" chain form");
    let parent = format!("{parent_account}::{parent_account}");
    assert!(
        output.contains(&format!(
            "seller_residual_queued token_contract={parent} order_id=98 offered_ticks=98 matched_ticks=2 residual_ticks=96 price_per_tick={} reason=restart_after_parent_settlement",
            dexdo_core::PRICE_STEP
        )),
        "startup must name the queued parent and exact residual on the operator channel: {output}"
    );
    assert!(
        output.contains("case=partial")
            && output.contains("residual_ticks=96")
            && output.contains("successor_rested=true")
            && output.contains("replacement_nonce=Some(5)")
            && output.contains(&format!(
                "replacement_token_contract=Some(\"{}\")",
                issue_1056_successor_token_contract(&issue_1056_seller_owner([0x56; 32]))
            )),
        "the real restart entry must queue PR1055's one exact durable successor: {output}"
    );
}

#[tokio::test]
async fn issue_1056_in_process_residual_relist_is_unchanged() {
    let root = tempfile::tempdir().expect(" in-process directory");
    let relisted = pool_run_after_parent_settled(root.path(), 2).await;
    relisted
        .outcome
        .expect("PR1055's in-process relist must remain healthy");
    assert_eq!(
        relisted.provisions,
        vec![(11, relisted.parent_price_per_tick, 96)]
    );
    assert_eq!(relisted.successor_posts, 1);
    assert_eq!(
        relisted.replacement,
        (Some(11), Some(relisted.successor_token_contract))
    );
}

#[test]
fn issue_1056_restart_after_full_fill_queues_nothing() {
    let output = issue_1056_child_output("full");
    // the operator channel names a per-deal TokenContract canonically, and a TokenContract is a
    // self-DApp account, so its DApp half is its own account id. The fixture holds the chain form.
    let parent_chain_form = issue_1056_parent_token_contract();
    let parent_account = parent_chain_form.strip_prefix("0:").expect(" chain form");
    let parent = format!("{parent_account}::{parent_account}");
    assert!(
        output.contains(&format!(
            "seller_residual_not_queued token_contract={parent} order_id=98 offered_ticks=98 matched_ticks=98 residual_ticks=0 reason=fully_matched"
        )),
        "startup must name the zero-residual disposition: {output}"
    );
    assert!(
        output.contains("case=full")
            && output.contains("residual_ticks=0")
            && output.contains("successor_rested=false")
            && output.contains("replacement_nonce=None")
            && output.contains("replacement_token_contract=None"),
        "a settled fully matched parent must not queue or link a successor: {output}"
    );
}
