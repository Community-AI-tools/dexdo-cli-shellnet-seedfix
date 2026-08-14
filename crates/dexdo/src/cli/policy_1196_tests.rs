use super::*;
use serde_json::json;

fn seller_policy() -> Value {
    json!({
        "version": 1,
        "seller": {
            "on": {
                "after_deal_done": "retire",
                "buyer_no_show": "retire_gateway",
                "dispute_against_me": "hold"
            },
            "max_open_deals": 1
        }
    })
}

fn write_policy(value: &Value) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("policy.json"),
        serde_json::to_vec(value).unwrap(),
    )
    .unwrap();
    dir
}

#[test]
fn seller_chain_unavailable_setting_defaults_to_stop_and_accepts_keep_serving() {
    let old_policy = write_policy(&seller_policy());
    assert_eq!(
        load_seller_chain_unavailable_action(Some(&old_policy.path().join("policy.json"))).unwrap(),
        dexdo::seller::gateway::ChainUnavailableAction::Stop,
        "an existing policy without the new optional setting gets the money-protecting default"
    );

    let mut keep_serving = seller_policy();
    keep_serving["seller"]["on"]["chain_unavailable"] = Value::from("keep_serving");
    let keep_serving = write_policy(&keep_serving);
    assert_eq!(
        load_seller_chain_unavailable_action(Some(&keep_serving.path().join("policy.json")))
            .unwrap(),
        dexdo::seller::gateway::ChainUnavailableAction::KeepServing
    );

    let mut scaffold = Value::Object(Map::new());
    scaffold_roles(&mut scaffold, PolicyRoleArg::Seller);
    assert_eq!(scaffold["seller"]["on"]["chain_unavailable"], "stop");
}
