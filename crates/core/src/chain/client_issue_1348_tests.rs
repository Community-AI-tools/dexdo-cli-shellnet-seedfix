use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn serve_money_responses(
    responses: Vec<(&'static str, &'static str)>,
) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind buyer money fixture");
    let endpoint = format!("http://{}", listener.local_addr().expect("fixture address"));
    let posts = Arc::new(AtomicUsize::new(0));
    let task_posts = Arc::clone(&posts);
    let task = tokio::spawn(async move {
        for (status, body) in responses {
            let (mut socket, _) = listener.accept().await.expect("accept buyer money POST");
            task_posts.fetch_add(1, Ordering::SeqCst);
            let mut request = [0_u8; 4096];
            let _ = socket
                .read(&mut request)
                .await
                .expect("read buyer money POST");
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write buyer money response");
        }
    });
    (endpoint, posts, task)
}

#[tokio::test]
async fn issue_1348_buyer_money_retries_queue_overflow_then_succeeds() {
    let account = "1".repeat(64);
    let client = build_money_post_http_client().expect("money POST client");
    let (endpoint, posts, task) = serve_money_responses(vec![
        (
            "200 OK",
            r#"{"error":"QUEUE_OVERFLOW: message queue is full"}"#,
        ),
        ("200 OK", r#"{"result":{}}"#),
    ])
    .await;

    retry_buyer_money_submit(&client, &endpoint, "signed-boc", &account, &account)
        .await
        .expect("a decoded queue refusal must retry and then succeed");
    task.await.expect("buyer money fixture task");
    assert_eq!(posts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn issue_1348_buyer_money_does_not_retry_unknown_outcome() {
    let account = "1".repeat(64);
    let client = build_money_post_http_client().expect("money POST client");
    let (endpoint, posts, task) =
        serve_money_responses(vec![("502 Bad Gateway", r#"{"error":"gateway"}"#)]).await;

    let error = retry_buyer_money_submit(&client, &endpoint, "signed-boc", &account, &account)
        .await
        .expect_err("an unknown POST outcome must remain terminal");
    task.await.expect("buyer money fixture task");
    assert!(matches!(
        error
            .chain()
            .find_map(|cause| cause.downcast_ref::<MoneySubmitError>()),
        Some(MoneySubmitError::Ambiguous { .. })
    ));
    assert_eq!(
        posts.load(Ordering::SeqCst),
        1,
        "the signed BUY BOC must not be resubmitted after an unknown outcome"
    );
}
