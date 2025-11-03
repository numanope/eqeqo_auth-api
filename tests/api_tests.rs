use auth_api::auth_server;
use httpageboy::Server;
use httpageboy::test_utils::{SERVER_URL, run_test, setup_test_server};
use serde_json::Value;
use std::time::Duration;
use tokio::time::sleep;

async fn create_test_server() -> Server {
  let _ = dotenvy::dotenv();
  auth_server(SERVER_URL, 10).await
}

async fn ensure_test_server() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;
}

async fn execute(request: &[u8], expected: &[u8]) -> String {
  ensure_test_server().await;
  run_test(request, expected)
}

fn response_body(resp: &str) -> Option<&str> {
  resp.split("\r\n\r\n").nth(1).map(|body| body.trim())
}

fn parse_json(resp: &str) -> Option<Value> {
  let body = response_body(resp)?;
  serde_json::from_str(body).ok()
}

fn extract_token(resp: &str) -> Option<String> {
  parse_json(resp).and_then(|json| {
    json
      .get("token")
      .and_then(|value| value.as_str().map(|s| s.to_string()))
  })
}

async fn login_and_get_token() -> String {
  let response = execute(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  )
  .await;
  extract_token(&response).expect("token in login response")
}

#[tokio::test]
async fn home_endpoint_returns_html() {
  execute(b"GET / HTTP/1.1\r\n\r\n", b"Welcome to the Auth API").await;
}

#[tokio::test]
async fn login_succeeds_with_valid_credentials() {
  let response = execute(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  )
  .await;
  let json = parse_json(&response).expect("json body");
  assert!(json.get("token").is_some(), "token missing in response");
  assert_eq!(json["payload"]["username"], "adm1");
}

#[tokio::test]
async fn login_fails_with_wrong_password() {
  execute(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"wrong\"}",
    b"Invalid credentials",
  )
  .await;
}

#[tokio::test]
async fn protected_route_requires_token_header() {
  execute(b"GET /users HTTP/1.1\r\n\r\n", b"Missing token header").await;
}

#[tokio::test]
async fn profile_returns_payload_when_token_valid() {
  let token = login_and_get_token().await;
  let request = format!("GET /auth/profile HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  let response = execute(request.as_bytes(), b"\"payload\"").await;
  let json = parse_json(&response).expect("json body");
  assert_eq!(json["payload"]["username"], "adm1");
  assert!(json.get("expires_at").is_some());
}

#[tokio::test]
async fn profile_rejects_invalid_token() {
  execute(
    b"GET /auth/profile HTTP/1.1\r\ntoken: invalid\r\n\r\n",
    b"Invalid token",
  )
  .await;
}

#[tokio::test]
async fn check_token_confirms_valid_token() {
  let token = login_and_get_token().await;
  let request = format!("POST /check-token HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  let response = execute(request.as_bytes(), b"\"valid\":true").await;
  let json = parse_json(&response).expect("json body");
  assert_eq!(json["payload"]["username"], "adm1");
}

#[tokio::test]
async fn check_token_requires_header() {
  execute(
    b"POST /check-token HTTP/1.1\r\n\r\n",
    b"Missing token header",
  )
  .await;
}

#[tokio::test]
async fn logout_revokes_token() {
  let token = login_and_get_token().await;
  let request = format!("POST /auth/logout HTTP/1.1\r\ntoken: {}\r\n\r\n", &token);
  execute(request.as_bytes(), b"logged_out").await;

  let profile_request = format!("GET /auth/profile HTTP/1.1\r\ntoken: {}\r\n\r\n", &token);
  execute(profile_request.as_bytes(), b"Invalid token").await;
}

#[tokio::test]
async fn logout_rejects_unknown_token() {
  execute(
    b"POST /auth/logout HTTP/1.1\r\ntoken: invalid\r\n\r\n",
    b"Invalid token",
  )
  .await;
}
