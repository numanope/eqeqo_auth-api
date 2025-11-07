use httpageboy::test_utils::{run_test, setup_test_server, SERVER_URL};
use httpageboy::Server;
use auth_api::auth_server;
use std::time::Duration;
use tokio::time::sleep;

async fn create_test_server() -> Server {
  let _ = dotenvy::dotenv();
  auth_server(SERVER_URL, 10).await
}

// Authentication

#[tokio::test]
async fn test_login_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
}

#[tokio::test]
async fn test_login_invalid_password() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"wrong\"}",
    b"Invalid credentials",
  );
}

#[tokio::test]
async fn test_logout_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let logout_request = format!("POST /auth/logout HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  run_test(logout_request.as_bytes(), b"\"status\":\"logged_out\"");
}

#[tokio::test]
async fn test_logout_missing_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(b"POST /auth/logout HTTP/1.1\r\n\r\n", b"Missing token header");
}

#[tokio::test]
async fn test_profile_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let profile_request = format!(
    "GET /auth/profile HTTP/1.1\r\ntoken: {}\r\n\r\n",
    token
  );
  run_test(profile_request.as_bytes(), b"\"payload\"");
}

#[tokio::test]
async fn test_profile_missing_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(b"GET /auth/profile HTTP/1.1\r\n\r\n", b"Missing token header");
}

#[tokio::test]
async fn test_check_token_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let check_request = format!(
    "POST /check-token HTTP/1.1\r\ntoken: {}\r\n\r\n",
    token
  );
  run_test(check_request.as_bytes(), b"\"valid\":true");
}

#[tokio::test]
async fn test_check_token_invalid_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(
    b"POST /check-token HTTP/1.1\r\ntoken: invalid\r\n\r\n",
    b"Invalid token",
  );
}

// Users

#[tokio::test]
async fn test_users_list_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let list_request = format!("GET /users HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  run_test(list_request.as_bytes(), b"\"username\":\"adm1\"");
}

#[tokio::test]
async fn test_users_list_missing_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(b"GET /users HTTP/1.1\r\n\r\n", b"Missing token header");
}

#[tokio::test]
async fn test_user_create_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let username = format!("user_{}", suffix);
  let password = format!("pass_{}", suffix);
  let document = format!("{}", suffix);
  let create_body = format!(
    "{{\"username\":\"{uname}\",\"password_hash\":\"{pwd}\",\"name\":\"{name}\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"{doc}\"}}",
    uname = username,
    pwd = password,
    name = "Generated User",
    doc = document
  );
  let create_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token,
    create_body
  );
  let expected_username = format!("\"username\":\"{}\"", username);
  run_test(create_request.as_bytes(), expected_username.as_bytes());
}

#[tokio::test]
async fn test_user_create_invalid_body() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let create_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\ntest",
    token
  );
  run_test(create_request.as_bytes(), b"Invalid request body");
}

#[tokio::test]
async fn test_user_update_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let username = format!("user_update_{}", suffix);
  let password = format!("pass_update_{}", suffix);
  let document = format!("doc{}", suffix);
  let create_body = format!(
    "{{\"username\":\"{uname}\",\"password_hash\":\"{pwd}\",\"name\":\"{name}\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"{doc}\"}}",
    uname = username,
    pwd = password,
    name = "Update Target",
    doc = document
  );
  let create_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token,
    create_body
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let user_id_segment = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("user id segment")
    .trim()
    .to_string();

  let update_body = format!("{{\"name\":\"{}\"}}", "Updated User");
  let update_request = format!(
    "PUT /users/{id} HTTP/1.1\r\ntoken: {token}\r\nContent-Type: application/json\r\n\r\n{body}",
    id = user_id_segment,
    token = token,
    body = update_body
  );
  run_test(update_request.as_bytes(), b"\"status\":\"success\"");
}

#[tokio::test]
async fn test_user_update_invalid_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let update_request = format!(
    "PUT /users/invalid-id HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"Nobody\"}}",
    token
  );
  run_test(update_request.as_bytes(), b"Invalid user ID");
}

#[tokio::test]
async fn test_user_delete_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let username = format!("user_delete_{}", suffix);
  let password = format!("pass_delete_{}", suffix);
  let document = format!("{}{}", suffix, 9);
  let create_body = format!(
    "{{\"username\":\"{uname}\",\"password_hash\":\"{pwd}\",\"name\":\"{name}\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"{doc}\"}}",
    uname = username,
    pwd = password,
    name = "Delete Target",
    doc = document
  );
  let create_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token,
    create_body
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let user_id_segment = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("user id segment")
    .trim()
    .to_string();

  let delete_request = format!(
    "DELETE /users/{id} HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = user_id_segment,
    token = token
  );
  run_test(delete_request.as_bytes(), b"HTTP/1.1 204 No Content");
}

#[tokio::test]
async fn test_user_delete_invalid_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let delete_request = format!(
    "DELETE /users/invalid-id HTTP/1.1\r\ntoken: {}\r\n\r\n",
    token
  );
  run_test(delete_request.as_bytes(), b"Invalid user ID");
}

// Roles

#[tokio::test]
async fn test_roles_list_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let list_request = format!("GET /roles HTTP/1.1\r\ntoken: {}\r\n\r\n", token);
  run_test(list_request.as_bytes(), b"\"name\":\"Admin\"");
}

#[tokio::test]
async fn test_roles_list_missing_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(b"GET /roles HTTP/1.1\r\n\r\n", b"Missing token header");
}

#[tokio::test]
async fn test_role_create_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("role_{}", suffix);
  let create_body = format!("{{\"name\":\"{}\"}}", role_name);
  let create_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token,
    create_body
  );
  let expected = format!("\"name\":\"{}\"", role_name);
  run_test(create_request.as_bytes(), expected.as_bytes());
}

#[tokio::test]
async fn test_role_create_invalid_body() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let create_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n---",
    token
  );
  run_test(create_request.as_bytes(), b"Invalid request body");
}

#[tokio::test]
async fn test_role_update_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("role_update_{}", suffix);
  let create_body = format!("{{\"name\":\"{}\"}}", role_name);
  let create_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token,
    create_body
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let role_id_segment = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let update_body = format!("{{\"name\":\"{}\"}}", "Role Updated");
  let update_request = format!(
    "PUT /roles/{id} HTTP/1.1\r\ntoken: {token}\r\nContent-Type: application/json\r\n\r\n{body}",
    id = role_id_segment,
    token = token,
    body = update_body
  );
  run_test(update_request.as_bytes(), b"\"status\":\"success\"");
}

#[tokio::test]
async fn test_role_update_invalid_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let update_request = format!(
    "PUT /roles/invalid HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"Oops\"}}",
    token
  );
  run_test(update_request.as_bytes(), b"Invalid role ID");
}

#[tokio::test]
async fn test_role_delete_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("role_delete_{}", suffix);
  let create_body = format!("{{\"name\":\"{}\"}}", role_name);
  let create_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token,
    create_body
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let role_id_segment = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let delete_request = format!(
    "DELETE /roles/{id} HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = role_id_segment,
    token = token
  );
  run_test(delete_request.as_bytes(), b"HTTP/1.1 204 No Content");
}

#[tokio::test]
async fn test_role_delete_invalid_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let delete_request = format!(
    "DELETE /roles/invalid HTTP/1.1\r\ntoken: {}\r\n\r\n",
    token
  );
  run_test(delete_request.as_bytes(), b"Invalid role ID");
}

// Permissions

#[tokio::test]
async fn test_permissions_list_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let list_request = format!(
    "GET /permissions HTTP/1.1\r\ntoken: {}\r\n\r\n",
    token
  );
  run_test(list_request.as_bytes(), b"\"name\":\"read\"");
}

#[tokio::test]
async fn test_permissions_list_missing_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(b"GET /permissions HTTP/1.1\r\n\r\n", b"Missing token header");
}

#[tokio::test]
async fn test_permission_create_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let permission_name = format!("permission_{}", suffix);
  let create_body = format!("{{\"name\":\"{}\"}}", permission_name);
  let create_request = format!(
    "POST /permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token,
    create_body
  );
  let expected = format!("\"name\":\"{}\"", permission_name);
  run_test(create_request.as_bytes(), expected.as_bytes());
}

#[tokio::test]
async fn test_permission_create_invalid_body() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let create_request = format!(
    "POST /permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{",
    token
  );
  run_test(create_request.as_bytes(), b"Invalid request body");
}

#[tokio::test]
async fn test_permission_update_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let permission_name = format!("permission_update_{}", suffix);
  let create_body = format!("{{\"name\":\"{}\"}}", permission_name);
  let create_request = format!(
    "POST /permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token,
    create_body
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let permission_id_segment = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("permission id segment")
    .trim()
    .to_string();

  let update_body = format!("{{\"name\":\"{}\"}}", "Permission Updated");
  let update_request = format!(
    "PUT /permissions/{id} HTTP/1.1\r\ntoken: {token}\r\nContent-Type: application/json\r\n\r\n{body}",
    id = permission_id_segment,
    token = token,
    body = update_body
  );
  run_test(update_request.as_bytes(), b"\"status\":\"success\"");
}

#[tokio::test]
async fn test_permission_update_invalid_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let update_request = format!(
    "PUT /permissions/invalid HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"Oops\"}}",
    token
  );
  run_test(update_request.as_bytes(), b"Invalid permission ID");
}

#[tokio::test]
async fn test_permission_delete_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let permission_name = format!("permission_delete_{}", suffix);
  let create_body = format!("{{\"name\":\"{}\"}}", permission_name);
  let create_request = format!(
    "POST /permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token,
    create_body
  );
  let create_response = run_test(create_request.as_bytes(), b"\"id\"");
  let permission_id_segment = create_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("permission id segment")
    .trim()
    .to_string();

  let delete_request = format!(
    "DELETE /permissions/{id} HTTP/1.1\r\ntoken: {token}\r\n\r\n",
    id = permission_id_segment,
    token = token
  );
  run_test(delete_request.as_bytes(), b"HTTP/1.1 204 No Content");
}

#[tokio::test]
async fn test_permission_delete_invalid_id() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let delete_request = format!(
    "DELETE /permissions/invalid HTTP/1.1\r\ntoken: {}\r\n\r\n",
    token
  );
  run_test(delete_request.as_bytes(), b"Invalid permission ID");
}

// Role-Permission relations

#[tokio::test]
async fn test_role_permissions_assign_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix_role = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("role_relation_{}", suffix_role);
  let create_role_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token,
    role_name
  );
  let role_response = run_test(create_role_request.as_bytes(), b"\"id\"");
  let role_id = role_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let suffix_permission = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let permission_name = format!("permission_relation_{}", suffix_permission);
  let create_permission_request = format!(
    "POST /permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token,
    permission_name
  );
  let permission_response = run_test(create_permission_request.as_bytes(), b"\"id\"");
  let permission_id = permission_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("permission id segment")
    .trim()
    .to_string();

  let assign_body = format!(
    "{{\"role_id\":{},\"permission_id\":{}}}",
    role_id,
    permission_id
  );
  let assign_request = format!(
    "POST /role-permissions HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token,
    assign_body
  );
  run_test(assign_request.as_bytes(), b"\"status\":\"success\"");
}

#[tokio::test]
async fn test_role_permissions_assign_missing_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(
    b"POST /role-permissions HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}",
    b"Missing token header",
  );
}

// Service-Roles relations

#[tokio::test]
async fn test_service_roles_assign_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix_service = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let service_name = format!("Service {}", suffix_service);
  let create_service_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{name}\",\"description\":\"{desc}\"}}",
    token,
    name = service_name,
    desc = "Assigned via test"
  );
  let service_response = run_test(create_service_request.as_bytes(), b"\"id\"");
  let service_id = service_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("service id segment")
    .trim()
    .to_string();

  let suffix_role = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("role_service_relation_{}", suffix_role);
  let create_role_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token,
    role_name
  );
  let role_response = run_test(create_role_request.as_bytes(), b"\"id\"");
  let role_id = role_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let assign_body = format!("{{\"service_id\":{},\"role_id\":{}}}", service_id, role_id);
  let assign_request = format!(
    "POST /service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token,
    assign_body
  );
  run_test(assign_request.as_bytes(), b"\"status\":\"success\"");
}

#[tokio::test]
async fn test_service_roles_assign_missing_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(
    b"POST /service-roles HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}",
    b"Missing token header",
  );
}

// Person-Service-Roles relations

#[tokio::test]
async fn test_person_service_roles_assign_success() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  let login_response = run_test(
    b"POST /auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"adm1\",\"password\":\"adm1-hash\"}",
    b"\"token\"",
  );
  let token = login_response
    .split("\"token\":\"")
    .nth(1)
    .and_then(|segment| segment.split('"').next())
    .expect("token value")
    .to_string();

  let suffix_user = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let username = format!("psr_user_{}", suffix_user);
  let password = format!("psr_pass_{}", suffix_user);
  let document = format!("{}{}", suffix_user, 1);
  let create_user_body = format!(
    "{{\"username\":\"{uname}\",\"password_hash\":\"{pwd}\",\"name\":\"{name}\",\"person_type\":\"N\",\"document_type\":\"DNI\",\"document_number\":\"{doc}\"}}",
    uname = username,
    pwd = password,
    name = "Relation User",
    doc = document
  );
  let create_user_request = format!(
    "POST /users HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token,
    create_user_body
  );
  let user_response = run_test(create_user_request.as_bytes(), b"\"id\"");
  let user_id = user_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("user id segment")
    .trim()
    .to_string();

  let suffix_service = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let service_name = format!("PSR Service {}", suffix_service);
  let create_service_request = format!(
    "POST /services HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{name}\",\"description\":\"{desc}\"}}",
    token,
    name = service_name,
    desc = "PSR test service"
  );
  let service_response = run_test(create_service_request.as_bytes(), b"\"id\"");
  let service_id = service_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("service id segment")
    .trim()
    .to_string();

  let suffix_role = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let role_name = format!("psr_role_{}", suffix_role);
  let create_role_request = format!(
    "POST /roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\"}}",
    token,
    role_name
  );
  let role_response = run_test(create_role_request.as_bytes(), b"\"id\"");
  let role_id = role_response
    .split("\"id\":")
    .nth(1)
    .and_then(|segment| segment.split(|c| c == ',' || c == '}').next())
    .expect("role id segment")
    .trim()
    .to_string();

  let assign_body = format!(
    "{{\"person_id\":{},\"service_id\":{},\"role_id\":{}}}",
    user_id,
    service_id,
    role_id
  );
  let assign_request = format!(
    "POST /person-service-roles HTTP/1.1\r\ntoken: {}\r\nContent-Type: application/json\r\n\r\n{}",
    token,
    assign_body
  );
  run_test(assign_request.as_bytes(), b"\"status\":\"success\"");
}

#[tokio::test]
async fn test_person_service_roles_assign_missing_token() {
  setup_test_server(|| create_test_server()).await;
  sleep(Duration::from_millis(100)).await;

  run_test(
    b"POST /person-service-roles HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}",
    b"Missing token header",
  );
}
