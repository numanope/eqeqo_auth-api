use httpageboy::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{error_response, require_token_without_renew};

#[derive(Serialize, sqlx::FromRow)]
pub struct Role {
  id: i32,
  name: String,
}

#[derive(Deserialize)]
pub struct CreateRolePayload {
  name: String,
}

pub async fn create_role(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let payload: CreateRolePayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "Invalid request body"),
  };
  match sqlx::query_as::<_, Role>("SELECT * FROM auth.create_role($1)")
    .bind(payload.name)
    .fetch_one(db.pool())
    .await
  {
    Ok(role) => Response {
      status: StatusCode::Created.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&role).unwrap(),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "Failed to create role"),
  }
}

pub async fn list_roles(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  match sqlx::query_as::<_, Role>("SELECT * FROM auth.list_roles()")
    .fetch_all(db.pool())
    .await
  {
    Ok(roles) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&roles).unwrap(),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "Failed to fetch roles"),
  }
}

pub async fn get_role(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid role ID"),
  };
  match sqlx::query_as::<_, Role>("SELECT * FROM auth.get_role($1)")
    .bind(id)
    .fetch_optional(db.pool())
    .await
  {
    Ok(Some(role)) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: serde_json::to_vec(&role).unwrap(),
    },
    Ok(None) => error_response(StatusCode::NotFound, "Role not found"),
    Err(_) => error_response(StatusCode::InternalServerError, "Failed to fetch role"),
  }
}

#[derive(Deserialize)]
pub struct UpdateRolePayload {
  name: String,
}

pub async fn update_role(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid role ID"),
  };
  let payload: UpdateRolePayload = match serde_json::from_slice(req.body.as_bytes()) {
    Ok(p) => p,
    Err(_) => return error_response(StatusCode::BadRequest, "Invalid request body"),
  };
  match sqlx::query("CALL auth.update_role($1, $2)")
    .bind(id)
    .bind(payload.name)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::Ok.to_string(),
      content_type: "application/json".to_string(),
      content: json!({ "status": "success" }).to_string().into_bytes(),
    },
    Err(err) => {
      eprintln!("[handler-error] update_role: {}", err);
      error_response(StatusCode::InternalServerError, "Failed to update role")
    }
  }
}

pub async fn delete_role(req: &Request) -> Response {
  let (db, _, _) = match require_token_without_renew(req).await {
    Ok(tuple) => tuple,
    Err(response) => return response,
  };
  let id: i32 = match req.params.get("id").and_then(|s| s.parse().ok()) {
    Some(id) => id,
    None => return error_response(StatusCode::BadRequest, "Invalid role ID"),
  };
  match sqlx::query("CALL auth.delete_role($1)")
    .bind(id)
    .execute(db.pool())
    .await
  {
    Ok(_) => Response {
      status: StatusCode::NoContent.to_string(),
      content_type: "application/json".to_string(),
      content: Vec::new(),
    },
    Err(_) => error_response(StatusCode::InternalServerError, "Failed to delete role"),
  }
}
