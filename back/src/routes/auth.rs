use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use sqlx::PgPool;
use std::sync::Arc;

use crate::models::auth::{AuthResponse, LoginRequest, RegisterRequest};
use crate::models::user::User;
use crate::utils::auth::{create_jwt, hash_password, verify_password};

pub async fn register(
    State(pool): State<Arc<PgPool>>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    let hashed_password = match hash_password(payload.password).await {
        Ok(h) => h,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(AuthResponse {
            message: "Failed to hash password".to_string(),
            token: None,
        })),
    };

    let role = payload.role.unwrap_or_else(|| "Viewer".to_string());

    let result = sqlx::query(
        "INSERT INTO users (username, email, password, role, created_at, updated_at) VALUES ($1, $2, $3, $4, NOW(), NOW())"
    )
    .bind(payload.username)
    .bind(payload.email)
    .bind(hashed_password)
    .bind(role)
    .execute(&*pool)
    .await;

    match result {
        Ok(_) => (StatusCode::CREATED, Json(AuthResponse {
            message: "User created successfully".to_string(),
            token: None,
        })),
        Err(e) => (StatusCode::BAD_REQUEST, Json(AuthResponse {
            message: format!("Failed to create user: {}", e),
            token: None,
        })),
    }
}

pub async fn login(
    State(pool): State<Arc<PgPool>>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let user = match sqlx::query_as::<_, User>(
        "SELECT id, username, email, password, role, created_at, updated_at FROM users WHERE username = $1"
    )
    .bind(payload.username.clone())
    .fetch_optional(&*pool)
    .await
    {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::UNAUTHORIZED, Json(AuthResponse {
            message: "Invalid username or password".to_string(),
            token: None,
        })),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(AuthResponse {
            message: format!("Database error: {}", e),
            token: None,
        })),
    };

    if !verify_password(payload.password, user.password).await {
        return (StatusCode::UNAUTHORIZED, Json(AuthResponse {
            message: "Invalid username or password".to_string(),
            token: None,
        }));
    }

    let role_str = match user.role {
        crate::models::user::Role::Admin => "Admin",
        crate::models::user::Role::Viewer => "Viewer",
    };

    match create_jwt(&user.username, role_str) {
        Ok(token) => (StatusCode::OK, Json(AuthResponse {
            message: "Login successful".to_string(),
            token: Some(token),
        })),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(AuthResponse {
            message: "Failed to create token".to_string(),
            token: None,
        })),
    }
}
