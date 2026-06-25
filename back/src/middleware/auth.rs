use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use crate::utils::auth::verify_jwt;

pub async fn require_auth(
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req.headers().get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let claims = verify_jwt(auth_header).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Insert claims into the request extensions so route handlers can access it
    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}
