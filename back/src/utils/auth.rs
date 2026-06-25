use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation};
use chrono::{Utc, Duration};
use crate::models::auth::Claims;
use std::env;
use once_cell::sync::Lazy;

static JWT_SECRET: Lazy<String> = Lazy::new(|| {
    env::var("JWT_SECRET").expect("JWT_SECRET must be set in .env")
});

pub async fn hash_password(password: String) -> Result<String, bcrypt::BcryptError> {
    tokio::task::spawn_blocking(move || {
        bcrypt::hash(password, bcrypt::DEFAULT_COST)
    })
    .await
    .expect("Task panicked")
}

pub async fn verify_password(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || {
        bcrypt::verify(password, &hash).unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

pub fn create_jwt(username: &str, role: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = Utc::now() + Duration::hours(24);
    let claims = Claims {
        sub: username.to_owned(),
        role: role.to_owned(),
        exp: expiration.timestamp(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes())
    )
}

pub fn verify_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::default();
    validation.validate_exp = true;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &validation
    )?;
    
    Ok(token_data.claims)
}