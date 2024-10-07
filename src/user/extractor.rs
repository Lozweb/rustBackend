use crate::config::Config;
use crate::error::AppError;
use crate::user::model::AuthUser;
use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::{Extension, RequestPartsExt};
use jsonwebtoken::{decode, Validation};

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let config = parts.extract::<Extension<Config>>().await?;
        try_extract_bearer(parts)
            .ok_or(AppError::Unauthorized)
            .and_then(|value| {
                decode::<AuthUser>(value, &config.auth_keys.decoding, &Validation::default())
                    .map_err(|_| AppError::Unauthorized)
            })
            .map(|token| token.claims)
    }
}

fn try_extract_bearer(parts: &mut Parts) -> Option<&str> {
    parts
        .headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}