use jsonwebtoken::{DecodingKey, EncodingKey};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

pub type UserPendingQueryCache = Cache<String, PendingQuery>;

#[derive(Debug, Clone)]
pub enum PendingQuery {
    Invite(String, RegisterQuery),
    Reset(String),
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegisterQuery {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Clone)]
pub enum ResetQuery {
    Ask { email: String },
    Reset { token: String, password: String },
}

#[derive(Debug, Serialize, Clone)]
pub enum ResetResponse {
    EmailSent,
    Changed { token: String },
}

#[derive(Debug, Deserialize)]
pub struct Credentials {
    pub username_or_email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Option<Uuid>,
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthResponse {
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EmailToken {
    pub email: String,
    pub exp: i64,
}

#[derive(Debug, Serialize)]
pub struct Claims {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub exp: i64,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct AuthUser {
    pub id: Uuid,
    pub username: String,
    pub email: String,
}

#[derive(Clone)]
pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl Keys {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}