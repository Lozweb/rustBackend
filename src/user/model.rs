use jsonwebtoken::{DecodingKey, EncodingKey};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Deserialize, Serialize)]
pub struct EmailToken {
    pub email: String,
    pub exp: i64,
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