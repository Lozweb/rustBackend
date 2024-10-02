use crate::config::Config;
use crate::error::{AppError, Result};
use crate::user::model::EmailToken;
use anyhow::Error;
use jsonwebtoken::{encode, Header};

pub fn generate_email_token(config: &Config, email: &str) -> Result<String> {
    let claims = EmailToken {
        email: email.to_string(),
        exp: get_timestamp_2_hours_from_now(),
    };
    encode(&Header::default(), &claims, &config.auth_keys.encoding)
        .map_err(|e| AppError::Unexpected(Error::from(e)))
}

fn get_timestamp_2_hours_from_now() -> i64 {
    use chrono::{Duration, Utc};
    (Utc::now() + Duration::hours(2)).timestamp()
}