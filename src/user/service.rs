use crate::config::Config;
use crate::error::{AppError, Result};
use crate::user::model::{Claims, EmailToken, User};
use anyhow::Error;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use jsonwebtoken::{encode, Header};
use uuid::Uuid;

pub fn generate_email_token(config: &Config, email: &str) -> Result<String> {
    let claims = EmailToken {
        email: email.to_string(),
        exp: get_timestamp_2_hours_from_now(),
    };
    encode(&Header::default(), &claims, &config.auth_keys.encoding)
        .map_err(|e| AppError::Unexpected(Error::from(e)))
}

pub fn generate_token(
    config: &Config,
    id: Uuid,
    username: String,
    email: String,
) -> Result<String> {
    let claims = Claims {
        id,
        username,
        email,
        exp: get_timestamp_two_day_from_now(),
    };
    encode(&Header::default(), &claims, &config.auth_keys.encoding)
        .map_err(|e| AppError::Unexpected(Error::from(e)))
}

pub fn hash_password<'a>(password: &str, salt: &'a SaltString) -> Result<PasswordHash<'a>> {
    Argon2::default()
        .hash_password(password.as_bytes(), salt)
        .map_err(|e| AppError::Unexpected(Error::msg(format!("Failed to hash password : {e}"))))
}

pub fn verify_password(user: User, password: &str) -> Result<User> {
    let hash = PasswordHash::new(&user.password).map_err(|_| AppError::Unauthorized)?;
    Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .map_err(|_| AppError::Unauthorized)
        .map(|_| user)
}

fn get_timestamp_2_hours_from_now() -> i64 {
    use chrono::{Duration, Utc};
    (Utc::now() + Duration::hours(2)).timestamp()
}

fn get_timestamp_two_day_from_now() -> i64 {
    use chrono::{Duration, Utc};
    (Utc::now() + Duration::days(2)).timestamp()
}