use crate::config::Config;
use crate::error::AppError::BadRequest;
use crate::error::{AppError, Result};
use crate::user::mail::send_reset_mail;
use crate::user::model::{Claims, EmailToken, PendingQuery, ResetResponse, User, UserPendingQueryCache};
use anyhow::Error;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use jsonwebtoken::{decode, encode, Header, Validation};
use sqlx::{query, query_as, PgPool};
use uuid::Uuid;

pub async fn ask_for_reset(
    db: &PgPool,
    config: &Config,
    cache: &UserPendingQueryCache,
    email: String,
) -> Result<ResetResponse> {
    let email = email.trim().to_ascii_lowercase();
    if email.is_empty() {
        return Err(BadRequest);
    }
    let count = query!(
        r#"
            SELECT COUNT(*) FROM "user" WHERE email = $1
        "#,
        email
    )
        .fetch_one(db)
        .await?
        .count
        .unwrap_or(0);

    if count > 0 {
        return Err(BadRequest);
    }

    let email_token = generate_email_token(config, &email)?;

    cache.insert(email.clone(), PendingQuery::Reset(email_token.clone()));

    send_reset_mail(config, &email, &email_token).await?;

    Ok(ResetResponse::EmailSent)
}

pub async fn reset_password(
    db: &PgPool,
    config: &Config,
    cache: &UserPendingQueryCache,
    token: String,
    password: String,
) -> Result<ResetResponse> {
    let pending_invite =
        decode::<EmailToken>(&token, &config.auth_keys.decoding, &Validation::default())
            .map_err(|_| AppError::Unauthorized)?;

    let email = &pending_invite.claims.email;

    let pending_query = cache.get(email).ok_or_else(|| AppError::Unauthorized)?;

    match pending_query {
        PendingQuery::Reset(invite_token) => {
            if token != invite_token {
                return Err(BadRequest);
            }
            let salt = SaltString::generate(&mut OsRng);
            let password = hash_password(&password, &salt)?;
            query!(
                r#"
                    UPDATE "user" SET password = $2
                    WHERE email = $1
                "#,
                email,
                password.to_string()
            )
                .execute(db)
                .await?;

            query_as!(User,r#"SELECT * FROM "user" WHERE email = $1"#, email)
                .fetch_optional(db)
                .await?
                .ok_or_else(|| AppError::Unauthorized)
                .and_then(|u| {
                    let id = u.id.expect("User id is missing");
                    let username = u.username;
                    generate_token(config, id, username, u.email)
                })
                .map(|token| ResetResponse::Changed { token })
        }
        _ => Err(AppError::Unauthorized)
    }
}

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