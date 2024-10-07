use crate::config::Config;
use crate::error::{AppError, Result};
use crate::user::model::{AuthUser, Claims, Credentials, EmailToken, User};
use anyhow::Error;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use jsonwebtoken::{encode, Header};
use sqlx::{query, query_as, PgPool};
use uuid::Uuid;

pub async fn users(
    db: &PgPool
) -> Result<Vec<AuthUser>> {
    Ok(query_as!(AuthUser, r#"SELECT id, username, email FROM "user""#).fetch_all(db).await?)
}

pub async fn user_by_username_or_email(
    db: &PgPool,
    credentials: &Credentials,
) -> Result<Option<User>> {
    let user = query_as!(
            User,
            r#"SELECT * FROM "user" WHERE username = $1 OR email = $1"#,
            credentials.username_or_email.trim().to_ascii_lowercase()
        )
        .fetch_optional(db)
        .await?;
    Ok(user)
}

pub async fn user_by_email(
    db: &PgPool,
    email: &str,
) -> Result<Option<User>> {
    let user = query_as!(User,r#"SELECT * FROM "user" WHERE email = $1"#, email)
        .fetch_optional(db)
        .await?;
    Ok(user)
}

pub async fn user_email_exist(
    db: &PgPool,
    email: &str,
) -> Result<bool> {
    let count = query!(r#"SELECT COUNT(*) FROM "user" WHERE email = $1"#, email)
        .fetch_one(db)
        .await?
        .count
        .unwrap_or(0);

    Ok(count > 0)
}

pub async fn username_or_email_exist(
    db: &PgPool,
    username: &str,
    email: &str,
) -> Result<bool> {
    let count = query!(
            r#"
                SELECT count(*) FROM "user" WHERE username = $1 OR email = $2
            "#,
            username,
            email
        )
        .fetch_one(db)
        .await?
        .count
        .unwrap_or(0);

    Ok(count > 0)
}

pub async fn update_password(
    db: &PgPool,
    email: &str,
    password: &str,
) -> Result<()> {
    let salt = SaltString::generate(&mut OsRng);
    let pass = hash_password(password, &salt)?;
    query!(
            r#"
                UPDATE "user" SET password = $2
                WHERE email = $1
            "#,
            email,
            pass.to_string()
        )
        .execute(db)
        .await?;
    Ok(())
}


pub async fn add_user(
    db: &PgPool,
    id: &Uuid,
    username: &str,
    email: &str,
    password: &str,
) -> Result<()> {
    let salt = SaltString::generate(&mut OsRng);
    let password = hash_password(password, &salt)?;
    query!(
                r#"
                    INSERT INTO "user" (id, username, email, password)
                    VALUES ($1, $2, $3, $4)
                "#,
                id,
                username,
                email,
                password.to_string()
            )
        .execute(db)
        .await?;
    Ok(())
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