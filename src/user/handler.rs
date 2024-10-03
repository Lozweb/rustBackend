use crate::config::Config;
use crate::db::new_uuid;
use crate::error::{AppError, Result};
use crate::user::mail::send_invitation_mail;
use crate::user::model::{AuthResponse, EmailToken, PendingQuery, RegisterQuery, UserPendingQueryCache};
use crate::user::service::{generate_email_token, generate_token, hash_password};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use axum::extract::Path;
use axum::{Extension, Json};
use jsonwebtoken::{decode, Validation};
use sqlx::{query, PgPool};

pub async fn register(
    Extension(db): Extension<PgPool>,
    Extension(cache): Extension<UserPendingQueryCache>,
    Extension(config): Extension<Config>,
    Json(q): Json<RegisterQuery>,
) -> Result<()> {
    let username = q.username.trim().to_ascii_lowercase();
    let email = q.email.trim().to_ascii_lowercase();
    if email.is_empty() || username.is_empty() || q.password.is_empty() {
        return Err(AppError::BadRequest);
    }

    let count = query!(
        r#"
            SELECT count(*) FROM "user" WHERE username = $1 OR email = $2
        "#,
        username,
        email
    )
        .fetch_one(&db)
        .await?
        .count
        .unwrap_or(0);

    if count > 0 {
        return Err(AppError::Conflict("Username or Email already exists".to_string()));
    }

    let pending_invite = generate_email_token(&config, &email)?;

    println!("{}", pending_invite);

    cache.insert(email.clone(), PendingQuery::Invite(pending_invite.clone(), q.clone()));

    send_invitation_mail(&config, &email, &pending_invite).await?;

    Ok(())
}

pub async fn confirm(
    Extension(db): Extension<PgPool>,
    Extension(config): Extension<Config>,
    Extension(cache): Extension<UserPendingQueryCache>,
    Path(token): Path<String>,
) -> Result<Json<AuthResponse>> {
    println!("tokent = {}", token);

    let pending_invite =
        decode::<EmailToken>(&token, &config.auth_keys.decoding, &Validation::default())
            .map_err(|_| AppError::Unauthorized)?;

    println!("pending invite = {:?}", pending_invite);

    let pending_query = cache
        .get(&pending_invite.claims.email)
        .ok_or_else(|| AppError::Unauthorized)?;

    println!("pending query = {:?}", pending_query);

    match pending_query {
        PendingQuery::Invite(invite_token, query) => {
            if token != invite_token {
                return Err(AppError::Unauthorized);
            }
            let id = new_uuid();
            let salt = SaltString::generate(&mut OsRng);
            let password = hash_password(&query.password, &salt)?;
            query!(
                r#"
                    INSERT INTO "user" (id, username, email, password)
                    VALUES ($1, $2, $3, $4)
                "#,
                id,
                query.username,
                query.email,
                password.to_string()
            )
                .execute(&db)
                .await?;

            generate_token(&config, id, query.username, query.email)
                .map(|token| Json(AuthResponse { token }))
        }
        _ => Err(AppError::Unauthorized),
    }
}