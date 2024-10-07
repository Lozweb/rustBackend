use crate::config::Config;
use crate::db::new_uuid;
use crate::error::{AppError, Result};
use crate::user::mail::send_invitation_mail;
use crate::user::model::{AuthResponse, AuthUser, Credentials, EmailToken, PendingQuery, RegisterQuery, ResetQuery, ResetResponse, User, UserPendingQueryCache};
use crate::user::service::{ask_for_reset, generate_email_token, generate_token, hash_password, reset_password, verify_password};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use axum::extract::Path;
use axum::{Extension, Json};
use jsonwebtoken::{decode, Validation};
use sqlx::{query, query_as, PgPool};
use tracing::log::info;

pub async fn get_users(
    Extension(db): Extension<PgPool>,
    _: AuthUser,
) -> Result<Json<Vec<AuthUser>>> {
    let users = query_as!(AuthUser, r#"SELECT id, username, email FROM "user""#)
        .fetch_all(&db).await?;
    Ok(Json(users))
}

pub async fn login(
    Extension(db): Extension<PgPool>,
    Extension(config): Extension<Config>,
    Json(credentials): Json<Credentials>,
) -> Result<Json<AuthResponse>> {
    query_as!(
        User,
        r#"SELECT * FROM "user" WHERE username = $1 OR email = $1"#,
        credentials.username_or_email.trim().to_ascii_lowercase()
    )
        .fetch_optional(&db)
        .await?
        .ok_or_else(|| AppError::Unauthorized)
        .and_then(|u| verify_password(u, &credentials.password))
        .and_then(|u| {
            let id = u.id.expect("User id is missing");
            let username = u.username;
            generate_token(&config, id, username, u.email)
        })
        .map(|token| Json(AuthResponse { token }))
}

pub async fn reset(
    Extension(db): Extension<PgPool>,
    Extension(config): Extension<Config>,
    Extension(cache): Extension<UserPendingQueryCache>,
    Json(q): Json<ResetQuery>,
) -> Result<Json<ResetResponse>> {
    let response = match q {
        ResetQuery::Ask { email } => { ask_for_reset(&db, &config, &cache, email).await? }
        ResetQuery::Reset { token, password } => { reset_password(&db, &config, &cache, token, password).await? }
    };

    Ok(Json(response))
}

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

    info!("{}", pending_invite);

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
    let pending_invite =
        decode::<EmailToken>(&token, &config.auth_keys.decoding, &Validation::default())
            .map_err(|_| AppError::Unauthorized)?;

    let pending_query = cache
        .get(&pending_invite.claims.email)
        .ok_or_else(|| AppError::Unauthorized)?;

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