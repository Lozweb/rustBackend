use crate::config::Config;
use crate::db::new_uuid;
use crate::error::{AppError, Result};
use crate::user::mail::{send_invitation_mail, send_reset_mail};
use crate::user::model::{AuthResponse, AuthUser, Credentials, EmailToken, PendingQuery, RegisterQuery, ResetQuery, ResetResponse, UserPendingQueryCache};
use crate::user::service::{add_user, generate_email_token, generate_token, update_password, user_by_email, user_by_username_or_email, user_email_exist, username_or_email_exist, users, verify_password};
use axum::extract::Path;
use axum::{Extension, Json};
use jsonwebtoken::{decode, Validation};
use sqlx::PgPool;
use tracing::log::info;

pub async fn get_users(
    Extension(db): Extension<PgPool>,
    _: AuthUser,
) -> Result<Json<Vec<AuthUser>>> {
    Ok(Json(users(&db).await?))
}
pub async fn login(
    Extension(db): Extension<PgPool>,
    Extension(config): Extension<Config>,
    Json(credentials): Json<Credentials>,
) -> Result<Json<AuthResponse>> {
    verify_password(
        user_by_username_or_email(&db, &credentials).await?.ok_or(AppError::NotFound)?,
        &credentials.password,
    )
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

async fn ask_for_reset(
    db: &PgPool,
    config: &Config,
    cache: &UserPendingQueryCache,
    email: String,
) -> Result<ResetResponse> {
    let email = email.trim().to_ascii_lowercase();

    if email.is_empty() { return Err(AppError::BadRequest); }

    if !user_email_exist(db, &email).await? {
        info!("User not exists");
        return Err(AppError::BadRequest);
    }

    let email_token = generate_email_token(config, &email)?;
    info!("Email token: {}", email_token);
    cache.insert(email.clone(), PendingQuery::Reset(email_token.clone()));
    send_reset_mail(config, &email, &email_token).await?;

    Ok(ResetResponse::EmailSent)
}

async fn reset_password(
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
                return Err(AppError::BadRequest);
            }

            update_password(db, email, &password).await?;

            user_by_email(db, email)
                .await?
                .ok_or(AppError::Unauthorized)
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

pub async fn register(
    Extension(db): Extension<PgPool>,
    Extension(cache): Extension<UserPendingQueryCache>,
    Extension(config): Extension<Config>,
    Json(q): Json<RegisterQuery>,
) -> Result<()> {
    let (username, email) = (
        q.username.trim().to_ascii_lowercase(),
        q.email.trim().to_ascii_lowercase()
    );

    if email.is_empty() || username.is_empty() || q.password.is_empty() {
        return Err(AppError::BadRequest);
    }

    if username_or_email_exist(&db, &username, &email).await? {
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
            add_user(&db, &id, &query.username, &query.email, &query.password).await?;

            generate_token(&config, id, query.username, query.email)
                .map(|token| Json(AuthResponse { token }))
        }
        _ => Err(AppError::Unauthorized),
    }
}