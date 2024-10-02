use crate::config::Config;
use crate::error::{AppError, Result};
use crate::user::mail::send_invitation_mail;
use crate::user::model::{PendingQuery, RegisterQuery, UserPendingQueryCache};
use crate::user::service::generate_email_token;
use axum::{Extension, Json};
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

    cache.insert(email.clone(), PendingQuery::Invite(pending_invite.clone(), q.clone()));

    send_invitation_mail(&config, &email, &pending_invite).await?;

    Ok(())
}