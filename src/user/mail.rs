use crate::config::Config;
use anyhow::Result;
use reqwest::header::ACCEPT;
use reqwest::Client;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct User {
    name: Option<String>,
    email: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    sender: User,
    to: Vec<User>,
    subject: String,
    html_content: String,
}

pub async fn send_invitation_mail(config: &Config, email: &str, token: &str) -> Result<()> {
    let body = format!(
        r#"
            Bonjour, validez votre compte en cliquant sur le lien suivant (valide pendant 2h)
            <a href="https://localhost:3000/confirm/{token}">Valider mon adresse email</a><br><br>
        "#
    );
    send_mail(config, "aelozweb@gmail.com", email, "Bienvenue", &body).await?;
    Ok(())
}

pub async fn send_reset_mail(config: &Config, email: &str, token: &str) -> Result<()> {
    let body = format!(
        r#"
            Bonjour, modifier votre mot de passe en cliquant sur le lien (valide pendant 2h)
            <a href="https://jamin.gjini.co/reset?token={token}">Modifier mon mot de passe</a>
        "#
    );

    send_mail(config, "aelozweb@gmail.com", email, "Modifier mon mot de passe", &body).await?;
    Ok(())
}

pub(crate) async fn send_mail(
    config: &Config,
    from: &str,
    to: &str,
    subject: &str,
    text: &str,
) -> Result<()> {
    Client::new()
        .post("https://api.brevo.com/v3/smtp/email")
        .header("api-key", config.brevo_api_key.to_owned())
        .header(ACCEPT, "application/json")
        .json(&Payload {
            sender: User {
                name: Some("Julien".to_string()),
                email: from.to_string(),
            },
            to: vec![User {
                name: None,
                email: to.to_string()
            }],
            subject: subject.to_string(),
            html_content: text.to_string(),
        })
        .send()
        .await?;
    Ok(())
}