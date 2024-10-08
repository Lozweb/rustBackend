use anyhow::Result;
use axum::Json;
use reqwest::Client;
use rust_backend::user::model::AuthUser;

#[tokio::test]
async fn register_already_exist_should_conflict() -> Result<()> {
    let client = httpc_test::new_client("http://localhost:3000")?;
    let res = client.do_post(
        "/api/user/register",
        (r#"{"username":"julien","email":"aelozweb@gmail.com","password":"123456"}"#,
         "application/json"),
    )
        .await?;

    assert_eq!(res.status(), 409);
    res.print().await?;

    Ok(())
}

#[tokio::test]
async fn register_should_succeed() -> Result<()> {
    let client = httpc_test::new_client("http://localhost:3000")?;
    let res = client.do_post(
        "/api/user/register",
        (r#"{"username":"durondil","email":"a6mic48@gmail.com","password":"123456"}"#, "application/json"),
    )
        .await?;

    assert_eq!(res.status(), 200);
    res.print().await?;

    Ok(())
}

#[tokio::test]
async fn confirm_email_should_succed() -> Result<()> {
    let client = httpc_test::new_client("http://localhost:3000")?;
    let res = client.do_post(
        "/api/user/confirm/eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6ImE2bWljNDhAZ21haWwuY29tIiwiZXhwIjoxNzI4MzE0NDQ1fQ.Q7i5vt289LmpLdegifSsOxOn2SQFUidhiM5-PHFCfBI",
        "",
    ).await?;

    assert_eq!(res.status(), 200);
    res.print().await?;

    Ok(())
}

#[tokio::test]
async fn login_with_username_should_success() -> Result<()> {
    let client = httpc_test::new_client("http://localhost:3000")?;
    let res = client.do_post(
        "/api/user/login",
        (r#"{"username_or_email":"julien","password":"1234"}"#, "application/json"),
    ).await?;

    assert_eq!(res.status(), 200);
    res.print().await?;
    Ok(())
}

#[tokio::test]
async fn login_with_email_should_success() -> Result<()> {
    let client = httpc_test::new_client("http://localhost:3000")?;
    let res = client.do_post(
        "/api/user/login",
        (r#"{"username_or_email":"a6mic48@gmail.com","password":"123456"}"#, "application/json"),
    ).await?;

    assert_eq!(res.status(), 200);
    res.print().await?;
    Ok(())
}

#[tokio::test]
async fn login_with_bad_credentials_should_fail() -> Result<()> {
    let client = httpc_test::new_client("http://localhost:3000")?;
    let res = client.do_post(
        "/api/user/login",
        (r#"{"username_or_email":"julien","password":"123456"}"#, "application/json"),
    ).await?;

    assert_eq!(res.status(), 401);
    res.print().await?;
    Ok(())
}

#[tokio::test]
async fn login_with_bad_credentials_should_fail2() -> Result<()> {
    let client = httpc_test::new_client("http://localhost:3000")?;
    let res = client.do_post(
        "/api/user/login",
        (r#"{"username_or_email":"durondil","password":"1234"}"#, "application/json"),
    ).await?;

    assert_eq!(res.status(), 401);
    res.print().await?;
    Ok(())
}

#[tokio::test]
async fn get_users_with_auth_token_should_success() -> Result<()> {
    let client = Client::new()
        .get("http://localhost:3000/api/user")
        .header("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjAxOTI2NzIzLWY3ZTktNzIxOC04YmYyLWQwOTIwYTNiZTlmNiIsInVzZXJuYW1lIjoiZHVyb25kaWwiLCJlbWFpbCI6ImE2bWljNDhAZ21haWwuY29tIiwiZXhwIjoxNzI4NDgwMTY0fQ.hUeHYxCDEa5Z33_QzgtYz99eueaWF6rnEyD0sJ0bpKc");

    let res = client.send().await?;
    assert_eq!(res.status(), 200);

    println!("{:#?}", res);
    let body = Json::<Vec<AuthUser>>(res.json().await?);
    println!("{:?}", body);
    Ok(())
}

#[tokio::test]
async fn get_user_with_none_token_should_fail() -> Result<()> {
    let client = Client::new()
        .get("http://localhost:3000/api/user")
        .header("Authorization", "Bearer ");
    let res = client.send().await?;
    assert_eq!(res.status(), 401);

    println!("{:#?}", res);
    Ok(())
}

#[tokio::test]
async fn ask_reset_password_should_success() -> Result<()> {
    let client = httpc_test::new_client("http://localhost:3000")?;
    let res = client.do_post(
        "/api/user/reset",
        (r#"
            {
              "Ask": {
                "email": "a6mic48@gmail.com"
              }
            }
        "#, "application/json"),
    ).await?;

    assert_eq!(res.status(), 200);
    res.print().await?;

    Ok(())
}

#[tokio::test]
async fn ask_reset_password_with_unknown_user_should_fail() -> Result<()> {
    let client = httpc_test::new_client("http://localhost:3000")?;
    let res = client.do_post(
        "/api/user/reset",
        (r#"
            {
              "Ask": {
                "email": "user@example.com"
              }
            }
        "#, "application/json"),
    ).await?;

    assert_eq!(res.status(), 400);
    res.print().await?;

    Ok(())
}

#[tokio::test]
async fn reset_password_confirmation_should_success() -> Result<()> {
    let client = httpc_test::new_client("http://localhost:3000")?;
    let res = client.do_post(
        "/api/user/reset",
        (r#"
                {
                    "Reset": {
                        "token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6ImE2bWljNDhAZ21haWwuY29tIiwiZXhwIjoxNzI4MzE0ODc2fQ.UgIWQOpRmWmr0SbTgg-YEKyqjjs8Ul7buDnq5g8yIzg",
                        "password":"01234"
                    }
                }
        "#, "application/json"),
    ).await?;

    assert_eq!(res.status(), 200);
    res.print().await?;

    Ok(())
}

#[tokio::test]
async fn reset_password_confirmation_with_bad_token_should_fail() -> Result<()> {
    let client = httpc_test::new_client("http://localhost:3000")?;
    let res = client.do_post(
        "/api/user/reset",
        (r#"
                {
                    "Reset": {
                        "token":"bad_token",
                        "password":"01234"
                    }
                }
        "#, "application/json"),
    ).await?;

    assert_eq!(res.status(), 401);
    res.print().await?;

    Ok(())
}

#[tokio::test]
async fn login_with_new_credential() -> Result<()> {
    let client = httpc_test::new_client("http://localhost:3000")?;
    let res = client.do_post(
        "/api/user/login",
        (r#"{"username_or_email":"durondil","password":"01234"}"#, "application/json"),
    ).await?;

    assert_eq!(res.status(), 200);
    res.print().await?;
    Ok(())
}