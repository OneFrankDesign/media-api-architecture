use anyhow::{anyhow, Context, Result};
use reqwest::{header, Client, StatusCode};
use serde_json::json;
use tokio::time::{sleep, Duration};

fn env_or_default(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn set_cookie_headers(response: &reqwest::Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(ToOwned::to_owned))
        .collect()
}

fn cookie_value_from_set_cookie(set_cookie: &[String], cookie_name: &str) -> Option<String> {
    set_cookie.iter().find_map(|cookie| {
        let mut parts = cookie.split(';');
        let first = parts.next()?.trim();
        let (name, value) = first.split_once('=')?;
        if name == cookie_name {
            Some(value.to_string())
        } else {
            None
        }
    })
}

async fn wait_for_ok(client: &Client, url: &str) -> Result<()> {
    let mut last_status: Option<StatusCode> = None;

    for _ in 0..120 {
        match client.get(url).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => {
                last_status = Some(response.status());
            }
            Err(_) => {}
        }

        sleep(Duration::from_millis(1000)).await;
    }

    Err(anyhow!(
        "timed out waiting for readiness at {url}; last status: {last_status:?}"
    ))
}

async fn wait_for_stack(client: &Client) -> Result<()> {
    let envoy_admin_port = env_or_default("ENVOY_ADMIN_PORT", "9901");
    let auth_port = env_or_default("AUTH_API_PORT", "8081");
    let main_health_port = env_or_default("MAIN_API_HEALTH_PORT", "50052");

    wait_for_ok(
        client,
        &format!("http://localhost:{envoy_admin_port}/ready"),
    )
    .await?;
    wait_for_ok(client, &format!("http://localhost:{auth_port}/health")).await?;
    wait_for_ok(
        client,
        &format!("http://localhost:{main_health_port}/healthz"),
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn compose_services_report_healthy() -> Result<()> {
    let client = Client::builder().build().context("client should build")?;
    wait_for_stack(&client).await?;

    let auth_port = env_or_default("AUTH_API_PORT", "8081");
    let main_health_port = env_or_default("MAIN_API_HEALTH_PORT", "50052");

    let auth = client
        .get(format!("http://localhost:{auth_port}/health"))
        .send()
        .await
        .context("auth health request should succeed")?;
    assert_eq!(auth.status(), StatusCode::OK);

    let main = client
        .get(format!("http://localhost:{main_health_port}/healthz"))
        .send()
        .await
        .context("main health request should succeed")?;
    assert_eq!(main.status(), StatusCode::OK);

    Ok(())
}

#[tokio::test]
async fn gateway_auth_session_and_logout_flow_succeeds_with_valid_origin_and_csrf() -> Result<()> {
    let client = Client::builder().build().context("client should build")?;
    wait_for_stack(&client).await?;

    let gateway_port = env_or_default("ENVOY_HTTP_PORT", "8080");
    let origin = "http://localhost:3000";
    let bootstrap_csrf = "bootstrap-csrf";

    let create_response = client
        .post(format!("http://localhost:{gateway_port}/auth/session"))
        .header(header::ORIGIN, origin)
        .header("x-csrf-token", bootstrap_csrf)
        .header(header::COOKIE, format!("csrf-token={bootstrap_csrf}"))
        .json(&json!({"subject": "e2e-user"}))
        .send()
        .await
        .context("session create request should succeed")?;

    assert_eq!(create_response.status(), StatusCode::CREATED);
    let set_cookies = set_cookie_headers(&create_response);
    let session_cookie =
        cookie_value_from_set_cookie(&set_cookies, "session").context("session cookie missing")?;
    let csrf_cookie =
        cookie_value_from_set_cookie(&set_cookies, "csrf-token").context("csrf cookie missing")?;

    let logout_response = client
        .post(format!("http://localhost:{gateway_port}/auth/logout"))
        .header(header::ORIGIN, origin)
        .header("x-csrf-token", csrf_cookie.clone())
        .header(
            header::COOKIE,
            format!("session={session_cookie}; csrf-token={csrf_cookie}"),
        )
        .send()
        .await
        .context("logout request should succeed")?;

    assert_eq!(logout_response.status(), StatusCode::OK);
    let logout_cookies = set_cookie_headers(&logout_response);
    assert!(logout_cookies
        .iter()
        .any(|cookie| cookie.starts_with("session=deleted") && cookie.contains("Max-Age=0")));
    assert!(logout_cookies
        .iter()
        .any(|cookie| cookie.starts_with("csrf-token=deleted") && cookie.contains("Max-Age=0")));

    Ok(())
}

#[tokio::test]
async fn gateway_rejects_invalid_origin_and_missing_csrf() -> Result<()> {
    let client = Client::builder().build().context("client should build")?;
    wait_for_stack(&client).await?;

    let gateway_port = env_or_default("ENVOY_HTTP_PORT", "8080");

    let invalid_origin_response = client
        .post(format!("http://localhost:{gateway_port}/auth/session"))
        .header(header::ORIGIN, "http://evil.local")
        .json(&json!({"subject": "attacker"}))
        .send()
        .await
        .context("invalid origin request should return response")?;

    assert_eq!(invalid_origin_response.status(), StatusCode::FORBIDDEN);
    let invalid_origin_body = invalid_origin_response
        .text()
        .await
        .context("response body should be readable")?;
    assert!(invalid_origin_body.contains("invalid origin"));

    let missing_csrf_response = client
        .post(format!("http://localhost:{gateway_port}/auth/session"))
        .header(header::ORIGIN, "http://localhost:3000")
        .json(&json!({"subject": "user"}))
        .send()
        .await
        .context("missing csrf request should return response")?;

    assert_eq!(missing_csrf_response.status(), StatusCode::FORBIDDEN);
    let missing_csrf_body = missing_csrf_response
        .text()
        .await
        .context("response body should be readable")?;
    assert!(missing_csrf_body.contains("csrf token mismatch"));

    Ok(())
}

#[tokio::test]
async fn gateway_does_not_bypass_security_for_unknown_auth_paths() -> Result<()> {
    let client = Client::builder().build().context("client should build")?;
    wait_for_stack(&client).await?;

    let gateway_port = env_or_default("ENVOY_HTTP_PORT", "8080");

    let response = client
        .post(format!("http://localhost:{gateway_port}/auth/admin/stats"))
        .header(header::ORIGIN, "http://localhost:3000")
        .header("x-csrf-token", "bootstrap-csrf")
        .header(header::COOKIE, "csrf-token=bootstrap-csrf")
        .json(&json!({}))
        .send()
        .await
        .context("request should return response")?;

    assert_ne!(response.status(), StatusCode::NOT_FOUND);
    assert!(response.status().is_client_error());

    Ok(())
}
