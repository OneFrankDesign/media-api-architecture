use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use main_api::api::v1::metadata_service_client::MetadataServiceClient;
use main_api::api::v1::{
    CreateMetadataRequest, ListMetadataRequest, MetadataSortField, MetadataStatus, Visibility,
};
use reqwest::{header, redirect::Policy, Client, StatusCode, Url};
use serde_json::json;
use tokio::time::sleep;

const CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const CLIENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const READINESS_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

fn env_or_default(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn build_test_client() -> Result<Client> {
    Client::builder()
        .cookie_store(true)
        .connect_timeout(CLIENT_CONNECT_TIMEOUT)
        .timeout(CLIENT_REQUEST_TIMEOUT)
        .build()
        .context("client should build")
}

fn build_no_redirect_client() -> Result<Client> {
    Client::builder()
        .cookie_store(true)
        .redirect(Policy::none())
        .connect_timeout(CLIENT_CONNECT_TIMEOUT)
        .timeout(CLIENT_REQUEST_TIMEOUT)
        .build()
        .context("client should build")
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

fn response_header(
    response: &reqwest::Response,
    header_name: &header::HeaderName,
) -> Option<String> {
    response
        .headers()
        .get(header_name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

fn absolutize_url(base: &str, candidate: &str) -> Result<String> {
    if candidate.starts_with("http://") || candidate.starts_with("https://") {
        return Ok(candidate.to_string());
    }

    let base_url = Url::parse(base).context("base URL should parse")?;
    base_url
        .join(candidate)
        .map(|url| url.to_string())
        .context("relative URL should resolve against base")
}

fn extract_input_value(body: &str, marker: &str) -> Result<String> {
    let start = body
        .find(marker)
        .ok_or_else(|| anyhow!("expected marker not found: {marker}"))?;
    let after = &body[start + marker.len()..];
    let end = after
        .find('"')
        .ok_or_else(|| anyhow!("missing closing quote for marker: {marker}"))?;

    Ok(after[..end].replace("&amp;", "&"))
}

struct OidcLoginFlow {
    callback_url: String,
    challenge_cookie: String,
}

async fn wait_for_ok(client: &Client, url: &str) -> Result<()> {
    let mut last_status: Option<StatusCode> = None;
    let mut last_error: Option<String> = None;

    for _ in 0..120 {
        match client
            .get(url)
            .timeout(READINESS_REQUEST_TIMEOUT)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => {
                last_status = Some(response.status());
                last_error = None;
            }
            Err(error) => {
                last_error = Some(error.to_string());
            }
        }

        sleep(Duration::from_millis(1000)).await;
    }

    Err(anyhow!(
        "timed out waiting for readiness at {url}; last status: {last_status:?}; last error: {last_error:?}"
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

async fn complete_oidc_login_flow(client: &Client, gateway_port: &str) -> Result<OidcLoginFlow> {
    let login_response = client
        .get(format!("http://localhost:{gateway_port}/auth/login"))
        .send()
        .await
        .context("auth/login request should succeed")?;
    assert_eq!(login_response.status(), StatusCode::FOUND);
    let challenge_cookie =
        cookie_value_from_set_cookie(&set_cookie_headers(&login_response), "auth-challenge")
            .context("auth/login should set auth-challenge cookie")?;

    let authorize_location = response_header(&login_response, &header::LOCATION)
        .context("auth/login should set location header")?;
    let browser_authorize_url =
        authorize_location.replace("http://oidc-mock", "http://localhost:9080");

    let authorize_response = client
        .get(browser_authorize_url)
        .send()
        .await
        .context("OIDC authorize request should succeed")?;
    assert_eq!(authorize_response.status(), StatusCode::FOUND);

    let login_page_location = response_header(&authorize_response, &header::LOCATION)
        .context("authorize response should redirect to login page")?;
    let login_page_url = absolutize_url("http://localhost:9080", &login_page_location)?;

    let login_page_response = client
        .get(login_page_url.clone())
        .send()
        .await
        .context("OIDC login page request should succeed")?;
    assert_eq!(login_page_response.status(), StatusCode::OK);
    let login_page_html = login_page_response
        .text()
        .await
        .context("OIDC login page should be readable")?;

    let csrf_token = extract_input_value(
        &login_page_html,
        "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"",
    )?;
    let return_url = extract_input_value(&login_page_html, "name=\"ReturnUrl\" value=\"")?;

    let login_submit_response = client
        .post(login_page_url)
        .form(&[
            ("ReturnUrl", return_url.as_str()),
            ("Username", "testuser"),
            ("Password", "testpass"),
            ("button", "login"),
            ("__RequestVerificationToken", csrf_token.as_str()),
        ])
        .send()
        .await
        .context("OIDC login form submission should succeed")?;
    assert_eq!(login_submit_response.status(), StatusCode::FOUND);

    let authorize_callback_location = response_header(&login_submit_response, &header::LOCATION)
        .context("login form should redirect to authorize callback")?
        .replace("&amp;", "&");
    let authorize_callback_url =
        absolutize_url("http://localhost:9080", &authorize_callback_location)?;

    let authorize_callback_response = client
        .get(authorize_callback_url)
        .send()
        .await
        .context("OIDC authorize callback should succeed")?;
    assert_eq!(authorize_callback_response.status(), StatusCode::FOUND);

    let callback_url = response_header(&authorize_callback_response, &header::LOCATION)
        .context("authorize callback should redirect back to gateway callback")?;

    Ok(OidcLoginFlow {
        callback_url,
        challenge_cookie,
    })
}

fn pkce_verifier_from_challenge_cookie(challenge_cookie: &str) -> Result<String> {
    let (encoded_payload, _) = challenge_cookie
        .split_once('.')
        .ok_or_else(|| anyhow!("challenge cookie format is invalid"))?;
    let payload = URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .context("challenge cookie payload should decode")?;
    let payload_json = serde_json::from_slice::<serde_json::Value>(&payload)
        .context("challenge cookie payload should be valid json")?;

    payload_json
        .get("verifier")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("challenge cookie payload missing verifier"))
}

async fn fetch_access_token(client: &Client, gateway_port: &str) -> Result<String> {
    let login_flow = complete_oidc_login_flow(client, gateway_port).await?;
    let verifier = pkce_verifier_from_challenge_cookie(&login_flow.challenge_cookie)?;
    let callback_url =
        Url::parse(&login_flow.callback_url).context("gateway callback URL should parse")?;
    let code = callback_url
        .query_pairs()
        .find(|(name, _)| name == "code")
        .map(|(_, value)| value.to_string())
        .context("gateway callback URL should include authorization code")?;

    let response = client
        .post("http://localhost:9080/connect/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", "media-api-client"),
            ("client_secret", "media-api-secret"),
            ("code", code.as_str()),
            ("redirect_uri", "http://localhost:8080/auth/callback"),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .context("authorization code token request should succeed")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable body>".to_string());
        return Err(anyhow!("token endpoint returned {status}: {body}"));
    }

    let body = response
        .json::<serde_json::Value>()
        .await
        .context("token endpoint response should parse as json")?;
    if let Some(id_token) = body.get("id_token").and_then(|value| value.as_str()) {
        return Ok(id_token.to_string());
    }

    body.get("access_token")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("token endpoint response missing id_token/access_token"))
}

fn authorized_grpc_request<T>(inner: T, access_token: &str) -> Result<tonic::Request<T>> {
    let mut request = tonic::Request::new(inner);
    let auth_value = format!("Bearer {access_token}")
        .parse()
        .context("authorization metadata should parse")?;
    request.metadata_mut().insert("authorization", auth_value);
    request.metadata_mut().insert(
        "origin",
        "http://localhost:3000"
            .parse()
            .context("origin metadata should parse")?,
    );
    request.metadata_mut().insert(
        "x-csrf-token",
        "bootstrap-csrf"
            .parse()
            .context("csrf metadata should parse")?,
    );
    request.metadata_mut().insert(
        "cookie",
        "csrf-token=bootstrap-csrf"
            .parse()
            .context("cookie metadata should parse")?,
    );
    Ok(request)
}

fn csrf_ready_grpc_request<T>(inner: T) -> Result<tonic::Request<T>> {
    let mut request = tonic::Request::new(inner);
    request.metadata_mut().insert(
        "origin",
        "http://localhost:3000"
            .parse()
            .context("origin metadata should parse")?,
    );
    request.metadata_mut().insert(
        "x-csrf-token",
        "bootstrap-csrf"
            .parse()
            .context("csrf metadata should parse")?,
    );
    request.metadata_mut().insert(
        "cookie",
        "csrf-token=bootstrap-csrf"
            .parse()
            .context("cookie metadata should parse")?,
    );
    Ok(request)
}

#[tokio::test]
async fn compose_services_report_healthy() -> Result<()> {
    let client = build_test_client()?;
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
async fn auth_login_redirects_to_oidc_provider() -> Result<()> {
    let client = build_no_redirect_client()?;
    wait_for_stack(&client).await?;

    let gateway_port = env_or_default("ENVOY_HTTP_PORT", "8080");

    let response = client
        .get(format!("http://localhost:{gateway_port}/auth/login"))
        .send()
        .await
        .context("auth/login should return a response")?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location =
        response_header(&response, &header::LOCATION).context("location header missing")?;
    assert!(location.contains("/connect/authorize"));
    assert!(location.contains("code_challenge="));
    assert!(location.contains("state="));

    let set_cookies = set_cookie_headers(&response);
    assert!(set_cookies
        .iter()
        .any(|cookie| cookie.starts_with("auth-challenge=")
            && cookie.contains("Path=/auth/callback")));

    Ok(())
}

#[tokio::test]
async fn auth_callback_exchanges_code_and_sets_session() -> Result<()> {
    let client = build_no_redirect_client()?;
    wait_for_stack(&client).await?;

    let gateway_port = env_or_default("ENVOY_HTTP_PORT", "8080");
    let login_flow = complete_oidc_login_flow(&client, &gateway_port).await?;

    let callback_response = client
        .get(login_flow.callback_url)
        .send()
        .await
        .context("auth/callback request should return response")?;

    assert_eq!(callback_response.status(), StatusCode::FOUND);

    let set_cookies = set_cookie_headers(&callback_response);
    assert!(set_cookies
        .iter()
        .any(|cookie| cookie.starts_with("session=") && cookie.contains("HttpOnly")));
    assert!(set_cookies
        .iter()
        .any(|cookie| cookie.starts_with("csrf-token=")));
    assert!(set_cookies.iter().any(|cookie| {
        cookie.starts_with("auth-challenge=deleted") && cookie.contains("Max-Age=0")
    }));
    assert_eq!(
        response_header(&callback_response, &header::LOCATION).unwrap_or_default(),
        "/"
    );

    Ok(())
}

#[tokio::test]
async fn auth_session_deprecated_but_functional() -> Result<()> {
    let client = build_test_client()?;
    wait_for_stack(&client).await?;

    let gateway_port = env_or_default("ENVOY_HTTP_PORT", "8080");
    let origin = "http://localhost:3000";
    let bootstrap_csrf = "bootstrap-csrf";

    let response = client
        .post(format!("http://localhost:{gateway_port}/auth/session"))
        .header(header::ORIGIN, origin)
        .header("x-csrf-token", bootstrap_csrf)
        .header(header::COOKIE, format!("csrf-token={bootstrap_csrf}"))
        .json(&json!({"subject": "deprecated-flow-user"}))
        .send()
        .await
        .context("session create request should succeed")?;

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response_header(&response, &header::HeaderName::from_static("deprecation"))
            .unwrap_or_default(),
        "true"
    );
    assert!(response
        .headers()
        .contains_key(header::HeaderName::from_static("sunset")));

    Ok(())
}

#[tokio::test]
async fn gateway_auth_session_and_logout_flow_succeeds_with_valid_origin_and_csrf() -> Result<()> {
    let client = build_test_client()?;
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
    let client = build_test_client()?;
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
    let client = build_test_client()?;
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

#[tokio::test]
async fn gateway_grpc_rejects_missing_bearer_token() -> Result<()> {
    let client = build_no_redirect_client()?;
    wait_for_stack(&client).await?;

    let gateway_port = env_or_default("ENVOY_HTTP_PORT", "8080");
    let endpoint =
        tonic::transport::Endpoint::from_shared(format!("http://localhost:{gateway_port}"))
            .context("gateway endpoint should parse")?;
    let channel = endpoint
        .connect()
        .await
        .context("gRPC channel to gateway should connect")?;
    let mut grpc = MetadataServiceClient::new(channel);

    let err = grpc
        .list_metadata(csrf_ready_grpc_request(ListMetadataRequest {
            page_size: 1,
            page_token: String::new(),
            filter_owner_id: String::new(),
            filter_visibility: 0,
            filter_tags: vec![],
            search_query: String::new(),
            sort_direction: 1,
            filter_status: MetadataStatus::Unspecified as i32,
            sort_field: MetadataSortField::CreatedAt as i32,
        })?)
        .await
        .expect_err("missing bearer token should be rejected");

    assert!(matches!(
        err.code(),
        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
    ));

    Ok(())
}

#[tokio::test]
async fn cursor_pagination_through_gateway() -> Result<()> {
    let client = build_no_redirect_client()?;
    wait_for_stack(&client).await?;

    let gateway_port = env_or_default("ENVOY_HTTP_PORT", "8080");
    let endpoint =
        tonic::transport::Endpoint::from_shared(format!("http://localhost:{gateway_port}"))
            .context("gateway endpoint should parse")?;
    let channel = endpoint
        .connect()
        .await
        .context("gRPC channel to gateway should connect")?;
    let mut grpc = MetadataServiceClient::new(channel);

    let access_token = fetch_access_token(&client, &gateway_port).await?;

    let unique_prefix = format!(
        "e2e-cursor-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );

    for idx in 0..3 {
        let create_request = CreateMetadataRequest {
            title: format!("{unique_prefix}-{idx}"),
            description: "cursor e2e".to_string(),
            tags: vec![unique_prefix.clone()],
            mime_type: "video/mp4".to_string(),
            file_size: 100 + idx as i64,
            visibility: Visibility::Public as i32,
            status: MetadataStatus::Ready as i32,
            resolution: None,
            thumbnails: vec![],
            stats: None,
            custom_metadata: std::collections::HashMap::new(),
        };

        grpc.create_metadata(authorized_grpc_request(create_request, &access_token)?)
            .await
            .context("create_metadata should succeed")?;
    }

    let first_page = grpc
        .list_metadata(authorized_grpc_request(
            ListMetadataRequest {
                page_size: 2,
                page_token: String::new(),
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec![],
                search_query: unique_prefix.clone(),
                sort_direction: 1,
                filter_status: MetadataStatus::Ready as i32,
                sort_field: MetadataSortField::CreatedAt as i32,
            },
            &access_token,
        )?)
        .await
        .context("first paginated list should succeed")?
        .into_inner();

    assert_eq!(first_page.metadata_list.len(), 2);
    assert!(first_page.has_exact_count);
    assert!(!first_page.next_page_token.is_empty());

    let second_page = grpc
        .list_metadata(authorized_grpc_request(
            ListMetadataRequest {
                page_size: 2,
                page_token: first_page.next_page_token.clone(),
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec![],
                search_query: unique_prefix,
                sort_direction: 1,
                filter_status: MetadataStatus::Ready as i32,
                sort_field: MetadataSortField::CreatedAt as i32,
            },
            &access_token,
        )?)
        .await
        .context("second paginated list should succeed")?
        .into_inner();

    assert!(!second_page.metadata_list.is_empty());
    assert!(!second_page.has_exact_count);

    Ok(())
}

#[tokio::test]
async fn gateway_rejects_cursor_with_changed_filter_status() -> Result<()> {
    let client = build_no_redirect_client()?;
    wait_for_stack(&client).await?;

    let gateway_port = env_or_default("ENVOY_HTTP_PORT", "8080");
    let endpoint =
        tonic::transport::Endpoint::from_shared(format!("http://localhost:{gateway_port}"))
            .context("gateway endpoint should parse")?;
    let channel = endpoint
        .connect()
        .await
        .context("gRPC channel to gateway should connect")?;
    let mut grpc = MetadataServiceClient::new(channel);

    let access_token = fetch_access_token(&client, &gateway_port).await?;
    let unique_prefix = format!(
        "e2e-cursor-filter-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );

    for idx in 0..3 {
        grpc.create_metadata(authorized_grpc_request(
            CreateMetadataRequest {
                title: format!("{unique_prefix}-{idx}"),
                description: "cursor filter mismatch e2e".to_string(),
                tags: vec![unique_prefix.clone()],
                mime_type: "video/mp4".to_string(),
                file_size: 100 + idx as i64,
                visibility: Visibility::Private as i32,
                status: MetadataStatus::Ready as i32,
                resolution: None,
                thumbnails: vec![],
                stats: None,
                custom_metadata: std::collections::HashMap::new(),
            },
            &access_token,
        )?)
        .await
        .context("create_metadata should succeed")?;
    }

    let first_page = grpc
        .list_metadata(authorized_grpc_request(
            ListMetadataRequest {
                page_size: 2,
                page_token: String::new(),
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec![],
                search_query: unique_prefix.clone(),
                sort_direction: 1,
                filter_status: MetadataStatus::Ready as i32,
                sort_field: MetadataSortField::CreatedAt as i32,
            },
            &access_token,
        )?)
        .await
        .context("first paginated list should succeed")?
        .into_inner();
    assert!(!first_page.next_page_token.is_empty());

    let err = grpc
        .list_metadata(authorized_grpc_request(
            ListMetadataRequest {
                page_size: 2,
                page_token: first_page.next_page_token,
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec![],
                search_query: unique_prefix,
                sort_direction: 1,
                filter_status: MetadataStatus::Failed as i32,
                sort_field: MetadataSortField::CreatedAt as i32,
            },
            &access_token,
        )?)
        .await
        .expect_err("cursor should fail when filter_status changes");

    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    Ok(())
}
