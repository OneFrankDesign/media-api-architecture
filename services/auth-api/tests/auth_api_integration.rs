use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use auth_api::{
    build_app_with_options, sign_challenge_cookie_value, AppState, OidcConfig, RateLimitOptions,
};
use axum::{
    body::Body,
    http::{
        header::{CONTENT_TYPE, COOKIE, SET_COOKIE},
        Request, StatusCode,
    },
    routing::{get, post},
    Json, Router,
};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use tokio::task::JoinHandle;
use tower::{Service, ServiceExt};

#[tokio::test]
async fn create_session_sets_session_and_csrf_cookies() {
    let app = build_app_with_options(AppState::new(String::new(), false), None);
    let request = Request::builder()
        .method("POST")
        .uri("/auth/session")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"subject":"alice"}"#))
        .expect("request should build");

    let response = app.oneshot(request).await.expect("request should succeed");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get("deprecation")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    assert!(response.headers().contains_key("sunset"));

    let cookies: Vec<String> = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie must be valid utf8")
                .to_string()
        })
        .collect();

    assert_eq!(cookies.len(), 2);
    assert!(cookies
        .iter()
        .any(|cookie| cookie.starts_with("session=") && cookie.contains("HttpOnly")));
    assert!(cookies
        .iter()
        .any(|cookie| cookie.starts_with("csrf-token=")));

    let body = response
        .into_body()
        .collect()
        .await
        .expect("body should be readable")
        .to_bytes();
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("response should be valid json");
    assert_eq!(json["subject"], "alice");
    assert_eq!(json["message"], "local session issued");
}

#[tokio::test]
async fn logout_expires_cookies() {
    let app = build_app_with_options(AppState::new(String::new(), false), None);
    let request = Request::builder()
        .method("POST")
        .uri("/auth/logout")
        .body(Body::empty())
        .expect("request should build");

    let response = app.oneshot(request).await.expect("request should succeed");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("deprecation")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    assert!(response.headers().contains_key("sunset"));

    let cookies: Vec<String> = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie must be valid utf8")
                .to_string()
        })
        .collect();

    assert_eq!(cookies.len(), 2);
    assert!(cookies
        .iter()
        .any(|cookie| cookie.starts_with("session=deleted") && cookie.contains("Max-Age=0")));
    assert!(cookies
        .iter()
        .any(|cookie| cookie.starts_with("csrf-token=deleted") && cookie.contains("Max-Age=0")));
}

#[tokio::test]
async fn secure_domain_config_is_reflected_in_cookies() {
    let app = build_app_with_options(AppState::new("example.com".to_string(), true), None);
    let request = Request::builder()
        .method("POST")
        .uri("/auth/session")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{}"#))
        .expect("request should build");

    let response = app.oneshot(request).await.expect("request should succeed");
    assert_eq!(response.status(), StatusCode::CREATED);

    let cookies: Vec<String> = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie must be valid utf8")
                .to_string()
        })
        .collect();

    assert!(cookies
        .iter()
        .all(|cookie| cookie.contains("Secure") && cookie.contains("Domain=example.com")));
}

#[tokio::test]
async fn login_redirect_rejects_if_oidc_config_missing() {
    let app = build_app_with_options(AppState::new(String::new(), false), None);
    let request = Request::builder()
        .method("GET")
        .uri("/auth/login")
        .body(Body::empty())
        .expect("request should build");

    let response = app.oneshot(request).await.expect("request should succeed");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn callback_error_distinguishes_access_denied_from_provider_failure() {
    let denied_app = build_app_with_options(AppState::new(String::new(), false), None);
    let denied_request = Request::builder()
        .method("GET")
        .uri("/auth/callback?error=access_denied")
        .body(Body::empty())
        .expect("request should build");

    let denied_response = denied_app
        .oneshot(denied_request)
        .await
        .expect("request should succeed");
    assert_eq!(denied_response.status(), StatusCode::FORBIDDEN);

    let secret = vec![0x22; 32];
    let signed =
        sign_challenge_cookie_value("test-verifier", "state-1", "nonce-1", i64::MAX, &secret)
            .expect("challenge should sign");

    let oidc = OidcConfig::new(
        "http://oidc-mock:80".to_string(),
        "media-api-client".to_string(),
        None,
        "http://localhost:8080/auth/callback".to_string(),
        "http://127.0.0.1:9/.well-known/openid-configuration".to_string(),
        secret,
    );

    let provider_failure_app =
        build_app_with_options(AppState::new(String::new(), false).with_oidc(oidc), None);
    let provider_failure_request = Request::builder()
        .method("GET")
        .uri("/auth/callback?code=abc&state=state-1")
        .header(COOKIE, format!("auth-challenge={signed}"))
        .body(Body::empty())
        .expect("request should build");

    let provider_failure_response = provider_failure_app
        .oneshot(provider_failure_request)
        .await
        .expect("request should succeed");
    assert_eq!(provider_failure_response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn login_redirect_sets_challenge_cookie_and_pkce_state() {
    let oidc = OidcConfig::new(
        "http://mock-issuer".to_string(),
        "media-api-client".to_string(),
        None,
        "http://localhost:8080/auth/callback".to_string(),
        "http://127.0.0.1:9/.well-known/openid-configuration".to_string(),
        vec![0x33; 32],
    );

    let app = build_app_with_options(
        AppState::new(String::new(), false)
            .with_oidc(oidc)
            .with_static_discovery(
                "http://localhost:9080/connect/authorize".to_string(),
                "http://localhost:9080/connect/token".to_string(),
                "http://localhost:9080/.well-known/jwks.json".to_string(),
            ),
        None,
    );
    let request = Request::builder()
        .method("GET")
        .uri("/auth/login")
        .body(Body::empty())
        .expect("request should build");

    let response = app.oneshot(request).await.expect("request should succeed");
    assert_eq!(response.status(), StatusCode::FOUND);

    let location = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("location header should be present");
    let location_url = reqwest::Url::parse(location).expect("redirect URL should parse");
    let query_pairs: std::collections::HashMap<String, String> =
        location_url.query_pairs().into_owned().collect();

    assert_eq!(
        query_pairs.get("response_type").map(String::as_str),
        Some("code")
    );
    assert_eq!(
        query_pairs.get("client_id").map(String::as_str),
        Some("media-api-client")
    );
    assert_eq!(
        query_pairs.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    assert!(query_pairs
        .get("code_challenge")
        .is_some_and(|value| !value.is_empty()));
    assert!(query_pairs
        .get("state")
        .is_some_and(|value| !value.is_empty()));

    let cookies: Vec<String> = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| value.to_str().expect("cookie should be utf8").to_string())
        .collect();
    assert!(cookies.iter().any(|cookie| {
        cookie.starts_with("auth-challenge=") && cookie.contains("Path=/auth/callback")
    }));
}

fn new_session_request(subject: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/auth/session")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(format!(r#"{{"subject":"{subject}"}}"#)))
        .expect("request should build")
}

fn login_request() -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri("/auth/login")
        .body(Body::empty())
        .expect("request should build")
}

#[derive(Debug, Serialize)]
struct MockIdTokenClaims {
    sub: String,
    nonce: String,
    exp: i64,
    iss: String,
    aud: String,
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn build_access_token(exp: i64) -> String {
    jsonwebtoken::encode(
        &Header::default(),
        &serde_json::json!({ "exp": exp }),
        &EncodingKey::from_secret(b"test-access-token-secret"),
    )
    .expect("access token should encode")
}

fn build_rs256_id_token(issuer: &str, audience: &str, nonce: &str, exp: i64) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-kid".to_string());

    jsonwebtoken::encode(
        &header,
        &MockIdTokenClaims {
            sub: "test-user-1".to_string(),
            nonce: nonce.to_string(),
            exp,
            iss: issuer.to_string(),
            aud: audience.to_string(),
        },
        &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes())
            .expect("rsa key should parse"),
    )
    .expect("id token should encode")
}

async fn start_discovery_counter_server(
    counter: Arc<AtomicUsize>,
) -> Option<(String, JoinHandle<()>)> {
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return None,
        Err(err) => panic!("listener should bind: {err}"),
    };
    let addr = listener.local_addr().expect("local addr should resolve");
    let base_url = format!("http://{addr}");

    let discovery_document = serde_json::json!({
        "authorization_endpoint": format!("{base_url}/authorize"),
        "token_endpoint": format!("{base_url}/token"),
        "jwks_uri": format!("{base_url}/jwks"),
    });

    let app = Router::new().route(
        "/.well-known/openid-configuration",
        get({
            let counter = Arc::clone(&counter);
            let discovery_document = discovery_document.clone();
            move || {
                let counter = Arc::clone(&counter);
                let discovery_document = discovery_document.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Json(discovery_document)
                }
            }
        }),
    );

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Some((
        format!("{base_url}/.well-known/openid-configuration"),
        handle,
    ))
}

async fn start_nonce_mismatch_oidc_server() -> Option<(String, String, JoinHandle<()>)> {
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return None,
        Err(err) => panic!("listener should bind: {err}"),
    };
    let addr = listener.local_addr().expect("local addr should resolve");
    let issuer = format!("http://{addr}");
    let discovery_url = format!("{issuer}/.well-known/openid-configuration");
    let access_token = build_access_token(unix_now() + 3600);
    let id_token = build_rs256_id_token(&issuer, "media-api-client", "provider-nonce", unix_now() + 3600);

    let discovery_document = serde_json::json!({
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
    });
    let token_response = serde_json::json!({
        "access_token": access_token,
        "id_token": id_token,
    });
    let jwks_response = serde_json::json!({
        "keys": [{
            "kid": "test-kid",
            "kty": "RSA",
            "n": TEST_RSA_PUBLIC_KEY_N,
            "e": TEST_RSA_PUBLIC_KEY_E,
        }]
    });

    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get({
                let discovery_document = discovery_document.clone();
                move || {
                    let discovery_document = discovery_document.clone();
                    async move { Json(discovery_document) }
                }
            }),
        )
        .route(
            "/token",
            post({
                let token_response = token_response.clone();
                move || {
                    let token_response = token_response.clone();
                    async move { Json(token_response) }
                }
            }),
        )
        .route(
            "/jwks",
            get({
                let jwks_response = jwks_response.clone();
                move || {
                    let jwks_response = jwks_response.clone();
                    async move { Json(jwks_response) }
                }
            }),
        );

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Some((issuer, discovery_url, handle))
}

const TEST_RSA_PUBLIC_KEY_N: &str = "7HJe3QCJOYDP7OxXQHU0Y_0CnkKFT_s0ANH-ehQ2ZV6FoSSVTXDox0dyeze7sLHZBhkeDwFYVVwfaTqjvoB04LEm74E_ZVkXCIVszY_uNif9yq7BcIfag1ZuzaSfRvwaynZE7Pf0cVCrdhrufKAnTT0TN50ElOd4tEg_fYCOKW8PwIjxN-PKRjvM53xak3jX1NJwg9YyOUoYGyGxzzwYNd0asEQ92SPlMNSMeicS-mlczXvIrUPuBdpdDXY4Xg3GkRyV0D8rieodrFC7Qo1PPFc2bD3kUv6zuZDGxtfQsZrw5i0FtmeYuO6ni5L0iV9JkfqbEaUyzQMpfA3jGqaVIQ";
const TEST_RSA_PUBLIC_KEY_E: &str = "AQAB";
const TEST_RSA_PRIVATE_KEY_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7HJe3QCJOYDP7OxXQHU0Y/0CnkKFT/s0ANH+ehQ2ZV6FoSSV\nTXDox0dyeze7sLHZBhkeDwFYVVwfaTqjvoB04LEm74E/ZVkXCIVszY/uNif9yq7B\ncIfag1ZuzaSfRvwaynZE7Pf0cVCrdhrufKAnTT0TN50ElOd4tEg/fYCOKW8PwIjx\nN+PKRjvM53xak3jX1NJwg9YyOUoYGyGxzzwYNd0asEQ92SPlMNSMeicS+mlczXvI\nrUPuBdpdDXY4Xg3GkRyV0D8rieodrFC7Qo1PPFc2bD3kUv6zuZDGxtfQsZrw5i0F\ntmeYuO6ni5L0iV9JkfqbEaUyzQMpfA3jGqaVIQIDAQABAoIBACpVl/KN5APtskzD\nTCP4WDcG1+8qDeByI6956cxFzi98KwTdHfZNnv//JNo28l4Cmc7jtGQPY5d09RLM\nMwEq0sJgNY5wX79vohYefYqYmJgNtP0TKQNS76bQVOpw7Suye8GAR3r+MkAPp4Nv\n8v9RVXgY1VYBwQ5AG3Z78RIxcEKujdNhMosA5IA/KzCJD/XxQvAkbpCRgU6HEWNS\ndvn6zxOCGfE6wtqBgWBbIxcUKkyxgTd4v8gTM9thgfYDvmDHXsdUIByx86hRaGW5\nV1pvu548SkbbdbxTFFjN0NBgC9Al/HjxTXWZiGyLCbbPStWmle7oJLZegegNHEGC\n7fOUOLkCgYEA9tTGLDviglQJai0RdCAMIzIY2piX6hFLr87Td/tlXMpaOR9jd446\ndFX0yvmg7AvKykYzwpKKfbF4Oa82CJ/ROjM82xO00DCenBAmj6H8kN98YTpg54XP\nYK7woNnA87g+rrq6anMpjC1bIuqhB2ws/y3wPqjm3Rfihr4AnHb6lwMCgYEA9TrY\nwzwSZXYb+Frw7sNV0n6Fxtq0W53A4q6/MAALazbGnOaab1imEpvbAwkSGXlhI0jM\nYbeylvn84NZAFzWf0zZ/F7PP8feTT+LmpTIxDaVrgvaoZU8yMIeW5/Y70SUhKiab\n9nATjJC8nZcxVYJlZRsVO+8yTsHvBGzSxk0OCAsCgYEA5Z2ONPwIfMD8eR8vy108\nrUkfQcsOFxq70/KNWmItKyK6x8ThXQicbDjCHkgWYT+fCIhCAlEcME110AOkOmWh\n14hupkYwwDNaeUe094zzTTn5lOEf4IDkJ8bV5mxrSM4u0ZC3detnzRUsYNDvt930\nBfaQNVoeWbKscjgyjVtJRk0CgYBmv2BA9PN0RXdUqK3YLEnSJybf+ZSl6kP99l+u\nueYO5uVyqgA89PSoSVsLO4q017GGeiMAMlqGfXmhrsMttk8fzO6VPMa8yBGV4Cjp\nQE1jPVL9jWFjCTqrMLRevkGz0I3DvmeMassWEzKkCMwn2rmnEiDkesUmUIVX4kyx\nv2lInwKBgD7N8KhN3fyM3PAyEx7eB0jQvTiCbXjvzz+5jawmoySFLt4IDY6r06+O\nw9tlNvgCk2ce2/dhr6Tfd+lbyEN3EGzVK/q42W9q35KqvfS71fH12bSC7AaExyZo\n5dVn/NAdfZh1Kjhb3j2HSGbeBK42C4iu8fwZXfIFrPVEiXxXujfF\n-----END RSA PRIVATE KEY-----\n";

#[tokio::test]
async fn rate_limit_returns_too_many_requests_after_threshold() {
    let mut app = build_app_with_options(
        AppState::new(String::new(), false),
        Some(RateLimitOptions {
            max_requests: 2,
            per: Duration::from_secs(60),
        }),
    )
    .into_service();

    let first = Service::call(&mut app, new_session_request("first"));
    let second = Service::call(&mut app, new_session_request("second"));
    let third = Service::call(&mut app, new_session_request("third"));

    let (first, second, third) = tokio::join!(first, second, third);
    let statuses = [
        first.expect("first request should complete").status(),
        second.expect("second request should complete").status(),
        third.expect("third request should complete").status(),
    ];

    assert!(statuses.iter().any(|status| *status == StatusCode::CREATED));
    assert!(statuses
        .iter()
        .any(|status| *status == StatusCode::TOO_MANY_REQUESTS));
}

#[tokio::test]
async fn callback_rejects_expired_challenge_cookie() {
    let secret = vec![0x44; 32];
    let signed =
        sign_challenge_cookie_value("test-verifier", "state-1", "nonce-1", 1, &secret)
            .expect("challenge should sign");

    let app = build_app_with_options(
        AppState::new(String::new(), false).with_oidc(OidcConfig::new(
            "http://mock-issuer".to_string(),
            "media-api-client".to_string(),
            Some("media-api-secret".to_string()),
            "http://localhost:8080/auth/callback".to_string(),
            "http://127.0.0.1:9/.well-known/openid-configuration".to_string(),
            secret,
        )),
        None,
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/auth/callback?code=abc&state=state-1")
                .header(COOKIE, format!("auth-challenge={signed}"))
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn callback_rejects_nonce_mismatch_after_token_verification() {
    let Some((issuer, discovery_url, server_handle)) = start_nonce_mismatch_oidc_server().await
    else {
        eprintln!("skipping nonce mismatch test: listener bind is not permitted");
        return;
    };
    let secret = vec![0x55; 32];
    let signed =
        sign_challenge_cookie_value("test-verifier", "state-1", "cookie-nonce", i64::MAX, &secret)
            .expect("challenge should sign");

    let app = build_app_with_options(
        AppState::new(String::new(), false).with_oidc(OidcConfig::new(
            issuer,
            "media-api-client".to_string(),
            Some("media-api-secret".to_string()),
            "http://localhost:8080/auth/callback".to_string(),
            discovery_url,
            secret,
        )),
        None,
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/auth/callback?code=abc&state=state-1")
                .header(COOKIE, format!("auth-challenge={signed}"))
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should succeed");

    server_handle.abort();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_redirect_refreshes_discovery_document_after_ttl() {
    let counter = Arc::new(AtomicUsize::new(0));
    let Some((discovery_url, server_handle)) =
        start_discovery_counter_server(Arc::clone(&counter)).await
    else {
        eprintln!("skipping discovery ttl test: listener bind is not permitted");
        return;
    };

    let app = build_app_with_options(
        AppState::new(String::new(), false)
            .with_oidc(OidcConfig::new(
                "http://mock-issuer".to_string(),
                "media-api-client".to_string(),
                None,
                "http://localhost:8080/auth/callback".to_string(),
                discovery_url,
                vec![0x66; 32],
            ))
            .with_oidc_discovery_ttl_secs(1),
        None,
    );

    let first = app
        .clone()
        .oneshot(login_request())
        .await
        .expect("first login request should succeed");
    assert_eq!(first.status(), StatusCode::FOUND);
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    let second = app
        .clone()
        .oneshot(login_request())
        .await
        .expect("second login request should succeed");
    assert_eq!(second.status(), StatusCode::FOUND);
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    tokio::time::sleep(Duration::from_secs(2)).await;

    let third = app
        .oneshot(login_request())
        .await
        .expect("third login request should succeed");
    assert_eq!(third.status(), StatusCode::FOUND);
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    server_handle.abort();
}
