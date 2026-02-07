use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use axum::{
    extract::State,
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};
use uuid::Uuid;

pub const DEFAULT_AUTH_ADDR: &str = "0.0.0.0:8081";

#[derive(Clone, Debug)]
pub struct AppState {
    cookie_domain: Arc<String>,
    cookie_secure: bool,
}

impl AppState {
    pub fn new(cookie_domain: String, cookie_secure: bool) -> Self {
        Self {
            cookie_domain: Arc::new(cookie_domain),
            cookie_secure,
        }
    }

    pub fn cookie_domain(&self) -> &str {
        self.cookie_domain.as_str()
    }

    pub fn cookie_secure(&self) -> bool {
        self.cookie_secure
    }
}

#[derive(Debug, Deserialize)]
struct SessionRequest {
    subject: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionResponse {
    subject: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    message: String,
}

pub fn default_auth_addr() -> SocketAddr {
    DEFAULT_AUTH_ADDR
        .parse()
        .expect("default auth listen address must parse")
}

pub fn load_state_from_env() -> AppState {
    let raw_cookie_domain = std::env::var("COOKIE_DOMAIN").unwrap_or_default();
    let cookie_domain = match sanitize_cookie_domain(&raw_cookie_domain) {
        Ok(Some(domain)) => domain,
        Ok(None) => String::new(),
        Err(reason) => {
            warn!(
                cookie_domain = %raw_cookie_domain,
                reason,
                "ignoring invalid COOKIE_DOMAIN"
            );
            String::new()
        }
    };

    let cookie_secure = env_bool("COOKIE_SECURE", false);
    AppState::new(cookie_domain, cookie_secure)
}

pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/auth/session", post(create_session))
        .route("/auth/logout", post(logout))
        .with_state(state)
}

pub async fn run(addr: SocketAddr, state: AppState) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, build_app(state)).await?;
    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn create_session(
    State(state): State<AppState>,
    Json(payload): Json<SessionRequest>,
) -> Response {
    let subject = payload.subject.unwrap_or_else(|| "local-user".to_string());
    let session_token = Uuid::new_v4().to_string();
    let csrf_token = Uuid::new_v4().to_string();

    let mut headers = HeaderMap::new();
    if let Err(err) = append_set_cookie(
        &mut headers,
        &session_cookie(
            &session_token,
            state.cookie_domain.as_str(),
            state.cookie_secure,
        ),
    ) {
        error!(error = %err, "failed to build session cookie header");
        return internal_error("failed to issue session cookie").into_response();
    }
    if let Err(err) = append_set_cookie(
        &mut headers,
        &csrf_cookie(
            &csrf_token,
            state.cookie_domain.as_str(),
            state.cookie_secure,
        ),
    ) {
        error!(error = %err, "failed to build csrf cookie header");
        return internal_error("failed to issue csrf cookie").into_response();
    }

    (
        StatusCode::CREATED,
        headers,
        Json(SessionResponse {
            subject,
            message: "local session issued".to_string(),
        }),
    )
        .into_response()
}

async fn logout(State(state): State<AppState>) -> Response {
    let mut headers = HeaderMap::new();

    if let Err(err) = append_set_cookie(
        &mut headers,
        &expired_cookie(
            "session",
            state.cookie_domain.as_str(),
            true,
            state.cookie_secure,
        ),
    ) {
        error!(error = %err, "failed to build session cookie expiration header");
        return internal_error("failed to clear session cookie").into_response();
    }
    if let Err(err) = append_set_cookie(
        &mut headers,
        &expired_cookie(
            "csrf-token",
            state.cookie_domain.as_str(),
            false,
            state.cookie_secure,
        ),
    ) {
        error!(error = %err, "failed to build csrf cookie expiration header");
        return internal_error("failed to clear csrf cookie").into_response();
    }

    (
        StatusCode::OK,
        headers,
        Json(serde_json::json!({ "message": "logged out" })),
    )
        .into_response()
}

fn session_cookie(token: &str, domain: &str, secure: bool) -> String {
    let mut cookie = format!("session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=900");
    if secure {
        cookie.push_str("; Secure");
    }
    if !domain.trim().is_empty() {
        cookie.push_str(&format!("; Domain={domain}"));
    }
    cookie
}

fn csrf_cookie(token: &str, domain: &str, secure: bool) -> String {
    let mut cookie = format!("csrf-token={token}; Path=/; SameSite=Strict; Max-Age=86400");
    if secure {
        cookie.push_str("; Secure");
    }
    if !domain.trim().is_empty() {
        cookie.push_str(&format!("; Domain={domain}"));
    }
    cookie
}

fn expired_cookie(name: &str, domain: &str, http_only: bool, secure: bool) -> String {
    let mut cookie = format!("{name}=deleted; Path=/; SameSite=Strict; Max-Age=0");
    if secure {
        cookie.push_str("; Secure");
    }
    if http_only {
        cookie.push_str("; HttpOnly");
    }
    if !domain.trim().is_empty() {
        cookie.push_str(&format!("; Domain={domain}"));
    }
    cookie
}

fn append_set_cookie(headers: &mut HeaderMap, cookie: &str) -> Result<(), String> {
    let header = HeaderValue::from_str(cookie).map_err(|err| err.to_string())?;
    headers.append(SET_COOKIE, header);
    Ok(())
}

fn internal_error(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            message: message.to_string(),
        }),
    )
}

pub fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

pub fn sanitize_cookie_domain(raw: &str) -> std::result::Result<Option<String>, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    // Leading dots are obsolete for modern cookie handling; normalize to bare host.
    let normalized = trimmed.trim_start_matches('.');
    if normalized.is_empty() {
        return Err("domain is empty after normalization");
    }
    if normalized.len() > 253 {
        return Err("domain exceeds max length");
    }

    for label in normalized.split('.') {
        if label.is_empty() {
            return Err("domain contains empty label");
        }
        if label.len() > 63 {
            return Err("domain label exceeds max length");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("domain label starts or ends with hyphen");
        }
        if !label
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        {
            return Err("domain contains invalid characters");
        }
    }

    Ok(Some(normalized.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_cookie_domain_accepts_expected_inputs() {
        assert_eq!(sanitize_cookie_domain(""), Ok(None));
        assert_eq!(
            sanitize_cookie_domain(".Example.COM"),
            Ok(Some("example.com".to_string()))
        );
        assert_eq!(
            sanitize_cookie_domain("api.media-local"),
            Ok(Some("api.media-local".to_string()))
        );
    }

    #[test]
    fn sanitize_cookie_domain_rejects_invalid_inputs() {
        let too_long_label = format!("{}", "a".repeat(64));
        let too_long_domain = format!("{}.com", "a".repeat(254));

        assert!(sanitize_cookie_domain(".").is_err());
        assert!(sanitize_cookie_domain("example..com").is_err());
        assert!(sanitize_cookie_domain("-example.com").is_err());
        assert!(sanitize_cookie_domain("example-.com").is_err());
        assert!(sanitize_cookie_domain("exa*mple.com").is_err());
        assert!(sanitize_cookie_domain(&format!("{too_long_label}.com")).is_err());
        assert!(sanitize_cookie_domain(&too_long_domain).is_err());
    }

    #[test]
    fn cookie_builders_include_expected_attributes() {
        let session = session_cookie("token", "example.com", true);
        assert!(session.starts_with("session=token"));
        assert!(session.contains("HttpOnly"));
        assert!(session.contains("SameSite=Strict"));
        assert!(session.contains("Secure"));
        assert!(session.contains("Domain=example.com"));

        let csrf = csrf_cookie("token", "", false);
        assert!(csrf.starts_with("csrf-token=token"));
        assert!(!csrf.contains("HttpOnly"));
        assert!(!csrf.contains("Secure"));

        let expired = expired_cookie("session", "example.com", true, true);
        assert!(expired.contains("Max-Age=0"));
        assert!(expired.contains("HttpOnly"));
        assert!(expired.contains("Secure"));
        assert!(expired.contains("Domain=example.com"));
    }

    #[test]
    fn env_bool_parses_truthy_values_and_defaults() {
        let key = "AUTH_API_TEST_BOOL_VALUE";
        std::env::remove_var(key);
        assert!(!env_bool(key, false));
        assert!(env_bool(key, true));

        std::env::set_var(key, "true");
        assert!(env_bool(key, false));
        std::env::set_var(key, "yes");
        assert!(env_bool(key, false));
        std::env::set_var(key, "On");
        assert!(env_bool(key, false));

        std::env::set_var(key, "false");
        assert!(!env_bool(key, true));

        std::env::remove_var(key);
    }
}
