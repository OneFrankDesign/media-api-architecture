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
use tracing::{error, info};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    cookie_domain: Arc<String>,
    cookie_secure: bool,
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "auth_api=info,tower_http=info".into()),
        )
        .init();

    let cookie_domain = std::env::var("COOKIE_DOMAIN").unwrap_or_default();
    let cookie_secure = env_bool("COOKIE_SECURE", false);
    let state = AppState {
        cookie_domain: Arc::new(cookie_domain),
        cookie_secure,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/auth/session", post(create_session))
        .route("/auth/logout", post(logout))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8081));
    info!(%addr, "starting auth api");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

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
    if let Err(err) = append_set_cookie(&mut headers, &session_cookie(
        &session_token,
        state.cookie_domain.as_str(),
        state.cookie_secure,
    )) {
        error!(error = %err, "failed to build session cookie header");
        return internal_error("failed to issue session cookie").into_response();
    }
    if let Err(err) = append_set_cookie(&mut headers, &csrf_cookie(
        &csrf_token,
        state.cookie_domain.as_str(),
        state.cookie_secure,
    )) {
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

    (StatusCode::OK, headers, Json(serde_json::json!({ "message": "logged out" }))).into_response()
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

fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}
