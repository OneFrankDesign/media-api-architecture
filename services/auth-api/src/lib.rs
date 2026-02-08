use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use axum::{
    error_handling::HandleErrorLayer,
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    BoxError, Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use metrics::counter;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use openidconnect::{CsrfToken, Nonce, PkceCodeChallenge, PkceCodeVerifier};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use tower::{buffer::BufferLayer, limit::RateLimitLayer, load_shed::LoadShedLayer, ServiceBuilder};
use tracing::{error, info, warn};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;
static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

pub const DEFAULT_AUTH_ADDR: &str = "0.0.0.0:8081";
pub const DEFAULT_RATE_LIMIT_REQUESTS: u64 = 1000;
pub const DEFAULT_RATE_LIMIT_WINDOW_SECS: u64 = 1;
pub const DEFAULT_SESSION_MAX_AGE_SECS: u64 = 900;
pub const DEFAULT_OIDC_DISCOVERY_TTL_SECS: u64 = 3600;
pub const CHALLENGE_COOKIE_MAX_AGE_SECS: u64 = 300;
pub const AUTH_CHALLENGE_COOKIE_NAME: &str = "auth-challenge";
pub const DEPRECATION_SUNSET: &str = "Tue, 30 Jun 2026 00:00:00 GMT";

#[derive(Clone)]
pub struct AppState {
    cookie_domain: Arc<String>,
    cookie_secure: bool,
    oidc: Option<Arc<OidcConfig>>,
    http_client: reqwest::Client,
    oidc_discovery_ttl_secs: u64,
    discovery_cache: Arc<RwLock<Option<CachedDiscovery>>>,
    jwks_cache: Arc<RwLock<Option<CachedJwks>>>,
}

#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub discovery_url: String,
    pub challenge_secret: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct RateLimitOptions {
    pub max_requests: u64,
    pub per: Duration,
}

impl Default for RateLimitOptions {
    fn default() -> Self {
        Self {
            max_requests: DEFAULT_RATE_LIMIT_REQUESTS,
            per: Duration::from_secs(DEFAULT_RATE_LIMIT_WINDOW_SECS),
        }
    }
}

impl AppState {
    pub fn new(cookie_domain: String, cookie_secure: bool) -> Self {
        Self {
            cookie_domain: Arc::new(cookie_domain),
            cookie_secure,
            oidc: None,
            http_client: reqwest::Client::new(),
            oidc_discovery_ttl_secs: DEFAULT_OIDC_DISCOVERY_TTL_SECS,
            discovery_cache: Arc::new(RwLock::new(None)),
            jwks_cache: Arc::new(RwLock::new(None)),
        }
    }

    pub fn with_oidc(mut self, oidc: OidcConfig) -> Self {
        self.oidc = Some(Arc::new(oidc));
        self
    }

    pub fn with_static_discovery(
        mut self,
        authorization_endpoint: String,
        token_endpoint: String,
        jwks_uri: String,
    ) -> Self {
        self.discovery_cache = Arc::new(RwLock::new(Some(CachedDiscovery {
            document: DiscoveryDocument {
                authorization_endpoint,
                token_endpoint,
                jwks_uri,
            },
            expires_at_unix: i64::MAX,
        })));
        self
    }

    pub fn cookie_domain(&self) -> &str {
        self.cookie_domain.as_str()
    }

    pub fn cookie_secure(&self) -> bool {
        self.cookie_secure
    }

    pub fn with_oidc_discovery_ttl_secs(mut self, ttl_secs: u64) -> Self {
        self.oidc_discovery_ttl_secs = ttl_secs.max(1);
        self
    }
}

impl OidcConfig {
    pub fn new(
        issuer: String,
        client_id: String,
        client_secret: Option<String>,
        redirect_uri: String,
        discovery_url: String,
        challenge_secret: Vec<u8>,
    ) -> Self {
        Self {
            issuer,
            client_id,
            client_secret,
            redirect_uri,
            discovery_url,
            challenge_secret,
        }
    }
}

#[derive(Debug, Deserialize)]
struct SessionRequest {
    subject: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
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

#[derive(Debug, Serialize, Deserialize)]
struct ChallengeCookiePayload {
    verifier: String,
    state: String,
    nonce: String,
    exp: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct DiscoveryDocument {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Debug, Clone)]
struct CachedDiscovery {
    document: DiscoveryDocument,
    expires_at_unix: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct TokenEndpointResponse {
    access_token: String,
    id_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    n: Option<String>,
    e: Option<String>,
}

#[derive(Debug, Clone)]
struct CachedJwks {
    jwks_uri: String,
    document: Jwks,
    expires_at_unix: i64,
}

#[derive(Debug, Deserialize, Clone)]
struct IdTokenClaims {
    sub: String,
    nonce: Option<String>,
    exp: i64,
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
    let discovery_ttl_secs =
        load_positive_u64_env("OIDC_DISCOVERY_TTL_SECS", DEFAULT_OIDC_DISCOVERY_TTL_SECS);
    let mut state = AppState::new(cookie_domain, cookie_secure)
        .with_oidc_discovery_ttl_secs(discovery_ttl_secs);

    if let Some(oidc) = load_oidc_config_from_env() {
        state = state.with_oidc(oidc);
    }

    state
}

pub fn build_app(state: AppState) -> Router {
    build_app_with_options(state, Some(RateLimitOptions::default()))
}

pub fn build_app_with_options(state: AppState, rate_limit: Option<RateLimitOptions>) -> Router {
    if let Err(err) = init_prometheus_handle() {
        warn!(error = %err, "failed to initialize prometheus recorder");
    }

    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/auth/login", get(auth_login))
        .route("/auth/callback", get(auth_callback))
        .route("/auth/session", post(create_session))
        .route("/auth/logout", post(logout))
        .with_state(state);

    if let Some(rate_limit) = rate_limit {
        app.layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|_: BoxError| async {
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(ErrorResponse {
                            message: "rate limit exceeded".to_string(),
                        }),
                    )
                }))
                .layer(BufferLayer::new(rate_limit.max_requests as usize))
                .layer(LoadShedLayer::new())
                .layer(RateLimitLayer::new(rate_limit.max_requests, rate_limit.per)),
        )
    } else {
        app
    }
}

pub async fn run(addr: SocketAddr, state: AppState) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, build_app(state))
        .with_graceful_shutdown(async {
            match shutdown_signal().await {
                Ok(signal_name) => info!(signal = signal_name, "shutdown signal received"),
                Err(err) => error!(error = %err, "failed to listen for shutdown signal"),
            }
        })
        .await?;
    Ok(())
}

async fn health() -> Json<HealthResponse> {
    counter!("auth_api.http.requests_total", "route" => "/health").increment(1);
    Json(HealthResponse { status: "ok" })
}

async fn metrics() -> String {
    counter!("auth_api.http.requests_total", "route" => "/metrics").increment(1);
    PROMETHEUS_HANDLE
        .get()
        .map(|handle| handle.render())
        .unwrap_or_default()
}

async fn auth_login(State(state): State<AppState>) -> Response {
    counter!("auth_api.http.requests_total", "route" => "/auth/login").increment(1);
    let Some(oidc) = state.oidc.as_ref() else {
        return internal_error("oidc configuration is missing").into_response();
    };

    let discovery = match discovery_document(&state, oidc).await {
        Ok(doc) => doc,
        Err(err) => {
            error!(error = %err, "failed to fetch OIDC discovery document");
            return bad_gateway("failed to load oidc configuration").into_response();
        }
    };

    let verifier_raw = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let verifier = PkceCodeVerifier::new(verifier_raw);
    let challenge = PkceCodeChallenge::from_code_verifier_sha256(&verifier);
    let state_token = CsrfToken::new_random();
    let nonce = Nonce::new_random();

    let payload = ChallengeCookiePayload {
        verifier: verifier.secret().to_string(),
        state: state_token.secret().to_string(),
        nonce: nonce.secret().to_string(),
        exp: unix_now() + CHALLENGE_COOKIE_MAX_AGE_SECS as i64,
    };

    let signed_challenge = match sign_challenge_payload(&payload, &oidc.challenge_secret) {
        Ok(value) => value,
        Err(err) => {
            error!(error = %err, "failed to sign auth challenge cookie");
            return internal_error("failed to start login flow").into_response();
        }
    };

    let authorize_url = match build_authorize_url(
        &discovery.authorization_endpoint,
        oidc,
        state_token.secret(),
        nonce.secret(),
        challenge.as_str(),
    ) {
        Ok(url) => url,
        Err(err) => {
            error!(error = %err, "failed to build authorize redirect URL");
            return internal_error("failed to start login flow").into_response();
        }
    };

    let mut headers = HeaderMap::new();
    if let Err(err) = append_set_cookie(
        &mut headers,
        &auth_challenge_cookie(
            &signed_challenge,
            state.cookie_domain(),
            state.cookie_secure(),
        ),
    ) {
        error!(error = %err, "failed to append auth challenge cookie");
        return internal_error("failed to start login flow").into_response();
    }

    match HeaderValue::from_str(authorize_url.as_str()) {
        Ok(location) => {
            headers.insert(header::LOCATION, location);
            (StatusCode::FOUND, headers).into_response()
        }
        Err(err) => {
            error!(error = %err, "authorize URL is not a valid header value");
            internal_error("failed to start login flow").into_response()
        }
    }
}

async fn auth_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthCallbackQuery>,
) -> Response {
    counter!("auth_api.http.requests_total", "route" => "/auth/callback").increment(1);
    if query.error.as_deref() == Some("access_denied") {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                message: "access denied; restart login".to_string(),
            }),
        )
            .into_response();
    }

    let code = match query.code {
        Some(code) if !code.trim().is_empty() => code,
        _ => {
            return bad_request("missing authorization code").into_response();
        }
    };

    let state_param = match query.state {
        Some(state) if !state.trim().is_empty() => state,
        _ => {
            return bad_request("missing state").into_response();
        }
    };

    let Some(oidc) = state.oidc.as_ref() else {
        return internal_error("oidc configuration is missing").into_response();
    };

    let cookie_value = match cookie_value(&headers, AUTH_CHALLENGE_COOKIE_NAME) {
        Some(value) => value,
        None => return unauthorized("missing auth challenge cookie").into_response(),
    };

    let payload = match verify_challenge_payload(&cookie_value, &oidc.challenge_secret) {
        Ok(payload) => payload,
        Err(err) => {
            warn!(error = %err, "invalid auth challenge cookie");
            return unauthorized("invalid auth challenge cookie").into_response();
        }
    };

    if payload.exp < unix_now() {
        return unauthorized("expired auth challenge cookie").into_response();
    }

    if !constant_time_equal(payload.state.as_bytes(), state_param.as_bytes()) {
        return unauthorized("state mismatch").into_response();
    }

    // /auth/callback is GET and intentionally bypasses CSRF double-submit; state is the anti-forgery control.
    let discovery = match discovery_document(&state, oidc).await {
        Ok(doc) => doc,
        Err(err) => {
            error!(error = %err, "failed to fetch OIDC discovery document");
            return bad_gateway("oidc provider unavailable, try again").into_response();
        }
    };

    let tokens = match exchange_code_for_tokens(
        &state.http_client,
        &discovery,
        oidc,
        &code,
        &payload.verifier,
    )
    .await
    {
        Ok(tokens) => tokens,
        Err(err) => {
            error!(error = %err, "failed to exchange authorization code");
            return bad_gateway("oidc provider unavailable, try again").into_response();
        }
    };

    let id_token = match tokens.id_token.as_deref() {
        Some(token) => token,
        None => return bad_gateway("token response missing id_token").into_response(),
    };

    let id_claims = match verify_id_token(&state, id_token, &discovery.jwks_uri, oidc).await {
            Ok(claims) => claims,
            Err(err) => {
                error!(error = %err, "id token verification failed");
                return unauthorized("invalid id token").into_response();
            }
        };

    match id_claims.nonce {
        Some(nonce) if constant_time_equal(nonce.as_bytes(), payload.nonce.as_bytes()) => {}
        _ => {
            return unauthorized("nonce mismatch").into_response();
        }
    }

    let exp = match access_token_exp(&tokens.access_token) {
        Some(exp) => exp,
        None => {
            warn!(
                subject = %id_claims.sub,
                "access token missing exp claim; falling back to id token exp"
            );
            id_claims.exp
        }
    };
    let now = unix_now();
    let bounded_exp = exp.min(id_claims.exp);
    let max_age = (bounded_exp - now)
        .clamp(1, DEFAULT_SESSION_MAX_AGE_SECS as i64) as u64;

    let session_token = Uuid::new_v4().to_string();
    let csrf_token = Uuid::new_v4().to_string();

    let mut response_headers = HeaderMap::new();
    if let Err(err) = append_set_cookie(
        &mut response_headers,
        &session_cookie(
            &session_token,
            state.cookie_domain(),
            state.cookie_secure(),
            max_age,
        ),
    ) {
        error!(error = %err, "failed to set session cookie");
        return internal_error("failed to issue session cookie").into_response();
    }

    if let Err(err) = append_set_cookie(
        &mut response_headers,
        &csrf_cookie(&csrf_token, state.cookie_domain(), state.cookie_secure()),
    ) {
        error!(error = %err, "failed to set csrf cookie");
        return internal_error("failed to issue csrf cookie").into_response();
    }

    if let Err(err) = append_set_cookie(
        &mut response_headers,
        &expired_cookie(
            AUTH_CHALLENGE_COOKIE_NAME,
            state.cookie_domain(),
            true,
            state.cookie_secure(),
            "/auth/callback",
        ),
    ) {
        error!(error = %err, "failed to clear auth challenge cookie");
        return internal_error("failed to complete login").into_response();
    }

    response_headers.insert(header::LOCATION, HeaderValue::from_static("/"));
    (StatusCode::FOUND, response_headers).into_response()
}

async fn create_session(
    State(state): State<AppState>,
    Json(payload): Json<SessionRequest>,
) -> Response {
    counter!("auth_api.http.requests_total", "route" => "/auth/session").increment(1);
    warn!("/auth/session is deprecated; use /auth/login + /auth/callback");

    let subject = payload.subject.unwrap_or_else(|| "local-user".to_string());
    let session_token = Uuid::new_v4().to_string();
    let csrf_token = Uuid::new_v4().to_string();

    let mut headers = HeaderMap::new();
    append_deprecation_headers(&mut headers);

    if let Err(err) = append_set_cookie(
        &mut headers,
        &session_cookie(
            &session_token,
            state.cookie_domain.as_str(),
            state.cookie_secure,
            DEFAULT_SESSION_MAX_AGE_SECS,
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
    counter!("auth_api.http.requests_total", "route" => "/auth/logout").increment(1);
    warn!("/auth/logout is deprecated; use /auth/login + /auth/callback");

    let mut headers = HeaderMap::new();
    append_deprecation_headers(&mut headers);

    if let Err(err) = append_set_cookie(
        &mut headers,
        &expired_cookie(
            "session",
            state.cookie_domain.as_str(),
            true,
            state.cookie_secure,
            "/",
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
            "/",
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

fn session_cookie(token: &str, domain: &str, secure: bool, max_age_secs: u64) -> String {
    let mut cookie =
        format!("session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_secs}");
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

fn auth_challenge_cookie(value: &str, domain: &str, secure: bool) -> String {
    let mut cookie = format!(
        "{AUTH_CHALLENGE_COOKIE_NAME}={value}; Path=/auth/callback; HttpOnly; SameSite=Lax; Max-Age={CHALLENGE_COOKIE_MAX_AGE_SECS}"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    if !domain.trim().is_empty() {
        cookie.push_str(&format!("; Domain={domain}"));
    }
    cookie
}

fn expired_cookie(name: &str, domain: &str, http_only: bool, secure: bool, path: &str) -> String {
    let mut cookie = format!("{name}=deleted; Path={path}; SameSite=Strict; Max-Age=0");
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
    headers.append(header::SET_COOKIE, header);
    Ok(())
}

fn append_deprecation_headers(headers: &mut HeaderMap) {
    headers.insert("deprecation", HeaderValue::from_static("true"));
    headers.insert("sunset", HeaderValue::from_static(DEPRECATION_SUNSET));
}

pub fn sign_challenge_cookie_value(
    verifier: &str,
    state: &str,
    nonce: &str,
    exp: i64,
    secret: &[u8],
) -> Result<String, String> {
    sign_challenge_payload(
        &ChallengeCookiePayload {
            verifier: verifier.to_string(),
            state: state.to_string(),
            nonce: nonce.to_string(),
            exp,
        },
        secret,
    )
}

fn sign_challenge_payload(
    payload: &ChallengeCookiePayload,
    secret: &[u8],
) -> Result<String, String> {
    let payload_json = serde_json::to_vec(payload).map_err(|err| err.to_string())?;
    let encoded_payload = URL_SAFE_NO_PAD.encode(payload_json);

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|err| err.to_string())?;
    mac.update(encoded_payload.as_bytes());
    let signature = mac.finalize().into_bytes();

    Ok(format!(
        "{encoded_payload}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn verify_challenge_payload(value: &str, secret: &[u8]) -> Result<ChallengeCookiePayload, String> {
    let (encoded_payload, encoded_signature) = value
        .split_once('.')
        .ok_or_else(|| "challenge cookie has invalid format".to_string())?;

    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|err| err.to_string())?;

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|err| err.to_string())?;
    mac.update(encoded_payload.as_bytes());
    let expected = mac.finalize().into_bytes();

    if !constant_time_equal(&signature, expected.as_ref()) {
        return Err("challenge cookie signature mismatch".to_string());
    }

    let payload_json = URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .map_err(|err| err.to_string())?;
    serde_json::from_slice::<ChallengeCookiePayload>(&payload_json).map_err(|err| err.to_string())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get_all(header::COOKIE).iter().find_map(|value| {
        value.to_str().ok().and_then(|cookie_header| {
            cookie_header.split(';').find_map(|cookie| {
                let (cookie_name, cookie_value) = cookie.trim().split_once('=')?;
                if cookie_name == name {
                    Some(cookie_value.to_string())
                } else {
                    None
                }
            })
        })
    })
}

fn build_authorize_url(
    authorization_endpoint: &str,
    oidc: &OidcConfig,
    state: &str,
    nonce: &str,
    code_challenge: &str,
) -> Result<reqwest::Url, String> {
    let mut url = reqwest::Url::parse(authorization_endpoint).map_err(|err| err.to_string())?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &oidc.client_id)
        .append_pair("redirect_uri", &oidc.redirect_uri)
        .append_pair("scope", "openid profile")
        .append_pair("state", state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256");

    Ok(url)
}

async fn discovery_document(
    state: &AppState,
    oidc: &OidcConfig,
) -> Result<DiscoveryDocument, String> {
    let now = unix_now();
    if let Some(cached) = state.discovery_cache.read().await.as_ref() {
        if cached.expires_at_unix > now {
            return Ok(cached.document.clone());
        }
    }

    let fresh = fetch_discovery_document(&state.http_client, oidc).await?;
    let expires_at_unix = now + state.oidc_discovery_ttl_secs as i64;
    {
        let mut cache = state.discovery_cache.write().await;
        *cache = Some(CachedDiscovery {
            document: fresh.clone(),
            expires_at_unix,
        });
    }
    Ok(fresh)
}

async fn fetch_discovery_document(
    client: &reqwest::Client,
    oidc: &OidcConfig,
) -> Result<DiscoveryDocument, String> {
    let response = client
        .get(&oidc.discovery_url)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        return Err(format!("discovery endpoint returned {}", response.status()));
    }

    response
        .json::<DiscoveryDocument>()
        .await
        .map_err(|err| err.to_string())
}

async fn exchange_code_for_tokens(
    client: &reqwest::Client,
    discovery: &DiscoveryDocument,
    oidc: &OidcConfig,
    code: &str,
    verifier: &str,
) -> Result<TokenEndpointResponse, String> {
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("client_id", oidc.client_id.clone()),
        ("redirect_uri", oidc.redirect_uri.clone()),
        ("code_verifier", verifier.to_string()),
    ];
    if let Some(client_secret) = &oidc.client_secret {
        form.push(("client_secret", client_secret.clone()));
    }

    let response = client
        .post(&discovery.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        return Err(format!("token endpoint returned {}", response.status()));
    }

    response
        .json::<TokenEndpointResponse>()
        .await
        .map_err(|err| err.to_string())
}

async fn verify_id_token(
    state: &AppState,
    id_token: &str,
    jwks_uri: &str,
    oidc: &OidcConfig,
) -> Result<IdTokenClaims, String> {
    let header = decode_header(id_token).map_err(|err| err.to_string())?;
    let kid = header.kid;

    let jwks = jwks_document(state, jwks_uri).await?;

    let jwk = if let Some(kid) = kid {
        jwks.keys
            .iter()
            .find(|key| key.kid.as_deref() == Some(kid.as_str()) && key.kty == "RSA")
    } else {
        jwks.keys.iter().find(|key| key.kty == "RSA")
    }
    .ok_or_else(|| "no matching RSA JWK found".to_string())?;

    let n = jwk
        .n
        .as_deref()
        .ok_or_else(|| "missing RSA modulus in JWK".to_string())?;
    let e = jwk
        .e
        .as_deref()
        .ok_or_else(|| "missing RSA exponent in JWK".to_string())?;

    let decoding_key = DecodingKey::from_rsa_components(n, e).map_err(|err| err.to_string())?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[oidc.issuer.as_str()]);
    validation.set_audience(&[oidc.client_id.as_str()]);

    let token_data = decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|err| err.to_string())?;

    Ok(token_data.claims)
}

async fn jwks_document(state: &AppState, jwks_uri: &str) -> Result<Jwks, String> {
    let now = unix_now();
    if let Some(cached) = state.jwks_cache.read().await.as_ref() {
        if cached.expires_at_unix > now && cached.jwks_uri == jwks_uri {
            return Ok(cached.document.clone());
        }
    }

    let fresh = fetch_jwks_document(&state.http_client, jwks_uri).await?;
    let expires_at_unix = now + state.oidc_discovery_ttl_secs as i64;
    {
        let mut cache = state.jwks_cache.write().await;
        *cache = Some(CachedJwks {
            jwks_uri: jwks_uri.to_string(),
            document: fresh.clone(),
            expires_at_unix,
        });
    }
    Ok(fresh)
}

async fn fetch_jwks_document(client: &reqwest::Client, jwks_uri: &str) -> Result<Jwks, String> {
    let jwks_response = client
        .get(jwks_uri)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !jwks_response.status().is_success() {
        return Err(format!("jwks endpoint returned {}", jwks_response.status()));
    }

    jwks_response
        .json::<Jwks>()
        .await
        .map_err(|err| err.to_string())
}

fn access_token_exp(access_token: &str) -> Option<i64> {
    let payload = access_token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value = serde_json::from_slice::<serde_json::Value>(&decoded).ok()?;
    value.get("exp")?.as_i64()
}

fn init_prometheus_handle() -> Result<PrometheusHandle> {
    if let Some(handle) = PROMETHEUS_HANDLE.get() {
        return Ok(handle.clone());
    }

    match PrometheusBuilder::new().install_recorder() {
        Ok(handle) => {
            let _ = PROMETHEUS_HANDLE.set(handle.clone());
            Ok(PROMETHEUS_HANDLE.get().cloned().unwrap_or(handle))
        }
        Err(err) => {
            if let Some(handle) = PROMETHEUS_HANDLE.get() {
                Ok(handle.clone())
            } else {
                Err(err.into())
            }
        }
    }
}

fn load_oidc_config_from_env() -> Option<OidcConfig> {
    let issuer = std::env::var("OIDC_ISSUER").unwrap_or_default();
    let client_id = std::env::var("OIDC_CLIENT_ID").unwrap_or_default();
    let client_secret = std::env::var("OIDC_CLIENT_SECRET").ok();
    let redirect_uri = std::env::var("OIDC_REDIRECT_URI").unwrap_or_default();
    let challenge_secret_raw = std::env::var("AUTH_CHALLENGE_SECRET").unwrap_or_default();

    if issuer.is_empty()
        && client_id.is_empty()
        && redirect_uri.is_empty()
        && challenge_secret_raw.is_empty()
    {
        return None;
    }

    if issuer.is_empty()
        || client_id.is_empty()
        || redirect_uri.is_empty()
        || challenge_secret_raw.is_empty()
    {
        warn!(
            "oidc configuration is incomplete; /auth/login and /auth/callback will be unavailable"
        );
        return None;
    }

    let challenge_secret = match parse_hex_secret(&challenge_secret_raw) {
        Ok(secret) if secret.len() >= 32 => secret,
        Ok(_) => {
            warn!("AUTH_CHALLENGE_SECRET must be at least 32 bytes");
            return None;
        }
        Err(reason) => {
            warn!(reason, "invalid AUTH_CHALLENGE_SECRET");
            return None;
        }
    };

    if let Ok(cursor_secret) = std::env::var("CURSOR_SECRET") {
        if !cursor_secret.is_empty()
            && constant_time_equal(cursor_secret.as_bytes(), challenge_secret_raw.as_bytes())
        {
            warn!("AUTH_CHALLENGE_SECRET must differ from CURSOR_SECRET");
            return None;
        }
    }

    let discovery_url = std::env::var("OIDC_DISCOVERY_URL").unwrap_or_else(|_| {
        format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        )
    });

    Some(OidcConfig::new(
        issuer,
        client_id,
        client_secret,
        redirect_uri,
        discovery_url,
        challenge_secret,
    ))
}

fn parse_hex_secret(raw: &str) -> Result<Vec<u8>, &'static str> {
    let value = raw.trim();
    if value.len() % 2 != 0 {
        return Err("hex secret must contain an even number of characters");
    }

    let mut decoded = Vec::with_capacity(value.len() / 2);
    let mut idx = 0;
    while idx < value.len() {
        let byte = u8::from_str_radix(&value[idx..idx + 2], 16)
            .map_err(|_| "hex secret contains invalid characters")?;
        decoded.push(byte);
        idx += 2;
    }

    Ok(decoded)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn internal_error(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            message: message.to_string(),
        }),
    )
}

fn bad_request(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            message: message.to_string(),
        }),
    )
}

fn bad_gateway(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_GATEWAY,
        Json(ErrorResponse {
            message: message.to_string(),
        }),
    )
}

fn unauthorized(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            message: message.to_string(),
        }),
    )
}

#[cfg(unix)]
async fn shutdown_signal() -> Result<&'static str> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result?;
            Ok("SIGINT")
        }
        _ = sigterm.recv() => Ok("SIGTERM"),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> Result<&'static str> {
    tokio::signal::ctrl_c().await?;
    Ok("SIGINT")
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

fn load_positive_u64_env(key: &str, default: u64) -> u64 {
    match std::env::var(key) {
        Ok(value) => match value.parse::<u64>() {
            Ok(parsed) if parsed > 0 => parsed,
            _ => {
                warn!(
                    env_key = key,
                    value = %value,
                    default = default,
                    "invalid numeric env value; using default"
                );
                default
            }
        },
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
        let session = session_cookie("token", "example.com", true, 900);
        assert!(session.starts_with("session=token"));
        assert!(session.contains("HttpOnly"));
        assert!(session.contains("SameSite=Strict"));
        assert!(session.contains("Secure"));
        assert!(session.contains("Domain=example.com"));

        let csrf = csrf_cookie("token", "", false);
        assert!(csrf.starts_with("csrf-token=token"));
        assert!(!csrf.contains("HttpOnly"));
        assert!(!csrf.contains("Secure"));

        let challenge = auth_challenge_cookie("signed", "example.com", true);
        assert!(challenge.starts_with("auth-challenge=signed"));
        assert!(challenge.contains("Path=/auth/callback"));
        assert!(challenge.contains("HttpOnly"));
        assert!(challenge.contains("SameSite=Lax"));

        let expired = expired_cookie("session", "example.com", true, true, "/");
        assert!(expired.contains("Max-Age=0"));
        assert!(expired.contains("HttpOnly"));
        assert!(expired.contains("Secure"));
        assert!(expired.contains("Domain=example.com"));
    }

    #[test]
    fn challenge_cookie_round_trip_sign_and_verify() {
        let secret = vec![0x11; 32];
        let signed =
            sign_challenge_cookie_value("verifier", "state", "nonce", unix_now() + 60, &secret)
                .expect("challenge should sign");
        let verified = verify_challenge_payload(&signed, &secret).expect("challenge should verify");

        assert_eq!(verified.verifier, "verifier");
        assert_eq!(verified.state, "state");
        assert_eq!(verified.nonce, "nonce");
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
