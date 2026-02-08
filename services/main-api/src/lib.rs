use std::{
    cmp::Ordering,
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::Result as AnyhowResult;
use axum::{extract::State, routing::get, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use metrics::counter;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use prost_types::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::{net::TcpListener, sync::broadcast, task::JoinSet};
use tonic::{metadata::MetadataMap, transport::Server, Request, Response, Status};
use tracing::{error, info, warn};
use uuid::Uuid;

pub mod api {
    pub mod v1 {
        tonic::include_proto!("api.v1");
    }
}

use api::v1::metadata_service_server::{MetadataService, MetadataServiceServer};
use api::v1::{
    CreateMetadataRequest, CreateMetadataResponse, DeleteMetadataRequest, DeleteMetadataResponse,
    GetMetadataRequest, GetMetadataResponse, HealthRequest, HealthResponse, ListMetadataRequest,
    ListMetadataResponse, UpdateMetadataRequest, UpdateMetadataResponse, VideoMetadata,
};

pub const DEFAULT_GRPC_ADDR: &str = "0.0.0.0:50051";
pub const DEFAULT_HEALTH_ADDR: &str = "0.0.0.0:50052";
pub const DEFAULT_CONCURRENCY_LIMIT_PER_CONNECTION: usize = 256;
pub const DEFAULT_TCP_KEEPALIVE_SECS: u64 = 60;
pub const DEFAULT_TCP_NODELAY: bool = true;
pub const DEFAULT_HTTP2_KEEPALIVE_INTERVAL_SECS: u64 = 30;
pub const DEFAULT_HTTP2_KEEPALIVE_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_INITIAL_CONNECTION_WINDOW_SIZE: u32 = 1024 * 1024;
pub const DEFAULT_INITIAL_STREAM_WINDOW_SIZE: u32 = 1024 * 1024;
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 32 * 1024;
pub const DEFAULT_MAX_DECODING_MESSAGE_SIZE: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_ENCODING_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_RECORDS: usize = 1_000_000;
pub const DEFAULT_ADMIN_UNSCOPED_LIST_LIMIT: usize = 100_000;
pub const DEFAULT_CURSOR_TTL_SECS: u64 = 300;
pub const DEFAULT_CURSOR_SECRET: &str = "media-api-default-cursor-secret";
static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortDirection {
    Asc,
    Desc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorPayload {
    pub last_created_at_seconds: i64,
    pub last_created_at_nanos: i32,
    pub last_id: String,
    pub sort_direction: SortDirection,
    pub filter_hash: u64,
    pub exp_unix: i64,
}

#[derive(Debug, Clone)]
pub enum PageTokenKind {
    Empty,
    Offset(usize),
    Cursor(CursorPayload),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequesterIdentity {
    pub sub: String,
    pub is_admin: bool,
}

#[derive(Debug, Deserialize)]
struct JwtPayloadClaims {
    sub: Option<String>,
    role: Option<serde_json::Value>,
    roles: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LegacyCursorPayload {
    last_created_at_seconds: i64,
    last_created_at_nanos: i32,
    last_id: String,
    sort_direction: SortDirection,
    filter_hash: u64,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DecodedCursorPayload {
    Current(CursorPayload),
    #[allow(dead_code)]
    Legacy(LegacyCursorPayload),
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub grpc_addr: SocketAddr,
    pub health_addr: SocketAddr,
    pub concurrency_limit_per_connection: usize,
    pub tcp_keepalive: Duration,
    pub tcp_nodelay: bool,
    pub http2_keepalive_interval: Duration,
    pub http2_keepalive_timeout: Duration,
    pub initial_connection_window_size: u32,
    pub initial_stream_window_size: u32,
    pub max_frame_size: u32,
    pub max_decoding_message_size: usize,
    pub max_encoding_message_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            grpc_addr: DEFAULT_GRPC_ADDR
                .parse()
                .expect("default gRPC listen address must parse"),
            health_addr: DEFAULT_HEALTH_ADDR
                .parse()
                .expect("default health listen address must parse"),
            concurrency_limit_per_connection: DEFAULT_CONCURRENCY_LIMIT_PER_CONNECTION,
            tcp_keepalive: Duration::from_secs(DEFAULT_TCP_KEEPALIVE_SECS),
            tcp_nodelay: DEFAULT_TCP_NODELAY,
            http2_keepalive_interval: Duration::from_secs(DEFAULT_HTTP2_KEEPALIVE_INTERVAL_SECS),
            http2_keepalive_timeout: Duration::from_secs(DEFAULT_HTTP2_KEEPALIVE_TIMEOUT_SECS),
            initial_connection_window_size: DEFAULT_INITIAL_CONNECTION_WINDOW_SIZE,
            initial_stream_window_size: DEFAULT_INITIAL_STREAM_WINDOW_SIZE,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_decoding_message_size: DEFAULT_MAX_DECODING_MESSAGE_SIZE,
            max_encoding_message_size: DEFAULT_MAX_ENCODING_MESSAGE_SIZE,
        }
    }
}

#[derive(Clone)]
pub struct MetadataStore {
    records: Arc<DashMap<String, Arc<VideoMetadata>>>,
    by_owner: Arc<DashMap<String, Vec<String>>>,
    by_visibility: Arc<DashMap<i32, Vec<String>>>,
    capacity_permits: Arc<DashMap<String, tokio::sync::OwnedSemaphorePermit>>,
    capacity_limiter: Arc<tokio::sync::Semaphore>,
    max_records: usize,
    mutation_lock: Arc<tokio::sync::Mutex<()>>,
}

impl MetadataStore {
    pub fn new(max_records: usize) -> Self {
        Self {
            records: Arc::new(DashMap::new()),
            by_owner: Arc::new(DashMap::new()),
            by_visibility: Arc::new(DashMap::new()),
            capacity_permits: Arc::new(DashMap::new()),
            capacity_limiter: Arc::new(tokio::sync::Semaphore::new(max_records)),
            max_records,
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    fn add_indexes_for(&self, row: &VideoMetadata) {
        self.by_owner
            .entry(row.owner_id.clone())
            .or_default()
            .push(row.id.clone());
        self.by_visibility
            .entry(row.visibility)
            .or_default()
            .push(row.id.clone());
    }

    fn remove_indexes_for(&self, row: &VideoMetadata) {
        if let Some(mut owner_ids) = self.by_owner.get_mut(&row.owner_id) {
            owner_ids.retain(|id| id != &row.id);
            if owner_ids.is_empty() {
                drop(owner_ids);
                self.by_owner.remove(&row.owner_id);
            }
        }

        if let Some(mut visibility_ids) = self.by_visibility.get_mut(&row.visibility) {
            visibility_ids.retain(|id| id != &row.id);
            if visibility_ids.is_empty() {
                drop(visibility_ids);
                self.by_visibility.remove(&row.visibility);
            }
        }
    }
}

impl Default for MetadataStore {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_RECORDS)
    }
}

#[derive(Clone)]
pub struct MetadataServiceImpl {
    store: MetadataStore,
    cursor_secret: Arc<Vec<u8>>,
    cursor_ttl_secs: u64,
    admin_unscoped_list_limit: usize,
}

impl Default for MetadataServiceImpl {
    fn default() -> Self {
        Self {
            store: MetadataStore::default(),
            cursor_secret: Arc::new(load_cursor_secret()),
            cursor_ttl_secs: load_cursor_ttl_secs(),
            admin_unscoped_list_limit: DEFAULT_ADMIN_UNSCOPED_LIST_LIMIT,
        }
    }
}

impl MetadataServiceImpl {
    fn collect_rows_for_owner_filter(&self, filter_owner_id: &str) -> Vec<Arc<VideoMetadata>> {
        if filter_owner_id.is_empty() {
            return self
                .store
                .records
                .iter()
                .map(|entry| Arc::clone(entry.value()))
                .collect();
        }

        self.store
            .by_owner
            .get(filter_owner_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| {
                        self.store
                            .records
                            .get(id)
                            .map(|entry| Arc::clone(entry.value()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[tonic::async_trait]
impl MetadataService for MetadataServiceImpl {
    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> std::result::Result<Response<HealthResponse>, Status> {
        counter!("main_api.grpc.requests_total", "method" => "health").increment(1);
        Ok(Response::new(HealthResponse {
            status: api::v1::health_response::Status::Healthy as i32,
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: now_timestamp(),
        }))
    }

    async fn create_metadata(
        &self,
        request: Request<CreateMetadataRequest>,
    ) -> std::result::Result<Response<CreateMetadataResponse>, Status> {
        counter!("main_api.grpc.requests_total", "method" => "create_metadata").increment(1);
        let identity = requester_identity(request.metadata())?;
        let req = request.into_inner();

        if req.title.trim().is_empty() {
            return Err(Status::invalid_argument("title is required"));
        }

        let id = Uuid::new_v4().to_string();
        let metadata = VideoMetadata {
            id: id.clone(),
            resource_id: format!("res-{id}"),
            title: req.title,
            description: req.description,
            tags: req.tags,
            mime_type: req.mime_type,
            file_size: req.file_size,
            owner_id: identity.sub,
            visibility: req.visibility,
            created_at: now_timestamp(),
            updated_at: now_timestamp(),
        };

        validate_metadata(&metadata)?;

        let permit = self
            .store
            .capacity_limiter
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                Status::resource_exhausted("metadata store has reached max capacity")
            })?;
        if self.store.records.len() >= self.store.max_records {
            return Err(Status::resource_exhausted(
                "metadata store has reached max capacity",
            ));
        }

        let metadata_ref = Arc::new(metadata.clone());
        self.store.records.insert(id.clone(), Arc::clone(&metadata_ref));
        self.store.add_indexes_for(metadata_ref.as_ref());
        self.store.capacity_permits.insert(id, permit);

        Ok(Response::new(CreateMetadataResponse {
            metadata: Some(metadata),
            from_cache: false,
        }))
    }

    async fn get_metadata(
        &self,
        request: Request<GetMetadataRequest>,
    ) -> std::result::Result<Response<GetMetadataResponse>, Status> {
        counter!("main_api.grpc.requests_total", "method" => "get_metadata").increment(1);
        let identity = requester_identity(request.metadata())?;
        let id = request.into_inner().id;

        if id.trim().is_empty() {
            return Err(Status::invalid_argument("id is required"));
        }

        let metadata = self
            .store
            .records
            .get(&id)
            .map(|entry| entry.value().as_ref().clone())
            .ok_or_else(|| Status::not_found("metadata not found"))?;
        if !identity.is_admin && metadata.owner_id != identity.sub {
            return Err(Status::permission_denied(
                "cannot access metadata owned by another user",
            ));
        }

        Ok(Response::new(GetMetadataResponse {
            metadata: Some(metadata),
            from_cache: false,
        }))
    }

    async fn list_metadata(
        &self,
        request: Request<ListMetadataRequest>,
    ) -> std::result::Result<Response<ListMetadataResponse>, Status> {
        counter!("main_api.grpc.requests_total", "method" => "list_metadata").increment(1);
        let identity = requester_identity(request.metadata())?;
        let mut req = request.into_inner();
        if !identity.is_admin {
            if req.filter_owner_id.is_empty() {
                req.filter_owner_id = identity.sub.clone();
            } else if req.filter_owner_id != identity.sub {
                return Err(Status::invalid_argument(
                    "filter_owner_id must match requester identity for non-admin access",
                ));
            }
        }

        let page_size = normalize_page_size(req.page_size);
        let page_token = classify_page_token(
            &req.page_token,
            self.cursor_secret.as_ref(),
            self.cursor_ttl_secs,
        )?;
        let filter_hash = compute_filter_hash(&req, &identity.sub, self.cursor_secret.as_ref());
        let sort_direction = normalize_sort_direction(req.sort_direction)?;

        if identity.is_admin
            && req.filter_owner_id.is_empty()
            && self.store.records.len() > self.admin_unscoped_list_limit
        {
            return Err(Status::resource_exhausted(
                "admin list without filter_owner_id exceeds configured scan limit",
            ));
        }

        let mut rows = self.collect_rows_for_owner_filter(&req.filter_owner_id);
        apply_list_filters(&mut rows, &req);

        rows.sort_by(|left, right| compare_rows(left.as_ref(), right.as_ref(), sort_direction));

        let (start, has_exact_count, total_count) = match page_token {
            PageTokenKind::Empty => (0, true, clamp_total_count(rows.len())),
            PageTokenKind::Offset(offset) => {
                (offset.min(rows.len()), true, clamp_total_count(rows.len()))
            }
            PageTokenKind::Cursor(cursor) => {
                if cursor.sort_direction != sort_direction {
                    return Err(Status::invalid_argument(
                        "cursor sort direction does not match request sort direction",
                    ));
                }
                if cursor.filter_hash != filter_hash {
                    return Err(Status::invalid_argument(
                        "cursor does not match current filter parameters",
                    ));
                }

                let start = cursor_start_index(&rows, &cursor);
                let remaining = clamp_total_count(rows.len().saturating_sub(start));
                (start, false, remaining)
            }
        };

        let end = (start + page_size).min(rows.len());
        let next_page_token = if end < rows.len() {
            let next_cursor = build_cursor_payload(
                rows[end - 1].as_ref(),
                sort_direction,
                filter_hash,
                self.cursor_ttl_secs,
            );
            encode_cursor(&next_cursor, self.cursor_secret.as_ref())?
        } else {
            String::new()
        };

        Ok(Response::new(ListMetadataResponse {
            metadata_list: rows[start..end]
                .iter()
                .map(|row| row.as_ref().clone())
                .collect(),
            next_page_token,
            total_count,
            has_exact_count,
        }))
    }

    async fn update_metadata(
        &self,
        request: Request<UpdateMetadataRequest>,
    ) -> std::result::Result<Response<UpdateMetadataResponse>, Status> {
        counter!("main_api.grpc.requests_total", "method" => "update_metadata").increment(1);
        let identity = requester_identity(request.metadata())?;
        let req = request.into_inner();

        if req.id.trim().is_empty() {
            return Err(Status::invalid_argument("id is required"));
        }

        let patch = req
            .metadata
            .ok_or_else(|| Status::invalid_argument("metadata payload is required"))?;

        let mask = req
            .update_mask
            .ok_or_else(|| Status::invalid_argument("update_mask is required"))?;
        if mask.paths.is_empty() {
            return Err(Status::invalid_argument(
                "update_mask.paths must not be empty",
            ));
        }

        let _mutation_guard = self.store.mutation_lock.lock().await;
        let existing = self
            .store
            .records
            .get(&req.id)
            .ok_or_else(|| Status::not_found("metadata not found"))?;
        if !identity.is_admin && existing.owner_id != identity.sub {
            return Err(Status::permission_denied(
                "cannot modify metadata owned by another user",
            ));
        }
        let mut candidate = existing.as_ref().clone();
        let previous = existing.as_ref().clone();
        drop(existing);

        for path in mask.paths {
            apply_field(&mut candidate, &patch, &path)?;
        }

        validate_metadata(&candidate)?;
        candidate.updated_at = now_timestamp();
        self.store
            .records
            .insert(req.id.clone(), Arc::new(candidate.clone()));

        if previous.owner_id != candidate.owner_id || previous.visibility != candidate.visibility {
            self.store.remove_indexes_for(&previous);
            self.store.add_indexes_for(&candidate);
        }

        Ok(Response::new(UpdateMetadataResponse {
            metadata: Some(candidate),
            from_cache: false,
        }))
    }

    async fn delete_metadata(
        &self,
        request: Request<DeleteMetadataRequest>,
    ) -> std::result::Result<Response<DeleteMetadataResponse>, Status> {
        counter!("main_api.grpc.requests_total", "method" => "delete_metadata").increment(1);
        let identity = requester_identity(request.metadata())?;
        let req = request.into_inner();

        if req.id.trim().is_empty() {
            return Err(Status::invalid_argument("id is required"));
        }

        let _mutation_guard = self.store.mutation_lock.lock().await;
        if let Some(existing) = self.store.records.get(&req.id) {
            if !identity.is_admin && existing.owner_id != identity.sub {
                return Err(Status::permission_denied(
                    "cannot delete metadata owned by another user",
                ));
            }
        }

        let removed = self
            .store
            .records
            .remove(&req.id)
            .ok_or_else(|| Status::not_found("metadata not found"))?;
        self.store.remove_indexes_for(removed.1.as_ref());
        self.store.capacity_permits.remove(&req.id);

        Ok(Response::new(DeleteMetadataResponse {}))
    }
}

pub fn apply_field(
    target: &mut VideoMetadata,
    patch: &VideoMetadata,
    field: &str,
) -> std::result::Result<(), Status> {
    match field {
        "title" => target.title = patch.title.clone(),
        "description" => {
            target.description = patch.description.clone();
        }
        "tags" => target.tags = patch.tags.clone(),
        "mime_type" => target.mime_type = patch.mime_type.clone(),
        "file_size" => target.file_size = patch.file_size,
        "owner_id" => {
            return Err(Status::invalid_argument(
                "owner_id is server-managed and cannot be updated",
            ))
        }
        "visibility" => target.visibility = patch.visibility,
        _ => {
            return Err(Status::invalid_argument(format!(
                "unsupported update_mask field: {field}"
            )))
        }
    }

    Ok(())
}

pub fn validate_metadata(metadata: &VideoMetadata) -> std::result::Result<(), Status> {
    if metadata.title.trim().is_empty() {
        return Err(Status::invalid_argument("title cannot be empty"));
    }

    if metadata.mime_type.trim().is_empty() {
        return Err(Status::invalid_argument("mime_type cannot be empty"));
    }

    if metadata.file_size < 0 {
        return Err(Status::invalid_argument("file_size must be >= 0"));
    }

    if api::v1::Visibility::try_from(metadata.visibility).is_err() {
        return Err(Status::invalid_argument(
            "visibility must be a known enum value",
        ));
    }

    Ok(())
}

pub fn sort_key(row: &VideoMetadata) -> (i64, i32, &str) {
    let (seconds, nanos) = row
        .created_at
        .as_ref()
        .map(|ts| (ts.seconds, ts.nanos))
        .unwrap_or((0, 0));

    (seconds, nanos, row.id.as_str())
}

pub fn compare_rows(
    left: &VideoMetadata,
    right: &VideoMetadata,
    sort_direction: SortDirection,
) -> Ordering {
    let ordering = sort_key(left).cmp(&sort_key(right));
    match sort_direction {
        SortDirection::Asc => ordering,
        SortDirection::Desc => ordering.reverse(),
    }
}

pub fn now_timestamp() -> Option<Timestamp> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;

    Some(Timestamp {
        seconds: now.as_secs() as i64,
        nanos: now.subsec_nanos() as i32,
    })
}

pub fn normalize_page_size(raw: i32) -> usize {
    if raw <= 0 {
        return 20;
    }

    raw.min(100) as usize
}

pub fn parse_page_token(token: &str) -> std::result::Result<usize, Status> {
    if token.is_empty() {
        return Ok(0);
    }

    token
        .parse::<usize>()
        .map_err(|_| Status::invalid_argument("invalid page_token: expected a numeric offset"))
}

pub fn classify_page_token(
    token: &str,
    secret: &[u8],
    _cursor_ttl_secs: u64,
) -> std::result::Result<PageTokenKind, Status> {
    if token.is_empty() {
        return Ok(PageTokenKind::Empty);
    }

    if token.chars().all(|ch| ch.is_ascii_digit()) {
        warn!("received legacy numeric page_token; offset pagination is deprecated");
        return parse_page_token(token).map(PageTokenKind::Offset);
    }

    decode_cursor_with_ttl(token, secret, _cursor_ttl_secs).map(PageTokenKind::Cursor)
}

pub fn parse_page_token_kind(
    token: &str,
    secret: &[u8],
    cursor_ttl_secs: u64,
) -> std::result::Result<PageTokenKind, Status> {
    classify_page_token(token, secret, cursor_ttl_secs)
}

pub fn load_cursor_secret() -> Vec<u8> {
    let raw = std::env::var("CURSOR_SECRET").ok();
    let missing_or_empty = raw
        .as_ref()
        .map(|value| value.trim().is_empty())
        .unwrap_or(true);

    match cursor_secret_from_env(raw, cfg!(debug_assertions)) {
        Ok(secret) => {
            if cfg!(debug_assertions) && missing_or_empty {
                warn!("CURSOR_SECRET is not set; using debug-only default cursor secret");
            }
            secret
        }
        Err(message) => panic!("{message}"),
    }
}

fn cursor_secret_from_env(
    raw: Option<String>,
    allow_debug_fallback: bool,
) -> std::result::Result<Vec<u8>, &'static str> {
    if let Some(secret) = raw.filter(|value| !value.trim().is_empty()) {
        return Ok(secret.into_bytes());
    }

    if allow_debug_fallback {
        return Ok(DEFAULT_CURSOR_SECRET.as_bytes().to_vec());
    }

    Err("CURSOR_SECRET must be set in release builds")
}

pub fn load_cursor_ttl_secs() -> u64 {
    match std::env::var("CURSOR_TTL_SECS") {
        Ok(value) => match value.parse::<u64>() {
            Ok(parsed) if parsed > 0 => parsed,
            _ => {
                warn!(
                    value = %value,
                    default = DEFAULT_CURSOR_TTL_SECS,
                    "invalid CURSOR_TTL_SECS, using default"
                );
                DEFAULT_CURSOR_TTL_SECS
            }
        },
        Err(_) => DEFAULT_CURSOR_TTL_SECS,
    }
}

pub fn compute_filter_hash(req: &ListMetadataRequest, requester_sub: &str, secret: &[u8]) -> u64 {
    let mut mac =
        HmacSha256::new_from_slice(secret).expect("cursor secret should be valid for HMAC");
    mac.update(requester_sub.as_bytes());
    mac.update(&[0]);
    mac.update(req.filter_owner_id.as_bytes());
    mac.update(&[0]);
    mac.update(&req.filter_visibility.to_be_bytes());
    mac.update(&[0]);
    // Canonicalize tags to avoid cursor invalidation when callers reorder identical filters.
    let mut canonical_tags: Vec<&str> = req.filter_tags.iter().map(String::as_str).collect();
    canonical_tags.sort_unstable();
    canonical_tags.dedup();
    for tag in canonical_tags {
        mac.update(tag.as_bytes());
        mac.update(&[0]);
    }
    mac.update(req.search_query.as_bytes());

    let digest = mac.finalize().into_bytes();
    u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("digest prefix should fit u64"),
    )
}

pub fn build_cursor_payload(
    row: &VideoMetadata,
    sort_direction: SortDirection,
    filter_hash: u64,
    cursor_ttl_secs: u64,
) -> CursorPayload {
    let (seconds, nanos) = row
        .created_at
        .as_ref()
        .map(|ts| (ts.seconds, ts.nanos))
        .unwrap_or((0, 0));

    CursorPayload {
        last_created_at_seconds: seconds,
        last_created_at_nanos: nanos,
        last_id: row.id.clone(),
        sort_direction,
        filter_hash,
        exp_unix: unix_now().saturating_add(cursor_ttl_secs as i64),
    }
}

pub fn row_is_after_cursor(row: &VideoMetadata, cursor: &CursorPayload) -> bool {
    let row_key = sort_key(row);
    let cursor_key = (
        cursor.last_created_at_seconds,
        cursor.last_created_at_nanos,
        cursor.last_id.as_str(),
    );

    match cursor.sort_direction {
        SortDirection::Asc => row_key > cursor_key,
        SortDirection::Desc => row_key < cursor_key,
    }
}

fn cursor_start_index(rows: &[Arc<VideoMetadata>], cursor: &CursorPayload) -> usize {
    rows.partition_point(|row| !row_is_after_cursor(row.as_ref(), cursor))
}

fn apply_list_filters(rows: &mut Vec<Arc<VideoMetadata>>, req: &ListMetadataRequest) {
    if req.filter_visibility != 0 {
        rows.retain(|row| row.visibility == req.filter_visibility);
    }

    if !req.filter_tags.is_empty() {
        rows.retain(|row| req.filter_tags.iter().all(|tag| row.tags.contains(tag)));
    }

    if !req.search_query.is_empty() {
        let needle = req.search_query.to_lowercase();
        rows.retain(|row| {
            row.title.to_lowercase().contains(&needle)
                || row.description.to_lowercase().contains(&needle)
        });
    }
}

pub fn encode_cursor(
    payload: &CursorPayload,
    secret: &[u8],
) -> std::result::Result<String, Status> {
    let encoded_payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(payload).map_err(|_| Status::internal("failed to serialize cursor"))?,
    );

    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| Status::internal("invalid cursor secret"))?;
    mac.update(encoded_payload.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{encoded_payload}.{signature}"))
}

pub fn decode_cursor(token: &str, secret: &[u8]) -> std::result::Result<CursorPayload, Status> {
    decode_cursor_with_ttl(token, secret, DEFAULT_CURSOR_TTL_SECS)
}

pub fn decode_cursor_with_ttl(
    token: &str,
    secret: &[u8],
    _cursor_ttl_secs: u64,
) -> std::result::Result<CursorPayload, Status> {
    let (encoded_payload, encoded_signature) = token
        .split_once('.')
        .ok_or_else(|| Status::invalid_argument("invalid cursor token format"))?;

    let provided_signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| Status::invalid_argument("invalid cursor signature encoding"))?;

    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| Status::internal("invalid cursor secret"))?;
    mac.update(encoded_payload.as_bytes());
    if mac.verify_slice(&provided_signature).is_err() {
        return Err(Status::invalid_argument("invalid cursor signature"));
    }

    let decoded_payload = URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .map_err(|_| Status::invalid_argument("invalid cursor payload encoding"))?;
    let payload = match serde_json::from_slice::<DecodedCursorPayload>(&decoded_payload)
        .map_err(|_| Status::invalid_argument("invalid cursor payload"))?
    {
        DecodedCursorPayload::Current(payload) => payload,
        DecodedCursorPayload::Legacy(_) => {
            warn!("received legacy cursor payload without exp_unix; rejecting token");
            return Err(Status::invalid_argument(
                "legacy cursor token is no longer supported; restart pagination",
            ));
        }
    };
    if payload.exp_unix < unix_now() {
        return Err(Status::invalid_argument("cursor token has expired"));
    }

    Ok(payload)
}

pub fn clamp_total_count(count: usize) -> i32 {
    count.try_into().unwrap_or(i32::MAX)
}

pub fn normalize_sort_direction(raw: i32) -> std::result::Result<SortDirection, Status> {
    match raw {
        0 | 1 => Ok(SortDirection::Asc),
        2 => Ok(SortDirection::Desc),
        _ => Err(Status::invalid_argument(
            "sort_direction must be unspecified, asc, or desc",
        )),
    }
}

pub fn requester_identity(
    metadata: &MetadataMap,
) -> std::result::Result<RequesterIdentity, Status> {
    let raw = metadata
        .get("x-jwt-payload")
        .ok_or_else(|| Status::unauthenticated("missing x-jwt-payload metadata"))?
        .to_str()
        .map_err(|_| Status::unauthenticated("invalid x-jwt-payload metadata"))?;

    let claims = parse_jwt_payload(raw)?;
    let sub = claims
        .sub
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| Status::unauthenticated("jwt subject claim is missing"))?;
    let is_admin =
        claim_contains_admin(claims.roles.as_ref()) || claim_contains_admin(claims.role.as_ref());

    Ok(RequesterIdentity { sub, is_admin })
}

fn parse_jwt_payload(raw: &str) -> std::result::Result<JwtPayloadClaims, Status> {
    if let Ok(claims) = serde_json::from_str::<JwtPayloadClaims>(raw) {
        return Ok(claims);
    }

    let decoded_payload = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| Status::unauthenticated("invalid x-jwt-payload encoding"))?;
    serde_json::from_slice::<JwtPayloadClaims>(&decoded_payload)
        .map_err(|_| Status::unauthenticated("invalid x-jwt-payload json"))
}

fn claim_contains_admin(value: Option<&serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::String(role)) => role.eq_ignore_ascii_case("admin"),
        Some(serde_json::Value::Array(roles)) => {
            roles.iter().any(|entry| claim_contains_admin(Some(entry)))
        }
        _ => false,
    }
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn init_prometheus_handle() -> AnyhowResult<PrometheusHandle> {
    if let Some(handle) = PROMETHEUS_HANDLE.get() {
        return Ok(handle.clone());
    }

    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(anyhow::Error::from)?;
    let _ = PROMETHEUS_HANDLE.set(handle.clone());
    Ok(PROMETHEUS_HANDLE.get().cloned().unwrap_or(handle))
}

pub fn build_health_router(prometheus: PrometheusHandle) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .with_state(prometheus)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn metrics(State(handle): State<PrometheusHandle>) -> String {
    handle.render()
}

pub async fn run(config: ServerConfig) -> AnyhowResult<()> {
    info!(grpc_addr = %config.grpc_addr, "starting gRPC server");
    info!(health_addr = %config.health_addr, "starting HTTP health endpoint");
    let prometheus_handle = init_prometheus_handle()?;

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let mut tasks = JoinSet::new();

    let grpc_service = MetadataServiceImpl::default();
    let mut grpc_shutdown = shutdown_tx.subscribe();
    tasks.spawn(async move {
        let result = Server::builder()
            .concurrency_limit_per_connection(config.concurrency_limit_per_connection)
            .tcp_keepalive(Some(config.tcp_keepalive))
            .tcp_nodelay(config.tcp_nodelay)
            .http2_keepalive_interval(Some(config.http2_keepalive_interval))
            .http2_keepalive_timeout(Some(config.http2_keepalive_timeout))
            .initial_connection_window_size(Some(config.initial_connection_window_size))
            .initial_stream_window_size(Some(config.initial_stream_window_size))
            .max_frame_size(Some(config.max_frame_size))
            .add_service(
                MetadataServiceServer::new(grpc_service)
                    .max_decoding_message_size(config.max_decoding_message_size)
                    .max_encoding_message_size(config.max_encoding_message_size),
            )
            .serve_with_shutdown(config.grpc_addr, async move {
                let _ = grpc_shutdown.recv().await;
            })
            .await
            .map_err(anyhow::Error::from);
        ("gRPC", result)
    });

    let mut health_shutdown = shutdown_tx.subscribe();
    let health_addr = config.health_addr;
    let health_router = build_health_router(prometheus_handle);
    tasks.spawn(async move {
        let result: AnyhowResult<()> = async move {
            let listener = TcpListener::bind(health_addr)
                .await
                .map_err(anyhow::Error::from)?;
            axum::serve(listener, health_router)
                .with_graceful_shutdown(async move {
                    let _ = health_shutdown.recv().await;
                })
                .await
                .map_err(anyhow::Error::from)?;
            Ok(())
        }
        .await;
        ("health", result)
    });

    let mut first_error: Option<anyhow::Error> = None;
    tokio::select! {
        signal = shutdown_signal() => {
            match signal {
                Ok(signal_name) => info!(signal = signal_name, "shutdown signal received"),
                Err(err) => {
                    error!(error = %err, "failed to listen for shutdown signal");
                    first_error = Some(err);
                }
            }
        }
        joined = tasks.join_next() => {
            if let Some(joined) = joined {
                if let Some(err) = observe_server_exit(joined) {
                    first_error = Some(err);
                }
            }
        }
    }

    let _ = shutdown_tx.send(());
    while let Some(joined) = tasks.join_next().await {
        if let Some(err) = observe_server_exit(joined) {
            if first_error.is_none() {
                first_error = Some(err);
            }
        }
    }

    info!("shutdown complete");
    if let Some(err) = first_error {
        return Err(err);
    }

    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() -> AnyhowResult<&'static str> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).map_err(anyhow::Error::from)?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.map(|_| "SIGINT").map_err(anyhow::Error::from),
        _ = sigterm.recv() => Ok("SIGTERM"),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> AnyhowResult<&'static str> {
    tokio::signal::ctrl_c().await.map_err(anyhow::Error::from)?;
    Ok("SIGINT")
}

fn observe_server_exit(
    joined: std::result::Result<(&'static str, AnyhowResult<()>), tokio::task::JoinError>,
) -> Option<anyhow::Error> {
    match joined {
        Ok((name, Ok(()))) => {
            info!(server = name, "server stopped");
            None
        }
        Ok((name, Err(err))) => {
            error!(server = name, error = %err, "server exited with error");
            Some(err)
        }
        Err(err) => {
            error!(error = %err, "server task panicked");
            Some(anyhow::Error::from(err))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn authorized_request<T>(inner: T, sub: &str, roles: &[&str]) -> Request<T> {
        let payload = json!({ "sub": sub, "roles": roles });
        let encoded =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload should serialize"));
        let mut request = Request::new(inner);
        request.metadata_mut().insert(
            "x-jwt-payload",
            encoded.parse().expect("metadata should parse"),
        );
        request
    }

    fn sample_metadata(id: &str, seconds: i64, nanos: i32) -> VideoMetadata {
        VideoMetadata {
            id: id.to_string(),
            resource_id: format!("res-{id}"),
            title: "sample".to_string(),
            description: "sample description".to_string(),
            tags: vec!["tag".to_string()],
            mime_type: "video/mp4".to_string(),
            file_size: 10,
            owner_id: "owner".to_string(),
            visibility: api::v1::Visibility::Private as i32,
            created_at: Some(Timestamp { seconds, nanos }),
            updated_at: Some(Timestamp { seconds, nanos }),
        }
    }

    #[test]
    fn normalize_page_size_defaults_and_caps() {
        assert_eq!(normalize_page_size(0), 20);
        assert_eq!(normalize_page_size(-10), 20);
        assert_eq!(normalize_page_size(25), 25);
        assert_eq!(normalize_page_size(500), 100);
    }

    #[test]
    fn parse_page_token_parses_numeric_offsets() {
        assert_eq!(parse_page_token("").expect("empty token should parse"), 0);
        assert_eq!(
            parse_page_token("7").expect("numeric token should parse"),
            7
        );

        let err = parse_page_token("not-a-number").expect_err("token should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn validate_metadata_checks_required_fields() {
        let mut metadata = sample_metadata("id-1", 1, 0);
        assert!(validate_metadata(&metadata).is_ok());

        metadata.title = "   ".to_string();
        let err = validate_metadata(&metadata).expect_err("empty title should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        metadata.title = "ok".to_string();
        metadata.mime_type = "   ".to_string();
        let err = validate_metadata(&metadata).expect_err("empty mime type should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        metadata.mime_type = "video/mp4".to_string();
        metadata.file_size = -1;
        let err = validate_metadata(&metadata).expect_err("negative size should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        metadata.file_size = 1;
        metadata.visibility = 99;
        let err = validate_metadata(&metadata).expect_err("invalid visibility should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn apply_field_updates_supported_fields_and_rejects_others() {
        let mut target = sample_metadata("id-1", 1, 0);
        let mut patch = sample_metadata("id-2", 2, 0);
        patch.title = "updated".to_string();
        patch.file_size = 42;
        patch.owner_id = "other-owner".to_string();

        apply_field(&mut target, &patch, "title").expect("title update should succeed");
        apply_field(&mut target, &patch, "file_size").expect("file size update should succeed");

        assert_eq!(target.title, "updated");
        assert_eq!(target.file_size, 42);

        let err = apply_field(&mut target, &patch, "owner_id")
            .expect_err("owner_id update should be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(target.owner_id, "owner");

        let err = apply_field(&mut target, &patch, "unknown").expect_err("field should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn sort_key_orders_by_timestamp_then_id() {
        let mut rows = vec![
            sample_metadata("b", 10, 1),
            sample_metadata("a", 10, 1),
            sample_metadata("c", 9, 999),
        ];

        rows.sort_by(|left, right| compare_rows(left, right, SortDirection::Asc));

        let ids: Vec<String> = rows.into_iter().map(|row| row.id).collect();
        assert_eq!(ids, vec!["c".to_string(), "a".to_string(), "b".to_string()]);
    }

    #[test]
    fn cursor_start_index_matches_linear_scan() {
        let mut rows = vec![
            Arc::new(sample_metadata("a", 1, 0)),
            Arc::new(sample_metadata("b", 2, 0)),
            Arc::new(sample_metadata("c", 3, 0)),
            Arc::new(sample_metadata("d", 4, 0)),
        ];
        rows.sort_by(|left, right| compare_rows(left, right, SortDirection::Asc));

        let cursor = CursorPayload {
            last_created_at_seconds: 2,
            last_created_at_nanos: 0,
            last_id: "b".to_string(),
            sort_direction: SortDirection::Asc,
            filter_hash: 0,
            exp_unix: unix_now() + 60,
        };

        let linear = rows
            .iter()
            .position(|row| row_is_after_cursor(row, &cursor))
            .unwrap_or(rows.len());
        let binary = cursor_start_index(&rows, &cursor);
        assert_eq!(binary, linear);
    }

    #[tokio::test]
    async fn create_metadata_enforces_max_records_limit() {
        let service = MetadataServiceImpl {
            store: MetadataStore::new(1),
            cursor_secret: Arc::new(b"test-cursor-secret".to_vec()),
            cursor_ttl_secs: DEFAULT_CURSOR_TTL_SECS,
            admin_unscoped_list_limit: DEFAULT_ADMIN_UNSCOPED_LIST_LIMIT,
        };

        service
            .create_metadata(authorized_request(
                CreateMetadataRequest {
                    title: "first".to_string(),
                    description: String::new(),
                    tags: vec![],
                    mime_type: "video/mp4".to_string(),
                    file_size: 1,
                    visibility: api::v1::Visibility::Private as i32,
                },
                "owner-1",
                &["user"],
            ))
            .await
            .expect("first record should succeed");

        let err = service
            .create_metadata(authorized_request(
                CreateMetadataRequest {
                    title: "second".to_string(),
                    description: String::new(),
                    tags: vec![],
                    mime_type: "video/mp4".to_string(),
                    file_size: 1,
                    visibility: api::v1::Visibility::Private as i32,
                },
                "owner-1",
                &["user"],
            ))
            .await
            .expect_err("second record should exceed max_records");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_create_respects_max_records_capacity() {
        let service = Arc::new(MetadataServiceImpl {
            store: MetadataStore::new(5),
            cursor_secret: Arc::new(b"test-cursor-secret".to_vec()),
            cursor_ttl_secs: DEFAULT_CURSOR_TTL_SECS,
            admin_unscoped_list_limit: DEFAULT_ADMIN_UNSCOPED_LIST_LIMIT,
        });

        let mut tasks = Vec::new();
        for idx in 0..32 {
            let service = Arc::clone(&service);
            tasks.push(tokio::spawn(async move {
                service
                    .create_metadata(authorized_request(
                        CreateMetadataRequest {
                            title: format!("record-{idx}"),
                            description: String::new(),
                            tags: vec![],
                            mime_type: "video/mp4".to_string(),
                            file_size: 1,
                            visibility: api::v1::Visibility::Private as i32,
                        },
                        "owner-1",
                        &["user"],
                    ))
                    .await
            }));
        }

        let mut created = 0;
        let mut exhausted = 0;
        for task in tasks {
            let result = task.await.expect("task should complete");
            match result {
                Ok(_) => created += 1,
                Err(status) if status.code() == tonic::Code::ResourceExhausted => exhausted += 1,
                Err(status) => panic!("unexpected create failure: {status}"),
            }
        }

        assert_eq!(created, 5);
        assert_eq!(exhausted, 27);
        assert_eq!(service.store.records.len(), 5);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_update_and_delete_do_not_resurrect_records() {
        let service = Arc::new(MetadataServiceImpl {
            store: MetadataStore::new(64),
            cursor_secret: Arc::new(b"test-cursor-secret".to_vec()),
            cursor_ttl_secs: DEFAULT_CURSOR_TTL_SECS,
            admin_unscoped_list_limit: DEFAULT_ADMIN_UNSCOPED_LIST_LIMIT,
        });

        for idx in 0..32 {
            let created = service
                .create_metadata(authorized_request(
                    CreateMetadataRequest {
                        title: format!("record-{idx}"),
                        description: "before".to_string(),
                        tags: vec![],
                        mime_type: "video/mp4".to_string(),
                        file_size: 1,
                        visibility: api::v1::Visibility::Private as i32,
                    },
                    "owner-1",
                    &["user"],
                ))
                .await
                .expect("record creation should succeed")
                .into_inner()
                .metadata
                .expect("metadata should be present");
            let id = created.id.clone();

            let mut patch = created.clone();
            patch.description = "after".to_string();

            let update_service = Arc::clone(&service);
            let update_id = id.clone();
            let update_task = tokio::spawn(async move {
                update_service
                    .update_metadata(authorized_request(
                        UpdateMetadataRequest {
                            id: update_id,
                            metadata: Some(patch),
                            update_mask: Some(prost_types::FieldMask {
                                paths: vec!["description".to_string()],
                            }),
                        },
                        "owner-1",
                        &["user"],
                    ))
                    .await
            });

            let delete_service = Arc::clone(&service);
            let delete_id = id.clone();
            let delete_task = tokio::spawn(async move {
                delete_service
                    .delete_metadata(authorized_request(
                        DeleteMetadataRequest {
                            id: delete_id,
                            permanent: false,
                        },
                        "owner-1",
                        &["user"],
                    ))
                    .await
            });

            let update_result = update_task.await.expect("update task should complete");
            let delete_result = delete_task.await.expect("delete task should complete");

            assert!(delete_result.is_ok(), "delete should succeed");
            if let Err(status) = update_result {
                assert_eq!(status.code(), tonic::Code::NotFound);
            }

            assert!(
                service.store.records.get(&id).is_none(),
                "record should not be resurrected after delete"
            );
            let owner_index_contains = service
                .store
                .by_owner
                .get("owner-1")
                .map(|ids| ids.iter().any(|candidate| candidate == &id))
                .unwrap_or(false);
            assert!(
                !owner_index_contains,
                "owner index should not retain deleted id"
            );
            let visibility_index_contains = service
                .store
                .by_visibility
                .get(&(api::v1::Visibility::Private as i32))
                .map(|ids| ids.iter().any(|candidate| candidate == &id))
                .unwrap_or(false);
            assert!(
                !visibility_index_contains,
                "visibility index should not retain deleted id"
            );
        }
    }

    #[tokio::test]
    async fn delete_releases_capacity_for_subsequent_create() {
        let service = MetadataServiceImpl {
            store: MetadataStore::new(1),
            cursor_secret: Arc::new(b"test-cursor-secret".to_vec()),
            cursor_ttl_secs: DEFAULT_CURSOR_TTL_SECS,
            admin_unscoped_list_limit: DEFAULT_ADMIN_UNSCOPED_LIST_LIMIT,
        };

        let created = service
            .create_metadata(authorized_request(
                CreateMetadataRequest {
                    title: "first".to_string(),
                    description: String::new(),
                    tags: vec![],
                    mime_type: "video/mp4".to_string(),
                    file_size: 1,
                    visibility: api::v1::Visibility::Private as i32,
                },
                "owner-1",
                &["user"],
            ))
            .await
            .expect("first create should succeed")
            .into_inner()
            .metadata
            .expect("metadata should be returned");

        let exhausted = service
            .create_metadata(authorized_request(
                CreateMetadataRequest {
                    title: "second".to_string(),
                    description: String::new(),
                    tags: vec![],
                    mime_type: "video/mp4".to_string(),
                    file_size: 1,
                    visibility: api::v1::Visibility::Private as i32,
                },
                "owner-1",
                &["user"],
            ))
            .await
            .expect_err("second create should be capacity-limited");
        assert_eq!(exhausted.code(), tonic::Code::ResourceExhausted);

        service
            .delete_metadata(authorized_request(
                DeleteMetadataRequest {
                    id: created.id.clone(),
                    permanent: false,
                },
                "owner-1",
                &["user"],
            ))
            .await
            .expect("delete should succeed");

        service
            .create_metadata(authorized_request(
                CreateMetadataRequest {
                    title: "third".to_string(),
                    description: String::new(),
                    tags: vec![],
                    mime_type: "video/mp4".to_string(),
                    file_size: 1,
                    visibility: api::v1::Visibility::Private as i32,
                },
                "owner-1",
                &["user"],
            ))
            .await
            .expect("create should succeed again after delete releases capacity");
    }

    #[test]
    fn cursor_round_trip_encodes_and_decodes() {
        let payload = CursorPayload {
            last_created_at_seconds: 10,
            last_created_at_nanos: 20,
            last_id: "id-1".to_string(),
            sort_direction: SortDirection::Asc,
            filter_hash: 42,
            exp_unix: unix_now() + 60,
        };
        let secret = b"test-cursor-secret";

        let encoded = encode_cursor(&payload, secret).expect("cursor should encode");
        let decoded = decode_cursor_with_ttl(&encoded, secret, DEFAULT_CURSOR_TTL_SECS)
            .expect("cursor should decode");

        assert_eq!(
            decoded.last_created_at_seconds,
            payload.last_created_at_seconds
        );
        assert_eq!(decoded.last_created_at_nanos, payload.last_created_at_nanos);
        assert_eq!(decoded.last_id, payload.last_id);
        assert_eq!(decoded.sort_direction, payload.sort_direction);
        assert_eq!(decoded.filter_hash, payload.filter_hash);
        assert_eq!(decoded.exp_unix, payload.exp_unix);
    }

    #[test]
    fn classify_page_token_supports_legacy_and_cursor_tokens() {
        let secret = b"test-cursor-secret";

        match classify_page_token("5", secret, DEFAULT_CURSOR_TTL_SECS)
            .expect("legacy token should parse")
        {
            PageTokenKind::Offset(offset) => assert_eq!(offset, 5),
            _ => panic!("expected legacy offset token"),
        }

        let payload = CursorPayload {
            last_created_at_seconds: 1,
            last_created_at_nanos: 0,
            last_id: "id-1".to_string(),
            sort_direction: SortDirection::Asc,
            filter_hash: 7,
            exp_unix: unix_now() + 60,
        };
        let token = encode_cursor(&payload, secret).expect("cursor should encode");

        match classify_page_token(&token, secret, DEFAULT_CURSOR_TTL_SECS)
            .expect("cursor token should parse")
        {
            PageTokenKind::Cursor(parsed) => assert_eq!(parsed.last_id, "id-1"),
            _ => panic!("expected cursor token"),
        }
    }

    #[test]
    fn classify_page_token_rejects_invalid_cursor_signature() {
        let payload = CursorPayload {
            last_created_at_seconds: 1,
            last_created_at_nanos: 0,
            last_id: "id-1".to_string(),
            sort_direction: SortDirection::Asc,
            filter_hash: 7,
            exp_unix: unix_now() + 60,
        };
        let token = encode_cursor(&payload, b"secret-a").expect("cursor should encode");

        let err = classify_page_token(&token, b"secret-b", DEFAULT_CURSOR_TTL_SECS)
            .expect_err("signature mismatch");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn decode_cursor_rejects_expired_payloads() {
        let payload = CursorPayload {
            last_created_at_seconds: 1,
            last_created_at_nanos: 0,
            last_id: "id-1".to_string(),
            sort_direction: SortDirection::Asc,
            filter_hash: 7,
            exp_unix: unix_now() - 1,
        };
        let token = encode_cursor(&payload, b"secret-a").expect("cursor should encode");

        let err = decode_cursor_with_ttl(&token, b"secret-a", DEFAULT_CURSOR_TTL_SECS)
            .expect_err("expired cursor should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn decode_cursor_rejects_malformed_tokens() {
        let err = decode_cursor_with_ttl("not-a-cursor", b"secret-a", DEFAULT_CURSOR_TTL_SECS)
            .expect_err("cursor without separator should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let err = decode_cursor_with_ttl("abc.%%%", b"secret-a", DEFAULT_CURSOR_TTL_SECS)
            .expect_err("invalid signature encoding should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let invalid_payload = "%%%";
        let mut mac = HmacSha256::new_from_slice(b"secret-a").expect("hmac should construct");
        mac.update(invalid_payload.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let token = format!("{invalid_payload}.{signature}");
        let err = decode_cursor_with_ttl(&token, b"secret-a", DEFAULT_CURSOR_TTL_SECS)
            .expect_err("invalid payload encoding should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let bad_payload = URL_SAFE_NO_PAD.encode("not-json");
        let mut mac = HmacSha256::new_from_slice(b"secret-a").expect("hmac should construct");
        mac.update(bad_payload.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let token = format!("{bad_payload}.{signature}");
        let err = decode_cursor_with_ttl(&token, b"secret-a", DEFAULT_CURSOR_TTL_SECS)
            .expect_err("non-json payload should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let wrong_shape = URL_SAFE_NO_PAD.encode(r#"{"unexpected":"schema"}"#);
        let mut mac = HmacSha256::new_from_slice(b"secret-a").expect("hmac should construct");
        mac.update(wrong_shape.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let token = format!("{wrong_shape}.{signature}");
        let err = decode_cursor_with_ttl(&token, b"secret-a", DEFAULT_CURSOR_TTL_SECS)
            .expect_err("wrong schema payload should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn decode_cursor_rejects_legacy_payloads_without_expiry() {
        let legacy_payload = URL_SAFE_NO_PAD.encode(
            r#"{
              "last_created_at_seconds": 1,
              "last_created_at_nanos": 0,
              "last_id": "legacy-id",
              "sort_direction": "asc",
              "filter_hash": 7
            }"#,
        );
        let mut mac = HmacSha256::new_from_slice(b"secret-a").expect("hmac should construct");
        mac.update(legacy_payload.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let token = format!("{legacy_payload}.{signature}");

        let err = decode_cursor_with_ttl(&token, b"secret-a", DEFAULT_CURSOR_TTL_SECS)
            .expect_err("legacy cursor payload should be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            err.message(),
            "legacy cursor token is no longer supported; restart pagination"
        );
    }

    #[test]
    fn cursor_secret_from_env_uses_debug_fallback_when_enabled() {
        let secret = cursor_secret_from_env(None, true).expect("debug fallback should be allowed");
        assert_eq!(secret, DEFAULT_CURSOR_SECRET.as_bytes());

        let secret = cursor_secret_from_env(Some("configured-secret".to_string()), true)
            .expect("explicit secret should be accepted");
        assert_eq!(secret.as_slice(), b"configured-secret");
    }

    #[test]
    fn cursor_secret_from_env_requires_value_without_debug_fallback() {
        let err = cursor_secret_from_env(None, false).expect_err("release mode should fail fast");
        assert_eq!(err, "CURSOR_SECRET must be set in release builds");
    }

    #[test]
    fn compute_filter_hash_is_bound_to_requester_identity() {
        let req = ListMetadataRequest {
            page_size: 20,
            page_token: String::new(),
            filter_owner_id: "owner-1".to_string(),
            filter_visibility: 0,
            filter_tags: vec!["tag-a".to_string()],
            search_query: "needle".to_string(),
            sort_direction: 0,
        };
        let secret = b"cursor-secret";
        let first = compute_filter_hash(&req, "user-a", secret);
        let second = compute_filter_hash(&req, "user-b", secret);
        assert_ne!(first, second);
    }

    #[test]
    fn compute_filter_hash_canonicalizes_filter_tags() {
        let req_a = ListMetadataRequest {
            page_size: 20,
            page_token: String::new(),
            filter_owner_id: "owner-1".to_string(),
            filter_visibility: 0,
            filter_tags: vec![
                "tag-b".to_string(),
                "tag-a".to_string(),
                "tag-b".to_string(),
            ],
            search_query: "needle".to_string(),
            sort_direction: 0,
        };
        let req_b = ListMetadataRequest {
            filter_tags: vec!["tag-a".to_string(), "tag-b".to_string()],
            ..req_a.clone()
        };
        let secret = b"cursor-secret";

        let hash_a = compute_filter_hash(&req_a, "user-a", secret);
        let hash_b = compute_filter_hash(&req_b, "user-a", secret);
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn requester_identity_accepts_base64_encoded_payload() {
        let request = authorized_request(HealthRequest {}, "user-1", &["admin"]);
        let identity = requester_identity(request.metadata()).expect("identity should parse");
        assert_eq!(identity.sub, "user-1");
        assert!(identity.is_admin);
    }

    #[tokio::test]
    async fn list_metadata_rejects_foreign_owner_filter_for_non_admin() {
        let service = MetadataServiceImpl::default();
        let err = service
            .list_metadata(authorized_request(
                ListMetadataRequest {
                    page_size: 10,
                    page_token: String::new(),
                    filter_owner_id: "other-owner".to_string(),
                    filter_visibility: 0,
                    filter_tags: vec![],
                    search_query: String::new(),
                    sort_direction: 0,
                },
                "caller-owner",
                &["user"],
            ))
            .await
            .expect_err("foreign owner filter should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn admin_unscoped_list_rejected_when_scan_limit_exceeded() {
        let service = MetadataServiceImpl {
            store: MetadataStore::new(8),
            cursor_secret: Arc::new(b"test-cursor-secret".to_vec()),
            cursor_ttl_secs: DEFAULT_CURSOR_TTL_SECS,
            admin_unscoped_list_limit: 2,
        };

        for idx in 0..3 {
            service
                .create_metadata(authorized_request(
                    CreateMetadataRequest {
                        title: format!("admin-scan-{idx}"),
                        description: String::new(),
                        tags: vec![],
                        mime_type: "video/mp4".to_string(),
                        file_size: 1,
                        visibility: api::v1::Visibility::Private as i32,
                    },
                    "owner-a",
                    &["user"],
                ))
                .await
                .expect("create should succeed");
        }

        let err = service
            .list_metadata(authorized_request(
                ListMetadataRequest {
                    page_size: 10,
                    page_token: String::new(),
                    filter_owner_id: String::new(),
                    filter_visibility: 0,
                    filter_tags: vec![],
                    search_query: String::new(),
                    sort_direction: 1,
                },
                "admin-user",
                &["admin"],
            ))
            .await
            .expect_err("admin unscoped list should be rejected above threshold");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }
}
