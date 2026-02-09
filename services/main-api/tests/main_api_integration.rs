use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use main_api::api::v1::metadata_service_server::MetadataService;
use main_api::api::v1::{
    CreateMetadataRequest, DeleteMetadataRequest, GetMetadataRequest, HealthRequest,
    ListMetadataRequest, MetadataSortField, MetadataStatus, Thumbnail, UpdateMetadataRequest,
    VideoMetadata, VideoResolution, VideoStats, Visibility,
};
use main_api::MetadataServiceImpl;
use prost_types::FieldMask;
use serde_json::json;
use tonic::{Code, Request};

const SORT_DIRECTION_UNSPECIFIED: i32 = 0;
const SORT_DIRECTION_ASC: i32 = 1;
const SORT_DIRECTION_DESC: i32 = 2;
const SORT_FIELD_CREATED_AT: i32 = 1;
const METADATA_STATUS_UNSPECIFIED: i32 = 0;
const METADATA_STATUS_READY: i32 = 2;
const METADATA_STATUS_FAILED: i32 = 3;

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

fn tamper_cursor_token(token: &str) -> String {
    let mut chars: Vec<char> = token.chars().collect();
    if let Some(last) = chars.last_mut() {
        *last = if *last == 'A' { 'B' } else { 'A' };
    }
    chars.into_iter().collect()
}

#[tokio::test]
async fn metadata_crud_and_health_happy_path() {
    let service = MetadataServiceImpl::default();

    let health = service
        .health(Request::new(HealthRequest {}))
        .await
        .expect("health should succeed")
        .into_inner();
    assert_eq!(
        health.status,
        main_api::api::v1::health_response::Status::Healthy as i32
    );
    assert!(!health.version.is_empty());
    assert!(health.timestamp.is_some());

    let created = service
        .create_metadata(authorized_request(
            CreateMetadataRequest {
                title: "A title".to_string(),
                description: "desc".to_string(),
                tags: vec!["tag-a".to_string()],
                mime_type: "video/mp4".to_string(),
                file_size: 123,
                visibility: Visibility::Public as i32,
                status: MetadataStatus::Ready as i32,
                resolution: None,
                thumbnails: vec![],
                stats: None,
                custom_metadata: std::collections::HashMap::new(),
            },
            "alice",
            &["user"],
        ))
        .await
        .expect("create should succeed")
        .into_inner();

    let created_metadata = created
        .metadata
        .expect("create response should include metadata");
    let id = created_metadata.id.clone();

    let fetched = service
        .get_metadata(authorized_request(
            GetMetadataRequest { id: id.clone() },
            "alice",
            &["user"],
        ))
        .await
        .expect("get should succeed")
        .into_inner();
    assert_eq!(
        fetched
            .metadata
            .expect("get response should include metadata")
            .title,
        "A title"
    );

    let updated = service
        .update_metadata(authorized_request(
            UpdateMetadataRequest {
                id: id.clone(),
                metadata: Some(VideoMetadata {
                    title: "New title".to_string(),
                    file_size: 456,
                    ..created_metadata.clone()
                }),
                update_mask: Some(FieldMask {
                    paths: vec!["title".to_string(), "file_size".to_string()],
                }),
            },
            "alice",
            &["user"],
        ))
        .await
        .expect("update should succeed")
        .into_inner();
    let updated_metadata = updated
        .metadata
        .expect("update response should include metadata");
    assert_eq!(updated_metadata.title, "New title");
    assert_eq!(updated_metadata.file_size, 456);

    let listed = service
        .list_metadata(authorized_request(
            ListMetadataRequest {
                page_size: 10,
                page_token: String::new(),
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec![],
                search_query: "new".to_string(),
                sort_direction: SORT_DIRECTION_UNSPECIFIED,
                filter_status: MetadataStatus::Ready as i32,
                sort_field: MetadataSortField::CreatedAt as i32,
            },
            "alice",
            &["user"],
        ))
        .await
        .expect("list should succeed")
        .into_inner();
    assert_eq!(listed.total_count, 1);
    assert_eq!(listed.metadata_list.len(), 1);

    service
        .delete_metadata(authorized_request(
            DeleteMetadataRequest {
                id: id.clone(),
                permanent: false,
            },
            "alice",
            &["user"],
        ))
        .await
        .expect("delete should succeed");

    let err = service
        .get_metadata(authorized_request(
            GetMetadataRequest { id },
            "alice",
            &["user"],
        ))
        .await
        .expect_err("deleted metadata should not be found");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn list_pagination_and_invalid_page_token_are_enforced() {
    let service = MetadataServiceImpl::default();

    for title in ["one", "two", "three"] {
        service
            .create_metadata(authorized_request(
                CreateMetadataRequest {
                    title: title.to_string(),
                    description: String::new(),
                    tags: vec![],
                    mime_type: "video/mp4".to_string(),
                    file_size: 1,
                    visibility: Visibility::Private as i32,
                    status: MetadataStatus::Ready as i32,
                    resolution: None,
                    thumbnails: vec![],
                    stats: None,
                    custom_metadata: std::collections::HashMap::new(),
                },
                "alice",
                &["user"],
            ))
            .await
            .expect("create should succeed");
    }

    let first_page = service
        .list_metadata(authorized_request(
            ListMetadataRequest {
                page_size: 2,
                page_token: String::new(),
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec![],
                search_query: String::new(),
                sort_direction: SORT_DIRECTION_UNSPECIFIED,
                filter_status: MetadataStatus::Ready as i32,
                sort_field: MetadataSortField::CreatedAt as i32,
            },
            "alice",
            &["user"],
        ))
        .await
        .expect("first page should succeed")
        .into_inner();

    assert_eq!(first_page.metadata_list.len(), 2);
    assert_eq!(first_page.total_count, 3);
    assert!(first_page.has_exact_count);
    assert!(!first_page.next_page_token.is_empty());

    let second_page = service
        .list_metadata(authorized_request(
            ListMetadataRequest {
                page_size: 2,
                page_token: first_page.next_page_token,
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec![],
                search_query: String::new(),
                sort_direction: SORT_DIRECTION_UNSPECIFIED,
                filter_status: MetadataStatus::Ready as i32,
                sort_field: MetadataSortField::CreatedAt as i32,
            },
            "alice",
            &["user"],
        ))
        .await
        .expect("second page should succeed")
        .into_inner();

    assert_eq!(second_page.metadata_list.len(), 1);
    assert!(!second_page.has_exact_count);
    assert!(second_page.next_page_token.is_empty());

    let err = service
        .list_metadata(authorized_request(
            ListMetadataRequest {
                page_size: 2,
                page_token: "oops".to_string(),
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec![],
                search_query: String::new(),
                sort_direction: SORT_DIRECTION_UNSPECIFIED,
                filter_status: MetadataStatus::Ready as i32,
                sort_field: MetadataSortField::CreatedAt as i32,
            },
            "alice",
            &["user"],
        ))
        .await
        .expect_err("invalid page token should fail");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn update_field_mask_and_missing_records_return_expected_errors() {
    let service = MetadataServiceImpl::default();

    let created = service
        .create_metadata(authorized_request(
            CreateMetadataRequest {
                title: "base".to_string(),
                description: String::new(),
                tags: vec![],
                mime_type: "video/mp4".to_string(),
                file_size: 1,
                visibility: Visibility::Private as i32,
                status: MetadataStatus::Ready as i32,
                resolution: None,
                thumbnails: vec![],
                stats: None,
                custom_metadata: std::collections::HashMap::new(),
            },
            "alice",
            &["user"],
        ))
        .await
        .expect("create should succeed")
        .into_inner();

    let metadata = created.metadata.expect("response should include metadata");
    let err = service
        .update_metadata(authorized_request(
            UpdateMetadataRequest {
                id: metadata.id.clone(),
                metadata: Some(metadata.clone()),
                update_mask: Some(FieldMask {
                    paths: vec!["not_supported".to_string()],
                }),
            },
            "alice",
            &["user"],
        ))
        .await
        .expect_err("unsupported field should fail");
    assert_eq!(err.code(), Code::InvalidArgument);

    let err = service
        .delete_metadata(authorized_request(
            DeleteMetadataRequest {
                id: "missing-id".to_string(),
                permanent: false,
            },
            "alice",
            &["user"],
        ))
        .await
        .expect_err("missing id should fail");
    assert_eq!(err.code(), Code::NotFound);

    let err = service
        .get_metadata(authorized_request(
            GetMetadataRequest { id: String::new() },
            "alice",
            &["user"],
        ))
        .await
        .expect_err("empty id should fail");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn non_admin_cursor_tokens_are_identity_bound() {
    let service = MetadataServiceImpl::default();

    for idx in 0..3 {
        service
            .create_metadata(authorized_request(
                CreateMetadataRequest {
                    title: format!("identity-bound-{idx}"),
                    description: String::new(),
                    tags: vec!["identity".to_string()],
                    mime_type: "video/mp4".to_string(),
                    file_size: 1,
                    visibility: Visibility::Private as i32,
                    status: MetadataStatus::Ready as i32,
                    resolution: None,
                    thumbnails: vec![],
                    stats: None,
                    custom_metadata: std::collections::HashMap::new(),
                },
                "owner-a",
                &["user"],
            ))
            .await
            .expect("create should succeed");
    }

    let first_page = service
        .list_metadata(authorized_request(
            ListMetadataRequest {
                page_size: 2,
                page_token: String::new(),
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec!["identity".to_string()],
                search_query: "identity-bound".to_string(),
                sort_direction: SORT_DIRECTION_ASC,
                filter_status: MetadataStatus::Ready as i32,
                sort_field: MetadataSortField::CreatedAt as i32,
            },
            "owner-a",
            &["user"],
        ))
        .await
        .expect("first page should succeed")
        .into_inner();

    let err = service
        .list_metadata(authorized_request(
            ListMetadataRequest {
                page_size: 2,
                page_token: first_page.next_page_token,
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec!["identity".to_string()],
                search_query: "identity-bound".to_string(),
                sort_direction: SORT_DIRECTION_ASC,
                filter_status: MetadataStatus::Ready as i32,
                sort_field: MetadataSortField::CreatedAt as i32,
            },
            "owner-b",
            &["user"],
        ))
        .await
        .expect_err("cursor should be rejected for a different user");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn tag_filters_use_and_semantics() {
    let service = MetadataServiceImpl::default();

    service
        .create_metadata(authorized_request(
            CreateMetadataRequest {
                title: "both-tags".to_string(),
                description: String::new(),
                tags: vec!["red".to_string(), "blue".to_string()],
                mime_type: "video/mp4".to_string(),
                file_size: 1,
                visibility: Visibility::Private as i32,
                status: MetadataStatus::Ready as i32,
                resolution: None,
                thumbnails: vec![],
                stats: None,
                custom_metadata: std::collections::HashMap::new(),
            },
            "owner-a",
            &["user"],
        ))
        .await
        .expect("first create should succeed");

    service
        .create_metadata(authorized_request(
            CreateMetadataRequest {
                title: "one-tag".to_string(),
                description: String::new(),
                tags: vec!["red".to_string()],
                mime_type: "video/mp4".to_string(),
                file_size: 1,
                visibility: Visibility::Private as i32,
                status: MetadataStatus::Ready as i32,
                resolution: None,
                thumbnails: vec![],
                stats: None,
                custom_metadata: std::collections::HashMap::new(),
            },
            "owner-a",
            &["user"],
        ))
        .await
        .expect("second create should succeed");

    let list = service
        .list_metadata(authorized_request(
            ListMetadataRequest {
                page_size: 10,
                page_token: String::new(),
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec!["red".to_string(), "blue".to_string()],
                search_query: String::new(),
                sort_direction: SORT_DIRECTION_ASC,
                filter_status: MetadataStatus::Ready as i32,
                sort_field: MetadataSortField::CreatedAt as i32,
            },
            "owner-a",
            &["user"],
        ))
        .await
        .expect("list should succeed")
        .into_inner();

    assert_eq!(list.total_count, 1);
    assert_eq!(list.metadata_list.len(), 1);
    assert_eq!(list.metadata_list[0].title, "both-tags");
}

#[tokio::test]
async fn list_supports_descending_sort_direction() {
    let service = MetadataServiceImpl::default();

    for title in ["sort-a", "sort-b", "sort-c"] {
        service
            .create_metadata(authorized_request(
                CreateMetadataRequest {
                    title: title.to_string(),
                    description: String::new(),
                    tags: vec!["sort".to_string()],
                    mime_type: "video/mp4".to_string(),
                    file_size: 1,
                    visibility: Visibility::Private as i32,
                    status: MetadataStatus::Ready as i32,
                    resolution: None,
                    thumbnails: vec![],
                    stats: None,
                    custom_metadata: std::collections::HashMap::new(),
                },
                "sort-owner",
                &["user"],
            ))
            .await
            .expect("create should succeed");
    }

    let ascending = service
        .list_metadata(authorized_request(
            ListMetadataRequest {
                page_size: 10,
                page_token: String::new(),
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec!["sort".to_string()],
                search_query: String::new(),
                sort_direction: SORT_DIRECTION_ASC,
                filter_status: MetadataStatus::Ready as i32,
                sort_field: MetadataSortField::CreatedAt as i32,
            },
            "sort-owner",
            &["user"],
        ))
        .await
        .expect("ascending list should succeed")
        .into_inner();

    let descending = service
        .list_metadata(authorized_request(
            ListMetadataRequest {
                page_size: 10,
                page_token: String::new(),
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec!["sort".to_string()],
                search_query: String::new(),
                sort_direction: SORT_DIRECTION_DESC,
                filter_status: MetadataStatus::Ready as i32,
                sort_field: MetadataSortField::CreatedAt as i32,
            },
            "sort-owner",
            &["user"],
        ))
        .await
        .expect("descending list should succeed")
        .into_inner();

    let ascending_ids: Vec<&str> = ascending
        .metadata_list
        .iter()
        .map(|row| row.id.as_str())
        .collect();
    let descending_ids: Vec<&str> = descending
        .metadata_list
        .iter()
        .map(|row| row.id.as_str())
        .collect();

    let mut reversed = ascending_ids.clone();
    reversed.reverse();
    assert_eq!(descending_ids, reversed);
}

#[tokio::test]
async fn non_owner_requests_are_permission_denied() {
    let service = MetadataServiceImpl::default();

    let created = service
        .create_metadata(authorized_request(
            CreateMetadataRequest {
                title: "owner-only".to_string(),
                description: "private".to_string(),
                tags: vec!["secure".to_string()],
                mime_type: "video/mp4".to_string(),
                file_size: 100,
                visibility: Visibility::Private as i32,
                status: MetadataStatus::Ready as i32,
                resolution: None,
                thumbnails: vec![],
                stats: None,
                custom_metadata: std::collections::HashMap::new(),
            },
            "owner-a",
            &["user"],
        ))
        .await
        .expect("create should succeed")
        .into_inner()
        .metadata
        .expect("metadata should be present");

    let get_err = service
        .get_metadata(authorized_request(
            GetMetadataRequest {
                id: created.id.clone(),
            },
            "owner-b",
            &["user"],
        ))
        .await
        .expect_err("non-owner get should fail");
    assert_eq!(get_err.code(), Code::PermissionDenied);

    let update_err = service
        .update_metadata(authorized_request(
            UpdateMetadataRequest {
                id: created.id.clone(),
                metadata: Some(VideoMetadata {
                    title: "hijacked".to_string(),
                    ..created.clone()
                }),
                update_mask: Some(FieldMask {
                    paths: vec!["title".to_string()],
                }),
            },
            "owner-b",
            &["user"],
        ))
        .await
        .expect_err("non-owner update should fail");
    assert_eq!(update_err.code(), Code::PermissionDenied);

    let delete_err = service
        .delete_metadata(authorized_request(
            DeleteMetadataRequest {
                id: created.id.clone(),
                permanent: false,
            },
            "owner-b",
            &["user"],
        ))
        .await
        .expect_err("non-owner delete should fail");
    assert_eq!(delete_err.code(), Code::PermissionDenied);

    let list_err = service
        .list_metadata(authorized_request(
            ListMetadataRequest {
                page_size: 10,
                page_token: String::new(),
                filter_owner_id: "owner-a".to_string(),
                filter_visibility: 0,
                filter_tags: vec![],
                search_query: String::new(),
                sort_direction: SORT_DIRECTION_ASC,
                filter_status: MetadataStatus::Ready as i32,
                sort_field: MetadataSortField::CreatedAt as i32,
            },
            "owner-b",
            &["user"],
        ))
        .await
        .expect_err("foreign owner filter should fail for non-admin");
    assert_eq!(list_err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn search_query_matches_title_and_description_case_insensitively() {
    let service = MetadataServiceImpl::default();

    for (title, description) in [
        ("Alpha Launch", "first"),
        ("Plain Title", "contains alpha keyword"),
        ("Gamma", "nothing relevant"),
    ] {
        service
            .create_metadata(authorized_request(
                CreateMetadataRequest {
                    title: title.to_string(),
                    description: description.to_string(),
                    tags: vec![],
                    mime_type: "video/mp4".to_string(),
                    file_size: 1,
                    visibility: Visibility::Private as i32,
                    status: MetadataStatus::Ready as i32,
                    resolution: None,
                    thumbnails: vec![],
                    stats: None,
                    custom_metadata: std::collections::HashMap::new(),
                },
                "search-owner",
                &["user"],
            ))
            .await
            .expect("create should succeed");
    }

    let matched = service
        .list_metadata(authorized_request(
            ListMetadataRequest {
                page_size: 20,
                page_token: String::new(),
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec![],
                search_query: "ALPHA".to_string(),
                sort_direction: SORT_DIRECTION_ASC,
                filter_status: MetadataStatus::Ready as i32,
                sort_field: MetadataSortField::CreatedAt as i32,
            },
            "search-owner",
            &["user"],
        ))
        .await
        .expect("search should succeed")
        .into_inner();
    let titles: Vec<&str> = matched
        .metadata_list
        .iter()
        .map(|row| row.title.as_str())
        .collect();
    assert_eq!(matched.total_count, 2);
    assert!(titles.contains(&"Alpha Launch"));
    assert!(titles.contains(&"Plain Title"));

    let empty = service
        .list_metadata(authorized_request(
            ListMetadataRequest {
                page_size: 20,
                page_token: String::new(),
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec![],
                search_query: "does-not-exist".to_string(),
                sort_direction: SORT_DIRECTION_ASC,
                filter_status: MetadataStatus::Ready as i32,
                sort_field: MetadataSortField::CreatedAt as i32,
            },
            "search-owner",
            &["user"],
        ))
        .await
        .expect("search should succeed")
        .into_inner();
    assert_eq!(empty.total_count, 0);
    assert!(empty.metadata_list.is_empty());
}

#[tokio::test]
async fn cursor_tamper_rejection_returns_invalid_argument() {
    let service = MetadataServiceImpl::default();

    for idx in 0..3 {
        service
            .create_metadata(authorized_request(
                CreateMetadataRequest {
                    title: format!("tamper-{idx}"),
                    description: String::new(),
                    tags: vec!["tamper".to_string()],
                    mime_type: "video/mp4".to_string(),
                    file_size: 10,
                    visibility: Visibility::Private as i32,
                    status: METADATA_STATUS_READY,
                    resolution: None,
                    thumbnails: vec![],
                    stats: None,
                    custom_metadata: std::collections::HashMap::new(),
                },
                "tamper-owner",
                &["user"],
            ))
            .await
            .expect("create should succeed");
    }

    let first_page = service
        .list_metadata(authorized_request(
            ListMetadataRequest {
                page_size: 2,
                page_token: String::new(),
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec!["tamper".to_string()],
                search_query: "tamper".to_string(),
                sort_direction: SORT_DIRECTION_ASC,
                filter_status: METADATA_STATUS_UNSPECIFIED,
                sort_field: SORT_FIELD_CREATED_AT,
            },
            "tamper-owner",
            &["user"],
        ))
        .await
        .expect("first page should succeed")
        .into_inner();
    assert!(!first_page.next_page_token.is_empty());

    let err = service
        .list_metadata(authorized_request(
            ListMetadataRequest {
                page_size: 2,
                page_token: tamper_cursor_token(&first_page.next_page_token),
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec!["tamper".to_string()],
                search_query: "tamper".to_string(),
                sort_direction: SORT_DIRECTION_ASC,
                filter_status: METADATA_STATUS_UNSPECIFIED,
                sort_field: SORT_FIELD_CREATED_AT,
            },
            "tamper-owner",
            &["user"],
        ))
        .await
        .expect_err("tampered cursor token should fail");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn cursor_filter_mismatch_rejection_returns_invalid_argument() {
    let service = MetadataServiceImpl::default();

    for idx in 0..3 {
        service
            .create_metadata(authorized_request(
                CreateMetadataRequest {
                    title: format!("filter-mismatch-{idx}"),
                    description: String::new(),
                    tags: vec!["filter-mismatch".to_string()],
                    mime_type: "video/mp4".to_string(),
                    file_size: 10,
                    visibility: Visibility::Private as i32,
                    status: METADATA_STATUS_READY,
                    resolution: None,
                    thumbnails: vec![],
                    stats: None,
                    custom_metadata: std::collections::HashMap::new(),
                },
                "filter-owner",
                &["user"],
            ))
            .await
            .expect("create should succeed");
    }

    let first_page = service
        .list_metadata(authorized_request(
            ListMetadataRequest {
                page_size: 2,
                page_token: String::new(),
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec!["filter-mismatch".to_string()],
                search_query: "filter-mismatch".to_string(),
                sort_direction: SORT_DIRECTION_ASC,
                filter_status: METADATA_STATUS_READY,
                sort_field: SORT_FIELD_CREATED_AT,
            },
            "filter-owner",
            &["user"],
        ))
        .await
        .expect("first page should succeed")
        .into_inner();
    assert!(!first_page.next_page_token.is_empty());

    let err = service
        .list_metadata(authorized_request(
            ListMetadataRequest {
                page_size: 2,
                page_token: first_page.next_page_token,
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec!["filter-mismatch".to_string()],
                search_query: "filter-mismatch".to_string(),
                sort_direction: SORT_DIRECTION_ASC,
                filter_status: METADATA_STATUS_FAILED,
                sort_field: SORT_FIELD_CREATED_AT,
            },
            "filter-owner",
            &["user"],
        ))
        .await
        .expect_err("cursor with changed filters should fail");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn pagination_order_is_stable_for_asc_and_desc_sort_directions() {
    let service = MetadataServiceImpl::default();

    for idx in 0..6 {
        service
            .create_metadata(authorized_request(
                CreateMetadataRequest {
                    title: format!("stable-order-{idx}"),
                    description: String::new(),
                    tags: vec!["stable-order".to_string()],
                    mime_type: "video/mp4".to_string(),
                    file_size: 5,
                    visibility: Visibility::Private as i32,
                    status: METADATA_STATUS_READY,
                    resolution: None,
                    thumbnails: vec![],
                    stats: None,
                    custom_metadata: std::collections::HashMap::new(),
                },
                "stable-owner",
                &["user"],
            ))
            .await
            .expect("create should succeed");
    }

    let mut asc_ids = Vec::new();
    let mut asc_token = String::new();
    loop {
        let page = service
            .list_metadata(authorized_request(
                ListMetadataRequest {
                    page_size: 2,
                    page_token: asc_token,
                    filter_owner_id: String::new(),
                    filter_visibility: 0,
                    filter_tags: vec!["stable-order".to_string()],
                    search_query: "stable-order".to_string(),
                    sort_direction: SORT_DIRECTION_ASC,
                    filter_status: METADATA_STATUS_READY,
                    sort_field: SORT_FIELD_CREATED_AT,
                },
                "stable-owner",
                &["user"],
            ))
            .await
            .expect("ascending page should succeed")
            .into_inner();

        asc_ids.extend(page.metadata_list.iter().map(|row| row.id.clone()));
        if page.next_page_token.is_empty() {
            break;
        }
        asc_token = page.next_page_token;
    }

    let mut desc_ids = Vec::new();
    let mut desc_token = String::new();
    loop {
        let page = service
            .list_metadata(authorized_request(
                ListMetadataRequest {
                    page_size: 2,
                    page_token: desc_token,
                    filter_owner_id: String::new(),
                    filter_visibility: 0,
                    filter_tags: vec!["stable-order".to_string()],
                    search_query: "stable-order".to_string(),
                    sort_direction: SORT_DIRECTION_DESC,
                    filter_status: METADATA_STATUS_READY,
                    sort_field: SORT_FIELD_CREATED_AT,
                },
                "stable-owner",
                &["user"],
            ))
            .await
            .expect("descending page should succeed")
            .into_inner();

        desc_ids.extend(page.metadata_list.iter().map(|row| row.id.clone()));
        if page.next_page_token.is_empty() {
            break;
        }
        desc_token = page.next_page_token;
    }

    assert_eq!(asc_ids.len(), 6);
    assert_eq!(desc_ids.len(), 6);
    let mut reversed = asc_ids.clone();
    reversed.reverse();
    assert_eq!(desc_ids, reversed);
}

#[tokio::test]
async fn expanded_metadata_fields_round_trip_and_list_filters_work() {
    let service = MetadataServiceImpl::default();

    let created = service
        .create_metadata(authorized_request(
            CreateMetadataRequest {
                title: "expanded-fields".to_string(),
                description: "with-status-resolution-thumbnail-stats".to_string(),
                tags: vec!["expanded".to_string()],
                mime_type: "video/mp4".to_string(),
                file_size: 500,
                visibility: Visibility::Private as i32,
                status: MetadataStatus::Ready as i32,
                resolution: Some(VideoResolution {
                    width: 1920,
                    height: 1080,
                }),
                thumbnails: vec![Thumbnail {
                    uri: "https://cdn.example/thumb-1.jpg".to_string(),
                    width: 320,
                    height: 180,
                }],
                stats: Some(VideoStats {
                    view_count: 10,
                    like_count: 5,
                    comment_count: 2,
                }),
                custom_metadata: std::collections::HashMap::from([(
                    "source".to_string(),
                    "camera-a".to_string(),
                )]),
            },
            "expanded-owner",
            &["user"],
        ))
        .await
        .expect("create should succeed")
        .into_inner();

    let created_metadata = created.metadata.expect("metadata should be present");
    assert_eq!(created_metadata.status, MetadataStatus::Ready as i32);
    assert_eq!(
        created_metadata
            .resolution
            .as_ref()
            .map(|resolution| resolution.width),
        Some(1920)
    );
    assert_eq!(created_metadata.thumbnails.len(), 1);
    assert_eq!(
        created_metadata
            .stats
            .as_ref()
            .map(|stats| stats.view_count),
        Some(10)
    );
    assert_eq!(
        created_metadata.custom_metadata.get("source"),
        Some(&"camera-a".to_string())
    );

    let updated = service
        .update_metadata(authorized_request(
            UpdateMetadataRequest {
                id: created_metadata.id.clone(),
                metadata: Some(VideoMetadata {
                    status: MetadataStatus::Failed as i32,
                    stats: Some(VideoStats {
                        view_count: 42,
                        like_count: 11,
                        comment_count: 3,
                    }),
                    custom_metadata: std::collections::HashMap::from([
                        ("source".to_string(), "camera-b".to_string()),
                        ("pipeline".to_string(), "transcode-v2".to_string()),
                    ]),
                    ..created_metadata.clone()
                }),
                update_mask: Some(FieldMask {
                    paths: vec![
                        "status".to_string(),
                        "stats".to_string(),
                        "custom_metadata".to_string(),
                    ],
                }),
            },
            "expanded-owner",
            &["user"],
        ))
        .await
        .expect("update should succeed")
        .into_inner();

    let updated_metadata = updated.metadata.expect("metadata should be present");
    assert_eq!(updated_metadata.status, MetadataStatus::Failed as i32);
    assert_eq!(
        updated_metadata
            .stats
            .as_ref()
            .map(|stats| stats.view_count),
        Some(42)
    );
    assert_eq!(
        updated_metadata.custom_metadata.get("pipeline"),
        Some(&"transcode-v2".to_string())
    );

    for (title, file_size, status) in [
        ("ready-small", 100_i64, MetadataStatus::Ready as i32),
        ("ready-large", 900_i64, MetadataStatus::Ready as i32),
        ("failed-medium", 400_i64, MetadataStatus::Failed as i32),
    ] {
        service
            .create_metadata(authorized_request(
                CreateMetadataRequest {
                    title: title.to_string(),
                    description: "list-probe".to_string(),
                    tags: vec!["expanded".to_string()],
                    mime_type: "video/mp4".to_string(),
                    file_size,
                    visibility: Visibility::Private as i32,
                    status,
                    resolution: None,
                    thumbnails: vec![],
                    stats: None,
                    custom_metadata: std::collections::HashMap::new(),
                },
                "expanded-owner",
                &["user"],
            ))
            .await
            .expect("create should succeed");
    }

    let listed_ready = service
        .list_metadata(authorized_request(
            ListMetadataRequest {
                page_size: 10,
                page_token: String::new(),
                filter_owner_id: String::new(),
                filter_visibility: 0,
                filter_tags: vec!["expanded".to_string()],
                search_query: String::new(),
                sort_direction: SORT_DIRECTION_DESC,
                filter_status: MetadataStatus::Ready as i32,
                sort_field: MetadataSortField::FileSize as i32,
            },
            "expanded-owner",
            &["user"],
        ))
        .await
        .expect("list should succeed")
        .into_inner();

    assert!(listed_ready.metadata_list.len() >= 2);
    assert!(listed_ready
        .metadata_list
        .iter()
        .all(|row| row.status == MetadataStatus::Ready as i32));
    let sizes: Vec<i64> = listed_ready
        .metadata_list
        .iter()
        .map(|row| row.file_size)
        .collect();
    let mut expected = sizes.clone();
    expected.sort_unstable_by(|left, right| right.cmp(left));
    assert_eq!(sizes, expected);

    let fetched = service
        .get_metadata(authorized_request(
            GetMetadataRequest {
                id: created_metadata.id,
            },
            "expanded-owner",
            &["user"],
        ))
        .await
        .expect("get should succeed")
        .into_inner()
        .metadata
        .expect("metadata should be present");
    assert_eq!(fetched.status, MetadataStatus::Failed as i32);
    assert_eq!(
        fetched.custom_metadata.get("source"),
        Some(&"camera-b".to_string())
    );
}
