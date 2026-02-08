use main_api::api::v1::metadata_service_server::MetadataService;
use main_api::api::v1::{
    CreateMetadataRequest, DeleteMetadataRequest, GetMetadataRequest, HealthRequest,
    ListMetadataRequest, UpdateMetadataRequest, VideoMetadata, Visibility,
};
use main_api::MetadataServiceImpl;
use prost_types::FieldMask;
use tonic::{Code, Request};

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
        .create_metadata(Request::new(CreateMetadataRequest {
            title: "A title".to_string(),
            description: "desc".to_string(),
            tags: vec!["tag-a".to_string()],
            mime_type: "video/mp4".to_string(),
            file_size: 123,
            visibility: Visibility::Public as i32,
        }))
        .await
        .expect("create should succeed")
        .into_inner();

    let created_metadata = created
        .metadata
        .expect("create response should include metadata");
    let id = created_metadata.id.clone();

    let fetched = service
        .get_metadata(Request::new(GetMetadataRequest { id: id.clone() }))
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
        .update_metadata(Request::new(UpdateMetadataRequest {
            id: id.clone(),
            metadata: Some(VideoMetadata {
                title: "New title".to_string(),
                file_size: 456,
                ..created_metadata.clone()
            }),
            update_mask: Some(FieldMask {
                paths: vec!["title".to_string(), "file_size".to_string()],
            }),
        }))
        .await
        .expect("update should succeed")
        .into_inner();
    let updated_metadata = updated
        .metadata
        .expect("update response should include metadata");
    assert_eq!(updated_metadata.title, "New title");
    assert_eq!(updated_metadata.file_size, 456);

    let listed = service
        .list_metadata(Request::new(ListMetadataRequest {
            page_size: 10,
            page_token: String::new(),
            filter_owner_id: String::new(),
            filter_visibility: 0,
            filter_tags: vec![],
            search_query: "new".to_string(),
        }))
        .await
        .expect("list should succeed")
        .into_inner();
    assert_eq!(listed.total_count, 1);
    assert_eq!(listed.metadata_list.len(), 1);

    service
        .delete_metadata(Request::new(DeleteMetadataRequest {
            id: id.clone(),
            permanent: false,
        }))
        .await
        .expect("delete should succeed");

    let err = service
        .get_metadata(Request::new(GetMetadataRequest { id }))
        .await
        .expect_err("deleted metadata should not be found");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn list_pagination_and_invalid_page_token_are_enforced() {
    let service = MetadataServiceImpl::default();

    for title in ["one", "two", "three"] {
        service
            .create_metadata(Request::new(CreateMetadataRequest {
                title: title.to_string(),
                description: String::new(),
                tags: vec![],
                mime_type: "video/mp4".to_string(),
                file_size: 1,
                visibility: Visibility::Private as i32,
            }))
            .await
            .expect("create should succeed");
    }

    let first_page = service
        .list_metadata(Request::new(ListMetadataRequest {
            page_size: 2,
            page_token: String::new(),
            filter_owner_id: String::new(),
            filter_visibility: 0,
            filter_tags: vec![],
            search_query: String::new(),
        }))
        .await
        .expect("first page should succeed")
        .into_inner();

    assert_eq!(first_page.metadata_list.len(), 2);
    assert_eq!(first_page.total_count, 3);
    assert!(!first_page.next_page_token.is_empty());

    let second_page = service
        .list_metadata(Request::new(ListMetadataRequest {
            page_size: 2,
            page_token: first_page.next_page_token,
            filter_owner_id: String::new(),
            filter_visibility: 0,
            filter_tags: vec![],
            search_query: String::new(),
        }))
        .await
        .expect("second page should succeed")
        .into_inner();

    assert_eq!(second_page.metadata_list.len(), 1);
    assert!(second_page.next_page_token.is_empty());

    let err = service
        .list_metadata(Request::new(ListMetadataRequest {
            page_size: 2,
            page_token: "oops".to_string(),
            filter_owner_id: String::new(),
            filter_visibility: 0,
            filter_tags: vec![],
            search_query: String::new(),
        }))
        .await
        .expect_err("invalid page token should fail");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn update_field_mask_and_missing_records_return_expected_errors() {
    let service = MetadataServiceImpl::default();

    let created = service
        .create_metadata(Request::new(CreateMetadataRequest {
            title: "base".to_string(),
            description: String::new(),
            tags: vec![],
            mime_type: "video/mp4".to_string(),
            file_size: 1,
            visibility: Visibility::Private as i32,
        }))
        .await
        .expect("create should succeed")
        .into_inner();

    let metadata = created.metadata.expect("response should include metadata");
    let err = service
        .update_metadata(Request::new(UpdateMetadataRequest {
            id: metadata.id.clone(),
            metadata: Some(metadata.clone()),
            update_mask: Some(FieldMask {
                paths: vec!["not_supported".to_string()],
            }),
        }))
        .await
        .expect_err("unsupported field should fail");
    assert_eq!(err.code(), Code::InvalidArgument);

    let err = service
        .delete_metadata(Request::new(DeleteMetadataRequest {
            id: "missing-id".to_string(),
            permanent: false,
        }))
        .await
        .expect_err("missing id should fail");
    assert_eq!(err.code(), Code::NotFound);

    let err = service
        .get_metadata(Request::new(GetMetadataRequest { id: String::new() }))
        .await
        .expect_err("empty id should fail");
    assert_eq!(err.code(), Code::InvalidArgument);
}
