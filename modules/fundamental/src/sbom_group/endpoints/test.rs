use crate::test::caller;
use actix_http::StatusCode;
use actix_web::test::TestRequest;
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyContext, call::CallService};

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_create_root_group(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let req = TestRequest::post()
        .uri("/api/v2/group/sbom")
        .set_json(json!({
            "name": "Production",
            "labels": {
                "env": "prod"
            }
        }))
        .to_request();

    let response = app.call_service(req).await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let body: Value = actix_web::test::read_body_json(response).await;
    assert_eq!(body["name"], "Production");
    assert_eq!(body["labels"]["env"], "prod");

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_create_child_group(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // Create parent
    let req = TestRequest::post()
        .uri("/api/v2/group/sbom")
        .set_json(json!({"name": "Parent"}))
        .to_request();

    let parent: Value = app.call_and_read_body_json(req).await;
    let parent_id = parent["id"].as_str().unwrap();

    // Create child
    let req = TestRequest::post()
        .uri("/api/v2/group/sbom")
        .set_json(json!({
            "name": "Child",
            "parent": parent_id
        }))
        .to_request();

    let response = app.call_service(req).await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let child: Value = actix_web::test::read_body_json(response).await;
    assert_eq!(child["name"], "Child");
    assert_eq!(child["parent"], parent_id);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_get_group_with_etag(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // Create group
    let req = TestRequest::post()
        .uri("/api/v2/group/sbom")
        .set_json(json!({"name": "TestGroup"}))
        .to_request();

    let group: Value = app.call_and_read_body_json(req).await;
    let group_id = group["id"].as_str().unwrap();

    // Get group
    let req = TestRequest::get()
        .uri(&format!("/api/v2/group/sbom/{}", group_id))
        .to_request();

    let response = app.call_service(req).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("etag"));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_list_groups(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // Create multiple groups
    for name in ["Group1", "Group2"] {
        let req = TestRequest::post()
            .uri("/api/v2/group/sbom")
            .set_json(json!({"name": name}))
            .to_request();
        let response = app.call_service(req).await;
        let status = response.status();
        // Debug: print status if not 201
        if status != StatusCode::CREATED {
            let body: Value = actix_web::test::read_body_json(response).await;
            panic!(
                "Failed to create group {}: status={:?}, body={:?}",
                name, status, body
            );
        }
    }

    // List groups
    let req = TestRequest::get().uri("/api/v2/group/sbom").to_request();

    let response = app.call_service(req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let result: Value = actix_web::test::read_body_json(response).await;
    println!("List result: {:?}", result);
    assert!(result["items"].as_array().unwrap().len() >= 2);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_path_lookup(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // Create parent
    let req = TestRequest::post()
        .uri("/api/v2/group/sbom")
        .set_json(json!({"name": "A"}))
        .to_request();

    let parent: Value = app.call_and_read_body_json(req).await;
    let parent_id = parent["id"].as_str().unwrap();

    // Create child
    let req = TestRequest::post()
        .uri("/api/v2/group/sbom")
        .set_json(json!({
            "name": "B",
            "parent": parent_id
        }))
        .to_request();

    app.call_service(req).await;

    // Lookup by path
    let req = TestRequest::get()
        .uri("/api/v2/group/sbom-by-path/A/B")
        .to_request();

    let response = app.call_service(req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let group: Value = actix_web::test::read_body_json(response).await;
    assert_eq!(group["name"], "B");

    Ok(())
}
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_update_with_if_match(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // Create group
    let req = TestRequest::post()
        .uri("/api/v2/group/sbom")
        .set_json(json!({"name": "TestGroup"}))
        .to_request();

    let group: Value = app.call_and_read_body_json(req).await;
    let group_id = group["id"].as_str().unwrap();
    let revision = group["revision"].as_i64().unwrap();

    // Update with correct If-Match
    let req = TestRequest::put()
        .uri(&format!("/api/v2/group/sbom/{}", group_id))
        .insert_header(("If-Match", format!("\"{}\"", revision)))
        .set_json(json!({"name": "UpdatedGroup"}))
        .to_request();

    let response = app.call_service(req).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify update
    let req = TestRequest::get()
        .uri(&format!("/api/v2/group/sbom/{}", group_id))
        .to_request();

    let updated: Value = app.call_and_read_body_json(req).await;
    assert_eq!(updated["name"], "UpdatedGroup");
    assert_eq!(updated["revision"], 2);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_update_with_wrong_if_match(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // Create group
    let req = TestRequest::post()
        .uri("/api/v2/group/sbom")
        .set_json(json!({"name": "TestGroup"}))
        .to_request();

    let group: Value = app.call_and_read_body_json(req).await;
    let group_id = group["id"].as_str().unwrap();

    // Update with wrong If-Match
    let req = TestRequest::put()
        .uri(&format!("/api/v2/group/sbom/{}", group_id))
        .insert_header(("If-Match", "\"999\""))
        .set_json(json!({"name": "UpdatedGroup"}))
        .to_request();

    let response = app.call_service(req).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_delete_with_if_match(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // Create group
    let req = TestRequest::post()
        .uri("/api/v2/group/sbom")
        .set_json(json!({"name": "TestGroup"}))
        .to_request();

    let group: Value = app.call_and_read_body_json(req).await;
    let group_id = group["id"].as_str().unwrap();
    let revision = group["revision"].as_i64().unwrap();

    // Delete with correct If-Match
    let req = TestRequest::delete()
        .uri(&format!("/api/v2/group/sbom/{}", group_id))
        .insert_header(("If-Match", format!("\"{}\"", revision)))
        .to_request();

    let response = app.call_service(req).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_delete_group_with_children(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // Create parent
    let req = TestRequest::post()
        .uri("/api/v2/group/sbom")
        .set_json(json!({"name": "Parent"}))
        .to_request();

    let parent: Value = app.call_and_read_body_json(req).await;
    let parent_id = parent["id"].as_str().unwrap();

    // Create child
    let req = TestRequest::post()
        .uri("/api/v2/group/sbom")
        .set_json(json!({"name": "Child", "parent": parent_id}))
        .to_request();

    app.call_service(req).await;

    // Try to delete parent (should fail)
    let req = TestRequest::delete()
        .uri(&format!("/api/v2/group/sbom/{}", parent_id))
        .to_request();

    let response = app.call_service(req).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_cycle_detection(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // Create A -> B -> C hierarchy
    let req = TestRequest::post()
        .uri("/api/v2/group/sbom")
        .set_json(json!({"name": "A"}))
        .to_request();
    let a: Value = app.call_and_read_body_json(req).await;
    let a_id = a["id"].as_str().unwrap();

    let req = TestRequest::post()
        .uri("/api/v2/group/sbom")
        .set_json(json!({"name": "B", "parent": a_id}))
        .to_request();
    let b: Value = app.call_and_read_body_json(req).await;
    let b_id = b["id"].as_str().unwrap();

    let req = TestRequest::post()
        .uri("/api/v2/group/sbom")
        .set_json(json!({"name": "C", "parent": b_id}))
        .to_request();
    let c: Value = app.call_and_read_body_json(req).await;
    let c_id = c["id"].as_str().unwrap();

    // Try to set A as parent of C (would create cycle C -> A -> B -> C)
    let req = TestRequest::put()
        .uri(&format!("/api/v2/group/sbom/{}", a_id))
        .insert_header(("If-Match", "\"1\""))
        .set_json(json!({"name": "A", "parent": c_id}))
        .to_request();

    let response = app.call_service(req).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_deep_path(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // Create a deep hierarchy (10 levels)
    let mut parent_id: Option<String> = None;
    for i in 0..10 {
        let req = TestRequest::post()
            .uri("/api/v2/group/sbom")
            .set_json(if let Some(pid) = &parent_id {
                json!({"name": format!("Level{}", i), "parent": pid})
            } else {
                json!({"name": format!("Level{}", i)})
            })
            .to_request();

        let group: Value = app.call_and_read_body_json(req).await;
        parent_id = Some(group["id"].as_str().unwrap().to_string());
    }

    // Construct path
    let path = (0..10)
        .map(|i| format!("Level{}", i))
        .collect::<Vec<_>>()
        .join("/");

    // Lookup by path
    let req = TestRequest::get()
        .uri(&format!("/api/v2/group/sbom-by-path/{}", path))
        .to_request();

    let response = app.call_service(req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let group: Value = actix_web::test::read_body_json(response).await;
    assert_eq!(group["name"], "Level9");

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_path_too_deep(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // Create a hierarchy that exceeds max depth (21 levels)
    let mut parent_id: Option<String> = None;
    for i in 0..21 {
        let req = TestRequest::post()
            .uri("/api/v2/group/sbom")
            .set_json(if let Some(pid) = &parent_id {
                json!({"name": format!("Level{}", i), "parent": pid})
            } else {
                json!({"name": format!("Level{}", i)})
            })
            .to_request();

        let group: Value = app.call_and_read_body_json(req).await;
        parent_id = Some(group["id"].as_str().unwrap().to_string());
    }

    // Construct path that's too deep
    let path = (0..21)
        .map(|i| format!("Level{}", i))
        .collect::<Vec<_>>()
        .join("/");

    // Lookup by path (should fail)
    let req = TestRequest::get()
        .uri(&format!("/api/v2/group/sbom-by-path/{}", path))
        .to_request();

    let response = app.call_service(req).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    Ok(())
}
