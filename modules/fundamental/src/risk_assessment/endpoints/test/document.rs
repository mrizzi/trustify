use crate::test::caller;
use actix_http::body::to_bytes;
use actix_web::{http::StatusCode, test::TestRequest};
use serde_json::{Value, json};
use test_context::test_context;
use trustify_test_context::{TrustifyContext, call::CallService};

/// Helper to create a group
async fn create_group(app: &impl CallService) -> anyhow::Result<String> {
    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v2/group/sbom")
                .set_json(json!({"name": "test-group-for-doc-upload"}))
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = to_bytes(response.into_body()).await.expect("must decode");
    let result: Value = serde_json::from_slice(&body)?;
    Ok(result["id"].as_str().unwrap().to_string())
}

/// Helper to create a risk assessment
async fn create_assessment(app: &impl CallService, group_id: &str) -> anyhow::Result<String> {
    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v2/risk-assessment")
                .set_json(json!({"groupId": group_id}))
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = to_bytes(response.into_body()).await.expect("must decode");
    let result: Value = serde_json::from_slice(&body)?;
    Ok(result["id"].as_str().unwrap().to_string())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn upload_and_download_document(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let group_id = create_group(&app).await?;
    let assessment_id = create_assessment(&app, &group_id).await?;

    let pdf_content = b"fake PDF content for testing";

    // Upload document
    let response = app
        .call_service(
            TestRequest::post()
                .uri(&format!(
                    "/api/v2/risk-assessment/{}/document/supply-chain",
                    assessment_id
                ))
                .set_payload(pdf_content.to_vec())
                .insert_header(("content-type", "application/octet-stream"))
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = to_bytes(response.into_body()).await.expect("must decode");
    let result: Value = serde_json::from_slice(&body)?;
    assert!(result["id"].as_str().is_some());

    // Download document
    let response = app
        .call_service(
            TestRequest::get()
                .uri(&format!(
                    "/api/v2/risk-assessment/{}/document/supply-chain",
                    assessment_id
                ))
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body()).await.expect("must decode");
    assert_eq!(body.as_ref(), pdf_content);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn download_document_not_found(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let group_id = create_group(&app).await?;
    let assessment_id = create_assessment(&app, &group_id).await?;

    let response = app
        .call_service(
            TestRequest::get()
                .uri(&format!(
                    "/api/v2/risk-assessment/{}/document/nonexistent",
                    assessment_id
                ))
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}
