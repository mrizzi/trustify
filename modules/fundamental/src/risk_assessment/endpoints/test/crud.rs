use crate::test::caller;
use actix_http::body::to_bytes;
use actix_web::{http::StatusCode, test::TestRequest};
use serde_json::{Value, json};
use test_context::test_context;
use trustify_test_context::{TrustifyContext, call::CallService};

/// Helper to create an SBOM group and return its ID
async fn create_group(app: &impl CallService) -> anyhow::Result<String> {
    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v2/group/sbom")
                .set_json(json!({"name": "test-group-for-risk-assessment"}))
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = to_bytes(response.into_body()).await.expect("must decode");
    let result: Value = serde_json::from_slice(&body)?;
    Ok(result["id"].as_str().unwrap().to_string())
}

/// Helper to create a risk assessment for a group
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
async fn create_risk_assessment(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let group_id = create_group(&app).await?;

    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v2/risk-assessment")
                .set_json(json!({"groupId": &group_id}))
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = to_bytes(response.into_body()).await.expect("must decode");
    let result: Value = serde_json::from_slice(&body)?;
    assert!(result["id"].as_str().is_some());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn create_risk_assessment_invalid_group(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v2/risk-assessment")
                .set_json(json!({"groupId": "00000000-0000-0000-0000-000000000000"}))
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn read_risk_assessment(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let group_id = create_group(&app).await?;
    let assessment_id = create_assessment(&app, &group_id).await?;

    let response = app
        .call_service(
            TestRequest::get()
                .uri(&format!("/api/v2/risk-assessment/{}", assessment_id))
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body()).await.expect("must decode");
    let result: Value = serde_json::from_slice(&body)?;
    assert_eq!(result["id"].as_str(), Some(assessment_id.as_str()));
    assert_eq!(result["groupId"].as_str(), Some(group_id.as_str()));
    assert_eq!(result["status"].as_str(), Some("pending"));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn read_risk_assessment_not_found(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let response = app
        .call_service(
            TestRequest::get()
                .uri("/api/v2/risk-assessment/00000000-0000-0000-0000-000000000000")
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn list_by_group(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let group_id = create_group(&app).await?;

    // Create two assessments for the same group
    create_assessment(&app, &group_id).await?;
    create_assessment(&app, &group_id).await?;

    let response = app
        .call_service(
            TestRequest::get()
                .uri(&format!("/api/v2/risk-assessment/group/{}", group_id))
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body()).await.expect("must decode");
    let result: Value = serde_json::from_slice(&body)?;
    let assessments = result.as_array().expect("must be array");
    assert_eq!(assessments.len(), 2);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn delete_risk_assessment(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let group_id = create_group(&app).await?;
    let assessment_id = create_assessment(&app, &group_id).await?;

    // Delete
    let response = app
        .call_service(
            TestRequest::delete()
                .uri(&format!("/api/v2/risk-assessment/{}", assessment_id))
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify it's gone
    let response = app
        .call_service(
            TestRequest::get()
                .uri(&format!("/api/v2/risk-assessment/{}", assessment_id))
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn get_results_empty(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let group_id = create_group(&app).await?;
    let assessment_id = create_assessment(&app, &group_id).await?;

    let response = app
        .call_service(
            TestRequest::get()
                .uri(&format!(
                    "/api/v2/risk-assessment/{}/results",
                    assessment_id
                ))
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body()).await.expect("must decode");
    let result: Value = serde_json::from_slice(&body)?;
    assert_eq!(
        result["assessmentId"].as_str(),
        Some(assessment_id.as_str())
    );
    assert!(result["categories"].as_array().unwrap().is_empty());

    Ok(())
}
