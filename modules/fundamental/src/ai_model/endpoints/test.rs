use crate::test::caller;
use actix_http::StatusCode;
use actix_web::test::TestRequest;
use test_context::test_context;
use test_log::test;
use trustify_common::model::PaginatedResults;
use trustify_module_ingestor::service::{Cache, Format, IngestorService};
use trustify_test_context::{TrustifyContext, call::CallService, document_bytes};

use crate::ai_model::model::AiModelSummary;

async fn ingest_nvidia(ctx: &TrustifyContext) {
    let data = document_bytes("cyclonedx/ai/nvidia_canary-1b-v2_aibom.json")
        .await
        .unwrap();
    let ingestor = IngestorService::new(
        trustify_module_ingestor::graph::Graph::new(ctx.db.clone()),
        ctx.storage.clone(),
        Default::default(),
    );
    ingestor
        .ingest(
            &data,
            Format::CycloneDX,
            [("type", "cyclonedx"), ("kind", "aibom")],
            None,
            Cache::Skip,
        )
        .await
        .expect("must ingest");
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_ai_models(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_nvidia(ctx).await;

    let app = caller(ctx).await?;
    let uri = "/api/v2/ai-model";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<AiModelSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(response.total, 1);
    let model = &response.items[0];
    assert_eq!(model.model_type.as_deref(), Some("transformer"));
    assert_eq!(model.primary_task.as_deref(), Some("text-generation"));
    assert_eq!(model.supplier.as_deref(), Some("nvidia"));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_ai_model_not_found(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let uri = format!("/api/v2/ai-model/{}/nonexistent", uuid::Uuid::new_v4());
    let request = TestRequest::get().uri(&uri).to_request();
    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_sbom_ai_models(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Ingest an AIBOM
    let data = document_bytes("cyclonedx/ai/nvidia_canary-1b-v2_aibom.json")
        .await
        .unwrap();
    let ingestor = IngestorService::new(
        trustify_module_ingestor::graph::Graph::new(ctx.db.clone()),
        ctx.storage.clone(),
        Default::default(),
    );
    let result = ingestor
        .ingest(
            &data,
            Format::CycloneDX,
            [("type", "cyclonedx"), ("kind", "aibom")],
            None,
            Cache::Skip,
        )
        .await
        .expect("must ingest");

    let sbom_id = match result.id {
        trustify_common::id::Id::Uuid(id) => id,
        _ => panic!("expected UUID"),
    };

    let app = caller(ctx).await?;
    let uri = format!("/api/v2/sbom/{sbom_id}/ai-models");
    let request = TestRequest::get().uri(&uri).to_request();
    let response: PaginatedResults<AiModelSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(response.total, 1);
    assert_eq!(
        response.items[0].model_type.as_deref(),
        Some("transformer")
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn non_aibom_has_no_ai_models(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Ingest a regular CycloneDX SBOM
    let data = document_bytes("zookeeper-3.9.2-cyclonedx.json")
        .await
        .unwrap();
    let ingestor = IngestorService::new(
        trustify_module_ingestor::graph::Graph::new(ctx.db.clone()),
        ctx.storage.clone(),
        Default::default(),
    );
    let result = ingestor
        .ingest(
            &data,
            Format::CycloneDX,
            ("source", "test"),
            None,
            Cache::Skip,
        )
        .await
        .expect("must ingest");

    let sbom_id = match result.id {
        trustify_common::id::Id::Uuid(id) => id,
        _ => panic!("expected UUID"),
    };

    let app = caller(ctx).await?;
    let uri = format!("/api/v2/sbom/{sbom_id}/ai-models");
    let request = TestRequest::get().uri(&uri).to_request();
    let response: PaginatedResults<AiModelSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(response.total, 0);
    assert!(response.items.is_empty());

    Ok(())
}
