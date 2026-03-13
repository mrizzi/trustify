use crate::test::caller;
use actix_web::test::TestRequest;
use serde_json::Value;
use urlencoding;
use test_context::test_context;
use test_log::test;
use trustify_module_ingestor::{
    graph::Graph,
    service::{Cache, Format, IngestorService},
};
use trustify_test_context::{TrustifyContext, call::CallService, document_bytes};

async fn ingest_nvidia_aibom(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let graph = Graph::new(ctx.db.clone());
    let data = document_bytes("cyclonedx/ai/nvidia_canary-1b-v2_aibom.json").await?;
    let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());
    ingestor
        .ingest(
            &data,
            Format::CycloneDX,
            [("type", "cyclonedx"), ("kind", "aibom")],
            None,
            Cache::Skip,
        )
        .await?;
    Ok(())
}

async fn ingest_ibm_aibom(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let graph = Graph::new(ctx.db.clone());
    let data =
        document_bytes("cyclonedx/ai/ibm-granite_granite-docling-258M_aibom.json").await?;
    let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());
    ingestor
        .ingest(
            &data,
            Format::CycloneDX,
            [("type", "cyclonedx"), ("kind", "aibom")],
            None,
            Cache::Skip,
        )
        .await?;
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_all_ai_models(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Ingest two AIBOMs
    ingest_nvidia_aibom(ctx).await?;
    ingest_ibm_aibom(ctx).await?;

    let request = TestRequest::get().uri("/api/v2/ai-model").to_request();
    let response: Value = app.call_and_read_body_json(request).await;

    let total = response.get("total").and_then(|v| v.as_u64()).unwrap();
    assert_eq!(total, 2, "expected two AI models across all SBOMs");

    let items = response.get("items").and_then(|v| v.as_array()).unwrap();
    assert_eq!(items.len(), 2);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_ai_models_filter_by_supplier(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ingest_nvidia_aibom(ctx).await?;
    ingest_ibm_aibom(ctx).await?;

    let request = TestRequest::get()
        .uri("/api/v2/ai-model?supplier=nvidia")
        .to_request();
    let response: Value = app.call_and_read_body_json(request).await;

    let total = response.get("total").and_then(|v| v.as_u64()).unwrap();
    assert_eq!(total, 1, "expected one NVIDIA AI model");

    let items = response.get("items").and_then(|v| v.as_array()).unwrap();
    assert_eq!(
        items[0].get("supplier").and_then(|v| v.as_str()),
        Some("nvidia")
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_sbom_ai_models(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ingest_nvidia_aibom(ctx).await?;

    // Find the SBOM ID by listing SBOMs
    let request = TestRequest::get()
        .uri("/api/v2/sbom?q=canary")
        .to_request();
    let response: Value = app.call_and_read_body_json(request).await;

    let sbom_id = response
        .get("items")
        .and_then(|v| v.as_array())
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(|v| v.as_str())
        .expect("should find the SBOM");

    // List AI models for this SBOM
    let uri = format!("/api/v2/sbom/{sbom_id}/ai-models");
    let request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;

    let total = response.get("total").and_then(|v| v.as_u64()).unwrap();
    assert_eq!(total, 1, "expected one AI model in this SBOM");

    let items = response.get("items").and_then(|v| v.as_array()).unwrap();
    let model = &items[0];
    assert_eq!(
        model.get("supplier").and_then(|v| v.as_str()),
        Some("nvidia")
    );
    assert_eq!(
        model.get("modelType").and_then(|v| v.as_str()),
        Some("transformer")
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_ai_model_details(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ingest_nvidia_aibom(ctx).await?;

    // First list AI models to get the IDs
    let request = TestRequest::get().uri("/api/v2/ai-model").to_request();
    let response: Value = app.call_and_read_body_json(request).await;

    let items = response.get("items").and_then(|v| v.as_array()).unwrap();
    let model = &items[0];
    let sbom_id = model.get("sbomId").and_then(|v| v.as_str()).unwrap();
    let node_id = model.get("nodeId").and_then(|v| v.as_str()).unwrap();

    // Get the detail endpoint — URL-encode the node_id as it may contain special chars
    let encoded_node_id = urlencoding::encode(node_id);
    let uri = format!("/api/v2/ai-model/{sbom_id}/{encoded_node_id}");
    let request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;

    assert_eq!(
        response.get("supplier").and_then(|v| v.as_str()),
        Some("nvidia")
    );
    assert_eq!(
        response.get("modelType").and_then(|v| v.as_str()),
        Some("transformer")
    );
    assert_eq!(
        response.get("primaryTask").and_then(|v| v.as_str()),
        Some("text-generation")
    );
    assert!(response.get("properties").is_some());
    assert!(response.get("externalReferences").is_some());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_ai_model_not_found(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let request = TestRequest::get()
        .uri("/api/v2/ai-model/00000000-0000-0000-0000-000000000000/nonexistent-node")
        .to_request();
    let response = app.call_service(request).await;

    assert_eq!(response.status(), 404);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_sbom_ai_models_empty(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Use a random non-existent UUID for the SBOM
    let request = TestRequest::get()
        .uri("/api/v2/sbom/00000000-0000-0000-0000-000000000000/ai-models")
        .to_request();
    let response: Value = app.call_and_read_body_json(request).await;

    let total = response.get("total").and_then(|v| v.as_u64()).unwrap();
    assert_eq!(total, 0, "expected no AI models for non-existent SBOM");

    Ok(())
}
