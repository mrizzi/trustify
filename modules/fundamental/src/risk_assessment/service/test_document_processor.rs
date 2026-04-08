use crate::risk_assessment::service::RiskAssessmentService;
use crate::risk_assessment::service::document_processor::{
    CriterionAssessment, Recommendation, RiskAssessmentEntry, RiskLevel, SarEvaluationResponse,
    store_criteria_results,
};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement, TransactionTrait};
use test_context::test_context;
use test_log::test;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_processing_disabled_without_env(_ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    temp_env::with_vars_unset(["TRUSTD_LLM_API_URL", "TRUSTD_LLM_MODEL"], || {
        let service = RiskAssessmentService::new();
        assert!(!service.processing_enabled());
    });
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_processing_enabled_with_env(_ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    temp_env::with_vars(
        [
            (
                "TRUSTD_LLM_API_URL",
                Some("http://localhost:11434/v1/chat/completions"),
            ),
            ("TRUSTD_LLM_MODEL", Some("llama3")),
        ],
        || {
            let service = RiskAssessmentService::new();
            assert!(service.processing_enabled());
        },
    );
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_store_criteria_results(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let db = &ctx.db;
    let tx = db.begin().await?;

    // Create a risk assessment and document for the test
    let service = RiskAssessmentService::new();
    let group_id = create_test_group(&tx).await?;

    let assessment_id = service
        .create(
            crate::risk_assessment::model::CreateRiskAssessmentRequest {
                group_id: group_id.clone(),
            },
            &tx,
        )
        .await?;

    let digests = trustify_common::hashing::Digests::digest("test pdf content");
    let doc_id = service
        .upload_document(&assessment_id, "sar", &digests, 16, &tx)
        .await?;

    let doc_uuid = uuid::Uuid::parse_str(&doc_id)?;

    // Build a mock evaluation response using the new schema structure
    let criteria_assessments = vec![
        CriterionAssessment {
            number: 1,
            name: "Threat identification".to_string(),
            rating: "complete".to_string(),
            what_documented: vec!["Threats are well identified".to_string()],
            gaps: vec![],
            impact: "No significant impact".to_string(),
            recommendations: vec![],
        },
        CriterionAssessment {
            number: 2,
            name: "Vulnerability identification".to_string(),
            rating: "partial".to_string(),
            what_documented: vec!["Some vulnerabilities documented".to_string()],
            gaps: vec!["Missing network vulnerability analysis".to_string()],
            impact: "Moderate impact on risk characterization".to_string(),
            recommendations: vec![Recommendation {
                action: "Add network vulnerability scan results".to_string(),
                priority: "high".to_string(),
            }],
        },
    ];

    // Only partial/missing criteria get risk assessments
    let risk_assessments = vec![RiskAssessmentEntry {
        criterion_number: 2,
        risk_level: RiskLevel {
            score: 6.0,
            level: "moderate".to_string(),
        },
    }];

    let evaluation = SarEvaluationResponse {
        criteria_assessments,
        risk_assessments,
        risk_prioritization: None,
    };

    // Store and verify
    let ids = store_criteria_results(doc_uuid, &evaluation, &tx).await?;
    assert_eq!(ids.len(), 2);

    // Verify results are retrievable
    let results = service.get_results(&assessment_id, &tx).await?;
    assert!(results.is_some());
    let results = results.unwrap();
    assert_eq!(results.categories.len(), 1);
    assert_eq!(results.categories[0].criteria.len(), 2);

    // Verify complete criterion gets default low risk
    let threat = results.categories[0]
        .criteria
        .iter()
        .find(|c| c.criterion == "Threat identification");
    assert!(threat.is_some());
    let threat = threat.unwrap();
    assert_eq!(threat.completeness, "complete");
    assert_eq!(threat.risk_level, "Low");
    assert!((threat.score - 0.0).abs() < f64::EPSILON);

    // Verify partial criterion gets risk from risk_assessments
    let vuln = results.categories[0]
        .criteria
        .iter()
        .find(|c| c.criterion == "Vulnerability identification");
    assert!(vuln.is_some());
    let vuln = vuln.unwrap();
    assert_eq!(vuln.completeness, "partial");
    assert_eq!(vuln.risk_level, "Moderate");
    assert!((vuln.score - 6.0).abs() < f64::EPSILON);

    tx.rollback().await?;
    Ok(())
}

async fn create_test_group(db: &impl ConnectionTrait) -> Result<String, anyhow::Error> {
    let group_id = uuid::Uuid::now_v7();
    let revision = uuid::Uuid::now_v7();
    db.execute(Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        "INSERT INTO sbom_group (id, name, revision, labels) VALUES ($1, $2, $3, $4)",
        [
            group_id.into(),
            "test-group".into(),
            revision.into(),
            serde_json::json!({}).into(),
        ],
    ))
    .await?;
    Ok(group_id.to_string())
}
