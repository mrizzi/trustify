use crate::Error;
use fortified_llm_client::{InvokeParams, LlmClient, ResponseFormat};
use sea_orm::{ActiveModelTrait, ConnectionTrait, Set};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use trustify_entity::risk_assessment_criteria;
use uuid::Uuid;

use super::llm_config::LlmConfig;

const SAR_SYSTEM_PROMPT: &str = include_str!("prompts/sar_system.txt");
const SAR_USER_TEMPLATE: &str = include_str!("prompts/sar_user.txt");
const RESPONSE_FORMAT_SCHEMA: &str = include_str!("prompts/response_schema.json");

/// A single recommendation action with priority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub action: String,
    pub priority: String,
}

/// Completeness assessment for a single NIST 800-30 criterion.
#[derive(Debug, Clone, Deserialize)]
pub struct CriterionAssessment {
    pub number: i32,
    pub name: String,
    pub rating: String,
    pub what_documented: Vec<String>,
    pub gaps: Vec<String>,
    pub impact: String,
    pub recommendations: Vec<Recommendation>,
}

/// Risk level with score and NIST level classification.
#[derive(Debug, Clone, Deserialize)]
pub struct RiskLevel {
    pub score: f64,
    pub level: String,
}

/// Risk assessment for a criterion rated partial or missing.
#[derive(Debug, Clone, Deserialize)]
pub struct RiskAssessmentEntry {
    pub criterion_number: i32,
    pub risk_level: RiskLevel,
}

/// Top-level LLM response matching the `response_schema.json` structure.
#[derive(Debug, Clone, Deserialize)]
pub struct SarEvaluationResponse {
    pub criteria_assessments: Vec<CriterionAssessment>,
    pub risk_assessments: Vec<RiskAssessmentEntry>,
    // risk_prioritization is present in the schema but not stored per-criterion.
}

/// Extract text content from a PDF file.
pub async fn extract_text_from_pdf(path: &Path) -> Result<String, Error> {
    let content = fortified_llm_client::extract_text_from_pdf(path)
        .await
        .map_err(|e| Error::Internal(format!("PDF extraction failed: {e}")))?;
    Ok(content.text)
}

/// Build the JSON schema for structured LLM output.
fn sar_response_format() -> ResponseFormat {
    let schema: Value = serde_json::from_str(RESPONSE_FORMAT_SCHEMA)
        .unwrap_or_else(|e| panic!("Invalid response_schema.json: {e}"));

    ResponseFormat::json_schema("sar_evaluation".to_string(), schema, true)
}

/// Evaluate document text against NIST 800-30 criteria using an LLM.
pub async fn evaluate_document(
    config: &LlmConfig,
    document_text: &str,
) -> Result<SarEvaluationResponse, Error> {
    let client = LlmClient::new(config.api_url.clone(), None);

    let user_prompt = SAR_USER_TEMPLATE.replace("{document_text}", document_text);
    let response_format = sar_response_format();

    let params = InvokeParams {
        model: &config.model,
        system_prompt: SAR_SYSTEM_PROMPT,
        user_prompt: &user_prompt,
        temperature: config.temperature,
        max_tokens: config.max_tokens,
        seed: None,
        api_key: config.api_key.as_deref(),
        timeout_secs: config.timeout_secs,
        response_format: Some(&response_format),
    };

    let response_text = client
        .invoke(params)
        .await
        .map_err(|e| Error::Internal(format!("LLM invocation failed: {e}")))?;

    let evaluation: SarEvaluationResponse = serde_json::from_str(&response_text)
        .map_err(|e| Error::Internal(format!("Failed to parse LLM response: {e}")))?;

    Ok(evaluation)
}

/// Convert an underscore-separated risk level (e.g. `very_high`) to title case (e.g. `Very high`).
fn format_risk_level(level: &str) -> String {
    let mut chars = level.replace('_', " ").chars().collect::<Vec<_>>();
    if let Some(first) = chars.first_mut() {
        *first = first.to_uppercase().next().unwrap_or(*first);
    }
    chars.into_iter().collect()
}

/// Persist evaluation results to the risk_assessment_criteria table.
///
/// Joins `criteria_assessments` with `risk_assessments` by criterion number to
/// combine completeness data with risk scores. Criteria rated "complete" that
/// have no corresponding risk assessment receive a default low risk level.
pub async fn store_criteria_results(
    document_id: Uuid,
    evaluation: &SarEvaluationResponse,
    db: &impl ConnectionTrait,
) -> Result<Vec<Uuid>, Error> {
    let mut ids = Vec::with_capacity(evaluation.criteria_assessments.len());

    // Build a lookup of risk assessments by criterion number.
    let risk_map: std::collections::HashMap<i32, &RiskAssessmentEntry> = evaluation
        .risk_assessments
        .iter()
        .map(|r| (r.criterion_number, r))
        .collect();

    for criterion in &evaluation.criteria_assessments {
        let id = Uuid::now_v7();

        // Derive risk level and score from the matching risk assessment entry,
        // falling back to defaults for criteria rated "complete".
        let (risk_level, score) = match risk_map.get(&criterion.number) {
            Some(risk) => (
                format_risk_level(&risk.risk_level.level),
                risk.risk_level.score,
            ),
            None => ("Low".to_string(), 0.0),
        };

        let model = risk_assessment_criteria::ActiveModel {
            id: Set(id),
            document_id: Set(document_id),
            criterion: Set(criterion.name.clone()),
            completeness: Set(criterion.rating.clone()),
            risk_level: Set(risk_level),
            score: Set(score),
            details: Set(None),
            what_documented: Set(Some(serde_json::to_value(&criterion.what_documented)
                .map_err(|e| Error::Internal(format!("Failed to serialize what_documented: {e}")))?)),
            gaps: Set(Some(serde_json::to_value(&criterion.gaps)
                .map_err(|e| Error::Internal(format!("Failed to serialize gaps: {e}")))?)),
            impact_description: Set(Some(criterion.impact.clone())),
            recommendations: Set(Some(serde_json::to_value(&criterion.recommendations)
                .map_err(|e| Error::Internal(format!("Failed to serialize recommendations: {e}")))?)),
        };
        model.insert(db).await?;
        ids.push(id);
    }

    Ok(ids)
}
