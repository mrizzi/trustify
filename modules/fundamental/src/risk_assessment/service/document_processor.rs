use crate::Error;
use fortified_llm_client::{InvokeParams, LlmClient, ResponseFormat};
use sea_orm::{ActiveModelTrait, ConnectionTrait, Set};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use trustify_entity::risk_assessment_criteria;
use uuid::Uuid;

use super::llm_config::LlmConfig;

const SAR_SYSTEM_PROMPT: &str = include_str!("prompts/sar_system.txt");
const SAR_USER_TEMPLATE: &str = include_str!("prompts/sar_user.txt");

/// Result of evaluating a single NIST 800-30 criterion.
#[derive(Debug, Clone, Deserialize)]
pub struct CriterionEvaluation {
    pub completeness: String,
    pub risk_level: String,
    pub score: f64,
    pub details: Option<serde_json::Value>,
}

/// LLM response containing per-criterion evaluations.
#[derive(Debug, Clone, Deserialize)]
pub struct SarEvaluationResponse {
    pub criteria: HashMap<String, CriterionEvaluation>,
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
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "criteria": {
                "type": "object",
                "properties": {
                    "threat_identification": { "$ref": "#/$defs/criterion" },
                    "vulnerability_identification": { "$ref": "#/$defs/criterion" },
                    "likelihood_assessment": { "$ref": "#/$defs/criterion" },
                    "impact_analysis": { "$ref": "#/$defs/criterion" },
                    "risk_determination": { "$ref": "#/$defs/criterion" },
                    "security_controls": { "$ref": "#/$defs/criterion" },
                    "risk_mitigation": { "$ref": "#/$defs/criterion" }
                },
                "required": [
                    "threat_identification",
                    "vulnerability_identification",
                    "likelihood_assessment",
                    "impact_analysis",
                    "risk_determination",
                    "security_controls",
                    "risk_mitigation"
                ],
                "additionalProperties": false
            }
        },
        "required": ["criteria"],
        "additionalProperties": false,
        "$defs": {
            "criterion": {
                "type": "object",
                "properties": {
                    "completeness": {
                        "type": "string",
                        "enum": ["complete", "partial", "missing"]
                    },
                    "risk_level": {
                        "type": "string",
                        "enum": ["low", "moderate", "high", "critical"]
                    },
                    "score": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0
                    },
                    "details": {
                        "type": "object",
                        "properties": {
                            "summary": { "type": "string" }
                        },
                        "required": ["summary"],
                        "additionalProperties": false
                    }
                },
                "required": ["completeness", "risk_level", "score", "details"],
                "additionalProperties": false
            }
        }
    });

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

/// Persist evaluation results to the risk_assessment_criteria table.
pub async fn store_criteria_results(
    document_id: Uuid,
    evaluation: &SarEvaluationResponse,
    db: &impl ConnectionTrait,
) -> Result<Vec<Uuid>, Error> {
    let mut ids = Vec::with_capacity(evaluation.criteria.len());

    for (criterion_name, result) in &evaluation.criteria {
        let id = Uuid::now_v7();
        let model = risk_assessment_criteria::ActiveModel {
            id: Set(id),
            document_id: Set(document_id),
            criterion: Set(criterion_name.clone()),
            completeness: Set(result.completeness.clone()),
            risk_level: Set(result.risk_level.clone()),
            score: Set(result.score),
            details: Set(result.details.clone()),
        };
        model.insert(db).await?;
        ids.push(id);
    }

    Ok(ids)
}
