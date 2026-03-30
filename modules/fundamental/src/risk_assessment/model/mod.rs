use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RiskAssessment {
    pub id: String,
    pub group_id: String,
    pub status: String,
    pub overall_score: Option<f64>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<trustify_entity::risk_assessment::Model> for RiskAssessment {
    fn from(model: trustify_entity::risk_assessment::Model) -> Self {
        Self {
            id: model.id.to_string(),
            group_id: model.group_id.to_string(),
            status: model.status,
            overall_score: model.overall_score,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateRiskAssessmentRequest {
    pub group_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RiskAssessmentResults {
    pub assessment_id: String,
    pub overall_score: Option<f64>,
    pub categories: Vec<CategoryResult>,
    pub scoring: Option<ScoringResult>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CategoryResult {
    pub category: String,
    pub document_id: String,
    pub processed: bool,
    pub criteria: Vec<CriterionResult>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CriterionResult {
    pub id: String,
    pub criterion: String,
    pub completeness: String,
    pub risk_level: String,
    pub score: f64,
    pub details: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CategoryScore {
    pub category: String,
    pub score: f64,
    pub weight: f64,
    pub weighted_score: f64,
    pub risk_level: String,
    pub criteria_count: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OverallScore {
    pub score: f64,
    pub risk_level: String,
    pub missing_categories: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScoringResult {
    pub overall: OverallScore,
    pub categories: Vec<CategoryScore>,
}
