use crate::Error;
use crate::risk_assessment::model::*;
use hex::ToHex;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, Set, query::QueryFilter,
};
use time::OffsetDateTime;
use trustify_common::{db::DatabaseErrors, hashing::Digests};
use trustify_entity::{
    risk_assessment, risk_assessment_criteria, risk_assessment_document, source_document,
};
use uuid::Uuid;

pub struct RiskAssessmentService;

impl RiskAssessmentService {
    pub fn new() -> Self {
        Self
    }

    pub async fn create(
        &self,
        request: CreateRiskAssessmentRequest,
        db: &impl ConnectionTrait,
    ) -> Result<String, Error> {
        let group_id = Uuid::parse_str(&request.group_id)
            .map_err(|_| Error::BadRequest("Invalid group_id".into(), None))?;

        let id = Uuid::now_v7();
        let now = OffsetDateTime::now_utc();

        let model = risk_assessment::ActiveModel {
            id: Set(id),
            group_id: Set(group_id),
            status: Set("pending".to_string()),
            overall_score: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        };

        model.insert(db).await.map_err(|err| {
            if err.is_foreign_key_violation() {
                Error::BadRequest("Group does not exist".into(), None)
            } else {
                err.into()
            }
        })?;

        Ok(id.to_string())
    }

    pub async fn read(
        &self,
        id: &str,
        db: &impl ConnectionTrait,
    ) -> Result<Option<RiskAssessment>, Error> {
        let uuid = Uuid::parse_str(id)
            .map_err(|_| Error::BadRequest("Invalid assessment ID".into(), None))?;

        let result = risk_assessment::Entity::find_by_id(uuid).one(db).await?;

        Ok(result.map(RiskAssessment::from))
    }

    pub async fn list_by_group(
        &self,
        group_id: &str,
        db: &impl ConnectionTrait,
    ) -> Result<Vec<RiskAssessment>, Error> {
        let uuid = Uuid::parse_str(group_id)
            .map_err(|_| Error::BadRequest("Invalid group ID".into(), None))?;

        let results = risk_assessment::Entity::find()
            .filter(risk_assessment::Column::GroupId.eq(uuid))
            .all(db)
            .await?;

        Ok(results.into_iter().map(RiskAssessment::from).collect())
    }

    pub async fn delete(&self, id: &str, db: &impl ConnectionTrait) -> Result<bool, Error> {
        let uuid = Uuid::parse_str(id)
            .map_err(|_| Error::BadRequest("Invalid assessment ID".into(), None))?;

        let result = risk_assessment::Entity::delete_by_id(uuid).exec(db).await?;

        Ok(result.rows_affected > 0)
    }

    pub async fn upload_document(
        &self,
        assessment_id: &str,
        category: &str,
        digests: &Digests,
        size: usize,
        db: &impl ConnectionTrait,
    ) -> Result<String, Error> {
        let assessment_uuid = Uuid::parse_str(assessment_id)
            .map_err(|_| Error::BadRequest("Invalid assessment ID".into(), None))?;

        // Verify assessment exists
        risk_assessment::Entity::find_by_id(assessment_uuid)
            .one(db)
            .await?
            .ok_or_else(|| Error::NotFound(assessment_id.to_string()))?;

        // Create source document record
        let source_doc = source_document::ActiveModel {
            id: Default::default(),
            sha256: Set(digests.sha256.encode_hex()),
            sha384: Set(digests.sha384.encode_hex()),
            sha512: Set(digests.sha512.encode_hex()),
            size: Set(size as i64),
            ingested: Set(OffsetDateTime::now_utc()),
        };

        let source_doc = source_doc.insert(db).await?;

        // Create risk assessment document record
        let doc_id = Uuid::now_v7();
        let doc = risk_assessment_document::ActiveModel {
            id: Set(doc_id),
            risk_assessment_id: Set(assessment_uuid),
            category: Set(category.to_string()),
            source_document_id: Set(source_doc.id),
            processed: Set(false),
            uploaded_at: Set(OffsetDateTime::now_utc()),
        };

        doc.insert(db).await?;

        Ok(doc_id.to_string())
    }

    pub async fn get_document_metadata(
        &self,
        assessment_id: &str,
        category: &str,
        db: &impl ConnectionTrait,
    ) -> Result<Option<source_document::Model>, Error> {
        let assessment_uuid = Uuid::parse_str(assessment_id)
            .map_err(|_| Error::BadRequest("Invalid assessment ID".into(), None))?;

        let doc = risk_assessment_document::Entity::find()
            .filter(risk_assessment_document::Column::RiskAssessmentId.eq(assessment_uuid))
            .filter(risk_assessment_document::Column::Category.eq(category))
            .one(db)
            .await?;

        let Some(doc) = doc else {
            return Ok(None);
        };

        let source_doc = source_document::Entity::find_by_id(doc.source_document_id)
            .one(db)
            .await?
            .ok_or_else(|| Error::Internal("Source document missing".to_string()))?;

        Ok(Some(source_doc))
    }

    pub async fn get_results(
        &self,
        assessment_id: &str,
        db: &impl ConnectionTrait,
    ) -> Result<Option<RiskAssessmentResults>, Error> {
        let assessment_uuid = Uuid::parse_str(assessment_id)
            .map_err(|_| Error::BadRequest("Invalid assessment ID".into(), None))?;

        let assessment = risk_assessment::Entity::find_by_id(assessment_uuid)
            .one(db)
            .await?;

        let Some(assessment) = assessment else {
            return Ok(None);
        };

        let documents = risk_assessment_document::Entity::find()
            .filter(risk_assessment_document::Column::RiskAssessmentId.eq(assessment_uuid))
            .all(db)
            .await?;

        let mut categories = Vec::with_capacity(documents.len());
        for doc in documents {
            let criteria = risk_assessment_criteria::Entity::find()
                .filter(risk_assessment_criteria::Column::DocumentId.eq(doc.id))
                .all(db)
                .await?;

            categories.push(CategoryResult {
                category: doc.category,
                document_id: doc.id.to_string(),
                processed: doc.processed,
                criteria: criteria
                    .into_iter()
                    .map(|c| CriterionResult {
                        id: c.id.to_string(),
                        criterion: c.criterion,
                        completeness: c.completeness,
                        risk_level: c.risk_level,
                        score: c.score,
                        details: c.details,
                    })
                    .collect(),
            });
        }

        Ok(Some(RiskAssessmentResults {
            assessment_id: assessment.id.to_string(),
            overall_score: assessment.overall_score,
            categories,
        }))
    }
}
