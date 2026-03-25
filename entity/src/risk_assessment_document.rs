use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "risk_assessment_document")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,

    pub risk_assessment_id: Uuid,
    pub category: String,
    pub source_document_id: Uuid,
    pub processed: bool,

    pub uploaded_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::risk_assessment::Entity",
        from = "Column::RiskAssessmentId",
        to = "super::risk_assessment::Column::Id"
    )]
    RiskAssessment,

    #[sea_orm(
        belongs_to = "super::source_document::Entity",
        from = "Column::SourceDocumentId",
        to = "super::source_document::Column::Id"
    )]
    SourceDocument,

    #[sea_orm(has_many = "super::risk_assessment_criteria::Entity")]
    Criteria,
}

impl Related<super::risk_assessment::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RiskAssessment.def()
    }
}

impl Related<super::source_document::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SourceDocument.def()
    }
}

impl Related<super::risk_assessment_criteria::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Criteria.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
