use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "risk_assessment_criteria")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,

    pub document_id: Uuid,
    pub criterion: String,
    pub completeness: String,
    pub risk_level: String,
    pub score: f64,
    pub details: Option<serde_json::Value>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::risk_assessment_document::Entity",
        from = "Column::DocumentId",
        to = "super::risk_assessment_document::Column::Id"
    )]
    Document,
}

impl Related<super::risk_assessment_document::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Document.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
