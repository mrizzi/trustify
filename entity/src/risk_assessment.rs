use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "risk_assessment")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,

    pub group_id: Uuid,
    pub status: String,
    pub overall_score: Option<f64>,

    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom_group::Entity",
        from = "Column::GroupId",
        to = "super::sbom_group::Column::Id"
    )]
    SbomGroup,

    #[sea_orm(has_many = "super::risk_assessment_document::Entity")]
    Documents,
}

impl Related<super::sbom_group::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SbomGroup.def()
    }
}

impl Related<super::risk_assessment_document::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Documents.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
