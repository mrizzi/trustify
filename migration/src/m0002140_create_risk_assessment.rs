use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // risk_assessment table
        manager
            .create_table(
                Table::create()
                    .table(RiskAssessment::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RiskAssessment::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(RiskAssessment::GroupId).uuid().not_null())
                    .col(ColumnDef::new(RiskAssessment::Status).string().not_null())
                    .col(ColumnDef::new(RiskAssessment::OverallScore).double())
                    .col(
                        ColumnDef::new(RiskAssessment::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RiskAssessment::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(RiskAssessment::GroupId)
                            .to(SbomGroup::Table, SbomGroup::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // risk_assessment_document table
        manager
            .create_table(
                Table::create()
                    .table(RiskAssessmentDocument::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RiskAssessmentDocument::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(RiskAssessmentDocument::RiskAssessmentId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RiskAssessmentDocument::Category)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RiskAssessmentDocument::SourceDocumentId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RiskAssessmentDocument::Processed)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(RiskAssessmentDocument::UploadedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(RiskAssessmentDocument::RiskAssessmentId)
                            .to(RiskAssessment::Table, RiskAssessment::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(RiskAssessmentDocument::SourceDocumentId)
                            .to(SourceDocument::Table, SourceDocument::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // risk_assessment_criteria table
        manager
            .create_table(
                Table::create()
                    .table(RiskAssessmentCriteria::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RiskAssessmentCriteria::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(RiskAssessmentCriteria::DocumentId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RiskAssessmentCriteria::Criterion)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RiskAssessmentCriteria::Completeness)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RiskAssessmentCriteria::RiskLevel)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RiskAssessmentCriteria::Score)
                            .double()
                            .not_null(),
                    )
                    .col(ColumnDef::new(RiskAssessmentCriteria::Details).json_binary())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(RiskAssessmentCriteria::DocumentId)
                            .to(RiskAssessmentDocument::Table, RiskAssessmentDocument::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(RiskAssessmentCriteria::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(RiskAssessmentDocument::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(RiskAssessment::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum RiskAssessment {
    Table,
    Id,
    GroupId,
    Status,
    OverallScore,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum RiskAssessmentDocument {
    Table,
    Id,
    RiskAssessmentId,
    Category,
    SourceDocumentId,
    Processed,
    UploadedAt,
}

#[derive(DeriveIden)]
enum RiskAssessmentCriteria {
    Table,
    Id,
    DocumentId,
    Criterion,
    Completeness,
    RiskLevel,
    Score,
    Details,
}

#[derive(DeriveIden)]
enum SbomGroup {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum SourceDocument {
    Table,
    Id,
}
