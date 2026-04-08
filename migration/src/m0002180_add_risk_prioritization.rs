use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(RiskAssessmentDocument::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(RiskAssessmentDocument::RiskPrioritization).json_binary(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(RiskAssessmentDocument::Table)
                    .drop_column(RiskAssessmentDocument::RiskPrioritization)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum RiskAssessmentDocument {
    Table,
    RiskPrioritization,
}
