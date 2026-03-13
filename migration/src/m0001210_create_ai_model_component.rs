use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AiModelComponent::Table)
                    .col(
                        ColumnDef::new(AiModelComponent::SbomId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AiModelComponent::NodeId)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(AiModelComponent::ModelType).string())
                    .col(ColumnDef::new(AiModelComponent::PrimaryTask).string())
                    .col(ColumnDef::new(AiModelComponent::Supplier).string())
                    .col(ColumnDef::new(AiModelComponent::License).string())
                    .col(ColumnDef::new(AiModelComponent::Properties).json_binary())
                    .col(
                        ColumnDef::new(AiModelComponent::ExternalReferences)
                            .json_binary(),
                    )
                    .primary_key(
                        Index::create()
                            .col(AiModelComponent::SbomId)
                            .col(AiModelComponent::NodeId)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                AiModelComponent::Table,
                                (AiModelComponent::SbomId, AiModelComponent::NodeId),
                            )
                            .to(
                                SbomNode::Table,
                                (SbomNode::SbomId, SbomNode::NodeId),
                            )
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
                    .table(AiModelComponent::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum AiModelComponent {
    Table,
    SbomId,
    NodeId,
    ModelType,
    PrimaryTask,
    Supplier,
    License,
    Properties,
    ExternalReferences,
}

#[derive(DeriveIden)]
pub enum SbomNode {
    Table,
    SbomId,
    NodeId,
}
