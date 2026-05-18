use sea_orm_migration::prelude::*;
use trustify_common::db::create_enum_if_not_exists;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(Clone, DeriveIden)]
enum StatusEnum {
    #[sea_orm(iden = "status")]
    Table,
    Affected,
    Fixed,
    NotAffected,
    UnderInvestigation,
    Recommended,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. Add temporary text columns to hold migrated status slugs.
        //    We can't create the enum type yet because the status TABLE occupies the name.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                ALTER TABLE purl_status
                    ADD COLUMN IF NOT EXISTS status_text text;
                ALTER TABLE product_status
                    ADD COLUMN IF NOT EXISTS status_text text;
                "#,
            )
            .await?;

        // 2. Migrate data from the old status table via slug-based join.
        //    Handles duplicate "fixed" UUIDs since both map to the same slug.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE purl_status
                SET status_text = s.slug
                FROM status s
                WHERE s.id = purl_status.status_id
                  AND purl_status.status_text IS NULL;

                UPDATE product_status
                SET status_text = s.slug
                FROM status s
                WHERE s.id = product_status.status_id
                  AND product_status.status_text IS NULL;
                "#,
            )
            .await?;

        // 3. Drop the old status_id FK columns (removes FK constraints on the status table)
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                ALTER TABLE purl_status
                    DROP COLUMN IF EXISTS status_id;
                ALTER TABLE product_status
                    DROP COLUMN IF EXISTS status_id;
                "#,
            )
            .await?;

        // 4. Drop the old status table (now safe since no FK references remain)
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS status CASCADE;")
            .await?;

        // 5. Create the PostgreSQL enum type 'status' (idempotent).
        //    Now safe since the table (and its implicit composite type) is gone.
        create_enum_if_not_exists(
            manager,
            StatusEnum::Table,
            [
                StatusEnum::Affected,
                StatusEnum::Fixed,
                StatusEnum::NotAffected,
                StatusEnum::UnderInvestigation,
                StatusEnum::Recommended,
            ],
        )
        .await?;

        // 6. Add the enum columns and cast the migrated text data
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                ALTER TABLE purl_status
                    ADD COLUMN IF NOT EXISTS status status;
                ALTER TABLE product_status
                    ADD COLUMN IF NOT EXISTS status status;

                UPDATE purl_status SET status = status_text::status;
                UPDATE product_status SET status = status_text::status;

                ALTER TABLE purl_status
                    ALTER COLUMN status SET NOT NULL;
                ALTER TABLE product_status
                    ALTER COLUMN status SET NOT NULL;

                ALTER TABLE purl_status
                    DROP COLUMN IF EXISTS status_text;
                ALTER TABLE product_status
                    DROP COLUMN IF EXISTS status_text;
                "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "Cannot reverse status table to enum migration".to_string(),
        ))
    }
}
