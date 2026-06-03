use sea_orm_migration::prelude::*;
use trustify_common::db::create_enum_if_not_exists;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Enum variants listed explicitly because the migration crate cannot depend on
// trustify_entity::status::Status (would create a circular dependency).
// Keep in sync with entity/src/status.rs — the serialization alignment test
// in that file will catch any drift.
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

        // 2b. Validate that all rows were migrated — fail early if orphaned status_id
        //     references left NULL status_text values.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DO $$
                DECLARE
                    null_purl_count bigint;
                    null_product_count bigint;
                BEGIN
                    SELECT count(*) INTO null_purl_count
                    FROM purl_status WHERE status_text IS NULL;
                    SELECT count(*) INTO null_product_count
                    FROM product_status WHERE status_text IS NULL;
                    IF null_purl_count > 0 OR null_product_count > 0 THEN
                        RAISE EXCEPTION 'Migration blocked: % purl_status and % product_status rows have NULL status_text (orphaned status_id references)',
                            null_purl_count, null_product_count;
                    END IF;
                END$$;
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

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 0. Save enum values to temporary text columns before dropping the enum.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                ALTER TABLE purl_status ADD COLUMN IF NOT EXISTS status_text text;
                ALTER TABLE product_status ADD COLUMN IF NOT EXISTS status_text text;
                UPDATE purl_status SET status_text = status::text;
                UPDATE product_status SET status_text = status::text;
                "#,
            )
            .await?;

        // 1. Drop enum columns and enum type — the enum type occupies the "status"
        //    name in pg_type, which would conflict with the implicit composite type
        //    created by the table in the next step.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                ALTER TABLE purl_status DROP COLUMN IF EXISTS status;
                ALTER TABLE product_status DROP COLUMN IF EXISTS status;
                DROP TYPE IF EXISTS status;
                "#,
            )
            .await?;

        // 2. Recreate the status table and seed data
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE TABLE IF NOT EXISTS status (
                    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
                    slug character varying NOT NULL,
                    name character varying NOT NULL,
                    description character varying
                );

                INSERT INTO status (id, slug, name, description) VALUES
                    ('85b912db-fc1b-4e75-8b27-68b68c0ed828', 'affected', 'Affected', 'Vulnerabililty affects'),
                    ('619aba21-abba-4220-9e3e-110cf87e5393', 'not_affected', 'Not Affected', 'Vulnerabililty does not affect'),
                    ('c0273e43-2b0c-4dae-a3b3-c4f9733fbfa7', 'fixed', 'Fixed', 'Vulnerabililty is fixed'),
                    ('23613500-86a4-4cdb-bc92-8c74e18764da', 'under_investigation', 'Under Investigation', 'Vulnerabililty is under investigation'),
                    ('2bb0325b-0948-44ea-bab7-46af9fc834eb', 'fixed', 'Fixed', 'Vulnerabililty is fixed'),
                    ('858a3f17-d864-4be8-932e-4a634de47b8b', 'recommended', 'Recommended', 'Vulnerabililty is fixed & recommended')
                ON CONFLICT DO NOTHING;
                "#,
            )
            .await?;

        // 3. Add status_id columns, populate from saved text via slug lookup, clean up
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                ALTER TABLE purl_status
                    ADD COLUMN IF NOT EXISTS status_id uuid;
                ALTER TABLE product_status
                    ADD COLUMN IF NOT EXISTS status_id uuid;

                UPDATE purl_status
                SET status_id = s.id
                FROM status s
                WHERE s.slug = purl_status.status_text;

                UPDATE product_status
                SET status_id = s.id
                FROM status s
                WHERE s.slug = product_status.status_text;

                ALTER TABLE purl_status
                    ALTER COLUMN status_id SET NOT NULL;
                ALTER TABLE product_status
                    ALTER COLUMN status_id SET NOT NULL;

                ALTER TABLE purl_status
                    ADD CONSTRAINT package_status_status_id_fkey
                    FOREIGN KEY (status_id) REFERENCES status(id);
                ALTER TABLE product_status
                    ADD CONSTRAINT product_status_status_id_fkey
                    FOREIGN KEY (status_id) REFERENCES status(id);

                ALTER TABLE purl_status DROP COLUMN IF EXISTS status_text;
                ALTER TABLE product_status DROP COLUMN IF EXISTS status_text;

                CREATE INDEX IF NOT EXISTS package_status_idx
                    ON purl_status USING btree (base_purl_id, advisory_id, status_id);
                CREATE INDEX IF NOT EXISTS purl_status_combo_idx
                    ON purl_status USING btree (base_purl_id, advisory_id, vulnerability_id, status_id, context_cpe_id);
                CREATE INDEX IF NOT EXISTS product_status_idx
                    ON product_status USING btree (context_cpe_id, status_id, package, vulnerability_id);
                "#,
            )
            .await?;

        Ok(())
    }
}
