use sqlx::AnyPool;

use super::Migration;

/// V2: Add upstream_id column to the proxies table.
/// This enables load-balanced backends in database mode by linking proxies to upstreams.
pub struct V002AddUpstreamId;

impl Migration for V002AddUpstreamId {
    fn version(&self) -> i64 {
        2
    }

    fn name(&self) -> &str {
        "add_upstream_id"
    }

    fn checksum(&self) -> &str {
        "v002_add_upstream_id_e5f6g7h8"
    }
}

impl V002AddUpstreamId {
    pub async fn up(&self, pool: &AnyPool, _db_type: &str) -> Result<(), anyhow::Error> {
        // ALTER TABLE ADD COLUMN IF NOT EXISTS is not supported by all backends.
        // SQLite doesn't support IF NOT EXISTS for columns, and will error if
        // the column already exists. We handle this by catching the error.
        let result = sqlx::query("ALTER TABLE proxies ADD COLUMN upstream_id TEXT")
            .execute(pool)
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                let err_msg = e.to_string().to_lowercase();
                // SQLite: "duplicate column name: upstream_id"
                // Postgres: "column \"upstream_id\" of relation \"proxies\" already exists"
                // MySQL: "Duplicate column name 'upstream_id'"
                if err_msg.contains("duplicate") || err_msg.contains("already exists") {
                    // Column already exists — this is fine (e.g., V1 was applied fresh
                    // with the column already included in the CREATE TABLE)
                    Ok(())
                } else {
                    Err(e.into())
                }
            }
        }
    }
}
