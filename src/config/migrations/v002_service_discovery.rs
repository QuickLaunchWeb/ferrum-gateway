use sqlx::AnyPool;

use super::Migration;

/// V2: Add `service_discovery` JSON column to `upstreams` table.
///
/// Stores per-upstream service discovery configuration as a nullable JSON
/// string (same pattern as `circuit_breaker` on `proxies`).
pub struct V002ServiceDiscovery;

impl Migration for V002ServiceDiscovery {
    fn version(&self) -> i64 {
        2
    }

    fn name(&self) -> &str {
        "service_discovery"
    }

    fn checksum(&self) -> &str {
        "v002_add_service_discovery_column"
    }
}

impl V002ServiceDiscovery {
    pub async fn up(&self, pool: &AnyPool, db_type: &str) -> Result<(), anyhow::Error> {
        // Enable foreign key enforcement for SQLite
        if db_type == "sqlite" {
            sqlx::query("PRAGMA foreign_keys = ON")
                .execute(pool)
                .await?;
        }

        let sql = if db_type == "mysql" {
            "ALTER TABLE upstreams ADD COLUMN service_discovery TEXT"
        } else {
            // PostgreSQL and SQLite
            "ALTER TABLE upstreams ADD COLUMN service_discovery TEXT"
        };

        sqlx::query(sql).execute(pool).await?;

        Ok(())
    }
}
