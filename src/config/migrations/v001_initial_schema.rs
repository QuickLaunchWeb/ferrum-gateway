use crate::fips::approved::Sha256;
use sqlx::AnyConnection;
use std::sync::OnceLock;

use super::Migration;
use super::sql_dialect::V001SqlBuilder;

/// Checksums recorded immediately around the MySQL `upstreams` primary-key
/// correction. The old DDL was valid for PostgreSQL and SQLite, while the
/// corrected DDL is valid for every backend, so both represent valid V001s.
pub(super) const COMPATIBLE_UPSTREAMS_PK_FIX_CHECKSUMS: [&str; 2] = [
    "sha256:094e4c56370bba562f1feeafe0b18403e8eb26c22e23d8b083e773a468180038",
    "sha256:24903f7bc521d6ceef02927bc7af812c5f92fb57c3ae4115a23b02b7d808c806",
];

/// V1: Initial schema — creates the baseline tables.
/// This matches the original inline schema from db_loader.rs.
pub struct V001InitialSchema;

impl Migration for V001InitialSchema {
    fn version(&self) -> i64 {
        1
    }

    fn name(&self) -> &str {
        "initial_schema"
    }

    fn checksum(&self) -> &str {
        static CHECKSUM: OnceLock<String> = OnceLock::new();
        CHECKSUM.get_or_init(|| {
            let mut hasher = Sha256::new();
            hasher.update(include_bytes!("v001_initial_schema.rs"));
            hasher.update(include_bytes!("sql_dialect.rs"));
            format!("sha256:{}", hex::encode(hasher.finalize()))
        })
    }
}

impl V001InitialSchema {
    pub async fn up(
        &self,
        connection: &mut AnyConnection,
        db_type: &str,
    ) -> Result<(), anyhow::Error> {
        V001SqlBuilder::new(db_type).apply(connection).await
    }
}
