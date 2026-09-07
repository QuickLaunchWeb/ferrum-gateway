//! Config backup loader for database mode startup failover.
//!
//! When the database is unreachable at startup, this loads a read-only JSON
//! backup file (provisioned externally via ConfigMap, PersistentVolume, etc.)
//! so the gateway can start serving with stale-but-working config rather than
//! failing entirely. The backup is never written by the gateway — it's purely
//! an external resilience mechanism for Kubernetes and similar environments.
//!
//! The file is provisioned by an operator and may well be an all-namespace
//! administrative export, so the loader projects it onto the gateway's
//! configured namespace (`FERRUM_NAMESPACE`) BEFORE validating or returning it.
//! Without that projection a gateway configured for one tenant would spend the
//! whole outage the fallback exists to bridge binding another tenant's
//! listeners and loading another tenant's consumers, credentials, plugin
//! policy, upstreams and trust material. Filtering first is also what keeps a
//! cross-namespace duplicate `listen_path` or proxy name in the file from
//! rejecting a candidate that is perfectly valid for the served namespace;
//! duplicates INSIDE the active namespace still reject exactly as before.
//!
//! Before serving, the loader applies the same rejecting runtime validation
//! contract as database full loads (`collect_rejecting_runtime_config_errors`).
//! Warning-only / node-local checks (certificate paths, optional plugin file
//! dependencies such as MaxMind `.mmdb`) stay out of this path: they are not
//! runtime-fatal for DB-mode snapshots and must not block backup bootstrap.

use crate::config::config_migration::ConfigMigrator;
use crate::config::namespace_filter::{NamespaceRetention, retain_namespace};
use crate::config::types::{CURRENT_CONFIG_VERSION, GatewayConfig};
use crate::config::validation_pipeline::collect_rejecting_runtime_config_errors;
use tracing::{error, info, warn};

/// Attempt to load a GatewayConfig from an externally provided backup JSON file.
/// This is used as a startup fallback in database mode when the DB is unreachable
/// (e.g. K8S pod restart while DB is down). The file is expected to be provided
/// externally (e.g. via ConfigMap, PersistentVolume, or sidecar export).
///
/// `namespace` is the gateway's configured serving namespace and is REQUIRED:
/// the returned candidate contains only the resources that namespace owns, so a
/// multi-namespace export is safe to provision as a startup backup.
///
/// Returns `Ok(None)` if the file does not exist. Returns `Err` with an
/// actionable message when the file exists but cannot be parsed, is at an
/// unsupported config version (with no migration path under the build-out
/// policy), carries an empty serving namespace, or fails the rejecting runtime
/// validation contract. Returns `Ok(Some(config))` only for a snapshot that is
/// safe to serve. A backup holding no resources in the active namespace yields
/// an empty-but-valid candidate, never a foreign one.
pub fn load_config_backup(
    path: &str,
    namespace: &str,
) -> Result<Option<GatewayConfig>, anyhow::Error> {
    // Fail closed rather than letting "" behave as a namespace that matches
    // nothing today and might match everything after a refactor.
    // `EnvConfig::validate()` already rejects an empty `FERRUM_NAMESPACE` at
    // startup; this is the loader's own guarantee that it cannot run without a
    // serving namespace.
    if namespace.is_empty() {
        anyhow::bail!(
            "Config backup at {path} cannot be loaded without a serving namespace; \
             set FERRUM_NAMESPACE"
        );
    }

    // Read once and classify the result directly. `Path::exists()` both creates
    // a check/use race and returns false for some metadata errors, which would
    // incorrectly collapse an inaccessible configured backup to `Ok(None)`.
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            warn!("No config backup file found at {}", path);
            return Ok(None);
        }
        Err(error) => {
            return Err(anyhow::anyhow!(
                "Failed to read config backup at {path}: {error}"
            ));
        }
    };

    let mut value: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse config backup at {path}: {e}"))?;

    normalize_backup_version_field(&mut value)?;
    ConfigMigrator::migrate_in_memory(&mut value)
        .map_err(|e| anyhow::anyhow!("Config backup at {path} failed version migration: {e}"))?;

    let backup_version = value
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!("Config backup at {path} is missing required 'version' field")
        })?;
    if backup_version != CURRENT_CONFIG_VERSION {
        anyhow::bail!(
            "Config backup at {path} has unsupported version '{backup_version}' \
             (current is '{CURRENT_CONFIG_VERSION}'); migrate supported older backups \
             or export a current-version snapshot"
        );
    }

    let mut config: GatewayConfig = serde_json::from_value(value)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize config backup at {path}: {e}"))?;

    // Preserve the same normalize → TLS resolution order used by database
    // full loads before the rejecting runtime contract runs.
    config.normalize_fields();
    config.resolve_upstream_tls();

    // Project onto the serving namespace BEFORE the rejecting contract runs.
    // The cross-resource validators treat `listen_path`, proxy/upstream name and
    // consumer identity as `(namespace, value)`-scoped, exactly as the admin API
    // and the SQL unique indexes do, so running them over a multi-namespace file
    // would reject a candidate that is valid for the namespace being served.
    // Duplicates within the active namespace are untouched by the filter and
    // still reject.
    let (config, filter_summary) = retain_namespace(config, namespace, NamespaceRetention::SERVING);

    let validation_errors = collect_rejecting_runtime_config_errors(&config);
    if !validation_errors.is_empty() {
        for message in &validation_errors {
            error!("Config backup rejected — {}", message);
        }
        anyhow::bail!(
            "Config backup at {path} failed runtime validation ({} rejecting error(s)): {}",
            validation_errors.len(),
            validation_errors.join("; ")
        );
    }

    // COUNT-ONLY diagnostic. The namespaces present in the file are never named
    // and never reach a serving or authorization decision: `retain_namespace`
    // has already reduced the candidate to the configured namespace, and
    // `known_namespaces` was collapsed to it.
    info!(
        "Config backup loaded for namespace '{}': {} proxies, {} consumers from {} \
         ({} namespace(s) present in the file, {} resource(s) excluded as \
         out-of-namespace)",
        namespace,
        config.proxies.len(),
        config.consumers.len(),
        path,
        filter_summary.source_namespace_count,
        filter_summary.excluded_resources
    );
    Ok(Some(config))
}

/// Accept the canonical string form and the natural JSON unsigned-integer
/// spelling of `version` (rewrite integers to strings for `GatewayConfig`).
/// Reject every other JSON type with a precise diagnostic.
fn normalize_backup_version_field(value: &mut serde_json::Value) -> Result<(), anyhow::Error> {
    match value.get_mut("version") {
        None => anyhow::bail!("Config backup missing required 'version' field"),
        Some(serde_json::Value::String(_)) => Ok(()),
        Some(other) => {
            if let Some(n) = other.as_u64() {
                *other = serde_json::Value::String(n.to_string());
                Ok(())
            } else {
                let value_type = match other {
                    serde_json::Value::Null => "null",
                    serde_json::Value::Bool(_) => "boolean",
                    serde_json::Value::Number(number) if number.is_i64() => "negative integer",
                    serde_json::Value::Number(_) => "floating-point number",
                    serde_json::Value::Array(_) => "array",
                    serde_json::Value::Object(_) => "object",
                    serde_json::Value::String(_) => "string",
                };
                anyhow::bail!(
                    "Config backup field 'version' must be a string or non-negative integer \
                     (got {value_type}); use version: \"{CURRENT_CONFIG_VERSION}\" or \
                     version: {CURRENT_CONFIG_VERSION}"
                );
            }
        }
    }
}
