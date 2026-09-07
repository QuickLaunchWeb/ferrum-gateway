use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::config::db_backend::validate_api_spec_proxy_plugin_association;
use crate::config::gateway_trust::GatewayTrustBundleRecord;
use crate::config::namespace_filter::{NamespaceRetention, retain_namespace};
use crate::config::types::{
    ApiSpec, Consumer, GatewayConfig, PluginConfig, Proxy, SpecFormat, Upstream,
};

/// Version of the `api_specs` backup section contract.
///
/// Bump when the section shape or restore semantics change in a
/// non-backward-compatible way. Older backups that omit the section entirely
/// remain restorable via the explicit deletion-confirmation preflight.
pub(crate) const API_SPECS_BACKUP_SECTION_VERSION: &str = "2";

/// Stable client text when `resources=` contains an unsupported token.
/// Never echoes the rejected token.
pub(crate) const BACKUP_UNSUPPORTED_RESOURCE_FILTER_ERROR: &str =
    "Unsupported backup resource filter";

/// Structurally malformed `resources` query parameter (key-only, duplicate, or
/// otherwise ambiguous). Distinct from an absent parameter and from a present
/// filter that merely contains unknown allow-list tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BackupResourcesQueryMalformed;

/// Parse the optional `resources` query parameter.
///
/// - Parameter absent → `Ok(None)` (unfiltered export)
/// - Single well-formed `resources=<csv>` → `Ok(Some(set))` (may still fail
///   allow-list / dependency validation later)
/// - Key-only (`?resources`), duplicate/ambiguous occurrences, or other
///   structural malformation → `Err` (fail closed; never widen to unfiltered)
pub(crate) fn parse_backup_resources(
    query: Option<&str>,
) -> Result<Option<HashSet<&str>>, BackupResourcesQueryMalformed> {
    let Some(query) = query else {
        return Ok(None);
    };

    let mut found_value: Option<&str> = None;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let Some(key) = parts.next() else {
            continue;
        };
        if key != "resources" {
            continue;
        }
        let Some(val) = parts.next() else {
            // Key-only `resources` (no `=`) is structurally malformed.
            return Err(BackupResourcesQueryMalformed);
        };
        if found_value.is_some() {
            // Duplicate/ambiguous `resources` occurrences fail closed.
            return Err(BackupResourcesQueryMalformed);
        }
        found_value = Some(val);
    }

    match found_value {
        None => Ok(None),
        Some(val) => Ok(Some(
            val.split(',')
                .map(str::trim)
                .filter(|resource| !resource.is_empty())
                .collect(),
        )),
    }
}

/// Fail closed when any `resources=` token is outside the closed allow-list.
///
/// Client text is static and never echoes the rejected token. Unknown tokens
/// must also never reach audit persistence (see
/// [`crate::admin::audit::backup_resources_audit_value`]).
pub(crate) fn validate_backup_resources_allowlist(
    filter: Option<&HashSet<&str>>,
) -> Result<(), &'static str> {
    let Some(filter) = filter else {
        return Ok(());
    };
    if filter
        .iter()
        .copied()
        .any(|name| !crate::admin::audit::is_canonical_backup_resource(name))
    {
        return Err(BACKUP_UNSUPPORTED_RESOURCE_FILTER_ERROR);
    }
    Ok(())
}

/// Stable error when a filtered backup requests `api_specs` without the
/// resource classes required for a directly restorable export.
pub(crate) const BACKUP_API_SPECS_FILTER_DEPENDENCY_ERROR: &str = "Filtered backups that include api_specs must also include proxies, upstreams, and plugin_configs";

/// Fail closed when a filtered backup requests `api_specs` without the owning
/// proxy and generated upstream/plugin resource classes.
///
/// Spec documents declare an owning proxy and stamp `api_spec_id` on generated
/// upstreams and plugin configs. Emitting specs without those classes produces
/// a self-invalid backup that restore rejects. Unfiltered backups (`None`) and
/// filters that omit `api_specs` are unchanged. `consumers` is not required
/// because API-spec extraction does not create consumers. Never silently
/// widens the filter or silently omits requested specs.
pub(crate) fn validate_backup_api_specs_resource_filter(
    filter: Option<&HashSet<&str>>,
) -> Result<(), &'static str> {
    let Some(filter) = filter else {
        return Ok(());
    };
    if !filter.contains("api_specs") {
        return Ok(());
    }
    if filter.contains("proxies")
        && filter.contains("upstreams")
        && filter.contains("plugin_configs")
    {
        return Ok(());
    }
    Err(BACKUP_API_SPECS_FILTER_DEPENDENCY_ERROR)
}

pub(crate) fn parse_restore_confirm(query: Option<&str>) -> bool {
    parse_query_flag(query, "confirm")
}

/// Explicit confirmation that a restore of a legacy backup (no `api_specs`
/// section) may permanently delete API specs present in the target namespace.
pub(crate) fn parse_confirm_api_spec_deletion(query: Option<&str>) -> bool {
    parse_query_flag(query, "confirm_api_spec_deletion")
}

fn parse_query_flag(query: Option<&str>, flag: &str) -> bool {
    let query = match query {
        Some(query) => query,
        None => return false,
    };
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if let (Some(key), Some(val)) = (parts.next(), parts.next())
            && key == flag
            && val == "true"
        {
            return true;
        }
    }
    false
}

#[derive(Serialize)]
pub(crate) struct BackupPayload<'a> {
    pub(crate) version: &'a str,
    pub(crate) ferrum_version: &'static str,
    pub(crate) exported_at: String,
    pub(crate) source: &'static str,
    pub(crate) counts: BackupCounts,
    pub(crate) proxies: &'a [Proxy],
    pub(crate) consumers: &'a [Consumer],
    pub(crate) plugin_configs: &'a [PluginConfig],
    pub(crate) upstreams: &'a [Upstream],
    /// Namespace-keyed gateway trust bundles (issue #3727).
    ///
    /// Always emitted (possibly empty) on database-backed exports so a restore
    /// can tell "this backup had no trust resource" from "this backup predates
    /// the resource". Restore treats an ABSENT section as "leave trust alone":
    /// silently revoking a namespace's roots because an operator restored an
    /// older config backup would be an outage, not a rollback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) gateway_trust_bundles: Option<&'a [GatewayTrustBundleRecord]>,
    /// Versioned admin-only API spec section. Always present on database-backed
    /// full exports (possibly with an empty `items` array). Omitted on
    /// cached-fallback exports, whose resources carry no ownership tags and so
    /// cannot describe managed relationships.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) api_specs: Option<&'a ApiSpecsBackupSection>,
}

#[derive(Serialize)]
pub(crate) struct BackupCounts {
    pub(crate) proxies: usize,
    pub(crate) consumers: usize,
    pub(crate) plugin_configs: usize,
    pub(crate) upstreams: usize,
    pub(crate) api_specs: usize,
    pub(crate) gateway_trust_bundles: usize,
}

/// Versioned backup/restore section for raw API spec documents and ownership
/// metadata required to reproduce generated-resource relationships.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ApiSpecsBackupSection {
    pub(crate) section_version: String,
    pub(crate) items: Vec<ApiSpecBackupItem>,
}

impl ApiSpecsBackupSection {
    pub(crate) fn empty() -> Self {
        Self {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: Vec::new(),
        }
    }

    pub(crate) fn from_specs(specs: &[ApiSpec]) -> Self {
        Self {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: specs.iter().map(ApiSpecBackupItem::from_api_spec).collect(),
        }
    }

    pub(crate) fn to_api_specs(&self) -> Result<Vec<ApiSpec>, String> {
        self.items
            .iter()
            .map(ApiSpecBackupItem::to_api_spec)
            .collect()
    }
}

/// Wire form of one API spec in a backup/restore payload.
///
/// `spec_content_base64` carries the gzip-compressed original document so JSON
/// backups stay compact and never emit a hostile multi-megabyte number array.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ApiSpecBackupItem {
    pub(crate) id: String,
    #[serde(default = "default_namespace")]
    pub(crate) namespace: String,
    pub(crate) proxy_id: String,
    pub(crate) spec_version: String,
    pub(crate) spec_format: SpecFormat,
    pub(crate) spec_content_base64: String,
    pub(crate) content_encoding: String,
    pub(crate) uncompressed_size: u64,
    pub(crate) content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) info_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) contact_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) contact_email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) license_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) license_identifier: Option<String>,
    #[serde(default)]
    pub(crate) tags: Vec<String>,
    #[serde(default)]
    pub(crate) server_urls: Vec<String>,
    #[serde(default)]
    pub(crate) operation_count: u32,
    #[serde(default)]
    pub(crate) resource_hash: String,
    /// Optional Base64 of gzip-compressed external-`$ref` admission snapshot
    /// (section version `"2"`+). Absent on version `"1"` backups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) external_ref_snapshot_base64: Option<String>,
    /// Aggregate digest of the external-`$ref` admission snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) external_ref_digest: Option<String>,
    pub(crate) created_at: chrono::DateTime<chrono::Utc>,
    pub(crate) updated_at: chrono::DateTime<chrono::Utc>,
}

fn default_namespace() -> String {
    "ferrum".to_string()
}

impl ApiSpecBackupItem {
    pub(crate) fn from_api_spec(spec: &ApiSpec) -> Self {
        Self {
            id: spec.id.clone(),
            namespace: spec.namespace.clone(),
            proxy_id: spec.proxy_id.clone(),
            spec_version: spec.spec_version.clone(),
            spec_format: spec.spec_format,
            spec_content_base64: base64::engine::general_purpose::STANDARD
                .encode(&spec.spec_content),
            content_encoding: spec.content_encoding.clone(),
            uncompressed_size: spec.uncompressed_size,
            content_hash: spec.content_hash.clone(),
            title: spec.title.clone(),
            info_version: spec.info_version.clone(),
            description: spec.description.clone(),
            contact_name: spec.contact_name.clone(),
            contact_email: spec.contact_email.clone(),
            license_name: spec.license_name.clone(),
            license_identifier: spec.license_identifier.clone(),
            tags: spec.tags.clone(),
            server_urls: spec.server_urls.clone(),
            operation_count: spec.operation_count,
            resource_hash: spec.resource_hash.clone(),
            external_ref_snapshot_base64: spec
                .external_ref_snapshot
                .as_ref()
                .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes)),
            external_ref_digest: spec.external_ref_digest.clone(),
            created_at: spec.created_at,
            updated_at: spec.updated_at,
        }
    }

    pub(crate) fn to_api_spec(&self) -> Result<ApiSpec, String> {
        let spec_content = base64::engine::general_purpose::STANDARD
            .decode(self.spec_content_base64.as_bytes())
            .map_err(|error| {
                format!(
                    "api_spec '{}': invalid spec_content_base64: {error}",
                    self.id
                )
            })?;
        let external_ref_snapshot = match &self.external_ref_snapshot_base64 {
            Some(encoded) => {
                let max_encoded =
                    crate::admin::api_specs::external_refs::MAX_EXTERNAL_REF_SNAPSHOT_COMPRESSED_BYTES
                        .saturating_mul(4)
                        .saturating_div(3)
                        .saturating_add(8);
                if encoded.len() > max_encoded {
                    return Err(
                        "api_spec external_ref_snapshot_base64 exceeds size limit".to_string()
                    );
                }
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(encoded.as_bytes())
                    .map_err(|_| "api_spec external_ref_snapshot_base64 is invalid".to_string())?;
                if bytes.len()
                    > crate::admin::api_specs::external_refs::MAX_EXTERNAL_REF_SNAPSHOT_COMPRESSED_BYTES
                {
                    return Err("api_spec external_ref_snapshot exceeds size limit".to_string());
                }
                Some(bytes)
            }
            None => None,
        };
        crate::admin::api_specs::external_refs::validate_external_ref_snapshot_pair(
            external_ref_snapshot.as_deref(),
            self.external_ref_digest.as_deref(),
        )
        .map_err(|_| "api_spec external-ref snapshot integrity validation failed".to_string())?;
        Ok(ApiSpec {
            id: self.id.clone(),
            namespace: self.namespace.clone(),
            proxy_id: self.proxy_id.clone(),
            spec_version: self.spec_version.clone(),
            spec_format: self.spec_format,
            spec_content,
            content_encoding: self.content_encoding.clone(),
            uncompressed_size: self.uncompressed_size,
            content_hash: self.content_hash.clone(),
            title: self.title.clone(),
            info_version: self.info_version.clone(),
            description: self.description.clone(),
            contact_name: self.contact_name.clone(),
            contact_email: self.contact_email.clone(),
            license_name: self.license_name.clone(),
            license_identifier: self.license_identifier.clone(),
            tags: self.tags.clone(),
            server_urls: self.server_urls.clone(),
            operation_count: self.operation_count,
            resource_hash: self.resource_hash.clone(),
            external_ref_snapshot,
            external_ref_digest: self.external_ref_digest.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Create-only `POST /batch` envelope. Resource items still use the same
/// schemas as the individual POST endpoints. Unknown top-level keys are
/// rejected so unimplemented verbs (`updates`, `deletes`, `dry_run`) cannot
/// look like a successful no-op. Backup metadata keys are accepted and
/// ignored so `GET /backup` output remains a valid additive import.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BatchCreateRequest {
    #[serde(default)]
    pub proxies: Vec<Proxy>,
    #[serde(default)]
    pub consumers: Vec<Consumer>,
    #[serde(default)]
    pub plugin_configs: Vec<PluginConfig>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[serde(default, rename = "version")]
    _version: String,
    #[serde(default, rename = "ferrum_version")]
    _ferrum_version: Option<String>,
    #[serde(default, rename = "exported_at")]
    _exported_at: Option<String>,
    #[serde(default, rename = "source")]
    _source: Option<String>,
    #[serde(default, rename = "counts")]
    _counts: Option<serde_json::Value>,
    #[serde(default, rename = "api_specs")]
    _api_specs: Option<serde_json::Value>,
    #[serde(default, rename = "gateway_trust_bundles")]
    _gateway_trust_bundles: Option<serde_json::Value>,
}

impl From<BatchCreateRequest> for RestorePayload {
    fn from(request: BatchCreateRequest) -> Self {
        RestorePayload {
            version: String::new(),
            proxies: request.proxies,
            consumers: request.consumers,
            plugin_configs: request.plugin_configs,
            upstreams: request.upstreams,
            api_specs: None,
            gateway_trust_bundles: None,
        }
    }
}

/// Why restore refuses an omitted resource id that `POST /batch` would mint.
pub(crate) const RESTORE_MISSING_ID_MESSAGE: &str = "Restore requires a non-empty resource id \
     (GET /backup always includes ids). POST /batch auto-generates omitted ids; POST /restore \
     does not, because a second restore of the same body would invent different identities.";

/// Collect restore validation errors for resources whose `id` was omitted.
pub(crate) fn restore_missing_resource_id_errors(payload: &RestorePayload) -> Vec<String> {
    let mut errors = Vec::new();
    let mut push = |kind: &str, id: &str| {
        if id.is_empty() {
            errors.push(format!("{kind} ID: {RESTORE_MISSING_ID_MESSAGE}"));
        }
    };
    for proxy in &payload.proxies {
        push("Proxy", &proxy.id);
    }
    for consumer in &payload.consumers {
        push("Consumer", &consumer.id);
    }
    for plugin in &payload.plugin_configs {
        push("PluginConfig", &plugin.id);
    }
    for upstream in &payload.upstreams {
        push("Upstream", &upstream.id);
    }
    errors
}

#[derive(Deserialize)]
pub(crate) struct RestorePayload {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub proxies: Vec<Proxy>,
    #[serde(default)]
    pub consumers: Vec<Consumer>,
    #[serde(default)]
    pub plugin_configs: Vec<PluginConfig>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    /// Present when the backup includes the versioned `api_specs` section.
    /// `None` means a legacy backup that omitted the section entirely.
    #[serde(default)]
    pub api_specs: Option<ApiSpecsBackupSection>,
    /// Gateway trust bundles (issue #3727). `None` means the backup predates
    /// the resource (or was a cached-fallback export) and trust must be left
    /// exactly as it is; `Some(vec![])` is an explicit "this namespace had no
    /// trust resource" and revokes.
    #[serde(default)]
    pub gateway_trust_bundles: Option<Vec<GatewayTrustBundleRecord>>,
}

/// Project a cached multi-namespace snapshot onto one namespace for a
/// namespace-scoped administrative export.
///
/// Delegates to the shared configuration-layer filter
/// ([`crate::config::namespace_filter::retain_namespace`]) so there is exactly
/// one definition of which `GatewayConfig` fields are namespace-owned: that
/// helper destructures the struct exhaustively, so a new namespace-owned field
/// cannot silently escape either this export or the database-mode startup
/// backup projection.
///
/// [`NamespaceRetention::EXPORT`] is the right policy here because this is data
/// at rest for a later restore rather than a snapshot about to be served: the
/// discovered `known_namespaces` list and the mesh model are carried through,
/// while every namespace-owned resource collection — proxies, consumers, plugin
/// configs, upstreams, trust records, Gateway TLS material and the
/// namespace-qualified TLS listener classification — is filtered.
pub(crate) fn filter_config_by_namespace(config: &GatewayConfig, namespace: &str) -> GatewayConfig {
    retain_namespace(config.clone(), namespace, NamespaceRetention::EXPORT).0
}

/// Validate the versioned `api_specs` backup section without logging document
/// contents, hashes, URLs, or other hostile metadata that could leak into
/// operator logs. Enforces the same stored-metadata bounds and declared-format
/// document parse used by ordinary POST/PUT admission, without re-extracting
/// resources or resolving external references.
#[cfg(test)]
pub(crate) fn validate_restore_api_specs_section(
    section: &ApiSpecsBackupSection,
    proxies: &[Proxy],
    upstreams: &[Upstream],
    plugin_configs: &[PluginConfig],
    max_spec_body_mib: usize,
) -> Result<Vec<ApiSpec>, Vec<String>> {
    validate_restore_api_specs_section_with_total_limit(
        section,
        proxies,
        upstreams,
        plugin_configs,
        max_spec_body_mib,
        100 * 1024 * 1024,
    )
}

pub(crate) fn validate_restore_api_specs_section_with_total_limit(
    section: &ApiSpecsBackupSection,
    proxies: &[Proxy],
    upstreams: &[Upstream],
    plugin_configs: &[PluginConfig],
    max_spec_body_mib: usize,
    max_total_spec_bytes: usize,
) -> Result<Vec<ApiSpec>, Vec<String>> {
    let mut errors = Vec::new();
    if section.section_version != "1" && section.section_version != API_SPECS_BACKUP_SECTION_VERSION
    {
        errors.push("Unsupported api_specs.section_version".to_string());
        return Err(errors);
    }

    let max_uncompressed = max_spec_body_mib.saturating_mul(1024 * 1024);
    let declared_total: u128 = section
        .items
        .iter()
        .map(|item| u128::from(item.uncompressed_size))
        .sum();
    if declared_total > max_total_spec_bytes as u128 {
        errors
            .push("api_specs: aggregate uncompressed_size exceeds restore body limit".to_string());
        return Err(errors);
    }
    // Compressed payload bound: reject absurd base64 that would decode past the
    // admin body ceiling even before gzip expansion.
    let max_compressed = max_uncompressed.saturating_mul(2).max(1024 * 1024);
    let mut seen_ids = HashSet::new();
    let mut seen_proxy_ids = HashSet::new();
    let proxy_by_id: HashMap<&str, &Proxy> = proxies
        .iter()
        .map(|proxy| (proxy.id.as_str(), proxy))
        .collect();

    let mut specs = Vec::with_capacity(section.items.len());
    let mut total_decompressed = 0usize;
    for item in &section.items {
        if let Err(error) = crate::config::types::validate_resource_id(&item.id) {
            errors.push(format!("api_spec id: {error}"));
            continue;
        }
        if let Err(error) = crate::config::types::validate_resource_id(&item.proxy_id) {
            errors.push(format!("api_spec '{}': proxy_id: {error}", item.id));
            continue;
        }
        if !seen_ids.insert(item.id.clone()) {
            errors.push(format!("duplicate api_spec id '{}'", item.id));
            continue;
        }
        if !seen_proxy_ids.insert(item.proxy_id.clone()) {
            errors.push(format!(
                "api_spec '{}': duplicate proxy_id '{}'",
                item.id, item.proxy_id
            ));
            continue;
        }
        if item.content_encoding != "gzip" {
            errors.push(format!(
                "api_spec '{}': unsupported content_encoding (expected gzip)",
                item.id
            ));
            continue;
        }
        if u128::from(item.uncompressed_size) > max_uncompressed as u128 {
            errors.push(format!(
                "api_spec '{}': uncompressed_size exceeds admin spec body limit",
                item.id
            ));
            continue;
        }
        if !item.resource_hash.is_empty()
            && (item.resource_hash.len() != 64
                || !item
                    .resource_hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            errors.push(format!(
                "api_spec '{}': resource_hash must be empty or lowercase SHA-256 hex",
                item.id
            ));
            continue;
        }
        // Bound base64 length before decode to avoid hostile allocation.
        let max_b64_len = max_compressed
            .saturating_mul(4)
            .saturating_div(3)
            .saturating_add(8);
        if item.spec_content_base64.len() > max_b64_len {
            errors.push(format!(
                "api_spec '{}': spec_content_base64 exceeds size limit",
                item.id
            ));
            continue;
        }
        let spec = match item.to_api_spec() {
            Ok(spec) => spec,
            Err(message) => {
                errors.push(message);
                continue;
            }
        };
        if spec.spec_content.len() > max_compressed {
            errors.push(format!(
                "api_spec '{}': compressed content exceeds size limit",
                item.id
            ));
            continue;
        }
        let decompressed = match crate::admin::spec_codec::decompress_gzip_capped(
            &spec.spec_content,
            max_uncompressed,
        ) {
            Ok(bytes) => bytes,
            Err(_) => {
                errors.push(format!(
                    "api_spec '{}': compressed content is corrupt or oversized",
                    item.id
                ));
                return Err(errors);
            }
        };
        total_decompressed = total_decompressed.saturating_add(decompressed.len());
        if total_decompressed > max_total_spec_bytes {
            errors.push(
                "api_specs: aggregate decompressed content exceeds restore body limit".to_string(),
            );
            return Err(errors);
        }
        if decompressed.len() as u64 != spec.uncompressed_size {
            errors.push(format!(
                "api_spec '{}': uncompressed_size does not match decompressed content",
                item.id
            ));
            continue;
        }
        let actual_hash = crate::admin::spec_codec::sha256_hex(&decompressed);
        if actual_hash != spec.content_hash {
            errors.push(format!(
                "api_spec '{}': content_hash does not match decompressed content",
                item.id
            ));
            continue;
        }
        // Fail closed on stored metadata: restore must not admit bounds,
        // cardinality, sort/dedup, or tag-whitelist violations that ordinary
        // POST/PUT extraction rejects. Do not echo hostile field values.
        if let Err(reason) = crate::admin::api_specs::extractor::validate_stored_api_spec_metadata(
            spec.title.as_deref(),
            spec.info_version.as_deref(),
            spec.description.as_deref(),
            spec.contact_name.as_deref(),
            spec.contact_email.as_deref(),
            spec.license_name.as_deref(),
            spec.license_identifier.as_deref(),
            &spec.tags,
            &spec.server_urls,
        ) {
            errors.push(format!("api_spec '{}': {reason}", item.id));
            continue;
        }
        // Validate document syntax for the *declared* format with the same
        // bounded parser as ingestion, and detect the spec-language version the
        // document actually declares. Do not re-extract resources or resolve
        // external refs — historical backups must remain restorable as-is.
        // Parse errors are mapped to generic messages so serde snippets that
        // may contain document fragments never enter operator responses/logs.
        let document_version =
            match crate::admin::api_specs::extractor::parse_declared_spec_document_version(
                &decompressed,
                spec.spec_format,
            ) {
                Ok(version) => version,
                Err(parse_error) => {
                    let reason = match parse_error {
                        crate::admin::api_specs::ExtractError::InvalidJson(_) => {
                            "document is not valid JSON for declared spec_format"
                        }
                        crate::admin::api_specs::ExtractError::InvalidYaml(_) => {
                            "document is not valid YAML for declared spec_format"
                        }
                        crate::admin::api_specs::ExtractError::UnknownVersion => {
                            "document declares no supported OpenAPI or Swagger version"
                        }
                        _ => "document failed bounded format validation",
                    };
                    errors.push(format!("api_spec '{}': {reason}", item.id));
                    continue;
                }
            };
        // Stored `spec_version` is what `GET /api-specs` reports and what
        // version-sensitive tooling keys off. A backup that claims one version
        // while carrying a document that declares another must not persist.
        // Never echo either value — both are attacker-controlled.
        if document_version != spec.spec_version {
            errors.push(format!(
                "api_spec '{}': spec_version does not match the version declared by the document",
                item.id
            ));
            continue;
        }
        match proxy_by_id.get(spec.proxy_id.as_str()) {
            Some(proxy) if proxy.api_spec_id.as_deref() == Some(spec.id.as_str()) => {}
            Some(_) => {
                errors.push(format!(
                    "api_spec '{}': owning proxy '{}' must carry api_spec_id '{}'",
                    spec.id, spec.proxy_id, spec.id
                ));
                continue;
            }
            None => {
                errors.push(format!(
                    "api_spec '{}': owning proxy '{}' is missing from the restore payload",
                    spec.id, spec.proxy_id
                ));
                continue;
            }
        }
        specs.push(spec);
    }

    // Owned resources must not reference specs absent from the section.
    for proxy in proxies {
        if let Some(spec_id) = proxy.api_spec_id.as_deref()
            && !seen_ids.contains(spec_id)
        {
            errors.push(format!(
                "proxy '{}': api_spec_id '{}' is not present in api_specs.items",
                proxy.id, spec_id
            ));
        }
    }
    for upstream in upstreams {
        if let Some(spec_id) = upstream.api_spec_id.as_deref()
            && !seen_ids.contains(spec_id)
        {
            errors.push(format!(
                "upstream '{}': api_spec_id '{}' is not present in api_specs.items",
                upstream.id, spec_id
            ));
        }
    }
    for plugin in plugin_configs {
        if let Some(spec_id) = plugin.api_spec_id.as_deref()
            && !seen_ids.contains(spec_id)
        {
            errors.push(format!(
                "plugin_config '{}': api_spec_id '{}' is not present in api_specs.items",
                plugin.id, spec_id
            ));
        }
    }

    validate_restore_api_spec_ownership_graph(
        &specs,
        proxies,
        upstreams,
        plugin_configs,
        &mut errors,
    );

    if errors.is_empty() {
        Ok(specs)
    } else {
        Err(errors)
    }
}

/// Reject server-managed ownership graphs that the API-spec lifecycle can never
/// produce and whose `PUT`/`DELETE` cleanup would therefore corrupt.
///
/// The checks mirror invariants already enforced elsewhere rather than inventing
/// a second policy:
///
/// * exactly one proxy carries a spec's id and it is that spec's `proxy_id`
///   (spec extraction stamps the owning proxy and nothing else);
/// * a spec owns at most one upstream (`load_single_spec_owned_upstream` and the
///   direct-proxy-delete recovery path both treat more as unrecoverable);
/// * a spec-owned upstream is only referenced by its own proxy (`Proxy::
///   after_validate` refuses attaching a spec-owned upstream to any other proxy);
/// * every spec-owned plugin is valid for the owning proxy per
///   [`validate_api_spec_proxy_plugin_association`] and is actually associated
///   with it (extraction always rebuilds `proxy.plugins` from the spec plugins).
///
/// Hand-managed resources (`api_spec_id == None`) are never inspected, so the
/// direct-admin drift that API-spec `PUT`/`DELETE` deliberately supports —
/// hand-added plugins/upstreams attached to a spec-owned proxy, or a spec-owned
/// proxy pointed at a hand-managed upstream — still restores unchanged.
///
/// Errors name only ids that already passed resource-id validation on the
/// canonical restore candidate; no document content or metadata is echoed.
fn validate_restore_api_spec_ownership_graph(
    specs: &[ApiSpec],
    proxies: &[Proxy],
    upstreams: &[Upstream],
    plugin_configs: &[PluginConfig],
    errors: &mut Vec<String>,
) {
    let mut proxies_by_spec: HashMap<&str, Vec<&Proxy>> = HashMap::new();
    for proxy in proxies {
        if let Some(spec_id) = proxy.api_spec_id.as_deref() {
            proxies_by_spec.entry(spec_id).or_default().push(proxy);
        }
    }
    let mut upstreams_by_spec: HashMap<&str, Vec<&Upstream>> = HashMap::new();
    for upstream in upstreams {
        if let Some(spec_id) = upstream.api_spec_id.as_deref() {
            upstreams_by_spec.entry(spec_id).or_default().push(upstream);
        }
    }
    let mut plugins_by_spec: HashMap<&str, Vec<&PluginConfig>> = HashMap::new();
    for plugin in plugin_configs {
        if let Some(spec_id) = plugin.api_spec_id.as_deref() {
            plugins_by_spec.entry(spec_id).or_default().push(plugin);
        }
    }

    for spec in specs {
        let spec_id = spec.id.as_str();
        let owning_proxy_id = spec.proxy_id.as_str();
        let tagged_proxies = proxies_by_spec
            .get(spec_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        // The per-item pass already proved the declared owner carries the tag,
        // so anything other than exactly that one proxy is a second claimant.
        if tagged_proxies.len() != 1 || tagged_proxies[0].id != spec.proxy_id {
            errors.push(format!(
                "api_spec '{spec_id}': exactly one proxy may carry this api_spec_id and it must be the declared owning proxy '{owning_proxy_id}'"
            ));
            continue;
        }
        let owning_proxy = tagged_proxies[0];

        let owned_upstreams = upstreams_by_spec
            .get(spec_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if owned_upstreams.len() > 1 {
            errors.push(format!(
                "api_spec '{spec_id}': owns {} upstreams; at most one spec-owned upstream is supported",
                owned_upstreams.len()
            ));
        }
        for upstream in owned_upstreams {
            for proxy in proxies {
                if proxy.id != owning_proxy_id
                    && proxy.upstream_id.as_deref() == Some(upstream.id.as_str())
                {
                    errors.push(format!(
                        "api_spec '{spec_id}': spec-owned upstream '{}' is referenced by proxy '{}', which this api_spec does not own",
                        upstream.id, proxy.id
                    ));
                }
            }
        }

        let associated_plugin_ids: HashSet<&str> = owning_proxy
            .plugins
            .iter()
            .map(|association| association.plugin_config_id.as_str())
            .collect();
        let owned_plugins = plugins_by_spec
            .get(spec_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        for plugin in owned_plugins {
            if validate_api_spec_proxy_plugin_association(plugin, owning_proxy_id).is_err() {
                errors.push(format!(
                    "api_spec '{spec_id}': spec-owned plugin_config '{}' is not a valid association for owning proxy '{owning_proxy_id}'",
                    plugin.id
                ));
                continue;
            }
            if !associated_plugin_ids.contains(plugin.id.as_str()) {
                errors.push(format!(
                    "api_spec '{spec_id}': spec-owned plugin_config '{}' is not associated with owning proxy '{owning_proxy_id}'",
                    plugin.id
                ));
            }
        }
    }
}

/// Clear ownership tags so restored resources become hand-managed after a
/// confirmed legacy restore that permanently deletes API specs.
pub(crate) fn clear_api_spec_ownership_tags(payload: &mut RestorePayload) {
    for proxy in &mut payload.proxies {
        proxy.api_spec_id = None;
    }
    for upstream in &mut payload.upstreams {
        upstream.api_spec_id = None;
    }
    for plugin in &mut payload.plugin_configs {
        plugin.api_spec_id = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_config() -> GatewayConfig {
        serde_json::from_value(json!({
            "version": "1",
            "known_namespaces": ["tenant-a", "tenant-b"],
            "proxies": [
                {
                    "id": "proxy-a",
                    "namespace": "tenant-a",
                    "listen_path": "/a",
                    "backend_scheme": "http",
                    "backend_host": "a.internal",
                    "backend_port": 8080
                },
                {
                    "id": "proxy-b",
                    "namespace": "tenant-b",
                    "listen_path": "/b",
                    "backend_scheme": "http",
                    "backend_host": "b.internal",
                    "backend_port": 8080
                }
            ],
            "consumers": [
                {"id": "consumer-a", "username": "alice", "namespace": "tenant-a"},
                {"id": "consumer-b", "username": "bob", "namespace": "tenant-b"}
            ],
            "plugin_configs": [
                {
                    "id": "plugin-a",
                    "plugin_name": "key_auth",
                    "namespace": "tenant-a",
                    "scope": "global",
                    "config": {}
                },
                {
                    "id": "plugin-b",
                    "plugin_name": "key_auth",
                    "namespace": "tenant-b",
                    "scope": "global",
                    "config": {}
                }
            ],
            "upstreams": [
                {"id": "upstream-a", "name": "up-a", "namespace": "tenant-a", "targets": []},
                {"id": "upstream-b", "name": "up-b", "namespace": "tenant-b", "targets": []}
            ]
        }))
        .expect("sample config should deserialize")
    }

    #[test]
    fn parse_backup_resources_absent_query_is_unfiltered() {
        assert_eq!(parse_backup_resources(None), Ok(None));
        assert_eq!(parse_backup_resources(Some("page=1")), Ok(None));
    }

    #[test]
    fn parse_backup_resources_trims_and_ignores_empty_tokens() {
        let resources =
            parse_backup_resources(Some("download=true&resources=proxies, upstreams,,"))
                .expect("resources filter should parse")
                .expect("resources filter should be present");

        assert!(resources.contains("proxies"));
        assert!(resources.contains("upstreams"));
        assert_eq!(resources.len(), 2);
    }

    #[test]
    fn parse_backup_resources_key_only_is_malformed() {
        assert_eq!(
            parse_backup_resources(Some("resources")),
            Err(BackupResourcesQueryMalformed)
        );
        assert_eq!(
            parse_backup_resources(Some("download=true&resources")),
            Err(BackupResourcesQueryMalformed)
        );
        assert_eq!(
            parse_backup_resources(Some("resources&page=1")),
            Err(BackupResourcesQueryMalformed)
        );
    }

    #[test]
    fn parse_backup_resources_duplicate_occurrences_are_malformed() {
        assert_eq!(
            parse_backup_resources(Some("resources=proxies&resources=consumers")),
            Err(BackupResourcesQueryMalformed)
        );
        assert_eq!(
            parse_backup_resources(Some("resources=proxies&resources=proxies")),
            Err(BackupResourcesQueryMalformed)
        );
        assert_eq!(
            parse_backup_resources(Some("resources=proxies&resources")),
            Err(BackupResourcesQueryMalformed)
        );
    }

    #[test]
    fn parse_backup_resources_empty_value_is_present_empty_filter() {
        let empty = parse_backup_resources(Some("resources="))
            .expect("empty value is structurally valid")
            .expect("parameter present");
        assert!(empty.is_empty());
    }

    #[test]
    fn validate_backup_resources_allowlist_rejects_unknown_without_echoing() {
        assert!(validate_backup_resources_allowlist(None).is_ok());
        let known = parse_backup_resources(Some("resources=proxies,consumers"))
            .expect("parse known")
            .expect("present");
        assert!(validate_backup_resources_allowlist(Some(&known)).is_ok());

        let unknown =
            parse_backup_resources(Some("resources=proxies,canary-secret-token-never-echoed"))
                .expect("parse unknown")
                .expect("present");
        assert_eq!(
            validate_backup_resources_allowlist(Some(&unknown)),
            Err(BACKUP_UNSUPPORTED_RESOURCE_FILTER_ERROR)
        );
        assert!(!BACKUP_UNSUPPORTED_RESOURCE_FILTER_ERROR.contains("canary"));
    }

    #[test]
    fn validate_backup_api_specs_resource_filter_accepts_no_filter_and_non_spec_filters() {
        assert!(validate_backup_api_specs_resource_filter(None).is_ok());

        let proxies_only = parse_backup_resources(Some("resources=proxies"))
            .expect("parse proxies")
            .expect("present");
        assert!(validate_backup_api_specs_resource_filter(Some(&proxies_only)).is_ok());

        let without_specs =
            parse_backup_resources(Some("resources=proxies,consumers,plugin_configs,upstreams"))
                .expect("parse without api_specs")
                .expect("present");
        assert!(validate_backup_api_specs_resource_filter(Some(&without_specs)).is_ok());
    }

    #[test]
    fn validate_backup_api_specs_resource_filter_requires_owning_resource_classes() {
        let api_specs_only = parse_backup_resources(Some("resources=api_specs"))
            .expect("parse api_specs")
            .expect("present");
        assert_eq!(
            validate_backup_api_specs_resource_filter(Some(&api_specs_only)),
            Err(BACKUP_API_SPECS_FILTER_DEPENDENCY_ERROR)
        );

        let missing_plugins = parse_backup_resources(Some("resources=api_specs,proxies,upstreams"))
            .expect("parse missing plugin_configs")
            .expect("present");
        assert_eq!(
            validate_backup_api_specs_resource_filter(Some(&missing_plugins)),
            Err(BACKUP_API_SPECS_FILTER_DEPENDENCY_ERROR)
        );

        let missing_upstreams =
            parse_backup_resources(Some("resources=api_specs,proxies,plugin_configs"))
                .expect("parse missing upstreams")
                .expect("present");
        assert_eq!(
            validate_backup_api_specs_resource_filter(Some(&missing_upstreams)),
            Err(BACKUP_API_SPECS_FILTER_DEPENDENCY_ERROR)
        );

        let missing_proxies =
            parse_backup_resources(Some("resources=api_specs,upstreams,plugin_configs"))
                .expect("parse missing proxies")
                .expect("present");
        assert_eq!(
            validate_backup_api_specs_resource_filter(Some(&missing_proxies)),
            Err(BACKUP_API_SPECS_FILTER_DEPENDENCY_ERROR)
        );
    }

    #[test]
    fn validate_backup_api_specs_resource_filter_accepts_complete_combination_any_order() {
        let complete = parse_backup_resources(Some(
            "resources= plugin_configs ,api_specs, proxies , upstreams ",
        ))
        .expect("parse complete filter with whitespace")
        .expect("present");
        assert!(validate_backup_api_specs_resource_filter(Some(&complete)).is_ok());

        let with_consumers = parse_backup_resources(Some(
            "resources=api_specs,proxies,upstreams,plugin_configs,consumers",
        ))
        .expect("parse with optional consumers")
        .expect("present");
        assert!(validate_backup_api_specs_resource_filter(Some(&with_consumers)).is_ok());
    }

    #[test]
    fn parse_restore_confirm_requires_true_value() {
        assert!(!parse_restore_confirm(None));
        assert!(!parse_restore_confirm(Some("confirm=false")));
        assert!(!parse_restore_confirm(Some("confirm=True")));
        assert!(parse_restore_confirm(Some("dry_run=false&confirm=true")));
    }

    #[test]
    fn parse_confirm_api_spec_deletion_requires_true_value() {
        assert!(!parse_confirm_api_spec_deletion(None));
        assert!(!parse_confirm_api_spec_deletion(Some(
            "confirm=true&confirm_api_spec_deletion=false"
        )));
        assert!(parse_confirm_api_spec_deletion(Some(
            "confirm=true&confirm_api_spec_deletion=true"
        )));
    }

    #[test]
    fn filter_config_by_namespace_keeps_only_matching_resources() {
        let filtered = filter_config_by_namespace(&sample_config(), "tenant-a");

        assert_eq!(filtered.version, "1");
        assert_eq!(filtered.known_namespaces, vec!["tenant-a", "tenant-b"]);
        assert_eq!(filtered.proxies.len(), 1);
        assert_eq!(filtered.proxies[0].id, "proxy-a");
        assert_eq!(filtered.consumers.len(), 1);
        assert_eq!(filtered.consumers[0].id, "consumer-a");
        assert_eq!(filtered.plugin_configs.len(), 1);
        assert_eq!(filtered.plugin_configs[0].id, "plugin-a");
        assert_eq!(filtered.upstreams.len(), 1);
        assert_eq!(filtered.upstreams[0].id, "upstream-a");
    }

    #[test]
    fn filter_config_by_namespace_returns_empty_resource_sets_for_miss() {
        let filtered = filter_config_by_namespace(&sample_config(), "tenant-c");

        assert!(filtered.proxies.is_empty());
        assert!(filtered.consumers.is_empty());
        assert!(filtered.plugin_configs.is_empty());
        assert!(filtered.upstreams.is_empty());
        assert_eq!(filtered.known_namespaces, vec!["tenant-a", "tenant-b"]);
    }

    #[test]
    fn api_spec_backup_item_round_trips_base64_content() {
        let content = br#"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"x-ferrum-proxy":{"id":"p"}}"#;
        let compressed = crate::admin::spec_codec::compress_gzip(content).expect("compress");
        let spec = ApiSpec {
            id: "spec-1".to_string(),
            namespace: "ferrum".to_string(),
            proxy_id: "proxy-1".to_string(),
            spec_version: "3.1.0".to_string(),
            spec_format: SpecFormat::Json,
            spec_content: compressed.clone(),
            content_encoding: "gzip".to_string(),
            uncompressed_size: content.len() as u64,
            content_hash: crate::admin::spec_codec::sha256_hex(content),
            title: Some("t".to_string()),
            info_version: Some("1".to_string()),
            description: None,
            contact_name: None,
            contact_email: None,
            license_name: None,
            license_identifier: None,
            tags: vec!["a".to_string()],
            server_urls: vec![],
            operation_count: 0,
            resource_hash: "abc".to_string(),
            external_ref_snapshot: None,
            external_ref_digest: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let item = ApiSpecBackupItem::from_api_spec(&spec);
        let restored = item.to_api_spec().expect("decode");
        assert_eq!(restored.spec_content, compressed);
        assert_eq!(restored.content_hash, spec.content_hash);
        assert!(!item.spec_content_base64.is_empty());
        assert!(!item.spec_content_base64.starts_with('['));
    }

    #[test]
    fn restore_payload_distinguishes_omitted_api_specs_section() {
        let legacy: RestorePayload = serde_json::from_value(json!({
            "proxies": []
        }))
        .expect("legacy payload");
        assert!(legacy.api_specs.is_none());

        let present: RestorePayload = serde_json::from_value(json!({
            "proxies": [],
            "api_specs": {
                "section_version": "1",
                "items": []
            }
        }))
        .expect("present section");
        assert!(present.api_specs.is_some());
        assert!(present.api_specs.as_ref().unwrap().items.is_empty());
    }

    fn sample_owned_proxy(spec_id: &str, proxy_id: &str) -> Proxy {
        serde_json::from_value(json!({
            "id": proxy_id,
            "namespace": "ferrum",
            "backend_host": "backend.example.com",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id}"),
            "api_spec_id": spec_id
        }))
        .expect("proxy")
    }

    fn sample_spec_item(spec_id: &str, proxy_id: &str, raw: &[u8]) -> ApiSpecBackupItem {
        let compressed = crate::admin::spec_codec::compress_gzip(raw).expect("compress");
        ApiSpecBackupItem {
            id: spec_id.to_string(),
            namespace: "ferrum".to_string(),
            proxy_id: proxy_id.to_string(),
            spec_version: "3.1.0".to_string(),
            spec_format: SpecFormat::Json,
            spec_content_base64: base64::engine::general_purpose::STANDARD.encode(&compressed),
            content_encoding: "gzip".to_string(),
            uncompressed_size: raw.len() as u64,
            content_hash: crate::admin::spec_codec::sha256_hex(raw),
            title: Some("t".to_string()),
            info_version: Some("1".to_string()),
            description: None,
            contact_name: None,
            contact_email: None,
            license_name: None,
            license_identifier: None,
            tags: vec![],
            server_urls: vec![],
            operation_count: 0,
            resource_hash: "a".repeat(64),
            external_ref_snapshot_base64: None,
            external_ref_digest: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn validate_api_specs_section_accepts_json_and_yaml_round_trip_items() {
        let json_raw = br#"{"openapi":"3.1.0","info":{"title":"j","version":"1"},"paths":{}}"#;
        let yaml_raw = b"openapi: \"3.0.3\"\ninfo:\n  title: y\n  version: \"1\"\npaths: {}\n";
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![sample_spec_item("spec-json", "proxy-json", json_raw), {
                let mut item = sample_spec_item("spec-yaml", "proxy-yaml", yaml_raw);
                item.spec_format = SpecFormat::Yaml;
                item.spec_version = "3.0.3".to_string();
                item
            }],
        };
        let proxies = vec![
            sample_owned_proxy("spec-json", "proxy-json"),
            sample_owned_proxy("spec-yaml", "proxy-yaml"),
        ];
        let specs = validate_restore_api_specs_section(&section, &proxies, &[], &[], 25)
            .expect("valid section");
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].spec_format, SpecFormat::Json);
        assert_eq!(specs[1].spec_format, SpecFormat::Yaml);
    }

    #[test]
    fn validate_api_specs_section_rejects_hostile_size_and_shape() {
        let raw = br#"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{}}"#;
        let mut item = sample_spec_item("spec-1", "proxy-1", raw);
        item.spec_content_base64 = "!!!not-base64!!!".to_string();
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![item],
        };
        let proxies = vec![sample_owned_proxy("spec-1", "proxy-1")];
        let err = validate_restore_api_specs_section(&section, &proxies, &[], &[], 25)
            .expect_err("bad base64");
        assert!(
            err.iter()
                .any(|e| e.contains("invalid spec_content_base64"))
        );

        let mut oversized = sample_spec_item("spec-2", "proxy-2", raw);
        oversized.uncompressed_size = 50 * 1024 * 1024;
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![oversized],
        };
        let proxies = vec![sample_owned_proxy("spec-2", "proxy-2")];
        let err = validate_restore_api_specs_section(&section, &proxies, &[], &[], 1)
            .expect_err("oversized");
        assert!(
            err.iter()
                .any(|e| e.contains("uncompressed_size exceeds admin spec body limit"))
        );

        let mut wrong_hash = sample_spec_item("spec-3", "proxy-3", raw);
        wrong_hash.content_hash = "0".repeat(64);
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![wrong_hash],
        };
        let proxies = vec![sample_owned_proxy("spec-3", "proxy-3")];
        let err = validate_restore_api_specs_section(&section, &proxies, &[], &[], 25)
            .expect_err("hash mismatch");
        assert!(
            err.iter()
                .any(|e| e.contains("content_hash does not match"))
        );

        let section = ApiSpecsBackupSection {
            section_version: "99".to_string(),
            items: vec![],
        };
        let err = validate_restore_api_specs_section(&section, &[], &[], &[], 25)
            .expect_err("bad version");
        assert!(
            err.iter()
                .any(|e| e.contains("Unsupported api_specs.section_version"))
        );
        assert!(err.iter().all(|e| !e.contains("99")));
    }

    #[test]
    fn validate_api_specs_section_rejects_aggregate_expansion_before_decompression() {
        let raw = br#"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{}}"#;
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![
                sample_spec_item("spec-1", "proxy-1", raw),
                sample_spec_item("spec-2", "proxy-2", raw),
            ],
        };
        let err = validate_restore_api_specs_section_with_total_limit(
            &section,
            &[],
            &[],
            &[],
            25,
            raw.len().saturating_mul(2).saturating_sub(1),
        )
        .expect_err("aggregate expansion must be bounded");
        assert_eq!(
            err,
            vec!["api_specs: aggregate uncompressed_size exceeds restore body limit"]
        );
    }

    #[test]
    fn validate_api_specs_section_rejects_actual_expansion_over_aggregate_limit() {
        let raw = br#"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{}}"#;
        let mut item = sample_spec_item("spec-1", "proxy-1", raw);
        item.uncompressed_size = 0;
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![item],
        };
        let err = validate_restore_api_specs_section_with_total_limit(
            &section,
            &[],
            &[],
            &[],
            25,
            raw.len().saturating_sub(1),
        )
        .expect_err("actual expansion must be bounded");
        assert_eq!(
            err,
            vec!["api_specs: aggregate decompressed content exceeds restore body limit"]
        );
    }

    #[test]
    fn validate_api_specs_section_rejects_unbounded_resource_hash() {
        let raw = br#"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{}}"#;
        let mut item = sample_spec_item("spec-1", "proxy-1", raw);
        item.resource_hash = "not-a-sha256".to_string();
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![item],
        };
        let proxies = vec![sample_owned_proxy("spec-1", "proxy-1")];
        let err = validate_restore_api_specs_section(&section, &proxies, &[], &[], 25)
            .expect_err("resource hash must be bounded");
        assert!(
            err.iter()
                .any(|e| e.contains("resource_hash must be empty or lowercase SHA-256 hex"))
        );
    }

    #[test]
    fn validate_api_specs_section_rejects_orphan_ownership_tags() {
        let raw = br#"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{}}"#;
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![sample_spec_item("spec-1", "proxy-1", raw)],
        };
        let proxies = vec![sample_owned_proxy("spec-1", "proxy-1")];
        let mut upstream: Upstream = serde_json::from_value(json!({
            "id": "up-1",
            "name": "up-1",
            "namespace": "ferrum",
            "targets": [],
            "api_spec_id": "missing-spec"
        }))
        .expect("upstream");
        let err =
            validate_restore_api_specs_section(&section, &proxies, &[upstream.clone()], &[], 25)
                .expect_err("orphan upstream tag");
        assert!(err.iter().any(|e| e.contains("upstream 'up-1'")));

        upstream.api_spec_id = Some("spec-1".to_string());
        let plugin: PluginConfig = serde_json::from_value(json!({
            "id": "plug-1",
            "plugin_name": "key_auth",
            "namespace": "ferrum",
            "scope": "proxy",
            "proxy_id": "proxy-1",
            "config": {},
            "api_spec_id": "missing-spec"
        }))
        .expect("plugin");
        let err =
            validate_restore_api_specs_section(&section, &proxies, &[upstream], &[plugin], 25)
                .expect_err("orphan plugin tag");
        assert!(err.iter().any(|e| e.contains("plugin_config 'plug-1'")));
    }

    #[test]
    fn validate_api_specs_section_rejects_hostile_metadata_and_format_mismatch() {
        let raw = br#"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{}}"#;
        let proxies = vec![sample_owned_proxy("spec-1", "proxy-1")];

        // Forbidden LIKE wildcard in a stored tag must fail closed.
        let mut item = sample_spec_item("spec-1", "proxy-1", raw);
        item.tags = vec!["api_v1".to_string()];
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![item],
        };
        let err = validate_restore_api_specs_section(&section, &proxies, &[], &[], 25)
            .expect_err("forbidden tag");
        assert!(
            err.iter()
                .any(|e| e.contains("tag contains forbidden character")),
            "expected forbidden-tag rejection, got {err:?}"
        );
        // Hostile tag value must not be echoed into the validation error.
        assert!(
            err.iter().all(|e| !e.contains("api_v1")),
            "validation errors must not echo hostile tag values: {err:?}"
        );

        // Oversized title exceeds the shared extraction bound.
        let mut item = sample_spec_item("spec-1", "proxy-1", raw);
        item.title = Some("t".repeat(1025));
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![item],
        };
        let err = validate_restore_api_specs_section(&section, &proxies, &[], &[], 25)
            .expect_err("oversized title");
        assert!(
            err.iter()
                .any(|e| e.contains("title exceeds maximum length")),
            "expected title bound rejection, got {err:?}"
        );

        // Unsorted / duplicate tags violate the list/filter membership invariant.
        let mut item = sample_spec_item("spec-1", "proxy-1", raw);
        item.tags = vec!["b".to_string(), "a".to_string()];
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![item],
        };
        let err = validate_restore_api_specs_section(&section, &proxies, &[], &[], 25)
            .expect_err("unsorted tags");
        assert!(
            err.iter()
                .any(|e| e.contains("tags must be sorted and de-duplicated")),
            "expected sorted/deduped rejection, got {err:?}"
        );

        // Declared JSON with YAML body must not be admitted.
        let yaml_raw = b"openapi: \"3.0.3\"\ninfo:\n  title: y\n  version: \"1\"\npaths: {}\n";
        let mut item = sample_spec_item("spec-1", "proxy-1", yaml_raw);
        item.spec_format = SpecFormat::Json;
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![item],
        };
        let err = validate_restore_api_specs_section(&section, &proxies, &[], &[], 25)
            .expect_err("format mismatch");
        assert!(
            err.iter()
                .any(|e| e.contains("document is not valid JSON for declared spec_format")),
            "expected declared-format rejection, got {err:?}"
        );

        // Too many server URLs.
        let mut item = sample_spec_item("spec-1", "proxy-1", raw);
        item.server_urls = (0..33)
            .map(|i| format!("https://example.test/{i}"))
            .collect();
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![item],
        };
        let err = validate_restore_api_specs_section(&section, &proxies, &[], &[], 25)
            .expect_err("too many server_urls");
        assert!(
            err.iter()
                .any(|e| e.contains("server_urls exceed maximum cardinality")),
            "expected server_urls cardinality rejection, got {err:?}"
        );
    }

    #[test]
    fn validate_api_specs_section_rejects_unknown_and_mismatched_spec_versions() {
        let proxies = vec![sample_owned_proxy("spec-1", "proxy-1")];

        // A document with no supported OpenAPI/Swagger version must not persist,
        // even though it is syntactically valid JSON for the declared format.
        let versionless = br#"{"info":{"title":"t","version":"1"},"paths":{}}"#;
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![sample_spec_item("spec-1", "proxy-1", versionless)],
        };
        let err = validate_restore_api_specs_section(&section, &proxies, &[], &[], 25)
            .expect_err("versionless document");
        assert!(
            err.iter()
                .any(|e| e.contains("declares no supported OpenAPI or Swagger version")),
            "expected unknown-version rejection, got {err:?}"
        );

        // Stored `spec_version` must equal the version the document declares.
        let raw = br#"{"swagger":"2.0","info":{"title":"t","version":"1"},"paths":{}}"#;
        let mut item = sample_spec_item("spec-1", "proxy-1", raw);
        item.spec_version = "3.1.0".to_string();
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![item],
        };
        let err = validate_restore_api_specs_section(&section, &proxies, &[], &[], 25)
            .expect_err("version mismatch");
        assert!(
            err.iter()
                .any(|e| e.contains("spec_version does not match the version")),
            "expected version-mismatch rejection, got {err:?}"
        );

        // The matching declaration still restores.
        let mut item = sample_spec_item("spec-1", "proxy-1", raw);
        item.spec_version = "2.0".to_string();
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![item],
        };
        let specs = validate_restore_api_specs_section(&section, &proxies, &[], &[], 25)
            .expect("matching swagger 2.0 version must restore");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].spec_version, "2.0");
    }

    fn owned_proxy_scoped_plugin(
        plugin_id: &str,
        proxy_id: &str,
        spec_id: &str,
    ) -> serde_json::Value {
        json!({
            "id": plugin_id,
            "plugin_name": "key_auth",
            "namespace": "ferrum",
            "scope": "proxy",
            "proxy_id": proxy_id,
            "config": {},
            "api_spec_id": spec_id
        })
    }

    fn owned_upstream(upstream_id: &str, spec_id: &str) -> Upstream {
        serde_json::from_value(json!({
            "id": upstream_id,
            "name": upstream_id,
            "namespace": "ferrum",
            "targets": [],
            "api_spec_id": spec_id
        }))
        .expect("upstream")
    }

    #[test]
    fn validate_api_specs_section_rejects_impossible_ownership_graphs() {
        let raw = br#"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{}}"#;
        let section = || ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![sample_spec_item("spec-1", "proxy-1", raw)],
        };

        // A second proxy claiming the same spec id is unreachable through the
        // API-spec lifecycle and would make PUT/DELETE cleanup ambiguous.
        let proxies = vec![
            sample_owned_proxy("spec-1", "proxy-1"),
            sample_owned_proxy("spec-1", "proxy-2"),
        ];
        let err = validate_restore_api_specs_section(&section(), &proxies, &[], &[], 25)
            .expect_err("second claimant proxy");
        assert!(
            err.iter()
                .any(|e| e.contains("exactly one proxy may carry this api_spec_id")),
            "expected second-claimant rejection, got {err:?}"
        );

        // Two spec-owned upstreams for one spec break the single-owned-upstream
        // lifecycle invariant.
        let proxies = vec![sample_owned_proxy("spec-1", "proxy-1")];
        let upstreams = vec![
            owned_upstream("up-1", "spec-1"),
            owned_upstream("up-2", "spec-1"),
        ];
        let err = validate_restore_api_specs_section(&section(), &proxies, &upstreams, &[], 25)
            .expect_err("multiple owned upstreams");
        assert!(
            err.iter()
                .any(|e| e.contains("at most one spec-owned upstream is supported")),
            "expected single-owned-upstream rejection, got {err:?}"
        );

        // A spec-owned upstream may not be attached to a proxy the spec does not
        // own; direct admin already refuses that attachment.
        let mut foreign_proxy = sample_owned_proxy("spec-1", "proxy-1");
        foreign_proxy.id = "proxy-hand".to_string();
        foreign_proxy.listen_path = Some("/hand".to_string());
        foreign_proxy.api_spec_id = None;
        foreign_proxy.upstream_id = Some("up-1".to_string());
        let proxies = vec![sample_owned_proxy("spec-1", "proxy-1"), foreign_proxy];
        let err = validate_restore_api_specs_section(
            &section(),
            &proxies,
            &[owned_upstream("up-1", "spec-1")],
            &[],
            25,
        )
        .expect_err("foreign reference to a spec-owned upstream");
        assert!(
            err.iter()
                .any(|e| e.contains("is referenced by proxy 'proxy-hand'")),
            "expected foreign-upstream-reference rejection, got {err:?}"
        );

        // A spec-owned plugin targeted at another proxy is lifecycle-invalid.
        let proxies = vec![sample_owned_proxy("spec-1", "proxy-1")];
        let plugin: PluginConfig =
            serde_json::from_value(owned_proxy_scoped_plugin("plug-1", "proxy-other", "spec-1"))
                .expect("plugin");
        let err = validate_restore_api_specs_section(&section(), &proxies, &[], &[plugin], 25)
            .expect_err("plugin targeting another proxy");
        assert!(
            err.iter()
                .any(|e| e.contains("is not a valid association for owning proxy 'proxy-1'")),
            "expected wrong-proxy plugin rejection, got {err:?}"
        );

        // A spec-owned plugin the owning proxy does not attach can never be
        // produced by extraction and would be silently inert.
        let plugin: PluginConfig =
            serde_json::from_value(owned_proxy_scoped_plugin("plug-1", "proxy-1", "spec-1"))
                .expect("plugin");
        let err = validate_restore_api_specs_section(
            &section(),
            &proxies,
            &[],
            std::slice::from_ref(&plugin),
            25,
        )
        .expect_err("unassociated spec-owned plugin");
        assert!(
            err.iter()
                .any(|e| e.contains("is not associated with owning proxy 'proxy-1'")),
            "expected unassociated-plugin rejection, got {err:?}"
        );

        // The well-formed graph — one owning proxy, one owned upstream, one
        // attached owned plugin, plus untouched hand-managed resources — passes.
        let mut owning_proxy = sample_owned_proxy("spec-1", "proxy-1");
        owning_proxy.plugins = vec![crate::config::types::PluginAssociation {
            plugin_config_id: "plug-1".to_string(),
        }];
        let hand_plugin: PluginConfig = serde_json::from_value(json!({
            "id": "hand-plug",
            "plugin_name": "key_auth",
            "namespace": "ferrum",
            "scope": "global",
            "config": {}
        }))
        .expect("hand plugin");
        let hand_upstream: Upstream = serde_json::from_value(json!({
            "id": "hand-up",
            "name": "hand-up",
            "namespace": "ferrum",
            "targets": []
        }))
        .expect("hand upstream");
        let specs = validate_restore_api_specs_section(
            &section(),
            &[owning_proxy],
            &[owned_upstream("up-1", "spec-1"), hand_upstream],
            &[plugin, hand_plugin],
            25,
        )
        .expect("a well-formed server-managed graph must restore");
        assert_eq!(specs.len(), 1);
    }

    #[test]
    fn clear_api_spec_ownership_tags_strips_all_resource_types() {
        let mut payload: RestorePayload = serde_json::from_value(json!({
            "proxies": [{
                "id": "p1",
                "listen_path": "/p",
                "backend_scheme": "http",
                "backend_host": "localhost",
                "backend_port": 8080,
                "api_spec_id": "s1"
            }],
            "upstreams": [{
                "id": "u1",
                "name": "u1",
                "targets": [],
                "api_spec_id": "s1"
            }],
            "plugin_configs": [{
                "id": "c1",
                "plugin_name": "key_auth",
                "scope": "global",
                "config": {},
                "api_spec_id": "s1"
            }]
        }))
        .expect("payload");
        clear_api_spec_ownership_tags(&mut payload);
        assert!(payload.proxies[0].api_spec_id.is_none());
        assert!(payload.upstreams[0].api_spec_id.is_none());
        assert!(payload.plugin_configs[0].api_spec_id.is_none());
    }

    #[test]
    fn restore_rejects_external_ref_pair_mismatch_and_corrupt_snapshot() {
        let raw = br#"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{}}"#;
        let mut item = sample_spec_item("spec-extref", "proxy-extref", raw);
        item.external_ref_digest = Some("a".repeat(64));
        let section = ApiSpecsBackupSection {
            section_version: API_SPECS_BACKUP_SECTION_VERSION.to_string(),
            items: vec![item.clone()],
        };
        let errors = validate_restore_api_specs_section(
            &section,
            &[sample_owned_proxy("spec-extref", "proxy-extref")],
            &[],
            &[],
            25,
        )
        .expect_err("digest without snapshot must fail");
        assert!(errors.iter().any(|error| error.contains("integrity")));

        item.external_ref_snapshot_base64 =
            Some(base64::engine::general_purpose::STANDARD.encode([0x1f, 0x8b, 0x00]));
        let hostile = "SECRET-CANARY";
        item.external_ref_snapshot_base64 = Some(format!(
            "{}{}",
            item.external_ref_snapshot_base64
                .as_deref()
                .unwrap_or_default(),
            hostile
        ));
        let error = item
            .to_api_spec()
            .expect_err("corrupt snapshot encoding/content must fail");
        assert!(!error.contains(hostile));
        assert!(error.contains("invalid") || error.contains("integrity"));
    }
}
