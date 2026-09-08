//! A2A Gateway plugin.
//!
//! Provides transparent observability and light policy enforcement for
//! Agent-to-Agent protocol traffic over HTTP JSON-RPC, HTTP+JSON/REST, and
//! gRPC. The plugin does not own A2A task state or route between agents in V1.

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use dashmap::DashMap;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tracing::warn;
use url::Url;

use super::utils::policy_digest;
use super::{
    A2aGrpcCardRewriteState, A2aGrpcCardSchema, HTTP_GRPC_PROTOCOLS, Plugin, PluginResult,
    RequestContext, ResponseStreamAction, ResponseStreamInspector,
};
use crate::util::unknown_keys::reject_unknown_keys;

/// Domain separator and schema version for [`A2aGateway`] replay provenance.
/// Bumping the version invalidates every previously persisted representation
/// rather than letting an old digest match new semantics.
const STATIC_POLICY_DIGEST_DOMAIN: &str = "ferrum.plugin.a2a_gateway.static.v1";

const DEFAULT_ENDPOINT_PATH: &str = "/a2a";
const DEFAULT_AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";
const DEFAULT_PROTOCOL_VERSION: &str = "0.3.0";
const DEFAULT_VERSION_HEADER: &str = "A2A-Version";
const DEFAULT_MAX_DETECTION_BODY_BYTES: u64 = 1024 * 1024;
/// Canonical gRPC service of the A2A protocol version this plugin implements.
///
/// `a2aproject/A2A` at tag `v0.3.0`, `specification/grpc/a2a.proto`, declares
/// `package a2a.v1; service A2AService`, so the fully-qualified name is
/// `a2a.v1.A2AService`. It is the primary default because it is the identity
/// whose `AgentCard` layout [`DEFAULT_PROTOCOL_VERSION`] describes. A2A 1.0's
/// `lf.a2a.v1.A2AService` is also recognized by default for policy continuity,
/// but its renumbered card is never decoded as 0.3.
const DEFAULT_GRPC_SERVICE: &str = "a2a.v1.A2AService";
/// A2A 1.0's gRPC service (`package lf.a2a.v1`). Recognized so an operator can
/// detect and police 1.0 traffic; its Agent Card layout is not one this
/// rewriter implements, so card rewriting on it fails closed.
const A2A_10_GRPC_SERVICE: &str = "lf.a2a.v1.A2AService";
const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;

/// The published A2A gRPC service identities and the `AgentCard` wire layout
/// each one carries, per the A2A specification.
///
/// A service name in this table has a schema fixed by the spec, so declaring a
/// contradicting `card_schema` for one is a configuration error rather than an
/// override — the layout is a property of the published protocol, not of the
/// deployment. Any other (custom) service name has no published schema and must
/// declare one explicitly to be rewritable.
const WELL_KNOWN_GRPC_SERVICE_SCHEMAS: &[(&str, A2aGrpcCardSchema)] = &[
    (DEFAULT_GRPC_SERVICE, A2aGrpcCardSchema::A2a03),
    (A2A_10_GRPC_SERVICE, A2aGrpcCardSchema::A2a10),
];

/// Config spelling of [`A2aGrpcCardSchema::A2a03`].
const CARD_SCHEMA_A2A_03: &str = "a2a-0.3";
/// Config spelling of [`A2aGrpcCardSchema::A2a10`].
const CARD_SCHEMA_A2A_10: &str = "a2a-1.0";
/// Config spelling of [`A2aGrpcCardSchema::Undeclared`].
const CARD_SCHEMA_NONE: &str = "none";

/// Authoritative closed set of top-level `a2a_gateway` configuration keys.
const A2A_CONFIG_KEYS: &[&str] = &[
    "detection",
    "discovery",
    "enabled",
    "endpoint",
    "mode",
    "observability",
    "policy",
];
const A2A_ENDPOINT_KEYS: &[&str] = &[
    "agent_card_path",
    "grpc_services",
    "path",
    "protocol_versions",
];
const A2A_GRPC_SERVICE_ENTRY_KEYS: &[&str] = &["card_schema", "service"];
const A2A_DETECTION_KEYS: &[&str] = &[
    "allow_unknown_methods_with_version_header",
    "bindings",
    "max_request_body_size",
    "strip_accept_encoding",
    "version_header",
];
const A2A_DISCOVERY_KEYS: &[&str] = &[
    "public_base_url",
    "rewrite_agent_card_urls",
    "trust_forwarded_headers",
    "allowed_public_origins",
];
const A2A_OBSERVABILITY_KEYS: &[&str] = &["emit_metadata", "log_payloads", "max_payload_size"];
const A2A_POLICY_KEYS: &[&str] = &["default_action", "methods"];
const A2A_POLICY_METHOD_KEYS: &[&str] = &["action"];

/// The complete A2A 0.3.x `AgentCard` top-level field table (`a2aproject/A2A`
/// at tag `v0.3.0`, `specification/grpc/a2a.proto`, "Next ID: 18"). Wire surgery
/// mutates only the endpoint fields and preserves every other field verbatim, so
/// skills/security/provider survive re-encoding without embedding a full
/// descriptor set — but every number below is still *known*, because a known
/// field carrying an unexpected shape must fail closed rather than be preserved
/// beside rewritten siblings after the signature block was dropped.
///
/// These numbers are layout-specific, NOT stable across A2A releases. A2A 1.0
/// renumbered `AgentCard`: field 3 became `repeated AgentInterface
/// supported_interfaces` (was `string url`), `signatures` moved from 17 to 13,
/// field 14 became `optional string icon_url` (was `preferred_transport`), and
/// `protocol_version` was removed outright. Applying the constants below to a
/// 1.0 card would replace each interface submessage with a bare URL string while
/// leaving the real signatures untouched, so the rewrite path must first prove
/// the 0.3 layout twice over: the gRPC service must be declared to carry it
/// ([`require_rewritable_card_schema`]) and the card must claim a configured 0.3
/// version on the wire ([`supports_agent_card_protobuf_layout`]).
const AGENT_CARD_PB_NAME: u32 = 1;
const AGENT_CARD_PB_DESCRIPTION: u32 = 2;
const AGENT_CARD_PB_URL: u32 = 3;
const AGENT_CARD_PB_PROVIDER: u32 = 4;
const AGENT_CARD_PB_VERSION: u32 = 5;
const AGENT_CARD_PB_DOCUMENTATION_URL: u32 = 6;
const AGENT_CARD_PB_CAPABILITIES: u32 = 7;
const AGENT_CARD_PB_SECURITY_SCHEMES: u32 = 8;
const AGENT_CARD_PB_SECURITY: u32 = 9;
const AGENT_CARD_PB_DEFAULT_INPUT_MODES: u32 = 10;
const AGENT_CARD_PB_DEFAULT_OUTPUT_MODES: u32 = 11;
const AGENT_CARD_PB_SKILLS: u32 = 12;
const AGENT_CARD_PB_SUPPORTS_AUTHENTICATED_EXTENDED_CARD: u32 = 13;
const AGENT_CARD_PB_PREFERRED_TRANSPORT: u32 = 14;
const AGENT_CARD_PB_ADDITIONAL_INTERFACES: u32 = 15;
const AGENT_CARD_PB_PROTOCOL_VERSION: u32 = 16;
const AGENT_CARD_PB_SIGNATURES: u32 = 17;
const AGENT_INTERFACE_PB_URL: u32 = 1;
const AGENT_INTERFACE_PB_TRANSPORT: u32 = 2;
const PROTO_WIRE_VARINT: u8 = 0;
const PROTO_WIRE_64BIT: u8 = 1;
const PROTO_WIRE_LEN: u8 = 2;
const PROTO_WIRE_32BIT: u8 = 5;

/// Response headers that describe the backend's original body and become stale
/// the moment the Agent Card body is re-serialized as uncompressed JSON. Dropped
/// case-insensitively when the plugin rewrites the card so clients never
/// revalidate, integrity-check, or content-decode the rewritten body against the
/// backend's original representation.
const BODY_COUPLED_RESPONSE_HEADERS: &[&str] = &[
    "content-length",
    "content-encoding",
    "etag",
    "last-modified",
    "content-digest",
    "digest",
    "content-md5",
];

const JSONRPC_METHODS: &[&str] = &[
    "message/send",
    "message/stream",
    "tasks/get",
    "tasks/list",
    "tasks/cancel",
    "tasks/resubscribe",
    "tasks/pushNotificationConfig/set",
    "tasks/pushNotificationConfig/get",
    "tasks/pushNotificationConfig/list",
    "tasks/pushNotificationConfig/delete",
    "agent/getCard",
    "agent/getExtendedAgentCard",
    "agent/getAuthenticatedExtendedCard",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum A2aBinding {
    JsonRpc,
    Rest,
    Grpc,
}

impl A2aBinding {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "jsonrpc" | "json-rpc" => Ok(Self::JsonRpc),
            "rest" | "http_json" | "http+json" => Ok(Self::Rest),
            "grpc" => Ok(Self::Grpc),
            other => Err(format!(
                "a2a_gateway: detection.bindings entries must be jsonrpc, rest, or grpc, got {other:?}"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::JsonRpc => "jsonrpc",
            Self::Rest => "rest",
            Self::Grpc => "grpc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyAction {
    Allow,
    Deny,
}

impl PolicyAction {
    fn parse(value: &str, field: &str) -> Result<Self, String> {
        match value {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            other => Err(format!(
                "a2a_gateway: '{field}' must be allow or deny, got {other:?}"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone)]
struct A2aEndpointConfig {
    path: String,
    agent_card_path: String,
    protocol_versions: Vec<String>,
    /// Configured A2A gRPC services, each mapped to the `AgentCard` wire layout
    /// it is declared to carry. Detection membership and card-layout selection
    /// are the same lookup, so a service can never be detected without its
    /// schema disposition also being known.
    grpc_services: HashMap<String, A2aGrpcCardSchema>,
}

#[derive(Debug, Clone)]
struct A2aDetectionConfig {
    bindings: HashSet<A2aBinding>,
    version_header: String,
    max_request_body_size: u64,
    allow_unknown_methods_with_version_header: bool,
    strip_accept_encoding: bool,
}

#[derive(Debug, Clone)]
struct A2aDiscoveryConfig {
    rewrite_agent_card_urls: bool,
    public_base_url: Option<String>,
    trust_forwarded_headers: bool,
    allowed_public_origins: HashSet<String>,
}

#[derive(Debug, Clone)]
struct A2aObservabilityConfig {
    emit_metadata: bool,
    log_payloads: bool,
    max_payload_size: usize,
}

#[derive(Debug, Clone)]
struct A2aPolicyConfig {
    default_action: PolicyAction,
    methods: HashMap<String, PolicyAction>,
}

#[derive(Debug, Clone)]
struct A2aEnvelope {
    id: Option<Value>,
    method: Option<String>,
    jsonrpc: Option<String>,
    is_request: bool,
    is_error: bool,
}

#[derive(Debug, Clone)]
struct A2aDetection {
    binding: A2aBinding,
    method: String,
    jsonrpc_id: Option<Value>,
    jsonrpc_batch_response: bool,
    task_id_hint: Option<String>,
    streaming_hint: bool,
    is_agent_card: bool,
    /// For the gRPC binding, the `AgentCard` layout the matched service is
    /// configured to carry. `None` for the HTTP bindings, whose card is JSON
    /// and carries no protobuf layout question.
    grpc_card_schema: Option<A2aGrpcCardSchema>,
    oversized_body: bool,
    inspection_failed: bool,
}

pub struct A2aGateway {
    enabled: bool,
    endpoint: A2aEndpointConfig,
    detection: A2aDetectionConfig,
    discovery: A2aDiscoveryConfig,
    observability: A2aObservabilityConfig,
    policy: A2aPolicyConfig,
    /// Content-derived digest of this instance's whole accepted static config,
    /// used as replay provenance (see `Plugin::response_presentation_policy`).
    ///
    /// Computed once at construction from the canonical form of the validated
    /// configuration, so it covers every present and future static knob without
    /// an enumeration that could silently fall behind a new field. Only the
    /// digest is ever exposed; the source config is not retained.
    static_policy_digest: [u8; 32],
    pending_stream_observations: Arc<DashMap<u64, A2aStreamObservationSlot>>,
}

type A2aStreamObservationSlot = Arc<Mutex<Option<A2aStreamObservation>>>;

struct A2aStreamObservation {
    stream_events: u64,
    task_id: Option<String>,
    context_id: Option<String>,
    task_state: Option<String>,
}

/// Observe-only SSE parser for one A2A response.
///
/// Bytes are never retained for release: `on_chunk` copies and returns the
/// current chunk immediately, while this owned state independently reassembles
/// SSE lines/events for metadata extraction. The per-event cap prevents a
/// malformed stream without delimiters from growing the accumulator without
/// bound; oversized events still pass through unchanged and are counted.
struct A2aSseStreamInspector {
    binding: Option<&'static str>,
    line: Vec<u8>,
    data: Vec<u8>,
    line_had_bytes: bool,
    pending_cr: bool,
    discarding_event: bool,
    event_has_data: bool,
    stream_events: u64,
    task_id: Option<String>,
    context_id: Option<String>,
    task_state: Option<String>,
    observation: A2aStreamObservationSlot,
}

impl A2aSseStreamInspector {
    fn new(binding: Option<&'static str>, observation: A2aStreamObservationSlot) -> Self {
        Self {
            binding,
            line: Vec::new(),
            data: Vec::new(),
            line_had_bytes: false,
            pending_cr: false,
            discarding_event: false,
            event_has_data: false,
            stream_events: 0,
            task_id: None,
            context_id: None,
            task_state: None,
            observation,
        }
    }

    fn ingest(&mut self, chunk: &[u8]) {
        for &byte in chunk {
            if self.pending_cr {
                self.pending_cr = false;
                self.finish_line();
                if byte == b'\n' {
                    continue;
                }
            }
            match byte {
                b'\r' => self.pending_cr = true,
                b'\n' => self.finish_line(),
                _ => self.push_line_byte(byte),
            }
        }
    }

    fn push_line_byte(&mut self, byte: u8) {
        self.line_had_bytes = true;
        if self.discarding_event {
            return;
        }
        if self.line.len() == MAX_SSE_EVENT_BYTES {
            self.event_has_data |= self.line.starts_with(b"data:");
            self.discarding_event = true;
            self.line.clear();
            self.data.clear();
            return;
        }
        self.line.push(byte);
    }

    fn finish_line(&mut self) {
        if !self.line_had_bytes {
            self.finish_event();
            return;
        }

        if !self.discarding_event
            && let Some(payload) = self.line.strip_prefix(b"data:")
        {
            let append_separator = self.event_has_data;
            self.event_has_data = true;
            let payload = payload.strip_prefix(b" ").unwrap_or(payload);
            let separator_len = usize::from(append_separator);
            if self
                .data
                .len()
                .saturating_add(separator_len)
                .saturating_add(payload.len())
                > MAX_SSE_EVENT_BYTES
            {
                self.discarding_event = true;
                self.data.clear();
            } else {
                if separator_len != 0 {
                    self.data.push(b'\n');
                }
                self.data.extend_from_slice(payload);
            }
        }

        self.line.clear();
        self.line_had_bytes = false;
    }

    fn finish_event(&mut self) {
        if self.event_has_data {
            self.stream_events = self.stream_events.saturating_add(1);
            if !self.discarding_event
                && self.data.as_slice() != b"[DONE]"
                && let Ok(value) = serde_json::from_slice::<Value>(&self.data)
            {
                if let Some(task_id) = extract_task_id_from_response(self.binding, &value) {
                    self.task_id = Some(task_id);
                }
                if let Some(context_id) = extract_context_id_from_response(self.binding, &value) {
                    self.context_id = Some(context_id);
                }
                if let Some(task_state) = find_task_state(&value) {
                    self.task_state = Some(task_state);
                }
            }
        }

        self.line.clear();
        self.data.clear();
        self.line_had_bytes = false;
        self.discarding_event = false;
        self.event_has_data = false;
    }

    fn finish(&mut self) {
        if self.pending_cr {
            self.pending_cr = false;
            self.finish_line();
        }
        if self.line_had_bytes {
            self.finish_line();
        }
        if self.event_has_data || self.discarding_event {
            self.finish_event();
        }
    }

    fn publish_observation(&mut self) {
        let observation = A2aStreamObservation {
            stream_events: self.stream_events,
            task_id: self.task_id.take(),
            context_id: self.context_id.take(),
            task_state: self.task_state.take(),
        };
        let mut slot = self
            .observation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(observation);
        }
    }
}

#[async_trait]
impl ResponseStreamInspector for A2aSseStreamInspector {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        self.ingest(chunk);
        ResponseStreamAction::Forward(Bytes::copy_from_slice(chunk))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        self.finish();
        self.publish_observation();
        ResponseStreamAction::Forward(Bytes::new())
    }
}

impl A2aGateway {
    pub fn new(config: &Value) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "a2a_gateway: config must be an object".to_string())?;
        reject_unknown_keys(object, "config", A2A_CONFIG_KEYS, "a2a_gateway: ")?;
        let enabled = optional_bool(object, "enabled")?.unwrap_or(true);
        let mode = optional_string(object, "mode")?.unwrap_or("transparent_proxy");
        if mode != "transparent_proxy" {
            return Err(format!(
                "a2a_gateway: 'mode' must be transparent_proxy in V1, got {mode:?}"
            ));
        }
        let endpoint = parse_endpoint(object)?;
        let detection = parse_detection(object)?;
        let observability = parse_observability(object)?;
        let policy = parse_policy(object)?;
        let discovery = parse_discovery(object)?;
        // Digest the accepted configuration as a whole. Every knob that shapes a
        // client-visible Agent Card — `discovery.public_base_url`,
        // `endpoint.path`, `endpoint.agent_card_path`,
        // `endpoint.protocol_versions`, `discovery.rewrite_agent_card_urls`, and
        // the `enabled` switch itself — is in here by construction, so enabling,
        // disabling, or editing any of them moves the provenance a persisted
        // replay is bound to.
        let static_policy_digest =
            policy_digest::static_config_digest(STATIC_POLICY_DIGEST_DOMAIN, config);
        Ok(Self {
            enabled,
            endpoint,
            detection,
            discovery,
            observability,
            policy,
            static_policy_digest,
            pending_stream_observations: Arc::new(DashMap::with_shard_amount(
                crate::util::sharding::pool_shard_amount(0),
            )),
        })
    }

    fn request_body<'a>(&self, ctx: &'a RequestContext) -> Option<&'a [u8]> {
        ctx.request_body_bytes
            .as_ref()
            .map(|body| body.as_ref())
            .or_else(|| ctx.metadata.get("request_body").map(|body| body.as_bytes()))
    }

    fn maybe_detect(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> Option<A2aDetection> {
        if self.detection.bindings.contains(&A2aBinding::Grpc)
            && let Some(detection) = self.detect_grpc(ctx, headers)
        {
            return Some(detection);
        }
        if self.detection.bindings.contains(&A2aBinding::Rest)
            && let Some(detection) = self.detect_rest(ctx)
        {
            return Some(detection);
        }
        if self.detection.bindings.contains(&A2aBinding::JsonRpc)
            && let Some(detection) = self.detect_jsonrpc(ctx, headers)
        {
            return Some(detection);
        }
        // Recognition is not an exemption from policy. Disabled bindings,
        // malformed envelopes, and unknown methods inside our scope cannot
        // prove that an explicitly denied operation will not be executed.
        if self.policy_requires_inspection() && self.request_in_scope(ctx) {
            return Some(A2aDetection {
                binding: if is_grpc_request(headers) {
                    A2aBinding::Grpc
                } else {
                    A2aBinding::Rest
                },
                method: "unknown".to_string(),
                jsonrpc_id: None,
                jsonrpc_batch_response: false,
                task_id_hint: None,
                streaming_hint: false,
                is_agent_card: false,
                grpc_card_schema: None,
                oversized_body: false,
                inspection_failed: true,
            });
        }
        None
    }

    fn request_in_scope(&self, ctx: &RequestContext) -> bool {
        let endpoint = self.endpoint.path.trim_end_matches('/');
        let path = ctx.path.as_str();
        endpoint.is_empty()
            || path == endpoint
            || path
                .strip_prefix(endpoint)
                .is_some_and(|rest| rest.starts_with('/'))
            || path.ends_with(&self.endpoint.agent_card_path)
            || self.endpoint.grpc_services.keys().any(|service| {
                path.strip_prefix('/')
                    .and_then(|path| path.strip_prefix(service))
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
            })
    }

    fn detect_jsonrpc(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> Option<A2aDetection> {
        if !ctx.method.eq_ignore_ascii_case("POST") || ctx.path != self.endpoint.path {
            return None;
        }
        if !content_type_is_json(headers) {
            return None;
        }
        let body = self.request_body(ctx)?;
        if self.detection.max_request_body_size > 0
            && body.len() as u64 > self.detection.max_request_body_size
        {
            warn!(
                body_size = body.len(),
                max_request_body_size = self.detection.max_request_body_size,
                "Skipping A2A JSON-RPC detection because request body exceeds plugin detection limit"
            );
            if self.policy_requires_inspection() {
                return Some(A2aDetection {
                    binding: A2aBinding::JsonRpc,
                    method: "unknown".to_string(),
                    jsonrpc_id: None,
                    jsonrpc_batch_response: false,
                    task_id_hint: None,
                    streaming_hint: false,
                    is_agent_card: false,
                    grpc_card_schema: None,
                    oversized_body: true,
                    inspection_failed: false,
                });
            }
            return None;
        }
        let value: Value = serde_json::from_slice(body).ok()?;
        if let Some(batch) = value.as_array() {
            return self.detect_jsonrpc_batch(batch, headers);
        }
        match self.detect_jsonrpc_value(&value, headers) {
            Some(detection) => Some(detection),
            // A body that carries a JSON-RPC `method` but is not a well-formed
            // 2.0 request (wrong/absent `jsonrpc`, etc.) must not slip past a
            // deny policy via a malformed envelope. Fail closed here exactly as
            // batch members do below. Other unrecognized payloads are handled
            // by the in-scope fallback in `maybe_detect`.
            None if value.get("method").is_some() => {
                self.jsonrpc_inspection_failed_detection(false)
            }
            None => None,
        }
    }

    fn detect_jsonrpc_batch(
        &self,
        batch: &[Value],
        headers: &HashMap<String, String>,
    ) -> Option<A2aDetection> {
        if batch.is_empty() {
            return self.jsonrpc_inspection_failed_detection(false);
        }
        let mut first_detection = None;
        for item in batch {
            let Some(mut detection) = self.detect_jsonrpc_value(item, headers) else {
                return self.jsonrpc_inspection_failed_detection(true);
            };
            detection.jsonrpc_batch_response = true;
            if self.policy_action(&detection.method) == PolicyAction::Deny {
                return Some(detection);
            }
            if detection.is_agent_card {
                // Any card member requires a buffered rewrite, including a
                // card that follows an ordinary operation in an allowed batch.
                detection.streaming_hint = false;
                first_detection = Some(detection);
            } else if first_detection.is_none() {
                first_detection = Some(detection);
            }
        }
        first_detection
    }

    fn detect_jsonrpc_value(
        &self,
        value: &Value,
        headers: &HashMap<String, String>,
    ) -> Option<A2aDetection> {
        let envelope = parse_jsonrpc_envelope(value).ok()?;
        if envelope.jsonrpc.as_deref() != Some("2.0")
            || !envelope.is_request
            || value.get("result").is_some()
            || value.get("error").is_some()
            || value
                .get("params")
                .is_some_and(|params| !params.is_object() && !params.is_array())
            || envelope
                .id
                .as_ref()
                .is_some_and(|id| !id.is_null() && !id.is_string() && !id.is_number())
        {
            return None;
        }
        let method = envelope.method?;
        let canonical_method = canonical_a2a_method(&method);
        let accepted_unknown = self.detection.allow_unknown_methods_with_version_header
            && header_value(headers, &self.detection.version_header).is_some();
        let unknown_denied_by_policy = self.policy_action("unknown") == PolicyAction::Deny;
        if canonical_method.is_none() && !accepted_unknown && !unknown_denied_by_policy {
            return None;
        }
        let metric_method = canonical_method.unwrap_or("unknown").to_string();
        let is_agent_card = is_agent_card_method(&metric_method);
        Some(A2aDetection {
            binding: A2aBinding::JsonRpc,
            streaming_hint: is_streaming_method(&metric_method),
            method: metric_method,
            jsonrpc_id: envelope.id,
            jsonrpc_batch_response: false,
            task_id_hint: extract_task_id_from_request(value),
            is_agent_card,
            grpc_card_schema: None,
            oversized_body: false,
            inspection_failed: false,
        })
    }

    fn jsonrpc_inspection_failed_detection(
        &self,
        jsonrpc_batch_response: bool,
    ) -> Option<A2aDetection> {
        self.policy_requires_inspection().then(|| A2aDetection {
            binding: A2aBinding::JsonRpc,
            method: "unknown".to_string(),
            jsonrpc_id: None,
            jsonrpc_batch_response,
            task_id_hint: None,
            streaming_hint: false,
            is_agent_card: false,
            grpc_card_schema: None,
            oversized_body: false,
            inspection_failed: true,
        })
    }

    fn detect_rest(&self, ctx: &RequestContext) -> Option<A2aDetection> {
        let method = ctx.method.as_str();
        let path = ctx.path.as_str();
        if path.ends_with(&self.endpoint.agent_card_path) && method.eq_ignore_ascii_case("GET") {
            return Some(A2aDetection {
                binding: A2aBinding::Rest,
                method: "agent/getCard".to_string(),
                jsonrpc_id: None,
                jsonrpc_batch_response: false,
                task_id_hint: None,
                streaming_hint: false,
                is_agent_card: true,
                grpc_card_schema: None,
                oversized_body: false,
                inspection_failed: false,
            });
        }
        let rest = self.rest_suffix(path)?;
        let (operation, task_id, streaming) = match_rest_operation(method, rest)?;
        Some(A2aDetection {
            binding: A2aBinding::Rest,
            method: operation.to_string(),
            jsonrpc_id: None,
            jsonrpc_batch_response: false,
            task_id_hint: task_id,
            streaming_hint: streaming,
            is_agent_card: matches!(
                operation,
                "agent/getCard"
                    | "agent/getExtendedAgentCard"
                    | "agent/getAuthenticatedExtendedCard"
            ),
            grpc_card_schema: None,
            oversized_body: false,
            inspection_failed: false,
        })
    }

    fn detect_grpc(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> Option<A2aDetection> {
        if !ctx.method.eq_ignore_ascii_case("POST") || !is_grpc_request(headers) {
            return None;
        }
        let normalized = ctx.path.strip_prefix('/').unwrap_or(ctx.path.as_str());
        let (service, grpc_method) = normalized.split_once('/')?;
        // One lookup answers both "is this an A2A service?" and "which Agent
        // Card layout does it carry?", so a detected service always has a known
        // schema disposition and the response path never has to re-derive a
        // service identity from a path the proxy may have rebased.
        let card_schema = *self.endpoint.grpc_services.get(service)?;
        let (operation, streaming) = grpc_operation(grpc_method)?;
        Some(A2aDetection {
            binding: A2aBinding::Grpc,
            method: operation.to_string(),
            jsonrpc_id: None,
            jsonrpc_batch_response: false,
            task_id_hint: None,
            streaming_hint: streaming,
            is_agent_card: is_agent_card_method(operation),
            grpc_card_schema: Some(card_schema),
            oversized_body: false,
            inspection_failed: false,
        })
    }

    fn emit_base_metadata(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        detection: &A2aDetection,
    ) {
        ctx.a2a_gateway_detected = true;
        ctx.a2a_gateway_binding = Some(detection.binding.as_str());
        ctx.a2a_gateway_is_agent_card = detection.is_agent_card;
        ctx.a2a_gateway_streaming = detection.streaming_hint;
        ctx.a2a_gateway_grpc_card_schema = detection.grpc_card_schema;

        if !self.observability.emit_metadata {
            return;
        }
        ctx.metadata
            .insert("a2a.enabled".to_string(), "true".to_string());
        ctx.metadata
            .insert("a2a.mode".to_string(), "transparent_proxy".to_string());
        ctx.metadata.insert(
            "a2a.binding".to_string(),
            detection.binding.as_str().to_string(),
        );
        ctx.metadata
            .insert("a2a.method".to_string(), detection.method.clone());
        ctx.metadata.insert(
            "a2a.streaming".to_string(),
            detection.streaming_hint.to_string(),
        );
        ctx.metadata
            .entry("a2a.policy_decision".to_string())
            .or_insert_with(|| "allow".to_string());
        if let Some(version) = header_value(headers, &self.detection.version_header)
            .or_else(|| self.endpoint.protocol_versions.first().map(String::as_str))
        {
            insert_bounded_metadata(
                ctx,
                "a2a.protocol_version",
                version,
                self.observability.max_payload_size,
            );
        }
        if let Some(task_id) = detection.task_id_hint.as_deref() {
            insert_bounded_metadata(
                ctx,
                "a2a.task_id",
                task_id,
                self.observability.max_payload_size,
            );
        }
    }

    fn policy_action(&self, method: &str) -> PolicyAction {
        self.policy
            .methods
            .get(method)
            .copied()
            .unwrap_or(self.policy.default_action)
    }

    fn policy_requires_inspection(&self) -> bool {
        self.policy.default_action == PolicyAction::Deny
            || self
                .policy
                .methods
                .values()
                .any(|action| *action == PolicyAction::Deny)
    }

    fn rest_suffix<'a>(&self, path: &'a str) -> Option<&'a str> {
        let endpoint_path = self.endpoint.path.trim_end_matches('/');
        if endpoint_path.is_empty() || endpoint_path == "/" {
            return normalized_rest_path(path).is_some().then_some(path);
        }
        path.strip_prefix(endpoint_path)
            .filter(|suffix| normalized_rest_path(suffix).is_some())
    }

    fn should_capture_http_response(&self, ctx: &RequestContext) -> bool {
        if is_grpc_request(&ctx.headers) {
            return false;
        }
        ctx.a2a_gateway_detected
            && !ctx.a2a_gateway_streaming
            && (self.observability.emit_metadata
                || (self.discovery.rewrite_agent_card_urls && ctx.a2a_gateway_is_agent_card))
    }

    fn should_rewrite_grpc_agent_card(&self, ctx: &RequestContext) -> bool {
        self.enabled
            && self.discovery.rewrite_agent_card_urls
            && ctx.a2a_gateway_detected
            && ctx.a2a_gateway_is_agent_card
            && !ctx.a2a_gateway_streaming
            && ctx.a2a_gateway_binding == Some("grpc")
    }

    /// The public origin every rewritten Agent Card URL is built from.
    ///
    /// Two effective modes, and the difference between them is exactly what
    /// [`Plugin::response_presentation_policy`] reports:
    ///
    /// - **Configured.** `discovery.public_base_url` is accepted static
    ///   configuration, so the rewritten base is a pure function of it.
    /// - **Request/transport-derived.** With no configured base and
    ///   `trust_forwarded_headers` enabled, the base comes from
    ///   `X-Forwarded-Proto` / `X-Forwarded-Host` / `Host` **and**, when no
    ///   forwarded scheme is present, from whether this connection carried a TLS
    ///   SNI hostname (`ctx.frontend_sni_hostname`). That last input belongs to
    ///   the transport, not to any request field a replay fingerprint binds —
    ///   see [`discovery_is_request_derived`].
    fn public_base_url(&self, ctx: &RequestContext) -> Option<String> {
        if let Some(configured) = self.discovery.public_base_url.as_deref() {
            return Some(configured.trim_end_matches('/').to_string());
        }
        if !self.discovery.trust_forwarded_headers {
            return None;
        }
        let proto = header_value(&ctx.headers, "x-forwarded-proto").unwrap_or_else(|| {
            if ctx.frontend_sni_hostname.is_some() {
                "https"
            } else {
                "http"
            }
        });
        let host = header_value(&ctx.headers, "x-forwarded-host")
            .or_else(|| header_value(&ctx.headers, "host"))?;
        let candidate = forwarded_public_base_url(proto, host)?;
        self.discovery
            .allowed_public_origins
            .contains(&candidate)
            .then_some(candidate)
    }

    fn stage_grpc_agent_card_rewrite(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Only a PROVEN-OK unary reply is a candidate Agent Card. A non-OK
        // upstream response — including one that streamed its failure in
        // trailers after a DATA frame — is forwarded as the upstream wrote it,
        // never re-decoded and never blamed on the rewriter.
        if !grpc_response_is_proven_ok(response_status, response_headers) {
            return PluginResult::Continue;
        }
        if body.is_empty() {
            // Trailers-only upstream replies carry no Agent Card payload.
            return PluginResult::Continue;
        }
        match validate_grpc_agent_card_rewrite(
            body,
            response_headers,
            ctx.a2a_gateway_grpc_card_schema,
            &self.endpoint.protocol_versions,
        ) {
            Ok(()) => {
                if self.public_base_url(ctx).is_none() {
                    return agent_card_origin_failure(ctx, true, self.observability.emit_metadata);
                }
                // Claimed. The transform phase owns the outcome from here, and
                // `on_final_response_body` fails closed if it never reports one,
                // so an admitted card can never reach the client un-rewritten.
                ctx.a2a_gateway_grpc_card_rewrite = Some(A2aGrpcCardRewriteState::Staged);
                PluginResult::Continue
            }
            Err(diagnostic) => {
                if self.observability.emit_metadata {
                    ctx.metadata
                        .insert("a2a.error".to_string(), diagnostic.to_string());
                }
                warn!(
                    error = diagnostic,
                    "Failing closed on unrewritable gRPC Agent Card response"
                );
                grpc_agent_card_rewrite_failure(diagnostic)
            }
        }
    }
}

#[async_trait]
impl Plugin for A2aGateway {
    fn name(&self) -> &str {
        "a2a_gateway"
    }

    fn priority(&self) -> u16 {
        super::priority::A2A_GATEWAY
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        HTTP_GRPC_PROTOCOLS
    }

    fn modifies_request_headers(&self) -> bool {
        self.enabled && self.detection.strip_accept_encoding
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.enabled && self.detection.bindings.contains(&A2aBinding::JsonRpc)
    }

    fn needs_request_body_bytes(&self) -> bool {
        self.enabled && self.detection.bindings.contains(&A2aBinding::JsonRpc)
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.enabled
            && self.detection.bindings.contains(&A2aBinding::JsonRpc)
            && ctx.method.eq_ignore_ascii_case("POST")
            && ctx.path == self.endpoint.path
            && content_type_is_json(&ctx.headers)
    }

    /// Agent Card rewriting is a presentation policy a finalized replay skips,
    /// so this instance enrolls in replay provenance — unconditionally, in one
    /// of two arms.
    ///
    /// `transform_response_body_with_context` is what makes enrollment
    /// mandatory: `request_deduplication` deliberately skips ordinary
    /// presentation transforms on a finalized replay, so without a contribution
    /// here a retained Agent Card could be replayed under a public base,
    /// `endpoint.path`, admitted `endpoint.protocol_versions`, or
    /// `rewrite_agent_card_urls` setting that has since changed.
    ///
    /// **`Static`** is reported for every configuration whose rewritten card is
    /// a pure function of accepted configuration — which is every deployment
    /// with a configured `discovery.public_base_url`, plus every deployment that
    /// does no rewriting at all. The digest covers the whole accepted config, so
    /// enabling, disabling, adding, removing, or editing an instance always
    /// moves it. Enrollment is unconditional (an internally disabled instance
    /// still contributes) for the same reason `response_transformer` and `sse`
    /// enroll unconditionally: "this instance rewrites nothing" is itself the
    /// policy a stored representation must be bound to, and a conditional
    /// contribution would make the per-proxy digest depend on live request state.
    ///
    /// **`Dynamic`** is reported for the request/transport-derived mode
    /// ([`discovery_is_request_derived`]): with no configured base and
    /// `trust_forwarded_headers` on, the rewritten origin is shaped by
    /// `X-Forwarded-*` / `Host` *and* by whether the connection carried a TLS
    /// SNI hostname. The deduplication fingerprint binds neither the complete
    /// forwarded header set nor `frontend_sni_hostname`, so two requests that
    /// share a replay key can legitimately deserve `https://…` and `http://…`
    /// cards. No construction-time digest can describe that, and the honest
    /// answer is that this proxy has no provable presentation policy at all.
    /// Config admission refuses the composition outright
    /// (`request_deduplication::validate_composition`); this is the runtime
    /// backstop for the admission paths that only warn. A configured
    /// public-base deployment is unaffected and keeps replaying normally.
    fn response_presentation_policy(&self) -> Option<super::ResponsePresentationPolicy> {
        if self.enabled && discovery_is_request_derived(&self.discovery) {
            return Some(super::ResponsePresentationPolicy::Dynamic);
        }
        Some(super::ResponsePresentationPolicy::Static(
            self.static_policy_digest,
        ))
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.enabled && (self.discovery.rewrite_agent_card_urls || self.observability.emit_metadata)
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        self.enabled
            && (self.should_capture_http_response(ctx) || self.should_rewrite_grpc_agent_card(ctx))
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        if content_type.is_some_and(is_event_stream_content_type) {
            return false;
        }
        self.should_buffer_response_body(ctx)
    }

    fn may_release_response_body_under_retries(&self, ctx: &RequestContext) -> bool {
        self.should_buffer_response_body(ctx)
    }

    fn should_release_response_body_under_retries(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        // Release only SSE, mirroring the non-retry content-type hook above:
        // an unexpected `text/event-stream` response is inherently streaming
        // and its retry decision is complete from status and headers. Every
        // other content type (JSON and otherwise) stays buffered because
        // `on_response_body` consumes the buffered body for metadata emission
        // and agent-card rewriting.
        self.should_buffer_response_body(ctx)
            && header_value(response_headers, "content-type")
                .is_some_and(is_event_stream_content_type)
    }

    fn requires_response_stream_hooks(&self) -> bool {
        self.enabled && self.observability.emit_metadata
    }

    fn forces_reqwest_dispatch(&self, ctx: &RequestContext) -> bool {
        self.enabled
            && self.observability.emit_metadata
            && ctx.a2a_gateway_detected
            && ctx.a2a_gateway_streaming
            && ctx.a2a_gateway_binding != Some("grpc")
    }

    fn response_stream_inspector(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        content_type: Option<&str>,
    ) -> Option<Box<dyn ResponseStreamInspector>> {
        if !self.enabled
            || !self.observability.emit_metadata
            || !ctx.a2a_gateway_detected
            || !(200..300).contains(&response_status)
            || !content_type.is_some_and(is_event_stream_content_type)
        {
            return None;
        }
        let stream_id = ctx.response_stream_id()?;
        let observation = Arc::new(Mutex::new(None));
        self.pending_stream_observations
            .insert(stream_id, Arc::clone(&observation));
        Some(Box::new(A2aSseStreamInspector::new(
            ctx.a2a_gateway_binding,
            observation,
        )))
    }

    async fn on_response_stream_terminated(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        _outcome: &crate::proxy::deferred_log::BodyOutcome,
    ) {
        if !self.observability.emit_metadata {
            return;
        }
        let Some(stream_id) = ctx.response_stream_id() else {
            return;
        };
        let Some((_, slot)) = self.pending_stream_observations.remove(&stream_id) else {
            return;
        };
        let observation = match slot.lock() {
            Ok(mut slot) => slot.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        let Some(observation) = observation else {
            return;
        };
        ctx.metadata.insert(
            "a2a.stream_events".to_string(),
            observation.stream_events.to_string(),
        );
        if let Some(task_id) = observation.task_id {
            insert_bounded_metadata(
                ctx,
                "a2a.task_id",
                &task_id,
                self.observability.max_payload_size,
            );
        }
        if let Some(context_id) = observation.context_id {
            insert_bounded_metadata(
                ctx,
                "a2a.context_id",
                &context_id,
                self.observability.max_payload_size,
            );
        }
        if let Some(task_state) = observation.task_state {
            emit_task_state(ctx, &task_state, self.observability.max_payload_size);
        }
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.enabled {
            return PluginResult::Continue;
        }
        let Some(detection) = self.maybe_detect(ctx, headers) else {
            return PluginResult::Continue;
        };
        self.emit_base_metadata(ctx, headers, &detection);
        if detection.oversized_body && self.policy_requires_inspection() {
            if self.observability.emit_metadata {
                ctx.metadata
                    .insert("a2a.policy_decision".to_string(), "deny".to_string());
                ctx.metadata.insert(
                    "a2a.error".to_string(),
                    "request_body_too_large".to_string(),
                );
            }
            return oversized_jsonrpc_response(&detection);
        }
        if detection.inspection_failed && self.policy_requires_inspection() {
            if self.observability.emit_metadata {
                ctx.metadata
                    .insert("a2a.policy_decision".to_string(), "deny".to_string());
                ctx.metadata.insert(
                    "a2a.error".to_string(),
                    "request_body_uninspectable".to_string(),
                );
            }
            return deny_response(&detection);
        }
        let action = self.policy_action(&detection.method);
        if self.observability.emit_metadata {
            ctx.metadata.insert(
                "a2a.policy_decision".to_string(),
                action.as_str().to_string(),
            );
        }
        if action == PolicyAction::Deny {
            return deny_response(&detection);
        }
        if detection.is_agent_card
            && self.discovery.rewrite_agent_card_urls
            && self.public_base_url(ctx).is_none()
        {
            return agent_card_origin_failure(
                ctx,
                detection.binding == A2aBinding::Grpc,
                self.observability.emit_metadata,
            );
        }
        if self.detection.strip_accept_encoding
            && (detection.is_agent_card
                || (self.observability.emit_metadata && !detection.streaming_hint))
        {
            remove_header(headers, "accept-encoding");
            // Agent Card gRPC rewriting needs an uncompressed unary frame; strip
            // message-level compression negotiation the same way HTTP decoding is
            // discouraged above.
            if detection.binding == A2aBinding::Grpc && detection.is_agent_card {
                remove_header(headers, "grpc-accept-encoding");
            }
        }
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.enabled || !ctx.a2a_gateway_detected {
            return PluginResult::Continue;
        }
        if response_headers
            .get("content-type")
            .is_some_and(|value| is_event_stream_content_type(value))
        {
            ctx.a2a_gateway_streaming = true;
            if self.observability.emit_metadata {
                ctx.metadata
                    .insert("a2a.streaming".to_string(), "true".to_string());
                let latency = Utc::now()
                    .signed_duration_since(ctx.timestamp_received)
                    .num_milliseconds()
                    .max(0);
                ctx.metadata
                    .insert("a2a.ttfb_ms".to_string(), latency.to_string());
            }
        }
        PluginResult::Continue
    }

    async fn on_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.enabled || !ctx.a2a_gateway_detected {
            return PluginResult::Continue;
        }
        if self.observability.emit_metadata {
            ctx.metadata
                .insert("a2a.response_body_size".to_string(), body.len().to_string());
            if self.observability.log_payloads
                && body.len() <= self.observability.max_payload_size
                && !is_grpc_request(&ctx.headers)
            {
                ctx.metadata.insert(
                    "a2a.payload.response".to_string(),
                    String::from_utf8_lossy(body).to_string(),
                );
            }
        }
        if self.should_rewrite_grpc_agent_card(ctx) {
            return self.stage_grpc_agent_card_rewrite(
                ctx,
                response_status,
                response_headers,
                body,
            );
        }
        if !response_headers
            .get("content-type")
            .is_none_or(|value| content_type_value_is_json(value))
        {
            return PluginResult::Continue;
        }
        let Ok(mut value) = serde_json::from_slice::<Value>(body) else {
            return PluginResult::Continue;
        };
        if self.observability.emit_metadata {
            emit_response_metadata(ctx, &value, self.observability.max_payload_size);
        }
        if !self.discovery.rewrite_agent_card_urls || !ctx.a2a_gateway_is_agent_card {
            return PluginResult::Continue;
        }
        let Some(public_base) = self.public_base_url(ctx) else {
            return agent_card_origin_failure(ctx, false, self.observability.emit_metadata);
        };
        let agent_card_path = if ctx.path.ends_with(&self.endpoint.agent_card_path) {
            ctx.path.as_str()
        } else {
            self.endpoint.agent_card_path.as_str()
        };
        if !rewrite_agent_card_response(
            &mut value,
            &public_base,
            &self.endpoint.path,
            agent_card_path,
        ) {
            return PluginResult::Continue;
        }
        let mut headers = response_headers.clone();
        headers.insert("content-type".to_string(), "application/json".to_string());
        for header in BODY_COUPLED_RESPONSE_HEADERS {
            remove_header(&mut headers, header);
        }
        PluginResult::Reject {
            status_code: response_status,
            body: value.to_string(),
            headers,
        }
    }

    async fn transform_response_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        _content_type: Option<&str>,
        response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // Only a card this plugin ADMITTED in `on_response_body` is rewritten.
        // Reading the staged state rather than re-deriving the decision keeps
        // the two phases from ever disagreeing about whether the response is a
        // proven-OK Agent Card — the transform hook is not handed the HTTP
        // status the admission gate needs.
        if !matches!(
            ctx.a2a_gateway_grpc_card_rewrite,
            Some(A2aGrpcCardRewriteState::Staged)
        ) {
            return None;
        }
        // Staging proved this is `Some`; a `None` here would leave the state
        // `Staged` and fail closed below rather than forward internal URLs.
        let public_base = self.public_base_url(ctx)?;
        // `0 = unlimited` is folded to the retained-response fallback here; a
        // raw effective limit of 0 would make the sink refuse every write.
        let ceiling = ctx.retained_response_body_ceiling();
        let card_schema = ctx.a2a_gateway_grpc_card_schema;
        match rewrite_grpc_agent_card_frame(
            body,
            response_headers,
            card_schema,
            &public_base,
            &self.endpoint.path,
            &self.endpoint.protocol_versions,
            ceiling,
        ) {
            // No URL differs from the public one: the backend's original,
            // still-signed frame is forwarded untouched.
            Ok(None) => {
                ctx.a2a_gateway_grpc_card_rewrite = Some(A2aGrpcCardRewriteState::Applied);
                None
            }
            Ok(Some(frame)) => {
                ctx.a2a_gateway_grpc_card_rewrite = Some(A2aGrpcCardRewriteState::Applied);
                Some(frame)
            }
            Err(AgentCardRewriteRefusal::Capacity) => {
                // The shared retained-response terminal owns this outcome: it
                // replaces the body with the health-neutral capacity refusal, so
                // the un-rewritten card never reaches the client and this plugin
                // must not additionally publish an `INTERNAL`.
                ctx.a2a_gateway_grpc_card_rewrite = Some(A2aGrpcCardRewriteState::CapacityRefused);
                ctx.mark_buffered_response_capacity_refusal_pending();
                None
            }
            Err(AgentCardRewriteRefusal::Diagnostic(diagnostic)) => {
                ctx.a2a_gateway_grpc_card_rewrite =
                    Some(A2aGrpcCardRewriteState::Failed(diagnostic));
                if self.observability.emit_metadata {
                    ctx.metadata
                        .insert("a2a.error".to_string(), diagnostic.to_string());
                }
                None
            }
        }
    }

    fn on_response_body_transformed(
        &self,
        _ctx: &mut RequestContext,
        response_headers: &mut HashMap<String, String>,
    ) {
        for header in BODY_COUPLED_RESPONSE_HEADERS {
            remove_header(response_headers, header);
        }
        // Rewritten frames are always uncompressed identity payloads.
        remove_header(response_headers, "grpc-encoding");
    }

    /// Fail closed for any admitted gRPC Agent Card whose rewrite did not
    /// actually reach the client.
    ///
    /// Two distinct residuals land here, and both must terminate the call rather
    /// than let the backend's internal endpoint URLs and now-invalid signatures
    /// be served:
    ///
    /// - `Failed` — the transform phase decoded further and refused.
    /// - `Staged` — the transform phase never reported at all. That is only
    ///   reachable if the producer window declined to invoke this plugin, but
    ///   "the rewrite silently did not run" must not be indistinguishable from
    ///   "no rewrite was needed", so it is a refusal too.
    ///
    /// A response the gateway has already replaced with its own terminal (the
    /// retained-response capacity refusal, a deadline, an earlier rejection)
    /// carries no card bytes and is left alone: it is no longer HTTP `200`, and
    /// re-deciding it here would relabel a health-neutral `503` capacity
    /// refusal as a gateway `INTERNAL`.
    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        _response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> PluginResult {
        let diagnostic = match ctx.a2a_gateway_grpc_card_rewrite.take() {
            None
            | Some(A2aGrpcCardRewriteState::Applied)
            | Some(A2aGrpcCardRewriteState::CapacityRefused) => return PluginResult::Continue,
            Some(A2aGrpcCardRewriteState::Failed(diagnostic)) => diagnostic,
            Some(A2aGrpcCardRewriteState::Staged) => "agent_card_grpc_rewrite_not_applied",
        };
        if response_status != 200 {
            return PluginResult::Continue;
        }
        if self.observability.emit_metadata {
            ctx.metadata
                .insert("a2a.error".to_string(), diagnostic.to_string());
        }
        warn!(
            error = diagnostic,
            "Failing closed on gRPC Agent Card rewrite failure after transform"
        );
        grpc_agent_card_rewrite_failure(diagnostic)
    }
}

fn parse_endpoint(object: &Map<String, Value>) -> Result<A2aEndpointConfig, String> {
    let endpoint = optional_object(object, "endpoint")?;
    if let Some(endpoint) = endpoint {
        reject_unknown_keys(
            endpoint,
            "config.endpoint",
            A2A_ENDPOINT_KEYS,
            "a2a_gateway: ",
        )?;
    }
    let path = optional_string_from_object(endpoint, "path")?
        .unwrap_or_else(|| DEFAULT_ENDPOINT_PATH.to_string());
    validate_path(&path, "endpoint.path")?;
    let agent_card_path = optional_string_from_object(endpoint, "agent_card_path")?
        .unwrap_or_else(|| DEFAULT_AGENT_CARD_PATH.to_string());
    validate_path(&agent_card_path, "endpoint.agent_card_path")?;
    let protocol_versions = optional_string_vec_from_object(endpoint, "protocol_versions")?
        .unwrap_or_else(|| vec![DEFAULT_PROTOCOL_VERSION.to_string()]);
    if protocol_versions.is_empty() {
        return Err("a2a_gateway: 'endpoint.protocol_versions' must not be empty".to_string());
    }
    if protocol_versions
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return Err(
            "a2a_gateway: 'endpoint.protocol_versions' entries must not be empty".to_string(),
        );
    }
    let grpc_services = parse_grpc_services(endpoint)?;
    Ok(A2aEndpointConfig {
        path,
        agent_card_path,
        protocol_versions,
        grpc_services,
    })
}

/// Parse `endpoint.grpc_services` into service name → declared Agent Card
/// layout.
///
/// Two accepted item shapes, and both leave the schema relationship stated
/// rather than inferred:
///
/// - A bare string. A published A2A service name resolves to the layout the
///   specification gives it ([`WELL_KNOWN_GRPC_SERVICE_SCHEMAS`]); any other
///   name has no published card layout, so it resolves to
///   [`A2aGrpcCardSchema::Undeclared`] — detected and policed, never decoded.
/// - `{service, card_schema}`. The explicit form a custom deployment uses to
///   declare which published layout its own service actually serves.
///
/// Declaring a `card_schema` that contradicts a published service name is
/// refused: the layout of `a2a.v1.A2AService` is a property of A2A 0.3, not a
/// per-deployment choice, and silently honoring an override is exactly how a
/// renumbered card ends up in the 0.3 decoder.
fn parse_grpc_services(
    endpoint: Option<&Map<String, Value>>,
) -> Result<HashMap<String, A2aGrpcCardSchema>, String> {
    let items = match endpoint.and_then(|endpoint| endpoint.get("grpc_services")) {
        None | Some(Value::Null) => return Ok(default_grpc_services()),
        Some(items) => items,
    };
    let items = items
        .as_array()
        .ok_or_else(|| "a2a_gateway: 'endpoint.grpc_services' must be an array".to_string())?;
    if items.is_empty() {
        return Err("a2a_gateway: 'endpoint.grpc_services' must not be empty".to_string());
    }
    let mut services = HashMap::with_capacity(items.len());
    for item in items {
        let (service, declared) = parse_grpc_service_entry(item)?;
        validate_grpc_service(service)?;
        let published = published_card_schema(service);
        let schema = match (published, declared) {
            // A published A2A service: the specification fixes its layout, so a
            // contradicting declaration is a configuration error rather than an
            // override. Restating the correct one is allowed and is a no-op.
            (Some(published), Some(declared)) if published != declared => {
                let published = card_schema_name(published);
                let declared = card_schema_name(declared);
                return Err(format!(
                    "a2a_gateway: endpoint.grpc_services entry {service:?} is a published A2A \
                     service whose Agent Card layout is {published:?}; it cannot declare \
                     card_schema {declared:?}"
                ));
            }
            (Some(published), _) => published,
            // A custom service name: whatever the operator declared, or no
            // declared layout at all.
            (None, Some(declared)) => declared,
            (None, None) => A2aGrpcCardSchema::Undeclared,
        };
        if services.insert(service.to_string(), schema).is_some() {
            return Err(format!(
                "a2a_gateway: duplicate endpoint.grpc_services entry {service:?}"
            ));
        }
    }
    Ok(services)
}

fn default_grpc_services() -> HashMap<String, A2aGrpcCardSchema> {
    let mut services = HashMap::with_capacity(2);
    services.insert(DEFAULT_GRPC_SERVICE.to_string(), A2aGrpcCardSchema::A2a03);
    services.insert(A2A_10_GRPC_SERVICE.to_string(), A2aGrpcCardSchema::A2a10);
    services
}

/// The Agent Card layout the A2A specification gives this service name, when it
/// is one of the published identities.
fn published_card_schema(service: &str) -> Option<A2aGrpcCardSchema> {
    WELL_KNOWN_GRPC_SERVICE_SCHEMAS
        .iter()
        .find(|(name, _)| *name == service)
        .map(|(_, schema)| *schema)
}

/// Split one `endpoint.grpc_services` item into its service name and the card
/// layout it explicitly declares, if any.
fn parse_grpc_service_entry(item: &Value) -> Result<(&str, Option<A2aGrpcCardSchema>), String> {
    match item {
        Value::String(service) => Ok((service.as_str(), None)),
        Value::Object(entry) => {
            reject_unknown_keys(
                entry,
                "config.endpoint.grpc_services[]",
                A2A_GRPC_SERVICE_ENTRY_KEYS,
                "a2a_gateway: ",
            )?;
            let service = match optional_string(entry, "service")? {
                Some(service) => service,
                None => return Err(GRPC_SERVICE_ENTRY_NEEDS_SERVICE.to_string()),
            };
            let declared = match optional_string(entry, "card_schema")? {
                Some(value) => Some(parse_card_schema(value)?),
                None => None,
            };
            Ok((service, declared))
        }
        other => Err(format!(
            "a2a_gateway: 'endpoint.grpc_services' entries must be a service name string or a \
             {{service, card_schema}} object, got {other}"
        )),
    }
}

const GRPC_SERVICE_ENTRY_NEEDS_SERVICE: &str =
    "a2a_gateway: 'endpoint.grpc_services' object entries require 'service'";

fn parse_card_schema(value: &str) -> Result<A2aGrpcCardSchema, String> {
    match value {
        CARD_SCHEMA_A2A_03 => Ok(A2aGrpcCardSchema::A2a03),
        CARD_SCHEMA_A2A_10 => Ok(A2aGrpcCardSchema::A2a10),
        CARD_SCHEMA_NONE => Ok(A2aGrpcCardSchema::Undeclared),
        other => Err(format!(
            "a2a_gateway: 'endpoint.grpc_services[].card_schema' must be {CARD_SCHEMA_A2A_03:?}, \
             {CARD_SCHEMA_A2A_10:?}, or {CARD_SCHEMA_NONE:?}, got {other:?}"
        )),
    }
}

fn card_schema_name(schema: A2aGrpcCardSchema) -> &'static str {
    match schema {
        A2aGrpcCardSchema::A2a03 => CARD_SCHEMA_A2A_03,
        A2aGrpcCardSchema::A2a10 => CARD_SCHEMA_A2A_10,
        A2aGrpcCardSchema::Undeclared => CARD_SCHEMA_NONE,
    }
}

fn parse_detection(object: &Map<String, Value>) -> Result<A2aDetectionConfig, String> {
    let detection = optional_object(object, "detection")?;
    if let Some(detection) = detection {
        reject_unknown_keys(
            detection,
            "config.detection",
            A2A_DETECTION_KEYS,
            "a2a_gateway: ",
        )?;
    }
    let bindings = optional_string_vec_from_object(detection, "bindings")?.unwrap_or_else(|| {
        vec![
            "jsonrpc".to_string(),
            "rest".to_string(),
            "grpc".to_string(),
        ]
    });
    if bindings.is_empty() {
        return Err("a2a_gateway: 'detection.bindings' must not be empty".to_string());
    }
    let mut binding_set = HashSet::with_capacity(bindings.len());
    for binding in bindings {
        binding_set.insert(A2aBinding::parse(&binding)?);
    }
    let version_header = optional_string_from_object(detection, "version_header")?
        .unwrap_or_else(|| DEFAULT_VERSION_HEADER.to_string());
    validate_header_name(&version_header, "detection.version_header")?;
    let max_request_body_size = optional_u64_from_object(detection, "max_request_body_size")?
        .unwrap_or(DEFAULT_MAX_DETECTION_BODY_BYTES);
    Ok(A2aDetectionConfig {
        bindings: binding_set,
        version_header,
        max_request_body_size,
        allow_unknown_methods_with_version_header: optional_bool_from_object(
            detection,
            "allow_unknown_methods_with_version_header",
        )?
        .unwrap_or(true),
        strip_accept_encoding: optional_bool_from_object(detection, "strip_accept_encoding")?
            .unwrap_or(true),
    })
}

fn parse_discovery(object: &Map<String, Value>) -> Result<A2aDiscoveryConfig, String> {
    let discovery = optional_object(object, "discovery")?;
    if let Some(discovery) = discovery {
        reject_unknown_keys(
            discovery,
            "config.discovery",
            A2A_DISCOVERY_KEYS,
            "a2a_gateway: ",
        )?;
    }
    let public_base_url = optional_string_from_object(discovery, "public_base_url")?;
    if let Some(url) = public_base_url.as_deref() {
        validate_public_base_url(url)?;
    }
    let rewrite_agent_card_urls =
        optional_bool_from_object(discovery, "rewrite_agent_card_urls")?.unwrap_or(true);
    let trust_forwarded_headers =
        optional_bool_from_object(discovery, "trust_forwarded_headers")?.unwrap_or(false);
    let mut allowed_public_origins = HashSet::new();
    for origin in
        optional_string_vec_from_object(discovery, "allowed_public_origins")?.unwrap_or_default()
    {
        validate_public_base_url(&origin)?;
        let parsed = Url::parse(&origin).map_err(|_| {
            "a2a_gateway: discovery.allowed_public_origins must contain absolute origins"
                .to_string()
        })?;
        if parsed.path() != "/" {
            return Err(
                "a2a_gateway: discovery.allowed_public_origins must not contain paths".to_string(),
            );
        }
        allowed_public_origins.insert(parsed.origin().ascii_serialization());
    }
    if rewrite_agent_card_urls
        && public_base_url.is_none()
        && (!trust_forwarded_headers || allowed_public_origins.is_empty())
    {
        return Err(
            "a2a_gateway: discovery.rewrite_agent_card_urls requires discovery.public_base_url or discovery.trust_forwarded_headers with nonempty discovery.allowed_public_origins; set discovery.rewrite_agent_card_urls=false for explicit passthrough".to_string(),
        );
    }
    Ok(A2aDiscoveryConfig {
        rewrite_agent_card_urls,
        public_base_url,
        trust_forwarded_headers,
        allowed_public_origins,
    })
}

/// Whether this discovery configuration selects the request/transport-derived
/// public base rather than a configured one.
///
/// This is the single definition of "A2A's Agent Card presentation is not a pure
/// function of accepted configuration". With no `public_base_url` and
/// `trust_forwarded_headers` enabled, [`A2aGateway::public_base_url`] falls back
/// to `X-Forwarded-Proto` / `X-Forwarded-Host` / `Host`, and — when no forwarded
/// scheme is present — to whether the connection carried a TLS SNI hostname.
/// `frontend_sni_hostname` is transport state, so the same request bytes on a
/// TLS and a cleartext listener yield `https://…` and `http://…` respectively;
/// no request fingerprint (and therefore no `request_deduplication` replay key)
/// witnesses the difference.
fn discovery_is_request_derived(discovery: &A2aDiscoveryConfig) -> bool {
    discovery.rewrite_agent_card_urls
        && discovery.public_base_url.is_none()
        && discovery.trust_forwarded_headers
}

/// Config-admission mirror of [`discovery_is_request_derived`], answered from
/// raw plugin configuration before any instance exists.
///
/// Admission (`request_deduplication::validate_composition`) works on
/// `PluginConfig` JSON, while the runtime backstop
/// (`Plugin::response_presentation_policy`) works on a constructed instance.
/// Both route through the same parser and the same predicate here, so the two
/// surfaces cannot drift; a configuration this parser rejects is not classified
/// at all, because the plugin constructor refuses it independently.
pub fn presentation_policy_is_request_derived(config: &Value) -> bool {
    let Some(object) = config.as_object() else {
        return false;
    };
    // Mirrors `A2aGateway::new`: `enabled` defaults to true, and a non-boolean
    // value is a configuration the constructor refuses outright.
    let enabled = match optional_bool(object, "enabled") {
        Ok(value) => value.unwrap_or(true),
        Err(_) => return false,
    };
    let Ok(discovery) = parse_discovery(object) else {
        return false;
    };
    enabled && discovery_is_request_derived(&discovery)
}

fn parse_observability(object: &Map<String, Value>) -> Result<A2aObservabilityConfig, String> {
    let observability = optional_object(object, "observability")?;
    if let Some(observability) = observability {
        reject_unknown_keys(
            observability,
            "config.observability",
            A2A_OBSERVABILITY_KEYS,
            "a2a_gateway: ",
        )?;
    }
    let max_payload_size = optional_u64_from_object(observability, "max_payload_size")?
        .unwrap_or(DEFAULT_MAX_DETECTION_BODY_BYTES);
    let max_payload_size = usize::try_from(max_payload_size)
        .map_err(|_| "a2a_gateway: 'observability.max_payload_size' is too large".to_string())?;
    if max_payload_size == 0 {
        return Err(
            "a2a_gateway: 'observability.max_payload_size' must be greater than zero".to_string(),
        );
    }
    Ok(A2aObservabilityConfig {
        emit_metadata: optional_bool_from_object(observability, "emit_metadata")?.unwrap_or(true),
        log_payloads: optional_bool_from_object(observability, "log_payloads")?.unwrap_or(false),
        max_payload_size,
    })
}

fn parse_policy(object: &Map<String, Value>) -> Result<A2aPolicyConfig, String> {
    let policy = optional_object(object, "policy")?;
    if let Some(policy) = policy {
        reject_unknown_keys(policy, "config.policy", A2A_POLICY_KEYS, "a2a_gateway: ")?;
    }
    let default_action = PolicyAction::parse(
        optional_string_from_object(policy, "default_action")?
            .as_deref()
            .unwrap_or("allow"),
        "policy.default_action",
    )?;
    let mut methods = HashMap::new();
    if let Some(methods_value) = policy.and_then(|policy| policy.get("methods")) {
        if methods_value.is_null() {
            return Ok(A2aPolicyConfig {
                default_action,
                methods,
            });
        }
        let methods_object = methods_value
            .as_object()
            .ok_or_else(|| "a2a_gateway: 'policy.methods' must be an object".to_string())?;
        for (method, value) in methods_object {
            let canonical_method = canonical_policy_method(method)
                .ok_or_else(|| format!("a2a_gateway: unsupported policy method name {method:?}"))?;
            let object = value.as_object().ok_or_else(|| {
                format!("a2a_gateway: policy.methods[{method:?}] must be an object")
            })?;
            reject_unknown_keys(
                object,
                &format!("config.policy.methods.{method}"),
                A2A_POLICY_METHOD_KEYS,
                "a2a_gateway: ",
            )?;
            let action = PolicyAction::parse(
                optional_string(object, "action")?.ok_or_else(|| {
                    format!("a2a_gateway: policy.methods[{method:?}].action is required")
                })?,
                &format!("policy.methods[{method:?}].action"),
            )?;
            if methods
                .insert(canonical_method.to_string(), action)
                .is_some()
            {
                return Err(format!(
                    "a2a_gateway: duplicate policy method name {canonical_method:?}"
                ));
            }
        }
    }
    Ok(A2aPolicyConfig {
        default_action,
        methods,
    })
}

fn parse_jsonrpc_envelope(value: &Value) -> Result<A2aEnvelope, ()> {
    let object = value.as_object().ok_or(())?;
    Ok(A2aEnvelope {
        id: object.get("id").cloned(),
        method: object
            .get("method")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        jsonrpc: object
            .get("jsonrpc")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        is_request: object.contains_key("method"),
        is_error: object.contains_key("error"),
    })
}

fn deny_response(detection: &A2aDetection) -> PluginResult {
    match detection.binding {
        A2aBinding::JsonRpc => PluginResult::Reject {
            status_code: 200,
            body: jsonrpc_error_response_body(
                detection,
                -32001,
                "A2A method denied by gateway policy",
            )
            .to_string(),
            headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
        },
        A2aBinding::Rest => PluginResult::Reject {
            status_code: 403,
            body: json!({
                "error": "A2A method denied by gateway policy",
                "method": detection.method
            })
            .to_string(),
            headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
        },
        A2aBinding::Grpc => PluginResult::Reject {
            status_code: 403,
            body: "A2A method denied by gateway policy".to_string(),
            headers: HashMap::new(),
        },
    }
}

fn jsonrpc_error_response_body(detection: &A2aDetection, code: i64, message: &str) -> Value {
    let response = json!({
        "jsonrpc": "2.0",
        "id": detection.jsonrpc_id.clone().unwrap_or(Value::Null),
        "error": {
            "code": code,
            "message": message,
            "data": {
                "gateway": "a2a_gateway",
                "method": detection.method
            }
        }
    });
    if detection.jsonrpc_batch_response {
        Value::Array(vec![response])
    } else {
        response
    }
}

fn oversized_jsonrpc_response(detection: &A2aDetection) -> PluginResult {
    PluginResult::Reject {
        status_code: 413,
        body: jsonrpc_error_response_body(
            detection,
            -32013,
            "A2A request body exceeds gateway detection limit",
        )
        .to_string(),
        headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
    }
}

fn match_rest_operation(method: &str, rest: &str) -> Option<(&'static str, Option<String>, bool)> {
    let rest = normalized_rest_path(rest)?;
    if method.eq_ignore_ascii_case("POST") && rest == "message:send" {
        return Some(("message/send", None, false));
    }
    if method.eq_ignore_ascii_case("POST") && rest == "message:stream" {
        return Some(("message/stream", None, true));
    }
    if method.eq_ignore_ascii_case("GET") && rest == "card" {
        return Some(("agent/getAuthenticatedExtendedCard", None, false));
    }
    if method.eq_ignore_ascii_case("GET") && rest == "extendedAgentCard" {
        return Some(("agent/getExtendedAgentCard", None, false));
    }
    if method.eq_ignore_ascii_case("GET") && rest == "tasks" {
        return Some(("tasks/list", None, false));
    }
    if let Some(task_id) = rest
        .strip_prefix("tasks/")
        .and_then(|tail| tail.strip_suffix(":cancel"))
        && method.eq_ignore_ascii_case("POST")
        && is_simple_path_id(task_id)
    {
        return Some(("tasks/cancel", Some(task_id.to_string()), false));
    }
    if let Some(task_id) = rest
        .strip_prefix("tasks/")
        .and_then(|tail| tail.strip_suffix(":subscribe"))
        && (method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("POST"))
        && is_simple_path_id(task_id)
    {
        return Some(("tasks/resubscribe", Some(task_id.to_string()), true));
    }
    if let Some(parent) = rest.strip_suffix("/pushNotificationConfigs")
        && let Some(task_id) = parent.strip_prefix("tasks/")
        && is_simple_path_id(task_id)
    {
        if method.eq_ignore_ascii_case("GET") {
            return Some((
                "tasks/pushNotificationConfig/list",
                Some(task_id.to_string()),
                false,
            ));
        }
        if method.eq_ignore_ascii_case("POST") {
            return Some((
                "tasks/pushNotificationConfig/set",
                Some(task_id.to_string()),
                false,
            ));
        }
    }
    if let Some(tail) = rest.strip_prefix("tasks/")
        && let Some((task_id, rest_tail)) = tail.split_once("/pushNotificationConfigs/")
        && is_simple_path_id(task_id)
        && is_simple_path_id(rest_tail)
    {
        if method.eq_ignore_ascii_case("GET") {
            return Some((
                "tasks/pushNotificationConfig/get",
                Some(task_id.to_string()),
                false,
            ));
        }
        if method.eq_ignore_ascii_case("DELETE") {
            return Some((
                "tasks/pushNotificationConfig/delete",
                Some(task_id.to_string()),
                false,
            ));
        }
    }
    if let Some(task_id) = rest.strip_prefix("tasks/")
        && method.eq_ignore_ascii_case("GET")
        && is_simple_path_id(task_id)
        && !task_id.ends_with(":cancel")
        && !task_id.ends_with(":subscribe")
    {
        return Some(("tasks/get", Some(task_id.to_string()), false));
    }
    None
}

fn normalized_rest_path(rest: &str) -> Option<&str> {
    let rest = rest.strip_prefix('/')?;
    let rest = strip_optional_rest_version(rest);
    if is_a2a_rest_route(rest) {
        return Some(rest);
    }
    let (_tenant, tail) = rest.split_once('/')?;
    let tail = strip_optional_rest_version(tail);
    is_a2a_rest_route(tail).then_some(tail)
}

fn strip_optional_rest_version(rest: &str) -> &str {
    rest.strip_prefix("v1/").unwrap_or(rest)
}

fn is_a2a_rest_route(rest: &str) -> bool {
    matches!(
        rest,
        "message:send" | "message:stream" | "card" | "extendedAgentCard" | "tasks"
    ) || rest.starts_with("tasks/")
}

fn is_simple_path_id(value: &str) -> bool {
    !value.is_empty() && !value.contains('/')
}

fn grpc_operation(method: &str) -> Option<(&'static str, bool)> {
    match method {
        "SetTaskPushNotificationConfig" => Some(("tasks/pushNotificationConfig/set", false)),
        // GetAgentCard resolves through canonical_a2a_method() below so gRPC
        // detection and policy-key normalization share one mapping and cannot
        // drift (the gRPC card RPC is the authenticated extended card).
        _ => canonical_a2a_method(method).map(|method| (method, is_streaming_method(method))),
    }
}

fn is_streaming_method(method: &str) -> bool {
    matches!(method, "message/stream" | "tasks/resubscribe")
}

fn is_agent_card_method(method: &str) -> bool {
    matches!(
        method,
        "agent/getCard" | "agent/getExtendedAgentCard" | "agent/getAuthenticatedExtendedCard"
    )
}

fn canonical_policy_method(method: &str) -> Option<&'static str> {
    if method == "unknown" {
        Some("unknown")
    } else {
        canonical_a2a_method(method)
    }
}

pub(crate) fn canonical_a2a_method(method: &str) -> Option<&'static str> {
    if let Some(canonical) = JSONRPC_METHODS
        .iter()
        .copied()
        .find(|canonical| *canonical == method)
    {
        return Some(canonical);
    }
    match method {
        "SendMessage" => Some("message/send"),
        "SendStreamingMessage" => Some("message/stream"),
        "GetTask" => Some("tasks/get"),
        "ListTasks" => Some("tasks/list"),
        "CancelTask" => Some("tasks/cancel"),
        "SubscribeToTask" | "TaskSubscription" => Some("tasks/resubscribe"),
        "CreateTaskPushNotificationConfig" | "CreateTaskPushNotification" => {
            Some("tasks/pushNotificationConfig/set")
        }
        "GetTaskPushNotificationConfig" | "GetTaskPushNotification" => {
            Some("tasks/pushNotificationConfig/get")
        }
        "ListTaskPushNotificationConfigs"
        | "ListTaskPushNotificationConfig"
        | "ListTaskPushNotification" => Some("tasks/pushNotificationConfig/list"),
        "DeleteTaskPushNotificationConfig" | "DeleteTaskPushNotification" => {
            Some("tasks/pushNotificationConfig/delete")
        }
        // The gRPC/PascalCase `GetAgentCard` RPC is the authenticated extended
        // card; keep this aligned with `grpc_operation()` so a `GetAgentCard`
        // policy key targets the same method the gRPC binding detects.
        "GetAgentCard" => Some("agent/getAuthenticatedExtendedCard"),
        "GetExtendedAgentCard" => Some("agent/getExtendedAgentCard"),
        "GetAuthenticatedExtendedCard" => Some("agent/getAuthenticatedExtendedCard"),
        _ => None,
    }
}

fn extract_task_id_from_request(value: &Value) -> Option<String> {
    string_at_any_path(
        value,
        &[
            &["params", "taskId"],
            &["params", "task_id"],
            &["params", "id"],
            &["params", "task", "id"],
            &["params", "message", "taskId"],
            &["params", "message", "task_id"],
        ],
    )
    .or_else(|| task_name_at_any_path(value, &[&["params", "name"], &["params", "task", "name"]]))
}

fn emit_response_metadata(ctx: &mut RequestContext, value: &Value, limit: usize) {
    if let Ok(envelope) = parse_jsonrpc_envelope(value)
        && envelope.is_error
        && let Some(error) = value.get("error")
    {
        if let Some(code) = error.get("code").and_then(Value::as_i64) {
            ctx.metadata
                .insert("a2a.error".to_string(), code.to_string());
        } else if let Some(message) = error.get("message").and_then(Value::as_str) {
            insert_bounded_metadata(ctx, "a2a.error", message, limit);
        }
    }
    if let Some(task_id) = extract_task_id_from_response(ctx.a2a_gateway_binding, value) {
        insert_bounded_metadata(ctx, "a2a.task_id", &task_id, limit);
    }
    if let Some(context_id) = extract_context_id_from_response(ctx.a2a_gateway_binding, value) {
        insert_bounded_metadata(ctx, "a2a.context_id", &context_id, limit);
    }
    if let Some(state) = find_task_state(value) {
        emit_task_state(ctx, &state, limit);
    }
}

fn extract_task_id_from_response(binding: Option<&str>, value: &Value) -> Option<String> {
    let common_id_paths: &[&[&str]] = &[
        &["result", "taskId"],
        &["result", "task_id"],
        &["result", "id"],
        &["result", "task", "id"],
        &["task", "id"],
    ];
    let rest_id_paths: &[&[&str]] = &[&["taskId"], &["task_id"], &["id"]];
    string_at_any_path(value, common_id_paths)
        .or_else(|| rest_only(binding, || string_at_any_path(value, rest_id_paths)))
        .or_else(|| {
            task_name_at_any_path(
                value,
                &[
                    &["result", "name"],
                    &["result", "task", "name"],
                    &["task", "name"],
                ],
            )
        })
        .or_else(|| rest_only(binding, || task_name_at_any_path(value, &[&["name"]])))
}

fn extract_context_id_from_response(binding: Option<&str>, value: &Value) -> Option<String> {
    let common_paths: &[&[&str]] = &[
        &["result", "contextId"],
        &["result", "context_id"],
        &["result", "task", "contextId"],
        &["result", "task", "context_id"],
        &["task", "contextId"],
        &["task", "context_id"],
    ];
    let rest_paths: &[&[&str]] = &[&["contextId"], &["context_id"]];
    string_at_any_path(value, common_paths)
        .or_else(|| rest_only(binding, || string_at_any_path(value, rest_paths)))
}

/// Evaluate `lookup` only when the detected binding is REST, flattening the
/// guard so callers stay in `Option<String>` rather than `Option<Option<_>>`.
/// REST responses lack the JSON-RPC `result` envelope, so a handful of id/name
/// fields are read from the top level for that binding alone.
fn rest_only(binding: Option<&str>, lookup: impl FnOnce() -> Option<String>) -> Option<String> {
    (binding == Some("rest")).then(lookup).flatten()
}

fn string_at_any_path(value: &Value, paths: &[&[&str]]) -> Option<String> {
    paths.iter().find_map(|path| {
        get_path(value, path)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn task_name_at_any_path(value: &Value, paths: &[&[&str]]) -> Option<String> {
    paths.iter().find_map(|path| {
        get_path(value, path)
            .and_then(Value::as_str)
            .and_then(task_id_from_name)
    })
}

fn find_task_state(value: &Value) -> Option<String> {
    let candidates = [
        &["result", "status", "state"][..],
        &["result", "task", "status", "state"][..],
        &["result", "statusUpdate", "status", "state"][..],
        &["result", "status_update", "status", "state"][..],
        &["task", "status", "state"][..],
        &["statusUpdate", "status", "state"][..],
        &["status_update", "status", "state"][..],
        &["status", "state"][..],
    ];
    for path in candidates {
        if let Some(state) = get_path(value, path).and_then(Value::as_str) {
            return Some(state.to_string());
        }
    }
    None
}

fn get_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

fn task_id_from_name(value: &str) -> Option<String> {
    value
        .strip_prefix("tasks/")
        .filter(|task_id| !task_id.is_empty() && !task_id.contains('/'))
        .map(ToOwned::to_owned)
}

// Only protocol states enter semantic metadata; arbitrary backend text is not
// a state. Bound work before normalization as well as the retained result.
fn normalize_task_state(value: &str) -> String {
    if value.len() > 64 {
        return "unknown".to_string();
    }
    let normalized = value.to_ascii_lowercase();
    let state = normalized
        .strip_prefix("task_state_")
        .unwrap_or(&normalized);
    match state.replace('_', "-").as_str() {
        "submitted" => "submitted",
        "working" => "working",
        "input-required" => "input-required",
        "completed" => "completed",
        "canceled" | "cancelled" => "canceled",
        "failed" => "failed",
        "rejected" => "rejected",
        "auth-required" => "auth-required",
        _ => "unknown",
    }
    .to_string()
}

fn emit_task_state(ctx: &mut RequestContext, value: &str, limit: usize) {
    let state = normalize_task_state(value);
    if state.len() > limit.min(1024) {
        ctx.metadata.remove("a2a.task_state");
        ctx.metadata
            .insert("a2a.task_state.truncated".to_string(), "true".to_string());
    } else {
        ctx.metadata
            .insert("a2a.task_state".to_string(), state.clone());
        ctx.metadata.remove("a2a.task_state.truncated");
    }
    if state == "unknown" && !value.eq_ignore_ascii_case("unknown") {
        ctx.metadata
            .insert("a2a.task_state.unrecognized".to_string(), "true".to_string());
    } else {
        ctx.metadata.remove("a2a.task_state.unrecognized");
    }
    if value.len() > limit.min(1024) {
        ctx.metadata
            .insert("a2a.task_state.truncated".to_string(), "true".to_string());
    }
}

/// The cap includes the ASCII marker. The separate flag distinguishes a
/// truncated identifier from a complete one with the same visible prefix.
/// A truncated identifier is diagnostic text, never an exact correlation key.
fn insert_bounded_metadata(ctx: &mut RequestContext, key: &str, value: &str, limit: usize) {
    let limit = limit.min(1024);
    let marker_key = match key {
        "a2a.task_id" => "a2a.task_id.truncated",
        "a2a.context_id" => "a2a.context_id.truncated",
        "a2a.error" => "a2a.error.truncated",
        "a2a.protocol_version" => "a2a.protocol_version.truncated",
        _ => return,
    };
    if value.len() <= limit {
        ctx.metadata.remove(marker_key);
        ctx.metadata.insert(key.to_string(), value.to_string());
        return;
    }
    let mut end = limit.saturating_sub(1);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut bounded = value[..end].to_string();
    if limit > 0 {
        bounded.push('~');
    }
    ctx.metadata.insert(key.to_string(), bounded);
    ctx.metadata.insert(marker_key.to_string(), "true".to_string());
}

fn agent_card_origin_failure(
    ctx: &mut RequestContext,
    grpc: bool,
    emit_metadata: bool,
) -> PluginResult {
    if emit_metadata {
        ctx.metadata.insert(
            "a2a.error".to_string(),
            "agent_card_public_origin_unavailable".to_string(),
        );
    }
    if grpc {
        return grpc_agent_card_rewrite_failure("agent_card_public_origin_unavailable");
    }
    PluginResult::Reject {
        status_code: 502,
        body: "{\"error\":\"agent_card_public_origin_unavailable\"}".to_string(),
        headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
    }
}

fn looks_like_agent_card(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    (object.contains_key("url")
        || object.contains_key("additionalInterfaces")
        || object.contains_key("additional_interfaces")
        || object.contains_key("supportedInterfaces")
        || object.contains_key("supported_interfaces"))
        && (object.contains_key("name") || object.contains_key("description"))
}

fn rewrite_agent_card_response(
    value: &mut Value,
    public_base: &str,
    endpoint_path: &str,
    agent_card_path: &str,
) -> bool {
    if let Some(batch) = value.as_array_mut() {
        let mut changed = false;
        for item in batch {
            changed |=
                rewrite_agent_card_response(item, public_base, endpoint_path, agent_card_path);
        }
        return changed;
    }
    if looks_like_agent_card(value) {
        return rewrite_agent_card_urls(value, public_base, endpoint_path, agent_card_path);
    }
    let Some(result) = value.get_mut("result") else {
        return false;
    };
    if !looks_like_agent_card(result) {
        return false;
    }
    rewrite_agent_card_urls(result, public_base, endpoint_path, agent_card_path)
}

fn rewrite_agent_card_urls(
    value: &mut Value,
    public_base: &str,
    endpoint_path: &str,
    agent_card_path: &str,
) -> bool {
    let Some(object) = value.as_object_mut() else {
        return false;
    };
    let mut changed = false;
    let preferred_transport = object
        .get("preferredTransport")
        .or_else(|| object.get("preferred_transport"))
        .and_then(Value::as_str);
    if should_rewrite_transport(preferred_transport)
        && let Some(url) = object.get_mut("url")
    {
        changed |= rewrite_url_value(url, public_base, endpoint_path);
    }
    for key in [
        "additionalInterfaces",
        "additional_interfaces",
        "supportedInterfaces",
        "supported_interfaces",
    ] {
        if let Some(Value::Array(interfaces)) = object.get_mut(key) {
            for interface in interfaces {
                let Some(interface_object) = interface.as_object_mut() else {
                    continue;
                };
                if !should_rewrite_transport(interface_transport(interface_object)) {
                    continue;
                }
                if let Some(url) = interface_object.get_mut("url") {
                    changed |= rewrite_url_value(url, public_base, endpoint_path);
                }
            }
        }
    }
    if let Some(url) = object.get_mut("agentCardUrl") {
        changed |= rewrite_url_value(url, public_base, agent_card_path);
    }
    if changed {
        object.remove("signatures");
    }
    changed
}

fn interface_transport(interface: &Map<String, Value>) -> Option<&str> {
    interface
        .get("transport")
        .or_else(|| interface.get("protocolBinding"))
        .or_else(|| interface.get("protocol_binding"))
        .and_then(Value::as_str)
}

fn should_rewrite_transport(transport: Option<&str>) -> bool {
    let Some(transport) = transport else {
        return true;
    };
    let normalized: String = transport
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    normalized == "jsonrpc"
}

/// Fail-closed terminal for a unary gRPC Agent Card the gateway admitted but
/// could not safely rewrite.
///
/// The HTTP status is `200`, matching
/// [`crate::plugins::grpc_deadline_exceeded_plugin_result`] and the rest of the
/// gateway's gRPC terminals: a gRPC failure rides HTTP 200 plus a `grpc-status`
/// trailer, and the normalizer collapses this to a Trailers-Only error with an
/// empty body, so the refused card's bytes never reach the client. An HTTP `500`
/// here would additionally publish a synthetic 5xx into transaction summaries
/// and gateway metrics for what is a gateway-side policy refusal, not a backend
/// fault. (Backend health, the circuit breaker, and adaptive concurrency are
/// unaffected either way — they record the backend's own dispatch outcome before
/// any response-body hook runs.)
///
/// `diagnostic` is always one of this module's fixed, low-cardinality string
/// literals. No response byte, header value, or URL is ever reflected into
/// `grpc-message` or `a2a.error`.
fn grpc_agent_card_rewrite_failure(diagnostic: &'static str) -> PluginResult {
    PluginResult::Reject {
        status_code: 200,
        body: String::new(),
        headers: HashMap::from([
            ("content-type".to_string(), "application/grpc".to_string()),
            ("grpc-status".to_string(), "13".to_string()),
            ("grpc-message".to_string(), diagnostic.to_string()),
        ]),
    }
}

/// Positive proof that a buffered upstream response is a SUCCESSFUL unary gRPC
/// reply, and therefore a candidate Agent Card at all.
///
/// Two independent facts are required, and neither is inferred:
///
/// - HTTP `200`. The gRPC HTTP/2 mapping puts every gRPC outcome under 200, so
///   any other status is a transport/gateway-level failure whose body is not a
///   protobuf message.
/// - A terminal `grpc-status` that is present and exactly `0`. On the buffered
///   native-gRPC path plugins see a merged header+trailer view
///   (`grpc_proxy::build_grpc_plugin_header_view`) in which the trailing value
///   wins for the reserved terminal keys, so an upstream that streamed
///   `HEADERS(200) + DATA + TRAILERS(grpc-status: 13)` is visible here as the
///   failure it is. Requiring the field to be PRESENT is the load-bearing half:
///   an absent terminal status is not an OK response — the client synthesizes
///   `UNKNOWN` for it — and treating "no status" as success is exactly how a
///   non-OK upstream reply gets mistaken for an Agent Card and then refused with
///   a rewrite diagnostic that blames the gateway.
///
/// An unproven response is left completely alone: the plugin neither rewrites it
/// nor fails it closed, so the upstream's own error reaches the client verbatim.
fn grpc_response_is_proven_ok(
    response_status: u16,
    response_headers: &HashMap<String, String>,
) -> bool {
    response_status == 200
        && header_value(response_headers, "grpc-status").is_some_and(|status| status.trim() == "0")
}

/// A unary gRPC Agent Card frame that passed decode, schema validation, and the
/// 0.3 layout gate. Borrows the backend's bytes; nothing is copied.
struct AdmittedAgentCard<'a> {
    /// The unframed protobuf message (the gRPC 5-byte prefix removed).
    message: &'a [u8],
    /// `AgentCard.preferred_transport` (field 14) when the card carries one.
    preferred_transport: Option<&'a str>,
}

/// Why a staged gRPC Agent Card rewrite produced no client-visible bytes.
///
/// The two arms have different client-visible terminals and must never be
/// conflated: a capacity refusal belongs to the shared retained-response
/// terminal (`503` / `RESOURCE_EXHAUSTED`, health-neutral, gateway-local), while
/// a fault is this plugin's own fail-closed gRPC `INTERNAL`.
enum AgentCardRewriteRefusal {
    /// Fixed, low-cardinality diagnostic. Never carries response content.
    Diagnostic(&'static str),
    /// The rewrite did not fit the per-response retained ceiling.
    Capacity,
}

/// Prove the gRPC SERVICE this reply came from is declared to carry the A2A 0.3
/// `AgentCard` layout, before a single byte of it is interpreted.
///
/// This is the service-identity half of the gate, and it is deliberately first:
/// a decoder is chosen by the protocol the endpoint speaks, never by whichever
/// layout the bytes could be coerced into. A2A publishes two gRPC packages —
/// `a2a.v1` (0.3) and `lf.a2a.v1` (1.0) — with materially different `AgentCard`
/// field numbers, so applying the 0.3 rewriter to a 1.0 service would replace
/// each `AgentInterface` submessage with a bare URL string and leave the real
/// signatures in place.
///
/// The two refusals are distinct facts and get distinct diagnostics:
/// `agent_card_grpc_schema_unsupported` means "this service's card layout is a
/// known one this gateway does not implement", and
/// `agent_card_grpc_schema_undeclared` means "this custom service never declared
/// a layout, so there is nothing to implement against". Neither is a complaint
/// about the card's own `protocol_version`, which is checked separately once the
/// layout question is settled.
fn require_rewritable_card_schema(schema: Option<A2aGrpcCardSchema>) -> Result<(), &'static str> {
    match schema {
        Some(A2aGrpcCardSchema::A2a03) => Ok(()),
        Some(A2aGrpcCardSchema::A2a10) => Err("agent_card_grpc_schema_unsupported"),
        // `None` is a gRPC Agent Card response with no recorded service
        // detection at all — unreachable through `should_rewrite_grpc_agent_card`,
        // and treated exactly like an undeclared layout rather than assumed 0.3.
        Some(A2aGrpcCardSchema::Undeclared) | None => Err("agent_card_grpc_schema_undeclared"),
    }
}

/// Decode, schema-validate, and version-gate a unary gRPC Agent Card body.
///
/// This is the single admission funnel: `on_response_body` calls it to decide
/// whether to stage a rewrite, and the transform phase calls it again over the
/// same bytes, so the two phases can never disagree about whether a card is
/// rewritable. It allocates nothing — every returned string borrows `body`.
///
/// A card on a service that does not declare the A2A 0.3 layout is rejected
/// before decoding ([`require_rewritable_card_schema`]); one that does not then
/// carry an explicit A2A 0.3.x `protocol_version` naming a configured version is
/// rejected with `unsupported_agent_card_protobuf_version` rather than forwarded
/// — see [`supports_agent_card_protobuf_layout`].
fn admit_grpc_agent_card_frame<'a>(
    body: &'a [u8],
    response_headers: &HashMap<String, String>,
    card_schema: Option<A2aGrpcCardSchema>,
    configured_versions: &[String],
) -> Result<AdmittedAgentCard<'a>, &'static str> {
    // Question zero, before a byte is read: does the SERVICE this reply came
    // from declare the layout this rewriter implements? A decoder is selected by
    // the endpoint's protocol, never by what the bytes could be read as.
    require_rewritable_card_schema(card_schema)?;
    let message = extract_uncompressed_unary_grpc_message(body, response_headers)?;
    // Then three ordered questions, because the diagnostic a client sees should
    // name the FIRST thing that is actually wrong:
    //
    //   1. Does this decode as protobuf, and is it Agent-Card shaped at all?
    //   2. Is its point release one this rewriter implements and the operator
    //      configured? A renumbered A2A 1.0 card served over a 0.3-declared
    //      service answers "no" here, and
    //      `unsupported_agent_card_protobuf_version` is the accurate, documented
    //      reason — not a complaint about a field 3 whose 0.3 meaning it never
    //      claimed to have.
    //   3. Only then: is the card well formed UNDER that layout?
    let probe = probe_agent_card_layout(message)?;
    if !probe.has_identity || !probe.has_endpoint {
        return Err("agent_card_protobuf_shape_unrecognized");
    }
    if let Some(fault) = probe.version_fault {
        return Err(fault);
    }
    let protocol_version = probe.protocol_version.unwrap_or("");
    if !supports_agent_card_protobuf_layout(protocol_version, configured_versions) {
        return Err("unsupported_agent_card_protobuf_version");
    }
    let schema = validate_agent_card_protobuf(message)?;
    Ok(AdmittedAgentCard {
        message,
        preferred_transport: schema.preferred_transport,
    })
}

/// Admission check for `on_response_body`: prove the card is rewritable without
/// producing a single output byte. The transform phase performs the bounded
/// rewrite.
fn validate_grpc_agent_card_rewrite(
    body: &[u8],
    response_headers: &HashMap<String, String>,
    card_schema: Option<A2aGrpcCardSchema>,
    configured_versions: &[String],
) -> Result<(), &'static str> {
    admit_grpc_agent_card_frame(body, response_headers, card_schema, configured_versions)
        .map(|_| ())
}

/// Rewrite a unary gRPC Agent Card frame straight into a ceiling-aware sink.
///
/// Returns `Ok(None)` when the card needs no mutation, `Ok(Some(frame))` with
/// the complete re-framed response, and `Err(..)` for anything that must fail
/// closed.
///
/// # Why this is two passes and not a builder
///
/// The retained-response contract forbids materialising a complete would-be
/// replacement outside the reserved construction sink (`GHSA-pwcm-6rh8-f2gh`):
/// a producer that assembles a finished `Vec` and then copies it through a
/// bounded writer has already made the allocation the aggregate budget exists to
/// bound. Protobuf makes that awkward, because a length-delimited record — the
/// gRPC frame's 5-byte prefix, and every rewritten `additional_interfaces`
/// submessage — declares its payload length BEFORE the payload.
///
/// So the same emission code runs twice over the same immutable input. Pass one
/// writes into [`ProtobufLengthCounter`], which allocates nothing and only
/// accumulates a byte count; that yields the exact frame length and whether any
/// URL actually changes. Pass two writes those identical bytes, from the first
/// byte, into [`BoundedResponseBodySink`], which refuses the write that would
/// cross the ceiling instead of allocating for it. At no point does a second
/// copy of the message, or of any interface submessage, exist.
///
/// Both passes are single, bounded, allocation-free walks of the input, so the
/// CPU cost stays linear in the response size with a small constant factor.
///
/// "Fail closed" includes any card that does not prove the 0.3 layout: a gRPC
/// service that does not declare the 0.3 card schema yields
/// `agent_card_grpc_schema_unsupported` / `agent_card_grpc_schema_undeclared`,
/// an absent/empty or non-configured `protocol_version` yields
/// `unsupported_agent_card_protobuf_version`, a known field with the wrong wire
/// type or a duplicated singular field yields
/// `agent_card_protobuf_field_wire_mismatch` / `..._field_duplicated`, and a URL
/// field that is not an absolute http(s) URL yields
/// `agent_card_protobuf_url_layout_mismatch`. The gateway never rewrites a
/// layout it cannot identify.
fn rewrite_grpc_agent_card_frame(
    body: &[u8],
    response_headers: &HashMap<String, String>,
    card_schema: Option<A2aGrpcCardSchema>,
    public_base: &str,
    endpoint_path: &str,
    configured_versions: &[String],
    ceiling: usize,
) -> Result<Option<Vec<u8>>, AgentCardRewriteRefusal> {
    let admitted =
        admit_grpc_agent_card_frame(body, response_headers, card_schema, configured_versions);
    let card = admitted.map_err(AgentCardRewriteRefusal::Diagnostic)?;
    // The one public URL every rewritten field reuses. Built once per response,
    // never per field and never per interface.
    let new_url = format!("{}{}", public_base.trim_end_matches('/'), endpoint_path);
    // An explicitly-encoded empty `preferred_transport` is proto3's default and
    // means "unset", which selects the JSON-RPC default just like an absent
    // field. Only a present, non-empty, non-JSONRPC transport suppresses the
    // `AgentCard.url` rewrite.
    let rewrite_preferred =
        should_rewrite_transport(card.preferred_transport.filter(|value| !value.is_empty()));

    // Pass one: exact encoded length, and whether anything changes at all. A
    // refused write here can only be the counter's own `usize` overflow, which
    // means the rewritten card cannot be addressed at all.
    let mut counter = ProtobufLengthCounter::default();
    let mut changed = false;
    emit_rewritten_agent_card(
        card.message,
        &new_url,
        rewrite_preferred,
        &mut counter,
        &mut changed,
    )
    .map_err(|error| {
        AgentCardRewriteRefusal::Diagnostic(if error == EMIT_REFUSED {
            "agent_card_grpc_frame_too_large"
        } else {
            error
        })
    })?;
    if !changed {
        // Nothing to rewrite: the backend's original, still-signed bytes are
        // forwarded untouched. `output` was never built, so there is nothing to
        // discard.
        return Ok(None);
    }
    let Ok(message_len) = u32::try_from(counter.len) else {
        return Err(AgentCardRewriteRefusal::Diagnostic(
            "agent_card_grpc_frame_too_large",
        ));
    };

    // Pass two: the same bytes, written from the first one into the sink.
    // `0 = unlimited` was already folded to the retained-response fallback by
    // `RequestContext::retained_response_body_ceiling`; a raw `0` here would make
    // every non-empty write refuse.
    let mut sink =
        crate::proxy::response_buffer_budget::BoundedResponseBodySink::with_ceiling(ceiling);
    if !sink.emit(&[0]) || !sink.emit(&message_len.to_be_bytes()) {
        return Err(AgentCardRewriteRefusal::Capacity);
    }
    let mut emitted_changed = false;
    emit_rewritten_agent_card(
        card.message,
        &new_url,
        rewrite_preferred,
        &mut sink,
        &mut emitted_changed,
    )
    .map_err(|error| {
        if error == EMIT_REFUSED {
            AgentCardRewriteRefusal::Capacity
        } else {
            AgentCardRewriteRefusal::Diagnostic(error)
        }
    })?;
    // The two passes run the same code over the same immutable bytes, so they
    // cannot legitimately disagree. Verifying it anyway keeps a future edit that
    // makes emission input-dependent from silently shipping a frame whose length
    // prefix was measured under different decisions.
    if emitted_changed != changed {
        return Err(AgentCardRewriteRefusal::Diagnostic(
            "agent_card_protobuf_rewrite_unstable",
        ));
    }
    match sink.finish() {
        // Compared by subtracting the 5-byte prefix off the published frame
        // rather than adding it to the measured length, so the check itself
        // cannot overflow `usize` on a 32-bit target.
        Some(frame) if frame.len().checked_sub(5) == Some(counter.len) => Ok(Some(frame)),
        // A published length that disagrees with the declared prefix would be a
        // malformed gRPC frame, so it is refused rather than emitted.
        Some(_) => Err(AgentCardRewriteRefusal::Diagnostic(
            "agent_card_protobuf_rewrite_unstable",
        )),
        None => Err(AgentCardRewriteRefusal::Capacity),
    }
}

/// Decide whether a decoded card may be rewritten with the 0.3.x field numbers.
///
/// This runs only AFTER [`require_rewritable_card_schema`] has proved the gRPC
/// service itself is declared to carry the 0.3 layout. The two checks answer
/// different questions and neither substitutes for the other: the service says
/// which `AgentCard` schema the endpoint speaks, the wire version says which
/// point release of that schema this particular card claims.
///
/// Two independent conditions, both required:
///
/// 1. **The wire version is one the operator configured.**
///    `endpoint.protocol_versions` is documented as a list of exact A2A protocol
///    version strings — there is no family, range, or wildcard syntax in the
///    schema (`openapi.yaml`) or in `docs/plugins.md` — so the comparison is
///    exact after trimming. Configuring `["0.3.0"]` therefore admits `0.3.0` and
///    refuses `0.3.99`: a version the operator never listed is a backend the
///    operator never vouched for, and its card layout is not this gateway's to
///    guess. An empty list admits nothing (config validation already rejects
///    one, so this is defense in depth rather than a reachable branch).
/// 2. **That version maps to the wire layout this rewriter implements**, which
///    is only the A2A 0.3 family. A configured `1.0.0` that a backend echoes
///    back is an exact match under (1) and still refused here, because the
///    rewriter's field numbers do not describe it.
///
/// The gate is also positive: rewriting requires affirmative evidence of the 0.3
/// layout ON THE WIRE. An absent or empty `protocol_version` is NOT evidence.
/// proto3 cannot distinguish "unset" from `""`, and every non-0.3 layout also
/// lacks field 16 — A2A 1.0 removed `protocol_version` from `AgentCard`
/// entirely — so an empty version is exactly the case where the gateway cannot
/// tell a 0.3 card from a renumbered one. Treating it as 0.3 (which the
/// operator's `endpoint.protocol_versions` would have permitted) corrupts 1.0
/// cards, so it fails closed instead, regardless of configuration.
fn supports_agent_card_protobuf_layout(
    protocol_version: &str,
    configured_versions: &[String],
) -> bool {
    let version = protocol_version.trim();
    if version.is_empty() {
        return false;
    }
    is_a2a_03_family(version)
        && configured_versions
            .iter()
            .any(|configured| configured.trim() == version)
}

fn is_a2a_03_family(version: &str) -> bool {
    let version = version.trim();
    version == "0.3" || version.starts_with("0.3.")
}

/// Upper bound, in bytes, on a rewritable Agent Card URL field before it is
/// refused without being handed to the URL parser at all.
///
/// The response body is already bounded by the retained-response ceiling, but a
/// single field inside it can still be megabytes of `http://`-prefixed text. An
/// endpoint URL that no client could put in a request line is not a URL this
/// gateway needs to identify, so the bound is applied first and the parse only
/// ever runs over a small, fixed amount of input.
const MAX_AGENT_CARD_URL_BYTES: usize = 4096;

/// Proof that a URL-bearing field the rewriter mutates really holds an absolute
/// `http`/`https` URL.
///
/// In the 0.3 layout `AgentCard.url` (field 3) and `AgentInterface.url`
/// (field 1) always hold one. UTF-8 validity alone does not prove that: a
/// serialized `AgentInterface` — which is what field 3 holds in the A2A 1.0
/// layout — is frequently valid UTF-8, because its tag bytes (`0x0a`, `0x12`),
/// short length prefixes, and ASCII URL/transport strings all stay below `0x80`.
/// So a value that is not an absolute http(s) URL is treated as a layout
/// mismatch and the rewrite fails closed rather than guessing.
///
/// A scheme *prefix* test is not that proof. `http://` followed by anything at
/// all — an empty authority, a bare `?`, a control character, a nested
/// `http://` — begins with those bytes without being a URL, and a submessage
/// whose first field happens to carry such a string would pass. This therefore
/// parses with the same `url::Url` the configured `discovery.public_base_url`
/// is validated against, under a fixed set of requirements:
///
/// - The input is bounded ([`MAX_AGENT_CARD_URL_BYTES`]) and free of ASCII
///   whitespace and control characters. The WHATWG parser silently strips
///   leading/trailing C0 and space and removes embedded tabs/newlines, so
///   without this a value that is *not* the URL it parses as would be accepted
///   and then re-emitted verbatim.
/// - The parsed scheme is exactly `http` or `https` — never `file`, `data`, or
///   an unknown scheme that merely embeds one of them.
/// - A real, non-empty host is present.
/// - The wire spelling carries an explicit `http`/`https` authority before any
///   path, query, or fragment. WHATWG recovery can infer a host from forms such
///   as `http:///a2a` where the authority is empty on the wire; those spellings
///   are rejected because downstream parsers may disagree.
/// - No embedded credentials. `http://user:pass@host/` is a URL, but publishing
///   one in a rewritten Agent Card would advertise a credential to every
///   discovery client, and Ferrum rejects embedded credentials at every other
///   boundary (`validate_public_base_url` does the same for the configured
///   base).
///
/// Only the boolean verdict leaves this function: the parsed/normalized form is
/// never emitted, so the backend's own bytes are what get preserved when no
/// rewrite is needed.
fn http_scheme_rest(value: &str) -> Option<&str> {
    if value
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
    {
        return value.get(7..);
    }
    if value
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
    {
        return value.get(8..);
    }
    None
}

/// Require a canonical absolute `http`/`https` authority spelling on the wire.
fn has_explicit_http_authority_spelling(value: &str) -> bool {
    let Some(rest) = http_scheme_rest(value) else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    !authority.is_empty()
        && !authority.starts_with(':')
        && !authority.bytes().any(|byte| byte == b'\\')
}

fn is_absolute_http_url(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_AGENT_CARD_URL_BYTES {
        return false;
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return false;
    }
    if !has_explicit_http_authority_spelling(value) {
        return false;
    }
    let Ok(parsed) = Url::parse(value) else {
        return false;
    };
    matches!(parsed.scheme(), "http" | "https")
        && parsed.host_str().is_some_and(|host| !host.is_empty())
        && parsed.username().is_empty()
        && parsed.password().is_none()
}

/// Decode a rewritable URL field, rejecting anything that is not an absolute
/// http(s) URL. See [`is_absolute_http_url`].
fn decode_rewritable_url_field(value: &[u8]) -> Result<&str, &'static str> {
    let current = std::str::from_utf8(value).map_err(|_| "agent_card_protobuf_url_invalid")?;
    if !is_absolute_http_url(current) {
        return Err("agent_card_protobuf_url_layout_mismatch");
    }
    Ok(current)
}

fn extract_uncompressed_unary_grpc_message<'a>(
    body: &'a [u8],
    response_headers: &HashMap<String, String>,
) -> Result<&'a [u8], &'static str> {
    if let Some(encoding) = header_value(response_headers, "grpc-encoding") {
        let encoding = encoding.trim();
        if !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity") {
            return Err("agent_card_grpc_encoding_unsupported");
        }
    }
    if body.len() < 5 {
        return Err("agent_card_grpc_frame_malformed");
    }
    if body[0] != 0 {
        return Err("agent_card_grpc_encoding_unsupported");
    }
    let msg_len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    let Some(expected) = msg_len.checked_add(5) else {
        return Err("agent_card_grpc_frame_malformed");
    };
    if expected != body.len() {
        return Err("agent_card_grpc_frame_malformed");
    }
    Ok(&body[5..])
}

// ---------------------------------------------------------------------------
// Bounded protobuf emission
// ---------------------------------------------------------------------------

/// Maximum protobuf field number, `2^29 - 1`. A tag whose field number exceeds
/// this is not valid protobuf, so it is refused rather than silently truncated
/// into a `u32`.
const PROTO_MAX_FIELD_NUMBER: u32 = (1 << 29) - 1;

/// Sentinel error meaning "the output pass refused a write", as opposed to a
/// decode or schema fault. It never reaches a client: callers translate it into
/// the counting pass's `agent_card_grpc_frame_too_large` or the sink pass's
/// capacity refusal.
const EMIT_REFUSED: &str = "agent_card_protobuf_emit_refused";

/// One output pass of the bounded protobuf rewriter.
///
/// The rewrite runs the SAME emission code against a counter and then against
/// the response sink; see [`rewrite_grpc_agent_card_frame`] for why that is what
/// keeps a length-prefixed message off the heap until the ceiling admits it.
trait ProtobufEmitter {
    /// Append `bytes`, or refuse. `false` is terminal for the pass.
    fn emit(&mut self, bytes: &[u8]) -> bool;
}

/// The allocation-free pass. Accumulates the exact encoded length and nothing
/// else; a `usize` overflow is refused rather than wrapped into an affordable
/// length.
#[derive(Default)]
struct ProtobufLengthCounter {
    len: usize,
}

impl ProtobufEmitter for ProtobufLengthCounter {
    fn emit(&mut self, bytes: &[u8]) -> bool {
        match self.len.checked_add(bytes.len()) {
            Some(len) => {
                self.len = len;
                true
            }
            None => false,
        }
    }
}

impl ProtobufEmitter for crate::proxy::response_buffer_budget::BoundedResponseBodySink {
    fn emit(&mut self, bytes: &[u8]) -> bool {
        self.push(bytes)
    }
}

/// Turn a refused write into the sentinel error so it propagates out of a
/// [`for_each_protobuf_field`] visitor.
fn emit_or_refuse(emitted: bool) -> Result<(), &'static str> {
    if emitted { Ok(()) } else { Err(EMIT_REFUSED) }
}

/// Base-128 varint. The scratch array is a fixed 10-byte STACK buffer — the
/// maximum encoded width of a `u64` — so no heap allocation stands beside the
/// sink.
fn emit_varint<E: ProtobufEmitter>(out: &mut E, mut value: u64) -> bool {
    let mut scratch = [0u8; 10];
    let mut len = 0;
    while value >= 0x80 {
        scratch[len] = (value as u8) | 0x80;
        len += 1;
        value >>= 7;
    }
    scratch[len] = value as u8;
    len += 1;
    out.emit(&scratch[..len])
}

fn emit_protobuf_key<E: ProtobufEmitter>(out: &mut E, field: u32, wire: u8) -> bool {
    emit_varint(out, u64::from(field) << 3 | u64::from(wire))
}

/// A complete length-delimited record whose payload is already in hand.
fn emit_protobuf_len_field<E: ProtobufEmitter>(out: &mut E, field: u32, value: &[u8]) -> bool {
    emit_protobuf_key(out, field, PROTO_WIRE_LEN)
        && emit_varint(out, value.len() as u64)
        && out.emit(value)
}

/// The tag and length prefix of a length-delimited record whose payload the
/// caller writes next. `payload_len` comes from the counting pass, which is what
/// removes the need to build the submessage first.
fn emit_protobuf_len_header<E: ProtobufEmitter>(
    out: &mut E,
    field: u32,
    payload_len: usize,
) -> bool {
    emit_protobuf_key(out, field, PROTO_WIRE_LEN) && emit_varint(out, payload_len as u64)
}

/// A field the rewriter does not touch, re-emitted with its original bytes.
fn emit_protobuf_verbatim_field<E: ProtobufEmitter>(
    out: &mut E,
    field: u32,
    wire: u8,
    value: &[u8],
) -> bool {
    if wire == PROTO_WIRE_LEN {
        emit_protobuf_len_field(out, field, value)
    } else {
        emit_protobuf_key(out, field, wire) && out.emit(value)
    }
}

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

/// What one bounded decode pass can say about a candidate card BEFORE its
/// layout family is known.
///
/// Deliberately layout-agnostic except for `protocol_version`: field presence is
/// judged by field NUMBER only, exactly as the pre-repair shape check did, so a
/// renumbered A2A 1.0 card is still recognised as Agent-Card-shaped and refused
/// with the version diagnostic rather than with a 0.3-specific field complaint.
struct AgentCardLayoutProbe<'a> {
    /// `AgentCard.protocol_version` (field 16), when it is a well-formed string.
    protocol_version: Option<&'a str>,
    /// A wire-type / duplication / UTF-8 fault on field 16 itself. Held rather
    /// than raised so the "is this an Agent Card at all" verdict comes first.
    version_fault: Option<&'static str>,
    /// A `name` or `description` is present.
    has_identity: bool,
    /// A `url` or at least one `additional_interfaces` is present.
    has_endpoint: bool,
}

/// One bounded decode pass answering "is this Agent-Card shaped, and what
/// protocol version does it claim?".
///
/// Decode faults (truncation, invalid field number, unsupported wire type,
/// varint overflow) propagate immediately: nothing about the message can be
/// trusted once the framing is ambiguous.
fn probe_agent_card_layout(message: &[u8]) -> Result<AgentCardLayoutProbe<'_>, &'static str> {
    let mut probe = AgentCardLayoutProbe {
        protocol_version: None,
        version_fault: None,
        has_identity: false,
        has_endpoint: false,
    };
    let mut version_seen = false;
    for_each_protobuf_field(message, |field, wire, value| {
        match field {
            AGENT_CARD_PB_NAME | AGENT_CARD_PB_DESCRIPTION => probe.has_identity = true,
            AGENT_CARD_PB_URL | AGENT_CARD_PB_ADDITIONAL_INTERFACES => probe.has_endpoint = true,
            AGENT_CARD_PB_PROTOCOL_VERSION => {
                if version_seen {
                    probe.version_fault = Some("agent_card_protobuf_field_duplicated");
                } else if wire != PROTO_WIRE_LEN {
                    probe.version_fault = Some("agent_card_protobuf_field_wire_mismatch");
                } else {
                    match decode_protobuf_string(value) {
                        Ok(version) => probe.protocol_version = Some(version),
                        Err(fault) => probe.version_fault = Some(fault),
                    }
                }
                version_seen = true;
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok(probe)
}

/// The known A2A 0.3 `AgentCard` scalars the rewrite decision reads, each proven
/// to appear at most once and with the wire type the 0.3 schema declares.
///
/// `protocol_version` is not carried here: the layout gate already read it from
/// [`AgentCardLayoutProbe`], and one authoritative reader is what keeps the gate
/// and the rewriter from disagreeing about which version admitted the card.
struct AgentCardSchema<'a> {
    preferred_transport: Option<&'a str>,
}

/// The known A2A 0.3 `AgentInterface` scalars, under the same proof.
struct AgentInterfaceSchema<'a> {
    url: Option<&'a str>,
    transport: Option<&'a str>,
}

fn expect_len_wire(wire: u8) -> Result<(), &'static str> {
    if wire == PROTO_WIRE_LEN {
        Ok(())
    } else {
        Err("agent_card_protobuf_field_wire_mismatch")
    }
}

fn expect_varint_wire(wire: u8) -> Result<(), &'static str> {
    if wire == PROTO_WIRE_VARINT {
        Ok(())
    } else {
        Err("agent_card_protobuf_field_wire_mismatch")
    }
}

/// Every singular top-level `AgentCard` field, so a second occurrence of any of
/// them is refused instead of silently taking proto3 last-wins semantics.
///
/// One `bool` per singular field rather than a bitmask: the compiler then
/// catches a field added to the wire table but never claimed here.
#[derive(Default)]
struct AgentCardSingularFields {
    name: bool,
    description: bool,
    url: bool,
    provider: bool,
    version: bool,
    documentation_url: bool,
    capabilities: bool,
    supports_authenticated_extended_card: bool,
    preferred_transport: bool,
    protocol_version: bool,
}

/// Claim a singular field, refusing a second occurrence.
fn claim_singular_field(seen: &mut bool) -> Result<(), &'static str> {
    if *seen {
        return Err("agent_card_protobuf_field_duplicated");
    }
    *seen = true;
    Ok(())
}

fn decode_protobuf_string(value: &[u8]) -> Result<&str, &'static str> {
    std::str::from_utf8(value).map_err(|_| "agent_card_protobuf_string_invalid")
}

/// Decode a protobuf `bool` field from the raw varint bytes the decoder
/// captured.
///
/// [`for_each_protobuf_field`] already proved the varint is canonical, so a
/// conforming `bool` is exactly one byte: `0x00` or `0x01`. Anything else — a
/// `2`, a `0xff`, or a longer encoding — is a value no conforming protobuf
/// encoder emits for this type, which makes it exactly the kind of
/// wire-representable-but-unrepresentable value this module refuses everywhere
/// else (over-long varints, group wire types, out-of-range field numbers). The
/// field is preserved verbatim beside rewritten siblings once the signature
/// block is dropped, so accepting a shape the backend's own parser would read
/// differently is not a difference this gateway may paper over.
fn decode_protobuf_bool(value: &[u8]) -> Result<bool, &'static str> {
    match value {
        [0x00] => Ok(false),
        [0x01] => Ok(true),
        _ => Err("agent_card_protobuf_bool_invalid"),
    }
}

/// Prove `message` is a schema-valid A2A 0.3 `AgentCard` before any field is
/// rewritten.
///
/// # What is actually validated, and where the boundary is
///
/// EVERY known top-level field of the 0.3 `AgentCard` is checked — all
/// seventeen, not just the ones whose values the rewriter reads. Three
/// properties are enforced, and the boundary past them is stated exactly so this
/// is not read as a deep validation it is not:
///
/// 1. **Wire type.** Each known number must carry the wire type the 0.3 schema
///    declares: length-delimited for every string, submessage, map entry, and
///    repeated string; a varint for the one `bool`
///    (`supports_authenticated_extended_card`, field 13), whose value must also
///    be a canonical `0`/`1` (see [`decode_protobuf_bool`]). A known field with
///    an unexpected wire type — `url` as a varint, `additional_interfaces` as a
///    fixed32 — would otherwise fall through the rewriter's catch-all arm and be
///    PRESERVED verbatim while its siblings were rewritten and the signature
///    block was dropped, publishing a half-rewritten card under no signature at
///    all.
/// 2. **Multiplicity.** Every singular field is claimed once
///    ([`AgentCardSingularFields`]); a second occurrence is ambiguous, because
///    proto3 last-wins semantics would let a backend hide the URL that actually
///    gets served behind a decoy earlier in the message. The genuinely repeated
///    fields — `security_schemes` (map entries), `security`,
///    `default_input_modes`, `default_output_modes`, `skills`,
///    `additional_interfaces`, `signatures` — may of course repeat.
/// 3. **UTF-8 for every known string that is re-emitted.** `name`,
///    `description`, `version`, `documentation_url`, `default_input_modes`,
///    `default_output_modes`, `preferred_transport`, and `protocol_version` are
///    all copied into the rebuilt card, so a value the gateway cannot even
///    represent as text must not be republished as though it had been
///    inspected. `url` is held to the stronger absolute-URL proof.
///
/// **The boundary:** the opaque submessages this rewriter deliberately preserves
/// — `provider` (4), `capabilities` (7), each `security_schemes` map entry (8),
/// each `security` (9), each `skills` (12), and each `signatures` (17) — are
/// checked for wire type and multiplicity ONLY. Their contents are never
/// decoded, and nothing here claims they are well formed. The single nested
/// exception is `additional_interfaces` (15), which the rewriter itself parses
/// and can mutate, so each `AgentInterface` gets its own required-shape check in
/// [`validate_agent_interface_protobuf`].
///
/// Unknown fields with any valid wire type are untouched and preserved, so a
/// newer 0.3.x point release that adds a field still round-trips.
///
/// The identity/endpoint requirement (a `name` or `description`, plus a `url` or
/// at least one usable `additional_interfaces`) is what distinguishes an Agent
/// Card from an arbitrary protobuf message that happens to decode.
fn validate_agent_card_protobuf(message: &[u8]) -> Result<AgentCardSchema<'_>, &'static str> {
    let mut preferred_transport = None;
    let mut seen = AgentCardSingularFields::default();
    let mut has_identity = false;
    let mut has_endpoint = false;
    for_each_protobuf_field(message, |field, wire, value| {
        match field {
            // ── Singular strings ─────────────────────────────────────────
            AGENT_CARD_PB_NAME => {
                claim_singular_field(&mut seen.name)?;
                expect_len_wire(wire)?;
                decode_protobuf_string(value)?;
                has_identity = true;
            }
            AGENT_CARD_PB_DESCRIPTION => {
                claim_singular_field(&mut seen.description)?;
                expect_len_wire(wire)?;
                decode_protobuf_string(value)?;
                has_identity = true;
            }
            AGENT_CARD_PB_VERSION => {
                claim_singular_field(&mut seen.version)?;
                expect_len_wire(wire)?;
                decode_protobuf_string(value)?;
            }
            // Not held to the absolute-URL proof: `documentation_url` is human
            // documentation the gateway never rewrites or fronts, and the 0.3
            // schema places no absoluteness requirement on it.
            AGENT_CARD_PB_DOCUMENTATION_URL => {
                claim_singular_field(&mut seen.documentation_url)?;
                expect_len_wire(wire)?;
                decode_protobuf_string(value)?;
            }
            AGENT_CARD_PB_PREFERRED_TRANSPORT => {
                claim_singular_field(&mut seen.preferred_transport)?;
                expect_len_wire(wire)?;
                preferred_transport = Some(decode_protobuf_string(value)?);
            }
            AGENT_CARD_PB_PROTOCOL_VERSION => {
                claim_singular_field(&mut seen.protocol_version)?;
                expect_len_wire(wire)?;
                decode_protobuf_string(value)?;
            }
            // ── Endpoint fields ──────────────────────────────────────────
            AGENT_CARD_PB_URL => {
                claim_singular_field(&mut seen.url)?;
                expect_len_wire(wire)?;
                // Validated even when `preferred_transport` means this field is
                // not rewritten: field 3 holding something that is not an
                // absolute http(s) URL is evidence the layout is not 0.3 at all,
                // which disqualifies the whole card, not just this field.
                decode_rewritable_url_field(value)?;
                has_endpoint = true;
            }
            AGENT_CARD_PB_ADDITIONAL_INTERFACES => {
                expect_len_wire(wire)?;
                // Every interface must carry a usable URL, so reaching this line
                // really does prove the card advertises an endpoint.
                validate_agent_interface_protobuf(value)?;
                has_endpoint = true;
            }
            // ── Repeated strings ─────────────────────────────────────────
            AGENT_CARD_PB_DEFAULT_INPUT_MODES | AGENT_CARD_PB_DEFAULT_OUTPUT_MODES => {
                expect_len_wire(wire)?;
                decode_protobuf_string(value)?;
            }
            // ── The one varint field ─────────────────────────────────────
            AGENT_CARD_PB_SUPPORTS_AUTHENTICATED_EXTENDED_CARD => {
                claim_singular_field(&mut seen.supports_authenticated_extended_card)?;
                expect_varint_wire(wire)?;
                decode_protobuf_bool(value)?;
            }
            // ── Singular opaque submessages (shape only; see the doc) ─────
            AGENT_CARD_PB_PROVIDER => {
                claim_singular_field(&mut seen.provider)?;
                expect_len_wire(wire)?;
            }
            AGENT_CARD_PB_CAPABILITIES => {
                claim_singular_field(&mut seen.capabilities)?;
                expect_len_wire(wire)?;
            }
            // ── Repeated opaque submessages / map entries ────────────────
            AGENT_CARD_PB_SECURITY_SCHEMES
            | AGENT_CARD_PB_SECURITY
            | AGENT_CARD_PB_SKILLS
            | AGENT_CARD_PB_SIGNATURES => expect_len_wire(wire)?,
            // Unknown, valid future fields: preserved verbatim.
            _ => {}
        }
        Ok(())
    })?;
    if !has_identity || !has_endpoint {
        return Err("agent_card_protobuf_shape_unrecognized");
    }
    Ok(AgentCardSchema {
        preferred_transport,
    })
}

/// The `AgentInterface` counterpart of [`validate_agent_card_protobuf`], for the
/// one nested message the rewriter actually parses and can mutate.
///
/// `url` is REQUIRED here even though the 0.3 proto carries no
/// `field_behavior` annotation on it. An interface without a URL is not a usable
/// endpoint: it can never be the JSON-RPC endpoint the gateway fronts, so
/// [`agent_interface_needs_rewrite`] would leave it untouched, and it would then
/// be preserved verbatim inside a card published as "rewritten" with its
/// signatures removed — while also being the only thing that made the card look
/// like it advertised an endpoint at all. Requiring the field means reaching the
/// end of this function proves a usable endpoint, and an explicitly-encoded
/// empty URL is already refused by the absolute-URL proof.
fn validate_agent_interface_protobuf(
    message: &[u8],
) -> Result<AgentInterfaceSchema<'_>, &'static str> {
    let mut url = None;
    let mut transport = None;
    let mut url_seen = false;
    let mut transport_seen = false;
    for_each_protobuf_field(message, |field, wire, value| {
        match field {
            AGENT_INTERFACE_PB_URL => {
                claim_singular_field(&mut url_seen)?;
                expect_len_wire(wire)?;
                url = Some(decode_rewritable_url_field(value)?);
            }
            AGENT_INTERFACE_PB_TRANSPORT => {
                claim_singular_field(&mut transport_seen)?;
                expect_len_wire(wire)?;
                transport = Some(decode_protobuf_string(value)?);
            }
            _ => {}
        }
        Ok(())
    })?;
    if url.is_none() {
        return Err("agent_card_protobuf_interface_url_missing");
    }
    Ok(AgentInterfaceSchema { url, transport })
}

/// Whether this advertised interface is the JSON-RPC endpoint the gateway
/// fronts, and is not already pointing at the public URL.
fn agent_interface_needs_rewrite(schema: &AgentInterfaceSchema<'_>, new_url: &str) -> bool {
    should_rewrite_transport(schema.transport.filter(|value| !value.is_empty()))
        && schema.url.is_some_and(|url| url != new_url)
}

// ---------------------------------------------------------------------------
// Rewrite emission
// ---------------------------------------------------------------------------

/// Emit the rewritten `AgentCard` body into `out`, recording in `changed`
/// whether any URL actually differs from the public one.
///
/// Runs identically into the counting pass and into the response sink. The card
/// has already been schema-validated, so the arms below can rely on the wire
/// types they name instead of re-checking them and falling through on mismatch.
fn emit_rewritten_agent_card<E: ProtobufEmitter>(
    message: &[u8],
    new_url: &str,
    rewrite_preferred: bool,
    out: &mut E,
    changed: &mut bool,
) -> Result<(), &'static str> {
    for_each_protobuf_field(message, |field, wire, value| {
        match field {
            AGENT_CARD_PB_SIGNATURES => {
                // Omitted from the rebuilt card: every rewritten field
                // invalidates the signatures over it. When nothing changes the
                // caller discards this pass entirely and forwards the backend's
                // original, still-signed bytes.
                Ok(())
            }
            AGENT_CARD_PB_URL if rewrite_preferred => {
                let current = decode_rewritable_url_field(value)?;
                if current == new_url {
                    emit_or_refuse(emit_protobuf_len_field(out, field, value))
                } else {
                    *changed = true;
                    emit_or_refuse(emit_protobuf_len_field(
                        out,
                        AGENT_CARD_PB_URL,
                        new_url.as_bytes(),
                    ))
                }
            }
            AGENT_CARD_PB_ADDITIONAL_INTERFACES => {
                let schema = validate_agent_interface_protobuf(value)?;
                if !agent_interface_needs_rewrite(&schema, new_url) {
                    return emit_or_refuse(emit_protobuf_len_field(out, field, value));
                }
                *changed = true;
                // The submessage's own length prefix comes from a counting pass
                // over the same emission code, so the rewritten interface is
                // never built as a separate `Vec` beside the sink.
                let mut counter = ProtobufLengthCounter::default();
                emit_rewritten_agent_interface(value, new_url, &mut counter)?;
                emit_or_refuse(emit_protobuf_len_header(out, field, counter.len))?;
                emit_rewritten_agent_interface(value, new_url, out)
            }
            _ => emit_or_refuse(emit_protobuf_verbatim_field(out, field, wire, value)),
        }
    })
}

/// Emit one rewritten `AgentInterface` submessage body (no length prefix).
/// Only called for an interface [`agent_interface_needs_rewrite`] selected.
fn emit_rewritten_agent_interface<E: ProtobufEmitter>(
    message: &[u8],
    new_url: &str,
    out: &mut E,
) -> Result<(), &'static str> {
    for_each_protobuf_field(message, |field, wire, value| {
        if field == AGENT_INTERFACE_PB_URL {
            emit_or_refuse(emit_protobuf_len_field(
                out,
                AGENT_INTERFACE_PB_URL,
                new_url.as_bytes(),
            ))
        } else {
            emit_or_refuse(emit_protobuf_verbatim_field(out, field, wire, value))
        }
    })
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Visit each top-level protobuf field of `message`.
///
/// The visitor receives `&'a [u8]` — the SAME lifetime as `message` — rather
/// than a higher-ranked `&[u8]`. Every value handed to the visitor is a
/// subslice of `message` (`split_at` / `&start[..consumed]`), so this is sound,
/// and it lets a caller such as [`validate_agent_card_protobuf`] hoist a
/// borrowed field value out of the closure instead of copying it.
///
/// Tags are validated before dispatch: a field number of `0` or above
/// [`PROTO_MAX_FIELD_NUMBER`] is not representable protobuf and is refused
/// rather than truncated into a `u32`, and the group wire types (`3`/`4`) are
/// refused outright rather than being resynchronized against.
fn for_each_protobuf_field<'a>(
    mut message: &'a [u8],
    mut visit: impl FnMut(u32, u8, &'a [u8]) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    while !message.is_empty() {
        let key = decode_varint(&mut message)?;
        let wire = (key & 0x07) as u8;
        let Ok(field) = u32::try_from(key >> 3) else {
            return Err("agent_card_protobuf_field_invalid");
        };
        if field == 0 || field > PROTO_MAX_FIELD_NUMBER {
            return Err("agent_card_protobuf_field_invalid");
        }
        let value = match wire {
            PROTO_WIRE_VARINT => {
                let start = message;
                let _ = decode_varint(&mut message)?;
                let consumed = start.len() - message.len();
                &start[..consumed]
            }
            PROTO_WIRE_64BIT => {
                if message.len() < 8 {
                    return Err("agent_card_protobuf_truncated");
                }
                let (value, rest) = message.split_at(8);
                message = rest;
                value
            }
            PROTO_WIRE_LEN => {
                // Checked, not `as usize`: on a 32-bit target an unchecked cast
                // truncates a 64-bit length into a small one that then passes
                // the bounds check below and silently reinterprets the
                // remainder of the message.
                let Ok(len) = usize::try_from(decode_varint(&mut message)?) else {
                    return Err("agent_card_protobuf_length_invalid");
                };
                if message.len() < len {
                    return Err("agent_card_protobuf_truncated");
                }
                let (value, rest) = message.split_at(len);
                message = rest;
                value
            }
            PROTO_WIRE_32BIT => {
                if message.len() < 4 {
                    return Err("agent_card_protobuf_truncated");
                }
                let (value, rest) = message.split_at(4);
                message = rest;
                value
            }
            _ => return Err("agent_card_protobuf_wire_type_unsupported"),
        };
        visit(field, wire, value)?;
    }
    Ok(())
}

/// Strict base-128 varint decode.
///
/// Three refusals a permissive decoder gets wrong, all of which let one byte
/// sequence mean two different things to the gateway and the backend:
///
/// - **Overflow.** A ten-byte varint's final byte contributes bits 63..69, so
///   only `0x00` and `0x01` are representable. A larger final byte is refused
///   rather than having its high bits truncated by the shift.
/// - **Over-long encoding.** More than ten bytes never terminates a `u64`.
/// - **Non-canonical padding.** A continuation chain that ends in a zero
///   group (`0x81 0x00` for `1`) encodes a value that already fit in fewer
///   bytes. Every conforming encoder emits the minimal form, so the redundant
///   form is refused instead of being accepted as an alias.
fn decode_varint(buf: &mut &[u8]) -> Result<u64, &'static str> {
    let mut result = 0u64;
    for shift in (0..64).step_by(7) {
        let Some((&byte, rest)) = buf.split_first() else {
            return Err("agent_card_protobuf_truncated");
        };
        *buf = rest;
        if shift == 63 && byte > 0x01 {
            // Bits above 63 have nowhere to go; `<< 63` would drop them.
            return Err("agent_card_protobuf_varint_overflow");
        }
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            if shift > 0 && byte == 0 {
                return Err("agent_card_protobuf_varint_noncanonical");
            }
            return Ok(result);
        }
    }
    Err("agent_card_protobuf_varint_overflow")
}
fn rewrite_url_value(value: &mut Value, public_base: &str, path: &str) -> bool {
    if !value.is_string() {
        return false;
    }
    let new_url = format!("{}{}", public_base.trim_end_matches('/'), path);
    if value.as_str() == Some(new_url.as_str()) {
        return false;
    }
    *value = Value::String(new_url);
    true
}

fn forwarded_public_base_url(proto: &str, host: &str) -> Option<String> {
    if proto.contains(',') || host.contains(',') {
        return None;
    }
    let scheme = normalized_public_scheme(proto)?;
    if host.is_empty()
        || host
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'\\' | b'@'))
    {
        return None;
    }
    let candidate = format!("{scheme}://{host}");
    let parsed = Url::parse(&candidate).ok()?;
    if parsed.scheme() != scheme
        || parsed.host_str().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

fn normalized_public_scheme(value: &str) -> Option<&'static str> {
    let scheme = value.trim_end_matches(':');
    if scheme.eq_ignore_ascii_case("http") {
        Some("http")
    } else if scheme.eq_ignore_ascii_case("https") {
        Some("https")
    } else {
        None
    }
}

fn content_type_is_json(headers: &HashMap<String, String>) -> bool {
    header_value(headers, "content-type").is_none_or(content_type_value_is_json)
}

fn content_type_value_is_json(value: &str) -> bool {
    let media_type = value.split(';').next().unwrap_or(value).trim();
    media_type.eq_ignore_ascii_case("application/json")
        || media_type.eq_ignore_ascii_case("application/json-rpc")
        || media_type
            .rsplit_once('+')
            .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("json"))
}

fn is_event_stream_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .unwrap_or(value)
        .trim()
        .eq_ignore_ascii_case("text/event-stream")
}

fn is_grpc_request(headers: &HashMap<String, String>) -> bool {
    header_value(headers, "content-type").is_some_and(|value| {
        crate::proxy::backend_dispatch::is_native_grpc_content_type(value.as_bytes())
    })
}

fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_str()))
}

fn remove_header(headers: &mut HashMap<String, String>, name: &str) {
    headers.retain(|key, _| !key.eq_ignore_ascii_case(name));
}

fn optional_object<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a Map<String, Value>>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(value)) => Ok(Some(value)),
        Some(other) => Err(format!(
            "a2a_gateway: '{key}' must be an object, got {other}"
        )),
    }
}

fn optional_bool(object: &Map<String, Value>, key: &str) -> Result<Option<bool>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(other) => Err(format!(
            "a2a_gateway: '{key}' must be a boolean, got {other}"
        )),
    }
}

fn optional_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        Some(other) => Err(format!(
            "a2a_gateway: '{key}' must be a string, got {other}"
        )),
    }
}

fn optional_string_from_object(
    object: Option<&Map<String, Value>>,
    key: &str,
) -> Result<Option<String>, String> {
    match object.and_then(|object| object.get(key)) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(other) => Err(format!(
            "a2a_gateway: '{key}' must be a string, got {other}"
        )),
    }
}

fn optional_bool_from_object(
    object: Option<&Map<String, Value>>,
    key: &str,
) -> Result<Option<bool>, String> {
    match object.and_then(|object| object.get(key)) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(other) => Err(format!(
            "a2a_gateway: '{key}' must be a boolean, got {other}"
        )),
    }
}

fn optional_u64_from_object(
    object: Option<&Map<String, Value>>,
    key: &str,
) -> Result<Option<u64>, String> {
    match object.and_then(|object| object.get(key)) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or_else(|| format!("a2a_gateway: '{key}' must be a positive integer"))
            .map(Some),
        Some(other) => Err(format!(
            "a2a_gateway: '{key}' must be a positive integer, got {other}"
        )),
    }
}

fn optional_string_vec_from_object(
    object: Option<&Map<String, Value>>,
    key: &str,
) -> Result<Option<Vec<String>>, String> {
    let Some(value) = object.and_then(|object| object.get(key)) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let array = value
        .as_array()
        .ok_or_else(|| format!("a2a_gateway: '{key}' must be an array"))?;
    let mut values = Vec::with_capacity(array.len());
    for (idx, item) in array.iter().enumerate() {
        values.push(
            item.as_str()
                .ok_or_else(|| format!("a2a_gateway: '{key}[{idx}]' must be a string"))?
                .to_string(),
        );
    }
    Ok(Some(values))
}

fn validate_path(path: &str, field: &str) -> Result<(), String> {
    if path.is_empty() || !path.starts_with('/') {
        return Err(format!("a2a_gateway: '{field}' must be a non-empty path"));
    }
    Ok(())
}

fn validate_header_name(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("a2a_gateway: '{field}' must not be empty"));
    }
    http::header::HeaderName::from_bytes(value.as_bytes())
        .map(|_| ())
        .map_err(|_| {
            format!("a2a_gateway: '{field}' must be a valid HTTP header name, got {value:?}")
        })
}

fn validate_public_base_url(value: &str) -> Result<(), String> {
    let parsed = Url::parse(value)
        .map_err(|error| format!("a2a_gateway: discovery.public_base_url invalid: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(
            "a2a_gateway: discovery.public_base_url scheme must be http or https".to_string(),
        );
    }
    if parsed.host_str().is_none() {
        return Err("a2a_gateway: discovery.public_base_url missing host".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(
            "a2a_gateway: discovery.public_base_url must not contain credentials".to_string(),
        );
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(
            "a2a_gateway: discovery.public_base_url must not contain query or fragment".to_string(),
        );
    }
    Ok(())
}

fn validate_grpc_service(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value
            .split('.')
            .any(|part| part.is_empty() || !is_valid_grpc_identifier(part))
    {
        return Err(format!(
            "a2a_gateway: endpoint.grpc_services entries must be valid gRPC service names, got {value:?}"
        ));
    }
    Ok(())
}

fn is_valid_grpc_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
