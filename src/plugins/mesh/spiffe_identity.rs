//! SPIFFE Identity Extraction Plugin
//!
//! Extracts a SPIFFE ID from the peer certificate's URI SAN and populates
//! `ctx.peer_spiffe_id`. Mesh deployments add this plugin to their proxy
//! config; non-mesh deployments never instantiate it — zero cost.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use serde_json::Value;
use tracing::debug;

use crate::identity::SpiffeId;
use crate::identity::spiffe::UriSanError;
use crate::plugins::{
    HTTP_FAMILY_AND_STREAM_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext,
    StreamConnectionContext, priority,
};

/// Outcome of extracting a SPIFFE ID from a peer certificate. The peer
/// certificate is fixed for the lifetime of a TLS connection, so the outcome
/// is immutable once derived and safe to share across every multiplexed
/// request on the connection.
#[derive(Debug, Clone)]
pub enum PeerSpiffeExtraction {
    /// The certificate carries exactly one valid SPIFFE URI SAN.
    Id(SpiffeId),
    /// The certificate has no SPIFFE URI SAN (or no SAN extension): no-op.
    NoSpiffeId,
    /// Multiple URI SANs or a malformed `spiffe://` URI: reject 403. Carries
    /// the error display for debug logs.
    Invalid(String),
    /// The DER did not parse as X.509: log-and-continue. Carries the error
    /// display for debug logs.
    Unparsed(String),
}

fn derive_peer_spiffe_extraction(der: &[u8]) -> PeerSpiffeExtraction {
    match crate::identity::spiffe::try_extract_spiffe_id(der) {
        Ok(Some(id)) => PeerSpiffeExtraction::Id(id),
        Ok(None) => PeerSpiffeExtraction::NoSpiffeId,
        Err(error) if uri_san_error_requires_rejection(&error) => {
            PeerSpiffeExtraction::Invalid(error.to_string())
        }
        Err(error) => PeerSpiffeExtraction::Unparsed(error.to_string()),
    }
}

/// Connection-local cache of the peer-cert SPIFFE extraction outcome.
///
/// HTTP-family listeners create one cache per mTLS transport connection
/// (alongside `MtlsAuthConnectionCache`) and share it across multiplexed
/// request contexts, so the full X.509 DER parse in `try_extract_spiffe_id`
/// runs at most once per connection instead of once per request. After the
/// first request the hot path is a single lock-free `OnceLock::get` load;
/// only the first extraction on a connection is serialized.
#[derive(Default)]
pub struct SpiffeIdentityConnectionCache {
    outcome: OnceLock<PeerSpiffeExtraction>,
    extraction_count: AtomicUsize,
}

impl std::fmt::Debug for SpiffeIdentityConnectionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeIdentityConnectionCache")
            .field("outcome", &self.outcome.get())
            .field("extraction_count", &self.extraction_count())
            .finish()
    }
}

impl SpiffeIdentityConnectionCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of certificate DER extractions performed through this cache.
    /// Exposed for instrumentation-backed regression tests.
    pub fn extraction_count(&self) -> usize {
        self.extraction_count.load(Ordering::Relaxed)
    }

    fn outcome(&self, der: &[u8]) -> &PeerSpiffeExtraction {
        self.outcome.get_or_init(|| {
            self.extraction_count.fetch_add(1, Ordering::Relaxed);
            derive_peer_spiffe_extraction(der)
        })
    }
}

pub struct SpiffeIdentity;

impl SpiffeIdentity {
    pub fn new(config: &Value) -> Result<Self, String> {
        match config {
            Value::Null => Ok(Self),
            Value::Object(obj) if obj.is_empty() => Ok(Self),
            Value::Object(_) => {
                Err("spiffe_identity: no configuration fields are supported".to_string())
            }
            other => Err(format!(
                "spiffe_identity: config must be an object, got: {other}"
            )),
        }
    }
}

fn uri_san_error_requires_rejection(error: &UriSanError) -> bool {
    matches!(
        error,
        UriSanError::MultipleUriSans { .. } | UriSanError::InvalidSpiffeId { .. }
    )
}

fn invalid_svid_reject(error: impl std::fmt::Display) -> PluginResult {
    debug!(
        "spiffe_identity: rejecting peer cert with invalid SPIFFE URI SAN: {}",
        error
    );
    PluginResult::Reject {
        status_code: 403,
        body: serde_json::json!({"error": "invalid SPIFFE identity certificate"}).to_string(),
        headers: std::collections::HashMap::new(),
    }
}

#[async_trait]
impl Plugin for SpiffeIdentity {
    fn name(&self) -> &str {
        "spiffe_identity"
    }

    fn priority(&self) -> u16 {
        priority::SPIFFE_IDENTITY
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        HTTP_FAMILY_AND_STREAM_PROTOCOLS
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        if ctx.peer_spiffe_id.is_some() {
            return PluginResult::Continue;
        }
        let Some(der) = ctx.tls_client_cert_der.clone() else {
            return PluginResult::Continue;
        };
        // Consume the connection-scoped outcome when the listener wired one
        // (H1/H2/H3 mTLS connections): the DER parse then runs at most once
        // per connection and every later multiplexed request reuses the
        // immutable outcome via a lock-free load. Contexts without a cache
        // (direct library callers, tests) derive inline with identical
        // semantics at per-request cost.
        let cache = ctx.peer_spiffe_extraction_cache.clone();
        let derived;
        let outcome = match cache.as_deref() {
            Some(cache) => cache.outcome(der.as_ref()),
            None => {
                derived = derive_peer_spiffe_extraction(der.as_ref());
                &derived
            }
        };
        match outcome {
            PeerSpiffeExtraction::Id(id) => {
                debug!("spiffe_identity: peer SPIFFE ID extracted: {}", id);
                ctx.peer_spiffe_id = Some(id.clone());
                PluginResult::Continue
            }
            PeerSpiffeExtraction::NoSpiffeId => PluginResult::Continue,
            PeerSpiffeExtraction::Invalid(error) => invalid_svid_reject(error),
            PeerSpiffeExtraction::Unparsed(error) => {
                debug!(
                    "spiffe_identity: could not parse peer cert for SPIFFE ID: {}",
                    error
                );
                PluginResult::Continue
            }
        }
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        // A pre-stamped peer identity (e.g. the node-waypoint eBPF-attested pod
        // SPIFFE ID set by the stream accept loop) must win over peer-cert
        // derivation here, mirroring the on_request_received guard. Otherwise a
        // TcpTls peer cert would clobber the kernel-attested pod principal that
        // mesh_authz uses for source-principal matching.
        if ctx
            .metadata
            .as_ref()
            .is_some_and(|m| m.contains_key("peer_spiffe_id"))
        {
            return PluginResult::Continue;
        }
        if let Some(der) = ctx.tls_client_cert_der.as_ref() {
            match crate::identity::spiffe::try_extract_spiffe_id(der.as_ref()) {
                Ok(Some(id)) => {
                    debug!("spiffe_identity: stream peer SPIFFE ID: {}", id);
                    ctx.insert_metadata("peer_spiffe_id".to_string(), id.to_string());
                }
                Ok(None) => {}
                Err(e) => {
                    if uri_san_error_requires_rejection(&e) {
                        return invalid_svid_reject(&e);
                    }
                    debug!(
                        "spiffe_identity: could not parse stream peer cert for SPIFFE ID: {}",
                        e
                    );
                }
            }
        }
        PluginResult::Continue
    }
}
