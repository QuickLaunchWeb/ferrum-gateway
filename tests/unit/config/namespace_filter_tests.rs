//! Structural parity for the shared `GatewayConfig` namespace projection.
//!
//! `retain_namespace` destructures `GatewayConfig` exhaustively, with no `..`
//! rest pattern, so a newly added namespace-owned field cannot compile until the
//! filter states what happens to it. That compile-time gate is half the
//! contract; the other half is the runtime assertion below, which populates
//! EVERY namespace-owned collection for two tenants and proves each one is
//! actually projected. A field added to the struct and then merely passed
//! through would still pass the compiler — it would not pass this test once the
//! fixture grows the corresponding entry, and the enumeration here is the list a
//! reviewer has to extend deliberately.

use ferrum_edge::config::gateway_trust::GatewayTrustBundleRecord;
use ferrum_edge::config::namespace_filter::{
    NamespaceRetention, retain_namespace, source_namespace_count,
};
use ferrum_edge::config::types::{FrontendTlsCertificateSource, GatewayConfig};
use ferrum_edge::identity::TrustDomain;
use ferrum_edge::modes::mesh::config::{TrustBundle, TrustBundleSet};
use serde_json::json;

/// Every namespace-owned collection on `GatewayConfig`, named once so the
/// assertions below and a future reviewer read the same list.
const NAMESPACE_OWNED_COLLECTIONS: [&str; 7] = [
    "proxies",
    "consumers",
    "plugin_configs",
    "upstreams",
    "gateway_trust_bundles",
    "frontend_tls_certificate_sources",
    "http_tls_listen_ports",
];

fn trust_record(namespace: &str) -> GatewayTrustBundleRecord {
    GatewayTrustBundleRecord::new(
        namespace,
        namespace,
        TrustBundleSet {
            local: TrustBundle {
                trust_domain: TrustDomain::new("cluster.local")
                    .expect("fixture trust domain is valid"),
                x509_authorities: Vec::new(),
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: Vec::new(),
        },
    )
}

fn tls_source(namespace: &str) -> FrontendTlsCertificateSource {
    FrontendTlsCertificateSource {
        namespace: namespace.to_string(),
        gateway: format!("{namespace}-gateway"),
        listener: "https".to_string(),
        hostname: None,
        cert_path: format!("/etc/ferrum/{namespace}/tls.crt"),
        key_path: format!("/etc/ferrum/{namespace}/tls.key"),
        default_certificate: true,
    }
}

/// A snapshot with an entry in every namespace-owned collection, for both
/// tenants. Deliberately built through serde for the wire-visible resources so
/// the fixture stays in step with the deserialization contract, and directly for
/// the `#[serde(skip)]` derived collections.
fn two_namespace_config() -> GatewayConfig {
    let mut config: GatewayConfig = serde_json::from_value(json!({
        "version": "1",
        "known_namespaces": ["tenant-a", "tenant-b"],
        "proxies": [
            {
                "id": "proxy-a",
                "namespace": "tenant-a",
                "listen_path": "/shared",
                "backend_host": "a.internal",
                "backend_port": 8080,
                "backend_scheme": "http"
            },
            {
                "id": "proxy-b",
                "namespace": "tenant-b",
                "listen_path": "/shared",
                "backend_host": "b.internal",
                "backend_port": 8080,
                "backend_scheme": "http"
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
                "config": {},
                "enabled": false
            },
            {
                "id": "plugin-b",
                "plugin_name": "key_auth",
                "namespace": "tenant-b",
                "scope": "global",
                "config": {},
                "enabled": false
            }
        ],
        "upstreams": [
            {"id": "upstream-a", "name": "up-a", "namespace": "tenant-a", "targets": []},
            {"id": "upstream-b", "name": "up-b", "namespace": "tenant-b", "targets": []}
        ],
        "frontend_tls_certificate_sources": [],
        "http_tls_listen_ports": [["tenant-a", 443], ["tenant-b", 443]]
    }))
    .expect("fixture deserializes");

    config.gateway_trust_bundles = vec![trust_record("tenant-a"), trust_record("tenant-b")];
    config.frontend_tls_certificate_sources = vec![tls_source("tenant-a"), tls_source("tenant-b")];
    config
}

#[test]
fn every_namespace_owned_collection_is_projected() {
    assert_eq!(
        NAMESPACE_OWNED_COLLECTIONS.len(),
        7,
        "extend this test when GatewayConfig grows a namespace-owned collection"
    );

    let config = two_namespace_config();
    // Guard the fixture itself: an empty collection would make its assertion
    // below vacuously true.
    assert_eq!(config.proxies.len(), 2);
    assert_eq!(config.consumers.len(), 2);
    assert_eq!(config.plugin_configs.len(), 2);
    assert_eq!(config.upstreams.len(), 2);
    assert_eq!(config.gateway_trust_bundles.len(), 2);
    assert_eq!(config.frontend_tls_certificate_sources.len(), 2);
    assert_eq!(config.http_tls_listen_ports.len(), 2);

    let (filtered, summary) = retain_namespace(config, "tenant-a", NamespaceRetention::SERVING);

    assert_eq!(filtered.proxies.len(), 1);
    assert_eq!(filtered.proxies[0].id, "proxy-a");
    assert_eq!(filtered.consumers.len(), 1);
    assert_eq!(filtered.consumers[0].id, "consumer-a");
    assert_eq!(filtered.plugin_configs.len(), 1);
    assert_eq!(filtered.plugin_configs[0].id, "plugin-a");
    assert_eq!(filtered.upstreams.len(), 1);
    assert_eq!(filtered.upstreams[0].id, "upstream-a");
    assert_eq!(filtered.gateway_trust_bundles.len(), 1);
    assert_eq!(filtered.gateway_trust_bundles[0].namespace, "tenant-a");
    assert_eq!(filtered.frontend_tls_certificate_sources.len(), 1);
    assert_eq!(
        filtered.frontend_tls_certificate_sources[0].namespace,
        "tenant-a"
    );
    let tls_listen_ports: Vec<(String, u16)> =
        filtered.http_tls_listen_ports.iter().cloned().collect();
    assert_eq!(tls_listen_ports, vec![("tenant-a".to_string(), 443u16)]);

    // The legacy singleton is re-projected from the retained set, never left
    // pointing at the other tenant's certificate.
    assert_eq!(
        filtered.frontend_tls_source_namespace.as_deref(),
        Some("tenant-a")
    );
    assert_eq!(
        filtered.frontend_tls_cert_path.as_deref(),
        Some("/etc/ferrum/tenant-a/tls.crt")
    );

    assert_eq!(summary.source_namespace_count, 2);
    assert_eq!(
        summary.excluded_resources, 7,
        "one foreign entry per namespace-owned collection"
    );

    // Nothing foreign survives anywhere in the projected snapshot.
    let serialized = serde_json::to_string(&filtered).expect("projection serializes");
    for forbidden in ["tenant-b", "proxy-b", "bob", "b.internal", "up-b"] {
        assert!(
            !serialized.contains(forbidden),
            "projection leaked '{forbidden}'"
        );
    }
}

#[test]
fn serving_retention_fails_closed_on_the_namespace_list_and_the_mesh_model() {
    let mut config = two_namespace_config();
    config.mesh = Some(Box::default());

    let (filtered, _) = retain_namespace(config, "tenant-a", NamespaceRetention::SERVING);

    assert_eq!(
        filtered.known_namespaces,
        vec!["tenant-a".to_string()],
        "a served snapshot must never carry foreign namespace names"
    );
    assert!(
        filtered.mesh.is_none(),
        "the configuration layer has no namespace-scoped mesh projection, so a \
         serving snapshot drops the model rather than carrying a multi-tenant one"
    );
}

#[test]
fn export_retention_keeps_the_discovered_namespace_list_and_the_mesh_model() {
    let mut config = two_namespace_config();
    config.mesh = Some(Box::default());

    let (filtered, _) = retain_namespace(config, "tenant-a", NamespaceRetention::EXPORT);

    assert_eq!(
        filtered.known_namespaces,
        vec!["tenant-a".to_string(), "tenant-b".to_string()],
        "a namespace-scoped export keeps the discovered namespace list"
    );
    assert!(filtered.mesh.is_some());
    // The resource projection is identical to the serving one.
    assert_eq!(filtered.proxies.len(), 1);
    assert_eq!(filtered.gateway_trust_bundles.len(), 1);
}

#[test]
fn a_namespace_with_nothing_in_the_snapshot_projects_to_empty_not_foreign() {
    let (filtered, summary) = retain_namespace(
        two_namespace_config(),
        "tenant-c",
        NamespaceRetention::SERVING,
    );

    assert!(filtered.proxies.is_empty());
    assert!(filtered.consumers.is_empty());
    assert!(filtered.plugin_configs.is_empty());
    assert!(filtered.upstreams.is_empty());
    assert!(filtered.gateway_trust_bundles.is_empty());
    assert!(filtered.frontend_tls_certificate_sources.is_empty());
    assert!(filtered.http_tls_listen_ports.is_empty());
    assert_eq!(filtered.known_namespaces, vec!["tenant-c".to_string()]);
    assert_eq!(summary.excluded_resources, 14);
}

#[test]
fn a_single_namespace_snapshot_is_projected_unchanged() {
    let mut config = two_namespace_config();
    config.proxies.retain(|proxy| proxy.namespace == "tenant-a");
    config
        .consumers
        .retain(|consumer| consumer.namespace == "tenant-a");
    config
        .plugin_configs
        .retain(|plugin| plugin.namespace == "tenant-a");
    config
        .upstreams
        .retain(|upstream| upstream.namespace == "tenant-a");
    config
        .gateway_trust_bundles
        .retain(|record| record.namespace == "tenant-a");
    config
        .frontend_tls_certificate_sources
        .retain(|source| source.namespace == "tenant-a");
    config
        .http_tls_listen_ports
        .retain(|(namespace, _)| namespace == "tenant-a");

    assert_eq!(source_namespace_count(&config), 1);

    let (filtered, summary) = retain_namespace(config, "tenant-a", NamespaceRetention::SERVING);
    assert_eq!(summary.source_namespace_count, 1);
    assert_eq!(summary.excluded_resources, 0);
    assert_eq!(filtered.proxies.len(), 1);
    assert_eq!(filtered.consumers.len(), 1);
    assert_eq!(filtered.plugin_configs.len(), 1);
    assert_eq!(filtered.upstreams.len(), 1);
    assert_eq!(filtered.gateway_trust_bundles.len(), 1);
    assert_eq!(filtered.frontend_tls_certificate_sources.len(), 1);
    assert_eq!(filtered.http_tls_listen_ports.len(), 1);
}

#[test]
fn the_projection_destructures_gateway_config_exhaustively() {
    // The compile-time half of the contract, pinned so a refactor cannot quietly
    // reintroduce a rest pattern and let a new namespace-owned field through.
    let source = include_str!("../../../src/config/namespace_filter.rs");
    let destructure_start = source
        .find("let GatewayConfig {")
        .expect("the projection must destructure GatewayConfig");
    let destructure_end = source[destructure_start..]
        .find("} = config;")
        .map(|offset| destructure_start + offset)
        .expect("the destructure must bind the whole struct");
    let destructure = &source[destructure_start..destructure_end];
    assert!(
        !destructure.contains(".."),
        "a `..` rest pattern would let a new namespace-owned field escape the filter"
    );
    for field in [
        "proxies",
        "consumers",
        "plugin_configs",
        "upstreams",
        "gateway_trust_bundles",
        "frontend_tls_certificate_sources",
        "http_tls_listen_ports",
        "quarantined_plugin_configs",
    ] {
        assert!(
            destructure.contains(field),
            "the destructure must bind `{field}`"
        );
    }
}
