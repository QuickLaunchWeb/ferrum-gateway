//! Connection admission for the NodeWaypoint transparent inbound capture
//! listener (issue #4626).
//!
//! The listener fronts ordinary application traffic for every enrolled pod on
//! the node, so before this admission gate a peer could hold arbitrarily many
//! relay tasks, descriptors, plugin states, and backend sockets regardless of
//! `FERRUM_MAX_CONNECTIONS`, per-source quotas, or critical overload — the
//! `ConnectionGuard` inside the spawned task only *recorded* occupancy.
//!
//! These pin the accept-loop decision itself: the refusal is reachable with
//! nothing but a limiter and the overload verdict, i.e. before a task or any
//! relay state exists.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::modes::mesh::node_waypoint_observability::{
    NodeWaypointCaptureAdmissionRejectReason, capture_admission_snapshot,
    record_capture_admission_rejection,
};
use ferrum_edge::proxy::node_waypoint_ingress_capture::{
    admit_captured_connection_with, capture_conn_limiter_from_env,
};
use ferrum_edge::util::conn_limit::ConnLimiter;

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
}

/// The reproducer's contract: `FERRUM_MAX_CONNECTIONS=8` must mean eight
/// captured connections can own per-connection state, and the ninth is refused.
#[test]
fn the_global_cap_admits_exactly_max_connections() {
    let limiter = Arc::new(ConnLimiter::new(8, 0));
    // Distinct sources so only the global cap can be the binding constraint.
    let permits: Vec<_> = (0..8)
        .map(|i| {
            admit_captured_connection_with(&limiter, false, ip(i))
                .expect("the first eight captured connections are admitted")
        })
        .collect();
    assert_eq!(limiter.snapshot().active_connections, 8);

    let rejected = admit_captured_connection_with(&limiter, false, ip(9))
        .expect_err("the ninth connection is over the FERRUM_MAX_CONNECTIONS ceiling");
    assert_eq!(
        rejected,
        NodeWaypointCaptureAdmissionRejectReason::MaxConnections
    );

    // RAII: releasing one slot re-opens exactly one.
    drop(permits);
    assert_eq!(limiter.snapshot().active_connections, 0);
    assert!(admit_captured_connection_with(&limiter, false, ip(9)).is_ok());
}

/// One source cannot occupy the whole node-wide pool.
#[test]
fn the_per_source_share_bounds_a_single_peer() {
    let limiter = Arc::new(ConnLimiter::new(16, 2));
    let noisy = ip(7);
    let _first = admit_captured_connection_with(&limiter, false, noisy).expect("first");
    let _second = admit_captured_connection_with(&limiter, false, noisy).expect("second");

    let rejected = admit_captured_connection_with(&limiter, false, noisy)
        .expect_err("the third connection from one source exceeds its share");
    assert_eq!(
        rejected,
        NodeWaypointCaptureAdmissionRejectReason::MaxConnectionsPerIp
    );

    // The global budget is untouched by that refusal — a different pod still
    // gets in, which is the whole point of the per-source dimension.
    assert!(admit_captured_connection_with(&limiter, false, ip(8)).is_ok());
}

/// A per-source refusal must not leak the global slot it speculatively took.
#[test]
fn a_per_source_refusal_releases_the_global_slot() {
    let limiter = Arc::new(ConnLimiter::new(4, 1));
    let held = admit_captured_connection_with(&limiter, false, ip(1)).expect("first");
    assert_eq!(limiter.snapshot().active_connections, 1);

    for _ in 0..8 {
        assert_eq!(
            admit_captured_connection_with(&limiter, false, ip(1)).unwrap_err(),
            NodeWaypointCaptureAdmissionRejectReason::MaxConnectionsPerIp
        );
    }
    // Still one, not nine: the refused attempts released their global permits.
    assert_eq!(limiter.snapshot().active_connections, 1);
    drop(held);
    assert_eq!(limiter.snapshot().active_connections, 0);
}

/// Critical overload admits nothing, and does so without consuming a slot —
/// the check runs before the semaphore is touched.
#[test]
fn critical_overload_admits_no_captured_connection() {
    let limiter = Arc::new(ConnLimiter::new(64, 8));
    let rejected = admit_captured_connection_with(&limiter, true, ip(3))
        .expect_err("critical overload admits nothing");
    assert_eq!(rejected, NodeWaypointCaptureAdmissionRejectReason::Overload);
    assert_eq!(limiter.snapshot().active_connections, 0);
    let snapshot = limiter.snapshot();
    assert_eq!(snapshot.rejected_max_connections, 0);
    assert_eq!(snapshot.rejected_max_connections_per_ip, 0);
}

/// IPv6 peers are tracked on the same per-source dimension.
#[test]
fn the_per_source_share_covers_ipv6_peers() {
    let limiter = Arc::new(ConnLimiter::new(16, 1));
    let peer = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
    let _held = admit_captured_connection_with(&limiter, false, peer).expect("first");
    assert_eq!(
        admit_captured_connection_with(&limiter, false, peer).unwrap_err(),
        NodeWaypointCaptureAdmissionRejectReason::MaxConnectionsPerIp
    );
}

/// Both dimensions come from the resolved env config, and `0` keeps meaning
/// "unlimited" on either one.
#[test]
fn the_limiter_is_sized_from_max_connections_and_the_tcp_per_ip_share() {
    let bounded = EnvConfig {
        max_connections: 8,
        tcp_max_connections_per_ip: 2,
        ..EnvConfig::default()
    };
    let snapshot = capture_conn_limiter_from_env(&bounded).snapshot();
    assert_eq!(snapshot.max_connections, 8);
    assert_eq!(snapshot.max_connections_per_ip, 2);

    let uncapped = EnvConfig {
        max_connections: 0,
        tcp_max_connections_per_ip: 0,
        ..EnvConfig::default()
    };
    let unlimited = capture_conn_limiter_from_env(&uncapped);
    let snapshot = unlimited.snapshot();
    assert_eq!(snapshot.max_connections, 0);
    assert_eq!(snapshot.max_connections_per_ip, 0);
    // Genuinely unbounded, not silently zero-permitted.
    let permits: Vec<_> = (0..64)
        .map(|_| {
            admit_captured_connection_with(&unlimited, false, ip(1))
                .expect("an unlimited limiter admits every connection")
        })
        .collect();
    assert_eq!(unlimited.snapshot().active_connections, 64);
    drop(permits);
}

/// The `reason` label set is closed and carries nothing peer-derived.
#[test]
fn rejection_labels_are_a_closed_set() {
    assert_eq!(
        NodeWaypointCaptureAdmissionRejectReason::Overload.as_str(),
        "overload"
    );
    assert_eq!(
        NodeWaypointCaptureAdmissionRejectReason::MaxConnections.as_str(),
        "max_connections"
    );
    assert_eq!(
        NodeWaypointCaptureAdmissionRejectReason::MaxConnectionsPerIp.as_str(),
        "max_connections_per_ip"
    );
}

/// Refusals are counted per reason. Process-static counters, so this asserts
/// deltas rather than absolutes.
#[test]
fn refusals_increment_their_own_counter() {
    let before = capture_admission_snapshot();
    record_capture_admission_rejection(NodeWaypointCaptureAdmissionRejectReason::Overload);
    record_capture_admission_rejection(NodeWaypointCaptureAdmissionRejectReason::MaxConnections);
    record_capture_admission_rejection(NodeWaypointCaptureAdmissionRejectReason::MaxConnections);
    let after = capture_admission_snapshot();
    assert_eq!(after.rejected_overload - before.rejected_overload, 1);
    assert_eq!(
        after.rejected_max_connections - before.rejected_max_connections,
        2
    );
    assert_eq!(
        after.rejected_max_connections_per_ip - before.rejected_max_connections_per_ip,
        0
    );
}
