//! Circuit breaker for preventing cascading failures.
//!
//! Implements a three-state circuit breaker pattern:
//! - **Closed**: Normal operation, requests pass through.
//! - **Open**: After repeated failures, requests are rejected with 503.
//! - **Half-Open**: After a timeout, a limited number of probe requests are allowed.

use crate::config::types::CircuitBreakerConfig;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use tracing::{info, warn};

const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
const STATE_HALF_OPEN: u8 = 2;

/// Circuit breaker state for a single proxy or target.
pub struct CircuitBreaker {
    state: AtomicU8,
    failure_count: AtomicU32,
    success_count: AtomicU32,
    last_failure_epoch_ms: AtomicU64,
    half_open_in_flight: AtomicU32,
    config: CircuitBreakerConfig,
}

/// Error returned when the circuit is open.
#[derive(Debug)]
pub struct CircuitOpenError;

impl std::fmt::Display for CircuitOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Circuit breaker is open")
    }
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: AtomicU8::new(STATE_CLOSED),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            last_failure_epoch_ms: AtomicU64::new(0),
            half_open_in_flight: AtomicU32::new(0),
            config,
        }
    }

    /// Check if a request can proceed. Returns Err if circuit is open.
    pub fn can_execute(&self) -> Result<(), CircuitOpenError> {
        let state = self.state.load(Ordering::Acquire);
        match state {
            STATE_CLOSED => Ok(()),
            STATE_OPEN => {
                // Check if timeout has elapsed
                let now = now_epoch_ms();
                let last_failure = self.last_failure_epoch_ms.load(Ordering::Relaxed);
                let timeout_ms = self.config.timeout_seconds.saturating_mul(1000);

                if now.saturating_sub(last_failure) >= timeout_ms {
                    // Attempt transition to half-open (only one thread wins the CAS)
                    match self.state.compare_exchange(
                        STATE_OPEN,
                        STATE_HALF_OPEN,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            // CAS winner: initialize half-open state
                            self.half_open_in_flight.store(1, Ordering::Relaxed);
                            self.success_count.store(0, Ordering::Relaxed);
                            info!("Circuit breaker transitioning from Open to Half-Open");
                            Ok(())
                        }
                        Err(current) => {
                            // CAS loser: another thread already transitioned.
                            // Fall through to handle the current state.
                            if current == STATE_HALF_OPEN {
                                // Use CAS loop to atomically claim a slot
                                loop {
                                    let in_flight =
                                        self.half_open_in_flight.load(Ordering::Acquire);
                                    if in_flight >= self.config.half_open_max_requests {
                                        return Err(CircuitOpenError);
                                    }
                                    match self.half_open_in_flight.compare_exchange_weak(
                                        in_flight,
                                        in_flight + 1,
                                        Ordering::AcqRel,
                                        Ordering::Acquire,
                                    ) {
                                        Ok(_) => return Ok(()),
                                        Err(_) => continue,
                                    }
                                }
                            } else {
                                // State changed to something else (e.g. Closed)
                                Ok(())
                            }
                        }
                    }
                } else {
                    Err(CircuitOpenError)
                }
            }
            STATE_HALF_OPEN => {
                // Use CAS loop to atomically claim a slot without exceeding the limit.
                loop {
                    let current = self.half_open_in_flight.load(Ordering::Acquire);
                    if current >= self.config.half_open_max_requests {
                        return Err(CircuitOpenError);
                    }
                    match self.half_open_in_flight.compare_exchange_weak(
                        current,
                        current + 1,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return Ok(()),
                        Err(_) => continue,
                    }
                }
            }
            _ => Ok(()),
        }
    }

    /// Record a successful response, transitioning from half-open to closed
    /// after enough successes reach the configured threshold.
    #[allow(dead_code)] // Public API — called by retry/proxy logic when circuit is half-open
    pub fn record_success(&self) {
        let state = self.state.load(Ordering::Acquire);
        match state {
            STATE_HALF_OPEN => {
                // Decrement in-flight counter so new probe requests can be admitted
                let _ = self.half_open_in_flight.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |v| v.checked_sub(1),
                );
                // Re-check state: another thread may have reopened the circuit
                // between our initial load and now.
                if self.state.load(Ordering::Acquire) != STATE_HALF_OPEN {
                    return;
                }
                let successes = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;
                if successes >= self.config.success_threshold {
                    // Use CAS to transition: only one thread should close the circuit
                    if self
                        .state
                        .compare_exchange(
                            STATE_HALF_OPEN,
                            STATE_CLOSED,
                            Ordering::SeqCst,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        info!("Circuit breaker closing (recovered)");
                        self.failure_count.store(0, Ordering::Relaxed);
                        self.success_count.store(0, Ordering::Relaxed);
                        self.half_open_in_flight.store(0, Ordering::Relaxed);
                    }
                }
            }
            STATE_CLOSED => {
                // Reset failure count on success
                if self.failure_count.load(Ordering::Relaxed) > 0 {
                    self.failure_count.store(0, Ordering::Relaxed);
                }
            }
            _ => {}
        }
    }

    /// Record a failed response.
    pub fn record_failure(&self, status_code: u16) {
        if !self.config.failure_status_codes.contains(&status_code) {
            // Non-failure status codes are neutral — don't treat as success or failure
            return;
        }

        let state = self.state.load(Ordering::Acquire);
        self.last_failure_epoch_ms
            .store(now_epoch_ms(), Ordering::Relaxed);

        match state {
            STATE_CLOSED => {
                let failures = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
                if failures >= self.config.failure_threshold {
                    warn!("Circuit breaker opening after {} failures", failures);
                    self.state.store(STATE_OPEN, Ordering::Release);
                }
            }
            STATE_HALF_OPEN => {
                // Decrement in-flight before reopening
                let _ = self.half_open_in_flight.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |v| v.checked_sub(1),
                );
                warn!("Circuit breaker reopening (probe failed)");
                self.state.store(STATE_OPEN, Ordering::SeqCst);
                self.success_count.store(0, Ordering::Relaxed);
                self.half_open_in_flight.store(0, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Get the config for this circuit breaker.
    pub fn config(&self) -> &CircuitBreakerConfig {
        &self.config
    }

    /// Current state name (for metrics/logging).
    #[allow(dead_code)]
    pub fn state_name(&self) -> &'static str {
        match self.state.load(Ordering::Relaxed) {
            STATE_CLOSED => "closed",
            STATE_OPEN => "open",
            STATE_HALF_OPEN => "half_open",
            _ => "unknown",
        }
    }
}

/// Cache of circuit breakers keyed by proxy ID.
pub struct CircuitBreakerCache {
    breakers: DashMap<String, Arc<CircuitBreaker>>,
}

impl Default for CircuitBreakerCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBreakerCache {
    pub fn new() -> Self {
        Self {
            breakers: DashMap::new(),
        }
    }

    /// Get or create a circuit breaker for a proxy.
    /// If the config has changed, replaces the breaker with a fresh one.
    pub fn get_or_create(
        &self,
        proxy_id: &str,
        config: &CircuitBreakerConfig,
    ) -> Arc<CircuitBreaker> {
        if let Some(existing) = self.breakers.get(proxy_id)
            && existing.config() == config
        {
            return existing.clone();
        }
        let cb = Arc::new(CircuitBreaker::new(config.clone()));
        self.breakers.insert(proxy_id.to_string(), cb.clone());
        cb
    }

    /// Check if a request can proceed for a given proxy.
    pub fn can_execute(
        &self,
        proxy_id: &str,
        config: &CircuitBreakerConfig,
    ) -> Result<Arc<CircuitBreaker>, CircuitOpenError> {
        let cb = self.get_or_create(proxy_id, config);
        cb.can_execute()?;
        Ok(cb)
    }

    /// Remove circuit breakers for proxies that no longer exist in config.
    /// Prevents unbounded memory growth when proxies are frequently added/deleted.
    pub fn prune(&self, removed_proxy_ids: &[String]) {
        for id in removed_proxy_ids {
            self.breakers.remove(id);
        }
    }
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout_seconds: 1,
            failure_status_codes: vec![500, 502, 503],
            half_open_max_requests: 1,
        }
    }

    #[test]
    fn test_closed_allows_requests() {
        let cb = CircuitBreaker::new(default_config());
        assert!(cb.can_execute().is_ok());
        assert_eq!(cb.state_name(), "closed");
    }

    #[test]
    fn test_opens_after_threshold() {
        let cb = CircuitBreaker::new(default_config());

        cb.record_failure(500);
        cb.record_failure(500);
        assert!(cb.can_execute().is_ok()); // Still closed

        cb.record_failure(500);
        assert_eq!(cb.state_name(), "open");
        assert!(cb.can_execute().is_err());
    }

    #[test]
    fn test_non_configured_status_treated_as_success() {
        let cb = CircuitBreaker::new(default_config());

        // 404 is not in failure_status_codes, should be treated as success
        cb.record_failure(404);
        cb.record_failure(404);
        cb.record_failure(404);
        assert_eq!(cb.state_name(), "closed");
    }

    #[test]
    fn test_success_resets_failure_count() {
        let cb = CircuitBreaker::new(default_config());

        cb.record_failure(500);
        cb.record_failure(500);
        cb.record_success(); // Should reset
        cb.record_failure(500);
        cb.record_failure(500);
        // Only 2 failures after reset, should still be closed
        assert_eq!(cb.state_name(), "closed");
    }

    #[test]
    fn test_half_open_recovery() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout_seconds: 0, // Immediate timeout for testing
            failure_status_codes: vec![500],
            half_open_max_requests: 2,
        };
        let cb = CircuitBreaker::new(config);

        // Trip open
        cb.record_failure(500);
        cb.record_failure(500);
        assert_eq!(cb.state_name(), "open");

        // Timeout elapsed (0 seconds), should transition to half-open
        assert!(cb.can_execute().is_ok());
        assert_eq!(cb.state_name(), "half_open");

        // Successful probes
        cb.record_success();
        cb.record_success();
        assert_eq!(cb.state_name(), "closed");
    }

    #[test]
    fn test_half_open_probe_failure_reopens() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout_seconds: 0,
            failure_status_codes: vec![500],
            half_open_max_requests: 1,
        };
        let cb = CircuitBreaker::new(config);

        // Trip open
        cb.record_failure(500);
        cb.record_failure(500);

        // Transition to half-open
        assert!(cb.can_execute().is_ok());

        // Probe fails
        cb.record_failure(500);
        assert_eq!(cb.state_name(), "open");
    }

    #[test]
    fn test_cache_creates_and_reuses() {
        let cache = CircuitBreakerCache::new();
        let config = default_config();

        let cb1 = cache.get_or_create("proxy-1", &config);
        let cb2 = cache.get_or_create("proxy-1", &config);

        // Should be the same instance
        assert!(Arc::ptr_eq(&cb1, &cb2));
    }

    #[test]
    fn test_half_open_max_requests_enforced() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 3,
            timeout_seconds: 0,
            failure_status_codes: vec![500],
            half_open_max_requests: 2,
        };
        let cb = CircuitBreaker::new(config);

        // Trip open
        cb.record_failure(500);
        assert_eq!(cb.state_name(), "open");

        // First call transitions to half-open and admits (slot 1)
        assert!(cb.can_execute().is_ok());
        assert_eq!(cb.state_name(), "half_open");

        // Second call admits (slot 2)
        assert!(cb.can_execute().is_ok());

        // Third call should be rejected — max 2 in-flight
        assert!(cb.can_execute().is_err());
    }

    #[test]
    fn test_half_open_slot_freed_on_success() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 3,
            timeout_seconds: 0,
            failure_status_codes: vec![500],
            half_open_max_requests: 1,
        };
        let cb = CircuitBreaker::new(config);

        // Trip open, transition to half-open
        cb.record_failure(500);
        assert!(cb.can_execute().is_ok()); // slot 1 taken

        // At max — should reject
        assert!(cb.can_execute().is_err());

        // Record success frees a slot
        cb.record_success();

        // Now should be able to get a slot again
        assert!(cb.can_execute().is_ok());
    }

    #[test]
    fn test_half_open_concurrent_slots() {
        use std::sync::Arc;

        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 10,
            timeout_seconds: 0,
            failure_status_codes: vec![500],
            half_open_max_requests: 5,
        };
        let cb = Arc::new(CircuitBreaker::new(config));

        // Trip open
        cb.record_failure(500);

        // Spawn threads that all try to get a half-open slot
        let mut handles = Vec::new();
        for _ in 0..20 {
            let cb_clone = cb.clone();
            handles.push(std::thread::spawn(move || cb_clone.can_execute().is_ok()));
        }

        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let admitted = results.iter().filter(|&&r| r).count();

        // Exactly 5 should be admitted (1 CAS winner + 4 from half-open slots)
        assert_eq!(
            admitted, 5,
            "Expected exactly 5 admitted in half-open, got {}",
            admitted
        );
    }

    #[test]
    fn test_concurrent_failure_recording() {
        use std::sync::Arc;

        let config = CircuitBreakerConfig {
            failure_threshold: 50,
            success_threshold: 1,
            timeout_seconds: 60,
            failure_status_codes: vec![500],
            half_open_max_requests: 1,
        };
        let cb = Arc::new(CircuitBreaker::new(config));

        // Spawn threads that all record failures concurrently
        let mut handles = Vec::new();
        for _ in 0..100 {
            let cb_clone = cb.clone();
            handles.push(std::thread::spawn(move || {
                cb_clone.record_failure(500);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        // After 100 failures with threshold 50, circuit must be open
        assert_eq!(cb.state_name(), "open");
    }

    #[test]
    fn test_cache_prune_removes_stale() {
        let cache = CircuitBreakerCache::new();
        let config = default_config();

        cache.get_or_create("proxy-1", &config);
        cache.get_or_create("proxy-2", &config);
        cache.get_or_create("proxy-3", &config);

        cache.prune(&["proxy-1".to_string(), "proxy-3".to_string()]);

        // proxy-2 should still exist
        assert!(cache.breakers.contains_key("proxy-2"));
        assert!(!cache.breakers.contains_key("proxy-1"));
        assert!(!cache.breakers.contains_key("proxy-3"));
    }

    #[test]
    fn test_cache_replaces_on_config_change() {
        let cache = CircuitBreakerCache::new();
        let config1 = default_config();
        let cb1 = cache.get_or_create("proxy-1", &config1);

        // Change the config
        let config2 = CircuitBreakerConfig {
            failure_threshold: 10,
            ..config1
        };
        let cb2 = cache.get_or_create("proxy-1", &config2);

        // Should be a different instance
        assert!(!Arc::ptr_eq(&cb1, &cb2));
    }
}
