//! HTTP/3 configuration types

use std::time::Duration;

/// HTTP/3 server configuration
#[derive(Debug, Clone)]
pub struct Http3ServerConfig {
    /// Maximum concurrent bidirectional streams per connection
    pub max_concurrent_streams: u32,
    /// Connection idle timeout
    pub idle_timeout: Duration,
}

impl Http3ServerConfig {
    /// Create from environment config
    pub fn from_env_config(env: &crate::config::EnvConfig) -> Self {
        Self {
            max_concurrent_streams: env.http3_max_streams,
            idle_timeout: Duration::from_secs(env.http3_idle_timeout),
        }
    }
}

impl Default for Http3ServerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 100,
            idle_timeout: Duration::from_secs(30),
        }
    }
}
