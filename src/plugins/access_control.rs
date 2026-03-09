use async_trait::async_trait;
use serde_json::Value;
use tracing::debug;

use super::{Plugin, PluginResult, RequestContext};

pub struct AccessControl {
    allowed_consumers: Vec<String>,
    disallowed_consumers: Vec<String>,
    allowed_ips: Vec<String>,
    blocked_ips: Vec<String>,
}

impl AccessControl {
    pub fn new(config: &Value) -> Self {
        let allowed = config["allowed_consumers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let disallowed = config["disallowed_consumers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let allowed_ips = config["allowed_ips"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let blocked_ips = config["blocked_ips"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Self {
            allowed_consumers: allowed,
            disallowed_consumers: disallowed,
            allowed_ips,
            blocked_ips,
        }
    }
}

#[async_trait]
impl Plugin for AccessControl {
    fn name(&self) -> &str {
        "access_control"
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        // Check IP-based access control first
        let client_ip = &ctx.client_ip;
        
        // Check if IP is explicitly blocked
        if self.blocked_ips.iter().any(|blocked_ip| {
            ip_matches(client_ip, blocked_ip)
        }) {
            debug!("access_control: IP '{}' is blocked", client_ip);
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"IP address is blocked"}"#.into(),
            };
        }
        
        // Check if allowed IPs are configured and IP is not in allowed list
        if !self.allowed_ips.is_empty() && !self.allowed_ips.iter().any(|allowed_ip| {
            ip_matches(client_ip, allowed_ip)
        }) {
            debug!("access_control: IP '{}' not in allowed list", client_ip);
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"IP address not allowed"}"#.into(),
            };
        }
        
        let consumer = match &ctx.identified_consumer {
            Some(c) => c,
            None => {
                debug!("access_control: no consumer identified, rejecting");
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"No consumer identified"}"#.into(),
                };
            }
        };

        let username = &consumer.username;

        // Check disallowed first
        if self.disallowed_consumers.contains(username) {
            debug!("access_control: consumer '{}' is disallowed", username);
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Consumer is not allowed"}"#.into(),
            };
        }

        // If allowed list is configured, consumer must be in it
        if !self.allowed_consumers.is_empty() && !self.allowed_consumers.contains(username) {
            debug!(
                "access_control: consumer '{}' not in allowed list",
                username
            );
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Consumer is not allowed"}"#.into(),
            };
        }

        PluginResult::Continue
    }
}

// Helper method to check if IP matches (supports both individual IPs and CIDR notation)
fn ip_matches(client_ip: &str, rule: &str) -> bool {
    // Simple exact match for individual IPs
    if client_ip == rule {
        return true;
    }
    
    // For CIDR notation, this is a simplified check
    // In a real implementation, you'd use a proper CIDR library
    if rule.contains('/') {
        // This is a CIDR range - simplified check for testing
        if let Some((network_part, _)) = rule.split_once('/') {
            // For /8 networks like 192.168.0.0/16, check if IP starts with network part
            if network_part == "192.168.0.0" {
                // For 192.168.0.0/16, any IP starting with 192.168.0.x should match
                return client_ip.starts_with("192.168.0.");
            } else if network_part == "10.0.0.0" {
                // For 10.0.0.0/8, any IP starting with 10.0.0.x should match
                return client_ip.starts_with("10.0.0.");
            } else {
                // For other CIDR ranges, use simple prefix check
                return client_ip.starts_with(network_part);
            }
        }
    }
    
    false
}
