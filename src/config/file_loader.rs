use crate::config::config_migration::ConfigMigrator;
use crate::config::types::{CURRENT_CONFIG_VERSION, GatewayConfig};
use std::path::Path;
use tracing::{error, info, warn};

/// Load configuration from a YAML or JSON file.
///
/// If the config file is at an older version than `CURRENT_CONFIG_VERSION`,
/// the config is migrated **in memory** before deserialization. The file on
/// disk is not modified — use `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=config`
/// to persist config file migrations.
pub fn load_config_from_file(path: &str) -> Result<GatewayConfig, anyhow::Error> {
    let file_path = Path::new(path);
    if !file_path.exists() {
        anyhow::bail!("Configuration file not found: {}", file_path.display());
    }

    let content = std::fs::read_to_string(file_path)?;
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Parse to a generic Value first so we can check/migrate the version
    let mut value: serde_json::Value = match ext.as_str() {
        "yaml" | "yml" => {
            info!("Loading YAML configuration from {}", file_path.display());
            let yaml_val: serde_yaml::Value = serde_yaml::from_str(&content)?;
            serde_json::to_value(yaml_val)?
        }
        "json" => {
            info!("Loading JSON configuration from {}", file_path.display());
            serde_json::from_str(&content)?
        }
        _ => {
            info!(
                "Attempting to parse config file {} (unknown extension)",
                file_path.display()
            );
            // Try YAML first, then JSON
            match serde_yaml::from_str::<serde_yaml::Value>(&content) {
                Ok(yaml_val) => serde_json::to_value(yaml_val)?,
                Err(_) => serde_json::from_str(&content)?,
            }
        }
    };

    // Detect config version and migrate in memory if needed
    let file_version = value
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("1")
        .to_string();

    if file_version != CURRENT_CONFIG_VERSION {
        warn!(
            "Config file is at version {}, current is {}. Migrating in memory.",
            file_version, CURRENT_CONFIG_VERSION
        );
        ConfigMigrator::migrate_in_memory(&mut value)?;
    }

    // Deserialize the (possibly migrated) value into GatewayConfig
    let config: GatewayConfig = serde_json::from_value(value)?;

    // Validate listen_path uniqueness
    if let Err(dupes) = config.validate_unique_listen_paths() {
        for msg in &dupes {
            error!("{}", msg);
        }
        anyhow::bail!(
            "Configuration validation failed: {} duplicate listen_path(s) found",
            dupes.len()
        );
    }

    info!(
        "Configuration loaded (version {}): {} proxies, {} consumers, {} plugin configs",
        config.version,
        config.proxies.len(),
        config.consumers.len(),
        config.plugin_configs.len()
    );

    Ok(config)
}

/// Reload config from file, returning the new config or an error.
pub fn reload_config_from_file(path: &str) -> Result<GatewayConfig, anyhow::Error> {
    info!("Reloading configuration from file: {}", path);
    load_config_from_file(path)
}
