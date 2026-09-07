mod admin;
mod build;
mod cli;
mod config;
#[allow(dead_code)]
mod env_lock;
#[allow(dead_code)]
mod gateway_trust_observability_lock;
mod identity;
mod logging_tests;
mod notifications;
mod openapi_yaml_tests;
// The OpenAPI parity tests build plugin fixtures with the shared plugin
// helpers. Only the helper closure is compiled here (the plugin suites
// themselves live in `unit_plugins_a_tests` / `unit_plugins_b_tests`); the
// helper modules that also carry tests run again in this target.
#[allow(dead_code, unused_imports)]
mod plugins {
    #[allow(dead_code)]
    pub(crate) mod plugin_utils;
    mod jwks_auth_tests;
    mod jwks_cache_tests;
    mod plugin_cache_tests;
    pub(crate) use plugin_cache_tests::{
        make_plugin_config_with_json, make_proxy, minimal_plugin_config,
    };
}
mod secrets;
#[allow(dead_code, unused_imports)]
pub(crate) mod tls;
mod util;
