//! Shared utilities for plugins.
//!
//! This module contains infrastructure that plugins share, keeping plugin
//! implementation files focused on their core logic.

pub mod http_client;

pub use http_client::PluginHttpClient;
