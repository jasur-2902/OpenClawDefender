//! Consent management for the telemetry system.
//!
//! Manages opt-in/opt-out state and installation ID generation.
//! Consent state is stored in the main `config.toml` under `[telemetry]`.

use uuid::Uuid;

use super::types::TelemetryConfig;

/// Manages telemetry consent state.
///
/// Wraps a `TelemetryConfig` and provides methods to opt in/out,
/// generate installation IDs, and query consent status.
#[derive(Debug, Clone)]
pub struct ConsentManager {
    config: TelemetryConfig,
}

impl ConsentManager {
    /// Create a new `ConsentManager` from the given config.
    pub fn new(config: TelemetryConfig) -> Self {
        Self { config }
    }

    /// Create a `ConsentManager` with default (disabled) config.
    pub fn default_disabled() -> Self {
        Self {
            config: TelemetryConfig::default(),
        }
    }

    /// Check whether telemetry is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Opt in to telemetry. Generates a new random UUID v4 installation ID
    /// and enables telemetry. Returns the newly generated installation ID.
    pub fn opt_in(&mut self) -> String {
        let id = Uuid::new_v4().to_string();
        self.config.enabled = true;
        self.config.installation_id = Some(id.clone());
        id
    }

    /// Opt out of telemetry. Disables telemetry and clears the installation ID.
    pub fn opt_out(&mut self) {
        self.config.enabled = false;
        self.config.installation_id = None;
    }

    /// Get the current installation ID, if any.
    pub fn get_installation_id(&self) -> Option<&str> {
        self.config.installation_id.as_deref()
    }

    /// Get a reference to the underlying config.
    pub fn config(&self) -> &TelemetryConfig {
        &self.config
    }

    /// Consume this manager and return the underlying config (for serialization).
    pub fn into_config(self) -> TelemetryConfig {
        self.config
    }
}
