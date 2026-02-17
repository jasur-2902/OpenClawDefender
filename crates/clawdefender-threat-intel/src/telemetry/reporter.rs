//! Telemetry report submission.
//!
//! Handles async HTTP submission of telemetry reports to the configured endpoint.

use super::types::TelemetryReport;
use crate::error::{Result, ThreatIntelError};

/// Submits telemetry reports to the collection endpoint.
#[derive(Debug, Clone)]
pub struct TelemetryReporter {
    endpoint_url: String,
    client: reqwest::Client,
    dry_run: bool,
}

impl TelemetryReporter {
    /// Create a new reporter that sends to the given endpoint URL.
    pub fn new(endpoint_url: &str) -> Self {
        Self {
            endpoint_url: endpoint_url.to_string(),
            client: reqwest::Client::new(),
            dry_run: false,
        }
    }

    /// Create a reporter in dry-run mode (logs but does not send).
    pub fn dry_run(endpoint_url: &str) -> Self {
        Self {
            endpoint_url: endpoint_url.to_string(),
            client: reqwest::Client::new(),
            dry_run: true,
        }
    }

    /// Check if this reporter is in dry-run mode.
    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Send a telemetry report to the configured endpoint.
    ///
    /// In dry-run mode, serializes the report and logs it but does not make
    /// a network request.
    ///
    /// Network errors are logged as warnings (the caller should retry next cycle).
    /// Server errors (4xx/5xx) are logged but do not trigger immediate retry.
    pub async fn send_report(&self, report: &TelemetryReport) -> Result<()> {
        let json = serde_json::to_string(report)
            .map_err(|e| ThreatIntelError::FetchError(format!("failed to serialize report: {e}")))?;

        if self.dry_run {
            tracing::info!(
                endpoint = %self.endpoint_url,
                bytes = json.len(),
                "dry-run: would send telemetry report"
            );
            tracing::debug!(report = %json, "dry-run telemetry report payload");
            return Ok(());
        }

        tracing::info!(
            endpoint = %self.endpoint_url,
            bytes = json.len(),
            "sending telemetry report"
        );

        let response = self
            .client
            .post(&self.endpoint_url)
            .header("Content-Type", "application/json")
            .body(json)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "telemetry report send failed (network error)");
                ThreatIntelError::FetchError(format!("telemetry send failed: {e}"))
            })?;

        let status = response.status();
        if !status.is_success() {
            let msg = format!("telemetry endpoint returned {status}");
            tracing::warn!(%status, "telemetry report rejected by server");
            return Err(ThreatIntelError::FetchError(msg));
        }

        tracing::info!("telemetry report submitted successfully");
        Ok(())
    }
}
