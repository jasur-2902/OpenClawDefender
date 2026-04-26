//! `rookbot alerts` — manage security alerts.
//!
//! Alerts are derived from high-severity events and blocked actions.
//! Alert state is stored in ~/.local/share/rookbot/alerts.json.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use clawdefender_core::audit::logger::FileAuditLogger;
use clawdefender_core::audit::{AuditFilter, AuditLogger, AuditRecord};
use clawdefender_core::config::settings::LogRotation;
use clawdefender_core::config::ClawConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum AlertsAction {
    /// List active alerts.
    List {
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        server: Option<String>,
    },
    /// Show full alert detail.
    Detail { id: String },
    /// Acknowledge an alert.
    Acknowledge { id: String },
    /// Dismiss an alert.
    Dismiss {
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Resolve an alert.
    Resolve {
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Launch investigation for an alert.
    Investigate {
        id: String,
        #[arg(long, default_value = "standard")]
        depth: String,
    },
}

/// Alert status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AlertStatus {
    New,
    Acknowledged,
    Investigating,
    Resolved,
    Dismissed,
}

/// A security alert derived from an audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub severity: String,
    pub status: AlertStatus,
    pub summary: String,
    pub server_name: Option<String>,
    pub event_id: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub dismissed_at: Option<DateTime<Utc>>,
    pub resolution_reason: Option<String>,
}

/// Alert store for persisting alerts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AlertStore {
    alerts: Vec<Alert>,
}

impl AlertStore {
    fn load(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        let store: AlertStore = serde_json::from_str(&content)?;
        Ok(store)
    }

    fn save(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(&self)?;
        fs::write(path, content)?;
        Ok(())
    }
}

/// Main entry point for the `alerts` command.
pub fn run(config: &ClawConfig, action: &AlertsAction) -> Result<()> {
    let alerts_path = get_alerts_path()?;
    let mut store = AlertStore::load(&alerts_path)?;

    match action {
        AlertsAction::List {
            severity,
            status,
            server,
        } => {
            // Generate alerts from recent audit events if needed.
            sync_alerts_from_audit_log(config, &mut store)?;
            store.save(&alerts_path)?;

            let filtered: Vec<_> = store
                .alerts
                .iter()
                .filter(|a| {
                    if let Some(ref sev) = severity {
                        if a.severity.to_lowercase() != sev.to_lowercase() {
                            return false;
                        }
                    }
                    if let Some(ref st) = status {
                        let status_str = format!("{:?}", a.status).to_lowercase();
                        if status_str != st.to_lowercase() {
                            return false;
                        }
                    }
                    if let Some(ref srv) = server {
                        if a.server_name.as_deref() != Some(srv.as_str()) {
                            return false;
                        }
                    }
                    true
                })
                .collect();

            if filtered.is_empty() {
                println!("No alerts found.");
                return Ok(());
            }

            println!(
                "  {:<8} {:<20} {:<12} {:<16} SUMMARY",
                "ID", "TIMESTAMP", "SEVERITY", "STATUS"
            );
            println!("  {}", "-".repeat(80));

            for alert in &filtered {
                let ts = alert.timestamp.format("%Y-%m-%d %H:%M:%S");
                let status_str = format!("{:?}", alert.status);
                let summary = if alert.summary.len() > 30 {
                    format!("{}...", &alert.summary[..27])
                } else {
                    alert.summary.clone()
                };

                println!(
                    "  {:<8} {:<20} {:<12} {:<16} {}",
                    &alert.id[..8],
                    ts,
                    alert.severity,
                    status_str,
                    summary
                );
            }

            println!();
            println!("  Total alerts: {}", filtered.len());
        }

        AlertsAction::Detail { id } => {
            let alert = store
                .alerts
                .iter()
                .find(|a| a.id.starts_with(id))
                .context("Alert not found")?;

            println!("Alert Detail");
            println!("  ID:         {}", alert.id);
            println!("  Timestamp:  {}", alert.timestamp.to_rfc3339());
            println!("  Severity:   {}", alert.severity);
            println!("  Status:     {:?}", alert.status);
            println!("  Summary:    {}", alert.summary);
            if let Some(ref server) = alert.server_name {
                println!("  Server:     {}", server);
            }
            if let Some(ref event_id) = alert.event_id {
                println!("  Event ID:   {}", event_id);
            }
            if let Some(ts) = alert.acknowledged_at {
                println!("  Acknowledged: {}", ts.to_rfc3339());
            }
            if let Some(ts) = alert.resolved_at {
                println!("  Resolved:   {}", ts.to_rfc3339());
            }
            if let Some(ref reason) = alert.resolution_reason {
                println!("  Reason:     {}", reason);
            }
        }

        AlertsAction::Acknowledge { id } => {
            let alert = store
                .alerts
                .iter_mut()
                .find(|a| a.id.starts_with(id))
                .context("Alert not found")?;

            alert.status = AlertStatus::Acknowledged;
            alert.acknowledged_at = Some(Utc::now());
            let alert_id = alert.id.clone();
            store.save(&alerts_path)?;

            println!("Alert {} acknowledged.", &alert_id[..8]);
        }

        AlertsAction::Dismiss { id, reason } => {
            let alert = store
                .alerts
                .iter_mut()
                .find(|a| a.id.starts_with(id))
                .context("Alert not found")?;

            alert.status = AlertStatus::Dismissed;
            alert.dismissed_at = Some(Utc::now());
            alert.resolution_reason = reason.clone();
            let alert_id = alert.id.clone();
            store.save(&alerts_path)?;

            println!("Alert {} dismissed.", &alert_id[..8]);
        }

        AlertsAction::Resolve { id, reason } => {
            let alert = store
                .alerts
                .iter_mut()
                .find(|a| a.id.starts_with(id))
                .context("Alert not found")?;

            alert.status = AlertStatus::Resolved;
            alert.resolved_at = Some(Utc::now());
            alert.resolution_reason = reason.clone();
            let alert_id = alert.id.clone();
            store.save(&alerts_path)?;

            println!("Alert {} resolved.", &alert_id[..8]);
        }

        AlertsAction::Investigate { id, depth } => {
            let alert = store
                .alerts
                .iter_mut()
                .find(|a| a.id.starts_with(id))
                .context("Alert not found")?;

            alert.status = AlertStatus::Investigating;
            let alert_id = alert.id.clone();
            store.save(&alerts_path)?;

            println!(
                "Launching {} investigation for alert {}...",
                depth,
                &alert_id[..8]
            );
            println!();
            println!("Investigation launched. Use `rookbot investigate show` to view results.");
        }
    }

    Ok(())
}

/// Sync alerts from the audit log.
fn sync_alerts_from_audit_log(config: &ClawConfig, store: &mut AlertStore) -> Result<()> {
    let log_path = &config.audit_log_path;
    if !log_path.exists() {
        return Ok(());
    }

    let logger = FileAuditLogger::new(
        log_path.to_path_buf(),
        LogRotation {
            max_size_mb: 0,
            max_files: 0,
        },
    )?;

    let filter = AuditFilter {
        from: None,
        to: None,
        source: None,
        action: Some("block".to_string()),
        limit: 100,
    };

    let records = logger.query(&filter)?;

    for record in records {
        // Check if alert already exists.
        let event_id = record.session_id.clone().unwrap_or_default();
        if store
            .alerts
            .iter()
            .any(|a| a.event_id.as_deref() == Some(&event_id))
        {
            continue;
        }

        // Create a new alert.
        let alert = Alert {
            id: format!("alert-{}", record.timestamp.timestamp_millis()),
            timestamp: record.timestamp,
            severity: infer_severity(&record),
            status: AlertStatus::New,
            summary: record.event_summary.clone(),
            server_name: record.server_name.clone(),
            event_id: record.session_id.clone(),
            acknowledged_at: None,
            resolved_at: None,
            dismissed_at: None,
            resolution_reason: None,
        };

        store.alerts.push(alert);
    }

    Ok(())
}

/// Infer alert severity from an audit record.
fn infer_severity(record: &AuditRecord) -> String {
    if record.action_taken == "block" {
        return "high".to_string();
    }
    if record.action_taken == "prompt" {
        return "medium".to_string();
    }
    "low".to_string()
}

/// Get the path to the alerts JSON file.
fn get_alerts_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    Ok(PathBuf::from(home).join(".local/share/rookbot/alerts.json"))
}
