//! Event routing pipeline.
//!
//! Receives [`CorrelatedEvent`]s from the correlation engine and fans them out
//! to the audit logger, connected UI clients, and (optionally) the SLM/swarm
//! analysis pipeline.

use tokio::sync::mpsc;
use tracing::{debug, warn};

use clawdefender_core::audit::AuditRecord;
use clawdefender_core::event::correlation::CorrelatedEvent;
use clawdefender_core::event::{Event, Severity};

/// Configuration for the event router.
pub struct EventRouterConfig {
    /// Minimum severity for forwarding uncorrelated events to SLM/Swarm.
    pub escalation_threshold: Severity,
}

impl Default for EventRouterConfig {
    fn default() -> Self {
        Self {
            escalation_threshold: Severity::High,
        }
    }
}

/// The event router receives correlated events and distributes them.
pub struct EventRouter {
    config: EventRouterConfig,
    audit_tx: mpsc::Sender<AuditRecord>,
    ui_tx: mpsc::Sender<CorrelatedEvent>,
}

impl EventRouter {
    pub fn new(
        config: EventRouterConfig,
        audit_tx: mpsc::Sender<AuditRecord>,
        ui_tx: mpsc::Sender<CorrelatedEvent>,
    ) -> Self {
        Self {
            config,
            audit_tx,
            ui_tx,
        }
    }

    /// Spawn the router task. Returns a handle to the spawned task.
    pub fn run(
        self,
        mut correlated_rx: mpsc::Receiver<CorrelatedEvent>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(event) = correlated_rx.recv().await {
                // Always forward to audit logger
                let audit_record = event.to_audit_record();
                if let Err(e) = self.audit_tx.try_send(audit_record) {
                    warn!(error = %e, "failed to send correlated event to audit logger");
                }

                // Forward to connected UIs
                if let Err(e) = self.ui_tx.try_send(event.clone()) {
                    debug!(error = %e, "no UI consumer for correlated event");
                }

                // If uncorrelated and high/critical severity, flag for analysis
                if event.mcp_event.is_none() && event.severity() >= self.config.escalation_threshold
                {
                    debug!(
                        id = %event.id,
                        severity = ?event.severity(),
                        "uncorrelated high-severity event flagged for analysis"
                    );
                }
            }
            debug!("event router shut down");
        })
    }
}
