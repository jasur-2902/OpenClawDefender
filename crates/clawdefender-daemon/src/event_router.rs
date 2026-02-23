//! Event routing pipeline.
//!
//! Receives [`CorrelatedEvent`]s from the correlation engine and fans them out
//! to the audit logger, connected UI clients, and (optionally) the behavioral
//! analysis engines (learning, anomaly scoring, kill chain detection, decision).

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use clawdefender_core::audit::{AuditRecord, SlmAnalysisRecord, SwarmAnalysisRecord};
use clawdefender_core::behavioral::{
    AnomalyScorer, BehavioralEvent, BehavioralEventType, DecisionEngine, KillChainDetector,
    KillChainEvent, LearningEngine,
};
use clawdefender_core::behavioral::killchain::StepEventType;
use clawdefender_core::event::correlation::CorrelatedEvent;
use clawdefender_core::event::mcp::McpEventKind;
use clawdefender_core::event::os::OsEventKind;
use clawdefender_core::event::{Event, Severity};
use clawdefender_core::policy::PolicyAction;
use clawdefender_slm::analyzer::{
    AnalysisContext, AnalysisEventType, AnalysisRequest, ServerReputation,
};
use clawdefender_slm::analyzer::build_user_prompt;
use clawdefender_slm::engine::RiskLevel;
use clawdefender_slm::SlmService;
use clawdefender_swarm::commander::Commander;
use clawdefender_swarm::prompts::SwarmEventData;

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

/// Optional behavioral engine handles, all behind Arc for shared ownership.
pub struct BehavioralEngines {
    pub learning: Arc<RwLock<LearningEngine>>,
    pub scorer: Arc<AnomalyScorer>,
    pub killchain: Arc<RwLock<KillChainDetector>>,
    pub decision: Arc<RwLock<DecisionEngine>>,
}

/// The event router receives correlated events and distributes them.
pub struct EventRouter {
    config: EventRouterConfig,
    audit_tx: mpsc::Sender<AuditRecord>,
    ui_tx: mpsc::Sender<CorrelatedEvent>,
    behavioral: Option<BehavioralEngines>,
    slm_service: Option<Arc<SlmService>>,
    swarm_commander: Option<Arc<Commander>>,
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
            behavioral: None,
            slm_service: None,
            swarm_commander: None,
        }
    }

    /// Attach behavioral engine references. If not called, behavioral
    /// processing is gracefully skipped.
    pub fn with_behavioral(mut self, engines: BehavioralEngines) -> Self {
        self.behavioral = Some(engines);
        self
    }

    /// Set the SLM service for advisory analysis of escalated events.
    pub fn with_slm_service(mut self, slm_service: Arc<SlmService>) -> Self {
        self.slm_service = Some(slm_service);
        self
    }

    /// Set the swarm commander for advisory analysis of critical events.
    pub fn with_swarm_commander(mut self, commander: Arc<Commander>) -> Self {
        self.swarm_commander = Some(commander);
        self
    }

    /// Spawn the router task. Returns a handle to the spawned task.
    pub fn run(
        self,
        mut correlated_rx: mpsc::Receiver<CorrelatedEvent>,
    ) -> tokio::task::JoinHandle<()> {
        let slm_service = self.slm_service.clone();
        let swarm_commander = self.swarm_commander.clone();
        let escalation_audit_tx = self.audit_tx.clone();

        tokio::spawn(async move {
            while let Some(event) = correlated_rx.recv().await {
                // Always forward to audit logger
                let mut audit_record = event.to_audit_record();

                // --- Behavioral engine processing (non-blocking) ---
                if let Some(ref engines) = self.behavioral {
                    self.process_behavioral(engines, &event, &mut audit_record)
                        .await;
                }

                if let Err(e) = self.audit_tx.try_send(audit_record) {
                    warn!(error = %e, "failed to send correlated event to audit logger");
                }

                // Forward to connected UIs
                if let Err(e) = self.ui_tx.try_send(event.clone()) {
                    debug!(error = %e, "no UI consumer for correlated event");
                }

                // If uncorrelated and high/critical severity, escalate to SLM/swarm.
                // SAFETY: SLM and swarm results are advisory-only. They enrich audit
                // logs but NEVER influence policy decisions.
                if event.mcp_event.is_none() && event.severity() >= self.config.escalation_threshold
                {
                    debug!(
                        id = %event.id,
                        severity = ?event.severity(),
                        "uncorrelated high-severity event flagged for analysis"
                    );

                    // Spawn non-blocking SLM analysis
                    if let Some(ref slm) = slm_service {
                        if slm.is_enabled() {
                            let slm = Arc::clone(slm);
                            let event_clone = event.clone();
                            let audit_tx = escalation_audit_tx.clone();
                            let swarm = swarm_commander.clone();

                            tokio::spawn(async move {
                                Self::run_escalation_analysis(
                                    slm, swarm, event_clone, audit_tx,
                                )
                                .await;
                            });
                        }
                    }
                }
            }
            debug!("event router shut down");
        })
    }

    /// Run SLM analysis (and optionally swarm) for an escalated event.
    /// SAFETY: This is advisory-only and runs asynchronously without blocking event routing.
    /// Results enrich the audit log but NEVER influence policy decisions.
    async fn run_escalation_analysis(
        slm: Arc<SlmService>,
        swarm: Option<Arc<Commander>>,
        event: CorrelatedEvent,
        audit_tx: mpsc::Sender<AuditRecord>,
    ) {
        // Build a description from the OS events
        let description = if event.os_events.is_empty() {
            "Unknown uncorrelated OS activity".to_string()
        } else {
            event
                .os_events
                .iter()
                .map(|e| format!("{:?}", e))
                .collect::<Vec<_>>()
                .join("; ")
        };

        let request = AnalysisRequest {
            event_type: AnalysisEventType::UncorrelatedOsActivity { description },
            server_name: "unknown".to_string(),
            client_name: "unknown".to_string(),
            context: AnalysisContext {
                recent_events: vec![],
                server_reputation: ServerReputation::default(),
            },
        };

        let prompt = build_user_prompt(&request);

        // Run SLM inference (advisory only)
        let slm_result = match slm.analyze_event(&prompt).await {
            Ok(resp) => {
                info!(
                    id = %event.id,
                    risk = %resp.risk_level,
                    confidence = resp.confidence,
                    latency_ms = resp.latency_ms,
                    "SLM escalation analysis complete (advisory only)"
                );
                Some(resp)
            }
            Err(e) => {
                warn!(
                    id = %event.id,
                    error = %e,
                    "SLM escalation analysis failed, continuing without"
                );
                None
            }
        };

        // Write SLM result as enrichment to audit log
        if let Some(ref resp) = slm_result {
            let model_name = slm
                .stats()
                .map(|s| s.model_name.clone())
                .unwrap_or_else(|| "unknown".to_string());

            let mut audit_record = event.to_audit_record();
            audit_record.slm_analysis = Some(SlmAnalysisRecord {
                risk_level: resp.risk_level.to_string(),
                explanation: resp.explanation.clone(),
                confidence: resp.confidence,
                latency_ms: resp.latency_ms,
                model: model_name,
            });

            // Also embed in event_details for Timeline.tsx SlmAnalysisSection
            if let Some(details) = audit_record.event_details.as_object_mut() {
                details.insert(
                    "slm_analysis".to_string(),
                    serde_json::json!({
                        "risk_level": resp.risk_level.to_string(),
                        "explanation": resp.explanation,
                        "confidence": resp.confidence,
                    }),
                );
            }

            if let Err(e) = audit_tx.try_send(audit_record) {
                warn!(error = %e, "failed to send SLM enrichment to audit logger");
            }
        }

        // Escalate to swarm for critical events (advisory only).
        // Trigger if SLM risk >= Critical OR event severity >= Critical.
        let slm_is_critical = slm_result
            .as_ref()
            .is_some_and(|r| r.risk_level >= RiskLevel::Critical);
        let event_is_critical = event.severity() >= Severity::Critical;

        if slm_is_critical || event_is_critical {
            if let Some(ref commander) = swarm {
                let slm_risk = slm_result
                    .as_ref()
                    .map(|r| r.risk_level.to_string())
                    .unwrap_or_else(|| "UNKNOWN".to_string());
                let slm_explanation = slm_result
                    .as_ref()
                    .map(|r| r.explanation.clone())
                    .unwrap_or_else(|| "SLM analysis unavailable".to_string());

                let swarm_event = SwarmEventData {
                    server_name: "unknown".to_string(),
                    client_name: "unknown".to_string(),
                    tool_name: None,
                    arguments: None,
                    resource_uri: None,
                    sampling_content: None,
                    recent_events: vec![],
                    slm_risk,
                    slm_explanation,
                };

                // Swarm has built-in 10-second timeout
                match commander.analyze(&swarm_event).await {
                    Ok(verdict) => {
                        info!(
                            id = %event.id,
                            risk = %verdict.risk_level,
                            confidence = verdict.confidence,
                            cost_usd = verdict.estimated_cost_usd,
                            "Swarm escalation analysis complete (advisory only)"
                        );

                        let mut audit_record = event.to_audit_record();
                        audit_record.swarm_analysis = Some(SwarmAnalysisRecord {
                            risk_level: verdict.risk_level,
                            explanation: verdict.explanation,
                            recommended_action: verdict.recommended_action,
                            confidence: verdict.confidence,
                            specialist_summaries: verdict
                                .specialist_reports
                                .iter()
                                .map(|r| r.verdict.clone())
                                .collect(),
                            total_tokens: verdict.total_input_tokens
                                + verdict.total_output_tokens,
                            estimated_cost_usd: verdict.estimated_cost_usd,
                            latency_ms: verdict.total_latency_ms,
                        });

                        if let Err(e) = audit_tx.try_send(audit_record) {
                            warn!(error = %e, "failed to send swarm enrichment to audit logger");
                        }
                    }
                    Err(e) => {
                        warn!(
                            id = %event.id,
                            error = %e,
                            "Swarm escalation analysis failed, continuing without"
                        );
                    }
                }
            }
        }
    }

    /// Process a correlated event through the behavioral engines.
    ///
    /// This extracts MCP and OS events, feeds them to the learning engine,
    /// scores them for anomalies, checks kill chains, and runs through the
    /// decision engine. Results are attached to the audit record.
    async fn process_behavioral(
        &self,
        engines: &BehavioralEngines,
        correlated: &CorrelatedEvent,
        audit_record: &mut AuditRecord,
    ) {
        // We use a default server/client name when not available.
        let server_name = audit_record
            .server_name
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let client_name = audit_record
            .client_name
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        // --- Feed MCP event to learning engine + build behavioral events ---
        let mut behavioral_events: Vec<BehavioralEvent> = Vec::new();
        let mut killchain_events: Vec<KillChainEvent> = Vec::new();

        if let Some(ref mcp) = correlated.mcp_event {
            // Feed to learning engine (try_write to avoid blocking)
            if let Ok(mut learning) = engines.learning.try_write() {
                learning.observe_mcp_event(&server_name, &client_name, mcp);
            }

            // Convert MCP event to behavioral event for scoring
            match &mcp.kind {
                McpEventKind::ToolCall(tc) => {
                    let arguments: HashMap<String, String> = tc
                        .arguments
                        .as_object()
                        .map(|obj| {
                            obj.iter()
                                .map(|(k, v)| (k.clone(), v.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();

                    behavioral_events.push(BehavioralEvent {
                        event_type: BehavioralEventType::ToolCall {
                            tool_name: tc.tool_name.clone(),
                            arguments,
                        },
                        server_name: server_name.clone(),
                        timestamp: mcp.timestamp,
                    });

                    killchain_events.push(KillChainEvent {
                        event_type: StepEventType::AnyToolCall,
                        path: None,
                        destination: None,
                        server_name: server_name.clone(),
                    });
                }
                McpEventKind::ResourceRead(rr) => {
                    behavioral_events.push(BehavioralEvent {
                        event_type: BehavioralEventType::FileAccess {
                            path: rr.uri.clone(),
                            is_write: false,
                        },
                        server_name: server_name.clone(),
                        timestamp: mcp.timestamp,
                    });

                    killchain_events.push(KillChainEvent {
                        event_type: StepEventType::FileRead,
                        path: Some(rr.uri.clone()),
                        destination: None,
                        server_name: server_name.clone(),
                    });
                }
                McpEventKind::SamplingRequest(_) => {
                    killchain_events.push(KillChainEvent {
                        event_type: StepEventType::SamplingResponse,
                        path: None,
                        destination: None,
                        server_name: server_name.clone(),
                    });
                }
                _ => {}
            }
        }

        // --- Feed OS events to learning engine + build behavioral/killchain events ---
        for os_event in &correlated.os_events {
            if let Ok(mut learning) = engines.learning.try_write() {
                learning.observe_os_event(&server_name, &client_name, os_event);
            }

            match &os_event.kind {
                OsEventKind::Open { path, flags } => {
                    let is_write = *flags & 0x3 != 0; // not O_RDONLY
                    behavioral_events.push(BehavioralEvent {
                        event_type: BehavioralEventType::FileAccess {
                            path: path.clone(),
                            is_write,
                        },
                        server_name: server_name.clone(),
                        timestamp: os_event.timestamp,
                    });

                    let step_type = if is_write {
                        StepEventType::FileWrite
                    } else {
                        StepEventType::FileRead
                    };
                    killchain_events.push(KillChainEvent {
                        event_type: step_type,
                        path: Some(path.clone()),
                        destination: None,
                        server_name: server_name.clone(),
                    });
                }
                OsEventKind::Close { path } | OsEventKind::Unlink { path } => {
                    behavioral_events.push(BehavioralEvent {
                        event_type: BehavioralEventType::FileAccess {
                            path: path.clone(),
                            is_write: true,
                        },
                        server_name: server_name.clone(),
                        timestamp: os_event.timestamp,
                    });
                }
                OsEventKind::Rename { source: _, dest } => {
                    behavioral_events.push(BehavioralEvent {
                        event_type: BehavioralEventType::FileAccess {
                            path: dest.clone(),
                            is_write: true,
                        },
                        server_name: server_name.clone(),
                        timestamp: os_event.timestamp,
                    });
                    killchain_events.push(KillChainEvent {
                        event_type: StepEventType::FileWrite,
                        path: Some(dest.clone()),
                        destination: None,
                        server_name: server_name.clone(),
                    });
                }
                OsEventKind::Connect {
                    address,
                    port,
                    ..
                } => {
                    behavioral_events.push(BehavioralEvent {
                        event_type: BehavioralEventType::NetworkConnect {
                            host: address.clone(),
                            port: *port,
                        },
                        server_name: server_name.clone(),
                        timestamp: os_event.timestamp,
                    });
                    killchain_events.push(KillChainEvent {
                        event_type: StepEventType::NetworkConnect,
                        path: None,
                        destination: Some(address.clone()),
                        server_name: server_name.clone(),
                    });
                }
                OsEventKind::Exec { .. } => {
                    killchain_events.push(KillChainEvent {
                        event_type: StepEventType::ShellExec,
                        path: None,
                        destination: None,
                        server_name: server_name.clone(),
                    });
                }
                _ => {}
            }
        }

        // --- Score behavioral events and check kill chains ---
        // Get profile snapshot for scoring (non-blocking read)
        let profile = {
            match engines.learning.try_read() {
                Ok(learning) => learning.get_profile(&server_name).cloned(),
                Err(_) => None,
            }
        };

        let profile = match profile {
            Some(p) => p,
            None => return, // No profile yet, nothing to score
        };

        // Find the highest anomaly score across all events in this correlation
        let mut highest_score = None;
        let mut highest_score_total = 0.0f64;

        for be in &behavioral_events {
            if let Some(score) = engines.scorer.score(be, &profile) {
                if score.total > highest_score_total {
                    highest_score_total = score.total;
                    highest_score = Some(score);
                }
            }
        }

        // Ingest kill chain events and collect matches
        let mut all_kc_matches = Vec::new();
        if let Ok(mut kc) = engines.killchain.try_write() {
            let timestamp = correlated
                .mcp_event
                .as_ref()
                .map(|e| e.timestamp)
                .or_else(|| correlated.os_events.first().map(|e| e.timestamp))
                .unwrap_or_else(chrono::Utc::now);

            for kce in killchain_events {
                let matches = kc.ingest(kce, timestamp);
                all_kc_matches.extend(matches);
            }
        }

        // Pick the most severe kill chain match
        let best_kc = all_kc_matches.into_iter().next();

        // --- Decision engine ---
        if let Ok(mut decision_engine) = engines.decision.try_write() {
            // Use Prompt as the default policy action so behavioral analysis runs
            let policy_action = PolicyAction::Prompt("behavioral".to_string());

            let decision = decision_engine.decide(
                &policy_action,
                &profile,
                highest_score,
                best_kc,
            );

            // Build audit data and attach to audit record
            let audit_data = decision_engine.build_audit_data(&decision, &profile);
            audit_record.behavioral = Some(audit_data);

            // Log significant findings
            match &decision {
                clawdefender_core::behavioral::BehavioralDecision::AutoBlock {
                    explanation, ..
                } => {
                    warn!(
                        server = %server_name,
                        explanation = %explanation,
                        "Behavioral engine: auto-block triggered"
                    );
                }
                clawdefender_core::behavioral::BehavioralDecision::EnrichedPrompt {
                    anomaly_score,
                    ..
                } => {
                    info!(
                        server = %server_name,
                        score = anomaly_score.total,
                        "Behavioral engine: anomaly detected"
                    );
                }
                _ => {}
            }
        }
    }
}
