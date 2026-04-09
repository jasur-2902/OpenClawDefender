//! Event routing pipeline.
//!
//! Receives [`CorrelatedEvent`]s from the correlation engine and fans them out
//! to the audit logger, connected UI clients, and (optionally) the behavioral
//! analysis engines (learning, anomaly scoring, kill chain detection, decision).
//!
//! Events are escalated to the SLM for advisory AI analysis when any of these
//! triggers fire:
//! - Anomaly score >= `anomaly_score_escalation_threshold` (default 0.6)
//! - Kill chain pattern match (regardless of anomaly score)
//! - DecisionEngine returns `EnrichedPrompt` or `AutoBlock`
//! - Uncorrelated high-severity OS event
//!
//! SLM escalation is rate-limited to `max_escalations_per_minute` (default 5).

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use clawdefender_core::audit::{AuditRecord, SlmAnalysisRecord, SwarmAnalysisRecord};
use clawdefender_core::behavioral::{
    AnomalyScorer, BehavioralDecision, BehavioralEvent, BehavioralEventType, DecisionEngine,
    KillChainDetector, KillChainEvent, LearningEngine,
};
use clawdefender_core::behavioral::killchain::{self, StepEventType};
use clawdefender_core::event::correlation::CorrelatedEvent;
use clawdefender_core::event::mcp::McpEventKind;
use clawdefender_core::event::os::OsEventKind;
use clawdefender_core::event::{Event, Severity};
use clawdefender_core::policy::PolicyAction;
use clawdefender_slm::analyzer::{
    AnalysisContext, AnalysisEventType, AnalysisRequest, ServerReputation,
};
use clawdefender_slm::analyzer::build_user_prompt;
use clawdefender_slm::clustering::ClusterEvent;
use clawdefender_slm::engine::RiskLevel;
use clawdefender_slm::pipeline::SlmPipeline;
use clawdefender_slm::{AiBackendManager, AiRequest, TaskType, SlmService};
use clawdefender_swarm::agent_session::AgentSessionManager;
use clawdefender_swarm::commander::Commander;
use clawdefender_swarm::prompts::SwarmEventData;

/// Configuration for the event router.
pub struct EventRouterConfig {
    /// Minimum severity for forwarding uncorrelated events to SLM/Swarm.
    pub escalation_threshold: Severity,
    /// Minimum anomaly score that triggers SLM escalation (0.0-1.0).
    /// Events at or above this score are sent to the SLM for AI analysis.
    pub anomaly_score_escalation_threshold: f64,
    /// Maximum number of SLM escalations allowed per minute.
    /// When the rate limit is hit, events are still processed normally
    /// (behavioral analysis, audit log) but without AI enrichment.
    pub max_escalations_per_minute: u32,
}

impl Default for EventRouterConfig {
    fn default() -> Self {
        Self {
            escalation_threshold: Severity::High,
            anomaly_score_escalation_threshold: 0.6,
            max_escalations_per_minute: 5,
        }
    }
}

/// Reason why an event was escalated to the SLM.
/// Fields are read via Debug formatting in trace logs.
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum EscalationReason {
    /// Anomaly score crossed the escalation threshold.
    HighAnomalyScore { score: f64 },
    /// A kill chain pattern was matched.
    KillChainMatch { pattern: String },
    /// The behavioral decision engine flagged the event.
    BehavioralDecision { decision_type: String },
    /// Uncorrelated OS event with high severity.
    UncorrelatedHighSeverity,
}

/// Optional behavioral engine handles, all behind Arc for shared ownership.
pub struct BehavioralEngines {
    pub learning: Arc<RwLock<LearningEngine>>,
    pub scorer: Arc<AnomalyScorer>,
    pub killchain: Arc<RwLock<KillChainDetector>>,
    pub decision: Arc<RwLock<DecisionEngine>>,
}

/// Simple sliding-window rate limiter.
///
/// Tracks timestamps of recent escalations and enforces a maximum count
/// within a 60-second rolling window.
struct EscalationRateLimiter {
    window: VecDeque<std::time::Instant>,
    max_per_minute: u32,
}

impl EscalationRateLimiter {
    fn new(max_per_minute: u32) -> Self {
        Self {
            window: VecDeque::new(),
            max_per_minute,
        }
    }

    /// Try to acquire a rate-limit slot. Returns `true` if allowed,
    /// `false` if the limit has been reached.
    fn try_acquire(&mut self) -> bool {
        let now = std::time::Instant::now();
        let cutoff = now - std::time::Duration::from_secs(60);

        // Evict entries older than 60 seconds.
        while self.window.front().is_some_and(|t| *t < cutoff) {
            self.window.pop_front();
        }

        if (self.window.len() as u32) < self.max_per_minute {
            self.window.push_back(now);
            true
        } else {
            false
        }
    }
}

/// The event router receives correlated events and distributes them.
pub struct EventRouter {
    config: EventRouterConfig,
    audit_tx: mpsc::Sender<AuditRecord>,
    ui_tx: mpsc::Sender<CorrelatedEvent>,
    behavioral: Option<BehavioralEngines>,
    slm_service: Option<Arc<SlmService>>,
    /// Dual AI backend manager (local SLM + cloud API).
    /// When present, takes priority over the legacy `slm_service` for
    /// escalation analysis, routing requests to the appropriate backend.
    ai_manager: Option<Arc<AiBackendManager>>,
    swarm_commander: Option<Arc<Commander>>,
    /// SLM pipeline for two-tier triage + clustering (optional).
    /// When present, escalated events are fed into the pipeline instead of
    /// calling `slm_service.analyze_event()` directly.
    slm_pipeline: Option<Arc<SlmPipeline>>,
    /// Phase 2: Cloud agent session manager for auto-escalation of suspicious
    /// HIGH/CRITICAL events to an Investigate session.
    cloud_agent_manager: Option<Arc<AgentSessionManager>>,
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
            ai_manager: None,
            swarm_commander: None,
            slm_pipeline: None,
            cloud_agent_manager: None,
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

    /// Set the dual AI backend manager for routing analysis requests to
    /// local SLM (fast triage) and cloud API (deep analysis).
    /// When set, takes priority over the legacy `slm_service` path.
    pub fn with_ai_manager(mut self, ai_manager: Arc<AiBackendManager>) -> Self {
        self.ai_manager = Some(ai_manager);
        self
    }

    /// Set the swarm commander for advisory analysis of critical events.
    pub fn with_swarm_commander(mut self, commander: Arc<Commander>) -> Self {
        self.swarm_commander = Some(commander);
        self
    }

    /// Set the SLM pipeline for two-tier triage + clustering.
    ///
    /// When the pipeline is attached, escalated events are fed into the
    /// clustering buffer instead of calling `slm_service.analyze_event()` directly.
    /// Non-escalated events are recorded as routine in the context window.
    pub fn with_slm_pipeline(mut self, pipeline: Arc<SlmPipeline>) -> Self {
        self.slm_pipeline = Some(pipeline);
        self
    }

    /// Set the cloud agent session manager for auto-escalation of suspicious events.
    ///
    /// When configured, events with SUSPICIOUS + HIGH/CRITICAL severity will
    /// automatically create an Investigate session with the cloud agent.
    pub fn with_cloud_agent_manager(mut self, manager: Arc<AgentSessionManager>) -> Self {
        self.cloud_agent_manager = Some(manager);
        self
    }

    /// Spawn the router task. Returns a handle to the spawned task.
    pub fn run(
        self,
        mut correlated_rx: mpsc::Receiver<CorrelatedEvent>,
    ) -> tokio::task::JoinHandle<()> {
        let slm_service = self.slm_service.clone();
        let ai_manager = self.ai_manager.clone();
        let swarm_commander = self.swarm_commander.clone();
        let cloud_agent_mgr = self.cloud_agent_manager.clone();
        let escalation_audit_tx = self.audit_tx.clone();
        let anomaly_threshold = self.config.anomaly_score_escalation_threshold;
        let mut rate_limiter = EscalationRateLimiter::new(self.config.max_escalations_per_minute);

        tokio::spawn(async move {
            while let Some(event) = correlated_rx.recv().await {
                // Always forward to audit logger
                let mut audit_record = event.to_audit_record();

                // --- Behavioral engine processing (non-blocking) ---
                let escalation_reasons = if let Some(ref engines) = self.behavioral {
                    self.process_behavioral(
                        engines,
                        &event,
                        &mut audit_record,
                        anomaly_threshold,
                    )
                    .await
                } else {
                    Vec::new()
                };

                // Check for uncorrelated high-severity OS events
                let mut all_reasons = escalation_reasons;
                if event.mcp_event.is_none()
                    && event.severity() >= self.config.escalation_threshold
                {
                    all_reasons.push(EscalationReason::UncorrelatedHighSeverity);
                }

                // Extract server name before audit_record is moved.
                let event_server_name = audit_record
                    .server_name
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());

                if let Err(e) = self.audit_tx.try_send(audit_record) {
                    warn!(error = %e, "failed to send correlated event to audit logger");
                }

                // Forward to connected UIs
                if let Err(e) = self.ui_tx.try_send(event.clone()) {
                    debug!(error = %e, "no UI consumer for correlated event");
                }

                // --- SLM escalation (advisory only) ---
                // SAFETY: SLM and swarm results are advisory-only. They enrich audit
                // logs but NEVER influence policy decisions.
                if !all_reasons.is_empty() {
                    // Prefer the pipeline (two-tier triage + clustering) when available.
                    if let Some(ref pipeline) = self.slm_pipeline {
                        if rate_limiter.try_acquire() {
                            debug!(
                                id = %event.id,
                                reasons = ?all_reasons.iter().map(|r| format!("{:?}", r)).collect::<Vec<_>>(),
                                "event escalated to SLM pipeline for triage"
                            );

                            let cluster_event = Self::correlated_to_cluster_event(&event);
                            pipeline.ingest(cluster_event).await;
                        } else {
                            warn!(
                                id = %event.id,
                                "SLM pipeline rate limit reached (max {} per minute), skipping",
                                self.config.max_escalations_per_minute
                            );
                        }
                    }
                    // Dual AI backend manager path: local triage + cloud deep analysis.
                    else if let Some(ref mgr) = ai_manager {
                        if rate_limiter.try_acquire() {
                            debug!(
                                id = %event.id,
                                reasons = ?all_reasons.iter().map(|r| format!("{:?}", r)).collect::<Vec<_>>(),
                                "event escalated to AI manager for dual-backend analysis"
                            );

                            let mgr = Arc::clone(mgr);
                            let event_clone = event.clone();
                            let audit_tx = escalation_audit_tx.clone();
                            let swarm = swarm_commander.clone();
                            let cloud = cloud_agent_mgr.clone();

                            tokio::spawn(async move {
                                Self::run_dual_escalation_analysis(
                                    mgr, swarm, cloud, event_clone, audit_tx,
                                )
                                .await;
                            });
                        } else {
                            warn!(
                                id = %event.id,
                                "AI escalation rate limit reached (max {} per minute), skipping",
                                self.config.max_escalations_per_minute
                            );
                        }
                    }
                    // Legacy fallback: direct SLM analysis (single backend).
                    else if let Some(ref slm) = slm_service {
                        if slm.is_enabled() {
                            // Apply rate limiting
                            if rate_limiter.try_acquire() {
                                debug!(
                                    id = %event.id,
                                    reasons = ?all_reasons.iter().map(|r| format!("{:?}", r)).collect::<Vec<_>>(),
                                    "event escalated to SLM for advisory analysis"
                                );

                                let slm = Arc::clone(slm);
                                let event_clone = event.clone();
                                let audit_tx = escalation_audit_tx.clone();
                                let swarm = swarm_commander.clone();
                                let cloud = cloud_agent_mgr.clone();

                                tokio::spawn(async move {
                                    Self::run_escalation_analysis(
                                        slm, swarm, cloud, event_clone, audit_tx,
                                    )
                                    .await;
                                });
                            } else {
                                warn!(
                                    id = %event.id,
                                    "SLM escalation rate limit reached (max {} per minute), skipping AI analysis",
                                    self.config.max_escalations_per_minute
                                );
                            }
                        }
                    }
                } else if let Some(ref pipeline) = self.slm_pipeline {
                    // Non-escalated event: record as routine in the context window
                    // so the SLM has awareness of normal activity patterns.
                    pipeline.record_routine_event(&event_server_name);
                }
            }
            debug!("event router shut down");
        })
    }

    /// Convert a correlated event into a [`ClusterEvent`] for the SLM pipeline.
    fn correlated_to_cluster_event(event: &CorrelatedEvent) -> ClusterEvent {
        let server_name = "unknown".to_string();
        let timestamp = event
            .mcp_event
            .as_ref()
            .map(|e| e.timestamp)
            .or_else(|| event.os_events.first().map(|e| e.timestamp))
            .unwrap_or_else(chrono::Utc::now);

        let (event_type, tool_name, target) = if let Some(ref mcp) = event.mcp_event {
            match &mcp.kind {
                McpEventKind::ToolCall(tc) => (
                    "tool_call".to_string(),
                    Some(tc.tool_name.clone()),
                    tc.arguments
                        .get("path")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                ),
                McpEventKind::ResourceRead(rr) => (
                    "resource_read".to_string(),
                    None,
                    Some(rr.uri.clone()),
                ),
                McpEventKind::SamplingRequest(_) => (
                    "sampling".to_string(),
                    None,
                    None,
                ),
                _ => (
                    format!("{:?}", mcp.kind),
                    None,
                    None,
                ),
            }
        } else if let Some(os) = event.os_events.first() {
            match &os.kind {
                OsEventKind::Open { path, .. } => (
                    "file_open".to_string(),
                    None,
                    Some(path.clone()),
                ),
                OsEventKind::Connect { address, .. } => (
                    "network_connect".to_string(),
                    None,
                    Some(address.clone()),
                ),
                OsEventKind::Exec { target_path, .. } => (
                    "exec".to_string(),
                    None,
                    Some(target_path.clone()),
                ),
                _ => (
                    "os_event".to_string(),
                    None,
                    None,
                ),
            }
        } else {
            ("unknown".to_string(), None, None)
        };

        ClusterEvent {
            timestamp,
            event_type,
            tool_name,
            target,
            anomaly_score: 0.0, // Anomaly score is computed by behavioral engines separately
            server_name,
        }
    }

    /// Run SLM analysis (and optionally swarm) for an escalated event.
    /// SAFETY: This is advisory-only and runs asynchronously without blocking event routing.
    /// Results enrich the audit log but NEVER influence policy decisions.
    async fn run_escalation_analysis(
        slm: Arc<SlmService>,
        swarm: Option<Arc<Commander>>,
        cloud_agent: Option<Arc<AgentSessionManager>>,
        event: CorrelatedEvent,
        audit_tx: mpsc::Sender<AuditRecord>,
    ) {
        let server_name = "unknown".to_string();
        let client_name = "unknown".to_string();

        // Build the analysis request based on the event type.
        let request = if let Some(ref mcp) = event.mcp_event {
            match &mcp.kind {
                McpEventKind::ToolCall(tc) => AnalysisRequest {
                    event_type: AnalysisEventType::McpToolCall {
                        tool_name: tc.tool_name.clone(),
                        arguments: tc.arguments.clone(),
                    },
                    server_name: server_name.clone(),
                    client_name: client_name.clone(),
                    context: AnalysisContext {
                        recent_events: vec![],
                        server_reputation: ServerReputation::default(),
                    },
                },
                McpEventKind::ResourceRead(rr) => AnalysisRequest {
                    event_type: AnalysisEventType::McpResourceRead {
                        uri: rr.uri.clone(),
                    },
                    server_name: server_name.clone(),
                    client_name: client_name.clone(),
                    context: AnalysisContext {
                        recent_events: vec![],
                        server_reputation: ServerReputation::default(),
                    },
                },
                McpEventKind::SamplingRequest(sr) => AnalysisRequest {
                    event_type: AnalysisEventType::McpSampling {
                        content: serde_json::to_string(&sr.messages)
                            .unwrap_or_else(|_| "sampling request".to_string()),
                    },
                    server_name: server_name.clone(),
                    client_name: client_name.clone(),
                    context: AnalysisContext {
                        recent_events: vec![],
                        server_reputation: ServerReputation::default(),
                    },
                },
                _ => {
                    // Build a description from the MCP event debug repr
                    let description = format!("{:?}", mcp.kind);
                    AnalysisRequest {
                        event_type: AnalysisEventType::UncorrelatedOsActivity { description },
                        server_name: server_name.clone(),
                        client_name: client_name.clone(),
                        context: AnalysisContext {
                            recent_events: vec![],
                            server_reputation: ServerReputation::default(),
                        },
                    }
                }
            }
        } else {
            // Uncorrelated OS events
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
            AnalysisRequest {
                event_type: AnalysisEventType::UncorrelatedOsActivity { description },
                server_name: server_name.clone(),
                client_name: client_name.clone(),
                context: AnalysisContext {
                    recent_events: vec![],
                    server_reputation: ServerReputation::default(),
                },
            }
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

                // Log the failure to audit so analysts can see analysis was attempted but failed.
                let mut audit_record = event.to_audit_record();
                audit_record.slm_analysis = Some(SlmAnalysisRecord {
                    risk_level: "analysis_failed".to_string(),
                    explanation: format!("SLM analysis failed: {}", e),
                    confidence: 0.0,
                    latency_ms: 0,
                    model: slm
                        .stats()
                        .map(|s| s.model_name.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                });
                if let Err(send_err) = audit_tx.try_send(audit_record) {
                    warn!(error = %send_err, "failed to send SLM failure record to audit logger");
                }

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
                    server_name,
                    client_name,
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

        // --- Phase 2: Cloud agent escalation ---
        // When the SLM flags an event as suspicious (risk >= High) and a cloud agent
        // manager is configured, automatically create an Investigate session so the
        // cloud LLM can perform deeper analysis with full tool access.
        // This is advisory-only and does not block event routing.
        let slm_is_high_or_above = slm_result
            .as_ref()
            .is_some_and(|r| r.risk_level >= RiskLevel::High);

        if slm_is_high_or_above {
            if let Some(ref agent_mgr) = cloud_agent {
                let slm_explanation = slm_result
                    .as_ref()
                    .map(|r| r.explanation.clone())
                    .unwrap_or_default();
                let slm_risk = slm_result
                    .as_ref()
                    .map(|r| r.risk_level.to_string())
                    .unwrap_or_default();

                let event_id = event.id.to_string();
                let briefing = format!(
                    "AUTO-ESCALATION from SLM triage.\n\
                     Event ID: {}\n\
                     SLM Risk: {}\n\
                     SLM Explanation: {}\n\
                     Event severity: {:?}\n\n\
                     Investigate this event thoroughly. Determine if this is a true \
                     positive or false positive. If true positive, assess the blast \
                     radius and recommend remediation steps.",
                    event_id,
                    slm_risk,
                    slm_explanation,
                    event.severity(),
                );

                use clawdefender_swarm::agent_session::SessionType as AgentSessionType;

                let query = format!(
                    "Investigate event {} — SLM flagged as {} risk: {}",
                    event_id, slm_risk, slm_explanation
                );

                match agent_mgr
                    .start_session(
                        AgentSessionType::Investigate { event_id: event_id.clone() },
                        briefing,
                        Some(query),
                    )
                    .await
                {
                    Ok(session_id) => {
                        info!(
                            event_id = %event_id,
                            session_id = %session_id,
                            slm_risk = %slm_risk,
                            "Cloud agent Investigate session auto-created for suspicious event"
                        );
                    }
                    Err(e) => {
                        warn!(
                            event_id = %event_id,
                            error = %e,
                            "Failed to auto-create cloud Investigate session, continuing without"
                        );
                    }
                }
            }
        }
    }

    /// Run dual-backend escalation analysis using the AiBackendManager.
    ///
    /// Step 1: Local triage (fast, always attempted via TaskType::Triage)
    /// Step 2: If local triage returns High+ risk and cloud is available,
    ///         spawn async deep analysis via TaskType::DeepAnalysis
    /// Step 3: Write enriched audit records for both results
    ///
    /// Also escalates to swarm/cloud agent for critical events (same as legacy path).
    /// SAFETY: This is advisory-only and runs asynchronously without blocking event routing.
    async fn run_dual_escalation_analysis(
        ai_manager: Arc<AiBackendManager>,
        swarm: Option<Arc<Commander>>,
        cloud_agent: Option<Arc<AgentSessionManager>>,
        event: CorrelatedEvent,
        audit_tx: mpsc::Sender<AuditRecord>,
    ) {
        let server_name = "unknown".to_string();
        let client_name = "unknown".to_string();

        // Build the analysis prompt from the event.
        let request = Self::build_analysis_request(&event, &server_name, &client_name);
        let prompt = build_user_prompt(&request);

        // --- Step 1: Local triage (fast path) ---
        let triage_request = AiRequest {
            task_type: TaskType::Triage,
            prompt: prompt.clone(),
            context: None,
        };

        let triage_result = ai_manager.analyze(triage_request).await;

        let slm_result = if let Some(ref resp) = triage_result.response {
            info!(
                id = %event.id,
                risk = %resp.risk_level,
                confidence = resp.confidence,
                latency_ms = resp.latency_ms,
                backend = %triage_result.backend_used,
                "AI triage analysis complete (advisory only)"
            );

            // Write triage result to audit log
            let model_name = triage_result.backend_used.clone();
            let mut audit_record = event.to_audit_record();
            audit_record.slm_analysis = Some(SlmAnalysisRecord {
                risk_level: resp.risk_level.to_string(),
                explanation: resp.explanation.clone(),
                confidence: resp.confidence,
                latency_ms: resp.latency_ms,
                model: model_name,
            });

            if let Some(details) = audit_record.event_details.as_object_mut() {
                details.insert(
                    "slm_analysis".to_string(),
                    serde_json::json!({
                        "risk_level": resp.risk_level.to_string(),
                        "explanation": resp.explanation,
                        "confidence": resp.confidence,
                        "backend": triage_result.backend_used,
                    }),
                );
            }

            if let Err(e) = audit_tx.try_send(audit_record) {
                warn!(error = %e, "failed to send triage enrichment to audit logger");
            }

            Some(resp.clone())
        } else {
            warn!(
                id = %event.id,
                message = ?triage_result.message,
                "AI triage analysis unavailable, continuing without"
            );

            // Log the unavailability
            let mut audit_record = event.to_audit_record();
            audit_record.slm_analysis = Some(SlmAnalysisRecord {
                risk_level: "analysis_unavailable".to_string(),
                explanation: triage_result
                    .message
                    .unwrap_or_else(|| "No AI backend available".to_string()),
                confidence: 0.0,
                latency_ms: 0,
                model: "none".to_string(),
            });
            if let Err(e) = audit_tx.try_send(audit_record) {
                warn!(error = %e, "failed to send AI unavailable record to audit logger");
            }

            None
        };

        // --- Step 2: Cloud deep analysis for high-risk events ---
        if let Some(ref triage_resp) = slm_result {
            if triage_resp.risk_level >= RiskLevel::High {
                let deep_request = AiRequest {
                    task_type: TaskType::DeepAnalysis,
                    prompt: format!(
                        "DEEP ANALYSIS REQUEST\n\
                         Local triage result: {} risk (confidence: {:.2})\n\
                         Triage explanation: {}\n\n\
                         Original event:\n{}",
                        triage_resp.risk_level,
                        triage_resp.confidence,
                        triage_resp.explanation,
                        prompt,
                    ),
                    context: Some(format!(
                        "Local triage: {} risk",
                        triage_resp.risk_level
                    )),
                };

                let deep_result = ai_manager.analyze(deep_request).await;

                if let Some(ref deep_resp) = deep_result.response {
                    info!(
                        id = %event.id,
                        risk = %deep_resp.risk_level,
                        confidence = deep_resp.confidence,
                        backend = %deep_result.backend_used,
                        fallback = deep_result.fallback_used,
                        "AI deep analysis complete (advisory only)"
                    );

                    // Enrich audit record with deep analysis
                    let mut audit_record = event.to_audit_record();
                    if let Some(details) = audit_record.event_details.as_object_mut() {
                        details.insert(
                            "deep_analysis".to_string(),
                            serde_json::json!({
                                "risk_level": deep_resp.risk_level.to_string(),
                                "explanation": deep_resp.explanation,
                                "confidence": deep_resp.confidence,
                                "backend": deep_result.backend_used,
                                "fallback_used": deep_result.fallback_used,
                            }),
                        );
                    }
                    if let Err(e) = audit_tx.try_send(audit_record) {
                        warn!(error = %e, "failed to send deep analysis enrichment to audit logger");
                    }
                } else {
                    debug!(
                        id = %event.id,
                        message = ?deep_result.message,
                        "AI deep analysis unavailable (cloud not configured or failed)"
                    );
                }
            }
        }

        // --- Step 3: Swarm escalation for critical events (same as legacy) ---
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
                    .unwrap_or_else(|| "AI analysis unavailable".to_string());

                let swarm_event = SwarmEventData {
                    server_name: server_name.clone(),
                    client_name: client_name.clone(),
                    tool_name: None,
                    arguments: None,
                    resource_uri: None,
                    sampling_content: None,
                    recent_events: vec![],
                    slm_risk,
                    slm_explanation,
                };

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

        // --- Step 4: Cloud agent auto-escalation for high-risk events ---
        let slm_is_high_or_above = slm_result
            .as_ref()
            .is_some_and(|r| r.risk_level >= RiskLevel::High);

        if slm_is_high_or_above {
            if let Some(ref agent_mgr) = cloud_agent {
                let slm_explanation = slm_result
                    .as_ref()
                    .map(|r| r.explanation.clone())
                    .unwrap_or_default();
                let slm_risk = slm_result
                    .as_ref()
                    .map(|r| r.risk_level.to_string())
                    .unwrap_or_default();

                let event_id = event.id.to_string();
                let briefing = format!(
                    "AUTO-ESCALATION from AI dual-backend triage.\n\
                     Event ID: {}\n\
                     Triage Risk: {}\n\
                     Triage Explanation: {}\n\
                     Event severity: {:?}\n\n\
                     Investigate this event thoroughly. Determine if this is a true \
                     positive or false positive. If true positive, assess the blast \
                     radius and recommend remediation steps.",
                    event_id,
                    slm_risk,
                    slm_explanation,
                    event.severity(),
                );

                use clawdefender_swarm::agent_session::SessionType as AgentSessionType;

                let query = format!(
                    "Investigate event {} — AI flagged as {} risk: {}",
                    event_id, slm_risk, slm_explanation
                );

                match agent_mgr
                    .start_session(
                        AgentSessionType::Investigate {
                            event_id: event_id.clone(),
                        },
                        briefing,
                        Some(query),
                    )
                    .await
                {
                    Ok(session_id) => {
                        info!(
                            event_id = %event_id,
                            session_id = %session_id,
                            slm_risk = %slm_risk,
                            "Cloud agent Investigate session auto-created for suspicious event"
                        );
                    }
                    Err(e) => {
                        warn!(
                            event_id = %event_id,
                            error = %e,
                            "Failed to auto-create cloud Investigate session, continuing without"
                        );
                    }
                }
            }
        }
    }

    /// Build an AnalysisRequest from a correlated event (shared by both legacy and dual paths).
    fn build_analysis_request(
        event: &CorrelatedEvent,
        server_name: &str,
        client_name: &str,
    ) -> AnalysisRequest {
        if let Some(ref mcp) = event.mcp_event {
            match &mcp.kind {
                McpEventKind::ToolCall(tc) => AnalysisRequest {
                    event_type: AnalysisEventType::McpToolCall {
                        tool_name: tc.tool_name.clone(),
                        arguments: tc.arguments.clone(),
                    },
                    server_name: server_name.to_string(),
                    client_name: client_name.to_string(),
                    context: AnalysisContext {
                        recent_events: vec![],
                        server_reputation: ServerReputation::default(),
                    },
                },
                McpEventKind::ResourceRead(rr) => AnalysisRequest {
                    event_type: AnalysisEventType::McpResourceRead {
                        uri: rr.uri.clone(),
                    },
                    server_name: server_name.to_string(),
                    client_name: client_name.to_string(),
                    context: AnalysisContext {
                        recent_events: vec![],
                        server_reputation: ServerReputation::default(),
                    },
                },
                McpEventKind::SamplingRequest(sr) => AnalysisRequest {
                    event_type: AnalysisEventType::McpSampling {
                        content: serde_json::to_string(&sr.messages)
                            .unwrap_or_else(|_| "sampling request".to_string()),
                    },
                    server_name: server_name.to_string(),
                    client_name: client_name.to_string(),
                    context: AnalysisContext {
                        recent_events: vec![],
                        server_reputation: ServerReputation::default(),
                    },
                },
                _ => {
                    let description = format!("{:?}", mcp.kind);
                    AnalysisRequest {
                        event_type: AnalysisEventType::UncorrelatedOsActivity { description },
                        server_name: server_name.to_string(),
                        client_name: client_name.to_string(),
                        context: AnalysisContext {
                            recent_events: vec![],
                            server_reputation: ServerReputation::default(),
                        },
                    }
                }
            }
        } else {
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
            AnalysisRequest {
                event_type: AnalysisEventType::UncorrelatedOsActivity { description },
                server_name: server_name.to_string(),
                client_name: client_name.to_string(),
                context: AnalysisContext {
                    recent_events: vec![],
                    server_reputation: ServerReputation::default(),
                },
            }
        }
    }

    /// Process a correlated event through the behavioral engines.
    ///
    /// This extracts MCP and OS events, feeds them to the learning engine,
    /// scores them for anomalies, checks kill chains, and runs through the
    /// decision engine. Results are attached to the audit record.
    ///
    /// Returns a list of escalation reasons if the event should be sent to the
    /// SLM for AI analysis. An empty list means no escalation.
    async fn process_behavioral(
        &self,
        engines: &BehavioralEngines,
        correlated: &CorrelatedEvent,
        audit_record: &mut AuditRecord,
        anomaly_escalation_threshold: f64,
    ) -> Vec<EscalationReason> {
        let mut escalation_reasons = Vec::new();

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
            None => return escalation_reasons, // No profile yet, nothing to score
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

        // Check anomaly score escalation threshold
        if highest_score_total >= anomaly_escalation_threshold {
            escalation_reasons.push(EscalationReason::HighAnomalyScore {
                score: highest_score_total,
            });
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
        let best_kc = if all_kc_matches.len() <= 1 {
            all_kc_matches.into_iter().next()
        } else {
            all_kc_matches.into_iter().max_by_key(|m| match m.severity {
                killchain::Severity::Critical => 4u8,
                killchain::Severity::High => 3,
                killchain::Severity::Medium => 2,
                killchain::Severity::Low => 1,
            })
        };

        // Any kill chain match triggers escalation regardless of anomaly score
        if let Some(ref kc_match) = best_kc {
            escalation_reasons.push(EscalationReason::KillChainMatch {
                pattern: kc_match.pattern.name.clone(),
            });
        }

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

            // Log significant findings and collect escalation reasons
            match &decision {
                BehavioralDecision::AutoBlock {
                    explanation, ..
                } => {
                    warn!(
                        server = %server_name,
                        explanation = %explanation,
                        "Behavioral engine: auto-block triggered"
                    );
                    escalation_reasons.push(EscalationReason::BehavioralDecision {
                        decision_type: "AutoBlock".to_string(),
                    });
                }
                BehavioralDecision::EnrichedPrompt {
                    anomaly_score,
                    ..
                } => {
                    info!(
                        server = %server_name,
                        score = anomaly_score.total,
                        "Behavioral engine: anomaly detected"
                    );
                    escalation_reasons.push(EscalationReason::BehavioralDecision {
                        decision_type: "EnrichedPrompt".to_string(),
                    });
                }
                _ => {}
            }
        }

        escalation_reasons
    }
}
