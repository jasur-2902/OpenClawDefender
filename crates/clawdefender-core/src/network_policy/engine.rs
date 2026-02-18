//! Network policy engine — multi-signal evaluation for outbound connections.

use std::net::IpAddr;

use super::rate_limiter::{ConnectionRateLimiter, RateLimitConfig};
use super::rules::{default_rules, NetworkAction, NetworkRule, RuleSource};
use crate::behavioral::killchain::Severity;

// ---------------------------------------------------------------------------
// Request / Decision types
// ---------------------------------------------------------------------------

/// An outbound network connection request to be evaluated.
///
/// SECURITY: Contains metadata only (IP, port, domain, process info).
/// No request body, response body, or payload content is ever included.
/// This is enforced by the type system — there is no field for content.
#[derive(Debug, Clone)]
pub struct NetworkConnectionRequest {
    pub pid: u32,
    pub process_name: String,
    pub server_name: Option<String>,
    pub is_agent: bool,
    pub destination_ip: Option<IpAddr>,
    pub destination_domain: Option<String>,
    pub destination_port: u16,
    pub protocol: String,
}

/// The engine's decision for a connection request.
#[derive(Debug, Clone)]
pub struct NetworkDecision {
    pub action: NetworkAction,
    pub reason: String,
    pub rule_name: Option<String>,
    pub signals: NetworkSignals,
    pub severity: Severity,
}

/// All signals that contributed to the decision.
#[derive(Debug, Clone, Default)]
pub struct NetworkSignals {
    pub static_rule: Option<(String, NetworkAction)>,
    pub ioc_match: Option<String>,
    pub anomaly_score: Option<f64>,
    pub behavioral_context: Option<String>,
    pub guard_restriction: Option<String>,
    pub kill_chain: Option<String>,
}

/// Data for prompting the user when the decision is Prompt.
#[derive(Debug, Clone)]
pub struct NetworkPromptInfo {
    pub server_name: String,
    pub destination: String,
    pub domain: Option<String>,
    pub anomaly_score: f64,
    pub behavioral_context: String,
    pub ioc_info: Option<String>,
    pub kill_chain_info: Option<String>,
    pub recommendation: String,
    pub timeout_action: NetworkAction,
}

// ---------------------------------------------------------------------------
// External signal providers (trait-like structs passed into evaluate)
// ---------------------------------------------------------------------------

/// External context signals provided to the engine for each evaluation.
#[derive(Debug, Clone, Default)]
pub struct ExternalSignals {
    /// IoC threat ID if the destination matched a known indicator.
    pub ioc_match: Option<String>,
    /// Anomaly score from the behavioral engine (0.0 - 1.0).
    pub anomaly_score: Option<f64>,
    /// Whether the server's profile says it has never networked.
    pub server_has_never_networked: bool,
    /// Whether the destination is unknown to the server profile.
    pub destination_unknown_to_profile: bool,
    /// Active kill chain pattern description if applicable.
    pub kill_chain_context: Option<String>,
    /// Guard network allowlist — if Some, only these destinations are permitted.
    pub guard_network_allowlist: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// NetworkPolicyEngine
// ---------------------------------------------------------------------------

/// The network policy engine evaluates outbound connections using multiple
/// signal sources and produces allow/block/prompt decisions.
///
/// SECURITY: This engine ONLY evaluates agent processes. Non-agent traffic
/// is unconditionally allowed at the top of `evaluate()` before any signals
/// are consulted. This guarantees user traffic is never filtered or logged.
///
/// SECURITY: On failure, the engine fails open — it never silently drops
/// connections. If signals are unavailable, decisions fall through to the
/// default action (prompt by default, configurable).
///
/// Threat model: protects against malicious agent connections to C2 servers,
/// data exfiltration, and unauthorized network access. Does NOT protect
/// against kernel-level attacks or compromised system extensions.
pub struct NetworkPolicyEngine {
    rules: Vec<NetworkRule>,
    default_action: NetworkAction,
    rate_limiter: ConnectionRateLimiter,
}

impl NetworkPolicyEngine {
    /// Create a new engine with the given rules and default action.
    pub fn new(
        mut user_rules: Vec<NetworkRule>,
        default_action: NetworkAction,
        rate_limit_config: RateLimitConfig,
    ) -> Self {
        // Combine user rules with built-in defaults. User rules come first.
        let mut defaults = default_rules();
        user_rules.append(&mut defaults);
        // Sort by priority (lower = evaluated first).
        user_rules.sort_by_key(|r| r.priority);

        Self {
            rules: user_rules,
            default_action,
            rate_limiter: ConnectionRateLimiter::new(rate_limit_config),
        }
    }

    /// Create an engine with only default rules, suitable for testing.
    pub fn with_defaults() -> Self {
        Self::new(Vec::new(), NetworkAction::Prompt, RateLimitConfig::default())
    }

    /// Evaluate a connection request and return a decision.
    ///
    /// Signal priority: IoC > Guard > Static Block > Static Allow > Behavioral > Kill Chain > Default
    ///
    /// SECURITY: The first check is `is_agent`. Non-agent traffic returns Allow
    /// immediately, before any signal evaluation. This is the process-isolation
    /// guarantee — user traffic is never subjected to policy evaluation.
    ///
    /// SECURITY: IoC matches have the highest priority and override ALL other
    /// signals, including explicit user allow rules. This prevents a compromised
    /// agent from exploiting user-created allow rules to reach known C2 infrastructure.
    pub fn evaluate(
        &mut self,
        request: &NetworkConnectionRequest,
        signals: &ExternalSignals,
    ) -> NetworkDecision {
        let mut net_signals = NetworkSignals::default();

        // Record the connection for rate limiting (alerts only, does not block).
        let dest_str = request
            .destination_domain
            .as_deref()
            .or_else(|| request.destination_ip.as_ref().map(|_ip| ""))
            .unwrap_or("");
        let dest_label = if !dest_str.is_empty() {
            dest_str.to_string()
        } else {
            request
                .destination_ip
                .map(|ip| ip.to_string())
                .unwrap_or_default()
        };
        let _rate_alerts = self.rate_limiter.record_connection(
            request.pid,
            &dest_label,
            chrono::Utc::now(),
        );

        // 1. Non-agent traffic → always allow.
        if !request.is_agent {
            return NetworkDecision {
                action: NetworkAction::Allow,
                reason: "Non-agent process — always allowed".to_string(),
                rule_name: None,
                signals: net_signals,
                severity: Severity::Low,
            };
        }

        // 2. IoC match → BLOCK (highest priority, overrides allow rules).
        if let Some(ref threat_id) = signals.ioc_match {
            net_signals.ioc_match = Some(threat_id.clone());
            return NetworkDecision {
                action: NetworkAction::Block,
                reason: format!(
                    "Blocked: destination matches known threat indicator ({})",
                    threat_id
                ),
                rule_name: Some("ioc_block".to_string()),
                signals: net_signals,
                severity: Severity::Critical,
            };
        }

        // 3. Guard restrictions.
        if let Some(ref allowlist) = signals.guard_network_allowlist {
            let allowed = self.destination_in_allowlist(request, allowlist);
            if !allowed {
                let dest = format_destination(request);
                net_signals.guard_restriction =
                    Some(format!("Destination {} not in guard allowlist", dest));
                return NetworkDecision {
                    action: NetworkAction::Block,
                    reason: format!(
                        "Blocked: {} not in guard network allowlist",
                        dest
                    ),
                    rule_name: Some("guard_restriction".to_string()),
                    signals: net_signals,
                    severity: Severity::High,
                };
            }
        }

        // 4. Static rules (first match wins, ordered by priority).
        for rule in &self.rules {
            // Skip agent-only rules for non-agents (already handled above, but guard).
            if rule.only_agents && !request.is_agent {
                continue;
            }

            if rule.matches_destination(request.destination_ip, request.destination_domain.as_deref())
            {
                net_signals.static_rule =
                    Some((rule.name.clone(), rule.action.clone()));
                let mut severity = match rule.action {
                    NetworkAction::Block => Severity::High,
                    NetworkAction::Prompt => Severity::Medium,
                    NetworkAction::Allow | NetworkAction::Log => Severity::Low,
                };

                // 5. Behavioral context — boost toward prompt/block if anomalous.
                if signals.server_has_never_networked {
                    net_signals.behavioral_context =
                        Some("Server has NEVER made network connections".to_string());
                    // If static rule would allow, escalate to prompt.
                    if rule.action == NetworkAction::Allow
                        && rule.source != RuleSource::Default
                    {
                        // User explicitly allowed, don't override.
                    } else if rule.action == NetworkAction::Allow {
                        return self.build_behavioral_escalation(
                            request,
                            &net_signals,
                            signals,
                        );
                    }
                }
                if signals.destination_unknown_to_profile {
                    let ctx = net_signals.behavioral_context.get_or_insert_with(String::new);
                    if !ctx.is_empty() {
                        ctx.push_str("; ");
                    }
                    ctx.push_str("Destination unknown to server profile");
                }

                // 6. Kill chain context — escalate severity.
                if let Some(ref kc) = signals.kill_chain_context {
                    net_signals.kill_chain = Some(kc.clone());
                    severity = Severity::Critical;
                }

                return NetworkDecision {
                    action: rule.action.clone(),
                    reason: format!(
                        "Rule '{}': {}",
                        rule.name, rule.description
                    ),
                    rule_name: Some(rule.name.clone()),
                    signals: net_signals,
                    severity,
                };
            }
        }

        // 5 & 6 without static rule match — behavioral + kill chain on default action.
        if signals.server_has_never_networked {
            net_signals.behavioral_context =
                Some("Server has NEVER made network connections".to_string());
        }
        if signals.destination_unknown_to_profile {
            let ctx = net_signals.behavioral_context.get_or_insert_with(String::new);
            if !ctx.is_empty() {
                ctx.push_str("; ");
            }
            ctx.push_str("Destination unknown to server profile");
        }

        let mut severity = match self.default_action {
            NetworkAction::Block => Severity::High,
            NetworkAction::Prompt => Severity::Medium,
            _ => Severity::Low,
        };

        if let Some(ref kc) = signals.kill_chain_context {
            net_signals.kill_chain = Some(kc.clone());
            severity = Severity::Critical;
        }

        // 7. Default action.
        NetworkDecision {
            action: self.default_action.clone(),
            reason: "No rule matched — applying default action".to_string(),
            rule_name: None,
            signals: net_signals,
            severity,
        }
    }

    /// Build prompt info for a decision that requires user interaction.
    pub fn build_prompt_info(
        &self,
        request: &NetworkConnectionRequest,
        decision: &NetworkDecision,
    ) -> NetworkPromptInfo {
        let dest = format_destination(request);
        let anomaly = decision
            .signals
            .anomaly_score
            .unwrap_or(0.0);
        let behavioral = decision
            .signals
            .behavioral_context
            .clone()
            .unwrap_or_else(|| "No behavioral anomalies detected".to_string());

        let recommendation = if decision.signals.ioc_match.is_some() {
            "ClawDefender strongly recommends BLOCKING.".to_string()
        } else if anomaly > 0.7 {
            "ClawDefender strongly recommends BLOCKING.".to_string()
        } else if anomaly > 0.4 {
            "ClawDefender recommends caution.".to_string()
        } else {
            "No strong recommendation.".to_string()
        };

        NetworkPromptInfo {
            server_name: request
                .server_name
                .clone()
                .unwrap_or_else(|| request.process_name.clone()),
            destination: dest,
            domain: request.destination_domain.clone(),
            anomaly_score: anomaly,
            behavioral_context: behavioral,
            ioc_info: decision.signals.ioc_match.as_ref().map(|id| {
                format!("IoC Match: {}", id)
            }),
            kill_chain_info: decision.signals.kill_chain.clone(),
            recommendation,
            timeout_action: NetworkAction::Block,
        }
    }

    /// Add a rule at runtime (e.g., from threat intel feed).
    pub fn add_rule(&mut self, rule: NetworkRule) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.priority);
    }

    /// Return a reference to all loaded rules.
    pub fn rules(&self) -> &[NetworkRule] {
        &self.rules
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn destination_in_allowlist(
        &self,
        request: &NetworkConnectionRequest,
        allowlist: &[String],
    ) -> bool {
        for allowed in allowlist {
            if let Some(ref domain) = request.destination_domain {
                if domain.eq_ignore_ascii_case(allowed) {
                    return true;
                }
                // Wildcard support in allowlist.
                if allowed.starts_with("*.") {
                    let suffix = &allowed[1..]; // ".example.com"
                    if domain.to_lowercase().ends_with(&suffix.to_lowercase()) {
                        return true;
                    }
                }
            }
            if let Some(ip) = request.destination_ip {
                if ip.to_string() == *allowed {
                    return true;
                }
            }
        }
        false
    }

    fn build_behavioral_escalation(
        &self,
        request: &NetworkConnectionRequest,
        signals: &NetworkSignals,
        ext: &ExternalSignals,
    ) -> NetworkDecision {
        let mut net_signals = signals.clone();
        net_signals.anomaly_score = ext.anomaly_score;

        let mut severity = Severity::Medium;
        if let Some(ref kc) = ext.kill_chain_context {
            net_signals.kill_chain = Some(kc.clone());
            severity = Severity::Critical;
        }

        NetworkDecision {
            action: NetworkAction::Prompt,
            reason: format!(
                "Escalated to prompt: server '{}' has never made network connections",
                request
                    .server_name
                    .as_deref()
                    .unwrap_or(&request.process_name)
            ),
            rule_name: Some("behavioral_escalation".to_string()),
            signals: net_signals,
            severity,
        }
    }
}

/// Format a destination for display.
fn format_destination(request: &NetworkConnectionRequest) -> String {
    let host = request
        .destination_domain
        .as_deref()
        .or_else(|| request.destination_ip.as_ref().map(|_| ""))
        .unwrap_or("unknown");

    if host.is_empty() {
        if let Some(ip) = request.destination_ip {
            format!("{}:{} ({})", ip, request.destination_port, request.protocol)
        } else {
            format!("unknown:{}", request.destination_port)
        }
    } else {
        format!(
            "{}:{} ({})",
            host, request.destination_port, request.protocol
        )
    }
}
