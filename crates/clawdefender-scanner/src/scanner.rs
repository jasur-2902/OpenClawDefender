use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::client::ScanClient;
use crate::evidence::EvidenceCollector;
use crate::finding::{Finding, Severity};
use crate::modules::{ScanContext, ScanModule};
use crate::progress::{ModuleStatus, ScanProgress};
use crate::sandbox::{Sandbox, SandboxConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub server_command: Vec<String>,
    #[serde(default = "default_module_timeout")]
    pub timeout_per_module: u64,
    #[serde(default = "default_total_timeout")]
    pub total_timeout: u64,
    pub modules: Option<Vec<String>>,
    #[serde(default = "default_output_format")]
    pub output_format: String,
    pub output_path: Option<PathBuf>,
    pub threshold: Option<Severity>,
    pub baseline_path: Option<PathBuf>,
}

fn default_module_timeout() -> u64 {
    300
}
fn default_total_timeout() -> u64 {
    1800
}
fn default_output_format() -> String {
    "terminal".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub target: String,
    pub scan_date: DateTime<Utc>,
    pub duration_secs: f64,
    pub findings: Vec<Finding>,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl ScanSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        Self {
            total: findings.len(),
            critical: findings.iter().filter(|f| f.severity == Severity::Critical).count(),
            high: findings.iter().filter(|f| f.severity == Severity::High).count(),
            medium: findings.iter().filter(|f| f.severity == Severity::Medium).count(),
            low: findings.iter().filter(|f| f.severity == Severity::Low).count(),
            info: findings.iter().filter(|f| f.severity == Severity::Info).count(),
        }
    }
}

pub struct Scanner {
    modules: Vec<Box<dyn ScanModule>>,
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    pub fn add_module(&mut self, module: Box<dyn ScanModule>) {
        self.modules.push(module);
    }

    pub fn default_modules() -> Vec<Box<dyn ScanModule>> {
        vec![
            Box::new(crate::modules::path_traversal::PathTraversalModule::new()),
            Box::new(crate::modules::prompt_injection::PromptInjectionModule::new()),
            Box::new(crate::modules::exfiltration::ExfiltrationModule::new()),
            Box::new(crate::modules::capability_escalation::CapabilityEscalationModule::new()),
            Box::new(crate::modules::dependency_audit::DependencyAuditModule::new()),
            Box::new(crate::modules::fuzzing::FuzzingModule::new()),
        ]
    }

    pub async fn run(&self, config: ScanConfig) -> Result<ScanReport> {
        let start = Instant::now();
        let _total_timeout = Duration::from_secs(config.total_timeout);
        let _module_timeout = Duration::from_secs(config.timeout_per_module);

        // Create sandbox
        let sandbox = Sandbox::new(&SandboxConfig::default())?;
        let env_vars = sandbox.env_vars();

        // Start client
        let mut client = ScanClient::start(&config.server_command, env_vars).await?;
        let _init_result = client.initialize().await?;

        // Discover tools and resources
        let tool_list = client.list_tools().await.unwrap_or_default();
        let resource_list = client.list_resources().await.unwrap_or_default();

        let server_stderr = client.server_stderr.clone();

        let target = config.server_command.join(" ");

        // Build scan context
        let mut ctx = ScanContext {
            client,
            sandbox,
            evidence: EvidenceCollector::new(),
            tool_list,
            resource_list,
            server_stderr: server_stderr.clone(),
        };

        // Filter modules
        let module_names: Vec<String> = self.modules.iter().map(|m| m.name().to_string()).collect();
        let mut progress = ScanProgress::new(module_names);

        let mut all_findings = Vec::new();

        for module in &self.modules {
            if let Some(ref filter) = config.modules {
                if !filter.contains(&module.name().to_string()) {
                    continue;
                }
            }

            progress.update_module(module.name(), ModuleStatus::Running);

            match module.run(&mut ctx).await {
                Ok(findings) => {
                    progress.update_module(
                        module.name(),
                        ModuleStatus::Complete {
                            findings: findings.clone(),
                        },
                    );
                    all_findings.extend(findings);
                }
                Err(e) => {
                    tracing::warn!(module = module.name(), error = %e, "Module failed");
                    progress.update_module(
                        module.name(),
                        ModuleStatus::Complete {
                            findings: Vec::new(),
                        },
                    );
                }
            }
        }

        // Sort findings by severity (highest first)
        all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        // Apply threshold filter
        if let Some(ref threshold) = config.threshold {
            all_findings.retain(|f| f.severity >= *threshold);
        }

        let duration_secs = start.elapsed().as_secs_f64();
        let summary = ScanSummary::from_findings(&all_findings);

        // Shutdown client
        ctx.client.shutdown().await.ok();

        Ok(ScanReport {
            target,
            scan_date: Utc::now(),
            duration_secs,
            findings: all_findings,
            summary,
        })
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Deduplicate findings that reference the same vulnerability.
/// Groups by (category, tool name from reproduction), keeps highest severity, merges evidence.
pub fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut groups: HashMap<String, Finding> = HashMap::new();

    for finding in findings {
        let tool_name = finding
            .reproduction
            .as_ref()
            .and_then(|r| r.tool.as_deref())
            .unwrap_or("unknown");
        let key = format!("{:?}::{}", finding.category, tool_name);

        match groups.get_mut(&key) {
            Some(existing) => {
                // Keep highest severity
                if finding.severity > existing.severity {
                    existing.severity = finding.severity;
                    existing.cvss = finding.cvss;
                    existing.title = finding.title.clone();
                }
                // Merge evidence
                existing
                    .evidence
                    .os_events
                    .extend(finding.evidence.os_events.into_iter());
                existing
                    .evidence
                    .files_modified
                    .extend(finding.evidence.files_modified.into_iter());
                existing
                    .evidence
                    .network_connections
                    .extend(finding.evidence.network_connections.into_iter());
                existing
                    .evidence
                    .messages
                    .extend(finding.evidence.messages.into_iter());
                if finding.evidence.canary_detected {
                    existing.evidence.canary_detected = true;
                }
                // Append description details
                if !finding.description.is_empty()
                    && !existing.description.contains(&finding.description)
                {
                    existing
                        .description
                        .push_str(&format!("\n\nAdditional: {}", finding.description));
                }
            }
            None => {
                groups.insert(key, finding);
            }
        }
    }

    // Dedup evidence vectors
    let mut results: Vec<Finding> = groups.into_values().collect();
    for f in &mut results {
        f.evidence.os_events.sort();
        f.evidence.os_events.dedup();
        f.evidence.files_modified.sort();
        f.evidence.files_modified.dedup();
        f.evidence.network_connections.sort();
        f.evidence.network_connections.dedup();
        f.evidence.messages.sort();
        f.evidence.messages.dedup();
    }
    results.sort_by(|a, b| b.severity.cmp(&a.severity));
    results
}

/// Cross-reference related findings. For example, if path traversal and injection
/// both reference the same file, note the correlation in descriptions.
pub fn correlate_findings(findings: &mut [Finding]) {
    let n = findings.len();
    if n < 2 {
        return;
    }

    // Collect cross-references based on overlapping evidence
    let mut annotations: Vec<(usize, String)> = Vec::new();

    for i in 0..n {
        for j in (i + 1)..n {
            if findings[i].category == findings[j].category {
                continue;
            }

            // Check for overlapping files
            let shared_files: Vec<String> = findings[i]
                .evidence
                .files_modified
                .iter()
                .filter(|f| findings[j].evidence.files_modified.contains(f))
                .cloned()
                .collect();

            // Check for overlapping network connections
            let shared_net: Vec<String> = findings[i]
                .evidence
                .network_connections
                .iter()
                .filter(|n| findings[j].evidence.network_connections.contains(n))
                .cloned()
                .collect();

            if !shared_files.is_empty() || !shared_net.is_empty() {
                let note_for_i = format!(
                    "\n[Cross-ref: related to {} finding \"{}\"]",
                    findings[j].category, findings[j].title
                );
                let note_for_j = format!(
                    "\n[Cross-ref: related to {} finding \"{}\"]",
                    findings[i].category, findings[i].title
                );
                annotations.push((i, note_for_i));
                annotations.push((j, note_for_j));
            }
        }
    }

    for (idx, note) in annotations {
        if !findings[idx].description.contains(&note) {
            findings[idx].description.push_str(&note);
        }
    }
}

/// Load a previous scan report from a JSON file (baseline).
pub fn load_baseline(path: &Path) -> Result<ScanReport> {
    let content = std::fs::read_to_string(path)?;
    let report: ScanReport = serde_json::from_str(&content)?;
    Ok(report)
}

/// Compute the delta between a current report and a baseline.
/// Returns only findings that are NOT present in the baseline,
/// comparing by (category, title, tool name).
pub fn compute_delta(current: &ScanReport, baseline: &ScanReport) -> Vec<Finding> {
    let baseline_keys: std::collections::HashSet<String> = baseline
        .findings
        .iter()
        .map(|f| {
            let tool = f
                .reproduction
                .as_ref()
                .and_then(|r| r.tool.as_deref())
                .unwrap_or("");
            format!("{:?}::{}::{}", f.category, tool, f.title)
        })
        .collect();

    current
        .findings
        .iter()
        .filter(|f| {
            let tool = f
                .reproduction
                .as_ref()
                .and_then(|r| r.tool.as_deref())
                .unwrap_or("");
            let key = format!("{:?}::{}::{}", f.category, tool, f.title);
            !baseline_keys.contains(&key)
        })
        .cloned()
        .collect()
}

/// Calculate the exit code for CI/CD based on findings and an optional threshold.
/// 0 = no critical/high, 1 = critical found, 2 = high found (no critical).
pub fn exit_code_for_findings(findings: &[Finding], threshold: Option<&Severity>) -> i32 {
    let min_severity = threshold.copied().unwrap_or(Severity::High);

    let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);
    let has_high = findings.iter().any(|f| f.severity == Severity::High);

    if has_critical && min_severity <= Severity::Critical {
        1
    } else if (has_high && min_severity <= Severity::High)
        || findings.iter().any(|f| f.severity >= min_severity)
    {
        2
    } else {
        0
    }
}
