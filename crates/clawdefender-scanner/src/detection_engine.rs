//! Unified detection engine that wires all host-scanning modules together.
//!
//! Runs YARA signature scanning, persistence enumeration, OSQuery-style
//! pattern detection, and optional ClamAV scanning **in parallel** via
//! `tokio::join!`, then cross-references and deduplicates findings.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::finding::{Finding, Severity};
use crate::modules::browser_audit::BrowserAuditModule;
use crate::modules::cis_benchmark::CisBenchmarkModule;
use crate::modules::clamav::ClamAvModule;
use crate::modules::clipboard_monitor::ClipboardMonitorModule;
use crate::modules::file_integrity::FileIntegrityModule;
use crate::modules::memory_scanner::MemoryScanModule;
use crate::modules::pattern_detection::PatternDetectionModule;
use crate::modules::persistence::PersistenceModule;
use crate::modules::signature_detection::SignatureDetectionModule;
use crate::modules::tcc_audit::TccAuditModule;
use crate::modules::ScanModule;

// ---------------------------------------------------------------------------
// Scan modes
// ---------------------------------------------------------------------------

/// Which detection modules to run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScanMode {
    /// All deterministic scanners including memory scanning.
    Full,
    /// YARA signature scanning only.
    SignaturesOnly,
    /// Persistence enumeration only.
    PersistenceOnly,
    /// OSQuery-style pattern detection only.
    PatternsOnly,
    /// ClamAV only (if installed).
    ClamavOnly,
    /// Process memory YARA scanning only.
    MemoryOnly,
    /// TCC permission audit only.
    TccOnly,
    /// File integrity check only.
    FileIntegrityOnly,
    /// CIS benchmark compliance only.
    CisOnly,
    /// Browser extension audit only.
    BrowserOnly,
    /// Clipboard security check only.
    ClipboardOnly,
}

impl Default for ScanMode {
    fn default() -> Self {
        Self::Full
    }
}

// ---------------------------------------------------------------------------
// Detection method badge (for GUI)
// ---------------------------------------------------------------------------

/// Detection method tag attached to each finding for GUI badges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DetectionMethod {
    YaraSignature,
    PersistenceEnum,
    PatternMatch,
    ClamAv,
    MemoryYaraScan,
    TccAudit,
    FileIntegrity,
    ClipboardCheck,
    CisBenchmark,
    BrowserAudit,
    KillChainCorrelation,
    AiAnalysis,
    CrossModuleCorrelation,
}

impl std::fmt::Display for DetectionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectionMethod::YaraSignature => write!(f, "YARA Signature"),
            DetectionMethod::PersistenceEnum => write!(f, "Persistence Scan"),
            DetectionMethod::PatternMatch => write!(f, "Pattern Match"),
            DetectionMethod::ClamAv => write!(f, "ClamAV"),
            DetectionMethod::MemoryYaraScan => write!(f, "Memory YARA Scan"),
            DetectionMethod::TccAudit => write!(f, "TCC Audit"),
            DetectionMethod::FileIntegrity => write!(f, "File Integrity"),
            DetectionMethod::ClipboardCheck => write!(f, "Clipboard Check"),
            DetectionMethod::CisBenchmark => write!(f, "CIS Benchmark"),
            DetectionMethod::BrowserAudit => write!(f, "Browser Audit"),
            DetectionMethod::KillChainCorrelation => write!(f, "Kill Chain"),
            DetectionMethod::AiAnalysis => write!(f, "AI Analysis"),
            DetectionMethod::CrossModuleCorrelation => write!(f, "Cross-Module"),
        }
    }
}

// ---------------------------------------------------------------------------
// Report structures
// ---------------------------------------------------------------------------

/// A finding enriched with detection method badge and optional AI analysis.
#[derive(Debug, Clone, Serialize)]
pub struct EnrichedFinding {
    #[serde(flatten)]
    pub finding: Finding,
    pub detection_methods: Vec<DetectionMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_analysis: Option<String>,
}

/// Unified report produced by the detection engine.
#[derive(Debug, Clone, Serialize)]
pub struct DetectionReport {
    pub findings: Vec<EnrichedFinding>,
    pub modules_run: Vec<String>,
    pub duration_secs: f64,
    pub summary: DetectionSummary,
}

/// Severity breakdown summary.
#[derive(Debug, Clone, Serialize)]
pub struct DetectionSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

impl DetectionSummary {
    fn from_findings(findings: &[EnrichedFinding]) -> Self {
        Self {
            critical: findings
                .iter()
                .filter(|f| matches!(f.finding.severity, Severity::Critical))
                .count(),
            high: findings
                .iter()
                .filter(|f| matches!(f.finding.severity, Severity::High))
                .count(),
            medium: findings
                .iter()
                .filter(|f| matches!(f.finding.severity, Severity::Medium))
                .count(),
            low: findings
                .iter()
                .filter(|f| matches!(f.finding.severity, Severity::Low))
                .count(),
            info: findings
                .iter()
                .filter(|f| matches!(f.finding.severity, Severity::Info))
                .count(),
            total: findings.len(),
        }
    }
}

// ---------------------------------------------------------------------------
// Detection Engine
// ---------------------------------------------------------------------------

/// Orchestrates all host-level detection modules and merges their output.
pub struct DetectionEngine {
    mode: ScanMode,
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self {
            mode: ScanMode::Full,
        }
    }

    pub fn with_mode(mode: ScanMode) -> Self {
        Self { mode }
    }

    /// Run detection modules **in parallel** and return unified findings.
    pub async fn run_all(&self) -> anyhow::Result<DetectionReport> {
        let start = std::time::Instant::now();

        let (findings, modules_run) = match &self.mode {
            ScanMode::Full => self.run_full().await,
            ScanMode::SignaturesOnly => {
                self.run_single(
                    Box::new(SignatureDetectionModule::new()),
                    DetectionMethod::YaraSignature,
                )
                .await
            }
            ScanMode::PersistenceOnly => {
                self.run_single(
                    Box::new(PersistenceModule::new()),
                    DetectionMethod::PersistenceEnum,
                )
                .await
            }
            ScanMode::PatternsOnly => {
                self.run_single(
                    Box::new(PatternDetectionModule::new()),
                    DetectionMethod::PatternMatch,
                )
                .await
            }
            ScanMode::ClamavOnly => {
                self.run_single(Box::new(ClamAvModule::new()), DetectionMethod::ClamAv)
                    .await
            }
            ScanMode::MemoryOnly => {
                self.run_single(
                    Box::new(MemoryScanModule::new()),
                    DetectionMethod::MemoryYaraScan,
                )
                .await
            }
            ScanMode::TccOnly => {
                self.run_single(Box::new(TccAuditModule::new()), DetectionMethod::TccAudit)
                    .await
            }
            ScanMode::FileIntegrityOnly => {
                self.run_single(
                    Box::new(FileIntegrityModule::new()),
                    DetectionMethod::FileIntegrity,
                )
                .await
            }
            ScanMode::CisOnly => {
                self.run_single(
                    Box::new(CisBenchmarkModule::new()),
                    DetectionMethod::CisBenchmark,
                )
                .await
            }
            ScanMode::BrowserOnly => {
                self.run_single(
                    Box::new(BrowserAuditModule::new()),
                    DetectionMethod::BrowserAudit,
                )
                .await
            }
            ScanMode::ClipboardOnly => {
                self.run_single(
                    Box::new(ClipboardMonitorModule::new()),
                    DetectionMethod::ClipboardCheck,
                )
                .await
            }
        };

        // Cross-reference and deduplicate
        let mut enriched = findings;
        cross_reference_findings(&mut enriched);
        enriched.sort_by(|a, b| b.finding.severity.cmp(&a.finding.severity));

        let summary = DetectionSummary::from_findings(&enriched);

        Ok(DetectionReport {
            findings: enriched,
            modules_run,
            duration_secs: start.elapsed().as_secs_f64(),
            summary,
        })
    }

    /// Run all modules in parallel via `tokio::join!`.
    async fn run_full(&self) -> (Vec<EnrichedFinding>, Vec<String>) {
        let sig_mod = SignatureDetectionModule::new();
        let persist_mod = PersistenceModule::new();
        let pattern_mod = PatternDetectionModule::new();
        let clamav_mod = ClamAvModule::new();
        let memory_mod = MemoryScanModule::new();
        let tcc_mod = TccAuditModule::new();
        let fim_mod = FileIntegrityModule::new();
        let clip_mod = ClipboardMonitorModule::new();
        let cis_mod = CisBenchmarkModule::new();
        let browser_mod = BrowserAuditModule::new();

        let (
            sig_res,
            persist_res,
            pattern_res,
            clamav_res,
            memory_res,
            tcc_res,
            fim_res,
            clip_res,
            cis_res,
            browser_res,
        ) = tokio::join!(
            sig_mod.run_standalone(),
            persist_mod.run_standalone(),
            pattern_mod.run_standalone(),
            clamav_mod.run_standalone(),
            memory_mod.run_standalone(),
            tcc_mod.run_standalone(),
            fim_mod.run_standalone(),
            clip_mod.run_standalone(),
            cis_mod.run_standalone(),
            browser_mod.run_standalone(),
        );

        let mut all_findings = Vec::new();
        let mut modules_run = Vec::new();

        // Helper closure to collect results from a module
        let mut collect =
            |name: &str, res: anyhow::Result<Vec<Finding>>, method: DetectionMethod| {
                modules_run.push(name.to_string());
                match res {
                    Ok(findings) => {
                        tracing::info!("{}: {} finding(s)", name, findings.len());
                        for f in findings {
                            all_findings.push(EnrichedFinding {
                                finding: f,
                                detection_methods: vec![method.clone()],
                                ai_analysis: None,
                            });
                        }
                    }
                    Err(e) => tracing::warn!("{}: error -- {}", name, e),
                }
            };

        collect(
            "signature-detection",
            sig_res,
            DetectionMethod::YaraSignature,
        );
        collect(
            "persistence-detection",
            persist_res,
            DetectionMethod::PersistenceEnum,
        );
        collect(
            "pattern-detection",
            pattern_res,
            DetectionMethod::PatternMatch,
        );
        collect("clamav-scan", clamav_res, DetectionMethod::ClamAv);
        collect(
            "memory-scanner",
            memory_res,
            DetectionMethod::MemoryYaraScan,
        );
        collect("tcc-audit", tcc_res, DetectionMethod::TccAudit);
        collect("file-integrity", fim_res, DetectionMethod::FileIntegrity);
        collect("clipboard-check", clip_res, DetectionMethod::ClipboardCheck);
        collect("cis-benchmark", cis_res, DetectionMethod::CisBenchmark);
        collect("browser-audit", browser_res, DetectionMethod::BrowserAudit);

        (all_findings, modules_run)
    }

    /// Run a single module.
    async fn run_single(
        &self,
        module: Box<dyn ScanModule>,
        method: DetectionMethod,
    ) -> (Vec<EnrichedFinding>, Vec<String>) {
        let name = module.name().to_string();
        let mut findings = Vec::new();

        match module.run_standalone().await {
            Ok(raw) => {
                tracing::info!("{}: {} finding(s)", name, raw.len());
                for f in raw {
                    findings.push(EnrichedFinding {
                        finding: f,
                        detection_methods: vec![method.clone()],
                        ai_analysis: None,
                    });
                }
            }
            Err(e) => tracing::warn!("{}: error -- {}", name, e),
        }

        (findings, vec![name])
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Cross-referencing & deduplication
// ---------------------------------------------------------------------------

/// Cross-reference findings from different modules:
/// 1. If a YARA finding and a persistence finding reference the same file,
///    merge them into a single Critical finding with combined evidence.
/// 2. Deduplicate: if two findings reference the same file path, keep the
///    higher severity and merge descriptions.
fn cross_reference_findings(findings: &mut Vec<EnrichedFinding>) {
    // Build an index of file paths -> finding indices
    let mut path_index: HashMap<String, Vec<usize>> = HashMap::new();

    for (i, ef) in findings.iter().enumerate() {
        for file_path in &ef.finding.evidence.files_modified {
            path_index.entry(file_path.clone()).or_default().push(i);
        }
    }

    // Track which findings to remove after merging
    let mut to_remove: Vec<usize> = Vec::new();

    for (_path, indices) in &path_index {
        if indices.len() < 2 {
            continue;
        }

        // Find the finding with highest severity to be the "primary"
        let primary_idx = *indices
            .iter()
            .max_by(|&&a, &&b| {
                findings[a]
                    .finding
                    .severity
                    .cmp(&findings[b].finding.severity)
            })
            .unwrap();

        for &idx in indices {
            if idx == primary_idx || to_remove.contains(&idx) {
                continue;
            }

            // Clone data from the secondary finding before mutating the primary
            let secondary_id = findings[idx].finding.id.clone();
            let secondary_desc = findings[idx].finding.description.clone();
            let secondary_category = findings[idx].finding.category;
            let secondary_os_events = findings[idx].finding.evidence.os_events.clone();
            let secondary_files = findings[idx].finding.evidence.files_modified.clone();
            let secondary_methods = findings[idx].detection_methods.clone();

            // Check if this is a cross-module correlation (different categories)
            let is_cross_module = findings[primary_idx].finding.category != secondary_category;

            // Merge the secondary finding into the primary
            findings[primary_idx].finding.description = format!(
                "{}\n\n--- Correlated from {} ---\n{}",
                findings[primary_idx].finding.description, secondary_id, secondary_desc
            );

            // Merge evidence
            for event in secondary_os_events {
                if !findings[primary_idx]
                    .finding
                    .evidence
                    .os_events
                    .contains(&event)
                {
                    findings[primary_idx].finding.evidence.os_events.push(event);
                }
            }
            for file in secondary_files {
                if !findings[primary_idx]
                    .finding
                    .evidence
                    .files_modified
                    .contains(&file)
                {
                    findings[primary_idx]
                        .finding
                        .evidence
                        .files_modified
                        .push(file);
                }
            }

            // Merge detection method badges
            for method in secondary_methods {
                if !findings[primary_idx].detection_methods.contains(&method) {
                    findings[primary_idx].detection_methods.push(method);
                }
            }

            // If cross-module correlation, escalate to Critical and add badge
            if is_cross_module && findings[primary_idx].finding.severity < Severity::Critical {
                findings[primary_idx].finding.severity = Severity::Critical;
                findings[primary_idx].finding.cvss = 9.5;
                findings[primary_idx].finding.title =
                    format!("[Correlated] {}", findings[primary_idx].finding.title);
                if !findings[primary_idx]
                    .detection_methods
                    .contains(&DetectionMethod::CrossModuleCorrelation)
                {
                    findings[primary_idx]
                        .detection_methods
                        .push(DetectionMethod::CrossModuleCorrelation);
                }
            }

            to_remove.push(idx);
        }
    }

    // Remove merged findings (in reverse order to preserve indices)
    to_remove.sort_unstable();
    to_remove.dedup();
    for idx in to_remove.into_iter().rev() {
        findings.remove(idx);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Evidence, ModuleCategory};

    fn make_enriched(
        id: &str,
        severity: Severity,
        category: ModuleCategory,
        files: Vec<&str>,
        method: DetectionMethod,
    ) -> EnrichedFinding {
        EnrichedFinding {
            finding: Finding {
                id: id.to_string(),
                title: format!("Finding {}", id),
                severity,
                cvss: 5.0,
                category,
                description: format!("Description for {}", id),
                reproduction: None,
                evidence: Evidence {
                    messages: Vec::new(),
                    audit_record: None,
                    canary_detected: false,
                    os_events: Vec::new(),
                    files_modified: files.into_iter().map(String::from).collect(),
                    network_connections: Vec::new(),
                    stderr_output: None,
                },
                remediation: "Fix it".to_string(),
            },
            detection_methods: vec![method],
            ai_analysis: None,
        }
    }

    #[test]
    fn test_cross_reference_merges_same_file() {
        let mut findings = vec![
            make_enriched(
                "YARA-001",
                Severity::High,
                ModuleCategory::SignatureDetection,
                vec!["/tmp/malware.bin"],
                DetectionMethod::YaraSignature,
            ),
            make_enriched(
                "PERSIST-001",
                Severity::Medium,
                ModuleCategory::Configuration,
                vec!["/tmp/malware.bin"],
                DetectionMethod::PersistenceEnum,
            ),
        ];

        cross_reference_findings(&mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding.severity, Severity::Critical);
        assert!(findings[0].finding.title.contains("Correlated"));
        assert!(findings[0].finding.description.contains("PERSIST-001"));
        // Should have all three badges
        assert!(findings[0]
            .detection_methods
            .contains(&DetectionMethod::YaraSignature));
        assert!(findings[0]
            .detection_methods
            .contains(&DetectionMethod::PersistenceEnum));
        assert!(findings[0]
            .detection_methods
            .contains(&DetectionMethod::CrossModuleCorrelation));
    }

    #[test]
    fn test_cross_reference_no_overlap() {
        let mut findings = vec![
            make_enriched(
                "YARA-001",
                Severity::High,
                ModuleCategory::SignatureDetection,
                vec!["/tmp/file_a.bin"],
                DetectionMethod::YaraSignature,
            ),
            make_enriched(
                "PERSIST-001",
                Severity::Medium,
                ModuleCategory::Configuration,
                vec!["/tmp/file_b.plist"],
                DetectionMethod::PersistenceEnum,
            ),
        ];

        cross_reference_findings(&mut findings);

        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_cross_reference_same_module_dedup() {
        let mut findings = vec![
            make_enriched(
                "PAT-001",
                Severity::High,
                ModuleCategory::SignatureDetection,
                vec!["/tmp/suspicious.sh"],
                DetectionMethod::PatternMatch,
            ),
            make_enriched(
                "PAT-002",
                Severity::Medium,
                ModuleCategory::SignatureDetection,
                vec!["/tmp/suspicious.sh"],
                DetectionMethod::PatternMatch,
            ),
        ];

        cross_reference_findings(&mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding.severity, Severity::High);
        // No cross-module badge since same category
        assert!(!findings[0]
            .detection_methods
            .contains(&DetectionMethod::CrossModuleCorrelation));
    }

    #[test]
    fn test_detection_engine_creation() {
        let engine = DetectionEngine::new();
        assert_eq!(engine.mode, ScanMode::Full);
    }

    #[test]
    fn test_detection_engine_with_mode() {
        let engine = DetectionEngine::with_mode(ScanMode::SignaturesOnly);
        assert_eq!(engine.mode, ScanMode::SignaturesOnly);
    }

    #[test]
    fn test_summary_from_findings() {
        let findings = vec![
            make_enriched(
                "A",
                Severity::Critical,
                ModuleCategory::SignatureDetection,
                vec![],
                DetectionMethod::YaraSignature,
            ),
            make_enriched(
                "B",
                Severity::High,
                ModuleCategory::SignatureDetection,
                vec![],
                DetectionMethod::YaraSignature,
            ),
            make_enriched(
                "C",
                Severity::Info,
                ModuleCategory::Configuration,
                vec![],
                DetectionMethod::ClamAv,
            ),
        ];
        let summary = DetectionSummary::from_findings(&findings);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 0);
        assert_eq!(summary.low, 0);
        assert_eq!(summary.info, 1);
        assert_eq!(summary.total, 3);
    }
}
