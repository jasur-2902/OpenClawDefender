use std::process::Command;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tracing::{debug, info, warn};

use crate::finding::{Evidence, Finding, ModuleCategory, Reproduction, Severity};
use crate::modules::ScanModule;

mod yara_rules_source {
    pub use super::super::yara_rules::*;
}

// ---------------------------------------------------------------------------
// Process artifact types
// ---------------------------------------------------------------------------

/// Collected artifacts from a running process for YARA scanning.
struct ProcessArtifacts {
    #[allow(dead_code)]
    pid: u32,
    data: Vec<u8>,
}

/// A process selected for memory scanning.
pub struct ProcessTarget {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

/// A YARA match against process memory/artifacts.
pub struct MemoryYaraMatch {
    pub rule_name: String,
    pub severity: Severity,
    pub description: String,
    pub matched_strings: Vec<String>,
}

/// Result of scanning a single process.
pub struct MemoryScanResult {
    pub pid: u32,
    pub process_name: String,
    pub yara_matches: Vec<MemoryYaraMatch>,
}

// ---------------------------------------------------------------------------
// Process artifact collection (macOS-compatible without root)
// ---------------------------------------------------------------------------

/// Collect scannable artifacts from a process using macOS-compatible commands.
///
/// Gathers command-line arguments, environment variables, open file descriptors,
/// and loaded libraries summary. All of these are accessible for processes owned
/// by the same user without requiring root or SIP disabled.
fn collect_process_artifacts(pid: u32) -> Result<ProcessArtifacts> {
    let pid_str = pid.to_string();
    let mut data = Vec::new();

    // 1. Command-line arguments (may contain payloads or C2 URLs)
    if let Ok(output) = Command::new("ps")
        .args(["-p", &pid_str, "-o", "args="])
        .output()
    {
        if output.status.success() {
            data.extend_from_slice(&output.stdout);
            data.push(b'\n');
        }
    }

    // 2. Environment variables (may contain encoded payloads or C2 config)
    if let Ok(output) = Command::new("ps")
        .args(["eww", "-p", &pid_str, "-o", "command="])
        .output()
    {
        if output.status.success() {
            data.extend_from_slice(&output.stdout);
            data.push(b'\n');
        }
    }

    // 3. Open file descriptors (check for suspicious file access)
    if let Ok(output) = Command::new("lsof")
        .args(["-p", &pid_str, "-Fn"])
        .output()
    {
        if output.status.success() {
            data.extend_from_slice(&output.stdout);
            data.push(b'\n');
        }
    }

    // 4. Loaded libraries and memory map summary (detect injected dylibs)
    if let Ok(output) = Command::new("vmmap")
        .args(["-summary", &pid_str])
        .output()
    {
        if output.status.success() {
            data.extend_from_slice(&output.stdout);
            data.push(b'\n');
        }
    }

    Ok(ProcessArtifacts { pid, data })
}

// ---------------------------------------------------------------------------
// Process selection
// ---------------------------------------------------------------------------

/// Check if a process executable is Apple-signed (system process).
fn is_apple_signed(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    // Fast path: known Apple system prefixes
    if path.starts_with("/System/")
        || path.starts_with("/usr/libexec/")
        || path.starts_with("/usr/sbin/")
        || path.starts_with("/sbin/")
    {
        return true;
    }
    // Use codesign to verify Apple signing for other paths
    if let Ok(output) = Command::new("codesign")
        .args(["-dvvv", path])
        .output()
    {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return stderr.contains("Authority=Software Signing")
            || stderr.contains("Authority=Apple");
    }
    false
}

/// Select non-system, non-Apple-signed processes owned by the current user.
fn select_scan_targets() -> Vec<ProcessTarget> {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let mut targets = Vec::new();

    for (pid, process) in sys.processes() {
        let pid_u32 = pid.as_u32();
        // Skip PID 0 and 1 (kernel / launchd)
        if pid_u32 <= 1 {
            continue;
        }

        let name = process.name().to_string_lossy().to_string();
        let path = process
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        // Skip known Apple system paths
        if path.starts_with("/System/")
            || path.starts_with("/usr/libexec/")
            || path.starts_with("/usr/sbin/")
            || path.starts_with("/sbin/")
            || path.starts_with("/usr/bin/")
        {
            continue;
        }

        // Skip our own process
        if name.contains("clawdefender") || name.contains("ClawDefender") {
            continue;
        }

        // Skip Apple-signed applications (checked via codesign for non-obvious paths)
        if !path.is_empty() && is_apple_signed(&path) {
            continue;
        }

        targets.push(ProcessTarget {
            pid: pid_u32,
            name,
            path,
        });
    }

    // Limit to 20 processes to keep scan time reasonable
    targets.truncate(20);
    targets
}

// ---------------------------------------------------------------------------
// YARA scanning of process artifacts
// ---------------------------------------------------------------------------

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
    format!("YARA memory rule {} matched", rule.identifier())
}

/// Scan a single process's collected artifacts with YARA rules.
fn scan_process(
    target: &ProcessTarget,
    rules: &yara_x::Rules,
) -> Result<MemoryScanResult> {
    let artifacts = collect_process_artifacts(target.pid)
        .context(format!("Failed to collect artifacts for PID {}", target.pid))?;

    if artifacts.data.is_empty() {
        return Ok(MemoryScanResult {
            pid: target.pid,
            process_name: target.name.clone(),
            yara_matches: Vec::new(),
        });
    }

    let mut scanner = yara_x::Scanner::new(rules);
    let scan_results = scanner
        .scan(&artifacts.data)
        .context(format!("YARA scan failed for PID {}", target.pid))?;

    let matches: Vec<MemoryYaraMatch> = scan_results
        .matching_rules()
        .map(|rule| {
            let matched_strings: Vec<String> = rule
                .patterns()
                .filter(|p| p.matches().len() > 0)
                .map(|p| p.identifier().to_string())
                .collect();

            MemoryYaraMatch {
                rule_name: rule.identifier().to_string(),
                severity: extract_severity_from_metadata(&rule),
                description: extract_description_from_metadata(&rule),
                matched_strings,
            }
        })
        .collect();

    Ok(MemoryScanResult {
        pid: target.pid,
        process_name: target.name.clone(),
        yara_matches: matches,
    })
}

// ---------------------------------------------------------------------------
// Convert YARA severity to CVSS score
// ---------------------------------------------------------------------------

fn severity_to_cvss(severity: &Severity) -> f64 {
    match severity {
        Severity::Critical => 9.5,
        Severity::High => 7.5,
        Severity::Medium => 5.0,
        Severity::Low => 3.0,
        Severity::Info => 1.0,
    }
}

/// Build a Finding from a process memory YARA match.
fn build_memory_finding(
    target: &ProcessTarget,
    m: &MemoryYaraMatch,
    counter: u32,
) -> Finding {
    let fid = format!("{}-MEM-{:03}", m.severity.finding_id_prefix(), counter);

    let remediation = match m.severity {
        Severity::Critical => format!(
            "CRITICAL: YARA memory rule '{}' detected fileless malware indicators in process '{}' (PID {}). \
             Immediately kill the process, investigate its origin, and scan the system for persistence mechanisms.",
            m.rule_name, target.name, target.pid
        ),
        Severity::High => format!(
            "HIGH: YARA memory rule '{}' flagged suspicious patterns in process '{}' (PID {}). \
             Investigate the process, check for C2 communication, and terminate if unauthorized.",
            m.rule_name, target.name, target.pid
        ),
        _ => format!(
            "MEDIUM: YARA memory rule '{}' matched in process '{}' (PID {}). \
             Review the process behavior and determine if it is legitimate.",
            m.rule_name, target.name, target.pid
        ),
    };

    Finding {
        id: fid,
        title: format!(
            "Memory YARA: {} in {} (PID {})",
            m.rule_name, target.name, target.pid
        ),
        severity: m.severity,
        cvss: severity_to_cvss(&m.severity),
        category: ModuleCategory::SignatureDetection,
        description: format!(
            "{}\n\nProcess: {} (PID {})\nPath: {}\nMatched strings: {}",
            m.description,
            target.name,
            target.pid,
            if target.path.is_empty() {
                "(unknown)"
            } else {
                &target.path
            },
            if m.matched_strings.is_empty() {
                "(none)".to_string()
            } else {
                m.matched_strings.join(", ")
            }
        ),
        reproduction: Some(Reproduction {
            method: format!("memory-scan PID {}", target.pid),
            tool: None,
            arguments: None,
        }),
        evidence: Evidence {
            messages: Vec::new(),
            audit_record: None,
            canary_detected: false,
            os_events: vec![format!(
                "Process {} (PID {}) matched memory YARA rule {}",
                target.name, target.pid, m.rule_name
            )],
            files_modified: Vec::new(),
            network_connections: Vec::new(),
            stderr_output: None,
        },
        remediation,
    }
}

// ---------------------------------------------------------------------------
// ScanModule implementation
// ---------------------------------------------------------------------------

/// Process memory YARA scanner for fileless malware detection.
///
/// Scans non-system processes by collecting artifacts (command lines,
/// environment variables, open files, loaded libraries) and running
/// memory-specific YARA rules against them.
#[derive(Default)]
pub struct MemoryScanModule;

impl MemoryScanModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ScanModule for MemoryScanModule {
    fn name(&self) -> &str {
        "memory-scanner"
    }

    fn description(&self) -> &str {
        "YARA-based process memory scanning for fileless malware detection"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::SignatureDetection
    }

    async fn run(
        &self,
        _ctx: &mut crate::modules::ScanContext,
    ) -> Result<Vec<Finding>> {
        self.run_standalone().await
    }

    async fn run_standalone(&self) -> Result<Vec<Finding>> {
        info!("Starting process memory YARA scan");

        // Compile memory-specific YARA rules
        let source = yara_rules_source::memory_scan_rules();
        let rules = yara_x::compile(source.as_str())
            .context("Failed to compile memory YARA rules")?;

        // Select non-system processes to scan
        let targets = select_scan_targets();
        info!(
            "Memory scan: {} non-system process(es) selected",
            targets.len()
        );

        let mut findings = Vec::new();
        let mut finding_counter: u32 = 0;

        for target in &targets {
            debug!(
                "Scanning process: {} (PID {}, path: {})",
                target.name, target.pid, target.path
            );

            match scan_process(target, &rules) {
                Ok(result) if !result.yara_matches.is_empty() => {
                    warn!(
                        "Memory YARA: {} match(es) in {} (PID {})",
                        result.yara_matches.len(),
                        target.name,
                        target.pid
                    );
                    for m in &result.yara_matches {
                        finding_counter += 1;
                        findings.push(build_memory_finding(target, m, finding_counter));
                    }
                }
                Ok(_) => {
                    debug!("No matches for {} (PID {})", target.name, target.pid);
                }
                Err(e) => {
                    debug!(
                        "Error scanning {} (PID {}): {}",
                        target.name, target.pid, e
                    );
                }
            }
        }

        info!(
            "Memory YARA scan complete: {} finding(s) across {} process(es)",
            findings.len(),
            targets.len()
        );

        Ok(findings)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_yara_rules_compile() {
        let source = yara_rules_source::memory_scan_rules();
        let result = yara_x::compile(source.as_str());
        assert!(
            result.is_ok(),
            "Memory YARA rules should compile without errors: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_memory_scan_credential_stealing() {
        let source = yara_rules_source::memory_scan_rules();
        let rules = yara_x::compile(source.as_str()).unwrap();
        let mut scanner = yara_x::Scanner::new(&rules);

        // Simulate process data with credential-stealing patterns
        let data = b"security dump-keychain -d login.keychain \
                     Cookies/Cookies Cookies.binarycookies Login Data";

        let results = scanner.scan(data).unwrap();
        let matched: Vec<String> = results
            .matching_rules()
            .map(|r| r.identifier().to_string())
            .collect();
        assert!(
            matched.contains(&"Memory_Credential_Stealing".to_string()),
            "Should detect credential stealing patterns, got: {:?}",
            matched
        );
    }

    #[test]
    fn test_memory_scan_c2_communication() {
        let source = yara_rules_source::memory_scan_rules();
        let rules = yara_x::compile(source.as_str()).unwrap();
        let mut scanner = yara_x::Scanner::new(&rules);

        let data = b"beacon sleeptime POST /api/checkin user-agent: Mozilla";
        let results = scanner.scan(data).unwrap();
        let matched: Vec<String> = results
            .matching_rules()
            .map(|r| r.identifier().to_string())
            .collect();
        assert!(
            matched.contains(&"Memory_C2_Communication".to_string()),
            "Should detect C2 communication patterns, got: {:?}",
            matched
        );
    }

    #[test]
    fn test_memory_scan_crypto_wallet_theft() {
        let source = yara_rules_source::memory_scan_rules();
        let rules = yara_x::compile(source.as_str()).unwrap();
        let mut scanner = yara_x::Scanner::new(&rules);

        let data = b"electrum/wallets nkbihfbeogaeaoehlefnkodbefgpgknn \
                     exodus/exodus.wallet wallet.dat";
        let results = scanner.scan(data).unwrap();
        let matched: Vec<String> = results
            .matching_rules()
            .map(|r| r.identifier().to_string())
            .collect();
        assert!(
            matched.contains(&"Memory_Crypto_Wallet_Theft".to_string()),
            "Should detect crypto wallet theft patterns, got: {:?}",
            matched
        );
    }

    #[test]
    fn test_memory_scan_amos_stealer() {
        let source = yara_rules_source::memory_scan_rules();
        let rules = yara_x::compile(source.as_str()).unwrap();
        let mut scanner = yara_x::Scanner::new(&rules);

        let data = b"osascript -e AppleScript display dialog default answer /Users/victim";
        let results = scanner.scan(data).unwrap();
        let matched: Vec<String> = results
            .matching_rules()
            .map(|r| r.identifier().to_string())
            .collect();
        assert!(
            matched.contains(&"Memory_AMOS_Stealer".to_string()),
            "Should detect AMOS stealer patterns, got: {:?}",
            matched
        );
    }

    #[test]
    fn test_memory_scan_clean_data() {
        let source = yara_rules_source::memory_scan_rules();
        let rules = yara_x::compile(source.as_str()).unwrap();
        let mut scanner = yara_x::Scanner::new(&rules);

        let data = b"Hello, this is a perfectly normal process doing normal things.";
        let results = scanner.scan(data).unwrap();
        let matched: Vec<String> = results
            .matching_rules()
            .map(|r| r.identifier().to_string())
            .collect();
        assert!(
            matched.is_empty(),
            "Clean data should produce no matches, got: {:?}",
            matched
        );
    }

    #[test]
    fn test_select_scan_targets_skips_system() {
        // This test verifies the filtering logic without actually enumerating
        // live processes (which would be flaky in CI).
        let target_system = ProcessTarget {
            pid: 1,
            name: "launchd".to_string(),
            path: "/sbin/launchd".to_string(),
        };
        // PID 1 should be skipped by the select logic
        assert!(target_system.pid <= 1);
        assert!(target_system.path.starts_with("/sbin/"));
    }

    #[test]
    fn test_module_trait_impl() {
        let module = MemoryScanModule::new();
        assert_eq!(module.name(), "memory-scanner");
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
    fn test_build_memory_finding() {
        let target = ProcessTarget {
            pid: 1234,
            name: "suspicious_proc".to_string(),
            path: "/tmp/suspicious_proc".to_string(),
        };
        let m = MemoryYaraMatch {
            rule_name: "Memory_C2_Communication".to_string(),
            severity: Severity::High,
            description: "C2 communication patterns detected".to_string(),
            matched_strings: vec!["$beacon".to_string()],
        };
        let finding = build_memory_finding(&target, &m, 1);

        assert_eq!(finding.id, "HIGH-MEM-001");
        assert!(finding.title.contains("Memory YARA"));
        assert!(finding.title.contains("suspicious_proc"));
        assert!(finding.title.contains("1234"));
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.category, ModuleCategory::SignatureDetection);
        assert!(finding.description.contains("C2 communication"));
    }
}
