//! TCC (Transparency, Consent, Control) permission auditor for macOS.
//!
//! Reads the macOS TCC database to enumerate granted permissions, then
//! classifies them by risk level and cross-references with code signing
//! to detect suspicious grants (e.g. unsigned apps with accessibility,
//! orphaned entries for apps that no longer exist, etc.).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::finding::{Evidence, Finding, ModuleCategory, Severity};
use crate::modules::{ScanContext, ScanModule};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TccEntry {
    pub service: String,
    pub client: String,
    pub client_type: i32, // 0 = bundle_id, 1 = absolute_path
    pub auth_value: i32,  // 0=denied, 1=unknown, 2=allowed, 3=limited
    pub last_modified: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TccAuditResult {
    pub entries: Vec<TccEntry>,
    pub findings: Vec<TccFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TccFinding {
    pub entry: TccEntry,
    pub risk: TccRisk,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TccRisk {
    CriticalPermission,
    HighPermission,
    OrphanedEntry,
    UnsignedWithCritical,
    UnusualCombination,
}

impl std::fmt::Display for TccRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TccRisk::CriticalPermission => write!(f, "Critical Permission"),
            TccRisk::HighPermission => write!(f, "High Permission"),
            TccRisk::OrphanedEntry => write!(f, "Orphaned Entry"),
            TccRisk::UnsignedWithCritical => write!(f, "Unsigned with Critical Permission"),
            TccRisk::UnusualCombination => write!(f, "Unusual Permission Combination"),
        }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CRITICAL_SERVICES: &[&str] = &[
    "kTCCServiceAccessibility",
    "kTCCServicePostEvent",
    "kTCCServiceScreenCapture",
    "kTCCServiceListenEvent",
];

const HIGH_SERVICES: &[&str] = &[
    "kTCCServiceCamera",
    "kTCCServiceMicrophone",
    "kTCCServiceSystemPolicyAllFiles",
];

const MEDIUM_SERVICES: &[&str] = &[
    "kTCCServiceAddressBook",
    "kTCCServiceCalendar",
    "kTCCServicePhotos",
    "kTCCServiceMediaLibrary",
    "kTCCServiceReminders",
    "kTCCServiceLocationServices",
];

/// Well-known apps that legitimately need accessibility permission.
const ACCESSIBILITY_ALLOWLIST: &[&str] = &[
    "com.apple.",
    "com.googlecode.iterm2",
    "com.microsoft.VSCode",
    "com.todesktop.230313mzl4w4u92",
    "com.github.atom",
    "org.mozilla.firefox",
    "com.google.Chrome",
    "com.brave.Browser",
    "com.1password.",
    "com.logi.",
    "com.logitech.",
    "com.parallels.",
    "com.vmware.",
    "org.virtualbox.",
    "com.crowdstrike.",
    "com.carbonblack.",
    "com.malwarebytes.",
    "com.objective-see.",
    "com.docker.",
    "com.jetbrains.",
    "net.kovidgoyal.kitty",
    "co.zeit.hyper",
    "dev.warp.Warp-Stable",
    "com.ragingmenace.MenuMeters",
    "com.knollsoft.Rectangle",
    "org.hammerspoon.Hammerspoon",
    "com.hegenberg.BetterTouchTool",
    "com.manytricks.Moom",
    "com.contextsformac.Contexts",
    "com.surteesstudios.Bartender",
    "com.bjango.istatmenus",
];

/// Apple paths / identifiers
const APPLE_PATHS: &[&str] = &[
    "/usr/libexec/",
    "/usr/sbin/",
    "/usr/bin/",
    "/System/",
    "/sbin/",
    "/bin/",
];

// ---------------------------------------------------------------------------
// TCC Database Reading
// ---------------------------------------------------------------------------

fn user_tcc_db_path() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join("Library/Application Support/com.apple.TCC/TCC.db"))
}

fn system_tcc_db_path() -> PathBuf {
    PathBuf::from("/Library/Application Support/com.apple.TCC/TCC.db")
}

fn read_tcc_database(path: &Path) -> Result<Vec<TccEntry>> {
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("Failed to open TCC database at {}", path.display()))?;

    let mut stmt = conn
        .prepare(
            "SELECT service, client, client_type, auth_value, auth_reason \
             FROM access WHERE auth_value = 2",
        )
        .context("Failed to prepare TCC query")?;

    let entries = stmt
        .query_map([], |row| {
            Ok(TccEntry {
                service: row.get(0)?,
                client: row.get(1)?,
                client_type: row.get(2)?,
                auth_value: row.get(3)?,
                last_modified: None,
            })
        })
        .context("Failed to execute TCC query")?
        .filter_map(|r| r.ok())
        .collect();

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Code Signing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum SigningStatus {
    AppleSigned,
    ThirdPartySigned(String),
    AdHocSigned,
    Unsigned,
    Unknown,
}

fn is_apple_client(client: &str) -> bool {
    client.starts_with("com.apple.") || client.starts_with("/System/") || client.starts_with("/usr/")
}

fn check_codesign(path: &Path) -> SigningStatus {
    let path_str = path.to_string_lossy();
    for prefix in APPLE_PATHS {
        if path_str.starts_with(prefix) {
            return SigningStatus::AppleSigned;
        }
    }

    let output = match Command::new("codesign")
        .args(["-dvv", &path_str])
        .output()
    {
        Ok(o) => o,
        Err(_) => return SigningStatus::Unknown,
    };

    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        if stderr.contains("not signed") {
            return SigningStatus::Unsigned;
        }
        return SigningStatus::Unknown;
    }

    if stderr.contains("Authority=Apple") || stderr.contains("Authority=Software Signing") {
        return SigningStatus::AppleSigned;
    }

    if stderr.contains("Signature=adhoc") {
        return SigningStatus::AdHocSigned;
    }

    for line in stderr.lines() {
        if let Some(team) = line.strip_prefix("TeamIdentifier=") {
            let team = team.trim();
            if team == "not set" {
                return SigningStatus::AdHocSigned;
            }
            return SigningStatus::ThirdPartySigned(team.to_string());
        }
    }

    SigningStatus::Unknown
}

/// Try to resolve a bundle ID to an on-disk app path.
fn resolve_bundle_id(bundle_id: &str) -> Option<PathBuf> {
    // Check common app directories
    let search_dirs = ["/Applications", "/System/Applications"];
    for dir in &search_dirs {
        let dir_path = Path::new(dir);
        if let Ok(entries) = std::fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("app") {
                    continue;
                }
                let info_plist = path.join("Contents/Info.plist");
                if let Ok(val) = plist::from_file::<_, plist::Value>(&info_plist) {
                    if let Some(dict) = val.as_dictionary() {
                        if let Some(bid) = dict.get("CFBundleIdentifier").and_then(|v| v.as_string())
                        {
                            if bid == bundle_id {
                                return Some(path);
                            }
                        }
                    }
                }
            }
        }
    }

    // Also check user Applications and ~/Applications
    if let Ok(home) = std::env::var("HOME") {
        let user_apps = PathBuf::from(&home).join("Applications");
        if let Ok(entries) = std::fs::read_dir(&user_apps) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("app") {
                    continue;
                }
                let info_plist = path.join("Contents/Info.plist");
                if let Ok(val) = plist::from_file::<_, plist::Value>(&info_plist) {
                    if let Some(dict) = val.as_dictionary() {
                        if let Some(bid) =
                            dict.get("CFBundleIdentifier").and_then(|v| v.as_string())
                        {
                            if bid == bundle_id {
                                return Some(path);
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Risk Classification
// ---------------------------------------------------------------------------

fn classify_service(service: &str) -> Severity {
    if CRITICAL_SERVICES.contains(&service) {
        Severity::Critical
    } else if HIGH_SERVICES.contains(&service) {
        Severity::High
    } else if MEDIUM_SERVICES.contains(&service) {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn is_in_unusual_location(path: &str) -> bool {
    let normal_prefixes = [
        "/Applications/",
        "/System/",
        "/usr/",
        "/bin/",
        "/sbin/",
        "/Library/",
    ];
    !normal_prefixes.iter().any(|p| path.starts_with(p))
}

fn is_cli_tool_or_script(path: &str) -> bool {
    let script_exts = [".sh", ".py", ".rb", ".pl", ".js"];
    if script_exts.iter().any(|ext| path.ends_with(ext)) {
        return true;
    }
    // Check if it's in a bin/sbin directory (command-line tool)
    if path.contains("/bin/") || path.contains("/sbin/") || path.contains("/libexec/") {
        return true;
    }
    false
}

fn is_allowlisted(client: &str) -> bool {
    ACCESSIBILITY_ALLOWLIST
        .iter()
        .any(|prefix| client.starts_with(prefix))
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

fn analyze_entries(entries: &[TccEntry]) -> Vec<TccFinding> {
    let mut findings = Vec::new();

    // Group entries by client for combination detection
    let mut client_services: std::collections::HashMap<String, Vec<&TccEntry>> =
        std::collections::HashMap::new();
    for entry in entries {
        client_services
            .entry(entry.client.clone())
            .or_default()
            .push(entry);
    }

    for entry in entries {
        // Skip Apple clients entirely
        if is_apple_client(&entry.client) {
            continue;
        }

        let base_severity = classify_service(&entry.service);

        // Check for orphaned entries
        let app_exists = if entry.client_type == 1 {
            // Absolute path
            Path::new(&entry.client).exists()
        } else {
            // Bundle ID — try to resolve
            resolve_bundle_id(&entry.client).is_some() || is_allowlisted(&entry.client)
        };

        if !app_exists && entry.client_type == 1 {
            findings.push(TccFinding {
                entry: entry.clone(),
                risk: TccRisk::OrphanedEntry,
                reason: format!(
                    "App '{}' has {} permission but no longer exists on disk. \
                     This may be a remnant from removed malware.",
                    entry.client,
                    friendly_service_name(&entry.service)
                ),
            });
            continue;
        }

        // Check signing status for path-based entries
        if entry.client_type == 1 {
            let signing = check_codesign(Path::new(&entry.client));
            let is_critical = CRITICAL_SERVICES.contains(&entry.service.as_str());
            let is_high = HIGH_SERVICES.contains(&entry.service.as_str());

            if (is_critical || is_high)
                && matches!(signing, SigningStatus::Unsigned | SigningStatus::AdHocSigned)
            {
                findings.push(TccFinding {
                    entry: entry.clone(),
                    risk: TccRisk::UnsignedWithCritical,
                    reason: format!(
                        "Unsigned/ad-hoc app '{}' has {} permission. \
                         Unsigned apps with sensitive permissions are a major red flag.",
                        entry.client,
                        friendly_service_name(&entry.service)
                    ),
                });
                continue;
            }
        }

        // CLI tool or script with critical permission
        if entry.client_type == 1 && is_cli_tool_or_script(&entry.client) {
            let is_critical = CRITICAL_SERVICES.contains(&entry.service.as_str());
            if is_critical {
                findings.push(TccFinding {
                    entry: entry.clone(),
                    risk: TccRisk::CriticalPermission,
                    reason: format!(
                        "Command-line tool/script '{}' has {} permission. \
                         Scripts with critical permissions can be easily weaponized.",
                        entry.client,
                        friendly_service_name(&entry.service)
                    ),
                });
                continue;
            }
        }

        // App in unusual location with critical/high permission
        if entry.client_type == 1 && is_in_unusual_location(&entry.client) {
            if base_severity <= Severity::High {
                findings.push(TccFinding {
                    entry: entry.clone(),
                    risk: TccRisk::CriticalPermission,
                    reason: format!(
                        "App '{}' is in an unusual location and has {} permission. \
                         Legitimate apps are typically installed in /Applications/.",
                        entry.client,
                        friendly_service_name(&entry.service)
                    ),
                });
                continue;
            }
        }

        // Non-allowlisted app with accessibility
        if entry.service == "kTCCServiceAccessibility" && !is_allowlisted(&entry.client) {
            findings.push(TccFinding {
                entry: entry.clone(),
                risk: TccRisk::CriticalPermission,
                reason: format!(
                    "'{}' has Accessibility permission (full UI control, keylogger capability). \
                     This app is not in the known-good allowlist.",
                    entry.client
                ),
            });
            continue;
        }

        // Critical/high permission for non-Apple apps
        if base_severity == Severity::Critical {
            findings.push(TccFinding {
                entry: entry.clone(),
                risk: TccRisk::CriticalPermission,
                reason: format!(
                    "'{}' has {} permission granted.",
                    entry.client,
                    friendly_service_name(&entry.service)
                ),
            });
        } else if base_severity == Severity::High {
            findings.push(TccFinding {
                entry: entry.clone(),
                risk: TccRisk::HighPermission,
                reason: format!(
                    "'{}' has {} permission granted.",
                    entry.client,
                    friendly_service_name(&entry.service)
                ),
            });
        }
    }

    // Detect unusual combinations: multiple critical permissions for same non-Apple client
    for (client, client_entries) in &client_services {
        if is_apple_client(client) {
            continue;
        }
        let critical_count = client_entries
            .iter()
            .filter(|e| CRITICAL_SERVICES.contains(&e.service.as_str()))
            .count();
        if critical_count >= 2 {
            // Use the first entry as representative
            if let Some(first) = client_entries.first() {
                let services: Vec<String> = client_entries
                    .iter()
                    .filter(|e| CRITICAL_SERVICES.contains(&e.service.as_str()))
                    .map(|e| friendly_service_name(&e.service))
                    .collect();
                findings.push(TccFinding {
                    entry: (*first).clone(),
                    risk: TccRisk::UnusualCombination,
                    reason: format!(
                        "'{}' has {} critical permissions: {}. \
                         Multiple critical permissions on one app significantly increases risk.",
                        client,
                        critical_count,
                        services.join(", ")
                    ),
                });
            }
        }
    }

    findings
}

fn friendly_service_name(service: &str) -> String {
    match service {
        "kTCCServiceAccessibility" => "Accessibility (UI control)".to_string(),
        "kTCCServicePostEvent" => "Synthetic Input (PostEvent)".to_string(),
        "kTCCServiceScreenCapture" => "Screen Capture".to_string(),
        "kTCCServiceListenEvent" => "Input Monitoring (ListenEvent)".to_string(),
        "kTCCServiceCamera" => "Camera".to_string(),
        "kTCCServiceMicrophone" => "Microphone".to_string(),
        "kTCCServiceSystemPolicyAllFiles" => "Full Disk Access".to_string(),
        "kTCCServiceAddressBook" => "Contacts".to_string(),
        "kTCCServiceCalendar" => "Calendar".to_string(),
        "kTCCServicePhotos" => "Photos".to_string(),
        "kTCCServiceMediaLibrary" => "Media Library".to_string(),
        "kTCCServiceReminders" => "Reminders".to_string(),
        "kTCCServiceLocationServices" => "Location Services".to_string(),
        other => other.strip_prefix("kTCCService").unwrap_or(other).to_string(),
    }
}

// ---------------------------------------------------------------------------
// Convert TccFindings -> scanner Findings
// ---------------------------------------------------------------------------

fn tcc_finding_to_finding(tf: &TccFinding, index: u32) -> Finding {
    let severity = match tf.risk {
        TccRisk::UnsignedWithCritical => Severity::Critical,
        TccRisk::CriticalPermission => Severity::High,
        TccRisk::OrphanedEntry => Severity::High,
        TccRisk::UnusualCombination => Severity::High,
        TccRisk::HighPermission => Severity::Medium,
    };

    let prefix = severity.finding_id_prefix();
    let id = format!("TCC-{prefix}-{:03}", index);

    let title = format!(
        "TCC: {} — {}",
        tf.risk,
        tf.entry
            .client
            .rsplit('/')
            .next()
            .unwrap_or(&tf.entry.client)
    );

    let description = format!(
        "{}\n\nService: {}\nClient: {}\nClient type: {}\nAuth value: {}",
        tf.reason,
        tf.entry.service,
        tf.entry.client,
        if tf.entry.client_type == 0 {
            "Bundle ID"
        } else {
            "Absolute Path"
        },
        tf.entry.auth_value,
    );

    let remediation = match tf.risk {
        TccRisk::OrphanedEntry => format!(
            "Remove the orphaned TCC entry for '{}'. \
             Open System Settings > Privacy & Security > {} and remove the entry, \
             or run: `tccutil reset {} {}`",
            tf.entry.client,
            friendly_service_name(&tf.entry.service),
            tf.entry.service,
            tf.entry.client,
        ),
        TccRisk::UnsignedWithCritical => format!(
            "URGENT: Unsigned app '{}' has {}. \
             Investigate immediately — this is a common indicator of malware. \
             Revoke in System Settings > Privacy & Security > {}.",
            tf.entry.client,
            friendly_service_name(&tf.entry.service),
            friendly_service_name(&tf.entry.service),
        ),
        TccRisk::CriticalPermission => format!(
            "Review whether '{}' truly needs {} permission. \
             If not recognized, revoke in System Settings > Privacy & Security > {}.",
            tf.entry.client,
            friendly_service_name(&tf.entry.service),
            friendly_service_name(&tf.entry.service),
        ),
        TccRisk::HighPermission => format!(
            "Verify that '{}' legitimately needs {} permission. \
             Revoke unnecessary permissions in System Settings > Privacy & Security.",
            tf.entry.client,
            friendly_service_name(&tf.entry.service),
        ),
        TccRisk::UnusualCombination => format!(
            "'{}' has multiple critical permissions. Review each grant individually \
             in System Settings > Privacy & Security and revoke any that are unnecessary.",
            tf.entry.client,
        ),
    };

    let cvss = match severity {
        Severity::Critical => 9.0,
        Severity::High => 7.0,
        Severity::Medium => 5.0,
        Severity::Low => 3.0,
        Severity::Info => 1.0,
    };

    Finding {
        id,
        title,
        severity,
        cvss,
        category: ModuleCategory::Configuration,
        description,
        reproduction: None,
        evidence: Evidence {
            messages: Vec::new(),
            audit_record: Some(format!(
                "TCC entry: service={}, client={}, auth_value={}",
                tf.entry.service, tf.entry.client, tf.entry.auth_value
            )),
            canary_detected: false,
            os_events: vec![format!(
                "TCC grant: {} -> {}",
                tf.entry.client, tf.entry.service
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

#[derive(Default)]
pub struct TccAuditModule;

impl TccAuditModule {
    pub fn new() -> Self {
        Self
    }

    /// Run the TCC audit and return both the raw result and scanner findings.
    pub async fn audit(&self) -> Result<(TccAuditResult, Vec<Finding>)> {
        let mut all_entries = Vec::new();

        // Read user TCC database
        if let Some(user_db) = user_tcc_db_path() {
            match read_tcc_database(&user_db) {
                Ok(entries) => {
                    info!("Read {} entries from user TCC database", entries.len());
                    all_entries.extend(entries);
                }
                Err(e) => {
                    debug!("Could not read user TCC database: {}", e);
                }
            }
        }

        // Optionally read system TCC database (needs root/FDA)
        let sys_db = system_tcc_db_path();
        if sys_db.exists() {
            match read_tcc_database(&sys_db) {
                Ok(entries) => {
                    info!("Read {} entries from system TCC database", entries.len());
                    all_entries.extend(entries);
                }
                Err(e) => {
                    debug!("Could not read system TCC database: {}", e);
                }
            }
        }

        let tcc_findings = analyze_entries(&all_entries);

        let mut findings: Vec<Finding> = Vec::new();
        let mut counter: u32 = 0;

        // If no entries could be read, produce an info-level finding
        if all_entries.is_empty() {
            findings.push(Finding {
                id: "TCC-INFO-001".to_string(),
                title: "TCC database not accessible".to_string(),
                severity: Severity::Info,
                cvss: 0.0,
                category: ModuleCategory::Configuration,
                description: "Could not read the TCC database. This usually means \
                    RookBot does not have Full Disk Access. Grant FDA in \
                    System Settings > Privacy & Security > Full Disk Access \
                    to enable TCC permission monitoring."
                    .to_string(),
                reproduction: None,
                evidence: Evidence::empty(),
                remediation: "Grant Full Disk Access to RookBot in \
                    System Settings > Privacy & Security > Full Disk Access."
                    .to_string(),
            });
        }

        for tf in &tcc_findings {
            counter += 1;
            findings.push(tcc_finding_to_finding(tf, counter));
        }

        let audit_result = TccAuditResult {
            entries: all_entries,
            findings: tcc_findings,
        };

        info!("TCC audit complete: {} finding(s)", findings.len());
        Ok((audit_result, findings))
    }
}

#[async_trait]
impl ScanModule for TccAuditModule {
    fn name(&self) -> &str {
        "tcc-audit"
    }

    fn description(&self) -> &str {
        "Audits macOS TCC permissions for suspicious grants"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Configuration
    }

    async fn run(&self, _ctx: &mut ScanContext) -> Result<Vec<Finding>> {
        self.run_standalone().await
    }

    async fn run_standalone(&self) -> Result<Vec<Finding>> {
        let (_audit_result, findings) = self.audit().await?;
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
    fn test_classify_critical_service() {
        assert_eq!(
            classify_service("kTCCServiceAccessibility"),
            Severity::Critical
        );
        assert_eq!(
            classify_service("kTCCServiceScreenCapture"),
            Severity::Critical
        );
        assert_eq!(
            classify_service("kTCCServicePostEvent"),
            Severity::Critical
        );
        assert_eq!(
            classify_service("kTCCServiceListenEvent"),
            Severity::Critical
        );
    }

    #[test]
    fn test_classify_high_service() {
        assert_eq!(classify_service("kTCCServiceCamera"), Severity::High);
        assert_eq!(classify_service("kTCCServiceMicrophone"), Severity::High);
        assert_eq!(
            classify_service("kTCCServiceSystemPolicyAllFiles"),
            Severity::High
        );
    }

    #[test]
    fn test_classify_medium_service() {
        assert_eq!(classify_service("kTCCServiceAddressBook"), Severity::Medium);
        assert_eq!(classify_service("kTCCServiceCalendar"), Severity::Medium);
        assert_eq!(classify_service("kTCCServicePhotos"), Severity::Medium);
    }

    #[test]
    fn test_classify_unknown_service() {
        assert_eq!(classify_service("kTCCServiceSomethingNew"), Severity::Low);
    }

    #[test]
    fn test_friendly_service_name() {
        assert_eq!(
            friendly_service_name("kTCCServiceAccessibility"),
            "Accessibility (UI control)"
        );
        assert_eq!(
            friendly_service_name("kTCCServiceCamera"),
            "Camera"
        );
        assert_eq!(
            friendly_service_name("kTCCServiceSystemPolicyAllFiles"),
            "Full Disk Access"
        );
        assert_eq!(
            friendly_service_name("kTCCServiceUnknownThing"),
            "UnknownThing"
        );
    }

    #[test]
    fn test_is_apple_client() {
        assert!(is_apple_client("com.apple.Safari"));
        assert!(is_apple_client("/System/Library/something"));
        assert!(is_apple_client("/usr/bin/something"));
        assert!(!is_apple_client("com.example.myapp"));
        assert!(!is_apple_client("/Applications/MyApp.app"));
    }

    #[test]
    fn test_is_in_unusual_location() {
        assert!(is_in_unusual_location("/tmp/evil"));
        assert!(is_in_unusual_location("/var/tmp/.hidden/app"));
        assert!(is_in_unusual_location("/Users/someone/Desktop/app"));
        assert!(!is_in_unusual_location("/Applications/Good.app"));
        assert!(!is_in_unusual_location("/System/Library/something"));
        assert!(!is_in_unusual_location("/usr/bin/tool"));
    }

    #[test]
    fn test_is_cli_tool_or_script() {
        assert!(is_cli_tool_or_script("/tmp/install.sh"));
        assert!(is_cli_tool_or_script("/usr/local/bin/tool"));
        assert!(is_cli_tool_or_script("/tmp/payload.py"));
        assert!(!is_cli_tool_or_script("/Applications/App.app"));
    }

    #[test]
    fn test_is_allowlisted() {
        assert!(is_allowlisted("com.apple.Terminal"));
        assert!(is_allowlisted("com.googlecode.iterm2"));
        assert!(is_allowlisted("com.microsoft.VSCode"));
        assert!(!is_allowlisted("com.evil.keylogger"));
    }

    #[test]
    fn test_analyze_orphaned_entry() {
        let entries = vec![TccEntry {
            service: "kTCCServiceAccessibility".to_string(),
            client: "/nonexistent/path/to/app".to_string(),
            client_type: 1,
            auth_value: 2,
            last_modified: None,
        }];

        let findings = analyze_entries(&entries);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].risk, TccRisk::OrphanedEntry);
    }

    #[test]
    fn test_analyze_apple_client_skipped() {
        let entries = vec![TccEntry {
            service: "kTCCServiceAccessibility".to_string(),
            client: "com.apple.Safari".to_string(),
            client_type: 0,
            auth_value: 2,
            last_modified: None,
        }];

        let findings = analyze_entries(&entries);
        assert!(findings.is_empty(), "Apple clients should be skipped");
    }

    #[test]
    fn test_analyze_critical_non_apple() {
        let entries = vec![TccEntry {
            service: "kTCCServiceScreenCapture".to_string(),
            client: "com.unknown.screengrabber".to_string(),
            client_type: 0,
            auth_value: 2,
            last_modified: None,
        }];

        let findings = analyze_entries(&entries);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].risk, TccRisk::CriticalPermission);
    }

    #[test]
    fn test_analyze_unusual_combination() {
        let entries = vec![
            TccEntry {
                service: "kTCCServiceAccessibility".to_string(),
                client: "com.suspicious.app".to_string(),
                client_type: 0,
                auth_value: 2,
                last_modified: None,
            },
            TccEntry {
                service: "kTCCServiceScreenCapture".to_string(),
                client: "com.suspicious.app".to_string(),
                client_type: 0,
                auth_value: 2,
                last_modified: None,
            },
        ];

        let findings = analyze_entries(&entries);
        let combo_finding = findings
            .iter()
            .find(|f| f.risk == TccRisk::UnusualCombination);
        assert!(
            combo_finding.is_some(),
            "Should detect unusual combination of critical permissions"
        );
    }

    #[test]
    fn test_tcc_finding_to_finding_produces_valid_finding() {
        let tf = TccFinding {
            entry: TccEntry {
                service: "kTCCServiceAccessibility".to_string(),
                client: "com.evil.keylogger".to_string(),
                client_type: 0,
                auth_value: 2,
                last_modified: None,
            },
            risk: TccRisk::CriticalPermission,
            reason: "Test critical permission".to_string(),
        };

        let finding = tcc_finding_to_finding(&tf, 1);
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.id.starts_with("TCC-"));
        assert!(finding.title.contains("TCC"));
        assert_eq!(finding.category, ModuleCategory::Configuration);
        assert!(!finding.remediation.is_empty());
    }

    #[test]
    fn test_unsigned_critical_severity() {
        let tf = TccFinding {
            entry: TccEntry {
                service: "kTCCServiceAccessibility".to_string(),
                client: "/tmp/evil".to_string(),
                client_type: 1,
                auth_value: 2,
                last_modified: None,
            },
            risk: TccRisk::UnsignedWithCritical,
            reason: "Unsigned with critical".to_string(),
        };

        let finding = tcc_finding_to_finding(&tf, 1);
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn test_module_trait_impl() {
        let module = TccAuditModule::new();
        assert_eq!(module.name(), "tcc-audit");
        assert_eq!(module.category(), ModuleCategory::Configuration);
        assert!(!module.description().is_empty());
    }

    #[test]
    fn test_tcc_risk_display() {
        assert_eq!(TccRisk::CriticalPermission.to_string(), "Critical Permission");
        assert_eq!(TccRisk::OrphanedEntry.to_string(), "Orphaned Entry");
        assert_eq!(
            TccRisk::UnsignedWithCritical.to_string(),
            "Unsigned with Critical Permission"
        );
    }

    #[test]
    fn test_high_permission_finding() {
        let entries = vec![TccEntry {
            service: "kTCCServiceCamera".to_string(),
            client: "com.unknown.recorder".to_string(),
            client_type: 0,
            auth_value: 2,
            last_modified: None,
        }];

        let findings = analyze_entries(&entries);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].risk, TccRisk::HighPermission);
    }

    #[test]
    fn test_unusual_location_detection() {
        let entries = vec![TccEntry {
            service: "kTCCServiceAccessibility".to_string(),
            client: "/tmp/.hidden/evil_app".to_string(),
            client_type: 1,
            auth_value: 2,
            last_modified: None,
        }];

        let findings = analyze_entries(&entries);
        assert!(!findings.is_empty());
        // Could be OrphanedEntry (doesn't exist) or CriticalPermission (unusual location)
        let has_relevant_finding = findings.iter().any(|f| {
            matches!(
                f.risk,
                TccRisk::OrphanedEntry | TccRisk::CriticalPermission | TccRisk::UnsignedWithCritical
            )
        });
        assert!(has_relevant_finding);
    }
}
