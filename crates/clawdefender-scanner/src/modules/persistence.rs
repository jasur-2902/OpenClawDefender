use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use async_trait::async_trait;

use crate::finding::{Evidence, Finding, ModuleCategory, Severity};
use crate::modules::{ScanContext, ScanModule};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PersistenceItem {
    pub path: PathBuf,
    pub item_type: PersistenceType,
    pub binary_path: Option<PathBuf>,
    pub signing_status: SigningStatus,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistenceType {
    LaunchAgent,
    LaunchDaemon,
    LoginItem,
    BrowserExtension,
    CronJob,
    ShellProfile,
    KernelExtension,
    SystemExtension,
    AuthorizationPlugin,
    DylibInjection,
}

impl std::fmt::Display for PersistenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersistenceType::LaunchAgent => write!(f, "Launch Agent"),
            PersistenceType::LaunchDaemon => write!(f, "Launch Daemon"),
            PersistenceType::LoginItem => write!(f, "Login Item"),
            PersistenceType::BrowserExtension => write!(f, "Browser Extension"),
            PersistenceType::CronJob => write!(f, "Cron Job"),
            PersistenceType::ShellProfile => write!(f, "Shell Profile"),
            PersistenceType::KernelExtension => write!(f, "Kernel Extension"),
            PersistenceType::SystemExtension => write!(f, "System Extension"),
            PersistenceType::AuthorizationPlugin => write!(f, "Authorization Plugin"),
            PersistenceType::DylibInjection => write!(f, "DYLD Injection"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningStatus {
    AppleSigned,
    ThirdPartySigned(String),
    AdHocSigned,
    Unsigned,
    Unknown,
}

impl std::fmt::Display for SigningStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningStatus::AppleSigned => write!(f, "Apple-signed"),
            SigningStatus::ThirdPartySigned(team) => write!(f, "Third-party signed ({})", team),
            SigningStatus::AdHocSigned => write!(f, "Ad-hoc signed"),
            SigningStatus::Unsigned => write!(f, "Unsigned"),
            SigningStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct PersistenceModule;

impl PersistenceModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ScanModule for PersistenceModule {
    fn name(&self) -> &str {
        "persistence-detection"
    }

    fn description(&self) -> &str {
        "Enumerates macOS persistence mechanisms (launch items, login items, browser extensions, cron jobs, shell profiles, kexts, authorization plugins, DYLD injection)"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Configuration
    }

    async fn run(&self, _ctx: &mut ScanContext) -> Result<Vec<Finding>> {
        self.run_standalone().await
    }

    async fn run_standalone(&self) -> Result<Vec<Finding>> {
        let items = enumerate_all_persistence();
        let findings = classify_and_report(&items);
        Ok(findings)
    }
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

fn enumerate_all_persistence() -> Vec<PersistenceItem> {
    let mut items = Vec::new();

    enumerate_launch_items(&mut items);
    enumerate_login_items(&mut items);
    enumerate_browser_extensions(&mut items);
    enumerate_cron_jobs(&mut items);
    enumerate_shell_profiles(&mut items);
    enumerate_kernel_extensions(&mut items);
    enumerate_system_extensions(&mut items);
    enumerate_authorization_plugins(&mut items);
    enumerate_dyld_injection(&mut items);

    items
}

// -- Launch Agents / Daemons ------------------------------------------------

fn enumerate_launch_items(items: &mut Vec<PersistenceItem>) {
    let mut dirs: Vec<(PathBuf, PersistenceType)> = vec![
        ("/Library/LaunchAgents".into(), PersistenceType::LaunchAgent),
        (
            "/Library/LaunchDaemons".into(),
            PersistenceType::LaunchDaemon,
        ),
    ];

    if let Some(home) = home_dir() {
        dirs.push((
            home.join("Library/LaunchAgents"),
            PersistenceType::LaunchAgent,
        ));
    }

    for (dir, ptype) in &dirs {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("plist") {
                continue;
            }
            let (binary, desc) = parse_plist_program(&path);
            let signing = binary
                .as_ref()
                .map(|b| check_codesign(b))
                .unwrap_or(SigningStatus::Unknown);

            items.push(PersistenceItem {
                path: path.clone(),
                item_type: ptype.clone(),
                binary_path: binary,
                signing_status: signing,
                description: desc,
            });
        }
    }
}

/// Parse a plist file to extract the `Program` or `ProgramArguments` key.
fn parse_plist_program(path: &Path) -> (Option<PathBuf>, String) {
    // Try the plist crate first for binary/xml plists
    if let Ok(val) = plist::from_file::<_, plist::Value>(path) {
        if let Some(dict) = val.as_dictionary() {
            // Program key (single string)
            if let Some(prog) = dict.get("Program").and_then(|v| v.as_string()) {
                return (Some(PathBuf::from(prog)), format!("Program: {}", prog));
            }
            // ProgramArguments key (array, first element is the binary)
            if let Some(args) = dict.get("ProgramArguments").and_then(|v| v.as_array()) {
                if let Some(first) = args.first().and_then(|v| v.as_string()) {
                    let display: Vec<String> = args
                        .iter()
                        .filter_map(|v| v.as_string().map(String::from))
                        .collect();
                    return (
                        Some(PathBuf::from(first)),
                        format!("ProgramArguments: {}", display.join(" ")),
                    );
                }
            }
            // Label for description
            if let Some(label) = dict.get("Label").and_then(|v| v.as_string()) {
                return (None, format!("Label: {}", label));
            }
        }
    }

    // Fallback: read as text and do simple string matching
    if let Ok(content) = fs::read_to_string(path) {
        if let Some(prog) = extract_xml_key_value(&content, "Program") {
            return (Some(PathBuf::from(&prog)), format!("Program: {}", prog));
        }
        if let Some(prog) = extract_program_arguments_first(&content) {
            return (
                Some(PathBuf::from(&prog)),
                format!("ProgramArguments[0]: {}", prog),
            );
        }
    }

    (None, format!("Plist at {}", path.display()))
}

fn extract_xml_key_value(content: &str, key: &str) -> Option<String> {
    let key_tag = format!("<key>{}</key>", key);
    let pos = content.find(&key_tag)?;
    let after = &content[pos + key_tag.len()..];
    let start = after.find("<string>")? + "<string>".len();
    let end = after[start..].find("</string>")?;
    Some(after[start..start + end].to_string())
}

fn extract_program_arguments_first(content: &str) -> Option<String> {
    let key_tag = "<key>ProgramArguments</key>";
    let pos = content.find(key_tag)?;
    let after = &content[pos + key_tag.len()..];
    // Find first <string> inside the <array>
    let start = after.find("<string>")? + "<string>".len();
    let end = after[start..].find("</string>")?;
    Some(after[start..start + end].to_string())
}

// -- Login Items ------------------------------------------------------------

fn enumerate_login_items(items: &mut Vec<PersistenceItem>) {
    if let Some(home) = home_dir() {
        let btm_path = home.join(
            "Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
        );
        if btm_path.exists() {
            items.push(PersistenceItem {
                path: btm_path.clone(),
                item_type: PersistenceType::LoginItem,
                binary_path: None,
                signing_status: SigningStatus::Unknown,
                description: "Background task management login items database".to_string(),
            });
        }
    }
}

// -- Browser Extensions -----------------------------------------------------

fn enumerate_browser_extensions(items: &mut Vec<PersistenceItem>) {
    let home = match home_dir() {
        Some(h) => h,
        None => return,
    };

    let extension_dirs = [
        (home.join("Library/Safari/Extensions"), "Safari"),
        (
            home.join("Library/Application Support/Google/Chrome/Default/Extensions"),
            "Chrome",
        ),
        (
            home.join("Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions"),
            "Brave",
        ),
        (
            home.join("Library/Application Support/Arc/User Data/Default/Extensions"),
            "Arc",
        ),
    ];

    for (dir, browser) in &extension_dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    items.push(PersistenceItem {
                        path: path.clone(),
                        item_type: PersistenceType::BrowserExtension,
                        binary_path: None,
                        signing_status: SigningStatus::Unknown,
                        description: format!(
                            "{} extension: {}",
                            browser,
                            path.file_name().unwrap_or_default().to_string_lossy()
                        ),
                    });
                }
            }
        }
    }

    // Firefox profiles: ~/Library/Application Support/Firefox/Profiles/*/extensions/
    let firefox_profiles = home.join("Library/Application Support/Firefox/Profiles");
    if let Ok(profiles) = fs::read_dir(&firefox_profiles) {
        for profile in profiles.flatten() {
            let ext_dir = profile.path().join("extensions");
            if let Ok(entries) = fs::read_dir(&ext_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    items.push(PersistenceItem {
                        path: path.clone(),
                        item_type: PersistenceType::BrowserExtension,
                        binary_path: None,
                        signing_status: SigningStatus::Unknown,
                        description: format!(
                            "Firefox extension: {}",
                            path.file_name().unwrap_or_default().to_string_lossy()
                        ),
                    });
                }
            }
        }
    }
}

// -- Cron Jobs --------------------------------------------------------------

fn enumerate_cron_jobs(items: &mut Vec<PersistenceItem>) {
    let output = match Command::new("crontab").arg("-l").output() {
        Ok(o) => o,
        Err(_) => return,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Extract the command portion (after the 5 schedule fields)
        let parts: Vec<&str> = line.splitn(6, char::is_whitespace).collect();
        let cmd = if parts.len() >= 6 { parts[5] } else { line };

        items.push(PersistenceItem {
            path: PathBuf::from("/var/at/tabs"),
            item_type: PersistenceType::CronJob,
            binary_path: cmd.split_whitespace().next().map(PathBuf::from),
            signing_status: SigningStatus::Unknown,
            description: format!("Cron entry: {}", line),
        });
    }
}

// -- Shell Profiles ---------------------------------------------------------

/// Patterns considered suspicious in shell profiles.
const SUSPICIOUS_SHELL_PATTERNS: &[&str] = &[
    "curl|bash",
    "curl|sh",
    "wget|bash",
    "wget|sh",
    "base64 --decode",
    "base64 -d",
    "base64 -D",
    "/tmp/.",
    "/var/tmp/.",
    "eval \"$(curl",
    "eval $(curl",
    "python -c",
    "python3 -c",
    "perl -e",
    "DYLD_INSERT_LIBRARIES",
];

fn enumerate_shell_profiles(items: &mut Vec<PersistenceItem>) {
    let home = match home_dir() {
        Some(h) => h,
        None => return,
    };

    let profiles = [
        ".zshrc",
        ".zprofile",
        ".zshenv",
        ".bashrc",
        ".bash_profile",
        ".profile",
    ];

    for name in &profiles {
        let path = home.join(name);
        if !path.exists() {
            continue;
        }

        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut suspicious_lines = Vec::new();
        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            for pattern in SUSPICIOUS_SHELL_PATTERNS {
                if trimmed.contains(pattern) {
                    suspicious_lines.push(format!("  Line {}: {}", i + 1, trimmed));
                    break;
                }
            }
        }

        if !suspicious_lines.is_empty() {
            items.push(PersistenceItem {
                path: path.clone(),
                item_type: PersistenceType::ShellProfile,
                binary_path: None,
                signing_status: SigningStatus::Unknown,
                description: format!(
                    "Suspicious entries in {}:\n{}",
                    name,
                    suspicious_lines.join("\n")
                ),
            });
        }
    }
}

// -- Kernel Extensions ------------------------------------------------------

fn enumerate_kernel_extensions(items: &mut Vec<PersistenceItem>) {
    let kext_dir = Path::new("/Library/Extensions");
    if let Ok(entries) = fs::read_dir(kext_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("kext") {
                let signing = check_codesign(&path);
                items.push(PersistenceItem {
                    path: path.clone(),
                    item_type: PersistenceType::KernelExtension,
                    binary_path: None,
                    signing_status: signing,
                    description: format!(
                        "Kernel extension: {}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ),
                });
            }
        }
    }
}

// -- System Extensions ------------------------------------------------------

fn enumerate_system_extensions(items: &mut Vec<PersistenceItem>) {
    let sysext_dir = Path::new("/Library/SystemExtensions");
    if let Ok(entries) = fs::read_dir(sysext_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() || path.is_file() {
                let signing = check_codesign(&path);
                items.push(PersistenceItem {
                    path: path.clone(),
                    item_type: PersistenceType::SystemExtension,
                    binary_path: None,
                    signing_status: signing,
                    description: format!(
                        "System extension: {}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ),
                });
            }
        }
    }
}

// -- Authorization Plugins --------------------------------------------------

fn enumerate_authorization_plugins(items: &mut Vec<PersistenceItem>) {
    let plugin_dir = Path::new("/Library/Security/SecurityAgentPlugins");
    if let Ok(entries) = fs::read_dir(plugin_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let signing = check_codesign(&path);
            items.push(PersistenceItem {
                path: path.clone(),
                item_type: PersistenceType::AuthorizationPlugin,
                binary_path: None,
                signing_status: signing,
                description: format!(
                    "Authorization plugin: {}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ),
            });
        }
    }
}

// -- DYLD Injection ---------------------------------------------------------

fn enumerate_dyld_injection(items: &mut Vec<PersistenceItem>) {
    // Check all launch plists for DYLD_INSERT_LIBRARIES in EnvironmentVariables
    let mut dirs: Vec<PathBuf> = vec![
        "/Library/LaunchAgents".into(),
        "/Library/LaunchDaemons".into(),
    ];
    if let Some(home) = home_dir() {
        dirs.push(home.join("Library/LaunchAgents"));
    }

    for dir in &dirs {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("plist") {
                continue;
            }
            if check_plist_for_dyld(&path) {
                items.push(PersistenceItem {
                    path: path.clone(),
                    item_type: PersistenceType::DylibInjection,
                    binary_path: None,
                    signing_status: SigningStatus::Unknown,
                    description: format!("DYLD_INSERT_LIBRARIES found in {}", path.display()),
                });
            }
        }
    }
}

fn check_plist_for_dyld(path: &Path) -> bool {
    // Try structured plist parse first
    if let Ok(val) = plist::from_file::<_, plist::Value>(path) {
        if let Some(dict) = val.as_dictionary() {
            if let Some(env) = dict
                .get("EnvironmentVariables")
                .and_then(|v| v.as_dictionary())
            {
                if env.contains_key("DYLD_INSERT_LIBRARIES") {
                    return true;
                }
            }
        }
    }
    // Fallback: text search
    if let Ok(content) = fs::read_to_string(path) {
        return content.contains("DYLD_INSERT_LIBRARIES");
    }
    false
}

// ---------------------------------------------------------------------------
// Code Signing
// ---------------------------------------------------------------------------

/// Known Apple system paths / prefixes
const APPLE_PATHS: &[&str] = &[
    "/usr/libexec/",
    "/usr/sbin/",
    "/usr/bin/",
    "/System/",
    "/sbin/",
    "/bin/",
];

fn check_codesign(binary: &Path) -> SigningStatus {
    // Quick check: if path starts with known Apple prefixes, assume Apple-signed
    let path_str = binary.to_string_lossy();
    for prefix in APPLE_PATHS {
        if path_str.starts_with(prefix) {
            return SigningStatus::AppleSigned;
        }
    }

    // Run `codesign -dvv` to get signing details
    let output = match Command::new("codesign").args(["-dvv", &path_str]).output() {
        Ok(o) => o,
        Err(_) => return SigningStatus::Unknown,
    };

    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        // codesign returns non-zero for unsigned binaries
        if stderr.contains("not signed") {
            return SigningStatus::Unsigned;
        }
        return SigningStatus::Unknown;
    }

    // Check for Apple signing
    if stderr.contains("Authority=Apple") || stderr.contains("Authority=Software Signing") {
        return SigningStatus::AppleSigned;
    }

    // Check for ad-hoc signing
    if stderr.contains("Signature=adhoc") {
        return SigningStatus::AdHocSigned;
    }

    // Extract team ID for third-party
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

// ---------------------------------------------------------------------------
// Classification & Reporting
// ---------------------------------------------------------------------------

fn classify_and_report(items: &[PersistenceItem]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut id_counter: u32 = 1;

    for item in items {
        let (severity, cvss) = classify_item(item);

        let prefix = severity.finding_id_prefix();
        let id = format!("PERSIST-{prefix}-{:03}", id_counter);
        id_counter += 1;

        let title = format!(
            "{}: {}",
            item.item_type,
            item.path.file_name().unwrap_or_default().to_string_lossy()
        );

        let description = format!(
            "Persistence item detected.\n\
             Type: {}\n\
             Path: {}\n\
             Binary: {}\n\
             Signing: {}\n\
             Details: {}",
            item.item_type,
            item.path.display(),
            item.binary_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "N/A".to_string()),
            item.signing_status,
            item.description,
        );

        let remediation = remediation_for(item);

        findings.push(Finding {
            id,
            title,
            severity,
            cvss,
            category: ModuleCategory::Configuration,
            description,
            reproduction: None,
            evidence: Evidence {
                messages: Vec::new(),
                audit_record: None,
                canary_detected: false,
                os_events: vec![format!("Persistence item at {}", item.path.display())],
                files_modified: vec![item.path.display().to_string()],
                network_connections: Vec::new(),
                stderr_output: None,
            },
            remediation,
        });
    }

    findings
}

fn classify_item(item: &PersistenceItem) -> (Severity, f64) {
    // DYLD injection is always high severity
    if item.item_type == PersistenceType::DylibInjection {
        return (Severity::High, 7.5);
    }

    // Unsigned items with hidden (dot-prefixed) filenames
    if item.signing_status == SigningStatus::Unsigned {
        let name = item.path.file_name().unwrap_or_default().to_string_lossy();
        if name.starts_with('.') {
            return (Severity::High, 7.5);
        }
    }

    // Items referencing binaries that do not exist
    if let Some(ref bin) = item.binary_path {
        if !bin.exists() {
            return (Severity::High, 7.0);
        }
    }

    // Unsigned items
    if item.signing_status == SigningStatus::Unsigned {
        return (Severity::Medium, 5.0);
    }

    // Ad-hoc signed items
    if item.signing_status == SigningStatus::AdHocSigned {
        return (Severity::Medium, 4.5);
    }

    // Suspicious shell profile entries
    if item.item_type == PersistenceType::ShellProfile {
        return (Severity::Medium, 5.0);
    }

    // Cron jobs are worth noting
    if item.item_type == PersistenceType::CronJob {
        return (Severity::Low, 3.0);
    }

    // Kernel extensions / auth plugins are notable
    if item.item_type == PersistenceType::KernelExtension
        || item.item_type == PersistenceType::AuthorizationPlugin
    {
        if item.signing_status == SigningStatus::AppleSigned {
            return (Severity::Info, 0.0);
        }
        return (Severity::Medium, 5.0);
    }

    // Normal third-party signed
    if let SigningStatus::ThirdPartySigned(_) = &item.signing_status {
        return (Severity::Info, 0.0);
    }

    // Apple-signed
    if item.signing_status == SigningStatus::AppleSigned {
        return (Severity::Info, 0.0);
    }

    // Default: Low for anything else (browser extensions, login items, etc.)
    (Severity::Low, 2.0)
}

fn remediation_for(item: &PersistenceItem) -> String {
    match item.item_type {
        PersistenceType::LaunchAgent | PersistenceType::LaunchDaemon => {
            format!(
                "Review the plist at {} and the binary it references. \
                 If unrecognized, unload with `launchctl unload '{}'` and remove the plist.",
                item.path.display(),
                item.path.display()
            )
        }
        PersistenceType::LoginItem => {
            "Review login items in System Settings > General > Login Items. \
             Remove any unrecognized entries."
                .to_string()
        }
        PersistenceType::BrowserExtension => {
            "Review installed browser extensions and remove any that are \
             unrecognized or no longer needed."
                .to_string()
        }
        PersistenceType::CronJob => {
            "Review cron jobs with `crontab -l`. Remove suspicious entries with `crontab -e`."
                .to_string()
        }
        PersistenceType::ShellProfile => {
            format!(
                "Review {} for suspicious additions. Remove any lines that \
                 download and execute remote code, decode base64 payloads, \
                 or reference hidden binaries.",
                item.path.display()
            )
        }
        PersistenceType::KernelExtension => {
            format!(
                "Review kernel extension at {}. Third-party kexts are deprecated \
                 on modern macOS. Remove if unrecognized.",
                item.path.display()
            )
        }
        PersistenceType::SystemExtension => {
            format!(
                "Review system extension at {}. Check System Settings > Privacy & Security \
                 > Extensions for approval status.",
                item.path.display()
            )
        }
        PersistenceType::AuthorizationPlugin => {
            format!(
                "Review authorization plugin at {}. Malicious auth plugins can intercept \
                 credentials. Remove if unrecognized.",
                item.path.display()
            )
        }
        PersistenceType::DylibInjection => {
            format!(
                "DYLD_INSERT_LIBRARIES found in {}. This is a known technique for \
                 injecting malicious code. Remove the environment variable entry from the plist.",
                item.path.display()
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_unsigned_hidden() {
        let item = PersistenceItem {
            path: PathBuf::from("/Library/LaunchAgents/.hidden.plist"),
            item_type: PersistenceType::LaunchAgent,
            binary_path: Some(PathBuf::from("/tmp/.malware")),
            signing_status: SigningStatus::Unsigned,
            description: "test".to_string(),
        };
        let (severity, _) = classify_item(&item);
        assert_eq!(severity, Severity::High);
    }

    #[test]
    fn test_classify_missing_binary() {
        let item = PersistenceItem {
            path: PathBuf::from("/Library/LaunchAgents/com.test.plist"),
            item_type: PersistenceType::LaunchAgent,
            binary_path: Some(PathBuf::from("/nonexistent/binary")),
            signing_status: SigningStatus::ThirdPartySigned("TEAM123".to_string()),
            description: "test".to_string(),
        };
        let (severity, _) = classify_item(&item);
        assert_eq!(severity, Severity::High);
    }

    #[test]
    fn test_classify_apple_signed() {
        let item = PersistenceItem {
            path: PathBuf::from("/Library/LaunchAgents/com.apple.something.plist"),
            item_type: PersistenceType::LaunchAgent,
            binary_path: Some(PathBuf::from("/usr/bin/true")), // exists on macOS
            signing_status: SigningStatus::AppleSigned,
            description: "test".to_string(),
        };
        let (severity, _) = classify_item(&item);
        assert_eq!(severity, Severity::Info);
    }

    #[test]
    fn test_classify_dyld_injection() {
        let item = PersistenceItem {
            path: PathBuf::from("/Library/LaunchAgents/com.evil.plist"),
            item_type: PersistenceType::DylibInjection,
            binary_path: None,
            signing_status: SigningStatus::Unknown,
            description: "DYLD_INSERT_LIBRARIES found".to_string(),
        };
        let (severity, _) = classify_item(&item);
        assert_eq!(severity, Severity::High);
    }

    #[test]
    fn test_classify_third_party_signed() {
        let item = PersistenceItem {
            path: PathBuf::from("/Library/LaunchAgents/com.vendor.agent.plist"),
            item_type: PersistenceType::LaunchAgent,
            // Use a path that exists on disk to avoid the "missing binary" rule
            binary_path: Some(PathBuf::from("/usr/bin/true")),
            signing_status: SigningStatus::ThirdPartySigned("ABCDEF1234".to_string()),
            description: "test".to_string(),
        };
        let (severity, _) = classify_item(&item);
        assert_eq!(severity, Severity::Info);
    }

    #[test]
    fn test_classify_cron_job() {
        let item = PersistenceItem {
            path: PathBuf::from("/var/at/tabs"),
            item_type: PersistenceType::CronJob,
            binary_path: Some(PathBuf::from("/usr/bin/true")),
            signing_status: SigningStatus::Unknown,
            description: "0 * * * * /usr/bin/true".to_string(),
        };
        let (severity, _) = classify_item(&item);
        assert_eq!(severity, Severity::Low);
    }

    #[test]
    fn test_classify_shell_profile() {
        let item = PersistenceItem {
            path: PathBuf::from("/Users/test/.zshrc"),
            item_type: PersistenceType::ShellProfile,
            binary_path: None,
            signing_status: SigningStatus::Unknown,
            description: "Suspicious entries in .zshrc".to_string(),
        };
        let (severity, _) = classify_item(&item);
        assert_eq!(severity, Severity::Medium);
    }

    #[test]
    fn test_persistence_type_display() {
        assert_eq!(PersistenceType::LaunchAgent.to_string(), "Launch Agent");
        assert_eq!(
            PersistenceType::DylibInjection.to_string(),
            "DYLD Injection"
        );
    }

    #[test]
    fn test_signing_status_display() {
        assert_eq!(SigningStatus::AppleSigned.to_string(), "Apple-signed");
        assert_eq!(
            SigningStatus::ThirdPartySigned("ABC".to_string()).to_string(),
            "Third-party signed (ABC)"
        );
        assert_eq!(SigningStatus::Unsigned.to_string(), "Unsigned");
    }

    #[test]
    fn test_extract_xml_key_value() {
        let content = r#"
        <dict>
            <key>Label</key>
            <string>com.example.test</string>
            <key>Program</key>
            <string>/usr/local/bin/test</string>
        </dict>"#;
        assert_eq!(
            extract_xml_key_value(content, "Program"),
            Some("/usr/local/bin/test".to_string())
        );
        assert_eq!(
            extract_xml_key_value(content, "Label"),
            Some("com.example.test".to_string())
        );
        assert_eq!(extract_xml_key_value(content, "Missing"), None);
    }

    #[test]
    fn test_extract_program_arguments_first() {
        let content = r#"
        <dict>
            <key>ProgramArguments</key>
            <array>
                <string>/usr/local/bin/test</string>
                <string>--flag</string>
            </array>
        </dict>"#;
        assert_eq!(
            extract_program_arguments_first(content),
            Some("/usr/local/bin/test".to_string())
        );
    }

    #[test]
    fn test_remediation_messages() {
        let item = PersistenceItem {
            path: PathBuf::from("/Library/LaunchAgents/com.test.plist"),
            item_type: PersistenceType::LaunchAgent,
            binary_path: None,
            signing_status: SigningStatus::Unknown,
            description: "test".to_string(),
        };
        let rem = remediation_for(&item);
        assert!(rem.contains("launchctl unload"));

        let item2 = PersistenceItem {
            path: PathBuf::from("/test"),
            item_type: PersistenceType::DylibInjection,
            binary_path: None,
            signing_status: SigningStatus::Unknown,
            description: "test".to_string(),
        };
        let rem2 = remediation_for(&item2);
        assert!(rem2.contains("DYLD_INSERT_LIBRARIES"));
    }
}
