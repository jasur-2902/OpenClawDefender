use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};

use crate::finding::{Evidence, Finding, ModuleCategory, Severity};
use crate::modules::{ScanContext, ScanModule};

// ---------------------------------------------------------------------------
// Types — Browser Extensions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionInfo {
    pub browser: String,
    pub extension_id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub host_permissions: Vec<String>,
    pub content_scripts: Vec<String>,
    pub path: PathBuf,
    pub manifest_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionRisk {
    pub extension: ExtensionInfo,
    pub risk_level: Severity,
    pub reasons: Vec<String>,
}

// ---------------------------------------------------------------------------
// Types — Login Anomalies
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginEvent {
    pub username: String,
    pub tty: String,
    pub source: String,
    pub login_time: Option<DateTime<Utc>>,
    pub logout_time: Option<DateTime<Utc>>,
    pub event_type: LoginEventType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LoginEventType {
    Login,
    Logout,
    FailedLogin,
    SudoSuccess,
    SudoFailure,
}

impl std::fmt::Display for LoginEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginEventType::Login => write!(f, "Login"),
            LoginEventType::Logout => write!(f, "Logout"),
            LoginEventType::FailedLogin => write!(f, "Failed Login"),
            LoginEventType::SudoSuccess => write!(f, "Sudo Success"),
            LoginEventType::SudoFailure => write!(f, "Sudo Failure"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginAnomaly {
    pub anomaly_type: String,
    pub description: String,
    pub severity: Severity,
    pub events: Vec<LoginEvent>,
}

// ---------------------------------------------------------------------------
// Known-malicious extension IDs (from public threat reports)
// ---------------------------------------------------------------------------

const KNOWN_MALICIOUS_IDS: &[(&str, &str)] = &[
    ("efaidnbmnnnibpcajpcglclefindmkaj", "Fake PDF Viewer (info stealer)"),
    ("ogfjmhfpmojodcolpobfhiljdgbknmip", "The Great Suspender (malware variant)"),
    ("hgimnogjllphhhkhlmebbmlgjoejdpjl", "CryptoCurrency Clipboard Hijacker"),
    ("lmjegmlicamnimmfhcmpkclmigmmcbeh", "PDF Toolbox (data exfiltration)"),
    ("akdgnmcogleenhbclghgeepfnkhepknl", "Autoskip for YouTube (spyware)"),
    ("fnjhmkhhmkbjkkabndcnnogagogbneec", "ChromeLoader variant"),
    ("pkedcjkdefgpdelpbcmbmeomcjbeemfm", "SearchBlox (credential stealer)"),
    ("jiofmdifiilpiniahclmfdkllndjokdm", "FB Stealer / NullMixer"),
    ("gcalenpjmijhcaocmgehoacafinbailg", "VenomSoftX (crypto hijacker)"),
    ("oaikpkmjlabkfhcnoglnfinnfmcppacl", "Rilide Stealer variant"),
    ("aohghmighlieiainnegkcijnfilokake", "Fake Google Docs (phishing)"),
    ("bcocdbombenodlegijagbhdjnifohcde", "SpiderX (form data stealer)"),
    ("kpocjpoifmommoiiiamepombpeoaehfh", "CacheFlow malware"),
    ("bbedlkgobihcneffkggkaicbagmajhab", "Fake ChatGPT extension (credential theft)"),
    ("dgjidcncolhgebcmgpnggcldncilmdbp", "Internet Download Manager (fake adware)"),
    ("gpdjojdkbbmdfjfahjcgigfpmkopogic", "Flash Player mimic (malicious)"),
    ("mabloidgodmbnmnhoenmhdjhdioolkhi", "Dormant Colors (ad hijacker)"),
    ("nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask impersonator (phishing)"),
    ("cjpalhdlnbpafiamejdnhcphjbkeiagm", "Suspicious uBlock Origin fork"),
    ("eppiocemhmnlbhjplcgkofciiegomcon", "Copyfish OCR trojanized version"),
];

// ---------------------------------------------------------------------------
// Permission risk classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PermissionRisk {
    Low,
    Medium,
    High,
    Critical,
}

pub fn classify_permission(perm: &str) -> PermissionRisk {
    let p = perm.to_lowercase();
    // Critical
    if p == "<all_urls>"
        || p == "*://*/*"
        || p == "http://*/*"
        || p == "https://*/*"
        || p == "webrequestblocking"
        || p == "nativemessaging"
        || p == "debugger"
    {
        return PermissionRisk::Critical;
    }
    // High
    if p == "cookies"
        || p == "tabs"
        || p == "history"
        || p == "webrequest"
        || p == "clipboardread"
        || p == "management"
        || p == "proxy"
        || p == "privacy"
        || p == "webnavigation"
    {
        return PermissionRisk::High;
    }
    // Medium
    if p == "storage"
        || p == "activetab"
        || p == "notifications"
        || p == "bookmarks"
        || p == "downloads"
        || p == "identity"
        || p == "geolocation"
    {
        return PermissionRisk::Medium;
    }
    // Low
    PermissionRisk::Low
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

// ---------------------------------------------------------------------------
// Browser Extension Enumeration
// ---------------------------------------------------------------------------

fn browser_extension_paths() -> Vec<(String, Vec<PathBuf>)> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };

    let mut paths = vec![
        (
            "Chrome".into(),
            vec![
                home.join("Library/Application Support/Google/Chrome/Default/Extensions"),
                home.join("Library/Application Support/Google/Chrome/Profile 1/Extensions"),
                home.join("Library/Application Support/Google/Chrome/Profile 2/Extensions"),
            ],
        ),
        (
            "Brave".into(),
            vec![home.join(
                "Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions",
            )],
        ),
        (
            "Arc".into(),
            vec![home.join(
                "Library/Application Support/Arc/User Data/Default/Extensions",
            )],
        ),
        (
            "Edge".into(),
            vec![home.join(
                "Library/Application Support/Microsoft Edge/Default/Extensions",
            )],
        ),
        (
            "Safari".into(),
            vec![
                home.join("Library/Safari/Extensions"),
                home.join("Library/Containers/com.apple.Safari/Data/Library/Safari/AppExtensions"),
            ],
        ),
    ];

    // Firefox: find profile dirs dynamically
    let firefox_profiles = home.join("Library/Application Support/Firefox/Profiles");
    if let Ok(entries) = fs::read_dir(&firefox_profiles) {
        let mut firefox_dirs = Vec::new();
        for entry in entries.flatten() {
            let ext_dir = entry.path().join("extensions");
            if ext_dir.is_dir() {
                firefox_dirs.push(ext_dir);
            }
        }
        if !firefox_dirs.is_empty() {
            paths.push(("Firefox".into(), firefox_dirs));
        }
    }

    paths
}

fn enumerate_chromium_extensions(browser: &str, extensions_dir: &Path) -> Vec<ExtensionInfo> {
    let mut results = Vec::new();
    let entries = match fs::read_dir(extensions_dir) {
        Ok(e) => e,
        Err(_) => return results,
    };

    for ext_entry in entries.flatten() {
        let ext_path = ext_entry.path();
        if !ext_path.is_dir() {
            continue;
        }
        let extension_id = ext_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Inside each extension ID dir, there are version dirs
        let version_dirs = match fs::read_dir(&ext_path) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for ver_entry in version_dirs.flatten() {
            let ver_path = ver_entry.path();
            if !ver_path.is_dir() {
                continue;
            }
            let manifest_path = ver_path.join("manifest.json");
            if !manifest_path.exists() {
                continue;
            }
            if let Some(info) =
                parse_chromium_manifest(browser, &extension_id, &manifest_path, &ver_path)
            {
                results.push(info);
            }
        }
    }
    results
}

fn parse_chromium_manifest(
    browser: &str,
    extension_id: &str,
    manifest_path: &Path,
    ext_path: &Path,
) -> Option<ExtensionInfo> {
    let content = fs::read_to_string(manifest_path).ok()?;
    let manifest: serde_json::Value = serde_json::from_str(&content).ok()?;

    let name = manifest
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
        .to_string();
    let version = manifest
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0")
        .to_string();
    let description = manifest
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let manifest_version = manifest
        .get("manifest_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(2) as u32;

    // Permissions (MV2 and MV3)
    let permissions = extract_string_array(&manifest, "permissions");

    // Host permissions (MV3 separates these)
    let mut host_permissions = extract_string_array(&manifest, "host_permissions");
    // In MV2, host patterns are mixed in with permissions
    if manifest_version == 2 {
        let (hosts, _): (Vec<String>, Vec<String>) = permissions
            .iter()
            .cloned()
            .partition(|p| p.contains("://") || p == "<all_urls>");
        host_permissions.extend(hosts);
    }

    // Content scripts matched URLs
    let content_scripts = manifest
        .get("content_scripts")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|cs| cs.get("matches"))
                .filter_map(|m| m.as_array())
                .flat_map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)))
                .collect()
        })
        .unwrap_or_default();

    Some(ExtensionInfo {
        browser: browser.to_string(),
        extension_id: extension_id.to_string(),
        name,
        version,
        description,
        permissions,
        host_permissions,
        content_scripts,
        path: ext_path.to_path_buf(),
        manifest_version,
    })
}

fn enumerate_firefox_extensions(extensions_dir: &Path) -> Vec<ExtensionInfo> {
    let mut results = Vec::new();
    let entries = match fs::read_dir(extensions_dir) {
        Ok(e) => e,
        Err(_) => return results,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        // Firefox extensions can be directories with manifest.json or .xpi files (ZIP)
        if path.is_dir() {
            let manifest_path = path.join("manifest.json");
            if manifest_path.exists() {
                let ext_id = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if let Some(info) =
                    parse_chromium_manifest("Firefox", &ext_id, &manifest_path, &path)
                {
                    results.push(info);
                }
            }
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e == "xpi")
            .unwrap_or(false)
        {
            // .xpi is a ZIP — try to read manifest.json from inside
            if let Some(info) = parse_xpi_extension(&path) {
                results.push(info);
            }
        }
    }
    results
}

fn parse_xpi_extension(xpi_path: &Path) -> Option<ExtensionInfo> {
    let file = fs::File::open(xpi_path).ok()?;
    let mut archive = zip::ZipArchive::new(file).ok()?;
    let mut manifest_entry = archive.by_name("manifest.json").ok()?;
    let mut content = String::new();
    std::io::Read::read_to_string(&mut manifest_entry, &mut content).ok()?;

    let manifest: serde_json::Value = serde_json::from_str(&content).ok()?;

    let ext_id = xpi_path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let name = manifest
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
        .to_string();
    let version = manifest
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0")
        .to_string();
    let description = manifest
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let manifest_version = manifest
        .get("manifest_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(2) as u32;

    let permissions = extract_string_array(&manifest, "permissions");
    let host_permissions = extract_string_array(&manifest, "host_permissions");
    let content_scripts = manifest
        .get("content_scripts")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|cs| cs.get("matches"))
                .filter_map(|m| m.as_array())
                .flat_map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)))
                .collect()
        })
        .unwrap_or_default();

    Some(ExtensionInfo {
        browser: "Firefox".to_string(),
        extension_id: ext_id,
        name,
        version,
        description,
        permissions,
        host_permissions,
        content_scripts,
        path: xpi_path.to_path_buf(),
        manifest_version,
    })
}

fn enumerate_safari_extensions(safari_dir: &Path) -> Vec<ExtensionInfo> {
    let mut results = Vec::new();
    let entries = match fs::read_dir(safari_dir) {
        Ok(e) => e,
        Err(_) => return results,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Safari extensions are .appex bundles or .safariextz
        results.push(ExtensionInfo {
            browser: "Safari".to_string(),
            extension_id: name.clone(),
            name: name.clone(),
            version: "unknown".to_string(),
            description: String::new(),
            permissions: Vec::new(),
            host_permissions: Vec::new(),
            content_scripts: Vec::new(),
            path,
            manifest_version: 0,
        });
    }
    results
}

fn extract_string_array(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

pub fn enumerate_all_extensions() -> Vec<ExtensionInfo> {
    let mut all = Vec::new();

    for (browser, dirs) in browser_extension_paths() {
        for dir in &dirs {
            if !dir.exists() {
                continue;
            }
            match browser.as_str() {
                "Firefox" => {
                    all.extend(enumerate_firefox_extensions(dir));
                }
                "Safari" => {
                    all.extend(enumerate_safari_extensions(dir));
                }
                _ => {
                    // Chrome, Brave, Arc, Edge — all Chromium-based
                    all.extend(enumerate_chromium_extensions(&browser, dir));
                }
            }
        }
    }

    all
}

// ---------------------------------------------------------------------------
// Risk Analysis
// ---------------------------------------------------------------------------

pub fn assess_extension_risk(ext: &ExtensionInfo) -> ExtensionRisk {
    let mut reasons = Vec::new();
    let mut max_severity = Severity::Info;

    // Check against known-malicious IDs
    for (bad_id, threat_name) in KNOWN_MALICIOUS_IDS {
        if ext.extension_id == *bad_id {
            reasons.push(format!("Known malicious extension: {}", threat_name));
            max_severity = Severity::Critical;
        }
    }

    // Analyze permissions
    let all_perms: Vec<&str> = ext
        .permissions
        .iter()
        .chain(ext.host_permissions.iter())
        .map(|s| s.as_str())
        .collect();

    let mut has_all_urls = false;
    let mut has_cookies = false;
    let mut has_native_messaging = false;
    let mut has_webrequest_blocking = false;
    let mut critical_count = 0u32;
    let mut high_count = 0u32;

    for perm in &all_perms {
        let risk = classify_permission(perm);
        match risk {
            PermissionRisk::Critical => {
                critical_count += 1;
                let p = perm.to_lowercase();
                if p == "<all_urls>" || p == "*://*/*" || p.contains("://") {
                    has_all_urls = true;
                }
                if p == "nativemessaging" {
                    has_native_messaging = true;
                }
                if p == "webrequestblocking" {
                    has_webrequest_blocking = true;
                }
            }
            PermissionRisk::High => {
                high_count += 1;
                if perm.to_lowercase() == "cookies" {
                    has_cookies = true;
                }
            }
            _ => {}
        }
    }

    // Session hijacking capability: <all_urls> + cookies
    if has_all_urls && has_cookies {
        reasons.push("Has <all_urls> + cookies access — session hijacking capability".to_string());
        if max_severity < Severity::High {
            max_severity = Severity::High;
        }
    }

    // Native messaging can run arbitrary code
    if has_native_messaging {
        reasons
            .push("Uses nativeMessaging — can communicate with native applications".to_string());
        if max_severity < Severity::High {
            max_severity = Severity::High;
        }
    }

    // webRequestBlocking can intercept/modify all web traffic
    if has_webrequest_blocking {
        reasons.push("Uses webRequestBlocking — can intercept and modify web traffic".to_string());
        if max_severity < Severity::High {
            max_severity = Severity::High;
        }
    }

    // Broad host permissions with many high-risk permissions
    if has_all_urls && high_count >= 3 {
        reasons.push(format!(
            "Broad host access combined with {} high-risk permissions",
            high_count
        ));
        if max_severity < Severity::High {
            max_severity = Severity::High;
        }
    }

    // Critical permission count
    if critical_count >= 2 && max_severity < Severity::Medium {
        reasons.push(format!(
            "{} critical-level permissions requested",
            critical_count
        ));
        max_severity = Severity::Medium;
    }

    // Empty name or description is suspicious
    if ext.name.is_empty() || ext.name == "Unknown" || ext.name.starts_with("__MSG_") {
        // __MSG_ prefix means the name is a localization key, not necessarily suspicious by itself
        // but combined with other factors it can be
        if critical_count > 0 || high_count > 0 {
            reasons.push("Unresolved extension name with elevated permissions".to_string());
            if max_severity < Severity::Medium {
                max_severity = Severity::Medium;
            }
        }
    }

    if ext.description.is_empty() && (critical_count > 0 || high_count > 0) {
        reasons.push("No description provided with elevated permissions".to_string());
        if max_severity < Severity::Low {
            max_severity = Severity::Low;
        }
    }

    // MV2 extensions have weaker security model
    if ext.manifest_version == 2 && critical_count > 0 {
        reasons.push("Uses Manifest V2 with critical permissions (weaker security model)".to_string());
        if max_severity < Severity::Low {
            max_severity = Severity::Low;
        }
    }

    // If no issues found, mark as info
    if reasons.is_empty() {
        reasons.push("No significant permission risks detected".to_string());
    }

    ExtensionRisk {
        extension: ext.clone(),
        risk_level: max_severity,
        reasons,
    }
}

// ---------------------------------------------------------------------------
// Login History Parsing
// ---------------------------------------------------------------------------

pub fn parse_login_history() -> Vec<LoginEvent> {
    let output = match Command::new("last").args(["-50"]).output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut events = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("wtmp") || line.starts_with("reboot") {
            continue;
        }

        if let Some(event) = parse_last_line(line) {
            events.push(event);
        }
    }
    events
}

fn parse_last_line(line: &str) -> Option<LoginEvent> {
    // Format: "username  tty  source  Mon DD HH:MM - HH:MM (duration)"
    // or:     "username  tty  source  Mon DD HH:MM   still logged in"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    let username = parts[0].to_string();
    let tty = parts[1].to_string();

    // Determine if the third field is a source (hostname/IP) or part of the date
    // On macOS `last` output, console logins may not have a source field
    let (source, date_start) = if parts.len() >= 7
        && (parts[2].contains('.') || parts[2].contains(':') || parts[2] == "console")
    {
        (parts[2].to_string(), 3)
    } else {
        ("local".to_string(), 2)
    };

    // Try to parse login time from remaining fields
    // Typical: "Mon DD HH:MM" or "Mon  DD HH:MM"
    let login_time = if parts.len() > date_start + 2 {
        parse_last_timestamp(parts.get(date_start), parts.get(date_start + 1), parts.get(date_start + 2))
    } else {
        None
    };

    let still_logged_in = line.contains("still logged in");
    let logout_time = if still_logged_in {
        None
    } else {
        // Look for "- HH:MM" pattern after the login time
        let dash_pos = parts.iter().position(|&p| p == "-");
        if let Some(pos) = dash_pos {
            parts.get(pos + 1).and_then(|t| {
                // The logout time only has HH:MM, build full timestamp from login date
                login_time.map(|lt| {
                    let time_parts: Vec<&str> = t.split(':').collect();
                    if time_parts.len() == 2 {
                        if let (Ok(h), Ok(m)) = (time_parts[0].parse::<u32>(), time_parts[1].parse::<u32>()) {
                            return lt.date_naive().and_hms_opt(h, m, 0)
                                .map(|ndt| DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc))
                                .unwrap_or(lt);
                        }
                    }
                    lt
                })
            })
        } else {
            None
        }
    };

    Some(LoginEvent {
        username,
        tty,
        source,
        login_time,
        logout_time,
        event_type: LoginEventType::Login,
    })
}

fn parse_last_timestamp(
    month_or_day_of_week: Option<&&str>,
    day: Option<&&str>,
    time: Option<&&str>,
) -> Option<DateTime<Utc>> {
    let dow = (*month_or_day_of_week?).to_string();
    let day_str = *day?;
    let time_str = *time?;

    // macOS `last` uses: "Mon DD HH:MM" where Mon is abbreviated month name
    // e.g., "Fri Apr 11 09:15"
    let month_num = match dow.to_lowercase().as_str() {
        "jan" => 1, "feb" => 2, "mar" => 3, "apr" => 4,
        "may" => 5, "jun" => 6, "jul" => 7, "aug" => 8,
        "sep" => 9, "oct" => 10, "nov" => 11, "dec" => 12,
        // If it looks like a day of week (Mon, Tue, etc.), skip it
        _ => return None,
    };

    let day_num: u32 = day_str.parse().ok()?;
    let time_parts: Vec<&str> = time_str.split(':').collect();
    if time_parts.len() != 2 {
        return None;
    }
    let hour: u32 = time_parts[0].parse().ok()?;
    let minute: u32 = time_parts[1].parse().ok()?;

    let year = Utc::now().format("%Y").to_string().parse::<i32>().ok()?;
    let ndt = NaiveDateTime::new(
        chrono::NaiveDate::from_ymd_opt(year, month_num, day_num)?,
        chrono::NaiveTime::from_hms_opt(hour, minute, 0)?,
    );
    Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc))
}

pub fn parse_sudo_history() -> Vec<LoginEvent> {
    // Use macOS unified log to find sudo events
    let output = match Command::new("log")
        .args([
            "show",
            "--predicate",
            "process == \"sudo\"",
            "--last",
            "24h",
            "--style",
            "compact",
        ])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut events = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Sudo success: contains "COMMAND=" without "NOT allowed"
        // Sudo failure: contains "NOT allowed" or "authentication failure"
        let is_sudo_line = line.contains("sudo") || line.contains("COMMAND=");
        if !is_sudo_line {
            continue;
        }

        let event_type = if line.contains("NOT allowed")
            || line.contains("authentication failure")
            || line.contains("incorrect password")
        {
            LoginEventType::SudoFailure
        } else if line.contains("COMMAND=") {
            LoginEventType::SudoSuccess
        } else {
            continue;
        };

        // Extract username: look for "user=<name>" or "<name> :"
        let username = extract_sudo_username(line).unwrap_or_else(|| "unknown".to_string());

        events.push(LoginEvent {
            username,
            tty: String::new(),
            source: "sudo".to_string(),
            login_time: None,
            logout_time: None,
            event_type,
        });
    }
    events
}

fn extract_sudo_username(line: &str) -> Option<String> {
    // Pattern: "username : TTY=..." or "user=username"
    if let Some(pos) = line.find(" : TTY=") {
        let before = &line[..pos];
        return before.split_whitespace().last().map(String::from);
    }
    if let Some(pos) = line.find("user=") {
        let after = &line[pos + 5..];
        return after.split_whitespace().next().map(String::from);
    }
    None
}

// ---------------------------------------------------------------------------
// Login Anomaly Detection
// ---------------------------------------------------------------------------

pub fn detect_login_anomalies(
    login_events: &[LoginEvent],
    sudo_events: &[LoginEvent],
) -> Vec<LoginAnomaly> {
    let mut anomalies = Vec::new();

    // 1. Failed sudo spikes: >5 failures in the dataset
    let sudo_failures: Vec<&LoginEvent> = sudo_events
        .iter()
        .filter(|e| e.event_type == LoginEventType::SudoFailure)
        .collect();

    if sudo_failures.len() > 5 {
        anomalies.push(LoginAnomaly {
            anomaly_type: "sudo_failure_spike".to_string(),
            description: format!(
                "{} sudo failures detected in the last 24 hours — possible brute-force attempt",
                sudo_failures.len()
            ),
            severity: Severity::High,
            events: sudo_failures.iter().map(|e| (*e).clone()).collect(),
        });
    } else if !sudo_failures.is_empty() {
        anomalies.push(LoginAnomaly {
            anomaly_type: "sudo_failures".to_string(),
            description: format!(
                "{} sudo failure(s) detected in the last 24 hours",
                sudo_failures.len()
            ),
            severity: Severity::Medium,
            events: sudo_failures.iter().map(|e| (*e).clone()).collect(),
        });
    }

    // 2. SSH logins from non-local sources
    let ssh_logins: Vec<&LoginEvent> = login_events
        .iter()
        .filter(|e| {
            e.source != "local"
                && e.source != "console"
                && e.source != ""
                && e.event_type == LoginEventType::Login
        })
        .collect();

    if !ssh_logins.is_empty() {
        // Check for diverse source IPs
        let unique_sources: std::collections::HashSet<&str> =
            ssh_logins.iter().map(|e| e.source.as_str()).collect();
        if unique_sources.len() > 3 {
            anomalies.push(LoginAnomaly {
                anomaly_type: "diverse_ssh_sources".to_string(),
                description: format!(
                    "SSH logins from {} different sources detected",
                    unique_sources.len()
                ),
                severity: Severity::High,
                events: ssh_logins.iter().map(|e| (*e).clone()).collect(),
            });
        } else {
            anomalies.push(LoginAnomaly {
                anomaly_type: "remote_logins".to_string(),
                description: format!(
                    "{} remote login(s) detected from: {}",
                    ssh_logins.len(),
                    unique_sources
                        .iter()
                        .cloned()
                        .collect::<Vec<&str>>()
                        .join(", ")
                ),
                severity: Severity::Low,
                events: ssh_logins.iter().map(|e| (*e).clone()).collect(),
            });
        }
    }

    // 3. Concurrent sessions (multiple active logins for the same user)
    let active_sessions: Vec<&LoginEvent> = login_events
        .iter()
        .filter(|e| e.logout_time.is_none() && e.event_type == LoginEventType::Login)
        .collect();

    let mut user_session_counts: HashMap<&str, u32> = HashMap::new();
    for session in &active_sessions {
        *user_session_counts
            .entry(session.username.as_str())
            .or_insert(0) += 1;
    }

    for (user, count) in &user_session_counts {
        if *count > 3 {
            anomalies.push(LoginAnomaly {
                anomaly_type: "concurrent_sessions".to_string(),
                description: format!(
                    "User '{}' has {} concurrent active sessions",
                    user, count
                ),
                severity: Severity::Medium,
                events: active_sessions
                    .iter()
                    .filter(|e| e.username == *user)
                    .map(|e| (*e).clone())
                    .collect(),
            });
        }
    }

    // 4. Unusual login times (outside 6AM-11PM local)
    let unusual_time_logins: Vec<&LoginEvent> = login_events
        .iter()
        .filter(|e| {
            if let Some(ref lt) = e.login_time {
                let hour = lt.hour();
                hour < 6 || hour >= 23
            } else {
                false
            }
        })
        .collect();

    if !unusual_time_logins.is_empty() {
        anomalies.push(LoginAnomaly {
            anomaly_type: "unusual_login_time".to_string(),
            description: format!(
                "{} login(s) detected outside normal hours (11PM-6AM)",
                unusual_time_logins.len()
            ),
            severity: Severity::Low,
            events: unusual_time_logins.iter().map(|e| (*e).clone()).collect(),
        });
    }

    anomalies
}

// ---------------------------------------------------------------------------
// Convert to Findings
// ---------------------------------------------------------------------------

fn audit_browser_extensions() -> Vec<Finding> {
    let extensions = enumerate_all_extensions();
    let mut findings = Vec::new();
    let mut id_counter: u32 = 1;

    for ext in &extensions {
        let risk = assess_extension_risk(ext);
        // Only report Medium+ risks as findings (or Info for known-malicious)
        if risk.risk_level < Severity::Low {
            continue;
        }

        let prefix = risk.risk_level.finding_id_prefix();
        let id = format!("BROWEXT-{prefix}-{:03}", id_counter);
        id_counter += 1;

        let title = format!(
            "{} extension: {} ({})",
            ext.browser, ext.name, ext.extension_id
        );

        let perm_list = ext
            .permissions
            .iter()
            .chain(ext.host_permissions.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");

        let description = format!(
            "Browser extension risk assessment.\n\
             Browser: {}\n\
             Name: {}\n\
             ID: {}\n\
             Version: {}\n\
             Manifest Version: {}\n\
             Permissions: {}\n\
             Path: {}\n\
             Risk Reasons:\n{}",
            ext.browser,
            ext.name,
            ext.extension_id,
            ext.version,
            ext.manifest_version,
            if perm_list.is_empty() {
                "none".to_string()
            } else {
                perm_list
            },
            ext.path.display(),
            risk.reasons
                .iter()
                .map(|r| format!("  - {}", r))
                .collect::<Vec<_>>()
                .join("\n"),
        );

        let cvss = match risk.risk_level {
            Severity::Critical => 9.0,
            Severity::High => 7.0,
            Severity::Medium => 5.0,
            Severity::Low => 3.0,
            Severity::Info => 0.0,
        };

        let remediation = format!(
            "Review the '{}' extension in {}. {}",
            ext.name,
            ext.browser,
            if risk.risk_level >= Severity::High {
                "Consider removing this extension immediately due to high risk."
            } else {
                "Verify this extension is trusted and necessary."
            }
        );

        findings.push(Finding {
            id,
            title,
            severity: risk.risk_level,
            cvss,
            category: ModuleCategory::Configuration,
            description,
            reproduction: None,
            evidence: Evidence {
                messages: Vec::new(),
                audit_record: None,
                canary_detected: false,
                os_events: vec![format!("Extension found at {}", ext.path.display())],
                files_modified: vec![ext.path.display().to_string()],
                network_connections: Vec::new(),
                stderr_output: None,
            },
            remediation,
        });
    }
    findings
}

fn detect_login_issues() -> Vec<Finding> {
    let login_events = parse_login_history();
    let sudo_events = parse_sudo_history();
    let anomalies = detect_login_anomalies(&login_events, &sudo_events);

    let mut findings = Vec::new();
    let mut id_counter: u32 = 1;

    for anomaly in &anomalies {
        let prefix = anomaly.severity.finding_id_prefix();
        let id = format!("LOGIN-{prefix}-{:03}", id_counter);
        id_counter += 1;

        let cvss = match anomaly.severity {
            Severity::Critical => 9.0,
            Severity::High => 7.0,
            Severity::Medium => 5.0,
            Severity::Low => 3.0,
            Severity::Info => 0.0,
        };

        let event_details: Vec<String> = anomaly
            .events
            .iter()
            .take(10) // Cap at 10 events in the finding description
            .map(|e| {
                format!(
                    "  {} | {} | {} | {} | {}",
                    e.event_type,
                    e.username,
                    e.tty,
                    e.source,
                    e.login_time
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_else(|| "N/A".to_string()),
                )
            })
            .collect();

        let description = format!(
            "{}\n\nRelated events:\n{}",
            anomaly.description,
            event_details.join("\n"),
        );

        let remediation = match anomaly.anomaly_type.as_str() {
            "sudo_failure_spike" => {
                "Investigate repeated sudo failures. Check if an unauthorized user or process \
                 is attempting privilege escalation. Review /var/log/system.log for details."
                    .to_string()
            }
            "sudo_failures" => {
                "Review sudo failure events. Ensure they are from legitimate user activity \
                 and not unauthorized access attempts."
                    .to_string()
            }
            "diverse_ssh_sources" => {
                "Multiple SSH source IPs detected. Verify all remote access is authorized. \
                 Consider restricting SSH access with AllowUsers or IP allowlists in sshd_config."
                    .to_string()
            }
            "remote_logins" => {
                "Remote login detected. Verify the source IP is authorized. \
                 Ensure SSH is configured with key-based authentication."
                    .to_string()
            }
            "concurrent_sessions" => {
                "Multiple concurrent sessions detected for the same user. \
                 Verify all sessions are legitimate."
                    .to_string()
            }
            "unusual_login_time" => {
                "Login detected outside normal business hours (11PM-6AM). \
                 Verify this activity is expected."
                    .to_string()
            }
            _ => "Review the detected anomaly and investigate further.".to_string(),
        };

        findings.push(Finding {
            id,
            title: format!("Login Anomaly: {}", anomaly.anomaly_type),
            severity: anomaly.severity,
            cvss,
            category: ModuleCategory::Configuration,
            description,
            reproduction: None,
            evidence: Evidence {
                messages: Vec::new(),
                audit_record: None,
                canary_detected: false,
                os_events: vec![anomaly.description.clone()],
                files_modified: Vec::new(),
                network_connections: Vec::new(),
                stderr_output: None,
            },
            remediation,
        });
    }
    findings
}

// ---------------------------------------------------------------------------
// Public Audit API (for Tauri commands)
// ---------------------------------------------------------------------------

/// Run a full browser extension audit and return structured results.
pub async fn run_full_browser_audit() -> Result<(Vec<ExtensionRisk>, Vec<Finding>)> {
    let extensions = enumerate_all_extensions();
    let risks: Vec<ExtensionRisk> = extensions.iter().map(|e| assess_extension_risk(e)).collect();
    let findings = audit_browser_extensions();
    Ok((risks, findings))
}

/// Run login anomaly detection and return structured results.
pub async fn run_login_anomaly_detection() -> Result<(Vec<LoginAnomaly>, Vec<Finding>)> {
    let login_events = parse_login_history();
    let sudo_events = parse_sudo_history();
    let anomalies = detect_login_anomalies(&login_events, &sudo_events);
    let findings = detect_login_issues();
    Ok((anomalies, findings))
}

// ---------------------------------------------------------------------------
// ScanModule Implementation
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct BrowserAuditModule;

impl BrowserAuditModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ScanModule for BrowserAuditModule {
    fn name(&self) -> &str {
        "browser-audit"
    }

    fn description(&self) -> &str {
        "Browser extension security audit and login anomaly detection"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Configuration
    }

    async fn run(&self, _ctx: &mut ScanContext) -> Result<Vec<Finding>> {
        self.run_standalone().await
    }

    async fn run_standalone(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Part A: Browser extensions
        findings.extend(audit_browser_extensions());

        // Part B: Login anomalies
        findings.extend(detect_login_issues());

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
    fn test_classify_permission_critical() {
        assert_eq!(classify_permission("<all_urls>"), PermissionRisk::Critical);
        assert_eq!(classify_permission("*://*/*"), PermissionRisk::Critical);
        assert_eq!(
            classify_permission("webRequestBlocking"),
            PermissionRisk::Critical
        );
        assert_eq!(
            classify_permission("nativeMessaging"),
            PermissionRisk::Critical
        );
        assert_eq!(classify_permission("debugger"), PermissionRisk::Critical);
    }

    #[test]
    fn test_classify_permission_high() {
        assert_eq!(classify_permission("cookies"), PermissionRisk::High);
        assert_eq!(classify_permission("tabs"), PermissionRisk::High);
        assert_eq!(classify_permission("history"), PermissionRisk::High);
        assert_eq!(classify_permission("webRequest"), PermissionRisk::High);
        assert_eq!(classify_permission("clipboardRead"), PermissionRisk::High);
        assert_eq!(classify_permission("management"), PermissionRisk::High);
    }

    #[test]
    fn test_classify_permission_medium() {
        assert_eq!(classify_permission("storage"), PermissionRisk::Medium);
        assert_eq!(classify_permission("activeTab"), PermissionRisk::Medium);
        assert_eq!(classify_permission("notifications"), PermissionRisk::Medium);
        assert_eq!(classify_permission("bookmarks"), PermissionRisk::Medium);
    }

    #[test]
    fn test_classify_permission_low() {
        assert_eq!(classify_permission("contextMenus"), PermissionRisk::Low);
        assert_eq!(classify_permission("alarms"), PermissionRisk::Low);
        assert_eq!(classify_permission("idle"), PermissionRisk::Low);
        assert_eq!(
            classify_permission("someUnknownPerm"),
            PermissionRisk::Low
        );
    }

    #[test]
    fn test_classify_permission_case_insensitive() {
        assert_eq!(classify_permission("COOKIES"), PermissionRisk::High);
        assert_eq!(classify_permission("NativeMessaging"), PermissionRisk::Critical);
    }

    #[test]
    fn test_parse_chromium_manifest_basic() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("manifest.json");
        let manifest = serde_json::json!({
            "manifest_version": 3,
            "name": "Test Extension",
            "version": "1.2.3",
            "description": "A test extension",
            "permissions": ["storage", "tabs"],
            "host_permissions": ["https://example.com/*"],
            "content_scripts": [{
                "matches": ["https://example.com/*"],
                "js": ["content.js"]
            }]
        });
        std::fs::write(&manifest_path, manifest.to_string()).unwrap();

        let info =
            parse_chromium_manifest("Chrome", "test-id-123", &manifest_path, dir.path()).unwrap();
        assert_eq!(info.browser, "Chrome");
        assert_eq!(info.extension_id, "test-id-123");
        assert_eq!(info.name, "Test Extension");
        assert_eq!(info.version, "1.2.3");
        assert_eq!(info.manifest_version, 3);
        assert_eq!(info.permissions, vec!["storage", "tabs"]);
        assert_eq!(info.host_permissions, vec!["https://example.com/*"]);
        assert_eq!(info.content_scripts, vec!["https://example.com/*"]);
    }

    #[test]
    fn test_parse_chromium_manifest_mv2_host_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("manifest.json");
        let manifest = serde_json::json!({
            "manifest_version": 2,
            "name": "Legacy Extension",
            "version": "0.1",
            "permissions": ["tabs", "<all_urls>", "cookies"]
        });
        std::fs::write(&manifest_path, manifest.to_string()).unwrap();

        let info =
            parse_chromium_manifest("Chrome", "legacy-ext", &manifest_path, dir.path()).unwrap();
        assert_eq!(info.manifest_version, 2);
        // MV2: <all_urls> should also appear in host_permissions
        assert!(info.host_permissions.contains(&"<all_urls>".to_string()));
    }

    #[test]
    fn test_risk_assessment_known_malicious() {
        let ext = ExtensionInfo {
            browser: "Chrome".to_string(),
            extension_id: "efaidnbmnnnibpcajpcglclefindmkaj".to_string(),
            name: "Fake PDF Viewer".to_string(),
            version: "1.0".to_string(),
            description: "".to_string(),
            permissions: vec![],
            host_permissions: vec![],
            content_scripts: vec![],
            path: PathBuf::from("/tmp/test"),
            manifest_version: 3,
        };

        let risk = assess_extension_risk(&ext);
        assert_eq!(risk.risk_level, Severity::Critical);
        assert!(risk
            .reasons
            .iter()
            .any(|r| r.contains("Known malicious")));
    }

    #[test]
    fn test_risk_assessment_session_hijacking() {
        let ext = ExtensionInfo {
            browser: "Chrome".to_string(),
            extension_id: "some-extension".to_string(),
            name: "Suspicious Ext".to_string(),
            version: "1.0".to_string(),
            description: "Does things".to_string(),
            permissions: vec!["cookies".to_string()],
            host_permissions: vec!["<all_urls>".to_string()],
            content_scripts: vec![],
            path: PathBuf::from("/tmp/test"),
            manifest_version: 3,
        };

        let risk = assess_extension_risk(&ext);
        assert!(risk.risk_level >= Severity::High);
        assert!(risk
            .reasons
            .iter()
            .any(|r| r.contains("session hijacking")));
    }

    #[test]
    fn test_risk_assessment_native_messaging() {
        let ext = ExtensionInfo {
            browser: "Chrome".to_string(),
            extension_id: "native-ext".to_string(),
            name: "Native Bridge".to_string(),
            version: "2.0".to_string(),
            description: "Communicates with native app".to_string(),
            permissions: vec!["nativeMessaging".to_string()],
            host_permissions: vec![],
            content_scripts: vec![],
            path: PathBuf::from("/tmp/test"),
            manifest_version: 3,
        };

        let risk = assess_extension_risk(&ext);
        assert!(risk.risk_level >= Severity::High);
        assert!(risk
            .reasons
            .iter()
            .any(|r| r.contains("nativeMessaging")));
    }

    #[test]
    fn test_risk_assessment_safe_extension() {
        let ext = ExtensionInfo {
            browser: "Chrome".to_string(),
            extension_id: "safe-ext-123".to_string(),
            name: "Safe Extension".to_string(),
            version: "1.0".to_string(),
            description: "A perfectly safe extension".to_string(),
            permissions: vec!["storage".to_string(), "contextMenus".to_string()],
            host_permissions: vec![],
            content_scripts: vec![],
            path: PathBuf::from("/tmp/test"),
            manifest_version: 3,
        };

        let risk = assess_extension_risk(&ext);
        assert_eq!(risk.risk_level, Severity::Info);
    }

    #[test]
    fn test_detect_login_anomalies_sudo_spike() {
        let sudo_events: Vec<LoginEvent> = (0..8)
            .map(|_| LoginEvent {
                username: "attacker".to_string(),
                tty: String::new(),
                source: "sudo".to_string(),
                login_time: None,
                logout_time: None,
                event_type: LoginEventType::SudoFailure,
            })
            .collect();

        let anomalies = detect_login_anomalies(&[], &sudo_events);
        assert!(!anomalies.is_empty());
        let spike = anomalies
            .iter()
            .find(|a| a.anomaly_type == "sudo_failure_spike");
        assert!(spike.is_some());
        assert_eq!(spike.unwrap().severity, Severity::High);
    }

    #[test]
    fn test_detect_login_anomalies_concurrent_sessions() {
        let login_events: Vec<LoginEvent> = (0..5)
            .map(|i| LoginEvent {
                username: "testuser".to_string(),
                tty: format!("ttys{:03}", i),
                source: "console".to_string(),
                login_time: Some(Utc::now()),
                logout_time: None, // still logged in
                event_type: LoginEventType::Login,
            })
            .collect();

        let anomalies = detect_login_anomalies(&login_events, &[]);
        let concurrent = anomalies
            .iter()
            .find(|a| a.anomaly_type == "concurrent_sessions");
        assert!(concurrent.is_some());
    }

    #[test]
    fn test_detect_login_anomalies_unusual_time() {
        let login_events = vec![LoginEvent {
            username: "nightowl".to_string(),
            tty: "ttys001".to_string(),
            source: "console".to_string(),
            login_time: Some(
                DateTime::from_naive_utc_and_offset(
                    chrono::NaiveDate::from_ymd_opt(2026, 4, 11)
                        .unwrap()
                        .and_hms_opt(3, 30, 0)
                        .unwrap(),
                    Utc,
                ),
            ),
            logout_time: Some(Utc::now()),
            event_type: LoginEventType::Login,
        }];

        let anomalies = detect_login_anomalies(&login_events, &[]);
        let unusual = anomalies
            .iter()
            .find(|a| a.anomaly_type == "unusual_login_time");
        assert!(unusual.is_some());
    }

    #[test]
    fn test_detect_login_anomalies_no_issues() {
        let login_events = vec![LoginEvent {
            username: "normaluser".to_string(),
            tty: "console".to_string(),
            source: "console".to_string(),
            login_time: Some(
                DateTime::from_naive_utc_and_offset(
                    chrono::NaiveDate::from_ymd_opt(2026, 4, 11)
                        .unwrap()
                        .and_hms_opt(10, 0, 0)
                        .unwrap(),
                    Utc,
                ),
            ),
            logout_time: Some(Utc::now()),
            event_type: LoginEventType::Login,
        }];

        let anomalies = detect_login_anomalies(&login_events, &[]);
        // Should have no anomalies (normal time, no sudo failures, no concurrent sessions)
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_extract_sudo_username() {
        let line = "2026-04-11 10:00:00 testuser : TTY=ttys001 ; PWD=/Users/testuser ; COMMAND=/usr/bin/ls";
        assert_eq!(extract_sudo_username(line), Some("testuser".to_string()));

        let line2 = "auth failure user=badguy";
        assert_eq!(extract_sudo_username(line2), Some("badguy".to_string()));
    }

    #[test]
    fn test_extension_info_serialization() {
        let ext = ExtensionInfo {
            browser: "Chrome".to_string(),
            extension_id: "test-id".to_string(),
            name: "Test".to_string(),
            version: "1.0".to_string(),
            description: "desc".to_string(),
            permissions: vec!["tabs".to_string()],
            host_permissions: vec![],
            content_scripts: vec![],
            path: PathBuf::from("/tmp/test"),
            manifest_version: 3,
        };

        let json = serde_json::to_string(&ext).unwrap();
        let deserialized: ExtensionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.extension_id, "test-id");
        assert_eq!(deserialized.manifest_version, 3);
    }

    #[tokio::test]
    async fn test_browser_audit_module_interface() {
        let module = BrowserAuditModule::new();
        assert_eq!(module.name(), "browser-audit");
        assert_eq!(module.category(), ModuleCategory::Configuration);

        // run_standalone should not panic even if no browsers are installed
        let result = module.run_standalone().await;
        assert!(result.is_ok());
    }
}
