//! CIS macOS Benchmark compliance checker.
//!
//! Maps macOS hardening checks to specific CIS Benchmark control IDs,
//! calculates a weighted compliance score, and provides remediation commands.
//! Complements the `pattern_detection` module by covering CIS controls
//! not already checked there.

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::finding::{calculate_cvss, CvssVector, Evidence, Finding, ModuleCategory, Severity};
use crate::modules::{ScanContext, ScanModule};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisCheckResult {
    pub cis_id: String,
    pub title: String,
    pub category: String,
    pub expected: String,
    pub actual: String,
    pub passed: bool,
    pub severity: Severity,
    pub remediation: String,
    pub cis_level: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub checks: Vec<CisCheckResult>,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub score: f64,
    pub critical_failures: usize,
}

// ---------------------------------------------------------------------------
// Command runner
// ---------------------------------------------------------------------------

/// Run a command and return its stdout, trimmed. Returns `None` on failure.
fn run_check(cmd: &str, args: &[&str]) -> Option<String> {
    let result = Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    let child = match result {
        Ok(c) => c,
        Err(e) => {
            debug!(cmd, ?args, %e, "CIS check: failed to spawn command");
            return None;
        }
    };

    match child.wait_with_output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            // Return stdout if non-empty, otherwise stderr for error info
            if !stdout.is_empty() {
                Some(stdout)
            } else if !stderr.is_empty() {
                Some(stderr)
            } else {
                Some(String::new())
            }
        }
        Err(e) => {
            debug!(cmd, ?args, %e, "CIS check: command wait failed");
            None
        }
    }
}

/// Build a CisCheckResult for a check that could not be executed.
fn check_not_executable(
    cis_id: &str,
    title: &str,
    category: &str,
    cis_level: u8,
) -> CisCheckResult {
    CisCheckResult {
        cis_id: cis_id.to_string(),
        title: title.to_string(),
        category: category.to_string(),
        expected: "N/A".to_string(),
        actual: "Check could not be executed".to_string(),
        passed: false,
        severity: Severity::Info,
        remediation: "Run RookBot with appropriate permissions to complete this check.".to_string(),
        cis_level,
    }
}

// ---------------------------------------------------------------------------
// Individual CIS checks
// ---------------------------------------------------------------------------
// NOTE: We skip checks already well-covered by pattern_detection.rs:
//   - SIP (csrutil status) -> integrity-sip-disabled
//   - Gatekeeper (spctl --status) -> integrity-gatekeeper-disabled
//   - Firewall enabled (ALF globalstate) -> integrity-firewall-disabled
//   - FileVault (fdesetup status) -> integrity-filevault-disabled
//   - Remote Login/SSH -> integrity-remote-login
//   - Auto-login -> config-admin-autologin
//   - Guest account enabled -> config-guest-account
//   - Internet sharing -> config-internet-sharing
//
// We DO include CIS checks that add new value or provide structured
// CIS compliance mapping even if they partially overlap, since the
// compliance report needs completeness for scoring.

/// 1.1 - Check for available software updates.
fn check_software_updates() -> CisCheckResult {
    let cis_id = "1.1";
    let title = "Ensure All Apple-provided Software Is Current";
    let category = "Software Updates";

    match run_check("softwareupdate", &["-l"]) {
        Some(output) => {
            let no_updates = output.contains("No new software available");
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "No new software available".to_string(),
                actual: if no_updates {
                    "No new software available".to_string()
                } else {
                    "Software updates are available".to_string()
                },
                passed: no_updates,
                severity: Severity::Medium,
                remediation: "Run: softwareupdate --install --all".to_string(),
                cis_level: 1,
            }
        }
        None => check_not_executable(cis_id, title, category, 1),
    }
}

/// 2.1.1 - Bluetooth powered off when not in use.
fn check_bluetooth_powered() -> CisCheckResult {
    let cis_id = "2.1.1";
    let title = "Ensure Bluetooth Is Disabled If No Devices Are Paired";
    let category = "Wireless";

    match run_check(
        "defaults",
        &[
            "read",
            "/Library/Preferences/com.apple.Bluetooth",
            "ControllerPowerState",
        ],
    ) {
        Some(output) => {
            let is_off = output.trim() == "0";
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "0 (Off)".to_string(),
                actual: format!("{} ({})", output.trim(), if is_off { "Off" } else { "On" }),
                passed: is_off,
                severity: Severity::Low,
                remediation: "System Settings > Bluetooth > Turn Bluetooth Off".to_string(),
                cis_level: 1,
            }
        }
        None => check_not_executable(cis_id, title, category, 1),
    }
}

/// 2.4.1 - Remote Apple Events disabled.
fn check_remote_apple_events() -> CisCheckResult {
    let cis_id = "2.4.1";
    let title = "Ensure Remote Apple Events Is Disabled";
    let category = "Sharing Services";

    match run_check("systemsetup", &["-getremoteappleevents"]) {
        Some(output) => {
            let is_off = output.contains("Off");
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "Off".to_string(),
                actual: if is_off {
                    "Off".to_string()
                } else {
                    "On".to_string()
                },
                passed: is_off,
                severity: Severity::Medium,
                remediation: "Run: sudo systemsetup -setremoteappleevents off".to_string(),
                cis_level: 1,
            }
        }
        None => check_not_executable(cis_id, title, category, 1),
    }
}

/// 2.4.2 - Internet Sharing disabled.
fn check_internet_sharing() -> CisCheckResult {
    let cis_id = "2.4.2";
    let title = "Ensure Internet Sharing Is Disabled";
    let category = "Sharing Services";

    // Read plist directly for NAT enabled state
    let plist_path = "/Library/Preferences/SystemConfiguration/com.apple.nat.plist";
    match std::fs::read(plist_path) {
        Ok(data) => {
            let content = String::from_utf8_lossy(&data);
            let is_enabled = content.contains("Enabled")
                && (content.contains("<true/>") || content.contains("true"));
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "NAT not enabled".to_string(),
                actual: if is_enabled {
                    "NAT is enabled".to_string()
                } else {
                    "NAT not enabled".to_string()
                },
                passed: !is_enabled,
                severity: Severity::Medium,
                remediation: "System Settings > General > Sharing > Internet Sharing > Off"
                    .to_string(),
                cis_level: 1,
            }
        }
        Err(_) => {
            // File doesn't exist = internet sharing not configured = pass
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "NAT not enabled".to_string(),
                actual: "NAT config not found (disabled)".to_string(),
                passed: true,
                severity: Severity::Medium,
                remediation: String::new(),
                cis_level: 1,
            }
        }
    }
}

/// 2.4.4 - Printer Sharing disabled.
fn check_printer_sharing() -> CisCheckResult {
    let cis_id = "2.4.4";
    let title = "Ensure Printer Sharing Is Disabled";
    let category = "Sharing Services";

    match run_check("cupsctl", &[]) {
        Some(output) => {
            let sharing_enabled = output.contains("_share_printers=1");
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "_share_printers=0".to_string(),
                actual: if sharing_enabled {
                    "_share_printers=1".to_string()
                } else {
                    "_share_printers=0".to_string()
                },
                passed: !sharing_enabled,
                severity: Severity::Low,
                remediation: "Run: cupsctl --no-share-printers".to_string(),
                cis_level: 1,
            }
        }
        None => check_not_executable(cis_id, title, category, 1),
    }
}

/// 2.4.5 - Remote Login (SSH) disabled.
fn check_remote_login() -> CisCheckResult {
    let cis_id = "2.4.5";
    let title = "Ensure Remote Login Is Disabled";
    let category = "Sharing Services";

    match run_check("systemsetup", &["-getremotelogin"]) {
        Some(output) => {
            let is_off = output.contains("Off");
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "Off".to_string(),
                actual: if is_off {
                    "Off".to_string()
                } else {
                    "On".to_string()
                },
                passed: is_off,
                severity: Severity::Medium,
                remediation: "Run: sudo systemsetup -setremotelogin off".to_string(),
                cis_level: 1,
            }
        }
        None => check_not_executable(cis_id, title, category, 1),
    }
}

/// 2.4.7 - Bluetooth Sharing disabled.
fn check_bluetooth_sharing() -> CisCheckResult {
    let cis_id = "2.4.7";
    let title = "Ensure Bluetooth Sharing Is Disabled";
    let category = "Sharing Services";

    match run_check(
        "defaults",
        &[
            "-currentHost",
            "read",
            "com.apple.Bluetooth",
            "PrefKeyServicesEnabled",
        ],
    ) {
        Some(output) => {
            let trimmed = output.trim();
            // 0 or "does not exist" both mean disabled
            let is_disabled = trimmed == "0" || trimmed.contains("does not exist");
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "0 (Disabled)".to_string(),
                actual: format!("{}", trimmed),
                passed: is_disabled,
                severity: Severity::Medium,
                remediation: "System Settings > General > Sharing > Bluetooth Sharing > Off"
                    .to_string(),
                cis_level: 1,
            }
        }
        None => {
            // Command failure likely means the key doesn't exist = disabled
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "0 (Disabled)".to_string(),
                actual: "Key not found (disabled)".to_string(),
                passed: true,
                severity: Severity::Medium,
                remediation: String::new(),
                cis_level: 1,
            }
        }
    }
}

/// 2.4.10 - Content Caching disabled.
fn check_content_caching() -> CisCheckResult {
    let cis_id = "2.4.10";
    let title = "Ensure Content Caching Is Disabled";
    let category = "Sharing Services";

    match run_check("AssetCacheManagerUtil", &["isActivated"]) {
        Some(output) => {
            let is_activated = output.contains("Activated");
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "Not Activated".to_string(),
                actual: if is_activated {
                    "Activated".to_string()
                } else {
                    "Not Activated".to_string()
                },
                passed: !is_activated,
                severity: Severity::Low,
                remediation: "System Settings > General > Sharing > Content Caching > Off"
                    .to_string(),
                cis_level: 2,
            }
        }
        None => {
            // Command not available or failed — assume not activated
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "Not Activated".to_string(),
                actual: "Unable to determine (likely disabled)".to_string(),
                passed: true,
                severity: Severity::Low,
                remediation: String::new(),
                cis_level: 2,
            }
        }
    }
}

/// 2.5.1 - FileVault enabled (CIS structured check).
fn check_filevault() -> CisCheckResult {
    let cis_id = "2.5.1";
    let title = "Ensure FileVault Is Enabled";
    let category = "Storage Security";

    match run_check("fdesetup", &["status"]) {
        Some(output) => {
            let is_on = output.contains("On");
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "FileVault is On".to_string(),
                actual: output.clone(),
                passed: is_on,
                severity: Severity::Critical,
                remediation: "System Settings > Privacy & Security > FileVault > Turn On FileVault"
                    .to_string(),
                cis_level: 1,
            }
        }
        None => check_not_executable(cis_id, title, category, 1),
    }
}

/// 2.5.2 - Gatekeeper enabled (CIS structured check).
fn check_gatekeeper() -> CisCheckResult {
    let cis_id = "2.5.2";
    let title = "Ensure Gatekeeper Is Enabled";
    let category = "System Security";

    match run_check("spctl", &["--status"]) {
        Some(output) => {
            let is_enabled = output.contains("enabled");
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "assessments enabled".to_string(),
                actual: output.clone(),
                passed: is_enabled,
                severity: Severity::Critical,
                remediation: "Run: sudo spctl --master-enable".to_string(),
                cis_level: 1,
            }
        }
        None => check_not_executable(cis_id, title, category, 1),
    }
}

/// 2.5.3 - Firewall enabled (CIS structured check).
fn check_firewall() -> CisCheckResult {
    let cis_id = "2.5.3";
    let title = "Ensure Firewall Is Enabled";
    let category = "Network Security";

    match run_check(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
    ) {
        Some(output) => {
            let is_enabled = output.contains("enabled");
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "Firewall enabled".to_string(),
                actual: output.clone(),
                passed: is_enabled,
                severity: Severity::High,
                remediation:
                    "Run: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"
                        .to_string(),
                cis_level: 1,
            }
        }
        None => check_not_executable(cis_id, title, category, 1),
    }
}

/// 2.5.4 - Firewall Stealth Mode enabled.
fn check_firewall_stealth() -> CisCheckResult {
    let cis_id = "2.5.4";
    let title = "Ensure Firewall Stealth Mode Is Enabled";
    let category = "Network Security";

    match run_check(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getstealthmode"],
    ) {
        Some(output) => {
            let is_enabled = output.contains("enabled");
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "Stealth mode enabled".to_string(),
                actual: output.clone(),
                passed: is_enabled,
                severity: Severity::Medium,
                remediation:
                    "Run: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"
                        .to_string(),
                cis_level: 1,
            }
        }
        None => check_not_executable(cis_id, title, category, 1),
    }
}

/// 5.1 - Sensitive file permissions for ~/.ssh/*.
fn check_ssh_permissions() -> CisCheckResult {
    let cis_id = "5.1";
    let title = "Ensure Home Directory SSH Config Permissions Are Secure";
    let category = "File Permissions";

    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => {
            return check_not_executable(cis_id, title, category, 1);
        }
    };

    let ssh_dir = std::path::PathBuf::from(&home).join(".ssh");
    if !ssh_dir.exists() {
        return CisCheckResult {
            cis_id: cis_id.to_string(),
            title: title.to_string(),
            category: category.to_string(),
            expected: "Private keys: 0600, public keys: 0644".to_string(),
            actual: "~/.ssh directory does not exist".to_string(),
            passed: true,
            severity: Severity::Medium,
            remediation: String::new(),
            cis_level: 1,
        };
    }

    let mut issues = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&ssh_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if let Ok(metadata) = std::fs::metadata(&path) {
                let mode = metadata.permissions().mode() & 0o777;
                // Private keys should be 0600
                if (name == "id_rsa"
                    || name == "id_ed25519"
                    || name == "id_ecdsa"
                    || name == "id_dsa"
                    || name.starts_with("id_") && !name.ends_with(".pub"))
                    && mode != 0o600
                {
                    issues.push(format!("{}: {:04o} (should be 0600)", name, mode));
                }
                // config should be 0600 or 0644
                if name == "config" && mode != 0o600 && mode != 0o644 {
                    issues.push(format!("{}: {:04o} (should be 0600 or 0644)", name, mode));
                }
            }
        }
    }

    let passed = issues.is_empty();
    CisCheckResult {
        cis_id: cis_id.to_string(),
        title: title.to_string(),
        category: category.to_string(),
        expected: "Private keys: 0600, public keys: 0644".to_string(),
        actual: if passed {
            "All SSH file permissions are correct".to_string()
        } else {
            issues.join("; ")
        },
        passed,
        severity: Severity::High,
        remediation: "Run: chmod 600 ~/.ssh/id_* && chmod 644 ~/.ssh/*.pub".to_string(),
        cis_level: 1,
    }
}

/// 5.6 - Auto-login disabled.
fn check_auto_login() -> CisCheckResult {
    let cis_id = "5.6";
    let title = "Ensure Automatic Login Is Disabled";
    let category = "Login Security";

    match run_check(
        "defaults",
        &[
            "read",
            "/Library/Preferences/com.apple.loginwindow",
            "autoLoginUser",
        ],
    ) {
        Some(output) => {
            let trimmed = output.trim();
            let is_disabled = trimmed.is_empty() || trimmed.contains("does not exist");
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "No auto-login user".to_string(),
                actual: if is_disabled {
                    "Auto-login disabled".to_string()
                } else {
                    format!("Auto-login user: {}", trimmed)
                },
                passed: is_disabled,
                severity: Severity::High,
                remediation:
                    "System Settings > Users & Groups > Login Options > Automatic login > Off"
                        .to_string(),
                cis_level: 1,
            }
        }
        None => {
            // Key not found = disabled
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "No auto-login user".to_string(),
                actual: "Auto-login disabled (key not found)".to_string(),
                passed: true,
                severity: Severity::High,
                remediation: String::new(),
                cis_level: 1,
            }
        }
    }
}

/// 5.7 - Screen saver password required.
fn check_screensaver_password() -> CisCheckResult {
    let cis_id = "5.7";
    let title = "Ensure a Password Is Required to Wake the Computer From Sleep or Screen Saver";
    let category = "Login Security";

    match run_check(
        "defaults",
        &["read", "com.apple.screensaver", "askForPassword"],
    ) {
        Some(output) => {
            let trimmed = output.trim();
            let is_set = trimmed == "1";
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "1 (Required)".to_string(),
                actual: format!(
                    "{} ({})",
                    trimmed,
                    if is_set { "Required" } else { "Not required" }
                ),
                passed: is_set,
                severity: Severity::High,
                remediation:
                    "System Settings > Lock Screen > Require password after screen saver begins or display is turned off > Immediately"
                        .to_string(),
                cis_level: 1,
            }
        }
        None => check_not_executable(cis_id, title, category, 1),
    }
}

/// 6.1.1 - Login window displays name and password fields.
fn check_login_window_display() -> CisCheckResult {
    let cis_id = "6.1.1";
    let title = "Ensure Login Window Displays as Name and Password";
    let category = "Login Window";

    match run_check(
        "defaults",
        &[
            "read",
            "/Library/Preferences/com.apple.loginwindow",
            "SHOWFULLNAME",
        ],
    ) {
        Some(output) => {
            let trimmed = output.trim();
            let is_set = trimmed == "1";
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "1 (Name and Password)".to_string(),
                actual: format!(
                    "{} ({})",
                    trimmed,
                    if is_set { "Name and Password" } else { "User list" }
                ),
                passed: is_set,
                severity: Severity::Low,
                remediation: "Run: sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true".to_string(),
                cis_level: 1,
            }
        }
        None => {
            // Key not found = shows user list = fail
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "1 (Name and Password)".to_string(),
                actual: "Key not found (shows user list)".to_string(),
                passed: false,
                severity: Severity::Low,
                remediation: "Run: sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true".to_string(),
                cis_level: 1,
            }
        }
    }
}

/// 6.1.2 - Password hints disabled.
fn check_password_hints() -> CisCheckResult {
    let cis_id = "6.1.2";
    let title = "Ensure Password Hints Are Disabled";
    let category = "Login Window";

    match run_check(
        "defaults",
        &[
            "read",
            "/Library/Preferences/com.apple.loginwindow",
            "RetriesUntilHint",
        ],
    ) {
        Some(output) => {
            let trimmed = output.trim();
            let is_disabled = trimmed == "0" || trimmed.contains("does not exist");
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "0 (Disabled)".to_string(),
                actual: format!("{}", trimmed),
                passed: is_disabled,
                severity: Severity::Low,
                remediation: "Run: sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0".to_string(),
                cis_level: 1,
            }
        }
        None => {
            // Key not found = no hints = pass
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "0 (Disabled)".to_string(),
                actual: "Key not found (disabled)".to_string(),
                passed: true,
                severity: Severity::Low,
                remediation: String::new(),
                cis_level: 1,
            }
        }
    }
}

/// 6.1.3 - Guest account disabled.
fn check_guest_account() -> CisCheckResult {
    let cis_id = "6.1.3";
    let title = "Ensure Guest Account Is Disabled";
    let category = "Login Window";

    match run_check(
        "defaults",
        &[
            "read",
            "/Library/Preferences/com.apple.loginwindow",
            "GuestEnabled",
        ],
    ) {
        Some(output) => {
            let trimmed = output.trim();
            let is_disabled = trimmed == "0" || trimmed.contains("does not exist");
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "0 (Disabled)".to_string(),
                actual: format!(
                    "{} ({})",
                    trimmed,
                    if is_disabled { "Disabled" } else { "Enabled" }
                ),
                passed: is_disabled,
                severity: Severity::Medium,
                remediation:
                    "System Settings > Users & Groups > Guest User > Allow guests to log in to this computer > Off"
                        .to_string(),
                cis_level: 1,
            }
        }
        None => {
            // Key not found = disabled
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "0 (Disabled)".to_string(),
                actual: "Key not found (disabled)".to_string(),
                passed: true,
                severity: Severity::Medium,
                remediation: String::new(),
                cis_level: 1,
            }
        }
    }
}

/// 6.1.4 - Guest access to shared folders disabled.
fn check_guest_shared_folders() -> CisCheckResult {
    let cis_id = "6.1.4";
    let title = "Ensure Guest Access to Shared Folders Is Disabled";
    let category = "Login Window";

    // Check both AFP and SMB guest access
    let afp_result = run_check(
        "defaults",
        &[
            "read",
            "/Library/Preferences/com.apple.AppleFileServer",
            "guestAccess",
        ],
    );
    let smb_result = run_check(
        "defaults",
        &[
            "read",
            "/Library/Preferences/SystemConfiguration/com.apple.smb.server",
            "AllowGuestAccess",
        ],
    );

    let afp_disabled = match &afp_result {
        Some(output) => {
            let t = output.trim();
            t == "0" || t.contains("does not exist")
        }
        None => true, // Not found = disabled
    };

    let smb_disabled = match &smb_result {
        Some(output) => {
            let t = output.trim();
            t == "0" || t.contains("does not exist")
        }
        None => true,
    };

    let passed = afp_disabled && smb_disabled;
    let mut details = Vec::new();
    if !afp_disabled {
        details.push("AFP guest access enabled");
    }
    if !smb_disabled {
        details.push("SMB guest access enabled");
    }

    CisCheckResult {
        cis_id: cis_id.to_string(),
        title: title.to_string(),
        category: category.to_string(),
        expected: "Guest access disabled for AFP and SMB".to_string(),
        actual: if passed {
            "Guest access disabled".to_string()
        } else {
            details.join(", ")
        },
        passed,
        severity: Severity::Medium,
        remediation:
            "Run: sudo defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -bool false && sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess -bool false"
                .to_string(),
        cis_level: 1,
    }
}

/// 6.2 - Show all filename extensions.
fn check_filename_extensions() -> CisCheckResult {
    let cis_id = "6.2";
    let title = "Ensure Show All Filename Extensions Setting Is Enabled";
    let category = "User Interface";

    match run_check(
        "defaults",
        &["read", "NSGlobalDomain", "AppleShowAllExtensions"],
    ) {
        Some(output) => {
            let trimmed = output.trim();
            let is_shown = trimmed == "1";
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "1 (Show all extensions)".to_string(),
                actual: format!(
                    "{} ({})",
                    trimmed,
                    if is_shown { "Shown" } else { "Hidden" }
                ),
                passed: is_shown,
                severity: Severity::Low,
                remediation: "Finder > Settings > Advanced > Show all filename extensions"
                    .to_string(),
                cis_level: 1,
            }
        }
        None => {
            // Key not found = extensions hidden = fail
            CisCheckResult {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                expected: "1 (Show all extensions)".to_string(),
                actual: "Key not found (extensions hidden)".to_string(),
                passed: false,
                severity: Severity::Low,
                remediation: "Finder > Settings > Advanced > Show all filename extensions"
                    .to_string(),
                cis_level: 1,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

/// Run all CIS checks and return the list of results.
pub fn run_all_cis_checks() -> Vec<CisCheckResult> {
    let checks: Vec<fn() -> CisCheckResult> = vec![
        check_software_updates,
        check_bluetooth_powered,
        check_remote_apple_events,
        check_internet_sharing,
        check_printer_sharing,
        check_remote_login,
        check_bluetooth_sharing,
        check_content_caching,
        check_filevault,
        check_gatekeeper,
        check_firewall,
        check_firewall_stealth,
        check_ssh_permissions,
        check_auto_login,
        check_screensaver_password,
        check_login_window_display,
        check_password_hints,
        check_guest_account,
        check_guest_shared_folders,
        check_filename_extensions,
    ];

    checks
        .iter()
        .map(|check_fn| {
            let result = check_fn();
            debug!(
                cis_id = %result.cis_id,
                passed = result.passed,
                "CIS check completed"
            );
            result
        })
        .collect()
}

/// Calculate a weighted compliance score from check results.
pub fn calculate_compliance_score(results: &[CisCheckResult]) -> f64 {
    let mut weighted_pass = 0.0;
    let mut total_weight = 0.0;

    for check in results {
        let weight = match check.severity {
            Severity::Critical => 4.0,
            Severity::High => 3.0,
            Severity::Medium => 2.0,
            Severity::Low => 1.0,
            Severity::Info => 0.5,
        };
        total_weight += weight;
        if check.passed {
            weighted_pass += weight;
        }
    }

    if total_weight == 0.0 {
        return 100.0;
    }
    (weighted_pass / total_weight) * 100.0
}

/// Build a full compliance report from check results.
pub fn build_compliance_report(results: Vec<CisCheckResult>) -> ComplianceReport {
    let total = results.len();
    let passed = results.iter().filter(|c| c.passed).count();
    let failed = total - passed;
    let score = calculate_compliance_score(&results);
    let critical_failures = results
        .iter()
        .filter(|c| !c.passed && c.severity == Severity::Critical)
        .count();

    ComplianceReport {
        checks: results,
        total,
        passed,
        failed,
        score,
        critical_failures,
    }
}

/// Convert a failed CIS check into a Finding for the scanner framework.
fn cis_check_to_finding(check: &CisCheckResult) -> Finding {
    let id = format!(
        "{}-CIS-{}",
        check.severity.finding_id_prefix(),
        check.cis_id.replace('.', "_")
    );

    let description = format!(
        "CIS macOS Benchmark {} (Level {}): {}\n\n\
         Expected: {}\n\
         Actual: {}\n\n\
         Category: {}",
        check.cis_id, check.cis_level, check.title, check.expected, check.actual, check.category
    );

    let cvss_vector = CvssVector::for_category(ModuleCategory::Configuration, check.severity);
    let cvss = calculate_cvss(&cvss_vector);

    Finding {
        id,
        title: format!("[CIS {}] {}", check.cis_id, check.title),
        severity: check.severity,
        cvss,
        category: ModuleCategory::Configuration,
        description,
        reproduction: None,
        evidence: Evidence {
            os_events: vec![format!(
                "cis-benchmark: {} — expected '{}', got '{}'",
                check.cis_id, check.expected, check.actual
            )],
            ..Evidence::empty()
        },
        remediation: check.remediation.clone(),
    }
}

/// Build a summary finding with the overall compliance score.
fn build_summary_finding(report: &ComplianceReport) -> Finding {
    let severity = if report.score >= 90.0 {
        Severity::Info
    } else if report.score >= 70.0 {
        Severity::Low
    } else if report.score >= 50.0 {
        Severity::Medium
    } else if report.score >= 30.0 {
        Severity::High
    } else {
        Severity::Critical
    };

    let id = format!("{}-CIS-SUMMARY", severity.finding_id_prefix());

    let description = format!(
        "CIS macOS Benchmark Compliance Score: {:.1}%\n\n\
         Total checks: {}\n\
         Passed: {}\n\
         Failed: {}\n\
         Critical failures: {}",
        report.score, report.total, report.passed, report.failed, report.critical_failures
    );

    let cvss_vector = CvssVector::for_category(ModuleCategory::Configuration, severity);
    let cvss = calculate_cvss(&cvss_vector);

    Finding {
        id,
        title: format!("CIS macOS Benchmark Compliance: {:.1}%", report.score),
        severity,
        cvss,
        category: ModuleCategory::Configuration,
        description,
        reproduction: None,
        evidence: Evidence {
            os_events: vec![format!(
                "cis-benchmark: {}/{} checks passed ({:.1}%)",
                report.passed, report.total, report.score
            )],
            ..Evidence::empty()
        },
        remediation: if report.failed > 0 {
            format!(
                "Review and remediate the {} failed CIS checks. \
                 Priority should be given to the {} critical failures.",
                report.failed, report.critical_failures
            )
        } else {
            "All CIS checks passed. Continue monitoring for compliance drift.".to_string()
        },
    }
}

// ---------------------------------------------------------------------------
// ScanModule implementation
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct CisBenchmarkModule;

impl CisBenchmarkModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ScanModule for CisBenchmarkModule {
    fn name(&self) -> &str {
        "cis-benchmark"
    }

    fn description(&self) -> &str {
        "CIS macOS Benchmark compliance checker"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Configuration
    }

    async fn run(&self, _ctx: &mut ScanContext) -> Result<Vec<Finding>> {
        self.run_standalone().await
    }

    async fn run_standalone(&self) -> Result<Vec<Finding>> {
        let results = run_all_cis_checks();
        let report = build_compliance_report(results);

        let mut findings = Vec::new();

        // One finding per failed check
        for check in report.checks.iter().filter(|c| !c.passed) {
            findings.push(cis_check_to_finding(check));
        }

        // Summary finding with compliance score
        findings.push(build_summary_finding(&report));

        Ok(findings)
    }
}

// ---------------------------------------------------------------------------
// Public API for Tauri command
// ---------------------------------------------------------------------------

/// Run the full CIS compliance scan and return the structured report.
pub fn run_cis_compliance_report() -> ComplianceReport {
    let results = run_all_cis_checks();
    build_compliance_report(results)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_score_all_pass() {
        let checks = vec![
            CisCheckResult {
                cis_id: "1.0".to_string(),
                title: "Test".to_string(),
                category: "Test".to_string(),
                expected: "a".to_string(),
                actual: "a".to_string(),
                passed: true,
                severity: Severity::Critical,
                remediation: String::new(),
                cis_level: 1,
            },
            CisCheckResult {
                cis_id: "2.0".to_string(),
                title: "Test2".to_string(),
                category: "Test".to_string(),
                expected: "b".to_string(),
                actual: "b".to_string(),
                passed: true,
                severity: Severity::Low,
                remediation: String::new(),
                cis_level: 1,
            },
        ];
        let score = calculate_compliance_score(&checks);
        assert!((score - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compliance_score_all_fail() {
        let checks = vec![CisCheckResult {
            cis_id: "1.0".to_string(),
            title: "Test".to_string(),
            category: "Test".to_string(),
            expected: "a".to_string(),
            actual: "b".to_string(),
            passed: false,
            severity: Severity::Critical,
            remediation: String::new(),
            cis_level: 1,
        }];
        let score = calculate_compliance_score(&checks);
        assert!(score.abs() < f64::EPSILON);
    }

    #[test]
    fn test_compliance_score_mixed() {
        let checks = vec![
            CisCheckResult {
                cis_id: "1.0".to_string(),
                title: "Critical pass".to_string(),
                category: "Test".to_string(),
                expected: "a".to_string(),
                actual: "a".to_string(),
                passed: true,
                severity: Severity::Critical, // weight 4
                remediation: String::new(),
                cis_level: 1,
            },
            CisCheckResult {
                cis_id: "2.0".to_string(),
                title: "Low fail".to_string(),
                category: "Test".to_string(),
                expected: "a".to_string(),
                actual: "b".to_string(),
                passed: false,
                severity: Severity::Low, // weight 1
                remediation: String::new(),
                cis_level: 1,
            },
        ];
        // Expected: 4.0 / 5.0 * 100 = 80.0
        let score = calculate_compliance_score(&checks);
        assert!((score - 80.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compliance_score_empty() {
        let checks: Vec<CisCheckResult> = vec![];
        let score = calculate_compliance_score(&checks);
        assert!((score - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_build_compliance_report() {
        let results = vec![
            CisCheckResult {
                cis_id: "1.0".to_string(),
                title: "Pass".to_string(),
                category: "Test".to_string(),
                expected: "a".to_string(),
                actual: "a".to_string(),
                passed: true,
                severity: Severity::High,
                remediation: String::new(),
                cis_level: 1,
            },
            CisCheckResult {
                cis_id: "2.0".to_string(),
                title: "Fail".to_string(),
                category: "Test".to_string(),
                expected: "a".to_string(),
                actual: "b".to_string(),
                passed: false,
                severity: Severity::Critical,
                remediation: "fix it".to_string(),
                cis_level: 1,
            },
        ];

        let report = build_compliance_report(results);
        assert_eq!(report.total, 2);
        assert_eq!(report.passed, 1);
        assert_eq!(report.failed, 1);
        assert_eq!(report.critical_failures, 1);
        assert!(report.score > 0.0);
        assert!(report.score < 100.0);
    }

    #[test]
    fn test_cis_check_to_finding() {
        let check = CisCheckResult {
            cis_id: "2.5.1".to_string(),
            title: "Ensure FileVault Is Enabled".to_string(),
            category: "Storage Security".to_string(),
            expected: "FileVault is On".to_string(),
            actual: "FileVault is Off".to_string(),
            passed: false,
            severity: Severity::Critical,
            remediation: "Turn on FileVault".to_string(),
            cis_level: 1,
        };

        let finding = cis_check_to_finding(&check);
        assert_eq!(finding.id, "CRIT-CIS-2_5_1");
        assert!(finding.title.contains("CIS 2.5.1"));
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.category, ModuleCategory::Configuration);
        assert!(finding.description.contains("FileVault"));
        assert_eq!(finding.remediation, "Turn on FileVault");
    }

    #[test]
    fn test_build_summary_finding_high_score() {
        let report = ComplianceReport {
            checks: vec![],
            total: 20,
            passed: 19,
            failed: 1,
            score: 95.0,
            critical_failures: 0,
        };

        let finding = build_summary_finding(&report);
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.title.contains("95.0%"));
    }

    #[test]
    fn test_build_summary_finding_low_score() {
        let report = ComplianceReport {
            checks: vec![],
            total: 20,
            passed: 5,
            failed: 15,
            score: 25.0,
            critical_failures: 3,
        };

        let finding = build_summary_finding(&report);
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.title.contains("25.0%"));
    }

    #[test]
    fn test_check_not_executable() {
        let result = check_not_executable("99.9", "Test Check", "Test", 1);
        assert!(!result.passed);
        assert_eq!(result.severity, Severity::Info);
        assert!(result.actual.contains("could not be executed"));
    }

    #[test]
    fn test_severity_weight_mapping() {
        // Verify the weights used in scoring
        let critical = CisCheckResult {
            cis_id: "c".to_string(),
            title: String::new(),
            category: String::new(),
            expected: String::new(),
            actual: String::new(),
            passed: true,
            severity: Severity::Critical,
            remediation: String::new(),
            cis_level: 1,
        };
        let info = CisCheckResult {
            cis_id: "i".to_string(),
            title: String::new(),
            category: String::new(),
            expected: String::new(),
            actual: String::new(),
            passed: false,
            severity: Severity::Info,
            remediation: String::new(),
            cis_level: 1,
        };

        // Critical=4.0, Info=0.5, total=4.5
        // Only critical passes: 4.0/4.5 = 88.89
        let score = calculate_compliance_score(&[critical, info]);
        let expected = (4.0 / 4.5) * 100.0;
        assert!((score - expected).abs() < 0.01);
    }

    #[test]
    fn test_run_all_cis_checks_returns_results() {
        let results = run_all_cis_checks();
        // We defined 20 checks
        assert_eq!(
            results.len(),
            20,
            "Expected 20 CIS checks, got {}",
            results.len()
        );
    }

    #[test]
    fn test_cis_ids_unique() {
        let results = run_all_cis_checks();
        let mut ids: Vec<&str> = results.iter().map(|r| r.cis_id.as_str()).collect();
        ids.sort();
        let len_before = ids.len();
        ids.dedup();
        assert_eq!(len_before, ids.len(), "Duplicate CIS IDs detected");
    }

    #[test]
    fn test_all_checks_have_valid_fields() {
        let results = run_all_cis_checks();
        for check in &results {
            assert!(!check.cis_id.is_empty(), "CIS ID should not be empty");
            assert!(!check.title.is_empty(), "Title should not be empty");
            assert!(!check.category.is_empty(), "Category should not be empty");
            assert!(
                check.cis_level == 1 || check.cis_level == 2,
                "CIS level should be 1 or 2, got {}",
                check.cis_level
            );
        }
    }

    #[tokio::test]
    async fn test_module_trait() {
        let module = CisBenchmarkModule::new();
        assert_eq!(module.name(), "cis-benchmark");
        assert_eq!(module.category(), ModuleCategory::Configuration);
        assert!(!module.description().is_empty());
    }

    #[tokio::test]
    async fn test_module_run_standalone() {
        let module = CisBenchmarkModule::new();
        let findings = module.run_standalone().await.unwrap();
        // Should always produce at least the summary finding
        assert!(
            !findings.is_empty(),
            "Should produce at least a summary finding"
        );
        // Last finding should be the summary
        let last = findings.last().unwrap();
        assert!(
            last.title.contains("Compliance"),
            "Last finding should be the compliance summary"
        );
    }

    #[test]
    fn test_run_cis_compliance_report() {
        let report = run_cis_compliance_report();
        assert_eq!(report.total, 20);
        assert!(report.score >= 0.0 && report.score <= 100.0);
        assert_eq!(report.passed + report.failed, report.total);
    }
}
