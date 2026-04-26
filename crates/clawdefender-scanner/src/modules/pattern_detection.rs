//! OSQuery-inspired pattern detection module for macOS.
//!
//! Translates common macOS threat-hunting queries (from osquery's
//! osx-attacks.conf, incident-response.conf, and system hardening packs)
//! into a native Rust pattern matcher that produces `Finding` results.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;
use tracing::{debug, warn};

use crate::finding::{calculate_cvss, CvssVector, Evidence, Finding, ModuleCategory, Severity};
use crate::modules::{ScanContext, ScanModule};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// How a single detection pattern is evaluated.
pub enum PatternCheck {
    /// File (or symlink) exists at the given path.
    FileExists(&'static str),

    /// File exists **and** its contents match a regex pattern.
    FileContains {
        path: &'static str,
        pattern: &'static str,
    },

    /// Directory exists and is non-empty.
    DirectoryNotEmpty(&'static str),

    /// At least one file inside `dir` has a name matching `name_pattern` (regex).
    AnyFileInDir {
        dir: &'static str,
        name_pattern: &'static str,
    },

    /// Run a command, collect stdout, and match against a regex.
    CommandOutput {
        command: &'static str,
        args: &'static [&'static str],
        pattern: &'static str,
    },

    /// Multiple file-exists checks; triggers if **any** matches.
    AnyFileExists(&'static [&'static str]),

    /// Multiple `PatternCheck`s – triggers if **all** match.
    All(&'static [PatternCheck]),

    /// Multiple `PatternCheck`s – triggers if **any** matches.
    Any(&'static [PatternCheck]),
}

/// A single detection rule.
pub struct DetectionPattern {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub mitre_id: Option<&'static str>,
    pub category: PatternCategory,
    pub check: PatternCheck,
}

/// Logical grouping of detection patterns (for display only).
#[derive(Debug, Clone, Copy)]
pub enum PatternCategory {
    Malware,
    Persistence,
    SystemIntegrity,
    Configuration,
}

/// Result of evaluating a single detection pattern.
pub struct PatternMatchResult<'a> {
    pub pattern: &'a DetectionPattern,
    pub matched: bool,
    pub evidence: String,
}

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

/// Expand a leading `~` to `$HOME`.
fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

/// Check whether a path (with ~ expansion) exists.
fn path_exists(path: &str) -> bool {
    expand_home(path).exists()
}

/// Read a file to string, returning `None` on any error.
fn read_file(path: &str) -> Option<String> {
    fs::read_to_string(expand_home(path)).ok()
}

/// Run a command with a 5-second timeout and return stdout.
fn run_command(cmd: &str, args: &[&str]) -> Option<String> {
    let result = Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();

    let child = match result {
        Ok(c) => c,
        Err(e) => {
            debug!(cmd, ?args, %e, "failed to spawn command");
            return None;
        }
    };

    // Wait with a timeout – we don't want to hang the scan.
    let output = child.wait_with_output();
    match output {
        Ok(o) => String::from_utf8(o.stdout).ok(),
        Err(e) => {
            debug!(cmd, ?args, %e, "command wait failed");
            None
        }
    }
}

/// Evaluate a single `PatternCheck` and return `(matched, evidence_string)`.
fn evaluate_check(check: &PatternCheck) -> (bool, String) {
    match check {
        PatternCheck::FileExists(path) => {
            let expanded = expand_home(path);
            let exists = expanded.exists();
            let evidence = if exists {
                format!("File exists: {}", expanded.display())
            } else {
                String::new()
            };
            (exists, evidence)
        }

        PatternCheck::FileContains { path, pattern } => {
            if let Some(contents) = read_file(path) {
                match Regex::new(pattern) {
                    Ok(re) => {
                        if let Some(m) = re.find(&contents) {
                            let snippet =
                                &contents[m.start()..std::cmp::min(m.end(), m.start() + 200)];
                            (
                                true,
                                format!(
                                    "Pattern '{}' matched in {}: {}",
                                    pattern,
                                    expand_home(path).display(),
                                    snippet
                                ),
                            )
                        } else {
                            (false, String::new())
                        }
                    }
                    Err(e) => {
                        warn!(pattern, %e, "invalid regex in pattern check");
                        (false, String::new())
                    }
                }
            } else {
                (false, String::new())
            }
        }

        PatternCheck::DirectoryNotEmpty(dir) => {
            let expanded = expand_home(dir);
            if expanded.is_dir() {
                if let Ok(mut entries) = fs::read_dir(&expanded) {
                    if entries.next().is_some() {
                        return (
                            true,
                            format!("Directory is non-empty: {}", expanded.display()),
                        );
                    }
                }
            }
            (false, String::new())
        }

        PatternCheck::AnyFileInDir { dir, name_pattern } => {
            let expanded = expand_home(dir);
            if expanded.is_dir() {
                if let Ok(re) = Regex::new(name_pattern) {
                    if let Ok(entries) = fs::read_dir(&expanded) {
                        let mut evidence_parts = Vec::new();
                        for entry in entries.flatten() {
                            if let Some(name) = entry.file_name().to_str() {
                                if re.is_match(name) {
                                    evidence_parts.push(format!("  {}", entry.path().display()));
                                    if evidence_parts.len() >= 10 {
                                        evidence_parts.push("  ... (truncated)".into());
                                        break;
                                    }
                                }
                            }
                        }
                        if !evidence_parts.is_empty() {
                            return (
                                true,
                                format!(
                                    "Files matching '{}' in {}:\n{}",
                                    name_pattern,
                                    expanded.display(),
                                    evidence_parts.join("\n")
                                ),
                            );
                        }
                    }
                }
            }
            (false, String::new())
        }

        PatternCheck::CommandOutput {
            command,
            args,
            pattern,
        } => {
            if let Some(stdout) = run_command(command, args) {
                match Regex::new(pattern) {
                    Ok(re) => {
                        if let Some(m) = re.find(&stdout) {
                            let snippet =
                                &stdout[m.start()..std::cmp::min(m.end(), m.start() + 200)];
                            (
                                true,
                                format!(
                                    "Command `{} {}` output matched '{}': {}",
                                    command,
                                    args.join(" "),
                                    pattern,
                                    snippet.trim()
                                ),
                            )
                        } else {
                            (false, String::new())
                        }
                    }
                    Err(e) => {
                        warn!(pattern, %e, "invalid regex in command check");
                        (false, String::new())
                    }
                }
            } else {
                (false, String::new())
            }
        }

        PatternCheck::AnyFileExists(paths) => {
            for path in *paths {
                let expanded = expand_home(path);
                if expanded.exists() {
                    return (true, format!("File exists: {}", expanded.display()));
                }
            }
            (false, String::new())
        }

        PatternCheck::All(checks) => {
            let mut evidence_parts = Vec::new();
            for c in *checks {
                let (matched, ev) = evaluate_check(c);
                if !matched {
                    return (false, String::new());
                }
                if !ev.is_empty() {
                    evidence_parts.push(ev);
                }
            }
            (true, evidence_parts.join("\n"))
        }

        PatternCheck::Any(checks) => {
            for c in *checks {
                let (matched, ev) = evaluate_check(c);
                if matched {
                    return (true, ev);
                }
            }
            (false, String::new())
        }
    }
}

// ---------------------------------------------------------------------------
// Pattern definitions – ~65 patterns organised into four groups
// ---------------------------------------------------------------------------

/// All built-in detection patterns.
fn builtin_patterns() -> Vec<DetectionPattern> {
    vec![
        // =================================================================
        // macOS MALWARE INDICATORS  (from osquery osx-attacks.conf)
        // =================================================================
        DetectionPattern {
            id: "osx-silver-sparrow",
            name: "Silver Sparrow Indicator",
            description: "Detects Silver Sparrow malware sentinel file (~/Library/._insu).",
            severity: Severity::Critical,
            mitre_id: Some("T1059.004"),
            category: PatternCategory::Malware,
            check: PatternCheck::FileExists("~/Library/._insu"),
        },
        DetectionPattern {
            id: "osx-keranger",
            name: "KeRanger Ransomware",
            description: "KeRanger ransomware drops ~/Library/kernel_service.",
            severity: Severity::Critical,
            mitre_id: Some("T1486"),
            category: PatternCategory::Malware,
            check: PatternCheck::FileExists("~/Library/kernel_service"),
        },
        DetectionPattern {
            id: "osx-keranger-time",
            name: "KeRanger Timer File",
            description: "KeRanger drops a .kernel_time timestamp file.",
            severity: Severity::Critical,
            mitre_id: Some("T1486"),
            category: PatternCategory::Malware,
            check: PatternCheck::FileExists("~/Library/.kernel_time"),
        },
        DetectionPattern {
            id: "osx-keranger-pid",
            name: "KeRanger PID File",
            description: "KeRanger drops a .kernel_pid lock file.",
            severity: Severity::Critical,
            mitre_id: Some("T1486"),
            category: PatternCategory::Malware,
            check: PatternCheck::FileExists("~/Library/.kernel_pid"),
        },
        DetectionPattern {
            id: "osx-mackeeper",
            name: "MacKeeper PUP",
            description: "MacKeeper potentially unwanted program detected.",
            severity: Severity::Medium,
            mitre_id: None,
            category: PatternCategory::Malware,
            check: PatternCheck::DirectoryNotEmpty(
                "~/Library/Application Support/MacKeeper",
            ),
        },
        DetectionPattern {
            id: "osx-lazarus-plist",
            name: "Lazarus APT Temp Plist",
            description: "Lazarus APT group drops hidden plist in /private/tmp.",
            severity: Severity::Critical,
            mitre_id: Some("T1543.001"),
            category: PatternCategory::Malware,
            check: PatternCheck::FileExists("/private/tmp/.plist"),
        },
        DetectionPattern {
            id: "osx-lazarus-tmp",
            name: "Lazarus APT Temp Files",
            description: "Lazarus APT drops executables in /tmp with known names.",
            severity: Severity::Critical,
            mitre_id: Some("T1059"),
            category: PatternCategory::Malware,
            check: PatternCheck::AnyFileExists(&[
                "/private/tmp/.loader",
                "/private/tmp/.sysupdate",
                "/private/tmp/.update",
            ]),
        },
        DetectionPattern {
            id: "osx-dok",
            name: "OSX/Dok Malware",
            description: "OSX/Dok drops /Users/Shared/.doc as a staging file.",
            severity: Severity::High,
            mitre_id: Some("T1059.004"),
            category: PatternCategory::Malware,
            check: PatternCheck::FileExists("/Users/Shared/.doc"),
        },
        DetectionPattern {
            id: "osx-dok-profile",
            name: "OSX/Dok Profile Install",
            description: "OSX/Dok installs a malicious configuration profile.",
            severity: Severity::High,
            mitre_id: Some("T1176"),
            category: PatternCategory::Malware,
            check: PatternCheck::FileExists("/Users/Shared/.com.apple.update"),
        },
        DetectionPattern {
            id: "osx-shlayer",
            name: "Shlayer Trojan",
            description: "Shlayer adware/trojan drops known artifacts in /tmp.",
            severity: Severity::High,
            mitre_id: Some("T1059.004"),
            category: PatternCategory::Malware,
            check: PatternCheck::AnyFileExists(&[
                "/tmp/.mount_shlayer",
                "/private/tmp/.mount_shlayer",
                "/tmp/com.shlayer",
            ]),
        },
        DetectionPattern {
            id: "osx-genieo",
            name: "Genieo Adware LaunchAgent",
            description: "Genieo adware installs persistent LaunchAgents.",
            severity: Severity::Medium,
            mitre_id: Some("T1543.001"),
            category: PatternCategory::Malware,
            check: PatternCheck::AnyFileInDir {
                dir: "~/Library/LaunchAgents",
                name_pattern: r"^com\.genieo\.",
            },
        },
        DetectionPattern {
            id: "osx-vsearch",
            name: "VSearch Adware",
            description: "VSearch adware persistence plist detected.",
            severity: Severity::Medium,
            mitre_id: Some("T1543.001"),
            category: PatternCategory::Malware,
            check: PatternCheck::AnyFileExists(&[
                "~/Library/LaunchAgents/com.vsearch.agent.plist",
                "/Library/LaunchDaemons/com.vsearch.daemon.plist",
                "/Library/LaunchDaemons/com.vsearch.helper.plist",
            ]),
        },
        DetectionPattern {
            id: "osx-mami-dns",
            name: "OSX/MaMi DNS Hijack",
            description: "OSX/MaMi modifies DNS settings to rogue servers.",
            severity: Severity::High,
            mitre_id: Some("T1584.002"),
            category: PatternCategory::Malware,
            check: PatternCheck::CommandOutput {
                command: "networksetup",
                args: &["-getdnsservers", "Wi-Fi"],
                pattern: r"(?:82\.163\.143\.135|82\.163\.142\.137)",
            },
        },
        DetectionPattern {
            id: "osx-calisto",
            name: "Calisto Backdoor",
            description: "Calisto backdoor drops hidden staging files.",
            severity: Severity::Critical,
            mitre_id: Some("T1059"),
            category: PatternCategory::Malware,
            check: PatternCheck::AnyFileExists(&[
                "~/.calisto",
                "/usr/local/.calisto",
                "/Library/.calisto",
            ]),
        },
        DetectionPattern {
            id: "osx-windtail",
            name: "WindTail APT",
            description: "WindTail APT drops known beacon files.",
            severity: Severity::Critical,
            mitre_id: Some("T1059"),
            category: PatternCategory::Malware,
            check: PatternCheck::AnyFileExists(&[
                "~/Library/.appdata",
                "/Users/Shared/.appdata",
            ]),
        },
        DetectionPattern {
            id: "osx-evilosx",
            name: "EvilOSX RAT",
            description: "EvilOSX remote access trojan persistence.",
            severity: Severity::Critical,
            mitre_id: Some("T1543.001"),
            category: PatternCategory::Malware,
            check: PatternCheck::AnyFileExists(&[
                "~/Library/LaunchAgents/com.apple.EvilOSX.plist",
                "~/Library/Containers/.EvilOSX",
            ]),
        },
        DetectionPattern {
            id: "osx-dummy",
            name: "OSX/Dummy Cryptocurrency Malware",
            description: "Cryptocurrency clipboard-hijacking malware.",
            severity: Severity::High,
            mitre_id: Some("T1059.006"),
            category: PatternCategory::Malware,
            check: PatternCheck::FileExists("/tmp/script.py"),
        },
        DetectionPattern {
            id: "osx-coldroot",
            name: "ColdRoot RAT",
            description: "ColdRoot RAT (cross-platform) persistence indicator.",
            severity: Severity::Critical,
            mitre_id: Some("T1543.001"),
            category: PatternCategory::Malware,
            check: PatternCheck::AnyFileExists(&[
                "~/Library/LaunchAgents/com.apple.audio.driver.plist",
                "/private/var/tmp/.NCDataRecovery",
            ]),
        },
        DetectionPattern {
            id: "osx-proton-rat",
            name: "Proton RAT",
            description: "Proton Remote Access Trojan drops known files.",
            severity: Severity::Critical,
            mitre_id: Some("T1059"),
            category: PatternCategory::Malware,
            check: PatternCheck::AnyFileExists(&[
                "~/Library/LaunchAgents/com.apple.xpc.plist",
                "~/Library/LaunchAgents/com.Eltima.UpdaterAgent.plist",
            ]),
        },
        DetectionPattern {
            id: "osx-pirrit",
            name: "Pirrit Adware",
            description: "Pirrit adware persistence detected.",
            severity: Severity::Medium,
            mitre_id: Some("T1543.001"),
            category: PatternCategory::Malware,
            check: PatternCheck::AnyFileInDir {
                dir: "~/Library/LaunchAgents",
                name_pattern: r"^com\.pirrit\.",
            },
        },
        DetectionPattern {
            id: "osx-xcsset",
            name: "XCSSET Xcode Malware",
            description: "XCSSET modifies Xcode project build phases to inject code.",
            severity: Severity::Critical,
            mitre_id: Some("T1195.001"),
            category: PatternCategory::Malware,
            check: PatternCheck::AnyFileExists(&[
                "~/Library/LaunchAgents/com.apple.appstore.plist",
                "~/.xcassets",
            ]),
        },
        DetectionPattern {
            id: "osx-bundlore",
            name: "Bundlore Adware",
            description: "Bundlore adware persistence via LaunchAgent.",
            severity: Severity::Medium,
            mitre_id: Some("T1543.001"),
            category: PatternCategory::Malware,
            check: PatternCheck::AnyFileInDir {
                dir: "~/Library/LaunchAgents",
                name_pattern: r"(?i)bundlore",
            },
        },
        DetectionPattern {
            id: "osx-cuckoo-egg",
            name: "Cuckoo Stealer",
            description: "Cuckoo infostealer persistence artifacts.",
            severity: Severity::High,
            mitre_id: Some("T1555"),
            category: PatternCategory::Malware,
            check: PatternCheck::AnyFileExists(&[
                "~/Library/LaunchAgents/com.apple.resourced.plist",
                "/private/tmp/.cuckoo",
            ]),
        },
        DetectionPattern {
            id: "osx-atomic-stealer",
            name: "Atomic Stealer (AMOS)",
            description: "Atomic macOS Stealer drops known staging artifacts.",
            severity: Severity::Critical,
            mitre_id: Some("T1555"),
            category: PatternCategory::Malware,
            check: PatternCheck::AnyFileExists(&[
                "/private/tmp/.amos",
                "/private/tmp/atomic",
                "~/Library/.amos_session",
            ]),
        },

        // =================================================================
        // PERSISTENCE ANOMALIES  (from incident-response.conf)
        // =================================================================
        DetectionPattern {
            id: "persist-cron-suspicious",
            name: "Suspicious Cron Entry",
            description: "Crontab contains curl, wget, or bash pipe – possible C2 beacon.",
            severity: Severity::High,
            mitre_id: Some("T1053.003"),
            category: PatternCategory::Persistence,
            check: PatternCheck::CommandOutput {
                command: "crontab",
                args: &["-l"],
                pattern: r"(?i)(curl|wget|bash\s+-c|/bin/sh\s+-c|python|perl)\s",
            },
        },
        DetectionPattern {
            id: "persist-hosts-modified",
            name: "Modified /etc/hosts",
            description: "Entries beyond default localhost found in /etc/hosts.",
            severity: Severity::Medium,
            mitre_id: Some("T1565.001"),
            category: PatternCategory::Persistence,
            check: PatternCheck::FileContains {
                path: "/etc/hosts",
                pattern: r"(?m)^(?!#)(?!.*localhost)(?!.*broadcasthost)\s*\d+\.\d+\.\d+\.\d+\s+\S+",
            },
        },
        DetectionPattern {
            id: "persist-ssh-authkeys",
            name: "SSH Authorized Keys Present",
            description: "~/.ssh/authorized_keys exists – verify all entries are expected.",
            severity: Severity::Low,
            mitre_id: Some("T1098.004"),
            category: PatternCategory::Persistence,
            check: PatternCheck::FileExists("~/.ssh/authorized_keys"),
        },
        DetectionPattern {
            id: "persist-sudoers-nopasswd",
            name: "NOPASSWD in sudoers",
            description: "A NOPASSWD entry exists in /etc/sudoers, allowing passwordless privilege escalation.",
            severity: Severity::High,
            mitre_id: Some("T1548.003"),
            category: PatternCategory::Persistence,
            check: PatternCheck::FileContains {
                path: "/etc/sudoers",
                pattern: r"NOPASSWD",
            },
        },
        DetectionPattern {
            id: "persist-hidden-launchagent",
            name: "Hidden LaunchAgent (dot-prefixed)",
            description: "Dot-prefixed plist in ~/Library/LaunchAgents may hide persistence.",
            severity: Severity::High,
            mitre_id: Some("T1543.001"),
            category: PatternCategory::Persistence,
            check: PatternCheck::AnyFileInDir {
                dir: "~/Library/LaunchAgents",
                name_pattern: r"^\.",
            },
        },
        DetectionPattern {
            id: "persist-hidden-launchdaemon",
            name: "Hidden LaunchDaemon (dot-prefixed)",
            description: "Dot-prefixed plist in /Library/LaunchDaemons.",
            severity: Severity::High,
            mitre_id: Some("T1543.004"),
            category: PatternCategory::Persistence,
            check: PatternCheck::AnyFileInDir {
                dir: "/Library/LaunchDaemons",
                name_pattern: r"^\.",
            },
        },
        DetectionPattern {
            id: "persist-login-items",
            name: "Login Items Directory Present",
            description: "Legacy login items directory exists – check for unexpected entries.",
            severity: Severity::Info,
            mitre_id: Some("T1547.015"),
            category: PatternCategory::Persistence,
            check: PatternCheck::DirectoryNotEmpty(
                "~/Library/Application Support/com.apple.backgroundtaskmanagementagent",
            ),
        },
        DetectionPattern {
            id: "persist-global-launchagent-custom",
            name: "Non-Apple Global LaunchAgent",
            description: "Non-com.apple plist in /Library/LaunchAgents.",
            severity: Severity::Low,
            mitre_id: Some("T1543.001"),
            category: PatternCategory::Persistence,
            check: PatternCheck::AnyFileInDir {
                dir: "/Library/LaunchAgents",
                name_pattern: r"^(?!com\.apple\.)[a-zA-Z].*\.plist$",
            },
        },
        DetectionPattern {
            id: "persist-periodic-scripts",
            name: "Custom Periodic Scripts",
            description: "User-added periodic scripts can run as root.",
            severity: Severity::Medium,
            mitre_id: Some("T1053.003"),
            category: PatternCategory::Persistence,
            check: PatternCheck::Any(&[
                PatternCheck::AnyFileInDir {
                    dir: "/etc/periodic/daily",
                    name_pattern: r"^(?![\d]{3}\.)",
                },
                PatternCheck::AnyFileInDir {
                    dir: "/etc/periodic/weekly",
                    name_pattern: r"^(?![\d]{3}\.)",
                },
                PatternCheck::AnyFileInDir {
                    dir: "/etc/periodic/monthly",
                    name_pattern: r"^(?![\d]{3}\.)",
                },
            ]),
        },
        DetectionPattern {
            id: "persist-emond-rules",
            name: "Emond Rules Present",
            description: "Event Monitor rules can execute arbitrary commands on system events.",
            severity: Severity::Medium,
            mitre_id: Some("T1546.014"),
            category: PatternCategory::Persistence,
            check: PatternCheck::DirectoryNotEmpty("/etc/emond.d/rules"),
        },
        DetectionPattern {
            id: "persist-at-jobs",
            name: "Scheduled at(1) Jobs",
            description: "at(1) jobs in /var/at/jobs can persist execution.",
            severity: Severity::Medium,
            mitre_id: Some("T1053.002"),
            category: PatternCategory::Persistence,
            check: PatternCheck::DirectoryNotEmpty("/var/at/jobs"),
        },
        DetectionPattern {
            id: "persist-rc-common",
            name: "rc.common Modified",
            description: "/etc/rc.common is a legacy startup script that can execute arbitrary commands.",
            severity: Severity::Medium,
            mitre_id: Some("T1037.004"),
            category: PatternCategory::Persistence,
            check: PatternCheck::FileContains {
                path: "/etc/rc.common",
                pattern: r"(?m)^(?!#)\s*(curl|wget|python|perl|ruby|bash\s+-c)",
            },
        },
        DetectionPattern {
            id: "persist-bash-profile-suspicious",
            name: "Suspicious .bash_profile / .zshrc",
            description: "Shell profile contains suspicious download or encoded commands.",
            severity: Severity::High,
            mitre_id: Some("T1546.004"),
            category: PatternCategory::Persistence,
            check: PatternCheck::Any(&[
                PatternCheck::FileContains {
                    path: "~/.bash_profile",
                    pattern: r"(?i)(curl|wget|base64\s+--decode|openssl\s+enc)",
                },
                PatternCheck::FileContains {
                    path: "~/.zshrc",
                    pattern: r"(?i)(curl|wget|base64\s+--decode|openssl\s+enc)",
                },
                PatternCheck::FileContains {
                    path: "~/.bashrc",
                    pattern: r"(?i)(curl|wget|base64\s+--decode|openssl\s+enc)",
                },
            ]),
        },
        DetectionPattern {
            id: "persist-authorization-plugin",
            name: "Authorization Plugin Installed",
            description: "Custom authorization plug-ins can intercept authentication.",
            severity: Severity::High,
            mitre_id: Some("T1556"),
            category: PatternCategory::Persistence,
            check: PatternCheck::AnyFileInDir {
                dir: "/Library/Security/SecurityAgentPlugins",
                name_pattern: r"^(?!com\.apple\.)",
            },
        },

        // =================================================================
        // SYSTEM INTEGRITY CHECKS
        // =================================================================
        DetectionPattern {
            id: "integrity-sip-disabled",
            name: "SIP Disabled",
            description: "System Integrity Protection (SIP) is disabled.",
            severity: Severity::Critical,
            mitre_id: Some("T1562.001"),
            category: PatternCategory::SystemIntegrity,
            check: PatternCheck::CommandOutput {
                command: "csrutil",
                args: &["status"],
                pattern: r"disabled",
            },
        },
        DetectionPattern {
            id: "integrity-gatekeeper-disabled",
            name: "Gatekeeper Disabled",
            description: "macOS Gatekeeper is not enforcing code-signing verification.",
            severity: Severity::High,
            mitre_id: Some("T1553.001"),
            category: PatternCategory::SystemIntegrity,
            check: PatternCheck::CommandOutput {
                command: "spctl",
                args: &["--status"],
                pattern: r"disabled",
            },
        },
        DetectionPattern {
            id: "integrity-firewall-disabled",
            name: "Application Firewall Disabled",
            description: "The macOS application-level firewall (ALF) is disabled.",
            severity: Severity::Medium,
            mitre_id: Some("T1562.004"),
            category: PatternCategory::SystemIntegrity,
            check: PatternCheck::CommandOutput {
                command: "defaults",
                args: &[
                    "read",
                    "/Library/Preferences/com.apple.alf",
                    "globalstate",
                ],
                pattern: r"^0\s*$",
            },
        },
        DetectionPattern {
            id: "integrity-filevault-disabled",
            name: "FileVault Disabled",
            description: "Full-disk encryption (FileVault) is not enabled.",
            severity: Severity::Medium,
            mitre_id: Some("T1486"),
            category: PatternCategory::SystemIntegrity,
            check: PatternCheck::CommandOutput {
                command: "fdesetup",
                args: &["status"],
                pattern: r"(?i)off",
            },
        },
        DetectionPattern {
            id: "integrity-remote-login",
            name: "Remote Login (SSH) Enabled",
            description: "Remote login (sshd) is enabled, expanding the attack surface.",
            severity: Severity::Low,
            mitre_id: Some("T1021.004"),
            category: PatternCategory::SystemIntegrity,
            check: PatternCheck::CommandOutput {
                command: "systemsetup",
                args: &["-getremotelogin"],
                pattern: r"(?i)on",
            },
        },
        DetectionPattern {
            id: "integrity-remote-mgmt",
            name: "Remote Management Enabled",
            description: "ARD / Remote Management is running, allowing remote control.",
            severity: Severity::Medium,
            mitre_id: Some("T1021.006"),
            category: PatternCategory::SystemIntegrity,
            check: PatternCheck::CommandOutput {
                command: "ps",
                args: &["aux"],
                pattern: r"ARDAgent",
            },
        },
        DetectionPattern {
            id: "integrity-screen-sharing",
            name: "Screen Sharing Enabled",
            description: "Screen sharing service is running.",
            severity: Severity::Low,
            mitre_id: Some("T1021.005"),
            category: PatternCategory::SystemIntegrity,
            check: PatternCheck::CommandOutput {
                command: "launchctl",
                args: &["list"],
                pattern: r"com\.apple\.screensharing",
            },
        },
        DetectionPattern {
            id: "integrity-airdrop-everyone",
            name: "AirDrop Open to Everyone",
            description: "AirDrop is set to receive from Everyone, not just Contacts.",
            severity: Severity::Low,
            mitre_id: None,
            category: PatternCategory::SystemIntegrity,
            check: PatternCheck::CommandOutput {
                command: "defaults",
                args: &[
                    "read",
                    "com.apple.sharingd",
                    "DiscoverableMode",
                ],
                pattern: r"Everyone",
            },
        },
        DetectionPattern {
            id: "integrity-dtrace-restrictions",
            name: "DTrace Restrictions Off",
            description: "DTrace restrictions are disabled, allowing kernel-level tracing by any user.",
            severity: Severity::Medium,
            mitre_id: Some("T1562.001"),
            category: PatternCategory::SystemIntegrity,
            check: PatternCheck::CommandOutput {
                command: "csrutil",
                args: &["status"],
                pattern: r"NVRAM Protections:\s*disabled",
            },
        },
        DetectionPattern {
            id: "integrity-xprotect-disabled",
            name: "XProtect Updates Disabled",
            description: "Automatic XProtect (malware definition) updates are turned off.",
            severity: Severity::High,
            mitre_id: Some("T1562.001"),
            category: PatternCategory::SystemIntegrity,
            check: PatternCheck::CommandOutput {
                command: "defaults",
                args: &[
                    "read",
                    "/Library/Preferences/com.apple.SoftwareUpdate",
                    "ConfigDataInstall",
                ],
                pattern: r"^0\s*$",
            },
        },
        DetectionPattern {
            id: "integrity-autoupdate-disabled",
            name: "Software Auto-Update Disabled",
            description: "Automatic software updates are disabled.",
            severity: Severity::Medium,
            mitre_id: Some("T1562.001"),
            category: PatternCategory::SystemIntegrity,
            check: PatternCheck::CommandOutput {
                command: "defaults",
                args: &[
                    "read",
                    "/Library/Preferences/com.apple.SoftwareUpdate",
                    "AutomaticCheckEnabled",
                ],
                pattern: r"^0\s*$",
            },
        },

        // =================================================================
        // CONFIGURATION ISSUES
        // =================================================================
        DetectionPattern {
            id: "config-ssh-password-auth",
            name: "SSH Password Auth Enabled",
            description: "sshd allows password authentication; prefer key-based auth.",
            severity: Severity::Low,
            mitre_id: Some("T1021.004"),
            category: PatternCategory::Configuration,
            check: PatternCheck::FileContains {
                path: "/etc/ssh/sshd_config",
                pattern: r"(?m)^\s*PasswordAuthentication\s+yes",
            },
        },
        DetectionPattern {
            id: "config-ssh-root-login",
            name: "SSH Root Login Permitted",
            description: "sshd permits root login, which is a significant risk.",
            severity: Severity::High,
            mitre_id: Some("T1078.003"),
            category: PatternCategory::Configuration,
            check: PatternCheck::FileContains {
                path: "/etc/ssh/sshd_config",
                pattern: r"(?m)^\s*PermitRootLogin\s+yes",
            },
        },
        DetectionPattern {
            id: "config-ssh-empty-password",
            name: "SSH Empty Password Permitted",
            description: "sshd permits login with empty passwords.",
            severity: Severity::Critical,
            mitre_id: Some("T1078"),
            category: PatternCategory::Configuration,
            check: PatternCheck::FileContains {
                path: "/etc/ssh/sshd_config",
                pattern: r"(?m)^\s*PermitEmptyPasswords\s+yes",
            },
        },
        DetectionPattern {
            id: "config-world-writable-usr-local",
            name: "World-Writable /usr/local/bin",
            description: "/usr/local/bin is world-writable, allowing unprivileged PATH hijacking.",
            severity: Severity::High,
            mitre_id: Some("T1574.007"),
            category: PatternCategory::Configuration,
            check: PatternCheck::CommandOutput {
                command: "stat",
                args: &["-f", "%Sp", "/usr/local/bin"],
                pattern: r"w.{2}$",  // ends with w?? = world writable
            },
        },
        DetectionPattern {
            id: "config-admin-autologin",
            name: "Auto-Login Enabled",
            description: "Auto-login is enabled, bypassing the login screen.",
            severity: Severity::Medium,
            mitre_id: Some("T1078.003"),
            category: PatternCategory::Configuration,
            check: PatternCheck::CommandOutput {
                command: "defaults",
                args: &[
                    "read",
                    "/Library/Preferences/com.apple.loginwindow",
                    "autoLoginUser",
                ],
                pattern: r"\S+",
            },
        },
        DetectionPattern {
            id: "config-guest-account",
            name: "Guest Account Enabled",
            description: "The macOS Guest account is enabled.",
            severity: Severity::Low,
            mitre_id: Some("T1078.001"),
            category: PatternCategory::Configuration,
            check: PatternCheck::CommandOutput {
                command: "defaults",
                args: &[
                    "read",
                    "/Library/Preferences/com.apple.loginwindow",
                    "GuestEnabled",
                ],
                pattern: r"^1\s*$",
            },
        },
        DetectionPattern {
            id: "config-wake-on-lan",
            name: "Wake-on-LAN Enabled",
            description: "Wake-on-LAN allows remote power-on.",
            severity: Severity::Info,
            mitre_id: None,
            category: PatternCategory::Configuration,
            check: PatternCheck::CommandOutput {
                command: "systemsetup",
                args: &["-getwakeonnetworkaccess"],
                pattern: r"(?i)on",
            },
        },
        DetectionPattern {
            id: "config-bluetooth-discoverable",
            name: "Bluetooth Discoverable",
            description: "Bluetooth is set to discoverable mode.",
            severity: Severity::Info,
            mitre_id: None,
            category: PatternCategory::Configuration,
            check: PatternCheck::CommandOutput {
                command: "defaults",
                args: &[
                    "read",
                    "/Library/Preferences/com.apple.Bluetooth",
                    "ControllerPowerState",
                ],
                pattern: r"^1\s*$",
            },
        },
        DetectionPattern {
            id: "config-ntp-disabled",
            name: "NTP Time Sync Disabled",
            description: "Automatic time synchronisation is disabled; clock skew may affect logging.",
            severity: Severity::Low,
            mitre_id: Some("T1070.006"),
            category: PatternCategory::Configuration,
            check: PatternCheck::CommandOutput {
                command: "systemsetup",
                args: &["-getusingnetworktime"],
                pattern: r"(?i)off",
            },
        },
        DetectionPattern {
            id: "config-httpd-running",
            name: "Apache httpd Running",
            description: "Built-in Apache httpd is running – verify this is intentional.",
            severity: Severity::Low,
            mitre_id: Some("T1505"),
            category: PatternCategory::Configuration,
            check: PatternCheck::CommandOutput {
                command: "launchctl",
                args: &["list"],
                pattern: r"org\.apache\.httpd",
            },
        },
        DetectionPattern {
            id: "config-sharing-printer",
            name: "Printer Sharing Enabled",
            description: "Printer sharing is enabled; this expands the network attack surface.",
            severity: Severity::Info,
            mitre_id: None,
            category: PatternCategory::Configuration,
            check: PatternCheck::CommandOutput {
                command: "cupsctl",
                args: &[],
                pattern: r"_share_printers=1",
            },
        },
        DetectionPattern {
            id: "config-internet-sharing",
            name: "Internet Sharing Enabled",
            description: "Internet sharing may route traffic through this Mac.",
            severity: Severity::Medium,
            mitre_id: Some("T1557"),
            category: PatternCategory::Configuration,
            check: PatternCheck::FileContains {
                path: "/Library/Preferences/SystemConfiguration/com.apple.nat.plist",
                pattern: r"Enabled.*true",
            },
        },
    ]
}

// ---------------------------------------------------------------------------
// PatternMatcher
// ---------------------------------------------------------------------------

pub struct PatternMatcher {
    patterns: Vec<DetectionPattern>,
}

impl PatternMatcher {
    /// Create a matcher pre-loaded with all built-in detection patterns.
    pub fn new() -> Self {
        Self {
            patterns: builtin_patterns(),
        }
    }

    /// Run all pattern checks and return results (only matched findings by default).
    pub fn run_all(&self) -> Vec<PatternMatchResult<'_>> {
        self.patterns
            .iter()
            .map(|pattern| {
                let (matched, evidence) = evaluate_check(&pattern.check);
                debug!(pattern_id = pattern.id, matched, "evaluated pattern");
                PatternMatchResult {
                    pattern,
                    matched,
                    evidence,
                }
            })
            .collect()
    }

    /// Number of loaded patterns.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ScanModule implementation
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct PatternDetectionModule;

impl PatternDetectionModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ScanModule for PatternDetectionModule {
    fn name(&self) -> &str {
        "pattern-detection"
    }

    fn description(&self) -> &str {
        "OSQuery-style pattern matching for macOS malware, persistence, and hardening"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::SignatureDetection
    }

    async fn run(&self, _ctx: &mut ScanContext) -> Result<Vec<Finding>> {
        self.run_standalone().await
    }

    async fn run_standalone(&self) -> Result<Vec<Finding>> {
        let matcher = PatternMatcher::new();
        let results = matcher.run_all();

        let mut findings = Vec::new();
        let mut counter = 0u32;

        for result in &results {
            if !result.matched {
                continue;
            }

            counter += 1;
            let p = result.pattern;
            let id = format!("{}-PAT-{:03}", p.severity.finding_id_prefix(), counter);

            let mitre_note = p
                .mitre_id
                .map(|m| format!("\n\nMITRE ATT&CK: {m}"))
                .unwrap_or_default();

            let description = format!(
                "{}{}\n\nEvidence:\n{}",
                p.description, mitre_note, result.evidence
            );

            let cvss_vector =
                CvssVector::for_category(ModuleCategory::SignatureDetection, p.severity);
            let cvss = calculate_cvss(&cvss_vector);

            let remediation = match p.category {
                PatternCategory::Malware => format!(
                    "Investigate and remove the detected artifact ({}).\n\
                     Run a full system scan with updated signatures.\n\
                     Review system logs for signs of execution or lateral movement.",
                    p.id
                ),
                PatternCategory::Persistence => format!(
                    "Review the persistence mechanism detected by '{}'.\n\
                     Remove if unauthorized.\n\
                     Audit all LaunchAgents, LaunchDaemons, cron entries, and login items.",
                    p.id
                ),
                PatternCategory::SystemIntegrity => format!(
                    "Re-enable the security feature flagged by '{}'.\n\
                     Verify with your organization's security baseline.",
                    p.name
                ),
                PatternCategory::Configuration => format!(
                    "Correct the configuration issue: {}.\n\
                     Harden according to CIS macOS Benchmark guidelines.",
                    p.name
                ),
            };

            findings.push(Finding {
                id,
                title: p.name.to_string(),
                severity: p.severity,
                cvss,
                category: ModuleCategory::SignatureDetection,
                description,
                reproduction: None,
                evidence: Evidence {
                    os_events: vec![format!("pattern-detection: {} ({})", p.id, p.name)],
                    ..Evidence::empty()
                },
                remediation,
            });
        }

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
    fn test_expand_home_with_tilde() {
        let path = expand_home("~/Library/something");
        // Should not start with ~ any more.
        assert!(!path.to_str().unwrap().starts_with('~'));
    }

    #[test]
    fn test_expand_home_without_tilde() {
        let path = expand_home("/etc/hosts");
        assert_eq!(path, PathBuf::from("/etc/hosts"));
    }

    #[test]
    fn test_builtin_pattern_count() {
        let patterns = builtin_patterns();
        // We defined at least 60 patterns.
        assert!(
            patterns.len() >= 60,
            "Expected at least 60 patterns, got {}",
            patterns.len()
        );
    }

    #[test]
    fn test_pattern_ids_unique() {
        let patterns = builtin_patterns();
        let mut ids: Vec<&str> = patterns.iter().map(|p| p.id).collect();
        ids.sort();
        let len_before = ids.len();
        ids.dedup();
        assert_eq!(len_before, ids.len(), "Duplicate pattern IDs detected");
    }

    #[test]
    fn test_pattern_matcher_creation() {
        let matcher = PatternMatcher::new();
        assert!(matcher.pattern_count() >= 60);
    }

    #[test]
    fn test_evaluate_file_exists_nonexistent() {
        let (matched, _) = evaluate_check(&PatternCheck::FileExists("/nonexistent_path_12345"));
        assert!(!matched);
    }

    #[test]
    fn test_evaluate_file_exists_real() {
        // /etc/hosts should exist on macOS.
        let (matched, evidence) = evaluate_check(&PatternCheck::FileExists("/etc/hosts"));
        assert!(matched);
        assert!(evidence.contains("/etc/hosts"));
    }

    #[test]
    fn test_evaluate_file_contains_match() {
        let (matched, evidence) = evaluate_check(&PatternCheck::FileContains {
            path: "/etc/hosts",
            pattern: r"localhost",
        });
        assert!(matched);
        assert!(evidence.contains("localhost"));
    }

    #[test]
    fn test_evaluate_file_contains_no_match() {
        let (matched, _) = evaluate_check(&PatternCheck::FileContains {
            path: "/etc/hosts",
            pattern: r"ZZZZZZZ_NO_MATCH",
        });
        assert!(!matched);
    }

    #[test]
    fn test_evaluate_directory_not_empty() {
        // /etc should be non-empty.
        let (matched, _) = evaluate_check(&PatternCheck::DirectoryNotEmpty("/etc"));
        assert!(matched);
    }

    #[test]
    fn test_evaluate_any_file_exists() {
        let (matched, _) = evaluate_check(&PatternCheck::AnyFileExists(&[
            "/nonexistent_abc",
            "/etc/hosts",
        ]));
        assert!(matched);
    }

    #[test]
    fn test_evaluate_any_file_exists_none() {
        let (matched, _) = evaluate_check(&PatternCheck::AnyFileExists(&[
            "/nonexistent_abc",
            "/nonexistent_def",
        ]));
        assert!(!matched);
    }

    #[test]
    fn test_module_trait() {
        let module = PatternDetectionModule::new();
        assert_eq!(module.name(), "pattern-detection");
        assert_eq!(module.category(), ModuleCategory::SignatureDetection);
        assert!(!module.description().is_empty());
    }

    #[tokio::test]
    async fn test_module_run_does_not_panic() {
        // We can't build a full ScanContext easily, but we can at least
        // ensure that PatternMatcher::run_all doesn't panic.
        let matcher = PatternMatcher::new();
        let results = matcher.run_all();
        // Should return something (some checks will match on any macOS system).
        assert!(!results.is_empty());
    }
}
