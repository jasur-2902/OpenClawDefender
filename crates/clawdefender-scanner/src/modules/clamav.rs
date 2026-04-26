use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use async_trait::async_trait;
use tracing;

use crate::finding::{Evidence, Finding, ModuleCategory, Severity};
use crate::modules::{ScanContext, ScanModule};

/// Common socket paths where clamd listens.
const SOCKET_PATHS: &[&str] = &[
    "/tmp/clamd.socket",
    "/var/run/clamav/clamd.ctl",
    "/usr/local/var/run/clamav/clamd.socket",
];

/// Maximum file size to scan (100 MB).
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Maximum age of files to scan (7 days).
const MAX_FILE_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Chunk size for INSTREAM protocol (8 KB).
const CHUNK_SIZE: usize = 8 * 1024;

/// Timeout for socket operations (30 seconds).
const SOCKET_TIMEOUT: Duration = Duration::from_secs(30);

/// Status of the ClamAV daemon on this system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClamAvStatus {
    Available(PathBuf),
    NotInstalled,
    NotRunning,
}

/// A finding from the ClamAV scanner.
pub struct ClamAvFinding {
    pub file_path: PathBuf,
    pub virus_name: String,
}

/// Scanner that talks to clamd over a Unix socket.
pub struct ClamAvScanner {
    socket_path: PathBuf,
}

impl ClamAvScanner {
    /// Detect whether clamd is available by trying known socket paths.
    pub fn detect() -> ClamAvStatus {
        for path_str in SOCKET_PATHS {
            let path = Path::new(path_str);
            if !path.exists() {
                continue;
            }
            match ping_clamd(path) {
                Ok(true) => return ClamAvStatus::Available(path.to_path_buf()),
                Ok(false) | Err(_) => continue,
            }
        }

        // Check if any socket path exists (daemon installed but not running)
        let any_socket_exists = SOCKET_PATHS.iter().any(|p| Path::new(p).exists());
        if any_socket_exists {
            ClamAvStatus::NotRunning
        } else {
            ClamAvStatus::NotInstalled
        }
    }

    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Scan a single file using the INSTREAM protocol.
    /// Returns `Some(virus_name)` if malware is detected, `None` if clean.
    pub fn scan_file(&self, path: &Path) -> Result<Option<String>> {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to read metadata for {}", path.display()))?;

        if metadata.len() > MAX_FILE_SIZE {
            tracing::debug!(path = %path.display(), "Skipping file larger than 100MB");
            return Ok(None);
        }

        let file_data = std::fs::read(path)
            .with_context(|| format!("Failed to read file {}", path.display()))?;

        let mut stream = UnixStream::connect(&self.socket_path).with_context(|| {
            format!(
                "Failed to connect to clamd at {}",
                self.socket_path.display()
            )
        })?;

        stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
        stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;

        // Send INSTREAM command (null-terminated)
        stream.write_all(b"zINSTREAM\0")?;

        // Send file data in chunks: [4-byte big-endian length][chunk data]
        for chunk in file_data.chunks(CHUNK_SIZE) {
            let len = chunk.len() as u32;
            stream.write_all(&len.to_be_bytes())?;
            stream.write_all(chunk)?;
        }

        // Signal end of stream with 4 zero bytes
        stream.write_all(&0u32.to_be_bytes())?;
        stream.flush()?;

        // Read response
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        let response_str = String::from_utf8_lossy(&response);
        let response_str = response_str.trim();

        parse_scan_response(response_str)
    }

    /// Scan recent files in ~/Downloads and ~/Desktop (less than 7 days old).
    pub fn scan_recent_downloads(&self) -> Result<Vec<ClamAvFinding>> {
        let home = match dirs_home() {
            Some(h) => h,
            None => {
                tracing::warn!("Could not determine home directory");
                return Ok(Vec::new());
            }
        };

        let scan_dirs = [home.join("Downloads"), home.join("Desktop")];
        let now = SystemTime::now();
        let mut findings = Vec::new();

        for dir in &scan_dirs {
            if !dir.exists() {
                continue;
            }

            let walker = walkdir::WalkDir::new(dir)
                .max_depth(3)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok());

            for entry in walker {
                if !entry.file_type().is_file() {
                    continue;
                }

                let path = entry.path();

                // Check file age
                let metadata = match std::fs::metadata(path) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                let modified = match metadata.modified() {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                let age = match now.duration_since(modified) {
                    Ok(d) => d,
                    Err(_) => continue,
                };

                if age > MAX_FILE_AGE {
                    continue;
                }

                // Skip files that are too large
                if metadata.len() > MAX_FILE_SIZE {
                    continue;
                }

                match self.scan_file(path) {
                    Ok(Some(virus_name)) => {
                        tracing::warn!(
                            path = %path.display(),
                            virus = %virus_name,
                            "ClamAV detected malware"
                        );
                        findings.push(ClamAvFinding {
                            file_path: path.to_path_buf(),
                            virus_name,
                        });
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!(
                            path = %path.display(),
                            error = %e,
                            "Failed to scan file with ClamAV"
                        );
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Scan binaries referenced by suspicious LaunchAgents/LaunchDaemons.
    /// Extracts Program/ProgramArguments from plists in standard launch directories.
    pub fn scan_suspicious_launch_binaries(&self) -> Result<Vec<ClamAvFinding>> {
        let mut dirs: Vec<PathBuf> = vec![
            "/Library/LaunchAgents".into(),
            "/Library/LaunchDaemons".into(),
        ];
        if let Some(home) = dirs_home() {
            dirs.push(home.join("Library/LaunchAgents"));
        }

        let mut findings = Vec::new();
        let mut scanned: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

        for dir in &dirs {
            let entries = match fs::read_dir(dir) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for entry in entries.flatten() {
                let plist_path = entry.path();
                if plist_path.extension().and_then(|e| e.to_str()) != Some("plist") {
                    continue;
                }

                let binary_path = match extract_plist_binary(&plist_path) {
                    Some(p) => p,
                    None => continue,
                };

                // Skip Apple system binaries
                if is_apple_system_path(&binary_path) {
                    continue;
                }

                // Skip if already scanned or doesn't exist
                if !binary_path.exists() || !scanned.insert(binary_path.clone()) {
                    continue;
                }

                match self.scan_file(&binary_path) {
                    Ok(Some(virus_name)) => {
                        tracing::warn!(
                            binary = %binary_path.display(),
                            plist = %plist_path.display(),
                            virus = %virus_name,
                            "ClamAV detected malware in LaunchAgent binary"
                        );
                        findings.push(ClamAvFinding {
                            file_path: binary_path,
                            virus_name,
                        });
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!(
                            binary = %binary_path.display(),
                            error = %e,
                            "Failed to scan LaunchAgent binary"
                        );
                    }
                }
            }
        }

        Ok(findings)
    }
}

/// Extract the binary path from a LaunchAgent/LaunchDaemon plist.
fn extract_plist_binary(path: &Path) -> Option<PathBuf> {
    // Try structured plist parse
    if let Ok(val) = plist::from_file::<_, plist::Value>(path) {
        if let Some(dict) = val.as_dictionary() {
            if let Some(prog) = dict.get("Program").and_then(|v| v.as_string()) {
                return Some(PathBuf::from(prog));
            }
            if let Some(args) = dict.get("ProgramArguments").and_then(|v| v.as_array()) {
                if let Some(first) = args.first().and_then(|v| v.as_string()) {
                    return Some(PathBuf::from(first));
                }
            }
        }
    }

    // Fallback: XML text search
    if let Ok(content) = fs::read_to_string(path) {
        if let Some(pos) = content.find("<key>Program</key>") {
            let after = &content[pos + "<key>Program</key>".len()..];
            if let Some(start) = after.find("<string>") {
                let start = start + "<string>".len();
                if let Some(end) = after[start..].find("</string>") {
                    return Some(PathBuf::from(&after[start..start + end]));
                }
            }
        }
        if let Some(pos) = content.find("<key>ProgramArguments</key>") {
            let after = &content[pos + "<key>ProgramArguments</key>".len()..];
            if let Some(start) = after.find("<string>") {
                let start = start + "<string>".len();
                if let Some(end) = after[start..].find("</string>") {
                    return Some(PathBuf::from(&after[start..start + end]));
                }
            }
        }
    }

    None
}

/// Check if a path is a known Apple system binary location.
fn is_apple_system_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    const APPLE_PREFIXES: &[&str] = &[
        "/usr/libexec/",
        "/usr/sbin/",
        "/usr/bin/",
        "/System/",
        "/sbin/",
        "/bin/",
    ];
    APPLE_PREFIXES
        .iter()
        .any(|prefix| path_str.starts_with(prefix))
}

/// Send PING to clamd and check for PONG response.
fn ping_clamd(socket_path: &Path) -> Result<bool> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    stream.write_all(b"PING\n")?;
    stream.flush()?;

    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf)?;
    let response = String::from_utf8_lossy(&buf[..n]);

    Ok(response.trim() == "PONG")
}

/// Parse a clamd scan response.
/// Expected formats:
///   "stream: OK"
///   "stream: <virusname> FOUND"
fn parse_scan_response(response: &str) -> Result<Option<String>> {
    if response.ends_with("OK") {
        Ok(None)
    } else if response.ends_with("FOUND") {
        // Format: "stream: VirusName FOUND"
        let after_colon = response
            .split_once(':')
            .map(|(_, rest)| rest.trim())
            .unwrap_or(response);

        // Strip trailing " FOUND"
        let virus_name = after_colon
            .strip_suffix("FOUND")
            .map(|s| s.trim())
            .unwrap_or(after_colon)
            .to_string();

        if virus_name.is_empty() {
            Ok(Some("Unknown".to_string()))
        } else {
            Ok(Some(virus_name))
        }
    } else {
        anyhow::bail!("Unexpected clamd response: {}", response)
    }
}

/// Get the user's home directory.
fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// ScanModule implementation for ClamAV integration.
#[derive(Default)]
pub struct ClamAvModule;

impl ClamAvModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ScanModule for ClamAvModule {
    fn name(&self) -> &str {
        "clamav-scan"
    }

    fn description(&self) -> &str {
        "Scans recent downloads and desktop files using ClamAV (if installed)"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Configuration
    }

    async fn run(&self, _ctx: &mut ScanContext) -> Result<Vec<Finding>> {
        self.run_standalone().await
    }

    async fn run_standalone(&self) -> Result<Vec<Finding>> {
        let status = ClamAvScanner::detect();

        match status {
            ClamAvStatus::NotInstalled => Ok(vec![Finding {
                id: "INFO-CLAMAV-001".into(),
                title: "ClamAV not available".into(),
                severity: Severity::Info,
                cvss: 0.0,
                category: ModuleCategory::Configuration,
                description: "ClamAV is not installed on this system. \
                        Install ClamAV for additional malware detection coverage. \
                        Run: brew install clamav"
                    .into(),
                reproduction: None,
                evidence: Evidence::empty(),
                remediation: "Install ClamAV: brew install clamav && \
                        sudo freshclam && brew services start clamav"
                    .into(),
            }]),
            ClamAvStatus::NotRunning => Ok(vec![Finding {
                id: "INFO-CLAMAV-002".into(),
                title: "ClamAV daemon not running".into(),
                severity: Severity::Info,
                cvss: 0.0,
                category: ModuleCategory::Configuration,
                description: "ClamAV appears to be installed but the clamd daemon is not running. \
                        Start the daemon for real-time malware scanning."
                    .into(),
                reproduction: None,
                evidence: Evidence::empty(),
                remediation:
                    "Start clamd: brew services start clamav (or: sudo freshclam && clamd)".into(),
            }]),
            ClamAvStatus::Available(socket_path) => {
                let scanner = ClamAvScanner::new(socket_path);
                let mut all_clamav_findings: Vec<ClamAvFinding> = Vec::new();

                // Scan recent downloads and desktop files
                match scanner.scan_recent_downloads() {
                    Ok(results) => all_clamav_findings.extend(results),
                    Err(e) => tracing::warn!(error = %e, "ClamAV download scan failed"),
                }

                // Scan binaries referenced by suspicious LaunchAgents
                match scanner.scan_suspicious_launch_binaries() {
                    Ok(results) => all_clamav_findings.extend(results),
                    Err(e) => tracing::warn!(error = %e, "ClamAV LaunchAgent scan failed"),
                }

                if all_clamav_findings.is_empty() {
                    Ok(vec![Finding {
                        id: "INFO-CLAMAV-003".into(),
                        title: "ClamAV scan clean".into(),
                        severity: Severity::Info,
                        cvss: 0.0,
                        category: ModuleCategory::Configuration,
                        description: "ClamAV scanned recent files in ~/Downloads, ~/Desktop, \
                            and binaries referenced by LaunchAgents/LaunchDaemons. \
                            No threats were detected."
                            .into(),
                        reproduction: None,
                        evidence: Evidence::empty(),
                        remediation:
                            "No action needed. Continue to keep ClamAV signatures updated \
                            with: freshclam"
                                .into(),
                    }])
                } else {
                    let mut findings = Vec::new();

                    for (i, cf) in all_clamav_findings.iter().enumerate() {
                        findings.push(Finding {
                            id: format!("HIGH-CLAMAV-{:03}", i + 1),
                            title: format!("Malware detected: {}", cf.virus_name),
                            severity: Severity::High,
                            cvss: 7.8,
                            category: ModuleCategory::SignatureDetection,
                            description: format!(
                                "ClamAV detected malware '{}' in file: {}",
                                cf.virus_name,
                                cf.file_path.display()
                            ),
                            reproduction: None,
                            evidence: Evidence {
                                files_modified: vec![cf.file_path.display().to_string()],
                                ..Evidence::empty()
                            },
                            remediation: format!(
                                "Quarantine or delete the infected file: {}. \
                                Investigate how the file was downloaded and scan \
                                related files for additional threats.",
                                cf.file_path.display()
                            ),
                        });
                    }

                    Ok(findings)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scan_response_clean() {
        let result = parse_scan_response("stream: OK").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_scan_response_virus_found() {
        let result = parse_scan_response("stream: Win.Test.EICAR_HDB-1 FOUND").unwrap();
        assert_eq!(result, Some("Win.Test.EICAR_HDB-1".to_string()));
    }

    #[test]
    fn test_parse_scan_response_unexpected() {
        let result = parse_scan_response("stream: ERROR something went wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_clamav_status_variants() {
        let not_installed = ClamAvStatus::NotInstalled;
        let not_running = ClamAvStatus::NotRunning;
        let available = ClamAvStatus::Available(PathBuf::from("/tmp/clamd.socket"));

        assert_eq!(not_installed, ClamAvStatus::NotInstalled);
        assert_eq!(not_running, ClamAvStatus::NotRunning);
        assert_eq!(
            available,
            ClamAvStatus::Available(PathBuf::from("/tmp/clamd.socket"))
        );
    }

    #[test]
    fn test_dirs_home() {
        // HOME should be set in test environment
        let home = dirs_home();
        assert!(home.is_some());
    }

    #[test]
    fn test_module_metadata() {
        let module = ClamAvModule::new();
        assert_eq!(module.name(), "clamav-scan");
        assert_eq!(module.category(), ModuleCategory::Configuration);
        assert!(!module.description().is_empty());
    }

    #[test]
    fn test_is_apple_system_path() {
        assert!(is_apple_system_path(Path::new("/usr/bin/python3")));
        assert!(is_apple_system_path(Path::new("/usr/libexec/something")));
        assert!(is_apple_system_path(Path::new("/System/Library/something")));
        assert!(is_apple_system_path(Path::new("/sbin/mount")));
        assert!(!is_apple_system_path(Path::new("/usr/local/bin/custom")));
        assert!(!is_apple_system_path(Path::new("/tmp/malware")));
        assert!(!is_apple_system_path(Path::new(
            "/Applications/App.app/Contents/MacOS/app"
        )));
    }

    #[test]
    fn test_extract_plist_binary_xml() {
        let dir = tempfile::tempdir().unwrap();
        let plist_path = dir.path().join("test.plist");
        std::fs::write(&plist_path, r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.test.agent</string>
    <key>Program</key>
    <string>/usr/local/bin/testbin</string>
</dict>
</plist>"#).unwrap();

        let result = extract_plist_binary(&plist_path);
        assert_eq!(result, Some(PathBuf::from("/usr/local/bin/testbin")));
    }

    #[test]
    fn test_extract_plist_binary_program_arguments() {
        let dir = tempfile::tempdir().unwrap();
        let plist_path = dir.path().join("test2.plist");
        std::fs::write(&plist_path, r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.test.agent2</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/homebrew/bin/daemon</string>
        <string>--foreground</string>
    </array>
</dict>
</plist>"#).unwrap();

        let result = extract_plist_binary(&plist_path);
        assert_eq!(result, Some(PathBuf::from("/opt/homebrew/bin/daemon")));
    }

    #[test]
    fn test_extract_plist_binary_no_program() {
        let dir = tempfile::tempdir().unwrap();
        let plist_path = dir.path().join("test3.plist");
        std::fs::write(&plist_path, r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.test.empty</string>
</dict>
</plist>"#).unwrap();

        let result = extract_plist_binary(&plist_path);
        assert_eq!(result, None);
    }
}
