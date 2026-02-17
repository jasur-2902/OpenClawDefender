//! Integration tests for the ClawDefender auto-installer system.

use clawdefender_guard::installer::{
    detect::{self, InstallationStatus},
    download::{compute_sha256, verify_checksum, Downloader, MockDownloader},
    platform::{Arch, Os, PlatformInfo, Shell},
    uninstall::{self, UninstallOptions, PATH_MARKER},
    version::{self, InstallMetadata},
    AutoInstaller, ConsentMode, InstallResult,
};
use std::path::Path;
use tempfile::TempDir;

// ─── Platform Detection ──────────────────────────────────────

#[test]
fn test_platform_detects_current_os() {
    let info = PlatformInfo::detect();
    if cfg!(target_os = "macos") {
        assert_eq!(info.os, Os::MacOS);
    } else if cfg!(target_os = "linux") {
        assert_eq!(info.os, Os::Linux);
    }
}

#[test]
fn test_platform_detects_current_arch() {
    let info = PlatformInfo::detect();
    if cfg!(target_arch = "aarch64") {
        assert_eq!(info.arch, Arch::Arm64);
    } else if cfg!(target_arch = "x86_64") {
        assert_eq!(info.arch, Arch::X86_64);
    }
}

#[test]
fn test_platform_string_format() {
    let info = PlatformInfo::detect();
    let ps = info.platform_string();
    // Should be "os-arch" format
    assert!(ps.contains('-'), "Platform string should contain a dash: {ps}");
    assert!(!ps.is_empty());
}

#[test]
fn test_platform_detects_shell() {
    let info = PlatformInfo::detect();
    // On CI or dev machines, SHELL should be set
    if std::env::var("SHELL").is_ok() {
        assert_ne!(info.shell, Shell::Unknown("unknown".to_string()));
    }
}

// ─── Installation Detection ─────────────────────────────────

#[test]
fn test_detect_not_installed_in_empty_paths() {
    let tmp = TempDir::new().unwrap();
    let paths = vec![tmp.path().join("nonexistent")];
    let status = detect::detect_installation_in_paths(&paths, None);
    assert_eq!(status, InstallationStatus::NotInstalled);
}

#[test]
fn test_detect_not_installed_system_wide() {
    // This test just verifies the function doesn't panic
    // It may or may not find clawdefender on the system
    let _status = detect::detect_installation(None);
}

// ─── Version Comparison ─────────────────────────────────────

#[test]
fn test_version_less_than_basic() {
    assert!(detect::version_less_than("0.1.0", "0.2.0"));
    assert!(detect::version_less_than("0.1.0", "1.0.0"));
    assert!(detect::version_less_than("1.0.0", "1.0.1"));
}

#[test]
fn test_version_not_less_than() {
    assert!(!detect::version_less_than("0.2.0", "0.1.0"));
    assert!(!detect::version_less_than("0.1.0", "0.1.0"));
    assert!(!detect::version_less_than("2.0.0", "1.0.0"));
}

#[test]
fn test_version_parse_output() {
    let result = detect::parse_version_output("clawdefender 0.3.1");
    assert_eq!(result.unwrap(), "0.3.1");

    let result = detect::parse_version_output("0.4.0\n");
    assert_eq!(result.unwrap(), "0.4.0");

    let result = detect::parse_version_output("garbage text");
    assert!(result.is_err());
}

// ─── Checksum Verification ──────────────────────────────────

#[test]
fn test_checksum_valid() {
    let data = b"clawdefender binary content";
    let hash = compute_sha256(data);
    let checksum_file = format!("{hash}  clawdefender\n");
    assert!(verify_checksum(data, &checksum_file).is_ok());
}

#[test]
fn test_checksum_invalid() {
    let data = b"clawdefender binary content";
    let bad_checksum = "0000000000000000000000000000000000000000000000000000000000000000  clawdefender\n";
    let result = verify_checksum(data, bad_checksum);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Checksum mismatch"));
}

#[test]
fn test_checksum_empty_file() {
    let data = b"data";
    let result = verify_checksum(data, "");
    assert!(result.is_err());
}

// ─── Consent Modes ──────────────────────────────────────────

#[test]
fn test_consent_pre_authorized() {
    let mode = ConsentMode::PreAuthorized;
    assert!(mode.is_authorized());
}

#[test]
fn test_consent_headless_env_var() {
    let mode = ConsentMode::HeadlessEnvVar;
    assert!(mode.is_authorized());
}

#[test]
fn test_consent_fallback_only() {
    let mode = ConsentMode::FallbackOnly;
    assert!(!mode.is_authorized());
}

#[test]
fn test_consent_interactive() {
    let mode = ConsentMode::Interactive;
    assert!(!mode.is_authorized());
}

#[tokio::test]
async fn test_fallback_mode_skips_install() {
    let downloader = MockDownloader::new(b"binary".to_vec(), "0.1.0");
    let installer = AutoInstaller::new(Box::new(downloader), ConsentMode::FallbackOnly);
    let tmp = TempDir::new().unwrap();
    let installer = installer
        .with_base_dir(tmp.path().join(".clawdefender"))
        .with_shell_config(tmp.path().join(".zshrc"));

    let result = installer.install().await.unwrap();
    assert_eq!(result, InstallResult::FallbackMode);
}

// ─── Installation Metadata ──────────────────────────────────

#[test]
fn test_metadata_write_and_read() {
    let tmp = TempDir::new().unwrap();
    let meta_path = tmp.path().join("install.json");

    let meta = InstallMetadata::new(
        "0.1.0",
        Path::new("/home/user/.clawdefender/bin/clawdefender"),
        "macos-arm64",
    );
    meta.write_to(&meta_path).unwrap();

    let loaded = InstallMetadata::read_from(&meta_path).unwrap();
    assert_eq!(loaded.version, "0.1.0");
    assert_eq!(loaded.platform, "macos-arm64");
    assert_eq!(loaded.install_method, "auto");
    assert_eq!(
        loaded.install_path,
        "/home/user/.clawdefender/bin/clawdefender"
    );
}

#[test]
fn test_metadata_creates_parent_dirs() {
    let tmp = TempDir::new().unwrap();
    let meta_path = tmp.path().join("deep/nested/dir/install.json");
    let meta = InstallMetadata::new("0.2.0", Path::new("/usr/local/bin/cd"), "linux-x86_64");
    assert!(meta.write_to(&meta_path).is_ok());
    assert!(meta_path.exists());
}

#[test]
fn test_check_for_update_available() {
    let msg = version::check_for_update("0.1.0", "0.2.0");
    assert!(msg.is_some());
    assert!(msg.unwrap().contains("0.1.0"));
}

#[test]
fn test_check_for_update_not_available() {
    assert!(version::check_for_update("0.2.0", "0.2.0").is_none());
    assert!(version::check_for_update("0.3.0", "0.2.0").is_none());
}

// ─── PATH Modification ─────────────────────────────────────

#[test]
fn test_path_addition_to_shell_config() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join(".zshrc");

    // Create initial config
    std::fs::write(&config_path, "# existing config\nexport FOO=bar\n").unwrap();

    // Simulate adding PATH (replicate what AutoInstaller does)
    let path_line = format!("export PATH=\"$HOME/.clawdefender/bin:$PATH\" {PATH_MARKER}");
    let mut content = std::fs::read_to_string(&config_path).unwrap();
    content.push_str(&path_line);
    content.push('\n');
    std::fs::write(&config_path, &content).unwrap();

    // Verify it was added
    let final_content = std::fs::read_to_string(&config_path).unwrap();
    assert!(final_content.contains(PATH_MARKER));
    assert!(final_content.contains(".clawdefender/bin"));
}

#[test]
fn test_path_removal_from_shell_config() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join(".zshrc");

    let content = format!(
        "# existing config\nexport FOO=bar\nexport PATH=\"$HOME/.clawdefender/bin:$PATH\" {PATH_MARKER}\n"
    );
    std::fs::write(&config_path, &content).unwrap();

    // Remove PATH entry
    let removed = uninstall::remove_path_from_shell_config(&config_path).unwrap();
    assert!(removed);

    let final_content = std::fs::read_to_string(&config_path).unwrap();
    assert!(!final_content.contains(PATH_MARKER));
    assert!(final_content.contains("export FOO=bar"));
}

#[test]
fn test_path_removal_noop_when_not_present() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join(".zshrc");
    std::fs::write(&config_path, "# no clawdefender here\n").unwrap();

    let removed = uninstall::remove_path_from_shell_config(&config_path).unwrap();
    assert!(!removed);
}

#[test]
fn test_path_removal_nonexistent_file() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("nonexistent_rc");
    let removed = uninstall::remove_path_from_shell_config(&config_path).unwrap();
    assert!(!removed);
}

// ─── Full Installation Flow ─────────────────────────────────

#[tokio::test]
async fn test_full_install_with_mock() {
    let tmp = TempDir::new().unwrap();
    let base_dir = tmp.path().join(".clawdefender");
    let shell_config = tmp.path().join(".zshrc");

    // Create initial shell config
    std::fs::write(&shell_config, "# my zshrc\n").unwrap();

    let binary_data = b"fake-clawdefender-binary".to_vec();
    let downloader = MockDownloader::new(binary_data, "0.1.0");

    let installer = AutoInstaller::new(Box::new(downloader), ConsentMode::PreAuthorized)
        .with_base_dir(base_dir.clone())
        .with_shell_config(shell_config.clone());

    let result = installer.install().await.unwrap();

    match result {
        InstallResult::Installed { path, version } => {
            assert_eq!(version, "0.1.0");
            assert!(path.to_string_lossy().contains(".clawdefender/bin"));
            // Binary should exist
            assert!(path.exists());
            // Metadata should exist
            assert!(base_dir.join("install.json").exists());
            // Shell config should be modified
            let config = std::fs::read_to_string(&shell_config).unwrap();
            assert!(config.contains(PATH_MARKER));
        }
        other => panic!("Expected Installed, got {other:?}"),
    }
}

#[tokio::test]
async fn test_install_already_installed() {
    let tmp = TempDir::new().unwrap();
    let base_dir = tmp.path().join(".clawdefender");
    let bin_dir = base_dir.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();

    // Create a fake binary
    std::fs::write(bin_dir.join("clawdefender"), b"fake binary").unwrap();

    // Create metadata indicating current version
    let meta = InstallMetadata::new(
        "0.1.0",
        &bin_dir.join("clawdefender"),
        "macos-arm64",
    );
    meta.write_to(&base_dir.join("install.json")).unwrap();

    let downloader = MockDownloader::new(b"new-binary".to_vec(), "0.1.0");
    let installer = AutoInstaller::new(Box::new(downloader), ConsentMode::PreAuthorized)
        .with_base_dir(base_dir)
        .with_shell_config(tmp.path().join(".zshrc"));

    let result = installer.install().await.unwrap();
    match result {
        InstallResult::AlreadyInstalled { version, .. } => {
            assert_eq!(version, "0.1.0");
        }
        other => panic!("Expected AlreadyInstalled, got {other:?}"),
    }
}

// ─── Rollback on Failure ────────────────────────────────────

#[tokio::test]
async fn test_rollback_on_download_failure() {
    let tmp = TempDir::new().unwrap();
    let base_dir = tmp.path().join(".clawdefender");
    let shell_config = tmp.path().join(".zshrc");
    std::fs::write(&shell_config, "# config\n").unwrap();

    let downloader = MockDownloader::failing();
    let installer = AutoInstaller::new(Box::new(downloader), ConsentMode::PreAuthorized)
        .with_base_dir(base_dir.clone())
        .with_shell_config(shell_config.clone());

    let result = installer.install().await;
    assert!(result.is_err());

    // Binary should not exist after rollback
    assert!(!base_dir.join("bin/clawdefender").exists());

    // Shell config should not have been modified
    let config = std::fs::read_to_string(&shell_config).unwrap();
    assert!(!config.contains(PATH_MARKER));
}

// ─── Uninstallation ─────────────────────────────────────────

#[test]
fn test_uninstall_removes_binary_and_path() {
    let tmp = TempDir::new().unwrap();
    let base_dir = tmp.path().join(".clawdefender");
    let bin_dir = base_dir.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();

    let binary_path = bin_dir.join("clawdefender");
    std::fs::write(&binary_path, b"fake binary").unwrap();

    let shell_config = tmp.path().join(".zshrc");
    std::fs::write(
        &shell_config,
        format!("# config\nexport PATH=\"...\" {PATH_MARKER}\n"),
    )
    .unwrap();

    let opts = UninstallOptions {
        remove_config: false,
        binary_path: binary_path.clone(),
        shell_config_path: shell_config.clone(),
        base_dir: base_dir.clone(),
    };

    let result = uninstall::uninstall(&opts).unwrap();
    assert!(result.binary_removed);
    assert!(result.path_cleaned);
    assert!(!result.config_removed);

    assert!(!binary_path.exists());
    let config = std::fs::read_to_string(&shell_config).unwrap();
    assert!(!config.contains(PATH_MARKER));
}

#[test]
fn test_uninstall_with_config_removal() {
    let tmp = TempDir::new().unwrap();
    let base_dir = tmp.path().join(".clawdefender");
    let bin_dir = base_dir.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();

    let binary_path = bin_dir.join("clawdefender");
    std::fs::write(&binary_path, b"fake binary").unwrap();

    // Create some config files
    std::fs::write(base_dir.join("config.toml"), "key = 'val'").unwrap();

    let shell_config = tmp.path().join(".zshrc");
    std::fs::write(&shell_config, "# config\n").unwrap();

    let opts = UninstallOptions {
        remove_config: true,
        binary_path,
        shell_config_path: shell_config,
        base_dir: base_dir.clone(),
    };

    let result = uninstall::uninstall(&opts).unwrap();
    assert!(result.binary_removed);
    assert!(result.config_removed);
    assert!(!base_dir.exists());
}

// ─── Mock Downloader Tests ──────────────────────────────────

#[tokio::test]
async fn test_mock_downloader_returns_binary() {
    let mock = MockDownloader::new(b"test binary data".to_vec(), "1.0.0");
    let data = mock.download("https://example.com/binary").await.unwrap();
    assert_eq!(data, b"test binary data");
}

#[tokio::test]
async fn test_mock_downloader_returns_checksum() {
    let binary = b"test binary data".to_vec();
    let expected_hash = compute_sha256(&binary);
    let mock = MockDownloader::new(binary, "1.0.0");

    let checksum_data = mock
        .download("https://example.com/binary.sha256")
        .await
        .unwrap();
    let checksum_str = String::from_utf8(checksum_data).unwrap();
    assert!(checksum_str.contains(&expected_hash));
}

#[tokio::test]
async fn test_mock_downloader_failing() {
    let mock = MockDownloader::failing();
    assert!(mock.download("https://example.com/binary").await.is_err());
    assert!(mock.get_latest_version().await.is_err());
}

#[tokio::test]
async fn test_mock_downloader_version() {
    let mock = MockDownloader::new(vec![], "2.5.0");
    let ver = mock.get_latest_version().await.unwrap();
    assert_eq!(ver, "2.5.0");
}
