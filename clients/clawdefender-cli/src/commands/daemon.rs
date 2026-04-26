//! `rookbot daemon` — manage the RookBot daemon lifecycle.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Subcommand;
use clawdefender_core::config::ClawConfig;

/// Daemon lifecycle management commands.
#[derive(Debug, Subcommand)]
pub enum DaemonAction {
    /// Start the daemon process
    Start {
        /// Run in foreground for debugging
        #[arg(long)]
        foreground: bool,
    },

    /// Stop the daemon process
    Stop {
        /// Force kill after timeout
        #[arg(long)]
        force: bool,
    },

    /// Restart the daemon (stop + start)
    Restart,

    /// Show daemon status and subsystem information
    Status,

    /// View daemon logs
    Logs {
        /// Follow log output (tail -f style)
        #[arg(short, long)]
        follow: bool,

        /// Number of lines to show
        #[arg(short = 'n', long, default_value = "50")]
        lines: usize,

        /// Filter by log level (error, warn, info, debug, trace)
        #[arg(short, long)]
        level: Option<String>,
    },

    /// Install privileged eslogger helper (requires sudo)
    InstallHelper,

    /// Uninstall privileged eslogger helper
    UninstallHelper,

    /// Full installation: binaries, directories, LaunchAgent
    Install {
        /// Install LaunchAgent to start at login
        #[arg(long)]
        launch_at_login: bool,
    },

    /// Full uninstallation
    Uninstall {
        /// Keep user data and logs
        #[arg(long)]
        keep_data: bool,
    },
}

/// Execute a daemon command.
pub fn execute(action: DaemonAction, config: &ClawConfig) -> Result<()> {
    match action {
        DaemonAction::Start { foreground } => start(config, foreground),
        DaemonAction::Stop { force } => stop(config, force),
        DaemonAction::Restart => restart(config),
        DaemonAction::Status => status(config),
        DaemonAction::Logs {
            follow,
            lines,
            level,
        } => logs(follow, lines, level),
        DaemonAction::InstallHelper => install_helper(),
        DaemonAction::UninstallHelper => uninstall_helper(),
        DaemonAction::Install { launch_at_login } => install(launch_at_login),
        DaemonAction::Uninstall { keep_data } => uninstall(keep_data),
    }
}

/// Start the daemon as a background process.
fn start(config: &ClawConfig, foreground: bool) -> Result<()> {
    let pid_path = pid_file_path();

    // Check if already running.
    if let Some(pid) = read_pid(&pid_path) {
        if is_process_alive(pid) {
            println!("Daemon is already running (PID {pid})");
            return Ok(());
        }
        // Stale PID file — clean up.
        fs::remove_file(&pid_path).ok();
    }

    // Find the daemon binary.
    let daemon_bin = find_daemon_binary()?;
    let config_path = default_config_path();

    if foreground {
        // Run in foreground for debugging.
        println!("Starting daemon in foreground mode...");
        let status = std::process::Command::new(&daemon_bin)
            .args(["--config", &config_path.to_string_lossy()])
            .status()
            .with_context(|| format!("failed to start daemon: {}", daemon_bin.display()))?;

        if !status.success() {
            anyhow::bail!("Daemon exited with status: {}", status);
        }
        return Ok(());
    }

    // Start as background process.
    let mut child = std::process::Command::new(&daemon_bin)
        .args(["--config", &config_path.to_string_lossy()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start daemon: {}", daemon_bin.display()))?;

    let child_pid = child.id();

    // Brief wait to catch immediate startup failures.
    std::thread::sleep(Duration::from_millis(200));
    match child.try_wait() {
        Ok(Some(status)) => {
            // Process exited immediately — capture stderr.
            let mut stderr = String::new();
            if let Some(mut err) = child.stderr.take() {
                err.read_to_string(&mut stderr).ok();
            }
            anyhow::bail!(
                "Daemon exited immediately with {}: {}",
                status,
                stderr.trim()
            );
        }
        Ok(None) => {
            println!("Daemon started (PID {})", child_pid);
        }
        Err(e) => {
            anyhow::bail!("Failed to check daemon status: {}", e);
        }
    }

    // Poll IPC socket until ready (timeout 15s).
    let socket_path = &config.daemon_socket_path;
    let timeout = Duration::from_secs(15);
    let start = Instant::now();

    print!("Waiting for daemon to be ready");
    std::io::stdout().flush().ok();

    loop {
        if start.elapsed() > timeout {
            println!("\nWarning: Daemon started but IPC socket not ready after 15s");
            break;
        }

        if let Ok(mut stream) = UnixStream::connect(socket_path) {
            stream.set_read_timeout(Some(Duration::from_secs(1))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(1))).ok();

            // Try a ping.
            if writeln!(stream, "ping").is_ok() {
                stream.flush().ok();
                let mut reader = BufReader::new(stream);
                let mut response = String::new();
                if reader.read_line(&mut response).is_ok() && !response.is_empty() {
                    println!(" ready!");
                    return Ok(());
                }
            }
        }

        print!(".");
        std::io::stdout().flush().ok();
        std::thread::sleep(Duration::from_millis(500));
    }

    Ok(())
}

/// Stop the running daemon.
fn stop(config: &ClawConfig, force: bool) -> Result<()> {
    let pid_path = pid_file_path();

    // Try IPC shutdown first.
    if let Ok(mut stream) = UnixStream::connect(&config.daemon_socket_path) {
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
        let msg = serde_json::to_string(&"shutdown")?;
        writeln!(stream, "{msg}")?;
        println!("Shutdown signal sent via IPC socket");

        // Wait for clean exit (10s timeout).
        let timeout = Duration::from_secs(10);
        let start = Instant::now();

        while start.elapsed() < timeout {
            if UnixStream::connect(&config.daemon_socket_path).is_err() {
                println!("Daemon stopped cleanly");
                fs::remove_file(&pid_path).ok();
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        println!("Warning: Daemon did not stop within 10s");
    }

    // Fall back to PID file + kill.
    if let Some(pid) = read_pid(&pid_path) {
        if is_process_alive(pid) {
            #[cfg(unix)]
            {
                // Send SIGTERM.
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
                println!("Sent SIGTERM to PID {pid}");

                if force {
                    // Wait a bit, then SIGKILL if still alive.
                    std::thread::sleep(Duration::from_secs(5));
                    if is_process_alive(pid) {
                        unsafe {
                            libc::kill(pid as i32, libc::SIGKILL);
                        }
                        println!("Force killed PID {pid} (SIGKILL)");
                    }
                }
            }
        } else {
            println!("Daemon not running (stale PID file)");
        }
        fs::remove_file(&pid_path).ok();
    } else if UnixStream::connect(&config.daemon_socket_path).is_err() {
        println!("Daemon is not running");
    }

    Ok(())
}

/// Show the daemon's status and subsystem information.
fn status(config: &ClawConfig) -> Result<()> {
    let pid_path = pid_file_path();

    println!("RookBot Daemon Status");
    println!("=====================");

    // Check PID file.
    match read_pid(&pid_path) {
        Some(pid) => {
            if is_process_alive(pid) {
                println!("  Process: running (PID {pid})");
            } else {
                println!("  Process: not running (stale PID file)");
            }
        }
        None => {
            println!("  Process: not running (no PID file)");
        }
    }

    // Try IPC status query.
    match UnixStream::connect(&config.daemon_socket_path) {
        Ok(mut stream) => {
            stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(3))).ok();
            writeln!(stream, "status")?;
            stream.flush()?;

            let mut reader = BufReader::new(stream);
            let mut response = String::new();
            if reader.read_line(&mut response).is_ok() && !response.is_empty() {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
                    println!("  IPC: connected");

                    // Show subsystem information.
                    if let Some(subsystems) = json.get("subsystems").and_then(|v| v.as_object()) {
                        println!("\n  Subsystems:");
                        for (name, status) in subsystems {
                            println!("    {}: {}", name, status.as_str().unwrap_or("unknown"));
                        }
                    }

                    // Show statistics.
                    println!("\n  Statistics:");
                    println!(
                        "    Messages total:    {}",
                        json.get("messages_total")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                    );
                    println!(
                        "    Messages allowed:  {}",
                        json.get("messages_allowed")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                    );
                    println!(
                        "    Messages blocked:  {}",
                        json.get("messages_blocked")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                    );
                    println!(
                        "    Messages prompted: {}",
                        json.get("messages_prompted")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                    );

                    // Show uptime.
                    if let Some(uptime) = json.get("uptime_seconds").and_then(|v| v.as_u64()) {
                        println!("    Uptime:            {}s", uptime);
                    }
                } else {
                    println!("  IPC: connected (unexpected response)");
                }
            }
        }
        Err(_) => {
            println!("  IPC: not available");
        }
    }

    println!("\n  Configuration:");
    println!("    Socket:  {}", config.daemon_socket_path.display());
    println!("    Policy:  {}", config.policy_path.display());
    println!("    Audit:   {}", config.audit_log_path.display());
    println!("    Sensor:  {}", config.sensor_config_path.display());

    Ok(())
}

/// Restart the daemon (stop + start).
fn restart(config: &ClawConfig) -> Result<()> {
    println!("Stopping daemon...");

    let old_pid = read_pid(&pid_file_path());

    stop(config, false)?;
    std::thread::sleep(Duration::from_secs(1));

    println!("Starting daemon...");
    start(config, false)?;

    // Verify new PID.
    if let (Some(old), Some(new)) = (old_pid, read_pid(&pid_file_path())) {
        if old != new {
            println!("Daemon restarted successfully (PID {} -> {})", old, new);
        }
    }

    Ok(())
}

/// View daemon logs.
fn logs(follow: bool, lines: usize, level: Option<String>) -> Result<()> {
    let log_path = log_file_path();

    if !log_path.exists() {
        anyhow::bail!("Log file not found: {}", log_path.display());
    }

    if follow {
        // Follow mode — tail -f style.
        println!("Following logs (Ctrl+C to stop)...\n");

        let mut file = fs::File::open(&log_path)?;
        let mut reader = BufReader::new(file);

        // Skip to last N lines.
        let mut all_lines = Vec::new();
        let mut line = String::new();
        while reader.read_line(&mut line).is_ok() && !line.is_empty() {
            all_lines.push(line.clone());
            line.clear();
        }

        let start_idx = all_lines.len().saturating_sub(lines);
        for line in &all_lines[start_idx..] {
            if should_show_line(line, &level) {
                print!("{}", line);
            }
        }

        // Now follow new lines.
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    // EOF — wait and try again.
                    std::thread::sleep(Duration::from_millis(100));
                    // Re-open file to handle rotation.
                    file = fs::File::open(&log_path)?;
                    reader = BufReader::new(file);
                }
                Ok(_) => {
                    if should_show_line(&line, &level) {
                        print!("{}", line);
                        std::io::stdout().flush().ok();
                    }
                }
                Err(e) => {
                    eprintln!("Error reading log: {}", e);
                    break;
                }
            }
        }
    } else {
        // Show last N lines.
        let file = fs::File::open(&log_path)?;
        let reader = BufReader::new(file);

        let mut all_lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();

        // Filter by level if specified.
        if level.is_some() {
            all_lines.retain(|line| should_show_line(line, &level));
        }

        let start_idx = all_lines.len().saturating_sub(lines);
        for line in &all_lines[start_idx..] {
            println!("{}", line);
        }
    }

    Ok(())
}

/// Install privileged eslogger helper.
fn install_helper() -> Result<()> {
    // Check for sudo.
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!(
            "This command requires sudo privileges.\nRun: sudo rookbot daemon install-helper"
        );
    }

    println!("Installing privileged eslogger helper...");

    let helper_bin = find_helper_binary()?;
    let install_path = PathBuf::from("/Library/PrivilegedHelperTools/com.rookbot.eslogger");

    // Copy binary.
    fs::copy(&helper_bin, &install_path)
        .with_context(|| format!("failed to copy helper to {}", install_path.display()))?;

    // Set ownership and permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&install_path, perms)?;
    }

    // Create LaunchDaemon plist.
    let plist_path = PathBuf::from("/Library/LaunchDaemons/com.rookbot.eslogger.plist");
    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.rookbot.eslogger</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/rookbot-eslogger.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/rookbot-eslogger.log</string>
</dict>
</plist>
"#,
        install_path.display()
    );

    fs::write(&plist_path, plist_content)
        .with_context(|| format!("failed to write plist to {}", plist_path.display()))?;

    // Load the LaunchDaemon.
    let output = std::process::Command::new("launchctl")
        .args(["load", plist_path.to_str().unwrap()])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Warning: launchctl load failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    println!("Eslogger helper installed successfully.");
    println!("  Binary: {}", install_path.display());
    println!("  Plist:  {}", plist_path.display());

    Ok(())
}

/// Uninstall privileged eslogger helper.
fn uninstall_helper() -> Result<()> {
    // Check for sudo.
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!(
            "This command requires sudo privileges.\nRun: sudo rookbot daemon uninstall-helper"
        );
    }

    println!("Uninstalling privileged eslogger helper...");

    let plist_path = PathBuf::from("/Library/LaunchDaemons/com.rookbot.eslogger.plist");
    let install_path = PathBuf::from("/Library/PrivilegedHelperTools/com.rookbot.eslogger");

    // Unload the LaunchDaemon.
    if plist_path.exists() {
        let output = std::process::Command::new("launchctl")
            .args(["unload", plist_path.to_str().unwrap()])
            .output()?;

        if !output.status.success() {
            eprintln!(
                "Warning: launchctl unload failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        fs::remove_file(&plist_path)?;
        println!("  Removed plist: {}", plist_path.display());
    }

    // Remove binary.
    if install_path.exists() {
        fs::remove_file(&install_path)?;
        println!("  Removed binary: {}", install_path.display());
    }

    println!("Eslogger helper uninstalled successfully.");

    Ok(())
}

/// Full installation.
fn install(launch_at_login: bool) -> Result<()> {
    println!("Installing RookBot...");

    // Create directories.
    let data_dir = data_dir_path();
    let config_dir = config_dir_path();
    let log_dir = data_dir.clone();

    for dir in [&data_dir, &config_dir, &log_dir] {
        fs::create_dir_all(dir)
            .with_context(|| format!("failed to create directory: {}", dir.display()))?;
        println!("  Created directory: {}", dir.display());
    }

    // Copy binaries.
    let daemon_bin = find_daemon_binary()?;
    let cli_bin = std::env::current_exe()?;

    let install_bin_dir = PathBuf::from("/usr/local/bin");
    let daemon_install = install_bin_dir.join("rookbot-daemon");
    let cli_install = install_bin_dir.join("rookbot");

    if daemon_install.exists() {
        println!(
            "  Daemon binary already exists: {}",
            daemon_install.display()
        );
    } else {
        fs::copy(&daemon_bin, &daemon_install)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o755);
            fs::set_permissions(&daemon_install, perms)?;
        }
        println!("  Installed daemon: {}", daemon_install.display());
    }

    if cli_install.exists() {
        println!("  CLI binary already exists: {}", cli_install.display());
    } else {
        fs::copy(&cli_bin, &cli_install)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o755);
            fs::set_permissions(&cli_install, perms)?;
        }
        println!("  Installed CLI: {}", cli_install.display());
    }

    // Create default config if it doesn't exist.
    let config_path = default_config_path();
    if !config_path.exists() {
        let default_config = include_str!("../default-config.toml");
        fs::write(&config_path, default_config)?;
        println!("  Created default config: {}", config_path.display());
    }

    // Install LaunchAgent if requested.
    if launch_at_login {
        install_launch_agent()?;
    }

    println!("\nInstallation complete!");
    println!("  Run `rookbot daemon start` to start the daemon.");

    Ok(())
}

/// Full uninstallation.
fn uninstall(keep_data: bool) -> Result<()> {
    println!("Uninstalling RookBot...");

    // Stop daemon first.
    let config = ClawConfig::default();
    if let Some(_pid) = read_pid(&pid_file_path()) {
        println!("  Stopping daemon...");
        stop(&config, true).ok();
    }

    // Remove LaunchAgent.
    remove_launch_agent()?;

    // Remove binaries.
    let daemon_install = PathBuf::from("/usr/local/bin/rookbot-daemon");
    let cli_install = PathBuf::from("/usr/local/bin/rookbot");

    for bin in [&daemon_install, &cli_install] {
        if bin.exists() {
            fs::remove_file(bin)?;
            println!("  Removed binary: {}", bin.display());
        }
    }

    // Remove data directories if requested.
    if !keep_data {
        let data_dir = data_dir_path();
        let config_dir = config_dir_path();

        for dir in [&data_dir, &config_dir] {
            if dir.exists() {
                fs::remove_dir_all(dir)?;
                println!("  Removed directory: {}", dir.display());
            }
        }
    } else {
        println!("  Kept user data (--keep-data)");
    }

    println!("\nUninstallation complete!");

    Ok(())
}

// --- Helpers ---

fn pid_file_path() -> PathBuf {
    data_dir_path().join("rookbot.pid")
}

fn log_file_path() -> PathBuf {
    data_dir_path().join("daemon.log")
}

fn data_dir_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".local/share/rookbot")
    } else {
        PathBuf::from("/tmp/rookbot")
    }
}

fn config_dir_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".config/rookbot")
    } else {
        PathBuf::from("/tmp/rookbot")
    }
}

fn default_config_path() -> PathBuf {
    config_dir_path().join("config.toml")
}

fn read_pid(path: &PathBuf) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn is_process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // kill(pid, 0) checks if process exists without sending a signal.
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

fn find_daemon_binary() -> Result<PathBuf> {
    // Check next to the current binary first (works in dev + production).
    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            let candidate = dir.join("rookbot-daemon");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    // Check common install locations.
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        for candidate in [
            PathBuf::from("/usr/local/bin/rookbot-daemon"),
            home.join(".cargo/bin/rookbot-daemon"),
        ] {
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    // Walk up from current exe to find workspace target directories.
    if let Ok(current) = std::env::current_exe() {
        let mut search = current.as_path();
        for _ in 0..10 {
            if let Some(parent) = search.parent() {
                let debug_bin = parent.join("target/debug/rookbot-daemon");
                let release_bin = parent.join("target/release/rookbot-daemon");
                if debug_bin.exists() {
                    return Ok(debug_bin);
                }
                if release_bin.exists() {
                    return Ok(release_bin);
                }
                search = parent;
            } else {
                break;
            }
        }
    }

    // Check PATH.
    if let Ok(output) = std::process::Command::new("which")
        .arg("rookbot-daemon")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }

    anyhow::bail!(
        "Could not find rookbot-daemon binary.\n\
         Make sure it is built with `cargo build -p clawdefender-daemon` or installed to /usr/local/bin."
    )
}

fn find_helper_binary() -> Result<PathBuf> {
    // Check common locations for the eslogger helper.
    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            let candidate = dir.join("rookbot-eslogger");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    // Check target directories.
    if let Ok(current) = std::env::current_exe() {
        let mut search = current.as_path();
        for _ in 0..10 {
            if let Some(parent) = search.parent() {
                let debug_bin = parent.join("target/debug/rookbot-eslogger");
                let release_bin = parent.join("target/release/rookbot-eslogger");
                if debug_bin.exists() {
                    return Ok(debug_bin);
                }
                if release_bin.exists() {
                    return Ok(release_bin);
                }
                search = parent;
            } else {
                break;
            }
        }
    }

    anyhow::bail!("Could not find rookbot-eslogger helper binary")
}

fn should_show_line(line: &str, level_filter: &Option<String>) -> bool {
    if let Some(level) = level_filter {
        let level_upper = level.to_uppercase();
        // Simple log level filtering — assumes logs contain level indicators.
        line.contains(&level_upper)
    } else {
        true
    }
}

fn install_launch_agent() -> Result<()> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let agents_dir = PathBuf::from(&home).join("Library/LaunchAgents");
    fs::create_dir_all(&agents_dir)?;

    let plist_path = agents_dir.join("com.rookbot.daemon.plist");
    let daemon_path = PathBuf::from("/usr/local/bin/rookbot-daemon");
    let config_path = default_config_path();

    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.rookbot.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>--config</string>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{}/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>{}/daemon.log</string>
</dict>
</plist>
"#,
        daemon_path.display(),
        config_path.display(),
        data_dir_path().display(),
        data_dir_path().display()
    );

    fs::write(&plist_path, plist_content)?;

    // Load the LaunchAgent.
    let output = std::process::Command::new("launchctl")
        .args(["load", plist_path.to_str().unwrap()])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Warning: launchctl load failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        println!("  Installed LaunchAgent: {}", plist_path.display());
    }

    Ok(())
}

fn remove_launch_agent() -> Result<()> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let plist_path = PathBuf::from(&home).join("Library/LaunchAgents/com.rookbot.daemon.plist");

    if plist_path.exists() {
        // Unload first.
        let output = std::process::Command::new("launchctl")
            .args(["unload", plist_path.to_str().unwrap()])
            .output()?;

        if !output.status.success() {
            eprintln!(
                "Warning: launchctl unload failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        fs::remove_file(&plist_path)?;
        println!("  Removed LaunchAgent: {}", plist_path.display());
    }

    Ok(())
}
