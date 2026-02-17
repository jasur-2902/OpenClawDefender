//! `clawdefender daemon` — manage the ClawDefender daemon lifecycle.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clawdefender_core::config::ClawConfig;

/// Start the daemon as a background process.
pub fn start(_config: &ClawConfig) -> Result<()> {
    let pid_path = pid_file_path();

    // Check if already running.
    if let Some(pid) = read_pid(&pid_path) {
        if is_process_alive(pid) {
            println!("Daemon is already running (PID {pid})");
            return Ok(());
        }
        // Stale PID file — clean up.
        std::fs::remove_file(&pid_path).ok();
    }

    // Find the daemon binary.
    let daemon_bin = find_daemon_binary()?;

    let config_path = default_config_path();

    let child = std::process::Command::new(&daemon_bin)
        .args(["--config", &config_path.to_string_lossy()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("failed to start daemon: {}", daemon_bin.display()))?;

    println!("Daemon started (PID {})", child.id());
    Ok(())
}

/// Stop the running daemon.
pub fn stop(config: &ClawConfig) -> Result<()> {
    let pid_path = pid_file_path();

    // Try IPC shutdown first.
    if let Ok(mut stream) = UnixStream::connect(&config.daemon_socket_path) {
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
        let msg = serde_json::to_string(&"shutdown")?;
        writeln!(stream, "{msg}")?;
        println!("Shutdown signal sent via IPC socket");
        // Give it a moment.
        std::thread::sleep(Duration::from_secs(1));
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
            }
        } else {
            println!("Daemon not running (stale PID file)");
        }
        std::fs::remove_file(&pid_path).ok();
    } else if UnixStream::connect(&config.daemon_socket_path).is_err() {
        println!("Daemon is not running");
    }

    Ok(())
}

/// Show the daemon's status and subsystem information.
pub fn status(config: &ClawConfig) -> Result<()> {
    let pid_path = pid_file_path();

    println!("ClawDefender Daemon Status");
    println!("==========================");

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
                    println!("  Messages total:    {}", json.get("messages_total").and_then(|v| v.as_u64()).unwrap_or(0));
                    println!("  Messages allowed:  {}", json.get("messages_allowed").and_then(|v| v.as_u64()).unwrap_or(0));
                    println!("  Messages blocked:  {}", json.get("messages_blocked").and_then(|v| v.as_u64()).unwrap_or(0));
                    println!("  Messages prompted: {}", json.get("messages_prompted").and_then(|v| v.as_u64()).unwrap_or(0));
                } else {
                    println!("  IPC: connected (unexpected response)");
                }
            }
        }
        Err(_) => {
            println!("  IPC: not available");
        }
    }

    println!("  Socket:  {}", config.daemon_socket_path.display());
    println!("  Policy:  {}", config.policy_path.display());
    println!("  Audit:   {}", config.audit_log_path.display());
    println!("  Sensor:  {}", config.sensor_config_path.display());

    Ok(())
}

/// Restart the daemon (stop + start).
pub fn restart(config: &ClawConfig) -> Result<()> {
    println!("Stopping daemon...");
    stop(config)?;
    std::thread::sleep(Duration::from_secs(1));
    println!("Starting daemon...");
    start(config)?;
    Ok(())
}

// --- Helpers ---

fn pid_file_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".local/share/clawdefender/clawdefender.pid")
    } else {
        PathBuf::from("/tmp/clawdefender.pid")
    }
}

fn default_config_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".config/clawdefender/config.toml")
    } else {
        PathBuf::from("/tmp/clawdefender/config.toml")
    }
}

fn read_pid(path: &PathBuf) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse()
        .ok()
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
    // Check next to the current binary first.
    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            let candidate = dir.join("clawdefender-daemon");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    // Check PATH.
    if let Ok(output) = std::process::Command::new("which")
        .arg("clawdefender-daemon")
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
        "Could not find clawdefender-daemon binary.\n\
         Make sure it is installed and in your PATH."
    )
}
