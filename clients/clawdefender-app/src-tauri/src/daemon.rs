use std::path::PathBuf;

/// Get the daemon socket path (must match ClawConfig::default_socket_path).
pub fn socket_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".local/share/clawdefender/clawdefender.sock")
}

/// Check if the daemon is running by checking if the socket exists
pub fn is_daemon_running() -> bool {
    let sock = socket_path();
    if !sock.exists() {
        return false;
    }
    // Try to connect to verify the socket is alive
    std::os::unix::net::UnixStream::connect(&sock).is_ok()
}

/// Start the daemon process directly (bypassing the CLI).
pub fn start_daemon_process() -> Result<(), String> {
    let daemon_bin = find_daemon_binary()
        .ok_or_else(|| "ClawDefender daemon binary not found. Build with `cargo build -p clawdefender-daemon` or install to /usr/local/bin.".to_string())?;

    tracing::info!(path = %daemon_bin.display(), "Starting daemon directly");

    let mut child = std::process::Command::new(&daemon_bin)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start daemon: {}", e))?;

    tracing::info!(pid = child.id(), "Daemon process spawned");

    // Brief wait to catch immediate startup failures (e.g. missing libs, bad config)
    std::thread::sleep(std::time::Duration::from_millis(300));
    match child.try_wait() {
        Ok(Some(status)) => {
            // Process already exited — read stderr for diagnostics
            let stderr_output = child
                .stderr
                .take()
                .and_then(|mut err| {
                    use std::io::Read;
                    let mut buf = String::new();
                    err.read_to_string(&mut buf).ok().map(|_| buf)
                })
                .unwrap_or_default();
            Err(format!(
                "Daemon exited immediately with {status}. stderr: {stderr_output}"
            ))
        }
        Ok(None) => {
            // Still running — daemon is starting up normally
            Ok(())
        }
        Err(e) => {
            tracing::warn!(error = %e, "Could not check daemon process status");
            Ok(())
        }
    }
}

/// Stop the daemon process directly via IPC socket or PID file.
pub fn stop_daemon_process() -> Result<(), String> {
    let sock_path = socket_path();

    // Try IPC shutdown first
    if let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&sock_path) {
        use std::io::Write;
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(3)));
        let _ = writeln!(stream, "\"shutdown\"");
        tracing::info!("Sent shutdown signal via IPC socket");
        // Give daemon time to shut down
        std::thread::sleep(std::time::Duration::from_secs(1));
        return Ok(());
    }

    // Fall back to PID file
    let home = std::env::var("HOME").unwrap_or_default();
    let pid_path = PathBuf::from(&home).join(".local/share/clawdefender/clawdefender.pid");
    if let Ok(pid_str) = std::fs::read_to_string(&pid_path) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            unsafe { libc::kill(pid, libc::SIGTERM); }
            tracing::info!(pid = pid, "Sent SIGTERM to daemon");
            std::fs::remove_file(&pid_path).ok();
            return Ok(());
        }
    }

    Err("Could not find running daemon to stop".to_string())
}

/// Find the `clawdefender-daemon` binary by searching sidecar location,
/// system install paths, and workspace target directories (for development).
fn find_daemon_binary() -> Option<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();

    // 1. Check Tauri sidecar resolution (production bundles)
    // In production .app, sidecars are in the same directory as the exe
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let sidecar = exe_dir.join("clawdefender-daemon");
            if sidecar.exists() {
                return Some(sidecar);
            }
        }
    }

    // 2. System install locations
    let system_paths = vec![
        PathBuf::from("/usr/local/bin/clawdefender-daemon"),
        PathBuf::from(&home).join(".cargo/bin/clawdefender-daemon"),
    ];
    for p in &system_paths {
        if p.exists() {
            return Some(p.clone());
        }
    }

    // 3. Workspace target directories (development mode)
    // Walk up from exe to find workspace root's target/debug/
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    {
        let mut search = exe_dir.as_path();
        for _ in 0..10 {
            let debug_bin = search.join("target/debug/clawdefender-daemon");
            let release_bin = search.join("target/release/clawdefender-daemon");
            if debug_bin.exists() {
                return Some(debug_bin);
            }
            if release_bin.exists() {
                return Some(release_bin);
            }
            match search.parent() {
                Some(parent) => search = parent,
                None => break,
            }
        }
    }

    None
}

/// Health check - verify daemon is responsive
#[allow(dead_code)]
pub async fn health_check() -> Result<bool, String> {
    Ok(is_daemon_running())
}
