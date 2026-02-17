use std::path::PathBuf;

/// Get the daemon socket path
pub fn socket_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".clawdefender/daemon.sock")
}

/// Check if the daemon is running by checking if the socket exists
pub fn is_daemon_running() -> bool {
    let sock = socket_path();
    if !sock.exists() {
        return false;
    }
    // Try to connect to verify the socket is alive
    match std::os::unix::net::UnixStream::connect(&sock) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Start the daemon process
pub fn start_daemon_process() -> Result<(), String> {
    // Look for clawdefender binary in common locations
    let possible_paths = vec![
        PathBuf::from("/usr/local/bin/clawdefender"),
        PathBuf::from(std::env::var("HOME").unwrap_or_default())
            .join(".cargo/bin/clawdefender"),
    ];

    let binary = possible_paths
        .iter()
        .find(|p| p.exists())
        .ok_or_else(|| "ClawDefender daemon binary not found".to_string())?;

    std::process::Command::new(binary)
        .arg("daemon")
        .arg("start")
        .spawn()
        .map_err(|e| format!("Failed to start daemon: {}", e))?;

    tracing::info!("Daemon process started");
    Ok(())
}

/// Stop the daemon process
pub fn stop_daemon_process() -> Result<(), String> {
    let possible_paths = vec![
        PathBuf::from("/usr/local/bin/clawdefender"),
        PathBuf::from(std::env::var("HOME").unwrap_or_default())
            .join(".cargo/bin/clawdefender"),
    ];

    let binary = possible_paths
        .iter()
        .find(|p| p.exists())
        .ok_or_else(|| "ClawDefender daemon binary not found".to_string())?;

    std::process::Command::new(binary)
        .arg("daemon")
        .arg("stop")
        .output()
        .map_err(|e| format!("Failed to stop daemon: {}", e))?;

    tracing::info!("Daemon process stopped");
    Ok(())
}

/// Health check - verify daemon is responsive
pub async fn health_check() -> Result<bool, String> {
    Ok(is_daemon_running())
}
