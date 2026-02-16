//! `clawai status` — check if the ClawAI daemon is running.

use std::os::unix::net::UnixStream;

use anyhow::Result;
use claw_core::config::ClawConfig;

pub fn run(config: &ClawConfig) -> Result<()> {
    let socket_path = &config.daemon_socket_path;

    println!("ClawAI Status");
    println!("  Socket: {}", socket_path.display());

    // Try to connect to the daemon socket to see if it is running.
    match UnixStream::connect(socket_path) {
        Ok(_stream) => {
            println!("  Daemon: running");
            // TODO: send a status request over the IPC protocol and display details.
        }
        Err(e) => {
            match e.kind() {
                std::io::ErrorKind::NotFound => {
                    println!("  Daemon: not running (socket not found)");
                }
                std::io::ErrorKind::ConnectionRefused => {
                    println!("  Daemon: not running (connection refused)");
                }
                _ => {
                    println!("  Daemon: unknown ({e})");
                }
            }
        }
    }

    println!("  Policy: {}", config.policy_path.display());
    println!("  Audit:  {}", config.audit_log_path.display());

    Ok(())
}
