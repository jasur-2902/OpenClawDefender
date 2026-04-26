//! IPC client for communicating with the Rookbot daemon.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clawdefender_core::ipc::protocol::{DaemonRequest, DaemonResponse};

/// Client for daemon IPC communication over Unix socket.
pub struct DaemonClient {
    socket_path: PathBuf,
    connect_timeout: Duration,
    command_timeout: Duration,
}

impl DaemonClient {
    /// Create a new client with the given socket path.
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            connect_timeout: Duration::from_secs(5),
            command_timeout: Duration::from_secs(30),
        }
    }

    /// Create from config, with optional socket override.
    pub fn from_config(
        config: &clawdefender_core::config::ClawConfig,
        socket_override: Option<&PathBuf>,
    ) -> Self {
        let socket_path = socket_override
            .cloned()
            .unwrap_or_else(|| config.daemon_socket_path.clone());
        Self::new(socket_path)
    }

    /// Default socket path.
    pub fn default_socket_path() -> PathBuf {
        if let Some(home) = std::env::var_os("HOME") {
            PathBuf::from(home).join(".local/share/rookbot/rookbot.sock")
        } else {
            PathBuf::from("/tmp/rookbot.sock")
        }
    }

    /// Check if the daemon is running (socket connectable).
    pub fn is_daemon_running(&self) -> bool {
        UnixStream::connect(&self.socket_path).is_ok()
    }

    /// Connect to the daemon socket.
    fn connect(&self) -> Result<UnixStream> {
        let stream = UnixStream::connect(&self.socket_path).with_context(|| {
            format!(
                "Daemon not running. Start with: rookbot daemon start\n  Socket: {}",
                self.socket_path.display()
            )
        })?;
        stream.set_read_timeout(Some(self.command_timeout)).ok();
        stream.set_write_timeout(Some(self.connect_timeout)).ok();
        Ok(stream)
    }

    /// Send a DaemonRequest and receive a DaemonResponse.
    pub fn send_command(&self, request: &DaemonRequest) -> Result<DaemonResponse> {
        let mut stream = self.connect()?;
        let msg = serde_json::to_string(request)?;
        writeln!(stream, "{msg}")?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response)?;

        let resp: DaemonResponse =
            serde_json::from_str(&response).with_context(|| "Invalid response from daemon")?;
        Ok(resp)
    }

    /// Send a raw string command (for legacy/simple commands like "status", "shutdown").
    pub fn send_raw(&self, command: &str) -> Result<String> {
        let mut stream = self.connect()?;
        writeln!(stream, "{command}")?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response)?;
        Ok(response)
    }

    /// Query daemon status.
    pub fn status_query(&self) -> Result<DaemonResponse> {
        self.send_command(&DaemonRequest::StatusQuery)
    }

    /// Request daemon shutdown.
    pub fn shutdown(&self) -> Result<DaemonResponse> {
        self.send_command(&DaemonRequest::Shutdown)
    }

    /// Get the socket path.
    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }
}
