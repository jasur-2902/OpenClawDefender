//! Daemon IPC client — connects to the ClawDefender daemon over a Unix domain
//! socket and exchanges JSON-line messages.
//!
//! The daemon protocol is simple:
//!   - Send `"status"\n` → receive JSON with proxy metrics
//!   - Send `"reload"\n` → receive `{"ok": true}` or `{"ok": false, "error": "..."}`
//!   - Send JSON `GuardRequest\n` → receive JSON `GuardResponse`
//!
//! The client is thread-safe (wrapped in Arc<Mutex>) and designed to be shared
//! across all Tauri command handlers via AppState.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::daemon;

/// Timeout for reading a response from the daemon.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for writing a request to the daemon.
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// Status response from the daemon's `"status"` command.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DaemonMetrics {
    #[serde(default)]
    pub messages_total: u64,
    #[serde(default)]
    pub messages_allowed: u64,
    #[serde(default)]
    pub messages_blocked: u64,
    #[serde(default)]
    pub messages_prompted: u64,
    #[serde(default)]
    pub messages_logged: u64,
    /// Live behavioral engine status from daemon.
    #[serde(default)]
    pub behavioral_status: Option<DaemonBehavioralStatus>,
}

/// Behavioral engine status reported by the daemon IPC.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DaemonBehavioralStatus {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub profiles: usize,
    #[serde(default)]
    pub learning_servers: usize,
    #[serde(default)]
    pub monitoring_servers: usize,
    #[serde(default)]
    pub auto_block_stats: Option<DaemonAutoBlockStats>,
}

/// Auto-block statistics from the decision engine.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DaemonAutoBlockStats {
    #[serde(default)]
    pub total_auto_blocks: u64,
    #[serde(default)]
    pub total_overrides: u64,
    #[serde(default)]
    pub auto_block_enabled: bool,
}

/// Reload response from the daemon's `"reload"` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
}

/// A connection to the daemon's Unix socket.
struct DaemonConnection {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

impl DaemonConnection {
    /// Connect to the daemon socket with timeout.
    fn connect(socket_path: &std::path::Path) -> Result<Self, String> {
        // Use a temporary std::net approach: connect with timeout via
        // the nix/libc-level socket or simply try_clone after connect.
        // UnixStream doesn't have connect_timeout, so we do a non-blocking
        // connect check.
        let stream = UnixStream::connect(socket_path)
            .map_err(|e| format!("Failed to connect to daemon socket: {}", e))?;

        stream
            .set_read_timeout(Some(READ_TIMEOUT))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(WRITE_TIMEOUT))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        let reader_stream = stream
            .try_clone()
            .map_err(|e| format!("Failed to clone stream: {}", e))?;
        let reader = BufReader::new(reader_stream);

        Ok(DaemonConnection { stream, reader })
    }

    /// Send a request line and read the response line.
    fn request(&mut self, message: &str) -> Result<String, String> {
        // Write the message followed by newline
        self.stream
            .write_all(message.as_bytes())
            .map_err(|e| format!("Failed to write to daemon: {}", e))?;
        self.stream
            .write_all(b"\n")
            .map_err(|e| format!("Failed to write newline: {}", e))?;
        self.stream
            .flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;

        // Read the response line
        let mut response = String::new();
        self.reader
            .read_line(&mut response)
            .map_err(|e| format!("Failed to read from daemon: {}", e))?;

        if response.is_empty() {
            return Err("Daemon closed connection".to_string());
        }

        Ok(response.trim().to_string())
    }
}

/// Thread-safe IPC client for communicating with the ClawDefender daemon.
///
/// Each method creates a fresh connection to avoid stale socket issues.
/// The socket path is derived from `daemon::socket_path()` — the single
/// source of truth for the daemon socket location.
#[derive(Debug, Clone)]
pub struct DaemonIpcClient {
    socket_path: PathBuf,
    /// Cached connection status — updated on each operation.
    connected: Arc<Mutex<bool>>,
}

impl DaemonIpcClient {
    /// Create a new IPC client. Does not connect immediately.
    pub fn new() -> Self {
        Self {
            socket_path: daemon::socket_path(),
            connected: Arc::new(Mutex::new(false)),
        }
    }

    /// Check if the daemon socket exists and is connectable.
    pub fn check_connection(&self) -> bool {
        let result = DaemonConnection::connect(&self.socket_path).is_ok();
        if let Ok(mut connected) = self.connected.lock() {
            *connected = result;
        }
        result
    }

    /// Get the last known connection state without probing.
    pub fn is_connected(&self) -> bool {
        self.connected.lock().map(|g| *g).unwrap_or(false)
    }

    /// Get the socket path.
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// Query daemon status metrics.
    pub fn query_status(&self) -> Result<DaemonMetrics, String> {
        let mut conn = self.connect()?;
        let response = conn.request("status")?;
        let metrics: DaemonMetrics = serde_json::from_str(&response)
            .map_err(|e| format!("Failed to parse status response: {}", e))?;
        debug!("Daemon status: {:?}", metrics);
        Ok(metrics)
    }

    /// Send a reload command to the daemon.
    pub fn reload_policy(&self) -> Result<ReloadResponse, String> {
        let mut conn = self.connect()?;
        let response = conn.request("reload")?;
        let result: ReloadResponse = serde_json::from_str(&response)
            .map_err(|e| format!("Failed to parse reload response: {}", e))?;
        Ok(result)
    }

    /// Send an arbitrary JSON request and get the response.
    pub fn send_json<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        request: &T,
    ) -> Result<R, String> {
        let mut conn = self.connect()?;
        let json = serde_json::to_string(request)
            .map_err(|e| format!("Failed to serialize request: {}", e))?;
        let response = conn.request(&json)?;
        let result: R = serde_json::from_str(&response)
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        Ok(result)
    }

    /// Internal: create a fresh connection and update connected state.
    fn connect(&self) -> Result<DaemonConnection, String> {
        match DaemonConnection::connect(&self.socket_path) {
            Ok(conn) => {
                if let Ok(mut connected) = self.connected.lock() {
                    *connected = true;
                }
                Ok(conn)
            }
            Err(e) => {
                if let Ok(mut connected) = self.connected.lock() {
                    *connected = false;
                }
                warn!("Daemon connection failed: {}", e);
                Err(e)
            }
        }
    }
}

impl Default for DaemonIpcClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Helper: spin up a mock daemon that responds to status queries.
    fn spawn_mock_daemon(socket_path: &std::path::Path) -> std::thread::JoinHandle<()> {
        let path = socket_path.to_path_buf();
        std::thread::spawn(move || {
            let listener = UnixListener::bind(&path).expect("bind mock daemon");
            // Accept one connection
            if let Ok((stream, _)) = listener.accept() {
                let reader_stream = stream.try_clone().unwrap();
                let mut reader = BufReader::new(reader_stream);
                let mut writer = stream;
                let mut line = String::new();

                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) => break,
                        Ok(_) => {
                            let trimmed = line.trim();
                            if trimmed == "status" || trimmed == "\"status\"" {
                                let response = serde_json::json!({
                                    "messages_total": 100,
                                    "messages_allowed": 90,
                                    "messages_blocked": 5,
                                    "messages_prompted": 3,
                                    "messages_logged": 2,
                                });
                                let _ = writeln!(writer, "{}", response);
                                let _ = writer.flush();
                            } else if trimmed == "reload" || trimmed == "\"reload\"" {
                                let _ = writeln!(writer, r#"{{"ok":true}}"#);
                                let _ = writer.flush();
                            } else {
                                let _ = writeln!(writer, r#"{{"error":"unknown command"}}"#);
                                let _ = writer.flush();
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        })
    }

    #[test]
    fn test_connection_to_nonexistent_socket() {
        let client = DaemonIpcClient {
            socket_path: PathBuf::from("/tmp/nonexistent-clawdefender-test.sock"),
            connected: Arc::new(Mutex::new(false)),
        };
        assert!(!client.check_connection());
        assert!(!client.is_connected());
    }

    #[test]
    fn test_query_status() {
        let tmp = TempDir::new().unwrap();
        let sock_path = tmp.path().join("test-daemon.sock");

        let _handle = spawn_mock_daemon(&sock_path);
        // Give the mock daemon time to bind
        std::thread::sleep(Duration::from_millis(100));

        let client = DaemonIpcClient {
            socket_path: sock_path,
            connected: Arc::new(Mutex::new(false)),
        };

        let metrics = client.query_status().expect("should get status");
        assert_eq!(metrics.messages_total, 100);
        assert_eq!(metrics.messages_allowed, 90);
        assert_eq!(metrics.messages_blocked, 5);
        assert!(client.is_connected());
    }

    #[test]
    fn test_reload_policy() {
        let tmp = TempDir::new().unwrap();
        let sock_path = tmp.path().join("test-daemon-reload.sock");

        let _handle = spawn_mock_daemon(&sock_path);
        std::thread::sleep(Duration::from_millis(100));

        let client = DaemonIpcClient {
            socket_path: sock_path,
            connected: Arc::new(Mutex::new(false)),
        };

        let result = client.reload_policy().expect("should reload");
        assert!(result.ok);
    }

    #[test]
    fn test_check_connection_with_live_socket() {
        let tmp = TempDir::new().unwrap();
        let sock_path = tmp.path().join("test-daemon-check.sock");

        let _handle = spawn_mock_daemon(&sock_path);
        std::thread::sleep(Duration::from_millis(100));

        let client = DaemonIpcClient {
            socket_path: sock_path,
            connected: Arc::new(Mutex::new(false)),
        };

        assert!(client.check_connection());
        assert!(client.is_connected());
    }
}
