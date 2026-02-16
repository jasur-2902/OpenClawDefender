//! Test harness for end-to-end MCP proxy integration tests.
//!
//! Spawns the `clawdefender-mcp-proxy` binary wrapping the `mock-mcp-server` binary
//! and provides helpers to send JSON-RPC messages and read responses.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

/// Timeout for individual send/receive operations.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Locates a binary in the cargo target directory.
fn find_binary(name: &str) -> PathBuf {
    // Walk up from CARGO_MANIFEST_DIR to find the workspace target directory.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("could not find workspace root");
    let target_dir = workspace_root.join("target/debug");
    let bin = target_dir.join(name);
    if bin.exists() {
        return bin;
    }
    let release_bin = workspace_root.join("target/release").join(name);
    if release_bin.exists() {
        return release_bin;
    }
    panic!(
        "binary '{}' not found at {} or release. Run `cargo build --workspace` first.",
        name,
        bin.display()
    );
}

#[allow(dead_code)]
pub struct TestHarness {
    pub proxy: Child,
    pub stdin: ChildStdin,
    pub reader: BufReader<ChildStdout>,
    pub policy_path: PathBuf,
    pub _temp_dir: tempfile::TempDir,
}

#[allow(dead_code)]
impl TestHarness {
    /// Create a new test harness with the given policy TOML content.
    pub async fn new(policy_toml: &str) -> Self {
        let temp_dir = tempfile::TempDir::new().expect("failed to create temp dir");
        let policy_path = temp_dir.path().join("policy.toml");
        std::fs::write(&policy_path, policy_toml).expect("failed to write policy");

        let proxy_bin = find_binary("clawdefender-mcp-proxy");
        let mock_server_bin = find_binary("mock-mcp-server");

        let mut proxy = Command::new(&proxy_bin)
            .arg("--policy")
            .arg(&policy_path)
            .arg("--")
            .arg(&mock_server_bin)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .env_remove("RUST_LOG")
            .spawn()
            .unwrap_or_else(|e| {
                panic!(
                    "failed to spawn proxy: {e}\n  proxy_bin: {}\n  mock_server: {}",
                    proxy_bin.display(),
                    mock_server_bin.display()
                )
            });

        let stdin = proxy.stdin.take().expect("failed to get proxy stdin");
        let stdout = proxy.stdout.take().expect("failed to get proxy stdout");
        let reader = BufReader::new(stdout);

        // Give the proxy a moment to start up and spawn the mock server.
        tokio::time::sleep(Duration::from_millis(300)).await;

        Self {
            proxy,
            stdin,
            reader,
            policy_path,
            _temp_dir: temp_dir,
        }
    }

    /// Send a JSON-RPC message and read the response.
    pub async fn send(&mut self, msg: &Value) -> Value {
        let mut line = serde_json::to_string(msg).expect("failed to serialize message");
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("failed to write to proxy stdin");
        self.stdin.flush().await.expect("failed to flush stdin");

        let mut response_line = String::new();
        timeout(IO_TIMEOUT, self.reader.read_line(&mut response_line))
            .await
            .expect("timeout waiting for proxy response")
            .expect("failed to read from proxy stdout");

        serde_json::from_str(response_line.trim())
            .unwrap_or_else(|e| panic!("invalid JSON response: {e}\nraw: {response_line}"))
    }

    /// Send a message without waiting for a response (for notifications).
    pub async fn send_no_response(&mut self, msg: &Value) {
        let mut line = serde_json::to_string(msg).expect("failed to serialize message");
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("failed to write to proxy stdin");
        self.stdin.flush().await.expect("failed to flush stdin");
    }

    /// Try to read a response line with a timeout. Returns None on timeout.
    pub async fn try_read(&mut self, dur: Duration) -> Option<Value> {
        let mut line = String::new();
        match timeout(dur, self.reader.read_line(&mut line)).await {
            Ok(Ok(0)) | Err(_) => None,
            Ok(Ok(_)) => serde_json::from_str(line.trim()).ok(),
            Ok(Err(_)) => None,
        }
    }

    /// Shut down the harness by dropping stdin and waiting for exit.
    pub async fn shutdown(mut self) -> std::process::ExitStatus {
        drop(self.stdin);
        timeout(Duration::from_secs(5), self.proxy.wait())
            .await
            .expect("timeout waiting for proxy to exit")
            .expect("failed to wait for proxy")
    }
}
