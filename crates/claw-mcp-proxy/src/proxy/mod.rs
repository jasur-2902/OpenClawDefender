//! Protocol proxy implementations (stdio, HTTP) and shared infrastructure.

pub mod http;
pub mod stdio;

pub use http::HttpProxy;
pub use stdio::StdioProxy;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use claw_core::ipc::protocol::{UiRequest, UiResponse};

/// Configuration shared by all proxy modes.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Command to spawn for stdio mode.
    pub server_command: Option<String>,
    /// Arguments for the server command.
    pub server_args: Vec<String>,
    /// Remote URL for HTTP mode.
    pub remote_url: Option<String>,
    /// How long to wait for a user prompt response before auto-denying.
    pub prompt_timeout: Duration,
    /// Maximum number of prompts that can be pending simultaneously.
    pub max_pending_prompts: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            server_command: None,
            server_args: Vec::new(),
            remote_url: None,
            prompt_timeout: Duration::from_secs(30),
            max_pending_prompts: 100,
        }
    }
}

/// Bridge between the proxy and the UI for user prompts.
///
/// Sends a [`UiRequest`] and provides a [`oneshot::Receiver`] so the caller
/// can await the user's response asynchronously.
#[derive(Clone)]
pub struct UiBridge {
    tx: mpsc::Sender<(UiRequest, oneshot::Sender<UiResponse>)>,
}

impl UiBridge {
    /// Create a new UiBridge backed by the given channel.
    pub fn new(tx: mpsc::Sender<(UiRequest, oneshot::Sender<UiResponse>)>) -> Self {
        Self { tx }
    }

    /// Send a prompt to the UI and return a receiver for the response.
    pub async fn send_prompt(
        &self,
        request: UiRequest,
    ) -> anyhow::Result<oneshot::Receiver<UiResponse>> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send((request, resp_tx))
            .await
            .map_err(|_| anyhow::anyhow!("UI bridge channel closed"))?;
        Ok(resp_rx)
    }
}

/// Runtime metrics for the proxy.
pub struct ProxyMetrics {
    pub messages_total: AtomicU64,
    pub messages_allowed: AtomicU64,
    pub messages_blocked: AtomicU64,
    pub messages_prompted: AtomicU64,
    pub messages_logged: AtomicU64,
}

impl ProxyMetrics {
    pub fn new() -> Self {
        Self {
            messages_total: AtomicU64::new(0),
            messages_allowed: AtomicU64::new(0),
            messages_blocked: AtomicU64::new(0),
            messages_prompted: AtomicU64::new(0),
            messages_logged: AtomicU64::new(0),
        }
    }

    pub fn inc_total(&self) {
        self.messages_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_allowed(&self) {
        self.messages_allowed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_blocked(&self) {
        self.messages_blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_prompted(&self) {
        self.messages_prompted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_logged(&self) {
        self.messages_logged.fetch_add(1, Ordering::Relaxed);
    }
}

impl Default for ProxyMetrics {
    fn default() -> Self {
        Self::new()
    }
}
