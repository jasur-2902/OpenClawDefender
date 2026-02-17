//! ClawDefender MCP Server.
//!
//! An MCP server that other MCP servers or agents can call to declare intent,
//! request permission, and report actions. This inverts the security model from
//! adversarial monitoring to cooperative participation.

pub mod auth;
pub mod protocol;
pub mod suggestions;
pub mod tools;
pub mod transport;
pub mod types;
pub mod validation;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::Mutex;
use tracing::info;

use clawdefender_core::audit::AuditLogger;
use clawdefender_core::policy::PolicyEngine;
use clawdefender_core::rate_limit::PromptRateLimiter;

/// Rate limiter for tool calls, keyed by caller identifier.
pub struct ToolRateLimiter {
    /// Per-caller counters: (count, window_start)
    counters: HashMap<String, (u32, Instant)>,
    /// Maximum calls per window.
    max_calls: u32,
    /// Time window.
    window: Duration,
}

impl ToolRateLimiter {
    pub fn new(max_calls: u32, window: Duration) -> Self {
        Self {
            counters: HashMap::new(),
            max_calls,
            window,
        }
    }

    /// Check whether a call from `caller` is allowed.
    pub fn check(&mut self, caller: &str) -> bool {
        let now = Instant::now();
        let entry = self.counters.entry(caller.to_string()).or_insert((0, now));

        if now.duration_since(entry.1) >= self.window {
            entry.0 = 0;
            entry.1 = now;
        }

        entry.0 += 1;
        entry.0 <= self.max_calls
    }
}

/// The ClawDefender MCP server.
pub struct McpServer {
    /// Policy engine for evaluating intents and queries.
    pub policy_engine: Arc<Mutex<Box<dyn PolicyEngine>>>,
    /// Audit logger for recording reported actions.
    pub audit_logger: Arc<dyn AuditLogger>,
    /// Server metadata.
    pub server_info: ServerInfo,
    /// Rate limiter for requestPermission (prompt flooding prevention).
    pub permission_rate_limiter: Arc<Mutex<PromptRateLimiter>>,
    /// Rate limiter for checkIntent calls.
    pub intent_rate_limiter: Arc<Mutex<ToolRateLimiter>>,
    /// Rate limiter for reportAction calls.
    pub report_rate_limiter: Arc<Mutex<ToolRateLimiter>>,
    /// HTTP authentication token (None if not using HTTP auth).
    pub auth_token: Option<String>,
}

/// Server metadata returned during initialization.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

impl Default for ServerInfo {
    fn default() -> Self {
        Self {
            name: "clawdefender".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

impl McpServer {
    /// Create a new MCP server with the given policy engine and audit logger.
    pub fn new(
        policy_engine: Box<dyn PolicyEngine>,
        audit_logger: Arc<dyn AuditLogger>,
    ) -> Self {
        Self {
            policy_engine: Arc::new(Mutex::new(policy_engine)),
            audit_logger,
            server_info: ServerInfo::default(),
            // 10 permission requests per 60 seconds per server (prompt flooding prevention)
            permission_rate_limiter: Arc::new(Mutex::new(
                PromptRateLimiter::new(10, Duration::from_secs(60)),
            )),
            // 100 checkIntent calls per 60 seconds per caller
            intent_rate_limiter: Arc::new(Mutex::new(
                ToolRateLimiter::new(100, Duration::from_secs(60)),
            )),
            // 1000 reportAction calls per 60 seconds per server
            report_rate_limiter: Arc::new(Mutex::new(
                ToolRateLimiter::new(1000, Duration::from_secs(60)),
            )),
            auth_token: None,
        }
    }

    /// Create a new MCP server with HTTP authentication enabled.
    pub fn with_auth_token(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }

    /// Run the server on stdio transport (reads JSON-RPC from stdin, writes to stdout).
    pub async fn run_stdio(self: Arc<Self>) -> Result<()> {
        info!("starting ClawDefender MCP server on stdio");
        transport::stdio::run(self).await
    }

    /// Run the server on HTTP transport at the given port.
    pub async fn run_http(self: Arc<Self>, port: u16) -> Result<()> {
        info!("starting ClawDefender MCP server on HTTP port {}", port);
        transport::http::run(self, port).await
    }
}
