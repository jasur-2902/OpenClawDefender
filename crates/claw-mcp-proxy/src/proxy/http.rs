//! HTTP/SSE-based MCP proxy.
// TODO: Phase 2 — full HTTP proxy implementation

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{bail, Result};

use claw_core::policy::engine::DefaultPolicyEngine;

/// HTTP reverse proxy for MCP servers that use HTTP+SSE transport.
pub struct HttpProxy {
    _target_url: String,
    _policy_engine: DefaultPolicyEngine,
}

impl HttpProxy {
    /// Create a new HTTP proxy targeting the given URL.
    pub fn new(target_url: String, policy_path: &Path) -> Result<Self> {
        let policy_engine = if policy_path.exists() {
            DefaultPolicyEngine::load(policy_path)?
        } else {
            DefaultPolicyEngine::empty()
        };
        Ok(Self {
            _target_url: target_url,
            _policy_engine: policy_engine,
        })
    }

    /// Start the HTTP proxy server.
    // TODO: Phase 2 — full HTTP proxy implementation
    pub async fn start(&self, _addr: SocketAddr) -> Result<()> {
        bail!("HTTP proxy not yet implemented")
    }
}
