//! Claw Compliant certification harness for MCP servers.
//!
//! Tests MCP servers for compliance with ClawDefender across three levels:
//! - Level 1 (Transparent): Survives ClawDefender proxy behavior
//! - Level 2 (Cooperative): Integrates with ClawDefender SDK
//! - Level 3 (Proactive): Declares security posture via manifest

pub mod harness;
pub mod level1;
pub mod level2;
pub mod level3;
pub mod manifest;
pub mod report;

use std::path::PathBuf;

use anyhow::Result;
use chrono::Utc;
use report::{CertificationReport, LevelReport, LevelResult};

/// Configuration for a certification run.
#[derive(Debug, Clone)]
pub struct CertifyConfig {
    /// The command (and arguments) to start the MCP server under test.
    pub server_command: Vec<String>,
    /// Whether to output JSON instead of text.
    pub json: bool,
    /// Optional output file path.
    pub output: Option<PathBuf>,
    /// Directory containing the server package (for manifest lookup).
    pub server_dir: Option<PathBuf>,
}

/// Top-level runner that executes all certification levels.
pub struct CertificationRunner {
    config: CertifyConfig,
}

impl CertificationRunner {
    pub fn new(config: CertifyConfig) -> Self {
        Self { config }
    }

    /// Run the full certification suite and return a report.
    pub async fn run(&self) -> Result<CertificationReport> {
        tracing::info!("Starting Claw Compliant certification");

        let server_name = self.discover_server_name().await?;
        tracing::info!(server = %server_name, "Identified server");

        // Level 1 — Transparent
        tracing::info!("Running Level 1 (Transparent) tests");
        let level1 = level1::run(&self.config).await?;

        // Level 2 — Cooperative
        tracing::info!("Running Level 2 (Cooperative) tests");
        let level2 = level2::run(&self.config).await?;

        // Level 3 — Proactive
        tracing::info!("Running Level 3 (Proactive) tests");
        let level3 = level3::run(&self.config).await?;

        let overall_level = compute_overall_level(&level1, &level2, &level3);

        Ok(CertificationReport {
            server_name,
            timestamp: Utc::now(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            level1,
            level2,
            level3,
            overall_level,
        })
    }

    /// Start the server briefly to get its name from the initialize response.
    async fn discover_server_name(&self) -> Result<String> {
        let mut h = harness::McpHarness::start(&self.config.server_command).await?;
        let init = h.initialize().await?;
        let name = init
            .get("serverInfo")
            .and_then(|s| s.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("unknown")
            .to_string();
        h.shutdown().await?;
        Ok(name)
    }
}

fn compute_overall_level(l1: &LevelReport, l2: &LevelReport, l3: &LevelReport) -> u8 {
    if l3.result == LevelResult::Pass {
        3
    } else if l2.result == LevelResult::Pass {
        2
    } else if l1.result == LevelResult::Pass {
        1
    } else {
        0
    }
}

/// Run certification and print/write the report.
pub async fn run_certification(config: CertifyConfig) -> Result<()> {
    let runner = CertificationRunner::new(config.clone());
    let report = runner.run().await?;

    let output_text = if config.json {
        report.to_json()?
    } else {
        report.to_text()
    };

    if let Some(path) = &config.output {
        std::fs::write(path, &output_text)?;
        println!("Report written to {}", path.display());
    } else {
        println!("{output_text}");
    }

    Ok(())
}
