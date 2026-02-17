use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::client::{ResourceInfo, ScanClient, ToolInfo};
use crate::evidence::EvidenceCollector;
use crate::finding::{Finding, ModuleCategory};
use crate::sandbox::Sandbox;

pub mod path_traversal;
pub mod prompt_injection;
pub mod exfiltration;
pub mod capability_escalation;
pub mod dependency_audit;
pub mod fuzzing;

/// Context provided to each scan module.
pub struct ScanContext {
    pub client: ScanClient,
    pub sandbox: Sandbox,
    pub evidence: EvidenceCollector,
    pub tool_list: Vec<ToolInfo>,
    pub resource_list: Vec<ResourceInfo>,
    pub server_stderr: Arc<Mutex<String>>,
}

/// Trait that all attack modules implement.
#[async_trait]
pub trait ScanModule: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn category(&self) -> ModuleCategory;
    async fn run(&self, ctx: &mut ScanContext) -> Result<Vec<Finding>>;
}
