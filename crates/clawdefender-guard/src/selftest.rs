//! Self-test module to verify guard enforcement after activation.

use tracing::{info, warn};

use crate::fallback::FallbackEngine;
use crate::types::{ActionResult, GuardStatus};

/// Result of a single self-test check.
#[derive(Debug)]
#[allow(dead_code)]
struct SelfTestCheck {
    name: &'static str,
    passed: bool,
    detail: String,
}

/// Run self-tests against the fallback engine to verify enforcement.
/// Returns Active if all pass, Degraded if any fail.
pub fn run_self_test(engine: &FallbackEngine) -> GuardStatus {
    let mut checks = Vec::new();

    // Test 1: Sensitive path should be blocked.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
    let ssh_path = format!("{home}/.ssh/id_rsa");
    let result = engine.check_action("read_file", &ssh_path);
    checks.push(SelfTestCheck {
        name: "block_sensitive_ssh",
        passed: matches!(result, ActionResult::Block(_)),
        detail: format!("check read_file on {ssh_path}: {result:?}"),
    });

    // Test 2: Undeclared tool should be blocked.
    let result = engine.check_action("undeclared_dangerous_tool", "/tmp/test");
    checks.push(SelfTestCheck {
        name: "block_undeclared_tool",
        passed: matches!(result, ActionResult::Block(_)),
        detail: format!("check undeclared_dangerous_tool: {result:?}"),
    });

    // Test 3: AWS credentials should be blocked.
    let aws_path = format!("{home}/.aws/credentials");
    let result = engine.check_action("read_file", &aws_path);
    checks.push(SelfTestCheck {
        name: "block_sensitive_aws",
        passed: matches!(result, ActionResult::Block(_)),
        detail: format!("check read_file on {aws_path}: {result:?}"),
    });

    // Evaluate results.
    let failed: Vec<&SelfTestCheck> = checks.iter().filter(|c| !c.passed).collect();
    if failed.is_empty() {
        info!("AgentGuard self-test: all {} checks passed", checks.len());
        GuardStatus::Active
    } else {
        let names: Vec<&str> = failed.iter().map(|c| c.name).collect();
        let msg = format!(
            "self-test failed: {} of {} checks failed ({})",
            failed.len(),
            checks.len(),
            names.join(", ")
        );
        warn!("AgentGuard self-test: {msg}");
        GuardStatus::Degraded(msg)
    }
}
