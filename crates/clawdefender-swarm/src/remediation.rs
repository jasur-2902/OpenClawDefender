//! Remediation engine — turns Claude's fix recommendations into executable actions.
//!
//! Parses structured `[REMEDIATION]` blocks from LLM responses, manages their
//! lifecycle (propose → approve → execute → revert), and provides one-click
//! fix capabilities for security findings.

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A single remediation action extracted from Claude's analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    pub id: String,
    pub finding_id: String,
    pub scan_id: String,

    pub title: String,
    pub description: String,
    #[serde(rename = "risk_level")]
    pub risk_of_fix: FixRisk,
    pub reversible: bool,
    /// Whether this remediation can be auto-executed (safe risk + not manual).
    pub auto_executable: bool,

    pub fix_type: FixType,

    pub status: RemediationStatus,
    pub executed_at: Option<DateTime<Utc>>,
    pub revert_data: Option<String>,
}

/// Risk level associated with applying a fix.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FixRisk {
    #[serde(rename = "safe")]
    Safe,
    #[serde(rename = "low")]
    LowRisk,
    #[serde(rename = "medium")]
    MediumRisk,
    #[serde(rename = "high")]
    HighRisk,
}

/// The kind of fix to apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FixType {
    PolicyChange {
        action: PolicyAction,
        rule_description: String,
        preview_diff: String,
    },
    SystemCommand {
        command: String,
        requires_sudo: bool,
        dry_run_output: Option<String>,
    },
    ConfigEdit {
        file_path: String,
        current_value: String,
        proposed_value: String,
        diff: String,
    },
    ManualAction {
        instructions: String,
    },
}

/// What a policy change does.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAction {
    AddRule,
    ModifyRule,
    DeleteRule,
}

/// Lifecycle status of a remediation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RemediationStatus {
    Proposed,
    Approved,
    Executed,
    Reverted,
    Rejected,
    Failed { error: String },
}

/// Human-readable preview of what a remediation will do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPreview {
    pub remediation_id: String,
    pub title: String,
    pub description: String,
    pub risk: FixRisk,
    pub reversible: bool,
    pub preview_text: String,
}

/// Aggregate statistics for remediations in a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationStats {
    pub total: usize,
    pub proposed: usize,
    pub executed: usize,
    pub reverted: usize,
    pub safe_count: usize,
    pub reversible_count: usize,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Extract `[REMEDIATION ...]...[/REMEDIATION]` blocks from LLM text output.
pub fn extract_remediations(text: &str, scan_id: &str) -> Vec<Remediation> {
    let mut results = Vec::new();
    let mut remaining = text;

    while let Some(start_idx) = remaining.find("[REMEDIATION ") {
        let after_tag = &remaining[start_idx..];
        // Find the closing bracket of the opening tag
        let Some(tag_end) = after_tag.find(']') else {
            remaining = &remaining[start_idx + 13..];
            continue;
        };

        let tag_line = &after_tag[..tag_end];

        // Find the end tag
        let Some(end_idx) = after_tag.find("[/REMEDIATION]") else {
            remaining = &remaining[start_idx + tag_end..];
            continue;
        };

        let body = after_tag[tag_end + 1..end_idx].trim();

        // Parse tag attributes: for=FINDING-3 risk=low reversible=yes
        let finding_id = parse_tag_attr(tag_line, "for").unwrap_or_default();
        let risk = parse_risk(&parse_tag_attr(tag_line, "risk").unwrap_or_default());
        let reversible = parse_tag_attr(tag_line, "reversible")
            .map(|v| v == "yes" || v == "true")
            .unwrap_or(false);

        // Parse body fields
        if let Some(remediation) =
            parse_remediation_body(body, &finding_id, scan_id, risk, reversible)
        {
            results.push(remediation);
        }

        remaining = &remaining[start_idx + end_idx + 14..];
    }

    results
}

/// Parse a single attribute from a tag line like `[REMEDIATION for=FINDING-3 risk=low]`.
fn parse_tag_attr(tag: &str, key: &str) -> Option<String> {
    let search = format!("{key}=");
    let idx = tag.find(&search)?;
    let after = &tag[idx + search.len()..];
    // Value ends at next space or end-of-string
    let value = after
        .split_whitespace()
        .next()
        .unwrap_or(after)
        .trim_end_matches(']');
    Some(value.to_string())
}

/// Map a risk string to a `FixRisk` enum.
fn parse_risk(s: &str) -> FixRisk {
    match s.to_lowercase().as_str() {
        "safe" => FixRisk::Safe,
        "low" => FixRisk::LowRisk,
        "medium" | "med" => FixRisk::MediumRisk,
        "high" => FixRisk::HighRisk,
        _ => FixRisk::MediumRisk,
    }
}

/// Parse the body of a `[REMEDIATION]` block into a `Remediation`.
fn parse_remediation_body(
    body: &str,
    finding_id: &str,
    scan_id: &str,
    risk: FixRisk,
    reversible: bool,
) -> Option<Remediation> {
    let fix_type_str = parse_body_field(body, "Type")?.to_lowercase();

    let fix_type = match fix_type_str.as_str() {
        "policy_change" | "policy" => {
            let action_str = parse_body_field(body, "Action").unwrap_or_default();
            let rule = parse_body_field(body, "Rule").unwrap_or_default();
            FixType::PolicyChange {
                action: parse_policy_action(&action_str),
                rule_description: action_str,
                preview_diff: rule,
            }
        }
        "system_command" | "command" => {
            let command = parse_body_field(body, "Command").unwrap_or_default();
            let requires_sudo = parse_body_field(body, "Sudo")
                .map(|v| v == "yes" || v == "true")
                .unwrap_or(false);
            FixType::SystemCommand {
                command,
                requires_sudo,
                dry_run_output: None,
            }
        }
        "config_edit" | "config" => {
            let file_path = parse_body_field(body, "File").unwrap_or_default();
            let current = parse_body_field(body, "Current").unwrap_or_default();
            let proposed = parse_body_field(body, "Proposed").unwrap_or_default();
            let diff = parse_body_field(body, "Diff").unwrap_or_default();
            FixType::ConfigEdit {
                file_path,
                current_value: current,
                proposed_value: proposed,
                diff,
            }
        }
        "manual" | "manual_action" => {
            let instructions = parse_body_field(body, "Instructions").unwrap_or_default();
            FixType::ManualAction { instructions }
        }
        _ => return None,
    };

    let title = parse_body_field(body, "Action")
        .or_else(|| parse_body_field(body, "Instructions"))
        .unwrap_or_else(|| format!("Fix for {finding_id}"));

    let auto_executable =
        risk == FixRisk::Safe && !matches!(fix_type, FixType::ManualAction { .. });

    Some(Remediation {
        id: format!("rem-{}", Uuid::new_v4()),
        finding_id: finding_id.to_string(),
        scan_id: scan_id.to_string(),
        title: title.clone(),
        description: title,
        risk_of_fix: risk,
        reversible,
        auto_executable,
        fix_type,
        status: RemediationStatus::Proposed,
        executed_at: None,
        revert_data: None,
    })
}

/// Extract a `Key: value` field from the body text.
fn parse_body_field(body: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(&prefix) {
            let value = rest.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Map an action description to a `PolicyAction` variant.
fn parse_policy_action(s: &str) -> PolicyAction {
    let lower = s.to_lowercase();
    if lower.starts_with("add") || lower.contains("add rule") {
        PolicyAction::AddRule
    } else if lower.starts_with("delete") || lower.starts_with("remove") {
        PolicyAction::DeleteRule
    } else {
        PolicyAction::ModifyRule
    }
}

// ---------------------------------------------------------------------------
// Allowed commands for SystemCommand execution
// ---------------------------------------------------------------------------

/// Commands considered safe to run without user confirmation.
const ALLOWED_REMEDIATION_COMMANDS: &[&str] =
    &["networksetup", "defaults", "launchctl", "chmod", "chflags"];

/// Check whether a command is in the remediation allowlist.
fn is_command_allowed(command: &str) -> bool {
    let binary = command.split_whitespace().next().unwrap_or("");
    ALLOWED_REMEDIATION_COMMANDS.contains(&binary)
}

// ---------------------------------------------------------------------------
// RemediationEngine
// ---------------------------------------------------------------------------

/// Manages remediations for a single scan — add, preview, execute, revert.
pub struct RemediationEngine {
    remediations: Vec<Remediation>,
    scan_id: String,
}

impl RemediationEngine {
    /// Create a new engine for the given scan.
    pub fn new(scan_id: String) -> Self {
        Self {
            remediations: Vec::new(),
            scan_id,
        }
    }

    /// Add remediations extracted from Claude's analysis.
    pub fn add_remediations(&mut self, remediations: Vec<Remediation>) {
        self.remediations.extend(remediations);
    }

    /// The scan ID this engine is associated with.
    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    /// Get all remediations for this scan.
    pub fn get_all(&self) -> &[Remediation] {
        &self.remediations
    }

    /// Get remediations associated with a specific finding.
    pub fn get_for_finding(&self, finding_id: &str) -> Vec<&Remediation> {
        self.remediations
            .iter()
            .filter(|r| r.finding_id == finding_id)
            .collect()
    }

    /// Preview what a remediation would do without executing it.
    pub fn preview(&self, remediation_id: &str) -> Result<RemediationPreview> {
        let rem = self.find(remediation_id)?;
        let preview_text = match &rem.fix_type {
            FixType::PolicyChange {
                action: _,
                rule_description,
                preview_diff,
            } => {
                format!("Policy change: {rule_description}\nDiff: {preview_diff}")
            }
            FixType::SystemCommand {
                command,
                requires_sudo,
                dry_run_output,
            } => {
                let sudo_note = if *requires_sudo {
                    " (requires sudo)"
                } else {
                    ""
                };
                let dry_run = dry_run_output
                    .as_deref()
                    .map(|o| format!("\nDry-run output: {o}"))
                    .unwrap_or_default();
                format!("Run command{sudo_note}: {command}{dry_run}")
            }
            FixType::ConfigEdit {
                file_path,
                current_value,
                proposed_value,
                diff,
            } => {
                format!(
                    "Edit {file_path}:\n  Current: {current_value}\n  Proposed: {proposed_value}\n  Diff: {diff}"
                )
            }
            FixType::ManualAction { instructions } => {
                format!("Manual action required:\n{instructions}")
            }
        };

        Ok(RemediationPreview {
            remediation_id: rem.id.clone(),
            title: rem.title.clone(),
            description: rem.description.clone(),
            risk: rem.risk_of_fix.clone(),
            reversible: rem.reversible,
            preview_text,
        })
    }

    /// Execute a single remediation by ID.
    pub fn execute(&mut self, remediation_id: &str) -> Result<()> {
        let rem = self.find_mut(remediation_id)?;

        match &rem.status {
            RemediationStatus::Proposed | RemediationStatus::Approved => {}
            other => bail!("Cannot execute remediation in status {:?}", other),
        }

        match &rem.fix_type {
            FixType::PolicyChange {
                rule_description, ..
            } => {
                // Store current state for revert and mark as needing Tauri relay
                rem.revert_data = Some(format!("pre-policy:{rule_description}"));
                rem.status = RemediationStatus::Executed;
                rem.executed_at = Some(Utc::now());
            }
            FixType::SystemCommand {
                command,
                requires_sudo,
                ..
            } => {
                if *requires_sudo {
                    // Convert to manual action — we cannot run sudo non-interactively
                    rem.status = RemediationStatus::Failed {
                        error: format!("Requires sudo — please run manually: sudo {command}"),
                    };
                    return Ok(());
                }
                if !is_command_allowed(command) {
                    rem.status = RemediationStatus::Failed {
                        error: format!("Command not in remediation allowlist: {command}"),
                    };
                    return Ok(());
                }
                // Command is allowed and does not require sudo — mark executed.
                // Actual execution would be relayed through Tauri/daemon.
                rem.revert_data = Some(format!("pre-command:{command}"));
                rem.status = RemediationStatus::Executed;
                rem.executed_at = Some(Utc::now());
            }
            FixType::ConfigEdit {
                file_path,
                current_value,
                proposed_value,
                ..
            } => {
                // Save current value for revert
                rem.revert_data = Some(current_value.clone());
                // In a real implementation we would write `proposed_value` to `file_path`
                // atomically. For now we record the intent.
                tracing::info!(
                    "ConfigEdit: would write proposed value to {file_path}: {proposed_value}"
                );
                rem.status = RemediationStatus::Executed;
                rem.executed_at = Some(Utc::now());
            }
            FixType::ManualAction { .. } => {
                // Manual actions are just displayed — user marks as done
                rem.status = RemediationStatus::Executed;
                rem.executed_at = Some(Utc::now());
            }
        }

        Ok(())
    }

    /// Revert a previously executed remediation.
    pub fn revert(&mut self, remediation_id: &str) -> Result<()> {
        let rem = self.find_mut(remediation_id)?;

        if rem.status != RemediationStatus::Executed {
            bail!("Cannot revert remediation in status {:?}", rem.status);
        }

        if !rem.reversible {
            bail!("Remediation {} is not marked as reversible", remediation_id);
        }

        match &rem.fix_type {
            FixType::PolicyChange { .. } => {
                // Restore saved policy state (via Tauri relay in production)
                if rem.revert_data.is_some() {
                    rem.status = RemediationStatus::Reverted;
                } else {
                    bail!("No revert data available for policy change");
                }
            }
            FixType::ConfigEdit { file_path, .. } => {
                if let Some(original) = &rem.revert_data {
                    tracing::info!(
                        "ConfigEdit revert: would restore original value to {file_path}: {original}"
                    );
                    rem.status = RemediationStatus::Reverted;
                } else {
                    bail!("No revert data available for config edit");
                }
            }
            FixType::SystemCommand { .. } => {
                // No automatic inverse command — flag as needing manual revert
                bail!(
                    "System command revert requires manual intervention. Original command data: {:?}",
                    rem.revert_data
                );
            }
            FixType::ManualAction { .. } => {
                bail!("Manual actions cannot be automatically reverted");
            }
        }

        Ok(())
    }

    /// Execute all remediations that are `Safe` risk and marked `reversible`.
    pub fn execute_all_safe(&mut self) -> Vec<Result<String>> {
        let safe_ids: Vec<String> = self
            .remediations
            .iter()
            .filter(|r| {
                r.risk_of_fix == FixRisk::Safe
                    && r.reversible
                    && matches!(
                        r.status,
                        RemediationStatus::Proposed | RemediationStatus::Approved
                    )
            })
            .map(|r| r.id.clone())
            .collect();

        let mut results = Vec::new();
        for id in safe_ids {
            match self.execute(&id) {
                Ok(()) => results.push(Ok(id)),
                Err(e) => results.push(Err(e)),
            }
        }
        results
    }

    /// Compute aggregate statistics.
    pub fn get_stats(&self) -> RemediationStats {
        let mut stats = RemediationStats {
            total: self.remediations.len(),
            proposed: 0,
            executed: 0,
            reverted: 0,
            safe_count: 0,
            reversible_count: 0,
        };

        for r in &self.remediations {
            match &r.status {
                RemediationStatus::Proposed => stats.proposed += 1,
                RemediationStatus::Executed => stats.executed += 1,
                RemediationStatus::Reverted => stats.reverted += 1,
                _ => {}
            }
            if r.risk_of_fix == FixRisk::Safe {
                stats.safe_count += 1;
            }
            if r.reversible {
                stats.reversible_count += 1;
            }
        }

        stats
    }

    // -- Internal helpers ---------------------------------------------------

    fn find(&self, id: &str) -> Result<&Remediation> {
        self.remediations
            .iter()
            .find(|r| r.id == id)
            .ok_or_else(|| anyhow::anyhow!("Remediation not found: {id}"))
    }

    fn find_mut(&mut self, id: &str) -> Result<&mut Remediation> {
        self.remediations
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| anyhow::anyhow!("Remediation not found: {id}"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Parsing tests ------------------------------------------------------

    #[test]
    fn test_extract_policy_change_remediation() {
        let text = r#"
Here is my analysis:

[REMEDIATION for=FINDING-3 risk=low reversible=yes]
Type: policy_change
Action: Add rule restricting FileManager file access
Rule: { server="FileManager", resource="~/*", action="prompt" }
[/REMEDIATION]

That concludes my findings.
"#;

        let remediations = extract_remediations(text, "scan-001");
        assert_eq!(remediations.len(), 1);

        let r = &remediations[0];
        assert_eq!(r.finding_id, "FINDING-3");
        assert_eq!(r.scan_id, "scan-001");
        assert_eq!(r.risk_of_fix, FixRisk::LowRisk);
        assert!(r.reversible);
        assert!(matches!(r.status, RemediationStatus::Proposed));
        assert!(matches!(r.fix_type, FixType::PolicyChange { .. }));

        if let FixType::PolicyChange {
            action,
            rule_description,
            ..
        } = &r.fix_type
        {
            assert!(matches!(action, PolicyAction::AddRule));
            assert!(rule_description.contains("restricting FileManager"));
        }
    }

    #[test]
    fn test_extract_manual_remediation() {
        let text = r#"
[REMEDIATION for=FINDING-5 risk=safe reversible=no]
Type: manual
Instructions: Open System Preferences → Privacy → Full Disk Access → remove FileManager
[/REMEDIATION]
"#;

        let remediations = extract_remediations(text, "scan-002");
        assert_eq!(remediations.len(), 1);

        let r = &remediations[0];
        assert_eq!(r.finding_id, "FINDING-5");
        assert_eq!(r.risk_of_fix, FixRisk::Safe);
        assert!(!r.reversible);

        if let FixType::ManualAction { instructions } = &r.fix_type {
            assert!(instructions.contains("System Preferences"));
        } else {
            panic!("Expected ManualAction fix type");
        }
    }

    #[test]
    fn test_extract_system_command_remediation() {
        let text = r#"
[REMEDIATION for=FINDING-7 risk=medium reversible=yes]
Type: system_command
Command: defaults write com.apple.screensaver askForPassword -int 1
Sudo: no
[/REMEDIATION]
"#;

        let remediations = extract_remediations(text, "scan-003");
        assert_eq!(remediations.len(), 1);

        let r = &remediations[0];
        assert_eq!(r.risk_of_fix, FixRisk::MediumRisk);
        assert!(r.reversible);

        if let FixType::SystemCommand {
            command,
            requires_sudo,
            ..
        } = &r.fix_type
        {
            assert!(command.contains("defaults write"));
            assert!(!requires_sudo);
        } else {
            panic!("Expected SystemCommand fix type");
        }
    }

    #[test]
    fn test_extract_config_edit_remediation() {
        let text = r#"
[REMEDIATION for=FINDING-9 risk=high reversible=yes]
Type: config_edit
File: /etc/ssh/sshd_config
Current: PermitRootLogin yes
Proposed: PermitRootLogin no
Diff: -PermitRootLogin yes +PermitRootLogin no
[/REMEDIATION]
"#;

        let remediations = extract_remediations(text, "scan-004");
        assert_eq!(remediations.len(), 1);

        let r = &remediations[0];
        assert_eq!(r.risk_of_fix, FixRisk::HighRisk);

        if let FixType::ConfigEdit {
            file_path,
            current_value,
            proposed_value,
            diff,
        } = &r.fix_type
        {
            assert_eq!(file_path, "/etc/ssh/sshd_config");
            assert_eq!(current_value, "PermitRootLogin yes");
            assert_eq!(proposed_value, "PermitRootLogin no");
            assert!(diff.contains("PermitRootLogin"));
        } else {
            panic!("Expected ConfigEdit fix type");
        }
    }

    #[test]
    fn test_extract_multiple_remediations() {
        let text = r#"
[REMEDIATION for=FINDING-1 risk=safe reversible=yes]
Type: policy_change
Action: Add firewall rule
Rule: block inbound on port 8080
[/REMEDIATION]

Some analysis text here.

[REMEDIATION for=FINDING-2 risk=low reversible=no]
Type: manual
Instructions: Review application permissions in system settings
[/REMEDIATION]

[REMEDIATION for=FINDING-3 risk=high reversible=yes]
Type: config_edit
File: ~/.zshrc
Current: export PATH=$PATH:/unsafe/bin
Proposed: # removed unsafe path
Diff: -export PATH=$PATH:/unsafe/bin
[/REMEDIATION]
"#;

        let remediations = extract_remediations(text, "scan-005");
        assert_eq!(remediations.len(), 3);
        assert_eq!(remediations[0].finding_id, "FINDING-1");
        assert_eq!(remediations[1].finding_id, "FINDING-2");
        assert_eq!(remediations[2].finding_id, "FINDING-3");
    }

    #[test]
    fn test_extract_empty_text() {
        let remediations = extract_remediations("", "scan-006");
        assert!(remediations.is_empty());
    }

    #[test]
    fn test_extract_no_remediation_blocks() {
        let text = "This is just a normal analysis with no remediation blocks.";
        let remediations = extract_remediations(text, "scan-007");
        assert!(remediations.is_empty());
    }

    #[test]
    fn test_extract_malformed_block_missing_end_tag() {
        let text = r#"
[REMEDIATION for=FINDING-1 risk=safe reversible=yes]
Type: manual
Instructions: Do something
"#;
        // No [/REMEDIATION] closing tag — should skip
        let remediations = extract_remediations(text, "scan-008");
        assert!(remediations.is_empty());
    }

    #[test]
    fn test_extract_malformed_block_missing_type() {
        let text = r#"
[REMEDIATION for=FINDING-1 risk=safe reversible=yes]
Instructions: Do something without a Type field
[/REMEDIATION]
"#;
        // Missing Type: field — parse_remediation_body returns None
        let remediations = extract_remediations(text, "scan-009");
        assert!(remediations.is_empty());
    }

    // -- Engine tests -------------------------------------------------------

    fn make_test_remediation(
        id: &str,
        finding_id: &str,
        risk: FixRisk,
        reversible: bool,
        fix_type: FixType,
    ) -> Remediation {
        let auto_executable =
            risk == FixRisk::Safe && !matches!(fix_type, FixType::ManualAction { .. });
        Remediation {
            id: id.to_string(),
            finding_id: finding_id.to_string(),
            scan_id: "test-scan".to_string(),
            title: format!("Fix for {finding_id}"),
            description: format!("Description for {finding_id}"),
            risk_of_fix: risk,
            reversible,
            auto_executable,
            fix_type,
            status: RemediationStatus::Proposed,
            executed_at: None,
            revert_data: None,
        }
    }

    #[test]
    fn test_engine_add_and_get() {
        let mut engine = RemediationEngine::new("scan-100".into());
        assert!(engine.get_all().is_empty());

        let rem = make_test_remediation(
            "rem-1",
            "FINDING-1",
            FixRisk::Safe,
            true,
            FixType::ManualAction {
                instructions: "Do something".into(),
            },
        );
        engine.add_remediations(vec![rem]);

        assert_eq!(engine.get_all().len(), 1);
        assert_eq!(engine.get_all()[0].id, "rem-1");
    }

    #[test]
    fn test_engine_get_for_finding() {
        let mut engine = RemediationEngine::new("scan-101".into());

        let rem1 = make_test_remediation(
            "rem-1",
            "FINDING-A",
            FixRisk::Safe,
            true,
            FixType::ManualAction {
                instructions: "Step 1".into(),
            },
        );
        let rem2 = make_test_remediation(
            "rem-2",
            "FINDING-B",
            FixRisk::LowRisk,
            false,
            FixType::ManualAction {
                instructions: "Step 2".into(),
            },
        );
        let rem3 = make_test_remediation(
            "rem-3",
            "FINDING-A",
            FixRisk::Safe,
            true,
            FixType::ManualAction {
                instructions: "Step 3".into(),
            },
        );
        engine.add_remediations(vec![rem1, rem2, rem3]);

        let for_a = engine.get_for_finding("FINDING-A");
        assert_eq!(for_a.len(), 2);
        assert!(for_a.iter().all(|r| r.finding_id == "FINDING-A"));

        let for_b = engine.get_for_finding("FINDING-B");
        assert_eq!(for_b.len(), 1);

        let for_c = engine.get_for_finding("FINDING-C");
        assert!(for_c.is_empty());
    }

    #[test]
    fn test_preview_policy_change() {
        let mut engine = RemediationEngine::new("scan-102".into());
        let rem = make_test_remediation(
            "rem-1",
            "FINDING-1",
            FixRisk::LowRisk,
            true,
            FixType::PolicyChange {
                action: PolicyAction::AddRule,
                rule_description: "Block FileManager access".into(),
                preview_diff: "add block rule".into(),
            },
        );
        engine.add_remediations(vec![rem]);

        let preview = engine.preview("rem-1").unwrap();
        assert_eq!(preview.remediation_id, "rem-1");
        assert_eq!(preview.risk, FixRisk::LowRisk);
        assert!(preview.reversible);
        assert!(preview.preview_text.contains("Policy change"));
        assert!(preview.preview_text.contains("Block FileManager access"));
    }

    #[test]
    fn test_preview_system_command() {
        let mut engine = RemediationEngine::new("scan-103".into());
        let rem = make_test_remediation(
            "rem-2",
            "FINDING-2",
            FixRisk::MediumRisk,
            false,
            FixType::SystemCommand {
                command: "defaults write com.apple.screensaver askForPassword -int 1".into(),
                requires_sudo: false,
                dry_run_output: Some("Would set askForPassword to 1".into()),
            },
        );
        engine.add_remediations(vec![rem]);

        let preview = engine.preview("rem-2").unwrap();
        assert!(preview.preview_text.contains("Run command"));
        assert!(preview.preview_text.contains("defaults write"));
        assert!(preview.preview_text.contains("Dry-run output"));
    }

    #[test]
    fn test_preview_config_edit() {
        let mut engine = RemediationEngine::new("scan-104".into());
        let rem = make_test_remediation(
            "rem-3",
            "FINDING-3",
            FixRisk::HighRisk,
            true,
            FixType::ConfigEdit {
                file_path: "/etc/ssh/sshd_config".into(),
                current_value: "PermitRootLogin yes".into(),
                proposed_value: "PermitRootLogin no".into(),
                diff: "-yes +no".into(),
            },
        );
        engine.add_remediations(vec![rem]);

        let preview = engine.preview("rem-3").unwrap();
        assert!(preview.preview_text.contains("Edit /etc/ssh/sshd_config"));
        assert!(preview.preview_text.contains("PermitRootLogin yes"));
        assert!(preview.preview_text.contains("PermitRootLogin no"));
    }

    #[test]
    fn test_preview_manual_action() {
        let mut engine = RemediationEngine::new("scan-105".into());
        let rem = make_test_remediation(
            "rem-4",
            "FINDING-4",
            FixRisk::Safe,
            false,
            FixType::ManualAction {
                instructions: "Open System Preferences and disable sharing".into(),
            },
        );
        engine.add_remediations(vec![rem]);

        let preview = engine.preview("rem-4").unwrap();
        assert!(preview.preview_text.contains("Manual action"));
        assert!(preview.preview_text.contains("System Preferences"));
    }

    #[test]
    fn test_preview_not_found() {
        let engine = RemediationEngine::new("scan-106".into());
        assert!(engine.preview("nonexistent").is_err());
    }

    #[test]
    fn test_execute_policy_change() {
        let mut engine = RemediationEngine::new("scan-110".into());
        let rem = make_test_remediation(
            "rem-1",
            "FINDING-1",
            FixRisk::Safe,
            true,
            FixType::PolicyChange {
                action: PolicyAction::AddRule,
                rule_description: "Block access".into(),
                preview_diff: "add block".into(),
            },
        );
        engine.add_remediations(vec![rem]);

        engine.execute("rem-1").unwrap();

        let r = &engine.get_all()[0];
        assert_eq!(r.status, RemediationStatus::Executed);
        assert!(r.executed_at.is_some());
        assert!(r.revert_data.is_some());
    }

    #[test]
    fn test_execute_manual_action() {
        let mut engine = RemediationEngine::new("scan-111".into());
        let rem = make_test_remediation(
            "rem-2",
            "FINDING-2",
            FixRisk::Safe,
            false,
            FixType::ManualAction {
                instructions: "Do this manually".into(),
            },
        );
        engine.add_remediations(vec![rem]);

        engine.execute("rem-2").unwrap();

        let r = &engine.get_all()[0];
        assert_eq!(r.status, RemediationStatus::Executed);
    }

    #[test]
    fn test_execute_sudo_command_fails() {
        let mut engine = RemediationEngine::new("scan-112".into());
        let rem = make_test_remediation(
            "rem-3",
            "FINDING-3",
            FixRisk::MediumRisk,
            true,
            FixType::SystemCommand {
                command: "pfctl -e".into(),
                requires_sudo: true,
                dry_run_output: None,
            },
        );
        engine.add_remediations(vec![rem]);

        engine.execute("rem-3").unwrap();

        let r = &engine.get_all()[0];
        assert!(matches!(r.status, RemediationStatus::Failed { .. }));
        if let RemediationStatus::Failed { error } = &r.status {
            assert!(error.contains("sudo"));
        }
    }

    #[test]
    fn test_execute_disallowed_command_fails() {
        let mut engine = RemediationEngine::new("scan-113".into());
        let rem = make_test_remediation(
            "rem-4",
            "FINDING-4",
            FixRisk::LowRisk,
            true,
            FixType::SystemCommand {
                command: "rm -rf /tmp/something".into(),
                requires_sudo: false,
                dry_run_output: None,
            },
        );
        engine.add_remediations(vec![rem]);

        engine.execute("rem-4").unwrap();

        let r = &engine.get_all()[0];
        assert!(matches!(r.status, RemediationStatus::Failed { .. }));
        if let RemediationStatus::Failed { error } = &r.status {
            assert!(error.contains("allowlist"));
        }
    }

    #[test]
    fn test_execute_allowed_command_succeeds() {
        let mut engine = RemediationEngine::new("scan-114".into());
        let rem = make_test_remediation(
            "rem-5",
            "FINDING-5",
            FixRisk::LowRisk,
            true,
            FixType::SystemCommand {
                command: "defaults write com.apple.screensaver askForPassword -int 1".into(),
                requires_sudo: false,
                dry_run_output: None,
            },
        );
        engine.add_remediations(vec![rem]);

        engine.execute("rem-5").unwrap();

        let r = &engine.get_all()[0];
        assert_eq!(r.status, RemediationStatus::Executed);
    }

    #[test]
    fn test_execute_config_edit() {
        let mut engine = RemediationEngine::new("scan-115".into());
        let rem = make_test_remediation(
            "rem-6",
            "FINDING-6",
            FixRisk::HighRisk,
            true,
            FixType::ConfigEdit {
                file_path: "/etc/hosts".into(),
                current_value: "# empty".into(),
                proposed_value: "127.0.0.1 evil.com".into(),
                diff: "+127.0.0.1 evil.com".into(),
            },
        );
        engine.add_remediations(vec![rem]);

        engine.execute("rem-6").unwrap();

        let r = &engine.get_all()[0];
        assert_eq!(r.status, RemediationStatus::Executed);
        assert_eq!(r.revert_data.as_deref(), Some("# empty"));
    }

    #[test]
    fn test_cannot_execute_already_executed() {
        let mut engine = RemediationEngine::new("scan-116".into());
        let rem = make_test_remediation(
            "rem-7",
            "FINDING-7",
            FixRisk::Safe,
            true,
            FixType::ManualAction {
                instructions: "Do something".into(),
            },
        );
        engine.add_remediations(vec![rem]);

        engine.execute("rem-7").unwrap();
        assert!(engine.execute("rem-7").is_err());
    }

    // -- Revert tests -------------------------------------------------------

    #[test]
    fn test_revert_policy_change() {
        let mut engine = RemediationEngine::new("scan-120".into());
        let rem = make_test_remediation(
            "rem-1",
            "FINDING-1",
            FixRisk::Safe,
            true,
            FixType::PolicyChange {
                action: PolicyAction::AddRule,
                rule_description: "Block access".into(),
                preview_diff: "add block".into(),
            },
        );
        engine.add_remediations(vec![rem]);

        // Execute then revert
        engine.execute("rem-1").unwrap();
        assert_eq!(engine.get_all()[0].status, RemediationStatus::Executed);

        engine.revert("rem-1").unwrap();
        assert_eq!(engine.get_all()[0].status, RemediationStatus::Reverted);
    }

    #[test]
    fn test_revert_config_edit() {
        let mut engine = RemediationEngine::new("scan-121".into());
        let rem = make_test_remediation(
            "rem-2",
            "FINDING-2",
            FixRisk::LowRisk,
            true,
            FixType::ConfigEdit {
                file_path: "/tmp/test.conf".into(),
                current_value: "original=yes".into(),
                proposed_value: "original=no".into(),
                diff: "-yes +no".into(),
            },
        );
        engine.add_remediations(vec![rem]);

        engine.execute("rem-2").unwrap();
        engine.revert("rem-2").unwrap();

        assert_eq!(engine.get_all()[0].status, RemediationStatus::Reverted);
    }

    #[test]
    fn test_revert_system_command_fails() {
        let mut engine = RemediationEngine::new("scan-122".into());
        let rem = make_test_remediation(
            "rem-3",
            "FINDING-3",
            FixRisk::LowRisk,
            true,
            FixType::SystemCommand {
                command: "defaults write com.apple.screensaver askForPassword -int 1".into(),
                requires_sudo: false,
                dry_run_output: None,
            },
        );
        engine.add_remediations(vec![rem]);

        engine.execute("rem-3").unwrap();
        assert!(engine.revert("rem-3").is_err());
    }

    #[test]
    fn test_revert_manual_action_fails() {
        let mut engine = RemediationEngine::new("scan-123".into());
        let rem = make_test_remediation(
            "rem-4",
            "FINDING-4",
            FixRisk::Safe,
            true, // reversible flag is true but manual actions can't auto-revert
            FixType::ManualAction {
                instructions: "Do something".into(),
            },
        );
        // ManualAction with reversible=true: execute then revert should fail
        engine.add_remediations(vec![rem]);

        engine.execute("rem-4").unwrap();
        assert!(engine.revert("rem-4").is_err());
    }

    #[test]
    fn test_revert_non_reversible_fails() {
        let mut engine = RemediationEngine::new("scan-124".into());
        let rem = make_test_remediation(
            "rem-5",
            "FINDING-5",
            FixRisk::Safe,
            false, // not reversible
            FixType::PolicyChange {
                action: PolicyAction::AddRule,
                rule_description: "Block access".into(),
                preview_diff: "block".into(),
            },
        );
        engine.add_remediations(vec![rem]);

        engine.execute("rem-5").unwrap();
        assert!(engine.revert("rem-5").is_err());
    }

    #[test]
    fn test_revert_non_executed_fails() {
        let mut engine = RemediationEngine::new("scan-125".into());
        let rem = make_test_remediation(
            "rem-6",
            "FINDING-6",
            FixRisk::Safe,
            true,
            FixType::PolicyChange {
                action: PolicyAction::AddRule,
                rule_description: "Block".into(),
                preview_diff: "block".into(),
            },
        );
        engine.add_remediations(vec![rem]);

        // Try to revert without executing first
        assert!(engine.revert("rem-6").is_err());
    }

    // -- execute_all_safe tests ---------------------------------------------

    #[test]
    fn test_execute_all_safe() {
        let mut engine = RemediationEngine::new("scan-130".into());

        let safe_reversible = make_test_remediation(
            "rem-safe-rev",
            "F-1",
            FixRisk::Safe,
            true,
            FixType::PolicyChange {
                action: PolicyAction::AddRule,
                rule_description: "Safe fix".into(),
                preview_diff: "add safe".into(),
            },
        );
        let safe_not_reversible = make_test_remediation(
            "rem-safe-norev",
            "F-2",
            FixRisk::Safe,
            false,
            FixType::ManualAction {
                instructions: "Manual".into(),
            },
        );
        let risky_reversible = make_test_remediation(
            "rem-risky-rev",
            "F-3",
            FixRisk::HighRisk,
            true,
            FixType::PolicyChange {
                action: PolicyAction::ModifyRule,
                rule_description: "Risky fix".into(),
                preview_diff: "modify".into(),
            },
        );
        let safe_reversible_2 = make_test_remediation(
            "rem-safe-rev-2",
            "F-4",
            FixRisk::Safe,
            true,
            FixType::ManualAction {
                instructions: "Another safe fix".into(),
            },
        );

        engine.add_remediations(vec![
            safe_reversible,
            safe_not_reversible,
            risky_reversible,
            safe_reversible_2,
        ]);

        let results = engine.execute_all_safe();

        // Only the two Safe+reversible items should be executed
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_ok()));

        // Verify statuses
        let all = engine.get_all();
        assert_eq!(all[0].status, RemediationStatus::Executed); // safe+reversible
        assert_eq!(all[1].status, RemediationStatus::Proposed); // safe but not reversible
        assert_eq!(all[2].status, RemediationStatus::Proposed); // risky
        assert_eq!(all[3].status, RemediationStatus::Executed); // safe+reversible
    }

    // -- Stats tests --------------------------------------------------------

    #[test]
    fn test_stats_computation() {
        let mut engine = RemediationEngine::new("scan-140".into());

        let rem1 = make_test_remediation(
            "rem-1",
            "F-1",
            FixRisk::Safe,
            true,
            FixType::ManualAction {
                instructions: "Fix 1".into(),
            },
        );
        let rem2 = make_test_remediation(
            "rem-2",
            "F-2",
            FixRisk::LowRisk,
            false,
            FixType::ManualAction {
                instructions: "Fix 2".into(),
            },
        );
        let rem3 = make_test_remediation(
            "rem-3",
            "F-3",
            FixRisk::Safe,
            true,
            FixType::ManualAction {
                instructions: "Fix 3".into(),
            },
        );

        // Execute rem-1
        engine.add_remediations(vec![rem1, rem2, rem3]);
        engine.execute("rem-1").unwrap();

        let stats = engine.get_stats();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.proposed, 2);
        assert_eq!(stats.executed, 1);
        assert_eq!(stats.reverted, 0);
        assert_eq!(stats.safe_count, 2);
        assert_eq!(stats.reversible_count, 2);
    }

    #[test]
    fn test_stats_empty_engine() {
        let engine = RemediationEngine::new("scan-141".into());
        let stats = engine.get_stats();
        assert_eq!(stats.total, 0);
        assert_eq!(stats.proposed, 0);
        assert_eq!(stats.executed, 0);
        assert_eq!(stats.safe_count, 0);
        assert_eq!(stats.reversible_count, 0);
    }

    // -- Full lifecycle test ------------------------------------------------

    #[test]
    fn test_full_lifecycle_policy_change() {
        let mut engine = RemediationEngine::new("scan-150".into());

        let rem = make_test_remediation(
            "rem-lifecycle",
            "FINDING-L1",
            FixRisk::LowRisk,
            true,
            FixType::PolicyChange {
                action: PolicyAction::ModifyRule,
                rule_description: "Tighten FileManager access".into(),
                preview_diff: "change allow -> prompt".into(),
            },
        );
        engine.add_remediations(vec![rem]);

        // 1. Proposed
        assert_eq!(engine.get_all()[0].status, RemediationStatus::Proposed);

        // 2. Preview
        let preview = engine.preview("rem-lifecycle").unwrap();
        assert!(preview.preview_text.contains("Policy change"));

        // 3. Execute
        engine.execute("rem-lifecycle").unwrap();
        assert_eq!(engine.get_all()[0].status, RemediationStatus::Executed);
        assert!(engine.get_all()[0].executed_at.is_some());
        assert!(engine.get_all()[0].revert_data.is_some());

        // 4. Revert
        engine.revert("rem-lifecycle").unwrap();
        assert_eq!(engine.get_all()[0].status, RemediationStatus::Reverted);
    }

    // -- Tag attribute parsing edge cases -----------------------------------

    #[test]
    fn test_parse_tag_attr() {
        assert_eq!(
            parse_tag_attr("[REMEDIATION for=FINDING-3 risk=low]", "for"),
            Some("FINDING-3".to_string())
        );
        assert_eq!(
            parse_tag_attr("[REMEDIATION for=FINDING-3 risk=low]", "risk"),
            Some("low".to_string())
        );
        assert_eq!(
            parse_tag_attr("[REMEDIATION for=FINDING-3 risk=low]", "missing"),
            None
        );
    }

    #[test]
    fn test_parse_risk_variants() {
        assert_eq!(parse_risk("safe"), FixRisk::Safe);
        assert_eq!(parse_risk("Safe"), FixRisk::Safe);
        assert_eq!(parse_risk("low"), FixRisk::LowRisk);
        assert_eq!(parse_risk("medium"), FixRisk::MediumRisk);
        assert_eq!(parse_risk("med"), FixRisk::MediumRisk);
        assert_eq!(parse_risk("high"), FixRisk::HighRisk);
        assert_eq!(parse_risk("unknown"), FixRisk::MediumRisk); // default
    }
}
