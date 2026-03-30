use crate::state::PolicyRule;
use super::generator::{generate_trust_rules, sanitize_server_name, trust_rule_key};
use super::levels::TrustLevel;
use super::permissions::{canonical_action, Permission};

use serde::{Deserialize, Serialize};

/// Information about a server's trust level, returned to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustLevelInfo {
    pub level: String,
    pub customized: bool,
    pub permissions: Vec<PermissionState>,
}

/// State of a single permission for a server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionState {
    pub id: String,
    pub name: String,
    pub description: String,
    pub action: String,
    pub locked: bool,
    pub overridden: bool,
}

/// A description of what changes when switching trust levels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionChange {
    pub permission: String,
    pub from_action: String,
    pub to_action: String,
    pub description: String,
}

/// Infer the trust level for a server from existing policy rules.
/// Returns (TrustLevel, is_customized).
/// If no trust rules exist for this server, returns (Standard, false).
pub fn infer_trust_level(server_name: &str, rules: &[PolicyRule]) -> (TrustLevel, bool) {
    let sanitized = sanitize_server_name(server_name);
    let prefix = format!("trust.{}.", sanitized);

    let trust_rules: Vec<&PolicyRule> = rules
        .iter()
        .filter(|r| r.name.starts_with(&prefix))
        .collect();

    if trust_rules.is_empty() {
        return (TrustLevel::Standard, false);
    }

    // Determine base level from average priority of non-sensitive rules
    let main_rules: Vec<&&PolicyRule> = trust_rules
        .iter()
        .filter(|r| !r.name.ends_with(".sensitive-paths") && !r.name.ends_with(".tool-call-list-only"))
        .collect();

    if main_rules.is_empty() {
        return (TrustLevel::Standard, false);
    }

    let avg_priority: f64 =
        main_rules.iter().map(|r| r.priority as f64).sum::<f64>() / main_rules.len() as f64;

    let base_level = if avg_priority >= 500.0 {
        TrustLevel::Restricted
    } else if avg_priority >= 400.0 {
        TrustLevel::Cautious
    } else if avg_priority >= 300.0 {
        TrustLevel::Standard
    } else {
        TrustLevel::Trusted
    };

    // Check if rules match the canonical set exactly
    let canonical = generate_trust_rules(server_name, base_level);
    let customized = !rules_match_canonical(&trust_rules, &canonical);

    if customized {
        // Check if it still looks like a known level with tweaks, or is fully custom
        // We keep the base level but mark it customized
        (base_level, true)
    } else {
        (base_level, false)
    }
}

/// Check if existing rules match the canonical rules for a trust level.
fn rules_match_canonical(existing: &[&PolicyRule], canonical: &[PolicyRule]) -> bool {
    // Every canonical rule must have a matching existing rule (same name + action)
    for canon in canonical {
        let found = existing.iter().any(|r| r.name == canon.name && r.action == canon.action);
        if !found {
            return false;
        }
    }
    // Check no extra trust rules exist beyond canonical + known extras (like tool-call-list-only)
    let canonical_names: std::collections::HashSet<&str> =
        canonical.iter().map(|r| r.name.as_str()).collect();
    for r in existing {
        if !canonical_names.contains(r.name.as_str()) {
            return false;
        }
    }
    true
}

/// Build a TrustLevelInfo for a server, examining current policy rules.
pub fn build_trust_level_info(server_name: &str, rules: &[PolicyRule]) -> TrustLevelInfo {
    let (level, customized) = infer_trust_level(server_name, rules);

    let permissions: Vec<PermissionState> = Permission::all()
        .iter()
        .map(|perm| {
            let key = trust_rule_key(server_name, perm.category());
            let current_action = rules
                .iter()
                .find(|r| r.name == key)
                .map(|r| r.action.as_str())
                .unwrap_or_else(|| canonical_action(level, *perm));

            let canonical = canonical_action(level, *perm);
            let overridden = current_action != canonical && !perm.is_locked();

            PermissionState {
                id: perm.frontend_id().to_string(),
                name: perm.label().to_string(),
                description: perm.description().to_string(),
                action: current_action.to_string(),
                locked: perm.is_locked(),
                overridden,
            }
        })
        .collect();

    TrustLevelInfo {
        level: level.as_str().to_string(),
        customized,
        permissions,
    }
}

/// Preview what changes would occur when switching from current rules to a new trust level.
pub fn preview_trust_change(
    server_name: &str,
    current_rules: &[PolicyRule],
    new_level: TrustLevel,
) -> Vec<PermissionChange> {
    let mut changes = Vec::new();

    for perm in Permission::all() {
        if perm.is_locked() {
            continue; // Sensitive paths never change
        }

        let key = trust_rule_key(server_name, perm.category());
        let current_action = current_rules
            .iter()
            .find(|r| r.name == key)
            .map(|r| r.action.as_str())
            .unwrap_or("prompt"); // default if no rule exists

        let new_action = canonical_action(new_level, *perm);

        if current_action != new_action {
            changes.push(PermissionChange {
                permission: perm.frontend_id().to_string(),
                from_action: current_action.to_string(),
                to_action: new_action.to_string(),
                description: format!(
                    "{}: {} -> {}",
                    perm.label(),
                    action_label(current_action),
                    action_label(new_action)
                ),
            });
        }
    }

    changes
}

fn action_label(action: &str) -> &str {
    match action {
        "allow" => "Allowed",
        "prompt" => "Ask first",
        "block" => "Blocked",
        _ => action,
    }
}
