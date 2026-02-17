//! Conflict detection between community rules and user-defined policy rules.

use serde::{Deserialize, Serialize};

use super::types::{CommunityRule, CommunityRulePack, RuleAction};

/// The type of conflict between two rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictType {
    /// The community rule is completely overridden by the user rule
    /// (same scope, user takes precedence).
    Overridden,
    /// The community rule contradicts the user rule
    /// (one blocks what the other allows, or vice-versa).
    Contradicts,
}

/// A detected conflict between a community rule and a user rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConflict {
    /// The community rule involved.
    pub community_rule: String,
    /// The user rule involved.
    pub user_rule: String,
    /// Kind of conflict.
    pub conflict_type: ConflictType,
    /// Human-readable description.
    pub description: String,
}

/// Represents a minimal user policy rule for conflict checking.
/// This mirrors the fields we need from `PolicyRule` without depending
/// on clawdefender-core directly.
#[derive(Debug, Clone)]
pub struct UserPolicyRule {
    pub name: String,
    pub action: UserAction,
    pub methods: Vec<String>,
    pub resource_paths: Vec<String>,
}

/// Simplified action enum for conflict detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserAction {
    Allow,
    Block,
    Prompt,
    Log,
}

/// Detects conflicts between community rule packs and user-defined rules.
pub struct ConflictDetector;

impl ConflictDetector {
    /// Detect conflicts between all rules in a community pack and a set of
    /// user rules.
    pub fn detect_conflicts(
        pack: &CommunityRulePack,
        user_rules: &[UserPolicyRule],
    ) -> Vec<RuleConflict> {
        let mut conflicts = Vec::new();

        for community_rule in &pack.rules {
            for user_rule in user_rules {
                if let Some(conflict) = Self::check_pair(community_rule, user_rule) {
                    conflicts.push(conflict);
                }
            }
        }

        conflicts
    }

    /// Check a single community-rule / user-rule pair for conflict.
    fn check_pair(community: &CommunityRule, user: &UserPolicyRule) -> Option<RuleConflict> {
        let paths_overlap = Self::paths_overlap(&community.paths, &user.resource_paths);
        let methods_overlap = Self::methods_overlap(&community.methods, &user.methods);

        // Rules must have overlapping scope to conflict.
        if !paths_overlap && !methods_overlap {
            return None;
        }

        let community_action = &community.action;
        let user_action = &user.action;

        // Contradicts: one blocks, the other allows (or vice versa).
        let contradicts = matches!(
            (community_action, user_action),
            (RuleAction::Block, UserAction::Allow)
                | (RuleAction::Allow, UserAction::Block)
        );

        if contradicts {
            return Some(RuleConflict {
                community_rule: community.name.clone(),
                user_rule: user.name.clone(),
                conflict_type: ConflictType::Contradicts,
                description: format!(
                    "Community rule '{}' ({}) contradicts user rule '{}' ({}) on overlapping scope",
                    community.name,
                    action_label(community_action),
                    user.name,
                    user_action_label(user_action),
                ),
            });
        }

        // Overridden: same scope, same or compatible action but user takes precedence.
        let overridden = paths_overlap || methods_overlap;
        if overridden && community_action_to_user(community_action) == *user_action {
            return Some(RuleConflict {
                community_rule: community.name.clone(),
                user_rule: user.name.clone(),
                conflict_type: ConflictType::Overridden,
                description: format!(
                    "Community rule '{}' is overridden by user rule '{}' (same action on overlapping scope)",
                    community.name, user.name,
                ),
            });
        }

        // Different non-contradictory actions on overlapping paths (e.g. log vs prompt).
        if paths_overlap && community_action_to_user(community_action) != *user_action {
            return Some(RuleConflict {
                community_rule: community.name.clone(),
                user_rule: user.name.clone(),
                conflict_type: ConflictType::Contradicts,
                description: format!(
                    "Community rule '{}' ({}) and user rule '{}' ({}) have different actions on overlapping paths",
                    community.name,
                    action_label(community_action),
                    user.name,
                    user_action_label(user_action),
                ),
            });
        }

        None
    }

    /// Check if two sets of path globs overlap.
    /// Simple heuristic: any shared literal prefix or identical patterns.
    fn paths_overlap(community_paths: &[String], user_paths: &[String]) -> bool {
        if community_paths.is_empty() || user_paths.is_empty() {
            return false;
        }
        for cp in community_paths {
            for up in user_paths {
                if Self::globs_may_overlap(cp, up) {
                    return true;
                }
            }
        }
        false
    }

    /// Check if two sets of methods overlap.
    fn methods_overlap(community_methods: &[String], user_methods: &[String]) -> bool {
        if community_methods.is_empty() || user_methods.is_empty() {
            return false;
        }
        for cm in community_methods {
            for um in user_methods {
                if cm == um {
                    return true;
                }
            }
        }
        false
    }

    /// Heuristic: two globs may overlap if one contains the other or they
    /// share a common prefix before the first wildcard.
    fn globs_may_overlap(a: &str, b: &str) -> bool {
        // Exact match.
        if a == b {
            return true;
        }
        // One is a prefix/superset of the other (with wildcards).
        let a_base = a.split('*').next().unwrap_or(a);
        let b_base = b.split('*').next().unwrap_or(b);
        a_base.starts_with(b_base) || b_base.starts_with(a_base)
    }
}

fn action_label(a: &RuleAction) -> &'static str {
    match a {
        RuleAction::Block => "block",
        RuleAction::Allow => "allow",
        RuleAction::Prompt => "prompt",
        RuleAction::Log => "log",
    }
}

fn user_action_label(a: &UserAction) -> &'static str {
    match a {
        UserAction::Block => "block",
        UserAction::Allow => "allow",
        UserAction::Prompt => "prompt",
        UserAction::Log => "log",
    }
}

fn community_action_to_user(a: &RuleAction) -> UserAction {
    match a {
        RuleAction::Block => UserAction::Block,
        RuleAction::Allow => UserAction::Allow,
        RuleAction::Prompt => UserAction::Prompt,
        RuleAction::Log => UserAction::Log,
    }
}
