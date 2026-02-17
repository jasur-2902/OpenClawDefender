//! Suggestions engine for the `checkIntent` tool.
//!
//! When an intent is blocked, provides helpful alternative approaches.

use crate::types::ActionType;

/// A suggestion pattern: if the target matches the pattern and the action type
/// matches, return the associated suggestion.
struct SuggestionRule {
    action_type: Option<ActionType>,
    target_contains: &'static str,
    suggestion: &'static str,
}

const SUGGESTION_RULES: &[SuggestionRule] = &[
    SuggestionRule {
        action_type: Some(ActionType::FileRead),
        target_contains: ".ssh/id_",
        suggestion: "Use environment variables or a secrets manager instead of reading SSH keys directly",
    },
    SuggestionRule {
        action_type: Some(ActionType::FileRead),
        target_contains: ".ssh/known_hosts",
        suggestion: "Use ssh-keyscan to verify host keys programmatically",
    },
    SuggestionRule {
        action_type: Some(ActionType::FileRead),
        target_contains: "credentials",
        suggestion: "Use environment variables for credentials instead of reading credential files",
    },
    SuggestionRule {
        action_type: Some(ActionType::FileRead),
        target_contains: ".env",
        suggestion: "Request specific environment variable values instead of reading the .env file",
    },
    SuggestionRule {
        action_type: Some(ActionType::FileRead),
        target_contains: "password",
        suggestion: "Use a secrets manager or environment variables for passwords",
    },
    SuggestionRule {
        action_type: Some(ActionType::FileRead),
        target_contains: "token",
        suggestion: "Use environment variables for API tokens instead of reading token files",
    },
    SuggestionRule {
        action_type: Some(ActionType::ShellExecute),
        target_contains: "rm -rf",
        suggestion: "Call requestPermission first for destructive operations, or use a safer alternative like trash",
    },
    SuggestionRule {
        action_type: Some(ActionType::ShellExecute),
        target_contains: "sudo",
        suggestion: "Avoid elevated privileges; call requestPermission with a justification for why root access is needed",
    },
    SuggestionRule {
        action_type: Some(ActionType::ShellExecute),
        target_contains: "curl",
        suggestion: "Use requestPermission to declare the target URL before making network requests",
    },
    SuggestionRule {
        action_type: Some(ActionType::ShellExecute),
        target_contains: "wget",
        suggestion: "Use requestPermission to declare the target URL before downloading files",
    },
    SuggestionRule {
        action_type: Some(ActionType::NetworkRequest),
        target_contains: "",
        suggestion: "Add the target host to the policy allow list, or call requestPermission first",
    },
    SuggestionRule {
        action_type: Some(ActionType::FileDelete),
        target_contains: "",
        suggestion: "Call requestPermission before deleting files; consider using trash instead of permanent deletion",
    },
    SuggestionRule {
        action_type: Some(ActionType::FileWrite),
        target_contains: "/etc/",
        suggestion: "System configuration changes require explicit permission; call requestPermission with justification",
    },
    SuggestionRule {
        action_type: Some(ActionType::FileWrite),
        target_contains: ".config",
        suggestion: "Configuration file modifications should use requestPermission to get explicit approval",
    },
    SuggestionRule {
        action_type: None,
        target_contains: "",
        suggestion: "Call requestPermission with a detailed justification to request access for this operation",
    },
];

/// Generate suggestions for a blocked intent.
///
/// Returns a list of helpful suggestions based on the action type and target.
pub fn suggest(action_type: &ActionType, target: &str) -> Vec<String> {
    let mut suggestions = Vec::new();

    for rule in SUGGESTION_RULES {
        // Match action type if specified.
        if let Some(ref rule_action) = rule.action_type {
            if rule_action != action_type {
                continue;
            }
        }

        // Match target pattern (empty means match all for this action type).
        if rule.target_contains.is_empty() || target.contains(rule.target_contains) {
            let s = rule.suggestion.to_string();
            if !suggestions.contains(&s) {
                suggestions.push(s);
            }
        }
    }

    // Always include the generic fallback if we have few suggestions.
    if suggestions.is_empty() {
        suggestions.push(
            "Call requestPermission with a detailed justification to request access for this operation"
                .to_string(),
        );
    }

    suggestions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_key_read_suggests_env_vars() {
        let suggestions = suggest(&ActionType::FileRead, "/home/user/.ssh/id_rsa");
        assert!(!suggestions.is_empty());
        assert!(suggestions[0].contains("environment variables"));
    }

    #[test]
    fn credentials_read_suggests_env_vars() {
        let suggestions = suggest(&ActionType::FileRead, "/app/credentials.json");
        assert!(!suggestions.is_empty());
        assert!(suggestions.iter().any(|s| s.contains("credentials")));
    }

    #[test]
    fn destructive_shell_suggests_request_permission() {
        let suggestions = suggest(&ActionType::ShellExecute, "rm -rf /tmp/data");
        assert!(!suggestions.is_empty());
        assert!(suggestions.iter().any(|s| s.contains("requestPermission")));
    }

    #[test]
    fn network_request_suggests_allow_list() {
        let suggestions = suggest(&ActionType::NetworkRequest, "https://evil.com");
        assert!(!suggestions.is_empty());
        assert!(suggestions.iter().any(|s| s.contains("allow list")));
    }

    #[test]
    fn file_delete_suggests_permission() {
        let suggestions = suggest(&ActionType::FileDelete, "/important/file.txt");
        assert!(!suggestions.is_empty());
        assert!(suggestions.iter().any(|s| s.contains("requestPermission")));
    }

    #[test]
    fn unknown_action_gets_generic_suggestion() {
        let suggestions = suggest(&ActionType::Other, "something");
        assert!(!suggestions.is_empty());
        assert!(suggestions.iter().any(|s| s.contains("requestPermission")));
    }

    #[test]
    fn sudo_command_suggests_avoiding_privileges() {
        let suggestions = suggest(&ActionType::ShellExecute, "sudo apt install foo");
        assert!(suggestions.iter().any(|s| s.contains("elevated privileges")));
    }

    #[test]
    fn env_file_read_suggests_specific_vars() {
        let suggestions = suggest(&ActionType::FileRead, "/app/.env");
        assert!(suggestions.iter().any(|s| s.contains("environment variable")));
    }

    #[test]
    fn etc_write_suggests_permission() {
        let suggestions = suggest(&ActionType::FileWrite, "/etc/hosts");
        assert!(suggestions.iter().any(|s| s.contains("requestPermission")));
    }
}
