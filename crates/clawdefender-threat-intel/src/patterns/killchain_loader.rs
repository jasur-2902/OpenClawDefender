//! Dynamic kill chain pattern loading from the threat feed.

use std::collections::HashSet;

use crate::types::KillChainPatterns;

use super::types::{
    DynamicAttackPattern, DynamicPatternStep, PatternSource, Severity, StepEventType,
};

// ---------------------------------------------------------------------------
// KillChainLoader
// ---------------------------------------------------------------------------

/// Loads and merges kill chain attack patterns from the threat feed.
pub struct KillChainLoader;

impl KillChainLoader {
    /// Parse feed data into dynamic attack patterns.
    pub fn load_from_feed(data: &KillChainPatterns) -> Vec<DynamicAttackPattern> {
        data.patterns
            .iter()
            .filter_map(|p| {
                let severity = match p.severity.to_lowercase().as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => {
                        tracing::warn!(id = %p.id, severity = %p.severity, "unknown severity, defaulting to medium");
                        Severity::Medium
                    }
                };

                let steps: Vec<DynamicPatternStep> = p
                    .stages
                    .iter()
                    .filter_map(|stage| parse_stage(stage))
                    .collect();

                if steps.is_empty() {
                    tracing::warn!(id = %p.id, "skipping pattern with no valid steps");
                    return None;
                }

                Some(DynamicAttackPattern {
                    id: p.id.clone(),
                    name: p.name.clone(),
                    severity,
                    window_seconds: 120, // default; feed format could extend this
                    explanation: p.description.clone(),
                    steps,
                    source: PatternSource::Feed,
                    version: data.version.clone(),
                })
            })
            .collect()
    }

    /// Merge built-in pattern names with dynamic patterns, deduplicating by ID.
    ///
    /// Built-in patterns are identified by their name (since core `AttackPattern`
    /// does not have an `id` field). Dynamic patterns with the same ID as an
    /// already-seen dynamic pattern are deduplicated, keeping the latest.
    ///
    /// Returns the merged list of `DynamicAttackPattern` values. The caller
    /// (Agent 7 integration layer) is responsible for converting these back
    /// to core `AttackPattern` values and injecting them into the detector.
    pub fn merge_patterns(
        builtin_names: &[String],
        dynamic: &[DynamicAttackPattern],
    ) -> Vec<DynamicAttackPattern> {
        let mut seen_ids: HashSet<String> = HashSet::new();
        let mut result: Vec<DynamicAttackPattern> = Vec::new();

        // Reserve built-in names so dynamic patterns don't shadow them.
        for name in builtin_names {
            seen_ids.insert(name.clone());
        }

        // Add dynamic patterns, skipping duplicates.
        for pat in dynamic {
            if seen_ids.contains(&pat.id) {
                continue;
            }
            seen_ids.insert(pat.id.clone());
            result.push(pat.clone());
        }

        result
    }

    /// Prepare a hot-reload payload: the list of new dynamic patterns that
    /// should be appended to the detector's built-in patterns.
    ///
    /// The actual mutation of `KillChainDetector` is left to the integration
    /// layer (Agent 7) because the detector lives in `clawdefender-core` and
    /// this crate does not depend on core.
    pub fn hot_reload_payload(
        builtin_names: &[String],
        new_patterns: &[DynamicAttackPattern],
    ) -> Vec<DynamicAttackPattern> {
        Self::merge_patterns(builtin_names, new_patterns)
    }
}

// ---------------------------------------------------------------------------
// Stage parser
// ---------------------------------------------------------------------------

/// Parse a stage string like "file_read:/secret/*" or "network_connect" into
/// a `DynamicPatternStep`.
fn parse_stage(stage: &str) -> Option<DynamicPatternStep> {
    let (event_str, pattern) = if let Some(idx) = stage.find(':') {
        (&stage[..idx], Some(stage[idx + 1..].to_string()))
    } else {
        (stage, None)
    };

    let event_type = match event_str.trim() {
        "file_read" => StepEventType::FileRead,
        "file_write" => StepEventType::FileWrite,
        "file_list" => StepEventType::FileList,
        "network_connect" => StepEventType::NetworkConnect,
        "shell_exec" => StepEventType::ShellExec,
        "sampling_response" => StepEventType::SamplingResponse,
        "any_tool_call" => StepEventType::AnyToolCall,
        _ => {
            tracing::warn!(stage = %stage, "unknown event type in stage");
            return None;
        }
    };

    // Determine whether pattern goes to path_pattern or destination_pattern
    let (path_pattern, destination_pattern) = match event_type {
        StepEventType::NetworkConnect => (None, pattern),
        _ => (pattern, None),
    };

    Some(DynamicPatternStep {
        event_type,
        path_pattern,
        destination_pattern,
        min_count: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::KillChainPattern;

    #[test]
    fn test_parse_stage_file_read() {
        let step = parse_stage("file_read:~/.ssh/*").unwrap();
        assert_eq!(step.event_type, StepEventType::FileRead);
        assert_eq!(step.path_pattern.as_deref(), Some("~/.ssh/*"));
        assert!(step.destination_pattern.is_none());
    }

    #[test]
    fn test_parse_stage_network() {
        let step = parse_stage("network_connect:!localhost").unwrap();
        assert_eq!(step.event_type, StepEventType::NetworkConnect);
        assert!(step.path_pattern.is_none());
        assert_eq!(step.destination_pattern.as_deref(), Some("!localhost"));
    }

    #[test]
    fn test_parse_stage_bare() {
        let step = parse_stage("shell_exec").unwrap();
        assert_eq!(step.event_type, StepEventType::ShellExec);
        assert!(step.path_pattern.is_none());
        assert!(step.destination_pattern.is_none());
    }

    #[test]
    fn test_parse_stage_unknown() {
        assert!(parse_stage("unknown_type").is_none());
    }

    #[test]
    fn test_load_from_feed() {
        let data = KillChainPatterns {
            version: "2.0.0".into(),
            patterns: vec![KillChainPattern {
                id: "feed_cred_exfil".into(),
                name: "Feed Credential Exfiltration".into(),
                description: "Reads creds then connects out".into(),
                stages: vec![
                    "file_read:~/.ssh/*".into(),
                    "network_connect:!localhost".into(),
                ],
                severity: "critical".into(),
            }],
        };

        let patterns = KillChainLoader::load_from_feed(&data);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].id, "feed_cred_exfil");
        assert_eq!(patterns[0].severity, Severity::Critical);
        assert_eq!(patterns[0].steps.len(), 2);
        assert_eq!(patterns[0].source, PatternSource::Feed);
        assert_eq!(patterns[0].version, "2.0.0");
    }

    #[test]
    fn test_merge_no_duplicates() {
        let builtin_names = vec!["credential_theft_exfiltration".to_string()];
        let dynamic = vec![
            DynamicAttackPattern {
                id: "credential_theft_exfiltration".into(), // same as built-in
                name: "dup".into(),
                severity: Severity::High,
                window_seconds: 60,
                explanation: "dup".into(),
                steps: vec![],
                source: PatternSource::Feed,
                version: "1.0.0".into(),
            },
            DynamicAttackPattern {
                id: "new_pattern".into(),
                name: "New".into(),
                severity: Severity::Medium,
                window_seconds: 30,
                explanation: "new".into(),
                steps: vec![],
                source: PatternSource::Feed,
                version: "1.0.0".into(),
            },
        ];

        let merged = KillChainLoader::merge_patterns(&builtin_names, &dynamic);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].id, "new_pattern");
    }
}
