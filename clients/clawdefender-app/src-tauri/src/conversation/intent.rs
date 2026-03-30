use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::entities::EntityExtractor;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A classified user intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentClassification {
    /// The intent ID (e.g., "status.overall", "control.block").
    pub intent_id: String,
    /// Classification confidence from 0.0 to 1.0.
    pub confidence: f32,
    /// Extracted named entities relevant to this intent.
    pub entities: HashMap<String, String>,
    /// How this intent was classified.
    pub method: ClassificationMethod,
}

/// How the intent was classified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationMethod {
    /// Matched by keyword/pattern rules (fast, deterministic).
    Keyword,
    /// Classified by the SLM (slower, required for ambiguous input).
    Llm,
    /// Fallback when nothing matched.
    Fallback,
}

// ---------------------------------------------------------------------------
// Keyword rule definition
// ---------------------------------------------------------------------------

struct KeywordRule {
    intent_id: &'static str,
    /// Exact phrases that map directly to this intent (Layer 1).
    exact_phrases: &'static [&'static str],
    /// Required keywords — at least one set must match (Layer 2).
    /// Each inner slice is an AND group: all words in a group must be present.
    keyword_groups: &'static [&'static [&'static str]],
    /// Optional: entity types this intent expects.
    expected_entities: &'static [&'static str],
    /// Base confidence for keyword match (Layer 2). Exact match always gets 1.0.
    keyword_confidence: f32,
}

// ---------------------------------------------------------------------------
// Intent registry — all 28 intents
// ---------------------------------------------------------------------------

const INTENT_RULES: &[KeywordRule] = &[
    // -----------------------------------------------------------------------
    // 5.1 Status Queries
    // -----------------------------------------------------------------------
    KeywordRule {
        intent_id: "status.overall",
        exact_phrases: &[
            "am i safe",
            "how's everything",
            "hows everything",
            "what's my status",
            "whats my status",
            "am i protected",
            "give me a summary",
            "how are things looking",
            "what's happening",
            "whats happening",
            "overall status",
            "system status",
        ],
        keyword_groups: &[
            &["status", "overall"],
            &["everything", "ok"],
            &["everything", "good"],
            &["summary"],
            &["overview"],
            &["protected"],
        ],
        expected_entities: &[],
        keyword_confidence: 0.8,
    },
    KeywordRule {
        intent_id: "status.protection_score",
        exact_phrases: &[
            "what's my protection score",
            "whats my protection score",
            "how protected am i",
            "protection level",
            "security rating",
            "my score",
        ],
        keyword_groups: &[
            &["protection", "score"],
            &["security", "score"],
            &["security", "rating"],
            &["protection", "level"],
            &["score"],
        ],
        expected_entities: &[],
        keyword_confidence: 0.75,
    },
    KeywordRule {
        intent_id: "status.daemon",
        exact_phrases: &[
            "is the daemon running",
            "daemon status",
            "is clawdefender running",
            "service status",
            "is protection active",
            "are you running",
            "are you on",
            "is the service up",
        ],
        keyword_groups: &[
            &["daemon", "running"],
            &["daemon", "status"],
            &["service", "running"],
            &["service", "status"],
            &["protection", "active"],
            &["daemon", "up"],
        ],
        expected_entities: &[],
        keyword_confidence: 0.85,
    },
    KeywordRule {
        intent_id: "status.server_specific",
        exact_phrases: &[],
        keyword_groups: &[
            &["status"],
            &["how", "is"],
            &["tell", "about"],
            &["what", "about"],
            &["doing"],
        ],
        expected_entities: &["server_name"],
        keyword_confidence: 0.7,
    },
    KeywordRule {
        intent_id: "status.model",
        exact_phrases: &[
            "what model is loaded",
            "ai status",
            "slm status",
            "is the ai model working",
            "which model am i using",
            "model status",
            "what ai am i using",
        ],
        keyword_groups: &[
            &["model", "loaded"],
            &["model", "status"],
            &["ai", "status"],
            &["slm", "status"],
            &["model", "using"],
            &["ai", "model"],
        ],
        expected_entities: &[],
        keyword_confidence: 0.8,
    },

    // -----------------------------------------------------------------------
    // 5.2 Activity Queries
    // -----------------------------------------------------------------------
    KeywordRule {
        intent_id: "activity.recent",
        exact_phrases: &[
            "what happened recently",
            "show me recent events",
            "recent activity",
            "what's been going on",
            "whats been going on",
            "any activity",
            "latest events",
            "recent events",
        ],
        keyword_groups: &[
            &["recent", "events"],
            &["recent", "activity"],
            &["latest", "events"],
            &["happened", "recently"],
            &["going", "on"],
        ],
        expected_entities: &[],
        keyword_confidence: 0.8,
    },
    KeywordRule {
        intent_id: "activity.time_range",
        exact_phrases: &[
            "what happened today",
            "events this hour",
            "what happened yesterday",
            "show me today's events",
            "show me todays events",
        ],
        keyword_groups: &[
            &["happened", "today"],
            &["events", "today"],
            &["happened", "yesterday"],
            &["activity", "today"],
            &["events", "hour"],
            &["last", "minutes"],
            &["events", "this"],
        ],
        expected_entities: &["time_range"],
        keyword_confidence: 0.75,
    },
    KeywordRule {
        intent_id: "activity.blocked",
        exact_phrases: &[
            "what did you block",
            "blocked events",
            "show me blocks",
            "what was denied",
            "any threats blocked",
            "blocked activity",
        ],
        keyword_groups: &[
            &["blocked", "events"],
            &["blocked", "activity"],
            &["threats", "blocked"],
            &["denied"],
            &["blocks"],
            &["you", "block"],
        ],
        expected_entities: &[],
        keyword_confidence: 0.8,
    },
    KeywordRule {
        intent_id: "activity.server",
        exact_phrases: &[],
        keyword_groups: &[
            &["been", "doing"],
            &["activity", "for"],
            &["events", "from"],
            &["activity"],
            &["events"],
        ],
        expected_entities: &["server_name"],
        keyword_confidence: 0.7,
    },
    KeywordRule {
        intent_id: "activity.stats",
        exact_phrases: &[
            "give me stats",
            "event statistics",
            "how many events",
            "event count",
            "activity summary",
            "show me numbers",
        ],
        keyword_groups: &[
            &["stats"],
            &["statistics"],
            &["event", "count"],
            &["how", "many", "events"],
            &["numbers"],
        ],
        expected_entities: &[],
        keyword_confidence: 0.75,
    },

    // -----------------------------------------------------------------------
    // 5.3 Risk Assessment
    // -----------------------------------------------------------------------
    KeywordRule {
        intent_id: "risk.file",
        exact_phrases: &[
            "is this file safe",
            "check this file",
            "analyze this file",
            "scan this file",
            "is this suspicious",
        ],
        keyword_groups: &[
            &["file", "safe"],
            &["check", "file"],
            &["analyze", "file"],
            &["scan", "file"],
            &["suspicious", "file"],
        ],
        expected_entities: &["file_path"],
        keyword_confidence: 0.75,
    },
    KeywordRule {
        intent_id: "risk.url",
        exact_phrases: &[
            "is this url safe",
            "check this link",
            "is this domain suspicious",
            "analyze this url",
            "should i trust this link",
        ],
        keyword_groups: &[
            &["url", "safe"],
            &["link", "safe"],
            &["check", "link"],
            &["check", "url"],
            &["domain", "suspicious"],
            &["trust", "link"],
            &["analyze", "url"],
        ],
        expected_entities: &["url"],
        keyword_confidence: 0.75,
    },
    KeywordRule {
        intent_id: "risk.server",
        exact_phrases: &[],
        keyword_groups: &[
            &["safe"],
            &["trust"],
            &["risk"],
            &["risky"],
            &["suspicious"],
        ],
        expected_entities: &["server_name"],
        keyword_confidence: 0.7,
    },
    KeywordRule {
        intent_id: "risk.action",
        exact_phrases: &[
            "should i allow this",
            "is this safe to allow",
            "what happens if i allow this",
            "should i block this",
            "what do you recommend",
        ],
        keyword_groups: &[
            &["should", "allow"],
            &["safe", "allow"],
            &["should", "block"],
            &["recommend"],
        ],
        expected_entities: &[],
        keyword_confidence: 0.7,
    },

    // -----------------------------------------------------------------------
    // 5.4 Control Actions
    // -----------------------------------------------------------------------
    KeywordRule {
        intent_id: "control.block",
        exact_phrases: &[
            "block it",
            "block this server",
        ],
        keyword_groups: &[
            &["block"],
            &["deny", "access"],
            &["shut", "down"],
            &["stop"],
        ],
        expected_entities: &["server_name"],
        keyword_confidence: 0.75,
    },
    KeywordRule {
        intent_id: "control.allow",
        exact_phrases: &[
            "allow it",
            "let it through",
            "allow this",
        ],
        keyword_groups: &[
            &["allow"],
            &["trust"],
            &["unblock"],
            &["permit"],
            &["let", "through"],
        ],
        expected_entities: &["server_name"],
        keyword_confidence: 0.75,
    },
    KeywordRule {
        intent_id: "control.trust_level",
        exact_phrases: &[],
        keyword_groups: &[
            &["strict", "mode"],
            &["tighten", "security"],
            &["relax", "rules"],
            &["change", "trust"],
            &["more", "restricted"],
        ],
        expected_entities: &["server_name", "trust_level"],
        keyword_confidence: 0.7,
    },
    KeywordRule {
        intent_id: "control.scan",
        exact_phrases: &[
            "run a scan",
            "scan my system",
            "scan my setup",
            "check for problems",
            "security scan",
            "audit my setup",
            "scan everything",
        ],
        keyword_groups: &[
            &["run", "scan"],
            &["start", "scan"],
            &["security", "scan"],
            &["scan", "system"],
            &["scan", "setup"],
            &["check", "problems"],
            &["audit"],
        ],
        expected_entities: &[],
        keyword_confidence: 0.85,
    },
    KeywordRule {
        intent_id: "control.tighten",
        exact_phrases: &[
            "tighten security",
            "lock everything down",
            "strict mode",
            "maximum protection",
            "paranoid mode",
            "tighten up",
        ],
        keyword_groups: &[
            &["tighten", "security"],
            &["lock", "down"],
            &["strict", "mode"],
            &["maximum", "protection"],
            &["paranoid"],
            &["tighten"],
        ],
        expected_entities: &[],
        keyword_confidence: 0.8,
    },
    KeywordRule {
        intent_id: "control.pause",
        exact_phrases: &[
            "pause protection",
            "stop monitoring",
            "disable guards",
            "take a break",
            "pause everything",
            "stand down",
        ],
        keyword_groups: &[
            &["pause", "protection"],
            &["stop", "monitoring"],
            &["disable", "guards"],
            &["pause", "everything"],
            &["stand", "down"],
        ],
        expected_entities: &[],
        keyword_confidence: 0.8,
    },
    KeywordRule {
        intent_id: "control.update_threat_intel",
        exact_phrases: &[
            "update threat intelligence",
            "refresh threat feed",
            "update blocklist",
            "get latest threats",
            "update iocs",
            "refresh feeds",
        ],
        keyword_groups: &[
            &["update", "threat"],
            &["refresh", "threat"],
            &["update", "blocklist"],
            &["refresh", "feed"],
            &["update", "ioc"],
            &["latest", "threats"],
        ],
        expected_entities: &[],
        keyword_confidence: 0.85,
    },
    KeywordRule {
        intent_id: "control.wrap",
        exact_phrases: &[
            "protect this server",
        ],
        keyword_groups: &[
            &["protect"],
            &["wrap"],
            &["add", "protection"],
            &["monitor"],
            &["start", "watching"],
        ],
        expected_entities: &["server_name"],
        keyword_confidence: 0.7,
    },
    KeywordRule {
        intent_id: "control.unwrap",
        exact_phrases: &[],
        keyword_groups: &[
            &["unprotect"],
            &["unwrap"],
            &["remove", "protection"],
            &["stop", "watching"],
        ],
        expected_entities: &["server_name"],
        keyword_confidence: 0.7,
    },

    // -----------------------------------------------------------------------
    // 5.5 Explanation Queries
    // -----------------------------------------------------------------------
    KeywordRule {
        intent_id: "explain.event",
        exact_phrases: &[
            "explain this event",
            "tell me more about this",
            "what does this event mean",
            "break this down for me",
        ],
        keyword_groups: &[
            &["explain", "event"],
            &["what", "happened", "event"],
            &["more", "about", "event"],
            &["break", "down"],
        ],
        expected_entities: &["event_id"],
        keyword_confidence: 0.7,
    },
    KeywordRule {
        intent_id: "explain.concept",
        exact_phrases: &[
            "what is mcp",
            "what are behavioral profiles",
            "what does anomaly score mean",
            "how does protection work",
            "what is a guard",
        ],
        keyword_groups: &[
            &["what", "is"],
            &["what", "are"],
            &["what", "does", "mean"],
            &["how", "does", "work"],
            &["explain"],
        ],
        expected_entities: &["concept"],
        keyword_confidence: 0.55,
    },
    KeywordRule {
        intent_id: "explain.why_blocked",
        exact_phrases: &[
            "why was this blocked",
            "why did you block that",
            "what's wrong with this",
            "whats wrong with this",
            "explain the block",
        ],
        keyword_groups: &[
            &["why", "blocked"],
            &["why", "block"],
            &["why", "denied"],
            &["wrong", "with"],
            &["explain", "block"],
        ],
        expected_entities: &[],
        keyword_confidence: 0.8,
    },
    KeywordRule {
        intent_id: "explain.recommendation",
        exact_phrases: &[
            "what should i do",
            "any recommendations",
            "what do you suggest",
            "how can i improve security",
            "what's your advice",
            "whats your advice",
            "help me improve",
        ],
        keyword_groups: &[
            &["recommendations"],
            &["suggest"],
            &["advice"],
            &["should", "do"],
            &["improve", "security"],
            &["improve"],
        ],
        expected_entities: &[],
        keyword_confidence: 0.7,
    },

    // -----------------------------------------------------------------------
    // 5.6 Navigation
    // -----------------------------------------------------------------------
    KeywordRule {
        intent_id: "navigate.page",
        exact_phrases: &[
            "go to settings",
            "show me the dashboard",
            "open policy editor",
            "take me to the scanner",
            "show network log",
            "open guards page",
            "go to dashboard",
            "open settings",
            "show me settings",
            "open scanner",
            "show guards",
            "go to policy",
            "open behavioral",
            "show events",
        ],
        keyword_groups: &[
            &["go", "to"],
            &["open"],
            &["show", "me"],
            &["take", "me"],
            &["navigate"],
        ],
        expected_entities: &["page_name"],
        keyword_confidence: 0.75,
    },
    KeywordRule {
        intent_id: "navigate.server_detail",
        exact_phrases: &[],
        keyword_groups: &[
            &["show", "me"],
            &["go", "to"],
            &["open"],
            &["view", "profile"],
            &["details"],
        ],
        expected_entities: &["server_name"],
        keyword_confidence: 0.65,
    },

    // -----------------------------------------------------------------------
    // 5.7 Help
    // -----------------------------------------------------------------------
    KeywordRule {
        intent_id: "help.general",
        exact_phrases: &[
            "help",
            "what can you do",
            "how does this work",
            "what can i ask you",
            "commands",
            "guide me",
        ],
        keyword_groups: &[
            &["help"],
            &["what", "can", "you"],
            &["guide"],
            &["commands"],
        ],
        expected_entities: &[],
        keyword_confidence: 0.75,
    },
    KeywordRule {
        intent_id: "help.how_to",
        exact_phrases: &[
            "how do i block a server",
            "how do i add a rule",
            "how to run a scan",
            "how do i change settings",
            "how to update threat feeds",
        ],
        keyword_groups: &[
            &["how", "do", "i"],
            &["how", "to"],
        ],
        expected_entities: &["topic"],
        keyword_confidence: 0.7,
    },
];

// ---------------------------------------------------------------------------
// Page name mapping for navigate.page
// ---------------------------------------------------------------------------

const PAGE_NAMES: &[(&[&str], &str)] = &[
    (&["dashboard", "home", "main"], "/"),
    (&["settings", "config", "preferences"], "/settings"),
    (&["policy", "rules", "policy editor"], "/policy"),
    (&["scanner", "scan", "audit"], "/scanner"),
    (&["network", "network log", "connections"], "/network"),
    (&["guards", "agents"], "/guards"),
    (&["behavioral", "profiles", "behavior"], "/behavioral"),
    (&["events", "activity", "log"], "/events"),
];

// ---------------------------------------------------------------------------
// Intent Classifier
// ---------------------------------------------------------------------------

pub struct IntentClassifier {
    entity_extractor: EntityExtractor,
}

impl IntentClassifier {
    pub fn new() -> Self {
        Self {
            entity_extractor: EntityExtractor::new(),
        }
    }

    /// Classify a user message into an intent.
    ///
    /// Runs three layers:
    /// 1. Exact phrase match (confidence = 1.0)
    /// 2. Keyword + entity matching (confidence varies)
    /// 3. LLM fallback (returns "unknown" for the executor to handle)
    pub fn classify(&self, message: &str) -> IntentClassification {
        let normalized = Self::normalize(message);
        let entities = self.entity_extractor.extract(message);

        // Layer 1: Exact phrase match
        if let Some(result) = self.try_exact_match(&normalized, &entities) {
            return result;
        }

        // Layer 2: Keyword + entity matching
        if let Some(result) = self.try_keyword_match(&normalized, &entities) {
            if result.confidence >= 0.5 {
                return result;
            }
        }

        // Layer 3: LLM fallback
        let mut fallback_entities = entities;
        fallback_entities.insert("raw_query".to_string(), message.to_string());
        IntentClassification {
            intent_id: "unknown".to_string(),
            confidence: 0.0,
            entities: fallback_entities,
            method: ClassificationMethod::Fallback,
        }
    }

    /// Normalize text for matching: lowercase, trim, collapse whitespace,
    /// strip basic punctuation.
    fn normalize(input: &str) -> String {
        input
            .to_lowercase()
            .chars()
            .filter(|c| c.is_alphanumeric() || c.is_whitespace() || *c == '/' || *c == '~' || *c == '.' || *c == '-' || *c == '_')
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ")
    }

    /// Layer 1: exact phrase lookup.
    fn try_exact_match(
        &self,
        normalized: &str,
        entities: &HashMap<String, String>,
    ) -> Option<IntentClassification> {
        for rule in INTENT_RULES {
            for phrase in rule.exact_phrases {
                if normalized == *phrase {
                    let mut result_entities = entities.clone();
                    self.enrich_entities(rule, &mut result_entities, normalized);
                    return Some(IntentClassification {
                        intent_id: rule.intent_id.to_string(),
                        confidence: 1.0,
                        entities: result_entities,
                        method: ClassificationMethod::Keyword,
                    });
                }
            }
        }
        None
    }

    /// Layer 2: keyword group matching with entity requirements.
    fn try_keyword_match(
        &self,
        normalized: &str,
        entities: &HashMap<String, String>,
    ) -> Option<IntentClassification> {
        let words: Vec<&str> = normalized.split_whitespace().collect();
        let mut best: Option<IntentClassification> = None;

        for rule in INTENT_RULES {
            // Check entity requirements: if an intent expects server_name but
            // we extracted none, skip (unless there are no entity requirements).
            let has_required_entities = rule.expected_entities.is_empty()
                || rule.expected_entities.iter().any(|e| entities.contains_key(*e));

            // For intents that REQUIRE entities (server_specific, activity.server,
            // risk.server, control.block, etc.), skip if missing.
            let entity_required = !rule.expected_entities.is_empty();

            // Count how many keyword groups match
            let mut matched_groups = 0;
            for group in rule.keyword_groups {
                let all_present = group.iter().all(|kw| words.contains(kw));
                if all_present {
                    matched_groups += 1;
                }
            }

            if matched_groups == 0 {
                continue;
            }

            // Skip if entity required but not present
            if entity_required && !has_required_entities {
                continue;
            }

            // Calculate confidence: any matching group gives the base confidence,
            // additional matches boost slightly.
            let extra_boost = ((matched_groups - 1) as f32 * 0.05).min(0.15);
            let entity_bonus = if has_required_entities && entity_required {
                0.1
            } else {
                0.0
            };
            let confidence =
                (rule.keyword_confidence + extra_boost + entity_bonus).min(0.95);

            // Keep best match
            if best
                .as_ref()
                .map_or(true, |b| confidence > b.confidence)
            {
                let mut result_entities = entities.clone();
                self.enrich_entities(rule, &mut result_entities, normalized);
                best = Some(IntentClassification {
                    intent_id: rule.intent_id.to_string(),
                    confidence,
                    entities: result_entities,
                    method: ClassificationMethod::Keyword,
                });
            }
        }

        best
    }

    /// Add intent-specific derived entities (e.g., page_name for navigate).
    fn enrich_entities(
        &self,
        rule: &KeywordRule,
        entities: &mut HashMap<String, String>,
        normalized: &str,
    ) {
        match rule.intent_id {
            "navigate.page" => {
                if !entities.contains_key("page_name") {
                    if let Some(page) = Self::extract_page_name(normalized) {
                        entities.insert("page_name".to_string(), page.to_string());
                    }
                }
            }
            "explain.concept" => {
                if !entities.contains_key("concept") {
                    // Try to extract the concept from "what is X" / "explain X"
                    let concept = Self::extract_concept(normalized);
                    if let Some(c) = concept {
                        entities.insert("concept".to_string(), c);
                    }
                }
            }
            "help.how_to" => {
                if !entities.contains_key("topic") {
                    // Extract the topic from "how do I X" / "how to X"
                    let topic = Self::extract_how_to_topic(normalized);
                    if let Some(t) = topic {
                        entities.insert("topic".to_string(), t);
                    }
                }
            }
            _ => {}
        }
    }

    /// Extract a page name from the input for navigation intents.
    fn extract_page_name(normalized: &str) -> Option<&'static str> {
        for (aliases, route) in PAGE_NAMES {
            for alias in *aliases {
                if normalized.contains(alias) {
                    return Some(route);
                }
            }
        }
        None
    }

    /// Extract a concept from "what is X" or "explain X" patterns.
    fn extract_concept(normalized: &str) -> Option<String> {
        // "what is X" / "what are X"
        if let Some(pos) = normalized.find("what is ") {
            let rest = &normalized[pos + 8..];
            if !rest.is_empty() {
                return Some(rest.trim().to_string());
            }
        }
        if let Some(pos) = normalized.find("what are ") {
            let rest = &normalized[pos + 9..];
            if !rest.is_empty() {
                return Some(rest.trim().to_string());
            }
        }
        if let Some(pos) = normalized.find("what does ") {
            let rest = &normalized[pos + 10..];
            let rest = rest.trim_end_matches(" mean").trim();
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
        if let Some(pos) = normalized.find("explain ") {
            let rest = &normalized[pos + 8..];
            if !rest.is_empty() {
                return Some(rest.trim().to_string());
            }
        }
        // "how does X work" pattern
        if let Some(pos) = normalized.find("how does ") {
            let rest = &normalized[pos + 9..];
            let rest = rest.trim_end_matches(" work").trim();
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
        if let Some(pos) = normalized.find("how do ") {
            let rest = &normalized[pos + 7..];
            let rest = rest.trim_end_matches(" work").trim();
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
        None
    }

    /// Extract a how-to topic from "how do I X" or "how to X" patterns.
    fn extract_how_to_topic(normalized: &str) -> Option<String> {
        if let Some(pos) = normalized.find("how do i ") {
            let rest = &normalized[pos + 9..];
            if !rest.is_empty() {
                return Some(rest.trim().to_string());
            }
        }
        if let Some(pos) = normalized.find("how to ") {
            let rest = &normalized[pos + 7..];
            if !rest.is_empty() {
                return Some(rest.trim().to_string());
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Tauri command
// ---------------------------------------------------------------------------

/// Classify a user message and return JSON-serialized IntentClassification.
#[tauri::command]
pub fn classify_intent(
    message: String,
    context_json: String,
) -> Result<String, String> {
    // Parse context if provided (for future use with pronoun resolution)
    let _context: Option<serde_json::Value> = if context_json.is_empty() {
        None
    } else {
        serde_json::from_str(&context_json).ok()
    };

    let classifier = IntentClassifier::new();
    let result = classifier.classify(&message);
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(msg: &str) -> IntentClassification {
        let classifier = IntentClassifier::new();
        classifier.classify(msg)
    }

    // -----------------------------------------------------------------------
    // Status intents
    // -----------------------------------------------------------------------

    #[test]
    fn test_status_overall_exact() {
        let r = classify("Am I safe?");
        assert_eq!(r.intent_id, "status.overall");
        assert_eq!(r.confidence, 1.0);
        assert_eq!(r.method, ClassificationMethod::Keyword);
    }

    #[test]
    fn test_status_overall_variations() {
        for msg in &[
            "How's everything?",
            "What's my status?",
            "Am I protected?",
            "Give me a summary",
            "How are things looking?",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "status.overall", "failed for: {}", msg);
            assert!(r.confidence >= 0.5, "low confidence for: {}", msg);
        }
    }

    #[test]
    fn test_status_overall_keyword() {
        let r = classify("give me an overview of the system");
        assert_eq!(r.intent_id, "status.overall");
        assert!(r.confidence >= 0.5);
    }

    #[test]
    fn test_status_protection_score() {
        for msg in &[
            "What's my protection score?",
            "How protected am I?",
            "Protection level",
            "Security rating",
            "My score",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "status.protection_score", "failed for: {}", msg);
        }
    }

    #[test]
    fn test_status_daemon() {
        for msg in &[
            "Is the daemon running?",
            "Daemon status",
            "Is ClawDefender running?",
            "Service status",
            "Is protection active?",
            "Are you running?",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "status.daemon", "failed for: {}", msg);
        }
    }

    #[test]
    fn test_status_server_specific() {
        let r = classify("What about cursor-server?");
        assert_eq!(r.intent_id, "status.server_specific");
        assert!(r.entities.contains_key("server_name"));
    }

    #[test]
    fn test_status_server_specific_variations() {
        for msg in &[
            "How is filesystem-server doing?",
            "Tell me about Claude",
            "Status of cursor-server",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "status.server_specific", "failed for: {}", msg);
            assert!(r.entities.contains_key("server_name"), "no server_name for: {}", msg);
        }
    }

    #[test]
    fn test_status_model() {
        for msg in &[
            "What model is loaded?",
            "AI status",
            "SLM status",
            "Is the AI model working?",
            "Which model am I using?",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "status.model", "failed for: {}", msg);
        }
    }

    // -----------------------------------------------------------------------
    // Activity intents
    // -----------------------------------------------------------------------

    #[test]
    fn test_activity_recent() {
        for msg in &[
            "What happened recently?",
            "Show me recent events",
            "Recent activity",
            "Any activity?",
            "Latest events",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "activity.recent", "failed for: {}", msg);
        }
    }

    #[test]
    fn test_activity_time_range() {
        for msg in &[
            "What happened today?",
            "Events this hour",
            "What happened yesterday?",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "activity.time_range", "failed for: {}", msg);
        }
    }

    #[test]
    fn test_activity_blocked() {
        for msg in &[
            "What did you block?",
            "Blocked events",
            "Show me blocks",
            "What was denied?",
            "Any threats blocked?",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "activity.blocked", "failed for: {}", msg);
        }
    }

    #[test]
    fn test_activity_server() {
        let r = classify("Show me activity for cursor-server");
        assert_eq!(r.intent_id, "activity.server");
        assert!(r.entities.contains_key("server_name"));
    }

    #[test]
    fn test_activity_server_events_from() {
        let r = classify("Events from cursor-server");
        assert_eq!(r.intent_id, "activity.server");
        assert!(r.entities.contains_key("server_name"));
    }

    #[test]
    fn test_activity_stats() {
        for msg in &[
            "Give me stats",
            "Event statistics",
            "How many events?",
            "Event count",
            "Activity summary",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "activity.stats", "failed for: {}", msg);
        }
    }

    // -----------------------------------------------------------------------
    // Risk intents
    // -----------------------------------------------------------------------

    #[test]
    fn test_risk_file() {
        for msg in &[
            "Is this file safe?",
            "Check this file",
            "Analyze this file",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "risk.file", "failed for: {}", msg);
        }
    }

    #[test]
    fn test_risk_file_with_path() {
        let r = classify("Is /etc/passwd safe?");
        assert!(
            r.intent_id == "risk.file" || r.entities.contains_key("file_path"),
            "expected risk.file or file_path entity"
        );
    }

    #[test]
    fn test_risk_url() {
        for msg in &[
            "Is this URL safe?",
            "Check this link",
            "Is this domain suspicious?",
            "Analyze this URL",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "risk.url", "failed for: {}", msg);
        }
    }

    #[test]
    fn test_risk_server() {
        let r = classify("Is cursor-server safe?");
        assert_eq!(r.intent_id, "risk.server");
        assert!(r.entities.contains_key("server_name"));
    }

    #[test]
    fn test_risk_action() {
        for msg in &[
            "Should I allow this?",
            "Is this safe to allow?",
            "What do you recommend?",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "risk.action", "failed for: {}", msg);
        }
    }

    // -----------------------------------------------------------------------
    // Control intents
    // -----------------------------------------------------------------------

    #[test]
    fn test_control_block() {
        let r = classify("Block cursor-server");
        assert_eq!(r.intent_id, "control.block");
        assert!(r.entities.contains_key("server_name"));
    }

    #[test]
    fn test_control_block_it() {
        let r = classify("Block it");
        assert_eq!(r.intent_id, "control.block");
        assert_eq!(r.confidence, 1.0);
    }

    #[test]
    fn test_control_allow() {
        let r = classify("Allow cursor-server");
        assert_eq!(r.intent_id, "control.allow");
        assert!(r.entities.contains_key("server_name"));
    }

    #[test]
    fn test_control_allow_it() {
        let r = classify("Allow it");
        assert_eq!(r.intent_id, "control.allow");
    }

    #[test]
    fn test_control_scan() {
        for msg in &[
            "Run a scan",
            "Scan my system",
            "Scan my setup",
            "Check for problems",
            "Security scan",
            "Audit my setup",
            "Scan everything",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "control.scan", "failed for: {}", msg);
        }
    }

    #[test]
    fn test_control_tighten() {
        for msg in &[
            "Tighten security",
            "Lock everything down",
            "Strict mode",
            "Maximum protection",
            "Paranoid mode",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "control.tighten", "failed for: {}", msg);
        }
    }

    #[test]
    fn test_control_pause() {
        for msg in &[
            "Pause protection",
            "Stop monitoring",
            "Disable guards",
            "Stand down",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "control.pause", "failed for: {}", msg);
        }
    }

    #[test]
    fn test_control_update_threat_intel() {
        for msg in &[
            "Update threat intelligence",
            "Refresh threat feed",
            "Update blocklist",
            "Get latest threats",
            "Update IOCs",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "control.update_threat_intel", "failed for: {}", msg);
        }
    }

    #[test]
    fn test_control_wrap() {
        let r = classify("Wrap filesystem-server");
        assert_eq!(r.intent_id, "control.wrap");
        assert!(r.entities.contains_key("server_name"));
    }

    #[test]
    fn test_control_unwrap() {
        let r = classify("Unwrap filesystem-server");
        assert_eq!(r.intent_id, "control.unwrap");
        assert!(r.entities.contains_key("server_name"));
    }

    // -----------------------------------------------------------------------
    // Explanation intents
    // -----------------------------------------------------------------------

    #[test]
    fn test_explain_event() {
        for msg in &[
            "Explain this event",
            "Tell me more about this",
            "What does this event mean?",
            "Break this down for me",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "explain.event", "failed for: {}", msg);
        }
    }

    #[test]
    fn test_explain_concept() {
        for msg in &[
            "What is MCP?",
            "What are behavioral profiles?",
            "How does protection work?",
            "What is a guard?",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "explain.concept", "failed for: {}", msg);
            assert!(r.entities.contains_key("concept"), "no concept for: {}", msg);
        }
    }

    #[test]
    fn test_explain_why_blocked() {
        for msg in &[
            "Why was this blocked?",
            "Why did you block that?",
            "Explain the block",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "explain.why_blocked", "failed for: {}", msg);
        }
    }

    #[test]
    fn test_explain_recommendation() {
        for msg in &[
            "What should I do?",
            "Any recommendations?",
            "What do you suggest?",
            "How can I improve security?",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "explain.recommendation", "failed for: {}", msg);
        }
    }

    // -----------------------------------------------------------------------
    // Navigation intents
    // -----------------------------------------------------------------------

    #[test]
    fn test_navigate_page() {
        let tests = &[
            ("Go to settings", "/settings"),
            ("Show me the dashboard", "/"),
            ("Open policy editor", "/policy"),
            ("Open scanner", "/scanner"),
            ("Show network log", "/network"),
            ("Open guards page", "/guards"),
        ];
        for (msg, expected_page) in tests {
            let r = classify(msg);
            assert_eq!(r.intent_id, "navigate.page", "failed for: {}", msg);
            assert_eq!(
                r.entities.get("page_name").map(|s| s.as_str()),
                Some(*expected_page),
                "wrong page for: {}",
                msg
            );
        }
    }

    // -----------------------------------------------------------------------
    // Help intents
    // -----------------------------------------------------------------------

    #[test]
    fn test_help_general() {
        for msg in &[
            "Help",
            "What can you do?",
            "Commands",
            "Guide me",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "help.general", "failed for: {}", msg);
        }
    }

    #[test]
    fn test_help_how_to() {
        for msg in &[
            "How do I block a server?",
            "How do I add a rule?",
            "How to run a scan?",
        ] {
            let r = classify(msg);
            assert_eq!(r.intent_id, "help.how_to", "failed for: {}", msg);
            assert!(r.entities.contains_key("topic"), "no topic for: {}", msg);
        }
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_input() {
        let r = classify("");
        assert_eq!(r.intent_id, "unknown");
        assert_eq!(r.confidence, 0.0);
        assert_eq!(r.method, ClassificationMethod::Fallback);
    }

    #[test]
    fn test_very_long_input() {
        let long_input = "a ".repeat(10000);
        let r = classify(&long_input);
        // Should not panic, just return fallback
        assert!(r.intent_id.len() > 0);
    }

    #[test]
    fn test_special_characters() {
        let r = classify("!!!???...");
        assert_eq!(r.intent_id, "unknown");
        assert_eq!(r.method, ClassificationMethod::Fallback);
    }

    #[test]
    fn test_case_insensitive() {
        let r = classify("AM I SAFE?");
        assert_eq!(r.intent_id, "status.overall");
        assert_eq!(r.confidence, 1.0);
    }

    #[test]
    fn test_fallback_returns_raw_query() {
        let r = classify("xyzzy gibberish nonsense");
        assert_eq!(r.intent_id, "unknown");
        assert!(r.entities.contains_key("raw_query"));
        assert_eq!(r.entities["raw_query"], "xyzzy gibberish nonsense");
    }

    #[test]
    fn test_classify_intent_command() {
        let result = classify_intent(
            "Am I safe?".to_string(),
            "".to_string(),
        );
        assert!(result.is_ok());
        let json = result.unwrap();
        let parsed: IntentClassification = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.intent_id, "status.overall");
    }

    #[test]
    fn test_classify_intent_command_with_context() {
        let context = serde_json::json!({
            "last_server": "cursor-server"
        });
        let result = classify_intent(
            "Block it".to_string(),
            serde_json::to_string(&context).unwrap(),
        );
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Ambiguous queries
    // -----------------------------------------------------------------------

    #[test]
    fn test_ambiguous_safe_without_entity() {
        // "Is this safe?" without file or server context
        let r = classify("Is this safe?");
        // Should match risk.action since no server/file entity
        assert!(
            r.intent_id == "risk.action" || r.intent_id == "risk.file" || r.intent_id == "unknown",
            "got unexpected intent: {}",
            r.intent_id
        );
    }

    #[test]
    fn test_scan_vs_scanner_navigation() {
        // "Scan" alone should be control.scan, not navigate.page
        let r = classify("Run a scan");
        assert_eq!(r.intent_id, "control.scan");
    }

    #[test]
    fn test_server_name_in_block() {
        let r = classify("Block filesystem-server");
        assert_eq!(r.intent_id, "control.block");
        assert_eq!(r.entities.get("server_name").map(|s| s.as_str()), Some("filesystem-server"));
    }

    #[test]
    fn test_all_intents_have_at_least_one_match() {
        let intents = vec![
            ("status.overall", "Am I safe?"),
            ("status.protection_score", "What's my protection score?"),
            ("status.daemon", "Is the daemon running?"),
            ("status.server_specific", "Status of cursor-server"),
            ("status.model", "AI status"),
            ("activity.recent", "Recent activity"),
            ("activity.time_range", "What happened today?"),
            ("activity.blocked", "Blocked events"),
            ("activity.server", "Show me activity for cursor-server"),
            ("activity.stats", "Give me stats"),
            ("risk.file", "Is this file safe?"),
            ("risk.url", "Check this link"),
            ("risk.server", "Is cursor-server safe?"),
            ("risk.action", "Should I allow this?"),
            ("control.block", "Block it"),
            ("control.allow", "Allow it"),
            ("control.scan", "Run a scan"),
            ("control.tighten", "Strict mode"),
            ("control.pause", "Pause protection"),
            ("control.update_threat_intel", "Update blocklist"),
            ("control.wrap", "Wrap filesystem-server"),
            ("control.unwrap", "Unwrap filesystem-server"),
            ("explain.event", "Explain this event"),
            ("explain.concept", "What is MCP?"),
            ("explain.why_blocked", "Why was this blocked?"),
            ("explain.recommendation", "What should I do?"),
            ("navigate.page", "Go to settings"),
            ("help.general", "Help"),
            ("help.how_to", "How do I block a server?"),
        ];

        for (expected_intent, msg) in intents {
            let r = classify(msg);
            assert_eq!(
                r.intent_id, expected_intent,
                "Expected {} for '{}', got {}",
                expected_intent, msg, r.intent_id
            );
        }
    }
}
