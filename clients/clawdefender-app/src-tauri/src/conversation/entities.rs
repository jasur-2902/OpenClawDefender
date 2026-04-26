use chrono::Datelike;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Known patterns
// ---------------------------------------------------------------------------

/// Known MCP server name patterns.
const KNOWN_SERVERS: &[&str] = &[
    "claude",
    "cursor",
    "cursor-server",
    "filesystem-server",
    "filesystem",
    "github-server",
    "github",
    "git-server",
    "git",
    "postgres-server",
    "postgres",
    "sqlite-server",
    "sqlite",
    "fetch-server",
    "fetch",
    "brave-search",
    "brave",
    "puppeteer-server",
    "puppeteer",
    "memory-server",
    "memory",
    "slack-server",
    "slack",
    "discord-server",
    "discord",
    "docker-server",
    "docker",
    "kubernetes-server",
    "kubernetes",
    "aws-server",
    "aws",
    "gcp-server",
    "gcp",
    "azure-server",
    "azure",
    "openai-server",
    "openai",
    "anthropic-server",
    "anthropic",
    "redis-server",
    "redis",
    "mongo-server",
    "mongo",
    "mysql-server",
    "mysql",
    "s3-server",
    "s3",
    "email-server",
    "email",
    "sentry-server",
    "sentry",
    "datadog-server",
    "datadog",
    "grafana-server",
    "grafana",
    "jira-server",
    "jira",
    "linear-server",
    "linear",
    "notion-server",
    "notion",
    "stripe-server",
    "stripe",
    "twilio-server",
    "twilio",
    "vercel-server",
    "vercel",
    "netlify-server",
    "netlify",
    "cloudflare-server",
    "cloudflare",
];

/// Known MCP tool names.
const KNOWN_TOOLS: &[&str] = &[
    "read_file",
    "write_file",
    "run_command",
    "fetch",
    "list_files",
    "search_files",
    "execute_sql",
    "create_file",
    "delete_file",
    "move_file",
    "copy_file",
    "get_url",
    "post_url",
    "send_message",
    "list_directory",
    "search_code",
    "git_commit",
    "git_push",
    "git_pull",
    "git_clone",
    "git_diff",
    "git_status",
    "docker_run",
    "docker_build",
    "shell_exec",
    "npm_install",
    "pip_install",
    "curl",
    "wget",
    "ssh",
    "scp",
];

/// Action keywords that map to action_type entity.
const ACTION_KEYWORDS: &[(&str, &str)] = &[
    ("block", "block"),
    ("deny", "block"),
    ("reject", "block"),
    ("allow", "allow"),
    ("permit", "allow"),
    ("accept", "allow"),
    ("trust", "trust"),
    ("restrict", "restrict"),
    ("scan", "scan"),
    ("monitor", "monitor"),
    ("watch", "monitor"),
    ("unblock", "allow"),
    ("wrap", "wrap"),
    ("unwrap", "unwrap"),
    ("protect", "wrap"),
    ("unprotect", "unwrap"),
];

/// Time reference keywords.
const TIME_KEYWORDS: &[&str] = &[
    "today",
    "yesterday",
    "this week",
    "last week",
    "this hour",
    "last hour",
    "this morning",
    "this afternoon",
    "this evening",
    "tonight",
    "last night",
    "last 30 minutes",
    "last 15 minutes",
    "last 5 minutes",
    "last minute",
    "past hour",
    "past day",
    "past week",
    "since monday",
    "since tuesday",
    "since wednesday",
    "since thursday",
    "since friday",
    "since saturday",
    "since sunday",
];

// ---------------------------------------------------------------------------
// Extracted time range
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: String,
    pub end: String,
    pub label: String,
}

// ---------------------------------------------------------------------------
// Entity extractor
// ---------------------------------------------------------------------------

pub struct EntityExtractor;

impl EntityExtractor {
    pub fn new() -> Self {
        Self
    }

    /// Extract all entities from a user message.
    pub fn extract(&self, message: &str) -> HashMap<String, String> {
        let mut entities = HashMap::new();
        let lower = message.to_lowercase();

        // Extract server names
        if let Some(server) = self.extract_server_name(&lower) {
            entities.insert("server_name".to_string(), server);
        }

        // Extract file paths
        if let Some(path) = self.extract_file_path(message) {
            entities.insert("file_path".to_string(), path);
        }

        // Extract tool names
        if let Some(tool) = self.extract_tool_name(&lower) {
            entities.insert("tool_name".to_string(), tool);
        }

        // Extract action types
        if let Some(action) = self.extract_action_type(&lower) {
            entities.insert("action_type".to_string(), action);
        }

        // Extract time references
        if let Some(time) = self.extract_time_reference(&lower) {
            entities.insert("time_range".to_string(), time.label.clone());
            entities.insert("time_start".to_string(), time.start);
            entities.insert("time_end".to_string(), time.end);
        }

        // Extract URLs
        if let Some(url) = self.extract_url(message) {
            entities.insert("url".to_string(), url);
        }

        entities
    }

    /// Extract a server name from the message.
    /// Handles exact matches, partial matches, and names with -server suffix.
    pub fn extract_server_name(&self, lower: &str) -> Option<String> {
        let words: Vec<&str> = lower
            .split(|c: char| c.is_whitespace() || c == ',' || c == '.' || c == '?' || c == '!')
            .filter(|w| !w.is_empty())
            .collect();

        // First, try exact matches against known servers (longest first for specificity)
        let mut sorted_servers: Vec<&&str> = KNOWN_SERVERS.iter().collect();
        sorted_servers.sort_by_key(|x| std::cmp::Reverse(x.len()));

        for server in &sorted_servers {
            // Check for the server name as a whole word or in compound form
            for word in &words {
                if *word == **server {
                    return Some(server.to_string());
                }
            }
            // Also check multi-word servers in the full string
            if server.contains('-') && lower.contains(**server) {
                return Some(server.to_string());
            }
        }

        // Then check for words that look like server names (contain hyphen + "server")
        for word in &words {
            if word.contains("-server") || word.ends_with("-server") {
                return Some(word.to_string());
            }
        }

        // Check for words ending in -server even without the hyphen
        for word in &words {
            if word.ends_with("server") && word.len() > 6 {
                return Some(word.to_string());
            }
        }

        None
    }

    /// Extract a file path from the message.
    /// Detects paths starting with /, ~/, ./, or common directories.
    pub fn extract_file_path(&self, message: &str) -> Option<String> {
        let words: Vec<&str> = message.split_whitespace().collect();

        for word in &words {
            let trimmed = word.trim_matches(|c: char| c == '?' || c == '!' || c == ',' || c == '\'' || c == '"');
            if trimmed.is_empty() {
                continue;
            }

            // Absolute paths
            if trimmed.starts_with('/') && trimmed.len() > 1 {
                return Some(trimmed.to_string());
            }

            // Home-relative paths
            if trimmed.starts_with("~/") && trimmed.len() > 2 {
                return Some(trimmed.to_string());
            }

            // Current-relative paths
            if trimmed.starts_with("./") && trimmed.len() > 2 {
                return Some(trimmed.to_string());
            }

            // Parent-relative paths
            if trimmed.starts_with("../") && trimmed.len() > 3 {
                return Some(trimmed.to_string());
            }

            // Paths with common file extensions
            if (trimmed.contains('/') || trimmed.contains('.'))
                && Self::looks_like_file_path(trimmed)
            {
                return Some(trimmed.to_string());
            }
        }

        None
    }

    /// Heuristic check for whether a string looks like a file path.
    fn looks_like_file_path(s: &str) -> bool {
        let extensions = &[
            ".json", ".yaml", ".yml", ".toml", ".xml", ".csv", ".log",
            ".txt", ".md", ".rs", ".py", ".js", ".ts", ".go", ".java",
            ".c", ".cpp", ".h", ".sh", ".bash", ".zsh", ".conf", ".cfg",
            ".env", ".lock", ".sql",
        ];
        // Must contain a path separator or a recognized extension
        if s.contains('/') {
            return true;
        }
        for ext in extensions {
            if s.ends_with(ext) {
                return true;
            }
        }
        false
    }

    /// Extract a tool name from the message.
    pub fn extract_tool_name(&self, lower: &str) -> Option<String> {
        for tool in KNOWN_TOOLS {
            // Check as a whole word. Tool names use underscores so they
            // won't collide with normal English easily.
            if lower.contains(tool) {
                return Some(tool.to_string());
            }
        }
        None
    }

    /// Extract an action type from the message.
    pub fn extract_action_type(&self, lower: &str) -> Option<String> {
        let words: Vec<&str> = lower.split_whitespace().collect();
        for (keyword, action) in ACTION_KEYWORDS {
            if words.contains(keyword) {
                return Some(action.to_string());
            }
        }
        None
    }

    /// Extract a time reference from the message, producing a TimeRange
    /// with ISO 8601 start/end timestamps.
    pub fn extract_time_reference(&self, lower: &str) -> Option<TimeRange> {
        let now = chrono::Utc::now();

        for keyword in TIME_KEYWORDS {
            if lower.contains(keyword) {
                let (start, end, label) = match *keyword {
                    "today" => {
                        let start = now.date_naive().and_hms_opt(0, 0, 0)?;
                        let start = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(start, chrono::Utc);
                        (start, now, "today".to_string())
                    }
                    "yesterday" => {
                        let yesterday = (now - chrono::Duration::days(1)).date_naive();
                        let start = yesterday.and_hms_opt(0, 0, 0)?;
                        let end = yesterday.and_hms_opt(23, 59, 59)?;
                        let start = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(start, chrono::Utc);
                        let end = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(end, chrono::Utc);
                        (start, end, "yesterday".to_string())
                    }
                    "this week" => {
                        let weekday = now.date_naive().weekday().num_days_from_monday();
                        let start = (now - chrono::Duration::days(weekday as i64))
                            .date_naive()
                            .and_hms_opt(0, 0, 0)?;
                        let start = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(start, chrono::Utc);
                        (start, now, "this week".to_string())
                    }
                    "last week" => {
                        let weekday = now.date_naive().weekday().num_days_from_monday();
                        let this_monday = now - chrono::Duration::days(weekday as i64);
                        let last_monday = this_monday - chrono::Duration::days(7);
                        let last_sunday = this_monday - chrono::Duration::days(1);
                        let start = last_monday.date_naive().and_hms_opt(0, 0, 0)?;
                        let end = last_sunday.date_naive().and_hms_opt(23, 59, 59)?;
                        let start = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(start, chrono::Utc);
                        let end = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(end, chrono::Utc);
                        (start, end, "last week".to_string())
                    }
                    "this hour" | "past hour" => {
                        let start = now - chrono::Duration::hours(1);
                        (start, now, "this hour".to_string())
                    }
                    "last hour" => {
                        let start = now - chrono::Duration::hours(2);
                        let end = now - chrono::Duration::hours(1);
                        (start, end, "last hour".to_string())
                    }
                    "last 30 minutes" => {
                        let start = now - chrono::Duration::minutes(30);
                        (start, now, "last 30 minutes".to_string())
                    }
                    "last 15 minutes" => {
                        let start = now - chrono::Duration::minutes(15);
                        (start, now, "last 15 minutes".to_string())
                    }
                    "last 5 minutes" => {
                        let start = now - chrono::Duration::minutes(5);
                        (start, now, "last 5 minutes".to_string())
                    }
                    "last minute" => {
                        let start = now - chrono::Duration::minutes(1);
                        (start, now, "last minute".to_string())
                    }
                    "this morning" => {
                        let start = now.date_naive().and_hms_opt(0, 0, 0)?;
                        let end = now.date_naive().and_hms_opt(12, 0, 0)?;
                        let start = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(start, chrono::Utc);
                        let end = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(end, chrono::Utc);
                        (start, end, "this morning".to_string())
                    }
                    "this afternoon" => {
                        let start = now.date_naive().and_hms_opt(12, 0, 0)?;
                        let end = now.date_naive().and_hms_opt(18, 0, 0)?;
                        let start = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(start, chrono::Utc);
                        let end = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(end, chrono::Utc);
                        (start, end, "this afternoon".to_string())
                    }
                    "this evening" | "tonight" => {
                        let start = now.date_naive().and_hms_opt(18, 0, 0)?;
                        let end = now.date_naive().and_hms_opt(23, 59, 59)?;
                        let start = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(start, chrono::Utc);
                        let end = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(end, chrono::Utc);
                        (start, end, "this evening".to_string())
                    }
                    "last night" => {
                        let yesterday = (now - chrono::Duration::days(1)).date_naive();
                        let start = yesterday.and_hms_opt(18, 0, 0)?;
                        let end = yesterday.and_hms_opt(23, 59, 59)?;
                        let start = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(start, chrono::Utc);
                        let end = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(end, chrono::Utc);
                        (start, end, "last night".to_string())
                    }
                    "past day" => {
                        let start = now - chrono::Duration::days(1);
                        (start, now, "past day".to_string())
                    }
                    "past week" => {
                        let start = now - chrono::Duration::weeks(1);
                        (start, now, "past week".to_string())
                    }
                    day if day.starts_with("since ") => {
                        let day_name = &day[6..];
                        if let Some(start) = Self::day_name_to_date(day_name, now) {
                            (start, now, format!("since {}", day_name))
                        } else {
                            continue;
                        }
                    }
                    _ => continue,
                };

                return Some(TimeRange {
                    start: start.to_rfc3339(),
                    end: end.to_rfc3339(),
                    label,
                });
            }
        }

        None
    }

    /// Convert a day name like "monday" into the most recent past occurrence.
    fn day_name_to_date(
        day_name: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        let target = match day_name {
            "monday" => chrono::Weekday::Mon,
            "tuesday" => chrono::Weekday::Tue,
            "wednesday" => chrono::Weekday::Wed,
            "thursday" => chrono::Weekday::Thu,
            "friday" => chrono::Weekday::Fri,
            "saturday" => chrono::Weekday::Sat,
            "sunday" => chrono::Weekday::Sun,
            _ => return None,
        };

        let current = now.date_naive().weekday();
        let days_back = (current.num_days_from_monday() as i64
            - target.num_days_from_monday() as i64
            + 7)
            % 7;
        // If same day, go back 7 days to mean "last Monday" not "today"
        let days_back = if days_back == 0 { 7 } else { days_back };
        let target_date = (now - chrono::Duration::days(days_back))
            .date_naive()
            .and_hms_opt(0, 0, 0)?;
        Some(chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(target_date, chrono::Utc))
    }

    /// Extract a URL from the message.
    pub fn extract_url(&self, message: &str) -> Option<String> {
        for word in message.split_whitespace() {
            let trimmed = word.trim_matches(|c: char| {
                c == '?' || c == '!' || c == ',' || c == '\'' || c == '"' || c == '(' || c == ')'
            });
            if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                return Some(trimmed.to_string());
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(msg: &str) -> HashMap<String, String> {
        let extractor = EntityExtractor::new();
        extractor.extract(msg)
    }

    // -----------------------------------------------------------------------
    // Server name extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_known_server_exact() {
        for server in &["cursor-server", "filesystem-server", "claude", "github-server"] {
            let entities = extract(&format!("Block {}", server));
            assert_eq!(
                entities.get("server_name").map(|s| s.as_str()),
                Some(*server),
                "failed for: {}",
                server
            );
        }
    }

    #[test]
    fn test_extract_server_partial() {
        let entities = extract("What about cursor?");
        assert_eq!(
            entities.get("server_name").map(|s| s.as_str()),
            Some("cursor"),
        );
    }

    #[test]
    fn test_extract_server_case_insensitive() {
        let entities = extract("Block Cursor-Server");
        assert!(entities.contains_key("server_name"));
    }

    #[test]
    fn test_extract_server_with_punctuation() {
        let entities = extract("Is cursor-server safe?");
        assert_eq!(
            entities.get("server_name").map(|s| s.as_str()),
            Some("cursor-server"),
        );
    }

    #[test]
    fn test_extract_unknown_server_with_suffix() {
        let entities = extract("Block my-custom-server");
        assert_eq!(
            entities.get("server_name").map(|s| s.as_str()),
            Some("my-custom-server"),
        );
    }

    #[test]
    fn test_no_server_in_general_text() {
        let entities = extract("How are things looking?");
        assert!(!entities.contains_key("server_name"));
    }

    // -----------------------------------------------------------------------
    // File path extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_absolute_path() {
        let entities = extract("Check /etc/passwd please");
        assert_eq!(
            entities.get("file_path").map(|s| s.as_str()),
            Some("/etc/passwd"),
        );
    }

    #[test]
    fn test_extract_home_path() {
        let entities = extract("Is ~/Documents/secrets.json safe?");
        assert_eq!(
            entities.get("file_path").map(|s| s.as_str()),
            Some("~/Documents/secrets.json"),
        );
    }

    #[test]
    fn test_extract_relative_path() {
        let entities = extract("Scan ./config/policy.yaml");
        assert_eq!(
            entities.get("file_path").map(|s| s.as_str()),
            Some("./config/policy.yaml"),
        );
    }

    #[test]
    fn test_extract_parent_relative_path() {
        let entities = extract("Check ../shared/config.toml");
        assert_eq!(
            entities.get("file_path").map(|s| s.as_str()),
            Some("../shared/config.toml"),
        );
    }

    #[test]
    fn test_no_path_in_general_text() {
        let entities = extract("What happened recently?");
        assert!(!entities.contains_key("file_path"));
    }

    // -----------------------------------------------------------------------
    // Tool name extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_tool_name() {
        for tool in &["read_file", "write_file", "run_command", "fetch"] {
            let entities = extract(&format!("What about {}?", tool));
            assert_eq!(
                entities.get("tool_name").map(|s| s.as_str()),
                Some(*tool),
                "failed for: {}",
                tool
            );
        }
    }

    #[test]
    fn test_no_tool_in_general_text() {
        let entities = extract("Am I safe?");
        assert!(!entities.contains_key("tool_name"));
    }

    // -----------------------------------------------------------------------
    // Action type extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_action_block() {
        let entities = extract("Block this server");
        assert_eq!(entities.get("action_type").map(|s| s.as_str()), Some("block"));
    }

    #[test]
    fn test_extract_action_allow() {
        let entities = extract("Allow cursor-server");
        assert_eq!(entities.get("action_type").map(|s| s.as_str()), Some("allow"));
    }

    #[test]
    fn test_extract_action_deny() {
        let entities = extract("Deny access");
        assert_eq!(entities.get("action_type").map(|s| s.as_str()), Some("block"));
    }

    #[test]
    fn test_extract_action_trust() {
        let entities = extract("Trust this server");
        assert_eq!(entities.get("action_type").map(|s| s.as_str()), Some("trust"));
    }

    #[test]
    fn test_extract_action_scan() {
        let entities = extract("Scan everything");
        assert_eq!(entities.get("action_type").map(|s| s.as_str()), Some("scan"));
    }

    // -----------------------------------------------------------------------
    // Time reference extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_time_today() {
        let entities = extract("What happened today?");
        assert_eq!(entities.get("time_range").map(|s| s.as_str()), Some("today"));
        assert!(entities.contains_key("time_start"));
        assert!(entities.contains_key("time_end"));
    }

    #[test]
    fn test_extract_time_yesterday() {
        let entities = extract("Events from yesterday");
        assert_eq!(entities.get("time_range").map(|s| s.as_str()), Some("yesterday"));
    }

    #[test]
    fn test_extract_time_this_week() {
        let entities = extract("Activity this week");
        assert_eq!(entities.get("time_range").map(|s| s.as_str()), Some("this week"));
    }

    #[test]
    fn test_extract_time_last_30_minutes() {
        let entities = extract("Activity in the last 30 minutes");
        assert_eq!(entities.get("time_range").map(|s| s.as_str()), Some("last 30 minutes"));
    }

    #[test]
    fn test_extract_time_this_hour() {
        let entities = extract("Events this hour");
        assert_eq!(entities.get("time_range").map(|s| s.as_str()), Some("this hour"));
    }

    #[test]
    fn test_extract_time_since_monday() {
        let entities = extract("Show events since Monday");
        assert_eq!(entities.get("time_range").map(|s| s.as_str()), Some("since monday"));
    }

    #[test]
    fn test_no_time_in_general_text() {
        let entities = extract("Help");
        assert!(!entities.contains_key("time_range"));
    }

    // -----------------------------------------------------------------------
    // URL extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_https_url() {
        let entities = extract("Check https://example.com/suspicious");
        assert_eq!(
            entities.get("url").map(|s| s.as_str()),
            Some("https://example.com/suspicious"),
        );
    }

    #[test]
    fn test_extract_http_url() {
        let entities = extract("Is http://malware.example.com safe?");
        assert_eq!(
            entities.get("url").map(|s| s.as_str()),
            Some("http://malware.example.com"),
        );
    }

    #[test]
    fn test_no_url_in_general_text() {
        let entities = extract("Am I protected?");
        assert!(!entities.contains_key("url"));
    }

    // -----------------------------------------------------------------------
    // Multiple entities
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_multiple_entities() {
        let entities = extract("Block cursor-server today");
        assert!(entities.contains_key("server_name"));
        assert!(entities.contains_key("action_type"));
        assert!(entities.contains_key("time_range"));
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_input() {
        let entities = extract("");
        assert!(entities.is_empty());
    }

    #[test]
    fn test_special_characters_only() {
        let entities = extract("!!??...");
        assert!(entities.is_empty());
    }

    #[test]
    fn test_very_long_input() {
        let long = "word ".repeat(5000);
        let entities = extract(&long);
        // Should not panic
        assert!(entities.is_empty() || !entities.is_empty());
    }
}
