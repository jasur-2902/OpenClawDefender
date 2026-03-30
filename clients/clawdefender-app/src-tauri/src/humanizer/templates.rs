use crate::state::AuditEvent;

/// Classification of an event into a humanization template.
#[derive(Debug, Clone, PartialEq)]
pub enum EventPattern {
    SshKeyAccess,
    AwsCredentials,
    EnvFileAccess,
    BrowserData,
    HighRiskShellCommand,
    SafeShellCommand,
    NetworkKnownApi,
    NetworkMalicious,
    NetworkUnknown,
    SamplingRequest,
    PromptInjection,
    KillChainStep,
    DiscoveryRequest,
    SessionStart,
    SessionEnd,
    FileReadProject,
    FileReadSensitive,
    FileWrite,
    AutoBlock,
    PolicyPrompt,
    FirstTimeAction,
    ActivityRateSpike,
    OutOfTerritory,
    UncorrelatedActivity,
    GenericFallback,
}

/// Template output for a classified event.
pub struct TemplateOutput {
    pub one_liner: String,
    pub expanded_explanation: String,
    pub educational_aside: Option<String>,
    pub risk_level: &'static str,
    pub risk_explanation: String,
    pub is_notable: bool,
}

/// Known safe shell commands that do not warrant concern.
const SAFE_COMMANDS: &[&str] = &[
    "ls", "pwd", "echo", "cat", "which", "grep", "find", "git", "cd", "head", "tail", "wc",
    "sort", "uniq", "diff", "mkdir", "touch", "cp", "mv",
];

/// High-risk shell command patterns.
const HIGH_RISK_PATTERNS: &[&str] = &[
    "curl|bash",
    "curl|sh",
    "wget|sh",
    "wget|bash",
    "rm -rf",
    "chmod 777",
    "eval ",
    "curl | bash",
    "curl | sh",
    "wget | sh",
    "wget | bash",
];

/// Known API domains that are expected for MCP server traffic.
const KNOWN_API_DOMAINS: &[&str] = &[
    "api.anthropic.com",
    "api.openai.com",
    "api.github.com",
    "github.com",
    "api.stripe.com",
    "api.brave.com",
    "googleapis.com",
    "api.cloudflare.com",
    "registry.npmjs.org",
    "pypi.org",
    "crates.io",
];

/// Classify an AuditEvent into the first matching EventPattern.
/// `is_first_occurrence` and `is_rate_spike` come from behavioral context.
pub fn classify_event(
    event: &AuditEvent,
    is_first_occurrence: bool,
    is_rate_spike: bool,
) -> EventPattern {
    let resource = event.resource.as_deref().unwrap_or("");
    let details_lower = event.details.to_lowercase();
    let action_lower = event.action.to_lowercase();

    // 1. SSH key access
    if resource.contains(".ssh/id_rsa")
        || resource.contains(".ssh/id_ed25519")
        || resource.contains(".ssh/id_ecdsa")
    {
        return EventPattern::SshKeyAccess;
    }

    // 2. AWS credentials
    if resource.contains(".aws/credentials") || resource.contains(".aws/config") {
        return EventPattern::AwsCredentials;
    }

    // 3. Env file access
    if resource.ends_with(".env") || resource.contains(".env.") {
        return EventPattern::EnvFileAccess;
    }

    // 4. Browser data
    if resource.contains("Cookies")
        || resource.contains("Login Data")
        || resource.contains("cookies.sqlite")
        || resource.contains("logins.json")
    {
        return EventPattern::BrowserData;
    }

    // 5. High-risk shell command
    let is_shell = action_lower.contains("execute")
        || action_lower.contains("command")
        || action_lower.contains("shell")
        || event.tool_name.as_deref() == Some("execute_command")
        || event.tool_name.as_deref() == Some("run_command");

    if is_shell {
        let cmd_text = if resource.is_empty() {
            &event.details
        } else {
            resource
        };
        let cmd_lower = cmd_text.to_lowercase();

        if HIGH_RISK_PATTERNS.iter().any(|p| cmd_lower.contains(p)) {
            return EventPattern::HighRiskShellCommand;
        }

        // 6. Safe shell command
        let first_word = cmd_text
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_start_matches("./");
        if SAFE_COMMANDS.iter().any(|&c| first_word == c) {
            return EventPattern::SafeShellCommand;
        }

        // If it is a shell command but not clearly safe or dangerous, fall through
    }

    // 7-9. Network events
    let is_network = event.event_type == "connect"
        || event.event_type == "network"
        || event.event_type == "http"
        || event.event_type == "fetch"
        || action_lower.contains("connect")
        || action_lower.contains("fetch");

    if is_network {
        // 8. Malicious/IoC
        if details_lower.contains("ioc")
            || details_lower.contains("blocklist")
            || details_lower.contains("malicious")
        {
            return EventPattern::NetworkMalicious;
        }

        // 7. Known API
        if KNOWN_API_DOMAINS
            .iter()
            .any(|d| resource.contains(d) || details_lower.contains(d))
        {
            return EventPattern::NetworkKnownApi;
        }

        // 9. Unknown
        return EventPattern::NetworkUnknown;
    }

    // 10. Sampling/createMessage
    if action_lower.contains("sampling") || action_lower.contains("createmessage") {
        return EventPattern::SamplingRequest;
    }

    // 11. Prompt injection
    if details_lower.contains("injection") || details_lower.contains("prompt injection") {
        return EventPattern::PromptInjection;
    }

    // 12. Kill chain step
    if details_lower.contains("kill chain") || details_lower.contains("kill_chain") {
        return EventPattern::KillChainStep;
    }

    // 13. Discovery request
    if action_lower == "tools/list"
        || action_lower == "resources/list"
        || action_lower == "prompts/list"
        || action_lower.contains("discovery")
        || action_lower.contains("list available")
    {
        return EventPattern::DiscoveryRequest;
    }

    // 14. Session start
    if action_lower == "session started" || action_lower == "session-start" {
        return EventPattern::SessionStart;
    }

    // 15. Session end
    if action_lower == "session ended" || action_lower == "session-end" {
        return EventPattern::SessionEnd;
    }

    // 19. Auto-block (check before file patterns to catch blocked file access)
    if (event.decision == "blocked" || event.decision == "denied" || event.decision == "block")
        && details_lower.contains("auto")
    {
        return EventPattern::AutoBlock;
    }

    // 20. Policy prompt
    if event.decision == "prompted" || event.decision == "prompt" {
        return EventPattern::PolicyPrompt;
    }

    // 16-17. File read
    let is_file_read = event.tool_name.as_deref() == Some("read_file")
        || action_lower.contains("read")
        || action_lower.contains("file read");

    if is_file_read && !resource.is_empty() {
        if is_project_path(resource) {
            return EventPattern::FileReadProject;
        }
        return EventPattern::FileReadSensitive;
    }

    // 18. File write
    if event.tool_name.as_deref() == Some("write_file")
        || event.tool_name.as_deref() == Some("create_file")
        || action_lower.contains("write")
        || action_lower.contains("create")
    {
        return EventPattern::FileWrite;
    }

    // 21. First-time action
    if is_first_occurrence {
        return EventPattern::FirstTimeAction;
    }

    // 22. Activity rate spike
    if is_rate_spike {
        return EventPattern::ActivityRateSpike;
    }

    // 24. Uncorrelated OS activity
    if details_lower.contains("uncorrelated") {
        return EventPattern::UncorrelatedActivity;
    }

    // 25. Generic fallback
    EventPattern::GenericFallback
}

/// Generate a TemplateOutput for a classified event pattern.
pub fn render_template(
    pattern: &EventPattern,
    server: &str,
    tool: &str,
    resource: &str,
    command: &str,
    action: &str,
    destination: &str,
) -> TemplateOutput {
    match pattern {
        EventPattern::SshKeyAccess => TemplateOutput {
            one_liner: format!("{} tried to read your SSH private key. I paused it.", server),
            expanded_explanation: format!(
                "The server \"{}\" made a tool call that attempted to open {}. SSH private keys grant access to remote servers, so I paused this and I am asking you before it goes further.",
                server, resource
            ),
            educational_aside: Some(
                "SSH keys are like master passwords to your servers. A legitimate server rarely needs to read the private key itself.".to_string()
            ),
            risk_level: "dangerous",
            risk_explanation: "This targets a sensitive credential file. Risk level: dangerous.".to_string(),
            is_notable: true,
        },

        EventPattern::AwsCredentials => TemplateOutput {
            one_liner: format!("{} tried to access your AWS credentials. Paused.", server),
            expanded_explanation: format!(
                "The server \"{}\" attempted to read your AWS credentials file at {}. This file contains secret keys that could give access to your cloud infrastructure.",
                server, resource
            ),
            educational_aside: Some(
                "If a server needs AWS access, it is safer to use environment variables with limited-scope IAM roles than to expose your credentials file.".to_string()
            ),
            risk_level: "dangerous",
            risk_explanation: "Cloud credential files contain keys to your infrastructure. Risk level: dangerous.".to_string(),
            is_notable: true,
        },

        EventPattern::EnvFileAccess => TemplateOutput {
            one_liner: format!("{} tried to read environment secrets at {}.", server, resource),
            expanded_explanation: format!(
                "The server \"{}\" attempted to read {}. Environment files often contain API keys, database passwords, and other secrets.",
                server, resource
            ),
            educational_aside: Some(
                ".env files are a common target because they concentrate secrets in a single readable file.".to_string()
            ),
            risk_level: "suspicious",
            risk_explanation: "Environment files frequently contain secrets. Risk level: suspicious.".to_string(),
            is_notable: true,
        },

        EventPattern::BrowserData => TemplateOutput {
            one_liner: format!("{} tried to access your browser passwords. Blocked.", server),
            expanded_explanation: format!(
                "The server \"{}\" attempted to read a browser password or cookie database at {}. There is no legitimate reason for an MCP server to access browser credentials. I blocked this automatically.",
                server, resource
            ),
            educational_aside: None,
            risk_level: "dangerous",
            risk_explanation: "Browser credential databases are never a valid target for MCP servers. Risk level: dangerous.".to_string(),
            is_notable: true,
        },

        EventPattern::HighRiskShellCommand => TemplateOutput {
            one_liner: format!("{} tried to run a dangerous shell command. Paused.", server),
            expanded_explanation: format!(
                "The server \"{}\" attempted to execute \"{}\". This type of command can download and run arbitrary code or permanently delete files. I paused it for your review.",
                server, command
            ),
            educational_aside: Some(
                "Piping a download directly into a shell (curl | bash) runs whatever code is on the other end with no review. It is one of the most common ways malicious code gets executed.".to_string()
            ),
            risk_level: "dangerous",
            risk_explanation: "This command pattern is associated with remote code execution or destructive operations. Risk level: dangerous.".to_string(),
            is_notable: true,
        },

        EventPattern::SafeShellCommand => TemplateOutput {
            one_liner: format!("{} ran a shell command: {}", server, command),
            expanded_explanation: format!(
                "The server \"{}\" executed {} in your project directory. This is a routine command within the expected working area.",
                server, command
            ),
            educational_aside: None,
            risk_level: "normal",
            risk_explanation: "This is a standard development command. Risk level: normal.".to_string(),
            is_notable: false,
        },

        EventPattern::NetworkKnownApi => TemplateOutput {
            one_liner: format!("{} connected to {}. Expected.", server, destination),
            expanded_explanation: format!(
                "The server \"{}\" made a network connection to {}, which is a recognized AI provider API. This is normal behavior for this type of server.",
                server, destination
            ),
            educational_aside: None,
            risk_level: "normal",
            risk_explanation: "Connection to a recognized API endpoint. Risk level: normal.".to_string(),
            is_notable: false,
        },

        EventPattern::NetworkMalicious => TemplateOutput {
            one_liner: format!("{} tried to contact a known malicious host. Blocked.", server),
            expanded_explanation: format!(
                "The server \"{}\" attempted to connect to {}, which is flagged in threat intelligence feeds as malicious. I blocked the connection. This could indicate a compromised MCP server.",
                server, destination
            ),
            educational_aside: Some(
                "Indicators of Compromise (IoCs) are addresses, file hashes, and patterns that have been observed in real-world attacks and shared by the security community.".to_string()
            ),
            risk_level: "dangerous",
            risk_explanation: "This destination matches known malicious infrastructure. Risk level: dangerous.".to_string(),
            is_notable: true,
        },

        EventPattern::NetworkUnknown => TemplateOutput {
            one_liner: format!("{} connected to an unfamiliar address: {}.", server, destination),
            expanded_explanation: format!(
                "The server \"{}\" connected to {}. I do not recognize this destination, and it is not in any allowlist. It could be legitimate, but I have not seen this server connect here before.",
                server, destination
            ),
            educational_aside: Some(
                "MCP servers normally only respond to your AI tool -- they do not usually reach out to the internet on their own.".to_string()
            ),
            risk_level: "unusual",
            risk_explanation: "Unknown destination not in any allowlist. Risk level: unusual.".to_string(),
            is_notable: true,
        },

        EventPattern::SamplingRequest => TemplateOutput {
            one_liner: format!("{} sent an AI sampling request.", server),
            expanded_explanation: format!(
                "The server \"{}\" sent a sampling/createMessage request, asking to generate AI content. This is the MCP mechanism for servers to use AI capabilities.",
                server
            ),
            educational_aside: Some(
                "sampling/createMessage lets a server ask your AI tool to generate text. A compromised server could use this to manipulate AI outputs.".to_string()
            ),
            risk_level: "unusual",
            risk_explanation: "AI sampling requests can be used to influence model outputs. Risk level: unusual.".to_string(),
            is_notable: true,
        },

        EventPattern::PromptInjection => TemplateOutput {
            one_liner: format!("I found a prompt injection attempt in a message from {}.", server),
            expanded_explanation: format!(
                "The server \"{}\" sent a sampling/createMessage request containing text that looks like a prompt injection attack. The suspicious content attempts to override your AI's instructions. I blocked the message.",
                server
            ),
            educational_aside: Some(
                "Prompt injection is when hidden instructions are smuggled into AI inputs, trying to override the AI's original instructions. It is one of the most common attack vectors for AI agents.".to_string()
            ),
            risk_level: "dangerous",
            risk_explanation: "Prompt injection attacks can cause AI tools to act against your interests. Risk level: dangerous.".to_string(),
            is_notable: true,
        },

        EventPattern::KillChainStep => TemplateOutput {
            one_liner: format!("I detected a multi-step attack pattern from {}.", server),
            expanded_explanation: format!(
                "The server \"{}\" executed a sequence of actions that matches a known attack pattern. See the attack chain timeline for the full sequence.",
                server
            ),
            educational_aside: Some(
                "A kill chain is a sequence of actions that individually might seem harmless but together form an attack -- like reading credentials, then connecting to the internet.".to_string()
            ),
            risk_level: "dangerous",
            risk_explanation: "Multi-step attack pattern detected. Risk level: dangerous.".to_string(),
            is_notable: true,
        },

        EventPattern::DiscoveryRequest => TemplateOutput {
            one_liner: format!("{} requested a list of available tools.", server),
            expanded_explanation: format!(
                "The server \"{}\" sent a discovery request to list available tools or resources. This is standard MCP protocol behavior during initialization.",
                server
            ),
            educational_aside: Some(
                "MCP servers discover their capabilities through list requests. This is normal startup behavior.".to_string()
            ),
            risk_level: "info",
            risk_explanation: "Standard protocol discovery. Risk level: info.".to_string(),
            is_notable: false,
        },

        EventPattern::SessionStart => TemplateOutput {
            one_liner: format!("{} session started.", server),
            expanded_explanation: format!(
                "A new session for the server \"{}\" has begun. I am monitoring all actions from this point.",
                server
            ),
            educational_aside: None,
            risk_level: "info",
            risk_explanation: "Session lifecycle event. Risk level: info.".to_string(),
            is_notable: false,
        },

        EventPattern::SessionEnd => TemplateOutput {
            one_liner: format!("{} session ended.", server),
            expanded_explanation: format!(
                "The session for \"{}\" has ended. All actions during this session were logged.",
                server
            ),
            educational_aside: None,
            risk_level: "info",
            risk_explanation: "Session lifecycle event. Risk level: info.".to_string(),
            is_notable: false,
        },

        EventPattern::FileReadProject => TemplateOutput {
            one_liner: format!("{} read {}.", server, resource),
            expanded_explanation: format!(
                "The server \"{}\" read the file {} in your project directory. This is within the server's expected working area.",
                server, resource
            ),
            educational_aside: None,
            risk_level: "normal",
            risk_explanation: "File access within project directory. Risk level: normal.".to_string(),
            is_notable: false,
        },

        EventPattern::FileReadSensitive => TemplateOutput {
            one_liner: format!("{} accessed a file outside your project: {}.", server, resource),
            expanded_explanation: format!(
                "The server \"{}\" read {}, which is outside your current project directory. This could be a normal config lookup, but I wanted you to know.",
                server, resource
            ),
            educational_aside: Some(
                "Files outside your project directory may contain sensitive configuration or system data.".to_string()
            ),
            risk_level: "unusual",
            risk_explanation: "Access outside expected territory. Risk level: unusual.".to_string(),
            is_notable: true,
        },

        EventPattern::FileWrite => TemplateOutput {
            one_liner: format!("{} wrote to {}.", server, resource),
            expanded_explanation: format!(
                "The server \"{}\" created or modified the file {}. File modifications are logged for your records.",
                server, resource
            ),
            educational_aside: None,
            risk_level: "normal",
            risk_explanation: "File modification within expected area. Risk level: normal.".to_string(),
            is_notable: false,
        },

        EventPattern::AutoBlock => TemplateOutput {
            one_liner: "I blocked this automatically -- it looked dangerous.".to_string(),
            expanded_explanation: format!(
                "I blocked an action by \"{}\" automatically because it combined multiple high-risk signals. Auto-blocking is enabled in your settings and activates when the risk level is very high. You can review this decision and override it.",
                server
            ),
            educational_aside: None,
            risk_level: "dangerous",
            risk_explanation: "Multiple high-risk signals combined. Risk level: dangerous.".to_string(),
            is_notable: true,
        },

        EventPattern::PolicyPrompt => TemplateOutput {
            one_liner: format!("{} wants to {}. Your call.", server, action),
            expanded_explanation: format!(
                "The server \"{}\" is requesting permission to {} on {}. Your policy requires approval for this type of action.",
                server, action, resource
            ),
            educational_aside: None,
            risk_level: "suspicious",
            risk_explanation: "Your policy requires human approval for this action.".to_string(),
            is_notable: true,
        },

        EventPattern::FirstTimeAction => TemplateOutput {
            one_liner: format!("{} just used {} for the first time.", server, tool),
            expanded_explanation: format!(
                "The server \"{}\" called the tool \"{}\" for the first time. Based on its learned behavior profile, this tool has not been part of its normal operation. This could be a new workflow or something unexpected.",
                server, tool
            ),
            educational_aside: None,
            risk_level: "unusual",
            risk_explanation: "New behavior from a server with an established profile. Risk level: unusual.".to_string(),
            is_notable: true,
        },

        EventPattern::ActivityRateSpike => TemplateOutput {
            one_liner: format!("{} is working much faster than normal.", server),
            expanded_explanation: format!(
                "The server \"{}\" is making requests at an unusually high pace. A sudden spike in activity can indicate automated behavior or a compromised server.",
                server
            ),
            educational_aside: None,
            risk_level: "suspicious",
            risk_explanation: "Activity rate exceeds 3x normal baseline. Risk level: suspicious.".to_string(),
            is_notable: true,
        },

        EventPattern::OutOfTerritory => TemplateOutput {
            one_liner: format!("{} accessed a path outside its usual territory.", server),
            expanded_explanation: format!(
                "The server \"{}\" accessed {}, which is outside the directories it normally works in.",
                server, resource
            ),
            educational_aside: None,
            risk_level: "unusual",
            risk_explanation: "Access outside learned territory boundaries. Risk level: unusual.".to_string(),
            is_notable: true,
        },

        EventPattern::UncorrelatedActivity => TemplateOutput {
            one_liner: "I noticed system activity that does not match any server request.".to_string(),
            expanded_explanation: format!(
                "A system event occurred ({}) that I cannot trace back to any MCP tool call or resource read. This could be normal background activity, or it could be a process acting on its own outside the MCP protocol.",
                action
            ),
            educational_aside: Some(
                "MCP servers should do their work through the protocol. Activity that happens outside the protocol could mean a server is doing things behind the scenes.".to_string()
            ),
            risk_level: "suspicious",
            risk_explanation: "Uncorrelated system activity warrants investigation. Risk level: suspicious.".to_string(),
            is_notable: true,
        },

        EventPattern::GenericFallback => TemplateOutput {
            one_liner: format!("{} performed {}.", server, action),
            expanded_explanation: format!(
                "The server \"{}\" performed the action \"{}\". No specific risk pattern was matched.",
                server, action
            ),
            educational_aside: None,
            risk_level: "normal",
            risk_explanation: "No specific risk pattern matched. Risk level: normal.".to_string(),
            is_notable: false,
        },
    }
}

/// Determine whether a resource path is within a project directory.
fn is_project_path(path: &str) -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() {
        return false;
    }

    // Common project locations
    let project_indicators = [
        "/Projects/",
        "/workspace/",
        "/code/",
        "/src/",
        "/repos/",
        "/dev/",
        "/Developer/",
    ];

    for indicator in &project_indicators {
        if path.contains(indicator) {
            return true;
        }
    }

    // Check for common project markers in the path components
    let relative = if path.starts_with(&home) {
        &path[home.len()..]
    } else {
        path
    };

    // If it is inside home and not in a sensitive location, consider it project-ish
    if path.starts_with(&home) {
        let sensitive = [
            "/.ssh/",
            "/.aws/",
            "/.config/",
            "/.local/",
            "/.gnupg/",
            "/Library/",
            "/.env",
        ];
        if sensitive.iter().any(|s| relative.contains(s)) {
            return false;
        }
        return true;
    }

    false
}
