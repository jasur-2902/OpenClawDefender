use serde::{Deserialize, Serialize};
use std::fmt;

/// CVSS v3.1 Base Score vector components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackComplexity {
    Low,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserInteraction {
    None,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    Unchanged,
    Changed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Impact {
    None,
    Low,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CvssVector {
    pub attack_vector: AttackVector,
    pub attack_complexity: AttackComplexity,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: UserInteraction,
    pub scope: Scope,
    pub confidentiality: Impact,
    pub integrity: Impact,
    pub availability: Impact,
}

impl CvssVector {
    /// Predefined vector for path traversal to credentials.
    /// AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
    pub fn path_traversal_credentials() -> Self {
        Self {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality: Impact::High,
            integrity: Impact::None,
            availability: Impact::None,
        }
    }

    /// Predefined vector for shell/command injection.
    /// AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
    pub fn shell_injection() -> Self {
        Self {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality: Impact::High,
            integrity: Impact::High,
            availability: Impact::High,
        }
    }

    /// Predefined vector for prompt injection with data exfiltration.
    /// AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N = 10.0 (capped)
    pub fn prompt_injection_exfil() -> Self {
        Self {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Changed,
            confidentiality: Impact::High,
            integrity: Impact::High,
            availability: Impact::None,
        }
    }

    /// Predefined vector for data exfiltration via network.
    /// AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
    pub fn data_exfiltration() -> Self {
        Self {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality: Impact::High,
            integrity: Impact::None,
            availability: Impact::None,
        }
    }

    /// Predefined vector for capability escalation.
    /// AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N = 8.1
    pub fn capability_escalation() -> Self {
        Self {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::Low,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality: Impact::High,
            integrity: Impact::High,
            availability: Impact::None,
        }
    }

    /// Predefined vector for dependency vulnerability (known CVE).
    /// AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L = 7.3
    pub fn dependency_vulnerability() -> Self {
        Self {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality: Impact::Low,
            integrity: Impact::Low,
            availability: Impact::Low,
        }
    }

    /// Predefined vector for fuzzing crash / resilience issue.
    /// AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H = 7.5
    pub fn fuzzing_crash() -> Self {
        Self {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality: Impact::None,
            integrity: Impact::None,
            availability: Impact::High,
        }
    }

    /// Predefined vector for configuration issues (info-level).
    /// AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N = 3.3
    pub fn configuration_info() -> Self {
        Self {
            attack_vector: AttackVector::Local,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::Low,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality: Impact::Low,
            integrity: Impact::None,
            availability: Impact::None,
        }
    }

    /// Return a predefined CVSS vector for a given module category and severity.
    pub fn for_category(category: ModuleCategory, severity: Severity) -> Self {
        match category {
            ModuleCategory::PathTraversal => Self::path_traversal_credentials(),
            ModuleCategory::PromptInjection => Self::prompt_injection_exfil(),
            ModuleCategory::DataExfiltration => Self::data_exfiltration(),
            ModuleCategory::CapabilityEscalation => Self::capability_escalation(),
            ModuleCategory::DependencyAudit => Self::dependency_vulnerability(),
            ModuleCategory::Fuzzing => Self::fuzzing_crash(),
            ModuleCategory::Configuration => {
                if severity >= Severity::Medium {
                    Self::dependency_vulnerability()
                } else {
                    Self::configuration_info()
                }
            }
        }
    }
}

/// Calculate CVSS v3.1 base score from a vector.
pub fn calculate_cvss(vector: &CvssVector) -> f64 {
    let av = match vector.attack_vector {
        AttackVector::Network => 0.85,
        AttackVector::Adjacent => 0.62,
        AttackVector::Local => 0.55,
        AttackVector::Physical => 0.20,
    };
    let ac = match vector.attack_complexity {
        AttackComplexity::Low => 0.77,
        AttackComplexity::High => 0.44,
    };
    let scope_changed = vector.scope == Scope::Changed;
    let pr = match (vector.privileges_required, scope_changed) {
        (PrivilegesRequired::None, _) => 0.85,
        (PrivilegesRequired::Low, false) => 0.62,
        (PrivilegesRequired::Low, true) => 0.68,
        (PrivilegesRequired::High, false) => 0.27,
        (PrivilegesRequired::High, true) => 0.50,
    };
    let ui = match vector.user_interaction {
        UserInteraction::None => 0.85,
        UserInteraction::Required => 0.62,
    };

    let conf = match vector.confidentiality {
        Impact::High => 0.56,
        Impact::Low => 0.22,
        Impact::None => 0.0,
    };
    let integ = match vector.integrity {
        Impact::High => 0.56,
        Impact::Low => 0.22,
        Impact::None => 0.0,
    };
    let avail = match vector.availability {
        Impact::High => 0.56,
        Impact::Low => 0.22,
        Impact::None => 0.0,
    };

    // ISS = 1 - [(1-C) * (1-I) * (1-A)]
    let iss = 1.0 - (1.0 - conf) * (1.0 - integ) * (1.0 - avail);

    if iss <= 0.0 {
        return 0.0;
    }

    let impact: f64 = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02_f64).powf(15.0)
    } else {
        6.42 * iss
    };

    let exploitability: f64 = 8.22 * av * ac * pr * ui;

    if impact <= 0.0 {
        return 0.0;
    }

    let score: f64 = if scope_changed {
        1.08 * (impact + exploitability)
    } else {
        impact + exploitability
    };

    // Round up to nearest 0.1
    let score = score.min(10.0);
    (score * 10.0).ceil() / 10.0
}

/// Convert a CVSS vector to its string representation.
pub fn cvss_to_string(vector: &CvssVector) -> String {
    let av = match vector.attack_vector {
        AttackVector::Network => "N",
        AttackVector::Adjacent => "A",
        AttackVector::Local => "L",
        AttackVector::Physical => "P",
    };
    let ac = match vector.attack_complexity {
        AttackComplexity::Low => "L",
        AttackComplexity::High => "H",
    };
    let pr = match vector.privileges_required {
        PrivilegesRequired::None => "N",
        PrivilegesRequired::Low => "L",
        PrivilegesRequired::High => "H",
    };
    let ui = match vector.user_interaction {
        UserInteraction::None => "N",
        UserInteraction::Required => "R",
    };
    let s = match vector.scope {
        Scope::Unchanged => "U",
        Scope::Changed => "C",
    };
    let c = match vector.confidentiality {
        Impact::High => "H",
        Impact::Low => "L",
        Impact::None => "N",
    };
    let i = match vector.integrity {
        Impact::High => "H",
        Impact::Low => "L",
        Impact::None => "N",
    };
    let a = match vector.availability {
        Impact::High => "H",
        Impact::Low => "L",
        Impact::None => "N",
    };
    format!("CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}")
}

/// Provide fix suggestions for each vulnerability category.
pub fn fix_suggestion(category: ModuleCategory, _finding_title: &str) -> Option<String> {
    let suggestion = match category {
        ModuleCategory::PathTraversal => {
            "## Path Traversal Fix\n\n\
             **Vulnerable (TypeScript):**\n\
             ```typescript\n\
             // UNSAFE: user input used directly in file path\n\
             const data = fs.readFileSync(`/data/${userInput}`);\n\
             ```\n\n\
             **Fixed (TypeScript):**\n\
             ```typescript\n\
             import path from 'path';\n\
             const BASE_DIR = '/data';\n\
             const resolved = path.resolve(BASE_DIR, userInput);\n\
             if (!resolved.startsWith(BASE_DIR + path.sep)) {\n\
             \x20 throw new Error('Path traversal blocked');\n\
             }\n\
             const data = fs.readFileSync(resolved);\n\
             ```\n\n\
             **Vulnerable (Python):**\n\
             ```python\n\
             # UNSAFE: user input used directly\n\
             with open(f'/data/{user_input}') as f:\n\
             \x20   data = f.read()\n\
             ```\n\n\
             **Fixed (Python):**\n\
             ```python\n\
             from pathlib import Path\n\
             BASE_DIR = Path('/data')\n\
             resolved = (BASE_DIR / user_input).resolve()\n\
             if not str(resolved).startswith(str(BASE_DIR.resolve()) + '/'):\n\
             \x20   raise ValueError('Path traversal blocked')\n\
             with open(resolved) as f:\n\
             \x20   data = f.read()\n\
             ```"
        }
        ModuleCategory::PromptInjection => {
            "## Prompt Injection Fix\n\n\
             **Vulnerable (TypeScript):**\n\
             ```typescript\n\
             // UNSAFE: user content embedded directly in prompt\n\
             const prompt = `Summarize this: ${userContent}`;\n\
             ```\n\n\
             **Fixed (TypeScript):**\n\
             ```typescript\n\
             // Use structured input with clear delimiters\n\
             const prompt = [\n\
             \x20 { role: 'system', content: 'You are a summarizer. Only summarize the user content.' },\n\
             \x20 { role: 'user', content: `<document>\\n${userContent}\\n</document>\\nSummarize the above.` }\n\
             ];\n\
             // Validate output does not contain tool calls or unexpected actions\n\
             ```\n\n\
             **Vulnerable (Python):**\n\
             ```python\n\
             # UNSAFE: no input sanitization\n\
             prompt = f\"Summarize: {user_content}\"\n\
             ```\n\n\
             **Fixed (Python):**\n\
             ```python\n\
             # Sanitize and delimit user content\n\
             sanitized = user_content.replace('\\n---\\n', '')\n\
             prompt = f\"<document>\\n{sanitized}\\n</document>\\nSummarize the document above.\"\n\
             # Validate LLM output before executing any tool calls\n\
             ```"
        }
        ModuleCategory::DataExfiltration => {
            "## Data Exfiltration Fix\n\n\
             **Vulnerable (TypeScript):**\n\
             ```typescript\n\
             // UNSAFE: server can make arbitrary network requests\n\
             const resp = await fetch(url); // url from LLM output\n\
             ```\n\n\
             **Fixed (TypeScript):**\n\
             ```typescript\n\
             // Allowlist outbound domains\n\
             const ALLOWED_HOSTS = new Set(['api.example.com']);\n\
             const parsed = new URL(url);\n\
             if (!ALLOWED_HOSTS.has(parsed.hostname)) {\n\
             \x20 throw new Error(`Blocked outbound request to ${parsed.hostname}`);\n\
             }\n\
             const resp = await fetch(url);\n\
             ```\n\n\
             **Vulnerable (Python):**\n\
             ```python\n\
             # UNSAFE: no outbound network restrictions\n\
             requests.get(url)  # url from tool output\n\
             ```\n\n\
             **Fixed (Python):**\n\
             ```python\n\
             from urllib.parse import urlparse\n\
             ALLOWED_HOSTS = {'api.example.com'}\n\
             parsed = urlparse(url)\n\
             if parsed.hostname not in ALLOWED_HOSTS:\n\
             \x20   raise ValueError(f'Blocked request to {parsed.hostname}')\n\
             requests.get(url)\n\
             ```"
        }
        ModuleCategory::CapabilityEscalation => {
            "## Capability Escalation Fix\n\n\
             **Vulnerable (TypeScript):**\n\
             ```typescript\n\
             // UNSAFE: tool executes arbitrary shell commands\n\
             server.addTool('run', async (args) => {\n\
             \x20 return execSync(args.command).toString();\n\
             });\n\
             ```\n\n\
             **Fixed (TypeScript):**\n\
             ```typescript\n\
             // Allowlist specific commands and validate arguments\n\
             const ALLOWED_COMMANDS = new Map([['ls', ['-la']], ['cat', []]]);\n\
             server.addTool('run', async (args) => {\n\
             \x20 const [cmd, ...cmdArgs] = args.command.split(' ');\n\
             \x20 if (!ALLOWED_COMMANDS.has(cmd)) throw new Error('Command not allowed');\n\
             \x20 return execFileSync(cmd, cmdArgs).toString();\n\
             });\n\
             ```\n\n\
             **Vulnerable (Python):**\n\
             ```python\n\
             # UNSAFE: subprocess with shell=True\n\
             subprocess.run(args['command'], shell=True)\n\
             ```\n\n\
             **Fixed (Python):**\n\
             ```python\n\
             import shlex\n\
             ALLOWED = {'ls', 'cat', 'head'}\n\
             parts = shlex.split(args['command'])\n\
             if parts[0] not in ALLOWED:\n\
             \x20   raise ValueError('Command not allowed')\n\
             subprocess.run(parts, shell=False)\n\
             ```"
        }
        ModuleCategory::DependencyAudit => {
            "## Dependency Vulnerability Fix\n\n\
             **TypeScript/Node.js:**\n\
             ```bash\n\
             # Audit and fix dependencies\n\
             npm audit\n\
             npm audit fix\n\
             # Pin dependency versions in package.json\n\
             # Use lockfile (package-lock.json) and verify integrity\n\
             ```\n\n\
             **Python:**\n\
             ```bash\n\
             # Audit dependencies\n\
             pip-audit\n\
             # Pin versions in requirements.txt\n\
             pip freeze > requirements.txt\n\
             # Use hash checking for integrity\n\
             pip install --require-hashes -r requirements.txt\n\
             ```\n\n\
             **General guidance:**\n\
             - Keep dependencies up to date\n\
             - Use lockfiles and verify checksums\n\
             - Remove unused dependencies\n\
             - Subscribe to security advisories for critical packages"
        }
        ModuleCategory::Fuzzing => {
            "## Resilience / Crash Fix\n\n\
             **Vulnerable (TypeScript):**\n\
             ```typescript\n\
             // UNSAFE: no input validation, crashes on unexpected data\n\
             server.addTool('process', async (args) => {\n\
             \x20 return JSON.parse(args.data).value.toString();\n\
             });\n\
             ```\n\n\
             **Fixed (TypeScript):**\n\
             ```typescript\n\
             server.addTool('process', async (args) => {\n\
             \x20 try {\n\
             \x20   const parsed = JSON.parse(args.data ?? '{}');\n\
             \x20   return String(parsed?.value ?? '');\n\
             \x20 } catch {\n\
             \x20   return { error: 'Invalid input data' };\n\
             \x20 }\n\
             });\n\
             ```\n\n\
             **Vulnerable (Python):**\n\
             ```python\n\
             # UNSAFE: no error handling for malformed input\n\
             def process(args):\n\
             \x20   return json.loads(args['data'])['value']\n\
             ```\n\n\
             **Fixed (Python):**\n\
             ```python\n\
             def process(args):\n\
             \x20   try:\n\
             \x20       parsed = json.loads(args.get('data', '{}'))\n\
             \x20       return str(parsed.get('value', ''))\n\
             \x20   except (json.JSONDecodeError, TypeError):\n\
             \x20       return {'error': 'Invalid input data'}\n\
             ```"
        }
        ModuleCategory::Configuration => {
            "## Configuration Fix\n\n\
             **General guidance:**\n\
             - Avoid exposing server metadata or version info to clients\n\
             - Use TLS for all network transports\n\
             - Set appropriate timeouts and rate limits\n\
             - Restrict tool permissions to minimum required scope\n\
             - Review and test configuration changes before deployment"
        }
    };
    Some(suggestion.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn finding_id_prefix(&self) -> &'static str {
        match self {
            Severity::Critical => "CRIT",
            Severity::High => "HIGH",
            Severity::Medium => "MED",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    fn ordinal(&self) -> u8 {
        match self {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ordinal().cmp(&other.ordinal())
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleCategory {
    PathTraversal,
    PromptInjection,
    DataExfiltration,
    CapabilityEscalation,
    DependencyAudit,
    Fuzzing,
    Configuration,
}

impl fmt::Display for ModuleCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModuleCategory::PathTraversal => write!(f, "Path Traversal"),
            ModuleCategory::PromptInjection => write!(f, "Prompt Injection"),
            ModuleCategory::DataExfiltration => write!(f, "Data Exfiltration"),
            ModuleCategory::CapabilityEscalation => write!(f, "Capability Escalation"),
            ModuleCategory::DependencyAudit => write!(f, "Dependency Audit"),
            ModuleCategory::Fuzzing => write!(f, "Fuzzing"),
            ModuleCategory::Configuration => write!(f, "Configuration"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub cvss: f64,
    pub category: ModuleCategory,
    pub description: String,
    pub reproduction: Option<Reproduction>,
    pub evidence: Evidence,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reproduction {
    pub method: String,
    pub tool: Option<String>,
    pub arguments: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub messages: Vec<usize>,
    pub audit_record: Option<String>,
    pub canary_detected: bool,
    pub os_events: Vec<String>,
    pub files_modified: Vec<String>,
    pub network_connections: Vec<String>,
    pub stderr_output: Option<String>,
}

impl Evidence {
    pub fn empty() -> Self {
        Self {
            messages: Vec::new(),
            audit_record: None,
            canary_detected: false,
            os_events: Vec::new(),
            files_modified: Vec::new(),
            network_connections: Vec::new(),
            stderr_output: None,
        }
    }
}
