use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use crate::finding::{Evidence, Finding, ModuleCategory, Severity};
use crate::modules::{ScanContext, ScanModule};

#[derive(Default)]
pub struct DependencyAuditModule;

impl DependencyAuditModule {
    pub fn new() -> Self {
        Self
    }
}

// ---------- npm audit JSON structures ----------

#[derive(Debug, Deserialize)]
struct NpmAuditOutput {
    #[serde(default)]
    vulnerabilities: std::collections::HashMap<String, NpmVuln>,
}

#[derive(Debug, Deserialize)]
struct NpmVuln {
    name: String,
    severity: String,
    #[serde(default)]
    via: Vec<NpmVia>,
    #[serde(default)]
    range: Option<String>,
    #[serde(default)]
    fix_available: Value,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum NpmVia {
    Advisory(NpmAdvisory),
    Name(#[allow(dead_code)] String),
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct NpmAdvisory {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    cwe: Vec<String>,
    #[serde(default)]
    cvss: Option<NpmCvss>,
}

#[derive(Debug, Deserialize)]
struct NpmCvss {
    #[serde(default)]
    score: f64,
}

// ---------- pip-audit JSON structures ----------

#[derive(Debug, Deserialize)]
struct PipAuditEntry {
    name: String,
    version: String,
    #[serde(default)]
    vulns: Vec<PipAuditVuln>,
}

#[derive(Debug, Deserialize)]
struct PipAuditVuln {
    id: String,
    #[serde(default)]
    fix_versions: Vec<String>,
    #[serde(default)]
    description: Option<String>,
}

// ---------- Secret patterns ----------

struct SecretPattern {
    name: &'static str,
    regex: &'static str,
    cvss: f64,
}

const SECRET_PATTERNS: &[SecretPattern] = &[
    SecretPattern {
        name: "API key / token / secret / password",
        regex: r#"(?i)(sk-|pk-|api[-_]?key|token|secret|password|credential)\s*[:=]\s*['"][^'"]{8,}['"]\s*"#,
        cvss: 7.5,
    },
    SecretPattern {
        name: "AWS Access Key ID",
        regex: r"AKIA[0-9A-Z]{16}",
        cvss: 9.0,
    },
    SecretPattern {
        name: "GitHub personal access token",
        regex: r"(ghp_|gho_|github_pat_)[A-Za-z0-9_]{30,}",
        cvss: 8.0,
    },
];

// ---------- EOL runtime versions ----------

fn is_eol_node(version: &str) -> bool {
    // Node versions that are end-of-life as of 2025
    let major = version
        .trim_start_matches('v')
        .split('.')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    // Odd versions are never LTS; even versions < 18 are EOL
    major > 0 && (major % 2 == 1 || major < 18)
}

fn is_eol_python(version: &str) -> bool {
    let parts: Vec<u32> = version.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.len() >= 2 {
        let (major, minor) = (parts[0], parts[1]);
        // Python < 3.9 is EOL
        major < 3 || (major == 3 && minor < 9)
    } else {
        false
    }
}

// ---------- Helpers ----------

fn npm_severity_to_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "moderate" | "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn lower_severity(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low => Severity::Info,
        Severity::Info => Severity::Info,
    }
}

fn default_cvss_for_severity(s: &Severity) -> f64 {
    match s {
        Severity::Critical => 9.0,
        Severity::High => 7.5,
        Severity::Medium => 5.0,
        Severity::Low => 3.0,
        Severity::Info => 0.0,
    }
}

#[allow(clippy::too_many_arguments)]
fn make_finding(
    id_counter: &mut u32,
    title: String,
    severity: Severity,
    cvss: f64,
    category: ModuleCategory,
    description: String,
    remediation: String,
    evidence_details: Vec<String>,
) -> Finding {
    let prefix = severity.finding_id_prefix();
    let id = format!("DEP-{prefix}-{:03}", *id_counter);
    *id_counter += 1;
    Finding {
        id,
        title,
        severity,
        cvss,
        category,
        description,
        reproduction: None,
        evidence: Evidence {
            messages: Vec::new(),
            audit_record: None,
            canary_detected: false,
            os_events: evidence_details,
            files_modified: Vec::new(),
            network_connections: Vec::new(),
            stderr_output: None,
        },
        remediation,
    }
}

fn find_files_recursive(dir: &Path, name: &str, max_depth: u32) -> Vec<PathBuf> {
    let mut results = Vec::new();
    find_files_inner(dir, name, 0, max_depth, &mut results);
    results
}

fn find_files_inner(dir: &Path, name: &str, depth: u32, max_depth: u32, results: &mut Vec<PathBuf>) {
    if depth > max_depth {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && path.file_name().map(|n| n == name).unwrap_or(false) {
            results.push(path);
        } else if path.is_dir() {
            let dir_name = path.file_name().unwrap_or_default().to_string_lossy();
            // Skip node_modules and .git to avoid deep recursion
            if dir_name != "node_modules" && dir_name != ".git" {
                find_files_inner(&path, name, depth + 1, max_depth, results);
            }
        }
    }
}

fn collect_source_files(dir: &Path, max_depth: u32) -> Vec<PathBuf> {
    let extensions = ["js", "ts", "py", "rb", "go", "rs", "java", "env", "cfg", "ini", "toml", "yaml", "yml", "json", "sh"];
    let mut results = Vec::new();
    collect_source_inner(dir, &extensions, 0, max_depth, &mut results);
    results
}

fn collect_source_inner(dir: &Path, extensions: &[&str], depth: u32, max_depth: u32, results: &mut Vec<PathBuf>) {
    if depth > max_depth {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if extensions.contains(&ext) {
                    results.push(path);
                }
            }
        } else if path.is_dir() {
            let dir_name = path.file_name().unwrap_or_default().to_string_lossy();
            if dir_name != "node_modules" && dir_name != ".git" && dir_name != "__pycache__" {
                collect_source_inner(&path, extensions, depth + 1, max_depth, results);
            }
        }
    }
}

fn check_world_writable(dir: &Path, max_depth: u32) -> Vec<PathBuf> {
    let mut results = Vec::new();
    check_world_writable_inner(dir, 0, max_depth, &mut results);
    results
}

fn check_world_writable_inner(dir: &Path, depth: u32, max_depth: u32, results: &mut Vec<PathBuf>) {
    if depth > max_depth {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if let Ok(metadata) = path.metadata() {
            let mode = metadata.permissions().mode();
            if mode & 0o002 != 0 {
                results.push(path.clone());
            }
        }
        if path.is_dir() {
            check_world_writable_inner(&path, depth + 1, max_depth, results);
        }
    }
}

// ---------- Module implementation ----------

#[async_trait]
impl ScanModule for DependencyAuditModule {
    fn name(&self) -> &str {
        "dependency-audit"
    }

    fn description(&self) -> &str {
        "Audits server dependencies for known vulnerabilities and configuration for insecure defaults"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DependencyAudit
    }

    async fn run(&self, ctx: &mut ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut id_counter: u32 = 1;
        let sandbox_root = ctx.sandbox.root().to_path_buf();

        // 1. Node.js dependency scanning
        scan_node_deps(&sandbox_root, &mut findings, &mut id_counter);

        // 2. Python dependency scanning
        scan_python_deps(&sandbox_root, &mut findings, &mut id_counter);

        // 3. Configuration audit checks
        check_running_as_root(&mut findings, &mut id_counter);
        check_world_writable_files(&sandbox_root, &mut findings, &mut id_counter);
        check_hardcoded_secrets(&sandbox_root, &mut findings, &mut id_counter);
        check_deprecated_runtimes(&mut findings, &mut id_counter);

        // 4. Manifest audit
        check_manifest(&sandbox_root, &ctx.tool_list, &mut findings, &mut id_counter);

        Ok(findings)
    }
}

// ---------- Node.js scanning ----------

fn scan_node_deps(root: &Path, findings: &mut Vec<Finding>, id_counter: &mut u32) {
    let package_jsons = find_files_recursive(root, "package.json", 5);
    for pj_path in package_jsons {
        let project_dir = match pj_path.parent() {
            Some(d) => d,
            None => continue,
        };

        // Try running npm audit
        if let Some(audit_findings) = try_npm_audit(project_dir, id_counter) {
            findings.extend(audit_findings);
        } else {
            // Fallback: parse package.json directly
            if let Ok(content) = fs::read_to_string(&pj_path) {
                parse_package_json_for_findings(&content, &pj_path, findings, id_counter);
            }
        }
    }
}

fn try_npm_audit(project_dir: &Path, id_counter: &mut u32) -> Option<Vec<Finding>> {
    let output = Command::new("npm")
        .args(["audit", "--json"])
        .current_dir(project_dir)
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_npm_audit_json(&stdout, project_dir, id_counter)
}

fn parse_npm_audit_json(json_str: &str, project_dir: &Path, id_counter: &mut u32) -> Option<Vec<Finding>> {
    let audit: NpmAuditOutput = serde_json::from_str(json_str).ok()?;
    let mut findings = Vec::new();

    for vuln in audit.vulnerabilities.values() {
        let base_severity = npm_severity_to_severity(&vuln.severity);

        let has_fix = match &vuln.fix_available {
            Value::Bool(b) => *b,
            Value::Object(_) => true,
            _ => false,
        };

        let severity = if has_fix {
            base_severity
        } else {
            lower_severity(base_severity)
        };

        // Extract advisory details from via
        let mut title = format!("Vulnerable dependency: {}", vuln.name);
        let mut description = format!(
            "Package '{}' has a known {} severity vulnerability.",
            vuln.name, vuln.severity
        );
        let mut cvss = default_cvss_for_severity(&severity);

        for via in &vuln.via {
            if let NpmVia::Advisory(adv) = via {
                if let Some(ref t) = adv.title {
                    title = format!("{}: {}", vuln.name, t);
                }
                if let Some(ref url) = adv.url {
                    description.push_str(&format!("\nAdvisory: {url}"));
                }
                if let Some(ref c) = adv.cvss {
                    if c.score > 0.0 {
                        cvss = c.score;
                    }
                }
            }
        }

        if let Some(ref range) = vuln.range {
            description.push_str(&format!("\nAffected range: {range}"));
        }

        let remediation = if has_fix {
            format!("Run `npm audit fix` in {} to update to a patched version.", project_dir.display())
        } else {
            format!(
                "No fix is currently available for {}. Consider finding an alternative package or monitoring for updates.",
                vuln.name
            )
        };

        findings.push(make_finding(
            id_counter,
            title,
            severity,
            cvss,
            ModuleCategory::DependencyAudit,
            description,
            remediation,
            vec![format!("npm audit in {}", project_dir.display())],
        ));
    }

    Some(findings)
}

fn parse_package_json_for_findings(
    content: &str,
    pj_path: &Path,
    findings: &mut Vec<Finding>,
    id_counter: &mut u32,
) {
    // Without npm audit, we can only report that dependencies exist but weren't audited
    let parsed: Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return,
    };

    let deps = parsed.get("dependencies").and_then(|d| d.as_object());
    if let Some(deps) = deps {
        if !deps.is_empty() {
            findings.push(make_finding(
                id_counter,
                "Node.js dependencies not audited".to_string(),
                Severity::Info,
                0.0,
                ModuleCategory::DependencyAudit,
                format!(
                    "Found {} dependencies in {} but npm audit was not available. \
                     Dependencies could not be checked for known vulnerabilities.",
                    deps.len(),
                    pj_path.display()
                ),
                "Install npm and run `npm audit` to check for vulnerabilities.".to_string(),
                vec![format!("package.json at {}", pj_path.display())],
            ));
        }
    }
}

// ---------- Python scanning ----------

fn scan_python_deps(root: &Path, findings: &mut Vec<Finding>, id_counter: &mut u32) {
    let req_files = find_files_recursive(root, "requirements.txt", 5);
    for req_path in &req_files {
        let project_dir = match req_path.parent() {
            Some(d) => d,
            None => continue,
        };

        // Try pip-audit first
        if let Some(audit_findings) = try_pip_audit(project_dir, id_counter) {
            findings.extend(audit_findings);
        } else if let Ok(content) = fs::read_to_string(req_path) {
            parse_requirements_txt(&content, req_path, findings, id_counter);
        }
    }

    // Also check pyproject.toml and Pipfile
    let pyproject_files = find_files_recursive(root, "pyproject.toml", 5);
    let pipfiles = find_files_recursive(root, "Pipfile", 5);

    for path in pyproject_files.iter().chain(pipfiles.iter()) {
        if !req_files.iter().any(|r| r.parent() == path.parent()) {
            findings.push(make_finding(
                id_counter,
                "Python project dependencies not audited".to_string(),
                Severity::Info,
                0.0,
                ModuleCategory::DependencyAudit,
                format!(
                    "Found Python dependency file at {} but no requirements.txt was found \
                     and pip-audit is not available.",
                    path.display()
                ),
                "Generate requirements.txt and run pip-audit to check for vulnerabilities.".to_string(),
                vec![format!("Dependency file at {}", path.display())],
            ));
        }
    }
}

fn try_pip_audit(project_dir: &Path, id_counter: &mut u32) -> Option<Vec<Finding>> {
    let output = Command::new("pip-audit")
        .args(["--format", "json", "-r", "requirements.txt"])
        .current_dir(project_dir)
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_pip_audit_json(&stdout, project_dir, id_counter)
}

fn parse_pip_audit_json(json_str: &str, project_dir: &Path, id_counter: &mut u32) -> Option<Vec<Finding>> {
    let entries: Vec<PipAuditEntry> = serde_json::from_str(json_str).ok()?;
    let mut findings = Vec::new();

    for entry in &entries {
        for vuln in &entry.vulns {
            let has_fix = !vuln.fix_versions.is_empty();
            let base_severity = Severity::High; // pip-audit doesn't provide severity, default HIGH
            let severity = if has_fix {
                base_severity
            } else {
                lower_severity(base_severity)
            };

            let description = format!(
                "Package '{}' version {} has vulnerability {}. {}",
                entry.name,
                entry.version,
                vuln.id,
                vuln.description.as_deref().unwrap_or("No description available.")
            );

            let remediation = if has_fix {
                format!(
                    "Upgrade {} to one of: {}",
                    entry.name,
                    vuln.fix_versions.join(", ")
                )
            } else {
                format!(
                    "No fix available for {} {}. Monitor {} for updates.",
                    entry.name, vuln.id, vuln.id
                )
            };

            findings.push(make_finding(
                id_counter,
                format!("{}: {}", entry.name, vuln.id),
                severity,
                default_cvss_for_severity(&severity),
                ModuleCategory::DependencyAudit,
                description,
                remediation,
                vec![format!("pip-audit in {}", project_dir.display())],
            ));
        }
    }

    Some(findings)
}

fn parse_requirements_txt(
    content: &str,
    req_path: &Path,
    findings: &mut Vec<Finding>,
    id_counter: &mut u32,
) {
    let mut packages = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        // Parse package==version or package>=version
        if let Some(idx) = line.find("==") {
            let name = line[..idx].trim();
            let version = line[idx + 2..].trim();
            packages.push((name.to_string(), version.to_string()));
        } else if let Some(idx) = line.find(">=") {
            let name = line[..idx].trim();
            let version = line[idx + 2..].trim();
            packages.push((name.to_string(), version.to_string()));
        }
    }

    if !packages.is_empty() {
        findings.push(make_finding(
            id_counter,
            "Python dependencies not audited".to_string(),
            Severity::Info,
            0.0,
            ModuleCategory::DependencyAudit,
            format!(
                "Found {} Python packages in {} but pip-audit is not available. \
                 Packages: {}",
                packages.len(),
                req_path.display(),
                packages
                    .iter()
                    .map(|(n, v)| format!("{n}=={v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "Install pip-audit and run `pip-audit -r requirements.txt` to check for vulnerabilities."
                .to_string(),
            vec![format!("requirements.txt at {}", req_path.display())],
        ));
    }
}

// ---------- Configuration checks ----------

fn check_running_as_root(findings: &mut Vec<Finding>, id_counter: &mut u32) {
    // Check effective UID
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        findings.push(make_finding(
            id_counter,
            "Server process running as root".to_string(),
            Severity::High,
            7.0,
            ModuleCategory::Configuration,
            "The scanner (and likely the MCP server) is running as root (UID 0). \
             Running as root gives the server unrestricted access to the system, \
             making any vulnerability significantly more impactful."
                .to_string(),
            "Run the MCP server as a non-root user with minimal required permissions. \
             Use a dedicated service account."
                .to_string(),
            vec!["Effective UID = 0".to_string()],
        ));
    }
}

fn check_world_writable_files(
    root: &Path,
    findings: &mut Vec<Finding>,
    id_counter: &mut u32,
) {
    let writable = check_world_writable(root, 4);
    for path in writable {
        findings.push(make_finding(
            id_counter,
            format!("World-writable file: {}", path.display()),
            Severity::Medium,
            5.0,
            ModuleCategory::Configuration,
            format!(
                "File {} is world-writable (permissions include o+w). \
                 Any user on the system can modify this file, which could lead to \
                 code injection or configuration tampering.",
                path.display()
            ),
            format!(
                "Remove world-writable permission: chmod o-w '{}'",
                path.display()
            ),
            vec![format!("File mode includes 0o002: {}", path.display())],
        ));
    }
}

fn check_hardcoded_secrets(
    root: &Path,
    findings: &mut Vec<Finding>,
    id_counter: &mut u32,
) {
    let source_files = collect_source_files(root, 5);
    let compiled_patterns: Vec<(&SecretPattern, Regex)> = SECRET_PATTERNS
        .iter()
        .filter_map(|sp| Regex::new(sp.regex).ok().map(|r| (sp, r)))
        .collect();

    for file_path in source_files {
        let content = match fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for (pattern, regex) in &compiled_patterns {
            for mat in regex.find_iter(&content) {
                // Truncate the matched text for display
                let matched = mat.as_str();
                let display_match = if matched.len() > 80 {
                    format!("{}...", &matched[..80])
                } else {
                    matched.to_string()
                };

                findings.push(make_finding(
                    id_counter,
                    format!("Hardcoded secret: {} in {}", pattern.name, file_path.file_name().unwrap_or_default().to_string_lossy()),
                    Severity::High,
                    pattern.cvss,
                    ModuleCategory::Configuration,
                    format!(
                        "Found potential {} in file {}:\n  {}",
                        pattern.name,
                        file_path.display(),
                        display_match
                    ),
                    "Remove hardcoded secrets from source files. Use environment variables \
                     or a secrets manager instead."
                        .to_string(),
                    vec![format!("Pattern match in {}", file_path.display())],
                ));
            }
        }
    }
}

fn check_deprecated_runtimes(findings: &mut Vec<Finding>, id_counter: &mut u32) {
    // Check Node.js version
    if let Ok(output) = Command::new("node").arg("--version").output() {
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if is_eol_node(&version) {
            findings.push(make_finding(
                id_counter,
                format!("Deprecated Node.js runtime: {version}"),
                Severity::Medium,
                4.0,
                ModuleCategory::Configuration,
                format!(
                    "Node.js {version} is end-of-life and no longer receives security updates. \
                     Known vulnerabilities in the runtime itself will not be patched."
                ),
                "Upgrade to a supported LTS version of Node.js (18.x, 20.x, or later).".to_string(),
                vec![format!("node --version: {version}")],
            ));
        }
    }

    // Check Python version
    if let Ok(output) = Command::new("python3").arg("--version").output() {
        let version_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        // Output: "Python 3.x.y"
        let version = version_str
            .strip_prefix("Python ")
            .unwrap_or(&version_str)
            .to_string();
        if is_eol_python(&version) {
            findings.push(make_finding(
                id_counter,
                format!("Deprecated Python runtime: {version}"),
                Severity::Medium,
                4.0,
                ModuleCategory::Configuration,
                format!(
                    "Python {version} is end-of-life and no longer receives security updates. \
                     Known vulnerabilities in the runtime itself will not be patched."
                ),
                "Upgrade to a supported version of Python (3.9+).".to_string(),
                vec![format!("python3 --version: {version}")],
            ));
        }
    }
}

// ---------- Manifest audit ----------

fn check_manifest(
    root: &Path,
    tool_list: &[crate::client::ToolInfo],
    findings: &mut Vec<Finding>,
    id_counter: &mut u32,
) {
    let manifest_path = root.join("clawdefender.toml");
    let content = match fs::read_to_string(&manifest_path) {
        Ok(c) => c,
        Err(_) => return, // No manifest, nothing to audit
    };

    let manifest: Value = match toml_minimal_parse(&content) {
        Some(v) => v,
        None => return,
    };

    // Check declared tools vs actual tools
    if let Some(declared_tools) = manifest
        .get("tools")
        .and_then(|t| t.as_array())
    {
        let declared_names: Vec<&str> = declared_tools
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
            .collect();

        for tool in tool_list {
            if !declared_names.contains(&tool.name.as_str()) {
                findings.push(make_finding(
                    id_counter,
                    format!("Undeclared tool capability: {}", tool.name),
                    Severity::High,
                    7.0,
                    ModuleCategory::DependencyAudit,
                    format!(
                        "Tool '{}' is available via tools/list but not declared in \
                         the clawdefender.toml manifest. This could indicate undocumented \
                         or hidden capabilities.",
                        tool.name
                    ),
                    format!(
                        "Add '{}' to the [tools] section of clawdefender.toml or remove the tool.",
                        tool.name
                    ),
                    vec![format!(
                        "Tool '{}' in tools/list but not in manifest",
                        tool.name
                    )],
                ));
            }
        }
    }

    // Check for overly broad permissions
    if let Some(permissions) = manifest.get("permissions").and_then(|p| p.as_array()) {
        for perm in permissions {
            if let Some(scope) = perm.get("scope").and_then(|s| s.as_str()) {
                if scope == "**" || scope == "*" {
                    findings.push(make_finding(
                        id_counter,
                        "Overly broad permission scope in manifest".to_string(),
                        Severity::Medium,
                        5.5,
                        ModuleCategory::DependencyAudit,
                        format!(
                            "Permission scope '{}' grants access to all operations. \
                             This defeats the purpose of permission scoping.",
                            scope
                        ),
                        "Narrow the permission scope to only the specific operations required."
                            .to_string(),
                        vec![format!("Scope '{}' in manifest permissions", scope)],
                    ));
                }
            }
        }
    }

    // Check missing max_risk
    if manifest.get("max_risk").is_none() {
        findings.push(make_finding(
            id_counter,
            "Missing max_risk level in manifest".to_string(),
            Severity::Medium,
            4.0,
            ModuleCategory::DependencyAudit,
            "The clawdefender.toml manifest does not declare a max_risk level. \
             Without a risk threshold, the scanner cannot enforce risk boundaries."
                .to_string(),
            "Add a `max_risk` field (e.g., max_risk = \"medium\") to the manifest.".to_string(),
            vec!["No max_risk in manifest".to_string()],
        ));
    }

    // Check declares_all_actions
    if let Some(declares_all) = manifest
        .get("declares_all_actions")
        .and_then(|d| d.as_bool())
    {
        if declares_all {
            // If declares_all_actions is true but there are undeclared tools, flag it
            if let Some(declared_tools) = manifest.get("tools").and_then(|t| t.as_array()) {
                let declared_names: Vec<&str> = declared_tools
                    .iter()
                    .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
                    .collect();
                let undeclared: Vec<&str> = tool_list
                    .iter()
                    .map(|t| t.name.as_str())
                    .filter(|n| !declared_names.contains(n))
                    .collect();
                if !undeclared.is_empty() {
                    findings.push(make_finding(
                        id_counter,
                        "Manifest claims complete action declaration but has undeclared tools"
                            .to_string(),
                        Severity::High,
                        7.5,
                        ModuleCategory::DependencyAudit,
                        format!(
                            "The manifest sets declares_all_actions = true, but the following \
                             tools are not declared: {}. This is either a misconfiguration \
                             or an attempt to hide capabilities.",
                            undeclared.join(", ")
                        ),
                        "Either declare all tools in the manifest or set declares_all_actions = false."
                            .to_string(),
                        vec![format!(
                            "Undeclared tools: {}",
                            undeclared.join(", ")
                        )],
                    ));
                }
            }
        }
    }
}

/// Minimal TOML parser that handles the subset we need for manifest checking.
/// Parses into serde_json::Value for uniform handling.
fn toml_minimal_parse(content: &str) -> Option<Value> {
    // We'll do a simple line-by-line parse for key = value, [[arrays]], [sections]
    let mut root = serde_json::Map::new();
    let mut current_section: Option<String> = None;
    let mut current_array_section: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Array of tables: [[section]]
        if line.starts_with("[[") && line.ends_with("]]") {
            let section = line[2..line.len() - 2].trim().to_string();
            current_array_section = Some(section.clone());
            current_section = None;
            // Ensure the array exists
            if !root.contains_key(&section) {
                root.insert(section.clone(), Value::Array(Vec::new()));
            }
            // Add a new empty object to the array
            if let Some(Value::Array(arr)) = root.get_mut(&section) {
                arr.push(Value::Object(serde_json::Map::new()));
            }
            continue;
        }

        // Table: [section]
        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim().to_string();
            current_section = Some(section.clone());
            current_array_section = None;
            if !root.contains_key(&section) {
                root.insert(section, Value::Object(serde_json::Map::new()));
            }
            continue;
        }

        // Key = Value
        if let Some(eq_idx) = line.find('=') {
            let key = line[..eq_idx].trim().to_string();
            let val_str = line[eq_idx + 1..].trim();
            let value = parse_toml_value(val_str);

            if let Some(ref arr_section) = current_array_section {
                if let Some(Value::Array(arr)) = root.get_mut(arr_section) {
                    if let Some(Value::Object(last)) = arr.last_mut() {
                        last.insert(key, value);
                    }
                }
            } else if let Some(ref section) = current_section {
                if let Some(Value::Object(map)) = root.get_mut(section) {
                    map.insert(key, value);
                }
            } else {
                root.insert(key, value);
            }
        }
    }

    Some(Value::Object(root))
}

fn parse_toml_value(s: &str) -> Value {
    // Boolean
    if s == "true" {
        return Value::Bool(true);
    }
    if s == "false" {
        return Value::Bool(false);
    }
    // Quoted string
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        return Value::String(s[1..s.len() - 1].to_string());
    }
    // Number
    if let Ok(n) = s.parse::<i64>() {
        return Value::Number(n.into());
    }
    if let Ok(n) = s.parse::<f64>() {
        if let Some(n) = serde_json::Number::from_f64(n) {
            return Value::Number(n);
        }
    }
    // Array (simple)
    if s.starts_with('[') && s.ends_with(']') {
        let inner = s[1..s.len() - 1].trim();
        if inner.is_empty() {
            return Value::Array(Vec::new());
        }
        let items: Vec<Value> = inner.split(',').map(|i| parse_toml_value(i.trim())).collect();
        return Value::Array(items);
    }
    // Fallback: string
    Value::String(s.to_string())
}

// ---------- Tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_npm_severity_mapping() {
        assert_eq!(npm_severity_to_severity("critical"), Severity::Critical);
        assert_eq!(npm_severity_to_severity("high"), Severity::High);
        assert_eq!(npm_severity_to_severity("moderate"), Severity::Medium);
        assert_eq!(npm_severity_to_severity("low"), Severity::Low);
        assert_eq!(npm_severity_to_severity("info"), Severity::Info);
        assert_eq!(npm_severity_to_severity("unknown"), Severity::Info);
    }

    #[test]
    fn test_lower_severity() {
        assert_eq!(lower_severity(Severity::Critical), Severity::High);
        assert_eq!(lower_severity(Severity::High), Severity::Medium);
        assert_eq!(lower_severity(Severity::Medium), Severity::Low);
        assert_eq!(lower_severity(Severity::Low), Severity::Info);
        assert_eq!(lower_severity(Severity::Info), Severity::Info);
    }

    #[test]
    fn test_parse_npm_audit_json_with_vulnerabilities() {
        let json = r#"{
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash",
                    "severity": "high",
                    "via": [
                        {
                            "title": "Prototype Pollution",
                            "url": "https://github.com/advisories/GHSA-test",
                            "severity": "high",
                            "cwe": ["CWE-1321"],
                            "cvss": { "score": 7.4 }
                        }
                    ],
                    "range": "<4.17.21",
                    "fix_available": true
                }
            }
        }"#;

        let mut id_counter = 1;
        let findings = parse_npm_audit_json(json, Path::new("/test"), &mut id_counter).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!((findings[0].cvss - 7.4).abs() < 0.01);
        assert!(findings[0].title.contains("lodash"));
        assert!(findings[0].title.contains("Prototype Pollution"));
        assert!(findings[0].remediation.contains("npm audit fix"));
    }

    #[test]
    fn test_parse_npm_audit_json_no_fix() {
        let json = r#"{
            "vulnerabilities": {
                "bad-pkg": {
                    "name": "bad-pkg",
                    "severity": "critical",
                    "via": ["some-dep"],
                    "fix_available": false
                }
            }
        }"#;

        let mut id_counter = 1;
        let findings = parse_npm_audit_json(json, Path::new("/test"), &mut id_counter).unwrap();
        assert_eq!(findings.len(), 1);
        // Critical without fix becomes High
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_parse_npm_audit_json_empty() {
        let json = r#"{ "vulnerabilities": {} }"#;
        let mut id_counter = 1;
        let findings = parse_npm_audit_json(json, Path::new("/test"), &mut id_counter).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_parse_requirements_txt() {
        let content = "# requirements\nflask==2.0.1\nrequests>=2.25.0\n-e git+https://example.com\n\ndjango==3.2.0\n";
        let mut findings = Vec::new();
        let mut id_counter = 1;
        parse_requirements_txt(content, Path::new("/test/requirements.txt"), &mut findings, &mut id_counter);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("flask==2.0.1"));
        assert!(findings[0].description.contains("requests==2.25.0"));
        assert!(findings[0].description.contains("django==3.2.0"));
        assert!(findings[0].description.contains("3 Python packages"));
    }

    #[test]
    fn test_secret_detection_api_key() {
        let re = Regex::new(SECRET_PATTERNS[0].regex).unwrap();
        // Should match
        assert!(re.is_match(r#"api_key = 'sk-abc12345678'"#));
        assert!(re.is_match(r#"token: "some-long-secret-value-here""#));
        assert!(re.is_match(r#"password = "mysecretpassword123""#));
        // Should not match (too short)
        assert!(!re.is_match(r#"api_key = 'short'"#));
    }

    #[test]
    fn test_secret_detection_aws_key() {
        let re = Regex::new(SECRET_PATTERNS[1].regex).unwrap();
        assert!(re.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(!re.is_match("AKIA123")); // Too short
        assert!(!re.is_match("NotAnAWSKey1234567890"));
    }

    #[test]
    fn test_secret_detection_github_token() {
        let re = Regex::new(SECRET_PATTERNS[2].regex).unwrap();
        assert!(re.is_match("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"));
        assert!(re.is_match("gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"));
        assert!(re.is_match("github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"));
        assert!(!re.is_match("ghp_short"));
    }

    #[test]
    fn test_world_writable_detection() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file_path = tmp.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        // Set world-writable
        let mut perms = fs::metadata(&file_path).unwrap().permissions();
        perms.set_mode(0o666);
        fs::set_permissions(&file_path, perms).unwrap();

        let writable = check_world_writable(tmp.path(), 2);
        assert!(writable.contains(&file_path));

        // Remove world-writable
        let mut perms = fs::metadata(&file_path).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&file_path, perms).unwrap();

        let writable = check_world_writable(tmp.path(), 2);
        assert!(!writable.contains(&file_path));
    }

    #[test]
    fn test_eol_node_versions() {
        assert!(is_eol_node("v14.21.3")); // Even < 18 = EOL
        assert!(is_eol_node("v16.20.0")); // Even < 18 = EOL
        assert!(is_eol_node("v17.9.1"));  // Odd = always EOL
        assert!(!is_eol_node("v18.19.0")); // LTS, still supported
        assert!(!is_eol_node("v20.10.0")); // LTS, still supported
        assert!(is_eol_node("v15.0.0"));   // Odd = EOL
    }

    #[test]
    fn test_eol_python_versions() {
        assert!(is_eol_python("2.7.18"));
        assert!(is_eol_python("3.7.17"));
        assert!(is_eol_python("3.8.19"));
        assert!(!is_eol_python("3.9.0"));
        assert!(!is_eol_python("3.12.0"));
    }

    #[test]
    fn test_manifest_audit_undeclared_tools() {
        let manifest_content = r#"
max_risk = "medium"
declares_all_actions = true

[[tools]]
name = "read_file"

[[tools]]
name = "write_file"
"#;

        let manifest = toml_minimal_parse(manifest_content).unwrap();
        let tool_list = vec![
            crate::client::ToolInfo {
                name: "read_file".to_string(),
                description: "Read a file".to_string(),
                input_schema: Value::Null,
            },
            crate::client::ToolInfo {
                name: "write_file".to_string(),
                description: "Write a file".to_string(),
                input_schema: Value::Null,
            },
            crate::client::ToolInfo {
                name: "execute_command".to_string(),
                description: "Execute a shell command".to_string(),
                input_schema: Value::Null,
            },
        ];

        let mut findings = Vec::new();
        let mut id_counter = 1;

        // Check declared tools vs actual tools
        if let Some(declared_tools) = manifest.get("tools").and_then(|t| t.as_array()) {
            let declared_names: Vec<&str> = declared_tools
                .iter()
                .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
                .collect();

            for tool in &tool_list {
                if !declared_names.contains(&tool.name.as_str()) {
                    findings.push(make_finding(
                        &mut id_counter,
                        format!("Undeclared tool: {}", tool.name),
                        Severity::High,
                        7.0,
                        ModuleCategory::DependencyAudit,
                        format!("Tool '{}' not in manifest", tool.name),
                        "Declare the tool in manifest".to_string(),
                        vec![],
                    ));
                }
            }
        }

        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("execute_command"));
    }

    #[test]
    fn test_manifest_missing_max_risk() {
        let manifest_content = r#"
declares_all_actions = false

[[tools]]
name = "read_file"
"#;

        let manifest = toml_minimal_parse(manifest_content).unwrap();
        assert!(manifest.get("max_risk").is_none());
    }

    #[test]
    fn test_toml_minimal_parse() {
        let content = r#"
max_risk = "high"
declares_all_actions = true

[[tools]]
name = "read_file"
scope = "**"

[[tools]]
name = "write_file"

[[permissions]]
scope = "**"
"#;

        let parsed = toml_minimal_parse(content).unwrap();
        assert_eq!(
            parsed.get("max_risk").and_then(|v| v.as_str()),
            Some("high")
        );
        assert_eq!(
            parsed.get("declares_all_actions").and_then(|v| v.as_bool()),
            Some(true)
        );

        let tools = parsed.get("tools").and_then(|t| t.as_array()).unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(
            tools[0].get("name").and_then(|n| n.as_str()),
            Some("read_file")
        );

        let perms = parsed.get("permissions").and_then(|p| p.as_array()).unwrap();
        assert_eq!(perms.len(), 1);
        assert_eq!(
            perms[0].get("scope").and_then(|s| s.as_str()),
            Some("**")
        );
    }

    #[test]
    fn test_pip_audit_json_parsing() {
        let json = r#"[
            {
                "name": "flask",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "CVE-2023-12345",
                        "fix_versions": ["2.3.3"],
                        "description": "A security issue"
                    }
                ]
            },
            {
                "name": "django",
                "version": "3.2.0",
                "vulns": []
            }
        ]"#;

        let mut id_counter = 1;
        let findings = parse_pip_audit_json(json, Path::new("/test"), &mut id_counter).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("flask"));
        assert!(findings[0].title.contains("CVE-2023-12345"));
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].remediation.contains("2.3.3"));
    }
}
