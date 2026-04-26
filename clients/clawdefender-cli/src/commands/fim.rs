//! `rookbot fim` — File integrity monitoring.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use clap::Subcommand;
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Debug)]
pub enum FimAction {
    /// Show FIM status.
    Status,
    /// Create or reset baseline.
    Baseline {
        #[arg(long)]
        reset: bool,
    },
    /// Check file integrity.
    Check {
        #[arg(long)]
        path: Option<String>,
    },
    /// Show integrity violations.
    Violations {
        #[arg(long, default_value = "50")]
        limit: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FimBaseline {
    #[serde(default)]
    files: HashMap<String, String>, // path -> sha256
    created_at: String,
}

impl Default for FimBaseline {
    fn default() -> Self {
        Self {
            files: HashMap::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FimViolation {
    path: String,
    expected_hash: String,
    actual_hash: String,
    detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FimState {
    #[serde(default)]
    violations: Vec<FimViolation>,
}

impl Default for FimState {
    fn default() -> Self {
        Self {
            violations: Vec::new(),
        }
    }
}

/// Run the fim subcommand.
pub fn run(action: &FimAction) -> Result<()> {
    match action {
        FimAction::Status => status(),
        FimAction::Baseline { reset } => baseline(*reset),
        FimAction::Check { path } => check(path.as_deref()),
        FimAction::Violations { limit } => violations(*limit),
    }
}

/// Show FIM status.
fn status() -> Result<()> {
    let baseline = load_baseline()?;

    println!("File Integrity Monitoring");
    println!("=========================");
    println!();

    if baseline.files.is_empty() {
        println!("  Status:       No baseline configured");
        println!();
        println!("  Create baseline: rookbot fim baseline");
        return Ok(());
    }

    println!("  Status:       Active");
    println!("  Baseline:     {} file(s) monitored", baseline.files.len());
    println!("  Created:      {}", baseline.created_at);
    println!();

    let state = load_state()?;
    println!("  Violations:   {}", state.violations.len());

    if !state.violations.is_empty() {
        println!();
        println!("  Recent violations:");
        for v in state.violations.iter().take(5) {
            println!("    - {}", v.path);
        }
    }

    Ok(())
}

/// Create or reset baseline.
fn baseline(reset: bool) -> Result<()> {
    let baseline_path = fim_baseline_path()?;

    if baseline_path.exists() && !reset {
        println!("Baseline already exists.");
        println!();
        println!("Reset baseline: rookbot fim baseline --reset");
        return Ok(());
    }

    println!("Creating FIM baseline...");
    println!();

    // Baseline critical system paths.
    let critical_paths = vec!["/usr/local/bin/rookbot", "/usr/local/bin/clawdefender"];

    let mut baseline = FimBaseline::default();

    for path_str in &critical_paths {
        let path = PathBuf::from(path_str);
        if path.exists() {
            if let Ok(hash) = compute_sha256(&path) {
                baseline.files.insert(path_str.to_string(), hash);
                println!("  Added: {}", path_str);
            }
        }
    }

    save_baseline(&baseline)?;

    println!();
    println!(
        "Baseline created: {} file(s) monitored",
        baseline.files.len()
    );
    Ok(())
}

/// Check file integrity.
fn check(path: Option<&str>) -> Result<()> {
    let baseline = load_baseline()?;

    if baseline.files.is_empty() {
        println!("No baseline configured. Run: rookbot fim baseline");
        return Ok(());
    }

    println!("Checking file integrity...");
    println!();

    let mut state = load_state()?;
    let mut violations = 0usize;

    let paths_to_check: Vec<String> = if let Some(p) = path {
        vec![p.to_string()]
    } else {
        baseline.files.keys().cloned().collect()
    };

    for file_path in &paths_to_check {
        if let Some(expected_hash) = baseline.files.get(file_path) {
            let path_buf = PathBuf::from(file_path);
            if !path_buf.exists() {
                println!("  MISSING: {}", file_path);
                violations += 1;
                continue;
            }

            let actual_hash = compute_sha256(&path_buf)?;
            if &actual_hash != expected_hash {
                println!("  VIOLATION: {}", file_path);
                println!("    Expected: {}", expected_hash);
                println!("    Actual:   {}", actual_hash);
                violations += 1;

                // Record violation.
                state.violations.push(FimViolation {
                    path: file_path.clone(),
                    expected_hash: expected_hash.clone(),
                    actual_hash: actual_hash.clone(),
                    detected_at: chrono::Utc::now().to_rfc3339(),
                });
            } else {
                println!("  OK: {}", file_path);
            }
        }
    }

    save_state(&state)?;

    println!();
    if violations == 0 {
        println!("All files passed integrity check.");
    } else {
        println!("{} violation(s) detected.", violations);
    }

    Ok(())
}

/// Show integrity violations.
fn violations(limit: usize) -> Result<()> {
    let state = load_state()?;

    println!("FIM Violations (last {} entries)", limit);
    println!("==================");
    println!();

    if state.violations.is_empty() {
        println!("  No violations recorded.");
        return Ok(());
    }

    let violations_to_show = state.violations.iter().rev().take(limit);

    println!("  {:<40} {:<20} STATUS", "PATH", "DETECTED");
    println!("  {}", "-".repeat(80));

    for v in violations_to_show {
        let ts = v.detected_at.split('T').next().unwrap_or(&v.detected_at);
        println!("  {:<40} {:<20} MODIFIED", v.path, ts);
    }

    println!();
    println!("  {} violation(s) total", state.violations.len());

    Ok(())
}

/// Compute SHA-256 hash of a file.
fn compute_sha256(path: &PathBuf) -> Result<String> {
    use sha2::{Digest, Sha256};

    let content = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

/// Load FIM baseline from ~/.local/share/rookbot/fim/baseline.json.
fn load_baseline() -> Result<FimBaseline> {
    let path = fim_baseline_path()?;
    if !path.exists() {
        return Ok(FimBaseline::default());
    }
    let content = std::fs::read_to_string(&path)?;
    let baseline: FimBaseline = serde_json::from_str(&content)?;
    Ok(baseline)
}

/// Save FIM baseline to ~/.local/share/rookbot/fim/baseline.json.
fn save_baseline(baseline: &FimBaseline) -> Result<()> {
    let path = fim_baseline_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(baseline)?;
    std::fs::write(&path, content)?;
    Ok(())
}

/// Load FIM state from ~/.local/share/rookbot/fim/state.json.
fn load_state() -> Result<FimState> {
    let path = fim_state_path()?;
    if !path.exists() {
        return Ok(FimState::default());
    }
    let content = std::fs::read_to_string(&path)?;
    let state: FimState = serde_json::from_str(&content)?;
    Ok(state)
}

/// Save FIM state to ~/.local/share/rookbot/fim/state.json.
fn save_state(state: &FimState) -> Result<()> {
    let path = fim_state_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(state)?;
    std::fs::write(&path, content)?;
    Ok(())
}

/// Return the path to fim/baseline.json.
fn fim_baseline_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")?;
    Ok(PathBuf::from(home).join(".local/share/rookbot/fim/baseline.json"))
}

/// Return the path to fim/state.json.
fn fim_state_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")?;
    Ok(PathBuf::from(home).join(".local/share/rookbot/fim/state.json"))
}
