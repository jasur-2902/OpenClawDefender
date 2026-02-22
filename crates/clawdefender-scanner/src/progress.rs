use std::time::Instant;

use crate::finding::Finding;

#[derive(Debug, Clone)]
pub enum ModuleStatus {
    Pending,
    Running,
    Complete { findings: Vec<Finding> },
}

#[derive(Debug)]
pub struct ModuleProgress {
    pub name: String,
    pub status: ModuleStatus,
}

#[derive(Debug)]
pub struct ScanProgress {
    modules: Vec<ModuleProgress>,
    start_time: Instant,
}

// ANSI color codes
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

impl ScanProgress {
    pub fn new(module_names: Vec<String>) -> Self {
        let modules = module_names
            .into_iter()
            .map(|name| ModuleProgress {
                name,
                status: ModuleStatus::Pending,
            })
            .collect();
        Self {
            modules,
            start_time: Instant::now(),
        }
    }

    pub fn update_module(&mut self, name: &str, status: ModuleStatus) {
        if let Some(m) = self.modules.iter_mut().find(|m| m.name == name) {
            m.status = status;
        }
    }

    pub fn render(&self) -> String {
        let total = self.modules.len();
        let completed = self
            .modules
            .iter()
            .filter(|m| matches!(m.status, ModuleStatus::Complete { .. }))
            .count();
        let running = self
            .modules
            .iter()
            .filter(|m| matches!(m.status, ModuleStatus::Running))
            .count();

        let elapsed = self.start_time.elapsed();
        let elapsed_secs = elapsed.as_secs();
        let elapsed_str = format!("{}m {:02}s", elapsed_secs / 60, elapsed_secs % 60);

        // Estimate remaining time
        let eta_str = if completed > 0 {
            let avg_per_module = elapsed.as_secs_f64() / completed as f64;
            let remaining = (total - completed) as f64 * avg_per_module;
            let rem_secs = remaining as u64;
            format!("~{}m {:02}s", rem_secs / 60, rem_secs % 60)
        } else {
            "estimating...".to_string()
        };

        let pct = if total > 0 {
            (completed * 100) / total
        } else {
            0
        };

        // Progress bar
        let bar_width = 30;
        let filled = if total > 0 {
            (completed * bar_width) / total
        } else {
            0
        };
        let bar_color = if completed == total { GREEN } else { CYAN };
        let bar = format!(
            "{BOLD}{bar_color}[{}{}]{RESET} {pct}% ({completed}/{total})",
            "\u{2588}".repeat(filled),
            "\u{2591}".repeat(bar_width - filled),
        );

        let mut lines = vec![
            format!("{BOLD}ClawDefender Security Scan{RESET}"),
            bar,
            format!(
                "  Elapsed: {CYAN}{elapsed_str}{RESET}  |  ETA: {CYAN}{eta_str}{RESET}  |  Running: {running}"
            ),
            String::new(),
        ];

        // Module statuses
        let total_findings: usize = self
            .modules
            .iter()
            .filter_map(|m| {
                if let ModuleStatus::Complete { findings } = &m.status {
                    Some(findings.len())
                } else {
                    None
                }
            })
            .sum();

        for m in &self.modules {
            let (icon, detail, color) = match &m.status {
                ModuleStatus::Pending => {
                    ("\u{25CB}".to_string(), "pending".to_string(), "\x1b[90m") // gray
                }
                ModuleStatus::Running => ("\u{25CF}".to_string(), "running...".to_string(), YELLOW),
                ModuleStatus::Complete { findings } => {
                    if findings.is_empty() {
                        ("\u{2713}".to_string(), "no findings".to_string(), GREEN)
                    } else {
                        let crit = findings
                            .iter()
                            .filter(|f| f.severity == crate::finding::Severity::Critical)
                            .count();
                        let high = findings
                            .iter()
                            .filter(|f| f.severity == crate::finding::Severity::High)
                            .count();
                        let detail = format!(
                            "{} finding(s){}{}",
                            findings.len(),
                            if crit > 0 {
                                format!(" [{RED}{crit} critical{RESET}{RED}]")
                            } else {
                                String::new()
                            },
                            if high > 0 {
                                format!(" [{YELLOW}{high} high{RESET}{RED}]")
                            } else {
                                String::new()
                            },
                        );
                        ("\u{2713}".to_string(), detail, RED)
                    }
                }
            };
            lines.push(format!("  {color}{icon} {:<25} {detail}{RESET}", m.name));
        }

        if total_findings > 0 {
            lines.push(String::new());
            lines.push(format!(
                "  {BOLD}{RED}Total findings so far: {total_findings}{RESET}"
            ));
        }

        lines.join("\n")
    }
}
