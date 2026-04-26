//! Output formatting for the Rookbot CLI.
//!
//! All commands use these helpers to support --json, --quiet, and human-readable modes.

use serde::Serialize;

/// Output mode determined by global CLI flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Human,
    Json,
    Quiet,
}

/// Global output context passed to every command.
#[derive(Debug, Clone)]
pub struct Output {
    pub mode: OutputMode,
    pub no_color: bool,
    pub verbose: bool,
}

impl Output {
    pub fn new(json: bool, quiet: bool, no_color: bool, verbose: bool) -> Self {
        let mode = if json {
            OutputMode::Json
        } else if quiet {
            OutputMode::Quiet
        } else {
            OutputMode::Human
        };
        Self { mode, no_color, verbose }
    }

    /// Print a human-readable line (skipped in json/quiet mode).
    pub fn println(&self, msg: &str) {
        if self.mode == OutputMode::Human {
            println!("{msg}");
        }
    }

    /// Print a blank line (human mode only).
    pub fn blank(&self) {
        if self.mode == OutputMode::Human {
            println!();
        }
    }

    /// Print a section header with underline.
    pub fn header(&self, title: &str) {
        if self.mode == OutputMode::Human {
            println!("{title}");
            println!("{}", "=".repeat(title.len()));
        }
    }

    /// Print a key-value pair.
    pub fn kv(&self, key: &str, value: &str) {
        if self.mode == OutputMode::Human {
            println!("  {:<20} {value}", format!("{key}:"));
        }
    }

    /// Print a success message with checkmark.
    pub fn success(&self, msg: &str) {
        if self.mode == OutputMode::Human {
            println!("\u{2705}  {msg}");
        }
    }

    /// Print a warning.
    pub fn warn(&self, msg: &str) {
        if self.mode == OutputMode::Human {
            eprintln!("\u{26a0}\u{fe0f}  {msg}");
        }
    }

    /// Print an error.
    pub fn error(&self, msg: &str) {
        if self.mode != OutputMode::Quiet {
            eprintln!("Error: {msg}");
        }
    }

    /// Print a check result (for doctor-style commands).
    pub fn check(&self, label: &str, ok: bool) -> bool {
        if self.mode == OutputMode::Human {
            let icon = if ok { "\u{2713}" } else { "\u{2717}" };
            println!("  {icon}  {label}");
        }
        ok
    }

    /// Print a hint/suggestion.
    pub fn hint(&self, msg: &str) {
        if self.mode == OutputMode::Human {
            println!("     -> {msg}");
        }
    }

    /// Output structured data. In JSON mode, serializes as JSON. In human mode, calls the formatter.
    pub fn data<T: Serialize>(&self, data: &T, human_fmt: impl FnOnce(&T)) {
        match self.mode {
            OutputMode::Json => {
                println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
            }
            OutputMode::Human => {
                human_fmt(data);
            }
            OutputMode::Quiet => {}
        }
    }

    /// Output JSON data directly (for --json mode).
    pub fn json<T: Serialize>(&self, data: &T) {
        if self.mode == OutputMode::Json {
            println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
        }
    }

    /// For quiet mode: just exit with the appropriate code.
    pub fn quiet_exit(&self, success: bool) {
        if self.mode == OutputMode::Quiet {
            std::process::exit(if success { 0 } else { 1 });
        }
    }

    /// Print verbose debug info (only in verbose mode).
    pub fn debug(&self, msg: &str) {
        if self.verbose {
            eprintln!("[debug] {msg}");
        }
    }

    /// Is this human output mode?
    pub fn is_human(&self) -> bool {
        self.mode == OutputMode::Human
    }

    /// Is this JSON output mode?
    pub fn is_json(&self) -> bool {
        self.mode == OutputMode::Json
    }
}
