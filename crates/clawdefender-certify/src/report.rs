//! Report generation for certification results.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Result for a single test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

/// Result rating for a compliance level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LevelResult {
    Pass,
    Partial,
    Fail,
}

impl std::fmt::Display for LevelResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LevelResult::Pass => write!(f, "PASS"),
            LevelResult::Partial => write!(f, "PARTIAL"),
            LevelResult::Fail => write!(f, "FAIL"),
        }
    }
}

/// Report for a single compliance level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelReport {
    pub name: String,
    pub tests: Vec<TestResult>,
    pub result: LevelResult,
}

impl LevelReport {
    /// Compute the level result from individual test results.
    pub fn from_tests(name: &str, tests: Vec<TestResult>) -> Self {
        let total = tests.len();
        let passed = tests.iter().filter(|t| t.passed).count();

        let result = if passed == total {
            LevelResult::Pass
        } else if total > 0 && passed >= (total + 1) / 2 {
            LevelResult::Partial
        } else {
            LevelResult::Fail
        };

        Self {
            name: name.to_string(),
            tests,
            result,
        }
    }
}

/// Full certification report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificationReport {
    pub server_name: String,
    pub timestamp: DateTime<Utc>,
    pub tool_version: String,
    pub level1: LevelReport,
    pub level2: LevelReport,
    pub level3: LevelReport,
    pub overall_level: u8,
}

impl CertificationReport {
    /// Render as human-readable text.
    pub fn to_text(&self) -> String {
        let mut out = String::new();

        out.push_str("ClawDefender Compliance Report\n");
        out.push_str(&"=".repeat(50));
        out.push('\n');
        out.push('\n');
        out.push_str(&format!("Server: {}\n", self.server_name));
        out.push_str(&format!("Date:   {}\n", self.timestamp.to_rfc3339()));
        out.push_str(&format!(
            "Tool:   clawdefender certify v{}\n",
            self.tool_version
        ));
        out.push('\n');

        format_level(&mut out, "Level 1", &self.level1);
        format_level(&mut out, "Level 2", &self.level2);
        format_level(&mut out, "Level 3", &self.level3);

        if self.overall_level == 0 {
            out.push_str("Overall: Not Compliant\n");
        } else {
            out.push_str(&format!(
                "Overall: Level {} Compliant\n",
                self.overall_level
            ));
        }

        out
    }

    /// Render as JSON.
    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

fn format_level(out: &mut String, label: &str, level: &LevelReport) {
    out.push_str(&format!("{} -- {}\n", label, level.name));
    for test in &level.tests {
        let icon = if test.passed { "  [PASS]" } else { "  [FAIL]" };
        out.push_str(&format!("{} {}\n", icon, test.name));
        if !test.passed && !test.message.is_empty() {
            out.push_str(&format!("         {}\n", test.message));
        }
    }
    out.push_str(&format!("  Result: {}\n\n", level.result));
}
