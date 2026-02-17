# ClawDefender v0.8 Release Notes

## Security Scanner -- General Availability

Phase 8 completes the ClawDefender Security Scanner with production-ready reporting, CLI integration, and CI/CD support. The scanner can now be used as a standalone tool to audit MCP servers for security vulnerabilities before deployment.

### New Features

**CVSS v3.1 Scoring**
All findings now include a CVSS v3.1 base score and vector string. Predefined vectors are assigned based on vulnerability category, providing standardized severity ratings that map to industry-standard vulnerability scoring. Scores range from 0.0 (informational) to 10.0 (critical remote code execution).

**Finding Deduplication**
When multiple modules or test cases discover the same underlying vulnerability, findings are automatically deduplicated. The scanner groups findings by category and tool name, keeps the highest severity, and merges evidence. Cross-module correlations are annotated (e.g., path traversal leading to data exfiltration).

**CLI `scan` Command**
A new `clawdefender scan` command provides full access to the scanner from the command line:
- `--json` for machine-readable output
- `--html <file>` for rich HTML reports
- `--output <file>` to write results to a file
- `--modules <list>` to run specific scan modules
- `--threshold <level>` to control exit code sensitivity
- `--baseline <file>` for delta scanning against a previous report
- `--list-modules` to discover available scan modules
- `--timeout <seconds>` to control scan duration

**Baseline Delta Scanning**
Compare current scan results against a previous baseline to identify only new vulnerabilities. This prevents alert fatigue in CI/CD pipelines by filtering out known and accepted findings. Store your baseline JSON in version control and reference it with `--baseline`.

**CI/CD Exit Codes**
The scanner returns structured exit codes: 0 for clean, 1 for critical findings, 2 for high-severity findings. Combined with `--threshold`, teams can tune their security gate to match their risk tolerance.

**Fix Suggestions**
Each finding category now includes concrete remediation guidance with code examples in both TypeScript and Python. Suggestions cover the vulnerable pattern, the fix, and best practices.

**Enhanced Progress Display**
The scan progress indicator now shows a visual progress bar with percentage, per-module status icons, elapsed and estimated remaining time, and finding counts with severity breakdown.

### Scanner Modules

The scanner ships with six attack modules covering the primary MCP threat surface:

1. **Path Traversal** -- Tests file access tools for directory traversal attacks
2. **Prompt Injection** -- Probes for instruction override and prompt manipulation
3. **Data Exfiltration** -- Detects unauthorized outbound data transmission
4. **Capability Escalation** -- Tests for privilege escalation and shell injection
5. **Dependency Audit** -- Scans server dependencies for known CVEs
6. **Fuzzing** -- Stress-tests tools with malformed and adversarial inputs

### Documentation

- **Scanner Guide** (`docs/scanner-guide.md`): Installation, usage, CI/CD integration, sandbox internals
- **Vulnerability Catalog** (`docs/vulnerability-catalog.md`): Reference for all vulnerability types with examples and fixes

### Test Coverage

The scanner crate includes 92+ unit tests across modules and 23 integration tests covering CVSS calculation, deduplication, baseline delta, exit codes, report serialization, and fix suggestions.
