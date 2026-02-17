# ClawDefender Security Scanner Guide

## Overview

ClawDefender Security Scanner is an automated security testing framework for MCP (Model Context Protocol) servers. It discovers vulnerabilities by simulating real attack scenarios against MCP server implementations in a sandboxed environment, providing actionable findings with CVSS scores and remediation guidance.

The scanner operates by launching the target MCP server, connecting as a client, and executing a series of attack modules that probe for common vulnerability classes including path traversal, prompt injection, data exfiltration, capability escalation, dependency issues, and resilience problems.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/clawai/clawdefender.git
cd clawdefender

# Build the CLI (includes the scanner)
cargo build --release

# The binary is at target/release/clawdefender
```

### Verify Installation

```bash
clawdefender scan --list-modules
```

This should display all six available scan modules.

## Running a Scan

### Basic Usage

```bash
# Scan an MCP server
clawdefender scan -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Scan with a custom timeout (seconds)
clawdefender scan --timeout 3600 -- python my_mcp_server.py

# Run only specific modules
clawdefender scan --modules path-traversal,prompt-injection -- npx server
```

The server command follows `--` (double dash) to separate scanner flags from the server command and its arguments.

### Output Formats

**Terminal output (default):**
```bash
clawdefender scan -- npx server
```

**JSON output:**
```bash
clawdefender scan --json -- npx server
```

**HTML report:**
```bash
clawdefender scan --html report.html -- npx server
```

**Write to file:**
```bash
clawdefender scan --output report.txt -- npx server
clawdefender scan --json --output report.json -- npx server
```

You can combine formats:
```bash
clawdefender scan --json --html report.html --output report.json -- npx server
```

### Exit Codes

The scanner uses exit codes for CI/CD integration:

| Exit Code | Meaning |
|-----------|---------|
| 0 | No critical or high severity findings |
| 1 | Critical severity finding(s) detected |
| 2 | High severity finding(s) detected (no critical) |

Adjust the threshold with `--threshold`:
```bash
# Fail on medium or higher
clawdefender scan --threshold medium -- npx server

# Only fail on critical
clawdefender scan --threshold critical -- npx server
```

## Interpreting Results

### Severity Levels

ClawDefender uses five severity levels aligned with industry standards:

- **CRITICAL** (CVSS 9.0-10.0): Immediate exploitation possible. Remote code execution, full credential theft, or complete system compromise. Requires immediate remediation.

- **HIGH** (CVSS 7.0-8.9): Significant security impact. Unauthorized data access, privilege escalation, or significant confidentiality breach. Should be fixed before production deployment.

- **MEDIUM** (CVSS 4.0-6.9): Moderate security impact. Limited data exposure, requires specific conditions to exploit. Should be addressed in the next development cycle.

- **LOW** (CVSS 0.1-3.9): Minor security concern. Informational disclosure or theoretical attack vectors. Fix as part of regular maintenance.

- **INFO** (CVSS 0.0): Informational finding. Best practice recommendations or configuration observations. No direct security impact.

### CVSS Scores

Each finding includes a CVSS v3.1 base score and vector string. The vector string (e.g., `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) breaks down the attack characteristics:

- **AV** (Attack Vector): Network, Adjacent, Local, Physical
- **AC** (Attack Complexity): Low, High
- **PR** (Privileges Required): None, Low, High
- **UI** (User Interaction): None, Required
- **S** (Scope): Unchanged, Changed
- **C/I/A** (Confidentiality/Integrity/Availability Impact): None, Low, High

### Finding Structure

Each finding contains:

- **ID**: Unique identifier with severity prefix (e.g., CRIT-001)
- **Title**: Brief description of the vulnerability
- **Severity**: Critical, High, Medium, Low, or Info
- **CVSS Score**: Numeric score (0.0-10.0) with vector string
- **Category**: Which attack module discovered it
- **Description**: Detailed explanation of the vulnerability
- **Evidence**: Proof including messages, file changes, network activity, canary detections
- **Reproduction**: Steps to reproduce (tool name, arguments)
- **Remediation**: Specific guidance on how to fix the issue

### Evidence and Canary Detection

The scanner plants canary data (fake credentials, SSH keys, API tokens) in the sandbox environment. If the MCP server reads and returns this data, it proves a real exfiltration or credential access vulnerability exists. Canary detections are marked prominently in findings.

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install ClawDefender
        run: cargo install clawdefender-cli

      - name: Run Security Scan
        run: |
          clawdefender scan \
            --json \
            --output scan-results.json \
            --html scan-report.html \
            --threshold high \
            -- npx -y ./my-mcp-server

      - name: Upload Scan Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: |
            scan-results.json
            scan-report.html
```

### GitLab CI

```yaml
security-scan:
  stage: test
  script:
    - cargo install clawdefender-cli
    - clawdefender scan --json --output scan-results.json --threshold high -- npx -y ./my-mcp-server
  artifacts:
    when: always
    paths:
      - scan-results.json
```

### Baseline Scanning for Regression Detection

Use baseline scanning to track security posture over time and only alert on new findings:

```bash
# Generate initial baseline
clawdefender scan --json --output baseline.json -- npx server

# In CI, compare against baseline
clawdefender scan --baseline baseline.json --json --output current.json -- npx server
```

When `--baseline` is provided, only findings NOT present in the baseline are reported and affect the exit code. This prevents alert fatigue from known accepted risks while catching regressions.

**Updating the baseline:**
```bash
# After addressing findings or accepting risks, update the baseline
clawdefender scan --json --output baseline.json -- npx server
# Commit baseline.json to your repository
```

## Customizing Scan Modules

### Available Modules

| Module | Category | Description |
|--------|----------|-------------|
| `path-traversal` | Path Traversal | Tests for directory traversal and unauthorized file access |
| `prompt-injection` | Prompt Injection | Tests for prompt injection attacks and instruction override |
| `exfiltration` | Data Exfiltration | Tests for unauthorized data exfiltration via network |
| `capability-escalation` | Capability Escalation | Tests for privilege escalation and tool abuse |
| `dependency-audit` | Dependency Audit | Audits server dependencies for known vulnerabilities |
| `fuzzing` | Fuzzing | Fuzzes tool inputs for crashes and unexpected behavior |

### Running Specific Modules

```bash
# Run only path traversal and injection tests
clawdefender scan --modules path-traversal,prompt-injection -- npx server

# Run everything except fuzzing (which can be slow)
clawdefender scan --modules path-traversal,prompt-injection,exfiltration,capability-escalation,dependency-audit -- npx server
```

### Module Timeout

Each module has a default timeout of 300 seconds. The total scan timeout defaults to 1800 seconds (30 minutes). Adjust with:

```bash
clawdefender scan --timeout 3600 -- npx server
```

## Understanding the Sandbox

The scanner runs each MCP server in a sandboxed environment that:

1. **Creates a temporary home directory** with realistic but fake files:
   - SSH keys with canary strings
   - AWS credentials with canary tokens
   - GPG keyrings with detectable markers
   - `.env` files with canary secrets
   - `.bash_history` with realistic entries
   - A mock project directory with `package.json`, source files, etc.

2. **Redirects environment variables** (`HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`) to the sandbox directory so the MCP server sees the fake filesystem.

3. **Plants canary strings** in sensitive files. If the MCP server reads and returns any canary data, the scanner proves a real vulnerability exists rather than relying on heuristics.

4. **Monitors filesystem and network activity** during the scan to collect evidence of unauthorized operations.

The sandbox is automatically cleaned up after the scan completes.

## Troubleshooting

### Scan Hangs or Times Out

- Increase the timeout: `--timeout 3600`
- Check that the server command works standalone: run it manually first
- Run a single module to isolate the issue: `--modules path-traversal`

### No Findings Reported

- Verify the server exposes tools: check `clawdefender scan --list-modules`
- Ensure the server starts correctly in the sandboxed environment
- Some servers may not be vulnerable -- that is the expected happy path

### Server Fails to Start

- Ensure all dependencies are installed (Node.js, Python, etc.)
- Check that the server command is correct
- Try running the server command manually to see error output

### False Positives

If a finding is a false positive:
- Add it to your baseline file and use `--baseline` in CI
- Filter by module to skip the problematic test category
- Report the false positive to help improve detection accuracy
