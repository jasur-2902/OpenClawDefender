# Step 5: My Tools Experience — Architecture Specification

**Version**: 1.0
**Date**: 2026-02-25
**Author**: Agent 1 (Tools Experience Architect)
**Status**: Final

---

## 1. Trust Level System

### 1.1 Trust Levels

| Level | ID | Label | Shield Color CSS Variable | Priority Range | Default |
|---|---|---|---|---|---|
| Trusted | `trusted` | Trusted | `--color-safe` (green) | 200-299 | No |
| Standard | `standard` | Standard | `--color-info` (blue) | 300-399 | Yes |
| Cautious | `cautious` | Cautious | `--color-warning` (amber) | 400-499 | No |
| Restricted | `restricted` | Restricted | `--color-danger` (red) | 500-599 | No |

### 1.2 Trust Level Permission Matrix

| Permission Category | Trusted | Standard | Cautious | Restricted |
|---|---|---|---|---|
| MCP tool calls | Allow all | Allow known, prompt unknown | Prompt most | Block most, allow `list_*` only |
| Read files (project dir) | Allow | Allow | Allow | Prompt |
| Read files (outside project) | Allow | Prompt | Prompt | Block |
| Write files | Allow | Prompt | Block | Block |
| Shell execution | Prompt | Prompt | Block | Block |
| Network access | Allow | Prompt | Prompt | Block |
| Sensitive paths (~/.ssh, ~/.aws, ~/.env) | **Block always** | **Block always** | **Block always** | **Block always** |

### 1.3 Policy Rule Naming Convention

All trust-level-generated rules follow this pattern:

```
trust.{server_name}.{category}
```

Where:
- `server_name` is the MCP server name, sanitized (lowercase, spaces to hyphens, alphanumeric + hyphens only)
- `category` is one of: `tool-call`, `file-read-project`, `file-read-external`, `file-write`, `shell-exec`, `network-access`, `sensitive-paths`

Example for a server named `filesystem-server` at Standard trust:
```
trust.filesystem-server.tool-call
trust.filesystem-server.file-read-project
trust.filesystem-server.file-read-external
trust.filesystem-server.file-write
trust.filesystem-server.shell-exec
trust.filesystem-server.network-access
trust.filesystem-server.sensitive-paths
```

### 1.4 TOML Policy Rules per Trust Level

All trust rules use the `trust.*` namespace in the `[rules]` table. The existing `sanitize_rule_key()` function in `commands.rs` is compatible with this format (dots are stripped but we use hyphens instead). **Important**: We must extend `sanitize_rule_key` to preserve dots for namespaced keys, OR use a separate function for trust rules.

**Decision**: Use a new function `trust_rule_key(server_name, category)` that produces the key directly without sanitizing dots away.

#### Trusted Level

```toml
[rules."trust.filesystem-server.tool-call"]
description = "Trust level: allow all tool calls"
action = "allow"
priority = 200
enabled = true
[rules."trust.filesystem-server.tool-call".match]
server_name = ["filesystem-server"]
event_type = ["tools/call"]

[rules."trust.filesystem-server.file-read-project"]
description = "Trust level: allow reading files in project directory"
action = "allow"
priority = 201
enabled = true
[rules."trust.filesystem-server.file-read-project".match]
server_name = ["filesystem-server"]
resource_path = ["{project_dir}/**"]

[rules."trust.filesystem-server.file-read-external"]
description = "Trust level: allow reading files outside project"
action = "allow"
priority = 202
enabled = true
[rules."trust.filesystem-server.file-read-external".match]
server_name = ["filesystem-server"]
resource_path = ["**"]

[rules."trust.filesystem-server.file-write"]
description = "Trust level: allow writing files"
action = "allow"
priority = 203
enabled = true
[rules."trust.filesystem-server.file-write".match]
server_name = ["filesystem-server"]
event_type = ["file_write", "file_create"]

[rules."trust.filesystem-server.shell-exec"]
description = "Trust level: prompt before shell execution"
action = "prompt"
priority = 204
enabled = true
message = "This trusted tool wants to run a command. Allow?"
[rules."trust.filesystem-server.shell-exec".match]
server_name = ["filesystem-server"]
event_type = ["exec"]

[rules."trust.filesystem-server.network-access"]
description = "Trust level: allow network access"
action = "allow"
priority = 205
enabled = true
[rules."trust.filesystem-server.network-access".match]
server_name = ["filesystem-server"]
event_type = ["connect"]

[rules."trust.filesystem-server.sensitive-paths"]
description = "Block access to sensitive paths (always enforced)"
action = "block"
priority = 999
enabled = true
[rules."trust.filesystem-server.sensitive-paths".match]
server_name = ["filesystem-server"]
resource_path = ["**/.ssh/**", "**/.aws/credentials", "**/.env*", "**/.gnupg/**", "**/id_rsa", "**/id_ed25519"]
```

#### Standard Level (Default)

```toml
[rules."trust.filesystem-server.tool-call"]
description = "Trust level: allow known tools, prompt unknown"
action = "prompt"
priority = 300
enabled = true
message = "This tool wants to perform an action. Allow?"
[rules."trust.filesystem-server.tool-call".match]
server_name = ["filesystem-server"]
event_type = ["tools/call"]

[rules."trust.filesystem-server.file-read-project"]
description = "Trust level: allow reading files in project directory"
action = "allow"
priority = 301
enabled = true
[rules."trust.filesystem-server.file-read-project".match]
server_name = ["filesystem-server"]
resource_path = ["{project_dir}/**"]

[rules."trust.filesystem-server.file-read-external"]
description = "Trust level: prompt before reading files outside project"
action = "prompt"
priority = 302
enabled = true
message = "This tool wants to read a file outside your project. Allow?"
[rules."trust.filesystem-server.file-read-external".match]
server_name = ["filesystem-server"]
resource_path = ["**"]

[rules."trust.filesystem-server.file-write"]
description = "Trust level: prompt before writing files"
action = "prompt"
priority = 303
enabled = true
message = "This tool wants to write a file. Allow?"
[rules."trust.filesystem-server.file-write".match]
server_name = ["filesystem-server"]
event_type = ["file_write", "file_create"]

[rules."trust.filesystem-server.shell-exec"]
description = "Trust level: prompt before shell execution"
action = "prompt"
priority = 304
enabled = true
message = "This tool wants to run a command. Allow?"
[rules."trust.filesystem-server.shell-exec".match]
server_name = ["filesystem-server"]
event_type = ["exec"]

[rules."trust.filesystem-server.network-access"]
description = "Trust level: prompt before network access"
action = "prompt"
priority = 305
enabled = true
message = "This tool wants to access the network. Allow?"
[rules."trust.filesystem-server.network-access".match]
server_name = ["filesystem-server"]
event_type = ["connect"]

[rules."trust.filesystem-server.sensitive-paths"]
description = "Block access to sensitive paths (always enforced)"
action = "block"
priority = 999
enabled = true
[rules."trust.filesystem-server.sensitive-paths".match]
server_name = ["filesystem-server"]
resource_path = ["**/.ssh/**", "**/.aws/credentials", "**/.env*", "**/.gnupg/**", "**/id_rsa", "**/id_ed25519"]
```

#### Cautious Level

```toml
[rules."trust.filesystem-server.tool-call"]
description = "Trust level: prompt before most tool calls"
action = "prompt"
priority = 400
enabled = true
message = "This tool is trying to perform an action. Review carefully."
[rules."trust.filesystem-server.tool-call".match]
server_name = ["filesystem-server"]
event_type = ["tools/call"]

[rules."trust.filesystem-server.file-read-project"]
description = "Trust level: allow reading files in project directory"
action = "allow"
priority = 401
enabled = true
[rules."trust.filesystem-server.file-read-project".match]
server_name = ["filesystem-server"]
resource_path = ["{project_dir}/**"]

[rules."trust.filesystem-server.file-read-external"]
description = "Trust level: prompt before reading files outside project"
action = "prompt"
priority = 402
enabled = true
message = "This tool wants to read a file outside your project. It is in cautious mode."
[rules."trust.filesystem-server.file-read-external".match]
server_name = ["filesystem-server"]
resource_path = ["**"]

[rules."trust.filesystem-server.file-write"]
description = "Trust level: block file writes"
action = "block"
priority = 403
enabled = true
[rules."trust.filesystem-server.file-write".match]
server_name = ["filesystem-server"]
event_type = ["file_write", "file_create"]

[rules."trust.filesystem-server.shell-exec"]
description = "Trust level: block shell execution"
action = "block"
priority = 404
enabled = true
[rules."trust.filesystem-server.shell-exec".match]
server_name = ["filesystem-server"]
event_type = ["exec"]

[rules."trust.filesystem-server.network-access"]
description = "Trust level: prompt before network access"
action = "prompt"
priority = 405
enabled = true
message = "This cautious-mode tool wants to access the network. Allow?"
[rules."trust.filesystem-server.network-access".match]
server_name = ["filesystem-server"]
event_type = ["connect"]

[rules."trust.filesystem-server.sensitive-paths"]
description = "Block access to sensitive paths (always enforced)"
action = "block"
priority = 999
enabled = true
[rules."trust.filesystem-server.sensitive-paths".match]
server_name = ["filesystem-server"]
resource_path = ["**/.ssh/**", "**/.aws/credentials", "**/.env*", "**/.gnupg/**", "**/id_rsa", "**/id_ed25519"]
```

#### Restricted Level

```toml
[rules."trust.filesystem-server.tool-call"]
description = "Trust level: block most tool calls, allow list_* only"
action = "block"
priority = 500
enabled = true
[rules."trust.filesystem-server.tool-call".match]
server_name = ["filesystem-server"]
event_type = ["tools/call"]
# Note: A companion allow rule at priority 501 permits list_* tools only
# This is implemented via a second rule:

[rules."trust.filesystem-server.tool-call-list-only"]
description = "Trust level: allow list_* tools in restricted mode"
action = "allow"
priority = 501
enabled = true
[rules."trust.filesystem-server.tool-call-list-only".match]
server_name = ["filesystem-server"]
event_type = ["tools/call"]
tool_name = ["list_*"]

[rules."trust.filesystem-server.file-read-project"]
description = "Trust level: prompt before reading project files"
action = "prompt"
priority = 502
enabled = true
message = "This restricted tool wants to read a project file. Allow?"
[rules."trust.filesystem-server.file-read-project".match]
server_name = ["filesystem-server"]
resource_path = ["{project_dir}/**"]

[rules."trust.filesystem-server.file-read-external"]
description = "Trust level: block reading files outside project"
action = "block"
priority = 503
enabled = true
[rules."trust.filesystem-server.file-read-external".match]
server_name = ["filesystem-server"]
resource_path = ["**"]

[rules."trust.filesystem-server.file-write"]
description = "Trust level: block file writes"
action = "block"
priority = 504
enabled = true
[rules."trust.filesystem-server.file-write".match]
server_name = ["filesystem-server"]
event_type = ["file_write", "file_create"]

[rules."trust.filesystem-server.shell-exec"]
description = "Trust level: block shell execution"
action = "block"
priority = 505
enabled = true
[rules."trust.filesystem-server.shell-exec".match]
server_name = ["filesystem-server"]
event_type = ["exec"]

[rules."trust.filesystem-server.network-access"]
description = "Trust level: block network access"
action = "block"
priority = 506
enabled = true
[rules."trust.filesystem-server.network-access".match]
server_name = ["filesystem-server"]
event_type = ["connect"]

[rules."trust.filesystem-server.sensitive-paths"]
description = "Block access to sensitive paths (always enforced)"
action = "block"
priority = 999
enabled = true
[rules."trust.filesystem-server.sensitive-paths".match]
server_name = ["filesystem-server"]
resource_path = ["**/.ssh/**", "**/.aws/credentials", "**/.env*", "**/.gnupg/**", "**/id_rsa", "**/id_ed25519"]
```

### 1.5 Rule Precedence

Priority evaluation order (highest priority number wins):

1. **Priority 999**: Sensitive path blocks (always enforced, never overridable)
2. **Priority 900-998**: User's explicit global rules (manually created in Policy Editor)
3. **Priority 500-599**: Restricted trust rules
4. **Priority 400-499**: Cautious trust rules
5. **Priority 300-399**: Standard trust rules
6. **Priority 200-299**: Trusted trust rules
7. **Priority 100-199**: User's lower-priority custom rules
8. **Priority 0-99**: Default policy rules

**Key invariant**: Trust-level rules are generated with priorities in their level's range. A user can create a rule at priority 900+ to override any trust rule. The `sensitive-paths` rule is always priority 999 and cannot be overridden by trust levels.

### 1.6 Trust Level Inference from Existing Rules

To derive the current trust level for a server, scan all rules matching `trust.{server_name}.*`:

```typescript
function inferTrustLevel(serverName: string, rules: PolicyRule[]): { level: TrustLevel; customized: boolean } {
  const trustRules = rules.filter(r => r.name.startsWith(`trust.${serverName}.`));

  if (trustRules.length === 0) {
    return { level: 'standard', customized: false };  // No trust rules = default
  }

  // Check priority range of the first non-sensitive rule
  const mainRules = trustRules.filter(r => !r.name.endsWith('.sensitive-paths'));
  if (mainRules.length === 0) {
    return { level: 'standard', customized: false };
  }

  const avgPriority = mainRules.reduce((sum, r) => sum + r.priority, 0) / mainRules.length;

  let baseLevel: TrustLevel;
  if (avgPriority >= 500) baseLevel = 'restricted';
  else if (avgPriority >= 400) baseLevel = 'cautious';
  else if (avgPriority >= 300) baseLevel = 'standard';
  else baseLevel = 'trusted';

  // Check if rules match the canonical set for this level
  const canonical = generateTrustRules(serverName, baseLevel);
  const customized = !rulesMatchCanonical(mainRules, canonical);

  return { level: baseLevel, customized };
}
```

Display: If customized is true, show "Standard (customized)" with a small edit icon.

---

## 2. Permission Grid Data Model

### 2.1 Permission Categories

| # | Category | UI Label | Policy Resource/Match | Icon |
|---|---|---|---|---|
| 1 | `file_read_project` | Read files in project | `resource_path` with `{project_dir}/**` | `FolderOpen` |
| 2 | `file_read_external` | Read files elsewhere | `resource_path` with `**` (excluding project) | `FolderSearch` |
| 3 | `file_write` | Write files | `event_type` = `file_write`, `file_create` | `FilePen` |
| 4 | `shell_exec` | Run commands | `event_type` = `exec` | `Terminal` |
| 5 | `network_access` | Access the internet | `event_type` = `connect` | `Globe` |
| 6 | `sensitive_paths` | Read sensitive files | `resource_path` with sensitive globs | `ShieldX` |

### 2.2 Permission States

Each permission (except sensitive_paths) has three states:

| State | Icon | Label | CSS Color | Policy Action |
|---|---|---|---|---|
| Allowed | `CheckCircle` | Allowed | `--color-safe` | `allow` |
| Ask first | `HelpCircle` | Ask first | `--color-warning` | `prompt` |
| Blocked | `XCircle` | Blocked | `--color-danger` | `block` |

Sensitive paths is always Blocked and rendered as a locked row (non-interactive).

### 2.3 Permission State Type

```typescript
type PermissionState = 'allow' | 'prompt' | 'block';

interface PermissionGrid {
  file_read_project: PermissionState;
  file_read_external: PermissionState;
  file_write: PermissionState;
  shell_exec: PermissionState;
  network_access: PermissionState;
  sensitive_paths: 'block'; // Always block, never overridable
}
```

### 2.4 Trust Level to Permission Grid Mapping

```typescript
const TRUST_PERMISSION_DEFAULTS: Record<TrustLevel, PermissionGrid> = {
  trusted: {
    file_read_project: 'allow',
    file_read_external: 'allow',
    file_write: 'allow',
    shell_exec: 'prompt',
    network_access: 'allow',
    sensitive_paths: 'block',
  },
  standard: {
    file_read_project: 'allow',
    file_read_external: 'prompt',
    file_write: 'prompt',
    shell_exec: 'prompt',
    network_access: 'prompt',
    sensitive_paths: 'block',
  },
  cautious: {
    file_read_project: 'allow',
    file_read_external: 'prompt',
    file_write: 'block',
    shell_exec: 'block',
    network_access: 'prompt',
    sensitive_paths: 'block',
  },
  restricted: {
    file_read_project: 'prompt',
    file_read_external: 'block',
    file_write: 'block',
    shell_exec: 'block',
    network_access: 'block',
    sensitive_paths: 'block',
  },
};
```

### 2.5 Individual Permission Overrides

Users can override individual permissions for a server. When any permission differs from the trust level's canonical set:

1. The trust level badge shows "(customized)" suffix
2. The overridden permission row shows a small "reset" icon to revert to canonical
3. The underlying rule's action is updated directly in the TOML

**Implementation**: When user changes a single permission:
1. Find the rule `trust.{server}.{category}`
2. Update only that rule's `action` field
3. Mark `customized: true` in the trust level display

When user changes the trust level via the dropdown:
1. Delete all `trust.{server}.*` rules
2. Generate canonical rules for the new level
3. Write to policy file

---

## 3. ToolCardData — Composite Data Model

### 3.1 TypeScript Interface

```typescript
export type TrustLevel = 'trusted' | 'standard' | 'cautious' | 'restricted';

export type BehavioralStatusValue = 'normal' | 'learning' | 'anomalous';

export interface ToolCapability {
  name: string;           // e.g., "read_file", "write_file", "execute_command"
  category: string;       // "filesystem" | "network" | "execution" | "other"
  risk_level: string;     // "low" | "medium" | "high"
}

export interface HealthWarning {
  severity: 'info' | 'warning' | 'critical';
  message: string;        // Claw-voice message, e.g., "This tool has not been updated in 90 days"
  action?: string;        // Optional action label, e.g., "Update now"
  action_command?: string; // Tauri command to invoke if user clicks action
}

export interface ToolCardData {
  // Identity
  server_name: string;
  client_name: string;         // "claude" | "cursor" | "vscode" | "windsurf"
  client_display_name: string; // "Claude Desktop" | "Cursor" | ...
  is_wrapped: boolean;

  // Trust
  trust_level: TrustLevel;
  trust_customized: boolean;
  permissions: PermissionGrid;

  // Behavioral (from ServerProfileSummary)
  behavioral_status: BehavioralStatusValue;
  learning_progress: number;    // 0.0 to 1.0, derived from total_calls / learning_event_threshold
  event_count_today: number;
  blocked_count_today: number;
  last_unusual_activity: string | null; // ISO timestamp or null
  anomaly_score_current: number;        // 0.0 to 1.0, NOT shown as raw number to user

  // Capabilities (inferred from server tools)
  capabilities: ToolCapability[];

  // Health
  health_warnings: HealthWarning[];

  // Guard (from GuardSummary, if registered)
  guard_status: 'active' | 'disabled' | 'none';
  guard_triggers_count: number;

  // Scan (from most recent ScanResult matching this server)
  scan_findings_count: number;
  scan_critical_count: number;
  last_scan_time: string | null;
}
```

### 3.2 Data Sources and Assembly

Each field of `ToolCardData` is sourced from a different backend system. The assembler runs on the Rust side as a single Tauri command.

| Field Group | Source | Tauri Command | How |
|---|---|---|---|
| Identity | `detect_mcp_clients` + `list_mcp_servers` | Existing commands | Read server list from config files |
| Trust | Policy file scan | `get_policy` | Scan `trust.{server}.*` rules |
| Behavioral | `get_profiles` + `get_behavioral_status` | Existing commands | Match by `server_name` |
| Capabilities | MCP server introspection | **New**: `get_server_capabilities` | Parse server's `tools/list` response or infer from command name |
| Health | Multiple checks | **New**: assembler logic | Check wrap status, scan age, reputation |
| Guard | `list_guards` | Existing command | Match by server name |
| Scan | `get_scan_results` | Existing command | Filter by server name |
| Events today | Event buffer in AppState | In-memory | Filter `event_buffer` by server + today's date |

### 3.3 New Tauri Command: `get_tool_cards`

```rust
#[tauri::command]
pub async fn get_tool_cards(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<ToolCardData>, String>
```

This is the primary data source for the My Tools page. It:
1. Calls `detect_mcp_clients` and `list_mcp_servers` for each
2. Reads the policy file once and builds trust info per server
3. Fetches behavioral profiles
4. Fetches guard list
5. Scans event buffer for today's counts
6. Builds health warnings
7. Returns the composite `Vec<ToolCardData>`

**Performance**: This runs on every My Tools page load and on 30-second intervals. It should complete in <100ms since all data is in-memory or local filesystem reads.

### 3.4 New Tauri Command: `get_tool_detail`

```rust
#[tauri::command]
pub async fn get_tool_detail(
    state: tauri::State<'_, AppState>,
    server_name: String,
    client_name: String,
) -> Result<ToolDetailData, String>
```

Extended version of `ToolCardData` with additional fields for the detail page:

```typescript
export interface ToolDetailData extends ToolCardData {
  // Full command line
  command: string[];

  // Recent events (last 50)
  recent_events: AuditEvent[];

  // Behavioral detail
  tools_count: number;
  total_calls: number;
  last_activity: string;

  // Full scan results
  scan_results: ScanModuleResult[] | null;

  // Reputation check
  reputation: ReputationResult | null;

  // Network traffic summary
  network_traffic: ServerTrafficData | null;
}
```

### 3.5 Capability Inference

Since MCP servers don't always expose a manifest, infer capabilities from:

1. **Server name heuristics**: `filesystem-server` -> filesystem capability, `fetch` -> network capability
2. **Command inspection**: If command contains `npx`, `node` -> likely JS-based tool
3. **Behavioral profile**: Tools that have been observed making file_write calls -> has write capability
4. **Known server registry**: Built-in map of common MCP servers to their capabilities

```typescript
const KNOWN_SERVER_CAPABILITIES: Record<string, ToolCapability[]> = {
  'filesystem': [
    { name: 'read_file', category: 'filesystem', risk_level: 'low' },
    { name: 'write_file', category: 'filesystem', risk_level: 'medium' },
    { name: 'list_directory', category: 'filesystem', risk_level: 'low' },
  ],
  'fetch': [
    { name: 'fetch', category: 'network', risk_level: 'medium' },
  ],
  'brave-search': [
    { name: 'brave_web_search', category: 'network', risk_level: 'low' },
  ],
  // ... more known servers
};
```

### 3.6 Health Warning Generation

Health warnings are generated by checking multiple conditions:

```rust
fn generate_health_warnings(server: &McpServer, scan: Option<&ScanResult>, reputation: Option<&ReputationResult>) -> Vec<HealthWarning> {
    let mut warnings = Vec::new();

    // Not wrapped
    if !server.wrapped {
        warnings.push(HealthWarning {
            severity: "warning",
            message: "This tool is not protected by Claw yet",
            action: Some("Protect now"),
            action_command: Some("wrap_server"),
        });
    }

    // Critical scan findings
    if let Some(scan) = scan {
        if scan.critical_count > 0 {
            warnings.push(HealthWarning {
                severity: "critical",
                message: format!("{} critical issues found in last scan", scan.critical_count),
                action: Some("View details"),
                action_command: None,
            });
        }
    }

    // Reputation match
    if let Some(rep) = reputation {
        if !rep.clean {
            warnings.push(HealthWarning {
                severity: "critical",
                message: "This tool matches a known threat in the blocklist",
                action: Some("Review"),
                action_command: None,
            });
        }
    }

    // No scan ever run
    if scan.is_none() {
        warnings.push(HealthWarning {
            severity: "info",
            message: "This tool has not been scanned yet",
            action: Some("Scan now"),
            action_command: Some("start_scan"),
        });
    }

    warnings
}
```

---

## 4. New Tool Detection System

### 4.1 Detection Flow

```
App startup
    |
    v
detect_mcp_clients() + list_mcp_servers() for each
    |
    v
Compare against known_servers.json (~/.clawdefender/known_servers.json)
    |
    +-- New servers found? --> Add to "new tools" queue
    |                          Emit Tauri event "new-tool-detected"
    |                          Show Claw message in sidebar
    |
    +-- No new servers --> Silent, no action
    |
    v
Start 60-second polling loop (same logic)
```

### 4.2 known_servers.json Format

```json
{
  "version": 1,
  "servers": {
    "filesystem-server": {
      "first_seen": "2026-02-25T10:00:00Z",
      "client": "claude",
      "trust_level": "standard",
      "acknowledged": true
    },
    "fetch": {
      "first_seen": "2026-02-25T10:00:00Z",
      "client": "cursor",
      "trust_level": "standard",
      "acknowledged": true
    }
  }
}
```

### 4.3 New Tauri Commands

```rust
#[tauri::command]
pub async fn get_new_tools() -> Result<Vec<NewToolInfo>, String>

#[tauri::command]
pub async fn acknowledge_new_tool(
    server_name: String,
    trust_level: String,
) -> Result<(), String>

#[tauri::command]
pub async fn dismiss_new_tool(
    server_name: String,
) -> Result<(), String>
```

### 4.4 NewToolInfo Type

```typescript
export interface NewToolInfo {
  server_name: string;
  client_name: string;
  client_display_name: string;
  first_seen: string;
  command: string[];
  suggested_trust_level: TrustLevel; // Based on capability inference
}
```

### 4.5 Tauri Events

```typescript
// Emitted when a new MCP server is detected that is not in known_servers.json
{ type: "new-tool-detected", payload: NewToolInfo }
```

The frontend listens for this event and:
1. Shows a toast: "New tool detected: {server_name}"
2. Adds a notification badge to the My Tools nav icon
3. Shows the new tool card with a "New" badge and trust level selector

### 4.6 Suggested Trust Level

For new tools, suggest a trust level based on:

| Signal | Suggested Level |
|---|---|
| Known safe server (in built-in registry) | Standard |
| Unknown server, has network capabilities | Cautious |
| Unknown server, filesystem only | Standard |
| Unknown server, has shell capabilities | Cautious |
| Reputation match found | Restricted |
| No information available | Standard |

---

## 5. Trust Level Backend Commands

### 5.1 New Tauri Commands for Trust Management

```rust
#[tauri::command]
pub async fn set_trust_level(
    state: tauri::State<'_, AppState>,
    server_name: String,
    trust_level: String,
) -> Result<(), String>
// Deletes all trust.{server}.* rules, generates canonical rules for the new level, writes to policy file

#[tauri::command]
pub async fn get_trust_level(
    server_name: String,
) -> Result<TrustLevelInfo, String>
// Reads policy file, infers trust level from existing rules

#[tauri::command]
pub async fn set_permission_override(
    state: tauri::State<'_, AppState>,
    server_name: String,
    permission: String,  // category name like "file_write"
    action: String,      // "allow" | "prompt" | "block"
) -> Result<(), String>
// Updates a single trust.{server}.{permission} rule's action

#[tauri::command]
pub async fn reset_permission_override(
    state: tauri::State<'_, AppState>,
    server_name: String,
    permission: String,
) -> Result<(), String>
// Resets a single permission back to the canonical value for the current trust level
```

### 5.2 TrustLevelInfo Type

```typescript
export interface TrustLevelInfo {
  level: TrustLevel;
  customized: boolean;
  permissions: PermissionGrid;
  rule_count: number;
}
```

---

## 6. Frontend Data Flow

### 6.1 Stores

**New store**: `src/stores/toolStore.ts`

```typescript
interface ToolStore {
  tools: ToolCardData[];
  newTools: NewToolInfo[];
  selectedTool: string | null; // server_name
  loading: boolean;
  error: string | null;

  fetchTools: () => Promise<void>;
  fetchNewTools: () => Promise<void>;
  setTrustLevel: (serverName: string, level: TrustLevel) => Promise<void>;
  setPermission: (serverName: string, permission: string, action: PermissionState) => Promise<void>;
  resetPermission: (serverName: string, permission: string) => Promise<void>;
  acknowledgeNewTool: (serverName: string, trustLevel: TrustLevel) => Promise<void>;
  dismissNewTool: (serverName: string) => Promise<void>;
}
```

### 6.2 Polling Strategy

- My Tools page visible: Poll `get_tool_cards` every 30 seconds
- Tool Detail page visible: Poll `get_tool_detail` every 10 seconds
- Background (any page): Poll `get_new_tools` every 60 seconds (for badge notifications)

### 6.3 Page Routes

| Route | Component | Data Source |
|---|---|---|
| `/tools` | `MyTools.tsx` | `get_tool_cards` |
| `/tools/:serverName` | `ToolDetail.tsx` | `get_tool_detail` |

---

## 7. Behavioral Summary Transformation

The existing `ServerProfileSummary` exposes raw numbers (anomaly_score, total_calls). Per the design system's cardinal rule, users never see raw scores. The transformation:

| Raw Data | User-Facing Display |
|---|---|
| `anomaly_score >= 0.7` | Badge: "Unusual activity" (warning color) |
| `anomaly_score >= 0.9` | Badge: "Suspicious" (danger color) |
| `anomaly_score < 0.4` | Badge: "Normal" (safe color) |
| `status = "learning"` | "Still getting to know this tool" + progress bar |
| `total_calls` | "847 actions today" (friendly format) |
| `tools_count` | "{n} capabilities" |

The `learning_progress` field is derived:
```typescript
const learningProgress = Math.min(1.0, profile.total_calls / LEARNING_EVENT_THRESHOLD);
// where LEARNING_EVENT_THRESHOLD = 100 (from BehavioralConfig default)
```

---

## 8. Compatibility Notes

### 8.1 Policy File Compatibility

Trust rules use the same `[rules]` table as existing rules. The `trust.*` prefix is a namespace convention only. Existing policy commands (`get_policy`, `add_rule`, `update_rule`, `delete_rule`) continue to work normally and can see/modify trust rules.

### 8.2 sanitize_rule_key Changes

The existing `sanitize_rule_key` strips dots. Trust rules use dots for namespacing. Two options:

**Option A (Recommended)**: Add a new function `trust_rule_key` that does NOT strip dots:
```rust
fn trust_rule_key(server_name: &str, category: &str) -> String {
    let sanitized_server = server_name.trim().to_lowercase()
        .replace(' ', "-")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect::<String>();
    format!("trust.{}.{}", sanitized_server, category)
}
```

**Option B**: Use hyphens instead of dots: `trust--filesystem-server--file-read-project`. Less readable.

Go with **Option A**. The TOML key `"trust.filesystem-server.file-read-project"` is valid when quoted.

### 8.3 Existing Policy Rules Not Affected

Trust rules are added alongside existing rules. The existing default rules (`block-sensitive-files`, `prompt-write-operations`, `audit-network-access`) remain untouched. Trust rules have higher priority (200-599) than defaults (0-99) but lower than user globals (900+).

### 8.4 Guard Integration

The existing `GuardRegistry` uses `PermissionSet` with file_read/file_write/network_allowlist. Trust levels map cleanly:

| Trust Level | Guard Equivalent |
|---|---|
| Trusted | file_read: `["**"]`, file_write: `["**"]`, shell_policy: `"prompt"`, network: `["*"]` |
| Standard | file_read: `["{project}/**"]`, file_write: `["{project}/**"]`, shell_policy: `"deny"`, network: `[]` |
| Cautious | file_read: `["{project}/**"]`, file_write: `[]`, shell_policy: `"deny"`, network: `[]` |
| Restricted | file_read: `[]`, file_write: `[]`, shell_policy: `"deny"`, network: `[]` |

Guard registration happens at daemon level, not in the Tauri app directly. Trust level changes trigger policy reload, which the daemon picks up.
