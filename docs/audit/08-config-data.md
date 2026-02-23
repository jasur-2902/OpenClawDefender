# ClawDefender Audit Report: Settings, Configuration & Data Storage

## Section 13: Settings & Configuration

### 13.1 Settings UI Overview (Settings.tsx)

The Settings page (`clients/clawdefender-app/src/pages/Settings.tsx`) is organized into five sections:

| Section | Settings | Config Key | Tauri Command | Persists? | Daemon Reads? |
|---------|----------|------------|---------------|-----------|---------------|
| **General** | Theme | `[ui].theme` | `update_settings` | Yes, to `config.toml` | Yes (UiConfig) |
| | Start at Login | `[ui].auto_start_daemon` | `enable_autostart` / `disable_autostart` + `update_settings` | Yes, to config.toml + LaunchAgent | Yes (autostart plugin) |
| | Show in Menu Bar | `[ui].minimize_to_tray` | `update_settings` | Yes, to `config.toml` | UI-only |
| **Protection** | Security Level | policy.toml rules | `apply_template` | Yes, writes `policy.toml` | Yes (policy engine reloads) |
| | Notifications | `[ui].notifications` | `update_settings` | Yes, to `config.toml` | Yes (UiConfig) |
| | Prompt Timeout | `[network_policy].prompt_timeout_seconds` | `update_settings` | Yes, to `config.toml` | Yes (NetworkPolicyConfig) |
| **AI Model** | Active Model | Runtime state | `activate_model` / `deactivate_model` | No (runtime only) | Yes (SLM engine) |
| | Download Model | Disk files | `download_model` / `cancel_download` | Yes (model .gguf files) | Yes |
| | Custom Model Path | Runtime | `activate_model` with path | No | Yes |
| | Cloud API Key | macOS Keychain | `save_api_key` / `clear_api_key` | Yes (Keychain) | Yes |
| | Cloud Provider/Model | Runtime state | `activate_cloud_provider` | No | Yes |
| | Analysis Frequency | React state only | None | **NO** | **NO** |
| **Network Protection** | Enable Network Filtering | `[network_policy].enabled` | `update_network_settings` | Yes, to `config.toml` | Yes |
| | Enable DNS Filtering | `[network_policy].dns_enabled` | `update_network_settings` | Yes | Yes |
| | Filter All Processes | `[network_policy].filter_all_processes` | `update_network_settings` | Yes | Yes |
| | Default Action | `[network_policy].default_agent_action` | `update_network_settings` | Yes | Yes |
| | Network Prompt Timeout | `[network_policy].prompt_timeout_seconds` | `update_network_settings` | Yes | Yes |
| | Block Private Ranges | `[network_policy].block_private_ranges` | `update_network_settings` | Yes | Yes |
| | Block DNS-over-HTTPS | `[network_policy].block_doh` | `update_network_settings` | Yes | Yes |
| | Log All DNS Queries | `[network_policy].log_all_dns` | `update_network_settings` | Yes | Yes |
| **Advanced** | Log Level | `[ui].log_level` | `update_settings` | Yes, to `config.toml` | Partially (env var `CLAWDEFENDER_LOG` in plist takes precedence) |
| | Event Retention | `[ui].event_retention_days` | `update_settings` | Yes, to `config.toml` | Logger uses `RETENTION_DAYS` constant (30), does NOT read this |
| | Export Config | N/A | `export_settings` | Writes to Desktop | N/A |
| | Import Config | N/A | `import_settings_from_content` | Yes, overwrites config.toml/policy.toml | Yes (on next load) |
| | Reset to Defaults | N/A | `update_settings` with defaults | Yes | Yes |

### 13.2 Settings Persistence Flow

1. **UI changes** -> `invoke("update_settings", { settings })` or `invoke("update_network_settings", { settings })`
2. **Tauri command** reads existing `~/.config/clawdefender/config.toml`, merges changes into the TOML table, writes back
3. **Daemon** loads config at startup via `ClawConfig::load()`. Config changes do NOT trigger a live reload in the daemon -- the Tauri app notes "config reload will take effect on next query" but there is no actual reload mechanism beyond `try_reload_daemon` which sends a reload command over IPC for policy changes only.

### 13.3 Settings Issues Found

| ID | Issue | Severity | Detail |
|----|-------|----------|--------|
| S13-1 | **Analysis Frequency not persisted** | Medium | The "Analysis Frequency" dropdown (`analysisFrequency` state) is only stored in React state. Changing it calls no Tauri command and does not write to config.toml. It resets to "all" on page reload. |
| S13-2 | **Event Retention setting not enforced** | Medium | `event_retention_days` is written to `[ui].event_retention_days` in config.toml, but the `FileAuditLogger` uses a hardcoded `RETENTION_DAYS = 30` constant and never reads the config value. |
| S13-3 | **Log Level not live-reloaded** | Low | Changing log level in the UI writes to config.toml, but the daemon's log level is set at startup from the `CLAWDEFENDER_LOG` env var in the LaunchAgent plist. The UI setting has no effect on a running daemon. |
| S13-4 | **Security Level not loaded from config** | Medium | `securityLevel` state defaults to "balanced" on mount but never reads the current policy template from policy.toml. The dropdown always starts at "balanced" regardless of actual policy. |
| S13-5 | **Active model not persisted across restarts** | Low | Model activation is runtime-only state. After daemon restart, no model is active until re-activated. The `slm.model_path` config key could persist this but is not written by `activate_model`. |
| S13-6 | **Config changes don't trigger daemon reload** | Medium | The `update_settings` command checks if daemon is connected and logs "config reload will take effect on next query" but performs no actual reload. Only `apply_template` calls `try_reload_daemon`. |
| S13-7 | **Export writes to hardcoded path** | Low | `export_settings` always writes to `~/Desktop/clawdefender-settings.json` with no user choice of destination. |
| S13-8 | **Updater pubkey is empty** | High | `tauri.conf.json` has `"pubkey": ""` in the updater plugin config. This means update signature verification is disabled, allowing unsigned updates. |

---

## Section 16: Configuration Files

### 16.1 Core Configuration: `~/.config/clawdefender/config.toml`

- **Format**: TOML
- **Created by**: Tauri `update_settings` / `update_network_settings` commands (auto-creates parent dirs)
- **Read by**: Daemon at startup (`ClawConfig::load()`), Tauri app (`get_settings`, `get_network_settings`)
- **Written by**: Tauri app settings UI
- **Auto-created**: No (defaults used if missing)
- **Sections**: `[ui]`, `[network_policy]`, `[slm]`, `[api_keys]`, `[swarm]`, `[eslogger]`, `[behavioral]`, `[injection_detector]`, `[guard_api]`, `[threat_intel]`, `[mcp_server]`, `[log_rotation]`

**Key defaults** (from `ClawConfig::default()`):

| Setting | Default |
|---------|---------|
| `daemon_socket_path` | `~/.local/share/clawdefender/clawdefender.sock` |
| `audit_log_path` | `~/.local/share/clawdefender/audit.jsonl` |
| `policy_path` | `~/.config/clawdefender/policy.toml` |
| `sensor_config_path` | `~/.config/clawdefender/sensor.toml` |
| `log_rotation.max_size_mb` | 50 |
| `log_rotation.max_files` | 10 |
| `slm.context_size` | 2048 |
| `slm.temperature` | 0.1 |
| `slm.use_gpu` | true |
| `swarm.daily_budget_usd` | 1.00 |
| `swarm.monthly_budget_usd` | 20.00 |
| `swarm.chat_port` | 3200 |
| `guard_api.port` | 3202 |
| `mcp_server.http_port` | 3201 |
| `threat_intel.feed_url` | `https://feed.clawdefender.io/v1/` |
| `threat_intel.update_interval_hours` | 6 |
| `behavioral.learning_event_threshold` | 100 |
| `behavioral.anomaly_threshold` | 0.7 |
| `injection_detector.threshold` | 0.6 |

### 16.2 Policy Configuration: `~/.config/clawdefender/policy.toml`

- **Format**: TOML
- **Created by**: `apply_template` Tauri command, or manual copy from `policies/templates/`
- **Read by**: MCP proxy (`--policy` flag, default `~/.config/clawdefender/policy.toml`), daemon policy engine
- **Written by**: Tauri `apply_template`, `import_settings_from_content`
- **Structure**: `[metadata]` + `[rules.<name>]` with fields: `description`, `action` (allow/block/prompt/log), `message`, `priority`, `[rules.<name>.match]` with `resource_path`, `tool_name`, `method`, `any`

**Shipped policy files**:

| File | Purpose |
|------|---------|
| `policies/default.toml` | Default policy: blocks credentials, prompts shell/network, allows project reads |
| `policies/injection_patterns.toml` | 18 regex patterns for prompt injection detection (severity 0.4-0.8) |
| `policies/killchain_patterns.toml` | 6 multi-step kill chain detection patterns (credential theft, persistence, data staging, shell escape, injection followthrough) |
| `policies/templates/strict.toml` | Maximum security: blocks shell, network, sampling; prompts everything else |
| `policies/templates/development.toml` | Balanced: blocks credentials, allows project reads, prompts shell/network |
| `policies/templates/audit-only.toml` | Logs everything, blocks nothing |
| `policies/templates/data-science.toml` | Allows Jupyter/pip/workspace, prompts network/shell |

### 16.3 Sensor Configuration: `~/.config/clawdefender/sensor.toml`

- **Format**: TOML
- **Created by**: Not auto-created; uses defaults if absent
- **Read by**: Daemon at startup (`SensorConfig::load()`)
- **Sections**: `[eslogger]`, `[fsevents]`, `[correlation]`, `[process_tree]`
- **Key defaults**: eslogger events = `["exec", "open", "close", "rename", "unlink", "connect", "fork", "exit"]`, correlation window = 500ms, process tree refresh = 5s

### 16.4 Noise Filter Configuration: `~/.config/clawdefender/noise.toml`

- **Format**: TOML
- **Created by**: Not auto-created
- **Read by**: `NoiseFilter` in clawdefender-slm at runtime
- **Purpose**: Custom rules to suppress noisy/irrelevant events from SLM analysis

### 16.5 Tauri Application Config: `tauri.conf.json`

- **Location**: `clients/clawdefender-app/src-tauri/tauri.conf.json`
- **Format**: JSON
- **Key values**: productName="ClawDefender", version="0.3.0", identifier="com.clawdefender.desktop"
- **CSP**: `default-src 'self'; connect-src 'self' http://localhost:* https://localhost:*; img-src 'self' asset: https://asset.localhost; style-src 'self' 'unsafe-inline'`
- **Bundle targets**: DMG and app for macOS, minimum system version 13.0
- **Updater**: Endpoint at GitHub releases, **pubkey is empty** (signatures not enforced)

### 16.6 Tauri Capabilities: `capabilities/default.json`

- **Permissions granted**: `core:default`, `shell:allow-open`, `shell:allow-execute`, `notification:default`, `notification:allow-*`, `process:default`, `updater:default`, `autostart:allow-*`
- **Note**: `shell:allow-execute` is a broad permission that allows the Tauri app to execute arbitrary shell commands

### 16.7 Build/Tooling Configuration Files

| File | Format | Purpose |
|------|--------|---------|
| `Cargo.toml` | TOML | Workspace-level Rust build config |
| `deny.toml` | TOML | cargo-deny config: vulnerability=deny, copyleft=deny, unknown-registry=deny |
| `rust-toolchain.toml` | TOML | Rust stable channel with rustfmt and clippy |
| `.cargo/config.toml` | TOML | Cargo build settings |
| `com.clawdefender.daemon.plist` | XML plist | macOS LaunchAgent for daemon autostart |

### 16.8 Static Data Files

| File | Format | Purpose |
|------|--------|---------|
| `certified-servers.json` | JSON | Registry of certified MCP servers (3 entries: ClawDefender, Python example, TypeScript example) |

---

## Section 17: Data Files & Storage

### 17.1 Data Directory Layout

All runtime data lives under `~/.local/share/clawdefender/`:

```
~/.local/share/clawdefender/
  audit.jsonl              # JSON Lines audit log
  audit.jsonl.1 ... .10    # Rotated audit logs
  clawdefender.sock        # Unix domain socket for daemon-UI IPC
  clawdefender.pid         # Daemon PID file
  server-token             # Auth token for MCP server HTTP API
  profiles.db              # SQLite database for behavioral profiles
  swarm_usage.db           # SQLite database for cloud swarm usage tracking
  chat.db                  # SQLite database for chat history
  models/                  # Downloaded GGUF model files
    *.gguf
  threat-intel/            # Downloaded threat intelligence data
    ioc/                   # Indicators of Compromise
    rules/                 # Rule packs
      installed-packs.json # Catalog of installed rule packs
```

### 17.2 Audit Log (`audit.jsonl`)

- **Format**: JSON Lines (one JSON object per line)
- **Location**: `~/.local/share/clawdefender/audit.jsonl` (configurable via `config.toml`)
- **Written by**: `FileAuditLogger` (channel-based async writer thread), MCP proxy `FileAuditLogger`
- **Read by**: Tauri app event viewer, audit query engine (`AuditQueryEngine`)
- **Rotation**: When file exceeds `max_size_mb` (default 50MB), rotated to `.1`, `.2`, etc., up to `max_files` (default 10)
- **Retention**: Hardcoded 30 days for rotated files (does NOT respect `event_retention_days` from settings)
- **Flush**: Every 100 records or every 1 second, whichever comes first

**AuditRecord fields**:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | DateTime<Utc> | When the event occurred |
| `source` | String | Origin: "mcp-proxy", "eslogger", "fsevents", "correlation" |
| `event_summary` | String | One-line human-readable summary |
| `event_details` | JSON Value | Full structured event data |
| `rule_matched` | Option<String> | Policy rule name that matched |
| `action_taken` | String | "allow", "block", "prompt", "log" |
| `response_time_ms` | Option<u64> | Policy decision latency |
| `session_id` | Option<String> | Session UUID |
| `direction` | Option<String> | "client_to_server" or "server_to_client" |
| `server_name` | Option<String> | MCP server name |
| `client_name` | Option<String> | MCP client name |
| `method` | Option<String> | JSON-RPC method name |

### 17.3 Behavioral Profiles Database (`profiles.db`)

- **Format**: SQLite
- **Location**: `~/.local/share/clawdefender/profiles.db`
- **Created by**: `ProfileStore::open()` (auto-creates dir and schema)
- **Read by**: Behavioral baseline engine in daemon
- **Written by**: Behavioral baseline engine (upsert on profile update)
- **Schema**:
  ```sql
  CREATE TABLE IF NOT EXISTS profiles (
      server_name TEXT PRIMARY KEY,
      profile_json TEXT NOT NULL,
      updated_at TEXT NOT NULL
  );
  ```
- **Profile JSON contains**: server_name, client_name, observation_count, learning_mode, tool_profile (tool usage counts), file_profile (directory prefixes), network_profile (hosts, has_networked), last_updated
- **Operations**: save/load/delete/export/import/reset

### 17.4 Swarm Usage Database (`swarm_usage.db`)

- **Format**: SQLite
- **Location**: `~/.local/share/clawdefender/swarm_usage.db`
- **Created by**: Daemon at startup (`create_dir_all` + open)
- **Purpose**: Track cloud API usage and costs for budget enforcement

### 17.5 Chat Database (`chat.db`)

- **Format**: SQLite
- **Location**: `~/.local/share/clawdefender/chat.db`
- **Created by**: Daemon at startup
- **Purpose**: Persist chat history for the security chat feature

### 17.6 AI Model Files

- **Location**: `~/.local/share/clawdefender/models/`
- **Format**: GGUF (quantized language model files)
- **Created by**: `ModelManager::ensure_dir()` creates the directory; `download_model` downloads files
- **Managed by**: `ModelManager` (list_installed, model_path, is_installed, download with SHA-256 verification)
- **Typical sizes**: 500MB - 4GB per model

### 17.7 Server Auth Token

- **Location**: `~/.local/share/clawdefender/server-token`
- **Format**: Plain text token
- **Created by**: MCP server at startup
- **Read by**: HTTP clients authenticating to the MCP server, Guard API clients
- **Used for**: Bearer token authentication for the HTTP API

### 17.8 Daemon PID File

- **Location**: `~/.local/share/clawdefender/clawdefender.pid`
- **Format**: Plain text (PID number)
- **Created by**: Daemon at startup
- **Read by**: CLI tools and GUI to detect running daemon

### 17.9 Cloud API Keys

- **Storage**: macOS Keychain (via `security` CLI tool)
- **Service name**: ClawDefender-specific keychain service
- **Operations**: `store_api_key` (add-generic-password), `delete_api_key` (delete-generic-password), `has_api_key`/`get_api_key` (find-generic-password)
- **Security**: Provider names validated against known provider list before keychain operations

### 17.10 Threat Intelligence Feed Data

**Source repository**: `threat-feed/` directory, published to `https://feed.clawdefender.io/v1/`

**Runtime cache location**: `~/.local/share/clawdefender/threat-intel/`

**Feed structure** (v1):

| Directory | Files | Purpose |
|-----------|-------|---------|
| Root | `manifest.json` | Feed manifest with SHA-256 checksums and sizes for all files |
| Root | `blocklist.json` | Known malicious/vulnerable MCP servers (12 entries: 4 malicious, 4 vulnerable, 4 compromised versions) |
| `rules/` | `index.json` + 5 rule pack files | Security rules: credential-protection, network-security, persistence-prevention, privacy-protection, filesystem-server-hardened |
| `patterns/` | `index.json` + 2 files | Kill chain patterns and injection signatures |
| `iocs/` | `index.json` + 3 files | Indicators of Compromise: malicious hosts, malicious hashes, suspicious tools |
| `profiles/` | `index.json` + 5 files | Behavioral profiles for known servers: filesystem, fetch, git, sqlite, brave-search |
| `signatures/` | `latest.sig` | Digital signature for feed verification |

**Feed update mechanism**:
- `FeedClient` polls `feed_url` every `update_interval_hours` (default 6h)
- Downloads are verified against manifest SHA-256 checksums
- `FeedCache` manages local storage in `~/.local/share/clawdefender/threat-intel/`
- Auto-apply settings control whether rules/blocklist/patterns/IoCs are applied automatically

**Feed tools** (in `threat-feed/tools/`):
- `publish-feed.sh`: Publishes feed to distribution endpoint
- `sign-feed.py`: Signs feed with digital signature
- `validate-feed.py`: Validates feed integrity

### 17.11 Daemon Logs

- **Location**: `/usr/local/var/log/clawdefender/daemon.stdout.log` and `daemon.stderr.log`
- **Configured by**: LaunchAgent plist (`com.clawdefender.daemon.plist`)
- **Log level**: Set by `CLAWDEFENDER_LOG` env var (default "info" in plist)

### 17.12 Honeypot Files

- **Location**: `~/.config/clawdefender/honeypot/ssh/`, `~/.config/clawdefender/honeypot/aws/`, `~/.config/clawdefender/honeypot/env`
- **Purpose**: Decoy credential files to detect and trigger alerts when AI agents attempt credential access
- **Referenced by**: Kill chain patterns and anomaly scorer in behavioral engine

### 17.13 Rule Pack Catalog

- **Location**: `~/.local/share/clawdefender/threat-intel/rules/installed-packs.json`
- **Format**: JSON
- **Created by**: `RuleCatalog::new()` (auto-creates)
- **Purpose**: Tracks which rule packs are installed and their versions

### 17.14 Data Integrity Summary

| Data Store | Integrity Mechanism |
|-----------|-------------------|
| Audit log | Channel-based async writes, buffered I/O, rotation, retention cleanup |
| Profiles DB | SQLite ACID transactions, schema auto-migration |
| Model files | SHA-256 verification on download |
| Threat feed | Manifest SHA-256 checksums, digital signatures (`latest.sig`) |
| API keys | macOS Keychain (OS-level encryption), provider validation |
| Config files | TOML parsing with defaults fallback, existing section preservation on write |

### 17.15 Data Storage Issues Found

| ID | Issue | Severity | Detail |
|----|-------|----------|--------|
| D17-1 | **No config file validation on import** | Medium | `import_settings_from_content` validates JSON structure and version, but the TOML config/policy content is written directly without validating it parses as valid TOML or has safe values. |
| D17-2 | **Server token stored as plain text** | Medium | `~/.local/share/clawdefender/server-token` is a plain text file. File permissions should be checked (should be 0600). |
| D17-3 | **No encryption at rest for profiles.db** | Low | Behavioral profile data (server activity patterns) is stored in unencrypted SQLite. |
| D17-4 | **PID file not cleaned on crash** | Low | If daemon crashes, stale PID file remains. No lock-file or flock mechanism. |
| D17-5 | **Updater pubkey empty** | High | The Tauri updater has an empty public key, meaning update signatures are not verified. This is a supply chain risk. |
| D17-6 | **Hardcoded retention vs configurable** | Medium | Logger `RETENTION_DAYS` is hardcoded to 30, ignoring the user's `event_retention_days` setting. |
