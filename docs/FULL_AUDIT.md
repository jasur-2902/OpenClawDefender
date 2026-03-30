# ClawDefender — Full System Audit

**Date:** 2026-03-29
**Branch:** `production`
**Version:** 0.5.0-beta
**Auditors:** 7-agent forensic team (read-only)
**Methodology:** Every .rs, .tsx, .ts file read and traced. No modifications made.

---

## Executive Summary

| Metric | Value |
|--------|------:|
| Workspace members | 16 + 1 excluded Tauri crate |
| Total Rust source files | 313 |
| Total Rust lines | 119,840 |
| Total TS/TSX files | ~116 (app) + SDKs |
| Total TS/TSX lines | 33,738 |
| Combined LOC | ~159,000 |
| Tauri `#[command]` functions | ~107 |
| Commands fully working | ~95 (92%) |
| Commands partial | 5 |
| Commands stubbed | 4 |
| Commands broken | 0 |
| GUI pages (active) | 13 |
| GUI pages fully functional | 13 (100%) |
| Non-functional UI elements | 1 (intentional "Coming Soon") |
| Rust `#[test]` functions | 2,195 across 155 files |
| Frontend test files | 14 |
| Fuzz targets | 3 |
| `todo!()`/`unimplemented!()` in prod | 0 |
| `// TODO` comments | 3 (minor) |
| `// HACK`/`STUB`/`FAKE` markers | 0 |
| Git commits | 16 (Feb 16-23 2026) |
| Overall completion | ~92% |

---

## 1. Project Structure & Architecture

### 1.1 Workspace Members

| # | Crate | LOC | Purpose |
|---|-------|----:|---------|
| 1 | clawdefender-core | 20,568 | Policy engine, audit logger, behavioral engine, config, events, DNS, network policy, correlation, IPC protocol |
| 2 | clawdefender-scanner | 8,711 | Vulnerability scanner (dependency audit, capability escalation, fuzzing, exfiltration, prompt injection, path traversal) |
| 3 | clawdefender-threat-intel | 7,304 | Feed client, Ed25519 verification, IoC engine, blocklist, community rules, telemetry |
| 4 | clawdefender-guard | 7,302 | Agent self-protection API, registry, REST API, fallback engine, self-test |
| 5 | clawdefender-slm | 6,552 | GGUF backend (llama.cpp), cloud backend, model registry, downloader, analyzer, sanitizer |
| 6 | clawdefender-sensor | 6,041 | eslogger (macOS), process tree, FSEvents, MCP-to-OS correlation engine |
| 7 | clawdefender-daemon | 5,759 | Background daemon, Unix socket IPC, event router, guard management |
| 8 | clawdefender-swarm | 5,017 | Cloud LLM orchestration, chat, cost tracking, keychain, data minimization |
| 9 | clawdefender-mcp-proxy | 4,967 | Stdio/HTTP MCP proxy, JSON-RPC parser, classifier, policy enforcement |
| 10 | clawdefender-mcp-server | 3,887 | MCP server for agent intent declaration |
| 11 | clawdefender-certify | 1,837 | Claw Compliant certification harness |
| 12 | clawdefender-tui | 1,369 | Terminal UI for daemon prompts |
| — | **Subtotal (crates/)** | **79,314** | |
| 13 | clawdefender-cli | 6,190 | CLI binary with 20+ subcommands |
| 14 | clawdefender-app (Tauri) | 33,509 | Desktop app Rust backend (71 .rs files) |
| 15 | mock-mcp-server | 264 | Test mock |
| 16 | mock-eslogger | 309 | Test mock |
| — | **Total Rust** | **119,840** | |

**Excluded from workspace:** `clients/clawdefender-app/src-tauri` (standalone Tauri crate)

### 1.2 Frontend

| Area | LOC |
|------|----:|
| Pages | 10,468 |
| Components | 10,997 |
| Tests | 3,798 |
| Utils | 1,009 |
| Stores | 886 |
| Constants | 755 |
| Hooks | 250 |
| Services | 184 |
| **Frontend total** | **~29,300** |

### 1.3 Inter-Crate Dependency Graph

```
clawdefender-core  (foundation — no internal deps)
    ├── clawdefender-slm           (depends on core)
    ├── clawdefender-swarm         (depends on core)
    ├── clawdefender-guard         (depends on core)
    ├── clawdefender-mcp-server    (depends on core)
    ├── clawdefender-scanner       (depends on core)
    ├── clawdefender-certify       (depends on core)
    ├── clawdefender-tui           (depends on core, swarm)
    ├── clawdefender-threat-intel  (standalone)
    ├── clawdefender-mcp-proxy     (depends on core, slm, swarm, threat-intel)
    ├── clawdefender-sensor        (depends on core, daemon)
    ├── clawdefender-daemon        (depends on core, mcp-proxy, sensor, slm[gguf], swarm, tui)
    └── clawdefender-cli           (depends on core, mcp-proxy, slm[gguf], swarm, mcp-server, certify, scanner)
```

### 1.4 SDKs & Extensions

| Component | LOC | Language |
|-----------|----:|---------|
| TypeScript SDK | 2,042 | TS |
| TypeScript Agent SDK | 1,731 | TS |
| Python SDK | 1,767 | Python |
| Python Agent SDK | 2,128 | Python |
| macOS Network Extension | 1,459 | Swift |

### 1.5 File Tree (Top-Level)

```
/Users/jasur/workspace/clawai/
├── Cargo.toml, Cargo.lock, justfile, deny.toml, rust-toolchain.toml
├── README.md, CONTRIBUTING.md, SECURITY.md, LICENSE-APACHE, LICENSE-MIT
├── certified-servers.json, com.clawdefender.daemon.plist
├── .github/workflows/ (ci.yml, build-app.yml, release.yml, security-audit.yml)
├── crates/ (12 Rust crates)
├── clients/ (CLI + Tauri app)
├── sdks/ (TypeScript, Python)
├── tests/ (mock-mcp-server, mock-eslogger, integration/)
├── fuzz/ (3 fuzz targets)
├── examples/ (7 example projects)
├── extensions/ (macOS Network Extension)
├── policies/ (default.toml, injection_patterns.toml, killchain_patterns.toml)
├── threat-feed/ (feed/v1/: blocklist, IoCs, patterns, signatures)
├── keys/ (signing keys)
├── scripts/ (install.sh, uninstall.sh)
├── Formula/ + Homebrew/ (Homebrew formulas)
└── docs/ (120+ markdown files)
```

---

## 2. Last Activity

### Git Log (All 16 Commits)

| Date | Hash | Message |
|------|------|---------|
| Feb 16 | 72ed639 | Initial commit: Phase 0 project scaffolding |
| Feb 16 | fa407af | Phase 1: core features — proxy, sensor, TUI, daemon, CLI |
| Feb 16 | 7ee3065 | V1: MCP Trust Layer — production proxy, TUI, CLI, security hardening |
| Feb 16 | bd2bee1 | Phase 3-4: Rename to ClawDefender, local SLM, cloud swarm |
| Feb 17 | c40afc5 | Phase 5: Agentic Trust Layer & SDK |
| Feb 17 | 1b28e44 | Phase 6R: Reality Check — 49 bugs fixed, 50 regression tests |
| Feb 17 | 0046127 | Phase 7: Autonomous Behavioral Defense Engine |
| Feb 17 | 28e732c | Phase 8: Agent Vulnerability Scanner |
| Feb 17 | 6544589 | Phase 9: Agent Self-Protection API |
| Feb 17 | 00e2385 | Phase 10+11: Native macOS GUI + Threat Intelligence |
| Feb 18 | 5a5d21f | Phase 12: macOS Network Extension |
| Feb 21 | faaf5d1 | Phase 13: GUI Phases 1-3 — real daemon connection, live events |
| Feb 22 | 7aa4697 | Phase 14: Fix daemon startup |
| Feb 23 | 1d00814 | Phase 15: Model Management System |
| Feb 23 | a356220 | fix: add missing bail! macro import |
| Feb 23 | ccb25d1 | feat: Phases B, C, D — real security, working controls, AI intelligence |

**Uncommitted changes:** ~120+ files modified/added/deleted in working tree (new pages, components, stores, backend modules).

---

## 3. Tauri Backend — Command-by-Command Audit

### 3.1 Daemon Management (4 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `get_daemon_status` | ✅ WORKING | Live IPC query → cached fallback → disconnected defaults |
| `start_daemon` | ✅ WORKING | Finds binary (sidecar/system/workspace), spawns detached with setsid, polls for IPC ready |
| `stop_daemon` | ✅ WORKING | IPC shutdown → SIGTERM → SIGKILL escalation, cleans PID/socket |
| `restart_daemon` | ✅ WORKING | Full lifecycle restart with stale cleanup |

### 3.2 MCP Client/Server Management (8 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `detect_mcp_clients` | ✅ WORKING | Real config file reads for Claude Desktop, Cursor, VS Code, Windsurf |
| `list_mcp_servers` | ✅ WORKING | Parses JSON configs, detects wrapped status via `_clawdefender_original` |
| `wrap_server` | ✅ WORKING | Saves original config, creates backup, atomic write, idempotent |
| `unwrap_server` | ✅ WORKING | Restores original from `_clawdefender_original`, atomic write |
| `wrap_and_initialize` | ✅ WORKING | Wrap + reputation check + trust rules + policy write |
| `unwrap_and_cleanup` | ✅ WORKING | Unwrap + remove trust rules, profile cleanup is best-effort |
| `wrap_multiple_servers` | ✅ WORKING | Sequential wrap for each server |
| `protect_new_tool` | ✅ WORKING | Wrap + register in known_servers.json |

### 3.3 Policy Management (10 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `get_policy` | ✅ WORKING | Reads ~/.config/clawdefender/policy.toml, creates default if missing |
| `add_rule` | ✅ WORKING | Validates, checks duplicates, atomic write, daemon reload |
| `update_rule` | ✅ WORKING | Updates in place, atomic write |
| `delete_rule` | ✅ WORKING | Removes from TOML, atomic write |
| `duplicate_rule` | ✅ WORKING | Creates `{name}-copy` with unique suffix |
| `toggle_rule` | ✅ WORKING | Flips `enabled` boolean |
| `reorder_rules` | ✅ WORKING | Assigns priorities by array index |
| `reload_policy` | ✅ WORKING | Sends `reload` IPC command |
| `list_templates` | ⚠️ PARTIAL | Hardcoded 4-template list (but apply_template generates real rules) |
| `apply_template` | ✅ WORKING | Generates real rules from template definitions |

### 3.4 Events & Activity (3 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `get_recent_events` | ✅ WORKING | In-memory buffer (10K cap) + audit.jsonl fallback, dedup, filters |
| `get_event_detail` | ✅ WORKING | Buffer search + audit.jsonl fallback |
| `get_missed_events` | ✅ WORKING | Reads audit.jsonl with timestamp filtering |

### 3.5 Behavioral Engine (3 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `get_behavioral_status` | ✅ WORKING | Real IPC query, falls back to SQLite profiles.db |
| `get_profiles` | ✅ WORKING | Real SQLite query on profiles.db |
| `get_profile_detail` | ✅ WORKING | Real SQLite query for full profile JSON |

### 3.6 Guards (2 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `list_guards` | ✅ WORKING | Real IPC `guard_list` command |
| `toggle_guard` | ✅ WORKING | Real IPC `guard_toggle` command |

### 3.7 Scanner (3 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `start_scan` | ✅ WORKING | 5 real modules (MCP config audit, policy strength, server reputation, system posture, behavioral anomaly) |
| `get_scan_progress` | ✅ WORKING | From in-memory ScanTracker |
| `get_scan_results` | ✅ WORKING | In-memory + disk fallback with path traversal protection |

### 3.8 System Health (2 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `run_doctor` | ✅ WORKING | 9 real checks: daemon, socket, config, policy, audit log, FDA, MCP clients, wrapped servers, AI model |
| `get_system_info` | ✅ WORKING | Real `sw_vers` call for macOS version |

### 3.9 Prompts (2 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `respond_to_prompt` | ✅ WORKING | `allow_always` creates persistent policy rule |
| `get_pending_prompts` | ✅ WORKING | From pending_prompts state (capped at 100) |

### 3.10 Settings (7 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `get_settings` | ✅ WORKING | Reads config.toml with defaults |
| `update_settings` | ✅ WORKING | Preserves unknown sections, validates, atomic write, daemon reload |
| `export_settings` | ✅ WORKING | Strips API keys/secrets before export |
| `import_settings_from_content` | ✅ WORKING | Validates size (<10KB), null bytes, path traversal, valid TOML |
| `enable_autostart` | ✅ WORKING | tauri_plugin_autostart |
| `disable_autostart` | ✅ WORKING | tauri_plugin_autostart |
| `is_autostart_enabled` | ✅ WORKING | tauri_plugin_autostart |

### 3.11 Threat Intelligence (9 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `get_feed_status` | ✅ WORKING | Reads manifest.json, counts IoC entries |
| `force_feed_update` | ✅ WORKING | Runs CLI `clawdefender feed update` |
| `get_blocklist_matches` | ✅ WORKING | Cross-references blocklist with installed servers |
| `get_rule_packs` | ✅ WORKING | Reads from threat-intel directory |
| `install_rule_pack` | ✅ WORKING | Validates pack ID, runs CLI |
| `uninstall_rule_pack` | ✅ WORKING | Runs CLI |
| `get_ioc_stats` | ✅ WORKING | Counts indicators from IoC JSON files |
| `check_server_reputation` | ✅ WORKING | Reads blocklist + IoC, matches server name |
| `get_telemetry_preview` | 🔶 STUBBED | Hardcoded category list (no real telemetry) |

### 3.12 Network (7 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `get_network_extension_status` | 🔶 STUBBED | Returns `{ loaded: false, mock_mode: true }` |
| `activate_network_extension` | 🔶 STUBBED | Returns error "not installed" |
| `deactivate_network_extension` | 🔶 STUBBED | Returns error "not installed" |
| `get_network_settings` | ✅ WORKING | Reads config.toml `[network_policy]` |
| `update_network_settings` | ✅ WORKING | Writes config.toml atomically |
| `get_network_connections` | ⚠️ PARTIAL | bytes_sent/received/duration always 0 |
| `get_network_summary` | ⚠️ PARTIAL | Same zero-byte limitation |

### 3.13 AI / SLM Model Management (18 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `save_api_key` | ✅ WORKING | macOS Keychain |
| `clear_api_key` | ✅ WORKING | Deletes from Keychain |
| `has_cloud_api_key` | ✅ WORKING | Checks Keychain |
| `test_api_connection` | ✅ WORKING | Real HTTP request to provider |
| `get_cloud_usage` | ⚠️ PARTIAL | Returns zeroed stats (no tracking) |
| `activate_cloud_provider` | ⚠️ PARTIAL | Creates MockSlmBackend, not real cloud inference |
| `download_model` | ✅ WORKING | Real HTTP with progress, SHA-256 verify, cancel |
| `get_download_progress` | ✅ WORKING | Percent, bytes, speed, ETA |
| `cancel_download` | ✅ WORKING | Cancellation + partial file cleanup |
| `delete_model` | ✅ WORKING | Removes GGUF file from disk |
| `get_model_catalog` | ✅ WORKING | 5 curated models with real HuggingFace URLs |
| `get_installed_models` | ✅ WORKING | Scans models directory |
| `get_system_capabilities` | ✅ WORKING | Real sysctl for RAM, GPU detection |
| `activate_model` | ✅ WORKING | Real GGUF loading via llama.cpp |
| `deactivate_model` | ✅ WORKING | Clears active model from state |
| `get_active_model` | ✅ WORKING | From AppState |
| `get_slm_analysis_for_prompt` | ✅ WORKING | Real GGUF inference (or mock if no model) |
| `get_slm_status` | ✅ WORKING | Model info, inference stats, GPU |

### 3.14 Trust System (5 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `get_server_trust_level` | ✅ WORKING | Reads from trust config |
| `set_server_trust_level` | ✅ WORKING | Generates 7 permission rules, writes policy, reloads |
| `set_server_permission` | ✅ WORKING | Granular per-permission control |
| `preview_trust_change_cmd` | ✅ WORKING | Dry-run diff preview |
| `update_single_permission` | ✅ WORKING | Modifies specific trust rule |

### 3.15 Tool Detection (8 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `detect_new_tools` | ✅ WORKING | Scans client configs for new servers |
| `get_new_tools` | ✅ WORKING | Returns cached new server list |
| `acknowledge_new_tool` | ✅ WORKING | Removes from new list |
| `dismiss_new_tool` | ✅ WORKING | Marks as acknowledged |
| `get_server_capabilities` | ✅ WORKING | Inferred capabilities |
| `get_server_health_warnings` | ✅ WORKING | Health warnings per server |
| `get_tool_card` | ✅ WORKING | Detailed tool info card |
| `get_all_tool_cards` | ✅ WORKING | Batch version |

### 3.16 Alerts (7 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `get_active_alerts_cmd` | ✅ WORKING | In-memory alert_state (capped 500) |
| `get_alert_detail` | ✅ WORKING | By ID |
| `dismiss_alert_cmd` | ✅ WORKING | Updates status |
| `resolve_alert_cmd` | ✅ WORKING | Updates status |
| `dismiss_all_alerts` | ✅ WORKING | Batch dismiss |
| `get_alert_stats_cmd` | ✅ WORKING | Counts by severity/status |
| `get_alert_history_cmd` | ✅ WORKING | All alerts including resolved |

### 3.17 Digest & Recommendations (6 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `generate_digest_cmd` | ✅ WORKING | Weekly digest from events + SLM |
| `get_latest_digest` | ✅ WORKING | Cached digest |
| `get_recommendations_cmd` | ✅ WORKING | Analyzes events for actionable recommendations |
| `execute_recommendation_cmd` | ✅ WORKING | Executes recommended actions |
| `dismiss_recommendation_cmd` | ✅ WORKING | Adds to dismissed set |
| `get_trend_analysis_cmd` | ✅ WORKING | Event trends |

### 3.18 Protection Score (4 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `get_protection_score` | ✅ WORKING | 6 real factors totaling 100 points |
| `get_score_history` | ✅ WORKING | SQLite history |
| `execute_fix_action` | ✅ WORKING | Applies recommended fixes |
| `recalculate_score` | ✅ WORKING | Force recalculation + emits event |

### 3.19 Conversation / Ask Claw (12 commands)

| Command | Status | Notes |
|---------|--------|-------|
| `classify_intent` | ✅ WORKING | 28 intent types, pattern-based NLU |
| `save_conversation_message` | ✅ WORKING | Persists to disk |
| `load_conversation` | ✅ WORKING | Reads from disk |
| `list_conversations` | ✅ WORKING | Lists all |
| `delete_conversation` | ✅ WORKING | Removes from disk |
| `search_conversations` | ✅ WORKING | Full-text search |
| `create_new_conversation` | ✅ WORKING | Initializes empty |
| `execute_query` | ✅ WORKING | Executes against real backends |
| `confirm_action` | ✅ WORKING | Executes confirmed actions |
| `synthesize_response` | ✅ WORKING | NL response generation |
| `get_latest_conversation_id` | ✅ WORKING | From storage |
| `update_conversation_summary` | ✅ WORKING | Updates metadata |

### 3.20 Other Commands

| Command | Status | Notes |
|---------|--------|-------|
| `kill_agent_process` | ✅ WORKING | Rejects PID < 500, SIGTERM → SIGKILL |
| `check_onboarding_complete` | ✅ WORKING | In-memory + disk flag |
| `complete_onboarding` | ✅ WORKING | Writes flag to disk |
| `get_humanized_events` | ✅ WORKING | Real humanization engine |
| `get_correlation_for_event` | ✅ WORKING | Time-based correlation |
| `get_coverage_summary` | ✅ WORKING | Policy coverage analysis |
| `get_guidance_state` | ✅ WORKING | 9 guidance milestones |
| `get_server_summary` | ✅ WORKING | Territory, tools, network, patterns |
| `get_pending_crash_reports` | ✅ WORKING | From crash_report module |
| `check_existing_installation` | ✅ WORKING | Detects existing config |
| `migrate_config` | ✅ WORKING | Reads old, writes new format |

---

## 4. Frontend — Page-by-Page Audit

### 4.1 Route Map

| Route | Page | Status |
|-------|------|--------|
| `/` | Home | ✅ Fully functional |
| `/ask` | AskClaw | ✅ Fully functional |
| `/tools` | MyTools | ✅ Fully functional |
| `/tools/:id` | ToolDetail | ✅ Fully functional |
| `/activity` | Activity | ✅ Fully functional |
| `/activity/:id` | EventDetail | ✅ Fully functional |
| `/alerts` | Alerts | ✅ Fully functional |
| `/alerts/:id` | AlertDetail | ✅ Fully functional |
| `/settings` | Settings | ✅ Fully functional |
| `/settings/policy` | PolicyEditor | ✅ Fully functional |
| `/settings/health` | SystemHealth | ✅ Fully functional |
| `/settings/threat-intel` | ThreatIntel | ✅ Fully functional |
| `/onboarding` | Onboarding | ✅ Fully functional |

Dead routes: **NONE.** 7 deprecated pages (AuditLog, Timeline, Dashboard, Guards, NetworkLog, Scanner, Behavioral) are in `_deprecated/` with redirect rules.

### 4.2 Page Details

**Home (`/`)** — 627 lines
- Protection score ring (animated SVG), quick stat cards, server overview, pending actions, recent Claw messages
- Invokes: `get_daemon_status`, `detect_mcp_clients`, `list_guards`, `get_slm_status`, `get_protection_score`, `get_score_history`, `execute_fix_action`
- Events: `score-changed`, `event`, `status-change`, `prompt`
- Polling: 30s

**Ask Claw (`/ask`)** — 868 lines
- Full conversational AI with intent classification, structured data rendering, action buttons, confirmation flow, drag-and-drop file/URL analysis, message history recall
- Invokes: `ask_claw`, `confirm_action`, `analyze_config`, `analyze_file`, `analyze_url`

**My Tools (`/tools`)** — 210 lines
- Tool card grid with wrapped/unwrapped separation, new tool banners, scan button
- Invokes: `start_scan`, `get_tool_cards`, `get_new_tools`
- Events: `new-tool-detected`
- Virtual: Progressive rendering (30 initial, "Show more")

**Tool Detail (`/tools/:id`)** — 509 lines
- 4 tabs: Permissions (PermissionGrid), Behavior (BehavioralProfile), Activity (filtered events), Security (scan/wrap)
- TrustLevelSelector with live preview diff
- Invokes: `get_recent_events`, `start_scan`, `wrap_server`, `get_trust_level`
- Polling: 10s

**Activity (`/activity`)** — 479 lines
- Virtual-scrolled event feed (ROW_HEIGHT=52, BUFFER=400px)
- 7 filters: search, server (multi-select), status, risk, time range, correlation, notable toggle
- Event grouping by time period + server+tool+action clusters
- Invokes: `get_humanized_events` (count: 500)
- Events: `clawdefender://event`

**Event Detail (`/activity/:id`)** — 515 lines
- Humanized explanation, behavioral context, educational aside, raw JSON viewer, MiniTimeline, CorrelationTimeline, CoverageInsight
- Invokes: `get_correlation_for_event`, `get_coverage_summary`

**Alerts (`/alerts`)** — 290 lines
- Active alerts, recommendations, recently handled
- Invokes: `get_active_alerts_cmd`, `get_alert_stats_cmd`, `get_recommendations_cmd`, `execute_recommendation_cmd`, `dismiss_recommendation_cmd`
- Events: `clawdefender://alert`

**Alert Detail (`/alerts/:id`)** — 397 lines
- ThreatStory (visual kill chain timeline with connected steps, verdict card, confidence)
- Invokes: `get_alert_detail`, `resolve_alert_cmd`, `dismiss_alert_cmd`, `add_rule`

**Settings (`/settings`)** — 1141 lines
- 7 sections: Protection Score header, Protection Level, AI Analysis (ModelManager), Notifications, Start at Login, About/Help, Advanced Mode
- Advanced mode: Theme, behavioral thresholds, data privacy, developer options, export/import
- Invokes: 15+ commands including `get_settings`, `update_settings`, `get_protection_score`, etc.
- Auto-save: `useDebouncedSave` hook

**Policy Editor (`/settings/policy`)** — 400 lines
- Full CRUD: New Rule, Edit, Duplicate, Enable/Disable, Move Up/Down, Delete, Change Level, Change Template, Reset
- 3 modals: RuleEditorModal, SecurityLevelChooser, TemplateBrowser — all wired
- Invokes: `get_policy`, `add_rule`, `update_rule`, `delete_rule`, `duplicate_rule`, `toggle_rule`, `reorder_rules`, `reload_policy`

**System Health (`/settings/health`)** — 234 lines
- 9-point diagnostic with pass/warn/fail, fix buttons per check
- Invokes: `run_doctor`, `get_system_info`

**Threat Intel (`/settings/threat-intel`)** — 372 lines
- Feed status, blocklist warnings, rule pack install/uninstall, IoC stats, telemetry toggle
- Invokes: 10 commands

**Onboarding (`/onboarding`)** — 1123 lines
- 5 screens: Welcome (typewriter), Detect (auto-scan + tool selection), Protection Level, FDA prompt, Complete (animated score ring)
- Session persistence via sessionStorage

### 4.3 Non-Functional UI Elements

**Only 1 found:** "Show related events" button in `EventRow.tsx` (line 282) — has `title="Coming soon"` and no-op click handler. Intentionally stubbed.

### 4.4 Zustand Stores

| Store | Fields | Backend | Notes |
|-------|--------|---------|-------|
| eventStore | HumanizedEvent[] (10K cap), PendingPrompt[], counts | invoke + events | 100ms batch flushing |
| alertStore | IntelligentAlert[], AlertStats | All invoke | Bounded at 500, auto-expire |
| appStore | DaemonStatus, ProtectionScore, guidance, sidebar | invoke | 30s TTL cache |
| serverStore | ServerInfo[], hasNewUnwrapped | invoke | 30s TTL cache |
| toolStore | ToolCardData[], NewToolInfo[], trust/permissions | invoke | Full CRUD |
| conversationStore | Conversations, messages, context | invoke | Full persistence |

**All stores use real invoke() calls. Zero mock data.**

### 4.5 Real-Time Event Bus

| Event | Source | Consumers |
|-------|--------|-----------|
| `clawdefender://event` | Backend | Layout, Home, ToolDetail, Activity |
| `clawdefender://status-change` | Backend | Layout, Home |
| `clawdefender://prompt` | Backend | Layout, NotificationLayer, Home |
| `clawdefender://alert` | Backend | Layout, Alerts, NotificationLayer |
| `clawdefender://score-changed` | Backend | Home, Settings, Sidebar |
| `clawdefender://navigate` | Tray | App.tsx |
| `clawdefender://auto-block` | Backend | NotificationLayer |
| `clawdefender://new-tool-detected` | Backend | MyTools |
| `clawdefender://guidance-*` | Backend | Layout |

All event listeners use proper cleanup.

### 4.6 Accessibility

- ARIA roles: alertdialog, alert, status, timer, progressbar, radiogroup, switch, listitem
- Focus trap via `useFocusTrap` on all modals
- Keyboard shortcuts: Cmd+K (Ask Claw), Cmd+, (Settings), D/A/S/P in prompts
- Screen reader announcements at 10s and 5s in PromptWindow
- `prefers-reduced-motion` respected
- 44px minimum touch targets
- Skip-to-content link

---

## 5. Core Library (`clawdefender-core`) — 20,568 LOC

**Overall Status: 100% REAL IMPLEMENTATION. No stubs found.**

### 5.1 Event Types (`event/`)
- `McpEvent` with 6 variants: ToolCall (tool_name, arguments, request_id), ResourceRead, SamplingRequest, ListRequest, Notification, Other
- `OsEvent` with 10 variants: Exec, Open, Close, Rename, Unlink, Connect (addr/port/protocol), Fork, Exit, PtyGrant, SetMode
- `CorrelatedEvent` linking McpEvent + Vec<OsEvent> with correlation status
- All have real fields, full serde support, Event trait implementations

### 5.2 Policy Engine (`policy/`)
- TOML loading with validation, disabled rule skipping, action aliases (allow/permit, block/deny/reject)
- Pattern matching: glob (with thread-local cache), regex (with 256KB ReDoS limit), exact
- Path canonicalization: null byte rejection, tilde expansion, symlink resolution, dot/dotdot removal, traversal prevention
- First-match-wins evaluation: session rules → file rules → default (Log)
- Permanent rule persistence via atomic_write
- **37+ tests** including performance benchmarks

### 5.3 Audit Logger (`audit/`)
- `FileAuditLogger` with channel-based async writer (mpsc + dedicated thread)
- `AuditRecord` with 30+ fields including SLM/swarm analysis, injection scan, threat intel, network connection
- Size-based rotation (50MB default), numbered files (.1, .2, etc.)
- Retention cleanup by age
- Session tracking (session-start/session-end records)
- **27+ tests** including concurrent writes, rotation, corrupt line handling

### 5.4 Config System (`config/`)
- `ClawConfig` with 18 sections, all with serde defaults
- Loads from `~/.config/clawdefender/config.toml`, returns defaults if missing
- No `save()` method on ClawConfig (saving handled by atomic_write elsewhere)

### 5.5 Behavioral Engine (`behavioral/`) — Most Sophisticated Module
- **Profile** (`profile.rs`): ToolProfile (counts, patterns, bigrams), FileProfile (directories, extensions, rates), NetworkProfile (hosts, ports, rates), TemporalProfile (gap stats with online variance)
- **Anomaly Scorer** (`anomaly.rs`): 9 weighted dimensions (UnknownTool, UnknownPath, UnknownNetwork, AbnormalRate, AbnormalSequence, AbnormalArguments, SensitiveTarget, FirstNetworkAccess, PrivilegeEscalation). Z-score analysis. Floor rule (any dim at 1.0 → total ≥ 0.7). 16 sensitive paths. **25+ tests**
- **Learning Engine** (`learning.rs`): Dual threshold (event count AND time). Updates all profile types. **7 tests**
- **Decision Engine** (`decision.rs`): NormalPrompt/EnrichedPrompt/AutoBlock/Skip/Learning. Auto-block OFF by default. Kill chain boost (+0.3). Override feedback loop. **20+ tests**
- **Injection Detector** (`injection_detector.rs`): 23 regex patterns across 7 categories. Aho-Corasick pre-filter. Composite scoring. Hot-reloadable from TOML. **30+ tests**
- **Kill Chain Detector** (`killchain.rs`): 6 attack patterns (credential theft, recon, persistence, data staging, shell escape, prompt injection followthrough). Per-server sliding windows (5min, 1000 events max). Custom patterns from TOML. **30+ tests**
- **Persistence** (`persistence.rs`): SQLite (rusqlite bundled). CRUD operations. **7 tests**
- **Profile Updater** (`update.rs`): EMA (alpha=0.1), conservative set expansion (5 observations required). **7 tests**

### 5.6 DNS Module (`dns/`)
- TTL-based cache (10K entries), domain intelligence (known-safe, DGA detection via Shannon entropy), DNS filter (allowlist → blocklist → IoC → heuristics, fail-open), reverse DNS enrichment, exfiltration detection (tunneling indicators, base64/hex encoding, query rate). **21 tests**

### 5.7 Network Policy Engine (`network_policy/`)
- Multi-signal evaluation: non-agent bypass → IoC (overrides ALL allow rules) → guard → static rules → behavioral escalation → kill chain → default
- CIDR matching (IPv4/IPv6), wildcard domains, negation support
- Rate limiter: per-PID connections/minute and unique destinations/10s (advisory, not blocking)
- **44+ tests** including 19 dedicated security invariant tests

### 5.8 Other Modules
- **Atomic Write** (`atomic_write.rs`): write-fsync-rename with backup. 8 tests
- **Correlation** (`correlation/mod.rs`): PID/PPID matching with time windows, 10K pending limit. 11 tests
- **IPC Protocol** (`ipc/protocol.rs`): 38 message variants across 4 enums (UiRequest, DaemonRequest, DaemonResponse, UiResponse)
- **Rate Limiter** (`rate_limit.rs`): Per-server prompt fatigue prevention. Session-scoped blocking. 8 tests
- **Network Log** (`network_log.rs`): Metadata-only connection logging. Privacy enforced at type level. 9 tests

---

## 6. Daemon (`clawdefender-daemon`) — 5,759 LOC

### 6.1 Startup
- Foreground tokio process (no fork/daemonize — GUI manages lifecycle)
- Two modes: `run` (standalone) and `proxy` (MCP proxy mode)
- Single-instance guard via PID file at `~/.local/share/clawdefender/clawdefender.pid`
- Status: **FULLY WORKING**

### 6.2 IPC
- Unix domain socket at `~/.local/share/clawdefender/clawdefender.sock`
- JSON-line protocol (one JSON message per line)
- 7 command types: status, reload, guard_list, guard_toggle, GuardRequest variants, shutdown
- Stale socket cleanup on startup
- Status: **FULLY WORKING** (14 unit tests)

### 6.3 Event Routing
- `EventRouter` receives `CorrelatedEvent`s from sensor subsystem
- Fans out to: audit logger, UI clients, behavioral engines (learning → anomaly → kill chain → decision)
- SLM/Swarm escalation for high-severity events (advisory only, never influences policy)
- **CRITICAL GAP:** MCP proxy events bypass EventRouter. They go directly to audit log via `audit_tx.try_send()`, not through correlation engine.
- Status: **PARTIALLY WORKING** due to pipeline gap

### 6.4 Guard Management
- `GuardRegistry` exposed via IPC and optional REST API
- Register/deregister, action checking with glob patterns, dead PID cleanup (5s interval)
- Status: **FULLY WORKING**

### 6.5 Other Features
- Health check via IPC `status` command and `GuardHealthCheck`
- PID file with stale detection (`libc::kill(pid, 0)`)
- Logging: tracing + tracing-subscriber, file or stderr based on TUI mode
- Signal handling: SIGTERM/SIGINT with graceful cleanup

---

## 7. MCP Proxy (`clawdefender-mcp-proxy`) — 4,967 LOC

### 7.1 Stdio Proxying
- Spawns child process with piped stdin/stdout (stderr inherited)
- Channel-based relay: client→server and server→client
- Transparent: preserves original raw bytes (key ordering, whitespace, Unicode escapes)
- Status: **FULLY WORKING**

### 7.2 JSON-RPC Parsing
- Correct discrimination: id+method=Request, id-only=Response, method-only=Notification
- Security: 10MB max message, 20MB max buffer, 128 max nesting depth, null ID support
- Status: **FULLY WORKING** (35+ unit tests)

### 7.3 Classification & Policy Enforcement
- Pass: initialize, ping, notifications. Log: tools/list, resources/list, unknown. Review: tools/call, resources/read, sampling/createMessage
- Review pipeline: policy evaluate → Allow/Block/Prompt/Log
- Block: returns JSON-RPC error -32001
- Prompt: awaits user decision (AllowOnce/AllowSession/AddPolicyRule/Deny/timeout)
- Status: **FULLY WORKING**

### 7.4 HTTP Proxy Mode
- Axum-based reverse proxy for HTTP+SSE MCP servers
- SSE relay at `/sse`, JSON-RPC interception at `/` and `/{*path}`
- Same classification pipeline as stdio
- Status: **FULLY WORKING**

### 7.5 The Known Pipeline Issue
**CONFIRMED:** Enriched proxy events do NOT reach the GUI via real-time event streaming. They reach the GUI only indirectly through audit.jsonl file watching. The `DaemonRequest::McpEventForward` message type exists in the protocol but is never sent by the proxy.

**Impact:** Behavioral analysis (anomaly scoring, kill chain detection) only processes OS-level sensor events, NOT MCP tool-call events. A tool call and its resulting file write are logged separately, never correlated in real-time.

---

## 8. SLM Engine (`clawdefender-slm`) — 6,552 LOC

### 8.1 Feature Flags
| Feature | Deps | Effect |
|---------|------|--------|
| `gguf` | `llama_cpp = "0.3"` | Real local GGUF inference |
| `cloud` | `reqwest` | Real cloud API calls (Anthropic/OpenAI/Google) |
| `download` | reqwest, sha2, futures-util, etc. | Model download with verification |
| `default` | (none) | **Mock backend only** |

Consumers: daemon enables `gguf`, CLI enables `gguf`, Tauri app enables ALL THREE.

### 8.2 GGUF Backend
- Real `llama_cpp::LlamaModel::load_from_file()` with ChatML format, Metal GPU, symlink detection
- Status: **WORKING** (when feature enabled + model exists)

### 8.3 Cloud Backend
- Real HTTP POST to `api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`
- API keys via macOS Keychain
- Token usage and cost tracking per provider
- Status: **WORKING** (when feature enabled + key configured)

### 8.4 Model Registry
- 5 GGUF models: Qwen3-1.7B, Qwen3-4B, Phi-4 Mini, Gemma3-1B, Gemma3-4B (real HuggingFace URLs + SHA-256)
- 3 cloud providers: Anthropic (claude-sonnet-4), OpenAI (gpt-4o-mini), Google (gemini-2.0-flash)
- System detection: `sysctl hw.memsize`, `uname -m`

### 8.5 Downloader
- HTTP download with resume (Range headers), SHA-256 verification, cancellation via CancellationToken, progress via watch channel, disk space check (statvfs), HTTPS-only validation
- Status: **WORKING**

### 8.6 Security
- `sanitizer.rs`: Regex injection detection, XML tag stripping, nonce-based wrapping, canary tokens
- `output_validator.rs`: Echo attack detection, injection artifacts, falls back to HIGH risk on failure
- `noise_filter.rs`: 5 built-in profiles (compiler, package manager, IDE, git, test runner), frequency suppression (5 events/10min)

---

## 9. Sensor (`clawdefender-sensor`) — 6,041 LOC

### 9.1 Eslogger (macOS)
- Spawns `sudo eslogger` as child process with 10 event types
- Crash recovery with exponential backoff (2s initial → 60s max, resets after 5min stable)
- FDA detection via `~/Library/Mail` read test
- macOS 13+ version check
- Event pre-filter: drops system processes (21 known), Apple-signed, system paths
- 100ms debounce for duplicate events
- Status: **WORKING** (macOS 13+, FDA, sudo required)

### 9.2 Process Tree
- Real `sysinfo::System` for OS process data
- Ancestry walking (max depth 100) with 5s TTL cache
- PID recycling detection via start_time
- 4-layer agent identification: Tagged → Known clients → Runtime heuristic → Transitive from parent
- Status: **WORKING**

### 9.3 Filesystem Watcher
- `notify` crate (cross-platform), sensitivity classification (Critical/High/Medium/Low)
- Event debouncer with coalescing (Removed > Renamed > Modified > Created)
- Rate limiter (500 events/sec threshold, then 1-in-N sampling)
- Status: **WORKING**

### 9.4 Correlation Engine
- Sliding windows for MCP (500) and OS (5000) events
- 4 matching rules: ToolCallToExec, ResourceReadToOpen, FileToolToFileOp, NetworkToolToConnect
- Process ancestry verification, fuzzy path matching (exact=1.0, prefix=0.8, substring=0.6)
- Status: **WORKING**

---

## 10. Threat Intelligence (`clawdefender-threat-intel`) — 7,304 LOC

### 10.1 Feed Client
- Real HTTP with reqwest, incremental updates (only changed files), offline fallback
- Ed25519 signature verification with key rotation support
- Embedded public key: `e9b20cb34831fe44...` (real, not all-zeros)
- Status: **WORKING**

### 10.2 IoC Engine
- 9 indicator types: IP, domain, URL, file hash, file path, process name, command line, tool sequence, argument pattern
- Aho-Corasick for domain multi-matching, CIDR for IP ranges, compiled regex for patterns
- Performance: 10K events through 1K indicators < 1 second
- Status: **WORKING**

### 10.3 Blocklist Matcher
- Match methods: exact name (case-insensitive), npm package, exact version, semver range, SHA-256 hash
- Override mechanism requiring exact confirmation text
- Status: **WORKING** (library — CLI bug uses empty blocklist)

### 10.4 Community Rules
- Rule pack lifecycle: catalog, install, uninstall, update
- Conflict detection between community and user rules
- Status: **WORKING**

### 10.5 Pattern Loading
- Kill chain patterns from feed, injection signatures (multilingual: 8 languages), profile seeds
- Hot-reload support
- Status: **WORKING**

### 10.6 Telemetry
- Opt-in (disabled by default), anonymous (UUID installation ID), aggregate only
- No file paths, server names, IP addresses, usernames, or API keys
- Status: **WORKING**

---

## 11. Cloud & Swarm (`clawdefender-swarm`) — 5,017 LOC

- `crates/clawdefender-cloud/` **DOES NOT EXIST**
- Cloud functionality lives in `clawdefender-swarm`
- `Commander` for cloud LLM analysis, `ChatManager` + `ChatServer`, `CostTracker` with budget limits
- Keychain integration for API keys
- Data minimization, output sanitization, audit hashing
- Results are **advisory only** (safety comments throughout)
- Status: **WORKING** (when API key configured)

---

## 12. SDK

- `crates/clawdefender-sdk/` **DOES NOT EXIST**
- TypeScript SDK: `sdks/typescript/` (2,042 LOC)
- TypeScript Agent SDK: `sdks/typescript-agent/` (1,731 LOC)
- Python SDK: `sdks/python/` (1,767 LOC)
- Python Agent SDK: `sdks/python-agent/` (2,128 LOC)
- Guard REST API is the closest equivalent to an SDK

---

## 13. CLI (`clawdefender-cli`) — 6,190 LOC

20+ commands: init, wrap, unwrap, proxy, status, policy, log, doctor, model, config, usage, chat, daemon, behavioral, profile, certify, serve, guard, feed, rules, ioc, telemetry, network, reputation, scan.

**CLI-specific bugs:**
1. `check_reputation` creates empty blocklist instead of loading from cache
2. `feed_update` uses all-zeros verifier key instead of `FeedVerifier::from_embedded()`
3. `ioc_add` stubbed ("future version")
4. `policy reload` has TODO for IPC

---

## 14. TUI

- `crates/claw-tui/` **DOES NOT EXIST**
- `crates/clawdefender-tui/` exists (1,369 LOC) — terminal UI for daemon prompts, not a standalone dashboard

---

## 15. Build System & CI

### 15.1 Feature Flags
Only `clawdefender-slm` has `[features]`. All other 14 crates compile unconditionally.

### 15.2 CI (GitHub Actions)
| Workflow | Triggers | Steps |
|----------|----------|-------|
| `ci.yml` | push to main, PRs | fmt, clippy, test, doc |
| `security-audit.yml` | push to main, weekly cron | cargo audit, cargo deny |
| `build-app.yml` | push to `clawdefender-v0.3` (STALE), tags | tsc, Tauri build, DMG |
| `release.yml` | tags `v*` | aarch64 + x86_64, universal binary, GitHub Release |

**Gaps:** No frontend tests in CI. No integration tests in CI. `build-app.yml` targets stale branch. Apple signing commented out.

### 15.3 justfile
22 commands: dev, test, lint, audit, release, install, package, integration-test, clean, docs, fuzz-jsonrpc, fuzz-policy, build-daemon, build-app, dev-app, build-sidecar, build-dmg, build-extension, build-all, preflight, etc.

**Issue:** `build-menubar` references nonexistent `clients/clawdefender-menubar`.

### 15.4 Release
- LTO fat, single codegen unit, stripped, opt-level "z", panic=abort
- Install/uninstall scripts with SHA-256 verification
- Homebrew formula
- macOS LaunchDaemon plist (com.clawdefender.daemon.plist)

---

## 16. Test Coverage

| Category | Tests |
|----------|------:|
| clawdefender-core (behavioral, policy, audit, DNS, network policy) | ~370 |
| clawdefender-app (Tauri backend: conversation, alerts, trust, etc.) | ~530 |
| clawdefender-slm | ~170 |
| clawdefender-guard | ~131 |
| clawdefender-scanner | ~115 |
| clawdefender-threat-intel | ~109 |
| clawdefender-sensor | ~96 |
| clawdefender-daemon | ~97 |
| clawdefender-mcp-proxy | ~76 |
| clawdefender-mcp-server | ~54 |
| clawdefender-swarm | ~88 |
| clawdefender-cli | ~41 |
| clawdefender-tui | ~33 |
| clawdefender-certify | ~22 |
| Integration tests | ~8 |
| **TOTAL** | **~2,195** |

**Quality:** Tests are meaningful security tests, not trivial placeholders. Includes dedicated `security_tests.rs`, `evasion_tests.rs`, `adversarial_tests.rs`, `injection_tests.rs` files. Performance benchmarks included.

**Fuzz targets:** `fuzz_jsonrpc_parser`, `fuzz_policy_engine`, `fuzz_eslogger_parser`

**Frontend:** 14 Vitest test files

---

## 17. Configuration & Data Files

### 17.1 Config Files
| File | Purpose | Persistence |
|------|---------|-------------|
| `~/.config/clawdefender/config.toml` | App settings (18 sections) | Read on startup, atomic write on change |
| `~/.config/clawdefender/policy.toml` | Policy rules | Read/write with backup, hot-reload |
| `~/.config/clawdefender/noise.toml` | SLM noise filter rules | Hot-reloadable |
| `~/.local/share/clawdefender/model_config.toml` | Active model config | Read/write |

### 17.2 Data Files
| File | Purpose |
|------|---------|
| `~/.local/share/clawdefender/audit.jsonl` | Audit log (rotated at 50MB) |
| `~/.local/share/clawdefender/profiles.db` | Behavioral profiles (SQLite) |
| `~/.local/share/clawdefender/clawdefender.pid` | Daemon PID file |
| `~/.local/share/clawdefender/clawdefender.sock` | Unix socket |
| `~/.local/share/clawdefender/daemon.log` | Daemon log |
| `~/.local/share/clawdefender/threat-intel/` | Cached threat feed data |
| `~/.local/share/clawdefender/models/` | Downloaded GGUF models |
| `~/.local/share/clawdefender/crashes/` | Crash reports |
| `~/.local/share/clawdefender/scans/` | Scan results |
| `~/.local/share/clawdefender/server-token` | Guard API bearer token (0600) |
| `~/.clawdefender/onboarding_complete` | Onboarding flag |

---

## 18. Known Issues & Broken Features

### Critical

1. **MCP-to-EventRouter pipeline gap**
   - **Root cause:** `lib.rs` line 1170 passes `audit_tx` to proxy, not `correlation_input_tx`. `DaemonRequest::McpEventForward` exists but is never sent.
   - **Impact:** Behavioral analysis never sees MCP events. MCP-to-OS correlation only works through audit.jsonl file watching, not real-time.
   - **Fix:** Wire `McpEventForward` from proxy → daemon IPC → correlation engine → EventRouter.

### Moderate

2. **Cloud AI uses MockSlmBackend** — `commands.rs` `activate_cloud_provider` creates MockSlmBackend instead of real CloudBackend. Fix: use `CloudBackend::new()` from `clawdefender_slm::cloud_backend`.

3. **Guard client IPC incomplete** — `guard.rs:124,205` has TODO comments. `activate()` and `deactivate()` never send GuardRegister/GuardDeregister IPC despite daemon supporting them.

4. **CLI threat intel bugs** — `check_reputation` uses empty blocklist, `feed_update` uses all-zeros key, `ioc_add` stubbed. All three have working library implementations.

5. **Network byte metrics always zero** — Daemon doesn't emit bytes_sent/received/duration in audit records.

6. **Cloud usage returns zeros** — `get_cloud_usage` hardcoded. No request counting.

### Minor

7. **Mock network extension** — Cannot block connections. Documented as intentional.
8. **HTTP proxy lacks server_name** — `build_audit_record` helper doesn't set server_name/client_name.
9. **Profile cleanup on unwrap** — No dedicated IPC command to delete behavioral profile.
10. **Baseline blocklist empty** — `servers: []` in bundled baseline.
11. **`build-app.yml` stale branch trigger** — Points to `clawdefender-v0.3`.
12. **No frontend linting** — No ESLint/Prettier configured.

---

## 19. TODO/FIXME/STUB Inventory

### `// TODO` (3 occurrences)

| File | Line | Text |
|------|------|------|
| `crates/clawdefender-mcp-proxy/src/proxy/stdio.rs` | 884 | `let server = "mcp-proxy"; // TODO: get actual server name` |
| `clients/clawdefender-cli/src/commands/policy.rs` | 174 | `// TODO: send actual reload command over IPC.` |
| `clients/clawdefender-app/src-tauri/src/humanizer/humanizer.rs` | 102 | `let client_name: Option<String> = None; // TODO: derive from server config when available` |

### Other Markers
- `todo!()`: **0** in production code
- `unimplemented!()`: **0** in production code
- `unreachable!()`: **1** (test code only)
- `panic!()`: **~100** (ALL in test code)
- `// FIXME`, `// HACK`, `// STUB`, `// MOCK`, `// FAKE`, `// HARDCODED`, `// PLACEHOLDER`: **0**
- `SYNTHETIC`: **4** (documentation only, not in code)

---

## 20. Feature Completeness Matrix

| Feature | Backend | Frontend | Integration | Status |
|---------|---------|----------|-------------|--------|
| MCP stdio proxy | ✅ | N/A | ✅ | Working |
| MCP HTTP proxy | ✅ | N/A | ✅ | Working |
| JSON-RPC parsing | ✅ | N/A | ✅ | Working |
| Policy evaluation | ✅ | ✅ | ✅ | Working |
| Policy CRUD | ✅ | ✅ | ✅ | Working |
| Audit logging | ✅ | ✅ | ✅ | Working |
| Event streaming | ✅ | ✅ | ⚠️ | Working (via file watch, not EventRouter for MCP) |
| Behavioral profiles | ✅ | ✅ | ✅ | Working |
| Anomaly detection | ✅ | ✅ | ⚠️ | Partial (only sees sensor events, not MCP) |
| Kill chain detection | ✅ | ✅ | ⚠️ | Partial (same limitation) |
| Injection detection | ✅ | N/A | ✅ | Working |
| Daemon IPC | ✅ | ✅ | ✅ | Working |
| Guard registry | ✅ | ✅ | ⚠️ | Working (server-side); client IPC incomplete |
| Guard REST API | ✅ | N/A | ✅ | Working |
| Eslogger sensor | ✅ | N/A | ✅ | Working (macOS 13+) |
| Process tree | ✅ | N/A | ✅ | Working |
| FS monitoring | ✅ | N/A | ✅ | Working |
| MCP-OS correlation | ✅ | ✅ | ⚠️ | Working (sensor only, not proxy events) |
| GGUF inference | ✅ | ✅ | ✅ | Working (with feature flag) |
| Cloud AI inference | ✅ | ⚠️ | ❌ | Library works, Tauri uses MockSlmBackend |
| Model download | ✅ | ✅ | ✅ | Working |
| Threat feed | ✅ | ✅ | ✅ | Working |
| IoC matching | ✅ | ✅ | ✅ | Working |
| Blocklist | ✅ | ✅ | ⚠️ | Library works, CLI uses empty blocklist |
| Community rules | ✅ | ✅ | ✅ | Working |
| Trust system | ✅ | ✅ | ✅ | Working |
| Protection score | ✅ | ✅ | ✅ | Working |
| Alert intelligence | ✅ | ✅ | ✅ | Working |
| Ask Claw (NLU) | ✅ | ✅ | ✅ | Working |
| Digest/recommendations | ✅ | ✅ | ✅ | Working |
| Progressive guidance | ✅ | ✅ | ✅ | Working |
| Scanner (5 modules) | ✅ | ✅ | ✅ | Working |
| Onboarding | ✅ | ✅ | ✅ | Working |
| Settings | ✅ | ✅ | ✅ | Working |
| System health | ✅ | ✅ | ✅ | Working |
| Network extension | ❌ | 🔶 | ❌ | Not implemented (requires Apple signing) |
| Network monitoring | ⚠️ | ⚠️ | ⚠️ | Audit records lack byte metrics |
| Telemetry | 🔶 | 🔶 | ❌ | Config toggle works, no actual collection |
| CLI tool management | ✅ | N/A | ⚠️ | 3 bugs in threat intel commands |
| TUI dashboard | ❌ | N/A | ❌ | Does not exist |

---

## Appendix A: AppState Fields

| Field | Type | Bounded | Used By |
|-------|------|---------|---------|
| `daemon_connected` | `Mutex<bool>` | — | monitor, tray, commands |
| `cached_status` | `Mutex<Option<DaemonStatus>>` | — | status commands |
| `event_buffer` | `Mutex<Vec<AuditEvent>>` | 10,000 | event_stream, recent_events |
| `pending_prompts` | `Mutex<Vec<PendingPrompt>>` | 100 | event_stream, respond_to_prompt |
| `onboarding_complete` | `Mutex<bool>` | — | onboarding commands |
| `ipc_client` | `DaemonIpcClient` | — | all daemon commands |
| `daemon_started_by_gui` | `Mutex<bool>` | — | lifecycle |
| `active_scans` | `Mutex<HashMap<...>>` | — | scanner commands |
| `download_manager` | `DownloadManager` | — | model commands |
| `active_slm` | `Mutex<Option<Arc<SlmService>>>` | — | AI commands |
| `active_model_info` | `Mutex<Option<ActiveModelInfo>>` | — | model status |
| `alert_state` | `Mutex<Vec<IntelligentAlert>>` | 500 | alert commands |
| `cached_digest` | `Mutex<Option<WeeklyDigest>>` | — | digest commands |
| `dismissed_recommendations` | `Mutex<HashSet<String>>` | — | recommendation commands |
| `guidance_store` | `Mutex<GuidanceStore>` | — | guidance commands |
| `cached_score` | `Mutex<Option<ProtectionScore>>` | — | score commands |
| `wrapped_server_count` | `Mutex<u32>` | — | status, monitor |
| `blocked_today_count` | `Mutex<u32>` | — | tray |
| `blocked_today_date` | `Mutex<Option<NaiveDate>>` | — | reset tracking |

All 19 fields are actively used. No dead fields.

---

## Appendix B: Feature Flag Matrix

| Crate | Feature | Default | Effect |
|-------|---------|---------|--------|
| clawdefender-slm | `gguf` | Off | Enables llama_cpp GGUF inference |
| clawdefender-slm | `cloud` | Off | Enables reqwest for cloud API |
| clawdefender-slm | `download` | Off | Enables model download pipeline |
| All other crates | (none) | — | No feature flags |

Consumers:
- `clawdefender-daemon`: enables `gguf`
- `clawdefender-cli`: enables `gguf`
- `clawdefender-app` (Tauri): enables `gguf`, `cloud`, `download`

---

## Appendix C: Dependency Concerns

| Issue | Details |
|-------|---------|
| `rand` 0.8 vs 0.9 | Scanner uses 0.8, mcp-server uses 0.9. May cause duplicate deps. |
| `dirs` 5 vs 6 | Guard/app use v5, mcp-server uses v6. |
| `llama_cpp = "0.3"` | Niche crate — verify maintenance status. |
| No ESLint/Prettier | Frontend has no JS/TS linting configured. |
| Apple signing absent | Developer ID signing and notarization commented out. |

---

## Appendix D: Recommended Next Steps (Prioritized)

### P0 — Critical (Unlocks Full Pipeline)
1. **Wire MCP-to-EventRouter pipeline** — Send `McpEventForward` from proxy to daemon correlation engine. This is the #1 gap: behavioral analysis never sees MCP events.

### P1 — High (Fixes Broken Features)
2. **Wire cloud AI inference** — Replace MockSlmBackend with real CloudBackend in `activate_cloud_provider`.
3. **Fix 3 CLI threat intel bugs** — Load blocklist from cache, use embedded verifier key, implement `ioc_add`.
4. **Complete Guard client IPC** — Send GuardRegister/GuardDeregister from AgentGuard.

### P2 — Medium (Polish & Distribution)
5. **Apple Developer signing + notarization** — Required for distribution.
6. **Add frontend tests to CI** — Run `vitest` in ci.yml.
7. **Fix stale CI trigger** — Update `build-app.yml` branch reference.
8. **Add ESLint/Prettier** — Frontend linting.
9. **Network byte metrics** — Emit bytes_sent/received from proxy audit records.

### P3 — Low (Nice to Have)
10. **Cloud usage tracking** — Implement request counting and token tracking.
11. **Profile cleanup on unwrap** — Add dedicated IPC command.
12. **Cleanup stale justfile commands** — Remove `build-menubar`.
13. **Unify `rand` and `dirs` versions** — Resolve version mismatches.
