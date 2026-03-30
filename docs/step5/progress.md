# Step 5: My Tools Experience — Progress Tracker

**Started**: 2026-02-25
**Target**: Complete build of the My Tools experience

---

## Agent Assignments

| # | Agent | Role | Status | Deliverables |
|---|---|---|---|---|
| 1 | Agent 1 | Tools Experience Architect | COMPLETE | architecture.md, progress.md |
| 2 | Agent 2 | Trust Level Backend | PENDING | Rust trust commands, rule generation, inference, TOML integration |
| 3 | Agent 3 | Tool Discovery & Card Assembler | PENDING | Capability inference, health warnings, get_tool_cards, get_tool_detail |
| 4 | Agent 4 | Wrap/Unwrap Enhancement | PENDING | Auto-scan on wrap, trust application, batch wrap, cleanup |
| 5 | Agent 5 | Frontend (My Tools + Tool Detail) | PENDING | MyTools.tsx, ToolDetail.tsx, toolStore.ts |
| 6 | Agent 6 | Behavioral Summary Humanizer | PENDING | Transform raw profiles to Claw-voice summaries |
| 7 | Agent 7 | Migration & Cleanup | PENDING | Move Behavioral/Guards into Tool Detail, clean Settings |
| 8 | Agent 8 | QA | PENDING | Build verification, trust lifecycle, permissions, performance |
| 9 | Agent 9 | Accessibility | PENDING | Keyboard nav, ARIA, screen reader, dark mode |

---

## Deliverables Checklist

### Architecture (Agent 1)

- [x] Trust Level -> Policy Rule Mapping (Section 1)
- [x] TOML rules for all 4 trust levels (Section 1.4)
- [x] Rule precedence model (Section 1.5)
- [x] Trust level inference algorithm (Section 1.6)
- [x] Permission Grid data model (Section 2)
- [x] Permission override interaction design (Section 2.5)
- [x] ToolCardData struct (Section 3.1)
- [x] Data source mapping (Section 3.2)
- [x] get_tool_cards command spec (Section 3.3)
- [x] get_tool_detail command spec (Section 3.4)
- [x] Capability inference system (Section 3.5)
- [x] Health warning generation (Section 3.6)
- [x] New tool detection system (Section 4)
- [x] known_servers.json format (Section 4.2)
- [x] New Tauri commands for detection (Section 4.3)
- [x] Trust management commands (Section 5)
- [x] Frontend data flow (Section 6)
- [x] Behavioral summary transformation (Section 7)
- [x] Compatibility notes (Section 8)

### Trust Level Backend (Agent 2)

- [ ] `trust_rule_key()` function
- [ ] `generate_trust_rules(server_name, level)` — produces Vec<PolicyRule>
- [ ] `infer_trust_level(server_name)` — reads policy, returns TrustLevelInfo
- [ ] `set_trust_level` Tauri command
- [ ] `get_trust_level` Tauri command
- [ ] `set_permission_override` Tauri command
- [ ] `reset_permission_override` Tauri command
- [ ] TrustLevel and TrustLevelInfo Rust types
- [ ] PermissionGrid Rust type
- [ ] Unit tests for rule generation (all 4 levels)
- [ ] Unit tests for trust level inference
- [ ] Unit tests for permission override
- [ ] Integration with existing policy file read/write

### Tool Discovery & Card Assembler (Agent 3)

- [ ] `get_tool_cards` Tauri command
- [ ] `get_tool_detail` Tauri command
- [ ] `get_server_capabilities` Tauri command
- [ ] Known server capability registry (built-in map)
- [ ] Capability inference from server name heuristics
- [ ] Capability inference from behavioral profile
- [ ] Health warning generator
- [ ] ToolCardData Rust struct
- [ ] ToolDetailData Rust struct
- [ ] ToolCapability and HealthWarning Rust structs
- [ ] Unit tests for capability inference
- [ ] Unit tests for health warning generation

### Wrap/Unwrap Enhancement (Agent 4)

- [ ] Auto-scan trigger after wrap
- [ ] Trust level application on first wrap (default: Standard)
- [ ] Batch wrap command for multiple servers
- [ ] Cleanup of trust rules on unwrap
- [ ] Backup verification on wrap/unwrap

### Frontend (Agent 5)

- [ ] `src/stores/toolStore.ts` — Zustand store
- [ ] `src/pages/MyTools.tsx` — tool card grid
- [ ] `src/pages/ToolDetail.tsx` — detail page
- [ ] Tool card component with shield icon, trust badge, status
- [ ] Trust level dropdown selector
- [ ] Permission grid component (6 rows, 3-state toggles)
- [ ] New tool notification banner
- [ ] New tool acknowledgment flow (trust level picker)
- [ ] Empty state for no tools
- [ ] Loading skeletons
- [ ] Routing: /tools and /tools/:serverName
- [ ] 30-second polling on My Tools page
- [ ] 10-second polling on Tool Detail page
- [ ] TypeScript types (ToolCardData, TrustLevel, PermissionGrid, etc.)

### Behavioral Summary Humanizer (Agent 6)

- [ ] Score-to-label mapping (no raw numbers shown)
- [ ] Learning progress bar with friendly text
- [ ] Activity count formatting ("847 actions today")
- [ ] Anomaly badge with Claw-voice description
- [ ] "Last unusual activity" relative time display

### Migration & Cleanup (Agent 7)

- [ ] Behavioral page data absorbed into Tool Detail
- [ ] Guards page data absorbed into Tool Detail
- [ ] Auto-block control moved to Settings
- [ ] Anomaly threshold control moved to Settings
- [ ] Old Behavioral.tsx confirmed deprecated
- [ ] Old Guards.tsx confirmed deprecated
- [ ] No functionality lost in migration
- [ ] Sidebar navigation updated (My Tools replaces separate Behavioral/Guards)

### QA (Agent 8)

- [ ] Frontend builds without errors
- [ ] Rust backend builds without errors
- [ ] Trust level set -> rules generated correctly
- [ ] Trust level change -> old rules removed, new rules written
- [ ] Permission override -> single rule updated
- [ ] Permission reset -> reverts to canonical
- [ ] Tool card displays correct data from all sources
- [ ] New tool detection fires on new server
- [ ] Performance: get_tool_cards < 100ms
- [ ] No regressions in existing commands

### Accessibility (Agent 9)

- [ ] All interactive elements keyboard-navigable
- [ ] Trust level dropdown accessible via keyboard
- [ ] Permission grid accessible via keyboard (arrow keys)
- [ ] ARIA labels on all status badges
- [ ] ARIA labels on permission states
- [ ] Screen reader announces trust level changes
- [ ] Focus management on page navigation
- [ ] Dark mode contrast ratios pass WCAG AA
- [ ] Reduced motion respected

---

## Acceptance Criteria

1. User opens My Tools and sees all detected MCP servers as cards
2. Each card shows: server name, client name, trust level badge, behavioral status, event count
3. Clicking a card opens the Tool Detail page with full info
4. User can change trust level via dropdown — rules are generated/applied immediately
5. User can override individual permissions — changes reflect in policy file
6. New tools are detected within 60 seconds and surfaced with a notification
7. Sensitive paths are always blocked and the row is visually locked
8. All text follows Claw's voice (no raw scores, no jargon)
9. Page loads in under 200ms, polling does not cause UI jank
10. Keyboard navigation works for all controls
