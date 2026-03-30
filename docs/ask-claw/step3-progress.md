# Ask Claw — Step 3 Progress Tracker

**Started**: 2026-02-24
**Status**: In Progress

---

## Agent Assignments

| Agent | Role | Status |
|-------|------|--------|
| Agent 1 | Conversation Architect — architecture doc + intent taxonomy | Complete |
| Agent 2 | Intent Classification Module (Rust) | Pending |
| Agent 3 | Query Execution Engine (Rust) | Pending |
| Agent 4 | Response Synthesis Engine (Rust) | Pending |
| Agent 5 | Drag-and-Drop File/URL Analysis (Rust) | Pending |
| Agent 6 | Conversation UI (React/TypeScript) | Pending |
| Agent 7 | Conversation Persistence + Context System | Pending |
| Agent 8 | Security Audit of Conversational Layer | Pending |
| Agent 9 | QA — Full Pipeline Testing | Pending |
| Agent 10 | Integration + Polish (tray, shortcuts, accessibility) | Pending |

---

## Deliverables

### Foundation (Agent 1)

| # | Deliverable | File | Status | Acceptance Criteria |
|---|-------------|------|--------|---------------------|
| 1.1 | Architecture document | `docs/ask-claw/architecture.md` | Complete | Pipeline design, data flow, module structure, all type definitions |
| 1.2 | Intent taxonomy (30 intents) | Included in architecture.md Section 5 | Complete | Every intent has ID, triggers, commands, strategy, confirmation flag |
| 1.3 | Response strategy matrix | Included in architecture.md Section 6 | Complete | Every intent mapped to template-only / template+LLM / LLM-required |
| 1.4 | Conversation state model | Included in architecture.md Section 7 | Complete | React state, context resolution rules, SQLite schema |
| 1.5 | Progress tracker | `docs/ask-claw/step3-progress.md` | Complete | This file |

### Backend — Intent Classification (Agent 2)

| # | Deliverable | File | Status | Acceptance Criteria |
|---|-------------|------|--------|---------------------|
| 2.1 | Intent registry data | `src-tauri/src/conversation/intents.rs` | Pending | All 30 intents with keyword patterns and entity extractors |
| 2.2 | Keyword classifier | `src-tauri/src/conversation/classifier.rs` | Pending | Classifies input -> IntentClassification in <5ms |
| 2.3 | LLM-assisted classifier | `src-tauri/src/conversation/classifier.rs` | Pending | Falls back to SLM when keyword confidence <0.6 |
| 2.4 | Entity extraction | `src-tauri/src/conversation/classifier.rs` | Pending | Extracts server_name, event_id, file_path, url, page_name, time_range |
| 2.5 | Unit tests | `src-tauri/src/conversation/classifier.rs` | Pending | 5+ trigger phrases per intent all classify correctly |

### Backend — Query Execution (Agent 3)

| # | Deliverable | File | Status | Acceptance Criteria |
|---|-------------|------|--------|---------------------|
| 3.1 | Intent router | `src-tauri/src/conversation/router.rs` | Pending | Maps every intent to correct QueryPlan with commands + params |
| 3.2 | Query executor | `src-tauri/src/conversation/executor.rs` | Pending | Executes QueryPlan, handles parallel queries, collects results |
| 3.3 | Confirmation flow | `src-tauri/src/conversation/router.rs` | Pending | control.* intents produce confirmation prompts |
| 3.4 | Error handling | `src-tauri/src/conversation/executor.rs` | Pending | Partial results on failure, graceful error messages |
| 3.5 | Unit tests | Tests in executor.rs/router.rs | Pending | All 30 intents route to valid commands; executor handles errors |

### Backend — Response Synthesis (Agent 4)

| # | Deliverable | File | Status | Acceptance Criteria |
|---|-------------|------|--------|---------------------|
| 4.1 | Template engine | `src-tauri/src/conversation/synthesizer.rs` | Pending | Templates for all template-only and template+LLM intents |
| 4.2 | LLM integration | `src-tauri/src/conversation/synthesizer.rs` | Pending | SLM polishes template output; canary verification; fallback |
| 4.3 | Structured data builder | `src-tauri/src/conversation/synthesizer.rs` | Pending | Produces correct StructuredData variant per intent |
| 4.4 | Voice compliance | All templates | Pending | Every template matches voice guide (first person, short sentences, no jargon) |
| 4.5 | Unit tests | Tests in synthesizer.rs | Pending | Template output matches expected format; LLM fallback works |

### Backend — Drag-and-Drop (Agent 5)

| # | Deliverable | File | Status | Acceptance Criteria |
|---|-------------|------|--------|---------------------|
| 5.1 | Input preprocessor | `src-tauri/src/conversation/preprocessor.rs` | Pending | Detects text/file/URL/event_ref input types |
| 5.2 | File analysis path | `src-tauri/src/conversation/preprocessor.rs` | Pending | File path input triggers risk.file intent |
| 5.3 | URL analysis path | `src-tauri/src/conversation/preprocessor.rs` | Pending | URL input triggers risk.url intent |
| 5.4 | Sanitization | `src-tauri/src/conversation/preprocessor.rs` | Pending | All input sanitized before processing |
| 5.5 | Unit tests | Tests in preprocessor.rs | Pending | File paths, URLs, plain text all detected correctly |

### Frontend — Conversation UI (Agent 6)

| # | Deliverable | File | Status | Acceptance Criteria |
|---|-------------|------|--------|---------------------|
| 6.1 | ConversationPanel | `src/components/conversation/ConversationPanel.tsx` | Pending | Sliding panel, opens/closes smoothly |
| 6.2 | MessageBubble | `src/components/conversation/MessageBubble.tsx` | Pending | User and Claw message styles, timestamps |
| 6.3 | StructuredDataCard | `src/components/conversation/StructuredDataCard.tsx` | Pending | Renders all 7 StructuredData variants |
| 6.4 | ActionButtonGroup | `src/components/conversation/ActionButtonGroup.tsx` | Pending | Renders action buttons, handles clicks |
| 6.5 | InputBar | `src/components/conversation/InputBar.tsx` | Pending | Text input + drag-drop zone + send button |
| 6.6 | QuickActions | `src/components/conversation/QuickActions.tsx` | Pending | Quick action chips, context-aware |
| 6.7 | useConversation hook | `src/hooks/useConversation.ts` | Pending | Full Tauri invoke integration |
| 6.8 | TypeScript types | `src/types/conversation.ts` | Pending | All types matching Rust definitions |
| 6.9 | Design system compliance | All components | Pending | Uses tokens.css, follows visual identity |

### Persistence + Context (Agent 7)

| # | Deliverable | File | Status | Acceptance Criteria |
|---|-------------|------|--------|---------------------|
| 7.1 | SQLite store | `src-tauri/src/conversation/persistence.rs` | Pending | Create DB, save/load turns, session management |
| 7.2 | Context resolver | `src-tauri/src/conversation/context.rs` | Pending | Pronoun resolution, entity carryover, page context |
| 7.3 | Session lifecycle | `src-tauri/src/conversation/persistence.rs` | Pending | Auto-create, 30min timeout, 30-day prune |
| 7.4 | Conversation engine | `src-tauri/src/conversation/mod.rs` | Pending | Wires all components together |
| 7.5 | Tauri commands | `src-tauri/src/commands.rs` (additions) | Pending | 5 new commands registered |

### Security Audit (Agent 8)

| # | Deliverable | File | Status | Acceptance Criteria |
|---|-------------|------|--------|---------------------|
| 8.1 | Input sanitization audit | N/A | Pending | All user input sanitized before LLM |
| 8.2 | Prompt injection testing | N/A | Pending | Canary verification works; injection patterns blocked |
| 8.3 | Action safety audit | N/A | Pending | All control actions require confirmation |
| 8.4 | Data handling audit | N/A | Pending | No secrets in LLM prompts; local-only storage |
| 8.5 | SQL injection check | N/A | Pending | All SQLite queries use parameterized statements |

### QA Testing (Agent 9)

| # | Deliverable | File | Status | Acceptance Criteria |
|---|-------------|------|--------|---------------------|
| 9.1 | Intent classification tests | N/A | Pending | All 150+ trigger phrases classify correctly |
| 9.2 | End-to-end pipeline tests | N/A | Pending | 10+ full user conversations produce correct responses |
| 9.3 | Error handling tests | N/A | Pending | Daemon down, SLM missing, command failures all handled |
| 9.4 | Voice compliance check | N/A | Pending | All responses pass 10-point voice guide checklist |
| 9.5 | Performance benchmarks | N/A | Pending | Template <100ms, Template+LLM <2s, LLM <5s |

### Integration + Polish (Agent 10)

| # | Deliverable | File | Status | Acceptance Criteria |
|---|-------------|------|--------|---------------------|
| 10.1 | Keyboard shortcut (Cmd+K) | N/A | Pending | Opens/closes conversation panel |
| 10.2 | Tray menu integration | N/A | Pending | "Ask Claw" option in system tray |
| 10.3 | Accessibility | N/A | Pending | ARIA labels, keyboard navigation, screen reader support |
| 10.4 | Animation polish | N/A | Pending | Smooth panel slide, typing indicator, message transitions |
| 10.5 | Error states | N/A | Pending | Empty state, error state, loading state all designed |

---

## Dependency Graph

```
Agent 1 (Architecture) ──> Agent 2 (Classifier)
                       ──> Agent 3 (Executor)
                       ──> Agent 4 (Synthesizer)
                       ──> Agent 5 (Preprocessor)
                       ──> Agent 6 (UI)
                       ──> Agent 7 (Persistence)

Agent 2 + 3 + 4 + 5 ──> Agent 7 (wires everything together)
Agent 6 + 7 ──> Agent 8 (security audit)
Agent 7 + 8 ──> Agent 9 (QA testing)
Agent 9 ──> Agent 10 (integration polish)
```

Agents 2-6 can work in parallel. Agent 7 integrates their output. Agent 8 audits, Agent 9 tests, Agent 10 polishes.
