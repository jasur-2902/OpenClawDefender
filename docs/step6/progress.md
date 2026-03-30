# Step 6: Progress Tracker

## Agent Status

| Agent | Role | Status | Dependencies | Notes |
|-------|------|--------|-------------|-------|
| 1 | Architecture | COMPLETE | None | architecture.md delivered |
| 2 | Event Humanization Engine | Pending | Agent 1 (architecture) | Rust: humanizer.rs, enrichment, templates |
| 3 | Alert Intelligence Engine | Pending | Agent 1 (architecture) | Rust: alert_engine.rs, kill_chain.rs, dedup |
| 4 | Prompt Window & Notification System | Pending | Agent 2 (humanized events) | notification_router.rs, PromptWindow redesign |
| 5 | Activity Feed Rebuild | Pending | Agent 2 (humanized events) | Activity.tsx, EventRow.tsx, humanizedEventStore |
| 6 | Alerts Page Rebuild | Pending | Agent 3 (alert engine) | Alerts.tsx, AlertDetail.tsx, intelligentAlertStore |
| 7 | Weekly Digest & Proactive Intelligence | Pending | Agent 2, Agent 3 | digest.rs, recommendations.rs, DigestPage |
| 8 | Event Correlation Display | Pending | Agent 2, Agent 3 | correlation.rs, CorrelationView component |
| 9 | QA Engineer | Pending | All agents | Build verification, tests, benchmarks |
| 10 | Accessibility & Polish | Pending | Agents 4-8 | Keyboard nav, ARIA, focus, animations |

## Dependency Graph

```
Agent 1 (Architecture)
  |
  +---> Agent 2 (Humanization Engine)
  |       |
  |       +---> Agent 4 (Prompt & Notifications)
  |       +---> Agent 5 (Activity Feed)
  |       +---> Agent 7 (Digest, partial)
  |       +---> Agent 8 (Correlation, partial)
  |
  +---> Agent 3 (Alert Engine)
          |
          +---> Agent 6 (Alerts Page)
          +---> Agent 7 (Digest, partial)
          +---> Agent 8 (Correlation, partial)

Agents 4-8 ---> Agent 9 (QA)
Agents 4-8 ---> Agent 10 (Accessibility)
```

## Key Files to Create

| File | Agent | Type |
|------|-------|------|
| `src-tauri/src/humanizer.rs` | 2 | Rust module |
| `src-tauri/src/alert_engine.rs` | 3 | Rust module |
| `src-tauri/src/kill_chain.rs` | 3 | Rust module |
| `src-tauri/src/notification_router.rs` | 4 | Rust module |
| `src-tauri/src/digest.rs` | 7 | Rust module |
| `src-tauri/src/recommendations.rs` | 7 | Rust module |
| `src-tauri/src/correlation.rs` | 8 | Rust module |
| `src/stores/humanizedEventStore.ts` | 5 | Zustand store |
| `src/stores/intelligentAlertStore.ts` | 6 | Zustand store |
| `src/stores/digestStore.ts` | 7 | Zustand store |

## Key Files to Modify

| File | Agent(s) | Changes |
|------|----------|---------|
| `src-tauri/src/lib.rs` | 2, 3, 4, 7, 8 | Register new modules and commands |
| `src-tauri/src/event_stream.rs` | 2, 4 | Route events through humanization pipeline |
| `src/types/index.ts` | 2, 3, 5, 6, 7, 8 | Add new TypeScript interfaces |
| `src/constants/messages.ts` | 2, 5, 6, 7 | Add humanization templates |
| `src/pages/Activity.tsx` | 5 | Rebuild to use HumanizedEvent |
| `src/pages/Alerts.tsx` | 6 | Rebuild to use IntelligentAlert |
| `src/pages/AlertDetail.tsx` | 6 | Rebuild with kill chain narrative |
| `src/pages/EventDetail.tsx` | 5 | Rebuild with humanized content |
| `src/components/PromptWindow.tsx` | 4 | Redesign with humanized context |
| `src/components/NotificationLayer.tsx` | 4 | Integrate notification router |
| `src/components/activity/EventRow.tsx` | 5 | Use HumanizedEvent fields |
| `src/components/alerts/ThreatStory.tsx` | 6 | Use KillChainNarrative |
| `src/stores/alertStore.ts` | 6 | Replace with intelligentAlertStore |
| `src/utils/alertGenerator.ts` | 3 | Move logic to Rust alert_engine.rs |
