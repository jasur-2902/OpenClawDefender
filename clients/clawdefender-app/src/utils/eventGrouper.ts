import type { HumanizedEvent } from "../types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type TimePeriod =
  | "right_now"
  | "earlier_today"
  | "yesterday"
  | "this_week"
  | "older";

export interface EventGroup {
  id: string;
  type: "single" | "grouped" | "kill_chain" | "prompt_sequence";
  period: TimePeriod;
  representative: HumanizedEvent;
  count: number;
  summary: string;
  children: HumanizedEvent[];
  kill_chain_id?: string;
}

// ---------------------------------------------------------------------------
// Time Period Classification
// ---------------------------------------------------------------------------

const FIVE_MINUTES = 5 * 60 * 1000;

export const PERIOD_LABELS: Record<TimePeriod, string> = {
  right_now: "Right now",
  earlier_today: "Earlier today",
  yesterday: "Yesterday",
  this_week: "This week",
  older: "Older",
};

function getTimePeriod(timestamp: string, now: Date): TimePeriod {
  const t = new Date(timestamp).getTime();
  const nowMs = now.getTime();

  if (nowMs - t < FIVE_MINUTES) return "right_now";

  const todayStart = new Date(now);
  todayStart.setHours(0, 0, 0, 0);

  if (t >= todayStart.getTime()) return "earlier_today";

  const yesterdayStart = new Date(todayStart);
  yesterdayStart.setDate(yesterdayStart.getDate() - 1);

  if (t >= yesterdayStart.getTime()) return "yesterday";

  const weekStart = new Date(todayStart);
  weekStart.setDate(weekStart.getDate() - 7);

  if (t >= weekStart.getTime()) return "this_week";

  return "older";
}

// ---------------------------------------------------------------------------
// Grouping Key & Summary
// ---------------------------------------------------------------------------

const GROUP_WINDOW_MS = 30_000; // 30 seconds

function getCommonPathPrefix(paths: string[]): string {
  const valid = paths.filter(Boolean);
  if (valid.length === 0) return "";
  if (valid.length === 1) return valid[0];

  const parts = valid.map((p) => p.split("/"));
  const minLen = Math.min(...parts.map((p) => p.length));
  const common: string[] = [];

  for (let i = 0; i < minLen; i++) {
    const seg = parts[0][i];
    if (parts.every((p) => p[i] === seg)) {
      common.push(seg);
    } else {
      break;
    }
  }

  return common.join("/") || "";
}

function shortenPath(path: string): string {
  if (!path) return "";
  // Replace home directory patterns with ~
  const home = path.replace(/^\/Users\/[^/]+/, "~").replace(/^\/home\/[^/]+/, "~");
  return home;
}

function resourceNoun(action: string, count: number): string {
  const lower = action.toLowerCase();
  if (lower.includes("read") || lower.includes("file")) {
    return count === 1 ? "file" : "files";
  }
  if (lower.includes("write") || lower.includes("create")) {
    return count === 1 ? "file" : "files";
  }
  if (lower.includes("command") || lower.includes("exec")) {
    return count === 1 ? "command" : "commands";
  }
  if (lower.includes("connect") || lower.includes("fetch") || lower.includes("network")) {
    return count === 1 ? "connection" : "connections";
  }
  return count === 1 ? "action" : "actions";
}

function actionVerb(action: string): string {
  const lower = action.toLowerCase();
  if (lower.includes("read")) return "read";
  if (lower.includes("write") || lower.includes("create")) return "wrote";
  if (lower.includes("list") || lower.includes("search")) return "searched";
  if (lower.includes("delete") || lower.includes("remove")) return "deleted";
  if (lower.includes("exec") || lower.includes("command") || lower.includes("run")) return "ran";
  if (lower.includes("connect") || lower.includes("fetch")) return "connected to";
  return "used";
}

function buildGroupSummary(events: HumanizedEvent[]): string {
  const first = events[0];
  const displayName = first.server_display_name;
  const verb = actionVerb(first.raw_event.action);
  const noun = resourceNoun(first.raw_event.action, events.length);

  const resources = events
    .map((e) => e.raw_event.resource ?? "")
    .filter(Boolean);
  const commonPath = getCommonPathPrefix(resources);

  if (commonPath) {
    return `${displayName} ${verb} ${events.length} ${noun} in ${shortenPath(commonPath)}`;
  }

  const tool = first.raw_event.tool_name;
  if (tool) {
    return `${displayName} ${verb} ${events.length} ${noun} via ${tool}`;
  }

  return `${displayName} ${verb} ${events.length} ${noun}`;
}

function buildKillChainSummary(events: HumanizedEvent[]): string {
  const displayName = events[0].server_display_name;
  const blocked = events.filter(
    (e) => e.action_taken === "Blocked" || e.action_taken === "AutoBlocked"
  ).length;
  if (blocked > 0) {
    return `Threat story: ${displayName} attempted a suspicious pattern -- ${blocked} action${blocked > 1 ? "s" : ""} blocked`;
  }
  return `Threat story: ${displayName} triggered a suspicious pattern (${events.length} events)`;
}

function buildPromptSequenceSummary(events: HumanizedEvent[]): string {
  const displayName = events[0].server_display_name;
  const outcome = events.find(
    (e) => e.action_taken === "Allowed" || e.action_taken === "Blocked"
  );
  if (outcome) {
    const verb = outcome.action_taken === "Allowed" ? "allowed" : "blocked";
    return `You were asked about ${displayName} and ${verb} it`;
  }
  return `${displayName} requested permission`;
}

// ---------------------------------------------------------------------------
// Group Key
// ---------------------------------------------------------------------------

function pathPrefix(resource: string | null): string {
  if (!resource) return "";
  const parts = resource.split("/");
  return parts.slice(0, Math.min(parts.length - 1, 3)).join("/");
}

interface PendingCluster {
  key: string;
  windowStart: number;
  events: HumanizedEvent[];
}

// ---------------------------------------------------------------------------
// Main Grouping Function
// ---------------------------------------------------------------------------

export function groupEvents(events: HumanizedEvent[], now?: Date): EventGroup[] {
  const currentTime = now ?? new Date();

  // 1. Classify events into time periods
  const periodBuckets = new Map<TimePeriod, HumanizedEvent[]>();
  const periodOrder: TimePeriod[] = [
    "right_now",
    "earlier_today",
    "yesterday",
    "this_week",
    "older",
  ];

  for (const period of periodOrder) {
    periodBuckets.set(period, []);
  }

  for (const event of events) {
    const period = getTimePeriod(event.timestamp, currentTime);
    periodBuckets.get(period)!.push(event);
  }

  // 2. Within each period, cluster events
  const groups: EventGroup[] = [];
  let groupId = 0;

  for (const period of periodOrder) {
    const bucket = periodBuckets.get(period)!;
    if (bucket.length === 0) continue;

    // --- Kill chain groups: events sharing the same kill_chain_id ---
    const killChainMap = new Map<string, HumanizedEvent[]>();
    const promptSequences: HumanizedEvent[][] = [];
    const remaining: HumanizedEvent[] = [];

    for (const event of bucket) {
      if (event.kill_chain_id) {
        const existing = killChainMap.get(event.kill_chain_id);
        if (existing) {
          existing.push(event);
        } else {
          killChainMap.set(event.kill_chain_id, [event]);
        }
      } else {
        remaining.push(event);
      }
    }

    // Emit kill chain groups
    for (const [kcId, kcEvents] of killChainMap) {
      groupId++;
      groups.push({
        id: `g-${groupId}`,
        type: "kill_chain",
        period,
        representative: kcEvents[0],
        count: kcEvents.length,
        summary: buildKillChainSummary(kcEvents),
        children: kcEvents,
        kill_chain_id: kcId,
      });
    }

    // --- Prompt-decision-outcome sequences ---
    // Find prompted events and group them with their nearby outcome
    const promptIndices = new Set<number>();
    for (let i = 0; i < remaining.length; i++) {
      if (remaining[i].action_taken === "Prompted" && !promptIndices.has(i)) {
        const promptEvent = remaining[i];
        const promptTime = new Date(promptEvent.timestamp).getTime();
        const sequence: HumanizedEvent[] = [promptEvent];
        promptIndices.add(i);

        // Find outcome within 60s from same server
        for (let j = i + 1; j < remaining.length && j < i + 5; j++) {
          if (promptIndices.has(j)) continue;
          const candidate = remaining[j];
          if (
            candidate.server_display_name === promptEvent.server_display_name &&
            Math.abs(new Date(candidate.timestamp).getTime() - promptTime) <= 60_000
          ) {
            sequence.push(candidate);
            promptIndices.add(j);
            break;
          }
        }

        if (sequence.length > 1) {
          promptSequences.push(sequence);
        } else {
          // Single prompt with no outcome -- just let it flow to normal grouping
          promptIndices.delete(i);
        }
      }
    }

    // Emit prompt sequences
    for (const seq of promptSequences) {
      groupId++;
      groups.push({
        id: `g-${groupId}`,
        type: "prompt_sequence",
        period,
        representative: seq[0],
        count: seq.length,
        summary: buildPromptSequenceSummary(seq),
        children: seq,
      });
    }

    // --- Standard clustering on remaining events ---
    const standardEvents = remaining.filter((_, i) => !promptIndices.has(i));
    const clusters: PendingCluster[] = [];

    for (const event of standardEvents) {
      const eventTime = new Date(event.timestamp).getTime();
      const clusterKey = [
        event.server_display_name,
        event.raw_event.tool_name ?? "",
        event.raw_event.action,
        pathPrefix(event.raw_event.resource),
      ].join("|");

      let added = false;
      for (const cluster of clusters) {
        if (
          cluster.key === clusterKey &&
          Math.abs(eventTime - cluster.windowStart) <= GROUP_WINDOW_MS
        ) {
          cluster.events.push(event);
          added = true;
          break;
        }
      }

      if (!added) {
        clusters.push({
          key: clusterKey,
          windowStart: eventTime,
          events: [event],
        });
      }
    }

    // 3. Convert clusters to EventGroups
    for (const cluster of clusters) {
      groupId++;
      if (cluster.events.length === 1) {
        const event = cluster.events[0];
        groups.push({
          id: `g-${groupId}`,
          type: "single",
          period,
          representative: event,
          count: 1,
          summary: event.one_liner,
          children: [event],
        });
      } else {
        groups.push({
          id: `g-${groupId}`,
          type: "grouped",
          period,
          representative: cluster.events[0],
          count: cluster.events.length,
          summary: buildGroupSummary(cluster.events),
          children: cluster.events,
        });
      }
    }
  }

  return groups;
}
