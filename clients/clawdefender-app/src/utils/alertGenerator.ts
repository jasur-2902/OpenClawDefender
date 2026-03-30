/**
 * Alert Generator
 *
 * Takes events from eventStore, identifies alert-worthy events,
 * deduplicates them, and populates alertStore.
 */

import type { AuditEvent } from "../types/index";
/** Legacy Alert type -- kept for backward compatibility with alertGenerator */
interface Alert {
  id: string;
  severity: string;
  title: string;
  description: string;
  timestamp: string;
  resolved: boolean;
  eventId?: string;
  serverName?: string;
  decision?: string;
  category?: string;
}

export type AlertSeverity = "dangerous" | "suspicious" | "unusual";

interface GeneratedAlert {
  id: string;
  severity: AlertSeverity;
  title: string;
  description: string;
  timestamp: string;
  resolved: boolean;
  eventId: string;
  serverName: string;
  decision: string;
  category: "block" | "kill_chain" | "uncorrelated" | "ioc" | "auto_block" | "high_risk";
}

function normalizeDecision(d: string): string {
  const lower = d.toLowerCase();
  if (lower === "blocked" || lower === "block" || lower === "denied" || lower === "deny") return "blocked";
  if (lower === "allowed" || lower === "allow") return "allowed";
  if (lower === "prompted" || lower === "prompt") return "prompted";
  return lower;
}

function generateTitle(event: AuditEvent): string {
  const server = event.server_name || "An unknown server";
  const tool = event.tool_name || "an action";
  const resource = event.resource || "";

  if (resource.includes(".ssh")) {
    return `${server} tried to read your SSH keys`;
  }
  if (resource.includes(".aws/credentials")) {
    return `${server} tried to access your AWS credentials`;
  }
  if (resource.includes(".env")) {
    return `${server} tried to read environment secrets`;
  }
  if (resource.includes("passwords") || resource.includes("cookies")) {
    return `${server} tried to access browser data`;
  }
  if (event.details.toLowerCase().includes("kill chain")) {
    return `Multi-step attack pattern detected from ${server}`;
  }
  if (event.details.toLowerCase().includes("injection")) {
    return `Prompt injection attempt from ${server}`;
  }
  if (event.details.toLowerCase().includes("exfiltration")) {
    return `Data exfiltration attempt from ${server}`;
  }

  const decision = normalizeDecision(event.decision);
  if (decision === "blocked") {
    return `${server} was blocked from using ${tool}`;
  }

  return `${server} did something unusual with ${tool}`;
}

function getSeverity(event: AuditEvent): AlertSeverity {
  if (event.risk_level === "critical") return "dangerous";
  if (event.risk_level === "high") return "suspicious";
  return "unusual";
}

function getCategory(event: AuditEvent): GeneratedAlert["category"] {
  const details = event.details.toLowerCase();
  if (details.includes("kill chain")) return "kill_chain";
  if (details.includes("uncorrelated")) return "uncorrelated";
  if (details.includes("ioc") || details.includes("indicator")) return "ioc";
  if (details.includes("auto-block") || details.includes("auto block")) return "auto_block";
  if (normalizeDecision(event.decision) === "blocked") return "block";
  return "high_risk";
}

function getActionDescription(event: AuditEvent): string {
  const decision = normalizeDecision(event.decision);
  if (decision === "blocked") return "Blocked";
  if (decision === "prompted") return "Flagged for review";
  return "Logged";
}

function deduplicationKey(event: AuditEvent): string {
  return `${event.server_name}:${event.tool_name || event.action}`;
}

/**
 * Given a list of events, returns alert-worthy ones that are deduplicated
 * (same server + same action within 5 minutes = one alert).
 */
export function generateAlerts(events: AuditEvent[]): GeneratedAlert[] {
  const alertWorthy = events.filter((e) => {
    if (e.risk_level === "critical" || e.risk_level === "high") return true;
    const decision = normalizeDecision(e.decision);
    if (decision === "blocked") return true;
    const details = e.details.toLowerCase();
    if (details.includes("kill chain")) return true;
    if (details.includes("uncorrelated")) return true;
    if (details.includes("ioc")) return true;
    return false;
  });

  // Deduplicate: same server + action within 5 minutes = one alert
  const DEDUP_WINDOW_MS = 5 * 60 * 1000;
  const seen = new Map<string, number>();
  const deduped: AuditEvent[] = [];

  for (const event of alertWorthy) {
    const key = deduplicationKey(event);
    const eventTime = new Date(event.timestamp).getTime();
    const lastSeen = seen.get(key);

    if (lastSeen !== undefined && eventTime - lastSeen < DEDUP_WINDOW_MS) {
      continue;
    }

    seen.set(key, eventTime);
    deduped.push(event);
  }

  return deduped.map((event) => ({
    id: `alert-${event.id}`,
    severity: getSeverity(event),
    title: generateTitle(event),
    description: `${getActionDescription(event)}. ${event.details}`,
    timestamp: event.timestamp,
    resolved: false,
    eventId: event.id,
    serverName: event.server_name,
    decision: normalizeDecision(event.decision),
    category: getCategory(event),
  }));
}

/**
 * Merge new alerts into existing ones, avoiding duplicates by eventId.
 */
export function mergeAlerts(existing: Alert[], incoming: GeneratedAlert[]): Alert[] {
  const existingEventIds = new Set(existing.map((a) => a.eventId).filter(Boolean));
  const newAlerts = incoming.filter((a) => !existingEventIds.has(a.eventId));
  return [...newAlerts, ...existing];
}
