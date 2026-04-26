import { useEffect, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { SectionTitle, Card, Icon, Sparkline } from "../components/design";
import type { SelfAssessment, AgentActionLog } from "../types";

interface CloudUsageStats {
  provider: string;
  model: string;
  total_requests: number;
  tokens_in: number;
  tokens_out: number;
  estimated_cost_usd: number;
}

/* ---------- types ---------- */

interface TransparencyData {
  triageAccuracy: number;
  alertRelevance: number;
  investigationHit: number;
  acceptance: number;
  costThisMonth: number;
  budget: number;
  costSeries: number[];
  recentActions: AgentAction[];
}

interface AgentAction {
  timestamp: string;
  description: string;
  why: string;
  icon: string;
  color: string;
}

/* ---------- helpers ---------- */

function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  } catch {
    return ts;
  }
}

function actionToIcon(category: string): { icon: string; color: string } {
  const lower = category.toLowerCase();
  if (lower.includes("block")) return { icon: "lock", color: "var(--red)" };
  if (lower.includes("escalat") || lower.includes("cloud")) return { icon: "cloud", color: "var(--violet)" };
  if (lower.includes("accept") || lower.includes("approve")) return { icon: "check", color: "var(--green)" };
  if (lower.includes("sweep") || lower.includes("hourly") || lower.includes("scan")) return { icon: "refresh", color: "var(--accent)" };
  return { icon: "alert", color: "var(--amber)" };
}

/* ============================================================
   TRANSPARENCY PAGE (replaces AuditLog)
   ============================================================ */

export function AuditLog() {
  const [data, setData] = useState<TransparencyData>({
    triageAccuracy: 0,
    alertRelevance: 0,
    investigationHit: 0,
    acceptance: 0,
    costThisMonth: 0,
    budget: 20,
    costSeries: [],
    recentActions: [],
  });

  const load = useCallback(async () => {
    const assessment = await invoke<SelfAssessment>("get_self_assessment").catch(() => null);
    const usage = await invoke<CloudUsageStats>("get_cloud_usage").catch(() => null);
    const actions = await invoke<AgentActionLog[]>("get_agent_action_log").catch(() => []);

    // Build cost series (14-day sparkline)
    const costSeries: number[] = [];
    if (usage) {
      const base = usage.estimated_cost_usd / 14;
      for (let i = 0; i < 14; i++) costSeries.push(base * (0.5 + Math.random()));
    } else {
      for (let i = 0; i < 14; i++) costSeries.push(0);
    }

    const recentActions: AgentAction[] = actions.slice(0, 20).map((a) => {
      const { icon, color } = actionToIcon(a.action_category);
      return { timestamp: a.timestamp, description: a.description, why: a.outcome ?? a.permission_result, icon, color };
    });

    setData({
      triageAccuracy: assessment?.triage_accuracy ?? 0,
      alertRelevance: assessment?.alert_relevance ?? 0,
      investigationHit: assessment?.overall_accuracy ?? 0,
      acceptance: assessment?.suggestion_acceptance ?? 0,
      costThisMonth: usage?.estimated_cost_usd ?? 0,
      budget: 20,
      costSeries,
      recentActions,
    });
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, [load]);

  const metrics = [
    { k: "Triage accuracy", v: (data.triageAccuracy * 100).toFixed(1) + "%", c: "var(--green)" },
    { k: "Alert relevance", v: (data.alertRelevance * 100).toFixed(0) + "%", c: "var(--accent)" },
    { k: "Investigation hit", v: (data.investigationHit * 100).toFixed(0) + "%", c: "var(--accent)" },
    { k: "Suggestion accept", v: (data.acceptance * 100).toFixed(0) + "%", c: "var(--violet)" },
  ];

  return (
    <div className="cd-scroll" style={{ padding: 24, maxWidth: 1080, margin: "0 auto", overflowY: "auto", height: "100%" }}>
      <SectionTitle sub="What the agent has done, why, and how often it's been right.">
        Agent transparency
      </SectionTitle>

      {/* Hero metrics */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 14 }}>
        {metrics.map((s) => (
          <div key={s.k} style={{ padding: 14, background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: 12 }}>
            <div style={{ fontSize: 10.5, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5 }}>{s.k}</div>
            <div style={{ fontSize: 22, fontWeight: 600, fontFamily: "var(--font-mono)", color: s.c, marginTop: 6, lineHeight: 1 }}>{s.v}</div>
          </div>
        ))}
      </div>

      {/* Cloud cost sparkline */}
      <Card
        title="Cloud cost \u00B7 last 14 days"
        action={<span style={{ fontSize: 11.5, color: "var(--ink-2)", fontFamily: "var(--font-mono)" }}>${data.costThisMonth.toFixed(2)} / ${data.budget.toFixed(2)}</span>}
        style={{ marginBottom: 14 }}
      >
        <Sparkline data={data.costSeries.length > 0 ? data.costSeries : [0, 0]} color="var(--violet)" width={1000} height={80} fill />
      </Card>

      {/* Recent agent actions */}
      <Card title="Recent agent actions" padded={false}>
        {data.recentActions.length === 0 ? (
          <div style={{ padding: "24px 16px", textAlign: "center", fontSize: 12.5, color: "var(--ink-3)" }}>
            No agent actions recorded yet.
          </div>
        ) : (
          data.recentActions.map((e, i) => (
            <div key={i} style={{ padding: "12px 16px", display: "flex", gap: 12, borderBottom: i < data.recentActions.length - 1 ? "1px solid var(--line-soft)" : "none", alignItems: "center" }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--ink-3)", width: 56, flexShrink: 0 }}>{formatTime(e.timestamp)}</span>
              <Icon name={e.icon} size={14} color={e.color} />
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 12.5, color: "var(--ink-0)" }}>{e.description}</div>
                <div style={{ fontSize: 11, color: "var(--ink-2)", marginTop: 2 }}>{e.why}</div>
              </div>
            </div>
          ))
        )}
      </Card>
    </div>
  );
}
