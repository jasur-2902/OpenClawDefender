import { useEffect, useState, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { useRefreshShortcut } from "../hooks/useKeyboardShortcuts";
import { useEventStore } from "../stores/eventStore";
import { useServerStore, type ServerInfo } from "../stores/serverStore";
import { useAppStore } from "../stores/appStore";
import { useConversationStore } from "../stores/conversationStore";
import { useTauriEvent } from "../hooks/useTauriEvent";
import { ProtectionScoreRing } from "../components/home/ProtectionScoreRing";
import { QuickStatCard } from "../components/home/QuickStatCard";
import { ScoreBreakdown } from "../components/home/ScoreBreakdown";
import { GuidanceAnchor } from "../components/guidance/GuidanceAnchor";
import { EMPTY_STATES } from "../constants/messages";
import { useToastStore } from "../components/notifications/ToastContainer";
import { useAiStatus } from "../hooks/useAiStatus";
import type {
  DaemonStatus,
  McpClient,
  GuardSummary,
  PendingPrompt,
  ProtectionScore,
  ScoreSnapshot,
} from "../types";

const POLL_INTERVAL = 30_000;

function isToday(timestamp: string): boolean {
  const d = new Date(timestamp);
  const now = new Date();
  return (
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate()
  );
}

function relativeTime(timestamp: string): string {
  const diff = Date.now() - new Date(timestamp).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

// --- Score Sparkline ---

function ScoreSparkline({
  history,
  onClick,
}: {
  history: ScoreSnapshot[];
  onClick?: () => void;
}) {
  if (history.length < 2) return null;

  const width = 120;
  const height = 30;
  const padding = 2;

  const scores = history.map((s) => s.score);
  const min = Math.min(...scores);
  const max = Math.max(...scores);
  const range = max - min || 1;

  const points = scores
    .map((s, i) => {
      const x = padding + (i / (scores.length - 1)) * (width - padding * 2);
      const y = height - padding - ((s - min) / range) * (height - padding * 2);
      return `${x},${y}`;
    })
    .join(" ");

  // Determine color based on trend
  const lastScore = scores[scores.length - 1];
  const firstScore = scores[0];
  let lineColor: string;
  if (lastScore < 50) {
    lineColor = "var(--color-danger)";
  } else if (lastScore < firstScore) {
    lineColor = "var(--color-warning)";
  } else {
    lineColor = "var(--color-safe)";
  }

  return (
    <button
      onClick={onClick}
      className="mt-2 bg-transparent border-none cursor-pointer p-1 rounded hover:bg-[var(--color-bg-tertiary)] transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--color-accent)]"
      aria-label="Score trend over last 7 days. Click for details."
    >
      <svg
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        role="img"
        aria-label="Score trend sparkline"
      >
        <polyline
          points={points}
          fill="none"
          stroke={lineColor}
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </button>
  );
}

// --- Main Home Component ---

export function Home() {
  const navigate = useNavigate();
  const events = useEventStore((s) => s.events);
  const setDaemonRunning = useEventStore((s) => s.setDaemonRunning);
  // addRawEvent handled by GlobalEventListener in App.tsx
  const addPrompt = useEventStore((s) => s.addPrompt);
  const fetchScore = useAppStore((s) => s.fetchScore);
  const fetchScoreHistory = useAppStore((s) => s.fetchScoreHistory);
  const score = useAppStore((s) => s.protectionScoreFull);
  const scoreHistory = useAppStore((s) => s.scoreHistory);
  const setProtectionScoreFull = useAppStore((s) => s.setProtectionScoreFull);
  const addToast = useToastStore((s) => s.addToast);
  const servers = useServerStore((s) => s.servers);
  const fetchServers = useServerStore((s) => s.fetchServers);
  const messages = useConversationStore((s) => s.messages);

  const [loading, setLoading] = useState(true);
  const [breakdownOpen, setBreakdownOpen] = useState(false);
  const [slmMockMode, setSlmMockMode] = useState(false);
  const { status: aiStatus, localActive, cloudActive } = useAiStatus();
  const [postureInfo, setPostureInfo] = useState<any>(null);
  const [latestSweep, setLatestSweep] = useState<any>(null);
  const [defenseScore, setDefenseScore] = useState<number | null>(null);
  const [knowledgeStats, setKnowledgeStats] = useState<any>(null);

  // Non-score home data (daemon, clients, guards, events)
  const [clients, setClients] = useState<McpClient[]>([]);
  const [guards, setGuards] = useState<GuardSummary[]>([]);

  // Fetch non-score data
  const fetchHomeData = useCallback(async () => {
    const results = await Promise.allSettled([
      invoke<DaemonStatus>("get_daemon_status"),
      invoke<McpClient[]>("detect_mcp_clients"),
      invoke<GuardSummary[]>("list_guards"),
    ]);

    const daemon = results[0].status === "fulfilled" ? results[0].value : null;
    const detectedClients = results[1].status === "fulfilled" ? results[1].value : [];
    const guardList = results[2].status === "fulfilled" ? results[2].value : [];

    if (daemon) {
      setDaemonRunning(daemon.running);
    }
    setClients(detectedClients);
    setGuards(guardList);
    fetchServers();
  }, [setDaemonRunning, fetchServers]);

  // Check SLM mock mode
  useEffect(() => {
    invoke<{ mock_mode?: boolean }>("get_slm_status")
      .then((s) => { if (s.mock_mode) setSlmMockMode(true); else setSlmMockMode(false); })
      .catch(() => {});
  }, []);

  // Load proactive monitoring data
  useEffect(() => {
    async function loadProactiveData() {
      try {
        const posture = await invoke("get_threat_posture");
        setPostureInfo(posture);
      } catch { /* ignore */ }
      try {
        const history = await invoke<any[]>("get_schedule_history", { id: "hourly_sweep", count: 1 });
        if (Array.isArray(history) && history.length > 0) {
          setLatestSweep(history[0]);
        }
      } catch { /* ignore */ }
      try {
        const score = await invoke<number | null>("get_defense_score");
        setDefenseScore(score);
      } catch { /* ignore */ }
      try {
        const stats = await invoke("get_knowledge_stats");
        setKnowledgeStats(stats);
      } catch { /* ignore */ }
    }
    loadProactiveData();
  }, []);

  // Cmd+R refreshes all home data (force bypass TTL cache)
  const refreshAll = useCallback(() => {
    fetchScore(true);
    fetchScoreHistory(true);
    fetchHomeData();
  }, [fetchScore, fetchScoreHistory, fetchHomeData]);
  useRefreshShortcut(refreshAll);

  // Initial load — uses TTL cache so re-navigations skip redundant IPC
  useEffect(() => {
    Promise.all([fetchScore(), fetchScoreHistory(), fetchHomeData()]).then(() =>
      setLoading(false)
    );
  }, [fetchScore, fetchScoreHistory, fetchHomeData]);

  // Poll non-score data periodically
  useEffect(() => {
    const interval = setInterval(fetchHomeData, POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchHomeData]);

  // --- Real-time score updates ---
  const handleScoreChanged = useCallback(
    (payload: ProtectionScore) => {
      setProtectionScoreFull(payload);
    },
    [setProtectionScoreFull]
  );
  useTauriEvent<ProtectionScore>("clawdefender://score-changed", handleScoreChanged);

  // Other Tauri events (clawdefender://event handled by GlobalEventListener in App.tsx)
  const handleStatusChange = useCallback(
    (payload: { daemon_running: boolean }) => {
      setDaemonRunning(payload.daemon_running);
      fetchHomeData();
      fetchScore();
    },
    [setDaemonRunning, fetchHomeData, fetchScore]
  );
  const handlePrompt = useCallback(
    (payload: PendingPrompt) => addPrompt(payload),
    [addPrompt]
  );
  useTauriEvent<{ daemon_running: boolean }>(
    "clawdefender://status-change",
    handleStatusChange
  );
  useTauriEvent<PendingPrompt>("clawdefender://prompt", handlePrompt);

  // --- Computed values ---
  const todayEvents = useMemo(
    () => events.filter((e) => isToday(e.timestamp)),
    [events]
  );
  const todayBlocked = useMemo(
    () =>
      todayEvents.filter(
        (e) => e.action_taken === "Blocked" || e.action_taken === "AutoBlocked"
      ).length,
    [todayEvents]
  );

  const highestAnomaly = useMemo(() => {
    const oneHourAgo = Date.now() - 3_600_000;
    const recent = events.filter(
      (e) => new Date(e.timestamp).getTime() > oneHourAgo
    );
    const riskMap: Record<string, number> = {
      dangerous: 0.95,
      suspicious: 0.8,
      unusual: 0.5,
      blocked: 0.7,
      normal: 0.2,
      info: 0.1,
    };
    let highest = 0;
    let serverName = "";
    for (const e of recent) {
      const s = riskMap[e.risk_level] ?? 0;
      if (s > highest) {
        highest = s;
        serverName = e.server_display_name;
      }
    }
    return { score: highest, serverName };
  }, [events]);

  const activeGuardsCount = useMemo(
    () => guards.filter((g) => g.enabled).length,
    [guards]
  );

  const monitoringSubtitle = useMemo(() => {
    const serverCount = Math.max(0, servers.length);
    const clientNames = clients
      .filter((c) => c.detected)
      .map((c) => c.display_name)
      .slice(0, 3);
    if (serverCount === 0 && clientNames.length === 0) {
      return "No AI tools detected yet";
    }
    const appPart =
      clientNames.length > 0 ? ` across ${clientNames.join(", ")}` : "";
    return `Monitoring ${serverCount} server${serverCount !== 1 ? "s" : ""}${appPart}`;
  }, [servers, clients]);

  // Recent Claw messages
  const recentClawMessages = useMemo(() => {
    return messages
      .filter((m) => m.role === "claw" && m.intentId === "proactive.alert")
      .slice(-5)
      .reverse();
  }, [messages]);

  // Pending actions: derived from score factors where status != "full"
  const pendingActions = useMemo(() => {
    if (!score) return [];
    return score.factors
      .filter((f) => f.status !== "full" && f.fix_actions && f.fix_actions.length > 0)
      .map((f) => ({
        label: f.fix_actions[0].label,
        description: f.details,
        factorId: f.id,
        actionIndex: 0,
        actionType: f.fix_actions[0].action_type,
        target: f.fix_actions[0].target,
      }));
  }, [score]);

  const allClear = score != null && score.factors.every((f) => f.status === "full");

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <h1 className="sr-only">Home — ClawDefender</h1>

      {/* Section 1: Protection Status Hero */}
      <section
        aria-label="Protection status"
        className="flex flex-col items-center py-8 rounded-xl bg-[var(--color-bg-secondary)] border border-[var(--color-border)]"
      >
        {loading || !score ? (
          <div className="flex flex-col items-center gap-4">
            <div className="w-[180px] h-[180px] rounded-full bg-[var(--color-bg-tertiary)] animate-pulse" />
            <div className="h-5 w-32 rounded bg-[var(--color-bg-tertiary)] animate-pulse" />
            <div className="h-4 w-48 rounded bg-[var(--color-bg-tertiary)] animate-pulse" />
          </div>
        ) : (
          <>
            <ProtectionScoreRing
              score={score.total}
              label={score.label}
              color={score.color}
              changeFromLast={score.change_from_last}
              onClick={() => setBreakdownOpen(true)}
              aria-expanded={breakdownOpen}
            />
            <ScoreSparkline
              history={scoreHistory}
              onClick={() => setBreakdownOpen(true)}
            />
            <p className="mt-3 text-sm text-[var(--color-text-secondary)] text-center max-w-sm">
              {monitoringSubtitle}
            </p>
            <div className="flex items-center gap-3 text-sm mt-2">
              <div className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${localActive ? 'bg-[var(--color-success)]' : 'bg-[var(--color-text-secondary)]'}`} />
                <span className="text-[var(--color-text-secondary)]">
                  Local: {aiStatus?.local.active ? aiStatus.local.model_name : 'Not loaded'}
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${cloudActive ? 'bg-[var(--color-success)]' : 'bg-[var(--color-text-secondary)]'}`} />
                <span className="text-[var(--color-text-secondary)]">
                  Cloud: {aiStatus?.cloud.active ? aiStatus.cloud.provider : 'Not configured'}
                </span>
              </div>
            </div>
            {!localActive && !cloudActive && (
              <button
                onClick={() => navigate("/settings")}
                className="mt-2 text-xs text-[var(--color-accent)] hover:underline"
              >
                Set up AI analysis in Settings for real-time security monitoring.
              </button>
            )}
          </>
        )}
      </section>

      {/* SLM Mock Mode Warning Banner */}
      {slmMockMode && (
        <section
          aria-label="AI analysis warning"
          className="flex items-center justify-between px-4 py-3 rounded-xl bg-[var(--color-warning-subtle)] border border-[var(--color-warning-border)]"
        >
          <p className="text-sm text-[var(--color-warning)]">
            AI analysis is running in basic mode. Download a model for full protection.
          </p>
          <button
            onClick={() => navigate("/settings")}
            className="text-sm font-medium text-[var(--color-warning)] hover:text-[var(--color-warning-dark)] whitespace-nowrap ml-4"
          >
            Set up now &rarr;
          </button>
        </section>
      )}

      {/* Section 2: Quick Stats Row */}
      <section
        aria-label="Quick statistics"
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4"
      >
        <QuickStatCard
          label="Events Today"
          value={todayEvents.length}
          navigateTo="/activity"
          loading={loading}
        />
        <QuickStatCard
          label="Blocked"
          value={todayBlocked}
          color="var(--color-danger)"
          navigateTo="/activity"
          loading={loading}
        />
        <QuickStatCard
          label="Highest Anomaly"
          value={
            highestAnomaly.score > 0.4
              ? highestAnomaly.serverName
              : "All Normal"
          }
          color={
            highestAnomaly.score >= 0.7
              ? "var(--color-danger)"
              : highestAnomaly.score >= 0.4
                ? "var(--color-warning)"
                : "var(--color-safe)"
          }
          navigateTo="/activity"
          loading={loading}
        />
        <QuickStatCard
          label="Active Guards"
          value={activeGuardsCount}
          color="var(--color-accent)"
          navigateTo="/tools"
          loading={loading}
        />
      </section>

      {/* Welcome message for first use (no events yet) */}
      {!loading && events.length === 0 && (
        <section
          aria-label="Welcome"
          className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-5"
        >
          <p className="text-sm text-[var(--color-text-primary)] mb-2">
            All set. I'm watching over your AI tools. If I need you, I'll let you know.
          </p>
          <p className="text-xs text-[var(--color-text-muted)]">
            Try using Claude Desktop or Cursor -- you'll see their activity appear here in real-time.
          </p>
        </section>
      )}

      {/* Section 3: Recent Claw Messages */}
      <section
        aria-label="Recent messages from Claw"
        className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4"
      >
        <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide mb-3">
          Recent Messages
        </h2>
        {recentClawMessages.length === 0 ? (
          <p className="text-sm text-[var(--color-text-muted)] py-2">
            I'll keep you posted here when something important happens.
          </p>
        ) : (
          <div className="space-y-2">
            {recentClawMessages.map((msg) => (
              <button
                key={msg.id}
                onClick={() => navigate("/ask")}
                className="w-full text-left flex items-start gap-3 p-3 rounded-lg hover:bg-[var(--color-bg-tertiary)] transition-colors cursor-pointer bg-transparent border-none"
              >
                <span className="text-xs text-[var(--color-text-muted)] whitespace-nowrap mt-0.5">
                  {relativeTime(msg.timestamp)}
                </span>
                <span className="text-sm text-[var(--color-text-primary)] line-clamp-2 flex-1">
                  {msg.contentText}
                </span>
              </button>
            ))}
          </div>
        )}
      </section>

      {/* Section: Proactive Monitoring */}
      <section aria-label="Proactive monitoring" className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Threat Posture */}
        <div
          className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4 cursor-pointer hover:border-[var(--color-accent-subtle)] transition-colors"
          onClick={() => navigate("/settings")}
        >
          <div className="flex items-center gap-2 mb-2">
            <span
              className="inline-block w-3 h-3 rounded-full"
              style={{
                backgroundColor: postureInfo
                  ? postureInfo.color === "green" ? "var(--color-success)"
                  : postureInfo.color === "yellow" ? "var(--color-warning)"
                  : postureInfo.color === "orange" ? "#f97316"
                  : postureInfo.color === "red" ? "var(--color-danger)"
                  : "var(--color-success)"
                  : "var(--color-text-muted)",
              }}
            />
            <span className="text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wide">
              Posture
            </span>
          </div>
          <span className="text-lg font-bold text-[var(--color-text-primary)]">
            {postureInfo?.level_name || "Normal"}
          </span>
          <p className="text-xs text-[var(--color-text-muted)] mt-1 truncate">
            {postureInfo?.reason || "Standard operation"}
          </p>
        </div>

        {/* Hourly Sweep */}
        <div className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4">
          <span className="text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wide">
            Last Sweep
          </span>
          <p className="text-sm font-semibold text-[var(--color-text-primary)] mt-2">
            {latestSweep
              ? latestSweep.status === "all_clear"
                ? "All Clear"
                : latestSweep.status === "needs_attention"
                ? "Needs Attention"
                : "Concerning"
              : "Pending..."}
          </p>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">
            {latestSweep
              ? `${latestSweep.suspicious_count} suspicious`
              : "No sweeps yet"}
          </p>
        </div>

        {/* Defense Score */}
        <div
          className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4 cursor-pointer hover:border-[var(--color-accent-subtle)] transition-colors"
          onClick={async () => {
            try {
              await invoke("run_threat_simulation");
              const score = await invoke<number | null>("get_defense_score");
              setDefenseScore(score);
            } catch { /* ignore */ }
          }}
        >
          <span className="text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wide">
            Defense Score
          </span>
          <p className="text-lg font-bold text-[var(--color-text-primary)] mt-2">
            {defenseScore !== null ? `${Math.round(defenseScore)}%` : "---"}
          </p>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">
            Click to run simulation
          </p>
        </div>

        {/* Knowledge Base */}
        <div className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4">
          <span className="text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wide">
            Agent Knowledge
          </span>
          <p className="text-sm font-semibold text-[var(--color-text-primary)] mt-2">
            {knowledgeStats ? `${knowledgeStats.total_entries} entries` : "---"}
          </p>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">
            {knowledgeStats
              ? `${knowledgeStats.server_count} servers, ${knowledgeStats.learned_pattern_count} patterns`
              : "Loading..."}
          </p>
        </div>
      </section>

      {/* Section 4: Server Overview */}
      <section aria-label="Server overview">
        <GuidanceAnchor id="home-server-overview" />
        <GuidanceAnchor id="server-section" />
        <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide mb-3">
          Server Overview
        </h2>
        {loading ? (
          <div className="flex gap-4 overflow-x-auto pb-2">
            {[1, 2, 3].map((i) => (
              <div
                key={i}
                className="shrink-0 w-56 h-28 rounded-xl bg-[var(--color-bg-secondary)] border border-[var(--color-border)] animate-pulse"
              />
            ))}
          </div>
        ) : servers.length === 0 ? (
          <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-6 text-center">
            <p className="text-sm text-[var(--color-text-secondary)]">
              {EMPTY_STATES.myTools.headline}
            </p>
            <p className="text-xs text-[var(--color-text-muted)] mt-1">
              {EMPTY_STATES.myTools.body}
            </p>
          </div>
        ) : (
          <div className="flex gap-4 overflow-x-auto pb-2">
            {servers.map((srv) => (
              <ServerMiniCard key={srv.name} server={srv} />
            ))}
          </div>
        )}
      </section>

      {/* Section 5: Quick Actions */}
      <section aria-label="Quick actions" className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        <button
          onClick={() => navigate("/investigations")}
          className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4 text-left hover:border-[var(--color-accent-subtle)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
        >
          <span className="text-sm font-medium text-[var(--color-text-primary)]">Threat Hunt</span>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">
            Proactive AI-powered threat sweep
          </p>
        </button>
        <button
          onClick={() => navigate("/scanner")}
          className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4 text-left hover:border-[var(--color-accent-subtle)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
        >
          <span className="text-sm font-medium text-[var(--color-text-primary)]">Security Scan</span>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">
            AI-driven security assessment
          </p>
        </button>
        <button
          onClick={() => navigate("/ask")}
          className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4 text-left hover:border-[var(--color-accent-subtle)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
        >
          <span className="text-sm font-medium text-[var(--color-text-primary)]">Ask Claw</span>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">
            Ask anything about your security
          </p>
        </button>
      </section>

      {/* Section 6: Pending Actions */}
      <section aria-label="Pending actions">
        <GuidanceAnchor id="home-pending-actions" />
        <GuidanceAnchor id="pending-actions" />
        {pendingActions.length > 0 && !allClear ? (
          <div className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-warning-border)] p-4">
            <h2 className="text-sm font-semibold text-[var(--color-warning)] uppercase tracking-wide mb-3">
              Pending Actions
            </h2>
            <div className="space-y-2">
              {pendingActions.map((action) => (
                <div
                  key={action.factorId}
                  className="flex items-center justify-between p-2 rounded-lg"
                >
                  <div className="flex-1 min-w-0">
                    <span className="text-sm text-[var(--color-text-primary)]">
                      {action.label}
                    </span>
                    <p className="text-xs text-[var(--color-text-muted)] mt-0.5 truncate">
                      {action.description}
                    </p>
                  </div>
                  {action.actionType === "navigate" ? (
                    <button
                      onClick={() => navigate(action.target)}
                      className="text-xs font-medium text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] ml-2 whitespace-nowrap"
                      aria-label={`Fix: ${action.label}`}
                    >
                      Fix
                    </button>
                  ) : (
                    <button
                      onClick={async () => {
                        try {
                          await invoke("execute_fix_action", {
                            factorId: action.factorId,
                            actionIndex: action.actionIndex,
                          });
                          addToast({ title: "Done.", severity: "success" });
                        } catch {
                          addToast({
                            title: "Could not complete that action. Try again in a moment.",
                            severity: "warning",
                          });
                        }
                      }}
                      className="text-xs font-medium text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] ml-2 whitespace-nowrap"
                      aria-label={`Fix: ${action.label}`}
                    >
                      Fix
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        ) : !loading ? (
          <div className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-safe-border)] p-4 flex items-center gap-3">
            <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-[var(--color-safe-subtle)] text-[var(--color-safe)] text-sm">
              &#10003;
            </span>
            <span className="text-sm text-[var(--color-text-primary)]">
              Everything looks good.
            </span>
          </div>
        ) : null}
      </section>

      {/* Score Breakdown Drawer */}
      {score && (
        <ScoreBreakdown
          open={breakdownOpen}
          onClose={() => setBreakdownOpen(false)}
          factors={score.factors}
          totalScore={score.total}
        />
      )}
    </div>
  );
}

function ServerMiniCard({ server }: { server: ServerInfo }) {
  const navigate = useNavigate();

  const trustColor = useMemo(() => {
    const level = server.trustLevel?.toLowerCase() ?? "";
    if (level === "high" || level === "trusted") return "var(--color-safe)";
    if (level === "medium") return "var(--color-warning)";
    if (level === "low" || level === "untrusted") return "var(--color-danger)";
    return "var(--color-text-secondary)";
  }, [server.trustLevel]);

  const anomalyColor = useMemo(() => {
    const s = server.anomalyScore ?? 0;
    if (s >= 0.7) return "var(--color-danger)";
    if (s >= 0.4) return "var(--color-warning)";
    return "var(--color-safe)";
  }, [server.anomalyScore]);

  const statusText = useMemo(() => {
    if (server.status === "running") {
      return `Active \u00b7 ${server.eventCount} actions`;
    }
    return server.status;
  }, [server.status, server.eventCount]);

  return (
    <button
      onClick={() => navigate(`/tools/${server.name}`)}
      className="shrink-0 w-56 bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4 text-left cursor-pointer hover:border-[var(--color-accent-subtle)] hover:bg-[var(--color-bg-tertiary)] transition-colors"
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-medium text-[var(--color-text-primary)] truncate">
          {server.name}
        </span>
        <span
          className="inline-block w-2 h-2 rounded-full shrink-0 ml-2"
          style={{ backgroundColor: anomalyColor }}
          aria-label={`Anomaly: ${(server.anomalyScore ?? 0) >= 0.7 ? "high" : (server.anomalyScore ?? 0) >= 0.4 ? "medium" : "normal"}`}
        />
      </div>
      <p className="text-xs text-[var(--color-text-muted)] truncate mb-2">
        {server.clientName}
      </p>
      <div className="flex items-center justify-between">
        <span className="text-xs text-[var(--color-text-secondary)]">
          {statusText}
        </span>
        {server.trustLevel && (
          <span
            className="text-[10px] font-medium px-1.5 py-0.5 rounded-full uppercase tracking-wider"
            style={{
              color: trustColor,
              backgroundColor: `color-mix(in srgb, ${trustColor} 15%, transparent)`,
            }}
          >
            {server.trustLevel}
          </span>
        )}
      </div>
    </button>
  );
}
