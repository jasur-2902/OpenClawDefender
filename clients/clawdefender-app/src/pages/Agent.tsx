import { useEffect, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type {
  AutonomyInfo,
  DashboardSummary,
  ResponsePlaybook,
  FeedbackStats,
  SelfAssessment,
  GeneratedReport,
  DecisionExplanation,
} from "../types";

type Tab = "overview" | "autonomy" | "playbooks" | "reports" | "decisions";

export function Agent() {
  const [tab, setTab] = useState<Tab>("overview");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Overview data
  const [dashboard, setDashboard] = useState<DashboardSummary | null>(null);
  const [autonomy, setAutonomy] = useState<AutonomyInfo | null>(null);
  const [feedbackStats, setFeedbackStats] = useState<FeedbackStats | null>(null);
  const [selfAssessment, setSelfAssessment] = useState<SelfAssessment | null>(null);

  // Tab-specific data
  const [playbooks, setPlaybooks] = useState<ResponsePlaybook[]>([]);
  const [reports, setReports] = useState<GeneratedReport[]>([]);
  const [decisions, setDecisions] = useState<DecisionExplanation[]>([]);

  const loadOverview = useCallback(async () => {
    try {
      const [dash, auto, fb, sa] = await Promise.all([
        invoke<DashboardSummary>("get_dashboard_summary"),
        invoke<AutonomyInfo>("get_autonomy_level"),
        invoke<FeedbackStats>("get_feedback_stats"),
        invoke<SelfAssessment>("get_self_assessment"),
      ]);
      setDashboard(dash);
      setAutonomy(auto);
      setFeedbackStats(fb);
      setSelfAssessment(sa);
      setError(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadOverview();
  }, [loadOverview]);

  useEffect(() => {
    if (tab === "playbooks" && playbooks.length === 0) {
      invoke<ResponsePlaybook[]>("list_response_playbooks")
        .then(setPlaybooks)
        .catch(() => {});
    }
    if (tab === "reports" && reports.length === 0) {
      invoke<GeneratedReport[]>("list_reports")
        .then(setReports)
        .catch(() => {});
    }
    if (tab === "decisions" && decisions.length === 0) {
      invoke<DecisionExplanation[]>("get_decision_explanations")
        .then(setDecisions)
        .catch(() => {});
    }
  }, [tab, playbooks.length, reports.length, decisions.length]);

  async function setLevel(level: string) {
    try {
      await invoke("set_autonomy_level", { level });
      const auto = await invoke<AutonomyInfo>("get_autonomy_level");
      setAutonomy(auto);
    } catch (e) {
      setError(String(e));
    }
  }

  async function toggleLockdown() {
    if (!autonomy) return;
    try {
      if (autonomy.is_locked_down) {
        await invoke("deactivate_lockdown");
      } else {
        await invoke("activate_lockdown", { reason: "Manual lockdown from GUI" });
      }
      const auto = await invoke<AutonomyInfo>("get_autonomy_level");
      setAutonomy(auto);
    } catch (e) {
      setError(String(e));
    }
  }

  const tabs: { id: Tab; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "autonomy", label: "Autonomy" },
    { id: "playbooks", label: "Playbooks" },
    { id: "reports", label: "Reports" },
    { id: "decisions", label: "Decisions" },
  ];

  const autonomyLevels = [
    { id: "L0ObserveOnly", label: "L0 — Observe", desc: "Monitor only, no actions" },
    { id: "L1Recommend", label: "L1 — Recommend", desc: "Suggest actions, user decides" },
    { id: "L2ActWithApproval", label: "L2 — Act + Approval", desc: "Act with countdown/approval" },
    { id: "L3FullAuto", label: "L3 — Full Auto", desc: "Autonomous actions on low-risk" },
  ];

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Agent</h1>
        {autonomy && (
          <div className="flex items-center gap-3">
            {autonomy.is_locked_down && (
              <span className="px-2.5 py-0.5 rounded-full text-xs font-medium text-[var(--color-danger)] bg-[var(--color-danger)]/20">
                LOCKDOWN
              </span>
            )}
            <span className="text-sm text-[var(--color-text-secondary)]">
              {autonomy.global_level}
            </span>
          </div>
        )}
      </div>

      {error && (
        <div className="rounded-lg border border-[var(--color-danger)] bg-[var(--color-danger)]/10 p-4 text-sm text-[var(--color-danger)]">
          {error}
        </div>
      )}

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-[var(--color-border)]">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              tab === t.id
                ? "border-[var(--color-accent)] text-[var(--color-accent)]"
                : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin w-6 h-6 border-2 border-[var(--color-accent)] border-t-transparent rounded-full" />
        </div>
      ) : (
        <>
          {tab === "overview" && dashboard && (
            <OverviewTab
              dashboard={dashboard}
              autonomy={autonomy}
              feedbackStats={feedbackStats}
              selfAssessment={selfAssessment}
            />
          )}
          {tab === "autonomy" && autonomy && (
            <AutonomyTab
              autonomy={autonomy}
              levels={autonomyLevels}
              onSetLevel={setLevel}
              onToggleLockdown={toggleLockdown}
            />
          )}
          {tab === "playbooks" && <PlaybooksTab playbooks={playbooks} />}
          {tab === "reports" && <ReportsTab reports={reports} />}
          {tab === "decisions" && <DecisionsTab decisions={decisions} />}
        </>
      )}
    </div>
  );
}

/* ─── Overview Tab ─── */

function OverviewTab({
  dashboard,
  autonomy,
  feedbackStats,
  selfAssessment,
}: {
  dashboard: DashboardSummary;
  autonomy: AutonomyInfo | null;
  feedbackStats: FeedbackStats | null;
  selfAssessment: SelfAssessment | null;
}) {
  return (
    <div className="space-y-6">
      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          label="Activities"
          value={dashboard.activity_summary.total}
          sub={`${dashboard.activity_summary.last_24h} last 24h`}
        />
        <StatCard
          label="Operations"
          value={dashboard.cost_summary.total_operations}
          sub={`avg ${Math.round(dashboard.cost_summary.avg_duration_ms)}ms`}
        />
        <StatCard
          label="Accuracy"
          value={`${Math.round(dashboard.accuracy_metrics.accuracy_rate * 100)}%`}
          sub={`${dashboard.accuracy_metrics.total_assessments} assessments`}
        />
        <StatCard
          label="Patterns"
          value={dashboard.pattern_stats.total_learned}
          sub={`${dashboard.pattern_stats.safe_count} safe, ${dashboard.pattern_stats.risk_count} risk`}
        />
      </div>

      {/* Autonomy + Accuracy row */}
      <div className="grid grid-cols-2 gap-4">
        {autonomy && (
          <Card title="Autonomy">
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-[var(--color-text-secondary)]">Level</span>
                <span>{autonomy.global_level}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--color-text-secondary)]">Actions</span>
                <span>{autonomy.stats.total_actions}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--color-text-secondary)]">Approval Rate</span>
                <span>{Math.round(autonomy.stats.approval_rate * 100)}%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--color-text-secondary)]">Auto Executed</span>
                <span>{autonomy.stats.auto_executed}</span>
              </div>
            </div>
          </Card>
        )}

        {selfAssessment && (
          <Card title="Self Assessment">
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-[var(--color-text-secondary)]">Overall Accuracy</span>
                <span>{Math.round(selfAssessment.overall_accuracy * 100)}%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--color-text-secondary)]">Triage Accuracy</span>
                <span>{Math.round(selfAssessment.triage_accuracy * 100)}%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--color-text-secondary)]">Alert Relevance</span>
                <span>{Math.round(selfAssessment.alert_relevance * 100)}%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--color-text-secondary)]">Trend</span>
                <span className={selfAssessment.trend === "improving" ? "text-[var(--color-success)]" : "text-[var(--color-text-primary)]"}>
                  {selfAssessment.trend}
                </span>
              </div>
              {(selfAssessment.areas_for_improvement?.length ?? 0) > 0 && (
                <div className="pt-1 border-t border-[var(--color-border)]">
                  <span className="text-[var(--color-text-secondary)]">Improve:</span>
                  <ul className="mt-1 list-disc list-inside text-xs text-[var(--color-text-secondary)]">
                    {selfAssessment.areas_for_improvement!.map((a, i) => (
                      <li key={i}>{a}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </Card>
        )}
      </div>

      {/* Audit summary */}
      <Card title="Audit Summary">
        <div className="grid grid-cols-4 gap-4 text-sm">
          <MiniStat label="Permissions Requested" value={dashboard.audit_summary.permissions_requested} />
          <MiniStat label="Granted" value={dashboard.audit_summary.permissions_granted} />
          <MiniStat label="Denied" value={dashboard.audit_summary.permissions_denied} />
          <MiniStat label="Lockdowns" value={dashboard.audit_summary.lockdowns_activated} />
        </div>
      </Card>

      {/* Recent decisions */}
      {dashboard.recent_decisions.length > 0 && (
        <Card title="Recent Decisions">
          <div className="space-y-3">
            {dashboard.recent_decisions.slice(0, 5).map((d) => (
              <div key={d.id} className="p-3 rounded-md bg-[var(--color-bg-tertiary)]">
                <div className="flex items-center justify-between text-sm">
                  <span className="font-medium">{d.decision_type}</span>
                  <span className="text-xs text-[var(--color-text-secondary)]">
                    {new Date(d.timestamp).toLocaleString()}
                  </span>
                </div>
                <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{d.conclusion}</p>
                <div className="mt-1 flex items-center gap-2 text-xs text-[var(--color-text-secondary)]">
                  <span>Confidence: {Math.round(d.confidence * 100)}%</span>
                  {d.server_name && <span>| {d.server_name}</span>}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Feedback stats */}
      {feedbackStats && (
        <Card title="Feedback">
          <div className="grid grid-cols-3 gap-4 text-sm">
            <MiniStat label="Triage Overrides" value={feedbackStats.triage_override_count} />
            <MiniStat label="Alert Dismissals" value={feedbackStats.alert_dismissal_count} />
            <MiniStat
              label="Suggestion Approval"
              value={`${Math.round(feedbackStats.suggestion_approval_rate * 100)}%`}
            />
          </div>
        </Card>
      )}
    </div>
  );
}

/* ─── Autonomy Tab ─── */

function AutonomyTab({
  autonomy,
  levels,
  onSetLevel,
  onToggleLockdown,
}: {
  autonomy: AutonomyInfo;
  levels: { id: string; label: string; desc: string }[];
  onSetLevel: (level: string) => void;
  onToggleLockdown: () => void;
}) {
  return (
    <div className="space-y-6">
      {/* Lockdown banner */}
      {autonomy.is_locked_down && (
        <div className="rounded-lg border border-[var(--color-danger)] bg-[var(--color-danger)]/10 p-4 flex items-center justify-between">
          <div>
            <span className="font-medium text-[var(--color-danger)]">Lockdown Active</span>
            <p className="text-sm text-[var(--color-text-secondary)] mt-1">
              All autonomous actions are suspended.
            </p>
          </div>
          <button
            onClick={onToggleLockdown}
            className="px-3 py-1.5 text-sm rounded-md bg-[var(--color-danger)] text-white hover:opacity-90"
          >
            Deactivate
          </button>
        </div>
      )}

      {/* Level selector */}
      <Card title="Autonomy Level">
        <div className="space-y-2">
          {levels.map((l) => (
            <button
              key={l.id}
              onClick={() => onSetLevel(l.id)}
              className={`w-full text-left p-3 rounded-md border transition-colors ${
                autonomy.global_level === l.id
                  ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10"
                  : "border-[var(--color-border)] hover:bg-[var(--color-bg-tertiary)]"
              }`}
            >
              <div className="font-medium text-sm">{l.label}</div>
              <div className="text-xs text-[var(--color-text-secondary)] mt-0.5">{l.desc}</div>
            </button>
          ))}
        </div>
      </Card>

      {/* Stats */}
      <Card title="Statistics">
        <div className="grid grid-cols-3 gap-4 text-sm">
          <MiniStat label="Total Actions" value={autonomy.stats.total_actions} />
          <MiniStat label="Approved" value={autonomy.stats.approved_actions} />
          <MiniStat label="Denied" value={autonomy.stats.denied_actions} />
          <MiniStat label="Auto Executed" value={autonomy.stats.auto_executed} />
          <MiniStat label="Approval Rate" value={`${Math.round(autonomy.stats.approval_rate * 100)}%`} />
          <MiniStat label="Days at Level" value={autonomy.stats.days_at_current_level} />
        </div>
      </Card>

      {/* Server overrides */}
      {Object.keys(autonomy.server_overrides).length > 0 && (
        <Card title="Server Overrides">
          <div className="space-y-2">
            {Object.entries(autonomy.server_overrides).map(([server, level]) => (
              <div key={server} className="flex items-center justify-between p-2 rounded-md bg-[var(--color-bg-tertiary)] text-sm">
                <span>{server}</span>
                <span className="text-[var(--color-text-secondary)]">{level}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Emergency lockdown button */}
      {!autonomy.is_locked_down && (
        <button
          onClick={onToggleLockdown}
          className="w-full py-2.5 rounded-md border border-[var(--color-danger)] text-[var(--color-danger)] text-sm font-medium hover:bg-[var(--color-danger)]/10 transition-colors"
        >
          Activate Emergency Lockdown
        </button>
      )}
    </div>
  );
}

/* ─── Playbooks Tab ─── */

function PlaybooksTab({ playbooks }: { playbooks: ResponsePlaybook[] }) {
  if (playbooks.length === 0) {
    return <EmptyState message="No playbooks configured" />;
  }

  return (
    <div className="space-y-3">
      {playbooks.map((pb) => (
        <div
          key={pb.id}
          className="p-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)]"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="font-medium text-sm">{pb.name}</span>
              {pb.is_builtin && (
                <span className="px-1.5 py-0.5 rounded text-xs bg-[var(--color-accent)]/20 text-[var(--color-accent)]">
                  built-in
                </span>
              )}
            </div>
            <span
              className={`px-2 py-0.5 rounded-full text-xs ${
                pb.enabled
                  ? "bg-[var(--color-success)]/20 text-[var(--color-success)]"
                  : "bg-[var(--color-text-secondary)]/20 text-[var(--color-text-secondary)]"
              }`}
            >
              {pb.enabled ? "Enabled" : "Disabled"}
            </span>
          </div>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{pb.description}</p>
          <div className="mt-2 flex items-center gap-3 text-xs text-[var(--color-text-secondary)]">
            <span>{pb.actions.length} action{pb.actions.length !== 1 ? "s" : ""}</span>
            <span>Requires: {pb.autonomy_required}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── Reports Tab ─── */

function ReportsTab({ reports }: { reports: GeneratedReport[] }) {
  if (reports.length === 0) {
    return <EmptyState message="No reports generated yet" />;
  }

  return (
    <div className="space-y-3">
      {reports.map((r) => (
        <div
          key={r.id}
          className="p-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)]"
        >
          <div className="flex items-center justify-between">
            <span className="font-medium text-sm">{r.report_type}</span>
            <span className="text-xs text-[var(--color-text-secondary)]">
              {new Date(r.generated_at).toLocaleDateString()}
            </span>
          </div>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{r.summary}</p>
          <div className="mt-2 flex items-center gap-3 text-xs text-[var(--color-text-secondary)]">
            <span>{r.format}</span>
            <span>{(r.size_bytes / 1024).toFixed(1)} KB</span>
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── Decisions Tab ─── */

function DecisionsTab({ decisions }: { decisions: DecisionExplanation[] }) {
  if (decisions.length === 0) {
    return <EmptyState message="No decisions recorded yet" />;
  }

  return (
    <div className="space-y-3">
      {decisions.map((d) => (
        <div
          key={d.id}
          className="p-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)]"
        >
          <div className="flex items-center justify-between">
            <span className="font-medium text-sm">{d.decision_type}</span>
            <span className="text-xs text-[var(--color-text-secondary)]">
              {new Date(d.timestamp).toLocaleString()}
            </span>
          </div>
          <p className="mt-2 text-sm">{d.conclusion}</p>
          {d.reasoning.length > 0 && (
            <ul className="mt-2 space-y-1 text-xs text-[var(--color-text-secondary)]">
              {d.reasoning.map((r, i) => (
                <li key={i} className="flex items-start gap-1.5">
                  <span className="mt-0.5 text-[var(--color-accent)]">&bull;</span>
                  <span>{r}</span>
                </li>
              ))}
            </ul>
          )}
          <div className="mt-2 flex items-center gap-3 text-xs text-[var(--color-text-secondary)]">
            <span>Confidence: {Math.round(d.confidence * 100)}%</span>
            {d.server_name && <span>Server: {d.server_name}</span>}
            <span>{d.factors.length} factor{d.factors.length !== 1 ? "s" : ""}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── Shared components ─── */

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
      <h2 className="text-sm font-semibold mb-3">{title}</h2>
      {children}
    </div>
  );
}

function StatCard({ label, value, sub }: { label: string; value: string | number; sub: string }) {
  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
      <div className="text-xs text-[var(--color-text-secondary)]">{label}</div>
      <div className="text-2xl font-bold mt-1">{value}</div>
      <div className="text-xs text-[var(--color-text-secondary)] mt-1">{sub}</div>
    </div>
  );
}

function MiniStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <div className="text-xs text-[var(--color-text-secondary)]">{label}</div>
      <div className="text-lg font-semibold mt-0.5">{value}</div>
    </div>
  );
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex items-center justify-center py-12 text-sm text-[var(--color-text-secondary)]">
      {message}
    </div>
  );
}
