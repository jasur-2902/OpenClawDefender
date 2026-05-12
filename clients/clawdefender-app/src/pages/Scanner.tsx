import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  ScanFindingEvent,
  ScanStageCompleteEvent,
  ScanCompleteEvent,
  PlaybookSummary,
} from "../types";
import { LiveScanView } from "../components/scanner/LiveScanView";
import { AiScanResults } from "../components/scanner/AiScanResults";
import { useScanStore } from "../stores/scanStore";
import type { ScanHistoryEntry } from "../stores/scanStore";
import { Icon, Badge, Btn, Card, ChessPiece } from "../components/design";
import type { PieceKind } from "../components/design";

// ---------------------------------------------------------------------------
// Quick Scan types (existing rule-based scanner)
// ---------------------------------------------------------------------------

interface ScanFinding {
  severity: string;
  category: string;
  module: string;
  description: string;
  affected_resource: string;
  fix_suggestion: string;
  fix_action: {
    action_type: string;
    client: string | null;
    server: string | null;
    rule_name: string | null;
    rule_resource: string | null;
    rule_action: string | null;
  } | null;
  ai_analysis?: string;
}

interface ScanModuleResult {
  module_id: string;
  module_name: string;
  status: string;
  findings: ScanFinding[];
  summary: string;
}

interface ScanResult {
  scan_id: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  modules: ScanModuleResult[];
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  scan_type?: string;
}

const SEVERITY_CONFIG: Record<string, { color: string; bg: string; label: string; order: number; cssVar: string }> = {
  critical: { color: "text-red-400", bg: "bg-red-500/20", label: "CRITICAL", order: 0, cssVar: "var(--red)" },
  high: { color: "text-orange-400", bg: "bg-orange-500/20", label: "HIGH", order: 1, cssVar: "var(--amber)" },
  medium: { color: "text-yellow-400", bg: "bg-yellow-500/20", label: "MEDIUM", order: 2, cssVar: "var(--amber)" },
  low: { color: "text-blue-400", bg: "bg-blue-500/20", label: "LOW", order: 3, cssVar: "var(--accent)" },
};

interface AskClawEntry {
  loading: boolean;
  response: string | null;
  followUp: string;
}

// ---------------------------------------------------------------------------
// Playbook-to-Chess-Piece mapping
// ---------------------------------------------------------------------------

interface PlaybookMeta {
  piece: PieceKind;
  label: string;
  description: string;
  color: string;
}

const PLAYBOOK_META: Record<string, PlaybookMeta> = {
  mcp_security_audit: {
    piece: "knight",
    label: "Quick checkup",
    description: "Fast MCP configuration check — reviews server configs, policies, and permissions for common security issues.",
    color: "var(--accent)",
  },
  full_audit: {
    piece: "queen",
    label: "Full audit",
    description: "Comprehensive security assessment — covers MCP config, system posture, credentials, and behavioral analysis.",
    color: "var(--violet)",
  },
  system_hardening: {
    piece: "rook",
    label: "System hardening",
    description: "Reviews system-level security settings and hardening measures.",
    color: "var(--green)",
  },
  credential_exposure: {
    piece: "pawn",
    label: "Credential exposure",
    description: "Scans for exposed credentials, tokens, and secrets in configurations.",
    color: "var(--amber)",
  },
  network_security: {
    piece: "bishop",
    label: "Network security",
    description: "Analyzes network-facing configurations and connection security.",
    color: "var(--accent)",
  },
  behavioral_deep_dive: {
    piece: "king",
    label: "Behavioral analysis",
    description: "Deep analysis of runtime behavior patterns and anomaly detection.",
    color: "var(--red)",
  },
};

const HERO_PLAYBOOK_IDS = ["mcp_security_audit", "full_audit"];
const CUSTOM_PLAYBOOK_IDS = ["system_hardening", "credential_exposure", "network_security", "behavioral_deep_dive"];

function formatDuration(secs: number): string {
  if (secs < 60) return `~${secs}s`;
  return `~${Math.ceil(secs / 60)} min`;
}

function formatCost(usd: number): string {
  if (usd < 0.01) return "<$0.01";
  return `~$${usd.toFixed(2)}`;
}

function relativeTime(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

// ---------------------------------------------------------------------------
// Top-level Scanner component
// ---------------------------------------------------------------------------

export function Scanner() {
  const phase = useScanStore((s) => s.aiScanPhase);
  const setPhase = useScanStore((s) => s.setAiScanPhase);
  const scanId = useScanStore((s) => s.aiScanId);
  const error = useScanStore((s) => s.aiScanError);
  const setError = useScanStore((s) => s.setAiScanError);
  const startNewAiScan = useScanStore((s) => s.startNewAiScan);
  const resetAiScan = useScanStore((s) => s.resetAiScan);
  const addScanHistory = useScanStore((s) => s.addScanHistory);
  const activeScanType = useScanStore((s) => s.activeScanType);
  const setActiveScanType = useScanStore((s) => s.setActiveScanType);
  const setLastPlaybookId = useScanStore((s) => s.setLastPlaybookId);
  const scanHistory = useScanStore((s) => s.scanHistory);

  const [starting, setStarting] = useState(false);
  const [playbooks, setPlaybooks] = useState<PlaybookSummary[]>([]);
  const [playbooksLoading, setPlaybooksLoading] = useState(true);
  const [customExpanded, setCustomExpanded] = useState(false);

  const historySectionRef = useRef<HTMLDivElement>(null);

  // ---- Fetch playbooks ----
  useEffect(() => {
    async function load() {
      try {
        const data = await invoke<PlaybookSummary[]>("get_scan_playbooks");
        setPlaybooks(data);
      } catch (e) {
        setError(String(e));
      } finally {
        setPlaybooksLoading(false);
      }
    }
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ---- Global event listeners for Quick Scan live feed ----
  const addQuickScanActivity = useScanStore((s) => s.addQuickScanActivity);
  const addQuickScanLiveFinding = useScanStore((s) => s.addQuickScanLiveFinding);
  const quickScanCurrentId = useScanStore((s) => s.quickScanCurrentId);
  const currentIdRef = useRef(quickScanCurrentId);
  currentIdRef.current = quickScanCurrentId;

  useEffect(() => {
    const unlisteners: Array<() => void> = [];

    listen<ScanFindingEvent>("rookbot://scan-finding", (event) => {
      const p = event.payload;
      if (currentIdRef.current && p.scan_id !== currentIdRef.current) return;
      addQuickScanLiveFinding({
        id: p.finding_id,
        severity: p.severity,
        title: p.title,
        stage: p.stage,
      });
      addQuickScanActivity({
        type: "finding",
        message: `${p.severity.toUpperCase()}: ${p.title}`,
        severity: p.severity,
      });
    }).then((fn) => unlisteners.push(fn));

    listen<ScanStageCompleteEvent>("rookbot://scan-stage-complete", (event) => {
      const p = event.payload;
      if (currentIdRef.current && p.scan_id !== currentIdRef.current) return;
      addQuickScanActivity({
        type: "stage",
        message: `${p.stage_name} completed (${p.stages_completed}/${p.stages_total})`,
      });
    }).then((fn) => unlisteners.push(fn));

    listen<ScanCompleteEvent>("rookbot://scan-complete", (event) => {
      const p = event.payload;
      if (currentIdRef.current && p.scan_id !== currentIdRef.current) return;
      addQuickScanActivity({
        type: "info",
        message: `Scan complete: ${p.summary}`,
      });
    }).then((fn) => unlisteners.push(fn));

    return () => {
      unlisteners.forEach((fn) => fn());
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ---- Handlers ----

  async function handleStartAiScan(playbookId: string) {
    setError(null);
    setStarting(true);
    try {
      const result = await invoke<{ scan_id: string }>("start_ai_scan", {
        playbookId,
      });
      startNewAiScan(result.scan_id);
      setActiveScanType("ai");
      setLastPlaybookId(playbookId);
    } catch (e) {
      setError(String(e));
    } finally {
      setStarting(false);
    }
  }

  function handleComplete() {
    if (scanId) {
      const meta = playbooks.find((p) => p.id === useScanStore.getState().lastPlaybookId);
      addScanHistory({
        scan_id: scanId,
        scan_type: "ai",
        status: "completed",
        findings_count: 0,
        started_at: new Date().toISOString(),
        playbook_id: useScanStore.getState().lastPlaybookId ?? undefined,
        playbook_name: meta?.name,
      });
    }
    setPhase("results");
  }

  function handleCancel() {
    setPhase("results");
  }

  function handleNewScan() {
    resetAiScan();
  }

  function handleRerun(entry: ScanHistoryEntry) {
    if (entry.scan_type === "ai" && entry.playbook_id) {
      handleStartAiScan(entry.playbook_id);
    }
  }

  function handleViewReport(entry: ScanHistoryEntry) {
    if (entry.scan_type === "ai") {
      useScanStore.getState().setAiScanId(entry.scan_id);
      setActiveScanType("ai");
      setPhase("results");
    }
  }

  function scrollToHistory() {
    historySectionRef.current?.scrollIntoView({ behavior: "smooth" });
  }

  const getPlaybook = (id: string) => playbooks.find((p) => p.id === id);

  // Available custom playbooks (only ones that exist in backend)
  const customPlaybooks = CUSTOM_PLAYBOOK_IDS
    .map((id) => ({ id, pb: getPlaybook(id), meta: PLAYBOOK_META[id] }))
    .filter((x) => x.meta);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      {/* Header */}
      <ScanHeader onHistoryClick={scrollToHistory} />

      {/* Scrollable content */}
      <div style={{ flex: 1, overflow: "auto" }} className="cd-scroll">
        <div style={{ padding: 24, display: "grid", gap: 24 }}>
          {/* Error banner */}
          {error && (
            <div style={{
              padding: 14, borderRadius: 10,
              background: "var(--red-soft)", border: "1px solid color-mix(in oklch, var(--red) 30%, transparent)",
              fontSize: 12.5, color: "var(--red)",
            }}>
              {error}
            </div>
          )}

          {/* ---- SELECT PHASE ---- */}
          {phase === "select" && (
            <>
              {/* Last Scan Banner */}
              {scanHistory.length > 0 && (
                <LastScanBanner
                  entry={scanHistory[0]}
                  onRerun={handleRerun}
                  onViewReport={handleViewReport}
                />
              )}

              {/* Hero Cards */}
              <HeroCardsSection
                playbooks={playbooks}
                loading={playbooksLoading}
                starting={starting}
                onStart={handleStartAiScan}
              />

              {/* Custom Scan Section */}
              {customPlaybooks.length > 0 && (
                <CustomScanSection
                  items={customPlaybooks}
                  expanded={customExpanded}
                  onToggle={() => setCustomExpanded(!customExpanded)}
                  starting={starting}
                  onStart={handleStartAiScan}
                />
              )}
            </>
          )}

          {/* ---- SCANNING PHASE ---- */}
          {phase === "scanning" && activeScanType === "ai" && scanId && (
            <LiveScanView
              scanId={scanId}
              onComplete={handleComplete}
              onCancel={handleCancel}
            />
          )}

          {/* ---- RESULTS PHASE (AI) ---- */}
          {phase === "results" && activeScanType === "ai" && scanId && (
            <AiScanResults scanId={scanId} onNewScan={handleNewScan} />
          )}

          {/* ---- RESULTS PHASE (fallback — scanId but no activeScanType) ---- */}
          {phase === "results" && !activeScanType && scanId && (
            <AiScanResults scanId={scanId} onNewScan={handleNewScan} />
          )}

          {/* ---- SCAN HISTORY (always at bottom when in select) ---- */}
          <div ref={historySectionRef}>
            <ScanHistorySection
              onViewReport={handleViewReport}
              onRerun={handleRerun}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ScanHeader
// ---------------------------------------------------------------------------

function ScanHeader({ onHistoryClick }: { onHistoryClick: () => void }) {
  return (
    <div style={{
      padding: "10px 24px",
      borderBottom: "1px solid var(--line)",
      display: "flex",
      alignItems: "center",
      justifyContent: "flex-end",
    }}>
      <Btn kind="ghost" size="sm" icon="history" onClick={onHistoryClick}>
        History
      </Btn>
    </div>
  );
}

// ---------------------------------------------------------------------------
// LastScanBanner
// ---------------------------------------------------------------------------

function LastScanBanner({
  entry,
  onRerun,
  onViewReport,
}: {
  entry: ScanHistoryEntry;
  onRerun: (entry: ScanHistoryEntry) => void;
  onViewReport: (entry: ScanHistoryEntry) => void;
}) {
  const typeLabel = entry.playbook_name
    ?? (entry.scan_type === "ai" ? "AI Scan" : "Security Scan");

  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 12,
      padding: "12px 16px",
      borderRadius: 10,
      background: "var(--bg-1)",
      border: "1px solid var(--line)",
    }}>
      <Icon name="history" size={16} color="var(--ink-3)" />
      <div style={{ flex: 1, display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
        <span style={{ fontSize: 12.5, color: "var(--ink-1)" }}>
          Last scan &middot; {relativeTime(entry.started_at)}
        </span>
        <Badge color={entry.scan_type === "ai" ? "var(--accent)" : "var(--ink-2)"} mono>
          {typeLabel}
        </Badge>
        <span style={{
          fontSize: 12, fontFamily: "var(--font-mono)",
          color: entry.findings_count > 0 ? "var(--amber)" : "var(--green)",
        }}>
          {entry.findings_count} findings
        </span>
      </div>
      <div style={{ display: "flex", gap: 6 }}>
        {entry.scan_type === "ai" && entry.playbook_id && (
          <Btn kind="soft" size="sm" icon="refresh-cw" onClick={() => onRerun(entry)}>
            Re-run
          </Btn>
        )}
        {entry.scan_type === "ai" && (
          <Btn kind="soft" size="sm" icon="file-text" onClick={() => onViewReport(entry)}>
            View report
          </Btn>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// HeroCardsSection
// ---------------------------------------------------------------------------

function HeroCardsSection({
  playbooks,
  loading,
  starting,
  onStart,
}: {
  playbooks: PlaybookSummary[];
  loading: boolean;
  starting: boolean;
  onStart: (playbookId: string) => void;
}) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
      {HERO_PLAYBOOK_IDS.map((id) => {
        const meta = PLAYBOOK_META[id];
        const pb = playbooks.find((p) => p.id === id);
        if (!meta) return null;
        return (
          <HeroCard
            key={id}
            piece={meta.piece}
            color={meta.color}
            title={meta.label}
            description={meta.description}
            stageCount={pb?.stage_count}
            duration={pb ? formatDuration(pb.estimated_duration_secs) : undefined}
            cost={pb ? formatCost(pb.estimated_cost_usd) : undefined}
            loading={loading}
            starting={starting}
            onStart={() => onStart(id)}
            isPrimary={id === "mcp_security_audit"}
          />
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// HeroCard
// ---------------------------------------------------------------------------

function HeroCard({
  piece,
  color,
  title,
  description,
  stageCount,
  duration,
  cost,
  loading,
  starting,
  onStart,
  isPrimary,
}: {
  piece: PieceKind;
  color: string;
  title: string;
  description: string;
  stageCount?: number;
  duration?: string;
  cost?: string;
  loading: boolean;
  starting: boolean;
  onStart: () => void;
  isPrimary: boolean;
}) {
  return (
    <div style={{
      padding: 28,
      borderRadius: 14,
      background: "var(--bg-1)",
      border: "1px solid var(--line)",
      display: "flex",
      flexDirection: "column",
      gap: 16,
    }}>
      <div style={{
        width: 52, height: 52, borderRadius: 14,
        background: `color-mix(in oklch, ${color} 12%, transparent)`,
        border: `1px solid color-mix(in oklch, ${color} 25%, transparent)`,
        display: "grid", placeItems: "center",
      }}>
        <ChessPiece kind={piece} size={30} style={{ color }} />
      </div>
      <div>
        <h2 style={{ margin: 0, fontSize: 17, fontWeight: 600, color: "var(--ink-0)" }}>
          {title}
        </h2>
        <p style={{ margin: "8px 0 0", fontSize: 13, color: "var(--ink-2)", lineHeight: 1.5 }}>
          {description}
        </p>
      </div>
      {!loading && stageCount != null && (
        <div style={{
          fontSize: 11.5, fontFamily: "var(--font-mono)",
          color: "var(--ink-3)", letterSpacing: 0.2,
        }}>
          {stageCount} stages &middot; {duration} &middot; {cost}
        </div>
      )}
      {loading && (
        <div style={{ fontSize: 11.5, color: "var(--ink-3)" }} className="cd-pulse">
          Loading...
        </div>
      )}
      <Btn
        kind={isPrimary ? "primary" : "accent"}
        icon="play"
        onClick={onStart}
        disabled={starting || loading}
        style={{ alignSelf: "flex-start" }}
      >
        {isPrimary ? "Start checkup" : "Start audit"}
      </Btn>
    </div>
  );
}

// ---------------------------------------------------------------------------
// CustomScanSection
// ---------------------------------------------------------------------------

function CustomScanSection({
  items,
  expanded,
  onToggle,
  starting,
  onStart,
}: {
  items: { id: string; pb: PlaybookSummary | undefined; meta: PlaybookMeta }[];
  expanded: boolean;
  onToggle: () => void;
  starting: boolean;
  onStart: (playbookId: string) => void;
}) {
  return (
    <div>
      <button
        onClick={onToggle}
        style={{
          display: "flex", alignItems: "center", gap: 8,
          background: "none", border: "none", cursor: "pointer",
          padding: "8px 0", color: "var(--ink-1)", fontSize: 13, fontWeight: 500,
        }}
      >
        <span style={{
          display: "inline-block", transition: "transform 0.15s",
          transform: expanded ? "rotate(90deg)" : "none",
          color: "var(--ink-3)", fontSize: 11,
        }}>
          &#9654;
        </span>
        Custom scan ({items.length} playbooks)
      </button>

      {expanded && (
        <div style={{
          display: "grid", gridTemplateColumns: "1fr 1fr",
          gap: 12, marginTop: 8,
        }}>
          {items.map(({ id, pb, meta }) => (
            <PlaybookCard
              key={id}
              piece={meta.piece}
              color={meta.color}
              name={meta.label}
              description={meta.description}
              stageCount={pb?.stage_count}
              duration={pb ? formatDuration(pb.estimated_duration_secs) : undefined}
              cost={pb ? formatCost(pb.estimated_cost_usd) : undefined}
              starting={starting}
              onStart={() => onStart(id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// PlaybookCard (smaller card for custom section)
// ---------------------------------------------------------------------------

function PlaybookCard({
  piece,
  color,
  name,
  description,
  stageCount,
  duration,
  cost,
  starting,
  onStart,
}: {
  piece: PieceKind;
  color: string;
  name: string;
  description: string;
  stageCount?: number;
  duration?: string;
  cost?: string;
  starting: boolean;
  onStart: () => void;
}) {
  return (
    <div style={{
      padding: 18,
      borderRadius: 12,
      background: "var(--bg-1)",
      border: "1px solid var(--line)",
      display: "flex",
      flexDirection: "column",
      gap: 10,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{
          width: 36, height: 36, borderRadius: 10,
          background: `color-mix(in oklch, ${color} 12%, transparent)`,
          border: `1px solid color-mix(in oklch, ${color} 25%, transparent)`,
          display: "grid", placeItems: "center", flexShrink: 0,
        }}>
          <ChessPiece kind={piece} size={20} style={{ color }} />
        </div>
        <span style={{ fontSize: 14, fontWeight: 600, color: "var(--ink-0)" }}>{name}</span>
      </div>
      <p style={{ margin: 0, fontSize: 12, color: "var(--ink-2)", lineHeight: 1.4 }}>
        {description}
      </p>
      {stageCount != null && (
        <div style={{
          fontSize: 10.5, fontFamily: "var(--font-mono)",
          color: "var(--ink-3)", letterSpacing: 0.2,
        }}>
          {stageCount} stages &middot; {duration} &middot; {cost}
        </div>
      )}
      <Btn kind="soft" size="sm" icon="play" onClick={onStart} disabled={starting} style={{ alignSelf: "flex-start" }}>
        Start
      </Btn>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ScanHistorySection
// ---------------------------------------------------------------------------

function ScanHistorySection({
  onViewReport,
  onRerun,
}: {
  onViewReport: (entry: ScanHistoryEntry) => void;
  onRerun: (entry: ScanHistoryEntry) => void;
}) {
  const scanHistory = useScanStore((s) => s.scanHistory);
  const [selectedEntry, setSelectedEntry] = useState<ScanHistoryEntry | null>(null);
  const [loadedResult, setLoadedResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedModules, setExpandedModules] = useState<Set<string>>(new Set());
  const [fixingAction, setFixingAction] = useState<string | null>(null);
  const [askClawState, setAskClawState] = useState<Map<string, AskClawEntry>>(new Map());

  async function selectEntry(entry: ScanHistoryEntry) {
    if (selectedEntry?.scan_id === entry.scan_id) {
      setSelectedEntry(null);
      setLoadedResult(null);
      return;
    }

    // AI scans: navigate to results view
    if (entry.scan_type === "ai") {
      onViewReport(entry);
      return;
    }

    // Quick scans: expand inline
    setSelectedEntry(entry);
    setLoadedResult(null);
    setError(null);
    setAskClawState(new Map());
    setLoading(true);
    try {
      const result = await invoke<ScanResult>("get_scan_results", { scanId: entry.scan_id });
      setLoadedResult(result);
      const withFindings = new Set(
        result.modules.filter((m) => m.findings.length > 0).map((m) => m.module_id)
      );
      setExpandedModules(withFindings);
    } catch (e) {
      setError(`Could not load results: ${String(e)}`);
    } finally {
      setLoading(false);
    }
  }

  function toggleExpanded(moduleId: string) {
    setExpandedModules((prev) => {
      const next = new Set(prev);
      if (next.has(moduleId)) next.delete(moduleId);
      else next.add(moduleId);
      return next;
    });
  }

  async function applyFix(finding: ScanFinding) {
    if (!finding.fix_action) return;
    const key = `${finding.fix_action.action_type}:${finding.affected_resource}`;
    setFixingAction(key);
    try {
      const result = await invoke<string>("apply_scan_fix", {
        client: finding.fix_action.client || "",
        server: finding.fix_action.server || "",
        actionType: finding.fix_action.action_type,
      });
      alert(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setFixingAction(null);
    }
  }

  async function askClawAboutFinding(findingKey: string, finding: ScanFinding, followUpQuestion?: string) {
    setAskClawState((prev) => {
      const next = new Map(prev);
      const existing = next.get(findingKey);
      next.set(findingKey, { loading: true, response: existing?.response ?? null, followUp: "" });
      return next;
    });

    const prompt = followUpQuestion
      ? followUpQuestion
      : `Analyze this security finding:\nSeverity: ${finding.severity} | Category: ${finding.category}\nFinding: ${finding.description}\nAffected: ${finding.affected_resource}\nSuggested fix: ${finding.fix_suggestion}\n\nIs this a real risk? What should I do?`;

    const contextJson = JSON.stringify({
      active_page: "scanner",
      finding_severity: finding.severity,
      finding_category: finding.category,
      finding_description: finding.description,
      affected_resource: finding.affected_resource,
    });

    try {
      const raw = await invoke<string>("ask_claw_ai", { input: prompt, contextJson });
      let message = raw;
      try {
        const parsed = JSON.parse(raw);
        message = parsed.message ?? parsed.explanation ?? raw;
      } catch { /* use raw string if not JSON */ }
      setAskClawState((prev) => {
        const next = new Map(prev);
        next.set(findingKey, { loading: false, response: message, followUp: "" });
        return next;
      });
    } catch (e) {
      setAskClawState((prev) => {
        const next = new Map(prev);
        next.set(findingKey, { loading: false, response: `Error: ${String(e)}`, followUp: "" });
        return next;
      });
    }
  }

  function toggleAskClaw(findingKey: string) {
    setAskClawState((prev) => {
      const next = new Map(prev);
      if (next.has(findingKey)) next.delete(findingKey);
      else next.set(findingKey, { loading: false, response: null, followUp: "" });
      return next;
    });
  }

  const sortedFindings = (findings: ScanFinding[]) =>
    [...findings].sort(
      (a, b) =>
        (SEVERITY_CONFIG[a.severity]?.order ?? 99) -
        (SEVERITY_CONFIG[b.severity]?.order ?? 99)
    );

  return (
    <div>
      <h2 style={{ margin: "0 0 14px", fontSize: 15, fontWeight: 600, color: "var(--ink-0)" }}>Scan History</h2>

      {scanHistory.length === 0 ? (
        <Card>
          <div style={{ textAlign: "center", padding: "24px 0" }}>
            <Icon name="history" size={28} color="var(--ink-3)" />
            <p style={{ fontSize: 13, color: "var(--ink-2)", marginTop: 10 }}>
              No scans recorded yet. Start a scan above to see history here.
            </p>
          </div>
        </Card>
      ) : (
        <div style={{ display: "grid", gap: 8 }}>
          {scanHistory.map((entry) => {
            const meta = entry.playbook_id ? PLAYBOOK_META[entry.playbook_id] : undefined;
            return (
              <div key={entry.scan_id}>
                <button onClick={() => selectEntry(entry)} style={{
                  width: "100%", textAlign: "left", cursor: "pointer",
                  padding: "12px 16px", borderRadius: 10,
                  background: "var(--bg-1)",
                  border: `1px solid ${selectedEntry?.scan_id === entry.scan_id ? "var(--accent-line)" : "var(--line)"}`,
                }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      {meta && (
                        <ChessPiece kind={meta.piece} size={16} style={{ color: meta.color }} />
                      )}
                      <Badge color={entry.status === "completed" ? "var(--green)" : entry.status === "failed" ? "var(--red)" : "var(--accent)"}>
                        {entry.status}
                      </Badge>
                      <Badge color={entry.scan_type === "ai" ? "var(--accent)" : "var(--ink-2)"} mono>
                        {entry.playbook_name ?? (entry.scan_type === "ai" ? "AI" : "Security")}
                      </Badge>
                      <span style={{ fontSize: 12, fontFamily: "var(--font-mono)", color: "var(--ink-1)" }}>
                        {entry.scan_id.slice(0, 16)}
                      </span>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 12, fontSize: 12 }}>
                      <span style={{ color: entry.findings_count > 0 ? "var(--amber)" : "var(--ink-2)", fontWeight: entry.findings_count > 0 ? 500 : 400 }}>
                        {entry.findings_count} findings
                      </span>
                      <span style={{ color: "var(--ink-3)", fontSize: 11 }}>{relativeTime(entry.started_at)}</span>
                      {entry.scan_type === "ai" && entry.playbook_id && (
                        <Btn kind="ghost" size="sm" icon="refresh-cw" onClick={(e) => { e.stopPropagation(); onRerun(entry); }}>
                          Re-run
                        </Btn>
                      )}
                      {entry.scan_type === "quick" && (
                        <span style={{
                          color: "var(--ink-3)", transition: "transform 0.15s", display: "inline-block",
                          transform: selectedEntry?.scan_id === entry.scan_id ? "rotate(180deg)" : "none",
                        }}>
                          &#9660;
                        </span>
                      )}
                    </div>
                  </div>
                </button>

                {selectedEntry?.scan_id === entry.scan_id && entry.scan_type === "quick" && (
                  <div style={{ marginTop: 4, marginLeft: 16, paddingLeft: 16, borderLeft: "2px solid var(--accent-line)" }}>
                    {loading && (
                      <div style={{ padding: "16px 0", fontSize: 12.5, color: "var(--ink-2)" }} className="cd-pulse">
                        Loading scan results...
                      </div>
                    )}
                    {error && <div style={{ padding: "12px 0", fontSize: 12.5, color: "var(--ink-2)" }}>{error}</div>}
                    {loadedResult && (
                      <QuickScanResults
                        scanResult={loadedResult}
                        expandedModules={expandedModules}
                        toggleExpanded={toggleExpanded}
                        sortedFindings={sortedFindings}
                        applyFix={applyFix}
                        fixingAction={fixingAction}
                        askClawState={askClawState}
                        toggleAskClaw={toggleAskClaw}
                        askClawAboutFinding={askClawAboutFinding}
                        setAskClawState={setAskClawState}
                      />
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Quick Scan Results
// ---------------------------------------------------------------------------

function QuickScanResults({
  scanResult,
  expandedModules,
  toggleExpanded,
  sortedFindings,
  applyFix,
  fixingAction,
  askClawState,
  toggleAskClaw,
  askClawAboutFinding,
  setAskClawState,
  onEnrichFinding,
  enrichingKeys,
}: {
  scanResult: ScanResult;
  expandedModules: Set<string>;
  toggleExpanded: (id: string) => void;
  sortedFindings: (findings: ScanFinding[]) => ScanFinding[];
  applyFix: (finding: ScanFinding) => void;
  fixingAction: string | null;
  askClawState: Map<string, AskClawEntry>;
  toggleAskClaw: (key: string) => void;
  askClawAboutFinding: (key: string, finding: ScanFinding, followUp?: string) => void;
  setAskClawState: React.Dispatch<React.SetStateAction<Map<string, AskClawEntry>>>;
  onEnrichFinding?: (moduleId: string, findingIndex: number) => void;
  enrichingKeys?: Set<string>;
}) {
  return (
    <div style={{ display: "grid", gap: 14 }}>
      {/* Summary header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <h2 style={{ margin: 0, fontSize: 13, fontWeight: 600, color: "var(--ink-1)" }}>Results</h2>
        <Badge color="var(--ink-2)" mono>{scanResult.total_findings} findings</Badge>
        {scanResult.total_findings > 0 && (
          <Btn size="sm" kind="accent" style={{ marginLeft: "auto" }} icon="check">
            Apply all safe fixes
          </Btn>
        )}
      </div>

      {/* Severity summary */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8 }}>
        <SeverityCard label="Critical" count={scanResult.critical_count} color="var(--red)" />
        <SeverityCard label="High" count={scanResult.high_count} color="var(--amber)" />
        <SeverityCard label="Medium" count={scanResult.medium_count} color="var(--amber)" />
        <SeverityCard label="Low" count={scanResult.low_count} color="var(--accent)" />
      </div>

      {/* Module results */}
      {scanResult.modules.map((mod) => (
        <div key={mod.module_id} style={{
          background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: 10, overflow: "hidden",
        }}>
          <button onClick={() => toggleExpanded(mod.module_id)} style={{
            width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between",
            padding: "12px 16px", cursor: "pointer", background: "transparent", border: "none",
            color: "var(--ink-0)",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{
                color: mod.status === "completed" && mod.findings.length === 0 ? "var(--green)" : mod.findings.length > 0 ? "var(--amber)" : "var(--ink-3)",
                fontSize: 16,
              }}>
                {mod.status === "completed" && mod.findings.length === 0 ? "\u2713" : mod.findings.length > 0 ? "\u26A0" : "\u2022"}
              </span>
              <span style={{ fontSize: 13, fontWeight: 500 }}>{mod.module_name}</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ fontSize: 11, color: "var(--ink-3)" }}>{mod.summary}</span>
              {mod.findings.length > 0 && <Badge color="var(--amber)" mono>{mod.findings.length}</Badge>}
              <span style={{
                color: "var(--ink-3)", transition: "transform 0.15s",
                transform: expandedModules.has(mod.module_id) ? "rotate(180deg)" : "none",
                display: "inline-block",
              }}>
                &#9660;
              </span>
            </div>
          </button>

          {expandedModules.has(mod.module_id) && (
            <div style={{ borderTop: "1px solid var(--line)" }}>
              {mod.findings.length === 0 ? (
                <div style={{ padding: "14px 16px", fontSize: 12.5, color: "var(--green)" }}>No issues found</div>
              ) : (
                sortedFindings(mod.findings).map((finding, idx) => {
                  const findingKey = `${mod.module_id}-${idx}`;
                  const clawEntry = askClawState.get(findingKey);
                  const cfg = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.low;
                  return (
                    <div key={idx} style={{ padding: "14px 16px", borderTop: idx > 0 ? "1px solid var(--line-soft)" : "none" }}>
                      <div style={{ display: "flex", alignItems: "stretch", gap: 12 }}>
                        <div style={{ width: 3, borderRadius: 2, background: cfg.cssVar, flexShrink: 0 }} />
                        <div style={{ flex: 1 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                            <Badge color={cfg.cssVar}>{finding.severity}</Badge>
                            <span style={{ fontSize: 10.5, padding: "2px 6px", background: "var(--bg-2)", borderRadius: 3, color: "var(--ink-2)" }}>{finding.category}</span>
                            <span style={{ fontSize: 12.5, fontWeight: 500, color: "var(--ink-0)" }}>{finding.description}</span>
                          </div>
                          <div style={{ fontSize: 11, color: "var(--ink-2)", marginBottom: 4 }}>
                            <span style={{ fontWeight: 500 }}>Resource:</span>{" "}
                            <span style={{ fontFamily: "var(--font-mono)" }}>{finding.affected_resource}</span>
                          </div>
                          <div style={{ fontSize: 11, color: "var(--ink-2)" }}>
                            <span style={{ fontWeight: 500 }}>Fix:</span> {finding.fix_suggestion}
                          </div>
                          {finding.fix_action && (
                            <div style={{ marginTop: 8 }}>
                              <Btn
                                size="sm"
                                kind="accent"
                                icon="check"
                                onClick={() => applyFix(finding)}
                                disabled={fixingAction === `${finding.fix_action.action_type}:${finding.affected_resource}`}
                              >
                                {fixingAction === `${finding.fix_action.action_type}:${finding.affected_resource}`
                                  ? "Applying..."
                                  : finding.fix_action.action_type === "wrap_server" ? "Wrap Server" : "Apply Fix"}
                              </Btn>
                            </div>
                          )}

                          {/* AI Analysis display */}
                          {finding.ai_analysis && (
                            <div style={{
                              marginTop: 10, padding: "10px 12px", borderRadius: 8,
                              background: "color-mix(in oklch, var(--violet) 6%, transparent)",
                              border: "1px solid color-mix(in oklch, var(--violet) 20%, transparent)",
                            }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                                <Icon name="sparkles" size={11} color="var(--violet)" />
                                <span style={{ fontSize: 10.5, fontWeight: 600, color: "var(--violet)" }}>AI Analysis</span>
                              </div>
                              <div style={{ fontSize: 11.5, color: "var(--ink-1)", whiteSpace: "pre-wrap", lineHeight: 1.5 }}>
                                {finding.ai_analysis}
                              </div>
                            </div>
                          )}

                          {/* On-demand AI enrichment button for critical/high findings */}
                          {!finding.ai_analysis && (finding.severity === "critical" || finding.severity === "high") && onEnrichFinding && (
                            <div style={{ marginTop: 8 }}>
                              <Btn
                                size="sm"
                                kind="soft"
                                icon="sparkles"
                                onClick={() => onEnrichFinding(mod.module_id, idx)}
                                disabled={enrichingKeys?.has(`${mod.module_id}-${idx}`)}
                              >
                                {enrichingKeys?.has(`${mod.module_id}-${idx}`) ? "Analyzing..." : "Get AI Analysis"}
                              </Btn>
                            </div>
                          )}
                        </div>
                        <Btn size="sm" kind={clawEntry ? "accent" : "soft"} onClick={() => toggleAskClaw(findingKey)}>
                          Ask Rook
                        </Btn>
                      </div>

                      {clawEntry && (
                        <AskClawPanel
                          findingKey={findingKey}
                          finding={finding}
                          entry={clawEntry}
                          onAnalyze={askClawAboutFinding}
                          setAskClawState={setAskClawState}
                        />
                      )}
                    </div>
                  );
                })
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Ask Rook inline panel (reusable)
// ---------------------------------------------------------------------------

function AskClawPanel({
  findingKey,
  finding,
  entry,
  onAnalyze,
  setAskClawState,
}: {
  findingKey: string;
  finding: ScanFinding;
  entry: AskClawEntry;
  onAnalyze: (key: string, finding: ScanFinding, followUp?: string) => void;
  setAskClawState: React.Dispatch<React.SetStateAction<Map<string, AskClawEntry>>>;
}) {
  return (
    <div style={{
      marginTop: 10, marginLeft: 15, padding: 12, borderRadius: 10,
      background: "var(--accent-soft)", border: "1px solid var(--accent-line)",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
        <Icon name="sparkles" size={13} color="var(--accent)" />
        <span style={{ fontSize: 11.5, fontWeight: 600, color: "var(--accent)" }}>Ask Rook AI</span>
        {entry.loading && <span style={{ fontSize: 11, color: "var(--ink-3)" }} className="cd-pulse">Analyzing...</span>}
      </div>

      {!entry.response && !entry.loading && (
        <Btn size="sm" kind="primary" onClick={() => onAnalyze(findingKey, finding)}>Analyze this finding</Btn>
      )}

      {entry.response && (
        <div style={{
          fontSize: 12, color: "var(--ink-0)", whiteSpace: "pre-wrap", lineHeight: 1.6,
          background: "var(--bg-1)", borderRadius: 8, padding: 10, marginBottom: 8,
        }}>
          {entry.response}
        </div>
      )}

      {entry.response && (
        <div style={{ display: "flex", gap: 6 }}>
          <input
            type="text"
            placeholder="Ask a follow-up question..."
            value={entry.followUp}
            onChange={(e) => {
              const val = e.target.value;
              setAskClawState((prev) => {
                const next = new Map(prev);
                const existing = next.get(findingKey);
                if (existing) next.set(findingKey, { ...existing, followUp: val });
                return next;
              });
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" && entry.followUp.trim()) {
                onAnalyze(findingKey, finding, entry.followUp.trim());
              }
            }}
            disabled={entry.loading}
            style={{
              flex: 1, padding: "6px 10px", borderRadius: 6, fontSize: 12,
              background: "var(--bg-0)", border: "1px solid var(--line)",
              color: "var(--ink-0)", outline: "none",
            }}
          />
          <Btn
            size="sm"
            kind="primary"
            icon="send"
            onClick={() => {
              if (entry.followUp.trim()) onAnalyze(findingKey, finding, entry.followUp.trim());
            }}
            disabled={entry.loading || !entry.followUp.trim()}
          >
            Send
          </Btn>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Severity Card
// ---------------------------------------------------------------------------

function SeverityCard({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div style={{
      borderRadius: 10, padding: 14, textAlign: "center",
      background: `color-mix(in oklch, ${color} 8%, transparent)`,
      border: `1px solid color-mix(in oklch, ${color} 20%, transparent)`,
    }}>
      <div style={{ fontSize: 22, fontWeight: 700, color, fontFamily: "var(--font-mono)" }}>{count}</div>
      <div style={{ fontSize: 10.5, color: "var(--ink-2)", marginTop: 2 }}>{label}</div>
    </div>
  );
}
