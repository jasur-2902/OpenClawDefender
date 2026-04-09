import { useState, useEffect, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  AiScanProgress,
  AiScanFinding,
  ScanFindingEvent,
  ScanStageCompleteEvent,
  ScanCompleteEvent,
  ScanUserRequest,
} from "../../types";
import { AiFindingCard } from "./AiFindingCard";

interface Props {
  scanId: string;
  onComplete: () => void;
  onCancel: () => void;
}

interface ActivityItem {
  id: string;
  type: "finding" | "stage" | "info";
  message: string;
  severity?: string;
  timestamp: number;
}

export function LiveScanView({ scanId, onComplete, onCancel }: Props) {
  const [progress, setProgress] = useState<AiScanProgress | null>(null);
  const [findings, setFindings] = useState<AiScanFinding[]>([]);
  const [completedStages, setCompletedStages] = useState<string[]>([]);
  const [scanComplete, setScanComplete] = useState(false);
  const [userRequest, setUserRequest] = useState<ScanUserRequest | null>(null);
  const [responseText, setResponseText] = useState("");
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [elapsed, setElapsed] = useState(0);
  const [cancelling, setCancelling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);
  const startTimeRef = useRef(Date.now());

  const addActivity = useCallback((item: Omit<ActivityItem, "id" | "timestamp">) => {
    setActivity((prev) => [
      ...prev,
      { ...item, id: `${Date.now()}-${Math.random()}`, timestamp: Date.now() },
    ]);
  }, []);

  // Poll progress every 2 seconds
  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const p = await invoke<AiScanProgress>("get_ai_scan_progress", { scanId });
        setProgress(p);
      } catch {
        // Scan might have completed already
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [scanId]);

  // Elapsed time timer
  useEffect(() => {
    startTimeRef.current = Date.now();
    const interval = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startTimeRef.current) / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // Listen to Tauri events
  useEffect(() => {
    const unlisteners: Array<() => void> = [];

    listen<ScanFindingEvent>("clawdefender://scan-finding", (event) => {
      const payload = event.payload;
      if (payload.scan_id !== scanId) return;
      addActivity({
        type: "finding",
        message: `${payload.severity.toUpperCase()}: ${payload.title}`,
        severity: payload.severity,
      });
      // We'll get the full finding from progress polling; add a minimal one for now
      setFindings((prev) => {
        if (prev.some((f) => f.id === payload.finding_id)) return prev;
        return [
          ...prev,
          {
            id: payload.finding_id,
            severity: payload.severity as AiScanFinding["severity"],
            title: payload.title,
            description: "",
            evidence_ids: [],
            remediation_hint: null,
            stage: payload.stage,
            discovered_at: new Date().toISOString(),
          },
        ];
      });
    }).then((fn) => unlisteners.push(fn));

    listen<ScanStageCompleteEvent>("clawdefender://scan-stage-complete", (event) => {
      const payload = event.payload;
      if (payload.scan_id !== scanId) return;
      setCompletedStages((prev) => [...prev, payload.stage_name]);
      addActivity({
        type: "stage",
        message: `Stage completed: ${payload.stage_name} (${payload.stages_completed}/${payload.stages_total})`,
      });
    }).then((fn) => unlisteners.push(fn));

    listen<ScanCompleteEvent>("clawdefender://scan-complete", (event) => {
      const payload = event.payload;
      if (payload.scan_id !== scanId) return;
      setScanComplete(true);
      addActivity({
        type: "info",
        message: `Scan ${payload.status}: ${payload.summary}`,
      });
      onComplete();
    }).then((fn) => unlisteners.push(fn));

    listen<ScanUserRequest>("clawdefender://scan-user-request", (event) => {
      const payload = event.payload;
      if (payload.scan_id !== scanId) return;
      setUserRequest(payload);
    }).then((fn) => unlisteners.push(fn));

    return () => {
      unlisteners.forEach((fn) => fn());
    };
  }, [scanId, addActivity, onComplete]);

  // Auto-scroll feed
  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [activity, findings]);

  async function handleCancel() {
    setCancelling(true);
    try {
      await invoke("cancel_ai_scan", { scanId });
      onCancel();
    } catch (e) {
      setError(String(e));
      setCancelling(false);
    }
  }

  async function handleUserResponse(approved: boolean) {
    if (!userRequest) return;
    try {
      await invoke("respond_to_scan_request", {
        scanId,
        requestId: userRequest.request_id,
        response: approved ? "approved" : "denied",
      });
      addActivity({
        type: "info",
        message: approved ? "User approved the request" : "User denied the request",
      });
    } catch (e) {
      setError(String(e));
    }
    setUserRequest(null);
    setResponseText("");
  }

  async function handleUserTextResponse() {
    if (!userRequest || !responseText.trim()) return;
    try {
      await invoke("respond_to_scan_request", {
        scanId,
        requestId: userRequest.request_id,
        response: responseText.trim(),
      });
      addActivity({ type: "info", message: `User responded: ${responseText.trim()}` });
    } catch (e) {
      setError(String(e));
    }
    setUserRequest(null);
    setResponseText("");
  }

  function formatElapsed(secs: number): string {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return m > 0 ? `${m}m ${s}s` : `${s}s`;
  }

  const progressPercent = progress?.progress_percent ?? 0;
  const stagesTotal = progress?.stages_total ?? 0;
  const stagesCompleted = progress?.stages_completed ?? completedStages.length;
  const toolCallsUsed = progress?.tool_calls_used ?? 0;
  const findingsCount = progress?.findings_count ?? findings.length;

  return (
    <div className="space-y-4">
      {error && (
        <div className="rounded-lg border border-[var(--color-danger)] bg-[var(--color-danger)]/10 p-3 text-sm text-[var(--color-danger)]">
          {error}
        </div>
      )}

      {/* User request banner */}
      {userRequest && (
        <div className="rounded-lg border-2 border-[var(--color-warning)] bg-[var(--color-warning)]/10 p-4 space-y-3">
          <div className="flex items-center gap-2">
            <span className="text-[var(--color-warning)] font-medium text-sm">Input Required</span>
          </div>
          <p className="text-sm text-[var(--color-text-primary)]">{userRequest.question}</p>
          {userRequest.context && (
            <p className="text-xs text-[var(--color-text-secondary)]">{userRequest.context}</p>
          )}
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleUserResponse(true)}
              className="px-3 py-1.5 rounded-md text-xs font-medium bg-[var(--color-safe)] text-white hover:opacity-90 transition-opacity"
            >
              Allow
            </button>
            <button
              onClick={() => handleUserResponse(false)}
              className="px-3 py-1.5 rounded-md text-xs font-medium bg-[var(--color-danger)] text-white hover:opacity-90 transition-opacity"
            >
              Deny
            </button>
            <div className="flex-1 flex items-center gap-2">
              <input
                type="text"
                value={responseText}
                onChange={(e) => setResponseText(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleUserTextResponse()}
                placeholder="Or type a response..."
                className="flex-1 px-2 py-1 rounded text-xs border border-[var(--color-border)] bg-[var(--color-bg-secondary)] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
              />
              <button
                onClick={handleUserTextResponse}
                disabled={!responseText.trim()}
                className="px-2.5 py-1 rounded text-xs font-medium bg-[var(--color-accent)] text-white disabled:opacity-50"
              >
                Send
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Header stats */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {!scanComplete && (
              <span className="inline-block w-2 h-2 rounded-full bg-[var(--color-accent)] animate-pulse" />
            )}
            <span className="text-sm font-medium text-[var(--color-text-primary)]">
              {scanComplete ? "Scan Complete" : progress?.current_stage ? `Analyzing: ${progress.current_stage}` : "Initializing..."}
            </span>
          </div>
          {!scanComplete && (
            <button
              onClick={handleCancel}
              disabled={cancelling}
              className="px-3 py-1 rounded-md text-xs font-medium border border-[var(--color-danger)] text-[var(--color-danger)] hover:bg-[var(--color-danger)]/10 disabled:opacity-50 transition-colors"
            >
              {cancelling ? "Cancelling..." : "Stop Scan"}
            </button>
          )}
        </div>

        {/* Progress bar */}
        <div>
          <div className="flex justify-between text-xs text-[var(--color-text-secondary)] mb-1">
            <span>Stages: {stagesCompleted}/{stagesTotal}</span>
            <span>{Math.round(progressPercent)}%</span>
          </div>
          <div className="w-full h-2 rounded-full bg-[var(--color-bg-primary)]">
            <div
              className="h-2 rounded-full bg-[var(--color-accent)] transition-all duration-500"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </div>

        {/* Stage stepper */}
        {stagesTotal > 0 && (
          <div className="flex items-center gap-1 overflow-x-auto py-1">
            {Array.from({ length: stagesTotal }, (_, i) => (
              <div
                key={i}
                className={`h-1.5 flex-1 rounded-full min-w-[20px] transition-colors ${
                  i < stagesCompleted
                    ? "bg-[var(--color-accent)]"
                    : i === stagesCompleted && !scanComplete
                      ? "bg-[var(--color-accent)]/40 animate-pulse"
                      : "bg-[var(--color-bg-tertiary)]"
                }`}
              />
            ))}
          </div>
        )}

        {/* Stats row */}
        <div className="flex gap-6 text-xs text-[var(--color-text-secondary)]">
          <div>
            <span className="text-[var(--color-text-muted)]">Elapsed: </span>
            <span className="font-medium text-[var(--color-text-primary)]">{formatElapsed(elapsed)}</span>
          </div>
          <div>
            <span className="text-[var(--color-text-muted)]">Tool Calls: </span>
            <span className="font-medium text-[var(--color-text-primary)]">{toolCallsUsed}</span>
          </div>
          <div>
            <span className="text-[var(--color-text-muted)]">Findings: </span>
            <span className={`font-medium ${findingsCount > 0 ? "text-[var(--color-warning)]" : "text-[var(--color-safe)]"}`}>
              {findingsCount}
            </span>
          </div>
        </div>
      </div>

      {/* Activity feed + findings split */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Activity feed */}
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] overflow-hidden">
          <div className="px-4 py-2 border-b border-[var(--color-border)]">
            <span className="text-xs font-medium text-[var(--color-text-secondary)]">Activity Feed</span>
          </div>
          <div
            ref={feedRef}
            className="max-h-80 overflow-y-auto p-2 space-y-1"
          >
            {activity.length === 0 && (
              <div className="text-xs text-[var(--color-text-muted)] p-2">
                Waiting for scan activity...
              </div>
            )}
            {activity.map((item) => (
              <div
                key={item.id}
                className={`flex items-start gap-2 px-2 py-1.5 rounded text-xs ${
                  item.type === "finding"
                    ? "bg-[var(--color-warning)]/5"
                    : item.type === "stage"
                      ? "bg-[var(--color-accent)]/5"
                      : "bg-transparent"
                }`}
              >
                <span className="shrink-0 mt-0.5">
                  {item.type === "finding" ? (
                    <span className={`inline-block w-1.5 h-1.5 rounded-full ${
                      item.severity === "critical" ? "bg-red-400" :
                      item.severity === "high" ? "bg-orange-400" :
                      item.severity === "medium" ? "bg-yellow-400" :
                      "bg-blue-400"
                    }`} />
                  ) : item.type === "stage" ? (
                    <span className="inline-block w-1.5 h-1.5 rounded-full bg-[var(--color-accent)]" />
                  ) : (
                    <span className="inline-block w-1.5 h-1.5 rounded-full bg-[var(--color-text-muted)]" />
                  )}
                </span>
                <span className="text-[var(--color-text-primary)] flex-1">{item.message}</span>
                <span className="text-[var(--color-text-muted)] shrink-0">
                  {formatElapsed(Math.floor((item.timestamp - startTimeRef.current) / 1000))}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Live findings */}
        <div className="space-y-2">
          <div className="text-xs font-medium text-[var(--color-text-secondary)] px-1">
            Findings ({findings.length})
          </div>
          {findings.length === 0 ? (
            <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
              <div className="text-xs text-[var(--color-text-muted)] text-center">
                {scanComplete ? "No findings discovered." : "No findings yet..."}
              </div>
            </div>
          ) : (
            <div className="space-y-2 max-h-80 overflow-y-auto">
              {findings.map((f) => (
                <AiFindingCard key={f.id} finding={f} scanId={scanId} animate />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
