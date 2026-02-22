import { useEffect, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { DoctorCheck, SystemInfo } from "../types";

export function SystemHealth() {
  const [checks, setChecks] = useState<DoctorCheck[]>([]);
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = useCallback(async () => {
    try {
      const [c, s] = await Promise.all([
        invoke<DoctorCheck[]>("run_doctor"),
        invoke<SystemInfo>("get_system_info"),
      ]);
      setChecks(c);
      setSystemInfo(s);
      setError(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  function overallStatus(): "pass" | "warn" | "fail" {
    if (checks.some((c) => c.status === "fail")) return "fail";
    if (checks.some((c) => c.status === "warn")) return "warn";
    return "pass";
  }

  function statusIcon(status: DoctorCheck["status"]): string {
    switch (status) {
      case "pass":
        return "\u2713";
      case "warn":
        return "\u26A0";
      case "fail":
        return "\u2717";
    }
  }

  function statusStyle(status: DoctorCheck["status"]): string {
    switch (status) {
      case "pass":
        return "text-[var(--color-success)] bg-[var(--color-success)]/20";
      case "warn":
        return "text-[var(--color-warning)] bg-[var(--color-warning)]/20";
      case "fail":
        return "text-[var(--color-danger)] bg-[var(--color-danger)]/20";
    }
  }

  function overallBadge() {
    const s = overallStatus();
    const labels = { pass: "Healthy", warn: "Warnings", fail: "Issues Found" };
    return (
      <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${statusStyle(s)}`}>
        {labels[s]}
      </span>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-bold">System Health</h1>
        {!loading && checks.length > 0 && overallBadge()}
      </div>

      {error && (
        <div className="rounded-lg border border-[var(--color-danger)] bg-[var(--color-danger)]/10 p-4 text-sm text-[var(--color-danger)]">
          {error}
        </div>
      )}

      {loading ? (
        <div className="text-sm text-[var(--color-text-secondary)]">Running diagnostics...</div>
      ) : (
        <>
          <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] overflow-hidden">
            <div className="px-4 py-3 border-b border-[var(--color-border)]">
              <h2 className="font-semibold">Diagnostic Checks</h2>
            </div>
            <div className="divide-y divide-[var(--color-border)]">
              {checks.map((check) => (
                <div key={check.name} className="px-4 py-3 flex items-start gap-3">
                  <span
                    className={`inline-flex items-center justify-center w-6 h-6 rounded-full text-sm font-bold flex-shrink-0 ${statusStyle(
                      check.status
                    )}`}
                  >
                    {statusIcon(check.status)}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">{check.name}</span>
                    </div>
                    <p className="text-sm text-[var(--color-text-secondary)] mt-0.5">
                      {check.message}
                    </p>
                    {check.fix_suggestion && (
                      <button
                        onClick={async () => {
                          const suggestion = check.fix_suggestion!.toLowerCase();
                          if (
                            suggestion.includes("system settings") ||
                            suggestion.includes("privacy")
                          ) {
                            try {
                              await invoke("open_url", {
                                url: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles",
                              });
                            } catch {
                              // Command may not exist; ignore
                            }
                          } else if (suggestion.includes("start daemon")) {
                            try {
                              await invoke("start_daemon");
                              loadData();
                            } catch {
                              // ignore
                            }
                          }
                        }}
                        className="mt-2 px-3 py-1 rounded-md text-xs font-medium bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] transition-colors"
                      >
                        Fix: {check.fix_suggestion}
                      </button>
                    )}
                  </div>
                </div>
              ))}
              {checks.length === 0 && (
                <div className="px-4 py-6 text-center text-sm text-[var(--color-text-secondary)]">
                  No diagnostic checks available.
                </div>
              )}
            </div>
            <div className="px-4 py-2 border-t border-[var(--color-border)]">
              <button
                onClick={() => {
                  setLoading(true);
                  loadData();
                }}
                className="text-sm text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] transition-colors"
              >
                Re-run diagnostics
              </button>
            </div>
          </div>

          {systemInfo && (
            <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] overflow-hidden">
              <div className="px-4 py-3 border-b border-[var(--color-border)]">
                <h2 className="font-semibold">System Information</h2>
              </div>
              <div className="divide-y divide-[var(--color-border)]">
                {[
                  { label: "Operating System", value: systemInfo.os },
                  { label: "OS Version", value: systemInfo.os_version },
                  { label: "Architecture", value: systemInfo.arch },
                  {
                    label: "Daemon Version",
                    value: systemInfo.daemon_version ?? "Not detected",
                  },
                  { label: "App Version", value: systemInfo.app_version },
                  { label: "Config Directory", value: systemInfo.config_dir },
                  { label: "Log Directory", value: systemInfo.log_dir },
                ].map((row) => (
                  <div
                    key={row.label}
                    className="px-4 py-2.5 flex items-center justify-between"
                  >
                    <span className="text-sm text-[var(--color-text-secondary)]">
                      {row.label}
                    </span>
                    <span className="text-sm font-mono">{row.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
