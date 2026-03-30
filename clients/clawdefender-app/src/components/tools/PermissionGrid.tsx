import { useCallback, useState } from "react";
import { useToolStore } from "../../stores/toolStore";
import type { PermissionState, PermissionAction } from "../../types";

const ACTION_OPTIONS: { value: PermissionAction; label: string; color: string }[] = [
  { value: "allow", label: "Allowed", color: "var(--color-safe)" },
  { value: "prompt", label: "Asks first", color: "var(--color-warning)" },
  { value: "block", label: "Blocked", color: "var(--color-danger)" },
];

const PERMISSION_ICONS: Record<string, string> = {
  file_read_project: "folder-open",
  file_read_external: "folder-search",
  file_write: "file-pen",
  shell_exec: "terminal",
  network_access: "globe",
  sensitive_paths: "shield-x",
};

interface PermissionGridProps {
  serverName: string;
  permissions: PermissionState[];
  onChanged?: () => void;
}

export function PermissionGrid({
  serverName,
  permissions,
  onChanged,
}: PermissionGridProps) {
  const setPermission = useToolStore((s) => s.setPermission);
  const resetPermission = useToolStore((s) => s.resetPermission);
  const [updating, setUpdating] = useState<string | null>(null);

  const handleChange = useCallback(
    async (permId: string, action: PermissionAction) => {
      setUpdating(permId);
      await setPermission(serverName, permId, action);
      setUpdating(null);
      onChanged?.();
    },
    [serverName, setPermission, onChanged]
  );

  const handleReset = useCallback(
    async (permId: string) => {
      setUpdating(permId);
      await resetPermission(serverName, permId);
      setUpdating(null);
      onChanged?.();
    },
    [serverName, resetPermission, onChanged]
  );

  const ACTION_CYCLE: PermissionAction[] = ["allow", "prompt", "block"];

  const handleRowKeyDown = useCallback(
    (e: React.KeyboardEvent, perm: PermissionState) => {
      if (perm.locked) return;

      const currentIdx = ACTION_CYCLE.indexOf(perm.action);
      let nextIdx = -1;

      if (e.key === "ArrowRight") {
        e.preventDefault();
        nextIdx = (currentIdx + 1) % ACTION_CYCLE.length;
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        nextIdx = (currentIdx - 1 + ACTION_CYCLE.length) % ACTION_CYCLE.length;
      }

      if (nextIdx >= 0) {
        handleChange(perm.id, ACTION_CYCLE[nextIdx]);
      }
    },
    [handleChange]
  );

  return (
    <div role="list" aria-label="Permission settings" className="space-y-1">
      {permissions.map((perm) => (
        <div
          key={perm.id}
          role="listitem"
          tabIndex={0}
          aria-label={`${perm.name}: ${perm.locked ? "Always blocked for your safety" : ACTION_OPTIONS.find((o) => o.value === perm.action)?.label ?? perm.action}`}
          onKeyDown={(e) => handleRowKeyDown(e, perm)}
          className={`flex items-center gap-3 p-3 rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1 ${
            perm.locked
              ? "bg-[var(--color-bg-sunken)] opacity-70"
              : "bg-[var(--color-bg-secondary)]"
          } ${perm.overridden ? "border border-[var(--color-warning-border)]" : ""}`}
        >
          {/* Icon */}
          <span aria-hidden="true">
            <PermIcon type={PERMISSION_ICONS[perm.id] ?? "shield"} />
          </span>

          {/* Label */}
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-[var(--color-text-primary)]">
              {perm.name}
            </p>
            <p className="text-xs text-[var(--color-text-muted)] truncate">
              {perm.description}
            </p>
          </div>

          {/* Lock indicator */}
          {perm.locked ? (
            <span
              className="inline-flex items-center gap-1 text-xs text-[var(--color-text-muted)]"
              title="Always blocked for your safety"
              aria-label="Always blocked for your safety"
            >
              <LockIcon />
              Always blocked
            </span>
          ) : (
            <div className="flex items-center gap-1">
              {/* Segmented toggle */}
              <div className="flex rounded-md border border-[var(--color-border)] overflow-hidden">
                {ACTION_OPTIONS.map((opt) => {
                  const isActive = perm.action === opt.value;
                  return (
                    <button
                      key={opt.value}
                      aria-pressed={isActive}
                      aria-label={`Set ${perm.name} to ${opt.label}`}
                      onClick={() => handleChange(perm.id, opt.value)}
                      disabled={updating === perm.id}
                      className={`px-2 py-1 text-[10px] font-medium transition-colors duration-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-inset ${
                        isActive
                          ? "text-white"
                          : "text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)] bg-[var(--color-bg-primary)]"
                      } disabled:opacity-40`}
                      style={isActive ? { backgroundColor: opt.color } : undefined}
                    >
                      {opt.label}
                    </button>
                  );
                })}
              </div>

              {/* Reset if overridden */}
              {perm.overridden && (
                <button
                  onClick={() => handleReset(perm.id)}
                  disabled={updating === perm.id}
                  className="text-[10px] text-[var(--color-accent)] hover:underline ml-1 disabled:opacity-40"
                  title="Reset to trust level default"
                >
                  Reset
                </button>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function PermIcon({ type }: { type: string }) {
  const props = {
    width: 16,
    height: 16,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "var(--color-text-secondary)",
    strokeWidth: 1.75,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    className: "shrink-0",
  };

  switch (type) {
    case "folder-open":
      return (
        <svg {...props}>
          <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
        </svg>
      );
    case "folder-search":
      return (
        <svg {...props}>
          <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
          <circle cx="14" cy="14" r="3" />
          <line x1="16.5" y1="16.5" x2="19" y2="19" />
        </svg>
      );
    case "file-pen":
      return (
        <svg {...props}>
          <path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z" />
        </svg>
      );
    case "terminal":
      return (
        <svg {...props}>
          <polyline points="4 17 10 11 4 5" />
          <line x1="12" y1="19" x2="20" y2="19" />
        </svg>
      );
    case "globe":
      return (
        <svg {...props}>
          <circle cx="12" cy="12" r="10" />
          <line x1="2" y1="12" x2="22" y2="12" />
          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
        </svg>
      );
    case "shield-x":
      return (
        <svg {...props} stroke="var(--color-danger)">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <line x1="9.5" y1="9.5" x2="14.5" y2="14.5" />
          <line x1="14.5" y1="9.5" x2="9.5" y2="14.5" />
        </svg>
      );
    default:
      return (
        <svg {...props}>
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
      );
  }
}

function LockIcon() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  );
}
