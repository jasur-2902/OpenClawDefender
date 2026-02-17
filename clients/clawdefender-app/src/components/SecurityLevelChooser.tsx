import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface SecurityLevelChooserProps {
  currentLevel: string;
  open: boolean;
  onClose: () => void;
  onApplied: () => void;
}

const levels = [
  {
    name: "monitor-only",
    label: "Monitor Only",
    description: "Log all activity without blocking. Good for initial setup.",
    changes: ["All rules set to audit", "No prompts or blocks", "Full logging enabled"],
    color: "var(--color-accent)",
  },
  {
    name: "balanced",
    label: "Balanced",
    description: "Block known dangers, prompt for unknowns, allow safe operations.",
    changes: ["File writes prompt user", "Network access allowed for known servers", "Dangerous patterns blocked"],
    color: "var(--color-warning)",
  },
  {
    name: "strict",
    label: "Strict",
    description: "Block by default, prompt for most actions. Maximum protection.",
    changes: ["All file writes blocked by default", "All network access requires approval", "Only whitelisted tools allowed"],
    color: "var(--color-danger)",
  },
];

export function SecurityLevelChooser({ currentLevel, open, onClose, onApplied }: SecurityLevelChooserProps) {
  const [selected, setSelected] = useState(currentLevel);
  const [applying, setApplying] = useState(false);

  if (!open) return null;

  async function handleApply() {
    if (selected === currentLevel) {
      onClose();
      return;
    }
    setApplying(true);
    try {
      await invoke("apply_template", { name: selected });
      onApplied();
      onClose();
    } catch (_err) {
      // Tauri command may not be available yet
    } finally {
      setApplying(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div
        className="w-full max-w-md rounded-xl border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-lg font-semibold mb-1">Security Level</h2>
        <p className="text-xs text-[var(--color-text-secondary)] mb-4">
          Choose a protection level. This replaces your current rules with a template.
        </p>

        <div className="space-y-3 mb-5">
          {levels.map((level) => {
            const isSelected = selected === level.name;
            const isCurrent = currentLevel === level.name;
            return (
              <button
                key={level.name}
                onClick={() => setSelected(level.name)}
                className={`w-full text-left p-4 rounded-lg border transition-colors ${
                  isSelected
                    ? "border-[var(--color-accent)] bg-[var(--color-bg-tertiary)]"
                    : "border-[var(--color-border)] bg-[var(--color-bg-primary)] hover:border-[var(--color-text-secondary)]"
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className="inline-block w-2.5 h-2.5 rounded-full"
                    style={{ backgroundColor: level.color }}
                  />
                  <span className="text-sm font-medium">{level.label}</span>
                  {isCurrent && (
                    <span className="ml-auto text-xs text-[var(--color-text-secondary)] bg-[var(--color-bg-tertiary)] px-2 py-0.5 rounded">
                      Current
                    </span>
                  )}
                </div>
                <p className="text-xs text-[var(--color-text-secondary)] mb-2">{level.description}</p>
                {isSelected && selected !== currentLevel && (
                  <div className="mt-2 pt-2 border-t border-[var(--color-border)]">
                    <p className="text-xs text-[var(--color-text-secondary)] mb-1">Changes:</p>
                    <ul className="space-y-0.5">
                      {level.changes.map((change) => (
                        <li key={change} className="text-xs text-[var(--color-text-primary)] flex items-center gap-1.5">
                          <span className="text-[var(--color-accent)]">&rarr;</span> {change}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </button>
            );
          })}
        </div>

        <div className="flex justify-end gap-2">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-sm text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] border border-[var(--color-border)] hover:bg-[var(--color-bg-tertiary)]"
          >
            Cancel
          </button>
          <button
            onClick={handleApply}
            disabled={applying}
            className="px-4 py-2 rounded-lg text-sm text-white bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)] disabled:opacity-50"
          >
            {applying ? "Applying..." : "Apply Level"}
          </button>
        </div>
      </div>
    </div>
  );
}
