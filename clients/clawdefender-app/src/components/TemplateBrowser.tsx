import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { PolicyTemplate } from "../types";

interface TemplateBrowserProps {
  open: boolean;
  onClose: () => void;
  onApplied: () => void;
}

export function TemplateBrowser({ open, onClose, onApplied }: TemplateBrowserProps) {
  const [templates, setTemplates] = useState<PolicyTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [confirmName, setConfirmName] = useState<string | null>(null);
  const [applying, setApplying] = useState(false);

  useEffect(() => {
    if (!open) return;
    setLoading(true);
    invoke<PolicyTemplate[]>("list_templates")
      .then(setTemplates)
      .catch(() => {
        setTemplates([
          { name: "monitor-only", description: "Log everything, block nothing", rules_count: 5, category: "Getting Started" },
          { name: "balanced", description: "Balanced protection for daily use", rules_count: 12, category: "Recommended" },
          { name: "strict", description: "Maximum protection, block by default", rules_count: 18, category: "High Security" },
          { name: "development", description: "Relaxed rules for development workflows", rules_count: 8, category: "Developer" },
        ]);
      })
      .finally(() => setLoading(false));
  }, [open]);

  if (!open) return null;

  async function handleApply(name: string) {
    setApplying(true);
    try {
      await invoke("apply_template", { name });
      onApplied();
      onClose();
    } catch (_err) {
      // Tauri command may not be available yet
    } finally {
      setApplying(false);
      setConfirmName(null);
    }
  }

  const categoryColors: Record<string, string> = {
    "Getting Started": "var(--color-accent)",
    Recommended: "var(--color-success)",
    "High Security": "var(--color-danger)",
    Developer: "var(--color-warning)",
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div
        className="w-full max-w-lg rounded-xl border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-6 shadow-2xl max-h-[80vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-lg font-semibold mb-1">Policy Templates</h2>
        <p className="text-xs text-[var(--color-text-secondary)] mb-4">
          Browse and apply pre-configured policy templates.
        </p>

        {loading ? (
          <div className="text-center py-8 text-sm text-[var(--color-text-secondary)]">Loading templates...</div>
        ) : (
          <div className="space-y-3 mb-4">
            {templates.map((t) => (
              <div
                key={t.name}
                className="p-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)]"
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm font-medium">{t.name}</span>
                  <span
                    className="text-xs px-2 py-0.5 rounded"
                    style={{
                      backgroundColor: `${categoryColors[t.category] ?? "var(--color-accent)"}20`,
                      color: categoryColors[t.category] ?? "var(--color-accent)",
                    }}
                  >
                    {t.category}
                  </span>
                  <span className="ml-auto text-xs text-[var(--color-text-secondary)]">
                    {t.rules_count} rules
                  </span>
                </div>
                <p className="text-xs text-[var(--color-text-secondary)] mb-3">{t.description}</p>

                {confirmName === t.name ? (
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-[var(--color-warning)]">Replace current rules?</span>
                    <button
                      onClick={() => handleApply(t.name)}
                      disabled={applying}
                      className="px-3 py-1 rounded text-xs text-white bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)] disabled:opacity-50"
                    >
                      {applying ? "Applying..." : "Confirm"}
                    </button>
                    <button
                      onClick={() => setConfirmName(null)}
                      className="px-3 py-1 rounded text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <div className="flex gap-2">
                    <button
                      onClick={() => setConfirmName(t.name)}
                      className="px-3 py-1 rounded text-xs text-white bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)]"
                    >
                      Apply
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        <div className="flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-sm text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] border border-[var(--color-border)] hover:bg-[var(--color-bg-tertiary)]"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
