import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface ProtectionLevelProps {
  currentLevel: string;
  onLevelChanged: () => void;
}

const levels = [
  {
    id: "monitor-only",
    templateName: "permissive",
    label: "Handle it for me",
    description: "I will log everything and let you know if something looks off, but I will not block anything.",
    color: "var(--color-accent)",
  },
  {
    id: "balanced",
    templateName: "balanced",
    label: "Ask me when in doubt",
    description: "I will block anything dangerous and ask you about the rest. Most people start here.",
    color: "var(--color-warning)",
  },
  {
    id: "strict",
    templateName: "strict",
    label: "Let me see everything",
    description: "Nothing gets through without your say-so. I will prompt you for every action.",
    color: "var(--color-danger)",
  },
];

export function ProtectionLevel({ currentLevel, onLevelChanged }: ProtectionLevelProps) {
  const [pendingLevel, setPendingLevel] = useState<string | null>(null);
  const [applying, setApplying] = useState(false);
  const [diffPreview, setDiffPreview] = useState<string[] | null>(null);

  async function handleSelect(levelId: string) {
    if (levelId === currentLevel) {
      setPendingLevel(null);
      setDiffPreview(null);
      return;
    }
    setPendingLevel(levelId);

    const level = levels.find((l) => l.id === levelId);
    if (!level) return;

    // Build a plain-language diff preview
    const changes: string[] = [];
    if (levelId === "monitor-only") {
      changes.push("All actions will be allowed through");
      changes.push("Everything will be logged for your review");
      changes.push("No prompts or blocks");
    } else if (levelId === "balanced") {
      changes.push("Known dangerous actions will be blocked");
      changes.push("Uncertain actions will ask for your decision");
      changes.push("Safe operations proceed automatically");
    } else if (levelId === "strict") {
      changes.push("Most actions will require your approval");
      changes.push("File writes blocked by default");
      changes.push("Network access requires approval");
    }
    setDiffPreview(changes);
  }

  async function handleApply() {
    if (!pendingLevel) return;
    const level = levels.find((l) => l.id === pendingLevel);
    if (!level) return;

    setApplying(true);
    try {
      await invoke("apply_template", { name: level.templateName });
      await invoke("reload_policy").catch(() => {});
      onLevelChanged();
      setPendingLevel(null);
      setDiffPreview(null);
    } catch {
      // Template may not be available
    } finally {
      setApplying(false);
    }
  }

  function handleCancel() {
    setPendingLevel(null);
    setDiffPreview(null);
  }

  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4">
      <p className="text-sm font-medium mb-1">Protection Level</p>
      <p className="text-xs text-[var(--color-text-secondary)] mb-4">
        Choose how I handle requests from your AI tools
      </p>

      <div className="space-y-2">
        {levels.map((level) => {
          const isActive = level.id === currentLevel && !pendingLevel;
          const isPending = level.id === pendingLevel;
          return (
            <button
              key={level.id}
              onClick={() => handleSelect(level.id)}
              aria-pressed={isActive}
              className={`w-full text-left p-3 rounded-lg border transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--color-accent)] ${
                isActive
                  ? "border-[var(--color-accent)] bg-[var(--color-accent-subtle)]"
                  : isPending
                  ? "border-[var(--color-warning)] bg-[var(--color-warning-subtle)]"
                  : "border-[var(--color-border)] hover:border-[var(--color-text-muted)]"
              }`}
            >
              <div className="flex items-center gap-2">
                <span
                  className="inline-block w-2.5 h-2.5 rounded-full shrink-0"
                  style={{ backgroundColor: level.color }}
                />
                <span className="text-sm font-medium">{level.label}</span>
                {isActive && (
                  <span className="ml-auto text-xs text-[var(--color-text-muted)] bg-[var(--color-bg-tertiary)] px-2 py-0.5 rounded">
                    Current
                  </span>
                )}
              </div>
              <p className="text-xs text-[var(--color-text-secondary)] mt-1 ml-[18px]">
                {level.description}
              </p>
            </button>
          );
        })}
      </div>

      {/* Diff preview + apply/cancel */}
      {pendingLevel && diffPreview && (
        <div className="mt-4 pt-4 border-t border-[var(--color-border)]">
          <p className="text-xs font-medium text-[var(--color-text-secondary)] mb-2">
            Switching will:
          </p>
          <ul className="space-y-1 mb-4">
            {diffPreview.map((change) => (
              <li key={change} className="text-xs text-[var(--color-text-primary)] flex items-center gap-1.5">
                <span className="text-[var(--color-accent)]">&rarr;</span> {change}
              </li>
            ))}
          </ul>
          <div className="flex gap-2">
            <button
              onClick={handleApply}
              disabled={applying}
              className="px-4 py-2 rounded-lg text-sm text-white bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)] disabled:opacity-50"
            >
              {applying ? "Applying..." : "Apply"}
            </button>
            <button
              onClick={handleCancel}
              className="px-4 py-2 rounded-lg text-sm text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] border border-[var(--color-border)] hover:bg-[var(--color-bg-tertiary)]"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
