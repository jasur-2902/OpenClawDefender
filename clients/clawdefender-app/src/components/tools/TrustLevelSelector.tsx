import { useState, useCallback, useRef, useEffect } from "react";
import { ShieldIcon, getTrustColor, getTrustLabel } from "./ShieldIcon";
import { useToolStore } from "../../stores/toolStore";
import type { TrustLevel, PermissionChange } from "../../types";

const TRUST_LEVELS: TrustLevel[] = ["trusted", "standard", "cautious", "restricted"];

const TRUST_DESCRIPTIONS: Record<TrustLevel, string> = {
  trusted: "Allow most actions. Only prompts for shell commands.",
  standard: "Balanced. Prompts for writes, network, and unknown tools.",
  cautious: "Restrictive. Blocks writes and commands, prompts for network.",
  restricted: "Maximum restriction. Blocks most actions.",
};

interface TrustLevelSelectorProps {
  serverName: string;
  currentLevel: TrustLevel;
  customized: boolean;
  onLevelChanged?: () => void;
}

export function TrustLevelSelector({
  serverName,
  currentLevel,
  customized,
  onLevelChanged,
}: TrustLevelSelectorProps) {
  const [selectedLevel, setSelectedLevel] = useState<TrustLevel | null>(null);
  const [changes, setChanges] = useState<PermissionChange[]>([]);
  const [applying, setApplying] = useState(false);

  const previewTrustChange = useToolStore((s) => s.previewTrustChange);
  const setTrustLevel = useToolStore((s) => s.setTrustLevel);
  const selectorRef = useRef<HTMLDivElement>(null);
  const applyButtonRef = useRef<HTMLButtonElement>(null);

  const handleSelect = useCallback(
    async (level: TrustLevel) => {
      if (level === currentLevel && !customized) {
        setSelectedLevel(null);
        setChanges([]);
        return;
      }
      setSelectedLevel(level);
      const preview = await previewTrustChange(serverName, level);
      setChanges(preview);
    },
    [serverName, currentLevel, customized, previewTrustChange]
  );

  const handleApply = useCallback(async () => {
    if (!selectedLevel) return;
    setApplying(true);
    await setTrustLevel(serverName, selectedLevel);
    setApplying(false);
    setSelectedLevel(null);
    setChanges([]);
    onLevelChanged?.();
    // Return focus to the selector after applying
    requestAnimationFrame(() => {
      const active = selectorRef.current?.querySelector<HTMLElement>('[aria-checked="true"]');
      active?.focus();
    });
  }, [selectedLevel, serverName, setTrustLevel, onLevelChanged]);

  const handleCancel = useCallback(() => {
    setSelectedLevel(null);
    setChanges([]);
    // Return focus to current level button
    requestAnimationFrame(() => {
      const active = selectorRef.current?.querySelector<HTMLElement>('[aria-checked="true"]');
      active?.focus();
    });
  }, []);

  const handleReset = useCallback(async () => {
    setApplying(true);
    await setTrustLevel(serverName, currentLevel);
    setApplying(false);
    onLevelChanged?.();
  }, [serverName, currentLevel, setTrustLevel, onLevelChanged]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      const activeLevel = selectedLevel ?? currentLevel;
      const idx = TRUST_LEVELS.indexOf(activeLevel);
      let nextIdx = -1;

      if (e.key === "ArrowRight" || e.key === "ArrowDown") {
        e.preventDefault();
        nextIdx = (idx + 1) % TRUST_LEVELS.length;
      } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
        e.preventDefault();
        nextIdx = (idx - 1 + TRUST_LEVELS.length) % TRUST_LEVELS.length;
      } else if (e.key === "Escape" && selectedLevel) {
        e.preventDefault();
        handleCancel();
        return;
      }

      if (nextIdx >= 0) {
        const nextLevel = TRUST_LEVELS[nextIdx];
        handleSelect(nextLevel);
        // Focus the new radio button
        requestAnimationFrame(() => {
          const buttons = selectorRef.current?.querySelectorAll<HTMLElement>('[role="radio"]');
          buttons?.[nextIdx]?.focus();
        });
      }
    },
    [selectedLevel, currentLevel, handleSelect, handleCancel]
  );

  // Focus the Apply button when diff preview appears
  useEffect(() => {
    if (selectedLevel && selectedLevel !== currentLevel && changes.length >= 0) {
      requestAnimationFrame(() => {
        applyButtonRef.current?.focus();
      });
    }
  }, [selectedLevel, currentLevel, changes]);

  return (
    <div>
      {/* Segmented control */}
      <div
        ref={selectorRef}
        role="radiogroup"
        aria-label="Trust level"
        className="flex rounded-lg border border-[var(--color-border)] overflow-hidden"
        onKeyDown={handleKeyDown}
      >
        {TRUST_LEVELS.map((level) => {
          const isActive =
            selectedLevel != null ? level === selectedLevel : level === currentLevel;
          return (
            <button
              key={level}
              role="radio"
              aria-checked={isActive}
              aria-label={`${getTrustLabel(level)}: ${TRUST_DESCRIPTIONS[level]}`}
              tabIndex={isActive ? 0 : -1}
              onClick={() => handleSelect(level)}
              className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium transition-colors duration-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-inset ${
                isActive
                  ? "bg-[var(--color-bg-tertiary)]"
                  : "bg-[var(--color-bg-secondary)] hover:bg-[var(--color-bg-tertiary)]"
              }`}
              style={
                isActive
                  ? { color: getTrustColor(level), borderBottom: `2px solid ${getTrustColor(level)}` }
                  : { color: "var(--color-text-secondary)" }
              }
            >
              <ShieldIcon level={level} size={14} />
              {getTrustLabel(level)}
            </button>
          );
        })}
      </div>

      {/* Description */}
      <p className="text-xs text-[var(--color-text-muted)] mt-2">
        {TRUST_DESCRIPTIONS[selectedLevel ?? currentLevel]}
      </p>

      {/* Customized indicator */}
      {customized && !selectedLevel && (
        <div className="flex items-center gap-2 mt-2">
          <span className="text-xs text-[var(--color-text-muted)]">
            Permissions have been customized
          </span>
          <button
            onClick={handleReset}
            disabled={applying}
            className="text-xs text-[var(--color-accent)] hover:underline disabled:opacity-50"
          >
            Reset to defaults
          </button>
        </div>
      )}

      {/* Preview changes */}
      {selectedLevel && selectedLevel !== currentLevel && (
        <div id="trust-diff-preview" className="mt-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] p-3" aria-live="polite">
          <p className="text-xs font-medium text-[var(--color-text-primary)] mb-2">
            Switching to {getTrustLabel(selectedLevel)} will:
          </p>
          {changes.length > 0 ? (
            <div className="space-y-1">
              {changes.map((c) => (
                <div key={c.permission} className="flex items-center gap-2 text-xs">
                  <span>
                    {c.to_action === c.from_action ? (
                      <span className="text-[var(--color-safe)]">Keep</span>
                    ) : (
                      <span className="text-[var(--color-warning)]">Change</span>
                    )}
                  </span>
                  <span className="text-[var(--color-text-secondary)]">
                    {c.description}
                  </span>
                  {c.to_action !== c.from_action && (
                    <span className="text-[var(--color-text-muted)]">
                      {c.from_action} &rarr; {c.to_action}
                    </span>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-[var(--color-text-muted)]">
              No permission changes to preview
            </p>
          )}
          <div className="flex items-center gap-2 mt-3">
            <button
              ref={applyButtonRef}
              onClick={handleApply}
              disabled={applying}
              aria-describedby="trust-diff-preview"
              className="px-3 py-1.5 rounded-md text-xs font-medium bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] disabled:opacity-40 transition-colors duration-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
            >
              {applying ? "Applying..." : "Apply"}
            </button>
            <button
              onClick={handleCancel}
              disabled={applying}
              className="px-3 py-1.5 rounded-md text-xs font-medium bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)] border border-[var(--color-border)] hover:bg-[var(--color-bg-sunken)] disabled:opacity-40 transition-colors duration-100"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
