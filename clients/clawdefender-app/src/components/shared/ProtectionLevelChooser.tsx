import { useCallback, useRef } from "react";
import { ONBOARDING_PROTECTION_LEVELS } from "../../constants/messages";

export type ProtectionLevelId = "handle" | "ask" | "watch";

interface LevelOption {
  id: ProtectionLevelId;
  label: string;
  quote: string;
  subtitle: string;
  templateName: string;
  recommended: boolean;
}

const LEVELS: LevelOption[] = [
  {
    id: "handle",
    label: ONBOARDING_PROTECTION_LEVELS.staySharp.label,
    quote: ONBOARDING_PROTECTION_LEVELS.staySharp.quote,
    subtitle: ONBOARDING_PROTECTION_LEVELS.staySharp.subtitle,
    templateName: "balanced",
    recommended: true,
  },
  {
    id: "ask",
    label: ONBOARDING_PROTECTION_LEVELS.lockItDown.label,
    quote: ONBOARDING_PROTECTION_LEVELS.lockItDown.quote,
    subtitle: ONBOARDING_PROTECTION_LEVELS.lockItDown.subtitle,
    templateName: "strict",
    recommended: false,
  },
  {
    id: "watch",
    label: ONBOARDING_PROTECTION_LEVELS.keepWatch.label,
    quote: ONBOARDING_PROTECTION_LEVELS.keepWatch.quote,
    subtitle: ONBOARDING_PROTECTION_LEVELS.keepWatch.subtitle,
    templateName: "permissive",
    recommended: false,
  },
];

interface ProtectionLevelChooserProps {
  selectedLevel: ProtectionLevelId;
  onSelect: (level: ProtectionLevelId) => void;
  showRecommended?: boolean;
  compact?: boolean;
}

export function getTemplateName(level: ProtectionLevelId): string {
  const found = LEVELS.find((l) => l.id === level);
  return found?.templateName ?? "balanced";
}

export function getLevelLabel(level: ProtectionLevelId): string {
  const found = LEVELS.find((l) => l.id === level);
  return found?.label ?? "Stay Sharp";
}

export function ProtectionLevelChooser({
  selectedLevel,
  onSelect,
  showRecommended = true,
  compact = false,
}: ProtectionLevelChooserProps) {
  const groupRef = useRef<HTMLDivElement>(null);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      const currentIndex = LEVELS.findIndex((l) => l.id === selectedLevel);
      let nextIndex = currentIndex;

      if (e.key === "ArrowDown" || e.key === "ArrowRight") {
        e.preventDefault();
        nextIndex = (currentIndex + 1) % LEVELS.length;
      } else if (e.key === "ArrowUp" || e.key === "ArrowLeft") {
        e.preventDefault();
        nextIndex = (currentIndex - 1 + LEVELS.length) % LEVELS.length;
      } else {
        return;
      }

      onSelect(LEVELS[nextIndex].id);
      // Focus the newly selected option
      const group = groupRef.current;
      if (group) {
        const buttons = group.querySelectorAll<HTMLElement>("[role='radio']");
        buttons[nextIndex]?.focus();
      }
    },
    [selectedLevel, onSelect]
  );

  return (
    <div
      ref={groupRef}
      role="radiogroup"
      aria-label="Protection level"
      onKeyDown={handleKeyDown}
      className={
        compact
          ? "space-y-2"
          : "flex flex-col gap-3 lg:flex-row lg:gap-4"
      }
    >
      {LEVELS.map((level) => {
        const isSelected = selectedLevel === level.id;

        return (
          <button
            key={level.id}
            role="radio"
            aria-checked={isSelected}
            aria-label={`${level.label}: ${level.subtitle}${level.recommended && showRecommended ? " (Recommended)" : ""}`}
            tabIndex={isSelected ? 0 : -1}
            onClick={() => onSelect(level.id)}
            className={`
              w-full text-left rounded-lg border-2 transition-colors
              focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--color-accent)]
              ${compact ? "p-3" : "p-5 lg:flex-1"}
              ${
                isSelected
                  ? "border-[var(--color-accent)] bg-[var(--color-accent-subtle)]"
                  : "border-[var(--color-border)] bg-[var(--color-bg-tertiary)] hover:border-[var(--color-text-muted)]"
              }
            `}
          >
            <div className="flex items-start justify-between gap-2">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className={`font-semibold ${compact ? "text-sm" : "text-base"} text-[var(--color-text-primary)]`}
                  >
                    {level.label}
                  </span>
                  {showRecommended && level.recommended && (
                    <span className="text-xs px-2 py-0.5 rounded-full bg-[var(--color-accent)] text-white font-medium">
                      Recommended
                    </span>
                  )}
                </div>
                {!compact && (
                  <p className="text-sm text-[var(--color-text-secondary)] mt-2 italic leading-relaxed">
                    "{level.quote}"
                  </p>
                )}
                <p
                  className={`text-[var(--color-text-muted)] ${compact ? "text-xs mt-1" : "text-sm mt-2"}`}
                >
                  {level.subtitle}
                </p>
              </div>
              {/* Radio indicator */}
              <div
                aria-hidden="true"
                className={`shrink-0 mt-1 w-5 h-5 rounded-full border-2 flex items-center justify-center ${
                  isSelected
                    ? "border-[var(--color-accent)]"
                    : "border-[var(--color-border)]"
                }`}
              >
                {isSelected && (
                  <div className="w-2.5 h-2.5 rounded-full bg-[var(--color-accent)]" />
                )}
              </div>
            </div>
          </button>
        );
      })}
    </div>
  );
}
