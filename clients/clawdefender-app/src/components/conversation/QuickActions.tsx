interface QuickActionsProps {
  suggestions: readonly string[];
  onAction: (message: string) => void;
  disabled: boolean;
}

export function QuickActions({ suggestions, onAction, disabled }: QuickActionsProps) {
  if (!suggestions.length) return null;

  return (
    <div className="flex flex-wrap gap-2">
      {suggestions.map((s) => (
        <button
          key={s}
          onClick={() => onAction(s)}
          disabled={disabled}
          className="rounded-full border border-[var(--color-border)] bg-[var(--color-bg-tertiary)] px-3 py-1.5 text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-accent)] transition-colors duration-150 disabled:opacity-50"
        >
          {s}
        </button>
      ))}
    </div>
  );
}
