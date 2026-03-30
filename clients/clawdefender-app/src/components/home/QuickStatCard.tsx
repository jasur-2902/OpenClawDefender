import { useNavigate } from "react-router-dom";

interface QuickStatCardProps {
  label: string;
  value: string | number;
  color?: string;
  navigateTo: string;
  loading?: boolean;
}

export function QuickStatCard({
  label,
  value,
  color,
  navigateTo,
  loading = false,
}: QuickStatCardProps) {
  const navigate = useNavigate();

  return (
    <button
      onClick={() => navigate(navigateTo)}
      className="bg-[var(--color-bg-secondary)] rounded-xl border border-[var(--color-border)] p-4 text-left cursor-pointer hover:border-[var(--color-border-subtle)] hover:bg-[var(--color-bg-tertiary)] transition-colors w-full focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--color-accent)]"
      aria-label={`${label}: ${value}`}
    >
      <p className="text-xs text-[var(--color-text-secondary)] uppercase tracking-wide">
        {label}
      </p>
      {loading ? (
        <div className="mt-2 h-7 w-12 rounded bg-[var(--color-bg-tertiary)] animate-pulse" />
      ) : (
        <p
          className="text-2xl font-bold mt-1 tabular-nums"
          style={{ color: color ?? "var(--color-text-primary)" }}
        >
          {value}
        </p>
      )}
    </button>
  );
}
