import type { TrustLevel } from "../../types";

const TRUST_COLORS: Record<TrustLevel, string> = {
  trusted: "var(--color-safe)",
  standard: "var(--color-info)",
  cautious: "var(--color-warning)",
  restricted: "var(--color-danger)",
};

interface ShieldIconProps {
  level: TrustLevel;
  size?: number;
  className?: string;
}

export function ShieldIcon({ level, size = 16, className = "" }: ShieldIconProps) {
  const color = TRUST_COLORS[level];

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      {level === "trusted" && (
        <polyline points="9 12 11 14 15 10" />
      )}
      {level === "standard" && (
        <line x1="12" y1="9" x2="12" y2="13" />
      )}
      {level === "cautious" && (
        <>
          <line x1="12" y1="9" x2="12" y2="13" />
          <line x1="12" y1="16" x2="12.01" y2="16" />
        </>
      )}
      {level === "restricted" && (
        <>
          <line x1="9.5" y1="9.5" x2="14.5" y2="14.5" />
          <line x1="14.5" y1="9.5" x2="9.5" y2="14.5" />
        </>
      )}
    </svg>
  );
}

export function getTrustColor(level: TrustLevel): string {
  return TRUST_COLORS[level];
}

export function getTrustLabel(level: TrustLevel): string {
  return level.charAt(0).toUpperCase() + level.slice(1);
}
