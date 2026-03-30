import { useEffect, useRef, useState, useMemo } from "react";

interface ProtectionScoreRingProps {
  score: number;
  label: string;
  color: string;
  changeFromLast: number | null;
  size?: number;
  strokeWidth?: number;
  onClick?: () => void;
}

/** Map backend color key to CSS variable. */
function colorVar(color: string): string {
  switch (color) {
    case "green":
      return "var(--color-safe)";
    case "green-light":
      return "var(--color-safe)";
    case "amber":
      return "var(--color-warning)";
    case "orange":
      return "var(--color-warning)";
    case "red":
      return "var(--color-danger)";
    default:
      return "var(--color-text-secondary)";
  }
}

function useAnimatedNumber(target: number, duration: number): number {
  const [value, setValue] = useState(0);
  const rafRef = useRef<number>(0);
  const prefersReducedMotion = useRef(
    typeof window !== "undefined" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );

  useEffect(() => {
    if (prefersReducedMotion.current) {
      setValue(target);
      return;
    }

    const start = performance.now();
    const from = 0;

    function tick(now: number) {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      // ease-out quad
      const eased = 1 - (1 - progress) * (1 - progress);
      setValue(Math.round(from + (target - from) * eased));
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(tick);
      }
    }

    rafRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafRef.current);
  }, [target, duration]);

  return value;
}

export function ProtectionScoreRing({
  score,
  label,
  color,
  changeFromLast,
  size = 180,
  strokeWidth = 10,
  onClick,
  ...rest
}: ProtectionScoreRingProps & Record<string, unknown>) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const cssColor = colorVar(color);

  const animatedScore = useAnimatedNumber(score, 1000);

  const progress = useMemo(
    () => circumference - (animatedScore / 100) * circumference,
    [animatedScore, circumference]
  );

  const changeBadge = useMemo(() => {
    if (changeFromLast == null || changeFromLast === 0) return null;
    const isPositive = changeFromLast > 0;
    const text = isPositive
      ? `+${changeFromLast}`
      : `${changeFromLast}`;
    const arrow = isPositive ? "\u2191" : "\u2193";
    const badgeColor = isPositive ? "var(--color-safe)" : "var(--color-danger)";
    const badgeBg = isPositive
      ? "var(--color-safe-subtle)"
      : "var(--color-danger-subtle)";
    return { text, arrow, badgeColor, badgeBg };
  }, [changeFromLast]);

  return (
    <button
      onClick={onClick}
      className="flex flex-col items-center gap-3 group cursor-pointer bg-transparent border-none p-0 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[var(--color-accent)] rounded-full"
      role="status"
      aria-label={`Protection score: ${score} out of 100. ${label}. Click for breakdown.`}
      {...rest}
    >
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          viewBox={`0 0 ${size} ${size}`}
          className="transform -rotate-90"
        >
          {/* Background ring */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="var(--color-bg-tertiary)"
            strokeWidth={strokeWidth}
          />
          {/* Progress ring */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={cssColor}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={progress}
            style={{
              transition: "stroke 0.3s ease",
            }}
          />
        </svg>
        {/* Score number in center */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="text-5xl font-bold tabular-nums"
            style={{ color: cssColor }}
          >
            {animatedScore}
          </span>
          {changeBadge && (
            <span
              className="mt-1 text-xs font-medium px-1.5 py-0.5 rounded-full tabular-nums"
              style={{
                color: changeBadge.badgeColor,
                backgroundColor: changeBadge.badgeBg,
              }}
            >
              {changeBadge.text} {changeBadge.arrow}
            </span>
          )}
        </div>
      </div>
      <div className="text-center">
        <p className="text-lg font-semibold" style={{ color: cssColor }}>
          {label}
        </p>
      </div>
    </button>
  );
}
