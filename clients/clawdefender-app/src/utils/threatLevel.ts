/**
 * RookBot Threat Level Utilities
 *
 * Maps internal anomaly scores to user-facing threat levels,
 * colors, icons, and notification priorities.
 *
 * See docs/design/threat-communication.md for the full specification.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ThreatLevel =
  | "dangerous"
  | "suspicious"
  | "unusual"
  | "normal"
  | "blocked"
  | "info";

export type NotificationPriority =
  | "prompt_with_sound"
  | "prompt"
  | "banner"
  | "toast"
  | "in_feed"
  | "silent";

// ---------------------------------------------------------------------------
// Score-to-Level Mapping
// ---------------------------------------------------------------------------

/**
 * Maps a numeric anomaly score (0.0 - 1.0) to a user-facing threat level.
 *
 * Thresholds (from threat-communication.md):
 *   >= 0.9  -> Dangerous
 *   >= 0.7  -> Suspicious
 *   >= 0.4  -> Unusual
 *    < 0.4  -> Normal
 */
export function getThreatLevel(anomalyScore: number): ThreatLevel {
  if (anomalyScore >= 0.9) return "dangerous";
  if (anomalyScore >= 0.7) return "suspicious";
  if (anomalyScore >= 0.4) return "unusual";
  return "normal";
}

// ---------------------------------------------------------------------------
// Color Mapping
// ---------------------------------------------------------------------------

const THREAT_COLORS: Record<ThreatLevel, string> = {
  dangerous: "var(--color-danger)",
  suspicious: "var(--color-warning)",
  unusual: "var(--color-info)",
  normal: "var(--color-safe)",
  blocked: "var(--color-danger)",
  info: "var(--color-info)",
};

/**
 * Returns the CSS variable string for the given threat level.
 * Use in inline styles or as a Tailwind arbitrary value.
 */
export function getThreatColor(level: ThreatLevel): string {
  return THREAT_COLORS[level];
}

// ---------------------------------------------------------------------------
// Tailwind Class Mapping
// ---------------------------------------------------------------------------

const THREAT_COLOR_CLASSES: Record<ThreatLevel, string> = {
  dangerous: "text-danger",
  suspicious: "text-warning",
  unusual: "text-info",
  normal: "text-safe",
  blocked: "text-danger",
  info: "text-info",
};

const THREAT_BG_CLASSES: Record<ThreatLevel, string> = {
  dangerous: "bg-danger-subtle",
  suspicious: "bg-warning-subtle",
  unusual: "bg-info-subtle",
  normal: "bg-safe-subtle",
  blocked: "bg-danger-subtle",
  info: "bg-info-subtle",
};

const THREAT_TEXT_ON_BG_CLASSES: Record<ThreatLevel, string> = {
  dangerous: "text-danger-dark",
  suspicious: "text-warning-dark",
  unusual: "text-info-dark",
  normal: "text-safe-dark",
  blocked: "text-danger-dark",
  info: "text-info-dark",
};

/**
 * Returns Tailwind text color class for the threat level.
 */
export function getThreatTextClass(level: ThreatLevel): string {
  return THREAT_COLOR_CLASSES[level];
}

/**
 * Returns Tailwind background class for badge/pill backgrounds.
 */
export function getThreatBgClass(level: ThreatLevel): string {
  return THREAT_BG_CLASSES[level];
}

/**
 * Returns Tailwind text class for text on colored backgrounds.
 */
export function getThreatTextOnBgClass(level: ThreatLevel): string {
  return THREAT_TEXT_ON_BG_CLASSES[level];
}

// ---------------------------------------------------------------------------
// Icon Mapping
// ---------------------------------------------------------------------------

const THREAT_ICONS: Record<ThreatLevel, string> = {
  dangerous: "ShieldX",
  suspicious: "AlertTriangle",
  unusual: "Eye",
  normal: "ShieldCheck",
  blocked: "Ban",
  info: "Info",
};

/**
 * Returns the Lucide React icon name for the given threat level.
 * Import the icon from `lucide-react` using this name.
 */
export function getThreatIcon(level: ThreatLevel): string {
  return THREAT_ICONS[level];
}

// ---------------------------------------------------------------------------
// Notification Priority Mapping
// ---------------------------------------------------------------------------

const NOTIFICATION_PRIORITIES: Record<ThreatLevel, NotificationPriority> = {
  dangerous: "prompt_with_sound",
  suspicious: "prompt",
  unusual: "banner",
  normal: "in_feed",
  blocked: "toast",
  info: "in_feed",
};

/**
 * Returns the notification priority for the given threat level.
 *
 * Priority tiers:
 *   prompt_with_sound — full prompt window + alert sound
 *   prompt            — full prompt window, no sound
 *   banner            — slide-in banner, persists 8s
 *   toast             — corner toast, auto-dismiss 4s
 *   in_feed           — timeline only, no interruption
 *   silent            — audit log only
 */
export function getNotificationPriority(
  level: ThreatLevel,
): NotificationPriority {
  return NOTIFICATION_PRIORITIES[level];
}

// ---------------------------------------------------------------------------
// Border Class Mapping (for alert cards with left accent)
// ---------------------------------------------------------------------------

const THREAT_BORDER_CLASSES: Record<ThreatLevel, string> = {
  dangerous: "border-l-danger-border",
  suspicious: "border-l-warning-border",
  unusual: "border-l-info-border",
  normal: "border-l-safe-border",
  blocked: "border-l-danger-border",
  info: "border-l-info-border",
};

/**
 * Returns the Tailwind class for the left-accent border on alert cards.
 */
export function getThreatBorderClass(level: ThreatLevel): string {
  return THREAT_BORDER_CLASSES[level];
}
