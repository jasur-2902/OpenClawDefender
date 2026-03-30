/**
 * Locale-aware date/time formatting utilities.
 *
 * All timestamps display in the user's local timezone (never raw UTC).
 * Uses Intl.DateTimeFormat for locale-aware formatting.
 */

const rtf = typeof Intl !== "undefined" && Intl.RelativeTimeFormat
  ? new Intl.RelativeTimeFormat(undefined, { numeric: "auto" })
  : null;

const shortTime = new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
});

const shortDate = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
});

const fullDateTime = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

/**
 * Compute the difference in calendar days between two Date objects,
 * handling DST and timezone transitions by comparing local dates.
 */
function calendarDayDiff(from: Date, to: Date): number {
  const fromDay = new Date(from.getFullYear(), from.getMonth(), from.getDate());
  const toDay = new Date(to.getFullYear(), to.getMonth(), to.getDate());
  return Math.round((toDay.getTime() - fromDay.getTime()) / 86_400_000);
}

/**
 * Format a relative time string.
 *
 * Handles: "just now", "2 minutes ago", "Yesterday", "Last week", etc.
 * Correctly handles timezone changes, DST transitions, and midnight boundaries
 * by comparing calendar days rather than raw millisecond deltas.
 */
export function formatRelativeTime(date: Date | string): string {
  const d = typeof date === "string" ? new Date(date) : date;
  const t = d.getTime();
  if (isNaN(t)) return typeof date === "string" ? date : "";

  const now = new Date();
  const diffMs = now.getTime() - t;
  const diffSec = Math.floor(diffMs / 1000);

  // Future dates: show absolute time
  if (diffSec < 0) {
    return fullDateTime.format(d);
  }

  // Under 1 minute
  if (diffSec < 60) return "just now";

  // Under 1 hour
  if (diffSec < 3600) {
    const mins = Math.floor(diffSec / 60);
    return rtf ? rtf.format(-mins, "minute") : `${mins}m ago`;
  }

  // Calendar day comparison for correct DST/midnight handling
  const dayDiff = calendarDayDiff(d, now);

  if (dayDiff === 0) {
    // Today: show relative hours
    const hours = Math.floor(diffSec / 3600);
    return rtf ? rtf.format(-hours, "hour") : `${hours}h ago`;
  }

  if (dayDiff === 1) {
    return rtf ? rtf.format(-1, "day") : "Yesterday";
  }

  if (dayDiff < 7) {
    return rtf ? rtf.format(-dayDiff, "day") : `${dayDiff} days ago`;
  }

  if (dayDiff < 14) {
    return rtf ? rtf.format(-1, "week") : "Last week";
  }

  if (dayDiff < 30) {
    const weeks = Math.floor(dayDiff / 7);
    return rtf ? rtf.format(-weeks, "week") : `${weeks} weeks ago`;
  }

  if (dayDiff < 365) {
    const months = Math.floor(dayDiff / 30);
    return rtf ? rtf.format(-months, "month") : `${months} months ago`;
  }

  // Over a year: show absolute date
  return fullDateTime.format(d);
}

/**
 * Smart event timestamp formatter.
 *
 * - Recent events (< 24h): relative time ("2 minutes ago")
 * - Today's older events: "Today at 2:30 PM"
 * - Yesterday: "Yesterday at 2:30 PM"
 * - This week: "3 days ago"
 * - Older: absolute date "Jan 15, 2:30 PM"
 */
export function formatEventTimestamp(ts: string): string {
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;

  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffSec = Math.floor(diffMs / 1000);

  // Under 1 minute
  if (diffSec < 60 && diffSec >= 0) return "just now";

  // Under 1 hour: relative
  if (diffSec < 3600 && diffSec >= 0) {
    const mins = Math.floor(diffSec / 60);
    return rtf ? rtf.format(-mins, "minute") : `${mins}m ago`;
  }

  const dayDiff = calendarDayDiff(d, now);

  if (dayDiff === 0 && diffSec < 86400 && diffSec >= 0) {
    // Same calendar day, less than a day ago: relative hours
    const hours = Math.floor(diffSec / 3600);
    return rtf ? rtf.format(-hours, "hour") : `${hours}h ago`;
  }

  if (dayDiff === 1) {
    return `Yesterday at ${shortTime.format(d)}`;
  }

  if (dayDiff > 1 && dayDiff < 7) {
    return formatRelativeTime(d);
  }

  // Older: show short date + time
  return `${shortDate.format(d)}, ${shortTime.format(d)}`;
}

/**
 * Format an absolute timestamp in the user's locale and timezone.
 */
export function formatAbsoluteTimestamp(ts: string): string {
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  return fullDateTime.format(d);
}
