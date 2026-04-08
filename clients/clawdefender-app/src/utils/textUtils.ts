/**
 * Text truncation and formatting utilities.
 *
 * All string operations use Array.from() to correctly handle
 * multi-byte Unicode characters (emoji, CJK, combining marks).
 */

/**
 * Truncate text in the middle, keeping beginning and end visible.
 * Useful for file paths: `/Users/john/very/long/.../file.txt`
 *
 * Unicode-safe: splits on codepoints, not UTF-16 code units.
 */
export function truncateMiddle(text: string, maxLen: number): string {
  if (!text) return "";
  const chars = Array.from(text);
  if (chars.length <= maxLen) return text;
  if (maxLen < 5) return truncateEnd(text, maxLen);

  const ellipsis = "\u2026"; // single-character ellipsis
  const available = maxLen - 1; // 1 char for ellipsis
  const headLen = Math.ceil(available / 2);
  const tailLen = available - headLen;

  return chars.slice(0, headLen).join("") + ellipsis + chars.slice(-tailLen).join("");
}

/**
 * Standard end-truncation with ellipsis.
 *
 * Unicode-safe: splits on codepoints, not UTF-16 code units.
 */
export function truncateEnd(text: string, maxLen: number): string {
  if (!text) return "";
  const chars = Array.from(text);
  if (chars.length <= maxLen) return text;
  if (maxLen <= 1) return "\u2026";

  return chars.slice(0, maxLen - 1).join("") + "\u2026";
}

/**
 * Format a byte count into a human-readable string.
 * Examples: "0 B", "1.2 KB", "450 MB", "3.1 GB"
 */
export function formatFileSize(bytes: number): string {
  if (bytes < 0) bytes = 0;
  if (bytes === 0) return "0 B";

  const units = ["B", "KB", "MB", "GB", "TB"];
  const k = 1024;
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), units.length - 1);
  const value = bytes / Math.pow(k, i);

  // Show integers for exact values, 1 decimal otherwise
  if (Number.isInteger(value) || i === 0) {
    return `${Math.round(value)} ${units[i]}`;
  }
  return `${value.toFixed(1)} ${units[i]}`;
}
