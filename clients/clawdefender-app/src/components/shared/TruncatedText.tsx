import { useState, useRef } from "react";
import { truncateMiddle, truncateEnd } from "../../utils/textUtils";

interface TruncatedTextProps {
  text: string;
  maxLen: number;
  /** "middle" keeps start+end visible (good for paths), "end" is standard ellipsis */
  mode?: "middle" | "end";
  /** Allow expanding to show full text inline */
  expandable?: boolean;
  /** Additional CSS classes */
  className?: string;
}

/**
 * Displays truncated text with a native tooltip showing the full value.
 * Optionally expandable inline via "Show more" / "Show less" toggle.
 */
export function TruncatedText({
  text,
  maxLen,
  mode = "end",
  expandable = false,
  className = "",
}: TruncatedTextProps) {
  const [expanded, setExpanded] = useState(false);

  const isTruncated = Array.from(text).length > maxLen;
  const truncated = mode === "middle"
    ? truncateMiddle(text, maxLen)
    : truncateEnd(text, maxLen);

  const displayText = expanded ? text : truncated;

  if (!isTruncated) {
    return <span className={className}>{text}</span>;
  }

  return (
    <span className={`${className} inline`}>
      <span title={text}>{displayText}</span>
      {expandable && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            setExpanded(!expanded);
          }}
          className="ml-1 text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] text-xs transition-colors"
          aria-label={expanded ? "Show less" : "Show full content"}
        >
          {expanded ? "Less" : "More"}
        </button>
      )}
    </span>
  );
}

/**
 * Expandable section for long JSON or structured content.
 * Shows a truncated preview with a "Show full content" toggle.
 */
export function ExpandableContent({
  content,
  previewLines = 3,
  className = "",
}: {
  content: string;
  previewLines?: number;
  className?: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const contentRef = useRef<HTMLPreElement>(null);

  const lines = content.split("\n");
  const needsTruncation = lines.length > previewLines;
  const preview = lines.slice(0, previewLines).join("\n");

  return (
    <div className={className}>
      <pre
        ref={contentRef}
        className={`text-xs font-mono text-[var(--color-text-primary)] bg-[var(--color-bg-primary)] rounded-lg p-3 whitespace-pre-wrap break-all ${
          !expanded && needsTruncation ? "max-h-[4.5em] overflow-hidden" : "max-h-[50vh] overflow-auto"
        }`}
      >
        {expanded ? content : preview}
        {!expanded && needsTruncation && "\u2026"}
      </pre>
      {needsTruncation && (
        <button
          onClick={() => setExpanded(!expanded)}
          className="mt-1 text-xs text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] transition-colors"
        >
          {expanded ? "Show less" : `Show full content (${lines.length} lines)`}
        </button>
      )}
    </div>
  );
}
