import { useState, useRef, useCallback, useEffect } from "react";
import { ASK_CLAW } from "../../constants/messages";

interface ConversationInputProps {
  onSubmit: (message: string) => void;
  disabled: boolean;
  thinking: boolean;
  suggestions: readonly string[];
}

export function ConversationInput({
  onSubmit,
  disabled,
  thinking,
  suggestions,
}: ConversationInputProps) {
  const [value, setValue] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const adjustHeight = useCallback(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = "auto";
    const maxHeight = 4 * 24; // ~4 lines
    el.style.height = `${Math.min(el.scrollHeight, maxHeight)}px`;
  }, []);

  useEffect(() => {
    adjustHeight();
  }, [value, adjustHeight]);

  const handleSubmit = useCallback(() => {
    const trimmed = value.trim();
    if (!trimmed || disabled) return;
    onSubmit(trimmed);
    setValue("");
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
    }
  }, [value, disabled, onSubmit]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        handleSubmit();
      }
    },
    [handleSubmit],
  );

  const handleSuggestionClick = useCallback(
    (suggestion: string) => {
      if (disabled) return;
      onSubmit(suggestion);
    },
    [disabled, onSubmit],
  );

  return (
    <div className="space-y-3">
      <div className="relative">
        <textarea
          ref={textareaRef}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={ASK_CLAW.inputPlaceholder}
          disabled={disabled}
          rows={1}
          className="w-full resize-none rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] px-4 py-3 pr-12 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)] focus:border-[var(--color-accent)] focus:outline-none transition-colors duration-150 disabled:opacity-50"
          aria-label="Message input"
        />
        <button
          onClick={handleSubmit}
          disabled={disabled || !value.trim()}
          className="absolute right-2 bottom-2 rounded-md px-2 py-1.5 text-xs font-medium text-white bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)] disabled:opacity-30 transition-opacity duration-150"
          aria-label="Send message"
        >
          Send
        </button>
      </div>

      {thinking && (
        <div className="flex items-center gap-2 text-sm text-[var(--color-text-secondary)]">
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-[var(--color-accent)] animate-analysis-pulse" />
          {ASK_CLAW.thinkingIndicator}
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        {suggestions.map((s) => (
          <button
            key={s}
            onClick={() => handleSuggestionClick(s)}
            disabled={disabled}
            className="rounded-full border border-[var(--color-border)] bg-[var(--color-bg-tertiary)] px-3 py-1 text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-accent)] transition-colors duration-150 disabled:opacity-50"
          >
            {s}
          </button>
        ))}
      </div>
    </div>
  );
}
