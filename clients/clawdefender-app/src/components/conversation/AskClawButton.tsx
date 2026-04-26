import { useNavigate } from "react-router-dom";

interface AskClawButtonProps {
  /** Pre-populated question for Claw. */
  question: string;
  /** Optional context hint passed via location state. */
  context?: string;
  /** Button text. Defaults to "Ask Rook". */
  label?: string;
  /** Visual variant. "inline" renders as a text button, "subtle" as a muted icon+text link. */
  variant?: "inline" | "subtle";
}

export function AskClawButton({
  question,
  context,
  label = "Ask Rook",
  variant = "subtle",
}: AskClawButtonProps) {
  const navigate = useNavigate();

  function handleClick() {
    navigate("/ask", {
      state: { question, context },
    });
  }

  if (variant === "inline") {
    return (
      <button
        onClick={handleClick}
        className="text-[var(--color-accent)] hover:underline text-sm font-medium"
        aria-label={`Ask Rook: ${question}`}
      >
        {label}
      </button>
    );
  }

  return (
    <button
      onClick={handleClick}
      className="flex items-center gap-1.5 text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-accent)] transition-colors"
      aria-label={`Ask Rook: ${question}`}
    >
      <span aria-hidden="true" className="text-sm">{"\u2709"}</span>
      <span>{label}</span>
    </button>
  );
}
