import { useState, useEffect, useCallback } from "react";

export interface ToastData {
  id: string;
  title: string;
  severity: "info" | "warning" | "danger" | "success";
  duration: number;
  action?: {
    label: string;
    onClick: () => void;
  };
}

interface ToastProps {
  toast: ToastData;
  onDismiss: (id: string) => void;
}

const severityStyles: Record<ToastData["severity"], { icon: string; color: string }> = {
  info: { icon: "\u24D8", color: "var(--color-accent)" },
  warning: { icon: "\u26A0", color: "var(--color-warning)" },
  danger: { icon: "\u2716", color: "var(--color-danger)" },
  success: { icon: "\u2714", color: "var(--color-success)" },
};

export function Toast({ toast, onDismiss }: ToastProps) {
  const [visible, setVisible] = useState(false);
  const [exiting, setExiting] = useState(false);

  const dismiss = useCallback(() => {
    setExiting(true);
    setTimeout(() => onDismiss(toast.id), 300);
  }, [onDismiss, toast.id]);

  useEffect(() => {
    requestAnimationFrame(() => setVisible(true));

    const timer = setTimeout(() => {
      dismiss();
    }, toast.duration);

    return () => clearTimeout(timer);
  }, [dismiss, toast.duration]);

  // Dismiss on Escape key
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        dismiss();
      }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [dismiss]);

  const style = severityStyles[toast.severity];

  return (
    <div
      role="status"
      aria-live="polite"
      aria-label={toast.title}
      className="w-72 bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-lg shadow-xl overflow-hidden cursor-pointer"
      onClick={dismiss}
      style={{
        transform: visible && !exiting ? "translateX(0)" : "translateX(120%)",
        opacity: visible && !exiting ? 1 : 0,
        transition: exiting
          ? "transform 300ms ease, opacity 300ms ease"
          : "transform 200ms ease, opacity 200ms ease",
      }}
    >
      <div className="flex items-start gap-2 px-3 py-2.5">
        <span
          className="shrink-0 text-sm mt-0.5"
          style={{ color: style.color }}
          aria-hidden="true"
        >
          {style.icon}
        </span>
        <div className="flex-1 min-w-0">
          <p className="text-xs text-[var(--color-text-primary)] leading-relaxed">
            {toast.title}
          </p>
          {toast.action && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                toast.action!.onClick();
                dismiss();
              }}
              className="mt-1 text-xs font-medium text-[var(--color-accent)] hover:underline"
            >
              {toast.action.label}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
