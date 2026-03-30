import { useState } from "react";

export interface ErrorBannerAction {
  label: string;
  onClick: () => void;
}

interface ErrorBannerProps {
  message: string;
  variant: "warning" | "error" | "info";
  actions?: ErrorBannerAction[];
  onDismiss?: () => void;
}

const variantStyles: Record<
  ErrorBannerProps["variant"],
  { bg: string; border: string; icon: string; iconColor: string }
> = {
  warning: {
    bg: "var(--color-warning-subtle)",
    border: "var(--color-warning-border)",
    icon: "\u26A0",
    iconColor: "var(--color-warning)",
  },
  error: {
    bg: "var(--color-danger-subtle)",
    border: "var(--color-danger-border)",
    icon: "\u2715",
    iconColor: "var(--color-danger)",
  },
  info: {
    bg: "var(--color-info-subtle)",
    border: "var(--color-info-border)",
    icon: "\u2139",
    iconColor: "var(--color-info)",
  },
};

export function ErrorBanner({ message, variant, actions, onDismiss }: ErrorBannerProps) {
  const [dismissed, setDismissed] = useState(false);
  if (dismissed) return null;

  const style = variantStyles[variant];

  return (
    <div
      role="alert"
      className="flex items-center gap-3 px-4 py-3 rounded-lg border"
      style={{
        backgroundColor: style.bg,
        borderColor: style.border,
      }}
    >
      <span
        className="shrink-0 text-sm"
        style={{ color: style.iconColor }}
        aria-hidden="true"
      >
        {style.icon}
      </span>
      <p className="flex-1 text-sm" style={{ color: "var(--color-text-primary)" }}>
        {message}
      </p>
      <div className="flex items-center gap-2 shrink-0">
        {actions?.map((action) => (
          <button
            key={action.label}
            onClick={action.onClick}
            className="text-xs font-medium px-3 py-1.5 rounded-md transition-colors duration-100"
            style={{
              backgroundColor: "var(--color-accent)",
              color: "white",
            }}
          >
            {action.label}
          </button>
        ))}
        {onDismiss && (
          <button
            onClick={() => {
              setDismissed(true);
              onDismiss();
            }}
            className="shrink-0 text-xs px-2 py-1 rounded-md transition-colors duration-100"
            style={{
              color: "var(--color-text-secondary)",
            }}
            aria-label="Dismiss"
          >
            Dismiss
          </button>
        )}
      </div>
    </div>
  );
}
