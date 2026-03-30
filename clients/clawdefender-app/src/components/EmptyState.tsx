import type { ReactNode } from "react";

export interface EmptyStateAction {
  label: string;
  onClick: () => void;
}

interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description: string;
  actions?: EmptyStateAction[];
}

export function EmptyState({ icon, title, description, actions }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center px-4">
      {icon && (
        <div
          className="w-12 h-12 rounded-full flex items-center justify-center mb-4"
          style={{ backgroundColor: "var(--color-bg-tertiary)" }}
          aria-hidden="true"
        >
          {icon}
        </div>
      )}
      <h2
        className="text-base font-medium mb-1"
        style={{ color: "var(--color-text-primary)" }}
      >
        {title}
      </h2>
      <p
        className="text-sm max-w-sm"
        style={{ color: "var(--color-text-secondary)" }}
      >
        {description}
      </p>
      {actions && actions.length > 0 && (
        <div className="flex items-center gap-3 mt-4">
          {actions.map((action, i) => (
            <button
              key={action.label}
              onClick={action.onClick}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors duration-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-1 ${
                i === 0
                  ? "text-white"
                  : "border"
              }`}
              style={
                i === 0
                  ? {
                      backgroundColor: "var(--color-accent)",
                      color: "white",
                    }
                  : {
                      borderColor: "var(--color-border)",
                      color: "var(--color-text-secondary)",
                    }
              }
            >
              {action.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
