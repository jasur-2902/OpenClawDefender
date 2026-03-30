import type { ServerCapabilities } from "../../types";

interface CapabilityIconsProps {
  capabilities: ServerCapabilities;
  size?: number;
}

const CAPABILITY_ENTRIES = [
  { key: "can_read_files" as const, label: "Read files", icon: "folder" },
  { key: "can_write_files" as const, label: "Write files", icon: "pencil" },
  { key: "can_execute_commands" as const, label: "Run commands", icon: "terminal" },
  { key: "can_access_network" as const, label: "Internet access", icon: "globe" },
  { key: "can_sample_llm" as const, label: "LLM sampling", icon: "chat" },
] as const;

export function CapabilityIcons({ capabilities, size = 14 }: CapabilityIconsProps) {
  return (
    <div className="flex items-center gap-1.5" role="group" aria-label="Capabilities">
      {CAPABILITY_ENTRIES.map((entry) => {
        const active = capabilities[entry.key];
        return (
          <span
            key={entry.key}
            role="img"
            aria-label={`${entry.label}: ${active ? "Yes" : "No"}`}
            title={`${entry.label}: ${active ? "Yes" : "No"}`}
            className={`inline-flex items-center justify-center rounded ${
              active
                ? "text-[var(--color-text-secondary)]"
                : "text-[var(--color-text-muted)] opacity-30"
            }`}
          >
            <CapIcon type={entry.icon} size={size} />
          </span>
        );
      })}
    </div>
  );
}

function CapIcon({ type, size }: { type: string; size: number }) {
  const props = {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.75,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true as const,
  };

  switch (type) {
    case "folder":
      return (
        <svg {...props}>
          <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
        </svg>
      );
    case "pencil":
      return (
        <svg {...props}>
          <path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z" />
          <path d="m15 5 4 4" />
        </svg>
      );
    case "terminal":
      return (
        <svg {...props}>
          <polyline points="4 17 10 11 4 5" />
          <line x1="12" y1="19" x2="20" y2="19" />
        </svg>
      );
    case "globe":
      return (
        <svg {...props}>
          <circle cx="12" cy="12" r="10" />
          <line x1="2" y1="12" x2="22" y2="12" />
          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
        </svg>
      );
    case "chat":
      return (
        <svg {...props}>
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
        </svg>
      );
    default:
      return null;
  }
}
