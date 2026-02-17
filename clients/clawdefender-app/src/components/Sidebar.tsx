import { NavLink } from "react-router-dom";
import { useEventStore } from "../stores/eventStore";

interface NavItem {
  path: string;
  label: string;
  icon: string;
}

const navItems: NavItem[] = [
  { path: "/", label: "Dashboard", icon: "grid" },
  { path: "/timeline", label: "Timeline", icon: "clock" },
  { path: "/policy", label: "Policy", icon: "shield" },
  { path: "/behavioral", label: "Behavioral", icon: "activity" },
  { path: "/scanner", label: "Scanner", icon: "search" },
  { path: "/guards", label: "Guards", icon: "lock" },
  { path: "/threat-intel", label: "Threat Intel", icon: "globe" },
  { path: "/audit", label: "Audit Log", icon: "list" },
  { path: "/settings", label: "Settings", icon: "settings" },
];

const iconMap: Record<string, string> = {
  grid: "\u25A6",
  clock: "\u25F7",
  shield: "\u25C8",
  activity: "\u2248",
  search: "\u2315",
  lock: "\u2261",
  globe: "\u2295",
  list: "\u2630",
  settings: "\u2699",
};

export function Sidebar() {
  const daemonRunning = useEventStore((s) => s.daemonRunning);
  const pendingPrompts = useEventStore((s) => s.pendingPrompts);

  return (
    <aside className="flex flex-col w-56 h-full border-r border-[var(--color-border)] bg-[var(--color-bg-secondary)]">
      <div className="flex items-center gap-2 px-4 py-4 border-b border-[var(--color-border)]">
        <span className="text-lg font-bold text-[var(--color-text-primary)]">
          ClawDefender
        </span>
      </div>

      <div className="px-4 py-2">
        <div className="flex items-center gap-2 text-xs" role="status" aria-label={`Daemon ${daemonRunning ? "running" : "stopped"}`}>
          <span
            aria-hidden="true"
            className={`inline-block w-2 h-2 rounded-full ${
              daemonRunning ? "bg-[var(--color-success)]" : "bg-[var(--color-danger)]"
            }`}
          />
          <span className="text-[var(--color-text-secondary)]">
            Daemon {daemonRunning ? "Running" : "Stopped"}
          </span>
        </div>
      </div>

      <nav aria-label="Main navigation" className="flex-1 px-2 py-2 space-y-0.5 overflow-y-auto">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === "/"}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                isActive
                  ? "bg-[var(--color-accent)] text-white"
                  : "text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-tertiary)] hover:text-[var(--color-text-primary)]"
              }`
            }
          >
            <span className="w-4 text-center">{iconMap[item.icon]}</span>
            <span>{item.label}</span>
            {item.path === "/" && pendingPrompts.length > 0 && (
              <span className="ml-auto bg-[var(--color-danger)] text-white text-xs px-1.5 py-0.5 rounded-full" aria-label={`${pendingPrompts.length} pending prompts`}>
                {pendingPrompts.length}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="px-4 py-3 border-t border-[var(--color-border)] text-xs text-[var(--color-text-secondary)]">
        v0.10.0
      </div>
    </aside>
  );
}
