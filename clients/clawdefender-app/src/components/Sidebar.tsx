import { NavLink, useLocation } from "react-router-dom";
import { Icon, Rook } from "./design";
import { useAlertStore } from "../stores/alertStore";

interface NavItem {
  id: string;
  path: string;
  label: string;
  icon: string;
  badge?: "alerts";
}

const NAV_ITEMS: NavItem[] = [
  { id: "home", path: "/", label: "Home", icon: "home" },
  { id: "activity", path: "/activity", label: "Activity", icon: "activity" },
  { id: "alerts", path: "/alerts", label: "Alerts", icon: "alert", badge: "alerts" },
  { id: "scan", path: "/scan", label: "Scans", icon: "scan" },
  { id: "ask", path: "/ask", label: "Ask Rook", icon: "chat" },
  { id: "tools", path: "/tools", label: "Tools", icon: "tools" },
  { id: "transparency", path: "/transparency", label: "Activity log", icon: "audit" },
  { id: "settings", path: "/settings", label: "Settings", icon: "settings" },
];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const unresolvedCount = useAlertStore((s) => s.unresolvedCount);
  const location = useLocation();

  return (
    <aside
      style={{
        background: "var(--bg-0)",
        borderRight: "1px solid var(--line)",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
        width: collapsed ? 60 : 220,
        transition: "width 0.2s ease",
      }}
    >
      {/* Brand */}
      <div
        style={{
          padding: collapsed ? "16px 12px" : "14px 16px",
          display: "flex",
          alignItems: "center",
          gap: 10,
          height: 56,
          minHeight: 56,
        }}
      >
        <div
          style={{
            width: 28,
            height: 28,
            borderRadius: 7,
            background: "var(--accent)",
            display: "grid",
            placeItems: "center",
            flexShrink: 0,
            boxShadow:
              "0 1px 2px oklch(0 0 0 / 0.10), inset 0 1px 0 oklch(1 0 0 / 0.20)",
          }}
        >
          <Rook size={15} color="white" />
        </div>
        {!collapsed && (
          <div style={{ overflow: "hidden" }}>
            <div
              style={{
                fontSize: 14,
                fontWeight: 600,
                letterSpacing: -0.2,
                lineHeight: 1.1,
                color: "var(--ink-0)",
              }}
            >
              RookBot
            </div>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav
        style={{
          flex: 1,
          padding: collapsed ? 8 : "4px 8px",
          overflowY: "auto",
        }}
        className="cd-scroll"
      >
        {NAV_ITEMS.map((item) => {
          const isActive =
            item.path === "/"
              ? location.pathname === "/"
              : location.pathname.startsWith(item.path);

          return (
            <NavLink
              key={item.id}
              to={item.path}
              end={item.path === "/"}
              title={collapsed ? item.label : undefined}
              style={{
                width: "100%",
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: collapsed ? "8px 0" : "7px 9px",
                justifyContent: collapsed ? "center" : "flex-start",
                borderRadius: 7,
                marginBottom: 1,
                background: isActive ? "var(--accent)" : "transparent",
                color: isActive ? "white" : "var(--ink-0)",
                fontSize: 13,
                fontWeight: isActive ? 500 : 400,
                position: "relative",
                transition: "background 0.12s",
                textDecoration: "none",
              }}
              onMouseEnter={(e) => {
                if (!isActive)
                  e.currentTarget.style.background = "oklch(0 0 0 / 0.05)";
              }}
              onMouseLeave={(e) => {
                if (!isActive)
                  e.currentTarget.style.background = "transparent";
              }}
            >
              <Icon
                name={item.icon}
                size={15}
                stroke={1.7}
                color={isActive ? "white" : "var(--ink-1)"}
              />
              {!collapsed && (
                <span style={{ flex: 1, textAlign: "left" }}>{item.label}</span>
              )}
              {!collapsed &&
                item.badge === "alerts" &&
                unresolvedCount > 0 && (
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 600,
                      padding: "1px 6px",
                      borderRadius: 999,
                      background: isActive
                        ? "rgba(255,255,255,0.25)"
                        : "var(--red)",
                      color: "white",
                    }}
                  >
                    {unresolvedCount}
                  </span>
                )}
            </NavLink>
          );
        })}
      </nav>

      {/* Footer: collapse toggle */}
      <div style={{ padding: 8 }}>
        <button
          onClick={onToggle}
          style={{
            width: "100%",
            padding: "6px 8px",
            color: "var(--ink-3)",
            fontSize: 11.5,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: 6,
            borderRadius: 6,
            background: "transparent",
            border: "none",
            cursor: "pointer",
          }}
          onMouseEnter={(e) =>
            (e.currentTarget.style.background = "oklch(0 0 0 / 0.04)")
          }
          onMouseLeave={(e) =>
            (e.currentTarget.style.background = "transparent")
          }
        >
          <Icon name="sidebar" size={13} />
          {!collapsed && "Collapse"}
        </button>
      </div>
    </aside>
  );
}
