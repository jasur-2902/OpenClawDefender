// ClawDefender — Apple HIG-style sidebar + simple titlebar + tray

const NAV_ITEMS = [
  { id: "home", label: "Home", icon: "home" },
  { id: "activity", label: "Activity", icon: "activity" },
  { id: "alerts", label: "Alerts", icon: "alert" },
  { id: "scan", label: "Scans", icon: "scan" },
  { id: "ask", label: "Ask Rook", icon: "chat" },
  { id: "tools", label: "Tools", icon: "tools" },
  { id: "transparency", label: "Activity log", icon: "audit" },
  { id: "settings", label: "Settings", icon: "settings" },
];

const Sidebar = ({ current, onNav, collapsed, onToggle }) => {
  return (
    <aside style={{
      background: "var(--bg-0)",
      borderRight: "1px solid var(--line)",
      display: "flex", flexDirection: "column",
      overflow: "hidden",
    }}>
      {/* Brand */}
      <div style={{
        padding: collapsed ? "16px 12px" : "14px 16px",
        display: "flex", alignItems: "center", gap: 10,
        height: 56, minHeight: 56,
      }}>
        <div style={{
          width: 28, height: 28, borderRadius: 7,
          background: "var(--accent)",
          display: "grid", placeItems: "center",
          flexShrink: 0,
          boxShadow: "0 1px 2px oklch(0 0 0 / 0.10), inset 0 1px 0 oklch(1 0 0 / 0.20)",
        }}>
          <Rook size={15} color="white"/>
        </div>
        {!collapsed && (
          <div style={{ overflow: "hidden" }}>
            <div style={{ fontSize: 14, fontWeight: 600, letterSpacing: -0.2, lineHeight: 1.1, color: "var(--ink-0)" }}>ClawDefender</div>
          </div>
        )}
      </div>

      {/* Nav — Apple Settings.app style */}
      <nav style={{ flex: 1, padding: collapsed ? 8 : "4px 8px", overflowY: "auto" }} className="cd-scroll">
        {NAV_ITEMS.map(item => {
          const active = current === item.id;
          return (
            <button key={item.id} onClick={() => onNav(item.id)} title={collapsed ? item.label : undefined}
              style={{
                width: "100%", display: "flex", alignItems: "center", gap: 10,
                padding: collapsed ? "8px 0" : "7px 9px",
                justifyContent: collapsed ? "center" : "flex-start",
                borderRadius: 7, marginBottom: 1,
                background: active ? "var(--accent)" : "transparent",
                color: active ? "white" : "var(--ink-0)",
                fontSize: 13, fontWeight: active ? 500 : 400,
                position: "relative",
                transition: "background 0.12s",
              }}
              onMouseEnter={e => !active && (e.currentTarget.style.background = "oklch(0 0 0 / 0.05)")}
              onMouseLeave={e => !active && (e.currentTarget.style.background = "transparent")}
            >
              <Icon name={item.icon} size={15} stroke={1.7} color={active ? "white" : "var(--ink-1)"}/>
              {!collapsed && <span style={{ flex: 1, textAlign: "left" }}>{item.label}</span>}
            </button>
          );
        })}
      </nav>

      {/* Footer: just a quiet collapse toggle */}
      <div style={{ padding: 8 }}>
        <button onClick={onToggle} style={{
          width: "100%", padding: "6px 8px",
          color: "var(--ink-3)", fontSize: 11.5,
          display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
          borderRadius: 6,
        }}
          onMouseEnter={e => e.currentTarget.style.background = "oklch(0 0 0 / 0.04)"}
          onMouseLeave={e => e.currentTarget.style.background = "transparent"}
        >
          <Icon name="sidebar" size={13}/>
          {!collapsed && "Collapse"}
        </button>
      </div>
    </aside>
  );
};

// Calm titlebar — just title + a subtle tray button. No live tickers in chrome.
const StatusHeader = ({ current, onTrayOpen, posture }) => {
  const titleMap = {
    home: "",  // Home page has its own large title
    activity: "Activity",
    alerts: "Alerts",
    scan: "Scans",
    ask: "Ask Rook",
    tools: "Tools",
    transparency: "Activity log",
    settings: "Settings",
    event: "Event",
    alertDetail: "Alert",
    onboarding: "",
  };
  const postureColor = {
    low: "var(--green)", normal: "var(--green)", elevated: "var(--amber)", high: "var(--red)", critical: "var(--red)"
  }[posture] || "var(--ink-2)";

  return (
    <header style={{
      height: 44, minHeight: 44,
      background: "var(--bg-0)",
      borderBottom: "1px solid var(--line)",
      display: "flex", alignItems: "center", padding: "0 20px", gap: 12,
    }}>
      <div style={{ flex: 1, fontSize: 13.5, fontWeight: 600, color: "var(--ink-0)" }}>
        {titleMap[current] || ""}
      </div>
      <button onClick={onTrayOpen} style={{
        width: 28, height: 28, borderRadius: 7,
        display: "grid", placeItems: "center",
        position: "relative",
        color: "var(--ink-1)",
      }}
        onMouseEnter={e => e.currentTarget.style.background = "oklch(0 0 0 / 0.05)"}
        onMouseLeave={e => e.currentTarget.style.background = "transparent"}
        title="Status menu">
        <Rook size={14} color="var(--ink-1)"/>
        <span style={{ position: "absolute", top: 4, right: 4, width: 6, height: 6, borderRadius: 999, background: postureColor, border: "1.5px solid var(--bg-0)" }}/>
      </button>
    </header>
  );
};

const TrayMenu = ({ open, onClose, onNav, posture, setPosture }) => {
  if (!open) return null;
  const postureColor = { low: "var(--green)", normal: "var(--green)", elevated: "var(--amber)", high: "var(--red)", critical: "var(--red)" }[posture];
  const postureLabel = { low: "All quiet", normal: "Defenders in position", elevated: "Pawn advanced", high: "Check", critical: "Mate threatened" }[posture];
  return (
    <>
      <div onClick={onClose} style={{ position: "absolute", inset: 0, zIndex: 50 }}/>
      <div className="cd-slide-in" style={{
        position: "absolute", top: 44 + 8, right: 16, width: 300,
        background: "var(--bg-1)",
        border: "1px solid oklch(0 0 0 / 0.08)",
        borderRadius: 12, boxShadow: "var(--shadow-lg)",
        zIndex: 60, overflow: "hidden",
      }}>
        <div style={{ padding: "16px 16px 14px", display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ width: 36, height: 36, borderRadius: 9, background: "var(--accent)", display: "grid", placeItems: "center" }}>
            <Rook size={18} color="white"/>
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: 600 }}>ClawDefender</div>
            <div style={{ fontSize: 12, color: postureColor, display: "flex", alignItems: "center", gap: 6, marginTop: 2 }}>
              <Dot color={postureColor} size={6} pulse/>
              {postureLabel}
            </div>
          </div>
        </div>

        <div style={{ height: 1, background: "var(--line)" }}/>

        <div style={{ padding: "6px 0" }}>
          {[
            { id: "home", label: "Open ClawDefender", icon: "home" },
            { id: "activity", label: "View activity", icon: "activity" },
            { id: "alerts", label: "View alerts", icon: "alert" },
            { id: "scan", label: "Run a scan", icon: "scan" },
            { id: "ask", label: "Ask Rook", icon: "chat" },
          ].map(it => (
            <button key={it.id} onClick={() => { onNav(it.id); onClose(); }} style={{
              width: "100%", padding: "8px 16px", display: "flex", alignItems: "center", gap: 10,
              fontSize: 13, color: "var(--ink-0)",
            }}
              onMouseEnter={e => e.currentTarget.style.background = "var(--accent-soft)"}
              onMouseLeave={e => e.currentTarget.style.background = "transparent"}
            >
              <Icon name={it.icon} size={14} color="var(--ink-2)"/>
              {it.label}
            </button>
          ))}
        </div>

        <div style={{ height: 1, background: "var(--line)" }}/>

        <div style={{ padding: "10px 16px", display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ fontSize: 12, color: "var(--ink-2)", flex: 1 }}>Pause for…</span>
          {["1h","8h"].map(p => (
            <button key={p} style={{ padding: "4px 10px", fontSize: 11.5, color: "var(--ink-1)", borderRadius: 6, background: "var(--bg-2)" }}>{p}</button>
          ))}
        </div>

        {/* Hidden posture override for design-tweaks; kept compact */}
        <div style={{ padding: "8px 12px", display: "flex", gap: 4, borderTop: "1px solid var(--line)", background: "var(--bg-2)" }}>
          {["low","normal","elevated","high","critical"].map(p => (
            <button key={p} onClick={() => setPosture(p)} title={p} style={{
              flex: 1, padding: "4px 0", fontSize: 10, color: posture === p ? "var(--ink-0)" : "var(--ink-3)",
              borderRadius: 4, background: posture === p ? "white" : "transparent",
              border: "1px solid " + (posture === p ? "var(--line-strong)" : "transparent"),
            }}>{p[0].toUpperCase()}</button>
          ))}
        </div>
      </div>
    </>
  );
};

Object.assign(window, { Sidebar, StatusHeader, TrayMenu, NAV_ITEMS });
