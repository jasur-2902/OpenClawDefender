// ClawDefender — shared UI atoms (icons, badges, rook glyph, sparkline, etc.)
// Exposes everything on window so other Babel scripts can use them.

const Rook = ({ size = 18, color = "currentColor" }) => (
  <svg width={size} height={size} viewBox="0 0 45 45" fill={color} aria-hidden="true" style={{ display: "block" }}>
    {/* Chess Rook — crenellated castle silhouette */}
    <path d="M9 36h27v-3H9zM12 33v-3h21v3zM11 14V8h4v3h4V8h7v3h4V8h4v6l-3 3v9H14l-3-3z"/>
    <path d="M14 17h17v9H14z" opacity="0.92"/>
  </svg>
);

const Dot = ({ color = "var(--accent)", size = 8, pulse = false, style }) => (
  <span style={{
    display: "inline-block",
    width: size, height: size, borderRadius: 999,
    background: color,
    boxShadow: pulse ? `0 0 0 0 ${color}` : "none",
    position: "relative",
    ...style
  }} className={pulse ? "cd-pulse-dot" : ""} />
);

const Badge = ({ children, color = "var(--ink-2)", soft, mono = false, style }) => (
  <span style={{
    display: "inline-flex", alignItems: "center", gap: 5,
    fontFamily: mono ? "var(--font-mono)" : "var(--font-ui)",
    fontSize: 10.5, fontWeight: 600, letterSpacing: 0.4,
    textTransform: mono ? "none" : "uppercase",
    padding: "3px 7px", borderRadius: 4,
    color, background: soft || `color-mix(in oklch, ${color} 14%, transparent)`,
    border: `1px solid color-mix(in oklch, ${color} 28%, transparent)`,
    ...style
  }}>{children}</span>
);

const ClassBadge = ({ kind }) => {
  const cls = CD.classifications[kind];
  if (!cls) return null;
  return <Badge color={cls.color} soft={cls.soft}>{cls.label}</Badge>;
};

const VerdictPill = ({ verdict }) => {
  const isBlock = verdict === "BLOCK";
  return (
    <span style={{
      fontFamily: "var(--font-mono)", fontSize: 10.5, fontWeight: 700, letterSpacing: 0.6,
      padding: "3px 7px", borderRadius: 4,
      color: isBlock ? "var(--red)" : "var(--green)",
      background: isBlock ? "var(--red-soft)" : "var(--green-soft)",
      border: `1px solid color-mix(in oklch, ${isBlock ? "var(--red)" : "var(--green)"} 32%, transparent)`,
    }}>{verdict}</span>
  );
};

// Minimal stroke icons — geometric, line-based
const Icon = ({ name, size = 18, stroke = 1.6, color = "currentColor" }) => {
  const props = { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: color, strokeWidth: stroke, strokeLinecap: "round", strokeLinejoin: "round" };
  switch (name) {
    case "home": return <svg {...props}><path d="M3 11l9-7 9 7"/><path d="M5 10v9h14v-9"/></svg>;
    case "activity": return <svg {...props}><path d="M3 12h4l3-8 4 16 3-8h4"/></svg>;
    case "alert": return <svg {...props}><path d="M12 3l9 16H3z"/><path d="M12 10v4"/><circle cx="12" cy="17" r=".7" fill={color}/></svg>;
    case "scan": return <svg {...props}><circle cx="11" cy="11" r="6"/><path d="M16 16l5 5"/></svg>;
    case "chat": return <svg {...props}><path d="M4 5h16v11H9l-5 4z"/></svg>;
    case "tools": return <svg {...props}><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>;
    case "settings": return <svg {...props}><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/></svg>;
    case "audit": return <svg {...props}><path d="M5 3h11l4 4v14H5z"/><path d="M9 12h7M9 16h7M9 8h4"/></svg>;
    case "sparkles": return <svg {...props}><path d="M12 4v6M12 14v6M4 12h6M14 12h6"/></svg>;
    case "lightning": return <svg {...props}><path d="M13 3L4 14h6l-1 7 9-11h-6z"/></svg>;
    case "shield": return <svg {...props}><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/></svg>;
    case "process": return <svg {...props}><rect x="4" y="6" width="16" height="3" rx="1"/><rect x="4" y="11" width="10" height="3" rx="1"/><rect x="4" y="16" width="13" height="3" rx="1"/></svg>;
    case "network": return <svg {...props}><circle cx="12" cy="6" r="2.5"/><circle cx="5" cy="18" r="2.5"/><circle cx="19" cy="18" r="2.5"/><path d="M12 8.5l-7 7M12 8.5l7 7"/></svg>;
    case "dns": return <svg {...props}><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18"/></svg>;
    case "wrench": return <svg {...props}><path d="M14 6a4 4 0 105 5l4 4-3 3-4-4a4 4 0 01-5-5z"/></svg>;
    case "search": return <svg {...props}><circle cx="11" cy="11" r="6"/><path d="M16 16l5 5"/></svg>;
    case "send": return <svg {...props}><path d="M3 12L21 4l-7 17-2-7z"/></svg>;
    case "chevron": return <svg {...props}><path d="M9 6l6 6-6 6"/></svg>;
    case "x": return <svg {...props}><path d="M5 5l14 14M19 5L5 19"/></svg>;
    case "check": return <svg {...props}><path d="M5 12l5 5 9-11"/></svg>;
    case "play": return <svg {...props}><path d="M6 4l13 8-13 8z" fill={color}/></svg>;
    case "pause": return <svg {...props}><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>;
    case "filter": return <svg {...props}><path d="M3 5h18l-7 9v6l-4-2v-4z"/></svg>;
    case "refresh": return <svg {...props}><path d="M4 12a8 8 0 0114-5l3 3M3 17l3-3a8 8 0 0014-5"/></svg>;
    case "download": return <svg {...props}><path d="M12 4v12M6 12l6 6 6-6M4 20h16"/></svg>;
    case "lock": return <svg {...props}><rect x="5" y="11" width="14" height="9" rx="1.5"/><path d="M8 11V7a4 4 0 018 0v4"/></svg>;
    case "cpu": return <svg {...props}><rect x="6" y="6" width="12" height="12" rx="1.5"/><rect x="9" y="9" width="6" height="6" rx="1"/><path d="M9 3v3M15 3v3M9 18v3M15 18v3M3 9h3M3 15h3M18 9h3M18 15h3"/></svg>;
    case "cloud": return <svg {...props}><path d="M7 18a4 4 0 010-8 5 5 0 019.6-1.5A4 4 0 0117 18z"/></svg>;
    case "key": return <svg {...props}><circle cx="8" cy="15" r="3"/><path d="M11 13l9-9M16 8l3 3"/></svg>;
    case "history": return <svg {...props}><path d="M3 12a9 9 0 109-9 9 9 0 00-7 3.5"/><path d="M3 4v4h4"/><path d="M12 7v5l3 2"/></svg>;
    case "sidebar": return <svg {...props}><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M9 4v16"/></svg>;
    default: return <svg {...props}><circle cx="12" cy="12" r="3"/></svg>;
  }
};

const Sparkline = ({ data, color = "var(--accent)", width = 120, height = 32, fill = true }) => {
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const range = max - min || 1;
  const step = width / (data.length - 1);
  const pts = data.map((v, i) => [i * step, height - ((v - min) / range) * (height - 4) - 2]);
  const d = pts.map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(" ");
  const fillD = fill ? `${d} L${width} ${height} L0 ${height} Z` : null;
  return (
    <svg width={width} height={height} style={{ display: "block" }}>
      {fillD && <path d={fillD} fill={color} opacity="0.12"/>}
      <path d={d} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  );
};

const Ring = ({ value = 0, max = 100, size = 96, stroke = 7, color = "var(--accent)", track = "var(--bg-3)", label, sub }) => {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(1, value / max));
  return (
    <div style={{ position: "relative", width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={track} strokeWidth={stroke}/>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={stroke}
          strokeDasharray={c} strokeDashoffset={c * (1 - pct)} strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 0.6s ease" }}/>
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", textAlign: "center" }}>
        <div>
          <div style={{ fontSize: 22, fontWeight: 600, fontFeatureSettings: '"tnum"' }}>{label ?? value}</div>
          {sub && <div style={{ fontSize: 10, color: "var(--ink-2)", marginTop: 2 }}>{sub}</div>}
        </div>
      </div>
    </div>
  );
};

const KV = ({ k, v, mono = false }) => (
  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", padding: "8px 0", borderBottom: "1px solid var(--line-soft)", gap: 16 }}>
    <span style={{ color: "var(--ink-2)", fontSize: 12 }}>{k}</span>
    <span style={{ fontFamily: mono ? "var(--font-mono)" : "var(--font-ui)", fontSize: 12, color: "var(--ink-0)", textAlign: "right" }}>{v}</span>
  </div>
);

const Card = ({ title, action, children, padded = true, style }) => (
  <div style={{
    background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: 12,
    overflow: "hidden", boxShadow: "0 1px 2px oklch(0 0 0 / 0.04)", ...style
  }}>
    {title && (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", borderBottom: "1px solid var(--line-soft)" }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--ink-0)" }}>{title}</div>
        {action}
      </div>
    )}
    <div style={{ padding: padded ? 16 : 0 }}>{children}</div>
  </div>
);

const Btn = ({ children, kind = "ghost", size = "md", icon, onClick, style, disabled }) => {
  const sizes = { sm: { p: "5px 10px", fs: 12, r: 6 }, md: { p: "7px 14px", fs: 13, r: 7 }, lg: { p: "10px 18px", fs: 14, r: 8 } };
  const s = sizes[size];
  const kinds = {
    primary: { bg: "var(--accent)", c: "white", b: "var(--accent)", sh: "0 1px 2px oklch(0 0 0 / 0.10), inset 0 1px 0 oklch(1 0 0 / 0.20)" },
    ghost: { bg: "transparent", c: "var(--ink-1)", b: "transparent", sh: "none" },
    soft: { bg: "var(--bg-2)", c: "var(--ink-0)", b: "var(--line)", sh: "none" },
    danger: { bg: "var(--red)", c: "white", b: "var(--red)", sh: "0 1px 2px oklch(0 0 0 / 0.10), inset 0 1px 0 oklch(1 0 0 / 0.20)" },
    accent: { bg: "var(--accent-soft)", c: "var(--accent)", b: "transparent", sh: "none" },
  };
  const k = kinds[kind];
  return (
    <button onClick={onClick} disabled={disabled} style={{
      display: "inline-flex", alignItems: "center", gap: 6,
      padding: s.p, fontSize: s.fs, fontWeight: 500,
      background: k.bg, color: k.c, border: `1px solid ${k.b}`,
      borderRadius: s.r, boxShadow: k.sh,
      opacity: disabled ? 0.4 : 1,
      cursor: disabled ? "not-allowed" : "pointer",
      transition: "transform 0.08s ease, filter 0.15s ease",
      ...style
    }}
    onMouseDown={e => !disabled && (e.currentTarget.style.transform = "scale(0.98)")}
    onMouseUp={e => (e.currentTarget.style.transform = "")}
    onMouseLeave={e => (e.currentTarget.style.transform = "")}
    >
      {icon && <Icon name={icon} size={13.5}/>}
      {children}
    </button>
  );
};

const SectionTitle = ({ children, sub }) => (
  <div style={{ marginBottom: 22 }}>
    <h1 style={{ margin: 0, fontSize: 26, fontWeight: 700, letterSpacing: -0.5, color: "var(--ink-0)" }}>{children}</h1>
    {sub && <div style={{ marginTop: 6, fontSize: 14, color: "var(--ink-2)" }}>{sub}</div>}
  </div>
);

const KindIcon = ({ kind, size = 14 }) => {
  const map = { process: "process", network: "network", dns: "dns", tool_call: "wrench" };
  const c = { process: "var(--violet)", network: "var(--accent)", dns: "var(--amber)", tool_call: "var(--ink-1)" }[kind] || "var(--ink-2)";
  return <Icon name={map[kind] || "process"} size={size} color={c}/>;
};

Object.assign(window, { Rook, Dot, Badge, ClassBadge, VerdictPill, Icon, Sparkline, Ring, KV, Card, Btn, SectionTitle, KindIcon });
