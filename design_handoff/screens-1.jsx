// ClawDefender — Apple HIG-style screens (Home + Activity)

const ScreenHome = ({ goto, onAlertClick, onEventClick, posture, events }) => {
  const postureColor = { low: "var(--green)", normal: "var(--green)", elevated: "var(--amber)", high: "var(--red)", critical: "var(--red)" }[posture];
  const isOk = posture === "low" || posture === "normal";
  const phrase = posturePhrase(posture);
  const board = postureBoard(posture);

  return (
    <div className="cd-scroll" style={{ overflowY: "auto", height: "100%" }}>
      <div style={{ maxWidth: 640, margin: "0 auto", padding: "44px 28px 24px" }}>

        {/* Hero: chessboard scene */}
        <div style={{ textAlign: "center", marginBottom: 36 }}>
          <div style={{
            display: "inline-flex", flexDirection: "column", alignItems: "center", gap: 16,
            padding: "20px 28px 22px",
            background: "var(--bg-1)",
            border: "1px solid var(--line)",
            borderRadius: 18,
            boxShadow: "0 1px 2px oklch(0 0 0 / 0.04), 0 8px 28px oklch(0 0 0 / 0.05)",
            marginBottom: 22,
          }}>
            <MiniBoard size={5} cells={board} tileSize={36}/>
            <div style={{
              fontSize: 11, fontWeight: 600, color: postureColor,
              textTransform: "uppercase", letterSpacing: 0.6,
              display: "flex", alignItems: "center", gap: 6,
            }}>
              <Dot color={postureColor} size={6} pulse={!isOk}/>
              {phrase.chess}
            </div>
          </div>
          <h1 style={{
            margin: 0, fontSize: 30, fontWeight: 700, letterSpacing: -0.6,
            color: "var(--ink-0)",
          }}>{phrase.headline}</h1>
          <p style={{
            margin: "10px auto 0", fontSize: 16, color: "var(--ink-2)",
            lineHeight: 1.5, maxWidth: 440,
          }}>{phrase.sub}</p>
        </div>

        {/* If posture is OK: just one quiet primary action */}
        {isOk && (
          <div style={{ display: "flex", justifyContent: "center", gap: 10, marginBottom: 36 }}>
            <Btn kind="primary" size="lg" icon="scan" onClick={() => goto("scan")}>Run a checkup</Btn>
            <Btn kind="soft" size="lg" icon="chat" onClick={() => goto("ask")}>Ask Rook</Btn>
          </div>
        )}

        {/* If something is wrong: one prominent attention card */}
        {!isOk && CD.alerts[0] && (
          <button onClick={() => onAlertClick(CD.alerts[0].id)} style={{
            width: "100%", textAlign: "left", padding: "18px 20px",
            background: "var(--bg-1)",
            border: `1px solid color-mix(in oklch, ${postureColor} 30%, var(--line))`,
            borderRadius: 14, marginBottom: 36,
            display: "flex", alignItems: "center", gap: 14,
            boxShadow: `0 4px 16px color-mix(in oklch, ${postureColor} 12%, transparent)`,
            cursor: "pointer",
          }}>
            <div style={{
              width: 36, height: 36, borderRadius: 10,
              background: `color-mix(in oklch, ${postureColor} 14%, transparent)`,
              display: "grid", placeItems: "center", flexShrink: 0,
            }}>
              <Icon name="alert" size={18} color={postureColor}/>
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 14.5, fontWeight: 600, marginBottom: 2 }}>{CD.alerts[0].title}</div>
              <div style={{ fontSize: 13, color: "var(--ink-2)", lineHeight: 1.45 }}>{CD.alerts[0].summary}</div>
            </div>
            <Icon name="chevron" size={14} color="var(--ink-3)"/>
          </button>
        )}

        {/* Quiet "today" summary — 3 friendly numbers, no monospace, no dashboards */}
        <div style={{ marginBottom: 14 }}>
          <SmallHeading>Today</SmallHeading>
          <div style={{
            background: "var(--bg-1)",
            border: "1px solid var(--line)",
            borderRadius: 12, overflow: "hidden",
            boxShadow: "0 1px 2px oklch(0 0 0 / 0.04)",
          }}>
            {[
              { label: "Apps watched", value: "5", icon: "tools", c: "var(--ink-1)" },
              { label: "Things checked", value: "8,412", icon: "shield", c: "var(--ink-1)" },
              { label: "Things blocked", value: "11", icon: "lock", c: "var(--green)" },
            ].map((row, i) => (
              <div key={row.label} style={{
                display: "flex", alignItems: "center", gap: 14,
                padding: "13px 16px",
                borderBottom: i < 2 ? "1px solid var(--line-soft)" : "none",
              }}>
                <div style={{
                  width: 28, height: 28, borderRadius: 7,
                  background: "var(--bg-2)", display: "grid", placeItems: "center", flexShrink: 0,
                }}>
                  <Icon name={row.icon} size={15} color="var(--ink-2)"/>
                </div>
                <span style={{ flex: 1, fontSize: 14, color: "var(--ink-0)" }}>{row.label}</span>
                <span style={{ fontSize: 15, fontWeight: 600, color: row.c, fontVariantNumeric: "tabular-nums" }}>{row.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Quick actions list — Settings.app row style */}
        <div>
          <SmallHeading>Tools</SmallHeading>
          <div style={{
            background: "var(--bg-1)",
            border: "1px solid var(--line)",
            borderRadius: 12, overflow: "hidden",
            boxShadow: "0 1px 2px oklch(0 0 0 / 0.04)",
          }}>
            {[
              { id: "scan", label: "Run a security scan", desc: "Have Rook check your AI tools for risks", icon: "scan", c: "var(--accent)" },
              { id: "ask", label: "Ask Rook", desc: "Ask anything in plain English", icon: "chat", c: "var(--violet)" },
              { id: "activity", label: "See what's happening", desc: "Live feed of every action your AI tools take", icon: "activity", c: "var(--green)" },
              { id: "tools", label: "Manage your AI tools", desc: "5 wrapped, 1 unwrapped", icon: "tools", c: "var(--amber)" },
            ].map((row, i, arr) => (
              <button key={row.id} onClick={() => goto(row.id)} style={{
                width: "100%", textAlign: "left",
                display: "flex", alignItems: "center", gap: 14,
                padding: "13px 16px",
                borderBottom: i < arr.length - 1 ? "1px solid var(--line-soft)" : "none",
                cursor: "pointer", background: "transparent",
              }}
                onMouseEnter={e => e.currentTarget.style.background = "var(--accent-soft)"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
              >
                <div style={{
                  width: 30, height: 30, borderRadius: 8,
                  background: `color-mix(in oklch, ${row.c} 14%, transparent)`,
                  display: "grid", placeItems: "center", flexShrink: 0,
                }}>
                  <Icon name={row.icon} size={15} color={row.c}/>
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 14, color: "var(--ink-0)" }}>{row.label}</div>
                  <div style={{ fontSize: 12.5, color: "var(--ink-2)", marginTop: 1 }}>{row.desc}</div>
                </div>
                <Icon name="chevron" size={13} color="var(--ink-3)"/>
              </button>
            ))}
          </div>
        </div>

        {/* Ask Rook dock — quiet, anchored, expands to chat */}
        <AskRookDock onOpenFull={() => goto("ask")}/>

      </div>
    </div>
  );
};

const SmallHeading = ({ children }) => (
  <div style={{
    fontSize: 11, fontWeight: 600, color: "var(--ink-2)",
    textTransform: "uppercase", letterSpacing: 0.5,
    padding: "0 4px 8px",
  }}>{children}</div>
);

// Activity is the "pro" surface — keep it dense but lighten it
const ScreenActivity = ({ onEventClick, liveMode, setLiveMode, filterMatter, setFilterMatter, filterKind, setFilterKind, filterServer, setFilterServer, events }) => {
  const visible = events.filter(e => {
    if (filterMatter && e.classification === "routine") return false;
    if (filterKind !== "all" && e.kind !== filterKind) return false;
    if (filterServer !== "all" && e.server !== filterServer) return false;
    return true;
  });

  return (
    <div style={{ display: "grid", gridTemplateRows: "auto 1fr", height: "100%" }}>
      {/* Toolbar */}
      <div style={{ padding: "12px 20px", borderBottom: "1px solid var(--line)", display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", background: "var(--bg-1)" }}>
        <Dot color={liveMode ? "var(--green)" : "var(--ink-3)"} size={7} pulse={liveMode}/>
        <span style={{ fontSize: 13, fontWeight: 600 }}>{visible.length} events</span>
        <span style={{ fontSize: 12, color: "var(--ink-3)" }}>· about one a second</span>
        <button onClick={() => setLiveMode(!liveMode)} style={{ padding: "4px 10px", borderRadius: 6, fontSize: 12, color: "var(--ink-1)", background: "var(--bg-2)" }}>
          {liveMode ? "Pause" : "Resume"}
        </button>

        <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
          <div style={{ position: "relative" }}>
            <Icon name="search" size={12} color="var(--ink-3)" style={{ position: "absolute", left: 9, top: 7 }}/>
            <input placeholder="Search…" style={{
              background: "var(--bg-2)", border: "none", borderRadius: 6,
              padding: "5px 10px 5px 26px", fontSize: 12.5, color: "var(--ink-0)", width: 200, outline: "none",
            }}/>
          </div>
          <Pill label="kind" value={filterKind} options={["all","process","network","dns"]} onChange={setFilterKind}/>
          <Pill label="app" value={filterServer} options={["all", ...CD.servers.map(s => s.id)]} onChange={setFilterServer}/>
          <button onClick={() => setFilterMatter(!filterMatter)} style={{
            padding: "5px 10px", fontSize: 12, borderRadius: 6,
            background: filterMatter ? "var(--accent-soft)" : "transparent",
            color: filterMatter ? "var(--accent)" : "var(--ink-2)",
          }}>Only what matters</button>
        </div>
      </div>

      <div className="cd-scroll" style={{ overflowY: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
          <thead>
            <tr style={{ position: "sticky", top: 0, background: "var(--bg-1)", zIndex: 1 }}>
              {["", "Time", "App", "What it did", "Where", "Result"].map((h, i) => (
                <th key={i} style={{ padding: "8px 12px", textAlign: i === 5 ? "right" : "left", fontSize: 11, fontWeight: 600, color: "var(--ink-2)", borderBottom: "1px solid var(--line)" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.map((e) => {
              const srv = CD.serverById(e.server);
              return (
                <tr key={e.id} onClick={() => onEventClick(e.id)} style={{ cursor: "pointer", borderBottom: "1px solid var(--line-soft)" }}
                  onMouseEnter={ev => ev.currentTarget.style.background = "var(--accent-soft)"}
                  onMouseLeave={ev => ev.currentTarget.style.background = "transparent"}
                >
                  <td style={{ padding: "11px 16px", width: 28 }}><KindIcon kind={e.kind}/></td>
                  <td style={{ padding: "11px 12px", color: "var(--ink-3)", whiteSpace: "nowrap", width: 70, fontVariantNumeric: "tabular-nums" }}>{CD.fmtTime(e.t)}</td>
                  <td style={{ padding: "11px 12px", color: "var(--ink-0)" }}>{srv?.name || e.server}</td>
                  <td style={{ padding: "11px 12px", fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--ink-1)", maxWidth: 380, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {e.kind === "process" ? `ran ${e.comm}` : e.kind === "network" ? `connected to ${e.target}` : `looked up ${e.target}`}
                  </td>
                  <td style={{ padding: "11px 12px", color: "var(--ink-2)", fontSize: 12 }}>{e.path?.split("/").slice(-2).join("/") || "—"}</td>
                  <td style={{ padding: "11px 16px", textAlign: "right" }}>
                    {e.classification !== "routine" ? <ClassBadge kind={e.classification}/> : <VerdictPill verdict={e.verdict}/>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const Pill = ({ label, value, options, onChange }) => (
  <label style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: "4px 8px", borderRadius: 6, fontSize: 12, color: "var(--ink-2)", background: "var(--bg-2)" }}>
    <span style={{ color: "var(--ink-3)" }}>{label}:</span>
    <select value={value} onChange={e => onChange(e.target.value)} style={{ background: "transparent", border: "none", color: "var(--ink-0)", fontSize: 12, outline: "none" }}>
      {options.map(o => <option key={o} value={o}>{o}</option>)}
    </select>
  </label>
);

Object.assign(window, { ScreenHome, ScreenActivity, Pill, SmallHeading });
