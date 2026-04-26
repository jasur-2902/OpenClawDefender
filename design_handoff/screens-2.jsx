// ClawDefender — Event Detail, Alert Detail, AI Scan, Ask Rook

const ScreenEventDetail = ({ eventId, onBack, onAlertClick }) => {
  const e = CD.eventById(eventId) || CD.events[5];
  const srv = CD.serverById(e.server);
  const [showRaw, setShowRaw] = React.useState(false);
  const dimensions = [
    { name: "novelty", v: 0.82 },
    { name: "rarity", v: 0.71 },
    { name: "scope", v: 0.45 },
    { name: "intent", v: 0.88 },
    { name: "freq", v: 0.34 },
    { name: "egress", v: 0.65 },
    { name: "priv", v: 0.22 },
    { name: "chain", v: 0.78 },
    { name: "intel", v: 0.95 },
  ];

  return (
    <div className="cd-scroll" style={{ padding: 24, maxWidth: 1080, margin: "0 auto", overflowY: "auto", height: "100%" }}>
      <button onClick={onBack} style={{ fontSize: 11.5, color: "var(--ink-2)", marginBottom: 14, display: "inline-flex", alignItems: "center", gap: 6 }}>
        <Icon name="chevron" size={11} color="var(--ink-2)" stroke={2}/> <span style={{ transform: "rotate(180deg)", display: "inline-block" }}/>Back
      </button>

      {/* Hero */}
      <div style={{ display: "flex", alignItems: "flex-start", gap: 16, marginBottom: 18 }}>
        <div style={{ width: 44, height: 44, borderRadius: 10, background: "var(--bg-2)", border: "1px solid var(--line)", display: "grid", placeItems: "center" }}>
          <KindIcon kind={e.kind} size={20}/>
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
            <VerdictPill verdict={e.verdict}/>
            <ClassBadge kind={e.classification}/>
            <span style={{ fontSize: 10.5, fontFamily: "var(--font-mono)", color: "var(--ink-3)" }}>{e.id} · {CD.fmtTime(e.t)}</span>
          </div>
          <h1 style={{ margin: 0, fontSize: 18, fontWeight: 600, fontFamily: "var(--font-mono)" }}>
            {e.comm} <span style={{ color: "var(--ink-3)" }}>→</span> {e.target}
          </h1>
          <div style={{ marginTop: 6, fontSize: 13, color: "var(--ink-2)", lineHeight: 1.55 }}>
            {e.reason || "Event passed local SLM triage with no anomalies."}
          </div>
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          <Btn icon="search" kind="accent">Investigate with AI</Btn>
          <Btn icon="lock" kind="danger">Block server</Btn>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: 14 }}>
        <div style={{ display: "grid", gap: 14 }}>
          {/* Triage */}
          <Card title="SLM Triage · Qwen3 1.7B" action={<Badge color="var(--accent)" mono>conf 0.91</Badge>}>
            <div style={{ fontSize: 12.5, color: "var(--ink-1)", lineHeight: 1.55 }}>
              Classified as <strong style={{ color: CD.classifications[e.classification]?.color }}>{e.classification}</strong>.
              {" "}{e.reason || "Matches established baseline for this server. No follow-up required."}
            </div>
            <div style={{ marginTop: 10, padding: 10, background: "var(--bg-2)", borderRadius: 8, fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--ink-2)" }}>
              prompt → "Evaluate this {e.kind} event…" · 187 tok/s · 412ms total
            </div>
          </Card>

          {/* Cloud analysis (only for suspicious) */}
          {e.classification === "suspicious" && (
            <Card title="Cloud Investigation · Claude Sonnet 4.5" action={<Badge color="var(--violet)" mono>conf 0.94</Badge>}>
              <div style={{ fontSize: 12.5, color: "var(--ink-1)", lineHeight: 1.6 }}>
                This event is <strong style={{ color: "var(--red)" }}>part of a multi-stage attack</strong>. Same server initiated
                a DNS query for a known C2 domain 4 seconds prior, then attempted TCP connect to a Tor exit relay 8 seconds later.
                Pattern matches MITRE T1071.001 (Application Layer Protocol).
              </div>
              <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
                <Btn kind="accent" icon="alert" onClick={() => onAlertClick("alrt_201")}>View parent alert</Btn>
                <Btn kind="ghost">Mark false positive</Btn>
              </div>
            </Card>
          )}

          {/* Top anomaly factors only — full radar tucked into expander */}
          <Card title="Top anomaly factors" action={<button onClick={() => setShowRaw(!showRaw)} style={{ fontSize: 11.5, color: "var(--accent)" }}>{showRaw ? "Hide raw event" : "Show raw event"}</button>}>
            <div style={{ display: "grid", gap: 6 }}>
              {[...dimensions].sort((a,b) => b.v - a.v).slice(0, 4).map(d => (
                <div key={d.name} style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 11.5 }}>
                  <span style={{ width: 70, fontFamily: "var(--font-mono)", color: "var(--ink-2)" }}>{d.name}</span>
                  <div style={{ flex: 1, height: 5, background: "var(--bg-3)", borderRadius: 3, overflow: "hidden" }}>
                    <div style={{ width: `${d.v * 100}%`, height: "100%", background: d.v > 0.7 ? "var(--red)" : d.v > 0.4 ? "var(--amber)" : "var(--green)" }}/>
                  </div>
                  <span style={{ width: 32, textAlign: "right", fontFamily: "var(--font-mono)", color: "var(--ink-1)" }}>{d.v.toFixed(2)}</span>
                </div>
              ))}
            </div>
            {showRaw && (
              <pre className="cd-slide-in" style={{ marginTop: 14, padding: 12, background: "var(--bg-2)", borderRadius: 8, fontFamily: "var(--font-mono)", fontSize: 11, lineHeight: 1.6, color: "var(--ink-1)", whiteSpace: "pre-wrap" }}>
{`{
  "kind": "${e.kind}",
  "hook": "${e.hook}",
  "pid": ${e.pid},
  "comm": "${e.comm}",
  "target": "${e.target}",
  "verdict": "${e.verdict}"
}`}
              </pre>
            )}
          </Card>
        </div>

        {/* Side rail */}
        <div style={{ display: "grid", gap: 14 }}>
          <Card title="Source server">
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
              <div style={{ width: 32, height: 32, borderRadius: 8, background: "var(--bg-2)", display: "grid", placeItems: "center", border: "1px solid var(--line)" }}>
                <Icon name="tools" size={14} color="var(--ink-1)"/>
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 13, fontWeight: 500 }}>{srv?.name}</div>
                <div style={{ fontSize: 10.5, color: "var(--ink-3)", fontFamily: "var(--font-mono)" }}>{srv?.client}</div>
              </div>
            </div>
            <KV k="Trust" v={srv?.trust}/>
            <KV k="Anomaly score" v={srv?.anomaly.toFixed(2)} mono/>
            <KV k="Events (24h)" v={srv?.events} mono/>
            <KV k="Wrapped" v={srv?.wrapped ? "yes" : "no"}/>
          </Card>

          <Card title="Behavioral context">
            <div style={{ fontSize: 12, color: "var(--ink-1)", lineHeight: 1.55 }}>
              This server normally accesses <span className="mono" style={{ color: "var(--ink-0)" }}>3.2</span> files per session.
              Today it has accessed <span className="mono" style={{ color: "var(--amber)" }}>47</span>.
            </div>
          </Card>

          <Card title="Correlated">
            <div style={{ display: "grid", gap: 6 }}>
              {[
                { id: "ev_8814", t: "T-4s", k: "dns", l: "udp_sendmsg paste.evil-c2…" },
                { id: "ev_8809", t: "T+0s", k: "process", l: "execve curl … | sh" },
                { id: "ev_8816", t: "T+8s", k: "network", l: "tcp_v4_connect 185.220.…" },
              ].map(c => (
                <div key={c.id} style={{ display: "flex", alignItems: "center", gap: 8, padding: 8, background: "var(--bg-2)", borderRadius: 6 }}>
                  <KindIcon kind={c.k} size={13}/>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--ink-3)", width: 40 }}>{c.t}</span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--ink-1)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.l}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

const RadarChart = ({ dims, size = 180 }) => {
  const cx = size / 2, cy = size / 2, r = size / 2 - 14;
  const n = dims.length;
  const pts = dims.map((d, i) => {
    const a = (Math.PI * 2 * i) / n - Math.PI / 2;
    const v = d.v * r;
    return [cx + Math.cos(a) * v, cy + Math.sin(a) * v];
  });
  const grid = [0.25, 0.5, 0.75, 1].map(s => {
    const gp = dims.map((d, i) => {
      const a = (Math.PI * 2 * i) / n - Math.PI / 2;
      return [cx + Math.cos(a) * r * s, cy + Math.sin(a) * r * s];
    });
    return gp.map((p, i) => `${i ? "L" : "M"}${p[0]},${p[1]}`).join("") + "Z";
  });
  const poly = pts.map((p, i) => `${i ? "L" : "M"}${p[0]},${p[1]}`).join("") + "Z";
  return (
    <svg width={size} height={size}>
      {grid.map((g, i) => <path key={i} d={g} fill="none" stroke="var(--line)" strokeWidth="0.7" opacity={0.5 + i*0.1}/>)}
      <path d={poly} fill="var(--accent)" fillOpacity="0.18" stroke="var(--accent)" strokeWidth="1.5"/>
      {pts.map((p, i) => <circle key={i} cx={p[0]} cy={p[1]} r="2.5" fill="var(--accent)"/>)}
    </svg>
  );
};

const ScreenAlertDetail = ({ alertId, onBack, onEventClick }) => {
  const a = CD.alerts.find(x => x.id === alertId) || CD.alerts[0];
  const sc = CD.severityColor(a.severity);
  return (
    <div className="cd-scroll" style={{ padding: 24, maxWidth: 1080, margin: "0 auto", overflowY: "auto", height: "100%" }}>
      <button onClick={onBack} style={{ fontSize: 11.5, color: "var(--ink-2)", marginBottom: 14 }}>← Back</button>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 14, marginBottom: 18 }}>
        <div style={{ width: 6, alignSelf: "stretch", borderRadius: 3, background: sc, marginTop: 2 }}/>
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
            <Badge color={sc}>{a.severity}</Badge>
            <Badge color="var(--ink-2)" mono>{a.id}</Badge>
            <span style={{ fontSize: 11, color: "var(--ink-3)" }}>{a.createdAt}</span>
          </div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 600, letterSpacing: -0.3 }}>{a.title}</h1>
          <div style={{ marginTop: 6, fontSize: 13.5, color: "var(--ink-2)", lineHeight: 1.5 }}>{a.summary}</div>
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          <Btn kind="primary" icon="search">Investigate</Btn>
          <Btn kind="danger" icon="lock">Block server</Btn>
          <Btn kind="ghost">Dismiss</Btn>
        </div>
      </div>

      {/* AI verdict card */}
      {a.intel && (
        <Card title="AI Verdict · Claude Sonnet 4.5" style={{ marginBottom: 14, borderColor: "color-mix(in oklch, var(--violet) 35%, var(--line))" }} action={<Badge color="var(--red)" mono>BLOCK · conf 0.94</Badge>}>
          <div style={{ fontSize: 13, color: "var(--ink-1)", lineHeight: 1.6 }}>{a.intel}</div>
        </Card>
      )}

      {/* Kill chain */}
      {a.killChain && (
        <Card title="ThreatStory — kill chain" style={{ marginBottom: 14 }}>
          <div style={{ display: "grid", gridTemplateColumns: `repeat(${a.killChain.length}, 1fr)`, gap: 8, position: "relative" }}>
            {a.killChain.map((s, i) => (
              <div key={i}>
                <div style={{ position: "relative", marginBottom: 12 }}>
                  <div style={{ height: 2, background: i === a.killChain.length - 1 ? "transparent" : sc, position: "absolute", top: 11, left: 24, right: -8 }}/>
                  <div style={{ width: 24, height: 24, borderRadius: 999, background: sc, color: "var(--bg-0)", display: "grid", placeItems: "center", fontSize: 11, fontWeight: 700, fontFamily: "var(--font-mono)", position: "relative", zIndex: 1 }}>{i + 1}</div>
                </div>
                <div style={{ fontSize: 10.5, color: sc, fontFamily: "var(--font-mono)", textTransform: "uppercase", letterSpacing: 0.5 }}>{s.t}</div>
                <div style={{ fontSize: 11.5, fontWeight: 600, marginTop: 2 }}>{s.stage}</div>
                <button onClick={() => onEventClick(s.id)} style={{ marginTop: 6, fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--ink-2)", textAlign: "left" }}>{s.label}</button>
              </div>
            ))}
          </div>
        </Card>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1.3fr 1fr", gap: 14 }}>
        <Card title="Recommended actions" padded={false}>
          {[
            { t: "Isolate shell-runner (revoke wrap)", d: "Server stops getting new tool calls. Audit log preserved.", k: "danger", icon: "lock" },
            { t: "Add 185.220.101.34 to kernel BLOCKLIST", d: "Insert FNV-1a hash into eBPF map. Future TCP attempts fail at kprobe.", k: "accent", icon: "shield" },
            { t: "Rotate any credentials touched in last hour", d: "1 SSH config + 0 keychain entries identified.", k: "accent", icon: "key" },
          ].map((r, i) => (
            <div key={i} style={{ padding: "14px 16px", borderBottom: i < 2 ? "1px solid var(--line-soft)" : "none", display: "flex", gap: 10 }}>
              <Icon name={r.icon} size={16} color={r.k === "danger" ? "var(--red)" : "var(--accent)"}/>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 12.5, fontWeight: 500 }}>{r.t}</div>
                <div style={{ fontSize: 11.5, color: "var(--ink-2)", marginTop: 3 }}>{r.d}</div>
              </div>
              <Btn size="sm" kind={r.k}>Apply</Btn>
            </div>
          ))}
        </Card>
        <Card title="Evidence">
          {a.eventIds.map(id => {
            const e = CD.eventById(id);
            if (!e) return null;
            return (
              <button key={id} onClick={() => onEventClick(id)} style={{ width: "100%", display: "flex", alignItems: "center", gap: 8, padding: "8px 10px", background: "var(--bg-2)", borderRadius: 6, marginBottom: 6, textAlign: "left" }}>
                <KindIcon kind={e.kind} size={13}/>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--ink-1)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.target}</span>
                <VerdictPill verdict={e.verdict}/>
              </button>
            );
          })}
        </Card>
      </div>
    </div>
  );
};

const ScreenAlerts = ({ onAlertClick }) => {
  const grouped = { critical: [], high: [], medium: [], low: [] };
  CD.alerts.forEach(a => grouped[a.severity]?.push(a));
  const sevLabel = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
  return (
    <div className="cd-scroll" style={{ overflowY: "auto", height: "100%" }}>
      <div style={{ maxWidth: 720, margin: "0 auto", padding: "40px 28px 48px" }}>
        <SectionTitle sub="Things ClawDefender thinks you should look at.">Alerts</SectionTitle>

        {Object.entries(grouped).filter(([_, list]) => list.length).map(([sev, list]) => {
          const sc = CD.severityColor(sev);
          return (
            <div key={sev} style={{ marginBottom: 24 }}>
              <div style={{
                display: "flex", alignItems: "center", gap: 8,
                padding: "0 4px 8px", fontSize: 11, fontWeight: 600,
                color: "var(--ink-2)", textTransform: "uppercase", letterSpacing: 0.5,
              }}>
                <Dot color={sc} size={6}/>
                {sevLabel[sev]} · {list.length}
              </div>
              <div style={{
                background: "var(--bg-1)",
                border: "1px solid var(--line)",
                borderRadius: 12, overflow: "hidden",
                boxShadow: "0 1px 2px oklch(0 0 0 / 0.04)",
              }}>
                {list.map((a, i) => (
                  <button key={a.id} onClick={() => onAlertClick(a.id)} style={{
                    width: "100%", display: "flex", alignItems: "flex-start", gap: 14,
                    padding: "14px 16px", textAlign: "left",
                    borderBottom: i < list.length - 1 ? "1px solid var(--line-soft)" : "none",
                    background: "transparent",
                  }}
                    onMouseEnter={e => e.currentTarget.style.background = "var(--accent-soft)"}
                    onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                  >
                    <div style={{
                      width: 8, height: 8, borderRadius: 999, background: sc,
                      marginTop: 6, flexShrink: 0,
                    }}/>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 3 }}>
                        <span style={{ fontSize: 14, fontWeight: 600, color: "var(--ink-0)", flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.title}</span>
                        <span style={{ fontSize: 12, color: "var(--ink-3)", flexShrink: 0 }}>{a.createdAt}</span>
                      </div>
                      <div style={{ fontSize: 13, color: "var(--ink-2)", lineHeight: 1.45, marginBottom: 6 }}>{a.summary}</div>
                      <div style={{ display: "flex", gap: 14, fontSize: 12, color: "var(--ink-3)" }}>
                        <span>{CD.serverById(a.server)?.name || a.server}</span>
                        <span>·</span>
                        <span>{a.status}</span>
                        {a.eventCount > 1 && <><span>·</span><span>{a.eventCount} events</span></>}
                      </div>
                    </div>
                    <Icon name="chevron" size={13} color="var(--ink-3)" style={{ marginTop: 4, flexShrink: 0 }}/>
                  </button>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

Object.assign(window, { ScreenEventDetail, ScreenAlerts, ScreenAlertDetail, RadarChart });
