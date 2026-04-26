// ClawDefender — AI Scan, Ask Rook, My Tools

const ScreenScan = () => {
  const [running, setRunning] = React.useState(true);
  const [stages, setStages] = React.useState(CD.scanStages);
  const [findings, setFindings] = React.useState(CD.scanFindings.slice(0, 3));
  const [feed, setFeed] = React.useState([
    { t: "00:00", k: "info", m: "Playbook 'MCP Security Audit' started — depth: standard" },
    { t: "00:01", k: "tool", m: "list_servers() → 6 servers" },
    { t: "00:03", k: "tool", m: "read_policy('/etc/claw-wall/config.toml')" },
    { t: "00:05", k: "info", m: "Stage 1 of 5 · Inventory ✓ (1.2s)" },
    { t: "00:06", k: "tool", m: "inspect_capabilities('shell-runner')" },
    { t: "00:07", k: "find", m: "shell-runner has CAP_NET_RAW (high)" },
    { t: "00:09", k: "tool", m: "scan_dns_resolvers()" },
    { t: "00:10", k: "find", m: "8.8.8.8 hardcoded in 3 servers (medium)" },
    { t: "00:12", k: "tool", m: "trace_filesystem_scope('filemanager-mcp')" },
    { t: "00:13", k: "find", m: "FileManager MCP can read entire $HOME (medium)" },
    { t: "00:15", k: "info", m: "Stage 2 of 5 · Configuration Analysis ✓ (4.8s)" },
    { t: "00:16", k: "tool", m: "probe_egress_patterns()…" },
  ]);
  const feedRef = React.useRef();

  React.useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [feed]);

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 320px", height: "100%" }}>
      <div style={{ padding: 24, overflowY: "auto" }} className="cd-scroll">
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
          <div style={{ width: 38, height: 38, borderRadius: 10, background: "var(--violet-soft)", border: "1px solid color-mix(in oklch, var(--violet) 30%, transparent)", display: "grid", placeItems: "center" }}>
            <Icon name="scan" size={18} color="var(--violet)"/>
          </div>
          <div style={{ flex: 1 }}>
            <h1 style={{ margin: 0, fontSize: 17, fontWeight: 600 }}>MCP Security Audit</h1>
            <div style={{ fontSize: 11.5, color: "var(--ink-2)", marginTop: 2 }}>Standard depth · 5 stages · powered by Claude</div>
          </div>
          <Btn kind="ghost" icon="x" onClick={() => setRunning(false)}>Stop</Btn>
        </div>

        {/* Stages */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 6, marginBottom: 18 }}>
          {stages.map((s, i) => (
            <div key={s.id} style={{
              padding: "10px 12px",
              background: "var(--bg-1)",
              border: "1px solid " + (s.status === "running" ? "var(--accent-line)" : "var(--line)"),
              borderRadius: 8,
              position: "relative", overflow: "hidden",
            }}>
              {s.status === "running" && <div className="cd-shimmer" style={{ position: "absolute", inset: 0 }}/>}
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                <div style={{
                  width: 16, height: 16, borderRadius: 999,
                  background: s.status === "done" ? "var(--green-soft)" : s.status === "running" ? "var(--accent-soft)" : "var(--bg-3)",
                  border: "1px solid " + (s.status === "done" ? "color-mix(in oklch, var(--green) 40%, transparent)" : s.status === "running" ? "var(--accent-line)" : "var(--line)"),
                  display: "grid", placeItems: "center", fontSize: 9, fontFamily: "var(--font-mono)",
                  color: s.status === "done" ? "var(--green)" : "var(--ink-3)",
                }}>{s.status === "done" ? "✓" : i + 1}</div>
                <span style={{ fontSize: 10, color: "var(--ink-3)", fontFamily: "var(--font-mono)", textTransform: "uppercase", letterSpacing: 0.4 }}>Stage {i + 1}</span>
              </div>
              <div style={{ fontSize: 12, fontWeight: 500, color: "var(--ink-1)" }}>{s.name}</div>
              {s.findings != null && (
                <div style={{ marginTop: 4, fontSize: 10.5, fontFamily: "var(--font-mono)", color: s.findings ? "var(--amber)" : "var(--ink-3)" }}>
                  {s.findings} finding{s.findings !== 1 ? "s" : ""}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Live feed */}
        <Card title="Investigation feed" action={<Badge color="var(--violet)" mono><span className="cd-pulse">●</span> live</Badge>} padded={false}>
          <div ref={feedRef} className="cd-scroll" style={{ maxHeight: 280, overflowY: "auto", fontFamily: "var(--font-mono)", fontSize: 11.5, padding: "10px 14px" }}>
            {feed.map((f, i) => (
              <div key={i} style={{ display: "flex", gap: 10, padding: "3px 0", color: "var(--ink-2)" }}>
                <span style={{ color: "var(--ink-4)", width: 42 }}>{f.t}</span>
                <span style={{ width: 50, color: f.k === "find" ? "var(--amber)" : f.k === "tool" ? "var(--accent)" : "var(--ink-3)" }}>
                  [{f.k === "find" ? "FIND" : f.k === "tool" ? "TOOL" : "INFO"}]
                </span>
                <span style={{ color: f.k === "find" ? "var(--ink-0)" : "var(--ink-1)" }}>{f.m}</span>
              </div>
            ))}
            <div style={{ display: "flex", gap: 10, padding: "3px 0", alignItems: "center" }}>
              <span style={{ color: "var(--ink-4)", width: 42 }}>—</span>
              <span style={{ width: 50, color: "var(--accent)" }}>[TOOL]</span>
              <span style={{ color: "var(--ink-2)" }}>analyzing egress patterns</span>
              <span className="cd-caret"/>
            </div>
          </div>
        </Card>

        {/* Findings */}
        <div style={{ marginTop: 18 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
            <h2 style={{ margin: 0, fontSize: 13, fontWeight: 600, color: "var(--ink-1)" }}>Findings</h2>
            <Badge color="var(--ink-2)" mono>{findings.length}</Badge>
            <Btn size="sm" kind="accent" style={{ marginLeft: "auto" }} icon="check">Apply all safe fixes</Btn>
          </div>
          <div style={{ display: "grid", gap: 8 }}>
            {findings.map(f => {
              const sc = CD.severityColor(f.severity);
              return (
                <div key={f.id} className="cd-slide-in" style={{
                  display: "flex", alignItems: "stretch", gap: 12, padding: 14,
                  background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: 10,
                }}>
                  <div style={{ width: 3, borderRadius: 2, background: sc }}/>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                      <Badge color={sc}>{f.severity}</Badge>
                      <span style={{ fontSize: 12.5, fontWeight: 500 }}>{f.title}</span>
                    </div>
                    <div style={{ fontSize: 11.5, color: "var(--ink-2)" }}>{f.evidence}</div>
                  </div>
                  <Btn size="sm" kind="accent" icon="check">{f.fix}</Btn>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Side rail */}
      <aside style={{ borderLeft: "1px solid var(--line)", padding: 18, background: "var(--bg-1)", display: "grid", alignContent: "start", gap: 14 }}>
        <div>
          <div style={{ fontSize: 10, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5 }}>Elapsed</div>
          <div style={{ fontSize: 22, fontFamily: "var(--font-mono)", marginTop: 2 }}>00:16</div>
        </div>
        <div>
          <div style={{ fontSize: 10, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5 }}>Tool calls</div>
          <div style={{ fontSize: 13, fontFamily: "var(--font-mono)", marginTop: 2 }}>11 / 40</div>
          <div style={{ height: 4, background: "var(--bg-3)", borderRadius: 2, marginTop: 6, overflow: "hidden" }}>
            <div style={{ width: "27%", height: "100%", background: "var(--accent)" }}/>
          </div>
        </div>
        <div>
          <div style={{ fontSize: 10, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5 }}>Cost so far</div>
          <div style={{ fontSize: 13, fontFamily: "var(--font-mono)", marginTop: 2 }}>$0.18 / ~$0.45</div>
        </div>
        <div style={{ borderTop: "1px solid var(--line-soft)", paddingTop: 14 }}>
          <div style={{ fontSize: 10, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 8 }}>Mid-scan guidance</div>
          <textarea placeholder="e.g. focus on filesystem scope" style={{
            width: "100%", background: "var(--bg-0)", border: "1px solid var(--line)", borderRadius: 6,
            padding: 8, fontSize: 11.5, color: "var(--ink-0)", outline: "none", resize: "none", minHeight: 60,
          }}/>
          <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
            <Btn kind="soft" size="sm" style={{ flex: 1, justifyContent: "center" }}>Skip stage</Btn>
            <Btn kind="primary" size="sm" icon="send">Send</Btn>
          </div>
        </div>
      </aside>
    </div>
  );
};

const ScreenAsk = () => {
  const [input, setInput] = React.useState("");
  const [messages, setMessages] = React.useState([
    { role: "user", text: "What happened today?" },
    { role: "assistant", mode: "cloud", text: "Today your machine ran 8,412 events from 5 wrapped servers. Three things stood out:", tools: [
      { call: "summarize_day(window=24h)", result: "812 routine · 31 notable · 4 suspicious" },
    ], list: [
      "shell-runner triggered a critical C2 alert at 14:32 — domain `paste.evil-c2.example` matched a known IoC and was blocked at the kprobe before the TCP connect could complete.",
      "FileManager MCP read `~/.ssh/config` for the first time in its 30-day baseline. Notable, not blocked.",
      "Cursor IDE's anomaly score drifted from 0.18 to 0.42 — within tolerance but worth noting.",
    ]},
    { role: "user", text: "Should I be worried about FileManager?" },
    { role: "assistant", mode: "cloud", text: "Probably not yet. I checked its behavioral profile and it hasn't done anything beyond reading the file — no follow-up DNS or network. The read happened seconds after you switched to a project that uses SSH-based deploy, which is a plausible explanation.", tools: [
      { call: "behavioral_profile('filemanager-mcp', window=30d)", result: "no anomalous chains" },
      { call: "correlate_events(server='filemanager-mcp', window=5m)", result: "0 follow-up events" },
    ], propose: { text: "Want me to scope FileManager to ~/Documents only as a precaution?", actions: ["Apply", "Not now"] }},
  ]);

  return (
    <div style={{ display: "grid", gridTemplateColumns: "240px 1fr", height: "100%" }}>
      {/* Convo sidebar */}
      <aside style={{ borderRight: "1px solid var(--line)", padding: 14, background: "var(--bg-1)" }}>
        <Btn kind="accent" icon="sparkles" style={{ width: "100%", justifyContent: "center", marginBottom: 12 }}>New conversation</Btn>
        <div style={{ fontSize: 10, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 8, padding: "0 4px" }}>History</div>
        {CD.chatHistory.map((c, i) => (
          <button key={c.id} style={{
            width: "100%", textAlign: "left", padding: "9px 10px", borderRadius: 6, marginBottom: 2,
            background: i === 0 ? "var(--bg-2)" : "transparent", color: i === 0 ? "var(--ink-0)" : "var(--ink-2)",
          }}>
            <div style={{ fontSize: 12, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.title}</div>
            <div style={{ fontSize: 10, color: "var(--ink-3)", fontFamily: "var(--font-mono)", marginTop: 2 }}>{c.at}</div>
          </button>
        ))}
      </aside>

      <div style={{ display: "grid", gridTemplateRows: "auto 1fr auto", overflow: "hidden" }}>
        <div style={{ padding: "14px 24px", borderBottom: "1px solid var(--line)", display: "flex", alignItems: "center", gap: 10 }}>
          <Icon name="chat" size={15} color="var(--accent)"/>
          <h2 style={{ margin: 0, fontSize: 13, fontWeight: 600 }}>shell-runner C2 beacon</h2>
          <Badge color="var(--violet)" mono><Icon name="cloud" size={10} color="var(--violet)"/> Powered by Claude</Badge>
        </div>

        <div className="cd-scroll" style={{ overflowY: "auto", padding: "20px 24px" }}>
          <div style={{ maxWidth: 760, margin: "0 auto", display: "grid", gap: 16 }}>
            {messages.map((m, i) => (
              <div key={i}>
                {m.role === "user" ? (
                  <div style={{ display: "flex", justifyContent: "flex-end" }}>
                    <div style={{ maxWidth: "75%", padding: "10px 14px", background: "var(--accent-soft)", border: "1px solid var(--accent-line)", borderRadius: 10, fontSize: 13, color: "var(--ink-0)" }}>{m.text}</div>
                  </div>
                ) : (
                  <div>
                    {m.tools && (
                      <div style={{ marginBottom: 10, display: "grid", gap: 4 }}>
                        {m.tools.map((t, j) => (
                          <div key={j} style={{ display: "flex", alignItems: "center", gap: 8, fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--ink-3)" }}>
                            <Icon name="search" size={11} color="var(--accent)"/>
                            <span style={{ color: "var(--accent)" }}>{t.call}</span>
                            <span>→</span>
                            <span>{t.result}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    <div style={{ fontSize: 13.5, color: "var(--ink-0)", lineHeight: 1.6 }}>{m.text}</div>
                    {m.list && (
                      <ol style={{ margin: "10px 0 0", paddingLeft: 18, fontSize: 12.5, color: "var(--ink-1)", lineHeight: 1.65 }}>
                        {m.list.map((x, j) => <li key={j} style={{ marginBottom: 4 }} dangerouslySetInnerHTML={{ __html: x.replace(/`([^`]+)`/g, "<span class='mono' style='background:var(--bg-2);padding:1px 5px;border-radius:3px;color:var(--ink-0)'>$1</span>") }}/>)}
                      </ol>
                    )}
                    {m.propose && (
                      <div style={{ marginTop: 14, padding: 12, background: "var(--bg-1)", border: "1px solid var(--accent-line)", borderRadius: 10, display: "flex", alignItems: "center", gap: 12 }}>
                        <Icon name="sparkles" size={15} color="var(--accent)"/>
                        <div style={{ flex: 1, fontSize: 12.5 }}>{m.propose.text}</div>
                        <Btn kind="primary" size="sm">Apply</Btn>
                        <Btn kind="ghost" size="sm">Not now</Btn>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        <div style={{ padding: "14px 24px", borderTop: "1px solid var(--line)" }}>
          <div style={{ maxWidth: 760, margin: "0 auto", display: "flex", gap: 8, alignItems: "flex-end", background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: 12, padding: 10 }}>
            <textarea value={input} onChange={e => setInput(e.target.value)} placeholder="Ask Rook anything — ‘is FileManager safe?’, ‘block all network for shell-runner’…" style={{
              flex: 1, background: "transparent", border: "none", outline: "none", color: "var(--ink-0)",
              fontSize: 13, resize: "none", minHeight: 22, maxHeight: 120, lineHeight: 1.5,
            }}/>
            <Btn kind="primary" icon="send">Send</Btn>
          </div>
        </div>
      </div>
    </div>
  );
};

const ScreenTools = ({ onServerClick }) => (
  <div className="cd-scroll" style={{ padding: 24, maxWidth: 1080, margin: "0 auto", overflowY: "auto", height: "100%" }}>
    <SectionTitle sub="Each MCP server is wrapped at the eBPF layer.">My Tools</SectionTitle>
    {/* Banner */}
    <div style={{ padding: 12, background: "var(--accent-soft)", border: "1px solid var(--accent-line)", borderRadius: 10, marginBottom: 14, display: "flex", alignItems: "center", gap: 12 }}>
      <Icon name="shield" size={16} color="var(--accent)"/>
      <div style={{ flex: 1, fontSize: 12.5 }}>
        <strong>1 unwrapped server</strong> <span style={{ color: "var(--ink-2)" }}>· shell-runner is running without protection</span>
      </div>
      <Btn kind="primary" size="sm">Wrap now</Btn>
    </div>

    <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
      {CD.servers.map(s => {
        const trustColor = s.trust === "trusted" ? "var(--green)" : s.trust === "watching" ? "var(--amber)" : "var(--red)";
        const piece = capabilityPiece(s.capabilities);
        return (
          <button key={s.id} onClick={() => onServerClick(s.id)} style={{
            textAlign: "left", padding: 16,
            background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: "var(--radius-lg)",
          }}
            onMouseEnter={e => e.currentTarget.style.borderColor = "var(--line-strong)"}
            onMouseLeave={e => e.currentTarget.style.borderColor = "var(--line)"}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
              <div title={piece.reason} style={{
                width: 40, height: 40, borderRadius: 9,
                background: "var(--bg-2)",
                border: "1px solid var(--line)",
                display: "grid", placeItems: "center",
                color: trustColor, flexShrink: 0,
              }}>
                <ChessPiece kind={piece.kind} color="white" size={26}/>
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13.5, fontWeight: 600 }}>{s.name}</div>
                <div style={{ fontSize: 10.5, color: "var(--ink-3)", fontFamily: "var(--font-mono)" }}>{s.client}</div>
              </div>
              <Badge color={trustColor}>{s.trust}</Badge>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 12, fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--ink-2)", marginBottom: 12 }}>
              <span><span style={{ color: "var(--ink-3)" }}>events </span>{s.events}</span>
              <span><span style={{ color: "var(--ink-3)" }}>anomaly </span><span style={{ color: s.anomaly > 0.6 ? "var(--red)" : s.anomaly > 0.3 ? "var(--amber)" : "var(--green)" }}>{s.anomaly.toFixed(2)}</span></span>
              <span style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 6 }}>
                <Dot color={s.wrapped ? "var(--green)" : "var(--red)"} size={6}/>
                {s.wrapped ? "wrapped" : "exposed"}
              </span>
            </div>
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
              {s.capabilities.map(c => (
                <span key={c} className="mono" style={{ fontSize: 10, padding: "2px 6px", background: "var(--bg-2)", color: "var(--ink-2)", borderRadius: 3 }}>{c}</span>
              ))}
            </div>
          </button>
        );
      })}
    </div>
  </div>
);

Object.assign(window, { ScreenScan, ScreenAsk, ScreenTools });
