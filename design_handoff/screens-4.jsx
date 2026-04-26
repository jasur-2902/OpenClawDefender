// ClawDefender — Settings, Transparency, Onboarding (rebalanced)

const ScreenSettings = () => {
  const [activeModel, setActiveModel] = React.useState("Qwen3 1.7B");
  const models = [
    { name: "Qwen3 1.7B", size: "1.1 GB", ram: "1.4 GB", status: "active", recommended: true },
    { name: "Qwen3 4B", size: "2.4 GB", ram: "3.2 GB", status: "downloaded" },
    { name: "Gemma3 1B", size: "0.8 GB", ram: "1.0 GB", status: "downloaded" },
    { name: "Gemma3 4B", size: "2.6 GB", ram: "3.4 GB", status: "available" },
  ];

  return (
    <div className="cd-scroll" style={{ padding: 24, maxWidth: 1080, margin: "0 auto", overflowY: "auto", height: "100%" }}>
      <SectionTitle sub="Local SLM handles 95% of triage on-device. Cloud is opt-in for deep investigations.">AI Analysis</SectionTitle>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        {/* Local */}
        <Card title="Local model" action={<Badge color="var(--green)" mono><Dot color="var(--green)" size={5} pulse style={{ marginRight: 4 }}/>active</Badge>}>
          <div style={{ padding: 12, background: "var(--bg-2)", borderRadius: 8, marginBottom: 14, display: "flex", alignItems: "center", gap: 10 }}>
            <Icon name="cpu" size={16} color="var(--accent)"/>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>{activeModel}</div>
              <div style={{ fontSize: 10.5, color: "var(--ink-3)", fontFamily: "var(--font-mono)", marginTop: 2 }}>187 tok/s · loaded 4h 12m · M3 Max Metal</div>
            </div>
          </div>
          <div style={{ display: "grid", gap: 6 }}>
            {models.map(m => (
              <div key={m.name} style={{
                padding: "9px 10px", borderRadius: 8,
                background: m.name === activeModel ? "var(--accent-soft)" : "transparent",
                border: "1px solid " + (m.name === activeModel ? "var(--accent-line)" : "var(--line-soft)"),
                display: "flex", alignItems: "center", gap: 10,
              }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12, fontWeight: 500, display: "flex", alignItems: "center", gap: 6 }}>
                    {m.name}
                    {m.recommended && <Badge color="var(--accent)">recommended</Badge>}
                  </div>
                  <div style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--ink-3)", marginTop: 2 }}>{m.size} · {m.ram} RAM</div>
                </div>
                {m.name === activeModel ? <Badge color="var(--accent)">active</Badge> :
                 m.status === "downloaded" ? <Btn size="sm" kind="soft" onClick={() => setActiveModel(m.name)}>Activate</Btn> :
                 <Btn size="sm" kind="ghost" icon="download">Get</Btn>}
              </div>
            ))}
          </div>
        </Card>

        {/* Cloud */}
        <Card title="Cloud reasoning" action={<Badge color="var(--violet)" mono><Dot color="var(--green)" size={5} pulse style={{ marginRight: 4 }}/>connected</Badge>}>
          <div style={{ display: "grid", gap: 12 }}>
            <Field label="Model">
              <select style={{ width: "100%", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 6, padding: "8px 10px", fontSize: 12, color: "var(--ink-0)", outline: "none" }}>
                <option>Claude Sonnet 4.5</option>
                <option>Claude Opus 4</option>
                <option>Claude Haiku 4.5</option>
              </select>
            </Field>
            <Field label="Monthly budget">
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <input type="range" min="5" max="100" defaultValue="20" style={{ flex: 1, accentColor: "var(--accent)" }}/>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--ink-1)", width: 50 }}>$20</span>
              </div>
              <div style={{ fontSize: 10.5, color: "var(--ink-3)", marginTop: 4, fontFamily: "var(--font-mono)" }}>used: $12.40 · projected: $17.80</div>
            </Field>
            <Field label="API key">
              <input type="password" defaultValue="sk-ant-XXXXXXXXXXXXXXXXXXXXXXXX" style={{ width: "100%", boxSizing: "border-box", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 6, padding: "8px 10px", fontSize: 12, fontFamily: "var(--font-mono)", color: "var(--ink-0)", outline: "none" }}/>
            </Field>
          </div>
        </Card>
      </div>

      <Card title="How they work together" style={{ marginTop: 14 }}>
        <div style={{ fontSize: 12.5, color: "var(--ink-1)", lineHeight: 1.65 }}>
          Every event flows first into <span className="mono" style={{ color: "var(--accent)" }}>{activeModel}</span> for triage.
          Anything <span style={{ color: "var(--red)" }}>suspicious</span> auto-escalates to <span className="mono" style={{ color: "var(--violet)" }}>Claude</span> with correlated context.
          You always see which brain answered.
        </div>
      </Card>
    </div>
  );
};

const Field = ({ label, children }) => (
  <div>
    <div style={{ fontSize: 10.5, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 6 }}>{label}</div>
    {children}
  </div>
);

const ScreenTransparency = () => {
  const t = CD.transparency;
  return (
    <div className="cd-scroll" style={{ padding: 24, maxWidth: 1080, margin: "0 auto", overflowY: "auto", height: "100%" }}>
      <SectionTitle sub="What the agent has done, why, and how often it's been right.">Agent transparency</SectionTitle>

      {/* Hero metrics — kept 4 but tighter */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 14 }}>
        {[
          { k: "Triage accuracy", v: (t.triageAccuracy * 100).toFixed(1) + "%", c: "var(--green)" },
          { k: "Alert relevance", v: (t.alertRelevance * 100).toFixed(0) + "%", c: "var(--accent)" },
          { k: "Investigation hit", v: (t.investigationHit * 100).toFixed(0) + "%", c: "var(--accent)" },
          { k: "Suggestion accept", v: (t.acceptance * 100).toFixed(0) + "%", c: "var(--violet)" },
        ].map(s => (
          <div key={s.k} style={{ padding: 14, background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: 12 }}>
            <div style={{ fontSize: 10.5, color: "var(--ink-3)", textTransform: "uppercase", letterSpacing: 0.5 }}>{s.k}</div>
            <div style={{ fontSize: 22, fontWeight: 600, fontFamily: "var(--font-mono)", color: s.c, marginTop: 6, lineHeight: 1 }}>{s.v}</div>
          </div>
        ))}
      </div>

      <Card title="Cloud cost · last 14 days" action={<span style={{ fontSize: 11.5, color: "var(--ink-2)", fontFamily: "var(--font-mono)" }}>${t.costThisMonth.toFixed(2)} / ${t.budget.toFixed(2)}</span>} style={{ marginBottom: 14 }}>
        <Sparkline data={t.costSeries} color="var(--violet)" width={1000} height={80} fill/>
      </Card>

      <Card title="Recent agent actions" padded={false}>
        {[
          { t: "14:32:18", a: "BLOCK 185.220.101.34 inserted into eBPF BLOCKLIST", w: "Cloud verdict conf 0.94", icon: "lock", c: "var(--red)" },
          { t: "14:32:14", a: "Escalated ev_8816 to Cloud", w: "Local SLM classified suspicious", icon: "cloud", c: "var(--violet)" },
          { t: "14:18:02", a: "User accepted scope reduction for FileManager MCP", w: "Suggestion accepted in 4 min", icon: "check", c: "var(--green)" },
          { t: "13:55:41", a: "Hourly sweep complete", w: "127 events analyzed, all routine or notable", icon: "refresh", c: "var(--accent)" },
        ].map((e, i) => (
          <div key={i} style={{ padding: "12px 16px", display: "flex", gap: 12, borderBottom: i < 3 ? "1px solid var(--line-soft)" : "none", alignItems: "center" }}>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--ink-3)", width: 56 }}>{e.t}</span>
            <Icon name={e.icon} size={14} color={e.c}/>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 12.5, color: "var(--ink-0)" }}>{e.a}</div>
              <div style={{ fontSize: 11, color: "var(--ink-2)", marginTop: 2 }}>{e.w}</div>
            </div>
          </div>
        ))}
      </Card>
    </div>
  );
};

const ScreenOnboarding = ({ onDone }) => {
  const [step, setStep] = React.useState(0);
  const steps = [
    { t: "Welcome to ClawDefender", d: "An AI-powered firewall that watches what your AI tools do — at the kernel level." },
    { t: "Grant kernel access", d: "ClawDefender attaches eBPF probes to monitor process, network, and DNS activity." },
    { t: "Pick a local model", d: "Runs on your machine. Triages events in ~400 ms each. We recommend Qwen3 1.7B." },
    { t: "Connect a cloud brain", d: "Optional. Used for escalations. Capped at $20/month by default." },
    { t: "Wrap your AI tools", d: "We found 3 MCP servers. Wrap them to start monitoring tool calls." },
  ];
  const s = steps[step];

  return (
    <div style={{ display: "grid", placeItems: "center", height: "100%", padding: 32 }}>
      <div style={{ width: "100%", maxWidth: 560, background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: "var(--radius-xl)", overflow: "hidden", boxShadow: "var(--shadow-lg)" }}>
        <div style={{ padding: "16px 24px", display: "flex", alignItems: "center", gap: 8, borderBottom: "1px solid var(--line-soft)" }}>
          {steps.map((_, i) => (
            <div key={i} style={{ flex: 1, height: 3, borderRadius: 2, background: i <= step ? "var(--accent)" : "var(--bg-3)", transition: "background 0.3s" }}/>
          ))}
          <span style={{ fontSize: 10.5, fontFamily: "var(--font-mono)", color: "var(--ink-3)", marginLeft: 8 }}>{step + 1} / {steps.length}</span>
        </div>

        <div style={{ padding: "32px 28px", textAlign: "center" }}>
          <div style={{ width: 56, height: 56, borderRadius: 14, background: "var(--accent-soft)", border: "1px solid var(--accent-line)", display: "grid", placeItems: "center", margin: "0 auto 18px" }}>
            <Rook size={28} color="var(--accent)"/>
          </div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 600, letterSpacing: -0.3 }}>{s.t}</h1>
          <p style={{ margin: "10px auto 0", fontSize: 13.5, color: "var(--ink-2)", lineHeight: 1.6, maxWidth: 420 }}>{s.d}</p>

          {step === 4 && (
            <div style={{ marginTop: 22, textAlign: "left", display: "grid", gap: 8 }}>
              {CD.servers.slice(0, 3).map(s => (
                <div key={s.id} style={{ padding: "10px 14px", background: "var(--bg-2)", borderRadius: 8, display: "flex", alignItems: "center", gap: 10 }}>
                  <Icon name="tools" size={14} color="var(--ink-1)"/>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 12.5 }}>{s.name}</div>
                    <div style={{ fontSize: 10.5, color: "var(--ink-3)", fontFamily: "var(--font-mono)" }}>{s.client}</div>
                  </div>
                  <input type="checkbox" defaultChecked style={{ accentColor: "var(--accent)" }}/>
                </div>
              ))}
            </div>
          )}
        </div>

        <div style={{ padding: "16px 24px", borderTop: "1px solid var(--line-soft)", display: "flex", gap: 8 }}>
          {step > 0 && <Btn kind="ghost" onClick={() => setStep(step - 1)}>Back</Btn>}
          <span style={{ flex: 1 }}/>
          {step < steps.length - 1 ? (
            <Btn kind="primary" onClick={() => setStep(step + 1)}>Continue</Btn>
          ) : (
            <Btn kind="primary" icon="check" onClick={onDone}>Start protecting</Btn>
          )}
        </div>
      </div>
    </div>
  );
};

Object.assign(window, { ScreenSettings, ScreenTransparency, ScreenOnboarding, Field });
