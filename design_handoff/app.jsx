// ClawDefender — Main app entry. Wires routing, sidebar, screens, tweaks.

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "accent_hue": 245,
  "density": "comfortable",
  "show_sidebar_labels": true,
  "live_animation": true,
  "monospace_data": true
}/*EDITMODE-END*/;

const App = () => {
  const tweaks = useTweaks(TWEAK_DEFAULTS);
  const [route, setRoute] = React.useState({ name: "home" });
  const [collapsed, setCollapsed] = React.useState(false);
  const [trayOpen, setTrayOpen] = React.useState(false);
  const [posture, setPosture] = React.useState("elevated");
  const [liveMode, setLiveMode] = React.useState(true);
  const [filterMatter, setFilterMatter] = React.useState(false);
  const [filterKind, setFilterKind] = React.useState("all");
  const [filterServer, setFilterServer] = React.useState("all");
  const [events, setEvents] = React.useState(CD.events);

  // Apply hue
  React.useEffect(() => {
    const h = tweaks.accent_hue ?? 245;
    document.documentElement.style.setProperty("--accent-h", String(h));
  }, [tweaks.accent_hue]);

  // Sidebar labels via tweak
  React.useEffect(() => {
    setCollapsed(!tweaks.show_sidebar_labels);
  }, [tweaks.show_sidebar_labels]);

  // Simulated live event stream — prepends a synthetic event every few seconds
  React.useEffect(() => {
    if (!liveMode) return;
    const id = setInterval(() => {
      const seed = CD.events[Math.floor(Math.random() * CD.events.length)];
      const fresh = { ...seed, id: "ev_" + (8900 + Math.floor(Math.random() * 99)), t: 1 };
      setEvents(prev => [fresh, ...prev.slice(0, 60)]);
    }, 4200);
    return () => clearInterval(id);
  }, [liveMode]);

  const goto = (name, params) => setRoute({ name, ...params });

  const screen = (() => {
    switch (route.name) {
      case "home":
        return <ScreenHome goto={goto} onAlertClick={(id) => goto("alertDetail", { alertId: id })} onEventClick={(id) => goto("event", { eventId: id })} posture={posture} events={events}/>;
      case "activity":
        return <ScreenActivity onEventClick={(id) => goto("event", { eventId: id })}
          liveMode={liveMode} setLiveMode={setLiveMode}
          filterMatter={filterMatter} setFilterMatter={setFilterMatter}
          filterKind={filterKind} setFilterKind={setFilterKind}
          filterServer={filterServer} setFilterServer={setFilterServer}
          events={events}/>;
      case "event":
        return <ScreenEventDetail eventId={route.eventId} onBack={() => goto("activity")} onAlertClick={(id) => goto("alertDetail", { alertId: id })}/>;
      case "alerts":
        return <ScreenAlerts onAlertClick={(id) => goto("alertDetail", { alertId: id })}/>;
      case "alertDetail":
        return <ScreenAlertDetail alertId={route.alertId} onBack={() => goto("alerts")} onEventClick={(id) => goto("event", { eventId: id })}/>;
      case "scan": return <ScreenScan/>;
      case "ask": return <ScreenAsk/>;
      case "tools": return <ScreenTools onServerClick={() => {}}/>;
      case "settings": return <ScreenSettings/>;
      case "transparency": return <ScreenTransparency/>;
      case "onboarding": return <ScreenOnboarding onDone={() => goto("home")}/>;
      default: return null;
    }
  })();

  const navCurrent = ["event"].includes(route.name) ? "activity"
    : route.name === "alertDetail" ? "alerts"
    : route.name;

  return (
    <div className={"cd-app" + (collapsed ? " collapsed" : "")}>
      <Sidebar current={navCurrent} onNav={(n) => goto(n)} collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)}/>
      <div style={{ display: "grid", gridTemplateRows: "auto 1fr", overflow: "hidden", position: "relative" }}>
        <StatusHeader current={route.name} onTrayOpen={() => setTrayOpen(!trayOpen)} posture={posture}/>
        <main style={{ overflow: "auto", position: "relative" }} className="cd-scroll">
          {screen}
        </main>
        <TrayMenu open={trayOpen} onClose={() => setTrayOpen(false)} onNav={goto} posture={posture} setPosture={setPosture}/>
      </div>

      <TweaksPanel title="Tweaks" defaultPosition={{ right: 24, bottom: 24 }}>
        <TweakSection title="Accent">
          <TweakSlider label="Hue" value={tweaks.accent_hue} min={0} max={360} step={5} onChange={v => tweaks.set("accent_hue", v)} display={`${tweaks.accent_hue}°`}/>
          <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
            {[{n:"Cool blue",h:245},{n:"Violet",h:295},{n:"Teal",h:175},{n:"Amber",h:65},{n:"Magenta",h:330}].map(p => (
              <button key={p.n} onClick={() => tweaks.set("accent_hue", p.h)} title={p.n}
                style={{ flex: 1, height: 26, borderRadius: 6, background: `oklch(0.70 0.15 ${p.h})`,
                  border: tweaks.accent_hue === p.h ? "2px solid var(--ink-0)" : "1px solid var(--line-strong)" }}/>
            ))}
          </div>
        </TweakSection>
        <TweakSection title="Layout">
          <TweakToggle label="Sidebar labels" value={tweaks.show_sidebar_labels} onChange={v => tweaks.set("show_sidebar_labels", v)}/>
          <TweakToggle label="Live animations" value={tweaks.live_animation} onChange={v => tweaks.set("live_animation", v)}/>
        </TweakSection>
        <TweakSection title="Demo">
          <TweakButton label="Show onboarding" onClick={() => goto("onboarding")}/>
          <TweakButton label="Cycle posture" onClick={() => {
            const order = ["low","normal","elevated","high","critical"];
            setPosture(order[(order.indexOf(posture) + 1) % order.length]);
          }}/>
        </TweakSection>
      </TweaksPanel>
    </div>
  );
};

ReactDOM.createRoot(document.getElementById("root")).render(<App/>);
