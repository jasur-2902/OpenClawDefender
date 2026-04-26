// AskRookDock — collapsed input pill that expands into a chat sheet.
// Quiet on Home; gently present without being the main thing.

const SAMPLE_REPLIES = {
  default: "I checked your last hour of activity — nothing unusual. 8,412 events across 5 wrapped apps; 11 things blocked. Want me to look further back, or focus on a specific app?",
  alert: "shell-runner tried to reach paste.evil-c2.example, which matches a known threat list. I blocked it before the connection completed. The app is still running but isolated. Want me to stop it entirely?",
  filemanager: "FileManager MCP read ~/.ssh/config — it has never touched that file in 30 days. It's not blocked yet. I'd recommend revoking its filesystem scope outside ~/Documents. Apply that change?",
  scan: "I can run a Standard scan (~30 sec, 5 stages) or Deep scan (~3 min, includes behavioral baseline). Standard is enough for daily checkups.",
};

const matchReply = (text) => {
  const t = text.toLowerCase();
  if (t.includes("alert") || t.includes("c2") || t.includes("shell")) return SAMPLE_REPLIES.alert;
  if (t.includes("filemanager") || t.includes("ssh")) return SAMPLE_REPLIES.filemanager;
  if (t.includes("scan") || t.includes("check")) return SAMPLE_REPLIES.scan;
  return SAMPLE_REPLIES.default;
};

const SUGGESTIONS = [
  "What happened today?",
  "Should I worry about FileManager?",
  "Run a quick checkup",
];

const AskRookDock = ({ onOpenFull }) => {
  const [open, setOpen] = React.useState(false);
  const [input, setInput] = React.useState("");
  const [messages, setMessages] = React.useState([]);
  const [thinking, setThinking] = React.useState(false);
  const inputRef = React.useRef(null);
  const scrollRef = React.useRef(null);

  // Focus input when sheet opens
  React.useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 220);
  }, [open]);

  // Esc to close
  React.useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape" && open) setOpen(false); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  // Scroll on new message
  React.useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, thinking]);

  const send = (text) => {
    const t = (text ?? input).trim();
    if (!t) return;
    setMessages(prev => [...prev, { role: "user", text: t }]);
    setInput("");
    setThinking(true);
    setTimeout(() => {
      setMessages(prev => [...prev, { role: "assistant", text: matchReply(t) }]);
      setThinking(false);
    }, 900);
  };

  return (
    <>
      {/* Collapsed dock — anchored at the bottom of Home, gentle presence */}
      <div style={{
        position: "sticky", bottom: 0, left: 0, right: 0,
        padding: "16px 0 24px",
        background: "linear-gradient(to bottom, transparent, var(--bg-0) 30%)",
        pointerEvents: "none",
        zIndex: 5,
      }}>
        <button onClick={() => setOpen(true)} style={{
          width: "100%", display: "flex", alignItems: "center", gap: 12,
          padding: "12px 16px", textAlign: "left",
          background: "var(--bg-1)",
          border: "1px solid var(--line)",
          borderRadius: 999,
          boxShadow: "0 4px 16px oklch(0 0 0 / 0.06), 0 1px 2px oklch(0 0 0 / 0.04)",
          cursor: "pointer",
          pointerEvents: "auto",
          transition: "transform 0.12s ease, box-shadow 0.12s ease",
        }}
          onMouseEnter={e => { e.currentTarget.style.boxShadow = "0 6px 20px oklch(0 0 0 / 0.10), 0 1px 2px oklch(0 0 0 / 0.06)"; }}
          onMouseLeave={e => { e.currentTarget.style.boxShadow = "0 4px 16px oklch(0 0 0 / 0.06), 0 1px 2px oklch(0 0 0 / 0.04)"; }}
        >
          <div style={{
            width: 26, height: 26, borderRadius: 7,
            background: "var(--accent-soft)",
            display: "grid", placeItems: "center", flexShrink: 0,
          }}>
            <Icon name="chat" size={14} color="var(--accent)"/>
          </div>
          <span style={{ flex: 1, fontSize: 14, color: "var(--ink-2)" }}>Ask Rook anything…</span>
          <kbd style={{
            fontSize: 10, color: "var(--ink-3)",
            padding: "2px 6px", borderRadius: 4,
            background: "var(--bg-2)", border: "1px solid var(--line)",
            fontFamily: "var(--font-ui)",
          }}>⌘K</kbd>
        </button>
      </div>

      {/* Expanded sheet */}
      {open && (
        <>
          {/* Backdrop */}
          <div onClick={() => setOpen(false)} style={{
            position: "fixed", inset: 0, zIndex: 100,
            background: "oklch(0 0 0 / 0.18)",
            animation: "cdFadeIn 0.18s ease",
          }}/>

          {/* Sheet */}
          <div className="cd-sheet-in" style={{
            position: "fixed", left: "50%", bottom: 24,
            transform: "translateX(-50%)",
            width: "min(640px, calc(100vw - 32px))",
            maxHeight: "min(620px, calc(100vh - 80px))",
            background: "var(--bg-1)",
            border: "1px solid oklch(0 0 0 / 0.08)",
            borderRadius: 16,
            boxShadow: "0 24px 64px oklch(0 0 0 / 0.20), 0 4px 12px oklch(0 0 0 / 0.08)",
            zIndex: 101,
            display: "flex", flexDirection: "column",
            overflow: "hidden",
          }}>
            {/* Header */}
            <div style={{
              padding: "12px 16px",
              borderBottom: "1px solid var(--line-soft)",
              display: "flex", alignItems: "center", gap: 10,
            }}>
              <div style={{
                width: 26, height: 26, borderRadius: 7,
                background: "var(--accent)",
                display: "grid", placeItems: "center",
              }}>
                <Rook size={13} color="white"/>
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 13.5, fontWeight: 600, color: "var(--ink-0)" }}>Ask Rook</div>
                <div style={{ fontSize: 11.5, color: "var(--ink-3)" }}>
                  Local model · Claude when needed
                </div>
              </div>
              <button onClick={() => { setOpen(false); onOpenFull?.(); }} style={{
                fontSize: 12, color: "var(--ink-2)",
                padding: "4px 10px", borderRadius: 6,
              }}
                onMouseEnter={e => e.currentTarget.style.background = "var(--bg-2)"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
              >Open full chat</button>
              <button onClick={() => setOpen(false)} style={{
                width: 24, height: 24, borderRadius: 6,
                display: "grid", placeItems: "center", color: "var(--ink-2)",
              }}
                onMouseEnter={e => e.currentTarget.style.background = "var(--bg-2)"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
              ><Icon name="x" size={14}/></button>
            </div>

            {/* Body */}
            <div ref={scrollRef} className="cd-scroll" style={{
              flex: 1, minHeight: 280, maxHeight: 460,
              overflowY: "auto", padding: "20px 16px",
            }}>
              {messages.length === 0 ? (
                <div style={{ padding: "8px 4px" }}>
                  <div style={{ fontSize: 13, color: "var(--ink-2)", marginBottom: 14, lineHeight: 1.5 }}>
                    Ask anything about your apps' activity. Rook can investigate, explain, or change settings on your behalf.
                  </div>
                  <div style={{ display: "grid", gap: 6 }}>
                    {SUGGESTIONS.map(s => (
                      <button key={s} onClick={() => send(s)} style={{
                        textAlign: "left", padding: "10px 12px",
                        fontSize: 13, color: "var(--ink-0)",
                        background: "var(--bg-2)",
                        border: "1px solid var(--line-soft)",
                        borderRadius: 9,
                      }}
                        onMouseEnter={e => { e.currentTarget.style.background = "var(--accent-soft)"; e.currentTarget.style.borderColor = "var(--accent-line)"; }}
                        onMouseLeave={e => { e.currentTarget.style.background = "var(--bg-2)"; e.currentTarget.style.borderColor = "var(--line-soft)"; }}
                      >{s}</button>
                    ))}
                  </div>
                </div>
              ) : (
                <div style={{ display: "grid", gap: 14 }}>
                  {messages.map((m, i) => (
                    m.role === "user" ? (
                      <div key={i} style={{ display: "flex", justifyContent: "flex-end" }}>
                        <div style={{
                          maxWidth: "78%",
                          padding: "8px 13px",
                          background: "var(--accent)", color: "white",
                          borderRadius: 16, borderBottomRightRadius: 4,
                          fontSize: 13.5, lineHeight: 1.45,
                        }}>{m.text}</div>
                      </div>
                    ) : (
                      <div key={i} style={{ display: "flex", gap: 8 }}>
                        <div style={{
                          width: 22, height: 22, borderRadius: 6,
                          background: "var(--accent)",
                          display: "grid", placeItems: "center", flexShrink: 0, marginTop: 1,
                        }}>
                          <Rook size={11} color="white"/>
                        </div>
                        <div style={{
                          maxWidth: "82%",
                          padding: "8px 13px",
                          background: "var(--bg-2)", color: "var(--ink-0)",
                          borderRadius: 16, borderBottomLeftRadius: 4,
                          fontSize: 13.5, lineHeight: 1.5,
                        }}>{m.text}</div>
                      </div>
                    )
                  ))}
                  {thinking && (
                    <div style={{ display: "flex", gap: 8 }}>
                      <div style={{
                        width: 22, height: 22, borderRadius: 6,
                        background: "var(--accent)",
                        display: "grid", placeItems: "center", flexShrink: 0, marginTop: 1,
                      }}>
                        <Rook size={11} color="white"/>
                      </div>
                      <div style={{
                        padding: "10px 13px", background: "var(--bg-2)",
                        borderRadius: 16, borderBottomLeftRadius: 4,
                        display: "flex", gap: 4,
                      }}>
                        {[0,1,2].map(i => (
                          <span key={i} className="cd-typing-dot" style={{
                            width: 6, height: 6, borderRadius: 999,
                            background: "var(--ink-3)",
                            animationDelay: `${i * 0.15}s`,
                          }}/>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Composer */}
            <div style={{
              padding: 12, borderTop: "1px solid var(--line-soft)",
              background: "var(--bg-1)",
            }}>
              <div style={{
                display: "flex", alignItems: "flex-end", gap: 8,
                background: "var(--bg-2)",
                border: "1px solid var(--line)",
                borderRadius: 12,
                padding: "6px 6px 6px 12px",
              }}>
                <textarea
                  ref={inputRef}
                  value={input}
                  onChange={e => setInput(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === "Enter" && !e.shiftKey) {
                      e.preventDefault();
                      send();
                    }
                  }}
                  rows={1}
                  placeholder="Ask Rook anything…"
                  style={{
                    flex: 1, background: "transparent", border: "none",
                    fontSize: 14, color: "var(--ink-0)", outline: "none",
                    resize: "none", padding: "8px 0", lineHeight: 1.4,
                    fontFamily: "var(--font-ui)",
                    maxHeight: 120,
                  }}
                />
                <button onClick={() => send()} disabled={!input.trim()} style={{
                  width: 30, height: 30, borderRadius: 8,
                  background: input.trim() ? "var(--accent)" : "var(--bg-3)",
                  color: "white", display: "grid", placeItems: "center",
                  cursor: input.trim() ? "pointer" : "default",
                  transition: "background 0.15s",
                }}>
                  <Icon name="send" size={14} color="white"/>
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </>
  );
};

Object.assign(window, { AskRookDock });
