// Realistic ClawDefender event data — pulled from the OpenClawDefender repo vocabulary.
// FirewallEvent → ProcessEvent / NetworkEvent / DnsEvent.

window.CD = window.CD || {};

CD.servers = [
  { id: "claude-desktop", name: "Claude Desktop", client: "claude.app", trust: "trusted", events: 412, anomaly: 0.08, wrapped: true, capabilities: ["filesystem", "shell", "network"] },
  { id: "cursor", name: "Cursor IDE", client: "cursor.app", trust: "trusted", events: 1284, anomaly: 0.12, wrapped: true, capabilities: ["filesystem", "git", "shell"] },
  { id: "filemanager-mcp", name: "FileManager MCP", client: "claude.app", trust: "watching", events: 89, anomaly: 0.62, wrapped: true, capabilities: ["filesystem", "metadata"] },
  { id: "github-mcp", name: "GitHub MCP", client: "cursor.app", trust: "trusted", events: 233, anomaly: 0.18, wrapped: true, capabilities: ["api:github", "network"] },
  { id: "shell-runner", name: "shell-runner", client: "vscode.app", trust: "untrusted", events: 14, anomaly: 0.84, wrapped: false, capabilities: ["shell", "process"] },
  { id: "postgres-mcp", name: "Postgres MCP", client: "cursor.app", trust: "trusted", events: 67, anomaly: 0.21, wrapped: true, capabilities: ["network", "db"] },
];

CD.classifications = {
  routine: { label: "routine", color: "var(--green)", soft: "var(--green-soft)" },
  notable: { label: "notable", color: "var(--amber)", soft: "var(--amber-soft)" },
  suspicious: { label: "suspicious", color: "var(--red)", soft: "var(--red-soft)" },
};

// Events modeled directly on FirewallEvent / ProcessEvent / NetworkEvent / DnsEvent
CD.events = [
  { id: "ev_8821", t: 2, kind: "process", hook: "sys_enter_execve", pid: 49213, uid: 501, comm: "node", path: "/usr/local/bin/node", cwd: "/Users/jay/work/api", server: "cursor", action: "execve", target: "/usr/local/bin/node", verdict: "ALLOW", classification: "routine", reason: "Known-safe binary path; matches developer baseline." },
  { id: "ev_8820", t: 6, kind: "network", hook: "tcp_v4_connect", pid: 49213, src: "192.168.1.42", dst: "140.82.114.4", port: 443, host: "api.github.com", server: "github-mcp", action: "tcp_v4_connect", target: "140.82.114.4:443", verdict: "ALLOW", classification: "routine", reason: "Known endpoint; recurring pattern for this server." },
  { id: "ev_8819", t: 14, kind: "dns", hook: "udp_sendmsg", pid: 49213, dst: "8.8.8.8", port: 53, domain: "api.github.com", server: "github-mcp", action: "dns_query", target: "api.github.com", verdict: "ALLOW", classification: "routine" },
  { id: "ev_8818", t: 22, kind: "process", hook: "sys_enter_execve", pid: 50331, uid: 501, comm: "python3", path: "/Users/jay/.venv/bin/python3", cwd: "/Users/jay/work/api", server: "claude-desktop", action: "execve", target: "/Users/jay/.venv/bin/python3", verdict: "ALLOW", classification: "routine" },
  { id: "ev_8817", t: 38, kind: "process", hook: "sys_enter_execve", pid: 50412, uid: 501, comm: "cat", path: "/bin/cat", cwd: "/Users/jay", server: "filemanager-mcp", action: "read_file", target: "~/.ssh/config", verdict: "ALLOW", classification: "notable", reason: "First time this server has accessed ~/.ssh — flagged for review." },
  { id: "ev_8816", t: 51, kind: "network", hook: "tcp_v4_connect", pid: 50421, src: "192.168.1.42", dst: "185.220.101.34", port: 443, host: "exit-relay-tor.example", server: "shell-runner", action: "tcp_v4_connect", target: "185.220.101.34:443", verdict: "BLOCK", classification: "suspicious", reason: "Destination matches known Tor exit relay IoC. Connection denied at kernel via FNV-1a blocklist." },
  { id: "ev_8815", t: 64, kind: "process", hook: "sys_enter_execve", pid: 50445, uid: 501, comm: "curl", path: "/usr/bin/curl", cwd: "/tmp", server: "shell-runner", action: "execve", target: "/usr/bin/curl", verdict: "ALLOW", classification: "notable", reason: "shell-runner spawning curl from /tmp — new for this server in last 30 days." },
  { id: "ev_8814", t: 72, kind: "dns", hook: "udp_sendmsg", pid: 50445, dst: "1.1.1.1", port: 53, domain: "paste.evil-c2.example", server: "shell-runner", action: "dns_query", target: "paste.evil-c2.example", verdict: "BLOCK", classification: "suspicious", reason: "Domain on threat intel feed (C2 infrastructure)." },
  { id: "ev_8813", t: 84, kind: "process", hook: "sys_enter_execve", pid: 50500, uid: 501, comm: "git", path: "/usr/bin/git", cwd: "/Users/jay/work/api", server: "cursor", action: "execve", target: "git fetch origin", verdict: "ALLOW", classification: "routine" },
  { id: "ev_8812", t: 95, kind: "network", hook: "tcp_v4_connect", pid: 50500, src: "192.168.1.42", dst: "140.82.121.6", port: 22, host: "ssh.github.com", server: "cursor", action: "tcp_v4_connect", target: "ssh.github.com:22", verdict: "ALLOW", classification: "routine" },
  { id: "ev_8811", t: 112, kind: "process", hook: "sys_enter_execve", pid: 50612, uid: 501, comm: "psql", path: "/opt/homebrew/bin/psql", cwd: "/Users/jay/work/api", server: "postgres-mcp", action: "execve", target: "psql -h db.internal", verdict: "ALLOW", classification: "routine" },
  { id: "ev_8810", t: 130, kind: "dns", hook: "udp_sendmsg", pid: 50612, dst: "8.8.8.8", port: 53, domain: "db.internal", server: "postgres-mcp", action: "dns_query", target: "db.internal", verdict: "ALLOW", classification: "routine" },
  { id: "ev_8809", t: 156, kind: "process", hook: "sys_enter_execve", pid: 50721, uid: 501, comm: "bash", path: "/bin/bash", cwd: "/tmp", server: "shell-runner", action: "execve", target: "bash -c 'curl … | sh'", verdict: "BLOCK", classification: "suspicious", reason: "Pattern matches `curl | sh` exec — classic dropper. Kill chain stage: initial access." },
  { id: "ev_8808", t: 188, kind: "network", hook: "tcp_v4_connect", pid: 49213, src: "192.168.1.42", dst: "104.16.85.20", port: 443, host: "registry.npmjs.org", server: "cursor", action: "tcp_v4_connect", target: "registry.npmjs.org:443", verdict: "ALLOW", classification: "routine" },
];

CD.alerts = [
  {
    id: "alrt_201",
    severity: "critical",
    title: "Possible C2 beacon — shell-runner",
    summary: "shell-runner attempted to resolve a domain on the threat intel feed and connect to a Tor exit relay within 12 seconds.",
    server: "shell-runner",
    eventCount: 3,
    eventIds: ["ev_8809", "ev_8814", "ev_8816"],
    createdAt: "2 min ago",
    status: "new",
    killChain: [
      { stage: "Initial Access", label: "execve `curl … | sh`", id: "ev_8809", t: "T+0s" },
      { stage: "Discovery", label: "dns_query paste.evil-c2.example", id: "ev_8814", t: "T+8s" },
      { stage: "C2", label: "tcp_v4_connect 185.220.101.34:443", id: "ev_8816", t: "T+12s" },
    ],
    intel: "Cloud (Claude) verdict: BLOCK — confidence 0.94. Domain matches dofloo botnet pattern; destination IP overlaps with TA0011 indicators. Recommend isolating shell-runner and rotating any credentials it could read."
  },
  {
    id: "alrt_200",
    severity: "high",
    title: "First-time SSH config read by FileManager MCP",
    summary: "FileManager MCP read ~/.ssh/config — has never accessed this directory in 30-day baseline.",
    server: "filemanager-mcp",
    eventCount: 1,
    eventIds: ["ev_8817"],
    createdAt: "8 min ago",
    status: "investigating",
  },
  {
    id: "alrt_199",
    severity: "medium",
    title: "Unexpected curl spawn from /tmp",
    summary: "shell-runner executed /usr/bin/curl with cwd=/tmp — unusual for this server.",
    server: "shell-runner",
    eventCount: 1,
    eventIds: ["ev_8815"],
    createdAt: "12 min ago",
    status: "new",
  },
  {
    id: "alrt_198",
    severity: "low",
    title: "Anomaly score elevated — Cursor IDE",
    summary: "Anomaly score 0.42 (baseline 0.18). Cursor opened 3× usual file count this hour.",
    server: "cursor",
    eventCount: 7,
    eventIds: [],
    createdAt: "47 min ago",
    status: "acknowledged",
  },
];

CD.severityColor = (s) => ({
  critical: "var(--red)",
  high: "var(--red)",
  medium: "var(--amber)",
  low: "var(--amber)",
  info: "var(--ink-2)",
}[s] || "var(--ink-2)");

CD.posture = {
  level: "elevated",
  reason: "shell-runner triggered 1 critical alert (C2 beacon) in last 5 minutes."
};

CD.aiStatus = {
  local: { model: "Qwen3 1.7B", status: "active", tps: 187, vram: "1.4 GB", quant: "Q4_K_M" },
  cloud: { provider: "Anthropic", model: "Claude Sonnet 4.5", status: "active", budget: 12.40, budgetCap: 20.0 },
};

CD.scanStages = [
  { id: 0, name: "Inventory", status: "done", findings: 0, ms: 1240 },
  { id: 1, name: "Configuration Analysis", status: "done", findings: 3, ms: 4810 },
  { id: 2, name: "Network Posture", status: "running", findings: 1, ms: null },
  { id: 3, name: "Behavioral Anomalies", status: "pending", findings: null, ms: null },
  { id: 4, name: "Verdict", status: "pending", findings: null, ms: null },
];

CD.scanFindings = [
  { id: "f1", severity: "high", title: "shell-runner has CAP_NET_RAW", evidence: "Capabilities granted at wrap time; not required by manifest.", fix: "Drop CAP_NET_RAW" },
  { id: "f2", severity: "medium", title: "DNS server 8.8.8.8 hardcoded in 3 servers", evidence: "Bypasses local resolver policy.", fix: "Route via /etc/resolv.conf" },
  { id: "f3", severity: "medium", title: "FileManager MCP can read entire $HOME", evidence: "Wrap policy allows /Users/jay/**.", fix: "Scope to ~/Documents/**" },
  { id: "f4", severity: "low", title: "Threat intel feed 4 hours stale", evidence: "Last refresh: 04:12 UTC.", fix: "Refresh now" },
];

CD.chatHistory = [
  { id: "c3", title: "shell-runner C2 beacon", at: "2m ago" },
  { id: "c2", title: "Why was psql allowed?", at: "1h ago" },
  { id: "c1", title: "Tighten policy for travel", at: "Yesterday" },
];

CD.transparency = {
  costThisMonth: 12.40,
  budget: 20.0,
  triageAccuracy: 0.962,
  alertRelevance: 0.83,
  investigationHit: 0.78,
  acceptance: 0.71,
  costSeries: [0.4, 0.6, 0.5, 0.9, 1.2, 1.0, 1.4, 1.3, 0.8, 0.7, 1.1, 1.6, 1.0, 0.9],
};

// Helpers
CD.fmtTime = (sec) => {
  if (sec < 60) return `${sec}s ago`;
  const m = Math.floor(sec / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return `${h}h ago`;
};

CD.serverById = (id) => CD.servers.find(s => s.id === id);
CD.eventById = (id) => CD.events.find(e => e.id === id);
