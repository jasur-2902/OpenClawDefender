/**
 * RookBot Message Constants
 *
 * All user-facing strings live here. Never hardcode a user-facing string.
 * Import from this file instead.
 *
 * See docs/design/onboarding-copy.md and docs/design/runtime-messages.md
 * for the full message specifications.
 */

// ---------------------------------------------------------------------------
// Onboarding
// ---------------------------------------------------------------------------

export interface OnboardingScreen {
  readonly headline: string;
  readonly body: string;
  readonly cta: string;
}

export interface OnboardingVariant {
  readonly a: OnboardingScreen;
  readonly b: OnboardingScreen;
  readonly c: OnboardingScreen;
}

export const ONBOARDING_WELCOME: OnboardingVariant = {
  a: {
    headline: "Hey. I am Claw.",
    body: "I am your AI security companion. I sit between you and the AI tools you use every day -- watching the traffic, catching the threats, keeping your machine safe. Let me take a quick look at what you have running.",
    cta: "Scan My System",
  },
  b: {
    headline: "Hey. I am Claw -- nice to meet you.",
    body: "I watch over the AI tools on your machine and make sure they behave. Think of me as a security expert who lives in your menu bar. I will scan your system, set up protection, and stay out of your way. Ready?",
    cta: "Let's Go",
  },
  c: {
    headline: "Meet Claw.",
    body: "I keep your AI tools honest. Every request they make passes through me first -- if something looks wrong, I catch it before it reaches your system. Let me see what you are working with.",
    cta: "Get Started",
  },
} as const;

export const ONBOARDING_SCAN_RESULTS: OnboardingScreen = {
  headline: "Here is what I found.",
  body: "I scanned your system for AI tools. These are the ones I can protect.",
  cta: "Protect These",
} as const;

export const ONBOARDING_SCAN_EMPTY: OnboardingScreen = {
  headline: "I did not find any AI tools yet.",
  body: "That is fine -- you might not have any installed, or they might not be running yet. You can add them manually later from the dashboard, or run this scan again any time.",
  cta: "Continue Without Tools",
} as const;

export interface ProtectionLevelOption {
  readonly label: string;
  readonly quote: string;
  readonly subtitle: string;
}

export const ONBOARDING_PROTECTION_LEVELS: Record<
  "keepWatch" | "staySharp" | "lockItDown",
  ProtectionLevelOption
> = {
  keepWatch: {
    label: "Keep Watch",
    quote:
      "I will log everything and let you know if something looks off, but I will not block anything. You stay in full control.",
    subtitle:
      "Good for exploring -- see what your tools are doing before setting rules.",
  },
  staySharp: {
    label: "Stay Sharp",
    quote:
      "I will block anything dangerous and ask you about the rest. Most people start here -- it is the right balance of safety and flow.",
    subtitle:
      "Good for everyday work -- protection without constant interruptions.",
  },
  lockItDown: {
    label: "Lock It Down",
    quote:
      "Nothing gets through without your say-so. I will prompt you for every action. It is thorough, but expect more interruptions.",
    subtitle:
      "Good for sensitive projects -- maximum control over every action.",
  },
} as const;

export const ONBOARDING_COMPLETE = {
  headline: "You are all set.",
  restartReminder:
    "One thing -- restart any AI apps you have open so they route through me. I will be in your menu bar whenever you need me.",
  menuBarIntro:
    "Look for me in your menu bar. Green means everything is fine. If something needs your attention, I will let you know.",
  cta: "Open Dashboard",
} as const;

export const ONBOARDING_FDA = {
  whyItHelps:
    "Full Disk Access lets me read the config files for your AI tools, so I can find and protect them automatically.",
  whatIfSkip:
    "Without it, I can still protect servers you add manually -- I just will not be able to discover them on my own.",
  guidance:
    "Open System Settings, go to Privacy & Security, then Full Disk Access, and toggle RookBot on. I will wait here.",
} as const;

// ---------------------------------------------------------------------------
// Empty States
// ---------------------------------------------------------------------------

export interface EmptyState {
  readonly headline: string;
  readonly body: string;
  readonly cta?: string;
  readonly ctaSecondary?: string;
}

export const EMPTY_STATES: Record<string, EmptyState> = {
  dashboard: {
    headline: "All quiet so far.",
    body: "I am watching your AI tools. When they start making requests, you will see activity here -- events, stats, and anything that needs your attention.",
  },
  activity: {
    headline: "Nothing here yet.",
    body: "This is where you will see a live feed of every MCP request your AI tools make -- tool calls, file reads, network activity, and how I handled each one.",
  },
  alerts: {
    headline: "No threats detected.",
    body: "That is a good thing. When I spot something risky -- a suspicious tool call, unusual behavior, a blocked action -- it shows up here.",
  },
  myTools: {
    headline: "No servers connected.",
    body: "I protect AI tools by wrapping their MCP servers. Add a server from your MCP client config, or run a scan to find them automatically.",
    cta: "Scan for Tools",
    ctaSecondary: "Add Manually",
  },
  scanner: {
    headline: "No scans yet.",
    body: "The scanner checks your MCP server configs for misconfigurations, exposed credentials, and known vulnerabilities. Run your first scan to see where things stand.",
    cta: "Start Scan",
  },
  guards: {
    headline: "No guards active.",
    body: "Guards are automated protections that watch for specific threat patterns -- like prompt injection, credential exfiltration, or privilege escalation. They run in the background and act on your behalf when something matches. Enable them from the guard library.",
    cta: "Browse Guards",
  },
  searchResults: {
    headline: "Nothing matched your search.",
    body: "",
  },
  askClaw: {
    headline: "Hey. I'm Claw.",
    body: "Ask me anything about your security, or drag a file here for analysis.",
    cta: "Am I safe right now?",
    ctaSecondary: "What has Claw been doing today?",
  },
} as const;

// ---------------------------------------------------------------------------
// Protection Score
// ---------------------------------------------------------------------------

export interface ProtectionScoreLevel {
  readonly label: string;
  readonly description: string;
}

export const PROTECTION_SCORE_LEVELS: Record<string, ProtectionScoreLevel> = {
  full: {
    label: "Full",
    description: "Fully protected. Every layer is active and up to date.",
  },
  high: {
    label: "High",
    description:
      "Looking good. A few minor things could be tightened up.",
  },
  medium: {
    label: "Medium",
    description:
      "There are gaps in your protection. Worth addressing when you have a moment.",
  },
  low: {
    label: "Low",
    description:
      "Several protections are missing or inactive. I would recommend fixing these soon.",
  },
} as const;

export const PROTECTION_SCORE_EXPLAINER =
  "Your protection score is a snapshot of how well-covered you are right now. 100 means everything is in place. Lower means there are things you can fix.";

export interface ProtectionScoreFactor {
  readonly reason: string;
  readonly fix: string;
}

export const PROTECTION_SCORE_FACTORS: Record<string, ProtectionScoreFactor> = {
  unwrappedServers: {
    reason:
      "Some of your AI tools are not routed through me -- I cannot see or control their traffic.",
    fix: "Wrap these servers from the My Tools page.",
  },
  threatIntelOutdated: {
    reason:
      "My threat definitions have not been updated recently. I might miss newly known attack patterns.",
    fix: "Check for threat intel updates in Settings.",
  },
  slmNotActive: {
    reason:
      "The local security model is not running. I am relying on rules alone, without behavioral analysis.",
    fix: "Enable the local model in Settings > AI Engine.",
  },
  fdaNotGranted: {
    reason:
      "I do not have Full Disk Access, so I cannot auto-discover your AI tools.",
    fix: "Grant Full Disk Access in System Settings > Privacy & Security.",
  },
  unresolvedAlerts: {
    reason:
      "There are alerts that have not been reviewed yet. They may need your attention.",
    fix: "Review open alerts on the Alerts page.",
  },
} as const;

// ---------------------------------------------------------------------------
// Prompt Window Templates
// ---------------------------------------------------------------------------

export const PROMPT_ACTIONS_LOW_RISK = {
  allowOnce: { label: "Allow Once", shortcut: "Enter" },
  allowAlways: { label: "Always Allow", shortcut: "A" },
  block: { label: "Block", shortcut: "B" },
  blockAlways: { label: "Always Block", shortcut: "Shift+B" },
} as const;

export const PROMPT_ACTIONS_HIGH_RISK = {
  block: { label: "Block", shortcut: "Enter" },
  blockAlways: { label: "Always Block", shortcut: "Shift+B" },
  allowOnce: { label: "Allow Anyway", shortcut: "A" },
  allowAlways: { label: "Always Allow", shortcut: "Shift+A" },
} as const;

export const PROMPT_TIMEOUT_MESSAGE =
  "No response -- I blocked this for now. You can review it anytime.";

// ---------------------------------------------------------------------------
// Auto-Block Toast Templates
// ---------------------------------------------------------------------------

export const AUTO_BLOCK_TOAST_ACTIONS = {
  review: "Review",
  trust: "Trust this",
} as const;

export const AUTO_BLOCK_TOASTS = [
  "I blocked read_file from accessing ~/.ssh/id_rsa. SSH keys are protected by default.",
  "I blocked run_command from running `rm -rf /`. Destructive system commands are always blocked.",
  "I blocked fetch from connecting to a known malicious host ({host}). This domain is on the threat feed.",
  "I blocked write_file from modifying /etc/passwd. System authentication files are protected.",
  "I blocked read_file from reading {path}. This path is outside the server's allowed territory.",
  "I blocked run_command from running `curl` with piped output to an external server. This looks like data exfiltration.",
  "I blocked write_file from creating a new file in /usr/local/bin. MCP servers cannot write to system directories.",
  "I blocked read_file from accessing .env. Environment files often contain secrets.",
  "I blocked run_command from running `chmod 777` on your project directory. Open permissions create security risks.",
  "I blocked fetch from uploading a file to {host}. Bulk file uploads to public sharing services are blocked by default.",
] as const;

// ---------------------------------------------------------------------------
// Notification Templates (from threat-communication.md)
// ---------------------------------------------------------------------------

export const NOTIFICATION_TEMPLATES = {
  sshKeyRead: {
    oneLiner: "An agent tried to read your SSH private key. I paused it.",
    expanded:
      'The server "{serverName}" made a tool call that attempted to open ~/.ssh/id_rsa. SSH private keys grant access to remote servers, so I stopped this and I am asking you before it goes further.',
    educational:
      "SSH keys are like master passwords to your servers. A legitimate agent rarely needs to read the private key itself.",
  },
  awsCredentials: {
    oneLiner: "An agent tried to access your AWS credentials. Paused.",
    expanded:
      'The server "{serverName}" attempted to read your AWS credentials file. This file contains secret keys that could give access to your cloud infrastructure.',
    educational:
      "If an agent needs AWS access, it is safer to use environment variables with limited-scope IAM roles than to expose your credentials file.",
  },
  browserPasswords: {
    oneLiner: "An agent tried to access your browser passwords. Blocked.",
    expanded:
      'The server "{serverName}" attempted to read a browser password or cookie database. There is no legitimate reason for an MCP server to access browser credentials. I blocked this automatically.',
  },
  lowRiskCommand: {
    oneLiner: 'Server ran a shell command: `{command}`',
    expanded:
      'The server "{serverName}" executed `{command}` in your project directory. This is a routine command within the expected working area.',
  },
  highRiskCommand: {
    oneLiner: "An agent tried to run a dangerous shell command. Paused.",
    expanded:
      'The server "{serverName}" attempted to execute `{command}`. This type of command can download and run arbitrary code or permanently delete files. I stopped it for your review.',
    educational:
      "Piping a download directly into a shell (`curl | bash`) runs whatever code is on the other end with no review. It is one of the most common ways malicious code gets executed.",
  },
  fileOutsideProjectFirst: {
    oneLiner:
      "An agent accessed a file outside your project for the first time.",
    expanded:
      'The server "{serverName}" read "{filePath}", which is outside your current project directory. This is the first time this server has reached outside the project. It might be a normal config lookup, but I wanted you to know.',
  },
  fileOutsideProjectRepeated: {
    oneLiner: "This agent keeps accessing files outside your project.",
    expanded:
      'The server "{serverName}" has now accessed {count} files outside your project directory. The most recent was "{filePath}". Repeated external file access can indicate data collection behavior.',
  },
  knownApiConnection: {
    oneLiner: "Server connected to `{destination}`. Expected.",
    expanded:
      'The server "{serverName}" made a network connection to `{destination}`, which is a recognized AI provider API. This is normal behavior for this type of server.',
  },
  unknownConnection: {
    oneLiner: "An agent connected to an unfamiliar address.",
    expanded:
      'The server "{serverName}" connected to `{destination}`. I do not recognize this destination, and it is not in any allowlist. It could be legitimate, but I have not seen this server connect here before.',
  },
  maliciousConnection: {
    oneLiner:
      "An agent tried to contact a known malicious server. Blocked.",
    expanded:
      'The server "{serverName}" attempted to connect to `{destination}`, which is flagged in threat intelligence feeds as malicious. I blocked the connection. This could indicate a compromised MCP server.',
    educational:
      "Indicators of Compromise (IoCs) are addresses, file hashes, and patterns that have been observed in real-world attacks and shared by the security community.",
  },
  killChainCredentialExfiltration: {
    oneLiner: "I detected a credential theft pattern and blocked it.",
    expanded:
      'The server "{serverName}" first read a credentials file, then immediately tried to make a network connection. This sequence matches a known credential exfiltration attack. I blocked the network connection and logged everything.',
  },
  killChainReconCredential: {
    oneLiner:
      "An agent scanned your files then went for credentials. Blocked.",
    expanded:
      'The server "{serverName}" first listed files across multiple directories, then targeted a sensitive credentials file. This pattern -- looking around first, then going for the valuables -- matches a known reconnaissance-to-theft attack chain. Blocked.',
  },
  killChainStagingExfiltration: {
    oneLiner:
      "An agent staged files and tried to send them out. Blocked.",
    expanded:
      'The server "{serverName}" copied data to a temporary location, then attempted an outbound network connection. This matches a data exfiltration pattern where files are gathered before being sent externally. I blocked the outbound connection.',
  },
  uncorrelatedActivity: {
    oneLiner:
      "I noticed system activity that does not match any agent request.",
    expanded:
      'A {eventType} event occurred on your system ({details}) that I cannot trace back to any MCP tool call or resource read. This could be normal background activity, or it could be a process acting on its own outside the MCP protocol.',
    educational:
      "MCP servers should do their work through the protocol. Activity that happens outside the protocol could mean a server is doing things behind the scenes.",
  },
  promptInjection: {
    oneLiner:
      "I found a prompt injection attempt in a message to your AI.",
    expanded:
      'The server "{serverName}" sent a sampling/createMessage request containing text that looks like a prompt injection attack. The suspicious content attempts to {injectionType}. I blocked the message.',
    educational:
      "Prompt injection is when hidden instructions are smuggled into AI inputs, trying to override the AI's original instructions. It is one of the most common attack vectors for AI agents.",
  },
  unknownTool: {
    oneLiner: "This server just used a tool it has never used before.",
    expanded:
      'The server "{serverName}" called the tool "{toolName}" for the first time. Based on its learned behavior profile, this tool has not been part of its normal operation. This could be a new workflow or something unexpected.',
  },
  firstNetworkAccess: {
    oneLiner:
      "A server that has never gone online just tried to connect to the internet.",
    expanded:
      'The server "{serverName}" has never made a network connection in its entire history with me. It just tried to connect to "{destination}". A server suddenly going online when it has always worked offline is worth attention.',
  },
  accessRateSpike: {
    oneLiner: "An agent is working much faster than normal.",
    expanded:
      'The server "{serverName}" is making requests at {rateDescription} its usual pace. A sudden spike in activity can indicate automated behavior or a compromised server running through a scripted attack sequence.',
  },
  autoBlock: {
    oneLiner: "Automatically blocked -- this looked dangerous.",
    expanded:
      'I blocked an action by "{serverName}" automatically because it combined multiple high-risk signals. Auto-blocking is enabled in your settings and activates when the risk level is very high. You can review this decision and override it.',
  },
  autoBlockOverridden: {
    oneLiner: "Got it -- override noted. I will keep watching.",
    expanded:
      "You chose to allow this action that I blocked automatically. I have logged your decision and will factor it into future assessments. I am still monitoring this server.",
  },
  newServerDetected: {
    oneLiner:
      "I found a new MCP server that I am not monitoring yet.",
    expanded:
      'The server "{serverName}" is configured in {clientName} but is not routed through my proxy. I cannot see what it does until it is wrapped. I recommend wrapping it so I can monitor its behavior.',
    educational:
      "Wrapping an MCP server means routing its traffic through me. I can then see every tool call and resource read, and block anything suspicious.",
  },
  serverVulnerability: {
    oneLiner: "A server you use has a known security issue.",
    expanded:
      'The server "{serverName}" (version {version}) has a known vulnerability: {vulnerabilitySummary}. This does not mean you are being attacked right now, but it means this server has a weakness that could be exploited.',
  },
  serverBlocklisted: {
    oneLiner: "This server is on the blocklist. Blocked.",
    expanded:
      'The server "{serverName}" matches an entry in the threat intelligence blocklist. It has been identified as malicious by the security community. I blocked it from running.',
  },
  slmHighRisk: {
    oneLiner: "My local AI flagged this as high risk.",
    expanded:
      'I ran this event through local AI analysis and it returned a high-risk assessment: {slmSummary}. Local analysis is a second opinion alongside behavioral scoring. Together, they suggest this event needs your attention.',
  },
  swarmCritical: {
    oneLiner:
      "Deep analysis confirms this is critical. Three specialists agree.",
    expanded:
      'I escalated this event to cloud-based specialist analysis. The threat assessment specialist, forensic analyst, and internal auditor all contributed. Their combined verdict is critical risk: {swarmSummary}. This is the highest confidence assessment I can provide.',
  },
  guardActivated: {
    oneLiner: 'A guard is now active for "{agentName}".',
    expanded:
      'The agent "{agentName}" has activated a security guard in {mode} mode. The guard will {modeDescription} actions taken by this agent against its defined policy.',
  },
  guardBlocked: {
    oneLiner: 'Guard blocked "{agentName}" from {actionSummary}.',
    expanded:
      'The guard protecting "{agentName}" intercepted and blocked an action: {actionDetail}. The action violated the guard\'s policy. The agent was notified that the action was denied.',
  },
  scanWithFindings: {
    oneLiner: "Scan finished. Found {count} issue(s) to review.",
    expanded:
      'I scanned "{serverName}" and found {count} potential security issues across {modulesWithFindings}. The most serious is: {topFindingSummary}. Review the full report for details and recommended fixes.',
  },
  scanClean: {
    oneLiner: "Scan complete. No issues found.",
    expanded:
      'I scanned "{serverName}" across all security modules and found nothing concerning. This is a good sign, but remember that scans are point-in-time checks. I will keep monitoring continuously.',
  },
  weeklyDigest: {
    oneLiner: "Your weekly security summary is ready.",
    expanded:
      "This week: {totalEvents} events monitored, {blockedCount} blocked, {promptedCount} required your decision. {serversMonitored} servers are being watched. {topFindingOrAllClear}. Full details in the audit log.",
  },
} as const;

// ---------------------------------------------------------------------------
// Proactive Alerts
// ---------------------------------------------------------------------------

export const PROACTIVE_ALERTS = {
  newClientDetected:
    "I found a new MCP client on your system: {clientName}. It is running {count} servers. I can start monitoring them whenever you are ready.",
  vulnerabilityDisclosed:
    "A vulnerability was disclosed today affecting {serverName} ({cveId}). The server you are running is an affected version. I recommend updating it. Until then, I am applying stricter monitoring to its network calls.",
  outdatedServer:
    "{serverName} has not been updated in {months} months. Outdated servers can miss security patches. It might be worth checking if a newer version is available.",
  firstThreatBlocked:
    "I just blocked my first real threat for you -- {serverName} tried to access your SSH keys and I stopped it. This is exactly what I am here for.",
  milestone:
    "{days} days of protection. {totalEvents} events monitored, {threatsBlocked} threats blocked. Things are running smoothly.",
  scoreImproved:
    "Your protection score went up to {newScore} from {oldScore} after you {reason}. I can see a lot more now.",
  scoreDropped:
    "Your protection score dropped to {newScore} from {oldScore}. The main reason: {reason}.",
} as const;

// ---------------------------------------------------------------------------
// Error Messages
// ---------------------------------------------------------------------------

export interface ErrorMessage {
  readonly title: string;
  readonly body: string;
  readonly recommended: string;
  readonly cta: string;
  readonly ctaSecondary: string;
}

export const ERROR_MESSAGES: Record<string, ErrorMessage> = {
  daemonNotRunning: {
    title: "Claw's daemon is not running.",
    body: "I cannot monitor your AI tools right now.",
    recommended:
      "Open RookBot to start the daemon, or run `rookbot daemon start` in your terminal.",
    cta: "Start daemon",
    ctaSecondary: "Learn more",
  },
  daemonCrashed: {
    title: "The daemon crashed and restarted.",
    body: "You were unprotected for about {seconds} seconds. Everything is running again now. I am looking into what caused the crash.",
    recommended:
      "No action needed unless this keeps happening. If it does, check the logs.",
    cta: "View crash log",
    ctaSecondary: "Learn more",
  },
  ipcConnectionLost: {
    title: "I lost connection to the daemon.",
    body: "Trying to reconnect. Monitoring is paused until the connection is restored.",
    recommended:
      "If this does not resolve in a few seconds, try restarting RookBot.",
    cta: "Restart",
    ctaSecondary: "Learn more",
  },
  slmDownloadFailed: {
    title: "I could not download the security model.",
    body: "Behavioral analysis will not be available until the model is installed.",
    recommended:
      "Check your internet connection and try again. The download is about 2 GB.",
    cta: "Retry download",
    ctaSecondary: "Learn more",
  },
  slmInferenceFailed: {
    title: "The local model returned an error during analysis.",
    body: "I am falling back to rule-based detection, which is less accurate but still functional.",
    recommended:
      "Try reloading the model in Settings > Model. If this keeps happening, re-downloading may fix it.",
    cta: "Reload model",
    ctaSecondary: "Learn more",
  },
  fdaNotGranted: {
    title: "I do not have Full Disk Access.",
    body: "This means I cannot see some process activity, which creates blind spots in monitoring. Your protection score is lower than it could be.",
    recommended:
      "Grant Full Disk Access to RookBot in System Settings > Privacy & Security.",
    cta: "Open System Settings",
    ctaSecondary: "Learn more",
  },
  noMcpClients: {
    title: "I did not find any MCP clients on your system.",
    body: "I need at least one (like Cursor, Claude Desktop, or Windsurf) to start monitoring.",
    recommended:
      "Install an MCP client, or if you already have one, make sure it has been run at least once so I can detect its configuration.",
    cta: "Scan again",
    ctaSecondary: "Learn more",
  },
  configCorrupted: {
    title: "Your config file was corrupted, but I recovered it from a backup.",
    body: "Your settings are from {date}. Check if anything looks off.",
    recommended:
      "Review your settings to make sure they match what you expect.",
    cta: "Open settings",
    ctaSecondary: "Learn more",
  },
  networkUnreachable: {
    title: "I cannot reach the threat intelligence feed.",
    body: "Threat detection is running on cached data, which may be out of date.",
    recommended:
      "Check your internet connection. I will keep trying in the background.",
    cta: "Retry now",
    ctaSecondary: "Learn more",
  },
  apiKeyInvalid: {
    title: "Your cloud analysis API key is not working.",
    body: "I am running local-only analysis, which covers the basics but misses deeper patterns.",
    recommended: "Check your API key in Settings > Cloud Analysis.",
    cta: "Open settings",
    ctaSecondary: "Learn more",
  },
  scanFailed: {
    title: "The security scan stopped before it finished.",
    body: "I scanned {completed} of {total} items. Partial results are available.",
    recommended:
      "Try running the scan again. If it keeps failing at the same point, something specific may be causing it.",
    cta: "Retry scan",
    ctaSecondary: "Learn more",
  },
  wrapPermissionDenied: {
    title: "I could not set up monitoring for {serverName}.",
    body: "I do not have permission to modify its launch configuration.",
    recommended:
      "Check that RookBot has write access to the MCP client's config file, or run the setup with elevated permissions.",
    cta: "Fix permissions",
    ctaSecondary: "Learn more",
  },
  wrapConfigChanged: {
    title: "I could not set up monitoring for {serverName}.",
    body: "The MCP client's configuration format has changed and I do not recognize the new structure yet.",
    recommended:
      "Check for a RookBot update. If none is available, you can configure the proxy manually.",
    cta: "Check for updates",
    ctaSecondary: "Learn more",
  },
  modelFileMissing: {
    title: "The security model file is missing.",
    body: "Behavioral analysis will not work until the model is reinstalled.",
    recommended: "Download the model again in Settings > Model.",
    cta: "Download model",
    ctaSecondary: "Learn more",
  },
  ipcCallFailed: {
    title: "Something went wrong.",
    body: "I had trouble completing that request. Your data is safe -- this is a temporary issue.",
    recommended: "Try again in a moment. If this keeps happening, restarting RookBot usually fixes it.",
    cta: "Try again",
    ctaSecondary: "Dismiss",
  },
  diskSpaceInsufficient: {
    title: "Not enough disk space.",
    body: "The model needs {needed} of free space, but you only have {available} available.",
    recommended: "Free up some disk space and try again.",
    cta: "Try again",
    ctaSecondary: "Learn more",
  },
  downloadPartial: {
    title: "The download did not finish.",
    body: "Part of the file was saved. You can resume from where it stopped.",
    recommended: "Your connection may have been interrupted. Try again when you have a stable connection.",
    cta: "Resume download",
    ctaSecondary: "Start over",
  },
} as const;

// ---------------------------------------------------------------------------
// Threat Level Labels
// ---------------------------------------------------------------------------

export interface ThreatLevelInfo {
  readonly label: string;
  readonly description: string;
}

export const THREAT_LEVEL_INFO: Record<string, ThreatLevelInfo> = {
  dangerous: {
    label: "Dangerous",
    description:
      "Requires immediate user attention or was auto-blocked. Maps to behavioral auto-block threshold, kill chain detection, or IoC match.",
  },
  suspicious: {
    label: "Suspicious",
    description:
      "High confidence that something is wrong but not definitively malicious. User decision required.",
  },
  unusual: {
    label: "Unusual",
    description:
      "Behavioral deviation from learned baseline. Logged and surfaced but does not block.",
  },
  normal: {
    label: "Normal",
    description:
      "Within learned behavioral baseline. Logged silently.",
  },
  blocked: {
    label: "Blocked",
    description:
      "System took automatic action. User can review and override.",
  },
  info: {
    label: "Info",
    description:
      "System status messages, mock mode notices, educational context.",
  },
} as const;

// ---------------------------------------------------------------------------
// Ask Rook
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Prompt Confirmation Messages
// ---------------------------------------------------------------------------

export const PROMPT_CONFIRMATION = {
  allowed: "Allowed.",
  allowedAlways: "Allowed. I added a rule so you won't be asked again.",
  blocked: "Blocked.",
  blockedAlways: "Blocked. I added a rule so this will always be blocked.",
  timeout: "No response -- I blocked this for now. You can review it anytime.",
  highRiskConfirm: "Are you sure? This action was flagged as risky.",
} as const;

// ---------------------------------------------------------------------------
// Notification Batch Messages
// ---------------------------------------------------------------------------

export const NOTIFICATION_BATCH = {
  title: "A lot is happening right now",
  body: "{count} events in the last few seconds",
  action: "View Activity",
} as const;

// ---------------------------------------------------------------------------
// Ask Rook
// ---------------------------------------------------------------------------

export const ASK_CLAW = {
  inputPlaceholder: "Ask Rook anything...",
  thinkingIndicator: "Let me check...",
  firstTimeGreeting: "Hey. I'm Claw. Ask me anything about your security, or drag a file here for analysis.",
  errorGeneric: "I ran into a problem trying to answer that.",
  errorRetry: "Try again",
  errorReport: "Let me know what happened",
  offlineMessage: "I'm having trouble connecting to my monitoring service. I can still answer general questions, but I can't check your current status.",
  confirmDo: "Do it",
  confirmCancel: "Never mind",
  confirmCancelled: "No problem. Let me know if you change your mind.",
  dragOverlay: "Drop a file, URL, or config for Claw to analyze",
  newConversation: "New chat",
  suggestions: {
    default: ["Am I safe?", "What happened today?", "Scan my setup"],
    afterStatus: ["What happened today?", "Scan my setup", "Show me threats"],
    afterBlock: ["What else has this tool been doing?", "Tighten my security"],
    afterExplain: ["Should I be worried?", "Block this server", "Show me more events"],
  },
} as const;

// ---------------------------------------------------------------------------
// Event Humanization Messages
// ---------------------------------------------------------------------------

export const HUMANIZATION_EMPTY = {
  noEvents: {
    headline: "No activity yet.",
    body: "When your AI tools start making requests, I will translate each one into plain language here.",
  },
  noMatchingEvents: {
    headline: "Nothing matches your filter.",
    body: "Try broadening your search or clearing the filter to see all activity.",
  },
} as const;

export const HUMANIZATION_FALLBACK = {
  unknownServer: "An unknown tool",
  unknownAction: "performed an action",
  noExplanation: "No additional details available for this event.",
  noBehavioralContext: "I do not have enough data about this tool to provide behavioral context yet.",
  noRiskExplanation: "No specific risk pattern was matched for this event.",
} as const;

export const HUMANIZATION_LABELS = {
  actionTaken: {
    Allowed: "Allowed",
    Blocked: "Blocked",
    Prompted: "Awaiting your decision",
    AutoBlocked: "Auto-blocked",
  },
  riskLevel: {
    dangerous: "Dangerous",
    suspicious: "Suspicious",
    unusual: "Unusual",
    normal: "Normal",
    blocked: "Blocked",
    info: "Info",
  },
  sections: {
    whatHappened: "What happened",
    whyItMatters: "Why it matters",
    behavioralContext: "Behavioral context",
    technicalDetails: "Technical details",
  },
} as const;
