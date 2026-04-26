# Rookbot Onboarding & Setup Copy

All copy follows the voice defined in `character-brief.md` -- calm, observant, direct, honest, warm. Claw speaks as a knowledgeable friend, never as software.

---

## Section 1 -- Onboarding Wizard Screens

### Screen 1 -- Welcome

**Variation A**

- Headline: "Hey. I am Claw."
- Body: "I am your AI security companion. I sit between you and the AI tools you use every day -- watching the traffic, catching the threats, keeping your machine safe. Let me take a quick look at what you have running."
- CTA: "Scan My System"

**Variation B (RECOMMENDED)**

- Headline: "Hey. I am Claw -- nice to meet you."
- Body: "I watch over the AI tools on your machine and make sure they behave. Think of me as a security expert who lives in your menu bar. I will scan your system, set up protection, and stay out of your way. Ready?"
- CTA: "Let's Go"

**Variation C**

- Headline: "Meet Claw."
- Body: "I keep your AI tools honest. Every request they make passes through me first -- if something looks wrong, I catch it before it reaches your system. Let me see what you are working with."
- CTA: "Get Started"

---

### Screen 2 -- What I Found

- Headline: "Here is what I found."
- Framing text: "I scanned your system for AI tools. These are the ones I can protect."

**Per-tool description format:**

```
[Tool Name]
Part of [Parent App]
Can: [capability 1], [capability 2], [capability 3]
```

Example:

```
claude-server
Part of Claude Desktop
Can: read files, write files, run commands, make network requests
```

- CTA: "Protect These"

**Empty state -- no tools found:**

- Headline: "I did not find any AI tools yet."
- Body: "That is fine -- you might not have any installed, or they might not be running yet. You can add them manually later from the dashboard, or run this scan again any time."
- CTA: "Continue Without Tools"

---

### Screen 3 -- How Careful Should I Be?

**Option 1 -- Keep Watch**

- Label: "Keep Watch"
- Claw quote: "I will log everything and let you know if something looks off, but I will not block anything. You stay in full control."
- Subtitle: Good for exploring -- see what your tools are doing before setting rules.

**Option 2 -- Stay Sharp (RECOMMENDED)**

- Label: "Stay Sharp"
- Claw quote: "I will block anything dangerous and ask you about the rest. Most people start here -- it is the right balance of safety and flow."
- Subtitle: Good for everyday work -- protection without constant interruptions.

**Option 3 -- Lock It Down**

- Label: "Lock It Down"
- Claw quote: "Nothing gets through without your say-so. I will prompt you for every action. It is thorough, but expect more interruptions."
- Subtitle: Good for sensitive projects -- maximum control over every action.

---

### Screen 4 -- Setup Complete

- Headline: "You are all set."
- Protection summary format:

```
[X] servers protected | [Level name] mode
```

Example: "3 servers protected | Stay Sharp mode"

- Restart reminder: "One thing -- restart any AI apps you have open so they route through me. I will be in your menu bar whenever you need me."
- Menu bar intro: "Look for me in your menu bar. Green means everything is fine. If something needs your attention, I will let you know."
- CTA: "Open Dashboard"

---

### FDA (Full Disk Access) Prompt

- Why it helps: "Full Disk Access lets me read the config files for your AI tools, so I can find and protect them automatically."
- What happens if you skip: "Without it, I can still protect servers you add manually -- I just will not be able to discover them on my own."
- System Settings guidance: "Open System Settings, go to Privacy & Security, then Full Disk Access, and toggle Rookbot on. I will wait here."

---

## Section 2 -- Empty States

### Dashboard -- No Events

- Headline: "All quiet so far."
- Body: "I am watching your AI tools. When they start making requests, you will see activity here -- events, stats, and anything that needs your attention."

### Activity Feed -- No Events

- Headline: "Nothing here yet."
- Body: "This is where you will see a live feed of every MCP request your AI tools make -- tool calls, file reads, network activity, and how I handled each one."

### Alerts -- No Threats

- Headline: "No threats detected."
- Body: "That is a good thing. When I spot something risky -- a suspicious tool call, unusual behavior, a blocked action -- it shows up here."

### My Tools -- No Servers

- Headline: "No servers connected."
- Body: "I protect AI tools by wrapping their MCP servers. Add a server from your MCP client config, or run a scan to find them automatically."
- CTA: "Scan for Tools" / "Add Manually"

### Scanner -- No History

- Headline: "No scans yet."
- Body: "The scanner checks your MCP server configs for misconfigurations, exposed credentials, and known vulnerabilities. Run your first scan to see where things stand."
- CTA: "Start Scan"

### Guards -- No Active Guards

- Headline: "No guards active."
- Body: "Guards are automated protections that watch for specific threat patterns -- like prompt injection, credential exfiltration, or privilege escalation. They run in the background and act on your behalf when something matches. Enable them from the guard library."
- CTA: "Browse Guards"

---

## Section 3 -- Protection Score Explainers

### What the Score Means

"Your protection score is a snapshot of how well-covered you are right now. 100 means everything is in place. Lower means there are things you can fix."

### Score Levels

**Full (100)**
"Fully protected. Every layer is active and up to date."

**High (80-99)**
"Looking good. A few minor things could be tightened up."

**Medium (50-79)**
"There are gaps in your protection. Worth addressing when you have a moment."

**Low (below 50)**
"Several protections are missing or inactive. I would recommend fixing these soon."

### Factors That Reduce the Score

**Unwrapped servers**
"Some of your AI tools are not routed through me -- I cannot see or control their traffic."
Fix: "Wrap these servers from the My Tools page."

**Threat intel outdated**
"My threat definitions have not been updated recently. I might miss newly known attack patterns."
Fix: "Check for threat intel updates in Settings."

**SLM not active**
"The local security model is not running. I am relying on rules alone, without behavioral analysis."
Fix: "Enable the local model in Settings > AI Engine."

**FDA not granted**
"I do not have Full Disk Access, so I cannot auto-discover your AI tools."
Fix: "Grant Full Disk Access in System Settings > Privacy & Security."

**Unresolved alerts**
"There are alerts that have not been reviewed yet. They may need your attention."
Fix: "Review open alerts on the Alerts page."
