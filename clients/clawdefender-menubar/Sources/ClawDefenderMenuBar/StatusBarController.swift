import AppKit

final class StatusBarController: NSObject, DaemonConnectionDelegate {
    private let statusItem: NSStatusItem
    private let menu = NSMenu()

    var daemonConnection: DaemonConnection!
    var notificationManager: NotificationManager!

    // State
    private var connected = false
    private var blockedCount: UInt64 = 0
    private var allowedCount: UInt64 = 0
    private var promptedCount: UInt64 = 0
    private var uptimeSecs: UInt64 = 0
    private var recentEvents: [(String, Severity)] = [] // (message, severity)
    private var pendingPrompts: [(eventSummary: String, ruleName: String, options: [String])] = []
    private var slmStatus: String?
    private var swarmStatus: String?

    override init() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        super.init()

        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "shield.checkmark", accessibilityDescription: "ClawDefender")
            button.image?.isTemplate = true
        }

        statusItem.menu = menu
        rebuildMenu()
    }

    // MARK: - Menu

    private func rebuildMenu() {
        menu.removeAllItems()

        // Header
        let statusText = connected ? "ClawDefender -- Running" : "ClawDefender -- Stopped"
        let headerItem = NSMenuItem(title: statusText, action: nil, keyEquivalent: "")
        headerItem.isEnabled = false
        menu.addItem(headerItem)

        if connected {
            let statsText = "Blocked: \(blockedCount)  Allowed: \(allowedCount)  Prompted: \(promptedCount)"
            let statsItem = NSMenuItem(title: statsText, action: nil, keyEquivalent: "")
            statsItem.isEnabled = false
            menu.addItem(statsItem)

            if uptimeSecs > 0 {
                let uptimeText = "Uptime: \(formatUptime(uptimeSecs))"
                let uptimeItem = NSMenuItem(title: uptimeText, action: nil, keyEquivalent: "")
                uptimeItem.isEnabled = false
                menu.addItem(uptimeItem)
            }
        }

        menu.addItem(NSMenuItem.separator())

        // Pending Approvals
        let pendingTitle = "Pending Approvals (\(pendingPrompts.count))"
        let pendingHeader = NSMenuItem(title: pendingTitle, action: nil, keyEquivalent: "")
        pendingHeader.isEnabled = false
        menu.addItem(pendingHeader)

        for (index, prompt) in pendingPrompts.enumerated() {
            let truncated = String(prompt.eventSummary.prefix(60))
            let item = NSMenuItem(title: "  \(truncated)", action: #selector(handlePendingPrompt(_:)), keyEquivalent: "")
            item.target = self
            item.tag = index
            menu.addItem(item)
        }

        menu.addItem(NSMenuItem.separator())

        // Recent Events
        let recentHeader = NSMenuItem(title: "Recent Events", action: nil, keyEquivalent: "")
        recentHeader.isEnabled = false
        menu.addItem(recentHeader)

        if recentEvents.isEmpty {
            let emptyItem = NSMenuItem(title: "  No recent events", action: nil, keyEquivalent: "")
            emptyItem.isEnabled = false
            menu.addItem(emptyItem)
        } else {
            for event in recentEvents.suffix(10) {
                let icon = severityIcon(event.1)
                let truncated = String(event.0.prefix(50))
                let item = NSMenuItem(title: "  \(icon) \(truncated)", action: nil, keyEquivalent: "")
                item.isEnabled = false
                menu.addItem(item)
            }
        }

        menu.addItem(NSMenuItem.separator())

        // Actions
        let auditItem = NSMenuItem(title: "View Audit Log...", action: #selector(openAuditLog), keyEquivalent: "l")
        auditItem.target = self
        menu.addItem(auditItem)

        let chatItem = NSMenuItem(title: "Open Chat...", action: #selector(openChat), keyEquivalent: "c")
        chatItem.target = self
        menu.addItem(chatItem)

        let prefsItem = NSMenuItem(title: "Preferences...", action: #selector(openPreferences), keyEquivalent: ",")
        prefsItem.target = self
        menu.addItem(prefsItem)

        menu.addItem(NSMenuItem.separator())

        // Subsystem status
        if let slm = slmStatus {
            let item = NSMenuItem(title: "SLM: \(slm)", action: nil, keyEquivalent: "")
            item.isEnabled = false
            menu.addItem(item)
        }
        if let swarm = swarmStatus {
            let item = NSMenuItem(title: "Swarm: \(swarm)", action: nil, keyEquivalent: "")
            item.isEnabled = false
            menu.addItem(item)
        }
        let sensorItem = NSMenuItem(title: "Sensor: \(connected ? "Connected" : "Disconnected")", action: nil, keyEquivalent: "")
        sensorItem.isEnabled = false
        menu.addItem(sensorItem)

        menu.addItem(NSMenuItem.separator())

        // Quit
        let quitItem = NSMenuItem(title: "Quit ClawDefender", action: #selector(quit), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)
    }

    private func updateStatusIcon() {
        guard let button = statusItem.button else { return }

        if !connected {
            button.image = NSImage(systemSymbolName: "shield.slash", accessibilityDescription: "ClawDefender - Disconnected")
        } else if !pendingPrompts.isEmpty {
            button.image = NSImage(systemSymbolName: "shield.checkmark.badge.exclamationmark", accessibilityDescription: "ClawDefender - Pending")
            button.contentTintColor = .systemYellow
        } else if blockedCount > 0 {
            button.image = NSImage(systemSymbolName: "shield.checkmark", accessibilityDescription: "ClawDefender - Active")
            button.contentTintColor = .systemGreen
        } else {
            button.image = NSImage(systemSymbolName: "shield.checkmark", accessibilityDescription: "ClawDefender")
            button.contentTintColor = nil
        }
        button.image?.isTemplate = (button.contentTintColor == nil)
    }

    // MARK: - Actions

    @objc private func handlePendingPrompt(_ sender: NSMenuItem) {
        let index = sender.tag
        guard index < pendingPrompts.count else { return }
        let prompt = pendingPrompts[index]
        let window = PromptWindow(
            eventSummary: prompt.eventSummary,
            ruleName: prompt.ruleName,
            options: prompt.options
        ) { [weak self] decision in
            self?.daemonConnection.send(response: .Decision(event_id: prompt.ruleName, action: decision))
            self?.pendingPrompts.remove(at: index)
            self?.rebuildMenu()
            self?.updateStatusIcon()
        }
        window.show()
    }

    @objc private func openAuditLog() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let auditPath = "\(home)/.local/share/clawdefender/audit.jsonl"
        let url = URL(fileURLWithPath: auditPath)
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    @objc private func openChat() {
        if let url = URL(string: "http://127.0.0.1:3200") {
            NSWorkspace.shared.open(url)
        }
    }

    @objc private func openPreferences() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let configPath = "\(home)/.config/clawdefender/config.toml"
        let url = URL(fileURLWithPath: configPath)
        NSWorkspace.shared.open(url)
    }

    @objc private func quit() {
        NSApplication.shared.terminate(nil)
    }

    // MARK: - DaemonConnectionDelegate

    func daemonDidConnect() {
        connected = true
        updateStatusIcon()
        rebuildMenu()
    }

    func daemonDidDisconnect() {
        connected = false
        pendingPrompts.removeAll()
        slmStatus = nil
        swarmStatus = nil
        updateStatusIcon()
        rebuildMenu()
    }

    func daemonDidReceive(request: UiRequest) {
        switch request {
        case .PromptUser(let summary, let ruleName, let options):
            pendingPrompts.append((eventSummary: summary, ruleName: ruleName, options: options))
            recentEvents.append((summary, .Medium))
            trimRecentEvents()
            updateStatusIcon()
            rebuildMenu()

            // Show prompt window
            let prompt = pendingPrompts.last!
            let promptIndex = pendingPrompts.count - 1
            let window = PromptWindow(
                eventSummary: prompt.eventSummary,
                ruleName: prompt.ruleName,
                options: prompt.options
            ) { [weak self] decision in
                self?.daemonConnection.send(response: .Decision(event_id: ruleName, action: decision))
                if promptIndex < self?.pendingPrompts.count ?? 0 {
                    self?.pendingPrompts.remove(at: promptIndex)
                }
                self?.rebuildMenu()
                self?.updateStatusIcon()
            }
            window.show()

            // Also send notification
            notificationManager?.showPromptNotification(eventSummary: summary, ruleName: ruleName)

        case .Alert(let severity, let message, let eventId):
            recentEvents.append((message, severity))
            trimRecentEvents()
            rebuildMenu()

            // Show alert window for High/Critical
            if severity == .High || severity == .Critical {
                let alertWindow = AlertWindow(
                    severity: severity,
                    message: message,
                    eventId: eventId
                ) { [weak self] action in
                    switch action {
                    case .dismiss:
                        self?.daemonConnection.send(response: .Dismiss(event_id: eventId))
                    case .killProcess(let pid):
                        self?.daemonConnection.send(response: .KillProcess(pid: pid))
                    case .viewDetails:
                        break // Handled in AlertWindow
                    }
                }
                alertWindow.show()
            }

            notificationManager?.showAlertNotification(severity: severity, message: message, eventId: eventId)

        case .StatusUpdate(let blocked, let allowed, let prompted, let uptime):
            blockedCount = blocked
            allowedCount = allowed
            promptedCount = prompted
            uptimeSecs = uptime
            rebuildMenu()

        case .SwarmEnrichment(_, let riskLevel, _, let recommendedAction, _):
            swarmStatus = "\(riskLevel) - \(recommendedAction)"
            rebuildMenu()

        case .SlmEnrichment(_, let riskLevel, _, let confidence):
            slmStatus = "\(riskLevel) (confidence: \(String(format: "%.0f%%", confidence * 100)))"
            rebuildMenu()
        }
    }

    // MARK: - Helpers

    private func trimRecentEvents() {
        if recentEvents.count > 50 {
            recentEvents = Array(recentEvents.suffix(50))
        }
    }

    private func severityIcon(_ severity: Severity) -> String {
        switch severity {
        case .Info: return "[i]"
        case .Low: return "[L]"
        case .Medium: return "[M]"
        case .High: return "[H]"
        case .Critical: return "[!]"
        }
    }

    private func formatUptime(_ seconds: UInt64) -> String {
        let hours = seconds / 3600
        let minutes = (seconds % 3600) / 60
        let secs = seconds % 60
        if hours > 0 {
            return "\(hours)h \(minutes)m"
        } else if minutes > 0 {
            return "\(minutes)m \(secs)s"
        } else {
            return "\(secs)s"
        }
    }
}
