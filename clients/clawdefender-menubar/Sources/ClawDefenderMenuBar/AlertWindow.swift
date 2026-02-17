import AppKit

enum AlertAction {
    case dismiss
    case killProcess(pid: UInt32)
    case viewDetails
}

final class AlertWindow: NSObject {
    private var window: NSWindow!
    private let severity: Severity
    private let message: String
    private let eventId: String
    private let onAction: (AlertAction) -> Void

    init(severity: Severity, message: String, eventId: String, onAction: @escaping (AlertAction) -> Void) {
        self.severity = severity
        self.message = message
        self.eventId = eventId
        self.onAction = onAction
        super.init()
    }

    func show() {
        let contentRect = NSRect(x: 0, y: 0, width: 500, height: 280)
        window = NSWindow(
            contentRect: contentRect,
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = "ClawDefender - \(severityText()) Alert"
        window.level = .floating
        window.center()
        window.isReleasedWhenClosed = false

        let contentView = NSView(frame: contentRect)
        window.contentView = contentView

        var y: CGFloat = contentRect.height - 30

        // Severity header
        let headerLabel = makeLabel(
            frame: NSRect(x: 20, y: y - 24, width: 460, height: 24),
            text: "\(severityIcon()) \(severityText()) Severity Alert",
            bold: true,
            size: 16
        )
        headerLabel.textColor = severityColor()
        contentView.addSubview(headerLabel)
        y -= 40

        // Message
        let messageLabel = makeLabel(
            frame: NSRect(x: 20, y: y - 60, width: 460, height: 60),
            text: message,
            bold: false,
            size: 13
        )
        messageLabel.maximumNumberOfLines = 3
        contentView.addSubview(messageLabel)
        y -= 70

        // Event ID
        let idLabel = makeLabel(
            frame: NSRect(x: 20, y: y - 18, width: 460, height: 18),
            text: "Event: \(eventId)",
            bold: false,
            size: 11
        )
        idLabel.textColor = .secondaryLabelColor
        contentView.addSubview(idLabel)
        y -= 30

        // Warning text
        let warningLabel = makeLabel(
            frame: NSRect(x: 20, y: y - 40, width: 460, height: 40),
            text: "Uncorrelated activity detected. This action was not matched to any known MCP client request.",
            bold: false,
            size: 11
        )
        warningLabel.textColor = .systemOrange
        warningLabel.maximumNumberOfLines = 2
        contentView.addSubview(warningLabel)

        // Buttons
        let buttonWidth: CGFloat = 130
        let buttonHeight: CGFloat = 32
        let spacing: CGFloat = 10
        let totalWidth = buttonWidth * 3 + spacing * 2
        let startX = (contentRect.width - totalWidth) / 2

        let dismissButton = NSButton(frame: NSRect(x: startX, y: 20, width: buttonWidth, height: buttonHeight))
        dismissButton.title = "Dismiss"
        dismissButton.bezelStyle = .rounded
        dismissButton.keyEquivalent = "\u{1b}" // Escape
        dismissButton.target = self
        dismissButton.action = #selector(dismissAlert)
        contentView.addSubview(dismissButton)

        let killButton = NSButton(frame: NSRect(x: startX + buttonWidth + spacing, y: 20, width: buttonWidth, height: buttonHeight))
        killButton.title = "Kill Process"
        killButton.bezelStyle = .rounded
        killButton.target = self
        killButton.action = #selector(killProcess)
        contentView.addSubview(killButton)

        let viewButton = NSButton(frame: NSRect(x: startX + (buttonWidth + spacing) * 2, y: 20, width: buttonWidth, height: buttonHeight))
        viewButton.title = "View Details"
        viewButton.bezelStyle = .rounded
        viewButton.target = self
        viewButton.action = #selector(viewDetails)
        contentView.addSubview(viewButton)

        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        NSSound.beep()
    }

    @objc private func dismissAlert() {
        window.close()
        onAction(.dismiss)
    }

    @objc private func killProcess() {
        // Prompt for PID
        let alert = NSAlert()
        alert.messageText = "Kill Process"
        alert.informativeText = "Enter the PID of the process to terminate:"
        alert.addButton(withTitle: "Kill")
        alert.addButton(withTitle: "Cancel")

        let input = NSTextField(frame: NSRect(x: 0, y: 0, width: 200, height: 24))
        input.placeholderString = "PID"
        alert.accessoryView = input

        let response = alert.runModal()
        if response == .alertFirstButtonReturn, let pid = UInt32(input.stringValue) {
            window.close()
            onAction(.killProcess(pid: pid))
        }
    }

    @objc private func viewDetails() {
        // Open audit log to view details
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let auditPath = "\(home)/.local/share/clawdefender/audit.jsonl"
        NSWorkspace.shared.open(URL(fileURLWithPath: auditPath))
        window.close()
        onAction(.viewDetails)
    }

    private func severityText() -> String {
        switch severity {
        case .Info: return "Info"
        case .Low: return "Low"
        case .Medium: return "Medium"
        case .High: return "High"
        case .Critical: return "Critical"
        }
    }

    private func severityIcon() -> String {
        switch severity {
        case .Info: return "[i]"
        case .Low: return "[L]"
        case .Medium: return "[M]"
        case .High: return "[!]"
        case .Critical: return "[!!]"
        }
    }

    private func severityColor() -> NSColor {
        switch severity {
        case .Info: return .labelColor
        case .Low: return .systemBlue
        case .Medium: return .systemYellow
        case .High: return .systemOrange
        case .Critical: return .systemRed
        }
    }

    private func makeLabel(frame: NSRect, text: String, bold: Bool, size: CGFloat) -> NSTextField {
        let label = NSTextField(frame: frame)
        label.stringValue = text
        label.isEditable = false
        label.isBordered = false
        label.drawsBackground = false
        label.font = bold ? .boldSystemFont(ofSize: size) : .systemFont(ofSize: size)
        label.lineBreakMode = .byTruncatingTail
        return label
    }
}
