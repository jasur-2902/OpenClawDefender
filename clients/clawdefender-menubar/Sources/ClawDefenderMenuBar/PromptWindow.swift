import AppKit

final class PromptWindow: NSObject {
    private var window: NSWindow!
    private var countdownTimer: Timer?
    private var remainingSeconds = 30
    private var countdownLabel: NSTextField!
    private let onDecision: (UserDecision) -> Void

    let eventSummary: String
    let ruleName: String
    let options: [String]

    init(eventSummary: String, ruleName: String, options: [String], onDecision: @escaping (UserDecision) -> Void) {
        self.eventSummary = eventSummary
        self.ruleName = ruleName
        self.options = options
        self.onDecision = onDecision
        super.init()
    }

    func show() {
        let contentRect = NSRect(x: 0, y: 0, width: 480, height: 320)
        window = NSWindow(
            contentRect: contentRect,
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = "ClawDefender - Action Required"
        window.level = .floating
        window.center()
        window.isReleasedWhenClosed = false

        let contentView = NSView(frame: contentRect)
        window.contentView = contentView

        var y: CGFloat = contentRect.height - 30

        // Shield icon + title
        let titleLabel = makeLabel(
            frame: NSRect(x: 20, y: y - 24, width: 440, height: 24),
            text: "Security Approval Required",
            bold: true,
            size: 16
        )
        contentView.addSubview(titleLabel)
        y -= 40

        // Event summary
        let summaryLabel = makeLabel(
            frame: NSRect(x: 20, y: y - 40, width: 440, height: 40),
            text: eventSummary,
            bold: false,
            size: 13
        )
        summaryLabel.maximumNumberOfLines = 2
        contentView.addSubview(summaryLabel)
        y -= 50

        // Rule name
        let ruleLabel = makeLabel(
            frame: NSRect(x: 20, y: y - 20, width: 440, height: 20),
            text: "Rule: \(ruleName)",
            bold: false,
            size: 11
        )
        ruleLabel.textColor = .secondaryLabelColor
        contentView.addSubview(ruleLabel)
        y -= 30

        // Countdown
        countdownLabel = makeLabel(
            frame: NSRect(x: 20, y: y - 20, width: 440, height: 20),
            text: "Auto-deny in \(remainingSeconds)s",
            bold: false,
            size: 11
        )
        countdownLabel.textColor = .systemOrange
        contentView.addSubview(countdownLabel)
        y -= 40

        // Buttons
        let buttonWidth: CGFloat = 130
        let buttonHeight: CGFloat = 32
        let spacing: CGFloat = 10
        let totalWidth = buttonWidth * 3 + spacing * 2
        let startX = (contentRect.width - totalWidth) / 2

        let denyButton = NSButton(frame: NSRect(x: startX, y: 20, width: buttonWidth, height: buttonHeight))
        denyButton.title = "Deny (D)"
        denyButton.bezelStyle = .rounded
        denyButton.keyEquivalent = "d"
        denyButton.target = self
        denyButton.action = #selector(denyOnce)
        contentView.addSubview(denyButton)

        let allowOnceButton = NSButton(frame: NSRect(x: startX + buttonWidth + spacing, y: 20, width: buttonWidth, height: buttonHeight))
        allowOnceButton.title = "Allow Once (A)"
        allowOnceButton.bezelStyle = .rounded
        allowOnceButton.keyEquivalent = "a"
        allowOnceButton.target = self
        allowOnceButton.action = #selector(allowOnce)
        contentView.addSubview(allowOnceButton)

        let alwaysAllowButton = NSButton(frame: NSRect(x: startX + (buttonWidth + spacing) * 2, y: 20, width: buttonWidth, height: buttonHeight))
        alwaysAllowButton.title = "Always Allow"
        alwaysAllowButton.bezelStyle = .rounded
        alwaysAllowButton.target = self
        alwaysAllowButton.action = #selector(alwaysAllow)
        contentView.addSubview(alwaysAllowButton)

        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        NSSound.beep()

        // Start countdown
        countdownTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.tick()
        }
    }

    private func tick() {
        remainingSeconds -= 1
        if remainingSeconds <= 0 {
            decide(.DenyOnce)
        } else {
            countdownLabel.stringValue = "Auto-deny in \(remainingSeconds)s"
        }
    }

    @objc private func denyOnce() {
        decide(.DenyOnce)
    }

    @objc private func allowOnce() {
        decide(.AllowOnce)
    }

    @objc private func alwaysAllow() {
        decide(.AddPolicyRule)
    }

    private func decide(_ decision: UserDecision) {
        countdownTimer?.invalidate()
        countdownTimer = nil
        window.close()
        onDecision(decision)
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
