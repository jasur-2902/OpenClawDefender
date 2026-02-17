import Foundation
import UserNotifications

final class NotificationManager: NSObject, UNUserNotificationCenterDelegate {
    weak var daemonConnection: DaemonConnection?

    private let center = UNUserNotificationCenter.current()
    private static let promptCategory = "CLAWDEFENDER_PROMPT"
    private static let alertCategory = "CLAWDEFENDER_ALERT"
    private static let allowAction = "ALLOW_ACTION"
    private static let denyAction = "DENY_ACTION"
    private static let viewAction = "VIEW_ACTION"

    override init() {
        super.init()
        center.delegate = self
        registerCategories()
    }

    func requestPermissions() {
        center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if let error = error {
                NSLog("ClawDefender: notification permission error: \(error)")
            }
        }
    }

    private func registerCategories() {
        let allowAction = UNNotificationAction(
            identifier: Self.allowAction,
            title: "Allow",
            options: []
        )
        let denyAction = UNNotificationAction(
            identifier: Self.denyAction,
            title: "Deny",
            options: [.destructive]
        )
        let promptCategory = UNNotificationCategory(
            identifier: Self.promptCategory,
            actions: [allowAction, denyAction],
            intentIdentifiers: [],
            options: []
        )

        let viewAction = UNNotificationAction(
            identifier: Self.viewAction,
            title: "View",
            options: [.foreground]
        )
        let alertCategory = UNNotificationCategory(
            identifier: Self.alertCategory,
            actions: [viewAction],
            intentIdentifiers: [],
            options: []
        )

        center.setNotificationCategories([promptCategory, alertCategory])
    }

    func showPromptNotification(eventSummary: String, ruleName: String) {
        let content = UNMutableNotificationContent()
        content.title = "ClawDefender - Approval Required"
        content.body = eventSummary
        content.sound = .default
        content.categoryIdentifier = Self.promptCategory
        content.userInfo = ["rule_name": ruleName, "type": "prompt"]

        let request = UNNotificationRequest(
            identifier: "prompt-\(ruleName)-\(Date().timeIntervalSince1970)",
            content: content,
            trigger: nil
        )
        center.add(request)
    }

    func showAlertNotification(severity: Severity, message: String, eventId: String) {
        let content = UNMutableNotificationContent()
        content.title = "ClawDefender - \(severity.rawValue) Alert"
        content.body = message
        content.sound = .default
        content.categoryIdentifier = Self.alertCategory
        content.userInfo = ["event_id": eventId, "type": "alert"]

        let request = UNNotificationRequest(
            identifier: "alert-\(eventId)",
            content: content,
            trigger: nil
        )
        center.add(request)
    }

    // MARK: - UNUserNotificationCenterDelegate

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let userInfo = response.notification.request.content.userInfo
        let actionIdentifier = response.actionIdentifier

        if let type = userInfo["type"] as? String {
            switch type {
            case "prompt":
                if let ruleName = userInfo["rule_name"] as? String {
                    let decision: UserDecision = (actionIdentifier == Self.allowAction) ? .AllowOnce : .DenyOnce
                    daemonConnection?.send(response: .Decision(event_id: ruleName, action: decision))
                }
            case "alert":
                // View action just brings app to foreground
                break
            default:
                break
            }
        }

        completionHandler()
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }
}
