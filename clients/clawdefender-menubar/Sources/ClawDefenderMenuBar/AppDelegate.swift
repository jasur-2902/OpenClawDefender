import AppKit

class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusBarController: StatusBarController!
    private var daemonConnection: DaemonConnection!
    private var notificationManager: NotificationManager!

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusBarController = StatusBarController()
        daemonConnection = DaemonConnection()
        notificationManager = NotificationManager()

        daemonConnection.delegate = statusBarController
        statusBarController.daemonConnection = daemonConnection
        statusBarController.notificationManager = notificationManager
        notificationManager.daemonConnection = daemonConnection

        notificationManager.requestPermissions()
        daemonConnection.connect()
    }

    func applicationWillTerminate(_ notification: Notification) {
        daemonConnection.disconnect()
    }
}
