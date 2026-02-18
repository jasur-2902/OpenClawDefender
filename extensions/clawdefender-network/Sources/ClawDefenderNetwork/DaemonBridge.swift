// DaemonBridge.swift — IPC bridge to the ClawDefender daemon.

import Foundation

// MARK: - XPC Protocol

/// Protocol for communicating with the ClawDefender daemon over XPC.
@objc protocol ClawDefenderNetworkProtocol {
    func isAgentProcess(_ pid: pid_t, reply: @escaping (Bool, String?) -> Void)
    func evaluateNetworkPolicy(pid: pid_t, host: String, port: UInt16,
                               reply: @escaping (String, String?) -> Void)
    func reportNetworkFlow(pid: pid_t, host: String, port: UInt16,
                          action: String, bytes: UInt64)
    func requestNetworkPermission(pid: pid_t, host: String, port: UInt16,
                                  serverName: String,
                                  reply: @escaping (String) -> Void)
}

// MARK: - DaemonBridge

/// Manages the connection to the ClawDefender daemon, supporting both XPC
/// and Unix domain socket transports with automatic reconnection.
///
/// SECURITY: XPC connection uses `NSXPCConnection(machServiceName:options:.privileged)`
/// which leverages macOS XPC security model. The mach service name
/// "com.clawdefender.daemon" is registered by the daemon's launchd plist,
/// ensuring only the legitimate daemon can claim this service name.
///
/// SECURITY: Fail-open design — when `permissiveOnDisconnect` is true (default),
/// all flows are allowed if the daemon is unreachable. This ensures ClawDefender
/// never breaks the user's network connectivity.
///
/// SECURITY: The extension never inspects encrypted content. It only passes
/// metadata (PID, host, port) to the daemon for policy evaluation.
final class DaemonBridge: @unchecked Sendable {
    /// Socket path for Unix domain socket IPC.
    private let socketPath: String

    /// Retry interval for reconnection attempts.
    private let reconnectInterval: TimeInterval

    /// Whether the daemon is currently reachable.
    private(set) var isConnected: Bool = false

    /// When true, all flows are allowed if the daemon is unreachable (fail-open).
    let permissiveOnDisconnect: Bool

    /// XPC connection (when using XPC transport).
    private var xpcConnection: NSXPCConnection?

    /// Lock for thread-safe access.
    private let lock = NSLock()

    init(
        socketPath: String = "/tmp/clawdefender.sock",
        reconnectInterval: TimeInterval = 5.0,
        permissiveOnDisconnect: Bool = true
    ) {
        self.socketPath = socketPath
        self.reconnectInterval = reconnectInterval
        self.permissiveOnDisconnect = permissiveOnDisconnect
    }

    // MARK: - Connection Management

    /// Establish XPC connection to the daemon.
    func connect() {
        lock.lock()
        defer { lock.unlock() }

        let connection = NSXPCConnection(
            machServiceName: "com.clawdefender.daemon",
            options: .privileged
        )
        connection.remoteObjectInterface = NSXPCInterface(
            with: ClawDefenderNetworkProtocol.self
        )
        connection.invalidationHandler = { [weak self] in
            self?.handleDisconnect()
        }
        connection.interruptionHandler = { [weak self] in
            self?.handleDisconnect()
        }
        connection.resume()
        xpcConnection = connection
        isConnected = true
        FlowLogger.shared.log(level: .info, message: "DaemonBridge: connected to daemon")
    }

    /// Handle a disconnect from the daemon. Schedules reconnection.
    private func handleDisconnect() {
        lock.lock()
        isConnected = false
        xpcConnection = nil
        lock.unlock()

        FlowLogger.shared.log(level: .warning, message: "DaemonBridge: disconnected from daemon")
        scheduleReconnect()
    }

    /// Schedule a reconnection attempt after the configured interval.
    private func scheduleReconnect() {
        DispatchQueue.global().asyncAfter(deadline: .now() + reconnectInterval) { [weak self] in
            guard let self = self else { return }
            if !self.isConnected {
                FlowLogger.shared.log(level: .info, message: "DaemonBridge: attempting reconnect")
                self.connect()
            }
        }
    }

    // MARK: - Daemon Queries

    /// Query the daemon to check if a PID is an agent process.
    func isAgentProcess(_ pid: pid_t) async -> (isAgent: Bool, serverName: String?) {
        guard isConnected else {
            // Fail-open: if daemon is unavailable, assume not an agent.
            return (false, nil)
        }

        return await withCheckedContinuation { continuation in
            guard let proxy = xpcConnection?.remoteObjectProxyWithErrorHandler({ error in
                FlowLogger.shared.log(
                    level: .error,
                    message: "DaemonBridge: XPC error querying agent status: \(error)"
                )
                continuation.resume(returning: (false, nil))
            }) as? ClawDefenderNetworkProtocol else {
                continuation.resume(returning: (false, nil))
                return
            }

            proxy.isAgentProcess(pid) { isAgent, serverName in
                continuation.resume(returning: (isAgent, serverName))
            }
        }
    }

    /// Evaluate network policy for a flow from an agent process.
    func evaluateNetworkPolicy(
        pid: pid_t,
        host: String,
        port: UInt16
    ) async -> (decision: String, reason: String?) {
        guard isConnected else {
            // Permissive mode when daemon is unavailable.
            return (permissiveOnDisconnect ? "allow" : "block",
                    "daemon unavailable")
        }

        return await withCheckedContinuation { continuation in
            guard let proxy = xpcConnection?.remoteObjectProxyWithErrorHandler({ error in
                FlowLogger.shared.log(
                    level: .error,
                    message: "DaemonBridge: XPC error evaluating policy: \(error)"
                )
                continuation.resume(returning: ("allow", "XPC error"))
            }) as? ClawDefenderNetworkProtocol else {
                continuation.resume(returning: ("allow", "no XPC proxy"))
                return
            }

            proxy.evaluateNetworkPolicy(pid: pid, host: host, port: port) { decision, reason in
                continuation.resume(returning: (decision, reason))
            }
        }
    }

    /// Request user permission for a network flow (prompt mode).
    func requestNetworkPermission(
        pid: pid_t,
        host: String,
        port: UInt16,
        serverName: String
    ) async -> String {
        guard isConnected else {
            // Default to block when daemon is unavailable and we need a prompt.
            return "block"
        }

        return await withCheckedContinuation { continuation in
            guard let proxy = xpcConnection?.remoteObjectProxyWithErrorHandler({ error in
                FlowLogger.shared.log(
                    level: .error,
                    message: "DaemonBridge: XPC error requesting permission: \(error)"
                )
                continuation.resume(returning: "block")
            }) as? ClawDefenderNetworkProtocol else {
                continuation.resume(returning: "block")
                return
            }

            proxy.requestNetworkPermission(
                pid: pid, host: host, port: port, serverName: serverName
            ) { decision in
                continuation.resume(returning: decision)
            }
        }
    }

    /// Report a completed network flow to the daemon for audit logging.
    func reportNetworkFlow(
        pid: pid_t,
        host: String,
        port: UInt16,
        action: String,
        bytes: UInt64
    ) {
        guard isConnected else { return }

        guard let proxy = xpcConnection?.remoteObjectProxyWithErrorHandler({ error in
            FlowLogger.shared.log(
                level: .error,
                message: "DaemonBridge: XPC error reporting flow: \(error)"
            )
        }) as? ClawDefenderNetworkProtocol else {
            return
        }

        proxy.reportNetworkFlow(
            pid: pid, host: host, port: port, action: action, bytes: bytes
        )
    }

    // MARK: - Security Verification

    /// Verify the identity of the daemon process via code signing.
    ///
    /// SECURITY: This method verifies that the XPC endpoint is served by a
    /// process signed with the expected team identifier and bundle ID.
    /// In production builds, this prevents a malicious process from
    /// impersonating the daemon over XPC.
    ///
    /// Note: This is a stub for the current development phase. Full
    /// implementation will use `SecCodeCopySigningInformation` and
    /// `SecRequirementCreateWithString` to validate the daemon's code
    /// signature against the expected team ID and bundle identifier.
    func verifyDaemonIdentity() -> Bool {
        guard let connection = xpcConnection else {
            FlowLogger.shared.log(
                level: .warning,
                message: "DaemonBridge: cannot verify identity — no XPC connection"
            )
            return false
        }

        // In production, this would:
        // 1. Get the remote process audit token from the XPC connection
        // 2. Create a SecCode from the audit token
        // 3. Validate against: anchor apple generic and
        //    identifier "com.clawdefender.daemon" and
        //    certificate leaf[subject.OU] = "<TEAM_ID>"
        // 4. Return false and disconnect if verification fails

        // For now, the XPC .privileged option provides basic protection
        // by requiring the daemon to be registered as a privileged
        // launchd service, which already requires root or admin install.
        FlowLogger.shared.log(
            level: .info,
            message: "DaemonBridge: daemon identity verification (stub) — relying on XPC privileged service registration"
        )
        return true
    }
}
