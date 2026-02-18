// FlowLogger.swift — Structured logging for network flow decisions.

import Foundation
import os.log

/// Log severity level.
enum LogLevel: String {
    case debug
    case info
    case warning
    case error
}

/// Singleton logger for network flow events. Writes structured entries to
/// both os_log (for Console.app / log stream) and to the daemon via IPC
/// for audit record creation.
final class FlowLogger: @unchecked Sendable {
    static let shared = FlowLogger()

    private let osLog = OSLog(
        subsystem: "com.clawdefender.network",
        category: "flows"
    )

    /// Reference set after initialization; used to forward flow logs to the daemon.
    var daemonBridge: DaemonBridge?

    private let dateFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    private init() {}

    // MARK: - Flow Logging

    /// Log a network flow decision.
    func logFlow(
        flow: NetworkFlow,
        decision: NetworkDecision,
        reason: String?,
        bytesTransferred: UInt64 = 0
    ) {
        let entry = FlowLogEntry(
            timestamp: dateFormatter.string(from: flow.timestamp),
            pid: flow.pid,
            processName: flow.processName,
            serverName: flow.serverName,
            destinationIP: flow.destinationIP,
            destinationDomain: flow.destinationDomain,
            port: flow.port,
            protocol: flow.protocol.rawValue,
            decision: decision.rawValue,
            reason: reason,
            bytesTransferred: bytesTransferred
        )

        // Log to os_log.
        let host = flow.destinationDomain ?? flow.destinationIP ?? "unknown"
        let message = "[\(decision.rawValue.uppercased())] pid=\(flow.pid) "
            + "process=\(flow.processName) "
            + "server=\(flow.serverName ?? "none") "
            + "dest=\(host):\(flow.port) "
            + "proto=\(flow.protocol.rawValue) "
            + "reason=\(reason ?? "none")"

        switch decision {
        case .allow:
            os_log(.info, log: osLog, "%{public}@", message)
        case .block:
            os_log(.error, log: osLog, "%{public}@", message)
        case .prompt:
            os_log(.default, log: osLog, "%{public}@", message)
        }

        // Forward to daemon for audit record creation.
        daemonBridge?.reportNetworkFlow(
            pid: flow.pid,
            host: host,
            port: flow.port,
            action: decision.rawValue,
            bytes: bytesTransferred
        )
    }

    // MARK: - General Logging

    /// Log a general message (not tied to a specific flow).
    func log(level: LogLevel, message: String) {
        switch level {
        case .debug:
            os_log(.debug, log: osLog, "%{public}@", message)
        case .info:
            os_log(.info, log: osLog, "%{public}@", message)
        case .warning:
            os_log(.default, log: osLog, "[WARN] %{public}@", message)
        case .error:
            os_log(.error, log: osLog, "[ERROR] %{public}@", message)
        }
    }
}
