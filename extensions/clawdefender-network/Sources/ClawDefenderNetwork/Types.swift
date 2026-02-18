// Types.swift — Shared types for ClawDefender Network Extension.

import Foundation

// MARK: - Network Decision

/// The verdict for a network flow.
enum NetworkDecision: String, Codable {
    case allow
    case block
    case prompt
}

// MARK: - Network Flow

/// Describes a single network flow observed by the filter.
struct NetworkFlow: Codable {
    let pid: pid_t
    let processName: String
    let serverName: String?
    let destinationIP: String?
    let destinationDomain: String?
    let port: UInt16
    let `protocol`: FlowProtocol
    let timestamp: Date

    init(
        pid: pid_t,
        processName: String = "",
        serverName: String? = nil,
        destinationIP: String? = nil,
        destinationDomain: String? = nil,
        port: UInt16 = 0,
        protocol proto: FlowProtocol = .tcp,
        timestamp: Date = Date()
    ) {
        self.pid = pid
        self.processName = processName
        self.serverName = serverName
        self.destinationIP = destinationIP
        self.destinationDomain = destinationDomain
        self.port = port
        self.protocol = proto
        self.timestamp = timestamp
    }
}

/// Transport protocol for a flow.
enum FlowProtocol: String, Codable {
    case tcp
    case udp
    case quic
    case unknown
}

// MARK: - Policy Cache Entry

/// A cached network policy decision with TTL.
struct PolicyCacheEntry {
    let host: String
    let port: UInt16
    let decision: NetworkDecision
    let reason: String?
    let expiresAt: Date

    var isExpired: Bool {
        Date() > expiresAt
    }
}

// MARK: - Process Cache Entry

/// Cached information about whether a PID is an agent process.
struct ProcessCacheEntry {
    let isAgent: Bool
    let serverName: String?
    let expiresAt: Date

    var isExpired: Bool {
        Date() > expiresAt
    }
}

// MARK: - Daemon IPC Messages

/// Request sent to the ClawDefender daemon over XPC / Unix socket.
struct DaemonIPCRequest: Codable {
    let type_: String
    let pid: pid_t?
    let host: String?
    let port: UInt16?
    let serverName: String?
    let action: String?
    let bytes: UInt64?

    enum CodingKeys: String, CodingKey {
        case type_ = "type"
        case pid, host, port, serverName, action, bytes
    }
}

/// Response from the ClawDefender daemon.
struct DaemonIPCResponse: Codable {
    let isAgent: Bool?
    let serverName: String?
    let decision: String?
    let reason: String?
    let error: String?
}

// MARK: - Flow Log Entry

/// A structured log entry for a network flow decision.
struct FlowLogEntry: Codable {
    let timestamp: String
    let pid: pid_t
    let processName: String
    let serverName: String?
    let destinationIP: String?
    let destinationDomain: String?
    let port: UInt16
    let `protocol`: String
    let decision: String
    let reason: String?
    let bytesTransferred: UInt64?
}
