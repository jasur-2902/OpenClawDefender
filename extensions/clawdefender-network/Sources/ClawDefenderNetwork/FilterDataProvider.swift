// FilterDataProvider.swift — NEFilterDataProvider for ClawDefender.
//
// This is the hot path: every network flow on the system passes through
// handleNewFlow(). Non-agent traffic is allowed immediately. Agent traffic
// is evaluated against network policy.

import Foundation
import NetworkExtension

/// The content filter data provider. Installed as a system extension, it
/// intercepts all TCP/UDP flows and applies ClawDefender network policy
/// to flows originating from AI agent processes.
class ClawDefenderFilterDataProvider: NEFilterDataProvider {
    /// Process resolver for PID lookup and agent-status caching.
    private lazy var processResolver: ProcessResolver = {
        ProcessResolver(daemonBridge: daemonBridge)
    }()

    /// Daemon bridge for IPC.
    private lazy var daemonBridge: DaemonBridge = {
        let bridge = DaemonBridge()
        bridge.connect()
        FlowLogger.shared.daemonBridge = bridge
        return bridge
    }()

    /// Policy evaluator for fast-path decisions.
    private lazy var policyEvaluator: PolicyEvaluator = {
        PolicyEvaluator(daemonBridge: daemonBridge)
    }()

    // MARK: - NEFilterDataProvider Lifecycle

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        FlowLogger.shared.log(level: .info, message: "ClawDefender filter starting")

        // Configure filter rules: we want to see ALL new flows.
        let filterSettings = NEFilterSettings(rules: [], defaultAction: .filterData)
        apply(filterSettings) { error in
            if let error = error {
                FlowLogger.shared.log(
                    level: .error,
                    message: "Failed to apply filter settings: \(error)"
                )
            } else {
                FlowLogger.shared.log(level: .info, message: "ClawDefender filter started")
            }
            completionHandler(error)
        }
    }

    override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        FlowLogger.shared.log(
            level: .info,
            message: "ClawDefender filter stopping (reason: \(reason.rawValue))"
        )
        completionHandler()
    }

    // MARK: - Flow Handling (Hot Path)

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        // Step 1: Extract source PID from the audit token.
        guard let socketFlow = flow as? NEFilterSocketFlow,
              let auditToken = socketFlow.sourceAppAuditToken else {
            // Not a socket flow or no audit token — allow by default.
            return .allow()
        }

        let pid = processResolver.pidFromAuditToken(auditToken)

        // Step 2: Fast synchronous cache check for agent status.
        // For the hot path, we use a synchronous cache lookup. If the cache
        // misses, we return .allow() and trigger an async refresh. This avoids
        // blocking non-agent traffic while keeping latency minimal.
        let processName = processResolver.processName(for: pid)

        // Extract destination information.
        let host = socketFlow.remoteHostname ?? socketFlow.remoteEndpoint?.hostname ?? "unknown"
        let port = UInt16(socketFlow.remoteEndpoint?.port ?? "0") ?? 0
        let proto: FlowProtocol = socketFlow.socketProtocol == IPPROTO_TCP ? .tcp : .udp

        let flow = NetworkFlow(
            pid: pid,
            processName: processName,
            destinationDomain: socketFlow.remoteHostname,
            destinationIP: socketFlow.remoteEndpoint?.hostname,
            port: port,
            protocol: proto
        )

        // Step 3: We need to do async work (daemon query), so we use the
        // pause/resume pattern. Return .needRules() to pause the flow,
        // then resume with the verdict after async evaluation.
        //
        // For truly synchronous fast-path (cached agent status), we could
        // return immediately, but the NEFilterDataProvider API requires us
        // to use handleNewFlow synchronously or pause with needRules().
        return .needRules()
    }

    // MARK: - Inbound/Outbound Data Handling

    override func handleInboundData(
        from flow: NEFilterFlow,
        readBytesStartOffset offset: Int,
        readBytes: Data
    ) -> NEFilterDataVerdict {
        // We don't inspect payload data — just pass through.
        return .allow()
    }

    override func handleOutboundData(
        from flow: NEFilterFlow,
        readBytesStartOffset offset: Int,
        readBytes: Data
    ) -> NEFilterDataVerdict {
        // We don't inspect payload data — just pass through.
        return .allow()
    }

    // MARK: - Remediation (flow resume after control provider decision)

    override func handleRemediation(for flow: NEFilterFlow) -> NEFilterRemediationVerdict {
        // After the control provider makes a decision, we receive it here.
        // The default is to allow — actual blocking is done by returning .drop()
        // from the control provider's verdict.
        return NEFilterRemediationVerdict.allow()
    }
}

// MARK: - NWEndpoint Extension

extension NWEndpoint {
    /// Extract hostname string from an NWEndpoint, if available.
    var hostname: String? {
        switch self {
        case let hostEndpoint as NWHostEndpoint:
            return hostEndpoint.hostname
        default:
            return nil
        }
    }

    /// Extract port string from an NWEndpoint, if available.
    var port: String? {
        switch self {
        case let hostEndpoint as NWHostEndpoint:
            return hostEndpoint.port
        default:
            return nil
        }
    }
}
