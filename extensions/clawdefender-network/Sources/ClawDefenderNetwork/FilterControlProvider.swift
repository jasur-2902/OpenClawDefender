// FilterControlProvider.swift — NEFilterControlProvider for ClawDefender.
//
// Handles flows that require user decision (prompt mode). When the data
// provider returns .needRules(), the control provider receives the flow
// and can make the final verdict after consulting the daemon.

import Foundation
import NetworkExtension

/// The content filter control provider. Handles flows escalated from the
/// data provider that need user-prompted decisions.
class ClawDefenderFilterControlProvider: NEFilterControlProvider {
    /// Daemon bridge for requesting user permission.
    private lazy var daemonBridge: DaemonBridge = {
        let bridge = DaemonBridge()
        bridge.connect()
        return bridge
    }()

    /// Process resolver for PID extraction.
    private lazy var processResolver: ProcessResolver = {
        ProcessResolver(daemonBridge: daemonBridge)
    }()

    /// Policy evaluator for local fast-path checks.
    private lazy var policyEvaluator: PolicyEvaluator = {
        PolicyEvaluator(daemonBridge: daemonBridge)
    }()

    /// Timeout for user prompts (seconds). Default to BLOCK on timeout.
    private let promptTimeout: TimeInterval = 30.0

    // MARK: - NEFilterControlProvider Lifecycle

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        FlowLogger.shared.log(
            level: .info,
            message: "ClawDefender control provider starting"
        )
        completionHandler(nil)
    }

    override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        FlowLogger.shared.log(
            level: .info,
            message: "ClawDefender control provider stopping (reason: \(reason.rawValue))"
        )
        completionHandler()
    }

    // MARK: - Flow Rule Handling

    override func handleNewFlow(
        _ flow: NEFilterFlow,
        completionHandler: @escaping (NEFilterControlVerdict) -> Void
    ) {
        // Extract flow details.
        guard let socketFlow = flow as? NEFilterSocketFlow,
              let auditToken = socketFlow.sourceAppAuditToken else {
            // No audit token — allow by default.
            completionHandler(.allow(withUpdateRules: false))
            return
        }

        let pid = processResolver.pidFromAuditToken(auditToken)
        let processName = processResolver.processName(for: pid)
        let host = socketFlow.remoteHostname
            ?? socketFlow.remoteEndpoint?.hostname
            ?? "unknown"
        let port = UInt16(socketFlow.remoteEndpoint?.port ?? "0") ?? 0

        // Perform async evaluation.
        Task {
            // First check if this PID is an agent process.
            let (isAgent, serverName) = await processResolver.isAgentProcess(pid)

            if !isAgent {
                // Not an agent process — allow immediately.
                let flow = NetworkFlow(
                    pid: pid,
                    processName: processName,
                    destinationDomain: socketFlow.remoteHostname,
                    destinationIP: socketFlow.remoteEndpoint?.hostname,
                    port: port
                )
                FlowLogger.shared.logFlow(
                    flow: flow,
                    decision: .allow,
                    reason: "not an agent process"
                )
                completionHandler(.allow(withUpdateRules: false))
                return
            }

            // Agent process — evaluate network policy.
            let (decision, reason) = await policyEvaluator.evaluate(
                pid: pid, host: host, port: port
            )

            let networkFlow = NetworkFlow(
                pid: pid,
                processName: processName,
                serverName: serverName,
                destinationDomain: socketFlow.remoteHostname,
                destinationIP: socketFlow.remoteEndpoint?.hostname,
                port: port
            )

            switch decision {
            case .allow:
                FlowLogger.shared.logFlow(
                    flow: networkFlow,
                    decision: .allow,
                    reason: reason
                )
                completionHandler(.allow(withUpdateRules: false))

            case .block:
                FlowLogger.shared.logFlow(
                    flow: networkFlow,
                    decision: .block,
                    reason: reason
                )
                completionHandler(.drop(withUpdateRules: false))

            case .prompt:
                // Request user permission via daemon. Block on timeout.
                let promptDecision = await self.requestUserPermission(
                    pid: pid,
                    host: host,
                    port: port,
                    serverName: serverName ?? "unknown"
                )

                let finalDecision: NetworkDecision =
                    promptDecision == "allow" ? .allow : .block

                FlowLogger.shared.logFlow(
                    flow: networkFlow,
                    decision: finalDecision,
                    reason: "user prompt: \(promptDecision)"
                )

                if finalDecision == .allow {
                    completionHandler(.allow(withUpdateRules: false))
                } else {
                    completionHandler(.drop(withUpdateRules: false))
                }
            }
        }
    }

    // MARK: - User Permission Request

    /// Request permission from the user via the daemon, with a timeout.
    /// Defaults to "block" if the daemon is unavailable or the user doesn't respond.
    private func requestUserPermission(
        pid: pid_t,
        host: String,
        port: UInt16,
        serverName: String
    ) async -> String {
        return await withTaskGroup(of: String.self) { group in
            // Task 1: Request permission from daemon.
            group.addTask {
                await self.daemonBridge.requestNetworkPermission(
                    pid: pid, host: host, port: port, serverName: serverName
                )
            }

            // Task 2: Timeout.
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(self.promptTimeout * 1_000_000_000))
                return "block"  // Default to block on timeout.
            }

            // Return whichever finishes first.
            let result = await group.next() ?? "block"
            group.cancelAll()
            return result
        }
    }
}
