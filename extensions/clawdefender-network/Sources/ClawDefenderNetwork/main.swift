// main.swift — ClawDefender Network Extension entry point.
//
// This is a macOS System Extension that hosts:
// - NEFilterDataProvider (content filter for TCP/UDP flows)
// - NEFilterControlProvider (user prompt handling)
// - NEDNSProxyProvider (DNS interception)
//
// The extension runs as a separate process managed by the system extension
// framework. It communicates with the ClawDefender daemon via XPC.

import Foundation
import NetworkExtension

// MARK: - Extension Entry Point

/// When running as a real system extension, the providers are instantiated
/// by the NetworkExtension framework based on Info.plist configuration.
/// This main.swift serves as the entry point and keeps the extension alive.
///
/// In mock mode (for development without entitlements), we simulate the
/// extension's behavior by reading from stdin or a Unix socket.

let isMockMode = CommandLine.arguments.contains("--mock")

if isMockMode {
    FlowLogger.shared.log(level: .info, message: "ClawDefender Network Extension starting in MOCK mode")
    runMockMode()
} else {
    FlowLogger.shared.log(level: .info, message: "ClawDefender Network Extension starting")

    // The NEProvider subclasses are loaded by the system based on the
    // NEProviderClasses key in Info.plist. We just need to keep the
    // extension process alive.
    autoreleasepool {
        NEProvider.startSystemExtensionMode()
    }

    // Keep the extension alive.
    dispatchMain()
}

// MARK: - Mock Mode

/// Simulates extension behavior for development. Reads simulated flow events
/// from stdin (JSON lines) and evaluates them against the daemon.
func runMockMode() {
    let daemonBridge = DaemonBridge(
        socketPath: "/tmp/clawdefender.sock",
        permissiveOnDisconnect: true
    )
    daemonBridge.connect()

    let processResolver = ProcessResolver(daemonBridge: daemonBridge)
    let policyEvaluator = PolicyEvaluator(daemonBridge: daemonBridge)
    FlowLogger.shared.daemonBridge = daemonBridge

    print("ClawDefender Network Extension (Mock Mode)")
    print("Enter JSON flow events or 'quit' to exit.")
    print("Format: {\"pid\": 1234, \"host\": \"example.com\", \"port\": 443}")
    print("")

    while let line = readLine() {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { continue }
        if trimmed == "quit" || trimmed == "exit" { break }

        guard let data = trimmed.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let pid = json["pid"] as? Int else {
            print("Error: invalid JSON. Expected {\"pid\": N, \"host\": \"...\", \"port\": N}")
            continue
        }

        let host = json["host"] as? String ?? "unknown"
        let port = UInt16(json["port"] as? Int ?? 0)

        Task {
            let (isAgent, serverName) = await processResolver.isAgentProcess(pid_t(pid))
            let processName = processResolver.processName(for: pid_t(pid))

            let flow = NetworkFlow(
                pid: pid_t(pid),
                processName: processName,
                serverName: serverName,
                destinationDomain: host,
                port: port
            )

            if !isAgent {
                FlowLogger.shared.logFlow(
                    flow: flow,
                    decision: .allow,
                    reason: "not an agent process"
                )
                print("  -> ALLOW (not an agent process)")
                return
            }

            let (decision, reason) = await policyEvaluator.evaluate(
                pid: pid_t(pid), host: host, port: port
            )

            FlowLogger.shared.logFlow(
                flow: flow,
                decision: decision,
                reason: reason
            )
            print("  -> \(decision.rawValue.uppercased()) (\(reason ?? "no reason"))")
        }
    }

    print("Mock mode exiting.")
}
