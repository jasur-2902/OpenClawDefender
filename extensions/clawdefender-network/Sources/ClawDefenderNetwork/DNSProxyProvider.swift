// DNSProxyProvider.swift — NEDNSProxyProvider for ClawDefender.
//
// Intercepts DNS queries from agent processes to enforce domain-level
// policy: blocked domains return NXDOMAIN, allowed domains are forwarded
// to the system resolver.

import Foundation
import NetworkExtension

/// DNS proxy provider that intercepts DNS lookups from AI agent processes
/// and applies domain filtering based on IoC blocklists and user policy.
class ClawDefenderDNSProxyProvider: NEDNSProxyProvider {
    /// Daemon bridge for agent status and policy queries.
    private lazy var daemonBridge: DaemonBridge = {
        let bridge = DaemonBridge()
        bridge.connect()
        return bridge
    }()

    /// Process resolver for PID lookups.
    private lazy var processResolver: ProcessResolver = {
        ProcessResolver(daemonBridge: daemonBridge)
    }()

    /// Blocked domains from IoC feed + user blocklist.
    private var blockedDomains: Set<String> = []
    private let blockedDomainsLock = NSLock()

    /// User-configured allowed domains (override for blocked domains).
    private var allowedDomains: Set<String> = []
    private let allowedDomainsLock = NSLock()

    // MARK: - NEDNSProxyProvider Lifecycle

    override func startProxy(
        options: [String: Any]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        FlowLogger.shared.log(level: .info, message: "ClawDefender DNS proxy starting")
        completionHandler(nil)
    }

    override func stopProxy(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        FlowLogger.shared.log(
            level: .info,
            message: "ClawDefender DNS proxy stopping (reason: \(reason.rawValue))"
        )
        completionHandler()
    }

    // MARK: - DNS Flow Handling

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let udpFlow = flow as? NEAppProxyUDPFlow else {
            // Not a UDP flow (DNS is UDP) — don't handle.
            return false
        }

        // Check if this flow is to a DNS port (53).
        // The flow's remoteEndpoint indicates where it's going.
        // We intercept DNS flows to port 53.

        Task {
            await handleDNSFlow(udpFlow)
        }

        return true  // We're handling this flow.
    }

    // MARK: - DNS Processing

    /// Handle a DNS UDP flow: read the query, evaluate, and respond.
    private func handleDNSFlow(_ flow: NEAppProxyUDPFlow) async {
        // Open the flow.
        do {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                flow.open(withLocalEndpoint: nil) { error in
                    if let error = error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume()
                    }
                }
            }
        } catch {
            FlowLogger.shared.log(
                level: .error,
                message: "DNS proxy: failed to open flow: \(error)"
            )
            return
        }

        // Read datagrams from the flow.
        do {
            let (datagrams, endpoints) = try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<([Data], [NWEndpoint]), Error>) in
                flow.readDatagrams { datagrams, endpoints, error in
                    if let error = error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume(returning: (datagrams ?? [], endpoints ?? []))
                    }
                }
            }

            for (index, datagram) in datagrams.enumerated() {
                let endpoint = index < endpoints.count ? endpoints[index] : nil
                await processDNSQuery(
                    datagram: datagram,
                    endpoint: endpoint,
                    flow: flow
                )
            }
        } catch {
            FlowLogger.shared.log(
                level: .error,
                message: "DNS proxy: failed to read datagrams: \(error)"
            )
        }
    }

    /// Process a single DNS query datagram.
    private func processDNSQuery(
        datagram: Data,
        endpoint: NWEndpoint?,
        flow: NEAppProxyUDPFlow
    ) async {
        // Parse the DNS query to extract the queried domain.
        guard let domain = extractDomainFromDNSQuery(datagram) else {
            // Can't parse — forward as-is to system resolver.
            if let endpoint = endpoint {
                flow.writeDatagrams([datagram], sentBy: [endpoint]) { _ in }
            }
            return
        }

        // Check if the domain is blocked.
        let isBlocked = isDomainBlocked(domain)

        if isBlocked {
            FlowLogger.shared.log(
                level: .warning,
                message: "DNS proxy: BLOCKED query for \(domain)"
            )

            // Return NXDOMAIN response.
            let nxdomainResponse = buildNXDOMAINResponse(for: datagram)
            if let endpoint = endpoint {
                flow.writeDatagrams([nxdomainResponse], sentBy: [endpoint]) { _ in }
            }
            return
        }

        // Domain is allowed — forward to system resolver.
        if let endpoint = endpoint {
            flow.writeDatagrams([datagram], sentBy: [endpoint]) { _ in }
        }
    }

    // MARK: - Domain Checking

    /// Check if a domain is on the blocklist and not on the allowlist.
    private func isDomainBlocked(_ domain: String) -> Bool {
        let lowered = domain.lowercased()

        // Check user allowlist first (override).
        allowedDomainsLock.lock()
        let isAllowed = allowedDomains.contains(lowered)
            || allowedDomains.contains(where: { lowered.hasSuffix(".\($0)") })
        allowedDomainsLock.unlock()

        if isAllowed {
            return false
        }

        // Check blocklist.
        blockedDomainsLock.lock()
        let blocked = blockedDomains.contains(lowered)
            || blockedDomains.contains(where: { lowered.hasSuffix(".\($0)") })
        blockedDomainsLock.unlock()

        return blocked
    }

    // MARK: - Blocklist Management

    /// Update the blocked domains list from IoC feed.
    func updateBlockedDomains(_ domains: Set<String>) {
        blockedDomainsLock.lock()
        blockedDomains = Set(domains.map { $0.lowercased() })
        blockedDomainsLock.unlock()

        FlowLogger.shared.log(
            level: .info,
            message: "DNS proxy: updated blocklist with \(domains.count) domains"
        )
    }

    /// Update the user-allowed domains (override list).
    func updateAllowedDomains(_ domains: Set<String>) {
        allowedDomainsLock.lock()
        allowedDomains = Set(domains.map { $0.lowercased() })
        allowedDomainsLock.unlock()
    }

    // MARK: - DNS Parsing Helpers

    /// Extract the queried domain name from a DNS query packet.
    /// Returns nil if the packet can't be parsed.
    private func extractDomainFromDNSQuery(_ data: Data) -> String? {
        // DNS packet structure:
        // - Header: 12 bytes
        // - Question section: name + type (2) + class (2)
        guard data.count > 12 else { return nil }

        var offset = 12  // Skip header.
        var labels: [String] = []

        while offset < data.count {
            let length = Int(data[offset])
            if length == 0 {
                break  // End of name.
            }
            offset += 1

            guard offset + length <= data.count else { return nil }

            let labelData = data[offset..<(offset + length)]
            guard let label = String(data: labelData, encoding: .ascii) else {
                return nil
            }
            labels.append(label)
            offset += length
        }

        return labels.isEmpty ? nil : labels.joined(separator: ".")
    }

    /// Build an NXDOMAIN DNS response for the given query.
    private func buildNXDOMAINResponse(for query: Data) -> Data {
        guard query.count >= 12 else { return query }

        var response = query
        // Set QR bit (response) and RCODE = 3 (NXDOMAIN).
        // Byte 2: QR=1, Opcode=0000, AA=1, TC=0, RD=1 -> 0x85
        // Byte 3: RA=1, Z=000, RCODE=0011 -> 0x83
        response[2] = 0x85
        response[3] = 0x83

        // Zero out answer, authority, and additional counts.
        response[6] = 0; response[7] = 0   // ANCOUNT
        response[8] = 0; response[9] = 0   // NSCOUNT
        response[10] = 0; response[11] = 0 // ARCOUNT

        return response
    }
}
