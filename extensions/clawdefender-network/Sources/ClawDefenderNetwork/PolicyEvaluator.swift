// PolicyEvaluator.swift — Local fast-path network policy evaluation.

import Foundation

/// Evaluates network policy locally using cached rules, with fallback to
/// the daemon for decisions not covered by the local cache.
final class PolicyEvaluator {
    /// Hosts that are always allowed (localhost variants).
    private static let alwaysAllowHosts: Set<String> = [
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
    ]

    /// Blocked hosts from IoC threat feed. Updated periodically by the daemon.
    private var blockedHosts: Set<String> = []
    private let blockedHostsLock = NSLock()

    /// Policy cache: (host, port) -> decision with TTL.
    private var policyCache: [String: PolicyCacheEntry] = []
    private let policyCacheLock = NSLock()

    /// Default TTL for cached policy decisions (seconds).
    private let defaultCacheTTL: TimeInterval

    /// Reference to the daemon bridge for non-cached decisions.
    private let daemonBridge: DaemonBridge

    init(daemonBridge: DaemonBridge, cacheTTL: TimeInterval = 30.0) {
        self.daemonBridge = daemonBridge
        self.defaultCacheTTL = cacheTTL
    }

    // MARK: - Policy Evaluation

    /// Evaluate network policy for a flow. Returns the decision and reason.
    ///
    /// Evaluation order:
    /// 1. Always-allow (localhost)
    /// 2. Always-block (IoC blocklist)
    /// 3. Policy cache hit
    /// 4. Query daemon
    func evaluate(
        pid: pid_t,
        host: String,
        port: UInt16
    ) async -> (decision: NetworkDecision, reason: String?) {
        // 1. Always-allow: localhost variants.
        if Self.alwaysAllowHosts.contains(host.lowercased()) {
            return (.allow, "localhost always allowed")
        }

        // 2. Always-block: IoC/threat feed blocklist.
        blockedHostsLock.lock()
        let isBlocked = blockedHosts.contains(host.lowercased())
        blockedHostsLock.unlock()

        if isBlocked {
            return (.block, "host on IoC blocklist")
        }

        // 3. Check policy cache.
        let cacheKey = "\(host.lowercased()):\(port)"
        policyCacheLock.lock()
        if let entry = policyCache[cacheKey], !entry.isExpired {
            policyCacheLock.unlock()
            return (entry.decision, entry.reason)
        }
        policyCacheLock.unlock()

        // 4. Query daemon for policy decision.
        let (decisionStr, reason) = await daemonBridge.evaluateNetworkPolicy(
            pid: pid, host: host, port: port
        )

        let decision: NetworkDecision
        switch decisionStr.lowercased() {
        case "allow": decision = .allow
        case "block": decision = .block
        case "prompt": decision = .prompt
        default: decision = .allow
        }

        // Cache the decision (except for "prompt" which needs fresh evaluation).
        if decision != .prompt {
            let entry = PolicyCacheEntry(
                host: host,
                port: port,
                decision: decision,
                reason: reason,
                expiresAt: Date().addingTimeInterval(defaultCacheTTL)
            )
            policyCacheLock.lock()
            policyCache[cacheKey] = entry
            policyCacheLock.unlock()
        }

        return (decision, reason)
    }

    // MARK: - Blocklist Management

    /// Update the IoC blocklist with a new set of blocked hosts.
    func updateBlockedHosts(_ hosts: Set<String>) {
        blockedHostsLock.lock()
        blockedHosts = Set(hosts.map { $0.lowercased() })
        blockedHostsLock.unlock()

        FlowLogger.shared.log(
            level: .info,
            message: "PolicyEvaluator: updated blocklist with \(hosts.count) hosts"
        )
    }

    /// Add a single host to the blocklist.
    func addBlockedHost(_ host: String) {
        blockedHostsLock.lock()
        blockedHosts.insert(host.lowercased())
        blockedHostsLock.unlock()
    }

    // MARK: - Cache Management

    /// Invalidate all cached policy decisions.
    func invalidateCache() {
        policyCacheLock.lock()
        policyCache.removeAll()
        policyCacheLock.unlock()
    }

    /// Remove expired entries from the policy cache.
    func pruneExpiredCache() {
        policyCacheLock.lock()
        policyCache = policyCache.filter { !$0.value.isExpired }
        policyCacheLock.unlock()
    }
}
