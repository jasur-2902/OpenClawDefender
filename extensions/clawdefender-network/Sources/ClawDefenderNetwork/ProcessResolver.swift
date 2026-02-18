// ProcessResolver.swift — Resolve PIDs from audit tokens and cache agent status.

import Foundation

/// Resolves process identifiers from audit tokens and maintains a cache of
/// agent-process lookups with a configurable TTL.
final class ProcessResolver {
    /// TTL for cached process lookups (seconds).
    private let cacheTTL: TimeInterval

    /// PID -> cached agent status.
    private var cache: [pid_t: ProcessCacheEntry] = [:]
    private let lock = NSLock()

    /// Reference to the daemon bridge for querying agent status.
    private let daemonBridge: DaemonBridge

    init(daemonBridge: DaemonBridge, cacheTTL: TimeInterval = 1.0) {
        self.daemonBridge = daemonBridge
        self.cacheTTL = cacheTTL
    }

    // MARK: - Audit Token Resolution

    /// Extract PID from an audit_token_t.
    ///
    /// Uses the BSM `audit_token_to_pid()` function available on macOS.
    func pidFromAuditToken(_ token: audit_token_t) -> pid_t {
        return audit_token_to_pid(token)
    }

    // MARK: - Agent Status Lookup

    /// Check if the given PID is an agent process. Returns cached result if
    /// available and not expired, otherwise queries the daemon.
    func isAgentProcess(_ pid: pid_t) async -> (isAgent: Bool, serverName: String?) {
        // Check cache first.
        lock.lock()
        if let entry = cache[pid], !entry.isExpired {
            lock.unlock()
            return (entry.isAgent, entry.serverName)
        }
        lock.unlock()

        // Query daemon.
        let result = await daemonBridge.isAgentProcess(pid)

        // Cache the result.
        let entry = ProcessCacheEntry(
            isAgent: result.isAgent,
            serverName: result.serverName,
            expiresAt: Date().addingTimeInterval(cacheTTL)
        )
        lock.lock()
        cache[pid] = entry
        lock.unlock()

        return result
    }

    /// Invalidate the cache entry for a specific PID (e.g., on process exit).
    func invalidate(pid: pid_t) {
        lock.lock()
        cache.removeValue(forKey: pid)
        lock.unlock()
    }

    /// Remove all expired entries from the cache.
    func pruneExpired() {
        lock.lock()
        let now = Date()
        cache = cache.filter { !$0.value.isExpired || $0.value.expiresAt > now }
        lock.unlock()
    }

    /// Get the process name for a PID via procinfo.
    func processName(for pid: pid_t) -> String {
        let pathBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PROC_PIDPATHINFO_MAXSIZE))
        defer { pathBuffer.deallocate() }

        let pathLength = proc_pidpath(pid, pathBuffer, UInt32(PROC_PIDPATHINFO_MAXSIZE))
        if pathLength > 0 {
            let path = String(cString: pathBuffer)
            return (path as NSString).lastPathComponent
        }
        return "unknown(\(pid))"
    }
}
