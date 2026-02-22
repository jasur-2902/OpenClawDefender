//! Network connection logging and forensics types.
//!
//! Provides structured types for logging every network connection decision,
//! traffic statistics per server, and summary aggregation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single network connection log entry.
///
/// SECURITY: This struct contains connection metadata only — IP addresses,
/// ports, domains, byte counts, and policy decisions. It explicitly does NOT
/// contain any request/response body, payload content, or application-layer
/// data. This is enforced by the type system: there are no fields for content.
///
/// SECURITY: All logs are stored locally only and never transmitted unless
/// the user explicitly opts into telemetry (aggregated counts only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectionLog {
    /// Fixed event type identifier.
    pub event_type: String,
    /// When the connection event occurred.
    pub timestamp: DateTime<Utc>,
    /// Process ID of the originating process.
    pub pid: u32,
    /// Name of the originating process.
    pub process_name: String,
    /// MCP server name, if applicable.
    pub server_name: Option<String>,
    /// MCP client name, if applicable.
    pub client_name: Option<String>,
    /// Connection details (protocol, addresses, TLS).
    pub connection: ConnectionInfo,
    /// The policy decision for this connection.
    pub decision: ConnectionDecision,
    /// Total bytes sent during this connection.
    pub bytes_sent: u64,
    /// Total bytes received during this connection.
    pub bytes_received: u64,
    /// Duration of the connection in milliseconds.
    pub duration_ms: u64,
}

/// Low-level connection information.
///
/// SECURITY: Metadata only — protocol, addresses, ports, TLS flag. No content
/// inspection is performed. The `tls` field indicates whether TLS was negotiated,
/// but ClawDefender never decrypts or intercepts TLS traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// Transport protocol: "tcp", "udp".
    pub protocol: String,
    /// Source IP address, if known.
    pub source_ip: Option<String>,
    /// Source port, if known.
    pub source_port: Option<u16>,
    /// Destination IP address.
    pub destination_ip: String,
    /// Destination port.
    pub destination_port: u16,
    /// Destination domain name, if resolved.
    pub destination_domain: Option<String>,
    /// Whether TLS was used.
    pub tls: bool,
}

/// The decision applied to a connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionDecision {
    /// Action taken: "allowed", "blocked", "prompted".
    pub action: String,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// Name of the policy rule that matched, if any.
    pub rule: Option<String>,
    /// Signals that contributed to the decision.
    pub signals: DecisionSignals,
}

/// Signals contributing to a connection decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionSignals {
    /// Whether an IoC (Indicator of Compromise) matched.
    pub ioc_match: bool,
    /// Anomaly score from the behavioral engine (0.0 - 1.0).
    pub anomaly_score: Option<f64>,
    /// Behavioral context description.
    pub behavioral: Option<String>,
    /// Kill chain stage if applicable.
    pub kill_chain: Option<String>,
}

/// Traffic statistics for a single server over a time period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTrafficStats {
    /// Name of the MCP server.
    pub server_name: String,
    /// Total number of connections.
    pub total_connections: u64,
    /// Connections that were allowed.
    pub connections_allowed: u64,
    /// Connections that were blocked.
    pub connections_blocked: u64,
    /// Connections that were prompted.
    pub connections_prompted: u64,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Number of unique destination addresses.
    pub unique_destinations: u32,
    /// Time period for the stats (e.g. "last_24h").
    pub period: String,
}

/// Summary of network activity over a time period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSummary {
    /// Total connections allowed.
    pub total_allowed: u64,
    /// Total connections blocked.
    pub total_blocked: u64,
    /// Total connections prompted.
    pub total_prompted: u64,
    /// Top destinations by connection count.
    pub top_destinations: Vec<(String, u64)>,
    /// Time period for the summary.
    pub period: String,
}

impl NetworkSummary {
    /// Aggregate a summary from a slice of connection logs.
    pub fn from_logs(logs: &[NetworkConnectionLog], period: &str) -> Self {
        let mut total_allowed = 0u64;
        let mut total_blocked = 0u64;
        let mut total_prompted = 0u64;
        let mut dest_counts: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();

        for log in logs {
            match log.decision.action.as_str() {
                "allowed" => total_allowed += 1,
                "blocked" => total_blocked += 1,
                "prompted" => total_prompted += 1,
                _ => {}
            }

            let dest = log
                .connection
                .destination_domain
                .as_deref()
                .unwrap_or(&log.connection.destination_ip);
            *dest_counts.entry(dest.to_string()).or_default() += 1;
        }

        let mut top_destinations: Vec<(String, u64)> = dest_counts.into_iter().collect();
        top_destinations.sort_by(|a, b| b.1.cmp(&a.1));
        top_destinations.truncate(10);

        NetworkSummary {
            total_allowed,
            total_blocked,
            total_prompted,
            top_destinations,
            period: period.to_string(),
        }
    }
}

impl NetworkTrafficStats {
    /// Aggregate traffic stats for a specific server from a slice of connection logs.
    pub fn from_logs(logs: &[NetworkConnectionLog], server_name: &str, period: &str) -> Self {
        let mut stats = NetworkTrafficStats {
            server_name: server_name.to_string(),
            total_connections: 0,
            connections_allowed: 0,
            connections_blocked: 0,
            connections_prompted: 0,
            bytes_sent: 0,
            bytes_received: 0,
            unique_destinations: 0,
            period: period.to_string(),
        };

        let mut unique_dests: std::collections::HashSet<String> = std::collections::HashSet::new();

        for log in logs {
            if log.server_name.as_deref() != Some(server_name) {
                continue;
            }

            stats.total_connections += 1;
            match log.decision.action.as_str() {
                "allowed" => stats.connections_allowed += 1,
                "blocked" => stats.connections_blocked += 1,
                "prompted" => stats.connections_prompted += 1,
                _ => {}
            }
            stats.bytes_sent += log.bytes_sent;
            stats.bytes_received += log.bytes_received;

            let dest = log
                .connection
                .destination_domain
                .as_deref()
                .unwrap_or(&log.connection.destination_ip);
            unique_dests.insert(dest.to_string());
        }

        stats.unique_destinations = unique_dests.len() as u32;
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_log(
        action: &str,
        dest_ip: &str,
        dest_domain: Option<&str>,
        server: Option<&str>,
        bytes_sent: u64,
        bytes_received: u64,
    ) -> NetworkConnectionLog {
        NetworkConnectionLog {
            event_type: "network_connection".to_string(),
            timestamp: Utc::now(),
            pid: 1234,
            process_name: "test-process".to_string(),
            server_name: server.map(|s| s.to_string()),
            client_name: None,
            connection: ConnectionInfo {
                protocol: "tcp".to_string(),
                source_ip: Some("192.168.1.100".to_string()),
                source_port: Some(54321),
                destination_ip: dest_ip.to_string(),
                destination_port: 443,
                destination_domain: dest_domain.map(|d| d.to_string()),
                tls: true,
            },
            decision: ConnectionDecision {
                action: action.to_string(),
                reason: "test reason".to_string(),
                rule: None,
                signals: DecisionSignals {
                    ioc_match: false,
                    anomaly_score: None,
                    behavioral: None,
                    kill_chain: None,
                },
            },
            bytes_sent,
            bytes_received,
            duration_ms: 100,
        }
    }

    #[test]
    fn test_network_connection_log_serialization() {
        let log = make_log(
            "allowed",
            "93.184.216.34",
            Some("example.com"),
            Some("filesystem"),
            1024,
            2048,
        );

        let json = serde_json::to_string(&log).unwrap();
        assert!(json.contains("network_connection"));
        assert!(json.contains("example.com"));
        assert!(json.contains("allowed"));

        let deserialized: NetworkConnectionLog = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.event_type, "network_connection");
        assert_eq!(
            deserialized.connection.destination_domain.as_deref(),
            Some("example.com")
        );
        assert_eq!(deserialized.decision.action, "allowed");
        assert_eq!(deserialized.bytes_sent, 1024);
        assert_eq!(deserialized.bytes_received, 2048);
    }

    #[test]
    fn test_connection_info_serialization() {
        let info = ConnectionInfo {
            protocol: "udp".to_string(),
            source_ip: None,
            source_port: None,
            destination_ip: "8.8.8.8".to_string(),
            destination_port: 53,
            destination_domain: None,
            tls: false,
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: ConnectionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.protocol, "udp");
        assert_eq!(deserialized.destination_port, 53);
        assert!(!deserialized.tls);
    }

    #[test]
    fn test_decision_signals_with_ioc() {
        let signals = DecisionSignals {
            ioc_match: true,
            anomaly_score: Some(0.95),
            behavioral: Some("Never networked before".to_string()),
            kill_chain: Some("C2 Communication".to_string()),
        };

        let json = serde_json::to_string(&signals).unwrap();
        let deserialized: DecisionSignals = serde_json::from_str(&json).unwrap();
        assert!(deserialized.ioc_match);
        assert_eq!(deserialized.anomaly_score, Some(0.95));
        assert_eq!(deserialized.kill_chain.as_deref(), Some("C2 Communication"));
    }

    #[test]
    fn test_network_summary_aggregation() {
        let logs = vec![
            make_log(
                "allowed",
                "93.184.216.34",
                Some("example.com"),
                Some("fs"),
                100,
                200,
            ),
            make_log(
                "allowed",
                "93.184.216.34",
                Some("example.com"),
                Some("fs"),
                150,
                300,
            ),
            make_log("blocked", "10.0.0.1", None, Some("fs"), 0, 0),
            make_log(
                "prompted",
                "172.16.0.1",
                Some("internal.corp"),
                Some("gh"),
                50,
                100,
            ),
        ];

        let summary = NetworkSummary::from_logs(&logs, "last_24h");
        assert_eq!(summary.total_allowed, 2);
        assert_eq!(summary.total_blocked, 1);
        assert_eq!(summary.total_prompted, 1);
        assert_eq!(summary.period, "last_24h");
        assert!(!summary.top_destinations.is_empty());
        // example.com should be the top destination with count 2
        assert_eq!(summary.top_destinations[0].0, "example.com");
        assert_eq!(summary.top_destinations[0].1, 2);
    }

    #[test]
    fn test_network_summary_empty_logs() {
        let summary = NetworkSummary::from_logs(&[], "last_24h");
        assert_eq!(summary.total_allowed, 0);
        assert_eq!(summary.total_blocked, 0);
        assert_eq!(summary.total_prompted, 0);
        assert!(summary.top_destinations.is_empty());
    }

    #[test]
    fn test_traffic_stats_per_server() {
        let logs = vec![
            make_log(
                "allowed",
                "1.1.1.1",
                Some("api.github.com"),
                Some("github"),
                500,
                1000,
            ),
            make_log(
                "allowed",
                "1.1.1.2",
                Some("cdn.github.com"),
                Some("github"),
                200,
                5000,
            ),
            make_log("blocked", "10.0.0.1", None, Some("github"), 0, 0),
            make_log(
                "allowed",
                "93.184.216.34",
                Some("example.com"),
                Some("filesystem"),
                100,
                200,
            ),
        ];

        let stats = NetworkTrafficStats::from_logs(&logs, "github", "last_24h");
        assert_eq!(stats.server_name, "github");
        assert_eq!(stats.total_connections, 3);
        assert_eq!(stats.connections_allowed, 2);
        assert_eq!(stats.connections_blocked, 1);
        assert_eq!(stats.connections_prompted, 0);
        assert_eq!(stats.bytes_sent, 700);
        assert_eq!(stats.bytes_received, 6000);
        assert_eq!(stats.unique_destinations, 3); // api.github.com, cdn.github.com, 10.0.0.1
    }

    #[test]
    fn test_traffic_stats_no_matching_server() {
        let logs = vec![make_log(
            "allowed",
            "1.1.1.1",
            None,
            Some("other"),
            100,
            200,
        )];

        let stats = NetworkTrafficStats::from_logs(&logs, "nonexistent", "last_24h");
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.unique_destinations, 0);
    }

    #[test]
    fn test_network_connection_log_without_optional_fields() {
        let log = make_log("allowed", "1.2.3.4", None, None, 0, 0);
        let json = serde_json::to_string(&log).unwrap();
        let deserialized: NetworkConnectionLog = serde_json::from_str(&json).unwrap();
        assert!(deserialized.server_name.is_none());
        assert!(deserialized.connection.destination_domain.is_none());
    }
}
