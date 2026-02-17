//! Webhook support for guard event notifications.
//!
//! Webhooks allow registered callbacks to receive notifications when guards
//! block operations or detect anomalies. Only localhost URLs are accepted.

use std::net::ToSocketAddrs;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::registry::WebhookRegistration;

/// Webhook event payload sent to registered URLs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub guard_id: String,
    pub event_type: String,
    pub action: String,
    pub target: String,
    pub reason: String,
    pub rule: String,
    pub timestamp: String,
}

/// Validate that a URL is a localhost URL.
pub fn validate_localhost_url(url: &str) -> Result<(), String> {
    let parsed = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or_else(|| "URL must start with http:// or https://".to_string())?;

    let host_port = parsed.split('/').next().unwrap_or(parsed);

    // Handle IPv6 bracket notation: [::1]:port
    let host = if host_port.starts_with('[') {
        // Extract the bracketed host including brackets
        host_port.split(']').next().map(|h| format!("{}]", h)).unwrap_or_default()
    } else {
        host_port.split(':').next().unwrap_or(host_port).to_string()
    };

    match host.as_str() {
        "127.0.0.1" | "localhost" | "[::1]" | "::1" => Ok(()),
        _ => Err(format!(
            "Only localhost URLs are allowed (127.0.0.1, localhost, [::1]), got '{}'",
            host
        )),
    }
}

/// Check if a webhook URL is reachable via a quick TCP connect.
pub async fn check_reachable(url: &str) -> bool {
    let parsed = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    let host_port = parsed.split('/').next().unwrap_or(parsed);

    // Add default port if not specified
    let addr = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{}:80", host_port)
    };

    match addr.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    tokio::net::TcpStream::connect(addr),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        debug!(url = url, "webhook URL is reachable");
                        true
                    }
                    Ok(Err(e)) => {
                        warn!(url = url, error = %e, "webhook URL TCP connect failed");
                        false
                    }
                    Err(_) => {
                        warn!(url = url, "webhook URL TCP connect timed out");
                        false
                    }
                }
            } else {
                false
            }
        }
        Err(e) => {
            warn!(url = url, error = %e, "webhook URL address resolution failed");
            false
        }
    }
}

/// Dispatch a webhook event to all registered webhooks for a guard.
pub async fn dispatch_event(
    webhooks: &[WebhookRegistration],
    event: &WebhookEvent,
) {
    let payload = match serde_json::to_string(event) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "failed to serialize webhook event");
            return;
        }
    };

    for webhook in webhooks {
        if !webhook.events.contains(&event.event_type) {
            continue;
        }

        let url = webhook.url.clone();
        let payload = payload.clone();

        // Fire-and-forget in background
        tokio::spawn(async move {
            debug!(url = %url, "dispatching webhook event");

            // Use a simple TCP connection + raw HTTP POST
            // (avoids adding reqwest dependency)
            if let Err(e) = send_webhook_post(&url, &payload).await {
                warn!(url = %url, error = %e, "webhook delivery failed");
            }
        });
    }
}

/// Send a raw HTTP POST to a webhook URL.
async fn send_webhook_post(url: &str, body: &str) -> Result<(), String> {
    let parsed = url
        .strip_prefix("http://")
        .ok_or("only http:// supported for webhooks")?;

    let (host_port, path) = match parsed.find('/') {
        Some(idx) => (&parsed[..idx], &parsed[idx..]),
        None => (parsed, "/"),
    };

    let addr = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{}:80", host_port)
    };

    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| "connection timed out".to_string())?
    .map_err(|e| e.to_string())?;

    use tokio::io::AsyncWriteExt;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host_port, body.len(), body
    );

    let (_, mut writer) = stream.into_split();
    writer
        .write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_localhost_127() {
        assert!(validate_localhost_url("http://127.0.0.1:8080/callback").is_ok());
    }

    #[test]
    fn test_validate_localhost_name() {
        assert!(validate_localhost_url("http://localhost:3000/hook").is_ok());
    }

    #[test]
    fn test_validate_localhost_ipv6() {
        assert!(validate_localhost_url("http://[::1]:9090/events").is_ok());
    }

    #[test]
    fn test_validate_remote_url_rejected() {
        assert!(validate_localhost_url("http://evil.com:8080/steal").is_err());
    }

    #[test]
    fn test_validate_no_scheme() {
        assert!(validate_localhost_url("127.0.0.1:8080/callback").is_err());
    }

    #[test]
    fn test_validate_https_localhost() {
        assert!(validate_localhost_url("https://localhost:443/hook").is_ok());
    }
}
