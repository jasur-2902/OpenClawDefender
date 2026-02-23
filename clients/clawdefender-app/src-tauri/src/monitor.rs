use std::thread;
use std::time::Duration;

use tauri::{AppHandle, Manager};
use tracing::info;

use crate::commands::count_wrapped_servers;
use crate::daemon;
use crate::events;
use crate::state::{AppState, DaemonStatus};

/// Poll interval for the connection monitor.
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Spawns a background thread that periodically checks the daemon connection
/// and updates AppState + emits frontend events on state changes.
pub fn start_connection_monitor(app: AppHandle) {
    thread::spawn(move || {
        let mut was_connected = false;

        loop {
            thread::sleep(POLL_INTERVAL);

            let state = app.state::<AppState>();
            let connected = state.ipc_client.check_connection();
            let wrapped = count_wrapped_servers();

            if connected {
                // Daemon is reachable — try to fetch metrics
                let status = match state.ipc_client.query_status() {
                    Ok(metrics) => DaemonStatus {
                        running: true,
                        pid: None,
                        uptime_seconds: None,
                        version: Some("0.10.0".to_string()),
                        socket_path: daemon::socket_path().to_string_lossy().into_owned(),
                        servers_proxied: wrapped,
                        events_processed: metrics.messages_total,
                    },
                    Err(_) => DaemonStatus {
                        running: true,
                        pid: None,
                        uptime_seconds: None,
                        version: Some("0.10.0".to_string()),
                        socket_path: daemon::socket_path().to_string_lossy().into_owned(),
                        servers_proxied: wrapped,
                        events_processed: 0,
                    },
                };

                state.update_daemon_status(true, Some(status));
            } else {
                let status = DaemonStatus {
                    running: false,
                    pid: None,
                    uptime_seconds: None,
                    version: None,
                    socket_path: daemon::socket_path().to_string_lossy().into_owned(),
                    servers_proxied: wrapped,
                    events_processed: 0,
                };
                state.update_daemon_status(false, Some(status));
            }

            // Emit frontend event only on state change
            if connected != was_connected {
                if connected {
                    info!("Daemon connection established");
                } else {
                    info!("Daemon connection lost");
                }
                events::emit_status_change(&app, connected);
                was_connected = connected;
            }
        }
    });
}
