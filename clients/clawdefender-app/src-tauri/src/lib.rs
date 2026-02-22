mod commands;
mod daemon;
mod event_stream;
mod events;
pub mod ipc_client;
mod monitor;
mod state;
mod tray;
mod windows;

use state::AppState;
use tauri::Manager;
use tauri_plugin_autostart::MacosLauncher;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![]),
        ))
        .manage(AppState::default())
        .setup(|app| {
            // Set up system tray
            if let Err(e) = tray::setup_tray(app.handle()) {
                tracing::error!("Failed to setup tray: {}", e);
            }

            // Start the background connection monitor
            monitor::start_connection_monitor(app.handle().clone());

            // Start the audit.jsonl event stream watcher
            event_stream::start_event_stream(app.handle().clone());

            // Auto-start the daemon if it's not already running
            if !daemon::is_daemon_running() {
                tracing::info!("Daemon not running — attempting auto-start");
                match daemon::start_daemon_process() {
                    Ok(()) => {
                        if let Some(state) = app.try_state::<AppState>() {
                            if let Ok(mut flag) = state.daemon_started_by_gui.lock() {
                                *flag = true;
                            }
                        }
                        tracing::info!("Daemon auto-started by GUI");
                    }
                    Err(e) => {
                        tracing::warn!("Could not auto-start daemon: {}", e);
                    }
                }
            }

            // On macOS, hide the window on close instead of quitting
            let main_window = app.get_webview_window("main");
            if let Some(window) = main_window {
                let app_handle = app.handle().clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = windows::hide_main_window(&app_handle);
                    }
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_daemon_status,
            commands::start_daemon,
            commands::stop_daemon,
            commands::detect_mcp_clients,
            commands::list_mcp_servers,
            commands::wrap_server,
            commands::unwrap_server,
            commands::get_policy,
            commands::update_rule,
            commands::add_rule,
            commands::delete_rule,
            commands::list_templates,
            commands::apply_template,
            commands::reload_policy,
            commands::get_recent_events,
            commands::get_profiles,
            commands::get_behavioral_status,
            commands::list_guards,
            commands::start_scan,
            commands::get_scan_progress,
            commands::run_doctor,
            commands::get_system_info,
            commands::respond_to_prompt,
            commands::check_onboarding_complete,
            commands::complete_onboarding,
            commands::get_settings,
            commands::update_settings,
            commands::get_feed_status,
            commands::force_feed_update,
            commands::get_blocklist_matches,
            commands::get_rule_packs,
            commands::install_rule_pack,
            commands::uninstall_rule_pack,
            commands::get_ioc_stats,
            commands::get_telemetry_status,
            commands::toggle_telemetry,
            commands::get_telemetry_preview,
            commands::check_server_reputation,
            commands::get_network_extension_status,
            commands::activate_network_extension,
            commands::deactivate_network_extension,
            commands::get_network_settings,
            commands::update_network_settings,
            commands::get_network_connections,
            commands::get_network_summary,
            commands::get_network_traffic_by_server,
            commands::export_network_log,
            commands::kill_agent_process,
            commands::enable_autostart,
            commands::disable_autostart,
            commands::is_autostart_enabled,
            commands::export_settings,
            commands::import_settings_from_content,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
