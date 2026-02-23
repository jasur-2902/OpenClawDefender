mod commands;
mod daemon;
mod event_stream;
mod events;
pub mod ipc_client;
mod monitor;
mod scanner;
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

            // Load configured AI model on startup
            if let Some(app_state) = app.try_state::<AppState>() {
                match clawdefender_slm::model_registry::load_active_config() {
                    Ok(config) => {
                        use clawdefender_slm::model_registry::ActiveModelConfig;
                        match config {
                            ActiveModelConfig::LocalCatalog { model_id, path } => {
                                let slm_config = clawdefender_slm::engine::SlmConfig {
                                    model_path: path.clone(),
                                    ..Default::default()
                                };
                                let service = clawdefender_slm::SlmService::new(slm_config, true);
                                let using_gpu = service.stats().map(|s| s.using_gpu).unwrap_or(false);
                                let display_name = clawdefender_slm::model_registry::find_model(&model_id)
                                    .map(|m| m.display_name)
                                    .unwrap_or_else(|| model_id.clone());
                                let size_bytes = clawdefender_slm::model_registry::find_model(&model_id)
                                    .map(|m| m.size_bytes);

                                let info = state::ActiveModelInfo {
                                    model_type: "local_catalog".to_string(),
                                    model_id: Some(model_id),
                                    model_name: display_name,
                                    file_path: Some(path.to_string_lossy().to_string()),
                                    provider: None,
                                    size_bytes,
                                    using_gpu,
                                    total_inferences: 0,
                                    avg_latency_ms: 0.0,
                                };

                                if let Ok(mut slm) = app_state.active_slm.lock() {
                                    *slm = Some(std::sync::Arc::new(service));
                                }
                                if let Ok(mut mi) = app_state.active_model_info.lock() {
                                    *mi = Some(info);
                                }
                                tracing::info!("Loaded saved AI model on startup");
                            }
                            ActiveModelConfig::LocalCustom { path } => {
                                let slm_config = clawdefender_slm::engine::SlmConfig {
                                    model_path: path.clone(),
                                    ..Default::default()
                                };
                                let service = clawdefender_slm::SlmService::new(slm_config, true);
                                let using_gpu = service.stats().map(|s| s.using_gpu).unwrap_or(false);
                                let size = std::fs::metadata(&path).map(|m| m.len()).ok();
                                let name = path.file_name()
                                    .map(|n| n.to_string_lossy().to_string())
                                    .unwrap_or_else(|| "Custom Model".to_string());

                                let info = state::ActiveModelInfo {
                                    model_type: "local_custom".to_string(),
                                    model_id: None,
                                    model_name: name,
                                    file_path: Some(path.to_string_lossy().to_string()),
                                    provider: None,
                                    size_bytes: size,
                                    using_gpu,
                                    total_inferences: 0,
                                    avg_latency_ms: 0.0,
                                };

                                if let Ok(mut slm) = app_state.active_slm.lock() {
                                    *slm = Some(std::sync::Arc::new(service));
                                }
                                if let Ok(mut mi) = app_state.active_model_info.lock() {
                                    *mi = Some(info);
                                }
                                tracing::info!("Loaded saved custom AI model on startup");
                            }
                            ActiveModelConfig::CloudApi { provider, model } => {
                                if clawdefender_slm::cloud_backend::has_api_key(&provider) {
                                    let provider_name = clawdefender_slm::model_registry::cloud_providers()
                                        .into_iter()
                                        .find(|p| p.id == provider)
                                        .map(|p| p.display_name)
                                        .unwrap_or_else(|| provider.clone());
                                    let model_name = clawdefender_slm::model_registry::cloud_providers()
                                        .into_iter()
                                        .find(|p| p.id == provider)
                                        .and_then(|p| p.models.into_iter().find(|m| m.id == model))
                                        .map(|m| m.display_name)
                                        .unwrap_or_else(|| model.clone());

                                    let backend: Box<dyn clawdefender_slm::engine::SlmBackend> =
                                        Box::new(clawdefender_slm::engine::MockSlmBackend {
                                            model_name: format!("{} ({})", model_name, provider_name),
                                            model_size: 0,
                                            gpu: false,
                                            ..Default::default()
                                        });
                                    let config = clawdefender_slm::engine::SlmConfig::default();
                                    let engine = std::sync::Arc::new(
                                        clawdefender_slm::engine::SlmEngine::new(backend, config.clone()),
                                    );
                                    let service = clawdefender_slm::SlmService::with_engine(engine, config);

                                    let info = state::ActiveModelInfo {
                                        model_type: "cloud_api".to_string(),
                                        model_id: Some(model),
                                        model_name: format!("{} ({})", model_name, provider_name),
                                        file_path: None,
                                        provider: Some(provider),
                                        size_bytes: None,
                                        using_gpu: false,
                                        total_inferences: 0,
                                        avg_latency_ms: 0.0,
                                    };

                                    if let Ok(mut slm) = app_state.active_slm.lock() {
                                        *slm = Some(std::sync::Arc::new(service));
                                    }
                                    if let Ok(mut mi) = app_state.active_model_info.lock() {
                                        *mi = Some(info);
                                    }
                                    tracing::info!("Loaded saved cloud AI model on startup");
                                } else {
                                    tracing::warn!("Cloud model configured but API key missing, skipping");
                                }
                            }
                            ActiveModelConfig::None => {}
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load AI model config: {}", e);
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
            commands::duplicate_rule,
            commands::toggle_rule,
            commands::reorder_rules,
            commands::list_templates,
            commands::apply_template,
            commands::reload_policy,
            commands::get_recent_events,
            commands::get_profiles,
            commands::get_behavioral_status,
            commands::list_guards,
            commands::start_scan,
            commands::get_scan_progress,
            commands::get_scan_results,
            commands::apply_scan_fix,
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
            commands::save_api_key,
            commands::clear_api_key,
            commands::has_cloud_api_key,
            commands::test_api_connection,
            commands::get_cloud_usage,
            commands::get_cloud_providers,
            commands::download_model,
            commands::download_custom_model,
            commands::get_download_progress,
            commands::cancel_download,
            commands::delete_model,
            commands::get_model_catalog,
            commands::get_installed_models,
            commands::get_system_capabilities,
            commands::activate_model,
            commands::activate_cloud_provider,
            commands::deactivate_model,
            commands::get_active_model,
            commands::list_available_models,
            commands::get_slm_analysis_for_prompt,
            commands::get_slm_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
