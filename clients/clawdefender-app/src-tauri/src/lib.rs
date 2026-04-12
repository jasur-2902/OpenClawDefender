pub mod alerts;
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

            // Load configured AI model(s) on startup via DualAiConfig migration
            if let Some(app_state) = app.try_state::<AppState>() {
                let ai_backends = app_state.ai_backends.clone();
                match clawdefender_slm::config_migration::load_dual_config() {
                    Ok(dual_config) => {
                        let mut local_loaded = false;

                        // Load local backend if configured
                        if let Some(ref local) = dual_config.local {
                            let slm_config = clawdefender_slm::engine::SlmConfig {
                                model_path: local.path.clone(),
                                ..Default::default()
                            };
                            let service = clawdefender_slm::SlmService::new(slm_config, true);
                            let using_gpu = service.stats().map(|s| s.using_gpu).unwrap_or(false);

                            let (display_name, size_bytes) = if local.model_type == "catalog" {
                                let mid = local.model_id.as_deref().unwrap_or("");
                                let name = clawdefender_slm::model_registry::find_model(mid)
                                    .map(|m| m.display_name)
                                    .unwrap_or_else(|| mid.to_string());
                                let size = clawdefender_slm::model_registry::find_model(mid)
                                    .map(|m| m.size_bytes);
                                (name, size)
                            } else {
                                let name = local.path.file_name()
                                    .map(|n| n.to_string_lossy().to_string())
                                    .unwrap_or_else(|| "Custom Model".to_string());
                                let size = std::fs::metadata(&local.path).map(|m| m.len()).ok();
                                (name, size)
                            };

                            let local_info = clawdefender_slm::LocalModelInfo {
                                model_name: display_name,
                                model_id: local.model_id.clone(),
                                file_path: Some(local.path.to_string_lossy().to_string()),
                                size_bytes,
                                using_gpu,
                            };
                            let svc = std::sync::Arc::new(service);
                            ai_backends.set_local(svc, local_info);
                            local_loaded = true;
                            tracing::info!("Loaded saved local AI model on startup");
                        }

                        // Load cloud backend if configured
                        if let Some(ref cloud) = dual_config.cloud {
                            if let Ok(Some(api_key)) = clawdefender_slm::cloud_backend::get_api_key(&cloud.provider) {
                                let model_display = clawdefender_slm::model_registry::cloud_providers()
                                    .into_iter()
                                    .find(|p| p.id == cloud.provider)
                                    .and_then(|p| p.models.into_iter().find(|m| m.id == cloud.model))
                                    .map(|m| m.display_name)
                                    .unwrap_or_else(|| cloud.model.clone());

                                let backend: Box<dyn clawdefender_slm::engine::SlmBackend> =
                                    Box::new(clawdefender_slm::cloud_backend::CloudBackend::new(
                                        cloud.provider.clone(),
                                        cloud.model.clone(),
                                        api_key,
                                    ));
                                let config = clawdefender_slm::engine::SlmConfig::default();
                                let engine = std::sync::Arc::new(
                                    clawdefender_slm::engine::SlmEngine::new(backend, config.clone()),
                                );
                                let service = clawdefender_slm::SlmService::with_engine(engine, config);
                                let svc = std::sync::Arc::new(service);

                                ai_backends.set_cloud(svc, cloud.provider.clone(), model_display);
                                tracing::info!("Loaded saved cloud AI model on startup");
                            } else {
                                tracing::warn!("Cloud model configured but API key missing for {}, skipping", cloud.provider);
                            }
                        }

                        // Always ensure a local backend is available: use heuristic analyzer
                        // when no GGUF model or cloud API is configured. This gives users
                        // real security analysis from day 1 without any setup.
                        if !local_loaded {
                            let backend: Box<dyn clawdefender_slm::engine::SlmBackend> =
                                Box::new(clawdefender_slm::engine::HeuristicSlmBackend::new());
                            let config = clawdefender_slm::engine::SlmConfig::default();
                            let engine = std::sync::Arc::new(
                                clawdefender_slm::engine::SlmEngine::new(backend, config.clone()),
                            );
                            let service = clawdefender_slm::SlmService::with_engine(engine, config);
                            let local_info = clawdefender_slm::LocalModelInfo {
                                model_name: "Heuristic Analyzer".to_string(),
                                model_id: Some("heuristic".to_string()),
                                file_path: None,
                                size_bytes: None,
                                using_gpu: false,
                            };
                            let svc = std::sync::Arc::new(service);
                            ai_backends.set_local(svc, local_info);
                            tracing::info!("No AI model configured — activated heuristic analyzer (works without download)");
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load AI model config: {}, using heuristic analyzer", e);
                        // Fall back to heuristic analyzer so AI is always available
                        let backend: Box<dyn clawdefender_slm::engine::SlmBackend> =
                            Box::new(clawdefender_slm::engine::HeuristicSlmBackend::new());
                        let config = clawdefender_slm::engine::SlmConfig::default();
                        let engine = std::sync::Arc::new(
                            clawdefender_slm::engine::SlmEngine::new(backend, config.clone()),
                        );
                        let service = clawdefender_slm::SlmService::with_engine(engine, config);
                        let local_info = clawdefender_slm::LocalModelInfo {
                            model_name: "Heuristic Analyzer".to_string(),
                            model_id: Some("heuristic".to_string()),
                            file_path: None,
                            size_bytes: None,
                            using_gpu: false,
                        };
                        let svc = std::sync::Arc::new(service);
                        ai_backends.set_local(svc, local_info);
                    }
                }
            }

            // Phase 2: Initialize cloud agent session manager if an API key is available.
            if let Some(app_state) = app.try_state::<AppState>() {
                // Try Anthropic first, then OpenAI, then Google
                let cloud_setup = clawdefender_slm::cloud_backend::get_api_key("anthropic")
                    .ok()
                    .flatten()
                    .map(|key| ("anthropic".to_string(), key, "claude-sonnet-4-20250514".to_string()))
                    .or_else(|| {
                        clawdefender_slm::cloud_backend::get_api_key("openai")
                            .ok()
                            .flatten()
                            .map(|key| ("openai".to_string(), key, "gpt-4o".to_string()))
                    })
                    .or_else(|| {
                        clawdefender_slm::cloud_backend::get_api_key("google")
                            .ok()
                            .flatten()
                            .map(|key| ("google".to_string(), key, "gemini-2.5-pro".to_string()))
                    });

                if let Some((provider_id, api_key, model)) = cloud_setup {
                    tracing::info!("Cloud API key found for {}, initializing agent session manager", provider_id);

                    // Build cloud provider
                    let cloud_provider: Box<dyn clawdefender_swarm::cloud_api::CloudProvider> =
                        match provider_id.as_str() {
                            "anthropic" => Box::new(
                                clawdefender_swarm::cloud_api::AnthropicProvider::new(api_key),
                            ),
                            "openai" => Box::new(
                                clawdefender_swarm::cloud_api::OpenAIProvider::new(api_key),
                            ),
                            "google" => Box::new(
                                clawdefender_swarm::cloud_api::OpenAIProvider::new(api_key)
                                    .with_base_url("https://generativelanguage.googleapis.com/v1beta/openai".to_string()),
                            ),
                            _ => Box::new(
                                clawdefender_swarm::cloud_api::OpenAIProvider::new(api_key),
                            ),
                        };

                    // Build privacy filter
                    let privacy_filter = std::sync::Arc::new(
                        clawdefender_swarm::privacy::PrivacyFilter::new(),
                    );

                    // Build cost tracker
                    let home = dirs::home_dir().unwrap_or_default();
                    let db_path = home
                        .join(".local/share/clawdefender/swarm_usage.db");
                    if let Some(parent) = db_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }

                    let cost_tracker_result = clawdefender_swarm::cost::CostTracker::new(
                        &db_path,
                        clawdefender_swarm::cost::PricingTable::default(),
                        clawdefender_swarm::cost::BudgetConfig::default(),
                    );

                    if let Ok(cost_tracker) = cost_tracker_result {
                        let cost_tracker_arc = std::sync::Arc::new(
                            std::sync::Mutex::new(cost_tracker),
                        );
                        let cost_guard = std::sync::Arc::new(
                            clawdefender_swarm::cost::CostGuard::new(cost_tracker_arc.clone()),
                        );

                        // Build CloudApiClient with middleware
                        let cloud_client = std::sync::Arc::new(
                            clawdefender_swarm::cloud_api::CloudApiClient::new(cloud_provider)
                                .with_privacy(privacy_filter.clone())
                                .with_cost_guard(cost_guard.clone()),
                        );

                        // Build ToolSandbox
                        let tool_sandbox = std::sync::Arc::new(
                            clawdefender_swarm::tool_sandbox::ToolSandbox::new(),
                        );

                        // Build sessions directory
                        let sessions_dir = home
                            .join(".local/share/clawdefender/agent_sessions");

                        // Create the AgentSessionManager
                        let session_manager = std::sync::Arc::new(
                            clawdefender_swarm::agent_session::AgentSessionManager::new(
                                cloud_client,
                                tool_sandbox,
                                model.clone(),
                                sessions_dir,
                            ),
                        );

                        if let Ok(mut mgr) = app_state.agent_session_manager.lock() {
                            *mgr = Some(session_manager);
                        }
                        if let Ok(mut ct) = app_state.cost_tracker.lock() {
                            *ct = Some(cost_tracker_arc);
                        }

                        // Phase 3: Initialize scan orchestrator using a second cloud client
                        let scan_cloud_provider: Box<dyn clawdefender_swarm::cloud_api::CloudProvider> = {
                            let key = clawdefender_slm::cloud_backend::get_api_key(&provider_id)
                                .ok().flatten().unwrap_or_default();
                            match provider_id.as_str() {
                                "anthropic" => Box::new(clawdefender_swarm::cloud_api::AnthropicProvider::new(key)),
                                "google" => Box::new(
                                    clawdefender_swarm::cloud_api::OpenAIProvider::new(key)
                                        .with_base_url("https://generativelanguage.googleapis.com/v1beta/openai".to_string()),
                                ),
                                _ => Box::new(clawdefender_swarm::cloud_api::OpenAIProvider::new(key)),
                            }
                        };

                        let scan_cloud_client = std::sync::Arc::new(
                            clawdefender_swarm::cloud_api::CloudApiClient::new(scan_cloud_provider)
                                .with_privacy(privacy_filter.clone())
                                .with_cost_guard(cost_guard),
                        );

                        let scan_tool_sandbox = std::sync::Arc::new(
                            clawdefender_swarm::tool_sandbox::ToolSandbox::new(),
                        );

                        let scans_dir = home.join(".local/share/clawdefender/ai_scans");

                        let scan_orch = std::sync::Arc::new(
                            clawdefender_swarm::scan_orchestrator::ScanOrchestrator::new(
                                scan_cloud_client,
                                scan_tool_sandbox,
                                model.clone(),
                                scans_dir,
                            ),
                        );

                        if let Ok(mut so) = app_state.scan_orchestrator.lock() {
                            *so = Some(scan_orch);
                        }
                        tracing::info!("Phase 3 scan orchestrator initialized successfully");

                        // Phase 4: Initialize threat hunter using a third cloud client
                        let hunt_cloud_provider: Box<dyn clawdefender_swarm::cloud_api::CloudProvider> = {
                            let key = clawdefender_slm::cloud_backend::get_api_key(&provider_id)
                                .ok().flatten().unwrap_or_default();
                            match provider_id.as_str() {
                                "anthropic" => Box::new(clawdefender_swarm::cloud_api::AnthropicProvider::new(key)),
                                "google" => Box::new(
                                    clawdefender_swarm::cloud_api::OpenAIProvider::new(key)
                                        .with_base_url("https://generativelanguage.googleapis.com/v1beta/openai".to_string()),
                                ),
                                _ => Box::new(clawdefender_swarm::cloud_api::OpenAIProvider::new(key)),
                            }
                        };

                        let hunt_cloud_client = std::sync::Arc::new(
                            clawdefender_swarm::cloud_api::CloudApiClient::new(hunt_cloud_provider)
                                .with_privacy(privacy_filter.clone()),
                        );

                        let hunt_tool_sandbox = std::sync::Arc::new(
                            clawdefender_swarm::tool_sandbox::ToolSandbox::new(),
                        );

                        let hunts_dir = home.join(".local/share/clawdefender/threat_hunts");

                        let hunt_model = model.clone();

                        let threat_hunter = std::sync::Arc::new(
                            clawdefender_swarm::threat_hunting::ThreatHunter::new(
                                hunt_cloud_client,
                                hunt_tool_sandbox,
                                hunt_model,
                                hunts_dir,
                            ),
                        );

                        if let Ok(mut th) = app_state.threat_hunter.lock() {
                            *th = Some(threat_hunter);
                        }
                        tracing::info!("Phase 4 threat hunter initialized successfully");

                        // Phase 4: Initialize investigation engine
                        let inv_cloud_provider: Box<dyn clawdefender_swarm::cloud_api::CloudProvider> = {
                            let key = clawdefender_slm::cloud_backend::get_api_key(&provider_id)
                                .ok().flatten().unwrap_or_default();
                            match provider_id.as_str() {
                                "anthropic" => Box::new(clawdefender_swarm::cloud_api::AnthropicProvider::new(key)),
                                "google" => Box::new(
                                    clawdefender_swarm::cloud_api::OpenAIProvider::new(key)
                                        .with_base_url("https://generativelanguage.googleapis.com/v1beta/openai".to_string()),
                                ),
                                _ => Box::new(clawdefender_swarm::cloud_api::OpenAIProvider::new(key)),
                            }
                        };

                        let inv_cloud_client = std::sync::Arc::new(
                            clawdefender_swarm::cloud_api::CloudApiClient::new(inv_cloud_provider)
                                .with_privacy(privacy_filter.clone()),
                        );

                        let inv_tool_sandbox = std::sync::Arc::new(
                            clawdefender_swarm::tool_sandbox::ToolSandbox::new(),
                        );

                        let inv_model = model.clone();

                        let inv_engine = std::sync::Arc::new(
                            clawdefender_swarm::investigation_engine::InvestigationEngine::new(
                                inv_cloud_client,
                                inv_tool_sandbox,
                                inv_model,
                            ),
                        );

                        if let Ok(mut ie) = app_state.investigation_engine.lock() {
                            *ie = Some(inv_engine);
                        }
                        tracing::info!("Phase 4 investigation engine initialized successfully");

                        if let Ok(mut pf) = app_state.privacy_filter.lock() {
                            *pf = Some(privacy_filter);
                        }

                        tracing::info!("Phase 2 agent session manager initialized successfully");
                    } else {
                        tracing::warn!("Failed to initialize cost tracker database, agent sessions disabled");
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

            // Start clipboard monitor if enabled in settings (opt-in)
            {
                let clip_handle = app.handle().clone();
                // Read the setting; default is false (off)
                let clipboard_enabled = {
                    let home = dirs::home_dir().unwrap_or_default();
                    let config_path = home.join(".config/clawdefender/config.toml");
                    if config_path.exists() {
                        std::fs::read_to_string(&config_path)
                            .ok()
                            .and_then(|c| c.parse::<toml::Value>().ok())
                            .and_then(|t| {
                                t.get("monitoring")
                                    .and_then(|m| m.get("clipboard_monitor_enabled"))
                                    .and_then(|v| v.as_bool())
                            })
                            .unwrap_or(false)
                    } else {
                        false
                    }
                };
                if clipboard_enabled {
                    commands::start_clipboard_monitor(clip_handle);
                }
            }

            // Auto-scan on first launch: if no previous scan results exist, trigger a scan
            {
                let scan_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    // Brief delay to let the UI finish loading
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

                    let home = dirs::home_dir().unwrap_or_default();
                    let scans_dir = home.join(".local/share/clawdefender/scans");
                    let has_previous_scans = scans_dir.exists()
                        && std::fs::read_dir(&scans_dir)
                            .map(|entries| entries.filter_map(|e| e.ok()).count() > 0)
                            .unwrap_or(false);

                    if !has_previous_scans {
                        tracing::info!("First launch detected — running automatic security scan");
                        let all_modules: Vec<String> = vec![
                            "mcp-config-audit".to_string(),
                            "policy-strength".to_string(),
                            "server-reputation".to_string(),
                            "system-posture".to_string(),
                            "behavioral-anomaly".to_string(),
                        ];
                        match commands::start_scan(
                            scan_handle,
                            String::new(),
                            all_modules,
                            300,
                        ).await {
                            Ok(scan_id) => {
                                tracing::info!("Auto-scan started: {}", scan_id);
                            }
                            Err(e) => {
                                tracing::warn!("Auto-scan failed to start: {}", e);
                            }
                        }
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
            commands::deactivate_cloud_provider,
            commands::get_ai_status,
            commands::get_routing_preferences,
            commands::update_routing_preferences,
            commands::get_rate_limit_status,
            commands::get_active_model,
            commands::list_available_models,
            commands::get_slm_analysis_for_prompt,
            commands::get_slm_status,
            commands::get_active_alerts_cmd,
            commands::get_alert_stats_cmd,
            commands::dismiss_alert_cmd,
            commands::resolve_alert_cmd,
            commands::dismiss_all_alerts,
            commands::get_alert_history_cmd,
            commands::get_alert_detail,
            commands::get_humanized_events,
            commands::get_protection_score,
            commands::get_score_history,
            commands::ask_claw,
            commands::confirm_action,
            commands::analyze_url,
            commands::execute_fix_action,
            commands::get_recommendations_cmd,
            commands::execute_recommendation_cmd,
            commands::dismiss_recommendation_cmd,
            commands::get_pending_prompts,
            commands::get_latest_conversation_id,
            commands::create_new_conversation,
            commands::save_conversation_message,
            commands::load_conversation,
            commands::list_conversations,
            commands::delete_conversation,
            commands::search_conversations,
            commands::analyze_config,
            commands::analyze_file,
            commands::get_tool_cards,
            commands::get_new_tools,
            commands::set_trust_level,
            commands::set_permission_override,
            commands::reset_permission_override,
            commands::dismiss_new_tool,
            commands::get_trust_level,
            commands::preview_trust_change,
            commands::get_server_summary,
            // Phase 2 — Agent Session commands
            commands::start_agent_session,
            commands::send_agent_message,
            commands::get_agent_session_status,
            commands::list_agent_sessions,
            commands::cancel_agent_session,
            commands::approve_pending_action,
            commands::reject_pending_action,
            // Phase 2 — Cloud status & budget commands
            commands::get_cloud_status,
            commands::get_budget_status,
            commands::update_budgets,
            commands::get_cloud_config,
            commands::update_cloud_config,
            // Phase 2 — Privacy commands
            commands::get_privacy_preview,
            commands::get_outbound_audit,
            // Phase 3 — AI scan orchestrator commands
            commands::start_ai_scan,
            commands::get_ai_scan_progress,
            commands::get_ai_scan_result,
            commands::cancel_ai_scan,
            commands::respond_to_scan_request,
            commands::get_scan_evidence_chain,
            commands::get_scan_remediations,
            commands::execute_scan_remediation,
            commands::revert_scan_remediation,
            commands::get_scan_playbooks,
            commands::get_playbook_detail,
            // Phase 3 — Report generator commands
            commands::generate_scan_report,
            commands::get_scan_report,
            commands::get_scan_comparison,
            commands::list_scan_reports,
            // Phase 4 — Threat Hunting commands
            commands::start_threat_hunt,
            commands::get_hunt_progress,
            commands::get_hunt_results,
            commands::cancel_threat_hunt,
            // Phase 4 — Investigation persistence commands
            commands::list_investigations,
            commands::get_investigation,
            commands::search_investigations,
            commands::delete_investigation,
            commands::pin_investigation,
            commands::export_investigation,
            commands::resume_investigation,
            // Phase 4 — Investigation Timeline commands
            commands::get_investigation_timeline,
            commands::get_event_story,
            commands::get_related_investigations,
            // Phase 4 — Investigation Engine commands
            commands::start_investigation,
            commands::get_investigation_progress,
            commands::get_investigation_result,
            commands::cancel_investigation,
            // Ask Claw AI commands
            commands::ask_claw_ai,
            commands::get_ask_claw_mode,
            commands::approve_claw_action,
            commands::reject_claw_action,
            commands::set_claw_context,
            commands::list_claw_conversations,
            // Phase 5 — Scheduled Analysis commands
            commands::get_analysis_schedules,
            commands::update_analysis_schedule,
            commands::run_schedule_now,
            commands::get_schedule_history,
            commands::get_monthly_cost_estimate,
            // Phase 5 — Drift Detection commands
            commands::get_drift_baselines,
            commands::check_server_drift,
            commands::check_all_drift,
            commands::reset_drift_baseline,
            // Phase 5 — Smart Alert commands
            commands::get_alert_groups,
            commands::get_alert_group_detail,
            commands::mute_alert_pattern,
            commands::get_alert_fatigue_suggestions,
            commands::set_quiet_hours,
            // Phase 5 — Adaptive Posture commands
            commands::get_threat_posture,
            commands::set_posture_override,
            commands::clear_posture_override,
            commands::get_posture_history,
            commands::get_posture_parameters,
            // Phase 5 — Threat Simulation commands
            commands::run_threat_simulation,
            commands::get_simulation_results,
            commands::get_simulation_history,
            commands::get_defense_score,
            commands::get_simulation_scenarios,
            // Phase 5 — Knowledge Base commands
            commands::get_knowledge_stats,
            commands::get_server_knowledge,
            commands::list_known_servers,
            commands::get_false_positives,
            commands::get_learned_patterns,
            commands::add_manual_knowledge,
            commands::forget_server_knowledge,
            commands::save_knowledge_base,
            commands::export_knowledge_base,
            // Phase 6 — Autonomy Framework commands
            commands::get_autonomy_level,
            commands::set_autonomy_level,
            commands::set_server_autonomy_override,
            commands::clear_server_autonomy_override,
            commands::activate_lockdown,
            commands::deactivate_lockdown,
            commands::get_autonomy_action_log,
            commands::get_autonomy_stats,
            // Phase 6 — Response Playbook commands
            commands::list_response_playbooks,
            commands::get_response_playbook,
            commands::get_playbook_executions,
            commands::test_response_playbook,
            // Phase 6 — Report Generation commands
            commands::list_reports,
            commands::get_report_content,
            commands::get_report_count,
            commands::delete_report,
            // Phase 6 — Feedback & Calibration commands
            commands::get_feedback_stats,
            commands::get_self_assessment,
            commands::run_calibration,
            commands::get_knowledge_suggestions,
            // Phase 6 — Data Portability commands
            commands::export_clawdefender_data,
            commands::preview_import,
            commands::get_export_history,
            // Phase 6 — Transparency Dashboard commands
            commands::get_dashboard_summary,
            commands::get_agent_activities,
            commands::get_cost_summary,
            commands::get_accuracy_metrics,
            commands::get_audit_trail,
            commands::get_decision_explanations,
            commands::get_learned_patterns_view,
            // UI State Persistence commands
            commands::get_ui_state,
            commands::set_ui_state,
            commands::remove_ui_state,
            // Sensor Health & FDA Setup commands
            commands::get_sensor_health,
            commands::open_system_settings_fda,
            // Unified Detection Pipeline
            commands::run_detection_scan,
            // Memory Scanner
            commands::run_memory_scan,
            // Clipboard Monitor
            commands::check_clipboard_now,
            commands::get_clipboard_threats,
            // TCC Permission Audit
            commands::run_tcc_audit,
            // File Integrity Monitor
            commands::run_integrity_check,
            commands::reset_integrity_baseline,
            // CIS Benchmark Compliance
            commands::run_cis_compliance,
            // Browser Extension Audit & Login Anomalies
            commands::run_browser_audit,
            commands::get_login_anomalies,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
