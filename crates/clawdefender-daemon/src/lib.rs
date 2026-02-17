//! ClawDefender daemon orchestration logic.
//!
//! The [`Daemon`] struct ties together the MCP proxy, policy engine,
//! audit logger, sensor subsystem (process tree, eslogger, FSEvents),
//! correlation engine, event router, TUI, and signal handling into a
//! single async process.

pub mod event_router;
pub mod ipc;
pub mod mock_network_extension;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use clawdefender_core::audit::logger::FileAuditLogger;
use clawdefender_core::audit::{AuditLogger, AuditRecord};
use clawdefender_core::config::settings::{ClawConfig, SensorConfig};
use clawdefender_core::event::correlation::CorrelatedEvent;
use clawdefender_core::policy::engine::DefaultPolicyEngine;
use clawdefender_core::policy::PolicyEngine;
use clawdefender_mcp_proxy::{ProxyConfig, StdioProxy, UiBridge};
use clawdefender_sensor::correlation::engine::{
    CorrelationConfig as EngineCorrelationConfig, CorrelationEngine, CorrelationInput,
};
use clawdefender_sensor::{
    default_watch_paths, EnhancedFsWatcher, EsloggerManager, ProcessTree,
};
use clawdefender_slm::context::ContextTracker;
use clawdefender_slm::engine::SlmConfig as SlmEngineConfig;
use clawdefender_slm::noise_filter::NoiseFilter;
use clawdefender_slm::SlmService;
use clawdefender_mcp_server::McpServer;
use clawdefender_swarm::chat::ChatManager;
use clawdefender_swarm::chat_server::ChatServer;
use clawdefender_swarm::commander::Commander;
use clawdefender_swarm::cost::{BudgetConfig, CostTracker, PricingTable};
use clawdefender_swarm::keychain::{self, KeyStore, Provider};
use clawdefender_swarm::llm_client::{HttpLlmClient, LlmClient};
use clawdefender_tui::{EventRecord, PendingPrompt};
use clawdefender_core::behavioral::{
    AnomalyScorer, DecisionEngine, InjectionDetector, InjectionDetectorConfig,
    KillChainDetector, LearningEngine, ProfileStore,
};
use clawdefender_guard::registry::GuardRegistry;
use clawdefender_threat_intel::blocklist::BlocklistMatcher;
use clawdefender_threat_intel::ioc::IoCDatabase;
use clawdefender_threat_intel::rules::manager::RulePackManager;
use clawdefender_threat_intel::telemetry::TelemetryAggregator;
use clawdefender_threat_intel::{FeedCache, FeedClient, FeedVerifier};

use event_router::{EventRouter, EventRouterConfig};

/// The main daemon that orchestrates all ClawDefender subsystems.
pub struct Daemon {
    config: ClawConfig,
    sensor_config: SensorConfig,
    policy_engine: Arc<RwLock<DefaultPolicyEngine>>,
    audit_logger: Arc<FileAuditLogger>,
    enable_tui: bool,
    /// Behavioral learning engine (profiles + learning phase).
    behavioral_engine: Option<Arc<RwLock<LearningEngine>>>,
    /// Anomaly scorer for behavioral analysis.
    anomaly_scorer: Option<Arc<AnomalyScorer>>,
    /// Kill chain detector.
    killchain_detector: Option<Arc<RwLock<KillChainDetector>>>,
    /// Decision engine for behavioral blocking decisions.
    decision_engine: Option<Arc<RwLock<DecisionEngine>>>,
    /// Injection detector.
    injection_detector: Option<Arc<RwLock<InjectionDetector>>>,
    /// Profile store (SQLite persistence).
    profile_store: Option<Arc<ProfileStore>>,
    /// Guard registry for agent guard management.
    guard_registry: Arc<GuardRegistry>,
    /// IoC database for threat intelligence matching.
    ioc_database: Option<Arc<RwLock<IoCDatabase>>>,
    /// Blocklist matcher for known-malicious server detection.
    blocklist_matcher: Option<Arc<BlocklistMatcher>>,
    /// Rule pack manager for community rules.
    rule_pack_manager: Option<Arc<RwLock<RulePackManager>>>,
    /// Telemetry aggregator for anonymous usage data.
    telemetry_aggregator: Option<Arc<std::sync::Mutex<TelemetryAggregator>>>,
    /// Feed client for threat intel updates.
    feed_client: Option<Arc<tokio::sync::Mutex<FeedClient>>>,
}

impl Daemon {
    /// Create a new daemon from the given configuration.
    pub fn new(config: ClawConfig, enable_tui: bool) -> Result<Self> {
        // Load policy engine -- use empty engine if policy file doesn't exist yet.
        let policy_engine = if config.policy_path.exists() {
            DefaultPolicyEngine::load(&config.policy_path).context("loading policy engine")?
        } else {
            info!(
                path = %config.policy_path.display(),
                "policy file not found, using empty policy"
            );
            DefaultPolicyEngine::empty()
        };

        // Load sensor configuration.
        let sensor_config = SensorConfig::load(&config.sensor_config_path)
            .unwrap_or_else(|e| {
                warn!(error = %e, "failed to load sensor config, using defaults");
                SensorConfig::default()
            });

        // Create audit logger.
        let audit_logger = FileAuditLogger::new(
            config.audit_log_path.clone(),
            config.log_rotation.clone(),
        )
        .context("creating audit logger")?;

        info!(
            audit_path = %config.audit_log_path.display(),
            "Audit logger: writing to path"
        );

        // --- Behavioral engine initialization ---
        let (behavioral_engine, anomaly_scorer, killchain_detector, decision_engine, injection_detector, profile_store) =
            if config.behavioral.enabled {
                // Open profile store
                let store = match ProfileStore::open(&ProfileStore::default_path()) {
                    Ok(s) => {
                        info!("Behavioral: profile store opened");
                        s
                    }
                    Err(e) => {
                        warn!(error = %e, "Behavioral: failed to open profile store, using in-memory");
                        ProfileStore::open_in_memory().expect("in-memory profile store")
                    }
                };
                let store = Arc::new(store);

                // Load existing profiles into learning engine
                let mut learning = LearningEngine::new(config.behavioral.clone());
                match store.load_all_profiles() {
                    Ok(profiles) => {
                        let count = profiles.len();
                        learning.load_profiles(profiles);
                        info!(count, "Behavioral: loaded {} profiles", count);
                    }
                    Err(e) => {
                        warn!(error = %e, "Behavioral: failed to load profiles");
                    }
                }

                let scorer = AnomalyScorer::new();
                let kc_detector = KillChainDetector::new();
                let dec_engine = DecisionEngine::from_config(
                    config.behavioral.anomaly_threshold,
                    config.behavioral.auto_block_threshold,
                    config.behavioral.auto_block_enabled,
                );

                // Initialize injection detector
                let inj_config = InjectionDetectorConfig {
                    enabled: config.injection_detector.enabled,
                    threshold: config.injection_detector.threshold,
                    patterns_path: config.injection_detector.patterns_path.clone(),
                    auto_block: config.injection_detector.auto_block,
                };
                let inj_detector = InjectionDetector::new(inj_config);

                info!("Behavioral engine: enabled (auto_block={})", config.behavioral.auto_block_enabled);
                info!("Injection detector: enabled (threshold={:.2})", config.injection_detector.threshold);

                (
                    Some(Arc::new(RwLock::new(learning))),
                    Some(Arc::new(scorer)),
                    Some(Arc::new(RwLock::new(kc_detector))),
                    Some(Arc::new(RwLock::new(dec_engine))),
                    Some(Arc::new(RwLock::new(inj_detector))),
                    Some(store),
                )
            } else {
                info!("Behavioral engine: disabled in config");
                (None, None, None, None, None, None)
            };

        // --- Threat intelligence initialization ---
        let (ioc_database, blocklist_matcher, rule_pack_manager, telemetry_aggregator, feed_client) =
            if config.threat_intel.enabled {
                let data_dir = if let Some(home) = std::env::var_os("HOME") {
                    PathBuf::from(home).join(".local/share/clawdefender/threat-intel")
                } else {
                    PathBuf::from("/tmp/clawdefender/threat-intel")
                };

                // Initialize feed cache and populate from baseline if empty.
                let cache = FeedCache::new(data_dir.clone());
                if !cache.is_populated() {
                    if let Err(e) = clawdefender_threat_intel::baseline::populate_cache_from_baseline(&cache) {
                        warn!(error = %e, "Threat intel: failed to populate baseline cache");
                    }
                }

                // Load IoC database from cache.
                let mut ioc_db = IoCDatabase::new();
                let ioc_dir = data_dir.join("ioc");
                let ioc_count = if ioc_dir.exists() {
                    ioc_db.load_from_directory(&ioc_dir).unwrap_or_else(|e| {
                        warn!(error = %e, "Threat intel: failed to load IoC database");
                        0
                    })
                } else {
                    0
                };

                // Load blocklist.
                let empty_blocklist = clawdefender_threat_intel::blocklist::types::Blocklist {
                    version: 0,
                    updated_at: String::new(),
                    entries: Vec::new(),
                };
                let blocklist = BlocklistMatcher::new(empty_blocklist);

                // Load community rules.
                let rules_dir = data_dir.join("rules");
                std::fs::create_dir_all(&rules_dir).ok();
                let catalog = clawdefender_threat_intel::rules::catalog::RuleCatalog::new(&rules_dir)
                    .unwrap_or_else(|e| {
                        warn!(error = %e, "Threat intel: failed to load rule catalog");
                        clawdefender_threat_intel::rules::catalog::RuleCatalog::in_memory()
                    });
                let rule_manager = RulePackManager::new(catalog, FeedCache::new(data_dir.clone()));
                let rules_count = rule_manager.catalog().list_installed().len();

                // Initialize telemetry aggregator.
                let telemetry = TelemetryAggregator::new();

                // Initialize feed client with Ed25519 verifier.
                let verifier = FeedVerifier::from_hex(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap_or_else(|_| {
                    // Fallback: create a dummy verifier (will fail signature checks but won't crash)
                    FeedVerifier::from_hex(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .expect("hex parse")
                });

                let ti_config = clawdefender_threat_intel::ThreatIntelConfig {
                    enabled: config.threat_intel.enabled,
                    feed_url: config.threat_intel.feed_url.clone(),
                    update_interval_hours: config.threat_intel.update_interval_hours,
                    auto_apply_rules: config.threat_intel.auto_apply_rules,
                    auto_apply_blocklist: config.threat_intel.auto_apply_blocklist,
                    auto_apply_patterns: config.threat_intel.auto_apply_patterns,
                    auto_apply_iocs: config.threat_intel.auto_apply_iocs,
                    notify_on_update: config.threat_intel.notify_on_update,
                };

                let feed_client_instance = FeedClient::new(
                    ti_config,
                    FeedCache::new(data_dir),
                    verifier,
                )
                .ok();

                info!(
                    ioc_count,
                    rules_count,
                    "Threat intelligence: loaded ({} IoCs, {} community rules)",
                    ioc_count,
                    rules_count
                );

                (
                    Some(Arc::new(RwLock::new(ioc_db))),
                    Some(Arc::new(blocklist)),
                    Some(Arc::new(RwLock::new(rule_manager))),
                    Some(Arc::new(std::sync::Mutex::new(telemetry))),
                    feed_client_instance.map(|fc| Arc::new(tokio::sync::Mutex::new(fc))),
                )
            } else {
                info!("Threat intelligence: disabled in config");
                (None, None, None, None, None)
            };

        Ok(Self {
            config,
            sensor_config,
            policy_engine: Arc::new(RwLock::new(policy_engine)),
            audit_logger: Arc::new(audit_logger),
            enable_tui,
            behavioral_engine,
            anomaly_scorer,
            killchain_detector,
            decision_engine,
            injection_detector,
            profile_store,
            guard_registry: Arc::new(GuardRegistry::new()),
            ioc_database,
            blocklist_matcher,
            rule_pack_manager,
            telemetry_aggregator,
            feed_client,
        })
    }

    /// Start the sensor subsystem (process tree, eslogger, FSEvents, correlation).
    ///
    /// Each step degrades gracefully -- sensor failure does not prevent the MCP
    /// proxy from running.
    async fn start_sensor_subsystem(
        &self,
        process_tree: Arc<RwLock<ProcessTree>>,
        audit_tx: mpsc::Sender<AuditRecord>,
        ui_event_tx: mpsc::Sender<CorrelatedEvent>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        // --- Step 1: Process tree with refresh timer ---
        {
            let tree = Arc::clone(&process_tree);
            let refresh_secs = self.sensor_config.process_tree.refresh_interval_secs;
            let tree_for_init = Arc::clone(&tree);

            // Initial refresh
            {
                let mut t = tree_for_init.write().await;
                match t.refresh() {
                    Ok(()) => info!(
                        count = t.len(),
                        "Process tree: monitoring {} processes",
                        t.len()
                    ),
                    Err(e) => warn!(error = %e, "Process tree: initial refresh failed"),
                }
            }

            let handle = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(refresh_secs));
                loop {
                    interval.tick().await;
                    let mut t = tree.write().await;
                    if let Err(e) = t.refresh() {
                        warn!(error = %e, "process tree refresh failed");
                    }
                }
            });
            handles.push(handle);
        }

        // --- Step 2: Correlation engine ---
        let (correlation_input_tx, correlation_input_rx) = mpsc::channel::<CorrelationInput>(4096);
        let (correlated_tx, correlated_rx) = mpsc::channel::<CorrelatedEvent>(1024);

        {
            let engine_config = EngineCorrelationConfig {
                match_window: Duration::from_millis(self.sensor_config.correlation.window_ms),
                ..EngineCorrelationConfig::default()
            };
            let engine = CorrelationEngine::new(engine_config, correlated_tx);
            let tree = Arc::clone(&process_tree);
            let handle = engine.run(correlation_input_rx, tree);
            info!("Correlation engine: active");
            handles.push(handle);
        }

        // --- Step 3: Event router ---
        {
            let router = EventRouter::new(
                EventRouterConfig::default(),
                audit_tx,
                ui_event_tx,
            );
            let handle = router.run(correlated_rx);
            handles.push(handle);
        }

        // --- Step 4: eslogger (if FDA is granted) ---
        if self.sensor_config.eslogger.enabled {
            let fda_granted = EsloggerManager::check_fda();
            if fda_granted {
                let events: Vec<&str> = self
                    .sensor_config
                    .eslogger
                    .events
                    .iter()
                    .map(|s| s.as_str())
                    .collect();
                match EsloggerManager::spawn(
                    &events,
                    Some(self.sensor_config.eslogger.channel_capacity),
                    &self.sensor_config.eslogger.ignore_processes,
                    &self.sensor_config.eslogger.ignore_paths,
                ) {
                    Ok((_manager, mut eslogger_rx)) => {
                        info!("eslogger: active");
                        let corr_tx = correlation_input_tx.clone();
                        let handle = tokio::spawn(async move {
                            while let Some(os_event) = eslogger_rx.recv().await {
                                if corr_tx
                                    .send(CorrelationInput::Os(os_event))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        });
                        handles.push(handle);
                    }
                    Err(e) => {
                        warn!(error = %e, "eslogger: unavailable (failed to spawn)");
                    }
                }
            } else {
                warn!("eslogger: unavailable (Full Disk Access not granted)");
            }
        } else {
            info!("eslogger: disabled in config");
        }

        // --- Step 5: EnhancedFsWatcher ---
        if self.sensor_config.fsevents.enabled {
            let watch_paths = if self.sensor_config.fsevents.watch_paths.is_empty() {
                default_watch_paths()
            } else {
                self.sensor_config.fsevents.watch_paths.clone()
            };

            if !watch_paths.is_empty() {
                match EnhancedFsWatcher::new(None) {
                    Ok(mut watcher) => match watcher.watch(&watch_paths) {
                        Ok(mut fs_rx) => {
                            info!(
                                count = watch_paths.len(),
                                "FSEvents: watching {} directories",
                                watch_paths.len()
                            );
                            let corr_tx = correlation_input_tx.clone();
                            let handle = tokio::spawn(async move {
                                while let Some(fs_event) = fs_rx.recv().await {
                                    let os_event =
                                        clawdefender_core::event::os::OsEvent::from(fs_event);
                                    if corr_tx
                                        .send(CorrelationInput::Os(os_event))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                            });
                            handles.push(handle);
                        }
                        Err(e) => {
                            warn!(error = %e, "FSEvents: failed to start watching");
                        }
                    },
                    Err(e) => {
                        warn!(error = %e, "FSEvents: failed to create watcher");
                    }
                }
            } else {
                info!("FSEvents: no paths to watch");
            }
        } else {
            info!("FSEvents: disabled in config");
        }

        // --- Step 6: Sensor config hot-reload ---
        let sensor_path = self.config.sensor_config_path.clone();
        if sensor_path.exists() {
            let handle = spawn_file_watcher(sensor_path, "sensor config");
            handles.push(handle);
        }

        // Keep the correlation input sender alive for the proxy to use.
        // We leak it into a static-ish handle via a background task.
        let _corr_tx = correlation_input_tx;

        handles
    }

    /// Main entry point for `clawdefender proxy -- <command> [args...]`.
    ///
    /// Spawns the MCP proxy, sensor subsystem, audit writer, TUI (or headless),
    /// and signal handlers, then runs until the proxy finishes or a signal is received.
    pub async fn run_proxy(self, command: String, args: Vec<String>) -> Result<()> {
        info!("ClawDefender daemon starting");

        // Write PID file.
        let pid_path = pid_file_path();
        write_pid_file(&pid_path)?;

        // --- Channels ---
        let (_prompt_tx, prompt_rx) = mpsc::channel::<PendingPrompt>(64);
        let (_event_tx, event_rx) = mpsc::channel::<EventRecord>(256);
        let (audit_tx, mut audit_rx) = mpsc::channel::<AuditRecord>(1024);

        // Channel for correlated events to be forwarded to UIs.
        let (_ui_correlated_tx, _ui_correlated_rx) = mpsc::channel::<CorrelatedEvent>(256);

        // --- UiBridge (connects proxy prompts to TUI) ---
        let (ui_req_tx, _ui_req_rx) =
            mpsc::channel::<(
                clawdefender_core::ipc::protocol::UiRequest,
                tokio::sync::oneshot::Sender<clawdefender_core::ipc::protocol::UiResponse>,
            )>(64);
        let ui_bridge = Arc::new(UiBridge::new(ui_req_tx));

        // --- Policy engine status ---
        info!("Policy engine: loaded");


        // --- SLM service (advisory only, graceful failure -> disabled mode) ---
        let slm_engine_config = SlmEngineConfig {
            model_path: self
                .config
                .slm
                .model_path
                .clone()
                .unwrap_or_default(),
            context_size: self.config.slm.context_size,
            max_output_tokens: self.config.slm.max_output_tokens,
            temperature: self.config.slm.temperature,
            use_gpu: self.config.slm.use_gpu,
            threads: self.config.slm.threads.unwrap_or(4),
            ..SlmEngineConfig::default()
        };
        let slm_service = Arc::new(SlmService::new(
            slm_engine_config,
            self.config.slm.enabled,
        ));
        if slm_service.is_enabled() {
            info!("SLM: enabled");
        } else {
            info!("SLM: disabled (no model or disabled in config)");
        }

        let noise_filter = Arc::new(tokio::sync::Mutex::new(NoiseFilter::new()));
        let context_tracker = Arc::new(tokio::sync::Mutex::new(ContextTracker::new()));

        // --- Swarm (cloud analysis) initialization ---
        let swarm_commander: Option<Arc<Commander>> = if self.config.swarm.enabled {
            let keystore: Arc<dyn KeyStore> = Arc::from(keychain::default_keystore());
            let has_api_key = keystore.get(&Provider::Anthropic).is_ok()
                || keystore.get(&Provider::OpenAi).is_ok();

            if has_api_key {
                let llm_client: Arc<dyn LlmClient> = Arc::new(HttpLlmClient::new(keystore));

                let data_dir = if let Some(home) = std::env::var_os("HOME") {
                    PathBuf::from(home).join(".local/share/clawdefender")
                } else {
                    PathBuf::from("/tmp/clawdefender")
                };
                std::fs::create_dir_all(&data_dir).ok();
                let cost_db = data_dir.join("swarm_usage.db");

                let budget = BudgetConfig {
                    daily_limit_usd: self.config.swarm.daily_budget_usd,
                    monthly_limit_usd: self.config.swarm.monthly_budget_usd,
                };
                let cost_tracker = match CostTracker::new(&cost_db, PricingTable::default(), budget)
                {
                    Ok(t) => Some(Arc::new(std::sync::Mutex::new(t))),
                    Err(e) => {
                        warn!(error = %e, "Failed to initialize swarm cost tracker");
                        None
                    }
                };

                let commander = Commander::new(llm_client, cost_tracker);
                info!("Swarm: enabled");
                Some(Arc::new(commander))
            } else {
                info!("Swarm: disabled (no API key)");
                None
            }
        } else {
            info!("Swarm: disabled in config");
            None
        };

        // --- Chat server (only if swarm is active) ---
        let chat_server_handle = if let Some(ref commander) = swarm_commander {
            let data_dir = if let Some(home) = std::env::var_os("HOME") {
                PathBuf::from(home).join(".local/share/clawdefender")
            } else {
                PathBuf::from("/tmp/clawdefender")
            };
            let chat_db = data_dir.join("chat.db");
            let llm_client = commander.llm_client();
            let cost_tracker = commander.cost_tracker();

            match ChatManager::new(&chat_db, llm_client, cost_tracker) {
                Ok(chat_manager) => {
                    let chat_manager = Arc::new(chat_manager);
                    let chat_port = self.config.swarm.chat_port;
                    let server = ChatServer::new(Arc::clone(&chat_manager), chat_port);
                    let handle = tokio::spawn(async move {
                        if let Err(e) = server.start().await {
                            warn!(error = %e, "Chat server exited");
                        }
                    });
                    info!(port = chat_port, "Chat server started");
                    Some(handle)
                }
                Err(e) => {
                    warn!(error = %e, "Failed to initialize chat manager");
                    None
                }
            }
        } else {
            None
        };

        // --- MCP server (cooperative security endpoint) ---
        let mcp_server_handle = if self.config.mcp_server.enabled {
            let policy_snapshot = if self.config.policy_path.exists() {
                DefaultPolicyEngine::load(&self.config.policy_path)
                    .unwrap_or_else(|_| DefaultPolicyEngine::empty())
            } else {
                DefaultPolicyEngine::empty()
            };
            let mcp_audit = Arc::clone(&self.audit_logger);
            let mcp_server = Arc::new(McpServer::new(Box::new(policy_snapshot), mcp_audit));
            let mcp_port = self.config.mcp_server.http_port;
            let handle = tokio::spawn(async move {
                if let Err(e) = mcp_server.run_http(mcp_port).await {
                    warn!(error = %e, "MCP server exited");
                }
            });
            info!(port = mcp_port, "MCP server: listening on HTTP port {}", mcp_port);
            Some(handle)
        } else {
            info!("MCP server: disabled in config");
            None
        };

        // --- Guard PID cleanup task ---
        let guard_registry_cleanup = Arc::clone(&self.guard_registry);
        let guard_cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                guard_registry_cleanup.cleanup_dead_pids().await;
            }
        });

        // --- Guard REST API server ---
        let guard_api_handle = if self.config.guard_api.enabled {
            let registry_for_api = (*self.guard_registry).clone();
            let api_config = clawdefender_guard::api::ApiConfig {
                bind_addr: format!("127.0.0.1:{}", self.config.guard_api.port)
                    .parse()
                    .unwrap(),
                token: String::new(),
            };
            let handle = tokio::spawn(async move {
                if let Err(e) =
                    clawdefender_guard::api::run_api_server(api_config, registry_for_api).await
                {
                    warn!(error = %e, "Guard API server exited");
                }
            });
            info!(
                port = self.config.guard_api.port,
                "Guard API server: listening on port {}", self.config.guard_api.port
            );
            Some(handle)
        } else {
            info!("Guard API server: disabled in config");
            None
        };

        // --- Audit writer task ---
        let audit_logger = Arc::clone(&self.audit_logger);
        let audit_writer_handle = tokio::spawn(async move {
            while let Some(record) = audit_rx.recv().await {
                if let Err(e) = audit_logger.log(&record) {
                    error!(error = %e, "failed to write audit record");
                }
            }
            info!("audit writer task finished");
        });

        // --- Sensor subsystem (process tree, eslogger, FSEvents, correlation) ---
        let process_tree = Arc::new(RwLock::new(ProcessTree::new()));
        let sensor_handles = self
            .start_sensor_subsystem(
                Arc::clone(&process_tree),
                audit_tx.clone(),
                _ui_correlated_tx,
            )
            .await;

        // --- TUI or headless ---
        let ui_mode = if self.enable_tui && std::io::stdout().is_terminal() {
            "TUI mode"
        } else {
            "headless"
        };
        info!(mode = ui_mode, "UI: {}", ui_mode);

        let tui_handle = if self.enable_tui && std::io::stdout().is_terminal() {
            Some(tokio::task::spawn_blocking(move || {
                let rt = tokio::runtime::Handle::current();
                if let Err(e) = rt.block_on(clawdefender_tui::run(prompt_rx, event_rx)) {
                    error!(error = %e, "TUI exited with error");
                }
            }))
        } else {
            Some(tokio::spawn(async move {
                if let Err(e) = clawdefender_tui::run_headless(prompt_rx).await {
                    error!(error = %e, "headless prompt handler exited with error");
                }
                drop(event_rx);
            }))
        };

        // --- Proxy config ---
        let proxy_config = ProxyConfig {
            server_command: Some(command.clone()),
            server_args: args.clone(),
            ..Default::default()
        };

        // Get a snapshot of the policy engine for the proxy.
        let policy_snapshot = {
            if self.config.policy_path.exists() {
                DefaultPolicyEngine::load(&self.config.policy_path)
                    .unwrap_or_else(|_| DefaultPolicyEngine::empty())
            } else {
                DefaultPolicyEngine::empty()
            }
        };

        // --- Create StdioProxy ---
        let slm_ctx = clawdefender_mcp_proxy::SlmContext {
            slm_service: Arc::clone(&slm_service),
            noise_filter: Arc::clone(&noise_filter),
            context_tracker: Arc::clone(&context_tracker),
        };
        let mut proxy = StdioProxy::with_full_config(
            proxy_config,
            policy_snapshot,
            audit_tx.clone(),
            Some(ui_bridge),
        )
        .with_slm_context(slm_ctx);

        if let Some(ref commander) = swarm_commander {
            proxy = proxy.with_swarm_context(clawdefender_mcp_proxy::SwarmContext {
                commander: Arc::clone(commander),
                escalation_threshold: self.config.swarm.escalation_threshold.clone(),
            });
        }

        if let Some(ref ioc_db) = self.ioc_database {
            proxy = proxy.with_threat_intel_context(clawdefender_mcp_proxy::ThreatIntelContext {
                ioc_database: Arc::clone(ioc_db),
            });
        }

        let metrics = Arc::clone(proxy.metrics());

        // --- Policy hot-reload via notify ---
        let policy_path = self.config.policy_path.clone();
        let policy_engine_for_reload = Arc::clone(&self.policy_engine);
        let _reload_handle = if policy_path.exists() {
            Some(spawn_policy_watcher(policy_path, policy_engine_for_reload))
        } else {
            None
        };

        // --- IPC server ---
        let socket_path = self.config.daemon_socket_path.clone();
        info!(path = %socket_path.display(), "IPC: listening on {}", socket_path.display());
        let metrics_for_ipc = Arc::clone(&metrics);
        let policy_for_ipc = Arc::clone(&self.policy_engine);
        let guard_registry_for_ipc = Arc::clone(&self.guard_registry);
        let ipc_handle = tokio::spawn(async move {
            if let Err(e) =
                ipc::run_ipc_server(socket_path, metrics_for_ipc, policy_for_ipc, guard_registry_for_ipc).await
            {
                warn!(error = %e, "IPC server exited");
            }
        });

        // --- Signal handlers ---
        #[cfg(unix)]
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        #[cfg(unix)]
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

        // --- Run proxy with graceful shutdown ---
        info!(cmd = %command, args = ?args, "MCP proxy: ready");

        #[cfg(unix)]
        {
            tokio::select! {
                result = proxy.run() => {
                    match &result {
                        Ok(()) => info!("proxy finished normally"),
                        Err(e) => error!(error = %e, "proxy exited with error"),
                    }
                    result?;
                }
                _ = sigterm.recv() => {
                    info!("SIGTERM received, shutting down");
                }
                _ = sigint.recv() => {
                    info!("SIGINT received, shutting down");
                }
            }
        }

        #[cfg(not(unix))]
        {
            tokio::select! {
                result = proxy.run() => {
                    match &result {
                        Ok(()) => info!("proxy finished normally"),
                        Err(e) => error!(error = %e, "proxy exited with error"),
                    }
                    result?;
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl-C received, shutting down");
                }
            }
        }

        // --- Cleanup ---
        // Drop audit sender to signal the writer to finish.
        drop(audit_tx);
        let _ = audit_writer_handle.await;

        // Shut down audit logger (flushes + session-end record).
        self.audit_logger.shutdown();

        // Abort sensor tasks.
        for handle in sensor_handles {
            handle.abort();
        }

        // Abort guard tasks.
        guard_cleanup_handle.abort();
        if let Some(handle) = guard_api_handle {
            handle.abort();
            info!("guard API server stopped");
        }

        // Abort IPC server.
        ipc_handle.abort();

        // Abort chat server.
        if let Some(handle) = chat_server_handle {
            handle.abort();
            info!("chat server stopped");
        }

        // Abort MCP server.
        if let Some(handle) = mcp_server_handle {
            handle.abort();
            info!("MCP server stopped");
        }

        // Wait for TUI.
        if let Some(handle) = tui_handle {
            let _ = handle.await;
        }

        // Remove PID file.
        remove_pid_file(&pid_path);

        info!("daemon shut down");
        Ok(())
    }
}

/// Spawn a file watcher for policy hot-reload.
fn spawn_policy_watcher(
    policy_path: PathBuf,
    policy_engine: Arc<RwLock<DefaultPolicyEngine>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        use notify::{Event, EventKind, RecursiveMode, Watcher};

        let (tx, mut rx) = mpsc::channel::<()>(4);

        let watch_path = policy_path.clone();
        let mut watcher = match notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                if matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_)
                ) {
                    let _ = tx.try_send(());
                }
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!(error = %e, "failed to create file watcher for policy reload");
                return;
            }
        };

        let watch_dir = watch_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        if let Err(e) = watcher.watch(watch_dir, RecursiveMode::NonRecursive) {
            warn!(error = %e, "failed to watch policy directory");
            return;
        }

        info!(path = %policy_path.display(), "watching policy file for changes");

        while rx.recv().await.is_some() {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            while rx.try_recv().is_ok() {}

            let mut engine = policy_engine.write().await;
            match engine.reload() {
                Ok(()) => {
                    info!("policy reloaded successfully");
                }
                Err(e) => {
                    warn!(error = %e, "failed to reload policy");
                }
            }
        }
    })
}

/// Spawn a generic file watcher that logs reload events (for sensor.toml etc.).
fn spawn_file_watcher(
    file_path: PathBuf,
    label: &'static str,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        use notify::{Event, EventKind, RecursiveMode, Watcher};

        let (tx, mut rx) = mpsc::channel::<()>(4);

        let watch_path = file_path.clone();
        let mut watcher = match notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                if matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_)
                ) {
                    let _ = tx.try_send(());
                }
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!(error = %e, label = label, "failed to create file watcher");
                return;
            }
        };

        let watch_dir = watch_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        if let Err(e) = watcher.watch(watch_dir, RecursiveMode::NonRecursive) {
            warn!(error = %e, label = label, "failed to watch directory");
            return;
        }

        info!(path = %file_path.display(), label = label, "watching file for changes");

        while rx.recv().await.is_some() {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            while rx.try_recv().is_ok() {}
            info!(label = label, "{} changed, reload pending", label);
        }
    })
}

/// Path for the daemon PID file.
fn pid_file_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".local/share/clawdefender/clawdefender.pid")
    } else {
        PathBuf::from("/tmp/clawdefender.pid")
    }
}

/// Write the current PID to the PID file.
fn write_pid_file(path: &PathBuf) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let pid = std::process::id();
    std::fs::write(path, pid.to_string())
        .with_context(|| format!("writing PID file: {}", path.display()))?;
    info!(pid = pid, path = %path.display(), "wrote PID file");
    Ok(())
}

/// Remove the PID file on clean shutdown.
fn remove_pid_file(path: &PathBuf) {
    if path.exists() {
        if let Err(e) = std::fs::remove_file(path) {
            warn!(error = %e, "failed to remove PID file");
        } else {
            info!(path = %path.display(), "removed PID file");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clawdefender_core::config::settings::SensorConfig;
    use clawdefender_core::ipc::protocol::{
        DaemonRequest, DaemonResponse, SubsystemStatus, UserDecision,
    };
    use tempfile::TempDir;

    fn test_config(dir: &TempDir) -> ClawConfig {
        let mut config = ClawConfig::default();
        config.audit_log_path = dir.path().join("audit.jsonl");
        config.daemon_socket_path = dir.path().join("test.sock");
        config.eslogger.enabled = false;
        config
    }

    #[test]
    fn daemon_new_with_default_config() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let daemon = Daemon::new(config, false).unwrap();
        assert!(!daemon.enable_tui);
    }

    #[test]
    fn daemon_new_loads_sensor_config_defaults() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        // Point to a non-existent sensor config -> should use defaults.
        config.sensor_config_path = dir.path().join("nonexistent-sensor.toml");
        let daemon = Daemon::new(config, false).unwrap();
        assert!(daemon.sensor_config.eslogger.enabled);
        assert_eq!(daemon.sensor_config.process_tree.refresh_interval_secs, 5);
    }

    #[test]
    fn daemon_new_loads_custom_sensor_config() {
        let dir = TempDir::new().unwrap();
        let sensor_path = dir.path().join("sensor.toml");
        std::fs::write(
            &sensor_path,
            r#"
[eslogger]
enabled = false

[process_tree]
refresh_interval_secs = 10

[correlation]
window_ms = 1000
"#,
        )
        .unwrap();

        let mut config = test_config(&dir);
        config.sensor_config_path = sensor_path;
        let daemon = Daemon::new(config, false).unwrap();
        assert!(!daemon.sensor_config.eslogger.enabled);
        assert_eq!(daemon.sensor_config.process_tree.refresh_interval_secs, 10);
        assert_eq!(daemon.sensor_config.correlation.window_ms, 1000);
    }

    #[test]
    fn daemon_graceful_without_fda() {
        // Daemon should create successfully even when eslogger is enabled
        // but FDA is not granted (the actual sensor start happens at runtime).
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let daemon = Daemon::new(config, false);
        assert!(daemon.is_ok(), "daemon should start without FDA");
    }

    #[test]
    fn pid_file_creation_and_cleanup() {
        let dir = TempDir::new().unwrap();
        let pid_path = dir.path().join("test.pid");
        write_pid_file(&pid_path).unwrap();
        assert!(pid_path.exists());
        let contents = std::fs::read_to_string(&pid_path).unwrap();
        assert_eq!(contents, std::process::id().to_string());
        remove_pid_file(&pid_path);
        assert!(!pid_path.exists());
    }

    #[tokio::test]
    async fn audit_channel_writer_processes_records() {
        let dir = TempDir::new().unwrap();
        let logger = Arc::new(
            FileAuditLogger::new(
                dir.path().join("audit.jsonl"),
                clawdefender_core::config::settings::LogRotation::default(),
            )
            .unwrap(),
        );

        let (audit_tx, mut audit_rx) = mpsc::channel::<AuditRecord>(16);
        let logger_clone = Arc::clone(&logger);
        let writer = tokio::spawn(async move {
            while let Some(record) = audit_rx.recv().await {
                logger_clone.log(&record).unwrap();
            }
        });

        let record = AuditRecord {
            timestamp: chrono::Utc::now(),
            source: "test".to_string(),
            event_summary: "test event".to_string(),
            event_details: serde_json::json!({}),
            rule_matched: None,
            action_taken: "allow".to_string(),
            response_time_ms: None,
            session_id: None,
            direction: None,
            server_name: None,
            client_name: None,
            jsonrpc_method: None,
            tool_name: None,
            arguments: None,
            classification: None,
            policy_rule: None,
            policy_action: None,
            user_decision: None,
            proxy_latency_us: None,
            slm_analysis: None,
            swarm_analysis: None,
            behavioral: None,
            injection_scan: None,
            threat_intel: None,
        };
        audit_tx.send(record).await.unwrap();
        drop(audit_tx);
        writer.await.unwrap();

        let filter = clawdefender_core::audit::AuditFilter {
            action: Some("allow".to_string()),
            limit: 100,
            ..Default::default()
        };
        let results = logger.query(&filter).unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn daemon_starts_with_swarm_disabled_no_api_key() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.swarm.enabled = true;
        let daemon = Daemon::new(config, false);
        assert!(daemon.is_ok(), "daemon should start even without API key");
    }

    #[test]
    fn daemon_starts_with_swarm_explicitly_disabled() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.swarm.enabled = false;
        let daemon = Daemon::new(config, false);
        assert!(daemon.is_ok(), "daemon should start with swarm disabled");
    }

    #[test]
    fn slm_service_disabled_without_model() {
        let slm_config = SlmEngineConfig::default();
        let svc = SlmService::new(slm_config, true);
        assert!(!svc.is_enabled());
    }

    #[test]
    fn slm_service_disabled_when_config_says_disabled() {
        let slm_config = SlmEngineConfig::default();
        let svc = SlmService::new(slm_config, false);
        assert!(!svc.is_enabled());
    }

    #[test]
    fn config_parsing_with_slm_section() {
        let toml_str = r#"
[slm]
enabled = true
context_size = 4096
max_output_tokens = 512
temperature = 0.2
use_gpu = false
threads = 8
"#;
        let config: ClawConfig = toml::from_str(toml_str).unwrap();
        assert!(config.slm.enabled);
        assert_eq!(config.slm.context_size, 4096);
        assert_eq!(config.slm.max_output_tokens, 512);
        assert!((config.slm.temperature - 0.2).abs() < f32::EPSILON);
        assert!(!config.slm.use_gpu);
        assert_eq!(config.slm.threads, Some(8));
        assert!(config.slm.model_path.is_none());
    }

    #[test]
    fn config_parsing_slm_defaults() {
        let toml_str = "";
        let config: ClawConfig = toml::from_str(toml_str).unwrap();
        assert!(config.slm.enabled);
        assert_eq!(config.slm.context_size, 2048);
        assert_eq!(config.slm.max_output_tokens, 256);
        assert!((config.slm.temperature - 0.1).abs() < f32::EPSILON);
        assert!(config.slm.use_gpu);
        assert!(config.slm.threads.is_none());
    }

    #[tokio::test]
    async fn audit_record_includes_slm_analysis_when_present() {
        use clawdefender_core::audit::SlmAnalysisRecord;

        let dir = TempDir::new().unwrap();
        let logger = Arc::new(
            FileAuditLogger::new(
                dir.path().join("audit.jsonl"),
                clawdefender_core::config::settings::LogRotation::default(),
            )
            .unwrap(),
        );

        let record = AuditRecord {
            timestamp: chrono::Utc::now(),
            source: "test".to_string(),
            event_summary: "test event".to_string(),
            event_details: serde_json::json!({}),
            rule_matched: None,
            action_taken: "slm_analysis".to_string(),
            response_time_ms: None,
            session_id: None,
            direction: None,
            server_name: None,
            client_name: None,
            jsonrpc_method: None,
            tool_name: None,
            arguments: None,
            classification: None,
            policy_rule: None,
            policy_action: None,
            user_decision: None,
            proxy_latency_us: None,
            slm_analysis: Some(SlmAnalysisRecord {
                risk_level: "HIGH".to_string(),
                explanation: "Suspicious file access".to_string(),
                confidence: 0.88,
                latency_ms: 150,
                model: "mock-model-q4".to_string(),
            }),
            swarm_analysis: None,
            behavioral: None,
            injection_scan: None,
            threat_intel: None,
        };

        logger.log(&record).unwrap();

        let filter = clawdefender_core::audit::AuditFilter {
            action: Some("slm_analysis".to_string()),
            limit: 100,
            ..Default::default()
        };
        let results = logger.query(&filter).unwrap();
        assert!(!results.is_empty());
        let first = &results[0];
        let slm = first.slm_analysis.as_ref().unwrap();
        assert_eq!(slm.risk_level, "HIGH");
        assert_eq!(slm.explanation, "Suspicious file access");
        assert!((slm.confidence - 0.88).abs() < f32::EPSILON);
        assert_eq!(slm.latency_ms, 150);
        assert_eq!(slm.model, "mock-model-q4");
    }

    // --- New tests for Phase 2 ---

    #[test]
    fn sensor_config_defaults() {
        let config = SensorConfig::default();
        assert!(config.eslogger.enabled);
        assert_eq!(config.process_tree.refresh_interval_secs, 5);
        assert_eq!(config.correlation.window_ms, 500);
    }

    #[test]
    fn sensor_config_load_from_toml() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sensor.toml");
        std::fs::write(
            &path,
            r#"
[eslogger]
enabled = false
events = ["exec", "open"]
channel_capacity = 5000

[fsevents]
enabled = true

[correlation]
window_ms = 2000

[process_tree]
refresh_interval_secs = 3
"#,
        )
        .unwrap();

        let config = SensorConfig::load(&path).unwrap();
        assert!(!config.eslogger.enabled);
        assert_eq!(config.eslogger.events, vec!["exec", "open"]);
        assert_eq!(config.eslogger.channel_capacity, 5000);
        assert!(config.fsevents.enabled);
        assert_eq!(config.correlation.window_ms, 2000);
        assert_eq!(config.process_tree.refresh_interval_secs, 3);
    }

    #[test]
    fn sensor_config_load_missing_file_returns_defaults() {
        let config = SensorConfig::load(std::path::Path::new("/nonexistent/sensor.toml")).unwrap();
        assert!(config.eslogger.enabled);
    }

    #[test]
    fn daemon_request_serialization() {
        let req = DaemonRequest::ProxyRegister {
            server_name: "fs-server".to_string(),
            client_name: "claude".to_string(),
            pid: 1234,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            DaemonRequest::ProxyRegister {
                server_name,
                client_name,
                pid,
            } => {
                assert_eq!(server_name, "fs-server");
                assert_eq!(client_name, "claude");
                assert_eq!(pid, 1234);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn daemon_response_serialization() {
        let resp = DaemonResponse::StatusReport {
            subsystems: vec![
                SubsystemStatus {
                    name: "eslogger".to_string(),
                    active: true,
                    detail: "monitoring 8 event types".to_string(),
                },
                SubsystemStatus {
                    name: "fsevents".to_string(),
                    active: true,
                    detail: "watching 5 directories".to_string(),
                },
            ],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: DaemonResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            DaemonResponse::StatusReport { subsystems } => {
                assert_eq!(subsystems.len(), 2);
                assert_eq!(subsystems[0].name, "eslogger");
                assert!(subsystems[0].active);
                assert_eq!(subsystems[1].name, "fsevents");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn daemon_request_shutdown_serialization() {
        let req = DaemonRequest::Shutdown;
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, DaemonRequest::Shutdown));
    }

    #[test]
    fn daemon_request_prompt_response_serialization() {
        let req = DaemonRequest::PromptResponse {
            event_id: "evt-123".to_string(),
            decision: UserDecision::AllowOnce,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            DaemonRequest::PromptResponse {
                event_id,
                decision,
            } => {
                assert_eq!(event_id, "evt-123");
                assert_eq!(decision, UserDecision::AllowOnce);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn daemon_response_error_serialization() {
        let resp = DaemonResponse::Error {
            message: "something went wrong".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: DaemonResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            DaemonResponse::Error { message } => {
                assert_eq!(message, "something went wrong");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn daemon_status_report_includes_all_subsystems() {
        let statuses = vec![
            SubsystemStatus {
                name: "policy_engine".to_string(),
                active: true,
                detail: "5 rules loaded".to_string(),
            },
            SubsystemStatus {
                name: "audit_logger".to_string(),
                active: true,
                detail: "/path/to/audit.jsonl".to_string(),
            },
            SubsystemStatus {
                name: "process_tree".to_string(),
                active: true,
                detail: "150 processes".to_string(),
            },
            SubsystemStatus {
                name: "eslogger".to_string(),
                active: false,
                detail: "FDA not granted".to_string(),
            },
            SubsystemStatus {
                name: "fsevents".to_string(),
                active: true,
                detail: "3 directories".to_string(),
            },
            SubsystemStatus {
                name: "correlation".to_string(),
                active: true,
                detail: "running".to_string(),
            },
            SubsystemStatus {
                name: "slm".to_string(),
                active: false,
                detail: "no model configured".to_string(),
            },
            SubsystemStatus {
                name: "swarm".to_string(),
                active: false,
                detail: "disabled".to_string(),
            },
        ];

        let resp = DaemonResponse::StatusReport {
            subsystems: statuses.clone(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: DaemonResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            DaemonResponse::StatusReport { subsystems } => {
                assert_eq!(subsystems.len(), 8);
                let eslogger = subsystems.iter().find(|s| s.name == "eslogger").unwrap();
                assert!(!eslogger.active);
                assert_eq!(eslogger.detail, "FDA not granted");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn config_has_sensor_config_path_default() {
        let config = ClawConfig::default();
        assert!(config.sensor_config_path.to_string_lossy().contains("sensor.toml"));
    }

    #[test]
    fn config_parses_sensor_config_path() {
        let toml_str = r#"
sensor_config_path = "/custom/path/sensor.toml"
"#;
        let config: ClawConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.sensor_config_path,
            PathBuf::from("/custom/path/sensor.toml")
        );
    }

    #[tokio::test]
    async fn event_router_forwards_to_audit() {
        let (audit_tx, mut audit_rx) = mpsc::channel::<AuditRecord>(16);
        let (ui_tx, _ui_rx) = mpsc::channel::<CorrelatedEvent>(16);
        let (correlated_tx, correlated_rx) = mpsc::channel::<CorrelatedEvent>(16);

        let router = EventRouter::new(EventRouterConfig::default(), audit_tx, ui_tx);
        let _handle = router.run(correlated_rx);

        let event = CorrelatedEvent {
            id: "test-1".to_string(),
            mcp_event: None,
            os_events: vec![],
            status: clawdefender_core::event::correlation::CorrelationStatus::Uncorrelated,
            correlated_at: Some(chrono::Utc::now()),
        };
        correlated_tx.send(event).await.unwrap();
        drop(correlated_tx);

        let record = tokio::time::timeout(Duration::from_secs(1), audit_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(record.source, "correlation");
    }

    // --- Behavioral engine integration tests ---

    #[test]
    fn behavioral_engine_initializes_when_enabled() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.behavioral.enabled = true;
        let daemon = Daemon::new(config, false).unwrap();
        assert!(daemon.behavioral_engine.is_some());
        assert!(daemon.anomaly_scorer.is_some());
        assert!(daemon.killchain_detector.is_some());
        assert!(daemon.decision_engine.is_some());
        assert!(daemon.injection_detector.is_some());
        assert!(daemon.profile_store.is_some());
    }

    #[test]
    fn behavioral_engine_disabled_when_config_says_disabled() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.behavioral.enabled = false;
        let daemon = Daemon::new(config, false).unwrap();
        assert!(daemon.behavioral_engine.is_none());
        assert!(daemon.anomaly_scorer.is_none());
        assert!(daemon.killchain_detector.is_none());
        assert!(daemon.decision_engine.is_none());
        assert!(daemon.injection_detector.is_none());
        assert!(daemon.profile_store.is_none());
    }

    #[test]
    fn behavioral_engine_default_config_is_enabled() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        // Default BehavioralConfig has enabled=true
        assert!(config.behavioral.enabled);
        let daemon = Daemon::new(config, false).unwrap();
        assert!(daemon.behavioral_engine.is_some());
    }

    #[test]
    fn behavioral_engine_respects_auto_block_config() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.behavioral.enabled = true;
        config.behavioral.auto_block_enabled = true;
        config.behavioral.auto_block_threshold = 0.85;
        config.behavioral.anomaly_threshold = 0.65;
        let daemon = Daemon::new(config, false).unwrap();
        // Verify decision engine has the right thresholds
        let de = daemon.decision_engine.as_ref().unwrap();
        let de_guard = de.try_read().unwrap();
        assert!(de_guard.auto_block_enabled);
        assert!((de_guard.auto_block_threshold - 0.85).abs() < f64::EPSILON);
        assert!((de_guard.anomaly_threshold - 0.65).abs() < f64::EPSILON);
    }

    #[test]
    fn behavioral_engine_preserves_phase0_behavior_disabled() {
        // When behavioral is disabled, daemon should still start normally
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.behavioral.enabled = false;
        let daemon = Daemon::new(config, false);
        assert!(daemon.is_ok());
    }

    #[test]
    fn audit_record_includes_behavioral_fields() {
        let record = AuditRecord {
            timestamp: chrono::Utc::now(),
            source: "test".to_string(),
            event_summary: "behavioral test".to_string(),
            event_details: serde_json::json!({}),
            rule_matched: None,
            action_taken: "allow".to_string(),
            response_time_ms: None,
            session_id: None,
            direction: None,
            server_name: None,
            client_name: None,
            jsonrpc_method: None,
            tool_name: None,
            arguments: None,
            classification: None,
            policy_rule: None,
            policy_action: None,
            user_decision: None,
            proxy_latency_us: None,
            slm_analysis: None,
            swarm_analysis: None,
            behavioral: Some(clawdefender_core::behavioral::BehavioralAuditData {
                anomaly_score: 0.75,
                anomaly_components: vec![],
                kill_chain: None,
                auto_blocked: false,
                profile_status: "active".to_string(),
                observation_count: 500,
            }),
            injection_scan: Some(clawdefender_core::audit::InjectionScanData {
                score: 0.3,
                patterns_found: vec!["test_pattern".to_string()],
            }),
            threat_intel: None,
        };

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("behavioral"));
        assert!(json.contains("0.75"));
        assert!(json.contains("injection_scan"));
        assert!(json.contains("test_pattern"));

        // Round-trip
        let deserialized: AuditRecord = serde_json::from_str(&json).unwrap();
        let b = deserialized.behavioral.unwrap();
        assert!((b.anomaly_score - 0.75).abs() < f64::EPSILON);
        assert_eq!(b.profile_status, "active");
        let inj = deserialized.injection_scan.unwrap();
        assert!((inj.score - 0.3).abs() < f64::EPSILON);
        assert_eq!(inj.patterns_found, vec!["test_pattern"]);
    }

    #[test]
    fn audit_record_omits_behavioral_when_none() {
        let record = AuditRecord {
            timestamp: chrono::Utc::now(),
            source: "test".to_string(),
            event_summary: "plain event".to_string(),
            event_details: serde_json::json!({}),
            rule_matched: None,
            action_taken: "allow".to_string(),
            response_time_ms: None,
            session_id: None,
            direction: None,
            server_name: None,
            client_name: None,
            jsonrpc_method: None,
            tool_name: None,
            arguments: None,
            classification: None,
            policy_rule: None,
            policy_action: None,
            user_decision: None,
            proxy_latency_us: None,
            slm_analysis: None,
            swarm_analysis: None,
            behavioral: None,
            injection_scan: None,
            threat_intel: None,
        };

        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("behavioral"));
        assert!(!json.contains("injection_scan"));
    }

    #[test]
    fn config_parsing_with_behavioral_section() {
        let toml_str = r#"
[behavioral]
enabled = true
learning_event_threshold = 200
learning_time_minutes = 60
anomaly_threshold = 0.8
auto_block_threshold = 0.95
auto_block_enabled = true

[injection_detector]
enabled = true
threshold = 0.5
auto_block = false
"#;
        let config: ClawConfig = toml::from_str(toml_str).unwrap();
        assert!(config.behavioral.enabled);
        assert_eq!(config.behavioral.learning_event_threshold, 200);
        assert_eq!(config.behavioral.learning_time_minutes, 60);
        assert!((config.behavioral.anomaly_threshold - 0.8).abs() < f64::EPSILON);
        assert!((config.behavioral.auto_block_threshold - 0.95).abs() < f64::EPSILON);
        assert!(config.behavioral.auto_block_enabled);
        assert!(config.injection_detector.enabled);
        assert!((config.injection_detector.threshold - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn config_parsing_behavioral_defaults() {
        let toml_str = "";
        let config: ClawConfig = toml::from_str(toml_str).unwrap();
        assert!(config.behavioral.enabled);
        assert_eq!(config.behavioral.learning_event_threshold, 100);
        assert_eq!(config.behavioral.learning_time_minutes, 30);
        assert!((config.behavioral.anomaly_threshold - 0.7).abs() < f64::EPSILON);
        assert!((config.behavioral.auto_block_threshold - 0.9).abs() < f64::EPSILON);
        assert!(!config.behavioral.auto_block_enabled);
        assert!(config.injection_detector.enabled);
        assert!((config.injection_detector.threshold - 0.6).abs() < f64::EPSILON);
    }

    #[test]
    fn injection_detector_initialization() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.behavioral.enabled = true;
        config.injection_detector.enabled = true;
        config.injection_detector.threshold = 0.5;
        let daemon = Daemon::new(config, false).unwrap();
        assert!(daemon.injection_detector.is_some());
    }

    // --- Threat intelligence integration tests ---

    #[test]
    fn threat_intel_initializes_when_enabled() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.threat_intel.enabled = true;
        let daemon = Daemon::new(config, false).unwrap();
        assert!(daemon.ioc_database.is_some());
        assert!(daemon.blocklist_matcher.is_some());
        assert!(daemon.rule_pack_manager.is_some());
        assert!(daemon.telemetry_aggregator.is_some());
    }

    #[test]
    fn threat_intel_disabled_when_config_says_disabled() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.threat_intel.enabled = false;
        let daemon = Daemon::new(config, false).unwrap();
        assert!(daemon.ioc_database.is_none());
        assert!(daemon.blocklist_matcher.is_none());
        assert!(daemon.rule_pack_manager.is_none());
        assert!(daemon.telemetry_aggregator.is_none());
        assert!(daemon.feed_client.is_none());
    }

    #[test]
    fn threat_intel_ioc_database_starts_empty() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.threat_intel.enabled = true;
        let daemon = Daemon::new(config, false).unwrap();
        let db = daemon.ioc_database.as_ref().unwrap();
        let db_guard = db.try_read().unwrap();
        let stats = db_guard.stats();
        // Empty because no IoC files have been pre-populated.
        assert_eq!(stats.total_entries, 0);
    }

    #[test]
    fn threat_intel_ioc_matching_pipeline() {
        use clawdefender_threat_intel::ioc::types::{
            EventData, Indicator, IndicatorEntry, Severity,
        };
        use clawdefender_threat_intel::ioc::IoCDatabase;

        // Create a database with a known indicator.
        let mut db = IoCDatabase::new();
        let entry = IndicatorEntry {
            indicator: Indicator::MaliciousDomain("evil.example.com".to_string()),
            severity: Severity::Critical,
            threat_id: "TI-001".to_string(),
            description: "Known malicious domain".to_string(),
            last_updated: chrono::Utc::now(),
            confidence: 0.95,
            false_positive_rate: 0.01,
            permanent: false,
            expires_at: None,
        };
        db.add_indicator_and_rebuild(entry);

        // Check an event that matches the indicator.
        let event = EventData {
            event_id: "test-event-1".to_string(),
            destination_domain: Some("evil.example.com".to_string()),
            ..Default::default()
        };
        let engine = db.engine();
        let matches = engine.check_event(&event);
        assert!(!matches.is_empty(), "should match the malicious domain IoC");
        assert_eq!(matches[0].indicator.threat_id, "TI-001");

        // Check an event that does NOT match.
        let safe_event = EventData {
            event_id: "test-event-2".to_string(),
            destination_domain: Some("safe.example.com".to_string()),
            ..Default::default()
        };
        let safe_matches = engine.check_event(&safe_event);
        assert!(safe_matches.is_empty(), "should not match a safe domain");
    }

    #[test]
    fn threat_intel_audit_record_with_ioc_match() {
        use clawdefender_core::audit::{IoCMatchRecord, ThreatIntelAuditData};

        let record = AuditRecord {
            timestamp: chrono::Utc::now(),
            source: "test".to_string(),
            event_summary: "threat intel match test".to_string(),
            event_details: serde_json::json!({}),
            rule_matched: None,
            action_taken: "allow".to_string(),
            response_time_ms: None,
            session_id: None,
            direction: None,
            server_name: None,
            client_name: None,
            jsonrpc_method: None,
            tool_name: None,
            arguments: None,
            classification: None,
            policy_rule: None,
            policy_action: None,
            user_decision: None,
            proxy_latency_us: None,
            slm_analysis: None,
            swarm_analysis: None,
            behavioral: None,
            injection_scan: None,
            threat_intel: Some(ThreatIntelAuditData {
                ioc_matches: vec![IoCMatchRecord {
                    threat_id: "TI-001".to_string(),
                    indicator_type: "MaliciousDomain".to_string(),
                    severity: "Critical".to_string(),
                }],
                blocklist_match: None,
                community_rule: None,
            }),
        };

        // Round-trip serialization.
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("threat_intel"));
        assert!(json.contains("TI-001"));
        assert!(json.contains("MaliciousDomain"));

        let deserialized: AuditRecord = serde_json::from_str(&json).unwrap();
        let ti = deserialized.threat_intel.unwrap();
        assert_eq!(ti.ioc_matches.len(), 1);
        assert_eq!(ti.ioc_matches[0].threat_id, "TI-001");
        assert_eq!(ti.ioc_matches[0].indicator_type, "MaliciousDomain");
        assert_eq!(ti.ioc_matches[0].severity, "Critical");
    }

    #[test]
    fn threat_intel_full_pipeline_concept() {
        // Test the full pipeline: add IoC -> check event -> build audit record with match.
        use clawdefender_threat_intel::ioc::types::{
            EventData, Indicator, IndicatorEntry, Severity,
        };
        use clawdefender_threat_intel::ioc::IoCDatabase;
        use clawdefender_core::audit::{IoCMatchRecord, ThreatIntelAuditData};

        // 1. Create IoC database and add an indicator.
        let mut db = IoCDatabase::new();
        db.add_indicator_and_rebuild(IndicatorEntry {
            indicator: Indicator::SuspiciousProcessName("evil-agent".to_string()),
            severity: Severity::High,
            threat_id: "TI-PROC-001".to_string(),
            description: "Known malicious process".to_string(),
            last_updated: chrono::Utc::now(),
            confidence: 0.9,
            false_positive_rate: 0.05,
            permanent: true,
            expires_at: None,
        });

        // 2. Simulate an event that matches.
        let event = EventData {
            event_id: "evt-123".to_string(),
            process_name: Some("evil-agent".to_string()),
            ..Default::default()
        };
        let engine = db.engine();
        let ioc_matches = engine.check_event(&event);
        assert_eq!(ioc_matches.len(), 1);

        // 3. Build the threat intel audit data from matches.
        let ti_data = ThreatIntelAuditData {
            ioc_matches: ioc_matches
                .iter()
                .map(|m| IoCMatchRecord {
                    threat_id: m.indicator.threat_id.clone(),
                    indicator_type: format!("{:?}", m.indicator.indicator),
                    severity: format!("{:?}", m.indicator.severity),
                })
                .collect(),
            blocklist_match: None,
            community_rule: None,
        };

        // 4. Build an audit record with the threat intel data.
        let record = AuditRecord {
            timestamp: chrono::Utc::now(),
            source: "proxy".to_string(),
            event_summary: "tool call: suspicious_tool".to_string(),
            event_details: serde_json::json!({"process": "evil-agent"}),
            rule_matched: None,
            action_taken: "allow".to_string(),
            response_time_ms: None,
            session_id: None,
            direction: None,
            server_name: Some("test-server".to_string()),
            client_name: None,
            jsonrpc_method: None,
            tool_name: Some("suspicious_tool".to_string()),
            arguments: None,
            classification: None,
            policy_rule: None,
            policy_action: None,
            user_decision: None,
            proxy_latency_us: None,
            slm_analysis: None,
            swarm_analysis: None,
            behavioral: None,
            injection_scan: None,
            threat_intel: Some(ti_data),
        };

        // 5. Verify the audit record round-trips correctly and contains IoC data.
        let json = serde_json::to_string(&record).unwrap();
        let parsed: AuditRecord = serde_json::from_str(&json).unwrap();
        let ti = parsed.threat_intel.as_ref().unwrap();
        assert_eq!(ti.ioc_matches.len(), 1);
        assert_eq!(ti.ioc_matches[0].threat_id, "TI-PROC-001");
        assert!(ti.ioc_matches[0].indicator_type.contains("SuspiciousProcessName"));
        assert!(ti.ioc_matches[0].severity.contains("High"));

        // 6. Verify it can be written to audit log and queried back.
        let dir = TempDir::new().unwrap();
        let logger = FileAuditLogger::new(
            dir.path().join("audit.jsonl"),
            clawdefender_core::config::settings::LogRotation::default(),
        )
        .unwrap();
        logger.log(&record).unwrap();

        let filter = clawdefender_core::audit::AuditFilter {
            limit: 100,
            ..Default::default()
        };
        let results = logger.query(&filter).unwrap();
        assert!(!results.is_empty(), "audit log should have at least one record");
        let matching = results
            .iter()
            .find(|r| r.threat_intel.is_some())
            .expect("should have a record with threat_intel data");
        let result_ti = matching.threat_intel.as_ref().unwrap();
        assert_eq!(result_ti.ioc_matches.len(), 1);
        assert_eq!(result_ti.ioc_matches[0].threat_id, "TI-PROC-001");
    }

    #[test]
    fn threat_intel_config_parsing() {
        let toml_str = r#"
[threat_intel]
enabled = true
feed_url = "https://example.com/feed"
update_interval_hours = 12
auto_apply_rules = true
auto_apply_blocklist = true
auto_apply_patterns = false
auto_apply_iocs = true
notify_on_update = true
"#;
        let config: ClawConfig = toml::from_str(toml_str).unwrap();
        assert!(config.threat_intel.enabled);
        assert_eq!(config.threat_intel.feed_url, "https://example.com/feed");
        assert_eq!(config.threat_intel.update_interval_hours, 12);
        assert!(config.threat_intel.auto_apply_rules);
        assert!(config.threat_intel.auto_apply_blocklist);
        assert!(!config.threat_intel.auto_apply_patterns);
        assert!(config.threat_intel.auto_apply_iocs);
        assert!(config.threat_intel.notify_on_update);
    }

    #[test]
    fn threat_intel_blocklist_matcher_creation() {
        use clawdefender_threat_intel::blocklist::BlocklistMatcher;
        use clawdefender_threat_intel::blocklist::types::Blocklist;

        let blocklist = Blocklist {
            version: 1,
            updated_at: "2026-01-01".to_string(),
            entries: Vec::new(),
        };
        let matcher = BlocklistMatcher::new(blocklist);
        let matches = matcher.check_server("some-server", None, None);
        assert!(matches.is_empty(), "empty blocklist should not match anything");
    }
}
