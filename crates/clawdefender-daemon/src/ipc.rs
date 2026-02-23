//! Unix domain socket IPC server for daemon status and control.
//!
//! Accepts JSON-line messages from clients on a Unix socket. Supports
//! `"status"` queries (returns proxy metrics), `"reload"` commands
//! (triggers policy hot-reload), and JSON-encoded `GuardRequest` messages
//! for agent guard management.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use clawdefender_core::behavioral::{DecisionEngine, LearningEngine};
use clawdefender_core::policy::engine::DefaultPolicyEngine;
use clawdefender_core::policy::PolicyEngine;
use clawdefender_guard::connection::{GuardRequest, GuardResponse};
use clawdefender_guard::registry::{GuardMode, GuardRegistry};
use clawdefender_mcp_proxy::ProxyMetrics;
use clawdefender_slm::SlmService;

/// Optional AI subsystem references for enriched status responses.
#[derive(Clone, Default)]
pub struct AiSubsystemContext {
    pub slm_service: Option<Arc<SlmService>>,
    pub behavioral_enabled: bool,
    pub behavioral_profile_count: Option<usize>,
    pub swarm_available: bool,
    /// Live reference to learning engine for real-time profile stats.
    pub learning_engine: Option<Arc<RwLock<LearningEngine>>>,
    /// Live reference to decision engine for auto-block stats.
    pub decision_engine: Option<Arc<RwLock<DecisionEngine>>>,
}

/// Run the IPC server, accepting connections on the given Unix socket path.
pub async fn run_ipc_server(
    socket_path: PathBuf,
    metrics: Arc<ProxyMetrics>,
    policy_engine: Arc<RwLock<DefaultPolicyEngine>>,
    guard_registry: Arc<GuardRegistry>,
) -> Result<()> {
    run_ipc_server_with_ai(
        socket_path,
        metrics,
        policy_engine,
        guard_registry,
        AiSubsystemContext::default(),
    )
    .await
}

/// Run the IPC server with AI subsystem context for enriched status.
pub async fn run_ipc_server_with_ai(
    socket_path: PathBuf,
    metrics: Arc<ProxyMetrics>,
    policy_engine: Arc<RwLock<DefaultPolicyEngine>>,
    guard_registry: Arc<GuardRegistry>,
    ai_ctx: AiSubsystemContext,
) -> Result<()> {
    // Remove stale socket if it exists.
    if socket_path.exists() {
        std::fs::remove_file(&socket_path).context("removing stale IPC socket")?;
    }

    // Ensure parent directory exists.
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).context("creating IPC socket parent directory")?;
    }

    let listener = UnixListener::bind(&socket_path).context("binding IPC socket")?;

    info!(path = %socket_path.display(), "IPC server listening");

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                debug!("IPC client connected");
                let metrics = Arc::clone(&metrics);
                let policy_engine = Arc::clone(&policy_engine);
                let guard_registry = Arc::clone(&guard_registry);
                let ai_ctx = ai_ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_client(stream, metrics, policy_engine, guard_registry, ai_ctx).await
                    {
                        debug!(error = %e, "IPC client disconnected");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "failed to accept IPC connection");
            }
        }
    }
}

async fn handle_client(
    stream: tokio::net::UnixStream,
    metrics: Arc<ProxyMetrics>,
    policy_engine: Arc<RwLock<DefaultPolicyEngine>>,
    guard_registry: Arc<GuardRegistry>,
    ai_ctx: AiSubsystemContext,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Try to parse as JSON GuardRequest first.
        if let Ok(guard_req) = serde_json::from_str::<GuardRequest>(trimmed) {
            let response = handle_guard_request(guard_req, &guard_registry).await;
            let response = serde_json::to_string(&response)?;
            writer.write_all(response.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
        } else if trimmed == "\"status\"" || trimmed == "status" {
            let mut response = serde_json::json!({
                "messages_total": metrics.messages_total.load(Ordering::Relaxed),
                "messages_allowed": metrics.messages_allowed.load(Ordering::Relaxed),
                "messages_blocked": metrics.messages_blocked.load(Ordering::Relaxed),
                "messages_prompted": metrics.messages_prompted.load(Ordering::Relaxed),
                "messages_logged": metrics.messages_logged.load(Ordering::Relaxed),
            });

            // Enrich with AI subsystem status (additive, backwards-compatible).
            if let Some(ref slm) = ai_ctx.slm_service {
                let slm_status = if let Some(stats) = slm.stats() {
                    serde_json::json!({
                        "loaded": true,
                        "model_name": stats.model_name,
                        "using_gpu": stats.using_gpu,
                        "total_inferences": stats.total_inferences,
                    })
                } else {
                    serde_json::json!({
                        "loaded": slm.is_enabled(),
                    })
                };
                response["slm_status"] = slm_status;
            }

            // Query live behavioral engine stats if available.
            let behavioral_status = if let Some(ref learning) = ai_ctx.learning_engine {
                if let Ok(learning) = learning.try_read() {
                    let profiles: Vec<_> = learning.all_profiles().collect();
                    let total = profiles.len();
                    let learning_count = profiles.iter().filter(|p| p.learning_mode).count();
                    let monitoring_count = total - learning_count;

                    let auto_block_stats = ai_ctx.decision_engine.as_ref()
                        .and_then(|de| de.try_read().ok())
                        .map(|de| serde_json::json!({
                            "total_auto_blocks": de.stats.total_auto_blocks,
                            "total_overrides": de.stats.total_overrides,
                            "override_rate": de.stats.override_rate,
                            "auto_block_enabled": de.auto_block_enabled,
                        }));

                    serde_json::json!({
                        "enabled": ai_ctx.behavioral_enabled,
                        "profiles": total,
                        "learning_servers": learning_count,
                        "monitoring_servers": monitoring_count,
                        "auto_block_stats": auto_block_stats,
                    })
                } else {
                    serde_json::json!({
                        "enabled": ai_ctx.behavioral_enabled,
                        "profiles": ai_ctx.behavioral_profile_count.unwrap_or(0),
                    })
                }
            } else {
                serde_json::json!({
                    "enabled": ai_ctx.behavioral_enabled,
                    "profiles": ai_ctx.behavioral_profile_count.unwrap_or(0),
                })
            };
            response["behavioral_status"] = behavioral_status;

            response["swarm_available"] = serde_json::json!(ai_ctx.swarm_available);

            let response = serde_json::to_string(&response)?;
            writer.write_all(response.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
        } else if trimmed == "\"reload\"" || trimmed == "reload" {
            let mut engine = policy_engine.write().await;
            let result = match engine.reload() {
                Ok(()) => {
                    info!("policy reloaded via IPC");
                    serde_json::json!({"ok": true})
                }
                Err(e) => {
                    warn!(error = %e, "policy reload via IPC failed");
                    serde_json::json!({"ok": false, "error": e.to_string()})
                }
            };
            let response = serde_json::to_string(&result)?;
            writer.write_all(response.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
        } else if trimmed == "\"shutdown\"" || trimmed == "shutdown" {
            info!("Shutdown requested via IPC");
            let response = serde_json::json!({"ok": true, "message": "shutting down"});
            let response = serde_json::to_string(&response)?;
            writer.write_all(response.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
            // Send SIGTERM to self to trigger the signal handler in run(),
            // which performs graceful cleanup of PID file, socket, and subsystems.
            #[cfg(unix)]
            unsafe {
                libc::kill(std::process::id() as i32, libc::SIGTERM);
            }
            #[cfg(not(unix))]
            std::process::exit(0);
        } else {
            warn!(line = trimmed, "unknown IPC command");
            let response = serde_json::json!({"error": "unknown command"});
            let response = serde_json::to_string(&response)?;
            writer.write_all(response.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
        }
    }

    Ok(())
}

/// Handle a GuardRequest message and return a GuardResponse.
async fn handle_guard_request(request: GuardRequest, registry: &GuardRegistry) -> GuardResponse {
    match request {
        GuardRequest::GuardRegister {
            agent_name,
            pid,
            permissions,
            policy_toml: _,
        } => {
            // Convert types::PermissionSet to registry::PermissionSet
            let shell_policy_str = match &permissions.shell_execute {
                clawdefender_guard::types::ShellPolicy::Deny => "deny".to_string(),
                clawdefender_guard::types::ShellPolicy::AllowList(_) => "allowlist".to_string(),
                clawdefender_guard::types::ShellPolicy::AllowWithApproval => "approval".to_string(),
            };
            let reg_perms = clawdefender_guard::registry::PermissionSet {
                file_read: permissions.file_read,
                file_write: permissions.file_write,
                file_delete: permissions.file_delete,
                shell_policy: shell_policy_str,
                network_allowlist: permissions.network.allowed_hosts,
                tools: permissions.tools,
                max_file_size: permissions.max_file_size,
                max_files_per_minute: permissions.max_files_per_minute,
                max_network_requests_per_minute: permissions.max_network_requests_per_minute,
            };

            let (guard_id, rule_count) = registry
                .register(agent_name.clone(), pid, reg_perms, GuardMode::Enforce)
                .await;

            info!(
                guard_id = %guard_id,
                agent = %agent_name,
                pid = pid,
                rules = rule_count,
                "guard registered via IPC"
            );

            GuardResponse::GuardRegistered { guard_id }
        }

        GuardRequest::GuardDeregister { agent_name, pid } => {
            // Find the guard by agent_name and pid, then deregister.
            let guards = registry.list().await;
            let mut deregistered = false;
            for guard in &guards {
                if guard.get("agent_name").and_then(|v| v.as_str()) == Some(&agent_name)
                    && guard.get("pid").and_then(|v| v.as_u64()) == Some(pid as u64)
                {
                    if let Some(id) = guard.get("guard_id").and_then(|v| v.as_str()) {
                        registry.deregister(id).await;
                        info!(agent = %agent_name, pid = pid, "guard deregistered via IPC");
                        deregistered = true;
                    }
                }
            }
            if deregistered {
                GuardResponse::GuardDeregistered
            } else {
                GuardResponse::Error {
                    message: format!(
                        "guard not found for agent '{}' with pid {}",
                        agent_name, pid
                    ),
                }
            }
        }

        GuardRequest::GuardStatsQuery { agent_name } => {
            let guards = registry.list().await;
            for guard in &guards {
                if guard.get("agent_name").and_then(|v| v.as_str()) == Some(&agent_name) {
                    if let Some(id) = guard.get("guard_id").and_then(|v| v.as_str()) {
                        if let Some(stats_val) = registry.get_stats(id).await {
                            let stats = clawdefender_guard::types::GuardStats {
                                activated_at: None,
                                operations_allowed: stats_val
                                    .get("checks_allowed")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0),
                                operations_blocked: stats_val
                                    .get("checks_blocked")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0),
                                blocked_details: vec![],
                                anomaly_alerts: 0,
                                status: clawdefender_guard::types::GuardStatus::Active,
                                monitored_operations: vec![],
                            };
                            return GuardResponse::GuardStatsResponse { stats };
                        }
                    }
                }
            }
            GuardResponse::Error {
                message: format!("guard not found for agent '{}'", agent_name),
            }
        }

        GuardRequest::GuardHealthCheck => {
            let _guards = registry.list().await;
            GuardResponse::GuardHealthResponse {
                status: clawdefender_guard::types::GuardStatus::Active,
            }
        }
    }
}
