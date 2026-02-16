mod ai_analyzer;
mod tui;

use std::fs;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use aya::maps::{Array, HashMap, RingBuf};
use aya::programs::{KProbe, TracePoint};
use aya::Ebpf;
use clap::{Parser, Subcommand};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use tokio::signal;
use tokio::sync::Mutex;

use ai_analyzer::{AiAnalyzer, AiVerdict};
use claw_wall_common::{
    BlocklistKey, BlocklistValue, FirewallEvent, GlobalConfig, EVENT_DNS, EVENT_NETWORK,
    EVENT_PROCESS, EVENT_WOULD_BLOCK_NETWORK, EVENT_WOULD_BLOCK_PROCESS, fnv1a_hash,
};
use tui::{AiVerdictRecord, EventRecord, EventType, SharedState, Verdict};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "claw-wall", about = "OpenClawDefender eBPF firewall daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Configure the daemon (interactive API key prompt)
    #[arg(long)]
    configure: bool,

    /// Generate and install a systemd service unit file
    #[arg(long)]
    install_service: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Configure the daemon (interactive API key prompt)
    Configure,
    /// Start the daemon (default)
    Run,
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const CONFIG_DIR: &str = "/etc/claw-wall";
const CONFIG_PATH: &str = "/etc/claw-wall/config.toml";
const EBPF_OBJ_PATH: &str = "/etc/claw-wall/claw-wall-ebpf.o";
const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/claw-wall.service";

#[derive(Debug, Serialize, Deserialize, Default)]
struct Config {
    #[serde(default)]
    audit_mode: bool,
    #[serde(default)]
    api: ApiConfig,
    #[serde(default)]
    blocklist: BlocklistConfig,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct ApiConfig {
    #[serde(default)]
    key: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct BlocklistConfig {
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    ips: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a null-padded byte array into a String, trimming at the first null.
fn bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Convert a raw u32 IP (network byte order) to a displayable Ipv4Addr.
fn u32_to_ipv4(ip: u32) -> Ipv4Addr {
    Ipv4Addr::from(ip.to_be())
}

/// Hash a blocklist entry into a BlocklistKey using FNV-1a.
fn make_blocklist_key(value: &str) -> BlocklistKey {
    BlocklistKey::from_hash(fnv1a_hash(value.as_bytes()))
}

/// Resolve a process path to an absolute path using CWD information.
///
/// If the path is already absolute (starts with '/'), it is returned as-is
/// after normalizing any `.` and `..` segments. If the path is relative,
/// it is joined with the CWD to produce an absolute path.
///
/// CWD resolution order:
///   1. Use the cwd field from the eBPF event (if non-empty)
///   2. Fall back to reading /proc/<pid>/cwd symlink
///   3. If both fail, return the original path unchanged
fn resolve_process_path(path: &str, cwd: &str, pid: u32) -> String {
    if path.is_empty() {
        return path.to_string();
    }

    // Already absolute - just normalize it
    if path.starts_with('/') {
        return normalize_path(Path::new(path));
    }

    // Relative path - resolve against CWD
    let resolved_cwd = if !cwd.is_empty() {
        Some(PathBuf::from(cwd))
    } else {
        // Fallback: read /proc/<pid>/cwd
        fs::read_link(format!("/proc/{}/cwd", pid)).ok()
    };

    match resolved_cwd {
        Some(cwd_path) => normalize_path(&cwd_path.join(path)),
        None => path.to_string(),
    }
}

/// Normalize a path by resolving `.` and `..` components without touching
/// the filesystem (no symlink resolution). Returns a clean absolute path.
fn normalize_path(path: &Path) -> String {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {} // skip "."
            Component::ParentDir => {
                // Pop the last component for "..", but never pop past root
                if !components.is_empty() {
                    components.pop();
                }
            }
            other => components.push(other),
        }
    }
    let result: PathBuf = components.iter().collect();
    result.to_string_lossy().into_owned()
}

/// Read and parse the config file, returning defaults if it doesn't exist.
fn load_config() -> Result<Config> {
    let path = Path::new(CONFIG_PATH);
    if !path.exists() {
        return Ok(Config::default());
    }
    let content = fs::read_to_string(path).context("Failed to read config file")?;
    let config: Config = toml::from_str(&content).context("Failed to parse config file")?;
    Ok(config)
}

// ---------------------------------------------------------------------------
// Subcommand: configure
// ---------------------------------------------------------------------------

fn run_configure() -> Result<()> {
    print!("Enter your Anthropic/OpenAI API Key: ");
    io::stdout().flush()?;

    let mut api_key = String::new();
    io::stdin()
        .read_line(&mut api_key)
        .context("Failed to read API key from stdin")?;
    let api_key = api_key.trim().to_string();

    if api_key.is_empty() {
        anyhow::bail!("API key cannot be empty");
    }

    // Load existing config to preserve blocklist entries
    let mut config = load_config().unwrap_or_default();
    config.api.key = api_key;

    let toml_str = toml::to_string_pretty(&config).context("Failed to serialize config")?;

    fs::create_dir_all(CONFIG_DIR).context("Failed to create config directory")?;
    fs::write(CONFIG_PATH, toml_str).context("Failed to write config file")?;
    fs::set_permissions(CONFIG_PATH, fs::Permissions::from_mode(0o600))
        .context("Failed to set config file permissions")?;

    info!("Configuration saved to {CONFIG_PATH} (mode 600)");
    println!("Configuration saved to {CONFIG_PATH}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand: install-service
// ---------------------------------------------------------------------------

fn run_install_service() -> Result<()> {
    let unit = "\
[Unit]
Description=OpenClawDefender eBPF Firewall Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/claw-wall run
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
";

    fs::write(SYSTEMD_UNIT_PATH, unit)
        .context("Failed to write systemd unit file (are you root?)")?;

    println!("Systemd unit installed at {SYSTEMD_UNIT_PATH}");
    println!("Run: systemctl daemon-reload && systemctl enable --now claw-wall");
    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand: run (main daemon loop)
// ---------------------------------------------------------------------------

async fn run_daemon() -> Result<()> {
    let config = load_config().context("Failed to load configuration")?;

    if config.api.key.is_empty() {
        warn!("No API key configured. Run `claw-wall configure` or `claw-wall --configure` first.");
    }

    // --- Load eBPF bytecode ---
    info!("Loading eBPF bytecode from {EBPF_OBJ_PATH}");
    let mut ebpf =
        Ebpf::load_file(EBPF_OBJ_PATH).context("Failed to load eBPF object file")?;

    // Optional: initialise aya-log forwarding from eBPF programs
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("Failed to initialise eBPF logger (non-fatal): {e}");
    }

    // --- Write global configuration to eBPF CONFIG map ---
    let mut config_map: Array<_, GlobalConfig> = Array::try_from(
        ebpf.map_mut("CONFIG")
            .context("CONFIG map not found in eBPF object")?,
    )
    .context("Failed to open CONFIG as Array")?;

    let global_cfg = GlobalConfig {
        audit_mode: if config.audit_mode { 1 } else { 0 },
    };
    config_map
        .set(0, global_cfg, 0)
        .context("Failed to write audit_mode to CONFIG map")?;

    if config.audit_mode {
        warn!("AUDIT MODE ENABLED — blocks will be logged but NOT enforced (dry-run)");
    } else {
        info!("Enforce mode active — blocks will be enforced");
    }

    // --- Attach tracepoint: sys_enter_execve ---
    let execve_prog: &mut TracePoint = ebpf
        .program_mut("claw_wall_execve")
        .context("eBPF program 'claw_wall_execve' not found")?
        .try_into()
        .context("Program is not a TracePoint")?;
    execve_prog.load().context("Failed to load execve tracepoint")?;
    execve_prog
        .attach("syscalls", "sys_enter_execve")
        .context("Failed to attach execve tracepoint")?;
    info!("Attached tracepoint: syscalls/sys_enter_execve");

    // --- Attach kprobe: tcp_v4_connect ---
    let connect_prog: &mut KProbe = ebpf
        .program_mut("claw_wall_connect")
        .context("eBPF program 'claw_wall_connect' not found")?
        .try_into()
        .context("Program is not a KProbe")?;
    connect_prog.load().context("Failed to load connect kprobe")?;
    connect_prog
        .attach("tcp_v4_connect", 0)
        .context("Failed to attach tcp_v4_connect kprobe")?;
    info!("Attached kprobe: tcp_v4_connect");

    // --- Attach kprobe: udp_sendmsg (DNS interception) ---
    let dns_prog: &mut KProbe = ebpf
        .program_mut("claw_wall_dns")
        .context("eBPF program 'claw_wall_dns' not found")?
        .try_into()
        .context("Program is not a KProbe")?;
    dns_prog.load().context("Failed to load DNS kprobe")?;
    dns_prog
        .attach("udp_sendmsg", 0)
        .context("Failed to attach udp_sendmsg kprobe")?;
    info!("Attached kprobe: udp_sendmsg (DNS)");

    // --- Populate blocklist HashMap ---
    let mut blocklist: HashMap<_, BlocklistKey, BlocklistValue> = HashMap::try_from(
        ebpf.map_mut("BLOCKLIST")
            .context("BLOCKLIST map not found in eBPF object")?,
    )
    .context("Failed to open BLOCKLIST as HashMap")?;

    let blocked_val = BlocklistValue { blocked: 1, _pad: 0 };

    for path in &config.blocklist.paths {
        let key = make_blocklist_key(path);
        blocklist
            .insert(&key, &blocked_val, 0)
            .context("Failed to insert path into BLOCKLIST")?;
        info!("Blocklisted path: {path}");
    }

    for ip in &config.blocklist.ips {
        let key = make_blocklist_key(ip);
        blocklist
            .insert(&key, &blocked_val, 0)
            .context("Failed to insert IP into BLOCKLIST")?;
        info!("Blocklisted IP: {ip}");
    }

    for domain in &config.blocklist.domains {
        let key = make_blocklist_key(domain);
        blocklist
            .insert(&key, &blocked_val, 0)
            .context("Failed to insert domain into BLOCKLIST")?;
        info!("Blocklisted domain: {domain}");
    }

    // Store domain blocklist for runtime DNS checking
    let blocked_domains = Arc::new(config.blocklist.domains.clone());

    // --- Open the RingBuf for events ---
    let ring_buf = RingBuf::try_from(
        ebpf.map_mut("EVENTS")
            .context("EVENTS ring buffer map not found in eBPF object")?,
    )
    .context("Failed to open EVENTS as RingBuf")?;

    // --- Create AI analyzer ---
    let ai_analyzer = Arc::new(AiAnalyzer::new(config.api.key.clone()));

    // Wrap the blocklist in Arc<Mutex<>> so the event loop can insert entries
    let blocklist = Arc::new(Mutex::new(blocklist));

    // --- Create shared TUI state ---
    let tui_state = tui::new_shared_state();

    // --- Create shutdown channel for TUI ---
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // --- Spawn TUI render loop ---
    let tui_state_clone = tui_state.clone();
    let tui_handle = tokio::spawn(async move {
        tui::run_tui(tui_state_clone, shutdown_rx).await;
    });

    info!("Daemon started — listening for eBPF events");
    let result = event_loop(ring_buf, blocklist, ai_analyzer, blocked_domains, tui_state).await;

    // Signal TUI to shut down and wait for it
    let _ = shutdown_tx.send(true);
    let _ = tui_handle.await;

    result
}

// ---------------------------------------------------------------------------
// Telemetry Router
// ---------------------------------------------------------------------------

/// Known-safe system paths that should be allowed without AI analysis.
const SAFE_PATH_PREFIXES: &[&str] = &[
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/lib/",
    "/lib/",
];

/// Check if a process event is known-safe (PID 1 or from a system path).
fn is_known_safe_process(pid: u32, path: &str) -> bool {
    if pid == 1 {
        return true;
    }
    SAFE_PATH_PREFIXES.iter().any(|prefix| path.starts_with(prefix))
}

/// Check if a network event is known-safe (PID 1 or loopback).
fn is_known_safe_network(pid: u32, dst_ip: u32) -> bool {
    if pid == 1 {
        return true;
    }
    // Loopback: 127.0.0.0/8 — first byte is 127 in network byte order
    let first_byte = (dst_ip & 0xFF) as u8;
    first_byte == 127
}

/// Main event processing loop. Reads FirewallEvent structs from the ring
/// buffer, filters known-safe events, delegates suspicious ones to AI,
/// updates the blocklist map on Block verdicts, and pushes records to TUI.
async fn event_loop(
    mut ring_buf: RingBuf<&mut aya::maps::MapData>,
    blocklist: Arc<Mutex<HashMap<&mut aya::maps::MapData, BlocklistKey, BlocklistValue>>>,
    ai_analyzer: Arc<AiAnalyzer>,
    blocked_domains: Arc<Vec<String>>,
    tui_state: SharedState,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received shutdown signal, exiting");
                return Ok(());
            }
            _ = tokio::task::yield_now() => {
                while let Some(item) = ring_buf.next() {
                    let data = item.as_ref();
                    if data.len() < std::mem::size_of::<FirewallEvent>() {
                        warn!(
                            "Received undersized event ({} bytes, expected {})",
                            data.len(),
                            std::mem::size_of::<FirewallEvent>()
                        );
                        continue;
                    }

                    // Safety: FirewallEvent is #[repr(C)], Copy, and we verified
                    // the buffer is large enough.
                    let event: FirewallEvent =
                        unsafe { std::ptr::read_unaligned(data.as_ptr() as *const FirewallEvent) };

                    route_event(
                        event,
                        Arc::clone(&blocklist),
                        Arc::clone(&ai_analyzer),
                        Arc::clone(&blocked_domains),
                        tui_state.clone(),
                    );
                }

                // Small sleep to avoid busy-spinning when no events are available
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Route a single event: log it, push to TUI, check if known-safe, and if
/// not spawn an async AI analysis task that may update the blocklist.
fn route_event(
    event: FirewallEvent,
    blocklist: Arc<Mutex<HashMap<&mut aya::maps::MapData, BlocklistKey, BlocklistValue>>>,
    ai_analyzer: Arc<AiAnalyzer>,
    blocked_domains: Arc<Vec<String>>,
    tui_state: SharedState,
) {
    match event.event_type {
        EVENT_PROCESS => {
            let proc = unsafe { &event.payload.process };
            let comm = bytes_to_string(&proc.comm);
            let raw_path = bytes_to_string(&proc.path);
            let cwd = bytes_to_string(&proc.cwd);
            let path = resolve_process_path(&raw_path, &cwd, proc.pid);
            let pid = proc.pid;
            let uid = proc.uid;

            let description = if path != raw_path {
                format!("comm=\"{}\" path=\"{}\" resolved=\"{}\"", comm, raw_path, path)
            } else {
                format!("comm=\"{}\" path=\"{}\"", comm, path)
            };

            info!("[PROCESS] pid={} uid={} {}", pid, uid, description);

            // Push event to TUI
            let record = EventRecord {
                timestamp: Instant::now(),
                event_type: EventType::Process,
                pid,
                description: description.clone(),
                blocked: false,
            };
            let tui_for_push = tui_state.clone();
            tokio::spawn(async move {
                let mut state = tui_for_push.write().await;
                state.push_event(record);
            });

            if is_known_safe_process(pid, &path) {
                return;
            }

            let ai_description = format!(
                "Process execution: pid={} uid={} comm=\"{}\" path=\"{}\"",
                pid, uid, comm, path
            );
            let blocklist_key_value = path;

            tokio::spawn(async move {
                let verdict = ai_analyzer.analyze(&ai_description).await;
                if verdict == AiVerdict::Block {
                    let key = make_blocklist_key(&blocklist_key_value);
                    let val = BlocklistValue { blocked: 1, _pad: 0 };
                    let mut map = blocklist.lock().await;
                    if let Err(e) = map.insert(&key, &val, 0) {
                        error!("Failed to insert blocked path into BLOCKLIST: {e}");
                    } else {
                        info!("AI blocked path inserted into BLOCKLIST: {blocklist_key_value}");
                    }
                }
                // Push AI verdict to TUI
                let mut state = tui_state.write().await;
                state.push_ai_verdict(AiVerdictRecord {
                    timestamp: Instant::now(),
                    target: blocklist_key_value,
                    verdict: if verdict == AiVerdict::Block {
                        Verdict::Block
                    } else {
                        Verdict::Allow
                    },
                });
            });
        }
        EVENT_NETWORK => {
            let net = unsafe { &event.payload.network };
            let src = u32_to_ipv4(net.src_ip);
            let dst = u32_to_ipv4(net.dst_ip);
            let port = u16::from_be(net.dst_port);
            let pid = net.pid;
            let dst_ip_raw = net.dst_ip;

            let description = format!("{} -> {}:{}", src, dst, port);

            info!("[NETWORK] pid={} {}", pid, description);

            // Push event to TUI
            let record = EventRecord {
                timestamp: Instant::now(),
                event_type: EventType::Network,
                pid,
                description: description.clone(),
                blocked: false,
            };
            let tui_for_push = tui_state.clone();
            tokio::spawn(async move {
                let mut state = tui_for_push.write().await;
                state.push_event(record);
            });

            if is_known_safe_network(pid, dst_ip_raw) {
                return;
            }

            let dst_str = dst.to_string();
            let ai_description = format!(
                "Network connection: pid={} src={} dst={}:{}",
                pid, src, dst, port
            );

            tokio::spawn(async move {
                let verdict = ai_analyzer.analyze(&ai_description).await;
                if verdict == AiVerdict::Block {
                    let key = make_blocklist_key(&dst_str);
                    let val = BlocklistValue { blocked: 1, _pad: 0 };
                    let mut map = blocklist.lock().await;
                    if let Err(e) = map.insert(&key, &val, 0) {
                        error!("Failed to insert blocked IP into BLOCKLIST: {e}");
                    } else {
                        info!("AI blocked IP inserted into BLOCKLIST: {dst_str}");
                    }
                }
                // Push AI verdict to TUI
                let mut state = tui_state.write().await;
                state.push_ai_verdict(AiVerdictRecord {
                    timestamp: Instant::now(),
                    target: dst_str,
                    verdict: if verdict == AiVerdict::Block {
                        Verdict::Block
                    } else {
                        Verdict::Allow
                    },
                });
            });
        }
        EVENT_DNS => {
            let dns = unsafe { &event.payload.dns };
            let domain = bytes_to_string(&dns.domain);
            let dst = u32_to_ipv4(dns.dst_ip);
            let pid = dns.pid;

            let description = format!("query \"{}\" via {}", domain, dst);

            // Check domain against blocklist
            let is_blocked = blocked_domains.iter().any(|blocked| {
                domain == *blocked || domain.ends_with(&format!(".{blocked}"))
            });

            if is_blocked {
                warn!("[DNS] BLOCKED pid={} {}", pid, description);
            } else {
                info!("[DNS] pid={} {}", pid, description);
            }

            // Push event to TUI
            let record = EventRecord {
                timestamp: Instant::now(),
                event_type: EventType::Dns,
                pid,
                description,
                blocked: is_blocked,
            };
            tokio::spawn(async move {
                let mut state = tui_state.write().await;
                state.push_event(record);
            });
        }
        EVENT_WOULD_BLOCK_PROCESS => {
            let proc = unsafe { &event.payload.process };
            let comm = bytes_to_string(&proc.comm);
            let raw_path = bytes_to_string(&proc.path);
            let cwd = bytes_to_string(&proc.cwd);
            let path = resolve_process_path(&raw_path, &cwd, proc.pid);
            let pid = proc.pid;
            let uid = proc.uid;

            warn!(
                "[AUDIT] WOULD_BLOCK process pid={} uid={} comm=\"{}\" path=\"{}\"",
                pid, uid, comm, path
            );

            // Push to TUI as blocked (audit)
            let record = EventRecord {
                timestamp: Instant::now(),
                event_type: EventType::Process,
                pid,
                description: format!("[AUDIT] comm=\"{}\" path=\"{}\"", comm, path),
                blocked: true,
            };
            let tui_for_push = tui_state.clone();
            tokio::spawn(async move {
                let mut state = tui_for_push.write().await;
                state.push_event(record);
            });
            // No AI analysis — this was a static blocklist hit
        }
        EVENT_WOULD_BLOCK_NETWORK => {
            let net = unsafe { &event.payload.network };
            let src = u32_to_ipv4(net.src_ip);
            let dst = u32_to_ipv4(net.dst_ip);
            let port = u16::from_be(net.dst_port);
            let pid = net.pid;

            warn!(
                "[AUDIT] WOULD_BLOCK network pid={} {} -> {}:{}",
                pid, src, dst, port
            );

            // Push to TUI as blocked (audit)
            let record = EventRecord {
                timestamp: Instant::now(),
                event_type: EventType::Network,
                pid,
                description: format!("[AUDIT] {} -> {}:{}", src, dst, port),
                blocked: true,
            };
            let tui_for_push = tui_state.clone();
            tokio::spawn(async move {
                let mut state = tui_for_push.write().await;
                state.push_event(record);
            });
            // No AI analysis — this was a static blocklist hit
        }
        other => {
            warn!("Unknown event_type: {other}");
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    // --configure flag takes precedence
    if cli.configure {
        return run_configure();
    }

    // --install-service flag
    if cli.install_service {
        return run_install_service();
    }

    // Subcommand dispatch
    match cli.command {
        Some(Command::Configure) => run_configure(),
        Some(Command::Run) | None => run_daemon().await,
    }
}
