use std::fs;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result};
use aya::maps::{HashMap, RingBuf};
use aya::programs::{KProbe, TracePoint};
use aya::Ebpf;
use clap::{Parser, Subcommand};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use tokio::signal;

use claw_wall_common::{
    BlocklistKey, BlocklistValue, FirewallEvent, EVENT_NETWORK, EVENT_PROCESS,
};

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

/// Hash a blocklist entry into a 32-byte BlocklistKey.
/// Uses a simple djb2-style spread across the key buffer so that lookups
/// in the eBPF HashMap are deterministic without pulling in a crypto crate.
fn make_blocklist_key(value: &str) -> BlocklistKey {
    let mut key = BlocklistKey { key: [0u8; 32] };
    let bytes = value.as_bytes();
    let len = bytes.len().min(32);
    key.key[..len].copy_from_slice(&bytes[..len]);
    key
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

    // --- Populate blocklist HashMap ---
    let mut blocklist: HashMap<_, BlocklistKey, BlocklistValue> = HashMap::try_from(
        ebpf.map_mut("BLOCKLIST")
            .context("BLOCKLIST map not found in eBPF object")?,
    )
    .context("Failed to open BLOCKLIST as HashMap")?;

    let blocked_val = BlocklistValue { blocked: 1 };

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

    // --- Open the RingBuf for events ---
    let ring_buf = RingBuf::try_from(
        ebpf.map_mut("EVENTS")
            .context("EVENTS ring buffer map not found in eBPF object")?,
    )
    .context("Failed to open EVENTS as RingBuf")?;

    info!("Daemon started — listening for eBPF events");
    event_loop(ring_buf).await
}

/// Main event processing loop. Reads FirewallEvent structs from the ring
/// buffer and logs them until a SIGTERM/SIGINT is received.
async fn event_loop(mut ring_buf: RingBuf<&mut aya::maps::MapData>) -> Result<()> {
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

                    process_event(&event);
                }

                // Small sleep to avoid busy-spinning when no events are available
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Decode and log a single FirewallEvent based on its event_type tag.
fn process_event(event: &FirewallEvent) {
    match event.event_type {
        EVENT_PROCESS => {
            // Safety: event_type == EVENT_PROCESS guarantees the process union
            // variant was written by the eBPF program.
            let proc = unsafe { &event.payload.process };
            let comm = bytes_to_string(&proc.comm);
            let path = bytes_to_string(&proc.path);
            info!(
                "[PROCESS] pid={} uid={} comm=\"{}\" path=\"{}\"",
                proc.pid, proc.uid, comm, path
            );
        }
        EVENT_NETWORK => {
            // Safety: event_type == EVENT_NETWORK guarantees the network union
            // variant was written by the eBPF program.
            let net = unsafe { &event.payload.network };
            let src = u32_to_ipv4(net.src_ip);
            let dst = u32_to_ipv4(net.dst_ip);
            let port = u16::from_be(net.dst_port);
            info!(
                "[NETWORK] pid={} {}:{} -> {}:{}",
                net.pid, src, 0, dst, port
            );
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
