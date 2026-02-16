//! ClawAI daemon binary entry point.

use clap::Parser;

/// ClawAI daemon - firewall for AI agents.
#[derive(Parser, Debug)]
#[command(name = "claw-daemon", version, about)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "clawai.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!(config = %args.config, "claw-daemon starting");
    // TODO: Phase 1 - initialize and run daemon
    Ok(())
}
