//! CLI client for interacting with the ClawAI daemon.

use clap::Parser;

/// ClawAI CLI - interact with the ClawAI daemon.
#[derive(Parser, Debug)]
#[command(name = "claw-cli", version, about)]
struct Args {
    /// Subcommand to execute
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Show daemon status
    Status,
    /// List active policies
    Policies,
    /// View audit log
    Audit,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    match args.command {
        Some(Commands::Status) => {
            // TODO: Phase 1 - query daemon status
            println!("ClawAI daemon status: not yet implemented");
        }
        Some(Commands::Policies) => {
            // TODO: Phase 1 - list policies
            println!("Policy listing: not yet implemented");
        }
        Some(Commands::Audit) => {
            // TODO: Phase 1 - show audit log
            println!("Audit log: not yet implemented");
        }
        None => {
            println!("ClawAI CLI - use --help for available commands");
        }
    }

    Ok(())
}
