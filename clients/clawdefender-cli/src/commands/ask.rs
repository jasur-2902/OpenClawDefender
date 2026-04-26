//! `rookbot ask` — Conversational security assistant from the terminal.

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Result};
use clap::Args;

use clawdefender_swarm::chat::{ChatManager, ChatMessage};
use clawdefender_swarm::cost::{BudgetConfig, CostTracker, PricingTable};
use clawdefender_swarm::keychain;
use clawdefender_swarm::llm_client::{HttpLlmClient, LlmClient, LlmRequest};

#[derive(Args, Debug)]
pub struct AskArgs {
    /// Your question (one-shot mode).
    pub question: Option<String>,
    /// Interactive chat mode.
    #[arg(long)]
    pub chat: bool,
}

/// Default database path for chat sessions: ~/.local/share/rookbot/ask.db
fn ask_db_path() -> PathBuf {
    let home = std::env::var_os("HOME").expect("HOME not set");
    PathBuf::from(home)
        .join(".local/share/rookbot")
        .join("ask.db")
}

/// Run one-shot question mode.
pub async fn ask_question(question: &str) -> Result<()> {
    let keystore = keychain::default_keystore();
    let has_api_key = keystore.get(&keychain::Provider::Anthropic).is_ok();

    if !has_api_key {
        bail!(
            "Cloud API key required for Ask Rook.\n\
             Configure with: rookbot cloud setup\n\
             Or use --chat for interactive mode with local fallback."
        );
    }

    let client = Arc::new(HttpLlmClient::new(Arc::from(keystore)));

    // Build system context (recent events, alerts, posture)
    let system_context = build_system_context();

    // Create request
    let request = LlmRequest {
        provider: keychain::Provider::Anthropic,
        model: "claude-3-5-sonnet-20241022".to_string(),
        system_prompt: format!(
            "You are Rook, a security assistant for the ClawDefender security platform.\n\
             \n\
             Current System Context:\n{system_context}\n\
             \n\
             Answer the user's security question clearly and concisely. If the question \
             requires investigation or data you don't have, suggest the appropriate rookbot command."
        ),
        user_prompt: question.to_string(),
        max_tokens: 1024,
        temperature: 0.7,
    };

    // Send request
    print!("Thinking...");
    io::stdout().flush()?;

    let response = client.complete(&request).await?;

    // Clear "Thinking..." line
    print!("\r           \r");
    io::stdout().flush()?;

    // Print response
    println!("{}", response.content);
    println!();
    println!("(Tokens: {} in, {} out)", response.input_tokens, response.output_tokens);

    Ok(())
}

/// Run interactive chat mode.
pub async fn run_interactive_chat() -> Result<()> {
    let db_path = ask_db_path();
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let keystore = keychain::default_keystore();
    let has_api_key = keystore.get(&keychain::Provider::Anthropic).is_ok();

    let client: Arc<dyn LlmClient> = if has_api_key {
        Arc::new(HttpLlmClient::new(Arc::from(keystore)))
    } else {
        println!("⚠️  No API key configured. Using pattern-based fallback mode.");
        println!("   Configure cloud access with: rookbot cloud setup");
        println!();
        Arc::new(clawdefender_swarm::llm_client::MockLlmClient::new())
    };

    let cost_tracker = if has_api_key {
        Some(Arc::new(std::sync::Mutex::new(CostTracker::new(
            &db_path,
            PricingTable::default(),
            BudgetConfig::default(),
        )?)))
    } else {
        None
    };

    let chat_mgr = Arc::new(ChatManager::new(&db_path, client, cost_tracker)?);

    // Create a general assistant session
    let session_id = chat_mgr.start_session(
        "ask-rook-session",
        "Ask Rook Interactive Session",
        "Active",
        "You are Rook, a security assistant for ClawDefender.",
    )?;

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║ Ask Rook — Interactive Security Assistant                 ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    println!("Type your security questions. Type 'exit' or 'quit' to end.");
    println!();

    // Build initial system context
    let system_context = build_system_context();

    loop {
        print!("Rook> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        if input.eq_ignore_ascii_case("exit") || input.eq_ignore_ascii_case("quit") {
            println!("Goodbye!");
            break;
        }

        // Send question to chat manager
        match chat_mgr.send_message(&session_id, input).await {
            Ok(response) => {
                println!();
                println!("{}", response);
                println!();
            }
            Err(e) => {
                eprintln!("Error: {e}");
                eprintln!("Please try again.");
                println!();
            }
        }
    }

    Ok(())
}

/// Build system context from current state.
fn build_system_context() -> String {
    // In a real implementation, this would query the daemon for:
    // - Recent events count
    // - Active alerts
    // - Current security posture
    // - Protected servers
    //
    // For now, return placeholder context.

    format!(
        "Recent Activity (Last 24h):\n\
         - Events: 142 total, 3 suspicious\n\
         - Alerts: 1 active (Medium severity)\n\
         - Security Posture: Monitoring\n\
         - Protected Servers: 4\n\
         \n\
         Note: For detailed investigation, use 'rookbot investigate <target>'"
    )
}
