//! `clawdefender chat` — post-analysis chat about flagged events.

use std::path::PathBuf;
use std::sync::Arc;

use clawdefender_swarm::chat::ChatManager;
use clawdefender_swarm::chat_server::ChatServer;
use clawdefender_swarm::cost::{BudgetConfig, CostTracker, PricingTable};
use clawdefender_swarm::keychain;
use clawdefender_swarm::llm_client::HttpLlmClient;

/// Default database path: ~/.local/share/clawdefender/usage.db
fn default_db_path() -> PathBuf {
    let home = std::env::var_os("HOME").expect("HOME not set");
    PathBuf::from(home)
        .join(".local/share/clawdefender")
        .join("usage.db")
}

/// List recent chat sessions.
pub fn list_sessions() -> anyhow::Result<()> {
    let db_path = default_db_path();

    // Use a dummy client since we only need to read from the database.
    let mock = Arc::new(clawdefender_swarm::llm_client::MockLlmClient::new());
    let mgr = ChatManager::new(&db_path, mock, None)?;

    let sessions = mgr.list_sessions();
    if sessions.is_empty() {
        println!("No chat sessions yet.");
        return Ok(());
    }

    println!(
        "{:<40} {:<16} {:<40} Created",
        "Session ID", "Event ID", "Summary"
    );
    println!("{}", "-".repeat(110));
    for (session_id, event_id, summary, created) in &sessions {
        let short_summary = if summary.len() > 38 {
            format!("{}...", &summary[..35])
        } else {
            summary.clone()
        };
        println!(
            "{:<40} {:<16} {:<40} {}",
            session_id, event_id, short_summary, created
        );
    }

    Ok(())
}

/// Start the chat server for a specific event and open the browser.
pub async fn start_chat(event_id: &str) -> anyhow::Result<()> {
    let db_path = default_db_path();
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let keystore = keychain::default_keystore();
    let client = Arc::new(HttpLlmClient::new(Arc::from(keystore)));
    let cost_tracker = CostTracker::new(&db_path, PricingTable::default(), BudgetConfig::default())?;
    let cost_tracker = Some(Arc::new(std::sync::Mutex::new(cost_tracker)));

    let mgr = Arc::new(ChatManager::new(&db_path, client, cost_tracker)?);

    // Create session if none exists for this event
    if mgr.find_session_by_event(event_id)?.is_none() {
        mgr.start_session(
            event_id,
            &format!("Event {}", event_id),
            "Unknown — start the swarm analysis first for full context.",
            "No specialist reports available. Run `clawdefender analyze` first for full context.",
        )?;
        println!("Created new chat session for event: {}", event_id);
    }

    let port = 3200u16;
    let url = format!("http://127.0.0.1:{}/chat/{}", port, event_id);

    println!("Starting chat server at {}", url);
    println!("Press Ctrl+C to stop.\n");

    // Open browser in a background task
    let url_clone = url.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if let Err(e) = open::that(&url_clone) {
            eprintln!("Could not open browser: {e}");
            eprintln!("Open manually: {}", url_clone);
        }
    });

    let server = ChatServer::new(mgr, port);
    server.start().await?;

    Ok(())
}
