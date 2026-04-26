//! `rookbot knowledge` — Knowledge base management.

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Subcommand;
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Debug)]
pub enum KnowledgeAction {
    /// List knowledge entries.
    List {
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        r#type: Option<String>,
    },
    /// Show a specific knowledge entry.
    Show { entry_id: String },
    /// Add a knowledge entry.
    Add {
        #[arg(long)]
        r#type: String,
        #[arg(long)]
        description: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// Delete a knowledge entry.
    Delete { entry_id: String },
    /// Export knowledge base.
    Export {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Import knowledge base.
    Import { file: PathBuf },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KnowledgeEntry {
    id: String,
    r#type: String,
    description: String,
    server: Option<String>,
    created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KnowledgeBase {
    entries: Vec<KnowledgeEntry>,
}

impl Default for KnowledgeBase {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

/// Run the knowledge subcommand.
pub fn run(action: &KnowledgeAction) -> Result<()> {
    match action {
        KnowledgeAction::List { server, r#type } => list(server.as_deref(), r#type.as_deref()),
        KnowledgeAction::Show { entry_id } => show(entry_id),
        KnowledgeAction::Add {
            r#type,
            description,
            server,
        } => add(r#type, description, server.as_deref()),
        KnowledgeAction::Delete { entry_id } => delete(entry_id),
        KnowledgeAction::Export { output } => export(output.as_deref()),
        KnowledgeAction::Import { file } => import(file),
    }
}

/// List knowledge entries.
fn list(server: Option<&str>, entry_type: Option<&str>) -> Result<()> {
    let kb = load_knowledge_base()?;

    println!("Knowledge Base");
    println!("==============");
    println!();

    if kb.entries.is_empty() {
        println!("  No knowledge entries.");
        return Ok(());
    }

    let mut entries: Vec<_> = kb
        .entries
        .iter()
        .filter(|e| {
            if let Some(srv) = server {
                if e.server.as_deref() != Some(srv) {
                    return false;
                }
            }
            if let Some(typ) = entry_type {
                if e.r#type != typ {
                    return false;
                }
            }
            true
        })
        .collect();

    if entries.is_empty() {
        println!("  No matching entries.");
        return Ok(());
    }

    entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    println!("  {:<16} {:<12} {:<20} DESCRIPTION", "ID", "TYPE", "SERVER");
    println!("  {}", "-".repeat(80));

    for entry in &entries {
        let srv = entry.server.as_deref().unwrap_or("-");
        let desc = if entry.description.len() > 30 {
            format!("{}...", &entry.description[..27])
        } else {
            entry.description.clone()
        };
        println!(
            "  {:<16} {:<12} {:<20} {}",
            entry.id, entry.r#type, srv, desc
        );
    }

    println!();
    println!("  {} entrie(s)", entries.len());

    Ok(())
}

/// Show a specific knowledge entry.
fn show(entry_id: &str) -> Result<()> {
    let kb = load_knowledge_base()?;
    let entry = kb
        .entries
        .iter()
        .find(|e| e.id == entry_id)
        .ok_or_else(|| anyhow::anyhow!("Knowledge entry not found: {}", entry_id))?;

    println!("Knowledge Entry: {}", entry.id);
    println!("================");
    println!();
    println!("  Type:        {}", entry.r#type);
    println!("  Server:      {}", entry.server.as_deref().unwrap_or("-"));
    println!("  Created:     {}", entry.created_at);
    println!();
    println!("  Description:");
    println!("  {}", entry.description);

    Ok(())
}

/// Add a knowledge entry.
fn add(entry_type: &str, description: &str, server: Option<&str>) -> Result<()> {
    let mut kb = load_knowledge_base()?;

    let id = format!("kb-{}", uuid::Uuid::new_v4().to_string()[..8].to_string());
    let entry = KnowledgeEntry {
        id: id.clone(),
        r#type: entry_type.to_string(),
        description: description.to_string(),
        server: server.map(|s| s.to_string()),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    kb.entries.push(entry);
    save_knowledge_base(&kb)?;

    println!("Added knowledge entry: {}", id);
    Ok(())
}

/// Delete a knowledge entry.
fn delete(entry_id: &str) -> Result<()> {
    let mut kb = load_knowledge_base()?;
    let before = kb.entries.len();
    kb.entries.retain(|e| e.id != entry_id);
    if kb.entries.len() == before {
        bail!("Knowledge entry not found: {}", entry_id);
    }
    save_knowledge_base(&kb)?;
    println!("Deleted knowledge entry: {}", entry_id);
    Ok(())
}

/// Export knowledge base.
fn export(output: Option<&std::path::Path>) -> Result<()> {
    let kb = load_knowledge_base()?;
    let json = serde_json::to_string_pretty(&kb)?;

    if let Some(path) = output {
        std::fs::write(path, &json)?;
        println!("Exported knowledge base to {}", path.display());
    } else {
        println!("{}", json);
    }

    Ok(())
}

/// Import knowledge base.
fn import(file: &PathBuf) -> Result<()> {
    let content = std::fs::read_to_string(file)?;
    let imported: KnowledgeBase = serde_json::from_str(&content)?;

    let mut kb = load_knowledge_base()?;
    let before = kb.entries.len();

    // Merge entries (avoid duplicates by ID).
    for entry in imported.entries {
        if !kb.entries.iter().any(|e| e.id == entry.id) {
            kb.entries.push(entry);
        }
    }

    save_knowledge_base(&kb)?;

    let added = kb.entries.len() - before;
    println!("Imported {} new knowledge entrie(s).", added);

    Ok(())
}

/// Load knowledge base from ~/.local/share/rookbot/knowledge.json.
fn load_knowledge_base() -> Result<KnowledgeBase> {
    let path = knowledge_base_path()?;
    if !path.exists() {
        return Ok(KnowledgeBase::default());
    }
    let content = std::fs::read_to_string(&path)?;
    let kb: KnowledgeBase = serde_json::from_str(&content)?;
    Ok(kb)
}

/// Save knowledge base to ~/.local/share/rookbot/knowledge.json.
fn save_knowledge_base(kb: &KnowledgeBase) -> Result<()> {
    let path = knowledge_base_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(kb)?;
    std::fs::write(&path, content)?;
    Ok(())
}

/// Return the path to knowledge.json.
fn knowledge_base_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")?;
    Ok(PathBuf::from(home).join(".local/share/rookbot/knowledge.json"))
}
