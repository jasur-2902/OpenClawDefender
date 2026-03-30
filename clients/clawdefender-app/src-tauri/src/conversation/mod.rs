pub mod analysis;
pub mod intent;
pub mod entities;
pub mod context;
pub mod executor;
pub mod rate_limiter;
pub mod storage;

pub mod synthesizer;
pub mod formatter;
pub mod templates;

#[cfg(test)]
mod adversarial_tests;

// Future modules owned by other agents:
// pub mod actions;
// pub mod preprocessor;
// pub mod router;

use storage::{ConversationStore, StoredMessage};

#[tauri::command]
pub fn save_conversation_message(message_json: String) -> Result<String, String> {
    let msg: StoredMessage =
        serde_json::from_str(&message_json).map_err(|e| format!("Invalid message JSON: {}", e))?;
    let store = ConversationStore::open()?;
    store.save_message(&msg)?;
    Ok("ok".to_string())
}

#[tauri::command]
pub fn load_conversation(conversation_id: String) -> Result<String, String> {
    let store = ConversationStore::open()?;
    let messages = store.load_conversation(&conversation_id)?;
    serde_json::to_string(&messages).map_err(|e| format!("Serialization error: {}", e))
}

#[tauri::command]
pub fn list_conversations(limit: u32) -> Result<String, String> {
    let store = ConversationStore::open()?;
    let summaries = store.list_conversations(limit)?;
    serde_json::to_string(&summaries).map_err(|e| format!("Serialization error: {}", e))
}

#[tauri::command]
pub fn delete_conversation(conversation_id: String) -> Result<String, String> {
    let store = ConversationStore::open()?;
    store.delete_conversation(&conversation_id)?;
    Ok("ok".to_string())
}

#[tauri::command]
pub fn search_conversations(query: String) -> Result<String, String> {
    let store = ConversationStore::open()?;
    let results = store.search_conversations(&query)?;
    serde_json::to_string(&results).map_err(|e| format!("Serialization error: {}", e))
}

#[tauri::command]
pub fn create_new_conversation() -> Result<String, String> {
    let store = ConversationStore::open()?;
    let id = store.create_conversation()?;
    serde_json::to_string(&id).map_err(|e| format!("Serialization error: {}", e))
}

#[tauri::command]
pub fn get_latest_conversation_id() -> Result<String, String> {
    let store = ConversationStore::open()?;
    let id = store.get_latest_conversation()?;
    serde_json::to_string(&id).map_err(|e| format!("Serialization error: {}", e))
}

#[tauri::command]
pub fn update_conversation_summary(conversation_id: String, summary: String) -> Result<String, String> {
    let store = ConversationStore::open()?;
    store.update_conversation_summary(&conversation_id, &summary)?;
    Ok("ok".to_string())
}
