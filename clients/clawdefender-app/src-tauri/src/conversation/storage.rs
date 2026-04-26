use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: String,
    pub conversation_id: String,
    pub role: String,
    pub content_text: String,
    pub content_rich_json: Option<String>,
    pub actions_json: Option<String>,
    pub intent_id: Option<String>,
    pub entities_json: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationSummary {
    pub id: String,
    pub created_at: String,
    pub updated_at: String,
    pub summary: Option<String>,
    pub message_count: u32,
    pub last_message_preview: Option<String>,
}

pub struct ConversationStore {
    conn: Connection,
}

impl ConversationStore {
    /// Opens or creates the database at the default path:
    /// `~/.local/share/rookbot/conversations.db`
    pub fn open() -> Result<Self, String> {
        let path = Self::default_db_path()?;
        Self::open_at(&path)
    }

    /// Opens or creates the database at the given path (useful for testing).
    pub fn open_at(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create database directory: {}", e))?;
        }

        let conn = Connection::open(path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(|e| format!("Failed to set pragmas: {}", e))?;

        let store = Self { conn };
        store.initialize_schema()?;
        Ok(store)
    }

    fn default_db_path() -> Result<PathBuf, String> {
        let home = std::env::var("HOME")
            .map_err(|_| "HOME environment variable not set".to_string())?;
        Ok(std::path::PathBuf::from(home)
            .join(".local/share/rookbot/conversations.db"))
    }

    fn initialize_schema(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS conversations (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    summary TEXT
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('user', 'claw')),
                    content_text TEXT NOT NULL,
                    content_rich_json TEXT,
                    actions_json TEXT,
                    intent_id TEXT,
                    entities_json TEXT,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (conversation_id) REFERENCES conversations(id)
                );

                CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id);
                CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);",
            )
            .map_err(|e| format!("Failed to initialize schema: {}", e))?;
        Ok(())
    }

    /// Creates a new conversation and returns its ID.
    pub fn create_conversation(&self) -> Result<String, String> {
        let now = chrono::Utc::now().to_rfc3339();
        let id = format!("conv-{}", chrono::Utc::now().timestamp_millis());

        self.conn
            .execute(
                "INSERT INTO conversations (id, created_at, updated_at) VALUES (?1, ?2, ?3)",
                params![id, now, now],
            )
            .map_err(|e| format!("Failed to create conversation: {}", e))?;

        Ok(id)
    }

    /// Saves a message and updates the parent conversation's `updated_at`.
    pub fn save_message(&self, msg: &StoredMessage) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO messages (id, conversation_id, role, content_text, content_rich_json, actions_json, intent_id, entities_json, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    msg.id,
                    msg.conversation_id,
                    msg.role,
                    msg.content_text,
                    msg.content_rich_json,
                    msg.actions_json,
                    msg.intent_id,
                    msg.entities_json,
                    msg.timestamp,
                ],
            )
            .map_err(|e| format!("Failed to save message: {}", e))?;

        self.conn
            .execute(
                "UPDATE conversations SET updated_at = ?1 WHERE id = ?2",
                params![msg.timestamp, msg.conversation_id],
            )
            .map_err(|e| format!("Failed to update conversation timestamp: {}", e))?;

        Ok(())
    }

    /// Loads all messages for a conversation, ordered by timestamp ascending.
    pub fn load_conversation(&self, conversation_id: &str) -> Result<Vec<StoredMessage>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, conversation_id, role, content_text, content_rich_json, actions_json, intent_id, entities_json, timestamp
                 FROM messages WHERE conversation_id = ?1 ORDER BY timestamp ASC",
            )
            .map_err(|e| format!("Failed to prepare query: {}", e))?;

        let rows = stmt
            .query_map(params![conversation_id], |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    conversation_id: row.get(1)?,
                    role: row.get(2)?,
                    content_text: row.get(3)?,
                    content_rich_json: row.get(4)?,
                    actions_json: row.get(5)?,
                    intent_id: row.get(6)?,
                    entities_json: row.get(7)?,
                    timestamp: row.get(8)?,
                })
            })
            .map_err(|e| format!("Failed to query messages: {}", e))?;

        let mut messages = Vec::new();
        for row in rows {
            messages.push(row.map_err(|e| format!("Failed to read message row: {}", e))?);
        }
        Ok(messages)
    }

    /// Lists conversations ordered by most recently updated, with message count and preview.
    pub fn list_conversations(&self, limit: u32) -> Result<Vec<ConversationSummary>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT c.id, c.created_at, c.updated_at, c.summary,
                        (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id) AS msg_count,
                        (SELECT m2.content_text FROM messages m2 WHERE m2.conversation_id = c.id ORDER BY m2.timestamp DESC LIMIT 1) AS last_preview
                 FROM conversations c
                 ORDER BY c.updated_at DESC
                 LIMIT ?1",
            )
            .map_err(|e| format!("Failed to prepare query: {}", e))?;

        let rows = stmt
            .query_map(params![limit], |row| {
                let preview: Option<String> = row.get(5)?;
                let truncated = preview.map(|p| {
                    if p.len() > 120 {
                        format!("{}...", &p[..117])
                    } else {
                        p
                    }
                });
                Ok(ConversationSummary {
                    id: row.get(0)?,
                    created_at: row.get(1)?,
                    updated_at: row.get(2)?,
                    summary: row.get(3)?,
                    message_count: row.get(4)?,
                    last_message_preview: truncated,
                })
            })
            .map_err(|e| format!("Failed to query conversations: {}", e))?;

        let mut summaries = Vec::new();
        for row in rows {
            summaries
                .push(row.map_err(|e| format!("Failed to read conversation row: {}", e))?);
        }
        Ok(summaries)
    }

    /// Deletes a conversation and all its messages.
    pub fn delete_conversation(&self, conversation_id: &str) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM messages WHERE conversation_id = ?1",
                params![conversation_id],
            )
            .map_err(|e| format!("Failed to delete messages: {}", e))?;

        self.conn
            .execute(
                "DELETE FROM conversations WHERE id = ?1",
                params![conversation_id],
            )
            .map_err(|e| format!("Failed to delete conversation: {}", e))?;

        Ok(())
    }

    /// Searches conversations by message content (case-insensitive substring match).
    pub fn search_conversations(&self, query: &str) -> Result<Vec<ConversationSummary>, String> {
        let pattern = format!("%{}%", query);
        let mut stmt = self
            .conn
            .prepare(
                "SELECT DISTINCT c.id, c.created_at, c.updated_at, c.summary,
                        (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id) AS msg_count,
                        (SELECT m2.content_text FROM messages m2 WHERE m2.conversation_id = c.id ORDER BY m2.timestamp DESC LIMIT 1) AS last_preview
                 FROM conversations c
                 JOIN messages m ON m.conversation_id = c.id
                 WHERE m.content_text LIKE ?1
                 ORDER BY c.updated_at DESC
                 LIMIT 50",
            )
            .map_err(|e| format!("Failed to prepare search query: {}", e))?;

        let rows = stmt
            .query_map(params![pattern], |row| {
                let preview: Option<String> = row.get(5)?;
                let truncated = preview.map(|p| {
                    if p.len() > 120 {
                        format!("{}...", &p[..117])
                    } else {
                        p
                    }
                });
                Ok(ConversationSummary {
                    id: row.get(0)?,
                    created_at: row.get(1)?,
                    updated_at: row.get(2)?,
                    summary: row.get(3)?,
                    message_count: row.get(4)?,
                    last_message_preview: truncated,
                })
            })
            .map_err(|e| format!("Failed to search conversations: {}", e))?;

        let mut summaries = Vec::new();
        for row in rows {
            summaries
                .push(row.map_err(|e| format!("Failed to read search result: {}", e))?);
        }
        Ok(summaries)
    }

    /// Returns the ID of the most recently updated conversation, if any.
    pub fn get_latest_conversation(&self) -> Result<Option<String>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM conversations ORDER BY updated_at DESC LIMIT 1")
            .map_err(|e| format!("Failed to prepare query: {}", e))?;

        let mut rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| format!("Failed to query latest conversation: {}", e))?;

        match rows.next() {
            Some(Ok(id)) => Ok(Some(id)),
            Some(Err(e)) => Err(format!("Failed to read row: {}", e)),
            None => Ok(None),
        }
    }

    /// Updates the human-readable summary of a conversation.
    pub fn update_conversation_summary(
        &self,
        conversation_id: &str,
        summary: &str,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE conversations SET summary = ?1 WHERE id = ?2",
                params![summary, conversation_id],
            )
            .map_err(|e| format!("Failed to update summary: {}", e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (ConversationStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test_conversations.db");
        let store = ConversationStore::open_at(&db_path).unwrap();
        (store, dir)
    }

    #[test]
    fn test_create_and_load_conversation() {
        let (store, _dir) = temp_store();
        let conv_id = store.create_conversation().unwrap();
        assert!(conv_id.starts_with("conv-"));

        let msg = StoredMessage {
            id: "msg-1".to_string(),
            conversation_id: conv_id.clone(),
            role: "user".to_string(),
            content_text: "Is the daemon running?".to_string(),
            content_rich_json: None,
            actions_json: None,
            intent_id: Some("daemon_status".to_string()),
            entities_json: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        store.save_message(&msg).unwrap();

        let msg2 = StoredMessage {
            id: "msg-2".to_string(),
            conversation_id: conv_id.clone(),
            role: "claw".to_string(),
            content_text: "The daemon is running.".to_string(),
            content_rich_json: Some(r#"{"type":"status"}"#.to_string()),
            actions_json: None,
            intent_id: Some("daemon_status".to_string()),
            entities_json: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        store.save_message(&msg2).unwrap();

        let messages = store.load_conversation(&conv_id).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].role, "user");
        assert_eq!(messages[1].role, "claw");
        assert_eq!(messages[0].content_text, "Is the daemon running?");
    }

    #[test]
    fn test_list_conversations() {
        let (store, _dir) = temp_store();

        let id1 = store.create_conversation().unwrap();
        store
            .save_message(&StoredMessage {
                id: "m1".to_string(),
                conversation_id: id1.clone(),
                role: "user".to_string(),
                content_text: "Hello".to_string(),
                content_rich_json: None,
                actions_json: None,
                intent_id: None,
                entities_json: None,
                timestamp: "2026-01-01T00:00:00Z".to_string(),
            })
            .unwrap();

        let id2 = store.create_conversation().unwrap();
        store
            .save_message(&StoredMessage {
                id: "m2".to_string(),
                conversation_id: id2.clone(),
                role: "user".to_string(),
                content_text: "World".to_string(),
                content_rich_json: None,
                actions_json: None,
                intent_id: None,
                entities_json: None,
                timestamp: "2026-01-02T00:00:00Z".to_string(),
            })
            .unwrap();

        let list = store.list_conversations(10).unwrap();
        assert_eq!(list.len(), 2);
        // Most recently updated first
        assert_eq!(list[0].id, id2);
        assert_eq!(list[0].message_count, 1);
        assert_eq!(
            list[0].last_message_preview.as_deref(),
            Some("World")
        );
    }

    #[test]
    fn test_delete_conversation() {
        let (store, _dir) = temp_store();
        let conv_id = store.create_conversation().unwrap();
        store
            .save_message(&StoredMessage {
                id: "m1".to_string(),
                conversation_id: conv_id.clone(),
                role: "user".to_string(),
                content_text: "test".to_string(),
                content_rich_json: None,
                actions_json: None,
                intent_id: None,
                entities_json: None,
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
            .unwrap();

        store.delete_conversation(&conv_id).unwrap();

        let messages = store.load_conversation(&conv_id).unwrap();
        assert!(messages.is_empty());

        let list = store.list_conversations(10).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn test_search_conversations() {
        let (store, _dir) = temp_store();
        let conv_id = store.create_conversation().unwrap();
        store
            .save_message(&StoredMessage {
                id: "m1".to_string(),
                conversation_id: conv_id.clone(),
                role: "user".to_string(),
                content_text: "block the filesystem server".to_string(),
                content_rich_json: None,
                actions_json: None,
                intent_id: None,
                entities_json: None,
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
            .unwrap();

        let results = store.search_conversations("filesystem").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, conv_id);

        let no_results = store.search_conversations("nonexistent").unwrap();
        assert!(no_results.is_empty());
    }

    #[test]
    fn test_get_latest_conversation() {
        let (store, _dir) = temp_store();

        assert!(store.get_latest_conversation().unwrap().is_none());

        let id1 = store.create_conversation().unwrap();
        // Small delay to ensure different timestamps
        let id2 = store.create_conversation().unwrap();

        let latest = store.get_latest_conversation().unwrap();
        assert!(latest.is_some());
        // id2 was created after id1, so it should be latest
        assert_eq!(latest.unwrap(), id2);

        // Update id1 to be newer
        store
            .save_message(&StoredMessage {
                id: "m1".to_string(),
                conversation_id: id1.clone(),
                role: "user".to_string(),
                content_text: "test".to_string(),
                content_rich_json: None,
                actions_json: None,
                intent_id: None,
                entities_json: None,
                timestamp: "2099-01-01T00:00:00Z".to_string(),
            })
            .unwrap();

        let latest = store.get_latest_conversation().unwrap();
        assert_eq!(latest.unwrap(), id1);
    }

    #[test]
    fn test_update_conversation_summary() {
        let (store, _dir) = temp_store();
        let conv_id = store.create_conversation().unwrap();

        store
            .update_conversation_summary(&conv_id, "Discussion about daemon status")
            .unwrap();

        let list = store.list_conversations(10).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(
            list[0].summary.as_deref(),
            Some("Discussion about daemon status")
        );
    }

    #[test]
    fn test_multiple_conversations_isolation() {
        let (store, _dir) = temp_store();
        let id1 = store.create_conversation().unwrap();
        let id2 = store.create_conversation().unwrap();

        store
            .save_message(&StoredMessage {
                id: "m1".to_string(),
                conversation_id: id1.clone(),
                role: "user".to_string(),
                content_text: "msg for conv 1".to_string(),
                content_rich_json: None,
                actions_json: None,
                intent_id: None,
                entities_json: None,
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
            .unwrap();

        store
            .save_message(&StoredMessage {
                id: "m2".to_string(),
                conversation_id: id2.clone(),
                role: "user".to_string(),
                content_text: "msg for conv 2".to_string(),
                content_rich_json: None,
                actions_json: None,
                intent_id: None,
                entities_json: None,
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
            .unwrap();

        let msgs1 = store.load_conversation(&id1).unwrap();
        assert_eq!(msgs1.len(), 1);
        assert_eq!(msgs1[0].content_text, "msg for conv 1");

        let msgs2 = store.load_conversation(&id2).unwrap();
        assert_eq!(msgs2.len(), 1);
        assert_eq!(msgs2[0].content_text, "msg for conv 2");
    }

    #[test]
    fn test_preview_truncation() {
        let (store, _dir) = temp_store();
        let conv_id = store.create_conversation().unwrap();
        let long_text = "a".repeat(200);

        store
            .save_message(&StoredMessage {
                id: "m1".to_string(),
                conversation_id: conv_id.clone(),
                role: "user".to_string(),
                content_text: long_text,
                content_rich_json: None,
                actions_json: None,
                intent_id: None,
                entities_json: None,
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
            .unwrap();

        let list = store.list_conversations(10).unwrap();
        let preview = list[0].last_message_preview.as_ref().unwrap();
        assert_eq!(preview.len(), 120); // 117 chars + "..."
        assert!(preview.ends_with("..."));
    }
}
