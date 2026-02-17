//! SQLite persistence for behavioral profiles.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::Connection;

use super::profile::ServerProfile;

/// Persistent storage for behavioral profiles using SQLite.
pub struct ProfileStore {
    conn: Connection,
}

impl ProfileStore {
    /// Open or create the profile database at the given path.
    pub fn open(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Creating directory for {}", db_path.display()))?;
        }
        let conn = Connection::open(db_path)
            .with_context(|| format!("Opening profile database at {}", db_path.display()))?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Open an in-memory database (useful for testing).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Default database path.
    pub fn default_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".local/share/clawdefender/profiles.db")
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS profiles (
                server_name TEXT PRIMARY KEY,
                profile_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );",
        )?;
        Ok(())
    }

    /// Upsert a profile (insert or replace).
    pub fn save_profile(&self, profile: &ServerProfile) -> Result<()> {
        let json = serde_json::to_string(profile)?;
        let updated_at = profile.last_updated.to_rfc3339();
        self.conn.execute(
            "INSERT INTO profiles (server_name, profile_json, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(server_name) DO UPDATE SET
                profile_json = excluded.profile_json,
                updated_at = excluded.updated_at",
            rusqlite::params![profile.server_name, json, updated_at],
        )?;
        Ok(())
    }

    /// Load all profiles from the database.
    pub fn load_all_profiles(&self) -> Result<Vec<ServerProfile>> {
        let mut stmt = self.conn.prepare("SELECT profile_json FROM profiles")?;
        let profiles = stmt
            .query_map([], |row| {
                let json: String = row.get(0)?;
                Ok(json)
            })?
            .filter_map(|r| r.ok())
            .filter_map(|json| serde_json::from_str(&json).ok())
            .collect();
        Ok(profiles)
    }

    /// Reset a profile back to learning mode by deleting it.
    pub fn reset_profile(&self, server_name: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM profiles WHERE server_name = ?1",
            rusqlite::params![server_name],
        )?;
        Ok(())
    }

    /// Export a profile as JSON.
    pub fn export_profile(&self, server_name: &str) -> Result<Option<serde_json::Value>> {
        let mut stmt = self
            .conn
            .prepare("SELECT profile_json FROM profiles WHERE server_name = ?1")?;
        let result = stmt
            .query_row(rusqlite::params![server_name], |row| {
                let json: String = row.get(0)?;
                Ok(json)
            })
            .ok();
        match result {
            Some(json) => {
                let value: serde_json::Value = serde_json::from_str(&json)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    /// Import a profile from JSON.
    pub fn import_profile(&self, json: &serde_json::Value) -> Result<()> {
        let profile: ServerProfile = serde_json::from_value(json.clone())?;
        self.save_profile(&profile)
    }

    /// Delete a profile entirely.
    pub fn delete_profile(&self, server_name: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM profiles WHERE server_name = ?1",
            rusqlite::params![server_name],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behavioral::profile::ServerProfile;

    fn make_test_profile(name: &str) -> ServerProfile {
        let mut profile = ServerProfile::new(name.to_string(), "test-client".to_string());
        profile.observation_count = 150;
        profile.learning_mode = false;
        profile
            .tool_profile
            .tool_counts
            .insert("read_file".to_string(), 50);
        profile
            .file_profile
            .directory_prefixes
            .insert("/home/user/project".to_string());
        profile.network_profile.has_networked = true;
        profile
            .network_profile
            .observed_hosts
            .insert("api.example.com".to_string());
        profile
    }

    #[test]
    fn test_save_and_load_profile() {
        let store = ProfileStore::open_in_memory().unwrap();
        let profile = make_test_profile("test-server");

        store.save_profile(&profile).unwrap();
        let loaded = store.load_all_profiles().unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].server_name, "test-server");
        assert_eq!(loaded[0].observation_count, 150);
        assert!(!loaded[0].learning_mode);
        assert_eq!(loaded[0].tool_profile.tool_counts["read_file"], 50);
    }

    #[test]
    fn test_upsert_overwrites() {
        let store = ProfileStore::open_in_memory().unwrap();
        let mut profile = make_test_profile("test-server");

        store.save_profile(&profile).unwrap();
        profile.observation_count = 200;
        store.save_profile(&profile).unwrap();

        let loaded = store.load_all_profiles().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].observation_count, 200);
    }

    #[test]
    fn test_delete_profile() {
        let store = ProfileStore::open_in_memory().unwrap();
        let profile = make_test_profile("test-server");

        store.save_profile(&profile).unwrap();
        store.delete_profile("test-server").unwrap();

        let loaded = store.load_all_profiles().unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_export_import_profile() {
        let store = ProfileStore::open_in_memory().unwrap();
        let profile = make_test_profile("test-server");

        store.save_profile(&profile).unwrap();
        let exported = store.export_profile("test-server").unwrap().unwrap();

        // Import into a fresh store
        let store2 = ProfileStore::open_in_memory().unwrap();
        store2.import_profile(&exported).unwrap();

        let loaded = store2.load_all_profiles().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].server_name, "test-server");
        assert_eq!(loaded[0].observation_count, 150);
    }

    #[test]
    fn test_export_nonexistent_returns_none() {
        let store = ProfileStore::open_in_memory().unwrap();
        let result = store.export_profile("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_reset_profile() {
        let store = ProfileStore::open_in_memory().unwrap();
        let profile = make_test_profile("test-server");

        store.save_profile(&profile).unwrap();
        store.reset_profile("test-server").unwrap();

        let loaded = store.load_all_profiles().unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_multiple_profiles() {
        let store = ProfileStore::open_in_memory().unwrap();

        store.save_profile(&make_test_profile("server-a")).unwrap();
        store.save_profile(&make_test_profile("server-b")).unwrap();
        store.save_profile(&make_test_profile("server-c")).unwrap();

        let loaded = store.load_all_profiles().unwrap();
        assert_eq!(loaded.len(), 3);
    }
}
