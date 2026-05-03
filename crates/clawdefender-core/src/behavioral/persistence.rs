//! SQLite persistence for behavioral profiles.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rusqlite::Connection;
use tracing::warn;

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
        PathBuf::from(home).join(".local/share/rookbot/profiles.db")
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

    /// Load a single profile by server name (for on-demand reload after eviction).
    ///
    /// Returns `None` if the server has no persisted profile.
    pub fn load_profile(&self, server_name: &str) -> Result<Option<ServerProfile>> {
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
                let profile: ServerProfile = serde_json::from_str(&json)?;
                Ok(Some(profile))
            }
            None => Ok(None),
        }
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

    /// Save multiple profiles in a single SQLite transaction.
    ///
    /// This is significantly more efficient than calling `save_profile` in a loop,
    /// as it amortizes the transaction overhead and performs a single fsync.
    pub fn save_profiles_batch(&self, profiles: &[ServerProfile]) -> Result<()> {
        if profiles.is_empty() {
            return Ok(());
        }
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        for profile in profiles {
            let json = serde_json::to_string(profile)?;
            let updated_at = profile.last_updated.to_rfc3339();
            if let Err(e) = self.conn.execute(
                "INSERT INTO profiles (server_name, profile_json, updated_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(server_name) DO UPDATE SET
                    profile_json = excluded.profile_json,
                    updated_at = excluded.updated_at",
                rusqlite::params![profile.server_name, json, updated_at],
            ) {
                // Rollback on error to keep the database consistent.
                let _ = self.conn.execute_batch("ROLLBACK");
                return Err(e.into());
            }
        }
        self.conn.execute_batch("COMMIT")?;
        Ok(())
    }
}

/// Flush interval for the profile batcher (30 seconds).
const PROFILE_FLUSH_INTERVAL: Duration = Duration::from_secs(30);

/// Batches profile updates in memory and writes them to SQLite in a single
/// transaction every 30 seconds. This reduces disk I/O from potentially
/// hundreds of individual writes per minute to a single batched write.
///
/// Thread-safe: all internal state is behind a `Mutex`.
pub struct ProfileBatcher {
    store: Arc<ProfileStore>,
    /// Profiles that have been modified since the last flush.
    pending: Mutex<HashMap<String, ServerProfile>>,
    /// Last time profiles were flushed to disk.
    last_flush: Mutex<Instant>,
}

impl ProfileBatcher {
    /// Create a new batcher wrapping the given store.
    pub fn new(store: Arc<ProfileStore>) -> Self {
        Self {
            store,
            pending: Mutex::new(HashMap::new()),
            last_flush: Mutex::new(Instant::now()),
        }
    }

    /// Queue a profile update. The profile will be written to SQLite on the
    /// next flush (at most 30 seconds away). If the same server is updated
    /// multiple times between flushes, only the latest snapshot is written.
    pub fn queue_update(&self, profile: ServerProfile) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(profile.server_name.clone(), profile);
        }

        // Check if it's time to flush.
        if self.should_flush() {
            self.flush();
        }
    }

    /// Returns true if enough time has elapsed since the last flush.
    fn should_flush(&self) -> bool {
        match self.last_flush.lock() {
            Ok(last) => last.elapsed() >= PROFILE_FLUSH_INTERVAL,
            Err(_) => true,
        }
    }

    /// Flush all pending profiles to SQLite in a single transaction.
    /// Safe to call at any time; does nothing if there are no pending updates.
    pub fn flush(&self) {
        let profiles: Vec<ServerProfile> = {
            match self.pending.lock() {
                Ok(mut pending) => {
                    if pending.is_empty() {
                        return;
                    }
                    let drained: Vec<_> = pending.drain().map(|(_, v)| v).collect();
                    drained
                }
                Err(_) => return,
            }
        };

        if let Err(e) = self.store.save_profiles_batch(&profiles) {
            warn!(error = %e, count = profiles.len(), "failed to batch-flush profiles to SQLite");
        }

        if let Ok(mut last) = self.last_flush.lock() {
            *last = Instant::now();
        }
    }

    /// Returns the number of pending (unflushed) profile updates.
    pub fn pending_count(&self) -> usize {
        self.pending.lock().map(|p| p.len()).unwrap_or(0)
    }
}

impl Drop for ProfileBatcher {
    fn drop(&mut self) {
        // Ensure all pending profiles are written on shutdown.
        self.flush();
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

    #[test]
    fn test_save_profiles_batch() {
        let store = ProfileStore::open_in_memory().unwrap();
        let profiles = vec![
            make_test_profile("server-a"),
            make_test_profile("server-b"),
            make_test_profile("server-c"),
        ];

        store.save_profiles_batch(&profiles).unwrap();

        let loaded = store.load_all_profiles().unwrap();
        assert_eq!(loaded.len(), 3);
    }

    #[test]
    fn test_save_profiles_batch_empty() {
        let store = ProfileStore::open_in_memory().unwrap();
        store.save_profiles_batch(&[]).unwrap();

        let loaded = store.load_all_profiles().unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_save_profiles_batch_upsert() {
        let store = ProfileStore::open_in_memory().unwrap();
        let profiles = vec![make_test_profile("server-a")];
        store.save_profiles_batch(&profiles).unwrap();

        // Update with a batch containing the same server
        let mut updated = make_test_profile("server-a");
        updated.observation_count = 999;
        store.save_profiles_batch(&[updated]).unwrap();

        let loaded = store.load_all_profiles().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].observation_count, 999);
    }

    #[test]
    fn test_profile_batcher_queues_and_flushes() {
        let store = Arc::new(ProfileStore::open_in_memory().unwrap());
        let batcher = ProfileBatcher::new(Arc::clone(&store));

        batcher.queue_update(make_test_profile("server-a"));
        batcher.queue_update(make_test_profile("server-b"));

        // Should be pending (flush interval hasn't elapsed)
        assert_eq!(batcher.pending_count(), 2);

        // Manual flush
        batcher.flush();

        assert_eq!(batcher.pending_count(), 0);
        let loaded = store.load_all_profiles().unwrap();
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn test_profile_batcher_deduplicates_updates() {
        let store = Arc::new(ProfileStore::open_in_memory().unwrap());
        let batcher = ProfileBatcher::new(Arc::clone(&store));

        let mut profile1 = make_test_profile("server-a");
        profile1.observation_count = 100;
        batcher.queue_update(profile1);

        let mut profile2 = make_test_profile("server-a");
        profile2.observation_count = 200;
        batcher.queue_update(profile2);

        // Only 1 pending because same server_name
        assert_eq!(batcher.pending_count(), 1);

        batcher.flush();

        let loaded = store.load_all_profiles().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].observation_count, 200);
    }

    #[test]
    fn test_profile_batcher_drop_flushes() {
        let store = Arc::new(ProfileStore::open_in_memory().unwrap());
        {
            let batcher = ProfileBatcher::new(Arc::clone(&store));
            batcher.queue_update(make_test_profile("server-drop"));
            // Batcher dropped here -- should auto-flush
        }

        let loaded = store.load_all_profiles().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].server_name, "server-drop");
    }
}
