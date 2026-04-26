use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Persisted state for fired/dismissed milestones and metadata needed by triggers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GuidanceStore {
    /// Milestones that have fired: id -> fired_at timestamp.
    pub fired: HashMap<String, String>,
    /// Milestones that the user has dismissed: id -> dismissed_at timestamp.
    pub dismissed: HashMap<String, String>,
    /// ISO 8601 timestamp of when onboarding was completed.
    pub onboarding_completed_at: Option<String>,
    /// Pages the user has visited (for feature nudges).
    pub page_visits: HashSet<String>,
}

impl GuidanceStore {
    /// Path to the guidance state file on disk.
    fn file_path() -> PathBuf {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default();
        home.join(".local/share/rookbot").join("guidance_state.json")
    }

    /// Load persisted guidance state from disk.
    pub fn load() -> Self {
        let path = Self::file_path();
        if !path.exists() {
            return Self::default();
        }
        match fs::read_to_string(&path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Persist guidance state to disk.
    pub fn save(&self) {
        let path = Self::file_path();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(&path, json);
        }
    }

    /// Mark a milestone as fired with the given timestamp.
    pub fn mark_fired(&mut self, id: &str, timestamp: &str) {
        self.fired.insert(id.to_string(), timestamp.to_string());
        self.save();
    }

    /// Mark a milestone as dismissed.
    pub fn mark_dismissed(&mut self, id: &str, timestamp: &str) {
        self.dismissed.insert(id.to_string(), timestamp.to_string());
        self.save();
    }

    /// Check if a milestone has already fired.
    pub fn has_fired(&self, id: &str) -> bool {
        self.fired.contains_key(id)
    }

    /// Record a page visit.
    pub fn record_page_visit(&mut self, page: &str) {
        if self.page_visits.insert(page.to_string()) {
            self.save();
        }
    }

    /// Check if the user has visited a specific page.
    pub fn has_visited_page(&self, page: &str) -> bool {
        self.page_visits.contains(page)
    }

    /// Reset all guidance state (for testing).
    pub fn reset(&mut self) {
        self.fired.clear();
        self.dismissed.clear();
        self.page_visits.clear();
        // Keep onboarding_completed_at
        self.save();
    }
}
