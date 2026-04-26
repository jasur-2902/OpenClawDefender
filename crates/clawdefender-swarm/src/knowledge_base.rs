use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::{debug, info, warn};
use uuid::Uuid;

// ============================================================================
// Main Knowledge Base
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityKnowledgeBase {
    pub server_profiles: HashMap<String, ServerKnowledge>,
    pub resolved_incidents: Vec<ResolvedIncident>,
    pub false_positives: Vec<FalsePositiveRecord>,
    pub user_preferences: UserSecurityPreferences,
    pub known_patterns: Vec<LearnedPattern>,
    pub created_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
    pub entry_count: u64,
    #[serde(skip)]
    storage_path: PathBuf,
}

impl SecurityKnowledgeBase {
    pub fn new() -> Self {
        Self::with_path(Self::default_storage_path())
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self {
            server_profiles: HashMap::new(),
            resolved_incidents: Vec::new(),
            false_positives: Vec::new(),
            user_preferences: UserSecurityPreferences::default(),
            known_patterns: Vec::new(),
            created_at: Utc::now(),
            last_updated: Utc::now(),
            entry_count: 0,
            storage_path: path,
        }
    }

    fn default_storage_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".local/share/rookbot/knowledge_base.json")
    }

    // ========================================================================
    // Server Knowledge
    // ========================================================================

    pub fn get_server_knowledge(&self, server: &str) -> Option<&ServerKnowledge> {
        self.server_profiles.get(server)
    }

    pub fn update_server_knowledge(&mut self, server: &str, update: ServerKnowledgeUpdate) {
        let profile = self
            .server_profiles
            .entry(server.to_string())
            .or_insert_with(|| ServerKnowledge::new(server));

        profile.last_seen = Utc::now();

        if let Some(assessment) = update.trust_assessment {
            profile.trust_assessment = assessment;
        }

        if let Some(behavior) = update.add_legitimate_behavior {
            if !profile.known_legitimate_behaviors.contains(&behavior) {
                profile.known_legitimate_behaviors.push(behavior);
            }
        }

        if let Some(fp) = update.add_false_positive {
            if !profile.known_false_positives.contains(&fp) {
                profile.known_false_positives.push(fp);
            }
        }

        if let Some(investigation_id) = update.add_investigation {
            if !profile.investigation_history.contains(&investigation_id) {
                profile.investigation_history.push(investigation_id);
            }
        }

        if let Some(note) = update.add_note {
            profile.notes.push(note);
        }

        self.last_updated = Utc::now();
        self.entry_count += 1;
    }

    pub fn add_trust_signal(&mut self, server: &str, signal: TrustSignal) {
        let profile = self
            .server_profiles
            .entry(server.to_string())
            .or_insert_with(|| ServerKnowledge::new(server));

        profile.user_trust_signals.push(signal);
        profile.trust_level = Self::calculate_trust_level(&profile.user_trust_signals);
        profile.last_seen = Utc::now();

        self.last_updated = Utc::now();
    }

    pub fn get_server_trust_level(&self, server: &str) -> TrustLevel {
        self.server_profiles
            .get(server)
            .map(|p| p.trust_level.clone())
            .unwrap_or(TrustLevel::Unknown)
    }

    pub fn forget_server(&mut self, server: &str) {
        self.server_profiles.remove(server);

        self.false_positives
            .retain(|fp| !fp.event_pattern.contains(server));
        self.resolved_incidents
            .retain(|inc| inc.server_name != server);
        self.known_patterns.iter_mut().for_each(|p| {
            p.indicators.retain(|i| !i.contains(server));
        });

        self.last_updated = Utc::now();
        info!("Forgot all knowledge for server: {}", server);
    }

    pub fn list_known_servers(&self) -> Vec<&ServerKnowledge> {
        self.server_profiles.values().collect()
    }

    fn calculate_trust_level(signals: &[TrustSignal]) -> TrustLevel {
        if signals.is_empty() {
            return TrustLevel::Unknown;
        }

        let mut allow_count = 0;
        let mut block_count = 0;
        let mut manual_trust = None;
        let mut has_threat = false;

        for signal in signals {
            match signal.signal_type {
                TrustSignalType::UserAllowedPrompt | TrustSignalType::InvestigationClear => {
                    allow_count += 1;
                }
                TrustSignalType::UserBlockedPrompt | TrustSignalType::InvestigationThreat => {
                    block_count += 1;
                    if matches!(signal.signal_type, TrustSignalType::InvestigationThreat) {
                        has_threat = true;
                    }
                }
                TrustSignalType::ManualTrustSet => {
                    manual_trust = Some(signal.context.clone());
                }
                TrustSignalType::UserDismissedAlert => {}
            }
        }

        if has_threat {
            return TrustLevel::Untrusted;
        }

        if let Some(trust) = manual_trust {
            return match trust.as_str() {
                "fully_trusted" => TrustLevel::FullyTrusted,
                "trusted" => TrustLevel::Trusted,
                "cautious" => TrustLevel::Cautious,
                "untrusted" => TrustLevel::Untrusted,
                _ => TrustLevel::Unknown,
            };
        }

        if block_count > allow_count {
            return TrustLevel::Untrusted;
        }

        if allow_count > block_count {
            if signals.len() >= 10 {
                return TrustLevel::Trusted;
            } else {
                return TrustLevel::Cautious;
            }
        }

        TrustLevel::Unknown
    }

    // ========================================================================
    // False Positives
    // ========================================================================

    pub fn add_false_positive(&mut self, pattern: &str, reason: &str, source: FPSource) {
        let fp = FalsePositiveRecord {
            id: Uuid::new_v4(),
            event_pattern: pattern.to_string(),
            reason: reason.to_string(),
            recorded_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(90),
            source,
            hit_count: 0,
            last_hit: None,
        };

        self.false_positives.push(fp);
        self.last_updated = Utc::now();
        self.entry_count += 1;

        info!("Added false positive: {} ({})", pattern, reason);
    }

    pub fn check_false_positive(&mut self, pattern: &str) -> Option<&FalsePositiveRecord> {
        let now = Utc::now();

        for fp in &mut self.false_positives {
            if fp.expires_at > now && fp.event_pattern == pattern {
                fp.hit_count += 1;
                fp.last_hit = Some(now);
                return Some(&*fp);
            }
        }

        None
    }

    pub fn remove_false_positive(&mut self, id: Uuid) {
        self.false_positives.retain(|fp| fp.id != id);
        self.last_updated = Utc::now();
    }

    pub fn list_false_positives(&self) -> &[FalsePositiveRecord] {
        &self.false_positives
    }

    // ========================================================================
    // Learned Patterns
    // ========================================================================

    pub fn add_pattern(&mut self, pattern: LearnedPattern) {
        self.known_patterns.push(pattern);
        self.last_updated = Utc::now();
        self.entry_count += 1;
    }

    pub fn check_pattern_match(&mut self, indicators: &[String]) -> Option<&LearnedPattern> {
        for pattern in &mut self.known_patterns {
            let matches = indicators
                .iter()
                .filter(|i| pattern.indicators.contains(i))
                .count();

            if matches >= (pattern.indicators.len() / 2).max(1) {
                pattern.hit_count += 1;
                pattern.last_seen = Some(Utc::now());
                return Some(&*pattern);
            }
        }

        None
    }

    pub fn list_patterns(&self) -> &[LearnedPattern] {
        &self.known_patterns
    }

    pub fn remove_pattern(&mut self, id: Uuid) {
        self.known_patterns.retain(|p| p.id != id);
        self.last_updated = Utc::now();
    }

    // ========================================================================
    // Resolved Incidents
    // ========================================================================

    pub fn add_resolved_incident(&mut self, incident: ResolvedIncident) {
        self.resolved_incidents.push(incident);
        self.last_updated = Utc::now();
        self.entry_count += 1;
    }

    pub fn get_server_incidents(&self, server: &str) -> Vec<&ResolvedIncident> {
        self.resolved_incidents
            .iter()
            .filter(|inc| inc.server_name == server)
            .collect()
    }

    pub fn list_incidents(&self, count: usize) -> Vec<&ResolvedIncident> {
        let mut incidents: Vec<&ResolvedIncident> = self.resolved_incidents.iter().collect();
        incidents.sort_by(|a, b| b.resolved_at.cmp(&a.resolved_at));
        incidents.into_iter().take(count).collect()
    }

    // ========================================================================
    // Knowledge Accumulation
    // ========================================================================

    pub fn learn_from_investigation(
        &mut self,
        server: &str,
        verdict: &str,
        confidence: f64,
        investigation_id: Uuid,
        summary: &str,
    ) {
        self.add_trust_signal(
            server,
            TrustSignal {
                signal_type: if verdict.contains("safe")
                    || verdict.contains("benign")
                    || verdict.contains("false positive")
                {
                    TrustSignalType::InvestigationClear
                } else {
                    TrustSignalType::InvestigationThreat
                },
                timestamp: Utc::now(),
                context: format!("Investigation {}: {}", investigation_id, verdict),
            },
        );

        if verdict.contains("false positive") && confidence > 0.7 {
            let pattern = format!("server={}", server);
            self.add_false_positive(
                &pattern,
                &format!("Investigation determined: {}", summary),
                FPSource::InvestigationResult,
            );
        }

        if verdict.contains("threat") || verdict.contains("attack") {
            let pattern = LearnedPattern {
                id: Uuid::new_v4(),
                pattern_name: format!("{} - {}", server, summary),
                description: verdict.to_string(),
                indicators: vec![format!("server={}", server)],
                learned_from: PatternSource::Investigation { investigation_id },
                severity: if confidence > 0.8 {
                    "high".to_string()
                } else {
                    "medium".to_string()
                },
                confidence,
                first_seen: Utc::now(),
                last_seen: None,
                hit_count: 0,
            };
            self.add_pattern(pattern);
        }

        self.update_server_knowledge(
            server,
            ServerKnowledgeUpdate {
                trust_assessment: Some(verdict.to_string()),
                add_investigation: Some(investigation_id),
                ..Default::default()
            },
        );
    }

    pub fn record_prompt_response(
        &mut self,
        server: &str,
        tool: &str,
        target: &str,
        response: &str,
    ) {
        let pattern = format!("server={} tool={} target={}", server, tool, target);

        let pref = self
            .user_preferences
            .prompt_response_patterns
            .entry(pattern.clone())
            .or_insert_with(|| PromptPreference {
                pattern: pattern.clone(),
                usual_response: response.to_string(),
                consistency: 1.0,
                sample_count: 0,
            });

        pref.sample_count += 1;

        if pref.usual_response == response {
            pref.consistency = (pref.consistency * (pref.sample_count - 1) as f64 + 1.0)
                / pref.sample_count as f64;
        } else {
            pref.consistency =
                (pref.consistency * (pref.sample_count - 1) as f64) / pref.sample_count as f64;
            if pref.consistency < 0.5 {
                pref.usual_response = response.to_string();
            }
        }

        let signal = TrustSignal {
            signal_type: if response == "allow" {
                TrustSignalType::UserAllowedPrompt
            } else {
                TrustSignalType::UserBlockedPrompt
            },
            timestamp: Utc::now(),
            context: format!("Prompt: {} {} {}", tool, target, response),
        };

        self.add_trust_signal(server, signal);
    }

    pub fn record_alert_dismissal(
        &mut self,
        server: &str,
        pattern: &str,
        count: u32,
    ) -> Option<String> {
        if count == 3 {
            return Some(
                "You've dismissed this pattern 3 times. Should I remember it as safe?".to_string(),
            );
        }

        if count >= 5 {
            self.add_false_positive(
                pattern,
                "Frequently dismissed by user",
                FPSource::UserDismiss,
            );
            return Some("Auto-added to false positives after 5 dismissals".to_string());
        }

        self.add_trust_signal(
            server,
            TrustSignal {
                signal_type: TrustSignalType::UserDismissedAlert,
                timestamp: Utc::now(),
                context: format!("Dismissed alert for pattern: {}", pattern),
            },
        );

        None
    }

    // ========================================================================
    // Knowledge Query
    // ========================================================================

    pub fn query(&mut self, q: &KnowledgeQuery) -> KnowledgeVerdict {
        let pattern = Self::build_pattern_string(q);

        if let Some(fp) = self.check_false_positive(&pattern) {
            return KnowledgeVerdict {
                classification: KnowledgeClassification::KnownFalsePositive,
                confidence: 0.9,
                reason: format!("Known false positive: {}", fp.reason),
                source_entry_id: Some(fp.id),
            };
        }

        let mut indicators = vec![format!("server={}", q.server_name)];
        if let Some(tool) = &q.tool_name {
            indicators.push(format!("tool={}", tool));
        }
        if let Some(target) = &q.target {
            indicators.push(format!("target={}", target));
        }

        if let Some(pattern) = self.check_pattern_match(&indicators) {
            return KnowledgeVerdict {
                classification: KnowledgeClassification::KnownAttackPattern,
                confidence: pattern.confidence,
                reason: format!("Matches known pattern: {}", pattern.pattern_name),
                source_entry_id: Some(pattern.id),
            };
        }

        let trust_level = self.get_server_trust_level(&q.server_name);
        match trust_level {
            TrustLevel::FullyTrusted => KnowledgeVerdict {
                classification: KnowledgeClassification::TrustedServer,
                confidence: 0.95,
                reason: "Server is fully trusted".to_string(),
                source_entry_id: None,
            },
            TrustLevel::Untrusted => KnowledgeVerdict {
                classification: KnowledgeClassification::UntrustedServer,
                confidence: 0.85,
                reason: "Server is untrusted based on history".to_string(),
                source_entry_id: None,
            },
            _ => KnowledgeVerdict {
                classification: KnowledgeClassification::NoKnowledge,
                confidence: 0.0,
                reason: "No relevant knowledge found".to_string(),
                source_entry_id: None,
            },
        }
    }

    fn build_pattern_string(q: &KnowledgeQuery) -> String {
        let mut parts = vec![format!("server={}", q.server_name)];

        if let Some(tool) = &q.tool_name {
            parts.push(format!("tool={}", tool));
        }
        if let Some(target) = &q.target {
            parts.push(format!("target={}", target));
        }

        parts.join(" ")
    }

    // ========================================================================
    // User Preferences
    // ========================================================================

    pub fn get_user_preferences(&self) -> &UserSecurityPreferences {
        &self.user_preferences
    }

    pub fn update_risk_tolerance(&mut self, tolerance: RiskTolerance) {
        self.user_preferences.preferred_risk_tolerance = tolerance;
        self.last_updated = Utc::now();
    }

    // ========================================================================
    // Maintenance
    // ========================================================================

    pub fn expire_old_entries(&mut self) -> u32 {
        let now = Utc::now();
        let before_count = self.false_positives.len();

        self.false_positives.retain(|fp| fp.expires_at > now);

        let expired = (before_count - self.false_positives.len()) as u32;

        if expired > 0 {
            self.last_updated = Utc::now();
            info!("Expired {} old false positive entries", expired);
        }

        expired
    }

    pub fn resolve_conflicts(&self) -> Vec<KnowledgeConflict> {
        let mut conflicts = Vec::new();

        for (server, profile) in &self.server_profiles {
            let fp_count = self
                .false_positives
                .iter()
                .filter(|fp| fp.event_pattern.contains(server))
                .count();

            let incident_count = self
                .resolved_incidents
                .iter()
                .filter(|inc| inc.server_name.as_str() == server && inc.verdict.contains("threat"))
                .count();

            if fp_count > 5 && incident_count > 2 {
                conflicts.push(KnowledgeConflict {
                    server_name: server.clone(),
                    conflict_type: "high_fp_and_threats".to_string(),
                    description: format!(
                        "Server has {} false positives but also {} threat incidents",
                        fp_count, incident_count
                    ),
                    entries: vec![
                        format!("FPs: {}", fp_count),
                        format!("Threats: {}", incident_count),
                        format!("Trust: {:?}", profile.trust_level),
                    ],
                });
            }

            let allow_signals = profile
                .user_trust_signals
                .iter()
                .filter(|s| {
                    matches!(
                        s.signal_type,
                        TrustSignalType::UserAllowedPrompt | TrustSignalType::InvestigationClear
                    )
                })
                .count();

            let block_signals = profile
                .user_trust_signals
                .iter()
                .filter(|s| {
                    matches!(
                        s.signal_type,
                        TrustSignalType::UserBlockedPrompt | TrustSignalType::InvestigationThreat
                    )
                })
                .count();

            if allow_signals > 0
                && block_signals > 0
                && (allow_signals as f64 / block_signals as f64).abs() < 1.5
            {
                conflicts.push(KnowledgeConflict {
                    server_name: server.clone(),
                    conflict_type: "mixed_signals".to_string(),
                    description: format!(
                        "Server has mixed trust signals: {} allow, {} block",
                        allow_signals, block_signals
                    ),
                    entries: vec![
                        format!("Allow: {}", allow_signals),
                        format!("Block: {}", block_signals),
                    ],
                });
            }
        }

        conflicts
    }

    pub fn get_entry_count(&self) -> u64 {
        self.entry_count
    }

    pub fn enforce_cap(&mut self) {
        const MAX_ENTRIES: usize = 1000;

        let total_entries = self.server_profiles.len()
            + self.false_positives.len()
            + self.known_patterns.len()
            + self.resolved_incidents.len();

        if total_entries <= MAX_ENTRIES {
            return;
        }

        let to_remove = total_entries - MAX_ENTRIES;
        let mut removed = 0;

        self.known_patterns
            .sort_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap());
        let remove_patterns = to_remove.min(self.known_patterns.len() / 4);
        self.known_patterns.drain(0..remove_patterns);
        removed += remove_patterns;

        if removed < to_remove {
            self.false_positives
                .sort_by(|a, b| a.hit_count.cmp(&b.hit_count));
            let remove_fps = (to_remove - removed).min(self.false_positives.len() / 4);
            self.false_positives.drain(0..remove_fps);
            removed += remove_fps;
        }

        if removed < to_remove {
            self.resolved_incidents
                .sort_by(|a, b| a.resolved_at.cmp(&b.resolved_at));
            let remove_incidents = (to_remove - removed).min(self.resolved_incidents.len() / 2);
            self.resolved_incidents.drain(0..remove_incidents);
            removed += remove_incidents;
        }

        self.last_updated = Utc::now();
        warn!("Enforced entry cap: removed {} low-value entries", removed);
    }

    // ========================================================================
    // Persistence
    // ========================================================================

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.storage_path.parent() {
            fs::create_dir_all(parent)
                .context("Failed to create knowledge base storage directory")?;
        }

        let json =
            serde_json::to_string_pretty(self).context("Failed to serialize knowledge base")?;

        fs::write(&self.storage_path, json).context("Failed to write knowledge base to disk")?;

        debug!("Saved knowledge base to {:?}", self.storage_path);
        Ok(())
    }

    pub fn load(&mut self) -> Result<()> {
        if !self.storage_path.exists() {
            info!("No existing knowledge base found, starting fresh");
            return Ok(());
        }

        let json = fs::read_to_string(&self.storage_path)
            .context("Failed to read knowledge base from disk")?;

        let loaded: SecurityKnowledgeBase =
            serde_json::from_str(&json).context("Failed to deserialize knowledge base")?;

        self.server_profiles = loaded.server_profiles;
        self.resolved_incidents = loaded.resolved_incidents;
        self.false_positives = loaded.false_positives;
        self.user_preferences = loaded.user_preferences;
        self.known_patterns = loaded.known_patterns;
        self.created_at = loaded.created_at;
        self.last_updated = loaded.last_updated;
        self.entry_count = loaded.entry_count;

        info!(
            "Loaded knowledge base from {:?} ({} entries)",
            self.storage_path, self.entry_count
        );
        Ok(())
    }

    // ========================================================================
    // Export/Import
    // ========================================================================

    pub fn export_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("Failed to export knowledge base to JSON")
    }

    pub fn import_json(&mut self, json: &str) -> Result<u32> {
        let imported: SecurityKnowledgeBase =
            serde_json::from_str(json).context("Failed to parse imported JSON")?;

        let mut count = 0;

        for (server, knowledge) in imported.server_profiles {
            if let std::collections::hash_map::Entry::Vacant(e) = self.server_profiles.entry(server)
            {
                e.insert(knowledge);
                count += 1;
            }
        }

        for fp in imported.false_positives {
            if !self.false_positives.iter().any(|existing| {
                existing.event_pattern == fp.event_pattern && existing.source == fp.source
            }) {
                self.false_positives.push(fp);
                count += 1;
            }
        }

        for pattern in imported.known_patterns {
            if !self
                .known_patterns
                .iter()
                .any(|p| p.pattern_name == pattern.pattern_name)
            {
                self.known_patterns.push(pattern);
                count += 1;
            }
        }

        for incident in imported.resolved_incidents {
            if !self.resolved_incidents.iter().any(|i| i.id == incident.id) {
                self.resolved_incidents.push(incident);
                count += 1;
            }
        }

        self.last_updated = Utc::now();
        self.entry_count += count as u64;

        info!("Imported {} new knowledge entries", count);
        Ok(count)
    }

    // ========================================================================
    // Viewer Data
    // ========================================================================

    pub fn get_server_summary(&self, server: &str) -> Option<ServerKnowledgeSummary> {
        self.server_profiles.get(server).map(|profile| {
            let false_positive_count = self
                .false_positives
                .iter()
                .filter(|fp| fp.event_pattern.contains(server))
                .count();

            let incident_count = self
                .resolved_incidents
                .iter()
                .filter(|inc| inc.server_name == server)
                .count();

            ServerKnowledgeSummary {
                server_name: server.to_string(),
                trust_level: profile.trust_level.clone(),
                trust_assessment: profile.trust_assessment.clone(),
                known_behaviors: profile.known_legitimate_behaviors.clone(),
                false_positive_count,
                investigation_count: profile.investigation_history.len(),
                incident_count,
                user_trust_signal_count: profile.user_trust_signals.len(),
                first_seen: profile.first_seen,
                last_seen: profile.last_seen,
            }
        })
    }

    pub fn get_knowledge_stats(&self) -> KnowledgeStats {
        let oldest_entry = self
            .server_profiles
            .values()
            .map(|p| p.first_seen)
            .min()
            .or_else(|| self.false_positives.iter().map(|fp| fp.recorded_at).min());

        let newest_entry = self
            .server_profiles
            .values()
            .map(|p| p.last_seen)
            .max()
            .or_else(|| self.false_positives.iter().map(|fp| fp.recorded_at).max());

        let storage_size_bytes = if self.storage_path.exists() {
            fs::metadata(&self.storage_path)
                .map(|m| m.len())
                .unwrap_or(0)
        } else {
            0
        };

        KnowledgeStats {
            total_entries: self.entry_count,
            server_count: self.server_profiles.len(),
            false_positive_count: self.false_positives.len(),
            learned_pattern_count: self.known_patterns.len(),
            resolved_incident_count: self.resolved_incidents.len(),
            storage_size_bytes,
            oldest_entry,
            newest_entry,
        }
    }

    // ========================================================================
    // Manual Knowledge Entry
    // ========================================================================

    pub fn add_manual_knowledge(&mut self, server: &str, knowledge_type: &str, content: &str) {
        match knowledge_type {
            "trust_assessment" => {
                self.update_server_knowledge(
                    server,
                    ServerKnowledgeUpdate {
                        trust_assessment: Some(content.to_string()),
                        ..Default::default()
                    },
                );
            }
            "legitimate_behavior" => {
                self.update_server_knowledge(
                    server,
                    ServerKnowledgeUpdate {
                        add_legitimate_behavior: Some(content.to_string()),
                        ..Default::default()
                    },
                );
            }
            "false_positive" => {
                self.add_false_positive(content, "Manually added", FPSource::ExplicitMark);
            }
            "note" => {
                self.update_server_knowledge(
                    server,
                    ServerKnowledgeUpdate {
                        add_note: Some(content.to_string()),
                        ..Default::default()
                    },
                );
            }
            "trust_level" => {
                self.add_trust_signal(
                    server,
                    TrustSignal {
                        signal_type: TrustSignalType::ManualTrustSet,
                        timestamp: Utc::now(),
                        context: content.to_string(),
                    },
                );
            }
            _ => {
                warn!("Unknown knowledge type: {}", knowledge_type);
            }
        }
    }
}

impl Default for SecurityKnowledgeBase {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Server Knowledge
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerKnowledge {
    pub server_name: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub trust_assessment: String,
    pub trust_level: TrustLevel,
    pub known_legitimate_behaviors: Vec<String>,
    pub known_false_positives: Vec<String>,
    pub investigation_history: Vec<Uuid>,
    pub user_trust_signals: Vec<TrustSignal>,
    pub notes: Vec<String>,
}

impl ServerKnowledge {
    fn new(server_name: &str) -> Self {
        Self {
            server_name: server_name.to_string(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            trust_assessment: String::new(),
            trust_level: TrustLevel::Unknown,
            known_legitimate_behaviors: Vec::new(),
            known_false_positives: Vec::new(),
            investigation_history: Vec::new(),
            user_trust_signals: Vec::new(),
            notes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    Unknown,
    Untrusted,
    Cautious,
    Trusted,
    FullyTrusted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSignal {
    pub signal_type: TrustSignalType,
    pub timestamp: DateTime<Utc>,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustSignalType {
    UserAllowedPrompt,
    UserBlockedPrompt,
    UserDismissedAlert,
    InvestigationClear,
    InvestigationThreat,
    ManualTrustSet,
}

#[derive(Debug, Clone, Default)]
pub struct ServerKnowledgeUpdate {
    pub trust_assessment: Option<String>,
    pub add_legitimate_behavior: Option<String>,
    pub add_false_positive: Option<String>,
    pub add_investigation: Option<Uuid>,
    pub add_note: Option<String>,
}

// ============================================================================
// False Positives
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveRecord {
    pub id: Uuid,
    pub event_pattern: String,
    pub reason: String,
    pub recorded_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub source: FPSource,
    pub hit_count: u32,
    pub last_hit: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FPSource {
    UserDismiss,
    InvestigationResult,
    ExplicitMark,
    AlertDismissal { alert_id: String },
}

// ============================================================================
// Resolved Incidents
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedIncident {
    pub id: Uuid,
    pub incident_type: String,
    pub server_name: String,
    pub summary: String,
    pub verdict: String,
    pub resolved_at: DateTime<Utc>,
    pub resolution: String,
    pub investigation_id: Option<Uuid>,
    pub lessons_learned: Vec<String>,
}

// ============================================================================
// Learned Patterns
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedPattern {
    pub id: Uuid,
    pub pattern_name: String,
    pub description: String,
    pub indicators: Vec<String>,
    pub learned_from: PatternSource,
    pub severity: String,
    pub confidence: f64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub hit_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternSource {
    Investigation { investigation_id: Uuid },
    ThreatHunt { hunt_id: Uuid },
    Scan { scan_id: String },
    Manual,
}

// ============================================================================
// User Preferences
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSecurityPreferences {
    pub prompt_response_patterns: HashMap<String, PromptPreference>,
    pub preferred_risk_tolerance: RiskTolerance,
    pub frequently_allowed_servers: Vec<String>,
    pub frequently_blocked_actions: Vec<String>,
    pub notification_preferences: NotificationPrefs,
}

impl Default for UserSecurityPreferences {
    fn default() -> Self {
        Self {
            prompt_response_patterns: HashMap::new(),
            preferred_risk_tolerance: RiskTolerance::Balanced,
            frequently_allowed_servers: Vec::new(),
            frequently_blocked_actions: Vec::new(),
            notification_preferences: NotificationPrefs::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RiskTolerance {
    Conservative,
    Balanced,
    Permissive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptPreference {
    pub pattern: String,
    pub usual_response: String,
    pub consistency: f64,
    pub sample_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationPrefs {
    pub prefers_quiet: bool,
    pub typical_active_hours: Option<(u8, u8)>,
    pub dismissed_notification_types: Vec<String>,
}

// ============================================================================
// Knowledge Query
// ============================================================================

#[derive(Debug, Clone)]
pub struct KnowledgeQuery {
    pub server_name: String,
    pub tool_name: Option<String>,
    pub target: Option<String>,
    pub event_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct KnowledgeVerdict {
    pub classification: KnowledgeClassification,
    pub confidence: f64,
    pub reason: String,
    pub source_entry_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum KnowledgeClassification {
    KnownFalsePositive,
    KnownAttackPattern,
    TrustedServer,
    UntrustedServer,
    NoKnowledge,
}

// ============================================================================
// Support Types
// ============================================================================

#[derive(Debug, Clone)]
pub struct KnowledgeConflict {
    pub server_name: String,
    pub conflict_type: String,
    pub description: String,
    pub entries: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ServerKnowledgeSummary {
    pub server_name: String,
    pub trust_level: TrustLevel,
    pub trust_assessment: String,
    pub known_behaviors: Vec<String>,
    pub false_positive_count: usize,
    pub investigation_count: usize,
    pub incident_count: usize,
    pub user_trust_signal_count: usize,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct KnowledgeStats {
    pub total_entries: u64,
    pub server_count: usize,
    pub false_positive_count: usize,
    pub learned_pattern_count: usize,
    pub resolved_incident_count: usize,
    pub storage_size_bytes: u64,
    pub oldest_entry: Option<DateTime<Utc>>,
    pub newest_entry: Option<DateTime<Utc>>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn temp_kb_path() -> PathBuf {
        env::temp_dir().join(format!("test_kb_{}.json", Uuid::new_v4()))
    }

    #[test]
    fn test_create_and_retrieve_server_knowledge() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.update_server_knowledge(
            "prod-web-01",
            ServerKnowledgeUpdate {
                trust_assessment: Some("Safe web server".to_string()),
                ..Default::default()
            },
        );

        let knowledge = kb.get_server_knowledge("prod-web-01");
        assert!(knowledge.is_some());
        assert_eq!(knowledge.unwrap().server_name, "prod-web-01");
        assert_eq!(knowledge.unwrap().trust_assessment, "Safe web server");
    }

    #[test]
    fn test_trust_level_calculation_no_signals() {
        let signals = vec![];
        assert_eq!(
            SecurityKnowledgeBase::calculate_trust_level(&signals),
            TrustLevel::Unknown
        );
    }

    #[test]
    fn test_trust_level_calculation_more_blocks() {
        let signals = vec![
            TrustSignal {
                signal_type: TrustSignalType::UserBlockedPrompt,
                timestamp: Utc::now(),
                context: "test".to_string(),
            },
            TrustSignal {
                signal_type: TrustSignalType::UserBlockedPrompt,
                timestamp: Utc::now(),
                context: "test".to_string(),
            },
            TrustSignal {
                signal_type: TrustSignalType::UserAllowedPrompt,
                timestamp: Utc::now(),
                context: "test".to_string(),
            },
        ];
        assert_eq!(
            SecurityKnowledgeBase::calculate_trust_level(&signals),
            TrustLevel::Untrusted
        );
    }

    #[test]
    fn test_trust_level_calculation_cautious() {
        let signals = vec![
            TrustSignal {
                signal_type: TrustSignalType::UserAllowedPrompt,
                timestamp: Utc::now(),
                context: "test".to_string(),
            },
            TrustSignal {
                signal_type: TrustSignalType::UserAllowedPrompt,
                timestamp: Utc::now(),
                context: "test".to_string(),
            },
        ];
        assert_eq!(
            SecurityKnowledgeBase::calculate_trust_level(&signals),
            TrustLevel::Cautious
        );
    }

    #[test]
    fn test_trust_level_calculation_trusted() {
        let mut signals = vec![];
        for _ in 0..10 {
            signals.push(TrustSignal {
                signal_type: TrustSignalType::UserAllowedPrompt,
                timestamp: Utc::now(),
                context: "test".to_string(),
            });
        }
        assert_eq!(
            SecurityKnowledgeBase::calculate_trust_level(&signals),
            TrustLevel::Trusted
        );
    }

    #[test]
    fn test_trust_level_manual_override() {
        let signals = vec![TrustSignal {
            signal_type: TrustSignalType::ManualTrustSet,
            timestamp: Utc::now(),
            context: "fully_trusted".to_string(),
        }];
        assert_eq!(
            SecurityKnowledgeBase::calculate_trust_level(&signals),
            TrustLevel::FullyTrusted
        );
    }

    #[test]
    fn test_trust_level_threat_overrides() {
        let signals = vec![
            TrustSignal {
                signal_type: TrustSignalType::InvestigationThreat,
                timestamp: Utc::now(),
                context: "threat found".to_string(),
            },
            TrustSignal {
                signal_type: TrustSignalType::UserAllowedPrompt,
                timestamp: Utc::now(),
                context: "test".to_string(),
            },
        ];
        assert_eq!(
            SecurityKnowledgeBase::calculate_trust_level(&signals),
            TrustLevel::Untrusted
        );
    }

    #[test]
    fn test_add_and_check_false_positive() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.add_false_positive("server=test tool=vim", "Safe editor", FPSource::UserDismiss);

        let result = kb.check_false_positive("server=test tool=vim");
        assert!(result.is_some());
        assert_eq!(result.unwrap().hit_count, 1);
    }

    #[test]
    fn test_false_positive_hit_count() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.add_false_positive("server=test tool=vim", "Safe editor", FPSource::UserDismiss);

        kb.check_false_positive("server=test tool=vim");
        kb.check_false_positive("server=test tool=vim");
        let result = kb.check_false_positive("server=test tool=vim");

        assert_eq!(result.unwrap().hit_count, 3);
    }

    #[test]
    fn test_false_positive_expiry() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        let mut fp = FalsePositiveRecord {
            id: Uuid::new_v4(),
            event_pattern: "old pattern".to_string(),
            reason: "test".to_string(),
            recorded_at: Utc::now() - Duration::days(100),
            expires_at: Utc::now() - Duration::days(10),
            source: FPSource::UserDismiss,
            hit_count: 0,
            last_hit: None,
        };

        kb.false_positives.push(fp.clone());

        fp.id = Uuid::new_v4();
        fp.event_pattern = "new pattern".to_string();
        fp.expires_at = Utc::now() + Duration::days(10);
        kb.false_positives.push(fp);

        let expired = kb.expire_old_entries();
        assert_eq!(expired, 1);
        assert_eq!(kb.false_positives.len(), 1);
    }

    #[test]
    fn test_add_and_match_learned_pattern() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        let pattern = LearnedPattern {
            id: Uuid::new_v4(),
            pattern_name: "SSH Key Theft".to_string(),
            description: "Accessing SSH keys".to_string(),
            indicators: vec!["target=~/.ssh/id_rsa".to_string()],
            learned_from: PatternSource::Manual,
            severity: "high".to_string(),
            confidence: 0.9,
            first_seen: Utc::now(),
            last_seen: None,
            hit_count: 0,
        };

        kb.add_pattern(pattern);

        let indicators = vec!["target=~/.ssh/id_rsa".to_string()];
        let matched = kb.check_pattern_match(&indicators);

        assert!(matched.is_some());
        assert_eq!(matched.unwrap().pattern_name, "SSH Key Theft");
        assert_eq!(matched.unwrap().hit_count, 1);
    }

    #[test]
    fn test_investigation_learning_false_positive() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        let inv_id = Uuid::new_v4();
        kb.learn_from_investigation(
            "test-server",
            "false positive - legitimate admin task",
            0.85,
            inv_id,
            "Admin was configuring SSH",
        );

        assert_eq!(kb.false_positives.len(), 1);
        assert!(kb.false_positives[0]
            .reason
            .contains("Investigation determined"));
    }

    #[test]
    fn test_investigation_learning_threat() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        let inv_id = Uuid::new_v4();
        kb.learn_from_investigation(
            "evil-server",
            "confirmed threat - data exfiltration",
            0.95,
            inv_id,
            "Stealing credentials",
        );

        assert_eq!(kb.known_patterns.len(), 1);
        assert_eq!(kb.known_patterns[0].severity, "high");
    }

    #[test]
    fn test_prompt_response_recording() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.record_prompt_response("server1", "vim", "/etc/passwd", "allow");
        kb.record_prompt_response("server1", "vim", "/etc/passwd", "allow");
        kb.record_prompt_response("server1", "vim", "/etc/passwd", "allow");

        let pattern = "server=server1 tool=vim target=/etc/passwd";
        let pref = kb.user_preferences.prompt_response_patterns.get(pattern);

        assert!(pref.is_some());
        assert_eq!(pref.unwrap().sample_count, 3);
        assert_eq!(pref.unwrap().usual_response, "allow");
        assert!(pref.unwrap().consistency > 0.99);
    }

    #[test]
    fn test_alert_dismissal_counting() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        let result = kb.record_alert_dismissal("server1", "pattern1", 1);
        assert!(result.is_none());

        let result = kb.record_alert_dismissal("server1", "pattern1", 3);
        assert!(result.is_some());
        assert!(result.unwrap().contains("3 times"));
    }

    #[test]
    fn test_alert_dismissal_auto_fp() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        let result = kb.record_alert_dismissal("server1", "pattern1", 5);
        assert!(result.is_some());
        assert!(result.unwrap().contains("Auto-added"));
        assert_eq!(kb.false_positives.len(), 1);
    }

    #[test]
    fn test_knowledge_query_false_positive_hit() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.add_false_positive(
            "server=test tool=vim target=/etc/hosts",
            "Safe edit",
            FPSource::UserDismiss,
        );

        let query = KnowledgeQuery {
            server_name: "test".to_string(),
            tool_name: Some("vim".to_string()),
            target: Some("/etc/hosts".to_string()),
            event_type: None,
        };

        let verdict = kb.query(&query);
        assert_eq!(
            verdict.classification,
            KnowledgeClassification::KnownFalsePositive
        );
    }

    #[test]
    fn test_knowledge_query_attack_pattern() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        let pattern = LearnedPattern {
            id: Uuid::new_v4(),
            pattern_name: "Credential Theft".to_string(),
            description: "Stealing passwords".to_string(),
            indicators: vec!["server=evil".to_string(), "tool=cat".to_string()],
            learned_from: PatternSource::Manual,
            severity: "critical".to_string(),
            confidence: 0.95,
            first_seen: Utc::now(),
            last_seen: None,
            hit_count: 0,
        };

        kb.add_pattern(pattern);

        let query = KnowledgeQuery {
            server_name: "evil".to_string(),
            tool_name: Some("cat".to_string()),
            target: None,
            event_type: None,
        };

        let verdict = kb.query(&query);
        assert_eq!(
            verdict.classification,
            KnowledgeClassification::KnownAttackPattern
        );
    }

    #[test]
    fn test_knowledge_query_trusted_server() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.add_trust_signal(
            "trusted-server",
            TrustSignal {
                signal_type: TrustSignalType::ManualTrustSet,
                timestamp: Utc::now(),
                context: "fully_trusted".to_string(),
            },
        );

        let query = KnowledgeQuery {
            server_name: "trusted-server".to_string(),
            tool_name: None,
            target: None,
            event_type: None,
        };

        let verdict = kb.query(&query);
        assert_eq!(
            verdict.classification,
            KnowledgeClassification::TrustedServer
        );
    }

    #[test]
    fn test_knowledge_query_untrusted_server() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.add_trust_signal(
            "bad-server",
            TrustSignal {
                signal_type: TrustSignalType::InvestigationThreat,
                timestamp: Utc::now(),
                context: "threat detected".to_string(),
            },
        );

        let query = KnowledgeQuery {
            server_name: "bad-server".to_string(),
            tool_name: None,
            target: None,
            event_type: None,
        };

        let verdict = kb.query(&query);
        assert_eq!(
            verdict.classification,
            KnowledgeClassification::UntrustedServer
        );
    }

    #[test]
    fn test_knowledge_query_no_knowledge() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        let query = KnowledgeQuery {
            server_name: "unknown-server".to_string(),
            tool_name: None,
            target: None,
            event_type: None,
        };

        let verdict = kb.query(&query);
        assert_eq!(verdict.classification, KnowledgeClassification::NoKnowledge);
    }

    #[test]
    fn test_conflict_detection() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.update_server_knowledge(
            "mixed-server",
            ServerKnowledgeUpdate {
                trust_assessment: Some("unclear".to_string()),
                ..Default::default()
            },
        );

        for _ in 0..6 {
            kb.add_false_positive("server=mixed-server pattern=X", "fp", FPSource::UserDismiss);
        }

        for _ in 0..3 {
            kb.add_resolved_incident(ResolvedIncident {
                id: Uuid::new_v4(),
                incident_type: "breach".to_string(),
                server_name: "mixed-server".to_string(),
                summary: "bad".to_string(),
                verdict: "confirmed threat".to_string(),
                resolved_at: Utc::now(),
                resolution: "blocked".to_string(),
                investigation_id: None,
                lessons_learned: vec![],
            });
        }

        let conflicts = kb.resolve_conflicts();
        assert!(!conflicts.is_empty());
        assert_eq!(conflicts[0].conflict_type, "high_fp_and_threats");
    }

    #[test]
    fn test_entry_count_cap() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        for i in 0..1200 {
            kb.add_pattern(LearnedPattern {
                id: Uuid::new_v4(),
                pattern_name: format!("Pattern {}", i),
                description: "test".to_string(),
                indicators: vec![],
                learned_from: PatternSource::Manual,
                severity: "low".to_string(),
                confidence: 0.1,
                first_seen: Utc::now(),
                last_seen: None,
                hit_count: 0,
            });
        }

        kb.enforce_cap();

        let total = kb.server_profiles.len()
            + kb.false_positives.len()
            + kb.known_patterns.len()
            + kb.resolved_incidents.len();

        assert!(total <= 1000);
    }

    #[test]
    fn test_save_and_load() {
        let path = temp_kb_path();
        let mut kb = SecurityKnowledgeBase::with_path(path.clone());

        kb.add_false_positive("test pattern", "test reason", FPSource::UserDismiss);
        kb.update_server_knowledge(
            "test-server",
            ServerKnowledgeUpdate {
                trust_assessment: Some("safe".to_string()),
                ..Default::default()
            },
        );

        kb.save().unwrap();

        let mut kb2 = SecurityKnowledgeBase::with_path(path.clone());
        kb2.load().unwrap();

        assert_eq!(kb2.false_positives.len(), 1);
        assert_eq!(kb2.server_profiles.len(), 1);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_export_import() {
        let mut kb1 = SecurityKnowledgeBase::with_path(temp_kb_path());
        kb1.add_false_positive("pattern1", "reason1", FPSource::UserDismiss);

        let json = kb1.export_json().unwrap();

        let mut kb2 = SecurityKnowledgeBase::with_path(temp_kb_path());
        let count = kb2.import_json(&json).unwrap();

        assert_eq!(count, 1);
        assert_eq!(kb2.false_positives.len(), 1);
    }

    #[test]
    fn test_forget_server() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.update_server_knowledge(
            "test-server",
            ServerKnowledgeUpdate {
                trust_assessment: Some("test".to_string()),
                ..Default::default()
            },
        );

        kb.add_false_positive(
            "server=test-server pattern=X",
            "test",
            FPSource::UserDismiss,
        );

        kb.forget_server("test-server");

        assert!(!kb.server_profiles.contains_key("test-server"));
        assert_eq!(kb.false_positives.len(), 0);
    }

    #[test]
    fn test_server_knowledge_summary() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.update_server_knowledge(
            "summary-test",
            ServerKnowledgeUpdate {
                trust_assessment: Some("trusted".to_string()),
                add_legitimate_behavior: Some("normal activity".to_string()),
                ..Default::default()
            },
        );

        kb.add_false_positive(
            "server=summary-test pattern=X",
            "test",
            FPSource::UserDismiss,
        );

        let summary = kb.get_server_summary("summary-test");
        assert!(summary.is_some());

        let s = summary.unwrap();
        assert_eq!(s.server_name, "summary-test");
        assert_eq!(s.false_positive_count, 1);
        assert_eq!(s.known_behaviors.len(), 1);
    }

    #[test]
    fn test_stats_calculation() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.update_server_knowledge(
            "stats-test",
            ServerKnowledgeUpdate {
                trust_assessment: Some("test".to_string()),
                ..Default::default()
            },
        );

        kb.add_false_positive("pattern", "reason", FPSource::UserDismiss);

        let stats = kb.get_knowledge_stats();
        assert_eq!(stats.server_count, 1);
        assert_eq!(stats.false_positive_count, 1);
    }

    #[test]
    fn test_manual_knowledge_entry() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.add_manual_knowledge("manual-server", "trust_assessment", "manually trusted");

        let knowledge = kb.get_server_knowledge("manual-server");
        assert!(knowledge.is_some());
        assert_eq!(knowledge.unwrap().trust_assessment, "manually trusted");
    }

    #[test]
    fn test_trust_signal_addition() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.add_trust_signal(
            "signal-test",
            TrustSignal {
                signal_type: TrustSignalType::UserAllowedPrompt,
                timestamp: Utc::now(),
                context: "test signal".to_string(),
            },
        );

        let knowledge = kb.get_server_knowledge("signal-test");
        assert!(knowledge.is_some());
        assert_eq!(knowledge.unwrap().user_trust_signals.len(), 1);
    }

    #[test]
    fn test_server_first_last_seen() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.update_server_knowledge(
            "time-test",
            ServerKnowledgeUpdate {
                trust_assessment: Some("test".to_string()),
                ..Default::default()
            },
        );

        let knowledge = kb.get_server_knowledge("time-test");
        assert!(knowledge.is_some());

        let k = knowledge.unwrap();
        assert!(k.first_seen <= k.last_seen);
    }

    #[test]
    fn test_resolved_incident_storage() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        let incident = ResolvedIncident {
            id: Uuid::new_v4(),
            incident_type: "breach".to_string(),
            server_name: "incident-server".to_string(),
            summary: "test incident".to_string(),
            verdict: "resolved".to_string(),
            resolved_at: Utc::now(),
            resolution: "blocked and contained".to_string(),
            investigation_id: Some(Uuid::new_v4()),
            lessons_learned: vec!["lesson 1".to_string()],
        };

        kb.add_resolved_incident(incident);

        let incidents = kb.get_server_incidents("incident-server");
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].incident_type, "breach");
    }

    #[test]
    fn test_user_preference_tracking() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.update_risk_tolerance(RiskTolerance::Conservative);

        let prefs = kb.get_user_preferences();
        assert_eq!(prefs.preferred_risk_tolerance, RiskTolerance::Conservative);
    }

    #[test]
    fn test_knowledge_accumulation_multiple_sources() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.add_manual_knowledge("multi-source", "trust_assessment", "initially safe");
        kb.record_prompt_response("multi-source", "ls", "/tmp", "allow");
        kb.add_trust_signal(
            "multi-source",
            TrustSignal {
                signal_type: TrustSignalType::InvestigationClear,
                timestamp: Utc::now(),
                context: "investigation cleared".to_string(),
            },
        );

        let knowledge = kb.get_server_knowledge("multi-source");
        assert!(knowledge.is_some());

        let k = knowledge.unwrap();
        assert_eq!(k.trust_assessment, "initially safe");
        assert!(k.user_trust_signals.len() >= 2);
    }

    #[test]
    fn test_empty_knowledge_base_queries() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        let query = KnowledgeQuery {
            server_name: "nonexistent".to_string(),
            tool_name: None,
            target: None,
            event_type: None,
        };

        let verdict = kb.query(&query);
        assert_eq!(verdict.classification, KnowledgeClassification::NoKnowledge);
        assert_eq!(verdict.confidence, 0.0);
    }

    #[test]
    fn test_list_known_servers() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.update_server_knowledge(
            "server1",
            ServerKnowledgeUpdate {
                trust_assessment: Some("test1".to_string()),
                ..Default::default()
            },
        );

        kb.update_server_knowledge(
            "server2",
            ServerKnowledgeUpdate {
                trust_assessment: Some("test2".to_string()),
                ..Default::default()
            },
        );

        let servers = kb.list_known_servers();
        assert_eq!(servers.len(), 2);
    }

    #[test]
    fn test_list_incidents_limit() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        for i in 0..10 {
            kb.add_resolved_incident(ResolvedIncident {
                id: Uuid::new_v4(),
                incident_type: format!("type{}", i),
                server_name: "test".to_string(),
                summary: format!("incident {}", i),
                verdict: "resolved".to_string(),
                resolved_at: Utc::now(),
                resolution: "done".to_string(),
                investigation_id: None,
                lessons_learned: vec![],
            });
        }

        let incidents = kb.list_incidents(5);
        assert_eq!(incidents.len(), 5);
    }

    #[test]
    fn test_remove_false_positive() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        kb.add_false_positive("pattern1", "reason1", FPSource::UserDismiss);
        let fp_id = kb.false_positives[0].id;

        kb.remove_false_positive(fp_id);
        assert_eq!(kb.false_positives.len(), 0);
    }

    #[test]
    fn test_remove_pattern() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        let pattern = LearnedPattern {
            id: Uuid::new_v4(),
            pattern_name: "Test Pattern".to_string(),
            description: "test".to_string(),
            indicators: vec![],
            learned_from: PatternSource::Manual,
            severity: "low".to_string(),
            confidence: 0.5,
            first_seen: Utc::now(),
            last_seen: None,
            hit_count: 0,
        };

        let pattern_id = pattern.id;
        kb.add_pattern(pattern);

        kb.remove_pattern(pattern_id);
        assert_eq!(kb.known_patterns.len(), 0);
    }

    #[test]
    fn test_get_entry_count() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        let initial = kb.get_entry_count();

        kb.add_false_positive("test", "test", FPSource::UserDismiss);

        assert!(kb.get_entry_count() > initial);
    }

    #[test]
    fn test_pattern_partial_match() {
        let mut kb = SecurityKnowledgeBase::with_path(temp_kb_path());

        let pattern = LearnedPattern {
            id: Uuid::new_v4(),
            pattern_name: "Multi-indicator".to_string(),
            description: "test".to_string(),
            indicators: vec![
                "indicator1".to_string(),
                "indicator2".to_string(),
                "indicator3".to_string(),
            ],
            learned_from: PatternSource::Manual,
            severity: "medium".to_string(),
            confidence: 0.8,
            first_seen: Utc::now(),
            last_seen: None,
            hit_count: 0,
        };

        kb.add_pattern(pattern);

        let indicators = vec!["indicator1".to_string(), "indicator2".to_string()];
        let matched = kb.check_pattern_match(&indicators);

        assert!(matched.is_some());
    }
}
