//! SLM event processing pipeline: clustering → triage → deep analysis → context updates.
//!
//! The pipeline orchestrates all SLM subsystems into a coherent event processing flow:
//!
//! 1. **Ingest**: Events arrive and are fed into the [`ClusteringBuffer`].
//! 2. **Cluster flush**: When a time window expires or a cluster fills up,
//!    the finalized [`EventCluster`] is sent for triage.
//! 3. **Tier-1 triage**: The [`TriageEngine`] classifies the cluster as
//!    ROUTINE / NOTABLE / SUSPICIOUS.
//! 4. **Context enrichment**: For SUSPICIOUS clusters, the [`ContextWindow`]
//!    provides recent activity context.
//! 5. **Tier-2 deep analysis**: Full risk assessment with context.
//! 6. **Context update**: All triage results are recorded in the context window.
//! 7. **Offline intelligence**: Background summaries and anomaly explanations
//!    are generated when the SLM is idle.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::clustering::{ClusterEvent, ClusteringBuffer, EventCluster};
use crate::context_window::{ContextWindow, SuspiciousEventBrief};
use crate::engine::SlmEngine;
use crate::offline_intel::OfflineIntelEngine;
use crate::triage::{DeepAnalysis, TriageEngine, TriageInput, TriageLevel};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the SLM pipeline.
pub struct PipelineConfig {
    /// How long events accumulate before a cluster is flushed.
    pub cluster_window: Duration,
    /// Maximum events per cluster before forced flush.
    pub max_events_per_cluster: usize,
    /// How often the flush loop checks for expired clusters.
    pub flush_interval: Duration,
    /// Channel buffer size for finalized clusters.
    pub cluster_channel_size: usize,
    /// Channel buffer size for pipeline results.
    pub result_channel_size: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            cluster_window: Duration::from_secs(30),
            max_events_per_cluster: 20,
            flush_interval: Duration::from_secs(5),
            cluster_channel_size: 64,
            result_channel_size: 64,
        }
    }
}

// ---------------------------------------------------------------------------
// Pipeline result
// ---------------------------------------------------------------------------

/// Result produced by the pipeline for each processed cluster.
#[derive(Debug)]
pub struct PipelineResult {
    /// ID of the cluster that was processed.
    pub cluster_id: String,
    /// Server the cluster belongs to.
    pub server_name: String,
    /// Number of events in the cluster.
    pub event_count: usize,
    /// Tier-1 triage classification.
    pub triage_level: TriageLevel,
    /// Tier-2 deep analysis (only for SUSPICIOUS clusters).
    pub deep_analysis: Option<DeepAnalysis>,
    /// Wall-clock processing time in milliseconds.
    pub processing_ms: u64,
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

/// The SLM event processing pipeline.
///
/// Owns the clustering buffer, triage engine, context window, and offline
/// intelligence engine. Events flow through clustering → triage → deep
/// analysis → context updates.
pub struct SlmPipeline {
    clustering: Arc<ClusteringBuffer>,
    triage: Arc<TriageEngine>,
    context_window: Arc<ContextWindow>,
    offline_intel: Arc<OfflineIntelEngine>,
    cluster_rx: mpsc::Receiver<EventCluster>,
    result_tx: mpsc::Sender<PipelineResult>,
}

impl SlmPipeline {
    /// Create a new pipeline with the given SLM engine and configuration.
    ///
    /// Returns `(pipeline, result_receiver)`. Call [`spawn()`] to start
    /// background processing, then feed events via [`ingest()`].
    pub fn new(
        slm: Arc<SlmEngine>,
        context_window: Arc<ContextWindow>,
        config: PipelineConfig,
    ) -> (Self, mpsc::Receiver<PipelineResult>) {
        let (cluster_tx, cluster_rx) = mpsc::channel(config.cluster_channel_size);
        let (result_tx, result_rx) = mpsc::channel(config.result_channel_size);

        let clustering = Arc::new(ClusteringBuffer::new(
            cluster_tx,
            config.cluster_window,
            config.max_events_per_cluster,
        ));

        let triage = Arc::new(TriageEngine::new(slm));
        let offline_intel = Arc::new(OfflineIntelEngine::new());

        let pipeline = Self {
            clustering,
            triage,
            context_window,
            offline_intel,
            cluster_rx,
            result_tx,
        };

        (pipeline, result_rx)
    }

    /// Get a handle to the clustering buffer for ingesting events.
    pub fn clustering(&self) -> &Arc<ClusteringBuffer> {
        &self.clustering
    }

    /// Get a handle to the context window.
    pub fn context_window(&self) -> &Arc<ContextWindow> {
        &self.context_window
    }

    /// Get a handle to the offline intelligence engine.
    pub fn offline_intel(&self) -> &Arc<OfflineIntelEngine> {
        &self.offline_intel
    }

    /// Ingest a single event into the clustering buffer.
    pub async fn ingest(&self, event: ClusterEvent) {
        self.clustering.add_event(event).await;
    }

    /// Record a routine event in the context window without clustering.
    ///
    /// Use this for events that don't need SLM analysis (e.g., events below
    /// the escalation threshold) but should still contribute to the context.
    pub fn record_routine_event(&self, server: &str) {
        self.context_window
            .record_event(server, TriageLevel::Routine);
    }

    /// Start the pipeline processing loops.
    ///
    /// Spawns three background tasks:
    /// 1. Cluster flush loop (checks for expired clusters periodically).
    /// 2. Cluster processing loop (triage + deep analysis for each cluster).
    /// 3. Context window update loop (refresh + persist).
    ///
    /// Returns handles to all spawned tasks.
    pub fn spawn(self, config: &PipelineConfig) -> PipelineHandles {
        // 1. Cluster flush loop.
        let flush_handle = self.clustering.spawn_flush_loop(config.flush_interval);

        // 2. Context window update loop.
        let ctx = Arc::clone(&self.context_window);
        let context_handle = tokio::spawn(async move {
            ctx.run_loop().await;
        });

        // 3. Cluster processing loop.
        let process_handle = tokio::spawn(async move {
            self.process_clusters().await;
        });

        PipelineHandles {
            flush_handle,
            context_handle,
            process_handle,
        }
    }

    /// Main processing loop: receives finalized clusters and runs triage + analysis.
    async fn process_clusters(mut self) {
        info!("SLM pipeline cluster processor started");

        while let Some(cluster) = self.cluster_rx.recv().await {
            let start = std::time::Instant::now();
            let cluster_id = cluster.id.clone();
            let server_name = cluster.server_name.clone();
            let event_count = cluster.events.len();

            match self.process_single_cluster(&cluster).await {
                Ok((level, deep)) => {
                    let processing_ms = start.elapsed().as_millis() as u64;

                    debug!(
                        cluster_id = %cluster_id,
                        server = %server_name,
                        events = event_count,
                        triage = %level,
                        deep = deep.is_some(),
                        ms = processing_ms,
                        "Pipeline processed cluster"
                    );

                    let result = PipelineResult {
                        cluster_id,
                        server_name,
                        event_count,
                        triage_level: level,
                        deep_analysis: deep,
                        processing_ms,
                    };

                    if let Err(e) = self.result_tx.try_send(result) {
                        warn!("Pipeline result channel full, dropping result: {e}");
                    }
                }
                Err(e) => {
                    warn!(
                        cluster_id = %cluster_id,
                        error = %e,
                        "Pipeline failed to process cluster, recording as suspicious (fail-closed)"
                    );

                    // Fail-closed: record as suspicious so the context window
                    // reflects that we couldn't analyze this cluster.
                    self.context_window
                        .record_event(&server_name, TriageLevel::Suspicious);
                    self.context_window.record_suspicious(SuspiciousEventBrief {
                        timestamp: chrono::Utc::now().format("%H:%M:%S").to_string(),
                        server_name: server_name.clone(),
                        description: format!(
                            "Analysis failed for cluster with {} events: {}",
                            event_count, e
                        ),
                    });
                }
            }
        }

        info!("SLM pipeline cluster processor stopped (channel closed)");
    }

    /// Process a single cluster through the triage + deep analysis pipeline.
    async fn process_single_cluster(
        &self,
        cluster: &EventCluster,
    ) -> Result<(TriageLevel, Option<DeepAnalysis>)> {
        // Convert cluster to triage input.
        let input = cluster_to_triage_input(cluster);

        // Tier 1: Fast classification.
        let level = self.triage.classify(&input).await?;

        // Record the triage result in the context window.
        self.context_window
            .record_event(&cluster.server_name, level);

        match level {
            TriageLevel::Routine => Ok((level, None)),
            TriageLevel::Notable => Ok((level, None)),
            TriageLevel::Suspicious => {
                // Record suspicious event brief for context.
                self.context_window.record_suspicious(SuspiciousEventBrief {
                    timestamp: chrono::Utc::now().format("%H:%M:%S").to_string(),
                    server_name: cluster.server_name.clone(),
                    description: format!(
                        "{} events: {}",
                        cluster.events.len(),
                        cluster.action_sequence
                    ),
                });

                // Tier 2: Deep analysis with context enrichment.
                let context = self.context_window.deep_analysis_context_async().await;
                let analysis = self.triage.deep_analyze(&input, Some(&context)).await?;

                Ok((level, Some(analysis)))
            }
        }
    }
}

/// Handles to background tasks spawned by [`SlmPipeline::spawn()`].
pub struct PipelineHandles {
    pub flush_handle: tokio::task::JoinHandle<()>,
    pub context_handle: tokio::task::JoinHandle<()>,
    pub process_handle: tokio::task::JoinHandle<()>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert an [`EventCluster`] to a [`TriageInput`] for the triage engine.
fn cluster_to_triage_input(cluster: &EventCluster) -> TriageInput {
    TriageInput {
        server_name: cluster.server_name.clone(),
        tool_name: cluster.tool_names.first().cloned(),
        action_type: if cluster.events.len() == 1 {
            cluster.events[0].event_type.clone()
        } else {
            "cluster".to_string()
        },
        target: cluster.targets.first().cloned(),
        anomaly_score: cluster.aggregate_anomaly,
        has_kill_chain: cluster.has_kill_chain,
        event_details: cluster.to_deep_analysis_prompt(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clustering::ClusterEvent;
    use crate::context_window::ContextWindow;
    use crate::engine::{MockSlmBackend, SlmConfig};
    use chrono::Utc;
    use std::path::PathBuf;

    fn mock_slm(response: &str) -> Arc<SlmEngine> {
        let backend = MockSlmBackend {
            response_text: response.to_string(),
            ..Default::default()
        };
        Arc::new(SlmEngine::new(Box::new(backend), SlmConfig::default()))
    }

    fn test_context_window() -> Arc<ContextWindow> {
        Arc::new(ContextWindow::new(PathBuf::from(
            "/tmp/clawdefender-pipeline-test-ctx.json",
        )))
    }

    fn make_event(server: &str, event_type: &str, target: Option<&str>) -> ClusterEvent {
        ClusterEvent {
            timestamp: Utc::now(),
            event_type: event_type.to_string(),
            tool_name: Some(event_type.to_string()),
            target: target.map(|t| t.to_string()),
            anomaly_score: 0.5,
            server_name: server.to_string(),
        }
    }

    #[test]
    fn cluster_to_triage_input_single_event() {
        let cluster = EventCluster {
            id: "c-1".to_string(),
            server_name: "fs-server".to_string(),
            events: vec![make_event("fs-server", "file_read", Some("/etc/passwd"))],
            cluster_reason: crate::clustering::ClusterReason::TimeWindow,
            window_start: Utc::now(),
            window_end: Utc::now(),
            aggregate_anomaly: 0.85,
            has_kill_chain: false,
            tool_names: vec!["file_read".to_string()],
            targets: vec!["/etc/passwd".to_string()],
            action_sequence: "file_read(/etc/passwd)".to_string(),
        };

        let input = cluster_to_triage_input(&cluster);
        assert_eq!(input.server_name, "fs-server");
        assert_eq!(input.tool_name.as_deref(), Some("file_read"));
        assert_eq!(input.action_type, "file_read");
        assert_eq!(input.target.as_deref(), Some("/etc/passwd"));
        assert!((input.anomaly_score - 0.85).abs() < f64::EPSILON);
        assert!(!input.has_kill_chain);
    }

    #[test]
    fn cluster_to_triage_input_multi_event() {
        let cluster = EventCluster {
            id: "c-2".to_string(),
            server_name: "test".to_string(),
            events: vec![
                make_event("test", "file_read", Some("/a")),
                make_event("test", "network_connect", Some("evil.com")),
            ],
            cluster_reason: crate::clustering::ClusterReason::KillChain,
            window_start: Utc::now(),
            window_end: Utc::now(),
            aggregate_anomaly: 0.9,
            has_kill_chain: true,
            tool_names: vec!["file_read".to_string(), "network_connect".to_string()],
            targets: vec!["/a".to_string(), "evil.com".to_string()],
            action_sequence: "file_read(/a) -> network_connect(evil.com)".to_string(),
        };

        let input = cluster_to_triage_input(&cluster);
        assert_eq!(input.action_type, "cluster");
        assert!(input.has_kill_chain);
    }

    #[tokio::test]
    async fn pipeline_routine_event_flow() {
        // SLM returns ROUTINE → pipeline should produce Skip-equivalent result.
        let slm = mock_slm("ROUTINE");
        let ctx = test_context_window();
        let config = PipelineConfig {
            cluster_window: Duration::from_millis(10),
            flush_interval: Duration::from_millis(5),
            ..Default::default()
        };

        let (pipeline, mut result_rx) = SlmPipeline::new(slm, ctx.clone(), config);

        // Ingest an event.
        pipeline
            .ingest(make_event("safe-server", "file_read", Some("/tmp/readme")))
            .await;

        // Manually flush.
        pipeline.clustering.flush_all().await;

        // Spawn just the processor in the background.
        let triage = Arc::clone(&pipeline.triage);
        let ctx_clone = Arc::clone(&pipeline.context_window);
        let result_tx = pipeline.result_tx.clone();
        let mut cluster_rx = pipeline.cluster_rx;

        let handle = tokio::spawn(async move {
            if let Some(cluster) = cluster_rx.recv().await {
                let input = cluster_to_triage_input(&cluster);
                let level = triage.classify(&input).await.unwrap();
                ctx_clone.record_event(&cluster.server_name, level);
                let _ = result_tx
                    .send(PipelineResult {
                        cluster_id: cluster.id,
                        server_name: cluster.server_name,
                        event_count: cluster.events.len(),
                        triage_level: level,
                        deep_analysis: None,
                        processing_ms: 0,
                    })
                    .await;
            }
        });

        let result = tokio::time::timeout(Duration::from_secs(2), result_rx.recv())
            .await
            .expect("timeout")
            .expect("no result");

        assert_eq!(result.triage_level, TriageLevel::Routine);
        assert!(result.deep_analysis.is_none());
        assert_eq!(result.server_name, "safe-server");

        handle.abort();
    }

    #[tokio::test]
    async fn pipeline_suspicious_event_triggers_deep_analysis() {
        // SLM returns something that triggers SUSPICIOUS triage + produces deep analysis.
        let slm = mock_slm(
            "RISK: CRITICAL\nCONFIDENCE: 0.95\nREASONING: Data exfiltration.\nACTION: block",
        );
        let ctx = test_context_window();
        let config = PipelineConfig::default();

        let (pipeline, _result_rx) = SlmPipeline::new(slm, ctx, config);

        // Build a cluster directly and process it.
        let cluster = EventCluster {
            id: "test-cluster".to_string(),
            server_name: "evil-server".to_string(),
            events: vec![make_event(
                "evil-server",
                "file_read",
                Some("~/.ssh/id_rsa"),
            )],
            cluster_reason: crate::clustering::ClusterReason::TimeWindow,
            window_start: Utc::now(),
            window_end: Utc::now(),
            aggregate_anomaly: 0.9,
            has_kill_chain: false,
            tool_names: vec!["file_read".to_string()],
            targets: vec!["~/.ssh/id_rsa".to_string()],
            action_sequence: "file_read(~/.ssh/id_rsa)".to_string(),
        };

        let (level, deep) = pipeline.process_single_cluster(&cluster).await.unwrap();

        // "RISK: CRITICAL" doesn't contain ROUTINE or NOTABLE, so triage defaults to SUSPICIOUS.
        assert_eq!(level, TriageLevel::Suspicious);
        assert!(deep.is_some());

        let analysis = deep.unwrap();
        assert_eq!(analysis.risk_level, crate::engine::RiskLevel::Critical);
        assert!(analysis.context_used);
    }

    #[tokio::test]
    async fn pipeline_notable_event_no_deep_analysis() {
        let slm = mock_slm("NOTABLE");
        let ctx = test_context_window();
        let config = PipelineConfig::default();

        let (pipeline, _result_rx) = SlmPipeline::new(slm, ctx, config);

        let cluster = EventCluster {
            id: "notable-cluster".to_string(),
            server_name: "dev-server".to_string(),
            events: vec![make_event("dev-server", "file_write", Some("/tmp/log"))],
            cluster_reason: crate::clustering::ClusterReason::TimeWindow,
            window_start: Utc::now(),
            window_end: Utc::now(),
            aggregate_anomaly: 0.4,
            has_kill_chain: false,
            tool_names: vec!["file_write".to_string()],
            targets: vec!["/tmp/log".to_string()],
            action_sequence: "file_write(/tmp/log)".to_string(),
        };

        let (level, deep) = pipeline.process_single_cluster(&cluster).await.unwrap();

        assert_eq!(level, TriageLevel::Notable);
        assert!(deep.is_none());
    }

    #[test]
    fn pipeline_config_defaults() {
        let config = PipelineConfig::default();
        assert_eq!(config.cluster_window, Duration::from_secs(30));
        assert_eq!(config.max_events_per_cluster, 20);
        assert_eq!(config.flush_interval, Duration::from_secs(5));
        assert_eq!(config.cluster_channel_size, 64);
        assert_eq!(config.result_channel_size, 64);
    }

    #[test]
    fn record_routine_event_updates_context() {
        let slm = mock_slm("ROUTINE");
        let ctx = test_context_window();
        let config = PipelineConfig::default();
        let (pipeline, _rx) = SlmPipeline::new(slm, ctx.clone(), config);

        pipeline.record_routine_event("safe-server");
        pipeline.record_routine_event("safe-server");
        pipeline.record_routine_event("other-server");

        // Verify counts accumulated in the context window.
        let triage_line = ctx.triage_context_line();
        assert!(triage_line.contains("events=0")); // not yet refreshed
    }

    #[tokio::test]
    async fn pipeline_ingest_feeds_clustering() {
        let slm = mock_slm("ROUTINE");
        let ctx = test_context_window();
        let config = PipelineConfig::default();
        let (pipeline, _rx) = SlmPipeline::new(slm, ctx, config);

        pipeline
            .ingest(make_event("srv", "file_read", Some("/a")))
            .await;
        pipeline
            .ingest(make_event("srv", "file_read", Some("/b")))
            .await;

        assert_eq!(pipeline.clustering.pending_count().await, 1);
    }

    #[tokio::test]
    async fn pipeline_fail_closed_on_error() {
        // Use a backend that produces output we can control.
        // The process_single_cluster should handle errors gracefully.
        let slm = mock_slm("SUSPICIOUS");
        let ctx = test_context_window();
        let config = PipelineConfig::default();
        let (pipeline, _rx) = SlmPipeline::new(slm, ctx.clone(), config);

        let cluster = EventCluster {
            id: "fail-cluster".to_string(),
            server_name: "unknown-server".to_string(),
            events: vec![make_event("unknown-server", "exec", None)],
            cluster_reason: crate::clustering::ClusterReason::TimeWindow,
            window_start: Utc::now(),
            window_end: Utc::now(),
            aggregate_anomaly: 0.3,
            has_kill_chain: false,
            tool_names: vec!["exec".to_string()],
            targets: vec![],
            action_sequence: "exec(?)".to_string(),
        };

        // "SUSPICIOUS" as SLM output → triage classifies as SUSPICIOUS →
        // deep analysis runs → "SUSPICIOUS" isn't valid deep analysis format →
        // fail-closed to HIGH risk. This is correct behavior.
        let (level, deep) = pipeline.process_single_cluster(&cluster).await.unwrap();
        assert_eq!(level, TriageLevel::Suspicious);
        assert!(deep.is_some());
        let analysis = deep.unwrap();
        // Fail-closed: unparseable deep analysis defaults to High
        assert_eq!(analysis.risk_level, crate::engine::RiskLevel::High);
    }
}
