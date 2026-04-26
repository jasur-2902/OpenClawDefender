//! Dual AI backend manager: local SLM + cloud API coexisting independently.
//!
//! The `AiBackendManager` routes requests to the right backend based on task type:
//! - **Local SLM** (always-on, fast, private): triage, context updates, quick assessments
//! - **Cloud API** (on-demand, powerful): deep analysis, investigations, agent scans
//!
//! Cloud-preferred tasks fall back to local SLM when cloud is unavailable.

use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use tracing::warn;

use crate::engine::{SlmResponse, SlmStats};
use crate::task_router::{
    FeatureRoutingConfig, RateLimitStatus, RoutingDecision as TaskRoutingDecision,
    RoutingPreferences, TaskRouter,
};
use crate::SlmService;

/// Manages two independent AI backends: local SLM (always-on, fast)
/// and cloud API (on-demand, powerful).
pub struct AiBackendManager {
    local_backend: RwLock<Option<LocalBackendState>>,
    cloud_backend: RwLock<Option<CloudBackendState>>,
    router: TaskRouter,
}

#[derive(Debug, Clone)]
pub struct LocalBackendState {
    pub service: Arc<SlmService>,
    pub model_info: LocalModelInfo,
    pub status: BackendStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct LocalModelInfo {
    pub model_name: String,
    pub model_id: Option<String>,
    pub file_path: Option<String>,
    pub size_bytes: Option<u64>,
    pub using_gpu: bool,
}

#[derive(Debug, Clone)]
pub struct CloudBackendState {
    pub service: Arc<SlmService>,
    pub provider: String,
    pub model_name: String,
    pub api_key_configured: bool,
    pub status: BackendStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BackendStatus {
    Ready,
    Loading,
    Failed(String),
    Unloaded,
    Unconfigured,
    AuthFailed,
    RateLimited,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TaskType {
    // Local only (fast, free, private)
    Triage,
    ContextUpdate,
    AnomalyExplanation,
    EventNarrative,
    QuickRiskAssessment,
    SecurityTip,

    // Cloud preferred, local fallback
    DeepAnalysis,
    Investigation,
    ScanAnalysis,
    AskClaw,
    ReportGeneration,
    ThreatHunt,

    // Cloud only
    AgentScan,
    PlaybookExecution,
}

#[derive(Debug, Clone)]
pub struct AiRequest {
    pub task_type: TaskType,
    pub prompt: String,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiResponse {
    pub response: Option<SlmResponse>,
    pub backend_used: String,
    pub fallback_used: bool,
    pub message: Option<String>,
}

/// Combined status of both backends for the GUI.
#[derive(Debug, Clone, Serialize)]
pub struct AiStatus {
    pub local: LocalStatusInfo,
    pub cloud: CloudStatusInfo,
    pub routing: TaskRoutingInfo,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct LocalStatusInfo {
    pub active: bool,
    pub model_name: Option<String>,
    pub model_size: Option<u64>,
    pub gpu_enabled: bool,
    pub status: Option<BackendStatus>,
    pub total_inferences: u64,
    pub avg_latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct CloudStatusInfo {
    pub active: bool,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub key_configured: bool,
    pub status: Option<BackendStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskRoutingInfo {
    pub fast_tasks: String,
    pub deep_tasks: String,
}

/// Internal routing decision (legacy, retained for existing tests).
#[cfg(test)]
enum RoutingDecision {
    LocalOnly,
    CloudPreferred,
    CloudOnly,
}

impl AiBackendManager {
    pub fn new() -> Self {
        Self {
            local_backend: RwLock::new(None),
            cloud_backend: RwLock::new(None),
            router: TaskRouter::default(),
        }
    }

    /// Create a new manager with specific routing preferences.
    pub fn new_with_preferences(prefs: RoutingPreferences) -> Self {
        Self {
            local_backend: RwLock::new(None),
            cloud_backend: RwLock::new(None),
            router: TaskRouter::new(prefs),
        }
    }

    /// Set/replace the local backend (GGUF model).
    pub fn set_local(&self, service: Arc<SlmService>, info: LocalModelInfo) {
        let mut guard = self.local_backend.write().unwrap();
        *guard = Some(LocalBackendState {
            service,
            model_info: info,
            status: BackendStatus::Ready,
        });
    }

    /// Clear the local backend.
    pub fn clear_local(&self) {
        let mut guard = self.local_backend.write().unwrap();
        *guard = None;
    }

    /// Set/replace the cloud backend.
    pub fn set_cloud(&self, service: Arc<SlmService>, provider: String, model: String) {
        let mut guard = self.cloud_backend.write().unwrap();
        *guard = Some(CloudBackendState {
            service,
            provider,
            model_name: model,
            api_key_configured: true,
            status: BackendStatus::Ready,
        });
    }

    /// Clear the cloud backend.
    pub fn clear_cloud(&self) {
        let mut guard = self.cloud_backend.write().unwrap();
        *guard = None;
    }

    /// Route a request to the right backend based on task type, preferences, and availability.
    pub async fn analyze(&self, request: AiRequest) -> AiResponse {
        let local_up = self.local_available();
        let cloud_up = self.cloud_available();
        let decision = self.router.route(&request.task_type, local_up, cloud_up);

        match decision {
            TaskRoutingDecision::UseLocal => self.use_local(&request).await,
            TaskRoutingDecision::UseCloud => self.use_cloud_only(&request).await,
            TaskRoutingDecision::UseCloudWithLocalFallback => {
                self.router.record_cloud_call();
                self.use_cloud_or_local(&request).await
            }
            TaskRoutingDecision::UseLocalReduced => {
                let mut resp = self.use_local(&request).await;
                if resp.response.is_some() {
                    resp.message = Some(
                        "Using local model (reduced quality — cloud unavailable or rate-limited)"
                            .to_string(),
                    );
                }
                resp
            }
            TaskRoutingDecision::RequiresCloud => AiResponse {
                response: None,
                backend_used: "unavailable".to_string(),
                fallback_used: false,
                message: Some(
                    "This feature requires a cloud AI backend. Add an API key in Settings."
                        .to_string(),
                ),
            },
            TaskRoutingDecision::Unavailable(reason) => AiResponse {
                response: None,
                backend_used: "unavailable".to_string(),
                fallback_used: false,
                message: Some(reason),
            },
            TaskRoutingDecision::AwaitConfirmation => AiResponse {
                response: None,
                backend_used: "pending_confirmation".to_string(),
                fallback_used: false,
                message: Some("Cloud usage requires user confirmation".to_string()),
            },
        }
    }

    /// Classify a task type into a simple routing decision (legacy, used by tests).
    #[cfg(test)]
    fn classify_task(&self, task_type: &TaskType) -> RoutingDecision {
        match task_type {
            // Local only (fast, free, private)
            TaskType::Triage
            | TaskType::ContextUpdate
            | TaskType::AnomalyExplanation
            | TaskType::EventNarrative
            | TaskType::QuickRiskAssessment
            | TaskType::SecurityTip => RoutingDecision::LocalOnly,

            // Cloud preferred, local fallback
            TaskType::DeepAnalysis
            | TaskType::Investigation
            | TaskType::ScanAnalysis
            | TaskType::AskClaw
            | TaskType::ReportGeneration
            | TaskType::ThreatHunt => RoutingDecision::CloudPreferred,

            // Cloud only
            TaskType::AgentScan | TaskType::PlaybookExecution => RoutingDecision::CloudOnly,
        }
    }

    /// Always use local (fast path).
    async fn use_local(&self, request: &AiRequest) -> AiResponse {
        // Clone the Arc and drop the guard before awaiting to avoid Send issues.
        let service = {
            let guard = self.local_backend.read().unwrap();
            match &*guard {
                Some(state) if state.status == BackendStatus::Ready => {
                    Some(Arc::clone(&state.service))
                }
                _ => None,
            }
        };

        match service {
            Some(svc) => match svc.analyze_event(&request.prompt).await {
                Ok(resp) => AiResponse {
                    response: Some(resp),
                    backend_used: "local".to_string(),
                    fallback_used: false,
                    message: None,
                },
                Err(e) => {
                    warn!("Local backend inference failed: {}", e);
                    AiResponse {
                        response: None,
                        backend_used: "unavailable".to_string(),
                        fallback_used: false,
                        message: Some(format!("Local inference failed: {}", e)),
                    }
                }
            },
            None => AiResponse {
                response: None,
                backend_used: "unavailable".to_string(),
                fallback_used: false,
                message: Some("No local model loaded".to_string()),
            },
        }
    }

    /// Try cloud first, fall back to local.
    async fn use_cloud_or_local(&self, request: &AiRequest) -> AiResponse {
        // Clone Arcs and drop guards before awaiting to avoid Send issues.
        let cloud_svc = {
            let guard = self.cloud_backend.read().unwrap();
            guard
                .as_ref()
                .filter(|s| s.status == BackendStatus::Ready)
                .map(|s| Arc::clone(&s.service))
        };

        // Try cloud first
        if let Some(svc) = cloud_svc {
            match svc.analyze_event(&request.prompt).await {
                Ok(resp) => {
                    return AiResponse {
                        response: Some(resp),
                        backend_used: "cloud".to_string(),
                        fallback_used: false,
                        message: None,
                    };
                }
                Err(e) => {
                    warn!("Cloud backend failed, falling back to local: {}", e);
                }
            }
        }

        // Fall back to local
        let local_svc = {
            let guard = self.local_backend.read().unwrap();
            guard
                .as_ref()
                .filter(|s| s.status == BackendStatus::Ready)
                .map(|s| Arc::clone(&s.service))
        };

        match local_svc {
            Some(svc) => match svc.analyze_event(&request.prompt).await {
                Ok(resp) => AiResponse {
                    response: Some(resp),
                    backend_used: "local".to_string(),
                    fallback_used: true,
                    message: Some("Cloud unavailable, used local model".to_string()),
                },
                Err(e) => {
                    warn!("Local fallback also failed: {}", e);
                    AiResponse {
                        response: None,
                        backend_used: "unavailable".to_string(),
                        fallback_used: true,
                        message: Some(format!("Both cloud and local backends failed: {}", e)),
                    }
                }
            },
            None => AiResponse {
                response: None,
                backend_used: "unavailable".to_string(),
                fallback_used: true,
                message: Some("Cloud failed and no local model available".to_string()),
            },
        }
    }

    /// Cloud only -- return unavailable if cloud is not configured.
    async fn use_cloud_only(&self, request: &AiRequest) -> AiResponse {
        // Clone the Arc and drop the guard before awaiting to avoid Send issues.
        let service = {
            let guard = self.cloud_backend.read().unwrap();
            match &*guard {
                Some(state) if state.status == BackendStatus::Ready => {
                    Some(Arc::clone(&state.service))
                }
                _ => None,
            }
        };

        match service {
            Some(svc) => match svc.analyze_event(&request.prompt).await {
                Ok(resp) => AiResponse {
                    response: Some(resp),
                    backend_used: "cloud".to_string(),
                    fallback_used: false,
                    message: None,
                },
                Err(e) => {
                    warn!("Cloud-only inference failed: {}", e);
                    AiResponse {
                        response: None,
                        backend_used: "unavailable".to_string(),
                        fallback_used: false,
                        message: Some(format!("Cloud inference failed: {}", e)),
                    }
                }
            },
            None => AiResponse {
                response: None,
                backend_used: "unavailable".to_string(),
                fallback_used: false,
                message: Some("Cloud API not configured. Add an API key in Settings.".to_string()),
            },
        }
    }

    /// Get combined status of both backends.
    pub fn get_status(&self) -> AiStatus {
        let local_guard = self.local_backend.read().unwrap();
        let cloud_guard = self.cloud_backend.read().unwrap();

        let local = match &*local_guard {
            Some(state) => {
                let stats = state.service.stats();
                LocalStatusInfo {
                    active: state.status == BackendStatus::Ready && state.service.is_enabled(),
                    model_name: Some(state.model_info.model_name.clone()),
                    model_size: state.model_info.size_bytes,
                    gpu_enabled: state.model_info.using_gpu,
                    status: Some(state.status.clone()),
                    total_inferences: stats.as_ref().map(|s| s.total_inferences).unwrap_or(0),
                    avg_latency_ms: stats.as_ref().map(|s| s.avg_latency_ms).unwrap_or(0.0),
                }
            }
            None => LocalStatusInfo::default(),
        };

        let cloud = match &*cloud_guard {
            Some(state) => CloudStatusInfo {
                active: state.status == BackendStatus::Ready,
                provider: Some(state.provider.clone()),
                model: Some(state.model_name.clone()),
                key_configured: state.api_key_configured,
                status: Some(state.status.clone()),
            },
            None => CloudStatusInfo::default(),
        };

        let fast_tasks = if local.active {
            "Local SLM".to_string()
        } else {
            "Unavailable".to_string()
        };
        let deep_tasks = if cloud.active {
            "Cloud API".to_string()
        } else if local.active {
            "Local SLM (fallback)".to_string()
        } else {
            "Unavailable".to_string()
        };

        AiStatus {
            local,
            cloud,
            routing: TaskRoutingInfo {
                fast_tasks,
                deep_tasks,
            },
        }
    }

    /// Check if local backend is available.
    pub fn local_available(&self) -> bool {
        let guard = self.local_backend.read().unwrap();
        guard
            .as_ref()
            .map(|s| s.status == BackendStatus::Ready && s.service.is_enabled())
            .unwrap_or(false)
    }

    /// Check if cloud backend is available.
    pub fn cloud_available(&self) -> bool {
        let guard = self.cloud_backend.read().unwrap();
        guard
            .as_ref()
            .map(|s| s.status == BackendStatus::Ready)
            .unwrap_or(false)
    }

    /// Get local backend stats (for ActiveModelInfo).
    pub fn local_stats(&self) -> Option<SlmStats> {
        let guard = self.local_backend.read().unwrap();
        guard.as_ref().and_then(|s| s.service.stats())
    }

    /// Get a reference to the local SlmService (for direct use by daemon triage).
    pub fn local_service(&self) -> Option<Arc<SlmService>> {
        let guard = self.local_backend.read().unwrap();
        guard.as_ref().map(|s| Arc::clone(&s.service))
    }

    /// Get a reference to the cloud SlmService.
    pub fn cloud_service(&self) -> Option<Arc<SlmService>> {
        let guard = self.cloud_backend.read().unwrap();
        guard.as_ref().map(|s| Arc::clone(&s.service))
    }

    /// Get local model info.
    pub fn local_model_info(&self) -> Option<LocalModelInfo> {
        let guard = self.local_backend.read().unwrap();
        guard.as_ref().map(|s| s.model_info.clone())
    }

    /// Get cloud backend provider and model name.
    pub fn cloud_info(&self) -> Option<(String, String)> {
        let guard = self.cloud_backend.read().unwrap();
        guard
            .as_ref()
            .map(|s| (s.provider.clone(), s.model_name.clone()))
    }

    /// Update routing preferences.
    pub fn update_routing_preferences(&self, prefs: RoutingPreferences) {
        self.router.update_preferences(prefs);
    }

    /// Get current routing preferences.
    pub fn get_routing_preferences(&self) -> RoutingPreferences {
        self.router.get_preferences()
    }

    /// Get rate limit status for cloud calls.
    pub fn get_rate_limit_status(&self) -> RateLimitStatus {
        self.router.rate_limit_status()
    }

    /// Update per-feature routing configuration.
    pub fn update_feature_routing(&self, config: FeatureRoutingConfig) {
        self.router.update_feature_routing(config);
    }

    /// Get current per-feature routing configuration.
    pub fn get_feature_routing(&self) -> FeatureRoutingConfig {
        self.router.get_feature_routing()
    }
}

impl Default for AiBackendManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{MockSlmBackend, SlmConfig, SlmEngine};

    fn mock_service() -> Arc<SlmService> {
        let backend = Box::new(MockSlmBackend::default());
        let config = SlmConfig::default();
        let engine = Arc::new(SlmEngine::new(backend, config.clone()));
        Arc::new(SlmService::with_engine(engine, config))
    }

    fn mock_local_info() -> LocalModelInfo {
        LocalModelInfo {
            model_name: "test-model".to_string(),
            model_id: Some("test-id".to_string()),
            file_path: Some("/tmp/test.gguf".to_string()),
            size_bytes: Some(1_000_000),
            using_gpu: false,
        }
    }

    #[test]
    fn new_manager_has_no_backends() {
        let mgr = AiBackendManager::new();
        assert!(!mgr.local_available());
        assert!(!mgr.cloud_available());
    }

    #[test]
    fn set_and_clear_local() {
        let mgr = AiBackendManager::new();
        let svc = mock_service();
        mgr.set_local(svc, mock_local_info());
        assert!(mgr.local_available());

        mgr.clear_local();
        assert!(!mgr.local_available());
    }

    #[test]
    fn set_and_clear_cloud() {
        let mgr = AiBackendManager::new();
        let svc = mock_service();
        mgr.set_cloud(svc, "anthropic".to_string(), "claude-sonnet".to_string());
        assert!(mgr.cloud_available());

        mgr.clear_cloud();
        assert!(!mgr.cloud_available());
    }

    #[tokio::test]
    async fn analyze_local_only_task() {
        let mgr = AiBackendManager::new();
        let svc = mock_service();
        mgr.set_local(svc, mock_local_info());

        let resp = mgr
            .analyze(AiRequest {
                task_type: TaskType::Triage,
                prompt: "test prompt".to_string(),
                context: None,
            })
            .await;
        assert_eq!(resp.backend_used, "local");
        assert!(!resp.fallback_used);
        assert!(resp.response.is_some());
    }

    #[tokio::test]
    async fn analyze_cloud_preferred_falls_back_to_local() {
        let mgr = AiBackendManager::new();
        // Only local available, no cloud
        let svc = mock_service();
        mgr.set_local(svc, mock_local_info());

        let resp = mgr
            .analyze(AiRequest {
                task_type: TaskType::DeepAnalysis,
                prompt: "deep analysis test".to_string(),
                context: None,
            })
            .await;
        assert_eq!(resp.backend_used, "local");
        // TaskRouter routes DeepAnalysis with local-only as UseLocalReduced
        assert!(!resp.fallback_used);
        assert!(resp.response.is_some());
        assert!(resp.message.unwrap().contains("reduced quality"));
    }

    #[tokio::test]
    async fn analyze_cloud_only_unavailable() {
        let mgr = AiBackendManager::new();
        // No cloud configured
        let resp = mgr
            .analyze(AiRequest {
                task_type: TaskType::AgentScan,
                prompt: "agent scan".to_string(),
                context: None,
            })
            .await;
        assert_eq!(resp.backend_used, "unavailable");
        assert!(resp.response.is_none());
        assert!(resp.message.is_some());
    }

    #[test]
    fn get_status_both_backends() {
        let mgr = AiBackendManager::new();
        let local_svc = mock_service();
        let cloud_svc = mock_service();

        mgr.set_local(local_svc, mock_local_info());
        mgr.set_cloud(
            cloud_svc,
            "anthropic".to_string(),
            "claude-sonnet".to_string(),
        );

        let status = mgr.get_status();
        assert!(status.local.active);
        assert!(status.cloud.active);
        assert_eq!(status.routing.fast_tasks, "Local SLM");
        assert_eq!(status.routing.deep_tasks, "Cloud API");
    }

    #[test]
    fn get_status_no_backends() {
        let mgr = AiBackendManager::new();
        let status = mgr.get_status();
        assert!(!status.local.active);
        assert!(!status.cloud.active);
        assert_eq!(status.routing.fast_tasks, "Unavailable");
        assert_eq!(status.routing.deep_tasks, "Unavailable");
    }

    #[tokio::test]
    async fn local_stats_returns_data() {
        let mgr = AiBackendManager::new();
        let svc = mock_service();
        mgr.set_local(svc.clone(), mock_local_info());

        // Run an inference to generate stats
        svc.analyze_event("test").await.unwrap();
        let stats = mgr.local_stats();
        assert!(stats.is_some());
        assert_eq!(stats.unwrap().total_inferences, 1);
    }

    #[test]
    fn local_service_returns_arc() {
        let mgr = AiBackendManager::new();
        assert!(mgr.local_service().is_none());

        let svc = mock_service();
        mgr.set_local(svc, mock_local_info());
        assert!(mgr.local_service().is_some());
    }

    #[test]
    fn cloud_service_returns_arc() {
        let mgr = AiBackendManager::new();
        assert!(mgr.cloud_service().is_none());

        let svc = mock_service();
        mgr.set_cloud(svc, "openai".to_string(), "gpt-4o".to_string());
        assert!(mgr.cloud_service().is_some());
    }

    #[test]
    fn classify_task_routing() {
        let mgr = AiBackendManager::new();

        // Verify local-only tasks
        assert!(matches!(
            mgr.classify_task(&TaskType::Triage),
            RoutingDecision::LocalOnly
        ));
        assert!(matches!(
            mgr.classify_task(&TaskType::SecurityTip),
            RoutingDecision::LocalOnly
        ));

        // Verify cloud-preferred tasks
        assert!(matches!(
            mgr.classify_task(&TaskType::DeepAnalysis),
            RoutingDecision::CloudPreferred
        ));
        assert!(matches!(
            mgr.classify_task(&TaskType::AskClaw),
            RoutingDecision::CloudPreferred
        ));

        // Verify cloud-only tasks
        assert!(matches!(
            mgr.classify_task(&TaskType::AgentScan),
            RoutingDecision::CloudOnly
        ));
        assert!(matches!(
            mgr.classify_task(&TaskType::PlaybookExecution),
            RoutingDecision::CloudOnly
        ));
    }
}
