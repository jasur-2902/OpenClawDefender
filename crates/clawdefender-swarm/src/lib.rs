//! Multi-agent swarm coordination for RookBot.

pub mod audit_hasher;
pub mod chat;
pub mod chat_server;
pub mod commander;
pub mod cost;
pub mod data_minimizer;
pub mod keychain;
pub mod llm_client;
pub mod output_sanitizer;
pub mod prompts;

pub use commander::SwarmVerdict;

// Phase 1-2: Cloud, agent sessions, privacy
pub mod agent_session;
pub mod cloud_api;
pub mod context_bridge;
pub mod privacy;
pub mod tool_sandbox;
pub mod tools;

// Phase 3: AI scan orchestrator
pub mod evidence;
pub mod remediation;
pub mod report_generator;
pub mod scan_orchestrator;
pub mod scan_playbooks;
pub mod scan_tools;

// Phase 4: Investigation & Threat Hunting
pub mod ask_claw_ai;
pub mod investigation_engine;
pub mod investigation_store;
pub mod investigation_timeline;
pub mod investigation_tools;
pub mod threat_hunting;

// Phase 5: Proactive Security Agent
pub mod adaptive_posture;
pub mod drift_detection;
pub mod knowledge_base;
pub mod scheduled_analysis;
pub mod smart_alerts;
pub mod threat_simulation;

// Phase 6: Agent Autonomy & Reporting
pub mod autonomy_framework;
pub mod data_portability;
pub mod feedback_calibration;
pub mod report_system;
pub mod response_playbooks;
pub mod transparency;
