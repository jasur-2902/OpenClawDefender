//! OS-level sensors for process and filesystem monitoring.
//!
//! This crate provides macOS-specific integrations for observing process and
//! filesystem activity via Endpoint Security (eslogger) and FSEvents.

pub mod eslogger;
pub mod fsevents;
pub mod proctree;

pub use eslogger::{parse_event, EsloggerEvent, EsloggerManager, EsloggerProcess};
pub use fsevents::{FsEvent, FsEventKind, FsWatcher};
pub use proctree::{AgentInfo, Confidence, ProcessInfo, ProcessTree};
