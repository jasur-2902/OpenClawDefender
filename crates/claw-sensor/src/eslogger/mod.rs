//! macOS Endpoint Security (eslogger) integration.
//!
//! Provides types, parsing, and process management for consuming events from
//! the macOS `eslogger` command-line tool.

pub mod parser;
pub mod process;
pub mod types;

pub use parser::parse_event;
pub use process::EsloggerManager;
pub use types::{EsloggerEvent, EsloggerProcess};
