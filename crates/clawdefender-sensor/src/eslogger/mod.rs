//! macOS Endpoint Security (eslogger) integration.
//!
//! Provides types, parsing, and process management for consuming events from
//! the macOS `eslogger` command-line tool.

pub mod filter;
pub mod parser;
pub mod process;
pub mod types;

pub use filter::EventPreFilter;
pub use parser::parse_event;
pub use process::EsloggerManager;
pub use types::{sanitize_path, EsloggerEvent, EsloggerProcess};
