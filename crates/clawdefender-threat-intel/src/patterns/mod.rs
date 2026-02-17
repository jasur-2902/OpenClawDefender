//! Dynamic pattern and signature loading from the threat feed.
//!
//! This module provides:
//! - Kill chain pattern loading and merging (`killchain_loader`)
//! - Injection signature loading with multilingual support (`injection_loader`)
//! - Pre-seeded behavioral profile loading (`profile_seeder`)
//! - Pattern versioning and pinning (`types`)

pub mod injection_loader;
pub mod killchain_loader;
pub mod profile_seeder;
pub mod types;

#[cfg(test)]
mod tests;

// Re-export key types for convenience.
pub use injection_loader::{InjectionSignatureLoader, PatternEntry};
pub use killchain_loader::KillChainLoader;
pub use profile_seeder::{ProfileSeeder, SeededServerProfile};
pub use types::{
    DynamicAttackPattern, DynamicInjectionPattern, DynamicPatternStep, PatternSource,
    PatternVersion, PreSeededProfile, Severity, VersionTracker,
};
