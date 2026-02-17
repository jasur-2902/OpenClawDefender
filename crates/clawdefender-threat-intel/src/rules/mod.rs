//! Community rules engine — distributes, imports, and manages community-contributed policy rules.

pub mod catalog;
pub mod conflict;
pub mod manager;
pub mod types;

#[cfg(test)]
mod tests;
