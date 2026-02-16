//! Inter-process communication between the ClawDefender daemon and the menu-bar UI.
//!
//! Messages are exchanged over a Unix domain socket using length-prefixed
//! JSON frames.

pub mod protocol;

pub use protocol::{UiRequest, UiResponse, UserDecision};
