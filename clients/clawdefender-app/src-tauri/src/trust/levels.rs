use serde::{Deserialize, Serialize};

/// Trust levels that control how much freedom an MCP server has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    Trusted,
    Standard,
    Cautious,
    Restricted,
    Custom,
}

impl TrustLevel {
    /// Parse a trust level from a string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<TrustLevel> {
        match s.to_lowercase().as_str() {
            "trusted" => Some(TrustLevel::Trusted),
            "standard" => Some(TrustLevel::Standard),
            "cautious" => Some(TrustLevel::Cautious),
            "restricted" => Some(TrustLevel::Restricted),
            "custom" => Some(TrustLevel::Custom),
            _ => None,
        }
    }

    /// The base priority for rules generated at this trust level.
    pub fn base_priority(self) -> i32 {
        match self {
            TrustLevel::Trusted => 200,
            TrustLevel::Standard => 300,
            TrustLevel::Cautious => 400,
            TrustLevel::Restricted => 500,
            TrustLevel::Custom => 300, // fallback
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TrustLevel::Trusted => "trusted",
            TrustLevel::Standard => "standard",
            TrustLevel::Cautious => "cautious",
            TrustLevel::Restricted => "restricted",
            TrustLevel::Custom => "custom",
        }
    }
}
