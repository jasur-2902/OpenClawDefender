//! Secure API key storage via macOS Keychain with in-memory fallback for testing.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{Context, Result};

/// Supported LLM providers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Provider {
    Anthropic,
    OpenAi,
    Custom { base_url: String },
}

impl Provider {
    /// Return a stable string identifier for this provider.
    pub fn service_name(&self) -> String {
        match self {
            Provider::Anthropic => "com.clawdefender.api-key.anthropic".to_string(),
            Provider::OpenAi => "com.clawdefender.api-key.openai".to_string(),
            Provider::Custom { base_url } => {
                format!("com.clawdefender.api-key.custom.{}", base_url)
            }
        }
    }

    /// Human-readable name for display purposes.
    pub fn display_name(&self) -> String {
        match self {
            Provider::Anthropic => "Anthropic".to_string(),
            Provider::OpenAi => "OpenAI".to_string(),
            Provider::Custom { base_url } => format!("Custom ({})", base_url),
        }
    }

    /// Auto-detect provider from an API key prefix.
    pub fn detect_from_key(key: &str) -> Option<Provider> {
        if key.starts_with("sk-ant-") {
            Some(Provider::Anthropic)
        } else if key.starts_with("sk-") {
            Some(Provider::OpenAi)
        } else {
            None
        }
    }

    /// All known built-in providers.
    pub fn all_builtin() -> Vec<Provider> {
        vec![Provider::Anthropic, Provider::OpenAi]
    }
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Trait abstracting key storage for testability.
pub trait KeyStore: Send + Sync {
    fn store(&self, provider: &Provider, key: &str) -> Result<()>;
    fn get(&self, provider: &Provider) -> Result<String>;
    fn delete(&self, provider: &Provider) -> Result<()>;
    fn list(&self) -> Vec<(String, bool)>;
}

// ---------------------------------------------------------------------------
// macOS Keychain implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub struct KeychainManager;

#[cfg(target_os = "macos")]
impl Default for KeychainManager {
    fn default() -> Self {
        Self
    }
}

#[cfg(target_os = "macos")]
impl KeychainManager {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "macos")]
impl KeyStore for KeychainManager {
    fn store(&self, provider: &Provider, key: &str) -> Result<()> {
        use security_framework::passwords::{delete_generic_password, set_generic_password};

        let service = provider.service_name();
        let account = "api-key";

        // Delete existing entry first (ignore errors if not found).
        let _ = delete_generic_password(&service, account);
        set_generic_password(&service, account, key.as_bytes())
            .context("Failed to store API key in Keychain")?;

        tracing::info!(provider = %provider.display_name(), "API key stored in Keychain");
        Ok(())
    }

    fn get(&self, provider: &Provider) -> Result<String> {
        use security_framework::passwords::get_generic_password;

        let service = provider.service_name();
        let account = "api-key";

        let bytes =
            get_generic_password(&service, account).context("API key not found in Keychain")?;
        let key = String::from_utf8(bytes).context("API key is not valid UTF-8")?;
        Ok(key)
    }

    fn delete(&self, provider: &Provider) -> Result<()> {
        use security_framework::passwords::delete_generic_password;

        let service = provider.service_name();
        let account = "api-key";

        delete_generic_password(&service, account)
            .context("Failed to delete API key from Keychain")?;

        tracing::info!(provider = %provider.display_name(), "API key removed from Keychain");
        Ok(())
    }

    fn list(&self) -> Vec<(String, bool)> {
        Provider::all_builtin()
            .into_iter()
            .map(|p| {
                let configured = self.get(&p).is_ok();
                (p.display_name(), configured)
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// In-memory key store (for testing and CI)
// ---------------------------------------------------------------------------

pub struct MemoryKeyStore {
    keys: Mutex<HashMap<String, String>>,
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MemoryKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore for MemoryKeyStore {
    fn store(&self, provider: &Provider, key: &str) -> Result<()> {
        let mut keys = self.keys.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        keys.insert(provider.service_name(), key.to_string());
        Ok(())
    }

    fn get(&self, provider: &Provider) -> Result<String> {
        let keys = self.keys.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        keys.get(&provider.service_name())
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No API key configured for {}", provider.display_name()))
    }

    fn delete(&self, provider: &Provider) -> Result<()> {
        let mut keys = self.keys.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        keys.remove(&provider.service_name());
        Ok(())
    }

    fn list(&self) -> Vec<(String, bool)> {
        let keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        Provider::all_builtin()
            .into_iter()
            .map(|p| {
                let configured = keys.contains_key(&p.service_name());
                (p.display_name(), configured)
            })
            .collect()
    }
}

/// Return the platform-appropriate default key store.
/// On macOS: KeychainManager. Otherwise (or for tests): MemoryKeyStore.
pub fn default_keystore() -> Box<dyn KeyStore> {
    #[cfg(target_os = "macos")]
    {
        Box::new(KeychainManager::new())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(MemoryKeyStore::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_detect_anthropic() {
        assert_eq!(
            Provider::detect_from_key("sk-ant-api03-abc123"),
            Some(Provider::Anthropic)
        );
    }

    #[test]
    fn test_provider_detect_openai() {
        assert_eq!(
            Provider::detect_from_key("sk-proj-abc123"),
            Some(Provider::OpenAi)
        );
    }

    #[test]
    fn test_provider_detect_unknown() {
        assert_eq!(Provider::detect_from_key("xai-abc123"), None);
    }

    #[test]
    fn test_memory_store_roundtrip() {
        let store = MemoryKeyStore::new();
        let provider = Provider::Anthropic;

        // Initially not found.
        assert!(store.get(&provider).is_err());

        // Store and retrieve.
        store.store(&provider, "sk-ant-test-key").unwrap();
        assert_eq!(store.get(&provider).unwrap(), "sk-ant-test-key");

        // List shows configured.
        let list = store.list();
        let anthropic_entry = list.iter().find(|(name, _)| name == "Anthropic").unwrap();
        assert!(anthropic_entry.1);

        let openai_entry = list.iter().find(|(name, _)| name == "OpenAI").unwrap();
        assert!(!openai_entry.1);
    }

    #[test]
    fn test_memory_store_delete() {
        let store = MemoryKeyStore::new();
        let provider = Provider::OpenAi;

        store.store(&provider, "sk-test-key").unwrap();
        assert!(store.get(&provider).is_ok());

        store.delete(&provider).unwrap();
        assert!(store.get(&provider).is_err());
    }

    #[test]
    fn test_memory_store_overwrite() {
        let store = MemoryKeyStore::new();
        let provider = Provider::Anthropic;

        store.store(&provider, "sk-ant-key1").unwrap();
        store.store(&provider, "sk-ant-key2").unwrap();
        assert_eq!(store.get(&provider).unwrap(), "sk-ant-key2");
    }

    #[test]
    fn test_custom_provider() {
        let store = MemoryKeyStore::new();
        let provider = Provider::Custom {
            base_url: "https://my-llm.example.com".to_string(),
        };

        store.store(&provider, "custom-key-123").unwrap();
        assert_eq!(store.get(&provider).unwrap(), "custom-key-123");
    }

    #[test]
    fn test_api_key_not_in_error_message() {
        let store = MemoryKeyStore::new();
        let provider = Provider::Anthropic;

        let err = store.get(&provider).unwrap_err();
        let msg = format!("{err}");
        assert!(!msg.contains("sk-ant-"));
        assert!(!msg.contains("sk-"));
    }

    #[test]
    fn test_service_names_are_distinct() {
        let anthropic = Provider::Anthropic.service_name();
        let openai = Provider::OpenAi.service_name();
        let custom = Provider::Custom {
            base_url: "https://example.com".to_string(),
        }
        .service_name();

        assert_ne!(anthropic, openai);
        assert_ne!(anthropic, custom);
        assert_ne!(openai, custom);
    }
}
