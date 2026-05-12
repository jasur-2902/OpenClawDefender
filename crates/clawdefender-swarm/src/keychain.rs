//! API key storage with file-based default and in-memory fallback for testing.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::Result;

/// Supported LLM providers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Provider {
    Anthropic,
    OpenAi,
    Google,
    Custom { base_url: String },
}

impl Provider {
    /// Return a stable string identifier for this provider.
    pub fn service_name(&self) -> String {
        match self {
            Provider::Anthropic => "com.rookbot.api-key.anthropic".to_string(),
            Provider::OpenAi => "com.rookbot.api-key.openai".to_string(),
            Provider::Google => "com.rookbot.api-key.google".to_string(),
            Provider::Custom { base_url } => {
                format!("com.rookbot.api-key.custom.{}", base_url)
            }
        }
    }

    /// Human-readable name for display purposes.
    pub fn display_name(&self) -> String {
        match self {
            Provider::Anthropic => "Anthropic".to_string(),
            Provider::OpenAi => "OpenAI".to_string(),
            Provider::Google => "Google".to_string(),
            Provider::Custom { base_url } => format!("Custom ({})", base_url),
        }
    }

    /// Auto-detect provider from an API key prefix.
    pub fn detect_from_key(key: &str) -> Option<Provider> {
        if key.starts_with("sk-ant-") {
            Some(Provider::Anthropic)
        } else if key.starts_with("sk-") {
            Some(Provider::OpenAi)
        } else if key.starts_with("AIza") {
            Some(Provider::Google)
        } else {
            None
        }
    }

    /// Environment variable name for this provider's API key.
    pub fn env_var_name(&self) -> Option<&'static str> {
        match self {
            Provider::Anthropic => Some("ANTHROPIC_API_KEY"),
            Provider::OpenAi => Some("OPENAI_API_KEY"),
            Provider::Google => Some("GOOGLE_API_KEY"),
            Provider::Custom { .. } => None,
        }
    }

    /// All known built-in providers.
    pub fn all_builtin() -> Vec<Provider> {
        vec![Provider::Anthropic, Provider::OpenAi, Provider::Google]
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
// File-based key store (~/.config/rookbot/credentials)
// ---------------------------------------------------------------------------

pub struct FileKeyStore {
    path: PathBuf,
}

impl FileKeyStore {
    pub fn new() -> Self {
        let home = std::env::var_os("HOME").expect("HOME not set");
        Self {
            path: PathBuf::from(home).join(".config/rookbot/credentials"),
        }
    }

    /// Provider key used inside the credentials file.
    fn file_key(provider: &Provider) -> String {
        match provider {
            Provider::Anthropic => "anthropic".to_string(),
            Provider::OpenAi => "openai".to_string(),
            Provider::Google => "google".to_string(),
            Provider::Custom { base_url } => format!("custom.{base_url}"),
        }
    }

    fn read_all(&self) -> HashMap<String, String> {
        let contents = match std::fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(_) => return HashMap::new(),
        };
        let mut map = HashMap::new();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                map.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        map
    }

    fn write_all(&self, map: &HashMap<String, String>) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut contents = String::from("# rookbot API credentials\n");
        let mut keys: Vec<_> = map.iter().collect();
        keys.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (k, v) in keys {
            contents.push_str(&format!("{k}={v}\n"));
        }

        std::fs::write(&self.path, &contents)?;

        // Restrict file permissions to owner-only (0600).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }
}

impl Default for FileKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore for FileKeyStore {
    fn store(&self, provider: &Provider, key: &str) -> Result<()> {
        let mut map = self.read_all();
        map.insert(Self::file_key(provider), key.to_string());
        self.write_all(&map)?;
        tracing::info!(provider = %provider.display_name(), "API key stored");
        Ok(())
    }

    fn get(&self, provider: &Provider) -> Result<String> {
        // Check environment variable first.
        if let Some(var) = provider.env_var_name() {
            if let Ok(val) = std::env::var(var) {
                if !val.is_empty() {
                    return Ok(val);
                }
            }
        }

        let map = self.read_all();
        map.get(&Self::file_key(provider))
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("No API key configured for {}", provider.display_name())
            })
    }

    fn delete(&self, provider: &Provider) -> Result<()> {
        let mut map = self.read_all();
        map.remove(&Self::file_key(provider));
        self.write_all(&map)?;
        tracing::info!(provider = %provider.display_name(), "API key removed");
        Ok(())
    }

    fn list(&self) -> Vec<(String, bool)> {
        let map = self.read_all();
        Provider::all_builtin()
            .into_iter()
            .map(|p| {
                // Check env var or file.
                let from_env = p
                    .env_var_name()
                    .and_then(|v| std::env::var(v).ok())
                    .map(|v| !v.is_empty())
                    .unwrap_or(false);
                let configured = from_env || map.contains_key(&Self::file_key(&p));
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
        // Check environment variable first.
        if let Some(var) = provider.env_var_name() {
            if let Ok(val) = std::env::var(var) {
                if !val.is_empty() {
                    return Ok(val);
                }
            }
        }

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

/// Return the default key store (file-based at ~/.config/rookbot/credentials).
pub fn default_keystore() -> Box<dyn KeyStore> {
    Box::new(FileKeyStore::new())
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
