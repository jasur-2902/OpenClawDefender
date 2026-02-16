//! CLI commands for managing API keys.

use std::io::{self, BufRead, Write};

use anyhow::Result;
use clawdefender_swarm::keychain::{KeyStore, Provider};

/// Store an API key for a provider.
pub fn set_api_key(
    keystore: &dyn KeyStore,
    provider_name: &str,
    key_from_arg: Option<&str>,
) -> Result<()> {
    let key = match key_from_arg {
        Some(k) => k.to_string(),
        None => {
            // Try reading from stdin (piped input or interactive).
            eprint!("Enter API key for {provider_name}: ");
            io::stderr().flush()?;
            let mut line = String::new();
            io::stdin().lock().read_line(&mut line)?;
            let trimmed = line.trim().to_string();
            if trimmed.is_empty() {
                anyhow::bail!("No API key provided");
            }
            trimmed
        }
    };

    let provider = resolve_provider(provider_name, Some(&key))?;
    keystore.store(&provider, &key)?;
    println!("API key stored for {}", provider.display_name());
    Ok(())
}

/// Show whether an API key is configured for a provider.
pub fn get_api_key(keystore: &dyn KeyStore, provider_name: &str) -> Result<()> {
    let provider = resolve_provider(provider_name, None)?;
    match keystore.get(&provider) {
        Ok(key) => {
            // Show only a masked version — never print the full key.
            let masked = if key.len() > 8 {
                format!("{}...{}", &key[..4], &key[key.len() - 4..])
            } else {
                "****".to_string()
            };
            println!("{}: configured ({})", provider.display_name(), masked);
        }
        Err(_) => {
            println!("{}: not configured", provider.display_name());
        }
    }
    Ok(())
}

/// Remove an API key for a provider.
pub fn remove_api_key(keystore: &dyn KeyStore, provider_name: &str) -> Result<()> {
    let provider = resolve_provider(provider_name, None)?;
    keystore.delete(&provider)?;
    println!("API key removed for {}", provider.display_name());
    Ok(())
}

/// List all configured providers.
pub fn list_api_keys(keystore: &dyn KeyStore) -> Result<()> {
    let entries = keystore.list();
    if entries.is_empty() {
        println!("No providers configured.");
        return Ok(());
    }
    for (name, configured) in entries {
        let status = if configured { "configured" } else { "not set" };
        println!("  {name}: {status}");
    }
    Ok(())
}

/// Resolve a provider name string to a Provider enum.
fn resolve_provider(name: &str, key: Option<&str>) -> Result<Provider> {
    match name.to_lowercase().as_str() {
        "anthropic" => Ok(Provider::Anthropic),
        "openai" => Ok(Provider::OpenAi),
        "auto" => {
            if let Some(k) = key {
                Provider::detect_from_key(k).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Cannot auto-detect provider from key prefix. \
                         Use --provider anthropic or --provider openai."
                    )
                })
            } else {
                anyhow::bail!("Provider name required. Use: anthropic, openai")
            }
        }
        other => {
            // Treat as custom provider with base_url.
            if other.starts_with("http") {
                Ok(Provider::Custom {
                    base_url: other.to_string(),
                })
            } else {
                anyhow::bail!(
                    "Unknown provider: {other}. Use: anthropic, openai, or a custom base URL."
                )
            }
        }
    }
}
