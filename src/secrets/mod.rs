//! Secrets management subsystem.
//!
//! Provides a `SecretStore` trait for pluggable secret backends and a
//! `SecretRegistry` that cascades reads across an ordered list of named stores.
//! Config order is precedence order for reads — first store wins on key lookup.
//! Writes default to the first store unless explicitly targeted.

pub mod external;
pub mod local;
pub mod migration;
pub mod tools;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::sync::Arc;

/// Trait implemented by each secret storage backend.
#[async_trait]
pub trait SecretStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<String>;
    async fn set(&self, key: &str, value: &str) -> Result<()>;
    async fn list(&self) -> Result<Vec<String>>;
    async fn delete(&self, key: &str) -> Result<()>;
}

/// An ordered collection of named secret stores.
///
/// Reads cascade through stores in config order — first hit wins.
/// Writes target the first store unless `--store` is given explicitly.
pub struct SecretRegistry {
    stores: Vec<(String, Arc<dyn SecretStore>)>,
}

impl SecretRegistry {
    pub fn new(stores: Vec<(String, Arc<dyn SecretStore>)>) -> Self {
        Self { stores }
    }

    /// Cascade read: try each store in order, return first hit.
    /// If store name is given, target that store directly.
    pub async fn get(&self, key: &str, store: Option<&str>) -> Result<String> {
        if let Some(name) = store {
            return self.named(name)?.get(key).await;
        }
        for (_, s) in &self.stores {
            if let Ok(val) = s.get(key).await {
                return Ok(val);
            }
        }
        Err(anyhow!("secret not found: {key}"))
    }

    /// Write to explicit store or first store by default.
    pub async fn set(&self, key: &str, value: &str, store: Option<&str>) -> Result<()> {
        validate_key(key)?;
        let normalized = key.to_ascii_uppercase();
        self.named_or_first(store)?.set(&normalized, value).await
    }

    /// List keys from a specific store, or all stores merged.
    pub async fn list(&self, store: Option<&str>, show_internal: bool) -> Result<Vec<String>> {
        let keys = if let Some(name) = store {
            self.named(name)?.list().await?
        } else {
            let mut seen = std::collections::HashSet::new();
            let mut all = Vec::new();
            for (_, s) in &self.stores {
                if let Ok(keys) = s.list().await {
                    for k in keys {
                        if seen.insert(k.clone()) {
                            all.push(k);
                        }
                    }
                }
            }
            all
        };
        if show_internal {
            Ok(keys)
        } else {
            Ok(keys.into_iter().filter(|k| !k.starts_with("__")).collect())
        }
    }

    /// Delete from explicit store or first store by default.
    pub async fn delete(&self, key: &str, store: Option<&str>) -> Result<()> {
        self.named_or_first(store)?.delete(key).await
    }

    /// Substitute `{{secret:KEY}}` and `{{secret@storename:KEY}}` tokens in content.
    /// Fails loudly if any referenced key or store is not found.
    pub async fn inject(&self, content: &str, store: Option<&str>) -> Result<String> {
        let mut result = String::with_capacity(content.len());
        let mut rest = content;

        while let Some(start) = rest.find("{{secret") {
            result.push_str(&rest[..start]);
            let after_open = &rest[start + 2..]; // skip "{{"
            let Some(end) = after_open.find("}}") else {
                // No closing — treat as literal
                result.push_str(&rest[start..]);
                rest = "";
                break;
            };
            let token = &after_open[..end]; // e.g. "secret:KEY" or "secret@store:KEY"
            let value = self.resolve_token(token, store).await?;
            result.push_str(&value);
            rest = &after_open[end + 2..]; // skip "}}"
        }
        result.push_str(rest);
        Ok(result)
    }

    /// Return list of (name, backend_type) for all configured stores.
    pub fn store_info(&self) -> Vec<StoreInfo> {
        self.stores
            .iter()
            .enumerate()
            .map(|(i, (name, _))| StoreInfo {
                name: name.clone(),
                is_default: i == 0,
            })
            .collect()
    }

    fn named(&self, name: &str) -> Result<&dyn SecretStore> {
        self.stores
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, s)| s.as_ref())
            .ok_or_else(|| anyhow!("unknown secret store: {name}"))
    }

    fn named_or_first(&self, name: Option<&str>) -> Result<&dyn SecretStore> {
        match name {
            Some(n) => self.named(n),
            None => self
                .stores
                .first()
                .map(|(_, s)| s.as_ref())
                .ok_or_else(|| anyhow!("no secret stores configured")),
        }
    }

    /// Resolve a single inject token like `secret:KEY` or `secret@store:KEY`.
    async fn resolve_token(&self, token: &str, default_store: Option<&str>) -> Result<String> {
        let body = token
            .strip_prefix("secret")
            .ok_or_else(|| anyhow!("invalid secret token: {{{{{token}}}}}"))?;

        if let Some(rest) = body.strip_prefix('@') {
            // {{secret@storename:KEY}}
            let colon = rest
                .find(':')
                .ok_or_else(|| anyhow!("invalid secret token: missing ':' in {{{{{token}}}}}"))?;
            let store_name = &rest[..colon];
            let key = &rest[colon + 1..];
            self.named(store_name)?.get(key).await
        } else if let Some(key) = body.strip_prefix(':') {
            // {{secret:KEY}}
            self.get(key, default_store).await
        } else {
            Err(anyhow!("invalid secret token: {{{{{token}}}}}"))
        }
    }
}

/// Info about a configured store for display purposes.
#[derive(Debug, Clone)]
pub struct StoreInfo {
    pub name: String,
    pub is_default: bool,
}

/// Validate key naming: alphanumeric + underscores only, no @ or :.
/// Auto-uppercased by the caller.
pub fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() {
        anyhow::bail!("secret key cannot be empty");
    }
    for ch in key.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' {
            anyhow::bail!(
                "invalid secret key '{key}': only alphanumeric and underscores allowed (got '{ch}')"
            );
        }
    }
    Ok(())
}

/// Build a `SecretRegistry` from the application `Config`.
///
/// Each entry point (agent, gateway, channels, CLI) calls this independently —
/// following the same pattern as `SecurityPolicy::from_config`, `create_observer`, etc.
///
/// Zero-config fallback: if no stores are defined, instantiate a single local
/// store at `<workspace>/.secrets`.
pub fn build_registry(config: &crate::config::Config) -> Result<SecretRegistry> {
    let workspace_dir = &config.workspace_dir;
    let config_dir = config
        .config_path
        .parent()
        .ok_or_else(|| anyhow!("config path must have a parent directory"))?;
    let encrypt_enabled = config.secrets.encrypt;

    let mut stores: Vec<(String, Arc<dyn SecretStore>)> = Vec::new();

    if config.secrets.stores.is_empty() {
        // Zero-config fallback: single local store
        let store = local::LocalSecretStore::new(
            workspace_dir.join(".secrets"),
            config_dir,
            encrypt_enabled,
        )?;
        stores.push(("local".to_string(), Arc::new(store)));
    } else {
        for entry in &config.secrets.stores {
            let store: Arc<dyn SecretStore> = match entry.backend.as_str() {
                "local" => {
                    let path = entry
                        .store_path
                        .as_deref()
                        .map(|p| {
                            let expanded = shellexpand::tilde(p);
                            std::path::PathBuf::from(expanded.as_ref())
                        })
                        .unwrap_or_else(|| workspace_dir.join(".secrets"));
                    Arc::new(local::LocalSecretStore::new(
                        path,
                        config_dir,
                        encrypt_enabled,
                    )?)
                }
                "external" => {
                    let binary = entry
                        .provider_binary
                        .as_deref()
                        .ok_or_else(|| {
                            anyhow!(
                                "secret store '{}': external backend requires provider_binary",
                                entry.name
                            )
                        })?;
                    let expanded = shellexpand::tilde(binary);
                    Arc::new(external::ExternalSecretStore::new(expanded.into_owned()))
                }
                other => anyhow::bail!("unknown secret store backend: {other}"),
            };
            stores.push((entry.name.clone(), store));
        }
    }

    Ok(SecretRegistry::new(stores))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_key_accepts_valid() {
        assert!(validate_key("GMAIL_KEY").is_ok());
        assert!(validate_key("my_key_123").is_ok());
        assert!(validate_key("A").is_ok());
        assert!(validate_key("__INTERNAL").is_ok());
    }

    #[test]
    fn validate_key_rejects_invalid() {
        assert!(validate_key("").is_err());
        assert!(validate_key("key@store").is_err());
        assert!(validate_key("key:value").is_err());
        assert!(validate_key("has space").is_err());
        assert!(validate_key("has-dash").is_err());
    }

    #[tokio::test]
    async fn registry_cascade_read() {
        use std::collections::HashMap;
        use tokio::sync::RwLock;

        struct InMemStore(RwLock<HashMap<String, String>>);

        #[async_trait]
        impl SecretStore for InMemStore {
            async fn get(&self, key: &str) -> Result<String> {
                self.0
                    .read()
                    .await
                    .get(key)
                    .cloned()
                    .ok_or_else(|| anyhow!("not found"))
            }
            async fn set(&self, key: &str, value: &str) -> Result<()> {
                self.0
                    .write()
                    .await
                    .insert(key.to_string(), value.to_string());
                Ok(())
            }
            async fn list(&self) -> Result<Vec<String>> {
                Ok(self.0.read().await.keys().cloned().collect())
            }
            async fn delete(&self, key: &str) -> Result<()> {
                self.0.write().await.remove(key);
                Ok(())
            }
        }

        let mut m1 = HashMap::new();
        m1.insert("KEY_A".to_string(), "from_store1".to_string());
        let store1: Arc<dyn SecretStore> = Arc::new(InMemStore(RwLock::new(m1)));

        let mut m2 = HashMap::new();
        m2.insert("KEY_A".to_string(), "from_store2".to_string());
        m2.insert("KEY_B".to_string(), "only_in_store2".to_string());
        let store2: Arc<dyn SecretStore> = Arc::new(InMemStore(RwLock::new(m2)));

        let registry = SecretRegistry::new(vec![
            ("first".to_string(), store1),
            ("second".to_string(), store2),
        ]);

        // Cascade: first store wins for KEY_A
        assert_eq!(registry.get("KEY_A", None).await.unwrap(), "from_store1");
        // Falls through to second store for KEY_B
        assert_eq!(registry.get("KEY_B", None).await.unwrap(), "only_in_store2");
        // Explicit store targeting
        assert_eq!(
            registry.get("KEY_A", Some("second")).await.unwrap(),
            "from_store2"
        );
    }

    #[tokio::test]
    async fn inject_substitutes_tokens() {
        use std::collections::HashMap;
        use tokio::sync::RwLock;

        struct InMemStore(RwLock<HashMap<String, String>>);

        #[async_trait]
        impl SecretStore for InMemStore {
            async fn get(&self, key: &str) -> Result<String> {
                self.0
                    .read()
                    .await
                    .get(key)
                    .cloned()
                    .ok_or_else(|| anyhow!("not found: {key}"))
            }
            async fn set(&self, _key: &str, _value: &str) -> Result<()> {
                Ok(())
            }
            async fn list(&self) -> Result<Vec<String>> {
                Ok(vec![])
            }
            async fn delete(&self, _key: &str) -> Result<()> {
                Ok(())
            }
        }

        let mut m = HashMap::new();
        m.insert("API_KEY".to_string(), "sk-abc123".to_string());
        let store: Arc<dyn SecretStore> = Arc::new(InMemStore(RwLock::new(m)));
        let registry = SecretRegistry::new(vec![("local".to_string(), store)]);

        let result = registry
            .inject("key={{secret:API_KEY}}&done", None)
            .await
            .unwrap();
        assert_eq!(result, "key=sk-abc123&done");
    }

    #[tokio::test]
    async fn inject_fails_on_missing_key() {
        use std::collections::HashMap;
        use tokio::sync::RwLock;

        struct InMemStore(RwLock<HashMap<String, String>>);

        #[async_trait]
        impl SecretStore for InMemStore {
            async fn get(&self, key: &str) -> Result<String> {
                Err(anyhow!("not found: {key}"))
            }
            async fn set(&self, _: &str, _: &str) -> Result<()> {
                Ok(())
            }
            async fn list(&self) -> Result<Vec<String>> {
                Ok(vec![])
            }
            async fn delete(&self, _: &str) -> Result<()> {
                Ok(())
            }
        }

        let store: Arc<dyn SecretStore> = Arc::new(InMemStore(RwLock::new(HashMap::new())));
        let registry = SecretRegistry::new(vec![("local".to_string(), store)]);

        let result = registry.inject("{{secret:MISSING}}", None).await;
        assert!(result.is_err());
    }
}
