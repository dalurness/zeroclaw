//! Local secret store backend.
//!
//! Stores all secrets as a single ChaCha20-Poly1305 encrypted JSON blob in a
//! `.secrets` file. Format: `secrets1:<hex(nonce || ciphertext || tag)>`.
//!
//! The internal JSON is a flat `{ "KEY": "value", ... }` object. Atomic
//! writes: decrypt → mutate → encrypt → write. No partial state.

use super::SecretStore;
use anyhow::{Context, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const BLOB_PREFIX: &str = "secrets1:";

/// Local encrypted secret store backed by a `.secrets` file.
pub struct LocalSecretStore {
    path: PathBuf,
    crypto: crate::security::secrets::SecretStore,
    /// Mutex for atomic read-modify-write on the blob file.
    lock: Mutex<()>,
}

impl LocalSecretStore {
    pub fn new(path: PathBuf, config_dir: &Path, encrypt_enabled: bool) -> Result<Self> {
        Ok(Self {
            path,
            crypto: crate::security::secrets::SecretStore::new(config_dir, encrypt_enabled),
            lock: Mutex::new(()),
        })
    }

    /// Read and decrypt the secrets blob. Returns empty map if file doesn't exist.
    fn load_map(&self) -> Result<BTreeMap<String, String>> {
        if !self.path.exists() {
            return Ok(BTreeMap::new());
        }
        let contents =
            std::fs::read_to_string(&self.path).context("failed to read .secrets file")?;
        let contents = contents.trim();
        if contents.is_empty() {
            return Ok(BTreeMap::new());
        }
        let hex_blob = contents
            .strip_prefix(BLOB_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("invalid .secrets file: missing '{BLOB_PREFIX}' prefix"))?;
        // Decrypt using the existing enc2: format by wrapping with the prefix
        let enc2_value = format!("enc2:{hex_blob}");
        let json_str = self.crypto.decrypt(&enc2_value)?;
        let map: BTreeMap<String, String> =
            serde_json::from_str(&json_str).context("failed to parse secrets JSON")?;
        Ok(map)
    }

    /// Encrypt and write the secrets blob atomically.
    fn save_map(&self, map: &BTreeMap<String, String>) -> Result<()> {
        let json_str = serde_json::to_string(map).context("failed to serialize secrets")?;
        let encrypted = self.crypto.encrypt(&json_str)?;
        // encrypted is "enc2:<hex>" — strip enc2: and replace with secrets1:
        let hex_blob = encrypted
            .strip_prefix("enc2:")
            .ok_or_else(|| anyhow::anyhow!("encryption did not produce enc2: prefix"))?;
        let blob = format!("{BLOB_PREFIX}{hex_blob}");

        // Atomic write: write to temp, then rename
        let tmp_path = self.path.with_extension("tmp");
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&tmp_path, blob.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    /// Re-encrypt the blob with a new key. Used by `rotate-key` CLI command.
    pub fn rotate_key(&self) -> Result<()> {
        let _guard = self.lock.lock();
        let map = self.load_map()?;
        if map.is_empty() {
            anyhow::bail!("no secrets to rotate — store is empty");
        }
        // Re-encrypting with the same SecretStore will use the same key but
        // generate a fresh nonce. For a true key rotation, the caller should
        // delete/regenerate the key file first, then call this method.
        self.save_map(&map)?;
        Ok(())
    }
}

#[async_trait]
impl SecretStore for LocalSecretStore {
    async fn get(&self, key: &str) -> Result<String> {
        let _guard = self.lock.lock();
        let map = self.load_map()?;
        map.get(key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("secret not found: {key}"))
    }

    async fn set(&self, key: &str, value: &str) -> Result<()> {
        let _guard = self.lock.lock();
        let mut map = self.load_map()?;
        map.insert(key.to_string(), value.to_string());
        self.save_map(&map)
    }

    async fn list(&self) -> Result<Vec<String>> {
        let _guard = self.lock.lock();
        let map = self.load_map()?;
        Ok(map.keys().cloned().collect())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let _guard = self.lock.lock();
        let mut map = self.load_map()?;
        if map.remove(key).is_none() {
            anyhow::bail!("secret not found: {key}");
        }
        self.save_map(&map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_store(tmp: &TempDir) -> LocalSecretStore {
        LocalSecretStore::new(
            tmp.path().join(".secrets"),
            tmp.path(),
            true,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn set_get_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp);
        store.set("API_KEY", "sk-test123").await.unwrap();
        let value = store.get("API_KEY").await.unwrap();
        assert_eq!(value, "sk-test123");
    }

    #[tokio::test]
    async fn get_missing_key_fails() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp);
        assert!(store.get("MISSING").await.is_err());
    }

    #[tokio::test]
    async fn list_keys() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp);
        store.set("KEY_A", "a").await.unwrap();
        store.set("KEY_B", "b").await.unwrap();
        let mut keys = store.list().await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["KEY_A", "KEY_B"]);
    }

    #[tokio::test]
    async fn delete_key() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp);
        store.set("TO_DELETE", "value").await.unwrap();
        store.delete("TO_DELETE").await.unwrap();
        assert!(store.get("TO_DELETE").await.is_err());
    }

    #[tokio::test]
    async fn delete_missing_key_fails() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp);
        assert!(store.delete("MISSING").await.is_err());
    }

    #[tokio::test]
    async fn persistence_across_instances() {
        let tmp = TempDir::new().unwrap();
        {
            let store = make_store(&tmp);
            store.set("PERSIST", "value").await.unwrap();
        }
        {
            let store = make_store(&tmp);
            assert_eq!(store.get("PERSIST").await.unwrap(), "value");
        }
    }

    #[tokio::test]
    async fn rotate_key_re_encrypts() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp);
        store.set("KEY", "value").await.unwrap();
        let before = std::fs::read_to_string(tmp.path().join(".secrets")).unwrap();
        store.rotate_key().unwrap();
        let after = std::fs::read_to_string(tmp.path().join(".secrets")).unwrap();
        // Different nonce means different ciphertext
        assert_ne!(before, after);
        // But same plaintext
        assert_eq!(store.get("KEY").await.unwrap(), "value");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn secrets_file_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp);
        store.set("KEY", "value").await.unwrap();
        let perms = std::fs::metadata(tmp.path().join(".secrets"))
            .unwrap()
            .permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}
