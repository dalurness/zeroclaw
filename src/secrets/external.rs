//! External secret store backend.
//!
//! Spawns a provider binary per operation and communicates via JSON stdio protocol.
//! One JSON line to stdin, one JSON line from stdout.

use super::SecretStore;
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::process::Stdio;

/// External secret store that delegates to a provider binary via JSON stdio.
pub struct ExternalSecretStore {
    binary_path: String,
}

impl ExternalSecretStore {
    pub fn new(binary_path: String) -> Self {
        Self { binary_path }
    }

    async fn call(&self, request: &Request) -> Result<Response> {
        let request_json =
            serde_json::to_string(request).context("failed to serialize request")?;

        let mut child = tokio::process::Command::new(&self.binary_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to spawn provider binary: {}", self.binary_path))?;

        // Write request to stdin
        {
            use tokio::io::AsyncWriteExt;
            let stdin = child.stdin.as_mut().context("failed to open stdin")?;
            stdin.write_all(request_json.as_bytes()).await?;
            stdin.write_all(b"\n").await?;
            stdin.flush().await?;
        }
        // Drop stdin to signal EOF
        child.stdin.take();

        let output = child
            .wait_with_output()
            .await
            .context("failed to wait for provider binary")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "provider binary exited with {}: {}",
                output.status,
                stderr.trim()
            );
        }

        let stdout = String::from_utf8(output.stdout)
            .context("provider binary output is not valid UTF-8")?;
        let line = stdout
            .lines()
            .next()
            .context("provider binary produced no output")?;

        let response: Response =
            serde_json::from_str(line).context("failed to parse provider response")?;

        if !response.ok {
            anyhow::bail!(
                "provider error: {}",
                response.error.as_deref().unwrap_or("unknown error")
            );
        }

        Ok(response)
    }
}

#[derive(Serialize)]
struct Request {
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

#[derive(Deserialize)]
struct Response {
    ok: bool,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    keys: Option<Vec<String>>,
    #[serde(default)]
    error: Option<String>,
}

#[async_trait]
impl SecretStore for ExternalSecretStore {
    async fn get(&self, key: &str) -> Result<String> {
        let resp = self
            .call(&Request {
                action: "get".to_string(),
                key: Some(key.to_string()),
                value: None,
            })
            .await?;
        resp.value
            .ok_or_else(|| anyhow::anyhow!("provider returned ok but no value for key: {key}"))
    }

    async fn set(&self, key: &str, value: &str) -> Result<()> {
        self.call(&Request {
            action: "set".to_string(),
            key: Some(key.to_string()),
            value: Some(value.to_string()),
        })
        .await?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<String>> {
        let resp = self
            .call(&Request {
                action: "list".to_string(),
                key: None,
                value: None,
            })
            .await?;
        Ok(resp.keys.unwrap_or_default())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.call(&Request {
            action: "delete".to_string(),
            key: Some(key.to_string()),
            value: None,
        })
        .await?;
        Ok(())
    }
}
