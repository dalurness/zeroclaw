//! Native LLM tools for secrets operations.
//!
//! Registered as native Rust tools in ZeroClaw's tool registry.
//! `secrets_get` is intentionally NOT registered — raw value retrieval
//! is not exposed to the LLM by default.

use crate::secrets::SecretRegistry;
use crate::tools::traits::{Tool, ToolResult};
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

// ── secrets_set ─────────────────────────────────────────────────

pub struct SecretsSetTool {
    registry: Arc<SecretRegistry>,
}

impl SecretsSetTool {
    pub fn new(registry: Arc<SecretRegistry>) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl Tool for SecretsSetTool {
    fn name(&self) -> &str {
        "secrets_set"
    }

    fn description(&self) -> &str {
        "Store a secret (API key, token, credential). Keys are auto-uppercased. Only alphanumeric and underscores allowed."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "Secret key name (alphanumeric + underscores, auto-uppercased)"
                },
                "value": {
                    "type": "string",
                    "description": "Secret value to store"
                },
                "store": {
                    "type": "string",
                    "description": "Optional target store name. If omitted, uses the default (first) store."
                }
            },
            "required": ["key", "value"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let key = args
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'key' parameter"))?;
        let value = args
            .get("value")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'value' parameter"))?;
        let store = args.get("store").and_then(|v| v.as_str());

        match self.registry.set(key, value, store).await {
            Ok(()) => Ok(ToolResult {
                success: true,
                output: format!("Secret '{}' stored successfully.", key.to_ascii_uppercase()),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Failed to store secret: {e}")),
            }),
        }
    }
}

// ── secrets_list ────────────────────────────────────────────────

pub struct SecretsListTool {
    registry: Arc<SecretRegistry>,
}

impl SecretsListTool {
    pub fn new(registry: Arc<SecretRegistry>) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl Tool for SecretsListTool {
    fn name(&self) -> &str {
        "secrets_list"
    }

    fn description(&self) -> &str {
        "List available secret key names (internal keys prefixed with __ are hidden)."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "store": {
                    "type": "string",
                    "description": "Optional store name to list from. If omitted, lists from all stores."
                }
            }
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let store = args.get("store").and_then(|v| v.as_str());
        match self.registry.list(store, false).await {
            Ok(keys) => {
                let output = if keys.is_empty() {
                    "No secrets stored.".to_string()
                } else {
                    keys.join("\n")
                };
                Ok(ToolResult {
                    success: true,
                    output,
                    error: None,
                })
            }
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Failed to list secrets: {e}")),
            }),
        }
    }
}

// ── secrets_delete ──────────────────────────────────────────────

pub struct SecretsDeleteTool {
    registry: Arc<SecretRegistry>,
}

impl SecretsDeleteTool {
    pub fn new(registry: Arc<SecretRegistry>) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl Tool for SecretsDeleteTool {
    fn name(&self) -> &str {
        "secrets_delete"
    }

    fn description(&self) -> &str {
        "Delete a stored secret by key name."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "Secret key name to delete"
                },
                "store": {
                    "type": "string",
                    "description": "Optional target store name."
                }
            },
            "required": ["key"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let key = args
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'key' parameter"))?;
        let store = args.get("store").and_then(|v| v.as_str());

        match self.registry.delete(key, store).await {
            Ok(()) => Ok(ToolResult {
                success: true,
                output: format!("Secret '{key}' deleted."),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Failed to delete secret: {e}")),
            }),
        }
    }
}

// ── secrets_inject ──────────────────────────────────────────────

pub struct SecretsInjectTool {
    registry: Arc<SecretRegistry>,
}

impl SecretsInjectTool {
    pub fn new(registry: Arc<SecretRegistry>) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl Tool for SecretsInjectTool {
    fn name(&self) -> &str {
        "secrets_inject"
    }

    fn description(&self) -> &str {
        "Substitute {{secret:KEY}} tokens in a string with their stored values. Returns the substituted string. Fails if any referenced key is not found."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "String containing {{secret:KEY}} tokens to substitute"
                },
                "store": {
                    "type": "string",
                    "description": "Optional default store for token resolution."
                }
            },
            "required": ["content"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let content = args
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'content' parameter"))?;
        let store = args.get("store").and_then(|v| v.as_str());

        match self.registry.inject(content, store).await {
            Ok(result) => Ok(ToolResult {
                success: true,
                output: result,
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Failed to inject secrets: {e}")),
            }),
        }
    }
}

// ── secrets_stores ──────────────────────────────────────────────

pub struct SecretsStoresTool {
    registry: Arc<SecretRegistry>,
}

impl SecretsStoresTool {
    pub fn new(registry: Arc<SecretRegistry>) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl Tool for SecretsStoresTool {
    fn name(&self) -> &str {
        "secrets_stores"
    }

    fn description(&self) -> &str {
        "List configured secret store names and which is the default write target."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {}
        })
    }

    async fn execute(&self, _args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let stores = self.registry.store_info();
        let output = if stores.is_empty() {
            "No secret stores configured.".to_string()
        } else {
            stores
                .iter()
                .map(|s| {
                    if s.is_default {
                        format!("{} (default)", s.name)
                    } else {
                        s.name.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        Ok(ToolResult {
            success: true,
            output,
            error: None,
        })
    }
}
