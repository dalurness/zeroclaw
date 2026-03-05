//! Credential migration from config.toml to the secrets store.
//!
//! On startup, checks for old-style encrypted keys in config (provider API key,
//! channel tokens). If found, decrypts using existing logic, re-stores via
//! `SecretStore::set` under `__`-prefixed reserved key names, removes from
//! config.toml, and saves.

use crate::config::Config;
use crate::secrets::SecretRegistry;
use anyhow::Result;

/// Migrate credentials from config.toml into the secret store.
/// Returns the number of credentials migrated.
pub async fn migrate_config_credentials(
    config: &mut Config,
    registry: &SecretRegistry,
) -> Result<usize> {
    let mut migrated = 0;

    // Provider API key
    if let Some(ref api_key) = config.api_key {
        if !api_key.is_empty() {
            registry
                .set("__API_KEY", api_key, None)
                .await
                .map_err(|e| {
                    tracing::warn!("secrets migration: failed to migrate api_key: {e}");
                    e
                })?;
            tracing::info!("secrets migration: migrated api_key -> __API_KEY");
            config.api_key = None;
            migrated += 1;
        }
    }

    // Telegram bot token
    if let Some(ref mut telegram) = config.channels_config.telegram {
        if !telegram.bot_token.is_empty() {
            registry
                .set("__TELEGRAM_TOKEN", &telegram.bot_token, None)
                .await
                .map_err(|e| {
                    tracing::warn!(
                        "secrets migration: failed to migrate telegram bot_token: {e}"
                    );
                    e
                })?;
            tracing::info!("secrets migration: migrated telegram bot_token -> __TELEGRAM_TOKEN");
            telegram.bot_token = String::new();
            migrated += 1;
        }
    }

    // Discord bot token
    if let Some(ref mut discord) = config.channels_config.discord {
        if !discord.bot_token.is_empty() {
            registry
                .set("__DISCORD_TOKEN", &discord.bot_token, None)
                .await
                .map_err(|e| {
                    tracing::warn!("secrets migration: failed to migrate discord bot_token: {e}");
                    e
                })?;
            tracing::info!("secrets migration: migrated discord bot_token -> __DISCORD_TOKEN");
            discord.bot_token = String::new();
            migrated += 1;
        }
    }

    // Slack bot token
    if let Some(ref mut slack) = config.channels_config.slack {
        if !slack.bot_token.is_empty() {
            registry
                .set("__SLACK_TOKEN", &slack.bot_token, None)
                .await
                .map_err(|e| {
                    tracing::warn!("secrets migration: failed to migrate slack bot_token: {e}");
                    e
                })?;
            tracing::info!("secrets migration: migrated slack bot_token -> __SLACK_TOKEN");
            slack.bot_token = String::new();
            migrated += 1;
        }
    }

    if migrated > 0 {
        config.save().await.map_err(|e| {
            tracing::warn!(
                "secrets migration: failed to save config after migrating {migrated} credentials: {e}"
            );
            e
        })?;
        tracing::info!(
            "secrets migration: completed — {migrated} credential(s) migrated to secret store"
        );
    }

    Ok(migrated)
}
