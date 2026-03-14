# ZeroClaw Secrets System — Design

## Problem

Bots need to use third-party API credentials (Gmail, weather services, etc.)
without those credentials ever passing through the LLM context. Currently
there's no way to store or retrieve arbitrary secrets — only the provider API
key and bot token are managed by ZeroClaw's onboard flow, stored directly in
`config.toml`.

Non-technical users need a simple way to add credentials when their bot asks
for them, and bot-built integration scripts need a way to retrieve them at
runtime without the LLM being involved.

There is also a longer-term goal of unifying all credential storage — including
the existing provider API key and channel tokens — through the same abstraction,
so secrets management is one auditable path rather than two.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  LLM (native Rust tools): secrets_set / secrets_list /      │
│                           secrets_delete / secrets_inject   │
│  CLI: zeroclaw secrets set|get|list|delete|inject|rotate-key│
│                           │                                 │
│                           ▼                                 │
│                   SecretRegistry                            │
│      (ordered stores; reads cascade, writes → first)        │
│                           │                                 │
│          ┌────────────────┴──────────────────┐              │
│          ▼                                   ▼              │
│   LocalSecretStore                  ExternalSecretStore     │
│   (.secrets, encrypted blob)        (provider binary, stdio)│
└─────────────────────────────────────────────────────────────┘
```

Two interfaces, one registry. The LLM calls secrets operations as native Rust
tools (no subprocess, no allowlist concern). The CLI exposes the same
operations for human and script use. Both go through the `SecretRegistry`,
which resolves the target store by name and delegates to the appropriate
`SecretStore` backend.

---

## The SecretStore Trait and SecretRegistry

```rust
trait SecretStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<String>;
    async fn set(&self, key: &str, value: &str) -> Result<()>;
    async fn list(&self) -> Result<Vec<String>>;
    async fn delete(&self, key: &str) -> Result<()>;
}

struct SecretRegistry {
    // Ordered — config order is precedence order for reads
    stores: Vec<(String, Box<dyn SecretStore>)>,
}

impl SecretRegistry {
    /// Reads: cascade through all stores in order, return first hit.
    /// If store name is given, skip cascade and target that store directly.
    async fn get(&self, key: &str, store: Option<&str>) -> Result<String> {
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

    /// Writes: target first store by default, or explicit name.
    async fn set(&self, key: &str, value: &str, store: Option<&str>) -> Result<()> {
        self.named_or_first(store)?.set(key, value).await
    }

    fn named(&self, name: &str) -> Result<&dyn SecretStore> {
        self.stores.iter()
            .find(|(n, _)| n == name)
            .map(|(_, s)| s.as_ref())
            .ok_or_else(|| anyhow!("unknown secret store: {name}"))
    }

    fn named_or_first(&self, name: Option<&str>) -> Result<&dyn SecretStore> {
        match name {
            Some(n) => self.named(n),
            None => self.stores.first()
                .map(|(_, s)| s.as_ref())
                .ok_or_else(|| anyhow!("no secret stores configured")),
        }
    }
}
```

All CLI commands and LLM tools go through `SecretRegistry`.

**Reads (get, inject):** cascade through stores in config order, return first
hit. No store name required for the common case.

**Writes (set, delete):** target the first store in the list unless `--store`
is explicitly given.

**Explicit targeting:** `--store <name>` (CLI) or `store` parameter (LLM
tool) available on all operations.

Config order is precedence order for reads. If the same key exists in
multiple stores, the first store wins. This is intentional — document it
clearly so users understand shadowing behavior.

Default write target resolution:
1. Explicit `--store <name>` / `store` parameter
2. First store in `[[secrets.stores]]`
3. Zero-config fallback: implicit `local` store

---

## Backend: `local` (default)

### Storage

Secrets are stored in a separate `.secrets` file (not `config.toml`), mode
600. The file contains a **single encrypted blob** — all secrets serialized as
JSON, then encrypted with ChaCha20 using ZeroClaw's existing key derivation.

```
# .secrets
secrets1:aGVsbG8gd29ybGQ...
```

The `secrets1:` prefix versions the format, following the existing `enc2:`
pattern so future format changes have a migration hook.

**Why a single blob instead of per-key encryption:**
- An attacker who exfiltrates the file sees one opaque blob — no key names,
  no structure, no enumerable surface
- Atomic writes: decrypt → mutate JSON → encrypt → write. No partial state.
- Single encryption/decryption surface, easier to audit.

The internal JSON before encryption looks like:

```json
{
  "GMAIL_KEY": "sk-abc123...",
  "WEATHER_API_KEY": "some-key",
  "__ANTHROPIC_API_KEY": "sk-ant-...",
  "__TELEGRAM_TOKEN": "123456:ABC..."
}
```

### Reserved Keys

Internal ZeroClaw credentials (provider API key, channel tokens) are migrated
into the secret store under reserved `__`-prefixed keys. This unifies all
credential storage through one path. The `list` command omits `__` keys by
default; a `--all` flag shows them.

### Config

```toml
[[secrets.stores]]
name = "local"
backend = "local"
store_path = ".secrets"   # optional, default shown
```

---

## Backend: `external`

For users who want to integrate an external credential store — a password
manager, a cloud secrets service, a custom sidecar, anything — without
modifying ZeroClaw's source code.

ZeroClaw spawns a configured provider binary on each secret operation and
communicates via a simple **JSON stdio protocol**. This binary IS the storage
backend — it is called by ZeroClaw's `SecretStore` implementation whenever
anything (CLI, native tool, inject) needs to read or write a secret.

### Protocol

ZeroClaw writes one JSON line to stdin, reads one JSON line from stdout.

**Request format:**
```json
{"action": "get",    "key": "GMAIL_KEY"}
{"action": "set",    "key": "GMAIL_KEY", "value": "sk-abc123..."}
{"action": "list"}
{"action": "delete", "key": "GMAIL_KEY"}
```

**Response format:**
```json
{"ok": true, "value": "sk-abc123..."}                        // get
{"ok": true}                                                  // set / delete
{"ok": true, "keys": ["GMAIL_KEY", "WEATHER_API_KEY"]}       // list
{"ok": false, "error": "key not found"}
```

The binary can be written in any language. ZeroClaw spawns it per operation
by default; a keep-alive mode can be added later via config if latency becomes
a concern.

### Config

```toml
[[secrets.stores]]
name = "bitwarden"
backend = "external"
provider_binary = "~/.zeroclaw/providers/bitwarden-provider"
```

Multiple stores can coexist — one local, one external, whatever combination
makes sense. **Config order is precedence order**: reads cascade top to
bottom, the first store is the default write target.

```toml
[[secrets.stores]]
name = "local"
backend = "local"
store_path = ".secrets"         # reads tried first; writes go here by default

[[secrets.stores]]
name = "bitwarden"
backend = "external"
provider_binary = "~/.zeroclaw/providers/bitwarden-provider"

[[secrets.stores]]
name = "work-vault"
backend = "external"
provider_binary = "~/.zeroclaw/providers/hashicorp-vault-provider"
```

### Extension Story

This is how agents and users add new secret backends without touching ZeroClaw
source:

1. Write a provider binary (script, compiled binary, anything executable)
2. Drop it somewhere on the filesystem
3. Set `backend = "external"` and `provider_binary = "/path/to/it"` in
   `config.toml`

A skill can ship a provider binary as an asset and document exactly what to
put in `config.toml`. A power user can implement the `SecretStore` trait in
Rust and upstream a PR or compile locally — the external protocol and the
Rust trait implement the same contract from different angles.

Trivial cases like a sidecar secrets server on the Docker network need nothing
more than a short shell script that curls the server as the provider binary.
There is no reason to build sidecar support into ZeroClaw itself.

### Security Note

The `provider_binary` path must be treated as trusted config. If an attacker
can modify `config.toml`, they can redirect secret operations to an arbitrary
binary. This is equivalent in risk profile to the existing `allowed_commands`
config. Document clearly; don't over-engineer it.

---

## CLI Interface

All commands accept an optional `--store <name>` flag to target a specific
named store. If omitted, the default store is used.

```
zeroclaw secrets set <key> <value> [--store <name>]
zeroclaw secrets get <key>         [--store <name>]
zeroclaw secrets list [--all]      [--store <name>]
zeroclaw secrets delete <key>      [--store <name>]
zeroclaw secrets inject <file>     [--store <name>]
zeroclaw secrets rotate-key        [--store <name>]
zeroclaw secrets stores                              # list configured store names and backends
```

### `get`

- Prints the raw value to stdout, nothing else
- Exit code 0 on success, non-zero if not found
- Controlled by `cli_get_enabled` (see Configuration)
- Designed for script capture: `API_KEY=$(zeroclaw secrets get GMAIL_KEY)`

### `inject`

Reads a file (or stdin if `-` is passed), substitutes all `{{secret:KEY}}`
tokens with their stored values, writes the result to stdout. The file is
never modified on disk.

```bash
zeroclaw secrets inject ~/script.js | node
zeroclaw secrets inject ~/script.py | python3
zeroclaw secrets inject ~/config.json | curl -d @- https://api.example.com
cat template.sh | zeroclaw secrets inject | bash
```

**Token syntax:**

```
{{secret:KEY}}                 — cascade through stores in config order
{{secret@storename:KEY}}       — target a specific named store explicitly
```

The `@storename` qualifier sits between the `secret` namespace and the `:`
delimiter so the key itself is always everything after `:`. This avoids
ambiguity even if a key value would otherwise look like it contains an `@`.

```python
api_key    = "{{secret:GMAIL_KEY}}"                  # default cascade
vault_key  = "{{secret@work-vault:VAULT_TOKEN}}"     # explicit store
```

The model writes a script file containing `{{secret:KEY}}` tokens instead of
real values. The inject command substitutes at execution time. Secret values
never appear in the script file on disk, and the model never receives them
in a tool result.

### `stores`

Lists all configured store names, their backends, and which is the default:

```
NAME         BACKEND    DEFAULT
local        local      yes
bitwarden    external
work-vault   external
```

**Key naming:**
- Alphanumeric + underscores only — no `@`, no `:`, no other special characters
- `@` and `:` are reserved as token syntax delimiters; keys containing them are rejected at set time
- Auto-normalized to uppercase
- `__` prefix reserved for internal ZeroClaw credentials

---

## Native LLM Tools

ZeroClaw registers the following secret operations as native Rust tools:

```
secrets_set(key, value, store?)    Store a secret (e.g. user provides a key in conversation)
secrets_list(store?)               List available key names
secrets_delete(key, store?)        Remove a secret
secrets_inject(content, store?)    Substitute {{secret:KEY}} tokens in a string, return result
secrets_stores()                   List configured store names and backends
```

The `store` parameter is optional on all operations. If omitted, the default
store is used. `secrets_stores()` gives the model visibility into what backends
are available so it can make informed choices.

`secrets_get` is **not** registered as an LLM tool by default. Secret values
reach scripts and integrations through `inject` or through scripts that call
the CLI directly — not by flowing back through the model's context window.

All tools call `SecretRegistry::resolve()` directly — no subprocess, no
allowlist configuration required.

---

## How Scripts and Skills Access Secrets

### Script written by the model, piped through inject

The model writes a script using `{{secret:KEY}}` tokens and runs it through
`inject`:

```bash
zeroclaw secrets inject ~/script.js | node
```

The model authors the integration without ever receiving secret values.

### Script written by the model, run by the user

The model writes the script to use the CLI directly at runtime:

```python
import subprocess

def get_secret(key):
    result = subprocess.run(
        ["zeroclaw", "secrets", "get", key],
        capture_output=True, text=True
    )
    return result.stdout.strip()

api_key = get_secret("GMAIL_KEY")
```

Same pattern works in any language. The model writes this boilerplate; the
secret retrieval happens inside the script process at runtime.

### Native Rust skill

The skill calls `SecretStore::get()` directly as a function call in Rust.
The model invokes the skill as a tool — it never needs to know what credentials
the skill uses internally:

```rust
// Model calls: send_email(to="...", subject="...", body="...")
// Skill implementation:
let api_key = secret_store.get("GMAIL_KEY").await?;
let client = GmailClient::new(api_key);
client.send(...).await
```

### External provider binary

The binary calls the CLI or uses the stdio protocol to retrieve what it needs.
ZeroClaw does not inject secrets into spawned processes automatically — the
binary is responsible for its own retrieval via the CLI or its own backend
protocol.

---

## Configuration

```toml
# Zero-config default: if no [[secrets.stores]] are defined, ZeroClaw
# behaves as if a single local store exists at the default .secrets path.

# Controls whether `zeroclaw secrets get` is enabled.
# Default false: use inject or have scripts call the CLI from within their
# own process. Set true if you need direct raw secret retrieval from the
# shell or from scripts that don't use inject.
# Note: this applies uniformly — there is no separate model vs. human flag.
# If you need to prevent the model from calling `zeroclaw secrets get`,
# ensure `zeroclaw` is not in allowed_commands.
cli_get_enabled = false

# One or more named stores. Config order is precedence order:
# - Reads cascade top to bottom, first hit wins
# - Writes default to the first store unless --store is specified
#
# No special "default" flag needed — position in the list is the contract.

[[secrets.stores]]
name = "local"
backend = "local"
store_path = ".secrets"            # optional

# [[secrets.stores]]
# name = "bitwarden"
# backend = "external"
# provider_binary = "~/.zeroclaw/providers/bitwarden-provider"
```

**Reasonable defaults rationale:**

| Setting | Default | What it protects |
|---|---|---|
| `cli_get_enabled` | `false` | Raw secret retrieval off by default; inject and native skill paths are the intended patterns |
| `secrets_get` LLM tool | not registered | Model doesn't get raw values unless you explicitly build that in |
| `secrets_inject` CLI | always available | Substitution utility, not raw retrieval |
| no stores configured | implicit local store | Zero-config installs work out of the box |

---

## Telegram Slash Command

**Deferred.** The native tool and CLI are sufficient for now. The slash
command (`/secret KEY value`) remains a useful future addition for non-technical
users who need to provide credentials conversationally without the value
hitting the LLM. When implemented:

- Intercept before LLM dispatch
- Parse key + value
- Call `SecretStore::set`
- Reply with confirmation
- Best-effort delete of user's message (not possible in DMs)

---

## Migration from Current Config Storage

ZeroClaw currently encrypts the provider API key and channel tokens directly
into `config.toml`. The migration path:

1. On startup, check for old-style encrypted keys in `config.toml`
2. If found: decrypt using existing logic, re-store via `SecretStore::set`
   under the reserved `__` prefix, remove from `config.toml`, save
3. One-time migration, logged clearly

This follows the precedent of the XOR → ChaCha20 (`enc2:`) migration already
in the codebase.

---

## Implementation Plan

All changes are in the ZeroClaw Rust source. Phases:

### Phase 1: SecretStore trait + SecretRegistry + LocalSecretStore

- `src/secrets/mod.rs` — `SecretStore` trait, `SecretRegistry` (named stores + default resolution)
- `src/secrets/local.rs` — encrypted blob impl (`.secrets` file, `secrets1:` prefix)
- `src/secrets/external.rs` — external process backend (stdio protocol)
- Reuse existing ChaCha20 encryption
- Wire `SecretRegistry` into `AppState` or equivalent so CLI and tool layers share one instance
- Zero-config fallback: if no `[[secrets.stores]]` defined, instantiate a default `LocalSecretStore`

### Phase 2: CLI subcommand

- Add `secrets` subcommand to the `clap` definition
- `set`, `get` (gated by `cli_get_enabled`), `list`, `delete`, `inject`, `rotate-key`, `stores`
- All commands accept `--store <name>` (optional)
- `get` outputs raw value only — designed for script capture
- `inject` reads file or stdin, substitutes `{{secret:KEY}}` and `{{secret@store:KEY}}`, writes to stdout
- `stores` lists configured store names, backends, and default

### Phase 3: Native LLM tools

- Register `secrets_set`, `secrets_list`, `secrets_delete`, `secrets_inject`, `secrets_stores`
  as native tools in ZeroClaw's tool registry
- All accept optional `store` parameter, resolved through `SecretRegistry`
- All call `SecretStore` methods directly — no subprocess

### Phase 4: Migrate existing credential storage

- Detect old-style keys in `config.toml` on startup
- Migrate into `SecretStore` under `__`-prefixed reserved keys
- Remove from `config.toml`, save, log the migration

### Phase 5: Rebuild and deploy

```bash
cd ~/code/research/zeroclaw
docker build --target dev -t zeroclaw-local:latest .
cd ~/bots
docker build -t bot-runtime:latest .
# Recreate bot containers
```

---

## Security Considerations

- Secrets encrypted at rest (ChaCha20, versioned blob format)
- Single blob: no key enumeration without decryption key
- `cli_get_enabled = false` by default — raw retrieval must be explicitly opted into
- No separate model vs. human access distinction — one flag, applied uniformly
- Model access to raw secrets gated by: (a) `secrets_get` not registered as LLM tool,
  (b) `zeroclaw` absent from `allowed_commands` if raw CLI access is a concern
- `inject` is a substitution utility — it writes to stdout, not back to disk
- `list` hides `__` internal keys by default to reduce accidental exposure
- Mode 600 on `.secrets` file; never committed to version control
- `provider_binary` path treated as trusted config — document the risk

---

## Open Questions

1. **Key derivation for local backend** — the existing ChaCha20 uses key
   material derived from the machine/install. Need to trace the onboard flow
   to confirm the key source, since `rotate-key` needs to know what it's
   rotating and migration between machines needs a clear story.

2. **`inject` and missing keys** — if a `{{secret:KEY}}` token appears in
   a file but the key doesn't exist in the target store, should `inject` fail
   loudly (exit non-zero, no output) or substitute an empty string? Fail loudly
   is safer. Same question applies if `{{secret:KEY@storename}}` references an
   unknown store name.

3. **`config.toml` section naming** — `[secrets]` is clean. Confirm it
   doesn't conflict with any existing config keys before committing.

4. **External backend process lifetime** — spawn per-call (default, simpler)
   vs. long-running daemon (faster). Start with per-call; add keep-alive as
   a config option if latency becomes a concern in practice.
