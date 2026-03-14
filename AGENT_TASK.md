# Agent Task: Implement ZeroClaw Secrets System

Read SECRETS_DESIGN.md first and understand it thoroughly before writing any code.

## Your task

Implement the secrets system in four phases:

### Phase 1: SecretStore trait + SecretRegistry + backends

Create `src/secrets/` module with:
- `src/secrets/mod.rs` — `SecretStore` trait, `SecretRegistry` struct (ordered Vec of named stores, cascading reads, first-store writes). See SECRETS_DESIGN.md for the exact Rust sketches.
- `src/secrets/local.rs` — `LocalSecretStore`: reads/writes a single ChaCha20-encrypted JSON blob to a `.secrets` file. Format prefix `secrets1:`. Reuse existing encryption from the codebase (look at how `migration.rs` and `config/` handle `enc2:` encrypted values — trace that code path and reuse it).
- `src/secrets/external.rs` — `ExternalSecretStore`: spawns a provider binary, communicates via JSON stdio protocol (see SECRETS_DESIGN.md for request/response format).

Config: `[[secrets.stores]]` array in `config.toml`. Each entry has `name`, `backend` (`"local"` or `"external"`), and backend-specific fields. Zero-config fallback: if no stores defined, behave as if a single local store exists at `.secrets`. See SECRETS_DESIGN.md Configuration section for the full TOML shape.

Wire `SecretRegistry` into `AppState` (or wherever the global app state lives) so both CLI and tool layers share one instance.

### Phase 2: CLI subcommand

Add a `secrets` subcommand to the clap CLI with sub-subcommands:
- `set <key> <value> [--store <name>]`
- `get <key> [--store <name>]` — gated by `cli_get_enabled` config flag (default `false`); raw value to stdout only
- `list [--all] [--store <name>]` — omits `__`-prefixed keys unless `--all`
- `delete <key> [--store <name>]`
- `inject <file|-> [--store <name>]` — reads file or stdin, substitutes `{{secret:KEY}}` and `{{secret@storename:KEY}}` tokens, writes to stdout
- `rotate-key [--store <name>]` — re-encrypts the local blob with a new key (local backend only)
- `stores` — lists configured store names, backends, and which is first (write default)

Key naming rules (enforce at `set` time): alphanumeric + underscores only, no `@` or `:`, auto-uppercased, `__` prefix reserved for internal use.

### Phase 3: Native LLM tools

Register these as native Rust tools in ZeroClaw's tool registry (look at how existing tools in `src/tools/` are registered):
- `secrets_set(key, value, store?)`
- `secrets_list(store?)`
- `secrets_delete(key, store?)`
- `secrets_inject(content, store?)` — substitutes `{{secret:KEY}}` tokens in a string, returns result
- `secrets_stores()` — lists configured store names and backends

Do NOT register `secrets_get` — raw value retrieval is intentionally not exposed to the LLM by default.

All tools route through `SecretRegistry` directly.

### Phase 4: Migration of existing credentials

On startup, check `config.toml` for old-style encrypted keys (provider API key, channel tokens — look at what `migration.rs` already handles and follow the same pattern). If found:
1. Decrypt using existing logic
2. Re-store via `SecretStore::set` under `__`-prefixed reserved key names (e.g. `__ANTHROPIC_API_KEY`, `__TELEGRAM_TOKEN`)
3. Remove from `config.toml`
4. Log the migration clearly

## Important notes

- Read SECRETS_DESIGN.md carefully — it has the rationale for every decision
- Trace existing encryption code before writing new crypto — reuse what's there
- `inject` should fail loudly (exit non-zero, no output) if a token references a key or store that does not exist
- Config order is precedence order for reads — document this in code comments
- `cli_get_enabled = false` is the default; the `get` subcommand must check this before proceeding

When completely finished, run:
openclaw system event --text "Done: ZeroClaw secrets system implemented across phases 1-4" --mode now
