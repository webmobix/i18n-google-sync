# Repository Guidelines

## Project Structure & Module Organization
`src/main.rs` holds the CLI entry point; domain-specific logic lives in `src/auth`, `src/files`, `src/sheets`, `src/sync`, and `src/utils`, with shared config in `src/config.rs`. Planning notes sit in `doc/plan.md`. Translation fixtures belong under `locales/<lang>/<namespace>.json`; keep samples lean so sync runs stay quick. Ignore Cargo outputs in `target/`.

## Build, Test, and Development Commands
Run `cargo fmt` before every commit and `cargo check` for fast feedback; use `cargo build` only when you need binaries. Keep the lint budget clean with `cargo clippy -- -D warnings`. Execute `cargo test` (or a focused target such as `cargo test sync::`) ahead of pull requests. For manual verification, chain `cargo run -- auth` and `cargo run -- sync --sheet-id <id> --dry-run` for the default full sync, or add `--mode add-keys` / `--mode sync-back` when you need one-way behaviour.

## Coding Style & Naming Conventions
Stick to Rust defaults: four-space indentation, `snake_case` symbols, `CamelCase` types, and `SCREAMING_SNAKE_CASE` constants. Extend error enums in `utils::errors` with precise variants. Prefer typed structs and builders instead of ad-hoc tuples when evolving sync flows, and enrich fallible paths with `anyhow::Context`. Add comments sparingly to flag non-obvious OAuth or Sheets quirks.

## Testing Guidelines
Co-locate unit tests inside `#[cfg(test)]` modules; use `tests/` only when you need end-to-end coverage. Name tests after behaviors, e.g., `sync_adds_formula_for_missing_locale`. Debug integration scenarios with `cargo test -- --nocapture` or a dry-run `cargo run -- sync ... --dry-run`. Ensure new code validates auth caches, file discovery, and sync backfills.

## Commit & Pull Request Guidelines
Follow the short typed subjects seen in history (`wip: can add keys`), leaning on Conventional Commit verbs like `feat:` or `refactor:`. Keep subjects ≤72 characters and use the body for rationale, risks, and follow-ups. Pull requests should link issues, list validation commands, and mention impacted sheet IDs or locale sets; attach screenshots or CLI excerpts for user-facing changes.

## Security & Configuration Tips
Keep `client_secret.json` and `tokens.json` in `.i18n-google-sync/` (project root or home directory) and out of version control. Rotate OAuth credentials as teammates join or leave, and redact sheet identifiers from logs before sharing.

## Team Collaboration Notes
Review `CLAUDE.md` before deep changes; it captures production expectations (non-interactive sync, scope validation, batch behavior). Coordinate roadmap updates through `doc/plan.md` so agents share the same assumptions. When adding new flows, document dry-run usage or credential implications in both the PR and this guide if practices shift.
