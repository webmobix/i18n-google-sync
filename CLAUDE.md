# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **production-ready** Rust CLI application that synchronizes i18next translation JSON files with Google Sheets. The system provides bidirectional sync capabilities with automatic Google Translate integration and is designed for team collaboration workflows.

## Core Architecture

The application uses a **two-step workflow**:
1. **Authentication Mode**: Browser-based OAuth2 flow stores tokens securely
2. **Sync Mode**: Non-interactive operations that NEVER trigger browser authentication

### Sync Operation Modes
- **Add Keys Mode** (`--mode add-keys`): Scans local JSON files and adds missing keys to Google Sheets with GOOGLETRANSLATE formulas
- **Sync Back Mode** (`--mode sync-back`): Reads translated values from sheets (including formula results) and updates local files
- **Full Sync Mode** (`--mode full-sync`): Default mode combining both add-keys and sync-back operations

### Authentication Security Model
- **Sync operations are completely non-interactive** - they will fail with clear error messages if tokens are missing/invalid
- **Token validation happens upfront** with detailed scope checking and debug logging
- **Multi-token support** handles multiple token entries with different scopes
- **Required scopes**: `https://www.googleapis.com/auth/spreadsheets` and `https://www.googleapis.com/auth/drive`

## Common Commands

```bash
# Build and development
cargo build
cargo test
cargo run -- --help

# Two-step workflow
cargo run -- auth --local-cache                              # Authenticate (stores tokens)
cargo run -- sync --sheet-id <ID> --mode add-keys --dry-run # Preview adding keys
cargo run -- sync --sheet-id <ID> --mode add-keys           # Add keys to sheets
cargo run -- sync --sheet-id <ID> --mode sync-back --dry-run # Preview sync back
cargo run -- sync --sheet-id <ID> --mode sync-back          # Sync translations back
cargo run -- sync --sheet-id <ID> --mode full-sync          # Both operations

# Testing authentication and API integration
cargo run -- auth --local-cache
cargo run -- sync --sheet-id "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms" --mode add-keys --dry-run

# Debug mode (shows detailed authentication flow)
RUST_LOG=debug cargo run -- sync --sheet-id <ID> --mode add-keys --dry-run
```

## Critical Implementation Details

### Authentication Flow (src/auth/oauth.rs)
- **AuthManager** handles OAuth2 flow with token caching
- **Token validation** checks file format and scopes before any API calls
- **Multi-entry token support** searches through token arrays to find valid combinations
- **Non-interactive mode** in sync operations prevents browser launches

### Google Sheets Integration (src/sheets/manager.rs)
- **SheetsManager** handles all Google Sheets API operations
- **Dynamic range calculation** for sheet structure setup (critical for avoiding API errors)
- **Batch operations** with chunking for large datasets
- **GOOGLETRANSLATE formula generation** for missing translations
- **Empty string detection** - keys with empty values get translation formulas

### Translation Key Management (src/files/parser.rs)
- **TranslationParser** scans locale directories and aggregates keys by namespace
- **Nested JSON support** with dot notation (e.g., `auth.login.title`)
- **Multi-language aggregation** combines keys across all languages into unified objects
- **File structure**: `/locales/$lang/$namespace.json`

### Sync Operations (src/sync/)
- **AddKeysMode**: Adds missing keys from local files to Google Sheets with GOOGLETRANSLATE formulas
- **SyncBackMode**: Reads translated values from sheets (including GOOGLETRANSLATE formula results) and updates local files with backup creation
- **FullSyncMode**: Bidirectional sync combining both operations in sequence

### Sync Back Implementation (Recently Added)
- **Dynamic worksheet discovery** using spreadsheet metadata instead of hardcoded namespaces
- **Dual API calls** to read both `FORMATTED_VALUE` (formula results) and `FORMULA` (to detect GOOGLETRANSLATE usage)
- **Change detection** comparing existing vs new translations with detailed dry-run previews
- **File backup** before modification (`file.json.backup`)
- **Nested JSON structure preservation** while supporting dot notation keys

## Data Flow Architecture

1. **File Discovery**: Parser scans `./locales/$lang/$namespace.json` files
2. **Key Aggregation**: Groups translation keys by namespace across all languages
3. **Sheet Connection**: Authenticates and connects to Google Sheets using stored tokens
4. **Worksheet Management**: Creates/manages separate tabs for each namespace
5. **Sync Operations**: Bidirectional data sync with duplicate prevention
6. **Translation Generation**: Automatic GOOGLETRANSLATE formulas for missing translations

## Critical Error Handling Patterns

### Authentication Errors
- **Token validation first** - checks file format and scopes before API calls
- **Clear error messages** with specific missing scopes and actionable steps
- **Debug logging** shows step-by-step authentication process
- **Never triggers browser** during sync operations

### Google Sheets API Errors
- **Range mismatch prevention** - dynamically calculates sheet ranges
- **Batch operation chunking** handles large datasets
- **Proper scope validation** ensures API permissions are sufficient
- **Context-aware error messages** with troubleshooting guidance

### Translation Logic
- **Empty string detection** - `""` values trigger GOOGLETRANSLATE formulas
- **Missing key handling** - generates translation formulas for absent translations
- **Duplicate prevention** - skips existing keys with detailed logging

## Key Configuration

### Required Google Cloud Setup
- OAuth2 "Desktop application" credentials
- Google Sheets API enabled
- Both `spreadsheets` and `drive` scopes required for full functionality

### File Locations
- **Client credentials**: `./.i18n-google-sync/client_secret.json` or `~/.i18n-google-sync/client_secret.json`
- **Tokens**: `./.i18n-google-sync/tokens.json` or `~/.i18n-google-sync/tokens.json` (auto-discovered)

### Sheet Structure
- Column A: Translation keys (dot notation supported)
- Column B: Descriptions (preserved, not synced)
- Column C+: Languages (default first, others alphabetically)
- Separate tabs for each namespace

## Development Guidelines

### When Working on Authentication
- Always test both auth and sync modes separately
- Ensure sync operations never trigger browser authentication
- Validate token scope requirements match API usage
- Test multi-token scenarios (multiple entries in tokens.json)

### When Working on Google Sheets Integration
- Use dynamic range calculation, never hardcode ranges like "A1:Z1"
- Test with both empty and populated sheets
- Ensure worksheet creation and management works reliably
- Test batch operations with large datasets

### When Working on Translation Logic
- Test empty string detection (`""` vs missing keys)
- Verify GOOGLETRANSLATE formula generation
- Test nested JSON structures with dot notation
- Ensure duplicate prevention works correctly

### Testing Approach
- Use `--dry-run` for safe testing of sheet operations
- Test with real Google Sheets for integration validation
- Verify authentication flow on fresh systems (no cached tokens)
- Test error scenarios (invalid tokens, missing sheets, etc.)

## Production Deployment Notes

- The system is designed for CI/CD pipelines with token pre-authentication
- Sync operations are completely non-interactive and safe for automation
- All operations support dry-run mode for safe preview
- Comprehensive error handling with actionable troubleshooting steps