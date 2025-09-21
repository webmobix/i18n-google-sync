# i18n Translation Sync to Google Sheets

A powerful Rust command-line tool that synchronizes **i18next** translation JSON files with Google Sheets, providing seamless bidirectional translation management with automatic Google Translate integration.

## ⚡ Quick Start

The tool uses a **two-step workflow**: authenticate once, then sync many times.

```bash
# Step 1: Authenticate (one-time setup)
cargo run -- auth

# Step 2: Sync operations (use as needed)
# Default: add new keys then pull translations back
cargo run -- sync --sheet-id "your-google-sheet-id" --dry-run
cargo run -- sync --sheet-id "your-google-sheet-id"

# Optional: mark a different language as the main column during the first run
cargo run -- sync --sheet-id "your-google-sheet-id" --main-language "fr"

# Optional one-way modes
cargo run -- sync --mode add-keys --sheet-id "your-google-sheet-id"
cargo run -- sync --mode sync-back --sheet-id "your-google-sheet-id"
```

This approach is **secure**, **CI-friendly**, and **efficient** for team workflows.

## 🚀 Features

- **📁 Smart File Detection**: Automatically discovers i18next translation files in `/locales/$lang/$namespace.json` structure
- **🔄 Bidirectional Sync**: Add new translation keys to sheets or sync translated content back to JSON files
- **🌐 Google Translate Integration**: Automatically generates `=GOOGLETRANSLATE()` formulas for missing translations
- **⭐ Main Language Flagging**: Tag the primary language column (e.g., `en (main)`) on the very first sheet setup via `--main-language`
- **🔑 Secure Authentication**: Browser-based OAuth2 flow with secure token caching
- **📊 Organized Sheets**: Each namespace becomes a separate sheet tab with proper column structure
- **🔍 Dry-Run Mode**: Preview all changes before applying them
- **⚡ Duplicate Prevention**: Intelligent checking to avoid duplicate entries
- **🛡️ Robust Error Handling**: Comprehensive validation and user-friendly error messages

## 📋 Sheet Structure

The tool organizes your translations in Google Sheets as follows:

| Column A | Column B | Column C | Column D | Column E |
|----------|----------|----------|----------|----------|
| **Translation Key** | **Description** | **Main Language (e.g., en (main))** | **Language 2 (e.g., fr)** | **Language 3 (e.g., de)** |
| `auth.login.title` | *(not synced)* | `Login` | `=GOOGLETRANSLATE(C2,"en","fr")` | `=GOOGLETRANSLATE(C2,"en","de")` |
| `auth.login.button` | *(not synced)* | `Sign In` | `Se connecter` | `Anmelden` |

- **Column A**: Translation keys (dot notation supported, e.g., `auth.login.title`)
- **Column B**: Descriptions (preserved, not synced)
- **Column C+**: Languages with the default language first (tagged as `(<lang> (main))` the very first time headers are created) and other locales ordered deterministically without disrupting existing columns
- **Separate Tabs**: Each namespace (e.g., `common`, `auth`, `dashboard`) gets its own sheet tab

## 🎯 Operation Modes

### 1. Add Keys Mode (`--mode add-keys`)
- Scans local translation files for new keys
- Adds missing keys to Google Sheets
- Populates default language values
- Generates `=GOOGLETRANSLATE()` formulas for other languages

### 2. Sync Back Mode (`--mode sync-back`)
- Reads translated values from Google Sheets
- Updates local JSON files with translations
- Extracts actual translated text (not formulas)
- Preserves JSON file structure and formatting

### 3. Full Sync Mode (`--mode full-sync`)
- Default behaviour when `--mode` is omitted
- Combines both add-keys and sync-back operations in a single run
- Ensures Google Translate formulas populate before local files are updated
- Handles conflicts intelligently

## 🔐 Prerequisites: Google Cloud Setup

Before using this tool, you need to set up Google Cloud credentials. The tool requires **two types of files**:

1. **`client_secret.json`** - OAuth2 app credentials from Google Cloud
2. **`tokens.json`** - User authentication tokens (created by the tool)

### 📋 Required Setup Steps

#### Step 1: Create Google Cloud Project

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the **Google Sheets API**:
   - Navigate to "APIs & Services" > "Library"
   - Search for "Google Sheets API"
   - Click "Enable"

#### Step 2: Create OAuth2 Credentials

1. Go to "APIs & Services" > "Credentials"
2. Click "Create Credentials" > "OAuth client ID"
3. If prompted, configure the OAuth consent screen:
   - Choose "External" user type
   - Fill in required fields (App name, User support email, Developer contact)
   - Add your email to test users
4. Choose **"Desktop application"** as the application type
5. Name your OAuth2 client (e.g., "i18n Sync Tool")
6. **Download the JSON file** - this is your `client_secret.json`

#### Step 3: Place Credentials File

The tool searches for `client_secret.json` in this order:

1. **Local directory**: `./.i18n-google-sync/client_secret.json`
2. **Home directory**: `~/.i18n-google-sync/client_secret.json`
3. **Fail** if neither found

**Recommended approach:**

```bash
# Option A: Place in project directory (per-project credentials)
mkdir -p ./.i18n-google-sync
cp ~/Downloads/client_secret_*.json ./.i18n-google-sync/client_secret.json

# Option B: Place in home directory (global credentials)
mkdir -p ~/.i18n-google-sync
cp ~/Downloads/client_secret_*.json ~/.i18n-google-sync/client_secret.json
```

#### Step 4: Test Your Setup

```bash
# Test with dry-run to verify credentials work
cargo run -- auth
cargo run -- sync add-keys --sheet-id "your-google-sheet-id" --dry-run
```

### 🔄 Two-Step Authentication Process

#### Step 1: Authenticate (One-time setup)

```bash
# Default: Store tokens in home directory (~/.i18n-google-sync/tokens.json)
cargo run -- auth

# Local: Store tokens in project directory (./.i18n-google-sync/tokens.json)
cargo run -- auth --local-cache

# Custom: Store tokens at specific location
cargo run -- auth --auth-cache /path/to/tokens.json
```

**What happens during authentication:**
1. Tool finds your `client_secret.json` file
2. Opens your browser to Google's consent page
3. You grant permission to access Google Sheets
4. Tool receives and stores authentication tokens

#### Step 2: Use Sync Operations

```bash
# Tokens are automatically found and used
cargo run -- sync add-keys --sheet-id "your-sheet-id" --main-language "en"
cargo run -- sync sync-back --sheet-id "your-sheet-id"
cargo run -- sync full-sync --sheet-id "your-sheet-id"
```

### 🗂️ File Storage Locations

The tool manages two types of files in consistent locations:

#### Client Credentials (`client_secret.json`)
Search order:
1. `./.i18n-google-sync/client_secret.json` (local directory)
2. `~/.i18n-google-sync/client_secret.json` (home directory)

#### Authentication Tokens (`tokens.json`)
Search order:
1. Custom path (if `--token-path` specified)
2. `./.i18n-google-sync/tokens.json` (local directory)
3. `~/.i18n-google-sync/tokens.json` (home directory)

### 🛡️ Security Features

- **Local Storage Only**: All credentials stored locally on your machine
- **Token Expiration**: Automatic token refresh when expired
- **No Hardcoded Secrets**: Requires your own Google Cloud credentials
- **Secure OAuth2 Flow**: Uses Google's standard authentication process

### 🚨 Troubleshooting

**"client_secret.json not found" error:**
```bash
# Make sure you have the file in one of these locations:
ls ./.i18n-google-sync/client_secret.json
ls ~/.i18n-google-sync/client_secret.json
```

**"No authentication tokens found" error:**
```bash
# Run the auth command first:
cargo run -- auth
```

**"Invalid client" error:**
- Ensure Google Sheets API is enabled in your Google Cloud project
- Verify your `client_secret.json` is valid and properly formatted
- Check that your OAuth2 app is configured for "Desktop application"

**Browser doesn't open automatically:**
- Copy the displayed URL and manually paste it in your browser

## 📦 Installation

### Prerequisites

- [Rust](https://rustup.rs/) (1.70 or later)
- Git
- A Google account with access to Google Sheets

### Build from Source

```bash
# Clone the repository
git clone https://github.com/your-org/i18n_google_sync.git
cd i18n_google_sync

# Build the project
cargo build --release

# The binary will be available at target/release/i18n_google_sync
```

### Development Build

```bash
# Clone and build for development
git clone https://github.com/your-org/i18n_google_sync.git
cd i18n_google_sync

# Run directly with Cargo
cargo run -- --help
```

## 🎮 Usage

### Command Line Interface

The tool now uses a **two-step workflow**: authenticate first, then sync. This approach is more secure and CI-friendly.

#### Authentication Command

```bash
i18n-google-sync auth [OPTIONS]

Options:
  --auth-cache <PATH>     Custom path to store authentication tokens
  --local-cache           Store tokens in ./.i18n-google-sync/tokens.json
  -h, --help             Print help
```

#### Sync Commands

```bash
i18n-google-sync sync [OPTIONS] --sheet-id <SHEET_ID>

Options:
  --sheet-id <SHEET_ID>     Google Sheet ID (required)
  --mode <MODE>             Sync operation mode [default: add-keys]
                           [possible values: add-keys, sync-back, full-sync]
  --locales-path <PATH>     Path to locales directory [default: ./locales]
  --default-lang <LANG>     Default language code [default: en]
  --dry-run                 Preview changes without applying them
  --token-path <PATH>       Custom path to read authentication tokens
  -h, --help               Print help
```

### Two-Step Workflow

#### Step 1: Authenticate (Once)

```bash
# Authenticate and store tokens in home directory (default)
cargo run -- auth

# Store tokens in local project directory
cargo run -- auth --local-cache

# Store tokens at custom location
cargo run -- auth --auth-cache ~/.config/i18n-sync/tokens.json
```

#### Step 2: Sync Operations (Many Times)

```bash
# Add new translation keys to Google Sheets (dry-run)
cargo run -- sync add-keys --sheet-id "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms" --dry-run

# Add keys for real
cargo run -- sync add-keys --sheet-id "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms"

# Sync translations back to local files
cargo run -- sync sync-back --sheet-id "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms"

# Full bidirectional sync
cargo run -- sync full-sync --sheet-id "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms"

# Use custom locales directory
cargo run -- sync add-keys --sheet-id "your-sheet-id" --locales-path /path/to/translations

# Spanish as default language
cargo run -- sync add-keys --sheet-id "your-sheet-id" --default-lang es

# Use custom token location
cargo run -- sync add-keys --sheet-id "your-sheet-id" --token-path /path/to/tokens.json
```

### Token Discovery

The tool automatically searches for authentication tokens in this order:

1. **Custom path** (if `--token-path` specified)
2. **Local directory**: `./.i18n-google-sync/tokens.json`
3. **Home directory**: `~/.i18n-google-sync/tokens.json`
4. **Fail** if none found

This allows you to authenticate once and run multiple sync operations without re-authentication.

### Expected File Structure

Your i18next files should follow this structure:

```
locales/
├── en/
│   ├── common.json
│   ├── auth.json
│   └── dashboard.json
├── fr/
│   ├── common.json
│   ├── auth.json
│   └── dashboard.json
└── de/
    ├── common.json
    ├── auth.json
    └── dashboard.json
```

Example `locales/en/auth.json`:
```json
{
  "login": {
    "title": "Sign In",
    "button": "Login",
    "forgot_password": "Forgot Password?"
  },
  "register": {
    "title": "Create Account",
    "button": "Sign Up"
  }
}
```

### Google Sheet ID

To find your Google Sheet ID:

1. Open your Google Sheet in a browser
2. Look at the URL: `https://docs.google.com/spreadsheets/d/SHEET_ID/edit`
3. Copy the `SHEET_ID` part (between `/d/` and `/edit`)

Example: `1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms`

## 💡 Workflow Examples

### Scenario 1: New Project Setup

```bash
# 1. Create your translation files
mkdir -p locales/en locales/fr locales/de

# 2. Add some initial translations (locales/en/common.json)
echo '{"hello": "Hello", "goodbye": "Goodbye"}' > locales/en/common.json

# 3. Create a new Google Sheet and get its ID

# 4. Authenticate with Google (one-time setup)
cargo run -- auth

# 5. First sync - add keys to sheet (preview first)
cargo run -- sync add-keys --sheet-id "your-sheet-id" --dry-run

# 6. Apply the changes
cargo run -- sync add-keys --sheet-id "your-sheet-id"

# 7. Google Translate will auto-generate translations in the sheet
# 8. Sync back the translated content
cargo run -- sync sync-back --sheet-id "your-sheet-id"
```

### Scenario 2: Adding New Features

```bash
# 1. Add new translation keys to your JSON files
# locales/en/auth.json: {"login": {"title": "Sign In", "button": "Login"}}

# 2. Preview what will be added to the sheet
cargo run -- sync add-keys --sheet-id "your-sheet-id" --dry-run

# 3. Add the new keys
cargo run -- sync add-keys --sheet-id "your-sheet-id"

# 4. Check Google Sheets - new translations should appear with GOOGLETRANSLATE formulas
# 5. After translations are processed, sync back
cargo run -- sync sync-back --sheet-id "your-sheet-id"
```

### Scenario 3: Translator Workflow

```bash
# 1. Translator updates translations directly in Google Sheets
# 2. Developer syncs changes back to code

# Preview what will be updated
cargo run -- sync sync-back --sheet-id "your-sheet-id" --dry-run

# Apply the changes
cargo run -- sync sync-back --sheet-id "your-sheet-id"

# 3. Commit the updated JSON files to version control
git add locales/
git commit -m "Update translations from Google Sheets"
```

### Scenario 4: CI/CD Pipeline

```bash
# In your CI/CD pipeline, you can authenticate once and then run multiple operations

# 1. Authenticate and store tokens for the pipeline
cargo run -- auth --local-cache

# 2. Add any new keys from feature branches
cargo run -- sync add-keys --sheet-id "your-sheet-id"

# 3. Sync back the latest translations for deployment
cargo run -- sync sync-back --sheet-id "your-sheet-id"

# 4. The tokens are automatically found in the local cache
# No need to re-authenticate for subsequent commands
```

### Scenario 5: Team Collaboration

```bash
# Each team member authenticates once on their machine
cargo run -- auth  # Stores tokens in home directory

# Everyone can then sync using the same commands
cargo run -- sync add-keys --sheet-id "shared-sheet-id"
cargo run -- sync sync-back --sheet-id "shared-sheet-id"

# Or use project-specific tokens for different projects
cargo run -- auth --local-cache  # Per-project authentication
```

## 🔧 Development

### Running Tests

```bash
# Run all tests
cargo test

# Run specific module tests
cargo test auth
cargo test config

# Run tests with output
cargo test -- --nocapture
```

### Project Structure

```
src/
├── main.rs              # CLI entry point
├── config.rs            # Configuration management
├── auth/
│   ├── mod.rs           # Authentication module
│   └── oauth.rs         # OAuth2 implementation
├── files/
│   ├── mod.rs           # File operations
│   ├── parser.rs        # JSON parsing
│   └── writer.rs        # JSON writing
├── sheets/
│   ├── mod.rs           # Google Sheets integration
│   ├── manager.rs       # Sheet operations
│   └── translate.rs     # Translation services
├── sync/
│   ├── mod.rs           # Sync operations
│   ├── add_keys.rs      # Add keys mode
│   ├── sync_back.rs     # Sync back mode
│   └── full_sync.rs     # Full sync mode
└── utils/
    ├── mod.rs           # Utilities
    └── errors.rs        # Error types
```

## 🐛 Troubleshooting

### Common Issues

**"Locales path does not exist" error:**
```bash
# Make sure your locales directory exists
mkdir -p locales/en
echo '{"test": "Hello"}' > locales/en/common.json
```

**"Sheet ID cannot be empty" error:**
```bash
# Ensure you provide a valid Google Sheet ID
cargo run -- --sheet-id "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms"
```

**Compilation errors:**
```bash
# Make sure you have the latest Rust version
rustup update
cargo clean
cargo build
```

**Permission denied on auth cache:**
```bash
# Use a writable directory for token cache
cargo run -- --sheet-id "your-id" --auth-cache ~/.config/i18n-sync/tokens.json
```

### Getting Help

1. **Check the help output:**
   ```bash
   cargo run -- --help
   ```

2. **Enable verbose logging:**
   ```bash
   RUST_LOG=debug cargo run -- --sheet-id "your-id" --dry-run
   ```

3. **Test with dry-run first:**
   ```bash
   cargo run -- --sheet-id "your-id" --dry-run
   ```

4. **Verify your setup:**
   - ✅ Google Sheets API is enabled in your Google Cloud project
   - ✅ OAuth2 credentials are properly configured
   - ✅ Your Google account has access to the target sheet
   - ✅ Locales directory exists and contains valid JSON files

## 📝 License

This project is licensed under the Apache-2.0 license - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ⭐ Acknowledgments

- Built with [Rust](https://www.rust-lang.org/)
- Uses [google-sheets4](https://docs.rs/google-sheets4/) for Google Sheets API integration
- OAuth2 implementation with [yup-oauth2](https://docs.rs/yup-oauth2/)
- CLI powered by [clap](https://docs.rs/clap/)

Build with ❤️ by Webmobix
