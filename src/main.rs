// Copyright 2025 Webmobix Solutions AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUTHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod auth;
mod config;
mod files;
mod sheets;
mod sync;
mod utils;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use config::{Config, OperationMode};
use std::path::PathBuf;
use tracing::info;

#[derive(Debug, Clone, ValueEnum)]
enum SyncMode {
    AddKeys,
    SyncBack,
    FullSync,
}

impl From<SyncMode> for OperationMode {
    fn from(sync_mode: SyncMode) -> Self {
        match sync_mode {
            SyncMode::AddKeys => OperationMode::AddKeys,
            SyncMode::SyncBack => OperationMode::SyncBack,
            SyncMode::FullSync => OperationMode::FullSync,
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn as_env_filter(&self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Authenticate with Google and save tokens
    Auth {
        /// Custom path to store authentication tokens
        #[arg(long)]
        auth_cache: Option<PathBuf>,

        /// Store tokens in ./.i18n-google-sync/tokens.json
        #[arg(long)]
        local_cache: bool,
    },
    /// Synchronize translations with Google Sheets
    Sync {
        /// Google Sheet ID (required)
        #[arg(long)]
        sheet_id: String,

        /// Sync operation mode
        #[arg(long, value_enum, default_value = "full-sync")]
        mode: SyncMode,

        /// Path to the locales directory
        #[arg(long, default_value = "./locales")]
        locales_path: PathBuf,

        /// Default language code
        #[arg(long, default_value = "en")]
        default_lang: String,

        /// Main language column to flag when creating headers
        #[arg(long, default_value = "en")]
        main_language: String,

        /// Preview changes without applying them
        #[arg(long)]
        dry_run: bool,

        /// Custom path to read authentication tokens
        #[arg(long)]
        token_path: Option<PathBuf>,
    },
}

#[derive(Parser)]
#[command(name = "i18n-google-sync")]
#[command(about = "Synchronize i18next translation files with Google Sheets")]
#[command(version)]
struct Cli {
    /// Controls verbosity of log output (overrides RUST_LOG when provided)
    #[arg(long, value_enum, default_value = "info", global = true)]
    log_level: LogLevel,
    #[command(subcommand)]
    command: Commands,
}

fn init_logging(level: &LogLevel) -> anyhow::Result<()> {
    use tracing_subscriber::{EnvFilter, fmt};

    let env_filter =
        EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(level.as_env_filter()))?;

    fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_level(true)
        .init();

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize default crypto provider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install rustls crypto provider"))?;

    let cli = Cli::parse();
    init_logging(&cli.log_level)?;

    match cli.command {
        Commands::Auth {
            auth_cache,
            local_cache,
        } => {
            handle_auth_command(auth_cache, local_cache).await?;
        }
        Commands::Sync {
            sheet_id,
            mode,
            locales_path,
            default_lang,
            main_language,
            dry_run,
            token_path,
        } => {
            handle_sync_command(
                sheet_id,
                mode,
                locales_path,
                default_lang,
                main_language,
                dry_run,
                token_path,
            )
            .await?;
        }
    }

    Ok(())
}

async fn handle_auth_command(auth_cache: Option<PathBuf>, local_cache: bool) -> anyhow::Result<()> {
    info!("🔑 Starting authentication flow");

    // Determine where to save tokens based on flags
    let token_cache_path = if local_cache {
        let local_cache_dir = PathBuf::from("./.i18n-google-sync");

        // Create the local cache directory if it doesn't exist
        if !local_cache_dir.exists() {
            info!("📁 Creating directory: {}", local_cache_dir.display());
            std::fs::create_dir_all(&local_cache_dir).with_context(|| {
                format!("Failed to create directory: {}", local_cache_dir.display())
            })?;
        }

        let local_path = local_cache_dir.join("tokens.json");
        info!(
            "📁 Will save tokens to local directory: {}",
            local_path.display()
        );
        Some(local_path)
    } else if let Some(path) = auth_cache {
        // Validate custom path directory exists or can be created
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            info!("📁 Creating directory: {}", parent.display());
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
        }
        info!("📁 Will save tokens to custom location: {}", path.display());
        Some(path)
    } else {
        // Default to home directory
        let home_dir = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .with_context(|| "Cannot determine home directory. Use --auth-cache to specify a custom location.")?;

        let cache_dir = PathBuf::from(home_dir).join(".i18n-google-sync");

        // Create the cache directory if it doesn't exist
        if !cache_dir.exists() {
            info!("📁 Creating directory: {}", cache_dir.display());
            std::fs::create_dir_all(&cache_dir)
                .with_context(|| format!("Failed to create directory: {}", cache_dir.display()))?;
        }

        let token_path = cache_dir.join("tokens.json");
        info!(
            "📁 Will save tokens to home directory: {}",
            token_path.display()
        );
        Some(token_path)
    };

    let auth_manager = auth::AuthManager::new(token_cache_path.clone());

    match auth_manager.authenticate().await {
        Ok(()) => {
            info!("✅ Authentication completed successfully");
            if let Some(path) = token_cache_path {
                info!("💾 Tokens saved to: {}", path.display());
                info!("You can now run sync commands:");
                info!("  cargo run -- sync add-keys --sheet-id YOUR_SHEET_ID");
                info!("  cargo run -- sync sync-back --sheet-id YOUR_SHEET_ID");
                info!("  cargo run -- sync full-sync --sheet-id YOUR_SHEET_ID");
            }
        }
        Err(err) => {
            anyhow::bail!(
                "❌ Authentication failed: {}\n\n\
                Troubleshooting tips:\n\
                • Make sure your browser can access Google authentication\n\
                • Check that Google Sheets API is enabled in your Google Cloud project\n\
                • Ensure you have permissions to the target Google Sheet\n\
                • Try using a custom client_secret.json file",
                err
            );
        }
    }

    Ok(())
}

async fn handle_sync_command(
    sheet_id: String,
    mode: SyncMode,
    locales_path: PathBuf,
    default_lang: String,
    main_language: String,
    dry_run: bool,
    token_override: Option<PathBuf>,
) -> anyhow::Result<()> {
    if dry_run {
        info!("🔍 Running in dry-run mode - no changes will be made");
    }

    info!("📁 Locales path: {:?}", locales_path);
    info!("📊 Sheet ID: {}", sheet_id);
    info!("🌐 Default language: {}", default_lang);
    info!("⭐ Main language: {}", main_language);
    info!("⚙️ Mode: {:?}", mode);

    // Step 1: Validate locales directory first (faster to fail early)
    if !locales_path.exists() {
        anyhow::bail!(
            "❌ Locales directory not found: {:?}\n\n\
            Please create the locales directory with translation files.\n\
            Expected structure:\n\
            {:?}/\n\
            ├── en/\n\
            │   ├── common.json\n\
            │   └── auth.json\n\
            ├── fr/\n\
            │   ├── common.json\n\
            │   └── auth.json\n\
            └── ...",
            locales_path,
            locales_path
        );
    }

    if !locales_path.is_dir() {
        anyhow::bail!(
            "❌ Locales path is not a directory: {:?}\n\
            Please provide a valid directory path containing translation files.",
            locales_path
        );
    }

    // Quick check: does the directory contain any language subdirectories?
    let has_language_dirs = std::fs::read_dir(&locales_path)?
        .filter_map(|entry| entry.ok())
        .any(|entry| {
            entry.path().is_dir() && entry.file_name().to_string_lossy().len() >= 2 // Basic language code check
        });

    if !has_language_dirs {
        anyhow::bail!(
            "❌ No language directories found in: {:?}\n\n\
            Expected structure with language directories (e.g., 'en', 'fr', 'es'):\n\
            {:?}/\n\
            ├── en/     ← language directories\n\
            ├── fr/\n\
            └── es/",
            locales_path,
            locales_path
        );
    }

    // Step 2: Resolve authentication tokens using shared helper
    let token_path = auth::AuthManager::resolve_token_path(token_override)?;

    // Create config for sync operations
    let config = Config::new(
        locales_path,
        sheet_id,
        default_lang,
        main_language,
        mode.into(),
        dry_run,
    );

    config.validate()?;

    // Execute the selected operation mode without authentication
    match config.mode {
        OperationMode::AddKeys => {
            let add_keys_mode = sync::AddKeysMode::new();
            add_keys_mode.execute(&config, token_path.clone()).await?;
        }
        OperationMode::SyncBack => {
            let sync_back_mode = sync::SyncBackMode::new();
            sync_back_mode.execute(&config, token_path.clone()).await?;
        }
        OperationMode::FullSync => {
            let full_sync_mode = sync::FullSyncMode::new();
            full_sync_mode.execute(&config, token_path).await?;
        }
    }

    Ok(())
}
