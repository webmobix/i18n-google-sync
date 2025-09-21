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

use crate::auth::oauth::AuthManager;
use crate::config::Config;
use crate::files::TranslationParser;
use crate::sheets::SheetsManager;
use anyhow::Result;
use std::collections::HashSet;
use std::path::PathBuf;
use tracing::{debug, info, warn};

pub struct AddKeysMode;

impl AddKeysMode {
    pub fn new() -> Self {
        Self
    }

    pub async fn execute(&self, config: &Config, token_path: PathBuf) -> Result<()> {
        info!("🔄 Executing Add Keys mode");

        let parser = TranslationParser::new();
        let auth_manager = AuthManager::new(Some(token_path));
        let mut sheets_manager = SheetsManager::new(
            config.sheet_id.clone(),
            auth_manager,
            config.main_language.clone(),
        );

        let all_languages = parser.list_languages(&config.locales_path)?;

        // Step 1: Scan local translation files and aggregate by namespace
        let namespace_keys = parser.scan_and_aggregate_by_namespace(&config.locales_path)?;
        info!(
            "📁 Found {} namespaces with translation keys",
            namespace_keys.len()
        );

        if namespace_keys.is_empty() {
            warn!(
                "⚠️  No translation files found in {:?}",
                config.locales_path
            );
            return Ok(());
        }

        // Step 2: Connect to Google Sheet
        sheets_manager.get_or_create_sheet().await?;

        // Step 3: Process each namespace
        let mut total_keys_added = 0;
        for (namespace, keys) in &namespace_keys {
            let keys_added = self
                .process_namespace(namespace, keys, config, &mut sheets_manager, &all_languages)
                .await?;
            total_keys_added += keys_added;
        }

        if config.dry_run {
            info!(
                "🔍 Dry run completed - {} keys would be added across {} namespaces",
                total_keys_added,
                namespace_keys.len()
            );
        } else {
            info!(
                "✅ Add keys operation completed - {} keys added across {} namespaces",
                total_keys_added,
                namespace_keys.len()
            );
        }

        Ok(())
    }

    async fn process_namespace(
        &self,
        namespace: &str,
        local_keys: &[crate::files::parser::TranslationKey],
        config: &Config,
        sheets_manager: &mut SheetsManager,
        all_languages: &[String],
    ) -> Result<usize> {
        info!(
            "🔍 Processing namespace: {} ({} local keys)",
            namespace,
            local_keys.len()
        );

        if local_keys.is_empty() {
            info!("📋 No keys found for namespace '{}', skipping", namespace);
            return Ok(0);
        }

        // Step 1: Get existing keys from sheet to prevent duplicates
        let existing_keys = sheets_manager.read_existing_keys(namespace).await?;
        info!(
            "📊 Found {} existing keys in sheet '{}'",
            existing_keys.len(),
            namespace
        );

        // Step 2: Find new keys that don't already exist in the sheet
        let new_keys = self.find_new_keys(local_keys, &existing_keys);

        // Step 3: Determine language column order without reordering existing headers
        let existing_header_languages = sheets_manager.header_languages(namespace).await?;

        let mut languages: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        let mut append_language = |language: &str| {
            let trimmed = language.trim();
            if trimmed.is_empty() {
                return;
            }

            if seen.insert(trimmed.to_string()) {
                languages.push(trimmed.to_string());
            }
        };

        for language in &existing_header_languages {
            append_language(language);
        }

        append_language(&config.main_language);
        append_language(&config.default_lang);

        for language in all_languages {
            append_language(language);
        }

        for key in &new_keys {
            for language in key.values.keys() {
                append_language(language);
            }
        }

        info!("🌍 Target languages for '{}': {:?}", namespace, languages);

        let new_language_columns: Vec<String> = languages
            .iter()
            .filter(|lang| {
                !existing_header_languages
                    .iter()
                    .any(|existing| existing == *lang)
            })
            .cloned()
            .collect();

        // Step 4: Ensure worksheet exists for this namespace and set up structure
        sheets_manager
            .ensure_worksheet(namespace, &languages)
            .await?;
        sheets_manager
            .setup_sheet_structure(namespace, &languages, &config.main_language)
            .await?;

        let filled_cells = sheets_manager
            .backfill_new_language_columns(
                namespace,
                &languages,
                &new_language_columns,
                &existing_keys,
                local_keys,
                &config.default_lang,
                config.dry_run,
            )
            .await?;

        if !new_language_columns.is_empty() {
            if config.dry_run {
                info!(
                    "🔍 [DRY RUN] Would backfill {} cells for new languages {:?} in '{}'",
                    filled_cells, new_language_columns, namespace
                );
            } else {
                info!(
                    "🔄 Backfilled {} cells for new languages {:?} in '{}'",
                    filled_cells, new_language_columns, namespace
                );
            }
        }

        if new_keys.is_empty() {
            info!(
                "✅ All keys for namespace '{}' already exist in sheet; no new rows required",
                namespace
            );
            return Ok(0);
        }

        info!(
            "🆕 Found {} new keys to add to namespace '{}'",
            new_keys.len(),
            namespace
        );

        // Step 5: Add new keys to sheet
        let keys_added = sheets_manager
            .batch_update_cells(namespace, &new_keys, &languages, config.dry_run)
            .await?;

        if config.dry_run {
            info!(
                "🔍 [DRY RUN] Would add {} keys to namespace '{}'",
                keys_added, namespace
            );
        } else {
            info!("✅ Added {} keys to namespace '{}'", keys_added, namespace);
        }

        Ok(keys_added)
    }

    /// Finds keys that don't already exist in the sheet to prevent duplicates.
    fn find_new_keys(
        &self,
        local_keys: &[crate::files::parser::TranslationKey],
        existing_keys: &std::collections::HashMap<
            String,
            std::collections::HashMap<String, String>,
        >,
    ) -> Vec<crate::files::parser::TranslationKey> {
        local_keys
            .iter()
            .filter(|key| {
                let exists = existing_keys.contains_key(&key.key_path);
                if exists {
                    debug!("⏭️  Skipping duplicate key: {}", key.key_path);
                }
                !exists
            })
            .cloned()
            .collect()
    }
}
