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
use crate::files::TranslationWriter;
use crate::sheets::SheetsManager;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::info;

pub struct SyncBackMode;

impl SyncBackMode {
    pub fn new() -> Self {
        Self
    }

    pub async fn execute(&self, config: &Config, token_path: PathBuf) -> Result<()> {
        info!("🔄 Executing Sync Back mode");

        let auth_manager = AuthManager::new(Some(token_path));
        let mut sheets_manager = SheetsManager::new(
            config.sheet_id.clone(),
            auth_manager,
            config.main_language.clone(),
        );
        let writer = TranslationWriter::new();

        // Step 1: Connect to Google Sheet
        sheets_manager.get_or_create_sheet().await?;

        // Step 2: Discover all worksheets (namespaces) dynamically
        let namespaces = sheets_manager.get_all_worksheets().await?;

        if namespaces.is_empty() {
            info!("📋 No worksheets found with translation data");
            return Ok(());
        }

        // Step 3: Collect all sync operations for preview/execution
        let mut sync_operations = Vec::new();
        let mut total_changes = 0;

        for namespace in &namespaces {
            let operations = self
                .prepare_sync_operations(namespace, config, &mut sheets_manager)
                .await?;
            total_changes += operations.iter().map(|op| op.changes.len()).sum::<usize>();
            sync_operations.extend(operations);
        }

        // Step 4: Show dry-run preview or execute operations
        if config.dry_run {
            self.show_dry_run_preview(&sync_operations, total_changes);
        } else {
            self.execute_sync_operations(&sync_operations, &writer)
                .await?;
            info!(
                "✅ Sync back operation completed - {} files updated with {} changes",
                sync_operations.len(),
                total_changes
            );
        }

        Ok(())
    }

    /// Prepare sync operations for a specific namespace
    async fn prepare_sync_operations(
        &self,
        namespace: &str,
        config: &Config,
        sheets_manager: &mut SheetsManager,
    ) -> Result<Vec<SyncOperation>> {
        info!("🔍 Preparing sync operations for namespace: {}", namespace);

        // Read all translations from sheet (including formula results)
        let sheet_translations = sheets_manager.read_existing_keys(namespace).await?;

        if sheet_translations.is_empty() {
            info!("📋 No translations found in sheet '{}'", namespace);
            return Ok(Vec::new());
        }

        // Group translations by language
        let mut language_translations: HashMap<String, HashMap<String, String>> = HashMap::new();

        for (key, lang_values) in sheet_translations {
            for (language, value) in lang_values {
                language_translations
                    .entry(language)
                    .or_default()
                    .insert(key.clone(), value);
            }
        }

        let mut operations = Vec::new();

        // Create sync operation for each language
        for (language, translations) in language_translations {
            let file_path = config
                .locales_path
                .join(&language)
                .join(format!("{}.json", namespace));

            // Compare with existing file to detect changes
            let changes = self.detect_changes(&file_path, &translations)?;

            if !changes.is_empty() {
                operations.push(SyncOperation {
                    namespace: namespace.to_string(),
                    language,
                    file_path,
                    translations,
                    changes,
                });
            }
        }

        info!(
            "📊 Prepared {} sync operations for namespace '{}'",
            operations.len(),
            namespace
        );
        Ok(operations)
    }

    /// Detect changes between existing file and new translations
    fn detect_changes(
        &self,
        file_path: &PathBuf,
        new_translations: &HashMap<String, String>,
    ) -> Result<Vec<ChangeInfo>> {
        let mut changes = Vec::new();

        // Read existing file if it exists
        let existing_translations = if file_path.exists() {
            let content = fs::read_to_string(file_path)
                .context(format!("Failed to read existing file: {:?}", file_path))?;

            // Parse existing JSON and extract flat key-value pairs
            match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(value) => self.extract_flat_translations(&value, ""),
                Err(_) => HashMap::new(), // Invalid JSON, treat as empty
            }
        } else {
            HashMap::new()
        };

        // Find changes
        for (key, new_value) in new_translations {
            match existing_translations.get(key) {
                Some(old_value) if old_value != new_value => {
                    changes.push(ChangeInfo {
                        key: key.clone(),
                        change_type: ChangeType::Modified,
                        old_value: Some(old_value.clone()),
                        new_value: new_value.clone(),
                    });
                }
                None => {
                    changes.push(ChangeInfo {
                        key: key.clone(),
                        change_type: ChangeType::Added,
                        old_value: None,
                        new_value: new_value.clone(),
                    });
                }
                _ => {
                    // No change needed
                }
            }
        }

        // Find removed keys (exist in file but not in sheet)
        for (key, old_value) in &existing_translations {
            if !new_translations.contains_key(key) {
                changes.push(ChangeInfo {
                    key: key.clone(),
                    change_type: ChangeType::Removed,
                    old_value: Some(old_value.clone()),
                    new_value: String::new(),
                });
            }
        }

        Ok(changes)
    }

    /// Extract flat translations from nested JSON structure
    fn extract_flat_translations(
        &self,
        value: &serde_json::Value,
        prefix: &str,
    ) -> HashMap<String, String> {
        let mut translations = HashMap::new();

        match value {
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    let full_key = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", prefix, key)
                    };

                    match val {
                        serde_json::Value::String(s) => {
                            translations.insert(full_key, s.clone());
                        }
                        serde_json::Value::Object(_) => {
                            translations.extend(self.extract_flat_translations(val, &full_key));
                        }
                        _ => {
                            // Convert other types to string
                            translations.insert(full_key, val.to_string());
                        }
                    }
                }
            }
            serde_json::Value::String(s) => {
                if !prefix.is_empty() {
                    translations.insert(prefix.to_string(), s.clone());
                }
            }
            _ => {
                if !prefix.is_empty() {
                    translations.insert(prefix.to_string(), value.to_string());
                }
            }
        }

        translations
    }

    /// Show comprehensive dry-run preview
    fn show_dry_run_preview(&self, operations: &[SyncOperation], total_changes: usize) {
        info!("\n🔍 [DRY RUN] Sync Back Preview:\n");

        if operations.is_empty() {
            info!("📋 No changes detected - all files are up to date");
            return;
        }

        // Group operations by namespace for better organization
        let mut namespaces: HashMap<String, Vec<&SyncOperation>> = HashMap::new();
        for op in operations {
            namespaces.entry(op.namespace.clone()).or_default().push(op);
        }

        for (namespace, namespace_ops) in namespaces {
            info!("📁 Namespace: {}", namespace);

            for op in namespace_ops {
                info!("  📄 {:?}", op.file_path);

                for change in &op.changes {
                    match change.change_type {
                        ChangeType::Added => {
                            info!("    ➕ {}: (new) → \"{}\"", change.key, change.new_value);
                        }
                        ChangeType::Modified => {
                            info!(
                                "    ✏️  {}: \"{}\" → \"{}\"",
                                change.key,
                                change.old_value.as_ref().unwrap_or(&"(empty)".to_string()),
                                change.new_value
                            );
                        }
                        ChangeType::Removed => {
                            info!(
                                "    ❌ {}: \"{}\" → (removed)",
                                change.key,
                                change.old_value.as_ref().unwrap_or(&"(empty)".to_string())
                            );
                        }
                    }
                }
                info!("");
            }
        }

        info!(
            "📊 Summary: {} files would be modified, {} total changes",
            operations.len(),
            total_changes
        );
        info!("🔍 Run without --dry-run to apply these changes");
    }

    /// Execute all sync operations
    async fn execute_sync_operations(
        &self,
        operations: &[SyncOperation],
        writer: &TranslationWriter,
    ) -> Result<()> {
        for operation in operations {
            info!("💾 Updating file: {:?}", operation.file_path);

            // Create backup before modifying
            writer.backup_file(&operation.file_path)?;

            // Write updated translations
            writer.write_translation_file(&operation.file_path, &operation.translations, true)?;

            info!(
                "✅ Updated {} with {} changes",
                operation.file_path.display(),
                operation.changes.len()
            );
        }

        Ok(())
    }
}

#[derive(Debug)]
struct SyncOperation {
    namespace: String,
    language: String,
    file_path: PathBuf,
    translations: HashMap<String, String>,
    changes: Vec<ChangeInfo>,
}

#[derive(Debug)]
struct ChangeInfo {
    key: String,
    change_type: ChangeType,
    old_value: Option<String>,
    new_value: String,
}

#[derive(Debug)]
enum ChangeType {
    Added,
    Modified,
    Removed,
}
