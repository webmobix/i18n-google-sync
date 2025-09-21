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

use anyhow::{Context, Result};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::info;

pub struct TranslationWriter;

impl TranslationWriter {
    pub fn new() -> Self {
        Self
    }

    /// Write translations back to a JSON file, preserving structure when possible.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the JSON file to write
    /// * `translations` - HashMap of translation keys to values (dot notation keys)
    /// * `preserve_structure` - Whether to maintain nested JSON structure
    ///
    /// # Returns
    ///
    /// Result indicating success or failure
    pub fn write_translation_file<P: AsRef<Path>>(
        &self,
        file_path: P,
        translations: &HashMap<String, String>,
        preserve_structure: bool,
    ) -> Result<()> {
        let file_path = file_path.as_ref();
        info!(
            "✍️  Writing {} translations to: {:?}",
            translations.len(),
            file_path
        );

        // Create directory if it doesn't exist
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)
                .context(format!("Failed to create directory: {:?}", parent))?;
        }

        let json_value = if preserve_structure {
            // Try to read existing file and merge translations
            if file_path.exists() {
                self.merge_translations_with_existing(file_path, translations)?
            } else {
                // Create new nested structure
                self.convert_flat_to_nested(translations)
            }
        } else {
            // Create flat structure
            let flat_map: Map<String, Value> = translations
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect();
            Value::Object(flat_map)
        };

        // Write JSON with pretty formatting
        let json_string =
            serde_json::to_string_pretty(&json_value).context("Failed to serialize JSON")?;

        fs::write(file_path, json_string)
            .context(format!("Failed to write file: {:?}", file_path))?;

        info!("✅ Successfully wrote translations to: {:?}", file_path);
        Ok(())
    }

    /// Create a backup copy of a file before modifying it.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the file to backup
    ///
    /// # Returns
    ///
    /// Result indicating success or failure
    pub fn backup_file<P: AsRef<Path>>(&self, file_path: P) -> Result<()> {
        let file_path = file_path.as_ref();

        if !file_path.exists() {
            // No need to backup a file that doesn't exist
            return Ok(());
        }

        let backup_path = file_path.with_extension(format!(
            "{}.backup",
            file_path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("json")
        ));

        fs::copy(file_path, &backup_path).context(format!(
            "Failed to create backup: {:?} -> {:?}",
            file_path, backup_path
        ))?;

        info!("📁 Created backup: {:?}", backup_path);
        Ok(())
    }

    /// Convert flat dot notation keys back to nested JSON structure.
    ///
    /// # Arguments
    ///
    /// * `flat_keys` - HashMap with dot notation keys (e.g., "auth.login.title")
    ///
    /// # Returns
    ///
    /// Nested JSON Value
    pub fn convert_flat_to_nested(&self, flat_keys: &HashMap<String, String>) -> Value {
        let mut root = Map::new();

        for (key, value) in flat_keys {
            self.set_nested_value(&mut root, key, Value::String(value.clone()));
        }

        Value::Object(root)
    }

    /// Helper method to set a value in a nested JSON structure using dot notation.
    ///
    /// # Arguments
    ///
    /// * `obj` - Mutable reference to the JSON object map
    /// * `key_path` - Dot notation key path (e.g., "auth.login.title")
    /// * `value` - Value to set
    fn set_nested_value(&self, obj: &mut Map<String, Value>, key_path: &str, value: Value) {
        let parts: Vec<&str> = key_path.split('.').collect();

        if parts.is_empty() {
            return;
        }

        if parts.len() == 1 {
            // Leaf node - set the value
            obj.insert(parts[0].to_string(), value);
        } else {
            // Navigate/create nested structure
            let first_part = parts[0];
            let remaining_path = parts[1..].join(".");

            // Get or create the nested object
            let nested_obj = obj
                .entry(first_part.to_string())
                .or_insert_with(|| Value::Object(Map::new()));

            // Ensure it's an object
            if let Value::Object(nested_map) = nested_obj {
                self.set_nested_value(nested_map, &remaining_path, value);
            }
        }
    }

    /// Merge new translations with existing file content, preserving structure.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to existing JSON file
    /// * `translations` - New translations to merge in
    ///
    /// # Returns
    ///
    /// Merged JSON Value
    fn merge_translations_with_existing<P: AsRef<Path>>(
        &self,
        file_path: P,
        translations: &HashMap<String, String>,
    ) -> Result<Value> {
        let content = fs::read_to_string(file_path.as_ref()).context(format!(
            "Failed to read existing file: {:?}",
            file_path.as_ref()
        ))?;

        let mut existing: Value =
            serde_json::from_str(&content).context("Failed to parse existing JSON file")?;

        // Merge translations into existing structure
        if let Value::Object(ref mut existing_map) = existing {
            for (key, value) in translations {
                self.set_nested_value(existing_map, key, Value::String(value.clone()));
            }
        } else {
            // If existing file is not an object, create new nested structure
            return Ok(self.convert_flat_to_nested(translations));
        }

        Ok(existing)
    }
}
