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

//! Configuration management for the i18n Google Sync application.
//!
//! This module provides the core configuration structures and validation
//! logic for the application, including operation modes and runtime settings.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Operation modes supported by the application.
///
/// Each mode defines a different synchronization behavior between
/// local i18next files and Google Sheets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OperationMode {
    /// Add new keys from local files to Google Sheets
    AddKeys,
    /// Sync translations back from Google Sheets to local files
    SyncBack,
    /// Bidirectional sync (add keys + sync back)
    FullSync,
}

/// Main configuration structure for sync operations.
///
/// Contains runtime settings for synchronization operations.
/// Authentication is handled separately via the auth command.
#[derive(Debug, Clone)]
pub struct Config {
    /// Path to the locales directory containing translation files
    pub locales_path: PathBuf,
    /// Google Sheet ID to synchronize with
    pub sheet_id: String,
    /// Default language code (e.g., "en", "fr")
    pub default_lang: String,
    /// Main language column to flag when creating sheet structure
    pub main_language: String,
    /// Selected operation mode
    pub mode: OperationMode,
    /// Whether to run in dry-run mode (no actual changes)
    pub dry_run: bool,
}

impl Config {
    /// Creates a new configuration instance for sync operations.
    ///
    /// # Arguments
    ///
    /// * `locales_path` - Path to the directory containing translation files
    /// * `sheet_id` - Google Sheet ID for synchronization
    /// * `default_lang` - Default language code
    /// * `mode` - Operation mode to execute
    /// * `dry_run` - Whether to run in preview mode
    ///
    /// # Returns
    ///
    /// A new `Config` instance with the provided settings.
    pub fn new(
        locales_path: PathBuf,
        sheet_id: String,
        default_lang: String,
        main_language: String,
        mode: OperationMode,
        dry_run: bool,
    ) -> Self {
        Self {
            locales_path,
            sheet_id,
            default_lang,
            main_language,
            mode,
            dry_run,
        }
    }

    /// Validates the configuration settings.
    ///
    /// Checks that all required fields are properly set and that
    /// file system paths exist and are accessible.
    ///
    /// # Returns
    ///
    /// `Ok(())` if configuration is valid, otherwise an error describing
    /// the validation failure.
    ///
    /// # Errors
    ///
    /// * If locales path does not exist or is not a directory
    /// * If sheet ID is empty
    /// * If default language is empty
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.locales_path.exists() {
            anyhow::bail!("Locales path does not exist: {:?}", self.locales_path);
        }

        if !self.locales_path.is_dir() {
            anyhow::bail!("Locales path is not a directory: {:?}", self.locales_path);
        }

        if self.sheet_id.is_empty() {
            anyhow::bail!("Sheet ID cannot be empty");
        }

        if self.default_lang.is_empty() {
            anyhow::bail!("Default language cannot be empty");
        }

        if self.main_language.is_empty() {
            anyhow::bail!("Main language cannot be empty");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Helper function to create a temporary directory for testing
    fn create_temp_dir() -> TempDir {
        TempDir::new().expect("Failed to create temporary directory")
    }

    #[test]
    fn test_config_new() {
        let temp_dir = create_temp_dir();
        let config = Config::new(
            temp_dir.path().to_path_buf(),
            "test_sheet_id".to_string(),
            "en".to_string(),
            "en".to_string(),
            OperationMode::AddKeys,
            false,
        );

        assert_eq!(config.locales_path, temp_dir.path());
        assert_eq!(config.sheet_id, "test_sheet_id");
        assert_eq!(config.default_lang, "en");
        assert_eq!(config.mode, OperationMode::AddKeys);
        assert!(!config.dry_run);
    }

    #[test]
    fn test_config_validation_success() {
        let temp_dir = create_temp_dir();
        let config = Config::new(
            temp_dir.path().to_path_buf(),
            "valid_sheet_id".to_string(),
            "en".to_string(),
            "en".to_string(),
            OperationMode::SyncBack,
            true,
        );

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_nonexistent_path() {
        let config = Config::new(
            PathBuf::from("/nonexistent/path"),
            "sheet_id".to_string(),
            "en".to_string(),
            "en".to_string(),
            OperationMode::FullSync,
            false,
        );

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    #[test]
    fn test_config_validation_path_is_file() {
        let temp_dir = create_temp_dir();
        let file_path = temp_dir.path().join("not_a_directory.txt");
        fs::write(&file_path, "test content").expect("Failed to create test file");

        let config = Config::new(
            file_path,
            "sheet_id".to_string(),
            "en".to_string(),
            "en".to_string(),
            OperationMode::AddKeys,
            false,
        );

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not a directory"));
    }

    #[test]
    fn test_config_validation_empty_sheet_id() {
        let temp_dir = create_temp_dir();
        let config = Config::new(
            temp_dir.path().to_path_buf(),
            "".to_string(),
            "en".to_string(),
            "en".to_string(),
            OperationMode::AddKeys,
            false,
        );

        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Sheet ID cannot be empty")
        );
    }

    #[test]
    fn test_config_validation_empty_default_lang() {
        let temp_dir = create_temp_dir();
        let config = Config::new(
            temp_dir.path().to_path_buf(),
            "sheet_id".to_string(),
            "".to_string(),
            "en".to_string(),
            OperationMode::AddKeys,
            false,
        );

        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Default language cannot be empty")
        );
    }

    #[test]
    fn test_config_validation_empty_main_language() {
        let temp_dir = create_temp_dir();
        let config = Config::new(
            temp_dir.path().to_path_buf(),
            "sheet_id".to_string(),
            "en".to_string(),
            "".to_string(),
            OperationMode::AddKeys,
            false,
        );

        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Main language cannot be empty")
        );
    }

    #[test]
    fn test_operation_mode_serialization() {
        let mode = OperationMode::AddKeys;
        let serialized = serde_json::to_string(&mode).expect("Failed to serialize");
        let deserialized: OperationMode =
            serde_json::from_str(&serialized).expect("Failed to deserialize");
        assert_eq!(mode, deserialized);
    }
}
