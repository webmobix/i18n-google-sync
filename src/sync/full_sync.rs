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

use crate::config::Config;
use crate::sync::{AddKeysMode, SyncBackMode};
use anyhow::Result;
use std::path::PathBuf;
use tokio::time::{Duration, sleep};
use tracing::info;

pub struct FullSyncMode;

impl FullSyncMode {
    pub fn new() -> Self {
        Self
    }

    pub async fn execute(&self, config: &Config, token_path: PathBuf) -> Result<()> {
        info!("🔄 Executing Full Sync mode (bidirectional)");

        let add_keys_mode = AddKeysMode::new();
        let sync_back_mode = SyncBackMode::new();

        // Step 1: Add new keys from local files to sheet
        info!("📤 Phase 1: Adding new keys to sheet");
        add_keys_mode.execute(config, token_path.clone()).await?;

        // Allow Google Sheets formulas a moment to populate translated values before pulling
        if !config.dry_run {
            info!("⏱️ Waiting for Google Sheets formulas to evaluate before syncing back");
            // Empirical delay; can be adjusted via env override in the future if needed
            sleep(Duration::from_secs(2)).await;
        }

        // Step 2: Sync back translations from sheet to local files
        info!("📥 Phase 2: Syncing translations back to files");
        sync_back_mode.execute(config, token_path).await?;

        // TODO: Handle conflicts between local and sheet versions
        // - Detect when both local and sheet have changes for the same key
        // - Provide conflict resolution strategies (prefer local, prefer sheet, manual)

        if config.dry_run {
            info!("🔍 Full sync dry run completed - no changes were made");
        } else {
            info!("✅ Full sync operation completed");
        }

        Ok(())
    }

    async fn detect_conflicts(&self, config: &Config) -> Result<Vec<String>> {
        // TODO: Implement conflict detection
        // Compare timestamps, content hashes, or other conflict indicators
        Ok(Vec::new())
    }

    async fn resolve_conflicts(
        &self,
        conflicts: &[String],
        strategy: ConflictResolutionStrategy,
    ) -> Result<()> {
        // TODO: Implement conflict resolution
        info!(
            "⚠️  Resolving {} conflicts with strategy: {:?}",
            conflicts.len(),
            strategy
        );
        Ok(())
    }
}

#[derive(Debug)]
pub enum ConflictResolutionStrategy {
    PreferLocal,
    PreferSheet,
    Manual,
}
