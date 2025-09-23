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

use crate::auth::oauth;
use crate::files::parser::TranslationKey;
use anyhow::{Context, Result};
use google_sheets4::{
    FieldMask, Sheets,
    api::{
        AddSheetRequest, BatchUpdateSpreadsheetRequest, BatchUpdateValuesRequest, CellData,
        CellFormat, GridProperties, GridRange, RepeatCellRequest, Request, SheetProperties,
        Spreadsheet, TextFormat, UpdateSheetPropertiesRequest, ValueRange,
    },
    hyper_rustls, yup_oauth2,
};
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use tokio::time::{Duration, sleep};
use tracing::{debug, error, info, warn};

pub struct SheetsManager {
    sheet_id: String,
    auth_manager: oauth::AuthManager,
    main_language: String,
    hub: Option<Sheets<hyper_rustls::HttpsConnector<HttpConnector>>>,
}

struct SheetRowData {
    row_number: usize,
    values: Vec<String>,
}

/// Outcome statistics returned by `batch_update_cells`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchUpdateOutcome {
    /// Number of entirely new rows (new keys) added to the sheet.
    pub new_rows: usize,
    /// Number of individual translation cells filled for existing keys.
    pub filled_cells: usize,
    /// Total number of value updates submitted (sum of all row + cell write operations prepared in the request).
    pub total_updates: usize,
}

const RATE_LIMIT_MAX_RETRIES: usize = 3;
const MAIN_LANGUAGE_SUFFIX: &str = " (main)";

impl SheetsManager {
    fn is_rate_limit_error(error: &google_sheets4::Error) -> bool {
        let message = error.to_string().to_lowercase();
        message.contains("rate")
            || message.contains("quota")
            || message.contains("too many requests")
            || message.contains("429")
    }

    fn rate_limit_delay(attempt: usize) -> Duration {
        let base_ms: u64 = 500;
        let exponent = attempt.saturating_sub(1) as u32;
        let multiplier = 2_u64.saturating_pow(exponent).min(16);
        Duration::from_millis(base_ms * multiplier)
    }

    async fn call_with_rate_limit_retry<T, F, Fut>(description: &str, mut operation: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, google_sheets4::Error>>,
    {
        let mut attempt = 0usize;
        loop {
            match operation().await {
                Ok(value) => return Ok(value),
                Err(err)
                    if attempt < RATE_LIMIT_MAX_RETRIES
                        && SheetsManager::is_rate_limit_error(&err) =>
                {
                    attempt += 1;
                    let delay = SheetsManager::rate_limit_delay(attempt);
                    warn!(
                        "🔁 {} hit Google rate limit (attempt {}/{}), retrying in {:?}",
                        description, attempt, RATE_LIMIT_MAX_RETRIES, delay
                    );
                    sleep(delay).await;
                }
                Err(err) => {
                    return Err(anyhow::anyhow!("{} failed: {}", description, err));
                }
            }
        }
    }

    /// Creates a new SheetsManager instance.
    ///
    /// # Arguments
    ///
    /// * `sheet_id` - Google Sheets ID to work with
    /// * `auth_manager` - Configured AuthManager for OAuth2 authentication
    pub fn new(sheet_id: String, auth_manager: oauth::AuthManager, main_language: String) -> Self {
        Self {
            sheet_id,
            auth_manager,
            main_language,
            hub: None,
        }
    }

    /// Initialize the Google Sheets API hub with authentication.
    /// For sync operations, this will ONLY use existing tokens and will NOT launch browser authentication.
    async fn init_hub(&mut self) -> Result<()> {
        if self.hub.is_some() {
            return Ok(());
        }

        info!("🔑 Initializing Google Sheets API connection...");

        // Resolve and validate tokens through AuthManager to ensure consistent handling
        let token_path = self.auth_manager.ensure_token_file()?;
        debug!("🔍 Using token cache at: {:?}", token_path);

        debug!("🔍 Loading client secret...");
        // Create the authenticator using existing tokens only
        let client_secret = self
            .auth_manager
            .load_client_secret()
            .await
            .context("Failed to load client secret for Google Sheets API")?;

        debug!(
            "🔍 Creating NON-INTERACTIVE authenticator with token path: {:?}",
            token_path
        );

        // Create a custom authenticator that will NEVER trigger interactive authentication
        let auth = self
            .create_non_interactive_authenticator(client_secret, token_path.clone())
            .await
            .context("Failed to create non-interactive Google Sheets authenticator")?;

        // Create HTTP client using the new pattern
        let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build(
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()?
                .https_or_http()
                .enable_http1()
                .build(),
        );

        // Create the Google Sheets hub
        self.hub = Some(Sheets::new(client, auth));

        info!("✅ Google Sheets API connection established (non-interactive mode)");
        Ok(())
    }

    /// Creates a non-interactive authenticator that will never trigger browser authentication
    async fn create_non_interactive_authenticator(
        &self,
        client_secret: google_sheets4::yup_oauth2::ApplicationSecret,
        token_path: std::path::PathBuf,
    ) -> Result<
        yup_oauth2::authenticator::Authenticator<
            hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        >,
    > {
        use google_sheets4::yup_oauth2::{InstalledFlowAuthenticator, InstalledFlowReturnMethod};

        // Create authenticator with explicit settings to prevent interactive flows
        let auth = InstalledFlowAuthenticator::builder(
            client_secret,
            InstalledFlowReturnMethod::HTTPRedirect, // Use redirect, not interactive
        )
        .persist_tokens_to_disk(token_path)
        .build()
        .await
        .context("Failed to build non-interactive authenticator")?;

        // Test the authenticator with our required scopes to ensure it doesn't trigger auth
        let scopes = &[
            "https://www.googleapis.com/auth/spreadsheets",
            "https://www.googleapis.com/auth/drive",
        ];
        debug!("🔍 Testing authenticator with scopes: {:?}", scopes);

        match auth.token(scopes).await {
            Ok(token) => {
                debug!("🔍 Successfully obtained token without interactive auth");
                debug!(
                    "🔍 Token preview: {}...",
                    token
                        .token()
                        .unwrap_or("None")
                        .chars()
                        .take(20)
                        .collect::<String>()
                );
            }
            Err(e) => {
                debug!("🔍 Authenticator test failed: {:?}", e);
                anyhow::bail!(
                    "Authenticator failed to get token without interactive auth: {}\n\
                    This means the stored tokens are invalid or expired.",
                    e
                );
            }
        }

        Ok(auth)
    }

    /// Get reference to the initialized hub
    async fn get_hub(&mut self) -> Result<&Sheets<hyper_rustls::HttpsConnector<HttpConnector>>> {
        self.init_hub().await?;
        self.hub
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Failed to initialize Google Sheets hub"))
    }

    /// Connect to an existing Google Sheet and validate access.
    ///
    /// This method verifies that the sheet exists and is accessible with current credentials.
    /// It does not create a new sheet - the sheet must already exist.
    ///
    /// # Returns
    ///
    /// `Ok(Spreadsheet)` if sheet exists and is accessible, otherwise an error.
    ///
    /// # Errors
    ///
    /// * If sheet ID is invalid or sheet doesn't exist
    /// * If user doesn't have permission to access the sheet
    /// * If Google Sheets API is unreachable
    pub async fn get_or_create_sheet(&mut self) -> Result<Spreadsheet> {
        info!("📊 Connecting to Google Sheet: {}", self.sheet_id);

        let sheet_id = self.sheet_id.clone();
        let hub = self.get_hub().await?;

        // Try to get the spreadsheet to verify it exists and we have access
        let result = Self::call_with_rate_limit_retry("fetch spreadsheet metadata", || {
            let hub = hub;
            let sheet_id = sheet_id.clone();
            async move { hub.spreadsheets().get(&sheet_id).doit().await }
        })
        .await;

        match result {
            Ok((_, spreadsheet)) => {
                info!(
                    "✅ Successfully connected to sheet: {}",
                    spreadsheet
                        .properties
                        .as_ref()
                        .and_then(|p| p.title.as_ref())
                        .unwrap_or(&sheet_id)
                );
                Ok(spreadsheet)
            }
            Err(e) => {
                let error_msg = format!(
                    "Failed to access Google Sheet with ID '{}'. Please verify:\n\
                    • The sheet ID is correct\n\
                    • The sheet exists and is not deleted\n\
                    • You have permission to access the sheet\n\
                    • Your authentication tokens are valid",
                    sheet_id
                );

                Err(anyhow::anyhow!("{}\n\nOriginal error: {}", error_msg, e))
            }
        }
    }

    /// Find a worksheet (tab) by namespace name.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace to search for (e.g., "common", "auth")
    ///
    /// # Returns
    ///
    /// `Ok(Some(sheet_id))` if worksheet exists, `Ok(None)` if not found, or error.
    pub async fn get_worksheet_by_namespace(&mut self, namespace: &str) -> Result<Option<i32>> {
        debug!("📋 Looking for worksheet: {}", namespace);

        let spreadsheet = self.get_or_create_sheet().await?;

        if let Some(sheets) = &spreadsheet.sheets {
            for sheet in sheets {
                if let Some(properties) = &sheet.properties
                    && let Some(title) = &properties.title
                    && title == namespace
                    && let Some(sheet_id) = properties.sheet_id
                {
                    debug!("✅ Found worksheet '{}' with ID: {}", namespace, sheet_id);
                    return Ok(Some(sheet_id));
                }
            }
        }

        debug!("❌ Worksheet '{}' not found", namespace);
        Ok(None)
    }

    /// Create a new worksheet (tab) for the given namespace.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace name for the worksheet title
    /// * `languages` - List of language codes to create columns for
    ///
    /// # Returns
    ///
    /// `Ok(sheet_id)` if creation succeeds, otherwise an error.
    pub async fn create_worksheet(&mut self, namespace: &str, languages: &[String]) -> Result<i32> {
        info!(
            "➕ Creating worksheet: {} with languages: {:?}",
            namespace, languages
        );

        let sheet_id = self.sheet_id.clone();
        let hub = self.get_hub().await?;

        // Create the add sheet request
        let add_sheet_request = AddSheetRequest {
            properties: Some(SheetProperties {
                title: Some(namespace.to_string()),
                grid_properties: Some(google_sheets4::api::GridProperties {
                    row_count: Some(1000),                            // Start with 1000 rows
                    column_count: Some((languages.len() + 2) as i32), // Key + Description + Languages
                    frozen_row_count: Some(1),                        // Freeze header row
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };

        // Create batch update request
        let batch_request = BatchUpdateSpreadsheetRequest {
            requests: Some(vec![Request {
                add_sheet: Some(add_sheet_request),
                ..Default::default()
            }]),
            ..Default::default()
        };

        // Execute the request
        let result = Self::call_with_rate_limit_retry("create worksheet", || {
            let hub = hub;
            let sheet_id = sheet_id.clone();
            let request = batch_request.clone();
            async move {
                hub.spreadsheets()
                    .batch_update(request, &sheet_id)
                    .doit()
                    .await
            }
        })
        .await;

        match result {
            Ok((_, response)) => {
                if let Some(replies) = response.replies
                    && let Some(reply) = replies.first()
                    && let Some(add_sheet) = &reply.add_sheet
                    && let Some(properties) = &add_sheet.properties
                    && let Some(new_sheet_id) = properties.sheet_id
                {
                    info!(
                        "✅ Created worksheet '{}' with ID: {}",
                        namespace, new_sheet_id
                    );

                    // Set up the sheet structure (headers)
                    let main_language = self.main_language.clone();
                    self.setup_sheet_structure(namespace, languages, main_language.as_str())
                        .await?;

                    return Ok(new_sheet_id);
                }
                Err(anyhow::anyhow!(
                    "Failed to get sheet ID from create response"
                ))
            }
            Err(e) => Err(anyhow::anyhow!(
                "Failed to create worksheet '{}': {}",
                namespace,
                e
            )),
        }
    }

    /// Read existing translation keys from a worksheet, including values from GOOGLETRANSLATE formulas.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace (worksheet name) to read from
    ///
    /// # Returns
    ///
    /// HashMap mapping translation keys to language values:
    /// `key -> language_code -> translation_value`
    pub async fn read_existing_keys(
        &mut self,
        namespace: &str,
    ) -> Result<HashMap<String, HashMap<String, String>>> {
        info!("📖 Reading existing keys from: {}", namespace);

        // First, check if the worksheet exists
        if self.get_worksheet_by_namespace(namespace).await?.is_none() {
            warn!("❌ Worksheet '{}' does not exist", namespace);
            return Ok(HashMap::new());
        }

        let sheet_id = self.sheet_id.clone();
        let hub = self.get_hub().await?;

        // Read all data from the worksheet with both formatted values and formulas
        let range = format!("{}!A:Z", namespace); // Read all columns A through Z

        // Get rendered/calculated values (including GOOGLETRANSLATE results)
        let formatted_result =
            Self::call_with_rate_limit_retry("read worksheet values (formatted)", || {
                let hub = hub;
                let sheet_id = sheet_id.clone();
                let range = range.clone();
                async move {
                    hub.spreadsheets()
                        .values_get(&sheet_id, &range)
                        .value_render_option("FORMATTED_VALUE")
                        .doit()
                        .await
                }
            })
            .await;

        // Get formulas to detect which cells contain GOOGLETRANSLATE
        let formula_result = Self::call_with_rate_limit_retry("read worksheet formulas", || {
            let hub = hub;
            let sheet_id = sheet_id.clone();
            let range = range.clone();
            async move {
                hub.spreadsheets()
                    .values_get(&sheet_id, &range)
                    .value_render_option("FORMULA")
                    .doit()
                    .await
            }
        })
        .await;

        match (formatted_result, formula_result) {
            (Ok((_, formatted_range)), Ok((_, formula_range))) => {
                let mut keys_map = HashMap::new();

                let formatted_values = formatted_range.values.unwrap_or_default();
                let formula_values = formula_range.values.unwrap_or_default();

                if formatted_values.is_empty() {
                    info!("📋 Worksheet '{}' has no data", namespace);
                    return Ok(keys_map);
                }

                // First row should contain headers: Key, Description, Language1, Language2, etc.
                let headers = &formatted_values[0];
                if headers.len() < 3 {
                    return Err(anyhow::anyhow!(
                        "Invalid worksheet format in '{}': expected at least 3 columns (Key, Description, Language)",
                        namespace
                    ));
                }

                // Extract language codes from headers (skip first 2 columns: Key, Description)
                let language_codes: Vec<String> = headers[2..]
                    .iter()
                    .map(|v| v.as_str().unwrap_or("").to_string())
                    .collect();

                info!(
                    "🌍 Found languages in '{}': {:?}",
                    namespace, language_codes
                );

                // Process each row (skip header row)
                let mut translation_count = 0;
                let mut formula_count = 0;

                for (row_index, formatted_row) in formatted_values.iter().skip(1).enumerate() {
                    if formatted_row.is_empty() {
                        continue; // Skip empty rows
                    }

                    // First column should be the translation key
                    let key = formatted_row[0].as_str().unwrap_or("").to_string();
                    if key.is_empty() {
                        continue; // Skip rows without keys
                    }

                    let mut language_values = HashMap::new();

                    // Get corresponding formula row (with bounds checking)
                    let empty_row = Vec::new();
                    let formula_row = formula_values.get(row_index + 1).unwrap_or(&empty_row);

                    // Extract values for each language (starting from column 2, after Key and Description)
                    for (lang_index, language_code) in language_codes.iter().enumerate() {
                        let col_index = lang_index + 2; // Add 2 for Key and Description columns

                        if col_index < formatted_row.len() && !language_code.is_empty() {
                            let formatted_value =
                                formatted_row[col_index].as_str().unwrap_or("").to_string();
                            let formula_value = formula_row
                                .get(col_index)
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();

                            if !formatted_value.is_empty() {
                                // Check if this is a GOOGLETRANSLATE formula
                                if formula_value.starts_with("=GOOGLETRANSLATE") {
                                    // Check if the formula calculated successfully
                                    if !formatted_value.starts_with("#ERROR!")
                                        && !formatted_value.starts_with("#N/A")
                                        && !formatted_value.starts_with("#VALUE!")
                                    {
                                        language_values
                                            .insert(language_code.clone(), formatted_value);
                                        formula_count += 1;
                                    } else {
                                        warn!(
                                            "⚠️  Skipping failed GOOGLETRANSLATE formula for key '{}', language '{}': {}",
                                            key, language_code, formatted_value
                                        );
                                    }
                                } else {
                                    // Regular value (manually entered)
                                    language_values.insert(language_code.clone(), formatted_value);
                                    translation_count += 1;
                                }
                            }
                        }
                    }

                    // INSERT/UPDATE CHANGE: Always record the key even if all translation cells are currently empty.
                    // This allows us to later fill empty translations without risking row overwrite due to
                    // mis-counting populated keys.
                    keys_map.entry(key).or_insert(language_values);
                }

                info!(
                    "✅ Read {} translation keys from '{}' ({} direct, {} from formulas)",
                    keys_map.len(),
                    namespace,
                    translation_count,
                    formula_count
                );
                Ok(keys_map)
            }
            (Err(formatted_err), _) => Err(anyhow::anyhow!(
                "Failed to read formatted values from worksheet '{}': {}",
                namespace,
                formatted_err
            )),
            (_, Err(formula_err)) => {
                warn!(
                    "⚠️  Could not read formulas from '{}', falling back to values only: {}",
                    namespace, formula_err
                );

                // Fallback: read only formatted values without formula detection
                self.read_existing_keys_fallback(namespace).await
            }
        }
    }

    /// Fallback method to read existing keys when formula API fails
    async fn read_existing_keys_fallback(
        &mut self,
        namespace: &str,
    ) -> Result<HashMap<String, HashMap<String, String>>> {
        let sheet_id = self.sheet_id.clone();
        let hub = self.get_hub().await?;
        let range = format!("{}!A:Z", namespace);

        let result = Self::call_with_rate_limit_retry("read worksheet values (fallback)", || {
            let hub = hub;
            let sheet_id = sheet_id.clone();
            let range = range.clone();
            async move {
                hub.spreadsheets()
                    .values_get(&sheet_id, &range)
                    .value_render_option("FORMATTED_VALUE")
                    .doit()
                    .await
            }
        })
        .await;

        match result {
            Ok((_, value_range)) => {
                let mut keys_map = HashMap::new();

                if let Some(values) = value_range.values {
                    if values.is_empty() {
                        info!("📋 Worksheet '{}' has no data", namespace);
                        return Ok(keys_map);
                    }

                    // First row should contain headers
                    let headers = &values[0];
                    if headers.len() < 3 {
                        return Err(anyhow::anyhow!(
                            "Invalid worksheet format in '{}': expected at least 3 columns",
                            namespace
                        ));
                    }

                    // Extract language codes from headers
                    let language_codes: Vec<String> = headers[2..]
                        .iter()
                        .map(|v| v.as_str().unwrap_or("").to_string())
                        .collect();

                    // Process each row (skip header row)
                    for row in values.iter().skip(1) {
                        if row.is_empty() {
                            continue;
                        }

                        let key = row[0].as_str().unwrap_or("").to_string();
                        if key.is_empty() {
                            continue;
                        }

                        let mut language_values = HashMap::new();

                        for (lang_index, language_code) in language_codes.iter().enumerate() {
                            let col_index = lang_index + 2;
                            if col_index < row.len() && !language_code.is_empty() {
                                let value = row[col_index].as_str().unwrap_or("").to_string();
                                if !value.is_empty() && !value.starts_with("#ERROR!") {
                                    language_values.insert(language_code.clone(), value);
                                }
                            }
                        }

                        // Always insert the key (even if language_values is empty) to allow subsequent backfill.
                        keys_map.insert(key, language_values);
                    }
                }

                info!(
                    "✅ Read {} translation keys from '{}' (fallback mode)",
                    keys_map.len(),
                    namespace
                );
                Ok(keys_map)
            }
            Err(e) => Err(anyhow::anyhow!(
                "Failed to read from worksheet '{}': {}",
                namespace,
                e
            )),
        }
    }

    /// Get all worksheet names (namespaces) from the spreadsheet.
    ///
    /// # Returns
    ///
    /// Vector of worksheet names that contain translation data
    pub async fn get_all_worksheets(&mut self) -> Result<Vec<String>> {
        debug!("📋 Discovering worksheets in spreadsheet");

        let spreadsheet = self.get_or_create_sheet().await?;
        let mut namespaces = Vec::new();

        if let Some(sheets) = spreadsheet.sheets {
            for sheet in sheets {
                if let Some(properties) = sheet.properties
                    && let Some(title) = properties.title
                {
                    // Skip default "Sheet1" if it's empty
                    if title == "Sheet1" {
                        // Check if Sheet1 has any data
                        if self.worksheet_has_data(&title).await? {
                            namespaces.push(title);
                        }
                    } else {
                        // Include all other named worksheets
                        namespaces.push(title);
                    }
                }
            }
        }

        info!("🔍 Found {} worksheets: {:?}", namespaces.len(), namespaces);
        Ok(namespaces)
    }

    /// Check if a worksheet contains any translation data.
    ///
    /// # Arguments
    ///
    /// * `worksheet_name` - Name of the worksheet to check
    ///
    /// # Returns
    ///
    /// `true` if the worksheet has data, `false` if empty
    async fn worksheet_has_data(&mut self, worksheet_name: &str) -> Result<bool> {
        let sheet_id = self.sheet_id.clone();
        let hub = self.get_hub().await?;
        let range = format!("{}!A1:C2", worksheet_name); // Check first few cells

        let result = Self::call_with_rate_limit_retry("check worksheet data presence", || {
            let hub = hub;
            let sheet_id = sheet_id.clone();
            let range = range.clone();
            async move {
                hub.spreadsheets()
                    .values_get(&sheet_id, &range)
                    .doit()
                    .await
            }
        })
        .await;

        match result {
            Ok((_, value_range)) => {
                if let Some(values) = value_range.values {
                    // Check if we have at least a header row with proper structure
                    if !values.is_empty() && values[0].len() >= 3 {
                        // Check if first cell looks like a translation key or "Translation Key" header
                        if let Some(first_cell) = values[0][0].as_str() {
                            return Ok(!first_cell.is_empty());
                        }
                    }
                }
                Ok(false)
            }
            Err(_) => {
                // If we can't read the worksheet, assume it doesn't have data
                Ok(false)
            }
        }
    }

    /// Batch update multiple cells in a worksheet efficiently.
    ///
    /// This method now performs TWO categories of updates without switching to Google Sheets "append" mode:
    /// 1. Adds entirely new keys by writing full rows at the next free row after the last non-empty key row
    ///    (determined via `fetch_last_used_row` scanning column A), avoiding the previous risk of row
    ///    overwrite when sparse rows or empty translation cells existed.
    /// 2. For existing keys, fills ONLY the missing language cells (empty translations) using either the
    ///    provided explicit translation or a generated GOOGLETRANSLATE formula referencing the row's default
    ///    language cell. Previously these keys were skipped completely, leaving gaps indefinitely.
    ///
    /// Overwrite prevention rationale:
    /// * We no longer infer the next row from `existing_keys.len()` (which ignored keys whose translations
    ///   were all empty). Instead we scan column A to find the true last used row number.
    /// * We always record keys (even with zero translations) in `read_existing_keys`, removing
    ///   under-count drift.
    /// * In-batch duplicate keys are ignored after the first occurrence.
    ///
    /// Return value semantics: returns a `BatchUpdateOutcome` struct containing:
    /// * `new_rows` - count of newly appended key rows
    /// * `filled_cells` - count of previously empty translation cells filled for existing rows
    /// * `total_updates` - total individual update operations (new row ranges + single-cell ranges)
    ///
    /// # Arguments
    /// * `namespace` - Worksheet name
    /// * `translation_keys` - Keys (with any subset of language values) from local source
    /// * `languages` - Ordered language headers corresponding to sheet columns
    /// * `dry_run` - If true, nothing is written; a preview of actions (new rows + cell backfills) is logged
    ///
    /// # Edge Cases Handled
    /// * Sparse sheets with blank rows
    /// * Keys present with all translations empty
    /// * Mixed manual and formula-based translations
    /// * Duplicate keys within the provided `translation_keys` slice
    ///
    /// # Returns
    /// Count of NEW rows added (existing key cell backfills are not counted in the return value)
    pub async fn batch_update_cells(
        &mut self,
        namespace: &str,
        translation_keys: &[TranslationKey],
        languages: &[String],
        dry_run: bool,
    ) -> Result<BatchUpdateOutcome> {
        if dry_run {
            info!(
                "🔍 [DRY RUN] Would process {} translation keys in worksheet '{}' (adding new + filling missing)",
                translation_keys.len(),
                namespace
            );
            for key in translation_keys.iter().take(10) { // preview subset
                info!("  📝 Key preview: {} ({} provided values)", key.key_path, key.values.len());
            }
            if translation_keys.len() > 10 {
                info!("  ... and {} more keys", translation_keys.len() - 10);
            }
        }

        if translation_keys.is_empty() {
            info!("📋 No translation keys to process in '{}'", namespace);
            return Ok(BatchUpdateOutcome { new_rows: 0, filled_cells: 0, total_updates: 0 });
        }

        info!(
            "💾 Processing {} translation keys in worksheet '{}' (add new + fill missing)",
            translation_keys.len(),
            namespace
        );

        // Existing keys map now includes keys with zero translations.
        let existing_keys = self.read_existing_keys(namespace).await?;

        // Determine actual last used row (header row is row 1). Prevents overwrites when keys had only empty translations.
        let last_used_row = self.fetch_last_used_row(namespace).await.unwrap_or(1);
        let mut next_row = if last_used_row < 1 { 2 } else { last_used_row + 1 };

        // Build key -> row number mapping by reading column A (excluding header) so we can update specific cells.
        let mut key_row_map: HashMap<String, usize> = HashMap::new();
        if last_used_row >= 2 { // there are data rows
            let sheet_id = self.sheet_id.clone();
            let hub = self.get_hub().await?;
            let range = format!("{}!A2:A{}", namespace, last_used_row);
            if let Ok((_, col_data)) = Self::call_with_rate_limit_retry("fetch key column for row mapping", || {
                let hub = hub; let sheet_id = sheet_id.clone(); let range = range.clone();
                async move { hub.spreadsheets().values_get(&sheet_id, &range).doit().await }
            }).await {
                if let Some(rows) = col_data.values { // rows is Vec<Vec<Value>>
                    for (idx, row) in rows.into_iter().enumerate() {
                        if let Some(first) = row.get(0).and_then(|v| v.as_str()) {
                            let key = first.trim();
                            if !key.is_empty() { key_row_map.insert(key.to_string(), idx + 2); } // +2 because A2 corresponds to idx 0
                        }
                    }
                }
            }
        }

        // REFACTORED: use planning helper instead of inline logic
        let (value_ranges, new_rows_added, existing_cells_filled, existing_keys_cells_per_language) =
            self.plan_batch_updates(
                namespace,
                translation_keys,
                languages,
                &existing_keys,
                next_row,
                &key_row_map,
            );

        if value_ranges.is_empty() {
            info!("📋 Nothing to add or fill in '{}'", namespace);
            return Ok(BatchUpdateOutcome { new_rows: 0, filled_cells: 0, total_updates: 0 });
        }

        if dry_run {
            info!("🔍 [DRY RUN] Would add {} new rows and fill {} existing empty cells ({} total updates) in '{}'", new_rows_added, existing_cells_filled, value_ranges.len(), namespace);
            for (lang, count) in existing_keys_cells_per_language.iter() {
                info!("  🌍 Missing cell fills for '{}': {}", lang, count);
            }
            return Ok(BatchUpdateOutcome { new_rows: new_rows_added, filled_cells: existing_cells_filled, total_updates: value_ranges.len() });
        }

        // Validate batch size to prevent API limits
        const MAX_BATCH_SIZE: usize = 100;
        if value_ranges.len() > MAX_BATCH_SIZE {
            let updated = self.batch_update_in_chunks(namespace, value_ranges, MAX_BATCH_SIZE).await?;
            if existing_cells_filled > 0 { info!("🧩 Filled {} existing cells while adding {} new rows in '{}'", existing_cells_filled, new_rows_added, namespace); }
            return Ok(BatchUpdateOutcome { new_rows: new_rows_added, filled_cells: existing_cells_filled, total_updates: updated });
        }

        // Execute batch update
        let batch_request = BatchUpdateValuesRequest {
            value_input_option: Some("USER_ENTERED".to_string()),
            data: Some(value_ranges.clone()),
            ..Default::default()
        };

        info!("🚀 Executing batch update: {} new rows, {} existing empty cells ({} value ranges)", new_rows_added, existing_cells_filled, value_ranges.len());

        let sheet_id = self.sheet_id.clone();
        let hub = self.get_hub().await?;
        let result = Self::call_with_rate_limit_retry("batch update worksheet values", || {
            let hub = hub; let sheet_id = sheet_id.clone(); let request = batch_request.clone();
            async move { hub.spreadsheets().values_batch_update(request, &sheet_id).doit().await }
        }).await;

        match result {
            Ok((_, response)) => {
                let updated_cells = response.total_updated_cells.unwrap_or(0);
                let updated_rows = response.total_updated_rows.unwrap_or(0);
                info!(
                    "✅ Batch complete: added {} new rows, filled {} existing cells (Google reports {} rows, {} cells updated) in '{}'",
                    new_rows_added, existing_cells_filled, updated_rows, updated_cells, namespace
                );
                for (lang, count) in existing_keys_cells_per_language.iter() {
                    info!("  🌍 Filled {} '{}' cells", count, lang);
                }
                Ok(BatchUpdateOutcome { new_rows: new_rows_added, filled_cells: existing_cells_filled, total_updates: updated_cells as usize })
            }
            Err(e) => {
                let error_msg = format!(
                    "Failed to batch update cells in worksheet '{}': {}",
                    namespace, e
                );
                error!("❌ {}", error_msg);
                if e.to_string().contains("quota") || e.to_string().contains("rate") {
                    info!("💡 Tip: You may have hit API rate limits. Try reducing batch size or wait before retrying.");
                } else if e.to_string().contains("permission") || e.to_string().contains("access") {
                    info!("💡 Tip: Check that you have edit permissions for this sheet.");
                } else if e.to_string().contains("not found") {
                    info!("💡 Tip: Verify the sheet ID and worksheet name are correct.");
                }

                Err(anyhow::anyhow!(error_msg))
            }
        }
    }

    /// Set up the sheet structure with proper headers and formatting.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The worksheet name to set up
    /// * `languages` - List of language codes for column headers
    ///
    /// # Returns
    ///
    /// `Ok(())` if setup succeeds, otherwise an error.
    pub async fn setup_sheet_structure(
        &mut self,
        namespace: &str,
        languages: &[String],
        main_language: &str,
    ) -> Result<()> {
        info!(
            "🏗️  Ensuring sheet structure for '{}' with languages: {:?}",
            namespace, languages
        );

        let existing_headers = self.fetch_existing_headers(namespace).await?;
        let mut existing_language_labels: HashMap<String, String> = HashMap::new();
        let mut current_languages: Vec<String> = Vec::new();

        if let Some(ref header_row) = existing_headers {
            for value in header_row.iter().skip(2) {
                let normalized = SheetsManager::normalize_language_header(value);
                if normalized.is_empty() {
                    continue;
                }

                current_languages.push(normalized.clone());
                existing_language_labels
                    .entry(normalized)
                    .or_insert_with(|| value.clone());
            }
        }

        if existing_headers.is_some() && current_languages == languages {
            info!(
                "📋 Header languages already match for '{}', skipping update",
                namespace
            );
            return Ok(());
        }

        if existing_headers.is_some() {
            let missing: Vec<_> = languages
                .iter()
                .filter(|lang| !current_languages.contains(lang))
                .cloned()
                .collect();

            if missing.is_empty() {
                info!(
                    "📋 Header languages for '{}' differ in order; updating to {:?}",
                    namespace, languages
                );
            } else {
                info!(
                    "➕ Adding missing language columns for '{}': {:?}",
                    namespace, missing
                );
            }
        }

        let is_initial_setup = existing_headers.is_none();

        let mut desired_headers = Vec::with_capacity(languages.len() + 2);
        desired_headers.push("Translation Key".to_string());
        desired_headers.push("Description".to_string());

        for language in languages {
            if let Some(existing_label) = existing_language_labels.get(language) {
                desired_headers.push(existing_label.clone());
            } else if is_initial_setup && language == main_language {
                desired_headers.push(SheetsManager::header_label_for_language(language, true));
            } else {
                desired_headers.push(language.clone());
            }
        }

        let sheet_id = self.sheet_id.clone();
        let hub = self.get_hub().await?;

        // Create the header row value range
        let end_column_index = languages.len() + 1; // zero-based index
        let end_column_letter = Self::column_index_to_letter(end_column_index);
        let header_range = format!("{}!A1:{}{}", namespace, end_column_letter, 1);

        let header_values: Vec<serde_json::Value> = desired_headers
            .iter()
            .map(|value| serde_json::Value::String(value.clone()))
            .collect();

        let value_range = ValueRange {
            range: Some(header_range.clone()),
            values: Some(vec![header_values]),
            major_dimension: Some("ROWS".to_string()),
            ..Default::default()
        };

        let result = Self::call_with_rate_limit_retry("update worksheet headers", || {
            let hub = hub;
            let sheet_id = sheet_id.clone();
            let header_range = header_range.clone();
            let values = value_range.clone();
            async move {
                hub.spreadsheets()
                    .values_update(values, &sheet_id, &header_range)
                    .value_input_option("USER_ENTERED")
                    .doit()
                    .await
            }
        })
        .await;

        match result {
            Ok(_) => {
                info!(
                    "✅ Successfully set up headers for worksheet '{}'",
                    namespace
                );

                // Apply formatting: bold headers and freeze first row
                self.format_sheet_headers(namespace, languages.len() + 2)
                    .await?;

                Ok(())
            }
            Err(e) => Err(anyhow::anyhow!(
                "Failed to set up sheet structure for '{}': {}",
                namespace,
                e
            )),
        }
    }

    /// Returns the ordered list of language headers currently present for a namespace.
    pub async fn header_languages(&mut self, namespace: &str) -> Result<Vec<String>> {
        let headers = self.fetch_existing_headers(namespace).await?;

        Ok(headers
            .map(|row| {
                row.into_iter()
                    .skip(2)
                    .map(|value| SheetsManager::normalize_language_header(&value))
                    .filter(|value| !value.is_empty())
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn fetch_sheet_rows(
        &mut self,
        namespace: &str,
        total_columns: usize,
    ) -> Result<Vec<SheetRowData>> {
        if total_columns == 0 {
            return Ok(Vec::new());
        }

        let sheet_id = self.sheet_id.clone();
        let hub = self.get_hub().await?;
        let end_column_letter = Self::column_index_to_letter(total_columns - 1);
        let range = format!("{}!A:{}", namespace, end_column_letter);

        let result = Self::call_with_rate_limit_retry("fetch worksheet rows", || {
            let hub = hub;
            let sheet_id = sheet_id.clone();
            let range = range.clone();
            async move {
                hub.spreadsheets()
                    .values_get(&sheet_id, &range)
                    .value_render_option("FORMATTED_VALUE")
                    .doit()
                    .await
            }
        })
        .await;

        match result {
            Ok((_, value_range)) => {
                let mut rows = Vec::new();
                let all_rows = value_range.values.unwrap_or_default();

                for (index, row) in all_rows.into_iter().enumerate() {
                    if index == 0 {
                        continue; // skip header row
                    }

                    let row_number = index + 1; // 1-based indexing
                    let values = row
                        .into_iter()
                        .map(|cell| Self::json_value_to_string(&cell))
                        .collect();

                    rows.push(SheetRowData { row_number, values });
                }

                Ok(rows)
            }
            Err(err) => {
                warn!(
                    "⚠️  Could not fetch rows for '{}' when backfilling languages: {}",
                    namespace, err
                );
                Ok(Vec::new())
            }
        }
    }

    pub async fn backfill_new_language_columns(
        &mut self,
        namespace: &str,
        languages: &[String],
        new_languages: &[String],
        existing_keys: &HashMap<String, HashMap<String, String>>,
        local_keys: &[TranslationKey],
        default_language: &str,
        dry_run: bool,
    ) -> Result<usize> {
        if new_languages.is_empty() {
            return Ok(0);
        }

        let total_columns = languages.len() + 2; // Key + Description + languages
        let rows = self.fetch_sheet_rows(namespace, total_columns).await?;

        if rows.is_empty() {
            debug!(
                "ℹ️  No existing rows to backfill for '{}' even though new languages {:?} were added",
                namespace, new_languages
            );
            return Ok(0);
        }

        let mut local_map: HashMap<&str, &TranslationKey> = HashMap::new();
        for key in local_keys {
            local_map.insert(key.key_path.as_str(), key);
        }

        let mut updates: Vec<ValueRange> = Vec::new();
        let mut updated_cells_per_language: HashMap<String, usize> = HashMap::new();

        for row in &rows {
            let key = match row.values.first() {
                Some(value) if !value.trim().is_empty() => value.clone(),
                _ => continue,
            };

            let translation_key = if let Some(local_key) = local_map.get(key.as_str()) {
                Cow::Borrowed(*local_key)
            } else {
                let mut values = HashMap::new();
                if let Some(existing) = existing_keys.get(&key) {
                    values.extend(existing.clone());
                }

                Cow::Owned(TranslationKey {
                    key_path: key.clone(),
                    values,
                    namespace: namespace.to_string(),
                })
            };

            let default_for_key =
                SheetsManager::find_default_language_static(&translation_key, languages)
                    .or_else(|| Some(default_language.to_string()));

            for language in new_languages {
                let Some(language_position) = languages.iter().position(|lang| lang == language)
                else {
                    continue;
                };

                let column_index = 2 + language_position;
                let existing_cell = row
                    .values
                    .get(column_index)
                    .map(|value| value.trim())
                    .unwrap_or("");

                if !existing_cell.is_empty() {
                    continue;
                }

                let cell_value = SheetsManager::get_cell_value_for_language_static(
                    &translation_key,
                    language,
                    &default_for_key,
                    languages,
                    row.row_number,
                );

                if cell_value.trim().is_empty() {
                    continue;
                }

                let column_letter = SheetsManager::column_index_to_letter(column_index);
                let range = format!(
                    "{}!{}{}:{}{}",
                    namespace, column_letter, row.row_number, column_letter, row.row_number
                );

                updates.push(ValueRange {
                    range: Some(range),
                    values: Some(vec![vec![serde_json::Value::String(cell_value)]]),
                    major_dimension: Some("ROWS".to_string()),
                    ..Default::default()
                });

                *updated_cells_per_language
                    .entry(language.clone())
                    .or_default() += 1;
            }
        }

        if updates.is_empty() {
            return Ok(0);
        }

        if dry_run {
            for (language, count) in &updated_cells_per_language {
                info!(
                    "🔍 [DRY RUN] Would backfill {} cells for language '{}' in '{}'",
                    count, language, namespace
                );
            }
            return Ok(updates.len());
        }

        const MAX_UPDATES_PER_REQUEST: usize = 100;
        let sheet_id = self.sheet_id.clone();
        let hub = self.get_hub().await?;

        for chunk in updates.chunks(MAX_UPDATES_PER_REQUEST) {
            let request = BatchUpdateValuesRequest {
                value_input_option: Some("USER_ENTERED".to_string()),
                data: Some(chunk.to_vec()),
                ..Default::default()
            };

            Self::call_with_rate_limit_retry("backfill language column", || {
                let hub = hub;
                let sheet_id = sheet_id.clone();
                let request = request.clone();
                async move {
                    hub.spreadsheets()
                        .values_batch_update(request, &sheet_id)
                        .doit()
                        .await
                }
            })
            .await?;
        }

        for (language, count) in &updated_cells_per_language {
            info!(
                "✅ Backfilled {} cells for language '{}' in '{}'",
                count, language, namespace
            );
        }

        Ok(updates.len())
    }

    /// Fetches the existing header row for a namespace (if any).
    async fn fetch_existing_headers(&mut self, namespace: &str) -> Result<Option<Vec<String>>> {
        let sheet_id = self.sheet_id.clone();
        let hub = self.get_hub().await?;
        let range = format!("{}!1:1", namespace);

        let result = Self::call_with_rate_limit_retry("fetch worksheet headers", || {
            let hub = hub;
            let sheet_id = sheet_id.clone();
            let range = range.clone();
            async move {
                hub.spreadsheets()
                    .values_get(&sheet_id, &range)
                    .doit()
                    .await
            }
        })
        .await;

        match result {
            Ok((_, response)) => {
                if let Some(values) = response.values
                    && let Some(first_row) = values.first()
                {
                    let mut headers = first_row
                        .iter()
                        .map(|cell| cell.as_str().unwrap_or("").to_string())
                        .collect::<Vec<_>>();

                    while headers
                        .last()
                        .map(|cell| cell.trim().is_empty())
                        .unwrap_or(false)
                    {
                        headers.pop();
                    }

                    if headers.is_empty() {
                        return Ok(None);
                    }

                    return Ok(Some(headers));
                }

                Ok(None)
            }
            Err(err) => {
                debug!(
                    "⚠️  Could not fetch headers for '{}', treating as missing: {}",
                    namespace, err
                );
                Ok(None)
            }
        }
    }

    /// Applies formatting to the sheet headers (bold text, frozen row).
    async fn format_sheet_headers(&mut self, namespace: &str, num_columns: usize) -> Result<()> {
        debug!("🎨 Applying formatting to headers for '{}'", namespace);

        // Get the worksheet ID for this namespace
        let worksheet_id = match self.get_worksheet_by_namespace(namespace).await? {
            Some(id) => id,
            None => {
                return Err(anyhow::anyhow!(
                    "Worksheet '{}' not found for formatting",
                    namespace
                ));
            }
        };

        let sheet_id = self.sheet_id.clone();
        let hub = self.get_hub().await?;

        // Create formatting requests
        let mut requests = vec![];

        // 1. Bold the header row
        requests.push(Request {
            repeat_cell: Some(RepeatCellRequest {
                range: Some(GridRange {
                    sheet_id: Some(worksheet_id),
                    start_row_index: Some(0),
                    end_row_index: Some(1),
                    start_column_index: Some(0),
                    end_column_index: Some(num_columns as i32),
                    ..Default::default()
                }),
                cell: Some(CellData {
                    user_entered_format: Some(CellFormat {
                        text_format: Some(TextFormat {
                            bold: Some(true),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                fields: Some(FieldMask::new(&["userEnteredFormat.textFormat.bold"])),
                ..Default::default()
            }),
            ..Default::default()
        });

        // 2. Freeze the first row
        requests.push(Request {
            update_sheet_properties: Some(UpdateSheetPropertiesRequest {
                properties: Some(SheetProperties {
                    sheet_id: Some(worksheet_id),
                    grid_properties: Some(GridProperties {
                        frozen_row_count: Some(1),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                fields: Some(FieldMask::new(&["gridProperties.frozenRowCount"])),
                ..Default::default()
            }),
            ..Default::default()
        });

        // Execute formatting requests
        let batch_request = BatchUpdateSpreadsheetRequest {
            requests: Some(requests),
            ..Default::default()
        };

        let result = Self::call_with_rate_limit_retry("apply header formatting", || {
            let hub = hub;
            let sheet_id = sheet_id.clone();
            let request = batch_request.clone();
            async move {
                hub.spreadsheets()
                    .batch_update(request, &sheet_id)
                    .doit()
                    .await
            }
        })
        .await;

        match result {
            Ok(_) => {
                debug!("✅ Successfully applied formatting to '{}'", namespace);
                Ok(())
            }
            Err(e) => {
                warn!(
                    "⚠️  Warning: Failed to apply formatting to '{}': {}",
                    namespace, e
                );
                // Don't fail the entire operation just because formatting failed
                Ok(())
            }
        }
    }

    /// Helper method to get or create a worksheet for a given namespace.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace to get or create a worksheet for
    /// * `languages` - Language codes to use if creating a new worksheet
    ///
    /// # Returns
    ///
    /// `Ok(sheet_id)` if worksheet exists or was created, otherwise an error.
    pub async fn ensure_worksheet(&mut self, namespace: &str, languages: &[String]) -> Result<i32> {
        match self.get_worksheet_by_namespace(namespace).await? {
            Some(sheet_id) => {
                info!(
                    "📋 Using existing worksheet '{}' (ID: {})",
                    namespace, sheet_id
                );
                Ok(sheet_id)
            }
            None => {
                info!("➕ Creating new worksheet '{}'", namespace);
                self.create_worksheet(namespace, languages).await
            }
        }
    }

    /// Finds the best default language to use as source for translations.
    ///
    /// Priority order: 'en', 'en-US', first language with a value, or first in list.
    fn find_default_language_static(
        translation_key: &TranslationKey,
        languages: &[String],
    ) -> Option<String> {
        // Priority 1: Check for English variants
        for lang in ["en", "en-US", "en-GB"] {
            if translation_key.values.contains_key(lang) {
                return Some(lang.to_string());
            }
        }

        // Priority 2: Find first language that has a value
        for language in languages {
            if translation_key.values.contains_key(language) {
                return Some(language.clone());
            }
        }

        // Priority 3: Use first language in the list as fallback
        languages.first().cloned()
    }

    /// Gets the appropriate cell value for a language, either the existing translation
    /// or a GOOGLETRANSLATE formula referencing the default language.
    fn get_cell_value_for_language_static(
        translation_key: &TranslationKey,
        target_language: &str,
        default_language: &Option<String>,
        languages: &[String],
        row_number: usize,
    ) -> String {
        // If we have a direct translation and it's not empty, use it
        if let Some(existing_value) = translation_key.values.get(target_language)
            && !existing_value.trim().is_empty()
        {
            return existing_value.clone();
        }
        // If empty, fall through to generate translation formula

        // If we don't have a default language, return whatever we have (likely empty)
        let default_lang = match default_language {
            Some(lang) => lang,
            None => {
                return translation_key
                    .values
                    .get(target_language)
                    .cloned()
                    .unwrap_or_default();
            }
        };

        // Don't create formula for the default language itself
        if target_language == default_lang {
            return translation_key
                .values
                .get(default_lang)
                .cloned()
                .unwrap_or_default();
        }

        // Determine the column letter for the default language header (Key=A index0, Desc=B index1)
        if let Some(default_position) = languages.iter().position(|lang| lang == default_lang) {
            let default_column_index = 2 + default_position; // shift for Key & Description columns
            let default_col_letter = Self::column_index_to_letter(default_column_index);
            let translate_service = crate::sheets::TranslateService::new();

            return translate_service.generate_translate_formula_with_cell_ref(
                &format!("{}{}", default_col_letter, row_number),
                default_lang,
                target_language,
            );
        }

        // Fallback: if we cannot determine default column, return existing value
        translation_key
            .values
            .get(target_language)
            .cloned()
            .unwrap_or_default()
    }

    fn header_label_for_language(language: &str, is_main: bool) -> String {
        if is_main {
            format!("{}{}", language, MAIN_LANGUAGE_SUFFIX)
        } else {
            language.to_string()
        }
    }

    fn normalize_language_header(value: &str) -> String {
        let trimmed = value.trim();
        if let Some(stripped) = trimmed.strip_suffix(MAIN_LANGUAGE_SUFFIX) {
            stripped.trim().to_string()
        } else {
            trimmed.to_string()
        }
    }

    fn json_value_to_string(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(num) => num.to_string(),
            serde_json::Value::Bool(flag) => flag.to_string(),
            serde_json::Value::Null => String::new(),
            other => other.to_string(),
        }
    }

    /// Converts a zero-based column index to a column letter (0=A, 25=Z, 26=AA, ...).
    fn column_index_to_letter(index: usize) -> String {
        let mut result = String::new();
        let mut n = index;

        loop {
            result.insert(0, (b'A' + (n % 26) as u8) as char);
            if n < 26 {
                break;
            }
            n = n / 26 - 1;
        }

        result
    }

    /// Handles large batch updates by splitting them into smaller chunks.
    async fn batch_update_in_chunks(
        &mut self,
        namespace: &str,
        value_ranges: Vec<ValueRange>,
        chunk_size: usize,
    ) -> Result<usize> {
        info!(
            "📦 Large batch detected ({} rows), splitting into chunks of {}",
            value_ranges.len(),
            chunk_size
        );

        let mut total_updated = 0;
        let chunks: Vec<_> = value_ranges.chunks(chunk_size).collect();

        for (i, chunk) in chunks.iter().enumerate() {
            info!(
                "📋 Processing chunk {} of {} ({} rows)...",
                i + 1,
                chunks.len(),
                chunk.len()
            );

            let chunk_request = BatchUpdateValuesRequest {
                value_input_option: Some("USER_ENTERED".to_string()),
                data: Some(chunk.to_vec()),
                ..Default::default()
            };

            let sheet_id = self.sheet_id.clone();
            let hub = self.get_hub().await?;

            let description = format!("batch update chunk {} of {}", i + 1, chunks.len());
            let result = Self::call_with_rate_limit_retry(description.as_str(), || {
                let hub = hub;
                let sheet_id = sheet_id.clone();
                let request = chunk_request.clone();
                async move {
                    hub.spreadsheets()
                        .values_batch_update(request, &sheet_id)
                        .doit()
                        .await
                }
            })
            .await;

            match result {
                Ok((_, response)) => {
                    let updated_rows = response.total_updated_rows.unwrap_or(0);
                    total_updated += updated_rows as usize;
                    info!(
                        "✅ Chunk {} completed: {} rows updated",
                        i + 1,
                        updated_rows
                    );

                    // Add a small delay between chunks to avoid rate limiting
                    if i < chunks.len() - 1 {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                }
                Err(e) => {
                    let error_msg = format!(
                        "Failed to update chunk {} in worksheet '{}': {}",
                        i + 1,
                        namespace,
                        e
                    );
                    error!("❌ {}", error_msg);
                    return Err(anyhow::anyhow!(error_msg));
                }
            }
        }

        info!(
            "🎉 All chunks completed! Total rows updated: {}",
            total_updated
        );
        Ok(total_updated)
    }

    async fn fetch_last_used_row(&mut self, namespace: &str) -> Result<usize> {
        // Read column A only (fast) to detect last non-empty key row.
        let sheet_id = self.sheet_id.clone();
        let hub = self.get_hub().await?;
        let range = format!("{}!A:A", namespace);
        let result = Self::call_with_rate_limit_retry("fetch last used row", || {
            let hub = hub;
            let sheet_id = sheet_id.clone();
            let range = range.clone();
            async move { hub.spreadsheets().values_get(&sheet_id, &range).doit().await }
        }).await?;

        let values = result.1.values.unwrap_or_default();
        // values.len() already equals the last non-empty row index (1-based),
        // because trailing empty rows are trimmed by the API.
        Ok(values.len())
    }

    // NEW: Pure planning helper extracted from batch_update_cells. Returns prepared value ranges and stats.
    fn plan_batch_updates(
        &self,
        namespace: &str,
        translation_keys: &[TranslationKey],
        languages: &[String],
        existing_keys: &HashMap<String, HashMap<String, String>>,
        mut next_row: usize,
        key_row_map: &HashMap<String, usize>,
    ) -> (
        Vec<ValueRange>,                // value ranges to send
        usize,                          // new rows added
        usize,                          // existing cells filled
        HashMap<String, usize>,         // per-language filled cell counts
    ) {
        use std::collections::HashSet;
        let mut processed: HashSet<&str> = HashSet::new();
        let mut value_ranges: Vec<ValueRange> = Vec::new();
        let mut new_rows_added = 0usize;
        let mut existing_cells_filled = 0usize;
        let mut per_language: HashMap<String, usize> = HashMap::new();

        for tk in translation_keys {
            if !processed.insert(tk.key_path.as_str()) {
                warn!("⚠️  Skipping duplicate key in input batch: {}", tk.key_path);
                continue;
            }

            if !existing_keys.contains_key(&tk.key_path) {
                // New key row
                let mut row_values = vec![
                    serde_json::Value::String(tk.key_path.clone()),
                    serde_json::Value::String(String::new()), // Description placeholder
                ];
                let default_language = Self::find_default_language_static(tk, languages);
                for lang in languages {
                    let v = Self::get_cell_value_for_language_static(
                        tk,
                        lang,
                        &default_language,
                        languages,
                        next_row,
                    );
                    row_values.push(serde_json::Value::String(v));
                }
                let end_col_index = languages.len() + 1; // zero-based index for last column
                let end_letter = Self::column_index_to_letter(end_col_index);
                let range = format!("{}!A{}:{}{}", namespace, next_row, end_letter, next_row);
                value_ranges.push(ValueRange {
                    range: Some(range),
                    values: Some(vec![row_values]),
                    major_dimension: Some("ROWS".into()),
                    ..Default::default()
                });
                next_row += 1;
                new_rows_added += 1;
                continue;
            }

            // Existing key: attempt to fill empty translations
            let row_number = if let Some(r) = key_row_map.get(&tk.key_path) {
                *r
            } else {
                // Row missing physically though logically present: treat as new
                let mut row_values = vec![
                    serde_json::Value::String(tk.key_path.clone()),
                    serde_json::Value::String(String::new()),
                ];
                let default_language = Self::find_default_language_static(tk, languages);
                for lang in languages {
                    let v = Self::get_cell_value_for_language_static(
                        tk,
                        lang,
                        &default_language,
                        languages,
                        next_row,
                    );
                    row_values.push(serde_json::Value::String(v));
                }
                let end_col_index = languages.len() + 1;
                let end_letter = Self::column_index_to_letter(end_col_index);
                let range = format!("{}!A{}:{}{}", namespace, next_row, end_letter, next_row);
                value_ranges.push(ValueRange {
                    range: Some(range),
                    values: Some(vec![row_values]),
                    major_dimension: Some("ROWS".into()),
                    ..Default::default()
                });
                next_row += 1;
                new_rows_added += 1;
                continue;
            };

            let existing_langs = existing_keys.get(&tk.key_path).unwrap();
            let default_language = Self::find_default_language_static(tk, languages)
                .or_else(|| {
                    Self::find_default_language_static(
                        &TranslationKey {
                            key_path: tk.key_path.clone(),
                            values: existing_langs.clone(),
                            namespace: namespace.to_string(),
                        },
                        languages,
                    )
                });

            for (pos, lang) in languages.iter().enumerate() {
                if existing_langs.contains_key(lang) {
                    continue;
                }
                let cell_value = Self::get_cell_value_for_language_static(
                    tk,
                    lang,
                    &default_language,
                    languages,
                    row_number,
                );
                if cell_value.trim().is_empty() {
                    continue;
                }
                let col_index = 2 + pos; // offset for key + desc
                let col_letter = Self::column_index_to_letter(col_index);
                let range = format!("{}!{}{}:{}{}", namespace, col_letter, row_number, col_letter, row_number);
                value_ranges.push(ValueRange {
                    range: Some(range),
                    values: Some(vec![vec![serde_json::Value::String(cell_value)]]),
                    major_dimension: Some("ROWS".into()),
                    ..Default::default()
                });
                existing_cells_filled += 1;
                *per_language.entry(lang.clone()).or_default() += 1;
            }
        }

        (value_ranges, new_rows_added, existing_cells_filled, per_language)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn build_translation_key(values: Vec<(&str, &str)>) -> TranslationKey {
        let mut map = HashMap::new();
        for (lang, value) in values {
            map.insert(lang.to_string(), value.to_string());
        }
        TranslationKey {
            key_path: "auth.login".to_string(),
            values: map,
            namespace: "auth".to_string(),
        }
    }

    #[test]
    fn generates_formula_for_missing_translation() {
        let key = build_translation_key(vec![("en", "Login")]);
        let languages = vec!["en".to_string(), "fr".to_string()];
        let default_lang = Some("en".to_string());

        let result = SheetsManager::get_cell_value_for_language_static(
            &key,
            "fr",
            &default_lang,
            &languages,
            5,
        );

        assert_eq!(result, "=GOOGLETRANSLATE(C5, \"en\", \"fr\")");
    }

    #[test]
    fn reuses_existing_translation_when_present() {
        let key = build_translation_key(vec![("en", "Login"), ("fr", "Connexion")]);
        let languages = vec!["en".to_string(), "fr".to_string()];
        let default_lang = Some("en".to_string());

        let result = SheetsManager::get_cell_value_for_language_static(
            &key,
            "fr",
            &default_lang,
            &languages,
            5,
        );

        assert_eq!(result, "Connexion");
    }

    // Additional tests for planning logic
    #[test]
    fn plan_new_rows_only() {
        let mgr = SheetsManager { sheet_id: "s".into(), auth_manager: crate::auth::oauth::AuthManager::new(None), main_language: "en".into(), hub: None };
        let languages = vec!["en".into(), "fr".into()];
        let tk1 = TranslationKey { key_path: "k1".into(), values: HashMap::from([(String::from("en"), String::from("Hello"))]), namespace: "ns".into() };
        let tk2 = TranslationKey { key_path: "k2".into(), values: HashMap::from([(String::from("en"), String::from("World"))]), namespace: "ns".into() };
        let existing = HashMap::new();
        let key_row_map = HashMap::new();
        let (ranges, new_rows, filled, per_lang) = mgr.plan_batch_updates("ns", &[tk1, tk2], &languages, &existing, 2, &key_row_map);
        assert_eq!(new_rows, 2);
        assert_eq!(filled, 0);
        assert!(per_lang.is_empty());
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn plan_fills_missing_cells() {
        let mgr = SheetsManager { sheet_id: "s".into(), auth_manager: crate::auth::oauth::AuthManager::new(None), main_language: "en".into(), hub: None };
        let languages = vec!["en".into(), "fr".into()];
        let mut existing: HashMap<String, HashMap<String,String>> = HashMap::new();
        existing.insert("k1".into(), HashMap::from([(String::from("en"), String::from("Hi"))]));
        let key_row_map = HashMap::from([(String::from("k1"), 2usize)]);
        let tk = TranslationKey { key_path: "k1".into(), values: HashMap::from([(String::from("en"), String::from("Hi"))]), namespace: "ns".into() };
        let (ranges, new_rows, filled, per_lang) = mgr.plan_batch_updates("ns", &[tk], &languages, &existing, 3, &key_row_map);
        assert_eq!(new_rows, 0);
        assert_eq!(filled, 1); // fr cell generated
        assert_eq!(per_lang.get("fr").copied(), Some(1));
        assert_eq!(ranges.len(), 1);
    }

    #[test]
    fn plan_skips_duplicates() {
        let mgr = SheetsManager { sheet_id: "s".into(), auth_manager: crate::auth::oauth::AuthManager::new(None), main_language: "en".into(), hub: None };
        let languages = vec!["en".into()];
        let existing = HashMap::new();
        let key_row_map = HashMap::new();
        let tk1 = TranslationKey { key_path: "dup".into(), values: HashMap::from([(String::from("en"), String::from("A"))]), namespace: "ns".into() };
        let tk2 = TranslationKey { key_path: "dup".into(), values: HashMap::from([(String::from("en"), String::from("B"))]), namespace: "ns".into() };
        let (ranges, new_rows, filled, _) = mgr.plan_batch_updates("ns", &[tk1, tk2], &languages, &existing, 2, &key_row_map);
        assert_eq!(new_rows, 1);
        assert_eq!(filled, 0);
        assert_eq!(ranges.len(), 1);
    }
}
