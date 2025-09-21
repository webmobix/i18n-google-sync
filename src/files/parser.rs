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

use anyhow::Result;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct TranslationKey {
    pub key_path: String,
    pub values: HashMap<String, String>,
    pub namespace: String,
}

#[derive(Debug)]
pub struct TranslationFile {
    pub namespace: String,
    pub language: String,
    pub keys: Vec<TranslationKey>,
}

pub struct TranslationParser;

impl TranslationParser {
    pub fn new() -> Self {
        Self
    }

    /// Lists language codes by inspecting subdirectories inside `locales_path`.
    pub fn list_languages<P: AsRef<Path>>(&self, locales_path: P) -> Result<Vec<String>> {
        let locales_path = locales_path.as_ref();

        if !locales_path.exists() {
            anyhow::bail!("Locales directory does not exist: {:?}", locales_path);
        }

        if !locales_path.is_dir() {
            anyhow::bail!("Path is not a directory: {:?}", locales_path);
        }

        let mut languages = Vec::new();
        for entry in fs::read_dir(locales_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir()
                && let Some(language) = path.file_name().and_then(|n| n.to_str())
            {
                languages.push(language.to_string());
            }
        }

        languages.sort();
        languages.dedup();
        Ok(languages)
    }

    pub fn scan_locales_directory<P: AsRef<Path>>(
        &self,
        locales_path: P,
    ) -> Result<Vec<TranslationFile>> {
        let mut files = Vec::new();
        let locales_path = locales_path.as_ref();

        info!("📂 Scanning locales directory: {:?}", locales_path);

        if !locales_path.exists() {
            anyhow::bail!("Locales directory does not exist: {:?}", locales_path);
        }

        if !locales_path.is_dir() {
            anyhow::bail!("Path is not a directory: {:?}", locales_path);
        }

        // Read all language directories (e.g., en, fr, es)
        for entry in fs::read_dir(locales_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir()
                && let Some(language) = path.file_name().and_then(|n| n.to_str())
            {
                debug!("🌍 Found language directory: {}", language);

                // Scan for JSON files in this language directory
                for file_entry in fs::read_dir(&path)? {
                    let file_entry = file_entry?;
                    let file_path = file_entry.path();

                    if file_path.is_file()
                        && file_path.extension().and_then(|ext| ext.to_str()) == Some("json")
                    {
                        match self.parse_translation_file(&file_path) {
                            Ok(translation_file) => {
                                debug!("✅ Parsed: {:?}", file_path);
                                files.push(translation_file);
                            }
                            Err(e) => {
                                warn!("❌ Failed to parse {:?}: {}", file_path, e);
                            }
                        }
                    }
                }
            }
        }

        info!("📊 Found {} translation files", files.len());
        Ok(files)
    }

    /// Aggregates translation keys by namespace, merging values from all languages.
    ///
    /// This method scans the locales directory and returns a HashMap where:
    /// - Key: namespace (e.g., "common", "auth")
    /// - Value: Vec<TranslationKey> with values from all languages
    ///
    /// # Arguments
    ///
    /// * `locales_path` - Path to the locales directory
    ///
    /// # Returns
    ///
    /// `Ok(HashMap<String, Vec<TranslationKey>>)` on success, keyed by namespace
    pub fn scan_and_aggregate_by_namespace<P: AsRef<Path>>(
        &self,
        locales_path: P,
    ) -> Result<HashMap<String, Vec<TranslationKey>>> {
        let translation_files = self.scan_locales_directory(locales_path)?;
        Ok(self.aggregate_keys_by_namespace(translation_files))
    }

    /// Aggregates translation keys from multiple language files by namespace.
    ///
    /// Takes translation files from different languages and combines keys with the same
    /// key_path into single TranslationKey objects containing values for all languages.
    ///
    /// # Arguments
    ///
    /// * `translation_files` - Vector of translation files from all languages
    ///
    /// # Returns
    ///
    /// HashMap mapping namespace to aggregated TranslationKey objects
    pub fn aggregate_keys_by_namespace(
        &self,
        translation_files: Vec<TranslationFile>,
    ) -> HashMap<String, Vec<TranslationKey>> {
        let mut namespace_keys: HashMap<String, HashMap<String, TranslationKey>> = HashMap::new();

        // Group translation files by namespace and aggregate keys
        for file in translation_files {
            let namespace_map = namespace_keys.entry(file.namespace.clone()).or_default();

            for key in file.keys {
                if let Some(existing_key) = namespace_map.get_mut(&key.key_path) {
                    // Merge language values into existing key
                    for (language, value) in key.values {
                        existing_key.values.insert(language, value);
                    }
                } else {
                    // Create new aggregated key
                    namespace_map.insert(key.key_path.clone(), key);
                }
            }
        }

        // Convert to final format
        let mut result = HashMap::new();
        for (namespace, key_map) in namespace_keys {
            let keys: Vec<TranslationKey> = key_map.into_values().collect();
            info!(
                "📋 Namespace '{}': {} unique keys across all languages",
                namespace,
                keys.len()
            );
            result.insert(namespace, keys);
        }

        result
    }

    pub fn parse_translation_file<P: AsRef<Path>>(&self, file_path: P) -> Result<TranslationFile> {
        let file_path = file_path.as_ref();
        debug!("📄 Parsing translation file: {:?}", file_path);

        // Extract namespace from filename (e.g., "common.json" -> "common")
        let namespace = file_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid filename: {:?}", file_path))?
            .to_string();

        // Extract language from parent directory (e.g., "locales/en/common.json" -> "en")
        let language = file_path
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("Cannot determine language from path: {:?}", file_path))?
            .to_string();

        // Read and parse JSON file
        let content = fs::read_to_string(file_path)?;
        let json_value: Value = serde_json::from_str(&content)?;

        // Extract all keys from the JSON structure
        let key_paths = self.extract_translation_keys(&json_value, "");
        let mut keys = Vec::new();

        for key_path in key_paths {
            // Get the value for this key path
            if let Some(value) = self.get_value_at_path(&json_value, &key_path) {
                let value_str = match value {
                    Value::String(s) => Some(s.clone()),
                    Value::Array(arr) => {
                        // Convert array to JSON string for storage
                        Some(serde_json::to_string(arr).unwrap_or_default())
                    }
                    Value::Number(n) => Some(n.to_string()),
                    Value::Bool(b) => Some(b.to_string()),
                    Value::Null => Some("null".to_string()),
                    _ => None,
                };

                if let Some(value_string) = value_str {
                    let mut values = HashMap::new();
                    values.insert(language.clone(), value_string);

                    keys.push(TranslationKey {
                        key_path: key_path.clone(),
                        values,
                        namespace: namespace.clone(),
                    });
                }
            }
        }

        info!(
            "🔑 Found {} translation keys in {}/{}",
            keys.len(),
            language,
            namespace
        );

        Ok(TranslationFile {
            namespace,
            language,
            keys,
        })
    }

    pub fn extract_translation_keys(&self, json_value: &Value, prefix: &str) -> Vec<String> {
        let mut keys = Vec::new();

        match json_value {
            Value::Object(map) => {
                for (key, value) in map {
                    let full_key = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", prefix, key)
                    };

                    match value {
                        Value::String(_) => {
                            // This is a leaf node - add it as a translation key
                            keys.push(full_key);
                        }
                        Value::Object(_) => {
                            // This is a nested object - recurse into it
                            let mut nested_keys = self.extract_translation_keys(value, &full_key);
                            keys.append(&mut nested_keys);
                        }
                        Value::Array(arr) => {
                            // Handle arrays - check if all elements are strings
                            if arr.iter().all(|item| item.is_string()) {
                                // Treat array of strings as a single translation key
                                keys.push(full_key);
                            } else {
                                // Recurse into array elements
                                for (index, item) in arr.iter().enumerate() {
                                    let indexed_key = format!("{}[{}]", full_key, index);
                                    let mut nested_keys =
                                        self.extract_translation_keys(item, &indexed_key);
                                    keys.append(&mut nested_keys);
                                }
                            }
                        }
                        _ => {
                            // For other value types (null, bool, number), treat as translation key
                            keys.push(full_key);
                        }
                    }
                }
            }
            Value::String(_) => {
                // If the root is a string and we have a prefix, add it
                if !prefix.is_empty() {
                    keys.push(prefix.to_string());
                }
            }
            _ => {
                // For other types at root level, add the prefix if it exists
                if !prefix.is_empty() {
                    keys.push(prefix.to_string());
                }
            }
        }

        keys
    }

    fn get_value_at_path<'a>(&self, json_value: &'a Value, key_path: &str) -> Option<&'a Value> {
        let mut current = json_value;

        for part in key_path.split('.') {
            // Handle array notation like "items[0]"
            if part.contains('[') && part.ends_with(']') {
                let bracket_pos = part.find('[').unwrap();
                let key = &part[..bracket_pos];
                let index_str = &part[bracket_pos + 1..part.len() - 1];

                if let Ok(index) = index_str.parse::<usize>() {
                    current = current.get(key)?;
                    current = current.get(index)?;
                } else {
                    return None;
                }
            } else {
                current = current.get(part)?;
            }
        }

        Some(current)
    }

    pub fn validate_file_structure<P: AsRef<Path>>(&self, locales_path: P) -> Result<()> {
        let locales_path = locales_path.as_ref();
        info!("🔍 Validating file structure in: {:?}", locales_path);

        if !locales_path.exists() {
            anyhow::bail!("Locales directory does not exist: {:?}", locales_path);
        }

        let mut language_dirs = Vec::new();
        let mut all_namespaces = HashSet::new();
        let mut files_by_language: HashMap<String, HashMap<String, HashSet<String>>> =
            HashMap::new();
        let mut parse_errors = Vec::new();
        let mut parse_error_entries = HashSet::new();

        // Single pass: collect languages, namespaces, and parsed key sets
        for entry in fs::read_dir(locales_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir()
                && let Some(language) = path.file_name().and_then(|n| n.to_str())
            {
                let language = language.to_string();
                language_dirs.push((language.clone(), path.clone()));

                for file_entry in fs::read_dir(&path)? {
                    let file_entry = file_entry?;
                    let file_path = file_entry.path();

                    if file_path.is_file()
                        && file_path.extension().and_then(|ext| ext.to_str()) == Some("json")
                        && let Some(namespace) =
                            file_path.file_stem().and_then(|stem| stem.to_str())
                    {
                        let namespace = namespace.to_string();
                        all_namespaces.insert(namespace.clone());

                        match self.parse_translation_file(&file_path) {
                            Ok(translation_file) => {
                                let key_set: HashSet<String> = translation_file
                                    .keys
                                    .iter()
                                    .map(|k| k.key_path.clone())
                                    .collect();

                                files_by_language
                                    .entry(language.clone())
                                    .or_default()
                                    .insert(namespace.clone(), key_set);
                            }
                            Err(e) => {
                                parse_errors.push(format!(
                                    "{}/{}.json (parse error: {})",
                                    language, namespace, e
                                ));
                                parse_error_entries.insert((language.clone(), namespace.clone()));
                            }
                        }
                    }
                }
            }
        }

        if language_dirs.is_empty() {
            anyhow::bail!("No language directories found in: {:?}", locales_path);
        }

        if all_namespaces.is_empty() {
            anyhow::bail!("No translation files found in any language directory");
        }

        info!(
            "🌍 Found languages: {:?}",
            language_dirs
                .iter()
                .map(|(lang, _)| lang)
                .collect::<Vec<_>>()
        );
        info!(
            "📄 Found namespaces: {:?}",
            all_namespaces.iter().collect::<Vec<_>>()
        );

        // Validate that all languages have all namespaces
        let mut missing_files = Vec::new();

        for (language, _) in &language_dirs {
            for namespace in &all_namespaces {
                if parse_error_entries.contains(&(language.clone(), namespace.clone())) {
                    // The file exists but failed to parse; will be reported separately
                    continue;
                }

                let has_file = files_by_language
                    .get(language)
                    .map(|namespaces| namespaces.contains_key(namespace))
                    .unwrap_or(false);

                if !has_file {
                    missing_files.push(format!("{}/{}.json", language, namespace));
                }
            }
        }

        if !missing_files.is_empty() {
            warn!("⚠️  Missing translation files:");
            for file in &missing_files {
                warn!("   - {}", file);
            }
            anyhow::bail!(
                "File structure validation failed: {} missing files",
                missing_files.len()
            );
        }

        if !parse_errors.is_empty() {
            warn!("⚠️  Files with parse errors:");
            for error in &parse_errors {
                warn!("   - {}", error);
            }
            anyhow::bail!(
                "File structure validation failed: {} parse errors",
                parse_errors.len()
            );
        }

        // Validate that all files have consistent key structures
        let mut inconsistent_files = Vec::new();

        for namespace in &all_namespaces {
            let mut namespace_keys: Option<HashSet<String>> = None;

            for (language, _) in &language_dirs {
                if let Some(language_files) = files_by_language.get(language)
                    && let Some(file_keys) = language_files.get(namespace)
                {
                    if let Some(expected_keys) = &namespace_keys {
                        if file_keys != expected_keys {
                            inconsistent_files.push(format!("{}/{}.json", language, namespace));
                        }
                    } else {
                        namespace_keys = Some(file_keys.clone());
                    }
                }
            }
        }

        if !inconsistent_files.is_empty() {
            warn!("⚠️  Files with inconsistent key structures:");
            for file in &inconsistent_files {
                warn!("   - {}", file);
            }
            anyhow::bail!(
                "Key structure validation failed: {} inconsistent files",
                inconsistent_files.len()
            );
        }

        info!("✅ File structure validation passed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_locale_structure() -> Result<TempDir> {
        let temp_dir = TempDir::new()?;
        let locales_path = temp_dir.path();

        // Create language directories
        let en_dir = locales_path.join("en");
        let fr_dir = locales_path.join("fr");
        let es_dir = locales_path.join("es");

        fs::create_dir_all(&en_dir)?;
        fs::create_dir_all(&fr_dir)?;
        fs::create_dir_all(&es_dir)?;

        // Create common.json files
        let common_en = r#"{
            "greeting": "Hello",
            "farewell": "Goodbye",
            "auth": {
                "login": {
                    "title": "Login",
                    "email": "Email",
                    "password": "Password"
                },
                "register": {
                    "title": "Register",
                    "confirm": "Confirm Password"
                }
            },
            "messages": ["Welcome", "Thank you", "Error occurred"]
        }"#;

        let common_fr = r#"{
            "greeting": "Bonjour",
            "farewell": "Au revoir",
            "auth": {
                "login": {
                    "title": "Connexion",
                    "email": "Email",
                    "password": "Mot de passe"
                },
                "register": {
                    "title": "S'inscrire",
                    "confirm": "Confirmer le mot de passe"
                }
            },
            "messages": ["Bienvenue", "Merci", "Erreur survenue"]
        }"#;

        let common_es = r#"{
            "greeting": "Hola",
            "farewell": "Adiós",
            "auth": {
                "login": {
                    "title": "Iniciar sesión",
                    "email": "Email",
                    "password": "Contraseña"
                },
                "register": {
                    "title": "Registrarse",
                    "confirm": "Confirmar contraseña"
                }
            },
            "messages": ["Bienvenido", "Gracias", "Error ocurrido"]
        }"#;

        fs::write(en_dir.join("common.json"), common_en)?;
        fs::write(fr_dir.join("common.json"), common_fr)?;
        fs::write(es_dir.join("common.json"), common_es)?;

        // Create errors.json files
        let errors_en = r#"{
            "validation": {
                "required": "This field is required",
                "email": "Invalid email format"
            },
            "network": "Network error"
        }"#;

        let errors_fr = r#"{
            "validation": {
                "required": "Ce champ est requis",
                "email": "Format d'email invalide"
            },
            "network": "Erreur réseau"
        }"#;

        let errors_es = r#"{
            "validation": {
                "required": "Este campo es requerido",
                "email": "Formato de email inválido"
            },
            "network": "Error de red"
        }"#;

        fs::write(en_dir.join("errors.json"), errors_en)?;
        fs::write(fr_dir.join("errors.json"), errors_fr)?;
        fs::write(es_dir.join("errors.json"), errors_es)?;

        Ok(temp_dir)
    }

    #[test]
    fn test_extract_translation_keys_simple() {
        let parser = TranslationParser::new();
        let json_value: Value = serde_json::from_str(
            r#"{
            "greeting": "Hello",
            "farewell": "Goodbye"
        }"#,
        )
        .unwrap();

        let keys = parser.extract_translation_keys(&json_value, "");
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"greeting".to_string()));
        assert!(keys.contains(&"farewell".to_string()));
    }

    #[test]
    fn test_extract_translation_keys_nested() {
        let parser = TranslationParser::new();
        let json_value: Value = serde_json::from_str(
            r#"{
            "auth": {
                "login": {
                    "title": "Login",
                    "email": "Email"
                },
                "register": {
                    "title": "Register"
                }
            }
        }"#,
        )
        .unwrap();

        let keys = parser.extract_translation_keys(&json_value, "");
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&"auth.login.title".to_string()));
        assert!(keys.contains(&"auth.login.email".to_string()));
        assert!(keys.contains(&"auth.register.title".to_string()));
    }

    #[test]
    fn test_extract_translation_keys_array() {
        let parser = TranslationParser::new();
        let json_value: Value = serde_json::from_str(
            r#"{
            "messages": ["Welcome", "Thank you", "Error"],
            "complex": [
                {"nested": "value1"},
                {"nested": "value2"}
            ]
        }"#,
        )
        .unwrap();

        let keys = parser.extract_translation_keys(&json_value, "");
        assert!(keys.contains(&"messages".to_string()));
        assert!(keys.contains(&"complex[0].nested".to_string()));
        assert!(keys.contains(&"complex[1].nested".to_string()));
    }

    #[test]
    fn test_get_value_at_path() {
        let parser = TranslationParser::new();
        let json_value: Value = serde_json::from_str(
            r#"{
            "auth": {
                "login": {
                    "title": "Login"
                }
            },
            "messages": ["Welcome", "Thank you"]
        }"#,
        )
        .unwrap();

        assert_eq!(
            parser
                .get_value_at_path(&json_value, "auth.login.title")
                .unwrap()
                .as_str()
                .unwrap(),
            "Login"
        );
        assert_eq!(
            parser
                .get_value_at_path(&json_value, "messages")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert!(
            parser
                .get_value_at_path(&json_value, "nonexistent")
                .is_none()
        );
    }

    #[test]
    fn test_parse_translation_file() -> Result<()> {
        let temp_dir = create_test_locale_structure()?;
        let parser = TranslationParser::new();

        let common_en_path = temp_dir.path().join("en").join("common.json");
        let translation_file = parser.parse_translation_file(&common_en_path)?;

        assert_eq!(translation_file.namespace, "common");
        assert_eq!(translation_file.language, "en");
        assert!(translation_file.keys.len() > 0);

        // Check for some expected keys
        let key_paths: Vec<&String> = translation_file.keys.iter().map(|k| &k.key_path).collect();
        assert!(key_paths.contains(&&"greeting".to_string()));
        assert!(key_paths.contains(&&"auth.login.title".to_string()));
        assert!(key_paths.contains(&&"messages".to_string()));

        // Check that values are correctly extracted
        let greeting_key = translation_file
            .keys
            .iter()
            .find(|k| k.key_path == "greeting")
            .unwrap();
        assert_eq!(greeting_key.values.get("en").unwrap(), "Hello");

        Ok(())
    }

    #[test]
    fn test_scan_locales_directory() -> Result<()> {
        let temp_dir = create_test_locale_structure()?;
        let parser = TranslationParser::new();

        let translation_files = parser.scan_locales_directory(temp_dir.path())?;

        assert_eq!(translation_files.len(), 6); // 3 languages × 2 namespaces

        // Check that we have all expected combinations
        let combinations: Vec<(String, String)> = translation_files
            .iter()
            .map(|f| (f.language.clone(), f.namespace.clone()))
            .collect();

        assert!(combinations.contains(&("en".to_string(), "common".to_string())));
        assert!(combinations.contains(&("fr".to_string(), "common".to_string())));
        assert!(combinations.contains(&("es".to_string(), "common".to_string())));
        assert!(combinations.contains(&("en".to_string(), "errors".to_string())));
        assert!(combinations.contains(&("fr".to_string(), "errors".to_string())));
        assert!(combinations.contains(&("es".to_string(), "errors".to_string())));

        Ok(())
    }

    #[test]
    fn test_validate_file_structure_success() -> Result<()> {
        let temp_dir = create_test_locale_structure()?;
        let parser = TranslationParser::new();

        // Should pass validation
        let result = parser.validate_file_structure(temp_dir.path());
        assert!(result.is_ok());

        Ok(())
    }

    #[test]
    fn test_validate_file_structure_missing_file() -> Result<()> {
        let temp_dir = create_test_locale_structure()?;
        let parser = TranslationParser::new();

        // Remove one file to create inconsistency
        let missing_file = temp_dir.path().join("fr").join("errors.json");
        fs::remove_file(missing_file)?;

        // Should fail validation
        let result = parser.validate_file_structure(temp_dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing files"));

        Ok(())
    }

    #[test]
    fn test_validate_file_structure_inconsistent_keys() -> Result<()> {
        let temp_dir = create_test_locale_structure()?;
        let parser = TranslationParser::new();

        // Modify one file to have different keys
        let inconsistent_file = temp_dir.path().join("fr").join("common.json");
        let inconsistent_content = r#"{
            "greeting": "Bonjour",
            "different_key": "Different value"
        }"#;
        fs::write(inconsistent_file, inconsistent_content)?;

        // Should fail validation
        let result = parser.validate_file_structure(temp_dir.path());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("inconsistent files")
        );

        Ok(())
    }

    #[test]
    fn test_scan_nonexistent_directory() {
        let parser = TranslationParser::new();
        let result = parser.scan_locales_directory("/nonexistent/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_json() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let invalid_file = temp_dir.path().join("invalid.json");
        fs::write(&invalid_file, "{ invalid json }")?;

        let parser = TranslationParser::new();
        let result = parser.parse_translation_file(&invalid_file);
        assert!(result.is_err());

        Ok(())
    }
}
