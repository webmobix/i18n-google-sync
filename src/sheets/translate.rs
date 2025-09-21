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

use tracing::warn;

pub struct TranslateService;

impl TranslateService {
    pub fn new() -> Self {
        Self
    }

    /// Generates a GOOGLETRANSLATE formula.
    ///
    /// For cell references, use the cell_reference parameter instead of source_text.
    /// For direct text, use source_text.
    pub fn generate_translate_formula(
        &self,
        source_text: &str,
        source_lang: &str,
        target_lang: &str,
    ) -> String {
        // Escape quotes in source text
        let escaped_text = source_text.replace("\"", "\"\"");
        format!(
            "=GOOGLETRANSLATE(\"{}\", \"{}\", \"{}\")",
            escaped_text,
            self.map_language_code(source_lang),
            self.map_language_code(target_lang)
        )
    }

    /// Generates a GOOGLETRANSLATE formula that references another cell.
    pub fn generate_translate_formula_with_cell_ref(
        &self,
        cell_reference: &str,
        source_lang: &str,
        target_lang: &str,
    ) -> String {
        format!(
            "=GOOGLETRANSLATE({}, \"{}\", \"{}\")",
            cell_reference,
            self.map_language_code(source_lang),
            self.map_language_code(target_lang)
        )
    }

    pub fn extract_translated_value(&self, cell_content: &str) -> String {
        // TODO: Parse actual translated text from cells (not the formula)
        if cell_content.starts_with("=GOOGLETRANSLATE") {
            // This would be the actual translated result from Google Sheets
            cell_content.to_string()
        } else {
            cell_content.to_string()
        }
    }

    /// Maps i18n language codes to Google Translate language codes.
    ///
    /// This is needed because:
    /// 1. Some i18n codes use region variants (e.g., 'zh-CN', 'pt-BR') that need mapping
    /// 2. Google Translate may use different codes than standard i18n codes
    /// 3. Some i18n codes might not be supported by Google Translate
    pub fn map_language_code(&self, i18n_code: &str) -> String {
        match i18n_code {
            // Standard mappings
            "en" | "en-US" | "en-GB" => "en".to_string(),
            "fr" | "fr-FR" | "fr-CA" => "fr".to_string(),
            "de" | "de-DE" | "de-AT" => "de".to_string(),
            "es" | "es-ES" | "es-MX" => "es".to_string(),
            "it" | "it-IT" => "it".to_string(),
            "pt" | "pt-PT" => "pt".to_string(),
            "pt-BR" => "pt".to_string(), // Brazilian Portuguese maps to Portuguese
            "ru" | "ru-RU" => "ru".to_string(),
            "ja" | "ja-JP" => "ja".to_string(),
            "ko" | "ko-KR" => "ko".to_string(),

            // Chinese variants
            "zh" | "zh-CN" => "zh".to_string(), // Simplified Chinese
            "zh-TW" | "zh-HK" => "zh-TW".to_string(), // Traditional Chinese

            // Additional common languages
            "ar" | "ar-SA" => "ar".to_string(),
            "hi" | "hi-IN" => "hi".to_string(),
            "nl" | "nl-NL" => "nl".to_string(),
            "sv" | "sv-SE" => "sv".to_string(),
            "no" | "nb" | "nb-NO" => "no".to_string(),
            "da" | "da-DK" => "da".to_string(),
            "fi" | "fi-FI" => "fi".to_string(),
            "pl" | "pl-PL" => "pl".to_string(),
            "tr" | "tr-TR" => "tr".to_string(),
            "he" | "he-IL" => "he".to_string(),
            "th" | "th-TH" => "th".to_string(),
            "vi" | "vi-VN" => "vi".to_string(),

            // Fallback: use the original code but warn about potential issues
            _ => {
                if i18n_code.contains('-') {
                    // For unknown region variants, try using just the language part
                    let lang_part = i18n_code.split('-').next().unwrap_or(i18n_code);
                    warn!(
                        "⚠️  Unknown language code '{}', using '{}'",
                        i18n_code, lang_part
                    );
                    lang_part.to_string()
                } else {
                    warn!("⚠️  Unknown language code '{}', using as-is", i18n_code);
                    i18n_code.to_string()
                }
            }
        }
    }

    pub fn batch_apply_translations(
        &self,
        translations: &[(String, String, String)], // (key, source_lang, target_lang)
        source_text_map: &std::collections::HashMap<String, String>,
    ) -> Vec<(String, String)> {
        // TODO: Generate formulas for multiple keys
        let mut formulas = Vec::new();

        for (key, source_lang, target_lang) in translations {
            if let Some(source_text) = source_text_map.get(key) {
                let source_code = self.map_language_code(source_lang);
                let target_code = self.map_language_code(target_lang);
                let formula =
                    self.generate_translate_formula(source_text, &source_code, &target_code);
                formulas.push((key.clone(), formula));
            }
        }

        formulas
    }
}
