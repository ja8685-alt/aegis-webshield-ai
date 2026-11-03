use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;
use url::Url;

const MAX_URL_SEEDS: usize = 5000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlSeed {
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlSeedImportResult {
    pub seed_count: usize,
    pub skipped_count: usize,
    pub seeds: Vec<UrlSeed>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UrlSeedImportError {
    #[error("URL seed document is empty")]
    EmptyDocument,
    #[error("URL seed at line {line} is invalid")]
    InvalidUrl { line: usize },
    #[error("URL seed at line {line} must use http or https")]
    UnsupportedScheme { line: usize },
    #[error("URL seed document has too many URLs")]
    TooManyUrls,
}

pub fn import_url_seed_document(document: &str) -> Result<UrlSeedImportResult, UrlSeedImportError> {
    if document.trim_matches('\u{feff}').trim().is_empty() {
        return Err(UrlSeedImportError::EmptyDocument);
    }

    let mut seen = HashSet::new();
    let mut seeds = Vec::new();
    let mut skipped_count = 0;

    for (index, line) in document.trim_start_matches('\u{feff}').lines().enumerate() {
        let line_number = index + 1;
        let Some(candidate) = seed_candidate(line) else {
            skipped_count += 1;
            continue;
        };
        let normalized = normalize_url_seed(candidate, line_number)?;
        if seen.insert(normalized.clone()) {
            if seeds.len() >= MAX_URL_SEEDS {
                return Err(UrlSeedImportError::TooManyUrls);
            }
            seeds.push(UrlSeed { url: normalized });
        } else {
            skipped_count += 1;
        }
    }

    if seeds.is_empty() {
        return Err(UrlSeedImportError::EmptyDocument);
    }

    Ok(UrlSeedImportResult {
        seed_count: seeds.len(),
        skipped_count,
        seeds,
    })
}

fn seed_candidate(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
        return None;
    }
    Some(trimmed)
}

fn normalize_url_seed(candidate: &str, line: usize) -> Result<String, UrlSeedImportError> {
    let url = Url::parse(candidate).map_err(|_| UrlSeedImportError::InvalidUrl { line })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(UrlSeedImportError::UnsupportedScheme { line });
    }

    let mut normalized = url;
    normalized.set_fragment(None);
    Ok(normalized.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_http_and_https_url_seeds() {
        let document = "\u{feff}# approved targets\nhttps://example.com/app#section\n\nhttp://example.com/api\n";

        let result = import_url_seed_document(document).expect("url seeds");

        assert_eq!(result.seed_count, 2);
        assert_eq!(result.skipped_count, 2);
        assert_eq!(result.seeds[0].url, "https://example.com/app");
        assert_eq!(result.seeds[1].url, "http://example.com/api");
    }

    #[test]
    fn deduplicates_normalized_urls() {
        let document = "https://example.com/app\nhttps://example.com/app#debug\n";

        let result = import_url_seed_document(document).expect("url seeds");

        assert_eq!(result.seed_count, 1);
        assert_eq!(result.skipped_count, 1);
        assert_eq!(result.seeds[0].url, "https://example.com/app");
    }

    #[test]
    fn rejects_empty_document() {
        let result = import_url_seed_document("# only comments\n\n");

        assert_eq!(result, Err(UrlSeedImportError::EmptyDocument));
    }

    #[test]
    fn rejects_invalid_url_with_line_number() {
        let result = import_url_seed_document("https://example.com\nnot a url\n");

        assert_eq!(result, Err(UrlSeedImportError::InvalidUrl { line: 2 }));
    }

    #[test]
    fn rejects_non_http_urls_with_line_number() {
        let result = import_url_seed_document("file:///etc/passwd\n");

        assert_eq!(
            result,
            Err(UrlSeedImportError::UnsupportedScheme { line: 1 })
        );
    }
}
