use std::collections::BTreeMap;

use aegis_native_engine::{ApprovedTarget, MAX_URL_BYTES};
use scraper::{ElementRef, Html, Selector};

use crate::{canonicalize_url, CanonicalUrl, CanonicalizationOutcome, DiscoveryError};

const HARD_MAX_JAVASCRIPT_BYTES: usize = 1024 * 1024;
const HARD_MAX_HTML_BYTES: usize = 2 * 1024 * 1024;
const HARD_MAX_LITERALS: usize = 5_000;
const HARD_MAX_CANDIDATES: usize = 300;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CandidateConfidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum JavaScriptCandidateSource {
    StaticString,
    AssetString,
    RouteDeclaration,
    RequestCall,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JavaScriptCandidate {
    pub url: CanonicalUrl,
    pub confidence: CandidateConfidence,
    pub source: JavaScriptCandidateSource,
    pub route_template: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JavaScriptExtractionLimits {
    pub max_source_bytes: usize,
    pub max_literals: usize,
    pub max_candidates: usize,
}

impl Default for JavaScriptExtractionLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: HARD_MAX_JAVASCRIPT_BYTES,
            max_literals: HARD_MAX_LITERALS,
            max_candidates: HARD_MAX_CANDIDATES,
        }
    }
}

impl JavaScriptExtractionLimits {
    fn validate(&self) -> Result<(), DiscoveryError> {
        if self.max_source_bytes == 0
            || self.max_source_bytes > HARD_MAX_JAVASCRIPT_BYTES
            || self.max_literals == 0
            || self.max_literals > HARD_MAX_LITERALS
            || self.max_candidates == 0
            || self.max_candidates > HARD_MAX_CANDIDATES
        {
            return Err(DiscoveryError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JavaScriptExtractionResult {
    pub candidates: Vec<JavaScriptCandidate>,
    pub inspected_literals: usize,
    pub ignored_literals: usize,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StaticAssetKind {
    Script,
    Stylesheet,
    Image,
    Frame,
    Media,
    Manifest,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticAsset {
    pub url: CanonicalUrl,
    pub kind: StaticAssetKind,
    pub confidence: CandidateConfidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssetExtractionLimits {
    pub max_html_bytes: usize,
    pub max_candidates: usize,
}

impl Default for AssetExtractionLimits {
    fn default() -> Self {
        Self {
            max_html_bytes: HARD_MAX_HTML_BYTES,
            max_candidates: HARD_MAX_CANDIDATES,
        }
    }
}

impl AssetExtractionLimits {
    fn validate(&self) -> Result<(), DiscoveryError> {
        if self.max_html_bytes == 0
            || self.max_html_bytes > HARD_MAX_HTML_BYTES
            || self.max_candidates == 0
            || self.max_candidates > HARD_MAX_CANDIDATES
        {
            return Err(DiscoveryError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticAssetResult {
    pub assets: Vec<StaticAsset>,
    pub inspected_candidates: usize,
    pub ignored_candidates: usize,
    pub truncated: bool,
}

/// Extracts static URL literals without executing JavaScript or evaluating expressions.
pub fn extract_javascript_endpoints(
    target: &ApprovedTarget,
    script_url: &str,
    source: &str,
    limits: JavaScriptExtractionLimits,
) -> Result<JavaScriptExtractionResult, DiscoveryError> {
    limits.validate()?;
    target
        .validate()
        .map_err(|_| DiscoveryError::InvalidTarget)?;
    if !target.contains_url(script_url) {
        return Err(DiscoveryError::DocumentOutOfScope);
    }
    if source.len() > limits.max_source_bytes {
        return Err(DiscoveryError::DocumentTooLarge);
    }

    let (literals, literal_limit_reached) = scan_literals(source, limits.max_literals);
    let mut candidates = BTreeMap::<String, JavaScriptCandidate>::new();
    let mut ignored_literals = 0usize;
    let mut truncated = literal_limit_reached;
    for literal in &literals {
        if candidates.len() >= limits.max_candidates {
            truncated = true;
            break;
        }
        if literal.dynamic_template || !looks_like_url_candidate(&literal.value) {
            ignored_literals += 1;
            continue;
        }
        let context_start = literal.start.saturating_sub(128);
        let context = String::from_utf8_lossy(&source.as_bytes()[context_start..literal.start]);
        let (confidence, candidate_source, route_template) =
            classify_javascript_candidate(&context, &literal.value);
        let CanonicalizationOutcome::Accepted(url) =
            canonicalize_url(target, script_url, &literal.value)?
        else {
            ignored_literals += 1;
            continue;
        };
        let key = url.dedup_key().to_string();
        let candidate = JavaScriptCandidate {
            url,
            confidence,
            source: candidate_source,
            route_template,
        };
        match candidates.get_mut(&key) {
            Some(existing) if candidate.confidence > existing.confidence => {
                *existing = candidate;
            }
            Some(existing) if candidate.confidence == existing.confidence => {
                existing.route_template &= candidate.route_template;
                existing.source = existing.source.max(candidate.source);
            }
            Some(_) => {}
            None => {
                candidates.insert(key, candidate);
            }
        }
    }

    Ok(JavaScriptExtractionResult {
        candidates: candidates.into_values().collect(),
        inspected_literals: literals.len(),
        ignored_literals,
        truncated,
    })
}

/// Extracts fetchable static asset URLs from HTML attributes.
pub fn extract_static_assets(
    target: &ApprovedTarget,
    document_url: &str,
    html: &str,
    limits: AssetExtractionLimits,
) -> Result<StaticAssetResult, DiscoveryError> {
    limits.validate()?;
    target
        .validate()
        .map_err(|_| DiscoveryError::InvalidTarget)?;
    if !target.contains_url(document_url) {
        return Err(DiscoveryError::DocumentOutOfScope);
    }
    if html.len() > limits.max_html_bytes {
        return Err(DiscoveryError::DocumentTooLarge);
    }
    let document = Html::parse_document(html);
    let selector = Selector::parse(
        "script[src], link[href], img[src], iframe[src], source[src], video[src], audio[src], object[data], embed[src]",
    )
    .map_err(|_| DiscoveryError::ParserSetupFailed)?;
    let base_selector =
        Selector::parse("base[href]").map_err(|_| DiscoveryError::ParserSetupFailed)?;
    let resolution_base = document
        .select(&base_selector)
        .next()
        .and_then(|base| base.value().attr("href"))
        .and_then(
            |candidate| match canonicalize_url(target, document_url, candidate) {
                Ok(CanonicalizationOutcome::Accepted(url)) => Some(url.into_string()),
                _ => None,
            },
        )
        .unwrap_or_else(|| document_url.to_string());
    let mut assets = BTreeMap::<String, StaticAsset>::new();
    let mut inspected_candidates = 0usize;
    let mut ignored_candidates = 0usize;
    let mut truncated = false;

    for element in document.select(&selector) {
        if inspected_candidates >= limits.max_candidates {
            truncated = true;
            break;
        }
        inspected_candidates += 1;
        let raw = if element.value().name() == "object" {
            element.value().attr("data")
        } else {
            element
                .value()
                .attr("src")
                .or_else(|| element.value().attr("href"))
        };
        let Some(raw) = raw else {
            ignored_candidates += 1;
            continue;
        };
        let CanonicalizationOutcome::Accepted(url) =
            canonicalize_url(target, &resolution_base, raw)?
        else {
            ignored_candidates += 1;
            continue;
        };
        let (kind, confidence) = classify_asset(element);
        let key = url.dedup_key().to_string();
        let candidate = StaticAsset {
            url,
            kind,
            confidence,
        };
        match assets.get_mut(&key) {
            Some(existing) if candidate.confidence > existing.confidence => *existing = candidate,
            Some(_) => {}
            None => {
                assets.insert(key, candidate);
            }
        }
    }

    Ok(StaticAssetResult {
        assets: assets.into_values().collect(),
        inspected_candidates,
        ignored_candidates,
        truncated,
    })
}

struct Literal {
    value: String,
    start: usize,
    dynamic_template: bool,
}

fn scan_literals(source: &str, limit: usize) -> (Vec<Literal>, bool) {
    let bytes = source.as_bytes();
    let mut literals = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if literals.len() >= limit {
            return (literals, true);
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            index += 2;
            while index < bytes.len() && !matches!(bytes[index], b'\r' | b'\n') {
                index += 1;
            }
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
            continue;
        }
        if matches!(bytes[index], b'\'' | b'"' | b'`') {
            let start = index;
            let (literal, next) = parse_literal(bytes, index);
            index = next.max(index + 1);
            if let Some((value, dynamic_template)) = literal {
                literals.push(Literal {
                    value,
                    start,
                    dynamic_template,
                });
            }
            continue;
        }
        index += 1;
    }
    (literals, false)
}

fn parse_literal(bytes: &[u8], start: usize) -> (Option<(String, bool)>, usize) {
    let quote = bytes[start];
    let mut output = Vec::new();
    let mut index = start + 1;
    let mut dynamic_template = false;
    while index < bytes.len() {
        let current = bytes[index];
        if current == quote {
            return (
                String::from_utf8(output)
                    .ok()
                    .filter(|value| value.len() <= MAX_URL_BYTES)
                    .map(|value| (value, dynamic_template)),
                index + 1,
            );
        }
        if quote == b'`' && current == b'$' && bytes.get(index + 1) == Some(&b'{') {
            dynamic_template = true;
        }
        if current == b'\\' {
            let Some(escaped) = bytes.get(index + 1).copied() else {
                return (None, bytes.len());
            };
            match escaped {
                b'x' => {
                    let Some(value) = decode_hex(bytes.get(index + 2..index + 4)) else {
                        return (None, index + 2);
                    };
                    output.push(value as u8);
                    index += 4;
                    continue;
                }
                b'u' => {
                    let Some(value) = decode_hex(bytes.get(index + 2..index + 6)) else {
                        return (None, index + 2);
                    };
                    let Some(character) = char::from_u32(value) else {
                        return (None, index + 6);
                    };
                    let mut encoded = [0u8; 4];
                    output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                    index += 6;
                    continue;
                }
                b'n' => output.push(b'\n'),
                b'r' => output.push(b'\r'),
                b't' => output.push(b'\t'),
                b'b' => output.push(8),
                b'f' => output.push(12),
                b'v' => output.push(11),
                b'\r' | b'\n' => {}
                value => output.push(value),
            }
            index += 2;
            continue;
        }
        if quote != b'`' && matches!(current, b'\r' | b'\n') {
            return (None, index + 1);
        }
        output.push(current);
        if output.len() > MAX_URL_BYTES {
            return (None, index + 1);
        }
        index += 1;
    }
    (None, bytes.len())
}

fn decode_hex(slice: Option<&[u8]>) -> Option<u32> {
    let slice = slice?;
    if slice.is_empty() {
        return None;
    }
    slice.iter().try_fold(0u32, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'f' => u32::from(byte - b'a' + 10),
            b'A'..=b'F' => u32::from(byte - b'A' + 10),
            _ => return None,
        };
        Some(value * 16 + digit)
    })
}

fn looks_like_url_candidate(value: &str) -> bool {
    if value.is_empty() || value.contains(['\r', '\n', '\0']) {
        return false;
    }
    value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with("http://")
        || value.starts_with("https://")
}

fn classify_javascript_candidate(
    context: &str,
    value: &str,
) -> (CandidateConfidence, JavaScriptCandidateSource, bool) {
    let compact = context
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if compact.ends_with("fetch(")
        || compact.ends_with("request(")
        || compact.ends_with("axios.get(")
        || compact.ends_with("axios.post(")
        || compact.ends_with("axios.put(")
        || compact.ends_with("axios.delete(")
    {
        return (
            CandidateConfidence::High,
            JavaScriptCandidateSource::RequestCall,
            contains_route_placeholder(value),
        );
    }
    if compact.ends_with("path:")
        || compact.ends_with("route:")
        || compact.ends_with("url:")
        || compact.ends_with("route(")
    {
        return (
            CandidateConfidence::Medium,
            JavaScriptCandidateSource::RouteDeclaration,
            contains_route_placeholder(value),
        );
    }
    if is_static_asset_path(value) {
        return (
            CandidateConfidence::Low,
            JavaScriptCandidateSource::AssetString,
            false,
        );
    }
    let confidence =
        if value.contains("/api/") || value.ends_with("/graphql") || value.ends_with(".json") {
            CandidateConfidence::Medium
        } else {
            CandidateConfidence::Low
        };
    (
        confidence,
        JavaScriptCandidateSource::StaticString,
        contains_route_placeholder(value),
    )
}

fn contains_route_placeholder(value: &str) -> bool {
    value.split('/').any(|segment| {
        segment.starts_with(':') || (segment.starts_with('{') && segment.ends_with('}'))
    })
}

fn is_static_asset_path(value: &str) -> bool {
    let path = value
        .split(['?', '#'])
        .next()
        .unwrap_or(value)
        .to_ascii_lowercase();
    [
        ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".woff", ".woff2",
        ".ttf", ".ico", ".map",
    ]
    .iter()
    .any(|extension| path.ends_with(extension))
}

fn classify_asset(element: ElementRef<'_>) -> (StaticAssetKind, CandidateConfidence) {
    match element.value().name() {
        "script" => (StaticAssetKind::Script, CandidateConfidence::High),
        "img" => (StaticAssetKind::Image, CandidateConfidence::Medium),
        "iframe" => (StaticAssetKind::Frame, CandidateConfidence::High),
        "source" | "video" | "audio" => (StaticAssetKind::Media, CandidateConfidence::Medium),
        "link" => {
            let rel = element
                .value()
                .attr("rel")
                .unwrap_or("")
                .to_ascii_lowercase();
            if rel
                .split_ascii_whitespace()
                .any(|value| value == "stylesheet")
            {
                (StaticAssetKind::Stylesheet, CandidateConfidence::High)
            } else if rel
                .split_ascii_whitespace()
                .any(|value| value == "manifest")
            {
                (StaticAssetKind::Manifest, CandidateConfidence::Medium)
            } else {
                (StaticAssetKind::Other, CandidateConfidence::Low)
            }
        }
        _ => (StaticAssetKind::Other, CandidateConfidence::Low),
    }
}

#[cfg(test)]
mod tests {
    use aegis_native_engine::ApprovedTarget;

    use super::{
        extract_javascript_endpoints, extract_static_assets, AssetExtractionLimits,
        CandidateConfidence, JavaScriptCandidateSource, JavaScriptExtractionLimits,
        StaticAssetKind,
    };

    fn target() -> ApprovedTarget {
        ApprovedTarget::new("target-1", "https://example.com", "/app").unwrap()
    }

    #[test]
    fn extracts_static_javascript_candidates_without_execution() {
        let source = r#"
            // fetch('/app/comment-only')
            fetch('/app/api/users?token=plain');
            axios.get("/app/api/users?token=plain");
            const route = { path: '/app/users/:id' };
            const asset = '\u002fapp/assets/main.js';
            const dynamic = `/app/users/${userId}`;
            const external = 'https://evil.example/api';
        "#;
        let result = extract_javascript_endpoints(
            &target(),
            "https://example.com/app/assets/bundle.js",
            source,
            JavaScriptExtractionLimits::default(),
        )
        .unwrap();

        assert_eq!(result.candidates.len(), 3);
        let api = result
            .candidates
            .iter()
            .find(|candidate| candidate.url.as_str().contains("/api/users"))
            .unwrap();
        assert_eq!(api.confidence, CandidateConfidence::High);
        assert_eq!(api.source, JavaScriptCandidateSource::RequestCall);
        assert!(!api.url.as_str().contains("plain"));
        let route = result
            .candidates
            .iter()
            .find(|candidate| candidate.url.as_str().contains(":id"))
            .unwrap();
        assert!(route.route_template);
        assert_eq!(route.confidence, CandidateConfidence::Medium);
        let asset = result
            .candidates
            .iter()
            .find(|candidate| candidate.url.as_str().ends_with("main.js"))
            .unwrap();
        assert_eq!(asset.confidence, CandidateConfidence::Low);
        assert!(!result
            .candidates
            .iter()
            .any(|candidate| candidate.url.as_str().contains("comment-only")));
        assert!(!result
            .candidates
            .iter()
            .any(|candidate| candidate.url.as_str().contains("userId")));
    }

    #[test]
    fn extracts_only_in_scope_static_assets_and_redacts_query_secret() {
        let html = r#"
            <base href="/app/assets/">
            <script src="main.js?api_key=plain"></script>
            <link rel="stylesheet" href="theme.css">
            <img src="/app/image.png">
            <iframe src="https://evil.example/frame"></iframe>
            <img src="data:image/png;base64,AAAA">
        "#;
        let result = extract_static_assets(
            &target(),
            "https://example.com/app/index",
            html,
            AssetExtractionLimits::default(),
        )
        .unwrap();
        assert_eq!(result.assets.len(), 3);
        assert_eq!(result.ignored_candidates, 2);
        let script = result
            .assets
            .iter()
            .find(|asset| asset.kind == StaticAssetKind::Script)
            .unwrap();
        assert_eq!(script.confidence, CandidateConfidence::High);
        assert!(!script.url.as_str().contains("plain"));
        assert!(script.url.as_str().contains("%5BREDACTED%5D"));
    }

    #[test]
    fn candidate_limits_report_truncation() {
        let limits = JavaScriptExtractionLimits {
            max_candidates: 1,
            ..JavaScriptExtractionLimits::default()
        };
        let result = extract_javascript_endpoints(
            &target(),
            "https://example.com/app/main.js",
            "fetch('/app/one'); fetch('/app/two');",
            limits,
        )
        .unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert!(result.truncated);
    }
}
