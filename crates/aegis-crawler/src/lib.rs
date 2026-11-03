use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use thiserror::Error;
use url::Url;

const DEFAULT_MAX_PAGES: usize = 25;
const DEFAULT_MAX_CANDIDATES: usize = 250;
const DEFAULT_MAX_DEPTH: usize = 2;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_USER_AGENT: &str = "Aegis WebShield AI crawler";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlCandidate {
    pub method: String,
    pub url: String,
    pub source: CrawlCandidateSource,
    #[serde(default)]
    pub parameters: Vec<CrawlParameter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlParameter {
    pub name: String,
    pub location: CrawlParameterLocation,
    pub required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrawlParameterLocation {
    Query,
    Body,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrawlCandidateSource {
    AnchorHref,
    FormAction,
    ScriptSrc,
    LinkHref,
    BrowserRoute,
    BrowserRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserCrawlObservation {
    #[serde(default)]
    pub routes: Vec<String>,
    #[serde(default)]
    pub requests: Vec<BrowserNetworkRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserNetworkRequest {
    pub method: String,
    pub url: String,
    pub resource_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlerOptions {
    pub max_pages: usize,
    pub max_candidates: usize,
    pub max_depth: usize,
    pub max_response_bytes: usize,
    pub user_agent: String,
}

impl Default for CrawlerOptions {
    fn default() -> Self {
        Self {
            max_pages: DEFAULT_MAX_PAGES,
            max_candidates: DEFAULT_MAX_CANDIDATES,
            max_depth: DEFAULT_MAX_DEPTH,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            user_agent: DEFAULT_USER_AGENT.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlerFetchRequest {
    pub url: String,
    pub method: String,
    pub user_agent: String,
    pub max_response_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlerFetchResponse {
    pub final_url: String,
    pub status_code: u16,
    pub content_type: Option<String>,
    pub body: String,
}

pub trait CrawlerFetchClient {
    fn fetch(&self, request: &CrawlerFetchRequest) -> Result<CrawlerFetchResponse, CrawlerError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlPage {
    pub url: String,
    pub depth: usize,
    pub status_code: u16,
    pub candidate_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlResult {
    pub pages: Vec<CrawlPage>,
    pub candidates: Vec<CrawlCandidate>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CrawlerError {
    #[error("base URL is invalid")]
    InvalidBaseUrl,
    #[error("base URL must use http or https")]
    UnsupportedBaseUrl,
    #[error("fetched URL is invalid")]
    InvalidFetchedUrl,
    #[error("crawler fetch failed: {0}")]
    FetchFailed(String),
}

pub fn extract_html_candidates(
    base_url: &str,
    html: &str,
) -> Result<Vec<CrawlCandidate>, CrawlerError> {
    let base = parse_base_url(base_url)?;
    let document = Html::parse_document(html);
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();

    collect_url_attribute(
        &base,
        &document,
        "a[href]",
        "href",
        "GET",
        CrawlCandidateSource::AnchorHref,
        &mut seen,
        &mut candidates,
    );
    collect_url_attribute(
        &base,
        &document,
        "script[src]",
        "src",
        "GET",
        CrawlCandidateSource::ScriptSrc,
        &mut seen,
        &mut candidates,
    );
    collect_url_attribute(
        &base,
        &document,
        "link[href]",
        "href",
        "GET",
        CrawlCandidateSource::LinkHref,
        &mut seen,
        &mut candidates,
    );
    collect_forms(&base, &document, &mut seen, &mut candidates);

    candidates.sort_by(|left, right| {
        left.url
            .cmp(&right.url)
            .then_with(|| left.method.cmp(&right.method))
            .then_with(|| source_rank(left.source).cmp(&source_rank(right.source)))
    });
    Ok(candidates)
}

pub fn crawl_approved_html_surface(
    seed_url: &str,
    options: CrawlerOptions,
    client: &impl CrawlerFetchClient,
) -> Result<CrawlResult, CrawlerError> {
    let seed = parse_base_url(seed_url)?;
    let options = normalized_options(options);
    let mut queue = VecDeque::from([(seed.to_string(), 0usize)]);
    let mut visited_pages = HashSet::new();
    let mut seen_candidates = HashSet::new();
    let mut pages = Vec::new();
    let mut candidates = Vec::new();

    while let Some((url, depth)) = queue.pop_front() {
        if pages.len() >= options.max_pages || !visited_pages.insert(url.clone()) {
            continue;
        }

        let request = CrawlerFetchRequest {
            url: url.clone(),
            method: "GET".to_string(),
            user_agent: options.user_agent.clone(),
            max_response_bytes: options.max_response_bytes,
        };
        let response = client.fetch(&request)?;
        let final_url =
            parse_base_url(&response.final_url).map_err(|_| CrawlerError::InvalidFetchedUrl)?;
        if !same_origin(&seed, &final_url) {
            pages.push(CrawlPage {
                url: final_url.to_string(),
                depth,
                status_code: response.status_code,
                candidate_count: 0,
            });
            continue;
        }

        if !is_success_html_response(response.status_code, response.content_type.as_deref()) {
            pages.push(CrawlPage {
                url: final_url.to_string(),
                depth,
                status_code: response.status_code,
                candidate_count: 0,
            });
            continue;
        }

        let page_candidates = extract_html_candidates(final_url.as_str(), &response.body)?;
        let candidate_count = page_candidates.len();
        for candidate in page_candidates {
            if candidates.len() >= options.max_candidates {
                break;
            }

            let key = format!(
                "{}|{}|{}",
                candidate.method,
                candidate.url,
                parameter_signature(&candidate.parameters)
            );
            let should_enqueue = candidate.method == "GET"
                && depth < options.max_depth
                && candidate_url_same_origin(&seed, &candidate.url)
                && !visited_pages.contains(&candidate.url);

            if seen_candidates.insert(key) {
                if should_enqueue {
                    queue.push_back((candidate.url.clone(), depth + 1));
                }
                candidates.push(candidate);
            }
        }
        pages.push(CrawlPage {
            url: final_url.to_string(),
            depth,
            status_code: response.status_code,
            candidate_count,
        });
    }

    candidates.sort_by(|left, right| {
        left.url
            .cmp(&right.url)
            .then_with(|| left.method.cmp(&right.method))
            .then_with(|| source_rank(left.source).cmp(&source_rank(right.source)))
    });
    Ok(CrawlResult { pages, candidates })
}

pub fn extract_browser_observation_candidates(
    base_url: &str,
    observation: &BrowserCrawlObservation,
) -> Result<Vec<CrawlCandidate>, CrawlerError> {
    let base = parse_base_url(base_url)?;
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();

    for route in &observation.routes {
        push_browser_candidate(
            &base,
            route,
            "GET",
            CrawlCandidateSource::BrowserRoute,
            &mut seen,
            &mut candidates,
        );
    }

    for request in &observation.requests {
        if !is_browser_request_candidate(request) {
            continue;
        }
        let method = normalize_browser_method(&request.method);
        push_browser_candidate(
            &base,
            &request.url,
            &method,
            CrawlCandidateSource::BrowserRequest,
            &mut seen,
            &mut candidates,
        );
    }

    candidates.sort_by(|left, right| {
        left.url
            .cmp(&right.url)
            .then_with(|| left.method.cmp(&right.method))
            .then_with(|| source_rank(left.source).cmp(&source_rank(right.source)))
    });
    Ok(candidates)
}

fn parse_base_url(base_url: &str) -> Result<Url, CrawlerError> {
    let base = Url::parse(base_url.trim()).map_err(|_| CrawlerError::InvalidBaseUrl)?;
    if !matches!(base.scheme(), "http" | "https") {
        return Err(CrawlerError::UnsupportedBaseUrl);
    }
    Ok(base)
}

fn collect_url_attribute(
    base: &Url,
    document: &Html,
    selector: &str,
    attribute: &str,
    method: &str,
    source: CrawlCandidateSource,
    seen: &mut HashSet<String>,
    candidates: &mut Vec<CrawlCandidate>,
) {
    let selector = Selector::parse(selector).expect("static selector");
    for element in document.select(&selector) {
        let Some(value) = element.value().attr(attribute) else {
            continue;
        };
        push_candidate(base, value, method, source, Vec::new(), seen, candidates);
    }
}

fn collect_forms(
    base: &Url,
    document: &Html,
    seen: &mut HashSet<String>,
    candidates: &mut Vec<CrawlCandidate>,
) {
    let selector = Selector::parse("form").expect("static selector");
    for element in document.select(&selector) {
        let action = element.value().attr("action").unwrap_or(base.path());
        let method = element
            .value()
            .attr("method")
            .unwrap_or("GET")
            .trim()
            .to_ascii_uppercase();
        let method = match method.as_str() {
            "POST" => "POST",
            _ => "GET",
        };
        let parameters = collect_form_parameters(&element, method);
        push_candidate(
            base,
            action,
            method,
            CrawlCandidateSource::FormAction,
            parameters,
            seen,
            candidates,
        );
    }
}

fn push_candidate(
    base: &Url,
    value: &str,
    method: &str,
    source: CrawlCandidateSource,
    parameters: Vec<CrawlParameter>,
    seen: &mut HashSet<String>,
    candidates: &mut Vec<CrawlCandidate>,
) {
    let Some(url) = normalize_candidate_url(base, value) else {
        return;
    };
    let key = format!("{}|{}|{}", method, url, parameter_signature(&parameters));
    if seen.insert(key) {
        candidates.push(CrawlCandidate {
            method: method.to_string(),
            url,
            source,
            parameters,
        });
    }
}

fn push_browser_candidate(
    base: &Url,
    value: &str,
    method: &str,
    source: CrawlCandidateSource,
    seen: &mut HashSet<String>,
    candidates: &mut Vec<CrawlCandidate>,
) {
    let Some((url, parameters)) = normalize_browser_candidate_url(base, value) else {
        return;
    };
    let key = format!("{}|{}|{}", method, url, parameter_signature(&parameters));
    if seen.insert(key) {
        candidates.push(CrawlCandidate {
            method: method.to_string(),
            url,
            source,
            parameters,
        });
    }
}

fn collect_form_parameters(form: &scraper::ElementRef<'_>, method: &str) -> Vec<CrawlParameter> {
    let selector = Selector::parse("input[name], textarea[name], select[name], button[name]")
        .expect("static selector");
    let location = if method == "POST" {
        CrawlParameterLocation::Body
    } else {
        CrawlParameterLocation::Query
    };
    let mut seen = HashSet::new();
    let mut parameters = Vec::new();

    for element in form.select(&selector) {
        let Some(name) = element.value().attr("name").map(str::trim) else {
            continue;
        };
        if name.is_empty() || !seen.insert(name.to_string()) {
            continue;
        }
        parameters.push(CrawlParameter {
            name: name.to_string(),
            location,
            required: element.value().attr("required").is_some(),
        });
    }

    parameters.sort_by(|left, right| left.name.cmp(&right.name));
    parameters
}

fn parameter_signature(parameters: &[CrawlParameter]) -> String {
    parameters
        .iter()
        .map(|parameter| {
            format!(
                "{:?}:{}:{}",
                parameter.location, parameter.name, parameter.required
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn normalize_candidate_url(base: &Url, value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.starts_with('#')
        || value.starts_with("mailto:")
        || value.starts_with("tel:")
        || value.to_ascii_lowercase().starts_with("javascript:")
    {
        return None;
    }

    let mut url = base.join(value).ok()?;
    if !matches!(url.scheme(), "http" | "https") || !same_origin(base, &url) {
        return None;
    }
    url.set_fragment(None);
    Some(url.to_string())
}

fn normalize_browser_candidate_url(
    base: &Url,
    value: &str,
) -> Option<(String, Vec<CrawlParameter>)> {
    let value = value.trim();
    if value.is_empty()
        || value.starts_with('#')
        || value.starts_with("mailto:")
        || value.starts_with("tel:")
        || value.to_ascii_lowercase().starts_with("javascript:")
    {
        return None;
    }

    let mut url = base.join(value).ok()?;
    if !matches!(url.scheme(), "http" | "https") || !same_origin(base, &url) {
        return None;
    }

    let mut seen = HashSet::new();
    let mut parameters = url
        .query_pairs()
        .filter_map(|(name, _value)| {
            let name = name.trim();
            if name.is_empty() || !seen.insert(name.to_string()) {
                return None;
            }
            Some(CrawlParameter {
                name: name.to_string(),
                location: CrawlParameterLocation::Query,
                required: false,
            })
        })
        .collect::<Vec<_>>();
    parameters.sort_by(|left, right| left.name.cmp(&right.name));
    url.set_query(None);
    url.set_fragment(None);
    Some((url.to_string(), parameters))
}

fn is_browser_request_candidate(request: &BrowserNetworkRequest) -> bool {
    let method = normalize_browser_method(&request.method);
    if !matches!(method.as_str(), "GET" | "HEAD" | "POST") {
        return false;
    }
    request
        .resource_type
        .as_deref()
        .map(|resource_type| {
            matches!(
                resource_type.trim().to_ascii_lowercase().as_str(),
                "document" | "fetch" | "xhr"
            )
        })
        .unwrap_or(true)
}

fn normalize_browser_method(method: &str) -> String {
    match method.trim().to_ascii_uppercase().as_str() {
        "HEAD" => "HEAD".to_string(),
        "POST" => "POST".to_string(),
        _ => "GET".to_string(),
    }
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn candidate_url_same_origin(seed: &Url, candidate_url: &str) -> bool {
    Url::parse(candidate_url)
        .map(|candidate| same_origin(seed, &candidate))
        .unwrap_or(false)
}

fn is_success_html_response(status_code: u16, content_type: Option<&str>) -> bool {
    (200..300).contains(&status_code)
        && content_type
            .map(|value| value.to_ascii_lowercase().contains("text/html"))
            .unwrap_or(true)
}

fn normalized_options(options: CrawlerOptions) -> CrawlerOptions {
    CrawlerOptions {
        max_pages: options.max_pages.max(1),
        max_candidates: options.max_candidates.max(1),
        max_depth: options.max_depth,
        max_response_bytes: options.max_response_bytes.max(1024),
        user_agent: if options.user_agent.trim().is_empty() {
            DEFAULT_USER_AGENT.to_string()
        } else {
            options.user_agent
        },
    }
}

fn source_rank(source: CrawlCandidateSource) -> u8 {
    match source {
        CrawlCandidateSource::AnchorHref => 1,
        CrawlCandidateSource::FormAction => 2,
        CrawlCandidateSource::ScriptSrc => 3,
        CrawlCandidateSource::LinkHref => 4,
        CrawlCandidateSource::BrowserRoute => 5,
        CrawlCandidateSource::BrowserRequest => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct StaticFetchClient {
        pages: HashMap<String, CrawlerFetchResponse>,
    }

    impl CrawlerFetchClient for StaticFetchClient {
        fn fetch(
            &self,
            request: &CrawlerFetchRequest,
        ) -> Result<CrawlerFetchResponse, CrawlerError> {
            self.pages
                .get(&request.url)
                .cloned()
                .ok_or_else(|| CrawlerError::FetchFailed(format!("missing {}", request.url)))
        }
    }

    #[test]
    fn extracts_same_origin_html_candidates() {
        let html = r##"
            <a href="/dashboard#top">Dashboard</a>
            <a href="https://evil.example/path">External</a>
            <a href="mailto:security@example.com">Mail</a>
            <script src="/assets/app.js"></script>
            <link href="/assets/app.css" rel="stylesheet">
            <form action="/search" method="get"></form>
            <form action="/login" method="post"></form>
        "##;

        let candidates =
            extract_html_candidates("https://example.com/app/index.html", html).expect("crawl");

        assert_eq!(candidates.len(), 5);
        assert!(candidates.iter().any(|candidate| {
            candidate.method == "GET" && candidate.url == "https://example.com/dashboard"
        }));
        assert!(candidates.iter().any(|candidate| {
            candidate.method == "POST" && candidate.url == "https://example.com/login"
        }));
        assert!(candidates
            .iter()
            .all(|candidate| candidate.url.starts_with("https://example.com/")));
    }

    #[test]
    fn deduplicates_method_and_url_pairs() {
        let html = r#"
            <a href="/health">Health</a>
            <a href="/health#fragment">Health duplicate</a>
            <form action="/health" method="get"></form>
            <form action="/health" method="post"></form>
        "#;

        let candidates = extract_html_candidates("https://example.com/", html).expect("crawl");

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].method, "GET");
        assert_eq!(candidates[1].method, "POST");
    }

    #[test]
    fn rejects_non_http_base_url() {
        let result = extract_html_candidates("file:///tmp/index.html", "<a href=\"/x\">x</a>");

        assert_eq!(result, Err(CrawlerError::UnsupportedBaseUrl));
    }

    #[test]
    fn collects_form_parameter_names_without_values() {
        let html = r#"
            <form action="/search" method="get">
                <input name="q" value="secret">
                <select name="category" required></select>
                <input name="q" value="duplicate">
            </form>
            <form action="/login" method="post">
                <input name="username" required>
                <input name="password" type="password" value="do-not-store">
            </form>
        "#;

        let candidates = extract_html_candidates("https://example.com/", html).expect("crawl");
        let search = candidates
            .iter()
            .find(|candidate| candidate.url == "https://example.com/search")
            .expect("search form");
        let login = candidates
            .iter()
            .find(|candidate| candidate.url == "https://example.com/login")
            .expect("login form");

        assert_eq!(search.parameters.len(), 2);
        assert!(search.parameters.iter().any(|parameter| {
            parameter.name == "q"
                && parameter.location == CrawlParameterLocation::Query
                && !parameter.required
        }));
        assert!(search.parameters.iter().any(|parameter| {
            parameter.name == "category"
                && parameter.location == CrawlParameterLocation::Query
                && parameter.required
        }));
        assert!(login.parameters.iter().any(|parameter| {
            parameter.name == "password" && parameter.location == CrawlParameterLocation::Body
        }));
        assert!(login
            .parameters
            .iter()
            .all(|parameter| !parameter.name.contains("do-not-store")));
    }

    #[test]
    fn crawls_same_origin_html_pages_with_limits() {
        let client = StaticFetchClient {
            pages: HashMap::from([
                (
                    "https://example.com/".to_string(),
                    CrawlerFetchResponse {
                        final_url: "https://example.com/".to_string(),
                        status_code: 200,
                        content_type: Some("text/html; charset=utf-8".to_string()),
                        body: r#"
                            <a href="/app">App</a>
                            <a href="https://outside.example/">Outside</a>
                            <form action="/login" method="post"></form>
                        "#
                        .to_string(),
                    },
                ),
                (
                    "https://example.com/app".to_string(),
                    CrawlerFetchResponse {
                        final_url: "https://example.com/app".to_string(),
                        status_code: 200,
                        content_type: Some("text/html".to_string()),
                        body: r#"<a href="/settings">Settings</a>"#.to_string(),
                    },
                ),
                (
                    "https://example.com/settings".to_string(),
                    CrawlerFetchResponse {
                        final_url: "https://example.com/settings".to_string(),
                        status_code: 200,
                        content_type: Some("text/html".to_string()),
                        body: r#"<a href="/billing">Billing</a>"#.to_string(),
                    },
                ),
            ]),
        };
        let result = crawl_approved_html_surface(
            "https://example.com/",
            CrawlerOptions {
                max_depth: 1,
                max_pages: 10,
                max_candidates: 10,
                ..CrawlerOptions::default()
            },
            &client,
        )
        .expect("crawl");

        assert_eq!(result.pages.len(), 2);
        assert!(result
            .candidates
            .iter()
            .any(|candidate| candidate.url == "https://example.com/app"));
        assert!(result
            .candidates
            .iter()
            .any(|candidate| candidate.url == "https://example.com/login"));
        assert!(result
            .candidates
            .iter()
            .all(|candidate| !candidate.url.starts_with("https://outside.example")));
        assert!(result
            .pages
            .iter()
            .all(|page| page.url.starts_with("https://example.com/")));
    }

    #[test]
    fn skips_non_html_responses_without_parsing_links() {
        let client = StaticFetchClient {
            pages: HashMap::from([(
                "https://example.com/".to_string(),
                CrawlerFetchResponse {
                    final_url: "https://example.com/".to_string(),
                    status_code: 200,
                    content_type: Some("application/json".to_string()),
                    body: r#"<a href="/hidden">Hidden</a>"#.to_string(),
                },
            )]),
        };

        let result =
            crawl_approved_html_surface("https://example.com/", CrawlerOptions::default(), &client)
                .expect("crawl");

        assert_eq!(result.pages.len(), 1);
        assert!(result.candidates.is_empty());
    }

    #[test]
    fn extracts_browser_observation_candidates_without_query_values() {
        let observation = BrowserCrawlObservation {
            routes: vec![
                "https://example.com/app/dashboard?token=secret#section".to_string(),
                "/app/settings?tab=profile".to_string(),
                "https://outside.example/admin".to_string(),
            ],
            requests: vec![
                BrowserNetworkRequest {
                    method: "GET".to_string(),
                    url: "https://example.com/api/users?search=alice&token=secret".to_string(),
                    resource_type: Some("xhr".to_string()),
                },
                BrowserNetworkRequest {
                    method: "POST".to_string(),
                    url: "https://example.com/api/session".to_string(),
                    resource_type: Some("fetch".to_string()),
                },
                BrowserNetworkRequest {
                    method: "GET".to_string(),
                    url: "https://example.com/assets/app.js".to_string(),
                    resource_type: Some("script".to_string()),
                },
            ],
        };

        let candidates =
            extract_browser_observation_candidates("https://example.com/", &observation)
                .expect("browser candidates");

        assert_eq!(candidates.len(), 4);
        assert!(candidates.iter().any(|candidate| {
            candidate.source == CrawlCandidateSource::BrowserRoute
                && candidate.url == "https://example.com/app/dashboard"
                && candidate
                    .parameters
                    .iter()
                    .any(|parameter| parameter.name == "token")
        }));
        assert!(candidates.iter().any(|candidate| {
            candidate.source == CrawlCandidateSource::BrowserRequest
                && candidate.method == "GET"
                && candidate.url == "https://example.com/api/users"
                && candidate
                    .parameters
                    .iter()
                    .any(|parameter| parameter.name == "search")
        }));
        assert!(candidates.iter().any(|candidate| {
            candidate.method == "POST" && candidate.url == "https://example.com/api/session"
        }));
        assert!(candidates
            .iter()
            .all(|candidate| !candidate.url.contains("secret")));
        assert!(candidates
            .iter()
            .all(|candidate| candidate.url.starts_with("https://example.com/")));
    }
}
