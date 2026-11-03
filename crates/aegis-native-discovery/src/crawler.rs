use std::collections::BTreeMap;

use aegis_native_engine::{ApprovedTarget, HttpMethod};
use scraper::{ElementRef, Html, Selector};

use crate::{canonicalize_url, CanonicalUrl, CanonicalizationOutcome, DiscoveryError};

const HARD_MAX_HTML_BYTES: usize = 2 * 1024 * 1024;
const HARD_MAX_CANDIDATES: usize = 300;
const HARD_MAX_FORM_FIELDS: usize = 64;
const MAX_FORM_FIELD_NAME_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrawlLimits {
    pub max_html_bytes: usize,
    pub max_candidates: usize,
    pub max_form_fields: usize,
}

impl Default for CrawlLimits {
    fn default() -> Self {
        Self {
            max_html_bytes: HARD_MAX_HTML_BYTES,
            max_candidates: HARD_MAX_CANDIDATES,
            max_form_fields: HARD_MAX_FORM_FIELDS,
        }
    }
}

impl CrawlLimits {
    pub fn validate(&self) -> Result<(), DiscoveryError> {
        if self.max_html_bytes == 0
            || self.max_html_bytes > HARD_MAX_HTML_BYTES
            || self.max_candidates == 0
            || self.max_candidates > HARD_MAX_CANDIDATES
            || self.max_form_fields == 0
            || self.max_form_fields > HARD_MAX_FORM_FIELDS
        {
            return Err(DiscoveryError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EndpointSource {
    Link,
    Form,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FormFieldKind {
    Text,
    Password,
    Hidden,
    Checkbox,
    Radio,
    File,
    Submit,
    Other,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FormField {
    pub name: String,
    pub kind: FormFieldKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredEndpoint {
    pub url: CanonicalUrl,
    pub method: HttpMethod,
    pub source: EndpointSource,
    pub form_fields: Vec<FormField>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrawlResult {
    pub endpoints: Vec<DiscoveredEndpoint>,
    pub inspected_candidates: usize,
    pub ignored_candidates: usize,
    pub truncated: bool,
}

/// Parses links and form contracts without retaining HTML or input values.
pub fn crawl_html(
    target: &ApprovedTarget,
    document_url: &str,
    html: &str,
    limits: CrawlLimits,
) -> Result<CrawlResult, DiscoveryError> {
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
    let candidate_selector = Selector::parse("a[href], area[href], form")
        .map_err(|_| DiscoveryError::ParserSetupFailed)?;
    let base_selector =
        Selector::parse("base[href]").map_err(|_| DiscoveryError::ParserSetupFailed)?;
    let field_selector = Selector::parse("input[name], select[name], textarea[name]")
        .map_err(|_| DiscoveryError::ParserSetupFailed)?;
    let mut endpoints = BTreeMap::<String, DiscoveredEndpoint>::new();
    let mut inspected_candidates = 0usize;
    let mut ignored_candidates = 0usize;
    let mut truncated = false;
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

    for element in document.select(&candidate_selector) {
        if inspected_candidates >= limits.max_candidates {
            truncated = true;
            break;
        }
        inspected_candidates += 1;
        let name = element.value().name();
        let (raw_url, method, source) = if name == "form" {
            let method = match element
                .value()
                .attr("method")
                .unwrap_or("get")
                .trim()
                .to_ascii_lowercase()
                .as_str()
            {
                "get" => HttpMethod::Get,
                "post" => HttpMethod::Post,
                _ => {
                    ignored_candidates += 1;
                    continue;
                }
            };
            let action = element.value().attr("action").unwrap_or(document_url);
            let action = if action.trim().is_empty() {
                document_url
            } else {
                action
            };
            (action, method, EndpointSource::Form)
        } else {
            let Some(href) = element.value().attr("href") else {
                ignored_candidates += 1;
                continue;
            };
            (href, HttpMethod::Get, EndpointSource::Link)
        };

        let CanonicalizationOutcome::Accepted(url) =
            canonicalize_url(target, &resolution_base, raw_url)?
        else {
            ignored_candidates += 1;
            continue;
        };
        let form_fields = if source == EndpointSource::Form {
            extract_form_fields(element, &field_selector, limits.max_form_fields)
        } else {
            Vec::new()
        };
        let key = format!("{}:{}", method_name(method), url.dedup_key());
        let candidate = DiscoveredEndpoint {
            url,
            method,
            source,
            form_fields,
        };
        match endpoints.get_mut(&key) {
            Some(existing) => merge_duplicate(existing, candidate),
            None => {
                endpoints.insert(key, candidate);
            }
        }
    }

    Ok(CrawlResult {
        endpoints: endpoints.into_values().collect(),
        inspected_candidates,
        ignored_candidates,
        truncated,
    })
}

fn extract_form_fields(
    form: ElementRef<'_>,
    selector: &Selector,
    max_fields: usize,
) -> Vec<FormField> {
    let mut fields = form
        .select(selector)
        .filter_map(|field| {
            let name = field.value().attr("name")?.trim();
            if name.is_empty()
                || name.len() > MAX_FORM_FIELD_NAME_BYTES
                || name.contains(['\r', '\n', '\0'])
            {
                return None;
            }
            Some(FormField {
                name: name.to_string(),
                kind: form_field_kind(field),
            })
        })
        .take(max_fields)
        .collect::<Vec<_>>();
    fields.sort_unstable();
    fields.dedup();
    fields
}

fn form_field_kind(field: ElementRef<'_>) -> FormFieldKind {
    match field.value().name() {
        "select" | "textarea" => FormFieldKind::Text,
        "input" => match field
            .value()
            .attr("type")
            .unwrap_or("text")
            .to_ascii_lowercase()
            .as_str()
        {
            "text" | "search" | "email" | "url" | "tel" | "number" => FormFieldKind::Text,
            "password" => FormFieldKind::Password,
            "hidden" => FormFieldKind::Hidden,
            "checkbox" => FormFieldKind::Checkbox,
            "radio" => FormFieldKind::Radio,
            "file" => FormFieldKind::File,
            "submit" | "button" | "image" => FormFieldKind::Submit,
            _ => FormFieldKind::Other,
        },
        _ => FormFieldKind::Other,
    }
}

fn merge_duplicate(existing: &mut DiscoveredEndpoint, candidate: DiscoveredEndpoint) {
    if candidate.source == EndpointSource::Form {
        existing.source = EndpointSource::Form;
    }
    existing.form_fields.extend(candidate.form_fields);
    existing.form_fields.sort_unstable();
    existing.form_fields.dedup();
}

fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Head => "HEAD",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Post => "POST",
    }
}

#[cfg(test)]
mod tests {
    use aegis_native_engine::{ApprovedTarget, HttpMethod};

    use super::{crawl_html, CrawlLimits, EndpointSource, FormFieldKind};
    use crate::DiscoveryError;

    fn target() -> ApprovedTarget {
        ApprovedTarget::new("target-1", "https://example.com", "/app").unwrap()
    }

    #[test]
    fn extracts_links_and_forms_with_scope_and_deduplication() {
        let html = r#"
            <a href="/app/items?b=2&a=1#one">first</a>
            <a href="/app/items?a=1&b=2#two">duplicate</a>
            <a href="https://evil.example/steal">external</a>
            <a href="javascript:alert(1)">script</a>
            <form action="/app/search" method="get">
              <input name="q" value="must-not-be-retained">
              <input name="token" value="secret">
            </form>
            <form action="/app/login" method="post">
              <input name="password" type="password" value="plain-password">
            </form>
        "#;
        let result = crawl_html(
            &target(),
            "https://example.com/app/index",
            html,
            CrawlLimits::default(),
        )
        .unwrap();

        assert_eq!(result.endpoints.len(), 3);
        assert_eq!(result.ignored_candidates, 2);
        assert!(!result.truncated);
        let search = result
            .endpoints
            .iter()
            .find(|endpoint| endpoint.url.as_str().contains("/search"))
            .unwrap();
        assert_eq!(search.method, HttpMethod::Get);
        assert_eq!(search.source, EndpointSource::Form);
        assert_eq!(search.form_fields.len(), 2);
        let login = result
            .endpoints
            .iter()
            .find(|endpoint| endpoint.url.as_str().contains("/login"))
            .unwrap();
        assert_eq!(login.method, HttpMethod::Post);
        assert_eq!(login.form_fields[0].kind, FormFieldKind::Password);
        assert!(!format!("{result:?}").contains("plain-password"));
        assert!(!format!("{result:?}").contains("must-not-be-retained"));
    }

    #[test]
    fn reports_candidate_truncation_deterministically() {
        let limits = CrawlLimits {
            max_candidates: 1,
            ..CrawlLimits::default()
        };
        let result = crawl_html(
            &target(),
            "https://example.com/app/",
            "<a href='/app/one'>one</a><a href='/app/two'>two</a>",
            limits,
        )
        .unwrap();
        assert_eq!(result.inspected_candidates, 1);
        assert_eq!(result.endpoints.len(), 1);
        assert!(result.truncated);
    }

    #[test]
    fn honors_in_scope_base_and_empty_form_action() {
        let html = r#"
            <base href="/app/v2/">
            <a href="users">users</a>
            <form action=""><input name="q"></form>
        "#;
        let result = crawl_html(
            &target(),
            "https://example.com/app/index",
            html,
            CrawlLimits::default(),
        )
        .unwrap();
        assert!(result
            .endpoints
            .iter()
            .any(|endpoint| endpoint.url.as_str() == "https://example.com/app/v2/users"));
        assert!(result
            .endpoints
            .iter()
            .any(|endpoint| endpoint.url.as_str() == "https://example.com/app/index"));
    }

    #[test]
    fn rejects_oversized_document_before_parsing() {
        let limits = CrawlLimits {
            max_html_bytes: 8,
            ..CrawlLimits::default()
        };
        assert_eq!(
            crawl_html(
                &target(),
                "https://example.com/app/",
                "<a href='/app/x'>",
                limits,
            ),
            Err(DiscoveryError::DocumentTooLarge)
        );
    }
}
