use aegis_native_engine::{ApprovedTarget, MAX_URL_BYTES};
use url::Url;

use crate::DiscoveryError;

const MAX_QUERY_PAIRS: usize = 64;

/// Secret-free, normalized URL suitable for endpoint deduplication and request planning.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CanonicalUrl {
    value: String,
    dedup_key: String,
}

impl CanonicalUrl {
    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn into_string(self) -> String {
        self.value
    }

    pub fn dedup_key(&self) -> &str {
        &self.dedup_key
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IgnoredCandidateReason {
    Empty,
    TooLong,
    InvalidUrl,
    UnsupportedScheme,
    UserInfo,
    OutOfScope,
    TooManyQueryPairs,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalizationOutcome {
    Accepted(CanonicalUrl),
    Ignored(IgnoredCandidateReason),
}

/// Resolves and normalizes one untrusted HTML URL candidate inside an approved target.
pub fn canonicalize_url(
    target: &ApprovedTarget,
    document_url: &str,
    raw_candidate: &str,
) -> Result<CanonicalizationOutcome, DiscoveryError> {
    target
        .validate()
        .map_err(|_| DiscoveryError::InvalidTarget)?;
    if !target.contains_url(document_url) {
        return Err(DiscoveryError::DocumentOutOfScope);
    }
    let base = Url::parse(document_url).map_err(|_| DiscoveryError::InvalidDocumentUrl)?;
    let candidate = raw_candidate.trim();
    if candidate.is_empty() {
        return Ok(CanonicalizationOutcome::Ignored(
            IgnoredCandidateReason::Empty,
        ));
    }
    if candidate.len() > MAX_URL_BYTES || candidate.contains(['\r', '\n', '\0']) {
        return Ok(CanonicalizationOutcome::Ignored(
            IgnoredCandidateReason::TooLong,
        ));
    }
    let mut resolved = match base.join(candidate) {
        Ok(value) => value,
        Err(_) => {
            return Ok(CanonicalizationOutcome::Ignored(
                IgnoredCandidateReason::InvalidUrl,
            ));
        }
    };
    if !matches!(resolved.scheme(), "http" | "https") {
        return Ok(CanonicalizationOutcome::Ignored(
            IgnoredCandidateReason::UnsupportedScheme,
        ));
    }
    if !resolved.username().is_empty() || resolved.password().is_some() {
        return Ok(CanonicalizationOutcome::Ignored(
            IgnoredCandidateReason::UserInfo,
        ));
    }
    resolved.set_fragment(None);
    if !target.contains_url(resolved.as_str()) {
        return Ok(CanonicalizationOutcome::Ignored(
            IgnoredCandidateReason::OutOfScope,
        ));
    }

    let mut query = resolved
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    if query.len() > MAX_QUERY_PAIRS {
        return Ok(CanonicalizationOutcome::Ignored(
            IgnoredCandidateReason::TooManyQueryPairs,
        ));
    }
    query.retain(|(name, _)| !is_tracking_parameter(name));
    for (name, value) in &mut query {
        if is_sensitive_parameter(name) {
            *value = "[REDACTED]".to_string();
        }
    }
    resolved.set_query(None);
    if !query.is_empty() {
        resolved.query_pairs_mut().extend_pairs(&query);
    }

    let value = resolved.to_string();
    if value.len() > MAX_URL_BYTES {
        return Ok(CanonicalizationOutcome::Ignored(
            IgnoredCandidateReason::TooLong,
        ));
    }
    if !target.contains_url(&value) {
        return Ok(CanonicalizationOutcome::Ignored(
            IgnoredCandidateReason::OutOfScope,
        ));
    }
    let mut dedup_url = resolved;
    let mut sorted_query = query;
    sorted_query.sort_unstable();
    dedup_url.set_query(None);
    if !sorted_query.is_empty() {
        dedup_url.query_pairs_mut().extend_pairs(&sorted_query);
    }
    Ok(CanonicalizationOutcome::Accepted(CanonicalUrl {
        value,
        dedup_key: dedup_url.to_string(),
    }))
}

fn is_tracking_parameter(name: &str) -> bool {
    let lower = name.to_ascii_lowercase().replace('-', "_");
    lower.starts_with("utm_")
        || matches!(
            lower.as_str(),
            "gclid" | "dclid" | "fbclid" | "msclkid" | "mc_cid" | "mc_eid"
        )
}

fn is_sensitive_parameter(name: &str) -> bool {
    let lower = name.to_ascii_lowercase().replace('-', "_");
    lower.contains("token")
        || lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("secret")
        || lower.contains("api_key")
        || lower == "key"
}

#[cfg(test)]
mod tests {
    use aegis_native_engine::ApprovedTarget;
    use url::Url;

    use super::{canonicalize_url, CanonicalizationOutcome, IgnoredCandidateReason};

    fn target() -> ApprovedTarget {
        ApprovedTarget::new("target-1", "https://example.com", "/app").unwrap()
    }

    #[test]
    fn normalizes_dedup_parts_and_redacts_sensitive_query() {
        let outcome = canonicalize_url(
            &target(),
            "https://example.com/app/index",
            "../app/items?token=plain&utm_source=x&b=2&a=1#section",
        )
        .unwrap();
        let CanonicalizationOutcome::Accepted(url) = outcome else {
            panic!("candidate should be accepted");
        };
        let parsed = Url::parse(url.as_str()).unwrap();
        assert!(parsed.fragment().is_none());
        assert_eq!(
            parsed.query_pairs().collect::<Vec<_>>(),
            vec![
                ("token".into(), "[REDACTED]".into()),
                ("b".into(), "2".into()),
                ("a".into(), "1".into())
            ]
        );
        assert!(url.dedup_key().contains("a=1&b=2&token="));
        assert!(!url.as_str().contains("plain"));
        assert!(!url.as_str().contains("utm_source"));
    }

    #[test]
    fn ignores_unsupported_and_out_of_scope_candidates() {
        assert_eq!(
            canonicalize_url(&target(), "https://example.com/app/", "javascript:alert(1)").unwrap(),
            CanonicalizationOutcome::Ignored(IgnoredCandidateReason::UnsupportedScheme)
        );
        assert_eq!(
            canonicalize_url(
                &target(),
                "https://example.com/app/",
                "https://evil.example/"
            )
            .unwrap(),
            CanonicalizationOutcome::Ignored(IgnoredCandidateReason::OutOfScope)
        );
        assert_eq!(
            canonicalize_url(&target(), "https://example.com/app/", "/admin").unwrap(),
            CanonicalizationOutcome::Ignored(IgnoredCandidateReason::OutOfScope)
        );
    }
}
