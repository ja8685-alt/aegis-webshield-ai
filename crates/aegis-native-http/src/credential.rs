use std::collections::HashSet;
use std::fmt::{Debug, Formatter};

use aegis_native_engine::ApprovedTarget;
use reqwest::header::{HeaderName, HeaderValue, AUTHORIZATION, COOKIE};
use url::Url;
use zeroize::Zeroizing;

use crate::HttpExecutionError;

const MAX_SECRET_BYTES: usize = 4_096;
const MAX_HEADER_NAME_BYTES: usize = 128;

/// Supported worker-only credential injection type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialKind {
    BearerToken,
    ApiKeyHeader { header_name: String },
    CookieSession,
}

/// Exact HTTPS origin and path scope bound to one credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialScope {
    target_id: String,
    scheme: String,
    host: String,
    port: u16,
    path_prefix: String,
}

impl CredentialScope {
    /// Creates a credential scope no wider than an approved HTTPS target.
    pub fn new(
        target: &ApprovedTarget,
        path_prefix: impl Into<String>,
    ) -> Result<Self, HttpExecutionError> {
        let origin =
            Url::parse(&target.origin).map_err(|_| HttpExecutionError::CredentialInvalid)?;
        if origin.scheme() != "https" {
            return Err(HttpExecutionError::CredentialInvalid);
        }
        Self::from_parts(target, &origin, path_prefix.into())
    }

    fn from_parts(
        target: &ApprovedTarget,
        origin: &Url,
        path_prefix: String,
    ) -> Result<Self, HttpExecutionError> {
        let host = origin
            .host_str()
            .ok_or(HttpExecutionError::CredentialInvalid)?
            .to_ascii_lowercase();
        let port = origin
            .port_or_known_default()
            .ok_or(HttpExecutionError::CredentialInvalid)?;
        if !path_prefix.starts_with('/')
            || path_prefix.len() > 2_048
            || path_prefix.contains(['\r', '\n', '?', '#'])
            || has_dot_segment(&path_prefix)
            || !path_is_within(&target.path_prefix, &path_prefix)
        {
            return Err(HttpExecutionError::CredentialInvalid);
        }
        Ok(Self {
            target_id: target.target_id.clone(),
            scheme: origin.scheme().to_string(),
            host,
            port,
            path_prefix,
        })
    }

    fn contains(&self, target_id: &str, url: &Url) -> bool {
        self.target_id == target_id
            && self.scheme == url.scheme()
            && url
                .host_str()
                .is_some_and(|host| host.eq_ignore_ascii_case(&self.host))
            && url.port_or_known_default() == Some(self.port)
            && path_is_within(&self.path_prefix, url.path())
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    }

    #[cfg(test)]
    pub(super) fn for_http_test(
        target: &ApprovedTarget,
        path_prefix: &str,
    ) -> Result<Self, HttpExecutionError> {
        let origin =
            Url::parse(&target.origin).map_err(|_| HttpExecutionError::CredentialInvalid)?;
        Self::from_parts(target, &origin, path_prefix.to_string())
    }
}

/// Credential plaintext that is zeroized and never serialized or printed.
pub struct EphemeralCredential {
    kind: CredentialKind,
    scope: CredentialScope,
    secret: Zeroizing<String>,
}

impl EphemeralCredential {
    /// Validates and wraps one credential plaintext for worker memory only.
    pub fn new(
        kind: CredentialKind,
        scope: CredentialScope,
        secret: String,
    ) -> Result<Self, HttpExecutionError> {
        validate_kind(&kind)?;
        validate_secret(&kind, &secret)?;
        Ok(Self {
            kind,
            scope,
            secret: Zeroizing::new(secret),
        })
    }

    pub(crate) fn header_for_url(
        &self,
        target_id: &str,
        url: &Url,
    ) -> Result<(HeaderName, HeaderValue), HttpExecutionError> {
        if !self.scope.contains(target_id, url) {
            return Err(HttpExecutionError::CredentialScopeMismatch);
        }
        let (name, value) = match &self.kind {
            CredentialKind::BearerToken => (
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", self.secret.as_str()))
                    .map_err(|_| HttpExecutionError::CredentialInvalid)?,
            ),
            CredentialKind::ApiKeyHeader { header_name } => (
                HeaderName::from_bytes(header_name.as_bytes())
                    .map_err(|_| HttpExecutionError::CredentialInvalid)?,
                HeaderValue::from_str(self.secret.as_str())
                    .map_err(|_| HttpExecutionError::CredentialInvalid)?,
            ),
            CredentialKind::CookieSession => (
                COOKIE,
                HeaderValue::from_str(self.secret.as_str())
                    .map_err(|_| HttpExecutionError::CredentialInvalid)?,
            ),
        };
        Ok((name, value))
    }

    pub(crate) fn secret(&self) -> &str {
        self.secret.as_str()
    }
}

impl Debug for EphemeralCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EphemeralCredential")
            .field("kind", &self.kind)
            .field("scope", &self.scope)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

fn validate_kind(kind: &CredentialKind) -> Result<(), HttpExecutionError> {
    let CredentialKind::ApiKeyHeader { header_name } = kind else {
        return Ok(());
    };
    if header_name.is_empty()
        || header_name.len() > MAX_HEADER_NAME_BYTES
        || !header_name
            .bytes()
            .next()
            .is_some_and(|value| value.is_ascii_alphabetic())
        || !header_name
            .bytes()
            .enumerate()
            .all(|(index, value)| value.is_ascii_alphanumeric() || (index > 0 && value == b'-'))
    {
        return Err(HttpExecutionError::CredentialInvalid);
    }
    let lower = header_name.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "authorization"
            | "cookie"
            | "set-cookie"
            | "host"
            | "content-length"
            | "connection"
            | "transfer-encoding"
            | "proxy-authorization"
            | "proxy-authenticate"
    ) || lower.starts_with("x-forwarded-")
    {
        return Err(HttpExecutionError::CredentialInvalid);
    }
    Ok(())
}

fn validate_secret(kind: &CredentialKind, value: &str) -> Result<(), HttpExecutionError> {
    if value.is_empty() || value.len() > MAX_SECRET_BYTES || value.contains(['\r', '\n', '\0']) {
        return Err(HttpExecutionError::CredentialInvalid);
    }
    if matches!(
        kind,
        CredentialKind::BearerToken | CredentialKind::ApiKeyHeader { .. }
    ) && (!value.is_ascii()
        || value
            .bytes()
            .any(|character| character.is_ascii_whitespace()))
    {
        return Err(HttpExecutionError::CredentialInvalid);
    }
    if matches!(kind, CredentialKind::CookieSession) {
        validate_cookie(value)?;
    }
    Ok(())
}

fn validate_cookie(value: &str) -> Result<(), HttpExecutionError> {
    let mut names = HashSet::new();
    for pair in value.split(';') {
        let pair = pair.trim();
        let (name, cookie_value) = pair
            .split_once('=')
            .ok_or(HttpExecutionError::CredentialInvalid)?;
        if name.is_empty()
            || !name.bytes().all(is_cookie_name_character)
            || !names.insert(name.to_ascii_lowercase())
            || cookie_value.bytes().any(|character| {
                character.is_ascii_whitespace()
                    || character.is_ascii_control()
                    || matches!(character, b'"' | b'\\' | b',' | b';')
            })
        {
            return Err(HttpExecutionError::CredentialInvalid);
        }
    }
    Ok(())
}

fn is_cookie_name_character(value: u8) -> bool {
    value.is_ascii_alphanumeric()
        || matches!(
            value,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn path_is_within(prefix: &str, candidate: &str) -> bool {
    if prefix == "/" {
        true
    } else if prefix.ends_with('/') {
        candidate.starts_with(prefix)
    } else {
        candidate == prefix || candidate.starts_with(&format!("{prefix}/"))
    }
}

fn has_dot_segment(path: &str) -> bool {
    path.split('/').any(|segment| {
        matches!(
            segment.to_ascii_lowercase().as_str(),
            "." | ".." | "%2e" | "%2e%2e" | ".%2e" | "%2e."
        )
    })
}

#[cfg(test)]
mod tests {
    use aegis_native_engine::ApprovedTarget;

    use super::{CredentialKind, CredentialScope, EphemeralCredential};

    #[test]
    fn production_scope_requires_https_and_no_wider_path() {
        let http = ApprovedTarget::new("target-1", "http://example.com", "/api").unwrap();
        assert!(CredentialScope::new(&http, "/api").is_err());

        let https = ApprovedTarget::new("target-1", "https://example.com", "/api").unwrap();
        assert!(CredentialScope::new(&https, "/api/private").is_ok());
        assert!(CredentialScope::new(&https, "/").is_err());
        assert!(CredentialScope::new(&https, "/api/%2e%2e/admin").is_err());
    }

    #[test]
    fn rejects_dangerous_api_key_headers_and_invalid_cookie() {
        let target = ApprovedTarget::new("target-1", "https://example.com", "/").unwrap();
        let scope = CredentialScope::new(&target, "/").unwrap();
        assert!(EphemeralCredential::new(
            CredentialKind::ApiKeyHeader {
                header_name: "Host".to_string()
            },
            scope.clone(),
            "secret".to_string()
        )
        .is_err());
        assert!(EphemeralCredential::new(
            CredentialKind::ApiKeyHeader {
                header_name: "1-Invalid".to_string()
            },
            scope.clone(),
            "secret".to_string()
        )
        .is_err());
        assert!(EphemeralCredential::new(
            CredentialKind::CookieSession,
            scope.clone(),
            "session=ok; broken cookie".to_string()
        )
        .is_err());
        assert!(EphemeralCredential::new(
            CredentialKind::CookieSession,
            scope,
            "session=one; Session=two".to_string()
        )
        .is_err());
    }

    #[test]
    fn debug_never_contains_plaintext() {
        let target = ApprovedTarget::new("target-1", "https://example.com", "/").unwrap();
        let credential = EphemeralCredential::new(
            CredentialKind::BearerToken,
            CredentialScope::new(&target, "/").unwrap(),
            "top-secret-token".to_string(),
        )
        .unwrap();
        assert!(!format!("{credential:?}").contains("top-secret-token"));
    }
}
