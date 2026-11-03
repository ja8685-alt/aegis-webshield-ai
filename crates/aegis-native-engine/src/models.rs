use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{ContractError, RedactedText};

/// Maximum identifier length in a service-boundary message.
pub const MAX_ID_BYTES: usize = 64;
/// Maximum serialized URL length.
pub const MAX_URL_BYTES: usize = 2_048;
/// Maximum header name length.
pub const MAX_HEADER_NAME_BYTES: usize = 128;
/// Maximum already-redacted header value length.
pub const MAX_HEADER_VALUE_BYTES: usize = 8_192;
/// D-146 evidence body limit.
pub const MAX_EVIDENCE_BODY_BYTES: usize = 16_384;
/// D-146 maximum response bytes read from a target.
pub const MAX_RESPONSE_BYTES: u64 = 2_097_152;
/// Maximum deterministic decision reason length.
pub const MAX_DECISION_REASON_BYTES: usize = 4_096;
/// Maximum number of headers retained in a request or response record.
pub const MAX_HEADER_COUNT: usize = 128;
/// Maximum normalized observations per evidence record.
pub const MAX_OBSERVATIONS: usize = 64;

/// Approved target scope used by all native request records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApprovedTarget {
    pub target_id: String,
    pub origin: String,
    pub path_prefix: String,
}

impl ApprovedTarget {
    /// Creates an exact HTTP(S) target scope without URL credentials or fragments.
    pub fn new(
        target_id: impl Into<String>,
        origin: impl Into<String>,
        path_prefix: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let target = Self {
            target_id: target_id.into(),
            origin: origin.into(),
            path_prefix: path_prefix.into(),
        };
        target.validate()?;
        Ok(target)
    }

    /// Validates identifier, normalized origin, and path prefix bounds.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_id("target_id", &self.target_id)?;
        validate_url_length(&self.origin)?;
        let url = Url::parse(&self.origin)
            .map_err(|_| ContractError::new("origin", "must be an absolute URL"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ContractError::new("origin", "scheme must be http or https"));
        }
        if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
            return Err(ContractError::new(
                "origin",
                "host is required and userinfo is forbidden",
            ));
        }
        if url.query().is_some() || url.fragment().is_some() || url.path() != "/" {
            return Err(ContractError::new(
                "origin",
                "must contain only scheme, host, and optional port",
            ));
        }
        if !self.path_prefix.starts_with('/')
            || self.path_prefix.len() > MAX_URL_BYTES
            || self.path_prefix.contains(['\r', '\n', '?', '#'])
        {
            return Err(ContractError::new(
                "path_prefix",
                "must be a bounded absolute path without fragment or controls",
            ));
        }
        Ok(())
    }

    /// Validates that a request URL remains in the exact origin and path prefix.
    pub fn contains_url(&self, request_url: &str) -> bool {
        let Ok(scope) = Url::parse(&self.origin) else {
            return false;
        };
        let Ok(candidate) = Url::parse(request_url) else {
            return false;
        };
        let path_matches = if self.path_prefix == "/" {
            true
        } else if self.path_prefix.ends_with('/') {
            candidate.path().starts_with(&self.path_prefix)
        } else {
            candidate.path() == self.path_prefix
                || candidate
                    .path()
                    .starts_with(&format!("{}/", self.path_prefix))
        };
        scope.scheme() == candidate.scheme()
            && scope.host_str() == candidate.host_str()
            && scope.port_or_known_default() == candidate.port_or_known_default()
            && path_matches
            && candidate.username().is_empty()
            && candidate.password().is_none()
            && candidate.fragment().is_none()
    }
}

/// HTTP methods permitted by the D-146 native safety policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Head,
    Options,
    Post,
}

/// Reason a bounded request was planned.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestPurpose {
    Discovery,
    Baseline,
    Probe,
    Control,
}

/// Header metadata that is redacted before persistence or service delivery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeaderRecord {
    pub name: String,
    pub value: RedactedText,
}

impl HeaderRecord {
    /// Creates a validated header and always redacts known secret header values.
    pub fn new(name: impl Into<String>, value: &str) -> Result<Self, ContractError> {
        let name = name.into();
        validate_header_name(&name)?;
        let value = if is_sensitive_header(&name) {
            RedactedText::new("[REDACTED]", MAX_HEADER_VALUE_BYTES)?
        } else {
            RedactedText::new(value, MAX_HEADER_VALUE_BYTES)?
        };
        Ok(Self { name, value })
    }
}

/// Digest and bounded redacted excerpt for a request or response payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PayloadSummary {
    pub byte_length: u64,
    pub sha256: String,
    pub redacted_excerpt: RedactedText,
    pub truncated: bool,
}

impl PayloadSummary {
    /// Summarizes payload bytes without retaining the full body.
    pub fn from_bytes(bytes: &[u8], observed_truncated: bool) -> Result<Self, ContractError> {
        Self::from_bytes_with_redactions(bytes, observed_truncated, &[])
    }

    /// Summarizes bytes while additionally removing exact ephemeral secrets from the excerpt.
    pub fn from_bytes_with_redactions(
        bytes: &[u8],
        observed_truncated: bool,
        exact_secrets: &[&str],
    ) -> Result<Self, ContractError> {
        let digest = Sha256::digest(bytes);
        let mut excerpt = String::from_utf8_lossy(bytes).into_owned();
        for secret in exact_secrets.iter().filter(|secret| !secret.is_empty()) {
            excerpt = excerpt.replace(secret, "[REDACTED]");
        }
        let redacted_excerpt = RedactedText::new(&excerpt, MAX_EVIDENCE_BODY_BYTES)?;
        Ok(Self {
            byte_length: bytes.len() as u64,
            sha256: hex_encode(&digest),
            truncated: observed_truncated || redacted_excerpt.truncated(),
            redacted_excerpt,
        })
    }

    /// Validates digest and target response size invariants.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.byte_length > MAX_RESPONSE_BYTES {
            return Err(ContractError::new(
                "byte_length",
                "exceeds maximum response size",
            ));
        }
        if self.sha256.len() != 64 || !self.sha256.bytes().all(|value| value.is_ascii_hexdigit()) {
            return Err(ContractError::new(
                "sha256",
                "must be a 64-character hexadecimal digest",
            ));
        }
        if self.redacted_excerpt.as_str().len() > MAX_EVIDENCE_BODY_BYTES {
            return Err(ContractError::new(
                "redacted_excerpt",
                "exceeds evidence body limit",
            ));
        }
        Ok(())
    }
}

/// Secret-free request record shared between worker, persistence, and review layers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeRequestRecord {
    pub request_id: String,
    pub target_id: String,
    pub method: HttpMethod,
    pub url: String,
    pub purpose: RequestPurpose,
    pub headers: Vec<HeaderRecord>,
    pub payload: Option<PayloadSummary>,
    pub credential_ref: Option<String>,
}

impl NativeRequestRecord {
    /// Validates a request record against an approved target scope.
    pub fn validate(&self, target: &ApprovedTarget) -> Result<(), ContractError> {
        validate_id("request_id", &self.request_id)?;
        validate_id("target_id", &self.target_id)?;
        if self.target_id != target.target_id || !target.contains_url(&self.url) {
            return Err(ContractError::new(
                "url",
                "must remain inside the approved target scope",
            ));
        }
        validate_url_length(&self.url)?;
        validate_redacted_url_query(&self.url)?;
        validate_headers(&self.headers)?;
        if let Some(payload) = &self.payload {
            payload.validate()?;
        }
        if let Some(credential_ref) = &self.credential_ref {
            validate_id("credential_ref", credential_ref)?;
        }
        if self.method == HttpMethod::Post
            && !matches!(
                self.purpose,
                RequestPurpose::Baseline | RequestPurpose::Control
            )
        {
            return Err(ContractError::new(
                "method",
                "POST requires a separately approved baseline or control contract",
            ));
        }
        Ok(())
    }
}

/// Secret-free response record bounded by D-146 limits.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeResponseRecord {
    pub status_code: u16,
    pub final_url: String,
    pub headers: Vec<HeaderRecord>,
    pub payload: PayloadSummary,
    pub duration_millis: u64,
}

impl NativeResponseRecord {
    /// Validates response scope, status, header, body, and duration limits.
    pub fn validate(&self, target: &ApprovedTarget) -> Result<(), ContractError> {
        if !(100..=599).contains(&self.status_code) {
            return Err(ContractError::new(
                "status_code",
                "must be a valid HTTP status",
            ));
        }
        if !target.contains_url(&self.final_url) {
            return Err(ContractError::new(
                "final_url",
                "cross-origin or out-of-prefix response is forbidden",
            ));
        }
        validate_redacted_url_query(&self.final_url)?;
        validate_headers(&self.headers)?;
        self.payload.validate()?;
        if self.duration_millis > 10_000 {
            return Err(ContractError::new(
                "duration_millis",
                "exceeds request timeout",
            ));
        }
        Ok(())
    }
}

/// Role of one exchange inside a deterministic evidence decision.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRole {
    Baseline,
    Probe,
    Control,
}

/// Raw exchange record after scope validation, redaction, and bounding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RawExchangeEvidence {
    pub evidence_id: String,
    pub role: EvidenceRole,
    pub request: NativeRequestRecord,
    pub response: NativeResponseRecord,
    pub captured_at: String,
}

impl RawExchangeEvidence {
    /// Validates raw evidence and ensures request purpose agrees with evidence role.
    pub fn validate(&self, target: &ApprovedTarget) -> Result<(), ContractError> {
        validate_id("evidence_id", &self.evidence_id)?;
        self.request.validate(target)?;
        self.response.validate(target)?;
        let role_matches = matches!(
            (self.role, self.request.purpose),
            (EvidenceRole::Baseline, RequestPurpose::Baseline)
                | (EvidenceRole::Probe, RequestPurpose::Probe)
                | (EvidenceRole::Control, RequestPurpose::Control)
        );
        if !role_matches {
            return Err(ContractError::new(
                "role",
                "must agree with request purpose",
            ));
        }
        validate_timestamp(&self.captured_at)
    }
}

/// One bounded deterministic observation derived from raw evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub code: String,
    pub value: RedactedText,
}

impl Observation {
    /// Creates an allowlist-shaped observation code and redacted value.
    pub fn new(code: impl Into<String>, value: &str) -> Result<Self, ContractError> {
        let code = code.into();
        validate_observation_code(&code)?;
        Ok(Self {
            code,
            value: RedactedText::new(value, MAX_DECISION_REASON_BYTES)?,
        })
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_observation_code(&self.code)?;
        if self.value.truncated() {
            return Err(ContractError::new(
                "observation.value",
                "must be present without truncation",
            ));
        }
        Ok(())
    }
}

/// Normalized, scanner-independent evidence that references raw exchanges.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NormalizedEvidence {
    pub evidence_id: String,
    pub raw_evidence_ref: String,
    pub role: EvidenceRole,
    pub observations: Vec<Observation>,
    pub decision_reason: RedactedText,
}

impl NormalizedEvidence {
    /// Validates evidence references, observation bounds, and decision reason size.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_id("evidence_id", &self.evidence_id)?;
        validate_id("raw_evidence_ref", &self.raw_evidence_ref)?;
        if self.observations.is_empty() || self.observations.len() > MAX_OBSERVATIONS {
            return Err(ContractError::new(
                "observations",
                "must contain one to 64 bounded observations",
            ));
        }
        for observation in &self.observations {
            observation.validate()?;
        }
        if self.decision_reason.as_str().is_empty()
            || self.decision_reason.as_str().len() > MAX_DECISION_REASON_BYTES
            || self.decision_reason.truncated()
        {
            return Err(ContractError::new(
                "decision_reason",
                "must be present and bounded",
            ));
        }
        Ok(())
    }
}

fn validate_observation_code(code: &str) -> Result<(), ContractError> {
    if code.is_empty()
        || code.len() > MAX_ID_BYTES
        || !code.bytes().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == b'_'
        })
    {
        return Err(ContractError::new(
            "observation.code",
            "must contain lowercase letters, digits, or underscore",
        ));
    }
    Ok(())
}

fn validate_id(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value.bytes().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(ContractError::new(
            field,
            "must be a bounded opaque identifier",
        ));
    }
    Ok(())
}

fn validate_url_length(value: &str) -> Result<(), ContractError> {
    if value.len() > MAX_URL_BYTES || value.contains(['\r', '\n']) {
        return Err(ContractError::new(
            "url",
            "exceeds length limit or contains controls",
        ));
    }
    Ok(())
}

fn validate_redacted_url_query(value: &str) -> Result<(), ContractError> {
    let url =
        Url::parse(value).map_err(|_| ContractError::new("url", "must be an absolute URL"))?;
    for (name, query_value) in url.query_pairs() {
        let name = name.to_ascii_lowercase().replace('-', "_");
        let sensitive = name.contains("token")
            || name.contains("password")
            || name.contains("passwd")
            || name.contains("secret")
            || name.contains("api_key")
            || name == "key";
        if sensitive && query_value != "[REDACTED]" {
            return Err(ContractError::new(
                "url.query",
                "sensitive query values must be redacted before recording",
            ));
        }
    }
    Ok(())
}

fn validate_headers(headers: &[HeaderRecord]) -> Result<(), ContractError> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(ContractError::new(
            "headers",
            "exceeds maximum header count",
        ));
    }
    for header in headers {
        validate_header_name(&header.name)?;
        if header.value.as_str().len() > MAX_HEADER_VALUE_BYTES {
            return Err(ContractError::new(
                "header.value",
                "exceeds maximum header value size",
            ));
        }
    }
    Ok(())
}

fn validate_header_name(value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > MAX_HEADER_NAME_BYTES
        || !value
            .bytes()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, b'-' | b'_'))
    {
        return Err(ContractError::new(
            "header.name",
            "must be an ASCII token with a bounded length",
        ));
    }
    Ok(())
}

fn is_sensitive_header(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
    ) || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("api-key")
}

fn validate_timestamp(value: &str) -> Result<(), ContractError> {
    if value.len() < 20
        || value.len() > 40
        || !value.contains('T')
        || !(value.ends_with('Z') || value.contains('+'))
        || value.contains(['\r', '\n'])
    {
        return Err(ContractError::new(
            "captured_at",
            "must be a bounded RFC3339-shaped timestamp",
        ));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovedTarget, EvidenceRole, HeaderRecord, HttpMethod, NativeRequestRecord,
        NativeResponseRecord, NormalizedEvidence, Observation, PayloadSummary, RawExchangeEvidence,
        RequestPurpose, MAX_EVIDENCE_BODY_BYTES,
    };
    use crate::RedactedText;

    fn target() -> ApprovedTarget {
        ApprovedTarget::new("target-1", "https://example.com", "/api/").unwrap()
    }

    fn payload(value: &str) -> PayloadSummary {
        PayloadSummary::from_bytes(value.as_bytes(), false).unwrap()
    }

    fn request(purpose: RequestPurpose) -> NativeRequestRecord {
        NativeRequestRecord {
            request_id: "request-1".to_string(),
            target_id: "target-1".to_string(),
            method: HttpMethod::Get,
            url: "https://example.com/api/orders?id=1".to_string(),
            purpose,
            headers: vec![HeaderRecord::new("Authorization", "Bearer secret-token").unwrap()],
            payload: None,
            credential_ref: Some("credential-1".to_string()),
        }
    }

    fn response() -> NativeResponseRecord {
        NativeResponseRecord {
            status_code: 200,
            final_url: "https://example.com/api/orders?id=1".to_string(),
            headers: vec![HeaderRecord::new("Content-Type", "application/json").unwrap()],
            payload: payload("{\"access_token\":\"secret-value\",\"ok\":true}"),
            duration_millis: 30,
        }
    }

    #[test]
    fn exact_origin_port_and_path_scope_are_required() {
        let target = target();
        assert!(target.contains_url("https://example.com/api/orders"));
        assert!(!target.contains_url("https://example.com/admin"));
        assert!(!target.contains_url("https://sub.example.com/api/orders"));
        assert!(!target.contains_url("http://example.com/api/orders"));
        assert!(!target.contains_url("https://example.com:8443/api/orders"));

        let segment_target =
            ApprovedTarget::new("target-2", "https://example.com", "/api").unwrap();
        assert!(segment_target.contains_url("https://example.com/api/orders"));
        assert!(!segment_target.contains_url("https://example.com/api-admin"));
    }

    #[test]
    fn request_and_response_records_never_retain_known_secrets() {
        let request = request(RequestPurpose::Probe);
        let response = response();
        assert_eq!(request.headers[0].value.as_str(), "[REDACTED]");
        assert!(!response
            .payload
            .redacted_excerpt
            .as_str()
            .contains("secret-value"));
        assert!(request.validate(&target()).is_ok());
        assert!(response.validate(&target()).is_ok());

        let serialized = serde_json::to_string(&(request, response)).unwrap();
        assert!(!serialized.contains("secret-token"));
        assert!(!serialized.contains("secret-value"));
    }

    #[test]
    fn payload_excerpt_is_bounded_without_storing_full_body() {
        let bytes = vec![b'a'; MAX_EVIDENCE_BODY_BYTES + 100];
        let summary = PayloadSummary::from_bytes(&bytes, false).unwrap();
        assert_eq!(
            summary.redacted_excerpt.as_str().len(),
            MAX_EVIDENCE_BODY_BYTES
        );
        assert!(summary.truncated);
        assert_eq!(summary.sha256.len(), 64);
    }

    #[test]
    fn raw_and_normalized_evidence_enforce_role_and_references() {
        let raw = RawExchangeEvidence {
            evidence_id: "raw-1".to_string(),
            role: EvidenceRole::Probe,
            request: request(RequestPurpose::Probe),
            response: response(),
            captured_at: "2026-07-16T12:00:00Z".to_string(),
        };
        assert!(raw.validate(&target()).is_ok());

        let normalized = NormalizedEvidence {
            evidence_id: "normalized-1".to_string(),
            raw_evidence_ref: "raw-1".to_string(),
            role: EvidenceRole::Probe,
            observations: vec![Observation::new("status_delta", "200 -> 500").unwrap()],
            decision_reason: RedactedText::new("probe response differs from control", 4096)
                .unwrap(),
        };
        assert!(normalized.validate().is_ok());
    }

    #[test]
    fn normalized_evidence_revalidates_deserialized_observation_shape_and_bounds() {
        let normalized = NormalizedEvidence {
            evidence_id: "normalized-1".to_string(),
            raw_evidence_ref: "raw-1".to_string(),
            role: EvidenceRole::Probe,
            observations: vec![Observation::new("status_delta", "200 -> 500").unwrap()],
            decision_reason: RedactedText::new("probe response differs from control", 4096)
                .unwrap(),
        };
        let mut invalid_code = serde_json::to_value(&normalized).unwrap();
        invalid_code["observations"][0]["code"] = serde_json::json!("INVALID-CODE");
        let invalid_code: NormalizedEvidence = serde_json::from_value(invalid_code).unwrap();
        assert_eq!(
            invalid_code.validate().unwrap_err().field(),
            "observation.code"
        );

        let mut truncated_value = normalized;
        truncated_value.observations[0].value =
            RedactedText::new(&"x".repeat(4_097), 4_096).unwrap();
        assert_eq!(
            truncated_value.validate().unwrap_err().field(),
            "observation.value"
        );
    }

    #[test]
    fn post_is_not_allowed_for_probe_purpose() {
        let mut request = request(RequestPurpose::Probe);
        request.method = HttpMethod::Post;
        assert!(request.validate(&target()).is_err());
    }

    #[test]
    fn sensitive_query_values_must_be_redacted_before_recording() {
        let mut request = request(RequestPurpose::Probe);
        request.url = "https://example.com/api/orders?access_token=raw-secret".to_string();
        assert!(request.validate(&target()).is_err());

        request.url = "https://example.com/api/orders?access_token=%5BREDACTED%5D".to_string();
        assert!(request.validate(&target()).is_ok());
    }
}
