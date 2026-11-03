use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{ContractError, HttpMethod, RedactedText};

/// Version prefix included in every canonical finding fingerprint.
pub const FINGERPRINT_VERSION: &str = "aegis.finding.v1";
const MAX_FINDING_TITLE_BYTES: usize = 255;
const MAX_WEAKNESS_KEY_BYTES: usize = 80;
const MAX_PARAMETER_NAME_BYTES: usize = 128;
const MAX_RULE_VERSION_BYTES: usize = 80;
const MAX_TIMELINE_OCCURRENCES: usize = 1_000;

/// Canonical risk severity independent of a scanner-specific label.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Confidence of the deterministic finding decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Location of the input or configuration element that caused a finding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterLocation {
    None,
    Path,
    Query,
    Header,
    Cookie,
    Form,
    JsonBody,
    ResponseHeader,
    ResponseBody,
    Transport,
}

impl ParameterLocation {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Path => "path",
            Self::Query => "query",
            Self::Header => "header",
            Self::Cookie => "cookie",
            Self::Form => "form",
            Self::JsonBody => "json_body",
            Self::ResponseHeader => "response_header",
            Self::ResponseBody => "response_body",
            Self::Transport => "transport",
        }
    }
}

/// Scanner-independent inputs used to generate a merge fingerprint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingIdentity {
    pub target_id: String,
    pub method: HttpMethod,
    pub canonical_endpoint: String,
    pub weakness_key: String,
    pub parameter_location: ParameterLocation,
    pub parameter_name: Option<String>,
}

impl FindingIdentity {
    /// Builds a validated identity and removes request values from the endpoint.
    pub fn new(
        target_id: impl Into<String>,
        method: HttpMethod,
        endpoint: &str,
        weakness_key: impl Into<String>,
        parameter_location: ParameterLocation,
        parameter_name: Option<String>,
    ) -> Result<Self, ContractError> {
        let target_id = target_id.into();
        validate_opaque("target_id", &target_id, 64)?;
        let weakness_key = weakness_key.into();
        validate_weakness_key(&weakness_key)?;
        let parameter_name = parameter_name
            .map(|name| validate_parameter_name(name, parameter_location))
            .transpose()?;
        if parameter_location == ParameterLocation::None && parameter_name.is_some() {
            return Err(ContractError::new(
                "parameter_name",
                "must be absent when parameter location is none",
            ));
        }
        if parameter_location != ParameterLocation::None && parameter_name.is_none() {
            return Err(ContractError::new(
                "parameter_name",
                "is required for a parameter-specific finding",
            ));
        }

        Ok(Self {
            target_id,
            method,
            canonical_endpoint: canonicalize_endpoint(endpoint)?,
            weakness_key,
            parameter_location,
            parameter_name,
        })
    }

    /// Computes a stable, scanner-independent SHA-256 merge fingerprint.
    pub fn fingerprint(&self) -> String {
        let method = method_name(self.method);
        let parameter_name = self.parameter_name.as_deref().unwrap_or("-");
        let input = format!(
            "{FINGERPRINT_VERSION}\n{}\n{method}\n{}\n{}\n{}\n{parameter_name}",
            self.target_id,
            self.canonical_endpoint,
            self.weakness_key,
            self.parameter_location.as_str()
        );
        hex_encode(&Sha256::digest(input.as_bytes()))
    }

    /// Revalidates canonical identity fields after deserialization.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_opaque("target_id", &self.target_id, 64)?;
        validate_weakness_key(&self.weakness_key)?;
        if canonicalize_endpoint(&self.canonical_endpoint)? != self.canonical_endpoint {
            return Err(ContractError::new(
                "canonical_endpoint",
                "must already be canonical and contain no request values",
            ));
        }
        match (&self.parameter_name, self.parameter_location) {
            (None, ParameterLocation::None) => Ok(()),
            (Some(value), location) if location != ParameterLocation::None => {
                if validate_parameter_name(value.clone(), location)? != *value {
                    return Err(ContractError::new(
                        "parameter_name",
                        "must already be normalized",
                    ));
                }
                Ok(())
            }
            _ => Err(ContractError::new(
                "parameter_name",
                "must agree with parameter location",
            )),
        }
    }
}

/// Provenance retained for audit and benchmark without affecting identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingProvenance {
    pub source_engine: String,
    pub rule_id: String,
    pub rule_version: String,
}

impl FindingProvenance {
    /// Creates bounded provenance. Source values are not part of the fingerprint.
    pub fn new(
        source_engine: impl Into<String>,
        rule_id: impl Into<String>,
        rule_version: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let provenance = Self {
            source_engine: source_engine.into(),
            rule_id: rule_id.into(),
            rule_version: rule_version.into(),
        };
        validate_opaque("source_engine", &provenance.source_engine, 40)?;
        validate_opaque("rule_id", &provenance.rule_id, 100)?;
        validate_opaque(
            "rule_version",
            &provenance.rule_version,
            MAX_RULE_VERSION_BYTES,
        )?;
        Ok(provenance)
    }

    /// Revalidates provenance after deserialization.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_opaque("source_engine", &self.source_engine, 40)?;
        validate_opaque("rule_id", &self.rule_id, 100)?;
        validate_opaque("rule_version", &self.rule_version, MAX_RULE_VERSION_BYTES)
    }
}

/// Canonical finding shared by native and imported scanner results.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalFinding {
    pub finding_id: String,
    pub identity: FindingIdentity,
    pub fingerprint: String,
    pub title: RedactedText,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence_refs: Vec<String>,
    pub provenance: FindingProvenance,
}

impl CanonicalFinding {
    /// Creates a finding and derives its fingerprint from canonical identity only.
    pub fn new(
        finding_id: impl Into<String>,
        identity: FindingIdentity,
        title: &str,
        severity: Severity,
        confidence: Confidence,
        evidence_refs: Vec<String>,
        provenance: FindingProvenance,
    ) -> Result<Self, ContractError> {
        let finding_id = finding_id.into();
        validate_opaque("finding_id", &finding_id, 64)?;
        validate_evidence_refs(&evidence_refs)?;
        let fingerprint = identity.fingerprint();
        Ok(Self {
            finding_id,
            identity,
            fingerprint,
            title: RedactedText::new(title, MAX_FINDING_TITLE_BYTES)?,
            severity,
            confidence,
            evidence_refs,
            provenance,
        })
    }

    /// Recomputes and verifies fingerprint and bounded references after deserialization.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_opaque("finding_id", &self.finding_id, 64)?;
        self.identity.validate()?;
        self.provenance.validate()?;
        validate_evidence_refs(&self.evidence_refs)?;
        if self.title.as_str().is_empty() || self.title.as_str().len() > MAX_FINDING_TITLE_BYTES {
            return Err(ContractError::new("title", "must be present and bounded"));
        }
        if self.fingerprint != self.identity.fingerprint() {
            return Err(ContractError::new(
                "fingerprint",
                "does not match canonical identity",
            ));
        }
        Ok(())
    }
}

/// Result of one bounded reproduction or revalidation attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReproductionOutcome {
    Reproduced,
    NotReproduced,
    Inconclusive,
    BlockedBySafetyPolicy,
}

/// Immutable occurrence appended to a canonical finding timeline.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingOccurrence {
    pub occurrence_id: String,
    pub scan_id: String,
    pub evidence_ref: String,
    pub outcome: ReproductionOutcome,
    pub observed_at: String,
    pub provenance: FindingProvenance,
}

impl FindingOccurrence {
    /// Validates bounded IDs and timestamp shape.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_opaque("occurrence_id", &self.occurrence_id, 64)?;
        validate_opaque("scan_id", &self.scan_id, 64)?;
        validate_opaque("evidence_ref", &self.evidence_ref, 64)?;
        validate_timestamp(&self.observed_at)?;
        self.provenance.validate()
    }
}

/// Ordered, duplicate-safe reproduction history for one fingerprint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingTimeline {
    pub fingerprint: String,
    pub occurrences: Vec<FindingOccurrence>,
}

impl FindingTimeline {
    /// Starts an empty timeline for a valid canonical finding.
    pub fn new(finding: &CanonicalFinding) -> Result<Self, ContractError> {
        finding.validate()?;
        Ok(Self {
            fingerprint: finding.fingerprint.clone(),
            occurrences: Vec::new(),
        })
    }

    /// Appends one immutable occurrence and rejects duplicate occurrence IDs.
    pub fn append(&mut self, occurrence: FindingOccurrence) -> Result<(), ContractError> {
        occurrence.validate()?;
        if self.occurrences.len() >= MAX_TIMELINE_OCCURRENCES {
            return Err(ContractError::new("occurrences", "timeline limit exceeded"));
        }
        if self
            .occurrences
            .iter()
            .any(|existing| existing.occurrence_id == occurrence.occurrence_id)
        {
            return Err(ContractError::new("occurrence_id", "duplicate occurrence"));
        }
        self.occurrences.push(occurrence);
        Ok(())
    }

    /// Revalidates bounds and duplicate occurrence IDs after deserialization.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.fingerprint.len() != 64
            || !self
                .fingerprint
                .bytes()
                .all(|value| value.is_ascii_hexdigit())
        {
            return Err(ContractError::new(
                "fingerprint",
                "must be a SHA-256 hexadecimal value",
            ));
        }
        if self.occurrences.len() > MAX_TIMELINE_OCCURRENCES {
            return Err(ContractError::new("occurrences", "timeline limit exceeded"));
        }
        let mut occurrence_ids = HashSet::with_capacity(self.occurrences.len());
        for occurrence in &self.occurrences {
            occurrence.validate()?;
            if !occurrence_ids.insert(&occurrence.occurrence_id) {
                return Err(ContractError::new("occurrence_id", "duplicate occurrence"));
            }
        }
        Ok(())
    }
}

fn canonicalize_endpoint(endpoint: &str) -> Result<String, ContractError> {
    if endpoint.len() > 2_048 || endpoint.contains(['\r', '\n']) {
        return Err(ContractError::new(
            "endpoint",
            "exceeds length limit or contains controls",
        ));
    }
    let url = Url::parse(endpoint)
        .map_err(|_| ContractError::new("endpoint", "must be an absolute URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ContractError::new(
            "endpoint",
            "must be a safe HTTP(S) URL without userinfo or fragment",
        ));
    }

    let host = url
        .host_str()
        .expect("validated URL must contain a host")
        .to_ascii_lowercase();
    let port = url
        .port()
        .map(|value| format!(":{value}"))
        .unwrap_or_default();
    let path = normalize_path(url.path());
    let mut query_names = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect::<Vec<_>>();
    query_names.sort();
    query_names.dedup();
    let query = if query_names.is_empty() {
        String::new()
    } else {
        format!("?{}", query_names.join("&"))
    };
    Ok(format!("{}://{host}{port}{path}{query}", url.scheme()))
}

fn normalize_path(path: &str) -> String {
    let uuid = uuid_segment_regex();
    let segments = path
        .split('/')
        .map(|segment| {
            if segment == "{id}"
                || segment.eq_ignore_ascii_case("%7Bid%7D")
                || (!segment.is_empty()
                    && (segment.bytes().all(|value| value.is_ascii_digit())
                        || uuid.is_match(segment)))
            {
                "{id}"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>();
    let normalized = segments.join("/");
    if normalized.is_empty() {
        "/".to_string()
    } else {
        normalized
    }
}

fn uuid_segment_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
            .expect("UUID segment regex must compile")
    })
}

fn validate_weakness_key(value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > MAX_WEAKNESS_KEY_BYTES
        || !value.bytes().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(ContractError::new(
            "weakness_key",
            "must be a bounded CWE or native rule family key",
        ));
    }
    Ok(())
}

fn validate_parameter_name(
    value: String,
    location: ParameterLocation,
) -> Result<String, ContractError> {
    let value = value.trim().to_string();
    if value.is_empty()
        || value.len() > MAX_PARAMETER_NAME_BYTES
        || value.contains(['\r', '\n', '\0'])
    {
        return Err(ContractError::new(
            "parameter_name",
            "must be present, bounded, and contain no controls",
        ));
    }
    let value = if matches!(
        location,
        ParameterLocation::Header | ParameterLocation::Cookie
    ) {
        value.to_ascii_lowercase()
    } else {
        value
    };
    Ok(value)
}

fn validate_evidence_refs(values: &[String]) -> Result<(), ContractError> {
    if values.is_empty() || values.len() > 16 {
        return Err(ContractError::new(
            "evidence_refs",
            "must contain one to 16 evidence references",
        ));
    }
    let mut unique = HashSet::with_capacity(values.len());
    for value in values {
        validate_opaque("evidence_ref", value, 64)?;
        if !unique.insert(value) {
            return Err(ContractError::new(
                "evidence_refs",
                "must not contain duplicates",
            ));
        }
    }
    Ok(())
}

fn validate_opaque(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > max_bytes
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

fn validate_timestamp(value: &str) -> Result<(), ContractError> {
    if value.len() < 20
        || value.len() > 40
        || !value.contains('T')
        || !(value.ends_with('Z') || value.contains('+'))
        || value.contains(['\r', '\n'])
    {
        return Err(ContractError::new(
            "observed_at",
            "must be a bounded RFC3339-shaped timestamp",
        ));
    }
    Ok(())
}

fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Head => "HEAD",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Post => "POST",
    }
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
        CanonicalFinding, Confidence, FindingIdentity, FindingOccurrence, FindingProvenance,
        FindingTimeline, ParameterLocation, ReproductionOutcome, Severity,
    };
    use crate::HttpMethod;

    fn identity(endpoint: &str, parameter_name: &str) -> FindingIdentity {
        FindingIdentity::new(
            "target-1",
            HttpMethod::Get,
            endpoint,
            "CWE-89",
            ParameterLocation::Query,
            Some(parameter_name.to_string()),
        )
        .unwrap()
    }

    fn provenance(source: &str) -> FindingProvenance {
        FindingProvenance::new(source, "sqli_error", "1.0.0").unwrap()
    }

    fn finding(source: &str) -> CanonicalFinding {
        CanonicalFinding::new(
            "finding-1",
            identity("https://example.com/api/users/123?id=1&sort=asc", "id"),
            "SQL injection candidate",
            Severity::High,
            Confidence::Medium,
            vec!["evidence-1".to_string()],
            provenance(source),
        )
        .unwrap()
    }

    #[test]
    fn fingerprint_ignores_query_values_order_and_dynamic_path_ids() {
        let first = identity("https://example.com/api/users/123?id=1&sort=asc", "id");
        let second = identity("https://example.com/api/users/456?sort=desc&id=999", "id");
        assert_eq!(first.canonical_endpoint, second.canonical_endpoint);
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert!(!first.canonical_endpoint.contains("999"));
        assert!(first.canonical_endpoint.ends_with("?id&sort"));
    }

    #[test]
    fn scanner_provenance_does_not_change_fingerprint() {
        let native = finding("aegis_native");
        let imported = finding("nuclei_import");
        assert_eq!(native.fingerprint, imported.fingerprint);
        assert_ne!(native.provenance, imported.provenance);
    }

    #[test]
    fn parameter_and_weakness_are_part_of_identity() {
        let first = identity("https://example.com/api/users/123?id=1", "id");
        let different_parameter = identity("https://example.com/api/users/123?id=1", "sort");
        let different_weakness = FindingIdentity::new(
            "target-1",
            HttpMethod::Get,
            "https://example.com/api/users/123?id=1",
            "CWE-79",
            ParameterLocation::Query,
            Some("id".to_string()),
        )
        .unwrap();
        assert_ne!(first.fingerprint(), different_parameter.fingerprint());
        assert_ne!(first.fingerprint(), different_weakness.fingerprint());
    }

    #[test]
    fn fingerprint_tampering_is_rejected_after_deserialization() {
        let mut tampered = finding("aegis_native");
        tampered.fingerprint = "0".repeat(64);
        assert!(tampered.validate().is_err());

        let mut noncanonical = finding("aegis_native");
        noncanonical.identity.canonical_endpoint =
            "https://example.com/api/users/{id}?id=secret&sort".to_string();
        noncanonical.fingerprint = noncanonical.identity.fingerprint();
        assert!(noncanonical.validate().is_err());
    }

    #[test]
    fn timeline_is_ordered_and_duplicate_safe() {
        let finding = finding("aegis_native");
        let mut timeline = FindingTimeline::new(&finding).unwrap();
        let occurrence = FindingOccurrence {
            occurrence_id: "occurrence-1".to_string(),
            scan_id: "scan-1".to_string(),
            evidence_ref: "evidence-1".to_string(),
            outcome: ReproductionOutcome::Reproduced,
            observed_at: "2026-07-16T13:00:00Z".to_string(),
            provenance: provenance("aegis_native"),
        };
        timeline.append(occurrence.clone()).unwrap();
        assert!(timeline.append(occurrence).is_err());
        assert_eq!(timeline.occurrences.len(), 1);
        assert!(timeline.validate().is_ok());
    }
}
