use std::collections::BTreeSet;
use std::fmt::{Debug, Display, Formatter};

use aegis_native_engine::{
    CanonicalFinding, Confidence, FindingIdentity, FindingProvenance, HttpMethod,
    ParameterLocation, Severity,
};
use url::Url;

const HARD_MAX_PROBES: usize = 16;
const HARD_MAX_BODY_VIEW_BYTES: usize = 65_536;
const HARD_MAX_HEADERS: usize = 64;
const HARD_MAX_HEADER_VALUE_BYTES: usize = 8_192;
const MAX_PATH_BYTES: usize = 2_048;
const RULE_VERSION: &str = "1.0.0";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ExposureProbeKind {
    EnvironmentFile,
    GitConfig,
    DebugPage,
    Actuator,
    AdminConsole,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CatalogEntry {
    path: &'static str,
    kind: ExposureProbeKind,
}

const CATALOG: [CatalogEntry; 9] = [
    CatalogEntry {
        path: "/.env",
        kind: ExposureProbeKind::EnvironmentFile,
    },
    CatalogEntry {
        path: "/.git/config",
        kind: ExposureProbeKind::GitConfig,
    },
    CatalogEntry {
        path: "/debug",
        kind: ExposureProbeKind::DebugPage,
    },
    CatalogEntry {
        path: "/__debug__",
        kind: ExposureProbeKind::DebugPage,
    },
    CatalogEntry {
        path: "/actuator",
        kind: ExposureProbeKind::Actuator,
    },
    CatalogEntry {
        path: "/actuator/env",
        kind: ExposureProbeKind::Actuator,
    },
    CatalogEntry {
        path: "/admin",
        kind: ExposureProbeKind::AdminConsole,
    },
    CatalogEntry {
        path: "/administrator",
        kind: ExposureProbeKind::AdminConsole,
    },
    CatalogEntry {
        path: "/manage",
        kind: ExposureProbeKind::AdminConsole,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExposureLimits {
    pub max_probes: usize,
    pub max_body_view_bytes: usize,
    pub max_headers: usize,
    pub max_header_value_bytes: usize,
}

impl Default for ExposureLimits {
    fn default() -> Self {
        Self {
            max_probes: 12,
            max_body_view_bytes: HARD_MAX_BODY_VIEW_BYTES,
            max_headers: HARD_MAX_HEADERS,
            max_header_value_bytes: HARD_MAX_HEADER_VALUE_BYTES,
        }
    }
}

impl ExposureLimits {
    fn validate(self) -> Result<(), ExposureRuntimeError> {
        if self.max_probes == 0
            || self.max_probes > HARD_MAX_PROBES
            || self.max_body_view_bytes == 0
            || self.max_body_view_bytes > HARD_MAX_BODY_VIEW_BYTES
            || self.max_headers == 0
            || self.max_headers > HARD_MAX_HEADERS
            || self.max_header_value_bytes == 0
            || self.max_header_value_bytes > HARD_MAX_HEADER_VALUE_BYTES
        {
            return Err(ExposureRuntimeError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExposureRuntimeError {
    InvalidLimits,
    InvalidPlan,
    InvalidPolicy,
    InvalidResponse,
    ContractViolation,
}

impl Display for ExposureRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "exposure detector limits are invalid",
            Self::InvalidPlan => "exposure probe plan is invalid",
            Self::InvalidPolicy => "exposure probe policy is invalid",
            Self::InvalidResponse => "exposure response view is invalid",
            Self::ContractViolation => "exposure finding contract could not be created",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ExposureRuntimeError {}

pub struct ExposurePlanContext<'a> {
    pub approved_path_prefix: &'a str,
}

impl Debug for ExposurePlanContext<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExposurePlanContext")
            .field(
                "approved_path_prefix_bytes",
                &self.approved_path_prefix.len(),
            )
            .finish()
    }
}

pub struct ExposureProbePolicy<'a> {
    /// Exact catalog-relative paths explicitly approved by the control plane.
    pub approved_catalog_paths: &'a [&'a str],
    pub enabled_kinds: &'a [ExposureProbeKind],
}

impl Debug for ExposureProbePolicy<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExposureProbePolicy")
            .field("approved_path_count", &self.approved_catalog_paths.len())
            .field("enabled_kind_count", &self.enabled_kinds.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ExposureProbe {
    probe_id: String,
    kind: ExposureProbeKind,
    catalog_path: &'static str,
    request_path: String,
}

impl ExposureProbe {
    pub fn probe_id(&self) -> &str {
        &self.probe_id
    }

    pub fn kind(&self) -> ExposureProbeKind {
        self.kind
    }

    pub fn catalog_path(&self) -> &'static str {
        self.catalog_path
    }

    pub fn request_path(&self) -> &str {
        &self.request_path
    }
}

impl Debug for ExposureProbe {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExposureProbe")
            .field("probe_id", &self.probe_id)
            .field("kind", &self.kind)
            .field("catalog_path", &self.catalog_path)
            .field("request_path_bytes", &self.request_path.len())
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ExposureHeader<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

impl Debug for ExposureHeader<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExposureHeader")
            .field("name", &self.name)
            .field("value_bytes", &self.value.len())
            .finish()
    }
}

pub struct ExposureResponse<'a> {
    pub target_id: &'a str,
    pub endpoint: &'a str,
    pub status_code: u16,
    pub headers: &'a [ExposureHeader<'a>],
    /// Bounded worker-local prefix. It is never copied into evidence.
    pub body_view: &'a [u8],
    pub body_view_truncated: bool,
    /// SHA-256 from the full bounded HTTP payload summary.
    pub payload_sha256: &'a str,
    pub baseline_status_code: u16,
    pub baseline_payload_sha256: &'a str,
    pub evidence_ref: &'a str,
}

impl Debug for ExposureResponse<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExposureResponse")
            .field("status_code", &self.status_code)
            .field("header_count", &self.headers.len())
            .field("body_view_bytes", &self.body_view.len())
            .field("body_view_truncated", &self.body_view_truncated)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExposureDecision {
    Candidate,
    NotExposed,
    Protected,
    Abstain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExposureSignal {
    EnvironmentAssignments,
    GitRepositoryConfig,
    DebugFrameworkPage,
    ActuatorIndex,
    ActuatorEnvironment,
    AdminLoginSurface,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExposureEvidence {
    pub status_code: u16,
    pub payload_sha256: String,
    pub body_view_truncated: bool,
    pub signal: Option<ExposureSignal>,
}

pub struct ExposureAssessment {
    pub decision: ExposureDecision,
    pub evidence: ExposureEvidence,
    pub finding: Option<CanonicalFinding>,
}

impl Debug for ExposureAssessment {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExposureAssessment")
            .field("decision", &self.decision)
            .field("evidence", &self.evidence)
            .field("has_finding", &self.finding.is_some())
            .finish()
    }
}

pub fn plan_exposure_probes(
    context: &ExposurePlanContext<'_>,
    policy: &ExposureProbePolicy<'_>,
    limits: ExposureLimits,
) -> Result<Vec<ExposureProbe>, ExposureRuntimeError> {
    limits.validate()?;
    validate_prefix(context.approved_path_prefix)?;
    if policy.approved_catalog_paths.is_empty()
        || policy.approved_catalog_paths.len() > CATALOG.len()
        || policy.enabled_kinds.is_empty()
    {
        return Err(ExposureRuntimeError::InvalidPolicy);
    }
    let approved = policy
        .approved_catalog_paths
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let enabled = policy
        .enabled_kinds
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if approved.len() != policy.approved_catalog_paths.len()
        || enabled.len() != policy.enabled_kinds.len()
        || approved
            .iter()
            .any(|path| !CATALOG.iter().any(|entry| entry.path == *path))
    {
        return Err(ExposureRuntimeError::InvalidPolicy);
    }
    let mut probes = Vec::new();
    for entry in CATALOG {
        if !approved.contains(entry.path) || !enabled.contains(&entry.kind) {
            continue;
        }
        if probes.len() >= limits.max_probes {
            return Err(ExposureRuntimeError::InvalidPolicy);
        }
        let request_path = join_prefix(context.approved_path_prefix, entry.path)?;
        probes.push(ExposureProbe {
            probe_id: format!("exposure-{:02}", probes.len() + 1),
            kind: entry.kind,
            catalog_path: entry.path,
            request_path,
        });
    }
    if probes.is_empty() {
        return Err(ExposureRuntimeError::InvalidPolicy);
    }
    Ok(probes)
}

pub fn assess_exposure_probe(
    probe: &ExposureProbe,
    response: &ExposureResponse<'_>,
    limits: ExposureLimits,
) -> Result<ExposureAssessment, ExposureRuntimeError> {
    limits.validate()?;
    validate_probe(probe)?;
    validate_response(response, limits)?;
    let endpoint =
        Url::parse(response.endpoint).map_err(|_| ExposureRuntimeError::InvalidResponse)?;
    if endpoint.path() != probe.request_path {
        return Err(ExposureRuntimeError::InvalidResponse);
    }
    let common_evidence = |signal| ExposureEvidence {
        status_code: response.status_code,
        payload_sha256: response.payload_sha256.to_string(),
        body_view_truncated: response.body_view_truncated,
        signal,
    };
    if response.status_code == response.baseline_status_code
        && response.payload_sha256 == response.baseline_payload_sha256
    {
        return Ok(ExposureAssessment {
            decision: ExposureDecision::NotExposed,
            evidence: common_evidence(None),
            finding: None,
        });
    }
    if matches!(response.status_code, 401 | 403) {
        return Ok(ExposureAssessment {
            decision: ExposureDecision::Protected,
            evidence: common_evidence(None),
            finding: None,
        });
    }
    if matches!(response.status_code, 404 | 410) {
        return Ok(ExposureAssessment {
            decision: ExposureDecision::NotExposed,
            evidence: common_evidence(None),
            finding: None,
        });
    }
    if response.status_code != 200 {
        return Ok(ExposureAssessment {
            decision: ExposureDecision::Abstain,
            evidence: common_evidence(None),
            finding: None,
        });
    }
    let signal = detect_signal(probe, response);
    let Some(signal) = signal else {
        return Ok(ExposureAssessment {
            decision: ExposureDecision::Abstain,
            evidence: common_evidence(None),
            finding: None,
        });
    };
    let finding = build_finding(probe, response)?;
    Ok(ExposureAssessment {
        decision: ExposureDecision::Candidate,
        evidence: common_evidence(Some(signal)),
        finding: Some(finding),
    })
}

fn detect_signal(probe: &ExposureProbe, response: &ExposureResponse<'_>) -> Option<ExposureSignal> {
    let content_type = response_content_type(response.headers);
    match probe.kind {
        ExposureProbeKind::EnvironmentFile => {
            if content_type.is_some_and(is_html_content_type) {
                return None;
            }
            let text = std::str::from_utf8(response.body_view).ok()?;
            let assignments = text
                .lines()
                .filter(|line| {
                    let line = line.trim();
                    !line.starts_with('#')
                        && line.split_once('=').is_some_and(|(name, _)| {
                            !name.is_empty()
                                && name.bytes().all(|byte| {
                                    byte.is_ascii_uppercase()
                                        || byte.is_ascii_digit()
                                        || byte == b'_'
                                })
                        })
                })
                .take(2)
                .count();
            (assignments >= 2).then_some(ExposureSignal::EnvironmentAssignments)
        }
        ExposureProbeKind::GitConfig => {
            if content_type.is_some_and(is_html_content_type) {
                return None;
            }
            (contains_ascii_case_insensitive(response.body_view, b"[core]")
                && contains_ascii_case_insensitive(response.body_view, b"repositoryformatversion"))
            .then_some(ExposureSignal::GitRepositoryConfig)
        }
        ExposureProbeKind::DebugPage => {
            if content_type.is_some_and(|value| !is_html_content_type(value)) {
                return None;
            }
            (contains_ascii_case_insensitive(response.body_view, b"debug toolbar")
                || contains_ascii_case_insensitive(response.body_view, b"werkzeug debugger")
                || contains_ascii_case_insensitive(response.body_view, b"django debug"))
            .then_some(ExposureSignal::DebugFrameworkPage)
        }
        ExposureProbeKind::Actuator if probe.catalog_path == "/actuator/env" => {
            if content_type.is_some_and(|value| !is_json_content_type(value)) {
                return None;
            }
            (contains_ascii_case_insensitive(response.body_view, b"propertysources")
                || contains_ascii_case_insensitive(response.body_view, b"activeprofiles"))
            .then_some(ExposureSignal::ActuatorEnvironment)
        }
        ExposureProbeKind::Actuator => {
            if content_type.is_some_and(|value| !is_json_content_type(value)) {
                return None;
            }
            (contains_ascii_case_insensitive(response.body_view, b"_links")
                && contains_ascii_case_insensitive(response.body_view, b"actuator"))
            .then_some(ExposureSignal::ActuatorIndex)
        }
        ExposureProbeKind::AdminConsole => {
            if content_type.is_some_and(|value| !is_html_content_type(value)) {
                return None;
            }
            let login = contains_ascii_case_insensitive(response.body_view, b"type=\"password\"")
                || contains_ascii_case_insensitive(response.body_view, b"name=\"password\"");
            let admin = contains_ascii_case_insensitive(response.body_view, b"admin")
                || contains_ascii_case_insensitive(response.body_view, b"administrator");
            (login && admin).then_some(ExposureSignal::AdminLoginSurface)
        }
    }
}

fn build_finding(
    probe: &ExposureProbe,
    response: &ExposureResponse<'_>,
) -> Result<CanonicalFinding, ExposureRuntimeError> {
    let (rule_id, weakness, title, severity) = match probe.kind {
        ExposureProbeKind::EnvironmentFile => (
            "aegis.exposure.sensitive-file.env",
            "CWE-538",
            "환경 설정 파일 노출 후보",
            Severity::High,
        ),
        ExposureProbeKind::GitConfig => (
            "aegis.exposure.sensitive-file.git",
            "CWE-538",
            "Git 저장소 설정 노출 후보",
            Severity::Medium,
        ),
        ExposureProbeKind::DebugPage => (
            "aegis.exposure.debug-page",
            "CWE-489",
            "Debug 기능 외부 노출 후보",
            Severity::Medium,
        ),
        ExposureProbeKind::Actuator => (
            "aegis.exposure.actuator",
            "CWE-215",
            "관리·환경 endpoint 노출 후보",
            Severity::Medium,
        ),
        ExposureProbeKind::AdminConsole => (
            "aegis.exposure.admin-console",
            "CWE-284",
            "관리자 로그인 표면 노출 후보",
            Severity::Low,
        ),
    };
    let identity = FindingIdentity::new(
        response.target_id,
        HttpMethod::Get,
        response.endpoint,
        weakness,
        ParameterLocation::Path,
        Some(probe.catalog_path.to_string()),
    )
    .map_err(|_| ExposureRuntimeError::ContractViolation)?;
    let finding_id = format!("native-{}", &identity.fingerprint()[..24]);
    CanonicalFinding::new(
        finding_id,
        identity,
        title,
        severity,
        Confidence::High,
        vec![response.evidence_ref.to_string()],
        FindingProvenance::new("native-passive", rule_id, RULE_VERSION)
            .map_err(|_| ExposureRuntimeError::ContractViolation)?,
    )
    .map_err(|_| ExposureRuntimeError::ContractViolation)
}

fn validate_prefix(prefix: &str) -> Result<(), ExposureRuntimeError> {
    if prefix.is_empty()
        || !prefix.starts_with('/')
        || prefix.len() > MAX_PATH_BYTES
        || prefix.contains(['\r', '\n', '\0', '?', '#'])
        || prefix.contains("..")
        || prefix.contains("//")
    {
        return Err(ExposureRuntimeError::InvalidPlan);
    }
    Ok(())
}

fn join_prefix(prefix: &str, catalog_path: &str) -> Result<String, ExposureRuntimeError> {
    let path = if prefix == "/" {
        catalog_path.to_string()
    } else {
        format!("{}{}", prefix.trim_end_matches('/'), catalog_path)
    };
    if path.len() > MAX_PATH_BYTES {
        return Err(ExposureRuntimeError::InvalidPlan);
    }
    Ok(path)
}

fn validate_probe(probe: &ExposureProbe) -> Result<(), ExposureRuntimeError> {
    let catalog = CATALOG
        .iter()
        .find(|entry| entry.path == probe.catalog_path && entry.kind == probe.kind)
        .ok_or(ExposureRuntimeError::InvalidPlan)?;
    if probe.probe_id.is_empty()
        || probe.probe_id.len() > 64
        || !probe
            .probe_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || !probe.request_path.ends_with(catalog.path)
        || probe.request_path.len() > MAX_PATH_BYTES
    {
        return Err(ExposureRuntimeError::InvalidPlan);
    }
    Ok(())
}

fn validate_response(
    response: &ExposureResponse<'_>,
    limits: ExposureLimits,
) -> Result<(), ExposureRuntimeError> {
    if !(100..=599).contains(&response.status_code)
        || !(100..=599).contains(&response.baseline_status_code)
        || response.headers.len() > limits.max_headers
        || response.body_view.len() > limits.max_body_view_bytes
        || !valid_sha256(response.payload_sha256)
        || !valid_sha256(response.baseline_payload_sha256)
        || response.evidence_ref.is_empty()
        || response.evidence_ref.len() > 64
    {
        return Err(ExposureRuntimeError::InvalidResponse);
    }
    FindingIdentity::new(
        response.target_id,
        HttpMethod::Get,
        response.endpoint,
        "CWE-538",
        ParameterLocation::Path,
        Some("/contract-validation".to_string()),
    )
    .map_err(|_| ExposureRuntimeError::InvalidResponse)?;
    let endpoint =
        Url::parse(response.endpoint).map_err(|_| ExposureRuntimeError::InvalidResponse)?;
    if endpoint.path().is_empty() || endpoint.query().is_some() || endpoint.fragment().is_some() {
        return Err(ExposureRuntimeError::InvalidResponse);
    }
    if !response
        .evidence_ref
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ExposureRuntimeError::InvalidResponse);
    }
    for header in response.headers {
        if header.name.is_empty()
            || header.name.len() > 128
            || !header
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || header.value.len() > limits.max_header_value_bytes
            || header.value.contains(['\r', '\n', '\0'])
        {
            return Err(ExposureRuntimeError::InvalidResponse);
        }
    }
    Ok(())
}

fn response_content_type<'a>(headers: &'a [ExposureHeader<'a>]) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-type"))
        .map(|header| header.value)
}

fn normalized_content_type(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase()
}

fn is_html_content_type(value: &str) -> bool {
    matches!(
        normalized_content_type(value).as_str(),
        "text/html" | "application/xhtml+xml"
    )
}

fn is_json_content_type(value: &str) -> bool {
    let value = normalized_content_type(value);
    value == "application/json" || value.ends_with("+json")
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.windows(needle.len()).any(|window| {
            window
                .iter()
                .zip(needle)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
        })
}

#[cfg(test)]
mod tests {
    use super::{
        assess_exposure_probe, plan_exposure_probes, ExposureDecision, ExposureLimits,
        ExposurePlanContext, ExposureProbeKind, ExposureProbePolicy, ExposureResponse,
        ExposureRuntimeError, ExposureSignal,
    };

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn response<'a>(endpoint: &'a str, status: u16, body: &'a [u8]) -> ExposureResponse<'a> {
        ExposureResponse {
            target_id: "target-1",
            endpoint,
            status_code: status,
            headers: &[],
            body_view: body,
            body_view_truncated: false,
            payload_sha256: HASH_A,
            baseline_status_code: 404,
            baseline_payload_sha256: HASH_B,
            evidence_ref: "evidence-1",
        }
    }

    fn probes() -> Vec<super::ExposureProbe> {
        plan_exposure_probes(
            &ExposurePlanContext {
                approved_path_prefix: "/app",
            },
            &ExposureProbePolicy {
                approved_catalog_paths: &["/.env", "/.git/config", "/admin"],
                enabled_kinds: &[
                    ExposureProbeKind::EnvironmentFile,
                    ExposureProbeKind::GitConfig,
                    ExposureProbeKind::AdminConsole,
                ],
            },
            ExposureLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn planner_intersects_exact_approval_catalog_and_scope() {
        let probes = probes();
        assert_eq!(probes.len(), 3);
        assert_eq!(probes[0].request_path, "/app/.env");
        assert_eq!(probes[1].request_path, "/app/.git/config");
        assert!(probes
            .iter()
            .all(|probe| probe.request_path.starts_with("/app/")));
        assert!(!format!(
            "{:?}",
            ExposurePlanContext {
                approved_path_prefix: "/private"
            }
        )
        .contains("/private"));
    }

    #[test]
    fn unapproved_or_traversal_plan_is_rejected() {
        assert!(plan_exposure_probes(
            &ExposurePlanContext {
                approved_path_prefix: "/app/../private",
            },
            &ExposureProbePolicy {
                approved_catalog_paths: &["/.env"],
                enabled_kinds: &[ExposureProbeKind::EnvironmentFile],
            },
            ExposureLimits::default(),
        )
        .is_err());
        assert!(plan_exposure_probes(
            &ExposurePlanContext {
                approved_path_prefix: "/",
            },
            &ExposureProbePolicy {
                approved_catalog_paths: &["/robots.txt"],
                enabled_kinds: &[ExposureProbeKind::EnvironmentFile],
            },
            ExposureLimits::default(),
        )
        .is_err());
    }

    #[test]
    fn sensitive_file_signal_creates_minimal_canonical_finding() {
        let probes = probes();
        let probe = &probes[0];
        let response = response(
            "https://example.com/app/.env",
            200,
            b"DB_HOST=localhost\nAPI_SECRET=must-not-leak\n",
        );
        let assessment =
            assess_exposure_probe(probe, &response, ExposureLimits::default()).unwrap();
        assert_eq!(assessment.decision, ExposureDecision::Candidate);
        assert_eq!(
            assessment.evidence.signal,
            Some(ExposureSignal::EnvironmentAssignments)
        );
        assert!(assessment.finding.as_ref().unwrap().validate().is_ok());
        let debug = format!("{response:?} {assessment:?}");
        assert!(!debug.contains("must-not-leak"));
        assert!(!debug.contains("example.com"));
    }

    #[test]
    fn baseline_protected_missing_and_ambiguous_responses_do_not_find() {
        let probes = probes();
        let probe = &probes[2];
        let mut same = response("https://example.com/app/admin", 404, b"soft 404");
        same.payload_sha256 = HASH_B;
        let assessment = assess_exposure_probe(probe, &same, ExposureLimits::default()).unwrap();
        assert_eq!(assessment.decision, ExposureDecision::NotExposed);
        let protected = response("https://example.com/app/admin", 401, b"");
        assert_eq!(
            assess_exposure_probe(probe, &protected, ExposureLimits::default())
                .unwrap()
                .decision,
            ExposureDecision::Protected
        );
        let ambiguous = response("https://example.com/app/admin", 200, b"generic home");
        assert_eq!(
            assess_exposure_probe(probe, &ambiguous, ExposureLimits::default())
                .unwrap()
                .decision,
            ExposureDecision::Abstain
        );
    }

    #[test]
    fn admin_signal_and_invalid_response_contract_are_bounded() {
        let probes = probes();
        let probe = &probes[2];
        let admin = response(
            "https://example.com/app/admin",
            200,
            br#"<h1>Admin Login</h1><input type="password">"#,
        );
        assert_eq!(
            assess_exposure_probe(probe, &admin, ExposureLimits::default())
                .unwrap()
                .decision,
            ExposureDecision::Candidate
        );
        let mut invalid = admin;
        invalid.payload_sha256 = "secret";
        assert!(matches!(
            assess_exposure_probe(probe, &invalid, ExposureLimits::default()),
            Err(ExposureRuntimeError::InvalidResponse)
        ));
        let wrong_endpoint = response(
            "https://example.com/app/other",
            200,
            br#"<h1>Admin Login</h1><input type="password">"#,
        );
        assert!(matches!(
            assess_exposure_probe(probe, &wrong_endpoint, ExposureLimits::default()),
            Err(ExposureRuntimeError::InvalidResponse)
        ));
    }
}
