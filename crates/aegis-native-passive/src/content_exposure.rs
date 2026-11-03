use std::collections::BTreeSet;
use std::fmt::{Debug, Display, Formatter};

use aegis_native_engine::{
    CanonicalFinding, Confidence, FindingIdentity, FindingProvenance, HttpMethod,
    ParameterLocation, Severity,
};

use crate::PassiveHeader;

const HARD_MAX_BODY_VIEW_BYTES: usize = 65_536;
const HARD_MAX_HEADERS: usize = 128;
const HARD_MAX_HEADER_VALUE_BYTES: usize = 8_192;
const HARD_MAX_OBSERVATIONS: usize = 32;
const RULE_VERSION: &str = "1.0.0";
const REDACTED: &str = "[REDACTED]";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentExposureLimits {
    pub max_body_view_bytes: usize,
    pub max_headers: usize,
    pub max_header_value_bytes: usize,
    pub max_observations: usize,
}

impl Default for ContentExposureLimits {
    fn default() -> Self {
        Self {
            max_body_view_bytes: HARD_MAX_BODY_VIEW_BYTES,
            max_headers: HARD_MAX_HEADERS,
            max_header_value_bytes: HARD_MAX_HEADER_VALUE_BYTES,
            max_observations: HARD_MAX_OBSERVATIONS,
        }
    }
}

impl ContentExposureLimits {
    fn validate(self) -> Result<(), ContentExposureRuntimeError> {
        if self.max_body_view_bytes == 0
            || self.max_body_view_bytes > HARD_MAX_BODY_VIEW_BYTES
            || self.max_headers == 0
            || self.max_headers > HARD_MAX_HEADERS
            || self.max_header_value_bytes == 0
            || self.max_header_value_bytes > HARD_MAX_HEADER_VALUE_BYTES
            || self.max_observations == 0
            || self.max_observations > HARD_MAX_OBSERVATIONS
        {
            return Err(ContentExposureRuntimeError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentExposureRuntimeError {
    InvalidLimits,
    InvalidInput,
    ObservationLimitExceeded,
    ContractViolation,
}

impl Display for ContentExposureRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "content exposure limits are invalid",
            Self::InvalidInput => "content exposure response input is invalid",
            Self::ObservationLimitExceeded => "content exposure observation limit exceeded",
            Self::ContractViolation => "content exposure finding contract could not be created",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ContentExposureRuntimeError {}

pub struct ContentExposureContext<'a> {
    pub target_id: &'a str,
    pub endpoint: &'a str,
    pub method: HttpMethod,
    pub status_code: u16,
    pub headers: &'a [PassiveHeader<'a>],
    pub body_view: &'a [u8],
    pub body_view_truncated: bool,
    pub evidence_ref: &'a str,
}

impl Debug for ContentExposureContext<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContentExposureContext")
            .field("method", &self.method)
            .field("status_code", &self.status_code)
            .field("header_count", &self.headers.len())
            .field("body_view_bytes", &self.body_view.len())
            .field("body_view_truncated", &self.body_view_truncated)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ContentExposureSignal {
    VersionBanner,
    JavaStackTrace,
    PythonStackTrace,
    DotNetStackTrace,
    NodeStackTrace,
    PhpStackTrace,
    JwtLikeToken,
    AwsAccessKey,
    PrivateKey,
    GenericSecretAssignment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentExposureObservation {
    pub signal: ContentExposureSignal,
    pub location: ParameterLocation,
    pub parameter_name: String,
    pub redacted_value: &'static str,
}

pub struct ContentExposureAssessment {
    pub findings: Vec<CanonicalFinding>,
    pub observations: Vec<ContentExposureObservation>,
    pub body_view_truncated: bool,
}

impl Debug for ContentExposureAssessment {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContentExposureAssessment")
            .field("finding_count", &self.findings.len())
            .field("observations", &self.observations)
            .field("body_view_truncated", &self.body_view_truncated)
            .finish()
    }
}

pub fn assess_content_exposure(
    context: &ContentExposureContext<'_>,
    limits: ContentExposureLimits,
) -> Result<ContentExposureAssessment, ContentExposureRuntimeError> {
    limits.validate()?;
    validate_context(context, limits)?;
    let mut observations = Vec::new();
    let mut seen = BTreeSet::new();

    for header_name in ["server", "x-powered-by", "x-aspnet-version"] {
        if context.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case(header_name)
                && contains_version_number(header.value.as_bytes())
        }) {
            observe(
                &mut observations,
                &mut seen,
                ContentExposureSignal::VersionBanner,
                ParameterLocation::ResponseHeader,
                header_name,
                limits,
            )?;
        }
    }

    if body_is_textual(context.headers) {
        for signal in stack_trace_signals(context.body_view) {
            observe(
                &mut observations,
                &mut seen,
                signal,
                ParameterLocation::ResponseBody,
                "response-body",
                limits,
            )?;
        }
        for signal in secret_signals(context.body_view) {
            observe(
                &mut observations,
                &mut seen,
                signal,
                ParameterLocation::ResponseBody,
                "response-body",
                limits,
            )?;
        }
    }

    let mut findings = Vec::with_capacity(observations.len());
    let mut finding_keys = BTreeSet::new();
    for observation in &observations {
        let key = (
            finding_rule_id(observation.signal),
            location_key(observation.location),
            observation.parameter_name.clone(),
        );
        if finding_keys.insert(key) {
            findings.push(build_finding(context, observation)?);
        }
    }
    Ok(ContentExposureAssessment {
        findings,
        observations,
        body_view_truncated: context.body_view_truncated,
    })
}

fn observe(
    observations: &mut Vec<ContentExposureObservation>,
    seen: &mut BTreeSet<(ContentExposureSignal, u8, String)>,
    signal: ContentExposureSignal,
    location: ParameterLocation,
    parameter_name: &str,
    limits: ContentExposureLimits,
) -> Result<(), ContentExposureRuntimeError> {
    let key = (signal, location_key(location), parameter_name.to_string());
    if !seen.insert(key) {
        return Ok(());
    }
    if observations.len() >= limits.max_observations {
        return Err(ContentExposureRuntimeError::ObservationLimitExceeded);
    }
    observations.push(ContentExposureObservation {
        signal,
        location,
        parameter_name: parameter_name.to_string(),
        redacted_value: REDACTED,
    });
    Ok(())
}

fn location_key(location: ParameterLocation) -> u8 {
    match location {
        ParameterLocation::None => 0,
        ParameterLocation::Path => 1,
        ParameterLocation::Query => 2,
        ParameterLocation::Header => 3,
        ParameterLocation::Cookie => 4,
        ParameterLocation::Form => 5,
        ParameterLocation::JsonBody => 6,
        ParameterLocation::ResponseHeader => 7,
        ParameterLocation::ResponseBody => 8,
        ParameterLocation::Transport => 9,
    }
}

fn build_finding(
    context: &ContentExposureContext<'_>,
    observation: &ContentExposureObservation,
) -> Result<CanonicalFinding, ContentExposureRuntimeError> {
    let (rule_id, weakness, title, severity, confidence) = match observation.signal {
        ContentExposureSignal::VersionBanner => (
            "aegis.exposure.version-banner",
            "CWE-200",
            "제품·프레임워크 버전 정보 노출",
            Severity::Low,
            Confidence::High,
        ),
        ContentExposureSignal::JavaStackTrace
        | ContentExposureSignal::PythonStackTrace
        | ContentExposureSignal::DotNetStackTrace
        | ContentExposureSignal::NodeStackTrace
        | ContentExposureSignal::PhpStackTrace => (
            "aegis.exposure.stack-trace",
            "CWE-209",
            "상세 오류·Stack trace 노출",
            Severity::Medium,
            Confidence::High,
        ),
        ContentExposureSignal::JwtLikeToken
        | ContentExposureSignal::AwsAccessKey
        | ContentExposureSignal::PrivateKey => (
            "aegis.exposure.secret-pattern",
            "CWE-200",
            "비밀정보 형식 노출 후보",
            Severity::High,
            Confidence::High,
        ),
        ContentExposureSignal::GenericSecretAssignment => (
            "aegis.exposure.secret-assignment",
            "CWE-200",
            "비밀정보 할당 표현 노출 후보",
            Severity::High,
            Confidence::Medium,
        ),
    };
    let identity = FindingIdentity::new(
        context.target_id,
        context.method,
        context.endpoint,
        weakness,
        observation.location,
        Some(observation.parameter_name.clone()),
    )
    .map_err(|_| ContentExposureRuntimeError::ContractViolation)?;
    let finding_id = format!("native-{}", &identity.fingerprint()[..24]);
    CanonicalFinding::new(
        finding_id,
        identity,
        title,
        severity,
        confidence,
        vec![context.evidence_ref.to_string()],
        FindingProvenance::new("native-passive", rule_id, RULE_VERSION)
            .map_err(|_| ContentExposureRuntimeError::ContractViolation)?,
    )
    .map_err(|_| ContentExposureRuntimeError::ContractViolation)
}

fn finding_rule_id(signal: ContentExposureSignal) -> &'static str {
    match signal {
        ContentExposureSignal::VersionBanner => "aegis.exposure.version-banner",
        ContentExposureSignal::JavaStackTrace
        | ContentExposureSignal::PythonStackTrace
        | ContentExposureSignal::DotNetStackTrace
        | ContentExposureSignal::NodeStackTrace
        | ContentExposureSignal::PhpStackTrace => "aegis.exposure.stack-trace",
        ContentExposureSignal::JwtLikeToken
        | ContentExposureSignal::AwsAccessKey
        | ContentExposureSignal::PrivateKey => "aegis.exposure.secret-pattern",
        ContentExposureSignal::GenericSecretAssignment => "aegis.exposure.secret-assignment",
    }
}

fn validate_context(
    context: &ContentExposureContext<'_>,
    limits: ContentExposureLimits,
) -> Result<(), ContentExposureRuntimeError> {
    if !(100..=599).contains(&context.status_code)
        || context.headers.len() > limits.max_headers
        || context.body_view.len() > limits.max_body_view_bytes
        || context.evidence_ref.is_empty()
        || context.evidence_ref.len() > 64
        || !context
            .evidence_ref
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ContentExposureRuntimeError::InvalidInput);
    }
    FindingIdentity::new(
        context.target_id,
        context.method,
        context.endpoint,
        "CWE-200",
        ParameterLocation::ResponseBody,
        Some("contract-validation".to_string()),
    )
    .map_err(|_| ContentExposureRuntimeError::InvalidInput)?;
    for header in context.headers {
        if header.name.is_empty()
            || header.name.len() > 128
            || !header
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || header.value.len() > limits.max_header_value_bytes
            || header.value.contains(['\r', '\n', '\0'])
        {
            return Err(ContentExposureRuntimeError::InvalidInput);
        }
    }
    Ok(())
}

fn body_is_textual(headers: &[PassiveHeader<'_>]) -> bool {
    let content_type = headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-type"))
        .map(|header| {
            header
                .value
                .split(';')
                .next()
                .unwrap_or(header.value)
                .trim()
                .to_ascii_lowercase()
        });
    content_type.is_none_or(|value| {
        value.starts_with("text/")
            || value.contains("json")
            || value.contains("xml")
            || value.contains("javascript")
            || value == "application/x-www-form-urlencoded"
    })
}

fn contains_version_number(value: &[u8]) -> bool {
    value
        .windows(3)
        .any(|window| window[0].is_ascii_digit() && window[1] == b'.' && window[2].is_ascii_digit())
}

fn stack_trace_signals(body: &[u8]) -> Vec<ContentExposureSignal> {
    let mut signals = Vec::new();
    if contains_ci(body, b"java.lang.") && contains_ci(body, b"\tat ") {
        signals.push(ContentExposureSignal::JavaStackTrace);
    }
    if contains_ci(body, b"traceback (most recent call last)") && contains_ci(body, b"file \"") {
        signals.push(ContentExposureSignal::PythonStackTrace);
    }
    if contains_ci(body, b"system.") && contains_ci(body, b"stacktrace") {
        signals.push(ContentExposureSignal::DotNetStackTrace);
    }
    if contains_ci(body, b"error:") && contains_ci(body, b"\n    at ") {
        signals.push(ContentExposureSignal::NodeStackTrace);
    }
    if contains_ci(body, b"fatal error:") && contains_ci(body, b"stack trace:") {
        signals.push(ContentExposureSignal::PhpStackTrace);
    }
    signals
}

fn secret_signals(body: &[u8]) -> Vec<ContentExposureSignal> {
    let mut signals = Vec::new();
    if has_jwt_like_token(body) {
        signals.push(ContentExposureSignal::JwtLikeToken);
    }
    if has_aws_access_key(body) {
        signals.push(ContentExposureSignal::AwsAccessKey);
    }
    // These are detector markers, not embedded keys. Keep the exact runtime bytes.
    if contains_ci(body, concat!("-----be", "gin private key-----").as_bytes())
        || contains_ci(
            body,
            concat!("-----be", "gin rsa private key-----").as_bytes(),
        )
        || contains_ci(
            body,
            concat!("-----be", "gin ec private key-----").as_bytes(),
        )
    {
        signals.push(ContentExposureSignal::PrivateKey);
    }
    if has_generic_secret_assignment(body) {
        signals.push(ContentExposureSignal::GenericSecretAssignment);
    }
    signals
}

fn has_jwt_like_token(body: &[u8]) -> bool {
    body.split(|byte| {
        byte.is_ascii_whitespace()
            || matches!(byte, b'"' | b'\'' | b'<' | b'>' | b',' | b';' | b'=' | b':')
    })
    .filter(|token| token.len() >= 32 && token.len() <= 4_096)
    .any(|token| {
        let parts = token.split(|byte| *byte == b'.').collect::<Vec<_>>();
        parts.len() == 3
            && parts[0].starts_with(concat!("ey", "J").as_bytes())
            && parts.iter().all(|part| {
                !part.is_empty()
                    && part
                        .iter()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
    })
}

fn has_aws_access_key(body: &[u8]) -> bool {
    body.windows(20).enumerate().any(|(index, window)| {
        let before_is_key = index > 0 && body[index - 1].is_ascii_alphanumeric();
        let after_index = index + 20;
        let after_is_key = after_index < body.len() && body[after_index].is_ascii_alphanumeric();
        !before_is_key
            && !after_is_key
            && window.starts_with(concat!("AK", "IA").as_bytes())
            && window[4..]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
}

fn has_generic_secret_assignment(body: &[u8]) -> bool {
    [b"api_key".as_slice(), b"secret", b"token", b"password"]
        .iter()
        .any(|key| has_assignment_for_key(body, key))
}

fn has_assignment_for_key(body: &[u8], key: &[u8]) -> bool {
    let mut search_start = 0usize;
    while search_start + key.len() <= body.len() {
        let Some(relative_index) = find_ci(&body[search_start..], key) else {
            return false;
        };
        let index = search_start + relative_index;
        let mut cursor = index + key.len();
        while cursor < body.len()
            && (body[cursor].is_ascii_whitespace() || matches!(body[cursor], b'"' | b'\''))
        {
            cursor += 1;
        }
        if cursor < body.len() && matches!(body[cursor], b'=' | b':') {
            cursor += 1;
            while cursor < body.len()
                && (body[cursor].is_ascii_whitespace() || matches!(body[cursor], b'"' | b'\''))
            {
                cursor += 1;
            }
            let value_start = cursor;
            while cursor < body.len()
                && cursor - value_start <= 128
                && !body[cursor].is_ascii_whitespace()
                && !matches!(body[cursor], b'"' | b'\'' | b',' | b';' | b'<' | b'>')
            {
                cursor += 1;
            }
            let value = &body[value_start..cursor];
            if value.len() >= 8
                && value.len() <= 128
                && !contains_ci(value, b"redacted")
                && !contains_ci(value, b"placeholder")
                && !contains_ci(value, b"example")
                && value.windows(2).any(|pair| pair[0] != pair[1])
            {
                return true;
            }
        }
        search_start = index + 1;
    }
    false
}

fn find_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    find_ci(haystack, needle).is_some()
}

#[cfg(test)]
mod tests {
    use aegis_native_engine::HttpMethod;

    use super::{
        assess_content_exposure, ContentExposureContext, ContentExposureLimits,
        ContentExposureRuntimeError, ContentExposureSignal,
    };
    use crate::PassiveHeader;

    fn context<'a>(headers: &'a [PassiveHeader<'a>], body: &'a [u8]) -> ContentExposureContext<'a> {
        ContentExposureContext {
            target_id: "target-1",
            endpoint: "https://example.com/api?token=must-not-leak",
            method: HttpMethod::Get,
            status_code: 500,
            headers,
            body_view: body,
            body_view_truncated: false,
            evidence_ref: "evidence-1",
        }
    }

    #[test]
    fn version_banner_and_stack_trace_create_redacted_findings() {
        let headers = [
            PassiveHeader {
                name: "Content-Type",
                value: "text/plain",
            },
            PassiveHeader {
                name: "Server",
                value: "ExampleServer/1.2.3",
            },
        ];
        let body = b"java.lang.IllegalStateException\n\tat com.example.App.run(App.java:10)";
        let assessment =
            assess_content_exposure(&context(&headers, body), ContentExposureLimits::default())
                .unwrap();
        assert_eq!(assessment.findings.len(), 2);
        assert!(assessment
            .findings
            .iter()
            .all(|finding| finding.validate().is_ok()));
        assert!(assessment
            .observations
            .iter()
            .all(|observation| observation.redacted_value == "[REDACTED]"));
        let debug = format!("{assessment:?}");
        assert!(!debug.contains("ExampleServer"));
        assert!(!debug.contains("com.example"));
    }

    #[test]
    fn jwt_aws_private_key_and_assignment_values_never_enter_output() {
        let headers = [PassiveHeader {
            name: "Content-Type",
            value: "application/json",
        }];
        let body = concat!(
            "token=ey",
            "JhbGciOiJIUzI1NiJ9.ey",
            "JzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl AK",
            "IAABCDEFGHIJKLMNOP -----BEGIN PRIVATE KEY----- api_key=super-secret-value"
        )
        .as_bytes();
        let assessment =
            assess_content_exposure(&context(&headers, body), ContentExposureLimits::default())
                .unwrap();
        let signals = assessment
            .observations
            .iter()
            .map(|observation| observation.signal)
            .collect::<Vec<_>>();
        assert!(signals.contains(&ContentExposureSignal::JwtLikeToken));
        assert!(signals.contains(&ContentExposureSignal::AwsAccessKey));
        assert!(signals.contains(&ContentExposureSignal::PrivateKey));
        assert!(signals.contains(&ContentExposureSignal::GenericSecretAssignment));
        let debug = format!("{:?} {assessment:?}", context(&headers, body));
        assert!(!debug.contains("super-secret-value"));
        assert!(!debug.contains("AKIA"));
        assert!(!debug.contains("eyJ"));
    }

    #[test]
    fn binary_content_and_placeholder_assignment_do_not_find() {
        let binary = [PassiveHeader {
            name: "Content-Type",
            value: "application/octet-stream",
        }];
        let assessment = assess_content_exposure(
            &context(&binary, b"password=real-looking-secret"),
            ContentExposureLimits::default(),
        )
        .unwrap();
        assert!(assessment.findings.is_empty());
        let text = [PassiveHeader {
            name: "Content-Type",
            value: "text/plain",
        }];
        let assessment = assess_content_exposure(
            &context(&text, b"password=example-placeholder"),
            ContentExposureLimits::default(),
        )
        .unwrap();
        assert!(assessment.findings.is_empty());
    }

    #[test]
    fn duplicate_signals_are_deduplicated() {
        let headers = [
            PassiveHeader {
                name: "Server",
                value: "one/1.0",
            },
            PassiveHeader {
                name: "X-Powered-By",
                value: "two/2.0",
            },
        ];
        let assessment =
            assess_content_exposure(&context(&headers, b""), ContentExposureLimits::default())
                .unwrap();
        assert_eq!(assessment.observations.len(), 2);
        assert!(assessment
            .observations
            .iter()
            .all(|observation| { observation.signal == ContentExposureSignal::VersionBanner }));
    }

    #[test]
    fn invalid_context_and_limits_fail_closed() {
        let headers = [PassiveHeader {
            name: "Server",
            value: "bad\r\nInjected: 1.0",
        }];
        assert!(matches!(
            assess_content_exposure(&context(&headers, b""), ContentExposureLimits::default(),),
            Err(ContentExposureRuntimeError::InvalidInput)
        ));
        assert!(assess_content_exposure(
            &context(&[], b""),
            ContentExposureLimits {
                max_observations: 0,
                ..ContentExposureLimits::default()
            },
        )
        .is_err());
    }
}
