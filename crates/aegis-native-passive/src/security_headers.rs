use std::collections::BTreeSet;
use std::fmt::{Debug, Display, Formatter};

use aegis_native_engine::{
    CanonicalFinding, Confidence, FindingIdentity, FindingProvenance, HttpMethod,
    ParameterLocation, Severity,
};
use sha2::{Digest, Sha256};

const HARD_MAX_HEADERS: usize = 128;
const HARD_MAX_HEADER_VALUE_BYTES: usize = 8_192;
const HARD_MAX_COOKIES: usize = 64;
const HARD_MAX_FINDINGS: usize = 256;
const HARD_MAX_WARNINGS: usize = 64;
const MAX_EXCEPTION_NAMES: usize = 64;
const MAX_COOKIE_NAME_BYTES: usize = 256;
const DEFAULT_HSTS_MAX_AGE: u64 = 31_536_000;
const RULE_VERSION: &str = "1.0.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityHeaderLimits {
    pub max_headers: usize,
    pub max_header_value_bytes: usize,
    pub max_cookies: usize,
    pub max_findings: usize,
    pub max_warnings: usize,
}

impl Default for SecurityHeaderLimits {
    fn default() -> Self {
        Self {
            max_headers: HARD_MAX_HEADERS,
            max_header_value_bytes: HARD_MAX_HEADER_VALUE_BYTES,
            max_cookies: HARD_MAX_COOKIES,
            max_findings: HARD_MAX_FINDINGS,
            max_warnings: HARD_MAX_WARNINGS,
        }
    }
}

impl SecurityHeaderLimits {
    fn validate(self) -> Result<(), SecurityHeaderRuntimeError> {
        if self.max_headers == 0
            || self.max_headers > HARD_MAX_HEADERS
            || self.max_header_value_bytes == 0
            || self.max_header_value_bytes > HARD_MAX_HEADER_VALUE_BYTES
            || self.max_cookies == 0
            || self.max_cookies > HARD_MAX_COOKIES
            || self.max_findings == 0
            || self.max_findings > HARD_MAX_FINDINGS
            || self.max_warnings == 0
            || self.max_warnings > HARD_MAX_WARNINGS
        {
            return Err(SecurityHeaderRuntimeError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityHeaderRuntimeError {
    InvalidLimits,
    InvalidInput,
    InvalidPolicy,
    FindingLimitExceeded,
    ContractViolation,
}

impl Display for SecurityHeaderRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "security header limits are invalid",
            Self::InvalidInput => "security header response input is invalid",
            Self::InvalidPolicy => "security header policy is invalid",
            Self::FindingLimitExceeded => "security header finding limit exceeded",
            Self::ContractViolation => "security header finding contract could not be created",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SecurityHeaderRuntimeError {}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PassiveHeader<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

impl Debug for PassiveHeader<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PassiveHeader")
            .field("name", &self.name)
            .field("value_bytes", &self.value.len())
            .finish()
    }
}

pub struct SecurityHeaderContext<'a> {
    pub target_id: &'a str,
    pub endpoint: &'a str,
    pub method: HttpMethod,
    pub status_code: u16,
    pub headers: &'a [PassiveHeader<'a>],
    pub evidence_ref: &'a str,
}

impl Debug for SecurityHeaderContext<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecurityHeaderContext")
            .field("method", &self.method)
            .field("status_code", &self.status_code)
            .field("header_count", &self.headers.len())
            .finish()
    }
}

pub struct SecurityHeaderPolicy<'a> {
    pub hsts_min_max_age: u64,
    pub require_hsts_include_subdomains: bool,
    pub script_readable_cookie_exceptions: &'a [&'a str],
    pub cross_site_cookie_exceptions: &'a [&'a str],
}

impl Default for SecurityHeaderPolicy<'static> {
    fn default() -> Self {
        Self {
            hsts_min_max_age: DEFAULT_HSTS_MAX_AGE,
            require_hsts_include_subdomains: false,
            script_readable_cookie_exceptions: &[],
            cross_site_cookie_exceptions: &[],
        }
    }
}

impl Debug for SecurityHeaderPolicy<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecurityHeaderPolicy")
            .field("hsts_min_max_age", &self.hsts_min_max_age)
            .field(
                "require_hsts_include_subdomains",
                &self.require_hsts_include_subdomains,
            )
            .field(
                "script_readable_cookie_exception_count",
                &self.script_readable_cookie_exceptions.len(),
            )
            .field(
                "cross_site_cookie_exception_count",
                &self.cross_site_cookie_exceptions.len(),
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderInspectionWarningKind {
    MalformedSetCookie,
    DuplicateCookieAttribute,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderInspectionWarning {
    pub kind: HeaderInspectionWarningKind,
    pub cookie_identity: Option<String>,
}

pub struct SecurityHeaderAssessment {
    pub findings: Vec<CanonicalFinding>,
    pub warnings: Vec<HeaderInspectionWarning>,
    pub inspected_cookie_count: usize,
}

impl Debug for SecurityHeaderAssessment {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecurityHeaderAssessment")
            .field("finding_count", &self.findings.len())
            .field("warning_count", &self.warnings.len())
            .field("inspected_cookie_count", &self.inspected_cookie_count)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeaderIssue {
    MissingContentSecurityPolicy,
    MissingFrameProtection,
    MissingContentTypeOptions,
    MissingStrictTransportSecurity,
    WeakStrictTransportSecurity,
    CookieMissingSecure,
    CookieMissingHttpOnly,
    CookieMissingSameSite,
    CookieUnapprovedCrossSite,
    CookieSameSiteNoneWithoutSecure,
    CookieHostPrefixInvalid,
    CookieSecurePrefixInvalid,
}

impl HeaderIssue {
    fn rule_id(self) -> &'static str {
        match self {
            Self::MissingContentSecurityPolicy => "aegis.config.header.csp",
            Self::MissingFrameProtection => "aegis.config.header.frame-protection",
            Self::MissingContentTypeOptions => "aegis.config.header.nosniff",
            Self::MissingStrictTransportSecurity | Self::WeakStrictTransportSecurity => {
                "aegis.config.header.hsts"
            }
            Self::CookieMissingSecure => "aegis.config.cookie.secure",
            Self::CookieMissingHttpOnly => "aegis.config.cookie.httponly",
            Self::CookieMissingSameSite
            | Self::CookieUnapprovedCrossSite
            | Self::CookieSameSiteNoneWithoutSecure => "aegis.config.cookie.samesite",
            Self::CookieHostPrefixInvalid => "aegis.config.cookie.host-prefix",
            Self::CookieSecurePrefixInvalid => "aegis.config.cookie.secure-prefix",
        }
    }

    fn weakness(self) -> &'static str {
        match self {
            Self::MissingFrameProtection => "CWE-1021",
            Self::CookieMissingSecure => "CWE-614",
            Self::CookieMissingHttpOnly => "CWE-1004",
            Self::CookieMissingSameSite
            | Self::CookieUnapprovedCrossSite
            | Self::CookieSameSiteNoneWithoutSecure => "CWE-1275",
            Self::MissingStrictTransportSecurity | Self::WeakStrictTransportSecurity => "CWE-319",
            Self::MissingContentSecurityPolicy
            | Self::MissingContentTypeOptions
            | Self::CookieHostPrefixInvalid
            | Self::CookieSecurePrefixInvalid => "CWE-693",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::MissingContentSecurityPolicy => "Content-Security-Policy 헤더 누락",
            Self::MissingFrameProtection => "프레임 삽입 방어 헤더 누락",
            Self::MissingContentTypeOptions => "X-Content-Type-Options nosniff 누락",
            Self::MissingStrictTransportSecurity => "Strict-Transport-Security 헤더 누락",
            Self::WeakStrictTransportSecurity => "Strict-Transport-Security 정책이 기준보다 약함",
            Self::CookieMissingSecure => "Cookie Secure 속성 누락",
            Self::CookieMissingHttpOnly => "Cookie HttpOnly 속성 누락",
            Self::CookieMissingSameSite => "Cookie SameSite 속성 누락 또는 오류",
            Self::CookieUnapprovedCrossSite => "승인되지 않은 cross-site Cookie",
            Self::CookieSameSiteNoneWithoutSecure => "SameSite=None Cookie의 Secure 속성 누락",
            Self::CookieHostPrefixInvalid => "__Host- Cookie prefix 계약 위반",
            Self::CookieSecurePrefixInvalid => "__Secure- Cookie prefix 계약 위반",
        }
    }

    fn severity(self) -> Severity {
        match self {
            Self::MissingContentSecurityPolicy
            | Self::MissingFrameProtection
            | Self::CookieMissingSecure
            | Self::CookieSameSiteNoneWithoutSecure
            | Self::CookieHostPrefixInvalid
            | Self::CookieSecurePrefixInvalid => Severity::Medium,
            Self::MissingContentTypeOptions
            | Self::MissingStrictTransportSecurity
            | Self::WeakStrictTransportSecurity
            | Self::CookieMissingHttpOnly
            | Self::CookieMissingSameSite
            | Self::CookieUnapprovedCrossSite => Severity::Low,
        }
    }

    fn confidence(self) -> Confidence {
        match self {
            Self::WeakStrictTransportSecurity | Self::CookieUnapprovedCrossSite => {
                Confidence::Medium
            }
            _ => Confidence::High,
        }
    }
}

struct ParsedCookie {
    name: String,
    identity: String,
    secure: bool,
    http_only: bool,
    same_site: Option<String>,
    path: Option<String>,
    has_domain: bool,
    duplicate_attribute: bool,
}

pub fn assess_security_headers(
    context: &SecurityHeaderContext<'_>,
    policy: &SecurityHeaderPolicy<'_>,
    limits: SecurityHeaderLimits,
) -> Result<SecurityHeaderAssessment, SecurityHeaderRuntimeError> {
    limits.validate()?;
    validate_context(context, limits)?;
    validate_policy(policy)?;

    let is_https = context.endpoint.starts_with("https://");
    let response_content_type = content_type(context.headers);
    let is_html = response_content_type.is_some_and(is_html_content_type);
    let nosniff_relevant = response_content_type.is_some_and(is_nosniff_relevant);
    let eligible_status = (200..400).contains(&context.status_code);
    let mut findings = Vec::new();
    let mut warnings = Vec::new();

    if eligible_status && is_html {
        if !has_nonempty_header(context.headers, "content-security-policy") {
            push_finding(
                &mut findings,
                context,
                HeaderIssue::MissingContentSecurityPolicy,
                ParameterLocation::ResponseHeader,
                "content-security-policy",
                limits,
            )?;
        }
        if !has_frame_protection(context.headers) {
            push_finding(
                &mut findings,
                context,
                HeaderIssue::MissingFrameProtection,
                ParameterLocation::ResponseHeader,
                "frame-protection",
                limits,
            )?;
        }
    }
    if eligible_status
        && nosniff_relevant
        && !has_exact_token(context.headers, "x-content-type-options", "nosniff")
    {
        push_finding(
            &mut findings,
            context,
            HeaderIssue::MissingContentTypeOptions,
            ParameterLocation::ResponseHeader,
            "x-content-type-options",
            limits,
        )?;
    }
    if eligible_status && is_https {
        match hsts_strength(context.headers, policy) {
            HstsStrength::Missing => push_finding(
                &mut findings,
                context,
                HeaderIssue::MissingStrictTransportSecurity,
                ParameterLocation::ResponseHeader,
                "strict-transport-security",
                limits,
            )?,
            HstsStrength::Weak => push_finding(
                &mut findings,
                context,
                HeaderIssue::WeakStrictTransportSecurity,
                ParameterLocation::ResponseHeader,
                "strict-transport-security",
                limits,
            )?,
            HstsStrength::Sufficient => {}
        }
    }

    let set_cookie_values = header_values(context.headers, "set-cookie");
    if set_cookie_values.len() > limits.max_cookies {
        return Err(SecurityHeaderRuntimeError::InvalidInput);
    }
    let mut inspected_cookie_count = 0usize;
    for value in set_cookie_values {
        let Some(cookie) = parse_set_cookie(value) else {
            push_warning(
                &mut warnings,
                HeaderInspectionWarning {
                    kind: HeaderInspectionWarningKind::MalformedSetCookie,
                    cookie_identity: None,
                },
                limits,
            );
            continue;
        };
        inspected_cookie_count += 1;
        if cookie.duplicate_attribute {
            push_warning(
                &mut warnings,
                HeaderInspectionWarning {
                    kind: HeaderInspectionWarningKind::DuplicateCookieAttribute,
                    cookie_identity: Some(cookie.identity.clone()),
                },
                limits,
            );
        }
        inspect_cookie(&cookie, context, policy, &mut findings, limits)?;
    }

    Ok(SecurityHeaderAssessment {
        findings,
        warnings,
        inspected_cookie_count,
    })
}

fn inspect_cookie(
    cookie: &ParsedCookie,
    context: &SecurityHeaderContext<'_>,
    policy: &SecurityHeaderPolicy<'_>,
    findings: &mut Vec<CanonicalFinding>,
    limits: SecurityHeaderLimits,
) -> Result<(), SecurityHeaderRuntimeError> {
    if !cookie.secure {
        push_cookie_finding(
            findings,
            context,
            cookie,
            HeaderIssue::CookieMissingSecure,
            limits,
        )?;
    }
    if !cookie.http_only
        && !policy
            .script_readable_cookie_exceptions
            .contains(&cookie.name.as_str())
    {
        push_cookie_finding(
            findings,
            context,
            cookie,
            HeaderIssue::CookieMissingHttpOnly,
            limits,
        )?;
    }
    match cookie.same_site.as_deref() {
        Some("lax" | "strict") => {}
        Some("none") => {
            if !cookie.secure {
                push_cookie_finding(
                    findings,
                    context,
                    cookie,
                    HeaderIssue::CookieSameSiteNoneWithoutSecure,
                    limits,
                )?;
            }
            if !policy
                .cross_site_cookie_exceptions
                .contains(&cookie.name.as_str())
            {
                push_cookie_finding(
                    findings,
                    context,
                    cookie,
                    HeaderIssue::CookieUnapprovedCrossSite,
                    limits,
                )?;
            }
        }
        _ => push_cookie_finding(
            findings,
            context,
            cookie,
            HeaderIssue::CookieMissingSameSite,
            limits,
        )?,
    }
    if cookie.name.starts_with("__Host-")
        && (!cookie.secure || cookie.has_domain || cookie.path.as_deref() != Some("/"))
    {
        push_cookie_finding(
            findings,
            context,
            cookie,
            HeaderIssue::CookieHostPrefixInvalid,
            limits,
        )?;
    }
    if cookie.name.starts_with("__Secure-") && !cookie.secure {
        push_cookie_finding(
            findings,
            context,
            cookie,
            HeaderIssue::CookieSecurePrefixInvalid,
            limits,
        )?;
    }
    Ok(())
}

fn push_cookie_finding(
    findings: &mut Vec<CanonicalFinding>,
    context: &SecurityHeaderContext<'_>,
    cookie: &ParsedCookie,
    issue: HeaderIssue,
    limits: SecurityHeaderLimits,
) -> Result<(), SecurityHeaderRuntimeError> {
    push_finding(
        findings,
        context,
        issue,
        ParameterLocation::Cookie,
        &cookie.identity,
        limits,
    )
}

fn push_finding(
    findings: &mut Vec<CanonicalFinding>,
    context: &SecurityHeaderContext<'_>,
    issue: HeaderIssue,
    location: ParameterLocation,
    parameter_name: &str,
    limits: SecurityHeaderLimits,
) -> Result<(), SecurityHeaderRuntimeError> {
    if findings.len() >= limits.max_findings {
        return Err(SecurityHeaderRuntimeError::FindingLimitExceeded);
    }
    let identity = FindingIdentity::new(
        context.target_id,
        context.method,
        context.endpoint,
        issue.weakness(),
        location,
        Some(parameter_name.to_string()),
    )
    .map_err(|_| SecurityHeaderRuntimeError::ContractViolation)?;
    let finding_id = format!("native-{}", &identity.fingerprint()[..24]);
    let provenance = FindingProvenance::new("native-passive", issue.rule_id(), RULE_VERSION)
        .map_err(|_| SecurityHeaderRuntimeError::ContractViolation)?;
    let finding = CanonicalFinding::new(
        finding_id,
        identity,
        issue.title(),
        issue.severity(),
        issue.confidence(),
        vec![context.evidence_ref.to_string()],
        provenance,
    )
    .map_err(|_| SecurityHeaderRuntimeError::ContractViolation)?;
    findings.push(finding);
    Ok(())
}

fn push_warning(
    warnings: &mut Vec<HeaderInspectionWarning>,
    warning: HeaderInspectionWarning,
    limits: SecurityHeaderLimits,
) {
    if warnings.len() < limits.max_warnings {
        warnings.push(warning);
    }
}

fn validate_context(
    context: &SecurityHeaderContext<'_>,
    limits: SecurityHeaderLimits,
) -> Result<(), SecurityHeaderRuntimeError> {
    if context.headers.len() > limits.max_headers
        || !(100..=599).contains(&context.status_code)
        || context.target_id.is_empty()
        || context.target_id.len() > 64
        || context.evidence_ref.is_empty()
        || context.evidence_ref.len() > 64
        || !(context.endpoint.starts_with("http://") || context.endpoint.starts_with("https://"))
    {
        return Err(SecurityHeaderRuntimeError::InvalidInput);
    }
    FindingIdentity::new(
        context.target_id,
        context.method,
        context.endpoint,
        "CWE-693",
        ParameterLocation::ResponseHeader,
        Some("contract-validation".to_string()),
    )
    .map_err(|_| SecurityHeaderRuntimeError::InvalidInput)?;
    if !context
        .evidence_ref
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(SecurityHeaderRuntimeError::InvalidInput);
    }
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
            return Err(SecurityHeaderRuntimeError::InvalidInput);
        }
    }
    Ok(())
}

fn validate_policy(policy: &SecurityHeaderPolicy<'_>) -> Result<(), SecurityHeaderRuntimeError> {
    if policy.hsts_min_max_age == 0
        || policy.hsts_min_max_age > u64::from(u32::MAX)
        || policy.script_readable_cookie_exceptions.len() > MAX_EXCEPTION_NAMES
        || policy.cross_site_cookie_exceptions.len() > MAX_EXCEPTION_NAMES
    {
        return Err(SecurityHeaderRuntimeError::InvalidPolicy);
    }
    for exceptions in [
        policy.script_readable_cookie_exceptions,
        policy.cross_site_cookie_exceptions,
    ] {
        let mut names = BTreeSet::new();
        for name in exceptions {
            if !valid_cookie_name(name) || !names.insert(*name) {
                return Err(SecurityHeaderRuntimeError::InvalidPolicy);
            }
        }
    }
    Ok(())
}

fn content_type<'a>(headers: &'a [PassiveHeader<'a>]) -> Option<&'a str> {
    header_values(headers, "content-type").into_iter().next()
}

fn is_html_content_type(value: &str) -> bool {
    matches!(
        value
            .split(';')
            .next()
            .unwrap_or(value)
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "text/html" | "application/xhtml+xml"
    )
}

fn is_nosniff_relevant(value: &str) -> bool {
    let content_type = value
        .split(';')
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase();
    matches!(
        content_type.as_str(),
        "text/html"
            | "application/xhtml+xml"
            | "text/css"
            | "application/javascript"
            | "text/javascript"
            | "application/json"
            | "application/xml"
            | "text/xml"
            | "image/svg+xml"
    ) || content_type.ends_with("+json")
        || content_type.ends_with("+xml")
}

fn header_values<'a>(headers: &'a [PassiveHeader<'a>], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value)
        .collect()
}

fn has_exact_token(headers: &[PassiveHeader<'_>], name: &str, expected: &str) -> bool {
    header_values(headers, name)
        .iter()
        .any(|value| value.trim().eq_ignore_ascii_case(expected))
}

fn has_nonempty_header(headers: &[PassiveHeader<'_>], name: &str) -> bool {
    header_values(headers, name)
        .iter()
        .any(|value| !value.trim().is_empty())
}

fn has_frame_protection(headers: &[PassiveHeader<'_>]) -> bool {
    let x_frame_options = header_values(headers, "x-frame-options")
        .iter()
        .any(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "deny" | "sameorigin"
            )
        });
    let csp_frame_ancestors = header_values(headers, "content-security-policy")
        .iter()
        .any(|value| {
            value.split(';').any(|directive| {
                directive
                    .split_ascii_whitespace()
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case("frame-ancestors"))
            })
        });
    x_frame_options || csp_frame_ancestors
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HstsStrength {
    Missing,
    Weak,
    Sufficient,
}

fn hsts_strength(headers: &[PassiveHeader<'_>], policy: &SecurityHeaderPolicy<'_>) -> HstsStrength {
    let values = header_values(headers, "strict-transport-security");
    if values.is_empty() {
        return HstsStrength::Missing;
    }
    if values.len() == 1
        && values
            .iter()
            .any(|value| hsts_value_is_sufficient(value, policy))
    {
        HstsStrength::Sufficient
    } else {
        HstsStrength::Weak
    }
}

fn hsts_value_is_sufficient(value: &str, policy: &SecurityHeaderPolicy<'_>) -> bool {
    let mut max_age = None;
    let mut include_subdomains = false;
    let mut seen = BTreeSet::new();
    for directive in value
        .split(';')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let (name, value) = directive
            .split_once('=')
            .map_or((directive, None), |(name, value)| {
                (name.trim(), Some(value.trim()))
            });
        let normalized_name = name.to_ascii_lowercase();
        if !seen.insert(normalized_name.clone()) {
            return false;
        }
        if normalized_name == "max-age" {
            max_age = value.and_then(|value| value.parse::<u64>().ok());
        } else if normalized_name == "includesubdomains" && value.is_none() {
            include_subdomains = true;
        }
    }
    max_age.is_some_and(|max_age| max_age >= policy.hsts_min_max_age)
        && (!policy.require_hsts_include_subdomains || include_subdomains)
}

fn parse_set_cookie(value: &str) -> Option<ParsedCookie> {
    let mut parts = value.split(';');
    let pair = parts.next()?.trim();
    let (name, _) = pair.split_once('=')?;
    let name = name.trim();
    if !valid_cookie_name(name) {
        return None;
    }
    let mut secure = false;
    let mut http_only = false;
    let mut same_site = None;
    let mut path = None;
    let mut has_domain = false;
    let mut seen = BTreeSet::new();
    let mut duplicate_attribute = false;
    for attribute in parts
        .map(str::trim)
        .filter(|attribute| !attribute.is_empty())
    {
        let (attribute_name, attribute_value) = attribute
            .split_once('=')
            .map_or((attribute, None), |(name, value)| {
                (name.trim(), Some(value.trim()))
            });
        let normalized_name = attribute_name.to_ascii_lowercase();
        if !seen.insert(normalized_name.clone()) {
            duplicate_attribute = true;
        }
        match normalized_name.as_str() {
            "secure" if attribute_value.is_none() => secure = true,
            "httponly" if attribute_value.is_none() => http_only = true,
            "samesite" => {
                same_site = attribute_value.map(|value| value.to_ascii_lowercase());
            }
            "path" => path = attribute_value.map(str::to_string),
            "domain" => has_domain = true,
            _ => {}
        }
    }
    Some(ParsedCookie {
        name: name.to_string(),
        identity: format!("cookie:{}", &sha256_hex(name.as_bytes())[..16]),
        secure,
        http_only,
        same_site,
        path,
        has_domain,
        duplicate_attribute,
    })
}

fn valid_cookie_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_COOKIE_NAME_BYTES
        && value.bytes().all(|byte| {
            byte > 0x20
                && byte < 0x7f
                && !matches!(
                    byte,
                    b'(' | b')'
                        | b'<'
                        | b'>'
                        | b'@'
                        | b','
                        | b';'
                        | b':'
                        | b'\\'
                        | b'"'
                        | b'/'
                        | b'['
                        | b']'
                        | b'?'
                        | b'='
                        | b'{'
                        | b'}'
                )
        })
}

fn sha256_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(value);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use aegis_native_engine::HttpMethod;

    use super::{
        assess_security_headers, HeaderInspectionWarningKind, PassiveHeader, SecurityHeaderContext,
        SecurityHeaderLimits, SecurityHeaderPolicy, SecurityHeaderRuntimeError,
    };

    fn context<'a>(
        endpoint: &'a str,
        headers: &'a [PassiveHeader<'a>],
    ) -> SecurityHeaderContext<'a> {
        SecurityHeaderContext {
            target_id: "target-1",
            endpoint,
            method: HttpMethod::Get,
            status_code: 200,
            headers,
            evidence_ref: "evidence-1",
        }
    }

    fn secure_headers<'a>() -> Vec<PassiveHeader<'a>> {
        vec![
            PassiveHeader {
                name: "Content-Type",
                value: "text/html; charset=utf-8",
            },
            PassiveHeader {
                name: "Content-Security-Policy",
                value: "default-src 'self'; frame-ancestors 'none'",
            },
            PassiveHeader {
                name: "X-Content-Type-Options",
                value: "nosniff",
            },
            PassiveHeader {
                name: "Strict-Transport-Security",
                value: "max-age=31536000; includeSubDomains",
            },
            PassiveHeader {
                name: "Set-Cookie",
                value: "__Host-session=private-secret; Path=/; Secure; HttpOnly; SameSite=Lax",
            },
        ]
    }

    #[test]
    fn secure_html_and_cookie_produce_no_findings_or_raw_debug() {
        let headers = secure_headers();
        let context = context("https://example.com/app", &headers);
        let assessment = assess_security_headers(
            &context,
            &SecurityHeaderPolicy::default(),
            SecurityHeaderLimits::default(),
        )
        .unwrap();
        assert!(assessment.findings.is_empty());
        assert!(assessment.warnings.is_empty());
        assert_eq!(assessment.inspected_cookie_count, 1);
        let debug = format!("{context:?} {assessment:?} {:?}", headers[4]);
        assert!(!debug.contains("private-secret"));
        assert!(!debug.contains("example.com"));
    }

    #[test]
    fn missing_html_security_headers_are_canonical_findings() {
        let headers = [PassiveHeader {
            name: "Content-Type",
            value: "text/html",
        }];
        let assessment = assess_security_headers(
            &context("https://example.com/account?token=secret", &headers),
            &SecurityHeaderPolicy::default(),
            SecurityHeaderLimits::default(),
        )
        .unwrap();
        assert_eq!(assessment.findings.len(), 4);
        assert!(assessment
            .findings
            .iter()
            .all(|finding| finding.validate().is_ok()));
        assert!(assessment.findings.iter().all(|finding| {
            !finding.identity.canonical_endpoint.contains("secret")
                && finding.evidence_refs == ["evidence-1"]
        }));
    }

    #[test]
    fn cookie_flags_prefixes_and_explicit_exceptions_are_enforced() {
        let headers = [
            PassiveHeader {
                name: "Content-Type",
                value: "application/json",
            },
            PassiveHeader {
                name: "X-Content-Type-Options",
                value: "nosniff",
            },
            PassiveHeader {
                name: "Strict-Transport-Security",
                value: "max-age=31536000",
            },
            PassiveHeader {
                name: "Set-Cookie",
                value: "session=secret; SameSite=None",
            },
            PassiveHeader {
                name: "Set-Cookie",
                value: "XSRF-TOKEN=value; Secure; SameSite=Lax",
            },
            PassiveHeader {
                name: "Set-Cookie",
                value: "__Host-bad=value; Secure; HttpOnly; SameSite=Strict; Domain=example.com",
            },
        ];
        let policy = SecurityHeaderPolicy {
            hsts_min_max_age: 31_536_000,
            require_hsts_include_subdomains: false,
            script_readable_cookie_exceptions: &["XSRF-TOKEN"],
            cross_site_cookie_exceptions: &[],
        };
        let assessment = assess_security_headers(
            &context("https://example.com/api", &headers),
            &policy,
            SecurityHeaderLimits::default(),
        )
        .unwrap();
        let rule_ids = assessment
            .findings
            .iter()
            .map(|finding| finding.provenance.rule_id.as_str())
            .collect::<Vec<_>>();
        assert!(rule_ids.contains(&"aegis.config.cookie.secure"));
        assert!(rule_ids.contains(&"aegis.config.cookie.httponly"));
        assert!(rule_ids.contains(&"aegis.config.cookie.samesite"));
        assert!(rule_ids.contains(&"aegis.config.cookie.host-prefix"));
        assert_eq!(
            rule_ids
                .iter()
                .filter(|rule_id| **rule_id == "aegis.config.cookie.httponly")
                .count(),
            1
        );
        assert!(assessment
            .findings
            .iter()
            .filter(|finding| finding.identity.parameter_location
                == aegis_native_engine::ParameterLocation::Cookie)
            .all(|finding| !finding
                .identity
                .parameter_name
                .as_deref()
                .unwrap()
                .contains("session")));
    }

    #[test]
    fn hsts_is_https_only_and_policy_can_require_include_subdomains() {
        let headers = [
            PassiveHeader {
                name: "Content-Type",
                value: "application/json",
            },
            PassiveHeader {
                name: "X-Content-Type-Options",
                value: "nosniff",
            },
            PassiveHeader {
                name: "Strict-Transport-Security",
                value: "max-age=31536000",
            },
        ];
        let strict_policy = SecurityHeaderPolicy {
            require_hsts_include_subdomains: true,
            ..SecurityHeaderPolicy::default()
        };
        let https = assess_security_headers(
            &context("https://example.com/api", &headers),
            &strict_policy,
            SecurityHeaderLimits::default(),
        )
        .unwrap();
        assert_eq!(https.findings.len(), 1);
        assert_eq!(
            https.findings[0].provenance.rule_id,
            "aegis.config.header.hsts"
        );
        let http = assess_security_headers(
            &context("http://example.com/api", &headers),
            &strict_policy,
            SecurityHeaderLimits::default(),
        )
        .unwrap();
        assert!(http.findings.is_empty());
    }

    #[test]
    fn malformed_and_duplicate_cookie_attributes_warn_without_raw_values() {
        let headers = [
            PassiveHeader {
                name: "X-Content-Type-Options",
                value: "nosniff",
            },
            PassiveHeader {
                name: "Set-Cookie",
                value: "malformed-without-equals; Secure",
            },
            PassiveHeader {
                name: "Set-Cookie",
                value: "ok=value; Secure; Secure; HttpOnly; SameSite=Lax",
            },
        ];
        let assessment = assess_security_headers(
            &context("https://example.com/api", &headers),
            &SecurityHeaderPolicy::default(),
            SecurityHeaderLimits::default(),
        )
        .unwrap();
        assert_eq!(assessment.warnings.len(), 2);
        assert_eq!(
            assessment.warnings[0].kind,
            HeaderInspectionWarningKind::MalformedSetCookie
        );
        assert_eq!(
            assessment.warnings[1].kind,
            HeaderInspectionWarningKind::DuplicateCookieAttribute
        );
        assert!(!format!("{assessment:?}").contains("malformed-without-equals"));
    }

    #[test]
    fn limits_and_invalid_header_values_fail_closed() {
        let headers = [PassiveHeader {
            name: "Set-Cookie",
            value: "a=b\r\nInjected: yes",
        }];
        assert!(matches!(
            assess_security_headers(
                &context("https://example.com", &headers),
                &SecurityHeaderPolicy::default(),
                SecurityHeaderLimits::default(),
            ),
            Err(SecurityHeaderRuntimeError::InvalidInput)
        ));
        assert!(assess_security_headers(
            &context("https://example.com", &[]),
            &SecurityHeaderPolicy::default(),
            SecurityHeaderLimits {
                max_headers: 0,
                ..SecurityHeaderLimits::default()
            },
        )
        .is_err());

        let secure = secure_headers();
        assert!(matches!(
            assess_security_headers(
                &context("https://", &secure),
                &SecurityHeaderPolicy::default(),
                SecurityHeaderLimits::default(),
            ),
            Err(SecurityHeaderRuntimeError::InvalidInput)
        ));

        let duplicate_policy = SecurityHeaderPolicy {
            script_readable_cookie_exceptions: &["XSRF-TOKEN", "XSRF-TOKEN"],
            ..SecurityHeaderPolicy::default()
        };
        assert!(matches!(
            assess_security_headers(
                &context("https://example.com", &secure),
                &duplicate_policy,
                SecurityHeaderLimits::default(),
            ),
            Err(SecurityHeaderRuntimeError::InvalidPolicy)
        ));
    }
}
