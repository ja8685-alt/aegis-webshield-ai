use std::collections::BTreeSet;
use std::fmt::{Debug, Display, Formatter};

use aegis_native_engine::{
    CanonicalFinding, Confidence, FindingIdentity, FindingProvenance, HttpMethod,
    ParameterLocation, Severity,
};
use url::Url;

use crate::PassiveHeader;

const HARD_MAX_HEADERS: usize = 128;
const HARD_MAX_HEADER_VALUE_BYTES: usize = 8_192;
const HARD_MAX_TRUSTED_ORIGINS: usize = 64;
const HARD_MAX_OBSERVATIONS: usize = 32;
const MAX_ORIGIN_BYTES: usize = 2_048;
const RULE_VERSION: &str = "1.0.0";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TlsMetadata {
    pub negotiated_version: TlsVersion,
    pub certificate_chain_valid: bool,
    pub hostname_valid: bool,
    pub days_until_expiry: i32,
}

impl Debug for TlsMetadata {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsMetadata")
            .field("negotiated_version", &self.negotiated_version)
            .field("certificate_chain_valid", &self.certificate_chain_valid)
            .field("hostname_valid", &self.hostname_valid)
            .field("days_until_expiry", &self.days_until_expiry)
            .finish()
    }
}

pub struct CorsProbeContext<'a> {
    pub request_origin: &'a str,
    pub credentialed_request: bool,
    pub preflight: bool,
    pub origin_probe_approved: bool,
    /// True only after two approved Origin probes proved response reflection.
    pub response_is_origin_dynamic: bool,
    /// Explicit endpoint contract for intentionally public non-credentialed CORS.
    pub public_cross_origin_approved: bool,
}

impl Debug for CorsProbeContext<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CorsProbeContext")
            .field("request_origin_bytes", &self.request_origin.len())
            .field("credentialed_request", &self.credentialed_request)
            .field("preflight", &self.preflight)
            .field("origin_probe_approved", &self.origin_probe_approved)
            .field(
                "response_is_origin_dynamic",
                &self.response_is_origin_dynamic,
            )
            .field(
                "public_cross_origin_approved",
                &self.public_cross_origin_approved,
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheAssessmentContext {
    pub authenticated_response: bool,
    pub sensitive_response: bool,
    pub public_cache_approved: bool,
}

pub struct TransportConfigurationContext<'a> {
    pub target_id: &'a str,
    pub endpoint: &'a str,
    pub method: HttpMethod,
    pub status_code: u16,
    pub response_headers: &'a [PassiveHeader<'a>],
    pub tls: Option<TlsMetadata>,
    pub cors: Option<CorsProbeContext<'a>>,
    pub cache: Option<CacheAssessmentContext>,
    pub evidence_ref: &'a str,
}

impl Debug for TransportConfigurationContext<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransportConfigurationContext")
            .field("method", &self.method)
            .field("status_code", &self.status_code)
            .field("header_count", &self.response_headers.len())
            .field("has_tls_metadata", &self.tls.is_some())
            .field("has_cors_probe", &self.cors.is_some())
            .field("has_cache_contract", &self.cache.is_some())
            .finish()
    }
}

pub struct TransportConfigurationPolicy<'a> {
    pub minimum_tls_version: TlsVersion,
    pub certificate_expiry_warning_days: u16,
    pub trusted_cors_origins: &'a [&'a str],
    pub allow_null_cors_origin: bool,
}

impl Default for TransportConfigurationPolicy<'static> {
    fn default() -> Self {
        Self {
            minimum_tls_version: TlsVersion::Tls12,
            certificate_expiry_warning_days: 14,
            trusted_cors_origins: &[],
            allow_null_cors_origin: false,
        }
    }
}

impl Debug for TransportConfigurationPolicy<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransportConfigurationPolicy")
            .field("minimum_tls_version", &self.minimum_tls_version)
            .field(
                "certificate_expiry_warning_days",
                &self.certificate_expiry_warning_days,
            )
            .field(
                "trusted_cors_origin_count",
                &self.trusted_cors_origins.len(),
            )
            .field("allow_null_cors_origin", &self.allow_null_cors_origin)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationLimits {
    pub max_headers: usize,
    pub max_header_value_bytes: usize,
    pub max_trusted_origins: usize,
    pub max_observations: usize,
}

impl Default for ConfigurationLimits {
    fn default() -> Self {
        Self {
            max_headers: HARD_MAX_HEADERS,
            max_header_value_bytes: HARD_MAX_HEADER_VALUE_BYTES,
            max_trusted_origins: HARD_MAX_TRUSTED_ORIGINS,
            max_observations: HARD_MAX_OBSERVATIONS,
        }
    }
}

impl ConfigurationLimits {
    fn validate(self) -> Result<(), ConfigurationRuntimeError> {
        if self.max_headers == 0
            || self.max_headers > HARD_MAX_HEADERS
            || self.max_header_value_bytes == 0
            || self.max_header_value_bytes > HARD_MAX_HEADER_VALUE_BYTES
            || self.max_trusted_origins == 0
            || self.max_trusted_origins > HARD_MAX_TRUSTED_ORIGINS
            || self.max_observations == 0
            || self.max_observations > HARD_MAX_OBSERVATIONS
        {
            return Err(ConfigurationRuntimeError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationRuntimeError {
    InvalidLimits,
    InvalidInput,
    InvalidPolicy,
    UnapprovedCorsProbe,
    ObservationLimitExceeded,
    ContractViolation,
}

impl Display for ConfigurationRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "transport configuration limits are invalid",
            Self::InvalidInput => "transport configuration input is invalid",
            Self::InvalidPolicy => "transport configuration policy is invalid",
            Self::UnapprovedCorsProbe => "CORS probe was not explicitly approved",
            Self::ObservationLimitExceeded => "transport configuration observation limit exceeded",
            Self::ContractViolation => "transport configuration finding could not be created",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ConfigurationRuntimeError {}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConfigurationSignal {
    LegacyTls,
    InvalidCertificateChain,
    InvalidCertificateHostname,
    ExpiredCertificate,
    ExpiringCertificate,
    CorsWildcard,
    CorsWildcardWithCredentials,
    CorsNullOrigin,
    CorsUntrustedOriginReflection,
    CorsUntrustedCredentials,
    CorsDynamicWithoutVaryOrigin,
    CorsPreflightMethodsMissing,
    SensitiveResponsePublicCache,
    SensitiveResponseMissingPrivateCache,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationObservation {
    pub signal: ConfigurationSignal,
    pub location: ParameterLocation,
    pub parameter_name: &'static str,
}

pub struct ConfigurationAssessment {
    pub findings: Vec<CanonicalFinding>,
    pub observations: Vec<ConfigurationObservation>,
    pub tls_evaluated: bool,
    pub cors_evaluated: bool,
    pub cache_evaluated: bool,
}

impl Debug for ConfigurationAssessment {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfigurationAssessment")
            .field("finding_count", &self.findings.len())
            .field("observations", &self.observations)
            .field("tls_evaluated", &self.tls_evaluated)
            .field("cors_evaluated", &self.cors_evaluated)
            .field("cache_evaluated", &self.cache_evaluated)
            .finish()
    }
}

pub fn assess_transport_configuration(
    context: &TransportConfigurationContext<'_>,
    policy: &TransportConfigurationPolicy<'_>,
    limits: ConfigurationLimits,
) -> Result<ConfigurationAssessment, ConfigurationRuntimeError> {
    limits.validate()?;
    let endpoint = validate_context(context, limits)?;
    validate_policy(policy, limits)?;
    let mut observations = Vec::new();

    if let Some(tls) = context.tls {
        inspect_tls(tls, policy, &mut observations, limits)?;
    }
    if let Some(cors) = &context.cors {
        if !cors.origin_probe_approved {
            return Err(ConfigurationRuntimeError::UnapprovedCorsProbe);
        }
        inspect_cors(
            cors,
            context.response_headers,
            policy,
            &mut observations,
            limits,
        )?;
    }
    if let Some(cache) = context.cache {
        inspect_cache(cache, context.response_headers, &mut observations, limits)?;
    }

    let mut findings = Vec::with_capacity(observations.len());
    for observation in &observations {
        findings.push(build_finding(context, observation)?);
    }
    Ok(ConfigurationAssessment {
        findings,
        observations,
        tls_evaluated: context.tls.is_some() && endpoint.scheme() == "https",
        cors_evaluated: context.cors.is_some(),
        cache_evaluated: context.cache.is_some(),
    })
}

fn inspect_tls(
    tls: TlsMetadata,
    policy: &TransportConfigurationPolicy<'_>,
    observations: &mut Vec<ConfigurationObservation>,
    limits: ConfigurationLimits,
) -> Result<(), ConfigurationRuntimeError> {
    if tls.negotiated_version < policy.minimum_tls_version {
        push_observation(
            observations,
            ConfigurationSignal::LegacyTls,
            ParameterLocation::Transport,
            "tls-version",
            limits,
        )?;
    }
    if !tls.certificate_chain_valid {
        push_observation(
            observations,
            ConfigurationSignal::InvalidCertificateChain,
            ParameterLocation::Transport,
            "certificate-chain",
            limits,
        )?;
    }
    if !tls.hostname_valid {
        push_observation(
            observations,
            ConfigurationSignal::InvalidCertificateHostname,
            ParameterLocation::Transport,
            "certificate-hostname",
            limits,
        )?;
    }
    if tls.days_until_expiry < 0 {
        push_observation(
            observations,
            ConfigurationSignal::ExpiredCertificate,
            ParameterLocation::Transport,
            "certificate-expiry",
            limits,
        )?;
    } else if tls.days_until_expiry <= i32::from(policy.certificate_expiry_warning_days) {
        push_observation(
            observations,
            ConfigurationSignal::ExpiringCertificate,
            ParameterLocation::Transport,
            "certificate-expiry",
            limits,
        )?;
    }
    Ok(())
}

fn inspect_cors(
    cors: &CorsProbeContext<'_>,
    headers: &[PassiveHeader<'_>],
    policy: &TransportConfigurationPolicy<'_>,
    observations: &mut Vec<ConfigurationObservation>,
    limits: ConfigurationLimits,
) -> Result<(), ConfigurationRuntimeError> {
    let allow_origins = header_values(headers, "access-control-allow-origin");
    if allow_origins.len() > 1 {
        return Err(ConfigurationRuntimeError::InvalidInput);
    }
    let Some(allow_origin) = allow_origins.first().map(|value| value.trim()) else {
        return Ok(());
    };
    let credential_values = header_values(headers, "access-control-allow-credentials");
    if credential_values.len() > 1
        || credential_values
            .iter()
            .any(|value| !matches!(value.trim().to_ascii_lowercase().as_str(), "true" | "false"))
    {
        return Err(ConfigurationRuntimeError::InvalidInput);
    }
    let allow_credentials = credential_values
        .first()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"));
    let origin_is_trusted = policy.trusted_cors_origins.contains(&cors.request_origin)
        || policy.allow_null_cors_origin && cors.request_origin == "null";

    if allow_origin != "*" && !allow_origin.eq_ignore_ascii_case("null") {
        validate_origin(allow_origin).map_err(|_| ConfigurationRuntimeError::InvalidInput)?;
    }
    if cors.preflight && header_values(headers, "access-control-allow-methods").is_empty() {
        push_observation(
            observations,
            ConfigurationSignal::CorsPreflightMethodsMissing,
            ParameterLocation::ResponseHeader,
            "access-control-allow-methods",
            limits,
        )?;
    }

    if allow_origin == "*" {
        if allow_credentials || cors.credentialed_request {
            push_observation(
                observations,
                ConfigurationSignal::CorsWildcardWithCredentials,
                ParameterLocation::ResponseHeader,
                "access-control-allow-origin",
                limits,
            )?;
        } else if !cors.public_cross_origin_approved {
            push_observation(
                observations,
                ConfigurationSignal::CorsWildcard,
                ParameterLocation::ResponseHeader,
                "access-control-allow-origin",
                limits,
            )?;
        }
        return Ok(());
    }
    if allow_origin.eq_ignore_ascii_case("null") && !policy.allow_null_cors_origin {
        push_observation(
            observations,
            ConfigurationSignal::CorsNullOrigin,
            ParameterLocation::ResponseHeader,
            "access-control-allow-origin",
            limits,
        )?;
    }
    if allow_origin == cors.request_origin {
        if !origin_is_trusted && !cors.public_cross_origin_approved {
            push_observation(
                observations,
                ConfigurationSignal::CorsUntrustedOriginReflection,
                ParameterLocation::ResponseHeader,
                "access-control-allow-origin",
                limits,
            )?;
        }
        if allow_credentials && !origin_is_trusted {
            push_observation(
                observations,
                ConfigurationSignal::CorsUntrustedCredentials,
                ParameterLocation::ResponseHeader,
                "access-control-allow-credentials",
                limits,
            )?;
        }
        if cors.response_is_origin_dynamic && !vary_contains_origin(headers) {
            push_observation(
                observations,
                ConfigurationSignal::CorsDynamicWithoutVaryOrigin,
                ParameterLocation::ResponseHeader,
                "vary",
                limits,
            )?;
        }
    }
    Ok(())
}

fn inspect_cache(
    cache: CacheAssessmentContext,
    headers: &[PassiveHeader<'_>],
    observations: &mut Vec<ConfigurationObservation>,
    limits: ConfigurationLimits,
) -> Result<(), ConfigurationRuntimeError> {
    if !(cache.authenticated_response || cache.sensitive_response) || cache.public_cache_approved {
        return Ok(());
    }
    let directives = cache_directives(headers);
    let explicitly_private = directives.contains("no-store") || directives.contains("private");
    let explicitly_shared = directives.contains("public")
        || directives.iter().any(|directive| {
            directive.starts_with("s-maxage=") || directive.starts_with("proxy-revalidate")
        });
    if explicitly_shared {
        push_observation(
            observations,
            ConfigurationSignal::SensitiveResponsePublicCache,
            ParameterLocation::ResponseHeader,
            "cache-control",
            limits,
        )?;
    } else if !explicitly_private {
        push_observation(
            observations,
            ConfigurationSignal::SensitiveResponseMissingPrivateCache,
            ParameterLocation::ResponseHeader,
            "cache-control",
            limits,
        )?;
    }
    Ok(())
}

fn push_observation(
    observations: &mut Vec<ConfigurationObservation>,
    signal: ConfigurationSignal,
    location: ParameterLocation,
    parameter_name: &'static str,
    limits: ConfigurationLimits,
) -> Result<(), ConfigurationRuntimeError> {
    if observations
        .iter()
        .any(|observation| observation.signal == signal)
    {
        return Ok(());
    }
    if observations.len() >= limits.max_observations {
        return Err(ConfigurationRuntimeError::ObservationLimitExceeded);
    }
    observations.push(ConfigurationObservation {
        signal,
        location,
        parameter_name,
    });
    Ok(())
}

fn build_finding(
    context: &TransportConfigurationContext<'_>,
    observation: &ConfigurationObservation,
) -> Result<CanonicalFinding, ConfigurationRuntimeError> {
    let (rule_id, weakness, title, severity, confidence) = match observation.signal {
        ConfigurationSignal::LegacyTls => (
            "aegis.config.tls.legacy-version",
            "CWE-326",
            "지원 중단 TLS version 사용",
            Severity::Medium,
            Confidence::High,
        ),
        ConfigurationSignal::InvalidCertificateChain
        | ConfigurationSignal::InvalidCertificateHostname
        | ConfigurationSignal::ExpiredCertificate => (
            "aegis.config.tls.certificate",
            "CWE-295",
            "TLS 인증서 검증 오류",
            Severity::High,
            Confidence::High,
        ),
        ConfigurationSignal::ExpiringCertificate => (
            "aegis.config.tls.certificate-expiry",
            "CWE-298",
            "TLS 인증서 만료 임박",
            Severity::Low,
            Confidence::High,
        ),
        ConfigurationSignal::CorsWildcard
        | ConfigurationSignal::CorsWildcardWithCredentials
        | ConfigurationSignal::CorsNullOrigin
        | ConfigurationSignal::CorsUntrustedOriginReflection
        | ConfigurationSignal::CorsUntrustedCredentials
        | ConfigurationSignal::CorsDynamicWithoutVaryOrigin
        | ConfigurationSignal::CorsPreflightMethodsMissing => (
            "aegis.config.cors",
            "CWE-942",
            "CORS 신뢰 경계 설정 오류",
            if matches!(
                observation.signal,
                ConfigurationSignal::CorsWildcardWithCredentials
                    | ConfigurationSignal::CorsUntrustedCredentials
            ) {
                Severity::High
            } else {
                Severity::Medium
            },
            Confidence::High,
        ),
        ConfigurationSignal::SensitiveResponsePublicCache
        | ConfigurationSignal::SensitiveResponseMissingPrivateCache => (
            "aegis.config.cache.sensitive-response",
            "CWE-524",
            "민감 응답 Cache-Control 설정 오류",
            Severity::Medium,
            Confidence::High,
        ),
    };
    let identity = FindingIdentity::new(
        context.target_id,
        context.method,
        context.endpoint,
        weakness,
        observation.location,
        Some(observation.parameter_name.to_string()),
    )
    .map_err(|_| ConfigurationRuntimeError::ContractViolation)?;
    let finding_id = format!("native-{}", &identity.fingerprint()[..24]);
    CanonicalFinding::new(
        finding_id,
        identity,
        title,
        severity,
        confidence,
        vec![context.evidence_ref.to_string()],
        FindingProvenance::new("native-passive", rule_id, RULE_VERSION)
            .map_err(|_| ConfigurationRuntimeError::ContractViolation)?,
    )
    .map_err(|_| ConfigurationRuntimeError::ContractViolation)
}

fn validate_context<'a>(
    context: &'a TransportConfigurationContext<'a>,
    limits: ConfigurationLimits,
) -> Result<Url, ConfigurationRuntimeError> {
    if !(100..=599).contains(&context.status_code)
        || context.response_headers.len() > limits.max_headers
        || context.evidence_ref.is_empty()
        || context.evidence_ref.len() > 64
        || !context
            .evidence_ref
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ConfigurationRuntimeError::InvalidInput);
    }
    let endpoint =
        Url::parse(context.endpoint).map_err(|_| ConfigurationRuntimeError::InvalidInput)?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
        || context.tls.is_some() && endpoint.scheme() != "https"
    {
        return Err(ConfigurationRuntimeError::InvalidInput);
    }
    FindingIdentity::new(
        context.target_id,
        context.method,
        context.endpoint,
        "CWE-693",
        ParameterLocation::Transport,
        Some("contract-validation".to_string()),
    )
    .map_err(|_| ConfigurationRuntimeError::InvalidInput)?;
    for header in context.response_headers {
        if header.name.is_empty()
            || header.name.len() > 128
            || !header
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || header.value.len() > limits.max_header_value_bytes
            || header.value.contains(['\r', '\n', '\0'])
        {
            return Err(ConfigurationRuntimeError::InvalidInput);
        }
    }
    if let Some(tls) = context.tls {
        if !(-36_500..=36_500).contains(&tls.days_until_expiry) {
            return Err(ConfigurationRuntimeError::InvalidInput);
        }
    }
    if let Some(cors) = &context.cors {
        validate_request_origin(cors.request_origin)?;
        if cors.credentialed_request && cors.public_cross_origin_approved {
            return Err(ConfigurationRuntimeError::InvalidInput);
        }
    }
    Ok(endpoint)
}

fn validate_policy(
    policy: &TransportConfigurationPolicy<'_>,
    limits: ConfigurationLimits,
) -> Result<(), ConfigurationRuntimeError> {
    if policy.minimum_tls_version < TlsVersion::Tls12
        || policy.certificate_expiry_warning_days == 0
        || policy.certificate_expiry_warning_days > 365
        || policy.trusted_cors_origins.len() > limits.max_trusted_origins
    {
        return Err(ConfigurationRuntimeError::InvalidPolicy);
    }
    let mut origins = BTreeSet::new();
    for origin in policy.trusted_cors_origins {
        validate_origin(origin)?;
        if !origins.insert(*origin) {
            return Err(ConfigurationRuntimeError::InvalidPolicy);
        }
    }
    Ok(())
}

fn validate_origin(origin: &str) -> Result<(), ConfigurationRuntimeError> {
    if origin.is_empty() || origin.len() > MAX_ORIGIN_BYTES {
        return Err(ConfigurationRuntimeError::InvalidPolicy);
    }
    let parsed = Url::parse(origin).map_err(|_| ConfigurationRuntimeError::InvalidPolicy)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || origin.ends_with('/')
        || parsed.origin().ascii_serialization() != origin
    {
        return Err(ConfigurationRuntimeError::InvalidPolicy);
    }
    Ok(())
}

fn validate_request_origin(origin: &str) -> Result<(), ConfigurationRuntimeError> {
    if origin == "null" {
        return Ok(());
    }
    validate_origin(origin).map_err(|_| ConfigurationRuntimeError::InvalidInput)
}

fn header_values<'a>(headers: &'a [PassiveHeader<'a>], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value)
        .collect()
}

fn vary_contains_origin(headers: &[PassiveHeader<'_>]) -> bool {
    header_values(headers, "vary").iter().any(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("origin"))
    })
}

fn cache_directives(headers: &[PassiveHeader<'_>]) -> BTreeSet<String> {
    header_values(headers, "cache-control")
        .iter()
        .flat_map(|value| value.split(','))
        .map(|directive| directive.trim().to_ascii_lowercase())
        .filter(|directive| !directive.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use aegis_native_engine::HttpMethod;

    use super::{
        assess_transport_configuration, CacheAssessmentContext, ConfigurationLimits,
        ConfigurationRuntimeError, ConfigurationSignal, CorsProbeContext, TlsMetadata, TlsVersion,
        TransportConfigurationContext, TransportConfigurationPolicy,
    };
    use crate::PassiveHeader;

    fn context<'a>(headers: &'a [PassiveHeader<'a>]) -> TransportConfigurationContext<'a> {
        TransportConfigurationContext {
            target_id: "target-1",
            endpoint: "https://example.com/account?token=must-not-leak",
            method: HttpMethod::Get,
            status_code: 200,
            response_headers: headers,
            tls: None,
            cors: None,
            cache: None,
            evidence_ref: "evidence-1",
        }
    }

    #[test]
    fn secure_tls_has_no_finding_while_legacy_invalid_and_expiry_are_separate() {
        let mut secure = context(&[]);
        secure.tls = Some(TlsMetadata {
            negotiated_version: TlsVersion::Tls13,
            certificate_chain_valid: true,
            hostname_valid: true,
            days_until_expiry: 90,
        });
        let assessment = assess_transport_configuration(
            &secure,
            &TransportConfigurationPolicy::default(),
            ConfigurationLimits::default(),
        )
        .unwrap();
        assert!(assessment.findings.is_empty());
        assert!(assessment.tls_evaluated);

        secure.tls = Some(TlsMetadata {
            negotiated_version: TlsVersion::Tls11,
            certificate_chain_valid: false,
            hostname_valid: false,
            days_until_expiry: -1,
        });
        let assessment = assess_transport_configuration(
            &secure,
            &TransportConfigurationPolicy::default(),
            ConfigurationLimits::default(),
        )
        .unwrap();
        assert_eq!(assessment.observations.len(), 4);
        assert!(assessment
            .observations
            .iter()
            .any(|item| item.signal == ConfigurationSignal::LegacyTls));
        assert!(assessment
            .findings
            .iter()
            .all(|finding| finding.validate().is_ok()));
    }

    #[test]
    fn cors_reflection_credentials_and_missing_vary_are_detected_without_origin_output() {
        let headers = [
            PassiveHeader {
                name: "Access-Control-Allow-Origin",
                value: "https://untrusted.example",
            },
            PassiveHeader {
                name: "Access-Control-Allow-Credentials",
                value: "true",
            },
        ];
        let mut input = context(&headers);
        input.cors = Some(CorsProbeContext {
            request_origin: "https://untrusted.example",
            credentialed_request: true,
            preflight: false,
            origin_probe_approved: true,
            response_is_origin_dynamic: true,
            public_cross_origin_approved: false,
        });
        let assessment = assess_transport_configuration(
            &input,
            &TransportConfigurationPolicy::default(),
            ConfigurationLimits::default(),
        )
        .unwrap();
        assert_eq!(assessment.observations.len(), 3);
        assert!(assessment
            .observations
            .iter()
            .any(|item| { item.signal == ConfigurationSignal::CorsUntrustedOriginReflection }));
        let debug = format!("{input:?} {assessment:?}");
        assert!(!debug.contains("untrusted.example"));
        assert!(!debug.contains("example.com/account"));
    }

    #[test]
    fn public_wildcard_and_trusted_dynamic_origin_require_explicit_context() {
        let wildcard = [PassiveHeader {
            name: "Access-Control-Allow-Origin",
            value: "*",
        }];
        let mut input = context(&wildcard);
        input.cors = Some(CorsProbeContext {
            request_origin: "https://reader.example",
            credentialed_request: false,
            preflight: false,
            origin_probe_approved: true,
            response_is_origin_dynamic: false,
            public_cross_origin_approved: true,
        });
        assert!(assess_transport_configuration(
            &input,
            &TransportConfigurationPolicy::default(),
            ConfigurationLimits::default(),
        )
        .unwrap()
        .findings
        .is_empty());

        let trusted_headers = [
            PassiveHeader {
                name: "Access-Control-Allow-Origin",
                value: "https://app.example",
            },
            PassiveHeader {
                name: "Access-Control-Allow-Methods",
                value: "GET, OPTIONS",
            },
            PassiveHeader {
                name: "Vary",
                value: "Accept-Encoding, Origin",
            },
        ];
        let mut trusted = context(&trusted_headers);
        trusted.cors = Some(CorsProbeContext {
            request_origin: "https://app.example",
            credentialed_request: false,
            preflight: true,
            origin_probe_approved: true,
            response_is_origin_dynamic: true,
            public_cross_origin_approved: false,
        });
        let policy = TransportConfigurationPolicy {
            trusted_cors_origins: &["https://app.example"],
            ..TransportConfigurationPolicy::default()
        };
        assert!(
            assess_transport_configuration(&trusted, &policy, ConfigurationLimits::default(),)
                .unwrap()
                .findings
                .is_empty()
        );

        let missing_methods_headers = [
            PassiveHeader {
                name: "Access-Control-Allow-Origin",
                value: "https://app.example",
            },
            PassiveHeader {
                name: "Vary",
                value: "Origin",
            },
        ];
        let mut missing_methods = context(&missing_methods_headers);
        missing_methods.cors = trusted.cors;
        let assessment = assess_transport_configuration(
            &missing_methods,
            &policy,
            ConfigurationLimits::default(),
        )
        .unwrap();
        assert!(assessment
            .observations
            .iter()
            .any(|item| { item.signal == ConfigurationSignal::CorsPreflightMethodsMissing }));
    }

    #[test]
    fn null_origin_is_only_allowed_by_explicit_policy() {
        let headers = [PassiveHeader {
            name: "Access-Control-Allow-Origin",
            value: "null",
        }];
        let mut input = context(&headers);
        input.cors = Some(CorsProbeContext {
            request_origin: "null",
            credentialed_request: false,
            preflight: false,
            origin_probe_approved: true,
            response_is_origin_dynamic: false,
            public_cross_origin_approved: false,
        });
        let assessment = assess_transport_configuration(
            &input,
            &TransportConfigurationPolicy::default(),
            ConfigurationLimits::default(),
        )
        .unwrap();
        assert_eq!(
            assessment.observations[0].signal,
            ConfigurationSignal::CorsNullOrigin
        );

        let policy = TransportConfigurationPolicy {
            allow_null_cors_origin: true,
            ..TransportConfigurationPolicy::default()
        };
        assert!(
            assess_transport_configuration(&input, &policy, ConfigurationLimits::default())
                .unwrap()
                .findings
                .is_empty()
        );
    }

    #[test]
    fn sensitive_cache_requires_private_or_no_store_unless_explicitly_public() {
        let headers = [PassiveHeader {
            name: "Cache-Control",
            value: "public, s-maxage=300",
        }];
        let mut input = context(&headers);
        input.cache = Some(CacheAssessmentContext {
            authenticated_response: true,
            sensitive_response: true,
            public_cache_approved: false,
        });
        let assessment = assess_transport_configuration(
            &input,
            &TransportConfigurationPolicy::default(),
            ConfigurationLimits::default(),
        )
        .unwrap();
        assert_eq!(
            assessment.observations[0].signal,
            ConfigurationSignal::SensitiveResponsePublicCache
        );

        input.cache.as_mut().unwrap().public_cache_approved = true;
        assert!(assess_transport_configuration(
            &input,
            &TransportConfigurationPolicy::default(),
            ConfigurationLimits::default(),
        )
        .unwrap()
        .findings
        .is_empty());
    }

    #[test]
    fn unapproved_cors_invalid_origin_header_and_limits_fail_closed() {
        let headers = [PassiveHeader {
            name: "Access-Control-Allow-Origin",
            value: "https://evil.example\r\nInjected: yes",
        }];
        let mut input = context(&headers);
        input.cors = Some(CorsProbeContext {
            request_origin: "https://evil.example",
            credentialed_request: false,
            preflight: false,
            origin_probe_approved: false,
            response_is_origin_dynamic: false,
            public_cross_origin_approved: false,
        });
        assert!(matches!(
            assess_transport_configuration(
                &input,
                &TransportConfigurationPolicy::default(),
                ConfigurationLimits::default(),
            ),
            Err(ConfigurationRuntimeError::InvalidInput)
                | Err(ConfigurationRuntimeError::UnapprovedCorsProbe)
        ));
        assert!(assess_transport_configuration(
            &context(&[]),
            &TransportConfigurationPolicy::default(),
            ConfigurationLimits {
                max_observations: 0,
                ..ConfigurationLimits::default()
            },
        )
        .is_err());
    }
}
