use aegis_crawler::{CrawlerError, CrawlerFetchClient, CrawlerFetchRequest, CrawlerFetchResponse};
use aegis_native_active::{
    assess_sql_injection, assess_xss_reflection, SqlInjectionContract, SqlInjectionDecision,
    SqlInjectionEvidence, SqlInjectionLimits, SqlInjectionPolicy, SqlResponseSample,
    XssProbeContract, XssReflectionDecision, XssReflectionInput, XssReflectionLimits,
    XssResponseSample,
};
use aegis_native_engine::{
    ApprovedTarget, CanonicalFinding, Confidence as NativeConfidence, HeaderRecord,
    HttpMethod as NativeHttpMethod, NativeRequestRecord, ParameterLocation, RequestPurpose,
    Severity as NativeSeverity,
};
use aegis_native_http::{
    classify_destination, AddressPolicy, DestinationClass, HttpExecutionLimits, NativeHttpExecutor,
    PublicAddressPolicy, SystemDnsResolver,
};
use aegis_native_passive::{
    assess_content_exposure, assess_security_headers, ContentExposureContext,
    ContentExposureLimits, PassiveHeader, SecurityHeaderContext, SecurityHeaderLimits,
    SecurityHeaderPolicy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use thiserror::Error;
use url::{Host, Url};

const DEFAULT_USER_AGENT: &str = "AegisNativeSecurityEngine/0.1 desktop";
const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024;
const DEFAULT_TIMEOUT_SECS: u64 = 8;
const DEFAULT_MAX_RETRY_ATTEMPTS: u8 = 0;
const MAX_SAFE_ACTIVE_PARAMETERS: usize = 10;
const NATIVE_META_PREFIX: &str = "__aegis_native_meta__=";
const XSS_MARKER_PREFIX: &str = "aegisxss_";
const SQLI_PROBE_VALUE: &str = "aegis_native_sqli_probe'";
const SQLI_CONTROL_VALUE: &str = "aegis_native_sqli_control";
const SURFACE_PROBE_PATHS: &[&str] = &[
    "/.env",
    "/.git/config",
    "/debug",
    "/actuator",
    "/actuator/env",
    "/admin",
    "/administrator",
    "/manage",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanTarget {
    pub id: String,
    pub method: Option<String>,
    pub url: String,
    pub approval_note: String,
    pub allow_private_network: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpProbeRequest {
    pub method: String,
    pub url: String,
    pub user_agent: String,
    pub timeout_millis: u64,
    pub retry_attempts: u8,
    pub max_response_bytes: usize,
    #[serde(default)]
    pub allow_private_network: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpProbeResponse {
    pub final_url: String,
    pub status_code: u16,
    pub headers: Vec<HttpHeader>,
    pub body_sample: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassiveFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: FindingSeverity,
    pub evidence: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScannerError {
    #[error("target must include an approval note before scanning")]
    MissingApproval,
    #[error("target url must be http or https")]
    UnsupportedScheme,
    #[error("passive probe method must be GET or HEAD")]
    UnsupportedMethod,
    #[error("target url is invalid")]
    InvalidUrl,
    #[error("private or local targets require explicit advanced approval")]
    PrivateNetworkNotAllowed,
    #[error("http probe failed: {0}")]
    HttpProbeFailed(String),
    #[error("http probe retry attempts exceed the safe scanner policy")]
    RetryAttemptsNotAllowed,
}

pub trait HttpProbeClient {
    fn execute(&self, request: &HttpProbeRequest) -> Result<HttpProbeResponse, ScannerError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeHttpProbeClient {
    allow_private_network: bool,
}

impl NativeHttpProbeClient {
    pub const fn new(allow_private_network: bool) -> Self {
        Self {
            allow_private_network,
        }
    }
}

impl Default for NativeHttpProbeClient {
    fn default() -> Self {
        Self::new(false)
    }
}

#[allow(non_upper_case_globals)]
pub const UreqHttpProbeClient: NativeHttpProbeClient = NativeHttpProbeClient::new(false);

#[derive(Clone, Copy, Debug)]
struct DesktopAddressPolicy {
    allow_private_network: bool,
}

impl AddressPolicy for DesktopAddressPolicy {
    fn allows(&self, address: std::net::IpAddr) -> bool {
        if !self.allow_private_network {
            return PublicAddressPolicy.allows(address);
        }
        !matches!(
            classify_destination(address),
            DestinationClass::Unspecified
                | DestinationClass::Multicast
                | DestinationClass::Reserved
        )
    }
}

impl HttpProbeClient for NativeHttpProbeClient {
    fn execute(&self, request: &HttpProbeRequest) -> Result<HttpProbeResponse, ScannerError> {
        if request.retry_attempts > DEFAULT_MAX_RETRY_ATTEMPTS {
            return Err(ScannerError::RetryAttemptsNotAllowed);
        }
        let allow_private_network = self.allow_private_network || request.allow_private_network;
        let target = approved_target_for_url("desktop-target", &request.url)?;
        let native_request = native_request_for_probe("request-desktop", request, &target)?;
        let limits = HttpExecutionLimits {
            request_timeout: Duration::from_millis(
                request
                    .timeout_millis
                    .clamp(1_000, DEFAULT_TIMEOUT_SECS * 1000),
            ),
            max_redirects: 5,
            max_response_bytes: request.max_response_bytes.max(1) as u64,
        };
        let executor = NativeHttpExecutor::new(
            SystemDnsResolver,
            DesktopAddressPolicy {
                allow_private_network,
            },
            limits,
        )
        .map_err(|error| ScannerError::HttpProbeFailed(error.to_string()))?;
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|error| ScannerError::HttpProbeFailed(error.to_string()))?;
        let executed = runtime
            .block_on(executor.execute(&target, &native_request))
            .map_err(|error| ScannerError::HttpProbeFailed(error.to_string()))?;
        let headers = executed
            .detection_headers()
            .iter()
            .map(|header| HttpHeader {
                name: header.name.clone(),
                value: header.value.clone(),
            })
            .collect();
        let body_sample = executed.body().to_vec();
        Ok(HttpProbeResponse {
            final_url: executed.record.final_url,
            status_code: executed.record.status_code,
            headers,
            body_sample,
        })
    }
}

impl CrawlerFetchClient for NativeHttpProbeClient {
    fn fetch(&self, request: &CrawlerFetchRequest) -> Result<CrawlerFetchResponse, CrawlerError> {
        let probe_request = HttpProbeRequest {
            method: request.method.clone(),
            url: request.url.clone(),
            user_agent: request.user_agent.clone(),
            timeout_millis: DEFAULT_TIMEOUT_SECS * 1000,
            retry_attempts: DEFAULT_MAX_RETRY_ATTEMPTS,
            max_response_bytes: request.max_response_bytes,
            allow_private_network: self.allow_private_network,
        };
        let response = self
            .execute(&probe_request)
            .map_err(|error| CrawlerError::FetchFailed(error.to_string()))?;
        let content_type = header_value(&response, "content-type").map(str::to_string);
        let body = String::from_utf8_lossy(&response.body_sample).into_owned();

        Ok(CrawlerFetchResponse {
            final_url: response.final_url,
            status_code: response.status_code,
            content_type,
            body,
        })
    }
}

pub fn build_passive_probe(target: &ScanTarget) -> Result<HttpProbeRequest, ScannerError> {
    validate_target(target)?;
    let method = validate_passive_method(target.method.as_deref())?;
    let request = HttpProbeRequest {
        method,
        url: target.url.trim().to_string(),
        user_agent: DEFAULT_USER_AGENT.to_string(),
        timeout_millis: DEFAULT_TIMEOUT_SECS * 1000,
        retry_attempts: DEFAULT_MAX_RETRY_ATTEMPTS,
        max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        allow_private_network: target.allow_private_network,
    };
    let native_target = approved_target_for_url(&target.id, &request.url)?;
    native_request_for_probe("request-validation", &request, &native_target)?;
    Ok(request)
}

pub fn run_passive_probe(
    target: &ScanTarget,
    client: &impl HttpProbeClient,
) -> Result<(HttpProbeResponse, Vec<PassiveFinding>), ScannerError> {
    let request = build_passive_probe(target)?;
    let response = client.execute(&request)?;
    let findings = analyze_passive_response_for_target(&target.id, &request.method, &response);
    Ok((response, findings))
}

pub fn surface_probe_targets(base_target: &ScanTarget) -> Result<Vec<ScanTarget>, ScannerError> {
    validate_target(base_target)?;
    let base_url = Url::parse(base_target.url.trim()).map_err(|_| ScannerError::InvalidUrl)?;
    let mut targets = Vec::new();

    for path in SURFACE_PROBE_PATHS {
        let mut url = base_url.clone();
        url.set_path(path);
        url.set_query(None);
        url.set_fragment(None);
        let candidate = url.to_string();
        if targets
            .iter()
            .any(|target: &ScanTarget| target.url == candidate)
        {
            continue;
        }
        targets.push(ScanTarget {
            id: format!(
                "{}:surface:{}",
                base_target.id,
                path.trim_start_matches('/')
            ),
            method: Some("GET".to_string()),
            url: candidate,
            approval_note: base_target.approval_note.clone(),
            allow_private_network: base_target.allow_private_network,
        });
    }

    Ok(targets)
}

pub fn run_safe_active_verifiers(
    target: &ScanTarget,
    client: &impl HttpProbeClient,
) -> Result<Vec<PassiveFinding>, ScannerError> {
    let baseline_request = build_passive_probe(target)?;
    let baseline_url = Url::parse(&baseline_request.url).map_err(|_| ScannerError::InvalidUrl)?;
    let parameter_names = query_parameter_names(&baseline_url);
    let mut findings = Vec::new();

    for parameter_name in parameter_names {
        findings.extend(run_xss_candidate(
            target,
            &baseline_request,
            &baseline_url,
            &parameter_name,
            client,
        )?);
        findings.extend(run_sqli_candidate(
            target,
            &baseline_request,
            &baseline_url,
            &parameter_name,
            client,
        )?);
    }

    Ok(findings)
}

pub fn analyze_passive_response(response: &HttpProbeResponse) -> Vec<PassiveFinding> {
    analyze_passive_response_for_target("analysis-target", "GET", response)
}

fn run_xss_candidate(
    target: &ScanTarget,
    baseline_request: &HttpProbeRequest,
    baseline_url: &Url,
    parameter_name: &str,
    client: &impl HttpProbeClient,
) -> Result<Vec<PassiveFinding>, ScannerError> {
    let seed = short_hash(format!("{}:{parameter_name}:xss", target.id).as_bytes());
    let probe_marker = format!("{XSS_MARKER_PREFIX}{}", &seed[..16]);
    let control_marker = format!(
        "{XSS_MARKER_PREFIX}{}",
        &short_hash(probe_marker.as_bytes())[..16]
    );
    let probe_url = mutate_query_parameter(baseline_url, parameter_name, &probe_marker);
    let control_url = mutate_query_parameter(baseline_url, parameter_name, &control_marker);
    let baseline = execute_samples(baseline_request, &baseline_request.url, 2, client)?;
    let probe = execute_samples(baseline_request, &probe_url, 2, client)?;
    let control = execute_samples(baseline_request, &control_url, 2, client)?;
    let baseline_samples = xss_samples(&baseline, "xss-baseline");
    let probe_samples = xss_samples(&probe, "xss-probe");
    let control_samples = xss_samples(&control, "xss-control");
    let assessment = assess_xss_reflection(
        &XssReflectionInput {
            contract: XssProbeContract {
                target_id: &target.id,
                endpoint: baseline_url.as_str(),
                method: NativeHttpMethod::Get,
                parameter_location: ParameterLocation::Query,
                parameter_name,
                probe_marker: &probe_marker,
                control_marker: &control_marker,
                explicitly_approved: true,
            },
            baseline: &baseline_samples,
            probe: &probe_samples,
            control: &control_samples,
        },
        XssReflectionLimits::default(),
    )
    .map_err(|error| ScannerError::HttpProbeFailed(error.to_string()))?;
    if assessment.decision != XssReflectionDecision::Candidate {
        return Ok(Vec::new());
    }
    let candidate = assessment
        .candidate
        .expect("candidate decision includes candidate");
    Ok(vec![active_candidate_finding(
        "aegis.candidate.reflected-xss",
        "Reflected XSS candidate requires confirmation",
        FindingSeverity::Medium,
        parameter_name,
        &candidate.candidate_id,
        &candidate.evidence_refs,
        "The native engine observed a reflected marker in a stable HTML context. Manual browser execution verification is required before treating this as confirmed XSS.",
    )])
}

fn run_sqli_candidate(
    target: &ScanTarget,
    baseline_request: &HttpProbeRequest,
    baseline_url: &Url,
    parameter_name: &str,
    client: &impl HttpProbeClient,
) -> Result<Vec<PassiveFinding>, ScannerError> {
    let probe_url = mutate_query_parameter(baseline_url, parameter_name, SQLI_PROBE_VALUE);
    let control_url = mutate_query_parameter(baseline_url, parameter_name, SQLI_CONTROL_VALUE);
    let baseline = execute_samples(baseline_request, &baseline_request.url, 1, client)?;
    let probe = execute_samples(baseline_request, &probe_url, 1, client)?;
    let control = execute_samples(baseline_request, &control_url, 1, client)?;
    let baseline_samples = sql_samples(&baseline, "sqli-baseline");
    let probe_samples = sql_samples(&probe, "sqli-probe");
    let control_samples = sql_samples(&control, "sqli-control");
    let policy = SqlInjectionPolicy {
        enable_error_stage: true,
        enable_boolean_stage: false,
        enable_timing_stage: false,
        maximum_time_delay_millis: 1_000,
    };
    let assessment = assess_sql_injection(
        &SqlInjectionContract {
            target_id: &target.id,
            endpoint: baseline_url.as_str(),
            method: NativeHttpMethod::Get,
            parameter_location: ParameterLocation::Query,
            parameter_name,
            explicitly_approved: true,
            time_probe_approved: false,
        },
        &SqlInjectionEvidence {
            baseline_error_samples: &baseline_samples,
            error_probe_samples: &probe_samples,
            error_control_samples: &control_samples,
            boolean_true: None,
            boolean_false: None,
            timing_probe: None,
            timing_control: None,
            requested_time_delay_millis: None,
        },
        policy,
        SqlInjectionLimits::default(),
    )
    .map_err(|error| ScannerError::HttpProbeFailed(error.to_string()))?;
    if assessment.decision != SqlInjectionDecision::Candidate {
        return Ok(Vec::new());
    }
    let candidate = assessment
        .candidate
        .expect("candidate decision includes candidate");
    Ok(vec![active_candidate_finding(
        "aegis.candidate.sql-injection",
        "SQL injection candidate requires confirmation",
        match candidate.confidence {
            NativeConfidence::High => FindingSeverity::High,
            NativeConfidence::Medium => FindingSeverity::Medium,
            NativeConfidence::Low => FindingSeverity::Low,
        },
        parameter_name,
        &candidate.candidate_id,
        &candidate.evidence_refs,
        "The native engine observed an error differential after a bounded query mutation. Manual confirmation is required before treating this as confirmed SQL injection.",
    )])
}

fn execute_samples(
    base: &HttpProbeRequest,
    url: &str,
    count: usize,
    client: &impl HttpProbeClient,
) -> Result<Vec<HttpProbeResponse>, ScannerError> {
    (0..count)
        .map(|_| {
            client.execute(&HttpProbeRequest {
                url: url.to_string(),
                ..base.clone()
            })
        })
        .collect()
}

fn xss_samples<'a>(
    responses: &'a [HttpProbeResponse],
    prefix: &'static str,
) -> Vec<XssResponseSample<'a>> {
    responses
        .iter()
        .enumerate()
        .map(|(index, response)| XssResponseSample {
            content_type: header_value(response, "content-type").unwrap_or("text/html"),
            body_view: &response.body_sample,
            body_view_truncated: false,
            evidence_ref: sample_ref(prefix, index),
        })
        .collect()
}

fn sql_samples<'a>(
    responses: &'a [HttpProbeResponse],
    prefix: &'static str,
) -> Vec<SqlResponseSample<'a>> {
    responses
        .iter()
        .enumerate()
        .map(|(index, response)| SqlResponseSample {
            content_type: header_value(response, "content-type").unwrap_or("text/plain"),
            body_view: &response.body_sample,
            body_view_truncated: false,
            evidence_ref: sample_ref(prefix, index),
        })
        .collect()
}

fn sample_ref(prefix: &'static str, index: usize) -> &'static str {
    match (prefix, index) {
        ("xss-baseline", 0) => "xss-baseline-1",
        ("xss-baseline", _) => "xss-baseline-2",
        ("xss-probe", 0) => "xss-probe-1",
        ("xss-probe", _) => "xss-probe-2",
        ("xss-control", 0) => "xss-control-1",
        ("xss-control", _) => "xss-control-2",
        ("sqli-baseline", _) => "sqli-baseline-1",
        ("sqli-probe", _) => "sqli-probe-1",
        ("sqli-control", _) => "sqli-control-1",
        _ => "native-sample",
    }
}

fn analyze_passive_response_for_target(
    target_id: &str,
    method: &str,
    response: &HttpProbeResponse,
) -> Vec<PassiveFinding> {
    let method = native_method(method).unwrap_or(NativeHttpMethod::Get);
    let passive_headers = response
        .headers
        .iter()
        .map(|header| PassiveHeader {
            name: header.name.as_str(),
            value: header.value.as_str(),
        })
        .collect::<Vec<_>>();
    let evidence_ref = "evidence-passive-baseline";
    let mut findings = Vec::new();
    if let Ok(assessment) = assess_security_headers(
        &SecurityHeaderContext {
            target_id,
            endpoint: &response.final_url,
            method,
            status_code: response.status_code,
            headers: &passive_headers,
            evidence_ref,
        },
        &SecurityHeaderPolicy::default(),
        SecurityHeaderLimits::default(),
    ) {
        findings.extend(
            assessment
                .findings
                .into_iter()
                .map(|finding| passive_from_canonical(finding, false)),
        );
    }
    if let Ok(assessment) = assess_content_exposure(
        &ContentExposureContext {
            target_id,
            endpoint: &response.final_url,
            method,
            status_code: response.status_code,
            headers: &passive_headers,
            body_view: &response.body_sample,
            body_view_truncated: false,
            evidence_ref,
        },
        ContentExposureLimits::default(),
    ) {
        findings.extend(
            assessment
                .findings
                .into_iter()
                .map(|finding| passive_from_canonical(finding, false)),
        );
    }
    findings
}

fn passive_from_canonical(
    finding: CanonicalFinding,
    requires_manual_confirmation: bool,
) -> PassiveFinding {
    let rule_id = finding.provenance.rule_id.clone();
    let evidence_refs = finding.evidence_refs.clone();
    let fingerprint = finding.fingerprint.clone();
    let parameter_name = finding.identity.parameter_name.clone();
    PassiveFinding {
        rule_id: rule_id.clone(),
        title: title_for_rule(&rule_id, finding.title.as_str()).to_string(),
        severity: severity_from_native(finding.severity),
        evidence: native_evidence(
            "native-passive",
            &fingerprint,
            &evidence_refs,
            parameter_name.as_deref(),
            requires_manual_confirmation,
            &format!(
                "Native engine finding {} on {}",
                rule_id, finding.identity.canonical_endpoint
            ),
        ),
        recommendation: recommendation_for_rule(&rule_id, requires_manual_confirmation).to_string(),
    }
}

fn active_candidate_finding(
    rule_id: &str,
    title: &str,
    severity: FindingSeverity,
    parameter_name: &str,
    fingerprint: &str,
    evidence_refs: &[String],
    summary: &str,
) -> PassiveFinding {
    PassiveFinding {
        rule_id: rule_id.to_string(),
        title: title.to_string(),
        severity,
        evidence: native_evidence(
            "native-active-candidate",
            fingerprint,
            evidence_refs,
            Some(parameter_name),
            true,
            summary,
        ),
        recommendation:
            "Review the candidate evidence, reproduce manually in an authorized test window, and only then mark it as confirmed remediation work."
                .to_string(),
    }
}

fn native_evidence(
    source: &str,
    fingerprint: &str,
    evidence_refs: &[String],
    parameter_name: Option<&str>,
    requires_manual_confirmation: bool,
    summary: &str,
) -> String {
    let metadata = serde_json::json!({
        "source": source,
        "fingerprint": fingerprint,
        "evidence_refs": evidence_refs,
        "parameter_name": parameter_name,
        "requires_manual_confirmation": requires_manual_confirmation
    });
    format!("{NATIVE_META_PREFIX}{metadata}\n{summary}")
}

pub fn split_native_evidence(value: &str) -> (Option<serde_json::Value>, String) {
    let Some(rest) = value.strip_prefix(NATIVE_META_PREFIX) else {
        return (None, value.to_string());
    };
    let Some((metadata, summary)) = rest.split_once('\n') else {
        return (None, value.to_string());
    };
    let parsed = serde_json::from_str(metadata).ok();
    (parsed, summary.to_string())
}

fn native_request_for_probe(
    request_id: &str,
    request: &HttpProbeRequest,
    target: &ApprovedTarget,
) -> Result<NativeRequestRecord, ScannerError> {
    let method = native_method(&request.method)?;
    let record = NativeRequestRecord {
        request_id: format!(
            "{}-{}",
            request_id,
            &short_hash(request.url.as_bytes())[..16]
        ),
        target_id: target.target_id.clone(),
        method,
        url: request.url.clone(),
        purpose: RequestPurpose::Probe,
        headers: vec![HeaderRecord::new("Accept", "*/*").map_err(|_| {
            ScannerError::HttpProbeFailed("native header validation failed".to_string())
        })?],
        payload: None,
        credential_ref: None,
    };
    record
        .validate(target)
        .map_err(|error| ScannerError::HttpProbeFailed(error.to_string()))?;
    Ok(record)
}

fn approved_target_for_url(target_id: &str, value: &str) -> Result<ApprovedTarget, ScannerError> {
    let parsed = Url::parse(value.trim()).map_err(|_| ScannerError::InvalidUrl)?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(ScannerError::UnsupportedScheme);
    }
    let mut origin = parsed.clone();
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);
    let path_prefix = if parsed.path().is_empty() {
        "/"
    } else {
        parsed.path()
    };
    ApprovedTarget::new(safe_target_id(target_id), origin.to_string(), path_prefix)
        .map_err(|error| ScannerError::HttpProbeFailed(error.to_string()))
}

fn safe_target_id(value: &str) -> String {
    let cleaned = value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        .take(40)
        .collect::<String>();
    if cleaned.is_empty() {
        "target-desktop".to_string()
    } else {
        cleaned
    }
}

fn native_method(method: &str) -> Result<NativeHttpMethod, ScannerError> {
    match method.trim().to_ascii_uppercase().as_str() {
        "GET" => Ok(NativeHttpMethod::Get),
        "HEAD" => Ok(NativeHttpMethod::Head),
        _ => Err(ScannerError::UnsupportedMethod),
    }
}

fn validate_target(target: &ScanTarget) -> Result<(), ScannerError> {
    if target.approval_note.trim().is_empty() {
        return Err(ScannerError::MissingApproval);
    }

    let url = Url::parse(target.url.trim()).map_err(|_| ScannerError::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ScannerError::UnsupportedScheme);
    }

    if is_private_or_local_url(&url) && !target.allow_private_network {
        return Err(ScannerError::PrivateNetworkNotAllowed);
    }

    Ok(())
}

fn validate_passive_method(method: Option<&str>) -> Result<String, ScannerError> {
    let method = method.unwrap_or("GET").trim().to_ascii_uppercase();
    match method.as_str() {
        "GET" | "HEAD" => Ok(method),
        _ => Err(ScannerError::UnsupportedMethod),
    }
}

fn query_parameter_names(url: &Url) -> Vec<String> {
    let mut names = Vec::new();
    for (name, _) in url.query_pairs() {
        let name = name.to_string();
        if !name.is_empty() && !names.contains(&name) {
            names.push(name);
            if names.len() >= MAX_SAFE_ACTIVE_PARAMETERS {
                break;
            }
        }
    }
    names
}

fn mutate_query_parameter(url: &Url, parameter_name: &str, value: &str) -> String {
    let mut mutated = url.clone();
    let pairs = url
        .query_pairs()
        .map(|(name, current_value)| {
            if name == parameter_name {
                (name.to_string(), value.to_string())
            } else {
                (name.to_string(), current_value.to_string())
            }
        })
        .collect::<Vec<_>>();
    mutated.query_pairs_mut().clear().extend_pairs(pairs);
    mutated.to_string()
}

fn header_value<'a>(response: &'a HttpProbeResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

fn severity_from_native(severity: NativeSeverity) -> FindingSeverity {
    match severity {
        NativeSeverity::Critical | NativeSeverity::High => FindingSeverity::High,
        NativeSeverity::Medium => FindingSeverity::Medium,
        NativeSeverity::Low => FindingSeverity::Low,
        NativeSeverity::Info => FindingSeverity::Info,
    }
}

fn title_for_rule<'a>(rule_id: &str, fallback: &'a str) -> &'a str {
    match rule_id {
        "aegis.config.header.csp" => "Content-Security-Policy header is missing or weak",
        "aegis.config.header.frame-protection" => "Frame embedding protection is missing",
        "aegis.config.header.nosniff" => "X-Content-Type-Options nosniff is missing",
        "aegis.config.header.hsts" => "Strict-Transport-Security is missing or weak",
        "aegis.config.cookie.secure" => "Cookie Secure attribute is missing",
        "aegis.config.cookie.httponly" => "Cookie HttpOnly attribute is missing",
        "aegis.config.cookie.samesite" => "Cookie SameSite attribute is missing or unapproved",
        "aegis.config.cookie.host-prefix" => "__Host- cookie prefix contract is violated",
        "aegis.config.cookie.secure-prefix" => "__Secure- cookie prefix contract is violated",
        "aegis.exposure.version-banner" => "Version banner disclosure candidate",
        "aegis.exposure.stack-trace" => "Stack trace disclosure candidate",
        "aegis.exposure.secret-pattern" => "Secret pattern exposure candidate",
        "aegis.exposure.secret-assignment" => "Secret assignment exposure candidate",
        _ => fallback,
    }
}

fn recommendation_for_rule(rule_id: &str, requires_manual_confirmation: bool) -> &'static str {
    if requires_manual_confirmation {
        return "Manually confirm the candidate before remediation or status changes.";
    }
    match rule_id {
        "aegis.config.header.csp" => "Set a restrictive Content-Security-Policy for browser-facing responses.",
        "aegis.config.header.frame-protection" => "Set CSP frame-ancestors or X-Frame-Options to restrict framing.",
        "aegis.config.header.nosniff" => "Set X-Content-Type-Options: nosniff for textual/browser resources.",
        "aegis.config.header.hsts" => "Set Strict-Transport-Security with an appropriate max-age on HTTPS responses.",
        "aegis.config.cookie.secure" => "Mark session and sensitive cookies as Secure.",
        "aegis.config.cookie.httponly" => "Mark cookies that do not need script access as HttpOnly.",
        "aegis.config.cookie.samesite" => "Set SameSite=Lax or Strict unless cross-site use is explicitly required.",
        "aegis.config.cookie.host-prefix" => "Ensure __Host- cookies are Secure, path=/, and omit Domain.",
        "aegis.config.cookie.secure-prefix" => "Ensure __Secure- cookies always include Secure.",
        "aegis.exposure.version-banner" => "Reduce product and framework version disclosure in response headers or body.",
        "aegis.exposure.stack-trace" => "Disable detailed error output in production and return generic error pages.",
        "aegis.exposure.secret-pattern" | "aegis.exposure.secret-assignment" => {
            "Remove exposed secret material, rotate affected credentials, and prevent secret rendering in responses."
        }
        _ => "Review the native engine evidence and apply the control recommended by the rule owner.",
    }
}

fn short_hash(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn is_private_or_local_url(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.octets()[0] == 0
        }
        Some(Host::Ipv6(address)) => {
            address.is_loopback()
                || address.is_unspecified()
                || address.segments()[0] & 0xfe00 == 0xfc00
                || address.segments()[0] & 0xffc0 == 0xfe80
        }
        Some(Host::Domain(domain)) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            matches!(domain.as_str(), "localhost" | "localhost.localdomain")
        }
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct StaticClient {
        responses: Mutex<HashMap<String, HttpProbeResponse>>,
    }

    impl StaticClient {
        fn with(entries: Vec<(&str, HttpProbeResponse)>) -> Self {
            Self {
                responses: Mutex::new(
                    entries
                        .into_iter()
                        .map(|(url, response)| (url.to_string(), response))
                        .collect(),
                ),
            }
        }
    }

    impl HttpProbeClient for StaticClient {
        fn execute(&self, request: &HttpProbeRequest) -> Result<HttpProbeResponse, ScannerError> {
            self.responses
                .lock()
                .expect("responses")
                .get(&request.url)
                .cloned()
                .ok_or_else(|| ScannerError::HttpProbeFailed(format!("missing {}", request.url)))
        }
    }

    fn target(url: &str, allow_private_network: bool, approval_note: &str) -> ScanTarget {
        ScanTarget {
            id: "target-1".to_string(),
            method: Some("GET".to_string()),
            url: url.to_string(),
            approval_note: approval_note.to_string(),
            allow_private_network,
        }
    }

    fn response(url: &str, body: &[u8], content_type: &str) -> HttpProbeResponse {
        HttpProbeResponse {
            final_url: url.to_string(),
            status_code: 200,
            headers: vec![HttpHeader {
                name: "Content-Type".to_string(),
                value: content_type.to_string(),
            }],
            body_sample: body.to_vec(),
        }
    }

    #[test]
    fn validates_sensitive_query_values_before_probe_build() {
        let error = build_passive_probe(&target(
            "https://example.com/search?token=secret",
            false,
            "owned",
        ))
        .expect_err("sensitive query rejected");

        assert!(matches!(error, ScannerError::HttpProbeFailed(_)));
    }

    #[test]
    fn blocks_private_targets_without_advanced_approval() {
        let error = build_passive_probe(&target("http://127.0.0.1/", false, "owned"))
            .expect_err("private target rejected");

        assert_eq!(error, ScannerError::PrivateNetworkNotAllowed);
    }

    #[test]
    fn reports_native_passive_header_findings() {
        let response = HttpProbeResponse {
            final_url: "https://example.com".to_string(),
            status_code: 200,
            headers: vec![HttpHeader {
                name: "Content-Type".to_string(),
                value: "text/html; charset=utf-8".to_string(),
            }],
            body_sample: b"<html></html>".to_vec(),
        };

        let findings = analyze_passive_response(&response);

        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "aegis.config.header.csp"));
        assert!(findings
            .iter()
            .any(|finding| finding.evidence.starts_with(NATIVE_META_PREFIX)));
    }

    #[test]
    fn reports_xss_candidate_as_manual_confirmation_required() {
        let base = "https://example.com/search?q=hello";
        let marker = format!(
            "{XSS_MARKER_PREFIX}{}",
            &short_hash("target-1:q:xss".as_bytes())[..16]
        );
        let control = format!(
            "{XSS_MARKER_PREFIX}{}",
            &short_hash(marker.as_bytes())[..16]
        );
        let client = StaticClient::with(vec![
            (base, response(base, b"<html>hello</html>", "text/html")),
            (
                &mutate_query_parameter(&Url::parse(base).unwrap(), "q", &marker),
                response(
                    base,
                    format!("<html>{marker}</html>").as_bytes(),
                    "text/html",
                ),
            ),
            (
                &mutate_query_parameter(&Url::parse(base).unwrap(), "q", &control),
                response(
                    base,
                    format!("<html>{control}</html>").as_bytes(),
                    "text/html",
                ),
            ),
            (
                &mutate_query_parameter(&Url::parse(base).unwrap(), "q", SQLI_PROBE_VALUE),
                response(base, b"normal", "text/plain"),
            ),
            (
                &mutate_query_parameter(&Url::parse(base).unwrap(), "q", SQLI_CONTROL_VALUE),
                response(base, b"normal", "text/plain"),
            ),
        ]);

        let findings = run_safe_active_verifiers(&target(base, false, "owned"), &client)
            .expect("active candidates");

        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "aegis.candidate.reflected-xss"
                && finding
                    .evidence
                    .contains("\"requires_manual_confirmation\":true")));
    }

    #[test]
    fn splits_native_evidence_metadata() {
        let evidence = native_evidence(
            "native-active-candidate",
            "candidate-1",
            &["ref-1".to_string()],
            Some("q"),
            true,
            "summary",
        );

        let (metadata, summary) = split_native_evidence(&evidence);

        assert_eq!(summary, "summary");
        assert_eq!(
            metadata.and_then(|value| value["source"].as_str().map(str::to_string)),
            Some("native-active-candidate".to_string())
        );
    }
}
