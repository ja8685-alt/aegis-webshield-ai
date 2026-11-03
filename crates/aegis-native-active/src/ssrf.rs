use std::collections::BTreeSet;
use std::fmt::{Debug, Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aegis_native_engine::{Confidence, FindingIdentity, HttpMethod, ParameterLocation};
use url::{Host, Url};

use crate::{ComparisonAssessment, ComparisonDecision, ComparisonSignal};

const MAX_ALLOWED_ORIGINS: usize = 16;
const MAX_PINNED_ADDRESSES: usize = 8;
const MAX_CALLBACK_EVENTS: usize = 4;
const MAX_TOKEN_BYTES: usize = 32;
const MAX_CALLBACK_WINDOW_MILLIS: u64 = 900_000;
const MAX_MUTATION_REQUESTS: usize = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SsrfMode {
    ControlledCallback,
    ResponseDifferential,
}

pub struct SsrfContract<'a> {
    pub target_id: &'a str,
    pub endpoint: &'a str,
    pub method: HttpMethod,
    pub parameter_location: ParameterLocation,
    pub parameter_name: &'a str,
    pub mode: SsrfMode,
    pub controlled_origin: &'a str,
    pub allowed_controlled_origins: &'a [&'a str],
    pub pinned_public_addresses: &'a [IpAddr],
    pub probe_token: &'a str,
    pub control_token: &'a str,
    pub issued_at_millis: u64,
    pub expires_at_millis: u64,
    pub explicitly_approved: bool,
}

impl Debug for SsrfContract<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SsrfContract")
            .field("method", &self.method)
            .field("parameter_location", &self.parameter_location)
            .field("parameter_name_bytes", &self.parameter_name.len())
            .field("mode", &self.mode)
            .field("controlled_origin_bytes", &self.controlled_origin.len())
            .field(
                "allowed_origin_count",
                &self.allowed_controlled_origins.len(),
            )
            .field("pinned_address_count", &self.pinned_public_addresses.len())
            .field("probe_token_bytes", &self.probe_token.len())
            .field("control_token_bytes", &self.control_token.len())
            .field(
                "callback_window_millis",
                &self.expires_at_millis.saturating_sub(self.issued_at_millis),
            )
            .field("explicitly_approved", &self.explicitly_approved)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SsrfLimits {
    pub max_allowed_origins: usize,
    pub max_pinned_addresses: usize,
    pub max_callback_events: usize,
    pub max_mutation_requests: usize,
}

impl Default for SsrfLimits {
    fn default() -> Self {
        Self {
            max_allowed_origins: MAX_ALLOWED_ORIGINS,
            max_pinned_addresses: MAX_PINNED_ADDRESSES,
            max_callback_events: MAX_CALLBACK_EVENTS,
            max_mutation_requests: MAX_MUTATION_REQUESTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SsrfRuntimeError {
    InvalidLimits,
    InvalidContract,
    InvalidControlledOrigin,
    ForbiddenDestination,
    UnapprovedProbe,
    InvalidInput,
    RequestBudgetExceeded,
}

impl Display for SsrfRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "SSRF limits are invalid",
            Self::InvalidContract => "SSRF contract is invalid",
            Self::InvalidControlledOrigin => "SSRF controlled origin is invalid",
            Self::ForbiddenDestination => "SSRF controlled destination is forbidden",
            Self::UnapprovedProbe => "SSRF probe was not explicitly approved",
            Self::InvalidInput => "SSRF evidence input is invalid",
            Self::RequestBudgetExceeded => "SSRF mutation request budget was exceeded",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SsrfRuntimeError {}

#[derive(Clone, Eq, PartialEq)]
pub struct SsrfProbePlan {
    mode: SsrfMode,
    mutation_request_count: usize,
    destination_origin_bytes: usize,
}

impl SsrfProbePlan {
    pub fn mode(&self) -> SsrfMode {
        self.mode
    }

    pub fn mutation_request_count(&self) -> usize {
        self.mutation_request_count
    }
}

impl Debug for SsrfProbePlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SsrfProbePlan")
            .field("mode", &self.mode)
            .field("mutation_request_count", &self.mutation_request_count)
            .field("destination_origin_bytes", &self.destination_origin_bytes)
            .finish()
    }
}

pub struct CallbackEvent<'a> {
    pub token: &'a str,
    pub received_at_millis: u64,
    pub signature_verified: bool,
    pub evidence_ref: &'a str,
}

impl Debug for CallbackEvent<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CallbackEvent")
            .field("token_bytes", &self.token.len())
            .field("received_at_millis", &self.received_at_millis)
            .field("signature_verified", &self.signature_verified)
            .finish()
    }
}

pub struct SsrfEvidence<'a> {
    pub probe_callback_events: &'a [CallbackEvent<'a>],
    pub control_callback_events: &'a [CallbackEvent<'a>],
    pub probe_comparison: Option<&'a ComparisonAssessment>,
    pub control_comparison: Option<&'a ComparisonAssessment>,
}

impl Debug for SsrfEvidence<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SsrfEvidence")
            .field(
                "probe_callback_event_count",
                &self.probe_callback_events.len(),
            )
            .field(
                "control_callback_event_count",
                &self.control_callback_events.len(),
            )
            .field("has_probe_comparison", &self.probe_comparison.is_some())
            .field("has_control_comparison", &self.control_comparison.is_some())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SsrfDecision {
    Candidate,
    NotObserved,
    Abstain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SsrfCandidate {
    pub candidate_id: String,
    pub mode: SsrfMode,
    pub confidence: Confidence,
    pub evidence_refs: Vec<String>,
    pub requires_manual_confirmation: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SsrfAssessment {
    pub decision: SsrfDecision,
    pub candidate: Option<SsrfCandidate>,
    pub probe_callback_count: usize,
    pub control_callback_count: usize,
}

pub fn plan_ssrf_probe(
    contract: &SsrfContract<'_>,
    limits: SsrfLimits,
) -> Result<SsrfProbePlan, SsrfRuntimeError> {
    validate_limits(limits)?;
    validate_contract(contract, limits)?;
    if !contract.explicitly_approved {
        return Err(SsrfRuntimeError::UnapprovedProbe);
    }
    let mutation_request_count = match contract.mode {
        SsrfMode::ControlledCallback => 2,
        SsrfMode::ResponseDifferential => 6,
    };
    if mutation_request_count > limits.max_mutation_requests {
        return Err(SsrfRuntimeError::RequestBudgetExceeded);
    }
    Ok(SsrfProbePlan {
        mode: contract.mode,
        mutation_request_count,
        destination_origin_bytes: contract.controlled_origin.len(),
    })
}

pub fn assess_ssrf(
    contract: &SsrfContract<'_>,
    evidence: &SsrfEvidence<'_>,
    now_millis: u64,
    limits: SsrfLimits,
) -> Result<SsrfAssessment, SsrfRuntimeError> {
    let identity = validate_contract(contract, limits)?;
    plan_ssrf_probe(contract, limits)?;
    if now_millis < contract.issued_at_millis || now_millis > contract.expires_at_millis {
        return Err(SsrfRuntimeError::InvalidInput);
    }
    match contract.mode {
        SsrfMode::ControlledCallback => assess_callback(contract, evidence, identity, limits),
        SsrfMode::ResponseDifferential => assess_differential(evidence, identity),
    }
}

fn assess_callback(
    contract: &SsrfContract<'_>,
    evidence: &SsrfEvidence<'_>,
    identity: FindingIdentity,
    limits: SsrfLimits,
) -> Result<SsrfAssessment, SsrfRuntimeError> {
    if evidence.probe_comparison.is_some()
        || evidence.control_comparison.is_some()
        || evidence.probe_callback_events.len() > limits.max_callback_events
        || evidence.control_callback_events.len() > limits.max_callback_events
    {
        return Err(SsrfRuntimeError::InvalidInput);
    }
    validate_events(
        evidence.probe_callback_events,
        contract.probe_token,
        contract,
    )?;
    validate_events(
        evidence.control_callback_events,
        contract.control_token,
        contract,
    )?;
    let probe_count = evidence.probe_callback_events.len();
    let control_count = evidence.control_callback_events.len();
    if control_count > 0 {
        return Ok(assessment(
            SsrfDecision::Abstain,
            None,
            probe_count,
            control_count,
        ));
    }
    if probe_count == 0 {
        return Ok(assessment(SsrfDecision::NotObserved, None, 0, 0));
    }
    let refs = evidence
        .probe_callback_events
        .iter()
        .map(|event| event.evidence_ref)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_string)
        .collect();
    Ok(assessment(
        SsrfDecision::Candidate,
        Some(candidate(
            &identity,
            SsrfMode::ControlledCallback,
            Confidence::High,
            refs,
        )),
        probe_count,
        control_count,
    ))
}

fn assess_differential(
    evidence: &SsrfEvidence<'_>,
    identity: FindingIdentity,
) -> Result<SsrfAssessment, SsrfRuntimeError> {
    if !evidence.probe_callback_events.is_empty() || !evidence.control_callback_events.is_empty() {
        return Err(SsrfRuntimeError::InvalidInput);
    }
    let (Some(probe), Some(control)) = (evidence.probe_comparison, evidence.control_comparison)
    else {
        return Err(SsrfRuntimeError::InvalidInput);
    };
    if probe.decision == ComparisonDecision::Abstain
        || control.decision == ComparisonDecision::Abstain
    {
        return Ok(assessment(SsrfDecision::Abstain, None, 0, 0));
    }
    let meaningful_change = probe.decision == ComparisonDecision::Changed
        && probe.observations.iter().any(|item| {
            matches!(
                item.signal,
                ComparisonSignal::StatusChanged | ComparisonSignal::TimingChanged
            )
        });
    if !meaningful_change || control.decision != ComparisonDecision::Stable {
        return Ok(assessment(SsrfDecision::NotObserved, None, 0, 0));
    }
    let refs = probe
        .evidence_refs
        .iter()
        .chain(&control.evidence_refs)
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_string)
        .collect();
    Ok(assessment(
        SsrfDecision::Candidate,
        Some(candidate(
            &identity,
            SsrfMode::ResponseDifferential,
            Confidence::Low,
            refs,
        )),
        0,
        0,
    ))
}

fn validate_limits(limits: SsrfLimits) -> Result<(), SsrfRuntimeError> {
    if limits.max_allowed_origins == 0
        || limits.max_allowed_origins > MAX_ALLOWED_ORIGINS
        || limits.max_pinned_addresses == 0
        || limits.max_pinned_addresses > MAX_PINNED_ADDRESSES
        || limits.max_callback_events == 0
        || limits.max_callback_events > MAX_CALLBACK_EVENTS
        || limits.max_mutation_requests == 0
        || limits.max_mutation_requests > MAX_MUTATION_REQUESTS
    {
        return Err(SsrfRuntimeError::InvalidLimits);
    }
    Ok(())
}

fn validate_contract(
    contract: &SsrfContract<'_>,
    limits: SsrfLimits,
) -> Result<FindingIdentity, SsrfRuntimeError> {
    validate_limits(limits)?;
    if !matches!(contract.method, HttpMethod::Get | HttpMethod::Post)
        || !matches!(
            contract.parameter_location,
            ParameterLocation::Query | ParameterLocation::Form | ParameterLocation::JsonBody
        )
        || !valid_token(contract.probe_token)
        || !valid_token(contract.control_token)
        || contract.probe_token == contract.control_token
        || contract.allowed_controlled_origins.is_empty()
        || contract.allowed_controlled_origins.len() > limits.max_allowed_origins
        || contract.pinned_public_addresses.is_empty()
        || contract.pinned_public_addresses.len() > limits.max_pinned_addresses
        || contract.issued_at_millis >= contract.expires_at_millis
        || contract.expires_at_millis - contract.issued_at_millis > MAX_CALLBACK_WINDOW_MILLIS
    {
        return Err(SsrfRuntimeError::InvalidContract);
    }
    let controlled = validate_origin(contract.controlled_origin)?;
    let mut allowed = BTreeSet::new();
    for origin in contract.allowed_controlled_origins {
        validate_origin(origin)?;
        if !allowed.insert(*origin) {
            return Err(SsrfRuntimeError::InvalidContract);
        }
    }
    if !allowed.contains(contract.controlled_origin) {
        return Err(SsrfRuntimeError::InvalidControlledOrigin);
    }
    if contract
        .pinned_public_addresses
        .iter()
        .any(|address| !is_public_destination(*address))
    {
        return Err(SsrfRuntimeError::ForbiddenDestination);
    }
    let literal_address = match controlled.host() {
        Some(Host::Ipv4(address)) => Some(IpAddr::V4(address)),
        Some(Host::Ipv6(address)) => Some(IpAddr::V6(address)),
        Some(Host::Domain(_)) => None,
        None => return Err(SsrfRuntimeError::InvalidControlledOrigin),
    };
    if literal_address.is_some_and(|address| !contract.pinned_public_addresses.contains(&address)) {
        return Err(SsrfRuntimeError::ForbiddenDestination);
    }
    FindingIdentity::new(
        contract.target_id,
        contract.method,
        contract.endpoint,
        "CWE-918",
        contract.parameter_location,
        Some(contract.parameter_name.to_string()),
    )
    .map_err(|_| SsrfRuntimeError::InvalidContract)
}

fn validate_origin(origin: &str) -> Result<Url, SsrfRuntimeError> {
    if origin.is_empty() || origin.len() > 2_048 || origin.ends_with('/') {
        return Err(SsrfRuntimeError::InvalidControlledOrigin);
    }
    let parsed = Url::parse(origin).map_err(|_| SsrfRuntimeError::InvalidControlledOrigin)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.origin().ascii_serialization() != origin
    {
        return Err(SsrfRuntimeError::InvalidControlledOrigin);
    }
    Ok(parsed)
}

fn valid_token(value: &str) -> bool {
    value.len() == MAX_TOKEN_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn validate_events(
    events: &[CallbackEvent<'_>],
    expected_token: &str,
    contract: &SsrfContract<'_>,
) -> Result<(), SsrfRuntimeError> {
    for event in events {
        if !event.signature_verified
            || event.token != expected_token
            || event.received_at_millis < contract.issued_at_millis
            || event.received_at_millis > contract.expires_at_millis
            || event.evidence_ref.is_empty()
            || event.evidence_ref.len() > 64
            || !event.evidence_ref.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(SsrfRuntimeError::InvalidInput);
        }
    }
    Ok(())
}

fn is_public_destination(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_documentation()
        || octets[0] == 0
        || octets[0] >= 240
        || octets[0] == 100 && (64..=127).contains(&octets[1])
        || octets[0] == 192 && octets[1] == 0 && octets[2] == 0
        || octets[0] == 198 && matches!(octets[1], 18 | 19)
        || octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || has_ipv6_prefix(address, 0x7e, 7)
        || has_ipv6_prefix(address, 0x3fb, 10)
        || has_ipv6_prefix(address, 0x3fa, 10)
        || has_ipv6_prefix(address, 0x20010db8, 32)
        || has_ipv6_prefix(address, 0x200100020000, 48)
        || has_ipv6_prefix(address, 0x0064ff9b0000000000000000, 96)
        || has_ipv6_prefix(address, 0x0064ff9b0001, 48)
        || has_ipv6_prefix(address, 0x20010000, 32)
        || has_ipv6_prefix(address, 0x2002, 16)
        || has_ipv6_prefix(address, 0x0100000000000000, 64)
        || !has_ipv6_prefix(address, 0b001, 3))
}

fn has_ipv6_prefix(address: Ipv6Addr, prefix: u128, bits: u32) -> bool {
    let shift = 128 - bits;
    u128::from(address) >> shift == prefix
}

fn candidate(
    identity: &FindingIdentity,
    mode: SsrfMode,
    confidence: Confidence,
    evidence_refs: Vec<String>,
) -> SsrfCandidate {
    SsrfCandidate {
        candidate_id: format!("ssrf-candidate-{}", &identity.fingerprint()[..24]),
        mode,
        confidence,
        evidence_refs,
        requires_manual_confirmation: true,
    }
}

fn assessment(
    decision: SsrfDecision,
    candidate: Option<SsrfCandidate>,
    probe_callback_count: usize,
    control_callback_count: usize,
) -> SsrfAssessment {
    SsrfAssessment {
        decision,
        candidate,
        probe_callback_count,
        control_callback_count,
    }
}

pub(crate) fn benchmark_outcomes() -> Result<(bool, bool), SsrfRuntimeError> {
    const PROBE_TOKEN: &str = "probe000000000000000000000000000";
    const CONTROL_TOKEN: &str = "control0000000000000000000000000";
    const PUBLIC_ADDRESSES: [IpAddr; 1] = [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))];
    let contract = SsrfContract {
        target_id: "benchmark-target",
        endpoint: "https://benchmark.invalid/fetch",
        method: HttpMethod::Post,
        parameter_location: ParameterLocation::JsonBody,
        parameter_name: "url",
        mode: SsrfMode::ControlledCallback,
        controlled_origin: "https://callback.invalid",
        allowed_controlled_origins: &["https://callback.invalid"],
        pinned_public_addresses: &PUBLIC_ADDRESSES,
        probe_token: PROBE_TOKEN,
        control_token: CONTROL_TOKEN,
        issued_at_millis: 1_000,
        expires_at_millis: 61_000,
        explicitly_approved: true,
    };
    plan_ssrf_probe(&contract, SsrfLimits::default())?;
    let probe = [CallbackEvent {
        token: PROBE_TOKEN,
        received_at_millis: 2_000,
        signature_verified: true,
        evidence_ref: "benchmark-callback",
    }];
    let positive_evidence = SsrfEvidence {
        probe_callback_events: &probe,
        control_callback_events: &[],
        probe_comparison: None,
        control_comparison: None,
    };
    let positive = assess_ssrf(&contract, &positive_evidence, 3_000, SsrfLimits::default())?;
    let negative_evidence = SsrfEvidence {
        probe_callback_events: &[],
        control_callback_events: &[],
        probe_comparison: None,
        control_comparison: None,
    };
    let negative = assess_ssrf(&contract, &negative_evidence, 3_000, SsrfLimits::default())?;
    Ok((
        positive.decision == SsrfDecision::Candidate && positive.candidate.is_some(),
        negative.decision == SsrfDecision::Candidate || negative.candidate.is_some(),
    ))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use aegis_native_engine::{HttpMethod, ParameterLocation};

    use super::{
        assess_ssrf, plan_ssrf_probe, CallbackEvent, SsrfContract, SsrfDecision, SsrfEvidence,
        SsrfLimits, SsrfMode, SsrfRuntimeError,
    };
    use crate::{
        compare_responses, ComparisonLimits, ComparisonPolicy, ResponseComparisonInput,
        ResponseSample,
    };

    const PROBE_TOKEN: &str = "probe000000000000000000000000000";
    const CONTROL_TOKEN: &str = "control0000000000000000000000000";
    const PUBLIC_ADDRESSES: [IpAddr; 1] = [IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34))];

    fn contract(mode: SsrfMode) -> SsrfContract<'static> {
        SsrfContract {
            target_id: "target-1",
            endpoint: "https://example.com/fetch",
            method: HttpMethod::Post,
            parameter_location: ParameterLocation::JsonBody,
            parameter_name: "url",
            mode,
            controlled_origin: "https://callback.example",
            allowed_controlled_origins: &["https://callback.example"],
            pinned_public_addresses: &PUBLIC_ADDRESSES,
            probe_token: PROBE_TOKEN,
            control_token: CONTROL_TOKEN,
            issued_at_millis: 1_000,
            expires_at_millis: 61_000,
            explicitly_approved: true,
        }
    }

    fn empty_evidence<'a>() -> SsrfEvidence<'a> {
        SsrfEvidence {
            probe_callback_events: &[],
            control_callback_events: &[],
            probe_comparison: None,
            control_comparison: None,
        }
    }

    fn comparison(status: u16, duration: [u64; 3]) -> crate::ComparisonAssessment {
        let make = |status_code, times: [u64; 3], evidence_ref: &'static str| {
            times
                .into_iter()
                .map(|duration_millis| ResponseSample {
                    status_code,
                    content_type: Some("text/plain"),
                    body_view: b"stable response",
                    body_view_truncated: false,
                    duration_millis,
                    evidence_ref,
                })
                .collect::<Vec<_>>()
        };
        let baseline = make(200, [90, 100, 110], "base-1");
        let probe = make(status, duration, "probe-1");
        let control = make(200, [92, 102, 112], "control-1");
        compare_responses(
            &ResponseComparisonInput {
                baseline: &baseline,
                probe: &probe,
                control: &control,
            },
            ComparisonPolicy::default(),
            ComparisonLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn callback_plan_is_two_requests_and_debug_hides_destination() {
        let contract = contract(SsrfMode::ControlledCallback);
        let plan = plan_ssrf_probe(&contract, SsrfLimits::default()).unwrap();
        assert_eq!(plan.mutation_request_count(), 2);
        let debug = format!("{contract:?} {plan:?}");
        assert!(!debug.contains("callback.example"));
        assert!(!debug.contains(PROBE_TOKEN));
    }

    #[test]
    fn signed_probe_callback_without_control_is_high_confidence_candidate() {
        let probe = [CallbackEvent {
            token: PROBE_TOKEN,
            received_at_millis: 2_000,
            signature_verified: true,
            evidence_ref: "callback-1",
        }];
        let evidence = SsrfEvidence {
            probe_callback_events: &probe,
            ..empty_evidence()
        };
        let assessment = assess_ssrf(
            &contract(SsrfMode::ControlledCallback),
            &evidence,
            3_000,
            SsrfLimits::default(),
        )
        .unwrap();
        assert_eq!(assessment.decision, SsrfDecision::Candidate);
        assert!(assessment.candidate.unwrap().requires_manual_confirmation);
    }

    #[test]
    fn control_callback_and_bad_signature_do_not_create_candidate() {
        let probe = [CallbackEvent {
            token: PROBE_TOKEN,
            received_at_millis: 2_000,
            signature_verified: true,
            evidence_ref: "callback-1",
        }];
        let control = [CallbackEvent {
            token: CONTROL_TOKEN,
            received_at_millis: 2_100,
            signature_verified: true,
            evidence_ref: "callback-2",
        }];
        let evidence = SsrfEvidence {
            probe_callback_events: &probe,
            control_callback_events: &control,
            ..empty_evidence()
        };
        assert_eq!(
            assess_ssrf(
                &contract(SsrfMode::ControlledCallback),
                &evidence,
                3_000,
                SsrfLimits::default(),
            )
            .unwrap()
            .decision,
            SsrfDecision::Abstain
        );

        let unsigned = [CallbackEvent {
            token: PROBE_TOKEN,
            received_at_millis: 2_000,
            signature_verified: false,
            evidence_ref: "callback-3",
        }];
        let unsigned_evidence = SsrfEvidence {
            probe_callback_events: &unsigned,
            ..empty_evidence()
        };
        assert_eq!(
            assess_ssrf(
                &contract(SsrfMode::ControlledCallback),
                &unsigned_evidence,
                3_000,
                SsrfLimits::default(),
            ),
            Err(SsrfRuntimeError::InvalidInput)
        );
    }

    #[test]
    fn response_differential_is_low_confidence_and_control_bound() {
        let probe = comparison(502, [900, 1_000, 1_100]);
        let control = comparison(200, [95, 105, 115]);
        let evidence = SsrfEvidence {
            probe_comparison: Some(&probe),
            control_comparison: Some(&control),
            ..empty_evidence()
        };
        let assessment = assess_ssrf(
            &contract(SsrfMode::ResponseDifferential),
            &evidence,
            3_000,
            SsrfLimits::default(),
        )
        .unwrap();
        assert_eq!(assessment.decision, SsrfDecision::Candidate);
        assert_eq!(
            assessment.candidate.unwrap().mode,
            SsrfMode::ResponseDifferential
        );
    }

    #[test]
    fn private_metadata_unapproved_and_expired_contracts_fail_closed() {
        let mut private = contract(SsrfMode::ControlledCallback);
        private.controlled_origin = "https://169.254.169.254";
        private.allowed_controlled_origins = &["https://169.254.169.254"];
        let private_addresses = ["169.254.169.254".parse().unwrap()];
        private.pinned_public_addresses = &private_addresses;
        assert_eq!(
            plan_ssrf_probe(&private, SsrfLimits::default()),
            Err(SsrfRuntimeError::ForbiddenDestination)
        );
        let mut unapproved = contract(SsrfMode::ControlledCallback);
        unapproved.explicitly_approved = false;
        assert_eq!(
            plan_ssrf_probe(&unapproved, SsrfLimits::default()),
            Err(SsrfRuntimeError::UnapprovedProbe)
        );
        assert!(assess_ssrf(
            &contract(SsrfMode::ControlledCallback),
            &empty_evidence(),
            70_000,
            SsrfLimits::default(),
        )
        .is_err());
    }
}
