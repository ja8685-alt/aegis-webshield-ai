use std::collections::BTreeSet;
use std::fmt::{Debug, Display, Formatter};

use aegis_native_engine::{FindingIdentity, HttpMethod, ParameterLocation};
use sha2::{Digest, Sha256};

const HARD_MAX_PLATFORMS: usize = 2;
const HARD_MAX_ENCODINGS: usize = 3;
const HARD_MAX_PROBES: usize = 6;
const HARD_MAX_MUTATION_REQUESTS: usize = 12;
const HARD_MAX_DEPTH: u8 = 4;
const HARD_MAX_SAMPLES_PER_ROLE: usize = 3;
const HARD_MAX_CANARY_BYTES: usize = 4_096;
const MAX_CANARY_PATH_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TraversalPlatform {
    Posix,
    Windows,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TraversalEncoding {
    Plain,
    PercentEncoded,
    DoublePercentEncoded,
}

pub struct PathTraversalContract<'a> {
    pub target_id: &'a str,
    pub endpoint: &'a str,
    pub method: HttpMethod,
    pub parameter_location: ParameterLocation,
    pub parameter_name: &'a str,
    pub canary_id: &'a str,
    pub canary_relative_path: &'a str,
    pub expected_canary_sha256: &'a str,
    pub expected_canary_bytes: usize,
    pub explicitly_approved: bool,
}

impl Debug for PathTraversalContract<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PathTraversalContract")
            .field("method", &self.method)
            .field("parameter_location", &self.parameter_location)
            .field("parameter_name_bytes", &self.parameter_name.len())
            .field("canary_id_bytes", &self.canary_id.len())
            .field(
                "canary_relative_path_bytes",
                &self.canary_relative_path.len(),
            )
            .field("expected_canary_bytes", &self.expected_canary_bytes)
            .field("explicitly_approved", &self.explicitly_approved)
            .finish()
    }
}

pub struct TraversalProbePolicy<'a> {
    pub platforms: &'a [TraversalPlatform],
    pub encodings: &'a [TraversalEncoding],
    pub maximum_depth: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathTraversalLimits {
    pub max_probes: usize,
    pub max_mutation_requests: usize,
    pub max_samples_per_role: usize,
    pub max_canary_bytes: usize,
}

impl Default for PathTraversalLimits {
    fn default() -> Self {
        Self {
            max_probes: HARD_MAX_PROBES,
            max_mutation_requests: HARD_MAX_MUTATION_REQUESTS,
            max_samples_per_role: HARD_MAX_SAMPLES_PER_ROLE,
            max_canary_bytes: HARD_MAX_CANARY_BYTES,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TraversalProbe {
    probe_id: String,
    platform: TraversalPlatform,
    encoding: TraversalEncoding,
    maximum_depth: u8,
    canary_id: String,
}

impl TraversalProbe {
    pub fn probe_id(&self) -> &str {
        &self.probe_id
    }

    pub fn platform(&self) -> TraversalPlatform {
        self.platform
    }

    pub fn encoding(&self) -> TraversalEncoding {
        self.encoding
    }

    pub fn maximum_depth(&self) -> u8 {
        self.maximum_depth
    }

    pub fn mutation_request_count(&self) -> usize {
        2
    }
}

impl Debug for TraversalProbe {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TraversalProbe")
            .field("probe_id", &self.probe_id)
            .field("platform", &self.platform)
            .field("encoding", &self.encoding)
            .field("maximum_depth", &self.maximum_depth)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathTraversalRuntimeError {
    InvalidLimits,
    InvalidPolicy,
    InvalidContract,
    UnapprovedProbe,
    InvalidProbe,
    InvalidInput,
    RequestBudgetExceeded,
}

impl Display for PathTraversalRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "path traversal limits are invalid",
            Self::InvalidPolicy => "path traversal policy is invalid",
            Self::InvalidContract => "path traversal contract is invalid",
            Self::UnapprovedProbe => "path traversal probe was not explicitly approved",
            Self::InvalidProbe => "path traversal probe is invalid",
            Self::InvalidInput => "path traversal evidence input is invalid",
            Self::RequestBudgetExceeded => "path traversal mutation request budget was exceeded",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PathTraversalRuntimeError {}

pub struct TraversalResponseSample<'a> {
    pub status_code: u16,
    pub body_view: &'a [u8],
    pub body_view_truncated: bool,
    pub evidence_ref: &'a str,
}

impl Debug for TraversalResponseSample<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TraversalResponseSample")
            .field("status_code", &self.status_code)
            .field("body_view_bytes", &self.body_view.len())
            .field("body_view_truncated", &self.body_view_truncated)
            .finish()
    }
}

pub struct PathTraversalInput<'a> {
    pub contract: PathTraversalContract<'a>,
    pub probe: &'a TraversalProbe,
    pub baseline: &'a [TraversalResponseSample<'a>],
    pub traversal: &'a [TraversalResponseSample<'a>],
    pub control: &'a [TraversalResponseSample<'a>],
}

impl Debug for PathTraversalInput<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PathTraversalInput")
            .field("contract", &self.contract)
            .field("probe", &self.probe)
            .field("baseline_samples", &self.baseline.len())
            .field("traversal_samples", &self.traversal.len())
            .field("control_samples", &self.control.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathTraversalDecision {
    Candidate,
    NotObserved,
    Abstain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathTraversalCandidate {
    pub candidate_id: String,
    pub platform: TraversalPlatform,
    pub encoding: TraversalEncoding,
    pub maximum_depth: u8,
    pub matched_canary_bytes: usize,
    pub evidence_refs: Vec<String>,
    pub requires_manual_confirmation: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathTraversalAssessment {
    pub decision: PathTraversalDecision,
    pub candidate: Option<PathTraversalCandidate>,
    pub baseline_canary_matches: usize,
    pub traversal_canary_matches: usize,
    pub control_canary_matches: usize,
}

pub fn plan_path_traversal_probes(
    contract: &PathTraversalContract<'_>,
    policy: &TraversalProbePolicy<'_>,
    limits: PathTraversalLimits,
) -> Result<Vec<TraversalProbe>, PathTraversalRuntimeError> {
    validate_limits(limits)?;
    validate_contract(contract)?;
    if contract.expected_canary_bytes > limits.max_canary_bytes {
        return Err(PathTraversalRuntimeError::InvalidContract);
    }
    if !contract.explicitly_approved {
        return Err(PathTraversalRuntimeError::UnapprovedProbe);
    }
    if policy.platforms.is_empty()
        || policy.platforms.len() > HARD_MAX_PLATFORMS
        || policy.encodings.is_empty()
        || policy.encodings.len() > HARD_MAX_ENCODINGS
        || policy.maximum_depth == 0
        || policy.maximum_depth > HARD_MAX_DEPTH
        || policy
            .platforms
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != policy.platforms.len()
        || policy
            .encodings
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != policy.encodings.len()
    {
        return Err(PathTraversalRuntimeError::InvalidPolicy);
    }
    let mut probes = Vec::new();
    for platform in policy.platforms {
        for encoding in policy.encodings {
            if probes.len() >= limits.max_probes {
                return Err(PathTraversalRuntimeError::RequestBudgetExceeded);
            }
            probes.push(TraversalProbe {
                probe_id: format!("traversal-{:02}", probes.len() + 1),
                platform: *platform,
                encoding: *encoding,
                maximum_depth: policy.maximum_depth,
                canary_id: contract.canary_id.to_string(),
            });
        }
    }
    if probes
        .iter()
        .map(TraversalProbe::mutation_request_count)
        .sum::<usize>()
        > limits.max_mutation_requests
    {
        return Err(PathTraversalRuntimeError::RequestBudgetExceeded);
    }
    Ok(probes)
}

pub fn assess_path_traversal(
    input: &PathTraversalInput<'_>,
    limits: PathTraversalLimits,
) -> Result<PathTraversalAssessment, PathTraversalRuntimeError> {
    validate_limits(limits)?;
    let identity = validate_contract(&input.contract)?;
    if input.contract.expected_canary_bytes > limits.max_canary_bytes {
        return Err(PathTraversalRuntimeError::InvalidContract);
    }
    if !input.contract.explicitly_approved {
        return Err(PathTraversalRuntimeError::UnapprovedProbe);
    }
    if input.probe.canary_id != input.contract.canary_id
        || input.probe.maximum_depth == 0
        || input.probe.maximum_depth > HARD_MAX_DEPTH
    {
        return Err(PathTraversalRuntimeError::InvalidProbe);
    }
    validate_samples(input, limits)?;
    let baseline_matches = canary_matches(input.baseline, &input.contract);
    let traversal_matches = canary_matches(input.traversal, &input.contract);
    let control_matches = canary_matches(input.control, &input.contract);
    if baseline_matches > 0 || control_matches > 0 {
        return Ok(assessment(
            PathTraversalDecision::Abstain,
            None,
            baseline_matches,
            traversal_matches,
            control_matches,
        ));
    }
    if traversal_matches == input.traversal.len() {
        let evidence_refs = input
            .baseline
            .iter()
            .chain(input.traversal)
            .chain(input.control)
            .map(|sample| sample.evidence_ref)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(str::to_string)
            .collect();
        let candidate = PathTraversalCandidate {
            candidate_id: format!("traversal-candidate-{}", &identity.fingerprint()[..24]),
            platform: input.probe.platform,
            encoding: input.probe.encoding,
            maximum_depth: input.probe.maximum_depth,
            matched_canary_bytes: input.contract.expected_canary_bytes,
            evidence_refs,
            requires_manual_confirmation: true,
        };
        return Ok(assessment(
            PathTraversalDecision::Candidate,
            Some(candidate),
            baseline_matches,
            traversal_matches,
            control_matches,
        ));
    }
    let decision = if traversal_matches == 0 {
        PathTraversalDecision::NotObserved
    } else {
        PathTraversalDecision::Abstain
    };
    Ok(assessment(
        decision,
        None,
        baseline_matches,
        traversal_matches,
        control_matches,
    ))
}

fn validate_limits(limits: PathTraversalLimits) -> Result<(), PathTraversalRuntimeError> {
    if limits.max_probes == 0
        || limits.max_probes > HARD_MAX_PROBES
        || limits.max_mutation_requests == 0
        || limits.max_mutation_requests > HARD_MAX_MUTATION_REQUESTS
        || limits.max_samples_per_role < 2
        || limits.max_samples_per_role > HARD_MAX_SAMPLES_PER_ROLE
        || limits.max_canary_bytes == 0
        || limits.max_canary_bytes > HARD_MAX_CANARY_BYTES
    {
        return Err(PathTraversalRuntimeError::InvalidLimits);
    }
    Ok(())
}

fn validate_contract(
    contract: &PathTraversalContract<'_>,
) -> Result<FindingIdentity, PathTraversalRuntimeError> {
    if !matches!(contract.method, HttpMethod::Get | HttpMethod::Post)
        || !matches!(
            contract.parameter_location,
            ParameterLocation::Query | ParameterLocation::Form | ParameterLocation::JsonBody
        )
        || !valid_identifier(contract.canary_id)
        || !valid_relative_canary_path(contract.canary_relative_path)
        || !valid_sha256(contract.expected_canary_sha256)
        || !(16..=HARD_MAX_CANARY_BYTES).contains(&contract.expected_canary_bytes)
    {
        return Err(PathTraversalRuntimeError::InvalidContract);
    }
    FindingIdentity::new(
        contract.target_id,
        contract.method,
        contract.endpoint,
        "CWE-22",
        contract.parameter_location,
        Some(contract.parameter_name.to_string()),
    )
    .map_err(|_| PathTraversalRuntimeError::InvalidContract)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_relative_canary_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CANARY_PATH_BYTES
        && !value.starts_with(['/', '\\'])
        && !value.ends_with(['/', '\\'])
        && !value.contains("..")
        && value.split(['/', '\\']).all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_samples(
    input: &PathTraversalInput<'_>,
    limits: PathTraversalLimits,
) -> Result<(), PathTraversalRuntimeError> {
    for samples in [input.baseline, input.traversal, input.control] {
        if samples.len() < 2 || samples.len() > limits.max_samples_per_role {
            return Err(PathTraversalRuntimeError::InvalidInput);
        }
        for sample in samples {
            if !(100..=599).contains(&sample.status_code)
                || sample.body_view_truncated
                || sample.body_view.len() > limits.max_canary_bytes
                || sample.evidence_ref.is_empty()
                || sample.evidence_ref.len() > 64
                || !sample.evidence_ref.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
                })
            {
                return Err(PathTraversalRuntimeError::InvalidInput);
            }
        }
    }
    Ok(())
}

fn canary_matches(
    samples: &[TraversalResponseSample<'_>],
    contract: &PathTraversalContract<'_>,
) -> usize {
    samples
        .iter()
        .filter(|sample| {
            sample.status_code == 200
                && sample.body_view.len() == contract.expected_canary_bytes
                && sha256_hex(sample.body_view) == contract.expected_canary_sha256
        })
        .count()
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

fn assessment(
    decision: PathTraversalDecision,
    candidate: Option<PathTraversalCandidate>,
    baseline_canary_matches: usize,
    traversal_canary_matches: usize,
    control_canary_matches: usize,
) -> PathTraversalAssessment {
    PathTraversalAssessment {
        decision,
        candidate,
        baseline_canary_matches,
        traversal_canary_matches,
        control_canary_matches,
    }
}

pub(crate) fn benchmark_outcomes() -> Result<(bool, bool), PathTraversalRuntimeError> {
    const CANARY: &[u8] = b"AEGIS SAFE CANARY FILE\n";
    let hash = sha256_hex(CANARY);
    let contract = || PathTraversalContract {
        target_id: "benchmark-target",
        endpoint: "https://benchmark.invalid/download",
        method: HttpMethod::Get,
        parameter_location: ParameterLocation::Query,
        parameter_name: "file",
        canary_id: "benchmark-canary",
        canary_relative_path: "fixtures/aegis-canary.txt",
        expected_canary_sha256: &hash,
        expected_canary_bytes: CANARY.len(),
        explicitly_approved: true,
    };
    let probes = plan_path_traversal_probes(
        &contract(),
        &TraversalProbePolicy {
            platforms: &[TraversalPlatform::Posix],
            encodings: &[TraversalEncoding::Plain],
            maximum_depth: 2,
        },
        PathTraversalLimits::default(),
    )?;
    let samples = |body| {
        vec![
            TraversalResponseSample {
                status_code: 200,
                body_view: body,
                body_view_truncated: false,
                evidence_ref: "benchmark-1",
            },
            TraversalResponseSample {
                status_code: 200,
                body_view: body,
                body_view_truncated: false,
                evidence_ref: "benchmark-2",
            },
        ]
    };
    let clean = samples(b"not found");
    let canary = samples(CANARY);
    let positive = assess_path_traversal(
        &PathTraversalInput {
            contract: contract(),
            probe: &probes[0],
            baseline: &clean,
            traversal: &canary,
            control: &clean,
        },
        PathTraversalLimits::default(),
    )?;
    let negative = assess_path_traversal(
        &PathTraversalInput {
            contract: contract(),
            probe: &probes[0],
            baseline: &clean,
            traversal: &clean,
            control: &clean,
        },
        PathTraversalLimits::default(),
    )?;
    Ok((
        positive.decision == PathTraversalDecision::Candidate && positive.candidate.is_some(),
        negative.decision == PathTraversalDecision::Candidate || negative.candidate.is_some(),
    ))
}

#[cfg(test)]
mod tests {
    use aegis_native_engine::{HttpMethod, ParameterLocation};

    use super::{
        assess_path_traversal, plan_path_traversal_probes, sha256_hex, PathTraversalContract,
        PathTraversalDecision, PathTraversalInput, PathTraversalLimits, PathTraversalRuntimeError,
        TraversalEncoding, TraversalPlatform, TraversalProbePolicy, TraversalResponseSample,
    };

    const CANARY: &[u8] = b"AEGIS SAFE CANARY FILE\n";

    fn contract(hash: &str) -> PathTraversalContract<'_> {
        PathTraversalContract {
            target_id: "target-1",
            endpoint: "https://example.com/download",
            method: HttpMethod::Get,
            parameter_location: ParameterLocation::Query,
            parameter_name: "file",
            canary_id: "canary-1",
            canary_relative_path: "fixtures/aegis-canary-1.txt",
            expected_canary_sha256: hash,
            expected_canary_bytes: CANARY.len(),
            explicitly_approved: true,
        }
    }

    fn samples<'a>(body: &'a [u8], prefix: &'static str) -> Vec<TraversalResponseSample<'a>> {
        vec![
            TraversalResponseSample {
                status_code: 200,
                body_view: body,
                body_view_truncated: false,
                evidence_ref: prefix,
            },
            TraversalResponseSample {
                status_code: 200,
                body_view: body,
                body_view_truncated: false,
                evidence_ref: prefix,
            },
        ]
    }

    fn probes<'a>(contract: &PathTraversalContract<'a>) -> Vec<super::TraversalProbe> {
        plan_path_traversal_probes(
            contract,
            &TraversalProbePolicy {
                platforms: &[TraversalPlatform::Posix, TraversalPlatform::Windows],
                encodings: &[
                    TraversalEncoding::Plain,
                    TraversalEncoding::PercentEncoded,
                    TraversalEncoding::DoublePercentEncoded,
                ],
                maximum_depth: 3,
            },
            PathTraversalLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn platform_encoding_matrix_stays_within_twelve_requests() {
        let hash = sha256_hex(CANARY);
        let probes = probes(&contract(&hash));
        assert_eq!(probes.len(), 6);
        assert_eq!(
            probes
                .iter()
                .map(super::TraversalProbe::mutation_request_count)
                .sum::<usize>(),
            12
        );
    }

    #[test]
    fn exact_repeated_canary_is_candidate_without_raw_body() {
        let hash = sha256_hex(CANARY);
        let first_contract = contract(&hash);
        let probes = probes(&first_contract);
        let baseline = samples(b"not found", "base-1");
        let traversal = samples(CANARY, "probe-1");
        let control = samples(b"not found", "control-1");
        let input = PathTraversalInput {
            contract: first_contract,
            probe: &probes[0],
            baseline: &baseline,
            traversal: &traversal,
            control: &control,
        };
        let assessment = assess_path_traversal(&input, PathTraversalLimits::default()).unwrap();
        assert_eq!(assessment.decision, PathTraversalDecision::Candidate);
        assert!(
            assessment
                .candidate
                .as_ref()
                .unwrap()
                .requires_manual_confirmation
        );
        let debug = format!("{input:?}");
        assert!(!debug.contains("AEGIS SAFE"));
        assert!(!debug.contains("example.com"));
        assert!(!debug.contains(&hash));
    }

    #[test]
    fn baseline_or_control_canary_collision_abstains() {
        let hash = sha256_hex(CANARY);
        let collision_contract = contract(&hash);
        let probes = probes(&collision_contract);
        let collision = samples(CANARY, "collision-1");
        let traversal = samples(CANARY, "probe-1");
        let clean = samples(b"not found", "clean-1");
        assert_eq!(
            assess_path_traversal(
                &PathTraversalInput {
                    contract: collision_contract,
                    probe: &probes[0],
                    baseline: &collision,
                    traversal: &traversal,
                    control: &clean,
                },
                PathTraversalLimits::default(),
            )
            .unwrap()
            .decision,
            PathTraversalDecision::Abstain
        );

        let contract = contract(&hash);
        assert_eq!(
            assess_path_traversal(
                &PathTraversalInput {
                    contract,
                    probe: &probes[0],
                    baseline: &clean,
                    traversal: &clean,
                    control: &clean,
                },
                PathTraversalLimits::default(),
            )
            .unwrap()
            .decision,
            PathTraversalDecision::NotObserved
        );
    }

    #[test]
    fn partial_probe_match_abstains_and_zero_match_is_not_observed() {
        let hash = sha256_hex(CANARY);
        let contract = contract(&hash);
        let probes = probes(&contract);
        let clean = samples(b"not found", "clean-1");
        let partial = [
            TraversalResponseSample {
                status_code: 200,
                body_view: CANARY,
                body_view_truncated: false,
                evidence_ref: "probe-1",
            },
            TraversalResponseSample {
                status_code: 404,
                body_view: b"not found",
                body_view_truncated: false,
                evidence_ref: "probe-2",
            },
        ];
        assert_eq!(
            assess_path_traversal(
                &PathTraversalInput {
                    contract,
                    probe: &probes[0],
                    baseline: &clean,
                    traversal: &partial,
                    control: &clean,
                },
                PathTraversalLimits::default(),
            )
            .unwrap()
            .decision,
            PathTraversalDecision::Abstain
        );
    }

    #[test]
    fn approval_path_hash_and_truncation_fail_closed() {
        let hash = sha256_hex(CANARY);
        let mut invalid_contract = contract(&hash);
        invalid_contract.explicitly_approved = false;
        assert_eq!(
            plan_path_traversal_probes(
                &invalid_contract,
                &TraversalProbePolicy {
                    platforms: &[TraversalPlatform::Posix],
                    encodings: &[TraversalEncoding::Plain],
                    maximum_depth: 2,
                },
                PathTraversalLimits::default(),
            ),
            Err(PathTraversalRuntimeError::UnapprovedProbe)
        );
        invalid_contract.explicitly_approved = true;
        invalid_contract.canary_relative_path = "../etc/passwd";
        assert_eq!(
            plan_path_traversal_probes(
                &invalid_contract,
                &TraversalProbePolicy {
                    platforms: &[TraversalPlatform::Posix],
                    encodings: &[TraversalEncoding::Plain],
                    maximum_depth: 2,
                },
                PathTraversalLimits::default(),
            ),
            Err(PathTraversalRuntimeError::InvalidContract)
        );

        let contract = contract(&hash);
        let probes = probes(&contract);
        let clean = samples(b"not found", "clean-1");
        let truncated = [
            TraversalResponseSample {
                status_code: 200,
                body_view: CANARY,
                body_view_truncated: true,
                evidence_ref: "probe-1",
            },
            TraversalResponseSample {
                status_code: 200,
                body_view: CANARY,
                body_view_truncated: true,
                evidence_ref: "probe-2",
            },
        ];
        assert_eq!(
            assess_path_traversal(
                &PathTraversalInput {
                    contract,
                    probe: &probes[0],
                    baseline: &clean,
                    traversal: &truncated,
                    control: &clean,
                },
                PathTraversalLimits::default(),
            ),
            Err(PathTraversalRuntimeError::InvalidInput)
        );
    }
}
