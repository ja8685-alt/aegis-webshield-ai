use std::collections::BTreeSet;
use std::fmt::{Debug, Display, Formatter};

use sha2::{Digest, Sha256};

const HARD_MAX_SAMPLES_PER_ROLE: usize = 7;
const HARD_MAX_BODY_VIEW_BYTES: usize = 65_536;
const HARD_MAX_TOKENS: usize = 4_096;
const MAX_TOKEN_BYTES: usize = 256;
const MAX_EVIDENCE_REF_BYTES: usize = 64;
const BASIS_POINTS: u64 = 10_000;

pub struct ResponseSample<'a> {
    pub status_code: u16,
    pub content_type: Option<&'a str>,
    pub body_view: &'a [u8],
    pub body_view_truncated: bool,
    pub duration_millis: u64,
    pub evidence_ref: &'a str,
}

impl Debug for ResponseSample<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResponseSample")
            .field("status_code", &self.status_code)
            .field("has_content_type", &self.content_type.is_some())
            .field("body_view_bytes", &self.body_view.len())
            .field("body_view_truncated", &self.body_view_truncated)
            .field("duration_millis", &self.duration_millis)
            .finish()
    }
}

pub struct ResponseComparisonInput<'a> {
    pub baseline: &'a [ResponseSample<'a>],
    pub probe: &'a [ResponseSample<'a>],
    pub control: &'a [ResponseSample<'a>],
}

impl Debug for ResponseComparisonInput<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResponseComparisonInput")
            .field("baseline_samples", &self.baseline.len())
            .field("probe_samples", &self.probe.len())
            .field("control_samples", &self.control.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComparisonLimits {
    pub max_samples_per_role: usize,
    pub max_body_view_bytes: usize,
    pub max_tokens_per_body: usize,
}

impl Default for ComparisonLimits {
    fn default() -> Self {
        Self {
            max_samples_per_role: HARD_MAX_SAMPLES_PER_ROLE,
            max_body_view_bytes: HARD_MAX_BODY_VIEW_BYTES,
            max_tokens_per_body: HARD_MAX_TOKENS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComparisonPolicy {
    pub minimum_samples_per_role: usize,
    pub changed_similarity_basis_points: u64,
    pub stable_control_similarity_basis_points: u64,
    pub minimum_timing_delta_millis: u64,
    pub timing_noise_multiplier: u64,
}

impl Default for ComparisonPolicy {
    fn default() -> Self {
        Self {
            minimum_samples_per_role: 3,
            changed_similarity_basis_points: 6_500,
            stable_control_similarity_basis_points: 9_000,
            minimum_timing_delta_millis: 500,
            timing_noise_multiplier: 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComparisonRuntimeError {
    InvalidLimits,
    InvalidPolicy,
    InvalidInput,
    TokenLimitExceeded,
}

impl Display for ComparisonRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "response comparison limits are invalid",
            Self::InvalidPolicy => "response comparison policy is invalid",
            Self::InvalidInput => "response comparison input is invalid",
            Self::TokenLimitExceeded => "response comparison token limit was exceeded",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ComparisonRuntimeError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComparisonDecision {
    Changed,
    Stable,
    Abstain,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ComparisonSignal {
    StatusChanged,
    BodyChanged,
    TimingChanged,
    ControlUnstable,
    BodyNotComparable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComparisonObservation {
    pub signal: ComparisonSignal,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ComparisonAssessment {
    pub decision: ComparisonDecision,
    pub observations: Vec<ComparisonObservation>,
    pub baseline_probe_similarity_basis_points: Option<u64>,
    pub baseline_control_similarity_basis_points: Option<u64>,
    pub baseline_duration_median_millis: u64,
    pub probe_duration_median_millis: u64,
    pub control_duration_median_millis: u64,
    pub timing_noise_millis: u64,
    pub evidence_refs: Vec<String>,
}

impl Debug for ComparisonAssessment {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ComparisonAssessment")
            .field("decision", &self.decision)
            .field("observations", &self.observations)
            .field(
                "baseline_probe_similarity_basis_points",
                &self.baseline_probe_similarity_basis_points,
            )
            .field(
                "baseline_control_similarity_basis_points",
                &self.baseline_control_similarity_basis_points,
            )
            .field(
                "baseline_duration_median_millis",
                &self.baseline_duration_median_millis,
            )
            .field(
                "probe_duration_median_millis",
                &self.probe_duration_median_millis,
            )
            .field(
                "control_duration_median_millis",
                &self.control_duration_median_millis,
            )
            .field("timing_noise_millis", &self.timing_noise_millis)
            .field("evidence_ref_count", &self.evidence_refs.len())
            .finish()
    }
}

pub fn compare_responses(
    input: &ResponseComparisonInput<'_>,
    policy: ComparisonPolicy,
    limits: ComparisonLimits,
) -> Result<ComparisonAssessment, ComparisonRuntimeError> {
    validate_limits(limits)?;
    validate_policy(policy, limits)?;
    validate_input(input, policy, limits)?;

    let baseline_status = consistent_status(input.baseline);
    let probe_status = consistent_status(input.probe);
    let control_status = consistent_status(input.control);
    let status_control_stable = baseline_status.is_some() && baseline_status == control_status;
    let status_changed =
        status_control_stable && probe_status.is_some() && baseline_status != probe_status;
    let status_unstable =
        baseline_status.is_none() || control_status.is_none() || probe_status.is_none();

    let bodies_comparable = input
        .baseline
        .iter()
        .chain(input.probe)
        .chain(input.control)
        .all(sample_body_is_comparable);
    let (probe_similarity, control_similarity) = if bodies_comparable {
        let baseline = normalized_bodies(input.baseline, limits)?;
        let probe = normalized_bodies(input.probe, limits)?;
        let control = normalized_bodies(input.control, limits)?;
        (
            Some(cross_role_median_similarity(&baseline, &probe)),
            Some(cross_role_median_similarity(&baseline, &control)),
        )
    } else {
        (None, None)
    };
    let body_control_stable = control_similarity
        .is_none_or(|value| value >= policy.stable_control_similarity_basis_points);
    let body_changed =
        probe_similarity.is_some_and(|value| value <= policy.changed_similarity_basis_points);

    let baseline_duration = duration_median(input.baseline);
    let probe_duration = duration_median(input.probe);
    let control_duration = duration_median(input.control);
    let timing_noise = combined_timing_noise(input.baseline, input.control);
    let timing_threshold = policy
        .minimum_timing_delta_millis
        .max(timing_noise.saturating_mul(policy.timing_noise_multiplier));
    let timing_changed = probe_duration
        >= baseline_duration
            .max(control_duration)
            .saturating_add(timing_threshold);

    let control_unstable = status_unstable || !status_control_stable || !body_control_stable;
    let mut signals = BTreeSet::new();
    if control_unstable {
        signals.insert(ComparisonSignal::ControlUnstable);
    }
    if !bodies_comparable {
        signals.insert(ComparisonSignal::BodyNotComparable);
    }
    if status_changed {
        signals.insert(ComparisonSignal::StatusChanged);
    }
    if body_changed {
        signals.insert(ComparisonSignal::BodyChanged);
    }
    if timing_changed {
        signals.insert(ComparisonSignal::TimingChanged);
    }
    let decision = if control_unstable {
        ComparisonDecision::Abstain
    } else if status_changed || body_changed || timing_changed {
        ComparisonDecision::Changed
    } else if !bodies_comparable && baseline_status == probe_status && !timing_changed {
        ComparisonDecision::Abstain
    } else {
        ComparisonDecision::Stable
    };

    Ok(ComparisonAssessment {
        decision,
        observations: signals
            .into_iter()
            .map(|signal| ComparisonObservation { signal })
            .collect(),
        baseline_probe_similarity_basis_points: probe_similarity,
        baseline_control_similarity_basis_points: control_similarity,
        baseline_duration_median_millis: baseline_duration,
        probe_duration_median_millis: probe_duration,
        control_duration_median_millis: control_duration,
        timing_noise_millis: timing_noise,
        evidence_refs: evidence_refs(input),
    })
}

fn validate_limits(limits: ComparisonLimits) -> Result<(), ComparisonRuntimeError> {
    if limits.max_samples_per_role == 0
        || limits.max_samples_per_role > HARD_MAX_SAMPLES_PER_ROLE
        || limits.max_body_view_bytes == 0
        || limits.max_body_view_bytes > HARD_MAX_BODY_VIEW_BYTES
        || limits.max_tokens_per_body == 0
        || limits.max_tokens_per_body > HARD_MAX_TOKENS
    {
        return Err(ComparisonRuntimeError::InvalidLimits);
    }
    Ok(())
}

fn validate_policy(
    policy: ComparisonPolicy,
    limits: ComparisonLimits,
) -> Result<(), ComparisonRuntimeError> {
    if policy.minimum_samples_per_role == 0
        || policy.minimum_samples_per_role > limits.max_samples_per_role
        || policy.changed_similarity_basis_points >= policy.stable_control_similarity_basis_points
        || policy.stable_control_similarity_basis_points > BASIS_POINTS
        || policy.minimum_timing_delta_millis == 0
        || policy.minimum_timing_delta_millis > 10_000
        || policy.timing_noise_multiplier == 0
        || policy.timing_noise_multiplier > 20
    {
        return Err(ComparisonRuntimeError::InvalidPolicy);
    }
    Ok(())
}

fn validate_input(
    input: &ResponseComparisonInput<'_>,
    policy: ComparisonPolicy,
    limits: ComparisonLimits,
) -> Result<(), ComparisonRuntimeError> {
    for samples in [input.baseline, input.probe, input.control] {
        if samples.len() < policy.minimum_samples_per_role
            || samples.len() > limits.max_samples_per_role
        {
            return Err(ComparisonRuntimeError::InvalidInput);
        }
        for sample in samples {
            if !(100..=599).contains(&sample.status_code)
                || sample.body_view.len() > limits.max_body_view_bytes
                || sample.duration_millis > 60_000
                || sample.evidence_ref.is_empty()
                || sample.evidence_ref.len() > MAX_EVIDENCE_REF_BYTES
                || !sample.evidence_ref.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
                })
                || sample.content_type.is_some_and(|value| {
                    value.is_empty() || value.len() > 256 || value.contains(['\r', '\n', '\0'])
                })
            {
                return Err(ComparisonRuntimeError::InvalidInput);
            }
        }
    }
    Ok(())
}

fn sample_body_is_comparable(sample: &ResponseSample<'_>) -> bool {
    !sample.body_view_truncated
        && sample.content_type.is_none_or(|value| {
            let normalized = value
                .split(';')
                .next()
                .unwrap_or(value)
                .trim()
                .to_ascii_lowercase();
            normalized.starts_with("text/")
                || matches!(
                    normalized.as_str(),
                    "application/json"
                        | "application/xml"
                        | "application/javascript"
                        | "application/x-www-form-urlencoded"
                )
                || normalized.ends_with("+json")
                || normalized.ends_with("+xml")
        })
        && std::str::from_utf8(sample.body_view).is_ok()
}

fn normalized_bodies(
    samples: &[ResponseSample<'_>],
    limits: ComparisonLimits,
) -> Result<Vec<BTreeSet<[u8; 8]>>, ComparisonRuntimeError> {
    samples
        .iter()
        .map(|sample| normalized_token_hashes(sample.body_view, limits))
        .collect()
}

fn normalized_token_hashes(
    body: &[u8],
    limits: ComparisonLimits,
) -> Result<BTreeSet<[u8; 8]>, ComparisonRuntimeError> {
    let text = std::str::from_utf8(body).map_err(|_| ComparisonRuntimeError::InvalidInput)?;
    let mut hashes = BTreeSet::new();
    let mut token_count = 0usize;
    for token in
        text.split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
    {
        if token.is_empty() {
            continue;
        }
        token_count += 1;
        if token_count > limits.max_tokens_per_body || token.len() > MAX_TOKEN_BYTES {
            return Err(ComparisonRuntimeError::TokenLimitExceeded);
        }
        let normalized = if token.len() >= 6 && token.bytes().all(|byte| byte.is_ascii_digit()) {
            "<number>".to_string()
        } else if token.len() >= 16 && token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            "<hex>".to_string()
        } else {
            token.to_ascii_lowercase()
        };
        let digest = Sha256::digest(normalized.as_bytes());
        let mut hash = [0u8; 8];
        hash.copy_from_slice(&digest[..8]);
        hashes.insert(hash);
    }
    Ok(hashes)
}

fn cross_role_median_similarity(left: &[BTreeSet<[u8; 8]>], right: &[BTreeSet<[u8; 8]>]) -> u64 {
    let mut similarities = left
        .iter()
        .flat_map(|left_body| {
            right
                .iter()
                .map(move |right_body| jaccard_similarity(left_body, right_body))
        })
        .collect::<Vec<_>>();
    median(&mut similarities)
}

fn jaccard_similarity(left: &BTreeSet<[u8; 8]>, right: &BTreeSet<[u8; 8]>) -> u64 {
    let union = left.union(right).count();
    if union == 0 {
        return BASIS_POINTS;
    }
    left.intersection(right).count() as u64 * BASIS_POINTS / union as u64
}

fn consistent_status(samples: &[ResponseSample<'_>]) -> Option<u16> {
    let status = samples.first()?.status_code;
    samples
        .iter()
        .all(|sample| sample.status_code == status)
        .then_some(status)
}

fn duration_median(samples: &[ResponseSample<'_>]) -> u64 {
    let mut values = samples
        .iter()
        .map(|sample| sample.duration_millis)
        .collect::<Vec<_>>();
    median(&mut values)
}

fn combined_timing_noise(baseline: &[ResponseSample<'_>], control: &[ResponseSample<'_>]) -> u64 {
    let mut values = baseline
        .iter()
        .chain(control)
        .map(|sample| sample.duration_millis)
        .collect::<Vec<_>>();
    let center = median(&mut values);
    let mut deviations = values
        .into_iter()
        .map(|value| value.abs_diff(center))
        .collect::<Vec<_>>();
    median(&mut deviations)
}

fn median(values: &mut [u64]) -> u64 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn evidence_refs(input: &ResponseComparisonInput<'_>) -> Vec<String> {
    input
        .baseline
        .iter()
        .chain(input.probe)
        .chain(input.control)
        .map(|sample| sample.evidence_ref)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        compare_responses, ComparisonDecision, ComparisonLimits, ComparisonPolicy,
        ComparisonRuntimeError, ComparisonSignal, ResponseComparisonInput, ResponseSample,
    };

    fn samples<'a>(body: &'a [u8], status: u16, durations: [u64; 3]) -> Vec<ResponseSample<'a>> {
        durations
            .into_iter()
            .enumerate()
            .map(|(index, duration_millis)| ResponseSample {
                status_code: status,
                content_type: Some("text/html"),
                body_view: body,
                body_view_truncated: false,
                duration_millis,
                evidence_ref: match index {
                    0 => "evidence-1",
                    1 => "evidence-2",
                    _ => "evidence-3",
                },
            })
            .collect()
    }

    #[test]
    fn dynamic_numbers_normalize_to_stable_body() {
        let baseline = samples(b"request 123456 completed for account", 200, [90, 100, 110]);
        let probe = samples(b"request 987654 completed for account", 200, [95, 105, 115]);
        let control = samples(b"request 456789 completed for account", 200, [92, 102, 112]);
        let assessment = compare_responses(
            &ResponseComparisonInput {
                baseline: &baseline,
                probe: &probe,
                control: &control,
            },
            ComparisonPolicy::default(),
            ComparisonLimits::default(),
        )
        .unwrap();
        assert_eq!(assessment.decision, ComparisonDecision::Stable);
        assert_eq!(
            assessment.baseline_probe_similarity_basis_points,
            Some(10_000)
        );
    }

    #[test]
    fn changed_body_and_status_require_stable_control() {
        let baseline = samples(b"normal account overview dashboard", 200, [90, 100, 110]);
        let probe = samples(
            b"database syntax exception stack trace",
            500,
            [95, 105, 115],
        );
        let control = samples(b"normal account overview dashboard", 200, [92, 102, 112]);
        let assessment = compare_responses(
            &ResponseComparisonInput {
                baseline: &baseline,
                probe: &probe,
                control: &control,
            },
            ComparisonPolicy::default(),
            ComparisonLimits::default(),
        )
        .unwrap();
        assert_eq!(assessment.decision, ComparisonDecision::Changed);
        assert!(assessment
            .observations
            .iter()
            .any(|item| item.signal == ComparisonSignal::StatusChanged));
        assert!(assessment
            .observations
            .iter()
            .any(|item| item.signal == ComparisonSignal::BodyChanged));
    }

    #[test]
    fn unstable_control_abstains() {
        let baseline = samples(b"normal account overview dashboard", 200, [90, 100, 110]);
        let probe = samples(b"different probe response", 500, [95, 105, 115]);
        let control = samples(b"unrelated maintenance page", 503, [92, 102, 112]);
        let assessment = compare_responses(
            &ResponseComparisonInput {
                baseline: &baseline,
                probe: &probe,
                control: &control,
            },
            ComparisonPolicy::default(),
            ComparisonLimits::default(),
        )
        .unwrap();
        assert_eq!(assessment.decision, ComparisonDecision::Abstain);
        assert!(assessment
            .observations
            .iter()
            .any(|item| item.signal == ComparisonSignal::ControlUnstable));
    }

    #[test]
    fn timing_change_must_exceed_median_noise_floor() {
        let baseline = samples(b"stable body content", 200, [90, 100, 110]);
        let probe = samples(b"stable body content", 200, [900, 1_000, 1_100]);
        let control = samples(b"stable body content", 200, [95, 105, 115]);
        let assessment = compare_responses(
            &ResponseComparisonInput {
                baseline: &baseline,
                probe: &probe,
                control: &control,
            },
            ComparisonPolicy::default(),
            ComparisonLimits::default(),
        )
        .unwrap();
        assert_eq!(assessment.decision, ComparisonDecision::Changed);
        assert!(assessment
            .observations
            .iter()
            .any(|item| item.signal == ComparisonSignal::TimingChanged));

        let noisy_baseline = samples(b"stable body content", 200, [100, 500, 900]);
        let noisy_probe = samples(b"stable body content", 200, [1_200, 1_300, 1_400]);
        let noisy_control = samples(b"stable body content", 200, [110, 510, 910]);
        let noisy_assessment = compare_responses(
            &ResponseComparisonInput {
                baseline: &noisy_baseline,
                probe: &noisy_probe,
                control: &noisy_control,
            },
            ComparisonPolicy::default(),
            ComparisonLimits::default(),
        )
        .unwrap();
        assert_eq!(noisy_assessment.decision, ComparisonDecision::Stable);
        assert!(!noisy_assessment
            .observations
            .iter()
            .any(|item| item.signal == ComparisonSignal::TimingChanged));
    }

    #[test]
    fn binary_or_truncated_body_abstains_without_raw_debug() {
        let mut baseline = samples(b"binary-secret", 200, [90, 100, 110]);
        let mut probe = samples(b"other-secret", 200, [95, 105, 115]);
        let mut control = samples(b"binary-secret", 200, [92, 102, 112]);
        for sample in baseline.iter_mut().chain(&mut probe).chain(&mut control) {
            sample.content_type = Some("application/octet-stream");
        }
        let input = ResponseComparisonInput {
            baseline: &baseline,
            probe: &probe,
            control: &control,
        };
        let assessment = compare_responses(
            &input,
            ComparisonPolicy::default(),
            ComparisonLimits::default(),
        )
        .unwrap();
        assert_eq!(assessment.decision, ComparisonDecision::Abstain);
        let debug = format!("{input:?} {assessment:?}");
        assert!(!debug.contains("binary-secret"));
        assert!(!debug.contains("other-secret"));
    }

    #[test]
    fn limits_samples_and_evidence_fail_closed() {
        let baseline = samples(b"stable", 200, [90, 100, 110]);
        let probe = samples(b"stable", 200, [90, 100, 110]);
        let mut control = samples(b"stable", 200, [90, 100, 110]);
        control[0].evidence_ref = "bad\nref";
        assert_eq!(
            compare_responses(
                &ResponseComparisonInput {
                    baseline: &baseline,
                    probe: &probe,
                    control: &control,
                },
                ComparisonPolicy::default(),
                ComparisonLimits::default(),
            ),
            Err(ComparisonRuntimeError::InvalidInput)
        );
        assert!(compare_responses(
            &ResponseComparisonInput {
                baseline: &baseline[..2],
                probe: &probe,
                control: &control,
            },
            ComparisonPolicy::default(),
            ComparisonLimits::default(),
        )
        .is_err());
    }
}
