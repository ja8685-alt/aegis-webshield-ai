use std::collections::BTreeSet;
use std::fmt::{Debug, Display, Formatter};

use aegis_native_engine::{Confidence, FindingIdentity, HttpMethod, ParameterLocation};

use crate::{ComparisonAssessment, ComparisonDecision, ComparisonSignal};

const HARD_MAX_ERROR_SAMPLES_PER_ROLE: usize = 2;
const HARD_MAX_BODY_VIEW_BYTES: usize = 65_536;
const ENDPOINT_MUTATION_BUDGET: usize = 12;

pub struct SqlInjectionContract<'a> {
    pub target_id: &'a str,
    pub endpoint: &'a str,
    pub method: HttpMethod,
    pub parameter_location: ParameterLocation,
    pub parameter_name: &'a str,
    pub explicitly_approved: bool,
    pub time_probe_approved: bool,
}

impl Debug for SqlInjectionContract<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqlInjectionContract")
            .field("method", &self.method)
            .field("parameter_location", &self.parameter_location)
            .field("parameter_name_bytes", &self.parameter_name.len())
            .field("explicitly_approved", &self.explicitly_approved)
            .field("time_probe_approved", &self.time_probe_approved)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqlInjectionPolicy {
    pub enable_error_stage: bool,
    pub enable_boolean_stage: bool,
    pub enable_timing_stage: bool,
    pub maximum_time_delay_millis: u64,
}

impl Default for SqlInjectionPolicy {
    fn default() -> Self {
        Self {
            enable_error_stage: true,
            enable_boolean_stage: true,
            enable_timing_stage: false,
            maximum_time_delay_millis: 1_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqlInjectionLimits {
    pub max_error_samples_per_role: usize,
    pub max_body_view_bytes: usize,
    pub max_mutation_requests: usize,
}

impl Default for SqlInjectionLimits {
    fn default() -> Self {
        Self {
            max_error_samples_per_role: HARD_MAX_ERROR_SAMPLES_PER_ROLE,
            max_body_view_bytes: HARD_MAX_BODY_VIEW_BYTES,
            max_mutation_requests: ENDPOINT_MUTATION_BUDGET,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlProbeStage {
    ErrorDifferential,
    BooleanDifferential,
    TimingDifferential,
}

impl SqlProbeStage {
    pub fn mutation_request_count(self) -> usize {
        match self {
            Self::ErrorDifferential => 2,
            Self::BooleanDifferential => 4,
            Self::TimingDifferential => 6,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlInjectionRuntimeError {
    InvalidLimits,
    InvalidPolicy,
    InvalidContract,
    UnapprovedProbe,
    InvalidInput,
    RequestBudgetExceeded,
}

impl Display for SqlInjectionRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "SQL injection limits are invalid",
            Self::InvalidPolicy => "SQL injection policy is invalid",
            Self::InvalidContract => "SQL injection contract is invalid",
            Self::UnapprovedProbe => "SQL injection probe was not explicitly approved",
            Self::InvalidInput => "SQL injection evidence input is invalid",
            Self::RequestBudgetExceeded => "SQL injection mutation request budget was exceeded",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SqlInjectionRuntimeError {}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SqlErrorFamily {
    GenericSyntax,
    SqlState,
    PostgreSql,
    MySql,
    Sqlite,
    Oracle,
    MicrosoftSqlServer,
    JavaDatabase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlInjectionSignal {
    ErrorDifferential(SqlErrorFamily),
    BooleanDifferential,
    TimingDifferential,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlInjectionDecision {
    Candidate,
    NotObserved,
    Abstain,
}

pub struct SqlResponseSample<'a> {
    pub content_type: &'a str,
    pub body_view: &'a [u8],
    pub body_view_truncated: bool,
    pub evidence_ref: &'a str,
}

impl Debug for SqlResponseSample<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqlResponseSample")
            .field("content_type_bytes", &self.content_type.len())
            .field("body_view_bytes", &self.body_view.len())
            .field("body_view_truncated", &self.body_view_truncated)
            .finish()
    }
}

pub struct SqlInjectionEvidence<'a> {
    pub baseline_error_samples: &'a [SqlResponseSample<'a>],
    pub error_probe_samples: &'a [SqlResponseSample<'a>],
    pub error_control_samples: &'a [SqlResponseSample<'a>],
    pub boolean_true: Option<&'a ComparisonAssessment>,
    pub boolean_false: Option<&'a ComparisonAssessment>,
    pub timing_probe: Option<&'a ComparisonAssessment>,
    pub timing_control: Option<&'a ComparisonAssessment>,
    pub requested_time_delay_millis: Option<u64>,
}

impl Debug for SqlInjectionEvidence<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqlInjectionEvidence")
            .field("baseline_error_samples", &self.baseline_error_samples.len())
            .field("error_probe_samples", &self.error_probe_samples.len())
            .field("error_control_samples", &self.error_control_samples.len())
            .field(
                "has_boolean_pair",
                &(self.boolean_true.is_some() && self.boolean_false.is_some()),
            )
            .field(
                "has_timing_pair",
                &(self.timing_probe.is_some() && self.timing_control.is_some()),
            )
            .field(
                "requested_time_delay_millis",
                &self.requested_time_delay_millis,
            )
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqlInjectionCandidate {
    pub candidate_id: String,
    pub signal: SqlInjectionSignal,
    pub confidence: Confidence,
    pub evidence_refs: Vec<String>,
    pub requires_manual_confirmation: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqlInjectionAssessment {
    pub decision: SqlInjectionDecision,
    pub evaluated_stages: Vec<SqlProbeStage>,
    pub candidate: Option<SqlInjectionCandidate>,
}

pub fn plan_sql_injection_stages(
    contract: &SqlInjectionContract<'_>,
    policy: SqlInjectionPolicy,
    limits: SqlInjectionLimits,
) -> Result<Vec<SqlProbeStage>, SqlInjectionRuntimeError> {
    validate_limits(limits)?;
    validate_policy(policy)?;
    validate_contract(contract)?;
    if !contract.explicitly_approved {
        return Err(SqlInjectionRuntimeError::UnapprovedProbe);
    }
    let mut stages = Vec::new();
    if policy.enable_error_stage {
        stages.push(SqlProbeStage::ErrorDifferential);
    }
    if policy.enable_boolean_stage {
        stages.push(SqlProbeStage::BooleanDifferential);
    }
    if policy.enable_timing_stage {
        if !contract.time_probe_approved {
            return Err(SqlInjectionRuntimeError::UnapprovedProbe);
        }
        stages.push(SqlProbeStage::TimingDifferential);
    }
    let request_count = stages
        .iter()
        .map(|stage| stage.mutation_request_count())
        .sum::<usize>();
    if stages.is_empty() || request_count > limits.max_mutation_requests {
        return Err(SqlInjectionRuntimeError::RequestBudgetExceeded);
    }
    Ok(stages)
}

pub fn assess_sql_injection(
    contract: &SqlInjectionContract<'_>,
    evidence: &SqlInjectionEvidence<'_>,
    policy: SqlInjectionPolicy,
    limits: SqlInjectionLimits,
) -> Result<SqlInjectionAssessment, SqlInjectionRuntimeError> {
    let identity = validate_contract(contract)?;
    let planned = plan_sql_injection_stages(contract, policy, limits)?;
    let mut evaluated = Vec::new();

    if planned.contains(&SqlProbeStage::ErrorDifferential) {
        validate_error_evidence(evidence, limits)?;
        evaluated.push(SqlProbeStage::ErrorDifferential);
        if let Some(family) = differential_error_family(evidence) {
            return Ok(candidate(
                &identity,
                SqlInjectionSignal::ErrorDifferential(family),
                Confidence::High,
                error_evidence_refs(evidence),
                evaluated,
            ));
        }
    }
    if planned.contains(&SqlProbeStage::BooleanDifferential) {
        evaluated.push(SqlProbeStage::BooleanDifferential);
        match (evidence.boolean_true, evidence.boolean_false) {
            (Some(true_result), Some(false_result))
                if true_result.decision == ComparisonDecision::Stable
                    && false_result.decision == ComparisonDecision::Changed =>
            {
                return Ok(candidate(
                    &identity,
                    SqlInjectionSignal::BooleanDifferential,
                    Confidence::High,
                    comparison_refs([true_result, false_result]),
                    evaluated,
                ));
            }
            (Some(left), Some(right))
                if left.decision == ComparisonDecision::Abstain
                    || right.decision == ComparisonDecision::Abstain =>
            {
                return Ok(abstain(evaluated));
            }
            (Some(_), Some(_)) => {}
            _ => return Err(SqlInjectionRuntimeError::InvalidInput),
        }
    }
    if planned.contains(&SqlProbeStage::TimingDifferential) {
        evaluated.push(SqlProbeStage::TimingDifferential);
        let delay = evidence
            .requested_time_delay_millis
            .ok_or(SqlInjectionRuntimeError::InvalidInput)?;
        if delay == 0 || delay > policy.maximum_time_delay_millis {
            return Err(SqlInjectionRuntimeError::InvalidInput);
        }
        match (evidence.timing_probe, evidence.timing_control) {
            (Some(probe), Some(control))
                if has_timing_change(probe) && control.decision == ComparisonDecision::Stable =>
            {
                return Ok(candidate(
                    &identity,
                    SqlInjectionSignal::TimingDifferential,
                    Confidence::Medium,
                    comparison_refs([probe, control]),
                    evaluated,
                ));
            }
            (Some(probe), Some(control))
                if probe.decision == ComparisonDecision::Abstain
                    || control.decision == ComparisonDecision::Abstain =>
            {
                return Ok(abstain(evaluated));
            }
            (Some(_), Some(_)) => {}
            _ => return Err(SqlInjectionRuntimeError::InvalidInput),
        }
    }
    Ok(SqlInjectionAssessment {
        decision: SqlInjectionDecision::NotObserved,
        evaluated_stages: evaluated,
        candidate: None,
    })
}

fn validate_limits(limits: SqlInjectionLimits) -> Result<(), SqlInjectionRuntimeError> {
    if limits.max_error_samples_per_role == 0
        || limits.max_error_samples_per_role > HARD_MAX_ERROR_SAMPLES_PER_ROLE
        || limits.max_body_view_bytes == 0
        || limits.max_body_view_bytes > HARD_MAX_BODY_VIEW_BYTES
        || limits.max_mutation_requests == 0
        || limits.max_mutation_requests > ENDPOINT_MUTATION_BUDGET
    {
        return Err(SqlInjectionRuntimeError::InvalidLimits);
    }
    Ok(())
}

fn validate_policy(policy: SqlInjectionPolicy) -> Result<(), SqlInjectionRuntimeError> {
    if policy.maximum_time_delay_millis < 500 || policy.maximum_time_delay_millis > 2_000 {
        return Err(SqlInjectionRuntimeError::InvalidPolicy);
    }
    Ok(())
}

fn validate_contract(
    contract: &SqlInjectionContract<'_>,
) -> Result<FindingIdentity, SqlInjectionRuntimeError> {
    if !matches!(contract.method, HttpMethod::Get | HttpMethod::Post)
        || !matches!(
            contract.parameter_location,
            ParameterLocation::Query | ParameterLocation::Form | ParameterLocation::JsonBody
        )
    {
        return Err(SqlInjectionRuntimeError::InvalidContract);
    }
    FindingIdentity::new(
        contract.target_id,
        contract.method,
        contract.endpoint,
        "CWE-89",
        contract.parameter_location,
        Some(contract.parameter_name.to_string()),
    )
    .map_err(|_| SqlInjectionRuntimeError::InvalidContract)
}

fn validate_error_evidence(
    evidence: &SqlInjectionEvidence<'_>,
    limits: SqlInjectionLimits,
) -> Result<(), SqlInjectionRuntimeError> {
    for samples in [
        evidence.baseline_error_samples,
        evidence.error_probe_samples,
        evidence.error_control_samples,
    ] {
        if samples.is_empty() || samples.len() > limits.max_error_samples_per_role {
            return Err(SqlInjectionRuntimeError::InvalidInput);
        }
        for sample in samples {
            if sample.body_view_truncated
                || sample.body_view.len() > limits.max_body_view_bytes
                || !textual(sample.content_type)
                || std::str::from_utf8(sample.body_view).is_err()
                || sample.evidence_ref.is_empty()
                || sample.evidence_ref.len() > 64
                || !sample.evidence_ref.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
                })
            {
                return Err(SqlInjectionRuntimeError::InvalidInput);
            }
        }
    }
    Ok(())
}

fn textual(content_type: &str) -> bool {
    let value = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    value.starts_with("text/") || value == "application/json" || value.ends_with("+json")
}

fn differential_error_family(evidence: &SqlInjectionEvidence<'_>) -> Option<SqlErrorFamily> {
    let baseline = common_error_families(evidence.baseline_error_samples);
    let control = common_error_families(evidence.error_control_samples);
    common_error_families(evidence.error_probe_samples)
        .difference(&baseline)
        .copied()
        .find(|family| !control.contains(family))
}

fn common_error_families(samples: &[SqlResponseSample<'_>]) -> BTreeSet<SqlErrorFamily> {
    let mut iter = samples.iter();
    let Some(first) = iter.next() else {
        return BTreeSet::new();
    };
    let mut common = error_families(first.body_view);
    for sample in iter {
        let current = error_families(sample.body_view);
        common.retain(|family| current.contains(family));
    }
    common
}

fn error_families(body: &[u8]) -> BTreeSet<SqlErrorFamily> {
    let patterns: &[(SqlErrorFamily, &[u8])] = &[
        (SqlErrorFamily::GenericSyntax, b"sql syntax"),
        (SqlErrorFamily::GenericSyntax, b"unterminated quoted string"),
        (SqlErrorFamily::SqlState, b"sqlstate["),
        (SqlErrorFamily::PostgreSql, b"pg_query("),
        (SqlErrorFamily::PostgreSql, b"postgresql error"),
        (SqlErrorFamily::MySql, b"mysql_fetch"),
        (SqlErrorFamily::MySql, b"mysqli_sql_exception"),
        (SqlErrorFamily::Sqlite, b"sqlite_error"),
        (SqlErrorFamily::Oracle, b"ora-"),
        (
            SqlErrorFamily::MicrosoftSqlServer,
            b"unclosed quotation mark",
        ),
        (SqlErrorFamily::JavaDatabase, b"java.sql.sqlexception"),
    ];
    patterns
        .iter()
        .filter_map(|(family, pattern)| contains_ci(body, pattern).then_some(*family))
        .collect()
}

fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn has_timing_change(assessment: &ComparisonAssessment) -> bool {
    assessment.decision == ComparisonDecision::Changed
        && assessment
            .observations
            .iter()
            .any(|item| item.signal == ComparisonSignal::TimingChanged)
}

fn candidate(
    identity: &FindingIdentity,
    signal: SqlInjectionSignal,
    confidence: Confidence,
    evidence_refs: Vec<String>,
    evaluated_stages: Vec<SqlProbeStage>,
) -> SqlInjectionAssessment {
    SqlInjectionAssessment {
        decision: SqlInjectionDecision::Candidate,
        evaluated_stages,
        candidate: Some(SqlInjectionCandidate {
            candidate_id: format!("sqli-candidate-{}", &identity.fingerprint()[..24]),
            signal,
            confidence,
            evidence_refs,
            requires_manual_confirmation: true,
        }),
    }
}

fn abstain(evaluated_stages: Vec<SqlProbeStage>) -> SqlInjectionAssessment {
    SqlInjectionAssessment {
        decision: SqlInjectionDecision::Abstain,
        evaluated_stages,
        candidate: None,
    }
}

fn error_evidence_refs(evidence: &SqlInjectionEvidence<'_>) -> Vec<String> {
    evidence
        .baseline_error_samples
        .iter()
        .chain(evidence.error_probe_samples)
        .chain(evidence.error_control_samples)
        .map(|sample| sample.evidence_ref)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn comparison_refs<const N: usize>(items: [&ComparisonAssessment; N]) -> Vec<String> {
    items
        .into_iter()
        .flat_map(|assessment| assessment.evidence_refs.iter().map(String::as_str))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_string)
        .collect()
}

pub(crate) fn benchmark_outcomes() -> Result<(bool, bool), SqlInjectionRuntimeError> {
    let contract = SqlInjectionContract {
        target_id: "benchmark-target",
        endpoint: "https://benchmark.invalid/search",
        method: HttpMethod::Get,
        parameter_location: ParameterLocation::Query,
        parameter_name: "query",
        explicitly_approved: true,
        time_probe_approved: false,
    };
    let sample = |body, evidence_ref| SqlResponseSample {
        content_type: "text/plain",
        body_view: body,
        body_view_truncated: false,
        evidence_ref,
    };
    let baseline = [sample(b"normal response", "benchmark-base")];
    let positive_probe = [
        sample(b"PostgreSQL error: syntax failure", "benchmark-probe-1"),
        sample(b"POSTGRESQL ERROR: syntax failure", "benchmark-probe-2"),
    ];
    let control = [sample(b"normal response", "benchmark-control")];
    let empty = SqlInjectionEvidence {
        baseline_error_samples: &[],
        error_probe_samples: &[],
        error_control_samples: &[],
        boolean_true: None,
        boolean_false: None,
        timing_probe: None,
        timing_control: None,
        requested_time_delay_millis: None,
    };
    let positive_evidence = SqlInjectionEvidence {
        baseline_error_samples: &baseline,
        error_probe_samples: &positive_probe,
        error_control_samples: &control,
        ..empty
    };
    let policy = SqlInjectionPolicy {
        enable_boolean_stage: false,
        ..SqlInjectionPolicy::default()
    };
    let positive = assess_sql_injection(
        &contract,
        &positive_evidence,
        policy,
        SqlInjectionLimits::default(),
    )?;
    let safe_error = [sample(b"SQL syntax error", "benchmark-safe")];
    let negative_evidence = SqlInjectionEvidence {
        baseline_error_samples: &safe_error,
        error_probe_samples: &safe_error,
        error_control_samples: &safe_error,
        ..empty
    };
    let negative = assess_sql_injection(
        &contract,
        &negative_evidence,
        policy,
        SqlInjectionLimits::default(),
    )?;
    Ok((
        positive.decision == SqlInjectionDecision::Candidate && positive.candidate.is_some(),
        negative.decision == SqlInjectionDecision::Candidate || negative.candidate.is_some(),
    ))
}

#[cfg(test)]
mod tests {
    use aegis_native_engine::{HttpMethod, ParameterLocation};

    use super::{
        assess_sql_injection, plan_sql_injection_stages, SqlErrorFamily, SqlInjectionContract,
        SqlInjectionDecision, SqlInjectionEvidence, SqlInjectionLimits, SqlInjectionPolicy,
        SqlInjectionRuntimeError, SqlInjectionSignal, SqlProbeStage, SqlResponseSample,
    };
    use crate::{
        compare_responses, ComparisonLimits, ComparisonPolicy, ResponseComparisonInput,
        ResponseSample,
    };

    fn contract() -> SqlInjectionContract<'static> {
        SqlInjectionContract {
            target_id: "target-1",
            endpoint: "https://example.com/search",
            method: HttpMethod::Get,
            parameter_location: ParameterLocation::Query,
            parameter_name: "query",
            explicitly_approved: true,
            time_probe_approved: false,
        }
    }

    fn error_sample<'a>(body: &'a [u8], evidence_ref: &'static str) -> SqlResponseSample<'a> {
        SqlResponseSample {
            content_type: "text/plain",
            body_view: body,
            body_view_truncated: false,
            evidence_ref,
        }
    }

    fn comparison(
        body: &'static [u8],
        probe_body: &'static [u8],
        durations: [u64; 3],
    ) -> crate::ComparisonAssessment {
        let make = |value, times: [u64; 3], prefix: &'static str| {
            times
                .into_iter()
                .map(|duration_millis| ResponseSample {
                    status_code: 200,
                    content_type: Some("text/plain"),
                    body_view: value,
                    body_view_truncated: false,
                    duration_millis,
                    evidence_ref: prefix,
                })
                .collect::<Vec<_>>()
        };
        let baseline = make(body, [90, 100, 110], "base-1");
        let probe = make(probe_body, durations, "probe-1");
        let control = make(body, [92, 102, 112], "control-1");
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

    fn empty_evidence<'a>() -> SqlInjectionEvidence<'a> {
        SqlInjectionEvidence {
            baseline_error_samples: &[],
            error_probe_samples: &[],
            error_control_samples: &[],
            boolean_true: None,
            boolean_false: None,
            timing_probe: None,
            timing_control: None,
            requested_time_delay_millis: None,
        }
    }

    #[test]
    fn plan_is_staged_and_bounded_to_twelve_mutations() {
        let mut contract = contract();
        contract.time_probe_approved = true;
        let policy = SqlInjectionPolicy {
            enable_timing_stage: true,
            ..SqlInjectionPolicy::default()
        };
        let stages =
            plan_sql_injection_stages(&contract, policy, SqlInjectionLimits::default()).unwrap();
        assert_eq!(
            stages,
            [
                SqlProbeStage::ErrorDifferential,
                SqlProbeStage::BooleanDifferential,
                SqlProbeStage::TimingDifferential
            ]
        );
        assert_eq!(
            stages
                .iter()
                .map(|stage| stage.mutation_request_count())
                .sum::<usize>(),
            12
        );
    }

    #[test]
    fn repeated_new_sql_error_is_high_confidence_candidate() {
        let baseline = [error_sample(b"normal response", "base-1")];
        let probe = [
            error_sample(b"PostgreSQL error: syntax failure", "probe-1"),
            error_sample(b"POSTGRESQL ERROR: syntax failure", "probe-2"),
        ];
        let control = [error_sample(b"normal response", "control-1")];
        let evidence = SqlInjectionEvidence {
            baseline_error_samples: &baseline,
            error_probe_samples: &probe,
            error_control_samples: &control,
            ..empty_evidence()
        };
        let assessment = assess_sql_injection(
            &contract(),
            &evidence,
            SqlInjectionPolicy {
                enable_boolean_stage: false,
                ..SqlInjectionPolicy::default()
            },
            SqlInjectionLimits::default(),
        )
        .unwrap();
        assert_eq!(assessment.decision, SqlInjectionDecision::Candidate);
        assert_eq!(
            assessment.candidate.unwrap().signal,
            SqlInjectionSignal::ErrorDifferential(SqlErrorFamily::PostgreSql)
        );
    }

    #[test]
    fn baseline_error_is_not_a_differential() {
        let baseline = [error_sample(b"SQL syntax error", "base-1")];
        let probe = [error_sample(b"SQL syntax error", "probe-1")];
        let control = [error_sample(b"SQL syntax error", "control-1")];
        let false_result = comparison(
            b"normal account overview",
            b"normal account overview",
            [95, 105, 115],
        );
        let true_result = comparison(
            b"normal account overview",
            b"normal account overview",
            [95, 105, 115],
        );
        let evidence = SqlInjectionEvidence {
            baseline_error_samples: &baseline,
            error_probe_samples: &probe,
            error_control_samples: &control,
            boolean_true: Some(&true_result),
            boolean_false: Some(&false_result),
            ..empty_evidence()
        };
        assert_eq!(
            assess_sql_injection(
                &contract(),
                &evidence,
                SqlInjectionPolicy::default(),
                SqlInjectionLimits::default(),
            )
            .unwrap()
            .decision,
            SqlInjectionDecision::NotObserved
        );
    }

    #[test]
    fn boolean_and_timing_require_control_differential() {
        let true_result = comparison(
            b"account exists dashboard",
            b"account exists dashboard",
            [95, 105, 115],
        );
        let false_result = comparison(
            b"account exists dashboard",
            b"no matching record",
            [95, 105, 115],
        );
        let evidence = SqlInjectionEvidence {
            boolean_true: Some(&true_result),
            boolean_false: Some(&false_result),
            ..empty_evidence()
        };
        let assessment = assess_sql_injection(
            &contract(),
            &evidence,
            SqlInjectionPolicy {
                enable_error_stage: false,
                ..SqlInjectionPolicy::default()
            },
            SqlInjectionLimits::default(),
        )
        .unwrap();
        assert_eq!(
            assessment.candidate.unwrap().signal,
            SqlInjectionSignal::BooleanDifferential
        );

        let timing = comparison(b"stable body", b"stable body", [900, 1_000, 1_100]);
        let timing_control = comparison(b"stable body", b"stable body", [95, 105, 115]);
        let mut contract = contract();
        contract.time_probe_approved = true;
        let timing_evidence = SqlInjectionEvidence {
            timing_probe: Some(&timing),
            timing_control: Some(&timing_control),
            requested_time_delay_millis: Some(1_000),
            ..empty_evidence()
        };
        let timing_assessment = assess_sql_injection(
            &contract,
            &timing_evidence,
            SqlInjectionPolicy {
                enable_error_stage: false,
                enable_boolean_stage: false,
                enable_timing_stage: true,
                maximum_time_delay_millis: 1_000,
            },
            SqlInjectionLimits::default(),
        )
        .unwrap();
        assert_eq!(
            timing_assessment.candidate.unwrap().signal,
            SqlInjectionSignal::TimingDifferential
        );
    }

    #[test]
    fn unapproved_time_probe_and_invalid_body_fail_closed() {
        let policy = SqlInjectionPolicy {
            enable_error_stage: false,
            enable_boolean_stage: false,
            enable_timing_stage: true,
            maximum_time_delay_millis: 1_000,
        };
        assert_eq!(
            plan_sql_injection_stages(&contract(), policy, SqlInjectionLimits::default()),
            Err(SqlInjectionRuntimeError::UnapprovedProbe)
        );
        let invalid = [SqlResponseSample {
            content_type: "text/plain",
            body_view: b"SQL syntax error",
            body_view_truncated: true,
            evidence_ref: "evidence-1",
        }];
        let evidence = SqlInjectionEvidence {
            baseline_error_samples: &invalid,
            error_probe_samples: &invalid,
            error_control_samples: &invalid,
            ..empty_evidence()
        };
        assert!(assess_sql_injection(
            &contract(),
            &evidence,
            SqlInjectionPolicy {
                enable_boolean_stage: false,
                ..SqlInjectionPolicy::default()
            },
            SqlInjectionLimits::default(),
        )
        .is_err());
    }
}
