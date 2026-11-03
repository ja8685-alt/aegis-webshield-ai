use std::collections::BTreeSet;
use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ContractError;

const CONTRACT_PREFIX: &str = "revalidation_";
const BUNDLE_PREFIX: &str = "bundle_";
const HARD_MAX_REQUESTS: usize = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevalidationSuccessCondition {
    ProbeSignalAbsent,
    AccessDenied,
    SafeStatusRange { minimum: u16, maximum: u16 },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevalidationStopReason {
    RequestFingerprintChanged,
    TargetChanged,
    SafetyPolicyBlocked,
    TargetUnstable,
    Timeout,
    OutOfScopeRedirect,
    EvidenceTruncated,
}

const MANDATORY_STOPS: [RevalidationStopReason; 7] = [
    RevalidationStopReason::RequestFingerprintChanged,
    RevalidationStopReason::TargetChanged,
    RevalidationStopReason::SafetyPolicyBlocked,
    RevalidationStopReason::TargetUnstable,
    RevalidationStopReason::Timeout,
    RevalidationStopReason::OutOfScopeRedirect,
    RevalidationStopReason::EvidenceTruncated,
];

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RevalidationContract {
    contract_ref: String,
    correlation_key: String,
    original_bundle_ref: String,
    target_id: String,
    request_fingerprint: String,
    success_condition: RevalidationSuccessCondition,
    max_requests: usize,
    required_consecutive_successes: usize,
    stop_conditions: Vec<RevalidationStopReason>,
    fingerprint: String,
}

impl RevalidationContract {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_ref: impl Into<String>,
        correlation_key: impl Into<String>,
        original_bundle_ref: impl Into<String>,
        target_id: impl Into<String>,
        request_fingerprint: impl Into<String>,
        success_condition: RevalidationSuccessCondition,
        max_requests: usize,
        required_consecutive_successes: usize,
    ) -> Result<Self, ContractError> {
        let mut contract = Self {
            contract_ref: contract_ref.into(),
            correlation_key: correlation_key.into(),
            original_bundle_ref: original_bundle_ref.into(),
            target_id: target_id.into(),
            request_fingerprint: request_fingerprint.into(),
            success_condition,
            max_requests,
            required_consecutive_successes,
            stop_conditions: MANDATORY_STOPS.to_vec(),
            fingerprint: String::new(),
        };
        contract.fingerprint = contract.compute_fingerprint();
        contract.validate()?;
        Ok(contract)
    }

    pub fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }

    pub fn correlation_key(&self) -> &str {
        &self.correlation_key
    }

    pub fn original_bundle_ref(&self) -> &str {
        &self.original_bundle_ref
    }

    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    pub fn success_condition(&self) -> RevalidationSuccessCondition {
        self.success_condition
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn max_requests(&self) -> usize {
        self.max_requests
    }

    pub fn required_consecutive_successes(&self) -> usize {
        self.required_consecutive_successes
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        validate_prefixed_hash("contract_ref", &self.contract_ref, CONTRACT_PREFIX)?;
        validate_sha256("correlation_key", &self.correlation_key)?;
        validate_prefixed_hash(
            "original_bundle_ref",
            &self.original_bundle_ref,
            BUNDLE_PREFIX,
        )?;
        validate_opaque("target_id", &self.target_id, 64)?;
        validate_sha256("request_fingerprint", &self.request_fingerprint)?;
        if self.max_requests < 2
            || self.max_requests > HARD_MAX_REQUESTS
            || self.required_consecutive_successes < 2
            || self.required_consecutive_successes > self.max_requests
        {
            return Err(ContractError::new(
                "request_limits",
                "requires two to six requests and at least two consecutive successes",
            ));
        }
        if let RevalidationSuccessCondition::SafeStatusRange { minimum, maximum } =
            self.success_condition
        {
            if minimum < 200 || maximum > 499 || minimum > maximum {
                return Err(ContractError::new(
                    "success_condition",
                    "safe status range must be ordered within 200..499",
                ));
            }
        }
        if self.stop_conditions != MANDATORY_STOPS {
            return Err(ContractError::new(
                "stop_conditions",
                "all mandatory fail-closed stop conditions are required",
            ));
        }
        validate_sha256("fingerprint", &self.fingerprint)?;
        if self.fingerprint != self.compute_fingerprint() {
            return Err(ContractError::new(
                "fingerprint",
                "revalidation contract integrity mismatch",
            ));
        }
        Ok(())
    }

    fn compute_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "aegis.revalidation.contract.v1");
        hash_field(&mut hasher, &self.contract_ref);
        hash_field(&mut hasher, &self.correlation_key);
        hash_field(&mut hasher, &self.original_bundle_ref);
        hash_field(&mut hasher, &self.target_id);
        hash_field(&mut hasher, &self.request_fingerprint);
        hash_field(&mut hasher, condition_tag(self.success_condition));
        if let RevalidationSuccessCondition::SafeStatusRange { minimum, maximum } =
            self.success_condition
        {
            hash_field(&mut hasher, &minimum.to_string());
            hash_field(&mut hasher, &maximum.to_string());
        }
        hash_field(&mut hasher, &self.max_requests.to_string());
        hash_field(
            &mut hasher,
            &self.required_consecutive_successes.to_string(),
        );
        for reason in &self.stop_conditions {
            hash_field(&mut hasher, stop_tag(*reason));
        }
        format!("{:x}", hasher.finalize())
    }
}

impl Debug for RevalidationContract {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RevalidationContract")
            .field("contract_ref_bytes", &self.contract_ref.len())
            .field("correlation_key_bytes", &self.correlation_key.len())
            .field("bundle_ref_bytes", &self.original_bundle_ref.len())
            .field("target_id_bytes", &self.target_id.len())
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("success_condition", &self.success_condition)
            .field("max_requests", &self.max_requests)
            .field(
                "required_consecutive_successes",
                &self.required_consecutive_successes,
            )
            .field("stop_condition_count", &self.stop_conditions.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RevalidationObservation {
    repetition: usize,
    request_fingerprint: String,
    target_id: String,
    status_code: u16,
    probe_signal_observed: bool,
    safety_permitted: bool,
    target_stable: bool,
    timed_out: bool,
    redirect_in_scope: bool,
    evidence_truncated: bool,
    evidence_ref: String,
}

impl RevalidationObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repetition: usize,
        request_fingerprint: impl Into<String>,
        target_id: impl Into<String>,
        status_code: u16,
        probe_signal_observed: bool,
        safety_permitted: bool,
        target_stable: bool,
        timed_out: bool,
        redirect_in_scope: bool,
        evidence_truncated: bool,
        evidence_ref: impl Into<String>,
    ) -> Self {
        Self {
            repetition,
            request_fingerprint: request_fingerprint.into(),
            target_id: target_id.into(),
            status_code,
            probe_signal_observed,
            safety_permitted,
            target_stable,
            timed_out,
            redirect_in_scope,
            evidence_truncated,
            evidence_ref: evidence_ref.into(),
        }
    }
}

impl Debug for RevalidationObservation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RevalidationObservation")
            .field("repetition", &self.repetition)
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("target_id_bytes", &self.target_id.len())
            .field("status_code", &self.status_code)
            .field("probe_signal_observed", &self.probe_signal_observed)
            .field("safety_permitted", &self.safety_permitted)
            .field("target_stable", &self.target_stable)
            .field("timed_out", &self.timed_out)
            .field("redirect_in_scope", &self.redirect_in_scope)
            .field("evidence_truncated", &self.evidence_truncated)
            .field("evidence_ref_bytes", &self.evidence_ref.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevalidationOutcome {
    Resolved,
    StillVulnerable,
    Inconclusive,
    Stopped,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RevalidationReport {
    contract_fingerprint: String,
    attempted_requests: usize,
    consecutive_successes: usize,
    outcome: RevalidationOutcome,
    stop_reason: Option<RevalidationStopReason>,
    evidence_refs: Vec<String>,
    fingerprint: String,
}

impl RevalidationReport {
    pub fn outcome(&self) -> RevalidationOutcome {
        self.outcome
    }

    pub fn stop_reason(&self) -> Option<RevalidationStopReason> {
        self.stop_reason
    }

    pub fn attempted_requests(&self) -> usize {
        self.attempted_requests
    }

    pub fn consecutive_successes(&self) -> usize {
        self.consecutive_successes
    }

    pub fn evidence_refs(&self) -> &[String] {
        &self.evidence_refs
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn validate(&self, contract: &RevalidationContract) -> Result<(), ContractError> {
        contract.validate()?;
        if self.contract_fingerprint != contract.fingerprint
            || self.attempted_requests > contract.max_requests
            || self.evidence_refs.len() != self.attempted_requests
            || self.consecutive_successes > self.attempted_requests
            || (self.outcome == RevalidationOutcome::Stopped) != self.stop_reason.is_some()
        {
            return Err(ContractError::new(
                "report",
                "revalidation report does not match contract or outcome",
            ));
        }
        let outcome_valid = match self.outcome {
            RevalidationOutcome::Resolved => {
                self.consecutive_successes >= contract.required_consecutive_successes
                    && self.stop_reason.is_none()
            }
            RevalidationOutcome::StillVulnerable => {
                self.attempted_requests == contract.max_requests
                    && self.consecutive_successes < contract.required_consecutive_successes
                    && self.stop_reason.is_none()
            }
            RevalidationOutcome::Inconclusive => {
                self.attempted_requests < contract.max_requests
                    && self.consecutive_successes < contract.required_consecutive_successes
                    && self.stop_reason.is_none()
            }
            RevalidationOutcome::Stopped => self.stop_reason.is_some(),
        };
        if !outcome_valid {
            return Err(ContractError::new(
                "outcome",
                "outcome does not match request and success counters",
            ));
        }
        let mut refs = BTreeSet::new();
        for reference in &self.evidence_refs {
            validate_opaque("evidence_ref", reference, 64)?;
            if !refs.insert(reference) {
                return Err(ContractError::new(
                    "evidence_refs",
                    "evidence references must be unique",
                ));
            }
        }
        validate_sha256("fingerprint", &self.fingerprint)?;
        if self.fingerprint != self.compute_fingerprint() {
            return Err(ContractError::new(
                "fingerprint",
                "revalidation report integrity mismatch",
            ));
        }
        Ok(())
    }

    fn compute_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "aegis.revalidation.report.v1");
        hash_field(&mut hasher, &self.contract_fingerprint);
        hash_field(&mut hasher, &self.attempted_requests.to_string());
        hash_field(&mut hasher, &self.consecutive_successes.to_string());
        hash_field(&mut hasher, outcome_tag(self.outcome));
        hash_field(
            &mut hasher,
            self.stop_reason.map(stop_tag).unwrap_or("none"),
        );
        hash_field(&mut hasher, &self.evidence_refs.len().to_string());
        for reference in &self.evidence_refs {
            hash_field(&mut hasher, reference);
        }
        format!("{:x}", hasher.finalize())
    }
}

impl Debug for RevalidationReport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RevalidationReport")
            .field(
                "contract_fingerprint_bytes",
                &self.contract_fingerprint.len(),
            )
            .field("attempted_requests", &self.attempted_requests)
            .field("consecutive_successes", &self.consecutive_successes)
            .field("outcome", &self.outcome)
            .field("stop_reason", &self.stop_reason)
            .field("evidence_count", &self.evidence_refs.len())
            .finish()
    }
}

pub fn evaluate_revalidation(
    contract: &RevalidationContract,
    observations: &[RevalidationObservation],
) -> Result<RevalidationReport, ContractError> {
    contract.validate()?;
    if observations.len() > contract.max_requests {
        return Err(ContractError::new(
            "observations",
            "revalidation request budget exceeded",
        ));
    }
    let mut consecutive = 0usize;
    let mut evidence_refs = Vec::new();
    let mut outcome = RevalidationOutcome::Inconclusive;
    let mut stop_reason = None;
    for (index, observation) in observations.iter().enumerate() {
        validate_observation(observation, index + 1)?;
        evidence_refs.push(observation.evidence_ref.clone());
        if let Some(reason) = observation_stop_reason(contract, observation) {
            if index + 1 < observations.len() {
                return Err(ContractError::new(
                    "observations",
                    "requests continued after a mandatory stop condition",
                ));
            }
            outcome = RevalidationOutcome::Stopped;
            stop_reason = Some(reason);
            break;
        }
        if condition_met(contract.success_condition, observation) {
            consecutive += 1;
            if consecutive >= contract.required_consecutive_successes {
                if index + 1 < observations.len() {
                    return Err(ContractError::new(
                        "observations",
                        "requests continued after success condition was satisfied",
                    ));
                }
                outcome = RevalidationOutcome::Resolved;
                break;
            }
        } else {
            consecutive = 0;
        }
    }
    if outcome == RevalidationOutcome::Inconclusive && observations.len() == contract.max_requests {
        outcome = RevalidationOutcome::StillVulnerable;
    }
    let mut report = RevalidationReport {
        contract_fingerprint: contract.fingerprint.clone(),
        attempted_requests: evidence_refs.len(),
        consecutive_successes: consecutive,
        outcome,
        stop_reason,
        evidence_refs,
        fingerprint: String::new(),
    };
    report.fingerprint = report.compute_fingerprint();
    report.validate(contract)?;
    Ok(report)
}

fn validate_observation(
    value: &RevalidationObservation,
    expected_repetition: usize,
) -> Result<(), ContractError> {
    if value.repetition != expected_repetition {
        return Err(ContractError::new(
            "repetition",
            "observations must be contiguous and ordered",
        ));
    }
    validate_sha256("request_fingerprint", &value.request_fingerprint)?;
    validate_opaque("target_id", &value.target_id, 64)?;
    if !(100..=599).contains(&value.status_code) {
        return Err(ContractError::new(
            "status_code",
            "must be a valid HTTP status",
        ));
    }
    validate_opaque("evidence_ref", &value.evidence_ref, 64)
}

fn observation_stop_reason(
    contract: &RevalidationContract,
    value: &RevalidationObservation,
) -> Option<RevalidationStopReason> {
    if value.request_fingerprint != contract.request_fingerprint {
        Some(RevalidationStopReason::RequestFingerprintChanged)
    } else if value.target_id != contract.target_id {
        Some(RevalidationStopReason::TargetChanged)
    } else if !value.safety_permitted {
        Some(RevalidationStopReason::SafetyPolicyBlocked)
    } else if !value.target_stable {
        Some(RevalidationStopReason::TargetUnstable)
    } else if value.timed_out {
        Some(RevalidationStopReason::Timeout)
    } else if !value.redirect_in_scope {
        Some(RevalidationStopReason::OutOfScopeRedirect)
    } else if value.evidence_truncated {
        Some(RevalidationStopReason::EvidenceTruncated)
    } else {
        None
    }
}

fn condition_met(condition: RevalidationSuccessCondition, value: &RevalidationObservation) -> bool {
    match condition {
        RevalidationSuccessCondition::ProbeSignalAbsent => !value.probe_signal_observed,
        RevalidationSuccessCondition::AccessDenied => matches!(value.status_code, 401 | 403),
        RevalidationSuccessCondition::SafeStatusRange { minimum, maximum } => {
            (minimum..=maximum).contains(&value.status_code)
        }
    }
}
fn validate_prefixed_hash(
    field: &'static str,
    value: &str,
    prefix: &str,
) -> Result<(), ContractError> {
    if value.len() != prefix.len() + 32
        || !value.starts_with(prefix)
        || !value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ContractError::new(
            field,
            "must use required prefix and 32 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}
fn validate_sha256(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ContractError::new(
            field,
            "must be a lowercase SHA-256 digest",
        ));
    }
    Ok(())
}
fn validate_opaque(field: &'static str, value: &str, max: usize) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > max
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ContractError::new(
            field,
            "must be a bounded opaque identifier",
        ));
    }
    Ok(())
}
fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}
fn condition_tag(value: RevalidationSuccessCondition) -> &'static str {
    match value {
        RevalidationSuccessCondition::ProbeSignalAbsent => "probe_signal_absent",
        RevalidationSuccessCondition::AccessDenied => "access_denied",
        RevalidationSuccessCondition::SafeStatusRange { .. } => "safe_status_range",
    }
}
fn stop_tag(value: RevalidationStopReason) -> &'static str {
    match value {
        RevalidationStopReason::RequestFingerprintChanged => "request_fingerprint_changed",
        RevalidationStopReason::TargetChanged => "target_changed",
        RevalidationStopReason::SafetyPolicyBlocked => "safety_policy_blocked",
        RevalidationStopReason::TargetUnstable => "target_unstable",
        RevalidationStopReason::Timeout => "timeout",
        RevalidationStopReason::OutOfScopeRedirect => "out_of_scope_redirect",
        RevalidationStopReason::EvidenceTruncated => "evidence_truncated",
    }
}
fn outcome_tag(value: RevalidationOutcome) -> &'static str {
    match value {
        RevalidationOutcome::Resolved => "resolved",
        RevalidationOutcome::StillVulnerable => "still_vulnerable",
        RevalidationOutcome::Inconclusive => "inconclusive",
        RevalidationOutcome::Stopped => "stopped",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        evaluate_revalidation, RevalidationContract, RevalidationObservation, RevalidationOutcome,
        RevalidationStopReason, RevalidationSuccessCondition,
    };

    const CONTRACT: &str = "revalidation_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CORRELATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BUNDLE: &str = "bundle_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const REQUEST_FP: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const OTHER_FP: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn contract() -> RevalidationContract {
        RevalidationContract::new(
            CONTRACT,
            CORRELATION,
            BUNDLE,
            "target-1",
            REQUEST_FP,
            RevalidationSuccessCondition::ProbeSignalAbsent,
            4,
            2,
        )
        .unwrap()
    }

    fn observation(repetition: usize, signal_observed: bool) -> RevalidationObservation {
        RevalidationObservation::new(
            repetition,
            REQUEST_FP,
            "target-1",
            200,
            signal_observed,
            true,
            true,
            false,
            true,
            false,
            format!("evidence-{repetition}"),
        )
    }

    #[test]
    fn two_consecutive_successes_resolve_with_early_stop() {
        let report =
            evaluate_revalidation(&contract(), &[observation(1, false), observation(2, false)])
                .unwrap();
        assert_eq!(report.outcome(), RevalidationOutcome::Resolved);
        assert_eq!(report.attempted_requests(), 2);
        assert_eq!(report.stop_reason(), None);
        assert!(report.validate(&contract()).is_ok());
    }

    #[test]
    fn success_must_be_consecutive_and_full_budget_can_remain_vulnerable() {
        let resolved = evaluate_revalidation(
            &contract(),
            &[
                observation(1, false),
                observation(2, true),
                observation(3, false),
                observation(4, false),
            ],
        )
        .unwrap();
        assert_eq!(resolved.outcome(), RevalidationOutcome::Resolved);
        assert_eq!(resolved.attempted_requests(), 4);

        let vulnerable = evaluate_revalidation(
            &contract(),
            &[
                observation(1, true),
                observation(2, true),
                observation(3, true),
                observation(4, true),
            ],
        )
        .unwrap();
        assert_eq!(vulnerable.outcome(), RevalidationOutcome::StillVulnerable);
    }

    #[test]
    fn partial_nonterminal_execution_is_inconclusive() {
        let report = evaluate_revalidation(&contract(), &[observation(1, false)]).unwrap();
        assert_eq!(report.outcome(), RevalidationOutcome::Inconclusive);
        assert_eq!(report.attempted_requests(), 1);
    }

    #[test]
    fn every_safety_boundary_stops_without_claiming_success() {
        let cases = [
            (
                RevalidationObservation::new(
                    1,
                    OTHER_FP,
                    "target-1",
                    200,
                    false,
                    true,
                    true,
                    false,
                    true,
                    false,
                    "evidence-1",
                ),
                RevalidationStopReason::RequestFingerprintChanged,
            ),
            (
                RevalidationObservation::new(
                    1,
                    REQUEST_FP,
                    "target-other",
                    200,
                    false,
                    true,
                    true,
                    false,
                    true,
                    false,
                    "evidence-1",
                ),
                RevalidationStopReason::TargetChanged,
            ),
            (
                RevalidationObservation::new(
                    1,
                    REQUEST_FP,
                    "target-1",
                    200,
                    false,
                    false,
                    true,
                    false,
                    true,
                    false,
                    "evidence-1",
                ),
                RevalidationStopReason::SafetyPolicyBlocked,
            ),
            (
                RevalidationObservation::new(
                    1,
                    REQUEST_FP,
                    "target-1",
                    200,
                    false,
                    true,
                    false,
                    false,
                    true,
                    false,
                    "evidence-1",
                ),
                RevalidationStopReason::TargetUnstable,
            ),
            (
                RevalidationObservation::new(
                    1,
                    REQUEST_FP,
                    "target-1",
                    200,
                    false,
                    true,
                    true,
                    true,
                    true,
                    false,
                    "evidence-1",
                ),
                RevalidationStopReason::Timeout,
            ),
            (
                RevalidationObservation::new(
                    1,
                    REQUEST_FP,
                    "target-1",
                    200,
                    false,
                    true,
                    true,
                    false,
                    false,
                    false,
                    "evidence-1",
                ),
                RevalidationStopReason::OutOfScopeRedirect,
            ),
            (
                RevalidationObservation::new(
                    1,
                    REQUEST_FP,
                    "target-1",
                    200,
                    false,
                    true,
                    true,
                    false,
                    true,
                    true,
                    "evidence-1",
                ),
                RevalidationStopReason::EvidenceTruncated,
            ),
        ];
        for (observation, expected) in cases {
            let report = evaluate_revalidation(&contract(), &[observation]).unwrap();
            assert_eq!(report.outcome(), RevalidationOutcome::Stopped);
            assert_eq!(report.stop_reason(), Some(expected));
        }
    }

    #[test]
    fn request_budget_order_and_terminal_continuation_fail_closed() {
        let too_many = (1..=5)
            .map(|repetition| observation(repetition, true))
            .collect::<Vec<_>>();
        assert_eq!(
            evaluate_revalidation(&contract(), &too_many)
                .unwrap_err()
                .field(),
            "observations"
        );
        assert_eq!(
            evaluate_revalidation(&contract(), &[observation(2, true)])
                .unwrap_err()
                .field(),
            "repetition"
        );
        assert_eq!(
            evaluate_revalidation(
                &contract(),
                &[
                    observation(1, false),
                    observation(2, false),
                    observation(3, false)
                ]
            )
            .unwrap_err()
            .field(),
            "observations"
        );
    }

    #[test]
    fn contract_limits_integrity_and_debug_are_bounded() {
        let error = RevalidationContract::new(
            CONTRACT,
            CORRELATION,
            BUNDLE,
            "target-1",
            REQUEST_FP,
            RevalidationSuccessCondition::AccessDenied,
            1,
            1,
        )
        .unwrap_err();
        assert_eq!(error.field(), "request_limits");
        let mut tampered_contract = contract();
        tampered_contract.stop_conditions.pop();
        assert_eq!(
            tampered_contract.validate().unwrap_err().field(),
            "stop_conditions"
        );

        let observation = observation(1, true);
        let report = evaluate_revalidation(&tampered_contract, &[]).unwrap_err();
        assert_eq!(report.field(), "stop_conditions");
        let debug = format!("{tampered_contract:?} {observation:?}");
        assert!(!debug.contains(CONTRACT));
        assert!(!debug.contains(REQUEST_FP));
        assert!(!debug.contains("target-1"));
        assert!(!debug.contains("evidence-1"));
    }
}
