use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ContractError, EvidenceBundle, EvidenceBundleDecision, RevalidationContract,
    RevalidationOutcome, RevalidationReport, RevalidationStopReason, RevalidationSuccessCondition,
};

const BUNDLE_PREFIX: &str = "bundle_";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceResolution {
    Resolved,
    Unresolved,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AfterEvidenceState {
    ProbeSignalAbsent,
    AccessDenied,
    SafeStatusObserved,
    ProbeSignalStillObserved,
    InsufficientEvidence,
    RevalidationStopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDeltaReason {
    ProbeSignalRemoved,
    AccessNowDenied,
    SafeStatusRestored,
    RequestBudgetExhaustedWithoutResolution,
    RequiredRepetitionsIncomplete,
    MandatoryStop(RevalidationStopReason),
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct OriginalEvidenceSnapshot {
    bundle_ref: String,
    target_id: String,
    bundle_fingerprint: String,
    decision: EvidenceBundleDecision,
}

impl OriginalEvidenceSnapshot {
    pub fn from_bundle(bundle: &EvidenceBundle) -> Result<Self, ContractError> {
        Self::new(
            bundle.bundle_ref(),
            bundle.context().target_id(),
            bundle.fingerprint(),
            bundle.decision(),
        )
    }

    pub fn new(
        bundle_ref: impl Into<String>,
        target_id: impl Into<String>,
        bundle_fingerprint: impl Into<String>,
        decision: EvidenceBundleDecision,
    ) -> Result<Self, ContractError> {
        let snapshot = Self {
            bundle_ref: bundle_ref.into(),
            target_id: target_id.into(),
            bundle_fingerprint: bundle_fingerprint.into(),
            decision,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn bundle_ref(&self) -> &str {
        &self.bundle_ref
    }

    pub fn decision(&self) -> EvidenceBundleDecision {
        self.decision
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_prefixed_hash("bundle_ref", &self.bundle_ref, BUNDLE_PREFIX)?;
        validate_opaque("target_id", &self.target_id)?;
        validate_sha256("bundle_fingerprint", &self.bundle_fingerprint)?;
        if !matches!(
            self.decision,
            EvidenceBundleDecision::Finding | EvidenceBundleDecision::Candidate
        ) {
            return Err(ContractError::new(
                "decision",
                "only a finding or candidate can enter fix revalidation",
            ));
        }
        Ok(())
    }
}

impl Debug for OriginalEvidenceSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OriginalEvidenceSnapshot")
            .field("bundle_ref_bytes", &self.bundle_ref.len())
            .field("target_id_bytes", &self.target_id.len())
            .field("bundle_fingerprint_bytes", &self.bundle_fingerprint.len())
            .field("decision", &self.decision)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceDelta {
    original_bundle_ref: String,
    original_bundle_fingerprint: String,
    target_id: String,
    revalidation_contract_fingerprint: String,
    revalidation_report_fingerprint: String,
    correlation_key: String,
    before: EvidenceBundleDecision,
    after: AfterEvidenceState,
    resolution: EvidenceResolution,
    reason: EvidenceDeltaReason,
    compared_evidence_count: usize,
    fingerprint: String,
}

impl EvidenceDelta {
    pub fn resolution(&self) -> EvidenceResolution {
        self.resolution
    }

    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    pub fn before(&self) -> EvidenceBundleDecision {
        self.before
    }

    pub fn after(&self) -> AfterEvidenceState {
        self.after
    }

    pub fn reason(&self) -> EvidenceDeltaReason {
        self.reason
    }

    pub fn compared_evidence_count(&self) -> usize {
        self.compared_evidence_count
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn validate(
        &self,
        original: &OriginalEvidenceSnapshot,
        contract: &RevalidationContract,
        report: &RevalidationReport,
    ) -> Result<(), ContractError> {
        original.validate()?;
        report.validate(contract)?;
        if self.original_bundle_ref != original.bundle_ref
            || self.original_bundle_fingerprint != original.bundle_fingerprint
            || self.target_id != original.target_id
            || self.revalidation_contract_fingerprint != contract.fingerprint()
            || self.revalidation_report_fingerprint != report.fingerprint()
            || self.correlation_key != contract.correlation_key()
            || self.before != original.decision
            || self.compared_evidence_count != report.evidence_refs().len()
        {
            return Err(ContractError::new(
                "evidence_delta",
                "delta references do not match original and revalidation evidence",
            ));
        }
        let (resolution, after, reason) = classify(contract, report)?;
        if self.resolution != resolution || self.after != after || self.reason != reason {
            return Err(ContractError::new(
                "evidence_delta",
                "delta outcome does not match revalidation evidence",
            ));
        }
        validate_sha256("fingerprint", &self.fingerprint)?;
        if self.fingerprint != self.compute_fingerprint() {
            return Err(ContractError::new(
                "fingerprint",
                "evidence delta integrity mismatch",
            ));
        }
        Ok(())
    }

    fn compute_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "aegis.evidence.delta.v1");
        hash_field(&mut hasher, &self.original_bundle_ref);
        hash_field(&mut hasher, &self.original_bundle_fingerprint);
        hash_field(&mut hasher, &self.target_id);
        hash_field(&mut hasher, &self.revalidation_contract_fingerprint);
        hash_field(&mut hasher, &self.revalidation_report_fingerprint);
        hash_field(&mut hasher, &self.correlation_key);
        hash_field(&mut hasher, decision_tag(self.before));
        hash_field(&mut hasher, after_tag(self.after));
        hash_field(&mut hasher, resolution_tag(self.resolution));
        hash_field(&mut hasher, reason_tag(self.reason));
        if let EvidenceDeltaReason::MandatoryStop(reason) = self.reason {
            hash_field(&mut hasher, stop_tag(reason));
        }
        hash_field(&mut hasher, &self.compared_evidence_count.to_string());
        format!("{:x}", hasher.finalize())
    }
}

impl Debug for EvidenceDelta {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceDelta")
            .field("original_bundle_ref_bytes", &self.original_bundle_ref.len())
            .field("correlation_key_bytes", &self.correlation_key.len())
            .field("before", &self.before)
            .field("after", &self.after)
            .field("resolution", &self.resolution)
            .field("reason", &self.reason)
            .field("compared_evidence_count", &self.compared_evidence_count)
            .finish()
    }
}

pub fn build_evidence_delta(
    original: &OriginalEvidenceSnapshot,
    contract: &RevalidationContract,
    report: &RevalidationReport,
) -> Result<EvidenceDelta, ContractError> {
    original.validate()?;
    report.validate(contract)?;
    if original.bundle_ref != contract.original_bundle_ref()
        || original.target_id != contract.target_id()
    {
        return Err(ContractError::new(
            "original_evidence",
            "revalidation must reference the exact original bundle and target",
        ));
    }
    let (resolution, after, reason) = classify(contract, report)?;
    let mut delta = EvidenceDelta {
        original_bundle_ref: original.bundle_ref.clone(),
        original_bundle_fingerprint: original.bundle_fingerprint.clone(),
        target_id: original.target_id.clone(),
        revalidation_contract_fingerprint: contract.fingerprint().to_owned(),
        revalidation_report_fingerprint: report.fingerprint().to_owned(),
        correlation_key: contract.correlation_key().to_owned(),
        before: original.decision,
        after,
        resolution,
        reason,
        compared_evidence_count: report.evidence_refs().len(),
        fingerprint: String::new(),
    };
    delta.fingerprint = delta.compute_fingerprint();
    delta.validate(original, contract, report)?;
    Ok(delta)
}

fn classify(
    contract: &RevalidationContract,
    report: &RevalidationReport,
) -> Result<(EvidenceResolution, AfterEvidenceState, EvidenceDeltaReason), ContractError> {
    let classified = match report.outcome() {
        RevalidationOutcome::Resolved => match contract.success_condition() {
            RevalidationSuccessCondition::ProbeSignalAbsent => (
                EvidenceResolution::Resolved,
                AfterEvidenceState::ProbeSignalAbsent,
                EvidenceDeltaReason::ProbeSignalRemoved,
            ),
            RevalidationSuccessCondition::AccessDenied => (
                EvidenceResolution::Resolved,
                AfterEvidenceState::AccessDenied,
                EvidenceDeltaReason::AccessNowDenied,
            ),
            RevalidationSuccessCondition::SafeStatusRange { .. } => (
                EvidenceResolution::Resolved,
                AfterEvidenceState::SafeStatusObserved,
                EvidenceDeltaReason::SafeStatusRestored,
            ),
        },
        RevalidationOutcome::StillVulnerable => (
            EvidenceResolution::Unresolved,
            AfterEvidenceState::ProbeSignalStillObserved,
            EvidenceDeltaReason::RequestBudgetExhaustedWithoutResolution,
        ),
        RevalidationOutcome::Inconclusive => (
            EvidenceResolution::Inconclusive,
            AfterEvidenceState::InsufficientEvidence,
            EvidenceDeltaReason::RequiredRepetitionsIncomplete,
        ),
        RevalidationOutcome::Stopped => (
            EvidenceResolution::Inconclusive,
            AfterEvidenceState::RevalidationStopped,
            EvidenceDeltaReason::MandatoryStop(report.stop_reason().ok_or_else(|| {
                ContractError::new("stop_reason", "stopped report requires a reason")
            })?),
        ),
    };
    Ok(classified)
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

fn validate_opaque(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > 64
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

fn decision_tag(value: EvidenceBundleDecision) -> &'static str {
    match value {
        EvidenceBundleDecision::Finding => "finding",
        EvidenceBundleDecision::Candidate => "candidate",
        EvidenceBundleDecision::NotObserved => "not_observed",
        EvidenceBundleDecision::Abstain => "abstain",
    }
}

fn after_tag(value: AfterEvidenceState) -> &'static str {
    match value {
        AfterEvidenceState::ProbeSignalAbsent => "probe_signal_absent",
        AfterEvidenceState::AccessDenied => "access_denied",
        AfterEvidenceState::SafeStatusObserved => "safe_status_observed",
        AfterEvidenceState::ProbeSignalStillObserved => "probe_signal_still_observed",
        AfterEvidenceState::InsufficientEvidence => "insufficient_evidence",
        AfterEvidenceState::RevalidationStopped => "revalidation_stopped",
    }
}

fn resolution_tag(value: EvidenceResolution) -> &'static str {
    match value {
        EvidenceResolution::Resolved => "resolved",
        EvidenceResolution::Unresolved => "unresolved",
        EvidenceResolution::Inconclusive => "inconclusive",
    }
}

fn reason_tag(value: EvidenceDeltaReason) -> &'static str {
    match value {
        EvidenceDeltaReason::ProbeSignalRemoved => "probe_signal_removed",
        EvidenceDeltaReason::AccessNowDenied => "access_now_denied",
        EvidenceDeltaReason::SafeStatusRestored => "safe_status_restored",
        EvidenceDeltaReason::RequestBudgetExhaustedWithoutResolution => {
            "request_budget_exhausted_without_resolution"
        }
        EvidenceDeltaReason::RequiredRepetitionsIncomplete => "required_repetitions_incomplete",
        EvidenceDeltaReason::MandatoryStop(_) => "mandatory_stop",
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

#[cfg(test)]
mod tests {
    use super::{
        build_evidence_delta, AfterEvidenceState, EvidenceDelta, EvidenceDeltaReason,
        EvidenceResolution, OriginalEvidenceSnapshot,
    };
    use crate::{
        evaluate_revalidation, EvidenceBundleDecision, RevalidationContract,
        RevalidationObservation, RevalidationStopReason, RevalidationSuccessCondition,
    };

    const CONTRACT: &str = "revalidation_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CORRELATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BUNDLE: &str = "bundle_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BUNDLE_FP: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const REQUEST_FP: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn original() -> OriginalEvidenceSnapshot {
        OriginalEvidenceSnapshot::new(
            BUNDLE,
            "target-1",
            BUNDLE_FP,
            EvidenceBundleDecision::Finding,
        )
        .unwrap()
    }

    fn contract(condition: RevalidationSuccessCondition) -> RevalidationContract {
        RevalidationContract::new(
            CONTRACT,
            CORRELATION,
            BUNDLE,
            "target-1",
            REQUEST_FP,
            condition,
            4,
            2,
        )
        .unwrap()
    }

    fn observation(repetition: usize, signal: bool) -> RevalidationObservation {
        RevalidationObservation::new(
            repetition,
            REQUEST_FP,
            "target-1",
            200,
            signal,
            true,
            true,
            false,
            true,
            false,
            format!("evidence-{repetition}"),
        )
    }

    #[test]
    fn absent_signal_is_an_evidence_backed_resolution() {
        let contract = contract(RevalidationSuccessCondition::ProbeSignalAbsent);
        let report =
            evaluate_revalidation(&contract, &[observation(1, false), observation(2, false)])
                .unwrap();
        let delta = build_evidence_delta(&original(), &contract, &report).unwrap();
        assert_eq!(delta.resolution(), EvidenceResolution::Resolved);
        assert_eq!(delta.after(), AfterEvidenceState::ProbeSignalAbsent);
        assert_eq!(delta.reason(), EvidenceDeltaReason::ProbeSignalRemoved);
        assert_eq!(delta.compared_evidence_count(), 2);
    }

    #[test]
    fn exhausted_budget_preserves_unresolved_status() {
        let contract = contract(RevalidationSuccessCondition::ProbeSignalAbsent);
        let report = evaluate_revalidation(
            &contract,
            &[
                observation(1, true),
                observation(2, true),
                observation(3, true),
                observation(4, true),
            ],
        )
        .unwrap();
        let delta = build_evidence_delta(&original(), &contract, &report).unwrap();
        assert_eq!(delta.resolution(), EvidenceResolution::Unresolved);
        assert_eq!(
            delta.reason(),
            EvidenceDeltaReason::RequestBudgetExhaustedWithoutResolution
        );
    }

    #[test]
    fn partial_repetitions_never_claim_resolution() {
        let contract = contract(RevalidationSuccessCondition::ProbeSignalAbsent);
        let report = evaluate_revalidation(&contract, &[observation(1, false)]).unwrap();
        let delta = build_evidence_delta(&original(), &contract, &report).unwrap();
        assert_eq!(delta.resolution(), EvidenceResolution::Inconclusive);
        assert_eq!(delta.after(), AfterEvidenceState::InsufficientEvidence);
    }

    #[test]
    fn mandatory_stop_remains_inconclusive_with_exact_reason() {
        let contract = contract(RevalidationSuccessCondition::ProbeSignalAbsent);
        let blocked = RevalidationObservation::new(
            1,
            REQUEST_FP,
            "target-1",
            200,
            true,
            false,
            true,
            false,
            true,
            false,
            "evidence-1",
        );
        let report = evaluate_revalidation(&contract, &[blocked]).unwrap();
        let delta = build_evidence_delta(&original(), &contract, &report).unwrap();
        assert_eq!(delta.resolution(), EvidenceResolution::Inconclusive);
        assert_eq!(
            delta.reason(),
            EvidenceDeltaReason::MandatoryStop(RevalidationStopReason::SafetyPolicyBlocked)
        );
    }

    #[test]
    fn different_original_bundle_or_non_finding_is_rejected() {
        let contract = contract(RevalidationSuccessCondition::ProbeSignalAbsent);
        let report = evaluate_revalidation(&contract, &[observation(1, true)]).unwrap();
        let other = OriginalEvidenceSnapshot::new(
            "bundle_dddddddddddddddddddddddddddddddd",
            "target-1",
            BUNDLE_FP,
            EvidenceBundleDecision::Candidate,
        )
        .unwrap();
        assert!(build_evidence_delta(&other, &contract, &report).is_err());
        assert!(OriginalEvidenceSnapshot::new(
            BUNDLE,
            "target-1",
            BUNDLE_FP,
            EvidenceBundleDecision::Abstain
        )
        .is_err());
    }

    #[test]
    fn serialized_delta_cannot_change_resolution_without_integrity_failure() {
        let contract = contract(RevalidationSuccessCondition::ProbeSignalAbsent);
        let report = evaluate_revalidation(&contract, &[observation(1, true)]).unwrap();
        let delta = build_evidence_delta(&original(), &contract, &report).unwrap();
        let mut value = serde_json::to_value(&delta).unwrap();
        value["resolution"] = serde_json::json!("resolved");
        let tampered: EvidenceDelta = serde_json::from_value(value).unwrap();
        assert!(tampered.validate(&original(), &contract, &report).is_err());
        assert!(!delta.fingerprint().is_empty());
    }
}
