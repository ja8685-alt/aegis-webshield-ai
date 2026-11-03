//! Deployment-neutral contracts for Aegis Native Security Engine.
//!
//! This crate must not depend on Axum, SQLx, MongoDB clients, queue clients,
//! subprocess execution, or AI provider SDKs. Deployment adapters belong to
//! the control plane, scanner worker, and AI service.

mod ai_evaluation;
mod ai_review;
mod confidence_adjustment;
mod correlation;
mod error;
mod evidence_bundle;
mod evidence_delta;
mod feedback_profiles;
mod finding;
mod fix_guide;
mod fix_guide_generation;
mod models;
mod redaction;
mod revalidation;

pub use ai_evaluation::{
    evaluate_gold_dataset, AiEvaluationGateFailure, AiEvaluationGates, AiEvaluationPrediction,
    AiEvaluationReport, AiGoldCase, AiGoldDataset, GoldCaseSplit,
};
pub use ai_review::{
    evaluate_ai_review, AiAbstainReason, AiEvidenceClaim, AiReviewDecision, AiReviewDisposition,
    AiReviewLabel, AiReviewRequest, AiReviewResponse, AI_REVIEW_SYSTEM_POLICY,
};
pub use confidence_adjustment::{
    adjust_confidence, ConfidenceAdjustment, ConfidenceAdjustmentLimits,
    ConfidenceAdjustmentReport, ConfidenceDisposition, RulePrecisionClass, RulePrecisionProfile,
    RuleReliability, TargetNoiseProfile, TargetStabilityClass,
};
pub use correlation::{
    correlate_findings, CorrelatedFinding, CorrelationContext, CorrelationLimits,
    CorrelationReport, FindingCorrelationInput, RootCauseKey,
};
pub use error::ContractError;
pub use evidence_bundle::{
    EvidenceBundle, EvidenceBundleContext, EvidenceBundleDecision, EvidenceBundleLimits,
    EvidenceDecisionCeiling, EvidenceExchange, ReproductionContract, RoleReproductionContract,
};
pub use evidence_delta::{
    build_evidence_delta, AfterEvidenceState, EvidenceDelta, EvidenceDeltaReason,
    EvidenceResolution, OriginalEvidenceSnapshot,
};
pub use feedback_profiles::{
    learn_next_scan_plan, learn_rule_reliability, FeedbackRoute, NextScanPlanProfile,
    NextScanStrategy, RuleFeedbackEvent, RuleFeedbackLabel, RuleFeedbackLearningProfile,
    ScanPlanFeedbackEvent,
};
pub use finding::{
    CanonicalFinding, Confidence, FindingIdentity, FindingOccurrence, FindingProvenance,
    FindingTimeline, ParameterLocation, ReproductionOutcome, Severity, FINGERPRINT_VERSION,
};
pub use fix_guide::{
    ExampleLanguage, FixGuideContract, FixLocationBasis, FixLocationCandidate, FixLocationKind,
    FixReference, ReferenceAuthority, SafeFixExample, SafetyProperty, TechnologyStack,
};
pub use fix_guide_generation::{
    generate_fix_guide, EvidenceLocationFact, FixGuideGenerationMode, GeneratedFixGuide,
    StackSelection, StackSelectionEvidence,
};
pub use models::{
    ApprovedTarget, EvidenceRole, HeaderRecord, HttpMethod, NativeRequestRecord,
    NativeResponseRecord, NormalizedEvidence, Observation, PayloadSummary, RawExchangeEvidence,
    RequestPurpose, MAX_EVIDENCE_BODY_BYTES, MAX_HEADER_COUNT, MAX_HEADER_NAME_BYTES,
    MAX_HEADER_VALUE_BYTES, MAX_RESPONSE_BYTES, MAX_URL_BYTES,
};
pub use redaction::{redact_sensitive_text, RedactedText};
pub use revalidation::{
    evaluate_revalidation, RevalidationContract, RevalidationObservation, RevalidationOutcome,
    RevalidationReport, RevalidationStopReason, RevalidationSuccessCondition,
};

/// Version of the engine-to-service boundary contract.
pub const ENGINE_CONTRACT_VERSION: &str = "aegis.native.contract.v1";

/// Version of the safety policy consumed by the engine runtime.
pub const POLICY_SCHEMA_VERSION: &str = "aegis.native.policy.v1";

/// A runtime role that participates in a native scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeRole {
    /// Authenticated SaaS control plane implemented by Rust Axum.
    ControlPlane,
    /// Deployment-neutral request planning and deterministic decision core.
    EngineCore,
    /// Sandboxed process that owns target network execution.
    ScannerWorker,
    /// Evidence-limited analysis and Fix Guide service implemented by FastAPI.
    AiService,
}

/// Security-sensitive capabilities assigned to one runtime role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceBoundary {
    /// Participating runtime role.
    pub role: RuntimeRole,
    /// Whether the role may open connections to the approved scan target.
    pub target_network_access: bool,
    /// Whether the role may briefly access decrypted scan credentials.
    pub credential_plaintext_access: bool,
    /// Whether the role is authoritative for tenant authorization.
    pub tenant_authorization_owner: bool,
    /// Whether the role is authoritative for canonical product persistence.
    pub canonical_persistence_owner: bool,
}

/// Fixed least-privilege service boundaries for contract v1.
pub const SERVICE_BOUNDARIES: [ServiceBoundary; 4] = [
    ServiceBoundary {
        role: RuntimeRole::ControlPlane,
        target_network_access: false,
        credential_plaintext_access: false,
        tenant_authorization_owner: true,
        canonical_persistence_owner: true,
    },
    ServiceBoundary {
        role: RuntimeRole::EngineCore,
        target_network_access: false,
        credential_plaintext_access: false,
        tenant_authorization_owner: false,
        canonical_persistence_owner: false,
    },
    ServiceBoundary {
        role: RuntimeRole::ScannerWorker,
        target_network_access: true,
        credential_plaintext_access: true,
        tenant_authorization_owner: false,
        canonical_persistence_owner: false,
    },
    ServiceBoundary {
        role: RuntimeRole::AiService,
        target_network_access: false,
        credential_plaintext_access: false,
        tenant_authorization_owner: false,
        canonical_persistence_owner: false,
    },
];

/// Returns the boundary for a participating runtime role.
pub fn boundary_for(role: RuntimeRole) -> &'static ServiceBoundary {
    SERVICE_BOUNDARIES
        .iter()
        .find(|boundary| boundary.role == role)
        .expect("every runtime role must have a service boundary")
}

#[cfg(test)]
mod tests {
    use super::{boundary_for, RuntimeRole, SERVICE_BOUNDARIES};

    #[test]
    fn only_scanner_worker_can_reach_targets_or_plaintext_credentials() {
        let privileged = SERVICE_BOUNDARIES
            .iter()
            .filter(|boundary| {
                boundary.target_network_access || boundary.credential_plaintext_access
            })
            .collect::<Vec<_>>();
        assert_eq!(privileged.len(), 1);
        assert_eq!(privileged[0].role, RuntimeRole::ScannerWorker);
    }

    #[test]
    fn control_plane_owns_tenant_authorization_and_product_persistence() {
        let control_plane = boundary_for(RuntimeRole::ControlPlane);
        assert!(control_plane.tenant_authorization_owner);
        assert!(control_plane.canonical_persistence_owner);

        for boundary in SERVICE_BOUNDARIES
            .iter()
            .filter(|boundary| boundary.role != RuntimeRole::ControlPlane)
        {
            assert!(!boundary.tenant_authorization_owner);
            assert!(!boundary.canonical_persistence_owner);
        }
    }

    #[test]
    fn ai_service_receives_no_target_network_or_plaintext_secret_capability() {
        let ai = boundary_for(RuntimeRole::AiService);
        assert!(!ai.target_network_access);
        assert!(!ai.credential_plaintext_access);
    }
}
