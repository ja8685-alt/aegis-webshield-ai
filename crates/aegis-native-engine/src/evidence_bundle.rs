use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ApprovedTarget, ContractError, EvidenceRole, HttpMethod, NormalizedEvidence,
    RawExchangeEvidence, RedactedText, RequestPurpose,
};

const BUNDLE_PREFIX: &str = "bundle_";
const TENANT_PREFIX: &str = "tenant_";
const SCAN_PREFIX: &str = "scan_";
const DETECTOR_PREFIX: &str = "detector_";
const REPRODUCTION_PREFIX: &str = "repro_";
const ACTION_PREFIX: &str = "action_";
const HARD_MAX_REPETITIONS_PER_ROLE: usize = 5;
const HARD_MAX_EXCHANGES: usize = 15;
const MAX_REASON_BYTES: usize = 4_096;
const MAX_REPRODUCTION_WINDOW_MILLIS: u64 = 86_400_000;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBundleContext {
    tenant_ref: String,
    scan_ref: String,
    target_id: String,
    detector_ref: String,
    detector_version: String,
}

impl EvidenceBundleContext {
    pub fn new(
        tenant_ref: impl Into<String>,
        scan_ref: impl Into<String>,
        target_id: impl Into<String>,
        detector_ref: impl Into<String>,
        detector_version: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let context = Self {
            tenant_ref: tenant_ref.into(),
            scan_ref: scan_ref.into(),
            target_id: target_id.into(),
            detector_ref: detector_ref.into(),
            detector_version: detector_version.into(),
        };
        context.validate()?;
        Ok(context)
    }

    pub fn tenant_ref(&self) -> &str {
        &self.tenant_ref
    }

    pub fn scan_ref(&self) -> &str {
        &self.scan_ref
    }

    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    pub fn detector_ref(&self) -> &str {
        &self.detector_ref
    }

    pub fn detector_version(&self) -> &str {
        &self.detector_version
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_prefixed_hash("tenant_ref", &self.tenant_ref, TENANT_PREFIX)?;
        validate_prefixed_hash("scan_ref", &self.scan_ref, SCAN_PREFIX)?;
        validate_opaque_id("target_id", &self.target_id)?;
        validate_prefixed_hash("detector_ref", &self.detector_ref, DETECTOR_PREFIX)?;
        validate_opaque_id("detector_version", &self.detector_version)
    }
}

impl Debug for EvidenceBundleContext {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceBundleContext")
            .field("tenant_ref_bytes", &self.tenant_ref.len())
            .field("scan_ref_bytes", &self.scan_ref.len())
            .field("target_id_bytes", &self.target_id.len())
            .field("detector_ref_bytes", &self.detector_ref.len())
            .field("detector_version", &self.detector_version)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDecisionCeiling {
    CandidateOnly,
    FindingAllowed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceBundleDecision {
    Finding,
    Candidate,
    NotObserved,
    Abstain,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoleReproductionContract {
    role: EvidenceRole,
    request_fingerprint: String,
    safety_action_ref: String,
    repetitions: usize,
}

impl RoleReproductionContract {
    pub fn new(
        role: EvidenceRole,
        request_fingerprint: impl Into<String>,
        safety_action_ref: impl Into<String>,
        repetitions: usize,
    ) -> Result<Self, ContractError> {
        let contract = Self {
            role,
            request_fingerprint: request_fingerprint.into(),
            safety_action_ref: safety_action_ref.into(),
            repetitions,
        };
        contract.validate(HARD_MAX_REPETITIONS_PER_ROLE)?;
        Ok(contract)
    }

    pub fn role(&self) -> EvidenceRole {
        self.role
    }

    pub fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }

    pub fn safety_action_ref(&self) -> &str {
        &self.safety_action_ref
    }

    pub fn repetitions(&self) -> usize {
        self.repetitions
    }

    fn validate(&self, max_repetitions: usize) -> Result<(), ContractError> {
        validate_sha256("request_fingerprint", &self.request_fingerprint)?;
        validate_prefixed_hash("safety_action_ref", &self.safety_action_ref, ACTION_PREFIX)?;
        if self.repetitions < 2 || self.repetitions > max_repetitions {
            return Err(ContractError::new(
                "repetitions",
                "must contain two to five reproductions per evidence role",
            ));
        }
        Ok(())
    }
}

impl Debug for RoleReproductionContract {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RoleReproductionContract")
            .field("role", &self.role)
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("safety_action_ref_bytes", &self.safety_action_ref.len())
            .field("repetitions", &self.repetitions)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReproductionContract {
    contract_ref: String,
    roles: Vec<RoleReproductionContract>,
    decision_ceiling: EvidenceDecisionCeiling,
    issued_at_millis: u64,
    expires_at_millis: u64,
    explicitly_approved: bool,
}

impl ReproductionContract {
    pub fn new(
        contract_ref: impl Into<String>,
        roles: Vec<RoleReproductionContract>,
        decision_ceiling: EvidenceDecisionCeiling,
        issued_at_millis: u64,
        expires_at_millis: u64,
        explicitly_approved: bool,
    ) -> Result<Self, ContractError> {
        let contract = Self {
            contract_ref: contract_ref.into(),
            roles,
            decision_ceiling,
            issued_at_millis,
            expires_at_millis,
            explicitly_approved,
        };
        contract.validate(HARD_MAX_REPETITIONS_PER_ROLE)?;
        Ok(contract)
    }

    pub fn contract_ref(&self) -> &str {
        &self.contract_ref
    }

    pub fn roles(&self) -> &[RoleReproductionContract] {
        &self.roles
    }

    pub fn decision_ceiling(&self) -> EvidenceDecisionCeiling {
        self.decision_ceiling
    }

    fn validate(&self, max_repetitions: usize) -> Result<(), ContractError> {
        validate_prefixed_hash("contract_ref", &self.contract_ref, REPRODUCTION_PREFIX)?;
        if !self.explicitly_approved {
            return Err(ContractError::new(
                "explicitly_approved",
                "reproduction contract must be explicitly approved",
            ));
        }
        if self.expires_at_millis <= self.issued_at_millis
            || self.expires_at_millis - self.issued_at_millis > MAX_REPRODUCTION_WINDOW_MILLIS
        {
            return Err(ContractError::new(
                "expires_at_millis",
                "reproduction window must be positive and at most 24 hours",
            ));
        }
        if self.roles.len() != 3 {
            return Err(ContractError::new(
                "roles",
                "reproduction contract requires baseline, probe, and control",
            ));
        }
        let mut roles = BTreeSet::new();
        for role in &self.roles {
            role.validate(max_repetitions)?;
            if !roles.insert(role.role) {
                return Err(ContractError::new("roles", "evidence role is duplicated"));
            }
        }
        if roles
            != BTreeSet::from([
                EvidenceRole::Baseline,
                EvidenceRole::Probe,
                EvidenceRole::Control,
            ])
        {
            return Err(ContractError::new(
                "roles",
                "baseline, probe, and control are all required",
            ));
        }
        Ok(())
    }
}

impl Debug for ReproductionContract {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReproductionContract")
            .field("contract_ref_bytes", &self.contract_ref.len())
            .field("role_count", &self.roles.len())
            .field("decision_ceiling", &self.decision_ceiling)
            .field("issued_at_millis", &self.issued_at_millis)
            .field("expires_at_millis", &self.expires_at_millis)
            .field("explicitly_approved", &self.explicitly_approved)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceExchange {
    repetition: usize,
    request_fingerprint: String,
    raw: RawExchangeEvidence,
    normalized: NormalizedEvidence,
}

impl EvidenceExchange {
    pub fn new(
        repetition: usize,
        request_fingerprint: impl Into<String>,
        raw: RawExchangeEvidence,
        normalized: NormalizedEvidence,
    ) -> Result<Self, ContractError> {
        let exchange = Self {
            repetition,
            request_fingerprint: request_fingerprint.into(),
            raw,
            normalized,
        };
        validate_sha256("request_fingerprint", &exchange.request_fingerprint)?;
        Ok(exchange)
    }

    pub fn role(&self) -> EvidenceRole {
        self.raw.role
    }

    pub fn repetition(&self) -> usize {
        self.repetition
    }

    pub fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }

    pub fn raw(&self) -> &RawExchangeEvidence {
        &self.raw
    }

    pub fn normalized(&self) -> &NormalizedEvidence {
        &self.normalized
    }
}

impl Debug for EvidenceExchange {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceExchange")
            .field("role", &self.raw.role)
            .field("repetition", &self.repetition)
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("raw_evidence_id_bytes", &self.raw.evidence_id.len())
            .field(
                "normalized_evidence_id_bytes",
                &self.normalized.evidence_id.len(),
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceBundleLimits {
    pub max_repetitions_per_role: usize,
    pub max_exchanges: usize,
}

impl Default for EvidenceBundleLimits {
    fn default() -> Self {
        Self {
            max_repetitions_per_role: HARD_MAX_REPETITIONS_PER_ROLE,
            max_exchanges: HARD_MAX_EXCHANGES,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    bundle_ref: String,
    context: EvidenceBundleContext,
    reproduction: ReproductionContract,
    decision: EvidenceBundleDecision,
    decision_reason: RedactedText,
    exchanges: Vec<EvidenceExchange>,
    finalized_at_millis: u64,
    fingerprint: String,
}

impl EvidenceBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bundle_ref: impl Into<String>,
        context: EvidenceBundleContext,
        reproduction: ReproductionContract,
        decision: EvidenceBundleDecision,
        decision_reason: &str,
        mut exchanges: Vec<EvidenceExchange>,
        finalized_at_millis: u64,
        target: &ApprovedTarget,
        limits: EvidenceBundleLimits,
    ) -> Result<Self, ContractError> {
        let decision_reason = RedactedText::new(decision_reason, MAX_REASON_BYTES)?;
        exchanges.sort_by_key(|exchange| (role_rank(exchange.role()), exchange.repetition));
        let mut bundle = Self {
            bundle_ref: bundle_ref.into(),
            context,
            reproduction,
            decision,
            decision_reason,
            exchanges,
            finalized_at_millis,
            fingerprint: String::new(),
        };
        bundle.validate_without_fingerprint(target, limits)?;
        bundle.fingerprint = bundle.compute_fingerprint();
        Ok(bundle)
    }

    pub fn bundle_ref(&self) -> &str {
        &self.bundle_ref
    }

    pub fn context(&self) -> &EvidenceBundleContext {
        &self.context
    }

    pub fn reproduction(&self) -> &ReproductionContract {
        &self.reproduction
    }

    pub fn decision(&self) -> EvidenceBundleDecision {
        self.decision
    }

    pub fn decision_reason(&self) -> &RedactedText {
        &self.decision_reason
    }

    pub fn exchanges(&self) -> &[EvidenceExchange] {
        &self.exchanges
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn validate(
        &self,
        target: &ApprovedTarget,
        limits: EvidenceBundleLimits,
    ) -> Result<(), ContractError> {
        self.validate_without_fingerprint(target, limits)?;
        validate_sha256("fingerprint", &self.fingerprint)?;
        if self.fingerprint != self.compute_fingerprint() {
            return Err(ContractError::new(
                "fingerprint",
                "evidence bundle integrity fingerprint does not match",
            ));
        }
        Ok(())
    }

    fn validate_without_fingerprint(
        &self,
        target: &ApprovedTarget,
        limits: EvidenceBundleLimits,
    ) -> Result<(), ContractError> {
        validate_limits(limits)?;
        validate_prefixed_hash("bundle_ref", &self.bundle_ref, BUNDLE_PREFIX)?;
        self.context.validate()?;
        self.reproduction
            .validate(limits.max_repetitions_per_role)?;
        if self.context.target_id != target.target_id {
            return Err(ContractError::new(
                "target_id",
                "bundle context does not match approved target",
            ));
        }
        if self.finalized_at_millis < self.reproduction.issued_at_millis
            || self.finalized_at_millis > self.reproduction.expires_at_millis
        {
            return Err(ContractError::new(
                "finalized_at_millis",
                "bundle must be finalized inside the reproduction window",
            ));
        }
        if self.decision_reason.as_str().is_empty() || self.decision_reason.truncated() {
            return Err(ContractError::new(
                "decision_reason",
                "decision reason must be present without truncation",
            ));
        }
        if self.decision == EvidenceBundleDecision::Finding
            && self.reproduction.decision_ceiling == EvidenceDecisionCeiling::CandidateOnly
        {
            return Err(ContractError::new(
                "decision",
                "candidate-only reproduction cannot create a finding",
            ));
        }
        let expected_count = self
            .reproduction
            .roles
            .iter()
            .map(|role| role.repetitions)
            .sum::<usize>();
        if self.exchanges.len() != expected_count || self.exchanges.len() > limits.max_exchanges {
            return Err(ContractError::new(
                "exchanges",
                "exchange count must exactly match the reproduction contract",
            ));
        }
        let contracts = self
            .reproduction
            .roles
            .iter()
            .map(|contract| (contract.role, contract))
            .collect::<BTreeMap<_, _>>();
        let mut role_repetitions = BTreeSet::new();
        let mut raw_ids = BTreeSet::new();
        let mut normalized_ids = BTreeSet::new();
        let mut request_ids = BTreeSet::new();
        for exchange in &self.exchanges {
            exchange.raw.validate(target)?;
            exchange.normalized.validate()?;
            let contract = contracts.get(&exchange.role()).ok_or_else(|| {
                ContractError::new("role", "exchange role is not in reproduction contract")
            })?;
            if exchange.repetition == 0
                || exchange.repetition > contract.repetitions
                || exchange.request_fingerprint != contract.request_fingerprint
                || exchange.raw.request.target_id != self.context.target_id
                || exchange.normalized.role != exchange.raw.role
                || exchange.normalized.raw_evidence_ref != exchange.raw.evidence_id
            {
                return Err(ContractError::new(
                    "exchange",
                    "exchange does not match role, repetition, target, or raw reference",
                ));
            }
            if !role_repetitions.insert((exchange.role(), exchange.repetition))
                || !raw_ids.insert(exchange.raw.evidence_id.as_str())
                || !normalized_ids.insert(exchange.normalized.evidence_id.as_str())
                || !request_ids.insert(exchange.raw.request.request_id.as_str())
            {
                return Err(ContractError::new(
                    "exchange",
                    "exchange role, evidence, or request identifier is duplicated",
                ));
            }
        }
        Ok(())
    }

    fn compute_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "aegis.evidence.bundle.v1");
        hash_field(&mut hasher, &self.bundle_ref);
        hash_field(&mut hasher, &self.context.tenant_ref);
        hash_field(&mut hasher, &self.context.scan_ref);
        hash_field(&mut hasher, &self.context.target_id);
        hash_field(&mut hasher, &self.context.detector_ref);
        hash_field(&mut hasher, &self.context.detector_version);
        hash_field(&mut hasher, &self.reproduction.contract_ref);
        hash_field(
            &mut hasher,
            match self.reproduction.decision_ceiling {
                EvidenceDecisionCeiling::CandidateOnly => "candidate_only",
                EvidenceDecisionCeiling::FindingAllowed => "finding_allowed",
            },
        );
        hash_field(&mut hasher, &self.reproduction.issued_at_millis.to_string());
        hash_field(
            &mut hasher,
            &self.reproduction.expires_at_millis.to_string(),
        );
        hash_field(&mut hasher, decision_tag(self.decision));
        hash_field(&mut hasher, self.decision_reason.as_str());
        hash_field(&mut hasher, &self.finalized_at_millis.to_string());
        let mut role_contracts = self.reproduction.roles.iter().collect::<Vec<_>>();
        role_contracts.sort_by_key(|contract| role_rank(contract.role));
        for contract in role_contracts {
            hash_field(&mut hasher, role_tag(contract.role));
            hash_field(&mut hasher, &contract.request_fingerprint);
            hash_field(&mut hasher, &contract.safety_action_ref);
            hash_field(&mut hasher, &contract.repetitions.to_string());
        }
        let mut exchanges = self.exchanges.iter().collect::<Vec<_>>();
        exchanges.sort_by_key(|exchange| (role_rank(exchange.role()), exchange.repetition));
        for exchange in exchanges {
            hash_exchange(&mut hasher, exchange);
        }
        format!("{:x}", hasher.finalize())
    }
}

impl Debug for EvidenceBundle {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceBundle")
            .field("bundle_ref_bytes", &self.bundle_ref.len())
            .field("context", &self.context)
            .field("reproduction", &self.reproduction)
            .field("decision", &self.decision)
            .field(
                "decision_reason_bytes",
                &self.decision_reason.as_str().len(),
            )
            .field("exchange_count", &self.exchanges.len())
            .field("finalized_at_millis", &self.finalized_at_millis)
            .field("fingerprint_bytes", &self.fingerprint.len())
            .finish()
    }
}

fn validate_limits(limits: EvidenceBundleLimits) -> Result<(), ContractError> {
    if limits.max_repetitions_per_role < 2
        || limits.max_repetitions_per_role > HARD_MAX_REPETITIONS_PER_ROLE
        || limits.max_exchanges < 6
        || limits.max_exchanges > HARD_MAX_EXCHANGES
    {
        return Err(ContractError::new(
            "limits",
            "evidence bundle limits exceed hard policy",
        ));
    }
    Ok(())
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
            "must use the required prefix and 32 lowercase hexadecimal characters",
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
            "must be a lowercase SHA-256 hexadecimal digest",
        ));
    }
    Ok(())
}

fn validate_opaque_id(field: &'static str, value: &str) -> Result<(), ContractError> {
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

fn hash_exchange(hasher: &mut Sha256, exchange: &EvidenceExchange) {
    hash_field(hasher, role_tag(exchange.raw.role));
    hash_field(hasher, &exchange.repetition.to_string());
    hash_field(hasher, &exchange.request_fingerprint);
    hash_field(hasher, &exchange.raw.evidence_id);
    hash_field(hasher, &exchange.raw.request.request_id);
    hash_field(hasher, &exchange.raw.request.target_id);
    hash_field(hasher, method_tag(exchange.raw.request.method));
    hash_field(hasher, &exchange.raw.request.url);
    hash_field(hasher, purpose_tag(exchange.raw.request.purpose));
    for header in &exchange.raw.request.headers {
        hash_field(hasher, &header.name);
        hash_field(hasher, header.value.as_str());
    }
    if let Some(payload) = &exchange.raw.request.payload {
        hash_field(hasher, &payload.byte_length.to_string());
        hash_field(hasher, &payload.sha256);
        hash_field(hasher, payload.redacted_excerpt.as_str());
        hash_field(hasher, if payload.truncated { "true" } else { "false" });
    }
    hash_field(
        hasher,
        exchange
            .raw
            .request
            .credential_ref
            .as_deref()
            .unwrap_or("none"),
    );
    hash_field(hasher, &exchange.raw.response.status_code.to_string());
    hash_field(hasher, &exchange.raw.response.final_url);
    for header in &exchange.raw.response.headers {
        hash_field(hasher, &header.name);
        hash_field(hasher, header.value.as_str());
    }
    hash_field(hasher, &exchange.raw.response.payload.sha256);
    hash_field(
        hasher,
        &exchange.raw.response.payload.byte_length.to_string(),
    );
    hash_field(
        hasher,
        exchange.raw.response.payload.redacted_excerpt.as_str(),
    );
    hash_field(
        hasher,
        if exchange.raw.response.payload.truncated {
            "true"
        } else {
            "false"
        },
    );
    hash_field(hasher, &exchange.raw.response.duration_millis.to_string());
    hash_field(hasher, &exchange.raw.captured_at);
    hash_field(hasher, &exchange.normalized.evidence_id);
    hash_field(hasher, &exchange.normalized.raw_evidence_ref);
    for observation in &exchange.normalized.observations {
        hash_field(hasher, &observation.code);
        hash_field(hasher, observation.value.as_str());
    }
    hash_field(hasher, exchange.normalized.decision_reason.as_str());
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn role_rank(role: EvidenceRole) -> u8 {
    match role {
        EvidenceRole::Baseline => 0,
        EvidenceRole::Probe => 1,
        EvidenceRole::Control => 2,
    }
}

fn role_tag(role: EvidenceRole) -> &'static str {
    match role {
        EvidenceRole::Baseline => "baseline",
        EvidenceRole::Probe => "probe",
        EvidenceRole::Control => "control",
    }
}

fn method_tag(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Head => "HEAD",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Post => "POST",
    }
}

fn purpose_tag(purpose: RequestPurpose) -> &'static str {
    match purpose {
        RequestPurpose::Discovery => "discovery",
        RequestPurpose::Baseline => "baseline",
        RequestPurpose::Probe => "probe",
        RequestPurpose::Control => "control",
    }
}

fn decision_tag(decision: EvidenceBundleDecision) -> &'static str {
    match decision {
        EvidenceBundleDecision::Finding => "finding",
        EvidenceBundleDecision::Candidate => "candidate",
        EvidenceBundleDecision::NotObserved => "not_observed",
        EvidenceBundleDecision::Abstain => "abstain",
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ApprovedTarget, EvidenceRole, HeaderRecord, HttpMethod, NativeRequestRecord,
        NativeResponseRecord, NormalizedEvidence, Observation, PayloadSummary, RawExchangeEvidence,
        RedactedText, RequestPurpose,
    };

    use super::{
        EvidenceBundle, EvidenceBundleContext, EvidenceBundleDecision, EvidenceBundleLimits,
        EvidenceDecisionCeiling, EvidenceExchange, ReproductionContract, RoleReproductionContract,
    };

    const TENANT: &str = "tenant_0123456789abcdef0123456789abcdef";
    const SCAN: &str = "scan_0123456789abcdef0123456789abcdef";
    const DETECTOR: &str = "detector_0123456789abcdef0123456789abcdef";
    const REPRO: &str = "repro_0123456789abcdef0123456789abcdef";
    const BUNDLE: &str = "bundle_0123456789abcdef0123456789abcdef";
    const ACTION_BASELINE: &str = "action_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ACTION_PROBE: &str = "action_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ACTION_CONTROL: &str = "action_cccccccccccccccccccccccccccccccc";
    const FP_BASELINE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FP_PROBE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const FP_CONTROL: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn target() -> ApprovedTarget {
        ApprovedTarget::new("target-1", "https://example.com", "/api/").unwrap()
    }

    fn context() -> EvidenceBundleContext {
        EvidenceBundleContext::new(TENANT, SCAN, "target-1", DETECTOR, "1.2.3").unwrap()
    }

    fn fingerprint(role: EvidenceRole) -> &'static str {
        match role {
            EvidenceRole::Baseline => FP_BASELINE,
            EvidenceRole::Probe => FP_PROBE,
            EvidenceRole::Control => FP_CONTROL,
        }
    }

    fn purpose(role: EvidenceRole) -> RequestPurpose {
        match role {
            EvidenceRole::Baseline => RequestPurpose::Baseline,
            EvidenceRole::Probe => RequestPurpose::Probe,
            EvidenceRole::Control => RequestPurpose::Control,
        }
    }

    fn role_name(role: EvidenceRole) -> &'static str {
        match role {
            EvidenceRole::Baseline => "baseline",
            EvidenceRole::Probe => "probe",
            EvidenceRole::Control => "control",
        }
    }

    fn reproduction(ceiling: EvidenceDecisionCeiling) -> ReproductionContract {
        ReproductionContract::new(
            REPRO,
            vec![
                RoleReproductionContract::new(
                    EvidenceRole::Baseline,
                    FP_BASELINE,
                    ACTION_BASELINE,
                    2,
                )
                .unwrap(),
                RoleReproductionContract::new(EvidenceRole::Probe, FP_PROBE, ACTION_PROBE, 2)
                    .unwrap(),
                RoleReproductionContract::new(EvidenceRole::Control, FP_CONTROL, ACTION_CONTROL, 2)
                    .unwrap(),
            ],
            ceiling,
            1_000,
            10_000,
            true,
        )
        .unwrap()
    }

    fn exchange(role: EvidenceRole, repetition: usize) -> EvidenceExchange {
        let name = role_name(role);
        let raw_id = format!("raw-{name}-{repetition}");
        let request = NativeRequestRecord {
            request_id: format!("request-{name}-{repetition}"),
            target_id: "target-1".to_string(),
            method: HttpMethod::Get,
            url: format!("https://example.com/api/orders?id={repetition}"),
            purpose: purpose(role),
            headers: vec![HeaderRecord::new("Authorization", "Bearer raw-secret").unwrap()],
            payload: None,
            credential_ref: Some("credential-ref".to_string()),
        };
        let response = NativeResponseRecord {
            status_code: if role == EvidenceRole::Probe {
                403
            } else {
                200
            },
            final_url: format!("https://example.com/api/orders?id={repetition}"),
            headers: vec![HeaderRecord::new("Content-Type", "application/json").unwrap()],
            payload: PayloadSummary::from_bytes(
                format!("{{\"role\":\"{name}\",\"access_token\":\"secret\"}}").as_bytes(),
                false,
            )
            .unwrap(),
            duration_millis: 25,
        };
        let raw = RawExchangeEvidence {
            evidence_id: raw_id.clone(),
            role,
            request,
            response,
            captured_at: "2026-07-16T12:00:00Z".to_string(),
        };
        let normalized = NormalizedEvidence {
            evidence_id: format!("normalized-{name}-{repetition}"),
            raw_evidence_ref: raw_id,
            role,
            observations: vec![Observation::new("status_class", "stable").unwrap()],
            decision_reason: RedactedText::new("deterministic role comparison", 4_096).unwrap(),
        };
        EvidenceExchange::new(repetition, fingerprint(role), raw, normalized).unwrap()
    }

    fn exchanges() -> Vec<EvidenceExchange> {
        let mut values = Vec::new();
        for role in [
            EvidenceRole::Control,
            EvidenceRole::Baseline,
            EvidenceRole::Probe,
        ] {
            values.push(exchange(role, 2));
            values.push(exchange(role, 1));
        }
        values
    }

    fn bundle() -> EvidenceBundle {
        EvidenceBundle::new(
            BUNDLE,
            context(),
            reproduction(EvidenceDecisionCeiling::CandidateOnly),
            EvidenceBundleDecision::Candidate,
            "probe differs from control; access_token=raw-secret",
            exchanges(),
            5_000,
            &target(),
            EvidenceBundleLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn complete_bundle_orders_roles_redacts_reason_and_round_trips() {
        let bundle = bundle();
        assert_eq!(bundle.exchanges().len(), 6);
        assert_eq!(bundle.exchanges()[0].role(), EvidenceRole::Baseline);
        assert_eq!(bundle.exchanges()[0].repetition(), 1);
        assert_eq!(bundle.fingerprint().len(), 64);
        assert!(!bundle.decision_reason().as_str().contains("raw-secret"));
        assert!(bundle
            .validate(&target(), EvidenceBundleLimits::default())
            .is_ok());
        let serialized = serde_json::to_string(&bundle).unwrap();
        let restored: EvidenceBundle = serde_json::from_str(&serialized).unwrap();
        assert_eq!(restored, bundle);
        assert!(restored
            .validate(&target(), EvidenceBundleLimits::default())
            .is_ok());
    }

    #[test]
    fn missing_role_repetition_is_rejected() {
        let mut incomplete = exchanges();
        incomplete.pop();
        let error = EvidenceBundle::new(
            BUNDLE,
            context(),
            reproduction(EvidenceDecisionCeiling::CandidateOnly),
            EvidenceBundleDecision::Candidate,
            "complete differential evidence",
            incomplete,
            5_000,
            &target(),
            EvidenceBundleLimits::default(),
        )
        .unwrap_err();
        assert_eq!(error.field(), "exchanges");
    }

    #[test]
    fn raw_normalized_reference_and_request_fingerprint_are_bound() {
        let mut bad_reference = exchanges();
        bad_reference[0].normalized.raw_evidence_ref = "raw-other".to_string();
        let error = EvidenceBundle::new(
            BUNDLE,
            context(),
            reproduction(EvidenceDecisionCeiling::CandidateOnly),
            EvidenceBundleDecision::Candidate,
            "linked evidence",
            bad_reference,
            5_000,
            &target(),
            EvidenceBundleLimits::default(),
        )
        .unwrap_err();
        assert_eq!(error.field(), "exchange");

        let mut bad_fingerprint = exchanges();
        bad_fingerprint[0].request_fingerprint = FP_PROBE.to_string();
        let error = EvidenceBundle::new(
            BUNDLE,
            context(),
            reproduction(EvidenceDecisionCeiling::CandidateOnly),
            EvidenceBundleDecision::Candidate,
            "bound request",
            bad_fingerprint,
            5_000,
            &target(),
            EvidenceBundleLimits::default(),
        )
        .unwrap_err();
        assert_eq!(error.field(), "exchange");
    }

    #[test]
    fn candidate_only_contract_cannot_create_finding() {
        let error = EvidenceBundle::new(
            BUNDLE,
            context(),
            reproduction(EvidenceDecisionCeiling::CandidateOnly),
            EvidenceBundleDecision::Finding,
            "must stay candidate",
            exchanges(),
            5_000,
            &target(),
            EvidenceBundleLimits::default(),
        )
        .unwrap_err();
        assert_eq!(error.field(), "decision");

        assert!(EvidenceBundle::new(
            BUNDLE,
            context(),
            reproduction(EvidenceDecisionCeiling::FindingAllowed),
            EvidenceBundleDecision::Finding,
            "passive deterministic finding",
            exchanges(),
            5_000,
            &target(),
            EvidenceBundleLimits::default(),
        )
        .is_ok());
    }

    #[test]
    fn duplicate_ids_and_integrity_tampering_are_rejected() {
        let mut duplicate = exchanges();
        duplicate[1].raw.evidence_id = duplicate[0].raw.evidence_id.clone();
        let error = EvidenceBundle::new(
            BUNDLE,
            context(),
            reproduction(EvidenceDecisionCeiling::CandidateOnly),
            EvidenceBundleDecision::Candidate,
            "unique evidence",
            duplicate,
            5_000,
            &target(),
            EvidenceBundleLimits::default(),
        )
        .unwrap_err();
        assert_eq!(error.field(), "exchange");

        let mut tampered = bundle();
        tampered.exchanges[0].raw.response.status_code = 201;
        let error = tampered
            .validate(&target(), EvidenceBundleLimits::default())
            .unwrap_err();
        assert_eq!(error.field(), "fingerprint");
    }

    #[test]
    fn reproduction_window_approval_and_debug_fail_closed() {
        let roles = reproduction(EvidenceDecisionCeiling::CandidateOnly)
            .roles()
            .to_vec();
        let error = ReproductionContract::new(
            REPRO,
            roles.clone(),
            EvidenceDecisionCeiling::CandidateOnly,
            1_000,
            2_000,
            false,
        )
        .unwrap_err();
        assert_eq!(error.field(), "explicitly_approved");
        let error = ReproductionContract::new(
            REPRO,
            roles,
            EvidenceDecisionCeiling::CandidateOnly,
            1_000,
            1_000 + 86_400_001,
            true,
        )
        .unwrap_err();
        assert_eq!(error.field(), "expires_at_millis");

        let bundle = bundle();
        let debug = format!("{bundle:?} {:?}", bundle.exchanges()[0]);
        assert!(!debug.contains("example.com"));
        assert!(!debug.contains(BUNDLE));
        assert!(!debug.contains(FP_BASELINE));
        assert!(!debug.contains("raw-secret"));
    }
}
