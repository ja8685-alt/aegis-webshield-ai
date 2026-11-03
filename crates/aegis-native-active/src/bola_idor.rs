use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Display, Formatter};

use aegis_native_engine::{Confidence, FindingIdentity, HttpMethod, ParameterLocation};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    plan_role_comparison, RoleAccessOutcome, RoleAccount, RoleComparisonContract,
    RoleComparisonError, RoleComparisonLimits, RoleComparisonMatrix, RoleComparisonPlan,
    RolePairRelation,
};

const OBJECT_PLACEHOLDER: &str = "{aegis_object_id}";
const OBJECT_PREFIX: &str = "object_";
const ROLE_PREFIX: &str = "role_";
const HARD_OBJECT_COUNT: usize = 2;
const HARD_MAX_REPETITIONS_PER_ROLE: usize = 3;
const HARD_MAX_IDENTIFIER_BYTES: usize = 128;
const HARD_MAX_REQUESTS: usize =
    HARD_OBJECT_COUNT * HARD_OBJECT_COUNT * HARD_MAX_REPETITIONS_PER_ROLE;

#[derive(Clone, Eq, PartialEq)]
pub struct OwnedObjectFixture {
    object_ref: String,
    owner_role_ref: String,
    identifier_value: String,
    identifier_fingerprint: String,
}

impl OwnedObjectFixture {
    pub fn new(
        object_ref: impl Into<String>,
        owner_role_ref: impl Into<String>,
        identifier_value: impl Into<String>,
        ownership_verified: bool,
        synthetic_and_disposable: bool,
    ) -> Result<Self, BolaRuntimeError> {
        let object_ref = object_ref.into();
        let owner_role_ref = owner_role_ref.into();
        let identifier_value = identifier_value.into();
        if !ownership_verified || !synthetic_and_disposable {
            return Err(BolaRuntimeError::UnsafeFixture);
        }
        if !valid_prefixed_hash(&object_ref, OBJECT_PREFIX)
            || !valid_prefixed_hash(&owner_role_ref, ROLE_PREFIX)
            || !valid_identifier(&identifier_value, HARD_MAX_IDENTIFIER_BYTES)
        {
            return Err(BolaRuntimeError::InvalidFixture);
        }
        let identifier_fingerprint = sha256_hex(identifier_value.as_bytes());
        Ok(Self {
            object_ref,
            owner_role_ref,
            identifier_value,
            identifier_fingerprint,
        })
    }

    pub fn object_ref(&self) -> &str {
        &self.object_ref
    }

    pub fn owner_role_ref(&self) -> &str {
        &self.owner_role_ref
    }
}

impl Debug for OwnedObjectFixture {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnedObjectFixture")
            .field("object_ref_bytes", &self.object_ref.len())
            .field("owner_role_ref_bytes", &self.owner_role_ref.len())
            .field("identifier_value_bytes", &self.identifier_value.len())
            .field(
                "identifier_fingerprint_bytes",
                &self.identifier_fingerprint.len(),
            )
            .finish()
    }
}

pub struct BolaContract<'a> {
    pub target_id: &'a str,
    pub endpoint_template: &'a str,
    pub method: HttpMethod,
    pub parameter_location: ParameterLocation,
    pub parameter_name: &'a str,
    pub base_request_fingerprint: &'a str,
    pub repetitions_per_role: usize,
    pub planned_at_millis: u64,
    pub explicitly_approved: bool,
}

impl Debug for BolaContract<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BolaContract")
            .field("method", &self.method)
            .field("parameter_location", &self.parameter_location)
            .field("parameter_name_bytes", &self.parameter_name.len())
            .field("endpoint_template_bytes", &self.endpoint_template.len())
            .field(
                "base_request_fingerprint_bytes",
                &self.base_request_fingerprint.len(),
            )
            .field("repetitions_per_role", &self.repetitions_per_role)
            .field("planned_at_millis", &self.planned_at_millis)
            .field("explicitly_approved", &self.explicitly_approved)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BolaLimits {
    pub object_count: usize,
    pub max_repetitions_per_role: usize,
    pub max_identifier_bytes: usize,
    pub max_requests: usize,
}

impl Default for BolaLimits {
    fn default() -> Self {
        Self {
            object_count: HARD_OBJECT_COUNT,
            max_repetitions_per_role: HARD_MAX_REPETITIONS_PER_ROLE,
            max_identifier_bytes: HARD_MAX_IDENTIFIER_BYTES,
            max_requests: HARD_MAX_REQUESTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BolaRuntimeError {
    InvalidLimits,
    InvalidContract,
    UnapprovedProbe,
    UnsafeFixture,
    InvalidFixture,
    DuplicateFixture,
    AccountFixtureMismatch,
    RequestLimitExceeded,
    RoleComparisonRejected,
    InvalidEvidence,
    MissingEvidence,
}

impl Display for BolaRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "BOLA/IDOR limits are invalid",
            Self::InvalidContract => "BOLA/IDOR contract is invalid",
            Self::UnapprovedProbe => "BOLA/IDOR probe was not explicitly approved",
            Self::UnsafeFixture => "BOLA/IDOR fixture is not verified synthetic test data",
            Self::InvalidFixture => "BOLA/IDOR fixture is invalid",
            Self::DuplicateFixture => "BOLA/IDOR fixtures are not ownership-isolated",
            Self::AccountFixtureMismatch => "BOLA/IDOR role accounts do not match fixture owners",
            Self::RequestLimitExceeded => "BOLA/IDOR request limit was exceeded",
            Self::RoleComparisonRejected => "BOLA/IDOR role comparison was rejected",
            Self::InvalidEvidence => "BOLA/IDOR comparison evidence is invalid",
            Self::MissingEvidence => "BOLA/IDOR comparison evidence is incomplete",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for BolaRuntimeError {}

impl From<RoleComparisonError> for BolaRuntimeError {
    fn from(_: RoleComparisonError) -> Self {
        Self::RoleComparisonRejected
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BolaObjectPlan {
    object_ref: String,
    owner_role_ref: String,
    identifier_value: String,
    identifier_fingerprint: String,
    request_fingerprint: String,
    comparison_plan: RoleComparisonPlan,
}

impl BolaObjectPlan {
    pub fn object_ref(&self) -> &str {
        &self.object_ref
    }

    pub fn owner_role_ref(&self) -> &str {
        &self.owner_role_ref
    }

    pub fn identifier_value(&self) -> &str {
        &self.identifier_value
    }

    pub fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }

    pub fn comparison_plan(&self) -> &RoleComparisonPlan {
        &self.comparison_plan
    }
}

impl Debug for BolaObjectPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BolaObjectPlan")
            .field("object_ref_bytes", &self.object_ref.len())
            .field("owner_role_ref_bytes", &self.owner_role_ref.len())
            .field("identifier_value_bytes", &self.identifier_value.len())
            .field(
                "identifier_fingerprint_bytes",
                &self.identifier_fingerprint.len(),
            )
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("comparison_plan", &self.comparison_plan)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BolaPlan {
    identity: FindingIdentity,
    objects: Vec<BolaObjectPlan>,
    request_count: usize,
}

impl BolaPlan {
    pub fn canonical_endpoint(&self) -> &str {
        &self.identity.canonical_endpoint
    }

    pub fn objects(&self) -> &[BolaObjectPlan] {
        &self.objects
    }

    pub fn request_count(&self) -> usize {
        self.request_count
    }
}

impl Debug for BolaPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BolaPlan")
            .field(
                "canonical_endpoint_bytes",
                &self.identity.canonical_endpoint.len(),
            )
            .field("object_count", &self.objects.len())
            .field("request_count", &self.request_count)
            .finish()
    }
}

pub struct BolaObjectEvidence<'a> {
    pub object_ref: &'a str,
    pub request_fingerprint: &'a str,
    pub comparison: &'a RoleComparisonMatrix,
}

impl Debug for BolaObjectEvidence<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BolaObjectEvidence")
            .field("object_ref_bytes", &self.object_ref.len())
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("comparison", &self.comparison)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BolaObjectDecision {
    Protected,
    EquivalentUnauthorizedAccess,
    DifferentialUnauthorizedAccess,
    Indeterminate,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BolaObjectAssessment {
    pub object_ref: String,
    pub decision: BolaObjectDecision,
    pub evidence_refs: Vec<String>,
}

impl Debug for BolaObjectAssessment {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BolaObjectAssessment")
            .field("object_ref_bytes", &self.object_ref.len())
            .field("decision", &self.decision)
            .field("evidence_ref_count", &self.evidence_refs.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BolaDecision {
    Candidate,
    NotObserved,
    Abstain,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BolaCandidate {
    pub candidate_id: String,
    pub confidence: Confidence,
    pub exposed_object_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub requires_manual_confirmation: bool,
}

impl Debug for BolaCandidate {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BolaCandidate")
            .field("candidate_id_bytes", &self.candidate_id.len())
            .field("confidence", &self.confidence)
            .field("exposed_object_count", &self.exposed_object_refs.len())
            .field("evidence_ref_count", &self.evidence_refs.len())
            .field(
                "requires_manual_confirmation",
                &self.requires_manual_confirmation,
            )
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BolaAssessment {
    pub decision: BolaDecision,
    pub objects: Vec<BolaObjectAssessment>,
    pub candidate: Option<BolaCandidate>,
}

pub fn plan_bola_idor(
    contract: &BolaContract<'_>,
    accounts: &[RoleAccount],
    fixtures: &[OwnedObjectFixture],
    limits: BolaLimits,
) -> Result<BolaPlan, BolaRuntimeError> {
    validate_limits(limits)?;
    if !contract.explicitly_approved {
        return Err(BolaRuntimeError::UnapprovedProbe);
    }
    validate_contract(contract, limits)?;
    validate_fixtures(accounts, fixtures, limits)?;
    let request_count = fixtures
        .len()
        .saturating_mul(accounts.len())
        .saturating_mul(contract.repetitions_per_role);
    if request_count > limits.max_requests {
        return Err(BolaRuntimeError::RequestLimitExceeded);
    }

    let identity_endpoint = replace_placeholder(contract.endpoint_template, "aegisobjectfixture")?;
    let identity = FindingIdentity::new(
        contract.target_id,
        contract.method,
        &identity_endpoint,
        "CWE-639",
        contract.parameter_location,
        Some(contract.parameter_name.to_string()),
    )
    .map_err(|_| BolaRuntimeError::InvalidContract)?;

    let mut objects = Vec::with_capacity(fixtures.len());
    for fixture in fixtures {
        let endpoint = replace_placeholder(contract.endpoint_template, &fixture.identifier_value)?;
        let request_fingerprint = mutation_fingerprint(
            contract.base_request_fingerprint,
            &fixture.identifier_fingerprint,
        );
        let comparison_plan = plan_role_comparison(
            &RoleComparisonContract {
                target_id: contract.target_id,
                endpoint: &endpoint,
                method: contract.method,
                request_fingerprint: &request_fingerprint,
                repetitions_per_role: contract.repetitions_per_role,
                planned_at_millis: contract.planned_at_millis,
                non_destructive_post_approved: false,
                explicitly_approved: true,
            },
            accounts,
            RoleComparisonLimits {
                max_roles: HARD_OBJECT_COUNT,
                max_repetitions_per_role: limits.max_repetitions_per_role,
                max_requests: accounts.len() * contract.repetitions_per_role,
            },
        )?;
        objects.push(BolaObjectPlan {
            object_ref: fixture.object_ref.clone(),
            owner_role_ref: fixture.owner_role_ref.clone(),
            identifier_value: fixture.identifier_value.clone(),
            identifier_fingerprint: fixture.identifier_fingerprint.clone(),
            request_fingerprint,
            comparison_plan,
        });
    }
    Ok(BolaPlan {
        identity,
        objects,
        request_count,
    })
}

pub fn assess_bola_idor(
    plan: &BolaPlan,
    evidence: &[BolaObjectEvidence<'_>],
) -> Result<BolaAssessment, BolaRuntimeError> {
    if evidence.len() != plan.objects.len() {
        return Err(BolaRuntimeError::MissingEvidence);
    }
    let mut evidence_by_object = BTreeMap::new();
    for item in evidence {
        if evidence_by_object.insert(item.object_ref, item).is_some() {
            return Err(BolaRuntimeError::InvalidEvidence);
        }
    }

    let mut objects = Vec::with_capacity(plan.objects.len());
    for object in &plan.objects {
        let item = evidence_by_object
            .get(object.object_ref.as_str())
            .ok_or(BolaRuntimeError::MissingEvidence)?;
        if item.request_fingerprint != object.request_fingerprint {
            return Err(BolaRuntimeError::InvalidEvidence);
        }
        objects.push(assess_object(object, item.comparison)?);
    }

    let exposed = objects
        .iter()
        .filter(|object| {
            matches!(
                object.decision,
                BolaObjectDecision::EquivalentUnauthorizedAccess
                    | BolaObjectDecision::DifferentialUnauthorizedAccess
            )
        })
        .collect::<Vec<_>>();
    if exposed.is_empty() {
        let decision = if objects
            .iter()
            .all(|object| object.decision == BolaObjectDecision::Protected)
        {
            BolaDecision::NotObserved
        } else {
            BolaDecision::Abstain
        };
        return Ok(BolaAssessment {
            decision,
            objects,
            candidate: None,
        });
    }

    let all_determinate = objects
        .iter()
        .all(|object| object.decision != BolaObjectDecision::Indeterminate);
    let equivalent_count = exposed
        .iter()
        .filter(|object| object.decision == BolaObjectDecision::EquivalentUnauthorizedAccess)
        .count();
    let confidence = if equivalent_count == plan.objects.len() {
        Confidence::High
    } else if equivalent_count > 0 && all_determinate {
        Confidence::Medium
    } else {
        Confidence::Low
    };
    let exposed_object_refs = exposed
        .iter()
        .map(|object| object.object_ref.clone())
        .collect();
    let evidence_refs = exposed
        .iter()
        .flat_map(|object| object.evidence_refs.iter().map(String::as_str))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_string)
        .collect();
    let candidate = BolaCandidate {
        candidate_id: format!("bola-candidate-{}", &plan.identity.fingerprint()[..24]),
        confidence,
        exposed_object_refs,
        evidence_refs,
        requires_manual_confirmation: true,
    };
    Ok(BolaAssessment {
        decision: BolaDecision::Candidate,
        objects,
        candidate: Some(candidate),
    })
}

fn validate_limits(limits: BolaLimits) -> Result<(), BolaRuntimeError> {
    if limits.object_count != HARD_OBJECT_COUNT
        || limits.max_repetitions_per_role < 2
        || limits.max_repetitions_per_role > HARD_MAX_REPETITIONS_PER_ROLE
        || limits.max_identifier_bytes == 0
        || limits.max_identifier_bytes > HARD_MAX_IDENTIFIER_BYTES
        || limits.max_requests < 8
        || limits.max_requests > HARD_MAX_REQUESTS
    {
        return Err(BolaRuntimeError::InvalidLimits);
    }
    Ok(())
}

fn validate_contract(
    contract: &BolaContract<'_>,
    limits: BolaLimits,
) -> Result<(), BolaRuntimeError> {
    if !matches!(contract.method, HttpMethod::Get | HttpMethod::Head)
        || !matches!(
            contract.parameter_location,
            ParameterLocation::Path | ParameterLocation::Query
        )
        || !valid_parameter_name(contract.parameter_name)
        || !valid_sha256(contract.base_request_fingerprint)
        || contract.repetitions_per_role < 2
        || contract.repetitions_per_role > limits.max_repetitions_per_role
        || contract
            .endpoint_template
            .matches(OBJECT_PLACEHOLDER)
            .count()
            != 1
    {
        return Err(BolaRuntimeError::InvalidContract);
    }
    let validation_endpoint =
        replace_placeholder(contract.endpoint_template, "aegisobjectfixture")?;
    let url = Url::parse(&validation_endpoint).map_err(|_| BolaRuntimeError::InvalidContract)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(BolaRuntimeError::InvalidContract);
    }
    let placeholder_path_segments = url
        .path_segments()
        .into_iter()
        .flatten()
        .filter(|segment| *segment == "aegisobjectfixture")
        .count();
    let matching_query_names = url
        .query_pairs()
        .filter(|(name, _)| name == contract.parameter_name)
        .count();
    let placeholder_query_names = url
        .query_pairs()
        .filter(|(name, value)| {
            name == contract.parameter_name && value.as_ref() == "aegisobjectfixture"
        })
        .count();
    match contract.parameter_location {
        ParameterLocation::Path
            if placeholder_path_segments == 1
                && placeholder_query_names == 0
                && matching_query_names == 0 =>
        {
            Ok(())
        }
        ParameterLocation::Query
            if placeholder_path_segments == 0
                && placeholder_query_names == 1
                && matching_query_names == 1 =>
        {
            Ok(())
        }
        _ => Err(BolaRuntimeError::InvalidContract),
    }
}

fn validate_fixtures(
    accounts: &[RoleAccount],
    fixtures: &[OwnedObjectFixture],
    limits: BolaLimits,
) -> Result<(), BolaRuntimeError> {
    if accounts.len() != HARD_OBJECT_COUNT || fixtures.len() != limits.object_count {
        return Err(BolaRuntimeError::AccountFixtureMismatch);
    }
    if fixtures.iter().any(|fixture| {
        fixture.identifier_value.len() > limits.max_identifier_bytes
            || !valid_identifier(&fixture.identifier_value, limits.max_identifier_bytes)
    }) {
        return Err(BolaRuntimeError::InvalidFixture);
    }
    let object_refs = fixtures
        .iter()
        .map(|fixture| fixture.object_ref.as_str())
        .collect::<BTreeSet<_>>();
    let identifier_fingerprints = fixtures
        .iter()
        .map(|fixture| fixture.identifier_fingerprint.as_str())
        .collect::<BTreeSet<_>>();
    let fixture_roles = fixtures
        .iter()
        .map(|fixture| fixture.owner_role_ref.as_str())
        .collect::<BTreeSet<_>>();
    if object_refs.len() != fixtures.len()
        || identifier_fingerprints.len() != fixtures.len()
        || fixture_roles.len() != fixtures.len()
    {
        return Err(BolaRuntimeError::DuplicateFixture);
    }
    let account_roles = accounts
        .iter()
        .map(RoleAccount::role_ref)
        .collect::<BTreeSet<_>>();
    if account_roles != fixture_roles {
        return Err(BolaRuntimeError::AccountFixtureMismatch);
    }
    Ok(())
}

fn assess_object(
    object: &BolaObjectPlan,
    matrix: &RoleComparisonMatrix,
) -> Result<BolaObjectAssessment, BolaRuntimeError> {
    if matrix.roles().len() != HARD_OBJECT_COUNT
        || matrix.pairs().len() != 1
        || !matrix.all_roles_stable()
        || matrix.roles().iter().any(|role| {
            !role.is_stable()
                || role.status_code().is_none()
                || role.access_outcome().is_none()
                || role.evidence_refs().len() < 2
                || role.evidence_refs().len() > HARD_MAX_REPETITIONS_PER_ROLE
                || role
                    .evidence_refs()
                    .iter()
                    .any(|reference| !valid_evidence_ref(reference))
        })
    {
        return Ok(object_assessment(
            object,
            BolaObjectDecision::Indeterminate,
            Vec::new(),
        ));
    }
    let roles = matrix
        .roles()
        .iter()
        .map(|role| role.role_ref())
        .collect::<BTreeSet<_>>();
    let planned_roles = object
        .comparison_plan
        .executions()
        .iter()
        .map(|execution| execution.role_ref())
        .collect::<BTreeSet<_>>();
    if roles != planned_roles || !roles.contains(object.owner_role_ref.as_str()) {
        return Err(BolaRuntimeError::InvalidEvidence);
    }
    let owner = matrix
        .roles()
        .iter()
        .find(|role| role.role_ref() == object.owner_role_ref)
        .ok_or(BolaRuntimeError::InvalidEvidence)?;
    let non_owner = matrix
        .roles()
        .iter()
        .find(|role| role.role_ref() != object.owner_role_ref)
        .ok_or(BolaRuntimeError::InvalidEvidence)?;
    let pair = &matrix.pairs()[0];
    let pair_roles = [pair.left_role_ref(), pair.right_role_ref()]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if pair_roles != roles {
        return Err(BolaRuntimeError::InvalidEvidence);
    }
    let evidence_refs = owner
        .evidence_refs()
        .iter()
        .chain(non_owner.evidence_refs())
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    if owner.access_outcome() != Some(RoleAccessOutcome::Allowed) {
        return Ok(object_assessment(
            object,
            BolaObjectDecision::Indeterminate,
            evidence_refs,
        ));
    }
    let decision = match non_owner.access_outcome() {
        Some(RoleAccessOutcome::Denied | RoleAccessOutcome::RedirectedToLogin) => {
            BolaObjectDecision::Protected
        }
        Some(RoleAccessOutcome::Allowed) if pair.relation() == RolePairRelation::Same => {
            BolaObjectDecision::EquivalentUnauthorizedAccess
        }
        Some(RoleAccessOutcome::Allowed)
            if matches!(
                pair.relation(),
                RolePairRelation::DifferentStatus | RolePairRelation::DifferentBody
            ) =>
        {
            BolaObjectDecision::DifferentialUnauthorizedAccess
        }
        _ => BolaObjectDecision::Indeterminate,
    };
    Ok(object_assessment(object, decision, evidence_refs))
}

fn object_assessment(
    object: &BolaObjectPlan,
    decision: BolaObjectDecision,
    evidence_refs: Vec<String>,
) -> BolaObjectAssessment {
    BolaObjectAssessment {
        object_ref: object.object_ref.clone(),
        decision,
        evidence_refs,
    }
}

fn replace_placeholder(template: &str, identifier: &str) -> Result<String, BolaRuntimeError> {
    if template.matches(OBJECT_PLACEHOLDER).count() != 1
        || !valid_identifier(identifier, HARD_MAX_IDENTIFIER_BYTES)
    {
        return Err(BolaRuntimeError::InvalidContract);
    }
    let endpoint = template.replacen(OBJECT_PLACEHOLDER, identifier, 1);
    Url::parse(&endpoint).map_err(|_| BolaRuntimeError::InvalidContract)?;
    Ok(endpoint)
}

fn mutation_fingerprint(base: &str, identifier_fingerprint: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(base.as_bytes());
    hasher.update([0]);
    hasher.update(identifier_fingerprint.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn sha256_hex(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn valid_parameter_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

fn valid_prefixed_hash(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 32
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_evidence_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

pub(crate) fn benchmark_outcomes() -> Result<(bool, bool), BolaRuntimeError> {
    const ROLE_A: &str = "role_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ROLE_B: &str = "role_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const TENANT: &str = "tenant_0123456789abcdef0123456789abcdef";
    const BASE_REQUEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BODY_A: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const BODY_B: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let account = |seed: char, role: &str| -> Result<RoleAccount, BolaRuntimeError> {
        let repeated = seed.to_string().repeat(32);
        let (mut graph, anonymous) = crate::SessionFlowGraph::new(
            format!("flow_{repeated}"),
            &format!("principal_{repeated}"),
            1_000,
            crate::SessionGraphLimits::default(),
        )
        .map_err(|_| BolaRuntimeError::RoleComparisonRejected)?;
        let (_, authenticated) = graph
            .add_request(crate::SessionRequestTransition {
                from_state: &anonymous,
                kind: crate::SessionRequestKind::Login,
                method: HttpMethod::Post,
                endpoint: "https://benchmark.invalid/login",
                outcome: crate::TransitionOutcome::LoginSucceeded,
                issued_credential: Some(
                    crate::CredentialReference::new(
                        format!("credref_{repeated}"),
                        crate::SessionCredentialKind::Cookie,
                        1,
                        Some(10_000),
                    )
                    .map_err(|_| BolaRuntimeError::RoleComparisonRejected)?,
                ),
                occurred_at_millis: 2_000,
                dependencies: &[],
            })
            .map_err(|_| BolaRuntimeError::RoleComparisonRejected)?;
        RoleAccount::from_session_state(role, TENANT, &graph, &authenticated)
            .map_err(|_| BolaRuntimeError::RoleComparisonRejected)
    };
    let fixtures = [
        OwnedObjectFixture::new(
            "object_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ROLE_A,
            "fixture-a-1001",
            true,
            true,
        )?,
        OwnedObjectFixture::new(
            "object_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ROLE_B,
            "fixture-b-2002",
            true,
            true,
        )?,
    ];
    let plan = plan_bola_idor(
        &BolaContract {
            target_id: "benchmark-target",
            endpoint_template: "https://benchmark.invalid/api/objects/{aegis_object_id}",
            method: HttpMethod::Get,
            parameter_location: ParameterLocation::Path,
            parameter_name: "object_id",
            base_request_fingerprint: BASE_REQUEST,
            repetitions_per_role: 2,
            planned_at_millis: 3_000,
            explicitly_approved: true,
        },
        &[account('a', ROLE_A)?, account('b', ROLE_B)?],
        &fixtures,
        BolaLimits::default(),
    )?;
    let matrix = |object: &BolaObjectPlan,
                  non_owner_outcome: RoleAccessOutcome,
                  non_owner_status: u16,
                  non_owner_body: &'static str|
     -> Result<RoleComparisonMatrix, BolaRuntimeError> {
        let owner = object.owner_role_ref();
        let non_owner = if owner == ROLE_A { ROLE_B } else { ROLE_A };
        let request = object.request_fingerprint();
        let observations = [
            crate::RoleResponseObservation {
                role_ref: owner,
                request_fingerprint: request,
                repetition: 1,
                status_code: 200,
                access_outcome: RoleAccessOutcome::Allowed,
                redacted_body_fingerprint: BODY_A,
                evidence_ref: "benchmark-owner-1",
            },
            crate::RoleResponseObservation {
                role_ref: owner,
                request_fingerprint: request,
                repetition: 2,
                status_code: 200,
                access_outcome: RoleAccessOutcome::Allowed,
                redacted_body_fingerprint: BODY_A,
                evidence_ref: "benchmark-owner-2",
            },
            crate::RoleResponseObservation {
                role_ref: non_owner,
                request_fingerprint: request,
                repetition: 1,
                status_code: non_owner_status,
                access_outcome: non_owner_outcome,
                redacted_body_fingerprint: non_owner_body,
                evidence_ref: "benchmark-non-owner-1",
            },
            crate::RoleResponseObservation {
                role_ref: non_owner,
                request_fingerprint: request,
                repetition: 2,
                status_code: non_owner_status,
                access_outcome: non_owner_outcome,
                redacted_body_fingerprint: non_owner_body,
                evidence_ref: "benchmark-non-owner-2",
            },
        ];
        crate::build_role_comparison_matrix(object.comparison_plan(), &observations)
            .map_err(|_| BolaRuntimeError::RoleComparisonRejected)
    };
    let positive_matrices = plan
        .objects()
        .iter()
        .map(|object| matrix(object, RoleAccessOutcome::Allowed, 200, BODY_A))
        .collect::<Result<Vec<_>, _>>()?;
    let positive_evidence = plan
        .objects()
        .iter()
        .zip(&positive_matrices)
        .map(|(object, comparison)| BolaObjectEvidence {
            object_ref: object.object_ref(),
            request_fingerprint: object.request_fingerprint(),
            comparison,
        })
        .collect::<Vec<_>>();
    let positive = assess_bola_idor(&plan, &positive_evidence)?;
    let negative_matrices = plan
        .objects()
        .iter()
        .map(|object| matrix(object, RoleAccessOutcome::Denied, 403, BODY_B))
        .collect::<Result<Vec<_>, _>>()?;
    let negative_evidence = plan
        .objects()
        .iter()
        .zip(&negative_matrices)
        .map(|(object, comparison)| BolaObjectEvidence {
            object_ref: object.object_ref(),
            request_fingerprint: object.request_fingerprint(),
            comparison,
        })
        .collect::<Vec<_>>();
    let negative = assess_bola_idor(&plan, &negative_evidence)?;
    Ok((
        positive.decision == BolaDecision::Candidate && positive.candidate.is_some(),
        negative.decision == BolaDecision::Candidate || negative.candidate.is_some(),
    ))
}

#[cfg(test)]
mod tests {
    use aegis_native_engine::{Confidence, HttpMethod, ParameterLocation};

    use super::{
        assess_bola_idor, plan_bola_idor, BolaContract, BolaDecision, BolaLimits,
        BolaObjectDecision, BolaObjectEvidence, BolaRuntimeError, OwnedObjectFixture,
    };
    use crate::{
        build_role_comparison_matrix, CredentialReference, RoleAccessOutcome, RoleAccount,
        RoleResponseObservation, SessionCredentialKind, SessionFlowGraph, SessionGraphLimits,
        SessionRequestKind, SessionRequestTransition, TransitionOutcome,
    };

    const ROLE_A: &str = "role_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ROLE_B: &str = "role_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const TENANT: &str = "tenant_0123456789abcdef0123456789abcdef";
    const BASE_REQUEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BODY_A: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const BODY_B: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn account(seed: char, role: &str) -> RoleAccount {
        let repeated = seed.to_string().repeat(32);
        let (mut graph, anonymous) = SessionFlowGraph::new(
            format!("flow_{repeated}"),
            &format!("principal_{repeated}"),
            1_000,
            SessionGraphLimits::default(),
        )
        .unwrap();
        let (_, authenticated) = graph
            .add_request(SessionRequestTransition {
                from_state: &anonymous,
                kind: SessionRequestKind::Login,
                method: HttpMethod::Post,
                endpoint: "https://example.com/login",
                outcome: TransitionOutcome::LoginSucceeded,
                issued_credential: Some(
                    CredentialReference::new(
                        format!("credref_{repeated}"),
                        SessionCredentialKind::Cookie,
                        1,
                        Some(10_000),
                    )
                    .unwrap(),
                ),
                occurred_at_millis: 2_000,
                dependencies: &[],
            })
            .unwrap();
        RoleAccount::from_session_state(role, TENANT, &graph, &authenticated).unwrap()
    }

    fn fixtures() -> [OwnedObjectFixture; 2] {
        [
            OwnedObjectFixture::new(
                "object_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ROLE_A,
                "fixture-a-1001",
                true,
                true,
            )
            .unwrap(),
            OwnedObjectFixture::new(
                "object_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ROLE_B,
                "fixture-b-2002",
                true,
                true,
            )
            .unwrap(),
        ]
    }

    fn contract() -> BolaContract<'static> {
        BolaContract {
            target_id: "target-1",
            endpoint_template: "https://example.com/api/objects/{aegis_object_id}?token=secret",
            method: HttpMethod::Get,
            parameter_location: ParameterLocation::Path,
            parameter_name: "object_id",
            base_request_fingerprint: BASE_REQUEST,
            repetitions_per_role: 2,
            planned_at_millis: 3_000,
            explicitly_approved: true,
        }
    }

    fn matrix(
        object: &super::BolaObjectPlan,
        non_owner_outcome: RoleAccessOutcome,
        non_owner_status: u16,
        non_owner_body: &'static str,
    ) -> crate::RoleComparisonMatrix {
        matrix_with_repeated_body(
            object,
            non_owner_outcome,
            non_owner_status,
            non_owner_body,
            non_owner_body,
        )
    }

    fn matrix_with_repeated_body(
        object: &super::BolaObjectPlan,
        non_owner_outcome: RoleAccessOutcome,
        non_owner_status: u16,
        first_non_owner_body: &'static str,
        second_non_owner_body: &'static str,
    ) -> crate::RoleComparisonMatrix {
        let owner = object.owner_role_ref();
        let non_owner = if owner == ROLE_A { ROLE_B } else { ROLE_A };
        let request = object.request_fingerprint();
        let observations = [
            RoleResponseObservation {
                role_ref: owner,
                request_fingerprint: request,
                repetition: 1,
                status_code: 200,
                access_outcome: RoleAccessOutcome::Allowed,
                redacted_body_fingerprint: BODY_A,
                evidence_ref: "evidence-owner-1",
            },
            RoleResponseObservation {
                role_ref: owner,
                request_fingerprint: request,
                repetition: 2,
                status_code: 200,
                access_outcome: RoleAccessOutcome::Allowed,
                redacted_body_fingerprint: BODY_A,
                evidence_ref: "evidence-owner-2",
            },
            RoleResponseObservation {
                role_ref: non_owner,
                request_fingerprint: request,
                repetition: 1,
                status_code: non_owner_status,
                access_outcome: non_owner_outcome,
                redacted_body_fingerprint: first_non_owner_body,
                evidence_ref: "evidence-non-owner-1",
            },
            RoleResponseObservation {
                role_ref: non_owner,
                request_fingerprint: request,
                repetition: 2,
                status_code: non_owner_status,
                access_outcome: non_owner_outcome,
                redacted_body_fingerprint: second_non_owner_body,
                evidence_ref: "evidence-non-owner-2",
            },
        ];
        build_role_comparison_matrix(object.comparison_plan(), &observations).unwrap()
    }

    fn plan() -> super::BolaPlan {
        plan_bola_idor(
            &contract(),
            &[account('a', ROLE_A), account('b', ROLE_B)],
            &fixtures(),
            BolaLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn plan_is_two_fixture_eight_request_read_only_comparison() {
        let plan = plan();
        assert_eq!(plan.objects().len(), 2);
        assert_eq!(plan.request_count(), 8);
        assert_ne!(
            plan.objects()[0].request_fingerprint(),
            plan.objects()[1].request_fingerprint()
        );
        assert_eq!(plan.objects()[0].comparison_plan().executions().len(), 4);
        assert!(!plan.canonical_endpoint().contains("secret"));
        let debug = format!("{plan:?} {:?}", plan.objects()[0]);
        assert!(!debug.contains("fixture-a-1001"));
        assert!(!debug.contains(ROLE_A));
        assert!(!debug.contains(BASE_REQUEST));
    }

    #[test]
    fn equivalent_non_owner_access_for_both_fixtures_is_high_confidence_candidate() {
        let plan = plan();
        let matrices = plan
            .objects()
            .iter()
            .map(|object| matrix(object, RoleAccessOutcome::Allowed, 200, BODY_A))
            .collect::<Vec<_>>();
        let evidence = plan
            .objects()
            .iter()
            .zip(&matrices)
            .map(|(object, comparison)| BolaObjectEvidence {
                object_ref: object.object_ref(),
                request_fingerprint: object.request_fingerprint(),
                comparison,
            })
            .collect::<Vec<_>>();
        let assessment = assess_bola_idor(&plan, &evidence).unwrap();
        assert_eq!(assessment.decision, BolaDecision::Candidate);
        let candidate = assessment.candidate.unwrap();
        assert_eq!(candidate.confidence, Confidence::High);
        assert_eq!(candidate.exposed_object_refs.len(), 2);
        assert!(candidate.requires_manual_confirmation);
    }

    #[test]
    fn denied_non_owner_access_for_both_fixtures_is_not_observed() {
        let plan = plan();
        let matrices = plan
            .objects()
            .iter()
            .map(|object| matrix(object, RoleAccessOutcome::Denied, 403, BODY_B))
            .collect::<Vec<_>>();
        let evidence = plan
            .objects()
            .iter()
            .zip(&matrices)
            .map(|(object, comparison)| BolaObjectEvidence {
                object_ref: object.object_ref(),
                request_fingerprint: object.request_fingerprint(),
                comparison,
            })
            .collect::<Vec<_>>();
        let assessment = assess_bola_idor(&plan, &evidence).unwrap();
        assert_eq!(assessment.decision, BolaDecision::NotObserved);
        assert!(assessment.candidate.is_none());
        assert!(assessment
            .objects
            .iter()
            .all(|object| object.decision == BolaObjectDecision::Protected));
    }

    #[test]
    fn one_equivalent_exposure_and_one_protected_fixture_is_medium_candidate() {
        let plan = plan();
        let first = matrix(&plan.objects()[0], RoleAccessOutcome::Allowed, 200, BODY_A);
        let second = matrix(&plan.objects()[1], RoleAccessOutcome::Denied, 403, BODY_B);
        let evidence = [
            BolaObjectEvidence {
                object_ref: plan.objects()[0].object_ref(),
                request_fingerprint: plan.objects()[0].request_fingerprint(),
                comparison: &first,
            },
            BolaObjectEvidence {
                object_ref: plan.objects()[1].object_ref(),
                request_fingerprint: plan.objects()[1].request_fingerprint(),
                comparison: &second,
            },
        ];
        let assessment = assess_bola_idor(&plan, &evidence).unwrap();
        assert_eq!(assessment.decision, BolaDecision::Candidate);
        assert_eq!(assessment.candidate.unwrap().confidence, Confidence::Medium);
    }

    #[test]
    fn differential_allowed_access_remains_low_confidence_manual_candidate() {
        let plan = plan();
        let matrices = plan
            .objects()
            .iter()
            .map(|object| matrix(object, RoleAccessOutcome::Allowed, 200, BODY_B))
            .collect::<Vec<_>>();
        let evidence = plan
            .objects()
            .iter()
            .zip(&matrices)
            .map(|(object, comparison)| BolaObjectEvidence {
                object_ref: object.object_ref(),
                request_fingerprint: object.request_fingerprint(),
                comparison,
            })
            .collect::<Vec<_>>();
        let assessment = assess_bola_idor(&plan, &evidence).unwrap();
        assert_eq!(assessment.decision, BolaDecision::Candidate);
        let candidate = assessment.candidate.unwrap();
        assert_eq!(candidate.confidence, Confidence::Low);
        assert!(candidate.requires_manual_confirmation);
        assert!(assessment.objects.iter().all(|object| {
            object.decision == BolaObjectDecision::DifferentialUnauthorizedAccess
        }));
    }

    #[test]
    fn unstable_fixture_comparison_abstains() {
        let plan = plan();
        let first = matrix_with_repeated_body(
            &plan.objects()[0],
            RoleAccessOutcome::Denied,
            403,
            BODY_B,
            BODY_A,
        );
        let second = matrix(&plan.objects()[1], RoleAccessOutcome::Denied, 403, BODY_B);
        let evidence = [
            BolaObjectEvidence {
                object_ref: plan.objects()[0].object_ref(),
                request_fingerprint: plan.objects()[0].request_fingerprint(),
                comparison: &first,
            },
            BolaObjectEvidence {
                object_ref: plan.objects()[1].object_ref(),
                request_fingerprint: plan.objects()[1].request_fingerprint(),
                comparison: &second,
            },
        ];
        assert_eq!(
            assess_bola_idor(&plan, &evidence).unwrap().decision,
            BolaDecision::Abstain
        );
    }

    #[test]
    fn unsafe_or_duplicate_fixtures_fail_closed() {
        assert_eq!(
            OwnedObjectFixture::new(
                "object_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ROLE_A,
                "real-customer-object",
                true,
                false,
            ),
            Err(BolaRuntimeError::UnsafeFixture)
        );
        let duplicate = [fixtures()[0].clone(), fixtures()[0].clone()];
        assert_eq!(
            plan_bola_idor(
                &contract(),
                &[account('a', ROLE_A), account('b', ROLE_B)],
                &duplicate,
                BolaLimits::default(),
            ),
            Err(BolaRuntimeError::DuplicateFixture)
        );
    }

    #[test]
    fn mutation_contract_and_evidence_binding_fail_closed() {
        let accounts = [account('a', ROLE_A), account('b', ROLE_B)];
        let fixtures = fixtures();
        let mut unsafe_method = contract();
        unsafe_method.method = HttpMethod::Post;
        assert_eq!(
            plan_bola_idor(&unsafe_method, &accounts, &fixtures, BolaLimits::default(),),
            Err(BolaRuntimeError::InvalidContract)
        );
        let mut unapproved = contract();
        unapproved.explicitly_approved = false;
        assert_eq!(
            plan_bola_idor(&unapproved, &accounts, &fixtures, BolaLimits::default(),),
            Err(BolaRuntimeError::UnapprovedProbe)
        );

        let plan = plan();
        let first = matrix(&plan.objects()[0], RoleAccessOutcome::Denied, 403, BODY_B);
        let second = matrix(&plan.objects()[1], RoleAccessOutcome::Denied, 403, BODY_B);
        let evidence = [
            BolaObjectEvidence {
                object_ref: plan.objects()[0].object_ref(),
                request_fingerprint: BASE_REQUEST,
                comparison: &first,
            },
            BolaObjectEvidence {
                object_ref: plan.objects()[1].object_ref(),
                request_fingerprint: plan.objects()[1].request_fingerprint(),
                comparison: &second,
            },
        ];
        assert_eq!(
            assess_bola_idor(&plan, &evidence),
            Err(BolaRuntimeError::InvalidEvidence)
        );
    }

    #[test]
    fn query_identifier_requires_one_exact_parameter_binding() {
        let accounts = [account('a', ROLE_A), account('b', ROLE_B)];
        let fixtures = fixtures();
        let mut query = contract();
        query.endpoint_template =
            "https://example.com/api/objects?object_id={aegis_object_id}&view=summary";
        query.parameter_location = ParameterLocation::Query;
        assert!(plan_bola_idor(&query, &accounts, &fixtures, BolaLimits::default()).is_ok());

        query.endpoint_template =
            "https://example.com/api/objects?object_id=fixed&object_id={aegis_object_id}";
        assert_eq!(
            plan_bola_idor(&query, &accounts, &fixtures, BolaLimits::default()),
            Err(BolaRuntimeError::InvalidContract)
        );

        let mut partial_path = contract();
        partial_path.endpoint_template = "https://example.com/api/objects/prefix-{aegis_object_id}";
        assert_eq!(
            plan_bola_idor(&partial_path, &accounts, &fixtures, BolaLimits::default(),),
            Err(BolaRuntimeError::InvalidContract)
        );

        let mut ambiguous_path = contract();
        ambiguous_path.endpoint_template =
            "https://example.com/api/objects/{aegis_object_id}?object_id=fixed";
        assert_eq!(
            plan_bola_idor(&ambiguous_path, &accounts, &fixtures, BolaLimits::default(),),
            Err(BolaRuntimeError::InvalidContract)
        );
    }
}
