use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Display, Formatter};

use aegis_native_engine::{FindingIdentity, HttpMethod, ParameterLocation};

use crate::{SessionFlowGraph, SessionPhase, SessionStateId};

const HARD_MAX_ROLES: usize = 8;
const HARD_MAX_REPETITIONS: usize = 3;
const HARD_MAX_REQUESTS: usize = HARD_MAX_ROLES * HARD_MAX_REPETITIONS;
const ROLE_PREFIX: &str = "role_";
const TENANT_PREFIX: &str = "tenant_";

#[derive(Clone, Eq, PartialEq)]
pub struct RoleAccount {
    role_ref: String,
    tenant_ref: String,
    principal_fingerprint: String,
    session_state_id: SessionStateId,
    credential_expires_at_millis: Option<u64>,
}

impl RoleAccount {
    pub fn from_session_state(
        role_ref: impl Into<String>,
        tenant_ref: impl Into<String>,
        graph: &SessionFlowGraph,
        state_id: &SessionStateId,
    ) -> Result<Self, RoleComparisonError> {
        let role_ref = role_ref.into();
        let tenant_ref = tenant_ref.into();
        if !valid_prefixed_hash(&role_ref, ROLE_PREFIX)
            || !valid_prefixed_hash(&tenant_ref, TENANT_PREFIX)
        {
            return Err(RoleComparisonError::InvalidAccount);
        }
        let state = graph
            .state(state_id)
            .ok_or(RoleComparisonError::InvalidSessionState)?;
        if !matches!(
            state.phase,
            SessionPhase::Authenticated | SessionPhase::Refreshed
        ) || state.credential.is_none()
        {
            return Err(RoleComparisonError::InvalidSessionState);
        }
        Ok(Self {
            role_ref,
            tenant_ref,
            principal_fingerprint: graph.principal_fingerprint().to_string(),
            session_state_id: state_id.clone(),
            credential_expires_at_millis: state
                .credential
                .as_ref()
                .and_then(|credential| credential.expires_at_millis),
        })
    }

    pub fn role_ref(&self) -> &str {
        &self.role_ref
    }

    pub fn session_state_id(&self) -> &SessionStateId {
        &self.session_state_id
    }
}

impl Debug for RoleAccount {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RoleAccount")
            .field("role_ref_bytes", &self.role_ref.len())
            .field("tenant_ref_bytes", &self.tenant_ref.len())
            .field("session_state_id", &self.session_state_id)
            .finish()
    }
}

pub struct RoleComparisonContract<'a> {
    pub target_id: &'a str,
    pub endpoint: &'a str,
    pub method: HttpMethod,
    pub request_fingerprint: &'a str,
    pub repetitions_per_role: usize,
    pub planned_at_millis: u64,
    pub non_destructive_post_approved: bool,
    pub explicitly_approved: bool,
}

impl Debug for RoleComparisonContract<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RoleComparisonContract")
            .field("method", &self.method)
            .field("endpoint_bytes", &self.endpoint.len())
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("repetitions_per_role", &self.repetitions_per_role)
            .field("planned_at_millis", &self.planned_at_millis)
            .field(
                "non_destructive_post_approved",
                &self.non_destructive_post_approved,
            )
            .field("explicitly_approved", &self.explicitly_approved)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleComparisonLimits {
    pub max_roles: usize,
    pub max_repetitions_per_role: usize,
    pub max_requests: usize,
}

impl Default for RoleComparisonLimits {
    fn default() -> Self {
        Self {
            max_roles: HARD_MAX_ROLES,
            max_repetitions_per_role: HARD_MAX_REPETITIONS,
            max_requests: HARD_MAX_REQUESTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoleComparisonError {
    InvalidLimits,
    InvalidAccount,
    InvalidSessionState,
    InvalidContract,
    UnapprovedComparison,
    TenantMismatch,
    DuplicateRole,
    DuplicatePrincipal,
    DuplicateSessionState,
    CredentialExpired,
    RequestLimitExceeded,
    InvalidObservation,
    MissingObservation,
}

impl Display for RoleComparisonError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "role comparison limits are invalid",
            Self::InvalidAccount => "role comparison account is invalid",
            Self::InvalidSessionState => "role comparison session state is invalid",
            Self::InvalidContract => "role comparison contract is invalid",
            Self::UnapprovedComparison => "role comparison was not explicitly approved",
            Self::TenantMismatch => "role comparison accounts belong to different tenants",
            Self::DuplicateRole => "role comparison contains a duplicate role",
            Self::DuplicatePrincipal => "role comparison roles reuse a principal",
            Self::DuplicateSessionState => "role comparison roles reuse a session state",
            Self::CredentialExpired => "role comparison account credential has expired",
            Self::RequestLimitExceeded => "role comparison request limit was exceeded",
            Self::InvalidObservation => "role response observation is invalid",
            Self::MissingObservation => "role response observation set is incomplete",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RoleComparisonError {}

#[derive(Clone, Eq, PartialEq)]
pub struct RoleExecution {
    role_ref: String,
    session_state_id: SessionStateId,
    request_fingerprint: String,
    repetition: usize,
}

impl RoleExecution {
    pub fn role_ref(&self) -> &str {
        &self.role_ref
    }

    pub fn session_state_id(&self) -> &SessionStateId {
        &self.session_state_id
    }

    pub fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }

    pub fn repetition(&self) -> usize {
        self.repetition
    }
}

impl Debug for RoleExecution {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RoleExecution")
            .field("role_ref_bytes", &self.role_ref.len())
            .field("session_state_id", &self.session_state_id)
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("repetition", &self.repetition)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RoleComparisonPlan {
    canonical_endpoint: String,
    request_fingerprint: String,
    repetitions_per_role: usize,
    roles: Vec<String>,
    executions: Vec<RoleExecution>,
}

impl RoleComparisonPlan {
    pub fn canonical_endpoint(&self) -> &str {
        &self.canonical_endpoint
    }

    pub fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }

    pub fn executions(&self) -> &[RoleExecution] {
        &self.executions
    }
}

impl Debug for RoleComparisonPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RoleComparisonPlan")
            .field("endpoint_bytes", &self.canonical_endpoint.len())
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("role_count", &self.roles.len())
            .field("repetitions_per_role", &self.repetitions_per_role)
            .field("execution_count", &self.executions.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoleAccessOutcome {
    Allowed,
    Denied,
    RedirectedToLogin,
    Unknown,
}

pub struct RoleResponseObservation<'a> {
    pub role_ref: &'a str,
    pub request_fingerprint: &'a str,
    pub repetition: usize,
    pub status_code: u16,
    pub access_outcome: RoleAccessOutcome,
    pub redacted_body_fingerprint: &'a str,
    pub evidence_ref: &'a str,
}

impl Debug for RoleResponseObservation<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RoleResponseObservation")
            .field("role_ref_bytes", &self.role_ref.len())
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("repetition", &self.repetition)
            .field("status_code", &self.status_code)
            .field("access_outcome", &self.access_outcome)
            .field(
                "redacted_body_fingerprint_bytes",
                &self.redacted_body_fingerprint.len(),
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RoleResult {
    role_ref: String,
    stable: bool,
    status_code: Option<u16>,
    access_outcome: Option<RoleAccessOutcome>,
    evidence_refs: Vec<String>,
    body_fingerprint: Option<String>,
}

impl RoleResult {
    pub fn role_ref(&self) -> &str {
        &self.role_ref
    }

    pub fn is_stable(&self) -> bool {
        self.stable
    }

    pub fn status_code(&self) -> Option<u16> {
        self.status_code
    }

    pub fn access_outcome(&self) -> Option<RoleAccessOutcome> {
        self.access_outcome
    }

    pub fn evidence_refs(&self) -> &[String] {
        &self.evidence_refs
    }
}

impl Debug for RoleResult {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RoleResult")
            .field("role_ref_bytes", &self.role_ref.len())
            .field("stable", &self.stable)
            .field("status_code", &self.status_code)
            .field("access_outcome", &self.access_outcome)
            .field("evidence_ref_count", &self.evidence_refs.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RolePairRelation {
    Same,
    DifferentAccess,
    DifferentStatus,
    DifferentBody,
    Unstable,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RolePairComparison {
    left_role_ref: String,
    right_role_ref: String,
    relation: RolePairRelation,
}

impl RolePairComparison {
    pub fn left_role_ref(&self) -> &str {
        &self.left_role_ref
    }

    pub fn right_role_ref(&self) -> &str {
        &self.right_role_ref
    }

    pub fn relation(&self) -> RolePairRelation {
        self.relation
    }
}

impl Debug for RolePairComparison {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RolePairComparison")
            .field("left_role_ref_bytes", &self.left_role_ref.len())
            .field("right_role_ref_bytes", &self.right_role_ref.len())
            .field("relation", &self.relation)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RoleComparisonMatrix {
    roles: Vec<RoleResult>,
    pairs: Vec<RolePairComparison>,
    all_roles_stable: bool,
}

impl RoleComparisonMatrix {
    pub fn roles(&self) -> &[RoleResult] {
        &self.roles
    }

    pub fn pairs(&self) -> &[RolePairComparison] {
        &self.pairs
    }

    pub fn all_roles_stable(&self) -> bool {
        self.all_roles_stable
    }
}

impl Debug for RoleComparisonMatrix {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RoleComparisonMatrix")
            .field("role_count", &self.roles.len())
            .field("pair_count", &self.pairs.len())
            .field("all_roles_stable", &self.all_roles_stable)
            .finish()
    }
}

pub fn plan_role_comparison(
    contract: &RoleComparisonContract<'_>,
    accounts: &[RoleAccount],
    limits: RoleComparisonLimits,
) -> Result<RoleComparisonPlan, RoleComparisonError> {
    validate_limits(limits)?;
    if !contract.explicitly_approved {
        return Err(RoleComparisonError::UnapprovedComparison);
    }
    if accounts.len() < 2
        || accounts.len() > limits.max_roles
        || contract.repetitions_per_role < 2
        || contract.repetitions_per_role > limits.max_repetitions_per_role
        || !valid_sha256(contract.request_fingerprint)
        || !matches!(
            contract.method,
            HttpMethod::Get | HttpMethod::Head | HttpMethod::Options | HttpMethod::Post
        )
        || contract.method == HttpMethod::Post && !contract.non_destructive_post_approved
    {
        return Err(RoleComparisonError::InvalidContract);
    }
    let tenant = &accounts[0].tenant_ref;
    if accounts.iter().any(|account| &account.tenant_ref != tenant) {
        return Err(RoleComparisonError::TenantMismatch);
    }
    let roles = accounts
        .iter()
        .map(|account| account.role_ref.clone())
        .collect::<BTreeSet<_>>();
    if roles.len() != accounts.len() {
        return Err(RoleComparisonError::DuplicateRole);
    }
    let principals = accounts
        .iter()
        .map(|account| account.principal_fingerprint.clone())
        .collect::<BTreeSet<_>>();
    if principals.len() != accounts.len() {
        return Err(RoleComparisonError::DuplicatePrincipal);
    }
    let session_states = accounts
        .iter()
        .map(|account| account.session_state_id.clone())
        .collect::<BTreeSet<_>>();
    if session_states.len() != accounts.len() {
        return Err(RoleComparisonError::DuplicateSessionState);
    }
    if accounts.iter().any(|account| {
        account
            .credential_expires_at_millis
            .is_some_and(|expiry| expiry <= contract.planned_at_millis)
    }) {
        return Err(RoleComparisonError::CredentialExpired);
    }
    let request_count = accounts.len() * contract.repetitions_per_role;
    if request_count > limits.max_requests {
        return Err(RoleComparisonError::RequestLimitExceeded);
    }
    let identity = FindingIdentity::new(
        contract.target_id,
        contract.method,
        contract.endpoint,
        "CWE-285",
        ParameterLocation::None,
        None,
    )
    .map_err(|_| RoleComparisonError::InvalidContract)?;
    let mut executions = Vec::with_capacity(request_count);
    for account in accounts {
        for repetition in 1..=contract.repetitions_per_role {
            executions.push(RoleExecution {
                role_ref: account.role_ref.clone(),
                session_state_id: account.session_state_id.clone(),
                request_fingerprint: contract.request_fingerprint.to_string(),
                repetition,
            });
        }
    }
    Ok(RoleComparisonPlan {
        canonical_endpoint: identity.canonical_endpoint,
        request_fingerprint: contract.request_fingerprint.to_string(),
        repetitions_per_role: contract.repetitions_per_role,
        roles: roles.into_iter().collect(),
        executions,
    })
}

pub fn build_role_comparison_matrix(
    plan: &RoleComparisonPlan,
    observations: &[RoleResponseObservation<'_>],
) -> Result<RoleComparisonMatrix, RoleComparisonError> {
    if observations.len() != plan.executions.len() {
        return Err(RoleComparisonError::MissingObservation);
    }
    let mut by_role = BTreeMap::<String, Vec<&RoleResponseObservation<'_>>>::new();
    let mut execution_keys = BTreeSet::new();
    for execution in &plan.executions {
        execution_keys.insert((execution.role_ref.as_str(), execution.repetition));
    }
    let mut observed_keys = BTreeSet::new();
    for observation in observations {
        validate_observation(observation, plan)?;
        if !observed_keys.insert((observation.role_ref, observation.repetition))
            || !execution_keys.contains(&(observation.role_ref, observation.repetition))
        {
            return Err(RoleComparisonError::InvalidObservation);
        }
        by_role
            .entry(observation.role_ref.to_string())
            .or_default()
            .push(observation);
    }
    if observed_keys.len() != execution_keys.len() {
        return Err(RoleComparisonError::MissingObservation);
    }
    let mut roles = Vec::with_capacity(plan.roles.len());
    for role_ref in &plan.roles {
        let samples = by_role
            .get(role_ref)
            .ok_or(RoleComparisonError::MissingObservation)?;
        let first = samples[0];
        let stable = samples.iter().all(|sample| {
            sample.status_code == first.status_code
                && sample.access_outcome == first.access_outcome
                && sample.redacted_body_fingerprint == first.redacted_body_fingerprint
        });
        roles.push(RoleResult {
            role_ref: role_ref.clone(),
            stable,
            status_code: stable.then_some(first.status_code),
            access_outcome: stable.then_some(first.access_outcome),
            evidence_refs: samples
                .iter()
                .map(|sample| sample.evidence_ref)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(str::to_string)
                .collect(),
            body_fingerprint: stable.then(|| first.redacted_body_fingerprint.to_string()),
        });
    }
    let mut pairs = Vec::new();
    for left_index in 0..roles.len() {
        for right_index in left_index + 1..roles.len() {
            let left = &roles[left_index];
            let right = &roles[right_index];
            pairs.push(RolePairComparison {
                left_role_ref: left.role_ref.clone(),
                right_role_ref: right.role_ref.clone(),
                relation: pair_relation(left, right),
            });
        }
    }
    Ok(RoleComparisonMatrix {
        all_roles_stable: roles.iter().all(|role| role.stable),
        roles,
        pairs,
    })
}

fn validate_limits(limits: RoleComparisonLimits) -> Result<(), RoleComparisonError> {
    if limits.max_roles < 2
        || limits.max_roles > HARD_MAX_ROLES
        || limits.max_repetitions_per_role < 2
        || limits.max_repetitions_per_role > HARD_MAX_REPETITIONS
        || limits.max_requests < 4
        || limits.max_requests > HARD_MAX_REQUESTS
    {
        return Err(RoleComparisonError::InvalidLimits);
    }
    Ok(())
}

fn validate_observation(
    observation: &RoleResponseObservation<'_>,
    plan: &RoleComparisonPlan,
) -> Result<(), RoleComparisonError> {
    if !valid_prefixed_hash(observation.role_ref, ROLE_PREFIX)
        || observation.request_fingerprint != plan.request_fingerprint
        || observation.repetition == 0
        || observation.repetition > plan.repetitions_per_role
        || !(100..=599).contains(&observation.status_code)
        || !valid_sha256(observation.redacted_body_fingerprint)
        || observation.evidence_ref.is_empty()
        || observation.evidence_ref.len() > 64
        || !observation
            .evidence_ref
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        || !outcome_matches_status(observation.access_outcome, observation.status_code)
    {
        return Err(RoleComparisonError::InvalidObservation);
    }
    Ok(())
}

fn outcome_matches_status(outcome: RoleAccessOutcome, status: u16) -> bool {
    match outcome {
        RoleAccessOutcome::Allowed => (200..300).contains(&status),
        RoleAccessOutcome::Denied => matches!(status, 401 | 403),
        RoleAccessOutcome::RedirectedToLogin => (300..400).contains(&status),
        RoleAccessOutcome::Unknown => true,
    }
}

fn pair_relation(left: &RoleResult, right: &RoleResult) -> RolePairRelation {
    if !left.stable || !right.stable {
        RolePairRelation::Unstable
    } else if left.access_outcome != right.access_outcome {
        RolePairRelation::DifferentAccess
    } else if left.status_code != right.status_code {
        RolePairRelation::DifferentStatus
    } else if left.body_fingerprint != right.body_fingerprint {
        RolePairRelation::DifferentBody
    } else {
        RolePairRelation::Same
    }
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

#[cfg(test)]
mod tests {
    use aegis_native_engine::HttpMethod;

    use super::{
        build_role_comparison_matrix, plan_role_comparison, RoleAccessOutcome, RoleAccount,
        RoleComparisonContract, RoleComparisonError, RoleComparisonLimits, RolePairRelation,
        RoleResponseObservation,
    };
    use crate::{
        CredentialReference, SessionCredentialKind, SessionFlowGraph, SessionGraphLimits,
        SessionRequestKind, SessionRequestTransition, TransitionOutcome,
    };

    const TENANT: &str = "tenant_0123456789abcdef0123456789abcdef";
    const REQUEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BODY_ALLOWED: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const BODY_DENIED: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn account(seed: char, role: &str) -> RoleAccount {
        account_with_seeds(seed, seed, role)
    }

    fn account_with_seeds(flow_seed: char, principal_seed: char, role: &str) -> RoleAccount {
        let flow_repeated = flow_seed.to_string().repeat(32);
        let principal_repeated = principal_seed.to_string().repeat(32);
        let flow = format!("flow_{flow_repeated}");
        let principal = format!("principal_{principal_repeated}");
        let credential = format!("credref_{principal_repeated}");
        let (mut graph, anonymous) =
            SessionFlowGraph::new(flow, &principal, 1_000, SessionGraphLimits::default()).unwrap();
        let (_step, authenticated) = graph
            .add_request(SessionRequestTransition {
                from_state: &anonymous,
                kind: SessionRequestKind::Login,
                method: HttpMethod::Post,
                endpoint: "https://example.com/login",
                outcome: TransitionOutcome::LoginSucceeded,
                issued_credential: Some(
                    CredentialReference::new(
                        credential,
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

    fn contract() -> RoleComparisonContract<'static> {
        RoleComparisonContract {
            target_id: "target-1",
            endpoint: "https://example.com/objects/1?token=secret",
            method: HttpMethod::Get,
            request_fingerprint: REQUEST,
            repetitions_per_role: 2,
            planned_at_millis: 3_000,
            non_destructive_post_approved: false,
            explicitly_approved: true,
        }
    }

    fn observations<'a>(
        role_a: &'a str,
        role_b: &'a str,
        second_body: &'a str,
        second_outcome: RoleAccessOutcome,
        second_status: u16,
    ) -> Vec<RoleResponseObservation<'a>> {
        vec![
            RoleResponseObservation {
                role_ref: role_a,
                request_fingerprint: REQUEST,
                repetition: 1,
                status_code: 200,
                access_outcome: RoleAccessOutcome::Allowed,
                redacted_body_fingerprint: BODY_ALLOWED,
                evidence_ref: "evidence-a1",
            },
            RoleResponseObservation {
                role_ref: role_a,
                request_fingerprint: REQUEST,
                repetition: 2,
                status_code: 200,
                access_outcome: RoleAccessOutcome::Allowed,
                redacted_body_fingerprint: BODY_ALLOWED,
                evidence_ref: "evidence-a2",
            },
            RoleResponseObservation {
                role_ref: role_b,
                request_fingerprint: REQUEST,
                repetition: 1,
                status_code: second_status,
                access_outcome: second_outcome,
                redacted_body_fingerprint: second_body,
                evidence_ref: "evidence-b1",
            },
            RoleResponseObservation {
                role_ref: role_b,
                request_fingerprint: REQUEST,
                repetition: 2,
                status_code: second_status,
                access_outcome: second_outcome,
                redacted_body_fingerprint: second_body,
                evidence_ref: "evidence-b2",
            },
        ]
    }

    #[test]
    fn plan_uses_distinct_sessions_and_identical_request_fingerprint() {
        let role_a = "role_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let role_b = "role_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let accounts = [account('a', role_a), account('b', role_b)];
        let plan =
            plan_role_comparison(&contract(), &accounts, RoleComparisonLimits::default()).unwrap();
        assert_eq!(plan.executions().len(), 4);
        assert!(plan
            .executions()
            .iter()
            .all(|execution| execution.request_fingerprint() == REQUEST));
        assert_ne!(
            plan.executions()[0].session_state_id(),
            plan.executions()[2].session_state_id()
        );
        assert!(!plan.canonical_endpoint().contains("secret"));
    }

    #[test]
    fn stable_allowed_and_denied_results_build_access_matrix() {
        let role_a = "role_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let role_b = "role_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let accounts = [account('a', role_a), account('b', role_b)];
        let plan =
            plan_role_comparison(&contract(), &accounts, RoleComparisonLimits::default()).unwrap();
        let matrix = build_role_comparison_matrix(
            &plan,
            &observations(role_a, role_b, BODY_DENIED, RoleAccessOutcome::Denied, 403),
        )
        .unwrap();
        assert!(matrix.all_roles_stable());
        assert_eq!(
            matrix.pairs()[0].relation(),
            RolePairRelation::DifferentAccess
        );
    }

    #[test]
    fn repeated_response_instability_is_preserved_not_hidden() {
        let role_a = "role_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let role_b = "role_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let accounts = [account('a', role_a), account('b', role_b)];
        let plan =
            plan_role_comparison(&contract(), &accounts, RoleComparisonLimits::default()).unwrap();
        let mut evidence =
            observations(role_a, role_b, BODY_DENIED, RoleAccessOutcome::Denied, 403);
        evidence[3].redacted_body_fingerprint = BODY_ALLOWED;
        let matrix = build_role_comparison_matrix(&plan, &evidence).unwrap();
        assert!(!matrix.all_roles_stable());
        assert_eq!(matrix.pairs()[0].relation(), RolePairRelation::Unstable);
    }

    #[test]
    fn duplicate_principal_or_role_is_rejected() {
        let role_a = "role_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let role_b = "role_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let first = account('a', role_a);
        let same_principal = account('a', role_b);
        assert_eq!(
            plan_role_comparison(
                &contract(),
                &[first, same_principal],
                RoleComparisonLimits::default(),
            ),
            Err(RoleComparisonError::DuplicatePrincipal)
        );

        let duplicate_role_accounts = [account('a', role_a), account('b', role_a)];
        assert_eq!(
            plan_role_comparison(
                &contract(),
                &duplicate_role_accounts,
                RoleComparisonLimits::default(),
            ),
            Err(RoleComparisonError::DuplicateRole)
        );

        let duplicate_state_accounts = [
            account_with_seeds('d', 'a', role_a),
            account_with_seeds('d', 'b', role_b),
        ];
        assert_eq!(
            plan_role_comparison(
                &contract(),
                &duplicate_state_accounts,
                RoleComparisonLimits::default(),
            ),
            Err(RoleComparisonError::DuplicateSessionState)
        );
    }

    #[test]
    fn logged_out_state_cannot_become_role_account() {
        let repeated = "d".repeat(32);
        let (graph, anonymous) = SessionFlowGraph::new(
            format!("flow_{repeated}"),
            &format!("principal_{repeated}"),
            1_000,
            SessionGraphLimits::default(),
        )
        .unwrap();
        assert!(RoleAccount::from_session_state(
            "role_dddddddddddddddddddddddddddddddd",
            TENANT,
            &graph,
            &anonymous,
        )
        .is_err());
    }

    #[test]
    fn post_approval_and_observation_contract_fail_closed() {
        let role_a = "role_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let role_b = "role_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let accounts = [account('a', role_a), account('b', role_b)];
        let mut expired = contract();
        expired.planned_at_millis = 10_000;
        assert_eq!(
            plan_role_comparison(&expired, &accounts, RoleComparisonLimits::default()),
            Err(RoleComparisonError::CredentialExpired)
        );
        let mut unsafe_post = contract();
        unsafe_post.method = HttpMethod::Post;
        assert!(
            plan_role_comparison(&unsafe_post, &accounts, RoleComparisonLimits::default(),)
                .is_err()
        );
        let plan =
            plan_role_comparison(&contract(), &accounts, RoleComparisonLimits::default()).unwrap();
        let mut evidence =
            observations(role_a, role_b, BODY_DENIED, RoleAccessOutcome::Denied, 403);
        evidence[0].request_fingerprint = BODY_ALLOWED;
        assert_eq!(
            build_role_comparison_matrix(&plan, &evidence),
            Err(RoleComparisonError::InvalidObservation)
        );
        let debug = format!("{plan:?} {:?}", accounts[0]);
        assert!(!debug.contains("example.com"));
        assert!(!debug.contains(REQUEST));
        let matrix = build_role_comparison_matrix(
            &plan,
            &observations(role_a, role_b, BODY_DENIED, RoleAccessOutcome::Denied, 403),
        )
        .unwrap();
        let debug = format!("{matrix:?} {:?}", matrix.pairs()[0]);
        assert!(!debug.contains(role_a));
        assert!(!debug.contains(role_b));
    }
}
