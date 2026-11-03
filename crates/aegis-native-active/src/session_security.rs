use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Display, Formatter};

use aegis_native_engine::{Confidence, FindingIdentity, HttpMethod, ParameterLocation};

use crate::{
    CredentialReference, SessionCredentialKind, SessionFlowGraph, SessionPhase, SessionRequestKind,
    SessionState, SessionStateId,
};

const HARD_MAX_REPETITIONS_PER_ROLE: usize = 3;
const HARD_MAX_REQUESTS: usize = 9;
const ROLE_COUNT: usize = 3;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SessionSecurityMode {
    LogoutInvalidation,
    ExpiryEnforcement,
    SessionFixation,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SessionSecurityRole {
    AuthenticatedBaseline,
    ReplayAfterLogout,
    ReplayAfterExpiry,
    PreAuthenticationControl,
    PostLoginAuthenticated,
    AnonymousControl,
}

pub struct SessionSecurityContract<'a> {
    pub target_id: &'a str,
    pub sentinel_endpoint: &'a str,
    pub method: HttpMethod,
    pub request_fingerprint: &'a str,
    pub repetitions_per_role: usize,
    pub planned_at_millis: u64,
    pub synthetic_read_only_sentinel: bool,
    pub explicitly_approved: bool,
}

impl Debug for SessionSecurityContract<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionSecurityContract")
            .field("method", &self.method)
            .field("sentinel_endpoint_bytes", &self.sentinel_endpoint.len())
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("repetitions_per_role", &self.repetitions_per_role)
            .field("planned_at_millis", &self.planned_at_millis)
            .field(
                "synthetic_read_only_sentinel",
                &self.synthetic_read_only_sentinel,
            )
            .field("explicitly_approved", &self.explicitly_approved)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SessionIdentifierComparison {
    pre_authentication_fingerprint: String,
    post_login_fingerprint: String,
}

impl SessionIdentifierComparison {
    pub fn new(
        pre_authentication_fingerprint: impl Into<String>,
        post_login_fingerprint: impl Into<String>,
    ) -> Result<Self, SessionSecurityRuntimeError> {
        let pre_authentication_fingerprint = pre_authentication_fingerprint.into();
        let post_login_fingerprint = post_login_fingerprint.into();
        if !valid_sha256(&pre_authentication_fingerprint) || !valid_sha256(&post_login_fingerprint)
        {
            return Err(SessionSecurityRuntimeError::InvalidCredential);
        }
        Ok(Self {
            pre_authentication_fingerprint,
            post_login_fingerprint,
        })
    }

    pub fn credential_rotated(&self) -> bool {
        self.pre_authentication_fingerprint != self.post_login_fingerprint
    }
}

impl Debug for SessionIdentifierComparison {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionIdentifierComparison")
            .field(
                "pre_authentication_fingerprint_bytes",
                &self.pre_authentication_fingerprint.len(),
            )
            .field(
                "post_login_fingerprint_bytes",
                &self.post_login_fingerprint.len(),
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionSecurityLimits {
    pub max_repetitions_per_role: usize,
    pub max_requests: usize,
}

impl Default for SessionSecurityLimits {
    fn default() -> Self {
        Self {
            max_repetitions_per_role: HARD_MAX_REPETITIONS_PER_ROLE,
            max_requests: HARD_MAX_REQUESTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionSecurityRuntimeError {
    InvalidLimits,
    InvalidContract,
    UnapprovedProbe,
    UnsafeSentinel,
    InvalidSessionFlow,
    InvalidCredential,
    AmbiguousCredentialExpiry,
    RequestLimitExceeded,
    InvalidObservation,
    MissingObservation,
}

impl Display for SessionSecurityRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "session security limits are invalid",
            Self::InvalidContract => "session security contract is invalid",
            Self::UnapprovedProbe => "session security probe was not explicitly approved",
            Self::UnsafeSentinel => "session security sentinel is not verified read-only test data",
            Self::InvalidSessionFlow => "session security flow is invalid",
            Self::InvalidCredential => "session security credential reference is invalid",
            Self::AmbiguousCredentialExpiry => {
                "session security result is ambiguous because of credential expiry"
            }
            Self::RequestLimitExceeded => "session security request limit was exceeded",
            Self::InvalidObservation => "session security observation is invalid",
            Self::MissingObservation => "session security observation set is incomplete",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SessionSecurityRuntimeError {}

#[derive(Clone, Eq, PartialEq)]
pub struct SessionSecurityExecution {
    role: SessionSecurityRole,
    credential_ref: Option<String>,
    request_fingerprint: String,
    repetition: usize,
    window_start_millis: u64,
    window_end_millis: u64,
}

impl SessionSecurityExecution {
    pub fn role(&self) -> SessionSecurityRole {
        self.role
    }

    pub fn credential_ref(&self) -> Option<&str> {
        self.credential_ref.as_deref()
    }

    pub fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }

    pub fn repetition(&self) -> usize {
        self.repetition
    }

    pub fn window_start_millis(&self) -> u64 {
        self.window_start_millis
    }

    pub fn window_end_millis(&self) -> u64 {
        self.window_end_millis
    }
}

impl Debug for SessionSecurityExecution {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionSecurityExecution")
            .field("role", &self.role)
            .field("has_credential_ref", &self.credential_ref.is_some())
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("repetition", &self.repetition)
            .field("window_start_millis", &self.window_start_millis)
            .field("window_end_millis", &self.window_end_millis)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SessionSecurityPlan {
    identity: FindingIdentity,
    mode: SessionSecurityMode,
    request_fingerprint: String,
    credential_rotated: Option<bool>,
    executions: Vec<SessionSecurityExecution>,
}

impl SessionSecurityPlan {
    pub fn mode(&self) -> SessionSecurityMode {
        self.mode
    }

    pub fn canonical_endpoint(&self) -> &str {
        &self.identity.canonical_endpoint
    }

    pub fn executions(&self) -> &[SessionSecurityExecution] {
        &self.executions
    }

    pub fn credential_rotated(&self) -> Option<bool> {
        self.credential_rotated
    }
}

impl Debug for SessionSecurityPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionSecurityPlan")
            .field("mode", &self.mode)
            .field(
                "canonical_endpoint_bytes",
                &self.identity.canonical_endpoint.len(),
            )
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("credential_rotated", &self.credential_rotated)
            .field("execution_count", &self.executions.len())
            .finish()
    }
}

pub struct SessionSecurityObservation<'a> {
    pub role: SessionSecurityRole,
    pub request_fingerprint: &'a str,
    pub repetition: usize,
    pub observed_at_millis: u64,
    pub status_code: u16,
    pub access_outcome: crate::RoleAccessOutcome,
    pub redacted_body_fingerprint: &'a str,
    pub evidence_ref: &'a str,
}

impl Debug for SessionSecurityObservation<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionSecurityObservation")
            .field("role", &self.role)
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("repetition", &self.repetition)
            .field("observed_at_millis", &self.observed_at_millis)
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
pub struct SessionSecurityResult {
    role: SessionSecurityRole,
    stable: bool,
    status_code: Option<u16>,
    access_outcome: Option<crate::RoleAccessOutcome>,
    body_fingerprint: Option<String>,
    evidence_refs: Vec<String>,
}

impl SessionSecurityResult {
    pub fn role(&self) -> SessionSecurityRole {
        self.role
    }

    pub fn is_stable(&self) -> bool {
        self.stable
    }

    pub fn status_code(&self) -> Option<u16> {
        self.status_code
    }

    pub fn access_outcome(&self) -> Option<crate::RoleAccessOutcome> {
        self.access_outcome
    }

    pub fn evidence_refs(&self) -> &[String] {
        &self.evidence_refs
    }
}

impl Debug for SessionSecurityResult {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionSecurityResult")
            .field("role", &self.role)
            .field("stable", &self.stable)
            .field("status_code", &self.status_code)
            .field("access_outcome", &self.access_outcome)
            .field("has_body_fingerprint", &self.body_fingerprint.is_some())
            .field("evidence_ref_count", &self.evidence_refs.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionSecuritySignal {
    SessionSurvivesLogout,
    SessionSurvivesExpiry,
    CredentialNotRotatedAfterLogin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionSecurityDecision {
    Candidate,
    NotObserved,
    Abstain,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SessionSecurityCandidate {
    pub candidate_id: String,
    pub signal: SessionSecuritySignal,
    pub confidence: Confidence,
    pub evidence_refs: Vec<String>,
    pub requires_manual_confirmation: bool,
}

impl Debug for SessionSecurityCandidate {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionSecurityCandidate")
            .field("candidate_id_bytes", &self.candidate_id.len())
            .field("signal", &self.signal)
            .field("confidence", &self.confidence)
            .field("evidence_ref_count", &self.evidence_refs.len())
            .field(
                "requires_manual_confirmation",
                &self.requires_manual_confirmation,
            )
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSecurityAssessment {
    pub decision: SessionSecurityDecision,
    pub results: Vec<SessionSecurityResult>,
    pub candidate: Option<SessionSecurityCandidate>,
}

pub fn plan_logout_invalidation(
    contract: &SessionSecurityContract<'_>,
    graph: &SessionFlowGraph,
    pre_logout_state_id: &SessionStateId,
    logged_out_state_id: &SessionStateId,
    limits: SessionSecurityLimits,
) -> Result<SessionSecurityPlan, SessionSecurityRuntimeError> {
    validate_plan_contract(contract, limits)?;
    graph
        .validate()
        .map_err(|_| SessionSecurityRuntimeError::InvalidSessionFlow)?;
    let pre_logout = authenticated_state(graph, pre_logout_state_id)?;
    let logged_out = graph
        .state(logged_out_state_id)
        .ok_or(SessionSecurityRuntimeError::InvalidSessionFlow)?;
    validate_logout_transition(graph, pre_logout, logged_out)?;
    if contract.planned_at_millis < logged_out.created_at_millis {
        return Err(SessionSecurityRuntimeError::InvalidSessionFlow);
    }
    let credential = pre_logout
        .credential
        .as_ref()
        .ok_or(SessionSecurityRuntimeError::InvalidCredential)?;
    if credential
        .expires_at_millis
        .is_some_and(|expiry| expiry <= contract.planned_at_millis)
    {
        return Err(SessionSecurityRuntimeError::AmbiguousCredentialExpiry);
    }
    build_plan(
        contract,
        SessionSecurityMode::LogoutInvalidation,
        "CWE-613",
        credential_location(credential.kind),
        [
            ExecutionSpec::new(
                SessionSecurityRole::AuthenticatedBaseline,
                Some(credential.reference_id()),
                pre_logout.created_at_millis,
                logged_out.created_at_millis.saturating_sub(1),
            ),
            ExecutionSpec::new(
                SessionSecurityRole::ReplayAfterLogout,
                Some(credential.reference_id()),
                logged_out.created_at_millis,
                contract.planned_at_millis,
            ),
            ExecutionSpec::new(
                SessionSecurityRole::AnonymousControl,
                None,
                logged_out.created_at_millis,
                contract.planned_at_millis,
            ),
        ],
        None,
        limits,
    )
}

pub fn plan_expiry_enforcement(
    contract: &SessionSecurityContract<'_>,
    graph: &SessionFlowGraph,
    pre_expiry_state_id: &SessionStateId,
    expired_state_id: &SessionStateId,
    limits: SessionSecurityLimits,
) -> Result<SessionSecurityPlan, SessionSecurityRuntimeError> {
    validate_plan_contract(contract, limits)?;
    graph
        .validate()
        .map_err(|_| SessionSecurityRuntimeError::InvalidSessionFlow)?;
    let pre_expiry = authenticated_state(graph, pre_expiry_state_id)?;
    let expired = graph
        .state(expired_state_id)
        .ok_or(SessionSecurityRuntimeError::InvalidSessionFlow)?;
    let credential = pre_expiry
        .credential
        .as_ref()
        .ok_or(SessionSecurityRuntimeError::InvalidCredential)?;
    let expiry = credential
        .expires_at_millis
        .ok_or(SessionSecurityRuntimeError::InvalidCredential)?;
    if expired.phase != SessionPhase::Expired
        || expired.created_at_millis < expiry
        || expired.created_by_step != pre_expiry.created_by_step
        || contract.planned_at_millis < expired.created_at_millis
    {
        return Err(SessionSecurityRuntimeError::InvalidSessionFlow);
    }
    build_plan(
        contract,
        SessionSecurityMode::ExpiryEnforcement,
        "CWE-613",
        credential_location(credential.kind),
        [
            ExecutionSpec::new(
                SessionSecurityRole::AuthenticatedBaseline,
                Some(credential.reference_id()),
                pre_expiry.created_at_millis,
                expired.created_at_millis.saturating_sub(1),
            ),
            ExecutionSpec::new(
                SessionSecurityRole::ReplayAfterExpiry,
                Some(credential.reference_id()),
                expired.created_at_millis,
                contract.planned_at_millis,
            ),
            ExecutionSpec::new(
                SessionSecurityRole::AnonymousControl,
                None,
                expired.created_at_millis,
                contract.planned_at_millis,
            ),
        ],
        None,
        limits,
    )
}

pub fn plan_session_fixation(
    contract: &SessionSecurityContract<'_>,
    graph: &SessionFlowGraph,
    pre_authentication_credential: &CredentialReference,
    identifier_comparison: &SessionIdentifierComparison,
    authenticated_state_id: &SessionStateId,
    limits: SessionSecurityLimits,
) -> Result<SessionSecurityPlan, SessionSecurityRuntimeError> {
    validate_plan_contract(contract, limits)?;
    graph
        .validate()
        .map_err(|_| SessionSecurityRuntimeError::InvalidSessionFlow)?;
    if pre_authentication_credential.kind != SessionCredentialKind::Cookie {
        return Err(SessionSecurityRuntimeError::InvalidCredential);
    }
    let authenticated = authenticated_state(graph, authenticated_state_id)?;
    validate_direct_login_state(graph, authenticated)?;
    let login_step = authenticated
        .created_by_step
        .as_ref()
        .and_then(|step_id| graph.step(step_id))
        .ok_or(SessionSecurityRuntimeError::InvalidSessionFlow)?;
    let anonymous = graph
        .state(&login_step.from_state)
        .ok_or(SessionSecurityRuntimeError::InvalidSessionFlow)?;
    let post_login = authenticated
        .credential
        .as_ref()
        .ok_or(SessionSecurityRuntimeError::InvalidCredential)?;
    if post_login.kind != SessionCredentialKind::Cookie
        || post_login
            .expires_at_millis
            .is_some_and(|expiry| expiry <= contract.planned_at_millis)
    {
        return Err(SessionSecurityRuntimeError::InvalidCredential);
    }
    if contract.planned_at_millis < authenticated.created_at_millis
        || pre_authentication_credential
            .expires_at_millis
            .is_some_and(|expiry| expiry <= authenticated.created_at_millis)
    {
        return Err(SessionSecurityRuntimeError::AmbiguousCredentialExpiry);
    }
    let rotated = identifier_comparison.credential_rotated();
    build_plan(
        contract,
        SessionSecurityMode::SessionFixation,
        "CWE-384",
        ParameterLocation::Cookie,
        [
            ExecutionSpec::new(
                SessionSecurityRole::PreAuthenticationControl,
                Some(pre_authentication_credential.reference_id()),
                anonymous.created_at_millis,
                authenticated.created_at_millis.saturating_sub(1),
            ),
            ExecutionSpec::new(
                SessionSecurityRole::PostLoginAuthenticated,
                Some(post_login.reference_id()),
                authenticated.created_at_millis,
                contract.planned_at_millis,
            ),
            ExecutionSpec::new(
                SessionSecurityRole::AnonymousControl,
                None,
                authenticated.created_at_millis,
                contract.planned_at_millis,
            ),
        ],
        Some(rotated),
        limits,
    )
}

pub fn assess_session_security(
    plan: &SessionSecurityPlan,
    observations: &[SessionSecurityObservation<'_>],
) -> Result<SessionSecurityAssessment, SessionSecurityRuntimeError> {
    if observations.len() != plan.executions.len() {
        return Err(SessionSecurityRuntimeError::MissingObservation);
    }
    let expected = plan
        .executions
        .iter()
        .map(|execution| (execution.role, execution.repetition))
        .collect::<BTreeSet<_>>();
    let mut observed = BTreeSet::new();
    let mut by_role = BTreeMap::<SessionSecurityRole, Vec<&SessionSecurityObservation<'_>>>::new();
    for observation in observations {
        validate_observation(observation, plan)?;
        if !observed.insert((observation.role, observation.repetition))
            || !expected.contains(&(observation.role, observation.repetition))
        {
            return Err(SessionSecurityRuntimeError::InvalidObservation);
        }
        by_role
            .entry(observation.role)
            .or_default()
            .push(observation);
    }
    if observed != expected {
        return Err(SessionSecurityRuntimeError::MissingObservation);
    }
    let mut results = Vec::with_capacity(ROLE_COUNT);
    for role in expected
        .iter()
        .map(|(role, _)| *role)
        .collect::<BTreeSet<_>>()
    {
        let samples = by_role
            .get(&role)
            .ok_or(SessionSecurityRuntimeError::MissingObservation)?;
        let first = samples[0];
        let stable = samples.iter().all(|sample| {
            sample.status_code == first.status_code
                && sample.access_outcome == first.access_outcome
                && sample.redacted_body_fingerprint == first.redacted_body_fingerprint
        });
        results.push(SessionSecurityResult {
            role,
            stable,
            status_code: stable.then_some(first.status_code),
            access_outcome: stable.then_some(first.access_outcome),
            body_fingerprint: stable.then(|| first.redacted_body_fingerprint.to_string()),
            evidence_refs: samples
                .iter()
                .map(|sample| sample.evidence_ref)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(str::to_string)
                .collect(),
        });
    }
    decide(plan, results)
}

fn build_plan(
    contract: &SessionSecurityContract<'_>,
    mode: SessionSecurityMode,
    weakness: &str,
    parameter_location: ParameterLocation,
    roles: [ExecutionSpec<'_>; ROLE_COUNT],
    credential_rotated: Option<bool>,
    limits: SessionSecurityLimits,
) -> Result<SessionSecurityPlan, SessionSecurityRuntimeError> {
    let identity = FindingIdentity::new(
        contract.target_id,
        contract.method,
        contract.sentinel_endpoint,
        weakness,
        parameter_location,
        Some("session".to_string()),
    )
    .map_err(|_| SessionSecurityRuntimeError::InvalidContract)?;
    let request_count = roles.len() * contract.repetitions_per_role;
    if request_count > limits.max_requests {
        return Err(SessionSecurityRuntimeError::RequestLimitExceeded);
    }
    let mut executions = Vec::with_capacity(request_count);
    for spec in roles {
        if spec.window_start_millis > spec.window_end_millis {
            return Err(SessionSecurityRuntimeError::InvalidSessionFlow);
        }
        for repetition in 1..=contract.repetitions_per_role {
            executions.push(SessionSecurityExecution {
                role: spec.role,
                credential_ref: spec.credential_ref.map(str::to_string),
                request_fingerprint: contract.request_fingerprint.to_string(),
                repetition,
                window_start_millis: spec.window_start_millis,
                window_end_millis: spec.window_end_millis,
            });
        }
    }
    Ok(SessionSecurityPlan {
        identity,
        mode,
        request_fingerprint: contract.request_fingerprint.to_string(),
        credential_rotated,
        executions,
    })
}

fn validate_plan_contract(
    contract: &SessionSecurityContract<'_>,
    limits: SessionSecurityLimits,
) -> Result<(), SessionSecurityRuntimeError> {
    validate_limits(limits)?;
    if !contract.explicitly_approved {
        return Err(SessionSecurityRuntimeError::UnapprovedProbe);
    }
    if !contract.synthetic_read_only_sentinel {
        return Err(SessionSecurityRuntimeError::UnsafeSentinel);
    }
    if !matches!(contract.method, HttpMethod::Get | HttpMethod::Head)
        || !valid_sha256(contract.request_fingerprint)
        || contract.repetitions_per_role < 2
        || contract.repetitions_per_role > limits.max_repetitions_per_role
    {
        return Err(SessionSecurityRuntimeError::InvalidContract);
    }
    FindingIdentity::new(
        contract.target_id,
        contract.method,
        contract.sentinel_endpoint,
        "CWE-613",
        ParameterLocation::Cookie,
        Some("session".to_string()),
    )
    .map_err(|_| SessionSecurityRuntimeError::InvalidContract)?;
    Ok(())
}

fn validate_limits(limits: SessionSecurityLimits) -> Result<(), SessionSecurityRuntimeError> {
    if limits.max_repetitions_per_role < 2
        || limits.max_repetitions_per_role > HARD_MAX_REPETITIONS_PER_ROLE
        || limits.max_requests < 6
        || limits.max_requests > HARD_MAX_REQUESTS
    {
        return Err(SessionSecurityRuntimeError::InvalidLimits);
    }
    Ok(())
}

fn authenticated_state<'a>(
    graph: &'a SessionFlowGraph,
    state_id: &SessionStateId,
) -> Result<&'a SessionState, SessionSecurityRuntimeError> {
    let state = graph
        .state(state_id)
        .ok_or(SessionSecurityRuntimeError::InvalidSessionFlow)?;
    if !matches!(
        state.phase,
        SessionPhase::Authenticated | SessionPhase::Refreshed
    ) || state.credential.is_none()
    {
        return Err(SessionSecurityRuntimeError::InvalidSessionFlow);
    }
    Ok(state)
}

fn validate_logout_transition(
    graph: &SessionFlowGraph,
    pre_logout: &SessionState,
    logged_out: &SessionState,
) -> Result<(), SessionSecurityRuntimeError> {
    let step_id = logged_out
        .created_by_step
        .as_ref()
        .ok_or(SessionSecurityRuntimeError::InvalidSessionFlow)?;
    let step = graph
        .step(step_id)
        .ok_or(SessionSecurityRuntimeError::InvalidSessionFlow)?;
    if logged_out.phase != SessionPhase::LoggedOut
        || logged_out.credential.is_some()
        || step.kind != SessionRequestKind::Logout
        || step.from_state != pre_logout.id
        || step.to_state != logged_out.id
    {
        return Err(SessionSecurityRuntimeError::InvalidSessionFlow);
    }
    Ok(())
}

fn validate_direct_login_state(
    graph: &SessionFlowGraph,
    authenticated: &SessionState,
) -> Result<(), SessionSecurityRuntimeError> {
    let step_id = authenticated
        .created_by_step
        .as_ref()
        .ok_or(SessionSecurityRuntimeError::InvalidSessionFlow)?;
    let step = graph
        .step(step_id)
        .ok_or(SessionSecurityRuntimeError::InvalidSessionFlow)?;
    let from = graph
        .state(&step.from_state)
        .ok_or(SessionSecurityRuntimeError::InvalidSessionFlow)?;
    if authenticated.phase != SessionPhase::Authenticated
        || step.kind != SessionRequestKind::Login
        || step.to_state != authenticated.id
        || from.phase != SessionPhase::Anonymous
    {
        return Err(SessionSecurityRuntimeError::InvalidSessionFlow);
    }
    Ok(())
}

fn validate_observation(
    observation: &SessionSecurityObservation<'_>,
    plan: &SessionSecurityPlan,
) -> Result<(), SessionSecurityRuntimeError> {
    let execution = plan
        .executions
        .iter()
        .find(|execution| {
            execution.role == observation.role && execution.repetition == observation.repetition
        })
        .ok_or(SessionSecurityRuntimeError::InvalidObservation)?;
    if observation.request_fingerprint != plan.request_fingerprint
        || observation.repetition == 0
        || observation.observed_at_millis < execution.window_start_millis
        || observation.observed_at_millis > execution.window_end_millis
        || !(100..=599).contains(&observation.status_code)
        || !valid_sha256(observation.redacted_body_fingerprint)
        || !valid_evidence_ref(observation.evidence_ref)
        || !outcome_matches_status(observation.access_outcome, observation.status_code)
    {
        return Err(SessionSecurityRuntimeError::InvalidObservation);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ExecutionSpec<'a> {
    role: SessionSecurityRole,
    credential_ref: Option<&'a str>,
    window_start_millis: u64,
    window_end_millis: u64,
}

impl<'a> ExecutionSpec<'a> {
    fn new(
        role: SessionSecurityRole,
        credential_ref: Option<&'a str>,
        window_start_millis: u64,
        window_end_millis: u64,
    ) -> Self {
        Self {
            role,
            credential_ref,
            window_start_millis,
            window_end_millis,
        }
    }
}

fn decide(
    plan: &SessionSecurityPlan,
    results: Vec<SessionSecurityResult>,
) -> Result<SessionSecurityAssessment, SessionSecurityRuntimeError> {
    if results.len() != ROLE_COUNT || results.iter().any(|result| !result.stable) {
        return Ok(assessment(SessionSecurityDecision::Abstain, results, None));
    }
    let anonymous = result(&results, SessionSecurityRole::AnonymousControl)?;
    if !denied(anonymous) {
        return Ok(assessment(SessionSecurityDecision::Abstain, results, None));
    }
    match plan.mode {
        SessionSecurityMode::LogoutInvalidation => decide_invalidation(
            plan,
            results,
            SessionSecurityRole::AuthenticatedBaseline,
            SessionSecurityRole::ReplayAfterLogout,
            SessionSecuritySignal::SessionSurvivesLogout,
        ),
        SessionSecurityMode::ExpiryEnforcement => decide_invalidation(
            plan,
            results,
            SessionSecurityRole::AuthenticatedBaseline,
            SessionSecurityRole::ReplayAfterExpiry,
            SessionSecuritySignal::SessionSurvivesExpiry,
        ),
        SessionSecurityMode::SessionFixation => decide_fixation(plan, results),
    }
}

fn decide_invalidation(
    plan: &SessionSecurityPlan,
    results: Vec<SessionSecurityResult>,
    baseline_role: SessionSecurityRole,
    replay_role: SessionSecurityRole,
    signal: SessionSecuritySignal,
) -> Result<SessionSecurityAssessment, SessionSecurityRuntimeError> {
    let baseline = result(&results, baseline_role)?;
    let replay = result(&results, replay_role)?;
    if !allowed(baseline) {
        return Ok(assessment(SessionSecurityDecision::Abstain, results, None));
    }
    if denied(replay) {
        return Ok(assessment(
            SessionSecurityDecision::NotObserved,
            results,
            None,
        ));
    }
    if !allowed(replay) {
        return Ok(assessment(SessionSecurityDecision::Abstain, results, None));
    }
    let confidence = if baseline.status_code == replay.status_code
        && baseline.body_fingerprint == replay.body_fingerprint
    {
        Confidence::High
    } else {
        Confidence::Medium
    };
    let candidate = candidate(plan, signal, confidence, &results);
    Ok(assessment(
        SessionSecurityDecision::Candidate,
        results,
        Some(candidate),
    ))
}

fn decide_fixation(
    plan: &SessionSecurityPlan,
    results: Vec<SessionSecurityResult>,
) -> Result<SessionSecurityAssessment, SessionSecurityRuntimeError> {
    let pre_auth = result(&results, SessionSecurityRole::PreAuthenticationControl)?;
    let post_login = result(&results, SessionSecurityRole::PostLoginAuthenticated)?;
    if !denied(pre_auth) || !allowed(post_login) {
        return Ok(assessment(SessionSecurityDecision::Abstain, results, None));
    }
    if plan.credential_rotated != Some(false) {
        return Ok(assessment(
            SessionSecurityDecision::NotObserved,
            results,
            None,
        ));
    }
    let candidate = candidate(
        plan,
        SessionSecuritySignal::CredentialNotRotatedAfterLogin,
        Confidence::High,
        &results,
    );
    Ok(assessment(
        SessionSecurityDecision::Candidate,
        results,
        Some(candidate),
    ))
}

fn result(
    results: &[SessionSecurityResult],
    role: SessionSecurityRole,
) -> Result<&SessionSecurityResult, SessionSecurityRuntimeError> {
    results
        .iter()
        .find(|result| result.role == role)
        .ok_or(SessionSecurityRuntimeError::MissingObservation)
}

fn allowed(result: &SessionSecurityResult) -> bool {
    result.access_outcome == Some(crate::RoleAccessOutcome::Allowed)
}

fn denied(result: &SessionSecurityResult) -> bool {
    matches!(
        result.access_outcome,
        Some(crate::RoleAccessOutcome::Denied | crate::RoleAccessOutcome::RedirectedToLogin)
    )
}

fn candidate(
    plan: &SessionSecurityPlan,
    signal: SessionSecuritySignal,
    confidence: Confidence,
    results: &[SessionSecurityResult],
) -> SessionSecurityCandidate {
    let namespace = match signal {
        SessionSecuritySignal::SessionSurvivesLogout => "logout",
        SessionSecuritySignal::SessionSurvivesExpiry => "expiry",
        SessionSecuritySignal::CredentialNotRotatedAfterLogin => "fixation",
    };
    SessionSecurityCandidate {
        candidate_id: format!(
            "session-{namespace}-candidate-{}",
            &plan.identity.fingerprint()[..24]
        ),
        signal,
        confidence,
        evidence_refs: results
            .iter()
            .flat_map(|result| result.evidence_refs.iter().map(String::as_str))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(str::to_string)
            .collect(),
        requires_manual_confirmation: true,
    }
}

fn credential_location(kind: SessionCredentialKind) -> ParameterLocation {
    match kind {
        SessionCredentialKind::Cookie => ParameterLocation::Cookie,
        SessionCredentialKind::Bearer | SessionCredentialKind::ApiKey => ParameterLocation::Header,
    }
}

fn assessment(
    decision: SessionSecurityDecision,
    results: Vec<SessionSecurityResult>,
    candidate: Option<SessionSecurityCandidate>,
) -> SessionSecurityAssessment {
    SessionSecurityAssessment {
        decision,
        results,
        candidate,
    }
}

fn outcome_matches_status(outcome: crate::RoleAccessOutcome, status: u16) -> bool {
    match outcome {
        crate::RoleAccessOutcome::Allowed => (200..300).contains(&status),
        crate::RoleAccessOutcome::Denied => matches!(status, 401 | 403),
        crate::RoleAccessOutcome::RedirectedToLogin => (300..400).contains(&status),
        crate::RoleAccessOutcome::Unknown => true,
    }
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

pub(crate) fn benchmark_outcomes() -> Result<(bool, bool), SessionSecurityRuntimeError> {
    const FLOW: &str = "flow_0123456789abcdef0123456789abcdef";
    const PRINCIPAL: &str = "principal_0123456789abcdef0123456789abcdef";
    const CREDENTIAL: &str = "credref_0123456789abcdef0123456789abcdef";
    const REQUEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BODY_ALLOWED: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const BODY_DENIED: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let (mut graph, anonymous) =
        SessionFlowGraph::new(FLOW, PRINCIPAL, 1_000, crate::SessionGraphLimits::default())
            .map_err(|_| SessionSecurityRuntimeError::InvalidSessionFlow)?;
    let credential =
        CredentialReference::new(CREDENTIAL, SessionCredentialKind::Cookie, 1, Some(10_000))
            .map_err(|_| SessionSecurityRuntimeError::InvalidCredential)?;
    let (login_step, authenticated) = graph
        .add_request(crate::SessionRequestTransition {
            from_state: &anonymous,
            kind: SessionRequestKind::Login,
            method: HttpMethod::Post,
            endpoint: "https://benchmark.invalid/login",
            outcome: crate::TransitionOutcome::LoginSucceeded,
            issued_credential: Some(credential),
            occurred_at_millis: 2_000,
            dependencies: &[],
        })
        .map_err(|_| SessionSecurityRuntimeError::InvalidSessionFlow)?;
    let (_, logged_out) = graph
        .add_request(crate::SessionRequestTransition {
            from_state: &authenticated,
            kind: SessionRequestKind::Logout,
            method: HttpMethod::Post,
            endpoint: "https://benchmark.invalid/logout",
            outcome: crate::TransitionOutcome::LogoutSucceeded,
            issued_credential: None,
            occurred_at_millis: 4_000,
            dependencies: std::slice::from_ref(&login_step),
        })
        .map_err(|_| SessionSecurityRuntimeError::InvalidSessionFlow)?;
    let contract = SessionSecurityContract {
        target_id: "benchmark-target",
        sentinel_endpoint: "https://benchmark.invalid/test-session",
        method: HttpMethod::Get,
        request_fingerprint: REQUEST,
        repetitions_per_role: 2,
        planned_at_millis: 6_000,
        synthetic_read_only_sentinel: true,
        explicitly_approved: true,
    };
    let plan = plan_logout_invalidation(
        &contract,
        &graph,
        &authenticated,
        &logged_out,
        SessionSecurityLimits::default(),
    )?;
    let observations = |replay_outcome, replay_status, replay_body| {
        plan.executions()
            .iter()
            .map(|execution| {
                let (access_outcome, status_code, body) = match execution.role() {
                    SessionSecurityRole::AuthenticatedBaseline
                    | SessionSecurityRole::PostLoginAuthenticated => {
                        (crate::RoleAccessOutcome::Allowed, 200, BODY_ALLOWED)
                    }
                    SessionSecurityRole::ReplayAfterLogout
                    | SessionSecurityRole::ReplayAfterExpiry => {
                        (replay_outcome, replay_status, replay_body)
                    }
                    SessionSecurityRole::PreAuthenticationControl
                    | SessionSecurityRole::AnonymousControl => {
                        (crate::RoleAccessOutcome::Denied, 403, BODY_DENIED)
                    }
                };
                SessionSecurityObservation {
                    role: execution.role(),
                    request_fingerprint: execution.request_fingerprint(),
                    repetition: execution.repetition(),
                    observed_at_millis: execution.window_start_millis(),
                    status_code,
                    access_outcome,
                    redacted_body_fingerprint: body,
                    evidence_ref: match (execution.role(), execution.repetition()) {
                        (SessionSecurityRole::AuthenticatedBaseline, 1) => "benchmark-base-1",
                        (SessionSecurityRole::AuthenticatedBaseline, 2) => "benchmark-base-2",
                        (SessionSecurityRole::ReplayAfterLogout, 1) => "benchmark-replay-1",
                        (SessionSecurityRole::ReplayAfterLogout, 2) => "benchmark-replay-2",
                        (SessionSecurityRole::PreAuthenticationControl, 1) => "benchmark-control-1",
                        (SessionSecurityRole::PreAuthenticationControl, 2) => "benchmark-control-2",
                        _ => "benchmark-other",
                    },
                }
            })
            .collect::<Vec<_>>()
    };
    let vulnerable = observations(crate::RoleAccessOutcome::Allowed, 200, BODY_ALLOWED);
    let positive = assess_session_security(&plan, &vulnerable)?;
    let safe = observations(crate::RoleAccessOutcome::Denied, 403, BODY_DENIED);
    let negative = assess_session_security(&plan, &safe)?;
    Ok((
        positive.decision == SessionSecurityDecision::Candidate && positive.candidate.is_some(),
        negative.decision == SessionSecurityDecision::Candidate || negative.candidate.is_some(),
    ))
}

#[cfg(test)]
mod tests {
    use aegis_native_engine::{Confidence, HttpMethod};

    use super::{
        assess_session_security, plan_expiry_enforcement, plan_logout_invalidation,
        plan_session_fixation, SessionIdentifierComparison, SessionSecurityContract,
        SessionSecurityDecision, SessionSecurityLimits, SessionSecurityMode,
        SessionSecurityObservation, SessionSecurityPlan, SessionSecurityRole,
        SessionSecurityRuntimeError, SessionSecuritySignal,
    };
    use crate::{
        CredentialReference, RoleAccessOutcome, SessionCredentialKind, SessionFlowGraph,
        SessionGraphLimits, SessionRequestKind, SessionRequestTransition, TransitionOutcome,
    };

    const FLOW: &str = "flow_0123456789abcdef0123456789abcdef";
    const PRINCIPAL: &str = "principal_0123456789abcdef0123456789abcdef";
    const CRED_1: &str = "credref_0123456789abcdef0123456789abcdef";
    const CRED_2: &str = "credref_fedcba9876543210fedcba9876543210";
    const REQUEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BODY_ALLOWED: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const BODY_DENIED: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const SESSION_ID_A: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const SESSION_ID_B: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    fn credential(id: &str, expiry: Option<u64>) -> CredentialReference {
        CredentialReference::new(id, SessionCredentialKind::Cookie, 1, expiry).unwrap()
    }

    fn contract(planned_at_millis: u64) -> SessionSecurityContract<'static> {
        SessionSecurityContract {
            target_id: "target-1",
            sentinel_endpoint: "https://example.com/test-session?token=secret",
            method: HttpMethod::Get,
            request_fingerprint: REQUEST,
            repetitions_per_role: 2,
            planned_at_millis,
            synthetic_read_only_sentinel: true,
            explicitly_approved: true,
        }
    }

    fn login_graph(
        credential: CredentialReference,
    ) -> (
        SessionFlowGraph,
        crate::SessionStateId,
        crate::SessionStepId,
        crate::SessionStateId,
    ) {
        let (mut graph, anonymous) =
            SessionFlowGraph::new(FLOW, PRINCIPAL, 1_000, SessionGraphLimits::default()).unwrap();
        let (login_step, authenticated) = graph
            .add_request(SessionRequestTransition {
                from_state: &anonymous,
                kind: SessionRequestKind::Login,
                method: HttpMethod::Post,
                endpoint: "https://example.com/login",
                outcome: TransitionOutcome::LoginSucceeded,
                issued_credential: Some(credential),
                occurred_at_millis: 2_000,
                dependencies: &[],
            })
            .unwrap();
        (graph, anonymous, login_step, authenticated)
    }

    fn logout_plan() -> SessionSecurityPlan {
        let (mut graph, _anonymous, login_step, authenticated) =
            login_graph(credential(CRED_1, Some(10_000)));
        let (_, logged_out) = graph
            .add_request(SessionRequestTransition {
                from_state: &authenticated,
                kind: SessionRequestKind::Logout,
                method: HttpMethod::Post,
                endpoint: "https://example.com/logout",
                outcome: TransitionOutcome::LogoutSucceeded,
                issued_credential: None,
                occurred_at_millis: 4_000,
                dependencies: std::slice::from_ref(&login_step),
            })
            .unwrap();
        plan_logout_invalidation(
            &contract(6_000),
            &graph,
            &authenticated,
            &logged_out,
            SessionSecurityLimits::default(),
        )
        .unwrap()
    }

    fn expiry_plan() -> SessionSecurityPlan {
        let (mut graph, _anonymous, _login_step, authenticated) =
            login_graph(credential(CRED_1, Some(5_000)));
        let expired = graph.expire_state(&authenticated, 5_000).unwrap();
        plan_expiry_enforcement(
            &contract(6_000),
            &graph,
            &authenticated,
            &expired,
            SessionSecurityLimits::default(),
        )
        .unwrap()
    }

    fn evidence_ref(role: SessionSecurityRole, repetition: usize) -> &'static str {
        match (role, repetition) {
            (SessionSecurityRole::AuthenticatedBaseline, 1) => "baseline-1",
            (SessionSecurityRole::AuthenticatedBaseline, 2) => "baseline-2",
            (SessionSecurityRole::ReplayAfterLogout, 1) => "logout-replay-1",
            (SessionSecurityRole::ReplayAfterLogout, 2) => "logout-replay-2",
            (SessionSecurityRole::ReplayAfterExpiry, 1) => "expiry-replay-1",
            (SessionSecurityRole::ReplayAfterExpiry, 2) => "expiry-replay-2",
            (SessionSecurityRole::PreAuthenticationControl, 1) => "pre-auth-1",
            (SessionSecurityRole::PreAuthenticationControl, 2) => "pre-auth-2",
            (SessionSecurityRole::PostLoginAuthenticated, 1) => "post-login-1",
            (SessionSecurityRole::PostLoginAuthenticated, 2) => "post-login-2",
            (SessionSecurityRole::AnonymousControl, 1) => "anonymous-1",
            (SessionSecurityRole::AnonymousControl, 2) => "anonymous-2",
            _ => "evidence-other",
        }
    }

    fn observations<'a>(
        plan: &'a SessionSecurityPlan,
        replay_outcome: RoleAccessOutcome,
        replay_status: u16,
        replay_body: &'static str,
    ) -> Vec<SessionSecurityObservation<'a>> {
        plan.executions()
            .iter()
            .map(|execution| {
                let (access_outcome, status_code, body) = match execution.role() {
                    SessionSecurityRole::AuthenticatedBaseline
                    | SessionSecurityRole::PostLoginAuthenticated => {
                        (RoleAccessOutcome::Allowed, 200, BODY_ALLOWED)
                    }
                    SessionSecurityRole::ReplayAfterLogout
                    | SessionSecurityRole::ReplayAfterExpiry => {
                        (replay_outcome, replay_status, replay_body)
                    }
                    SessionSecurityRole::PreAuthenticationControl
                    | SessionSecurityRole::AnonymousControl => {
                        (RoleAccessOutcome::Denied, 403, BODY_DENIED)
                    }
                };
                SessionSecurityObservation {
                    role: execution.role(),
                    request_fingerprint: execution.request_fingerprint(),
                    repetition: execution.repetition(),
                    observed_at_millis: execution.window_start_millis(),
                    status_code,
                    access_outcome,
                    redacted_body_fingerprint: body,
                    evidence_ref: evidence_ref(execution.role(), execution.repetition()),
                }
            })
            .collect()
    }

    #[test]
    fn logout_replay_plan_is_read_only_bounded_and_redacted() {
        let plan = logout_plan();
        assert_eq!(plan.mode(), SessionSecurityMode::LogoutInvalidation);
        assert_eq!(plan.executions().len(), 6);
        assert!(plan
            .executions()
            .iter()
            .filter(|execution| execution.role() == SessionSecurityRole::ReplayAfterLogout)
            .all(|execution| execution.credential_ref() == Some(CRED_1)));
        assert!(!plan.canonical_endpoint().contains("secret"));
        let debug = format!("{plan:?} {:?}", plan.executions()[0]);
        assert!(!debug.contains("example.com"));
        assert!(!debug.contains(CRED_1));
        assert!(!debug.contains(REQUEST));
    }

    #[test]
    fn session_surviving_logout_is_high_confidence_manual_candidate() {
        let plan = logout_plan();
        let evidence = observations(&plan, RoleAccessOutcome::Allowed, 200, BODY_ALLOWED);
        let assessment = assess_session_security(&plan, &evidence).unwrap();
        assert_eq!(assessment.decision, SessionSecurityDecision::Candidate);
        let candidate = assessment.candidate.unwrap();
        assert_eq!(
            candidate.signal,
            SessionSecuritySignal::SessionSurvivesLogout
        );
        assert_eq!(candidate.confidence, Confidence::High);
        assert!(candidate.requires_manual_confirmation);
    }

    #[test]
    fn denied_logout_replay_is_not_observed() {
        let plan = logout_plan();
        let evidence = observations(&plan, RoleAccessOutcome::Denied, 403, BODY_DENIED);
        let assessment = assess_session_security(&plan, &evidence).unwrap();
        assert_eq!(assessment.decision, SessionSecurityDecision::NotObserved);
        assert!(assessment.candidate.is_none());
    }

    #[test]
    fn session_surviving_declared_expiry_is_candidate() {
        let plan = expiry_plan();
        assert_eq!(plan.mode(), SessionSecurityMode::ExpiryEnforcement);
        let evidence = observations(&plan, RoleAccessOutcome::Allowed, 200, BODY_ALLOWED);
        let assessment = assess_session_security(&plan, &evidence).unwrap();
        assert_eq!(assessment.decision, SessionSecurityDecision::Candidate);
        assert_eq!(
            assessment.candidate.unwrap().signal,
            SessionSecuritySignal::SessionSurvivesExpiry
        );
    }

    #[test]
    fn fixation_requires_cookie_rotation_and_valid_controls() {
        let (graph, _anonymous, _login_step, authenticated) =
            login_graph(credential(CRED_1, Some(10_000)));
        let pre_auth = credential(CRED_2, Some(10_000));
        let unchanged_identifier =
            SessionIdentifierComparison::new(SESSION_ID_A, SESSION_ID_A).unwrap();
        assert!(!format!("{unchanged_identifier:?}").contains(SESSION_ID_A));
        assert_eq!(
            SessionIdentifierComparison::new("raw-session-id", SESSION_ID_B),
            Err(SessionSecurityRuntimeError::InvalidCredential)
        );
        let plan = plan_session_fixation(
            &contract(6_000),
            &graph,
            &pre_auth,
            &unchanged_identifier,
            &authenticated,
            SessionSecurityLimits::default(),
        )
        .unwrap();
        assert_eq!(plan.credential_rotated(), Some(false));
        let evidence = observations(&plan, RoleAccessOutcome::Denied, 403, BODY_DENIED);
        let assessment = assess_session_security(&plan, &evidence).unwrap();
        assert_eq!(assessment.decision, SessionSecurityDecision::Candidate);
        assert_eq!(
            assessment.candidate.unwrap().signal,
            SessionSecuritySignal::CredentialNotRotatedAfterLogin
        );

        let rotated_identifier =
            SessionIdentifierComparison::new(SESSION_ID_A, SESSION_ID_B).unwrap();
        let rotated = plan_session_fixation(
            &contract(6_000),
            &graph,
            &pre_auth,
            &rotated_identifier,
            &authenticated,
            SessionSecurityLimits::default(),
        )
        .unwrap();
        let evidence = observations(&rotated, RoleAccessOutcome::Denied, 403, BODY_DENIED);
        assert_eq!(
            assess_session_security(&rotated, &evidence)
                .unwrap()
                .decision,
            SessionSecurityDecision::NotObserved
        );
    }

    #[test]
    fn unstable_or_out_of_window_evidence_fails_closed() {
        let plan = logout_plan();
        let mut unstable = observations(&plan, RoleAccessOutcome::Allowed, 200, BODY_ALLOWED);
        let replay = unstable
            .iter_mut()
            .find(|item| {
                item.role == SessionSecurityRole::ReplayAfterLogout && item.repetition == 2
            })
            .unwrap();
        replay.redacted_body_fingerprint = BODY_DENIED;
        assert_eq!(
            assess_session_security(&plan, &unstable).unwrap().decision,
            SessionSecurityDecision::Abstain
        );

        let mut out_of_window = observations(&plan, RoleAccessOutcome::Denied, 403, BODY_DENIED);
        out_of_window[0].observed_at_millis = u64::MAX;
        assert_eq!(
            assess_session_security(&plan, &out_of_window),
            Err(SessionSecurityRuntimeError::InvalidObservation)
        );
    }

    #[test]
    fn unsafe_contract_and_expiry_overlap_are_rejected() {
        let (mut graph, _anonymous, login_step, authenticated) =
            login_graph(credential(CRED_1, Some(5_000)));
        let (_, logged_out) = graph
            .add_request(SessionRequestTransition {
                from_state: &authenticated,
                kind: SessionRequestKind::Logout,
                method: HttpMethod::Post,
                endpoint: "https://example.com/logout",
                outcome: TransitionOutcome::LogoutSucceeded,
                issued_credential: None,
                occurred_at_millis: 4_000,
                dependencies: std::slice::from_ref(&login_step),
            })
            .unwrap();
        assert_eq!(
            plan_logout_invalidation(
                &contract(5_000),
                &graph,
                &authenticated,
                &logged_out,
                SessionSecurityLimits::default(),
            ),
            Err(SessionSecurityRuntimeError::AmbiguousCredentialExpiry)
        );

        let mut unsafe_contract = contract(4_500);
        unsafe_contract.method = HttpMethod::Post;
        assert_eq!(
            plan_logout_invalidation(
                &unsafe_contract,
                &graph,
                &authenticated,
                &logged_out,
                SessionSecurityLimits::default(),
            ),
            Err(SessionSecurityRuntimeError::InvalidContract)
        );
        let mut unapproved = contract(4_500);
        unapproved.explicitly_approved = false;
        assert_eq!(
            plan_logout_invalidation(
                &unapproved,
                &graph,
                &authenticated,
                &logged_out,
                SessionSecurityLimits::default(),
            ),
            Err(SessionSecurityRuntimeError::UnapprovedProbe)
        );
    }
}
