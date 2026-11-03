use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Display, Formatter};

use aegis_native_engine::{FindingIdentity, HttpMethod, ParameterLocation};
use sha2::{Digest, Sha256};

const HARD_MAX_STATES: usize = 256;
const HARD_MAX_STEPS: usize = 256;
const HARD_MAX_DEPENDENCIES: usize = 1_024;
const MAX_REFERENCE_BYTES: usize = 64;
const FLOW_PREFIX: &str = "flow_";
const PRINCIPAL_PREFIX: &str = "principal_";
const CREDENTIAL_PREFIX: &str = "credref_";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SessionCredentialKind {
    Cookie,
    Bearer,
    ApiKey,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CredentialReference {
    reference_id: String,
    pub kind: SessionCredentialKind,
    pub generation: u16,
    pub expires_at_millis: Option<u64>,
}

impl CredentialReference {
    pub fn new(
        reference_id: impl Into<String>,
        kind: SessionCredentialKind,
        generation: u16,
        expires_at_millis: Option<u64>,
    ) -> Result<Self, SessionGraphError> {
        let reference_id = reference_id.into();
        if !valid_prefixed_hash(&reference_id, CREDENTIAL_PREFIX) || generation == 0 {
            return Err(SessionGraphError::InvalidCredentialReference);
        }
        Ok(Self {
            reference_id,
            kind,
            generation,
            expires_at_millis,
        })
    }

    pub fn reference_id(&self) -> &str {
        &self.reference_id
    }
}

impl Debug for CredentialReference {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialReference")
            .field("kind", &self.kind)
            .field("generation", &self.generation)
            .field("expires_at_millis", &self.expires_at_millis)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SessionPhase {
    Anonymous,
    Authenticated,
    Refreshed,
    LoggedOut,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SessionRequestKind {
    Login,
    Refresh,
    Logout,
    Navigation,
    Probe,
    Control,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionOutcome {
    LoginSucceeded,
    RefreshSucceeded,
    LogoutSucceeded,
    Unchanged,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SessionStateId(String);

impl SessionStateId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SessionStepId(String);

impl SessionStepId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RequestDependency {
    pub prerequisite: SessionStepId,
    pub dependent: SessionStepId,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SessionState {
    pub id: SessionStateId,
    pub phase: SessionPhase,
    pub credential: Option<CredentialReference>,
    pub created_at_millis: u64,
    pub created_by_step: Option<SessionStepId>,
    principal_fingerprint: String,
}

impl Debug for SessionState {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionState")
            .field("id", &self.id)
            .field("phase", &self.phase)
            .field("credential", &self.credential)
            .field("created_at_millis", &self.created_at_millis)
            .field("created_by_step", &self.created_by_step)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SessionRequestStep {
    pub id: SessionStepId,
    pub kind: SessionRequestKind,
    pub method: HttpMethod,
    pub canonical_endpoint: String,
    pub from_state: SessionStateId,
    pub to_state: SessionStateId,
    pub occurred_at_millis: u64,
    pub direct_dependencies: BTreeSet<SessionStepId>,
}

impl Debug for SessionRequestStep {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionRequestStep")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("method", &self.method)
            .field("endpoint_bytes", &self.canonical_endpoint.len())
            .field("from_state", &self.from_state)
            .field("to_state", &self.to_state)
            .field("occurred_at_millis", &self.occurred_at_millis)
            .field("dependency_count", &self.direct_dependencies.len())
            .finish()
    }
}

pub struct SessionRequestTransition<'a> {
    pub from_state: &'a SessionStateId,
    pub kind: SessionRequestKind,
    pub method: HttpMethod,
    pub endpoint: &'a str,
    pub outcome: TransitionOutcome,
    pub issued_credential: Option<CredentialReference>,
    pub occurred_at_millis: u64,
    pub dependencies: &'a [SessionStepId],
}

impl Debug for SessionRequestTransition<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionRequestTransition")
            .field("from_state", &self.from_state)
            .field("kind", &self.kind)
            .field("method", &self.method)
            .field("endpoint_bytes", &self.endpoint.len())
            .field("outcome", &self.outcome)
            .field("issued_credential", &self.issued_credential)
            .field("occurred_at_millis", &self.occurred_at_millis)
            .field("dependency_count", &self.dependencies.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionGraphLimits {
    pub max_states: usize,
    pub max_steps: usize,
    pub max_dependencies: usize,
}

impl Default for SessionGraphLimits {
    fn default() -> Self {
        Self {
            max_states: HARD_MAX_STATES,
            max_steps: HARD_MAX_STEPS,
            max_dependencies: HARD_MAX_DEPENDENCIES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionGraphError {
    InvalidLimits,
    InvalidFlow,
    InvalidPrincipal,
    InvalidCredentialReference,
    CredentialExpired,
    InvalidTransition,
    InvalidRequest,
    StateNotFound,
    StepNotFound,
    MissingStateDependency,
    StateLimitExceeded,
    StepLimitExceeded,
    DependencyLimitExceeded,
    IntegrityViolation,
}

impl Display for SessionGraphError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "session graph limits are invalid",
            Self::InvalidFlow => "session flow reference is invalid",
            Self::InvalidPrincipal => "session principal reference is invalid",
            Self::InvalidCredentialReference => "session credential reference is invalid",
            Self::CredentialExpired => "session credential reference has expired",
            Self::InvalidTransition => "session state transition is invalid",
            Self::InvalidRequest => "session request is invalid",
            Self::StateNotFound => "session state was not found",
            Self::StepNotFound => "session request step was not found",
            Self::MissingStateDependency => {
                "session request omitted its state-producing dependency"
            }
            Self::StateLimitExceeded => "session state limit was exceeded",
            Self::StepLimitExceeded => "session request step limit was exceeded",
            Self::DependencyLimitExceeded => "session request dependency limit was exceeded",
            Self::IntegrityViolation => "session graph integrity validation failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SessionGraphError {}

pub struct SessionFlowGraph {
    limits: SessionGraphLimits,
    flow_id: String,
    principal_fingerprint: String,
    states: BTreeMap<SessionStateId, SessionState>,
    steps: BTreeMap<SessionStepId, SessionRequestStep>,
    dependencies: BTreeSet<RequestDependency>,
    next_state_sequence: u64,
    next_step_sequence: u64,
}

impl Debug for SessionFlowGraph {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionFlowGraph")
            .field("state_count", &self.states.len())
            .field("step_count", &self.steps.len())
            .field("dependency_count", &self.dependencies.len())
            .finish()
    }
}

impl SessionFlowGraph {
    pub fn new(
        flow_id: impl Into<String>,
        principal_ref: &str,
        created_at_millis: u64,
        limits: SessionGraphLimits,
    ) -> Result<(Self, SessionStateId), SessionGraphError> {
        validate_limits(limits)?;
        let flow_id = flow_id.into();
        if !valid_prefixed_hash(&flow_id, FLOW_PREFIX) {
            return Err(SessionGraphError::InvalidFlow);
        }
        if !valid_prefixed_hash(principal_ref, PRINCIPAL_PREFIX) {
            return Err(SessionGraphError::InvalidPrincipal);
        }
        let principal_fingerprint = sha256_hex(principal_ref.as_bytes());
        let initial_id = state_id(&flow_id, 1, SessionPhase::Anonymous);
        let initial = SessionState {
            id: initial_id.clone(),
            phase: SessionPhase::Anonymous,
            credential: None,
            created_at_millis,
            created_by_step: None,
            principal_fingerprint: principal_fingerprint.clone(),
        };
        let mut states = BTreeMap::new();
        states.insert(initial_id.clone(), initial);
        Ok((
            Self {
                limits,
                flow_id,
                principal_fingerprint,
                states,
                steps: BTreeMap::new(),
                dependencies: BTreeSet::new(),
                next_state_sequence: 2,
                next_step_sequence: 1,
            },
            initial_id,
        ))
    }

    pub fn add_request(
        &mut self,
        transition: SessionRequestTransition<'_>,
    ) -> Result<(SessionStepId, SessionStateId), SessionGraphError> {
        if self.states.len() >= self.limits.max_states {
            return Err(SessionGraphError::StateLimitExceeded);
        }
        if self.steps.len() >= self.limits.max_steps {
            return Err(SessionGraphError::StepLimitExceeded);
        }
        let from = self
            .states
            .get(transition.from_state)
            .ok_or(SessionGraphError::StateNotFound)?;
        validate_request(&transition, from)?;
        let dependencies = transition
            .dependencies
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if dependencies.len() != transition.dependencies.len() {
            return Err(SessionGraphError::InvalidRequest);
        }
        for dependency in &dependencies {
            if !self.steps.contains_key(dependency) {
                return Err(SessionGraphError::StepNotFound);
            }
        }
        if from
            .created_by_step
            .as_ref()
            .is_some_and(|creator| !dependencies.contains(creator))
        {
            return Err(SessionGraphError::MissingStateDependency);
        }
        if self.dependencies.len().saturating_add(dependencies.len()) > self.limits.max_dependencies
        {
            return Err(SessionGraphError::DependencyLimitExceeded);
        }

        let identity = FindingIdentity::new(
            self.flow_id.clone(),
            transition.method,
            transition.endpoint,
            "CWE-287",
            ParameterLocation::None,
            None,
        )
        .map_err(|_| SessionGraphError::InvalidRequest)?;
        let (phase, credential) = next_state_values(from, &transition)?;
        let step_id = step_id(&self.flow_id, self.next_step_sequence, transition.kind);
        let next_state_id = state_id(&self.flow_id, self.next_state_sequence, phase);
        let step = SessionRequestStep {
            id: step_id.clone(),
            kind: transition.kind,
            method: transition.method,
            canonical_endpoint: identity.canonical_endpoint,
            from_state: transition.from_state.clone(),
            to_state: next_state_id.clone(),
            occurred_at_millis: transition.occurred_at_millis,
            direct_dependencies: dependencies.clone(),
        };
        let state = SessionState {
            id: next_state_id.clone(),
            phase,
            credential,
            created_at_millis: transition.occurred_at_millis,
            created_by_step: Some(step_id.clone()),
            principal_fingerprint: self.principal_fingerprint.clone(),
        };
        for prerequisite in dependencies {
            self.dependencies.insert(RequestDependency {
                prerequisite,
                dependent: step_id.clone(),
            });
        }
        self.steps.insert(step_id.clone(), step);
        self.states.insert(next_state_id.clone(), state);
        self.next_step_sequence += 1;
        self.next_state_sequence += 1;
        Ok((step_id, next_state_id))
    }

    pub fn expire_state(
        &mut self,
        from_state: &SessionStateId,
        occurred_at_millis: u64,
    ) -> Result<SessionStateId, SessionGraphError> {
        if self.states.len() >= self.limits.max_states {
            return Err(SessionGraphError::StateLimitExceeded);
        }
        let from = self
            .states
            .get(from_state)
            .ok_or(SessionGraphError::StateNotFound)?;
        if !matches!(
            from.phase,
            SessionPhase::Authenticated | SessionPhase::Refreshed
        ) || occurred_at_millis < from.created_at_millis
        {
            return Err(SessionGraphError::InvalidTransition);
        }
        let id = state_id(
            &self.flow_id,
            self.next_state_sequence,
            SessionPhase::Expired,
        );
        self.states.insert(
            id.clone(),
            SessionState {
                id: id.clone(),
                phase: SessionPhase::Expired,
                credential: None,
                created_at_millis: occurred_at_millis,
                created_by_step: from.created_by_step.clone(),
                principal_fingerprint: self.principal_fingerprint.clone(),
            },
        );
        self.next_state_sequence += 1;
        Ok(id)
    }

    pub fn state(&self, id: &SessionStateId) -> Option<&SessionState> {
        self.states.get(id)
    }

    pub fn step(&self, id: &SessionStepId) -> Option<&SessionRequestStep> {
        self.steps.get(id)
    }

    pub fn dependencies(&self) -> impl Iterator<Item = &RequestDependency> {
        self.dependencies.iter()
    }

    pub(crate) fn principal_fingerprint(&self) -> &str {
        &self.principal_fingerprint
    }

    pub fn prerequisites(
        &self,
        step_id: &SessionStepId,
    ) -> Result<BTreeSet<SessionStepId>, SessionGraphError> {
        if !self.steps.contains_key(step_id) {
            return Err(SessionGraphError::StepNotFound);
        }
        let mut collected = BTreeSet::new();
        let mut pending = vec![step_id.clone()];
        while let Some(dependent) = pending.pop() {
            for edge in self
                .dependencies
                .iter()
                .filter(|edge| edge.dependent == dependent)
            {
                if collected.insert(edge.prerequisite.clone()) {
                    pending.push(edge.prerequisite.clone());
                }
            }
        }
        Ok(collected)
    }

    pub fn ready_steps(&self, completed: &BTreeSet<SessionStepId>) -> Vec<SessionStepId> {
        self.steps
            .values()
            .filter(|step| {
                !completed.contains(&step.id)
                    && step
                        .direct_dependencies
                        .iter()
                        .all(|dependency| completed.contains(dependency))
            })
            .map(|step| step.id.clone())
            .collect()
    }

    pub fn validate(&self) -> Result<(), SessionGraphError> {
        if self.states.len() > self.limits.max_states
            || self.steps.len() > self.limits.max_steps
            || self.dependencies.len() > self.limits.max_dependencies
            || self
                .states
                .values()
                .any(|state| state.principal_fingerprint != self.principal_fingerprint)
        {
            return Err(SessionGraphError::IntegrityViolation);
        }
        for step in self.steps.values() {
            if !self.states.contains_key(&step.from_state)
                || !self.states.contains_key(&step.to_state)
                || step.direct_dependencies.iter().any(|dependency| {
                    !self.steps.contains_key(dependency)
                        || !self.dependencies.contains(&RequestDependency {
                            prerequisite: dependency.clone(),
                            dependent: step.id.clone(),
                        })
                })
            {
                return Err(SessionGraphError::IntegrityViolation);
            }
            if self.prerequisites(&step.id)?.contains(&step.id) {
                return Err(SessionGraphError::IntegrityViolation);
            }
        }
        Ok(())
    }
}

fn validate_limits(limits: SessionGraphLimits) -> Result<(), SessionGraphError> {
    if limits.max_states == 0
        || limits.max_states > HARD_MAX_STATES
        || limits.max_steps == 0
        || limits.max_steps > HARD_MAX_STEPS
        || limits.max_dependencies == 0
        || limits.max_dependencies > HARD_MAX_DEPENDENCIES
    {
        return Err(SessionGraphError::InvalidLimits);
    }
    Ok(())
}

fn validate_request(
    transition: &SessionRequestTransition<'_>,
    from: &SessionState,
) -> Result<(), SessionGraphError> {
    if transition.occurred_at_millis < from.created_at_millis
        || !method_allowed(transition.kind, transition.method)
        || from.credential.as_ref().is_some_and(|credential| {
            credential
                .expires_at_millis
                .is_some_and(|expiry| expiry <= transition.occurred_at_millis)
        })
    {
        return if from.credential.as_ref().is_some_and(|credential| {
            credential
                .expires_at_millis
                .is_some_and(|expiry| expiry <= transition.occurred_at_millis)
        }) {
            Err(SessionGraphError::CredentialExpired)
        } else {
            Err(SessionGraphError::InvalidRequest)
        };
    }
    Ok(())
}

fn method_allowed(kind: SessionRequestKind, method: HttpMethod) -> bool {
    match kind {
        SessionRequestKind::Login | SessionRequestKind::Refresh | SessionRequestKind::Logout => {
            method == HttpMethod::Post
        }
        SessionRequestKind::Navigation => {
            matches!(
                method,
                HttpMethod::Get | HttpMethod::Head | HttpMethod::Options
            )
        }
        SessionRequestKind::Probe | SessionRequestKind::Control => {
            matches!(method, HttpMethod::Get | HttpMethod::Post)
        }
    }
}

fn next_state_values(
    from: &SessionState,
    transition: &SessionRequestTransition<'_>,
) -> Result<(SessionPhase, Option<CredentialReference>), SessionGraphError> {
    match (transition.kind, transition.outcome, from.phase) {
        (
            SessionRequestKind::Login,
            TransitionOutcome::LoginSucceeded,
            SessionPhase::Anonymous | SessionPhase::LoggedOut | SessionPhase::Expired,
        ) => {
            let credential = transition
                .issued_credential
                .clone()
                .ok_or(SessionGraphError::InvalidTransition)?;
            if credential.generation != 1
                || credential
                    .expires_at_millis
                    .is_some_and(|expiry| expiry <= transition.occurred_at_millis)
            {
                return Err(SessionGraphError::InvalidCredentialReference);
            }
            Ok((SessionPhase::Authenticated, Some(credential)))
        }
        (
            SessionRequestKind::Refresh,
            TransitionOutcome::RefreshSucceeded,
            SessionPhase::Authenticated | SessionPhase::Refreshed,
        ) => {
            let current = from
                .credential
                .as_ref()
                .ok_or(SessionGraphError::InvalidTransition)?;
            let credential = transition
                .issued_credential
                .clone()
                .ok_or(SessionGraphError::InvalidTransition)?;
            if credential.kind != current.kind
                || credential.generation <= current.generation
                || credential.reference_id == current.reference_id
                || credential
                    .expires_at_millis
                    .is_some_and(|expiry| expiry <= transition.occurred_at_millis)
            {
                return Err(SessionGraphError::InvalidCredentialReference);
            }
            Ok((SessionPhase::Refreshed, Some(credential)))
        }
        (
            SessionRequestKind::Logout,
            TransitionOutcome::LogoutSucceeded,
            SessionPhase::Authenticated | SessionPhase::Refreshed,
        ) if transition.issued_credential.is_none() => Ok((SessionPhase::LoggedOut, None)),
        (
            SessionRequestKind::Navigation
            | SessionRequestKind::Probe
            | SessionRequestKind::Control,
            TransitionOutcome::Unchanged,
            _,
        ) if transition.issued_credential.is_none() => Ok((from.phase, from.credential.clone())),
        _ => Err(SessionGraphError::InvalidTransition),
    }
}

fn valid_prefixed_hash(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 32
        && value.len() <= MAX_REFERENCE_BYTES
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn state_id(flow_id: &str, sequence: u64, phase: SessionPhase) -> SessionStateId {
    SessionStateId(format!(
        "state_{}",
        &sha256_hex(format!("{flow_id}\0{sequence}\0{phase:?}").as_bytes())[..24]
    ))
}

fn step_id(flow_id: &str, sequence: u64, kind: SessionRequestKind) -> SessionStepId {
    SessionStepId(format!(
        "step_{}",
        &sha256_hex(format!("{flow_id}\0{sequence}\0{kind:?}").as_bytes())[..24]
    ))
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use aegis_native_engine::HttpMethod;

    use super::{
        CredentialReference, SessionCredentialKind, SessionFlowGraph, SessionGraphError,
        SessionGraphLimits, SessionPhase, SessionRequestKind, SessionRequestTransition,
        TransitionOutcome,
    };

    const FLOW: &str = "flow_0123456789abcdef0123456789abcdef";
    const PRINCIPAL: &str = "principal_0123456789abcdef0123456789abcdef";
    const CRED_1: &str = "credref_0123456789abcdef0123456789abcdef";
    const CRED_2: &str = "credref_fedcba9876543210fedcba9876543210";

    fn credential(id: &str, generation: u16, expiry: u64) -> CredentialReference {
        CredentialReference::new(id, SessionCredentialKind::Cookie, generation, Some(expiry))
            .unwrap()
    }

    #[test]
    fn login_refresh_navigation_logout_form_ordered_dependency_graph() {
        let (mut graph, anonymous) =
            SessionFlowGraph::new(FLOW, PRINCIPAL, 1_000, SessionGraphLimits::default()).unwrap();
        let (login_step, authenticated) = graph
            .add_request(SessionRequestTransition {
                from_state: &anonymous,
                kind: SessionRequestKind::Login,
                method: HttpMethod::Post,
                endpoint: "https://example.com/login?nonce=secret",
                outcome: TransitionOutcome::LoginSucceeded,
                issued_credential: Some(credential(CRED_1, 1, 10_000)),
                occurred_at_millis: 2_000,
                dependencies: &[],
            })
            .unwrap();
        let (refresh_step, refreshed) = graph
            .add_request(SessionRequestTransition {
                from_state: &authenticated,
                kind: SessionRequestKind::Refresh,
                method: HttpMethod::Post,
                endpoint: "https://example.com/refresh",
                outcome: TransitionOutcome::RefreshSucceeded,
                issued_credential: Some(credential(CRED_2, 2, 20_000)),
                occurred_at_millis: 3_000,
                dependencies: std::slice::from_ref(&login_step),
            })
            .unwrap();
        let (navigation_step, navigated) = graph
            .add_request(SessionRequestTransition {
                from_state: &refreshed,
                kind: SessionRequestKind::Navigation,
                method: HttpMethod::Get,
                endpoint: "https://example.com/account?token=secret",
                outcome: TransitionOutcome::Unchanged,
                issued_credential: None,
                occurred_at_millis: 4_000,
                dependencies: std::slice::from_ref(&refresh_step),
            })
            .unwrap();
        let (_logout_step, logged_out) = graph
            .add_request(SessionRequestTransition {
                from_state: &navigated,
                kind: SessionRequestKind::Logout,
                method: HttpMethod::Post,
                endpoint: "https://example.com/logout",
                outcome: TransitionOutcome::LogoutSucceeded,
                issued_credential: None,
                occurred_at_millis: 5_000,
                dependencies: std::slice::from_ref(&navigation_step),
            })
            .unwrap();
        assert_eq!(
            graph.state(&refreshed).unwrap().phase,
            SessionPhase::Refreshed
        );
        assert_eq!(
            graph.state(&logged_out).unwrap().phase,
            SessionPhase::LoggedOut
        );
        assert!(graph.state(&logged_out).unwrap().credential.is_none());
        assert_eq!(graph.prerequisites(&navigation_step).unwrap().len(), 2);
        assert!(graph.validate().is_ok());
        let debug = format!("{graph:?} {:?}", graph.step(&navigation_step).unwrap());
        assert!(!debug.contains("example.com"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains(CRED_1));
    }

    #[test]
    fn state_producer_must_be_an_explicit_dependency() {
        let (mut graph, anonymous) =
            SessionFlowGraph::new(FLOW, PRINCIPAL, 1_000, SessionGraphLimits::default()).unwrap();
        let (_login_step, authenticated) = graph
            .add_request(SessionRequestTransition {
                from_state: &anonymous,
                kind: SessionRequestKind::Login,
                method: HttpMethod::Post,
                endpoint: "https://example.com/login",
                outcome: TransitionOutcome::LoginSucceeded,
                issued_credential: Some(credential(CRED_1, 1, 10_000)),
                occurred_at_millis: 2_000,
                dependencies: &[],
            })
            .unwrap();
        assert_eq!(
            graph.add_request(SessionRequestTransition {
                from_state: &authenticated,
                kind: SessionRequestKind::Navigation,
                method: HttpMethod::Get,
                endpoint: "https://example.com/account",
                outcome: TransitionOutcome::Unchanged,
                issued_credential: None,
                occurred_at_millis: 3_000,
                dependencies: &[],
            }),
            Err(SessionGraphError::MissingStateDependency)
        );
    }

    #[test]
    fn refresh_requires_rotated_generation_and_unexpired_reference() {
        let (mut graph, anonymous) =
            SessionFlowGraph::new(FLOW, PRINCIPAL, 1_000, SessionGraphLimits::default()).unwrap();
        let (login_step, authenticated) = graph
            .add_request(SessionRequestTransition {
                from_state: &anonymous,
                kind: SessionRequestKind::Login,
                method: HttpMethod::Post,
                endpoint: "https://example.com/login",
                outcome: TransitionOutcome::LoginSucceeded,
                issued_credential: Some(credential(CRED_1, 1, 10_000)),
                occurred_at_millis: 2_000,
                dependencies: &[],
            })
            .unwrap();
        assert!(graph
            .add_request(SessionRequestTransition {
                from_state: &authenticated,
                kind: SessionRequestKind::Refresh,
                method: HttpMethod::Post,
                endpoint: "https://example.com/refresh",
                outcome: TransitionOutcome::RefreshSucceeded,
                issued_credential: Some(credential(CRED_1, 1, 20_000)),
                occurred_at_millis: 3_000,
                dependencies: std::slice::from_ref(&login_step),
            })
            .is_err());
        assert_eq!(
            graph.add_request(SessionRequestTransition {
                from_state: &authenticated,
                kind: SessionRequestKind::Navigation,
                method: HttpMethod::Get,
                endpoint: "https://example.com/account",
                outcome: TransitionOutcome::Unchanged,
                issued_credential: None,
                occurred_at_millis: 11_000,
                dependencies: std::slice::from_ref(&login_step),
            }),
            Err(SessionGraphError::CredentialExpired)
        );
    }

    #[test]
    fn expire_clears_credential_and_rejects_invalid_phase() {
        let (mut graph, anonymous) =
            SessionFlowGraph::new(FLOW, PRINCIPAL, 1_000, SessionGraphLimits::default()).unwrap();
        assert!(graph.expire_state(&anonymous, 2_000).is_err());
        let (login_step, authenticated) = graph
            .add_request(SessionRequestTransition {
                from_state: &anonymous,
                kind: SessionRequestKind::Login,
                method: HttpMethod::Post,
                endpoint: "https://example.com/login",
                outcome: TransitionOutcome::LoginSucceeded,
                issued_credential: Some(credential(CRED_1, 1, 10_000)),
                occurred_at_millis: 2_000,
                dependencies: &[],
            })
            .unwrap();
        let expired = graph.expire_state(&authenticated, 10_000).unwrap();
        assert_eq!(graph.state(&expired).unwrap().phase, SessionPhase::Expired);
        assert!(graph.state(&expired).unwrap().credential.is_none());
        assert_eq!(
            graph.state(&expired).unwrap().created_by_step.as_ref(),
            Some(&login_step)
        );
    }

    #[test]
    fn ready_steps_respect_dependencies() {
        let (mut graph, anonymous) =
            SessionFlowGraph::new(FLOW, PRINCIPAL, 1_000, SessionGraphLimits::default()).unwrap();
        let (login_step, authenticated) = graph
            .add_request(SessionRequestTransition {
                from_state: &anonymous,
                kind: SessionRequestKind::Login,
                method: HttpMethod::Post,
                endpoint: "https://example.com/login",
                outcome: TransitionOutcome::LoginSucceeded,
                issued_credential: Some(credential(CRED_1, 1, 10_000)),
                occurred_at_millis: 2_000,
                dependencies: &[],
            })
            .unwrap();
        let (navigation_step, _state) = graph
            .add_request(SessionRequestTransition {
                from_state: &authenticated,
                kind: SessionRequestKind::Navigation,
                method: HttpMethod::Get,
                endpoint: "https://example.com/account",
                outcome: TransitionOutcome::Unchanged,
                issued_credential: None,
                occurred_at_millis: 3_000,
                dependencies: std::slice::from_ref(&login_step),
            })
            .unwrap();
        assert_eq!(
            graph.ready_steps(&BTreeSet::new()),
            std::slice::from_ref(&login_step)
        );
        let completed = BTreeSet::from([login_step]);
        assert_eq!(graph.ready_steps(&completed), [navigation_step]);
    }

    #[test]
    fn references_methods_and_limits_fail_closed() {
        assert!(SessionFlowGraph::new(
            "flow_secret",
            PRINCIPAL,
            1_000,
            SessionGraphLimits::default()
        )
        .is_err());
        assert!(CredentialReference::new(
            "raw-session-cookie",
            SessionCredentialKind::Cookie,
            1,
            None
        )
        .is_err());
        assert!(CredentialReference::new(
            "credref_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            SessionCredentialKind::Bearer,
            1,
            None
        )
        .is_err());
        assert!(SessionFlowGraph::new(
            FLOW,
            PRINCIPAL,
            1_000,
            SessionGraphLimits {
                max_states: 0,
                ..SessionGraphLimits::default()
            }
        )
        .is_err());
    }
}
