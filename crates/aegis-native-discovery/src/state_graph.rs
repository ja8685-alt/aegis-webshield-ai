use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};

use sha2::{Digest, Sha256};

use crate::{CanonicalUrl, GraphqlOperationKind};

const ENDPOINT_ID_VERSION: &str = "aegis.endpoint.v1";
const HARD_MAX_NODES: usize = 2_000;
const HARD_MAX_EDGES: usize = 8_000;
const HARD_MAX_EVENTS: usize = 20_000;
const MAX_GRAPHQL_FIELD_BYTES: usize = 128;
const MAX_FINDINGS_PER_ENDPOINT: u16 = 1_000;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SurfaceHttpMethod {
    Get,
    Head,
    Options,
    Post,
    Put,
    Patch,
    Delete,
    Trace,
}

impl SurfaceHttpMethod {
    fn name(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Trace => "TRACE",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndpointIdentity {
    Http {
        method: SurfaceHttpMethod,
        url: CanonicalUrl,
    },
    Graphql {
        endpoint: CanonicalUrl,
        kind: GraphqlOperationKind,
        field: String,
    },
}

impl EndpointIdentity {
    pub fn http(method: SurfaceHttpMethod, url: CanonicalUrl) -> Self {
        Self::Http { method, url }
    }

    pub fn graphql(
        endpoint: CanonicalUrl,
        kind: GraphqlOperationKind,
        field: impl Into<String>,
    ) -> Result<Self, EndpointGraphError> {
        let field = field.into();
        validate_graphql_field(&field)?;
        Ok(Self::Graphql {
            endpoint,
            kind,
            field,
        })
    }

    fn fingerprint_material(&self) -> String {
        match self {
            Self::Http { method, url } => {
                format!("http\0{}\0{}", method.name(), url.dedup_key())
            }
            Self::Graphql {
                endpoint,
                kind,
                field,
            } => format!(
                "graphql\0{}\0{}\0{}",
                endpoint.dedup_key(),
                graphql_kind_name(*kind),
                field
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EndpointId(String);

impl EndpointId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn from_identity(identity: &EndpointIdentity) -> Self {
        let mut digest = Sha256::new();
        digest.update(ENDPOINT_ID_VERSION.as_bytes());
        digest.update([0]);
        digest.update(identity.fingerprint_material().as_bytes());
        Self(hex_encode(&digest.finalize()))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EndpointSourceKind {
    Seed,
    HtmlLink,
    HtmlForm,
    JavaScript,
    StaticAsset,
    OpenApi,
    GraphqlIntrospection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointAuthState {
    Unknown,
    Public,
    CredentialRequired,
    CredentialReady,
    PublicAndAuthenticated,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CoverageReason {
    AuthenticationUnavailable,
    RouteParametersUnbound,
    DestructiveMethod,
    UnsupportedMethod,
    DynamicTemplate,
    IntrospectionNotApproved,
    UserExcluded,
    BudgetExhausted,
    Cancelled,
    NetworkFailure,
    ResponseLimit,
    ParseLimit,
    RuleNotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VisitState {
    Discovered,
    Queued,
    Visited,
    Skipped(CoverageReason),
    Failed(CoverageReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestState {
    Pending,
    Tested { finding_count: u16 },
    NotTested(CoverageReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointNode {
    pub id: EndpointId,
    pub identity: EndpointIdentity,
    pub sources: BTreeSet<EndpointSourceKind>,
    pub auth_state: EndpointAuthState,
    pub visit_state: VisitState,
    pub test_state: TestState,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DiscoveryEdge {
    pub from: Option<EndpointId>,
    pub to: EndpointId,
    pub source: EndpointSourceKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageTransition {
    Discovered,
    Queued,
    Visited,
    VisitSkipped,
    VisitFailed,
    Tested,
    NotTested,
    AuthStateChanged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageEvent {
    pub sequence: u64,
    pub endpoint_id: EndpointId,
    pub transition: CoverageTransition,
    pub reason: Option<CoverageReason>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CoverageSummary {
    pub total: usize,
    pub discovered: usize,
    pub queued: usize,
    pub visited: usize,
    pub visit_skipped: usize,
    pub visit_failed: usize,
    pub test_pending: usize,
    pub tested: usize,
    pub not_tested: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointGraphLimits {
    pub max_nodes: usize,
    pub max_edges: usize,
    pub max_events: usize,
}

impl Default for EndpointGraphLimits {
    fn default() -> Self {
        Self {
            max_nodes: HARD_MAX_NODES,
            max_edges: HARD_MAX_EDGES,
            max_events: HARD_MAX_EVENTS,
        }
    }
}

impl EndpointGraphLimits {
    fn validate(&self) -> Result<(), EndpointGraphError> {
        if self.max_nodes == 0
            || self.max_nodes > HARD_MAX_NODES
            || self.max_edges == 0
            || self.max_edges > HARD_MAX_EDGES
            || self.max_events == 0
            || self.max_events > HARD_MAX_EVENTS
        {
            return Err(EndpointGraphError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointGraphError {
    InvalidLimits,
    InvalidIdentity,
    EndpointLimitExceeded,
    EdgeLimitExceeded,
    EventLimitExceeded,
    EndpointNotFound,
    ParentNotFound,
    InvalidTransition,
    InvalidFindingCount,
    IntegrityViolation,
}

impl Display for EndpointGraphError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "endpoint graph limits are invalid",
            Self::InvalidIdentity => "endpoint identity is invalid",
            Self::EndpointLimitExceeded => "endpoint graph node limit exceeded",
            Self::EdgeLimitExceeded => "endpoint graph edge limit exceeded",
            Self::EventLimitExceeded => "endpoint coverage event limit exceeded",
            Self::EndpointNotFound => "endpoint was not found",
            Self::ParentNotFound => "discovery parent endpoint was not found",
            Self::InvalidTransition => "endpoint state transition is invalid",
            Self::InvalidFindingCount => "endpoint finding count is invalid",
            Self::IntegrityViolation => "endpoint graph integrity validation failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for EndpointGraphError {}

pub struct EndpointStateGraph {
    limits: EndpointGraphLimits,
    nodes: BTreeMap<EndpointId, EndpointNode>,
    edges: BTreeSet<DiscoveryEdge>,
    events: Vec<CoverageEvent>,
    next_sequence: u64,
}

impl EndpointStateGraph {
    pub fn new(limits: EndpointGraphLimits) -> Result<Self, EndpointGraphError> {
        limits.validate()?;
        Ok(Self {
            limits,
            nodes: BTreeMap::new(),
            edges: BTreeSet::new(),
            events: Vec::new(),
            next_sequence: 1,
        })
    }

    pub fn upsert(
        &mut self,
        identity: EndpointIdentity,
        source: EndpointSourceKind,
        auth_state: EndpointAuthState,
        parent: Option<&EndpointId>,
    ) -> Result<EndpointId, EndpointGraphError> {
        if let Some(parent) = parent {
            if !self.nodes.contains_key(parent) {
                return Err(EndpointGraphError::ParentNotFound);
            }
        }
        let id = EndpointId::from_identity(&identity);
        let is_new = !self.nodes.contains_key(&id);
        let mut auth_changed = false;
        let edge = DiscoveryEdge {
            from: parent.cloned(),
            to: id.clone(),
            source,
        };
        if !self.edges.contains(&edge) && self.edges.len() >= self.limits.max_edges {
            return Err(EndpointGraphError::EdgeLimitExceeded);
        }
        if is_new && self.nodes.len() >= self.limits.max_nodes {
            return Err(EndpointGraphError::EndpointLimitExceeded);
        }
        if is_new {
            self.ensure_event_capacity(1)?;
            let mut sources = BTreeSet::new();
            sources.insert(source);
            self.nodes.insert(
                id.clone(),
                EndpointNode {
                    id: id.clone(),
                    identity,
                    sources,
                    auth_state,
                    visit_state: VisitState::Discovered,
                    test_state: TestState::Pending,
                },
            );
            self.record_event(&id, CoverageTransition::Discovered, None)?;
        } else {
            let existing = self
                .nodes
                .get(&id)
                .ok_or(EndpointGraphError::IntegrityViolation)?;
            if existing.identity.fingerprint_material() != identity.fingerprint_material() {
                return Err(EndpointGraphError::IntegrityViolation);
            }
            let merged_auth = merge_auth_state(existing.auth_state, auth_state);
            auth_changed = merged_auth != existing.auth_state;
            if auth_changed {
                self.ensure_event_capacity(1)?;
            }
            let node = self
                .nodes
                .get_mut(&id)
                .ok_or(EndpointGraphError::IntegrityViolation)?;
            node.sources.insert(source);
            node.auth_state = merged_auth;
        }
        self.edges.insert(edge);
        if auth_changed {
            self.record_event(&id, CoverageTransition::AuthStateChanged, None)?;
        }
        Ok(id)
    }

    pub fn set_auth_state(
        &mut self,
        id: &EndpointId,
        auth_state: EndpointAuthState,
    ) -> Result<(), EndpointGraphError> {
        let current = self
            .nodes
            .get(id)
            .ok_or(EndpointGraphError::EndpointNotFound)?
            .auth_state;
        let merged = merge_auth_state(current, auth_state);
        if merged != current {
            self.ensure_event_capacity(1)?;
            self.nodes
                .get_mut(id)
                .ok_or(EndpointGraphError::EndpointNotFound)?
                .auth_state = merged;
            self.record_event(id, CoverageTransition::AuthStateChanged, None)?;
        }
        Ok(())
    }

    pub fn queue(&mut self, id: &EndpointId) -> Result<(), EndpointGraphError> {
        match self
            .nodes
            .get(id)
            .ok_or(EndpointGraphError::EndpointNotFound)?
            .visit_state
        {
            VisitState::Discovered => {}
            VisitState::Queued => return Ok(()),
            _ => return Err(EndpointGraphError::InvalidTransition),
        }
        self.ensure_event_capacity(1)?;
        self.node_mut(id)?.visit_state = VisitState::Queued;
        self.record_event(id, CoverageTransition::Queued, None)
    }

    pub fn mark_visited(&mut self, id: &EndpointId) -> Result<(), EndpointGraphError> {
        if self
            .nodes
            .get(id)
            .ok_or(EndpointGraphError::EndpointNotFound)?
            .visit_state
            != VisitState::Queued
        {
            return Err(EndpointGraphError::InvalidTransition);
        }
        self.ensure_event_capacity(1)?;
        self.node_mut(id)?.visit_state = VisitState::Visited;
        self.record_event(id, CoverageTransition::Visited, None)
    }

    pub fn mark_visit_skipped(
        &mut self,
        id: &EndpointId,
        reason: CoverageReason,
    ) -> Result<(), EndpointGraphError> {
        self.finish_visit_without_test(id, reason, true)
    }

    pub fn mark_visit_failed(
        &mut self,
        id: &EndpointId,
        reason: CoverageReason,
    ) -> Result<(), EndpointGraphError> {
        self.finish_visit_without_test(id, reason, false)
    }

    pub fn mark_tested(
        &mut self,
        id: &EndpointId,
        finding_count: u16,
    ) -> Result<(), EndpointGraphError> {
        if finding_count > MAX_FINDINGS_PER_ENDPOINT {
            return Err(EndpointGraphError::InvalidFindingCount);
        }
        let node = self
            .nodes
            .get(id)
            .ok_or(EndpointGraphError::EndpointNotFound)?;
        if node.visit_state != VisitState::Visited || node.test_state != TestState::Pending {
            return Err(EndpointGraphError::InvalidTransition);
        }
        self.ensure_event_capacity(1)?;
        self.node_mut(id)?.test_state = TestState::Tested { finding_count };
        self.record_event(id, CoverageTransition::Tested, None)
    }

    pub fn mark_not_tested(
        &mut self,
        id: &EndpointId,
        reason: CoverageReason,
    ) -> Result<(), EndpointGraphError> {
        if self
            .nodes
            .get(id)
            .ok_or(EndpointGraphError::EndpointNotFound)?
            .test_state
            != TestState::Pending
        {
            return Err(EndpointGraphError::InvalidTransition);
        }
        self.ensure_event_capacity(1)?;
        self.node_mut(id)?.test_state = TestState::NotTested(reason);
        self.record_event(id, CoverageTransition::NotTested, Some(reason))
    }

    pub fn node(&self, id: &EndpointId) -> Option<&EndpointNode> {
        self.nodes.get(id)
    }

    pub fn nodes(&self) -> impl Iterator<Item = &EndpointNode> {
        self.nodes.values()
    }

    pub fn edges(&self) -> impl Iterator<Item = &DiscoveryEdge> {
        self.edges.iter()
    }

    pub fn events(&self) -> &[CoverageEvent] {
        &self.events
    }

    pub fn summary(&self) -> CoverageSummary {
        let mut summary = CoverageSummary {
            total: self.nodes.len(),
            ..CoverageSummary::default()
        };
        for node in self.nodes.values() {
            match node.visit_state {
                VisitState::Discovered => summary.discovered += 1,
                VisitState::Queued => summary.queued += 1,
                VisitState::Visited => summary.visited += 1,
                VisitState::Skipped(_) => summary.visit_skipped += 1,
                VisitState::Failed(_) => summary.visit_failed += 1,
            }
            match node.test_state {
                TestState::Pending => summary.test_pending += 1,
                TestState::Tested { .. } => summary.tested += 1,
                TestState::NotTested(_) => summary.not_tested += 1,
            }
        }
        summary
    }

    pub fn validate(&self) -> Result<(), EndpointGraphError> {
        if self.nodes.len() > self.limits.max_nodes
            || self.edges.len() > self.limits.max_edges
            || self.events.len() > self.limits.max_events
        {
            return Err(EndpointGraphError::IntegrityViolation);
        }
        for (id, node) in &self.nodes {
            if id != &node.id || id != &EndpointId::from_identity(&node.identity) {
                return Err(EndpointGraphError::IntegrityViolation);
            }
        }
        for edge in &self.edges {
            if !self.nodes.contains_key(&edge.to)
                || edge
                    .from
                    .as_ref()
                    .is_some_and(|from| !self.nodes.contains_key(from))
            {
                return Err(EndpointGraphError::IntegrityViolation);
            }
        }
        let mut expected_sequence = 1u64;
        for event in &self.events {
            if event.sequence != expected_sequence || !self.nodes.contains_key(&event.endpoint_id) {
                return Err(EndpointGraphError::IntegrityViolation);
            }
            expected_sequence += 1;
        }
        if self.next_sequence != expected_sequence {
            return Err(EndpointGraphError::IntegrityViolation);
        }
        Ok(())
    }

    fn node_mut(&mut self, id: &EndpointId) -> Result<&mut EndpointNode, EndpointGraphError> {
        self.nodes
            .get_mut(id)
            .ok_or(EndpointGraphError::EndpointNotFound)
    }

    fn finish_visit_without_test(
        &mut self,
        id: &EndpointId,
        reason: CoverageReason,
        skipped: bool,
    ) -> Result<(), EndpointGraphError> {
        let node = self
            .nodes
            .get(id)
            .ok_or(EndpointGraphError::EndpointNotFound)?;
        if !matches!(
            node.visit_state,
            VisitState::Discovered | VisitState::Queued
        ) || node.test_state != TestState::Pending
        {
            return Err(EndpointGraphError::InvalidTransition);
        }
        self.ensure_event_capacity(2)?;
        let node = self.node_mut(id)?;
        node.visit_state = if skipped {
            VisitState::Skipped(reason)
        } else {
            VisitState::Failed(reason)
        };
        node.test_state = TestState::NotTested(reason);
        self.record_event(
            id,
            if skipped {
                CoverageTransition::VisitSkipped
            } else {
                CoverageTransition::VisitFailed
            },
            Some(reason),
        )?;
        self.record_event(id, CoverageTransition::NotTested, Some(reason))
    }

    fn record_event(
        &mut self,
        endpoint_id: &EndpointId,
        transition: CoverageTransition,
        reason: Option<CoverageReason>,
    ) -> Result<(), EndpointGraphError> {
        if self.events.len() >= self.limits.max_events {
            return Err(EndpointGraphError::EventLimitExceeded);
        }
        self.events.push(CoverageEvent {
            sequence: self.next_sequence,
            endpoint_id: endpoint_id.clone(),
            transition,
            reason,
        });
        self.next_sequence += 1;
        Ok(())
    }

    fn ensure_event_capacity(&self, additional: usize) -> Result<(), EndpointGraphError> {
        if self.events.len().saturating_add(additional) > self.limits.max_events {
            return Err(EndpointGraphError::EventLimitExceeded);
        }
        Ok(())
    }
}

fn merge_auth_state(current: EndpointAuthState, incoming: EndpointAuthState) -> EndpointAuthState {
    use EndpointAuthState::{
        CredentialReady, CredentialRequired, Public, PublicAndAuthenticated, Unknown,
    };
    match (current, incoming) {
        (value, Unknown) | (Unknown, value) => value,
        (PublicAndAuthenticated, _) | (_, PublicAndAuthenticated) => PublicAndAuthenticated,
        (Public, CredentialRequired | CredentialReady)
        | (CredentialRequired | CredentialReady, Public) => PublicAndAuthenticated,
        (CredentialRequired, CredentialReady) | (CredentialReady, CredentialRequired) => {
            CredentialReady
        }
        (left, right) if left == right => left,
        (left, _) => left,
    }
}

fn validate_graphql_field(value: &str) -> Result<(), EndpointGraphError> {
    let mut bytes = value.bytes();
    if value.is_empty()
        || value.len() > MAX_GRAPHQL_FIELD_BYTES
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(EndpointGraphError::InvalidIdentity);
    }
    Ok(())
}

fn graphql_kind_name(kind: GraphqlOperationKind) -> &'static str {
    match kind {
        GraphqlOperationKind::Query => "query",
        GraphqlOperationKind::Mutation => "mutation",
        GraphqlOperationKind::Subscription => "subscription",
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use aegis_native_engine::ApprovedTarget;

    use super::{
        CoverageReason, EndpointAuthState, EndpointGraphError, EndpointGraphLimits,
        EndpointIdentity, EndpointSourceKind, EndpointStateGraph, SurfaceHttpMethod, TestState,
        VisitState,
    };
    use crate::{canonicalize_url, CanonicalizationOutcome};

    fn canonical(raw: &str) -> crate::CanonicalUrl {
        let target = ApprovedTarget::new("target-1", "https://example.com", "/app").unwrap();
        let CanonicalizationOutcome::Accepted(url) =
            canonicalize_url(&target, "https://example.com/app/", raw).unwrap()
        else {
            panic!("fixture URL must be accepted");
        };
        url
    }

    fn graph() -> EndpointStateGraph {
        EndpointStateGraph::new(EndpointGraphLimits::default()).unwrap()
    }

    #[test]
    fn deduplicates_query_order_and_merges_sources_and_auth_state() {
        let mut graph = graph();
        let first = graph
            .upsert(
                EndpointIdentity::http(SurfaceHttpMethod::Get, canonical("/app/users?b=2&a=1")),
                EndpointSourceKind::HtmlLink,
                EndpointAuthState::Public,
                None,
            )
            .unwrap();
        let second = graph
            .upsert(
                EndpointIdentity::http(SurfaceHttpMethod::Get, canonical("/app/users?a=1&b=2")),
                EndpointSourceKind::OpenApi,
                EndpointAuthState::CredentialReady,
                None,
            )
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(graph.summary().total, 1);
        let node = graph.node(&first).unwrap();
        assert_eq!(node.sources.len(), 2);
        assert_eq!(node.auth_state, EndpointAuthState::PublicAndAuthenticated);
        assert_eq!(graph.edges().count(), 2);
        graph.validate().unwrap();
    }

    #[test]
    fn method_is_part_of_endpoint_identity() {
        let mut graph = graph();
        let get = graph
            .upsert(
                EndpointIdentity::http(SurfaceHttpMethod::Get, canonical("/app/users")),
                EndpointSourceKind::HtmlLink,
                EndpointAuthState::Unknown,
                None,
            )
            .unwrap();
        let post = graph
            .upsert(
                EndpointIdentity::http(SurfaceHttpMethod::Post, canonical("/app/users")),
                EndpointSourceKind::HtmlForm,
                EndpointAuthState::Unknown,
                Some(&get),
            )
            .unwrap();
        assert_ne!(get, post);
        assert_eq!(graph.summary().total, 2);
        assert_eq!(graph.edges().filter(|edge| edge.from.is_some()).count(), 1);
    }

    #[test]
    fn visit_and_test_transitions_produce_coverage_ledger() {
        let mut graph = graph();
        let tested = graph
            .upsert(
                EndpointIdentity::http(SurfaceHttpMethod::Get, canonical("/app/health")),
                EndpointSourceKind::Seed,
                EndpointAuthState::Public,
                None,
            )
            .unwrap();
        graph.queue(&tested).unwrap();
        graph.mark_visited(&tested).unwrap();
        graph.mark_tested(&tested, 2).unwrap();

        let skipped = graph
            .upsert(
                EndpointIdentity::http(SurfaceHttpMethod::Delete, canonical("/app/users/1")),
                EndpointSourceKind::OpenApi,
                EndpointAuthState::CredentialRequired,
                None,
            )
            .unwrap();
        graph
            .mark_visit_skipped(&skipped, CoverageReason::DestructiveMethod)
            .unwrap();

        let summary = graph.summary();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.visited, 1);
        assert_eq!(summary.tested, 1);
        assert_eq!(summary.visit_skipped, 1);
        assert_eq!(summary.not_tested, 1);
        assert_eq!(
            graph.node(&tested).unwrap().test_state,
            TestState::Tested { finding_count: 2 }
        );
        assert_eq!(
            graph.node(&skipped).unwrap().visit_state,
            VisitState::Skipped(CoverageReason::DestructiveMethod)
        );
        assert!(graph
            .events()
            .iter()
            .all(|event| !format!("{event:?}").contains("example.com")));
        graph.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_transitions_and_missing_parent() {
        let mut graph = graph();
        let id = graph
            .upsert(
                EndpointIdentity::http(SurfaceHttpMethod::Get, canonical("/app/one")),
                EndpointSourceKind::Seed,
                EndpointAuthState::Public,
                None,
            )
            .unwrap();
        assert_eq!(
            graph.mark_visited(&id),
            Err(EndpointGraphError::InvalidTransition)
        );
        let missing = super::EndpointId("0".repeat(64));
        assert_eq!(
            graph.upsert(
                EndpointIdentity::http(SurfaceHttpMethod::Get, canonical("/app/two")),
                EndpointSourceKind::HtmlLink,
                EndpointAuthState::Unknown,
                Some(&missing),
            ),
            Err(EndpointGraphError::ParentNotFound)
        );
    }

    #[test]
    fn enforces_node_limit_without_partial_insert() {
        let limits = EndpointGraphLimits {
            max_nodes: 1,
            max_edges: 2,
            max_events: 4,
        };
        let mut graph = EndpointStateGraph::new(limits).unwrap();
        graph
            .upsert(
                EndpointIdentity::http(SurfaceHttpMethod::Get, canonical("/app/one")),
                EndpointSourceKind::Seed,
                EndpointAuthState::Public,
                None,
            )
            .unwrap();
        assert_eq!(
            graph.upsert(
                EndpointIdentity::http(SurfaceHttpMethod::Get, canonical("/app/two")),
                EndpointSourceKind::Seed,
                EndpointAuthState::Public,
                None,
            ),
            Err(EndpointGraphError::EndpointLimitExceeded)
        );
        assert_eq!(graph.summary().total, 1);
        graph.validate().unwrap();
    }

    #[test]
    fn event_and_edge_limit_failures_leave_state_unchanged() {
        let limits = EndpointGraphLimits {
            max_nodes: 2,
            max_edges: 1,
            max_events: 1,
        };
        let mut graph = EndpointStateGraph::new(limits).unwrap();
        let id = graph
            .upsert(
                EndpointIdentity::http(SurfaceHttpMethod::Get, canonical("/app/one")),
                EndpointSourceKind::Seed,
                EndpointAuthState::Public,
                None,
            )
            .unwrap();
        assert_eq!(
            graph.queue(&id),
            Err(EndpointGraphError::EventLimitExceeded)
        );
        assert_eq!(graph.node(&id).unwrap().visit_state, VisitState::Discovered);
        assert_eq!(
            graph.upsert(
                EndpointIdentity::http(SurfaceHttpMethod::Get, canonical("/app/one")),
                EndpointSourceKind::OpenApi,
                EndpointAuthState::CredentialReady,
                None,
            ),
            Err(EndpointGraphError::EdgeLimitExceeded)
        );
        let node = graph.node(&id).unwrap();
        assert_eq!(node.sources.len(), 1);
        assert_eq!(node.auth_state, EndpointAuthState::Public);
        graph.validate().unwrap();
    }
}
