use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Display, Formatter};

use aegis_native_engine::{FindingIdentity, HttpMethod, ParameterLocation};

const ACTION_PREFIX: &str = "action_";
const HARD_MAX_ACTIONS: usize = 64;
const HARD_MAX_EXECUTIONS_PER_ACTION: usize = 3;
const HARD_MAX_EXECUTIONS: usize = HARD_MAX_ACTIONS * HARD_MAX_EXECUTIONS_PER_ACTION;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StateActionKind {
    ReadOnlyObservation,
    SessionLogin,
    SessionLogout,
    SessionRefresh,
    InertStateProbe,
    AccountOrPermissionChange,
    PurchaseOrPayment,
    MessageOrEmailSend,
    DataDelete,
    FileUploadOrExecution,
    UnknownStateChange,
}

impl StateActionKind {
    fn is_forbidden(self) -> bool {
        matches!(
            self,
            Self::AccountOrPermissionChange
                | Self::PurchaseOrPayment
                | Self::MessageOrEmailSend
                | Self::DataDelete
                | Self::FileUploadOrExecution
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionClassificationSource {
    OpenApiOperation,
    ObservedRequest,
    OperatorVerified,
    UrlHeuristic,
}

impl ActionClassificationSource {
    fn is_strong(self) -> bool {
        !matches!(self, Self::UrlHeuristic)
    }
}

pub struct StateActionDescriptor<'a> {
    pub action_ref: &'a str,
    pub target_id: &'a str,
    pub endpoint: &'a str,
    pub method: HttpMethod,
    pub kind: StateActionKind,
    pub classification_source: ActionClassificationSource,
    pub request_fingerprint: &'a str,
    pub classification_evidence_ref: &'a str,
    pub max_executions: usize,
    pub synthetic_test_context: bool,
    pub non_destructive_contract: bool,
    pub payload_is_inert: bool,
    pub explicitly_approved: bool,
}

impl Debug for StateActionDescriptor<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StateActionDescriptor")
            .field("action_ref_bytes", &self.action_ref.len())
            .field("endpoint_bytes", &self.endpoint.len())
            .field("method", &self.method)
            .field("kind", &self.kind)
            .field("classification_source", &self.classification_source)
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("max_executions", &self.max_executions)
            .field("synthetic_test_context", &self.synthetic_test_context)
            .field("non_destructive_contract", &self.non_destructive_contract)
            .field("payload_is_inert", &self.payload_is_inert)
            .field("explicitly_approved", &self.explicitly_approved)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateSafetyLimits {
    pub max_actions: usize,
    pub max_executions_per_action: usize,
    pub max_executions: usize,
}

impl Default for StateSafetyLimits {
    fn default() -> Self {
        Self {
            max_actions: HARD_MAX_ACTIONS,
            max_executions_per_action: HARD_MAX_EXECUTIONS_PER_ACTION,
            max_executions: HARD_MAX_EXECUTIONS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateSafetyRuntimeError {
    InvalidLimits,
    InvalidAction,
    DuplicateAction,
    ExecutionBudgetExceeded,
    InvalidReceipt,
    DuplicateReceipt,
    UnpermittedExecution,
}

impl Display for StateSafetyRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "state safety limits are invalid",
            Self::InvalidAction => "state action descriptor is invalid",
            Self::DuplicateAction => "state action descriptor is duplicated",
            Self::ExecutionBudgetExceeded => "state action execution budget was exceeded",
            Self::InvalidReceipt => "state action execution receipt is invalid",
            Self::DuplicateReceipt => "state action execution receipt is duplicated",
            Self::UnpermittedExecution => "state action execution has no safety permit",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for StateSafetyRuntimeError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateActionVerdict {
    Permitted,
    Blocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateBlockReason {
    ForbiddenSemantic,
    UnknownStateChange,
    WeakClassification,
    MissingExplicitApproval,
    NonSyntheticContext,
    MissingNonDestructiveContract,
    NonInertPostPayload,
    MethodKindMismatch,
}

#[derive(Clone, Eq, PartialEq)]
pub struct StateActionRecord {
    action_ref: String,
    pub method: HttpMethod,
    pub kind: StateActionKind,
    pub verdict: StateActionVerdict,
    pub block_reason: Option<StateBlockReason>,
    classification_evidence_ref: String,
}

impl StateActionRecord {
    pub fn action_ref(&self) -> &str {
        &self.action_ref
    }

    pub fn classification_evidence_ref(&self) -> &str {
        &self.classification_evidence_ref
    }
}

impl Debug for StateActionRecord {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StateActionRecord")
            .field("action_ref_bytes", &self.action_ref.len())
            .field("method", &self.method)
            .field("kind", &self.kind)
            .field("verdict", &self.verdict)
            .field("block_reason", &self.block_reason)
            .field(
                "classification_evidence_ref_bytes",
                &self.classification_evidence_ref.len(),
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StateActionPermit {
    action_ref: String,
    canonical_endpoint: String,
    method: HttpMethod,
    kind: StateActionKind,
    request_fingerprint: String,
    max_executions: usize,
}

impl StateActionPermit {
    pub fn action_ref(&self) -> &str {
        &self.action_ref
    }

    pub fn canonical_endpoint(&self) -> &str {
        &self.canonical_endpoint
    }

    pub fn method(&self) -> HttpMethod {
        self.method
    }

    pub fn kind(&self) -> StateActionKind {
        self.kind
    }

    pub fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }

    pub fn max_executions(&self) -> usize {
        self.max_executions
    }
}

impl Debug for StateActionPermit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StateActionPermit")
            .field("action_ref_bytes", &self.action_ref.len())
            .field("canonical_endpoint_bytes", &self.canonical_endpoint.len())
            .field("method", &self.method)
            .field("kind", &self.kind)
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("max_executions", &self.max_executions)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StateSafetyReport {
    records: Vec<StateActionRecord>,
    permits: Vec<StateActionPermit>,
    execution_budget: usize,
}

impl StateSafetyReport {
    pub fn records(&self) -> &[StateActionRecord] {
        &self.records
    }

    pub fn permits(&self) -> &[StateActionPermit] {
        &self.permits
    }

    pub fn execution_budget(&self) -> usize {
        self.execution_budget
    }

    pub fn blocked_action_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.verdict == StateActionVerdict::Blocked)
            .count()
    }

    pub fn forbidden_permit_count(&self) -> usize {
        self.permits
            .iter()
            .filter(|permit| permit.kind.is_forbidden())
            .count()
    }
}

impl Debug for StateSafetyReport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StateSafetyReport")
            .field("record_count", &self.records.len())
            .field("permit_count", &self.permits.len())
            .field("blocked_action_count", &self.blocked_action_count())
            .field("execution_budget", &self.execution_budget)
            .field("forbidden_permit_count", &self.forbidden_permit_count())
            .finish()
    }
}

pub struct StateExecutionReceipt<'a> {
    pub action_ref: &'a str,
    pub method: HttpMethod,
    pub request_fingerprint: &'a str,
    pub repetition: usize,
    pub evidence_ref: &'a str,
}

impl Debug for StateExecutionReceipt<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StateExecutionReceipt")
            .field("action_ref_bytes", &self.action_ref.len())
            .field("method", &self.method)
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("repetition", &self.repetition)
            .field("evidence_ref_bytes", &self.evidence_ref.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StateSafetyQaEvidence {
    planned_action_count: usize,
    permitted_action_count: usize,
    blocked_action_count: usize,
    executed_request_count: usize,
    destructive_execution_count: usize,
    blocked_evidence_refs: Vec<String>,
    execution_evidence_refs: Vec<String>,
}

impl StateSafetyQaEvidence {
    pub fn planned_action_count(&self) -> usize {
        self.planned_action_count
    }

    pub fn permitted_action_count(&self) -> usize {
        self.permitted_action_count
    }

    pub fn blocked_action_count(&self) -> usize {
        self.blocked_action_count
    }

    pub fn executed_request_count(&self) -> usize {
        self.executed_request_count
    }

    pub fn destructive_execution_count(&self) -> usize {
        self.destructive_execution_count
    }

    pub fn blocked_evidence_refs(&self) -> &[String] {
        &self.blocked_evidence_refs
    }

    pub fn execution_evidence_refs(&self) -> &[String] {
        &self.execution_evidence_refs
    }
}

impl Debug for StateSafetyQaEvidence {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StateSafetyQaEvidence")
            .field("planned_action_count", &self.planned_action_count)
            .field("permitted_action_count", &self.permitted_action_count)
            .field("blocked_action_count", &self.blocked_action_count)
            .field("executed_request_count", &self.executed_request_count)
            .field(
                "destructive_execution_count",
                &self.destructive_execution_count,
            )
            .field(
                "blocked_evidence_ref_count",
                &self.blocked_evidence_refs.len(),
            )
            .field(
                "execution_evidence_ref_count",
                &self.execution_evidence_refs.len(),
            )
            .finish()
    }
}

pub fn evaluate_state_actions(
    actions: &[StateActionDescriptor<'_>],
    limits: StateSafetyLimits,
) -> Result<StateSafetyReport, StateSafetyRuntimeError> {
    validate_limits(limits)?;
    if actions.is_empty() || actions.len() > limits.max_actions {
        return Err(StateSafetyRuntimeError::InvalidAction);
    }
    let mut action_refs = BTreeSet::new();
    let mut records = Vec::with_capacity(actions.len());
    let mut permits = Vec::new();
    let mut execution_budget = 0usize;
    for action in actions {
        let identity = validate_action(action, limits)?;
        if !action_refs.insert(action.action_ref) {
            return Err(StateSafetyRuntimeError::DuplicateAction);
        }
        let block_reason = classify_block_reason(action);
        let verdict = if block_reason.is_some() {
            StateActionVerdict::Blocked
        } else {
            StateActionVerdict::Permitted
        };
        records.push(StateActionRecord {
            action_ref: action.action_ref.to_string(),
            method: action.method,
            kind: action.kind,
            verdict,
            block_reason,
            classification_evidence_ref: action.classification_evidence_ref.to_string(),
        });
        if verdict == StateActionVerdict::Permitted {
            execution_budget = execution_budget.saturating_add(action.max_executions);
            if execution_budget > limits.max_executions {
                return Err(StateSafetyRuntimeError::ExecutionBudgetExceeded);
            }
            permits.push(StateActionPermit {
                action_ref: action.action_ref.to_string(),
                canonical_endpoint: identity.canonical_endpoint,
                method: action.method,
                kind: action.kind,
                request_fingerprint: action.request_fingerprint.to_string(),
                max_executions: action.max_executions,
            });
        }
    }
    let report = StateSafetyReport {
        records,
        permits,
        execution_budget,
    };
    if report.forbidden_permit_count() != 0 {
        return Err(StateSafetyRuntimeError::InvalidAction);
    }
    Ok(report)
}

pub fn audit_state_executions(
    report: &StateSafetyReport,
    receipts: &[StateExecutionReceipt<'_>],
    limits: StateSafetyLimits,
) -> Result<StateSafetyQaEvidence, StateSafetyRuntimeError> {
    validate_limits(limits)?;
    if report.records.len() > limits.max_actions
        || report.execution_budget > limits.max_executions
        || receipts.len() > limits.max_executions
    {
        return Err(StateSafetyRuntimeError::ExecutionBudgetExceeded);
    }
    let permits = report
        .permits
        .iter()
        .map(|permit| (permit.action_ref.as_str(), permit))
        .collect::<BTreeMap<_, _>>();
    let blocked = report
        .records
        .iter()
        .filter(|record| record.verdict == StateActionVerdict::Blocked)
        .map(|record| record.action_ref.as_str())
        .collect::<BTreeSet<_>>();
    let mut receipt_keys = BTreeSet::new();
    let mut execution_evidence_refs = BTreeSet::new();
    for receipt in receipts {
        if blocked.contains(receipt.action_ref) {
            return Err(StateSafetyRuntimeError::UnpermittedExecution);
        }
        let permit = permits
            .get(receipt.action_ref)
            .ok_or(StateSafetyRuntimeError::UnpermittedExecution)?;
        if receipt.method != permit.method
            || receipt.request_fingerprint != permit.request_fingerprint
            || receipt.repetition == 0
            || receipt.repetition > permit.max_executions
            || !valid_evidence_ref(receipt.evidence_ref)
        {
            return Err(StateSafetyRuntimeError::InvalidReceipt);
        }
        if !receipt_keys.insert((receipt.action_ref, receipt.repetition)) {
            return Err(StateSafetyRuntimeError::DuplicateReceipt);
        }
        execution_evidence_refs.insert(receipt.evidence_ref);
    }
    if receipts.len() > report.execution_budget {
        return Err(StateSafetyRuntimeError::ExecutionBudgetExceeded);
    }
    let blocked_evidence_refs = report
        .records
        .iter()
        .filter(|record| record.verdict == StateActionVerdict::Blocked)
        .map(|record| record.classification_evidence_ref.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_string)
        .collect();
    Ok(StateSafetyQaEvidence {
        planned_action_count: report.records.len(),
        permitted_action_count: report.permits.len(),
        blocked_action_count: report.blocked_action_count(),
        executed_request_count: receipts.len(),
        destructive_execution_count: 0,
        blocked_evidence_refs,
        execution_evidence_refs: execution_evidence_refs
            .into_iter()
            .map(str::to_string)
            .collect(),
    })
}

fn validate_limits(limits: StateSafetyLimits) -> Result<(), StateSafetyRuntimeError> {
    if limits.max_actions == 0
        || limits.max_actions > HARD_MAX_ACTIONS
        || limits.max_executions_per_action == 0
        || limits.max_executions_per_action > HARD_MAX_EXECUTIONS_PER_ACTION
        || limits.max_executions == 0
        || limits.max_executions > HARD_MAX_EXECUTIONS
    {
        return Err(StateSafetyRuntimeError::InvalidLimits);
    }
    Ok(())
}

fn validate_action(
    action: &StateActionDescriptor<'_>,
    limits: StateSafetyLimits,
) -> Result<FindingIdentity, StateSafetyRuntimeError> {
    if !valid_prefixed_hash(action.action_ref, ACTION_PREFIX)
        || !valid_sha256(action.request_fingerprint)
        || !valid_evidence_ref(action.classification_evidence_ref)
        || action.max_executions == 0
        || action.max_executions > limits.max_executions_per_action
    {
        return Err(StateSafetyRuntimeError::InvalidAction);
    }
    FindingIdentity::new(
        action.target_id,
        action.method,
        action.endpoint,
        "CWE-841",
        ParameterLocation::None,
        None,
    )
    .map_err(|_| StateSafetyRuntimeError::InvalidAction)
}

fn classify_block_reason(action: &StateActionDescriptor<'_>) -> Option<StateBlockReason> {
    if action.kind.is_forbidden() {
        return Some(StateBlockReason::ForbiddenSemantic);
    }
    if action.kind == StateActionKind::UnknownStateChange {
        return Some(StateBlockReason::UnknownStateChange);
    }
    if !action.classification_source.is_strong() {
        return Some(StateBlockReason::WeakClassification);
    }
    if !action.explicitly_approved {
        return Some(StateBlockReason::MissingExplicitApproval);
    }
    if !action.synthetic_test_context {
        return Some(StateBlockReason::NonSyntheticContext);
    }
    if !action.non_destructive_contract {
        return Some(StateBlockReason::MissingNonDestructiveContract);
    }
    let method_matches = match action.kind {
        StateActionKind::ReadOnlyObservation => matches!(
            action.method,
            HttpMethod::Get | HttpMethod::Head | HttpMethod::Options
        ),
        StateActionKind::SessionLogin
        | StateActionKind::SessionLogout
        | StateActionKind::SessionRefresh => action.method == HttpMethod::Post,
        StateActionKind::InertStateProbe => {
            matches!(action.method, HttpMethod::Get | HttpMethod::Post)
        }
        _ => false,
    };
    if !method_matches {
        return Some(StateBlockReason::MethodKindMismatch);
    }
    if action.method == HttpMethod::Post
        && action.kind == StateActionKind::InertStateProbe
        && !action.payload_is_inert
    {
        return Some(StateBlockReason::NonInertPostPayload);
    }
    None
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

#[cfg(test)]
mod tests {
    use aegis_native_engine::HttpMethod;

    use super::{
        audit_state_executions, evaluate_state_actions, ActionClassificationSource,
        StateActionDescriptor, StateActionKind, StateActionVerdict, StateBlockReason,
        StateExecutionReceipt, StateSafetyLimits, StateSafetyRuntimeError,
    };

    const ACTION_A: &str = "action_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ACTION_B: &str = "action_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ACTION_C: &str = "action_cccccccccccccccccccccccccccccccc";
    const ACTION_D: &str = "action_dddddddddddddddddddddddddddddddd";
    const ACTION_E: &str = "action_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const REQUEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn action(
        action_ref: &'static str,
        method: HttpMethod,
        kind: StateActionKind,
    ) -> StateActionDescriptor<'static> {
        StateActionDescriptor {
            action_ref,
            target_id: "target-1",
            endpoint: "https://example.com/state-action?token=secret",
            method,
            kind,
            classification_source: ActionClassificationSource::ObservedRequest,
            request_fingerprint: REQUEST,
            classification_evidence_ref: "classification-evidence",
            max_executions: 2,
            synthetic_test_context: true,
            non_destructive_contract: true,
            payload_is_inert: true,
            explicitly_approved: true,
        }
    }

    #[test]
    fn payment_delete_send_permission_and_upload_never_receive_permits() {
        let actions = [
            action(
                ACTION_A,
                HttpMethod::Post,
                StateActionKind::PurchaseOrPayment,
            ),
            action(ACTION_B, HttpMethod::Post, StateActionKind::DataDelete),
            action(
                ACTION_C,
                HttpMethod::Post,
                StateActionKind::MessageOrEmailSend,
            ),
            action(
                ACTION_D,
                HttpMethod::Post,
                StateActionKind::AccountOrPermissionChange,
            ),
            action(
                ACTION_E,
                HttpMethod::Post,
                StateActionKind::FileUploadOrExecution,
            ),
        ];
        let report = evaluate_state_actions(&actions, StateSafetyLimits::default()).unwrap();
        assert!(report.permits().is_empty());
        assert_eq!(report.blocked_action_count(), 5);
        assert_eq!(report.forbidden_permit_count(), 0);
        assert!(report.records().iter().all(|record| {
            record.verdict == StateActionVerdict::Blocked
                && record.block_reason == Some(StateBlockReason::ForbiddenSemantic)
        }));
        let qa = audit_state_executions(&report, &[], StateSafetyLimits::default()).unwrap();
        assert_eq!(qa.blocked_action_count(), 5);
        assert_eq!(qa.executed_request_count(), 0);
        assert_eq!(qa.destructive_execution_count(), 0);
        assert_eq!(qa.blocked_evidence_refs().len(), 1);
    }

    #[test]
    fn approved_read_only_action_receives_bounded_permit_and_audits_receipts() {
        let actions = [action(
            ACTION_A,
            HttpMethod::Get,
            StateActionKind::ReadOnlyObservation,
        )];
        let report = evaluate_state_actions(&actions, StateSafetyLimits::default()).unwrap();
        assert_eq!(report.permits().len(), 1);
        assert_eq!(report.execution_budget(), 2);
        let permit = &report.permits()[0];
        assert!(!permit.canonical_endpoint().contains("secret"));
        let receipts = [
            StateExecutionReceipt {
                action_ref: permit.action_ref(),
                method: permit.method(),
                request_fingerprint: permit.request_fingerprint(),
                repetition: 1,
                evidence_ref: "execution-1",
            },
            StateExecutionReceipt {
                action_ref: permit.action_ref(),
                method: permit.method(),
                request_fingerprint: permit.request_fingerprint(),
                repetition: 2,
                evidence_ref: "execution-2",
            },
        ];
        let qa = audit_state_executions(&report, &receipts, StateSafetyLimits::default()).unwrap();
        assert_eq!(qa.planned_action_count(), 1);
        assert_eq!(qa.permitted_action_count(), 1);
        assert_eq!(qa.executed_request_count(), 2);
        assert_eq!(qa.destructive_execution_count(), 0);
        assert_eq!(qa.execution_evidence_refs().len(), 2);
    }

    #[test]
    fn session_lifecycle_posts_require_strong_synthetic_contract() {
        let actions = [
            action(ACTION_A, HttpMethod::Post, StateActionKind::SessionLogin),
            action(ACTION_B, HttpMethod::Post, StateActionKind::SessionLogout),
            action(ACTION_C, HttpMethod::Post, StateActionKind::SessionRefresh),
        ];
        let report = evaluate_state_actions(&actions, StateSafetyLimits::default()).unwrap();
        assert_eq!(report.permits().len(), 3);

        let mut real_context = action(ACTION_D, HttpMethod::Post, StateActionKind::SessionLogin);
        real_context.synthetic_test_context = false;
        let report = evaluate_state_actions(&[real_context], StateSafetyLimits::default()).unwrap();
        assert_eq!(
            report.records()[0].block_reason,
            Some(StateBlockReason::NonSyntheticContext)
        );
    }

    #[test]
    fn unknown_heuristic_and_non_inert_post_actions_are_blocked() {
        let unknown = action(
            ACTION_A,
            HttpMethod::Get,
            StateActionKind::UnknownStateChange,
        );
        let mut heuristic = action(
            ACTION_B,
            HttpMethod::Get,
            StateActionKind::ReadOnlyObservation,
        );
        heuristic.classification_source = ActionClassificationSource::UrlHeuristic;
        let mut non_inert = action(ACTION_C, HttpMethod::Post, StateActionKind::InertStateProbe);
        non_inert.payload_is_inert = false;
        let report = evaluate_state_actions(
            &[unknown, heuristic, non_inert],
            StateSafetyLimits::default(),
        )
        .unwrap();
        assert_eq!(report.blocked_action_count(), 3);
        assert_eq!(
            report.records()[0].block_reason,
            Some(StateBlockReason::UnknownStateChange)
        );
        assert_eq!(
            report.records()[1].block_reason,
            Some(StateBlockReason::WeakClassification)
        );
        assert_eq!(
            report.records()[2].block_reason,
            Some(StateBlockReason::NonInertPostPayload)
        );
    }

    #[test]
    fn receipt_for_blocked_or_unknown_action_is_rejected() {
        let actions = [action(
            ACTION_A,
            HttpMethod::Post,
            StateActionKind::PurchaseOrPayment,
        )];
        let report = evaluate_state_actions(&actions, StateSafetyLimits::default()).unwrap();
        let blocked_receipt = [StateExecutionReceipt {
            action_ref: ACTION_A,
            method: HttpMethod::Post,
            request_fingerprint: REQUEST,
            repetition: 1,
            evidence_ref: "forbidden-execution",
        }];
        assert_eq!(
            audit_state_executions(&report, &blocked_receipt, StateSafetyLimits::default(),),
            Err(StateSafetyRuntimeError::UnpermittedExecution)
        );
    }

    #[test]
    fn duplicate_actions_receipts_and_mismatched_receipts_fail_closed() {
        let first = action(
            ACTION_A,
            HttpMethod::Get,
            StateActionKind::ReadOnlyObservation,
        );
        let duplicate = action(
            ACTION_A,
            HttpMethod::Get,
            StateActionKind::ReadOnlyObservation,
        );
        assert_eq!(
            evaluate_state_actions(&[first, duplicate], StateSafetyLimits::default()),
            Err(StateSafetyRuntimeError::DuplicateAction)
        );

        let report = evaluate_state_actions(
            &[action(
                ACTION_A,
                HttpMethod::Get,
                StateActionKind::ReadOnlyObservation,
            )],
            StateSafetyLimits::default(),
        )
        .unwrap();
        let permit = &report.permits()[0];
        let duplicate_receipts = [
            StateExecutionReceipt {
                action_ref: permit.action_ref(),
                method: HttpMethod::Get,
                request_fingerprint: REQUEST,
                repetition: 1,
                evidence_ref: "execution-1",
            },
            StateExecutionReceipt {
                action_ref: permit.action_ref(),
                method: HttpMethod::Get,
                request_fingerprint: REQUEST,
                repetition: 1,
                evidence_ref: "execution-duplicate",
            },
        ];
        assert_eq!(
            audit_state_executions(&report, &duplicate_receipts, StateSafetyLimits::default(),),
            Err(StateSafetyRuntimeError::DuplicateReceipt)
        );

        let mismatch = [StateExecutionReceipt {
            action_ref: permit.action_ref(),
            method: HttpMethod::Post,
            request_fingerprint: REQUEST,
            repetition: 1,
            evidence_ref: "execution-mismatch",
        }];
        assert_eq!(
            audit_state_executions(&report, &mismatch, StateSafetyLimits::default()),
            Err(StateSafetyRuntimeError::InvalidReceipt)
        );
    }

    #[test]
    fn descriptors_reports_and_qa_debug_hide_sensitive_values() {
        let descriptor = action(
            ACTION_A,
            HttpMethod::Get,
            StateActionKind::ReadOnlyObservation,
        );
        let descriptor_debug = format!("{descriptor:?}");
        assert!(!descriptor_debug.contains("example.com"));
        assert!(!descriptor_debug.contains(ACTION_A));
        assert!(!descriptor_debug.contains(REQUEST));
        let report = evaluate_state_actions(&[descriptor], StateSafetyLimits::default()).unwrap();
        let receipt = StateExecutionReceipt {
            action_ref: ACTION_A,
            method: HttpMethod::Get,
            request_fingerprint: REQUEST,
            repetition: 1,
            evidence_ref: "execution-secret-ref",
        };
        let qa = audit_state_executions(
            &report,
            std::slice::from_ref(&receipt),
            StateSafetyLimits::default(),
        )
        .unwrap();
        let debug = format!("{report:?} {:?} {receipt:?} {qa:?}", report.permits()[0]);
        assert!(!debug.contains("example.com"));
        assert!(!debug.contains(ACTION_A));
        assert!(!debug.contains(REQUEST));
        assert!(!debug.contains("execution-secret-ref"));
    }
}
