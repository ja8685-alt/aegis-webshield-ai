//! Bounded baseline, probe, and control response comparison.
//!
//! Raw bodies remain worker-local. The comparator retains only aggregate
//! similarity, timing, status, and evidence-reference metadata.

mod benchmark;
mod bola_idor;
mod path_traversal;
mod response_comparison;
mod role_comparison;
mod session_graph;
mod session_security;
mod sql_injection;
mod ssrf;
mod state_safety;
mod xss_reflection;

pub use benchmark::{run_active_benchmark, ActiveBenchmarkError, ActiveBenchmarkReport};
pub use bola_idor::{
    assess_bola_idor, plan_bola_idor, BolaAssessment, BolaCandidate, BolaContract, BolaDecision,
    BolaLimits, BolaObjectAssessment, BolaObjectDecision, BolaObjectEvidence, BolaObjectPlan,
    BolaPlan, BolaRuntimeError, OwnedObjectFixture,
};
pub use path_traversal::{
    assess_path_traversal, plan_path_traversal_probes, PathTraversalAssessment,
    PathTraversalCandidate, PathTraversalContract, PathTraversalDecision, PathTraversalInput,
    PathTraversalLimits, PathTraversalRuntimeError, TraversalEncoding, TraversalPlatform,
    TraversalProbe, TraversalProbePolicy, TraversalResponseSample,
};
pub use response_comparison::{
    compare_responses, ComparisonAssessment, ComparisonDecision, ComparisonLimits,
    ComparisonObservation, ComparisonPolicy, ComparisonRuntimeError, ComparisonSignal,
    ResponseComparisonInput, ResponseSample,
};
pub use role_comparison::{
    build_role_comparison_matrix, plan_role_comparison, RoleAccessOutcome, RoleAccount,
    RoleComparisonContract, RoleComparisonError, RoleComparisonLimits, RoleComparisonMatrix,
    RoleComparisonPlan, RoleExecution, RolePairComparison, RolePairRelation,
    RoleResponseObservation, RoleResult,
};
pub use session_graph::{
    CredentialReference, RequestDependency, SessionCredentialKind, SessionFlowGraph,
    SessionGraphError, SessionGraphLimits, SessionPhase, SessionRequestKind, SessionRequestStep,
    SessionRequestTransition, SessionState, SessionStateId, SessionStepId, TransitionOutcome,
};
pub use session_security::{
    assess_session_security, plan_expiry_enforcement, plan_logout_invalidation,
    plan_session_fixation, SessionIdentifierComparison, SessionSecurityAssessment,
    SessionSecurityCandidate, SessionSecurityContract, SessionSecurityDecision,
    SessionSecurityExecution, SessionSecurityLimits, SessionSecurityMode,
    SessionSecurityObservation, SessionSecurityPlan, SessionSecurityResult, SessionSecurityRole,
    SessionSecurityRuntimeError, SessionSecuritySignal,
};
pub use sql_injection::{
    assess_sql_injection, plan_sql_injection_stages, SqlErrorFamily, SqlInjectionAssessment,
    SqlInjectionCandidate, SqlInjectionContract, SqlInjectionDecision, SqlInjectionEvidence,
    SqlInjectionLimits, SqlInjectionPolicy, SqlInjectionRuntimeError, SqlInjectionSignal,
    SqlProbeStage, SqlResponseSample,
};
pub use ssrf::{
    assess_ssrf, plan_ssrf_probe, CallbackEvent, SsrfAssessment, SsrfCandidate, SsrfContract,
    SsrfDecision, SsrfEvidence, SsrfLimits, SsrfMode, SsrfProbePlan, SsrfRuntimeError,
};
pub use state_safety::{
    audit_state_executions, evaluate_state_actions, ActionClassificationSource,
    StateActionDescriptor, StateActionKind, StateActionPermit, StateActionRecord,
    StateActionVerdict, StateBlockReason, StateExecutionReceipt, StateSafetyLimits,
    StateSafetyQaEvidence, StateSafetyReport, StateSafetyRuntimeError,
};
pub use xss_reflection::{
    assess_xss_reflection, ReflectionContext, XssCandidate, XssProbeContract,
    XssReflectionAssessment, XssReflectionDecision, XssReflectionInput, XssReflectionLimits,
    XssReflectionRuntimeError, XssResponseSample,
};
