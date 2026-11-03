use std::collections::BTreeSet;
use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    AiReviewRequest, ContractError, ExampleLanguage, FixGuideContract, FixLocationBasis,
    FixLocationCandidate, FixLocationKind, FixReference, ReferenceAuthority, RootCauseKey,
    SafeFixExample, SafetyProperty, TechnologyStack,
};

const GENERATED_PREFIX: &str = "generatedguide_";
const LOCATION_PREFIX: &str = "fixlocation_";
const EXAMPLE_PREFIX: &str = "fixexample_";
const OPERATOR_APPROVAL_PREFIX: &str = "operatorapproval_";
const HARD_MAX_LOCATION_FACTS: usize = 16;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum StackSelectionEvidence {
    ClaimRef(String),
    OperatorApprovalRef(String),
}

impl Debug for StackSelectionEvidence {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClaimRef(value) => formatter
                .debug_tuple("ClaimRef")
                .field(&value.len())
                .finish(),
            Self::OperatorApprovalRef(value) => formatter
                .debug_tuple("OperatorApprovalRef")
                .field(&value.len())
                .finish(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct StackSelection {
    stack: TechnologyStack,
    evidence: StackSelectionEvidence,
}

impl StackSelection {
    pub fn from_claim(stack: TechnologyStack, claim_ref: impl Into<String>) -> Self {
        Self {
            stack,
            evidence: StackSelectionEvidence::ClaimRef(claim_ref.into()),
        }
    }

    pub fn operator_provided(stack: TechnologyStack, approval_ref: impl Into<String>) -> Self {
        Self {
            stack,
            evidence: StackSelectionEvidence::OperatorApprovalRef(approval_ref.into()),
        }
    }
}

impl Debug for StackSelection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StackSelection")
            .field("stack", &self.stack)
            .field("evidence", &self.evidence)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceLocationFact {
    location_ref: String,
    kind: FixLocationKind,
    relative_path: Option<String>,
    symbol: Option<String>,
    claim_ref: String,
}

impl EvidenceLocationFact {
    pub fn new(
        location_ref: impl Into<String>,
        kind: FixLocationKind,
        relative_path: Option<String>,
        symbol: Option<String>,
        claim_ref: impl Into<String>,
    ) -> Self {
        Self {
            location_ref: location_ref.into(),
            kind,
            relative_path,
            symbol,
            claim_ref: claim_ref.into(),
        }
    }
}

impl Debug for EvidenceLocationFact {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceLocationFact")
            .field("location_ref_bytes", &self.location_ref.len())
            .field("kind", &self.kind)
            .field("path_bytes", &self.relative_path.as_ref().map(String::len))
            .field("symbol_bytes", &self.symbol.as_ref().map(String::len))
            .field("claim_ref_bytes", &self.claim_ref.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixGuideGenerationMode {
    EvidenceBacked,
    TemplateFallback,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GeneratedFixGuide {
    generated_ref: String,
    review_fingerprint: String,
    mode: FixGuideGenerationMode,
    cited_claim_refs: Vec<String>,
    guide: FixGuideContract,
    fingerprint: String,
}

impl GeneratedFixGuide {
    pub fn mode(&self) -> FixGuideGenerationMode {
        self.mode
    }

    pub fn cited_claim_refs(&self) -> &[String] {
        &self.cited_claim_refs
    }

    pub fn guide(&self) -> &FixGuideContract {
        &self.guide
    }

    pub fn validate(&self, review: &AiReviewRequest) -> Result<(), ContractError> {
        validate_prefixed_hash("generated_ref", &self.generated_ref, GENERATED_PREFIX)?;
        if self.review_fingerprint != review.fingerprint() {
            return Err(ContractError::new(
                "review_fingerprint",
                "generated guide must bind to exact AI review request",
            ));
        }
        self.guide.validate()?;
        let allowed = review
            .claims()
            .iter()
            .map(|claim| claim.claim_ref())
            .collect::<BTreeSet<_>>();
        let mut previous: Option<&str> = None;
        for reference in &self.cited_claim_refs {
            if !allowed.contains(reference.as_str())
                || previous.is_some_and(|value| value >= reference.as_str())
            {
                return Err(ContractError::new(
                    "cited_claim_refs",
                    "citations must be sorted, unique, and present in review",
                ));
            }
            previous = Some(reference);
        }
        if self.mode == FixGuideGenerationMode::EvidenceBacked && self.cited_claim_refs.is_empty() {
            return Err(ContractError::new(
                "cited_claim_refs",
                "evidence-backed guide requires citations",
            ));
        }
        let has_evidence_location = self
            .guide
            .locations()
            .iter()
            .any(|location| location.basis() == FixLocationBasis::Evidence);
        if has_evidence_location != (self.mode == FixGuideGenerationMode::EvidenceBacked) {
            return Err(ContractError::new(
                "mode",
                "generation mode must match location evidence basis",
            ));
        }
        validate_sha256("fingerprint", &self.fingerprint)?;
        if self.fingerprint != self.compute_fingerprint() {
            return Err(ContractError::new(
                "fingerprint",
                "generated Fix Guide integrity mismatch",
            ));
        }
        Ok(())
    }

    fn compute_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "aegis.generated-fix-guide.v1");
        hash_field(&mut hasher, &self.generated_ref);
        hash_field(&mut hasher, &self.review_fingerprint);
        hash_field(
            &mut hasher,
            match self.mode {
                FixGuideGenerationMode::EvidenceBacked => "evidence_backed",
                FixGuideGenerationMode::TemplateFallback => "template_fallback",
            },
        );
        hash_field(&mut hasher, &self.cited_claim_refs.len().to_string());
        for reference in &self.cited_claim_refs {
            hash_field(&mut hasher, reference);
        }
        hash_field(&mut hasher, self.guide.fingerprint());
        format!("{:x}", hasher.finalize())
    }
}

impl Debug for GeneratedFixGuide {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GeneratedFixGuide")
            .field("generated_ref_bytes", &self.generated_ref.len())
            .field("review_fingerprint_bytes", &self.review_fingerprint.len())
            .field("mode", &self.mode)
            .field("citation_count", &self.cited_claim_refs.len())
            .field("guide", &self.guide)
            .field("fingerprint_bytes", &self.fingerprint.len())
            .finish()
    }
}

pub fn generate_fix_guide(
    generated_ref: impl Into<String>,
    guide_ref: impl Into<String>,
    review: &AiReviewRequest,
    stack_selection: StackSelection,
    location_facts: Vec<EvidenceLocationFact>,
) -> Result<GeneratedFixGuide, ContractError> {
    if location_facts.len() > HARD_MAX_LOCATION_FACTS {
        return Err(ContractError::new(
            "location_facts",
            "location fact limit exceeded",
        ));
    }
    let mut citations = BTreeSet::new();
    validate_stack_selection(review, &stack_selection, &mut citations)?;
    let stack = stack_selection.stack;
    let locations = if location_facts.is_empty() {
        vec![fallback_location(review, stack)?]
    } else {
        location_facts
            .iter()
            .map(|fact| location_from_claim(review, fact, &mut citations))
            .collect::<Result<Vec<_>, _>>()?
    };
    let mode = if location_facts.is_empty() {
        FixGuideGenerationMode::TemplateFallback
    } else {
        FixGuideGenerationMode::EvidenceBacked
    };
    let root_cause = RootCauseKey::new(review.weakness_key(), review.root_cause_mechanism())?;
    let (language, code, safety_property) = template_example(stack, review.weakness_key());
    let example = SafeFixExample::new(
        template_example_ref(review.correlation_key()),
        language,
        code,
        vec![safety_property, SafetyProperty::FailClosedErrorHandling],
    )?;
    let references = vec![
        FixReference::new(ReferenceAuthority::Cwe, review.weakness_key())?,
        FixReference::new(
            ReferenceAuthority::OwaspCheatSheet,
            reference_control(review.weakness_key()),
        )?,
    ];
    let guide = FixGuideContract::new(
        guide_ref,
        review.correlation_key(),
        root_cause,
        stack,
        summary_template(review.weakness_key()),
        locations,
        vec![example],
        references,
    )?;
    let mut generated = GeneratedFixGuide {
        generated_ref: generated_ref.into(),
        review_fingerprint: review.fingerprint().to_string(),
        mode,
        cited_claim_refs: citations.into_iter().collect(),
        guide,
        fingerprint: String::new(),
    };
    generated.fingerprint = generated.compute_fingerprint();
    generated.validate(review)?;
    Ok(generated)
}

fn validate_stack_selection(
    review: &AiReviewRequest,
    selection: &StackSelection,
    citations: &mut BTreeSet<String>,
) -> Result<(), ContractError> {
    match &selection.evidence {
        StackSelectionEvidence::ClaimRef(reference) => {
            let claim = find_claim(review, reference)?;
            if claim.code() != "technology_stack"
                || claim.value().as_str() != stack_tag(selection.stack)
            {
                return Err(ContractError::new(
                    "stack_selection",
                    "technology stack must exactly match cited claim",
                ));
            }
            citations.insert(reference.clone());
        }
        StackSelectionEvidence::OperatorApprovalRef(reference) => {
            validate_prefixed_hash("operator_approval_ref", reference, OPERATOR_APPROVAL_PREFIX)?;
        }
    }
    Ok(())
}

fn location_from_claim(
    review: &AiReviewRequest,
    fact: &EvidenceLocationFact,
    citations: &mut BTreeSet<String>,
) -> Result<FixLocationCandidate, ContractError> {
    validate_prefixed_hash("location_ref", &fact.location_ref, LOCATION_PREFIX)?;
    let claim = find_claim(review, &fact.claim_ref)?;
    let matches = match (claim.code(), &fact.relative_path, &fact.symbol) {
        ("source_path", Some(path), None) => claim.value().as_str() == path,
        ("handler_symbol", None, Some(symbol)) => claim.value().as_str() == symbol,
        _ => false,
    };
    if !matches {
        return Err(ContractError::new(
            "location_fact",
            "location must exactly match a source_path or handler_symbol claim",
        ));
    }
    citations.insert(fact.claim_ref.clone());
    FixLocationCandidate::new(
        fact.location_ref.clone(),
        fact.kind,
        fact.relative_path.clone(),
        fact.symbol.clone(),
        FixLocationBasis::Evidence,
    )
}

fn fallback_location(
    review: &AiReviewRequest,
    stack: TechnologyStack,
) -> Result<FixLocationCandidate, ContractError> {
    FixLocationCandidate::new(
        template_location_ref(review.correlation_key()),
        FixLocationKind::FunctionOrHandler,
        None,
        Some(fallback_symbol(stack).to_string()),
        FixLocationBasis::FrameworkConvention,
    )
}

fn find_claim<'a>(
    review: &'a AiReviewRequest,
    reference: &str,
) -> Result<&'a crate::AiEvidenceClaim, ContractError> {
    review
        .claims()
        .iter()
        .find(|claim| claim.claim_ref() == reference)
        .ok_or_else(|| ContractError::new("claim_ref", "referenced evidence claim does not exist"))
}

fn template_location_ref(correlation_key: &str) -> String {
    prefixed_digest(LOCATION_PREFIX, "location", correlation_key)
}
fn template_example_ref(correlation_key: &str) -> String {
    prefixed_digest(EXAMPLE_PREFIX, "example", correlation_key)
}
fn prefixed_digest(prefix: &str, domain: &str, value: &str) -> String {
    let digest = format!(
        "{:x}",
        Sha256::digest(format!("{domain}\0{value}").as_bytes())
    );
    format!("{prefix}{}", &digest[..32])
}

fn template_example(
    stack: TechnologyStack,
    weakness: &str,
) -> (ExampleLanguage, &'static str, SafetyProperty) {
    let language = match stack {
        TechnologyStack::RustAxum => ExampleLanguage::Rust,
        TechnologyStack::PythonFastApi => ExampleLanguage::Python,
        TechnologyStack::NodeExpress => ExampleLanguage::TypeScript,
        TechnologyStack::JavaSpring => ExampleLanguage::Java,
        TechnologyStack::DotNetAspNet => ExampleLanguage::CSharp,
        TechnologyStack::GoNetHttp => ExampleLanguage::Go,
        TechnologyStack::Generic => ExampleLanguage::Pseudocode,
    };
    match weakness {
        "CWE-89" => (language, "Use the framework parameter-binding API; keep untrusted values separate from the SQL command text.", SafetyProperty::ParameterizedQuery),
        "CWE-79" => (language, "Apply context-specific output encoding at the final HTML rendering boundary.", SafetyProperty::ContextualOutputEncoding),
        "CWE-22" => (language, "Resolve and canonicalize the path, then verify it remains under the approved base directory.", SafetyProperty::CanonicalPath),
        "CWE-918" => (language, "Resolve the destination server-side and allow only approved schemes, hosts, ports, and public addresses.", SafetyProperty::NetworkDestinationAllowlist),
        _ => (language, "Validate input against a server-side allowlist and fail closed when validation is inconclusive.", SafetyProperty::ServerSideAllowlist),
    }
}

fn summary_template(weakness: &str) -> &'static str {
    match weakness {
        "CWE-89" => "입력값이 SQL 명령 구조와 분리되지 않은 것이 원인이다.",
        "CWE-79" => "신뢰할 수 없는 값이 출력 문맥에 맞게 인코딩되지 않은 것이 원인이다.",
        "CWE-22" => "사용자 제어 경로가 기준 디렉터리 안으로 정규화·제한되지 않은 것이 원인이다.",
        "CWE-918" => "서버 측 요청 목적지가 엄격한 허용 목록으로 제한되지 않은 것이 원인이다.",
        _ => "검증되지 않은 입력이 보안 경계의 민감 동작에 직접 사용된 것이 원인이다.",
    }
}
fn reference_control(weakness: &str) -> &'static str {
    match weakness {
        "CWE-89" => "SQL Injection Prevention",
        "CWE-79" => "Cross Site Scripting Prevention",
        "CWE-22" => "File Upload and Path Validation",
        "CWE-918" => "Server Side Request Forgery Prevention",
        _ => "Input Validation",
    }
}
fn fallback_symbol(stack: TechnologyStack) -> &'static str {
    match stack {
        TechnologyStack::RustAxum => "axum_request_handler",
        TechnologyStack::PythonFastApi => "fastapi_path_operation",
        TechnologyStack::NodeExpress => "express_route_handler",
        TechnologyStack::JavaSpring => "spring_controller_method",
        TechnologyStack::DotNetAspNet => "aspnet_controller_action",
        TechnologyStack::GoNetHttp => "http_handler",
        TechnologyStack::Generic => "request_handler",
    }
}
fn stack_tag(stack: TechnologyStack) -> &'static str {
    match stack {
        TechnologyStack::RustAxum => "rust_axum",
        TechnologyStack::PythonFastApi => "python_fastapi",
        TechnologyStack::NodeExpress => "node_express",
        TechnologyStack::JavaSpring => "java_spring",
        TechnologyStack::DotNetAspNet => "dotnet_aspnet",
        TechnologyStack::GoNetHttp => "go_net_http",
        TechnologyStack::Generic => "generic",
    }
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
fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use crate::{
        adjust_confidence, correlate_findings, AiEvidenceClaim, AiReviewRequest, CanonicalFinding,
        Confidence, ConfidenceAdjustmentLimits, CorrelationContext, CorrelationLimits,
        FindingCorrelationInput, FindingIdentity, FindingProvenance, HttpMethod, ParameterLocation,
        RootCauseKey, RulePrecisionProfile, Severity, TargetNoiseProfile,
    };

    use super::{generate_fix_guide, EvidenceLocationFact, FixGuideGenerationMode, StackSelection};
    use crate::{FixLocationBasis, FixLocationKind, TechnologyStack};

    const TENANT: &str = "tenant_0123456789abcdef0123456789abcdef";
    const SCAN: &str = "scan_0123456789abcdef0123456789abcdef";
    const BUNDLE: &str = "bundle_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const RULE_PROFILE: &str = "ruleprofile_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NOISE_PROFILE: &str = "noise_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const REVIEW: &str = "review_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CLAIM_STACK: &str = "claim_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CLAIM_PATH: &str = "claim_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const GENERATED: &str = "generatedguide_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const GUIDE: &str = "fixguide_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const LOCATION: &str = "fixlocation_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const APPROVAL: &str = "operatorapproval_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn provenance() -> FindingProvenance {
        FindingProvenance::new("aegis_native", "sqli_error", "1.0.0").unwrap()
    }

    fn review(stack_value: &str) -> AiReviewRequest {
        let context = CorrelationContext::new(TENANT, SCAN).unwrap();
        let identity = FindingIdentity::new(
            "target-1",
            HttpMethod::Get,
            "https://example.com/api/users/123?id=1",
            "CWE-89",
            ParameterLocation::Query,
            Some("id".to_string()),
        )
        .unwrap();
        let finding = CanonicalFinding::new(
            "finding-1",
            identity,
            "SQL injection candidate",
            Severity::High,
            Confidence::High,
            vec!["evidence-stack".to_string(), "evidence-path".to_string()],
            provenance(),
        )
        .unwrap();
        let input = FindingCorrelationInput::new(
            finding,
            RootCauseKey::new("CWE-89", "unsafe_sql_interpolation").unwrap(),
            BUNDLE,
        )
        .unwrap();
        let correlation =
            correlate_findings(context.clone(), vec![input], CorrelationLimits::default()).unwrap();
        let adjustment = adjust_confidence(
            &correlation,
            vec![RulePrecisionProfile::new(RULE_PROFILE, provenance(), 95, 5, 0).unwrap()],
            vec![
                TargetNoiseProfile::new(NOISE_PROFILE, context, "target-1", 10, 1, 0, 1, 1)
                    .unwrap(),
            ],
            ConfidenceAdjustmentLimits::default(),
        )
        .unwrap();
        AiReviewRequest::new(
            REVIEW,
            &correlation,
            &adjustment,
            0,
            vec![
                AiEvidenceClaim::new(
                    CLAIM_STACK,
                    "evidence-stack",
                    "technology_stack",
                    stack_value,
                )
                .unwrap(),
                AiEvidenceClaim::new(
                    CLAIM_PATH,
                    "evidence-path",
                    "source_path",
                    "src/routes/users.rs",
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn exact_claim_values_generate_evidence_backed_locations() {
        let review = review("rust_axum");
        let generated = generate_fix_guide(
            GENERATED,
            GUIDE,
            &review,
            StackSelection::from_claim(TechnologyStack::RustAxum, CLAIM_STACK),
            vec![EvidenceLocationFact::new(
                LOCATION,
                FixLocationKind::SourceFile,
                Some("src/routes/users.rs".to_string()),
                None,
                CLAIM_PATH,
            )],
        )
        .unwrap();
        assert_eq!(generated.mode(), FixGuideGenerationMode::EvidenceBacked);
        assert_eq!(generated.cited_claim_refs(), &[CLAIM_STACK, CLAIM_PATH]);
        assert_eq!(
            generated.guide().locations()[0].basis(),
            FixLocationBasis::Evidence
        );
        assert_eq!(
            generated.guide().locations()[0].relative_path(),
            Some("src/routes/users.rs")
        );
        assert!(generated.validate(&review).is_ok());
    }

    #[test]
    fn missing_location_evidence_uses_an_explicit_template_fallback() {
        let review = review("rust_axum");
        let generated = generate_fix_guide(
            GENERATED,
            GUIDE,
            &review,
            StackSelection::from_claim(TechnologyStack::RustAxum, CLAIM_STACK),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(generated.mode(), FixGuideGenerationMode::TemplateFallback);
        assert_eq!(generated.cited_claim_refs(), &[CLAIM_STACK]);
        assert_eq!(
            generated.guide().locations()[0].basis(),
            FixLocationBasis::FrameworkConvention
        );
        assert_eq!(generated.guide().locations()[0].relative_path(), None);
    }

    #[test]
    fn generated_location_cannot_differ_from_its_cited_claim() {
        let review = review("rust_axum");
        let error = generate_fix_guide(
            GENERATED,
            GUIDE,
            &review,
            StackSelection::from_claim(TechnologyStack::RustAxum, CLAIM_STACK),
            vec![EvidenceLocationFact::new(
                LOCATION,
                FixLocationKind::SourceFile,
                Some("src/admin.rs".to_string()),
                None,
                CLAIM_PATH,
            )],
        )
        .unwrap_err();
        assert_eq!(error.field(), "location_fact");
    }

    #[test]
    fn stack_requires_an_exact_claim_or_valid_operator_approval() {
        let review = review("rust_axum");
        let error = generate_fix_guide(
            GENERATED,
            GUIDE,
            &review,
            StackSelection::from_claim(TechnologyStack::PythonFastApi, CLAIM_STACK),
            Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error.field(), "stack_selection");
        let error = generate_fix_guide(
            GENERATED,
            GUIDE,
            &review,
            StackSelection::operator_provided(TechnologyStack::RustAxum, "approval-invalid"),
            Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error.field(), "operator_approval_ref");
        assert!(generate_fix_guide(
            GENERATED,
            GUIDE,
            &review,
            StackSelection::operator_provided(TechnologyStack::RustAxum, APPROVAL),
            Vec::new(),
        )
        .is_ok());
    }

    #[test]
    fn every_supported_stack_receives_a_matching_internal_template() {
        let review = review("rust_axum");
        for stack in [
            TechnologyStack::RustAxum,
            TechnologyStack::PythonFastApi,
            TechnologyStack::NodeExpress,
            TechnologyStack::JavaSpring,
            TechnologyStack::DotNetAspNet,
            TechnologyStack::GoNetHttp,
            TechnologyStack::Generic,
        ] {
            let generated = generate_fix_guide(
                GENERATED,
                GUIDE,
                &review,
                StackSelection::operator_provided(stack, APPROVAL),
                Vec::new(),
            )
            .unwrap();
            assert_eq!(generated.guide().stack(), stack);
            assert!(generated.guide().validate().is_ok());
        }
    }

    #[test]
    fn generated_wrapper_integrity_and_debug_hide_evidence_values() {
        let review = review("rust_axum");
        let mut generated = generate_fix_guide(
            GENERATED,
            GUIDE,
            &review,
            StackSelection::from_claim(TechnologyStack::RustAxum, CLAIM_STACK),
            Vec::new(),
        )
        .unwrap();
        generated.mode = FixGuideGenerationMode::EvidenceBacked;
        assert_eq!(generated.validate(&review).unwrap_err().field(), "mode");
        let debug = format!("{generated:?}");
        assert!(!debug.contains(GENERATED));
        assert!(!debug.contains(CLAIM_STACK));
        assert!(!debug.contains("src/routes/users.rs"));
    }
}
