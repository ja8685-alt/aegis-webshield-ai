use std::collections::BTreeSet;
use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ContractError, RedactedText, RootCauseKey};

const GUIDE_PREFIX: &str = "fixguide_";
const LOCATION_PREFIX: &str = "fixlocation_";
const EXAMPLE_PREFIX: &str = "fixexample_";
const MAX_SUMMARY_BYTES: usize = 1_024;
const MAX_CODE_BYTES: usize = 4_096;
const HARD_MAX_LOCATIONS: usize = 16;
const HARD_MAX_EXAMPLES: usize = 8;
const HARD_MAX_REFERENCES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnologyStack {
    RustAxum,
    PythonFastApi,
    NodeExpress,
    JavaSpring,
    DotNetAspNet,
    GoNetHttp,
    Generic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixLocationKind {
    SourceFile,
    FunctionOrHandler,
    Configuration,
    Dependency,
    Infrastructure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixLocationBasis {
    Evidence,
    FrameworkConvention,
    OperatorProvided,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixLocationCandidate {
    location_ref: String,
    kind: FixLocationKind,
    relative_path: Option<String>,
    symbol: Option<String>,
    basis: FixLocationBasis,
}

impl FixLocationCandidate {
    pub fn new(
        location_ref: impl Into<String>,
        kind: FixLocationKind,
        relative_path: Option<String>,
        symbol: Option<String>,
        basis: FixLocationBasis,
    ) -> Result<Self, ContractError> {
        let candidate = Self {
            location_ref: location_ref.into(),
            kind,
            relative_path,
            symbol,
            basis,
        };
        candidate.validate()?;
        Ok(candidate)
    }

    pub fn basis(&self) -> FixLocationBasis {
        self.basis
    }

    pub fn relative_path(&self) -> Option<&str> {
        self.relative_path.as_deref()
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_prefixed_hash("location_ref", &self.location_ref, LOCATION_PREFIX)?;
        if self.relative_path.is_none() && self.symbol.is_none() {
            return Err(ContractError::new(
                "location",
                "relative path or symbol is required",
            ));
        }
        if let Some(path) = &self.relative_path {
            validate_relative_path(path)?;
        }
        if let Some(symbol) = &self.symbol {
            validate_display_identifier("symbol", symbol, 128)?;
        }
        if self.basis == FixLocationBasis::FrameworkConvention
            && self.kind == FixLocationKind::SourceFile
            && self.symbol.is_some()
        {
            return Err(ContractError::new(
                "basis",
                "framework convention cannot assert an exact source symbol",
            ));
        }
        Ok(())
    }
}

impl Debug for FixLocationCandidate {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FixLocationCandidate")
            .field("location_ref_bytes", &self.location_ref.len())
            .field("kind", &self.kind)
            .field("path_bytes", &self.relative_path.as_ref().map(String::len))
            .field("symbol_bytes", &self.symbol.as_ref().map(String::len))
            .field("basis", &self.basis)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyProperty {
    ParameterizedQuery,
    ContextualOutputEncoding,
    ServerSideAllowlist,
    LeastPrivilege,
    SecureCookie,
    CsrfToken,
    CanonicalPath,
    NetworkDestinationAllowlist,
    FailClosedErrorHandling,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExampleLanguage {
    Rust,
    Python,
    TypeScript,
    Java,
    CSharp,
    Go,
    Pseudocode,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SafeFixExample {
    example_ref: String,
    language: ExampleLanguage,
    code: RedactedText,
    safety_properties: Vec<SafetyProperty>,
}

impl SafeFixExample {
    pub fn new(
        example_ref: impl Into<String>,
        language: ExampleLanguage,
        code: &str,
        mut safety_properties: Vec<SafetyProperty>,
    ) -> Result<Self, ContractError> {
        safety_properties.sort();
        safety_properties.dedup();
        let example = Self {
            example_ref: example_ref.into(),
            language,
            code: RedactedText::new(code, MAX_CODE_BYTES)?,
            safety_properties,
        };
        example.validate()?;
        Ok(example)
    }

    pub fn language(&self) -> ExampleLanguage {
        self.language
    }

    pub fn safety_properties(&self) -> &[SafetyProperty] {
        &self.safety_properties
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_prefixed_hash("example_ref", &self.example_ref, EXAMPLE_PREFIX)?;
        if self.code.as_str().is_empty() || self.code.truncated() {
            return Err(ContractError::new(
                "code",
                "safe example must be present without truncation",
            ));
        }
        if self.safety_properties.is_empty()
            || self.safety_properties.len() > 8
            || self
                .safety_properties
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(ContractError::new(
                "safety_properties",
                "must be sorted, unique, and bounded",
            ));
        }
        let lowercase = self.code.as_str().to_ascii_lowercase();
        for forbidden in [
            "169.254.169.254",
            "../",
            "<script",
            "password=",
            "access_token=",
            "api_key=",
            "authorization: bearer",
        ] {
            if lowercase.contains(forbidden) {
                return Err(ContractError::new(
                    "code",
                    "example contains a forbidden exploit or credential pattern",
                ));
            }
        }
        Ok(())
    }
}

impl Debug for SafeFixExample {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SafeFixExample")
            .field("example_ref_bytes", &self.example_ref.len())
            .field("language", &self.language)
            .field("code_bytes", &self.code.as_str().len())
            .field("safety_properties", &self.safety_properties)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceAuthority {
    Cwe,
    OwaspAsvs,
    OwaspCheatSheet,
    FrameworkOfficial,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct FixReference {
    authority: ReferenceAuthority,
    control_id: String,
}

impl FixReference {
    pub fn new(
        authority: ReferenceAuthority,
        control_id: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let reference = Self {
            authority,
            control_id: control_id.into(),
        };
        reference.validate()?;
        Ok(reference)
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_display_identifier("control_id", &self.control_id, 96)
    }
}

impl Debug for FixReference {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FixReference")
            .field("authority", &self.authority)
            .field("control_id", &self.control_id)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixGuideContract {
    guide_ref: String,
    correlation_key: String,
    root_cause: RootCauseKey,
    stack: TechnologyStack,
    root_cause_summary: RedactedText,
    locations: Vec<FixLocationCandidate>,
    examples: Vec<SafeFixExample>,
    references: Vec<FixReference>,
    fingerprint: String,
}

impl FixGuideContract {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        guide_ref: impl Into<String>,
        correlation_key: impl Into<String>,
        root_cause: RootCauseKey,
        stack: TechnologyStack,
        root_cause_summary: &str,
        mut locations: Vec<FixLocationCandidate>,
        mut examples: Vec<SafeFixExample>,
        mut references: Vec<FixReference>,
    ) -> Result<Self, ContractError> {
        locations.sort_by(|left, right| left.location_ref.cmp(&right.location_ref));
        examples.sort_by(|left, right| left.example_ref.cmp(&right.example_ref));
        references.sort();
        references.dedup();
        let mut guide = Self {
            guide_ref: guide_ref.into(),
            correlation_key: correlation_key.into(),
            root_cause,
            stack,
            root_cause_summary: RedactedText::new(root_cause_summary, MAX_SUMMARY_BYTES)?,
            locations,
            examples,
            references,
            fingerprint: String::new(),
        };
        guide.fingerprint = guide.compute_fingerprint();
        guide.validate()?;
        Ok(guide)
    }

    pub fn stack(&self) -> TechnologyStack {
        self.stack
    }

    pub fn locations(&self) -> &[FixLocationCandidate] {
        &self.locations
    }

    pub fn examples(&self) -> &[SafeFixExample] {
        &self.examples
    }

    pub fn references(&self) -> &[FixReference] {
        &self.references
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        validate_prefixed_hash("guide_ref", &self.guide_ref, GUIDE_PREFIX)?;
        validate_sha256("correlation_key", &self.correlation_key)?;
        RootCauseKey::new(self.root_cause.weakness_key(), self.root_cause.mechanism())?;
        if self.root_cause_summary.as_str().is_empty() || self.root_cause_summary.truncated() {
            return Err(ContractError::new(
                "root_cause_summary",
                "must be present without truncation",
            ));
        }
        validate_collection_sizes(self)?;
        validate_locations(&self.locations)?;
        validate_examples(self.stack, &self.examples)?;
        validate_references(&self.root_cause, &self.references)?;
        validate_required_safety(&self.root_cause, &self.examples)?;
        validate_sha256("fingerprint", &self.fingerprint)?;
        if self.fingerprint != self.compute_fingerprint() {
            return Err(ContractError::new(
                "fingerprint",
                "Fix Guide integrity fingerprint does not match",
            ));
        }
        Ok(())
    }

    fn compute_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "aegis.fix-guide.contract.v1");
        hash_field(&mut hasher, &self.guide_ref);
        hash_field(&mut hasher, &self.correlation_key);
        hash_field(&mut hasher, self.root_cause.weakness_key());
        hash_field(&mut hasher, self.root_cause.mechanism());
        hash_field(&mut hasher, stack_tag(self.stack));
        hash_field(&mut hasher, self.root_cause_summary.as_str());
        hash_field(&mut hasher, &self.locations.len().to_string());
        for location in &self.locations {
            hash_field(&mut hasher, &location.location_ref);
            hash_field(&mut hasher, location_kind_tag(location.kind));
            hash_field(
                &mut hasher,
                location.relative_path.as_deref().unwrap_or("none"),
            );
            hash_field(&mut hasher, location.symbol.as_deref().unwrap_or("none"));
            hash_field(&mut hasher, location_basis_tag(location.basis));
        }
        hash_field(&mut hasher, &self.examples.len().to_string());
        for example in &self.examples {
            hash_field(&mut hasher, &example.example_ref);
            hash_field(&mut hasher, language_tag(example.language));
            hash_field(&mut hasher, example.code.as_str());
            for property in &example.safety_properties {
                hash_field(&mut hasher, safety_tag(*property));
            }
        }
        hash_field(&mut hasher, &self.references.len().to_string());
        for reference in &self.references {
            hash_field(&mut hasher, authority_tag(reference.authority));
            hash_field(&mut hasher, &reference.control_id);
        }
        format!("{:x}", hasher.finalize())
    }
}

impl Debug for FixGuideContract {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FixGuideContract")
            .field("guide_ref_bytes", &self.guide_ref.len())
            .field("correlation_key_bytes", &self.correlation_key.len())
            .field("root_cause", &self.root_cause)
            .field("stack", &self.stack)
            .field("summary_bytes", &self.root_cause_summary.as_str().len())
            .field("location_count", &self.locations.len())
            .field("example_count", &self.examples.len())
            .field("reference_count", &self.references.len())
            .field("fingerprint_bytes", &self.fingerprint.len())
            .finish()
    }
}

fn validate_collection_sizes(guide: &FixGuideContract) -> Result<(), ContractError> {
    if guide.locations.is_empty()
        || guide.locations.len() > HARD_MAX_LOCATIONS
        || guide.examples.is_empty()
        || guide.examples.len() > HARD_MAX_EXAMPLES
        || guide.references.is_empty()
        || guide.references.len() > HARD_MAX_REFERENCES
    {
        return Err(ContractError::new(
            "guide_content",
            "locations, examples, and references must be present within hard limits",
        ));
    }
    Ok(())
}

fn validate_locations(values: &[FixLocationCandidate]) -> Result<(), ContractError> {
    let mut previous: Option<&str> = None;
    for value in values {
        value.validate()?;
        if previous.is_some_and(|item| item >= value.location_ref.as_str()) {
            return Err(ContractError::new("locations", "must be sorted and unique"));
        }
        previous = Some(&value.location_ref);
    }
    Ok(())
}

fn validate_examples(
    stack: TechnologyStack,
    values: &[SafeFixExample],
) -> Result<(), ContractError> {
    let mut previous: Option<&str> = None;
    for value in values {
        value.validate()?;
        if !language_matches_stack(value.language, stack) {
            return Err(ContractError::new(
                "language",
                "example language does not match technology stack",
            ));
        }
        if previous.is_some_and(|item| item >= value.example_ref.as_str()) {
            return Err(ContractError::new("examples", "must be sorted and unique"));
        }
        previous = Some(&value.example_ref);
    }
    Ok(())
}

fn validate_references(root: &RootCauseKey, values: &[FixReference]) -> Result<(), ContractError> {
    let mut previous: Option<&FixReference> = None;
    let mut has_cwe = false;
    for value in values {
        value.validate()?;
        if previous.is_some_and(|item| item >= value) {
            return Err(ContractError::new(
                "references",
                "must be sorted and unique",
            ));
        }
        if value.authority == ReferenceAuthority::Cwe && value.control_id == root.weakness_key() {
            has_cwe = true;
        }
        previous = Some(value);
    }
    if !has_cwe {
        return Err(ContractError::new(
            "references",
            "exact root-cause CWE reference is required",
        ));
    }
    Ok(())
}

fn validate_required_safety(
    root: &RootCauseKey,
    examples: &[SafeFixExample],
) -> Result<(), ContractError> {
    let properties = examples
        .iter()
        .flat_map(|example| example.safety_properties.iter().copied())
        .collect::<BTreeSet<_>>();
    let required = match root.weakness_key() {
        "CWE-89" => Some(SafetyProperty::ParameterizedQuery),
        "CWE-79" => Some(SafetyProperty::ContextualOutputEncoding),
        "CWE-22" => Some(SafetyProperty::CanonicalPath),
        "CWE-918" => Some(SafetyProperty::NetworkDestinationAllowlist),
        _ => None,
    };
    if required.is_some_and(|value| !properties.contains(&value)) {
        return Err(ContractError::new(
            "safety_properties",
            "examples do not include the weakness-specific safety property",
        ));
    }
    Ok(())
}

fn language_matches_stack(language: ExampleLanguage, stack: TechnologyStack) -> bool {
    matches!(
        (language, stack),
        (ExampleLanguage::Rust, TechnologyStack::RustAxum)
            | (ExampleLanguage::Python, TechnologyStack::PythonFastApi)
            | (ExampleLanguage::TypeScript, TechnologyStack::NodeExpress)
            | (ExampleLanguage::Java, TechnologyStack::JavaSpring)
            | (ExampleLanguage::CSharp, TechnologyStack::DotNetAspNet)
            | (ExampleLanguage::Go, TechnologyStack::GoNetHttp)
            | (ExampleLanguage::Pseudocode, TechnologyStack::Generic)
    )
}

fn validate_relative_path(value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > 256
        || value.starts_with('/')
        || value.contains(['\\', '\r', '\n', '\0'])
        || value
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(ContractError::new(
            "relative_path",
            "must be a normalized relative path without traversal",
        ));
    }
    Ok(())
}
fn validate_display_identifier(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), ContractError> {
    if value.is_empty() || value.len() > max || value.contains(['\r', '\n', '\0']) {
        return Err(ContractError::new(
            field,
            "must be present, bounded, and contain no controls",
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
fn stack_tag(value: TechnologyStack) -> &'static str {
    match value {
        TechnologyStack::RustAxum => "rust_axum",
        TechnologyStack::PythonFastApi => "python_fastapi",
        TechnologyStack::NodeExpress => "node_express",
        TechnologyStack::JavaSpring => "java_spring",
        TechnologyStack::DotNetAspNet => "dotnet_aspnet",
        TechnologyStack::GoNetHttp => "go_net_http",
        TechnologyStack::Generic => "generic",
    }
}
fn location_kind_tag(value: FixLocationKind) -> &'static str {
    match value {
        FixLocationKind::SourceFile => "source_file",
        FixLocationKind::FunctionOrHandler => "function_or_handler",
        FixLocationKind::Configuration => "configuration",
        FixLocationKind::Dependency => "dependency",
        FixLocationKind::Infrastructure => "infrastructure",
    }
}
fn location_basis_tag(value: FixLocationBasis) -> &'static str {
    match value {
        FixLocationBasis::Evidence => "evidence",
        FixLocationBasis::FrameworkConvention => "framework_convention",
        FixLocationBasis::OperatorProvided => "operator_provided",
    }
}
fn language_tag(value: ExampleLanguage) -> &'static str {
    match value {
        ExampleLanguage::Rust => "rust",
        ExampleLanguage::Python => "python",
        ExampleLanguage::TypeScript => "typescript",
        ExampleLanguage::Java => "java",
        ExampleLanguage::CSharp => "csharp",
        ExampleLanguage::Go => "go",
        ExampleLanguage::Pseudocode => "pseudocode",
    }
}
fn safety_tag(value: SafetyProperty) -> &'static str {
    match value {
        SafetyProperty::ParameterizedQuery => "parameterized_query",
        SafetyProperty::ContextualOutputEncoding => "contextual_output_encoding",
        SafetyProperty::ServerSideAllowlist => "server_side_allowlist",
        SafetyProperty::LeastPrivilege => "least_privilege",
        SafetyProperty::SecureCookie => "secure_cookie",
        SafetyProperty::CsrfToken => "csrf_token",
        SafetyProperty::CanonicalPath => "canonical_path",
        SafetyProperty::NetworkDestinationAllowlist => "network_destination_allowlist",
        SafetyProperty::FailClosedErrorHandling => "fail_closed_error_handling",
    }
}
fn authority_tag(value: ReferenceAuthority) -> &'static str {
    match value {
        ReferenceAuthority::Cwe => "cwe",
        ReferenceAuthority::OwaspAsvs => "owasp_asvs",
        ReferenceAuthority::OwaspCheatSheet => "owasp_cheat_sheet",
        ReferenceAuthority::FrameworkOfficial => "framework_official",
    }
}

#[cfg(test)]
mod tests {
    use crate::RootCauseKey;

    use super::{
        ExampleLanguage, FixGuideContract, FixLocationBasis, FixLocationCandidate, FixLocationKind,
        FixReference, ReferenceAuthority, SafeFixExample, SafetyProperty, TechnologyStack,
    };

    const GUIDE: &str = "fixguide_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const LOCATION_A: &str = "fixlocation_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const LOCATION_B: &str = "fixlocation_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const EXAMPLE: &str = "fixexample_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CORRELATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn location() -> FixLocationCandidate {
        FixLocationCandidate::new(
            LOCATION_A,
            FixLocationKind::FunctionOrHandler,
            Some("src/routes/users.rs".to_string()),
            Some("get_user".to_string()),
            FixLocationBasis::Evidence,
        )
        .unwrap()
    }

    fn example(properties: Vec<SafetyProperty>) -> SafeFixExample {
        SafeFixExample::new(
            EXAMPLE,
            ExampleLanguage::Rust,
            "sqlx::query(\"SELECT name FROM users WHERE id = $1\").bind(user_id);",
            properties,
        )
        .unwrap()
    }

    fn references() -> Vec<FixReference> {
        vec![
            FixReference::new(ReferenceAuthority::OwaspAsvs, "V5.3.4").unwrap(),
            FixReference::new(ReferenceAuthority::Cwe, "CWE-89").unwrap(),
        ]
    }

    fn guide() -> FixGuideContract {
        FixGuideContract::new(
            GUIDE,
            CORRELATION,
            RootCauseKey::new("CWE-89", "unsafe_sql_interpolation").unwrap(),
            TechnologyStack::RustAxum,
            "사용자 입력이 SQL 명령과 분리되지 않은 것이 원인이다.",
            vec![location()],
            vec![example(vec![
                SafetyProperty::LeastPrivilege,
                SafetyProperty::ParameterizedQuery,
            ])],
            references(),
        )
        .unwrap()
    }

    #[test]
    fn stack_specific_contract_is_sorted_integrity_bound_and_round_trips() {
        let guide = guide();
        assert_eq!(guide.stack(), TechnologyStack::RustAxum);
        assert_eq!(guide.locations().len(), 1);
        assert_eq!(
            guide.examples()[0].safety_properties(),
            &[
                SafetyProperty::ParameterizedQuery,
                SafetyProperty::LeastPrivilege
            ]
        );
        assert_eq!(guide.references()[0].authority, ReferenceAuthority::Cwe);
        assert_eq!(guide.fingerprint().len(), 64);
        let json = serde_json::to_string(&guide).unwrap();
        let restored: FixGuideContract = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, guide);
        assert!(restored.validate().is_ok());

        let debug = format!(
            "{guide:?} {:?} {:?}",
            guide.locations()[0],
            guide.examples()[0]
        );
        assert!(!debug.contains(GUIDE));
        assert!(!debug.contains(CORRELATION));
        assert!(!debug.contains("src/routes/users.rs"));
        assert!(!debug.contains("SELECT name"));
    }

    #[test]
    fn location_paths_are_relative_normalized_and_evidence_bounded() {
        for path in [
            "/etc/passwd",
            "src/../secret.rs",
            "src//users.rs",
            "C:\\secret.rs",
        ] {
            let error = FixLocationCandidate::new(
                LOCATION_A,
                FixLocationKind::SourceFile,
                Some(path.to_string()),
                None,
                FixLocationBasis::Evidence,
            )
            .unwrap_err();
            assert_eq!(error.field(), "relative_path");
        }
        let error = FixLocationCandidate::new(
            LOCATION_A,
            FixLocationKind::SourceFile,
            Some("src/routes/users.rs".to_string()),
            Some("asserted_symbol".to_string()),
            FixLocationBasis::FrameworkConvention,
        )
        .unwrap_err();
        assert_eq!(error.field(), "basis");
    }

    #[test]
    fn example_language_and_weakness_specific_safety_must_match() {
        let python = SafeFixExample::new(
            EXAMPLE,
            ExampleLanguage::Python,
            "cursor.execute(\"SELECT name FROM users WHERE id = %s\", (user_id,))",
            vec![SafetyProperty::ParameterizedQuery],
        )
        .unwrap();
        let error = FixGuideContract::new(
            GUIDE,
            CORRELATION,
            RootCauseKey::new("CWE-89", "unsafe_sql_interpolation").unwrap(),
            TechnologyStack::RustAxum,
            "SQL input binding is missing",
            vec![location()],
            vec![python],
            references(),
        )
        .unwrap_err();
        assert_eq!(error.field(), "language");

        let error = FixGuideContract::new(
            GUIDE,
            CORRELATION,
            RootCauseKey::new("CWE-89", "unsafe_sql_interpolation").unwrap(),
            TechnologyStack::RustAxum,
            "SQL input binding is missing",
            vec![location()],
            vec![example(vec![SafetyProperty::LeastPrivilege])],
            references(),
        )
        .unwrap_err();
        assert_eq!(error.field(), "safety_properties");
    }

    #[test]
    fn exploit_and_credential_patterns_or_truncated_examples_are_rejected() {
        for code in [
            "fetch('http://169.254.169.254/latest')",
            "open('../../etc/passwd')",
            "password=hardcoded",
            "<script>alert(1)</script>",
        ] {
            assert_eq!(
                SafeFixExample::new(
                    EXAMPLE,
                    ExampleLanguage::Rust,
                    code,
                    vec![SafetyProperty::FailClosedErrorHandling],
                )
                .unwrap_err()
                .field(),
                "code"
            );
        }
        assert_eq!(
            SafeFixExample::new(
                EXAMPLE,
                ExampleLanguage::Rust,
                &"x".repeat(4_097),
                vec![SafetyProperty::ParameterizedQuery],
            )
            .unwrap_err()
            .field(),
            "code"
        );
    }

    #[test]
    fn exact_cwe_reference_and_unique_content_are_required() {
        let wrong_reference = vec![
            FixReference::new(ReferenceAuthority::Cwe, "CWE-79").unwrap(),
            FixReference::new(ReferenceAuthority::OwaspAsvs, "V5.3.4").unwrap(),
        ];
        assert_eq!(
            FixGuideContract::new(
                GUIDE,
                CORRELATION,
                RootCauseKey::new("CWE-89", "unsafe_sql_interpolation").unwrap(),
                TechnologyStack::RustAxum,
                "SQL input binding is missing",
                vec![location()],
                vec![example(vec![SafetyProperty::ParameterizedQuery])],
                wrong_reference,
            )
            .unwrap_err()
            .field(),
            "references"
        );
        let duplicate_location = FixLocationCandidate::new(
            LOCATION_A,
            FixLocationKind::Configuration,
            Some("config/security.toml".to_string()),
            None,
            FixLocationBasis::OperatorProvided,
        )
        .unwrap();
        assert_eq!(
            FixGuideContract::new(
                GUIDE,
                CORRELATION,
                RootCauseKey::new("CWE-89", "unsafe_sql_interpolation").unwrap(),
                TechnologyStack::RustAxum,
                "SQL input binding is missing",
                vec![location(), duplicate_location],
                vec![example(vec![SafetyProperty::ParameterizedQuery])],
                references(),
            )
            .unwrap_err()
            .field(),
            "locations"
        );
    }

    #[test]
    fn nested_contract_tampering_breaks_integrity() {
        let mut guide = guide();
        guide.locations.push(
            FixLocationCandidate::new(
                LOCATION_B,
                FixLocationKind::Configuration,
                Some("config/security.toml".to_string()),
                None,
                FixLocationBasis::OperatorProvided,
            )
            .unwrap(),
        );
        assert_eq!(guide.validate().unwrap_err().field(), "fingerprint");
    }
}
