use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    CanonicalFinding, Confidence, ContractError, FindingIdentity, FindingProvenance, HttpMethod,
    ParameterLocation, RedactedText, Severity,
};

const TENANT_PREFIX: &str = "tenant_";
const SCAN_PREFIX: &str = "scan_";
const BUNDLE_PREFIX: &str = "bundle_";
const HARD_MAX_INPUTS: usize = 512;
const HARD_MAX_GROUPS: usize = 512;
const HARD_MAX_REFERENCES_PER_GROUP: usize = 512;
const MAX_ROOT_CAUSE_MECHANISM_BYTES: usize = 96;

/// Tenant and scan boundary for one correlation run.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CorrelationContext {
    tenant_ref: String,
    scan_ref: String,
}

impl CorrelationContext {
    pub fn new(
        tenant_ref: impl Into<String>,
        scan_ref: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let context = Self {
            tenant_ref: tenant_ref.into(),
            scan_ref: scan_ref.into(),
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

    fn validate(&self) -> Result<(), ContractError> {
        validate_prefixed_hash("tenant_ref", &self.tenant_ref, TENANT_PREFIX)?;
        validate_prefixed_hash("scan_ref", &self.scan_ref, SCAN_PREFIX)
    }
}

impl Debug for CorrelationContext {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CorrelationContext")
            .field("tenant_ref_bytes", &self.tenant_ref.len())
            .field("scan_ref_bytes", &self.scan_ref.len())
            .finish()
    }
}

/// Scanner-independent cause variant under one weakness family.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RootCauseKey {
    weakness_key: String,
    mechanism: String,
}

impl RootCauseKey {
    pub fn new(
        weakness_key: impl Into<String>,
        mechanism: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let root_cause = Self {
            weakness_key: weakness_key.into(),
            mechanism: mechanism.into(),
        };
        root_cause.validate()?;
        Ok(root_cause)
    }

    pub fn weakness_key(&self) -> &str {
        &self.weakness_key
    }

    pub fn mechanism(&self) -> &str {
        &self.mechanism
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_root_cause_part("root_cause.weakness_key", &self.weakness_key, 80)?;
        validate_root_cause_part(
            "root_cause.mechanism",
            &self.mechanism,
            MAX_ROOT_CAUSE_MECHANISM_BYTES,
        )?;
        if self.mechanism.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(ContractError::new(
                "root_cause.mechanism",
                "must be a canonical lowercase cause key",
            ));
        }
        Ok(())
    }
}

impl Debug for RootCauseKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RootCauseKey")
            .field("weakness_key_bytes", &self.weakness_key.len())
            .field("mechanism_bytes", &self.mechanism.len())
            .finish()
    }
}

/// One validated finding and its D-181 evidence bundle binding.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingCorrelationInput {
    finding: CanonicalFinding,
    root_cause: RootCauseKey,
    evidence_bundle_ref: String,
}

impl FindingCorrelationInput {
    pub fn new(
        finding: CanonicalFinding,
        root_cause: RootCauseKey,
        evidence_bundle_ref: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let input = Self {
            finding,
            root_cause,
            evidence_bundle_ref: evidence_bundle_ref.into(),
        };
        input.validate()?;
        Ok(input)
    }

    pub fn finding(&self) -> &CanonicalFinding {
        &self.finding
    }

    pub fn root_cause(&self) -> &RootCauseKey {
        &self.root_cause
    }

    pub fn evidence_bundle_ref(&self) -> &str {
        &self.evidence_bundle_ref
    }

    fn validate(&self) -> Result<(), ContractError> {
        self.finding.validate()?;
        if self.finding.title.truncated() {
            return Err(ContractError::new(
                "title",
                "correlation input title must not be truncated",
            ));
        }
        self.root_cause.validate()?;
        if self.root_cause.weakness_key != self.finding.identity.weakness_key {
            return Err(ContractError::new(
                "root_cause.weakness_key",
                "must match finding identity weakness",
            ));
        }
        validate_prefixed_hash(
            "evidence_bundle_ref",
            &self.evidence_bundle_ref,
            BUNDLE_PREFIX,
        )
    }
}

impl Debug for FindingCorrelationInput {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FindingCorrelationInput")
            .field("finding_id_bytes", &self.finding.finding_id.len())
            .field("root_cause", &self.root_cause)
            .field("evidence_bundle_ref_bytes", &self.evidence_bundle_ref.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorrelationLimits {
    pub max_inputs: usize,
    pub max_groups: usize,
    pub max_references_per_group: usize,
}

impl Default for CorrelationLimits {
    fn default() -> Self {
        Self {
            max_inputs: HARD_MAX_INPUTS,
            max_groups: HARD_MAX_GROUPS,
            max_references_per_group: HARD_MAX_REFERENCES_PER_GROUP,
        }
    }
}

/// One exact endpoint, parameter, and root-cause group.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CorrelatedFinding {
    correlation_key: String,
    identity: FindingIdentity,
    root_cause: RootCauseKey,
    title: RedactedText,
    severity_floor: Severity,
    severity_ceiling: Severity,
    confidence_floor: Confidence,
    confidence_ceiling: Confidence,
    source_finding_ids: Vec<String>,
    evidence_bundle_refs: Vec<String>,
    evidence_refs: Vec<String>,
    provenances: Vec<FindingProvenance>,
}

impl CorrelatedFinding {
    pub fn correlation_key(&self) -> &str {
        &self.correlation_key
    }

    pub fn identity(&self) -> &FindingIdentity {
        &self.identity
    }

    pub fn root_cause(&self) -> &RootCauseKey {
        &self.root_cause
    }

    pub fn title(&self) -> &RedactedText {
        &self.title
    }

    pub fn severity_range(&self) -> (Severity, Severity) {
        (self.severity_floor, self.severity_ceiling)
    }

    pub fn confidence_range(&self) -> (Confidence, Confidence) {
        (self.confidence_floor, self.confidence_ceiling)
    }

    pub fn has_assessment_disagreement(&self) -> bool {
        self.severity_floor != self.severity_ceiling
            || self.confidence_floor != self.confidence_ceiling
    }

    pub fn source_finding_ids(&self) -> &[String] {
        &self.source_finding_ids
    }

    pub fn evidence_bundle_refs(&self) -> &[String] {
        &self.evidence_bundle_refs
    }

    pub fn evidence_refs(&self) -> &[String] {
        &self.evidence_refs
    }

    pub fn provenances(&self) -> &[FindingProvenance] {
        &self.provenances
    }

    fn validate(
        &self,
        context: &CorrelationContext,
        limits: CorrelationLimits,
    ) -> Result<(), ContractError> {
        self.identity.validate()?;
        self.root_cause.validate()?;
        if self.root_cause.weakness_key != self.identity.weakness_key {
            return Err(ContractError::new(
                "root_cause.weakness_key",
                "must match correlated finding weakness",
            ));
        }
        validate_sha256("correlation_key", &self.correlation_key)?;
        if self.correlation_key != correlation_key(context, &self.identity, &self.root_cause) {
            return Err(ContractError::new(
                "correlation_key",
                "does not match endpoint, parameter, and root cause",
            ));
        }
        if self.title.as_str().is_empty() || self.title.truncated() {
            return Err(ContractError::new(
                "title",
                "must be present without truncation",
            ));
        }
        if severity_rank(self.severity_floor) > severity_rank(self.severity_ceiling)
            || confidence_rank(self.confidence_floor) > confidence_rank(self.confidence_ceiling)
        {
            return Err(ContractError::new(
                "assessment_range",
                "floor must not exceed ceiling",
            ));
        }
        validate_sorted_refs(
            "source_finding_ids",
            &self.source_finding_ids,
            limits.max_references_per_group,
            None,
        )?;
        validate_sorted_refs(
            "evidence_bundle_refs",
            &self.evidence_bundle_refs,
            limits.max_references_per_group,
            Some(BUNDLE_PREFIX),
        )?;
        validate_sorted_refs(
            "evidence_refs",
            &self.evidence_refs,
            limits.max_references_per_group,
            None,
        )?;
        if self.provenances.is_empty() || self.provenances.len() > limits.max_references_per_group {
            return Err(ContractError::new(
                "provenances",
                "must be present within correlation limits",
            ));
        }
        let mut previous = None;
        for provenance in &self.provenances {
            provenance.validate()?;
            let key = provenance_key(provenance);
            if previous.as_ref().is_some_and(|value| value >= &key) {
                return Err(ContractError::new(
                    "provenances",
                    "must be strictly sorted and unique",
                ));
            }
            previous = Some(key);
        }
        Ok(())
    }
}

impl Debug for CorrelatedFinding {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CorrelatedFinding")
            .field("correlation_key_bytes", &self.correlation_key.len())
            .field("target_id_bytes", &self.identity.target_id.len())
            .field("endpoint_bytes", &self.identity.canonical_endpoint.len())
            .field("root_cause", &self.root_cause)
            .field("title_bytes", &self.title.as_str().len())
            .field("severity_floor", &self.severity_floor)
            .field("severity_ceiling", &self.severity_ceiling)
            .field("confidence_floor", &self.confidence_floor)
            .field("confidence_ceiling", &self.confidence_ceiling)
            .field("source_count", &self.source_finding_ids.len())
            .field("bundle_count", &self.evidence_bundle_refs.len())
            .field("evidence_count", &self.evidence_refs.len())
            .field("provenance_count", &self.provenances.len())
            .finish()
    }
}

/// Deterministic, integrity-protected result of one correlation run.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CorrelationReport {
    context: CorrelationContext,
    input_count: usize,
    groups: Vec<CorrelatedFinding>,
    fingerprint: String,
}

impl CorrelationReport {
    pub fn context(&self) -> &CorrelationContext {
        &self.context
    }

    pub fn input_count(&self) -> usize {
        self.input_count
    }

    pub fn groups(&self) -> &[CorrelatedFinding] {
        &self.groups
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn validate(&self, limits: CorrelationLimits) -> Result<(), ContractError> {
        validate_limits(limits)?;
        self.context.validate()?;
        if self.input_count == 0
            || self.input_count > limits.max_inputs
            || self.groups.is_empty()
            || self.groups.len() > limits.max_groups
        {
            return Err(ContractError::new(
                "report",
                "input and group counts must be present within limits",
            ));
        }
        let mut previous_key: Option<&str> = None;
        let mut source_ids = BTreeSet::new();
        let mut counted_inputs = 0usize;
        for group in &self.groups {
            group.validate(&self.context, limits)?;
            if previous_key.is_some_and(|value| value >= group.correlation_key.as_str()) {
                return Err(ContractError::new(
                    "groups",
                    "must be strictly sorted and unique",
                ));
            }
            previous_key = Some(&group.correlation_key);
            counted_inputs = counted_inputs
                .checked_add(group.source_finding_ids.len())
                .ok_or_else(|| ContractError::new("input_count", "count overflow"))?;
            for finding_id in &group.source_finding_ids {
                if !source_ids.insert(finding_id) {
                    return Err(ContractError::new(
                        "source_finding_ids",
                        "finding ID cannot appear in multiple groups",
                    ));
                }
            }
        }
        if counted_inputs != self.input_count {
            return Err(ContractError::new(
                "input_count",
                "must equal grouped source finding count",
            ));
        }
        validate_sha256("fingerprint", &self.fingerprint)?;
        if self.fingerprint != self.compute_fingerprint() {
            return Err(ContractError::new(
                "fingerprint",
                "correlation report integrity fingerprint does not match",
            ));
        }
        Ok(())
    }

    fn compute_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "aegis.finding.correlation.v1");
        hash_field(&mut hasher, &self.context.tenant_ref);
        hash_field(&mut hasher, &self.context.scan_ref);
        hash_field(&mut hasher, &self.input_count.to_string());
        hash_field(&mut hasher, &self.groups.len().to_string());
        for group in &self.groups {
            hash_group(&mut hasher, group);
        }
        format!("{:x}", hasher.finalize())
    }
}

impl Debug for CorrelationReport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CorrelationReport")
            .field("context", &self.context)
            .field("input_count", &self.input_count)
            .field("group_count", &self.groups.len())
            .field("fingerprint_bytes", &self.fingerprint.len())
            .finish()
    }
}

struct GroupAccumulator {
    identity: FindingIdentity,
    root_cause: RootCauseKey,
    titles: BTreeMap<String, RedactedText>,
    severity_floor: Severity,
    severity_ceiling: Severity,
    confidence_floor: Confidence,
    confidence_ceiling: Confidence,
    source_finding_ids: BTreeSet<String>,
    evidence_bundle_refs: BTreeSet<String>,
    evidence_refs: BTreeSet<String>,
    provenances: BTreeMap<(String, String, String), FindingProvenance>,
}

impl GroupAccumulator {
    fn new(input: &FindingCorrelationInput) -> Self {
        let finding = &input.finding;
        let mut titles = BTreeMap::new();
        titles.insert(finding.title.as_str().to_string(), finding.title.clone());
        let mut source_finding_ids = BTreeSet::new();
        source_finding_ids.insert(finding.finding_id.clone());
        let mut evidence_bundle_refs = BTreeSet::new();
        evidence_bundle_refs.insert(input.evidence_bundle_ref.clone());
        let evidence_refs = finding.evidence_refs.iter().cloned().collect();
        let mut provenances = BTreeMap::new();
        provenances.insert(
            provenance_key(&finding.provenance),
            finding.provenance.clone(),
        );
        Self {
            identity: finding.identity.clone(),
            root_cause: input.root_cause.clone(),
            titles,
            severity_floor: finding.severity,
            severity_ceiling: finding.severity,
            confidence_floor: finding.confidence,
            confidence_ceiling: finding.confidence,
            source_finding_ids,
            evidence_bundle_refs,
            evidence_refs,
            provenances,
        }
    }

    fn merge(
        &mut self,
        input: &FindingCorrelationInput,
        limits: CorrelationLimits,
    ) -> Result<(), ContractError> {
        if self.identity != input.finding.identity || self.root_cause != input.root_cause {
            return Err(ContractError::new(
                "correlation_key",
                "hash collision across different finding identities",
            ));
        }
        if !self
            .source_finding_ids
            .insert(input.finding.finding_id.clone())
        {
            return Err(ContractError::new(
                "finding_id",
                "duplicate correlation input",
            ));
        }
        self.titles.insert(
            input.finding.title.as_str().to_string(),
            input.finding.title.clone(),
        );
        self.evidence_bundle_refs
            .insert(input.evidence_bundle_ref.clone());
        self.evidence_refs
            .extend(input.finding.evidence_refs.iter().cloned());
        self.provenances.insert(
            provenance_key(&input.finding.provenance),
            input.finding.provenance.clone(),
        );
        if self.source_finding_ids.len() > limits.max_references_per_group
            || self.evidence_bundle_refs.len() > limits.max_references_per_group
            || self.evidence_refs.len() > limits.max_references_per_group
            || self.provenances.len() > limits.max_references_per_group
        {
            return Err(ContractError::new(
                "group",
                "merged references exceed correlation limits",
            ));
        }
        self.severity_floor = min_severity(self.severity_floor, input.finding.severity);
        self.severity_ceiling = max_severity(self.severity_ceiling, input.finding.severity);
        self.confidence_floor = min_confidence(self.confidence_floor, input.finding.confidence);
        self.confidence_ceiling = max_confidence(self.confidence_ceiling, input.finding.confidence);
        Ok(())
    }

    fn finish(self, correlation_key: String) -> CorrelatedFinding {
        let title = self
            .titles
            .into_values()
            .next()
            .expect("every correlation group has at least one title");
        CorrelatedFinding {
            correlation_key,
            identity: self.identity,
            root_cause: self.root_cause,
            title,
            severity_floor: self.severity_floor,
            severity_ceiling: self.severity_ceiling,
            confidence_floor: self.confidence_floor,
            confidence_ceiling: self.confidence_ceiling,
            source_finding_ids: self.source_finding_ids.into_iter().collect(),
            evidence_bundle_refs: self.evidence_bundle_refs.into_iter().collect(),
            evidence_refs: self.evidence_refs.into_iter().collect(),
            provenances: self.provenances.into_values().collect(),
        }
    }
}

/// Correlates duplicate findings inside one tenant and scan boundary.
pub fn correlate_findings(
    context: CorrelationContext,
    inputs: Vec<FindingCorrelationInput>,
    limits: CorrelationLimits,
) -> Result<CorrelationReport, ContractError> {
    validate_limits(limits)?;
    context.validate()?;
    if inputs.is_empty() || inputs.len() > limits.max_inputs {
        return Err(ContractError::new(
            "inputs",
            "must be present within correlation limits",
        ));
    }
    let mut seen_finding_ids = BTreeSet::new();
    let mut accumulators = BTreeMap::<String, GroupAccumulator>::new();
    for input in &inputs {
        input.validate()?;
        if !seen_finding_ids.insert(input.finding.finding_id.as_str()) {
            return Err(ContractError::new(
                "finding_id",
                "duplicate correlation input",
            ));
        }
        let key = correlation_key(&context, &input.finding.identity, &input.root_cause);
        if let Some(accumulator) = accumulators.get_mut(&key) {
            accumulator.merge(input, limits)?;
        } else {
            if accumulators.len() >= limits.max_groups {
                return Err(ContractError::new(
                    "groups",
                    "correlation group limit exceeded",
                ));
            }
            accumulators.insert(key, GroupAccumulator::new(input));
        }
    }
    let groups = accumulators
        .into_iter()
        .map(|(key, accumulator)| accumulator.finish(key))
        .collect::<Vec<_>>();
    let mut report = CorrelationReport {
        context,
        input_count: inputs.len(),
        groups,
        fingerprint: String::new(),
    };
    report.fingerprint = report.compute_fingerprint();
    report.validate(limits)?;
    Ok(report)
}

fn correlation_key(
    context: &CorrelationContext,
    identity: &FindingIdentity,
    root_cause: &RootCauseKey,
) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "aegis.finding.correlation-key.v1");
    hash_field(&mut hasher, &context.tenant_ref);
    hash_field(&mut hasher, &context.scan_ref);
    hash_field(&mut hasher, &identity.target_id);
    hash_field(&mut hasher, method_tag(identity.method));
    hash_field(&mut hasher, &identity.canonical_endpoint);
    hash_field(
        &mut hasher,
        parameter_location_tag(identity.parameter_location),
    );
    hash_field(
        &mut hasher,
        identity.parameter_name.as_deref().unwrap_or("none"),
    );
    hash_field(&mut hasher, &root_cause.weakness_key);
    hash_field(&mut hasher, &root_cause.mechanism);
    format!("{:x}", hasher.finalize())
}

fn hash_group(hasher: &mut Sha256, group: &CorrelatedFinding) {
    hash_field(hasher, "group");
    hash_field(hasher, &group.correlation_key);
    hash_field(hasher, &group.identity.fingerprint());
    hash_field(hasher, &group.root_cause.weakness_key);
    hash_field(hasher, &group.root_cause.mechanism);
    hash_field(hasher, group.title.as_str());
    hash_field(hasher, severity_tag(group.severity_floor));
    hash_field(hasher, severity_tag(group.severity_ceiling));
    hash_field(hasher, confidence_tag(group.confidence_floor));
    hash_field(hasher, confidence_tag(group.confidence_ceiling));
    hash_field(hasher, "source_finding_ids");
    hash_field(hasher, &group.source_finding_ids.len().to_string());
    for value in &group.source_finding_ids {
        hash_field(hasher, value);
    }
    hash_field(hasher, "evidence_bundle_refs");
    hash_field(hasher, &group.evidence_bundle_refs.len().to_string());
    for value in &group.evidence_bundle_refs {
        hash_field(hasher, value);
    }
    hash_field(hasher, "evidence_refs");
    hash_field(hasher, &group.evidence_refs.len().to_string());
    for value in &group.evidence_refs {
        hash_field(hasher, value);
    }
    hash_field(hasher, "provenances");
    hash_field(hasher, &group.provenances.len().to_string());
    for provenance in &group.provenances {
        hash_field(hasher, &provenance.source_engine);
        hash_field(hasher, &provenance.rule_id);
        hash_field(hasher, &provenance.rule_version);
    }
}

fn validate_limits(limits: CorrelationLimits) -> Result<(), ContractError> {
    if limits.max_inputs == 0
        || limits.max_inputs > HARD_MAX_INPUTS
        || limits.max_groups == 0
        || limits.max_groups > HARD_MAX_GROUPS
        || limits.max_references_per_group == 0
        || limits.max_references_per_group > HARD_MAX_REFERENCES_PER_GROUP
    {
        return Err(ContractError::new(
            "limits",
            "correlation limits exceed hard policy",
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

fn validate_root_cause_part(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ContractError::new(
            field,
            "must be a bounded scanner-independent cause key",
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

fn validate_sorted_refs(
    field: &'static str,
    values: &[String],
    max_values: usize,
    required_prefix: Option<&str>,
) -> Result<(), ContractError> {
    if values.is_empty() || values.len() > max_values {
        return Err(ContractError::new(
            field,
            "must be present within correlation limits",
        ));
    }
    let mut previous: Option<&str> = None;
    for value in values {
        if let Some(prefix) = required_prefix {
            validate_prefixed_hash(field, value, prefix)?;
        } else if value.is_empty()
            || value.len() > 64
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(ContractError::new(field, "contains an invalid reference"));
        }
        if previous.is_some_and(|existing| existing >= value.as_str()) {
            return Err(ContractError::new(
                field,
                "must be strictly sorted and unique",
            ));
        }
        previous = Some(value);
    }
    Ok(())
}

fn provenance_key(provenance: &FindingProvenance) -> (String, String, String) {
    (
        provenance.source_engine.clone(),
        provenance.rule_id.clone(),
        provenance.rule_version.clone(),
    )
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn method_tag(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Head => "HEAD",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Post => "POST",
    }
}

fn parameter_location_tag(location: ParameterLocation) -> &'static str {
    match location {
        ParameterLocation::None => "none",
        ParameterLocation::Path => "path",
        ParameterLocation::Query => "query",
        ParameterLocation::Header => "header",
        ParameterLocation::Cookie => "cookie",
        ParameterLocation::Form => "form",
        ParameterLocation::JsonBody => "json_body",
        ParameterLocation::ResponseHeader => "response_header",
        ParameterLocation::ResponseBody => "response_body",
        ParameterLocation::Transport => "transport",
    }
}

fn severity_rank(value: Severity) -> u8 {
    match value {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn severity_tag(value: Severity) -> &'static str {
    match value {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn confidence_rank(value: Confidence) -> u8 {
    match value {
        Confidence::Low => 0,
        Confidence::Medium => 1,
        Confidence::High => 2,
    }
}

fn confidence_tag(value: Confidence) -> &'static str {
    match value {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

fn min_severity(left: Severity, right: Severity) -> Severity {
    if severity_rank(left) <= severity_rank(right) {
        left
    } else {
        right
    }
}

fn max_severity(left: Severity, right: Severity) -> Severity {
    if severity_rank(left) >= severity_rank(right) {
        left
    } else {
        right
    }
}

fn min_confidence(left: Confidence, right: Confidence) -> Confidence {
    if confidence_rank(left) <= confidence_rank(right) {
        left
    } else {
        right
    }
}

fn max_confidence(left: Confidence, right: Confidence) -> Confidence {
    if confidence_rank(left) >= confidence_rank(right) {
        left
    } else {
        right
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        CanonicalFinding, Confidence, FindingIdentity, FindingProvenance, HttpMethod,
        ParameterLocation, Severity,
    };

    use super::{
        correlate_findings, CorrelationContext, CorrelationLimits, FindingCorrelationInput,
        RootCauseKey,
    };

    const TENANT: &str = "tenant_0123456789abcdef0123456789abcdef";
    const SCAN: &str = "scan_0123456789abcdef0123456789abcdef";
    const OTHER_SCAN: &str = "scan_abcdef0123456789abcdef0123456789";
    const BUNDLE_A: &str = "bundle_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BUNDLE_B: &str = "bundle_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const BUNDLE_C: &str = "bundle_cccccccccccccccccccccccccccccccc";

    fn context(scan_ref: &str) -> CorrelationContext {
        CorrelationContext::new(TENANT, scan_ref).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn input(
        finding_id: &str,
        endpoint: &str,
        parameter_name: &str,
        mechanism: &str,
        source_engine: &str,
        severity: Severity,
        confidence: Confidence,
        bundle_ref: &str,
    ) -> FindingCorrelationInput {
        let identity = FindingIdentity::new(
            "target-1",
            HttpMethod::Get,
            endpoint,
            "CWE-89",
            ParameterLocation::Query,
            Some(parameter_name.to_string()),
        )
        .unwrap();
        let finding = CanonicalFinding::new(
            finding_id,
            identity,
            &format!("{source_engine} SQL injection candidate"),
            severity,
            confidence,
            vec![format!("evidence-{finding_id}")],
            FindingProvenance::new(source_engine, "sqli_error", "1.0.0").unwrap(),
        )
        .unwrap();
        FindingCorrelationInput::new(
            finding,
            RootCauseKey::new("CWE-89", mechanism).unwrap(),
            bundle_ref,
        )
        .unwrap()
    }

    fn first_input() -> FindingCorrelationInput {
        input(
            "finding-native",
            "https://example.com/api/users/123?id=1&sort=asc",
            "id",
            "unsafe_sql_interpolation",
            "aegis_native",
            Severity::High,
            Confidence::High,
            BUNDLE_A,
        )
    }

    fn duplicate_input() -> FindingCorrelationInput {
        input(
            "finding-imported",
            "https://example.com/api/users/456?sort=desc&id=999",
            "id",
            "unsafe_sql_interpolation",
            "nuclei_import",
            Severity::Medium,
            Confidence::Low,
            BUNDLE_B,
        )
    }

    #[test]
    fn exact_identity_and_root_cause_merge_without_hiding_assessment_range() {
        let report = correlate_findings(
            context(SCAN),
            vec![duplicate_input(), first_input()],
            CorrelationLimits::default(),
        )
        .unwrap();
        assert_eq!(report.input_count(), 2);
        assert_eq!(report.groups().len(), 1);
        let group = &report.groups()[0];
        assert_eq!(group.source_finding_ids().len(), 2);
        assert_eq!(group.evidence_bundle_refs(), &[BUNDLE_A, BUNDLE_B]);
        assert_eq!(group.evidence_refs().len(), 2);
        assert_eq!(group.provenances().len(), 2);
        assert_eq!(group.severity_range(), (Severity::Medium, Severity::High));
        assert_eq!(
            group.confidence_range(),
            (Confidence::Low, Confidence::High)
        );
        assert!(group.has_assessment_disagreement());
        assert!(group.identity().canonical_endpoint.ends_with("?id&sort"));

        let serialized = serde_json::to_string(&report).unwrap();
        let restored = serde_json::from_str(&serialized).unwrap();
        assert_eq!(report, restored);
        assert!(report.validate(CorrelationLimits::default()).is_ok());
    }

    #[test]
    fn parameter_and_concrete_root_cause_prevent_false_merges() {
        let different_parameter = input(
            "finding-sort",
            "https://example.com/api/users/999?id=1&sort=asc",
            "sort",
            "unsafe_sql_interpolation",
            "aegis_native",
            Severity::High,
            Confidence::Medium,
            BUNDLE_B,
        );
        let different_mechanism = input(
            "finding-timing",
            "https://example.com/api/users/777?id=2&sort=desc",
            "id",
            "unsafe_stored_procedure_parameter",
            "aegis_native",
            Severity::High,
            Confidence::Medium,
            BUNDLE_C,
        );
        let report = correlate_findings(
            context(SCAN),
            vec![first_input(), different_parameter, different_mechanism],
            CorrelationLimits::default(),
        )
        .unwrap();
        assert_eq!(report.groups().len(), 3);
    }

    #[test]
    fn tenant_and_scan_context_are_part_of_the_correlation_key() {
        let first = correlate_findings(
            context(SCAN),
            vec![first_input()],
            CorrelationLimits::default(),
        )
        .unwrap();
        let other_scan = correlate_findings(
            context(OTHER_SCAN),
            vec![first_input()],
            CorrelationLimits::default(),
        )
        .unwrap();
        assert_ne!(
            first.groups()[0].correlation_key(),
            other_scan.groups()[0].correlation_key()
        );
        assert_ne!(first.fingerprint(), other_scan.fingerprint());
    }

    #[test]
    fn invalid_bundle_root_cause_and_duplicate_inputs_fail_closed() {
        let error = RootCauseKey::new("CWE-89", "Unsafe_SQL_Interpolation").unwrap_err();
        assert_eq!(error.field(), "root_cause.mechanism");
        let finding = first_input().finding().clone();
        let error = FindingCorrelationInput::new(
            finding.clone(),
            RootCauseKey::new("CWE-79", "unsafe_sql_interpolation").unwrap(),
            BUNDLE_A,
        )
        .unwrap_err();
        assert_eq!(error.field(), "root_cause.weakness_key");
        let error = FindingCorrelationInput::new(
            finding,
            RootCauseKey::new("CWE-89", "unsafe_sql_interpolation").unwrap(),
            "bundle-invalid",
        )
        .unwrap_err();
        assert_eq!(error.field(), "evidence_bundle_ref");

        let duplicate = first_input();
        let error = correlate_findings(
            context(SCAN),
            vec![duplicate.clone(), duplicate],
            CorrelationLimits::default(),
        )
        .unwrap_err();
        assert_eq!(error.field(), "finding_id");
    }

    #[test]
    fn ordering_is_deterministic_and_nested_tampering_breaks_integrity() {
        let first = correlate_findings(
            context(SCAN),
            vec![first_input(), duplicate_input()],
            CorrelationLimits::default(),
        )
        .unwrap();
        let reversed = correlate_findings(
            context(SCAN),
            vec![duplicate_input(), first_input()],
            CorrelationLimits::default(),
        )
        .unwrap();
        assert_eq!(first, reversed);

        let mut tampered = first;
        tampered.groups[0]
            .evidence_refs
            .push("evidence-tampered".to_string());
        tampered.groups[0].evidence_refs.sort();
        assert_eq!(
            tampered
                .validate(CorrelationLimits::default())
                .unwrap_err()
                .field(),
            "fingerprint"
        );
    }

    #[test]
    fn group_and_reference_limits_and_debug_output_are_bounded() {
        let separate = input(
            "finding-separate",
            "https://example.com/api/orders/123?id=1",
            "id",
            "unsafe_sql_interpolation",
            "aegis_native",
            Severity::High,
            Confidence::Medium,
            BUNDLE_C,
        );
        let error = correlate_findings(
            context(SCAN),
            vec![first_input(), separate],
            CorrelationLimits {
                max_inputs: 2,
                max_groups: 1,
                max_references_per_group: 2,
            },
        )
        .unwrap_err();
        assert_eq!(error.field(), "groups");
        let error = correlate_findings(
            context(SCAN),
            vec![first_input(), duplicate_input()],
            CorrelationLimits {
                max_inputs: 2,
                max_groups: 2,
                max_references_per_group: 1,
            },
        )
        .unwrap_err();
        assert_eq!(error.field(), "group");

        let report = correlate_findings(
            context(SCAN),
            vec![first_input()],
            CorrelationLimits::default(),
        )
        .unwrap();
        let debug = format!("{report:?} {:?}", report.groups()[0]);
        assert!(!debug.contains("example.com"));
        assert!(!debug.contains(TENANT));
        assert!(!debug.contains(SCAN));
        assert!(!debug.contains(BUNDLE_A));
        assert!(!debug.contains("SQL injection candidate"));
    }
}
