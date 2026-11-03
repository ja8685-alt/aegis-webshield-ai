use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    Confidence, ContractError, CorrelatedFinding, CorrelationContext, CorrelationLimits,
    CorrelationReport, FindingProvenance,
};

const RULE_PROFILE_PREFIX: &str = "ruleprofile_";
const NOISE_PROFILE_PREFIX: &str = "noise_";
const HARD_MAX_PROFILES: usize = 512;
const HARD_MAX_SAMPLES: u64 = 1_000_000;
const MIN_CALIBRATION_SAMPLES: u64 = 20;
const MIN_STABILITY_SAMPLES: u64 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RulePrecisionClass {
    High,
    Acceptable,
    Low,
    Uncalibrated,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RulePrecisionProfile {
    profile_ref: String,
    provenance: FindingProvenance,
    confirmed_count: u64,
    false_positive_count: u64,
    insufficient_evidence_count: u64,
    precision_basis_points: Option<u16>,
    class: RulePrecisionClass,
}

impl RulePrecisionProfile {
    pub fn new(
        profile_ref: impl Into<String>,
        provenance: FindingProvenance,
        confirmed_count: u64,
        false_positive_count: u64,
        insufficient_evidence_count: u64,
    ) -> Result<Self, ContractError> {
        let labeled = confirmed_count
            .checked_add(false_positive_count)
            .ok_or_else(|| ContractError::new("samples", "rule precision sample count overflow"))?;
        let total = labeled
            .checked_add(insufficient_evidence_count)
            .ok_or_else(|| ContractError::new("samples", "rule sample count overflow"))?;
        if total == 0 || total > HARD_MAX_SAMPLES {
            return Err(ContractError::new(
                "samples",
                "rule profile requires one to one million bounded samples",
            ));
        }
        let precision_basis_points = calculate_precision(confirmed_count, labeled);
        let class = classify_rule_precision(labeled, precision_basis_points);
        let profile = Self {
            profile_ref: profile_ref.into(),
            provenance,
            confirmed_count,
            false_positive_count,
            insufficient_evidence_count,
            precision_basis_points,
            class,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn profile_ref(&self) -> &str {
        &self.profile_ref
    }

    pub fn provenance(&self) -> &FindingProvenance {
        &self.provenance
    }

    pub fn precision_basis_points(&self) -> Option<u16> {
        self.precision_basis_points
    }

    pub fn class(&self) -> RulePrecisionClass {
        self.class
    }

    pub fn sample_count(&self) -> u64 {
        self.confirmed_count + self.false_positive_count + self.insufficient_evidence_count
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_prefixed_hash("profile_ref", &self.profile_ref, RULE_PROFILE_PREFIX)?;
        self.provenance.validate()?;
        let labeled = self
            .confirmed_count
            .checked_add(self.false_positive_count)
            .ok_or_else(|| ContractError::new("samples", "rule sample count overflow"))?;
        let total = labeled
            .checked_add(self.insufficient_evidence_count)
            .ok_or_else(|| ContractError::new("samples", "rule sample count overflow"))?;
        if total == 0 || total > HARD_MAX_SAMPLES {
            return Err(ContractError::new(
                "samples",
                "rule sample count is invalid",
            ));
        }
        let expected_precision = calculate_precision(self.confirmed_count, labeled);
        if self.precision_basis_points != expected_precision
            || self.class != classify_rule_precision(labeled, expected_precision)
        {
            return Err(ContractError::new(
                "precision",
                "stored precision classification does not match samples",
            ));
        }
        Ok(())
    }
}

impl Debug for RulePrecisionProfile {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RulePrecisionProfile")
            .field("profile_ref_bytes", &self.profile_ref.len())
            .field("sample_count", &self.sample_count())
            .field("precision_basis_points", &self.precision_basis_points)
            .field("class", &self.class)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetStabilityClass {
    Stable,
    Variable,
    Unstable,
    Insufficient,
    Missing,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TargetNoiseProfile {
    profile_ref: String,
    context: CorrelationContext,
    target_id: String,
    observed_samples: u64,
    unstable_samples: u64,
    timeout_samples: u64,
    status_variance_samples: u64,
    body_variance_samples: u64,
    instability_basis_points: u16,
    timeout_basis_points: u16,
    class: TargetStabilityClass,
}

impl TargetNoiseProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_ref: impl Into<String>,
        context: CorrelationContext,
        target_id: impl Into<String>,
        observed_samples: u64,
        unstable_samples: u64,
        timeout_samples: u64,
        status_variance_samples: u64,
        body_variance_samples: u64,
    ) -> Result<Self, ContractError> {
        validate_noise_counts(
            observed_samples,
            unstable_samples,
            timeout_samples,
            status_variance_samples,
            body_variance_samples,
        )?;
        let instability_basis_points = ((unstable_samples * 10_000) / observed_samples) as u16;
        let timeout_basis_points = ((timeout_samples * 10_000) / observed_samples) as u16;
        let class = classify_target_stability(
            observed_samples,
            instability_basis_points,
            timeout_basis_points,
        );
        let profile = Self {
            profile_ref: profile_ref.into(),
            context,
            target_id: target_id.into(),
            observed_samples,
            unstable_samples,
            timeout_samples,
            status_variance_samples,
            body_variance_samples,
            instability_basis_points,
            timeout_basis_points,
            class,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn profile_ref(&self) -> &str {
        &self.profile_ref
    }

    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    pub fn instability_basis_points(&self) -> u16 {
        self.instability_basis_points
    }

    pub fn class(&self) -> TargetStabilityClass {
        self.class
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_prefixed_hash("profile_ref", &self.profile_ref, NOISE_PROFILE_PREFIX)?;
        CorrelationContext::new(self.context.tenant_ref(), self.context.scan_ref())?;
        validate_opaque("target_id", &self.target_id, 64)?;
        validate_noise_counts(
            self.observed_samples,
            self.unstable_samples,
            self.timeout_samples,
            self.status_variance_samples,
            self.body_variance_samples,
        )?;
        let instability = ((self.unstable_samples * 10_000) / self.observed_samples) as u16;
        let timeout = ((self.timeout_samples * 10_000) / self.observed_samples) as u16;
        if self.instability_basis_points != instability
            || self.timeout_basis_points != timeout
            || self.class != classify_target_stability(self.observed_samples, instability, timeout)
        {
            return Err(ContractError::new(
                "noise_classification",
                "stored target stability does not match samples",
            ));
        }
        Ok(())
    }
}

impl Debug for TargetNoiseProfile {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TargetNoiseProfile")
            .field("profile_ref_bytes", &self.profile_ref.len())
            .field("context", &self.context)
            .field("target_id_bytes", &self.target_id.len())
            .field("observed_samples", &self.observed_samples)
            .field("instability_basis_points", &self.instability_basis_points)
            .field("timeout_basis_points", &self.timeout_basis_points)
            .field("class", &self.class)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleReliability {
    High,
    Acceptable,
    Low,
    Uncalibrated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceDisposition {
    Retained,
    Reduced,
    UnstableTarget,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceAdjustment {
    correlation_key: String,
    original_floor: Confidence,
    original_ceiling: Confidence,
    adjusted_floor: Confidence,
    adjusted_ceiling: Confidence,
    rule_reliability: RuleReliability,
    target_stability: TargetStabilityClass,
    unstable_target: bool,
    disposition: ConfidenceDisposition,
    rule_profile_refs: Vec<String>,
    noise_profile_ref: Option<String>,
}

impl ConfidenceAdjustment {
    pub fn correlation_key(&self) -> &str {
        &self.correlation_key
    }

    pub fn adjusted_range(&self) -> (Confidence, Confidence) {
        (self.adjusted_floor, self.adjusted_ceiling)
    }

    pub fn rule_reliability(&self) -> RuleReliability {
        self.rule_reliability
    }

    pub fn target_stability(&self) -> TargetStabilityClass {
        self.target_stability
    }

    pub fn unstable_target(&self) -> bool {
        self.unstable_target
    }

    pub fn disposition(&self) -> ConfidenceDisposition {
        self.disposition
    }
}

impl Debug for ConfidenceAdjustment {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfidenceAdjustment")
            .field("correlation_key_bytes", &self.correlation_key.len())
            .field("original_floor", &self.original_floor)
            .field("original_ceiling", &self.original_ceiling)
            .field("adjusted_floor", &self.adjusted_floor)
            .field("adjusted_ceiling", &self.adjusted_ceiling)
            .field("rule_reliability", &self.rule_reliability)
            .field("target_stability", &self.target_stability)
            .field("unstable_target", &self.unstable_target)
            .field("disposition", &self.disposition)
            .field("rule_profile_count", &self.rule_profile_refs.len())
            .field("has_noise_profile", &self.noise_profile_ref.is_some())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfidenceAdjustmentLimits {
    pub max_rule_profiles: usize,
    pub max_noise_profiles: usize,
}

impl Default for ConfidenceAdjustmentLimits {
    fn default() -> Self {
        Self {
            max_rule_profiles: HARD_MAX_PROFILES,
            max_noise_profiles: HARD_MAX_PROFILES,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceAdjustmentReport {
    context: CorrelationContext,
    correlation_report_fingerprint: String,
    adjustments: Vec<ConfidenceAdjustment>,
    fingerprint: String,
}

impl ConfidenceAdjustmentReport {
    pub fn adjustments(&self) -> &[ConfidenceAdjustment] {
        &self.adjustments
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn validate(&self, correlation: &CorrelationReport) -> Result<(), ContractError> {
        correlation.validate(CorrelationLimits::default())?;
        if self.context != *correlation.context()
            || self.correlation_report_fingerprint != correlation.fingerprint()
            || self.adjustments.len() != correlation.groups().len()
        {
            return Err(ContractError::new(
                "correlation_report",
                "adjustment report must match exact correlation report",
            ));
        }
        for (adjustment, group) in self.adjustments.iter().zip(correlation.groups()) {
            validate_adjustment(adjustment, group)?;
        }
        validate_sha256("fingerprint", &self.fingerprint)?;
        if self.fingerprint != self.compute_fingerprint() {
            return Err(ContractError::new(
                "fingerprint",
                "confidence adjustment integrity fingerprint does not match",
            ));
        }
        Ok(())
    }

    fn compute_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "aegis.confidence.adjustment.v1");
        hash_field(&mut hasher, self.context.tenant_ref());
        hash_field(&mut hasher, self.context.scan_ref());
        hash_field(&mut hasher, &self.correlation_report_fingerprint);
        hash_field(&mut hasher, &self.adjustments.len().to_string());
        for adjustment in &self.adjustments {
            hash_adjustment(&mut hasher, adjustment);
        }
        format!("{:x}", hasher.finalize())
    }
}

impl Debug for ConfidenceAdjustmentReport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfidenceAdjustmentReport")
            .field("context", &self.context)
            .field(
                "correlation_fingerprint_bytes",
                &self.correlation_report_fingerprint.len(),
            )
            .field("adjustment_count", &self.adjustments.len())
            .field("fingerprint_bytes", &self.fingerprint.len())
            .finish()
    }
}

pub fn adjust_confidence(
    correlation: &CorrelationReport,
    rule_profiles: Vec<RulePrecisionProfile>,
    noise_profiles: Vec<TargetNoiseProfile>,
    limits: ConfidenceAdjustmentLimits,
) -> Result<ConfidenceAdjustmentReport, ContractError> {
    validate_adjustment_limits(limits)?;
    correlation.validate(CorrelationLimits::default())?;
    if rule_profiles.len() > limits.max_rule_profiles
        || noise_profiles.len() > limits.max_noise_profiles
    {
        return Err(ContractError::new("profiles", "profile limit exceeded"));
    }
    let mut rules = BTreeMap::new();
    let mut rule_refs = BTreeSet::new();
    for profile in rule_profiles {
        profile.validate()?;
        if !rule_refs.insert(profile.profile_ref.clone())
            || rules
                .insert(provenance_key(&profile.provenance), profile)
                .is_some()
        {
            return Err(ContractError::new(
                "rule_profiles",
                "duplicate rule profile",
            ));
        }
    }
    let mut noise = BTreeMap::new();
    let mut noise_refs = BTreeSet::new();
    for profile in noise_profiles {
        profile.validate()?;
        if profile.context != *correlation.context() {
            return Err(ContractError::new(
                "noise_profile.context",
                "must match correlation context",
            ));
        }
        if !noise_refs.insert(profile.profile_ref.clone())
            || noise.insert(profile.target_id.clone(), profile).is_some()
        {
            return Err(ContractError::new(
                "noise_profiles",
                "duplicate target noise profile",
            ));
        }
    }
    let adjustments = correlation
        .groups()
        .iter()
        .map(|group| build_adjustment(group, &rules, &noise))
        .collect::<Vec<_>>();
    let used_rule_refs = adjustments
        .iter()
        .flat_map(|adjustment| adjustment.rule_profile_refs.iter().cloned())
        .collect::<BTreeSet<_>>();
    let used_noise_refs = adjustments
        .iter()
        .filter_map(|adjustment| adjustment.noise_profile_ref.clone())
        .collect::<BTreeSet<_>>();
    if used_rule_refs != rule_refs || used_noise_refs != noise_refs {
        return Err(ContractError::new(
            "profiles",
            "every supplied profile must match a correlated finding",
        ));
    }
    let mut report = ConfidenceAdjustmentReport {
        context: correlation.context().clone(),
        correlation_report_fingerprint: correlation.fingerprint().to_string(),
        adjustments,
        fingerprint: String::new(),
    };
    report.fingerprint = report.compute_fingerprint();
    report.validate(correlation)?;
    Ok(report)
}

fn build_adjustment(
    group: &CorrelatedFinding,
    rules: &BTreeMap<(String, String, String), RulePrecisionProfile>,
    noise: &BTreeMap<String, TargetNoiseProfile>,
) -> ConfidenceAdjustment {
    let (original_floor, original_ceiling) = group.confidence_range();
    let mut classes = Vec::new();
    let mut rule_profile_refs = Vec::new();
    for provenance in group.provenances() {
        if let Some(profile) = rules.get(&provenance_key(provenance)) {
            classes.push(profile.class);
            rule_profile_refs.push(profile.profile_ref.clone());
        } else {
            classes.push(RulePrecisionClass::Uncalibrated);
        }
    }
    rule_profile_refs.sort();
    rule_profile_refs.dedup();
    let rule_reliability = combined_reliability(&classes);
    let target_profile = noise.get(&group.identity().target_id);
    let target_stability = target_profile
        .map(|profile| profile.class)
        .unwrap_or(TargetStabilityClass::Missing);
    let unstable_target = target_stability == TargetStabilityClass::Unstable;
    let reductions = rule_reduction(rule_reliability) + noise_reduction(target_stability);
    let adjusted_floor = reduce_confidence(original_floor, reductions);
    let adjusted_ceiling = reduce_confidence(original_ceiling, reductions);
    let disposition = if unstable_target {
        ConfidenceDisposition::UnstableTarget
    } else if adjusted_floor != original_floor || adjusted_ceiling != original_ceiling {
        ConfidenceDisposition::Reduced
    } else {
        ConfidenceDisposition::Retained
    };
    ConfidenceAdjustment {
        correlation_key: group.correlation_key().to_string(),
        original_floor,
        original_ceiling,
        adjusted_floor,
        adjusted_ceiling,
        rule_reliability,
        target_stability,
        unstable_target,
        disposition,
        rule_profile_refs,
        noise_profile_ref: target_profile.map(|profile| profile.profile_ref.clone()),
    }
}

fn validate_adjustment(
    adjustment: &ConfidenceAdjustment,
    group: &CorrelatedFinding,
) -> Result<(), ContractError> {
    if adjustment.correlation_key != group.correlation_key() {
        return Err(ContractError::new(
            "correlation_key",
            "adjustment order or correlation key does not match",
        ));
    }
    let (floor, ceiling) = group.confidence_range();
    let expected_reductions =
        rule_reduction(adjustment.rule_reliability) + noise_reduction(adjustment.target_stability);
    if adjustment.original_floor != floor
        || adjustment.original_ceiling != ceiling
        || adjustment.adjusted_floor != reduce_confidence(floor, expected_reductions)
        || adjustment.adjusted_ceiling != reduce_confidence(ceiling, expected_reductions)
        || confidence_rank(adjustment.adjusted_floor) > confidence_rank(adjustment.adjusted_ceiling)
        || adjustment.unstable_target
            != (adjustment.target_stability == TargetStabilityClass::Unstable)
    {
        return Err(ContractError::new(
            "confidence_adjustment",
            "adjustment must only retain or reduce source confidence",
        ));
    }
    validate_sorted_profile_refs(&adjustment.rule_profile_refs, RULE_PROFILE_PREFIX)?;
    if adjustment.rule_reliability != RuleReliability::Uncalibrated
        && adjustment.rule_profile_refs.is_empty()
    {
        return Err(ContractError::new(
            "rule_profile_refs",
            "calibrated reliability requires a profile reference",
        ));
    }
    if let Some(reference) = &adjustment.noise_profile_ref {
        validate_prefixed_hash("noise_profile_ref", reference, NOISE_PROFILE_PREFIX)?;
    }
    if (adjustment.target_stability == TargetStabilityClass::Missing)
        != adjustment.noise_profile_ref.is_none()
    {
        return Err(ContractError::new(
            "noise_profile_ref",
            "missing stability and profile reference must agree",
        ));
    }
    let expected_disposition = if adjustment.unstable_target {
        ConfidenceDisposition::UnstableTarget
    } else if adjustment.adjusted_floor != floor || adjustment.adjusted_ceiling != ceiling {
        ConfidenceDisposition::Reduced
    } else {
        ConfidenceDisposition::Retained
    };
    if adjustment.disposition != expected_disposition {
        return Err(ContractError::new(
            "disposition",
            "does not match confidence adjustment",
        ));
    }
    Ok(())
}

fn classify_rule_precision(labeled: u64, precision: Option<u16>) -> RulePrecisionClass {
    if labeled < MIN_CALIBRATION_SAMPLES {
        RulePrecisionClass::Uncalibrated
    } else if precision.is_some_and(|value| value >= 9_500) {
        RulePrecisionClass::High
    } else if precision.is_some_and(|value| value >= 8_000) {
        RulePrecisionClass::Acceptable
    } else {
        RulePrecisionClass::Low
    }
}

fn calculate_precision(confirmed: u64, labeled: u64) -> Option<u16> {
    confirmed
        .checked_mul(10_000)?
        .checked_div(labeled)
        .map(|value| value as u16)
}

fn classify_target_stability(
    observed: u64,
    instability_basis_points: u16,
    timeout_basis_points: u16,
) -> TargetStabilityClass {
    if observed < MIN_STABILITY_SAMPLES {
        TargetStabilityClass::Insufficient
    } else if instability_basis_points >= 2_500 || timeout_basis_points >= 1_500 {
        TargetStabilityClass::Unstable
    } else if instability_basis_points <= 1_000 && timeout_basis_points <= 500 {
        TargetStabilityClass::Stable
    } else {
        TargetStabilityClass::Variable
    }
}

fn combined_reliability(classes: &[RulePrecisionClass]) -> RuleReliability {
    if classes.contains(&RulePrecisionClass::Low) {
        RuleReliability::Low
    } else if classes.contains(&RulePrecisionClass::Uncalibrated) {
        RuleReliability::Uncalibrated
    } else if classes
        .iter()
        .all(|class| *class == RulePrecisionClass::High)
    {
        RuleReliability::High
    } else {
        RuleReliability::Acceptable
    }
}

fn rule_reduction(value: RuleReliability) -> u8 {
    match value {
        RuleReliability::High | RuleReliability::Acceptable => 0,
        RuleReliability::Uncalibrated => 1,
        RuleReliability::Low => 2,
    }
}

fn noise_reduction(value: TargetStabilityClass) -> u8 {
    match value {
        TargetStabilityClass::Stable => 0,
        TargetStabilityClass::Variable
        | TargetStabilityClass::Insufficient
        | TargetStabilityClass::Missing => 1,
        TargetStabilityClass::Unstable => 2,
    }
}

fn reduce_confidence(value: Confidence, reductions: u8) -> Confidence {
    match confidence_rank(value).saturating_sub(reductions) {
        0 => Confidence::Low,
        1 => Confidence::Medium,
        _ => Confidence::High,
    }
}

fn validate_noise_counts(
    observed: u64,
    unstable: u64,
    timeout: u64,
    status_variance: u64,
    body_variance: u64,
) -> Result<(), ContractError> {
    if observed == 0
        || observed > HARD_MAX_SAMPLES
        || unstable > observed
        || timeout > unstable
        || status_variance > unstable
        || body_variance > unstable
    {
        return Err(ContractError::new(
            "noise_samples",
            "noise counts must be bounded subsets of observed samples",
        ));
    }
    Ok(())
}

fn validate_adjustment_limits(limits: ConfidenceAdjustmentLimits) -> Result<(), ContractError> {
    if limits.max_rule_profiles > HARD_MAX_PROFILES || limits.max_noise_profiles > HARD_MAX_PROFILES
    {
        return Err(ContractError::new(
            "limits",
            "confidence adjustment limits exceed hard policy",
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

fn validate_opaque(field: &'static str, value: &str, max: usize) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > max
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ContractError::new(
            field,
            "must be a bounded opaque identifier",
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

fn validate_sorted_profile_refs(values: &[String], prefix: &str) -> Result<(), ContractError> {
    let mut previous: Option<&str> = None;
    for value in values {
        validate_prefixed_hash("rule_profile_refs", value, prefix)?;
        if previous.is_some_and(|existing| existing >= value.as_str()) {
            return Err(ContractError::new(
                "rule_profile_refs",
                "must be strictly sorted and unique",
            ));
        }
        previous = Some(value);
    }
    Ok(())
}

fn provenance_key(value: &FindingProvenance) -> (String, String, String) {
    (
        value.source_engine.clone(),
        value.rule_id.clone(),
        value.rule_version.clone(),
    )
}

fn hash_adjustment(hasher: &mut Sha256, value: &ConfidenceAdjustment) {
    hash_field(hasher, &value.correlation_key);
    hash_field(hasher, confidence_tag(value.original_floor));
    hash_field(hasher, confidence_tag(value.original_ceiling));
    hash_field(hasher, confidence_tag(value.adjusted_floor));
    hash_field(hasher, confidence_tag(value.adjusted_ceiling));
    hash_field(hasher, rule_reliability_tag(value.rule_reliability));
    hash_field(hasher, stability_tag(value.target_stability));
    hash_field(
        hasher,
        if value.unstable_target {
            "true"
        } else {
            "false"
        },
    );
    hash_field(hasher, disposition_tag(value.disposition));
    hash_field(hasher, &value.rule_profile_refs.len().to_string());
    for reference in &value.rule_profile_refs {
        hash_field(hasher, reference);
    }
    hash_field(
        hasher,
        value.noise_profile_ref.as_deref().unwrap_or("missing"),
    );
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
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

fn rule_reliability_tag(value: RuleReliability) -> &'static str {
    match value {
        RuleReliability::High => "high",
        RuleReliability::Acceptable => "acceptable",
        RuleReliability::Low => "low",
        RuleReliability::Uncalibrated => "uncalibrated",
    }
}

fn stability_tag(value: TargetStabilityClass) -> &'static str {
    match value {
        TargetStabilityClass::Stable => "stable",
        TargetStabilityClass::Variable => "variable",
        TargetStabilityClass::Unstable => "unstable",
        TargetStabilityClass::Insufficient => "insufficient",
        TargetStabilityClass::Missing => "missing",
    }
}

fn disposition_tag(value: ConfidenceDisposition) -> &'static str {
    match value {
        ConfidenceDisposition::Retained => "retained",
        ConfidenceDisposition::Reduced => "reduced",
        ConfidenceDisposition::UnstableTarget => "unstable_target",
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        correlate_findings, CanonicalFinding, Confidence, CorrelationContext, CorrelationLimits,
        FindingCorrelationInput, FindingIdentity, FindingProvenance, HttpMethod, ParameterLocation,
        RootCauseKey, Severity,
    };

    use super::{
        adjust_confidence, ConfidenceAdjustmentLimits, ConfidenceDisposition, RulePrecisionClass,
        RulePrecisionProfile, RuleReliability, TargetNoiseProfile, TargetStabilityClass,
    };

    const TENANT: &str = "tenant_0123456789abcdef0123456789abcdef";
    const SCAN: &str = "scan_0123456789abcdef0123456789abcdef";
    const OTHER_SCAN: &str = "scan_abcdef0123456789abcdef0123456789";
    const BUNDLE: &str = "bundle_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const RULE_PROFILE: &str = "ruleprofile_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_RULE_PROFILE: &str = "ruleprofile_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NOISE_PROFILE: &str = "noise_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn context(scan: &str) -> CorrelationContext {
        CorrelationContext::new(TENANT, scan).unwrap()
    }

    fn provenance() -> FindingProvenance {
        FindingProvenance::new("aegis_native", "sqli_error", "1.0.0").unwrap()
    }

    fn correlation(confidence: Confidence) -> crate::CorrelationReport {
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
            confidence,
            vec!["evidence-1".to_string()],
            provenance(),
        )
        .unwrap();
        let input = FindingCorrelationInput::new(
            finding,
            RootCauseKey::new("CWE-89", "unsafe_sql_interpolation").unwrap(),
            BUNDLE,
        )
        .unwrap();
        correlate_findings(context(SCAN), vec![input], CorrelationLimits::default()).unwrap()
    }

    fn rule_profile(
        profile_ref: &str,
        confirmed: u64,
        false_positive: u64,
        insufficient: u64,
    ) -> RulePrecisionProfile {
        RulePrecisionProfile::new(
            profile_ref,
            provenance(),
            confirmed,
            false_positive,
            insufficient,
        )
        .unwrap()
    }

    fn noise(scan: &str, observed: u64, unstable: u64, timeout: u64) -> TargetNoiseProfile {
        TargetNoiseProfile::new(
            NOISE_PROFILE,
            context(scan),
            "target-1",
            observed,
            unstable,
            timeout,
            unstable.saturating_sub(timeout),
            unstable,
        )
        .unwrap()
    }

    #[test]
    fn precision_profile_uses_only_labeled_samples_and_revalidates_storage() {
        let high = rule_profile(RULE_PROFILE, 95, 5, 50);
        assert_eq!(high.precision_basis_points(), Some(9_500));
        assert_eq!(high.class(), RulePrecisionClass::High);
        assert_eq!(high.sample_count(), 150);
        assert_eq!(
            rule_profile(RULE_PROFILE, 16, 4, 0).class(),
            RulePrecisionClass::Acceptable
        );
        assert_eq!(
            rule_profile(RULE_PROFILE, 10, 10, 0).class(),
            RulePrecisionClass::Low
        );
        assert_eq!(
            rule_profile(RULE_PROFILE, 18, 1, 0).class(),
            RulePrecisionClass::Uncalibrated
        );
        let insufficient_only = rule_profile(RULE_PROFILE, 0, 0, 30);
        assert_eq!(insufficient_only.precision_basis_points(), None);
        assert_eq!(insufficient_only.class(), RulePrecisionClass::Uncalibrated);

        let mut tampered = high;
        tampered.precision_basis_points = Some(10_000);
        assert_eq!(tampered.validate().unwrap_err().field(), "precision");
    }

    #[test]
    fn target_noise_classifies_stable_variable_unstable_and_insufficient() {
        assert_eq!(noise(SCAN, 10, 1, 0).class(), TargetStabilityClass::Stable);
        assert_eq!(
            noise(SCAN, 10, 2, 1).class(),
            TargetStabilityClass::Variable
        );
        assert_eq!(
            noise(SCAN, 10, 3, 1).class(),
            TargetStabilityClass::Unstable
        );
        assert_eq!(
            noise(SCAN, 4, 0, 0).class(),
            TargetStabilityClass::Insufficient
        );
        assert_eq!(noise(SCAN, 10, 3, 1).instability_basis_points(), 3_000);

        let error =
            TargetNoiseProfile::new(NOISE_PROFILE, context(SCAN), "target-1", 10, 2, 3, 0, 0)
                .unwrap_err();
        assert_eq!(error.field(), "noise_samples");
    }

    #[test]
    fn high_precision_and_stable_target_never_raise_or_reduce_confidence() {
        let correlation = correlation(Confidence::High);
        let report = adjust_confidence(
            &correlation,
            vec![rule_profile(RULE_PROFILE, 95, 5, 0)],
            vec![noise(SCAN, 10, 1, 0)],
            ConfidenceAdjustmentLimits::default(),
        )
        .unwrap();
        let adjustment = &report.adjustments()[0];
        assert_eq!(
            adjustment.adjusted_range(),
            (Confidence::High, Confidence::High)
        );
        assert_eq!(adjustment.rule_reliability(), RuleReliability::High);
        assert_eq!(adjustment.target_stability(), TargetStabilityClass::Stable);
        assert_eq!(adjustment.disposition(), ConfidenceDisposition::Retained);
        assert!(!adjustment.unstable_target());

        let json = serde_json::to_string(&report).unwrap();
        let restored = serde_json::from_str(&json).unwrap();
        assert_eq!(report, restored);
        assert!(report.validate(&correlation).is_ok());
    }

    #[test]
    fn low_precision_and_unstable_target_reduce_to_low_and_mark_target() {
        let correlation = correlation(Confidence::High);
        let report = adjust_confidence(
            &correlation,
            vec![rule_profile(RULE_PROFILE, 10, 10, 0)],
            vec![noise(SCAN, 20, 6, 3)],
            ConfidenceAdjustmentLimits::default(),
        )
        .unwrap();
        let adjustment = &report.adjustments()[0];
        assert_eq!(
            adjustment.adjusted_range(),
            (Confidence::Low, Confidence::Low)
        );
        assert_eq!(adjustment.rule_reliability(), RuleReliability::Low);
        assert_eq!(
            adjustment.target_stability(),
            TargetStabilityClass::Unstable
        );
        assert_eq!(
            adjustment.disposition(),
            ConfidenceDisposition::UnstableTarget
        );
        assert!(adjustment.unstable_target());
    }

    #[test]
    fn missing_profiles_are_uncalibrated_and_cannot_preserve_high_confidence() {
        let correlation = correlation(Confidence::High);
        let report = adjust_confidence(
            &correlation,
            Vec::new(),
            Vec::new(),
            ConfidenceAdjustmentLimits::default(),
        )
        .unwrap();
        let adjustment = &report.adjustments()[0];
        assert_eq!(adjustment.rule_reliability(), RuleReliability::Uncalibrated);
        assert_eq!(adjustment.target_stability(), TargetStabilityClass::Missing);
        assert_eq!(
            adjustment.adjusted_range(),
            (Confidence::Low, Confidence::Low)
        );
        assert_eq!(adjustment.disposition(), ConfidenceDisposition::Reduced);
    }

    #[test]
    fn duplicate_or_cross_context_profiles_and_report_tampering_fail_closed() {
        let correlation = correlation(Confidence::High);
        let duplicate_error = adjust_confidence(
            &correlation,
            vec![
                rule_profile(RULE_PROFILE, 95, 5, 0),
                rule_profile(OTHER_RULE_PROFILE, 90, 10, 0),
            ],
            Vec::new(),
            ConfidenceAdjustmentLimits::default(),
        )
        .unwrap_err();
        assert_eq!(duplicate_error.field(), "rule_profiles");
        let context_error = adjust_confidence(
            &correlation,
            Vec::new(),
            vec![noise(OTHER_SCAN, 10, 1, 0)],
            ConfidenceAdjustmentLimits::default(),
        )
        .unwrap_err();
        assert_eq!(context_error.field(), "noise_profile.context");
        let unrelated = RulePrecisionProfile::new(
            OTHER_RULE_PROFILE,
            FindingProvenance::new("aegis_native", "other_rule", "1.0.0").unwrap(),
            95,
            5,
            0,
        )
        .unwrap();
        let unused_error = adjust_confidence(
            &correlation,
            vec![unrelated],
            Vec::new(),
            ConfidenceAdjustmentLimits::default(),
        )
        .unwrap_err();
        assert_eq!(unused_error.field(), "profiles");

        let mut report = adjust_confidence(
            &correlation,
            vec![rule_profile(RULE_PROFILE, 95, 5, 0)],
            vec![noise(SCAN, 10, 1, 0)],
            ConfidenceAdjustmentLimits::default(),
        )
        .unwrap();
        report.adjustments[0].rule_reliability = RuleReliability::Low;
        assert_eq!(
            report.validate(&correlation).unwrap_err().field(),
            "confidence_adjustment"
        );

        let debug = format!("{report:?} {:?}", report.adjustments()[0]);
        assert!(!debug.contains("example.com"));
        assert!(!debug.contains(TENANT));
        assert!(!debug.contains(SCAN));
        assert!(!debug.contains(RULE_PROFILE));
        assert!(!debug.contains(NOISE_PROFILE));
    }
}
