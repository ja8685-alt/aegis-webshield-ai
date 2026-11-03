use std::collections::BTreeSet;
use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ContractError, EvidenceDelta, EvidenceResolution, FindingProvenance, RulePrecisionProfile,
};

const RULE_EVENT_PREFIX: &str = "rulefeedback_";
const SCAN_EVENT_PREFIX: &str = "scanfeedback_";
const ADJUDICATION_PREFIX: &str = "adjudication_";
const SCAN_PLAN_PREFIX: &str = "scanplan_";
const MAX_EVENTS: usize = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackRoute {
    RuleReliability,
    NextScanPlan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleFeedbackLabel {
    Confirmed,
    FalsePositive,
    InsufficientEvidence,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuleFeedbackEvent {
    event_ref: String,
    finding_fingerprint: String,
    provenance: FindingProvenance,
    label: RuleFeedbackLabel,
    adjudication_ref: String,
    occurred_at_millis: u64,
    route: FeedbackRoute,
    fingerprint: String,
}

impl RuleFeedbackEvent {
    pub fn new(
        event_ref: impl Into<String>,
        finding_fingerprint: impl Into<String>,
        provenance: FindingProvenance,
        label: RuleFeedbackLabel,
        adjudication_ref: impl Into<String>,
        occurred_at_millis: u64,
    ) -> Result<Self, ContractError> {
        let mut event = Self {
            event_ref: event_ref.into(),
            finding_fingerprint: finding_fingerprint.into(),
            provenance,
            label,
            adjudication_ref: adjudication_ref.into(),
            occurred_at_millis,
            route: FeedbackRoute::RuleReliability,
            fingerprint: String::new(),
        };
        event.fingerprint = event.compute_fingerprint();
        event.validate()?;
        Ok(event)
    }

    pub fn label(&self) -> RuleFeedbackLabel {
        self.label
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_prefixed_hash("event_ref", &self.event_ref, RULE_EVENT_PREFIX)?;
        validate_sha256("finding_fingerprint", &self.finding_fingerprint)?;
        self.provenance.validate()?;
        validate_prefixed_hash(
            "adjudication_ref",
            &self.adjudication_ref,
            ADJUDICATION_PREFIX,
        )?;
        if self.occurred_at_millis == 0 || self.route != FeedbackRoute::RuleReliability {
            return Err(ContractError::new(
                "rule_feedback",
                "rule feedback requires a timestamp and rule-reliability route",
            ));
        }
        validate_sha256("fingerprint", &self.fingerprint)?;
        if self.fingerprint != self.compute_fingerprint() {
            return Err(ContractError::new(
                "fingerprint",
                "rule feedback integrity mismatch",
            ));
        }
        Ok(())
    }

    fn compute_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "aegis.feedback.rule.v1");
        hash_field(&mut hasher, &self.event_ref);
        hash_field(&mut hasher, &self.finding_fingerprint);
        hash_provenance(&mut hasher, &self.provenance);
        hash_field(&mut hasher, rule_label_tag(self.label));
        hash_field(&mut hasher, &self.adjudication_ref);
        hash_field(&mut hasher, &self.occurred_at_millis.to_string());
        hash_field(&mut hasher, route_tag(self.route));
        format!("{:x}", hasher.finalize())
    }
}

impl Debug for RuleFeedbackEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuleFeedbackEvent")
            .field("event_ref_bytes", &self.event_ref.len())
            .field("finding_fingerprint_bytes", &self.finding_fingerprint.len())
            .field("provenance", &self.provenance)
            .field("label", &self.label)
            .field("occurred_at_millis", &self.occurred_at_millis)
            .field("route", &self.route)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuleFeedbackLearningProfile {
    rule_profile: RulePrecisionProfile,
    source_event_fingerprints: Vec<String>,
    fingerprint: String,
}

impl RuleFeedbackLearningProfile {
    pub fn rule_profile(&self) -> &RulePrecisionProfile {
        &self.rule_profile
    }

    pub fn source_event_count(&self) -> usize {
        self.source_event_fingerprints.len()
    }

    pub fn validate(&self, events: &[RuleFeedbackEvent]) -> Result<(), ContractError> {
        let rebuilt = build_rule_profile(self.rule_profile.profile_ref(), events)?;
        if self.rule_profile != rebuilt
            || self.source_event_fingerprints != sorted_event_fingerprints(events)?
        {
            return Err(ContractError::new(
                "rule_profile",
                "rule profile does not match its dedicated feedback events",
            ));
        }
        validate_sha256("fingerprint", &self.fingerprint)?;
        if self.fingerprint != self.compute_fingerprint() {
            return Err(ContractError::new(
                "fingerprint",
                "rule feedback profile integrity mismatch",
            ));
        }
        Ok(())
    }

    fn compute_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "aegis.feedback.rule.profile.v1");
        hash_field(&mut hasher, self.rule_profile.profile_ref());
        hash_provenance(&mut hasher, self.rule_profile.provenance());
        hash_field(&mut hasher, &self.rule_profile.sample_count().to_string());
        hash_field(
            &mut hasher,
            &self
                .rule_profile
                .precision_basis_points()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_owned()),
        );
        for fingerprint in &self.source_event_fingerprints {
            hash_field(&mut hasher, fingerprint);
        }
        format!("{:x}", hasher.finalize())
    }
}

impl Debug for RuleFeedbackLearningProfile {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuleFeedbackLearningProfile")
            .field("rule_profile", &self.rule_profile)
            .field("source_event_count", &self.source_event_fingerprints.len())
            .finish()
    }
}

pub fn learn_rule_reliability(
    profile_ref: impl Into<String>,
    events: &[RuleFeedbackEvent],
) -> Result<RuleFeedbackLearningProfile, ContractError> {
    let profile_ref = profile_ref.into();
    let rule_profile = build_rule_profile(&profile_ref, events)?;
    let source_event_fingerprints = sorted_event_fingerprints(events)?;
    let mut profile = RuleFeedbackLearningProfile {
        rule_profile,
        source_event_fingerprints,
        fingerprint: String::new(),
    };
    profile.fingerprint = profile.compute_fingerprint();
    profile.validate(events)?;
    Ok(profile)
}

fn build_rule_profile(
    profile_ref: &str,
    events: &[RuleFeedbackEvent],
) -> Result<RulePrecisionProfile, ContractError> {
    validate_event_count(events.len())?;
    let first = events
        .first()
        .ok_or_else(|| ContractError::new("events", "at least one feedback event is required"))?;
    first.validate()?;
    let mut confirmed = 0u64;
    let mut false_positive = 0u64;
    let mut insufficient = 0u64;
    for event in events {
        event.validate()?;
        if event.provenance != first.provenance {
            return Err(ContractError::new(
                "provenance",
                "one rule profile cannot mix rule provenance",
            ));
        }
        match event.label {
            RuleFeedbackLabel::Confirmed => confirmed += 1,
            RuleFeedbackLabel::FalsePositive => false_positive += 1,
            RuleFeedbackLabel::InsufficientEvidence => insufficient += 1,
        }
    }
    RulePrecisionProfile::new(
        profile_ref,
        first.provenance.clone(),
        confirmed,
        false_positive,
        insufficient,
    )
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanPlanFeedbackEvent {
    event_ref: String,
    target_id: String,
    evidence_delta_fingerprint: String,
    resolution: EvidenceResolution,
    occurred_at_millis: u64,
    route: FeedbackRoute,
    fingerprint: String,
}

impl ScanPlanFeedbackEvent {
    pub fn from_delta(
        event_ref: impl Into<String>,
        delta: &EvidenceDelta,
        occurred_at_millis: u64,
    ) -> Result<Self, ContractError> {
        let mut event = Self {
            event_ref: event_ref.into(),
            target_id: delta.target_id().to_owned(),
            evidence_delta_fingerprint: delta.fingerprint().to_owned(),
            resolution: delta.resolution(),
            occurred_at_millis,
            route: FeedbackRoute::NextScanPlan,
            fingerprint: String::new(),
        };
        event.fingerprint = event.compute_fingerprint();
        event.validate()?;
        Ok(event)
    }

    pub fn resolution(&self) -> EvidenceResolution {
        self.resolution
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_prefixed_hash("event_ref", &self.event_ref, SCAN_EVENT_PREFIX)?;
        validate_opaque("target_id", &self.target_id)?;
        validate_sha256(
            "evidence_delta_fingerprint",
            &self.evidence_delta_fingerprint,
        )?;
        if self.occurred_at_millis == 0 || self.route != FeedbackRoute::NextScanPlan {
            return Err(ContractError::new(
                "scan_feedback",
                "scan feedback requires a timestamp and next-scan-plan route",
            ));
        }
        validate_sha256("fingerprint", &self.fingerprint)?;
        if self.fingerprint != self.compute_fingerprint() {
            return Err(ContractError::new(
                "fingerprint",
                "scan-plan feedback integrity mismatch",
            ));
        }
        Ok(())
    }

    fn compute_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "aegis.feedback.scan.v1");
        hash_field(&mut hasher, &self.event_ref);
        hash_field(&mut hasher, &self.target_id);
        hash_field(&mut hasher, &self.evidence_delta_fingerprint);
        hash_field(&mut hasher, resolution_tag(self.resolution));
        hash_field(&mut hasher, &self.occurred_at_millis.to_string());
        hash_field(&mut hasher, route_tag(self.route));
        format!("{:x}", hasher.finalize())
    }
}

impl Debug for ScanPlanFeedbackEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScanPlanFeedbackEvent")
            .field("event_ref_bytes", &self.event_ref.len())
            .field("target_id_bytes", &self.target_id.len())
            .field("resolution", &self.resolution)
            .field("occurred_at_millis", &self.occurred_at_millis)
            .field("route", &self.route)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextScanStrategy {
    VerifyRecentFix,
    PrioritizeUnresolved,
    ManualReviewFirst,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct NextScanPlanProfile {
    profile_ref: String,
    target_id: String,
    resolved_count: usize,
    unresolved_count: usize,
    inconclusive_count: usize,
    strategy: NextScanStrategy,
    source_event_fingerprints: Vec<String>,
    fingerprint: String,
}

impl NextScanPlanProfile {
    pub fn strategy(&self) -> NextScanStrategy {
        self.strategy
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        (
            self.resolved_count,
            self.unresolved_count,
            self.inconclusive_count,
        )
    }

    pub fn validate(&self, events: &[ScanPlanFeedbackEvent]) -> Result<(), ContractError> {
        validate_prefixed_hash("profile_ref", &self.profile_ref, SCAN_PLAN_PREFIX)?;
        let (resolved, unresolved, inconclusive, fingerprints) =
            scan_counts(events, &self.target_id)?;
        if self.resolved_count != resolved
            || self.unresolved_count != unresolved
            || self.inconclusive_count != inconclusive
            || self.strategy != choose_strategy(resolved, unresolved, inconclusive)
            || self.source_event_fingerprints != fingerprints
        {
            return Err(ContractError::new(
                "scan_plan",
                "next scan plan does not match its dedicated fix feedback",
            ));
        }
        validate_sha256("fingerprint", &self.fingerprint)?;
        if self.fingerprint != self.compute_fingerprint() {
            return Err(ContractError::new(
                "fingerprint",
                "next scan plan integrity mismatch",
            ));
        }
        Ok(())
    }

    fn compute_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "aegis.feedback.scan.profile.v1");
        hash_field(&mut hasher, &self.profile_ref);
        hash_field(&mut hasher, &self.target_id);
        hash_field(&mut hasher, &self.resolved_count.to_string());
        hash_field(&mut hasher, &self.unresolved_count.to_string());
        hash_field(&mut hasher, &self.inconclusive_count.to_string());
        hash_field(&mut hasher, strategy_tag(self.strategy));
        for fingerprint in &self.source_event_fingerprints {
            hash_field(&mut hasher, fingerprint);
        }
        format!("{:x}", hasher.finalize())
    }
}

impl Debug for NextScanPlanProfile {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NextScanPlanProfile")
            .field("profile_ref_bytes", &self.profile_ref.len())
            .field("target_id_bytes", &self.target_id.len())
            .field("resolved_count", &self.resolved_count)
            .field("unresolved_count", &self.unresolved_count)
            .field("inconclusive_count", &self.inconclusive_count)
            .field("strategy", &self.strategy)
            .field("source_event_count", &self.source_event_fingerprints.len())
            .finish()
    }
}

pub fn learn_next_scan_plan(
    profile_ref: impl Into<String>,
    events: &[ScanPlanFeedbackEvent],
) -> Result<NextScanPlanProfile, ContractError> {
    validate_event_count(events.len())?;
    let target_id = events
        .first()
        .ok_or_else(|| ContractError::new("events", "at least one feedback event is required"))?
        .target_id
        .clone();
    let (resolved, unresolved, inconclusive, source_event_fingerprints) =
        scan_counts(events, &target_id)?;
    let mut profile = NextScanPlanProfile {
        profile_ref: profile_ref.into(),
        target_id,
        resolved_count: resolved,
        unresolved_count: unresolved,
        inconclusive_count: inconclusive,
        strategy: choose_strategy(resolved, unresolved, inconclusive),
        source_event_fingerprints,
        fingerprint: String::new(),
    };
    profile.fingerprint = profile.compute_fingerprint();
    profile.validate(events)?;
    Ok(profile)
}

fn scan_counts(
    events: &[ScanPlanFeedbackEvent],
    target_id: &str,
) -> Result<(usize, usize, usize, Vec<String>), ContractError> {
    validate_event_count(events.len())?;
    validate_opaque("target_id", target_id)?;
    let mut resolved = 0usize;
    let mut unresolved = 0usize;
    let mut inconclusive = 0usize;
    for event in events {
        event.validate()?;
        if event.target_id != target_id {
            return Err(ContractError::new(
                "target_id",
                "one next-scan profile cannot mix targets",
            ));
        }
        match event.resolution {
            EvidenceResolution::Resolved => resolved += 1,
            EvidenceResolution::Unresolved => unresolved += 1,
            EvidenceResolution::Inconclusive => inconclusive += 1,
        }
    }
    Ok((
        resolved,
        unresolved,
        inconclusive,
        sorted_scan_event_fingerprints(events)?,
    ))
}

fn choose_strategy(resolved: usize, unresolved: usize, inconclusive: usize) -> NextScanStrategy {
    if inconclusive > 0 {
        NextScanStrategy::ManualReviewFirst
    } else if unresolved > 0 {
        NextScanStrategy::PrioritizeUnresolved
    } else {
        debug_assert!(resolved > 0);
        NextScanStrategy::VerifyRecentFix
    }
}

fn sorted_event_fingerprints(events: &[RuleFeedbackEvent]) -> Result<Vec<String>, ContractError> {
    validate_event_count(events.len())?;
    let mut unique = BTreeSet::new();
    for event in events {
        event.validate()?;
        if !unique.insert(event.event_ref.as_str()) {
            return Err(ContractError::new(
                "event_ref",
                "feedback event references must be unique",
            ));
        }
    }
    let mut fingerprints = events
        .iter()
        .map(|event| event.fingerprint.clone())
        .collect::<Vec<_>>();
    fingerprints.sort();
    Ok(fingerprints)
}

fn sorted_scan_event_fingerprints(
    events: &[ScanPlanFeedbackEvent],
) -> Result<Vec<String>, ContractError> {
    validate_event_count(events.len())?;
    let mut unique = BTreeSet::new();
    for event in events {
        if !unique.insert(event.event_ref.as_str()) {
            return Err(ContractError::new(
                "event_ref",
                "feedback event references must be unique",
            ));
        }
    }
    let mut fingerprints = events
        .iter()
        .map(|event| event.fingerprint.clone())
        .collect::<Vec<_>>();
    fingerprints.sort();
    Ok(fingerprints)
}

fn validate_event_count(count: usize) -> Result<(), ContractError> {
    if count == 0 || count > MAX_EVENTS {
        return Err(ContractError::new(
            "events",
            "feedback profiles require one to ten thousand events",
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

fn validate_opaque(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > 64
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

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn hash_provenance(hasher: &mut Sha256, provenance: &FindingProvenance) {
    hash_field(hasher, &provenance.source_engine);
    hash_field(hasher, &provenance.rule_id);
    hash_field(hasher, &provenance.rule_version);
}

fn rule_label_tag(value: RuleFeedbackLabel) -> &'static str {
    match value {
        RuleFeedbackLabel::Confirmed => "confirmed",
        RuleFeedbackLabel::FalsePositive => "false_positive",
        RuleFeedbackLabel::InsufficientEvidence => "insufficient_evidence",
    }
}

fn route_tag(value: FeedbackRoute) -> &'static str {
    match value {
        FeedbackRoute::RuleReliability => "rule_reliability",
        FeedbackRoute::NextScanPlan => "next_scan_plan",
    }
}

fn resolution_tag(value: EvidenceResolution) -> &'static str {
    match value {
        EvidenceResolution::Resolved => "resolved",
        EvidenceResolution::Unresolved => "unresolved",
        EvidenceResolution::Inconclusive => "inconclusive",
    }
}

fn strategy_tag(value: NextScanStrategy) -> &'static str {
    match value {
        NextScanStrategy::VerifyRecentFix => "verify_recent_fix",
        NextScanStrategy::PrioritizeUnresolved => "prioritize_unresolved",
        NextScanStrategy::ManualReviewFirst => "manual_review_first",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        learn_next_scan_plan, learn_rule_reliability, NextScanStrategy, RuleFeedbackEvent,
        RuleFeedbackLabel, RuleFeedbackLearningProfile, ScanPlanFeedbackEvent,
    };
    use crate::{
        build_evidence_delta, evaluate_revalidation, EvidenceBundleDecision, FindingProvenance,
        OriginalEvidenceSnapshot, RevalidationContract, RevalidationObservation,
        RevalidationSuccessCondition, RulePrecisionClass,
    };

    const FINDING_FP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BUNDLE_FP: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const REQUEST_FP: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn provenance(rule: &str) -> FindingProvenance {
        FindingProvenance::new("native", rule, "1.0.0").unwrap()
    }

    fn rule_event(index: usize, label: RuleFeedbackLabel) -> RuleFeedbackEvent {
        RuleFeedbackEvent::new(
            format!("rulefeedback_{index:032x}"),
            FINDING_FP,
            provenance("xss-reflection"),
            label,
            format!("adjudication_{index:032x}"),
            index as u64 + 1,
        )
        .unwrap()
    }

    fn delta(signal_observed: bool, observations: usize) -> crate::EvidenceDelta {
        let original = OriginalEvidenceSnapshot::new(
            "bundle_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "target-1",
            BUNDLE_FP,
            EvidenceBundleDecision::Finding,
        )
        .unwrap();
        let contract = RevalidationContract::new(
            "revalidation_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            FINDING_FP,
            original.bundle_ref(),
            "target-1",
            REQUEST_FP,
            RevalidationSuccessCondition::ProbeSignalAbsent,
            4,
            2,
        )
        .unwrap();
        let samples = (1..=observations)
            .map(|index| {
                RevalidationObservation::new(
                    index,
                    REQUEST_FP,
                    "target-1",
                    200,
                    signal_observed,
                    true,
                    true,
                    false,
                    true,
                    false,
                    format!("evidence-{index}"),
                )
            })
            .collect::<Vec<_>>();
        let report = evaluate_revalidation(&contract, &samples).unwrap();
        build_evidence_delta(&original, &contract, &report).unwrap()
    }

    #[test]
    fn adjudication_events_only_build_rule_reliability_profile() {
        let events = (0..20)
            .map(|index| {
                rule_event(
                    index,
                    if index < 15 {
                        RuleFeedbackLabel::Confirmed
                    } else {
                        RuleFeedbackLabel::FalsePositive
                    },
                )
            })
            .collect::<Vec<_>>();
        let profile =
            learn_rule_reliability("ruleprofile_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &events)
                .unwrap();
        assert_eq!(profile.rule_profile().precision_basis_points(), Some(7_500));
        assert_eq!(profile.rule_profile().class(), RulePrecisionClass::Low);
        assert_eq!(profile.source_event_count(), 20);
    }

    #[test]
    fn resolved_fix_feedback_schedules_verification_not_rule_learning() {
        let event = ScanPlanFeedbackEvent::from_delta(
            "scanfeedback_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &delta(false, 2),
            1,
        )
        .unwrap();
        let profile =
            learn_next_scan_plan("scanplan_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &[event]).unwrap();
        assert_eq!(profile.strategy(), NextScanStrategy::VerifyRecentFix);
        assert_eq!(profile.counts(), (1, 0, 0));
    }

    #[test]
    fn unresolved_fix_feedback_is_prioritized() {
        let event = ScanPlanFeedbackEvent::from_delta(
            "scanfeedback_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            &delta(true, 4),
            1,
        )
        .unwrap();
        let profile =
            learn_next_scan_plan("scanplan_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", &[event]).unwrap();
        assert_eq!(profile.strategy(), NextScanStrategy::PrioritizeUnresolved);
        assert_eq!(profile.counts(), (0, 1, 0));
    }

    #[test]
    fn inconclusive_fix_feedback_requires_manual_review_first() {
        let event = ScanPlanFeedbackEvent::from_delta(
            "scanfeedback_cccccccccccccccccccccccccccccccc",
            &delta(false, 1),
            1,
        )
        .unwrap();
        let profile =
            learn_next_scan_plan("scanplan_cccccccccccccccccccccccccccccccc", &[event]).unwrap();
        assert_eq!(profile.strategy(), NextScanStrategy::ManualReviewFirst);
        assert_eq!(profile.counts(), (0, 0, 1));
    }

    #[test]
    fn mixed_rules_duplicate_events_and_route_tampering_fail_closed() {
        let first = rule_event(1, RuleFeedbackLabel::Confirmed);
        let mut other_rule = rule_event(2, RuleFeedbackLabel::FalsePositive);
        other_rule.provenance = provenance("sql-injection");
        other_rule.fingerprint = other_rule.compute_fingerprint();
        assert!(learn_rule_reliability(
            "ruleprofile_dddddddddddddddddddddddddddddddd",
            &[first.clone(), other_rule]
        )
        .is_err());
        assert!(learn_rule_reliability(
            "ruleprofile_dddddddddddddddddddddddddddddddd",
            &[first.clone(), first.clone()]
        )
        .is_err());

        let profile = learn_rule_reliability(
            "ruleprofile_dddddddddddddddddddddddddddddddd",
            std::slice::from_ref(&first),
        )
        .unwrap();
        let mut value = serde_json::to_value(&profile).unwrap();
        value["source_event_fingerprints"] = serde_json::json!([]);
        let tampered: RuleFeedbackLearningProfile = serde_json::from_value(value).unwrap();
        assert!(tampered.validate(&[first]).is_err());
    }
}
