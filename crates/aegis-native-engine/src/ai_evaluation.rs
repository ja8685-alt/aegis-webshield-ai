use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AiReviewDisposition, AiReviewLabel, ContractError};

const DATASET_PREFIX: &str = "dataset_";
const CASE_PREFIX: &str = "goldcase_";
const ADJUDICATION_PREFIX: &str = "adjudication_";
const HARD_MAX_CASES: usize = 10_000;
const MIN_ADJUDICATORS: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoldCaseSplit {
    Calibration,
    Holdout,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AiGoldCase {
    case_ref: String,
    request_fingerprint: String,
    expected_label: AiReviewLabel,
    split: GoldCaseSplit,
    adjudication_ref: String,
    adjudicator_count: u8,
    evidence_complete: bool,
}

impl AiGoldCase {
    pub fn new(
        case_ref: impl Into<String>,
        request_fingerprint: impl Into<String>,
        expected_label: AiReviewLabel,
        split: GoldCaseSplit,
        adjudication_ref: impl Into<String>,
        adjudicator_count: u8,
        evidence_complete: bool,
    ) -> Result<Self, ContractError> {
        let case = Self {
            case_ref: case_ref.into(),
            request_fingerprint: request_fingerprint.into(),
            expected_label,
            split,
            adjudication_ref: adjudication_ref.into(),
            adjudicator_count,
            evidence_complete,
        };
        case.validate()?;
        Ok(case)
    }

    pub fn case_ref(&self) -> &str {
        &self.case_ref
    }

    pub fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }

    pub fn expected_label(&self) -> AiReviewLabel {
        self.expected_label
    }

    pub fn split(&self) -> GoldCaseSplit {
        self.split
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_prefixed_hash("case_ref", &self.case_ref, CASE_PREFIX)?;
        validate_sha256("request_fingerprint", &self.request_fingerprint)?;
        validate_prefixed_hash(
            "adjudication_ref",
            &self.adjudication_ref,
            ADJUDICATION_PREFIX,
        )?;
        if self.adjudicator_count < MIN_ADJUDICATORS || !self.evidence_complete {
            return Err(ContractError::new(
                "adjudication",
                "gold cases require complete evidence and at least two adjudicators",
            ));
        }
        Ok(())
    }
}

impl Debug for AiGoldCase {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AiGoldCase")
            .field("case_ref_bytes", &self.case_ref.len())
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("expected_label", &self.expected_label)
            .field("split", &self.split)
            .field("adjudicator_count", &self.adjudicator_count)
            .field("evidence_complete", &self.evidence_complete)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AiGoldDataset {
    dataset_ref: String,
    version: String,
    cases: Vec<AiGoldCase>,
    fingerprint: String,
}

impl AiGoldDataset {
    pub fn new(
        dataset_ref: impl Into<String>,
        version: impl Into<String>,
        mut cases: Vec<AiGoldCase>,
    ) -> Result<Self, ContractError> {
        cases.sort_by(|left, right| left.case_ref.cmp(&right.case_ref));
        let mut dataset = Self {
            dataset_ref: dataset_ref.into(),
            version: version.into(),
            cases,
            fingerprint: String::new(),
        };
        dataset.fingerprint = dataset.compute_fingerprint();
        dataset.validate()?;
        Ok(dataset)
    }

    pub fn cases(&self) -> &[AiGoldCase] {
        &self.cases
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        validate_prefixed_hash("dataset_ref", &self.dataset_ref, DATASET_PREFIX)?;
        validate_opaque("version", &self.version, 64)?;
        if self.cases.len() < 3 || self.cases.len() > HARD_MAX_CASES {
            return Err(ContractError::new(
                "cases",
                "gold dataset requires three to 10000 cases",
            ));
        }
        let mut previous: Option<&str> = None;
        let mut holdout_labels = BTreeSet::new();
        let mut request_fingerprints = BTreeSet::new();
        for case in &self.cases {
            case.validate()?;
            if previous.is_some_and(|value| value >= case.case_ref())
                || !request_fingerprints.insert(case.request_fingerprint())
            {
                return Err(ContractError::new(
                    "cases",
                    "case and request references must be unique and sorted",
                ));
            }
            previous = Some(case.case_ref());
            if case.split == GoldCaseSplit::Holdout {
                holdout_labels.insert(label_rank(case.expected_label));
            }
        }
        if holdout_labels != BTreeSet::from([0, 1, 2]) {
            return Err(ContractError::new(
                "holdout",
                "holdout split must cover all three gold labels",
            ));
        }
        validate_sha256("fingerprint", &self.fingerprint)?;
        if self.fingerprint != self.compute_fingerprint() {
            return Err(ContractError::new(
                "fingerprint",
                "gold dataset integrity fingerprint does not match",
            ));
        }
        Ok(())
    }

    fn compute_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "aegis.ai.gold-dataset.v1");
        hash_field(&mut hasher, &self.dataset_ref);
        hash_field(&mut hasher, &self.version);
        hash_field(&mut hasher, &self.cases.len().to_string());
        for case in &self.cases {
            hash_field(&mut hasher, &case.case_ref);
            hash_field(&mut hasher, &case.request_fingerprint);
            hash_field(&mut hasher, label_tag(case.expected_label));
            hash_field(&mut hasher, split_tag(case.split));
            hash_field(&mut hasher, &case.adjudication_ref);
            hash_field(&mut hasher, &case.adjudicator_count.to_string());
            hash_field(
                &mut hasher,
                if case.evidence_complete {
                    "true"
                } else {
                    "false"
                },
            );
        }
        format!("{:x}", hasher.finalize())
    }
}

impl Debug for AiGoldDataset {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AiGoldDataset")
            .field("dataset_ref_bytes", &self.dataset_ref.len())
            .field("version", &self.version)
            .field("case_count", &self.cases.len())
            .field("fingerprint_bytes", &self.fingerprint.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AiEvaluationPrediction {
    case_ref: String,
    request_fingerprint: String,
    predicted_label: AiReviewLabel,
    confidence_basis_points: u16,
    disposition: AiReviewDisposition,
}

impl AiEvaluationPrediction {
    pub fn new(
        case_ref: impl Into<String>,
        request_fingerprint: impl Into<String>,
        predicted_label: AiReviewLabel,
        confidence_basis_points: u16,
        disposition: AiReviewDisposition,
    ) -> Result<Self, ContractError> {
        let prediction = Self {
            case_ref: case_ref.into(),
            request_fingerprint: request_fingerprint.into(),
            predicted_label,
            confidence_basis_points,
            disposition,
        };
        prediction.validate()?;
        Ok(prediction)
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_prefixed_hash("case_ref", &self.case_ref, CASE_PREFIX)?;
        validate_sha256("request_fingerprint", &self.request_fingerprint)?;
        if self.confidence_basis_points > 10_000 {
            return Err(ContractError::new(
                "confidence_basis_points",
                "must be between zero and 10000",
            ));
        }
        if self.predicted_label == AiReviewLabel::InsufficientEvidence
            && self.disposition != AiReviewDisposition::Abstain
        {
            return Err(ContractError::new(
                "disposition",
                "insufficient-evidence prediction must abstain",
            ));
        }
        if !matches!(
            (self.predicted_label, self.disposition),
            (_, AiReviewDisposition::Abstain)
                | (
                    AiReviewLabel::Confirmed,
                    AiReviewDisposition::ConfirmedCandidate
                )
                | (
                    AiReviewLabel::FalsePositive,
                    AiReviewDisposition::FalsePositiveCandidate
                )
        ) {
            return Err(ContractError::new(
                "disposition",
                "decisive disposition must match predicted label",
            ));
        }
        Ok(())
    }
}

impl Debug for AiEvaluationPrediction {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AiEvaluationPrediction")
            .field("case_ref_bytes", &self.case_ref.len())
            .field("request_fingerprint_bytes", &self.request_fingerprint.len())
            .field("predicted_label", &self.predicted_label)
            .field("confidence_basis_points", &self.confidence_basis_points)
            .field("disposition", &self.disposition)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AiEvaluationGates {
    pub min_holdout_cases: usize,
    pub min_accuracy_basis_points: u16,
    pub min_decisive_precision_basis_points: u16,
    pub min_insufficient_abstain_recall_basis_points: u16,
    pub min_coverage_basis_points: u16,
    pub max_calibration_error_basis_points: u16,
    pub max_unsafe_insufficient_decisions: usize,
}

impl Default for AiEvaluationGates {
    fn default() -> Self {
        Self {
            min_holdout_cases: 30,
            min_accuracy_basis_points: 8_500,
            min_decisive_precision_basis_points: 9_000,
            min_insufficient_abstain_recall_basis_points: 9_500,
            min_coverage_basis_points: 5_000,
            max_calibration_error_basis_points: 1_000,
            max_unsafe_insufficient_decisions: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiEvaluationGateFailure {
    HoldoutSize,
    Accuracy,
    ConfirmedPrecision,
    FalsePositivePrecision,
    InsufficientAbstainRecall,
    Coverage,
    CalibrationError,
    UnsafeInsufficientDecision,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AiEvaluationReport {
    dataset_fingerprint: String,
    holdout_count: usize,
    exact_correct: usize,
    accuracy_basis_points: u16,
    confirmed_precision_basis_points: Option<u16>,
    false_positive_precision_basis_points: Option<u16>,
    insufficient_abstain_recall_basis_points: u16,
    coverage_basis_points: u16,
    calibration_error_basis_points: u16,
    unsafe_insufficient_decisions: usize,
    gate_failures: Vec<AiEvaluationGateFailure>,
    passed: bool,
    fingerprint: String,
}

impl AiEvaluationReport {
    pub fn passed(&self) -> bool {
        self.passed
    }

    pub fn accuracy_basis_points(&self) -> u16 {
        self.accuracy_basis_points
    }

    pub fn confirmed_precision_basis_points(&self) -> Option<u16> {
        self.confirmed_precision_basis_points
    }

    pub fn false_positive_precision_basis_points(&self) -> Option<u16> {
        self.false_positive_precision_basis_points
    }

    pub fn insufficient_abstain_recall_basis_points(&self) -> u16 {
        self.insufficient_abstain_recall_basis_points
    }

    pub fn coverage_basis_points(&self) -> u16 {
        self.coverage_basis_points
    }

    pub fn calibration_error_basis_points(&self) -> u16 {
        self.calibration_error_basis_points
    }

    pub fn gate_failures(&self) -> &[AiEvaluationGateFailure] {
        &self.gate_failures
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        validate_sha256("dataset_fingerprint", &self.dataset_fingerprint)?;
        if self.holdout_count == 0
            || self.exact_correct > self.holdout_count
            || self.accuracy_basis_points
                != ratio_basis_points(self.exact_correct, self.holdout_count)
            || self.passed != self.gate_failures.is_empty()
            || self
                .gate_failures
                .windows(2)
                .any(|pair| gate_rank(pair[0]) >= gate_rank(pair[1]))
        {
            return Err(ContractError::new(
                "report",
                "evaluation report invariants do not match",
            ));
        }
        for value in [
            self.accuracy_basis_points,
            self.confirmed_precision_basis_points.unwrap_or(0),
            self.false_positive_precision_basis_points.unwrap_or(0),
            self.insufficient_abstain_recall_basis_points,
            self.coverage_basis_points,
            self.calibration_error_basis_points,
        ] {
            if value > 10_000 {
                return Err(ContractError::new("metrics", "basis points exceed 10000"));
            }
        }
        validate_sha256("fingerprint", &self.fingerprint)?;
        if self.fingerprint != self.compute_fingerprint() {
            return Err(ContractError::new(
                "fingerprint",
                "evaluation report integrity mismatch",
            ));
        }
        Ok(())
    }

    fn compute_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "aegis.ai.evaluation-report.v1");
        hash_field(&mut hasher, &self.dataset_fingerprint);
        hash_field(&mut hasher, &self.holdout_count.to_string());
        hash_field(&mut hasher, &self.exact_correct.to_string());
        hash_field(&mut hasher, &self.accuracy_basis_points.to_string());
        hash_field(
            &mut hasher,
            &option_metric(self.confirmed_precision_basis_points),
        );
        hash_field(
            &mut hasher,
            &option_metric(self.false_positive_precision_basis_points),
        );
        hash_field(
            &mut hasher,
            &self.insufficient_abstain_recall_basis_points.to_string(),
        );
        hash_field(&mut hasher, &self.coverage_basis_points.to_string());
        hash_field(
            &mut hasher,
            &self.calibration_error_basis_points.to_string(),
        );
        hash_field(&mut hasher, &self.unsafe_insufficient_decisions.to_string());
        hash_field(&mut hasher, &self.gate_failures.len().to_string());
        for failure in &self.gate_failures {
            hash_field(&mut hasher, gate_tag(*failure));
        }
        hash_field(&mut hasher, if self.passed { "true" } else { "false" });
        format!("{:x}", hasher.finalize())
    }
}

impl Debug for AiEvaluationReport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AiEvaluationReport")
            .field("dataset_fingerprint_bytes", &self.dataset_fingerprint.len())
            .field("holdout_count", &self.holdout_count)
            .field("accuracy_basis_points", &self.accuracy_basis_points)
            .field("coverage_basis_points", &self.coverage_basis_points)
            .field(
                "calibration_error_basis_points",
                &self.calibration_error_basis_points,
            )
            .field(
                "unsafe_insufficient_decisions",
                &self.unsafe_insufficient_decisions,
            )
            .field("gate_failures", &self.gate_failures)
            .field("passed", &self.passed)
            .finish()
    }
}

pub fn evaluate_gold_dataset(
    dataset: &AiGoldDataset,
    predictions: Vec<AiEvaluationPrediction>,
    gates: AiEvaluationGates,
) -> Result<AiEvaluationReport, ContractError> {
    dataset.validate()?;
    validate_gates(gates)?;
    let holdout = dataset
        .cases
        .iter()
        .filter(|case| case.split == GoldCaseSplit::Holdout)
        .map(|case| (case.case_ref.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    if predictions.len() != holdout.len() {
        return Err(ContractError::new(
            "predictions",
            "one prediction per holdout case is required",
        ));
    }
    let mut prediction_map = BTreeMap::new();
    for prediction in predictions {
        prediction.validate()?;
        if prediction_map
            .insert(prediction.case_ref.clone(), prediction)
            .is_some()
        {
            return Err(ContractError::new("predictions", "duplicate prediction"));
        }
    }
    let mut rows = Vec::with_capacity(holdout.len());
    for (case_ref, case) in holdout {
        let prediction = prediction_map
            .remove(case_ref)
            .ok_or_else(|| ContractError::new("predictions", "holdout prediction is missing"))?;
        if prediction.request_fingerprint != case.request_fingerprint {
            return Err(ContractError::new(
                "request_fingerprint",
                "prediction does not match gold request",
            ));
        }
        rows.push((case, prediction));
    }
    if !prediction_map.is_empty() {
        return Err(ContractError::new(
            "predictions",
            "calibration or unknown case predicted",
        ));
    }
    let holdout_count = rows.len();
    let exact_correct = rows
        .iter()
        .filter(|(case, prediction)| case.expected_label == prediction.predicted_label)
        .count();
    let accuracy = ratio_basis_points(exact_correct, holdout_count);
    let confirmed_precision = decisive_precision(&rows, AiReviewLabel::Confirmed);
    let false_positive_precision = decisive_precision(&rows, AiReviewLabel::FalsePositive);
    let insufficient_total = rows
        .iter()
        .filter(|(case, _)| case.expected_label == AiReviewLabel::InsufficientEvidence)
        .count();
    let insufficient_abstained = rows
        .iter()
        .filter(|(case, prediction)| {
            case.expected_label == AiReviewLabel::InsufficientEvidence
                && prediction.disposition == AiReviewDisposition::Abstain
        })
        .count();
    let insufficient_recall = ratio_basis_points(insufficient_abstained, insufficient_total);
    let decisive_count = rows
        .iter()
        .filter(|(_, prediction)| prediction.disposition != AiReviewDisposition::Abstain)
        .count();
    let coverage = ratio_basis_points(decisive_count, holdout_count);
    let unsafe_insufficient = insufficient_total - insufficient_abstained;
    let calibration_error = calibration_error_basis_points(&rows);
    let mut failures = Vec::new();
    if holdout_count < gates.min_holdout_cases {
        failures.push(AiEvaluationGateFailure::HoldoutSize);
    }
    if accuracy < gates.min_accuracy_basis_points {
        failures.push(AiEvaluationGateFailure::Accuracy);
    }
    if confirmed_precision.is_none_or(|value| value < gates.min_decisive_precision_basis_points) {
        failures.push(AiEvaluationGateFailure::ConfirmedPrecision);
    }
    if false_positive_precision
        .is_none_or(|value| value < gates.min_decisive_precision_basis_points)
    {
        failures.push(AiEvaluationGateFailure::FalsePositivePrecision);
    }
    if insufficient_recall < gates.min_insufficient_abstain_recall_basis_points {
        failures.push(AiEvaluationGateFailure::InsufficientAbstainRecall);
    }
    if coverage < gates.min_coverage_basis_points {
        failures.push(AiEvaluationGateFailure::Coverage);
    }
    if calibration_error > gates.max_calibration_error_basis_points {
        failures.push(AiEvaluationGateFailure::CalibrationError);
    }
    if unsafe_insufficient > gates.max_unsafe_insufficient_decisions {
        failures.push(AiEvaluationGateFailure::UnsafeInsufficientDecision);
    }
    failures.sort_by_key(|failure| gate_rank(*failure));
    let mut report = AiEvaluationReport {
        dataset_fingerprint: dataset.fingerprint.clone(),
        holdout_count,
        exact_correct,
        accuracy_basis_points: accuracy,
        confirmed_precision_basis_points: confirmed_precision,
        false_positive_precision_basis_points: false_positive_precision,
        insufficient_abstain_recall_basis_points: insufficient_recall,
        coverage_basis_points: coverage,
        calibration_error_basis_points: calibration_error,
        unsafe_insufficient_decisions: unsafe_insufficient,
        passed: failures.is_empty(),
        gate_failures: failures,
        fingerprint: String::new(),
    };
    report.fingerprint = report.compute_fingerprint();
    report.validate()?;
    Ok(report)
}

fn decisive_precision(
    rows: &[(&AiGoldCase, AiEvaluationPrediction)],
    label: AiReviewLabel,
) -> Option<u16> {
    let predicted = rows
        .iter()
        .filter(|(_, prediction)| {
            prediction.predicted_label == label
                && prediction.disposition != AiReviewDisposition::Abstain
        })
        .count();
    if predicted == 0 {
        return None;
    }
    let correct = rows
        .iter()
        .filter(|(case, prediction)| {
            case.expected_label == label
                && prediction.predicted_label == label
                && prediction.disposition != AiReviewDisposition::Abstain
        })
        .count();
    Some(ratio_basis_points(correct, predicted))
}

fn calibration_error_basis_points(rows: &[(&AiGoldCase, AiEvaluationPrediction)]) -> u16 {
    let mut bins = [(0usize, 0usize, 0u64); 10];
    for (case, prediction) in rows {
        let index = usize::from((prediction.confidence_basis_points / 1_000).min(9));
        bins[index].0 += 1;
        bins[index].1 += usize::from(case.expected_label == prediction.predicted_label);
        bins[index].2 += u64::from(prediction.confidence_basis_points);
    }
    let weighted_error = bins
        .iter()
        .map(|(count, correct, confidence_sum)| {
            if *count == 0 {
                return 0u64;
            }
            let accuracy = u64::from(ratio_basis_points(*correct, *count));
            let mean_confidence = confidence_sum / *count as u64;
            accuracy.abs_diff(mean_confidence) * *count as u64
        })
        .sum::<u64>();
    (weighted_error / rows.len() as u64) as u16
}

fn ratio_basis_points(numerator: usize, denominator: usize) -> u16 {
    ((numerator as u64 * 10_000) / denominator as u64) as u16
}

fn validate_gates(gates: AiEvaluationGates) -> Result<(), ContractError> {
    if gates.min_holdout_cases < 3
        || gates.min_holdout_cases > HARD_MAX_CASES
        || [
            gates.min_accuracy_basis_points,
            gates.min_decisive_precision_basis_points,
            gates.min_insufficient_abstain_recall_basis_points,
            gates.min_coverage_basis_points,
            gates.max_calibration_error_basis_points,
        ]
        .iter()
        .any(|value| *value > 10_000)
    {
        return Err(ContractError::new(
            "gates",
            "basis-point gate exceeds 10000",
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
fn validate_opaque(field: &'static str, value: &str, max: usize) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > max
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ContractError::new(field, "must be a bounded opaque value"));
    }
    Ok(())
}
fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}
fn label_rank(value: AiReviewLabel) -> u8 {
    match value {
        AiReviewLabel::Confirmed => 0,
        AiReviewLabel::FalsePositive => 1,
        AiReviewLabel::InsufficientEvidence => 2,
    }
}
fn label_tag(value: AiReviewLabel) -> &'static str {
    match value {
        AiReviewLabel::Confirmed => "confirmed",
        AiReviewLabel::FalsePositive => "false_positive",
        AiReviewLabel::InsufficientEvidence => "insufficient_evidence",
    }
}
fn split_tag(value: GoldCaseSplit) -> &'static str {
    match value {
        GoldCaseSplit::Calibration => "calibration",
        GoldCaseSplit::Holdout => "holdout",
    }
}
fn option_metric(value: Option<u16>) -> String {
    value.map_or_else(|| "none".to_string(), |value| value.to_string())
}
fn gate_rank(value: AiEvaluationGateFailure) -> u8 {
    match value {
        AiEvaluationGateFailure::HoldoutSize => 0,
        AiEvaluationGateFailure::Accuracy => 1,
        AiEvaluationGateFailure::ConfirmedPrecision => 2,
        AiEvaluationGateFailure::FalsePositivePrecision => 3,
        AiEvaluationGateFailure::InsufficientAbstainRecall => 4,
        AiEvaluationGateFailure::Coverage => 5,
        AiEvaluationGateFailure::CalibrationError => 6,
        AiEvaluationGateFailure::UnsafeInsufficientDecision => 7,
    }
}
fn gate_tag(value: AiEvaluationGateFailure) -> &'static str {
    match value {
        AiEvaluationGateFailure::HoldoutSize => "holdout_size",
        AiEvaluationGateFailure::Accuracy => "accuracy",
        AiEvaluationGateFailure::ConfirmedPrecision => "confirmed_precision",
        AiEvaluationGateFailure::FalsePositivePrecision => "false_positive_precision",
        AiEvaluationGateFailure::InsufficientAbstainRecall => "insufficient_abstain_recall",
        AiEvaluationGateFailure::Coverage => "coverage",
        AiEvaluationGateFailure::CalibrationError => "calibration_error",
        AiEvaluationGateFailure::UnsafeInsufficientDecision => "unsafe_insufficient_decision",
    }
}

#[cfg(test)]
mod tests {
    use crate::{AiReviewDisposition, AiReviewLabel};

    use super::{
        evaluate_gold_dataset, AiEvaluationGateFailure, AiEvaluationGates, AiEvaluationPrediction,
        AiGoldCase, AiGoldDataset, GoldCaseSplit,
    };

    const DATASET: &str = "dataset_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CASE_A: &str = "goldcase_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CASE_B: &str = "goldcase_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const CASE_C: &str = "goldcase_cccccccccccccccccccccccccccccccc";
    const CASE_D: &str = "goldcase_dddddddddddddddddddddddddddddddd";
    const ADJUDICATION_A: &str = "adjudication_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ADJUDICATION_B: &str = "adjudication_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ADJUDICATION_C: &str = "adjudication_cccccccccccccccccccccccccccccccc";
    const ADJUDICATION_D: &str = "adjudication_dddddddddddddddddddddddddddddddd";
    const FP_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FP_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const FP_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const FP_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn case(
        case_ref: &str,
        fingerprint: &str,
        label: AiReviewLabel,
        split: GoldCaseSplit,
        adjudication_ref: &str,
    ) -> AiGoldCase {
        AiGoldCase::new(
            case_ref,
            fingerprint,
            label,
            split,
            adjudication_ref,
            2,
            true,
        )
        .unwrap()
    }

    fn dataset(with_calibration: bool) -> AiGoldDataset {
        let mut cases = vec![
            case(
                CASE_C,
                FP_C,
                AiReviewLabel::InsufficientEvidence,
                GoldCaseSplit::Holdout,
                ADJUDICATION_C,
            ),
            case(
                CASE_A,
                FP_A,
                AiReviewLabel::Confirmed,
                GoldCaseSplit::Holdout,
                ADJUDICATION_A,
            ),
            case(
                CASE_B,
                FP_B,
                AiReviewLabel::FalsePositive,
                GoldCaseSplit::Holdout,
                ADJUDICATION_B,
            ),
        ];
        if with_calibration {
            cases.push(case(
                CASE_D,
                FP_D,
                AiReviewLabel::Confirmed,
                GoldCaseSplit::Calibration,
                ADJUDICATION_D,
            ));
        }
        AiGoldDataset::new(DATASET, "1.0.0", cases).unwrap()
    }

    fn prediction(
        case_ref: &str,
        fingerprint: &str,
        label: AiReviewLabel,
        disposition: AiReviewDisposition,
        confidence: u16,
    ) -> AiEvaluationPrediction {
        AiEvaluationPrediction::new(case_ref, fingerprint, label, confidence, disposition).unwrap()
    }

    fn perfect_predictions() -> Vec<AiEvaluationPrediction> {
        vec![
            prediction(
                CASE_B,
                FP_B,
                AiReviewLabel::FalsePositive,
                AiReviewDisposition::FalsePositiveCandidate,
                9_500,
            ),
            prediction(
                CASE_C,
                FP_C,
                AiReviewLabel::InsufficientEvidence,
                AiReviewDisposition::Abstain,
                9_500,
            ),
            prediction(
                CASE_A,
                FP_A,
                AiReviewLabel::Confirmed,
                AiReviewDisposition::ConfirmedCandidate,
                9_500,
            ),
        ]
    }

    fn fixture_gates() -> AiEvaluationGates {
        AiEvaluationGates {
            min_holdout_cases: 3,
            ..AiEvaluationGates::default()
        }
    }

    #[test]
    fn gold_dataset_is_adjudicated_sorted_integrity_bound_and_round_trips() {
        let dataset = dataset(true);
        assert_eq!(dataset.cases().len(), 4);
        assert_eq!(dataset.cases()[0].case_ref(), CASE_A);
        assert_eq!(dataset.fingerprint().len(), 64);
        let json = serde_json::to_string(&dataset).unwrap();
        let restored: AiGoldDataset = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, dataset);
        assert!(restored.validate().is_ok());

        let debug = format!("{dataset:?} {:?}", dataset.cases()[0]);
        assert!(!debug.contains(DATASET));
        assert!(!debug.contains(CASE_A));
        assert!(!debug.contains(FP_A));
        assert!(!debug.contains(ADJUDICATION_A));
    }

    #[test]
    fn incomplete_adjudication_duplicate_request_and_missing_label_fail_closed() {
        let error = AiGoldCase::new(
            CASE_A,
            FP_A,
            AiReviewLabel::Confirmed,
            GoldCaseSplit::Holdout,
            ADJUDICATION_A,
            1,
            true,
        )
        .unwrap_err();
        assert_eq!(error.field(), "adjudication");

        let duplicate_request = vec![
            case(
                CASE_A,
                FP_A,
                AiReviewLabel::Confirmed,
                GoldCaseSplit::Holdout,
                ADJUDICATION_A,
            ),
            case(
                CASE_B,
                FP_A,
                AiReviewLabel::FalsePositive,
                GoldCaseSplit::Holdout,
                ADJUDICATION_B,
            ),
            case(
                CASE_C,
                FP_C,
                AiReviewLabel::InsufficientEvidence,
                GoldCaseSplit::Holdout,
                ADJUDICATION_C,
            ),
        ];
        assert_eq!(
            AiGoldDataset::new(DATASET, "1.0.0", duplicate_request)
                .unwrap_err()
                .field(),
            "cases"
        );
        let missing_label = vec![
            case(
                CASE_A,
                FP_A,
                AiReviewLabel::Confirmed,
                GoldCaseSplit::Holdout,
                ADJUDICATION_A,
            ),
            case(
                CASE_B,
                FP_B,
                AiReviewLabel::Confirmed,
                GoldCaseSplit::Holdout,
                ADJUDICATION_B,
            ),
            case(
                CASE_C,
                FP_C,
                AiReviewLabel::FalsePositive,
                GoldCaseSplit::Holdout,
                ADJUDICATION_C,
            ),
        ];
        assert_eq!(
            AiGoldDataset::new(DATASET, "1.0.0", missing_label)
                .unwrap_err()
                .field(),
            "holdout"
        );
    }

    #[test]
    fn perfect_holdout_predictions_pass_all_quality_gates() {
        let default_report = evaluate_gold_dataset(
            &dataset(false),
            perfect_predictions(),
            AiEvaluationGates::default(),
        )
        .unwrap();
        assert!(!default_report.passed());
        assert!(default_report
            .gate_failures()
            .contains(&AiEvaluationGateFailure::HoldoutSize));
        let report =
            evaluate_gold_dataset(&dataset(false), perfect_predictions(), fixture_gates()).unwrap();
        assert!(report.passed());
        assert_eq!(report.accuracy_basis_points(), 10_000);
        assert_eq!(report.confirmed_precision_basis_points(), Some(10_000));
        assert_eq!(report.false_positive_precision_basis_points(), Some(10_000));
        assert_eq!(report.insufficient_abstain_recall_basis_points(), 10_000);
        assert_eq!(report.coverage_basis_points(), 6_666);
        assert_eq!(report.calibration_error_basis_points(), 500);
        assert!(report.gate_failures().is_empty());
    }

    #[test]
    fn always_abstain_does_not_pass_on_label_accuracy_alone() {
        let predictions = vec![
            prediction(
                CASE_A,
                FP_A,
                AiReviewLabel::Confirmed,
                AiReviewDisposition::Abstain,
                9_500,
            ),
            prediction(
                CASE_B,
                FP_B,
                AiReviewLabel::FalsePositive,
                AiReviewDisposition::Abstain,
                9_500,
            ),
            prediction(
                CASE_C,
                FP_C,
                AiReviewLabel::InsufficientEvidence,
                AiReviewDisposition::Abstain,
                9_500,
            ),
        ];
        let report = evaluate_gold_dataset(&dataset(false), predictions, fixture_gates()).unwrap();
        assert_eq!(report.accuracy_basis_points(), 10_000);
        assert_eq!(report.coverage_basis_points(), 0);
        assert!(!report.passed());
        assert!(report
            .gate_failures()
            .contains(&AiEvaluationGateFailure::ConfirmedPrecision));
        assert!(report
            .gate_failures()
            .contains(&AiEvaluationGateFailure::FalsePositivePrecision));
        assert!(report
            .gate_failures()
            .contains(&AiEvaluationGateFailure::Coverage));
    }

    #[test]
    fn unsafe_decision_on_insufficient_evidence_fails_release_gate() {
        let mut predictions = perfect_predictions();
        predictions[1] = prediction(
            CASE_C,
            FP_C,
            AiReviewLabel::Confirmed,
            AiReviewDisposition::ConfirmedCandidate,
            9_900,
        );
        let report = evaluate_gold_dataset(&dataset(false), predictions, fixture_gates()).unwrap();
        assert!(!report.passed());
        assert!(report
            .gate_failures()
            .contains(&AiEvaluationGateFailure::UnsafeInsufficientDecision));
        assert!(report
            .gate_failures()
            .contains(&AiEvaluationGateFailure::InsufficientAbstainRecall));
    }

    #[test]
    fn calibration_cases_are_excluded_and_binding_or_report_tampering_is_rejected() {
        let dataset = dataset(true);
        let mut extra = perfect_predictions();
        extra.push(prediction(
            CASE_D,
            FP_D,
            AiReviewLabel::Confirmed,
            AiReviewDisposition::ConfirmedCandidate,
            9_500,
        ));
        assert_eq!(
            evaluate_gold_dataset(&dataset, extra, fixture_gates())
                .unwrap_err()
                .field(),
            "predictions"
        );
        let mut wrong_binding = perfect_predictions();
        wrong_binding[0] = prediction(
            CASE_B,
            FP_D,
            AiReviewLabel::FalsePositive,
            AiReviewDisposition::FalsePositiveCandidate,
            9_500,
        );
        assert_eq!(
            evaluate_gold_dataset(&dataset, wrong_binding, fixture_gates())
                .unwrap_err()
                .field(),
            "request_fingerprint"
        );

        let mut report =
            evaluate_gold_dataset(&dataset, perfect_predictions(), fixture_gates()).unwrap();
        report.coverage_basis_points = 6_000;
        assert_eq!(report.validate().unwrap_err().field(), "fingerprint");
    }
}
