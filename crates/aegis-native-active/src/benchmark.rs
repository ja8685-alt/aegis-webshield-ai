use std::fmt::{Display, Formatter};
use std::time::Instant;

use serde::{Deserialize, Serialize};

const FAMILY_COUNT: usize = 6;
const POSITIVE_CASES: usize = 6;
const NEGATIVE_CASES: usize = 6;
const MAX_ITERATIONS: usize = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveBenchmarkError {
    InvalidIterations,
    DetectorFailure,
    NonDeterministicResult,
}

impl Display for ActiveBenchmarkError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIterations => "active benchmark iteration count is invalid",
            Self::DetectorFailure => "active benchmark detector execution failed",
            Self::NonDeterministicResult => "active benchmark result changed between iterations",
        })
    }
}

impl std::error::Error for ActiveBenchmarkError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActiveBenchmarkReport {
    pub schema_version: String,
    pub iterations: usize,
    pub case_count: usize,
    pub seeded_positive_cases: usize,
    pub seeded_negative_cases: usize,
    pub covered_candidate_families: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub true_negatives: usize,
    pub precision_basis_points: u16,
    pub recall_basis_points: u16,
    pub reproduction_basis_points: u16,
    pub total_case_executions: usize,
    pub p95_family_pair_duration_micros: u64,
    pub mismatched_case_ids: Vec<String>,
    pub network_requests: usize,
    pub external_scanner_processes: usize,
    pub destructive_requests: usize,
}

impl ActiveBenchmarkReport {
    pub fn validate(&self) -> Result<(), ActiveBenchmarkError> {
        let expected_precision = ratio_basis_points(
            self.true_positives,
            self.true_positives.saturating_add(self.false_positives),
        );
        let expected_recall = ratio_basis_points(
            self.true_positives,
            self.true_positives.saturating_add(self.false_negatives),
        );
        if self.schema_version != "aegis.native.active-benchmark.v1"
            || self.iterations == 0
            || self.iterations > MAX_ITERATIONS
            || self.case_count != POSITIVE_CASES + NEGATIVE_CASES
            || self.seeded_positive_cases != POSITIVE_CASES
            || self.seeded_negative_cases != NEGATIVE_CASES
            || self.covered_candidate_families != FAMILY_COUNT
            || self.true_positives + self.false_negatives != POSITIVE_CASES
            || self.true_negatives + self.false_positives != NEGATIVE_CASES
            || self.precision_basis_points != expected_precision
            || self.recall_basis_points != expected_recall
            || self.reproduction_basis_points != 10_000
            || self.total_case_executions != self.case_count * self.iterations
            || self.mismatched_case_ids.len() != self.false_positives + self.false_negatives
            || self.network_requests != 0
            || self.external_scanner_processes != 0
            || self.destructive_requests != 0
        {
            return Err(ActiveBenchmarkError::NonDeterministicResult);
        }
        Ok(())
    }
}

type OutcomeRunner = fn() -> Result<(bool, bool), ActiveBenchmarkError>;

pub fn run_active_benchmark(
    iterations: usize,
) -> Result<ActiveBenchmarkReport, ActiveBenchmarkError> {
    if iterations == 0 || iterations > MAX_ITERATIONS {
        return Err(ActiveBenchmarkError::InvalidIterations);
    }
    let families: [(&str, OutcomeRunner); FAMILY_COUNT] = [
        ("reflected_xss", xss_outcome),
        ("sql_injection", sql_outcome),
        ("path_traversal", traversal_outcome),
        ("ssrf", ssrf_outcome),
        ("session_security", session_outcome),
        ("bola_idor", bola_outcome),
    ];
    let mut baseline = None;
    let mut durations = Vec::with_capacity(iterations * FAMILY_COUNT);
    for _ in 0..iterations {
        let mut current = Vec::with_capacity(FAMILY_COUNT);
        for (_, runner) in families {
            let started = Instant::now();
            current.push(runner()?);
            let micros = started.elapsed().as_micros().max(1);
            durations.push(u64::try_from(micros).unwrap_or(u64::MAX));
        }
        if let Some(expected) = &baseline {
            if expected != &current {
                return Err(ActiveBenchmarkError::NonDeterministicResult);
            }
        } else {
            baseline = Some(current);
        }
    }
    let outcomes = baseline.ok_or(ActiveBenchmarkError::InvalidIterations)?;
    let mut true_positives = 0usize;
    let mut false_positives = 0usize;
    let mut false_negatives = 0usize;
    let mut true_negatives = 0usize;
    let mut mismatched_case_ids = Vec::new();
    for ((family, _), (positive_detected, negative_detected)) in families.into_iter().zip(outcomes)
    {
        if positive_detected {
            true_positives += 1;
        } else {
            false_negatives += 1;
            mismatched_case_ids.push(format!("{family}-positive"));
        }
        if negative_detected {
            false_positives += 1;
            mismatched_case_ids.push(format!("{family}-negative"));
        } else {
            true_negatives += 1;
        }
    }
    durations.sort_unstable();
    let p95_index = (durations.len() * 95).div_ceil(100).saturating_sub(1);
    let precision_basis_points = ratio_basis_points(
        true_positives,
        true_positives.saturating_add(false_positives),
    );
    let recall_basis_points = ratio_basis_points(
        true_positives,
        true_positives.saturating_add(false_negatives),
    );
    let report = ActiveBenchmarkReport {
        schema_version: "aegis.native.active-benchmark.v1".to_string(),
        iterations,
        case_count: POSITIVE_CASES + NEGATIVE_CASES,
        seeded_positive_cases: POSITIVE_CASES,
        seeded_negative_cases: NEGATIVE_CASES,
        covered_candidate_families: FAMILY_COUNT,
        true_positives,
        false_positives,
        false_negatives,
        true_negatives,
        precision_basis_points,
        recall_basis_points,
        reproduction_basis_points: 10_000,
        total_case_executions: (POSITIVE_CASES + NEGATIVE_CASES) * iterations,
        p95_family_pair_duration_micros: durations[p95_index],
        mismatched_case_ids,
        network_requests: 0,
        external_scanner_processes: 0,
        destructive_requests: 0,
    };
    report.validate()?;
    Ok(report)
}

fn ratio_basis_points(numerator: usize, denominator: usize) -> u16 {
    if denominator == 0 {
        return 0;
    }
    let value = numerator.saturating_mul(10_000) / denominator;
    u16::try_from(value).unwrap_or(0)
}

fn xss_outcome() -> Result<(bool, bool), ActiveBenchmarkError> {
    super::xss_reflection::benchmark_outcomes().map_err(|_| ActiveBenchmarkError::DetectorFailure)
}

fn sql_outcome() -> Result<(bool, bool), ActiveBenchmarkError> {
    super::sql_injection::benchmark_outcomes().map_err(|_| ActiveBenchmarkError::DetectorFailure)
}

fn traversal_outcome() -> Result<(bool, bool), ActiveBenchmarkError> {
    super::path_traversal::benchmark_outcomes().map_err(|_| ActiveBenchmarkError::DetectorFailure)
}

fn ssrf_outcome() -> Result<(bool, bool), ActiveBenchmarkError> {
    super::ssrf::benchmark_outcomes().map_err(|_| ActiveBenchmarkError::DetectorFailure)
}

fn session_outcome() -> Result<(bool, bool), ActiveBenchmarkError> {
    super::session_security::benchmark_outcomes().map_err(|_| ActiveBenchmarkError::DetectorFailure)
}

fn bola_outcome() -> Result<(bool, bool), ActiveBenchmarkError> {
    super::bola_idor::benchmark_outcomes().map_err(|_| ActiveBenchmarkError::DetectorFailure)
}

#[cfg(test)]
mod tests {
    use super::{run_active_benchmark, ActiveBenchmarkError, ActiveBenchmarkReport};

    #[test]
    fn actual_candidate_detectors_pass_balanced_fixtures() {
        let report = run_active_benchmark(3).unwrap();
        assert_eq!((report.true_positives, report.true_negatives), (6, 6));
        assert_eq!((report.false_positives, report.false_negatives), (0, 0));
        assert_eq!(report.precision_basis_points, 10_000);
        assert_eq!(report.recall_basis_points, 10_000);
        assert!(report.mismatched_case_ids.is_empty());
    }

    #[test]
    fn iteration_limits_fail_closed() {
        assert_eq!(
            run_active_benchmark(0),
            Err(ActiveBenchmarkError::InvalidIterations)
        );
        assert_eq!(
            run_active_benchmark(1_001),
            Err(ActiveBenchmarkError::InvalidIterations)
        );
    }

    #[test]
    fn serialized_report_preserves_validation_contract() {
        let report = run_active_benchmark(1).unwrap();
        let encoded = serde_json::to_vec(&report).unwrap();
        let decoded: ActiveBenchmarkReport = serde_json::from_slice(&encoded).unwrap();
        decoded.validate().unwrap();
    }

    #[test]
    fn serialized_report_rejects_metric_tampering() {
        let report = run_active_benchmark(1).unwrap();
        let mut value = serde_json::to_value(report).unwrap();
        value["precision_basis_points"] = serde_json::json!(8_500);
        let tampered: ActiveBenchmarkReport = serde_json::from_value(value).unwrap();
        assert_eq!(
            tampered.validate(),
            Err(ActiveBenchmarkError::NonDeterministicResult)
        );
    }
}
