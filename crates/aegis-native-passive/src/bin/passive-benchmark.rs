use std::fmt::{Display, Formatter};

use aegis_native_passive::{run_passive_benchmark, PassiveBenchmarkError, PassiveBenchmarkReport};

const DEFAULT_ITERATIONS: u32 = 1_000;

#[derive(Debug)]
enum CliError {
    Usage,
    Benchmark(PassiveBenchmarkError),
}

impl Display for CliError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage => formatter.write_str("usage: passive-benchmark [--iterations 1..10000]"),
            Self::Benchmark(error) => Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for CliError {}

fn main() -> Result<(), CliError> {
    let iterations = parse_iterations()?;
    let report = run_passive_benchmark(iterations).map_err(CliError::Benchmark)?;
    print_report(&report);
    Ok(())
}

fn parse_iterations() -> Result<u32, CliError> {
    let mut arguments = std::env::args().skip(1);
    let Some(flag) = arguments.next() else {
        return Ok(DEFAULT_ITERATIONS);
    };
    if flag != "--iterations" {
        return Err(CliError::Usage);
    }
    let value = arguments.next().ok_or(CliError::Usage)?;
    if arguments.next().is_some() {
        return Err(CliError::Usage);
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|iterations| (1..=10_000).contains(iterations))
        .ok_or(CliError::Usage)
}

fn print_report(report: &PassiveBenchmarkReport) {
    let mismatches = report
        .mismatched_case_ids
        .iter()
        .map(|case_id| format!("\"{case_id}\""))
        .collect::<Vec<_>>()
        .join(",");
    println!(
        concat!(
            "{{",
            "\"schema_version\":\"aegis.native.passive-benchmark.v1\",",
            "\"iterations\":{},",
            "\"case_count\":{},",
            "\"case_executions\":{},",
            "\"seeded_positive_cases\":{},",
            "\"seeded_negative_cases\":{},",
            "\"true_positives\":{},",
            "\"false_positives\":{},",
            "\"true_negatives\":{},",
            "\"false_negatives\":{},",
            "\"covered_detector_families\":{},",
            "\"precision_basis_points\":{},",
            "\"seeded_coverage_basis_points\":{},",
            "\"total_duration_micros\":{},",
            "\"p95_case_duration_micros\":{},",
            "\"mismatched_case_ids\":[{}]",
            "}}"
        ),
        report.iterations,
        report.case_count,
        report.case_executions,
        report.seeded_positive_cases,
        report.seeded_negative_cases,
        report.true_positives,
        report.false_positives,
        report.true_negatives,
        report.false_negatives,
        report.covered_detector_families,
        report.precision_basis_points,
        report.seeded_coverage_basis_points,
        report.total_duration_micros,
        report.p95_case_duration_micros,
        mismatches,
    );
}

#[cfg(test)]
mod tests {
    use super::DEFAULT_ITERATIONS;

    #[test]
    fn default_iteration_count_is_bounded() {
        assert!((1..=10_000).contains(&DEFAULT_ITERATIONS));
    }
}
