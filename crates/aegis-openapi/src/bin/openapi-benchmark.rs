use std::env;
use std::fmt::{Display, Formatter};
use std::time::Instant;

use aegis_openapi::{import_openapi_document, OpenApiImportError};
use serde::Serialize;

const MAX_ENDPOINTS: usize = 5_000;
const MAX_ITERATIONS: usize = 20;

#[derive(Debug)]
enum BenchmarkError {
    Usage,
    Import(OpenApiImportError),
    InvalidResult,
}

impl Display for BenchmarkError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage => formatter
                .write_str("usage: openapi-benchmark [--endpoints 1..5000] [--iterations 1..20]"),
            Self::Import(error) => Display::fmt(error, formatter),
            Self::InvalidResult => {
                formatter.write_str("OpenAPI benchmark produced an invalid result")
            }
        }
    }
}

impl std::error::Error for BenchmarkError {}

impl From<OpenApiImportError> for BenchmarkError {
    fn from(value: OpenApiImportError) -> Self {
        Self::Import(value)
    }
}

#[derive(Debug, Serialize)]
struct BenchmarkReport {
    schema_version: &'static str,
    endpoints: usize,
    iterations: usize,
    document_bytes: usize,
    total_duration_micros: u64,
    p95_import_duration_micros: u64,
    endpoint_limit_enforced: bool,
    network_requests: usize,
}

fn main() -> Result<(), BenchmarkError> {
    let (endpoint_count, iterations) = parse_arguments()?;
    let document = build_document(endpoint_count);
    let mut durations = Vec::with_capacity(iterations);
    let started = Instant::now();

    for _ in 0..iterations {
        let iteration_started = Instant::now();
        let result = import_openapi_document(&document, None)?;
        durations.push(duration_micros(iteration_started.elapsed().as_nanos()));
        if result.endpoints.len() != endpoint_count {
            return Err(BenchmarkError::InvalidResult);
        }
    }

    durations.sort_unstable();
    let p95_index = durations
        .len()
        .saturating_mul(95)
        .div_ceil(100)
        .saturating_sub(1);
    let endpoint_limit_enforced = if endpoint_count == MAX_ENDPOINTS {
        matches!(
            import_openapi_document(&build_document(MAX_ENDPOINTS + 1), None),
            Err(OpenApiImportError::TooManyEndpoints)
        )
    } else {
        true
    };
    if !endpoint_limit_enforced {
        return Err(BenchmarkError::InvalidResult);
    }

    let report = BenchmarkReport {
        schema_version: "aegis.openapi-benchmark.v1",
        endpoints: endpoint_count,
        iterations,
        document_bytes: document.len(),
        total_duration_micros: duration_micros(started.elapsed().as_nanos()),
        p95_import_duration_micros: durations[p95_index],
        endpoint_limit_enforced,
        network_requests: 0,
    };
    println!(
        "{}",
        serde_json::to_string(&report).map_err(|_| BenchmarkError::InvalidResult)?
    );
    Ok(())
}

fn parse_arguments() -> Result<(usize, usize), BenchmarkError> {
    let mut endpoint_count = MAX_ENDPOINTS;
    let mut iterations = 3usize;
    let mut arguments = env::args().skip(1);

    while let Some(flag) = arguments.next() {
        let value = arguments.next().ok_or(BenchmarkError::Usage)?;
        match flag.as_str() {
            "--endpoints" => endpoint_count = parse_bounded(&value, MAX_ENDPOINTS)?,
            "--iterations" => iterations = parse_bounded(&value, MAX_ITERATIONS)?,
            _ => return Err(BenchmarkError::Usage),
        }
    }
    Ok((endpoint_count, iterations))
}

fn parse_bounded(value: &str, maximum: usize) -> Result<usize, BenchmarkError> {
    value
        .parse::<usize>()
        .ok()
        .filter(|value| (1..=maximum).contains(value))
        .ok_or(BenchmarkError::Usage)
}

fn build_document(endpoint_count: usize) -> String {
    let mut document = String::with_capacity(endpoint_count.saturating_mul(120));
    document.push_str(
        r#"{"openapi":"3.0.3","info":{"title":"RC benchmark","version":"1.0.0"},"servers":[{"url":"https://benchmark.invalid"}],"paths":{"#,
    );
    for index in 0..endpoint_count {
        if index > 0 {
            document.push(',');
        }
        document.push_str(&format!(
            r#""/resources/{index}":{{"get":{{"operationId":"getResource{index}","parameters":[{{"name":"query","in":"query","required":false}}]}}}}"#
        ));
    }
    document.push_str("}}");
    document
}

fn duration_micros(nanos: u128) -> u64 {
    u64::try_from(nanos.div_ceil(1_000).max(1)).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{build_document, parse_bounded, BenchmarkError, MAX_ENDPOINTS};
    use aegis_openapi::{import_openapi_document, OpenApiImportError};

    #[test]
    fn generated_document_imports_requested_endpoint_count() {
        let result = import_openapi_document(&build_document(25), None).unwrap();
        assert_eq!(result.endpoints.len(), 25);
    }

    #[test]
    fn generated_over_limit_document_is_rejected() {
        assert_eq!(
            import_openapi_document(&build_document(MAX_ENDPOINTS + 1), None),
            Err(OpenApiImportError::TooManyEndpoints)
        );
    }

    #[test]
    fn bounded_arguments_reject_zero_and_values_over_limit() {
        assert!(matches!(parse_bounded("0", 10), Err(BenchmarkError::Usage)));
        assert!(matches!(
            parse_bounded("11", 10),
            Err(BenchmarkError::Usage)
        ));
        assert_eq!(parse_bounded("10", 10).unwrap(), 10);
    }
}
