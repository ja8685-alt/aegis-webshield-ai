use std::env;

use aegis_native_active::{run_active_benchmark, ActiveBenchmarkError};

fn main() -> Result<(), ActiveBenchmarkError> {
    let args = env::args().collect::<Vec<_>>();
    let iterations = match args.as_slice() {
        [_, flag, value] if flag == "--iterations" => value
            .parse::<usize>()
            .map_err(|_| ActiveBenchmarkError::InvalidIterations)?,
        _ => return Err(ActiveBenchmarkError::InvalidIterations),
    };
    let report = run_active_benchmark(iterations)?;
    let encoded =
        serde_json::to_string(&report).map_err(|_| ActiveBenchmarkError::NonDeterministicResult)?;
    println!("{encoded}");
    Ok(())
}
