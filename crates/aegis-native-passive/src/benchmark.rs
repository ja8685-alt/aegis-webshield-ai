use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::time::Instant;

use aegis_native_engine::{CanonicalFinding, HttpMethod};

use crate::{
    assess_content_exposure, assess_exposure_probe, assess_security_headers,
    assess_transport_configuration, plan_exposure_probes, CacheAssessmentContext,
    ConfigurationLimits, ContentExposureContext, ContentExposureLimits, CorsProbeContext,
    ExposureHeader, ExposureLimits, ExposurePlanContext, ExposureProbeKind, ExposureProbePolicy,
    ExposureResponse, PassiveHeader, SecurityHeaderContext, SecurityHeaderLimits,
    SecurityHeaderPolicy, TlsMetadata, TlsVersion, TransportConfigurationContext,
    TransportConfigurationPolicy,
};

const HARD_MAX_ITERATIONS: u32 = 10_000;
const BASIS_POINTS: u64 = 10_000;
const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassiveBenchmarkError {
    InvalidIterations,
    DetectorFailure,
    InvalidFinding,
    NonDeterministicResult,
}

impl Display for PassiveBenchmarkError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidIterations => "passive benchmark iteration count is invalid",
            Self::DetectorFailure => "passive benchmark detector execution failed",
            Self::InvalidFinding => "passive benchmark produced an invalid finding",
            Self::NonDeterministicResult => "passive benchmark result was not deterministic",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PassiveBenchmarkError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PassiveBenchmarkReport {
    pub iterations: u32,
    pub case_count: usize,
    pub case_executions: u64,
    pub seeded_positive_cases: usize,
    pub seeded_negative_cases: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub true_negatives: usize,
    pub false_negatives: usize,
    pub covered_detector_families: usize,
    pub precision_basis_points: u64,
    pub seeded_coverage_basis_points: u64,
    pub total_duration_micros: u64,
    pub p95_case_duration_micros: u64,
    pub mismatched_case_ids: Vec<&'static str>,
}

#[derive(Clone, Copy)]
enum FixtureCase {
    MissingSecurityHeaders,
    SecureSecurityHeaders,
    VersionAndStackExposure,
    CleanContent,
    SecretPatternExposure,
    PlaceholderContent,
    EnvironmentFileExposure,
    EnvironmentFileBaseline,
    AdminSurfaceExposure,
    ProtectedAdminSurface,
    LegacyTls,
    SecureTls,
    ReflectedCors,
    TrustedCors,
    PublicSensitiveCache,
    PrivateSensitiveCache,
}

impl FixtureCase {
    const ALL: [Self; 16] = [
        Self::MissingSecurityHeaders,
        Self::SecureSecurityHeaders,
        Self::VersionAndStackExposure,
        Self::CleanContent,
        Self::SecretPatternExposure,
        Self::PlaceholderContent,
        Self::EnvironmentFileExposure,
        Self::EnvironmentFileBaseline,
        Self::AdminSurfaceExposure,
        Self::ProtectedAdminSurface,
        Self::LegacyTls,
        Self::SecureTls,
        Self::ReflectedCors,
        Self::TrustedCors,
        Self::PublicSensitiveCache,
        Self::PrivateSensitiveCache,
    ];

    fn id(self) -> &'static str {
        match self {
            Self::MissingSecurityHeaders => "headers-missing-positive",
            Self::SecureSecurityHeaders => "headers-secure-negative",
            Self::VersionAndStackExposure => "content-version-stack-positive",
            Self::CleanContent => "content-clean-negative",
            Self::SecretPatternExposure => "content-secret-positive",
            Self::PlaceholderContent => "content-placeholder-negative",
            Self::EnvironmentFileExposure => "path-env-positive",
            Self::EnvironmentFileBaseline => "path-env-baseline-negative",
            Self::AdminSurfaceExposure => "path-admin-positive",
            Self::ProtectedAdminSurface => "path-admin-protected-negative",
            Self::LegacyTls => "transport-tls-positive",
            Self::SecureTls => "transport-tls-negative",
            Self::ReflectedCors => "transport-cors-positive",
            Self::TrustedCors => "transport-cors-negative",
            Self::PublicSensitiveCache => "transport-cache-positive",
            Self::PrivateSensitiveCache => "transport-cache-negative",
        }
    }

    fn family(self) -> &'static str {
        match self {
            Self::MissingSecurityHeaders | Self::SecureSecurityHeaders => "security-headers",
            Self::VersionAndStackExposure
            | Self::CleanContent
            | Self::SecretPatternExposure
            | Self::PlaceholderContent => "content-exposure",
            Self::EnvironmentFileExposure
            | Self::EnvironmentFileBaseline
            | Self::AdminSurfaceExposure
            | Self::ProtectedAdminSurface => "path-exposure",
            Self::LegacyTls
            | Self::SecureTls
            | Self::ReflectedCors
            | Self::TrustedCors
            | Self::PublicSensitiveCache
            | Self::PrivateSensitiveCache => "transport-configuration",
        }
    }

    fn expected_finding(self) -> bool {
        matches!(
            self,
            Self::MissingSecurityHeaders
                | Self::VersionAndStackExposure
                | Self::SecretPatternExposure
                | Self::EnvironmentFileExposure
                | Self::AdminSurfaceExposure
                | Self::LegacyTls
                | Self::ReflectedCors
                | Self::PublicSensitiveCache
        )
    }

    fn detected_finding(self) -> Result<bool, PassiveBenchmarkError> {
        match self {
            Self::MissingSecurityHeaders => run_security_header_case(false),
            Self::SecureSecurityHeaders => run_security_header_case(true),
            Self::VersionAndStackExposure => run_content_case(ContentFixture::VersionAndStack),
            Self::CleanContent => run_content_case(ContentFixture::Clean),
            Self::SecretPatternExposure => run_content_case(ContentFixture::Secret),
            Self::PlaceholderContent => run_content_case(ContentFixture::Placeholder),
            Self::EnvironmentFileExposure => run_exposure_case(ExposureFixture::Environment, 200),
            Self::EnvironmentFileBaseline => run_exposure_case(ExposureFixture::Environment, 404),
            Self::AdminSurfaceExposure => run_exposure_case(ExposureFixture::Admin, 200),
            Self::ProtectedAdminSurface => run_exposure_case(ExposureFixture::Admin, 401),
            Self::LegacyTls => run_transport_case(TransportFixture::LegacyTls),
            Self::SecureTls => run_transport_case(TransportFixture::SecureTls),
            Self::ReflectedCors => run_transport_case(TransportFixture::ReflectedCors),
            Self::TrustedCors => run_transport_case(TransportFixture::TrustedCors),
            Self::PublicSensitiveCache => run_transport_case(TransportFixture::PublicCache),
            Self::PrivateSensitiveCache => run_transport_case(TransportFixture::PrivateCache),
        }
    }
}

pub fn run_passive_benchmark(
    iterations: u32,
) -> Result<PassiveBenchmarkReport, PassiveBenchmarkError> {
    if iterations == 0 || iterations > HARD_MAX_ITERATIONS {
        return Err(PassiveBenchmarkError::InvalidIterations);
    }
    let started = Instant::now();
    let mut durations = Vec::with_capacity(FixtureCase::ALL.len() * iterations as usize);
    let mut first_results = Vec::with_capacity(FixtureCase::ALL.len());

    for iteration in 0..iterations {
        for case in FixtureCase::ALL {
            let case_started = Instant::now();
            let detected = case.detected_finding()?;
            durations.push(duration_micros(case_started.elapsed().as_nanos()));
            if iteration == 0 {
                first_results.push(detected);
            } else if first_results[case_index(case)] != detected {
                return Err(PassiveBenchmarkError::NonDeterministicResult);
            }
        }
    }

    let mut true_positives = 0;
    let mut false_positives = 0;
    let mut true_negatives = 0;
    let mut false_negatives = 0;
    let mut mismatched_case_ids = Vec::new();
    for (case, detected) in FixtureCase::ALL.into_iter().zip(first_results) {
        match (case.expected_finding(), detected) {
            (true, true) => true_positives += 1,
            (false, true) => {
                false_positives += 1;
                mismatched_case_ids.push(case.id());
            }
            (false, false) => true_negatives += 1,
            (true, false) => {
                false_negatives += 1;
                mismatched_case_ids.push(case.id());
            }
        }
    }
    durations.sort_unstable();
    let p95_index = durations
        .len()
        .saturating_mul(95)
        .div_ceil(100)
        .saturating_sub(1);
    let seeded_positive_cases = true_positives + false_negatives;
    let seeded_negative_cases = true_negatives + false_positives;
    let detector_families = FixtureCase::ALL
        .iter()
        .map(|case| case.family())
        .collect::<BTreeSet<_>>();

    Ok(PassiveBenchmarkReport {
        iterations,
        case_count: FixtureCase::ALL.len(),
        case_executions: u64::from(iterations) * FixtureCase::ALL.len() as u64,
        seeded_positive_cases,
        seeded_negative_cases,
        true_positives,
        false_positives,
        true_negatives,
        false_negatives,
        covered_detector_families: detector_families.len(),
        precision_basis_points: ratio_basis_points(
            true_positives,
            true_positives + false_positives,
        ),
        seeded_coverage_basis_points: ratio_basis_points(true_positives, seeded_positive_cases),
        total_duration_micros: duration_micros(started.elapsed().as_nanos()),
        p95_case_duration_micros: durations[p95_index],
        mismatched_case_ids,
    })
}

fn case_index(case: FixtureCase) -> usize {
    FixtureCase::ALL
        .iter()
        .position(|candidate| candidate.id() == case.id())
        .unwrap_or(0)
}

fn ratio_basis_points(numerator: usize, denominator: usize) -> u64 {
    if denominator == 0 {
        return 0;
    }
    (numerator as u64 * BASIS_POINTS) / denominator as u64
}

fn duration_micros(nanos: u128) -> u64 {
    let rounded_up = nanos.div_ceil(1_000);
    u64::try_from(rounded_up).unwrap_or(u64::MAX)
}

fn validate_findings(findings: &[CanonicalFinding]) -> Result<bool, PassiveBenchmarkError> {
    if findings.iter().any(|finding| finding.validate().is_err()) {
        return Err(PassiveBenchmarkError::InvalidFinding);
    }
    Ok(!findings.is_empty())
}

fn run_security_header_case(secure: bool) -> Result<bool, PassiveBenchmarkError> {
    let insecure_headers = [PassiveHeader {
        name: "Content-Type",
        value: "text/html",
    }];
    let secure_headers = [
        PassiveHeader {
            name: "Content-Type",
            value: "text/html; charset=utf-8",
        },
        PassiveHeader {
            name: "Content-Security-Policy",
            value: "default-src 'self'; frame-ancestors 'none'",
        },
        PassiveHeader {
            name: "X-Content-Type-Options",
            value: "nosniff",
        },
        PassiveHeader {
            name: "Strict-Transport-Security",
            value: "max-age=31536000; includeSubDomains",
        },
        PassiveHeader {
            name: "Set-Cookie",
            value: "__Host-session=fixture-value; Path=/; Secure; HttpOnly; SameSite=Lax",
        },
    ];
    let headers = if secure {
        secure_headers.as_slice()
    } else {
        insecure_headers.as_slice()
    };
    let context = SecurityHeaderContext {
        target_id: "benchmark-target",
        endpoint: "https://benchmark.invalid/app",
        method: HttpMethod::Get,
        status_code: 200,
        headers,
        evidence_ref: "benchmark-evidence",
    };
    let assessment = assess_security_headers(
        &context,
        &SecurityHeaderPolicy::default(),
        SecurityHeaderLimits::default(),
    )
    .map_err(|_| PassiveBenchmarkError::DetectorFailure)?;
    validate_findings(&assessment.findings)
}

#[derive(Clone, Copy)]
enum ContentFixture {
    VersionAndStack,
    Clean,
    Secret,
    Placeholder,
}

fn run_content_case(fixture: ContentFixture) -> Result<bool, PassiveBenchmarkError> {
    let text_header = [PassiveHeader {
        name: "Content-Type",
        value: "text/plain",
    }];
    let version_headers = [
        PassiveHeader {
            name: "Content-Type",
            value: "text/plain",
        },
        PassiveHeader {
            name: "Server",
            value: "FixtureServer/1.2.3",
        },
    ];
    let (headers, body): (&[PassiveHeader<'_>], &[u8]) = match fixture {
        ContentFixture::VersionAndStack => (
            &version_headers,
            b"java.lang.IllegalStateException\n\tat benchmark.App.run(App.java:10)",
        ),
        ContentFixture::Clean => (&text_header, b"request completed"),
        ContentFixture::Secret => (
            &text_header,
            concat!(
                "token=ey",
                "JhbGciOiJIUzI1NiJ9.ey",
                "JzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl"
            )
            .as_bytes(),
        ),
        ContentFixture::Placeholder => (&text_header, b"token=example-placeholder"),
    };
    let context = ContentExposureContext {
        target_id: "benchmark-target",
        endpoint: "https://benchmark.invalid/api",
        method: HttpMethod::Get,
        status_code: 500,
        headers,
        body_view: body,
        body_view_truncated: false,
        evidence_ref: "benchmark-evidence",
    };
    let assessment = assess_content_exposure(&context, ContentExposureLimits::default())
        .map_err(|_| PassiveBenchmarkError::DetectorFailure)?;
    validate_findings(&assessment.findings)
}

#[derive(Clone, Copy)]
enum ExposureFixture {
    Environment,
    Admin,
}

fn run_exposure_case(
    fixture: ExposureFixture,
    status_code: u16,
) -> Result<bool, PassiveBenchmarkError> {
    let (catalog_path, kind, endpoint, body): (&str, ExposureProbeKind, &str, &[u8]) = match fixture
    {
        ExposureFixture::Environment => (
            "/.env",
            ExposureProbeKind::EnvironmentFile,
            "https://benchmark.invalid/app/.env",
            b"DB_HOST=localhost\nAPI_SECRET=fixture-value\n",
        ),
        ExposureFixture::Admin => (
            "/admin",
            ExposureProbeKind::AdminConsole,
            "https://benchmark.invalid/app/admin",
            br#"<h1>Admin Login</h1><input type="password">"#,
        ),
    };
    let probes = plan_exposure_probes(
        &ExposurePlanContext {
            approved_path_prefix: "/app",
        },
        &ExposureProbePolicy {
            approved_catalog_paths: &[catalog_path],
            enabled_kinds: &[kind],
        },
        ExposureLimits::default(),
    )
    .map_err(|_| PassiveBenchmarkError::DetectorFailure)?;
    let response = ExposureResponse {
        target_id: "benchmark-target",
        endpoint,
        status_code,
        headers: &[] as &[ExposureHeader<'_>],
        body_view: body,
        body_view_truncated: false,
        payload_sha256: if status_code == 404 { HASH_B } else { HASH_A },
        baseline_status_code: 404,
        baseline_payload_sha256: HASH_B,
        evidence_ref: "benchmark-evidence",
    };
    let assessment = assess_exposure_probe(&probes[0], &response, ExposureLimits::default())
        .map_err(|_| PassiveBenchmarkError::DetectorFailure)?;
    match assessment.finding.as_ref() {
        Some(finding) if finding.validate().is_err() => Err(PassiveBenchmarkError::InvalidFinding),
        Some(_) => Ok(true),
        None => Ok(false),
    }
}

#[derive(Clone, Copy)]
enum TransportFixture {
    LegacyTls,
    SecureTls,
    ReflectedCors,
    TrustedCors,
    PublicCache,
    PrivateCache,
}

fn run_transport_case(fixture: TransportFixture) -> Result<bool, PassiveBenchmarkError> {
    let reflected_headers = [
        PassiveHeader {
            name: "Access-Control-Allow-Origin",
            value: "https://untrusted.invalid",
        },
        PassiveHeader {
            name: "Access-Control-Allow-Credentials",
            value: "true",
        },
    ];
    let trusted_headers = [
        PassiveHeader {
            name: "Access-Control-Allow-Origin",
            value: "https://app.invalid",
        },
        PassiveHeader {
            name: "Vary",
            value: "Origin",
        },
    ];
    let public_cache_headers = [PassiveHeader {
        name: "Cache-Control",
        value: "public, s-maxage=300",
    }];
    let private_cache_headers = [PassiveHeader {
        name: "Cache-Control",
        value: "private, no-store",
    }];
    let headers = match fixture {
        TransportFixture::ReflectedCors => reflected_headers.as_slice(),
        TransportFixture::TrustedCors => trusted_headers.as_slice(),
        TransportFixture::PublicCache => public_cache_headers.as_slice(),
        TransportFixture::PrivateCache => private_cache_headers.as_slice(),
        TransportFixture::LegacyTls | TransportFixture::SecureTls => &[],
    };
    let mut context = TransportConfigurationContext {
        target_id: "benchmark-target",
        endpoint: "https://benchmark.invalid/account",
        method: HttpMethod::Get,
        status_code: 200,
        response_headers: headers,
        tls: None,
        cors: None,
        cache: None,
        evidence_ref: "benchmark-evidence",
    };
    let mut trusted_origins: &[&str] = &[];
    match fixture {
        TransportFixture::LegacyTls => {
            context.tls = Some(TlsMetadata {
                negotiated_version: TlsVersion::Tls11,
                certificate_chain_valid: true,
                hostname_valid: true,
                days_until_expiry: 90,
            });
        }
        TransportFixture::SecureTls => {
            context.tls = Some(TlsMetadata {
                negotiated_version: TlsVersion::Tls13,
                certificate_chain_valid: true,
                hostname_valid: true,
                days_until_expiry: 90,
            });
        }
        TransportFixture::ReflectedCors => {
            context.cors = Some(CorsProbeContext {
                request_origin: "https://untrusted.invalid",
                credentialed_request: true,
                preflight: false,
                origin_probe_approved: true,
                response_is_origin_dynamic: true,
                public_cross_origin_approved: false,
            });
        }
        TransportFixture::TrustedCors => {
            trusted_origins = &["https://app.invalid"];
            context.cors = Some(CorsProbeContext {
                request_origin: "https://app.invalid",
                credentialed_request: false,
                preflight: false,
                origin_probe_approved: true,
                response_is_origin_dynamic: true,
                public_cross_origin_approved: false,
            });
        }
        TransportFixture::PublicCache => {
            context.cache = Some(CacheAssessmentContext {
                authenticated_response: true,
                sensitive_response: true,
                public_cache_approved: false,
            });
        }
        TransportFixture::PrivateCache => {
            context.cache = Some(CacheAssessmentContext {
                authenticated_response: true,
                sensitive_response: true,
                public_cache_approved: false,
            });
        }
    }
    let policy = TransportConfigurationPolicy {
        trusted_cors_origins: trusted_origins,
        ..TransportConfigurationPolicy::default()
    };
    let assessment =
        assess_transport_configuration(&context, &policy, ConfigurationLimits::default())
            .map_err(|_| PassiveBenchmarkError::DetectorFailure)?;
    validate_findings(&assessment.findings)
}

#[cfg(test)]
mod tests {
    use super::{run_passive_benchmark, PassiveBenchmarkError};

    #[test]
    fn seeded_corpus_has_exact_accuracy_and_family_coverage() {
        let report = run_passive_benchmark(2).unwrap();
        assert_eq!(report.case_count, 16);
        assert_eq!(report.case_executions, 32);
        assert_eq!(report.seeded_positive_cases, 8);
        assert_eq!(report.seeded_negative_cases, 8);
        assert_eq!(report.true_positives, 8);
        assert_eq!(report.true_negatives, 8);
        assert_eq!(report.false_positives, 0);
        assert_eq!(report.false_negatives, 0);
        assert_eq!(report.covered_detector_families, 4);
        assert_eq!(report.precision_basis_points, 10_000);
        assert_eq!(report.seeded_coverage_basis_points, 10_000);
        assert!(report.mismatched_case_ids.is_empty());
    }

    #[test]
    fn iteration_limit_fails_closed() {
        assert_eq!(
            run_passive_benchmark(0),
            Err(PassiveBenchmarkError::InvalidIterations)
        );
        assert_eq!(
            run_passive_benchmark(10_001),
            Err(PassiveBenchmarkError::InvalidIterations)
        );
    }
}
