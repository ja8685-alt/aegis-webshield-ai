//! Deterministic passive/configuration detectors.
//!
//! This crate consumes bounded worker-local response views and emits canonical,
//! evidence-referenced findings without retaining raw response values.

mod benchmark;
mod content_exposure;
mod exposure;
mod security_headers;
mod transport_config;

pub use benchmark::{run_passive_benchmark, PassiveBenchmarkError, PassiveBenchmarkReport};
pub use content_exposure::{
    assess_content_exposure, ContentExposureAssessment, ContentExposureContext,
    ContentExposureLimits, ContentExposureObservation, ContentExposureRuntimeError,
    ContentExposureSignal,
};
pub use exposure::{
    assess_exposure_probe, plan_exposure_probes, ExposureAssessment, ExposureDecision,
    ExposureEvidence, ExposureHeader, ExposureLimits, ExposurePlanContext, ExposureProbe,
    ExposureProbeKind, ExposureProbePolicy, ExposureResponse, ExposureRuntimeError, ExposureSignal,
};
pub use security_headers::{
    assess_security_headers, HeaderInspectionWarning, HeaderInspectionWarningKind, PassiveHeader,
    SecurityHeaderAssessment, SecurityHeaderContext, SecurityHeaderLimits, SecurityHeaderPolicy,
    SecurityHeaderRuntimeError,
};
pub use transport_config::{
    assess_transport_configuration, CacheAssessmentContext, ConfigurationAssessment,
    ConfigurationLimits, ConfigurationObservation, ConfigurationRuntimeError, ConfigurationSignal,
    CorsProbeContext, TlsMetadata, TlsVersion, TransportConfigurationContext,
    TransportConfigurationPolicy,
};
