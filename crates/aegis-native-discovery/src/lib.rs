//! Scope-safe HTML endpoint discovery for Aegis Native Security Engine.

mod canonical;
mod crawler;
mod graphql;
mod openapi;
mod state_graph;
mod static_extraction;

pub use canonical::{
    canonicalize_url, CanonicalUrl, CanonicalizationOutcome, IgnoredCandidateReason,
};
pub use crawler::{
    crawl_html, CrawlLimits, CrawlResult, DiscoveredEndpoint, EndpointSource, FormField,
    FormFieldKind,
};
pub use graphql::{
    import_graphql_introspection, plan_graphql_introspection, GraphqlArgument, GraphqlField,
    GraphqlIntrospectionLimits, GraphqlIntrospectionPlan, GraphqlOperationKind, GraphqlSurface,
    GraphqlSurfaceError, GRAPHQL_INTROSPECTION_QUERY,
};
pub use openapi::{
    import_openapi, ApiAuthKind, ApiAuthScheme, ApiMethod, ApiOperation, ApiParameter,
    ApiParameterLocation, ImportedOpenApi, OpenApiDocumentFormat, OpenApiImportError,
    OpenApiImportLimits, RequestBodyContract,
};
pub use state_graph::{
    CoverageEvent, CoverageReason, CoverageSummary, CoverageTransition, DiscoveryEdge,
    EndpointAuthState, EndpointGraphError, EndpointGraphLimits, EndpointId, EndpointIdentity,
    EndpointNode, EndpointSourceKind, EndpointStateGraph, SurfaceHttpMethod, TestState, VisitState,
};
pub use static_extraction::{
    extract_javascript_endpoints, extract_static_assets, AssetExtractionLimits,
    CandidateConfidence, JavaScriptCandidate, JavaScriptCandidateSource,
    JavaScriptExtractionLimits, JavaScriptExtractionResult, StaticAsset, StaticAssetKind,
    StaticAssetResult,
};

use std::fmt::{Display, Formatter};

/// Sanitized discovery errors that never include document HTML or candidate URLs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryError {
    InvalidTarget,
    InvalidDocumentUrl,
    DocumentOutOfScope,
    DocumentTooLarge,
    InvalidLimits,
    ParserSetupFailed,
}

impl Display for DiscoveryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidTarget => "approved target is invalid",
            Self::InvalidDocumentUrl => "document URL is invalid",
            Self::DocumentOutOfScope => "document URL is outside the approved target",
            Self::DocumentTooLarge => "HTML document exceeded the discovery limit",
            Self::InvalidLimits => "discovery limits are invalid",
            Self::ParserSetupFailed => "HTML selector setup failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for DiscoveryError {}
