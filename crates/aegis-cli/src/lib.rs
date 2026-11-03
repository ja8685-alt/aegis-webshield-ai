use aegis_core::rule_pack_channel_supported;
use aegis_crawler::{
    crawl_approved_html_surface, extract_browser_observation_candidates, extract_html_candidates,
    BrowserCrawlObservation, CrawlCandidate, CrawlPage, CrawlerError, CrawlerFetchClient,
    CrawlerOptions,
};
use aegis_openapi::{import_openapi_document, OpenApiImportError, OpenApiImportResult};
use aegis_scanner::{
    build_passive_probe, run_passive_probe, run_safe_active_verifiers, split_native_evidence,
    surface_probe_targets, FindingSeverity, HttpProbeClient, PassiveFinding, ScanTarget,
    ScannerError,
};
use aegis_storage::{
    list_findings, list_scans, list_target_endpoints, list_targets, FindingRecord, ScanRecord,
    StorageError, TargetEndpointRecord, TargetRecord,
};
use aegis_triage::triage_rule;
use aegis_urlseed::{import_url_seed_document, UrlSeedImportError, UrlSeedImportResult};
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use flate2::read::DeflateDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{Cursor, Read},
    path::PathBuf,
};
use thiserror::Error;
use url::Url;

const MAX_OPENAPI_DOCUMENT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_URL_SEED_DOCUMENT_BYTES: u64 = 512 * 1024;
const MAX_HTML_DOCUMENT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_BASELINE_REPORT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_RULE_DOCUMENT_BYTES: u64 = 512 * 1024;
const MAX_RULE_FEED_DOCUMENT_BYTES: u64 = 128 * 1024;
const MAX_RULE_BUNDLE_BYTES: u64 = 10 * 1024 * 1024;
const MAX_RULE_BUNDLE_ENTRY_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CRAWL_URL_PAGES: usize = 50;
const MAX_CRAWL_URL_CANDIDATES: usize = 250;
const MAX_CRAWL_URL_DEPTH: usize = 3;

#[derive(Debug, Parser)]
#[command(
    name = "aegis-scan",
    version,
    about = "Aegis WebShield AI security scan CLI"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Scan(ScanCommand),
    ScanLocal(LocalScanCommand),
    Report(ReportCommand),
    Rules(RulesCommand),
    ImportOpenapi(ImportOpenApiCommand),
    ImportUrls(ImportUrlsCommand),
    CrawlHtml(CrawlHtmlCommand),
    CrawlBrowserLog(CrawlBrowserLogCommand),
    CrawlUrl(CrawlUrlCommand),
    VerifyActive(VerifyActiveCommand),
}

#[derive(Debug, Parser)]
pub struct LocalScanCommand {
    #[arg(long)]
    pub app_data_dir: PathBuf,
    #[arg(long)]
    pub database: Option<PathBuf>,
    #[arg(long)]
    pub project_id: Option<String>,
    #[arg(long)]
    pub target_id: Option<String>,
    #[arg(long, value_enum, default_value_t = LocalScanProfile::Safe)]
    pub profile: LocalScanProfile,
    #[arg(long, value_enum, default_value_t = FailOn::Critical)]
    pub fail_on: FailOn,
    #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
    pub format: ReportFormat,
}

#[derive(Debug, Parser)]
pub struct ReportCommand {
    #[command(subcommand)]
    pub command: ReportSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ReportSubcommand {
    Export(ReportExportCommand),
}

#[derive(Debug, Parser)]
pub struct RulesCommand {
    #[command(subcommand)]
    pub command: RulesSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum RulesSubcommand {
    Test(RulesTestCommand),
    FeedCheck(RulesFeedCheckCommand),
    FeedSign(RulesFeedSignCommand),
    BundleCheck(RulesBundleCheckCommand),
}

#[derive(Debug, Parser)]
pub struct ScanCommand {
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long)]
    pub openapi: Option<PathBuf>,
    #[arg(long)]
    pub base_url: Option<String>,
    #[arg(long)]
    pub approval_note: String,
    #[arg(long, default_value_t = false)]
    pub allow_private_network: bool,
    #[arg(long, value_enum, default_value_t = FailOn::Critical)]
    pub fail_on: FailOn,
    #[arg(long)]
    pub baseline_file: Option<PathBuf>,
    #[arg(long, value_enum)]
    pub fail_on_new: Option<FailOn>,
    #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
    pub format: ReportFormat,
}

#[derive(Debug, Parser)]
pub struct ImportOpenApiCommand {
    #[arg(long)]
    pub file: PathBuf,
    #[arg(long)]
    pub base_url: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,
}

#[derive(Debug, Parser)]
pub struct ImportUrlsCommand {
    #[arg(long)]
    pub file: PathBuf,
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,
}

#[derive(Debug, Parser)]
pub struct CrawlHtmlCommand {
    #[arg(long)]
    pub file: PathBuf,
    #[arg(long)]
    pub base_url: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,
}

#[derive(Debug, Parser)]
pub struct CrawlBrowserLogCommand {
    #[arg(long)]
    pub file: PathBuf,
    #[arg(long)]
    pub base_url: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,
}

#[derive(Debug, Parser)]
pub struct CrawlUrlCommand {
    #[arg(long)]
    pub url: String,
    #[arg(long)]
    pub approval_note: String,
    #[arg(long, default_value_t = false)]
    pub allow_private_network: bool,
    #[arg(long, default_value_t = 25)]
    pub max_pages: usize,
    #[arg(long, default_value_t = 250)]
    pub max_candidates: usize,
    #[arg(long, default_value_t = 2)]
    pub max_depth: usize,
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,
}

#[derive(Debug, Parser)]
pub struct VerifyActiveCommand {
    #[arg(long)]
    pub url: String,
    #[arg(long)]
    pub approval_note: String,
    #[arg(long, default_value_t = false)]
    pub allow_private_network: bool,
    #[arg(long, value_enum, default_value_t = FailOn::Critical)]
    pub fail_on: FailOn,
    #[arg(long)]
    pub baseline_file: Option<PathBuf>,
    #[arg(long, value_enum)]
    pub fail_on_new: Option<FailOn>,
    #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
    pub format: ReportFormat,
}

#[derive(Debug, Parser)]
pub struct ReportExportCommand {
    #[arg(long)]
    pub app_data_dir: PathBuf,
    #[arg(long)]
    pub database: Option<PathBuf>,
    #[arg(long)]
    pub scan_id: String,
    #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
    pub format: ReportFormat,
}

#[derive(Debug, Parser)]
pub struct RulesTestCommand {
    #[arg(long)]
    pub path: PathBuf,
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,
}

#[derive(Debug, Parser)]
pub struct RulesFeedCheckCommand {
    #[arg(long)]
    pub file: PathBuf,
    #[arg(long)]
    pub current_version: Option<String>,
    #[arg(long)]
    pub public_key_hex: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,
}

#[derive(Debug, Parser)]
pub struct RulesFeedSignCommand {
    #[arg(long)]
    pub file: PathBuf,
    #[arg(long)]
    pub private_key_hex: String,
    #[arg(long)]
    pub out: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,
}

#[derive(Debug, Parser)]
pub struct RulesBundleCheckCommand {
    #[arg(long)]
    pub file: PathBuf,
    #[arg(long)]
    pub expected_manifest_sha256: Option<String>,
    #[arg(long)]
    pub public_key_hex: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOn {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Json,
    Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    Json,
    Text,
    Sarif,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LocalScanProfile {
    Passive,
    Surface,
    Safe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliScanReport {
    pub scan_source: String,
    pub target_url: String,
    pub final_url: String,
    pub status_code: u16,
    pub endpoint_count: usize,
    pub skipped_endpoint_count: usize,
    pub finding_count: usize,
    pub highest_severity: Option<FindingSeverity>,
    pub failed_policy: bool,
    pub fail_on: String,
    pub baseline_diff: Option<CliBaselineDiff>,
    pub findings: Vec<PassiveFinding>,
    pub endpoint_results: Vec<CliScanEndpointResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliScanEndpointResult {
    pub method: String,
    pub url: String,
    pub status_code: u16,
    pub findings: Vec<PassiveFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CliHtmlCrawlResult {
    pub base_url: String,
    pub candidate_count: usize,
    pub candidates: Vec<CrawlCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CliBrowserCrawlResult {
    pub base_url: String,
    pub route_count: usize,
    pub request_count: usize,
    pub candidate_count: usize,
    pub candidates: Vec<CrawlCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CliUrlCrawlResult {
    pub seed_url: String,
    pub page_count: usize,
    pub candidate_count: usize,
    pub pages: Vec<CrawlPage>,
    pub candidates: Vec<CrawlCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliActiveVerifyReport {
    pub target_url: String,
    pub finding_count: usize,
    pub highest_severity: Option<FindingSeverity>,
    pub failed_policy: bool,
    pub fail_on: String,
    pub baseline_diff: Option<CliBaselineDiff>,
    pub findings: Vec<PassiveFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CliSavedScanReport {
    pub scan: ScanRecord,
    pub finding_count: usize,
    pub highest_severity: Option<String>,
    pub findings: Vec<FindingRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CliLocalScanReport {
    pub project_id: Option<String>,
    pub target_id: Option<String>,
    pub profile: String,
    pub target_count: usize,
    pub endpoint_count: usize,
    pub finding_count: usize,
    pub highest_severity: Option<FindingSeverity>,
    pub failed_policy: bool,
    pub fail_on: String,
    pub findings: Vec<CliLocalScanFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CliLocalScanFinding {
    pub target_id: String,
    pub target_name: String,
    pub endpoint: String,
    pub method: String,
    pub status_code: Option<u16>,
    pub finding: PassiveFinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CliRulesTestReport {
    pub path: String,
    pub file_count: usize,
    pub rule_count: usize,
    pub issue_count: usize,
    pub passed: bool,
    pub rules: Vec<CliRuleSummary>,
    pub issues: Vec<CliRuleIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CliRuleSummary {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub enabled: bool,
    pub confidence: String,
    pub cwe: Option<String>,
    pub owasp_category: Option<String>,
    pub source_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CliRuleIssue {
    pub source_file: String,
    pub rule_id: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CliRulesFeedCheckReport {
    pub file: String,
    pub current_version: Option<String>,
    pub latest_version: String,
    pub channel: String,
    pub update_available: bool,
    pub entitlement_allowed: bool,
    pub manifest_sha256: String,
    pub manifest_url: Option<String>,
    pub published_at: Option<String>,
    pub minimum_app_version: Option<String>,
    pub signature_verified: bool,
    pub issue_count: usize,
    pub passed: bool,
    pub issues: Vec<CliRulesFeedIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CliRulesFeedIssue {
    pub field: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CliRulesFeedSignReport {
    pub input_file: String,
    pub output_file: Option<String>,
    pub latest_version: String,
    pub channel: String,
    pub public_key_hex: String,
    pub signature: String,
    #[serde(skip_serializing)]
    pub signed_document: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CliRulesBundleCheckReport {
    pub file: String,
    pub entry_count: usize,
    pub manifest_path: Option<String>,
    pub manifest_sha256: Option<String>,
    pub version: Option<String>,
    pub channel: Option<String>,
    pub rule_count: usize,
    pub enabled_rule_count: usize,
    pub disabled_rule_count: usize,
    pub entitlement_allowed: bool,
    pub signature_verified: bool,
    pub issue_count: usize,
    pub passed: bool,
    pub issues: Vec<CliRulesFeedIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliBaselineDiff {
    pub baseline_file: String,
    pub fail_on_new: String,
    pub new_count: usize,
    pub recurring_count: usize,
    pub resolved_count: usize,
    pub new_findings: Vec<PassiveFinding>,
    pub recurring_findings: Vec<PassiveFinding>,
    pub resolved_findings: Vec<PassiveFinding>,
}

#[derive(Debug, Deserialize)]
struct BaselineFindingsReport {
    findings: Vec<PassiveFinding>,
}

#[derive(Debug, Deserialize)]
struct RulePackDocument {
    rules: Vec<RulePackRule>,
}

#[derive(Debug, Deserialize)]
struct RulePackRule {
    id: Option<String>,
    title: Option<String>,
    severity: Option<String>,
    enabled: Option<bool>,
    confidence: Option<String>,
    cwe: Option<String>,
    owasp_category: Option<String>,
    evidence: Option<String>,
    recommendation: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RulePackManifestDocument {
    version: Option<String>,
    channel: Option<String>,
    published_at: Option<String>,
    rules: Vec<RulePackRule>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RulePackUpdateFeedDocument {
    latest_version: Option<String>,
    channel: Option<String>,
    manifest_sha256: Option<String>,
    manifest_url: Option<String>,
    published_at: Option<String>,
    minimum_app_version: Option<String>,
    signature: Option<String>,
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    Scan(#[from] ScannerError),
    #[error("{0}")]
    OpenApi(#[from] OpenApiImportError),
    #[error("{0}")]
    UrlSeed(#[from] UrlSeedImportError),
    #[error("{0}")]
    Crawler(#[from] CrawlerError),
    #[error("{0}")]
    Storage(#[from] StorageError),
    #[error("OpenAPI document is too large")]
    DocumentTooLarge,
    #[error("URL seed document is too large")]
    UrlSeedDocumentTooLarge,
    #[error("HTML document is too large")]
    HtmlDocumentTooLarge,
    #[error("failed to read OpenAPI document: {0}")]
    ReadDocument(#[from] std::io::Error),
    #[error("failed to serialize report: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("baseline report file is too large")]
    BaselineTooLarge,
    #[error("failed to parse baseline report: {0}")]
    ParseBaseline(serde_json::Error),
    #[error("failed to parse browser crawl log: {0}")]
    ParseBrowserLog(serde_json::Error),
    #[error("saved scan was not found in local storage")]
    SavedScanNotFound,
    #[error("local scan requires --project-id or --target-id")]
    LocalScanTargetRequired,
    #[error("local scan target was not found in local storage")]
    LocalScanTargetNotFound,
    #[error("rule document is too large")]
    RuleDocumentTooLarge,
    #[error("rule feed document is too large")]
    RuleFeedDocumentTooLarge,
    #[error("rule bundle archive is too large")]
    RuleBundleTooLarge,
    #[error("failed to read rule bundle archive: {0}")]
    RuleBundleArchive(String),
    #[error("rules path must be a JSON file or a directory containing JSON files")]
    RulesPathInvalid,
    #[error("failed to parse rule document {path}: {source}")]
    ParseRuleDocument {
        path: String,
        source: serde_json::Error,
    },
    #[error("failed to parse rule feed document {path}: {source}")]
    ParseRuleFeedDocument {
        path: String,
        source: serde_json::Error,
    },
    #[error("rule feed must pass schema validation before signing")]
    RuleFeedInvalidForSigning,
    #[error("{0}")]
    RuleFeedSigningKey(String),
    #[error("scan requires either --url or --openapi")]
    ScanTargetRequired,
    #[error("scan accepts only one of --url or --openapi")]
    ScanTargetConflict,
    #[error("{field} must be between {min} and {max}")]
    CrawlOptionOutOfRange {
        field: &'static str,
        min: usize,
        max: usize,
    },
}

pub fn run_scan_command(
    command: &ScanCommand,
    client: &impl HttpProbeClient,
) -> Result<CliScanReport, CliError> {
    match (&command.url, &command.openapi) {
        (Some(_), Some(_)) => return Err(CliError::ScanTargetConflict),
        (None, None) => return Err(CliError::ScanTargetRequired),
        (Some(_), None) => {}
        (None, Some(_)) => return run_openapi_scan_command(command, client),
    }

    let url = command
        .url
        .as_ref()
        .expect("url was checked above")
        .trim()
        .to_string();
    let target = ScanTarget {
        id: "cli-target".to_string(),
        method: None,
        url: url.clone(),
        approval_note: command.approval_note.clone(),
        allow_private_network: command.allow_private_network,
    };
    let (response, findings) = run_passive_probe(&target, client)?;
    let endpoint_results = vec![CliScanEndpointResult {
        method: "GET".to_string(),
        url: response.final_url.clone(),
        status_code: response.status_code,
        findings: findings.clone(),
    }];
    let report_highest_severity = highest_severity(&findings);
    let threshold_failed = report_highest_severity
        .map(|severity| severity_meets_policy(severity, command.fail_on))
        .unwrap_or(false);
    let baseline_diff = command
        .baseline_file
        .as_ref()
        .map(|path| {
            baseline_diff(
                path,
                command.fail_on_new.unwrap_or(command.fail_on),
                &findings,
            )
        })
        .transpose()?;
    let new_policy_failed = baseline_diff
        .as_ref()
        .map(|diff| {
            highest_severity(&diff.new_findings)
                .map(|severity| {
                    severity_meets_policy(severity, command.fail_on_new.unwrap_or(command.fail_on))
                })
                .unwrap_or(false)
        })
        .unwrap_or(false);

    Ok(CliScanReport {
        scan_source: "url".to_string(),
        target_url: url,
        final_url: response.final_url,
        status_code: response.status_code,
        endpoint_count: 1,
        skipped_endpoint_count: 0,
        finding_count: findings.len(),
        highest_severity: report_highest_severity,
        failed_policy: threshold_failed || new_policy_failed,
        fail_on: format!("{:?}", command.fail_on).to_ascii_lowercase(),
        baseline_diff,
        findings,
        endpoint_results,
    })
}

fn run_openapi_scan_command(
    command: &ScanCommand,
    client: &impl HttpProbeClient,
) -> Result<CliScanReport, CliError> {
    let openapi_file = command.openapi.as_ref().expect("openapi was checked");
    let import_command = ImportOpenApiCommand {
        file: openapi_file.clone(),
        base_url: command.base_url.clone(),
        format: OutputFormat::Json,
    };
    let import_result = run_import_openapi_command(&import_command)?;
    let mut findings = Vec::new();
    let mut endpoint_results = Vec::new();
    let mut skipped_endpoint_count = 0usize;

    for endpoint in &import_result.endpoints {
        if !matches!(endpoint.method.as_str(), "GET" | "HEAD") {
            skipped_endpoint_count += 1;
            continue;
        }
        let target = ScanTarget {
            id: endpoint
                .operation_id
                .clone()
                .unwrap_or_else(|| format!("{} {}", endpoint.method, endpoint.path)),
            method: Some(endpoint.method.clone()),
            url: endpoint.url.clone(),
            approval_note: command.approval_note.clone(),
            allow_private_network: command.allow_private_network,
        };
        let (response, endpoint_findings) = run_passive_probe(&target, client)?;
        findings.extend(endpoint_findings.clone());
        endpoint_results.push(CliScanEndpointResult {
            method: endpoint.method.clone(),
            url: endpoint.url.clone(),
            status_code: response.status_code,
            findings: endpoint_findings,
        });
    }

    let report_highest_severity = highest_severity(&findings);
    let threshold_failed = report_highest_severity
        .map(|severity| severity_meets_policy(severity, command.fail_on))
        .unwrap_or(false);
    let baseline_diff = command
        .baseline_file
        .as_ref()
        .map(|path| {
            baseline_diff(
                path,
                command.fail_on_new.unwrap_or(command.fail_on),
                &findings,
            )
        })
        .transpose()?;
    let new_policy_failed = baseline_diff
        .as_ref()
        .map(|diff| {
            highest_severity(&diff.new_findings)
                .map(|severity| {
                    severity_meets_policy(severity, command.fail_on_new.unwrap_or(command.fail_on))
                })
                .unwrap_or(false)
        })
        .unwrap_or(false);
    let status_code = endpoint_results
        .first()
        .map(|result| result.status_code)
        .unwrap_or(0);

    Ok(CliScanReport {
        scan_source: "openapi".to_string(),
        target_url: import_result.base_url.clone(),
        final_url: import_result.base_url,
        status_code,
        endpoint_count: endpoint_results.len(),
        skipped_endpoint_count,
        finding_count: findings.len(),
        highest_severity: report_highest_severity,
        failed_policy: threshold_failed || new_policy_failed,
        fail_on: format!("{:?}", command.fail_on).to_ascii_lowercase(),
        baseline_diff,
        findings,
        endpoint_results,
    })
}

pub fn run_local_scan_command(
    command: &LocalScanCommand,
    client: &impl HttpProbeClient,
) -> Result<CliLocalScanReport, CliError> {
    let database_path = local_database_path(&command.app_data_dir, command.database.as_ref());
    let targets = select_local_scan_targets(command, &database_path)?;
    let mut findings = Vec::new();
    let mut endpoint_count = 0usize;

    for target in &targets {
        for scan_target in local_scan_targets_for_target(
            &command.app_data_dir,
            &database_path,
            target,
            command.profile,
        )? {
            endpoint_count += 1;
            let method = scan_target
                .method
                .clone()
                .unwrap_or_else(|| "GET".to_string());
            if matches!(command.profile, LocalScanProfile::Safe) {
                let active_findings = run_safe_active_verifiers(&scan_target, client)?;
                findings.extend(
                    active_findings
                        .into_iter()
                        .map(|finding| CliLocalScanFinding {
                            target_id: target.id.clone(),
                            target_name: target.name.clone(),
                            endpoint: scan_target.url.clone(),
                            method: method.clone(),
                            status_code: None,
                            finding,
                        }),
                );
            } else {
                let (response, passive_findings) = run_passive_probe(&scan_target, client)?;
                findings.extend(
                    passive_findings
                        .into_iter()
                        .map(|finding| CliLocalScanFinding {
                            target_id: target.id.clone(),
                            target_name: target.name.clone(),
                            endpoint: scan_target.url.clone(),
                            method: method.clone(),
                            status_code: Some(response.status_code),
                            finding,
                        }),
                );
            }
        }
    }

    let highest_severity = highest_local_severity(&findings);
    let failed_policy = highest_severity
        .map(|severity| severity_meets_policy(severity, command.fail_on))
        .unwrap_or(false);

    Ok(CliLocalScanReport {
        project_id: command.project_id.clone(),
        target_id: command.target_id.clone(),
        profile: format!("{:?}", command.profile).to_ascii_lowercase(),
        target_count: targets.len(),
        endpoint_count,
        finding_count: findings.len(),
        highest_severity,
        failed_policy,
        fail_on: format!("{:?}", command.fail_on).to_ascii_lowercase(),
        findings,
    })
}

pub fn render_report(report: &CliScanReport, format: ReportFormat) -> Result<String, CliError> {
    let report = redacted_scan_report(report);
    if matches!(format, ReportFormat::Json) {
        return render_json_report_with_evidence_metadata(&report);
    }
    if matches!(format, ReportFormat::Sarif) {
        return render_scan_sarif_report(&report);
    }

    let highest = report
        .highest_severity
        .map(|severity| format!("{:?}", severity).to_ascii_lowercase())
        .unwrap_or_else(|| "none".to_string());
    let baseline = report
        .baseline_diff
        .as_ref()
        .map(|diff| {
            format!(
                "\nBaseline: new {}, recurring {}, resolved {}",
                diff.new_count, diff.recurring_count, diff.resolved_count
            )
        })
        .unwrap_or_default();
    Ok(format!(
        "Aegis scan completed\nSource: {}\nTarget: {}\nStatus: {}\nEndpoints: {}\nSkipped endpoints: {}\nFindings: {}\nManual confirmation required: {}\nHighest severity: {}\nPolicy failed: {}",
        report.scan_source,
        report.final_url,
        report.status_code,
        report.endpoint_count,
        report.skipped_endpoint_count,
        report.finding_count,
        count_manual_confirmation_findings(&report.findings),
        highest,
        report.failed_policy
    ) + &baseline)
}

pub fn render_local_scan_report(
    report: &CliLocalScanReport,
    format: ReportFormat,
) -> Result<String, CliError> {
    let report = redacted_local_scan_report(report);
    if matches!(format, ReportFormat::Json) {
        return render_json_report_with_evidence_metadata(&report);
    }
    if matches!(format, ReportFormat::Sarif) {
        return render_local_sarif_report(&report);
    }

    let highest = report
        .highest_severity
        .map(|severity| format!("{:?}", severity).to_ascii_lowercase())
        .unwrap_or_else(|| "none".to_string());
    Ok(format!(
        "Local scan completed\nTargets: {}\nEndpoints: {}\nProfile: {}\nFindings: {}\nManual confirmation required: {}\nHighest severity: {}\nPolicy failed: {}",
        report.target_count,
        report.endpoint_count,
        report.profile,
        report.finding_count,
        report
            .findings
            .iter()
            .filter(|finding| evidence_metadata_from_text(&finding.finding.evidence).requires_manual_confirmation)
            .count(),
        highest,
        report.failed_policy
    ))
}

pub fn run_import_openapi_command(
    command: &ImportOpenApiCommand,
) -> Result<OpenApiImportResult, CliError> {
    let metadata = fs::metadata(&command.file)?;
    if metadata.len() > MAX_OPENAPI_DOCUMENT_BYTES {
        return Err(CliError::DocumentTooLarge);
    }
    let document = fs::read_to_string(&command.file)?;
    import_openapi_document(&document, command.base_url.as_deref()).map_err(CliError::from)
}

pub fn run_import_urls_command(
    command: &ImportUrlsCommand,
) -> Result<UrlSeedImportResult, CliError> {
    let metadata = fs::metadata(&command.file)?;
    if metadata.len() > MAX_URL_SEED_DOCUMENT_BYTES {
        return Err(CliError::UrlSeedDocumentTooLarge);
    }
    let document = fs::read_to_string(&command.file)?;
    import_url_seed_document(&document).map_err(CliError::from)
}

pub fn run_crawl_html_command(command: &CrawlHtmlCommand) -> Result<CliHtmlCrawlResult, CliError> {
    let metadata = fs::metadata(&command.file)?;
    if metadata.len() > MAX_HTML_DOCUMENT_BYTES {
        return Err(CliError::HtmlDocumentTooLarge);
    }
    let document = fs::read_to_string(&command.file)?;
    let candidates = extract_html_candidates(&command.base_url, &document)?;

    Ok(CliHtmlCrawlResult {
        base_url: command.base_url.trim().to_string(),
        candidate_count: candidates.len(),
        candidates,
    })
}

pub fn run_crawl_browser_log_command(
    command: &CrawlBrowserLogCommand,
) -> Result<CliBrowserCrawlResult, CliError> {
    let metadata = fs::metadata(&command.file)?;
    if metadata.len() > MAX_HTML_DOCUMENT_BYTES {
        return Err(CliError::HtmlDocumentTooLarge);
    }
    let document = fs::read_to_string(&command.file)?;
    let observation = serde_json::from_str::<BrowserCrawlObservation>(&document)
        .map_err(CliError::ParseBrowserLog)?;
    let candidates = extract_browser_observation_candidates(&command.base_url, &observation)?;

    Ok(CliBrowserCrawlResult {
        base_url: command.base_url.trim().to_string(),
        route_count: observation.routes.len(),
        request_count: observation.requests.len(),
        candidate_count: candidates.len(),
        candidates,
    })
}

pub fn run_crawl_url_command(
    command: &CrawlUrlCommand,
    client: &impl CrawlerFetchClient,
) -> Result<CliUrlCrawlResult, CliError> {
    let crawler_options =
        validate_crawl_url_options(command.max_pages, command.max_candidates, command.max_depth)?;
    let target = ScanTarget {
        id: "cli-crawl-target".to_string(),
        method: Some("GET".to_string()),
        url: command.url.clone(),
        approval_note: command.approval_note.clone(),
        allow_private_network: command.allow_private_network,
    };
    build_passive_probe(&target)?;

    let result = crawl_approved_html_surface(&command.url, crawler_options, client)?;

    Ok(CliUrlCrawlResult {
        seed_url: command.url.trim().to_string(),
        page_count: result.pages.len(),
        candidate_count: result.candidates.len(),
        pages: result.pages,
        candidates: result.candidates,
    })
}

fn validate_crawl_url_options(
    max_pages: usize,
    max_candidates: usize,
    max_depth: usize,
) -> Result<CrawlerOptions, CliError> {
    validate_crawl_url_bound("max-pages", max_pages, 1, MAX_CRAWL_URL_PAGES)?;
    validate_crawl_url_bound(
        "max-candidates",
        max_candidates,
        1,
        MAX_CRAWL_URL_CANDIDATES,
    )?;
    validate_crawl_url_bound("max-depth", max_depth, 0, MAX_CRAWL_URL_DEPTH)?;

    Ok(CrawlerOptions {
        max_pages,
        max_candidates,
        max_depth,
        ..CrawlerOptions::default()
    })
}

fn validate_crawl_url_bound(
    field: &'static str,
    value: usize,
    min: usize,
    max: usize,
) -> Result<(), CliError> {
    if value < min || value > max {
        return Err(CliError::CrawlOptionOutOfRange { field, min, max });
    }
    Ok(())
}

pub fn run_verify_active_command(
    command: &VerifyActiveCommand,
    client: &impl HttpProbeClient,
) -> Result<CliActiveVerifyReport, CliError> {
    let target = ScanTarget {
        id: "cli-active-target".to_string(),
        method: Some("GET".to_string()),
        url: command.url.clone(),
        approval_note: command.approval_note.clone(),
        allow_private_network: command.allow_private_network,
    };
    let findings = run_safe_active_verifiers(&target, client)?;
    let report_highest_severity = highest_severity(&findings);
    let threshold_failed = report_highest_severity
        .map(|severity| severity_meets_policy(severity, command.fail_on))
        .unwrap_or(false);
    let baseline_diff = command
        .baseline_file
        .as_ref()
        .map(|path| {
            baseline_diff(
                path,
                command.fail_on_new.unwrap_or(command.fail_on),
                &findings,
            )
        })
        .transpose()?;
    let new_policy_failed = baseline_diff
        .as_ref()
        .map(|diff| {
            highest_severity(&diff.new_findings)
                .map(|severity| {
                    severity_meets_policy(severity, command.fail_on_new.unwrap_or(command.fail_on))
                })
                .unwrap_or(false)
        })
        .unwrap_or(false);

    Ok(CliActiveVerifyReport {
        target_url: command.url.trim().to_string(),
        finding_count: findings.len(),
        highest_severity: report_highest_severity,
        failed_policy: threshold_failed || new_policy_failed,
        fail_on: format!("{:?}", command.fail_on).to_ascii_lowercase(),
        baseline_diff,
        findings,
    })
}

pub fn run_report_export_command(
    command: &ReportExportCommand,
) -> Result<CliSavedScanReport, CliError> {
    let database_path = command
        .database
        .clone()
        .unwrap_or_else(|| command.app_data_dir.join("aegis-webshield-ai.sqlite3"));
    let scans = list_scans(&command.app_data_dir, &database_path)?;
    let scan = scans
        .into_iter()
        .find(|scan| scan.id == command.scan_id)
        .ok_or(CliError::SavedScanNotFound)?;
    let findings = list_findings(&command.app_data_dir, &database_path)?
        .into_iter()
        .filter(|finding| finding.scan_id == scan.id)
        .collect::<Vec<_>>();
    let highest_severity = highest_saved_severity(&findings).map(str::to_string);

    Ok(CliSavedScanReport {
        scan,
        finding_count: findings.len(),
        highest_severity,
        findings,
    })
}

pub fn run_rules_test_command(command: &RulesTestCommand) -> Result<CliRulesTestReport, CliError> {
    let rule_files = discover_rule_files(&command.path)?;
    let mut rules = Vec::new();
    let mut issues = Vec::new();
    let mut seen_rule_ids = BTreeSet::new();

    for rule_file in &rule_files {
        let source_file = rule_file.display().to_string();
        let metadata = fs::metadata(rule_file)?;
        if metadata.len() > MAX_RULE_DOCUMENT_BYTES {
            return Err(CliError::RuleDocumentTooLarge);
        }
        let document = fs::read_to_string(rule_file)?;
        let parsed = serde_json::from_str::<RulePackDocument>(json_without_bom(&document))
            .map_err(|source| CliError::ParseRuleDocument {
                path: source_file.clone(),
                source,
            })?;

        if parsed.rules.is_empty() {
            issues.push(CliRuleIssue {
                source_file: source_file.clone(),
                rule_id: None,
                message: "rule document must contain at least one rule".to_string(),
            });
        }

        for rule in parsed.rules {
            let rule_id = optional_trimmed(&rule.id).unwrap_or_default();
            if !seen_rule_ids.insert(rule_id.clone()) {
                issues.push(CliRuleIssue {
                    source_file: source_file.clone(),
                    rule_id: Some(rule_id.clone()),
                    message: "rule id must be unique across the tested rule pack".to_string(),
                });
            }
            issues.extend(validate_rule_pack_rule(&source_file, &rule));
            rules.push(CliRuleSummary {
                id: rule_id,
                title: optional_trimmed(&rule.title).unwrap_or_default(),
                severity: optional_trimmed(&rule.severity)
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
                enabled: rule.enabled.unwrap_or(true),
                confidence: optional_trimmed(&rule.confidence)
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
                cwe: optional_trimmed(&rule.cwe),
                owasp_category: rule
                    .owasp_category
                    .as_ref()
                    .map(|value| value.trim().to_string()),
                source_file: source_file.clone(),
            });
        }
    }

    Ok(CliRulesTestReport {
        path: command.path.display().to_string(),
        file_count: rule_files.len(),
        rule_count: rules.len(),
        issue_count: issues.len(),
        passed: issues.is_empty(),
        rules,
        issues,
    })
}

pub fn run_rules_feed_check_command(
    command: &RulesFeedCheckCommand,
) -> Result<CliRulesFeedCheckReport, CliError> {
    let metadata = fs::metadata(&command.file)?;
    if metadata.len() > MAX_RULE_FEED_DOCUMENT_BYTES {
        return Err(CliError::RuleFeedDocumentTooLarge);
    }
    let source_file = command.file.display().to_string();
    let document = fs::read_to_string(&command.file)?;
    let feed = serde_json::from_str::<RulePackUpdateFeedDocument>(json_without_bom(&document))
        .map_err(|source| CliError::ParseRuleFeedDocument {
            path: source_file.clone(),
            source,
        })?;

    let mut issues = validate_rule_pack_update_feed(&feed);
    let signature_verified = match optional_trimmed(&command.public_key_hex) {
        Some(public_key_hex) => match verify_rule_feed_signature(&feed, &public_key_hex) {
            Ok(()) => true,
            Err(message) => {
                issues.push(rule_feed_issue("signature", &message));
                false
            }
        },
        None => false,
    };
    let latest_version = optional_trimmed(&feed.latest_version).unwrap_or_default();
    let channel = optional_trimmed(&feed.channel).unwrap_or_default();
    let manifest_sha256 = optional_trimmed(&feed.manifest_sha256).unwrap_or_default();
    let entitlement_allowed = rule_pack_channel_supported(&channel);
    if !entitlement_allowed {
        issues.push(CliRulesFeedIssue {
            field: "channel".to_string(),
            message: rule_feed_channel_block_reason(&channel).to_string(),
        });
    }
    let current_version = command
        .current_version
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let update_available = current_version
        .as_ref()
        .map(|current| latest_version.as_str() > current.as_str())
        .unwrap_or(false);
    let issue_count = issues.len();

    Ok(CliRulesFeedCheckReport {
        file: source_file,
        current_version,
        latest_version,
        channel,
        update_available,
        entitlement_allowed,
        manifest_sha256,
        manifest_url: optional_trimmed(&feed.manifest_url),
        published_at: optional_trimmed(&feed.published_at),
        minimum_app_version: optional_trimmed(&feed.minimum_app_version),
        signature_verified,
        issue_count,
        passed: issue_count == 0,
        issues,
    })
}

pub fn run_rules_feed_sign_command(
    command: &RulesFeedSignCommand,
) -> Result<CliRulesFeedSignReport, CliError> {
    let metadata = fs::metadata(&command.file)?;
    if metadata.len() > MAX_RULE_FEED_DOCUMENT_BYTES {
        return Err(CliError::RuleFeedDocumentTooLarge);
    }
    let source_file = command.file.display().to_string();
    let document = fs::read_to_string(&command.file)?;
    let mut feed = serde_json::from_str::<RulePackUpdateFeedDocument>(json_without_bom(&document))
        .map_err(|source| CliError::ParseRuleFeedDocument {
            path: source_file.clone(),
            source,
        })?;
    let issues = validate_rule_pack_update_feed(&feed);
    if !issues.is_empty() {
        return Err(CliError::RuleFeedInvalidForSigning);
    }
    let signing_key = rule_feed_signing_key(&command.private_key_hex)?;
    feed.signature = None;
    let signature = signing_key.sign(rule_feed_signature_payload(&feed).as_bytes());
    let signature_hex = hex_encode(signature.to_bytes().as_slice());
    feed.signature = Some(signature_hex.clone());
    let signed_document = serde_json::to_string_pretty(&feed)?;
    if let Some(out_path) = &command.out {
        fs::write(out_path, signed_document.as_bytes())?;
    }

    Ok(CliRulesFeedSignReport {
        input_file: source_file,
        output_file: command.out.as_ref().map(|path| path.display().to_string()),
        latest_version: optional_trimmed(&feed.latest_version).unwrap_or_default(),
        channel: optional_trimmed(&feed.channel).unwrap_or_default(),
        public_key_hex: hex_encode(signing_key.verifying_key().to_bytes().as_slice()),
        signature: signature_hex,
        signed_document,
    })
}

pub fn run_rules_bundle_check_command(
    command: &RulesBundleCheckCommand,
) -> Result<CliRulesBundleCheckReport, CliError> {
    let metadata = fs::metadata(&command.file)?;
    if metadata.len() > MAX_RULE_BUNDLE_BYTES {
        return Err(CliError::RuleBundleTooLarge);
    }

    let source_file = command.file.display().to_string();
    let bundle_bytes = fs::read(&command.file)?;
    let archive = parse_rule_bundle_zip(&bundle_bytes)?;
    let entry_count = archive.len();
    let mut issues = Vec::new();
    let mut manifest_document = None;
    let mut signature_hex = None;

    for entry in &archive {
        if !is_safe_rule_bundle_entry_name(&entry.name) {
            issues.push(rule_feed_issue(
                "entry",
                &format!("bundle entry path is not allowed: {}", entry.name),
            ));
        }
        if entry.uncompressed_size > MAX_RULE_BUNDLE_ENTRY_BYTES {
            issues.push(rule_feed_issue(
                "entry",
                &format!("bundle entry is too large: {}", entry.name),
            ));
        }

        if entry.name == "manifest.json" {
            let document = read_rule_bundle_entry(&bundle_bytes, entry)?;
            manifest_document = Some(String::from_utf8(document).map_err(|error| {
                CliError::RuleBundleArchive(format!("manifest.json is not valid UTF-8: {error}"))
            })?);
        } else if entry.name == "manifest.sig" {
            let document = read_rule_bundle_entry(&bundle_bytes, entry)?;
            let document = String::from_utf8(document).map_err(|error| {
                CliError::RuleBundleArchive(format!("manifest.sig is not valid UTF-8: {error}"))
            })?;
            signature_hex = optional_trimmed(&Some(document));
        }
    }

    let mut manifest_path = None;
    let mut manifest_sha256 = None;
    let mut version = None;
    let mut channel = None;
    let mut rule_count = 0usize;
    let mut enabled_rule_count = 0usize;
    let mut disabled_rule_count = 0usize;
    let mut entitlement_allowed = true;
    let mut signature_verified = false;

    if let Some(document) = manifest_document {
        manifest_path = Some("manifest.json".to_string());
        if document.len() as u64 > MAX_RULE_DOCUMENT_BYTES {
            issues.push(rule_feed_issue(
                "manifest",
                "manifest.json is larger than 512KB",
            ));
        }
        let actual_sha256 = sha256_hex(document.as_bytes());
        manifest_sha256 = Some(actual_sha256.clone());
        if let Some(expected) = optional_trimmed(&command.expected_manifest_sha256) {
            if !is_valid_sha256_hex(&expected) {
                issues.push(rule_feed_issue(
                    "expected_manifest_sha256",
                    "expected_manifest_sha256 must be 64 hexadecimal characters",
                ));
            } else if !expected.eq_ignore_ascii_case(&actual_sha256) {
                issues.push(rule_feed_issue(
                    "expected_manifest_sha256",
                    "manifest SHA-256 does not match expected_manifest_sha256",
                ));
            }
        }
        match serde_json::from_str::<RulePackManifestDocument>(json_without_bom(&document)) {
            Ok(manifest) => {
                version = optional_trimmed(&manifest.version);
                channel = optional_trimmed(&manifest.channel);
                rule_count = manifest.rules.len();
                enabled_rule_count = manifest
                    .rules
                    .iter()
                    .filter(|rule| rule.enabled != Some(false))
                    .count();
                disabled_rule_count = manifest
                    .rules
                    .iter()
                    .filter(|rule| rule.enabled == Some(false))
                    .count();
                issues.extend(validate_rule_pack_manifest_document(&manifest));
                entitlement_allowed = channel
                    .as_deref()
                    .map(|value| rule_pack_channel_supported(value))
                    .unwrap_or(false);
                if !entitlement_allowed {
                    issues.push(rule_feed_issue(
                        "channel",
                        rule_feed_channel_block_reason(channel.as_deref().unwrap_or("")),
                    ));
                }
            }
            Err(source) => issues.push(rule_feed_issue(
                "manifest",
                &format!("manifest.json parse failed: {source}"),
            )),
        }

        if let Some(public_key_hex) = optional_trimmed(&command.public_key_hex) {
            match signature_hex {
                Some(signature_hex) => {
                    match verify_detached_ed25519_signature(
                        document.as_bytes(),
                        &public_key_hex,
                        &signature_hex,
                    ) {
                        Ok(()) => signature_verified = true,
                        Err(message) => issues.push(rule_feed_issue("manifest.sig", &message)),
                    }
                }
                None => issues.push(rule_feed_issue(
                    "manifest.sig",
                    "manifest.sig is required when --public-key-hex is provided",
                )),
            }
        }
    } else {
        issues.push(rule_feed_issue(
            "manifest",
            "rule bundle must contain root manifest.json",
        ));
    }

    let issue_count = issues.len();
    Ok(CliRulesBundleCheckReport {
        file: source_file,
        entry_count,
        manifest_path,
        manifest_sha256,
        version,
        channel,
        rule_count,
        enabled_rule_count,
        disabled_rule_count,
        entitlement_allowed,
        signature_verified,
        issue_count,
        passed: issue_count == 0,
        issues,
    })
}

pub fn render_openapi_import(
    result: &OpenApiImportResult,
    format: OutputFormat,
) -> Result<String, CliError> {
    if matches!(format, OutputFormat::Json) {
        return Ok(serde_json::to_string_pretty(result)?);
    }

    Ok(format!(
        "OpenAPI import completed\nTitle: {}\nBase URL: {}\nEndpoints: {}",
        result.title.as_deref().unwrap_or("untitled"),
        result.base_url,
        result.endpoints.len()
    ))
}

pub fn render_saved_scan_report(
    report: &CliSavedScanReport,
    format: ReportFormat,
) -> Result<String, CliError> {
    let report = redacted_saved_scan_report(report);
    if matches!(format, ReportFormat::Json) {
        return render_json_report_with_evidence_metadata(&report);
    }
    if matches!(format, ReportFormat::Sarif) {
        return render_saved_sarif_report(&report);
    }

    Ok(format!(
        "Saved scan report exported\nScan: {}\nTarget: {}\nPhase: {}\nFindings: {}\nManual confirmation required: {}\nHighest severity: {}",
        report.scan.id,
        report.scan.target_url,
        report.scan.phase,
        report.finding_count,
        report
            .findings
            .iter()
            .filter(|finding| evidence_metadata_from_json_text(&finding.evidence_json).requires_manual_confirmation)
            .count(),
        report.highest_severity.as_deref().unwrap_or("none")
    ))
}

pub fn render_rules_test(
    report: &CliRulesTestReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    if matches!(format, OutputFormat::Json) {
        return Ok(serde_json::to_string_pretty(report)?);
    }

    Ok(format!(
        "Rules test completed\nFiles: {}\nRules: {}\nIssues: {}\nPassed: {}",
        report.file_count, report.rule_count, report.issue_count, report.passed
    ))
}

pub fn render_rules_feed_check(
    report: &CliRulesFeedCheckReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    if matches!(format, OutputFormat::Json) {
        return Ok(serde_json::to_string_pretty(report)?);
    }

    Ok(format!(
        "Rules feed check completed\nCurrent version: {}\nLatest version: {}\nChannel: {}\nUpdate available: {}\nChannel supported: {}\nSignature verified: {}\nIssues: {}\nPassed: {}",
        report.current_version.as_deref().unwrap_or("unknown"),
        report.latest_version,
        report.channel,
        report.update_available,
        report.entitlement_allowed,
        report.signature_verified,
        report.issue_count,
        report.passed
    ))
}

pub fn render_rules_feed_sign(
    report: &CliRulesFeedSignReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    if matches!(format, OutputFormat::Json) {
        if report.output_file.is_none() {
            return Ok(report.signed_document.clone());
        }
        return Ok(serde_json::to_string_pretty(report)?);
    }

    Ok(format!(
        "Rules feed signed\nLatest version: {}\nChannel: {}\nOutput: {}\nPublic key: {}\nSignature: {}",
        report.latest_version,
        report.channel,
        report.output_file.as_deref().unwrap_or("stdout"),
        report.public_key_hex,
        report.signature
    ))
}

pub fn render_rules_bundle_check(
    report: &CliRulesBundleCheckReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    if matches!(format, OutputFormat::Json) {
        return Ok(serde_json::to_string_pretty(report)?);
    }

    Ok(format!(
        "Rules bundle check completed\nEntries: {}\nManifest: {}\nVersion: {}\nChannel: {}\nRules: {} enabled / {} total\nChannel supported: {}\nSignature verified: {}\nIssues: {}\nPassed: {}",
        report.entry_count,
        report.manifest_path.as_deref().unwrap_or("missing"),
        report.version.as_deref().unwrap_or("unknown"),
        report.channel.as_deref().unwrap_or("unknown"),
        report.enabled_rule_count,
        report.rule_count,
        report.entitlement_allowed,
        report.signature_verified,
        report.issue_count,
        report.passed
    ))
}

pub fn render_url_seed_import(
    result: &UrlSeedImportResult,
    format: OutputFormat,
) -> Result<String, CliError> {
    if matches!(format, OutputFormat::Json) {
        return Ok(serde_json::to_string_pretty(result)?);
    }

    Ok(format!(
        "URL seed import completed\nSeeds: {}\nSkipped lines: {}",
        result.seed_count, result.skipped_count
    ))
}

pub fn render_html_crawl(
    result: &CliHtmlCrawlResult,
    format: OutputFormat,
) -> Result<String, CliError> {
    if matches!(format, OutputFormat::Json) {
        return Ok(serde_json::to_string_pretty(result)?);
    }

    Ok(format!(
        "HTML crawl completed\nBase URL: {}\nCandidates: {}",
        result.base_url, result.candidate_count
    ))
}

pub fn render_browser_crawl(
    result: &CliBrowserCrawlResult,
    format: OutputFormat,
) -> Result<String, CliError> {
    if matches!(format, OutputFormat::Json) {
        return Ok(serde_json::to_string_pretty(result)?);
    }

    Ok(format!(
        "Browser crawl log completed\nBase URL: {}\nRoutes: {}\nRequests: {}\nCandidates: {}",
        result.base_url, result.route_count, result.request_count, result.candidate_count
    ))
}

pub fn render_url_crawl(
    result: &CliUrlCrawlResult,
    format: OutputFormat,
) -> Result<String, CliError> {
    if matches!(format, OutputFormat::Json) {
        return Ok(serde_json::to_string_pretty(result)?);
    }

    Ok(format!(
        "URL crawl completed\nSeed URL: {}\nPages: {}\nCandidates: {}",
        result.seed_url, result.page_count, result.candidate_count
    ))
}

pub fn render_active_verify(
    report: &CliActiveVerifyReport,
    format: ReportFormat,
) -> Result<String, CliError> {
    let report = redacted_active_verify_report(report);
    if matches!(format, ReportFormat::Json) {
        return render_json_report_with_evidence_metadata(&report);
    }
    if matches!(format, ReportFormat::Sarif) {
        return render_sarif_report(
            "aegis-scan safe active verification",
            &report.target_url,
            report.failed_policy,
            report.baseline_diff.as_ref(),
            &report.findings,
        );
    }

    let highest = report
        .highest_severity
        .map(|severity| format!("{:?}", severity).to_ascii_lowercase())
        .unwrap_or_else(|| "none".to_string());
    let baseline = report
        .baseline_diff
        .as_ref()
        .map(|diff| {
            format!(
                "\nBaseline: new {}, recurring {}, resolved {}",
                diff.new_count, diff.recurring_count, diff.resolved_count
            )
        })
        .unwrap_or_default();
    Ok(format!(
        "Active verification completed\nTarget: {}\nFindings: {}\nManual confirmation required: {}\nHighest severity: {}\nPolicy failed: {}",
        report.target_url,
        report.finding_count,
        count_manual_confirmation_findings(&report.findings),
        highest,
        report.failed_policy
    ) + &baseline)
}

pub fn exit_code(report: &CliScanReport) -> i32 {
    if report.failed_policy {
        2
    } else {
        0
    }
}

fn highest_severity(findings: &[PassiveFinding]) -> Option<FindingSeverity> {
    findings
        .iter()
        .map(|finding| finding.severity)
        .min_by_key(|severity| severity_rank(*severity))
}

fn baseline_diff(
    baseline_file: &PathBuf,
    fail_on_new: FailOn,
    current_findings: &[PassiveFinding],
) -> Result<CliBaselineDiff, CliError> {
    let metadata = fs::metadata(baseline_file)?;
    if metadata.len() > MAX_BASELINE_REPORT_BYTES {
        return Err(CliError::BaselineTooLarge);
    }
    let document = fs::read_to_string(baseline_file)?;
    let baseline = serde_json::from_str::<BaselineFindingsReport>(&document)
        .map_err(CliError::ParseBaseline)?;
    let baseline_keys = finding_keys(&baseline.findings);
    let current_keys = finding_keys(current_findings);

    let new_findings = current_findings
        .iter()
        .filter(|finding| !baseline_keys.contains(&finding_key(finding)))
        .cloned()
        .collect::<Vec<_>>();
    let recurring_findings = current_findings
        .iter()
        .filter(|finding| baseline_keys.contains(&finding_key(finding)))
        .cloned()
        .collect::<Vec<_>>();
    let resolved_findings = baseline
        .findings
        .iter()
        .filter(|finding| !current_keys.contains(&finding_key(finding)))
        .cloned()
        .collect::<Vec<_>>();

    Ok(CliBaselineDiff {
        baseline_file: baseline_file.display().to_string(),
        fail_on_new: format!("{:?}", fail_on_new).to_ascii_lowercase(),
        new_count: new_findings.len(),
        recurring_count: recurring_findings.len(),
        resolved_count: resolved_findings.len(),
        new_findings,
        recurring_findings,
        resolved_findings,
    })
}

fn render_sarif_report(
    run_name: &str,
    target_url: &str,
    failed_policy: bool,
    baseline_diff: Option<&CliBaselineDiff>,
    findings: &[PassiveFinding],
) -> Result<String, CliError> {
    let rule_ids = findings
        .iter()
        .map(|finding| finding.rule_id.clone())
        .collect::<BTreeSet<_>>();
    let rules = rule_ids
        .iter()
        .map(|rule_id| {
            let finding = findings
                .iter()
                .find(|finding| finding.rule_id == *rule_id)
                .expect("rule id came from findings");
            let metadata = evidence_metadata_from_text(&finding.evidence);
            serde_json::json!({
                "id": rule_id,
                "name": &finding.title,
                "shortDescription": {
                    "text": &finding.title
                },
                "fullDescription": {
                    "text": &finding.recommendation
                },
                "properties": {
                    "severity": severity_label(finding.severity),
                    "source": &metadata.source,
                    "requires_manual_confirmation": metadata.requires_manual_confirmation,
                    "finding_classification": metadata.classification()
                }
            })
        })
        .collect::<Vec<_>>();
    let results = findings
        .iter()
        .map(|finding| {
            let metadata = evidence_metadata_from_text(&finding.evidence);
            serde_json::json!({
                "ruleId": &finding.rule_id,
                "level": sarif_level(finding.severity),
                "message": {
                    "text": sarif_message_text(&finding.title, &metadata)
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": target_url
                            }
                        }
                    }
                ],
                "properties": {
                    "severity": severity_label(finding.severity),
                    "evidence": &finding.evidence,
                    "recommendation": &finding.recommendation,
                    "source": &metadata.source,
                    "requires_manual_confirmation": metadata.requires_manual_confirmation,
                    "finding_classification": metadata.classification(),
                    "baseline_status": baseline_status(finding, baseline_diff)
                }
            })
        })
        .collect::<Vec<_>>();
    let baseline_properties = baseline_diff
        .map(|diff| {
            serde_json::json!({
                "baseline_file": &diff.baseline_file,
                "fail_on_new": &diff.fail_on_new,
                "new_count": diff.new_count,
                "recurring_count": diff.recurring_count,
                "resolved_count": diff.resolved_count
            })
        })
        .unwrap_or_else(|| serde_json::json!(null));
    let sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Aegis WebShield AI",
                        "rules": rules
                    }
                },
                "automationDetails": {
                    "id": run_name
                },
                "invocations": [
                    {
                        "executionSuccessful": true,
                        "properties": {
                            "policy_failed": failed_policy,
                            "baseline_diff": baseline_properties
                        }
                    }
                ],
                "results": results
            }
        ]
    });
    Ok(serde_json::to_string_pretty(&sarif)?)
}

fn render_scan_sarif_report(report: &CliScanReport) -> Result<String, CliError> {
    let rule_ids = report
        .findings
        .iter()
        .map(|finding| finding.rule_id.clone())
        .collect::<BTreeSet<_>>();
    let rules = rule_ids
        .iter()
        .map(|rule_id| {
            let finding = report
                .findings
                .iter()
                .find(|finding| finding.rule_id == *rule_id)
                .expect("rule id came from findings");
            let metadata = evidence_metadata_from_text(&finding.evidence);
            serde_json::json!({
                "id": rule_id,
                "name": &finding.title,
                "shortDescription": {
                    "text": &finding.title
                },
                "fullDescription": {
                    "text": &finding.recommendation
                },
                "properties": {
                    "severity": severity_label(finding.severity),
                    "source": &metadata.source,
                    "requires_manual_confirmation": metadata.requires_manual_confirmation,
                    "finding_classification": metadata.classification()
                }
            })
        })
        .collect::<Vec<_>>();
    let results = report
        .endpoint_results
        .iter()
        .flat_map(|endpoint| {
            endpoint.findings.iter().map(|finding| {
                let metadata = evidence_metadata_from_text(&finding.evidence);
                serde_json::json!({
                    "ruleId": &finding.rule_id,
                    "level": sarif_level(finding.severity),
                    "message": {
                        "text": sarif_message_text(&finding.title, &metadata)
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": &endpoint.url
                                }
                            }
                        }
                    ],
                    "properties": {
                        "method": &endpoint.method,
                        "http_status": endpoint.status_code,
                        "severity": severity_label(finding.severity),
                        "evidence": &finding.evidence,
                        "recommendation": &finding.recommendation,
                        "source": &metadata.source,
                        "requires_manual_confirmation": metadata.requires_manual_confirmation,
                        "finding_classification": metadata.classification(),
                        "baseline_status": baseline_status(finding, report.baseline_diff.as_ref())
                    }
                })
            })
        })
        .collect::<Vec<_>>();
    let baseline_properties = report
        .baseline_diff
        .as_ref()
        .map(|diff| {
            serde_json::json!({
                "baseline_file": &diff.baseline_file,
                "fail_on_new": &diff.fail_on_new,
                "new_count": diff.new_count,
                "recurring_count": diff.recurring_count,
                "resolved_count": diff.resolved_count
            })
        })
        .unwrap_or_else(|| serde_json::json!(null));
    let sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Aegis WebShield AI",
                        "rules": rules
                    }
                },
                "automationDetails": {
                    "id": format!("aegis-scan {} passive scan", report.scan_source)
                },
                "invocations": [
                    {
                        "executionSuccessful": true,
                        "properties": {
                            "scan_source": &report.scan_source,
                            "target_url": &report.target_url,
                            "endpoint_count": report.endpoint_count,
                            "skipped_endpoint_count": report.skipped_endpoint_count,
                            "finding_count": report.finding_count,
                            "policy_failed": report.failed_policy,
                            "baseline_diff": baseline_properties
                        }
                    }
                ],
                "results": results
            }
        ]
    });
    Ok(serde_json::to_string_pretty(&sarif)?)
}

fn render_saved_sarif_report(report: &CliSavedScanReport) -> Result<String, CliError> {
    let rule_ids = report
        .findings
        .iter()
        .map(|finding| {
            finding
                .dedupe_key
                .clone()
                .unwrap_or_else(|| finding.title.clone())
        })
        .collect::<BTreeSet<_>>();
    let rules = rule_ids
        .iter()
        .map(|rule_id| {
            let finding = report
                .findings
                .iter()
                .find(|finding| {
                    finding
                        .dedupe_key
                        .as_ref()
                        .map(|dedupe_key| dedupe_key == rule_id)
                        .unwrap_or_else(|| finding.title == *rule_id)
                })
                .expect("rule id came from findings");
            let metadata = evidence_metadata_from_json_text(&finding.evidence_json);
            serde_json::json!({
                "id": rule_id,
                "name": &finding.title,
                "shortDescription": {
                    "text": &finding.title
                },
                "fullDescription": {
                    "text": &finding.remediation
                },
                "properties": {
                    "severity": &finding.severity,
                    "confidence": &finding.confidence,
                    "cwe": &finding.cwe,
                    "owasp_category": &finding.owasp_category,
                    "source": &metadata.source,
                    "requires_manual_confirmation": metadata.requires_manual_confirmation,
                    "finding_classification": metadata.classification()
                }
            })
        })
        .collect::<Vec<_>>();
    let results = report
        .findings
        .iter()
        .map(|finding| {
            let rule_id = finding.dedupe_key.as_ref().unwrap_or(&finding.title);
            let metadata = evidence_metadata_from_json_text(&finding.evidence_json);
            serde_json::json!({
                "ruleId": rule_id,
                "level": saved_sarif_level(&finding.severity),
                "message": {
                    "text": sarif_message_text(&finding.title, &metadata)
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": &finding.endpoint
                            }
                        }
                    }
                ],
                "properties": {
                    "severity": &finding.severity,
                    "confidence": &finding.confidence,
                    "status": &finding.status,
                    "parameter_name": &finding.parameter_name,
                    "evidence": parsed_json_or_string(&finding.evidence_json),
                    "remediation": &finding.remediation,
                    "source": &metadata.source,
                    "requires_manual_confirmation": metadata.requires_manual_confirmation,
                    "finding_classification": metadata.classification(),
                    "cwe": &finding.cwe,
                    "owasp_category": &finding.owasp_category
                }
            })
        })
        .collect::<Vec<_>>();
    let sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Aegis WebShield AI",
                        "rules": rules
                    }
                },
                "automationDetails": {
                    "id": format!("aegis-scan saved report {}", report.scan.id)
                },
                "invocations": [
                    {
                        "executionSuccessful": true,
                        "properties": {
                            "scan_id": &report.scan.id,
                            "project_id": &report.scan.project_id,
                            "target_id": &report.scan.target_id,
                            "profile": &report.scan.profile,
                            "phase": &report.scan.phase,
                            "finding_count": report.finding_count
                        }
                    }
                ],
                "results": results
            }
        ]
    });
    Ok(serde_json::to_string_pretty(&sarif)?)
}

fn render_local_sarif_report(report: &CliLocalScanReport) -> Result<String, CliError> {
    let rule_ids = report
        .findings
        .iter()
        .map(|finding| finding.finding.rule_id.clone())
        .collect::<BTreeSet<_>>();
    let rules = rule_ids
        .iter()
        .map(|rule_id| {
            let finding = report
                .findings
                .iter()
                .find(|finding| finding.finding.rule_id == *rule_id)
                .expect("rule id came from findings");
            let metadata = evidence_metadata_from_text(&finding.finding.evidence);
            serde_json::json!({
                "id": rule_id,
                "name": &finding.finding.title,
                "shortDescription": {
                    "text": &finding.finding.title
                },
                "fullDescription": {
                    "text": &finding.finding.recommendation
                },
                "properties": {
                    "severity": severity_label(finding.finding.severity),
                    "source": &metadata.source,
                    "requires_manual_confirmation": metadata.requires_manual_confirmation,
                    "finding_classification": metadata.classification()
                }
            })
        })
        .collect::<Vec<_>>();
    let results = report
        .findings
        .iter()
        .map(|finding| {
            let metadata = evidence_metadata_from_text(&finding.finding.evidence);
            serde_json::json!({
                "ruleId": &finding.finding.rule_id,
                "level": sarif_level(finding.finding.severity),
                "message": {
                    "text": sarif_message_text(&finding.finding.title, &metadata)
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": &finding.endpoint
                            }
                        }
                    }
                ],
                "properties": {
                    "target_id": &finding.target_id,
                    "target_name": &finding.target_name,
                    "method": &finding.method,
                    "http_status": finding.status_code,
                    "severity": severity_label(finding.finding.severity),
                    "evidence": &finding.finding.evidence,
                    "recommendation": &finding.finding.recommendation,
                    "source": &metadata.source,
                    "requires_manual_confirmation": metadata.requires_manual_confirmation,
                    "finding_classification": metadata.classification()
                }
            })
        })
        .collect::<Vec<_>>();
    let sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Aegis WebShield AI",
                        "rules": rules
                    }
                },
                "automationDetails": {
                    "id": "aegis-scan local workspace scan"
                },
                "invocations": [
                    {
                        "executionSuccessful": true,
                        "properties": {
                            "project_id": &report.project_id,
                            "target_id": &report.target_id,
                            "profile": &report.profile,
                            "target_count": report.target_count,
                            "endpoint_count": report.endpoint_count,
                            "finding_count": report.finding_count,
                            "policy_failed": report.failed_policy
                        }
                    }
                ],
                "results": results
            }
        ]
    });
    Ok(serde_json::to_string_pretty(&sarif)?)
}

fn local_database_path(app_data_dir: &std::path::Path, database: Option<&PathBuf>) -> PathBuf {
    database
        .cloned()
        .unwrap_or_else(|| app_data_dir.join("aegis-webshield-ai.sqlite3"))
}

fn discover_rule_files(path: &PathBuf) -> Result<Vec<PathBuf>, CliError> {
    let metadata = fs::metadata(path)?;
    if metadata.is_file() {
        if is_json_file(path) {
            return Ok(vec![path.clone()]);
        }
        return Err(CliError::RulesPathInvalid);
    }
    if !metadata.is_dir() {
        return Err(CliError::RulesPathInvalid);
    }

    let mut files = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|path| path.is_file() && is_json_file(path))
        .collect::<Vec<_>>();
    files.sort();
    if files.is_empty() {
        return Err(CliError::RulesPathInvalid);
    }
    Ok(files)
}

fn is_json_file(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
}

fn validate_rule_pack_rule(source_file: &str, rule: &RulePackRule) -> Vec<CliRuleIssue> {
    let mut issues = Vec::new();
    let rule_id = optional_trimmed(&rule.id).unwrap_or_default();
    let rule_id_option = if rule_id.is_empty() {
        None
    } else {
        Some(rule_id.clone())
    };

    if !is_valid_rule_id(&rule_id) {
        issues.push(rule_issue(
            source_file,
            rule_id_option.clone(),
            "rule id is required and must use lowercase namespace segments such as passive.missing_csp",
        ));
    }
    if optional_trimmed(&rule.title).is_none() {
        issues.push(rule_issue(
            source_file,
            rule_id_option.clone(),
            "rule title is required",
        ));
    }
    if !rule
        .severity
        .as_ref()
        .map(|severity| is_valid_rule_severity(severity))
        .unwrap_or(false)
    {
        issues.push(rule_issue(
            source_file,
            rule_id_option.clone(),
            "severity must be one of critical, high, medium, low, info",
        ));
    }
    if !rule
        .confidence
        .as_ref()
        .map(|confidence| is_valid_rule_confidence(confidence))
        .unwrap_or(false)
    {
        issues.push(rule_issue(
            source_file,
            rule_id_option.clone(),
            "confidence must be one of high, medium, low",
        ));
    }
    if rule
        .evidence
        .as_ref()
        .map(|value| value.trim().is_empty())
        .unwrap_or(true)
    {
        issues.push(rule_issue(
            source_file,
            rule_id_option.clone(),
            "evidence description is required",
        ));
    }
    if optional_trimmed(&rule.recommendation).is_none() {
        issues.push(rule_issue(
            source_file,
            rule_id_option.clone(),
            "recommendation is required",
        ));
    }
    if let Some(cwe) = &rule.cwe {
        if !is_valid_cwe(cwe) {
            issues.push(rule_issue(
                source_file,
                rule_id_option.clone(),
                "cwe must use format CWE-<number>",
            ));
        }
    }
    if let Some(owasp_category) = &rule.owasp_category {
        if !is_valid_owasp_category(owasp_category) {
            issues.push(rule_issue(
                source_file,
                rule_id_option.clone(),
                "owasp_category must use format A## Category",
            ));
        }
    }
    let triage = triage_rule(&rule_id);
    if triage.cwe.is_none() && rule.cwe.is_none() {
        issues.push(rule_issue(
            source_file,
            rule_id_option,
            "unknown rule id must declare explicit cwe metadata",
        ));
    }

    issues
}

fn validate_rule_pack_update_feed(feed: &RulePackUpdateFeedDocument) -> Vec<CliRulesFeedIssue> {
    let mut issues = Vec::new();

    match optional_trimmed(&feed.latest_version) {
        Some(version) if is_valid_rule_feed_text(&version, 80) => {}
        _ => issues.push(rule_feed_issue(
            "latest_version",
            "latest_version is required and must be 1-80 characters",
        )),
    }
    match optional_trimmed(&feed.channel) {
        Some(channel) if is_valid_rule_pack_channel(&channel) => {}
        _ => issues.push(rule_feed_issue(
            "channel",
            "channel must be one of built-in, community, pro, team, enterprise, local",
        )),
    }
    match optional_trimmed(&feed.manifest_sha256) {
        Some(sha256) if is_valid_sha256_hex(&sha256) => {}
        _ => issues.push(rule_feed_issue(
            "manifest_sha256",
            "manifest_sha256 must be 64 hexadecimal characters",
        )),
    }
    if let Some(manifest_url) = optional_trimmed(&feed.manifest_url) {
        if !is_valid_https_url(&manifest_url) {
            issues.push(rule_feed_issue(
                "manifest_url",
                "manifest_url must be an https URL when present",
            ));
        }
    }
    if let Some(minimum_app_version) = optional_trimmed(&feed.minimum_app_version) {
        if !is_valid_rule_feed_text(&minimum_app_version, 80) {
            issues.push(rule_feed_issue(
                "minimum_app_version",
                "minimum_app_version must be 1-80 characters when present",
            ));
        }
    }

    issues
}

#[derive(Debug)]
struct RuleBundleZipEntry {
    name: String,
    compression_method: u16,
    compressed_size: u64,
    uncompressed_size: u64,
    local_header_offset: usize,
}

fn parse_rule_bundle_zip(bytes: &[u8]) -> Result<Vec<RuleBundleZipEntry>, CliError> {
    let eocd_offset = find_zip_eocd(bytes).ok_or_else(|| {
        CliError::RuleBundleArchive("missing ZIP end of central directory".into())
    })?;
    let entry_count = read_u16_le(bytes, eocd_offset + 10)? as usize;
    let central_directory_size = read_u32_le(bytes, eocd_offset + 12)? as usize;
    let central_directory_offset = read_u32_le(bytes, eocd_offset + 16)? as usize;
    if central_directory_offset
        .checked_add(central_directory_size)
        .map(|end| end > bytes.len())
        .unwrap_or(true)
    {
        return Err(CliError::RuleBundleArchive(
            "ZIP central directory is out of bounds".into(),
        ));
    }

    let mut entries = Vec::with_capacity(entry_count);
    let mut offset = central_directory_offset;
    for _ in 0..entry_count {
        if read_u32_le(bytes, offset)? != 0x0201_4b50 {
            return Err(CliError::RuleBundleArchive(
                "invalid ZIP central directory header".into(),
            ));
        }
        let compression_method = read_u16_le(bytes, offset + 10)?;
        let compressed_size = read_u32_le(bytes, offset + 20)? as u64;
        let uncompressed_size = read_u32_le(bytes, offset + 24)? as u64;
        let name_len = read_u16_le(bytes, offset + 28)? as usize;
        let extra_len = read_u16_le(bytes, offset + 30)? as usize;
        let comment_len = read_u16_le(bytes, offset + 32)? as usize;
        let local_header_offset = read_u32_le(bytes, offset + 42)? as usize;
        let name_start = offset + 46;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or_else(|| CliError::RuleBundleArchive("ZIP entry name overflow".into()))?;
        if name_end > bytes.len() {
            return Err(CliError::RuleBundleArchive(
                "ZIP entry name is out of bounds".into(),
            ));
        }
        let name = std::str::from_utf8(&bytes[name_start..name_end])
            .map_err(|error| {
                CliError::RuleBundleArchive(format!("ZIP entry name is not UTF-8: {error}"))
            })?
            .to_string();
        entries.push(RuleBundleZipEntry {
            name,
            compression_method,
            compressed_size,
            uncompressed_size,
            local_header_offset,
        });
        offset = name_end
            .checked_add(extra_len)
            .and_then(|value| value.checked_add(comment_len))
            .ok_or_else(|| CliError::RuleBundleArchive("ZIP central directory overflow".into()))?;
    }
    Ok(entries)
}

fn read_rule_bundle_entry(bytes: &[u8], entry: &RuleBundleZipEntry) -> Result<Vec<u8>, CliError> {
    if read_u32_le(bytes, entry.local_header_offset)? != 0x0403_4b50 {
        return Err(CliError::RuleBundleArchive(format!(
            "invalid ZIP local header for {}",
            entry.name
        )));
    }
    let name_len = read_u16_le(bytes, entry.local_header_offset + 26)? as usize;
    let extra_len = read_u16_le(bytes, entry.local_header_offset + 28)? as usize;
    let data_start = entry
        .local_header_offset
        .checked_add(30)
        .and_then(|value| value.checked_add(name_len))
        .and_then(|value| value.checked_add(extra_len))
        .ok_or_else(|| CliError::RuleBundleArchive("ZIP local entry overflow".into()))?;
    let data_end = data_start
        .checked_add(entry.compressed_size as usize)
        .ok_or_else(|| CliError::RuleBundleArchive("ZIP compressed entry overflow".into()))?;
    if data_end > bytes.len() {
        return Err(CliError::RuleBundleArchive(format!(
            "ZIP entry data is out of bounds: {}",
            entry.name
        )));
    }
    let compressed = &bytes[data_start..data_end];
    let mut output = Vec::new();
    match entry.compression_method {
        0 => output.extend_from_slice(compressed),
        8 => {
            let mut decoder = DeflateDecoder::new(Cursor::new(compressed));
            decoder.read_to_end(&mut output).map_err(|error| {
                CliError::RuleBundleArchive(format!(
                    "failed to inflate ZIP entry {}: {error}",
                    entry.name
                ))
            })?;
        }
        method => {
            return Err(CliError::RuleBundleArchive(format!(
                "unsupported ZIP compression method {method} for {}",
                entry.name
            )));
        }
    }
    if output.len() as u64 != entry.uncompressed_size {
        return Err(CliError::RuleBundleArchive(format!(
            "ZIP entry size mismatch: {}",
            entry.name
        )));
    }
    Ok(output)
}

fn find_zip_eocd(bytes: &[u8]) -> Option<usize> {
    let min_eocd_len = 22usize;
    if bytes.len() < min_eocd_len {
        return None;
    }
    let search_start = bytes.len().saturating_sub(65_557);
    (search_start..=bytes.len() - min_eocd_len)
        .rev()
        .find(|offset| bytes[*offset..].starts_with(&[0x50, 0x4b, 0x05, 0x06]))
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16, CliError> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| CliError::RuleBundleArchive("ZIP offset overflow".into()))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| CliError::RuleBundleArchive("ZIP field is out of bounds".into()))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, CliError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| CliError::RuleBundleArchive("ZIP offset overflow".into()))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| CliError::RuleBundleArchive("ZIP field is out of bounds".into()))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn verify_rule_feed_signature(
    feed: &RulePackUpdateFeedDocument,
    public_key_hex: &str,
) -> Result<(), String> {
    let public_key_bytes = decode_fixed_hex(public_key_hex, 32)
        .map_err(|_| "public_key_hex must be 64 hexadecimal characters".to_string())?;
    let signature_hex = optional_trimmed(&feed.signature)
        .ok_or_else(|| "signature is required when --public-key-hex is provided".to_string())?;
    let signature_bytes = decode_fixed_hex(&signature_hex, 64)
        .map_err(|_| "signature must be 128 hexadecimal characters".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(
        public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "public_key_hex must decode to 32 bytes".to_string())?,
    )
    .map_err(|_| "public_key_hex is not a valid Ed25519 public key".to_string())?;
    let signature = Signature::from_bytes(
        signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "signature must decode to 64 bytes".to_string())?,
    );
    verifying_key
        .verify(rule_feed_signature_payload(feed).as_bytes(), &signature)
        .map_err(|_| "signature verification failed".to_string())
}

fn verify_detached_ed25519_signature(
    payload: &[u8],
    public_key_hex: &str,
    signature_hex: &str,
) -> Result<(), String> {
    let public_key_bytes = decode_fixed_hex(public_key_hex, 32)
        .map_err(|_| "public_key_hex must be 64 hexadecimal characters".to_string())?;
    let signature_bytes = decode_fixed_hex(signature_hex, 64)
        .map_err(|_| "signature must be 128 hexadecimal characters".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(
        public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "public_key_hex must decode to 32 bytes".to_string())?,
    )
    .map_err(|_| "public_key_hex is not a valid Ed25519 public key".to_string())?;
    let signature = Signature::from_bytes(
        signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "signature must decode to 64 bytes".to_string())?,
    );
    verifying_key
        .verify(payload, &signature)
        .map_err(|_| "signature verification failed".to_string())
}

fn rule_feed_signing_key(private_key_hex: &str) -> Result<SigningKey, CliError> {
    let private_key_bytes = decode_fixed_hex(private_key_hex, 32).map_err(|_| {
        CliError::RuleFeedSigningKey(
            "private_key_hex must be a 32-byte Ed25519 signing key seed encoded as 64 hex characters"
                .to_string(),
        )
    })?;
    let key_bytes: [u8; 32] = private_key_bytes.as_slice().try_into().map_err(|_| {
        CliError::RuleFeedSigningKey("private_key_hex must decode to 32 bytes".to_string())
    })?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

fn rule_feed_signature_payload(feed: &RulePackUpdateFeedDocument) -> String {
    format!(
        "latest_version={}\nchannel={}\nmanifest_sha256={}\nmanifest_url={}\npublished_at={}\nminimum_app_version={}\n",
        optional_trimmed(&feed.latest_version).unwrap_or_default(),
        optional_trimmed(&feed.channel).unwrap_or_default(),
        optional_trimmed(&feed.manifest_sha256).unwrap_or_default(),
        optional_trimmed(&feed.manifest_url).unwrap_or_default(),
        optional_trimmed(&feed.published_at).unwrap_or_default(),
        optional_trimmed(&feed.minimum_app_version).unwrap_or_default()
    )
}

fn decode_fixed_hex(value: &str, expected_bytes: usize) -> Result<Vec<u8>, ()> {
    let value = value.trim();
    if value.len() != expected_bytes * 2
        || !value.chars().all(|character| character.is_ascii_hexdigit())
    {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(expected_bytes);
    for index in (0..value.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&value[index..index + 2], 16).map_err(|_| ())?);
    }
    Ok(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex_encode(&digest[..])
}

fn validate_rule_pack_manifest_document(
    manifest: &RulePackManifestDocument,
) -> Vec<CliRulesFeedIssue> {
    let mut issues = Vec::new();
    match optional_trimmed(&manifest.version) {
        Some(version) if is_valid_rule_feed_text(&version, 80) => {}
        _ => issues.push(rule_feed_issue(
            "version",
            "version is required and must be 1-80 characters",
        )),
    }
    match optional_trimmed(&manifest.channel) {
        Some(channel) if is_valid_rule_pack_channel(&channel) => {}
        _ => issues.push(rule_feed_issue(
            "channel",
            "channel must be one of built-in, community, pro, team, enterprise, local",
        )),
    }
    if let Some(published_at) = optional_trimmed(&manifest.published_at) {
        if !is_valid_rule_feed_text(&published_at, 120) {
            issues.push(rule_feed_issue(
                "published_at",
                "published_at must be 1-120 characters when present",
            ));
        }
    }
    if manifest.rules.is_empty() {
        issues.push(rule_feed_issue(
            "rules",
            "manifest must include at least one rule",
        ));
    }
    if manifest.rules.len() > 5000 {
        issues.push(rule_feed_issue(
            "rules",
            "manifest must include no more than 5000 rules",
        ));
    }
    let mut seen_rule_ids = BTreeSet::new();
    for rule in &manifest.rules {
        let rule_id = optional_trimmed(&rule.id).unwrap_or_default();
        if rule_id.len() < 3
            || rule_id.len() > 160
            || rule_id.chars().any(char::is_whitespace)
            || rule_id.chars().any(char::is_control)
        {
            issues.push(rule_feed_issue(
                "rules.id",
                "rule id is required, must be 3-160 characters, and must not contain whitespace",
            ));
        } else if !seen_rule_ids.insert(rule_id.clone()) {
            issues.push(rule_feed_issue("rules.id", "rule id must be unique"));
        }
        if let Some(severity) = optional_trimmed(&rule.severity) {
            if !is_valid_rule_severity(&severity) {
                issues.push(rule_feed_issue(
                    "rules.severity",
                    "severity must be one of critical, high, medium, low, info",
                ));
            }
        }
    }
    issues
}

fn is_safe_rule_bundle_entry_name(name: &str) -> bool {
    if name.is_empty()
        || name.starts_with('/')
        || name.starts_with('\\')
        || name.contains('\\')
        || name.contains(':')
        || name.chars().any(char::is_control)
    {
        return false;
    }
    name.split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn rule_feed_channel_block_reason(_channel: &str) -> &'static str {
    "unsupported rule pack channel"
}

fn is_valid_rule_pack_channel(channel: &str) -> bool {
    matches!(
        channel,
        "built-in" | "community" | "pro" | "team" | "enterprise" | "local"
    )
}

fn is_valid_rule_feed_text(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && !value.chars().any(char::is_control)
}

fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn is_valid_https_url(value: &str) -> bool {
    value.starts_with("https://")
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

fn optional_trimmed(value: &Option<String>) -> Option<String> {
    value.as_ref().map(|value| value.trim()).and_then(|value| {
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    })
}

fn json_without_bom(document: &str) -> &str {
    document.trim_start_matches('\u{feff}')
}

fn rule_feed_issue(field: &str, message: &str) -> CliRulesFeedIssue {
    CliRulesFeedIssue {
        field: field.to_string(),
        message: message.to_string(),
    }
}

fn rule_issue(source_file: &str, rule_id: Option<String>, message: &str) -> CliRuleIssue {
    CliRuleIssue {
        source_file: source_file.to_string(),
        rule_id,
        message: message.to_string(),
    }
}

fn is_valid_rule_id(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.contains('.')
        && trimmed.split('.').all(|segment| {
            !segment.is_empty()
                && segment.chars().all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
                })
        })
}

fn is_valid_rule_severity(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "critical" | "high" | "medium" | "low" | "info"
    )
}

fn is_valid_rule_confidence(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "high" | "medium" | "low"
    )
}

fn is_valid_cwe(value: &str) -> bool {
    let Some(number) = value.trim().strip_prefix("CWE-") else {
        return false;
    };
    !number.is_empty() && number.chars().all(|character| character.is_ascii_digit())
}

fn is_valid_owasp_category(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() > 4
        && trimmed.as_bytes().get(0) == Some(&b'A')
        && trimmed.as_bytes().get(3) == Some(&b' ')
        && trimmed[1..3]
            .chars()
            .all(|character| character.is_ascii_digit())
}

fn select_local_scan_targets(
    command: &LocalScanCommand,
    database_path: &PathBuf,
) -> Result<Vec<TargetRecord>, CliError> {
    if command.project_id.is_none() && command.target_id.is_none() {
        return Err(CliError::LocalScanTargetRequired);
    }
    let targets = list_targets(
        &command.app_data_dir,
        database_path,
        command.project_id.clone(),
    )?;
    let targets = if let Some(target_id) = &command.target_id {
        targets
            .into_iter()
            .filter(|target| target.id == *target_id)
            .collect::<Vec<_>>()
    } else {
        targets
    };
    if targets.is_empty() {
        return Err(CliError::LocalScanTargetNotFound);
    }
    Ok(targets)
}

fn local_scan_targets_for_target(
    app_data_dir: &std::path::Path,
    database_path: &PathBuf,
    target: &TargetRecord,
    profile: LocalScanProfile,
) -> Result<Vec<ScanTarget>, CliError> {
    let endpoints = list_target_endpoints(app_data_dir, database_path, Some(target.id.clone()))?;
    let endpoints = endpoints
        .into_iter()
        .filter(|endpoint| is_local_scan_endpoint_allowed(endpoint, profile))
        .collect::<Vec<_>>();
    if endpoints.is_empty() {
        let mut targets = vec![storage_target_to_scan_target(
            target,
            None,
            target.url.clone(),
        )];
        if matches!(profile, LocalScanProfile::Surface) {
            append_unique_scan_targets(
                &mut targets,
                surface_probe_targets(&storage_target_to_scan_target(
                    target,
                    None,
                    target.url.clone(),
                ))?,
            );
        }
        return Ok(targets);
    }
    let mut targets = endpoints
        .into_iter()
        .map(|endpoint| storage_target_to_scan_target(target, Some(endpoint.method), endpoint.url))
        .collect::<Vec<_>>();
    if matches!(profile, LocalScanProfile::Surface) {
        append_unique_scan_targets(
            &mut targets,
            surface_probe_targets(&storage_target_to_scan_target(
                target,
                None,
                target.url.clone(),
            ))?,
        );
    }
    Ok(targets)
}

fn append_unique_scan_targets(targets: &mut Vec<ScanTarget>, candidates: Vec<ScanTarget>) {
    let mut seen = targets
        .iter()
        .map(|target| target.url.clone())
        .collect::<BTreeSet<_>>();
    for candidate in candidates {
        if seen.insert(candidate.url.clone()) {
            targets.push(candidate);
        }
    }
}

fn is_local_scan_endpoint_allowed(
    endpoint: &TargetEndpointRecord,
    profile: LocalScanProfile,
) -> bool {
    match profile {
        LocalScanProfile::Safe | LocalScanProfile::Passive | LocalScanProfile::Surface => {
            matches!(endpoint.method.as_str(), "GET" | "HEAD")
        }
    }
}

fn storage_target_to_scan_target(
    target: &TargetRecord,
    method: Option<String>,
    url: String,
) -> ScanTarget {
    ScanTarget {
        id: target.id.clone(),
        method,
        url,
        approval_note: target.approval_note.clone(),
        allow_private_network: target.allow_private_network,
    }
}

fn highest_local_severity(findings: &[CliLocalScanFinding]) -> Option<FindingSeverity> {
    findings
        .iter()
        .map(|finding| finding.finding.severity)
        .min_by_key(|severity| severity_rank(*severity))
}

fn parsed_json_or_string(value: &str) -> serde_json::Value {
    serde_json::from_str(value).unwrap_or_else(|_| serde_json::Value::String(value.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EvidenceMetadata {
    source: String,
    requires_manual_confirmation: bool,
}

impl EvidenceMetadata {
    fn classification(&self) -> &'static str {
        if self.requires_manual_confirmation {
            "candidate"
        } else {
            "deterministic"
        }
    }
}

fn sarif_message_text(title: &str, metadata: &EvidenceMetadata) -> String {
    if metadata.requires_manual_confirmation {
        format!("{title} (manual confirmation required)")
    } else {
        title.to_string()
    }
}

fn render_json_report_with_evidence_metadata<T: Serialize>(report: &T) -> Result<String, CliError> {
    let mut value = serde_json::to_value(report)?;
    enrich_json_evidence_metadata(&mut value);
    Ok(serde_json::to_string_pretty(&value)?)
}

fn enrich_json_evidence_metadata(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                enrich_json_evidence_metadata(value);
            }
        }
        serde_json::Value::Object(map) => {
            let metadata = map
                .get("evidence")
                .and_then(serde_json::Value::as_str)
                .map(evidence_metadata_from_text)
                .or_else(|| {
                    map.get("evidence_json")
                        .and_then(serde_json::Value::as_str)
                        .map(evidence_metadata_from_json_text)
                });
            if let Some(metadata) = metadata {
                let finding_classification = metadata.classification().to_string();
                map.insert(
                    "source".to_string(),
                    serde_json::Value::String(metadata.source),
                );
                map.insert(
                    "requires_manual_confirmation".to_string(),
                    serde_json::Value::Bool(metadata.requires_manual_confirmation),
                );
                map.insert(
                    "finding_classification".to_string(),
                    serde_json::Value::String(finding_classification),
                );
            }
            for value in map.values_mut() {
                enrich_json_evidence_metadata(value);
            }
        }
        _ => {}
    }
}

fn evidence_metadata_from_text(evidence: &str) -> EvidenceMetadata {
    let (metadata, _) = split_native_evidence(evidence);
    evidence_metadata_from_value(metadata.as_ref())
}

fn evidence_metadata_from_json_text(evidence_json: &str) -> EvidenceMetadata {
    let value = serde_json::from_str::<serde_json::Value>(evidence_json).ok();
    evidence_metadata_from_value(value.as_ref())
}

fn evidence_metadata_from_value(value: Option<&serde_json::Value>) -> EvidenceMetadata {
    let source = value
        .and_then(|value| value.get("source"))
        .and_then(serde_json::Value::as_str)
        .filter(|source| !source.trim().is_empty())
        .unwrap_or("unknown")
        .to_string();
    let requires_manual_confirmation = value
        .and_then(|value| value.get("requires_manual_confirmation"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    EvidenceMetadata {
        source,
        requires_manual_confirmation,
    }
}

fn count_manual_confirmation_findings(findings: &[PassiveFinding]) -> usize {
    findings
        .iter()
        .filter(|finding| {
            evidence_metadata_from_text(&finding.evidence).requires_manual_confirmation
        })
        .count()
}

fn redacted_scan_report(report: &CliScanReport) -> CliScanReport {
    let mut report = report.clone();
    report.target_url = redact_report_text(&report.target_url);
    report.final_url = redact_report_text(&report.final_url);
    report.findings = redacted_passive_findings(&report.findings);
    report.endpoint_results = report
        .endpoint_results
        .into_iter()
        .map(|mut endpoint| {
            endpoint.url = redact_report_text(&endpoint.url);
            endpoint.findings = redacted_passive_findings(&endpoint.findings);
            endpoint
        })
        .collect();
    report.baseline_diff = report.baseline_diff.map(redacted_baseline_diff);
    report
}

fn redacted_active_verify_report(report: &CliActiveVerifyReport) -> CliActiveVerifyReport {
    let mut report = report.clone();
    report.target_url = redact_report_text(&report.target_url);
    report.findings = redacted_passive_findings(&report.findings);
    report.baseline_diff = report.baseline_diff.map(redacted_baseline_diff);
    report
}

fn redacted_local_scan_report(report: &CliLocalScanReport) -> CliLocalScanReport {
    let mut report = report.clone();
    report.findings = report
        .findings
        .into_iter()
        .map(|mut finding| {
            finding.endpoint = redact_report_text(&finding.endpoint);
            finding.finding.evidence = redact_report_text(&finding.finding.evidence);
            finding
        })
        .collect();
    report
}

fn redacted_saved_scan_report(report: &CliSavedScanReport) -> CliSavedScanReport {
    let mut scan = report.scan.clone();
    scan.target_url = redact_report_text(&scan.target_url);
    let findings = report
        .findings
        .iter()
        .cloned()
        .map(|mut finding| {
            finding.endpoint = redact_report_text(&finding.endpoint);
            finding.evidence_json =
                serde_json::to_string(&redacted_json_or_string(&finding.evidence_json))
                    .unwrap_or_else(|_| "\"[REDACTED]\"".to_string());
            finding.dedupe_key = finding.dedupe_key.as_deref().map(redact_report_identifier);
            finding
        })
        .collect();
    CliSavedScanReport {
        scan,
        finding_count: report.finding_count,
        highest_severity: report.highest_severity.clone(),
        findings,
    }
}

fn redacted_json_or_string(value: &str) -> serde_json::Value {
    redact_report_json(parsed_json_or_string(value))
}

fn redact_report_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(value) => serde_json::Value::String(redact_report_text(&value)),
        serde_json::Value::Array(values) => serde_json::Value::Array(
            values
                .into_iter()
                .map(redact_report_json)
                .collect::<Vec<_>>(),
        ),
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    if is_sensitive_report_key(&key) {
                        (key, serde_json::Value::String("[REDACTED]".to_string()))
                    } else {
                        (key, redact_report_json(value))
                    }
                })
                .collect(),
        ),
        value => value,
    }
}

fn redacted_passive_findings(findings: &[PassiveFinding]) -> Vec<PassiveFinding> {
    findings
        .iter()
        .cloned()
        .map(|mut finding| {
            finding.evidence = redact_report_text(&finding.evidence);
            finding
        })
        .collect()
}

fn redacted_baseline_diff(mut diff: CliBaselineDiff) -> CliBaselineDiff {
    diff.new_findings = redacted_passive_findings(&diff.new_findings);
    diff.recurring_findings = redacted_passive_findings(&diff.recurring_findings);
    diff.resolved_findings = redacted_passive_findings(&diff.resolved_findings);
    diff
}

fn redact_report_text(value: &str) -> String {
    let redacted_urls = canonicalize_evidence_urls_for_fingerprint(value);
    redacted_urls
        .lines()
        .map(redact_sensitive_report_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_report_identifier(value: &str) -> String {
    value
        .split('|')
        .map(redact_report_text)
        .collect::<Vec<_>>()
        .join("|")
}

fn redact_sensitive_report_line(line: &str) -> String {
    let mut redacted_tokens = Vec::new();
    let tokens = line.split_whitespace().collect::<Vec<_>>();
    let mut index = 0usize;

    while index < tokens.len() {
        let token = tokens[index];
        if let Some(redacted) = redact_sensitive_report_token(token) {
            redacted_tokens.push(redacted);
            index += 1;
            continue;
        }

        let trimmed = token.trim_matches(|character: char| {
            matches!(character, '"' | '\'' | '{' | '[' | ',' | ')' | ']' | '}')
        });
        let key = trimmed.trim_end_matches(|character| character == ':' || character == '=');
        if trimmed.len() > key.len() && is_sensitive_report_key(key) {
            redacted_tokens.push(format!("{token} [REDACTED]"));
            index += sensitive_report_value_token_count(key, &tokens[index + 1..]);
            continue;
        }

        redacted_tokens.push(token.to_string());
        index += 1;
    }

    redacted_tokens.join(" ")
}

fn redact_sensitive_report_token(token: &str) -> Option<String> {
    let separator_index = token.find('=').or_else(|| token.find(':'))?;
    if token[separator_index + 1..].is_empty() {
        return None;
    }
    let key = token[..separator_index]
        .trim_matches(|character: char| matches!(character, '"' | '\'' | '{' | '[' | ',' | '('));
    if !is_sensitive_report_key(key) {
        return None;
    }
    let prefix = &token[..=separator_index];
    let suffix = token[separator_index + 1..]
        .chars()
        .rev()
        .take_while(|character| matches!(character, '"' | '\'' | ',' | ')' | ']' | '}'))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    Some(format!("{prefix}[REDACTED]{suffix}"))
}

fn sensitive_report_value_token_count(key: &str, remaining_tokens: &[&str]) -> usize {
    if remaining_tokens.is_empty() {
        return 1;
    }
    if key.eq_ignore_ascii_case("authorization")
        && remaining_tokens
            .first()
            .map(|token| token.eq_ignore_ascii_case("bearer"))
            .unwrap_or(false)
    {
        return remaining_tokens.len().min(2) + 1;
    }
    2
}

fn is_sensitive_report_key(key: &str) -> bool {
    let normalized = key
        .trim()
        .trim_matches(|character| character == '"' || character == '\'');
    matches!(
        normalized.to_ascii_lowercase().as_str(),
        "authorization"
            | "cookie"
            | "set-cookie"
            | "api_key"
            | "api-key"
            | "access_token"
            | "access-token"
            | "refresh_token"
            | "refresh-token"
            | "token"
            | "password"
            | "secret"
            | "secret_key"
            | "secret-key"
            | "private_key"
            | "private-key"
    )
}

fn highest_saved_severity(findings: &[FindingRecord]) -> Option<&'static str> {
    findings
        .iter()
        .map(|finding| finding.severity.as_str())
        .min_by_key(|severity| saved_severity_rank(severity))
        .map(normalize_saved_severity)
}

fn saved_sarif_level(severity: &str) -> &'static str {
    match normalize_saved_severity(severity) {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

fn saved_severity_rank(severity: &str) -> u8 {
    match normalize_saved_severity(severity) {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn normalize_saved_severity(severity: &str) -> &'static str {
    match severity {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "info",
    }
}

fn baseline_status(
    finding: &PassiveFinding,
    baseline_diff: Option<&CliBaselineDiff>,
) -> &'static str {
    let Some(diff) = baseline_diff else {
        return "current";
    };
    let key = finding_key(finding);
    if diff
        .new_findings
        .iter()
        .any(|finding| finding_key(finding) == key)
    {
        "new"
    } else if diff
        .recurring_findings
        .iter()
        .any(|finding| finding_key(finding) == key)
    {
        "recurring"
    } else {
        "current"
    }
}

fn sarif_level(severity: FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::High => "error",
        FindingSeverity::Medium => "warning",
        FindingSeverity::Low | FindingSeverity::Info => "note",
    }
}

fn severity_label(severity: FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::High => "high",
        FindingSeverity::Medium => "medium",
        FindingSeverity::Low => "low",
        FindingSeverity::Info => "info",
    }
}

fn finding_keys(findings: &[PassiveFinding]) -> Vec<String> {
    findings.iter().map(finding_key).collect()
}

fn finding_key(finding: &PassiveFinding) -> String {
    format!(
        "{}|{}",
        finding.rule_id,
        canonicalize_evidence_urls_for_fingerprint(&finding.evidence)
    )
}

fn canonicalize_evidence_urls_for_fingerprint(evidence: &str) -> String {
    evidence
        .lines()
        .map(canonicalize_evidence_url_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn canonicalize_evidence_url_line(line: &str) -> String {
    line.split_whitespace()
        .map(canonicalize_evidence_token)
        .collect::<Vec<_>>()
        .join(" ")
}

fn canonicalize_evidence_token(token: &str) -> String {
    let leading_trimmed = token.trim_start_matches(|character: char| {
        matches!(character, '"' | '\'' | '(' | '[' | '{' | '<')
    });
    let leading_len = token.len() - leading_trimmed.len();
    let core = leading_trimmed.trim_end_matches(|character: char| {
        matches!(
            character,
            '"' | '\'' | ')' | ']' | '}' | '>' | ',' | '.' | ';' | ':'
        )
    });
    let trailing_len = leading_trimmed.len() - core.len();

    if !(core.starts_with("http://") || core.starts_with("https://")) {
        return token.to_string();
    }

    let Some(canonical) = canonical_url_fingerprint(core) else {
        return token.to_string();
    };
    format!(
        "{}{}{}",
        &token[..leading_len],
        canonical,
        &leading_trimmed[core.len()..core.len() + trailing_len]
    )
}

fn canonical_url_fingerprint(url: &str) -> Option<String> {
    let mut url = Url::parse(url).ok()?;

    if let Some(host) = url.host_str().map(str::to_ascii_lowercase) {
        let _ = url.set_host(Some(&host));
    }
    if matches!(
        (url.scheme(), url.port()),
        ("http", Some(80)) | ("https", Some(443))
    ) {
        let _ = url.set_port(None);
    }

    let query_names = url
        .query_pairs()
        .filter_map(|(name, _)| {
            let name = name.trim();
            (!name.is_empty()).then(|| name.to_string())
        })
        .collect::<BTreeSet<_>>();
    url.set_fragment(None);
    url.set_query(None);
    if !query_names.is_empty() {
        url.query_pairs_mut()
            .clear()
            .extend_pairs(query_names.iter().map(|name| (name.as_str(), "")));
    }

    Some(url.to_string())
}

fn severity_meets_policy(severity: FindingSeverity, fail_on: FailOn) -> bool {
    match fail_on {
        FailOn::Never => false,
        FailOn::Critical => false,
        FailOn::High => matches!(severity, FindingSeverity::High),
        FailOn::Medium => matches!(severity, FindingSeverity::High | FindingSeverity::Medium),
        FailOn::Low => matches!(
            severity,
            FindingSeverity::High | FindingSeverity::Medium | FindingSeverity::Low
        ),
        FailOn::Info => true,
    }
}

fn severity_rank(severity: FindingSeverity) -> u8 {
    match severity {
        FindingSeverity::High => 1,
        FindingSeverity::Medium => 2,
        FindingSeverity::Low => 3,
        FindingSeverity::Info => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_crawler::{CrawlerFetchRequest, CrawlerFetchResponse};
    use aegis_scanner::{HttpHeader, HttpProbeRequest, HttpProbeResponse};
    use aegis_storage::{
        create_finding, create_project, create_scan, create_target, replace_target_endpoints,
        update_scan_phase, CreateFindingInput, CreateProjectInput, CreateScanInput,
        CreateTargetEndpointInput, CreateTargetInput, ReplaceTargetEndpointsInput,
        UpdateScanPhaseInput,
    };
    use aegis_urlseed::UrlSeed;
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;

    #[derive(Debug)]
    struct StaticClient;

    impl HttpProbeClient for StaticClient {
        fn execute(&self, request: &HttpProbeRequest) -> Result<HttpProbeResponse, ScannerError> {
            Ok(HttpProbeResponse {
                final_url: request.url.clone(),
                status_code: 200,
                headers: vec![
                    HttpHeader {
                        name: "Server".to_string(),
                        value: "ExampleServer/1.0".to_string(),
                    },
                    HttpHeader {
                        name: "Content-Type".to_string(),
                        value: "text/html; charset=utf-8".to_string(),
                    },
                ],
                body_sample: Vec::new(),
            })
        }
    }

    #[derive(Debug)]
    struct StaticCrawlerClient {
        pages: HashMap<String, CrawlerFetchResponse>,
    }

    impl CrawlerFetchClient for StaticCrawlerClient {
        fn fetch(
            &self,
            request: &CrawlerFetchRequest,
        ) -> Result<CrawlerFetchResponse, CrawlerError> {
            self.pages
                .get(&request.url)
                .cloned()
                .ok_or_else(|| CrawlerError::FetchFailed(format!("missing {}", request.url)))
        }
    }

    #[derive(Debug)]
    struct StaticActiveClient {
        responses: HashMap<String, HttpProbeResponse>,
    }

    impl HttpProbeClient for StaticActiveClient {
        fn execute(&self, request: &HttpProbeRequest) -> Result<HttpProbeResponse, ScannerError> {
            if let Some(response) = self.responses.get(&request.url).cloned() {
                return Ok(response);
            }
            let marker = Url::parse(&request.url).ok().and_then(|url| {
                url.query_pairs().find_map(|(_, value)| {
                    value.starts_with("aegisxss_").then(|| value.to_string())
                })
            });
            Ok(HttpProbeResponse {
                final_url: request.url.clone(),
                status_code: 200,
                headers: vec![HttpHeader {
                    name: "Content-Type".to_string(),
                    value: "text/html; charset=utf-8".to_string(),
                }],
                body_sample: marker
                    .map(|marker| format!("<html>{marker}</html>").into_bytes())
                    .unwrap_or_else(|| b"<html>normal</html>".to_vec()),
            })
        }
    }

    fn command(fail_on: FailOn) -> ScanCommand {
        ScanCommand {
            url: Some("https://example.com".to_string()),
            openapi: None,
            base_url: None,
            approval_note: "Owner approval captured in SEC-1".to_string(),
            allow_private_network: false,
            fail_on,
            baseline_file: None,
            fail_on_new: None,
            format: ReportFormat::Json,
        }
    }

    fn crawl_url_command() -> CrawlUrlCommand {
        CrawlUrlCommand {
            url: "https://example.com/".to_string(),
            approval_note: "Owner approval captured in SEC-1".to_string(),
            allow_private_network: false,
            max_pages: 5,
            max_candidates: 10,
            max_depth: 1,
            format: OutputFormat::Json,
        }
    }

    fn verify_active_command() -> VerifyActiveCommand {
        VerifyActiveCommand {
            url: "https://example.com/search?q=hello".to_string(),
            approval_note: "Owner approval captured in SEC-1".to_string(),
            allow_private_network: false,
            fail_on: FailOn::Medium,
            baseline_file: None,
            fail_on_new: None,
            format: ReportFormat::Json,
        }
    }

    fn native_candidate_evidence(summary: &str) -> String {
        format!(
            "__aegis_native_meta__={}\n{}",
            serde_json::json!({
                "source": "native-active-candidate",
                "fingerprint": "candidate-fingerprint",
                "evidence_refs": ["sample-1"],
                "requires_manual_confirmation": true
            }),
            summary
        )
    }

    fn saved_report_fixture() -> (tempfile::TempDir, ReportExportCommand) {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("aegis.sqlite3");
        let project = create_project(
            temp_dir.path(),
            &db_path,
            CreateProjectInput {
                name: "Staging".to_string(),
                description: "".to_string(),
            },
        )
        .expect("project");
        let target = create_target(
            temp_dir.path(),
            &db_path,
            CreateTargetInput {
                project_id: project.id.clone(),
                target_type: "url".to_string(),
                name: "Staging Web".to_string(),
                url: "https://staging.example.com".to_string(),
                approval_note: "Owner approval captured".to_string(),
                allow_private_network: false,
            },
        )
        .expect("target");
        let scan = create_scan(
            temp_dir.path(),
            &db_path,
            CreateScanInput {
                project_id: project.id,
                target_id: target.id,
                profile: "safe".to_string(),
            },
        )
        .expect("scan");
        create_finding(
            temp_dir.path(),
            &db_path,
            CreateFindingInput {
                scan_id: scan.id.clone(),
                title: "Missing CSP".to_string(),
                severity: "medium".to_string(),
                confidence: "high".to_string(),
                endpoint: "https://staging.example.com/login?session=raw-secret#frag".to_string(),
                parameter_name: None,
                evidence_json: serde_json::json!({
                    "rule_id": "passive.missing_csp",
                    "url": "https://staging.example.com/login?token=raw-token&next=/home#frag",
                    "authorization": "Bearer raw-token",
                    "nested": {
                        "password": "raw-password",
                        "safe": "kept"
                    }
                })
                .to_string(),
                remediation: "Add a restrictive CSP header".to_string(),
                cwe: Some("CWE-693".to_string()),
                owasp_category: Some("A05 Security Misconfiguration".to_string()),
                dedupe_key: Some(
                    "passive.missing_csp|https://staging.example.com/login?session=raw-secret#frag"
                        .to_string(),
                ),
            },
        )
        .expect("finding");
        update_scan_phase(
            temp_dir.path(),
            &db_path,
            UpdateScanPhaseInput {
                id: scan.id.clone(),
                phase: "completed".to_string(),
                status_message: "Scan completed".to_string(),
            },
        )
        .expect("scan completed");

        let command = ReportExportCommand {
            app_data_dir: temp_dir.path().to_path_buf(),
            database: Some(db_path),
            scan_id: scan.id,
            format: ReportFormat::Json,
        };
        (temp_dir, command)
    }

    fn local_scan_fixture() -> (tempfile::TempDir, LocalScanCommand) {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("aegis.sqlite3");
        let project = create_project(
            temp_dir.path(),
            &db_path,
            CreateProjectInput {
                name: "Staging".to_string(),
                description: "".to_string(),
            },
        )
        .expect("project");
        let target = create_target(
            temp_dir.path(),
            &db_path,
            CreateTargetInput {
                project_id: project.id,
                target_type: "url".to_string(),
                name: "Staging Web".to_string(),
                url: "https://staging.example.com".to_string(),
                approval_note: "Owner approval captured".to_string(),
                allow_private_network: false,
            },
        )
        .expect("target");
        replace_target_endpoints(
            temp_dir.path(),
            &db_path,
            ReplaceTargetEndpointsInput {
                target_id: target.id.clone(),
                endpoints: vec![
                    CreateTargetEndpointInput {
                        method: "GET".to_string(),
                        path: "/health".to_string(),
                        url: "https://staging.example.com/health".to_string(),
                        operation_id: Some("health".to_string()),
                        parameters_json: "[]".to_string(),
                    },
                    CreateTargetEndpointInput {
                        method: "POST".to_string(),
                        path: "/login".to_string(),
                        url: "https://staging.example.com/login".to_string(),
                        operation_id: Some("login".to_string()),
                        parameters_json: "[]".to_string(),
                    },
                ],
            },
        )
        .expect("endpoints");
        let command = LocalScanCommand {
            app_data_dir: temp_dir.path().to_path_buf(),
            database: Some(db_path),
            project_id: None,
            target_id: Some(target.id),
            profile: LocalScanProfile::Passive,
            fail_on: FailOn::Medium,
            format: ReportFormat::Json,
        };
        (temp_dir, command)
    }

    fn write_test_zip(path: &std::path::Path, entries: &[(&str, &[u8])]) {
        let mut output = Vec::new();
        let mut central_directory = Vec::new();
        for (name, content) in entries {
            let local_header_offset = output.len() as u32;
            let name_bytes = name.as_bytes();
            output.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            output.extend_from_slice(&20u16.to_le_bytes());
            output.extend_from_slice(&0u16.to_le_bytes());
            output.extend_from_slice(&0u16.to_le_bytes());
            output.extend_from_slice(&0u16.to_le_bytes());
            output.extend_from_slice(&0u16.to_le_bytes());
            output.extend_from_slice(&0u32.to_le_bytes());
            output.extend_from_slice(&(content.len() as u32).to_le_bytes());
            output.extend_from_slice(&(content.len() as u32).to_le_bytes());
            output.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            output.extend_from_slice(&0u16.to_le_bytes());
            output.extend_from_slice(name_bytes);
            output.extend_from_slice(content);

            central_directory.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central_directory.extend_from_slice(&20u16.to_le_bytes());
            central_directory.extend_from_slice(&20u16.to_le_bytes());
            central_directory.extend_from_slice(&0u16.to_le_bytes());
            central_directory.extend_from_slice(&0u16.to_le_bytes());
            central_directory.extend_from_slice(&0u16.to_le_bytes());
            central_directory.extend_from_slice(&0u16.to_le_bytes());
            central_directory.extend_from_slice(&0u32.to_le_bytes());
            central_directory.extend_from_slice(&(content.len() as u32).to_le_bytes());
            central_directory.extend_from_slice(&(content.len() as u32).to_le_bytes());
            central_directory.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            central_directory.extend_from_slice(&0u16.to_le_bytes());
            central_directory.extend_from_slice(&0u16.to_le_bytes());
            central_directory.extend_from_slice(&0u16.to_le_bytes());
            central_directory.extend_from_slice(&0u16.to_le_bytes());
            central_directory.extend_from_slice(&0u32.to_le_bytes());
            central_directory.extend_from_slice(&local_header_offset.to_le_bytes());
            central_directory.extend_from_slice(name_bytes);
        }
        let central_directory_offset = output.len() as u32;
        let central_directory_size = central_directory.len() as u32;
        output.extend_from_slice(&central_directory);
        output.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        output.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        output.extend_from_slice(&central_directory_size.to_le_bytes());
        output.extend_from_slice(&central_directory_offset.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        fs::write(path, output).expect("zip file");
    }

    #[test]
    fn scan_report_marks_policy_failure_for_medium_threshold() {
        let report = run_scan_command(&command(FailOn::Medium), &StaticClient).expect("report");

        assert_eq!(report.finding_count, 5);
        assert_eq!(report.highest_severity, Some(FindingSeverity::Medium));
        assert!(report.failed_policy);
        assert_eq!(exit_code(&report), 2);
    }

    #[test]
    fn scan_report_allows_never_fail_policy() {
        let report = run_scan_command(&command(FailOn::Never), &StaticClient).expect("report");

        assert!(!report.failed_policy);
        assert_eq!(exit_code(&report), 0);
    }

    #[test]
    fn renders_json_report() {
        let report = run_scan_command(&command(FailOn::Never), &StaticClient).expect("report");
        let rendered = render_report(&report, ReportFormat::Json).expect("json");

        assert!(rendered.contains("\"target_url\""));
        assert!(rendered.contains("https://example.com"));
        assert!(rendered.contains("\"finding_count\": 5"));
    }

    #[test]
    fn renders_scan_report_with_redacted_urls_and_evidence() {
        let finding = PassiveFinding {
            rule_id: "passive.token_pattern".to_string(),
            title: "Token exposure".to_string(),
            severity: FindingSeverity::Medium,
            evidence:
                "https://example.com/search?token=raw-token&page=1#frag authorization: Bearer raw-token"
                    .to_string(),
            recommendation: "Remove exposed token".to_string(),
        };
        let report = CliScanReport {
            scan_source: "url".to_string(),
            target_url: "https://example.com/search?token=raw-token#frag".to_string(),
            final_url: "https://example.com/search?token=raw-token#frag".to_string(),
            status_code: 200,
            endpoint_count: 1,
            skipped_endpoint_count: 0,
            finding_count: 1,
            highest_severity: Some(FindingSeverity::Medium),
            failed_policy: true,
            fail_on: "medium".to_string(),
            baseline_diff: None,
            findings: vec![finding.clone()],
            endpoint_results: vec![CliScanEndpointResult {
                method: "GET".to_string(),
                url: "https://example.com/search?token=raw-token#frag".to_string(),
                status_code: 200,
                findings: vec![finding],
            }],
        };

        let json = render_report(&report, ReportFormat::Json).expect("json");
        let sarif = render_report(&report, ReportFormat::Sarif).expect("sarif");
        let text = render_report(&report, ReportFormat::Text).expect("text");

        assert!(json.contains("\"target_url\": \"https://example.com/search?token=\""));
        assert!(sarif.contains("\"uri\": \"https://example.com/search?token=\""));
        assert!(text.contains("Target: https://example.com/search?token="));
        assert!(json.contains("authorization: [REDACTED]"));
        assert!(sarif.contains("authorization: [REDACTED]"));
        assert!(!json.contains("raw-token"));
        assert!(!sarif.contains("raw-token"));
        assert!(!text.contains("raw-token"));
        assert!(!json.contains("#frag"));
        assert!(!sarif.contains("#frag"));
        assert!(!text.contains("#frag"));
    }

    #[test]
    fn renders_scan_sarif_report() {
        let report = run_scan_command(&command(FailOn::Never), &StaticClient).expect("report");
        let rendered = render_report(&report, ReportFormat::Sarif).expect("sarif");

        assert!(rendered.contains("\"version\": \"2.1.0\""));
        assert!(rendered.contains("\"name\": \"Aegis WebShield AI\""));
        assert!(rendered.contains("\"ruleId\": \"aegis.config.header.csp\""));
        assert!(rendered.contains("https://example.com"));
    }

    #[test]
    fn scans_openapi_get_and_head_endpoints() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let openapi_path = temp_dir.path().join("openapi.yaml");
        fs::write(
            &openapi_path,
            r#"
openapi: 3.0.3
info:
  title: Store API
  version: 1.0.0
servers:
  - url: https://api.example.com/v1
paths:
  /health:
    get:
      operationId: health
    post:
      operationId: createHealth
  /status:
    head:
      operationId: statusHead
"#,
        )
        .expect("openapi file");
        let command = ScanCommand {
            url: None,
            openapi: Some(openapi_path),
            base_url: None,
            approval_note: "Owner approval captured in SEC-1".to_string(),
            allow_private_network: false,
            fail_on: FailOn::Medium,
            baseline_file: None,
            fail_on_new: None,
            format: ReportFormat::Json,
        };

        let report = run_scan_command(&command, &StaticClient).expect("report");
        let rendered = render_report(&report, ReportFormat::Sarif).expect("sarif");

        assert_eq!(report.scan_source, "openapi");
        assert_eq!(report.endpoint_count, 2);
        assert_eq!(report.skipped_endpoint_count, 1);
        assert_eq!(report.finding_count, 10);
        assert!(report.failed_policy);
        assert!(report
            .endpoint_results
            .iter()
            .any(|endpoint| endpoint.url == "https://api.example.com/v1/health"));
        assert!(rendered.contains("\"scan_source\": \"openapi\""));
        assert!(rendered.contains("\"uri\": \"https://api.example.com/v1/health\""));
        assert!(rendered.contains("\"method\": \"HEAD\""));
    }

    #[test]
    fn exports_saved_scan_report_from_local_storage() {
        let (_temp_dir, command) = saved_report_fixture();

        let report = run_report_export_command(&command).expect("saved report");
        let rendered = render_saved_scan_report(&report, ReportFormat::Json).expect("json");

        assert_eq!(report.finding_count, 1);
        assert_eq!(report.highest_severity, Some("medium".to_string()));
        assert!(rendered.contains("\"target_url\""));
        assert!(rendered.contains("https://staging.example.com"));
        assert!(rendered.contains("\"title\": \"Missing CSP\""));
        assert!(rendered.contains("\"endpoint\": \"https://staging.example.com/login?session=\""));
        assert!(rendered.contains("\\\"authorization\\\":\\\"[REDACTED]\\\""));
        assert!(rendered.contains("\\\"password\\\":\\\"[REDACTED]\\\""));
        assert!(rendered.contains("\\\"safe\\\":\\\"kept\\\""));
        assert!(!rendered.contains("raw-token"));
        assert!(!rendered.contains("raw-password"));
        assert!(!rendered.contains("raw-secret"));
        assert!(!rendered.contains("#frag"));
    }

    #[test]
    fn renders_saved_scan_sarif_report() {
        let (_temp_dir, mut command) = saved_report_fixture();
        command.format = ReportFormat::Sarif;

        let report = run_report_export_command(&command).expect("saved report");
        let rendered = render_saved_scan_report(&report, command.format).expect("sarif");

        assert!(rendered.contains("\"version\": \"2.1.0\""));
        assert!(rendered.contains("\"scan_id\""));
        assert!(rendered.contains(
            "\"ruleId\": \"passive.missing_csp|https://staging.example.com/login?session=\""
        ));
        assert!(rendered.contains("\"uri\": \"https://staging.example.com/login?session=\""));
        assert!(rendered.contains("\"authorization\": \"[REDACTED]\""));
        assert!(!rendered.contains("raw-token"));
        assert!(!rendered.contains("raw-secret"));
        assert!(!rendered.contains("#frag"));
    }

    #[test]
    fn renders_local_scan_report_with_redacted_endpoint_and_evidence() {
        let report = CliLocalScanReport {
            project_id: Some("project-1".to_string()),
            target_id: Some("target-1".to_string()),
            profile: "safe".to_string(),
            target_count: 1,
            endpoint_count: 1,
            finding_count: 1,
            highest_severity: Some(FindingSeverity::Medium),
            failed_policy: true,
            fail_on: "medium".to_string(),
            findings: vec![CliLocalScanFinding {
                target_id: "target-1".to_string(),
                target_name: "Staging".to_string(),
                endpoint: "https://example.com/app?session=raw-secret#frag".to_string(),
                method: "GET".to_string(),
                status_code: Some(200),
                finding: PassiveFinding {
                    rule_id: "passive.token_pattern".to_string(),
                    title: "Token exposure".to_string(),
                    severity: FindingSeverity::Medium,
                    evidence: "cookie: raw-cookie".to_string(),
                    recommendation: "Remove exposed token".to_string(),
                },
            }],
        };

        let json = render_local_scan_report(&report, ReportFormat::Json).expect("json");
        let sarif = render_local_scan_report(&report, ReportFormat::Sarif).expect("sarif");

        assert!(json.contains("\"endpoint\": \"https://example.com/app?session=\""));
        assert!(sarif.contains("\"uri\": \"https://example.com/app?session=\""));
        assert!(json.contains("cookie: [REDACTED]"));
        assert!(sarif.contains("cookie: [REDACTED]"));
        assert!(!json.contains("raw-secret"));
        assert!(!sarif.contains("raw-secret"));
        assert!(!json.contains("raw-cookie"));
        assert!(!sarif.contains("raw-cookie"));
        assert!(!json.contains("#frag"));
        assert!(!sarif.contains("#frag"));
    }

    #[test]
    fn validates_rule_pack_documents() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let rule_path = temp_dir.path().join("passive.json");
        fs::write(
            &rule_path,
            serde_json::json!({
                "rules": [
                    {
                        "id": "passive.missing_csp",
                        "title": "Content Security Policy header is missing",
                        "severity": "medium",
                        "confidence": "high",
                        "cwe": "CWE-693",
                        "owasp_category": "A05 Security Misconfiguration",
                        "evidence": "Response does not include a CSP header",
                        "recommendation": "Add a restrictive Content-Security-Policy header",
                        "enabled": false
                    }
                ]
            })
            .to_string(),
        )
        .expect("rule file");
        let command = RulesTestCommand {
            path: temp_dir.path().to_path_buf(),
            format: OutputFormat::Json,
        };

        let report = run_rules_test_command(&command).expect("rules test");
        let rendered = render_rules_test(&report, OutputFormat::Text).expect("text");

        assert!(report.passed);
        assert_eq!(report.file_count, 1);
        assert_eq!(report.rule_count, 1);
        assert!(!report.rules[0].enabled);
        assert!(rendered.contains("Passed: true"));
    }

    #[test]
    fn reports_rule_pack_issues() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let rule_path = temp_dir.path().join("custom.json");
        fs::write(
            &rule_path,
            serde_json::json!({
                "rules": [
                    {
                        "id": "custom.missing_auth",
                        "title": "Missing auth check",
                        "severity": "urgent",
                        "confidence": "certain",
                        "evidence": "",
                        "recommendation": ""
                    },
                    {
                        "id": "custom.missing_auth",
                        "title": "Duplicate",
                        "severity": "low",
                        "confidence": "medium",
                        "evidence": "Observed unauthenticated access",
                        "recommendation": "Require authentication"
                    }
                ]
            })
            .to_string(),
        )
        .expect("rule file");
        let command = RulesTestCommand {
            path: rule_path,
            format: OutputFormat::Json,
        };

        let report = run_rules_test_command(&command).expect("rules test");
        let rendered = render_rules_test(&report, OutputFormat::Json).expect("json");

        assert!(!report.passed);
        assert_eq!(report.rule_count, 2);
        assert!(report.issue_count >= 5);
        assert!(rendered.contains("rule id must be unique"));
        assert!(rendered.contains("unknown rule id must declare explicit cwe metadata"));
    }

    #[test]
    fn validates_rule_pack_update_feed() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let feed_path = temp_dir.path().join("feed.json");
        fs::write(
            &feed_path,
            serde_json::json!({
                "latest_version": "2026.06.24-local",
                "channel": "local",
                "published_at": "2026-06-24T00:00:00Z",
                "minimum_app_version": "0.1.0",
                "manifest_url": "https://updates.example.com/aegis/rules/manifest.json",
                "manifest_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            })
            .to_string(),
        )
        .expect("feed file");
        let command = RulesFeedCheckCommand {
            file: feed_path,
            current_version: Some("2026.06.12".to_string()),

            public_key_hex: None,
            format: OutputFormat::Json,
        };

        let report = run_rules_feed_check_command(&command).expect("feed check");
        let rendered = render_rules_feed_check(&report, OutputFormat::Text).expect("text");

        assert!(report.passed);
        assert!(report.update_available);
        assert!(report.entitlement_allowed);
        assert!(rendered.contains("Update available: true"));
    }

    #[test]
    fn accepts_legacy_pro_rule_pack_feed_without_activation() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let feed_path = temp_dir.path().join("feed.json");
        fs::write(
            &feed_path,
            serde_json::json!({
                "latest_version": "2026.06.24-pro",
                "channel": "pro",
                "manifest_url": "https://updates.example.com/aegis/rules/pro/manifest.json",
                "manifest_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            })
            .to_string(),
        )
        .expect("feed file");
        let command = RulesFeedCheckCommand {
            file: feed_path,
            current_version: Some("2026.06.12".to_string()),

            public_key_hex: None,
            format: OutputFormat::Json,
        };

        let report = run_rules_feed_check_command(&command).expect("feed check");
        let rendered = render_rules_feed_check(&report, OutputFormat::Json).expect("json");

        assert!(report.passed);
        assert!(report.entitlement_allowed);
        assert_eq!(report.issue_count, 0);
        assert!(rendered.contains("pro"));
    }

    #[test]
    fn verifies_signed_rule_pack_update_feed() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let feed_path = temp_dir.path().join("feed.json");
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let mut feed = RulePackUpdateFeedDocument {
            latest_version: Some("2026.06.24-local".to_string()),
            channel: Some("local".to_string()),
            manifest_sha256: Some(
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
            ),
            manifest_url: Some("https://updates.example.com/aegis/rules/manifest.json".to_string()),
            published_at: Some("2026-06-24T00:00:00Z".to_string()),
            minimum_app_version: Some("0.1.0".to_string()),
            signature: None,
        };
        let signature = signing_key.sign(rule_feed_signature_payload(&feed).as_bytes());
        feed.signature = Some(hex_encode(signature.to_bytes().as_slice()));
        fs::write(&feed_path, serde_json::to_string(&feed).expect("feed json")).expect("feed file");
        let command = RulesFeedCheckCommand {
            file: feed_path,
            current_version: Some("2026.06.12".to_string()),

            public_key_hex: Some(hex_encode(
                signing_key.verifying_key().to_bytes().as_slice(),
            )),
            format: OutputFormat::Json,
        };

        let report = run_rules_feed_check_command(&command).expect("feed check");
        let rendered = render_rules_feed_check(&report, OutputFormat::Text).expect("text");

        assert!(report.passed);
        assert!(report.signature_verified);
        assert!(rendered.contains("Signature verified: true"));
    }

    #[test]
    fn signs_rule_pack_update_feed_for_release_ci() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let feed_path = temp_dir.path().join("feed.json");
        let signed_path = temp_dir.path().join("signed-feed.json");
        let private_key_hex = hex_encode(&[9u8; 32]);
        fs::write(
            &feed_path,
            serde_json::json!({
                "latest_version": "2026.06.24-local",
                "channel": "local",
                "manifest_url": "https://updates.example.com/aegis/rules/manifest.json",
                "manifest_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            })
            .to_string(),
        )
        .expect("feed file");
        let sign_command = RulesFeedSignCommand {
            file: feed_path,
            private_key_hex,
            out: Some(signed_path.clone()),
            format: OutputFormat::Json,
        };

        let sign_report = run_rules_feed_sign_command(&sign_command).expect("feed sign");
        let rendered = render_rules_feed_sign(&sign_report, OutputFormat::Text).expect("text");
        let check_command = RulesFeedCheckCommand {
            file: signed_path,
            current_version: Some("2026.06.12".to_string()),

            public_key_hex: Some(sign_report.public_key_hex.clone()),
            format: OutputFormat::Json,
        };
        let check_report = run_rules_feed_check_command(&check_command).expect("feed check");

        assert!(rendered.contains("Rules feed signed"));
        assert_eq!(sign_report.signature.len(), 128);
        assert!(check_report.passed);
        assert!(check_report.signature_verified);
    }

    #[test]
    fn validates_signed_rule_pack_bundle() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let bundle_path = temp_dir.path().join("rules.zip");
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let manifest = serde_json::json!({
            "version": "2026.06.25-local",
            "channel": "local",
            "published_at": "2026-06-25T00:00:00Z",
            "rules": [
                {
                    "id": "passive.missing_csp",
                    "severity": "medium",
                    "enabled": false
                }
            ]
        })
        .to_string();
        let signature = signing_key.sign(manifest.as_bytes());
        let signature_hex = hex_encode(signature.to_bytes().as_slice());
        write_test_zip(
            &bundle_path,
            &[
                ("manifest.json", manifest.as_bytes()),
                ("manifest.sig", signature_hex.as_bytes()),
                ("rules/passive.json", br#"{"rules":[]}"#),
            ],
        );
        let command = RulesBundleCheckCommand {
            file: bundle_path,
            expected_manifest_sha256: Some(sha256_hex(manifest.as_bytes())),
            public_key_hex: Some(hex_encode(
                signing_key.verifying_key().to_bytes().as_slice(),
            )),

            format: OutputFormat::Json,
        };

        let report = run_rules_bundle_check_command(&command).expect("bundle check");
        let rendered = render_rules_bundle_check(&report, OutputFormat::Text).expect("text");

        assert!(report.passed);
        assert_eq!(report.rule_count, 1);
        assert_eq!(report.enabled_rule_count, 0);
        assert_eq!(report.disabled_rule_count, 1);
        assert!(report.signature_verified);
        assert!(rendered.contains("Rules: 0 enabled / 1 total"));
        assert!(rendered.contains("Passed: true"));
    }

    #[test]
    fn rejects_rule_pack_bundle_path_traversal() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let bundle_path = temp_dir.path().join("rules.zip");
        let manifest = serde_json::json!({
            "version": "2026.06.25-local",
            "channel": "local",
            "rules": [
                {
                    "id": "passive.missing_csp",
                    "severity": "medium"
                }
            ]
        })
        .to_string();
        write_test_zip(
            &bundle_path,
            &[
                ("manifest.json", manifest.as_bytes()),
                ("../escape.json", br#"{}"#),
            ],
        );
        let command = RulesBundleCheckCommand {
            file: bundle_path,
            expected_manifest_sha256: None,
            public_key_hex: None,

            format: OutputFormat::Json,
        };

        let report = run_rules_bundle_check_command(&command).expect("bundle check");
        let rendered = render_rules_bundle_check(&report, OutputFormat::Json).expect("json");

        assert!(!report.passed);
        assert_eq!(report.issue_count, 1);
        assert!(rendered.contains("bundle entry path is not allowed"));
    }

    #[test]
    fn runs_local_scan_from_saved_target_endpoints() {
        let (_temp_dir, command) = local_scan_fixture();

        let report = run_local_scan_command(&command, &StaticClient).expect("local scan");
        let rendered = render_local_scan_report(&report, ReportFormat::Text).expect("text");

        assert_eq!(report.target_count, 1);
        assert_eq!(report.endpoint_count, 1);
        assert_eq!(report.finding_count, 5);
        assert!(report.failed_policy);
        assert!(report
            .findings
            .iter()
            .all(|finding| finding.endpoint == "https://staging.example.com/health"));
        assert!(rendered.contains("Local scan completed"));
    }

    #[test]
    fn surface_local_scan_adds_well_known_probe_targets() {
        let (_temp_dir, mut command) = local_scan_fixture();
        command.profile = LocalScanProfile::Surface;

        let report = run_local_scan_command(&command, &StaticClient).expect("surface scan");

        assert!(report.endpoint_count > 1);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.endpoint == "https://staging.example.com/.env"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.endpoint.starts_with("https://staging.example.com/")));
    }

    #[test]
    fn renders_local_scan_sarif_report() {
        let (_temp_dir, mut command) = local_scan_fixture();
        command.format = ReportFormat::Sarif;

        let report = run_local_scan_command(&command, &StaticClient).expect("local scan");
        let rendered = render_local_scan_report(&report, command.format).expect("sarif");

        assert!(rendered.contains("\"version\": \"2.1.0\""));
        assert!(rendered.contains("\"policy_failed\": true"));
        assert!(rendered.contains("\"uri\": \"https://staging.example.com/health\""));
        assert!(rendered.contains("\"target_name\": \"Staging Web\""));
    }

    #[test]
    fn scan_report_can_fail_only_on_new_baseline_findings() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let baseline_path = temp_dir.path().join("baseline.json");
        fs::write(
            &baseline_path,
            serde_json::json!({
                "findings": [
                    {
                        "rule_id": "passive.resolved_rule",
                        "title": "Resolved old finding",
                        "severity": "medium",
                        "evidence": "old evidence",
                        "recommendation": "Already fixed"
                    }
                ]
            })
            .to_string(),
        )
        .expect("baseline file");
        let mut command = command(FailOn::Never);
        command.baseline_file = Some(baseline_path);
        command.fail_on_new = Some(FailOn::Medium);

        let report = run_scan_command(&command, &StaticClient).expect("report");
        let baseline = report.baseline_diff.as_ref().expect("baseline diff");

        assert!(report.failed_policy);
        assert_eq!(exit_code(&report), 2);
        assert_eq!(baseline.new_count, 5);
        assert_eq!(baseline.recurring_count, 0);
        assert_eq!(baseline.resolved_count, 1);
    }

    #[test]
    fn baseline_fingerprint_canonicalizes_evidence_urls_without_query_values() {
        let baseline = PassiveFinding {
            rule_id: "passive.missing_csp".to_string(),
            title: "Missing CSP".to_string(),
            severity: FindingSeverity::Medium,
            evidence: "https://EXAMPLE.com:443/search?token=old&page=1#frag returned no CSP"
                .to_string(),
            recommendation: "Add CSP".to_string(),
        };
        let current = PassiveFinding {
            rule_id: "passive.missing_csp".to_string(),
            title: "Missing CSP".to_string(),
            severity: FindingSeverity::Medium,
            evidence: "https://example.com/search?page=2&token=new returned no CSP".to_string(),
            recommendation: "Add CSP".to_string(),
        };

        assert_eq!(finding_key(&baseline), finding_key(&current));
        assert!(finding_key(&current).contains("page=&token="));
        assert!(!finding_key(&current).contains("new"));
        assert!(!finding_key(&baseline).contains("old"));
    }

    #[test]
    fn renders_openapi_import_text() {
        let result = OpenApiImportResult {
            title: Some("Store API".to_string()),
            version: Some("1.0.0".to_string()),
            base_url: "https://api.example.com".to_string(),
            endpoints: Vec::new(),
        };

        let rendered = render_openapi_import(&result, OutputFormat::Text).expect("text");

        assert!(rendered.contains("OpenAPI import completed"));
        assert!(rendered.contains("Store API"));
        assert!(rendered.contains("Endpoints: 0"));
    }

    #[test]
    fn renders_url_seed_import_text() {
        let result = UrlSeedImportResult {
            seed_count: 1,
            skipped_count: 2,
            seeds: vec![UrlSeed {
                url: "https://example.com/app".to_string(),
            }],
        };

        let rendered = render_url_seed_import(&result, OutputFormat::Text).expect("text");

        assert!(rendered.contains("URL seed import completed"));
        assert!(rendered.contains("Seeds: 1"));
        assert!(rendered.contains("Skipped lines: 2"));
    }

    #[test]
    fn crawls_html_file_for_candidates() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let html_path = temp_dir.path().join("page.html");
        fs::write(
            &html_path,
            r#"
            <a href="/dashboard">Dashboard</a>
            <form action="/login" method="post"></form>
            <script src="https://external.example/app.js"></script>
            "#,
        )
        .expect("write html");
        let command = CrawlHtmlCommand {
            file: html_path,
            base_url: "https://example.com/app".to_string(),
            format: OutputFormat::Json,
        };

        let result = run_crawl_html_command(&command).expect("crawl");

        assert_eq!(result.candidate_count, 2);
        assert!(result.candidates.iter().any(|candidate| {
            candidate.method == "GET" && candidate.url == "https://example.com/dashboard"
        }));
        assert!(result.candidates.iter().any(|candidate| {
            candidate.method == "POST" && candidate.url == "https://example.com/login"
        }));
    }

    #[test]
    fn renders_html_crawl_text() {
        let result = CliHtmlCrawlResult {
            base_url: "https://example.com".to_string(),
            candidate_count: 2,
            candidates: Vec::new(),
        };

        let rendered = render_html_crawl(&result, OutputFormat::Text).expect("text");

        assert!(rendered.contains("HTML crawl completed"));
        assert!(rendered.contains("Base URL: https://example.com"));
        assert!(rendered.contains("Candidates: 2"));
    }

    #[test]
    fn converts_browser_crawl_log_to_candidates() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let log_path = temp_dir.path().join("browser-log.json");
        fs::write(
            &log_path,
            serde_json::json!({
                "routes": [
                    "https://example.com/app?token=secret"
                ],
                "requests": [
                    {
                        "method": "GET",
                        "url": "https://example.com/api/users?search=alice&token=secret",
                        "resource_type": "xhr"
                    },
                    {
                        "method": "GET",
                        "url": "https://example.com/assets/app.js",
                        "resource_type": "script"
                    }
                ]
            })
            .to_string(),
        )
        .expect("browser log");
        let command = CrawlBrowserLogCommand {
            file: log_path,
            base_url: "https://example.com/".to_string(),
            format: OutputFormat::Json,
        };

        let result = run_crawl_browser_log_command(&command).expect("browser crawl");
        let rendered = render_browser_crawl(&result, OutputFormat::Text).expect("text");

        assert_eq!(result.route_count, 1);
        assert_eq!(result.request_count, 2);
        assert_eq!(result.candidate_count, 2);
        assert!(result
            .candidates
            .iter()
            .all(|candidate| !candidate.url.contains("secret")));
        assert!(rendered.contains("Browser crawl log completed"));
    }

    #[test]
    fn crawls_approved_url_with_injected_fetch_client() {
        let client = StaticCrawlerClient {
            pages: HashMap::from([
                (
                    "https://example.com/".to_string(),
                    CrawlerFetchResponse {
                        final_url: "https://example.com/".to_string(),
                        status_code: 200,
                        content_type: Some("text/html".to_string()),
                        body:
                            r#"<a href="/app">App</a><form action="/login" method="post"></form>"#
                                .to_string(),
                    },
                ),
                (
                    "https://example.com/app".to_string(),
                    CrawlerFetchResponse {
                        final_url: "https://example.com/app".to_string(),
                        status_code: 200,
                        content_type: Some("text/html".to_string()),
                        body: r#"<a href="/settings">Settings</a>"#.to_string(),
                    },
                ),
            ]),
        };

        let result = run_crawl_url_command(&crawl_url_command(), &client).expect("crawl");

        assert_eq!(result.page_count, 2);
        assert_eq!(result.candidate_count, 3);
        assert!(result
            .candidates
            .iter()
            .any(|candidate| candidate.url == "https://example.com/login"));
    }

    #[test]
    fn crawl_url_requires_approval_note() {
        let mut command = crawl_url_command();
        command.approval_note = " ".to_string();
        let client = StaticCrawlerClient {
            pages: HashMap::new(),
        };

        let result = run_crawl_url_command(&command, &client);

        assert!(matches!(
            result,
            Err(CliError::Scan(ScannerError::MissingApproval))
        ));
    }

    #[test]
    fn crawl_url_rejects_unbounded_options() {
        let mut command = crawl_url_command();
        command.max_pages = MAX_CRAWL_URL_PAGES + 1;
        let client = StaticCrawlerClient {
            pages: HashMap::new(),
        };

        let result = run_crawl_url_command(&command, &client);

        assert!(matches!(
            result,
            Err(CliError::CrawlOptionOutOfRange {
                field: "max-pages",
                min: 1,
                max: MAX_CRAWL_URL_PAGES
            })
        ));
    }

    #[test]
    fn renders_url_crawl_text() {
        let result = CliUrlCrawlResult {
            seed_url: "https://example.com/".to_string(),
            page_count: 2,
            candidate_count: 3,
            pages: Vec::new(),
            candidates: Vec::new(),
        };

        let rendered = render_url_crawl(&result, OutputFormat::Text).expect("text");

        assert!(rendered.contains("URL crawl completed"));
        assert!(rendered.contains("Pages: 2"));
        assert!(rendered.contains("Candidates: 3"));
    }

    #[test]
    fn verifies_safe_active_signals_with_injected_client() {
        let mutated_url = "https://example.com/search?q=aegis-safe-reflect-marker-q";
        let redirect_url =
            "https://example.com/search?q=https%3A%2F%2Faegis.invalid%2Fopen-redirect-probe";
        let client = StaticActiveClient {
            responses: HashMap::from([
                (
                    mutated_url.to_string(),
                    HttpProbeResponse {
                        final_url: mutated_url.to_string(),
                        status_code: 200,
                        headers: Vec::new(),
                        body_sample: b"aegis-safe-reflect-marker-q".to_vec(),
                    },
                ),
                (
                    redirect_url.to_string(),
                    HttpProbeResponse {
                        final_url: "https://example.com/search?q=blocked".to_string(),
                        status_code: 200,
                        headers: Vec::new(),
                        body_sample: Vec::new(),
                    },
                ),
            ]),
        };

        let report = run_verify_active_command(&verify_active_command(), &client).expect("verify");
        let rendered = render_active_verify(&report, ReportFormat::Text).expect("text");

        assert_eq!(report.finding_count, 1);
        assert!(report.failed_policy);
        assert!(rendered.contains("Active verification completed"));
    }

    #[test]
    fn renders_active_verify_report_with_redacted_target_and_evidence() {
        let report = CliActiveVerifyReport {
            target_url: "https://example.com/search?token=raw-token#frag".to_string(),
            finding_count: 1,
            highest_severity: Some(FindingSeverity::Medium),
            failed_policy: true,
            fail_on: "medium".to_string(),
            baseline_diff: None,
            findings: vec![PassiveFinding {
                rule_id: "active.reflected_xss_signal".to_string(),
                title: "Reflected input signal".to_string(),
                severity: FindingSeverity::Medium,
                evidence: "https://example.com/search?token=raw-token#frag password=raw-password"
                    .to_string(),
                recommendation: "Validate reflected input".to_string(),
            }],
        };

        let json = render_active_verify(&report, ReportFormat::Json).expect("json");
        let sarif = render_active_verify(&report, ReportFormat::Sarif).expect("sarif");
        let text = render_active_verify(&report, ReportFormat::Text).expect("text");

        assert!(json.contains("\"target_url\": \"https://example.com/search?token=\""));
        assert!(sarif.contains("\"uri\": \"https://example.com/search?token=\""));
        assert!(text.contains("Target: https://example.com/search?token="));
        assert!(json.contains("password=[REDACTED]"));
        assert!(sarif.contains("password=[REDACTED]"));
        assert!(!json.contains("raw-token"));
        assert!(!sarif.contains("raw-token"));
        assert!(!text.contains("raw-token"));
        assert!(!json.contains("raw-password"));
        assert!(!sarif.contains("raw-password"));
        assert!(!json.contains("#frag"));
        assert!(!sarif.contains("#frag"));
        assert!(!text.contains("#frag"));
    }

    #[test]
    fn renders_cli_candidate_metadata_without_confirming_exploit() {
        let report = CliActiveVerifyReport {
            target_url: "https://example.com/search?q=test".to_string(),
            finding_count: 1,
            highest_severity: Some(FindingSeverity::Medium),
            failed_policy: true,
            fail_on: "medium".to_string(),
            baseline_diff: None,
            findings: vec![PassiveFinding {
                rule_id: "aegis.candidate.reflected-xss".to_string(),
                title: "Reflected XSS candidate requires confirmation".to_string(),
                severity: FindingSeverity::Medium,
                evidence: native_candidate_evidence("marker reflected in response sample"),
                recommendation: "Manually confirm before remediation".to_string(),
            }],
        };

        let json = render_active_verify(&report, ReportFormat::Json).expect("json");
        let sarif = render_active_verify(&report, ReportFormat::Sarif).expect("sarif");
        let text = render_active_verify(&report, ReportFormat::Text).expect("text");

        assert!(json.contains("\"source\": \"native-active-candidate\""));
        assert!(json.contains("\"requires_manual_confirmation\": true"));
        assert!(json.contains("\"finding_classification\": \"candidate\""));
        assert!(sarif.contains("\"source\": \"native-active-candidate\""));
        assert!(sarif.contains("\"requires_manual_confirmation\": true"));
        assert!(sarif.contains("\"finding_classification\": \"candidate\""));
        assert!(sarif.contains("manual confirmation required"));
        assert!(text.contains("Manual confirmation required: 1"));
    }
}
