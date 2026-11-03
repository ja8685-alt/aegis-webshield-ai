#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use aegis_ai::{AiFixGuide, AiFixGuideClient, AiFixGuideRequest, OpenAiResponsesClient};
use aegis_core::{
    rule_pack_channel_supported, validate_scan_plan, ApprovedTarget, LocalEngineService,
    LocalEngineSnapshot, ScanPlan, ScanProfile, UsageSnapshot, MAX_CONCURRENT_SCANS,
};
use aegis_crawler::{
    crawl_approved_html_surface, extract_browser_observation_candidates, extract_html_candidates,
    BrowserCrawlObservation, CrawlCandidate, CrawlCandidateSource, CrawlPage, CrawlerOptions,
};
use aegis_openapi::{import_openapi_document as parse_openapi_document, OpenApiImportResult};
use aegis_scanner::{
    build_passive_probe, run_passive_probe, run_safe_active_verifiers, split_native_evidence,
    surface_probe_targets, FindingSeverity, NativeHttpProbeClient, PassiveFinding, ScanTarget,
    UreqHttpProbeClient,
};
use aegis_secrets::{PlatformSecretStore, SecretDescriptor, SecretSnapshot, SecretStore};
use aegis_storage::{
    cancel_scan, create_audit_log, create_finding, create_project, create_scan, create_target,
    deactivate_project, deactivate_target, initialize_local_storage, list_audit_logs,
    list_findings, list_projects, list_scans, list_target_endpoints, list_targets,
    local_usage_snapshot, recover_interrupted_scans, replace_target_endpoints, scan_baseline_diff,
    update_finding_status, update_project, update_scan_phase, update_target, AuditLogRecord,
    BaselineDiffSummary, CreateAuditLogInput, CreateFindingInput, CreateProjectInput,
    CreateScanInput, CreateTargetEndpointInput, CreateTargetInput, FindingRecord,
    LocalStorageSnapshot, ProjectRecord, ReplaceTargetEndpointsInput, ScanRecord,
    TargetEndpointRecord, TargetRecord, UpdateFindingStatusInput, UpdateProjectInput,
    UpdateScanPhaseInput, UpdateTargetInput,
};
use aegis_triage::triage_rule;
use aegis_urlseed::{import_url_seed_document as parse_url_seed_document, UrlSeedImportResult};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use flate2::read::DeflateDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::{Manager, State};
use url::Url;

const MAX_OPENAPI_DOCUMENT_CHARS: usize = 2 * 1024 * 1024;
const MAX_URL_SEED_DOCUMENT_CHARS: usize = 512 * 1024;
const MAX_HTML_DOCUMENT_CHARS: usize = 2 * 1024 * 1024;
const MAX_REPORT_ARTIFACT_BYTES: u64 = 20 * 1024 * 1024;
const MAX_RULE_PACK_MANIFEST_CHARS: usize = 512 * 1024;
const MAX_RULE_PACK_FEED_CHARS: usize = 128 * 1024;
const MAX_RULE_PACK_BUNDLE_BYTES: usize = 10 * 1024 * 1024;
const MAX_RULE_PACK_BUNDLE_ENTRY_BYTES: u64 = 2 * 1024 * 1024;
const MAX_DESKTOP_CRAWL_PAGES: usize = 50;
const MAX_DESKTOP_CRAWL_CANDIDATES: usize = 250;
const MAX_DESKTOP_CRAWL_DEPTH: usize = 3;
const DEFAULT_RULE_PACK_VERSION: &str = "2026.06.12";
const DEFAULT_RULE_PACK_CHANNEL: &str = "built-in";
const DEFAULT_REPORT_ARTIFACT_RETENTION_DAYS: u64 = 30;

#[derive(Debug, Deserialize)]
struct DeactivateProjectCommand {
    project_id: String,
}

#[derive(Debug, Deserialize)]
struct DeactivateTargetCommand {
    target_id: String,
}

#[derive(Debug, Deserialize)]
struct CancelScanCommand {
    scan_id: String,
}

#[derive(Debug, Deserialize)]
struct ScanBaselineDiffCommand {
    scan_id: String,
}

#[derive(Debug, Deserialize)]
struct SetScanRunnerCommand {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct SaveAiApiKeyCommand {
    provider: String,
    account: String,
    secret_value: String,
}

#[derive(Debug, Deserialize)]
struct DeleteAiApiKeyCommand {
    provider: String,
    account: String,
}

#[derive(Debug, Deserialize)]
struct GenerateAiFixGuideCommand {
    provider: String,
    account: String,
    request: AiFixGuideRequest,
}

#[derive(Debug, Deserialize)]
struct RecordReportExportCommand {
    format: String,
    finding_count: u32,
    artifact_file_name: Option<String>,
    artifact_content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CleanupReportArtifactsCommand {
    older_than_days: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ImportRulePackManifestCommand {
    document: String,
    expected_manifest_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ImportRulePackBundleCommand {
    bundle_bytes: Vec<u8>,
    bundle_file_name: Option<String>,
    expected_manifest_sha256: Option<String>,
    public_key_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RollbackRulePackManifestCommand {
    confirm: bool,
}

#[derive(Debug, Deserialize)]
struct CheckRulePackUpdateFeedCommand {
    document: String,
    public_key_hex: Option<String>,
}

#[derive(Debug, Serialize)]
struct RecordReportExportResult {
    usage: UsageSnapshot,
    artifact: ReportArtifactRecord,
}

#[derive(Debug, Serialize)]
struct ReportArtifactRecord {
    file_name: String,
    relative_path: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct CleanupReportArtifactsResult {
    deleted_count: u32,
    deleted_bytes: u64,
}

#[derive(Debug, Serialize)]
struct SupportDiagnosticsResult {
    file_name: String,
    relative_path: String,
    size_bytes: u64,
    sha256: String,
    generated_at: String,
}

#[derive(Debug, Serialize)]
struct SupportDiagnosticsAuditLogRecord {
    action: String,
    entity_type: String,
    severity: String,
    metadata_json_redacted: String,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct RulePackStatus {
    version: String,
    channel: String,
    source: String,
    rule_count: u32,
    enabled_rule_count: u32,
    disabled_rule_count: u32,
    published_at: Option<String>,
    imported_at: Option<String>,
    manifest_sha256: Option<String>,
    bundle_sha256: Option<String>,
    bundle_size_bytes: Option<u64>,
    bundle_file_name: Option<String>,
    rollback_available: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct RulePackBundleMetadata {
    version: String,
    channel: String,
    manifest_sha256: String,
    bundle_sha256: String,
    bundle_size_bytes: u64,
    bundle_file_name: Option<String>,
    imported_at: String,
}

#[derive(Debug, Deserialize)]
struct RulePackManifest {
    version: String,
    channel: String,
    published_at: Option<String>,
    rules: Vec<RulePackManifestRule>,
}

#[derive(Debug, Deserialize)]
struct RulePackManifestRule {
    id: String,
    severity: Option<String>,
    enabled: Option<bool>,
}

#[derive(Debug, Clone)]
struct RuntimeRulePack {
    version: String,
    channel: String,
    manifest_sha256: String,
    severities: BTreeMap<String, String>,
    disabled_rules: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
struct RulePackUpdateFeed {
    latest_version: String,
    channel: String,
    manifest_sha256: String,
    manifest_url: Option<String>,
    published_at: Option<String>,
    minimum_app_version: Option<String>,
    signature: Option<String>,
}

#[derive(Debug, Serialize)]
struct RulePackUpdateFeedStatus {
    current_version: String,
    latest_version: String,
    channel: String,
    update_available: bool,
    entitlement_allowed: bool,
    blocked_reason: Option<String>,
    manifest_sha256: String,
    manifest_url: Option<String>,
    published_at: Option<String>,
    minimum_app_version: Option<String>,
    signature_verified: bool,
}

#[derive(Debug, Deserialize)]
struct ImportOpenApiDocumentCommand {
    document: String,
    base_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ImportUrlSeedDocumentCommand {
    document: String,
}

#[derive(Debug, Deserialize)]
struct CrawlHtmlDocumentCommand {
    document: String,
    base_url: String,
}

#[derive(Debug, Deserialize)]
struct CrawlBrowserObservationCommand {
    document: String,
    base_url: String,
}

#[derive(Debug, Deserialize)]
struct CrawlApprovedUrlCommand {
    url: String,
    approval_note: String,
    allow_private_network: bool,
    max_pages: usize,
    max_candidates: usize,
    max_depth: usize,
}

#[derive(Debug, Serialize)]
struct DesktopUrlCrawlResult {
    seed_url: String,
    page_count: usize,
    candidate_count: usize,
    pages: Vec<CrawlPage>,
    candidates: Vec<CrawlCandidate>,
}

#[derive(Debug, Deserialize)]
struct ReplaceOpenApiEndpointCandidatesCommand {
    target_id: String,
    endpoints: Vec<aegis_openapi::OpenApiEndpoint>,
}

#[derive(Debug, Deserialize)]
struct ReplaceUrlSeedEndpointCandidatesCommand {
    target_id: String,
    seeds: Vec<aegis_urlseed::UrlSeed>,
}

#[derive(Debug, Deserialize)]
struct ReplaceHtmlCrawlEndpointCandidatesCommand {
    target_id: String,
    candidates: Vec<CrawlCandidate>,
}

#[derive(Debug, Deserialize)]
struct ListTargetEndpointsCommand {
    target_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScanRunnerStatus {
    enabled: bool,
}

#[derive(Debug, Clone, Copy)]
enum ReportExportFormat {
    Html,
    Markdown,
    Json,
    Pdf,
    Sarif,
}

impl ReportExportFormat {
    fn label(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Markdown => "markdown",
            Self::Json => "json",
            Self::Pdf => "pdf",
            Self::Sarif => "sarif",
        }
    }
}

fn validate_report_format(value: &str) -> Result<ReportExportFormat, String> {
    match value.trim() {
        "html" => Ok(ReportExportFormat::Html),
        "markdown" => Ok(ReportExportFormat::Markdown),
        "json" => Ok(ReportExportFormat::Json),
        "pdf" => Ok(ReportExportFormat::Pdf),
        "sarif" => Ok(ReportExportFormat::Sarif),
        _ => Err("Unsupported report format".to_string()),
    }
}

fn validate_report_artifact_file_name(value: Option<&str>) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 160
        || value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || value
            .chars()
            .any(|character| matches!(character, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        || value.chars().any(char::is_control)
    {
        return Err("Invalid report artifact file name".to_string());
    }
    Ok(Some(value.to_string()))
}

struct AppState {
    local_engine: Mutex<LocalEngineService>,
    app_data_dir: PathBuf,
    database_path: PathBuf,
    scan_runner_enabled: Arc<AtomicBool>,
    secret_store: PlatformSecretStore,
}

#[tauri::command]
fn local_engine_status(state: State<'_, AppState>) -> Result<LocalEngineSnapshot, String> {
    let engine = state
        .local_engine
        .lock()
        .map_err(|_| "engine lock failed".to_string())?;
    Ok(engine.snapshot())
}

#[tauri::command]
fn start_local_engine(state: State<'_, AppState>) -> Result<LocalEngineSnapshot, String> {
    let mut engine = state
        .local_engine
        .lock()
        .map_err(|_| "engine lock failed".to_string())?;
    Ok(engine.start())
}

#[tauri::command]
fn stop_local_engine(state: State<'_, AppState>) -> Result<LocalEngineSnapshot, String> {
    let mut engine = state
        .local_engine
        .lock()
        .map_err(|_| "engine lock failed".to_string())?;
    Ok(engine.stop())
}

#[tauri::command]
fn save_ai_api_key(
    state: State<'_, AppState>,
    input: SaveAiApiKeyCommand,
) -> Result<SecretSnapshot, String> {
    state
        .secret_store
        .save_secret(
            &SecretDescriptor {
                provider: input.provider,
                account: input.account,
            },
            &input.secret_value,
        )
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn delete_ai_api_key(
    state: State<'_, AppState>,
    input: DeleteAiApiKeyCommand,
) -> Result<(), String> {
    state
        .secret_store
        .delete_secret(&SecretDescriptor {
            provider: input.provider,
            account: input.account,
        })
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn generate_ai_fix_guide(
    state: State<'_, AppState>,
    input: GenerateAiFixGuideCommand,
) -> Result<AiFixGuide, String> {
    if input.provider != "openai" {
        return Err("Only OpenAI AI Fix Guide provider is currently available".to_string());
    }
    write_ai_fix_guide_audit(
        &state,
        "ai_fix_guide.requested",
        "info",
        &input.provider,
        &input.account,
        &input.request.finding_id,
        None,
    )?;
    let api_key = match state.secret_store.get_secret(&SecretDescriptor {
        provider: input.provider.clone(),
        account: input.account.clone(),
    }) {
        Ok(api_key) => api_key,
        Err(error) => {
            let message = error.to_string();
            write_ai_fix_guide_audit(
                &state,
                "ai_fix_guide.failed",
                "warning",
                &input.provider,
                &input.account,
                &input.request.finding_id,
                Some(&message),
            )?;
            return Err(message);
        }
    };
    match OpenAiResponsesClient::new(api_key).generate_fix_guide(&input.request) {
        Ok(guide) => {
            write_ai_fix_guide_audit(
                &state,
                "ai_fix_guide.generated",
                "info",
                &input.provider,
                &input.account,
                &input.request.finding_id,
                None,
            )?;
            Ok(guide)
        }
        Err(error) => {
            let message = error.to_string();
            write_ai_fix_guide_audit(
                &state,
                "ai_fix_guide.failed",
                "warning",
                &input.provider,
                &input.account,
                &input.request.finding_id,
                Some(&message),
            )?;
            Err(message)
        }
    }
}

#[tauri::command]
fn import_openapi_document(
    input: ImportOpenApiDocumentCommand,
) -> Result<OpenApiImportResult, String> {
    if input.document.len() > MAX_OPENAPI_DOCUMENT_CHARS {
        return Err("OpenAPI document is too large".to_string());
    }
    parse_openapi_document(&input.document, input.base_url.as_deref())
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn import_url_seed_document(
    input: ImportUrlSeedDocumentCommand,
) -> Result<UrlSeedImportResult, String> {
    if input.document.len() > MAX_URL_SEED_DOCUMENT_CHARS {
        return Err("URL seed document is too large".to_string());
    }
    parse_url_seed_document(&input.document).map_err(|error| error.to_string())
}

#[tauri::command]
fn crawl_html_document(input: CrawlHtmlDocumentCommand) -> Result<Vec<CrawlCandidate>, String> {
    if input.document.len() > MAX_HTML_DOCUMENT_CHARS {
        return Err("HTML document is too large".to_string());
    }
    extract_html_candidates(&input.base_url, &input.document).map_err(|error| error.to_string())
}

#[tauri::command]
fn crawl_browser_observation(
    input: CrawlBrowserObservationCommand,
) -> Result<Vec<CrawlCandidate>, String> {
    if input.document.len() > MAX_HTML_DOCUMENT_CHARS {
        return Err("Browser observation document is too large".to_string());
    }
    let observation = serde_json::from_str::<BrowserCrawlObservation>(&input.document)
        .map_err(|error| error.to_string())?;
    extract_browser_observation_candidates(&input.base_url, &observation)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn crawl_approved_url(input: CrawlApprovedUrlCommand) -> Result<DesktopUrlCrawlResult, String> {
    let crawler_options =
        validate_desktop_crawler_options(input.max_pages, input.max_candidates, input.max_depth)?;
    let target = ScanTarget {
        id: "desktop-crawl-target".to_string(),
        method: Some("GET".to_string()),
        url: input.url.clone(),
        approval_note: input.approval_note.clone(),
        allow_private_network: input.allow_private_network,
    };
    build_passive_probe(&target).map_err(|error| error.to_string())?;

    let client = NativeHttpProbeClient::new(input.allow_private_network);
    let result = crawl_approved_html_surface(&input.url, crawler_options, &client)
        .map_err(|error| error.to_string())?;

    Ok(DesktopUrlCrawlResult {
        seed_url: input.url.trim().to_string(),
        page_count: result.pages.len(),
        candidate_count: result.candidates.len(),
        pages: result.pages,
        candidates: result.candidates,
    })
}

fn validate_desktop_crawler_options(
    max_pages: usize,
    max_candidates: usize,
    max_depth: usize,
) -> Result<CrawlerOptions, String> {
    if max_pages == 0 || max_pages > MAX_DESKTOP_CRAWL_PAGES {
        return Err(format!(
            "Max pages must be between 1 and {MAX_DESKTOP_CRAWL_PAGES}"
        ));
    }
    if max_candidates == 0 || max_candidates > MAX_DESKTOP_CRAWL_CANDIDATES {
        return Err(format!(
            "Max candidates must be between 1 and {MAX_DESKTOP_CRAWL_CANDIDATES}"
        ));
    }
    if max_depth > MAX_DESKTOP_CRAWL_DEPTH {
        return Err(format!(
            "Max depth must be at most {MAX_DESKTOP_CRAWL_DEPTH}"
        ));
    }

    Ok(CrawlerOptions {
        max_pages,
        max_candidates,
        max_depth,
        ..CrawlerOptions::default()
    })
}

#[tauri::command]
fn local_storage_status(state: State<'_, AppState>) -> Result<LocalStorageSnapshot, String> {
    initialize_local_storage(&state.app_data_dir, &state.database_path)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn local_usage_status(state: State<'_, AppState>) -> Result<UsageSnapshot, String> {
    read_usage_snapshot(&state)
}

#[tauri::command]
fn record_report_export(
    state: State<'_, AppState>,
    input: RecordReportExportCommand,
) -> Result<RecordReportExportResult, String> {
    let format = validate_report_format(&input.format)?;
    let artifact = save_report_artifact(&state, format, &input)?;
    write_report_export_audit(&state, format, &input, &artifact)?;
    let usage = read_usage_snapshot(&state)?;
    Ok(RecordReportExportResult { usage, artifact })
}

#[tauri::command]
fn cleanup_report_artifacts(
    state: State<'_, AppState>,
    input: CleanupReportArtifactsCommand,
) -> Result<CleanupReportArtifactsResult, String> {
    let result = cleanup_report_artifacts_in_dir(&state.app_data_dir, input.older_than_days)?;
    write_report_cleanup_audit(&state, input.older_than_days, &result)?;
    Ok(result)
}

#[tauri::command]
fn collect_support_diagnostics(
    state: State<'_, AppState>,
) -> Result<SupportDiagnosticsResult, String> {
    let result = save_support_diagnostics(&state)?;
    write_support_diagnostics_audit(&state, &result)?;
    Ok(result)
}

#[tauri::command]
fn local_rule_pack_status(state: State<'_, AppState>) -> Result<RulePackStatus, String> {
    read_rule_pack_status(&state.app_data_dir)
}

#[tauri::command]
fn import_rule_pack_manifest(
    state: State<'_, AppState>,
    input: ImportRulePackManifestCommand,
) -> Result<RulePackStatus, String> {
    let manifest = parse_rule_pack_manifest(&input.document)?;
    let manifest_sha256 = sha256_hex(input.document.as_bytes());
    validate_expected_sha256(input.expected_manifest_sha256.as_deref(), &manifest_sha256)?;
    ensure_rule_pack_channel_allowed(&state, &manifest.channel)?;
    let rules_dir = state.app_data_dir.join("rules");
    fs::create_dir_all(&rules_dir).map_err(|error| error.to_string())?;
    let manifest_path = rules_dir.join("manifest.json");
    ensure_child_path(&rules_dir, &manifest_path)?;
    backup_existing_rule_pack_state(&rules_dir, &manifest_path)?;
    remove_current_rule_pack_bundle_metadata(&rules_dir)?;
    fs::write(&manifest_path, input.document.as_bytes()).map_err(|error| error.to_string())?;
    let status = rule_pack_status_from_manifest(
        &state.app_data_dir,
        &manifest,
        "local",
        Some(current_unix_timestamp().to_string()),
        Some(manifest_sha256),
        None,
    );
    write_rule_pack_import_audit(&state, &status)?;
    Ok(status)
}

#[tauri::command]
fn import_rule_pack_bundle(
    state: State<'_, AppState>,
    input: ImportRulePackBundleCommand,
) -> Result<RulePackStatus, String> {
    if input.bundle_bytes.len() > MAX_RULE_PACK_BUNDLE_BYTES {
        return Err("Rule pack bundle is too large".to_string());
    }
    let bundle_sha256 = sha256_hex(&input.bundle_bytes);
    let entries = parse_rule_pack_bundle_zip(&input.bundle_bytes)?;
    let mut manifest_document = None;
    let mut signature_hex = None;

    for entry in &entries {
        validate_rule_pack_bundle_entry(entry)?;
        if entry.name == "manifest.json" {
            let bytes = read_rule_pack_bundle_entry(&input.bundle_bytes, entry)?;
            manifest_document = Some(
                String::from_utf8(bytes)
                    .map_err(|error| format!("Rule pack bundle manifest is not UTF-8: {error}"))?,
            );
        } else if entry.name == "manifest.sig" {
            let bytes = read_rule_pack_bundle_entry(&input.bundle_bytes, entry)?;
            let signature = String::from_utf8(bytes)
                .map_err(|error| format!("Rule pack bundle signature is not UTF-8: {error}"))?;
            let signature = signature.trim();
            if !signature.is_empty() {
                signature_hex = Some(signature.to_string());
            }
        }
    }

    let document = manifest_document
        .ok_or_else(|| "Rule pack bundle must contain root manifest.json".to_string())?;
    let manifest_sha256 = sha256_hex(document.as_bytes());
    validate_expected_sha256(input.expected_manifest_sha256.as_deref(), &manifest_sha256)?;
    if let Some(public_key_hex) = input
        .public_key_hex
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let signature_hex = signature_hex.as_deref().ok_or_else(|| {
            "Rule pack bundle signature is required when a public key is provided".to_string()
        })?;
        verify_detached_rule_pack_signature(document.as_bytes(), signature_hex, public_key_hex)?;
    }

    let manifest = parse_rule_pack_manifest(&document)?;
    ensure_rule_pack_channel_allowed(&state, &manifest.channel)?;
    let rules_dir = state.app_data_dir.join("rules");
    fs::create_dir_all(&rules_dir).map_err(|error| error.to_string())?;
    let manifest_path = rules_dir.join("manifest.json");
    ensure_child_path(&rules_dir, &manifest_path)?;
    backup_existing_rule_pack_state(&rules_dir, &manifest_path)?;
    save_rule_pack_bundle_artifact(&rules_dir, &bundle_sha256, &input.bundle_bytes)?;
    let imported_at = current_unix_timestamp().to_string();
    let bundle_metadata = RulePackBundleMetadata {
        version: manifest.version.trim().to_string(),
        channel: manifest.channel.trim().to_string(),
        manifest_sha256: manifest_sha256.clone(),
        bundle_sha256,
        bundle_size_bytes: input.bundle_bytes.len() as u64,
        bundle_file_name: input
            .bundle_file_name
            .as_deref()
            .and_then(sanitize_bundle_file_name),
        imported_at: imported_at.clone(),
    };
    write_rule_pack_bundle_metadata(&rules_dir, &bundle_metadata)?;
    fs::write(&manifest_path, document.as_bytes()).map_err(|error| error.to_string())?;
    let status = rule_pack_status_from_manifest(
        &state.app_data_dir,
        &manifest,
        "bundle",
        Some(imported_at),
        Some(manifest_sha256),
        Some(&bundle_metadata),
    );
    write_rule_pack_import_audit(&state, &status)?;
    Ok(status)
}

#[tauri::command]
fn rollback_rule_pack_manifest(
    state: State<'_, AppState>,
    input: RollbackRulePackManifestCommand,
) -> Result<RulePackStatus, String> {
    if !input.confirm {
        return Err("Rule pack rollback confirmation is required".to_string());
    }
    let rules_dir = state.app_data_dir.join("rules");
    let manifest_path = rules_dir.join("manifest.json");
    let previous_path = rules_dir.join("manifest.previous.json");
    ensure_child_path(&rules_dir, &manifest_path)?;
    ensure_child_path(&rules_dir, &previous_path)?;
    if !previous_path.exists() {
        return Err("No previous rule pack manifest is available".to_string());
    }
    fs::copy(&previous_path, &manifest_path).map_err(|error| error.to_string())?;
    restore_previous_rule_pack_bundle_metadata(&rules_dir)?;
    let status = read_rule_pack_status(&state.app_data_dir)?;
    write_rule_pack_rollback_audit(&state, &status)?;
    Ok(status)
}

#[tauri::command]
fn check_rule_pack_update_feed(
    state: State<'_, AppState>,
    input: CheckRulePackUpdateFeedCommand,
) -> Result<RulePackUpdateFeedStatus, String> {
    let feed = parse_rule_pack_update_feed(&input.document)?;
    let signature_verified = match input
        .public_key_hex
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(public_key_hex) => {
            verify_rule_pack_feed_signature(&feed, public_key_hex)?;
            true
        }
        None => false,
    };
    let current = read_rule_pack_status(&state.app_data_dir)?;
    let blocked_reason = rule_pack_channel_block_reason(&state, &feed.channel)?;
    let update_available = rule_pack_update_available(&current.version, &feed.latest_version);
    let status = RulePackUpdateFeedStatus {
        current_version: current.version.clone(),
        latest_version: feed.latest_version,
        channel: feed.channel,
        update_available,
        entitlement_allowed: blocked_reason.is_none(),
        blocked_reason,
        manifest_sha256: feed.manifest_sha256,
        manifest_url: feed.manifest_url,
        published_at: feed.published_at,
        minimum_app_version: feed.minimum_app_version,
        signature_verified,
    };
    write_rule_pack_feed_check_audit(&state, &status)?;
    Ok(status)
}

#[tauri::command]
fn list_local_projects(state: State<'_, AppState>) -> Result<Vec<ProjectRecord>, String> {
    list_projects(&state.app_data_dir, &state.database_path).map_err(|error| error.to_string())
}

#[tauri::command]
fn create_local_project(
    state: State<'_, AppState>,
    input: CreateProjectInput,
) -> Result<ProjectRecord, String> {
    create_project(&state.app_data_dir, &state.database_path, input)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn update_local_project(
    state: State<'_, AppState>,
    input: UpdateProjectInput,
) -> Result<ProjectRecord, String> {
    update_project(&state.app_data_dir, &state.database_path, input)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn deactivate_local_project(
    state: State<'_, AppState>,
    input: DeactivateProjectCommand,
) -> Result<(), String> {
    deactivate_project(&state.app_data_dir, &state.database_path, input.project_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_local_targets(state: State<'_, AppState>) -> Result<Vec<TargetRecord>, String> {
    list_targets(&state.app_data_dir, &state.database_path, None).map_err(|error| error.to_string())
}

#[tauri::command]
fn list_local_target_endpoints(
    state: State<'_, AppState>,
    input: Option<ListTargetEndpointsCommand>,
) -> Result<Vec<TargetEndpointRecord>, String> {
    list_target_endpoints(
        &state.app_data_dir,
        &state.database_path,
        input.and_then(|input| input.target_id),
    )
    .map_err(|error| error.to_string())
}

#[tauri::command]
fn replace_openapi_endpoint_candidates(
    state: State<'_, AppState>,
    input: ReplaceOpenApiEndpointCandidatesCommand,
) -> Result<Vec<TargetEndpointRecord>, String> {
    let target_id = input.target_id;
    let endpoints = input
        .endpoints
        .into_iter()
        .map(|endpoint| {
            openapi_endpoint_parameters_json(&endpoint)
                .map(|parameters_json| CreateTargetEndpointInput {
                    method: endpoint.method,
                    path: endpoint.path,
                    url: endpoint.url,
                    operation_id: endpoint.operation_id,
                    parameters_json,
                })
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;

    let endpoint_count = endpoints.len();
    let records = replace_target_endpoints(
        &state.app_data_dir,
        &state.database_path,
        ReplaceTargetEndpointsInput {
            target_id: target_id.clone(),
            endpoints,
        },
    )
    .map_err(|error| error.to_string())?;
    write_endpoint_import_audit(&state, &target_id, "openapi", endpoint_count)?;
    Ok(records)
}

fn openapi_endpoint_parameters_json(
    endpoint: &aegis_openapi::OpenApiEndpoint,
) -> Result<String, String> {
    let mut parameters = endpoint
        .parameters
        .iter()
        .map(|parameter| serde_json::json!(parameter))
        .collect::<Vec<_>>();

    if !endpoint.tags.is_empty() || !endpoint.security_requirements.is_empty() {
        parameters.push(serde_json::json!({
            "name": "x-aegis-openapi-metadata",
            "location": "metadata",
            "required": false,
            "tags": &endpoint.tags,
            "security_requirements": &endpoint.security_requirements,
        }));
    }

    serde_json::to_string(&parameters).map_err(|error| error.to_string())
}

#[tauri::command]
fn replace_url_seed_endpoint_candidates(
    state: State<'_, AppState>,
    input: ReplaceUrlSeedEndpointCandidatesCommand,
) -> Result<Vec<TargetEndpointRecord>, String> {
    let target_id = input.target_id;
    let endpoints = input
        .seeds
        .into_iter()
        .map(|seed| {
            let url = Url::parse(&seed.url).map_err(|error| error.to_string())?;
            let path = match url.query() {
                Some(query) => format!("{}?{}", url.path(), query),
                None => url.path().to_string(),
            };
            serde_json::to_string(&Vec::<String>::new())
                .map(|parameters_json| CreateTargetEndpointInput {
                    method: "GET".to_string(),
                    path,
                    url: seed.url,
                    operation_id: None,
                    parameters_json,
                })
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;

    let endpoint_count = endpoints.len();
    let records = replace_target_endpoints(
        &state.app_data_dir,
        &state.database_path,
        ReplaceTargetEndpointsInput {
            target_id: target_id.clone(),
            endpoints,
        },
    )
    .map_err(|error| error.to_string())?;
    write_endpoint_import_audit(&state, &target_id, "url_seed", endpoint_count)?;
    Ok(records)
}

#[tauri::command]
fn replace_html_crawl_endpoint_candidates(
    state: State<'_, AppState>,
    input: ReplaceHtmlCrawlEndpointCandidatesCommand,
) -> Result<Vec<TargetEndpointRecord>, String> {
    let target_id = input.target_id;
    let endpoints = input
        .candidates
        .into_iter()
        .map(|candidate| {
            let url = Url::parse(&candidate.url).map_err(|error| error.to_string())?;
            let path = match url.query() {
                Some(query) => format!("{}?{}", url.path(), query),
                None => url.path().to_string(),
            };
            serde_json::to_string(&candidate.parameters)
                .map(|parameters_json| CreateTargetEndpointInput {
                    method: candidate.method,
                    path,
                    url: candidate.url,
                    operation_id: Some(format!(
                        "crawler:{}",
                        crawl_candidate_source_label(candidate.source)
                    )),
                    parameters_json,
                })
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;

    let endpoint_count = endpoints.len();
    let records = replace_target_endpoints(
        &state.app_data_dir,
        &state.database_path,
        ReplaceTargetEndpointsInput {
            target_id: target_id.clone(),
            endpoints,
        },
    )
    .map_err(|error| error.to_string())?;
    write_endpoint_import_audit(&state, &target_id, "crawler", endpoint_count)?;
    Ok(records)
}

#[tauri::command]
fn create_local_target(
    state: State<'_, AppState>,
    input: CreateTargetInput,
) -> Result<TargetRecord, String> {
    validate_target_scope(
        &input.url,
        input.allow_private_network,
        &input.approval_note,
    )?;
    create_target(&state.app_data_dir, &state.database_path, input)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn update_local_target(
    state: State<'_, AppState>,
    input: UpdateTargetInput,
) -> Result<TargetRecord, String> {
    validate_target_scope(
        &input.url,
        input.allow_private_network,
        &input.approval_note,
    )?;
    update_target(&state.app_data_dir, &state.database_path, input)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn deactivate_local_target(
    state: State<'_, AppState>,
    input: DeactivateTargetCommand,
) -> Result<(), String> {
    deactivate_target(&state.app_data_dir, &state.database_path, input.target_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_local_scans(state: State<'_, AppState>) -> Result<Vec<ScanRecord>, String> {
    list_scans(&state.app_data_dir, &state.database_path).map_err(|error| error.to_string())
}

#[tauri::command]
fn list_local_findings(state: State<'_, AppState>) -> Result<Vec<FindingRecord>, String> {
    list_findings(&state.app_data_dir, &state.database_path).map_err(|error| error.to_string())
}

#[tauri::command]
fn local_scan_baseline_diff(
    state: State<'_, AppState>,
    input: ScanBaselineDiffCommand,
) -> Result<BaselineDiffSummary, String> {
    scan_baseline_diff(&state.app_data_dir, &state.database_path, input.scan_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_local_audit_logs(state: State<'_, AppState>) -> Result<Vec<AuditLogRecord>, String> {
    list_audit_logs(&state.app_data_dir, &state.database_path).map_err(|error| error.to_string())
}

#[tauri::command]
fn update_local_finding_status(
    state: State<'_, AppState>,
    input: UpdateFindingStatusInput,
) -> Result<FindingRecord, String> {
    let finding_id = input.id.clone();
    let next_status = input.status.clone();
    let previous = list_findings(&state.app_data_dir, &state.database_path)
        .map_err(|error| error.to_string())?
        .into_iter()
        .find(|finding| finding.id == finding_id);
    let updated = update_finding_status(&state.app_data_dir, &state.database_path, input)
        .map_err(|error| error.to_string())?;
    write_finding_status_audit(&state, previous.as_ref(), &updated, &next_status)?;
    Ok(updated)
}

#[tauri::command]
fn create_local_scan(
    state: State<'_, AppState>,
    input: CreateScanInput,
) -> Result<ScanRecord, String> {
    ensure_scan_allowed(&state)?;
    create_scan(&state.app_data_dir, &state.database_path, input).map_err(|error| error.to_string())
}

#[tauri::command]
fn advance_local_scan(state: State<'_, AppState>) -> Result<Option<ScanRecord>, String> {
    advance_next_scan(&state)
}

#[tauri::command]
fn run_local_scan_queue(state: State<'_, AppState>) -> Result<Vec<ScanRecord>, String> {
    run_scan_queue_paths(&state.app_data_dir, &state.database_path, 5)
}

#[tauri::command]
fn set_scan_runner_enabled(
    state: State<'_, AppState>,
    input: SetScanRunnerCommand,
) -> ScanRunnerStatus {
    state
        .scan_runner_enabled
        .store(input.enabled, Ordering::Relaxed);
    ScanRunnerStatus {
        enabled: input.enabled,
    }
}

#[tauri::command]
fn scan_runner_status(state: State<'_, AppState>) -> ScanRunnerStatus {
    ScanRunnerStatus {
        enabled: state.scan_runner_enabled.load(Ordering::Relaxed),
    }
}

fn run_scan_queue_paths(
    app_data_dir: &Path,
    database_path: &Path,
    max_steps: usize,
) -> Result<Vec<ScanRecord>, String> {
    let mut updates = Vec::new();
    for _ in 0..max_steps {
        let Some(scan) = advance_next_scan_paths(app_data_dir, database_path)? else {
            break;
        };
        updates.push(scan);
    }
    Ok(updates)
}

#[tauri::command]
fn cancel_local_scan(
    state: State<'_, AppState>,
    input: CancelScanCommand,
) -> Result<ScanRecord, String> {
    cancel_scan(&state.app_data_dir, &state.database_path, input.scan_id)
        .map_err(|error| error.to_string())
}

fn advance_next_scan(state: &State<'_, AppState>) -> Result<Option<ScanRecord>, String> {
    advance_next_scan_paths(&state.app_data_dir, &state.database_path)
}

fn ensure_scan_allowed(state: &State<'_, AppState>) -> Result<(), String> {
    if read_usage_snapshot(state)?.scan_capacity_available() {
        Ok(())
    } else {
        Err(format!("Local scan capacity reached ({MAX_CONCURRENT_SCANS}); wait for an active scan to finish"))
    }
}

fn validate_target_scope(
    url: &str,
    allow_private_network: bool,
    approval_note: &str,
) -> Result<(), String> {
    validate_scan_plan(&ScanPlan {
        target: ApprovedTarget {
            id: "pending-target".to_string(),
            url: url.to_string(),
            allow_private_network,
            approval_note: approval_note.to_string(),
        },
        profile: ScanProfile::Safe,
        enabled_checks: vec!["scope_validation".to_string()],
    })
    .map_err(|error| error.to_string())
}

fn read_usage_snapshot(state: &State<'_, AppState>) -> Result<UsageSnapshot, String> {
    let usage = local_usage_snapshot(&state.app_data_dir, &state.database_path)
        .map_err(|error| error.to_string())?;
    Ok(UsageSnapshot {
        monthly_scans: usage.monthly_scans,
        projects: usage.projects,
        targets: usage.targets,
        reports: usage.reports,
        ai_fix_guides: usage.ai_fix_guides,
        active_scans: usage.active_scans,
    })
}

fn save_report_artifact(
    state: &State<'_, AppState>,
    format: ReportExportFormat,
    input: &RecordReportExportCommand,
) -> Result<ReportArtifactRecord, String> {
    let content = input
        .artifact_content
        .as_deref()
        .ok_or_else(|| "Report artifact content is required".to_string())?;
    let bytes = content.as_bytes();
    if bytes.len() as u64 > MAX_REPORT_ARTIFACT_BYTES {
        return Err("Report artifact is too large".to_string());
    }

    let requested_name = input
        .artifact_file_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| default_report_artifact_file_name(format));
    let file_name = validate_report_artifact_file_name(Some(&requested_name))?
        .ok_or_else(|| "Invalid report artifact file name".to_string())?;
    validate_report_artifact_extension(format, &file_name)?;

    let reports_dir = state.app_data_dir.join("reports");
    fs::create_dir_all(&reports_dir).map_err(|error| error.to_string())?;
    let artifact_path = reports_dir.join(&file_name);
    ensure_child_path(&reports_dir, &artifact_path)?;
    fs::write(&artifact_path, bytes).map_err(|error| error.to_string())?;

    let sha256 = sha256_hex(bytes);

    Ok(ReportArtifactRecord {
        file_name,
        relative_path: format!(
            "reports/{}",
            artifact_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("report")
        ),
        size_bytes: bytes.len() as u64,
        sha256,
    })
}

fn save_support_diagnostics(
    state: &State<'_, AppState>,
) -> Result<SupportDiagnosticsResult, String> {
    let generated_at = current_unix_timestamp().to_string();
    let diagnostics_dir = state.app_data_dir.join("diagnostics");
    fs::create_dir_all(&diagnostics_dir).map_err(|error| error.to_string())?;
    let file_name = format!("aegis-diagnostics-{generated_at}.json");
    let artifact_path = diagnostics_dir.join(&file_name);
    ensure_child_path(&diagnostics_dir, &artifact_path)?;

    let database_size_bytes = fs::metadata(&state.database_path)
        .map(|metadata| metadata.len())
        .ok();
    let storage = initialize_local_storage(&state.app_data_dir, &state.database_path)
        .map_err(|error| error.to_string())?;
    let usage = read_usage_snapshot(state)?;
    let rule_pack = read_rule_pack_status(&state.app_data_dir)?;
    let audit_logs = list_audit_logs(&state.app_data_dir, &state.database_path)
        .map_err(|error| error.to_string())?;
    let diagnostics_audit_logs = audit_logs
        .into_iter()
        .take(20)
        .map(support_diagnostics_audit_log_record)
        .collect::<Vec<_>>();
    let engine = state
        .local_engine
        .lock()
        .map_err(|_| "engine lock failed".to_string())?
        .snapshot();

    let diagnostics = serde_json::json!({
        "product": "Aegis WebShield AI",
        "app_version": env!("CARGO_PKG_VERSION"),
        "generated_at": &generated_at,
        "platform": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "family": std::env::consts::FAMILY,
        },
        "storage": {
            "database_file_name": state.database_path.file_name().and_then(|value| value.to_str()),
            "database_exists": state.database_path.exists(),
            "database_size_bytes": database_size_bytes,
            "applied_migrations": storage.applied_migrations,
            "workspace_count": storage.workspace_count,
            "project_count": storage.project_count,
            "target_count": storage.target_count,
        },
        "usage": usage,
        "edition": "community",
        "engine": engine,
        "rule_pack": rule_pack,
        "recent_audit_logs": diagnostics_audit_logs,
        "redaction_notes": [
            "No API keys, license keys, approval notes, target URLs, finding evidence, or report bodies are included.",
            "Audit log ids, actors, and entity ids are omitted from support bundles; metadata is parsed and reserialized after redaction checks."
        ]
    });
    let content = serde_json::to_string_pretty(&diagnostics).map_err(|error| error.to_string())?;
    fs::write(&artifact_path, content.as_bytes()).map_err(|error| error.to_string())?;
    let size_bytes = fs::metadata(&artifact_path)
        .map_err(|error| error.to_string())?
        .len();
    let sha256 = sha256_hex(content.as_bytes());

    Ok(SupportDiagnosticsResult {
        file_name,
        relative_path: format!(
            "diagnostics/{}",
            artifact_path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("aegis-diagnostics.json")
        ),
        size_bytes,
        sha256,
        generated_at,
    })
}

fn support_diagnostics_audit_log_record(
    record: AuditLogRecord,
) -> SupportDiagnosticsAuditLogRecord {
    let metadata = support_diagnostics_metadata_value(&record.metadata_json_redacted);
    SupportDiagnosticsAuditLogRecord {
        action: record.action,
        entity_type: record.entity_type,
        severity: record.severity,
        metadata_json_redacted: serde_json::to_string(&metadata)
            .unwrap_or_else(|_| "{\"metadata_omitted\":true}".to_string()),
        created_at: record.created_at,
    }
}

fn support_diagnostics_metadata_value(value: &str) -> serde_json::Value {
    let Ok(metadata) = serde_json::from_str::<serde_json::Value>(value) else {
        return serde_json::json!({
            "metadata_omitted": true,
            "reason": "invalid_json"
        });
    };
    if validate_support_diagnostics_metadata(&metadata).is_err() {
        return serde_json::json!({
            "metadata_omitted": true,
            "reason": "blocked_sensitive_metadata"
        });
    }
    metadata
}

fn validate_support_diagnostics_metadata(value: &serde_json::Value) -> Result<(), String> {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                validate_support_diagnostics_metadata(item)?;
            }
        }
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if is_blocked_support_diagnostics_key(key) {
                    return Err(format!(
                        "Audit metadata key is not allowed in support diagnostics: {key}"
                    ));
                }
                validate_support_diagnostics_metadata(child)?;
            }
        }
        serde_json::Value::String(value) => {
            if looks_like_raw_url(value) {
                return Err("Audit metadata contains a raw URL".to_string());
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_blocked_support_diagnostics_key(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "api_key"
            | "approval_note"
            | "artifact_content"
            | "authorization"
            | "cookie"
            | "endpoint"
            | "evidence"
            | "evidence_json"
            | "license_key"
            | "license_key_hash"
            | "password"
            | "private_key"
            | "prompt"
            | "provider_response"
            | "request_body"
            | "response_body"
            | "secret"
            | "secret_value"
            | "set-cookie"
            | "target_url"
            | "url"
    )
}

fn looks_like_raw_url(value: &str) -> bool {
    value.contains("http://") || value.contains("https://")
}

fn default_report_artifact_file_name(format: ReportExportFormat) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    format!(
        "aegis-webshield-findings-{timestamp}.{}",
        report_artifact_extension(format)
    )
}

fn report_artifact_extension(format: ReportExportFormat) -> &'static str {
    match format {
        ReportExportFormat::Html => "html",
        ReportExportFormat::Markdown => "md",
        ReportExportFormat::Json => "json",
        ReportExportFormat::Pdf => "pdf",
        ReportExportFormat::Sarif => "sarif",
    }
}

fn validate_report_artifact_extension(
    format: ReportExportFormat,
    file_name: &str,
) -> Result<(), String> {
    let expected = format!(".{}", report_artifact_extension(format));
    if file_name.ends_with(&expected) {
        Ok(())
    } else {
        Err("Report artifact extension does not match format".to_string())
    }
}

fn ensure_child_path(parent: &Path, child: &Path) -> Result<(), String> {
    let parent = parent.canonicalize().map_err(|error| error.to_string())?;
    let child_parent = child
        .parent()
        .ok_or_else(|| "Report artifact path is invalid".to_string())?
        .canonicalize()
        .map_err(|error| error.to_string())?;
    if child_parent == parent {
        Ok(())
    } else {
        Err("Artifact path escapes the expected directory".to_string())
    }
}

fn cleanup_report_artifacts_in_dir(
    app_data_dir: &Path,
    older_than_days: Option<u64>,
) -> Result<CleanupReportArtifactsResult, String> {
    let reports_dir = app_data_dir.join("reports");
    if !reports_dir.exists() {
        return Ok(CleanupReportArtifactsResult {
            deleted_count: 0,
            deleted_bytes: 0,
        });
    }

    let reports_dir = reports_dir
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let cutoff = older_than_days.map(|days| {
        SystemTime::now()
            .checked_sub(Duration::from_secs(days.saturating_mul(24 * 60 * 60)))
            .unwrap_or(UNIX_EPOCH)
    });
    let mut deleted_count = 0;
    let mut deleted_bytes = 0;

    for entry in fs::read_dir(&reports_dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        ensure_child_path(&reports_dir, &path)?;
        let metadata = entry.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file() {
            continue;
        }
        if let Some(cutoff) = cutoff {
            let modified = metadata.modified().map_err(|error| error.to_string())?;
            if modified >= cutoff {
                continue;
            }
        }
        let size = metadata.len();
        fs::remove_file(&path).map_err(|error| error.to_string())?;
        deleted_count += 1;
        deleted_bytes += size;
    }

    Ok(CleanupReportArtifactsResult {
        deleted_count,
        deleted_bytes,
    })
}

fn run_scheduled_report_artifact_cleanup(
    app_data_dir: &Path,
    database_path: &Path,
) -> Result<(), String> {
    initialize_local_storage(app_data_dir, database_path).map_err(|error| error.to_string())?;
    let retention_days = Some(DEFAULT_REPORT_ARTIFACT_RETENTION_DAYS);
    let result = cleanup_report_artifacts_in_dir(app_data_dir, retention_days)?;
    if result.deleted_count > 0 {
        write_report_cleanup_audit_paths(
            app_data_dir,
            database_path,
            retention_days,
            &result,
            true,
        )?;
    }
    Ok(())
}

fn read_rule_pack_status(app_data_dir: &Path) -> Result<RulePackStatus, String> {
    let manifest_path = app_data_dir.join("rules").join("manifest.json");
    if !manifest_path.exists() {
        return Ok(RulePackStatus {
            version: DEFAULT_RULE_PACK_VERSION.to_string(),
            channel: DEFAULT_RULE_PACK_CHANNEL.to_string(),
            source: "built-in".to_string(),
            rule_count: 0,
            enabled_rule_count: 0,
            disabled_rule_count: 0,
            published_at: None,
            imported_at: None,
            manifest_sha256: None,
            bundle_sha256: None,
            bundle_size_bytes: None,
            bundle_file_name: None,
            rollback_available: false,
        });
    }
    let document = fs::read_to_string(&manifest_path).map_err(|error| error.to_string())?;
    let manifest = parse_rule_pack_manifest(&document)?;
    let manifest_sha256 = sha256_hex(document.as_bytes());
    let bundle_metadata = read_rule_pack_bundle_metadata(app_data_dir)?.filter(|metadata| {
        metadata
            .manifest_sha256
            .eq_ignore_ascii_case(&manifest_sha256)
    });
    Ok(rule_pack_status_from_manifest(
        app_data_dir,
        &manifest,
        if bundle_metadata.is_some() {
            "bundle"
        } else {
            "local"
        },
        None,
        Some(manifest_sha256),
        bundle_metadata.as_ref(),
    ))
}

fn parse_rule_pack_manifest(document: &str) -> Result<RulePackManifest, String> {
    if document.len() > MAX_RULE_PACK_MANIFEST_CHARS {
        return Err("Rule pack manifest is too large".to_string());
    }
    let manifest = serde_json::from_str::<RulePackManifest>(json_without_bom(document))
        .map_err(|error| format!("Rule pack manifest parse failed: {error}"))?;
    validate_rule_pack_manifest(&manifest)?;
    Ok(manifest)
}

fn parse_rule_pack_update_feed(document: &str) -> Result<RulePackUpdateFeed, String> {
    if document.len() > MAX_RULE_PACK_FEED_CHARS {
        return Err("Rule pack update feed is too large".to_string());
    }
    let feed = serde_json::from_str::<RulePackUpdateFeed>(json_without_bom(document))
        .map_err(|error| format!("Rule pack update feed parse failed: {error}"))?;
    validate_rule_pack_update_feed(&feed)?;
    Ok(feed)
}

#[derive(Debug)]
struct RulePackBundleEntry {
    name: String,
    compression_method: u16,
    compressed_size: u64,
    uncompressed_size: u64,
    local_header_offset: usize,
}

fn parse_rule_pack_bundle_zip(bytes: &[u8]) -> Result<Vec<RulePackBundleEntry>, String> {
    let eocd_offset = find_zip_eocd(bytes)
        .ok_or_else(|| "Rule pack bundle is not a readable ZIP archive".to_string())?;
    let entry_count = read_zip_u16(bytes, eocd_offset + 10)? as usize;
    let central_directory_size = read_zip_u32(bytes, eocd_offset + 12)? as usize;
    let central_directory_offset = read_zip_u32(bytes, eocd_offset + 16)? as usize;
    if central_directory_offset
        .checked_add(central_directory_size)
        .map(|end| end > bytes.len())
        .unwrap_or(true)
    {
        return Err("Rule pack bundle central directory is out of bounds".to_string());
    }

    let mut entries = Vec::with_capacity(entry_count);
    let mut offset = central_directory_offset;
    for _ in 0..entry_count {
        if read_zip_u32(bytes, offset)? != 0x0201_4b50 {
            return Err("Invalid rule pack bundle central directory".to_string());
        }
        let compression_method = read_zip_u16(bytes, offset + 10)?;
        let compressed_size = read_zip_u32(bytes, offset + 20)? as u64;
        let uncompressed_size = read_zip_u32(bytes, offset + 24)? as u64;
        let name_len = read_zip_u16(bytes, offset + 28)? as usize;
        let extra_len = read_zip_u16(bytes, offset + 30)? as usize;
        let comment_len = read_zip_u16(bytes, offset + 32)? as usize;
        let local_header_offset = read_zip_u32(bytes, offset + 42)? as usize;
        let name_start = offset + 46;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or_else(|| "Rule pack bundle entry name overflow".to_string())?;
        if name_end > bytes.len() {
            return Err("Rule pack bundle entry name is out of bounds".to_string());
        }
        let name = std::str::from_utf8(&bytes[name_start..name_end])
            .map_err(|error| format!("Rule pack bundle entry name is not UTF-8: {error}"))?
            .to_string();
        entries.push(RulePackBundleEntry {
            name,
            compression_method,
            compressed_size,
            uncompressed_size,
            local_header_offset,
        });
        offset = name_end
            .checked_add(extra_len)
            .and_then(|value| value.checked_add(comment_len))
            .ok_or_else(|| "Rule pack bundle central directory overflow".to_string())?;
    }
    Ok(entries)
}

fn validate_rule_pack_bundle_entry(entry: &RulePackBundleEntry) -> Result<(), String> {
    if !is_safe_rule_pack_bundle_entry_name(&entry.name) {
        return Err(format!(
            "Rule pack bundle entry path is not allowed: {}",
            entry.name
        ));
    }
    if entry.uncompressed_size > MAX_RULE_PACK_BUNDLE_ENTRY_BYTES {
        return Err(format!(
            "Rule pack bundle entry is too large: {}",
            entry.name
        ));
    }
    Ok(())
}

fn read_rule_pack_bundle_entry(
    bytes: &[u8],
    entry: &RulePackBundleEntry,
) -> Result<Vec<u8>, String> {
    if read_zip_u32(bytes, entry.local_header_offset)? != 0x0403_4b50 {
        return Err(format!(
            "Invalid rule pack bundle local header for {}",
            entry.name
        ));
    }
    let name_len = read_zip_u16(bytes, entry.local_header_offset + 26)? as usize;
    let extra_len = read_zip_u16(bytes, entry.local_header_offset + 28)? as usize;
    let data_start = entry
        .local_header_offset
        .checked_add(30)
        .and_then(|value| value.checked_add(name_len))
        .and_then(|value| value.checked_add(extra_len))
        .ok_or_else(|| "Rule pack bundle local entry overflow".to_string())?;
    let data_end = data_start
        .checked_add(entry.compressed_size as usize)
        .ok_or_else(|| "Rule pack bundle compressed entry overflow".to_string())?;
    if data_end > bytes.len() {
        return Err(format!(
            "Rule pack bundle entry data is out of bounds: {}",
            entry.name
        ));
    }
    let compressed = &bytes[data_start..data_end];
    let mut output = Vec::new();
    match entry.compression_method {
        0 => output.extend_from_slice(compressed),
        8 => {
            let mut decoder = DeflateDecoder::new(Cursor::new(compressed));
            decoder.read_to_end(&mut output).map_err(|error| {
                format!("Failed to inflate rule pack entry {}: {error}", entry.name)
            })?;
        }
        method => {
            return Err(format!(
                "Unsupported rule pack bundle compression method {method} for {}",
                entry.name
            ));
        }
    }
    if output.len() as u64 != entry.uncompressed_size {
        return Err(format!(
            "Rule pack bundle entry size mismatch: {}",
            entry.name
        ));
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

fn read_zip_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| "Rule pack bundle offset overflow".to_string())?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| "Rule pack bundle field is out of bounds".to_string())?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_zip_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| "Rule pack bundle offset overflow".to_string())?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| "Rule pack bundle field is out of bounds".to_string())?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn is_safe_rule_pack_bundle_entry_name(name: &str) -> bool {
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

fn backup_existing_rule_pack_state(rules_dir: &Path, manifest_path: &Path) -> Result<(), String> {
    if manifest_path.exists() {
        let previous_path = rules_dir.join("manifest.previous.json");
        ensure_child_path(rules_dir, &previous_path)?;
        fs::copy(manifest_path, previous_path).map_err(|error| error.to_string())?;
    }
    let metadata_path = rules_dir.join("bundle.json");
    let previous_metadata_path = rules_dir.join("bundle.previous.json");
    ensure_child_path(rules_dir, &metadata_path)?;
    ensure_child_path(rules_dir, &previous_metadata_path)?;
    if metadata_path.exists() {
        fs::copy(&metadata_path, &previous_metadata_path).map_err(|error| error.to_string())?;
    } else if previous_metadata_path.exists() {
        fs::remove_file(&previous_metadata_path).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn remove_current_rule_pack_bundle_metadata(rules_dir: &Path) -> Result<(), String> {
    let metadata_path = rules_dir.join("bundle.json");
    ensure_child_path(rules_dir, &metadata_path)?;
    if metadata_path.exists() {
        fs::remove_file(metadata_path).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn restore_previous_rule_pack_bundle_metadata(rules_dir: &Path) -> Result<(), String> {
    let metadata_path = rules_dir.join("bundle.json");
    let previous_metadata_path = rules_dir.join("bundle.previous.json");
    ensure_child_path(rules_dir, &metadata_path)?;
    ensure_child_path(rules_dir, &previous_metadata_path)?;
    if previous_metadata_path.exists() {
        fs::copy(previous_metadata_path, metadata_path).map_err(|error| error.to_string())?;
    } else if metadata_path.exists() {
        fs::remove_file(metadata_path).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn save_rule_pack_bundle_artifact(
    rules_dir: &Path,
    bundle_sha256: &str,
    bundle_bytes: &[u8],
) -> Result<(), String> {
    let bundles_dir = rules_dir.join("bundles");
    fs::create_dir_all(&bundles_dir).map_err(|error| error.to_string())?;
    ensure_child_path(rules_dir, &bundles_dir)?;
    let artifact_path = bundles_dir.join(format!("{bundle_sha256}.zip"));
    ensure_child_path(&bundles_dir, &artifact_path)?;
    fs::write(artifact_path, bundle_bytes).map_err(|error| error.to_string())
}

fn write_rule_pack_bundle_metadata(
    rules_dir: &Path,
    metadata: &RulePackBundleMetadata,
) -> Result<(), String> {
    let metadata_path = rules_dir.join("bundle.json");
    ensure_child_path(rules_dir, &metadata_path)?;
    let document = serde_json::to_string_pretty(metadata).map_err(|error| error.to_string())?;
    fs::write(metadata_path, document.as_bytes()).map_err(|error| error.to_string())
}

fn read_rule_pack_bundle_metadata(
    app_data_dir: &Path,
) -> Result<Option<RulePackBundleMetadata>, String> {
    let metadata_path = app_data_dir.join("rules").join("bundle.json");
    if !metadata_path.exists() {
        return Ok(None);
    }
    let document = fs::read_to_string(metadata_path).map_err(|error| error.to_string())?;
    let metadata = serde_json::from_str::<RulePackBundleMetadata>(&document)
        .map_err(|error| format!("Rule pack bundle metadata parse failed: {error}"))?;
    Ok(Some(metadata))
}

fn read_runtime_rule_pack(app_data_dir: &Path) -> Result<Option<RuntimeRulePack>, String> {
    let manifest_path = app_data_dir.join("rules").join("manifest.json");
    if !manifest_path.exists() {
        return Ok(None);
    }
    let document = fs::read_to_string(&manifest_path).map_err(|error| error.to_string())?;
    let manifest = parse_rule_pack_manifest(&document)?;
    let severities = manifest
        .rules
        .iter()
        .filter_map(|rule| {
            rule.severity
                .as_ref()
                .map(|severity| (rule.id.trim().to_string(), severity.trim().to_string()))
        })
        .collect::<BTreeMap<_, _>>();
    let disabled_rules = manifest
        .rules
        .iter()
        .filter(|rule| rule.enabled == Some(false))
        .map(|rule| rule.id.trim().to_string())
        .collect::<BTreeSet<_>>();
    Ok(Some(RuntimeRulePack {
        version: manifest.version.trim().to_string(),
        channel: manifest.channel.trim().to_string(),
        manifest_sha256: sha256_hex(document.as_bytes()),
        severities,
        disabled_rules,
    }))
}

fn sanitize_bundle_file_name(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 160
        || value.contains('/')
        || value.contains('\\')
        || value.contains(':')
        || value.chars().any(char::is_control)
    {
        return None;
    }
    Some(value.to_string())
}

fn validate_rule_pack_manifest(manifest: &RulePackManifest) -> Result<(), String> {
    validate_rule_pack_text(&manifest.version, "rule pack version", 1, 80)?;
    validate_rule_pack_channel(&manifest.channel)?;
    if manifest.rules.is_empty() {
        return Err("Rule pack manifest must include at least one rule".to_string());
    }
    if manifest.rules.len() > 5000 {
        return Err("Rule pack manifest contains too many rules".to_string());
    }

    let mut seen = std::collections::BTreeSet::new();
    for rule in &manifest.rules {
        validate_rule_pack_text(&rule.id, "rule id", 3, 160)?;
        if rule.id.chars().any(char::is_whitespace) {
            return Err("Rule id must not contain whitespace".to_string());
        }
        if !seen.insert(rule.id.clone()) {
            return Err(format!("Duplicate rule id in manifest: {}", rule.id));
        }
        if let Some(severity) = &rule.severity {
            match severity.as_str() {
                "critical" | "high" | "medium" | "low" | "info" => {}
                _ => return Err(format!("Unsupported rule severity: {severity}")),
            }
        }
    }
    Ok(())
}

fn validate_rule_pack_update_feed(feed: &RulePackUpdateFeed) -> Result<(), String> {
    validate_rule_pack_text(&feed.latest_version, "rule pack latest version", 1, 80)?;
    validate_rule_pack_channel(&feed.channel)?;
    validate_expected_sha256(Some(&feed.manifest_sha256), &feed.manifest_sha256)?;
    if let Some(manifest_url) = &feed.manifest_url {
        let parsed = Url::parse(manifest_url).map_err(|_| "Invalid rule pack manifest URL")?;
        if parsed.scheme() != "https" {
            return Err("Rule pack manifest URL must use https".to_string());
        }
    }
    if let Some(minimum_app_version) = &feed.minimum_app_version {
        validate_rule_pack_text(minimum_app_version, "minimum app version", 1, 80)?;
    }
    Ok(())
}

fn verify_rule_pack_feed_signature(
    feed: &RulePackUpdateFeed,
    public_key_hex: &str,
) -> Result<(), String> {
    let public_key_bytes = decode_fixed_hex(public_key_hex, 32)
        .map_err(|_| "Rule pack feed public key must be 64 hexadecimal characters".to_string())?;
    let signature_hex = feed
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "Rule pack feed signature is required when a public key is provided".to_string()
        })?;
    let signature_bytes = decode_fixed_hex(signature_hex, 64)
        .map_err(|_| "Rule pack feed signature must be 128 hexadecimal characters".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(
        public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Rule pack feed public key must decode to 32 bytes".to_string())?,
    )
    .map_err(|_| "Rule pack feed public key is not a valid Ed25519 key".to_string())?;
    let signature = Signature::from_bytes(
        signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Rule pack feed signature must decode to 64 bytes".to_string())?,
    );
    verifying_key
        .verify(
            rule_pack_feed_signature_payload(feed).as_bytes(),
            &signature,
        )
        .map_err(|_| "Rule pack feed signature verification failed".to_string())
}

fn verify_detached_rule_pack_signature(
    payload: &[u8],
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<(), String> {
    let public_key_bytes = decode_fixed_hex(public_key_hex, 32)
        .map_err(|_| "Rule pack bundle public key must be 64 hexadecimal characters".to_string())?;
    let signature_bytes = decode_fixed_hex(signature_hex, 64)
        .map_err(|_| "Rule pack bundle signature must be 128 hexadecimal characters".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(
        public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Rule pack bundle public key must decode to 32 bytes".to_string())?,
    )
    .map_err(|_| "Rule pack bundle public key is not a valid Ed25519 key".to_string())?;
    let signature = Signature::from_bytes(
        signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Rule pack bundle signature must decode to 64 bytes".to_string())?,
    );
    verifying_key
        .verify(payload, &signature)
        .map_err(|_| "Rule pack bundle signature verification failed".to_string())
}

fn rule_pack_feed_signature_payload(feed: &RulePackUpdateFeed) -> String {
    format!(
        "latest_version={}\nchannel={}\nmanifest_sha256={}\nmanifest_url={}\npublished_at={}\nminimum_app_version={}\n",
        feed.latest_version.trim(),
        feed.channel.trim(),
        feed.manifest_sha256.trim(),
        feed.manifest_url.as_deref().map(str::trim).unwrap_or_default(),
        feed.published_at.as_deref().map(str::trim).unwrap_or_default(),
        feed.minimum_app_version.as_deref().map(str::trim).unwrap_or_default()
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

fn json_without_bom(document: &str) -> &str {
    document.trim_start_matches('\u{feff}')
}

fn validate_rule_pack_channel(channel: &str) -> Result<(), String> {
    match channel.trim() {
        "built-in" | "community" | "pro" | "team" | "enterprise" | "local" => Ok(()),
        _ => Err("Unsupported rule pack channel".to_string()),
    }
}

fn validate_rule_pack_text(
    value: &str,
    field_name: &str,
    min_len: usize,
    max_len: usize,
) -> Result<(), String> {
    let value = value.trim();
    if value.len() < min_len || value.len() > max_len || value.chars().any(char::is_control) {
        Err(format!("Invalid {field_name}"))
    } else {
        Ok(())
    }
}

fn validate_expected_sha256(expected: Option<&str>, actual: &str) -> Result<(), String> {
    let Some(expected) = expected.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    if expected.len() != 64
        || !expected
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err("Expected manifest SHA-256 must be 64 hexadecimal characters".to_string());
    }
    if !expected.eq_ignore_ascii_case(actual) {
        return Err("Rule pack manifest SHA-256 does not match the expected value".to_string());
    }
    Ok(())
}

fn ensure_rule_pack_channel_allowed(
    state: &State<'_, AppState>,
    channel: &str,
) -> Result<(), String> {
    if let Some(blocked_reason) = rule_pack_channel_block_reason(state, channel)? {
        return Err(blocked_reason);
    }
    Ok(())
}

fn rule_pack_channel_block_reason(
    _state: &State<'_, AppState>,
    channel: &str,
) -> Result<Option<String>, String> {
    Ok(if rule_pack_channel_supported(channel.trim()) {
        None
    } else {
        Some("Unsupported rule pack channel".to_string())
    })
}

fn rule_pack_update_available(current: &str, latest: &str) -> bool {
    let current = current.trim();
    let latest = latest.trim();
    !latest.is_empty() && latest != current && latest > current
}

fn rule_pack_status_from_manifest(
    app_data_dir: &Path,
    manifest: &RulePackManifest,
    source: &str,
    imported_at: Option<String>,
    manifest_sha256: Option<String>,
    bundle_metadata: Option<&RulePackBundleMetadata>,
) -> RulePackStatus {
    RulePackStatus {
        version: manifest.version.trim().to_string(),
        channel: manifest.channel.trim().to_string(),
        source: source.to_string(),
        rule_count: manifest.rules.len() as u32,
        enabled_rule_count: manifest
            .rules
            .iter()
            .filter(|rule| rule.enabled != Some(false))
            .count() as u32,
        disabled_rule_count: manifest
            .rules
            .iter()
            .filter(|rule| rule.enabled == Some(false))
            .count() as u32,
        published_at: manifest.published_at.clone(),
        imported_at: imported_at
            .or_else(|| bundle_metadata.map(|metadata| metadata.imported_at.clone())),
        manifest_sha256,
        bundle_sha256: bundle_metadata.map(|metadata| metadata.bundle_sha256.clone()),
        bundle_size_bytes: bundle_metadata.map(|metadata| metadata.bundle_size_bytes),
        bundle_file_name: bundle_metadata.and_then(|metadata| metadata.bundle_file_name.clone()),
        rollback_available: app_data_dir
            .join("rules")
            .join("manifest.previous.json")
            .exists(),
    }
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn write_report_export_audit(
    state: &State<'_, AppState>,
    format: ReportExportFormat,
    input: &RecordReportExportCommand,
    artifact: &ReportArtifactRecord,
) -> Result<(), String> {
    let metadata_json_redacted = serde_json::json!({
        "format": format.label(),
        "finding_count": input.finding_count,
        "artifact_file_name": &artifact.file_name,
        "artifact_relative_path": &artifact.relative_path,
        "artifact_size_bytes": artifact.size_bytes,
        "artifact_sha256": &artifact.sha256,
    })
    .to_string();

    create_audit_log(
        &state.app_data_dir,
        &state.database_path,
        CreateAuditLogInput {
            actor_user_id: Some("local-user".to_string()),
            action: "report.generated".to_string(),
            entity_type: "report".to_string(),
            entity_id: format.label().to_string(),
            severity: "info".to_string(),
            metadata_json_redacted,
        },
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn write_report_cleanup_audit(
    state: &State<'_, AppState>,
    older_than_days: Option<u64>,
    result: &CleanupReportArtifactsResult,
) -> Result<(), String> {
    write_report_cleanup_audit_paths(
        &state.app_data_dir,
        &state.database_path,
        older_than_days,
        result,
        false,
    )
}

fn write_report_cleanup_audit_paths(
    app_data_dir: &Path,
    database_path: &Path,
    older_than_days: Option<u64>,
    result: &CleanupReportArtifactsResult,
    scheduled: bool,
) -> Result<(), String> {
    let metadata_json_redacted = serde_json::json!({
        "older_than_days": older_than_days,
        "deleted_count": result.deleted_count,
        "deleted_bytes": result.deleted_bytes,
        "scheduled": scheduled,
    })
    .to_string();

    create_audit_log(
        app_data_dir,
        database_path,
        CreateAuditLogInput {
            actor_user_id: Some(if scheduled {
                "local-system".to_string()
            } else {
                "local-user".to_string()
            }),
            action: "report.artifacts_cleaned".to_string(),
            entity_type: "report_artifacts".to_string(),
            entity_id: "reports".to_string(),
            severity: "info".to_string(),
            metadata_json_redacted,
        },
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn write_support_diagnostics_audit(
    state: &State<'_, AppState>,
    result: &SupportDiagnosticsResult,
) -> Result<(), String> {
    let metadata_json_redacted = serde_json::json!({
        "artifact_file_name": &result.file_name,
        "artifact_relative_path": &result.relative_path,
        "artifact_size_bytes": result.size_bytes,
        "artifact_sha256": &result.sha256,
    })
    .to_string();

    create_audit_log(
        &state.app_data_dir,
        &state.database_path,
        CreateAuditLogInput {
            actor_user_id: Some("local-user".to_string()),
            action: "support.diagnostics_generated".to_string(),
            entity_type: "support_diagnostics".to_string(),
            entity_id: result.generated_at.clone(),
            severity: "info".to_string(),
            metadata_json_redacted,
        },
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn write_rule_pack_import_audit(
    state: &State<'_, AppState>,
    status: &RulePackStatus,
) -> Result<(), String> {
    let metadata_json_redacted = serde_json::json!({
        "version": &status.version,
        "channel": &status.channel,
        "source": &status.source,
        "rule_count": status.rule_count,
        "enabled_rule_count": status.enabled_rule_count,
        "disabled_rule_count": status.disabled_rule_count,
        "manifest_sha256": &status.manifest_sha256,
        "bundle_sha256": &status.bundle_sha256,
        "bundle_size_bytes": status.bundle_size_bytes,
        "bundle_file_name_present": status.bundle_file_name.is_some(),
    })
    .to_string();

    create_audit_log(
        &state.app_data_dir,
        &state.database_path,
        CreateAuditLogInput {
            actor_user_id: Some("local-user".to_string()),
            action: "rule_pack.manifest_imported".to_string(),
            entity_type: "rule_pack".to_string(),
            entity_id: status.version.clone(),
            severity: "info".to_string(),
            metadata_json_redacted,
        },
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn write_rule_pack_rollback_audit(
    state: &State<'_, AppState>,
    status: &RulePackStatus,
) -> Result<(), String> {
    let metadata_json_redacted = serde_json::json!({
        "version": &status.version,
        "channel": &status.channel,
        "rule_count": status.rule_count,
        "enabled_rule_count": status.enabled_rule_count,
        "disabled_rule_count": status.disabled_rule_count,
        "manifest_sha256": &status.manifest_sha256,
    })
    .to_string();

    create_audit_log(
        &state.app_data_dir,
        &state.database_path,
        CreateAuditLogInput {
            actor_user_id: Some("local-user".to_string()),
            action: "rule_pack.manifest_rolled_back".to_string(),
            entity_type: "rule_pack".to_string(),
            entity_id: status.version.clone(),
            severity: "info".to_string(),
            metadata_json_redacted,
        },
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn write_rule_pack_feed_check_audit(
    state: &State<'_, AppState>,
    status: &RulePackUpdateFeedStatus,
) -> Result<(), String> {
    let metadata_json_redacted = serde_json::json!({
        "current_version": &status.current_version,
        "latest_version": &status.latest_version,
        "channel": &status.channel,
        "update_available": status.update_available,
        "entitlement_allowed": status.entitlement_allowed,
        "blocked_reason": &status.blocked_reason,
        "manifest_sha256": &status.manifest_sha256,
        "manifest_url_present": status.manifest_url.is_some(),
        "signature_verified": status.signature_verified,
    })
    .to_string();

    create_audit_log(
        &state.app_data_dir,
        &state.database_path,
        CreateAuditLogInput {
            actor_user_id: Some("local-user".to_string()),
            action: "rule_pack.feed_checked".to_string(),
            entity_type: "rule_pack".to_string(),
            entity_id: status.latest_version.clone(),
            severity: "info".to_string(),
            metadata_json_redacted,
        },
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn write_endpoint_import_audit(
    state: &State<'_, AppState>,
    target_id: &str,
    source: &str,
    endpoint_count: usize,
) -> Result<(), String> {
    let metadata_json_redacted = serde_json::json!({
        "source": source,
        "endpoint_count": endpoint_count,
    })
    .to_string();

    create_audit_log(
        &state.app_data_dir,
        &state.database_path,
        CreateAuditLogInput {
            actor_user_id: Some("local-user".to_string()),
            action: "target.endpoints_replaced".to_string(),
            entity_type: "target".to_string(),
            entity_id: target_id.to_string(),
            severity: "info".to_string(),
            metadata_json_redacted,
        },
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn write_finding_status_audit(
    state: &State<'_, AppState>,
    previous: Option<&FindingRecord>,
    updated: &FindingRecord,
    requested_status: &str,
) -> Result<(), String> {
    let metadata_json_redacted = serde_json::json!({
        "previous_status": previous.map(|finding| finding.status.as_str()),
        "requested_status": requested_status,
        "new_status": updated.status,
        "severity": updated.severity,
        "title": updated.title,
    })
    .to_string();

    create_audit_log(
        &state.app_data_dir,
        &state.database_path,
        CreateAuditLogInput {
            actor_user_id: Some("local-user".to_string()),
            action: "finding.status_changed".to_string(),
            entity_type: "finding".to_string(),
            entity_id: updated.id.clone(),
            severity: "info".to_string(),
            metadata_json_redacted,
        },
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn write_ai_fix_guide_audit(
    state: &State<'_, AppState>,
    action: &str,
    severity: &str,
    provider: &str,
    account: &str,
    finding_id: &str,
    error: Option<&str>,
) -> Result<(), String> {
    let account = account.trim();
    let metadata_json_redacted = serde_json::json!({
        "provider": provider,
        "account_present": !account.is_empty(),
        "account_hash": if account.is_empty() { None } else { Some(short_sha256(account.as_bytes())) },
        "error": error.map(redact_audit_error),
    })
    .to_string();

    create_audit_log(
        &state.app_data_dir,
        &state.database_path,
        CreateAuditLogInput {
            actor_user_id: Some("local-user".to_string()),
            action: action.to_string(),
            entity_type: "finding".to_string(),
            entity_id: finding_id.to_string(),
            severity: severity.to_string(),
            metadata_json_redacted,
        },
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn redact_audit_error(value: &str) -> String {
    let redacted = value
        .split_whitespace()
        .map(|part| {
            let lower = part.to_ascii_lowercase();
            if lower.starts_with("sk-")
                || lower.contains("api_key=")
                || lower.contains("apikey=")
                || lower.contains("access_token=")
                || lower.contains("refresh_token=")
                || lower.contains("token=")
                || lower.contains("password=")
                || lower.contains("secret=")
                || lower.contains("secret_key=")
                || lower.contains("private_key=")
                || lower.contains("authorization:")
                || lower.contains("set-cookie:")
                || lower.contains("cookie:")
                || lower.contains("bearer")
            {
                "[REDACTED]"
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    redacted.chars().take(512).collect()
}

fn short_sha256(bytes: &[u8]) -> String {
    sha256_hex(bytes).chars().take(16).collect()
}

fn advance_next_scan_paths(
    app_data_dir: &Path,
    database_path: &Path,
) -> Result<Option<ScanRecord>, String> {
    let scans = list_scans(app_data_dir, database_path).map_err(|error| error.to_string())?;
    let Some(scan) = scans
        .into_iter()
        .rev()
        .find(|scan| !matches!(scan.phase.as_str(), "completed" | "failed" | "canceled"))
    else {
        return Ok(None);
    };

    let targets =
        list_targets(app_data_dir, database_path, None).map_err(|error| error.to_string())?;
    let target = targets
        .into_iter()
        .find(|target| target.id == scan.target_id)
        .ok_or_else(|| "scan target is not active".to_string())?;
    let (phase, status_message) = next_scan_phase(app_data_dir, database_path, &scan, &target);
    let updated = update_scan_phase(
        app_data_dir,
        database_path,
        UpdateScanPhaseInput {
            id: scan.id,
            phase,
            status_message,
        },
    )
    .map_err(|error| error.to_string())?;
    Ok(Some(updated))
}

fn next_scan_phase(
    app_data_dir: &Path,
    database_path: &Path,
    scan: &ScanRecord,
    target: &TargetRecord,
) -> (String, String) {
    match scan.phase.as_str() {
        "queued" => (
            "validating".to_string(),
            "Scope validation started by Local Engine Service".to_string(),
        ),
        "validating" => {
            match passive_probe_targets(app_data_dir, database_path, target, &scan.profile) {
                Ok(probe_targets) => match probe_targets
                    .iter()
                    .map(build_passive_probe)
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(requests) => (
                        "crawling".to_string(),
                        truncate_status(format!(
                            "Prepared {} safe passive probes; first probe {} {}",
                            requests.len(),
                            requests[0].method,
                            requests[0].url
                        )),
                    ),
                    Err(error) => (
                        "failed".to_string(),
                        truncate_status(format!("Scope validation failed: {}", error)),
                    ),
                },
                Err(error) => (
                    "failed".to_string(),
                    truncate_status(format!("Scope validation failed: {}", error)),
                ),
            }
        }
        "crawling" => {
            let client = UreqHttpProbeClient;
            let probe_targets =
                match passive_probe_targets(app_data_dir, database_path, target, &scan.profile) {
                    Ok(probe_targets) => probe_targets,
                    Err(error) => return ("failed".to_string(), truncate_status(error)),
                };
            let probe_count = probe_targets.len();
            let mut finding_count = 0usize;
            for probe_target in probe_targets {
                let probe_method = probe_target.method.clone();
                match run_passive_probe(&probe_target, &client) {
                    Ok((response, findings)) => {
                        match store_scan_findings(
                            app_data_dir,
                            database_path,
                            scan,
                            probe_method.as_deref(),
                            &response.final_url,
                            Some(response.status_code),
                            findings,
                        ) {
                            Ok(saved_count) => finding_count += saved_count,
                            Err(error) => {
                                return ("failed".to_string(), truncate_status(error));
                            }
                        }
                    }
                    Err(error) => {
                        return (
                            "failed".to_string(),
                            truncate_status(format!("HTTP probe failed: {}", error)),
                        )
                    }
                }
            }
            (
                "analyzing".to_string(),
                truncate_status(format!(
                    "{} HTTP probes completed, {} findings saved",
                    probe_count, finding_count
                )),
            )
        }
        "analyzing" => {
            if scan.profile != "safe" {
                return (
                    "reporting".to_string(),
                    "Passive analyzer completed".to_string(),
                );
            }

            let client = UreqHttpProbeClient;
            let active_targets = match active_verify_targets(app_data_dir, database_path, target) {
                Ok(active_targets) => active_targets,
                Err(error) => return ("failed".to_string(), truncate_status(error)),
            };
            let active_count = active_targets.len();
            let mut finding_count = 0usize;
            for active_target in active_targets {
                match run_safe_active_verifiers(&active_target, &client) {
                    Ok(findings) => {
                        match store_scan_findings(
                            app_data_dir,
                            database_path,
                            scan,
                            Some("GET"),
                            &active_target.url,
                            None,
                            findings,
                        ) {
                            Ok(saved_count) => finding_count += saved_count,
                            Err(error) => {
                                return ("failed".to_string(), truncate_status(error));
                            }
                        }
                    }
                    Err(error) => {
                        return (
                            "failed".to_string(),
                            truncate_status(format!("Safe active verification failed: {}", error)),
                        )
                    }
                }
            }

            (
                "reporting".to_string(),
                truncate_status(format!(
                    "{} safe active verifications completed, {} findings saved",
                    active_count, finding_count
                )),
            )
        }
        "reporting" => ("completed".to_string(), "Scan completed".to_string()),
        _ => (
            "failed".to_string(),
            "Scan entered an invalid phase".to_string(),
        ),
    }
}

fn scan_target(target: &TargetRecord) -> ScanTarget {
    scan_target_with_method(target, target.id.clone(), None, target.url.clone())
}

fn passive_probe_targets(
    app_data_dir: &Path,
    database_path: &Path,
    target: &TargetRecord,
    profile: &str,
) -> Result<Vec<ScanTarget>, String> {
    let endpoints = list_target_endpoints(app_data_dir, database_path, Some(target.id.clone()))
        .map_err(|error| error.to_string())?;
    let mut probe_targets = endpoints
        .into_iter()
        .filter(|endpoint| matches!(endpoint.method.as_str(), "GET" | "HEAD"))
        .map(|endpoint| {
            scan_target_with_method(target, endpoint.id, Some(endpoint.method), endpoint.url)
        })
        .collect::<Vec<_>>();

    if probe_targets.is_empty() {
        probe_targets.push(scan_target(target));
    }
    if profile == "surface" {
        append_unique_scan_targets(
            &mut probe_targets,
            surface_probe_targets(&scan_target(target)).map_err(|error| error.to_string())?,
        );
    }
    Ok(probe_targets)
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

fn active_verify_targets(
    app_data_dir: &Path,
    database_path: &Path,
    target: &TargetRecord,
) -> Result<Vec<ScanTarget>, String> {
    let endpoints = list_target_endpoints(app_data_dir, database_path, Some(target.id.clone()))
        .map_err(|error| error.to_string())?;
    let mut verify_targets = endpoints
        .into_iter()
        .filter(|endpoint| endpoint.method == "GET" && url_has_query_parameters(&endpoint.url))
        .map(|endpoint| {
            scan_target_with_method(target, endpoint.id, Some("GET".to_string()), endpoint.url)
        })
        .collect::<Vec<_>>();

    if verify_targets.is_empty() && url_has_query_parameters(&target.url) {
        verify_targets.push(scan_target_with_method(
            target,
            target.id.clone(),
            Some("GET".to_string()),
            target.url.clone(),
        ));
    }
    Ok(verify_targets)
}

fn url_has_query_parameters(url: &str) -> bool {
    Url::parse(url)
        .map(|url| url.query_pairs().next().is_some())
        .unwrap_or(false)
}

fn scan_target_with_method(
    target: &TargetRecord,
    id: String,
    method: Option<String>,
    url: String,
) -> ScanTarget {
    ScanTarget {
        id,
        method,
        url,
        approval_note: target.approval_note.clone(),
        allow_private_network: target.allow_private_network,
    }
}

fn crawl_candidate_source_label(source: CrawlCandidateSource) -> &'static str {
    match source {
        CrawlCandidateSource::AnchorHref => "anchor_href",
        CrawlCandidateSource::FormAction => "form_action",
        CrawlCandidateSource::ScriptSrc => "script_src",
        CrawlCandidateSource::LinkHref => "link_href",
        CrawlCandidateSource::BrowserRoute => "browser_route",
        CrawlCandidateSource::BrowserRequest => "browser_request",
    }
}

fn store_scan_findings(
    app_data_dir: &Path,
    database_path: &Path,
    scan: &ScanRecord,
    method: Option<&str>,
    endpoint: &str,
    status_code: Option<u16>,
    findings: Vec<PassiveFinding>,
) -> Result<usize, String> {
    let runtime_rule_pack = read_runtime_rule_pack(app_data_dir)?;
    let mut saved_count = 0usize;
    for finding in findings {
        let PassiveFinding {
            rule_id,
            title,
            severity,
            evidence,
            recommendation,
        } = finding;
        if runtime_rule_pack
            .as_ref()
            .map(|rule_pack| rule_pack.disabled_rules.contains(&rule_id))
            .unwrap_or(false)
        {
            continue;
        }
        let (native_metadata, evidence_summary) = split_native_evidence(&evidence);
        let source = native_metadata
            .as_ref()
            .and_then(|metadata| metadata.get("source"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| finding_source(&rule_id));
        let parameter_name = native_metadata
            .as_ref()
            .and_then(|metadata| metadata.get("parameter_name"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .or_else(|| active_evidence_parameter_name(&rule_id, &evidence));
        let requires_manual_confirmation = native_metadata
            .as_ref()
            .and_then(|metadata| metadata.get("requires_manual_confirmation"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let native_fingerprint = native_metadata
            .as_ref()
            .and_then(|metadata| metadata.get("fingerprint"))
            .and_then(serde_json::Value::as_str);
        let native_evidence_refs = native_metadata
            .as_ref()
            .and_then(|metadata| metadata.get("evidence_refs"))
            .cloned();
        let default_severity = severity_label(severity).to_string();
        let applied_severity = runtime_rule_pack
            .as_ref()
            .and_then(|rule_pack| rule_pack.severities.get(&rule_id))
            .cloned()
            .unwrap_or_else(|| default_severity.clone());
        let rule_pack_metadata = runtime_rule_pack.as_ref().map(|rule_pack| {
            serde_json::json!({
                "version": &rule_pack.version,
                "channel": &rule_pack.channel,
                "manifest_sha256": &rule_pack.manifest_sha256,
                "severity_overridden": applied_severity != default_severity,
            })
        });
        let evidence_json = serde_json::json!({
            "rule_id": rule_id.clone(),
            "source": source,
            "evidence": evidence_summary,
            "http_status": status_code,
            "native_fingerprint": native_fingerprint,
            "native_evidence_refs": native_evidence_refs,
            "requires_manual_confirmation": requires_manual_confirmation,
            "rule_pack": rule_pack_metadata,
            "reproduction": {
                "method": method.unwrap_or("GET"),
                "url": endpoint,
                "parameter": parameter_name.clone(),
                "safe": true,
                "scope": "explicitly approved target only"
            }
        })
        .to_string();
        let triage = triage_rule(&rule_id);
        let dedupe_endpoint = dedupe_endpoint_fingerprint(endpoint);
        let dedupe_key = Some(match parameter_name.as_deref() {
            Some(parameter_name) => format!("{}|{}|{}", rule_id, dedupe_endpoint, parameter_name),
            None => format!("{}|{}", rule_id, dedupe_endpoint),
        });
        create_finding(
            app_data_dir,
            database_path,
            CreateFindingInput {
                scan_id: scan.id.clone(),
                title,
                severity: applied_severity,
                confidence: triage.confidence.to_string(),
                endpoint: endpoint.to_string(),
                parameter_name,
                evidence_json,
                remediation: recommendation,
                cwe: triage.cwe.map(ToString::to_string),
                owasp_category: triage.owasp_category.map(ToString::to_string),
                dedupe_key,
            },
        )
        .map_err(|error| format!("Finding save failed: {}", error))?;
        saved_count += 1;
    }
    Ok(saved_count)
}

fn dedupe_endpoint_fingerprint(endpoint: &str) -> String {
    let Ok(mut url) = Url::parse(endpoint.trim()) else {
        return endpoint.trim().to_string();
    };

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

    url.to_string()
}

fn finding_source(rule_id: &str) -> &'static str {
    if rule_id.starts_with("active.") {
        "active"
    } else if rule_id.starts_with("surface.") {
        "surface"
    } else {
        "passive"
    }
}

fn severity_label(severity: FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::Info => "info",
        FindingSeverity::Low => "low",
        FindingSeverity::Medium => "medium",
        FindingSeverity::High => "high",
    }
}

fn active_evidence_parameter_name(rule_id: &str, evidence: &str) -> Option<String> {
    if !rule_id.starts_with("active.") {
        return None;
    }
    let marker = "query parameter '";
    let start = evidence.find(marker)? + marker.len();
    let end = evidence[start..].find('\'')? + start;
    let parameter = evidence[start..end].trim();
    (!parameter.is_empty()).then(|| parameter.to_string())
}

fn truncate_status(value: String) -> String {
    const MAX_STATUS_LEN: usize = 240;
    if value.len() <= MAX_STATUS_LEN {
        return value;
    }
    let mut truncated = value;
    truncated.truncate(MAX_STATUS_LEN);
    truncated
}

fn recover_interrupted_scans_on_startup(app_data_dir: &Path, database_path: &Path) {
    match recover_interrupted_scans(app_data_dir, database_path) {
        Ok(recovered) if recovered.is_empty() => {}
        Ok(recovered) => {
            let metadata_json_redacted = serde_json::json!({
                "recovered_scan_count": recovered.len(),
                "restored_phase": "queued",
                "auto_started": false,
            })
            .to_string();
            if let Err(error) = create_audit_log(
                app_data_dir,
                database_path,
                CreateAuditLogInput {
                    actor_user_id: Some("local-system".to_string()),
                    action: "scan.recovered_after_restart".to_string(),
                    entity_type: "scan".to_string(),
                    entity_id: "interrupted-scans".to_string(),
                    severity: "info".to_string(),
                    metadata_json_redacted,
                },
            ) {
                eprintln!("scan recovery audit write failed: {error}");
            }
            eprintln!(
                "recovered {} interrupted scans after restart",
                recovered.len()
            );
        }
        Err(error) => eprintln!("scan recovery after restart failed: {error}"),
    }
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let app_data_dir = app
                .path()
                .app_data_dir()
                .map_err(|error| Box::<dyn std::error::Error>::from(error))?;
            let database_path = app_data_dir.join("aegis-webshield-ai.sqlite3");
            let engine = LocalEngineService::new(env!("CARGO_PKG_VERSION"), MAX_CONCURRENT_SCANS);
            let scan_runner_enabled = Arc::new(AtomicBool::new(false));
            if let Err(error) = run_scheduled_report_artifact_cleanup(&app_data_dir, &database_path)
            {
                eprintln!("scheduled report artifact cleanup failed: {error}");
            }
            recover_interrupted_scans_on_startup(&app_data_dir, &database_path);
            spawn_scan_runner(
                app_data_dir.clone(),
                database_path.clone(),
                Arc::clone(&scan_runner_enabled),
            );

            app.manage(AppState {
                local_engine: Mutex::new(engine),
                app_data_dir,
                database_path,
                scan_runner_enabled,
                secret_store: PlatformSecretStore::default(),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            local_engine_status,
            start_local_engine,
            stop_local_engine,
            save_ai_api_key,
            delete_ai_api_key,
            generate_ai_fix_guide,
            crawl_html_document,
            crawl_browser_observation,
            crawl_approved_url,
            import_openapi_document,
            import_url_seed_document,
            local_rule_pack_status,
            import_rule_pack_manifest,
            import_rule_pack_bundle,
            rollback_rule_pack_manifest,
            check_rule_pack_update_feed,
            local_storage_status,
            local_usage_status,
            record_report_export,
            cleanup_report_artifacts,
            collect_support_diagnostics,
            list_local_projects,
            create_local_project,
            update_local_project,
            deactivate_local_project,
            list_local_targets,
            list_local_target_endpoints,
            replace_openapi_endpoint_candidates,
            replace_url_seed_endpoint_candidates,
            replace_html_crawl_endpoint_candidates,
            create_local_target,
            update_local_target,
            deactivate_local_target,
            list_local_scans,
            list_local_findings,
            local_scan_baseline_diff,
            list_local_audit_logs,
            update_local_finding_status,
            create_local_scan,
            advance_local_scan,
            run_local_scan_queue,
            cancel_local_scan,
            set_scan_runner_enabled,
            scan_runner_status
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Aegis WebShield AI");
}

fn spawn_scan_runner(app_data_dir: PathBuf, database_path: PathBuf, enabled: Arc<AtomicBool>) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(1400));
        if !enabled.load(Ordering::Relaxed) {
            continue;
        }

        match advance_next_scan_paths(&app_data_dir, &database_path) {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => enabled.store(false, Ordering::Relaxed),
        }
    });
}
