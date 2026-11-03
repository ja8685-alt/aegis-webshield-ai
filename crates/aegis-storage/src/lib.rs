use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_initial_local_store",
        include_str!("../../../src-tauri/migrations/0001_initial_local_store.sql"),
    ),
    (
        "0002_target_endpoints",
        include_str!("../../../src-tauri/migrations/0002_target_endpoints.sql"),
    ),
    (
        "0003_findings_dedupe_key",
        include_str!("../../../src-tauri/migrations/0003_findings_dedupe_key.sql"),
    ),
];
const LOCAL_WORKSPACE_ID: &str = "local-workspace";
const MAX_NAME_LEN: usize = 120;
const MAX_DESCRIPTION_LEN: usize = 500;
const MAX_URL_LEN: usize = 2048;
const MAX_APPROVAL_NOTE_LEN: usize = 1000;
const MAX_FINDING_TITLE_LEN: usize = 240;
const MAX_FINDING_ENDPOINT_LEN: usize = 2048;
const MAX_FINDING_EVIDENCE_LEN: usize = 8000;
const MAX_FINDING_REMEDIATION_LEN: usize = 1200;
const MAX_FINDING_DEDUPE_KEY_LEN: usize = 4096;
const MAX_AUDIT_FIELD_LEN: usize = 160;
const MAX_AUDIT_METADATA_LEN: usize = 4000;
const MAX_ENDPOINT_PATH_LEN: usize = 2048;
const MAX_ENDPOINT_METHOD_LEN: usize = 12;
const MAX_ENDPOINT_PARAMETERS_LEN: usize = 4000;
const MAX_TARGET_ENDPOINTS: usize = 5000;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage path is not inside the app data directory")]
    InvalidAppDataPath,
    #[error("failed to prepare storage directory")]
    Directory(#[from] std::io::Error),
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("sqlite operation failed")]
    Sqlite(#[from] rusqlite::Error),
}

#[derive(Debug, Clone, Serialize)]
pub struct LocalStorageSnapshot {
    pub database_path: String,
    pub applied_migrations: Vec<String>,
    pub workspace_count: u32,
    pub project_count: u32,
    pub target_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LocalUsageSnapshot {
    pub monthly_scans: u32,
    pub projects: u32,
    pub targets: u32,
    pub reports: u32,
    pub ai_fix_guides: u32,
    pub active_scans: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectRecord {
    pub id: String,
    pub name: String,
    pub description: String,
    pub status: String,
    pub target_count: u32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateProjectInput {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateProjectInput {
    pub id: String,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetRecord {
    pub id: String,
    pub project_id: String,
    pub target_type: String,
    pub name: String,
    pub url: String,
    pub approval_note: String,
    pub allow_private_network: bool,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateTargetInput {
    pub project_id: String,
    pub target_type: String,
    pub name: String,
    pub url: String,
    pub approval_note: String,
    pub allow_private_network: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateTargetInput {
    pub id: String,
    pub target_type: String,
    pub name: String,
    pub url: String,
    pub approval_note: String,
    pub allow_private_network: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetEndpointRecord {
    pub id: String,
    pub target_id: String,
    pub method: String,
    pub path: String,
    pub url: String,
    pub operation_id: Option<String>,
    pub parameters_json: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateTargetEndpointInput {
    pub method: String,
    pub path: String,
    pub url: String,
    pub operation_id: Option<String>,
    pub parameters_json: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReplaceTargetEndpointsInput {
    pub target_id: String,
    pub endpoints: Vec<CreateTargetEndpointInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanRecord {
    pub id: String,
    pub project_id: String,
    pub target_id: String,
    pub project_name: String,
    pub target_name: String,
    pub target_url: String,
    pub profile: String,
    pub phase: String,
    pub status_message: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateScanInput {
    pub project_id: String,
    pub target_id: String,
    pub profile: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateScanPhaseInput {
    pub id: String,
    pub phase: String,
    pub status_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingRecord {
    pub id: String,
    pub scan_id: String,
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub endpoint: String,
    pub parameter_name: Option<String>,
    pub status: String,
    pub evidence_json: String,
    pub remediation: String,
    pub cwe: Option<String>,
    pub owasp_category: Option<String>,
    pub dedupe_key: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BaselineDiffSummary {
    pub scan_id: String,
    pub baseline_scan_id: Option<String>,
    pub new_findings: Vec<FindingRecord>,
    pub recurring_findings: Vec<FindingRecord>,
    pub resolved_findings: Vec<FindingRecord>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateFindingInput {
    pub scan_id: String,
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub endpoint: String,
    pub parameter_name: Option<String>,
    pub evidence_json: String,
    pub remediation: String,
    pub cwe: Option<String>,
    pub owasp_category: Option<String>,
    pub dedupe_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateFindingStatusInput {
    pub id: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditLogRecord {
    pub id: String,
    pub actor_user_id: Option<String>,
    pub action: String,
    pub entity_type: String,
    pub entity_id: String,
    pub severity: String,
    pub metadata_json_redacted: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateAuditLogInput {
    pub actor_user_id: Option<String>,
    pub action: String,
    pub entity_type: String,
    pub entity_id: String,
    pub severity: String,
    pub metadata_json_redacted: String,
}

pub fn initialize_local_storage(
    app_data_dir: &Path,
    database_path: &Path,
) -> Result<LocalStorageSnapshot, StorageError> {
    ensure_inside_app_data_dir(app_data_dir, database_path)?;

    if let Some(parent) = database_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut connection = Connection::open(database_path)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    apply_migrations(&mut connection)?;
    seed_local_workspace(&connection)?;
    snapshot(&connection, database_path)
}

pub fn create_project(
    app_data_dir: &Path,
    database_path: &Path,
    input: CreateProjectInput,
) -> Result<ProjectRecord, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    let name = validate_text(input.name, "project name", 1, MAX_NAME_LEN)?;
    let description = validate_text(
        input.description,
        "project description",
        0,
        MAX_DESCRIPTION_LEN,
    )?;
    let id = format!("project-{}", Uuid::new_v4());

    connection.execute(
        "INSERT INTO projects (id, workspace_id, name, description, status, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, 'active', datetime('now'), datetime('now'))",
        params![id, LOCAL_WORKSPACE_ID, name, description],
    )?;

    get_project(&connection, &id)
}

pub fn list_projects(
    app_data_dir: &Path,
    database_path: &Path,
) -> Result<Vec<ProjectRecord>, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    read_projects(&connection)
}

pub fn update_project(
    app_data_dir: &Path,
    database_path: &Path,
    input: UpdateProjectInput,
) -> Result<ProjectRecord, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    ensure_project_exists(&connection, &input.id)?;
    let name = validate_text(input.name, "project name", 1, MAX_NAME_LEN)?;
    let description = validate_text(
        input.description,
        "project description",
        0,
        MAX_DESCRIPTION_LEN,
    )?;

    connection.execute(
        "UPDATE projects
        SET name = ?1, description = ?2, updated_at = datetime('now')
        WHERE id = ?3 AND status = 'active'",
        params![name, description, input.id],
    )?;

    get_project(&connection, &input.id)
}

pub fn deactivate_project(
    app_data_dir: &Path,
    database_path: &Path,
    project_id: String,
) -> Result<(), StorageError> {
    let mut connection = open_initialized_connection(app_data_dir, database_path)?;
    ensure_project_exists(&connection, &project_id)?;
    let transaction = connection.transaction()?;

    transaction.execute(
        "UPDATE targets
        SET status = 'inactive', updated_at = datetime('now')
        WHERE project_id = ?1 AND status = 'active'",
        params![project_id],
    )?;
    transaction.execute(
        "UPDATE projects
        SET status = 'inactive', updated_at = datetime('now')
        WHERE id = ?1 AND status = 'active'",
        params![project_id],
    )?;

    transaction.commit()?;
    Ok(())
}

pub fn create_target(
    app_data_dir: &Path,
    database_path: &Path,
    input: CreateTargetInput,
) -> Result<TargetRecord, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    ensure_project_exists(&connection, &input.project_id)?;

    let target_type = validate_target_type(input.target_type)?;
    let name = validate_text(input.name, "target name", 1, MAX_NAME_LEN)?;
    let url = validate_url(input.url)?;
    let approval_note = validate_text(
        input.approval_note,
        "approval note",
        1,
        MAX_APPROVAL_NOTE_LEN,
    )?;
    let id = format!("target-{}", Uuid::new_v4());
    let allow_private_network = i64::from(input.allow_private_network);

    connection.execute(
        "INSERT INTO targets (
            id, project_id, target_type, name, url, approval_note,
            allow_private_network, status, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', datetime('now'), datetime('now'))",
        params![
            id,
            input.project_id,
            target_type,
            name,
            url,
            approval_note,
            allow_private_network
        ],
    )?;

    get_target(&connection, &id)
}

pub fn list_targets(
    app_data_dir: &Path,
    database_path: &Path,
    project_id: Option<String>,
) -> Result<Vec<TargetRecord>, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;

    if let Some(project_id) = project_id {
        ensure_project_exists(&connection, &project_id)?;
        read_targets_for_project(&connection, &project_id)
    } else {
        read_targets(&connection)
    }
}

pub fn update_target(
    app_data_dir: &Path,
    database_path: &Path,
    input: UpdateTargetInput,
) -> Result<TargetRecord, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    ensure_target_exists(&connection, &input.id)?;

    let target_type = validate_target_type(input.target_type)?;
    let name = validate_text(input.name, "target name", 1, MAX_NAME_LEN)?;
    let url = validate_url(input.url)?;
    let approval_note = validate_text(
        input.approval_note,
        "approval note",
        1,
        MAX_APPROVAL_NOTE_LEN,
    )?;
    let allow_private_network = i64::from(input.allow_private_network);

    connection.execute(
        "UPDATE targets
        SET target_type = ?1, name = ?2, url = ?3, approval_note = ?4,
            allow_private_network = ?5, updated_at = datetime('now')
        WHERE id = ?6 AND status = 'active'",
        params![
            target_type,
            name,
            url,
            approval_note,
            allow_private_network,
            input.id
        ],
    )?;

    get_target(&connection, &input.id)
}

pub fn deactivate_target(
    app_data_dir: &Path,
    database_path: &Path,
    target_id: String,
) -> Result<(), StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    ensure_target_exists(&connection, &target_id)?;

    connection.execute(
        "UPDATE targets
        SET status = 'inactive', updated_at = datetime('now')
        WHERE id = ?1 AND status = 'active'",
        params![target_id],
    )?;
    Ok(())
}

pub fn replace_target_endpoints(
    app_data_dir: &Path,
    database_path: &Path,
    input: ReplaceTargetEndpointsInput,
) -> Result<Vec<TargetEndpointRecord>, StorageError> {
    let mut connection = open_initialized_connection(app_data_dir, database_path)?;
    ensure_target_exists(&connection, &input.target_id)?;
    if input.endpoints.len() > MAX_TARGET_ENDPOINTS {
        return Err(StorageError::InvalidInput("endpoint count"));
    }
    let transaction = connection.transaction()?;

    transaction.execute(
        "UPDATE target_endpoints
        SET status = 'inactive', updated_at = datetime('now')
        WHERE target_id = ?1 AND status = 'active'",
        params![input.target_id],
    )?;

    for endpoint in input.endpoints {
        let method = validate_endpoint_method(endpoint.method)?;
        let path = validate_text(endpoint.path, "endpoint path", 1, MAX_ENDPOINT_PATH_LEN)?;
        let url = validate_url(endpoint.url)?;
        let operation_id =
            validate_optional_text(endpoint.operation_id, "operation id", MAX_AUDIT_FIELD_LEN)?;
        let parameters_json = validate_text(
            endpoint.parameters_json,
            "endpoint parameters",
            2,
            MAX_ENDPOINT_PARAMETERS_LEN,
        )?;
        let id = format!("endpoint-{}", Uuid::new_v4());

        transaction.execute(
            "INSERT INTO target_endpoints (
                id, target_id, method, path, url, operation_id, parameters_json,
                status, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', datetime('now'), datetime('now'))
            ON CONFLICT(target_id, method, path) DO UPDATE SET
                url = excluded.url,
                operation_id = excluded.operation_id,
                parameters_json = excluded.parameters_json,
                status = 'active',
                updated_at = datetime('now')",
            params![
                id,
                input.target_id,
                method,
                path,
                url,
                operation_id,
                parameters_json
            ],
        )?;
    }

    transaction.commit()?;
    read_target_endpoints(
        &open_initialized_connection(app_data_dir, database_path)?,
        Some(&input.target_id),
    )
}

pub fn list_target_endpoints(
    app_data_dir: &Path,
    database_path: &Path,
    target_id: Option<String>,
) -> Result<Vec<TargetEndpointRecord>, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    if let Some(target_id) = target_id {
        ensure_target_exists(&connection, &target_id)?;
        read_target_endpoints(&connection, Some(&target_id))
    } else {
        read_target_endpoints(&connection, None)
    }
}

pub fn create_scan(
    app_data_dir: &Path,
    database_path: &Path,
    input: CreateScanInput,
) -> Result<ScanRecord, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    ensure_project_exists(&connection, &input.project_id)?;
    ensure_target_belongs_to_project(&connection, &input.target_id, &input.project_id)?;
    let profile = validate_scan_profile(input.profile)?;
    let id = format!("scan-{}", Uuid::new_v4());

    connection.execute(
        "INSERT INTO scans (
            id, project_id, target_id, profile, phase, status_message,
            started_at, finished_at, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, 'queued', 'Waiting for Local Engine Service', NULL, NULL, datetime('now'), datetime('now'))",
        params![id, input.project_id, input.target_id, profile],
    )?;

    get_scan(&connection, &id)
}

pub fn list_scans(
    app_data_dir: &Path,
    database_path: &Path,
) -> Result<Vec<ScanRecord>, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    read_scans(&connection)
}

pub fn recover_interrupted_scans(
    app_data_dir: &Path,
    database_path: &Path,
) -> Result<Vec<ScanRecord>, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    let mut statement = connection.prepare(
        "SELECT id FROM scans
        WHERE phase IN ('validating', 'crawling', 'analyzing', 'reporting')
        ORDER BY created_at ASC",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    let mut scan_ids = Vec::new();
    for row in rows {
        scan_ids.push(row?);
    }
    drop(statement);

    if scan_ids.is_empty() {
        return Ok(Vec::new());
    }

    connection.execute(
        "UPDATE scans
        SET phase = 'queued',
            status_message = 'Recovered after app restart; waiting for Local Engine Service',
            finished_at = NULL,
            updated_at = datetime('now')
        WHERE phase IN ('validating', 'crawling', 'analyzing', 'reporting')",
        [],
    )?;

    scan_ids
        .iter()
        .map(|scan_id| get_scan(&connection, scan_id))
        .collect()
}

pub fn local_usage_snapshot(
    app_data_dir: &Path,
    database_path: &Path,
) -> Result<LocalUsageSnapshot, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    Ok(LocalUsageSnapshot {
        monthly_scans: count_current_month_scans(&connection)?,
        projects: count_table(&connection, "projects")?,
        targets: count_table(&connection, "targets")?,
        reports: count_current_month_reports(&connection)?,
        ai_fix_guides: count_current_month_ai_fix_guides(&connection)?,
        active_scans: count_active_scans(&connection)?,
    })
}

pub fn update_scan_phase(
    app_data_dir: &Path,
    database_path: &Path,
    input: UpdateScanPhaseInput,
) -> Result<ScanRecord, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    ensure_scan_exists(&connection, &input.id)?;
    let phase = validate_scan_phase(input.phase)?;
    let status_message = validate_text(input.status_message, "scan status", 1, 240)?;
    let started_at_sql = if phase == "validating" {
        "COALESCE(started_at, datetime('now'))"
    } else {
        "started_at"
    };
    let finished_at_sql = if matches!(phase.as_str(), "completed" | "failed" | "canceled") {
        "COALESCE(finished_at, datetime('now'))"
    } else {
        "finished_at"
    };

    connection.execute(
        &format!(
            "UPDATE scans
            SET phase = ?1, status_message = ?2,
                started_at = {started_at_sql},
                finished_at = {finished_at_sql},
                updated_at = datetime('now')
            WHERE id = ?3"
        ),
        params![phase, status_message, input.id],
    )?;

    get_scan(&connection, &input.id)
}

pub fn cancel_scan(
    app_data_dir: &Path,
    database_path: &Path,
    scan_id: String,
) -> Result<ScanRecord, StorageError> {
    update_scan_phase(
        app_data_dir,
        database_path,
        UpdateScanPhaseInput {
            id: scan_id,
            phase: "canceled".to_string(),
            status_message: "Scan canceled by user".to_string(),
        },
    )
}

pub fn create_finding(
    app_data_dir: &Path,
    database_path: &Path,
    input: CreateFindingInput,
) -> Result<FindingRecord, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    ensure_scan_exists(&connection, &input.scan_id)?;
    let title = validate_text(input.title, "finding title", 1, MAX_FINDING_TITLE_LEN)?;
    let severity = validate_finding_severity(input.severity)?;
    let confidence = validate_finding_confidence(input.confidence)?;
    let endpoint = validate_text(
        input.endpoint,
        "finding endpoint",
        1,
        MAX_FINDING_ENDPOINT_LEN,
    )?;
    let parameter_name = validate_optional_text(input.parameter_name, "finding parameter", 120)?;
    let evidence_json = validate_text(
        input.evidence_json,
        "finding evidence",
        2,
        MAX_FINDING_EVIDENCE_LEN,
    )?;
    let remediation = validate_text(
        input.remediation,
        "finding remediation",
        0,
        MAX_FINDING_REMEDIATION_LEN,
    )?;
    let cwe = validate_optional_text(input.cwe, "finding cwe", 80)?;
    let owasp_category = validate_optional_text(input.owasp_category, "finding owasp", 120)?;
    let dedupe_key = validate_optional_text(
        input.dedupe_key,
        "finding dedupe key",
        MAX_FINDING_DEDUPE_KEY_LEN,
    )?;

    if let Some(existing_id) =
        existing_finding_by_dedupe_key(&connection, &input.scan_id, &dedupe_key)?
    {
        return get_finding(&connection, &existing_id);
    }
    let id = format!("finding-{}", Uuid::new_v4());

    connection.execute(
        "INSERT INTO findings (
            id, scan_id, title, severity, confidence, endpoint, parameter_name,
            status, evidence_json, remediation, cwe, owasp_category, dedupe_key, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'new', ?8, ?9, ?10, ?11, ?12, datetime('now'), datetime('now'))",
        params![
            id,
            input.scan_id,
            title,
            severity,
            confidence,
            endpoint,
            parameter_name,
            evidence_json,
            remediation,
            cwe,
            owasp_category,
            dedupe_key
        ],
    )?;

    get_finding(&connection, &id)
}

pub fn list_findings(
    app_data_dir: &Path,
    database_path: &Path,
) -> Result<Vec<FindingRecord>, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    read_findings(&connection)
}

pub fn scan_baseline_diff(
    app_data_dir: &Path,
    database_path: &Path,
    scan_id: String,
) -> Result<BaselineDiffSummary, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    let scan = get_scan(&connection, &scan_id)?;
    let current_findings = read_findings_for_scan(&connection, &scan_id)?;
    let baseline_scan_id = previous_completed_scan_id(&connection, &scan)?;

    let Some(baseline_scan_id) = baseline_scan_id else {
        return Ok(BaselineDiffSummary {
            scan_id,
            baseline_scan_id: None,
            new_findings: current_findings,
            recurring_findings: Vec::new(),
            resolved_findings: Vec::new(),
        });
    };

    let baseline_findings = read_findings_for_scan(&connection, &baseline_scan_id)?;
    let baseline_keys = comparable_dedupe_keys(&baseline_findings);
    let current_keys = comparable_dedupe_keys(&current_findings);

    let new_findings = current_findings
        .iter()
        .filter(|finding| {
            finding
                .dedupe_key
                .as_ref()
                .map(|key| !baseline_keys.contains(key))
                .unwrap_or(true)
        })
        .cloned()
        .collect();
    let recurring_findings = current_findings
        .iter()
        .filter(|finding| {
            finding
                .dedupe_key
                .as_ref()
                .map(|key| baseline_keys.contains(key))
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    let resolved_findings = baseline_findings
        .iter()
        .filter(|finding| is_comparable_baseline_finding(finding))
        .filter(|finding| {
            finding
                .dedupe_key
                .as_ref()
                .map(|key| !current_keys.contains(key))
                .unwrap_or(false)
        })
        .cloned()
        .collect();

    Ok(BaselineDiffSummary {
        scan_id,
        baseline_scan_id: Some(baseline_scan_id),
        new_findings,
        recurring_findings,
        resolved_findings,
    })
}

pub fn update_finding_status(
    app_data_dir: &Path,
    database_path: &Path,
    input: UpdateFindingStatusInput,
) -> Result<FindingRecord, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    ensure_finding_exists(&connection, &input.id)?;
    let status = validate_finding_status(input.status)?;

    connection.execute(
        "UPDATE findings
        SET status = ?1, updated_at = datetime('now')
        WHERE id = ?2",
        params![status, input.id],
    )?;

    get_finding(&connection, &input.id)
}

pub fn create_audit_log(
    app_data_dir: &Path,
    database_path: &Path,
    input: CreateAuditLogInput,
) -> Result<AuditLogRecord, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    let actor_user_id =
        validate_optional_text(input.actor_user_id, "audit actor", MAX_AUDIT_FIELD_LEN)?;
    let action = validate_text(input.action, "audit action", 1, MAX_AUDIT_FIELD_LEN)?;
    let entity_type = validate_text(
        input.entity_type,
        "audit entity type",
        1,
        MAX_AUDIT_FIELD_LEN,
    )?;
    let entity_id = validate_text(input.entity_id, "audit entity id", 1, MAX_AUDIT_FIELD_LEN)?;
    let severity = validate_audit_severity(input.severity)?;
    let metadata_json_redacted = validate_text(
        input.metadata_json_redacted,
        "audit metadata",
        2,
        MAX_AUDIT_METADATA_LEN,
    )?;
    let id = format!("audit-{}", Uuid::new_v4());

    connection.execute(
        "INSERT INTO audit_logs (
            id, workspace_id, actor_user_id, action, entity_type, entity_id,
            severity, metadata_json_redacted, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, datetime('now'))",
        params![
            id,
            LOCAL_WORKSPACE_ID,
            actor_user_id,
            action,
            entity_type,
            entity_id,
            severity,
            metadata_json_redacted
        ],
    )?;

    get_audit_log(&connection, &id)
}

pub fn list_audit_logs(
    app_data_dir: &Path,
    database_path: &Path,
) -> Result<Vec<AuditLogRecord>, StorageError> {
    let connection = open_initialized_connection(app_data_dir, database_path)?;
    read_audit_logs(&connection)
}

fn open_initialized_connection(
    app_data_dir: &Path,
    database_path: &Path,
) -> Result<Connection, StorageError> {
    initialize_local_storage(app_data_dir, database_path)?;
    let connection = Connection::open(database_path)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    Ok(connection)
}

fn ensure_inside_app_data_dir(
    app_data_dir: &Path,
    database_path: &Path,
) -> Result<(), StorageError> {
    let parent = database_path
        .parent()
        .ok_or(StorageError::InvalidAppDataPath)?;

    let canonical_base = canonicalize_existing_or_parent(app_data_dir)?;
    let canonical_parent = canonicalize_existing_or_parent(parent)?;

    if canonical_parent.starts_with(canonical_base) {
        Ok(())
    } else {
        Err(StorageError::InvalidAppDataPath)
    }
}

fn canonicalize_existing_or_parent(path: &Path) -> Result<PathBuf, StorageError> {
    if path.exists() {
        return Ok(path.canonicalize()?);
    }

    if let Some(parent) = path.parent() {
        if parent.exists() {
            let file_name = path.file_name().ok_or(StorageError::InvalidAppDataPath)?;
            return Ok(parent.canonicalize()?.join(file_name));
        }
    }

    Ok(path.to_path_buf())
}

fn apply_migrations(connection: &mut Connection) -> Result<(), StorageError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            id TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )?;

    let transaction = connection.transaction()?;
    for (migration_id, migration_sql) in MIGRATIONS {
        let already_applied = transaction
            .query_row(
                "SELECT id FROM schema_migrations WHERE id = ?1",
                params![migration_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .is_some();

        if !already_applied {
            transaction.execute_batch(migration_sql)?;
            transaction.execute(
                "INSERT INTO schema_migrations (id) VALUES (?1)",
                params![migration_id],
            )?;
        }
    }

    transaction.commit()?;
    Ok(())
}

fn seed_local_workspace(connection: &Connection) -> Result<(), StorageError> {
    connection.execute(
        "INSERT OR IGNORE INTO workspaces (id, name, plan, created_at, updated_at)
        VALUES (?1, ?2, ?3, datetime('now'), datetime('now'))",
        params![LOCAL_WORKSPACE_ID, "Local Workspace", "free"],
    )?;
    Ok(())
}

fn snapshot(
    connection: &Connection,
    database_path: &Path,
) -> Result<LocalStorageSnapshot, StorageError> {
    let applied_migrations = read_applied_migrations(connection)?;

    Ok(LocalStorageSnapshot {
        database_path: database_path.display().to_string(),
        applied_migrations,
        workspace_count: count_table(connection, "workspaces")?,
        project_count: count_table(connection, "projects")?,
        target_count: count_table(connection, "targets")?,
    })
}

fn read_applied_migrations(connection: &Connection) -> Result<Vec<String>, StorageError> {
    let mut statement =
        connection.prepare("SELECT id FROM schema_migrations ORDER BY applied_at ASC, id ASC")?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;

    let mut migrations = Vec::new();
    for row in rows {
        migrations.push(row?);
    }
    Ok(migrations)
}

fn count_table(connection: &Connection, table_name: &str) -> Result<u32, StorageError> {
    let sql = match table_name {
        "workspaces" => "SELECT COUNT(*) FROM workspaces",
        "projects" => "SELECT COUNT(*) FROM projects WHERE status = 'active'",
        "targets" => "SELECT COUNT(*) FROM targets WHERE status = 'active'",
        _ => return Err(StorageError::InvalidAppDataPath),
    };

    let count = connection.query_row(sql, [], |row| row.get::<_, u32>(0))?;
    Ok(count)
}

fn count_current_month_scans(connection: &Connection) -> Result<u32, StorageError> {
    let count = connection.query_row(
        "SELECT COUNT(*) FROM scans
        WHERE strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')",
        [],
        |row| row.get::<_, u32>(0),
    )?;
    Ok(count)
}

fn count_active_scans(connection: &Connection) -> Result<u32, StorageError> {
    let count = connection.query_row(
        "SELECT COUNT(*) FROM scans
        WHERE phase NOT IN ('completed', 'failed', 'canceled')",
        [],
        |row| row.get::<_, u32>(0),
    )?;
    Ok(count)
}

fn count_current_month_ai_fix_guides(connection: &Connection) -> Result<u32, StorageError> {
    let count = connection.query_row(
        "SELECT COUNT(*) FROM audit_logs
        WHERE action = 'ai_fix_guide.generated'
            AND strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')",
        [],
        |row| row.get::<_, u32>(0),
    )?;
    Ok(count)
}

fn count_current_month_reports(connection: &Connection) -> Result<u32, StorageError> {
    let count = connection.query_row(
        "SELECT COUNT(*) FROM audit_logs
        WHERE action = 'report.generated'
            AND strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')",
        [],
        |row| row.get::<_, u32>(0),
    )?;
    Ok(count)
}

fn validate_text(
    value: String,
    field_name: &'static str,
    min_len: usize,
    max_len: usize,
) -> Result<String, StorageError> {
    let trimmed = value.trim().to_string();
    if trimmed.len() < min_len {
        return Err(StorageError::InvalidInput(field_name));
    }
    if trimmed.len() > max_len {
        return Err(StorageError::InvalidInput(field_name));
    }
    Ok(trimmed)
}

fn validate_optional_text(
    value: Option<String>,
    field_name: &'static str,
    max_len: usize,
) -> Result<Option<String>, StorageError> {
    match value {
        Some(value) => {
            let value = validate_text(value, field_name, 0, max_len)?;
            if value.is_empty() {
                Ok(None)
            } else {
                Ok(Some(value))
            }
        }
        None => Ok(None),
    }
}

fn validate_target_type(value: String) -> Result<String, StorageError> {
    match value.trim() {
        "url" | "api" | "openapi" => Ok(value.trim().to_string()),
        _ => Err(StorageError::InvalidInput("target type")),
    }
}

fn validate_url(value: String) -> Result<String, StorageError> {
    let url = validate_text(value, "target url", 1, MAX_URL_LEN)?;
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(StorageError::InvalidInput("target url"));
    }
    if url.contains(char::is_whitespace) {
        return Err(StorageError::InvalidInput("target url"));
    }
    Ok(url)
}

fn validate_scan_profile(value: String) -> Result<String, StorageError> {
    match value.trim() {
        "safe" | "passive" | "surface" => Ok(value.trim().to_string()),
        _ => Err(StorageError::InvalidInput("scan profile")),
    }
}

fn validate_scan_phase(value: String) -> Result<String, StorageError> {
    match value.trim() {
        "queued" | "validating" | "crawling" | "analyzing" | "reporting" | "completed"
        | "failed" | "canceled" => Ok(value.trim().to_string()),
        _ => Err(StorageError::InvalidInput("scan phase")),
    }
}

fn validate_finding_severity(value: String) -> Result<String, StorageError> {
    match value.trim() {
        "critical" | "high" | "medium" | "low" | "info" => Ok(value.trim().to_string()),
        _ => Err(StorageError::InvalidInput("finding severity")),
    }
}

fn validate_finding_confidence(value: String) -> Result<String, StorageError> {
    match value.trim() {
        "high" | "medium" | "low" => Ok(value.trim().to_string()),
        _ => Err(StorageError::InvalidInput("finding confidence")),
    }
}

fn validate_finding_status(value: String) -> Result<String, StorageError> {
    match value.trim() {
        "new" | "open" | "accepted_risk" | "false_positive" | "resolved" => {
            Ok(value.trim().to_string())
        }
        _ => Err(StorageError::InvalidInput("finding status")),
    }
}

fn validate_endpoint_method(value: String) -> Result<String, StorageError> {
    let method = validate_text(value, "endpoint method", 1, MAX_ENDPOINT_METHOD_LEN)?;
    let method = method.to_ascii_uppercase();
    match method.as_str() {
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "TRACE" => Ok(method),
        _ => Err(StorageError::InvalidInput("endpoint method")),
    }
}

fn validate_audit_severity(value: String) -> Result<String, StorageError> {
    match value.trim() {
        "info" | "warning" | "error" => Ok(value.trim().to_string()),
        _ => Err(StorageError::InvalidInput("audit severity")),
    }
}

fn ensure_project_exists(connection: &Connection, project_id: &str) -> Result<(), StorageError> {
    let exists = connection
        .query_row(
            "SELECT id FROM projects WHERE id = ?1 AND status = 'active'",
            params![project_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .is_some();

    if exists {
        Ok(())
    } else {
        Err(StorageError::InvalidInput("project id"))
    }
}

fn ensure_target_exists(connection: &Connection, target_id: &str) -> Result<(), StorageError> {
    let exists = connection
        .query_row(
            "SELECT id FROM targets WHERE id = ?1 AND status = 'active'",
            params![target_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .is_some();

    if exists {
        Ok(())
    } else {
        Err(StorageError::InvalidInput("target id"))
    }
}

fn ensure_target_belongs_to_project(
    connection: &Connection,
    target_id: &str,
    project_id: &str,
) -> Result<(), StorageError> {
    let exists = connection
        .query_row(
            "SELECT id FROM targets
            WHERE id = ?1 AND project_id = ?2 AND status = 'active'",
            params![target_id, project_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .is_some();

    if exists {
        Ok(())
    } else {
        Err(StorageError::InvalidInput("target id"))
    }
}

fn ensure_scan_exists(connection: &Connection, scan_id: &str) -> Result<(), StorageError> {
    let exists = connection
        .query_row(
            "SELECT id FROM scans WHERE id = ?1",
            params![scan_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .is_some();

    if exists {
        Ok(())
    } else {
        Err(StorageError::InvalidInput("scan id"))
    }
}

fn ensure_finding_exists(connection: &Connection, finding_id: &str) -> Result<(), StorageError> {
    let exists = connection
        .query_row(
            "SELECT id FROM findings WHERE id = ?1",
            params![finding_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .is_some();

    if exists {
        Ok(())
    } else {
        Err(StorageError::InvalidInput("finding id"))
    }
}

fn get_project(connection: &Connection, project_id: &str) -> Result<ProjectRecord, StorageError> {
    connection
        .query_row(
            "SELECT
                p.id, p.name, p.description, p.status, p.created_at, p.updated_at,
                COUNT(t.id) AS target_count
            FROM projects p
            LEFT JOIN targets t ON t.project_id = p.id AND t.status = 'active'
            WHERE p.id = ?1
            GROUP BY p.id",
            params![project_id],
            map_project,
        )
        .map_err(StorageError::from)
}

fn read_projects(connection: &Connection) -> Result<Vec<ProjectRecord>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT
            p.id, p.name, p.description, p.status, p.created_at, p.updated_at,
            COUNT(t.id) AS target_count
        FROM projects p
        LEFT JOIN targets t ON t.project_id = p.id AND t.status = 'active'
        WHERE p.workspace_id = ?1 AND p.status = 'active'
        GROUP BY p.id
        ORDER BY p.created_at DESC, p.name ASC",
    )?;
    let rows = statement.query_map(params![LOCAL_WORKSPACE_ID], map_project)?;

    let mut projects = Vec::new();
    for row in rows {
        projects.push(row?);
    }
    Ok(projects)
}

fn map_project(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectRecord> {
    Ok(ProjectRecord {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        status: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
        target_count: row.get(6)?,
    })
}

fn get_target(connection: &Connection, target_id: &str) -> Result<TargetRecord, StorageError> {
    connection
        .query_row(
            "SELECT id, project_id, target_type, name, url, approval_note,
                allow_private_network, status, created_at, updated_at
            FROM targets
            WHERE id = ?1",
            params![target_id],
            map_target,
        )
        .map_err(StorageError::from)
}

fn read_targets(connection: &Connection) -> Result<Vec<TargetRecord>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT id, project_id, target_type, name, url, approval_note,
            allow_private_network, status, created_at, updated_at
        FROM targets
        WHERE status = 'active'
        ORDER BY created_at DESC, name ASC",
    )?;
    let rows = statement.query_map([], map_target)?;

    let mut targets = Vec::new();
    for row in rows {
        targets.push(row?);
    }
    Ok(targets)
}

fn read_targets_for_project(
    connection: &Connection,
    project_id: &str,
) -> Result<Vec<TargetRecord>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT id, project_id, target_type, name, url, approval_note,
            allow_private_network, status, created_at, updated_at
        FROM targets
        WHERE project_id = ?1 AND status = 'active'
        ORDER BY created_at DESC, name ASC",
    )?;
    let rows = statement.query_map(params![project_id], map_target)?;

    let mut targets = Vec::new();
    for row in rows {
        targets.push(row?);
    }
    Ok(targets)
}

fn map_target(row: &rusqlite::Row<'_>) -> rusqlite::Result<TargetRecord> {
    let allow_private_network: i64 = row.get(6)?;
    Ok(TargetRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        target_type: row.get(2)?,
        name: row.get(3)?,
        url: row.get(4)?,
        approval_note: row.get(5)?,
        allow_private_network: allow_private_network == 1,
        status: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

fn get_scan(connection: &Connection, scan_id: &str) -> Result<ScanRecord, StorageError> {
    connection
        .query_row(
            "SELECT
                s.id, s.project_id, s.target_id, p.name, t.name, t.url,
                s.profile, s.phase, s.status_message, s.started_at, s.finished_at,
                s.created_at, s.updated_at
            FROM scans s
            JOIN projects p ON p.id = s.project_id
            JOIN targets t ON t.id = s.target_id
            WHERE s.id = ?1",
            params![scan_id],
            map_scan,
        )
        .map_err(StorageError::from)
}

fn read_scans(connection: &Connection) -> Result<Vec<ScanRecord>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT
            s.id, s.project_id, s.target_id, p.name, t.name, t.url,
            s.profile, s.phase, s.status_message, s.started_at, s.finished_at,
            s.created_at, s.updated_at
        FROM scans s
        JOIN projects p ON p.id = s.project_id
        JOIN targets t ON t.id = s.target_id
        ORDER BY s.created_at DESC",
    )?;
    let rows = statement.query_map([], map_scan)?;

    let mut scans = Vec::new();
    for row in rows {
        scans.push(row?);
    }
    Ok(scans)
}

fn map_scan(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScanRecord> {
    Ok(ScanRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        target_id: row.get(2)?,
        project_name: row.get(3)?,
        target_name: row.get(4)?,
        target_url: row.get(5)?,
        profile: row.get(6)?,
        phase: row.get(7)?,
        status_message: row.get(8)?,
        started_at: row.get(9)?,
        finished_at: row.get(10)?,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
    })
}

fn get_finding(connection: &Connection, finding_id: &str) -> Result<FindingRecord, StorageError> {
    connection
        .query_row(
            "SELECT id, scan_id, title, severity, confidence, endpoint, parameter_name,
                status, evidence_json, remediation, cwe, owasp_category, dedupe_key, created_at, updated_at
            FROM findings
            WHERE id = ?1",
            params![finding_id],
            map_finding,
        )
        .map_err(StorageError::from)
}

fn existing_finding_by_dedupe_key(
    connection: &Connection,
    scan_id: &str,
    dedupe_key: &Option<String>,
) -> Result<Option<String>, StorageError> {
    let Some(dedupe_key) = dedupe_key else {
        return Ok(None);
    };
    connection
        .query_row(
            "SELECT id FROM findings WHERE scan_id = ?1 AND dedupe_key = ?2",
            params![scan_id, dedupe_key],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(StorageError::from)
}

fn read_findings(connection: &Connection) -> Result<Vec<FindingRecord>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT id, scan_id, title, severity, confidence, endpoint, parameter_name,
            status, evidence_json, remediation, cwe, owasp_category, dedupe_key, created_at, updated_at
        FROM findings
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            created_at DESC",
    )?;
    let rows = statement.query_map([], map_finding)?;

    let mut findings = Vec::new();
    for row in rows {
        findings.push(row?);
    }
    Ok(findings)
}

fn read_findings_for_scan(
    connection: &Connection,
    scan_id: &str,
) -> Result<Vec<FindingRecord>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT id, scan_id, title, severity, confidence, endpoint, parameter_name,
            status, evidence_json, remediation, cwe, owasp_category, dedupe_key, created_at, updated_at
        FROM findings
        WHERE scan_id = ?1
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            created_at DESC",
    )?;
    let rows = statement.query_map(params![scan_id], map_finding)?;

    let mut findings = Vec::new();
    for row in rows {
        findings.push(row?);
    }
    Ok(findings)
}

fn previous_completed_scan_id(
    connection: &Connection,
    scan: &ScanRecord,
) -> Result<Option<String>, StorageError> {
    connection
        .query_row(
            "SELECT id
            FROM scans
            WHERE target_id = ?1
                AND phase = 'completed'
                AND id != ?2
                AND rowid < (SELECT rowid FROM scans WHERE id = ?2)
            ORDER BY rowid DESC
            LIMIT 1",
            params![&scan.target_id, &scan.id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(StorageError::from)
}

fn comparable_dedupe_keys(findings: &[FindingRecord]) -> Vec<String> {
    findings
        .iter()
        .filter(|finding| is_comparable_baseline_finding(finding))
        .filter_map(|finding| finding.dedupe_key.clone())
        .collect()
}

fn is_comparable_baseline_finding(finding: &FindingRecord) -> bool {
    !matches!(
        finding.status.as_str(),
        "false_positive" | "resolved" | "accepted_risk"
    )
}

fn map_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<FindingRecord> {
    Ok(FindingRecord {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        title: row.get(2)?,
        severity: row.get(3)?,
        confidence: row.get(4)?,
        endpoint: row.get(5)?,
        parameter_name: row.get(6)?,
        status: row.get(7)?,
        evidence_json: row.get(8)?,
        remediation: row.get(9)?,
        cwe: row.get(10)?,
        owasp_category: row.get(11)?,
        dedupe_key: row.get(12)?,
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

fn read_target_endpoints(
    connection: &Connection,
    target_id: Option<&str>,
) -> Result<Vec<TargetEndpointRecord>, StorageError> {
    let mut endpoints = Vec::new();
    if let Some(target_id) = target_id {
        let mut statement = connection.prepare(
            "SELECT id, target_id, method, path, url, operation_id, parameters_json,
                status, created_at, updated_at
            FROM target_endpoints
            WHERE target_id = ?1 AND status = 'active'
            ORDER BY path ASC, method ASC",
        )?;
        let rows = statement.query_map(params![target_id], map_target_endpoint)?;
        for row in rows {
            endpoints.push(row?);
        }
    } else {
        let mut statement = connection.prepare(
            "SELECT id, target_id, method, path, url, operation_id, parameters_json,
                status, created_at, updated_at
            FROM target_endpoints
            WHERE status = 'active'
            ORDER BY created_at DESC, path ASC, method ASC",
        )?;
        let rows = statement.query_map([], map_target_endpoint)?;
        for row in rows {
            endpoints.push(row?);
        }
    }
    Ok(endpoints)
}

fn map_target_endpoint(row: &rusqlite::Row<'_>) -> rusqlite::Result<TargetEndpointRecord> {
    Ok(TargetEndpointRecord {
        id: row.get(0)?,
        target_id: row.get(1)?,
        method: row.get(2)?,
        path: row.get(3)?,
        url: row.get(4)?,
        operation_id: row.get(5)?,
        parameters_json: row.get(6)?,
        status: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

fn get_audit_log(
    connection: &Connection,
    audit_log_id: &str,
) -> Result<AuditLogRecord, StorageError> {
    connection
        .query_row(
            "SELECT id, actor_user_id, action, entity_type, entity_id, severity,
                metadata_json_redacted, created_at
            FROM audit_logs
            WHERE id = ?1",
            params![audit_log_id],
            map_audit_log,
        )
        .map_err(StorageError::from)
}

fn read_audit_logs(connection: &Connection) -> Result<Vec<AuditLogRecord>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT id, actor_user_id, action, entity_type, entity_id, severity,
            metadata_json_redacted, created_at
        FROM audit_logs
        WHERE workspace_id = ?1
        ORDER BY created_at DESC, id DESC
        LIMIT 200",
    )?;
    let rows = statement.query_map(params![LOCAL_WORKSPACE_ID], map_audit_log)?;

    let mut audit_logs = Vec::new();
    for row in rows {
        audit_logs.push(row?);
    }
    Ok(audit_logs)
}

fn map_audit_log(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditLogRecord> {
    Ok(AuditLogRecord {
        id: row.get(0)?,
        actor_user_id: row.get(1)?,
        action: row.get(2)?,
        entity_type: row.get(3)?,
        entity_id: row.get(4)?,
        severity: row.get(5)?,
        metadata_json_redacted: row.get(6)?,
        created_at: row.get(7)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migration_ids() -> Vec<String> {
        MIGRATIONS
            .iter()
            .map(|(migration_id, _)| migration_id.to_string())
            .collect()
    }

    #[test]
    fn applies_initial_migration_and_seeds_workspace() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("aegis.sqlite3");

        let snapshot = initialize_local_storage(temp_dir.path(), &db_path).expect("storage init");

        assert_eq!(snapshot.applied_migrations, migration_ids());
        assert_eq!(snapshot.workspace_count, 1);
        assert_eq!(snapshot.project_count, 0);
        assert_eq!(snapshot.target_count, 0);
    }

    #[test]
    fn migration_runner_is_idempotent() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("aegis.sqlite3");

        initialize_local_storage(temp_dir.path(), &db_path).expect("first init");
        let snapshot = initialize_local_storage(temp_dir.path(), &db_path).expect("second init");

        assert_eq!(snapshot.applied_migrations, migration_ids());
        assert_eq!(snapshot.workspace_count, 1);
    }

    #[test]
    fn community_upgrade_preserves_projects_and_ignores_legacy_license_state() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("legacy.sqlite3");
        let project = create_project(
            temp_dir.path(),
            &db_path,
            CreateProjectInput {
                name: "Existing local project".to_string(),
                description: "Synthetic upgrade fixture".to_string(),
            },
        )
        .expect("project");
        {
            let connection = Connection::open(&db_path).expect("fixture connection");
            connection.execute(
                "INSERT INTO licenses (id, workspace_id, plan, status, expires_at, created_at, updated_at)
                 VALUES ('legacy-fixture', ?1, 'pro', 'expired', '2000-01-01T00:00:00Z', datetime('now'), datetime('now'))",
                params![LOCAL_WORKSPACE_ID],
            ).expect("legacy row");
        }
        initialize_local_storage(temp_dir.path(), &db_path).expect("community reopen");
        let projects = list_projects(temp_dir.path(), &db_path).expect("existing projects");
        assert!(projects.iter().any(|item| item.id == project.id));
        create_project(
            temp_dir.path(),
            &db_path,
            CreateProjectInput {
                name: "Community project".to_string(),
                description: String::new(),
            },
        )
        .expect("expired legacy license cannot block project creation");
        let connection = Connection::open(&db_path).expect("fixture connection");
        let legacy_rows: i64 = connection
            .query_row("SELECT COUNT(*) FROM licenses", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            legacy_rows, 1,
            "publication must not destroy existing user records"
        );
    }

    #[test]
    fn rejects_database_path_outside_app_data_dir() {
        let app_dir = tempfile::tempdir().expect("app dir");
        let other_dir = tempfile::tempdir().expect("other dir");
        let db_path = other_dir.path().join("aegis.sqlite3");

        let error = initialize_local_storage(app_dir.path(), &db_path).expect_err("path rejected");

        assert!(matches!(error, StorageError::InvalidAppDataPath));
    }

    #[test]
    fn creates_project_and_approved_target() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("aegis.sqlite3");

        let project = create_project(
            temp_dir.path(),
            &db_path,
            CreateProjectInput {
                name: "Staging".to_string(),
                description: "Primary staging surface".to_string(),
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
                approval_note: "Owner approval captured in ticket SEC-100".to_string(),
                allow_private_network: false,
            },
        )
        .expect("target");

        let projects = list_projects(temp_dir.path(), &db_path).expect("projects");
        let targets = list_targets(temp_dir.path(), &db_path, Some(project.id)).expect("targets");

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].target_count, 1);
        assert_eq!(targets, vec![target]);
    }

    #[test]
    fn rejects_target_without_http_scheme() {
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

        let error = create_target(
            temp_dir.path(),
            &db_path,
            CreateTargetInput {
                project_id: project.id,
                target_type: "url".to_string(),
                name: "Bad target".to_string(),
                url: "file:///etc/passwd".to_string(),
                approval_note: "approved".to_string(),
                allow_private_network: false,
            },
        )
        .expect_err("invalid url");

        assert!(matches!(error, StorageError::InvalidInput("target url")));
    }

    #[test]
    fn replaces_target_endpoint_candidates() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("aegis.sqlite3");
        let project = create_project(
            temp_dir.path(),
            &db_path,
            CreateProjectInput {
                name: "API".to_string(),
                description: "".to_string(),
            },
        )
        .expect("project");
        let target = create_target(
            temp_dir.path(),
            &db_path,
            CreateTargetInput {
                project_id: project.id,
                target_type: "openapi".to_string(),
                name: "Public API".to_string(),
                url: "https://api.example.com".to_string(),
                approval_note: "Owner approval captured".to_string(),
                allow_private_network: false,
            },
        )
        .expect("target");

        let endpoints = replace_target_endpoints(
            temp_dir.path(),
            &db_path,
            ReplaceTargetEndpointsInput {
                target_id: target.id.clone(),
                endpoints: vec![CreateTargetEndpointInput {
                    method: "get".to_string(),
                    path: "/health".to_string(),
                    url: "https://api.example.com/health".to_string(),
                    operation_id: Some("health".to_string()),
                    parameters_json: "[]".to_string(),
                }],
            },
        )
        .expect("endpoints");

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].method, "GET");
        assert_eq!(endpoints[0].operation_id, Some("health".to_string()));

        let endpoints = replace_target_endpoints(
            temp_dir.path(),
            &db_path,
            ReplaceTargetEndpointsInput {
                target_id: target.id.clone(),
                endpoints: vec![CreateTargetEndpointInput {
                    method: "post".to_string(),
                    path: "/pets".to_string(),
                    url: "https://api.example.com/pets".to_string(),
                    operation_id: None,
                    parameters_json: "[{\"name\":\"body\"}]".to_string(),
                }],
            },
        )
        .expect("replacement endpoints");
        let listed =
            list_target_endpoints(temp_dir.path(), &db_path, Some(target.id)).expect("listed");

        assert_eq!(endpoints, listed);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].method, "POST");
        assert_eq!(listed[0].path, "/pets");
    }

    #[test]
    fn rejects_endpoint_replacement_over_target_limit_without_deleting_existing() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("aegis.sqlite3");
        let project = create_project(
            temp_dir.path(),
            &db_path,
            CreateProjectInput {
                name: "API".to_string(),
                description: "".to_string(),
            },
        )
        .expect("project");
        let target = create_target(
            temp_dir.path(),
            &db_path,
            CreateTargetInput {
                project_id: project.id,
                target_type: "openapi".to_string(),
                name: "Large API".to_string(),
                url: "https://api.example.com".to_string(),
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
                endpoints: vec![CreateTargetEndpointInput {
                    method: "get".to_string(),
                    path: "/health".to_string(),
                    url: "https://api.example.com/health".to_string(),
                    operation_id: None,
                    parameters_json: "[]".to_string(),
                }],
            },
        )
        .expect("seed endpoint");

        let too_many = (0..=MAX_TARGET_ENDPOINTS)
            .map(|index| CreateTargetEndpointInput {
                method: "get".to_string(),
                path: format!("/items/{index}"),
                url: format!("https://api.example.com/items/{index}"),
                operation_id: None,
                parameters_json: "[]".to_string(),
            })
            .collect::<Vec<_>>();
        let error = replace_target_endpoints(
            temp_dir.path(),
            &db_path,
            ReplaceTargetEndpointsInput {
                target_id: target.id.clone(),
                endpoints: too_many,
            },
        )
        .expect_err("endpoint limit");
        assert!(matches!(
            error,
            StorageError::InvalidInput("endpoint count")
        ));

        let listed = list_target_endpoints(temp_dir.path(), &db_path, Some(target.id))
            .expect("existing endpoints");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].path, "/health");
    }

    #[test]
    fn updates_project_and_target() {
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

        let project = update_project(
            temp_dir.path(),
            &db_path,
            UpdateProjectInput {
                id: project.id,
                name: "Production".to_string(),
                description: "Promoted surface".to_string(),
            },
        )
        .expect("updated project");
        let target = update_target(
            temp_dir.path(),
            &db_path,
            UpdateTargetInput {
                id: target.id,
                target_type: "api".to_string(),
                name: "Production API".to_string(),
                url: "https://api.example.com".to_string(),
                approval_note: "Owner approval refreshed".to_string(),
                allow_private_network: false,
            },
        )
        .expect("updated target");

        assert_eq!(project.name, "Production");
        assert_eq!(project.description, "Promoted surface");
        assert_eq!(target.target_type, "api");
        assert_eq!(target.name, "Production API");
        assert_eq!(target.url, "https://api.example.com");
    }

    #[test]
    fn deactivates_target_without_removing_project() {
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

        deactivate_target(temp_dir.path(), &db_path, target.id).expect("deactivate target");

        let projects = list_projects(temp_dir.path(), &db_path).expect("projects");
        let targets = list_targets(temp_dir.path(), &db_path, None).expect("targets");
        let snapshot = initialize_local_storage(temp_dir.path(), &db_path).expect("snapshot");

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].target_count, 0);
        assert!(targets.is_empty());
        assert_eq!(snapshot.target_count, 0);
    }

    #[test]
    fn deactivates_project_and_its_targets() {
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
        create_target(
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

        deactivate_project(temp_dir.path(), &db_path, project.id).expect("deactivate project");

        let projects = list_projects(temp_dir.path(), &db_path).expect("projects");
        let targets = list_targets(temp_dir.path(), &db_path, None).expect("targets");
        let snapshot = initialize_local_storage(temp_dir.path(), &db_path).expect("snapshot");

        assert!(projects.is_empty());
        assert!(targets.is_empty());
        assert_eq!(snapshot.project_count, 0);
        assert_eq!(snapshot.target_count, 0);
    }

    #[test]
    fn creates_scan_for_active_approved_target() {
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
        let scans = list_scans(temp_dir.path(), &db_path).expect("scans");

        assert_eq!(scan.phase, "queued");
        assert_eq!(scan.status_message, "Waiting for Local Engine Service");
        assert_eq!(scans, vec![scan]);
    }

    #[test]
    fn reports_local_usage_snapshot() {
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
        create_scan(
            temp_dir.path(),
            &db_path,
            CreateScanInput {
                project_id: project.id,
                target_id: target.id,
                profile: "safe".to_string(),
            },
        )
        .expect("scan");
        create_audit_log(
            temp_dir.path(),
            &db_path,
            CreateAuditLogInput {
                actor_user_id: Some("local-user".to_string()),
                action: "ai_fix_guide.generated".to_string(),
                entity_type: "finding".to_string(),
                entity_id: "finding-123".to_string(),
                severity: "info".to_string(),
                metadata_json_redacted: "{}".to_string(),
            },
        )
        .expect("audit log");
        create_audit_log(
            temp_dir.path(),
            &db_path,
            CreateAuditLogInput {
                actor_user_id: Some("local-user".to_string()),
                action: "report.generated".to_string(),
                entity_type: "report".to_string(),
                entity_id: "markdown".to_string(),
                severity: "info".to_string(),
                metadata_json_redacted: "{\"format\":\"markdown\"}".to_string(),
            },
        )
        .expect("report audit log");

        let usage = local_usage_snapshot(temp_dir.path(), &db_path).expect("usage");

        assert_eq!(usage.monthly_scans, 1);
        assert_eq!(usage.projects, 1);
        assert_eq!(usage.targets, 1);
        assert_eq!(usage.reports, 1);
        assert_eq!(usage.ai_fix_guides, 1);
        assert_eq!(usage.active_scans, 1);
    }

    #[test]
    fn rejects_scan_for_target_outside_project() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("aegis.sqlite3");
        let project_a = create_project(
            temp_dir.path(),
            &db_path,
            CreateProjectInput {
                name: "A".to_string(),
                description: "".to_string(),
            },
        )
        .expect("project a");
        let project_b = create_project(
            temp_dir.path(),
            &db_path,
            CreateProjectInput {
                name: "B".to_string(),
                description: "".to_string(),
            },
        )
        .expect("project b");
        let target = create_target(
            temp_dir.path(),
            &db_path,
            CreateTargetInput {
                project_id: project_b.id,
                target_type: "url".to_string(),
                name: "B target".to_string(),
                url: "https://b.example.com".to_string(),
                approval_note: "Owner approval captured".to_string(),
                allow_private_network: false,
            },
        )
        .expect("target");

        let error = create_scan(
            temp_dir.path(),
            &db_path,
            CreateScanInput {
                project_id: project_a.id,
                target_id: target.id,
                profile: "safe".to_string(),
            },
        )
        .expect_err("target rejected");

        assert!(matches!(error, StorageError::InvalidInput("target id")));
    }

    #[test]
    fn rejects_unknown_scan_profile() {
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

        let error = create_scan(
            temp_dir.path(),
            &db_path,
            CreateScanInput {
                project_id: project.id,
                target_id: target.id,
                profile: "destructive".to_string(),
            },
        )
        .expect_err("profile rejected");

        assert!(matches!(error, StorageError::InvalidInput("scan profile")));
    }

    #[test]
    fn updates_scan_phase_and_timestamps() {
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

        let validating = update_scan_phase(
            temp_dir.path(),
            &db_path,
            UpdateScanPhaseInput {
                id: scan.id.clone(),
                phase: "validating".to_string(),
                status_message: "Scope accepted".to_string(),
            },
        )
        .expect("validating");
        let completed = update_scan_phase(
            temp_dir.path(),
            &db_path,
            UpdateScanPhaseInput {
                id: scan.id,
                phase: "completed".to_string(),
                status_message: "Scan completed".to_string(),
            },
        )
        .expect("completed");

        assert_eq!(validating.phase, "validating");
        assert!(validating.started_at.is_some());
        assert_eq!(completed.phase, "completed");
        assert!(completed.started_at.is_some());
        assert!(completed.finished_at.is_some());
    }

    #[test]
    fn rejects_unknown_scan_phase() {
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

        let error = update_scan_phase(
            temp_dir.path(),
            &db_path,
            UpdateScanPhaseInput {
                id: scan.id,
                phase: "exploit".to_string(),
                status_message: "Nope".to_string(),
            },
        )
        .expect_err("phase rejected");

        assert!(matches!(error, StorageError::InvalidInput("scan phase")));
    }

    #[test]
    fn cancels_scan_with_finished_timestamp() {
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

        let canceled = cancel_scan(temp_dir.path(), &db_path, scan.id).expect("canceled");

        assert_eq!(canceled.phase, "canceled");
        assert_eq!(canceled.status_message, "Scan canceled by user");
        assert!(canceled.finished_at.is_some());
    }

    #[test]
    fn recovers_interrupted_scans_without_reopening_terminal_or_queued_scans() {
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

        let queued = create_scan(
            temp_dir.path(),
            &db_path,
            CreateScanInput {
                project_id: project.id.clone(),
                target_id: target.id.clone(),
                profile: "safe".to_string(),
            },
        )
        .expect("queued scan");
        let crawling = create_scan(
            temp_dir.path(),
            &db_path,
            CreateScanInput {
                project_id: project.id.clone(),
                target_id: target.id.clone(),
                profile: "safe".to_string(),
            },
        )
        .expect("crawling scan");
        let failed = create_scan(
            temp_dir.path(),
            &db_path,
            CreateScanInput {
                project_id: project.id,
                target_id: target.id,
                profile: "safe".to_string(),
            },
        )
        .expect("failed scan");

        update_scan_phase(
            temp_dir.path(),
            &db_path,
            UpdateScanPhaseInput {
                id: crawling.id.clone(),
                phase: "crawling".to_string(),
                status_message: "Passive probes running".to_string(),
            },
        )
        .expect("mark crawling");
        update_scan_phase(
            temp_dir.path(),
            &db_path,
            UpdateScanPhaseInput {
                id: failed.id.clone(),
                phase: "failed".to_string(),
                status_message: "Probe failed".to_string(),
            },
        )
        .expect("mark failed");

        let recovered = recover_interrupted_scans(temp_dir.path(), &db_path)
            .expect("recover interrupted scans");

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].id, crawling.id);
        assert_eq!(recovered[0].phase, "queued");
        assert_eq!(
            recovered[0].status_message,
            "Recovered after app restart; waiting for Local Engine Service"
        );
        assert!(recovered[0].finished_at.is_none());

        let scans = list_scans(temp_dir.path(), &db_path).expect("scans");
        let queued = scans
            .iter()
            .find(|scan| scan.id == queued.id)
            .expect("queued scan");
        let failed = scans
            .iter()
            .find(|scan| scan.id == failed.id)
            .expect("failed scan");

        assert_eq!(queued.phase, "queued");
        assert_eq!(queued.status_message, "Waiting for Local Engine Service");
        assert_eq!(failed.phase, "failed");
        assert_eq!(failed.status_message, "Probe failed");
        assert!(failed.finished_at.is_some());
    }

    #[test]
    fn creates_and_lists_findings_for_scan() {
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

        let finding = create_finding(
            temp_dir.path(),
            &db_path,
            CreateFindingInput {
                scan_id: scan.id.clone(),
                title: "Missing Content-Security-Policy header".to_string(),
                severity: "medium".to_string(),
                confidence: "high".to_string(),
                endpoint: "https://staging.example.com".to_string(),
                parameter_name: None,
                evidence_json: "{\"header\":\"Content-Security-Policy\"}".to_string(),
                remediation: "Add a restrictive CSP header".to_string(),
                cwe: Some("CWE-693".to_string()),
                owasp_category: Some("A05 Security Misconfiguration".to_string()),
                dedupe_key: Some("passive.missing_csp|https://staging.example.com".to_string()),
            },
        )
        .expect("finding");
        let duplicate = create_finding(
            temp_dir.path(),
            &db_path,
            CreateFindingInput {
                scan_id: scan.id,
                title: "Duplicate Missing Content-Security-Policy header".to_string(),
                severity: "medium".to_string(),
                confidence: "medium".to_string(),
                endpoint: "https://staging.example.com".to_string(),
                parameter_name: None,
                evidence_json: "{\"header\":\"Content-Security-Policy\"}".to_string(),
                remediation: "Duplicate remediation".to_string(),
                cwe: None,
                owasp_category: None,
                dedupe_key: Some("passive.missing_csp|https://staging.example.com".to_string()),
            },
        )
        .expect("duplicate finding");
        let findings = list_findings(temp_dir.path(), &db_path).expect("findings");

        assert_eq!(duplicate, finding);
        assert_eq!(findings, vec![finding]);
        assert_eq!(findings[0].status, "new");
        assert_eq!(
            findings[0].dedupe_key,
            Some("passive.missing_csp|https://staging.example.com".to_string())
        );
    }

    #[test]
    fn compares_scan_findings_against_previous_completed_baseline() {
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
        let baseline_scan = create_scan(
            temp_dir.path(),
            &db_path,
            CreateScanInput {
                project_id: project.id.clone(),
                target_id: target.id.clone(),
                profile: "safe".to_string(),
            },
        )
        .expect("baseline scan");
        create_finding(
            temp_dir.path(),
            &db_path,
            CreateFindingInput {
                scan_id: baseline_scan.id.clone(),
                title: "Missing CSP".to_string(),
                severity: "medium".to_string(),
                confidence: "high".to_string(),
                endpoint: "https://staging.example.com".to_string(),
                parameter_name: None,
                evidence_json: "{}".to_string(),
                remediation: "Add CSP".to_string(),
                cwe: None,
                owasp_category: None,
                dedupe_key: Some("passive.missing_csp|https://staging.example.com".to_string()),
            },
        )
        .expect("baseline recurring finding");
        create_finding(
            temp_dir.path(),
            &db_path,
            CreateFindingInput {
                scan_id: baseline_scan.id.clone(),
                title: "Server header disclosure".to_string(),
                severity: "info".to_string(),
                confidence: "medium".to_string(),
                endpoint: "https://staging.example.com".to_string(),
                parameter_name: None,
                evidence_json: "{}".to_string(),
                remediation: "Reduce server header detail".to_string(),
                cwe: None,
                owasp_category: None,
                dedupe_key: Some(
                    "passive.server_header_disclosure|https://staging.example.com".to_string(),
                ),
            },
        )
        .expect("baseline resolved finding");
        update_scan_phase(
            temp_dir.path(),
            &db_path,
            UpdateScanPhaseInput {
                id: baseline_scan.id.clone(),
                phase: "completed".to_string(),
                status_message: "Baseline completed".to_string(),
            },
        )
        .expect("baseline completed");

        let current_scan = create_scan(
            temp_dir.path(),
            &db_path,
            CreateScanInput {
                project_id: project.id,
                target_id: target.id,
                profile: "safe".to_string(),
            },
        )
        .expect("current scan");
        create_finding(
            temp_dir.path(),
            &db_path,
            CreateFindingInput {
                scan_id: current_scan.id.clone(),
                title: "Missing CSP".to_string(),
                severity: "medium".to_string(),
                confidence: "high".to_string(),
                endpoint: "https://staging.example.com".to_string(),
                parameter_name: None,
                evidence_json: "{}".to_string(),
                remediation: "Add CSP".to_string(),
                cwe: None,
                owasp_category: None,
                dedupe_key: Some("passive.missing_csp|https://staging.example.com".to_string()),
            },
        )
        .expect("current recurring finding");
        create_finding(
            temp_dir.path(),
            &db_path,
            CreateFindingInput {
                scan_id: current_scan.id.clone(),
                title: "Open redirect signal".to_string(),
                severity: "medium".to_string(),
                confidence: "high".to_string(),
                endpoint: "https://staging.example.com/login?next=/home".to_string(),
                parameter_name: Some("next".to_string()),
                evidence_json: "{}".to_string(),
                remediation: "Allow-list redirect targets".to_string(),
                cwe: None,
                owasp_category: None,
                dedupe_key: Some(
                    "active.open_redirect_signal|https://staging.example.com/login?next=/home|next"
                        .to_string(),
                ),
            },
        )
        .expect("current new finding");

        let diff = scan_baseline_diff(temp_dir.path(), &db_path, current_scan.id.clone())
            .expect("baseline diff");

        assert_eq!(diff.scan_id, current_scan.id);
        assert_eq!(diff.baseline_scan_id, Some(baseline_scan.id));
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.new_findings[0].title, "Open redirect signal");
        assert_eq!(diff.recurring_findings.len(), 1);
        assert_eq!(diff.recurring_findings[0].title, "Missing CSP");
        assert_eq!(diff.resolved_findings.len(), 1);
        assert_eq!(diff.resolved_findings[0].title, "Server header disclosure");
    }

    #[test]
    fn rejects_unknown_finding_severity() {
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

        let error = create_finding(
            temp_dir.path(),
            &db_path,
            CreateFindingInput {
                scan_id: scan.id,
                title: "Invalid finding".to_string(),
                severity: "urgent".to_string(),
                confidence: "high".to_string(),
                endpoint: "https://staging.example.com".to_string(),
                parameter_name: None,
                evidence_json: "{}".to_string(),
                remediation: "".to_string(),
                cwe: None,
                owasp_category: None,
                dedupe_key: None,
            },
        )
        .expect_err("severity rejected");

        assert!(matches!(
            error,
            StorageError::InvalidInput("finding severity")
        ));
    }

    #[test]
    fn updates_finding_status() {
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
        let finding = create_finding(
            temp_dir.path(),
            &db_path,
            CreateFindingInput {
                scan_id: scan.id,
                title: "Missing Content-Security-Policy header".to_string(),
                severity: "medium".to_string(),
                confidence: "high".to_string(),
                endpoint: "https://staging.example.com".to_string(),
                parameter_name: None,
                evidence_json: "{}".to_string(),
                remediation: "Add CSP".to_string(),
                cwe: None,
                owasp_category: None,
                dedupe_key: Some("passive.missing_csp|https://staging.example.com".to_string()),
            },
        )
        .expect("finding");

        let updated = update_finding_status(
            temp_dir.path(),
            &db_path,
            UpdateFindingStatusInput {
                id: finding.id,
                status: "accepted_risk".to_string(),
            },
        )
        .expect("updated finding");

        assert_eq!(updated.status, "accepted_risk");
    }

    #[test]
    fn rejects_unknown_finding_status() {
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
        let finding = create_finding(
            temp_dir.path(),
            &db_path,
            CreateFindingInput {
                scan_id: scan.id,
                title: "Missing Content-Security-Policy header".to_string(),
                severity: "medium".to_string(),
                confidence: "high".to_string(),
                endpoint: "https://staging.example.com".to_string(),
                parameter_name: None,
                evidence_json: "{}".to_string(),
                remediation: "Add CSP".to_string(),
                cwe: None,
                owasp_category: None,
                dedupe_key: Some("passive.missing_csp|https://staging.example.com".to_string()),
            },
        )
        .expect("finding");

        let error = update_finding_status(
            temp_dir.path(),
            &db_path,
            UpdateFindingStatusInput {
                id: finding.id,
                status: "ignored_forever".to_string(),
            },
        )
        .expect_err("status rejected");

        assert!(matches!(
            error,
            StorageError::InvalidInput("finding status")
        ));
    }

    #[test]
    fn creates_and_lists_audit_logs() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("aegis.sqlite3");

        let audit_log = create_audit_log(
            temp_dir.path(),
            &db_path,
            CreateAuditLogInput {
                actor_user_id: Some("local-user".to_string()),
                action: "ai_fix_guide.generated".to_string(),
                entity_type: "finding".to_string(),
                entity_id: "finding-123".to_string(),
                severity: "info".to_string(),
                metadata_json_redacted: "{\"provider\":\"openai\"}".to_string(),
            },
        )
        .expect("audit log");
        let audit_logs = list_audit_logs(temp_dir.path(), &db_path).expect("audit logs");

        assert_eq!(audit_logs, vec![audit_log]);
        assert_eq!(audit_logs[0].actor_user_id, Some("local-user".to_string()));
        assert_eq!(audit_logs[0].action, "ai_fix_guide.generated");
        assert_eq!(
            audit_logs[0].metadata_json_redacted,
            "{\"provider\":\"openai\"}"
        );
    }

    #[test]
    fn rejects_unknown_audit_severity() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("aegis.sqlite3");

        let error = create_audit_log(
            temp_dir.path(),
            &db_path,
            CreateAuditLogInput {
                actor_user_id: None,
                action: "ai_fix_guide.failed".to_string(),
                entity_type: "finding".to_string(),
                entity_id: "finding-123".to_string(),
                severity: "critical".to_string(),
                metadata_json_redacted: "{}".to_string(),
            },
        )
        .expect_err("severity rejected");

        assert!(matches!(
            error,
            StorageError::InvalidInput("audit severity")
        ));
    }
}
