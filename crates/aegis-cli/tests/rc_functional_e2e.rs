use std::fs;

use aegis_cli::{
    render_local_scan_report, render_saved_scan_report, run_local_scan_command,
    run_report_export_command, run_rules_feed_check_command, run_rules_test_command, FailOn,
    LocalScanCommand, LocalScanProfile, OutputFormat, ReportExportCommand, ReportFormat,
    RulesFeedCheckCommand, RulesTestCommand,
};
use aegis_scanner::{
    HttpHeader, HttpProbeClient, HttpProbeRequest, HttpProbeResponse, ScannerError,
};
use aegis_storage::{
    create_finding, create_project, create_scan, create_target, replace_target_endpoints,
    update_scan_phase, CreateFindingInput, CreateProjectInput, CreateScanInput,
    CreateTargetEndpointInput, CreateTargetInput, ReplaceTargetEndpointsInput,
    UpdateScanPhaseInput,
};

struct DeterministicClient;

impl HttpProbeClient for DeterministicClient {
    fn execute(&self, request: &HttpProbeRequest) -> Result<HttpProbeResponse, ScannerError> {
        assert_eq!(request.method, "GET");
        assert_eq!(request.retry_attempts, 0);
        Ok(HttpProbeResponse {
            final_url: request.url.clone(),
            status_code: 200,
            headers: vec![HttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body_sample: br#"{"status":"ok"}"#.to_vec(),
        })
    }
}

#[test]
fn rc_local_scan_report_and_unrestricted_rule_flow() {
    let temp_dir = tempfile::tempdir().expect("temporary app data");
    let database_path = temp_dir.path().join("aegis-webshield-ai.sqlite3");
    let project = create_project(
        temp_dir.path(),
        &database_path,
        CreateProjectInput {
            name: "RC E2E".to_string(),
            description: "Release candidate functional flow".to_string(),
        },
    )
    .expect("project created");
    let target = create_target(
        temp_dir.path(),
        &database_path,
        CreateTargetInput {
            project_id: project.id.clone(),
            target_type: "openapi".to_string(),
            name: "Staging API".to_string(),
            url: "https://staging.example.com".to_string(),
            approval_note: "SEC-RC-E2E owner approval".to_string(),
            allow_private_network: false,
        },
    )
    .expect("target created");
    replace_target_endpoints(
        temp_dir.path(),
        &database_path,
        ReplaceTargetEndpointsInput {
            target_id: target.id.clone(),
            endpoints: vec![CreateTargetEndpointInput {
                method: "GET".to_string(),
                path: "/health".to_string(),
                url: "https://staging.example.com/health".to_string(),
                operation_id: Some("health".to_string()),
                parameters_json: r#"[{"name":"token","in":"query"}]"#.to_string(),
            }],
        },
    )
    .expect("endpoint persisted");

    let local_command = LocalScanCommand {
        app_data_dir: temp_dir.path().to_path_buf(),
        database: Some(database_path.clone()),
        project_id: Some(project.id.clone()),
        target_id: Some(target.id.clone()),
        profile: LocalScanProfile::Passive,
        fail_on: FailOn::Medium,
        format: ReportFormat::Json,
    };
    let local_report =
        run_local_scan_command(&local_command, &DeterministicClient).expect("local scan completed");
    assert_eq!(local_report.target_count, 1);
    assert_eq!(local_report.endpoint_count, 1);
    assert!(local_report.finding_count > 0);
    let local_json =
        render_local_scan_report(&local_report, ReportFormat::Json).expect("local JSON report");
    assert!(local_json.contains("https://staging.example.com/health"));

    let scan = create_scan(
        temp_dir.path(),
        &database_path,
        CreateScanInput {
            project_id: project.id,
            target_id: target.id,
            profile: "safe".to_string(),
        },
    )
    .expect("scan record created");
    create_finding(
        temp_dir.path(),
        &database_path,
        CreateFindingInput {
            scan_id: scan.id.clone(),
            title: "Manual confirmation candidate".to_string(),
            severity: "high".to_string(),
            confidence: "medium".to_string(),
            endpoint: "https://staging.example.com/search?q=raw-query-secret#fragment".to_string(),
            parameter_name: Some("q".to_string()),
            evidence_json: serde_json::json!({
                "source": "native_active",
                "requires_manual_confirmation": true,
                "finding_classification": "candidate",
                "authorization": "Bearer raw-authorization-secret",
                "url": "https://staging.example.com/search?token=raw-query-secret#fragment"
            })
            .to_string(),
            remediation: "Confirm manually before remediation".to_string(),
            cwe: Some("CWE-79".to_string()),
            owasp_category: Some("A03 Injection".to_string()),
            dedupe_key: Some("rc-e2e-candidate".to_string()),
        },
    )
    .expect("finding persisted");
    update_scan_phase(
        temp_dir.path(),
        &database_path,
        UpdateScanPhaseInput {
            id: scan.id.clone(),
            phase: "completed".to_string(),
            status_message: "RC E2E completed".to_string(),
        },
    )
    .expect("scan completed");

    let export_command = ReportExportCommand {
        app_data_dir: temp_dir.path().to_path_buf(),
        database: Some(database_path.clone()),
        scan_id: scan.id,
        format: ReportFormat::Json,
    };
    let saved_report = run_report_export_command(&export_command).expect("saved report loaded");
    let saved_json =
        render_saved_scan_report(&saved_report, ReportFormat::Json).expect("saved JSON report");
    let saved_sarif =
        render_saved_scan_report(&saved_report, ReportFormat::Sarif).expect("saved SARIF report");
    for report in [&saved_json, &saved_sarif] {
        assert!(report.contains("requires_manual_confirmation"));
        assert!(report.contains("candidate"));
        assert!(!report.contains("raw-query-secret"));
        assert!(!report.contains("raw-authorization-secret"));
        assert!(!report.contains("#fragment"));
    }

    let rule_path = temp_dir.path().join("rules.json");
    fs::write(
        &rule_path,
        serde_json::json!({
            "rules": [{
                "id": "passive.missing_csp",
                "title": "CSP is missing",
                "severity": "medium",
                "confidence": "high",
                "cwe": "CWE-693",
                "owasp_category": "A05 Security Misconfiguration",
                "evidence": "CSP header absent",
                "recommendation": "Add a restrictive CSP"
            }]
        })
        .to_string(),
    )
    .expect("rule fixture");
    let rules = run_rules_test_command(&RulesTestCommand {
        path: rule_path,
        format: OutputFormat::Json,
    })
    .expect("rule pack tested");
    assert!(rules.passed);

    let feed_path = temp_dir.path().join("feed.json");
    fs::write(
        &feed_path,
        serde_json::json!({
            "latest_version": "2026.08.01-pro",
            "channel": "pro",
            "published_at": "2026-08-01T00:00:00Z",
            "minimum_app_version": "0.1.0",
            "manifest_url": "https://updates.example.com/aegis/rules/manifest.json",
            "manifest_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        })
        .to_string(),
    )
    .expect("feed fixture");
    for channel in [
        "built-in",
        "community",
        "local",
        "pro",
        "team",
        "enterprise",
    ] {
        let mut document: serde_json::Value =
            serde_json::from_slice(&fs::read(&feed_path).unwrap()).unwrap();
        document["channel"] = channel.into();
        fs::write(&feed_path, serde_json::to_vec(&document).unwrap()).unwrap();
        let feed = run_rules_feed_check_command(&RulesFeedCheckCommand {
            file: feed_path.clone(),
            current_version: Some("2026.07.31".to_string()),
            public_key_hex: None,
            format: OutputFormat::Json,
        })
        .expect("feed evaluated without license activation");
        assert!(feed.passed, "{channel}: {:?}", feed.issues);
        assert!(feed.entitlement_allowed);
        assert!(feed.update_available);
    }
}
