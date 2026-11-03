# AI Provider and Audit Log Design

## Purpose

Aegis WebShield AI uses the user's configured API key to generate AI Fix Guides for findings. The desktop app must treat this as a commercial, auditable feature rather than a demo helper.

## Provider Adapter

- The first provider adapter is OpenAI Responses API.
- API keys are loaded from the platform secret store at call time.
- API keys, prompts, and raw evidence must not be written to SQLite audit logs.
- The provider adapter validates required input before making an outbound request.
- OpenAI requests use `store: false` and a structured `text.format` JSON schema so the app receives `summary`, `safe_fix_steps`, `verification_steps`, and `cautions` as typed fields instead of parsing free-form prose.
- The provider prompt keeps stable security instructions separate from dynamic finding context and redacts common secret/token patterns before sending evidence, including API keys, bearer tokens, access/refresh tokens, passwords, secret/private key fields, cookies, and Set-Cookie values.
- AI Fix Guide is available without activation or monthly quotas. The user supplies a provider API key; validation and redaction still precede the outbound request. Provider charges may apply.
- Provider errors are returned to the UI as user-visible failures and are also recorded as audit events.

## Audit Events

AI Fix Guide calls, report exports, endpoint imports, and security workflow changes write audit events to the local SQLite `audit_logs` table.

- `ai_fix_guide.requested`: written before secret lookup and provider execution.
- `ai_fix_guide.generated`: written after a successful provider response.
- `ai_fix_guide.failed`: written when secret lookup or provider execution fails.
- `report.generated`: written after a report export passes plan and usage checks.
- `report.artifacts_cleaned`: written after local report artifact cleanup runs.
- `rule_pack.manifest_imported`: written after an offline rule pack manifest passes validation and is saved locally.
- `rule_pack.manifest_rolled_back`: written after a previous offline rule pack manifest is restored.
- `rule_pack.feed_checked`: written after a rule pack update feed document is validated and compared with the current local manifest.
- `finding.status_changed`: written after a finding workflow status changes.
- `target.endpoints_replaced`: written after OpenAPI, URL seed, HTML crawler, live crawler, or browser observation endpoint candidates replace the saved target endpoint set.
- `scan.recovered_after_restart`: written when app startup moves interrupted non-terminal scans back to `queued` without automatically starting outbound scan traffic.

Audit metadata is redacted JSON and currently contains:

- `provider`
- `account_present`
- `account_hash` as a short non-reversible SHA-256 prefix when an account label is provided
- `error` when applicable
- report `format`, `finding_count`, `artifact_file_name`, `artifact_relative_path`, `artifact_size_bytes`, and `artifact_sha256`
- report cleanup `older_than_days`, `deleted_count`, `deleted_bytes`, and `scheduled`
- rule pack import/rollback `version`, `channel`, `rule_count`, and `manifest_sha256`
- rule pack feed check `current_version`, `latest_version`, `channel`, `update_available`, `entitlement_allowed`, `blocked_reason`, `manifest_sha256`, `manifest_url_present`, and `signature_verified`
- finding `previous_status`, `requested_status`, `new_status`, `severity`, and `title`
- endpoint import `source` and `endpoint_count`
- scan recovery `recovered_scan_count`, `restored_phase`, and `auto_started`

## Usage Accounting

The local usage snapshot counts monthly AI Fix Guide usage from `ai_fix_guide.generated` audit events. Failed calls are auditable but do not count as successful guide usage.

## Desktop Display

The dashboard shows recent local audit records in the Security Events panel.

- Source command: `list_local_audit_logs`
- Row limit: latest 8 records in the dashboard view
- Metadata display: redacted JSON only
- Refresh behavior: initial load, periodic scan refresh, report export, AI Fix Guide generation, and manual refresh

## Security Rules

- Never persist API keys outside the platform secret store.
- Never store raw prompt content, full evidence payloads, or authorization headers in audit metadata.
- Never store raw AI provider account labels, email addresses, API keys, tokens, passwords, cookies, Set-Cookie values, or provider authorization errors in audit metadata.
- Never store report body or finding evidence JSON in audit metadata.
- Never store approved target URLs, approval note text, or browser observation URL query values in endpoint import audit metadata.
- Keep the audit metadata schema small and intentionally redacted.
- Validate audit action, entity, severity, and metadata lengths before insertion.
- Preserve explicit user approval boundaries for scan targets; AI guidance must not expand scope.
