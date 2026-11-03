# Support Diagnostics Bundle

## Purpose

Aegis WebShield AI needs a repeatable support artifact for installation, storage, rule pack, and local engine troubleshooting. The bundle is generated locally and stored under the app data `diagnostics/` directory.

## Desktop Command

- Command: `collect_support_diagnostics`
- Output directory: `diagnostics/`
- File name: `aegis-diagnostics-<unix_timestamp>.json`
- Audit event: `support.diagnostics_generated`
- Verification command: `npm run support:verify-diagnostics -- <path-to-diagnostics.json>`
- Release preflight hook: set `AEGIS_SUPPORT_DIAGNOSTICS_PATH=<path-to-diagnostics.json>` before `npm run release:preflight`

The command returns file name, relative path, byte size, SHA-256, and generated timestamp so support staff can ask the user to attach the generated artifact.
The verification command accepts only safe repository-relative paths; absolute paths and `.`/`..` path segments are rejected before the artifact is read.

## Included Data

- Product name and app version
- OS, architecture, and platform family
- SQLite database file presence, file size, migration list, and workspace/project/target counts
- Local usage snapshot
- Community edition identifier (no license or online-account metadata)
- Local engine snapshot
- Rule pack status
- Latest 20 audit log records as a minimized support shape: action, entity type, severity, created timestamp, and parsed/reserialized redacted metadata only

## Excluded Data

The bundle must not include:

- API keys or secret store values
- License keys or license key hashes
- Approval note text
- Target URLs or browser observation URLs
- Finding evidence JSON or report bodies
- Raw AI prompts or provider responses

## Security Notes

- The bundle is generated only by explicit user action in the desktop UI.
- The audit event records only artifact file name, relative path, size, and SHA-256.
- Audit log ids, actors, and entity ids are omitted from support bundles to avoid leaking local identifiers or target-like values.
- Existing audit metadata is reused only after local command-level redaction, JSON parsing, blocked key checks, and raw URL checks. Invalid or unsafe legacy metadata is replaced with a small `metadata_omitted` marker instead of blocking bundle generation.
- Support or release operators can run `support:verify-diagnostics` before attaching a bundle to a ticket. The verifier requires a safe repository-relative artifact path, checks the required top-level structure, caps audit records at 20, rejects audit ids/actors/entity ids, rejects database paths, parses `recent_audit_logs[].metadata_json_redacted`, and scans for blocked fields such as API keys, authorization/cookie values, license key material, approval notes, URLs/endpoints, finding evidence, request/response bodies, report bodies, and raw prompts.
