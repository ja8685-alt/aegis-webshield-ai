# OpenAPI Importer Design

## Purpose

The OpenAPI importer converts approved API specifications into normalized scan candidates for the custom Aegis WebShield AI engine.

## Current Scope

- Supports OpenAPI 3.x documents.
- Accepts JSON first, then YAML as a compatibility input.
- Reads the first usable HTTP or HTTPS `servers[].url`.
- Applies `servers[].variables.*.default` values before normalizing server URLs.
- Allows a caller-provided base URL override for documents without a server block.
- Extracts method, path, full URL, operation ID, and path/operation parameters.
- Resolves local JSON Pointer `$ref` values for path items and parameters.
- Preserves operation tags and security requirement scheme names.
- Exposes a desktop Tauri command for pasted document analysis.
- Desktop target creation supports local `.json`, `.yaml`, and `.yml` file selection through a bounded browser file input.
- Shows imported endpoint candidates in the Projects & Approved Targets screen.
- Persists imported endpoint candidates per approved target in local SQLite.
- Runs saved GET/HEAD endpoint candidates during safe passive scan execution with matching HTTP methods.
- Does not perform network requests.
- Does not import authentication secrets.

## Security Rules

- Reject empty documents.
- Reject OpenAPI 2.x / Swagger 2.0 documents for now.
- Reject non-HTTP server URLs such as `file://`.
- Accept UTF-8 BOM input from Windows-created specification files.
- Keep endpoint extraction deterministic and bounded.
- Enforce a maximum endpoint count of 5000 before the importer can feed scan scheduling.
- Local endpoint persistence also rejects target endpoint replacement batches above 5000 before mutating existing endpoint records.
- Target approval and private network checks still happen in the scan scope layer before execution.
- Passive probe execution only allows GET and HEAD methods.
- Security requirement metadata stores scheme names only; scopes or credential values are not used as authentication material.

## Dependency Note

The first implementation uses `serde_json` and `serde_yaml` for parsing. `serde_yaml` is marked deprecated upstream, so the importer should isolate YAML parsing behind this crate and revisit the YAML parser before release candidate hardening.

## Next Steps

- Extend `$ref` support beyond local JSON Pointer references when a safe local-file policy exists.
- Extend scan scheduling beyond GET/HEAD after safe active verifier policy is implemented.
