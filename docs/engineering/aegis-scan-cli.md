# aegis-scan CLI Design

## Purpose

`aegis-scan` is the command line entry point for Aegis WebShield AI. It is designed for CI/CD gates, repeatable scans, and automation workflows that do not require opening the desktop app.

## Current Command

```powershell
aegis-scan scan --url https://example.com --approval-note "Owner approval captured in SEC-123" --fail-on medium --format json
```

Baseline-aware CI gate example:

```powershell
aegis-scan scan --url https://example.com --approval-note "Owner approval captured in SEC-123" --baseline-file .\previous-scan.json --fail-on never --fail-on-new medium --format sarif
```

OpenAPI orchestration example:

```powershell
aegis-scan scan --openapi .\openapi.yaml --base-url https://api.example.com --approval-note "Owner approval captured in SEC-123" --fail-on medium --format sarif
```

Supported options:

- `--url`: approved HTTP or HTTPS target URL. Use either `--url` or `--openapi`.
- `--openapi`: local OpenAPI 3.x JSON or YAML document to import and scan.
- `--base-url`: optional HTTP/HTTPS base URL override for `--openapi`.
- `--approval-note`: required authorization evidence for the scan target.
- `--allow-private-network`: explicit opt-in for localhost/private network targets.
- `--fail-on`: CI policy threshold. Supported values are `critical`, `high`, `medium`, `low`, `info`, `never`.
- `--baseline-file`: optional previous JSON report produced by `scan` or `verify-active`.
- `--fail-on-new`: optional CI policy threshold that only evaluates findings not present in the baseline report.
- `--format`: report format. Supported values are `json`, `text`, `sarif`.

When `--openapi` is used, the CLI imports endpoint candidates, probes only safe passive `GET` and `HEAD` operations, skips unsafe methods, and records endpoint-level results in JSON/SARIF output. It does not execute POST/PUT/PATCH/DELETE operations from the OpenAPI document.

CLI report renderers for `scan`, `scan-local`, `verify-active`, and `report export` use report-safe output copies. Target URLs, endpoint URLs, baseline findings, and finding evidence strip URL query values and fragments while preserving query parameter names, and mask authorization, cookie, token, password, secret, and private key values before JSON, text, or SARIF output is printed. Native active candidates also expose `source`, `requires_manual_confirmation`, and `finding_classification` metadata in JSON/SARIF output, and text summaries include a manual-confirmation count.

## Local Workspace Scan

```powershell
aegis-scan scan-local --app-data-dir "$env:APPDATA\com.aegis.webshield.ai" --target-id target-123 --profile passive --fail-on medium --format sarif
```

Supported options:

- `--app-data-dir`: local Aegis app data directory that contains the desktop SQLite database.
- `--database`: optional explicit SQLite database path. Defaults to `aegis-webshield-ai.sqlite3` inside `--app-data-dir`.
- `--project-id`: scan active targets in a saved desktop project.
- `--target-id`: scan one saved desktop target. Can be combined with `--project-id` to constrain lookup.
- `--profile`: local scan profile. Supported values are `passive`, `surface`, `safe`.
- `--fail-on`: CI policy threshold. Supported values are `critical`, `high`, `medium`, `low`, `info`, `never`.
- `--format`: report format. Supported values are `json`, `text`, `sarif`.

The command reads approved targets and saved endpoint candidates from local SQLite storage. If GET/HEAD endpoint candidates exist, it probes only those safe methods; otherwise it probes the target URL itself. `surface` profile also adds origin-scoped well-known sensitive path probes such as `/.env`, `/.git/config`, `/actuator/env`, and common admin consoles. `safe` profile also runs current safe active query-parameter verifiers for eligible endpoints.

## OpenAPI Import

```powershell
aegis-scan import-openapi --file .\openapi.yaml --base-url https://api.example.com --format json
```

Supported options:

- `--file`: local OpenAPI JSON or YAML document.
- `--base-url`: optional HTTP/HTTPS base URL override.
- `--format`: import result format. Supported values are `json`, `text`.

The import command does not make network requests. It reads the document, validates OpenAPI 3.x, and prints normalized endpoint candidates for later scan scheduling.

## URL Seed Import

```powershell
aegis-scan import-urls --file .\approved-urls.txt --format json
```

Supported options:

- `--file`: local text file containing one approved HTTP/HTTPS URL per line.
- `--format`: import result format. Supported values are `json`, `text`.

The import command does not make network requests. It ignores blank/comment lines, removes URL fragments, rejects non-HTTP schemes, and prints normalized seed candidates for later scan scheduling.

## HTML Crawl Candidate Extraction

```powershell
aegis-scan crawl-html --file .\page.html --base-url https://example.com/app --format json
```

Supported options:

- `--file`: local HTML document.
- `--base-url`: approved HTTP/HTTPS page URL used to resolve relative links.
- `--format`: extraction result format. Supported values are `json`, `text`.

The command does not make network requests. It parses local HTML and prints same-origin candidate URLs from anchors, forms, scripts, and stylesheets.

## Browser Crawl Log Candidate Extraction

```powershell
aegis-scan crawl-browser-log --file .\browser-observation.json --base-url https://example.com/app --format json
```

Supported options:

- `--file`: local JSON document containing browser crawler observations.
- `--base-url`: approved HTTP/HTTPS page URL used to constrain same-origin candidates.
- `--format`: extraction result format. Supported values are `json`, `text`.

The command does not launch a browser or make network requests. It normalizes route and network observations collected by a browser worker, keeps same-origin document/fetch/XHR candidates, and strips query values while preserving query parameter names. This is the stable ingestion contract for the planned Playwright worker.

Observation file generation:

```powershell
npm run browser:crawl -- --url https://example.com/app --approval-note "Owner approval captured in SEC-123" --out .\browser-observation.json
```

The worker uses Playwright Chromium. Run `npx playwright install chromium` once on machines that will execute browser crawling. The worker stores only approval-note presence, not the approval note text, and strips query values before writing the observation file.

Browser observation JSON shape:

```json
{
  "routes": ["https://example.com/app/dashboard?tab=profile"],
  "requests": [
    {
      "method": "GET",
      "url": "https://example.com/api/users?search=alice",
      "resource_type": "xhr"
    }
  ]
}
```

## Approved URL Crawl

```powershell
aegis-scan crawl-url --url https://example.com --approval-note "Owner approval captured in SEC-123" --max-pages 25 --max-depth 2 --format json
```

Supported options:

- `--url`: approved HTTP or HTTPS seed URL.
- `--approval-note`: required authorization evidence for the crawl target.
- `--allow-private-network`: explicit opt-in for localhost/private network targets.
- `--max-pages`: maximum fetched HTML pages, capped at 50.
- `--max-candidates`: maximum collected endpoint candidates, capped at 250.
- `--max-depth`: same-origin crawl depth limit, capped at 3.
- `--format`: crawl result format. Supported values are `json`, `text`.

The command uses the same explicit approval and private-network policy as `scan`. It validates crawl bounds before any network request, only schedules `GET` requests for same-origin HTML traversal, and records POST forms as candidates without executing POST requests.

## Safe Active Verification

```powershell
aegis-scan verify-active --url "https://example.com/search?q=test&next=/home" --approval-note "Owner approval captured in SEC-123" --fail-on medium --format json
```

Baseline-aware active verification gate example:

```powershell
aegis-scan verify-active --url "https://example.com/search?q=test&next=/home" --approval-note "Owner approval captured in SEC-123" --baseline-file .\previous-active.json --fail-on never --fail-on-new medium --format sarif
```

Supported options:

- `--url`: approved HTTP or HTTPS URL with query parameters to verify.
- `--approval-note`: required authorization evidence for the verification target.
- `--allow-private-network`: explicit opt-in for localhost/private network targets.
- `--fail-on`: CI policy threshold. Supported values are `critical`, `high`, `medium`, `low`, `info`, `never`.
- `--baseline-file`: optional previous JSON report produced by `scan` or `verify-active`.
- `--fail-on-new`: optional CI policy threshold that only evaluates findings not present in the baseline report.
- `--format`: report format. Supported values are `json`, `text`, `sarif`.

The command only mutates existing query parameters through `GET` requests. Current safe active checks look for reflected input, open redirect, error-based SQL injection, and path traversal file disclosure signals using non-destructive markers. Redirects are not followed automatically; redirect evidence is taken from the response URL or `Location` header. SQL injection checks do not extract data or run boolean/time-based probes. Path traversal checks use read-only path markers and never attempt writes, deletes, or command execution. Active finding evidence includes a redacted baseline response diff summary with status and body sample size delta only.

## Saved Scan Report Export

```powershell
aegis-scan report export --app-data-dir "$env:APPDATA\com.aegis.webshield.ai" --scan-id scan-123 --format sarif
```

Supported options:

- `--app-data-dir`: local Aegis app data directory that contains the desktop SQLite database.
- `--database`: optional explicit SQLite database path. Defaults to `aegis-webshield-ai.sqlite3` inside `--app-data-dir`.
- `--scan-id`: saved desktop scan id to export.
- `--format`: report format. Supported values are `json`, `text`, `sarif`.

The command reads saved scan/finding records from local SQLite storage and does not run network requests. JSON, text, and SARIF output use a report-safe copy of the saved records: URL query values and fragments are stripped while query parameter names are preserved, and evidence fields such as authorization, cookies, tokens, passwords, secrets, and private keys are redacted. SARIF output preserves finding status, confidence, CWE/OWASP metadata, parameter context, native source/manual-confirmation metadata, and redacted evidence properties for CI/code scanning ingestion.

## Rule Pack Validation

```powershell
aegis-scan rules test --path .\rules --format json
aegis-scan rules feed-sign --file .\rule-feed.json --private-key-hex <ed25519-private-key-seed-hex> --out .\signed-rule-feed.json
aegis-scan rules feed-check --file .\rule-feed.json --current-version 2026.06.12 --format json
aegis-scan rules feed-check --file .\rule-feed.json --public-key-hex <ed25519-public-key-hex> --format json
aegis-scan rules bundle-check --file .\rule-pack.zip --expected-manifest-sha256 <manifest-sha256> --public-key-hex <ed25519-public-key-hex> --format json
```

Supported options:

- `--path`: a JSON rule document or a directory containing JSON rule documents.
- `--private-key-hex`: 32-byte Ed25519 signing key seed in hex for `rules feed-sign`.
- `--out`: optional signed feed output path. If omitted with JSON output, the signed feed JSON is printed to stdout.
- `--file`: a rule pack update feed JSON document for `rules feed-check`, or a ZIP rule pack bundle for `rules bundle-check`.
- `--current-version`: optional current local rule pack version used to report update availability.
- `--expected-manifest-sha256`: optional expected SHA-256 of bundle root `manifest.json` for `rules bundle-check`.
- All supported rule channel labels are available without activation. The former `--pro-active` flag has been removed.
- `--public-key-hex`: optional 32-byte Ed25519 public key in hex. When provided, the feed must include a valid `signature`; bundle checks require root `manifest.sig` as a detached signature over `manifest.json`.
- `--format`: validation report format. Supported values are `json`, `text`.

The command validates local rule metadata without network requests. Each JSON document must contain a top-level `rules` array. Rules are checked for unique IDs, known severity and confidence values, optional boolean `enabled` metadata, evidence/remediation text, CWE format, OWASP category format, and explicit CWE metadata for rule IDs that are not covered by the built-in triage mapping. The command exits with code `2` when validation issues are found, so it can be used as a CI gate before shipping a rule pack.

`rules feed-sign` signs the canonical feed payload and writes a `signature` field without printing the private key. `rules feed-check` validates the update feed schema without fetching the manifest. It checks latest version text, channel, HTTPS manifest URL, manifest SHA-256 format, optional Ed25519 feed signature, and supported channel labels. The command exits with code `2` when the feed is invalid, when a provided public key cannot verify the feed signature, or when the channel is unsupported. All supported legacy channel labels are available without activation.

`rules bundle-check` validates an offline ZIP rule pack bundle without extracting it to disk. The bundle must contain a root `manifest.json`; optional signature verification uses root `manifest.sig` as a 128-character Ed25519 signature hex over the exact manifest bytes. The command rejects archive entries with absolute paths, drive prefixes, backslashes, empty path segments, or `..` traversal segments, limits the archive to 10MB, limits each entry to 2MB, and checks manifest version, channel, rule count, enabled/disabled counts, unique rule IDs, optional severity values, expected manifest SHA-256, and supported channel labels. Stored and deflated ZIP entries are supported for manifest reads.

## Exit Codes

- `0`: scan completed and did not violate the configured gate policy.
- `1`: CLI usage, validation, network, serialization, or scan execution failure.
- `2`: scan completed but findings violated the configured gate policy, or a CI validation command found rule/feed issues.

When `--baseline-file` is provided, JSON and text reports include baseline diff counts for new, recurring, and resolved findings. SARIF output also includes `baseline_status` result properties and run-level baseline counts. `--fail-on-new` can be used with `--fail-on never` to fail only on newly introduced findings. Baseline comparison fingerprints canonicalize URLs found in finding evidence by removing fragments and replacing query values with sorted query parameter names.

## Security Rules

- The CLI uses the same explicit approval model as the desktop app.
- Private network and localhost targets remain blocked unless `--allow-private-network` is provided.
- The first implementation only runs safe passive probing.
- Destructive payloads are not part of the CLI gate.
- CI output must not include secrets or authorization headers.
- Rule feed signing private keys must come from the release secret store and must not be committed or printed in logs.

## Roadmap

- Extend baseline diff policy to saved desktop scan reports.
