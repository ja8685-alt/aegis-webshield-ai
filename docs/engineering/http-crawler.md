# HTTP Crawler

## 2026-06-25 Browser Worker Output Path Note

- Playwright browser crawl worker `--out` must be a safe repository-relative path.
- Absolute paths and `.`/`..` path segments are rejected before browser observation JSON is written.
- Browser worker runtime options are bounded: `--wait-ms` max 10000, `--timeout-ms` max 60000, and `--max-requests` max 1000.
- Desktop Tauri `crawl_approved_url` enforces server-side crawl bounds: max pages 50, max candidates 250, and max depth 3.

작성일: 2026-06-13  
상태: 구현 중인 자체 보안 엔진 crawler 기준

## 목적

HTTP crawler는 사용자가 승인한 URL과 HTML 문서에서 같은 origin의 endpoint 후보를 수집해 scan scheduler가 더 넓은 attack surface를 안전하게 검사할 수 있게 한다. 현재 구현은 HTML parser 기반 후보 추출기, bounded crawl scheduler, browser observation normalizer로 나뉜다.

## 현재 구현

- Crate: `crates/aegis-crawler`
- 주요 함수:
  - `extract_html_candidates(base_url, html)`
  - `crawl_approved_html_surface(seed_url, options, client)`
  - `normalize_browser_observations(base_url, document)`
- HTML parser는 `scraper`를 사용한다.
- fetch 실행은 `CrawlerFetchClient` trait로 주입한다.
- 수집 대상은 `a[href]`, `form[action]`, `script[src]`, `link[href]`다.
- URL fragment를 제거한다.
- `mailto:`, `tel:`, `javascript:`, 빈 값, fragment-only 값은 무시한다.
- base URL과 같은 origin의 `http`/`https` URL만 선택한다.
- `GET|url`, `POST|url` 기준으로 중복을 제거한다.
- form method는 현재 `GET`과 `POST`만 구분하고 나머지는 `GET`으로 안전하게 축소한다.
- form input/select/textarea/button의 `name`, `required`, query/body 위치를 수집하되 입력값은 저장하지 않는다.
- CLI `aegis-scan crawl-html` 명령으로 로컬 HTML 파일의 candidate 추출 결과를 확인할 수 있다.
- CLI `aegis-scan crawl-url` 명령으로 명시 승인된 seed URL을 bounded same-origin crawler로 순회할 수 있다.
- CLI `aegis-scan crawl-browser-log` 명령으로 browser worker가 남긴 route/XHR/fetch observation JSON을 endpoint 후보로 정규화할 수 있다.
- Node script `npm run browser:crawl -- --url ... --approval-note ... --out ...`로 Playwright Chromium 기반 browser observation JSON을 생성할 수 있다.
- `aegis-scanner`의 `UreqHttpProbeClient`가 `CrawlerFetchClient`를 구현해 CLI와 엔진에서 같은 HTTP 실행 adapter를 사용한다.
- Desktop target creation flow에서 pasted HTML 또는 `.html`, `.htm` 파일과 base URL을 분석해 endpoint 후보로 저장할 수 있다.
- Desktop target creation flow에서 승인 문구가 있는 target URL을 직접 bounded same-origin crawler로 순회하고 endpoint 후보로 저장할 수 있다.
- Desktop target creation flow에서 browser observation JSON paste 또는 `.json` 파일과 base URL을 분석해 route/XHR/fetch endpoint 후보로 저장할 수 있다.
- 저장된 crawler endpoint 후보는 기존 scan runner의 endpoint scheduling에 사용한다.
- `CrawlerOptions`로 `max_pages`, `max_candidates`, `max_depth`, `max_response_bytes`, `user_agent`를 제한한다.
- `crawl_approved_html_surface`는 BFS 방식으로 `GET` HTML 문서만 순회하고, non-HTML response는 link parsing 없이 page 기록만 남긴다.
- browser worker와 observation normalizer는 query value를 저장하지 않고 query parameter name만 metadata로 보존한다.

## 안전 원칙

- crawler crate는 네트워크 요청을 직접 수행하지 않고, 호출자가 명시적으로 제공한 fetch client만 사용한다.
- 다른 origin은 후보에서 제외한다.
- redirect 후 fetch 이후 final URL이 seed와 같은 origin인지 다시 확인한다.
- crawler scheduler는 `GET` 요청만 생성한다.
- destructive payload 생성은 하지 않는다.
- POST form은 후보로 기록하되 passive probe 실행 단계에서는 기존 method policy에 의해 실행을 제한한다.
- Desktop 파일 입력은 브라우저 file input으로 읽고, HTML 문서와 browser observation JSON은 각각 2 MiB로 제한한다.

## Browser Worker 흐름

1. `npm install` 후 `npx playwright install chromium`으로 Chromium runtime을 준비한다.
2. `npm run browser:crawl -- --url https://example.com --approval-note "Owner approval captured in SEC-123" --out .\.aegis\browser-observation.json`을 실행한다.
3. Desktop target creation flow의 Browser observation 패널 또는 `aegis-scan crawl-browser-log --file .\.aegis\browser-observation.json --base-url https://example.com --format json`으로 endpoint 후보를 정규화한다.

worker는 route 변경과 `document`, `fetch`, `xhr` 요청만 기록한다. 승인 문구의 존재 여부만 저장하고 원문은 observation 파일에 저장하지 않는다.

## 다음 확장 후보

- Desktop target creation flow에서 browser worker 실행 자동화
- crawler 실행 이력 저장과 retry/resume metadata
- robots/sitemap 기반 seed 확장
- timeout, retry, redirect count 제한
