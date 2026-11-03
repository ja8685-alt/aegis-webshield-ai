# 2026-06-25 implementation note

- Sensitive token pattern analysis is limited to API/text content types (`application/json`, `+json`, XML, NDJSON, `text/plain`, `text/csv`) or responses already classified as sensitive by path/cookie context.
- HTML documentation/examples are not scanned for the generic token-name pattern unless another sensitive-response signal applies.
- `passive.csp_inline_without_nonce_or_hash` reports script/style directives that allow `'unsafe-inline'` without a nonce or SHA-256/384/512 hash source in the same directive.

# Passive Analyzer Rules

작성일: 2026-06-13  
상태: 구현 중인 자체 보안 엔진 규칙 기준

## 목적

이 문서는 Aegis WebShield AI 자체 엔진의 passive analyzer가 HTTP 응답을 어떻게 판정하는지 정리한다. 현재 단계의 passive rule은 사용자가 명시 승인한 URL/API에 대해 안전한 GET/HEAD 요청만 수행하고, 응답 헤더 기반의 낮은 침습도 진단을 우선 제공한다.

## 안전 원칙

- 기본 probe method는 `GET`이다.
- OpenAPI 등에서 저장된 endpoint method가 `HEAD`이면 `HEAD`로 probe할 수 있다.
- passive probe에서는 `POST`, `PUT`, `PATCH`, `DELETE` 등 상태 변경 가능성이 있는 method를 거부한다.
- 사설망, loopback, link-local, documentation IP 대역은 고급 설정에서 별도 허용되지 않으면 차단한다.
- finding evidence에는 HTTP body 전문을 저장하지 않고, 필요한 최소 증거만 저장한다.

## 현재 규칙

| Rule ID | Severity | 조건 | 권장 조치 |
| --- | --- | --- | --- |
| `passive.missing_csp` | Medium | `Content-Security-Policy` 누락 | 기본 CSP를 설정하고 script/style/resource 출처를 제한한다. |
| `passive.csp_allows_unsafe_inline` | Medium | CSP script/style source에 `'unsafe-inline'` 허용 | nonce, hash, 외부 script/style로 전환하고 inline 실행을 제거한다. |
| `passive.csp_allows_unsafe_eval` | Medium | CSP script source에 `'unsafe-eval'` 허용 | runtime string-to-code 실행 경로를 제거하고 `'unsafe-eval'`을 삭제한다. |
| `passive.csp_wildcard_source` | Low | CSP source directive에 `*` 허용 | 필요한 신뢰 origin만 명시한다. |
| `passive.csp_allows_insecure_http` | Low | CSP source directive에 `http:` 또는 `http://...` 허용 | HTTPS source로 전환하거나 legacy 예외를 명시적으로 관리한다. |
| `passive.missing_x_content_type_options` | Low | `X-Content-Type-Options` 누락 | `X-Content-Type-Options: nosniff`를 설정한다. |
| `passive.missing_hsts` | Medium | HTTPS 응답에서 `Strict-Transport-Security` 누락 | 적절한 `max-age`를 가진 HSTS를 설정한다. |
| `passive.missing_https_redirect` | Medium | HTTP 응답이 같은 host의 HTTPS URL로 3xx redirect하지 않음 | HTTP 요청을 canonical HTTPS origin으로 redirect한다. |
| `passive.missing_referrer_policy` | Low | `Referrer-Policy` 누락 | `strict-origin-when-cross-origin` 또는 `no-referrer` 등 정책을 설정한다. |
| `passive.missing_permissions_policy` | Low | `Permissions-Policy` 누락 | 앱에 필요 없는 browser feature를 명시적으로 제한한다. |
| `passive.missing_clickjacking_protection` | Medium | `X-Frame-Options`가 없고 CSP `frame-ancestors`도 없음 | CSP `frame-ancestors` 또는 `X-Frame-Options`로 frame 삽입을 제한한다. |
| `passive.missing_cross_origin_opener_policy` | Low | `Cross-Origin-Opener-Policy` 누락 | browser isolation이 필요한 화면에 COOP를 설정한다. |
| `passive.missing_cross_origin_resource_policy` | Low | `Cross-Origin-Resource-Policy` 누락 | cross-origin embedding을 제한해야 하는 resource에 CORP를 설정한다. |
| `passive.missing_x_permitted_cross_domain_policies` | Info | `X-Permitted-Cross-Domain-Policies` 누락 | legacy cross-domain policy가 필요 없으면 `none`을 설정한다. |
| `passive.server_header_disclosure` | Info | `Server` 헤더가 노출됨 | 서버 제품명/버전 노출을 최소화한다. |
| `passive.cookie_missing_secure` | Medium | HTTPS 응답의 `Set-Cookie`에 `Secure` 속성 누락 | HTTPS에서 전달되는 cookie에는 `Secure`를 설정한다. |
| `passive.cookie_missing_http_only` | Medium | `Set-Cookie`에 `HttpOnly` 속성 누락 | session 및 보안 민감 cookie에는 `HttpOnly`를 설정한다. |
| `passive.cookie_missing_same_site` | Low | `Set-Cookie`에 `SameSite` 속성 누락 | cross-site 전달이 필요 없으면 `SameSite=Lax` 또는 `SameSite=Strict`를 설정한다. |
| `passive.cookie_same_site_none_without_secure` | Medium | `SameSite=None` cookie에 `Secure` 속성 누락 | `SameSite=None`이 필요하면 `Secure`도 함께 설정한다. |
| `passive.cors_wildcard_with_credentials` | Medium | `Access-Control-Allow-Origin: *`와 credentialed CORS 조합 | 허용 origin allow-list를 사용하고 credentialed wildcard CORS를 제거한다. |
| `passive.sensitive_response_cacheable` | Low | 로그인/account/session/token/admin 또는 cookie 응답에 `no-store`/`no-cache` 정책 없음 | 민감 응답에 `Cache-Control: no-store`를 설정한다. |
| `passive.sensitive_token_pattern` | High | 응답 sample에 API key, access token, secret key 등 민감 토큰 패턴 존재 | 응답에서 secret을 제거하고 노출 가능 credential을 회전한다. |
| `passive.mixed_content_reference` | Low | HTTPS 응답 sample이 `http://` script/style/image/form resource를 참조 | 모든 하위 resource와 form action을 HTTPS로 제공한다. |
| `passive.source_map_exposed` | Low | `.map` 응답 또는 `sourceMappingURL` reference 노출 | production source map 공개를 제한하거나 인증 뒤로 이동한다. |

## 판정 기준

- Header name 비교는 대소문자를 구분하지 않는다.
- HSTS는 최종 URL이 `https://`로 시작하는 응답에서만 검사한다.
- HTTP canonical redirect는 3xx 응답과 같은 host의 HTTPS `Location`이 있을 때 통과로 본다.
- CSP 품질 분석은 CSP가 존재할 때 source directive를 파싱해 위험 token을 검사한다.
- Clickjacking 방어는 `X-Frame-Options` 또는 CSP `frame-ancestors` 중 하나가 있으면 통과로 본다.
- Cookie 분석은 `Set-Cookie` value 전체를 evidence에 저장하지 않고 cookie 이름과 누락 속성만 기록한다.
- Body sample 분석은 민감값 원문을 evidence에 저장하지 않고 매칭된 pattern 이름만 기록한다.
- Cache policy 분석은 민감 경로 또는 `Set-Cookie` 응답에서만 수행한다.
- 모든 browser security header가 있고, `Server` 헤더가 없으며, cookie 보안 속성이 충족되면 finding을 생성하지 않는다.

## 다음 확장 후보

- CSP nonce/hash 적용 수준 및 directive별 세분화 분석
- API response content-type 기반 민감정보 노출 신호 정교화
