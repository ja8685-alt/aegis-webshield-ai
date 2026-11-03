# Aegis WebShield AI 시큐어 코딩 가이드

작성일: 2026-06-12  
적용 범위: 전체 개발 과정  
대상 스택: Rust, Tauri, React/TypeScript, SQLite, Python 보조 도구

## 1. 기본 원칙

- 보안 제품이므로 모든 기능은 기본적으로 보수적인 동작을 선택한다.
- 외부 요청, 파일 접근, 프로세스 실행, 리포트 생성, AI API 호출은 명시적 정책을 통과해야 한다.
- UI에서 숨기는 제한은 보안 통제가 아니다. 중요한 제한은 Local Engine Service와 Rust core에서 강제한다.
- 민감정보는 수집하지 않는 것을 우선하고, 필요한 경우 최소 범위로 저장하며, 출력 전 항상 마스킹한다.
- 실패 메시지는 사용자에게 필요한 수준만 보여주고, 상세 원인은 진단 로그에 제한적으로 남긴다.

## 2. 입력 검증

모든 사용자 입력은 길이, 형식, 허용 문자, 허용 범위를 검증한다.

검증 대상:

- URL, API base URL, OpenAPI URL.
- 프로젝트명, 대상명, 리포트명.
- Header name/value.
- Cookie, Bearer token, API Key.
- 파일 경로, import 파일명.
- CIDR, IP, host.
- CLI 인자.

규칙:

- URL은 `http`, `https`만 허용한다.
- 기본은 명시 승인된 URL/API만 스캔한다.
- 사설망, IP, CIDR은 고급 설정에서 별도 허용된 경우만 허용한다.
- cloud metadata endpoint는 항상 차단한다.
- 문자열 길이는 API와 UI 양쪽에서 제한한다.
- allowlist가 가능한 곳은 allowlist를 사용한다.

## 3. 스캔 안전성

스캔 요청은 반드시 `Scope Validator`와 `RequestPolicyEngine`을 통과해야 한다.

기본 차단:

- scope 밖 redirect.
- `localhost`, private CIDR, IP 직접 스캔. 단, 고급 설정에서 명시 허용한 경우 제외.
- cloud metadata endpoint.
- destructive method 또는 payload.
- 결제, 삭제, 탈퇴, 메일 발송 등 상태 변경 위험이 높은 액션.

기본 점검 범위:

- Passive checks.
- Surface exposure checks.
- OpenAPI importer.
- HTTP crawler.
- Safe active checks: reflected XSS, open redirect.

## 4. 비밀정보와 인증정보

저장 금지:

- API Key 평문 DB 저장.
- Authorization header 평문 로그.
- Cookie/Set-Cookie 원문 리포트 출력.
- private key, password, token 원문 저장.

저장 방식:

- 사용자 API Key는 OS secure storage에 저장한다.
- SQLite에는 secret reference 또는 설정 상태만 저장한다.
- 리포트와 로그에는 마스킹된 값만 저장한다.

마스킹 키워드:

- `authorization`
- `cookie`
- `set-cookie`
- `token`
- `password`
- `secret`
- `api_key`
- `private_key`
- `access_key`

## 5. Rust 코딩 기준

- `unwrap`, `expect`는 앱 초기화처럼 복구 불가능한 영역 외에는 사용하지 않는다.
- 에러 타입은 도메인별로 정의하고 사용자 메시지와 내부 로그 메시지를 분리한다.
- 외부 명령 실행 시 shell string을 만들지 않고 executable과 args를 분리한다.
- 파일 경로는 canonicalize 후 앱 데이터 디렉터리 내부인지 확인한다.
- 네트워크 요청은 timeout, retry budget, rate limit을 가진다.
- 테스트는 보안 정책 실패 케이스를 반드시 포함한다.

## 6. Tauri 보안 기준

- Local API는 기본적으로 `127.0.0.1`에만 bind한다.
- 매 실행마다 local token을 발급한다.
- Tauri command는 필요한 기능만 노출한다.
- command 인자는 Rust에서 다시 검증한다.
- 파일 시스템 접근은 앱 데이터 디렉터리로 제한한다.
- 외부 URL open은 명시 allowlist를 사용한다.
- Tauri CSP는 release candidate에서 non-empty 정책으로 고정하고 `verify:tauri-security`로 `csp: null`, unsafe script/style, wildcard source를 차단한다.

## 7. React/TypeScript 기준

- API 응답과 설정 파일은 Zod 또는 동등한 schema로 검증한다.
- HTML 삽입은 금지한다. 필요한 경우 sanitize 후 제한적으로 사용한다.
- 긴 URL, header, evidence는 UI에서 안전하게 줄바꿈 또는 truncate한다.
- 유료 잠금은 사용하지 않는다. 대상 승인과 리소스 안전 제한은 UI와 별개로 Rust에서 강제한다.
- 로그와 리포트 preview는 마스킹된 데이터만 사용한다.

## 8. SQLite와 로컬 저장소

- 모든 SQL은 prepared statement를 사용한다.
- migration은 버전 순서대로 적용한다.
- DB 파일은 앱 데이터 디렉터리 아래에 둔다.
- 원본 HTTP body 전체 저장은 기본 비활성으로 둔다.
- evidence excerpt는 길이 제한과 마스킹을 적용한다.
- export/import 파일은 확장자, 크기, 구조를 검증한다.

## 9. AI API 사용 기준

- 사용자 API Key는 OS secure storage에 저장한다.
- AI 요청 payload에는 필요한 finding evidence만 포함한다.
- token, cookie, password, secret은 AI 요청 전에 마스킹한다.
- AI 응답은 확정 판정이 아니라 보조 가이드로 표시한다.
- prompt version과 모델명을 저장해 재현 가능성을 확보한다.

## 10. 리포트와 로그

리포트:

- 고객 제출용 리포트에는 민감정보 원문을 넣지 않는다.
- 재현 요청은 token/cookie를 placeholder로 치환한다.
- 내부 경로와 scanner stderr는 기본 제외한다.

로그:

- 사용자에게 보이는 로그는 짧고 안전한 메시지로 제한한다.
- 상세 진단 번들은 사용자가 명시 export할 때만 생성한다.
- 진단 번들도 마스킹을 통과해야 한다.

## 11. 의존성 관리

- Rust crate와 npm package는 lockfile을 커밋한다.
- 새 의존성 추가 시 목적과 대체 가능성을 검토한다.
- 보안 취약 의존성은 릴리스 전 점검한다.
- 빌드 도구와 runtime dependency를 구분한다.

## 12. 커밋 전 보안 체크리스트

- [ ] scope 밖 요청 가능성이 없는가?
- [ ] secret이 로그, 리포트, 테스트 fixture에 들어가지 않았는가?
- [ ] 사용자 입력에 길이/형식 검증이 있는가?
- [ ] SQL/command 실행이 문자열 결합으로 만들어지지 않았는가?
- [ ] 대상 승인과 리소스 안전 제한이 core/service에서 강제되는가?
- [ ] 실패 메시지가 민감정보를 노출하지 않는가?
- [ ] 테스트에 실패/차단 케이스가 포함되어 있는가?
- [ ] 반복 오류와 보안상 주의점이 개발 로그에 기록되었는가?
