# Safe Active Verifier

작성일: 2026-06-13  
상태: 구현 중인 자체 보안 엔진 active verifier 기준

## 목적

Safe active verifier는 명시 승인된 target에 대해 상태 변경 가능성이 낮은 `GET` query parameter만 변형해 취약점 신호를 확인한다. 1차 구현은 exploitation이 아니라 reflected input과 open redirect 가능성의 evidence 수집에 집중한다.

## 현재 구현

- Crate: `crates/aegis-scanner`
- 주요 함수: `run_safe_active_verifiers(target, client)`
- CLI 명령: `aegis-scan verify-active`
- Desktop 연결: `safe` scan profile의 `analyzing` phase에서 실행
- 대상:
  - 승인 문구가 있는 HTTP/HTTPS URL
  - 기존 query parameter가 있는 `GET` target
- 지원 규칙:
  - `active.reflected_xss_signal`
  - `active.open_redirect_signal`
  - `active.error_based_sqli_signal`
  - `active.path_traversal_signal`
- Desktop finding evidence JSON에는 `source`, 원문 `evidence`, `http_status`, `reproduction` metadata를 저장한다.
- `reproduction`은 method, 변형된 URL, parameter name, safe flag, scope note만 포함하며 payload 값이나 민감정보를 저장하지 않는다.
- Endpoint당 safe active 검증은 고유 query parameter 최대 10개만 대상으로 하며, parameter당 reflected input, open redirect, error-based SQLi, path traversal probe를 1회씩만 실행한다.
- HTTP probe request는 `retry_attempts = 0` 정책을 기본값으로 사용한다. 현재 `UreqHttpProbeClient`는 0보다 큰 retry budget을 거부해 scanner가 자동 재시도를 수행하지 않도록 고정한다.
- Safe active 실행은 승인된 원본 URL을 baseline으로 1회 probe하고, 각 finding evidence에 baseline 대비 변형 응답의 status와 body sample size delta를 저장한다. 원문 body나 payload 값은 저장하지 않는다.

## 안전 원칙

- `POST`, `PUT`, `PATCH`, `DELETE` 등 상태 변경 가능 method를 사용하지 않는다.
- 새 endpoint를 추측하지 않고, 사용자가 승인한 URL의 기존 query parameter만 변형한다.
- reflected input 검증은 harmless marker만 사용하며 script 실행 payload를 사용하지 않는다.
- open redirect 검증은 `https://aegis.invalid/open-redirect-probe` marker를 사용한다.
- error-based SQLi 검증은 안전 마커와 작은 quote 변형만 사용하며 데이터 추출, boolean-based, time-based 검증을 수행하지 않는다.
- path traversal 검증은 read-only 경로 marker만 사용하며 파일 쓰기, 삭제, 명령 실행 payload를 사용하지 않는다.
- HTTP adapter는 redirect를 자동 추적하지 않고 `Location` 응답을 evidence로 판단한다.
- private network와 localhost 대상은 기존 advanced approval 정책을 그대로 따른다.
- 자동 재시도는 하지 않는다. 같은 endpoint에 대한 반복 probe는 parameter budget과 scan scheduling 정책으로만 통제한다.

## 다음 확장 후보

- active verifier별 confidence 조정 정책
