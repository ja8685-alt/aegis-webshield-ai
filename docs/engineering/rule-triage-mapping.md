# Rule Triage Mapping

작성일: 2026-06-13  
상태: 구현 중인 자체 보안 엔진 triage 기준

## 목적

Rule triage mapping은 scanner rule id를 finding 저장에 필요한 confidence, CWE, OWASP category로 변환한다. 스캐너가 단순 문자열 결과를 저장하는 데서 멈추지 않고, 리포트와 AI Fix Guide가 바로 사용할 수 있는 보안 분류 정보를 갖도록 하는 단계다.

## 구현 위치

- Crate: `crates/aegis-triage`
- 주요 함수: `triage_rule(rule_id: &str) -> RuleTriage`
- Desktop 저장 연결: `src-tauri/src/main.rs`의 `store_passive_findings`

## 현재 매핑

| Rule group | Confidence | CWE | OWASP |
| --- | --- | --- | --- |
| Passive security header rules | high | CWE-693 | A05 Security Misconfiguration |
| Passive cookie attribute rules | high | CWE-614 | A05 Security Misconfiguration |
| Passive CORS/cache/mixed content/source map rules | medium | CWE-693 | A05 Security Misconfiguration |
| Passive sensitive token pattern rules | high | CWE-200 | A02 Cryptographic Failures |
| Passive server header disclosure | medium | CWE-200 | A05 Security Misconfiguration |
| Safe active reflected input signal | medium | CWE-79 | A03 Injection |
| Safe active open redirect signal | medium | CWE-601 | A01 Broken Access Control |
| Safe active error-based SQLi signal | medium | CWE-89 | A03 Injection |
| Safe active path traversal signal | high | CWE-22 | A01 Broken Access Control |
| Exposed `.git`, `.env`, backup/dump files | high | CWE-538 | A01 Broken Access Control |
| Reachable debug/admin endpoints | medium | CWE-284 | A01 Broken Access Control |
| Directory listing enabled | high | CWE-548 | A05 Security Misconfiguration |
| Stack trace disclosure | high | CWE-209 | A05 Security Misconfiguration |
| Unknown rule ids | medium | none | none |

## 운영 원칙

- Rule id가 mapping table에 없으면 저장은 계속하되 `medium` confidence와 빈 CWE/OWASP를 사용한다.
- Confidence는 evidence 강도 기준이다. 예를 들어 명확한 노출 파일 2xx 응답은 `high`, 경로 접근 가능성만 확인된 admin/debug endpoint는 `medium`으로 둔다.
- CWE/OWASP는 리포트, SARIF, AI Fix Guide 입력에서 재사용된다.
- Desktop local storage는 `rule_id|endpoint` 형식의 per-scan dedupe key를 저장해 같은 scan 내 반복 finding을 기존 finding으로 병합한다.
- 매핑 변경은 rule 테스트와 함께 갱신한다.

## 다음 확장 후보

- Finding dedupe key 생성
- Severity override 정책
- Rule별 remediation template version
- Rule pack version과 mapping version 분리
- CWE/OWASP mapping export for report generators
