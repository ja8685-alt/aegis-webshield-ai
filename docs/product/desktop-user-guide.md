# Aegis WebShield AI Desktop 사용자 가이드

기준 버전: 1.0.0 community source preview (2026-11-03)

지원 환경: Windows x64

## 1. 시작 전 확인

Aegis WebShield AI는 사용자가 소유하거나 명시적으로 진단 승인을 받은 웹 사이트와 API만 스캔한다. 대상 등록 시 승인 근거를 입력해야 하며, localhost·사설 IP·link-local 주소는 `Allow private network`를 별도로 승인해야 한다. 승인되지 않은 제3자 시스템은 등록하거나 스캔하지 않는다.

현재 소스 프리뷰의 실행 방법은 루트 README를 따른다. 설치 파일이 별도로 공개되는 경우 배포 페이지의 SHA-256과 게시자 서명, 알려진 제한사항을 확인한다. 소스 공개가 설치 파일의 서명·설치 검증 완료를 의미하지 않는다.

## 2. 첫 스캔

1. `Projects & Approved Targets`에서 프로젝트를 만든다.
2. 프로젝트 아래에 URL 또는 API target을 추가하고 소유권·승인 티켓 등 승인 근거를 기록한다.
3. 필요하면 OpenAPI JSON/YAML, URL seed, HTML 또는 browser observation 파일을 가져와 endpoint 후보를 만든다.
4. `Scan Queue`에서 프로젝트, target, profile을 선택해 scan을 생성한다.
5. Local Engine runner가 켜져 있는지 확인하고 scan 완료까지 기다린다. 실행 중인 scan은 취소할 수 있다.
6. `Findings`에서 severity, confidence, CWE/OWASP 분류, endpoint, evidence와 remediation을 검토한다.

`passive`는 응답과 보안 헤더를 분석하고, `surface`는 제한된 노출 경로를 확인한다. `safe`는 읽기 전용·비파괴 검증 후보를 추가한다. Active 결과는 확정 exploit이 아니라 `manual confirmation required` 후보이므로 운영 환경 변경이나 별도 수동 검증 없이 확정 취약점으로 보고하지 않는다.

## 3. Finding과 리포트

Finding status와 confidence를 검토하고 동일 endpoint/rule의 중복이 병합됐는지 확인한다. Baseline이 있는 경우 new, recurring, resolved 구분을 함께 본다.

Reports 영역에서 Markdown, HTML, JSON, PDF, SARIF를 모두 무료로 내보낼 수 있다. 모든 export는 URL query value와 fragment를 제거하고 authorization, cookie, token, password, secret, private key 값을 마스킹한다. 외부 전달 전에는 대상명과 업무 정보가 공개 가능한지 사용자가 확인한다.

## 4. AI Fix Guide

AI Fix Guide는 무료 선택 기능이며 사용자가 직접 저장한 API key가 필요하다. Key는 Windows Credential Manager에 저장되고 로컬 SQLite에는 평문으로 기록되지 않는다. 선택한 finding의 마스킹된 정보만 provider에 전송되며 요청은 저장 비활성화 정책을 사용한다. 생성된 제안은 참고 초안이므로 코드 리뷰와 테스트 없이 운영 환경에 적용하지 않는다.

## 5. Rule Pack과 커뮤니티 정책

Settings의 `Rule Pack Updates`에서 현재 version과 channel을 확인할 수 있다. 서명된 ZIP bundle 또는 승인된 manifest만 import하고, checksum 또는 public key가 제공되면 반드시 검증한다. 문제가 생기면 이전 pack으로 rollback한다. 지원 채널은 모두 활성화 없이 사용하며 과거 유료 채널 이름도 호환성 레이블로 허용한다.

라이선스나 월간 과금 한도는 없다. 로컬 동시 스캔 용량과 네트워크·파일·요청 안전 제한은 유지한다.

## 6. 문제 해결과 지원 진단

- Scan이 중단되면 앱을 다시 시작한다. 비정상 종료 전에 완료되지 않은 scan은 `queued`로 복구되며 사용자가 다시 시작하거나 취소할 수 있다.
- Engine 또는 storage 상태가 비정상이면 Settings 상태를 확인한 뒤 앱을 한 번 재시작한다.
- Rule Pack 문제가 의심되면 현재 version/channel을 기록하고 rollback 후 재시도한다.
- 지원 요청 전 Settings의 `Support Diagnostics`에서 진단 JSON을 생성한다.

진단 bundle에는 version, platform, storage count, usage, community edition, engine/rule pack 상태와 최소화된 audit record만 포함된다. API key, license key, 승인 문구, target URL, finding evidence, raw AI prompt/provider response는 포함하지 않는다. 첨부 전 파일을 직접 열어 조직 정책상 전달 가능한지 확인한다.

## 7. 데이터와 보안 원칙

- 프로젝트, target, scan, finding과 audit log는 로컬 SQLite에 저장된다.
- API key는 OS secure storage에 저장된다.
- 외부 scan 요청은 승인된 scope와 request policy를 통과해야 한다.
- Redirect와 DNS 결과는 연결 전 다시 검사하며 금지 destination으로 이동하면 차단한다.
- 앱 데이터나 rule/report artifact를 수동 편집하지 말고 필요한 경우 백업 후 지원 절차를 따른다.

현재 제한사항은 [v1.0 Known Issues](known-issues-v1.0.md)를 확인한다.
