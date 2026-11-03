# Aegis WebShield AI 관리자 운영 가이드

기준 버전: 1.0.0 release candidate

적용 범위: Windows 무료 커뮤니티 로컬 설치형 앱

## 배포와 설치

1. 공식 release의 MSI/NSIS artifact, SHA-256, release notes를 함께 보관한다.
2. 설치 전 Authenticode signature의 상태, 게시자, timestamp를 검증한다.
3. 조직의 allowlist·EDR·proxy 정책과 충돌 여부를 사전 검증 그룹에서 확인한다.
4. 설치 후 앱 실행, version/icon, Credential Manager 저장·삭제, dashboard, audit redaction을 smoke test한다.
5. 설치 artifact와 smoke evidence의 path, SHA-256, size가 일치하는지 release verifier로 확인한다.

Unsigned 개발 bundle은 운영 배포하지 않는다. 현재 release candidate gate와 명령은 [Windows Release Checklist](windows-release-checklist.md)를 따른다.

## 로컬 데이터와 비밀정보

앱 데이터에는 SQLite, report, diagnostics, rule manifest/bundle이 포함된다. 조직 backup이 필요하면 앱을 종료한 상태에서 앱 데이터 전체를 보호된 위치에 보관한다. 개별 DB row, migration table, rule metadata를 직접 편집하지 않는다.

사용자 AI API key는 Windows Credential Manager에 저장된다. 지원 담당자는 key 원문을 요청하거나 diagnostics에 첨부하도록 안내해서는 안 된다. License key 원문도 ticket, email, audit metadata에 남기지 않는다.

## 라이선스와 Rule Pack

- 라이선스 활성화와 월간 과금 한도 없이 기능이 사용 가능한지 확인한다.
- 모든 지원 룰 채널은 무료로 허용하되 해시·서명·입력 안전 검사를 유지한다.
- Offline bundle은 size/path traversal, manifest SHA-256, optional Ed25519 signature를 검증한다.
- Import 전에 현재 version/channel/checksum을 기록하고 rollback artifact가 생성되는지 확인한다.
- Feed check는 update availability만 평가하며 임의 download/apply 권한을 부여하지 않는다.

## 지원 접수 절차

1. 제품 version, Windows version, installer 종류, 문제 발생 시각과 재현 단계만 먼저 받는다.
2. 사용자에게 Settings의 `Support Diagnostics`에서 bundle을 명시적으로 생성하도록 안내한다.
3. 수신 전 API key, target URL, approval note, finding evidence가 포함되지 않았는지 사용자에게 확인시킨다.
4. 내부 환경에서는 `npm run support:verify-diagnostics -- <safe-repo-relative-path>`로 구조와 금지 필드를 검사한다.
5. Ticket에는 diagnostics SHA-256, size, 수집 시각과 최소 재현 정보만 기록한다.

진단 bundle이 verifier를 통과하지 못하면 첨부하지 않고 새 bundle을 생성한다. 원본 SQLite나 Credential Manager export를 일반 지원 절차로 요청하지 않는다.

## 장애 복구

- 비정상 종료 후 non-terminal scan은 startup에서 `queued`로 복구된다. 사용자가 scope와 대상 상태를 다시 확인한 뒤 재개하거나 취소한다.
- Rule update 이후 finding 동작이 달라지면 current/previous metadata를 확인하고 rollback한다.
- Report 정리 작업은 report artifact만 대상으로 하며 audit log는 유지한다.
- DB 손상이 의심되면 앱을 종료하고 전체 앱 데이터 backup과 diagnostics를 확보한 뒤 escalation한다. 새 DB 생성이나 파일 삭제는 사용자 승인 없이 수행하지 않는다.

## Release Candidate 운영 게이트

`npm run rc:security-performance` evidence는 정확한 package version, Git commit, clean working tree에 귀속된다. `release:audit -- --strict`는 이 evidence와 installer signature, installer/app smoke, update manifest, SmartScreen submission package를 요구한다. SmartScreen tracker는 Microsoft case가 생성된 이후 `--require-smartscreen-tracker`로 별도 강제한다.

외부 입력이 필요한 gate를 임시 JSON이나 self-asserted 값으로 우회하지 않는다. 실패 항목은 release run report에 남기고 실제 서명·설치·게시 증거가 준비될 때 다시 실행한다.
