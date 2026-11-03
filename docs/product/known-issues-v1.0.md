# Aegis WebShield AI v1.0 Known Issues

갱신일: 2026-11-03

상태: 무료 커뮤니티 소스 프리뷰. 아래 설치 파일 검증은 소스 공개와 별도다.

## 검증된 Windows 설치 파일 배포 전 확인 항목

| 항목 | 현재 상태 | 출시 전 조치 |
|---|---|---|
| Windows installer Authenticode | 로컬 MSI/NSIS bundle은 생성됐지만 유효한 배포 서명 evidence가 없음 | 상용 인증서로 두 artifact를 서명하고 SHA-256/size가 일치하는 signature report 생성 |
| 설치 후 앱 smoke | 자동 installer artifact smoke는 완료, MSI/NSIS silent install/uninstall 및 설치 앱의 수동 UI/Credential Manager/redaction evidence는 없음 | 관리자 권한 릴리스 세션에서 자동 설치/삭제 후 MSI와 NSIS 대상 수동 검증 및 `app-smoke:record` 실행 |
| Update manifest | 실제 HTTPS artifact URL과 release signature 입력이 없음 | 공개 배포 URL과 실제 signature로 version 일치 manifest 생성·검증 |
| Support diagnostics release evidence | 설치 앱에서 생성·검증한 release candidate diagnostics가 없음 | Settings에서 redacted diagnostics를 생성하고 `support:verify-diagnostics` 통과 후 release evidence로 보관 |

위 항목이 남아 있는 build는 설치 검증이 완료된 안정판으로 표시하지 않는다. 기존 배포 증거는 소스가 변경된 커뮤니티 버전에 자동 승계되지 않는다.

## 제품 제한사항

- 소스 프리뷰는 Windows x64 로컬 설치형 앱과 CLI를 중심으로 한다. macOS/Linux 데스크톱 패키지와 조직 계정 서버는 검증·제공하지 않는다.
- Native active finding은 확정 exploit이 아니라 수동 확인이 필요한 candidate다. 자동 결과만으로 침해 또는 exploit 성공을 단정하지 않는다.
- 모든 지원 룰 채널 이름은 무료로 사용할 수 있다. 과거 채널 이름이 조직 계정 서버나 유료 서비스를 의미하지 않는다.
- Rule feed check는 remote update 존재 여부와 서명을 검증하지만 자동 download/apply는 수행하지 않는다.
- SmartScreen 평판은 유효한 서명과 Microsoft submission 이후에도 초기 download에서 경고가 나타날 수 있다. 배포 담당자는 case tracker를 유지하고 경고 우회 방법을 일반 사용자에게 안내하지 않는다.

## 보고 방법

문제가 발생하면 Desktop Settings에서 redacted Support Diagnostics를 생성하고 [관리자 운영 가이드](../engineering/administrator-operations-guide.md)의 접수 절차를 따른다. API key, license key, target URL, approval note 또는 원본 finding evidence는 일반 ticket에 첨부하지 않는다.
