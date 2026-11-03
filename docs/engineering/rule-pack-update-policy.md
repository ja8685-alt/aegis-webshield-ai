# Rule pack update policy

갱신일: 2026-11-03

앱 업데이트와 룰 업데이트를 분리한다. 앱 데이터의 `rules/manifest.json`과
`rules/bundles/`에 검증한 내용을 저장하고 이전 manifest/bundle 메타데이터로 롤백한다.

## 채널

`built-in`, `community`, `local`, `pro`, `team`, `enterprise`는 모두 무료로 허용하는 레이블이다.
활성화·온라인 계정·구독을 검사하지 않는다. 알 수 없는 채널은 거절한다.
기존 API의 `entitlement_allowed`는 호환성을 위해 유지하며 지원 채널 여부를 뜻한다.
CLI `--pro-active`는 제거했다. 채널 이름이 조직 서버나 별도 호스팅 서비스를 제공한다는 뜻은 아니다.

## 검증과 저장

- Manifest의 version, channel, rule id/count, severity, enabled 메타데이터를 검증한다.
- 명시된 expected SHA-256과 public key가 있으면 해당 해시·서명 검증이 실패할 때 거절한다.
- ZIP bundle은 디스크에 임의 추출하지 않고 root `manifest.json`을 읽는다.
- 선택적 `manifest.sig`는 정확한 manifest 바이트에 대한 Ed25519 서명이다.
- 절대 경로·드라이브·역슬래시·빈 세그먼트·상위 경로 이동을 거절한다.
- ZIP 최대 10MB, entry 최대 2MB를 적용한다. stored/deflated manifest 읽기를 지원한다.
- `enabled: false`인 일치 규칙 결과는 저장하지 않으며 severity override와 마스킹한 pack 출처를 기록한다.
- Feed check는 version·HTTPS URL·SHA-256·선택적 서명을 검증하지만 자동 다운로드·적용하지 않는다.
- Audit에는 최소 메타데이터를 남기며 개인키와 원본 인증정보는 넣지 않는다.

## CLI

`rules test`, `rules feed-check`, `rules feed-sign`, `rules bundle-check`를 사용한다.
검증 실패는 종료 코드 2로 보고한다. 서명 개인키는 환경에서 제공하며 공개 소스에 포함하지 않는다.
자세한 인자는 `cargo run --locked -p aegis-cli -- rules --help`와 [CLI 안내](aegis-scan-cli.md)를 따른다.
