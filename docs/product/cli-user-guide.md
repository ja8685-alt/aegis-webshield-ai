# aegis-scan CLI 사용자 가이드

기준 버전: 1.0.0 release candidate

## 1. 기본 원칙

CLI도 Desktop과 같은 scope·request policy와 native engine을 사용한다. 모든 network scan에는 `--approval-note`가 필요하다. 사설망 target은 소유권을 확인한 뒤에만 `--allow-private-network`를 명시한다. CI log로 출력되는 URL query value, fragment와 일반적인 secret 필드는 자동 마스킹된다.

```powershell
aegis-scan --version
aegis-scan --help
```

종료 코드는 `0` 성공, `1` 인자·입력·network·serialization·실행 오류, `2` finding 또는 rule policy gate 실패다.

## 2. URL과 OpenAPI scan

```powershell
aegis-scan scan `
  --url https://staging.example.com `
  --approval-note "SEC-123 owner approval" `
  --fail-on high `
  --format sarif > aegis.sarif
```

```powershell
aegis-scan scan `
  --openapi .\openapi.yaml `
  --base-url https://api.staging.example.com `
  --approval-note "SEC-124 API owner approval" `
  --fail-on high `
  --format json > aegis.json
```

OpenAPI scan은 GET/HEAD endpoint만 passive probe하며 POST/PUT/PATCH/DELETE를 실행하지 않는다. `--fail-on never`는 결과를 기록하되 finding으로 CI를 실패시키지 않는다.

## 3. Baseline gate

이전 JSON 결과를 baseline으로 사용해 새 finding만 차단할 수 있다.

```powershell
aegis-scan scan `
  --url https://staging.example.com `
  --approval-note "SEC-125 regression scan" `
  --baseline-file .\baseline.json `
  --fail-on never `
  --fail-on-new medium `
  --format json > current.json
```

Baseline 파일은 신뢰할 수 있는 CI artifact에서 가져오고 임의 수정 여부를 확인한다.

## 4. Safe active 후보

```powershell
aegis-scan verify-active `
  --url "https://staging.example.com/search?q=test" `
  --approval-note "SEC-126 safe verification" `
  --fail-on high `
  --format json > active-candidates.json
```

이 명령은 기존 query parameter만 GET으로 변형하며 zero retry, no destructive payload 정책을 적용한다. 결과는 후보이며 JSON/SARIF의 `requires_manual_confirmation`과 `finding_classification`을 유지해야 한다.

## 5. Desktop 로컬 데이터 사용

```powershell
aegis-scan scan-local `
  --app-data-dir <APP_DATA_DIR> `
  --project-id <PROJECT_ID> `
  --target-id <TARGET_ID> `
  --profile safe `
  --fail-on high `
  --format sarif > local-scan.sarif
```

```powershell
aegis-scan report export `
  --app-data-dir <APP_DATA_DIR> `
  --scan-id <SCAN_ID> `
  --format json > saved-scan.json
```

`--database`는 기본 DB가 아닌 명시적 로컬 DB를 사용할 때만 지정한다. 앱 실행 중 DB를 복사·수정하거나 여러 process에서 migration을 수행하지 않는다.

## 6. Import, crawl, rule 명령

지원 명령은 `import-openapi`, `import-urls`, `crawl-html`, `crawl-browser-log`, `crawl-url`이다. 각 명령의 현재 제한은 `aegis-scan <command> --help`로 확인한다. Live crawl은 same-origin과 page/candidate/depth 상한을 적용한다.

Rule pack 운영 명령:

```powershell
aegis-scan rules test --help
aegis-scan rules feed-check --help
aegis-scan rules bundle-check --help
```

`feed-sign`은 release secret store가 주입한 Ed25519 private key seed를 사용하는 배포 담당자 전용 명령이다. 개발자 workstation의 shell history나 repository에 private key를 저장하지 않는다.

## 7. CI 권장 설정

- 고정된 CLI version과 rule pack checksum을 사용한다.
- SARIF는 CI artifact 또는 code scanning 입력으로 저장한다.
- stdout report와 stderr 오류를 분리하고 secret masking이 해제되는 wrapper를 사용하지 않는다.
- timeout을 설정하고 exit code `1`과 `2`를 구분한다.
- 승인 note에는 ticket ID 같은 최소 근거만 넣고 고객명·credential·URL query secret을 넣지 않는다.

세부 명령 계약은 [CLI 설계 및 명령 명세](../engineering/aegis-scan-cli.md)를 참고한다.
