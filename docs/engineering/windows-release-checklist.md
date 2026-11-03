# Windows Release Checklist

## 2026-06-25 SmartScreen Tracker Path Note

- Tracker artifact paths must be safe repo-relative paths without absolute paths or `.`/`..` segments.
- `smartscreen:verify-tracker` verifies that each tracked artifact exists locally and matches its recorded SHA-256.
- `release:audit` runs SmartScreen tracker verification automatically when `release/smartscreen/smartscreen-tracker-<version>.json` exists.
- SmartScreen submission evidence file paths, including optional update manifests, must also be safe repo-relative paths and match local file presence.
- `AEGIS_UPDATE_MANIFEST_PATH`, `AEGIS_SUPPORT_DIAGNOSTICS_PATH`, `AEGIS_RULE_FEED_PATH`, `support:verify-diagnostics`, `verify-update-manifest --file`, and `verify-smartscreen-tracker --file` must use safe repo-relative paths before release evidence is read or written.
- `release:windows-candidate` can include tracker verification by passing `-SmartScreenTrackerPath release\smartscreen\smartscreen-tracker-<version>.json`.
- `release:windows-candidate` accepts only safe repository-relative `-ReportPath`, app-smoke report paths, update manifest path, support diagnostics path, and `-SmartScreenTrackerPath` values.
- `release:machine-check` and `verify:windows-signatures` also keep report outputs and installer artifact directories inside the repository.

작성일: 2026-06-13  
상태: 구현 중인 Windows 설치형 앱 릴리스 기준

## 목적

Aegis WebShield AI는 Windows 설치형 상용 앱을 목표로 하므로, 기능 개발과 별도로 반복 가능한 native 검증과 installer 생성 절차가 필요하다.

## 로컬 검증 명령

Windows PowerShell에서 실행한다.

최종 Windows 릴리스 후보 머신에서는 전체 흐름을 오케스트레이션 명령으로 실행한다.

```powershell
npm run release:windows-candidate -- --StrictAudit
```

이 명령은 machine check, RC security/performance evidence, RC functional E2E evidence, preflight, Windows native verification, bundle build, signature verification, installer smoke, release prepare, SmartScreen package, release verify, release candidate audit 순서로 실행한다. Evidence를 preflight보다 먼저 갱신해 이전 commit에 귀속된 stale evidence가 audit에 사용되지 않게 한다. `-StrictAudit`에서는 installer smoke가 MSI와 NSIS의 silent install/uninstall을 모두 실행하며, 두 형식의 성공 결과가 없으면 strict audit가 실패한다. 각 설치/삭제 프로세스는 기본 300초 제한을 적용하며 필요하면 `-InstallerSmokeProcessTimeoutSeconds`로 10~1800초 범위에서 조정한다. 코드 서명 전 중간 점검에는 필요한 단계를 명시적으로 건너뛸 수 있다.

설치 후 앱 실행 확인까지 완료한 릴리스 후보에서는 MSI와 NSIS app smoke result를 각각 지정한다. 단일 `-AppSmokeReportPath`는 중간 점검 호환용이며 strict audit는 두 형식을 모두 요구한다.

```powershell
npm run release:windows-candidate -- --StrictAudit --MsiAppSmokeReportPath release\app-smoke\app-smoke-1.0.0-msi.json --NsisAppSmokeReportPath release\app-smoke\app-smoke-1.0.0-nsis.json
```

설치 앱에서 생성해 검증한 support diagnostics evidence도 명시할 수 있다.

```powershell
npm run release:windows-candidate -- --StrictAudit --MsiAppSmokeReportPath release\app-smoke\app-smoke-1.0.0-msi.json --NsisAppSmokeReportPath release\app-smoke\app-smoke-1.0.0-nsis.json --SupportDiagnosticsPath release\support-diagnostics\support-diagnostics-1.0.0.json
```

```powershell
npm run release:windows-candidate -- --SkipSignatureVerification --SkipInstallerSmoke --SkipSmartScreenPackage
```

생성 항목:

- `release/windows-release-candidate-run.json`

각 단계의 시작/종료 시각, exit code, skip 여부, 실패 메시지를 기록한다. 실패한 경우에도 가능한 범위에서 run report를 남긴다.

릴리스 머신 준비 상태를 먼저 확인한다.

```powershell
npm run release:machine-check
```

생성 항목:

- `release/windows-release-machine-check.json`

검증 항목:

- Windows OS 여부
- Node/NPM PATH, standard install path, or explicit env path와 supported Node version
- Rust `rustc`/`cargo` PATH, standard rustup path, or explicit env path와 version
- Visual Studio Build Tools VC++ x86/x64 component
- optional `signtool.exe` PATH, Windows Kits path, or explicit env path
- 누락된 toolchain에 대한 next step

Rust가 누락되어 있으면 user profile 기준 rustup/MSVC toolchain bootstrap을 먼저 실행한다.

```powershell
npm run bootstrap:windows-rust
```

Windows toolchain resolver는 다음 순서로 tool 위치를 확인한다.

- 명시 환경변수: `AEGIS_CARGO_PATH`, `AEGIS_RUSTC_PATH`, `AEGIS_RUSTUP_PATH`, `AEGIS_NODE_PATH`, `AEGIS_NPM_PATH`, `AEGIS_SIGNTOOL_PATH`
- `PATH`
- Rust standard paths: `%CARGO_HOME%\bin`, `%USERPROFILE%\.cargo\bin`, `%LOCALAPPDATA%\Programs\Rust\bin`
- Node standard paths: `%ProgramFiles%\nodejs`, `%ProgramFiles(x86)%\nodejs`
- Signing standard path: Windows Kits 10 x64 `signtool.exe`

```powershell
npm run release:preflight
```

공통 preflight 검증 항목:

- frontend TypeScript/Vite build
- `npm audit --audit-level=moderate`
- `release:prepare`
- `release:verify`
- `release:audit`
- `release:audit`에서 기존 RC security/performance evidence 검증
- brand icon asset/config verification through `release:audit`
- Tauri CSP/security config verification through `release:audit`
- separate MSI/NSIS installed app smoke result verification when explicit paths are provided or current-version reports exist under `release/app-smoke/`
- optional support diagnostics verification when `AEGIS_SUPPORT_DIAGNOSTICS_PATH` is set; both `release:preflight` and `release:audit` run `support:verify-diagnostics` for that artifact

Windows native 검증은 별도로 실행한다.

```powershell
npm run verify:windows
```

검증 항목:

- Rust/Node/NPM toolchain 확인. PATH에 없더라도 위 resolver가 찾은 명시/표준 경로를 사용한다.
- Node version `>=20.19.0` 또는 `>=22.12.0` 확인
- frontend TypeScript/Vite build
- `cargo fmt --all --check`
- 전체 workspace crate 테스트
- Windows Credential Manager secret store compile check
- Tauri app compile check

## 설치 파일 생성

Windows PowerShell에서 실행한다.

```powershell
npm run bundle:windows
```

생성 대상:

- MSI installer
- NSIS installer

Tauri bundle 설정은 `src-tauri/tauri.conf.json`에 둔다.

## Code Signature Verification

Installer artifacts must be Authenticode signed before publishing. 서명용 PFX 비밀번호를 command line이나 환경변수로 전달하지 않고, Windows `CurrentUser\My` 또는 `LocalMachine\My` 인증서 저장소에 등록된 Code Signing 인증서의 명시적 SHA-1 thumbprint를 사용한다. Timestamp URL은 credential, query, fragment가 없는 공개 HTTPS RFC 3161 endpoint만 허용한다.

법인 OV/EV 선택, 신청 정보와 서류, 대표전화 및 권한 검증, USB 토큰 설정, 갱신·폐기 운영은 [법인용 Windows 코드 서명 인증서 발급 및 운영 가이드](windows-code-signing-certificate-issuance.md)를 따른다.

```powershell
npm run sign:windows-installers -- --CertificateThumbprint <40-hex-thumbprint> --TimestampUrl https://<tsa-host>/<rfc3161-path>
```

Local Machine 인증서 저장소를 사용할 때는 관리자 권한 PowerShell에서 `--MachineStore`를 추가한다. 명령은 현재 package version의 MSI와 NSIS가 모두 있는지, 인증서가 private key와 Code Signing EKU를 보유하고 유효기간 안인지 확인한다. 기존의 유효한 다른 서명이나 잘못된 서명은 기본적으로 덮어쓰지 않는다. 서명 후 `release/signature-verification.json`을 생성하며 모든 artifact의 현재 SHA-256과 크기를 기록한다. 인증서와 artifact 선택만 검증하려면 `--DryRun`을 사용한다.

전체 후보 흐름에서 bundle 직후 서명하려면 다음과 같이 전달한다.

```powershell
npm run release:windows-candidate -- --StrictAudit --SigningCertificateThumbprint <40-hex-thumbprint> --SigningTimestampUrl https://<tsa-host>/<rfc3161-path> --SigningMachineStore
```

서명된 NSIS에서 실제 update manifest까지 같은 후보 흐름으로 만들 때는 릴리스 서명 값만 환경변수로 주입하고 공개 base URL을 전달한다. 서명 값은 command arguments나 run report에 기록되지 않는다.

```powershell
$env:AEGIS_RELEASE_SIGNATURE = "<release-signature>"
npm run release:windows-candidate -- --StrictAudit --SigningCertificateThumbprint <40-hex-thumbprint> --SigningTimestampUrl https://<tsa-host>/<rfc3161-path> --SigningMachineStore --UpdateBaseUrl https://downloads.example.com/aegis-webshield-ai/1.0.0/
```

오케스트레이터는 Authenticode 서명과 installer smoke 이후 `release/update-manifest-<version>.json`을 생성·검증하고, 같은 경로를 SmartScreen package와 strict audit에 전달한다. `--UpdateManifestPath`로 기존 manifest를 지정하면 새로 생성하지 않고 검증한 뒤 동일하게 연결한다.

After signing MSI/NSIS artifacts, run the signature gate on Windows PowerShell.

```powershell
npm run verify:windows-signatures
```

The command scans `target/release/bundle` for `.msi` and `.exe` artifacts, with a legacy fallback to `src-tauri/target/release/bundle`, and fails with exit code 2 when any artifact is unsigned or has an invalid signature. To keep a release evidence file, pass an explicit report path. The report records each artifact path, SHA-256, and byte size; `release:audit` compares those values with the current bundle artifacts so stale or partial signature evidence cannot satisfy strict release gates.

```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify-windows-signatures.ps1 -ReportPath release\signature-verification.json
```

## Update Manifest Verification

자동 업데이트 manifest를 게시하기 전 `docs/engineering/desktop-update-channel-policy.md`의 형식을 따른 JSON을 검증한다.

```powershell
npm run update:verify-manifest -- --file release\update-manifest-stable.json
```

bundle artifact에서 update manifest 초안을 생성할 때는 릴리스 서명과 HTTPS artifact base URL을 명시한다. 서명값은 Git에 남기지 말고 릴리스 secret store 또는 일회성 환경 변수로 주입한다.

```powershell
$env:AEGIS_RELEASE_SIGNATURE = "<release-signature>"
$env:AEGIS_UPDATE_BASE_URL = "https://downloads.example.com/aegis-webshield-ai/1.0.0/"
npm run update:prepare-manifest -- --artifact nsis --channel stable --out release\update-manifest-1.0.0.json
npm run update:verify-manifest -- --file release\update-manifest-1.0.0.json
```

검증 항목은 product/version/channel/pub_date/platform schema, HTTPS artifact URL, SHA-256, release signature, private key/token/API key 계열 필드 차단이다. v1.0 Windows release manifest는 현재 `package.json` version과 일치해야 하고, `platforms.windows-x86_64`를 반드시 포함해야 하며, artifact URL은 embedded credential, query string, fragment, sensitive label이 없는 공개 HTTPS URL이어야 한다.

## SmartScreen Submission Package

Windows Defender SmartScreen 평판 제출 전 제출 증적 패키지를 생성한다. 실제 제출은 Microsoft 포털에서 수행하지만, 로컬 패키지는 release notes, checksum, installer artifact, signature verification report, installer smoke report, 선택적 update manifest를 한 번에 묶어 확인한다.

```powershell
npm run smartscreen:prepare
```

자동 업데이트 manifest도 함께 제출 증적으로 묶을 때는 `AEGIS_UPDATE_MANIFEST_PATH`를 지정한다.

```powershell
$env:AEGIS_UPDATE_MANIFEST_PATH = "release\update-manifest-stable.json"
npm run smartscreen:prepare
```

생성 항목:

- `release/smartscreen/smartscreen-submission-<version>.json`
- `release/smartscreen/smartscreen-submission-<version>.md`

`release:verify`는 SmartScreen 제출 JSON이 있을 경우 product/version/checklist와 민감 필드명을 추가로 검증한다.

제출 후에는 Microsoft submission case ID와 평판 상태를 공개 릴리스 노트가 아닌 로컬 운영 tracker에 기록한다.

```powershell
npm run smartscreen:verify-tracker -- --file release\smartscreen\smartscreen-tracker-1.0.0.json
```

tracker JSON 예시:

```json
{
  "product": "Aegis WebShield AI",
  "version": "1.0.0",
  "channel": "stable",
  "submission_case_id": "MS-CASE-000000",
  "submitted_at": "2026-06-24T00:00:00Z",
  "status": "submitted",
  "next_review_at": "2026-06-27T00:00:00Z",
  "artifacts": [
    {
      "path": "target/release/bundle/nsis/Aegis WebShield AI_1.0.0_x64-setup.exe",
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    },
    {
      "path": "target/release/bundle/msi/Aegis WebShield AI_1.0.0_x64_en-US.msi",
      "sha256": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
    }
  ],
  "notes": "Keep customer and account data out of this file."
}
```

허용 상태값은 `submitted`, `under_review`, `approved`, `needs_changes`, `rejected`, `closed`이다. Tracker evidence must match the current package version, use a whitespace-free 6-80 character Microsoft case identifier, keep `next_review_at` at or after `submitted_at`, and include every current MSI/NSIS bundle artifact with matching SHA-256 values.

## 릴리스 노트와 Checksum

설치 파일 생성 후 실행한다.

```powershell
npm run release:prepare
npm run release:verify
```

`release:prepare`는 생성된 release notes에 `Known Issues`와 `Upgrade Notes` 섹션을 항상 포함한다. 배포 담당자는 명령 실행 전 세미콜론 또는 줄바꿈으로 구분된 환경 변수를 설정해 기본 bullet을 교체할 수 있다.

```powershell
$env:AEGIS_RELEASE_KNOWN_ISSUES = "Windows installer smoke test must pass on the signing machine"
$env:AEGIS_RELEASE_UPGRADE_NOTES = "Back up local app data before upgrading from pre-release builds"
npm run release:prepare
```

생성 항목:

- `release/Aegis-WebShield-AI-<version>.md`
- `release/SHA256SUMS-<version>.txt` when installer artifacts exist
- optional signed rule feed artifacts when `AEGIS_RULE_FEED_PATH` is provided

`release:prepare`는 `target/release/bundle` installer artifacts와 기존 release rule feed evidence가 있으면 함께 SHA-256 checksum에 포함한다.

`release:verify`는 package/Tauri/Cargo version 일치, release notes 존재 여부, `SHA256SUMS-<version>.txt` checksum 재계산, signed rule feed artifact 완결성, rule feed check pass 여부, sign report 내 private key material 노출 여부, SmartScreen submission package artifact 존재/SHA-256/checksum coverage를 검증한다. Checksum과 SmartScreen artifact 경로는 absolute path나 `.`/`..` segment가 없는 repo-relative 안전 경로여야 한다. JSON release evidence는 Windows PowerShell 생성 파일을 고려해 UTF-8 BOM을 허용한다. 오류가 있으면 exit code 2를 반환하며, 자동화 환경에서는 `npm run release:verify -- --json`으로 요약 JSON을 받을 수 있다.

`release/` 디렉터리는 로컬 산출물로 취급하며 Git에 커밋하지 않는다.

## Release Candidate Audit

개발 환경에서는 누락된 Windows artifact를 warning으로 확인한다.

```powershell
npm run release:audit
```

실제 배포 후보에서는 installer artifact, signature verification report/result, installer smoke report, update manifest, MSI/NSIS installed app smoke result, SmartScreen submission package까지 필수 증적으로 요구한다.

```powershell
npm run release:audit -- --strict
```

Strict audit는 `release/rc-security-performance/rc-security-performance-<version>.json`을 요구한다. Windows release machine에서 정확한 release candidate commit을 checkout한 뒤 생성한다.

```powershell
npm run rc:security-performance
npm run verify:rc-security-performance -- --file release/rc-security-performance/rc-security-performance-1.0.0.json
```

runner는 core scope policy, native HTTP destination/redirect/DNS rebinding 격리, native evidence redaction, scanner request policy 테스트를 실행한다. 이어서 release mode passive/active detector benchmark와 생성된 5,000-endpoint OpenAPI 문서의 3회 import 성능을 기록한다. verifier는 seeded false positive/negative 0건, active reproduction 결정성, benchmark network/destructive activity 0건, endpoint limit 강제, p95 상한, 현재 package version 및 정확한 Git commit 일치와 clean working tree를 요구한다. 다른 commit이나 수정 중인 working tree에서 생성한 evidence는 strict RC gate를 통과할 수 없다. 개발 중 임시 측정에는 `--allow-dirty`를 사용할 수 있지만 해당 결과는 strict audit evidence로 인정되지 않는다.

자동화 가능한 설치형 기능 E2E evidence도 같은 clean commit에서 생성한다.

```powershell
npm run rc:functional-e2e
npm run verify:rc-functional-e2e -- --file release/rc-functional-e2e/rc-functional-e2e-1.0.0.json
```

이 E2E는 persisted project/target/endpoint에서 local passive scan을 실행하고, 저장 finding의 JSON/SARIF redaction 및 native active candidate metadata를 확인한다. 이어서 rule pack validation, 모든 지원 채널의 활성화 없는 사용, update manifest 정상 수락 및 unsafe HTTP/query/short-signature 거부를 검증한다. `release:audit -- --strict`와 Windows release candidate orchestration은 해당 evidence를 필수로 확인한다. 소스 공개는 이 설치 파일 릴리스 절차와 별도다.

출시 승인 전 [Desktop 사용자 가이드](../product/desktop-user-guide.md), [CLI 사용자 가이드](../product/cli-user-guide.md), [관리자 운영 가이드](administrator-operations-guide.md), [v1.0 Known Issues](../product/known-issues-v1.0.md)가 release candidate 동작과 일치하는지 함께 검토한다.

## Release Tag Readiness

Release tag는 수동으로 만들기 전에 읽기 전용 readiness gate를 통과해야 한다.

```powershell
npm run release:tag-readiness -- --expected-version 1.0.0
```

이 명령은 package/Tauri/Cargo version 일치, prerelease suffix가 없는 v1 이상 version, clean working tree, `main` branch, upstream 설정과 ahead/behind 0, 동일 local/remote tag 부재, `release:verify`, `release:audit -- --strict`를 확인한다. Remote tag 확인을 생략하는 offline 우회 옵션은 제공하지 않는다. 모든 항목이 통과한 뒤에만 현재 commit에 annotated `v<version>` tag를 만들고 원격에 push한다. Readiness 명령 자체는 tag나 remote state를 변경하지 않는다.

Strict audit requires installer artifacts, signature verification report/result, MSI와 NSIS silent install/uninstall 결과를 포함한 installer smoke report, update manifest, MSI와 NSIS 각각의 installed app smoke result, and SmartScreen submission package. After Microsoft returns a submission case ID, require tracker evidence explicitly:

```powershell
npm run release:audit -- --strict --require-smartscreen-tracker
```

`AEGIS_UPDATE_MANIFEST_PATH`를 지정하거나 기본 `release/update-manifest-<version>.json` 파일이 존재하면 `release:audit`가 `verify-update-manifest --file`로 manifest schema, 안전한 artifact path, 민감 필드 차단 기준까지 검증한다.

installer artifact가 존재할 때 `release:audit`는 SmartScreen submission package의 artifact path와 SHA-256이 실제 bundle artifact와 일치하는지도 검증한다.
`release:audit -- --strict`는 기본 `release/support-diagnostics/support-diagnostics-<version>.json`을 필수 evidence로 요구한다. 다른 파일을 사용할 때는 `AEGIS_SUPPORT_DIAGNOSTICS_PATH`에 safe repo-relative path를 지정하며, `release:audit`는 해당 artifact를 `support:verify-diagnostics`로 검증하고 실패 시 audit도 실패시킨다. Windows candidate의 `-SupportDiagnosticsPath`는 이 환경변수를 검증된 in-repository path로 설정한 뒤 preflight와 audit에 전달한다.

Rule pack update feed를 릴리스에 포함할 때는 release secret store에서 Ed25519 private key seed를 주입하고 다음 환경 변수를 설정한다.

```powershell
$env:AEGIS_RULE_FEED_PATH = "release\rule-feed.json"
$env:AEGIS_RULE_FEED_PRIVATE_KEY_HEX = "<ed25519-private-key-seed-hex>"
$env:AEGIS_RULE_FEED_CURRENT_VERSION = "2026.06.12"
npm run release:prepare
```

생성 항목:

- `release/rule-feed-<version>.signed.json`
- `release/rule-feed-sign-<version>.json`
- `release/rule-feed-check-<version>.json`

`AEGIS_RULE_FEED_PRIVATE_KEY_HEX`는 로그, 문서, Git에 남기지 않는다. 이미 서명된 feed를 검증만 할 때는 `AEGIS_RULE_FEED_PUBLIC_KEY_HEX`를 사용한다.

## Installer Smoke Test

설치 파일 생성 후 Windows PowerShell에서 실행한다.

```powershell
npm run smoke:windows-installer
```

`smoke-windows-installer.ps1 -ArtifactDir` must resolve inside the repository; absolute paths or `..` traversal outside the checkout are rejected so installer smoke reports never record out-of-repo artifact evidence.

기본 smoke test는 `target/release/bundle` 아래의 MSI/NSIS 산출물 존재 여부, SHA-256, 파일 크기를 확인하고 `release/installer-smoke/installer-smoke-<timestamp>.json` 리포트를 생성한다. 이전 `src-tauri/target/release/bundle` 산출물 위치도 fallback으로 확인한다.
Bundle 디렉터리에 이전 version artifact가 남아 있어도 release prepare, audit, signature, smoke, update manifest, app smoke, SmartScreen package/tracker는 현재 `package.json` version이 filename에 포함된 MSI/NSIS만 선택한다. Current-version artifact가 없으면 이전 파일로 fallback하지 않고 실패한다.

MSI silent install/uninstall까지 검증할 때는 관리자 권한 PowerShell에서 다음 명령을 직접 실행한다.

```powershell
powershell -ExecutionPolicy Bypass -File scripts/smoke-windows-installer.ps1 -InstallMsi
```

NSIS silent install/uninstall까지 검증할 때는 관리자 권한 PowerShell에서 다음 명령을 직접 실행한다. 스크립트는 임시 설치 디렉터리를 지정해 `/S` 설치를 실행하고 생성된 uninstaller를 `/S`로 실행한 뒤 결과를 smoke report에 기록한다.

```powershell
powershell -ExecutionPolicy Bypass -File scripts/smoke-windows-installer.ps1 -InstallNsis
```

MSI와 NSIS를 함께 깊게 검증할 때는 두 switch를 함께 지정한다.

```powershell
powershell -ExecutionPolicy Bypass -File scripts/smoke-windows-installer.ps1 -InstallMsi -InstallNsis
```

MSI 설치/삭제 로그와 NSIS 설치/삭제 결과는 `release/installer-smoke/` 아래에 남긴다.

## Installed App Smoke Result

MSI/NSIS silent install/uninstall 자동 smoke와 별개로, 설치 후 실제 앱을 실행해 UI와 OS secure storage 동작을 확인하고 결과를 로컬 JSON으로 남긴다.

```powershell
npm run app-smoke:record -- --installer msi --checked-by release-operator --all-checks-passed --out release\app-smoke\app-smoke-1.0.0-msi.json
npm run verify:app-smoke -- --file release\app-smoke\app-smoke-1.0.0-msi.json
npm run app-smoke:record -- --installer nsis --checked-by release-operator --all-checks-passed --out release\app-smoke\app-smoke-1.0.0-nsis.json
npm run verify:app-smoke -- --file release\app-smoke\app-smoke-1.0.0-nsis.json
```

`app-smoke:record --out`, optional `--artifact-path`, and `verify:app-smoke --file` accept only safe repository-relative paths. Absolute paths and `.`/`..` path segments are rejected before writing or reading release evidence. App smoke evidence must match the current package version, reference an MSI/NSIS artifact under `target/release/bundle` or `src-tauri/target/release/bundle`, match the artifact SHA-256/size, and have a `checked_at` timestamp after the referenced artifact was generated.

`app-smoke:record`는 설치 후 앱 실행, 버전 표시, 브랜드 아이콘, Windows Credential Manager 저장/삭제, dashboard load, audit redaction 확인을 모두 수동으로 끝낸 뒤 실행한다. 개별 확인을 더 명시적으로 남기려면 `--all-checks-passed` 대신 `--app-launched --version-visible --brand-icon-visible --credential-manager-save-delete-passed --scan-dashboard-loaded --audit-log-redaction-checked`를 사용한다. 기본 출력은 `release/app-smoke/app-smoke-<version>-<installer>-<timestamp>.json`이며, 생성 직후 `verify:app-smoke`를 자동 실행한다. `--artifact-path`를 생략하면 `target/release/bundle`에서 installer 종류에 맞는 최신 MSI/NSIS artifact를 찾아 `artifact_path`, `artifact_sha256`, `artifact_size_bytes`를 함께 기록한다.

app smoke JSON 예시:

```json
{
  "product": "Aegis WebShield AI",
  "version": "1.0.0",
  "installer": "msi",
  "artifact_path": "target/release/bundle/msi/Aegis WebShield AI_1.0.0_x64_en-US.msi",
  "artifact_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "artifact_size_bytes": 6721536,
  "checked_at": "2026-06-24T00:00:00Z",
  "checked_by": "release-operator",
  "app_launched": true,
  "version_visible": true,
  "brand_icon_visible": true,
  "credential_manager_save_delete_passed": true,
  "scan_dashboard_loaded": true,
  "audit_log_redaction_checked": true,
  "notes": "No customer data or secrets recorded."
}
```

`release:audit -- --strict`는 `release/app-smoke/app-smoke-*.json`에서 현재 package version과 installer 종류가 각각 일치하는 최신 MSI·NSIS 파일을 선택하며, 두 보고서가 모두 존재하고 검증을 통과해야 성공한다.

`release:windows-candidate`는 `-MsiAppSmokeReportPath`와 `-NsisAppSmokeReportPath`가 지정되면 각 파일을 `verify:app-smoke`로 검증하고 run report에 결과를 남긴다. 경로를 지정하지 않으면 현재 version과 installer 종류가 일치하는 최신 파일을 각각 사용한다. 아직 설치 후 UI 확인을 수행하지 않는 중간 점검에서는 `-SkipAppSmokeResult`로 두 단계를 건너뛸 수 있다.

## 릴리스 전 확인

- 앱 이름: `Aegis WebShield AI`
- 앱 식별자: `com.aegis.webshield.ai`
- CLI 이름: `aegis-scan`
- 아이콘 리소스: `src-tauri/icons`, `npm run verify:brand-icons` 통과
- 활성화·월간 과금 한도 없이 기능이 동작하고 자원 안전 제한은 유지되는지 확인
- 승인된 URL/API 범위 밖 스캔 차단 확인
- API key가 SQLite 또는 audit log에 저장되지 않는지 확인
- report export와 finding status audit log 확인
- installer smoke test 리포트와 MSI 설치/삭제 로그 확인
- MSI와 NSIS installed app smoke result 각각 검증 통과 확인
- installer Authenticode signature verification 통과 확인
- update manifest verification 통과 확인
- SmartScreen submission package 생성 및 release verify 통과 확인
- SmartScreen submission tracker 검증 통과 확인
- release candidate audit strict mode 통과 확인

## 다음 확장 후보

- Microsoft submission portal 결과를 릴리스 운영 대시보드로 집계
