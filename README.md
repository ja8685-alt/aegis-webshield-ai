# Aegis WebShield AI

**무료 오픈소스 웹/API 보안 점검 도구 · Free, open-source web/API security scanner**

웹 보안·웹 취약점 점검·API 보안 테스트를 위한 데스크톱 앱과 CLI입니다.
A desktop app and CLI for web security testing, web vulnerability scanning, and API security.

[GitHub](https://github.com/ja8685-alt/aegis-webshield-ai) ·
[버그 신고 / Bug reports](https://github.com/ja8685-alt/aegis-webshield-ai/issues) ·
[비공개 보안 신고 / Private security reports](https://github.com/ja8685-alt/aegis-webshield-ai/security/advisories/new)

[한국어](#한국어) · [English](#english)

## 한국어

Aegis WebShield AI는 Rust 기반 스캐너, Windows 데스크톱 앱(Tauri + React),
`aegis-scan` CLI를 제공하는 로컬 중심 보안 점검 프로젝트입니다.
프로젝트·대상·점검 결과는 사용자 컴퓨터의 SQLite에 저장합니다.
계정 가입, 유료 플랜, 라이선스 활성화, 월간 기능 사용량 제한이 없습니다.

**현재 상태: 커뮤니티 소스 프리뷰.** 패키지 버전은 1.0.0이지만, 판매용 제품이나
모든 환경에서 검증된 안정 릴리스를 뜻하지 않습니다. Windows x64를 우선 지원하며
macOS/Linux 데스크톱 패키지는 검증하지 않았습니다.

### 주요 기능

- 명시적으로 승인한 웹/API 대상의 패시브 점검, 노출 정보 점검, 제한된 액티브 검증
- OpenAPI 3.x JSON/YAML, URL 목록, HTML, 브라우저 관측 로그에서 엔드포인트 가져오기
- 프로젝트·대상·스캔·발견 사항의 로컬 관리와 이전 스캔 대비 변화 확인
- HTML, Markdown, JSON, PDF, SARIF 리포트 및 CLI의 CI 실패 조건
- 룰 팩 검사·가져오기·롤백과 선택적 서명 검증
- 선택적 AI 수정 가이드: 사용자가 입력한 OpenAI API 키 사용

모든 구현된 기능을 무료로 사용할 수 있습니다. **AI 제공자의 API 사용료는 별도**이며,
키를 입력하지 않아도 스캐너와 리포트 기능을 사용할 수 있습니다.
AI 요청 시 필요한 마스킹된 발견 사항이 해당 제공자에게 전송됩니다.
키는 Windows Credential Manager에 저장하며, 저장소에 공용 API 키를 제공하지 않습니다.

### 개발 환경과 실행

Windows x64 기준 준비물:

- Node.js 22.12 이상인 22.x 버전과 npm
- Rust stable MSVC 툴체인과 Visual Studio Build Tools의 C++ 데스크톱 개발 구성 요소
- Microsoft Edge WebView2 Runtime
- 브라우저 크롤러를 사용할 때만 Playwright Chromium

저장소를 내려받아 루트 폴더에서 실행합니다.

```powershell
git clone https://github.com/ja8685-alt/aegis-webshield-ai.git
cd aegis-webshield-ai
npm ci
npm run tauri -- dev
```

브라우저에서 화면만 미리 보려면 `npm run dev`를 사용합니다. 이 모드는 예시 데이터를
표시하며 네이티브 스캔·DB·자격증명 저장 기능은 실행하지 않습니다.

CLI 빌드 및 명령 확인:

```powershell
cargo build --locked -p aegis-cli
cargo run --locked -p aegis-cli -- --help
cargo run --locked -p aegis-cli -- scan --help
```

실제 스캔은 소유하거나 명시적 허가를 받은 대상에만 수행하세요.
승인 인자와 사용 예제는 [CLI 안내](docs/product/cli-user-guide.md)를 참고하세요.
브라우저 크롤러의 선택적 설치 명령은 `npx playwright install chromium`입니다.

### 검증과 설치 파일 생성

```powershell
npm run build
npm run test:publication
cargo test --locked --workspace
npm run verify:tauri-security
npm run verify:brand-icons
```

Windows MSI/NSIS를 로컬에서 생성하려면 `npm run bundle:windows`를 실행합니다.
빌드만으로 코드 서명·SmartScreen 평판·설치 후 동작이 검증되지는 않습니다.
배포용 설치 파일은 [Windows 릴리스 절차](docs/engineering/windows-release-checklist.md)에
따라 별도로 확인해야 합니다. 소스 공개에 유료 서명 인증서는 필요하지 않습니다.

### 데이터와 안전 범위

- 실제 DB, 스캔 결과, 진단 번들, API 키, 개인키, 인증서, 개발자의 Git 설정은 공개 소스에 포함하지 않습니다.
- DB 스키마와 마이그레이션은 앱 실행에 필요한 코드로 포함합니다. 기존 데이터는 업그레이드 시 유지합니다.
- 동시 스캔 수, 요청·파일 크기·크롤링 범위 제한, 대상 승인, 민감정보 마스킹은 유지합니다.
- 액티브 검증 결과는 수동 확인이 필요한 후보이며, 취약점 악용 성공을 보증하지 않습니다.
- AI 출력 역시 검토가 필요한 보조 가이드입니다. 자동 다운로드·조직 계정 서버는 제공하지 않습니다.

[데스크톱 안내](docs/product/desktop-user-guide.md) ·
[알려진 제한](docs/product/known-issues-v1.0.md) ·
[기여 안내](CONTRIBUTING.md) · [보안 신고](SECURITY.md)

### 라이선스와 공개 패키지

프로젝트 코드는 [Apache License 2.0](LICENSE)으로 제공합니다.
의존성은 각자의 라이선스를 따릅니다. [NOTICE](NOTICE)와
[의존성 고지](THIRD_PARTY_NOTICES.md)를 확인하세요.

새 공개 저장소에는 아래에서 생성한 소스만 첫 커밋으로 추가합니다.
기존 저장소의 `.git`과 비공개 작업 이력은 복사하지 않습니다.
`npm run public:prepare`는 검토된 목록의 파일만 복사하고 비밀정보 검사를 통과한
**Git 이력 없는 소스 폴더와 ZIP**을 `release/public-source/`에 생성합니다.
공개 절차는 [공개 준비 안내](docs/engineering/open-source-publication.md)를 참고하세요.

## English

Aegis WebShield AI is a local-first security scanning project with a Rust engine,
a Windows desktop application (Tauri + React), and the `aegis-scan` CLI.
Projects, targets, and scan results are stored in SQLite on the user's computer.
There is no account registration, paid tier, license activation, or monthly feature quota.

**Status: community source preview.** The package version is 1.0.0; this is not a claim
of a commercially validated or universally stable release. Windows x64 is the primary
desktop target. macOS/Linux desktop packages have not been validated.

### Features

- Passive checks, exposure checks, and bounded active verification of explicitly approved targets
- Endpoint import from OpenAPI 3.x JSON/YAML, URL lists, HTML, and browser observation logs
- Local project/target/scan/finding management and comparison with previous scans
- HTML, Markdown, JSON, PDF, and SARIF reports; CLI failure policies for CI
- Rule pack validation, import, rollback, and optional signature verification
- Optional AI remediation guides using your own OpenAI API key

All implemented features are free. **AI provider API charges are separate.**
Scanning and reporting work without an AI key. When you request a guide, the required
redacted finding information is sent to the provider. Keys are stored in Windows
Credential Manager; this repository does not supply shared API credentials.

### Build and run

On Windows x64, install Node.js 22.x (22.12 or later), npm, the stable Rust MSVC
toolchain, Visual Studio Build Tools with Desktop development with C++, and the
Microsoft Edge WebView2 Runtime. Playwright Chromium is optional for browser crawling.

From the downloaded repository root:

```powershell
git clone https://github.com/ja8685-alt/aegis-webshield-ai.git
cd aegis-webshield-ai
npm ci
npm run tauri -- dev
```

Use `npm run dev` for a browser-only UI preview. It displays sample data and does
not run native scanning, database, or credential-storage commands.

```powershell
cargo build --locked -p aegis-cli
cargo run --locked -p aegis-cli -- --help
cargo run --locked -p aegis-cli -- scan --help
```

Only scan targets you own or are explicitly authorized to test. See the
[CLI guide](docs/product/cli-user-guide.md) for approval arguments and examples.
For the optional browser crawler, run `npx playwright install chromium`.

### Validation and Windows installers

```powershell
npm run build
npm run test:publication
cargo test --locked --workspace
npm run verify:tauri-security
npm run verify:brand-icons
```

Run `npm run bundle:windows` to build local MSI/NSIS installers. A successful build
does not establish signing, SmartScreen reputation, or installed-app correctness.
Follow the [Windows release checklist](docs/engineering/windows-release-checklist.md)
before distributing installers. A paid signing certificate is not required to publish source.

### Data, safety, and limitations

- Public source excludes real databases, scan reports, diagnostics, API keys, private keys,
  certificates, and developer Git configuration.
- Database schemas and migrations remain as application code. Upgrades preserve existing data.
- Resource limits, target approval, bounded crawling, and redaction remain enabled.
- Active results are candidates requiring manual confirmation, not proof of exploitation.
- AI output needs human review. Automatic update downloads and organization account servers are not provided.

[Desktop guide](docs/product/desktop-user-guide.md) ·
[Known limitations](docs/product/known-issues-v1.0.md) ·
[Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md)

### License and publication

Project code is available under the [Apache License 2.0](LICENSE).
Dependencies retain their own terms; see [NOTICE](NOTICE) and
[third-party notices](THIRD_PARTY_NOTICES.md).

Start a new public repository with the reviewed source files as its first commit.
Do not copy the existing repository's `.git` directory or private history.
`npm run public:prepare` copies only the
reviewed file inventory and scans it for secrets, producing a **history-free source
directory and ZIP** under `release/public-source/`.
See the [publication guide](docs/engineering/open-source-publication.md).
