# 오픈소스 공개 준비 / Public source publication

갱신일: 2026-11-03

최종 결정: **새 저장소에 공개한다.** 기존 저장소를 대상으로 준비했던 이력 교체는 중단한다.
기존 원격에 강제 푸시하거나 공개 설정을 바꾸지 않는다. 비공개 백업과 이력 정리 후보는
보관만 하며 새 저장소에 업로드하지 않는다.

## 공개 범위

Apache-2.0 커뮤니티 소스를 공개한다. `scripts/public-source-files.json`에 명시한 소스,
테스트, SQL 스키마, 빌드 설정, 공개 문서와 라이선스만 패키징한다.
실제 DB·키·내부 주소·고객 데이터·릴리스 증거·Git 이력·개인 개발 문서는 제외한다.

기존 비공개 원격을 public으로 바꾸거나 `git push --mirror`하지 않는다.
과거 커밋에는 작성자 이메일, 삭제된 파일, 비공개 원격 정보가 남을 수 있다.
새 저장소에는 이력 없는 공개 폴더의 파일만 첫 커밋으로 추가한다.
원본 저장소와 사용자의 실제 앱 데이터는 보존한다.

## 준비 명령

```powershell
npm ci
npm run notices:generate
npm run test:publication
npm run build
cargo test --locked --workspace
npm run public:prepare
```

`public:prepare`에는 PATH의 Gitleaks가 필요하다. 검증 기준 버전은 8.30.1이다.
도구가 없거나 검사가 실패하면 패키징을 중단한다. 비밀정보 검사는 로컬에서 수행하며
후보 값은 출력하지 않는다. 필터를 넓혀 실제 키나 DB를 통과시키지 않는다.

패키지는 `release/public-source/<timestamp>/source/`, `source.zip`, `manifest.json`이다.
manifest는 공개 상대 경로·파일 크기·SHA-256·검사 결과만 포함하며 개인 경로·원본 커밋
작성자·비공개 원격·Git 설정은 포함하지 않는다. 기존 출력이 있으면 덮어쓰지 않는다.
ZIP만 공개해도 되며, source 폴더에서 새 Git 저장소를 시작해도 된다.

공개 폴더에서도 `npm ci`, `npm run build`, `cargo test --locked --workspace`를 확인한다.
웹 UI 미리보기는 네이티브 앱 검증을 대신하지 않는다.

## 공개 직전 저장소 설정

새 저장소의 소유자·이름·공개 여부는 관리자가 결정한다. 공개 폴더만 추가하고 원래 `.git`을
복사하지 않는다. 작성자 이메일의 공개 범위를 확인하고 필요하면 호스팅 서비스의 비공개 이메일을 사용한다.
비공개 취약점 신고, 시크릿 검사·푸시 보호, 기본 브랜치 보호를 활성화한다.
CI가 새 저장소에서 통과한 뒤 릴리스 설명에 커뮤니티 프리뷰 상태를 명시한다.

새 저장소는 빈 저장소로 만들고 검증된 `source.zip`을 별도 폴더에 풀어 시작한다.
원래 작업 폴더·백업 bundle·release 폴더 전체를 복사하지 않는다.
첫 커밋 전에 저장소 로컬 `user.name`과 `user.email`을 공개 가능한 값으로 설정한다.
기존 Git의 개인 이메일을 그대로 상속하지 않도록 확인한다. GitHub라면 계정 설정의
비공개 이메일을 사용할 수 있다. 새 원격 주소를 확인한 뒤 첫 커밋과 `main`만 푸시한다.
이 절차에는 기존 원격 이력의 강제 교체나 서버 객체 삭제가 필요하지 않다.

GitHub에서는 `.github/workflows/ci.yml`을 사용한다. Bitbucket을 선택했다면
`bitbucket-pipelines.yml`의 수동 `public-source-checks`를 실행한다. Bitbucket의
Linux Rust 단계는 Tauri Desktop을 제외한 엔진·CLI 테스트이며 Windows 앱 검증을
대신하지 않는다. 실제 호스팅 CI 성공 여부는 원격 실행 결과로 확인한다.
`SECURITY.md`의 비공개 신고 경로도 선택한 호스팅 서비스에서 실제 사용할 수 있게 설정한다.

Apache-2.0 적용은 프로젝트 자체 코드에 대한 것이다. 외부 반입 코드·이미지·기여의 재배포
권한과 고지는 권리자가 확인해야 한다. 의존성 메타데이터 목록은 법적 권리 확인을 대신하지 않는다.
의존성을 포함한 바이너리 배포 시에는 각 라이선스의 고지·소스 제공 조건을 별도로 충족한다.

## 설치 파일

소스 공개와 MSI/NSIS 공개는 별도다. Windows 서명, 설치/삭제, 실제 앱·Credential Manager,
마스킹·진단 검증을 통과하지 않은 설치 파일을 검증된 안정판으로 표시하지 않는다.
공개 소스 패키지에는 설치 파일, 서명 인증서, 업데이트 개인키, 실제 배포 서버 설정을 넣지 않는다.

## English summary

Publish only the explicit public file inventory as a fresh, history-free repository.
Do not change the old private repository's visibility or mirror its Git history.
`npm run public:prepare` rejects unsafe paths, symlinks, data/credential files, and
secret-scan failures, then writes a source directory, ZIP, and SHA-256 manifest.
Original application data and private history remain untouched.

The final decision is to use a new repository. The existing-repository history
replacement is cancelled; private backup bundles and sanitized-history candidates
must not be uploaded. Extract the reviewed ZIP into a separate directory, choose
a public-safe local Git author identity, and push only the new initial main branch
to the confirmed destination. No force push or old-server history cleanup is needed.

Use the GitHub workflow on GitHub, or manually run `public-source-checks` on
Bitbucket. Bitbucket's Linux Rust step excludes Tauri Desktop. Verify actual hosted
CI results and configure a working private security-reporting route before release.

The maintainer chooses the public repository, enables private security reporting and
secret protection, verifies CI, and confirms redistribution rights. Source publication
does not certify an installer release or establish exhaustive security/legal clearance.
