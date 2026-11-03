# URL Seed Importer Design

작성일: 2026-06-13  
상태: 구현 중인 자체 보안 엔진 importer 기준

## 목적

URL seed importer는 사용자가 승인한 URL 목록을 자체 scan engine의 초기 seed 후보로 정규화한다. OpenAPI 문서가 없는 사이트, admin console, 공개 landing page, 특정 API endpoint를 안전하게 등록하기 위한 가장 단순한 입력 경로다.

## 현재 범위

- `aegis-urlseed` workspace crate로 구현한다.
- 일반 텍스트 파일이나 pasted text를 입력으로 받는다.
- 한 줄에 하나의 URL을 허용한다.
- 빈 줄, `#` 주석, `//` 주석을 건너뛴다.
- UTF-8 BOM을 허용한다.
- `http`와 `https` URL만 허용한다.
- URL fragment를 제거한다.
- 정규화 후 중복 URL을 제거한다.
- 최대 5,000개 seed로 제한한다.
- `aegis-scan import-urls` CLI 명령으로 JSON/text 출력을 제공한다.
- Desktop target creation flow에서 pasted URL 목록 또는 `.txt`, `.csv`, `.list` 파일을 분석하고 endpoint 후보로 저장한다.
- 저장된 URL seed endpoint 후보는 scan runner가 base target보다 우선해 safe passive probe 대상으로 사용한다.

## 보안 규칙

- importer는 네트워크 요청을 수행하지 않는다.
- importer는 승인 입력을 정규화할 뿐 실제 scan scope 검증을 대체하지 않는다.
- private network 허용 여부는 scan 실행 단계의 scope validator가 다시 판단한다.
- URL fragment는 HTTP 요청에 사용되지 않으므로 제거한다.
- 오류에는 line number를 포함하되 URL credential이나 body 내용은 저장하지 않는다.
- Desktop 파일 입력은 브라우저 file input으로 읽고, URL seed 문서는 512 KiB로 제한한다.

## CLI 예시

```powershell
aegis-scan import-urls --file .\approved-urls.txt --format json
```

입력 예시:

```text
# Approved by SEC-123
https://example.com/
https://example.com/admin#login
https://api.example.com/v1/health
```

## 다음 확장 후보

- Seed별 method/profile/approval note metadata 지원
- CSV 입력 컬럼 매핑 지원
- HTTP crawler와 OpenAPI endpoint 후보를 같은 scheduler queue로 병합
