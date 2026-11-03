# 2026-06-25 implementation note

- Desktop finding dedupe keys now use a canonical endpoint fingerprint: URL fragments are removed, hosts are normalized, default ports are omitted, and query values are replaced by sorted query parameter names before building `rule_id|endpoint` keys.
- Displayed finding endpoints and reproduction URLs keep the original scanned URL, but dedupe keys avoid storing raw query values.
- CLI baseline comparison now applies the same URL canonicalization to URLs found in finding evidence before computing stable finding fingerprints.

# Finding Dedupe

작성일: 2026-06-13  
상태: 구현 중인 local storage dedupe 기준

## 목적

Finding dedupe는 같은 scan에서 동일 rule과 endpoint가 반복 저장되는 일을 막는다. OpenAPI endpoint, URL seed, crawler 후보가 같은 URL을 중복으로 제공할 수 있으므로 저장소 레벨에서 한 번 더 병합한다.

## 현재 구현

- Migration: `0003_findings_dedupe_key`
- Column: `findings.dedupe_key`
- Unique index: `(scan_id, dedupe_key)` where `dedupe_key IS NOT NULL`
- Desktop 저장 흐름의 key 형식:
  - 일반 finding: `rule_id|endpoint`
  - parameter 단위 active finding: `rule_id|endpoint|parameter_name`
- 중복 key로 `create_finding`을 호출하면 새 row를 만들지 않고 기존 finding을 반환한다.
- evidence JSON은 report export와 AI Fix Guide 입력에서 같은 구조를 재사용할 수 있도록 `source`와 `reproduction` 메타데이터를 포함한다.

## 보안/운영 기준

- Dedupe key는 민감정보가 아닌 rule id와 endpoint scheduling metadata만 사용한다.
- 기존 DB의 finding은 `NULL` dedupe key로 유지되어 migration이 backward-compatible하다.
- Dedupe key가 없는 외부/미래 importer 입력은 기존처럼 저장할 수 있다.
- Scan이 다르면 같은 rule/endpoint라도 별도 finding으로 저장한다.

## 다음 확장 후보

- normalized URL canonicalization
- evidence hash 기반 보조 dedupe
- baseline diff용 stable fingerprint 분리
