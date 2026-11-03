# Desktop Update Channel Policy

작성일: 2026-06-24  
상태: 릴리스 후보 준비 기준

## 목적

Aegis WebShield AI Desktop의 자동 업데이트는 설치형 보안 제품의 신뢰 경로에 포함된다. 업데이트 채널은 앱 업데이트와 rule pack 업데이트를 분리하고, 배포 artifact의 서명, 체크섬, 채널 권한을 릴리스 전에 검증할 수 있어야 한다.

## 채널

- `stable`: 일반 고객용 기본 채널. 코드 서명, installer smoke test, signature verification, release preflight가 모두 통과한 artifact만 게시한다.
- `beta`: 사전 검증 고객과 내부 QA용 채널. stable과 동일한 서명/체크섬 기준을 적용하되 known issues를 release notes에 명시한다.
- `internal`: 개발/QA 내부 채널. 외부 고객에게 노출하지 않으며, 다운로드 URL과 manifest는 공개 문서에 기록하지 않는다.

## Manifest 형식

업데이트 manifest는 JSON으로 관리한다. 릴리스 CI 또는 운영자는 게시 전 `npm run update:verify-manifest -- --file <path>`를 실행한다.

```json
{
  "product": "Aegis WebShield AI",
  "version": "1.0.0",
  "channel": "stable",
  "pub_date": "2026-06-24T00:00:00Z",
  "platforms": {
    "windows-x86_64": {
      "url": "https://downloads.example.com/aegis/Aegis-WebShield-AI-1.0.0-x64-setup.exe",
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "signature": "base64-or-provider-release-signature",
      "size_bytes": 12345678
    }
  }
}
```

필수 기준:

- `product`는 `Aegis WebShield AI`여야 한다.
- `version`은 semantic version이어야 하며 현재 `package.json` version과 일치해야 한다.
- `channel`은 `stable`, `beta`, `internal` 중 하나여야 한다.
- `pub_date`는 ISO-8601 timestamp여야 한다.
- 다운로드 URL은 `https://`만 허용하며 embedded credential, query string, fragment, token/password/secret 등 민감 label을 포함하지 않는다.
- `platforms.windows-x86_64`는 Windows desktop v1.0 release manifest에 반드시 포함되어야 한다.
- 각 artifact는 SHA-256과 release signature를 포함해야 한다.
- manifest에는 private key, token, API key, password, secret 계열 필드를 포함하지 않는다.

## 릴리스 순서

1. Windows 네이티브 검증을 실행한다.
2. MSI/NSIS artifact를 생성한다.
3. artifact에 코드 서명을 적용한다.
4. installer smoke test와 Authenticode signature verification을 실행한다.
5. release notes, checksum, signed rule feed artifact를 생성하고 `release:verify`를 통과시킨다.
6. update manifest를 작성하고 `update:verify-manifest`를 통과시킨다.
7. manifest와 artifact를 채널별 저장소에 게시한다.

## 보안 원칙

- 앱 업데이트 manifest와 rule pack update feed는 별도 파일과 별도 검증 흐름으로 관리한다.
- update manifest는 artifact 위치와 무결성 정보만 담고, 라이선스 키나 고객 식별자를 포함하지 않는다.
- 안정 채널 게시 전 unsigned artifact는 허용하지 않는다.
- 내부 채널 URL과 manifest는 고객용 release notes에 노출하지 않는다.
