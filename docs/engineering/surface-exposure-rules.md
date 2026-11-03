# 2026-06-25 implementation note

- Surface profile scans now combine saved safe GET/HEAD endpoint candidates with origin-scoped well-known sensitive path probes such as `/.env`, `/.git/config`, `/actuator/env`, `/phpinfo.php`, `/server-status`, and common admin consoles.

# Surface Exposure Rules

작성일: 2026-06-13  
상태: 구현 중인 자체 보안 엔진 규칙 기준

## 목적

Surface exposure rule은 사용자가 승인한 URL/API를 안전하게 probe한 뒤, 공개되어서는 안 되는 경로와 응답 신호를 식별한다. 현재 구현은 추가 공격 payload 없이 HTTP 응답의 최종 URL, 상태 코드, 제한된 body sample만 사용한다.

## 안전 원칙

- 상태 변경 요청을 보내지 않는다. passive probe의 `GET`/`HEAD` 제한을 그대로 따른다.
- body 전문을 evidence에 저장하지 않는다.
- `.env`, `.git`, backup/dump 파일은 HTTP 2xx/3xx 응답일 때만 노출로 판단한다.
- debug/admin endpoint는 HTTP 5xx 미만이면 접근 가능한 surface로 기록한다.
- directory listing과 stack trace는 제한된 body sample에서 대표 marker만 확인한다.

## 현재 규칙

| Rule ID | Severity | 조건 | 권장 조치 |
| --- | --- | --- | --- |
| `surface.exposed_git_metadata` | High | `/.git` 또는 `/.git/...` 경로가 HTTP 2xx/3xx로 응답 | `.git` 경로를 차단하고 document root에서 repository metadata를 제거한다. |
| `surface.exposed_env_file` | High | `.env` 계열 경로가 HTTP 2xx/3xx로 응답 | 환경 파일을 web root 밖으로 이동하고 노출 가능성이 있는 secret을 회전한다. |
| `surface.exposed_backup_or_dump_file` | Medium | `.bak`, `.backup`, `.old`, `.orig`, `.save`, `.sql`, `.dump`, `.zip`, `.tar`, `.tar.gz`, `.tgz` 경로가 HTTP 2xx/3xx로 응답 | 백업과 dump 파일을 document root 밖으로 이동하고 인증된 운영 경로로만 접근하게 한다. |
| `surface.exposed_debug_endpoint` | Medium | `/debug`, `/actuator/...`, `/phpinfo.php`, `/server-status` 등 debug/management 경로가 HTTP 5xx 미만으로 응답 | production debug endpoint를 비활성화하거나 인증/네트워크 제한을 적용한다. |
| `surface.admin_console_reachable` | Low | `/admin`, `/wp-admin`, `/phpmyadmin`, `/manager/html`, `/console` 등 admin 경로가 HTTP 5xx 미만으로 응답 | 강한 인증, MFA, 접근 IP 제한, rate limit을 적용한다. |
| `surface.directory_listing_enabled` | Medium | body sample이 auto-generated directory index marker를 포함 | directory index를 비활성화하고 명시적 index 문서를 제공한다. |
| `surface.stack_trace_disclosure` | Medium | body sample이 framework/runtime stack trace marker를 포함 | production 상세 오류 출력을 끄고 stack trace는 보호된 log로만 보낸다. |

## 다음 확장 후보

- HTTP crawler가 수집한 link/form/script endpoint에 surface rule 적용
- OpenAPI endpoint와 well-known sensitive path 후보 결합
- CORS exposure rule
- cache policy rule
- baseline diff로 새로 열린 admin/debug endpoint 감지
- finding dedupe key와 confidence score 분리
