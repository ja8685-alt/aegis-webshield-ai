# Local activity and resource policy

현재 정책은 [커뮤니티 에디션](community-edition.md)을 따른다.

- 프로젝트·대상·월간 스캔·리포트·AI 가이드에 과금 한도가 없다.
- usage snapshot은 로컬 활동 표시와 진단에만 사용한다.
- `UsageSnapshot::scan_capacity_available`은 활성 스캔 수만 검사한다.
- `MAX_CONCURRENT_SCANS = 2`는 자원 보호 기준이며 라이선스와 무관하다.
- 대상 승인·사설망 옵션·요청 예산·마스킹은 유지한다.
- 기존 DB의 플랜 필드와 licenses 테이블은 이전 마이그레이션 호환용이며 사용하지 않는다.
