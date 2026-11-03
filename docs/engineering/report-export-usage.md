# Report export and activity

갱신일: 2026-11-03

HTML, Markdown, JSON, PDF, SARIF 리포트를 모두 무료로 제공한다. 월간 내보내기 한도는 없다.
리포트 생성 성공은 활동 통계와 감사 로그로 기록하지만 과금 접근 제어에 사용하지 않는다.

- Desktop은 마스킹된 artifact를 앱 데이터 `reports/`에 저장한다.
- 파일명·크기·SHA-256을 감사 메타데이터로 남긴다.
- URL query value/fragment와 authorization, cookie, token, password, key 값은 출력 전에 마스킹한다.
- Native active 결과는 `source`, `requires_manual_confirmation`, `finding_classification`으로 후보 여부를 표시한다.
- PDF는 요약·필터·증거·수정 안내를 포함하는 텍스트 중심 출력이다.
- Reports 패널에서 기간 기준 정리를 요청할 수 있으며 입력 범위는 1~3650일이다.
- 시작 시 30일 기준 정리와 명시적 정리는 앱 데이터의 리포트 artifact에만 적용한다.
- CLI의 저장된 스캔 JSON/text/SARIF 내보내기도 마스킹된 복사본을 사용한다.
- 리포트 데이터·진단 출력·사용자 DB는 소스 배포 패키지에 포함하지 않는다.
