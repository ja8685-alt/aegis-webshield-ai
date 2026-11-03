# 기여 안내 / Contributing

버그 재현, 문서·번역, 탐지 오탐 개선, 테스트 기여를 환영합니다.
Contributions to reproducibility, documentation, translations, detection accuracy,
and tests are welcome.

1. README의 환경과 명령으로 실행합니다. / Start with the README setup instructions.
2. 작은 변경을 만들고 목적과 재현 방법을 설명합니다. / Keep changes focused and explain their purpose.
3. 동작 변경에는 회귀 테스트를 포함합니다. / Include regression coverage for behavior changes.
4. `cargo fmt --all -- --check`, `cargo test --locked --workspace`, `npm run build`,
   `npm run test:publication`을 실행합니다. / Run these checks before a pull request.

실제 대상 URL, 고객 결과, 쿠키, 자격증명, DB, 내부 서버 주소를 이슈·PR·테스트에
첨부하지 마세요. 예약된 `example.com`, `.example`, `.invalid`와 합성 데이터를 사용하세요.
Do not submit customer data, credentials, real target URLs, databases, or internal
infrastructure details. Use reserved example domains and synthetic fixtures.

요청 승인, 네트워크 격리, 리다이렉트 검사, 파일 크기 제한, 마스킹, 서명 검증은
유료 제한이 아닙니다. 기여 과정에서 제거하지 마세요.
Approval, isolation, redirect checks, resource bounds, redaction, and signature
verification are safety controls and must remain intact.

보안 문제는 [SECURITY.md](SECURITY.md)를 따르세요. 새 의존성에는 라이선스와
용도를 명시하고 `npm run notices:generate`로 고지를 갱신하세요.
Follow SECURITY.md for security issues. Explain new dependencies and their licenses,
and regenerate notices with `npm run notices:generate`.

기여자는 제출한 코드의 배포 권리가 있어야 하며 프로젝트에 대한 기여는 별도 명시가
없는 한 Apache-2.0으로 제공됩니다. 상표·외부 저작물의 권리는 별도입니다.
Only submit work you have the right to contribute. Unless explicitly stated otherwise,
contributions are provided under Apache-2.0; third-party and trademark rights remain separate.

응답 시간이나 기능 반영을 보장하지 않는 커뮤니티 프로젝트입니다.
This is a community project with no guaranteed response time or implementation commitment.
