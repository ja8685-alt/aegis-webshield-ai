# 법인용 Windows 코드 서명 인증서 발급 및 운영 가이드

## 문서 목적

이 문서는 Aegis WebShield AI의 Windows MSI/NSIS 설치 파일을 Authenticode로 서명하기 위한 법인 명의 공개 신뢰 Code Signing 인증서의 선택, 발급, 검증, 설치, 서명, 갱신 및 폐기 절차를 정의한다.

여기서 다루는 인증서는 은행, 세금계산서, 전자계약에 사용하는 국내 법인 공동인증서가 아니다. Windows 설치 화면에 검증된 게시자 이름을 표시하고 배포 파일의 발행자와 무결성을 증명하는 Code Signing 인증서다.

이 문서의 외부 정책 확인 기준일은 2026-08-05다. 인증기관(CA)의 상품, 지원 국가, 유효기간, 검증 및 키 보관 정책은 주문 전에 다시 확인한다.

## 권장 선택

Aegis WebShield AI의 일반 MSI/NSIS 배포에는 다음 구성을 기본으로 한다.

- 인증서: 법인 OV(Organization Validation) Code Signing
- 개인키 보관: CA가 제공하거나 인정하는 USB 암호화 토큰
- 서명 환경: 접근이 제한된 전용 Windows 릴리스 계정과 릴리스 머신
- 서명 도구: Windows SDK SignTool
- 파일 및 타임스탬프 다이제스트: SHA-256
- 타임스탬프: CA가 제공하는 공개 HTTPS RFC 3161 endpoint
- 인증서 선택: Windows 인증서 저장소의 명시적 SHA-1 thumbprint

EV Code Signing은 다음 조건 중 하나가 확인될 때 선택한다.

- Windows Hardware Developer Center를 사용하는 커널 드라이버 배포가 필요하다.
- 고객이나 조달 계약이 EV 인증서를 명시적으로 요구한다.
- 더 엄격한 법인·담당자 검증 수준 자체가 계약상 요구사항이다.

Microsoft는 현재 EV 인증서가 SmartScreen 평판을 즉시 부여하지 않는다고 안내한다. 따라서 SmartScreen 경고 제거만을 목적으로 EV를 구매하지 않는다. 신규 OV/EV 서명 앱은 모두 충분한 배포 이력과 긍정적 평판이 쌓이기 전까지 SmartScreen 경고가 나타날 수 있다.

Microsoft Artifact Signing의 Public Trust는 지원 지역 제한이 있으므로 한국 법인이 직접 사용할 수 있는지 주문 시점에 확인한다. 지원되지 않으면 공개 CA의 OV 인증서 또는 Microsoft Store 배포를 사용한다.

## 업계 필수 키 보관 정책

공개 신뢰 Code Signing 인증서는 OV와 EV 모두 개인키를 적격 Hardware Crypto Module에서 생성, 저장 및 사용해야 한다. 일반 PFX 파일을 내려받아 개발자 PC나 CI 환경변수에 복사하는 방식을 발급 전제로 삼지 않는다.

허용되는 대표 방식은 다음과 같다.

- CA 제공 USB 암호화 토큰
- CA가 인정하고 key attestation을 지원하는 자체 HSM
- 요구사항을 충족하는 관리형 클라우드 HSM 또는 원격 서명 서비스

단일 Windows 릴리스 머신에서 수동 승인 방식으로 MSI/NSIS를 서명하는 현재 단계에는 USB 토큰이 가장 단순하다. 무인 CI 서명이 필요해지면 USB 토큰의 PIN 자동화를 시도하지 말고 HSM 또는 관리형 서명 서비스로 별도 전환을 설계한다.

## 신청 전 준비사항

### 법인 식별정보

다음 정보를 법인 서류와 일치하도록 확정한다.

- 법인의 정식 한글명
- 인증서 Subject에 사용할 정식 영문명
- 법인등록번호 또는 사업자등록번호
- 설립 국가와 법인 형태
- 본점 소재지와 영문 주소
- 대표자 이름
- 회사 웹사이트와 소유 도메인
- 회사 대표전화

영문 법인명은 임의의 제품 브랜드명을 넣지 않는다. CA가 법인 등기 또는 정부 자료와 연결하여 인정할 수 있는 표기인지 주문 전에 서면으로 확인한다. 인증서에 기록된 조직명이 Windows의 `Verified publisher`로 표시되며, 발급 후 이름을 바꾸려면 재발급이 필요할 수 있다.

### 담당자와 권한

다음 역할을 정한다. CA에 따라 한 명이 여러 역할을 겸할 수 있다.

- Certificate Requester: 인증서를 실제로 신청하는 담당자
- Certificate Approver 또는 Verified Contact: 법인을 대신해 발급을 승인하는 담당자
- Contract Signer: 가입자 계약에 동의할 권한이 있는 담당자
- Release Signer: 발급 후 토큰을 보관하고 실제 릴리스 서명을 수행하는 담당자

신청 담당자는 개인 이메일보다 회사 도메인의 개인별 업무 이메일을 사용한다. 공용 메일이나 무료 이메일은 추가 검증 사유가 될 수 있으므로 CA와 미리 협의한다.

### 대표전화 검증

대표전화 검증은 발급 지연이 자주 발생하는 단계다. CA는 신청서에 입력한 개인 휴대전화만 신뢰하지 않고 정부 자료, 통신사 자료 또는 신뢰 가능한 독립 데이터 소스에서 법인과 연결된 연락 방법을 확인할 수 있다.

신청 전에 다음을 완료한다.

- 회사 홈페이지에 법인명, 주소, 대표전화를 일관되게 표시한다.
- 외부에서 확인 가능한 회사 대표전화가 실제로 수신되는지 점검한다.
- 자동응답을 사용하는 경우 담당자 또는 경영지원 부서로 연결되게 한다.
- 전화 수신 담당자에게 해외 CA의 영문 검증 전화가 올 수 있음을 알린다.
- 신청자의 이름, 직책, 재직 여부 및 인증서 신청 권한을 확인할 담당자를 지정한다.
- 대표전화가 독립적으로 확인되지 않으면 CA에 허용 가능한 대체 증빙을 먼저 문의한다.

## 예상 제출서류

정확한 서류는 CA와 검증 결과에 따라 달라진다. 불필요한 개인정보 제출을 피하고, CA 검증 담당자가 요구한 공식 업로드 채널만 사용한다.

기본 준비 자료:

- 사업자등록증 또는 사업자등록증명
- 법인 등기사항전부증명서
- 법인명과 본점 주소의 영문 표기
- 인증서 신청 담당자의 회사 이메일, 이름 및 직책
- 가입자 계약 또는 Subscriber Agreement 승인
- 회사 대표전화를 통한 신청 권한 확인 준비

추가로 요청될 수 있는 자료:

- 영문 사업자등록증명 또는 영문 번역본
- 대표자나 담당자의 신분증
- 재직증명서
- 법인 인감이 포함된 위임장
- 전화요금 또는 공공요금 고지서
- 은행 거래 증명 또는 주소 증명
- 변호사나 회계사가 작성한 확인서
- 번역 공증 또는 원본 대조 확인

주문 전에 임의로 번역 공증을 진행하지 않는다. CA가 인정하는 문서 종류, 발행일 제한, 번역자 및 공증 형식이 다를 수 있으므로 주문번호를 받은 뒤 검증 담당자의 요구에 맞춘다.

## CA 및 상품 비교 항목

DigiCert, GlobalSign, Sectigo 등 공개 신뢰 Code Signing CA 또는 공식 리셀러에 동일한 조건으로 견적과 사전 검증 가능 여부를 문의한다.

확인할 항목:

- 상품명이 법인 OV Code Signing인지
- 인증서 Subject에 표시될 정확한 법인명
- 한국 법인 검증과 한국 서류 처리 가능 여부
- 검증 지원 언어와 운영 시간대
- 인증서의 실제 유효기간
- USB 토큰 포함 여부, 제조사, 배송비 및 예상 배송 기간
- Windows용 토큰 미들웨어와 CSP/KSP 제공 여부
- Windows SDK SignTool 및 SHA-256 Authenticode 호환 여부
- 공개 HTTPS RFC 3161 타임스탬프 URL
- 발급 실패 시 환불 정책
- 영문명이나 조직정보 오류 시 재발급 정책
- 토큰 분실·고장·PIN 잠김 시 교체 절차와 비용
- 개인키 침해 의심 시 폐기 SLA와 긴급 연락 채널
- 갱신 시 법인 검증 정보 재사용 가능 여부
- 향후 HSM 또는 클라우드 서명 서비스로 이전 가능한지

CA의 웹사이트와 공식 리셀러의 설명이 다르면 CA의 현재 Certificate Policy, Certification Practice Statement와 검증 담당자의 서면 답변을 우선한다.

## 발급 절차

1. 후보 CA에 법인 영문명, 한국 법인 여부, 대표전화 확인 방법을 제시하고 사전 발급 가능 여부를 문의한다.
2. 법인 OV Code Signing 상품과 USB 토큰 또는 승인된 HSM 보관 방식을 선택한다.
3. 인증서 Subject에 사용할 법인명을 최종 확인한다.
4. 법인등록번호, 주소, 대표전화, 신청·승인 담당자 정보를 입력한다.
5. 결제하고 Subscriber Agreement에 동의한다.
6. CA가 법인의 법적 실재성, 주소, 운영 상태와 제재·사기 관련 정보를 검증한다.
7. 자동 검증이 부족하면 CA가 요청한 법인 서류를 공식 채널에 제출한다.
8. CA가 독립적으로 확인한 대표전화 또는 허용된 업무 연락 방법으로 법인에 연락한다.
9. 신청자의 신원, 재직 여부와 법인을 대신한 신청 권한을 확인한다.
10. Verified Contact 또는 승인 담당자가 인증서 요청을 승인한다.
11. 모든 검증이 완료되면 CA가 인증서를 발급한다.
12. USB 토큰 방식이면 CA 또는 배송사가 토큰과 초기화 정보를 전달한다.
13. 토큰 미들웨어를 설치하고 초기 PIN을 즉시 변경한다.
14. Windows 인증서 저장소와 SignTool에서 인증서 및 개인키 접근을 확인한다.

서류와 대표전화가 준비된 경우에도 내부 결재, CA 검증 및 국제배송을 고려해 전체 일정을 최소 1~2주로 계획한다. 이 기간은 보장된 CA SLA가 아니며 영문명, 주소, 전화 또는 권한 확인이 실패하면 더 길어질 수 있다.

## 토큰 수령과 Windows 설정

토큰 제조사의 공식 배포 경로에서 현재 Windows용 미들웨어를 설치한다. 이메일 첨부 파일이나 비공식 다운로드 사이트의 드라이버를 사용하지 않는다.

초기 설정 순서:

1. 전용 릴리스 머신에서 토큰 미들웨어를 설치한다.
2. USB 토큰을 연결하고 CA가 제공한 초기 PIN 절차를 따른다.
3. 초기 PIN을 조직의 비밀정보 관리 정책에 맞는 값으로 변경한다.
4. PIN 잠금 횟수와 관리자 PIN 또는 복구 정책을 기록한다.
5. 인증서가 `CurrentUser\My` 또는 `LocalMachine\My`에 노출되는지 확인한다.
6. 인증서의 Subject, 유효기간, Code Signing EKU와 private key 접근을 확인한다.
7. 테스트 바이너리에 서명하고 RFC 3161 타임스탬프와 인증서 체인을 검증한다.

현재 사용자 저장소 확인:

```powershell
Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
  Format-List Subject, Thumbprint, NotBefore, NotAfter, HasPrivateKey
```

컴퓨터 저장소 확인:

```powershell
Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert |
  Format-List Subject, Thumbprint, NotBefore, NotAfter, HasPrivateKey
```

확인 조건:

- `Subject`가 승인한 법인명과 일치한다.
- 인증서가 현재 유효기간 안에 있다.
- Code Signing EKU `1.3.6.1.5.5.7.3.3`이 포함되어 있다.
- `HasPrivateKey`가 `True`이고 실제 서명 시 토큰을 통해 접근할 수 있다.
- 사용할 인증서 thumbprint가 정확히 식별된다.

thumbprint가 SHA-1 형식인 것은 Windows 인증서 선택 식별자이기 때문이다. 실제 파일 서명과 타임스탬프 다이제스트는 SHA-256을 사용한다.

## Aegis WebShield AI 서명 절차

현재 저장소는 PFX와 비밀번호를 전달하지 않고 `CurrentUser\My` 또는 `LocalMachine\My`의 인증서를 명시적 thumbprint로 선택한다. 토큰 PIN을 명령행이나 환경변수에 전달하지 않는다.

### 사전 점검

Windows SDK 또는 Visual Studio의 SignTool과 토큰 미들웨어가 설치된 릴리스 머신에서 번들을 생성한다.

```powershell
npm run bundle:windows
```

서명 대상과 인증서 선택만 먼저 점검한다.

```powershell
npm run sign:windows-installers -- --CertificateThumbprint <40-hex-thumbprint> --TimestampUrl https://<tsa-host>/<rfc3161-path> --DryRun
```

### 실제 서명

`CurrentUser\My` 인증서를 사용할 때:

```powershell
npm run sign:windows-installers -- --CertificateThumbprint <40-hex-thumbprint> --TimestampUrl https://<tsa-host>/<rfc3161-path>
```

`LocalMachine\My` 인증서를 사용할 때는 관리자 PowerShell에서 다음과 같이 실행한다.

```powershell
npm run sign:windows-installers -- --CertificateThumbprint <40-hex-thumbprint> --TimestampUrl https://<tsa-host>/<rfc3161-path> --MachineStore
```

CA가 문서 예제로 HTTP 타임스탬프 URL을 제공하더라도 이 저장소에는 credential, query, fragment가 없는 공개 HTTPS RFC 3161 endpoint만 전달한다.

### 서명 검증

```powershell
npm run verify:windows-signatures
```

수동 교차 확인이 필요하면 Windows SDK SignTool을 사용한다.

```powershell
signtool verify /pa /all /v <installer-path>
```

최종 릴리스 후보에서는 전체 오케스트레이션에 인증서와 타임스탬프를 전달한다.

```powershell
npm run release:windows-candidate -- --StrictAudit --SigningCertificateThumbprint <40-hex-thumbprint> --SigningTimestampUrl https://<tsa-host>/<rfc3161-path>
```

`LocalMachine\My`를 사용하면 `--SigningMachineStore`를 추가한다.

서명 후 MSI/NSIS를 수정하거나 다시 패키징하지 않는다. 변경이 필요하면 원본 빌드 단계로 돌아가 새 artifact를 만든 뒤 다시 서명하고 검증한다.

## SmartScreen 운영

공개 신뢰 인증서로 서명하면 Windows가 인증서의 법인명을 게시자로 확인하고 파일 변조 여부를 검증할 수 있다. 그러나 서명만으로 앱의 안전성이나 SmartScreen 무경고를 보장하지 않는다.

- 모든 정식 릴리스를 동일한 법인 신원으로 일관되게 서명한다.
- 서명하지 않은 설치 파일을 공식 채널에 게시하지 않는다.
- 서명 후 artifact를 수정하지 않는다.
- 공식 HTTPS 다운로드 도메인과 릴리스 페이지를 일관되게 유지한다.
- 악성 또는 Potentially Unwanted Application으로 오인될 동작을 릴리스 전에 점검한다.
- 신규 릴리스의 SmartScreen 상태와 제출·검토 증적은 Windows 릴리스 체크리스트에 따라 관리한다.

## 운영 보안

- 토큰과 PIN을 같은 장소에 보관하지 않는다.
- PIN을 소스코드, `.env`, CI 변수, 명령행, 릴리스 로그 또는 지원 문서에 기록하지 않는다.
- 토큰 사용 권한을 최소 인원으로 제한한다.
- 릴리스 담당자와 인증서 폐기 승인 담당자를 구분한다.
- 서명 시도와 릴리스 artifact SHA-256을 감사 가능한 증적으로 남긴다.
- 토큰을 일반 개발, 이메일, 웹브라우징에 사용하는 PC에 상시 연결하지 않는다.
- 원격 USB 전달이나 비공식 USB-over-network 도구를 사용하지 않는다.
- 토큰 분실, PIN 유출 또는 비정상 서명이 의심되면 배포를 중단하고 즉시 CA에 인증서 폐기를 요청한다.
- 인증서와 토큰의 만료·갱신·폐기 책임자를 자산대장에 기록한다.

## 갱신과 폐기

인증서 만료 45~60일 전부터 갱신을 시작한다.

갱신 절차:

1. 법인명, 주소, 대표전화와 담당자 변경 여부를 확인한다.
2. 기존 CA의 검증 재사용 가능 기간을 확인한다.
3. 새 인증서와 새 개인키를 발급받는다.
4. 새 인증서의 Subject, EKU, 체인과 SignTool 동작을 검증한다.
5. 배포 스크립트에 전달하는 thumbprint를 새 값으로 변경한다.
6. 테스트 artifact를 서명하고 별도 Windows 환경에서 검증한다.
7. 구 인증서는 유효한 이전 릴리스 검증과 비상 롤백 정책을 고려하여 통제된 상태로 보관한다.
8. 더 이상 필요하지 않거나 침해된 인증서는 CA 절차에 따라 폐기한다.

유효한 RFC 3161 타임스탬프가 있는 과거 서명은 인증서가 정상 만료된 뒤에도 서명 당시의 유효성을 증명할 수 있다. 타임스탬프가 없는 서명은 인증서 만료 후 무효로 취급될 수 있으므로 모든 정식 서명에 타임스탬프를 적용한다.

## 구매 전 문의 템플릿

```text
Subject: Korean corporation OV Code Signing certificate pre-validation inquiry

We are a corporation registered in the Republic of Korea and plan to sign Windows MSI and NSIS installers.

Please confirm:
1. Whether the proposed English organization name can be used as the certificate Subject.
2. Which Korean corporate documents and translations are required.
3. How the organization telephone number and requester authority will be verified.
4. Whether a hardware USB token, middleware, and shipping to Korea are included.
5. Whether the token is compatible with Windows SDK SignTool using SHA-256 and RFC 3161 timestamping.
6. The public HTTPS RFC 3161 timestamp URL.
7. Certificate validity, expected validation time, reissue policy, and token replacement procedure.
8. Revocation contact and SLA in case of key compromise.
```

문의에는 신분증, 인감, 비밀번호 또는 불필요한 개인정보를 첨부하지 않는다. 검증 담당자가 배정된 후 CA의 인증된 업로드 채널을 이용한다.

## 발급 완료 체크리스트

- [ ] 인증서 Subject의 법인명이 승인된 영문명과 일치한다.
- [ ] 회사 대표전화와 신청 권한 검증이 완료되었다.
- [ ] 토큰과 인증서가 정식 인수인계 기록에 포함되었다.
- [ ] 초기 PIN이 변경되었고 PIN 보관 정책이 적용되었다.
- [ ] 인증서가 Windows 인증서 저장소에서 조회된다.
- [ ] Code Signing EKU와 private key 접근이 확인되었다.
- [ ] 공개 HTTPS RFC 3161 타임스탬프 URL이 확인되었다.
- [ ] `--DryRun`이 성공했다.
- [ ] 테스트 MSI와 NSIS 서명이 성공했다.
- [ ] `npm run verify:windows-signatures`가 성공했다.
- [ ] 별도 Windows 환경에서 게시자명과 서명 체인을 확인했다.
- [ ] 토큰 분실·침해 시 폐기 연락망을 기록했다.
- [ ] 인증서 만료 45~60일 전 갱신 알림을 등록했다.

## 참고 자료

- [Microsoft SmartScreen reputation for Windows app developers](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)
- [Microsoft SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)
- [Microsoft Time Stamping Authenticode Signatures](https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures)
- [CA/Browser Forum Code Signing Baseline Requirements](https://cabforum.org/working-groups/code-signing/requirements/)
- [DigiCert Code Signing certificate request](https://docs.digicert.com/en/certcentral/order-and-manage-certificates/request-certificates/request-a-code-signing-or-ev-code-signing-certificate/request-code-signing-certificate.html)
- [DigiCert Organization Validation](https://docs.digicert.com/en/certcentral/get-started/understand-how-certcentral-works/understand-certificate-validation/validation-levels-in-certcentral/organization-validation--ov-.html)
- [Sectigo OV Code Signing validation](https://www.sectigo.com/faqs/detail/OV-Code-Signing-Validation-for-Organizations-and-Individuals)
- [GlobalSign Code Signing certificates](https://www.globalsign.com/en/code-signing-certificate)
- [Windows release checklist](windows-release-checklist.md)
