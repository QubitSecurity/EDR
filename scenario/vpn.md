## 예시 5) VPN/SSL VPN 계정 탈취 및 Lateral Movement 시작

**[1] 이벤트/장비 로그에서 탐지**

* SSL VPN 로그:

  * 평소와 다른 국가/시간대/단말 정보로 접속
* AD 보안 로그:

  * 로그인 후 곧바로 여러 서버에 대한 4624/4625, 5140(공유 접근) 등 발생

**[2] 포렌식 항목으로 확인**

* VPN 게이트웨이/클라이언트 설정 파일, 저장된 자격 증명 여부
* 접속 단말의 브라우저 쿠키/캐시, OTP 백업 여부
* 내부 서버에서의 접속 흔적(최근 RDP/MSTSC 목록, SMB 접속 이력)

**[3] AI로 내용 분석**

* AI 프롬프트 예:

  > “다음 VPN 접속 로그와 AD 로그인 이벤트, 내부 서버 접근 로그를 시간 순으로 정리해서
  > 계정 탈취 후 내부 확산(Lateral Movement) 패턴인지 분석해 줘.
  > 공격자의 목표(파일 서버 접근, 백업 서버 접근 등)를 추정하고,
  > ‘계정 탈취 공격 진행 중/의심/정상’으로 판정해 줘.”

**[4] 공격 판단 + 근거 저장**

* `verdict`: `계정 탈취 후 내부 확산 공격 진행 중`
* `reason`:

  * `[1] 평소 사용 지역과 다른 해외 IP에서 SSL VPN 접속`
  * `[2] 로그인 직후 다수 서버에 대한 SMB/RDP 로그인 시도(성공/실패 혼재)`
  * `[3] 특정 파일 서버에서 대량 파일 열람·복사 이벤트 집중 발생`

---

## Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant Attacker as 공격자
    participant VPN as SSL VPN 장비
    participant DC as AD/인증 서버
    participant EventLog as VPN 로그 + AD 보안 로그
    participant XDR as PLURA-XDR
    participant Forensic as PLURA-Forensic 스크립트(VPN 단말)
    participant AI as AI 분석엔진
    participant DB as 증적저장소

    Attacker ->> VPN: 탈취 계정으로 로그인 시도 (이상 국가/단말)
    VPN ->> EventLog: VPN 접속 로그(위치/단말/시간) 기록
    VPN ->> DC: 내부 자원 접근 트래픽 전달

    DC ->> EventLog: 4624/4625, 5140 등 내부 서버 접근 이벤트 기록
    EventLog ->> XDR: VPN + AD 로그 수집
    XDR ->> XDR: 평소 패턴과 다른 위치/시간/서버 접근 상관분석

    XDR ->> Forensic: 의심 단말 또는 계정 관련 포렌식 수집 요청
    Forensic ->> DC: 해당 계정의 최근 로그인 서버·리소스 목록 조회
    DC -->> Forensic: 접속 이력·공유 접근 정보
    Forensic -->> XDR: Lateral Movement 후보 경로 보고

    XDR ->> AI: VPN 로그 + AD 로그 + 포렌식 경로 정보 전달
    AI ->> AI: 계정 탈취 및 내부 확산 공격 여부 분석
    AI -->> XDR: 판정(진행 중/의심/정상) + 공격 목표 추정·근거

    XDR ->> DB: 판정 결과 + 경로·로그·포렌식 증적 저장
    XDR -->> XDR: 고위험 인시던트 생성 및 계정 차단·세션 강제 종료 제안
```
