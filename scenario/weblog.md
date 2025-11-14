## 예시 4) 웹 로그 + 서버 로그 기반 웹셸 / 취약점 악용 시도

**[1] 이벤트 로그/웹 로그에서 탐지**

* IIS/Apache/Nginx 로그:

  * `cmd=whoami`, `system()`, `cmd.exe /c`, `powershell -enc` 등 포함 요청
  * 파일 업로드 요청 후 `.php`, `.jsp`, `.aspx` 실행 패턴
* Windows:

  * Sysmon 1/11: `w3wp.exe`, `apache.exe` 자식으로 `cmd.exe`, `powershell.exe` 실행

**[2] 포렌식 항목으로 확인**

* 웹 루트 디렉토리 신규/수정 파일 목록
* 업로드 디렉토리(.tmp 포함)에서 의심 스크립트 파일 해시, 내용 일부 샘플링
* 방화벽/WAF 로그(차단/탐지 여부)

**[3] AI로 내용 분석**

* AI 프롬프트 예:

  > “다음 웹 서버 로그와 웹 루트 내 신규 파일 목록, 프로세스 트리를 분석해서
  > 웹셸 업로드 및 실행 공격 여부를 판정해 줘.
  > 공격 단계(스캔 → 업로드 → 실행)를 시간 순으로 정리하고,
  > 웹셸 명령 형태(파일 관리, 시스템 명령 실행 등)도 요약해 줘.”

**[4] 공격 판단 + 근거 저장**

* `verdict`: `웹셸 실행 공격 확정`
* `reason`:

  * `[1] 파일 업로드 요청 직후 동일 IP에서 업로드된 .php 파일 직접 호출`
  * `[2] w3wp.exe 자식으로 cmd.exe/powershell.exe 실행, 명령줄에 whoami/hostname 등 포함`
  * `[3] 신규 .php 파일 내용에서 eval/base64_decode 등 웹셸 패턴 발견`

---

## Sequence Diagram
sequenceDiagram
    autonumber
    participant Attacker as 공격자
    participant WebSrv as 웹 서버
    participant WebLog as 웹 서버 로그(IIS/Apache 등)
    participant EventLog as Sysmon/보안 로그
    participant XDR as PLURA-XDR
    participant Forensic as PLURA-Forensic 스크립트(웹셸)
    participant AI as AI 분석엔진
    participant DB as 증적저장소

    Attacker ->> WebSrv: 취약점 악용·파일 업로드 요청
    WebSrv ->> WebLog: 의심 URL/파라미터·업로드 요청 기록
    WebSrv ->> EventLog: w3wp/apache 자식으로 cmd/powershell 실행 로그

    WebLog ->> XDR: 웹 요청 로그 수집
    EventLog ->> XDR: 프로세스 생성 로그 수집
    XDR ->> XDR: 웹셸 패턴 + 자식 프로세스 패턴 상관분석

    XDR ->> Forensic: 웹 루트·업로드 폴더 포렌식 수집 요청
    Forensic ->> WebSrv: 신규/수정 스크립트 파일 목록·해시·일부 내용 조회
    WebSrv -->> Forensic: 수집 결과 전달
    Forensic -->> XDR: 웹셸 후보 파일 정보 보고

    XDR ->> AI: 웹 로그 + 프로세스 트리 + 파일 내용 요약 전달
    AI ->> AI: 웹셸 업로드·실행 여부 및 단계별 시나리오 분석
    AI -->> XDR: 공격 확정/의심 판정 + 상세 근거·타임라인

    XDR ->> DB: 판정 결과 + 웹 로그 + 파일 메타데이터 저장
    XDR -->> XDR: 인시던트 생성, 차단 규칙/WAF 가상 패치 제안
```mermaid

```
