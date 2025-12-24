## rev1에서 문제였던 핵심 포인트(중요)

### 1) 드라이버 `PathName`이 Windows에서는 종종 “실제 파일 경로 형태가 아님”

`Win32_SystemDriver.PathName`은 흔히 이런 형태가 나옵니다.

* `\SystemRoot\System32\drivers\xxx.sys`
* `system32\drivers\xxx.sys`
* `\??\C:\Windows\System32\drivers\xxx.sys`

rev1은 이걸 제대로 `C:\Windows\...`로 변환하지 못해서 `Test-Path`가 실패하고, **정상 드라이버도 “Missing”으로 대량 탐지될 수 있습니다.**

➡️ rev2에서는 `Resolve-WindowsPath()`로 위 패턴들을 **정상 파일 경로로 변환**합니다.

---

### 2) 서비스/작업/WM I의 실행 경로도 환경변수/따옴표/인자 때문에 깨질 수 있음

예: `%SystemRoot%\System32\svchost.exe -k ...`
rev1은 “파일 경로만 정확히 뽑는” 처리가 약해서 `Test-Path`가 실패할 수 있었고, 그럼 오탐이 증가합니다.

➡️ rev2에서는 `Extract-ExePath()` + `ExpandEnvironmentVariables()`를 적용했습니다.

---

### 3) WMI 이벤트 구독은 “무조건 의심”으로 잡으면 오탐 가능

rev1은 WMI가 있으면 거의 다 잡히는 조건이었는데, 운영 환경에 따라 합법 WMI도 존재합니다.

➡️ rev2에서는 WMI의 경우 아래 조건 중 하나일 때만 의심 처리합니다.

* 실행파일 **Missing**
* 실행파일이 **사용자 쓰기 가능 경로**
* 실행파일이 **비시스템/비프로그램 경로(NonSystemPath)**

---

## rev2가 유지하는 PLURA-Forensic 철학

* ✅ **로그 파일 생성 없음**
* ✅ **탐지 없으면 무출력(quiet)**
* ✅ **탐지되면 3가지 Alert만 출력**

  * `[Alert] Hidden Entry Found!`
  * `[Alert] Suspicious Rootkit Found!`
  * `[Alert] Backdoor Found!`

---

## 출력 포맷도 Linux와 최대한 맞춤

각 탐지 항목은 항상

* `[!] FilePath: ...`
* `Modified/Created/MD5/SHA256`

형태로 나가도록 고정했습니다.

---

## Exit code 정책

* 0: 아무것도 없음
* 10: Hidden Entry Found
* 20: Suspicious Rootkit Found
* 30: Backdoor Found
* 40: 2개 이상 동시 발견(상관분석 관점)

---

## 실행 방법

관리자 PowerShell에서:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\rootkit_detect_scanner_windows_v1.0-rev2.ps1
```

(원할 때만)

```powershell
.\rootkit_detect_scanner_windows_v1.0-rev2.ps1 -ShowSystemInfo
```

---

## 다음 확인 포인트

Windows 환경에서 한번 실행해 보신 뒤, 만약

* `Hidden Entry Found`가 과다(업무용 정상이 많이 잡힘)
* `Suspicious Rootkit Found`가 너무 많음(드라이버가 많이 잡힘)

같은 현상이 있으면, 그건 “코드 오류”라기보다 **탐지 정책(휴리스틱) 튜닝** 문제일 가능성이 큽니다.
그 경우 PLURA 기준으로 **허용(allowlist) / 제외(exclude) 경로**를 아주 얇게 넣어 오탐을 정리하는 게 가장 깔끔합니다.

원하시면, 실제 한 번 실행한 출력(특히 Rootkit Found에 잡힌 드라이버 몇 개)만 주시면 **오탐 줄이는 규칙을 PLURA 철학에 맞게(출력 최소 유지)** 바로 튜닝해드릴게요.
