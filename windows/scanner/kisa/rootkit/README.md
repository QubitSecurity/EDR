# Rootkit Detection Scanner (Windows)  
**v1.0-rev10**

PLURA-Forensic 기준에 맞춘 **Windows 루트킷·백도어 점검 스크립트**입니다.  
로그 파일을 생성하지 않으며, **실행 결과는 표준 출력으로만 제공**됩니다.

---

## 📌 주요 특징

- ✅ **로그 파일 생성 없음**
- ✅ **탐지 여부와 무관하게 항상 결과 블록 출력**
- ✅ **노이즈 억제 정책 기본 적용**
- ✅ **탐지 시 추가 증적 자동 조회**
  - 파일 존재 여부 (`Test-Path`)
  - 접근 가능 여부 (Present / Missing / AccessDenied)
  - 서명, 해시, 버전 정보 등

---

## 🔍 점검 대상

본 스크립트는 다음 항목을 점검합니다.

1. **Hidden Entry (자동 실행 이상)**
   - Scheduled Task
   - Service
   - WMI Event Subscription

2. **Suspicious Rootkit**
   - 로드 중인 커널 드라이버(.sys)
   - 비시스템 경로, 비신뢰 서명 등 휴리스틱 기반

3. **Backdoor**
   - 리스닝 포트 + 사용자 쓰기 가능 경로 실행 파일

---

## 🚀 실행 방법

### 1) 관리자 권한 PowerShell 실행

```powershell
powershell -ExecutionPolicy Bypass -File .\rootkit_detect_scanner_windows_v1.0-rev10.ps1
````

---

## 📤 출력 형식 (항상 동일)

### ▶ 탐지된 항목이 없는 경우

```
============================================================
                        SCAN RESULT
============================================================
- File Not Found!
============================================================
                        END
============================================================
```

### ▶ 탐지된 항목이 있는 경우 (예시)

```
============================================================
                        SCAN RESULT
============================================================
[Alert] Hidden Entry Found!
[!] FilePath: C:\Users\...\Zoom.exe
 - Source: ScheduledTask
 - Reason: UserWritablePath
 - Presence: Present
 - Test-Path: True
 - Company : Zoom Communications, Inc.
 - SigStatus: Valid
 - SHA256: ...
============================================================
                        END
============================================================
```

---

## 🧪 디버그 모드 (억제된 항목 확인)

노이즈 억제 정책으로 **출력에서 제외된 항목의 사유**를 확인하려면:

```powershell
$env:PLURA_DEBUG="1"
powershell -ExecutionPolicy Bypass -File .\rootkit_detect_scanner_windows_v1.0-rev10.ps1
```

출력 예:

```
[PLURA_DEBUG] Suppress UserWritablePath trusted vendor: C:\Users\...\Zoom.exe
[PLURA_DEBUG] Suppress MS Windows task MissingBinary: \Microsoft\Windows\UpdateOrchestrator\USO_UxBroker
```

> ⚠️ 디버그 메시지는 **stderr**로 출력됩니다.

---

## 🔕 기본 노이즈 억제 정책

다음 항목은 기본적으로 **출력에서 제외**됩니다.

* ✔ **UserWritablePath 이지만**

  * 서명 Valid
  * 신뢰 벤더(예: Zoom)

* ✔ `\Microsoft\Windows\` 하위 ScheduledTask의 `MissingBinary`

  * UpdateOrchestrator 등 Windows 잔재 작업

* ✔ `C:\Program Files\WindowsApps\` 경로의 서비스

  * 패키지 버전 변경으로 인한 경로 드리프트

---

## 🧩 Exit Code

| Exit Code | 의미                    |
| --------- | --------------------- |
| `0`       | 탐지 결과 없음              |
| `10`      | Hidden Entry 발견       |
| `20`      | Suspicious Rootkit 발견 |
| `30`      | Backdoor 발견           |
| `40`      | 복수 카테고리 발견            |

---

## 🧠 운영 가이드 (PLURA 기준)

* **운영 기본**

  * DEBUG 비활성
  * 출력 결과만 수집

* **사고 분석**

  * `PLURA_DEBUG=1`로 억제 사유 포함 출력
  * 출력 전체를 그대로 GPT/분석 시스템에 입력 가능

---

## 📎 파일

* `rootkit_detect_scanner_windows_v1.0-rev10.ps1`
* `README.md` (본 문서)

---

**PLURA-Forensic Philosophy**

> “로그는 남기지 않고,
> 분석에 필요한 모든 근거는
> 한 번의 실행 결과에 담는다.”

---
