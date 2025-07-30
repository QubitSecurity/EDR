# 🛡️ PLURA SecureMode 정책 적용

이 저장소는 SecureMode 정책을 시스템에 적용하기 위한 **보안 강화 구성 자동화 스크립트**를 포함하고 있습니다.

Windows Defender Application Control(WDAC)을 기반으로 PowerShell을 Constrained Language Mode(CLM)로 제한하고, 신뢰된 애플리케이션만 실행되도록 시스템을 보호합니다.

---

## 🖥️ 시스템 요구 사항

SecureMode 적용을 위해서는 다음 환경이 사전에 필요합니다:

- ✅ **UEFI 기반 부팅 방식**
- ✅ **Secure Boot 활성화**
- ✅ Windows 10 1903 이상 (Enterprise 또는 Education 권장)
- ✅ 관리자 권한

> WDAC는 서명된 스크립트 실행을 제한하는 보안 구조이며, Secure Boot 환경이 반드시 필요합니다.

---

## 📁 구성 파일

| 파일명 | 설명 |
|--------|------|
| `plura-policy.xml` | WDAC 정책 정의 파일 (Publisher/Path 룰 포함, LOLBin 차단 포함) |
| `plura-apply-wdac.ps1` | 정책을 시스템에 적용하고 로그를 기록하는 PowerShell 자동화 스크립트 |
| `plura-wdac-automation.ps1` | 정책 생성, 병합, 적용까지 자동 수행하는 통합 스크립트 (선택사항) |

---

## ⚙️ 주요 기능

- Publisher 기반 WDAC 정책 생성 및 적용
- LOLBin(wscript.exe, regsvr32.exe 등) 실행 차단
- `Program Files`, `AppData` 경로 기반 예외 허용
- CLM(제한 언어 모드) 자동 적용
- 정책 자동 병합 및 배포 스크립트 제공
- 적용 결과 로그 기록

---

## 🚀 사용 방법

### 1. Publisher 기반 정책 생성

```powershell
New-CIPolicy -Level Publisher -Fallback Hash -UserPEs -FilePath .\plura-policy.xml
Set-RuleOption -FilePath .\plura-policy.xml -Option 0  # Enforce
Set-RuleOption -FilePath .\plura-policy.xml -Option 3  # UMCI 적용
```

### 2. Supplemental 정책 병합 (필요한 경우)

```powershell
$xmls = @(
    ".\plura-policy.xml",
    ".\supplemental-policy.xml"
)
Merge-CIPolicy -PolicyPaths $xmls -OutputFilePath .\merged-policy.xml
```

### 3. 정책 변환 및 배포

```powershell
ConvertFrom-CIPolicy -XmlFilePath .\merged-policy.xml -BinaryFilePath .\SIPolicy.p7b
Copy-Item .\SIPolicy.p7b -Destination "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b" -Force
```

### 4. 통합 스크립트 (plura-wdac-automation.ps1 사용 시)

```powershell
powershell -ExecutionPolicy Bypass -File .\plura-wdac-automation.ps1
```

> 정책 적용 후 반드시 시스템을 **재부팅**해야 합니다.

---

## 📄 로그 파일 경로

```plaintext
C:\Program Files\Plura\plura-wdac-log.txt
```

---

## 🔐 LOLBin 차단 목록

WDAC 정책에는 다음 실행 파일 차단이 포함되어 있습니다:

* `wscript.exe`
* `cscript.exe`
* `mshta.exe`
* `regsvr32.exe`
* `rundll32.exe`

---

## 🔄 정책 유지보수 팁

| 전략 | 설명 |
|--------|------|
| ✅ **Publisher 기반 허용** | 서명된 앱은 업데이트되어도 계속 허용됨 |
| ✅ **Path 기반 예외 허용** | AppData, Program Files 내 경로 기반 허용 유지 |
| ⚠️ **Hash 기반만 사용할 경우** | 앱이 업데이트되면 정책 재생성 필요함 |

> 따라서 가능하면 Publisher + Path 기반 정책을 구성하고, Hash는 Fallback 용도로만 사용하는 것을 권장합니다.

---

## ⚠️ 주의 사항

- 정책 적용 후, 허용되지 않은 앱은 실행이 차단됩니다.
- 정책 수정 후 `.bin`으로 재변환하여 재배포해야 적용됩니다.
- 반드시 관리자 권한으로 실행해야 하며, UEFI + Secure Boot 환경이 필요합니다.

---

## 📬 문의

정책 템플릿 구성이나 자동화 관련 문의는 PLURA-XDR 기술팀으로 연락해 주세요.
