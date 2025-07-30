# 🛡️ PLURA SecureMode 정책 적용

이 저장소는 SecureMode 정책을 시스템에 적용하기 위한 **보안 강화 구성 자동화 스크립트**를 포함하고 있습니다.

이 저장소는 Windows Defender Application Control(WDAC)을 기반으로 PowerShell을 Constrained Language Mode(CLM)로 제한하고, 신뢰된 애플리케이션만 실행되도록 시스템을 보호합니다.

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

---

## ⚙️ 주요 기능

- Publisher 기반 WDAC 정책 적용
- LOLBin(wscript.exe, regsvr32.exe 등) 실행 차단
- `Program Files`, `AppData` 경로 기반 예외 허용
- CLM(제한 언어 모드) 자동 적용
- 적용 결과 로그 기록

---

## 🚀 사용 방법

### 1. WDAC 정책 생성 (Publisher 기반 권장)

```powershell
New-CIPolicy -FilePath .\plura-policy.xml -Level Publisher -UserPEs -Fallback Hash
ConvertFrom-CIPolicy -XmlFilePath .\plura-policy.xml -BinaryFilePath "C:\Program Files\Plura\plura-policy.bin"
```

### 2. 정책 적용 스크립트 실행

```powershell
powershell -ExecutionPolicy Bypass -File .\plura-apply-wdac.ps1
```

### 3. 시스템 재부팅

정책은 시스템 부팅 시 적용됩니다. **반드시 재부팅이 필요합니다.**

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

WDAC 정책을 Hash 기반으로 생성하면 앱 업데이트 시 정책이 무력화될 수 있습니다. 아래 방식으로 해결 가능합니다:

| 방법 | 설명 |
|------|------|
| ✅ **Publisher 기반 허용** | 서명된 앱은 업데이트 되어도 실행 허용 유지됨 |
| ✅ **Path 기반 예외 병행** | AppData, Program Files 경로 기반 예외 허용 가능 |
| 🔁 `-Fallback Hash` 사용 | 서명 없는 앱만 해시 기반으로 처리 |

---

## ⚠️ 주의 사항

* 정책 적용 후, 허용되지 않은 앱은 차단됩니다.
* 정책 수정 시 `.xml → .bin` 재변환 필요
* 관리자 권한으로 실행해야 하며, 반드시 **UEFI + Secure Boot** 환경에서만 유효합니다.

---

## 📬 문의

정책 템플릿 구성이나 자동화 관련 문의는 PLURA-XDR 기술팀으로 연락 주시기 바랍니다.
