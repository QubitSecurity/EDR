# 🛡️ PLURA SecureMode 정책 적용

이 저장소는 SecureMode 정책을 시스템에 적용하기 위한 **보안 강화 구성 자동화 스크립트**를 포함하고 있습니다.

이 저장소는 Windows Defender Application Control(WDAC)을 기반으로 PowerShell을 Constrained Language Mode(CLM)로 제한하고, 신뢰된 애플리케이션만 실행되도록 시스템을 보호합니다.

---

## 🖥️ 시스템 요구 사항

SecureMode 적용을 위해서는 다음 환경이 사전에 필요합니다:

- ✅ **UEFI 기반 부팅 방식**
- ✅ **Secure Boot 활성화**
- ✅ **Windows 10 1903 이상**
  - Pro, Enterprise, Education 에디션 지원
- ✅ **Windows Server 2019 이상**
  - Standard, Datacenter 에디션에서 동작 확인됨
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

## 📘 HSS_Helper 예외처리 가이드 (PyInstaller 기반 프로그램)

HSS_Helper.exe는 PyInstaller로 빌드된 실행파일입니다. 기본적으로 `--onefile` 모드로 패키징된 경우 실행 시 `Temp` 폴더에 압축 해제되어 실행되며, 이는 WDAC에서 차단됩니다.

이를 해결하기 위해 `--onedir` 모드로 패키징하고, 고정된 설치 경로에서 실행되도록 해야 합니다.

### ✅ 1. PyInstaller 설치 및 onedir 모드 빌드

```bash
pip install pyinstaller
pyinstaller --onedir --noconsole --name HSS_Helper main.py
```

- `dist/HSS_Helper/` 폴더가 생성되며, 그 안에 `HSS_Helper.exe`와 필요한 파일이 포함됨
- 전체 폴더를 `C:\Program Files\HSS_Helper\`와 같은 고정된 위치에 복사

### ✅ 2. WDAC 정책에 실행 경로 예외 추가

```xml
<FilePathRules>
  <FilePathRule Id="Allow_HSSHelper" Action="Allow" Path="C:\Program Files\HSS_Helper\*" />
</FilePathRules>
```

이제 해당 경로에 있는 실행 파일들은 WDAC 정책에 의해 신뢰되어 차단되지 않음

---

## 🔄 정책 유지보수 팁

WDAC 정책을 Hash 기반으로 생성하면 앱 업데이트 시 정책이 무력화될 수 있습니다. 아래 방식으로 해결 가능합니다:

| 방법 | 설명 |
|------|------|
| ✅ **Publisher 기반 허용** | 서명된 앱은 업데이트 되어도 실행 허용 유지됨 |
| ✅ **Path 기반 예외 병행** | AppData, Program Files 경로 기반 예외 허용 가능 |
| 🔁 `-Fallback Hash` 사용 | 서명 없는 앱만 해시 기반으로 처리 |

> 따라서 가능하면 Publisher + Path 기반 정책을 구성하고, Hash는 Fallback 용도로만 사용하는 것을 권장합니다.

---

## ⚠️ 주의 사항

* 정책 적용 후, 허용되지 않은 앱은 차단됩니다.
* 정책 수정 시 `.xml → .bin` 재변환 필요
* 관리자 권한으로 실행해야 하며, 반드시 **UEFI + Secure Boot** 환경에서만 유효합니다.

---

## 📬 문의

정책 템플릿 구성이나 자동화 관련 문의는 PLURA-XDR 기술팀으로 연락 주시기 바랍니다.
