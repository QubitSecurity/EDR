# 🛡️ PLURA SecureMode 정책 적용 안내서

이 저장소는 SecureMode 정책을 시스템에 적용하기 위한 **보안 강화 구성 자동화 스크립트**를 포함하고 있습니다.

이 저장소는 Windows Defender Application Control(WDAC)을 기반으로 PowerShell을 Constrained Language Mode(CLM)로 제한하고, 신뢰된 애플리케이션만 실행되도록 시스템을 보호합니다.

---

## 🖥️ 시스템 요구 사항

SecureMode 정책을 적용하기 위해서는 아래와 같은 사전 조건이 충족되어야 합니다:

- ✅ **UEFI 기반 부팅 방식**
- ✅ **Secure Boot 활성화**
- ✅ Windows 10 버전 1903 이상 (Enterprise 또는 Education 권장)
- ✅ 관리자 권한

> WDAC는 커널 레벨에서 신뢰된 코드만 실행되도록 제한하므로, UEFI + Secure Boot 환경이 필수입니다.  
> Legacy BIOS 또는 Secure Boot 비활성화 환경에서는 정책이 적용되지 않거나 우회될 수 있습니다.

---

## 📁 구성 파일

| 파일명 | 설명 |
|--------|------|
| `plura-policy.xml` | WDAC 정책 정의 파일 (Path/Publisher/Hash 룰 포함, LOLBin 차단 설정 포함) |
| `plura-apply-wdac.ps1` | 정책을 시스템에 적용하고 로그를 기록하는 PowerShell 자동화 스크립트 |

---

## ⚙️ 주요 기능

- `SIPolicy.p7b`로 변환된 WDAC 정책을 시스템 폴더에 자동 배치
- LOLBin (wscript.exe, regsvr32.exe, mshta.exe 등) 실행 차단
- `Program Files`, `AppData` 경로 기반 예외 허용
- 정책 적용 결과 로그 기록
- PowerShell CLM 적용 상태 확인

---

## 🚀 사용 방법

### 1. WDAC 정책 바이너리 생성

```powershell
ConvertFrom-CIPolicy -XmlFilePath .\plura-policy.xml -BinaryFilePath "C:\Program Files\Plura\plura-policy.bin"
````

### 2. 스크립트 실행 (관리자 권한 필요)

```powershell
powershell -ExecutionPolicy Bypass -File .\plura-apply-wdac.ps1
```

### 3. 시스템 재부팅

적용된 WDAC 정책은 시스템 부팅 시 로드됩니다. **반드시 재부팅이 필요합니다.**

---

## 📄 로그 파일

* 적용 결과는 아래 경로에 기록됩니다:

```plaintext
C:\Program Files\Plura\plura-wdac-log.txt
```

---

## 🔐 LOLBin 차단 목록

`plura-policy.xml`에는 다음 실행파일에 대한 차단 설정이 포함되어 있습니다:

* `wscript.exe`
* `cscript.exe`
* `mshta.exe`
* `regsvr32.exe`
* `rundll32.exe`

---

## ⚠️ 주의 사항

* 정책 적용 후, **허용되지 않은 앱은 실행이 차단**될 수 있습니다.
* 정책을 수정한 경우, `.xml → .bin`으로 다시 변환한 뒤 재배포 필요
* 반드시 관리자 권한으로 실행하십시오.

---

## 📬 문의

정책 템플릿 구성이나 예외 등록 자동화 관련 지원이 필요하시면 보안 운영 담당자 또는 PLURA-XDR 기술팀에 문의해 주세요.
