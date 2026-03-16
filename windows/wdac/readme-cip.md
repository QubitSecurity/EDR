다음은 **GitHub에 바로 올릴 수 있는 최종 README.md (HowTo 문서)**입니다.
PLURA-XDR Secure OS / WDAC 정책 관리 문서 스타일에 맞게 정리했습니다.

---

# PLURA WDAC LOLBAS Deny Policy Generator

## Overview

이 프로젝트는 **LOLBAS(Living Off The Land Binaries and Scripts)** 목록 전체를 기반으로
각 항목을 **개별 WDAC(App Control for Business) 차단 정책**으로 생성하는 도구입니다.

각 LOLBAS 항목에 대해 다음 파일을 자동 생성합니다.

```
PLURA_WDAC_LOLBAS_DENY_<ToolName>.xml
{PolicyId}.cip
manifest.json
```

예:

```
PLURA_WDAC_LOLBAS_DENY_AddinUtil.xml
{GUID}.cip
manifest.json
```

이 방식은 다음과 같은 목적을 위해 설계되었습니다.

* 공격자가 LOLBAS 도구를 악용하는 것을 **WDAC 정책으로 차단**
* LOLBAS 항목별 **개별 정책 관리**
* 필요 시 특정 정책만 **선택적으로 배포**
* PLURA-XDR Secure OS 관리 기능과 연동

---

# Architecture

생성되는 디렉토리 구조

```
repo.plura.io
└─ wdac
   ├─ PLURA_WDAC_LOLBAS_DENY_AddinUtil
   │  ├─ PLURA_WDAC_LOLBAS_DENY_AddinUtil.xml
   │  ├─ {PolicyId}.cip
   │  └─ manifest.json
   │
   ├─ PLURA_WDAC_LOLBAS_DENY_AppInstaller
   │  ├─ PLURA_WDAC_LOLBAS_DENY_AppInstaller.xml
   │  ├─ {PolicyId}.cip
   │  └─ manifest.json
   │
   └─ ...
```

각 정책은 **독립 WDAC 정책**으로 관리됩니다.

---

# manifest.json Format

각 정책 폴더에는 다음 형태의 `manifest.json`이 포함됩니다.

```json
{
  "PolicyId": "{9F4DB2E7-7C25-4F8B-A2B7-9102A8C9D531}",
  "FriendlyName": "PLURA_WDAC_LOLBAS_DENY",
  "BinaryFileName": "{9F4DB2E7-7C25-4F8B-A2B7-9102A8C9D531}.cip",
  "Targets": [
    "mshta.exe",
    "wscript.exe",
    "cscript.exe"
  ]
}
```

필드 설명

| Field          | Description           |
| -------------- | --------------------- |
| PolicyId       | WDAC Policy GUID      |
| FriendlyName   | 정책 이름                 |
| BinaryFileName | WDAC binary policy 파일 |
| Targets        | 차단 대상 executable      |

---

# LOLBAS Source

정책 생성 시 다음 공식 데이터 소스를 사용합니다.

```
https://lolbas-project.github.io/api/lolbas.json
```

이 API에는 현재 모든 LOLBAS 항목이 포함되어 있습니다.

예:

```
AddinUtil.exe
AppInstaller.exe
Bitsadmin.exe
Certutil.exe
Mshta.exe
Regsvr32.exe
Rundll32.exe
...
```

---

# WDAC Policy Strategy

정책 생성 방식

```
AllowAll.xml
        │
        └─ Deny rule 추가
                │
                └─ ConvertFrom-CIPolicy
                         │
                         └─ .cip 생성
```

Microsoft 권장 방식:

* **AllowAll 기반 정책**
* Deny rule 추가
* Multiple policy deployment

---

# Requirements

지원 OS

```
Windows 10
Windows 11
Windows Server 2019+
Windows Server 2022+
```

필수 구성 요소

```
WDAC (App Control for Business)
PowerShell 5.1
CodeIntegrity module
```

관리자 권한 PowerShell 필요

---

# Installation

Repository 다운로드

```
git clone https://github.com/plura-security/plura-wdac-lolbas
```

또는

```
Download ZIP
```

---

# Usage

## 1 실행 정책 우회

```
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

또는

```
powershell.exe -ExecutionPolicy Bypass
```

---

## 2 정책 생성

```
.\New-PluraLolbasWdacPolicies.ps1 `
  -OutputPath "C:\repo\wdac" `
  -CleanOutput
```

결과

```
229 policies generated
```

---

## 3 일부 LOLBAS만 생성

```
.\New-PluraLolbasWdacPolicies.ps1 `
  -OutputPath "C:\repo\wdac" `
  -IncludeName AddinUtil,AppInstaller
```

---

# Output Example

```
[INFO] Downloading LOLBAS data
[1/229] AddinUtil.exe
[2/229] AppInstaller.exe
[3/229] Aspnet_Compiler.exe
...
Done. success=229
```

---

# WDAC Deployment

생성된 `.cip` 정책을 배포하려면

```
CiTool.exe --update-policy policy.cip
```

또는

```
Copy policy to

EFI\Microsoft\Boot\CiPolicies\Active
```

---

# Audit Mode (Recommended)

운영 환경 적용 전 **Audit Mode** 테스트 권장

```
.\New-PluraLolbasWdacPolicies.ps1 `
  -OutputPath "C:\repo\wdac" `
  -AuditMode
```

Audit Mode에서는 차단 대신 로그만 기록됩니다.

---

# Security Benefit

LOLBAS 공격 차단 예

| Tool          | Attack           |
| ------------- | ---------------- |
| mshta.exe     | HTA malware      |
| certutil.exe  | malware download |
| bitsadmin.exe | file download    |
| rundll32.exe  | DLL execution    |
| regsvr32.exe  | script execution |

WDAC 정책으로 이러한 공격을 차단할 수 있습니다.

---

# Integration with PLURA-XDR

이 정책은 다음 기능과 통합됩니다.

```
PLURA-XDR Secure OS Management
PLURA-XDR EDR Detection
PLURA-XDR Forensic Analysis
```

관리 항목

```
Secure OS Status
WDAC Policy Status
LOLBAS Execution Detection
```

---

# References

LOLBAS Project

[https://lolbas-project.github.io/](https://lolbas-project.github.io/)

Microsoft WDAC

[https://learn.microsoft.com/windows/security/application-security/application-control/](https://learn.microsoft.com/windows/security/application-security/application-control/)

MITRE ATT&CK

[https://attack.mitre.org/](https://attack.mitre.org/)

---

# License

MIT License

---

# Author

PLURA Security Team

[https://plura.io](https://plura.io)

---

원하시면 제가 다음 단계로 **GitHub용으로 더 완성도 높은 버전**도 만들어 드릴 수 있습니다.

예를 들면

* GitHub README 디자인
* Architecture diagram
* WDAC policy flow diagram
* LOLBAS 공격 예시
* Secure OS 개념 설명

이 문서는 **GitHub 스타 받을 수 있는 수준의 보안 프로젝트 README**로 업그레이드할 수 있습니다.
