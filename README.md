# EDR
PLURA Standard Audit & Logging Configuration

## 🛠️ Sysmon

> **Why Sysmon**
>
> Sysmon is used as a **standard logging system** for PLURA.  
> It provides **consistent and detailed security logs** across **Windows and Linux**,  
> enabling unified detection, investigation, and response.
>
> Using Sysmon on both platforms is **strongly recommended** to maintain  
> a common audit baseline and cross-platform visibility.

> **Sysmon을 사용하는 이유**
>
> Sysmon은 PLURA의 **표준 로깅 시스템**으로 사용됩니다.  
> Windows와 Linux 환경에서 **동일한 보안 이벤트 기준과 로그 구조**를 제공하여  
> 통합 탐지·분석·대응을 가능하게 합니다.
>
> 따라서 **운영 환경에서는 Windows와 Linux 모두에 Sysmon 사용을 권장**합니다.

  * 🪟 [Windows](https://github.com/QubitSecurity/EDR/tree/main/Windows/sysmon/)
  * 🔴 [RHEL](https://github.com/QubitSecurity/EDR/tree/main/RHEL/sysmon/)
  * 🟠 [Ubuntu](https://github.com/QubitSecurity/EDR/tree/main/Ubuntu/sysmon/)

---

## 🔗 Useful Links

### 리눅스에서도 Sysmon을 사용해야 하는 이유

- https://blog.plura.io/ko/respond/linux_sysmon/

### Windows Subcategory and SubcategoryGUID

- https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d

### Windows Security Log Events

- https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx
