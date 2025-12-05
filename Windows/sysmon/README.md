## 📘 Sysmon 설치 및 운영 가이드 (PLURA-XDR 전용)

본 문서는 **PLURA-XDR** 환경에서 Desktop(워크스테이션)과 Server(서버) 시스템에
Sysmon을 설치하고 설정을 관리하기 위한 가이드입니다.

Sysmon 실행 파일: **Sysmon64.exe**
권장 버전: **v15.15 이상**

---

## 🏷️ d- / s- 파일 구분

| Prefix | 의미                | 대상 OS                             |
| ------ | ----------------- | --------------------------------- |
| **d-** | Desktop 전용 Config | Windows 10 / 11 등 클라이언트           |
| **s-** | Server 전용 Config  | Windows Server 2016 / 2019 / 2022 |

Desktop과 Server의 동작 특성이 다르기 때문에, PLURA에서는
각 환경에 최적화된 Sysmon 규칙 세트를 분리하여 제공합니다.

---

## 🔧 1. Sysmon 설치 (Install)

모든 명령은 **관리자 권한 PowerShell 또는 CMD**에서 실행해야 합니다.

### ✔ PLURA Sysmon 설정 파일별 설치 명령

---

### **1) Desktop — d-sysmon-27-plura.xml 설치**

```powershell
Sysmon64.exe -i .\d-sysmon-27-plura.xml -accepteula
```

---

### **2) Server — s-sysmon-27-plura.xml 설치**

```powershell
Sysmon64.exe -i .\s-sysmon-27-plura.xml -accepteula
```

---

### **3) Server — s-sysmon-plura-v2.1.xml 설치**

```powershell
Sysmon64.exe -i .\s-sysmon-plura-v2.1.xml -accepteula
```

---

### **4) Desktop — d-sysmon-plura-v2.1.xml 설치**

```powershell
Sysmon64.exe -i .\d-sysmon-plura-v2.1.xml -accepteula
```

---

## 🔁 2. 설정 업데이트 (Change Config)

Sysmon이 이미 설치된 환경에서 **룰만 최신 파일로 교체**할 때 사용합니다.

```powershell
Sysmon64.exe -c .\변경할-설정파일.xml
```

예시:

```powershell
Sysmon64.exe -c .\d-sysmon-plura-v2.1.xml
```

* **서비스 재시작 없이 즉시 반영됨**
* 기존 설치(`-i`)가 되어 있어야 사용 가능

---

## ❌ 3. Sysmon 제거 (Uninstall)

Sysmon 서비스 및 드라이버 제거:

```powershell
Sysmon64.exe -u
```

강제로 완전 제거(드라이버/로그 포함):

```powershell
Sysmon64.exe -u force
```

---

## 🧪 4. 설치 상태 확인

```powershell
sc query Sysmon64
```

또는 PowerShell:

```powershell
Get-Service Sysmon64
```

---

## 📍 5. Sysmon 로그 위치

**이벤트 뷰어 →**
`Applications and Services Logs` →
`Microsoft` →
`Windows` →
`Sysmon` →
`Operational`

---

## 📄 6. 참고 사항

* `schemaversion` 은 Sysmon 버전과 반드시 호환되어야 합니다.
* Desktop(d-)과 Server(s-) 설정 파일을 혼용하면
  **불필요한 로그 증가 또는 누락이 발생할 수 있으므로 반드시 구분해서 사용**하세요.
* PLURA-XDR은 Sysmon 로그 기반 탐지 기능을 강화하고 있으므로
  가급적 **v2.1 정책(최신)** 사용을 권장합니다.

---
