## 📘 Sysmon 설치 및 운영 가이드 (PLURA-XDR 전용)

본 문서는 **PLURA-XDR** 환경에서 Desktop(워크스테이션)과 Server(서버) 시스템에  
Sysmon을 설치하고 설정을 관리하기 위한 가이드입니다.

Sysmon 실행 파일: **Sysmon64.exe**
권장 버전: **v15.15 이상**

---

## 🔽 Sysmon 다운로드

공식 Microsoft Sysinternals(Sysmon) 다운로드 페이지:

👉 **[https://learn.microsoft.com/ko-kr/sysinternals/downloads/sysmon](https://learn.microsoft.com/ko-kr/sysinternals/downloads/sysmon)**

위 링크에서 최신 버전의 Sysmon을 다운로드한 뒤, 압축을 해제하고  
`Sysmon64.exe` 파일을 사용해 아래 명령들을 실행하십시오.

---

## 🏷️ d- / s- 파일 구분

| Prefix | 의미                | 대상 OS                             |
| ------ | ----------------- | --------------------------------- |
| **d-** | Desktop 전용 Config | Windows 10 / Windows 11           |
| **s-** | Server 전용 Config  | Windows Server 2016 / 2019 / 2022 |

Desktop과 Server의 로그 특성, 성능, 서비스 구성 차이 때문에  
PLURA에서는 운영환경에 최적화된 별도 Sysmon 룰셋을 제공합니다.

---

## 🔧 1. Sysmon 설치 (Install)

반드시 **관리자 권한 PowerShell 또는 CMD**에서 실행해야 합니다.

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

Sysmon이 이미 설치된 상태에서 **룰만 최신 파일로 교체**할 때 사용합니다.

```powershell
Sysmon64.exe -c .\변경할-설정파일.xml
```

예시:

```powershell
Sysmon64.exe -c .\d-sysmon-plura-v2.1.xml
```

* 서비스 재시작 없이 즉시 반영됨
* 최초 설치(`-i`)가 되어 있어야 사용 가능

---

## ❌ 3. Sysmon 제거 (Uninstall)

Sysmon 서비스 및 드라이버 제거:

```powershell
Sysmon64.exe -u
```

드라이버, 서비스, 로그까지 **강제로 완전 제거**하려면:

```powershell
Sysmon64.exe -u force
```

---

## 🧪 4. Sysmon 설치 상태 확인

```powershell
sc query Sysmon64
```

또는 PowerShell:

```powershell
Get-Service Sysmon64
```

---

## 📍 5. Sysmon 로그 위치

```
Event Viewer
 └─ Applications and Services Logs
     └─ Microsoft
         └─ Windows
             └─ Sysmon
                 └─ Operational
```

### ✔ 전체 경로 문자열

```
C:\Windows\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx
```


![Event Viewer with sysmon](img/eventviewer-sysmon.png)


---

## 📄 6. 참고 사항

* XML 설정 파일의 `schemaversion` 은 Sysmon 버전과 호환되어야 합니다.
* Desktop(d-)과 Server(s-) 설정 파일을 혼용하면
  **불필요하거나 과도한 로그가 생성되거나 중요한 이벤트가 누락될 수 있습니다.**
* PLURA-XDR에서는 **v2.1 규칙 세트(최신)** 사용을 권장합니다.
* 설치 및 제거는 **재부팅이 필요하지 않습니다.**

---
