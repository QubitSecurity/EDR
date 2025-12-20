아래는 **특정 프로세스를 지정하지 않고도**
**Windows 프로세스 인젝션(Process Injection) 공격을 “로그 중심”으로 탐지**하는 실전 방법을
**고급 감사 정책 → Sysmon → 기타 보조 수단** 순서로 정리한 것입니다.

---

![Image](https://www.safebreach.com/wp-content/uploads/2023/12/image16-2-1024x489.webp)

![Image](https://images.contentstack.io/v3/assets/bltefdd0b53724fa2ce/blt414e818295fc42dc/5e2f925ce147ae4537d92acb/process-injection-techniques-blogs-iat-ex.png)

![Image](https://www.oreilly.com/api/v2/epubs/urn%3Aorm%3Abook%3A9781788392501/files/assets/19eb9b3e-9923-4e6f-9bef-b9b9dbfdc700.png)

## 🎯 기본 전제

* ❌ 특정 프로세스(예: explorer.exe, lsass.exe)를 **화이트/블랙리스트로 지정하지 않음**
* ✅ **행위(Behavior) 기반**으로 탐지
* ✅ **차단이 아니라 로그 수집 & 포렌식 중심**
* ✅ MITRE ATT&CK **T1055 (Process Injection)** 대응

---

# 1️⃣ Windows 고급 감사 정책 (Advanced Audit Policy)

> **OS 기본 기능만으로 가능한 1차 가시성 확보**

### 🔧 반드시 활성화할 감사 항목

```text
Computer Configuration
 └─ Windows Settings
    └─ Security Settings
       └─ Advanced Audit Policy Configuration
```

### ✅ 권장 설정

| 감사 범주             | 세부 항목                                     | 이유                  |
| ----------------- | ----------------------------------------- | ------------------- |
| Process Tracking  | **Audit Process Creation (4688)**         | 인젝션 전·후 프로세스 체인 추적  |
| Process Tracking  | **Audit Process Termination (4689)**      | 인젝션 후 프로세스 종료 패턴    |
| Object Access     | **Audit Handle Manipulation (4656/4663)** | 타 프로세스 메모리 접근       |
| Object Access     | **Audit Kernel Object**                   | Process Handle Open |
| Detailed Tracking | **Audit RPC Events**                      | 원격/비정상 호출 흔적        |
| Policy Change     | Audit Policy Change                       | 감사 회피 시도 탐지         |

📌 **핵심 포인트**
→ *“누가 어떤 프로세스 핸들을 열었는가”* 를 남김
→ 단독으로는 한계가 있으므로 **Sysmon과 반드시 결합**

---

# 2️⃣ Sysmon 기반 프로세스 인젝션 탐지 (핵심)

> **가장 현실적이고 강력한 로그 수집 수단**

## 🔥 필수 Sysmon Event ID

### 🧠 Event ID 10 — **ProcessAccess (핵심)**

```text
Event ID: 10
Source: Microsoft-Windows-Sysmon
```

**의미**

> 한 프로세스가 **다른 프로세스의 메모리에 접근**

### 📌 인젝션과 직접 연관된 AccessMask

| AccessMask | 의미                      |
| ---------- | ----------------------- |
| `0x1F0FFF` | Full Access             |
| `0x143A`   | VM_WRITE + VM_OPERATION |
| `0x1410`   | VM_READ                 |
| `0x0010`   | PROCESS_VM_READ         |
| `0x0020`   | PROCESS_VM_WRITE        |

➡️ **정상 프로그램도 발생 가능**
➡️ 그래서 **“행위 조합”으로 판단**

---

## 🔗 함께 보는 Sysmon 이벤트 (상관 분석)

| Event ID | 의미                          |
| -------- | --------------------------- |
| **1**    | Process Create              |
| **7**    | Image Load (Reflective DLL) |
| **8**    | CreateRemoteThread          |
| **10**   | ProcessAccess               |
| **11**   | FileCreate (드롭퍼)            |
| **25**   | Process Tampering (최신 버전)   |

---

## 🧩 인젝션 시그니처 없는 탐지 로직 (중요)

> ❌ 특정 프로세스 이름 기반 탐지 ❌
> ✅ **행위 체인 기반 탐지**

### 🔍 탐지 조건 예시 (개념)

```text
[조건 1]
Process A → ProcessAccess (Event 10)
AccessMask ∈ {VM_WRITE, VM_OPERATION}

[조건 2]
동일 PID/시간대
→ CreateRemoteThread (Event 8)
OR
→ ImageLoad (비정상 경로 DLL)

[조건 3]
부모-자식 관계 비정상
```

📌 **이 방식은**

* explorer.exe
* svchost.exe
* lsass.exe
  **어떤 프로세스든 자동 적용**

---

# 3️⃣ PowerShell & Script 기반 인젝션 탐지

## 🧪 ScriptBlockLogging (Event ID 4104)

```powershell
Set-ProcessMitigation -System -Enable ScriptBlockLogging
```

### 📌 탐지 대상

* `Add-Type`
* `VirtualAlloc`
* `WriteProcessMemory`
* `CreateRemoteThread`
* `NtCreateThreadEx`

➡️ **파일 없는 인젝션(Fileless)** 탐지에 매우 중요

---

# 4️⃣ 메모리·행위 기반 보조 로그

## 🧬 Windows Defender (차단 없이 로그)

* **Attack Surface Reduction (ASR)**
  → Audit Mode 권장

```text
Block credential stealing from LSASS (Audit)
Block process injection (Audit)
```

➡️ Defender 이벤트 로그만 활용 (차단 ❌)

---

## 🧠 ETW (고급)

| Provider                              | 용도        |
| ------------------------------------- | --------- |
| Microsoft-Windows-Threat-Intelligence | 메모리 공격    |
| Microsoft-Windows-Kernel-Process      | Thread 생성 |
| Microsoft-Windows-Kernel-Memory       | RWX 메모리   |

📌 대규모 환경에서는 **Sysmon + ETW 일부 연계** 추천

---

# 5️⃣ “프로세스 지정 없이” 탐지하기 위한 핵심 원칙

## ✅ 반드시 지켜야 할 5가지

1. **프로세스 이름 기준 탐지 ❌**
2. **AccessMask + Thread + ImageLoad 조합**
3. **시간 상관 분석 (±5초)**
4. **부모-자식 관계 이상 탐지**
5. **정상 관리자 도구도 로그는 남김**

---

# 6️⃣ 추천 최소 로그 세트 (운영 현실 기준)

| 구분                    | 필수 여부 |
| --------------------- | ----- |
| 고급 감사 정책              | ✅     |
| Sysmon Event 1/7/8/10 | ✅     |
| PowerShell 4104       | ✅     |
| Defender ASR (Audit)  | ◯     |
| ETW                   | 선택    |

---

## 🧩 요약 한 문장

> **프로세스 인젝션은 “누가 누구의 메모리에, 어떤 권한으로, 어떤 스레드를 만들었는가”를 로그로 남기면 특정 프로세스를 지정하지 않아도 충분히 탐지할 수 있습니다.**

---

원하시면 다음도 바로 정리해 드릴 수 있습니다:

* 📄 **Sysmon XML (curated / strict)** – 인젝션 전용 최적화
* 🔗 **EventID 10 중심 상관 규칙 (SIEM/XDR)**
* 🧠 **MITRE ATT&CK 매핑 테이블**
* 🔍 **실제 공격 시나리오 기반 로그 예시**

어디까지 필요하신지 말씀 주세요.
