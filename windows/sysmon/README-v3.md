# PLURA-Forensic – Sysmon Desktop / Server Configuration (v3.1)

본 저장소는 **PLURA-Forensic** 관점에서 설계된  
Sysmon Desktop(d-) / Server(s-) 설정 파일을 포함합니다.

랜섬웨어, LOLBAS, Living-off-the-Land 공격 등
**실제 침해 사고 대응을 염두에 둔 탐지·차단 중심 설계**를 목표로 합니다.

---

## 📁 파일 구성 개요

### Desktop (d- prefix)

- `d-sysmon-27-plura-v3.1.xml`
- `d-sysmon-29-plura-v3.1.xml`
- `d-sysmon-plura-v3.1-merge-27.xml`
- `d-sysmon-plura-v3.1-merge-29.xml`
- `d-sysmon-plura-v3.1-desktop.xml`

### Server (s- prefix)

- `s-sysmon-27-plura-v3.1.xml`
- `s-sysmon-29-plura-v3.1.xml`
- `s-sysmon-plura-v3.1-merge-27.xml`
- `s-sysmon-plura-v3.1-merge-29.xml`
- `s-sysmon-plura-v3.1.xml`

---

## 🔍 Sysmon Event ID 27 vs 29 – 차이점 정리

### ✅ Sysmon Event ID 27  
**(File Blocked / 차단 중심 정책)**

| 항목 | 설명 |
|----|----|
| 목적 | **의심 파일 실행 차단 + 로그 기록** |
| 성격 | **능동적 방어 (Preventive Control)** |
| 영향 | 실제 실행이 차단되므로 운영 영향 가능 |
| 주요 활용 | 랜섬웨어, 드로퍼, LOLBAS 초기 실행 차단 |

**주의사항**
- 정상 업무 파일이 차단될 수 있으므로  
  ▶ 예외(AllowList) 관리가 반드시 필요
- 운영 환경에서는 **사전 테스트 및 단계적 적용 권장**

---

### ✅ Sysmon Event ID 29  
**(File Executable Detected / 탐지 전용 정책)**

| 항목 | 설명 |
|----|----|
| 목적 | **새 실행 파일 생성 탐지** |
| 성격 | **수동적 탐지 (Detective Control)** |
| 영향 | 시스템 동작에 영향 없음 |
| 주요 활용 | 침해 지표 수집, 포렌식, 상관 분석 |

**특징**
- 운영 안정성이 높아 **모든 환경에 무조건 적용 가능**
- 차단은 하지 않으므로 **즉각적 공격 저지는 불가**

---

## 🛡️ 랜섬웨어 대응 관점에서의 권고 정책

### 🔴 핵심 결론

> **실질적인 랜섬웨어 대응을 준비하려면  
> Sysmon Event ID 27 기반 차단 정책 운영을 권고합니다.**

### 이유

- 랜섬웨어는 **“실행 순간”을 놓치면 피해가 확산**
- Event ID 29는 **사후 탐지·분석에는 유효**하나,
  실행 자체를 막을 수는 없음
- Event ID 27은 **실행 단계에서 공격을 차단**할 수 있는
  거의 유일한 Sysmon 레벨의 통제 수단

---

## ⚖️ 운영 전략 권장 시나리오

### 1️⃣ 보수적 운영 환경
- **Event ID 29 단독 사용**
- 탐지 + 포렌식 중심
- 차단 부담이 없는 환경

### 2️⃣ 보안 우선 환경 (권장)
- **Event ID 27 + 29 병행**
- 29로 전체 가시성 확보
- 27로 고위험 실행 파일 차단

### 3️⃣ 성숙한 보안 운영 환경
- Event ID 27 적극 활용
- 화이트리스트 기반 예외 관리
- PLURA-XDR / SIEM 연동 자동 대응

---

## 📌 정리

- **29번**: 안정적인 **탐지·가시성 확보용**
- **27번**: 실제 공격을 멈추는 **차단용 핵심 정책**
- 랜섬웨어 대응을 “탐지”가 아닌 “저지” 관점에서 본다면  
  ▶ **27번 차단 정책 운영은 선택이 아닌 필수**

---

© PLURA-Forensic / PLURA-XDR  
Everything is visible. Everything is protected.
