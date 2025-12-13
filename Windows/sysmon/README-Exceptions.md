## 📘 Sysmon Event ID 27 예외 처리 가이드

*(Desktop / 사용자 운영용)*

본 문서는 **Sysmon Event ID 27 (FileBlockExecutable)** 이 활성화된 환경에서
**정상적인 설치 프로그램이 차단될 경우**,
사용자가 **안전하게 예외 규칙을 추가·해제하는 방법**을 안내합니다.

본 가이드는 **PLURA Desktop 정책(d-sysmon-plura-v3.0-merge27.xml)** 기준으로 작성되었습니다.

---

## 🔒 Sysmon Event ID 27이란?

Sysmon **Event ID 27 (FileBlockExecutable)** 은
다음과 같은 행위를 **차단(Block)** 하기 위해 사용됩니다.

* 사용자 쓰기 가능 경로에서 실행 파일 생성
* `Temp`, `Downloads`, `ProgramData` 등에서 실행 파일 드롭
* LOLBAS 기반 실행 파일 위장 생성
* 지속성(Persistence) 목적의 실행 파일 생성

즉, **악성코드 초기 침투를 차단하는 매우 강력한 방어 규칙**입니다.

---

## ⚠️ 왜 예외 처리가 필요한가요?

일부 정상 프로그램(예: WinSCP, Zoom, Chrome, VS Code 등)은
설치 과정에서 다음과 같은 동작을 수행합니다.

* 설치 EXE가 `AppData\Local\Temp` 아래에 파일을 풀어냄
* Inno Setup 기반 설치 프로그램이 `is-xxxx.tmp` 폴더 생성
* 임시 EXE/DLL을 생성한 뒤 실제 설치 수행

이 경우 **Sysmon ID 27이 정상 설치를 차단**할 수 있습니다.

👉 이 문서는 **보안을 약화시키지 않으면서**,
👉 **필요한 설치만 정확히 허용**하는 방법을 제공합니다.

---

# 1️⃣ 예외 규칙 추가 위치

아래 파일을 엽니다.

```
d-sysmon-27-plura.xml
(또는 d-sysmon-plura-v3.0-merge27.xml)
```

아래 RuleGroup을 찾습니다.

```xml
<RuleGroup name="Exclude_LegitActivity_Desktop" groupRelation="or">
  <FileBlockExecutable onmatch="exclude">
    ...
    <!-- (20) BITS tmp 파일 -->
    <Rule groupRelation="and">
      <Image condition="is">C:\WINDOWS\System32\svchost.exe</Image>
      <TargetFilename condition="contains">\AppData\Local\Temp\BIT\</TargetFilename>
    </Rule>

    <!-- (21) WinSCP 설치 프로그램 예외 -->  ← 여기부터 추가
    ...
  </FileBlockExecutable>
</RuleGroup>
```

👉 **반드시 `FileBlockExecutable onmatch="exclude"` 내부에 추가해야 합니다.**

---

# 2️⃣ WinSCP 설치 예외 규칙 추가 (권장 방식)

아래 내용을 **주석 위치 바로 아래에 그대로 추가**합니다.

```xml
<!-- (21) WinSCP 설치 프로그램 예외 -->
<!--
설명:
- Image: 실제 실행 주체 (설치 프로그램)
- TargetFilename: 설치 과정 중 생성되는 실행 파일 위치
- Sysmon ID 27은 "어디에서 실행 파일이 생성되었는지"를 기준으로 차단하므로
  두 조건을 함께 사용해야 안전한 예외 처리가 됩니다.
-->

<!-- 1단계: WinSCP 설치 파일이 Temp 아래로 파일을 풀어낼 때 허용 -->
<Rule groupRelation="and">
  <!-- 특정 버전의 WinSCP 설치 파일 -->
  <Image condition="end with">WinSCP-6.5.5-Setup.exe</Image>
  <!-- 설치 중 AppData\Local\Temp 경로에 파일 생성 허용 -->
  <TargetFilename condition="contains">\AppData\Local\Temp\</TargetFilename>
</Rule>

<!-- 2단계: Inno Setup 계열 설치 프로그램이 생성하는 is-xxxx.tmp 폴더 허용 -->
<Rule groupRelation="and">
  <!-- Inno Setup 기반 WinSCP 실행 파일 -->
  <Image condition="contains">WinSCP</Image>
  <!-- Inno Setup 공통 임시 폴더 -->
  <TargetFilename condition="contains">\AppData\Local\Temp\is-</TargetFilename>
</Rule>
```

---

## 🔐 보안상 중요한 주의사항 (필독)

* ✅ **설치 파일 이름을 정확히 지정 (버전 고정)**
* ❌ `Image contains WinSCP` 단독 사용 ❌
* ❌ `TargetFilename contains \Temp\` 단독 허용 ❌
* ❌ Temp 전체 실행 허용 ❌

📌 **이 예외는 WinSCP 6.5.5 전용입니다.**
버전이 변경되면 파일명이 달라지므로 **차단이 다시 발생할 수 있으며**,
그 경우 **새 버전에 맞는 예외를 추가**해야 합니다.

---

# 3️⃣ 설정 적용 방법

관리자 권한 **CMD 또는 PowerShell**에서 실행합니다.

```cmd
Sysmon64.exe -c d-sysmon-27-plura.xml
```

또는 병합본 사용 시:

```cmd
Sysmon64.exe -c d-sysmon-plura-v3.0-merge27.xml
```

### 정상 적용 기준

* 오류 메시지 없음
* Sysmon Operational 로그에 **Event ID 16 (ConfigChange)** 발생

---

# 4️⃣ 예외 해제(차단 복구) 방법

다시 차단하고 싶다면:

1. 아래 블록 전체를 **삭제 또는 주석 처리**

```xml
<!-- (21) WinSCP 설치 프로그램 예외 -->
<Rule ...>
...
</Rule>
<Rule ...>
...
</Rule>
```

2. 설정 재적용

```cmd
Sysmon64.exe -c d-sysmon-27-plura.xml
```

👉 즉시 차단 정책이 다시 활성화됩니다.

---

# 5️⃣ 다른 프로그램 예외 처리 템플릿 (사용자용)

다른 정상 프로그램도 **같은 패턴**으로 예외 처리할 수 있습니다.

### 🔁 교체 항목

* `[설치파일명].exe`
* `[프로그램이름]`

```xml
<!-- 정상 설치 프로그램 예외 템플릿 -->
<Rule groupRelation="and">
  <Image condition="end with">[설치파일명].exe</Image>
  <TargetFilename condition="contains">\AppData\Local\Temp\</TargetFilename>
</Rule>

<!-- Inno Setup / 유사 설치기 공통 예외 -->
<Rule groupRelation="and">
  <Image condition="contains">[프로그램이름]</Image>
  <TargetFilename condition="contains">\AppData\Local\Temp\is-</TargetFilename>
</Rule>
```

📌 예:

* `FileZilla-Setup.exe / FileZilla`
* `PuTTY-Installer.exe / PuTTY`
* `ZoomInstallerFull.exe / Zoom`

---

# 🎯 최종 정리

* Sysmon ID 27은 **강력한 실행 파일 차단 보호**
* 예외는 **최소 범위 + 명확한 조건**으로만 추가
* 본 가이드는 **보안을 약화시키지 않는 표준 예외 처리 방식**
* PLURA Desktop 운영 환경에 **즉시 사용 가능**

---
