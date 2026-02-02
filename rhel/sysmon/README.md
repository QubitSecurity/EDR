# 🐧 RHEL & Rocky Linux

## Sysmon (Sysmon for Linux) 버전별 설치 가이드

> 대상 OS
>
> * **RHEL / Rocky Linux 7**
> * **RHEL / Rocky Linux 8**
> * **RHEL / Rocky Linux 9**

---

## 0️⃣ 공통 사전 조건

```bash
# root 권한
sudo -i

# 커널 버전 확인
uname -r

# OS 버전 확인
cat /etc/redhat-release
```


---

## 0️⃣-1 운영 권장: Sysmon 설정 파일 위치 표준화

> 목표: **설정 원본은 `/etc`** 에 보관하고, **Sysmon 서비스는 `/opt/sysmon/config.xml`** 을 보도록 맞춥니다.  
> 이렇게 해두면 운영자가 관리하는 “원본 설정”과 서비스가 실제로 읽는 “적용 설정”을 일관되게 유지할 수 있습니다.

### 권장 구조

* 원본(관리/백업/형상관리): `/etc/sysmon/sysmon-config.xml`
* 서비스 참조(기본 `sysmon.service`와 호환): `/opt/sysmon/config.xml` → `/etc/sysmon/sysmon-config.xml` (심볼릭 링크)

### 적용 방법 (권장: 심볼릭 링크)

```bash
# 1) 설정 디렉터리 생성
sudo mkdir -p /etc/sysmon

# 2) (예) 현재 경로의 sysmon-config.xml을 표준 경로로 배치
sudo install -o root -g root -m 0640 sysmon-config.xml /etc/sysmon/sysmon-config.xml

# 3) Sysmon 기본 참조 경로로 링크
#    (기본 sysmon.service가 /opt/sysmon/config.xml을 참고하는 경우가 많음)
sudo mkdir -p /opt/sysmon
sudo ln -sf /etc/sysmon/sysmon-config.xml /opt/sysmon/config.xml
```

### (선택) systemd 오버라이드로 `/etc` 경로를 직접 사용

> 아래 예시는 `sysmon` 바이너리 경로가 `/opt/sysmon/sysmon`인 경우입니다.  
> 만약 `command -v sysmon` 결과가 `/usr/bin/sysmon`이라면, drop-in의 `ExecStart=` 경로도 그에 맞게 바꿔 주세요.

```bash
# sysmon 바이너리 경로 확인
command -v sysmon

# drop-in 생성/편집
sudo systemctl edit sysmon
```

편집기에 아래 입력:

```ini
[Service]
ExecStart=
ExecStart=/opt/sysmon/sysmon -i /etc/sysmon/sysmon-config.xml -service
WorkingDirectory=/opt/sysmon
```

적용:

```bash
sudo systemctl daemon-reload
sudo systemctl restart sysmon
```

### 설정 적용 여부 확인

```bash
# 링크/파일 존재 확인
ls -l /etc/sysmon/sysmon-config.xml /opt/sysmon/config.xml

# sysmon 서비스가 어떤 config를 물고 뜨는지 확인
systemctl show -p ExecStart --value sysmon

# Sysmon이 로딩한 현재 설정 덤프(길 수 있음)
sysmon -c | head -n 40
```

---

## 1️⃣ RHEL / Rocky Linux 7

### ⚠️ 주의

* **Sysmon for Linux 지원은 제한적**
* eBPF 기능이 불완전 → **운영 환경 권장 ❌**
* 테스트/PoC 용도로만 사용 권장

### 설치

```bash
curl -LO https://github.com/microsoft/SysmonForLinux/releases/latest/download/sysmonforlinux.rpm
yum install -y sysmonforlinux.rpm
```

### 서비스 시작

```bash
# 기본 설정 적용
sysmon -i

# (선택) 커스텀 설정 적용(표준 경로 사용 시)
# sysmon -i /opt/sysmon/config.xml
systemctl start sysmon
systemctl enable sysmon
```

---

## 2️⃣ RHEL / Rocky Linux 8 (권장)

### ✅ 특징

* **가장 안정적인 운영 버전**
* eBPF 지원 안정
* Sysmon + SIEM/XDR 연계에 적합

### 설치

```bash
curl -LO https://github.com/microsoft/SysmonForLinux/releases/latest/download/sysmonforlinux.rpm
dnf install -y sysmonforlinux.rpm
```

### 설정 적용 & 시작

```bash
# 기본 설정 적용
sysmon -i

# 또는 커스텀 설정 (권장: /etc/sysmon/sysmon-config.xml → /opt/sysmon/config.xml)
sysmon -i /opt/sysmon/config.xml

systemctl start sysmon
systemctl enable sysmon
```

### 상태 확인

```bash
systemctl status sysmon
```

---

## 3️⃣ RHEL / Rocky Linux 9 (최신, 신중)

### ⚠️ 특징

* 최신 커널 + 강화된 eBPF 보안
* 일부 환경에서 **eBPF 권한/정책 이슈 발생 가능**
* **사전 테스트 필수**

### 설치

```bash
curl -LO https://github.com/microsoft/SysmonForLinux/releases/latest/download/sysmonforlinux.rpm
dnf install -y sysmonforlinux.rpm
```

### SELinux / eBPF 이슈 발생 시 점검

```bash
getenforce
ausearch -m avc -ts recent
```

### 서비스 시작

```bash
# (권장) 커스텀 설정 적용
sysmon -i /opt/sysmon/config.xml
systemctl start sysmon
systemctl enable sysmon
```

---

## 4️⃣ 로그 위치 (공통)

```bash
/var/log/syslog
/var/log/messages
```

Sysmon 이벤트는 **journald / syslog** 를 통해 수집됨

---

## 5️⃣ 운영 권장 요약 ✅

| OS 버전          | 권장도   | 비고            |
| -------------- | ----- | ------------- |
| RHEL / Rocky 7 | ❌     | eBPF 미흡, 테스트용 |
| RHEL / Rocky 8 | ⭐⭐⭐⭐⭐ | **운영 최적**     |
| RHEL / Rocky 9 | ⭐⭐⭐   | 최신, 사전 검증 필수  |

---

## ✔️ 실무 한 줄 결론

> **운영 환경에서는 RHEL/Rocky 8 + Sysmon (curated 설정) 조합을 기본으로 사용**  
> RHEL/Rocky 9는 **PoC → 검증 후 단계적 적용** 권장

---
