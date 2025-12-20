# 🐧 RHEL & Rocky Linux

## Sysmon (Sysmon for Linux) 버전별 설치 가이드 (간단)

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
sysmon -i
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

# 또는 커스텀 설정
sysmon -i sysmon-config.xml

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
sysmon -i sysmon-config.xml
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
