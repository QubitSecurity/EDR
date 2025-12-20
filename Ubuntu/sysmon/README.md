# 🐧 Ubuntu

## Sysmon (Sysmon for Linux) 버전별 설치 가이드

> 대상 OS
>
> * **Ubuntu 20.04 LTS**
> * **Ubuntu 22.04 LTS**
> * **Ubuntu 24.04 LTS**

---

## 0️⃣ 공통 사전 조건

```bash
# root 권한
sudo -i

# OS / 커널 확인
lsb_release -a
uname -r
```

---

## 1️⃣ Ubuntu 20.04 LTS

### ⚠️ 특징

* eBPF 초기 안정화 단계
* **운영 가능하나 성능·기능 제한 존재**
* 테스트 또는 제한적 운영 권장

### 설치

```bash
curl -LO https://github.com/microsoft/SysmonForLinux/releases/latest/download/sysmonforlinux.deb
apt install -y ./sysmonforlinux.deb
```

### 설정 적용 & 시작

```bash
# 기본 설정
sysmon -i

# 또는 커스텀 설정
sysmon -i sysmon-config.xml

systemctl start sysmon
systemctl enable sysmon
```

---

## 2️⃣ Ubuntu 22.04 LTS (권장 ⭐)

### ✅ 특징

* eBPF 성숙 단계
* **운영 안정성·성능 균형 최적**
* Sysmon + SIEM/XDR 연계에 가장 적합

### 설치

```bash
curl -LO https://github.com/microsoft/SysmonForLinux/releases/latest/download/sysmonforlinux.deb
apt install -y ./sysmonforlinux.deb
```

### 설정 적용 & 시작

```bash
sysmon -i sysmon-config.xml
systemctl start sysmon
systemctl enable sysmon
```

### 상태 확인

```bash
systemctl status sysmon
```

---

## 3️⃣ Ubuntu 24.04 LTS (최신, 주의)

### ⚠️ 특징

* 최신 커널 + 강화된 eBPF 보안 정책
* 환경에 따라 **eBPF 권한/제약 이슈 발생 가능**
* **운영 전 PoC 필수**

### 설치

```bash
curl -LO https://github.com/microsoft/SysmonForLinux/releases/latest/download/sysmonforlinux.deb
apt install -y ./sysmonforlinux.deb
```

### 문제 발생 시 점검 포인트

```bash
# AppArmor 상태
aa-status

# 커널 메시지
dmesg | tail
```

### 서비스 시작

```bash
sysmon -i sysmon-config.xml
systemctl start sysmon
systemctl enable sysmon
```

---

## 4️⃣ 로그 위치 (Ubuntu 공통)

```bash
# journald
journalctl -u sysmon

# rsyslog 사용 시
/var/log/syslog
```

---

## 5️⃣ 운영 권장 요약 ✅

| Ubuntu 버전 | 권장도   | 비고           |
| --------- | ----- | ------------ |
| 20.04 LTS | ⭐⭐    | 제한적 운영       |
| 22.04 LTS | ⭐⭐⭐⭐⭐ | **운영 표준**    |
| 24.04 LTS | ⭐⭐⭐   | 최신, 사전 검증 필수 |

---

## ✔️ 실무 한 줄 결론

> **Ubuntu 운영 환경에서는 22.04 LTS + Sysmon (curated 설정) 조합을 기본값으로 사용**
> 24.04 LTS는 **PoC → 검증 → 단계적 확대 적용**이 안전

---
