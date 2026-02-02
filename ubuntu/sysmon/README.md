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

## 0️⃣-1 운영 권장: Sysmon 설정 파일 위치 표준화

> 목표: **설정 원본은 `/etc`** 에 보관하고, **Sysmon 서비스는 `/opt/sysmon/config.xml`** 을 보도록 맞춥니다.  
> Ubuntu에서도 기본 `sysmon.service`가 `/opt/sysmon/config.xml`을 참조하는 경우가 많아, 표준 경로를 정해두면 운영이 편해집니다.

### 권장 구조

* 원본(관리/백업/형상관리): `/etc/sysmon/sysmon-config.xml`
* 서비스 참조(기본 `sysmon.service`와 호환): `/opt/sysmon/config.xml` → `/etc/sysmon/sysmon-config.xml` (심볼릭 링크)

### 적용 방법 (권장: 심볼릭 링크)

```bash
sudo mkdir -p /etc/sysmon
sudo install -o root -g root -m 0640 sysmon-config.xml /etc/sysmon/sysmon-config.xml

# (기본 sysmon.service가 /opt/sysmon/config.xml을 참고하는 경우가 많음)
sudo mkdir -p /opt/sysmon
sudo ln -sf /etc/sysmon/sysmon-config.xml /opt/sysmon/config.xml
```

### (선택) systemd 오버라이드로 `/etc` 경로를 직접 사용

> 아래 예시는 `sysmon` 바이너리 경로가 `/opt/sysmon/sysmon`인 경우입니다.  
> 만약 `command -v sysmon` 결과가 `/usr/bin/sysmon`이라면, drop-in의 `ExecStart=` 경로도 그에 맞게 바꿔 주세요.

```bash
command -v sysmon
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
ls -l /etc/sysmon/sysmon-config.xml /opt/sysmon/config.xml
systemctl show -p ExecStart --value sysmon
sysmon -c | head -n 40
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

# 또는 커스텀 설정 (권장: /etc/sysmon/sysmon-config.xml → /opt/sysmon/config.xml)
sysmon -i /opt/sysmon/config.xml

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
# (권장) 커스텀 설정 적용
sysmon -i /opt/sysmon/config.xml
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
# (권장) 커스텀 설정 적용
sysmon -i /opt/sysmon/config.xml
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
