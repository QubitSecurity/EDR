# 🐧 RHEL / Rocky Linux — Sysmon (Sysmon for Linux) 설치 가이드

> **목표**
>
> * 설치 전에는 “무엇을 준비해야 하는지 / 어떤 버전을 운영에 권장하는지”만 먼저 이해할 수 있도록 구성했습니다.
> * **권장 디렉터리 구조 / 설정 파일 위치 표준화** 같은 운영 팁은 **설치 이후(후반부)** 에 정리했습니다.

---

## 0️⃣ 공통 사전 조건 (설치 전)

아래 확인은 설치 전에 한 번만 점검하면 됩니다.

```bash
# root 권한
sudo -i

# OS 버전 확인
cat /etc/redhat-release

# 커널 버전 확인
uname -r
```

### 네트워크/배포 환경
* 인터넷에서 패키지를 내려받는다면 **HTTPS(443)로 GitHub 다운로드가 가능**해야 합니다.
* 인터넷이 불가한 폐쇄망이면, 다른 PC에서 RPM을 내려받아 서버로 복사 후 설치하세요(아래 설치 단계 참고).

---

## 1️⃣ 운영 권장 (설치 전 의사결정)

| OS 버전          | 권장도   | 설치 전 참고 |
|----------------|---------|-------------|
| RHEL / Rocky 7 | ❌       | eBPF 제약이 커서 **운영 비권장**, 테스트/PoC 용도 권장 |
| RHEL / Rocky 8 | ⭐⭐⭐⭐⭐   | **운영 표준 권장** |
| RHEL / Rocky 9 | ⭐⭐⭐     | 최신 커널/보안 정책 영향으로 **사전 PoC 권장** |

> 실무 결론: **운영은 RHEL/Rocky 8을 기본값**, RHEL/Rocky 9는 **PoC → 검증 → 단계적 확대** 권장

---

## 2️⃣ 설치 (버전별)

> 패키지는 Microsoft SysmonForLinux 릴리스의 `sysmonforlinux.rpm`을 사용합니다.

### 2-1) RHEL / Rocky 8 (권장)

```bash
curl -LO https://github.com/microsoft/SysmonForLinux/releases/latest/download/sysmonforlinux.rpm
dnf install -y ./sysmonforlinux.rpm
```

### 2-2) RHEL / Rocky 9

```bash
curl -LO https://github.com/microsoft/SysmonForLinux/releases/latest/download/sysmonforlinux.rpm
dnf install -y ./sysmonforlinux.rpm
```

**(선택) SELinux/eBPF 이슈 점검**
```bash
getenforce
ausearch -m avc -ts recent
```

### 2-3) RHEL / Rocky 7 (테스트/PoC 권장)

```bash
curl -LO https://github.com/microsoft/SysmonForLinux/releases/latest/download/sysmonforlinux.rpm
yum install -y ./sysmonforlinux.rpm
```

---

## 3️⃣ 설정 적용 & 서비스 시작

### 3-1) 기본 설정으로 시작

```bash
sysmon -i
systemctl enable --now sysmon
```

### 3-2) 커스텀 설정으로 시작 (권장)

예: `sysmon-config.xml`을 현재 디렉터리에 두었다고 가정합니다.

```bash
sysmon -i sysmon-config.xml
systemctl enable --now sysmon
```

---

## 4️⃣ 설치 후 확인 (기본)

### 4-1) 서비스 상태

```bash
systemctl status sysmon --no-pager
```

### 4-2) Sysmon이 실제로 어떤 설정 파일 경로로 기동되는지 확인

> 설치 시점에 “어떤 파일을 -i로 물고 떠 있는지”를 확인하는 용도입니다.

```bash
systemctl show -p ExecStart --value sysmon
```

### 4-3) 현재 로딩된 설정 덤프(선택)

```bash
# 현재 적용된 설정(XML)을 출력합니다(길 수 있습니다)
sysmon -c | head -n 40
```

---

## 5️⃣ 로그 확인

환경에 따라 journald 또는 syslog로 확인합니다.

```bash
# journald
journalctl -u sysmon -n 200 --no-pager
```

```bash
# syslog 계열(환경에 따라 존재)
ls -l /var/log/messages /var/log/syslog 2>/dev/null
```

---

## 6️⃣ 설치 후 운영 권장 (선택) — 설정 파일 위치 표준화

> 이 섹션은 **설치가 끝난 뒤** 운영 편의/유지보수를 위해 적용합니다.

### 권장 개념
* **원본(관리/백업/형상관리)**: `/etc/sysmon/sysmon-config.xml`
* **서비스가 보는 경로(호환성 목적)**: `/opt/sysmon/config.xml`
* `/opt/sysmon/config.xml` → `/etc/sysmon/sysmon-config.xml`로 **심볼릭 링크**를 걸어 두면,
  * 서비스 유닛을 크게 건드리지 않고
  * 운영 표준 경로(`/etc`)에 원본을 유지할 수 있습니다.

### 적용 예시

```bash
# 원본 보관 경로 준비
mkdir -p /etc/sysmon
install -o root -g root -m 0640 sysmon-config.xml /etc/sysmon/sysmon-config.xml

# Sysmon 기본 경로에 링크(기본 서비스 유닛과 호환)
mkdir -p /opt/sysmon
ln -sf /etc/sysmon/sysmon-config.xml /opt/sysmon/config.xml

# 링크 경로로 설정 적용 후 재시작
sysmon -i /opt/sysmon/config.xml
systemctl restart sysmon
```

### 적용 확인

```bash
ls -l /etc/sysmon/sysmon-config.xml /opt/sysmon/config.xml
systemctl show -p ExecStart --value sysmon
```

---

