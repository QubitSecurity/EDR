**CentOS 7과 RHEL 8 환경에서 `auditd` 설치 및 확인 방법** 안내

---

### ✅ `auditd` 설치 여부 및 설치 방법

`syslog-audit`는 **Linux 감사 로그(`auditd`)를 수집하는 에이전트**로, 운영 서버에서 감사 로그가 활성화되어 있어야 정상 동작합니다.
운영 중인 서버에 `auditd`가 설치되어 있는지 먼저 확인해 주세요.

---

#### 🔹 CentOS 7의 경우

* `auditd`는 기본 설치되어 있지 않은 경우가 많으며, 다음 명령어로 설치 가능합니다:

  ```bash
  sudo yum install audit
  ```

* 설치 후 서비스 활성화:

  ```bash
  sudo systemctl enable auditd
  sudo systemctl start auditd
  ```

---

#### 🔹 RHEL 8 이상

* `auditd`는 기본적으로 포함되어 있는 경우가 많지만, 설치 여부는 아래 명령어로 확인 가능합니다:

  ```bash
  rpm -q audit
  ```

* 만약 설치되어 있지 않다면, 다음 명령어로 설치할 수 있습니다:

  ```bash
  sudo dnf install audit
  ```

* 이후 서비스 활성화:

  ```bash
  sudo systemctl enable auditd
  sudo systemctl start auditd
  ```

---
