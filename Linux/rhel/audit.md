개요:

1. **“규칙 없이 자동으로 나오는 것”** vs
2. **“ATT&CK용으로 내가 규칙을 넣어야 나오는 것”**

을 구분해서, **대표적인 키들에 대한 설정 예시**를 보여드릴게요.
(141개를 한 번에 1:1로 모두 쓰면 너무 길고 부정확해져서, **ATT&CK에서 진짜 많이 쓸 핵심 그룹** 기준으로 정리하겠습니다.)

---

## 1. 규칙 없이 “거의 자동”으로 나오는 것들

이 친구들은 **auditd 서비스만 켜져 있고, PAM/SELinux가 audit 지원 빌드**이면
대부분의 RHEL에서 **추가 룰 없이도** 많이 찍힙니다.

### 1) 시스템 부팅/종료/런레벨

* **SYSTEM_BOOT / SYSTEM_SHUTDOWN / SYSTEM_RUNLEVEL**
* **KERNEL / KERNEL_OTHER**
* **DAEMON_START / DAEMON_END / DAEMON_ABORT / DAEMON_ROTATE / DAEMON_RESUME**

👉 별도 `-w` / `-a` 룰 없이도,
`systemd` + `auditd`가 올라가면 커널/서비스가 알아서 이벤트 쏩니다.

**추가 설정 팁**

* `/etc/audit/auditd.conf`에서 최소한:

```ini
log_format = RAW
flush = INCREMENTAL
max_log_file = 8
num_logs = 5
```

* `systemctl enable --now auditd`
* 부팅 시 `/sbin/auditd`가 **initramfs 단계에서 가능한 한 빨리 뜨도록** (RHEL 가이드 기본값)

---

### 2) 로그인/인증/세션 관련 (PAM 기반)

* **USER_AUTH, USER_LOGIN, USER_START, USER_END, USER_LOGOUT, LOGIN**
* **일부 ANOM_LOGIN_*** (정책에 따라)

이건 **PAM 모듈이 audit를 지원하면** 자동으로 audit 이벤트를 쏩니다.

**체크 포인트**

* `/etc/pam.d/system-auth` (RHEL) / `/etc/pam.d/password-auth`에
  `pam_unix.so` / `pam_sss.so` 등에 `audit` 옵션이 붙어 있는지:

```text
auth    required    pam_unix.so try_first_pass nullok audit
account required    pam_unix.so
session required    pam_unix.so
```

* sshd, login, sudo 등 주요 로그인 엔트리가 PAM을 타야 합니다.

👉 이 쪽은 **추가 auditd rule 없이도** 많이 나와요.
다만, **정책(잠금, 실패 임계치 등)** 을 pam faillock/tally2에서 켜줘야
ANOM_LOGIN_* 류가 풍부하게 생깁니다.

---

### 3) SELinux / AVC 관련

* **AVC / AVC_PATH / USER_AVC / SELINUX_ERR / USER_SELINUX_ERR / MAC_STATUS / MAC_POLICY_LOAD / MAC_CONFIG_CHANGE …**

이건:

1. **SELinux가 Enforcing/Permissive 상태로 활성화**되어 있고
2. 정책에서 `dontaudit`으로 다 막지 않은 이상

→ `setroubleshootd` / 커널 LSM이 **자동으로 audit** 이벤트를 쏩니다.

**필수 조건**

* `/etc/selinux/config`:

```ini
SELINUX=enforcing      # 또는 permissive
SELINUXTYPE=targeted   # 기본
```

* `sestatus`로 활성 상태 확인

👉 SELinux 관련 이벤트는 **“기본=✅”에 가까운 축**입니다.
다만, ATT&CK 관점에서는 **추가로 execve/파일/소켓까지 같이 캡처해야 실질적인 분석**이 됩니다.

---

## 2. 나머지(ATT&CK 핵심)들은 **대부분 내가 규칙을 넣어야** 나옵니다

이제부터가 진짜 질문하신 부분입니다.
대표 그룹별로:

* **어떤 이벤트 타입들이 이 규칙으로 나올 수 있는지**
* **예시 auditd 규칙**

을 같이 붙여볼게요.

---

## 2-1. 계정/그룹 생성·삭제·변경 (ADD_USER / DEL_USER / USER_MGMT …)

### 관련 이벤트 타입 (ATT&CK: 계정 생성 T1136, 권한 남용 등)

* `ADD_USER`, `DEL_USER`, `ADD_GROUP`, `DEL_GROUP`
* `USER_MGMT`, `USER_ACCT`
* `ANOM_ADD_ACCT`, `ANOM_DEL_ACCT`, `ANOM_MOD_ACCT`
* `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` 변경 시 `PATH`, `SYSCALL`

### 추천 auditd 설정 (RHEL)

`/etc/audit/rules.d/10-accounts.rules` 예시:

```bash
# 계정/그룹 데이터베이스 파일 변경 감시
-w /etc/passwd   -p wa -k identity
-w /etc/shadow   -p wa -k identity
-w /etc/group    -p wa -k identity
-w /etc/gshadow  -p wa -k identity

# 계정/그룹 관리 명령 감시
-w /usr/sbin/useradd  -p x -k user_mgmt
-w /usr/sbin/userdel  -p x -k user_mgmt
-w /usr/sbin/usermod  -p x -k user_mgmt
-w /usr/sbin/groupadd -p x -k group_mgmt
-w /usr/sbin/groupdel -p x -k group_mgmt
-w /usr/sbin/groupmod -p x -k group_mgmt

# 패스워드, 인증 토큰 변경
-w /usr/bin/passwd    -p x -k passwd_change
-w /usr/bin/chage     -p x -k passwd_change
-w /usr/sbin/chpasswd -p x -k passwd_change
```

**이 규칙들로 기대하는 타입**

* 계정/그룹 추가/삭제: `ADD_USER`, `DEL_USER`, `ADD_GROUP`, `DEL_GROUP`, `USER_MGMT`
* 파일 변경: `PATH`, `SYSCALL`, `CWD`
* 비정상 계정 변경 시: `ANOM_ADD_ACCT`, `ANOM_DEL_ACCT`, `ANOM_MOD_ACCT` (정책조건 충족 시)

---

## 2-2. 프로세스/명령 실행 (EXECVE / SYSCALL / USER_CMD …)

### 관련 이벤트 타입 (ATT&CK: T1059, T1105 등)

* `EXECVE`, `SYSCALL`, `CWD`, `PATH`, `TTY`, `USER_CMD`
* 간접적으로: `ANOM_EXEC`, `ANOM_MK_EXEC`, `ANOM_ROOT_TRANS`, `CAPSET`, `BPRM_FCAPS` …

### 최소 추천 규칙 (일반 사용자 계정 실행만)

```bash
# 64비트
-a always,exit -F arch=b64 -S execve -C auid>=1000 -F auid!=4294967295 -k exec_log

# 32비트 (멀티아치 시스템일 때)
-a always,exit -F arch=b32 -S execve -C auid>=1000 -F auid!=4294967295 -k exec_log
```

**좀 더 깊게 가고 싶으면:**

```bash
# setuid / setgid 변경 (권한 상승 탐지)
-a always,exit -F arch=b64 -S setuid,setreuid,setresuid,setgid,setregid,setresgid -F auid>=1000 -F auid!=4294967295 -k priv_change
```

**이 규칙들로 기대하는 타입**

* 모든 사용자 명령: `EXECVE`, `SYSCALL`, `CWD`, `PATH`
* 터미널과 연동되면: `TTY`, `USER_CMD`
* setuid 등으로 인한 권한 변화: `SYSCALL` + `ANOM_ROOT_TRANS`/`CAPSET`/`BPRM_FCAPS` 등

---

## 2-3. 파일/설정 변경 (FS_RELABEL / LABEL_* / PATH …)

ATT&CK의 **Persistence, Defense Evasion, Privilege Escalation** 관점에서 중요한 설정 파일들을 봐야 합니다.

### 대표 설정 대상

* SSH: `/etc/ssh/sshd_config`
* sudo: `/etc/sudoers`, `/etc/sudoers.d/`
* 서비스 단위: `/etc/systemd/system/`, `/usr/lib/systemd/system/`
* SELinux 정책: `/etc/selinux/`, `/sys/fs/selinux/` (정책 로드 자체는 MAC_* 이벤트로도 나옴)

### 예시 규칙

```bash
# SSH 설정 변경
-w /etc/ssh/sshd_config -p wa -k ssh_config

# sudo 설정 변경
-w /etc/sudoers         -p wa -k sudo_config
-w /etc/sudoers.d/      -p wa -k sudo_config

# systemd 서비스 유닛 변경
-w /etc/systemd/system/        -p wa -k service_change
-w /usr/lib/systemd/system/    -p wa -k service_change
```

**이 규칙들로 기대하는 타입**

* 설정 파일 변경: `PATH`, `SYSCALL`, `CWD`
* SELinux 쪽 정책 변경 시: `MAC_POLICY_LOAD`, `MAC_CONFIG_CHANGE`, `MAC_STATUS`
  (이는 별도 서브시스템 로직 + 일부 audit hook으로 생성)

---

## 2-4. 방화벽/네트워크 (NETFILTER_CFG / NETFILTER_PKT / SOCKADDR …)

### 관련 이벤트 타입

* 방화벽/정책: `NETFILTER_CFG`
* 패킷 추적: `NETFILTER_PKT`
* 소켓/연결: `SOCKETCALL`, `SOCKADDR`, `OBJ_PID`

**중요 포인트:**
`NETFILTER_CFG`/`NETFILTER_PKT`는 주로 **커널 Netfilter와 audit hook**에서 자동 발생하고,
일반적인 audit.rules로 “직접” 잡는다기 보다는:

* iptables/nftables 명령 실행을 감시하는 방식 +
* 커널에서 자동 쏘는 `NETFILTER_*`를 같이 보는 방식입니다.

### 예시 규칙

```bash
# iptables / nftables 명령 실행 추적
-w /usr/sbin/iptables  -p x -k fw_change
-w /usr/sbin/ip6tables -p x -k fw_change
-w /usr/sbin/nft       -p x -k fw_change
```

**이 규칙들로 기대하는 타입**

* 명령 실행: `EXECVE`, `SYSCALL`, `CWD`, `PATH`
* 실제 커널 체인 변경: `NETFILTER_CFG`
* (패킷 단위는 `NETFILTER_PKT` 옵션/커널 설정에 따라 추가)

---

## 2-5. 무결성/TPM (INTEGRITY_* / INTEGRITY_PCR …)

이건 **IMA/EVM/TPM 서브시스템을 켜야** 나오고,
audit 규칙만으로는 안 됩니다.

### 필수 전제

1. 커널 부팅 옵션에 IMA/EVM/TPM 활성
2. `/etc/ima/ima-policy` 등에 정책 설정
3. auditd는 그 이벤트를 log로 받아주기만 하면 됨

### auditd 측 설정

보통 **추가 audit.rules 필요 없이**, IMA가 audit로 쏘는 것을 받습니다.
다만, **해당 메시지에 별도 키를 붙이고 싶으면** `log_prefix`를 활용한 후 SIEM에서 처리.

👉 여기서는 “각 항목별 설정값”이라기보다 **OS 보안 프레임워크 구성 전체**에 가까운 영역이라,
PLURA-Forensic 문서에서는 **별도 챕터(“무결성/TPM 활성 가이드”)**로 빼시는 게 좋습니다.

---

## 2-6. 가상화 (VIRT_CONTROL / VIRT_RESOURCE / VIRT_MACHINE_ID)

이건 **libvirt / QEMU-KVM**와 audit 연동을 켜야 합니다.

### 필수 전제

* libvirt가 audit 지원 빌드이고, `/etc/libvirt/libvirtd.conf` 또는 `/etc/libvirt/qemu.conf`에서
  audit 로깅이 활성화되어 있어야 합니다. (예: `log_filters`, `log_outputs` 설정 등)

**audit.rules** 차원에서 직접 할 수 있는 건 적고,
대부분 **libvirt가 auditd로 던지는 VIRT_* 이벤트를 받아서 저장**하는 구조입니다.

---

## 3. 실제로는 어떻게 가져가면 좋냐?

말씀하신 대로:

> **마이터 ATT&CK을 제대로 보기 위해서는,
> “기본 자동 로그 + 추가 audit.rules”를 합쳐서 꽤 많은 설정이 필요**합니다.

그래서 PLURA-Forensic/Linux-Log 쪽 설계로는 보통:

1. **자동 로그(기본=✅ 타입)**

   * SYSTEM_*, DAEMON_*, KERNEL_*, LOGIN/USER_AUTH, SELINUX_ERR/AVC 등
   * → “OS가 알아서 던지는 것”을 잘 받아서 정규화

2. **ATT&CK 핵심 세트용 audit.rules**

   * 계정/그룹/권한 변경
   * EXECVE/파일/TTY/소켓
   * 중요 설정 파일 watch
   * iptables/nftables 명령 감시
   * (선택) SYSCALL/NETFILTER_PKT/MMAP 등 deep 분석용

3. **특수 서브시스템(SELinux, IMA/EVM, TPM, libvirt 등)**

   * 각자 enable + policy 설정 → audit로 떨어지는 것을 수집

---

## 4. 다음 단계 제안

원하시면, 지금까지 정리한 걸 바탕으로:

* `rhel-auditd-attack-baseline.rules`
  (계정·실행·네트워크·설정 변경 위주 **ATT&CK 최소 세트**)

* `rhel-auditd-attack-deep.rules`
  (`SYSCALL`, `NETFILTER_PKT`, `MMAP` 같은 **고볼륨 심화 세트**)

