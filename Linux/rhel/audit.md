# RHEL auditd 기반 MITRE ATT&CK 탐지를 위한 PLURA 설정 가이드

## 0. 문서 목적

이 문서는 **RHEL 서버에서 auditd + PLURA 에이전트**를 사용하여
**MITRE ATT&CK 관점의 보안 이벤트를 수집**하기 위한 기초 설정 방법을 안내합니다.

핵심 포인트는 두 가지입니다.

1. **규칙 없이 자동으로 나오는 이벤트**
2. **ATT&CK 탐지를 위해 내가 audit 규칙을 넣어야 나오는 이벤트**

를 구분하고,
이를 바탕으로 PLURA 전용 규칙 파일:

* `rhel-auditd-attack-baseline.rules`  (기본/상시 권장 세트)
* `rhel-auditd-attack-deep.rules`      (심화·고볼륨 세트)

을 제공하는 것에 목적이 있습니다.

---

## 1. 규칙 없이 “거의 자동”으로 나오는 것들

다음 이벤트들은 **auditd 서비스만 켜져 있고, PAM/SELinux가 audit 지원 빌드**라면
추가 규칙 없이도 **어느 정도 자동으로 생성**됩니다.

### 1-1. 시스템 부팅/종료/런레벨

자동 생성되는 대표 이벤트:

* `SYSTEM_BOOT`, `SYSTEM_SHUTDOWN`, `SYSTEM_RUNLEVEL`
* `KERNEL`, `KERNEL_OTHER`
* `DAEMON_START`, `DAEMON_END`, `DAEMON_ABORT`, `DAEMON_ROTATE`, `DAEMON_RESUME`

즉, OS 부팅·종료·런레벨 변경·auditd 데몬 시작/종료 등은
별도 `-w` / `-a` 규칙 없이도 커널과 systemd가 **auditd로 바로 이벤트를 전송**합니다.

**추천 기본 설정 (auditd)**

`/etc/audit/auditd.conf` 예시:

```ini
log_format = RAW
flush = INCREMENTAL
max_log_file = 8
num_logs = 5
```

그리고:

```bash
systemctl enable --now auditd
```

---

### 1-2. 로그인/인증/세션 관련 (PAM 기반)

자동 생성되는 대표 이벤트:

* `USER_AUTH`, `USER_LOGIN`, `USER_START`, `USER_END`, `USER_LOGOUT`, `LOGIN`
* 일부 `ANOM_LOGIN_*` (계정 잠금/정책 설정에 따라)

PAM 모듈이 audit를 지원하는 경우:

* 로그인/로그아웃, 인증 성공/실패, 세션 시작/종료 시
  auditd로 자동 이벤트를 보냅니다.

**체크 포인트 (RHEL 기준)**

`/etc/pam.d/system-auth` 또는 `/etc/pam.d/password-auth` 등에
`audit` 옵션이 포함되어 있는지 확인합니다.

```text
auth    required    pam_unix.so try_first_pass nullok audit
account required    pam_unix.so
session required    pam_unix.so
```

그리고 sshd, login, sudo 등 주요 로그인 엔트리가
이 PAM 스택을 타도록 설정되어 있어야 합니다.

> **참고:**
> ANOM_LOGIN_* 류(로그인 실패 누적, 시간/위치 정책 위반 등)를 잘 활용하려면
> pam_faillock, pam_tally2 등의 정책(잠금 임계치 등)을 설정해야 합니다.

---

### 1-3. SELinux / AVC 관련

자동 생성되는 대표 이벤트:

* `AVC`, `AVC_PATH`
* `USER_AVC`, `SELINUX_ERR`, `USER_SELINUX_ERR`
* `MAC_STATUS`, `MAC_POLICY_LOAD`, `MAC_CONFIG_CHANGE` 등

전제:

1. SELinux가 **enforcing 또는 permissive**로 활성화되어 있고,
2. 정책에서 해당 동작을 `dontaudit`으로 완전히 무시하지 않는 경우,

커널 LSM/SELinux가 **자동으로 audit 이벤트를 생성**합니다.

`/etc/selinux/config` 예:

```ini
SELINUX=enforcing      # 또는 permissive
SELINUXTYPE=targeted   # 기본값
```

```bash
sestatus   # SELinux 활성 상태 확인
```

> SELinux 쪽 이벤트는 “OS가 자동으로 던지는 축”에 가깝지만,
> 실제 ATT&CK 분석에서는 **execve / 파일 / 소켓 정보**를 함께 수집해야
> 의미 있는 스토리(누가, 어떤 프로세스를, 어느 파일에, 어떤 권한으로 접근했는지)가 나옵니다.

그래서 아래의 **추가 규칙(audit.rules)** 가 필요합니다.

---

## 2. ATT&CK 탐지를 위해 “내가 규칙을 넣어야” 나오는 것들

나머지 ATT&CK 핵심 이벤트들은 대부분 **규칙을 추가해야만** 로그가 찍힙니다.

아래는 대표적인 그룹입니다.

---

### 2-1. 계정/그룹 생성·삭제·변경

(ADD_USER / DEL_USER / USER_MGMT …)

**관련 이벤트 타입 (예: T1136, 계정 생성 / 계정 조작)**

* `ADD_USER`, `DEL_USER`, `ADD_GROUP`, `DEL_GROUP`
* `USER_MGMT`, `USER_ACCT`
* `ANOM_ADD_ACCT`, `ANOM_DEL_ACCT`, `ANOM_MOD_ACCT`
* `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` 변경 시: `PATH`, `SYSCALL`, `CWD`

**예시 규칙 (기본 개념용, 실제 PLURA 룰은 plura_* 키 사용)**

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

# 패스워드/인증 토큰 변경
-w /usr/bin/passwd    -p x -k passwd_change
-w /usr/bin/chage     -p x -k passwd_change
-w /usr/sbin/chpasswd -p x -k passwd_change
```

---

### 2-2. 프로세스/명령 실행

(EXECVE / SYSCALL / USER_CMD …)

**관련 이벤트 타입 (예: T1059 Command & Scripting, T1105 등)**

* 직접: `EXECVE`, `SYSCALL`, `CWD`, `PATH`, `TTY`, `USER_CMD`
* 간접: `ANOM_EXEC`, `ANOM_MK_EXEC`, `ANOM_ROOT_TRANS`, `CAPSET`, `BPRM_FCAPS` …

**최소 실행 추적 규칙 (일반 사용자 계정만)**

```bash
# 64비트
-a always,exit -F arch=b64 -S execve \
  -C auid>=1000 -F auid!=4294967295 \
  -k exec_log

# 32비트 (멀티아치 시스템일 때만)
-a always,exit -F arch=b32 -S execve \
  -C auid>=1000 -F auid!=4294967295 \
  -k exec_log
```

**권한 상승 감시 (setuid/setgid 등)**

```bash
-a always,exit -F arch=b64 \
  -S setuid,setreuid,setresuid,setgid,setregid,setresgid \
  -F auid>=1000 -F auid!=4294967295 \
  -k priv_change
```

---

### 2-3. 파일/설정 변경

(FS_RELABEL / LABEL_* / PATH …)

**대표 대상 (Persistence / Defense Evasion / Priv Esc)**

* SSH 설정: `/etc/ssh/sshd_config`
* sudo 설정: `/etc/sudoers`, `/etc/sudoers.d/`
* 서비스 유닛: `/etc/systemd/system/`, `/usr/lib/systemd/system/`
* SELinux 정책: `/etc/selinux/…`, `/sys/fs/selinux/…`

**예시 규칙**

```bash
# SSH 설정 변경
-w /etc/ssh/sshd_config -p wa -k ssh_config

# sudo 설정 변경
-w /etc/sudoers         -p wa -k sudo_config
-w /etc/sudoers.d/      -p wa -k sudo_config

# systemd 서비스 유닛 변경
-w /etc/systemd/system/     -p wa -k service_change
-w /usr/lib/systemd/system/ -p wa -k service_change
```

---

### 2-4. 방화벽/네트워크

(NETFILTER_CFG / NETFILTER_PKT / SOCKADDR …)

**관련 이벤트 타입**

* 정책/체인 변경: `NETFILTER_CFG`
* 패킷 추적: `NETFILTER_PKT`
* 소켓/연결: `SOCKETCALL`, `SOCKADDR`, `OBJ_PID` 등

일반적으로:

* **iptables/nft 실행을 audit로 감시**하고,
* 커널이 자동으로 쏘는 `NETFILTER_CFG` 이벤트와 함께 분석합니다.

**예시 규칙**

```bash
# iptables / nftables 명령 실행 추적
-w /usr/sbin/iptables  -p x -k fw_change
-w /usr/sbin/ip6tables -p x -k fw_change
-w /usr/sbin/nft       -p x -k fw_change
```

---

### 2-5. 무결성/TPM (INTEGRITY_* / INTEGRITY_PCR …)

이 영역은 **audit.rules만으로 해결되지 않고**,
OS 보안 프레임워크(IMA/EVM/TPM)를 활성화해야 합니다.

전제:

1. 커널 부팅 옵션에 IMA/EVM/TPM 활성
2. `/etc/ima/ima-policy` 등에서 정책 구성
3. IMA/EVM이 audit로 쏘는 이벤트를 auditd가 받아 저장

→ PLURA-Forensic 문서에서는 **“무결성/TPM 활성 가이드”**를 별도 챕터로 두는 것이 좋습니다.

---

### 2-6. 가상화 (VIRT_CONTROL / VIRT_RESOURCE / VIRT_MACHINE_ID)

libvirt / QEMU-KVM 환경에서:

* VM 시작/중지/리소스 변경 등은 `VIRT_*` 이벤트로 떨어질 수 있습니다.

전제:

* libvirt가 audit 지원 빌드일 것
* `/etc/libvirt/libvirtd.conf` 또는 `/etc/libvirt/qemu.conf`에서
  audit 관련 옵션(`log_filters`, `log_outputs` 등)이 활성화되어 있을 것

audit.rules에서 할 수 있는 것은 제한적이고,
대부분은 “libvirt가 auditd로 쏘는 이벤트를 그대로 수집”하는 구조입니다.

---

## 3. PLURA 전용 RHEL auditd 룰 세트

ATT&CK 관점에서 의미 있는 이벤트를 안정적으로 수집할 수 있도록,
PLURA는 RHEL용으로 아래 두 개의 규칙 파일을 제공합니다.

* **`rhel-auditd-attack-baseline.rules`**
  → 실서비스에 상시 적용 가능한 **기본 ATT&CK 세트**

* **`rhel-auditd-attack-deep.rules`**
  → 포렌식/연구/특정 고위험 서버에만 적용하는 **심화 추적 세트**

모든 규칙에는 `-k plura_...` 형태의 tag를 사용하여
**“PLURA 에이전트가 생성한 룰”임을 명확히 표시**합니다.

### 3-1. rhel-auditd-attack-baseline.rules

```bash
###############################################
# rhel-auditd-attack-baseline.rules
# - 목적: MITRE ATT&CK 최소 커버용 PLURA 기본 룰
# - 특징: auid>=1000 (실사용자) 중심, 운영 가능한 로그량
# - 태그: plura_* 로 시작 (PLURA 에이전트 생성 룰 식별용)
###############################################

##############
# 0. 공통 필터
##############
# (여기서는 -D, -b 등 글로벌 옵션은 다루지 않음)
# 기본 정책은 상위 메인 rules 파일에서 관리한다고 가정.

#######################################
# 1. 계정 / 그룹 / 인증 정보 변경 추적
#######################################

# 계정/그룹 데이터베이스 파일 변경 감시
-w /etc/passwd   -p wa -k plura_identity
-w /etc/shadow   -p wa -k plura_identity
-w /etc/group    -p wa -k plura_identity
-w /etc/gshadow  -p wa -k plura_identity

# 계정/그룹 관리 명령 사용 추적
-w /usr/sbin/useradd   -p x -k plura_user_mgmt
-w /usr/sbin/userdel   -p x -k plura_user_mgmt
-w /usr/sbin/usermod   -p x -k plura_user_mgmt
-w /usr/sbin/groupadd  -p x -k plura_group_mgmt
-w /usr/sbin/groupdel  -p x -k plura_group_mgmt
-w /usr/sbin/groupmod  -p x -k plura_group_mgmt

# 패스워드/계정 속성 변경
-w /usr/bin/passwd     -p x -k plura_passwd_change
-w /usr/bin/chage      -p x -k plura_passwd_change
-w /usr/sbin/chpasswd  -p x -k plura_passwd_change

##########################################
# 2. 로그인/세션/권한상승(계정 탈취, sudo/su)
##########################################

# su, sudo 실행 (권한 상승 시도 추적 – T1078, T1068 등)
-w /bin/su         -p x -k plura_su_exec
-w /usr/bin/sudo   -p x -k plura_sudo_exec
-w /usr/bin/sudoedit -p x -k plura_sudo_exec

# sudoers 설정 변경 (Defense Evasion)
-w /etc/sudoers       -p wa -k plura_sudo_config
-w /etc/sudoers.d/    -p wa -k plura_sudo_config

##########################################
# 3. 프로세스/명령 실행 (EXECVE – ATT&CK 핵심)
##########################################

# 일반 사용자(auid>=1000)의 execve 전체 추적 (T1059 Command and Scripting)
# 64bit
-a always,exit -F arch=b64 -S execve \
  -C auid>=1000 -F auid!=4294967295 \
  -k plura_execve_user

# 32bit (멀티아치 시스템일 경우만 활성화)
#-a always,exit -F arch=b32 -S execve \
#  -C auid>=1000 -F auid!=4294967295 \
#  -k plura_execve_user

##########################################
# 4. 중요 설정 파일 변경 (Persistence / Defense Evasion)
##########################################

# SSH 서버 설정 변경
-w /etc/ssh/sshd_config   -p wa -k plura_ssh_config

# systemd 서비스 유닛 변경 (서비스 등록/변조 – Persistence)
-w /etc/systemd/system/       -p wa -k plura_service_change
-w /usr/lib/systemd/system/   -p wa -k plura_service_change

# Crontab 및 주기 작업 (T1053 Scheduled Task/Job)
-w /etc/crontab               -p wa -k plura_cron
-w /etc/cron.hourly/          -p wa -k plura_cron
-w /etc/cron.daily/           -p wa -k plura_cron
-w /etc/cron.weekly/          -p wa -k plura_cron
-w /etc/cron.monthly/         -p wa -k plura_cron
-w /etc/cron.d/               -p wa -k plura_cron
-w /var/spool/cron/           -p wa -k plura_cron

##########################################
# 5. 방화벽 / 네트워크 정책 변경 (Netfilter)
##########################################

# iptables / nftables 실행 추적 (T1562 Defense Evasion, 방화벽 변조)
-w /usr/sbin/iptables   -p x -k plura_fw_change
-w /usr/sbin/ip6tables  -p x -k plura_fw_change
-w /usr/sbin/nft        -p x -k plura_fw_change

##########################################
# 6. SELinux / MAC 정책 변경
##########################################

# SELinux 설정/정책 파일 변경
-w /etc/selinux/            -p wa -k plura_selinux_conf

##########################################
# 7. Auditd / 로깅 설정 변경
##########################################

# auditd 설정 자체 변경 탐지 (Defense Evasion – 로그 끄기)
-w /etc/audit/           -p wa -k plura_audit_config
-w /usr/sbin/auditctl    -p x  -k plura_audit_config
-w /usr/sbin/auditd      -p x  -k plura_audit_config

##########################################
# 8. 핵심 바이너리 위변조 (무결성 관점 최소)
##########################################

# su / sudo / sshd / passwd 등 핵심 바이너리 변경
-w /bin/su               -p wa -k plura_core_bin
-w /usr/bin/sudo         -p wa -k plura_core_bin
-w /usr/sbin/sshd        -p wa -k plura_core_bin
-w /usr/bin/passwd       -p wa -k plura_core_bin
```

---

### 3-2. rhel-auditd-attack-deep.rules

```bash
################################################
# rhel-auditd-attack-deep.rules
# - 목적: 심화 포렌식/연구용 (고볼륨, 선택 적용)
# - 특징: SYSCALL/네트워크/메모리/파일 동작을 더 넓게 추적
# - 태그: plura_* (PLURA 에이전트 생성 룰)
################################################

##############
# 0. 공통 필터
##############
# 심화 규칙은 보통 특정 서버(예: 의심 서버, 연구 환경)에만 적용 권장.

##########################################
# 1. 심화 execve 추적 (root 포함)
##########################################

# root 계정(auid=0) 및 시스템 서비스의 execve 추가 추적
# 64bit
-a always,exit -F arch=b64 -S execve \
  -F auid=0 \
  -k plura_execve_root

# 32bit (옵션)
#-a always,exit -F arch=b32 -S execve \
#  -F auid=0 \
#  -k plura_execve_root

##########################################
# 2. 고위험 syscall 클러스터 (Privilege Esc / Defense Evasion)
##########################################

# 권한/ID 변경 계열 (setuid/setgid 등)
-a always,exit -F arch=b64 \
  -S setuid,setreuid,setresuid,setgid,setregid,setresgid \
  -F auid>=1000 -F auid!=4294967295 \
  -k plura_sys_privchange

# capability / security 속성 변경
-a always,exit -F arch=b64 \
  -S capset \
  -F auid>=1000 -F auid!=4294967295 \
  -k plura_sys_capset

# 파일 권한/소유권 변경 (chmod/chown/chattr 등 고위험만 선별)
-a always,exit -F arch=b64 \
  -S chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown \
  -F auid>=1000 -F auid!=4294967295 \
  -k plura_sys_chmod_chown

# mount/umount – 파일시스템/장치 마운트 변경
-a always,exit -F arch=b64 \
  -S mount,umount2 \
  -F auid>=1000 -F auid!=4294967295 \
  -k plura_sys_mount

# ptrace – 프로세스 인젝션/디버깅 시도
-a always,exit -F arch=b64 \
  -S ptrace \
  -F auid>=1000 -F auid!=4294967295 \
  -k plura_sys_ptrace

##########################################
# 3. 메모리 조작 / 코드 영역 변경 (MMAP/MPROTECT)
##########################################

# mmap / mprotect – 코드 인젝션, ROP 등 탐지 보조
-a always,exit -F arch=b64 \
  -S mmap,mprotect \
  -F auid>=1000 -F auid!=4294967295 \
  -k plura_sys_mmap

##########################################
# 4. 심화 파일 동작 (홈디렉터리 중심)
##########################################

# /home, /root, /tmp 아래의 파일 생성/삭제/속성변경
# (open/openat/creat/unlink/rename/link 등)
-a always,exit -F arch=b64 \
  -S open,openat,creat,truncate,ftruncate,unlink,unlinkat,rename,renameat,link,linkat,symlink,symlinkat \
  -F dir=/home \
  -F auid>=1000 -F auid!=4294967295 \
  -k plura_fs_home

-a always,exit -F arch=b64 \
  -S open,openat,creat,truncate,ftruncate,unlink,unlinkat,rename,renameat,link,linkat,symlink,symlinkat \
  -F dir=/root \
  -k plura_fs_root

-a always,exit -F arch=b64 \
  -S open,openat,creat,truncate,ftruncate,unlink,unlinkat,rename,renameat,link,linkat,symlink,symlinkat \
  -F dir=/tmp \
  -k plura_fs_tmp

##########################################
# 5. 네트워크 syscall (connect/accept 등)
##########################################

# outbound/inbound 연결 추적 (T1041, T1071 등)
-a always,exit -F arch=b64 \
  -S socket,connect,accept,accept4,bind,listen \
  -F auid>=1000 -F auid!=4294967295 \
  -k plura_net_socket

# 데이터 송수신 (간략 세트 – sendto/recvfrom)
-a always,exit -F arch=b64 \
  -S sendto,recvfrom,sendmsg,recvmsg \
  -F auid>=1000 -F auid!=4294967295 \
  -k plura_net_data

##########################################
# 6. netfilter 패킷(고볼륨) & 방화벽 심층
##########################################
# 주의: NETFILTER_PKT는 커널 설정에 따라 매우 고볼륨이 될 수 있음.
# auditd rule로 직접 제어하기보다는, 커널 netfilter 설정+log_level로 조절.
# 여기서는 iptables/nft 실행은 baseline에서 이미 추적 중 (plura_fw_change).

##########################################
# 7. 모든 SYSCALL 전역 추적 (연구/POC 환경 전용)
##########################################
# ※ 정말 로그 폭탄이므로, 일반 운영환경에는 권장 X
# 예시만 제시하고 기본은 주석 처리.

#-a always,exit -F arch=b64 \
#  -S all \
#  -F auid>=1000 -F auid!=4294967295 \
#  -k plura_sys_all_user

# root 포함 전체 syscall (강력 경고: 연구/샌드박스에서만)
#-a always,exit -F arch=b64 \
#  -S all \
#  -k plura_sys_all_any
```

---

## 4. 적용 방법 & 운영 팁

1. 위 두 파일을 RHEL 서버에 저장:

```bash
cp rhel-auditd-attack-baseline.rules /etc/audit/rules.d/
cp rhel-auditd-attack-deep.rules     /etc/audit/rules.d/   # (선택적)
```

2. 규칙 로드:

```bash
augenrules --load
# 또는
systemctl restart auditd
```

3. PLURA 에이전트는 `-k plura_*` 태그를 기준으로
   **PLURA가 설치/관리한 룰에서 생성된 로그**를 식별할 수 있습니다.

4. **운영 권장**

* 모든 서버:
  → `rhel-auditd-attack-baseline.rules` 만 먼저 적용
* 고위험/분석용 서버(예: 침해 의심 서버, PoC 환경):
  → `…-deep.rules` 를 추가 적용 (로그량·성능 영향 모니터링 필수)

---
