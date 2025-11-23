# 📘 **AIX Audit 로그 외부 전송 + 공격 탐지 룰 설정 안내서**

이 문서는 IBM AIX 서버에서 **Audit(감사) 로그를 외부 서버(PLURA-XDR / SIEM)로 안정적으로 전송**하고,
공격 탐지를 위한 **AIX 기본(Baseline) 룰** 및 Linux(RHEL) 고급(Deep) 룰을 안내하기 위해 작성되었습니다.

---

# 1. 🛡️ AIX Audit 로그 외부 전송 개요

AIX 서버의 Audit 로그는 보안 관제·포렌식 분석·SIEM 연동을 위해 외부 서버로 전송하는 것이 필수적입니다.

AIX는 일반 Linux와 달리 **auditstream → syslog 파이프 방식**이 가장 안정적이며 현장에서 표준으로 사용됩니다.

---

# 2. ✅ 권장 방식: auditstream → syslog 전달

AIX Audit 내부 동작 흐름은 다음과 같습니다:

```
BIN 로그 → auditstream → logger(local6.notice) → syslog → 외부 서버
```

이 방식은 다음과 같은 장점이 있습니다:

✔ 시스템 부하 낮음  
✔ 실시간 전송  
✔ syslog 표준 포맷  
✔ PLURA·Elastic·Splunk·syslog-ng 연동 쉬움  
✔ 운영 현장에서 가장 안정적

---

# 3. 📌 설정 절차

## 3.1 auditstream 설정

### 구성 파일 편집

```
vi /etc/security/audit/config
```

### stream 섹션 추가/수정

```
streammode = on
streamcmds = /usr/sbin/auditstream | logger -p local6.notice
```

* `auditstream` : AIX Audit 이벤트를 실시간 출력
* `logger` : syslog 입력으로 전달
* `local6.notice` : syslog facility/priority

---

## 3.2 syslog.conf에서 외부 서버로 전송

```
vi /etc/syslog.conf
```

다음 한 줄을 추가합니다.

```
local6.notice    @<외부-로그-수집서버-IP>
```

TCP 전송 시:

```
local6.notice    @@<외부-로그-수집서버-IP>
```

아카이브도 남기려면:

```
local6.notice    /var/log/aix_audit.log
```

---

## 3.3 syslog 재기동

```
refresh -s syslogd
```

불가할 경우:

```
stopsrc -s syslogd
startsrc -s syslogd
```

---

## 3.4 Audit subsystem 재시작

```
audit shutdown
audit start
```

---

# 4. 🔧 테스트 절차

### 1) 로그인 실패 테스트

```
su wronguser
```

### 2) 명령 실행

```
ls
touch testfile
```

### 3) 외부 서버에서 수신 확인

```
tcpdump -nnA port 514
```

또는

```
journalctl -f
tail -f /var/log/messages
```

---

# 5. 🔎 실제 전송되는 로그 예시

```
Feb 20 11:32:01 aix01 root: AUDIT_EVENT PROC_Create pid=5411 user=root cmd=touch
```

PLURA, Elastic, Splunk 등에서 쉽게 파싱됩니다.

---

# 6. 🧩 Facility/Severity 변경 (선택)

원하면 다음처럼 변경할 수 있습니다:

```
logger -p local4.info
```

* Facility: `local0`~`local7`
* Severity: `debug`~`emerg`

---

# 7. 🧰 Syslog-ng 또는 rsyslog와의 연동

AIX에서 syslog-ng 서버로 직접 전송 가능:

```
local6.notice    @syslog-ng-server:514
```

---

# 8. ✋ 비권장: auditpr → 파일 저장 → syslog-forward

```
BIN → auditpr → text 파일 → syslog forward
```

성능이 좋지 않기 때문에 운영환경에서는 거의 사용하지 않습니다.

---

# 9. 🔥 공격 탐지 룰 포함 (중요)

아래는 AIX 및 RHEL 환경에서 사용할 수 있는 공격 탐지 룰 파일입니다.

---

# 9.1 [📄](aix-auditd-attack-baseline.rules) **aix-auditd-attack-baseline.rules**

(IBM AIX 기본 공격 탐지 룰)

AIX Audit 구조(Class / Event 기반)에 맞추어 다음 Baseline 룰을 제공합니다.

```
# AIX ATTACK BASELINE RULESET
# File: aix-auditd-attack-baseline.rules

#####################################################################
# 1. LOGIN & AUTH
#####################################################################
classes:
    LOGIN:
        events = LG_su, LG_login, LG_passwd, LG_faillog
    AUTH1:
        events = AT_passwd, AT_loginchk
    AUTH2:
        events = AT_su, AT_rolechg

#####################################################################
# 2. PRIVILEGE ESCALATION
#####################################################################
classes:
    USER:
        events = US_su, US_sudo
    PROC_Create:
        events = P_Create
    CMD_Exec:
        events = C_Exec

#####################################################################
# 3. FILE ACCESS & INTEGRITY
#####################################################################
classes:
    FILE_Write:
        events = FW_create, FW_delete
    FS_Access:
        events = FS_perm

objects:
    critical_files:
        /etc/passwd
        /etc/shadow
        /etc/security/user
        /etc/hosts

#####################################################################
# 4. NETWORK EVENTS
#####################################################################
classes:
    NET:
        events = N_connect
    TCP:
        events = TCP_connect

#####################################################################
# 5. SYSTEM CONFIG MODIFICATION
#####################################################################
classes:
    RAS:
        events = R_change

#####################################################################
# 6. APPLY USERS
#####################################################################
users:
    root:
        auditclasses = LOGIN,AUTH1,AUTH2,USER,PROC_Create,CMD_Exec,FILE_Write,NET,RAS
    default:
        auditclasses = LOGIN,AUTH1
```

---

# 9.2 📄 **rhel-auditd-attack-deep.rules**

(RHEL Linux 고급 공격 탐지 룰)

Linux auditd는 보다 상세한 Deep 분석이 가능합니다.

```
# RHEL ATTACK DEEP RULESET
# File: rhel-auditd-attack-deep.rules

##############################
# 1. ACCOUNT / AUTH
##############################
-w /etc/passwd -p wa -k acct_change
-w /etc/shadow -p wa -k shadow_change
-w /var/log/secure -p rwa -k auth_log

##############################
# 2. PRIVILEGE ESCALATION
##############################
-w /usr/bin/sudo -p x -k sudo_exec
-a always,exit -F arch=b64 -S setuid -k setuid_calls
-a always,exit -F arch=b64 -S execve -C uid!=euid -k eop
-a always,exit -F arch=b64 -S execve -C uid=0 -k root_cmd

##############################
# 3. COMMAND EXECUTION
##############################
-a always,exit -F arch=b64 -S execve -k exec_log

##############################
# 4. NETWORK & REMOTE
##############################
-w /etc/ssh/sshd_config -p wa -k ssh_cfg
-a always,exit -F arch=b64 -S connect -k net_connect

##############################
# 5. FILE & SYSTEM MODIFICATION
##############################
-w /etc/sudoers -p wa -k sudoers_edit
-w /etc/crontab -p wa -k cron_edit
-w /etc/systemd/system -p wa -k systemd_edit

##############################
# 6. PERSISTENCE
##############################
-w /etc/rc.local -p wa -k rc_local
-w /root/.bashrc -p wa -k bashrc_mod

##############################
# 7. DATA EXFILTRATION
##############################
-a always,exit -F arch=b64 -S open -F dir=/etc -k etc_read
-a always,exit -F arch=b64 -S open -F dir=/home -k home_read

##############################
# 8. LOG TAMPERING
##############################
-w /var/log -p wa -k log_tamper
```

---

# 10. 📌 최종 구성 요약

```
AIX AUDIT → auditstream → logger(local6.notice) → syslog → 외부 수집 서버
```

*

AIX: **Baseline 공격 탐지 룰 적용**
RHEL: **Deep 공격 탐지 룰 적용**

---

# 11. 추가 지원 가능 항목

원하시면 다음 문서도 제작해 드립니다:

✅ AIX 보안 설정 자동 점검 스크립트
✅ AIX Audit → JSON 변환 파서
✅ RHEL auditd 고급 룰셋(전체 MITRE 매핑)
✅ PLURA-XDR 포렌식용 룰 최적화 버전
✅ 고객사 제출용 PDF 설명서
