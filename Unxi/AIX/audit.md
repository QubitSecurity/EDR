**AIX Audit 로그를 syslog로 외부 서버(예: PLURA-XDR, Elastic, Splunk, Syslog-ng 등)로 전송하는 표준 구성 절차**입니다.
현장에서 가장 안정적으로 동작하는 방식 기준으로 작성했습니다.

---

# 🛡️ AIX AUDIT → SYSLOG → 외부 서버 전송 설정 가이드

AIX Audit 로그를 외부로 보내는 방법은 크게 두 가지입니다.

---

# ✅ **방법 1 (권장): auditstream → syslog 파이프 방식**

AIX는 기본적으로 audit 로그를 **BIN → auditstream → syslog로 전달**할 수 있습니다.
가장 안정적이며, PLURA·SIEM 연동에 많이 쓰는 방식입니다.

---

# 1) auditstream에서 syslog로 이벤트 전송 설정

### 설정 파일 열기

```
vi /etc/security/audit/config
```

### 아래를 추가·수정합니다:

#### 🔧 stream 섹션 설정

```
streammode = on
streamcmds = /usr/sbin/auditstream | logger -p local6.notice
```

* `auditstream` → 실시간 audit 이벤트 출력
* `logger` → syslog 입력으로 전달
* `local6.notice` → syslog facility/priority (원하면 local0~local7 변경 가능)

### `bin` 섹션은 그대로 둡니다 (필요 시 보관용)

---

# 2) syslog.conf 에 외부 서버로 전송 추가

### syslog 설정 열기

```
vi /etc/syslog.conf
```

### 아래 추가

```
local6.notice    @<외부-로그-수집서버-IP>
```

또는 TCP 사용 시:

```
local6.notice    @@<외부-로그-수집서버-IP>
```

아카이브 로그도 남기고 싶다면:

```
local6.notice    /var/log/aix_audit.log
```

---

# 3) syslog 재기동

```
refresh -s syslogd
```

syslog 설정이 안 먹는 경우:

```
stopsrc -s syslogd
startsrc -s syslogd
```

---

# 4) audit subsystem 재기동

```
audit shutdown
audit start
```

---

# 5) 테스트

## Test A — login 실패

```
su wronguser
```

## Test B — 명령 실행

```
ls
touch testfile
```

## Test C — syslog 수신 확인

수신 서버에서:

```
tcpdump -nnA port 514
```

또는

```
journalctl -f
tail -f /var/log/messages
```

---

# 🔎 전송되는 로그 형태 예시

메시지는 대략 다음과 같이 전달됩니다:

```
Feb 20 11:32:01 aix01 root: AUDIT_EVENT PROC_Create pid=5411 user=root cmd=touch
```

PLURA, SIEM, ELK에서 쉽게 파싱 가능.

---

# 🧩 (선택) Facility/Severity 변경

원하는 경우 변경 가능:

* Facility: local0~local7
* Severity: debug/info/notice/warning/err/crit/alert/emerg

예)

```
logger -p local4.info
```

---

# 🧰 (선택) Syslog-ng 또는 rsyslog 설치 환경에서

AIX → syslog-ng 서버로 바로 전달 가능:

```
local6.notice    @syslog-ng-server:514
```

---

# 🛡️ (대안) 방법 2: auditpr → 파일 → syslog-forward 방식 (비권장)

BIN → auditpr → text 파일 → syslog 로 전송하는 구조
성능이 나빠서 보통 PLURA나 SIEM 환경에서는 거의 사용하지 않습니다.

필요 시 구성 방법도 알려드릴 수 있습니다.

---

# 📌 최종 권장 구성 요약

```
AIX AUDIT → auditstream → logger(local6.notice) → syslog → 외부 서버
```

✔ 안정적
✔ 성능 좋음
✔ SIEM/PLURA 연동 쉬움
✔ 실시간 가능

---

# 필요하시면 추가로 만들어드립니다

필요하면 다음도 제공 가능합니다:

✅ **AIX → PLURA 수집 최적화 syslog 템플릿**
✅ **AIX audit 로그 JSON 변환기 (awk/sed/perl)**
✅ **보안 솔루션용 로그 파서 규칙 작성**
✅ **CIS/AIX 보안 설정 자동 점검 스크립트(prod용)**

계속 설정할까요?
