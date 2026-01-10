# 📄 PLURA V6 · Rocky Linux 9

## audit.log → ceelog 통합 수집 **최소 설치 가이드**

*(audisp-syslog 방식)*

> 🎯 목적
> Linux audit 이벤트를 **ceelog로 통합 수집**하여 PLURA-XDR로 전송
> ceelog에서는 아래 기준으로 구분
>
> ```json
> "programname": "audisp-syslog",
> "syslogtag": "audisp-syslog:"
> ```

---

## 0. 전제 조건

* OS: **Rocky Linux 9**
* rsyslog + PLURA ceelog 템플릿 사용 중
* 다음 파일이 이미 존재

  * `/etc/rsyslog.d/77-plura.conf`
  * `/etc/rsyslog.d/99-plura.conf`
* PLURA Agent 설치 완료

---

## 1. 필수 패키지 설치 (이것이 핵심)

```bash
dnf install -y audispd-plugins
```

> ✔ 이 패키지가 없으면 **절대 동작하지 않음**

---

## 2. audisp-syslog 플러그인 설정

### 2-1. 디렉터리 생성

```bash
mkdir -p /etc/audisp/plugins.d
chmod 755 /etc/audisp/plugins.d
```

---

### 2-2. `/etc/audisp/plugins.d/syslog.conf` 생성

```bash
cat <<'EOF' > /etc/audisp/plugins.d/syslog.conf
# --- PLURA audisp syslog plugin ---
active = yes
direction = out
path = /sbin/audisp-syslog
type = always
args = LOG_INFO
format = string
EOF
```

확인:

```bash
cat /etc/audisp/plugins.d/syslog.conf
```

---

## 3. auditd dispatcher 설정

### `/etc/audit/auditd.conf`에 아래 항목이 **존재해야 함**

```ini
dispatcher = /sbin/audispd
disp_qos = lossy
q_depth = 2000
```

### 없을 경우 한 번만 추가

```bash
grep -q '^dispatcher' /etc/audit/auditd.conf || cat <<'EOF' >> /etc/audit/auditd.conf

# --- PLURA audit dispatcher ---
dispatcher = /sbin/audispd
disp_qos = lossy
q_depth = 2000
EOF
```

확인:

```bash
grep -E '^(dispatcher|disp_qos|q_depth)' /etc/audit/auditd.conf
```

---

## 4. 재부팅 (필수)

audisp 플러그인은 **auditd 시작 시에만 로드**됩니다.

```bash
reboot
```

---

## 5. 부팅 후 상태 확인

### 5-1. auditd / audisp-syslog 실행 확인

```bash
systemctl status auditd --no-pager
```

정상 예:

```text
├─ auditd
└─ audisp-syslog LOG_INFO
```

---

## 6. 동작 확인 (이게 끝)

### 6-1. audit 이벤트 발생

```bash
id >/dev/null
touch /tmp/audit-ceelog-test
```

---

### 6-2. ceelog 확인

```bash
grep '"programname":"audisp-syslog"' /var/log/plura/ceelog-127.0.0.1.log | tail -n 5
```

정상 예:

```json
{
  "programname": "audisp-syslog",
  "syslogtag": "audisp-syslog:",
  "msg": " type=SYSCALL msg=audit(…)"
}
```

✔ 요구사항 충족

---

## 7. 최종 데이터 흐름

```
auditd
 └─ /var/log/audit/audit.log      (원본 유지)
 └─ audisp-syslog
        ↓
     syslog (/dev/log)
        ↓
     rsyslog
        ↓
/var/log/plura/ceelog-*.log
   └─ programname = audisp-syslog
   └─ syslogtag   = audisp-syslog:
```

---

## 8. 하지 않는 것 (명시)

아래는 **설정하지 않음**.

* rsyslog imfile로 audit.log 읽기
* SELinux 정책 변경
* `/var/log/messages` 확인
* ceelog 포맷 수정

---

## 🎯 요약 (한 문장)

> **`audispd-plugins` 설치 후
> `audisp-syslog`를 활성화하면
> audit 이벤트는 `programname=audisp-syslog` 형태로 ceelog에 통합 수집된다.**

---
