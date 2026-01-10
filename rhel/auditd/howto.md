> 🎯 설명서
> **`audit.log`의 감사 이벤트를 ceelog로 통합 전송**
> ceelog에서는 아래로 구분
>
> ```json
> "programname": "audisp-syslog",
> "syslogtag": "audisp-syslog:"
> ```

아래는 **Rocky Linux 9 기준, 재현 가능한 정답 설정**입니다.

---

# ✅ audit.log → ceelog (audisp-syslog 방식)

## **최소 수동 설정 가이드**

---

## 0️⃣ 전제 조건

* OS: Rocky Linux 9
* audit / auditd / audispd-plugins 설치됨
* rsyslog + PLURA ceelog 템플릿 사용 중
* `/etc/rsyslog.d/77-plura.conf`, `99-plura.conf` 존재

---

## 1️⃣ audisp-syslog 플러그인 활성화 (핵심)

### 📄 `/etc/audit/plugins.d/syslog.conf`

```ini
active = yes
direction = out
path = /sbin/audisp-syslog
type = always
args = LOG_INFO
format = string
```

의미:

* auditd → dispatcher → **audisp-syslog 실행**
* 모든 audit 이벤트를 문자열로 syslog로 전달

---

# 1️⃣ `/etc/audisp/plugins.d/` 디렉터리 생성

Rocky Linux 9에서 **패키지 최소 설치 상태**면 이 디렉터리가 없는 게 정상입니다.
먼저 디렉터리부터 만듭니다.

```bash
mkdir -p /etc/audisp/plugins.d
chmod 755 /etc/audisp/plugins.d
```

---

# 2️⃣ `/etc/audisp/plugins.d/syslog.conf` 생성 (핵심)

아래를 **그대로 한 번에 실행**하세요.

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


---


## 2️⃣ auditd dispatcher 활성화 확인

### 📄 `/etc/audit/auditd.conf`

아래 항목이 **존재해야 합니다**.

```ini
dispatcher = /sbin/audispd
disp_qos = lossy
q_depth = 2000
```

삽입:

```bash
AUDIT_CONF="/etc/audit/auditd.conf"

# dispatcher 설정
if grep -qE '^[[:space:]]*dispatcher[[:space:]]*=' "$AUDIT_CONF"; then
    sed -i 's|^[[:space:]]*dispatcher[[:space:]]*=.*|dispatcher = /sbin/audispd|' "$AUDIT_CONF"
else
    echo 'dispatcher = /sbin/audispd' >> "$AUDIT_CONF"
fi

# disp_qos 설정
if grep -qE '^[[:space:]]*disp_qos[[:space:]]*=' "$AUDIT_CONF"; then
    sed -i 's|^[[:space:]]*disp_qos[[:space:]]*=.*|disp_qos = lossy|' "$AUDIT_CONF"
else
    echo 'disp_qos = lossy' >> "$AUDIT_CONF"
fi
```

또는

삽입:

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

## 3️⃣ auditd 재기동 (Rocky 9 필수)

Rocky 9에서는 **dispatcher 설정 변경 시 재부팅이 가장 확실**합니다.

```bash
reboot
```

부팅 후 확인:

```bash
systemctl status auditd
```

정상 예:

```text
├─ auditd
└─ audisp-syslog LOG_INFO
```

---

## 4️⃣ rsyslog 설정 (PLURA ceelog은 그대로 사용)

이미 사용 중인 설정 그대로 두면 됩니다.

### 📄 `/etc/rsyslog.d/77-plura.conf`

* CEETemplate 정의 (수정 ❌)

### 📄 `/etc/rsyslog.d/99-plura.conf`

```conf
$template DynaFile,"/var/log/plura/ceelog-%FROMHOST-IP%.log"
*.* -?DynaFile;CEETemplate
```

👉 **audisp-syslog에서 나온 syslog 이벤트는 자동으로 ceelog에 기록됨**

---

## 5️⃣ 동작 확인 (이게 끝)

### 5-1. audit 이벤트 발생

```bash
id >/dev/null
touch /tmp/audit-ceelog-test
```

### 5-2. ceelog 확인

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

👉 **요구사항 충족**

---

## 6️⃣ 최종 데이터 흐름 (요청하신 그대로)

```
auditd
 └─ /var/log/audit/audit.log        (원본 유지)
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

## 7️⃣ 의도적으로 하지 않는 것

아래는 **전부 불필요**합니다.

* rsyslog imfile로 audit.log 읽기
* SELinux 정책 변경
* audit 이벤트를 `/var/log/messages`에서 확인
* ceelog에 직접 가공 필드 추가

---

## 🎯 최종 요약 (한 문장)

> **`audisp-syslog`를 통해 audit 이벤트를 syslog로 흘리고,
> rsyslog의 PLURA ceelog 템플릿으로 받아
> `programname=audisp-syslog` 형태로 통합 수집하면 됩니다.**

---


