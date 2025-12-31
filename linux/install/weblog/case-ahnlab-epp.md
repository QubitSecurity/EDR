아래 절차를 진행하여 주십시오:

---

## 1. `plura.conf` 찾기

```bash
find / -type f -name "plura.conf" 2>/dev/null
```

출력된 경로를 확인하세요.

---

## 2. `plura.conf` 이동 (방법 B 경로)

```bash
# 예: 기존 위치가 /etc/nginx/conf.d/plura.conf 인 경우
mv /etc/nginx/conf.d/plura.conf /opt/ahnlab/epp/service/nginx/conf/plura.conf
```

---

## 3. nginx.conf에 include 확인

`/opt/ahnlab/epp/service/nginx/conf/nginx.conf` 의 `http { ... }` 블록 안에 다음이 있는지 확인:

```nginx
include /opt/ahnlab/epp/service/nginx/conf/plura.conf;
```

없으면 추가합니다.

---

## 4. graceful reload

```bash
/opt/ahnlab/epp/service/nginx/sbin/nginx -s reload
```

> reload는 연결을 끊지 않고 설정만 다시 읽어옵니다.

---

## 5. 웹로그 확인

```bash
tail -f /var/log/plura/weblog.log
```

또는 마지막 50줄만 확인하려면:

```bash
tail -n 50 /var/log/plura/weblog.log
```

---
