# ModPlura-Apache

# 설치 정보 수집

### 프로세스 검사

- 마스터 프로세스의 개수 → 멀티 인스턴스 여부 확인
- 마스터 프로세스의 사용자 → root가 아닌 경우도 있음
- 마스터 프로세스의 실행 파일 → 실행 중인 프로세스의 실행 파일, ex) /usr/ local/apache/bin/httpd

```bash
# 1. 프로세스 이름으로 PID 찾기
# 2. 부모 PID($3)가 1(init/systemd)인 것 필터링
# 3. 만약 일반 사용자가 실행했다면 해당 사용자 이름이 나올 것임
ps -ef | grep -E 'httpd|apache2' | awk '$3 == 1 {print "Master PID:", $2, " | User:", $1, " | Command:", $8}'
```

### 설정 파일 위치

```bash
/usr/sbin/httpd -V | grep -E 'HTTPD_ROOT|SERVER_CONFIG_FILE'
```

→ HTTPD_ROOT="/etc/httpd"

→ SERVER_CONFIG_FILE="conf/httpd.conf"

SERVER_CONFIG_FILE 경로가 상대 경로라면, HTTPD_ROOT 기준

⇒ $HTTPD_ROOT/$SERVER_CONFIG_FILE=/etc/httpd/conf/httpd.conf

- 실패 시 대안

```bash
# 해당 프로세스가 열고 있는 모든 파일 중 .conf 찾기
ls -l /proc/$PID/fd | xargs -I{} readlink {} | grep ".conf"
```

# 설정 릴로드 명령

**kill -HUP (SIGHUB) $MPID**

→ 진행 중인 연결을 끊지 않으면서 설정 파일만 다시 읽고 자식 프로세스들을 갱신

⇒ service reload와 동일

```bash
#!/bin/bash

# 1. 실행 중인 마스터 프로세스의 경로와 PID 찾기
TARGET_PROCESS=$(ps -ef | grep -E 'httpd|apache2' | grep -v grep | awk '$3 == 1 {print $8, $2}')
HTTPD_PATH=$(echo $TARGET_PROCESS | awk '{print $1}')
MASTER_PID=$(echo $TARGET_PROCESS | awk '{print $2}')

if [ -z "$MASTER_PID" ]; then
    echo "❌ 실행 중인 아파치 프로세스를 찾을 수 없습니다."
    exit 1
fi

echo "🔍 발견된 마스터 PID: $MASTER_PID ($HTTPD_PATH)"

# 2. 설정 파일 문법 검사 (-t 옵션)
echo "Check syntax..."
$HTTPD_PATH -t > /dev/null 2>&1

if [ $? -eq 0 ]; then
    # 3. 문법이 정상일 때만 릴로드 실행
    sudo kill -HUP $MASTER_PID
    echo "✅ 아파치 설정이 성공적으로 릴로드되었습니다."
else
    echo "❌ 설정 파일에 오류가 있습니다! '$HTTPD_PATH -t' 로 확인하세요."
    exit 1
fi
```
