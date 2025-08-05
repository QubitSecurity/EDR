#!/bin/bash

set -e

echo https_proxy=$https_proxy

echo "Switching to root user..."
sudo -s <<EOF

echo "Downloading and installing PLURA agent..."
curl -sSL https://repo.plura.io/v5/agent/linux/install.sh | bash

echo "Registering agent with license key..."

# 라이선스 키 입력 (여기를 실제 키로 바꾸세요)
plura register "YOUR_LICENSE_KEY_HERE"

grep license= /etc/plura/conf/.license

echo "Checking agent installation version..."
/usr/local/sbin/plurad -version

#  웹로그 모듈 설치
plura install_weblog

echo "Installation complete."

ps -ef | grep plurad |grep -v grep

EOF
