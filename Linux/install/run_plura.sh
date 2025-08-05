#!/bin/bash

set -e

echo "Switching to root user..."
sudo -s <<EOF

echo "Downloading and installing PLURA agent..."
curl -sSL https://repo.plura.io/v5/agent/linux/install.sh | bash

# 라이선스 키 입력 (여기를 실제 키로 바꾸세요)
LICENSE_KEY="YOUR_LICENSE_KEY_HERE"

echo "Registering agent with license key..."
plura register "$LICENSE_KEY"

echo "Checking agent installation version..."
/usr/sbin/plurad -version

echo "Installation complete."

EOF
