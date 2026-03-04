#!/usr/bin/env bash
# apache-info-check.sh
# Collect Apache installation and runtime information

echo "===== Apache Web Server Information ====="

echo
echo "[1] Apache Process Check"
ps -ef | grep -E "httpd|apache2" | grep -v grep

echo
echo "[2] Apache Binary Location"
APACHE_BIN=$(which httpd 2>/dev/null || which apache2 2>/dev/null)

if [ -z "$APACHE_BIN" ]; then
    echo "Apache binary not found"
else
    echo "Binary Path : $APACHE_BIN"
fi

echo
echo "[3] Apache Version"
if [ -n "$APACHE_BIN" ]; then
    $APACHE_BIN -v
fi

echo
echo "[4] Apache Build Information"
if [ -n "$APACHE_BIN" ]; then
    $APACHE_BIN -V
fi

echo
echo "[5] Apache Configuration File"
if [ -n "$APACHE_BIN" ]; then
    $APACHE_BIN -V | grep SERVER_CONFIG_FILE
fi

echo
echo "[6] ServerRoot (Install Path)"
if [ -n "$APACHE_BIN" ]; then
    $APACHE_BIN -V | grep SERVER_ROOT
fi

echo
echo "[7] Apache Run User"
grep -E "User|Group" /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null

echo
echo "[8] DocumentRoot"
grep -R "DocumentRoot" /etc/httpd /etc/apache2 2>/dev/null

echo
echo "[9] Loaded Apache Modules"
if [ -n "$APACHE_BIN" ]; then
    $APACHE_BIN -M 2>/dev/null
fi

echo
echo "[10] Apache Package Information"

if command -v rpm >/dev/null 2>&1; then
    rpm -qa | grep -i httpd
fi

if command -v dpkg >/dev/null 2>&1; then
    dpkg -l | grep apache
fi

echo
echo "[11] Apache Listening Ports"
ss -lntp | grep -E "httpd|apache2"

echo
echo "===== END ====="
