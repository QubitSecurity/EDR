#!/bin/bash

auditctl -W /etc/passwd -p wa -k qubit-passwd
auditctl -W /etc/shadow -p wa -k qubit-shadow
auditctl -W /usr/sbin/useradd -p x -k qubit-useradd
auditctl -W /usr/bin/w -p x -k qubit-recon
auditctl -W /etc/localtime -p wa -k qubit-time
auditctl -W /etc/hosts -p wa -k qubit-host
auditctl -W /etc/selinux -p wa -k qubit-selinux
auditctl -W /etc/sysctl.conf -p wa -k qubit-kernel
auditctl -W /usr/bin/wget -p x -k qubit-wget
auditctl -W /usr/bin/curl -p x -k qubit-curl
auditctl -W /usr/bin/base64 -p x -k qubit-base64
auditctl -W /usr/bin/nc -p x -k qubit-nc
auditctl -W /usr/bin/ncat -p x -k qubit-nc
auditctl -W /usr/sbin/userdel -p x -k qubit-userdel
auditctl -W /usr/bin/whoami -p x -k qubit-recon
auditctl -W /etc/hosts -p w -k qubit_homepageforgery
