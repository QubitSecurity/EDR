# First Install
PS C:\temp> powershell -ExecutionPolicy Bypass -File .\run-sysmon.ps1

# Download
PS C:\temp> powershell -ExecutionPolicy Bypass -File .\download-sysmon-xml.ps1 desktop/d-sysmon-plura-v3-merge-latest.xml
Downloading...
  URL : https://raw.githubusercontent.com/QubitSecurity/EDR/main/Windows/sysmon/desktop/d-sysmon-plura-v3-merge-latest.xml
  DEST: C:\Program Files\PLURA\desktop\d-sysmon-plura-v3-merge-latest.xml
OK: Download completed.


# Update
PS C:\temp> powershell -ExecutionPolicy Bypass -File .\sysmon-config-update.ps1 desktop/d-sysmon-plura-v3-merge-latest.xml
Applying Sysmon config: C:\Program Files\PLURA\desktop\d-sysmon-plura-v3-merge-latest.xml


System Monitor v15.14 - System activity monitor
By Mark Russinovich and Thomas Garnier
Copyright (C) 2014-2024 Microsoft Corporation
Using libxml2. libxml2 is Copyright (C) 1998-2012 Daniel Veillard. All Rights Reserved.
Sysinternals - www.sysinternals.com

Loading configuration file with schema version 5.00
Sysmon schema version: 4.90
Configuration file validated.
Configuration updated.
