# 실제 존재 여부 확인 방법

PowerShell에서 확인하면 됩니다.

```powershell
Get-Command CiTool.exe
```

또는

```powershell
Test-Path C:\Windows\System32\CiTool.exe
```

TRUE 나오면 사용 가능합니다.

---

# 정상 설치된 경우 위치

```text
C:\Windows\System32\CiTool.exe
```

---

# 동작 테스트

```powershell
CiTool.exe --list-policies
```

정상이라면 예:

```text
Active Policies:
{GUID}
Policy Name: WDAC Policy
Policy Status: Enabled
```

---
