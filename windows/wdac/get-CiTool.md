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

속도 체크:

```powershell
Measure-Command { powershell.exe -ExecutionPolicy Bypass -File .\wd-wdac-light-ultrafast.ps1 -PostRunWaitSeconds 0 } | Select-Object TotalSeconds
```

```text
PS C:\WINDOWS\system32> tasklist /svc /fi "imagename eq PluraService.exe"

이미지 이름                    PID 서비스
========================= ======== ============================================
PluraService.exe              3384 PLURA
PS C:\WINDOWS\system32>
PS C:\WINDOWS\system32> sc.exe sidtype  Plura unrestricted
[SC] ChangeServiceConfig2 성공
PS C:\WINDOWS\system32>
PS C:\WINDOWS\system32> sc.exe showsid PLURA

이름: PLURA
서비스 SID: S-1-5-80-3427437279-2399216130-3600404540-2081304160-213528526
상태: 활성
PS C:\WINDOWS\system32>
```

---
