## **1回省 SYSTEM 계정으로 실행하는 방법**

### 🔹 Sysinternals PsExec 사용

1. [PsExec 다운로드](https://learn.microsoft.com/sysinternals/downloads/psexec) 후 압축 해제
   (예: `C:\tools\PsExec.exe`)

2. **관리자 권한 PowerShell 또는 CMD** 실행

3. SYSTEM 권한 PowerShell 열기:

   ```powershell
   C:\tools\PsExec.exe -i -s powershell.exe
   ```

   * `-i` : 현재 데스크톱에서 대화형 실행
   * `-s` : SYSTEM 계정으로 실행

4. 새로 열린 **SYSTEM 권한 PowerShell 창**에서 스크립트 실행:

   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File "C:\temp\Set-HoneypotAudit.ps1" -TargetUser harry
   ```

---
