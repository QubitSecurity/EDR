Strict에만 추가로 들어간 18개(= Curated에선 제외했던 것)
- 아래 18개가 Strict에서만 포함됩니다.
AppInstaller.exe
Cmd.exe
Conhost.exe
Csc.exe
Cscript.exe
CustomShellHost.exe
Ilasm.exe
Jsc.exe
Msbuild.exe
Msedge.exe
Msiexec.exe
OneDriveStandaloneUpdater.exe
Wscript.exe
msedge_proxy.exe
msedgewebview2.exe
vbc.exe
winget.exe
wt.exe

왜 이 18개를 Curated에서 뺐나? (운영 관점)
- 이 18개는 서버 환경에서 정상 업무/운영 작업에도 등장 빈도가 높거나, 또는 차단 시 영향이 큰 편이라 Curated에서 일부러 제외한 것입니다.

(A) “운영/자동화에서 너무 흔한” 계열
- Cmd.exe, Conhost.exe, Cscript.exe, Wscript.exe
서버 운영/배치/로그온 스크립트/에이전트 설치/유지보수에서 흔함
Strict는 이들이 Temp/ProgramData 등에 PE를 떨어뜨리는 흐름을 더 강하게 막지만,
반대로 정상 설치/업데이트가 PE를 임시로 풀어놓는 작업도 같이 막을 확률이 커집니다.

(B) “개발/빌드/컴파일 도구” 계열
- Msbuild.exe, Csc.exe, vbc.exe, Ilasm.exe, Jsc.exe
공격자도 악용하지만(LOLBIN 특성),
서버에서 배포/빌드/에이전트 업데이트 등과 섞이면 오탐/업무영향이 생길 수 있어 Curated에서 제외하는 경우가 많습니다.

(C) “브라우저/패키지/앱 설치” 계열
- Msedge.exe, msedge_proxy.exe, msedgewebview2.exe, AppInstaller.exe, winget.exe, wt.exe
서버에서 “사람이 직접 브라우징/winget 설치”를 거의 안 하면 Strict 적용이 효과적일 수 있지만,
반대로 관리 서버/점프 서버에서 이 도구를 쓰는 조직이면 차단 이벤트가 많이 발생할 수 있습니다.

(D) 설치/업데이트 관련
- Msiexec.exe, OneDriveStandaloneUpdater.exe
정상 패치/업데이트/에이전트 설치와 겹칠 가능성이 있습니다.
