# SessionServices 채널

## 1) 전체 요약 테이블

**형식: `EventID / 채널명 / 의미`**

### 🔹 A. SessionServices

채널: `Microsoft-Windows-RemoteDesktopServices-SessionServices/Operational`

| EventID | 채널명                                   | 의미 (요약)                                                                           |
| ------: | ------------------------------------- | --------------------------------------------------------------------------------- |
|       2 | RemoteDesktopServices-SessionServices | RDP 디스플레이 컨트롤 모듈이 모니터 레이아웃 변경 실패 (멀티 모니터·해상도 관련 오류) ([terminal312.rssing.com][1]) |
|      21 | RemoteDesktopServices-SessionServices | RDP 세션 Logon 성공 (사용자·세션·IP 기반 RDP 로그인 기록) ([secuworld.tistory.com][2])            |
|      22 | RemoteDesktopServices-SessionServices | RDP Shell 시작 (실제 사용자 셸/바탕화면이 뜬 시점) ([secuworld.tistory.com][2])                   |
|      23 | RemoteDesktopServices-SessionServices | RDP Logoff 성공 (세션 종료) ([secuworld.tistory.com][2])                                |
|      24 | RemoteDesktopServices-SessionServices | RDP 세션 Disconnected (창 닫기·네트워크 끊김 등으로 세션 분리) ([secuworld.tistory.com][2])         |
|      25 | RemoteDesktopServices-SessionServices | RDP 세션 Reconnection 성공 (기존 세션으로 재연결) ([secuworld.tistory.com][2])                 |
|     104 | RemoteDesktopServices-SessionServices | RDP 관련 보안 디스크립터/설정 변경 감지(접속 권한·구성 변경 모니터링용) ([posts.specterops.io][3])            |

> 실무 팁: **21/22/23/24/25**만 잘 써도 “한 사용자 RDP 타임라인(접속–사용–종료)”을 SessionServices만으로도 꽤 복원할 수 있습니다.

---

### 🔹 B. LocalSessionManager (LSM)

채널: `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`

| EventID | 채널명                                  | 의미 (요약)                                                                                                          |
| ------: | ------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
|      21 | TerminalServices-LocalSessionManager | Remote Desktop Services: 세션 로그온 성공 (세션 ID, 사용자, 클라이언트 IP 포함) ([Cyber Triage][4])                                 |
|      22 | TerminalServices-LocalSessionManager | Shell start notification (셸 시작 알림 – 실제 인터랙티브 세션 시작 시점) ([Cyber Triage][4])                                       |
|      23 | TerminalServices-LocalSessionManager | 세션 Logoff 성공 (보통 Security 4634와 페어링) ([Cyber Triage][4])                                                         |
|      24 | TerminalServices-LocalSessionManager | 세션 Disconnected (사용자가 의도적으로 끊거나 네트워크 문제로 끊김) ([Cyber Triage][4])                                                 |
|      25 | TerminalServices-LocalSessionManager | 세션 Reconnection 성공 (끊어진 세션으로 다시 붙음) ([Cyber Triage][4])                                                          |
|      39 | TerminalServices-LocalSessionManager | “Session X has been disconnected by session Y” — 다른 세션이 강제로 끊음(관리자가 킥, 세션 강제 종료 상황 분석용) ([ponderthebits.com][5]) |
|      40 | TerminalServices-LocalSessionManager | 세션 Disconnect/Reconnect 사유 코드 포함 (정책, 타임아웃, 네트워크 에러 등 이유 분석에 중요) ([Cyber Triage][4])                             |

> 실무 팁: LSM은 **“세션 ID 축”으로 RDP 세션 타임라인을 잡는 핵심 채널**입니다. Security 4624/4634와 함께 세션ID·LogonID를 매칭하면 꽤 정교한 타임라인이 나옵니다.

---

### 🔹 C. RemoteConnectionManager (RCM)

채널: `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`

| EventID | 채널명                                      | 의미 (요약)                                                                                                                 |
| ------: | ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
|     261 | TerminalServices-RemoteConnectionManager | Listener RDP-Tcp가 새로운 연결을 수신 (RDP 연결 시도 감지용) ([NinjaOne][6])                                                            |
|    1149 | TerminalServices-RemoteConnectionManager | “Remote Desktop Services: User authentication succeeded” – 사용자/도메인/원격 IP까지 찍히는 **RDP 인증 성공** 이벤트 ([Microsoft Learn][7]) |
|    1056 | TerminalServices-RemoteConnectionManager | RD Session Host용 새 self-signed 인증서 생성 성공 (TLS용 서버 인증서) ([gradenegger.eu][8])                                            |
|    1057 | TerminalServices-RemoteConnectionManager | RD Session Host가 새 self-signed 인증서 생성 실패 – 상태 코드 '키 집합 없음' 등 인증서/키 스토어 문제 ([Microsoft Learn][9])                        |
|    1058 | TerminalServices-RemoteConnectionManager | RD Session Host가 새 self-signed 인증서 생성 실패 – 상태 코드 '이미 존재' 등 중복/구성 문제 ([Microsoft Learn][9])                              |

> 실무 팁:
>
> * **261 → 1149 → (LSM 21/22)** 순서로 보면 “TCP 연결 수신 → 사용자 인증 성공 → 세션 생성” 흐름을 복원할 수 있습니다.
> * 인증서 관련 1056/1057/1058은 **TLS 구성 오류로 인한 RDP 불가** 상황 디버깅에 중요합니다.

---

### 🔹 D. RdpCoreTS

채널: `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational`

| EventID | 채널명                             | 의미 (요약)                                                                                                                                       |
| ------: | ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
|      98 | RemoteDesktopServices-RdpCoreTS | TCP 연결이 정상적으로 설정됨 (핸드셰이크 완료) ([FRSecure][10])                                                                                                 |
|     131 | RemoteDesktopServices-RdpCoreTS | 서버가 클라이언트 `IP:PORT`로부터 새 TCP 연결 수락 — **RDP 접속 원격 IP를 가장 명확히 남기는 이벤트** ([Microsoft Learn][11])                                                 |
|     140 | RemoteDesktopServices-RdpCoreTS | “A connection from the client IP failed because the user name or password is not correct” → **RDP 인증 실패 + 소스 IP** 추적에 핵심 ([Server Fault][12]) |
|     142 | RemoteDesktopServices-RdpCoreTS | TCP socket READ 실패, error 64 – 네트워크 읽기 오류(갑작스런 끊김 등) ([Reddit][13])                                                                           |
|     143 | RemoteDesktopServices-RdpCoreTS | TCP socket WRITE 실패, error 64 – 네트워크 쓰기 오류 ([Reddit][13])                                                                                     |
|     226 | RemoteDesktopServices-RdpCoreTS | RDP_TCP: StateUnknown → Event_Disconnect 전이 중 오류 – 내부 RDP 상태 머신 문제(종종 불안정한 연결과 연관) ([Microsoft Learn][14])                                    |
|     227 | RemoteDesktopServices-RdpCoreTS | RemoteFX 모듈: CreateVirtualChannel 실패 (0xd0000001) – RemoteFX/가상 채널 관련 오류로 세션 품질/안정성 이슈 ([Microsoft Learn][15])                                |

> 실무 팁:
>
> * **131/98** → 네트워크 레벨에서 실제 RDP TCP 세션 성립 여부 확인
> * **140** → “브루트포스/암호 틀린 RDP 시도”의 IP를 깔끔하게 뽑는 데 최적
> * **142/143/226/227** → “RDP 자꾸 끊긴다” 상담 들어올 때, 네트워크/암호화/RemoteFX 쪽 장애 근거로 사용

---

## 2) 어떻게 쓰면 좋을지 (간단 가이드)

PLURA-Forensic / DB-EventID 쪽으로 연결하면:

* **세션 타임라인용(누가 언제 접속·사용·종료했는지)**

  * SessionServices + LocalSessionManager
  * EventID 21/22/23/24/25 + 39/40

* **인증/원격 IP·브루트포스 탐지**

  * RemoteConnectionManager 1149 (성공)
  * RdpCoreTS 140 (실패 + IP), 131 (TCP 수락 + IP)

* **장애/품질 이슈 분석용**

  * RdpCoreTS 98/131/142/143/226/227
  * RemoteConnectionManager 1056/1057/1058 (인증서 문제)


[1]: https://terminal312.rssing.com/chan-6668882/all_p739.html?utm_source=chatgpt.com "Forum Remote Desktop Services (Terminal Services)"
[2]: https://secuworld.tistory.com/17?utm_source=chatgpt.com "Log On-Off 내역 분석"
[3]: https://posts.specterops.io/security-descriptor-auditing-methodology-investigating-event-log-security-d64f4289965d?utm_source=chatgpt.com "Security Descriptor Auditing Methodology: Investigating Event ..."
[4]: https://www.cybertriage.com/artifact/terminalservices_localsessionmanager_log/?utm_source=chatgpt.com "Windows Terminal Services - Local Session Manager Log"
[5]: https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/?utm_source=chatgpt.com "Windows RDP-Related Event Logs: Identification, Tracking, ..."
[6]: https://www.ninjaone.com/blog/monitor-for-unexpected-rdp-sessions/?utm_source=chatgpt.com "How to Monitor for Unexpected RDP Sessions"
[7]: https://learn.microsoft.com/en-us/answers/questions/194082/rdp-logon-fails-observing-error-an-error-occurred?utm_source=chatgpt.com "RDP logon fails - observing error \"An error occurred when ..."
[8]: https://www.gradenegger.eu/en/details-of-the-event-with-id-1056-of-the-source-microsoft-windows-terminal-services-remote-connection-manager/?utm_source=chatgpt.com "Details of event with ID 1056 of source Microsoft-Windows- ..."
[9]: https://learn.microsoft.com/ko-kr/troubleshoot/azure/virtual-machines/windows/event-id-troubleshoot-vm-rdp-connecton?utm_source=chatgpt.com "이벤트 ID로 Azure VM RDP 연결 문제 해결 - Virtual Machines"
[10]: https://frsecure.com/blog/rdp-connection-event-logs/?utm_source=chatgpt.com "Making Sense of RDP Connection Event Logs"
[11]: https://learn.microsoft.com/en-us/answers/questions/1695930/intermittent-rds-connection-issue?utm_source=chatgpt.com "Intermittent RDS Connection Issue - Microsoft Q&A"
[12]: https://serverfault.com/questions/721362/how-to-log-the-ip-that-connects-from-outside-of-company-to-terminal-server?utm_source=chatgpt.com "How to log the IP that connects from outside of company ..."
[13]: https://www.reddit.com/r/msp/comments/1b8v5e0/rdp_issue_between_client_sites/?utm_source=chatgpt.com "RDP issue between client sites : r/msp"
[14]: https://learn.microsoft.com/en-us/answers/questions/1023115/windows-server-2022-remote-desktop-disconnects-bri?utm_source=chatgpt.com "Windows Server 2022: Remote Desktop disconnects briefly ..."
[15]: https://learn.microsoft.com/en-us/answers/questions/459568/windows-2019-server-rds-disconnecting-with-error-2?utm_source=chatgpt.com "Windows 2019 server RDS disconnecting with error 227"
