# Sysmon ID 27 예외 처리 방법 (WinSCP 예시)

## 1. 예외 규칙 추가 위치

`d-sysmon-27-plura.xml` 파일에서 아래 위치를 찾습니다.

```xml
<RuleGroup name="Exclude_LegitActivity_Desktop" groupRelation="or">
  <FileBlockExecutable onmatch="exclude">
    ...
    <!-- (20) BITS tmp 파일 -->
    <Rule groupRelation="and">
      <Image condition="is">C:\WINDOWS\System32\svchost.exe</Image>
      <TargetFilename condition="contains">\AppData\Local\Temp\BIT\</TargetFilename>
    </Rule>

    <!-- (21) WinSCP 설치 프로그램 예외 -->  ← 여기부터 추가
    ...
  </FileBlockExecutable>
</RuleGroup>
````

## 2. WinSCP 설치 예외 규칙 추가

위 주석(`<!-- (21) WinSCP 설치 프로그램 예외 -->`) 아래에 다음 내용을 그대로 붙여 넣습니다.

```xml
<!-- (21) WinSCP 설치 프로그램 예외 -->
<!-- 1단계: 설치 exe가 Temp 아래로 파일을 풀어낼 때 허용 -->
<Rule groupRelation="and">
  <!-- 다운로드 폴더에서 실행되는 WinSCP 설치 파일 -->
  <Image condition="end with">WinSCP-6.5.5-Setup.exe</Image>
  <!-- 이 설치 파일이 AppData\Local\Temp 아래에 뭔가를 만들 때는 허용 -->
  <TargetFilename condition="contains">\AppData\Local\Temp\</TargetFilename>
</Rule>

<!-- 2단계: Inno Setup가 만드는 is-xxxx.tmp 폴더 내 실행 허용 -->
<Rule groupRelation="and">
  <Image condition="contains">WinSCP</Image>
  <TargetFilename condition="contains">\AppData\Local\Temp\is-</TargetFilename>
</Rule>
```

※ 다른 프로그램을 예외 처리할 때는
`WinSCP-6.5.5-Setup.exe`, `WinSCP` 부분을 해당 프로그램 이름으로만 바꾸면 됩니다.

## 3. 설정 적용 방법

관리자 권한 CMD 또는 PowerShell에서 실행합니다.

```cmd
Sysmon64.exe -c d-sysmon-27-plura.xml
```

오류 메시지가 없으면 설정이 정상 반영된 것입니다.

## 4. 예외 해제 방법

이 예외를 다시 막고 싶으면, 위에서 추가한

```xml
<!-- (21) WinSCP 설치 프로그램 예외 -->
...
```

두 개의 `<Rule>` 블록 전체를 삭제하거나 주석 처리한 뒤,
다시 한 번 아래 명령으로 설정을 적용합니다.

```cmd
Sysmon64.exe -c d-sysmon-27-plura.xml
```

---
