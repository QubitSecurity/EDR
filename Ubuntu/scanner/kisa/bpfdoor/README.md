# BPFDoor 악성코드 탐지 스크립트 (Ubuntu/Debian)
**bpfdoor_check-ubuntu-v1.5 (2025-12-25-u1)**

PLURA-Forensic 기준에 맞춘 **Ubuntu/Debian 환경용 BPFDoor(Backdoor) 의심 징후 점검 스크립트**입니다.  
기본 동작은 **로그 파일을 생성하지 않으며**, 실행 결과는 **표준 출력(stdout)** 으로만 제공합니다.  
(필요 시에만 `-o` 옵션으로 출력 내용을 파일로 tee 할 수 있습니다.)

> 본 문서는 PLURA-Forensic 스타일 README(“로그 미생성/표준 출력/노이즈 억제/탐지 시 증적 자동 조회/Exit Code”) 구성을 참고하여 작성했습니다.

---

## 📌 주요 특징

- ✅ **YARA 미사용 (YARA-free)**
- ✅ **기본 로그 파일 생성 없음** (stdout 출력만)
- ✅ **탐지 시 추가 증적 자동 조회(A/B/C)**
  - A) BPF 매직 시퀀스(전역/프로세스별)
  - B) BPF 근거 라인(`ss -0pb`에서 해당 PID 라인 캡처)
  - C) **Ubuntu/Debian 패키지 무결성 검증(dpkg 기반)**  
- ✅ **노이즈 억제(Baseline 흡수) 기본 적용**
  - 정상 시스템 데몬이 BPF를 사용하는 케이스를 **내장(builtin) baseline**으로 자동 흡수
- ✅ **PLURA 수집/파싱용 출력 지원** (`--plura`, logfmt 유사 `key=value`)

---

## 🔍 점검 대상

본 스크립트는 BPFDoor에서 자주 언급되는 징후를 **행위/아티팩트 기반**으로 점검합니다.

1. **BPF 사용 프로세스 탐지**
   - `ss -0pb` 출력에서 `pid=<PID>`를 추출하여 BPF 사용 프로세스를 식별

2. **BPF 매직 시퀀스(수치) 탐지**
   - `ss -0pb` 출력 내 BPFDoor 의심 수치(매직 시퀀스) 존재 여부 확인  
   - (전역) `magic_dec_present`, `magic_hex_present`  
   - (PID별) `magic_in_pid`

3. **환경변수 조작(은닉) 탐지**
   - 아래 3개 환경변수가 **동시에 존재하는 프로세스** 탐지
     - `HOME=/tmp`
     - `HISTFILE=/dev/null`
     - `MYSQL_HISTFILE=/dev/null`

4. **실행파일/무결성/증거 수집**
   - `/proc/<PID>/exe`, `readlink -f`
   - sha256 (`sha256sum`)
   - **Ubuntu/Debian: dpkg-query / dpkg -V 기반 무결성 검증**

---

## 🚀 실행 방법

### 1) root 권한 실행(권장)

```bash
sudo bash bpfdoor_check-ubuntu-v1.5.sh
```

> `/proc/<pid>/environ` 접근 및 `ss -0pb` 결과 확보를 위해 root 실행을 권장합니다.

---

## 📤 출력 형식

### 1) 기본 출력(사람이 읽기 좋은 리포트)

- 상단 헤더(호스트/커널/버전)
- 점검 상태(BPF/ENV/STRINGS/VERIFY/BASELINE)
- PID별 근거 블록
- 요약/종료 코드 정책

#### ▶ 케이스 A: 탐지 없음

```text
Result: No findings (BPF/ENV indicators not detected).
(exit 0)
```

#### ▶ 케이스 B: Baseline-only (정상 흡수)

```text
----- PID <pid> | severity_raw=MED | severity_final=LOW | score=40 | baseline=1 (builtin) -----
reasons : BPF_ACTIVE
...
Result: Baseline-only findings detected (...) -> treated as NORMAL (exit 0)
```

#### ▶ 케이스 C: Actionable findings (조치 필요 가능)

```text
Result: Actionable findings detected (...); baseline=<n>
(exit 1)
```

---

### 2) PLURA 수집/파싱용 출력 (`--plura`)

```bash
sudo bash bpfdoor_check-ubuntu-v1.5.sh --plura
```

- **1라인 1레코드(logfmt 유사 `key=value`)** 로 출력됩니다.
- 값에 공백이 있으면 `key="..."` 형태로 자동 quoting 됩니다.
- `plura_event=header|finding|summary` 로 레코드 유형이 구분됩니다.

#### 핵심 필드(요약)

- 공통: `plura_schema`, `plura_event`, `tool`, `run_id`, `ts`, `host`, `version`, `revision`
- finding: `pid`, `severity`, `severity_final`, `score`, `reasons`, `comm`, `exe`, `exe_real`, `sha256`
- 검증(A/B/C): `bpf_line_count`, `bpf_ss`, `magic_in_pid`,
  - Ubuntu: `pkg_mgr=dpkg`, `pkg_verify`, `pkg`, `pkg_v`
- Baseline: `baseline`, `baseline_source`, `baseline_match`, `actionable`
- summary: `findings`, `actionable_findings`, `baseline_findings`, `exit_code`

#### syslog로 흘려보내기(선택)

```bash
sudo bash bpfdoor_check-ubuntu-v1.5.sh --plura | while IFS= read -r line; do
  logger -t bpfdoor_check -- "$line"
done
```

---

## 🔕 기본 노이즈 억제(Baseline) 정책

외부 allowlist 없이도 운영 가능하도록 **내장(builtin) baseline 규칙**이 포함됩니다.

### Baseline이 적용되는 조건(요약)

- “약한 징후(weak-only)”만 존재해야 함  
  예: `reasons=BPF_ACTIVE` 단독
- `magic_in_pid=0` 이어야 함
- **Ubuntu/Debian에서는 `pkg_verify=clean` 이어야 함** (dpkg 검증 clean)
- 내장 규칙에 매칭되는 시스템 데몬일 것  
  (기본 탑재: `NetworkManager` / `network-manager` 패키지)

### Baseline 제어 옵션

- Baseline 흡수 비활성화(모든 결과를 조치대상으로 보고 싶을 때)
  ```bash
  sudo bash bpfdoor_check-ubuntu-v1.5.sh --no-baseline
  ```

- Baseline으로 분류된 finding 레코드 자체를 출력에서 제외
  ```bash
  sudo bash bpfdoor_check-ubuntu-v1.5.sh --suppress-baseline
  ```

---

## 🧩 Exit Code

| Exit Code | 의미 |
|---:|---|
| `0` | **Actionable 탐지 없음** (탐지 자체가 없거나, **baseline-only**로 흡수된 경우 포함) |
| `1` | **Actionable 탐지 존재** (조사/대응 필요 가능성) |
| `2` | 오류/실행 조건 불충족 (예: root가 아닌 상태로 실행) |

---

## 🆚 RHEL/CentOS 버전과의 차이점

Ubuntu/Debian 버전은 기능/출력 철학은 동일하지만, **패키지 관리/무결성 검증(C)** 이 다릅니다.

### 1) 패키지 소유/무결성 검증(C) 차이

| 항목 | RHEL/CentOS 버전 | Ubuntu/Debian 버전 |
|---|---|---|
| 패키지 소유 확인 | `rpm -qf <exe_real>` | `dpkg-query -S <exe_real>` |
| 패키지 무결성 검증 | `rpm -V <pkg>` | `dpkg -V <pkg>` |
| 결과 필드 | `rpm_verify`, `rpm_pkg`, `rpm_v` | `pkg_verify`, `pkg`, `pkg_v` |
| baseline 게이트 | `rpm_verify=clean` | `pkg_verify=clean` |

> Ubuntu에서는 rpm 기반 검증이 불가능하므로, v1.5u는 **dpkg 기반**으로 동일 목적을 달성합니다.

### 2) baseline 내장 규칙 차이

- RHEL/CentOS: 보통 패키지명이 `NetworkManager-*`
- Ubuntu/Debian: 보통 패키지명이 `network-manager*`

따라서 Ubuntu 버전의 builtin baseline 규칙은 `pkg=network-manager*` 기반으로 동작합니다.

### 3) 설치/운영 차이(권장)

- Ubuntu에서 `ss`(iproute2), `strings`(binutils), `dpkg` 도구가 기본 제공되지 않는 최소 이미지일 수 있습니다.
  - `ss` 미존재 시 BPF 점검이 스킵됩니다.
  - `strings` 미존재 시 strings IOC 점검만 비활성화됩니다.

---

## 📎 파일

- `bpfdoor_check-ubuntu-v1.5.sh`
- `README.md` (본 문서)

---

**PLURA-Forensic Philosophy**

> “로그는 남기지 않고,  
> 분석에 필요한 모든 근거는  
> 한 번의 실행 결과에 담는다.” fileciteturn1file1L157-L162
