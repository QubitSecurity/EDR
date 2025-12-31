## BPFDoor 악성코드 탐지 스크립트 (Linux)
**bpfdoor_check-v1.5 (rev6)**

PLURA-Forensic 기준에 맞춘 **Linux BPFDoor(Backdoor) 의심 징후 점검 스크립트**입니다.  
기본 동작은 **로그 파일을 생성하지 않으며**, 실행 결과는 **표준 출력(stdout)** 으로만 제공합니다.  
(필요 시에만 `-o` 옵션으로 출력 내용을 파일로 tee 할 수 있습니다.)

> 본 문서는 PLURA-Forensic 스타일의 README(“로그 미생성/표준 출력/노이즈 억제/탐지 시 증적 자동 조회/Exit Code”) 구성과 철학을 참고하여 작성했습니다. :contentReference[oaicite:1]{index=1}

---

## 📌 주요 특징

- ✅ **YARA 미사용 (YARA-free)**
- ✅ **기본 로그 파일 생성 없음** (stdout 출력만)
- ✅ **탐지 여부와 무관하게 항상 헤더/요약 블록 출력**
- ✅ **노이즈 억제(Baseline 흡수) 정책 기본 적용**
  - 정상적인 시스템 데몬이 BPF를 사용하는 케이스를 **내장(builtin) baseline 규칙으로 자동 흡수**
- ✅ **탐지 시 추가 증적 자동 조회**
  - BPF 근거(`ss -0pb`에서 해당 PID 라인 캡처)
  - KISA 매직 시퀀스(숫자) 존재 여부(전역/프로세스별)
  - `/proc/<pid>/environ` 기반 ENV 조작 흔적 점검
  - 실행파일 경로/sha256
  - (RHEL/CentOS 계열) `rpm -qf`, `rpm -V` 기반 무결성 검증
  - (옵션) `strings` 기반 IOC(문자열) 빠른 확인

---

## 🔍 점검 대상

본 스크립트는 BPFDoor에서 자주 언급되는 징후를 **행위/아티팩트 기반**으로 점검합니다.

1. **BPF 사용 프로세스 탐지**
   - `ss -0pb` 출력에서 `pid=<PID>`를 추출하여 “BPF 사용(또는 BPF 필터 연결) 프로세스”를 식별

2. **BPF 매직 시퀀스(수치) 탐지**
   - `ss -0pb` 출력 내에 특정 수치(매직 시퀀스)가 존재하는지 확인  
   - (전역) `magic_dec_present`, `magic_hex_present`  
   - (PID별) `magic_in_pid`

3. **환경변수 조작(은닉) 탐지**
   - 아래 3개가 **동시에 존재하는 프로세스**를 탐지
     - `HOME=/tmp`
     - `HISTFILE=/dev/null`
     - `MYSQL_HISTFILE=/dev/null`

4. **실행파일/무결성/증거 수집**
   - `/proc/<PID>/exe`, `readlink -f`
   - sha256 (`sha256sum`)
   - (RHEL/CentOS) rpm 소유/검증 결과

---

## 🚀 실행 방법

### 1) root 권한으로 실행 (권장)

```bash
sudo bash bpfdoor_check-v1.5.sh
````

> `/proc/<pid>/environ` 접근 및 `ss -0pb` 결과 확보를 위해 root 실행을 권장합니다.

---

## 📤 출력 형식

### 1) 기본 출력(사람이 읽기 좋은 리포트)

* 상단 헤더(호스트/커널/버전)
* 점검 상태(BPF/ENV/STRINGS/VERIFY/BASELINE)
* PID별 근거 블록
* 요약/종료 코드 정책

#### ▶ 케이스 A: 탐지 없음 (예시)

```text
Result: No findings (BPF/ENV indicators not detected).
(exit 0)
```

#### ▶ 케이스 B: Baseline-only (정상 흡수) (예시)

```text
----- PID 950 | severity_raw=MED | severity_final=LOW | score=40 | baseline=1 (builtin) -----
reasons : BPF_ACTIVE
...
Result: Baseline-only findings detected (1 PID(s)) -> treated as NORMAL (exit 0)
```

#### ▶ 케이스 C: Actionable findings (조치 필요 가능) (예시)

```text
Result: Actionable findings detected (1 PID(s)); baseline=0
(exit 1)
```

---

### 2) PLURA 수집/파싱용 출력 (`--plura`)

```bash
sudo bash bpfdoor_check-v1.5.sh --plura
```

* **1라인 1레코드(logfmt 유사 `key=value`)** 로 출력됩니다.
* 값에 공백이 있으면 `key="..."` 형태로 자동 quoting 됩니다.
* `plura_event=header|finding|summary` 로 레코드 유형이 구분됩니다.

#### 핵심 필드(요약)

* 공통: `plura_schema`, `plura_event`, `tool`, `run_id`, `ts`, `host`, `version`, `revision`
* finding: `pid`, `severity`, `severity_final`, `score`, `reasons`, `comm`, `exe`, `exe_real`, `sha256`
* 검증(A/B/C): `bpf_line_count`, `bpf_ss`, `magic_in_pid`, `rpm_verify`, `rpm_pkg`, `rpm_v`
* Baseline: `baseline`, `baseline_source`, `baseline_match`, `actionable`
* summary: `findings`, `actionable_findings`, `baseline_findings`, `exit_code`

#### syslog로 흘려보내기(선택)

```bash
sudo bash bpfdoor_check-v1.5.sh --plura | while IFS= read -r line; do
  logger -t bpfdoor_check -- "$line"
done
```

---

## 🔕 기본 노이즈 억제(Baseline) 정책

allowlist 파일 없이도 운영 가능하도록 **내장(builtin) baseline 규칙**이 포함됩니다.

### Baseline이 적용되는 조건(요약)

* “약한 징후(weak-only)”만 존재해야 함
  예: `reasons=BPF_ACTIVE` 단독
* `magic_in_pid=0` 이어야 함
* `rpm_verify=clean` 이어야 함 (rpm 사용 가능한 환경 기준)
* 내장 규칙에 매칭되는 시스템 데몬일 것
  (기본 탑재: `NetworkManager`)

### Baseline 제어 옵션

* Baseline 흡수 비활성화(모든 결과를 조치대상으로 보고 싶을 때)

  ```bash
  sudo bash bpfdoor_check-v1.5.sh --no-baseline
  ```

* Baseline으로 분류된 finding 레코드 자체를 출력에서 제외

  ```bash
  sudo bash bpfdoor_check-v1.5.sh --suppress-baseline
  ```

---

## 🧩 Exit Code

| Exit Code | 의미                                                              |
| --------: | --------------------------------------------------------------- |
|       `0` | **Actionable 탐지 없음** (탐지 자체가 없거나, **baseline-only**로 흡수된 경우 포함) |
|       `1` | **Actionable 탐지 존재** (조사/대응 필요 가능성)                             |
|       `2` | 오류/실행 조건 불충족 (예: root가 아닌 상태로 실행)                               |

---

## 🧠 운영 가이드 (PLURA 기준)

* **운영 기본**

  * `sudo bash bpfdoor_check-v1.5.sh` (baseline 흡수 ON)
  * 또는 `--plura` 출력만 PLURA로 수집/검색

* **사고 분석**

  * `--no-baseline`으로 baseline 흡수 없이 원시 탐지 확인
  * 출력 결과 전체를 그대로 사건 분석/보고서에 증적(근거)로 첨부 가능

> 핵심은 “파일 스캔 엔진”보다, **행위/환경/무결성/근거 라인**을 한 번에 수집해 포렌식 판단을 빠르게 하는 것입니다.

---

## 📎 파일

* `bpfdoor_check-v1.5.sh`
* `README.md` (본 문서)

---

**PLURA-Forensic Philosophy**

> “로그는 남기지 않고,
> 분석에 필요한 모든 근거는
> 한 번의 실행 결과에 담는다.” 

---
