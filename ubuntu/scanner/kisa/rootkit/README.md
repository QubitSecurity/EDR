# 루트킷 점검 스크립트 (Ubuntu/Debian)
**rootkit_detect_scanner_ubuntu_v1.0u (2025-12-25-u1)**

PLURA-Forensic 기준에 맞춘 **Ubuntu/Debian 환경용 루트킷/백도어 의심 징후 점검 스크립트**입니다.  
기본 동작은 **로그 파일을 자동 생성하지 않으며**, 실행 결과는 **표준 출력(stdout)** 으로만 제공합니다.  
(필요 시 `-o/--output` 옵션으로 출력 내용을 파일로도 저장할 수 있습니다.)

> 본 README는 Ubuntu용 스크립트(`rootkit_detect_scanner_ubuntu_v1.0u.sh`) 동작/옵션/출력/Exit Code를 기준으로 작성되었습니다.

---

## ✅ 주요 특징

- ✅ **Ubuntu/Debian 최적화**
  - `/etc/os-release`, `/etc/lsb-release`, `/etc/debian_version` 기반 OS 표시
  - systemd + runlevel 디렉토리(예: `/etc/systemd/system/`, `/etc/rc*.d/`) 스캔
- ✅ **Raw 디렉터리 엔트리 비교 기반 “Hidden Entry” 탐지**
  - 파일시스템 메타데이터 목록 vs `ls -a` 결과 비교로 숨김 엔트리 의심 검출
- ✅ **탐지 시 자동 추가 분석**
  - 숨김 엔트리 파일/모듈 파일의 mtime/ctime/MD5/SHA256 출력
  - `insmod` 문자열 기반 모듈 경로 추출 → 의심 모듈 후보로 등록
  - (가능 시) `objdump/readelf`로 `/proc` 엔트리/`call_usermodehelper` 백도어 경로 추정
- ✅ **로그 파일 자동 생성 없음**
  - 운영 시스템에서 불필요한 파일 생성 최소화
  - 필요할 때만 `-o`로 저장
- ✅ **PLURA 수집/파싱용 출력 지원**
  - `--plura` : logfmt 유사 `key=value` 레코드 출력

---

## 🎯 점검 범위

### 1) Hidden Entry (숨김 엔트리) 탐지
각 대상 디렉터리에서:

- **FS 메타데이터 목록(FS_LIST)**: 파일시스템 도구로 inode 디렉터리 엔트리 열거
- **ls 목록(LS_LIST)**: `ls -a`로 열거되는 사용자 가시 목록
- `FS_LIST - LS_LIST` 차집합이 존재하면 **Hidden Entry 의심**으로 처리

> 이 방식은 “유저랜드에서 숨김 처리된 파일” 또는 “파일시스템 수준/루트킷 개입” 의심 상황에서 유용합니다.

### 2) Rootkit module (insmod 기반) 의심 모듈 탐지
Hidden Entry 파일(또는 옵션에 따라 일반 파일)에서 `strings`로 `insmod` 흔적을 찾고, 모듈 경로를 추출합니다.

- 모듈 후보가 발견되면 **Suspicious Rootkit Found**로 분류
- 모듈 내부 `strings`에서 경로/URL 형태 문자열을 찾아 **Backdoor Indicator**로 분류(추가 IOC)

### 3) Rootkit 모듈 추가 분석(가능할 때)
아래 도구가 존재할 때만 수행합니다.

- `strings`, `objdump`, `readelf`, `dd`
- `/proc` 엔트리 생성 함수(예: `proc_create`) 주변 `.rodata` 문자열 추정
- `call_usermodehelper` 주변에서 **비정상 실행 경로** 추정(예: `/dev/shm/...`)

---

## 🧰 요구사항(도구/패키지)

이 스크립트는 “도구가 없으면 해당 파일시스템 스캔을 **skip**”합니다.  
따라서 최소 설치 환경에서는 **스캔 커버리지가 0일 수 있습니다.**

### 파일시스템별 raw 스캔 도구
- ext2/3/4: `debugfs` → 패키지: `e2fsprogs`
- xfs: `xfs_db` → 패키지: `xfsprogs`
- btrfs: `btrfs` → 패키지: `btrfs-progs`

### 모듈 분석 도구(선택)
- `strings`, `objdump`, `readelf` → 패키지: `binutils`

---

## 🚀 실행 방법

### 1) 기본 실행(권장)
```bash
sudo bash rootkit_detect_scanner_ubuntu_v1.0u.sh
```

### 2) 출력 파일 저장(선택)
```bash
sudo bash rootkit_detect_scanner_ubuntu_v1.0u.sh -o /var/log/rootkit_scan.log
```

### 3) PLURA 수집/파싱용 출력
```bash
sudo bash rootkit_detect_scanner_ubuntu_v1.0u.sh --plura
```

---

## 📤 출력 형식

### 1) 기본 출력(text)
- System Information(호스트/커널/OS)
- 디렉터리별 스캔 상태
- Hidden/Rootkit/Backdoor 결과 요약
- Scan Coverage(스캔 성공/스킵 수) 출력

> **중요:** Raw 스캔 도구가 없어 대부분 스킵된 경우, “깨끗함”으로 오해하지 않도록 **Scan Coverage를 반드시 확인**하세요.

### 2) `--plura` 출력(logfmt 유사)
`plura_event=header|finding|summary` 3종으로 레코드가 구분됩니다.

#### 예시 필드
- header: `host`, `ip`, `kernel`, `os`, `version`, `revision`
- finding:
  - `category=HiddenEntry` + `path`, `sha256` …
  - `category=RootkitModule` + `module_name`, `proc_entry`, `backdoor_path` …
  - `category=BackdoorIndicator` + `indicator`
- summary: `hidden_count`, `rootkit_count`, `backdoor_count`, `scan_scanned`, `scan_skipped`, `exit_code`

---

## 🧩 Exit Code

| Exit Code | 의미 |
|---:|---|
| `0` | 탐지 없음 |
| `10` | Hidden Entry 탐지 |
| `20` | Rootkit(모듈) 의심 탐지 |
| `30` | Backdoor Indicator 탐지 |
| `40` | 복수 카테고리 동시 탐지 |
| `2` | 오류/실행 조건 불충족(예: root 아님) |

---

## 🆚 원본(v1.0-rev1) 대비 Ubuntu판 변경 요약

Ubuntu판은 원본 스크립트에서 아래를 개선/조정했습니다. fileciteturn4file0L8-L33

1) **로그 파일 자동 생성 제거**
- 원본: 실행 시 호스트 기반 로그 파일 생성 가능
- Ubuntu판: 기본은 **stdout만**, 필요 시 `-o`로 저장

2) **스캔 커버리지(coverage) 출력**
- 도구 미설치로 raw 스캔이 전부 스킵될 수 있으므로,
  - `Raw scanned`, `Skipped`를 출력하고
  - 스캔 0일 때 경고 메시지를 출력

3) **insmod 경로 결합 로직 보정**
- 상대경로 insmod가 나올 때 경로 결합이 깨질 수 있는 부분을 보정했습니다.

4) **백도어 문자열 후보 필터 로직 보정**
- 문자열 필터 조건을 보정하여 후보가 누락되지 않도록 했습니다.

---

## 📎 파일
- `rootkit_detect_scanner_ubuntu_v1.0u.sh` (Ubuntu/Debian용)
- `README.md` (본 문서)

---

**PLURA-Forensic Philosophy**

> “로그는 남기지 않고, 분석에 필요한 근거는 한 번의 실행 결과에 담는다.”
