# 📦 PLURA-XDR Agent 설치 가이드

이 프로젝트는 Linux 환경에서 PLURA-XDR Agent를 빠르게 설치할 수 있도록 자동화한 스크립트 모음입니다.

## 📁 포함 파일

- `add_hosts.sh` – `repo.plura.io` 등 관련 도메인을 `/etc/hosts`에 등록하는 스크립트
- `install_plura.sh` – 에이전트를 설치하고, 라이선스를 등록하며, 정상 설치 여부를 확인하는 스크립트

---

## 🛠️ 설치 순서

### 1️⃣ `add_hosts.sh` 실행

먼저 PLURA 설치에 필요한 도메인 정보를 `/etc/hosts`에 등록해야 합니다.

```bash
sudo bash ./add_hosts.sh
````

> ⚠️ **주의:**
> `add_hosts.sh` 파일에 등록된 IP 및 도메인은 사용자 환경에 따라 다를 수 있습니다.
> 반드시 **자신의 환경에 맞는 주소로 수정**한 뒤 실행해 주세요.

---

### 2️⃣ `run_plura.sh` 실행

에이전트를 설치하고 라이선스 키를 등록합니다.

```bash
bash ./install_plura.sh
```

> ⚠️ **주의:**
> `run_plura.sh` 내부의 `LICENSE_KEY="..."` 항목은
> 반드시 **PLURA 웹 UI에서 확인한 본인의 라이선스 키로 수정**해 주세요.

> 라이선스 키 확인 방법:
> PLURA 웹 로그인 → 상단 메뉴 `[관리] > [라이선스] > Install Agents`

---

## ✅ 설치 완료 확인

설치가 완료되면 아래 명령을 통해 정상 설치 여부를 확인할 수 있습니다.

```bash
/usr/local/sbin/plurad -version
```

---

## 📌 기타 안내

* 모든 설치 명령은 `sudo` 또는 `root` 권한으로 실행해야 합니다.
* 설치 후 문제 발생 시 PLURA 기술 지원팀에 문의해 주세요.

---

감사합니다.
