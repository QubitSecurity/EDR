## 🔧 스크립트 안의 프록시를 우회하는 3가지 방법

---

### ✅ 방법 1: `install.sh` 수정 후 실행 (권장)

`install.sh` 파일을 직접 열어서, 내부에 있는 `curl` 명령들을 다음처럼 **`--noproxy "*"`** 옵션을 추가해 수정합니다.

#### 예시 수정 전:

```bash
curl -s https://repo.plura.io/v5/agent/linux/install.sh -o install.sh
```

#### 예시 수정 후:

```bash
curl --noproxy "*" -s https://repo.plura.io/v5/agent/linux/install.sh -o install.sh
```

> `vim install.sh` 또는 `nano install.sh`로 편집 후 실행하세요.

---

### ✅ 방법 2: 스크립트 실행 전에 프록시 환경변수 해제

프록시 환경변수가 시스템에 설정되어 있다면, 실행 전에 `curl` 명령이 이를 사용하지 않도록 **일시적으로 제거**하거나 **빈 값으로 설정**할 수 있습니다:

```bash
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
export no_proxy="*"
bash install.sh
```

또는:

```bash
env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY no_proxy="*" bash install.sh
```

> 이 방식은 `install.sh` 안의 `curl`이 환경 변수에 의존할 때만 효과가 있습니다.

---

### ✅ 방법 3: `curl` 명령을 `alias`로 강제 적용 (전체 시스템 적용)

```bash
alias curl='curl --noproxy "*"'
```

이후 실행되는 모든 `curl` 명령에 `--noproxy "*"`가 자동으로 붙습니다.

⚠️ 단점:

* `install.sh` 안에서 `curl`을 `\curl` 또는 절대 경로(`/usr/bin/curl`)로 호출하면 `alias`가 무시됩니다.
* 시스템 전체에 영향을 주므로 일시적인 상황에만 권장합니다.

---
