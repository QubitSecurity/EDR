Proxy `unset` 사용 방법:

```bash
unset https_proxy HTTPS_PROXY
```

---

### ✅ 설명:

* `unset`은 **Bash 내장 명령어**이고 CentOS 7의 기본 셸은 `bash`입니다.
* `https_proxy`와 `HTTPS_PROXY` 둘 다 사용되는 경우가 있으므로 **둘 다 unset** 해주는 것이 안전합니다.
* 필요 시 `http_proxy`, `HTTP_PROXY`도 함께 unset 해주시면 좋습니다:

```bash
unset http_proxy HTTP_PROXY https_proxy HTTPS_PROXY
```

---

### 🧪 확인 방법:

```bash
echo $https_proxy
echo $HTTPS_PROXY
```

이렇게 입력했을 때 아무것도 출력되지 않으면 unset 성공입니다.

---

### 📝 참고:

이 설정은 현재 셸에만 적용됩니다.
**영구적으로 적용하려면** 아래 파일에서 삭제하거나 주석 처리해야 합니다:

* `~/.bashrc`
* `~/.bash_profile`
* `/etc/profile` 또는 `/etc/environment` (시스템 전체 적용 시)

```bash
# 예시: ~/.bashrc 에서 주석 처리
# export https_proxy="http://proxy.example.com:8080"
```

---
