`curl`이 사용하는 **프록시 설정(proxy 설정)을 확인**하기 위해서는 다음 방법들을 사용할 수 있습니다:

---

## ✅ 1. 환경변수로 설정된 프록시 확인 (`curl`이 참조)

```bash
env | grep -i proxy
```

출력 예:

```
http_proxy=http://proxy.example.com:8080
https_proxy=http://proxy.example.com:8080
no_proxy=localhost,127.0.0.1
```

또는 (더 명확하게):

```bash
echo $http_proxy
echo $https_proxy
echo $no_proxy
```

> `curl`은 기본적으로 이 환경변수를 따릅니다.

---

## ✅ 2. `curl -v` (verbose)로 동작 확인

어떤 프록시를 사용하고 있는지 직접 확인하고 싶다면 `-v` 옵션을 사용하세요:

```bash
curl -v https://example.com
```

출력 예:

```
* Uses proxy env variable https_proxy == 'http://proxy.example.com:8080'
```

* 위와 같이 명확히 어떤 프록시를 사용하는지 표시됩니다.
* 사용 중인 인증, 연결 IP, 프록시 여부 등을 추적할 수 있습니다.

---

## ✅ 3. 프록시 없이 테스트 (비교용)

```bash
curl --noproxy "*" -v https://example.com
```

> 위 명령으로 프록시 없이 실행하고, 기존 명령과 `-v` 로그를 비교하면 **프록시 사용 여부**를 정확히 확인할 수 있습니다.

---

## ✅ 4. `curl`이 사용하는 설정 파일 확인 (`~/.curlrc`)

```bash
cat ~/.curlrc
```

> `proxy = "http://proxy.example.com:8080"` 와 같은 설정이 있다면 항상 프록시를 타게 됩니다.

---

## ✅ 5. 전체 시스템 프록시 (특히 데스크탑 환경)

* Ubuntu(GNOME 등): `gsettings get org.gnome.system.proxy mode`
* macOS: `networksetup -getwebproxy Wi-Fi`
* Windows PowerShell:

  ```powershell
  netsh winhttp show proxy
  ```

---

## 🔎 요약

| 방법              | 명령어                                         |                 |
| --------------- | ------------------------------------------- | --------------- |
| 🌍 환경변수 확인      | \`env                                       | grep -i proxy\` |
| 🔍 `curl` 동작 확인 | `curl -v https://example.com`               |                 |
| 🧪 프록시 우회 테스트   | `curl --noproxy "*" -v https://example.com` |                 |
| 🧾 사용자 설정 파일    | `cat ~/.curlrc`                             |                 |
| 🖥️ 시스템 프록시 설정  | OS 별 명령어                                    |                 |

---


