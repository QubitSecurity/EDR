### ✅ tput stderr만 버리기

기존 라인을 그대로 두고 뒤에 `2>/dev/null`만 추가함.

```bash
RED=$(tput setaf 1 2>/dev/null); GREEN=$(tput setaf 2 2>/dev/null); YELLOW=$(tput setaf 3 2>/dev/null); BLUE=$(tput setaf 4 2>/dev/null); RESET=$(tput sgr0 2>/dev/null)
```
