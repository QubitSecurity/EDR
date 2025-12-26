# /etc/profile.d/plura-cmd.sh

# bash에서만, 그리고 인터랙티브 쉘에서만 동작
if [ -z "${BASH_VERSION:-}" ]; then
  return 0 2>/dev/null || exit 0
fi
case "$-" in
  *i*) : ;;
  *) return 0 ;;
esac

plura_log2syslog() {
  local cmd="${BASH_COMMAND:-}"

  # 제어문자 최소 치환(로그 포이즈닝 완화)
  cmd=${cmd//$'\n'/\\n}
  cmd=${cmd//$'\r'/\\r}
  cmd=${cmd//$'\t'/\\t}

  # 실제 사용자 추적(가능하면 SUDO_USER 우선)
  local user="${SUDO_USER:-${USER:-unknown}}"
  local pwd="${PWD:-unknown}"

  # 원격접속 IP(있으면)
  local src="local"
  if [ -n "${SSH_CLIENT:-}" ]; then
    src="${SSH_CLIENT%% *}"
  elif [ -n "${SSH_CONNECTION:-}" ]; then
    src="${SSH_CONNECTION%% *}"
  fi

  # tty (가능하면)
  local tty="notty"
  tty="$(tty 2>/dev/null || echo notty)"

  logger -p local0.notice -t plura-cmd -i -- \
    "user=${user} uid=${UID} src=${src} tty=${tty} pwd=${pwd} cmd=${cmd}"
}

trap 'plura_log2syslog' DEBUG
