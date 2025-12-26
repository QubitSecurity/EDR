# /etc/profile.d/plura-cmd.sh

# Run only in Bash and only for interactive shells.
if [ -z "${BASH_VERSION:-}" ]; then
  return 0 2>/dev/null || exit 0
fi

case "$-" in
  *i*) : ;;
  *) return 0 ;;
esac

plura_log2syslog() {
  local cmd="${BASH_COMMAND:-}"

  # Minimal control-character escaping (mitigates log poisoning).
  cmd=${cmd//$'\n'/\\n}
  cmd=${cmd//$'\r'/\\r}
  cmd=${cmd//$'\t'/\\t}

  # Track the real user (prefer SUDO_USER when available).
  local user="${SUDO_USER:-${USER:-unknown}}"
  local pwd="${PWD:-unknown}"

  # Remote source IP (if available).
  local src="local"
  if [ -n "${SSH_CLIENT:-}" ]; then
    src="${SSH_CLIENT%% *}"
  elif [ -n "${SSH_CONNECTION:-}" ]; then
    src="${SSH_CONNECTION%% *}"
  fi

  # TTY (if available).
  local tty="notty"
  tty="$(tty 2>/dev/null || echo notty)"

  logger -p local0.notice -t plura-cmd -i -- \
    "user=${user} uid=${UID} src=${src} tty=${tty} pwd=${pwd} cmd=${cmd}"
}

trap 'plura_log2syslog' DEBUG
