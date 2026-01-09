# /etc/plura/plura-cmd.sh
# version: 3.1
# PLURA command collection for interactive Bash sessions (shared for RHEL/Ubuntu).
#
# - Intended to be sourced by Bash (e.g., copied to /etc/profile.d/plura-cmd.sh).
# - No effect in non-Bash shells or non-interactive sessions.
# - Logs each command (BASH_COMMAND) to syslog (local0.notice) using tag "plura-cmd".
#
# Noise filtering:
# - Filters common prompt-hook noise such as terminal title updates:
#   printf "\033]0;... \007" ...
# - To disable filtering, set PLURA_CMD_FILTER_PROMPT=0 before sourcing.

# Prevent double-loading in the same shell.
if [ -n "${__PLURA_CMD_LOADED:-}" ]; then
  return 0 2>/dev/null || exit 0
fi
__PLURA_CMD_LOADED=1

# Bash only.
if [ -z "${BASH_VERSION:-}" ]; then
  return 0 2>/dev/null || exit 0
fi

# Interactive shells only.
case "$-" in
  *i*) : ;;
  *) return 0 ;;
esac

# Require logger binary.
command -v logger >/dev/null 2>&1 || return 0

: "${PLURA_CMD_FILTER_PROMPT:=1}"

plura_should_ignore_cmd() {
  local c="${1-}"

  # Ignore empty commands.
  [[ -z "$c" ]] && return 0

  # Filter prompt-hook noise (terminal title updates, VTE hooks, etc.).
  if [[ "${PLURA_CMD_FILTER_PROMPT}" == "1" ]]; then
    # Common VTE prompt hook function name.
    [[ "$c" == __vte_prompt_command* ]] && return 0

    # Terminal title update (OSC 0): printf "\033]0;... \007" ...
    # Match both \007 and \a (some systems use \a as BEL).
    if [[ "$c" == printf* && "$c" == *'\033]0;'* && ( "$c" == *'\007'* || "$c" == *'\a'* ) ]]; then
      return 0
    fi
  fi

  return 1
}

plura_log2syslog() {
  # Re-entry guard (defensive; avoids recursion).
  if [ -n "${__PLURA_CMD_IN_LOG:-}" ]; then
    return 0
  fi
  __PLURA_CMD_IN_LOG=1

  local cmd cmd_sanitized user pwd src tty

  # The command about to be executed (Bash sets BASH_COMMAND).
  cmd=${BASH_COMMAND-}

  # Drop noisy prompt-hook commands.
  if plura_should_ignore_cmd "$cmd"; then
    __PLURA_CMD_IN_LOG=
    return 0
  fi

  # Sanitize control characters to prevent multi-line log injection.
  cmd_sanitized=$(printf '%s' "$cmd" | tr '\n\r\t' ' ')

  # Prefer original login user if sudo was used.
  user=${SUDO_USER:-${LOGNAME:-${USER:-unknown}}}
  pwd=${PWD:-unknown}

  # Remote source IP (if available).
  src=local
  if [ -n "${SSH_CLIENT:-}" ]; then
    src=${SSH_CLIENT%% *}
  elif [ -n "${SSH_CONNECTION:-}" ]; then
    src=${SSH_CONNECTION%% *}
  fi

  # TTY (prefer SSH_TTY if present to avoid extra calls).
  tty=notty
  if [ -n "${SSH_TTY:-}" ]; then
    tty=$SSH_TTY
  else
    tty=$(tty 2>/dev/null || echo notty)
  fi

  logger -p local0.notice -t plura-cmd -i -- \
    "user=${user} uid=${UID:-} euid=${EUID:-} src=${src} tty=${tty} pwd=${pwd} cmd=${cmd_sanitized}"

  __PLURA_CMD_IN_LOG=
}

trap 'plura_log2syslog' DEBUG
