#!/usr/bin/env bash
# bpfdoor_check-ubuntu.sh - BPFDoor integrated triage (YARA-free) for PLURA-Forensic (Ubuntu/Debian)
#
# VERSION  : 1.5u
# REVISION : 2025-12-25-u1
# SCHEMA   : bpfdoor_check_plura_v1
#
# Ubuntu/Debian adaptation highlights:
#   - Replace RPM ownership/verify (rpm -qf / rpm -V) with DPKG ownership/verify:
#       * dpkg-query -S <file>
#       * dpkg -V <package>   (filtered to the executable path)
#   - Baseline absorption gates on pkg_mgr=dpkg and pkg_verify=clean
#   - Built-in baseline rule uses Ubuntu package name (network-manager)
#
# What it does (no YARA):
#   1) BPF check: `ss -0pb` -> processes with active BPF usage (KISA [붙임1])
#   2) Magic check: scans `ss -0pb` output for KISA magic sequences (KISA section 3)
#   3) ENV check: finds processes with all suspicious vars (KISA [붙임2])
#   4) Correlates findings per PID and prints evidence-friendly details
#   5) (Optional) strings triage on executable of FOUND PIDs only
#   6) Auto verification (A/B/C) for every finding PID:
#        A) Confirm magic sequences presence/absence in ss output (+ per PID)
#        B) Capture BPF evidence lines for that PID (from ss output)
#        C) DPKG ownership/verification for the executable (Ubuntu/Debian)
#   7) Baseline absorption (NO file required):
#        - Built-in baseline rules for common benign daemons (starts with NetworkManager)
#        - Only applies when finding is "weak-only" (typically BPF_ACTIVE only)
#        - Requires: magic_in_pid=0 AND pkg_verify=clean
#        - baseline=1 -> severity_final=LOW and counted as non-actionable
#        - Exit code becomes 0 if ONLY baseline findings exist (automation-friendly)
#
# Exit codes:
#   0: No actionable findings (includes "baseline-only" results)
#   1: Actionable findings exist
#   2: Error / insufficient privileges
#
# Usage:
#   sudo bash bpfdoor_check-ubuntu-v1.5.sh
#   sudo bash bpfdoor_check-ubuntu-v1.5.sh --plura
#   sudo bash bpfdoor_check-ubuntu-v1.5.sh --suppress-baseline
#
# Notes:
#   - Requires root for accurate /proc/<pid>/environ reads.
#   - Does NOT kill/quarantine anything (forensic-safe).
#   - `ss -0pb` support depends on kernel/iproute2; older systems may return empty.

set -u
set -o pipefail

VERSION="1.5u"
REVISION="2025-12-25-u1"
SCHEMA="bpfdoor_check_plura_v1"

FORMAT="text"     # text | plura
OUTFILE=""
DO_STRINGS=1
DO_VERIFY=1
RUN_ID=""

# Baseline / suppression
DO_BASELINE=1
SUPPRESS_BASELINE=0              # if 1, baseline findings won't be printed/emitted as finding events

# Optional allowlist file (still supported, but not required)
DO_ALLOWLIST=1
ALLOWLIST_FILE=""                # if empty, use default resolution
ALLOWLIST_FILE_DEFAULT="/etc/bpfdoor_check.allow"
ALLOWLIST_FILE_FALLBACK="./bpfdoor_check.allow"

usage() {
  cat <<'USAGE'
bpfdoor_check-ubuntu.sh - BPFDoor triage (YARA-free) for Ubuntu/Debian

Options:
  --plura, --kv               Output logfmt-like key=value lines only (ingest-friendly)
  -o, --output <file>         Tee output to <file> (append)
  --no-strings                Skip strings-based triage (only for found PIDs)
  --no-verify                 Skip auto verification steps (A/B/C)
  --no-baseline               Disable baseline absorption (treat weak BPF as actionable)
  --suppress-baseline         Do not emit baseline findings (still emits header/summary)
  --allowlist <file>          Use external allowlist file (optional)
  --no-allowlist              Disable external allowlist usage (built-in baseline still works)
  --run-id <id>               Set run_id to correlate header/finding/summary lines
  -h, --help                  Show help

Examples:
  sudo bash bpfdoor_check-ubuntu-v1.5.sh
  sudo bash bpfdoor_check-ubuntu-v1.5.sh --plura
  sudo bash bpfdoor_check-ubuntu-v1.5.sh --suppress-baseline
USAGE
}

have() { command -v "$1" >/dev/null 2>&1; }

# Require root to avoid silent false-negatives (notably /proc/<pid>/environ)
if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: This script must run as root (use sudo) for complete checks." >&2
  exit 2
fi

# args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plura|--kv)
      FORMAT="plura"; shift ;;
    -o|--output)
      if [[ $# -lt 2 ]]; then echo "ERROR: --output requires a file path" >&2; exit 2; fi
      OUTFILE="$2"; shift 2 ;;
    --no-strings)
      DO_STRINGS=0; shift ;;
    --no-verify)
      DO_VERIFY=0; shift ;;
    --no-baseline)
      DO_BASELINE=0; shift ;;
    --suppress-baseline)
      SUPPRESS_BASELINE=1; shift ;;
    --allowlist)
      if [[ $# -lt 2 ]]; then echo "ERROR: --allowlist requires a file path" >&2; exit 2; fi
      ALLOWLIST_FILE="$2"; shift 2 ;;
    --no-allowlist)
      DO_ALLOWLIST=0; shift ;;
    --run-id)
      if [[ $# -lt 2 ]]; then echo "ERROR: --run-id requires a value" >&2; exit 2; fi
      RUN_ID="$2"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "ERROR: Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

# output to file if requested
if [[ -n "$OUTFILE" ]]; then
  mkdir -p "$(dirname "$OUTFILE")" 2>/dev/null || true
  exec > >(tee -a "$OUTFILE") 2>&1
fi

TS="$(date -Is 2>/dev/null || date)"
HOST="$(hostname 2>/dev/null || echo "unknown")"
KERNEL="$(uname -r 2>/dev/null || echo "unknown")"
RUN_ID="${RUN_ID:-$(date +%s 2>/dev/null || echo 0)-$$}"

# -----------------------------
# logfmt helpers (for --plura)
# -----------------------------
KV_LINE=""
kv_reset() { KV_LINE=""; }
kv_add() {
  local k="$1"
  local v="${2-}"
  local enc=""

  if [[ -z "$v" ]]; then
    enc='""'
  elif [[ "$v" == *$'\n'* || "$v" == *$'\r'* ]]; then
    v="${v//$'\r'/\\r}"
    v="${v//$'\n'/\\n}"
    v="${v//\\/\\\\}"
    v="${v//\"/\\\"}"
    enc="\"$v\""
  elif [[ "$v" == *" "* || "$v" == *$'\t'* || "$v" == *'"'* ]]; then
    v="${v//\\/\\\\}"
    v="${v//\"/\\\"}"
    enc="\"$v\""
  else
    enc="$v"
  fi

  KV_LINE+="${k}=${enc} "
}
kv_emit() {
  printf '%s\n' "${KV_LINE% }"
  KV_LINE=""
}

# -----------------------------
# evidence helpers
# -----------------------------
proc_comm() { cat "/proc/$1/comm" 2>/dev/null || echo "Unknown"; }
proc_exe_link() { readlink "/proc/$1/exe" 2>/dev/null || echo "N/A"; }
proc_exe_real() { readlink -f "/proc/$1/exe" 2>/dev/null || echo ""; }
proc_ps() {
  ps -p "$1" -o user=,pid=,ppid=,lstart=,cmd= 2>/dev/null | sed -e 's/^[[:space:]]*//'
}
sha256_of() {
  local f="$1"
  if [[ -n "$f" && -r "$f" && -f "$f" ]] && have sha256sum; then
    sha256sum "$f" 2>/dev/null | awk '{print $1}'
  else
    echo "N/A"
  fi
}
severity_for() {
  local s="$1"
  if (( s >= 70 )); then echo "HIGH"
  elif (( s >= 40 )); then echo "MED"
  elif (( s > 0 )); then echo "LOW"
  else echo "NONE"
  fi
}

# normalize multi-line evidence to a single line, trimmed + truncated
oneline_trunc() {
  local s="$1"
  local max="${2:-900}"
  s="$(printf '%s' "$s" | tr '\r\n' '; ' | tr '\t' ' ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')"
  if [[ ${#s} -gt $max ]]; then
    s="${s:0:$max}...(truncated)"
  fi
  printf '%s' "$s"
}

# -----------------------------
# findings storage
# -----------------------------
declare -A REASONS   # pid -> comma reasons
declare -A SCORE     # pid -> score int
declare -A EXTRA     # pid -> extra notes

# verification storage (per PID)
declare -A V_BPF_LINE_COUNT   # pid -> int
declare -A V_BPF_LINES_SAMPLE # pid -> string (single-line)
declare -A V_MAGIC_IN_PID     # pid -> 0/1

# package verification (Ubuntu/Debian)
declare -A V_PKG_MGR          # pid -> dpkg|none
declare -A V_PKG             # pid -> package name / unowned / N/A
declare -A V_PKG_VERIFY       # pid -> clean/changed/unowned/not_available/error
declare -A V_PKG_VERIFY_OUT   # pid -> string

# baseline storage (per PID)
declare -A V_BASELINE         # pid -> 0/1
declare -A V_BASELINE_SOURCE  # pid -> builtin|allowlist|none
declare -A V_BASELINE_MATCH   # pid -> rule string
declare -A V_SEVERITY_RAW     # pid -> HIGH/MED/LOW/NONE
declare -A V_SEVERITY_FINAL   # pid -> HIGH/MED/LOW/NONE
declare -A V_ACTIONABLE       # pid -> 0/1

add_reason() {
  local pid="$1" reason="$2" points="$3"
  local cur="${REASONS[$pid]:-}"

  if [[ -z "$cur" ]]; then
    REASONS["$pid"]="$reason"
  else
    if [[ ",$cur," != *",$reason,"* ]]; then
      REASONS["$pid"]="$cur,$reason"
    fi
  fi

  local sc="${SCORE[$pid]:-0}"
  SCORE["$pid"]=$(( sc + points ))
}

note_extra() {
  local pid="$1" msg="$2"
  if [[ -z "${EXTRA[$pid]:-}" ]]; then
    EXTRA["$pid"]="$msg"
  else
    EXTRA["$pid"]="${EXTRA[$pid]}; $msg"
  fi
}

# -----------------------------
# allowlist loader + matcher (optional)
# -----------------------------
ALLOW_RULES=()
ALLOWLIST_STATUS="disabled"   # disabled|none|loaded|empty|unreadable
ALLOWLIST_LOADED="0"
ALLOWLIST_USED_FILE=""

trim_ws() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

resolve_allowlist_file() {
  if [[ -n "$ALLOWLIST_FILE" ]]; then printf '%s' "$ALLOWLIST_FILE"; return; fi
  if [[ -r "$ALLOWLIST_FILE_DEFAULT" ]]; then printf '%s' "$ALLOWLIST_FILE_DEFAULT"; return; fi
  if [[ -r "$ALLOWLIST_FILE_FALLBACK" ]]; then printf '%s' "$ALLOWLIST_FILE_FALLBACK"; return; fi
  printf '%s' ""
}

load_allowlist() {
  ALLOW_RULES=()
  ALLOWLIST_LOADED="0"
  ALLOWLIST_STATUS="disabled"
  ALLOWLIST_USED_FILE=""

  if [[ "$DO_ALLOWLIST" -ne 1 ]]; then
    ALLOWLIST_STATUS="disabled"
    return
  fi

  local f
  f="$(resolve_allowlist_file)"
  if [[ -z "$f" ]]; then
    ALLOWLIST_STATUS="none"
    return
  fi
  if [[ ! -r "$f" ]]; then
    ALLOWLIST_STATUS="unreadable"
    ALLOWLIST_USED_FILE="$f"
    return
  fi

  ALLOWLIST_USED_FILE="$f"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="$(trim_ws "$line")"
    [[ -z "$line" ]] && continue
    [[ "$line" == \#* ]] && continue
    ALLOW_RULES+=("$line")
  done < "$f"

  ALLOWLIST_LOADED="${#ALLOW_RULES[@]}"
  ALLOWLIST_STATUS=$([[ "$ALLOWLIST_LOADED" -gt 0 ]] && echo "loaded" || echo "empty")
}

# rule: comma-separated key=glob tokens
# supported keys: comm, exe_real, exe, pkg
rule_matches() {
  local rule="$1"
  local comm="$2"
  local exe_real="$3"
  local exe_link="$4"
  local pkg="$5"

  local IFS=,
  local tokens
  read -ra tokens <<< "$rule"
  unset IFS

  local tok key pat val
  for tok in "${tokens[@]}"; do
    tok="$(trim_ws "$tok")"
    [[ -z "$tok" ]] && continue
    key="${tok%%=*}"
    pat="${tok#*=}"
    key="$(trim_ws "$key")"
    pat="$(trim_ws "$pat")"
    [[ -z "$key" || -z "$pat" ]] && return 1

    case "$key" in
      comm)     val="$comm" ;;
      exe_real) val="$exe_real" ;;
      exe)      val="$exe_link" ;;
      pkg)      val="$pkg" ;;
      *)        return 1 ;;
    esac

    if [[ "$val" != $pat ]]; then
      return 1
    fi
  done
  return 0
}

baseline_eligible_weakonly() {
  local reasons="$1"
  [[ -z "$reasons" ]] && return 1
  local r=",$reasons,"
  if [[ "$r" == *",BPF_MAGIC,"* ]]; then return 1; fi
  if [[ "$r" == *",ENV_SUSP,"* ]]; then return 1; fi
  if [[ "$r" == *",EXE_DELETED,"* ]]; then return 1; fi
  if [[ "$r" == *",STRINGS_IOC,"* ]]; then return 1; fi
  if [[ "$r" == *",PKG_VERIFY_CHANGED,"* ]]; then return 1; fi
  return 0
}

# Built-in baseline rules for Ubuntu/Debian (NO external file needed)
BASELINE_BUILTIN_RULES=(
  'comm=NetworkManager,exe_real=/usr/sbin/NetworkManager,pkg=network-manager*'
)
BUILTIN_RULES_COUNT="${#BASELINE_BUILTIN_RULES[@]}"

load_allowlist

# -----------------------------
# 1) BPF check (ss -0pb) + magic scan
# -----------------------------
SS_OUT=""
BPF_STATUS="skipped"
BPF_SS_BYTES="0"

MAGIC_DEC_RE="21139|29269|960051513|36204|40783"
MAGIC_HEX_DEC_RE="$((0x5293))|$((0x7255))|$((0x39393939))|$((0x8D6C))|$((0x9F4F))"

MAGIC_DEC_PRESENT="0"
MAGIC_HEX_PRESENT="0"
MAGIC_PIDS_CSV=""

if have ss; then
  SS_OUT="$(ss -0pb 2>/dev/null || true)"
  BPF_SS_BYTES="${#SS_OUT}"

  if [[ -n "$SS_OUT" ]]; then
    BPF_STATUS="ok"

    mapfile -t BPF_PIDS < <(printf '%s\n' "$SS_OUT" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)
    for pid in "${BPF_PIDS[@]:-}"; do
      [[ -n "$pid" ]] && add_reason "$pid" "BPF_ACTIVE" 40
    done

    mapfile -t MAGIC_PIDS < <(
      printf '%s\n' "$SS_OUT" \
        | grep -E "$MAGIC_DEC_RE" \
        | grep -oE 'pid=[0-9]+' \
        | cut -d= -f2 \
        | sort -u
    )
    if (( ${#MAGIC_PIDS[@]} > 0 )); then
      MAGIC_DEC_PRESENT="1"
      MAGIC_PIDS_CSV="$(IFS=,; echo "${MAGIC_PIDS[*]}")"
      for pid in "${MAGIC_PIDS[@]:-}"; do
        [[ -n "$pid" ]] && add_reason "$pid" "BPF_MAGIC" 30
      done
    fi

    if printf '%s\n' "$SS_OUT" | grep -Eq "$MAGIC_HEX_DEC_RE"; then
      MAGIC_HEX_PRESENT="1"
    fi
  else
    BPF_STATUS="empty"
  fi
else
  BPF_STATUS="ss_missing"
fi

# -----------------------------
# 2) ENV check (/proc/*/environ)
# -----------------------------
CHECK_ENV=("HOME=/tmp" "HISTFILE=/dev/null" "MYSQL_HISTFILE=/dev/null")
ENV_SCANNED="0"

for p in /proc/[0-9]*; do
  pid="${p#/proc/}"
  [[ -r "$p/environ" ]] || continue

  ENV_SCANNED=$((ENV_SCANNED + 1))

  env_data="$(tr '\0' '\n' < "$p/environ" 2>/dev/null || true)"
  [[ -n "$env_data" ]] || continue

  match_all=1
  for item in "${CHECK_ENV[@]}"; do
    if ! printf '%s\n' "$env_data" | grep -qF "$item"; then
      match_all=0
      break
    fi
  done

  if [[ "$match_all" -eq 1 ]]; then
    add_reason "$pid" "ENV_SUSP" 30
  fi
done

# -----------------------------
# 3) Enrich & optional strings triage
# -----------------------------
if [[ "$DO_STRINGS" -eq 1 ]] && ! have strings; then
  DO_STRINGS=0
fi
STRINGS_STATUS=$([[ "$DO_STRINGS" -eq 1 ]] && echo "enabled" || echo "disabled")

PIDS=()
for pid in "${!SCORE[@]}"; do
  PIDS+=("$pid")
done
IFS=$'\n' PIDS_SORTED=($(printf '%s\n' "${PIDS[@]:-}" | sort -n 2>/dev/null)); unset IFS

for pid in "${PIDS_SORTED[@]:-}"; do
  [[ -d "/proc/$pid" ]] || continue

  exe_link="$(proc_exe_link "$pid")"
  exe_real="$(proc_exe_real "$pid")"

  if [[ "$exe_link" == *"(deleted)"* ]]; then
    add_reason "$pid" "EXE_DELETED" 20
  fi

  if [[ "$DO_STRINGS" -eq 1 && -n "$exe_real" && -r "$exe_real" && -f "$exe_real" ]]; then
    IOC_RE='MYSQL_HISTFILE=/dev/null|:h:d:l:s:b:t:|:f:wiunomc|:f:x:wiuoc|ttcompat'
    matches="$(strings -a -n 5 "$exe_real" 2>/dev/null | grep -E "$IOC_RE" | head -n 8 | tr '\n' ';')"
    if [[ -n "$matches" ]]; then
      add_reason "$pid" "STRINGS_IOC" 20
      note_extra "$pid" "strings_ioc=${matches%;}"
    fi
  fi
done

# -----------------------------
# 4) Auto verification (A/B/C) for ALL finding PIDs
# -----------------------------
VERIFY_STATUS=$([[ "$DO_VERIFY" -eq 1 ]] && echo "enabled" || echo "disabled")

PKG_MGR="none"
if have dpkg-query && have dpkg; then
  PKG_MGR="dpkg"
fi

if [[ "$DO_VERIFY" -eq 1 && "${#PIDS_SORTED[@]}" -gt 0 ]]; then
  for pid in "${PIDS_SORTED[@]}"; do
    [[ -d "/proc/$pid" ]] || continue

    # B) BPF evidence lines for this PID (from ss output)
    if [[ -n "$SS_OUT" ]]; then
      pid_lines="$(printf '%s\n' "$SS_OUT" | grep -E "pid=${pid}([^0-9]|$)" || true)"
      if [[ -n "$pid_lines" ]]; then
        pid_line_count="$(printf '%s\n' "$pid_lines" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"
        V_BPF_LINE_COUNT["$pid"]="${pid_line_count:-0}"
        V_BPF_LINES_SAMPLE["$pid"]="$(oneline_trunc "$pid_lines" 900)"
      else
        V_BPF_LINE_COUNT["$pid"]="0"
        V_BPF_LINES_SAMPLE["$pid"]=""
      fi

      if printf '%s\n' "$pid_lines" | grep -Eq "$MAGIC_DEC_RE|$MAGIC_HEX_DEC_RE"; then
        V_MAGIC_IN_PID["$pid"]="1"
      else
        V_MAGIC_IN_PID["$pid"]="0"
      fi
    else
      V_BPF_LINE_COUNT["$pid"]="0"
      V_BPF_LINES_SAMPLE["$pid"]=""
      V_MAGIC_IN_PID["$pid"]="0"
    fi

    # C) DPKG ownership + verify (Ubuntu/Debian)
    exe_real="$(proc_exe_real "$pid")"
    V_PKG_MGR["$pid"]="$PKG_MGR"

    if [[ "$PKG_MGR" != "dpkg" ]]; then
      V_PKG_VERIFY["$pid"]="not_available"
      V_PKG["$pid"]="N/A"
      V_PKG_VERIFY_OUT["$pid"]=""
      continue
    fi

    if [[ -z "$exe_real" || ! -e "$exe_real" ]]; then
      V_PKG_VERIFY["$pid"]="error"
      V_PKG["$pid"]="N/A"
      V_PKG_VERIFY_OUT["$pid"]="exe_real_missing"
      continue
    fi

    # Ownership: dpkg-query -S
    owner_out="$(dpkg-query -S "$exe_real" 2>/dev/null || true)"
    if [[ -z "$owner_out" ]]; then
      V_PKG_VERIFY["$pid"]="unowned"
      V_PKG["$pid"]="unowned"
      V_PKG_VERIFY_OUT["$pid"]=""
      continue
    fi

    # owner_out might have multiple lines; take first package name (before ':')
    pkg="$(printf '%s\n' "$owner_out" | head -n 1 | cut -d: -f1 | awk '{print $1}')"
    pkg="$(trim_ws "$pkg")"
    if [[ -z "$pkg" ]]; then
      V_PKG_VERIFY["$pid"]="error"
      V_PKG["$pid"]="N/A"
      V_PKG_VERIFY_OUT["$pid"]="dpkg_query_parse_failed"
      continue
    fi
    V_PKG["$pid"]="$pkg"

    # Verify: dpkg -V <pkg>, but filter to this executable path
    ver_all=""
    dpkg -V "$pkg" >/tmp/.bpfdoor_dpkg_verify.$$ 2>/dev/null
    rc=$?
    if [[ -r /tmp/.bpfdoor_dpkg_verify.$$ ]]; then
      ver_all="$(cat /tmp/.bpfdoor_dpkg_verify.$$ 2>/dev/null || true)"
      rm -f /tmp/.bpfdoor_dpkg_verify.$$ >/dev/null 2>&1 || true
    fi

    ver_out="$(printf '%s\n' "$ver_all" | grep -F "$exe_real" || true)"

    if [[ -n "$ver_out" ]]; then
      V_PKG_VERIFY["$pid"]="changed"
      V_PKG_VERIFY_OUT["$pid"]="$(oneline_trunc "$ver_out" 900)"
      add_reason "$pid" "PKG_VERIFY_CHANGED" 10
    else
      # If dpkg -V failed hard and produced no output, mark error instead of clean
      if [[ "$rc" -ne 0 && -z "$ver_all" ]]; then
        V_PKG_VERIFY["$pid"]="error"
        V_PKG_VERIFY_OUT["$pid"]="dpkg_verify_failed"
      else
        V_PKG_VERIFY["$pid"]="clean"
        V_PKG_VERIFY_OUT["$pid"]=""
      fi
    fi
  done
fi

# -----------------------------
# 5) Baseline absorption (built-in + optional allowlist)
# -----------------------------
BASELINE_COUNT="0"
BASELINE_ALLOWLIST_COUNT="0"
BASELINE_BUILTIN_COUNT="0"

if [[ "${#PIDS_SORTED[@]}" -gt 0 ]]; then
  for pid in "${PIDS_SORTED[@]}"; do
    V_BASELINE["$pid"]="0"
    V_BASELINE_SOURCE["$pid"]="none"
    V_BASELINE_MATCH["$pid"]=""

    [[ -d "/proc/$pid" ]] || continue
    [[ "$DO_BASELINE" -eq 1 ]] || continue

    reasons="${REASONS[$pid]:-}"
    if ! baseline_eligible_weakonly "$reasons"; then
      continue
    fi

    # Safety gates:
    #  - no magic in this PID lines
    #  - package verification must be clean (dpkg)
    if [[ "${V_MAGIC_IN_PID[$pid]:-0}" != "0" ]]; then
      continue
    fi
    if [[ "${V_PKG_VERIFY[$pid]:-not_available}" != "clean" ]]; then
      continue
    fi

    comm="$(proc_comm "$pid")"
    exe_link="$(proc_exe_link "$pid")"
    exe_real="$(proc_exe_real "$pid")"
    pkg="${V_PKG[$pid]:-}"

    # allowlist match (optional)
    if [[ "$ALLOWLIST_LOADED" -gt 0 ]]; then
      for rule in "${ALLOW_RULES[@]}"; do
        if rule_matches "$rule" "$comm" "$exe_real" "$exe_link" "$pkg"; then
          V_BASELINE["$pid"]="1"
          V_BASELINE_SOURCE["$pid"]="allowlist"
          V_BASELINE_MATCH["$pid"]="$rule"
          BASELINE_COUNT=$((BASELINE_COUNT + 1))
          BASELINE_ALLOWLIST_COUNT=$((BASELINE_ALLOWLIST_COUNT + 1))
          break
        fi
      done
    fi

    # built-in baseline match
    if [[ "${V_BASELINE[$pid]}" -ne 1 ]]; then
      for rule in "${BASELINE_BUILTIN_RULES[@]}"; do
        if rule_matches "$rule" "$comm" "$exe_real" "$exe_link" "$pkg"; then
          V_BASELINE["$pid"]="1"
          V_BASELINE_SOURCE["$pid"]="builtin"
          V_BASELINE_MATCH["$pid"]="$rule"
          BASELINE_COUNT=$((BASELINE_COUNT + 1))
          BASELINE_BUILTIN_COUNT=$((BASELINE_BUILTIN_COUNT + 1))
          break
        fi
      done
    fi
  done
fi

# -----------------------------
# 6) Output
# -----------------------------
if [[ "$FORMAT" == "text" ]]; then
  echo "=== BPFDoor integrated check (YARA-free) ==="
  echo "timestamp : $TS"
  echo "host      : $HOST"
  echo "kernel    : $KERNEL"
  echo "version   : $VERSION"
  echo "revision  : $REVISION"
  echo "schema    : $SCHEMA"
  echo "run_id    : $RUN_ID"
  echo

  echo "[BPF] status=$BPF_STATUS ss_bytes=$BPF_SS_BYTES magic_dec_present=$MAGIC_DEC_PRESENT magic_hex_present=$MAGIC_HEX_PRESENT magic_pids=${MAGIC_PIDS_CSV:-none}"
  echo "[ENV] scanned=$ENV_SCANNED target=${CHECK_ENV[*]}"
  echo "[STRINGS] $STRINGS_STATUS (found-PIDs only)"
  echo "[VERIFY] $VERIFY_STATUS (A/B/C for every finding PID) pkg_mgr=$PKG_MGR"
  echo "[BASELINE] enabled=$DO_BASELINE builtin_rules=$BUILTIN_RULES_COUNT allowlist_status=$ALLOWLIST_STATUS allowlist_rules=$ALLOWLIST_LOADED baseline_total=$BASELINE_COUNT suppress_baseline=$SUPPRESS_BASELINE"
  echo

  if [[ "${#PIDS_SORTED[@]}" -eq 0 ]]; then
    echo "Result: No findings (BPF/ENV indicators not detected)."
    exit 0
  fi

  high_raw=0; med_raw=0; low_raw=0
  high_final=0; med_final=0; low_final=0

  emitted_findings=0
  suppressed_findings=0
  actionable_findings=0
  baseline_findings=0

  for pid in "${PIDS_SORTED[@]}"; do
    [[ -d "/proc/$pid" ]] || continue

    sc="${SCORE[$pid]:-0}"
    sev_raw="$(severity_for "$sc")"
    sev_final="$sev_raw"

    baseline="${V_BASELINE[$pid]:-0}"
    bsrc="${V_BASELINE_SOURCE[$pid]:-none}"
    bmatch="${V_BASELINE_MATCH[$pid]:-}"

    if [[ "$baseline" -eq 1 ]]; then
      sev_final="LOW"
      baseline_findings=$((baseline_findings+1))
    else
      actionable_findings=$((actionable_findings+1))
    fi

    V_SEVERITY_RAW["$pid"]="$sev_raw"
    V_SEVERITY_FINAL["$pid"]="$sev_final"
    V_ACTIONABLE["$pid"]=$([[ "$baseline" -eq 1 ]] && echo "0" || echo "1")

    case "$sev_raw" in
      HIGH) high_raw=$((high_raw+1)) ;;
      MED)  med_raw=$((med_raw+1)) ;;
      LOW)  low_raw=$((low_raw+1)) ;;
    esac
    case "$sev_final" in
      HIGH) high_final=$((high_final+1)) ;;
      MED)  med_final=$((med_final+1)) ;;
      LOW)  low_final=$((low_final+1)) ;;
    esac

    if [[ "$SUPPRESS_BASELINE" -eq 1 && "$baseline" -eq 1 ]]; then
      suppressed_findings=$((suppressed_findings+1))
      continue
    fi
    emitted_findings=$((emitted_findings+1))

    comm="$(proc_comm "$pid")"
    exe_link="$(proc_exe_link "$pid")"
    exe_real="$(proc_exe_real "$pid")"
    ps_line="$(proc_ps "$pid")"
    sha="$(sha256_of "$exe_real")"

    echo "----- PID $pid | severity_raw=$sev_raw | severity_final=$sev_final | score=$sc | baseline=$baseline ($bsrc) -----"
    echo "reasons : ${REASONS[$pid]}"
    echo "comm    : $comm"
    echo "exe     : $exe_link"
    [[ -n "$exe_real" ]] && echo "exe_real: $exe_real"
    echo "sha256  : $sha"
    [[ -n "$ps_line" ]] && echo "ps      : $ps_line"
    [[ -n "${EXTRA[$pid]:-}" ]] && echo "extra   : ${EXTRA[$pid]}"

    if [[ "$baseline" -eq 1 && -n "$bmatch" ]]; then
      echo "baseline_match: $bmatch"
    fi

    if [[ "$DO_VERIFY" -eq 1 ]]; then
      echo "verify  : bpf_line_count=${V_BPF_LINE_COUNT[$pid]:-0} magic_in_pid=${V_MAGIC_IN_PID[$pid]:-0} pkg_mgr=${V_PKG_MGR[$pid]:-none} pkg_verify=${V_PKG_VERIFY[$pid]:-N/A} pkg=${V_PKG[$pid]:-N/A}"
      [[ -n "${V_BPF_LINES_SAMPLE[$pid]:-}" ]] && echo "bpf_ss  : ${V_BPF_LINES_SAMPLE[$pid]}"
      [[ -n "${V_PKG_VERIFY_OUT[$pid]:-}" ]] && echo "pkg_v   : ${V_PKG_VERIFY_OUT[$pid]}"
    fi

    echo
  done

  if [[ "$actionable_findings" -eq 0 ]]; then
    echo "Result: Baseline-only findings detected ($baseline_findings PID(s)) -> treated as NORMAL (exit 0)"
  else
    echo "Result: Actionable findings detected ($actionable_findings PID(s)); baseline=$baseline_findings"
  fi
  echo

  echo "Summary(raw):   HIGH=$high_raw, MED=$med_raw, LOW=$low_raw"
  echo "Summary(final): HIGH=$high_final, MED=$med_final, LOW=$low_final, baseline_total=$BASELINE_COUNT (builtin=$BASELINE_BUILTIN_COUNT, allowlist=$BASELINE_ALLOWLIST_COUNT)"
  if [[ "$SUPPRESS_BASELINE" -eq 1 ]]; then
    echo "Summary(output): emitted_findings=$emitted_findings suppressed_baseline=$suppressed_findings"
  fi
  echo "Tip: For each PID, validate executable path with: ls -l /proc/<PID>/exe"

  if [[ "$actionable_findings" -gt 0 ]]; then
    exit 1
  fi
  exit 0

else
  # PLURA-friendly logfmt-like key=value lines

  kv_reset
  kv_add "plura_schema" "$SCHEMA"
  kv_add "plura_event" "header"
  kv_add "plura_record" "BPFDoorCheck"
  kv_add "tool" "bpfdoor_check"
  kv_add "run_id" "$RUN_ID"
  kv_add "ts" "$TS"
  kv_add "host" "$HOST"
  kv_add "kernel" "$KERNEL"
  kv_add "version" "$VERSION"
  kv_add "revision" "$REVISION"
  kv_add "bpf_status" "$BPF_STATUS"
  kv_add "bpf_ss_bytes" "$BPF_SS_BYTES"
  kv_add "magic_dec_present" "$MAGIC_DEC_PRESENT"
  kv_add "magic_hex_present" "$MAGIC_HEX_PRESENT"
  kv_add "magic_pids" "${MAGIC_PIDS_CSV:-}"
  kv_add "env_scanned" "$ENV_SCANNED"
  kv_add "strings" "$STRINGS_STATUS"
  kv_add "verify" "$VERIFY_STATUS"
  kv_add "pkg_mgr" "$PKG_MGR"
  kv_add "baseline" "$DO_BASELINE"
  kv_add "baseline_builtin_rules" "$BUILTIN_RULES_COUNT"
  kv_add "baseline_total" "$BASELINE_COUNT"
  kv_add "baseline_builtin" "$BASELINE_BUILTIN_COUNT"
  kv_add "baseline_allowlist" "$BASELINE_ALLOWLIST_COUNT"
  kv_add "allowlist_status" "$ALLOWLIST_STATUS"
  kv_add "allowlist_rules" "$ALLOWLIST_LOADED"
  kv_add "suppress_baseline" "$SUPPRESS_BASELINE"
  kv_emit

  if [[ "${#PIDS_SORTED[@]}" -eq 0 ]]; then
    kv_reset
    kv_add "plura_schema" "$SCHEMA"
    kv_add "plura_event" "summary"
    kv_add "tool" "bpfdoor_check"
    kv_add "run_id" "$RUN_ID"
    kv_add "ts" "$TS"
    kv_add "host" "$HOST"
    kv_add "version" "$VERSION"
    kv_add "revision" "$REVISION"
    kv_add "bpf_status" "$BPF_STATUS"
    kv_add "findings" "0"
    kv_add "actionable_findings" "0"
    kv_add "baseline_findings" "0"
    kv_add "exit_code" "0"
    kv_emit
    exit 0
  fi

  high_raw=0; med_raw=0; low_raw=0
  high_final=0; med_final=0; low_final=0
  emitted_findings=0
  suppressed_findings=0
  actionable_findings=0
  baseline_findings=0

  for pid in "${PIDS_SORTED[@]}"; do
    [[ -d "/proc/$pid" ]] || continue

    sc="${SCORE[$pid]:-0}"
    sev_raw="$(severity_for "$sc")"
    sev_final="$sev_raw"

    baseline="${V_BASELINE[$pid]:-0}"
    bsrc="${V_BASELINE_SOURCE[$pid]:-none}"
    bmatch="${V_BASELINE_MATCH[$pid]:-}"

    if [[ "$baseline" -eq 1 ]]; then
      sev_final="LOW"
      baseline_findings=$((baseline_findings+1))
    else
      actionable_findings=$((actionable_findings+1))
    fi

    case "$sev_raw" in
      HIGH) high_raw=$((high_raw+1)) ;;
      MED)  med_raw=$((med_raw+1)) ;;
      LOW)  low_raw=$((low_raw+1)) ;;
    esac
    case "$sev_final" in
      HIGH) high_final=$((high_final+1)) ;;
      MED)  med_final=$((med_final+1)) ;;
      LOW)  low_final=$((low_final+1)) ;;
    esac

    if [[ "$SUPPRESS_BASELINE" -eq 1 && "$baseline" -eq 1 ]]; then
      suppressed_findings=$((suppressed_findings+1))
      continue
    fi
    emitted_findings=$((emitted_findings+1))

    comm="$(proc_comm "$pid")"
    exe_link="$(proc_exe_link "$pid")"
    exe_real="$(proc_exe_real "$pid")"
    ps_line="$(proc_ps "$pid")"
    sha="$(sha256_of "$exe_real")"
    extra="${EXTRA[$pid]:-}"

    kv_reset
    kv_add "plura_schema" "$SCHEMA"
    kv_add "plura_event" "finding"
    kv_add "tool" "bpfdoor_check"
    kv_add "run_id" "$RUN_ID"
    kv_add "ts" "$TS"
    kv_add "host" "$HOST"
    kv_add "version" "$VERSION"
    kv_add "revision" "$REVISION"
    kv_add "bpf_status" "$BPF_STATUS"

    kv_add "pid" "$pid"
    kv_add "severity" "$sev_raw"
    kv_add "severity_final" "$sev_final"
    kv_add "score" "$sc"
    kv_add "reasons" "${REASONS[$pid]}"
    kv_add "comm" "$comm"
    kv_add "exe" "$exe_link"
    [[ -n "$exe_real" ]] && kv_add "exe_real" "$exe_real"
    kv_add "sha256" "$sha"
    [[ -n "$ps_line" ]] && kv_add "ps" "$ps_line"
    [[ -n "$extra" ]] && kv_add "extra" "$extra"

    kv_add "bpf_line_count" "${V_BPF_LINE_COUNT[$pid]:-0}"
    kv_add "magic_in_pid" "${V_MAGIC_IN_PID[$pid]:-0}"
    kv_add "pkg_mgr" "${V_PKG_MGR[$pid]:-none}"
    kv_add "pkg_verify" "${V_PKG_VERIFY[$pid]:-}"
    kv_add "pkg" "${V_PKG[$pid]:-}"
    [[ -n "${V_BPF_LINES_SAMPLE[$pid]:-}" ]] && kv_add "bpf_ss" "${V_BPF_LINES_SAMPLE[$pid]}"
    [[ -n "${V_PKG_VERIFY_OUT[$pid]:-}" ]] && kv_add "pkg_v" "${V_PKG_VERIFY_OUT[$pid]}"

    kv_add "baseline" "$baseline"
    kv_add "baseline_source" "$bsrc"
    [[ -n "$bmatch" ]] && kv_add "baseline_match" "$(oneline_trunc "$bmatch" 300)"
    kv_add "actionable" $([[ "$baseline" -eq 1 ]] && echo "0" || echo "1")

    kv_emit
  done

  exit_code=$([[ "$actionable_findings" -gt 0 ]] && echo "1" || echo "0")
  kv_reset
  kv_add "plura_schema" "$SCHEMA"
  kv_add "plura_event" "summary"
  kv_add "tool" "bpfdoor_check"
  kv_add "run_id" "$RUN_ID"
  kv_add "ts" "$TS"
  kv_add "host" "$HOST"
  kv_add "version" "$VERSION"
  kv_add "revision" "$REVISION"
  kv_add "bpf_status" "$BPF_STATUS"
  kv_add "findings" "${#PIDS_SORTED[@]}"
  kv_add "actionable_findings" "$actionable_findings"
  kv_add "baseline_findings" "$baseline_findings"
  kv_add "high_raw" "$high_raw"; kv_add "med_raw" "$med_raw"; kv_add "low_raw" "$low_raw"
  kv_add "high_final" "$high_final"; kv_add "med_final" "$med_final"; kv_add "low_final" "$low_final"
  kv_add "baseline_total" "$BASELINE_COUNT"
  kv_add "baseline_builtin" "$BASELINE_BUILTIN_COUNT"
  kv_add "baseline_allowlist" "$BASELINE_ALLOWLIST_COUNT"
  kv_add "emitted_findings" "$emitted_findings"
  kv_add "suppressed_baseline" "$suppressed_findings"
  kv_add "exit_code" "$exit_code"
  kv_emit

  if [[ "$actionable_findings" -gt 0 ]]; then
    exit 1
  fi
  exit 0
fi
