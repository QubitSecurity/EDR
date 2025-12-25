#!/usr/bin/env bash
# bpfdoor_check.sh - BPFDoor triage (YARA-free) for PLURA-Forensic
#
# What it does (no YARA):
#   1) Finds processes with active BPF usage via `ss -0pb` (KISA [붙임1])
#   2) Flags BPF output lines containing known BPFDoor magic sequences (KISA section 3)
#   3) Finds processes whose environment contains all suspicious vars:
#        HOME=/tmp, HISTFILE=/dev/null, MYSQL_HISTFILE=/dev/null (KISA [붙임2])
#   4) Correlates findings per PID and prints evidence-friendly details
#   5) (Optional) Runs `strings` triage on the executable of FOUND PIDs only (KISA section 8)
#
# Exit codes:
#   0: No findings
#   1: Findings exist
#   2: Error / insufficient privileges
#
# Usage:
#   sudo ./bpfdoor_check.sh
#   sudo ./bpfdoor_check.sh --plura                 # key=value lines (ingest-friendly)
#   sudo ./bpfdoor_check.sh -o /var/log/bpfdoor_check.log
#   sudo ./bpfdoor_check.sh --no-strings            # skip strings triage
#
# Notes:
#   - BPF check requires kernel/iproute2 support; on older systems it may not work.
#   - This script does NOT quarantine/kill anything (forensic-safe).

set -u
set -o pipefail

VERSION="1.0"
FORMAT="text"     # text | plura
OUTFILE=""
DO_STRINGS=1

usage() {
  cat <<'USAGE'
bpfdoor_check.sh - BPFDoor triage (YARA-free)

Options:
  --plura, --kv         Output key=value lines only (ingest-friendly)
  -o, --output <file>   Tee output to <file> (append)
  --no-strings          Skip strings-based triage (only for found PIDs)
  -h, --help            Show help

Examples:
  sudo ./bpfdoor_check.sh
  sudo ./bpfdoor_check.sh --plura
  sudo ./bpfdoor_check.sh -o /var/log/bpfdoor_check.log
USAGE
}

have() { command -v "$1" >/dev/null 2>&1; }

# privileges
SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
  if have sudo; then
    SUDO="sudo"
  else
    echo "ERROR: root privileges required (run as root or install sudo)." >&2
    exit 2
  fi
fi

# args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plura|--kv) FORMAT="plura"; shift ;;
    -o|--output)
      if [[ $# -lt 2 ]]; then echo "ERROR: --output requires a file path" >&2; exit 2; fi
      OUTFILE="$2"; shift 2 ;;
    --no-strings) DO_STRINGS=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: Unknown option: $1" >&2; usage; exit 2 ;;
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

# evidence helpers
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

# store findings
declare -A REASONS   # pid -> comma reasons
declare -A SCORE     # pid -> score int
declare -A EXTRA     # pid -> extra notes (e.g., strings matches)

add_reason() {
  local pid="$1" reason="$2" points="$3"
  local cur="${REASONS[$pid]:-}"
  if [[ -z "$cur" ]]; then
    REASONS["$pid"]="$reason"
  else
    # avoid duplicates
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

print_header_text() {
  cat <<EOF
=== BPFDoor integrated check (YARA-free) ===
timestamp : $TS
host      : $HOST
kernel    : $KERNEL
version   : $VERSION
EOF
}

print_kv() {
  # prints a single key=value line; values are quoted if they contain spaces
  local k="$1" v="$2"
  if [[ "$v" == *" "* || "$v" == *$'\t'* ]]; then
    printf '%s="%s" ' "$k" "${v//\"/\\\"}"
  else
    printf '%s=%s ' "$k" "$v"
  fi
}

# -----------------------------
# 1) BPF check (ss -0pb)
# -----------------------------
SS_OUT=""
if have ss; then
  # capture output once for both PID extraction and magic checks
  SS_OUT="$($SUDO ss -0pb 2>/dev/null || true)"
  if [[ -n "$SS_OUT" ]]; then
    # PIDs with active BPF usage
    printf "%s\n" "$SS_OUT" \
      | grep -oE 'pid=[0-9]+' \
      | cut -d= -f2 \
      | sort -u \
      | while read -r pid; do
          [[ -z "$pid" ]] && continue
          add_reason "$pid" "BPF_ACTIVE" 40
        done

    # Magic sequences (KISA: 21139|29269|960051513|36204|40783)
    MAGIC_LINES="$(printf "%s\n" "$SS_OUT" | grep -E "21139|29269|960051513|36204|40783" || true)"
    if [[ -n "$MAGIC_LINES" ]]; then
      printf "%s\n" "$MAGIC_LINES" \
        | grep -oE 'pid=[0-9]+' \
        | cut -d= -f2 \
        | sort -u \
        | while read -r pid; do
            [[ -z "$pid" ]] && continue
            add_reason "$pid" "BPF_MAGIC" 30
          done
    fi
  fi
fi

# -----------------------------
# 2) ENV check (/proc/*/environ)
# -----------------------------
CHECK_ENV=("HOME=/tmp" "HISTFILE=/dev/null" "MYSQL_HISTFILE=/dev/null")
for p in /proc/[0-9]*; do
  pid="${p#/proc/}"
  [[ -r "$p/environ" ]] || continue

  env_data="$(tr '\0' '\n' < "$p/environ" 2>/dev/null || true)"
  [[ -n "$env_data" ]] || continue

  match_all=1
  for item in "${CHECK_ENV[@]}"; do
    if ! printf "%s\n" "$env_data" | grep -qF "$item"; then
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
  # not an error; just skip
  DO_STRINGS=0
fi

# identify findings PIDs
PIDS=()
for pid in "${!SCORE[@]}"; do
  PIDS+=("$pid")
done
IFS=$'\n' PIDS_SORTED=($(printf "%s\n" "${PIDS[@]}" | sort -n 2>/dev/null)); unset IFS

# enrich per PID
for pid in "${PIDS_SORTED[@]:-}"; do
  [[ -d "/proc/$pid" ]] || continue

  exe_link="$(proc_exe_link "$pid")"
  exe_real="$(proc_exe_real "$pid")"

  if [[ "$exe_link" == *"(deleted)"* ]]; then
    add_reason "$pid" "EXE_DELETED" 20
  fi

  # Optional strings triage on the executable *of found PIDs only*
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
# 4) Output
# -----------------------------
if [[ "$FORMAT" == "text" ]]; then
  print_header_text
  echo

  # quick status lines
  if ! have ss; then
    echo "[BPF] ss not found -> BPF check skipped"
  elif [[ -z "$SS_OUT" ]]; then
    echo "[BPF] ss -0pb returned empty output (kernel/iproute2 limitations or no BPF filters)"
  else
    echo "[BPF] ss -0pb collected (${#SS_OUT} bytes)"
  fi
  echo "[ENV] scanned /proc/*/environ for: ${CHECK_ENV[*]}"
  if [[ "$DO_STRINGS" -eq 1 ]]; then
    echo "[STRINGS] enabled (found-PIDs only)"
  else
    echo "[STRINGS] disabled"
  fi
  echo

  if [[ "${#PIDS_SORTED[@]}" -eq 0 ]]; then
    echo "Result: No findings (BPF/ENV indicators not detected)."
    exit 0
  fi

  echo "Result: Findings detected (${#PIDS_SORTED[@]} PID(s))"
  echo

  high=0; med=0; low=0
  for pid in "${PIDS_SORTED[@]}"; do
    [[ -d "/proc/$pid" ]] || continue

    sc="${SCORE[$pid]:-0}"
    sev="$(severity_for "$sc")"
    case "$sev" in
      HIGH) high=$((high+1)) ;;
      MED)  med=$((med+1)) ;;
      LOW)  low=$((low+1)) ;;
    esac

    comm="$(proc_comm "$pid")"
    exe_link="$(proc_exe_link "$pid")"
    exe_real="$(proc_exe_real "$pid")"
    ps_line="$(proc_ps "$pid")"
    sha="$(sha256_of "$exe_real")"

    echo "----- PID $pid | severity=$sev | score=$sc -----"
    echo "reasons : ${REASONS[$pid]}"
    echo "comm    : $comm"
    echo "exe     : $exe_link"
    if [[ -n "$exe_real" ]]; then
      echo "exe_real: $exe_real"
    fi
    echo "sha256  : $sha"
    if [[ -n "$ps_line" ]]; then
      echo "ps      : $ps_line"
    else
      echo "ps      : (process ended or permission denied)"
    fi
    if [[ -n "${EXTRA[$pid]:-}" ]]; then
      echo "extra   : ${EXTRA[$pid]}"
    fi
    echo
  done

  echo "Summary: HIGH=$high, MED=$med, LOW=$low"
  echo "Tip: For each suspicious PID, validate executable path with: ${SUDO:+$SUDO }ls -l /proc/<PID>/exe"
  exit 1

else
  # PLURA-friendly key=value lines (no section text)
  # header record
  print_kv "plura_record" "BPFDoorCheck"; print_kv "ts" "$TS"; print_kv "host" "$HOST"; print_kv "kernel" "$KERNEL"; print_kv "version" "$VERSION"
  printf "\n"

  if [[ "${#PIDS_SORTED[@]}" -eq 0 ]]; then
    print_kv "plura_event" "summary"; print_kv "findings" "0"; printf "\n"
    exit 0
  fi

  for pid in "${PIDS_SORTED[@]}"; do
    [[ -d "/proc/$pid" ]] || continue
    sc="${SCORE[$pid]:-0}"
    sev="$(severity_for "$sc")"

    comm="$(proc_comm "$pid")"
    exe_link="$(proc_exe_link "$pid")"
    exe_real="$(proc_exe_real "$pid")"
    ps_line="$(proc_ps "$pid")"
    sha="$(sha256_of "$exe_real")"
    extra="${EXTRA[$pid]:-}"

    print_kv "plura_event" "finding"
    print_kv "ts" "$TS"
    print_kv "host" "$HOST"
    print_kv "pid" "$pid"
    print_kv "severity" "$sev"
    print_kv "score" "$sc"
    print_kv "reasons" "${REASONS[$pid]}"
    print_kv "comm" "$comm"
    print_kv "exe" "$exe_link"
    if [[ -n "$exe_real" ]]; then print_kv "exe_real" "$exe_real"; fi
    print_kv "sha256" "$sha"
    if [[ -n "$ps_line" ]]; then print_kv "ps" "$ps_line"; fi
    if [[ -n "$extra" ]]; then print_kv "extra" "$extra"; fi
    printf "\n"
  done

  print_kv "plura_event" "summary"; print_kv "findings" "${#PIDS_SORTED[@]}"; printf "\n"
  exit 1
fi
