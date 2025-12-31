#!/usr/bin/env bash
# Rootkit Detection Scanner (Linux) - Ubuntu/Debian Edition
# Based on: rootkit_detect_scanner_v1.1.sh
#
# VERSION  : 1.0u
# REVISION : 2025-12-25-u1
# SCHEMA   : rootkit_detect_scanner_plura_v1
#
# Goals for Ubuntu/Debian:
#   - Work well on Ubuntu/Debian defaults (systemd + dpkg-based systems)
#   - Avoid misleading "clean" results when filesystem raw-scan tools are missing
#   - Optional: no logfile by default (PLURA-friendly). Use -o/--output to save a copy.
#   - Fix two logic issues found in the original:
#       * Backdoor string filter condition (|| -> &&)
#       * Relative insmod module path join (missing '/')
#
# What it does:
#   1) Raw filesystem directory entry scan to detect "Hidden Entry" files:
#        - Compare directory entries from filesystem metadata vs `ls -a` results
#        - Supported fs: ext2/3/4 (debugfs), xfs (xfs_db), btrfs (btrfs-progs)
#   2) If a suspicious startup entry contains `insmod ...`, extract module path(s)
#   3) For extracted modules, attempt lightweight analysis:
#        - Extract module name, proc entry, call_usermodehelper backdoor path, vermagic
#
# Exit codes (compatible with PLURA-style Windows README):
#   0  : No findings
#   10 : Hidden Entry found
#   20 : Suspicious Rootkit found (module)
#   30 : Backdoor found
#   40 : Multiple categories found
#   2  : Error / insufficient privileges
#
# Usage:
#   sudo bash rootkit_detect_scanner_ubuntu_v1.0u.sh
#   sudo bash rootkit_detect_scanner_ubuntu_v1.0u.sh -o /var/log/rootkit_scan.log
#   sudo bash rootkit_detect_scanner_ubuntu_v1.0u.sh --plura
#
# Notes:
#   - Run as root to access filesystem tools and system directories.
#   - On Ubuntu minimal images, you may need:
#       * e2fsprogs (debugfs) for ext*
#       * xfsprogs (xfs_db) for xfs
#       * btrfs-progs for btrfs
#       * binutils (strings, objdump, readelf) for module analysis
#
# Optional env:
#   PLURA_DEBUG=1  -> print extra diagnostics to stderr

set -u
set -o pipefail

VERSION="1.0u"
REVISION="2025-12-25-u1"
SCHEMA="rootkit_detect_scanner_plura_v1"

FORMAT="text"   # text | plura
OUTFILE=""      # if set, append sanitized output
RUN_ID=""

# Behavior knobs
VISIBLE_FILE_ANALYSIS=0   # 1 = also analyze visible files for insmod strings
NO_COLOR=0

# Findings
HIDDEN_FOUND=0; ROOTKIT_FOUND=0; BACKDOOR_FOUND=0
HIDDEN_LIST=()
ROOTKIT_LIST=()
BACKDOOR_LIST=()

# Per-module analysis temps
ROOTKIT_NAME=""
BACKDOOR_PATH=""
MODULE_NAME=""
PROC_ENTRY=""

have_cmd() { command -v "$1" >/dev/null 2>&1; }
is_tty() { [[ -t 1 ]]; }

debug() {
  if [[ "${PLURA_DEBUG:-0}" == "1" ]]; then
    printf '[PLURA_DEBUG] %s\n' "$*" >&2
  fi
}

usage() {
  cat <<'USAGE'
Rootkit Detection Scanner (Linux) - Ubuntu/Debian Edition

Options:
  --plura, --kv               Output logfmt-like key=value lines (ingest-friendly)
  -o, --output <file>         Append a sanitized copy of output to <file>
  --visible-analysis          Also analyze visible files for insmod strings (may increase noise)
  --no-color                  Disable ANSI colors
  --run-id <id>               Set run_id to correlate logs
  -h, --help                  Show help

Examples:
  sudo bash rootkit_detect_scanner_ubuntu_v1.0u.sh
  sudo bash rootkit_detect_scanner_ubuntu_v1.0u.sh -o /var/log/rootkit_scan.log
  sudo bash rootkit_detect_scanner_ubuntu_v1.0u.sh --plura
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plura|--kv) FORMAT="plura"; shift ;;
    -o|--output)
      [[ $# -lt 2 ]] && { echo "ERROR: --output requires a file path" >&2; exit 2; }
      OUTFILE="$2"; shift 2 ;;
    --visible-analysis)
      VISIBLE_FILE_ANALYSIS=1; shift ;;
    --no-color)
      NO_COLOR=1; shift ;;
    --run-id)
      [[ $# -lt 2 ]] && { echo "ERROR: --run-id requires a value" >&2; exit 2; }
      RUN_ID="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "ERROR: Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

# Colors (only when tty and not disabled)
if is_tty && [[ "$NO_COLOR" -eq 0 ]]; then
  RED=$(tput setaf 1 2>/dev/null || true)
  GREEN=$(tput setaf 2 2>/dev/null || true)
  YELLOW=$(tput setaf 3 2>/dev/null || true)
  BLUE=$(tput setaf 4 2>/dev/null || true)
  RESET=$(tput sgr0 2>/dev/null || true)
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; RESET=""
fi

# Output helper: stdout + optional sanitized file copy
sanitize_ansi() {
  # strip common ANSI escape sequences
  sed -e 's/\x1b\[[0-9;]*[a-zA-Z]//g' -e 's/\x1b(B//g'
}

emit() {
  # Always stdout for PLURA ingest; debug to stderr only
  local line="$1"
  printf '%s\n' "$line"
  if [[ -n "$OUTFILE" ]]; then
    mkdir -p "$(dirname "$OUTFILE")" 2>/dev/null || true
    printf '%s\n' "$line" | sanitize_ansi >> "$OUTFILE" 2>/dev/null || true
  fi
}

need_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "${RED}[ERROR]${RESET} Run as root(uid=0)" >&2
    exit 2
  fi
  debug "Running with root privileges (uid=0)"
}

get_ip_addr() {
  local ip=""
  if have_cmd ip; then
    ip=$(ip -4 addr show 2>/dev/null | awk '/inet / && $2 !~ /^127\./ {print $2}' | cut -d/ -f1 | head -n1)
  elif have_cmd ifconfig; then
    ip=$(ifconfig 2>/dev/null | awk '/inet / && $2 !~ /^127\./ {print $2}' | sed 's/addr://g' | head -n1)
  fi
  echo "${ip:-unknown_ip}"
}

HOSTNAME_STR="$(hostname 2>/dev/null || echo unknown_host)"
IP_STR="$(get_ip_addr)"
TS_ISO="$(date -Is 2>/dev/null || date)"
KERNEL_STR="$(uname -r 2>/dev/null || echo Unknown)"
ARCH_STR="$(uname -m 2>/dev/null || echo Unknown)"
OS_STR="Unknown OS"
if [[ -f /etc/os-release ]]; then
  OS_STR="$(grep "^PRETTY_NAME=" /etc/os-release 2>/dev/null | cut -d'"' -f2)"
elif [[ -f /etc/lsb-release ]]; then
  OS_STR="$(grep "^DISTRIB_DESCRIPTION=" /etc/lsb-release 2>/dev/null | cut -d'=' -f2 | tr -d '"')"
elif [[ -f /etc/debian_version ]]; then
  OS_STR="Debian $(cat /etc/debian_version 2>/dev/null)"
fi

RUN_ID="${RUN_ID:-$(date +%s 2>/dev/null || echo 0)-$$}"

file_details_kv() {
  # prints: mtime=... ctime=... md5=... sha256=...
  local path="$1"
  local mtime="N/A" ctime="N/A" md5="N/A" sha256="N/A"
  if [[ -e "$path" ]]; then
    mtime="$(stat -c %y "$path" 2>/dev/null || echo N/A)"
    ctime="$(stat -c %z "$path" 2>/dev/null || echo N/A)"
    if [[ -f "$path" ]]; then
      have_cmd md5sum && md5="$(md5sum "$path" 2>/dev/null | awk '{print $1}' || echo N/A)"
      have_cmd sha256sum && sha256="$(sha256sum "$path" 2>/dev/null | awk '{print $1}' || echo N/A)"
    fi
  fi
  printf '%s\t%s\t%s\t%s\n' "$mtime" "$ctime" "$md5" "$sha256"
}

# -----------------------------
# PLURA logfmt helpers
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
kv_emit() { emit "${KV_LINE% }"; KV_LINE=""; }

# -----------------------------
# Report helpers
# -----------------------------
report_hidden() {
  local path="$1"
  if [[ ${#HIDDEN_LIST[@]} -eq 0 ]] || [[ ! " ${HIDDEN_LIST[*]} " =~ " ${path} " ]]; then
    HIDDEN_LIST+=("$path")
  fi
  HIDDEN_FOUND=1
  emit "  ${RED}[!]${RESET} Hidden Entry File: ${RED}$path${RESET}"
}

report_deleted() {
  local path="$1"
  emit "  ${YELLOW}[!]${RESET} Deleted File: ${YELLOW}$path${RESET}"
}

# -----------------------------
# Rootkit module extraction (from insmod strings)
# -----------------------------
extract_insmod_targets() {
  # Input: file path (startup entry)
  # Output: one module path per line (best effort)
  local full_path="$1"
  [[ -f "$full_path" ]] || return 0
  have_cmd strings || { debug "strings missing -> skip insmod extraction for $full_path"; return 0; }

  # Extract plausible "insmod ..." command fragments
  # We then parse tokens and skip options (-f, --foo, etc)
  strings "$full_path" 2>/dev/null | grep -E "insmod[[:space:]]+" | while IFS= read -r line; do
    # keep substring from first "insmod"
    local rest="${line#*insmod}"
    rest="$(printf '%s' "$rest" | sed 's/^[[:space:]]\+//')"

    local tok=""
    local target=""
    for tok in $rest; do
      # skip obvious options
      if [[ "$tok" == -* ]]; then
        continue
      fi
      target="$tok"
      break
    done

    [[ -n "$target" ]] && printf '%s\n' "$target"
  done | sort -u
}

find_rootkit_module() {
  local full_path="$1"
  local file_type="${2:-normal}"

  local targets=()
  mapfile -t targets < <(extract_insmod_targets "$full_path")
  [[ ${#targets[@]} -eq 0 ]] && return 0

  for target in "${targets[@]}"; do
    # Normalize relative paths (fix: add missing '/')
    if [[ "$target" != /* ]]; then
      local base
      base="$(dirname "$full_path")"
      # strip leading ./ for nicer join
      target="${target#./}"
      target="$base/$target"
    fi

    ROOTKIT_FOUND=1
    if [[ ${#ROOTKIT_LIST[@]} -eq 0 ]] || [[ ! " ${ROOTKIT_LIST[*]} " =~ " ${target} " ]]; then
      ROOTKIT_LIST+=("$target")
    fi

    if [[ "$file_type" == "hidden" ]]; then
      emit "  [+] Found insmod in hidden entry file: ${RED}$full_path${RESET}"
      emit "    ${RED}[!]${RESET} Suspicious Rootkit Found : ${RED}$target${RESET}"
    else
      emit "  [+] Found insmod in entry file: ${YELLOW}$full_path${RESET}"
      emit "    ${RED}[!]${RESET} Suspicious Rootkit Found : ${RED}$target${RESET}"
    fi

    # Optional: scan module strings for suspicious paths/URLs
    have_cmd strings || continue
    while IFS= read -r line; do
      # FIX: should be AND (skip unless it contains '//' OR starts with '/')
      [[ "$line" != *"//"* && "$line" != /* ]] && continue
      local cand
      cand="$(echo "$line" | xargs 2>/dev/null || echo "$line")"
      [[ -z "$cand" ]] && continue
      BACKDOOR_FOUND=1
      if [[ ${#BACKDOOR_LIST[@]} -eq 0 ]] || [[ ! " ${BACKDOOR_LIST[*]} " =~ " ${cand} " ]]; then
        BACKDOOR_LIST+=("$cand")
      fi
      emit "    ${RED}[!]${RESET} Suspicious Backdoor String: ${RED}$cand${RESET}"
    done < <(strings "$target" 2>/dev/null || true)
  done
}

# -----------------------------
# Filesystem raw scan
# -----------------------------
SCAN_TOTAL=0
SCAN_SCANNED=0
SCAN_SKIPPED=0
SCAN_SKIPPED_REASONS=()

scan_fs_dir() {
  local TARGET_PATH="$1"

  [[ -d "$TARGET_PATH" ]] || { debug "Missing dir: $TARGET_PATH"; return 0; }
  SCAN_TOTAL=$((SCAN_TOTAL + 1))

  local FS="" FSTYPE=""
  read -r FS FSTYPE <<<"$(df -T "$TARGET_PATH" 2>/dev/null | awk 'NR==2 { print $1, $2 }')"
  [[ -n "$FS" && -n "$FSTYPE" ]] || { SCAN_SKIPPED=$((SCAN_SKIPPED+1)); SCAN_SKIPPED_REASONS+=("$TARGET_PATH:df_failed"); return 0; }

  local TARGET_INODE=""
  TARGET_INODE="$(stat -c %i "$TARGET_PATH" 2>/dev/null || true)"
  [[ -n "$TARGET_INODE" ]] || { SCAN_SKIPPED=$((SCAN_SKIPPED+1)); SCAN_SKIPPED_REASONS+=("$TARGET_PATH:stat_failed"); return 0; }

  local LS_LIST=""
  LS_LIST="$(ls -a "$TARGET_PATH" 2>/dev/null | sort || true)"

  emit "[*] DIR: $TARGET_PATH, FS=$FS, FSTYPE=$FSTYPE, TARGET_INODE=$TARGET_INODE"

  local FS_LIST=""
  case "$FSTYPE" in
    xfs)
      if ! have_cmd xfs_db; then
        emit "[!] xfs_db not found. Install: apt-get install xfsprogs  (skip $TARGET_PATH)"
        SCAN_SKIPPED=$((SCAN_SKIPPED+1)); SCAN_SKIPPED_REASONS+=("$TARGET_PATH:xfs_db_missing")
        return 0
      fi

      local DBLOCKS=""
      DBLOCKS="$(xfs_db -r "$FS" -c "inode $TARGET_INODE" -c "print" 2>/dev/null | awk '/nblocks/ {print $3}')"
      if [[ -z "$DBLOCKS" || "$DBLOCKS" -eq 0 ]]; then
        FS_LIST="$(xfs_db -r "$FS" -c "inode $TARGET_INODE" -c "print" 2>/dev/null | awk -F'"' '/name/ {print $2}' | grep -v '^$' | sort || true)"
      else
        FS_LIST="$(
          for i in $(seq 0 $((DBLOCKS-1))); do
            xfs_db -r "$FS" -c "inode $TARGET_INODE" -c "dblock $i" -c "print" 2>/dev/null | awk -F'"' '/name/ {print $2}'
          done | grep -v '^$' | sort
        )"
      fi
      ;;
    ext2|ext3|ext4)
      if ! have_cmd debugfs; then
        emit "[!] debugfs not found. Install: apt-get install e2fsprogs  (skip $TARGET_PATH)"
        SCAN_SKIPPED=$((SCAN_SKIPPED+1)); SCAN_SKIPPED_REASONS+=("$TARGET_PATH:debugfs_missing")
        return 0
      fi

      FS_LIST="$(debugfs -R "ls -l <$TARGET_INODE>" "$FS" 2>/dev/null \
        | awk 'NF>=8 {print $NF}' \
        | grep -v '^$' \
        | sort || true)"
      ;;
    btrfs)
      if ! have_cmd btrfs; then
        emit "[!] btrfs command not found. Install: apt-get install btrfs-progs  (skip $TARGET_PATH)"
        SCAN_SKIPPED=$((SCAN_SKIPPED+1)); SCAN_SKIPPED_REASONS+=("$TARGET_PATH:btrfs_missing")
        return 0
      fi

      FS_LIST="$(btrfs inspect-internal dump-tree "$FS" 2>/dev/null \
        | awk -v inode="$TARGET_INODE" '
          /DIR_ITEM/ && $0 ~ ("key \\("inode" DIR_ITEM") {show=1}
          show && /location key/ {is_subvol=($0 ~ /ROOT_ITEM/) }
          show && /name:/ {
            sub(/.*name: /,"")
            name=$0
            if (!is_subvol) {print name}
            show=0; is_subvol=0
          }' \
        | grep -v '^$' \
        | sort || true)"
      ;;
    *)
      emit "[!] Filesystem type '$FSTYPE' not supported for raw entry scan at $TARGET_PATH (skip)."
      SCAN_SKIPPED=$((SCAN_SKIPPED+1)); SCAN_SKIPPED_REASONS+=("$TARGET_PATH:unsupported_fs=$FSTYPE")
      return 0
      ;;
  esac

  # If we got here, we attempted a scan (even if FS_LIST is empty)
  SCAN_SCANNED=$((SCAN_SCANNED + 1))

  # Normalize escaped slashes (best effort)
  local FS_LIST_NORMALIZED=""
  local tmp
  tmp="$(echo "$FS_LIST" | sed 's/\\x5c/\\/g')"
  if [[ "$tmp" != "$FS_LIST" ]]; then
    FS_LIST_NORMALIZED="$tmp"
  else
    FS_LIST_NORMALIZED="$(echo "$FS_LIST" | sed 's/\\\\x/\\x/g')"
  fi

  local hidden_files=""
  hidden_files="$(comm -23 <(echo "$FS_LIST_NORMALIZED" | sort) <(echo "$LS_LIST" | sort) || true)"
  if [[ -n "$hidden_files" ]]; then
    while IFS= read -r file; do
      [[ -z "$file" || "$file" == "." || "$file" == ".." || "$file" == "selinux" ]] && continue
      local full_path="$TARGET_PATH$file"
      if [[ -e "$full_path" ]]; then
        report_hidden "$full_path"
        find_rootkit_module "$full_path" "hidden"
      else
        report_deleted "$full_path"
      fi
    done <<< "$hidden_files"
  fi

  if [[ "$VISIBLE_FILE_ANALYSIS" -eq 1 ]]; then
    local visible_files="$LS_LIST"
    if [[ -n "$visible_files" ]]; then
      while IFS= read -r file; do
        [[ -z "$file" || "$file" == "." || "$file" == ".." || "$file" == "selinux" ]] && continue
        local full_path="$TARGET_PATH$file"
        [[ -f "$full_path" ]] && find_rootkit_module "$full_path" "normal"
      done <<< "$visible_files"
    fi
  fi
}

scan_fs() {
  emit "${BLUE}============================================================${RESET}"
  emit "${BLUE}[+] Detecting Suspicious file (scan_fs)${RESET}"
  emit "${BLUE}============================================================${RESET}"

  # Ubuntu/Debian runlevel dirs are often present; include more than rev1
  local TARGET_DIRS=(
    "/etc/systemd/system/"
    "/etc/init.d/"
    "/etc/rcS.d/"
    "/etc/rc0.d/"
    "/etc/rc1.d/"
    "/etc/rc2.d/"
    "/etc/rc3.d/"
    "/etc/rc4.d/"
    "/etc/rc5.d/"
    "/etc/rc6.d/"
  )

  for TARGET_PATH in "${TARGET_DIRS[@]}"; do
    if [[ ! -d "$TARGET_PATH" ]]; then
      emit "[!] Target directory '$TARGET_PATH' does not exist. Skipping."
      continue
    fi
    scan_fs_dir "$TARGET_PATH"
  done

  # Coverage warning to prevent false confidence
  if [[ "$SCAN_SCANNED" -eq 0 ]]; then
    emit "${YELLOW}[WARN]${RESET} Raw filesystem scan coverage is 0 (all directories skipped)."
    emit "       Install tools: e2fsprogs (debugfs), xfsprogs (xfs_db), btrfs-progs (btrfs)"
  fi
}

# -----------------------------
# Rootkit module deep(er) analysis (best effort)
# -----------------------------
find_section_offset() {
  local section="$1"
  local section_offset=""

  # More robust readelf parsing than the original (section name match)
  if ! have_cmd readelf; then
    echo ""
    return
  fi

  # readelf -S output: [Nr] Name Type Address Off Size ...
  # We match the Name column (2nd after bracket), but spacing varies; use awk.
  section_offset="$(
    readelf -S --wide "$ROOTKIT_NAME" 2>/dev/null \
      | awk -v sec="$section" '
        $0 ~ /^\s*\[[ 0-9]+\]/ {
          # Name is field 2, Off is typically field 6, but we search hex tokens.
          name=$2
          if (name==sec) {
            # Print the last hex token in the line as a fallback.
            for (i=1;i<=NF;i++) if ($i ~ /^[0-9a-fA-F]{6,16}$/ && $i!="0" && $i!="00000000" && $i!="0000000000000000") last=$i
            if (last!="") {print last; exit}
          }
        }'
  )"

  if [[ -z "$section_offset" ]]; then
    # Fallback: any rodata section
    section_offset="$(
      readelf -S --wide "$ROOTKIT_NAME" 2>/dev/null \
        | awk '
          $0 ~ /\.rodata/ {
            for (i=1;i<=NF;i++) if ($i ~ /^[0-9a-fA-F]{6,16}$/ && $i!="0" && $i!="00000000" && $i!="0000000000000000") last=$i
            if (last!="") {print last; exit}
          }'
    )"
  fi

  echo "$section_offset"
}

extract_string_from_offset() {
  local section="$1"
  local offset="$2"
  local count="${3:-200}"

  local section_offset
  section_offset="$(find_section_offset "$section")"
  [[ -n "$section_offset" ]] || return 0

  local section_dec
  section_dec="$(printf "%d" "0x$section_offset" 2>/dev/null || echo "")"
  [[ -n "$section_dec" ]] || return 0

  local abs_skip="$section_dec"
  if [[ -n "$offset" ]]; then
    local off_dec
    off_dec="$(printf "%d" "0x$offset" 2>/dev/null || echo "")"
    [[ -n "$off_dec" ]] && abs_skip=$((section_dec + off_dec))
  fi

  dd if="$ROOTKIT_NAME" bs=1 skip="$abs_skip" count="$count" 2>/dev/null | strings 2>/dev/null | head -n1
}

analyze_function_calls() {
  local func_name="$1"
  have_cmd objdump || { debug "objdump missing -> skip func analysis ($func_name)"; return 0; }
  have_cmd readelf || { debug "readelf missing -> skip func analysis ($func_name)"; return 0; }
  have_cmd dd || { debug "dd missing -> skip func analysis ($func_name)"; return 0; }
  have_cmd strings || { debug "strings missing -> skip func analysis ($func_name)"; return 0; }

  local call_locations=""
  call_locations="$(objdump -drw "$ROOTKIT_NAME" 2>/dev/null | grep -n "$func_name" || true)"
  [[ -n "$call_locations" ]] || return 0

  while IFS= read -r call_line; do
    [[ -z "$call_line" ]] && continue
    local line_number
    line_number="$(echo "$call_line" | cut -d: -f1)"
    [[ -n "$line_number" ]] || continue

    local start_line=$((line_number - 20))
    local end_line=$((line_number + 10))
    local call_context=""
    call_context="$(objdump -drw "$ROOTKIT_NAME" 2>/dev/null | sed -n "${start_line},${end_line}p")"

    local rodata_refs=""
    rodata_refs="$(echo "$call_context" | grep ".rodata" | sort -u || true)"
    [[ -n "$rodata_refs" ]] || continue

    local processed=""
    while IFS= read -r ref_line; do
      [[ -z "$ref_line" ]] && continue

      local section offset key extracted_string
      section="$(echo "$ref_line" | grep -o "\.rodata[^+[:space:]]*" | head -n1 || true)"
      offset="$(echo "$ref_line" | grep -o "+0x[0-9a-fA-F]*" | sed 's/+0x//' | head -n1 || true)"
      [[ -n "$section" ]] || continue

      key="${section}+${offset}"
      echo "$processed" | grep -qF "$key" && continue
      processed="$processed $key"

      extracted_string="$(extract_string_from_offset "$section" "$offset" 200 || true)"
      [[ -n "$extracted_string" ]] || continue

      if [[ "$func_name" == "call_usermodehelper" ]]; then
        if [[ "$extracted_string" == /* && "$extracted_string" != "/bin/sh" && "$extracted_string" != "/bin/bash" ]]; then
          BACKDOOR_PATH="$extracted_string"
          BACKDOOR_FOUND=1
          if [[ ${#BACKDOOR_LIST[@]} -eq 0 ]] || [[ ! " ${BACKDOOR_LIST[*]} " =~ " ${BACKDOOR_PATH} " ]]; then
            BACKDOOR_LIST+=("$BACKDOOR_PATH")
          fi
          return 0
        fi
      elif [[ "$func_name" == "proc_create" || "$func_name" == "create_proc_entry" ]]; then
        if [[ "$extracted_string" == *"/"* && -z "$PROC_ENTRY" ]]; then
          PROC_ENTRY="$extracted_string"
          return 0
        fi
      fi
    done <<< "$rodata_refs"
  done <<< "$call_locations"
}

extract_module_info() {
  have_cmd readelf || return 0
  have_cmd dd || return 0
  have_cmd strings || return 0

  # Best-effort: find a gnu linkonce section offset and read strings
  local gnu_section_offset=""
  gnu_section_offset="$(readelf -S --wide "$ROOTKIT_NAME" 2>/dev/null | awk '/gnu.*linkonce/ {print $6; exit}' | head -n1)"
  [[ -n "$gnu_section_offset" && "$gnu_section_offset" != "00000000" && "$gnu_section_offset" != "0" ]] || return 0

  local offset_dec
  offset_dec="$(printf "%d" "0x$gnu_section_offset" 2>/dev/null || echo "")"
  [[ -n "$offset_dec" ]] || return 0

  local module_name=""
  module_name="$(dd if="$ROOTKIT_NAME" bs=1 skip="$offset_dec" count=64 2>/dev/null | strings 2>/dev/null | head -n1)"
  [[ -n "$module_name" ]] && MODULE_NAME="$module_name"
}

extract_vermagic_info() {
  have_cmd strings || { echo ""; return 0; }
  strings "$ROOTKIT_NAME" 2>/dev/null | grep "vermagic=" | head -n1 | sed 's/vermagic=//'
}

p_rootkit_info() {
  local rootkit="$1"
  [[ -e "$rootkit" ]] || { emit " - ${YELLOW}File Not Found!${RESET}"; return 0; }

  ROOTKIT_NAME="$rootkit"
  MODULE_NAME=""; PROC_ENTRY=""; BACKDOOR_PATH=""

  if ! have_cmd objdump || ! have_cmd readelf || ! have_cmd dd || ! have_cmd strings; then
    emit "${YELLOW}[!][SKIP]${RESET} Missing analysis commands (install: apt-get install binutils)."
    return 0
  fi

  extract_module_info
  if [[ -z "$MODULE_NAME" ]]; then
    emit "${YELLOW}[!]${RESET} Unable to extract module name. Skipping further analysis."
    return 0
  fi

  analyze_function_calls "proc_create"
  [[ -z "$PROC_ENTRY" ]] && analyze_function_calls "create_proc_entry"
  analyze_function_calls "call_usermodehelper"

  emit " - Invisible Rootkit Module Name: ${MODULE_NAME:-Not found}"
  emit " - Proc Entry: /proc/${PROC_ENTRY:-Not found}"
  emit " - Backdoor Path: ${RED}${BACKDOOR_PATH:-Not found}${RESET}"

  local vermagic=""
  vermagic="$(extract_vermagic_info || true)"
  if [[ -n "$vermagic" ]]; then
    emit " - Module Version Magic: $vermagic"
  else
    emit " - Module Version Magic: ${YELLOW}Not found${RESET}"
  fi
}

# -----------------------------
# Main
# -----------------------------
main_text() {
  emit "${BLUE}============================================================${RESET}"
  emit "${BLUE}     Rootkit Detection Scanner (Ubuntu/Debian) v${VERSION}${RESET}"
  emit "${BLUE}============================================================${RESET}"

  need_root

  emit "${BLUE}============================================================${RESET}"
  emit "${BLUE}[+] System Information${RESET}"
  emit "${BLUE}============================================================${RESET}"
  emit " - Timestamp: $TS_ISO"
  emit " - RunID: $RUN_ID"
  emit " - Hostname: $HOSTNAME_STR"
  emit " - IP: $IP_STR"
  emit " - Kernel: $KERNEL_STR"
  emit " - OS: $OS_STR  $ARCH_STR"
  emit " - Version: $VERSION"
  emit " - Revision: $REVISION"
  emit

  scan_fs
  emit
  emit "${BLUE}============================================================${RESET}"
  emit "${BLUE}                        SCAN RESULT${RESET}"
  emit "${BLUE}============================================================${RESET}"

  if [[ "$HIDDEN_FOUND" -eq 0 ]]; then
    emit "${GREEN}[OK]${RESET} No Hidden Entry"
  else
    emit "${RED}[Alert]${RESET} Hidden Entry Found!"
    for hidden in "${HIDDEN_LIST[@]}"; do
      emit "${RED}[!]${RESET} FilePath: ${RED}$hidden${RESET}"
      read -r mtime ctime md5 sha256 < <(file_details_kv "$hidden")
      emit " - Modified: $mtime"
      emit " - Changed: $ctime"
      emit " - MD5: $md5"
      emit " - SHA256: $sha256"
    done
  fi

  if [[ "$ROOTKIT_FOUND" -eq 0 ]]; then
    emit "${GREEN}[OK]${RESET} Rootkit Not Found"
  else
    emit "${RED}[Alert]${RESET} Suspicious Rootkit Found!"
    for rootkit in "${ROOTKIT_LIST[@]}"; do
      emit "${RED}[!]${RESET} FilePath: ${RED}$rootkit${RESET}"
      read -r mtime ctime md5 sha256 < <(file_details_kv "$rootkit")
      emit " - Modified: $mtime"
      emit " - Changed: $ctime"
      emit " - MD5: $md5"
      emit " - SHA256: $sha256"
      emit "${BLUE}-------------- Rootkit File Analysis -------------${RESET}"
      p_rootkit_info "$rootkit"
      emit "${BLUE}--------------------------------------------------${RESET}"
    done
  fi

  if [[ "$BACKDOOR_FOUND" -eq 0 ]]; then
    emit "${GREEN}[OK]${RESET} Backdoor Not Found"
  else
    emit "${RED}[Alert]${RESET} Backdoor Found!"
    for backdoor in "${BACKDOOR_LIST[@]}"; do
      emit "${RED}[!]${RESET} Indicator: ${RED}$backdoor${RESET}"
      # If it's a path and exists, add file details
      if [[ "$backdoor" == /* && -e "$backdoor" ]]; then
        read -r mtime ctime md5 sha256 < <(file_details_kv "$backdoor")
        emit " - Modified: $mtime"
        emit " - Changed: $ctime"
        emit " - MD5: $md5"
        emit " - SHA256: $sha256"
      fi
    done
  fi

  emit
  emit "${BLUE}============================================================${RESET}"
  emit "${BLUE}[*] Scan Coverage${RESET}"
  emit "${BLUE}============================================================${RESET}"
  emit " - Target dirs (exists): $SCAN_TOTAL"
  emit " - Raw scanned: $SCAN_SCANNED"
  emit " - Skipped: $SCAN_SKIPPED"
  if [[ "$SCAN_SKIPPED" -gt 0 && "${PLURA_DEBUG:-0}" == "1" ]]; then
    for r in "${SCAN_SKIPPED_REASONS[@]}"; do
      emit " - SkippedReason: $r"
    done
  fi

  emit
  emit "${BLUE}============================================================${RESET}"
  emit "${BLUE}[*] Scan Complete!${RESET}"
  emit "${BLUE}============================================================${RESET}"

  # Exit code mapping
  local code=0
  if [[ "$HIDDEN_FOUND" -eq 1 ]]; then code=$((code + 10)); fi
  if [[ "$ROOTKIT_FOUND" -eq 1 ]]; then code=$((code + 20)); fi
  if [[ "$BACKDOOR_FOUND" -eq 1 ]]; then code=$((code + 30)); fi
  # Normalize to 40 when multiple
  if (( code != 0 && code != 10 && code != 20 && code != 30 )); then
    code=40
  fi
  return "$code"
}

main_plura() {
  need_root

  # header
  kv_reset
  kv_add "plura_schema" "$SCHEMA"
  kv_add "plura_event" "header"
  kv_add "tool" "rootkit_detect_scanner"
  kv_add "run_id" "$RUN_ID"
  kv_add "ts" "$TS_ISO"
  kv_add "host" "$HOSTNAME_STR"
  kv_add "ip" "$IP_STR"
  kv_add "kernel" "$KERNEL_STR"
  kv_add "os" "$OS_STR"
  kv_add "arch" "$ARCH_STR"
  kv_add "version" "$VERSION"
  kv_add "revision" "$REVISION"
  kv_add "visible_analysis" "$VISIBLE_FILE_ANALYSIS"
  kv_emit

  scan_fs

  # findings
  local hidden_cnt="${#HIDDEN_LIST[@]}"
  local rootkit_cnt="${#ROOTKIT_LIST[@]}"
  local backdoor_cnt="${#BACKDOOR_LIST[@]}"

  for hidden in "${HIDDEN_LIST[@]}"; do
    read -r mtime ctime md5 sha256 < <(file_details_kv "$hidden")
    kv_reset
    kv_add "plura_schema" "$SCHEMA"
    kv_add "plura_event" "finding"
    kv_add "tool" "rootkit_detect_scanner"
    kv_add "run_id" "$RUN_ID"
    kv_add "ts" "$TS_ISO"
    kv_add "category" "HiddenEntry"
    kv_add "path" "$hidden"
    kv_add "mtime" "$mtime"
    kv_add "ctime" "$ctime"
    kv_add "md5" "$md5"
    kv_add "sha256" "$sha256"
    kv_emit
  done

  for rootkit in "${ROOTKIT_LIST[@]}"; do
    read -r mtime ctime md5 sha256 < <(file_details_kv "$rootkit")

    # best-effort module analysis (won't fail the run)
    ROOTKIT_NAME="$rootkit"
    MODULE_NAME=""; PROC_ENTRY=""; BACKDOOR_PATH=""
    extract_module_info || true
    [[ -n "$MODULE_NAME" ]] && analyze_function_calls "proc_create" || true
    [[ -n "$MODULE_NAME" && -z "$PROC_ENTRY" ]] && analyze_function_calls "create_proc_entry" || true
    [[ -n "$MODULE_NAME" ]] && analyze_function_calls "call_usermodehelper" || true
    local vermagic=""
    vermagic="$(extract_vermagic_info || true)"

    kv_reset
    kv_add "plura_schema" "$SCHEMA"
    kv_add "plura_event" "finding"
    kv_add "tool" "rootkit_detect_scanner"
    kv_add "run_id" "$RUN_ID"
    kv_add "ts" "$TS_ISO"
    kv_add "category" "RootkitModule"
    kv_add "path" "$rootkit"
    kv_add "mtime" "$mtime"
    kv_add "ctime" "$ctime"
    kv_add "md5" "$md5"
    kv_add "sha256" "$sha256"
    [[ -n "$MODULE_NAME" ]] && kv_add "module_name" "$MODULE_NAME"
    [[ -n "$PROC_ENTRY" ]] && kv_add "proc_entry" "$PROC_ENTRY"
    [[ -n "$BACKDOOR_PATH" ]] && kv_add "backdoor_path" "$BACKDOOR_PATH"
    [[ -n "$vermagic" ]] && kv_add "vermagic" "$vermagic"
    kv_emit
  done

  for backdoor in "${BACKDOOR_LIST[@]}"; do
    kv_reset
    kv_add "plura_schema" "$SCHEMA"
    kv_add "plura_event" "finding"
    kv_add "tool" "rootkit_detect_scanner"
    kv_add "run_id" "$RUN_ID"
    kv_add "ts" "$TS_ISO"
    kv_add "category" "BackdoorIndicator"
    kv_add "indicator" "$backdoor"
    kv_emit
  done

  # summary + exit code mapping
  local code=0
  [[ "$HIDDEN_FOUND" -eq 1 ]] && code=$((code + 10))
  [[ "$ROOTKIT_FOUND" -eq 1 ]] && code=$((code + 20))
  [[ "$BACKDOOR_FOUND" -eq 1 ]] && code=$((code + 30))
  if (( code != 0 && code != 10 && code != 20 && code != 30 )); then
    code=40
  fi

  kv_reset
  kv_add "plura_schema" "$SCHEMA"
  kv_add "plura_event" "summary"
  kv_add "tool" "rootkit_detect_scanner"
  kv_add "run_id" "$RUN_ID"
  kv_add "ts" "$TS_ISO"
  kv_add "hidden_count" "$hidden_cnt"
  kv_add "rootkit_count" "$rootkit_cnt"
  kv_add "backdoor_count" "$backdoor_cnt"
  kv_add "scan_total_dirs" "$SCAN_TOTAL"
  kv_add "scan_scanned" "$SCAN_SCANNED"
  kv_add "scan_skipped" "$SCAN_SKIPPED"
  kv_add "exit_code" "$code"
  kv_emit

  return "$code"
}

if [[ "$FORMAT" == "plura" ]]; then
  main_plura
  exit $?
else
  main_text
  exit $?
fi
