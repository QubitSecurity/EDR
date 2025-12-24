#!/usr/bin/env bash
# Rootkit Detection Scanner v1.0-rev1

set -u


RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3); BLUE=$(tput setaf 4); RESET=$(tput sgr0)
HIDDEN_FOUND=0; ROOTKIT_FOUND=0; BACKDOOR_FOUND=0
HIDDEN_LIST=()
ROOTKIT_LIST=()
BACKDOOR_LIST=()

ROOTKIT_NAME=""
BACKDOOR_PATH=""
MODULE_NAME=""
PROC_ENTRY=""

VISIBLE_FILE_ANALYSIS=0

have_cmd() { command -v "$1" >/dev/null 2>&1; }

get_ip_addr() {
    local ip
    if have_cmd ip; then
        ip=$(ip -4 addr show | awk '/inet / && $2 !~ /^127\./ {print $2}' | cut -d/ -f1 | head -n1)
    elif have_cmd ifconfig; then
        ip=$(ifconfig | awk '/inet / && $2 !~ /^127\./ {print $2}' | sed 's/addr://g' | head -n1)
    fi
    echo "${ip:-unknown_ip}"
}

HOSTNAME_STR="$(hostname)"
IP_STR="$(get_ip_addr)"
TIME_STR="$(date '+%Y%m%d_%H%M%S')"
LOG_FILE="${HOSTNAME_STR}_${IP_STR}_result_${TIME_STR}.log"

log() {
    echo "$1" >&2
    echo "$1" | sed -e 's/\x1b\[[0-9;]*[a-zA-Z]//g' -e 's/\x1b(B//g' >> "$LOG_FILE" 2>/dev/null || true
}

need_root() {
  [[ $(id -u) -ne 0 ]] && { echo "${RED}[ERROR]${RESET} Run as root(uid=0)"; exit 1; }
  log "${GREEN}[OK]${RESET} Running with root privileges (uid=0)"
}



get_system_info() {
    local kernel_version=$(uname -r 2>/dev/null || echo "Unknown")
    local machine_arch=$(uname -m 2>/dev/null || echo "Unknown")
    local os_release=""
    if [[ -f /etc/os-release ]]; then
        os_release=$(grep "^PRETTY_NAME=" /etc/os-release 2>/dev/null | cut -d'"' -f2)
    elif [[ -f /etc/redhat-release ]]; then
        os_release=$(cat /etc/redhat-release 2>/dev/null)
    elif [[ -f /etc/debian_version ]]; then
        os_release="Debian $(cat /etc/debian_version 2>/dev/null)"
    else
        os_release="Unknown OS"
    fi

    log "${BLUE}============================================================${RESET}" 
    log "${BLUE}[+] System Information${RESET}"
    log "${BLUE}============================================================${RESET}"    
    log " - Hostname: $HOSTNAME_STR"
    log " - IP: $IP_STR"
    log " - Kernel: $kernel_version"
    log " - OS: $os_release  $machine_arch"
}

file_details() {
  local path="$1"
  
  if [[ ! -e "$path" ]]; then
    log " - ${YELLOW}File Not Found!${RESET}"
    return
  fi
  
  local mtime=$(stat -c %y "$path" 2>/dev/null || echo "N/A")
  local chtime=$(stat -c %z "$path" 2>/dev/null || echo "N/A")
  local md5="N/A"; local sha256="N/A"
  [[ -f "$path" ]] && { md5=$(md5sum "$path" | awk '{print $1}'); sha256=$(sha256sum "$path" | awk '{print $1}'); }

  log " - Modified: $mtime"
  log " - Changed: $chtime"
  log " - MD5: $md5"
  log " - SHA256: $sha256"
}

report_hidden() {
  local path="$1"
  if [[ ${#HIDDEN_LIST[@]} -eq 0 ]] || [[ ! " ${HIDDEN_LIST[*]} " =~ " ${path} " ]]; then
    HIDDEN_LIST+=("$path")
  fi
  log "  ${RED}[!]${RESET} Hidden Entry File: ${RED}$path${RESET}"
}

report_deleted() {
    local path="$1"
    log "  ${YELLOW}[!]${RESET} Deleted File: ${YELLOW}$path${RESET}"
}

find_rootkit_module() {
    local full_path="$1"
    local file_type="${2:-normal}"
    
    if [[ -f "$full_path" ]]; then
        local insmods=()
        mapfile -t insmods < <(strings "$full_path" 2>/dev/null | grep -E "insmod[[:space:]]+" | sed -n 's/.*insmod[[:space:]]\+\([^ ]\+\).*/\1/p')
        
        [[ ${#insmods[@]} -eq 0 ]] && return
        for target in "${insmods[@]}"; do
            [[ "$target" != /* ]] && target="$(dirname "$full_path")$target"
            ROOTKIT_FOUND=1
            if [[ ${#ROOTKIT_LIST[@]} -eq 0 ]] || [[ ! " ${ROOTKIT_LIST[*]} " =~ " ${target} " ]]; then
                ROOTKIT_LIST+=("$target")
            fi
            if [[ "$file_type" == "hidden" ]]; then
                log "  [+] Found insmod in hidden entry file: ${RED}$full_path${RESET}"
                log "    ${RED}[!]${RESET} Suspicious Rootkit Found : ${RED}$target${RESET}"
            else
                log "  [+] Found insmod in normal entry file: ${YELLOW}$full_path${RESET}"
                log "    ${RED}[!]${RESET} Suspicious Rootkit Found : ${RED}$target${RESET}"

            fi
            while IFS= read -r line; do
                [[ "$line" != *"//"* || "$line" != /* ]] && continue
                local cand=$(echo "$line" | xargs)
                BACKDOOR_FOUND=1
                if [[ ${#BACKDOOR_LIST[@]} -eq 0 ]] || [[ ! " ${BACKDOOR_LIST[*]} " =~ " ${cand} " ]]; then
                    BACKDOOR_LIST+=("$cand")
                fi
                log "    ${RED}[!]${RESET} Suspicious Backdoor Found: ${RED}$cand ${RESET}"
            done < <(strings "$target" 2>/dev/null)             
        done
    fi
}

scan_fs() {
    log "${BLUE}============================================================${RESET}" 
    log "${BLUE}[+] Detecting Suspicious file (scan_fs)${RESET}"
    log "${BLUE}============================================================${RESET}"

    TARGET_DIRS=(
        "/etc/systemd/system/"
        "/etc/init.d/"
        "/etc/rc2.d/"
        "/etc/rc3.d/"
        "/etc/rc5.d/"
    )

    for TARGET_PATH in "${TARGET_DIRS[@]}"; do
        if [ ! -d "$TARGET_PATH" ]; then
            log "[!] Target directory '$TARGET_PATH' does not exist. Skipping scan."
            continue
        fi

        read FS FSTYPE <<< "$(df -T "$TARGET_PATH" | awk 'NR==2 { print $1, $2 }')"
        TARGET_INODE=$(stat -c %i "$TARGET_PATH")

        LS_LIST=$(ls -a "$TARGET_PATH" | sort)
        log "[*] DIR: $TARGET_PATH, FS=$FS, FSTYPE=$FSTYPE, TARGET_INODE=$TARGET_INODE"

        case "$FSTYPE" in
            xfs)
                if ! command -v xfs_db >/dev/null 2>&1; then
                    log "[!] xfs_db command not found. Cannot scan XFS filesystem at $TARGET_PATH."
                    continue
                fi
                DBLOCKS=$(xfs_db -r "$FS" -c "inode $TARGET_INODE" -c "print" 2>/dev/null \
                    | awk '/nblocks/ {print $3}')
                
                if [[ -z "$DBLOCKS" ]] || [[ "$DBLOCKS" -eq 0 ]]; then
                    FS_LIST=$(xfs_db -r "$FS" -c "inode $TARGET_INODE" -c "print" 2>/dev/null \
                        | awk -F'"' '/name/ {print $2}' | grep -v '^$' | sort)
                else
                    FS_LIST=$(
                        for i in $(seq 0 $((DBLOCKS-1))); do
                            xfs_db -r "$FS" -c "inode $TARGET_INODE" -c "dblock $i" -c "print" 2>/dev/null \
                                | awk -F'"' '/name/ {print $2}'
                        done | grep -v '^$' | sort
                    )
                fi
                ;;
            ext2|ext3|ext4)
                if ! command -v debugfs >/dev/null 2>&1; then
                    log "[!] debugfs command not found. Cannot scan EXT filesystem at $TARGET_PATH."
                    continue
                fi
                FS_LIST=$(debugfs -R "ls -l <$TARGET_INODE>" "$FS" 2>/dev/null \
                    | awk 'NF>=8 {print $NF}' \
                    | grep -v '^$' \
                    | sort)
                ;;
            btrfs)
                if ! command -v btrfs >/dev/null 2>&1; then
                    log "[!] btrfs command not found. Cannot scan BTRFS filesystem at $TARGET_PATH."
                    continue
                fi
                FS_LIST=$(btrfs inspect-internal dump-tree "$FS" 2>/dev/null \
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
                    | sort)
                ;;
            *)
                log "[!] Filesystem type is '$FSTYPE'. Only XFS, EXT2/3/4, and BTRFS are supported for $TARGET_PATH."
                continue
                ;;
        esac

        tmp=$(echo "$FS_LIST" | sed 's/\\x5c/\\/g')
        if [[ "$tmp" != "$FS_LIST" ]]; then
            FS_LIST_NORMALIZED=$tmp
        else
            FS_LIST_NORMALIZED=$(echo "$FS_LIST" | sed 's/\\\\x/\\x/g')
        fi
        
        LS_LIST_NORMALIZED=$(echo "$LS_LIST")
        
        hidden_files=$(comm -23 <(echo "$FS_LIST_NORMALIZED" | sort) <(echo "$LS_LIST_NORMALIZED" | sort))
        if [ -n "$hidden_files" ]; then
            while IFS= read -r file; do
                [[ -z "$file" || "$file" == "." || "$file" == ".." || "$file" == "selinux" ]] && continue
                local full_path="$TARGET_PATH$file"
                
                if [[ -e "$full_path" ]]; then
                    HIDDEN_FOUND=1
                    report_hidden "$full_path"
                    find_rootkit_module "$full_path" "hidden"
                else
                    report_deleted "$full_path"
                fi
            done <<< "$hidden_files"
        fi
        
        if [[ "$VISIBLE_FILE_ANALYSIS" -eq 1 ]]; then
            local visible_files="$LS_LIST"
            if [ -n "$visible_files" ]; then
                while IFS= read -r file; do
                    [[ -z "$file" || "$file" == "." || "$file" == ".." || "$file" == "selinux" ]] && continue
                    local full_path="$TARGET_PATH$file"
                    
                    if [[ -f "$full_path" ]]; then
                        find_rootkit_module "$full_path" "normal"
                    fi
                done <<< "$visible_files"
            fi
        fi
    done
}


find_section_offset() {
    local section="$1"
    local section_info=$(readelf -S "$ROOTKIT_NAME" | grep "\s$section\s")
    local section_offset=""
    
    for col in 5 6 7; do
        local test_offset=$(echo "$section_info" | awk -v c=$col '{print $c}' | head -n1)
        if echo "$test_offset" | grep -qE "^[0-9a-f]{4,16}$" && [ "$test_offset" != "0000000000000000" ] && [ "$test_offset" != "00000000" ]; then
            section_offset="$test_offset"
            break
        fi
    done

    if [ -z "$section_offset" ]; then
        section_info=$(readelf -S "$ROOTKIT_NAME" | grep "rodata")
        section_offset=$(echo "$section_info" | head -n1 | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9a-f]{8,16}$/ && $i != "00000000" && $i != "0000000000000000") print $i}' | tail -n1)
    fi
    
    echo "$section_offset"
}

extract_string_from_offset() {
    local section="$1"
    local offset="$2"
    local count="${3:-200}"
    
    local section_offset=$(find_section_offset "$section")
    
    if [ -n "$section_offset" ] && [ "$section_offset" != "0" ]; then
        local section_dec=$(printf "%d" 0x$section_offset 2>/dev/null)
        local abs_skip
        
        if [ -n "$offset" ] && [ "$offset" != "" ]; then
            local off_dec=$(printf "%d" 0x$offset 2>/dev/null)
            abs_skip=$((section_dec + off_dec))
        else
            abs_skip=$section_dec
        fi
        
        dd if="$ROOTKIT_NAME" bs=1 skip=$abs_skip count=$count 2>/dev/null | strings | head -n1
    fi
}

analyze_function_calls() {
    local func_name="$1"
    local call_locations=$(objdump -drw "$ROOTKIT_NAME" | grep -n "$func_name")
    if [ -z "$call_locations" ]; then
        log "${YELLOW}[info]${RESET} No $func_name calls"
        return
    fi
    
    local call_count=0
    local results=""
    
    while IFS= read -r call_line; do
        [ -z "$call_line" ] && continue
        call_count=$((call_count + 1))
        line_number=$(echo "$call_line" | cut -d: -f1)
        
        func_context=$(echo "$call_line" | grep -o "<[^>]*>" || echo "")
        
        start_line=$((line_number - 20))
        end_line=$((line_number + 10))
        
        call_context=$(objdump -drw "$ROOTKIT_NAME" | sed -n "${start_line},${end_line}p")
        rodata_refs=$(echo "$call_context" | grep ".rodata" | sort -u)
        
        if [ -z "$rodata_refs" ]; then
            continue
        else
            processed=""
            found_arg=""
            
            while IFS= read -r ref_line; do
                [ -z "$ref_line" ] && continue
                
                section=$(echo "$ref_line" | grep -o "\.rodata[^+]*" | head -n1)
                offset=$(echo "$ref_line" | grep -o "+0x[0-9a-fA-F]*" | sed 's/+0x//' | head -n1)
                
                if [ -n "$section" ]; then
                    key="${section}+${offset}"
                    if echo "$processed" | grep -q "$key"; then
                        continue
                    fi
                    processed="$processed $key"
                    
                    extracted_string=$(extract_string_from_offset "$section" "$offset")
                    
                    if [ -n "$extracted_string" ]; then
                        if [ "$func_name" = "call_usermodehelper" ]; then
                            if echo "$extracted_string" | grep -q "^/" && [[ "$extracted_string" != "/bin/sh" && "$extracted_string" != "/bin/bash" ]]; then
                                BACKDOOR_PATH="$extracted_string"
                                BACKDOOR_FOUND=1
                                if [[ ${#BACKDOOR_LIST[@]} -eq 0 ]] || [[ ! " ${BACKDOOR_LIST[*]} " =~ " ${BACKDOOR_PATH} " ]]; then

                                    BACKDOOR_LIST+=("$BACKDOOR_PATH")
                                fi
                                break
                            fi
                        elif [ "$func_name" = "proc_create" ] || [ "$func_name" = "create_proc_entry" ]; then
                            found_arg="$extracted_string"
                            if [ -z "$results" ]; then
                                if [[ "$extracted_string" == *"/"* ]]; then
                                    PROC_ENTRY="$extracted_string"
                                fi
                            fi
                            break
                        fi
                    fi
                fi
            done <<< "$rodata_refs"
        fi
    done <<< "$call_locations"
    
}

extract_module_info() {
    local gnu_section_offset=$(readelf -S "$ROOTKIT_NAME" | grep "gnu.*linkonce" | awk '{print $5}' | head -n1)
    
    if [ -n "$gnu_section_offset" ] && [ "$gnu_section_offset" != "00000000" ]; then
        local offset_dec=$(printf "%d" 0x$gnu_section_offset 2>/dev/null)
        local module_name=$(dd if="$ROOTKIT_NAME" bs=1 skip=$offset_dec count=64 2>/dev/null | strings | head -n1)
        
        if [ -n "$module_name" ]; then
            MODULE_NAME="$module_name"
        fi
    fi
}

extract_vermagic_info() {
    local vermagic_info=""
    
    if command -v strings >/dev/null 2>&1; then
        vermagic_info=$(strings "$ROOTKIT_NAME" 2>/dev/null | grep "vermagic=" | head -n1 | sed 's/vermagic=//')
    fi
    if [ -n "$vermagic_info" ]; then
        log " - Module Version Magic: $vermagic_info"
    else
        log " - Module Version Magic: ${YELLOW}Not found${RESET}"
    fi
}

p_rootkit_info() {
    if [[ ! -e $ROOTKIT_NAME ]]; then
        log " - ${YELLOW}File Not Found!${RESET}"
        return
    fi


    if ! command -v objdump >/dev/null 2>&1 || ! command -v readelf >/dev/null 2>&1 || ! command -v dd >/dev/null 2>&1; then
        log "${YELLOW}[!][SKIP] Commands for analysis do not exist.${RESET}"
        return
    fi
    
    MODULE_NAME=""
    PROC_ENTRY=""
    BACKDOOR_PATH=""

    extract_module_info
    if [ -z "$MODULE_NAME" ]; then
        log "${YELLOW}[!] Unable to extract module name. Skipping further analysis.${RESET}"
        return
    fi

    analyze_function_calls "proc_create"
    if [ -z "$PROC_ENTRY" ]; then
        analyze_function_calls "create_proc_entry"
    fi
    
    analyze_function_calls "call_usermodehelper"

    log " - Invisible Rootkit Module Name: ${MODULE_NAME:-'Not found'}"
    log " - Proc Entry: /proc/${PROC_ENTRY:-'Not found'}"
    log " - Backdoor Path: ${RED}${BACKDOOR_PATH:-'Not found'}${RESET}"
    extract_vermagic_info

}


main() {

  log "${BLUE}============================================================${RESET}"
  log "${BLUE}           Rootkit Detection Scanner v.1.0-rev1${RESET}"
  log "${BLUE}============================================================${RESET}"
  need_root
  get_system_info
  log "${BLUE}============================================================${RESET}"

  
  scan_fs
  log ""
  log ""
  log "${BLUE}============================================================${RESET}"
  log "${BLUE}                        SCAN RESULT${RESET}"
  log "${BLUE}============================================================${RESET}"
  if [[ "$HIDDEN_FOUND" -eq 0 ]]; then
    log "${GREEN}[OK]${RESET} No Hidden Entry"
  else
    log "${RED}[Alert]${RESET} Hidden Entry Found!"
    for hidden in "${HIDDEN_LIST[@]}"; do
      log "${RED}[!]${RESET} FilePath: ${RED}$hidden${RESET}"
      file_details "$hidden"
    done
  fi
 
  if [[ "$ROOTKIT_FOUND" -eq 0 ]]; then
    log "${GREEN}[OK]${RESET} Rootkit Not Found"
  else
    log "${RED}[Alert]${RESET} Suspicious Rootkit Found!"
    for rootkit in "${ROOTKIT_LIST[@]}"; do
      log "${RED}[!]${RESET} FilePath: ${RED}$rootkit${RESET}"
      file_details "$rootkit"
      ROOTKIT_NAME="$rootkit"
      log "${BLUE}-------------- Rootkit File Analysis -------------${RESET}"
      p_rootkit_info
      log "${BLUE}--------------------------------------------------${RESET}"
    done
  fi

  if [[ "$BACKDOOR_FOUND" -eq 0 ]]; then
    log "${GREEN}[OK]${RESET} Backdoor Not Found"
  else
    log "${RED}[Alert]${RESET} Backdoor Found!"
    for backdoor in "${BACKDOOR_LIST[@]}"; do
      log "${RED}[!]${RESET} FilePath: ${RED}$backdoor${RESET}"
      file_details "$backdoor"
    done
  fi


  log "${BLUE}============================================================${RESET}"
  log "${BLUE}[*] Scan Complete!${RESET}"
  log "${BLUE}============================================================${RESET}"
}

main "$@"
