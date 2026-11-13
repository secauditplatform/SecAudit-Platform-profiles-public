#!/bin/bash

export LC_ALL=C

if [ -z "${BASH_VERSION:-}" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    fi
    printf '%s\n' "ERROR: bash is required." >&2
    exit 1
fi

set -o pipefail

TL_FIND_CAP="${TL_FIND_CAP:-20}"
TL_CMD_CAP="${TL_CMD_CAP:-12}"
TL_DNF_CAP="${TL_DNF_CAP:-30}"
TL_ALLOW_CONTAINER_KMOD="${TL_ALLOW_CONTAINER_KMOD:-${LINUX_CRE_ALLOW_CONTAINER_MODULES:-${ALMA_CRE_ALLOW_CONTAINER_MODULES:-0}}}"

# --- bootstrap / reporting ---
sec_audit_report_pass() { printf 'RULE%s= PASS: %s\n' "$1" "$2"; }
sec_audit_report_fail() { printf 'RULE%s= FAIL: %s\n' "$1" "${3:-$2}"; }
sec_audit_report_skip() { printf 'RULE%s= SKIP: %s\n' "$1" "$2"; }

# --- string / cmd / rpm utils ---
sec_audit_have_bin() { command -v "$1" >/dev/null 2>&1; }

sec_audit_trim_ws() {
    local s="${1-}"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

sec_audit_to_lower() {
    printf '%s' "${1-}" | tr '[:upper:]' '[:lower:]'
}

sec_audit_exec_with_timeout() {
    local secs="$1"
    shift
    if sec_audit_have_bin timeout; then
        timeout "$secs" "$@"
    else
        "$@"
    fi
}

sec_audit_init_is_systemd() {
    sec_audit_have_bin systemctl && [ -d /run/systemd/system ]
}

sec_audit_rpm_is_installed() {
    local pkg
    sec_audit_have_bin rpm || return 1
    for pkg in "$@"; do
        rpm -q "$pkg" &>/dev/null && return 0
    done
    return 1
}

sec_audit_rpm_all_installed() {
    local pkg
    sec_audit_have_bin rpm || return 1
    for pkg in "$@"; do
        rpm -q "$pkg" &>/dev/null || return 1
    done
    return 0
}

sec_audit_pkg_is_installed() {
    local pkg
    if sec_audit_have_bin rpm; then
        for pkg in "$@"; do
            rpm -q "$pkg" &>/dev/null && return 0
        done
    fi
    if sec_audit_have_bin dpkg-query; then
        for pkg in "$@"; do
            dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed' && return 0
        done
    fi
    if sec_audit_have_bin dpkg; then
        for pkg in "$@"; do
            dpkg -l "$pkg" 2>/dev/null | grep -q '^ii' && return 0
        done
    fi
    return 1
}

# --- find / mounts ---
sec_audit_gentle_find() {
    local cap="" argv=()
    if [[ "${1:-}" == --timeout=* ]]; then
        cap="${1#--timeout=}"
        shift
    fi
    [ -n "$cap" ] && sec_audit_have_bin timeout && argv+=(timeout "$cap")
    sec_audit_have_bin nice && argv+=(nice -n 19)
    sec_audit_have_bin ionice && argv+=(ionice -c3)
    argv+=(find "$@")
    "${argv[@]}"
}

sec_audit_find_exited_timeout() {
    local rc=0
    "$@" >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 124 ]
}

sec_audit_local_disk_roots() {
    if ! sec_audit_have_bin findmnt; then
        printf '%s\n' /
        return 0
    fi
    findmnt -rn -o TARGET,FSTYPE,OPTIONS 2>/dev/null | awk '
        BEGIN {
            skip["proc"]; skip["sysfs"]; skip["devtmpfs"]; skip["devpts"];
            skip["tmpfs"]; skip["cgroup"]; skip["cgroup2"]; skip["pstore"];
            skip["securityfs"]; skip["debugfs"]; skip["tracefs"]; skip["configfs"];
            skip["fusectl"]; skip["mqueue"]; skip["hugetlbfs"]; skip["rpc_pipefs"];
            skip["autofs"]; skip["overlay"]; skip["squashfs"]; skip["iso9660"];
            skip["nfs"]; skip["nfs4"]; skip["cifs"]; skip["smbfs"]; skip["sshfs"];
            skip["fuse.sshfs"]; skip["afs"]; skip["ceph"]; skip["glusterfs"];
            skip["gpfs"]; skip["lustre"]; skip["efivarfs"]; skip["bpf"];
        }
        {
            tgt=$1; fs=$2; opt=$3;
            if (tgt == "" || fs == "" || tgt ~ "^/(proc|sys|dev|run)(/|$)") next;
            if (fs in skip) next;
            if (opt ~ /(^|,)bind(,|$)/) next;
            print tgt;
        }
    ' | sort -u
}

sec_audit_mnt_tool_ok() { sec_audit_have_bin findmnt; }

sec_audit_mnt_resolves() {
    local mp="${1%/}"
    sec_audit_mnt_tool_ok || return 1
    findmnt -kn -T "$mp" &>/dev/null
}

sec_audit_mnt_is_dedicated() {
    local mp="${1%/}" tgt
    sec_audit_mnt_tool_ok || return 1
    tgt=$(findmnt -kn -T "$mp" -o TARGET --noheadings 2>/dev/null | head -n1)
    tgt=$(sec_audit_trim_ws "$tgt")
    tgt="${tgt%/}"
    [ -n "$tgt" ] && [ "$tgt" = "$mp" ]
}

sec_audit_mnt_src() {
    local mp="${1%/}" s
    sec_audit_mnt_tool_ok || return 1
    s=$(findmnt -kn -T "$mp" -o SOURCE --noheadings 2>/dev/null | head -n1)
    printf '%s' "$(sec_audit_trim_ws "$s")"
}

sec_audit_mnt_kind() {
    local mp="${1%/}" f
    sec_audit_mnt_tool_ok || return 1
    f=$(findmnt -kn -T "$mp" -o FSTYPE --noheadings 2>/dev/null | head -n1)
    printf '%s' "$(sec_audit_trim_ws "$f")"
}

sec_audit_mnt_opts() {
    local mp="${1%/}" o
    sec_audit_mnt_tool_ok || return 1
    o=$(findmnt -kn -T "$mp" -o OPTIONS --noheadings 2>/dev/null | head -n1)
    printf '%s' "$(sec_audit_trim_ws "$o")"
}

sec_audit_mnt_flag_set() {
    local mp="$1" want="$2" csv token
    sec_audit_mnt_tool_ok || return 1
    csv=$(sec_audit_mnt_opts "$mp")
    [ -z "$csv" ] && return 1
    local IFS=,
    for token in $csv; do
        token=$(sec_audit_trim_ws "$token")
        [ "$token" = "$want" ] && return 0
    done
    return 1
}

sec_audit_volume_isolated() {
    local mp="${1%/}" src root_src
    sec_audit_mnt_tool_ok || return 1
    sec_audit_mnt_is_dedicated "$mp" || return 1
    src=$(sec_audit_mnt_src "$mp")
    root_src=$(sec_audit_mnt_src /)
    [ -n "$src" ] && [ -n "$root_src" ] && [ "$src" != "$root_src" ]
}

sec_audit_tmp_volume_ok() {
    local fst src root_src
    sec_audit_mnt_tool_ok || return 1
    sec_audit_mnt_is_dedicated /tmp || return 1
    fst=$(sec_audit_mnt_kind /tmp)
    src=$(sec_audit_mnt_src /tmp)
    root_src=$(sec_audit_mnt_src /)
    [ "$fst" = "tmpfs" ] && return 0
    [ -n "$src" ] && [ -n "$root_src" ] && [ "$src" != "$root_src" ] && return 0
    return 1
}

sec_audit_shm_volume_ok() {
    local fst src root_src
    sec_audit_mnt_tool_ok || return 1
    sec_audit_mnt_is_dedicated /dev/shm || return 1
    fst=$(sec_audit_mnt_kind /dev/shm)
    src=$(sec_audit_mnt_src /dev/shm)
    root_src=$(sec_audit_mnt_src /)
    [ "$fst" = "tmpfs" ] && return 0
    [ -n "$src" ] && [ -n "$root_src" ] && [ "$src" != "$root_src" ] && return 0
    return 1
}

sec_audit_volume_persisted() {
    local mp="${1%/}" unit=""
    if [[ -f /etc/fstab ]] && grep -Pqs "[[:space:]]${mp//\//\\/}[[:space:]]" /etc/fstab 2>/dev/null; then
        return 0
    fi
    if sec_audit_have_bin systemd-escape; then
        unit="$(systemd-escape --path "$mp" 2>/dev/null).mount"
        if [[ -n "$unit" && ( -f "/etc/systemd/system/${unit}" || -f "/usr/lib/systemd/system/${unit}" || -f "/run/systemd/generator/${unit}" ) ]]; then
            return 0
        fi
    fi
    case "$mp" in
        /tmp)
            [[ -f /usr/lib/systemd/system/tmp.mount || -f /etc/systemd/system/tmp.mount ]] && return 0
            ;;
        /dev/shm)
            [[ -f /usr/lib/systemd/system/dev-shm.mount || -f /etc/systemd/system/dev-shm.mount ]] && return 0
            ;;
    esac
    return 1
}

sec_audit_persist_note() {
    local mp="${1%/}"
    if sec_audit_volume_persisted "$mp"; then
        printf '%s' ""
    else
        printf '%s' " | not persisted in fstab or systemd .mount (lost after reboot)"
    fi
}

sec_audit_fstab_has_flag() {
    local mp="${1%/}" flag="$2"
    [[ -f /etc/fstab ]] || return 1
    awk -v mp="$mp" -v flag="$flag" '
        BEGIN { found = 0 }
        $0 ~ /^[[:space:]]*#/ { next }
        NF >= 4 && $2 == mp {
            n = split($4, opts, ",")
            for (i = 1; i <= n; i++) {
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", opts[i])
                if (opts[i] == flag) found = 1
            }
        }
        END { exit(found ? 0 : 1) }
    ' /etc/fstab 2>/dev/null
}

# --- dnf / repos ---
sec_audit_dnf_ini_main() {
    local want="$1" f files=()
    [[ -f /etc/dnf/dnf.conf ]] && files+=(/etc/dnf/dnf.conf)
    if [[ -d /etc/dnf/dnf.conf.d ]]; then
        shopt -s nullglob
        for f in /etc/dnf/dnf.conf.d/*.conf; do
            [[ -f $f ]] && files+=("$f")
        done
        shopt -u nullglob
    fi
    ((${#files[@]})) || { printf '%s\n' ""; return 0; }
    awk -v want="$1" '
        function sec_audit_trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
        function lc(s)  { return tolower(s) }
        BEGIN { in_main = 0; v = "" }
        /^[[:space:]]*\[main[[:space:]]*\]/ { in_main = 1; next }
        /^[[:space:]]*\[/ { in_main = 0; next }
        in_main {
            line = $0
            sub(/#.*/, "", line)
            if (line ~ /^[[:space:]]*$/ || line !~ /=/) next
            eq = index(line, "=")
            key = sec_audit_trim(substr(line, 1, eq - 1))
            val = sec_audit_trim(substr(line, eq + 1))
            if (lc(key) == lc(want)) v = val
        }
        END { print v }
    ' "${files[@]}" 2>/dev/null
}

sec_audit_as_false() {
    case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')" in
        0|false|no|off) return 0 ;;
        *) return 1 ;;
    esac
}

sec_audit_as_true() {
    case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

sec_audit_count_rpm_gpg() {
    local c
    if ! sec_audit_have_bin rpm; then
        printf '%s\n' 0
        return 0
    fi
    c=$(rpm -qa 'gpg-pubkey*' 2>/dev/null | grep -cve '^[[:space:]]*$' || true)
    printf '%s\n' "${c:-0}"
}

sec_audit_repos_gpgcheck_off() {
    local f
    [[ -d /etc/yum.repos.d ]] || return 0
    shopt -s nullglob
    for f in /etc/yum.repos.d/*.repo; do
        [[ -f $f ]] || continue
        awk '
            function sec_audit_trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
            function is_false(s, t) {
                t = tolower(s); gsub(/^[[:space:]]+|[[:space:]]+$/, "", t)
                return (t == "0" || t == "false" || t == "no" || t == "off")
            }
            function flush() {
                if (sec == "") return
                if (enabled && gc_explicit && is_false(gc_val)) print FILENAME "|" sec
                sec = ""; enabled = 1; gc_explicit = 0; gc_val = ""
            }
            BEGIN { sec = ""; enabled = 1; gc_explicit = 0; gc_val = "" }
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*;/ { next }
            /^[[:space:]]*\[/ {
                flush()
                line = $0; sub(/#.*/, "", line); gsub(/^\[|\]$/, "", line)
                sec = sec_audit_trim(line); enabled = 1; gc_explicit = 0; gc_val = ""; next
            }
            {
                line = $0; sub(/#.*/, "", line)
                if (line !~ /=/) next
                eq = index(line, "=")
                k = tolower(sec_audit_trim(substr(line, 1, eq - 1)))
                v = sec_audit_trim(substr(line, eq + 1))
                if (k == "enabled") {
                    vv = tolower(v)
                    if (vv == "0" || vv == "false" || vv == "no" || vv == "off") enabled = 0
                    else enabled = 1
                    next
                }
                if (k == "gpgcheck") { gc_explicit = 1; gc_val = v }
            }
            END { flush() }
        ' "$f" 2>/dev/null
    done
    shopt -u nullglob
}

sec_audit_repos_repogpg_off() {
    local f
    [[ -d /etc/yum.repos.d ]] || return 0
    shopt -s nullglob
    for f in /etc/yum.repos.d/*.repo; do
        [[ -f $f ]] || continue
        awk '
            function sec_audit_trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
            function is_false(s, t) {
                t = tolower(s); gsub(/^[[:space:]]+|[[:space:]]+$/, "", t)
                return (t == "0" || t == "false" || t == "no" || t == "off")
            }
            function flush() {
                if (sec == "") return
                if (enabled && rgc_explicit && is_false(rgc_val)) print FILENAME "|" sec
                sec = ""; enabled = 1; rgc_explicit = 0; rgc_val = ""
            }
            BEGIN { sec = ""; enabled = 1; rgc_explicit = 0; rgc_val = "" }
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*;/ { next }
            /^[[:space:]]*\[/ {
                flush()
                line = $0; sub(/#.*/, "", line); gsub(/^\[|\]$/, "", line)
                sec = sec_audit_trim(line); enabled = 1; rgc_explicit = 0; rgc_val = ""; next
            }
            {
                line = $0; sub(/#.*/, "", line)
                if (line !~ /=/) next
                eq = index(line, "=")
                k = tolower(sec_audit_trim(substr(line, 1, eq - 1)))
                v = sec_audit_trim(substr(line, eq + 1))
                if (k == "enabled") {
                    vv = tolower(v)
                    if (vv == "0" || vv == "false" || vv == "no" || vv == "off") enabled = 0
                    else enabled = 1
                    next
                }
                if (k == "repo_gpgcheck") { rgc_explicit = 1; rgc_val = v }
            }
            END { flush() }
        ' "$f" 2>/dev/null
    done
    shopt -u nullglob
}

sec_audit_enabled_repo_has_uri() {
    local f
    [[ -d /etc/yum.repos.d ]] || return 1
    shopt -s nullglob
    for f in /etc/yum.repos.d/*.repo; do
        [[ -f $f ]] || continue
        awk '
            function sec_audit_trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
            BEGIN { sec = ""; enabled = 1; has_uri = 0; found = 0 }
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*;/ { next }
            /^[[:space:]]*\[/ {
                if (sec != "" && enabled && has_uri) found = 1
                line = $0; sub(/#.*/, "", line); gsub(/^\[|\]$/, "", line)
                sec = sec_audit_trim(line); enabled = 1; has_uri = 0; next
            }
            {
                line = $0; sub(/#.*/, "", line)
                if (line !~ /=/) next
                eq = index(line, "=")
                k = tolower(sec_audit_trim(substr(line, 1, eq - 1)))
                v = sec_audit_trim(substr(line, eq + 1))
                if (k == "enabled") {
                    vv = tolower(v)
                    if (vv == "0" || vv == "false" || vv == "no" || vv == "off") enabled = 0
                    else enabled = 1
                    next
                }
                if (k == "baseurl" || k == "mirrorlist" || k == "metalink") {
                    if (v != "" && tolower(v) != "none") has_uri = 1
                }
            }
            END {
                if (sec != "" && enabled && has_uri) found = 1
                exit(found ? 0 : 1)
            }
        ' "$f" && { shopt -u nullglob; return 0; }
    done
    shopt -u nullglob
    return 1
}

sec_audit_count_enabled_dnf_repos() {
    local n
    if ! sec_audit_have_bin dnf; then
        printf '%s\n' 0
        return 0
    fi
    n=$(sec_audit_exec_with_timeout "$TL_DNF_CAP" dnf -q repolist enabled 2>/dev/null | awk '
        /^repo[[:space:]]+id[[:space:]]/ { hdr = 1; next }
        hdr && NF >= 1 && $1 != "" && $1 !~ /^repolist:/ && $1 !~ /^Repo/ { c++ }
        END { print c + 0 }
    ')
    printf '%s\n' "${n:-0}"
}

# --- sshd cache ---
_SSHD_PRIMED=0
_SSHD_DUMP=""

sec_audit_prime_sshd_dump() {
    [ "$_SSHD_PRIMED" -eq 1 ] && return 0
    _SSHD_PRIMED=1
    if sec_audit_have_bin sshd; then
        _SSHD_DUMP=$(sshd -T 2>/dev/null) || _SSHD_DUMP=""
    else
        _SSHD_DUMP=""
    fi
}

sec_audit_sshd_dump() { sec_audit_prime_sshd_dump; printf '%s\n' "$_SSHD_DUMP"; }
sec_audit_sshd_dump_grep() { sec_audit_prime_sshd_dump; printf '%s\n' "$_SSHD_DUMP" | grep "$@"; }
sec_audit_sshd_dump_awk() { sec_audit_prime_sshd_dump; printf '%s\n' "$_SSHD_DUMP" | awk "$@"; }

sec_audit_sshd_dump_ready() {
    sec_audit_prime_sshd_dump
    sec_audit_have_bin sshd || return 1
    [[ -n "${_SSHD_DUMP//[[:space:]]/}" ]]
}

sec_audit_sshd_kv() {
    local key
    key=$(sec_audit_to_lower "$1")
    sec_audit_prime_sshd_dump
    awk -v k="$key" 'tolower($1)==k { $1=""; sub(/^ /,""); print; exit }' <<<"$_SSHD_DUMP"
}

sec_audit_sshd_int() {
    local v
    v=$(sec_audit_sshd_kv "$1")
    [[ "$v" =~ ^[0-9]+$ ]] && printf '%s' "$v"
}

# --- auditd cache ---
_AUDITCTL_PRIMED=0
_AUDITCTL_DUMP=""

sec_audit_prime_auditctl() {
    [ "$_AUDITCTL_PRIMED" -eq 1 ] && return 0
    _AUDITCTL_PRIMED=1
    if sec_audit_have_bin auditctl; then
        _AUDITCTL_DUMP=$(auditctl -l 2>/dev/null) || _AUDITCTL_DUMP=""
    else
        _AUDITCTL_DUMP=""
    fi
}

sec_audit_auditctl_grep() { sec_audit_prime_auditctl; printf '%s\n' "$_AUDITCTL_DUMP" | grep "$@"; }

_AUDIT_FILES_PRIMED=0
_AUDIT_FILES_DUMP=""

sec_audit_prime_audit_files() {
    [ "$_AUDIT_FILES_PRIMED" -eq 1 ] && return 0
    _AUDIT_FILES_PRIMED=1
    shopt -s nullglob
    _AUDIT_FILES_DUMP=$(cat /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null)
    shopt -u nullglob
}

sec_audit_audit_files_grep() { sec_audit_prime_audit_files; printf '%s\n' "$_AUDIT_FILES_DUMP" | grep "$@"; }

sec_audit_audit_on_disk_and_kernel() {
    sec_audit_prime_audit_files
    sec_audit_prime_auditctl
    printf '%s\n' "$_AUDIT_FILES_DUMP" | grep -q "$@" || return 1
    printf '%s\n' "$_AUDITCTL_DUMP" | grep -q "$@" || return 1
    return 0
}

sec_audit_audit_log_dir() {
    local raw
    [[ -f /etc/audit/auditd.conf ]] || return 1
    raw=$(awk -F= '/^[[:space:]]*log_file[[:space:]]*=/{print $2; exit}' /etc/audit/auditd.conf 2>/dev/null)
    raw=$(sec_audit_trim_ws "$raw")
    [ -n "$raw" ] || raw=/var/log/audit/audit.log
    dirname "$raw"
}

# --- sysctl ---
sec_audit_live_sysctl_raw() {
    sec_audit_have_bin sysctl || return 1
    sysctl -n "$1" 2>/dev/null | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

sec_audit_live_sysctl() { printf '%s' "$(sec_audit_live_sysctl_raw "$1")"; }

sec_audit_live_sysctl_is() {
    local got
    got=$(sec_audit_live_sysctl_raw "$1") || return 1
    [[ "$got" == "$2" ]]
}

sec_audit_disk_sysctl_last() {
    local key="$1" esc val="" line f
    esc=${key//./\\.}
    shopt -s nullglob
    local order=(/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf)
    [[ -f /etc/sysctl.conf ]] && order+=(/etc/sysctl.conf)
    for f in "${order[@]}"; do
        [[ -f $f ]] || continue
        while IFS= read -r line || [[ -n $line ]]; do
            [[ $line =~ ^[[:space:]]*# ]] && continue
            [[ $line =~ ^[[:space:]]*$ ]] && continue
            if [[ $line =~ ^[[:space:]]*${esc}[[:space:]]*=[[:space:]]*([^#[:space:]]+) ]]; then
                val="${BASH_REMATCH[1]}"
            fi
        done <"$f"
    done
    shopt -u nullglob
    printf '%s' "$val"
}

sec_audit_sysctl_mismatch_note() {
    local key="$1" want="$2" disk got
    got=$(sec_audit_live_sysctl_raw "$key") || got=""
    disk=$(sec_audit_disk_sysctl_last "$key")
    [[ -z $disk ]] && return 0
    if [[ "$got" == "$want" && "$disk" != "$want" ]]; then
        printf '%s' " | note: last on-disk assignment is ${disk} (runtime overrides until reboot)"
    elif [[ "$got" != "$want" && "$disk" == "$want" ]]; then
        printf '%s' " | on-disk last value is ${want} but kernel has '${got:-?}'; run sysctl --system or reboot"
    elif [[ "$got" != "$want" && -n $disk && "$disk" != "$want" ]]; then
        printf '%s' " | on-disk last value is ${disk}, kernel '${got:-?}'"
    fi
}

sec_audit_iface_sysctl_offenders() {
    local leaf="$1" want="$2" p base val
    base="/proc/sys/net/ipv4/conf"
    [[ -d $base ]] || return 0
    shopt -s nullglob
    for p in "$base"/*/ "$base"/; do
        [[ -d $p ]] || continue
        local iface
        iface=$(basename "$p")
        [[ "$iface" == "all" || "$iface" == "default" || "$iface" == "lo" ]] && continue
        [[ -f ${p}${leaf} ]] || continue
        val=$(tr -d '[:space:]' <"${p}${leaf}" 2>/dev/null)
        if [[ -n "$val" && "$val" != "$want" ]]; then
            printf '%s=%s ' "$iface" "$val"
        fi
    done
    shopt -u nullglob
}

sec_audit_audit_sysctl() {
    local num="$1" key="$2" want="$3" r disk hint="" extra=""
    r=$(sec_audit_live_sysctl "$key")
    disk=$(sec_audit_disk_sysctl_last "$key")
    hint=$(sec_audit_sysctl_mismatch_note "$key" "$want")
    if ! sec_audit_live_sysctl_is "$key" "$want"; then
        sec_audit_report_fail "$num" "kernel ${key} is '${r:-<unreadable>}', expected ${want}${hint}"
        return 0
    fi
    if [[ -n "$disk" && "$disk" != "$want" ]]; then
        sec_audit_report_fail "$num" "kernel ${key}=${want} but last on-disk assignment is ${disk} (not reboot-safe)${hint}"
        return 0
    fi
    case "$key" in
        net.ipv4.conf.all.*)
            extra=$(sec_audit_iface_sysctl_offenders "${key##*.}" "$want")
            if [[ -n "$extra" ]]; then
                sec_audit_report_fail "$num" "${key}=${want} but per-interface values differ: ${extra}"
                return 0
            fi
            ;;
    esac
    sec_audit_report_pass "$num" "${key}=${want} in kernel and on disk${hint}"
}

# --- kernel modules ---
sec_audit_kmod_listed_for_boot() {
    local pat="" a
    for a in "$@"; do
        pat+="${pat:+|}${a}"
    done
    grep -rqE "^[[:space:]]*(${pat})([[:space:]]|$)" /etc/modules-load.d /usr/lib/modules-load.d /run/modules-load.d 2>/dev/null
}

sec_audit_kmod_currently_loaded() {
    local name="$1"
    [[ -f /proc/modules ]] && awk '{print $1}' /proc/modules | grep -qx "$name" && return 0
    lsmod 2>/dev/null | awk '{print $1}' | grep -qx "$name"
}

sec_audit_kmod_object_scan() {
    local pattern="$1" cap="${2:-$TL_FIND_CAP}" rc=0 out=""
    out=$(sec_audit_gentle_find --timeout="$cap" /usr/lib/modules/ /lib/modules/ \
        -xdev -ignore_readdir_race -type f -name "${pattern}" -print -quit 2>/dev/null) || rc=$?
    if [ "$rc" -eq 124 ]; then
        return 2
    fi
    [ -n "$out" ]
}

sec_audit_kmod_probe_blocked() {
    local mod="$1" out="" cfg
    sec_audit_have_bin modprobe || return 1
    cfg=$(modprobe --showconfig 2>/dev/null)
    printf '%s\n' "$cfg" | grep -Pq "^\h*(blacklist|install)\h+${mod}\b" || return 1
    out=$(modprobe -n -v "$mod" 2>&1) || true
    if grep -qiE '(install /bin/false|/bin/true|module blacklisted|FATAL|not found|Module .* not found)' <<<"$out"; then
        return 0
    fi
    grep -qiE '^install[[:space:]]' <<<"$out"
}

sec_audit_kmod_container_waiver() {
    local mod="$1"
    case "$mod" in
        overlay|squashfs)
            [[ "${TL_ALLOW_CONTAINER_KMOD}" == "1" ]]
            ;;
        *) return 1 ;;
    esac
}

sec_audit_audit_kmod_absent() {
    local num="$1" label="$2" mod="$3" ko_pattern="$4"
    shift 4
    local alias loaded=0 a
    if sec_audit_kmod_container_waiver "$mod"; then
        sec_audit_report_pass "$num" "${label} (waived: TL_ALLOW_CONTAINER_KMOD=1)"
        return 0
    fi
    for a in "$@"; do
        if sec_audit_kmod_listed_for_boot "$a"; then
            sec_audit_report_fail "$num" "${label} is listed in modules-load.d (auto-load at boot)"
            return 0
        fi
    done
    case "$(sec_audit_kmod_object_scan "$ko_pattern"; echo $?)" in
        2) sec_audit_report_fail "$num" "incomplete_scan: module scan timed out for ${label}"; return 0 ;;
        1) sec_audit_report_pass "$num" "${label} is not available (no kernel object on disk)"; return 0 ;;
    esac
    loaded=0
    for a in "$@"; do
        if sec_audit_kmod_currently_loaded "$a"; then
            loaded=1
            break
        fi
    done
    if [ "$loaded" -eq 1 ]; then
        sec_audit_report_fail "$num" "${label} is currently loaded"
        return 0
    fi
    if sec_audit_kmod_probe_blocked "$mod"; then
        sec_audit_report_pass "$num" "${label} is blocked (blacklist/install /bin/false and modprobe -n refuses load)"
        return 0
    fi
    sec_audit_report_fail "$num" "${label} is available on disk and not effectively blocked"
}

# --- systemd units ---
sec_audit_unit_enable_state() { systemctl is-enabled "$1" 2>/dev/null || true; }
sec_audit_unit_active_state() { systemctl is-active "$1" 2>/dev/null || true; }

sec_audit_unit_is_live() {
    local unit state
    for unit in "$@"; do
        state=$(sec_audit_unit_enable_state "$unit")
        case "$state" in
            enabled|enabled-runtime|linked|linked-runtime|alias) return 0 ;;
        esac
        case "$(sec_audit_unit_active_state "$unit")" in
            active|activating) return 0 ;;
        esac
    done
    return 1
}

sec_audit_audit_service_idle() {
    local num="$1" pkg="$2" pass_msg="$3" fail_msg="$4"
    shift 4
    if ! sec_audit_pkg_is_installed "$pkg"; then
        sec_audit_report_pass "$num" "$pass_msg"
    elif sec_audit_unit_is_live "$@"; then
        sec_audit_report_fail "$num" "$fail_msg"
    else
        sec_audit_report_pass "$num" "$pass_msg (package present but units masked/disabled/inactive)"
    fi
}

# --- files ---
sec_audit_file_octal() { stat -Lc '%a' "$1" 2>/dev/null; }
sec_audit_shadow_readable() { [[ -r /etc/shadow ]]; }
sec_audit_file_owner() { stat -Lc '%U:%G' "$1" 2>/dev/null; }
sec_audit_file_user() { stat -Lc '%U' "$1" 2>/dev/null; }
sec_audit_file_group() { stat -Lc '%G' "$1" 2>/dev/null; }

sec_audit_mode_no_more_permissive() {
    local path="$1" max="$2" got
    [[ -e $path ]] || return 1
    got=$(sec_audit_file_octal "$path") || return 1
    [[ "$got" =~ ^[0-7]+$ ]] || return 1
    (( (8#$got & ~8#$max) == 0 ))
}

sec_audit_owned_as() {
    local path="$1" want="$2"
    [[ "$(sec_audit_file_owner "$path")" == "$want" ]]
}

sec_audit_audit_file_access() {
    local num="$1" path="$2" maxmode="$3" owner="$4" pass_msg="$5" missing_ok="${6:-0}" extra_group="${7:-}"
    if [[ ! -e $path ]]; then
        if [[ "$missing_ok" == "1" ]]; then
            sec_audit_report_pass "$num" "${pass_msg} (file absent)"
        else
            sec_audit_report_fail "$num" "${path} is missing"
        fi
        return 0
    fi
    if ! sec_audit_mode_no_more_permissive "$path" "$maxmode"; then
        sec_audit_report_fail "$num" "${path} mode $(sec_audit_file_octal "$path") is more permissive than ${maxmode}"
        return 0
    fi
    if [[ -n "$extra_group" ]]; then
        if [[ "$(sec_audit_file_user "$path")" != "${owner%%:*}" ]]; then
            sec_audit_report_fail "$num" "${path} owner is $(sec_audit_file_user "$path"), expected ${owner%%:*}"
            return 0
        fi
        case "$(sec_audit_file_group "$path")" in
            ${owner##*:}|${extra_group}) ;;
            *) sec_audit_report_fail "$num" "${path} group is $(sec_audit_file_group "$path"), expected ${owner##*:} or ${extra_group}"; return 0 ;;
        esac
    else
        if ! sec_audit_owned_as "$path" "$owner"; then
            sec_audit_report_fail "$num" "${path} owner is $(sec_audit_file_owner "$path"), expected ${owner}"
            return 0
        fi
    fi
    sec_audit_report_pass "$num" "$pass_msg (mode $(sec_audit_file_octal "$path"), owner $(sec_audit_file_owner "$path"))"
}

sec_audit_audit_dir_access() {
    sec_audit_audit_file_access "$@"
}

# --- grub ---
sec_audit_grub_configs() {
    local p
    [[ -f /boot/grub2/grub.cfg ]] && printf '%s\n' /boot/grub2/grub.cfg
    [[ -f /boot/grub/grub.cfg ]] && printf '%s\n' /boot/grub/grub.cfg
    [[ -f /boot/grub/grub.cfg ]] || true
    [[ -f /boot/grub2/user.cfg ]] && printf '%s\n' /boot/grub2/user.cfg
    shopt -s nullglob
    for p in /boot/efi/*/grub.cfg /boot/efi/EFI/*/grub.cfg /boot/efi/EFI/*/grubenv; do
        [[ -f $p && $p == *.cfg ]] && printf '%s\n' "$p"
    done
    shopt -u nullglob
}

sec_audit_grub_configs_grep() {
    local pat="$1" p found=0
    while IFS= read -r p; do
        [[ -f $p ]] || continue
        if grep -qE "$pat" "$p" 2>/dev/null; then
            found=1
            break
        fi
    done <<< "$(sec_audit_grub_configs)"
    [ "$found" -eq 1 ]
}

# --- PAM ---
sec_audit_pam_password_files() {
    local f p
    for f in /etc/pam.d/password-auth /etc/pam.d/system-auth; do
        [[ -e $f ]] || continue
        if sec_audit_have_bin readlink; then
            p=$(readlink -f "$f" 2>/dev/null || echo "$f")
        else
            p=$f
        fi
        printf '%s\n' "$p"
    done | sort -u
}

sec_audit_pam_auth_files() {
    local f p
    for f in /etc/pam.d/password-auth /etc/pam.d/system-auth /etc/pam.d/su /etc/pam.d/sshd; do
        [[ -e $f ]] || continue
        if sec_audit_have_bin readlink; then
            p=$(readlink -f "$f" 2>/dev/null || echo "$f")
        else
            p=$f
        fi
        printf '%s\n' "$p"
    done | sort -u
}

sec_audit_pwquality_before_unix() {
    local p any=0 stacks
    stacks="$(sec_audit_pam_password_files)"
    while IFS= read -r p; do
        [[ -f $p ]] || continue
        grep -qE '^[[:space:]]*password[[:space:]]' "$p" 2>/dev/null || continue
        any=1
        awk '
            function bad_order(buf) {
                if (buf !~ /pam_pwquality\.so/) return 1
                ipw = index(buf, "pam_pwquality.so")
                iun = index(buf, "pam_unix.so")
                if (iun > 0 && ipw > iun) return 1
                return 0
            }
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*password[[:space:]]+/ {
                buf = $0
                while (getline > 0) {
                    if ($0 ~ /^[[:space:]]*(account|auth|session|password)[[:space:]]/) break
                    buf = buf " " $0
                }
                if (bad_order(buf)) exit 1
            }
            END { exit 0 }
        ' "$p" || return 1
    done <<< "$stacks"
    [[ $any -eq 1 ]]
}

sec_audit_pam_password_has() {
    local mod="$1" p stacks
    stacks="$(sec_audit_pam_password_files)"
    while IFS= read -r p; do
        [[ -f $p ]] || continue
        if awk -v m="$mod" '
            BEGIN { found = 0 }
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*password[[:space:]]+/ {
                buf = $0
                while (getline > 0) {
                    if ($0 ~ /^[[:space:]]*(account|auth|session|password)[[:space:]]/) break
                    buf = buf " " $0
                }
                if (index(buf, m) > 0) found = 1
            }
            END { exit(found ? 0 : 1) }
        ' "$p"; then
            return 0
        fi
    done <<< "$stacks"
    return 1
}

sec_audit_pam_auth_has() {
    local mod="$1" p stacks
    stacks="$(sec_audit_pam_auth_files)"
    while IFS= read -r p; do
        [[ -f $p ]] || continue
        grep -E '^[[:space:]]*auth[[:space:]]' "$p" 2>/dev/null | grep -q "$mod" && return 0
    done <<< "$stacks"
    return 1
}

sec_audit_pam_pw_grep() {
    local pattern="$1" p stacks
    stacks="$(sec_audit_pam_password_files)"
    while IFS= read -r p; do
        [[ -f $p ]] || continue
        grep -Pq "$pattern" "$p" 2>/dev/null && return 0
    done <<< "$stacks"
    return 1
}

sec_audit_pam_pw_igrep() {
    local pattern="$1" p stacks
    stacks="$(sec_audit_pam_password_files)"
    while IFS= read -r p; do
        [[ -f $p ]] || continue
        grep -Piq "$pattern" "$p" 2>/dev/null && return 0
    done <<< "$stacks"
    return 1
}

sec_audit_pam_login_igrep() {
    local pattern="$1" p
    while IFS= read -r p; do
        [[ -f $p ]] || continue
        grep -Piq "$pattern" "$p" 2>/dev/null && return 0
    done <<< "$(sec_audit_pam_auth_files)"
    return 1
}

# --- misc ---
sec_audit_core_dumps_blocked() {
    grep -Psiq '^\*\s+hard\s+core\s+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null || return 1
    if grep -rPiq '^\h*DefaultLimitCORE\h*=\h*(infinity|unlimited)\b' /etc/systemd/system.conf /etc/systemd/user.conf /etc/systemd/system.conf.d/*.conf /etc/systemd/user.conf.d/*.conf 2>/dev/null; then
        return 1
    fi
    if grep -rPiq '^\h*DefaultLimitCORE\h*=\h*[1-9][0-9]*\b' /etc/systemd/system.conf /etc/systemd/user.conf /etc/systemd/system.conf.d/*.conf /etc/systemd/user.conf.d/*.conf 2>/dev/null; then
        return 1
    fi
    return 0
}

sec_audit_gdm_present() { sec_audit_rpm_is_installed gdm; }

sec_audit_dconf_gdm_has() {
    local pat="$1"
    shopt -s nullglob
    local files=(/etc/dconf/db/gdm.d/* /etc/dconf/db/local.d/* /etc/dconf/db/distro.d/*)
    shopt -u nullglob
    ((${#files[@]})) || return 1
    grep -Rqs -- "$pat" "${files[@]}" 2>/dev/null
}

sec_audit_journald_merged() {
    if sec_audit_have_bin systemd-analyze; then
        systemd-analyze cat-config systemd/journald.conf 2>/dev/null
        return 0
    fi
    cat /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null
}

sec_audit_journald_kv() {
    local key="$1"
    sec_audit_journald_merged | awk -F= -v k="$key" '
        $0 ~ /^[[:space:]]*#/ { next }
        $1 == k { v=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", v) }
        END { print v }
    '
}

sec_audit_os_id() {
    awk -F= '/^ID=/{gsub(/"/,"",$2); print $2; exit}' /etc/os-release 2>/dev/null
}

sec_audit_banner_leaks_os() {
    local file="$1" id
    [[ -f $file ]] || return 1
    id=$(sec_audit_os_id)
    grep -Psiq "(\\\\v|\\\\r|\\\\m|\\\\s|\\b${id}\\b)" "$file" 2>/dev/null
}

sec_audit_login_defs_int() {
    local key="$1"
    awk -v k="$key" '$1==k {print $2; exit}' /etc/login.defs 2>/dev/null
}

sec_audit_uid_min() {
    local v
    v=$(sec_audit_login_defs_int UID_MIN)
    printf '%s' "${v:-1000}"
}

sec_audit_valid_shell_pat() {
    awk -F/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells 2>/dev/null \
        | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -
}

sec_audit_audit_isolated_volume() {
    local num="$1" mp="$2" pass_msg="$3" kind="${4:-separate}"
    local ok=1
    if [[ "$kind" == "tmp" ]]; then
        sec_audit_tmp_volume_ok || ok=0
    elif [[ "$kind" == "shm" ]]; then
        sec_audit_shm_volume_ok || ok=0
    else
        sec_audit_volume_isolated "$mp" || ok=0
    fi
    if [ "$ok" -eq 1 ]; then
        if sec_audit_volume_persisted "$mp"; then
            sec_audit_report_pass "$num" "$pass_msg (fstype=$(sec_audit_mnt_kind "$mp"), source=$(sec_audit_mnt_src "$mp"))"
        else
            sec_audit_report_fail "$num" "${mp} isolation is runtime-only (missing fstab or systemd .mount persistence)"
        fi
    else
        sec_audit_report_fail "$num" "${mp} is not a dedicated tmpfs/separate partition"
    fi
}

sec_audit_audit_mount_flag() {
    local num="$1" mp="$2" flag="$3"
    if ! sec_audit_mnt_resolves "$mp"; then
        sec_audit_report_fail "$num" "${flag} is not set on ${mp} (path not resolvable / not an explicit mount)"
        return 0
    fi
    if ! sec_audit_mnt_flag_set "$mp" "$flag"; then
        sec_audit_report_fail "$num" "${flag} is not set on runtime mount ${mp} (opts: $(sec_audit_mnt_opts "$mp"))"
        return 0
    fi
    if sec_audit_volume_persisted "$mp" && ! sec_audit_fstab_has_flag "$mp" "$flag"; then
        local unit_note
        unit_note=$(sec_audit_persist_note "$mp")
        if [[ -n "$unit_note" ]] || ! grep -q "$flag" <<<"$(sec_audit_mnt_opts "$mp")"; then
            :
        fi
        if [[ -f /etc/fstab ]] && grep -Pqs "[[:space:]]${mp//\//\\/}[[:space:]]" /etc/fstab && ! sec_audit_fstab_has_flag "$mp" "$flag"; then
            sec_audit_report_fail "$num" "${flag} is set at runtime on ${mp} but missing from fstab (not reboot-safe)"
            return 0
        fi
    fi
    sec_audit_report_pass "$num" "${flag} option set on ${mp}$(sec_audit_persist_note "$mp")"
}

sec_audit_audit_pkg_absent() {
    local num="$1" pkg="$2" pass_msg="$3" fail_msg="$4"
    if sec_audit_pkg_is_installed "$pkg"; then
        sec_audit_report_fail "$num" "$fail_msg"
    else
        sec_audit_report_pass "$num" "$pass_msg"
    fi
}

# --- compatibility aliases ---
sec_audit_low_impact_find() { sec_audit_gentle_find "$@"; }
sec_audit_low_impact_find_timed_out() { sec_audit_find_exited_timeout "$@"; }
sec_audit_safe_find_roots() { sec_audit_local_disk_roots; }
sec_audit_pkg_installed() { sec_audit_pkg_is_installed "$@"; }
sec_audit_rule_pass() { sec_audit_report_pass "$@"; }
sec_audit_rule_fail() { sec_audit_report_fail "$@"; }
sec_audit_emit_pass() { sec_audit_report_pass "$@"; }
sec_audit_emit_fail() { sec_audit_report_fail "$@"; }
sec_audit_rule_kernel_mod_unavailable() { sec_audit_audit_kmod_absent "$@"; }
sec_audit_rule_service_not_in_use() { sec_audit_audit_service_idle "$@"; }
sec_audit_rule_sysctl_check() { sec_audit_audit_sysctl "$@"; }
sec_audit_mount_persisted() { sec_audit_volume_persisted "$@"; }
sec_audit_mount_is_mounted() { sec_audit_mnt_is_dedicated "$@"; }
sec_audit_mount_has_option() { sec_audit_mnt_flag_set "$@"; }
sec_audit_mount_separate_partition_ok() { sec_audit_volume_isolated "$@"; }
sec_audit_findmnt_have() { sec_audit_mnt_tool_ok; }
sec_audit_findmnt_path_resolvable() { sec_audit_mnt_resolves "$@"; }
sec_audit_findmnt_is_explicit_mountpoint() { sec_audit_mnt_is_dedicated "$@"; }
sec_audit_findmnt_source_for() { sec_audit_mnt_src "$@"; }
sec_audit_findmnt_fstype_for() { sec_audit_mnt_kind "$@"; }
sec_audit_findmnt_options_raw() { sec_audit_mnt_opts "$@"; }
sec_audit_findmnt_has_mnt_option() { sec_audit_mnt_flag_set "$@"; }
sec_audit_findmnt_separate_partition_ok() { sec_audit_volume_isolated "$@"; }
sec_audit_findmnt_tmp_sec_ok() { sec_audit_tmp_volume_ok; }
sec_audit_findmnt_shm_sec_ok() { sec_audit_shm_volume_ok; }
sec_audit_kernel_mod_in_modules_load() { sec_audit_kmod_listed_for_boot "$@"; }
sec_audit_kernel_mod_lsmod_name_loaded() { sec_audit_kmod_currently_loaded "$@"; }
sec_audit_kernel_mod_ko_scan() { sec_audit_kmod_object_scan "$@"; }
sec_audit_kernel_mod_refuses_load() { sec_audit_kmod_probe_blocked "$@"; }
sec_audit_kmod_waiver() { sec_audit_kmod_container_waiver "$@"; }
sec_audit_systemd_unit_enabled_or_active() { sec_audit_unit_is_live "$@"; }

sec_audit_have_bin() { command -v "$1" >/dev/null 2>&1; }

sec_audit_trim() {
    local s="${1#"${1%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

CHK_PASS=0
CHK_FAIL=0

sec_audit_report_pass() { CHK_PASS=$((CHK_PASS + 1)); printf 'RULE%s= PASS: %s\n' "$1" "$2"; }
sec_audit_report_fail() { CHK_FAIL=$((CHK_FAIL + 1)); printf 'RULE%s= FAIL: %s\n' "$1" "$2"; }

TALOSCTL_OK=0
YQ_OK=0
MACHINE_CONFIG_SPEC=""
SECURITY_STATE_YAML=""
TIMESERVER_YAML=""
ADMISSION_CONTROL_YAML=""

sec_audit_talosctl_run() {
    sec_audit_have_bin talosctl || return 1
    talosctl "$@" 2>/dev/null
}

sec_audit_talosctl_read() {
    local path="$1"
    sec_audit_talosctl_run read "$path"
}

sec_audit_talosctl_get_yaml() {
    sec_audit_talosctl_run get "$@" -o yaml
}

sec_audit_init_talos_env() {
    if sec_audit_have_bin talosctl; then
        if talosctl version >/dev/null 2>&1; then
            TALOSCTL_OK=1
        fi
    fi
    sec_audit_have_bin yq && YQ_OK=1

    if [ "$TALOSCTL_OK" -eq 1 ]; then
        SECURITY_STATE_YAML=$(sec_audit_talosctl_get_yaml securitystate)
        TIMESERVER_YAML=$(sec_audit_talosctl_get_yaml timeserver)
        ADMISSION_CONTROL_YAML=$(sec_audit_talosctl_get_yaml admissioncontrolconfigs.kubernetes.talos.dev admission-control)
        if [ "$YQ_OK" -eq 1 ]; then
            MACHINE_CONFIG_SPEC=$(sec_audit_talosctl_get_yaml machineconfig | yq '.spec // .' 2>/dev/null)
        fi
    fi
}

sec_audit_require_talosctl() {
    local num="$1" ctx="$2"
    if [ "$TALOSCTL_OK" -eq 0 ]; then
        sec_audit_report_fail "$num" "${ctx}: talosctl is unavailable or cannot reach the Talos node (install talosctl and configure endpoints/kubeconfig)"
        return 1
    fi
    return 0
}

sec_audit_require_yq() {
    local num="$1" ctx="$2"
    if [ "$YQ_OK" -eq 0 ]; then
        sec_audit_report_fail "$num" "${ctx}: yq is required to parse Talos YAML output (install yq)"
        return 1
    fi
    return 0
}

sec_audit_yq_from_spec() {
    printf '%s' "$MACHINE_CONFIG_SPEC" | yq "$@" 2>/dev/null
}

sec_audit_talos_proc_value() {
    local key="$1"
    sec_audit_trim "$(sec_audit_talosctl_read "/proc/sys/${key//.//}" 2>/dev/null | head -n1)"
}

sec_audit_firewall_policy_configured() {
    local fw_yaml policy rules machine_fw default_action

    if [ -n "$MACHINE_CONFIG_SPEC" ] && [ "$YQ_OK" -eq 1 ]; then
        machine_fw=$(sec_audit_yq_from_spec '.machine.network.firewall // {}')
        default_action=$(printf '%s' "$machine_fw" | yq '.defaultAction // ""' 2>/dev/null)
        if [ -n "$default_action" ] && [ "$default_action" != "null" ]; then
            return 0
        fi
        if printf '%s' "$machine_fw" | yq '.rules // [] | length' 2>/dev/null | grep -qvE '^0$'; then
            return 0
        fi
    fi

    policy=$(sec_audit_talosctl_get_yaml networkdefaultactionconfigs 2>/dev/null)
    rules=$(sec_audit_talosctl_get_yaml networkruleconfigs 2>/dev/null)
    if [ -n "$policy" ] && printf '%s' "$policy" | grep -q 'kind:[[:space:]]*NetworkDefaultActionConfig'; then
        return 0
    fi
    if [ -n "$rules" ] && printf '%s' "$rules" | grep -q 'kind:[[:space:]]*NetworkRuleConfig'; then
        return 0
    fi

    fw_yaml=$(sec_audit_talosctl_read /system/state/config.yaml 2>/dev/null)
    if [ -n "$fw_yaml" ]; then
        if printf '%s' "$fw_yaml" | grep -qE 'kind:[[:space:]]*Network(DefaultAction|Rule)Config'; then
            return 0
        fi
        if printf '%s' "$fw_yaml" | grep -qE 'defaultAction:[[:space:]]*(block|drop)'; then
            return 0
        fi
    fi

    return 1
}

sec_audit_disk_encryption_uses_tpm_or_kms() {
    local enc_yaml
    enc_yaml=$(sec_audit_yq_from_spec '.machine.systemDiskEncryption // {}')
    [ -z "$enc_yaml" ] || [ "$enc_yaml" = "null" ] && return 1

    for method in state ephemeral; do
        if printf '%s' "$enc_yaml" | yq ".${method} // {}" 2>/dev/null | grep -qE '(^|[[:space:]])(tpm|kms):'; then
            return 0
        fi
    done

    if printf '%s' "$enc_yaml" | grep -qE '(^|[[:space:]])(tpm|kms):'; then
        return 0
    fi
    return 1
}

sec_audit_count_ntp_servers() {
    local count=0
    if [ -n "$TIMESERVER_YAML" ] && [ "$YQ_OK" -eq 1 ]; then
        count=$(printf '%s' "$TIMESERVER_YAML" | yq '.spec.timeServers // [] | length' 2>/dev/null)
        case "$count" in
            '' | null) count=0 ;;
            *[!0-9]*) count=0 ;;
        esac
        if [ "$count" -ge 2 ]; then
            printf '%s' "$count"
            return 0
        fi
    fi

    count=$(printf '%s' "$TIMESERVER_YAML" | grep -cE '^[[:space:]]*-[[:space:]]+' 2>/dev/null || true)
    printf '%s' "${count:-0}"
}

sec_audit_check_rule1() {
    local enabled detail
 sec_audit_require_talosctl 1 " 1.1.1 SecureBoot" || return

    if [ "$YQ_OK" -eq 1 ] && [ -n "$SECURITY_STATE_YAML" ]; then
        enabled=$(printf '%s' "$SECURITY_STATE_YAML" | yq '.spec.secureBoot // .spec.secureboot // false' 2>/dev/null)
        case "$(printf '%s' "$enabled" | tr '[:upper:]' '[:lower:]')" in
            true | 1 | yes)
                sec_audit_report_pass 1 "SecureBoot is enabled (securitystate.spec.secureBoot=true; UEFI verifies UKI and bootloader signatures)"
                return
                ;;
            false | 0 | no)
                sec_audit_report_fail 1 "SecureBoot is not enabled (securitystate.spec.secureBoot=false; enable Secure Boot in UEFI and use a signed Talos UKI image)"
                return
                ;;
        esac
    fi

    if printf '%s' "$SECURITY_STATE_YAML" | grep -qiE 'secure[Bb]oot:[[:space:]]*true'; then
        sec_audit_report_pass 1 "SecureBoot is enabled (detected in talosctl get securitystate output)"
    elif printf '%s' "$SECURITY_STATE_YAML" | grep -qiE 'secure[Bb]oot:[[:space:]]*false'; then
        sec_audit_report_fail 1 "SecureBoot is not enabled (securitystate reports secureBoot=false; enable Secure Boot in UEFI and use a signed Talos UKI image)"
    else
        detail="talosctl get securitystate did not report secureBoot=true"
        sec_audit_report_fail 1 "SecureBoot is not enabled (${detail}; note: Secure Boot is not supported on legacy BIOS x86 platforms)"
    fi
}

sec_audit_check_rule2() {
    local methods=""
 sec_audit_require_talosctl 2 " 1.2.1 system disk encryption" || return
 sec_audit_require_yq 2 " 1.2.1 system disk encryption" || return

    if sec_audit_disk_encryption_uses_tpm_or_kms; then
        methods=$(sec_audit_yq_from_spec '.machine.systemDiskEncryption' 2>/dev/null | grep -oE '(tpm|kms):' | tr -d ':' | sort -u | tr '\n' ',' | sed 's/,$//')
        sec_audit_report_pass 2 "System disk encryption is configured with TPM or KMS (methods detected: ${methods:-tpm/kms}; LUKS2 protects STATE/EPHEMERAL partitions)"
    else
        sec_audit_report_fail 2 "System disk encryption is not configured with TPM or KMS (configure machine.systemDiskEncryption.state/ephemeral with tpm and/or kms keys in machine config)"
    fi
}

sec_audit_check_rule3() {
    local version tag_line
 sec_audit_require_talosctl 3 " 1.3 Talos version" || return

    tag_line=$(talosctl version 2>/dev/null | grep -i 'tag' | head -1)
    version=$(printf '%s' "$tag_line" | awk '{print $NF}')
    version=$(sec_audit_trim "$version")
    version=${version#v}

    if [ -n "$version" ]; then
        sec_audit_report_pass 3 "Current Talos version: ${version} (Manual verification recommended: compare with latest stable release at https://github.com/siderolabs/talos/releases)"
    else
        sec_audit_report_fail 3 "Unable to determine Talos version (talosctl version did not return a Tag line; verify cluster connectivity and talosctl configuration)"
    fi
}

sec_audit_check_rule4() {
    local count servers
 sec_audit_require_talosctl 4 " 2.1 NTP" || return

    count=$(sec_audit_count_ntp_servers)
    if [ "${count:-0}" -ge 2 ]; then
        if [ "$YQ_OK" -eq 1 ] && [ -n "$TIMESERVER_YAML" ]; then
            servers=$(printf '%s' "$TIMESERVER_YAML" | yq '.spec.timeServers // [] | join(", ")' 2>/dev/null)
            sec_audit_report_pass 4 "At least 2 NTP servers are configured (${count} servers: ${servers:-see talosctl get timeserver})"
        else
            sec_audit_report_pass 4 "At least 2 NTP servers are configured (${count} entries found in TimeServer resource)"
        fi
    else
 sec_audit_report_fail 4 "Less than 2 NTP servers are configured (found ${count:-0}; recommends >=2 timeServers in machine.time.servers or TimeServer resource; default single server time.cloudflare.com is insufficient)"
    fi
}

sec_audit_check_rule5() {
    local scheduling scheduling_lc
 sec_audit_require_talosctl 5 " 3.1 control plane scheduling" || return
 sec_audit_require_yq 5 " 3.1 control plane scheduling" || return

    scheduling=$(sec_audit_yq_from_spec '.cluster.allowSchedulingOnControlPlanes // ""')
    scheduling=$(sec_audit_trim "$scheduling")
    scheduling_lc=$(printf '%s' "$scheduling" | tr '[:upper:]' '[:lower:]')

    if [ -z "$scheduling" ] || [ "$scheduling" = "null" ] || [ "$scheduling_lc" = "false" ]; then
        sec_audit_report_pass 5 "Control plane scheduling is disabled (false or not set) (cluster.allowSchedulingOnControlPlanes=${scheduling:-unset}; workloads should not run on control plane nodes)"
    else
        sec_audit_report_fail 5 "Control plane scheduling is enabled (cluster.allowSchedulingOnControlPlanes=${scheduling}; set to false to keep sensitive control-plane data off worker-scheduled pods)"
    fi
}

sec_audit_check_rule6() {
    local policy
 sec_audit_require_talosctl 6 " 3.2 Pod Security Standards" || return
 sec_audit_require_yq 6 " 3.2 Pod Security Standards" || return

    policy=$(printf '%s' "$ADMISSION_CONTROL_YAML" | yq '.spec.config[0].configuration.defaults.enforce // ""' 2>/dev/null)
    policy=$(sec_audit_trim "$policy")
    policy_lc=$(printf '%s' "$policy" | tr '[:upper:]' '[:lower:]')

    if [ "$policy_lc" = "restricted" ]; then
        sec_audit_report_pass 6 "Pod Security Standards policy is set to restricted (admission-control defaults.enforce=restricted)"
    else
        sec_audit_report_fail 6 "Pod Security Standards policy is not set to restricted (current: ${policy:-<unset>}; configure admission-control plugin defaults.enforce to restricted)"
    fi
}

sec_audit_check_rule7() {
    local rbac
 sec_audit_require_talosctl 7 " 4.1 RBAC" || return
 sec_audit_require_yq 7 " 4.1 RBAC" || return

    rbac=$(sec_audit_yq_from_spec '.machine.features.rbac // ""')
    rbac_lc=$(printf '%s' "$(sec_audit_trim "$rbac")" | tr '[:upper:]' '[:lower:]')

    if [ "$rbac_lc" = "true" ]; then
        sec_audit_report_pass 7 "RBAC is enabled (machine.features.rbac=true; Kubernetes role-based access control is active)"
    else
        sec_audit_report_fail 7 "RBAC is not enabled (machine.features.rbac=${rbac:-<unset>}; enable RBAC in machine features)"
    fi
}

sec_audit_check_rule8() {
    local all_val default_val
 sec_audit_require_talosctl 8 " 5.1.1 send_redirects" || return

    all_val=$(sec_audit_talos_proc_value 'net.ipv4.conf.all.send_redirects')
    default_val=$(sec_audit_talos_proc_value 'net.ipv4.conf.default.send_redirects')

    if [ "$all_val" = "0" ] && [ "$default_val" = "0" ]; then
        sec_audit_report_pass 8 "Packet redirect sending is disabled (net.ipv4.conf.all.send_redirects=0, net.ipv4.conf.default.send_redirects=0)"
    else
        sec_audit_report_fail 8 "Packet redirect sending is not disabled (all=${all_val:-?}, default=${default_val:-?}; expected 0 on host-only Talos nodes)"
    fi
}

sec_audit_check_rule9() {
    local v4a v4d v6a v6d bad=""
 sec_audit_require_talosctl 9 " 5.2.1 accept_source_route" || return

    v4a=$(sec_audit_talos_proc_value 'net.ipv4.conf.all.accept_source_route')
    v4d=$(sec_audit_talos_proc_value 'net.ipv4.conf.default.accept_source_route')
    v6a=$(sec_audit_talos_proc_value 'net.ipv6.conf.all.accept_source_route')
    v6d=$(sec_audit_talos_proc_value 'net.ipv6.conf.default.accept_source_route')

    for pair in "all/ipv4=$v4a" "default/ipv4=$v4d" "all/ipv6=$v6a" "default/ipv6=$v6d"; do
        val=${pair#*=}
        [ "$val" = "0" ] || bad+="${pair%=*}=${val:-?} "
    done

    if [ -z "$bad" ]; then
        sec_audit_report_pass 9 "Source routed packets are not accepted (accept_source_route=0 for ipv4/ipv6 all and default interfaces)"
    else
        sec_audit_report_fail 9 "Source routed packets acceptance is not disabled (non-zero: ${bad%; }; set all accept_source_route sysctls to 0)"
    fi
}

sec_audit_check_rule10() {
    local v4a v4d v6a v6d bad=""
 sec_audit_require_talosctl 10 " 5.2.2 accept_redirects" || return

    v4a=$(sec_audit_talos_proc_value 'net.ipv4.conf.all.accept_redirects')
    v4d=$(sec_audit_talos_proc_value 'net.ipv4.conf.default.accept_redirects')
    v6a=$(sec_audit_talos_proc_value 'net.ipv6.conf.all.accept_redirects')
    v6d=$(sec_audit_talos_proc_value 'net.ipv6.conf.default.accept_redirects')

    for pair in "all/ipv4=$v4a" "default/ipv4=$v4d" "all/ipv6=$v6a" "default/ipv6=$v6d"; do
        val=${pair#*=}
        [ "$val" = "0" ] || bad+="${pair%=*}=${val:-?} "
    done

    if [ -z "$bad" ]; then
        sec_audit_report_pass 10 "ICMP redirects are not accepted (accept_redirects=0 for ipv4/ipv6 all and default interfaces)"
    else
        sec_audit_report_fail 10 "ICMP redirects acceptance is not disabled (non-zero: ${bad%; }; prevents malicious routing table updates)"
    fi
}

sec_audit_check_rule11() {
    local all_val default_val
 sec_audit_require_talosctl 11 " 5.2.3 secure_redirects" || return

    all_val=$(sec_audit_talos_proc_value 'net.ipv4.conf.all.secure_redirects')
    default_val=$(sec_audit_talos_proc_value 'net.ipv4.conf.default.secure_redirects')

    if [ "$all_val" = "0" ] && [ "$default_val" = "0" ]; then
        sec_audit_report_pass 11 "Secure ICMP redirects are not accepted (net.ipv4.conf.all.secure_redirects=0, default=0)"
    else
        sec_audit_report_fail 11 "Secure ICMP redirects acceptance is not disabled (all=${all_val:-?}, default=${default_val:-?}; expected 0)"
    fi
}

sec_audit_check_rule12() {
    local all_val default_val
 sec_audit_require_talosctl 12 " 5.2.4 log_martians" || return

    all_val=$(sec_audit_talos_proc_value 'net.ipv4.conf.all.log_martians')
    default_val=$(sec_audit_talos_proc_value 'net.ipv4.conf.default.log_martians')

    if [ "$all_val" = "1" ] && [ "$default_val" = "1" ]; then
        sec_audit_report_pass 12 "Suspicious (martian) packets are logged (log_martians=1 on all and default interfaces)"
    else
        sec_audit_report_fail 12 "Suspicious (martian) packets logging is not enabled (all=${all_val:-?}, default=${default_val:-?}; expected 1)"
    fi
}

sec_audit_check_rule13() {
    local val
 sec_audit_require_talosctl 13 " 5.2.5 icmp_echo_ignore_broadcasts" || return

    val=$(sec_audit_talos_proc_value 'net.ipv4.icmp_echo_ignore_broadcasts')
    if [ "$val" = "1" ]; then
        sec_audit_report_pass 13 "Broadcast ICMP requests are ignored (net.ipv4.icmp_echo_ignore_broadcasts=1; mitigates Smurf amplification)"
    else
        sec_audit_report_fail 13 "Broadcast ICMP requests are not ignored (net.ipv4.icmp_echo_ignore_broadcasts=${val:-?}; expected 1)"
    fi
}

sec_audit_check_rule14() {
    local val
 sec_audit_require_talosctl 14 " 5.2.6 icmp_ignore_bogus_error_responses" || return

    val=$(sec_audit_talos_proc_value 'net.ipv4.icmp_ignore_bogus_error_responses')
    if [ "$val" = "1" ]; then
        sec_audit_report_pass 14 "Bogus ICMP responses are ignored (net.ipv4.icmp_ignore_bogus_error_responses=1)"
    else
        sec_audit_report_fail 14 "Bogus ICMP responses are not ignored (net.ipv4.icmp_ignore_bogus_error_responses=${val:-?}; expected 1)"
    fi
}

sec_audit_check_rule15() {
    local val
 sec_audit_require_talosctl 15 " 5.2.7 tcp_syncookies" || return

    val=$(sec_audit_talos_proc_value 'net.ipv4.tcp_syncookies')
    if [ "$val" = "1" ]; then
        sec_audit_report_pass 15 "TCP SYN Cookies is enabled (net.ipv4.tcp_syncookies=1; protects against SYN-flood DoS)"
    else
        sec_audit_report_fail 15 "TCP SYN Cookies is not enabled (net.ipv4.tcp_syncookies=${val:-?}; expected 1)"
    fi
}

sec_audit_check_rule16() {
    local all_val default_val all_ok default_ok
 sec_audit_require_talosctl 16 " 5.2.8 rp_filter" || return

    all_val=$(sec_audit_talos_proc_value 'net.ipv4.conf.all.rp_filter')
    default_val=$(sec_audit_talos_proc_value 'net.ipv4.conf.default.rp_filter')

    case "$all_val" in 1 | 2) all_ok=1 ;; *) all_ok=0 ;; esac
    case "$default_val" in 1 | 2) default_ok=1 ;; *) default_ok=0 ;; esac

    if [ "$all_ok" -eq 1 ] && [ "$default_ok" -eq 1 ]; then
 sec_audit_report_pass 16 "Reverse Path Filtering is enabled (value: all=${all_val}, default=${default_val}; accepts strict=1 or loose=2 mode)"
    else
        sec_audit_report_fail 16 "Reverse Path Filtering is not enabled (all: ${all_val:-?}, default: ${default_val:-?}; set rp_filter to 1 or 2 when using symmetric routes)"
    fi
}

sec_audit_check_rule17() {
 sec_audit_require_talosctl 17 " 5.3.1.1 control plane firewall" || return

    if sec_audit_firewall_policy_configured; then
        sec_audit_report_pass 17 "Control plane firewall policy is configured (NetworkDefaultActionConfig and/or NetworkRuleConfig or machine.network.firewall present)"
    else
        sec_audit_report_fail 17 "Control plane firewall policy is not configured (define default deny firewall policy and explicit NetworkRuleConfig rules for control plane APIs)"
    fi
}

sec_audit_check_rule18() {
 sec_audit_require_talosctl 18 " 5.3.2.1 worker firewall" || return

    if sec_audit_firewall_policy_configured; then
        sec_audit_report_pass 18 "Worker node firewall policy is configured (NetworkDefaultActionConfig and/or NetworkRuleConfig or machine.network.firewall present)"
    else
        sec_audit_report_fail 18 "Worker node firewall policy is not configured (apply default-deny host firewall with explicit allow rules for required worker services)"
    fi
}

sec_audit_check_rule19() {
    local enabled enabled_lc identities
 sec_audit_require_talosctl 19 " 5.4.1 KubeSpan" || return

    if [ "$YQ_OK" -eq 1 ]; then
        enabled=$(sec_audit_yq_from_spec '.machine.network.kubespan.enabled // ""')
        enabled_lc=$(printf '%s' "$(sec_audit_trim "$enabled")" | tr '[:upper:]' '[:lower:]')
        if [ "$enabled_lc" = "true" ]; then
            identities=$(sec_audit_talosctl_get_yaml kubespanidentities 2>/dev/null | grep -c 'kind:[[:space:]]*KubeSpanIdentity' || true)
            sec_audit_report_pass 19 "KubeSpan is enabled (machine.network.kubespan.enabled=true${identities:+, identities=${identities}}; WireGuard mesh encrypts inter-node traffic)"
            return
        fi
    fi

    if sec_audit_talosctl_get_yaml kubespanidentities 2>/dev/null | grep -q 'kind:[[:space:]]*KubeSpanIdentity'; then
        sec_audit_report_pass 19 "KubeSpan is enabled (KubeSpanIdentity resources present; cluster mesh encryption active)"
    else
        sec_audit_report_fail 19 "KubeSpan is not enabled (set machine.network.kubespan.enabled=true when cross-network WireGuard encryption is required)"
    fi
}

sec_audit_check_rule20() {
    local kmsg_cfg cmdline kernel_log
 sec_audit_require_talosctl 20 " 6.1.1 kernel logging" || return

    cmdline=$(sec_audit_talosctl_read /proc/cmdline 2>/dev/null)
    kernel_log=$(printf '%s' "$cmdline" | grep -oE 'talos\.logging\.kernel=[^[:space:]]+' | head -1)

    if [ "$YQ_OK" -eq 1 ]; then
        kmsg_cfg=$(sec_audit_yq_from_spec '.. | select(.kind? == "KmsgLogConfig") | .endpoint // .url // .address' 2>/dev/null | head -1)
        kmsg_cfg=$(sec_audit_trim "$kmsg_cfg")
    fi

    if [ -n "$kernel_log" ] || [ -n "$kmsg_cfg" ]; then
        sec_audit_report_pass 20 "Kernel logging is configured to send logs to a remote service (${kernel_log:-KmsgLogConfig endpoint=${kmsg_cfg}})"
    else
        sec_audit_report_fail 20 "Kernel logging is not configured to send logs to a remote service (add talos.logging.kernel= endpoint on kernel cmdline or KmsgLogConfig in machine config)"
    fi
}

sec_audit_check_rule21() {
    local count endpoint
 sec_audit_require_talosctl 21 " 6.2.1 service logging" || return
 sec_audit_require_yq 21 " 6.2.1 service logging" || return

    count=$(sec_audit_yq_from_spec '.machine.logging.destinations // [] | length' 2>/dev/null)
    case "$count" in
        '' | null) count=0 ;;
        *[!0-9]*) count=0 ;;
    esac

    if [ "${count:-0}" -gt 0 ]; then
        endpoint=$(sec_audit_yq_from_spec '.machine.logging.destinations[0].endpoint // .machine.logging.destinations[0].url // ""' 2>/dev/null)
        endpoint=$(sec_audit_trim "$endpoint")
        sec_audit_report_pass 21 "Service logging is configured to send logs to a remote service (${count} destination(s)${endpoint:+, primary endpoint=${endpoint}})"
    else
        sec_audit_report_fail 21 "Service logging is not configured to send logs to a remote service (configure machine.logging.destinations with a remote syslog/OTLP endpoint)"
    fi
}

sec_audit_run_all_checks() {
    sec_audit_init_talos_env

    sec_audit_check_rule1
    sec_audit_check_rule2
    sec_audit_check_rule3
    sec_audit_check_rule4
    sec_audit_check_rule5
    sec_audit_check_rule6
    sec_audit_check_rule7
    sec_audit_check_rule8
    sec_audit_check_rule9
    sec_audit_check_rule10
    sec_audit_check_rule11
    sec_audit_check_rule12
    sec_audit_check_rule13
    sec_audit_check_rule14
    sec_audit_check_rule15
    sec_audit_check_rule16
    sec_audit_check_rule17
    sec_audit_check_rule18
    sec_audit_check_rule19
    sec_audit_check_rule20
    sec_audit_check_rule21

    printf 'SUMMARY: PASS=%d FAIL=%d\n' "$CHK_PASS" "$CHK_FAIL"
}

sec_audit_run_all_checks
exit 0

