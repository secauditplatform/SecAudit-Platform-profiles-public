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

AZ_FIND_CAP="${AZ_FIND_CAP:-20}"
AZ_CMD_CAP="${AZ_CMD_CAP:-12}"
AZ_DNF_CAP="${AZ_DNF_CAP:-30}"
AZ_ALLOW_CONTAINER_KMOD="${AZ_ALLOW_CONTAINER_KMOD:-${LINUX_CRE_ALLOW_CONTAINER_MODULES:-${ALMA_CRE_ALLOW_CONTAINER_MODULES:-0}}}"

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
        function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
        function lc(s)  { return tolower(s) }
        BEGIN { in_main = 0; v = "" }
        /^[[:space:]]*\[main[[:space:]]*\]/ { in_main = 1; next }
        /^[[:space:]]*\[/ { in_main = 0; next }
        in_main {
            line = $0
            sub(/#.*/, "", line)
            if (line ~ /^[[:space:]]*$/ || line !~ /=/) next
            eq = index(line, "=")
            key = trim(substr(line, 1, eq - 1))
            val = trim(substr(line, eq + 1))
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
            function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
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
                sec = trim(line); enabled = 1; gc_explicit = 0; gc_val = ""; next
            }
            {
                line = $0; sub(/#.*/, "", line)
                if (line !~ /=/) next
                eq = index(line, "=")
                k = tolower(trim(substr(line, 1, eq - 1)))
                v = trim(substr(line, eq + 1))
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
            function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
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
                sec = trim(line); enabled = 1; rgc_explicit = 0; rgc_val = ""; next
            }
            {
                line = $0; sub(/#.*/, "", line)
                if (line !~ /=/) next
                eq = index(line, "=")
                k = tolower(trim(substr(line, 1, eq - 1)))
                v = trim(substr(line, eq + 1))
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
            function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
            BEGIN { sec = ""; enabled = 1; has_uri = 0; found = 0 }
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*;/ { next }
            /^[[:space:]]*\[/ {
                if (sec != "" && enabled && has_uri) found = 1
                line = $0; sub(/#.*/, "", line); gsub(/^\[|\]$/, "", line)
                sec = trim(line); enabled = 1; has_uri = 0; next
            }
            {
                line = $0; sub(/#.*/, "", line)
                if (line !~ /=/) next
                eq = index(line, "=")
                k = tolower(trim(substr(line, 1, eq - 1)))
                v = trim(substr(line, eq + 1))
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
    n=$(sec_audit_exec_with_timeout "$AZ_DNF_CAP" dnf -q repolist enabled 2>/dev/null | awk '
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
    local pattern="$1" cap="${2:-$AZ_FIND_CAP}" rc=0 out=""
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
            [[ "${AZ_ALLOW_CONTAINER_KMOD}" == "1" ]]
            ;;
        *) return 1 ;;
    esac
}

sec_audit_audit_kmod_absent() {
    local num="$1" label="$2" mod="$3" ko_pattern="$4"
    shift 4
    local alias loaded=0 a
    if sec_audit_kmod_container_waiver "$mod"; then
        sec_audit_report_pass "$num" "${label} (waived: AZ_ALLOW_CONTAINER_KMOD=1)"
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
sec_audit_findmnt_have() { sec_audit_mnt_tool_ok; }
sec_audit_findmnt_path_resolvable() { sec_audit_mnt_resolves "$@"; }
sec_audit_findmnt_is_explicit_mountpoint() { sec_audit_mnt_is_dedicated "$@"; }
sec_audit_findmnt_source_for() { sec_audit_mnt_src "$@"; }
sec_audit_findmnt_fstype_for() { sec_audit_mnt_kind "$@"; }
sec_audit_findmnt_options_raw() { sec_audit_mnt_opts "$@"; }
sec_audit_findmnt_has_mnt_option() { sec_audit_mnt_flag_set "$@"; }
sec_audit_findmnt_separate_partition_ok() { sec_audit_volume_isolated "$@"; }
sec_audit_kernel_mod_in_modules_load() { sec_audit_kmod_listed_for_boot "$@"; }
sec_audit_kernel_mod_lsmod_name_loaded() { sec_audit_kmod_currently_loaded "$@"; }
sec_audit_kernel_mod_ko_scan() { sec_audit_kmod_object_scan "$@"; }
sec_audit_kernel_mod_refuses_load() { sec_audit_kmod_probe_blocked "$@"; }
sec_audit_kmod_waiver() { sec_audit_kmod_container_waiver "$@"; }
sec_audit_systemd_unit_enabled_or_active() { sec_audit_unit_is_live "$@"; }

sec_audit_findmnt_tmp_sec_ok() {
    local fst src root_src
    sec_audit_findmnt_have || return 1
    sec_audit_findmnt_is_explicit_mountpoint /tmp || return 1
    fst=$(sec_audit_findmnt_fstype_for /tmp)
    src=$(sec_audit_findmnt_source_for /tmp)
    root_src=$(sec_audit_findmnt_source_for /)
    [ "$fst" = "tmpfs" ] && return 0
    [ -n "$src" ] && [ -n "$root_src" ] && [ "$src" != "$root_src" ] && return 0
    return 1
}

sec_audit_findmnt_shm_sec_ok() {
    local fst src root_src
    sec_audit_findmnt_have || return 1
    sec_audit_findmnt_is_explicit_mountpoint /dev/shm || return 1
    fst=$(sec_audit_findmnt_fstype_for /dev/shm)
    src=$(sec_audit_findmnt_source_for /dev/shm)
    root_src=$(sec_audit_findmnt_source_for /)
    [ "$fst" = "tmpfs" ] && return 0
    [ -n "$src" ] && [ -n "$root_src" ] && [ "$src" != "$root_src" ] && return 0
    return 1
}

sec_audit_dnf_main_last_value() {
    local want="$1" f files=()
    [[ -f /etc/dnf/dnf.conf ]] && files+=(/etc/dnf/dnf.conf)
    if [[ -d /etc/dnf/dnf.conf.d ]]; then
        shopt -s nullglob
        for f in /etc/dnf/dnf.conf.d/*.conf; do
            [[ -f $f ]] && files+=("$f")
        done
        shopt -u nullglob
    fi
    ((${#files[@]})) || {
        builtin printf '%s\n' ""
        return 0
    }
    awk -v want="$1" '
        function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
        function lc(s)  { return tolower(s) }
        BEGIN { in_main = 0; v = "" }
        /^[[:space:]]*\[main[[:space:]]*\]/ {
            in_main = 1
            next
        }
        /^[[:space:]]*\[/ {
            in_main = 0
            next
        }
        in_main {
            line = $0
            sub(/#.*/, "", line)
            if (line ~ /^[[:space:]]*$/ || line !~ /=/) next
            eq = index(line, "=")
            key = trim(substr(line, 1, eq - 1))
            val = trim(substr(line, eq + 1))
            if (lc(key) == lc(want)) v = val
        }
        END { print v }
    ' "${files[@]}" 2>/dev/null
}

sec_audit_dnf_val_is_false() {
    case "$(builtin printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')" in
    0 | false | no | off) return 0 ;;
    *) return 1 ;;
    esac
}

sec_audit_dnf_val_is_true() {
    case "$(builtin printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')" in
    1 | true | yes | on) return 0 ;;
    *) return 1 ;;
    esac
}

sec_audit_rpm_gpg_pubkey_pkg_count() {
    local c
    if ! sec_audit_have_bin rpm; then
        builtin printf '%s\n' 0
        return 0
    fi
    c=$(rpm -qa 'gpg-pubkey*' 2>/dev/null | grep -cve '^[[:space:]]*$' || true)
    builtin printf '%s\n' "${c:-0}"
}

sec_audit_yum_repo_list_explicit_gpgcheck0() {
    local f
    [[ -d /etc/yum.repos.d ]] || return 0
    shopt -s nullglob
    for f in /etc/yum.repos.d/*.repo; do
        [[ -f $f ]] || continue
        awk '
            function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
            function flush() {
                if (sec == "") return
                if (enabled && gc_explicit && sec_audit_dnf_val_is_false(gc_val)) {
                    print FILENAME "|" sec
                }
                sec = ""
                enabled = 1
                gc_explicit = 0
                gc_val = ""
            }
            function sec_audit_dnf_val_is_false(s, t) {
                t = tolower(s)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", t)
                return (t == "0" || t == "false" || t == "no" || t == "off")
            }
            BEGIN { sec = ""; enabled = 1; gc_explicit = 0; gc_val = "" }
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*;/ { next }
            /^[[:space:]]*\[/ {
                flush()
                line = $0
                sub(/#.*/, "", line)
                gsub(/^\[|\]$/, "", line)
                sec = trim(line)
                enabled = 1
                gc_explicit = 0
                gc_val = ""
                next
            }
            {
                line = $0
                sub(/#.*/, "", line)
                if (line !~ /=/) next
                eq = index(line, "=")
                k = tolower(trim(substr(line, 1, eq - 1)))
                v = trim(substr(line, eq + 1))
                if (k == "enabled") {
                    vv = tolower(v)
                    if (vv == "0" || vv == "false" || vv == "no" || vv == "off") enabled = 0
                    else enabled = 1
                    next
                }
                if (k == "gpgcheck") {
                    gc_explicit = 1
                    gc_val = v
                }
            }
            END { flush() }
        ' "$f" 2>/dev/null
    done
    shopt -u nullglob
}

sec_audit_yum_repo_list_explicit_repo_gpgcheck0() {
    local f
    [[ -d /etc/yum.repos.d ]] || return 0
    shopt -s nullglob
    for f in /etc/yum.repos.d/*.repo; do
        [[ -f $f ]] || continue
        awk '
            function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
            function flush() {
                if (sec == "") return
                if (enabled && rgc_explicit && sec_audit_dnf_val_is_false(rgc_val)) {
                    print FILENAME "|" sec
                }
                sec = ""
                enabled = 1
                rgc_explicit = 0
                rgc_val = ""
            }
            function sec_audit_dnf_val_is_false(s, t) {
                t = tolower(s)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", t)
                return (t == "0" || t == "false" || t == "no" || t == "off")
            }
            BEGIN { sec = ""; enabled = 1; rgc_explicit = 0; rgc_val = "" }
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*;/ { next }
            /^[[:space:]]*\[/ {
                flush()
                line = $0
                sub(/#.*/, "", line)
                gsub(/^\[|\]$/, "", line)
                sec = trim(line)
                enabled = 1
                rgc_explicit = 0
                rgc_val = ""
                next
            }
            {
                line = $0
                sub(/#.*/, "", line)
                if (line !~ /=/) next
                eq = index(line, "=")
                k = tolower(trim(substr(line, 1, eq - 1)))
                v = trim(substr(line, eq + 1))
                if (k == "enabled") {
                    vv = tolower(v)
                    if (vv == "0" || vv == "false" || vv == "no" || vv == "off") enabled = 0
                    else enabled = 1
                    next
                }
                if (k == "repo_gpgcheck") {
                    rgc_explicit = 1
                    rgc_val = v
                }
            }
            END { flush() }
        ' "$f" 2>/dev/null
    done
    shopt -u nullglob
}

sec_audit_yum_repo_any_enabled_has_uris() {
    local f
    [[ -d /etc/yum.repos.d ]] || return 1
    shopt -s nullglob
    for f in /etc/yum.repos.d/*.repo; do
        [[ -f $f ]] || continue
        awk '
            function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
            BEGIN { sec = ""; enabled = 1; has_uri = 0; found = 0 }
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*;/ { next }
            /^[[:space:]]*\[/ {
                if (sec != "" && enabled && has_uri) found = 1
                line = $0
                sub(/#.*/, "", line)
                gsub(/^\[|\]$/, "", line)
                sec = trim(line)
                enabled = 1
                has_uri = 0
                next
            }
            {
                line = $0
                sub(/#.*/, "", line)
                if (line !~ /=/) next
                eq = index(line, "=")
                k = tolower(trim(substr(line, 1, eq - 1)))
                v = trim(substr(line, eq + 1))
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

sec_audit_dnf_repolist_enabled_count() {
    local n
    if ! sec_audit_have_bin dnf; then
        builtin printf '%s\n' 0
        return 0
    fi
    n=$(dnf -q repolist enabled 2>/dev/null | awk '
        /^repo[[:space:]]+id[[:space:]]/ { hdr = 1; next }
        hdr && NF >= 1 && $1 != "" && $1 !~ /^repolist:/ && $1 !~ /^Repo/ { c++ }
        END { print c + 0 }
    ')
    [[ -n "$n" ]] || n=0
    builtin printf '%s\n' "$n"
}

sec_audit_tdnf_main_last_value() {
    local want="$1" f=/etc/tdnf/tdnf.conf v=""
    [[ -f $f ]] || {
        builtin printf '%s\n' ""
        return 0
    }
    v=$(awk -v want="$1" '
        function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
        function lc(s)  { return tolower(s) }
        BEGIN { in_main = 0; val = ""; out = "" }
        /^[[:space:]]*\[main[[:space:]]*\]/ { in_main = 1; next }
        /^[[:space:]]*\[/ { in_main = 0; next }
        in_main {
            line = $0
            sub(/#.*/, "", line)
            if (line ~ /^[[:space:]]*$/ || line !~ /=/) next
            eq = index(line, "=")
            key = trim(substr(line, 1, eq - 1))
            val = trim(substr(line, eq + 1))
            if (lc(key) == lc(want)) out = val
        }
        END { print out }
    ' "$f" 2>/dev/null)
    builtin printf '%s\n' "$v"
}

sec_audit_pkg_service_not_enabled_or_masked() {
    local unit="$1"
    local en ac
    en=$(systemctl is-enabled "$unit" 2>/dev/null)
    ac=$(systemctl is-active "$unit" 2>/dev/null)
    case "$en" in
    masked | disabled | static)
        [ "$ac" != "active" ] && return 0
        return 1
        ;;
    enabled)
        return 1
        ;;
    *)
        [ "$ac" != "active" ] && return 0
        return 1
        ;;
    esac
}

sec_audit_pkgmgr_repolist_enabled_count() {
    local n
    if sec_audit_have_bin tdnf; then
        n=$(tdnf -q repolist enabled 2>/dev/null | awk '
            /^repo[[:space:]]+id[[:space:]]/ { hdr = 1; next }
            hdr && NF >= 1 && $1 != "" && $1 !~ /^repolist:/ && $1 !~ /^Repo/ { c++ }
            END { print c + 0 }
        ')
        [[ -n "$n" ]] || n=0
        builtin printf '%s\n' "$n"
        return 0
    fi
    sec_audit_dnf_repolist_enabled_count
}

_SSHD_T_READY=0
_sshd_t_cache=""

sec_audit_sshd_t_ensure() {
    [ "${_SSHD_T_READY:-0}" -eq 1 ] && return 0
    _SSHD_T_READY=1
    if sec_audit_have_bin sshd; then
        _sshd_t_cache=$(sshd -T 2>/dev/null) || _sshd_t_cache=""
    else
        _sshd_t_cache=""
    fi
}

sec_audit_sshd_effective_dump() {
    sec_audit_sshd_t_ensure
    builtin printf '%s\n' "$_sshd_t_cache"
}

sec_audit_sshd_t_grep() {
    sec_audit_sshd_t_ensure
    builtin printf '%s\n' "$_sshd_t_cache" | grep "$@"
}

sec_audit_sshd_t_awk() {
    sec_audit_sshd_t_ensure
    builtin printf '%s\n' "$_sshd_t_cache" | awk "$@"
}

_AUDITCTL_L_READY=0
_auditctl_l_cache=""

sec_audit_auditctl_l_ensure() {
    [ "${_AUDITCTL_L_READY:-0}" -eq 1 ] && return 0
    _AUDITCTL_L_READY=1
    if sec_audit_have_bin auditctl; then
        _auditctl_l_cache=$(auditctl -l 2>/dev/null) || _auditctl_l_cache=""
    else
        _auditctl_l_cache=""
    fi
}

sec_audit_auditctl_rules_grep() {
    sec_audit_auditctl_l_ensure
    builtin printf '%s\n' "$_auditctl_l_cache" | grep "$@"
}

sec_audit_pkg_any_installed() {
    for pkg in "$@"; do
        if rpm -q "$pkg" &>/dev/null; then
            return 0
        fi
    done
    return 1
}

sec_audit_sysctl_key_runtime_raw() {
    sec_audit_have_bin sysctl || return 1
    sysctl -n "$1" 2>/dev/null | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

sec_audit_sysctl_key_runtime() {
    builtin printf '%s' "$(sec_audit_sysctl_key_runtime_raw "$1")"
}

sec_audit_sysctl_runtime_equals() {
    local got
    got=$(sec_audit_sysctl_key_runtime_raw "$1") || return 1
    [[ "$got" == "$2" ]]
}

sec_audit_sysctl_runtime_matches_regex() {
    local got
    got=$(sec_audit_sysctl_key_runtime_raw "$1") || return 1
    [[ "$got" =~ $2 ]]
}

sec_audit_sysctl_files_last_assignment_value() {
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
    builtin printf '%s' "$val"
}

sec_audit_sysctl_runtime_disk_hint() {
    local key="$1" want="$2" disk got
    got=$(sec_audit_sysctl_key_runtime_raw "$key") || got=""
    disk=$(sec_audit_sysctl_files_last_assignment_value "$key")
    [[ -z $disk ]] && return 0
    if [[ "$got" == "$want" && "$disk" != "$want" ]]; then
        builtin printf '%s' " | note: last on-disk assignment is ${disk} (runtime overrides until reboot)"
    elif [[ "$got" != "$want" && "$disk" == "$want" ]]; then
        builtin printf '%s' " | on-disk last value is ${want} but kernel has '${got:-?}'; run sysctl --system or reboot"
    elif [[ "$got" != "$want" && -n $disk && "$disk" != "$want" ]]; then
        builtin printf '%s' " | on-disk last value is ${disk}, kernel '${got:-?}'"
    fi
}

sec_audit_limits_core_zero_and_systemd_ok() {
    grep -Psi '^\*\s+hard\s+core\s+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null || return 1
    if grep -rPqi '^\h*DefaultLimitCORE\h*=\h*(infinity|unlimited)\b' /etc/systemd/system.conf /etc/systemd/user.conf /etc/systemd/system.conf.d/*.conf /etc/systemd/user.conf.d/*.conf 2>/dev/null; then
        return 1
    fi
    if grep -rPqi '^\h*DefaultLimitCORE\h*=\h*[1-9][0-9]*\b' /etc/systemd/system.conf /etc/systemd/user.conf /etc/systemd/system.conf.d/*.conf /etc/systemd/user.conf.d/*.conf 2>/dev/null; then
        return 1
    fi
    return 0
}

_audit_rules_files_ready=0
_audit_rules_files_cache=""

sec_audit_audit_rules_files_ensure() {
    [ "${_audit_rules_files_ready:-0}" -eq 1 ] && return 0
    _audit_rules_files_ready=1
    shopt -s nullglob
    _audit_rules_files_cache=$(cat /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null)
    shopt -u nullglob
}

sec_audit_audit_rules_files_grep() {
    sec_audit_audit_rules_files_ensure
    builtin printf '%s\n' "$_audit_rules_files_cache" | grep "$@"
}

sec_audit_audit_rule_loaded_and_on_disk() {
    sec_audit_audit_rules_files_ensure
    sec_audit_auditctl_l_ensure
    builtin printf '%s\n' "$_audit_rules_files_cache" | grep -q "$@" || return 1
    builtin printf '%s\n' "$_auditctl_l_cache" | grep -q "$@" || return 1
    return 0
}

sec_audit_pam_stack_paths_password_system() {
    local f p
    for f in /etc/pam.d/password-auth /etc/pam.d/system-auth; do
        [[ -e $f ]] || continue
        if sec_audit_have_bin readlink; then
            p=$(readlink -f "$f" 2>/dev/null || echo "$f")
        else
            p=$f
        fi
        builtin printf '%s\n' "$p"
    done | sort -u
}

sec_audit_pam_password_pwquality_before_unix_all_stacks() {
    local p any=0
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
    done <<< "$(sec_audit_pam_stack_paths_password_system)"
    [[ $any -eq 1 ]]
}

sec_audit_pam_password_line_has_module() {
    local mod="$1" p
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
    done <<< "$(sec_audit_pam_stack_paths_password_system)"
    return 1
}

sec_audit_grub_cfg_paths() {
    local p
    [[ -f /boot/grub2/grub.cfg ]] && builtin printf '%s\n' /boot/grub2/grub.cfg
    [[ -f /boot/grub/grub.cfg ]] && builtin printf '%s\n' /boot/grub/grub.cfg
    shopt -s nullglob
    for p in /boot/efi/*/grub.cfg /boot/efi/EFI/*/grub.cfg; do
        [[ -f $p ]] && builtin printf '%s\n' "$p"
    done
    shopt -u nullglob
}

sec_audit_grub_cfg_grep() {
    local pat="$1" p found=0
    while IFS= read -r p; do
        [[ -f $p ]] || continue
        if grep -qE "$pat" "$p" 2>/dev/null; then
            found=1
            break
        fi
    done <<< "$(sec_audit_grub_cfg_paths)"
    [ "${found:-0}" -eq 1 ]
}

sec_audit_sshd_effective_usable() {
    sec_audit_sshd_t_ensure
    if ! sec_audit_have_bin sshd; then
        return 1
    fi
    [[ -n "${_sshd_t_cache//[[:space:]]/}" ]]
}

sec_audit_pam_stacks_grep_P() {
    local pattern="$1" p stacks
    stacks="$(sec_audit_pam_stack_paths_password_system)"
    while IFS= read -r p; do
        [[ -f $p ]] || continue
        if grep -P "$pattern" "$p" 2>/dev/null; then
            return 0
        fi
    done <<< "$stacks"
    return 1
}

sec_audit_pam_stacks_grep_Pi() {
    local pattern="$1" p stacks
    stacks="$(sec_audit_pam_stack_paths_password_system)"
    while IFS= read -r p; do
        [[ -f $p ]] || continue
        if grep -Pi "$pattern" "$p" 2>/dev/null; then
            return 0
        fi
    done <<< "$stacks"
    return 1
}

sec_audit_pam_auth_stacks_grep_Pi() {
    local pattern="$1" f p paths=""
    for f in /etc/pam.d/password-auth /etc/pam.d/system-auth /etc/pam.d/su; do
        [[ -e $f ]] || continue
        if sec_audit_have_bin readlink; then
            p=$(readlink -f "$f" 2>/dev/null || echo "$f")
        else
            p=$f
        fi
        paths+="${paths:+$'\n'}$p"
    done
    while IFS= read -r p; do
        [[ -f $p ]] || continue
        if grep -Pi "$pattern" "$p" 2>/dev/null; then
            return 0
        fi
    done <<< "$(sort -u <<< "$paths")"
    return 1
}
# RULE1:
sec_audit_audit_kmod_absent 1 "cramfs kernel module" cramfs cramfs.ko* "cramfs"
# RULE2:
sec_audit_audit_kmod_absent 2 "freevxfs kernel module" freevxfs freevxfs.ko* "freevxfs"
# RULE3:
sec_audit_audit_kmod_absent 3 "hfs kernel module" hfs hfs.ko* "hfs"
# RULE4:
sec_audit_audit_kmod_absent 4 "hfsplus kernel module" hfsplus hfsplus.ko* "hfsplus"
# RULE5:
sec_audit_audit_kmod_absent 5 "jffs2 kernel module" jffs2 jffs2.ko* "jffs2"
# RULE6:
UNUSED_FS="squashfs udf overlay"
FAIL=0
for fs in $UNUSED_FS; do
    if sec_audit_kernel_mod_in_modules_load "$fs"; then
        FAIL=1
        continue
    fi
    if sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "${fs}.ko*" 2>/dev/null | grep -q .; then
        if lsmod | grep -q "$fs"; then
            FAIL=1
        elif ! modprobe --showconfig 2>/dev/null | grep -Pq "^\h*(blacklist|install)\h+${fs}\b"; then
            FAIL=1
        fi
    fi
done
if [ $FAIL -eq 0 ]; then
    sec_audit_report_pass 6 "unused filesystems kernel modules are not available"
else
    sec_audit_report_fail 6 "unused filesystems kernel modules are not available"
fi

# RULE7:
if sec_audit_findmnt_tmp_sec_ok; then
    if sec_audit_mount_persisted /tmp; then
        sec_audit_report_pass 7 "/tmp is tmpfs or a separate partition"
    else
        sec_audit_report_fail 7 "/tmp is tmpfs or a separate partition is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 7 "/tmp does not meet tmpfs or separate-partition requirement"
fi
# RULE8:
if sec_audit_findmnt_path_resolvable /tmp && sec_audit_findmnt_has_mnt_option /tmp nodev; then
    sec_audit_report_pass 8 "nodev option set on /tmp partition"
elif ! sec_audit_findmnt_path_resolvable /tmp; then
    sec_audit_report_fail 8 "nodev is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 8 "nodev is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE9:
if sec_audit_findmnt_path_resolvable /tmp && sec_audit_findmnt_has_mnt_option /tmp nosuid; then
    sec_audit_report_pass 9 "nosuid option set on /tmp partition"
elif ! sec_audit_findmnt_path_resolvable /tmp; then
    sec_audit_report_fail 9 "nosuid is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 9 "nosuid is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE10:
if sec_audit_findmnt_shm_sec_ok; then
    if sec_audit_mount_persisted /dev/shm; then
        sec_audit_report_pass 10 "/dev/shm is tmpfs or a separate partition"
    else
        sec_audit_report_fail 10 "/dev/shm is tmpfs or a separate partition is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 10 "/dev/shm does not meet tmpfs or separate-partition requirement"
fi
# RULE11:
if sec_audit_findmnt_path_resolvable /dev/shm && sec_audit_findmnt_has_mnt_option /dev/shm nodev; then
    sec_audit_report_pass 11 "nodev option set on /dev/shm partition"
elif ! sec_audit_findmnt_path_resolvable /dev/shm; then
    sec_audit_report_fail 11 "nodev is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 11 "nodev is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
fi

# RULE12:
if sec_audit_findmnt_path_resolvable /dev/shm && sec_audit_findmnt_has_mnt_option /dev/shm nosuid; then
    sec_audit_report_pass 12 "nosuid option set on /dev/shm partition"
elif ! sec_audit_findmnt_path_resolvable /dev/shm; then
    sec_audit_report_fail 12 "nosuid is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 12 "nosuid is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
fi

# RULE13:
_rule13_k=$(sec_audit_rpm_gpg_pubkey_pkg_count)
_rule13_sample=""
if sec_audit_have_bin rpm && [ "${_rule13_k:-0}" -gt 0 ]; then
    _rule13_sample=$(
        rpm -qa 'gpg-pubkey*' --qf '%{VERSION}\n' 2>/dev/null | awk 'NF && NR <= 6 { s = (s ? s "," : s) $1 } END { print s }'
    )
fi
if ! sec_audit_have_bin rpm; then
    sec_audit_report_fail 13 "rpm not available; cannot verify gpg-pubkey packages in the RPM database"
elif [ "${_rule13_k:-0}" -eq 0 ]; then
    sec_audit_report_fail 13 "no gpg-pubkey packages in the RPM database (import distribution or repository signing keys)"
else
    sec_audit_report_pass 13 "${_rule13_k} gpg-pubkey package(s) in RPM DB (sample key VERSION ids: ${_rule13_sample:-n/a})"
fi

# RULE14:
_rule14_main=$(sec_audit_dnf_main_last_value gpgcheck)
[ -z "$_rule14_main" ] && _rule14_main=$(sec_audit_tdnf_main_last_value gpgcheck)
_rule14_repo=$(sec_audit_yum_repo_list_explicit_gpgcheck0 | head -n1)
if sec_audit_dnf_val_is_false "$_rule14_main"; then
    sec_audit_report_fail 14 "merged [main] gpgcheck is disabled (effective value: ${_rule14_main})"
elif [ -n "$_rule14_repo" ]; then
    sec_audit_report_fail 14 "enabled repository section explicitly sets gpgcheck=0 (${_rule14_repo//|/ -> })"
else
    sec_audit_report_pass 14 "[main] gpgcheck is not false and no enabled .repo section forces gpgcheck=0"
fi

# RULE15:
_tdnf_gc=$(sec_audit_tdnf_main_last_value gpgcheck)
if sec_audit_dnf_val_is_true "$_tdnf_gc"; then
    _req_repo=$(sec_audit_yum_repo_list_explicit_gpgcheck0 | head -n1)
    if [ -n "$_req_repo" ]; then
        sec_audit_report_fail 15 "enabled repository section explicitly sets gpgcheck=0 (${_req_repo//|/ -> })"
    else
        sec_audit_report_pass 15 "TDNF gpgcheck is globally activated"
    fi
elif [ -z "$_tdnf_gc" ]; then
    sec_audit_report_fail 15 "gpgcheck not explicitly enabled in /etc/tdnf/tdnf.conf [main]"
else
    sec_audit_report_fail 15 "TDNF gpgcheck is not enabled (effective: ${_tdnf_gc})"
fi

# RULE16:
_rule16_repos_n=$(sec_audit_pkgmgr_repolist_enabled_count)
if [ ! -d /etc/yum.repos.d ]; then
    sec_audit_report_fail 16 "/etc/yum.repos.d is missing"
else
    _rule16_nrepo=0
    shopt -s nullglob
    for _rf in /etc/yum.repos.d/*.repo; do
        [ -f "$_rf" ] && _rule16_nrepo=$((_rule16_nrepo + 1))
    done
    shopt -u nullglob
    if [ "${_rule16_nrepo:-0}" -eq 0 ]; then
        sec_audit_report_fail 16 "no .repo files under /etc/yum.repos.d"
    elif ! sec_audit_yum_repo_any_enabled_has_uris; then
        sec_audit_report_fail 16 "no enabled repository section defines a non-empty baseurl, mirrorlist, or metalink"
    elif { sec_audit_have_bin tdnf || sec_audit_have_bin dnf; } && [ "${_rule16_repos_n:-0}" -eq 0 ]; then
        sec_audit_report_fail 16 ".repo files define URIs but package manager repolist enabled reports 0 repos (metadata, plugin, or config error)"
    else
        if { sec_audit_have_bin tdnf || sec_audit_have_bin dnf; } && [ "${_rule16_repos_n:-0}" -gt 0 ]; then
            sec_audit_report_pass 16 "${_rule16_nrepo} .repo file(s); package manager reports ${_rule16_repos_n} enabled repo(s); enabled sections include package URIs"
        else
            sec_audit_report_pass 16 "${_rule16_nrepo} .repo file(s); enabled sections include baseurl/mirrorlist/metalink (package manager not used for count)"
        fi
    fi
fi

# RULE17:
_rule17_r=$(sec_audit_sysctl_key_runtime kernel.randomize_va_space)
if sec_audit_sysctl_runtime_equals kernel.randomize_va_space 2; then
    sec_audit_report_pass 17 "kernel.randomize_va_space=2 in kernel$(sec_audit_sysctl_runtime_disk_hint kernel.randomize_va_space 2)"
else
    sec_audit_report_fail 17 "kernel.randomize_va_space is '${_rule17_r:-<unreadable>}', expected 2$(sec_audit_sysctl_runtime_disk_hint kernel.randomize_va_space 2)"
fi

# RULE18:
_rule18_cat=$(systemd-analyze cat-config systemd/coredump.conf 2>/dev/null)
_rule18_corep=$(sec_audit_sysctl_key_runtime kernel.core_pattern)
if builtin printf '%s\n' "$_rule18_cat" | grep -Pq '^\h*ProcessSizeMax=\h*0\b'; then
    if [[ "$_rule18_corep" == *systemd-coredump* ]] || [[ "$_rule18_corep" == *coredump* ]]; then
        sec_audit_report_pass 18 "merged coredump.conf sets ProcessSizeMax=0; kernel.core_pattern uses systemd-coredump"
    else
        sec_audit_report_pass 18 "merged coredump.conf sets ProcessSizeMax=0 (kernel.core_pattern='${_rule18_corep:-?}' may omit systemd-coredump text)"
    fi
else
    sec_audit_report_fail 18 "merged systemd/coredump.conf does not set ProcessSizeMax=0"
fi

# RULE19:
_rule19_cat=$(systemd-analyze cat-config systemd/coredump.conf 2>/dev/null)
if builtin printf '%s\n' "$_rule19_cat" | grep -Pq '^\h*Storage=\h*none\b'; then
    sec_audit_report_pass 19 "merged systemd/coredump.conf sets Storage=none"
else
    sec_audit_report_fail 19 "merged systemd/coredump.conf does not set Storage=none"
fi

# RULE20:
if grep -Pqsi "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/\"//g')\b)" /etc/issue 2>/dev/null; then
    sec_audit_report_fail 20 "/etc/issue is missing or does not contain required local login banner"
else
    sec_audit_report_pass 20 "/etc/issue is configured"
fi

# RULE21:
if [ -f /etc/issue.net ]; then
    if grep -Pqsi "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/\"//g')\b)" /etc/issue.net 2>/dev/null; then
        sec_audit_report_fail 21 "/etc/issue.net is missing or does not contain required remote login banner"
    else
        sec_audit_report_pass 21 "/etc/issue.net is configured"
    fi
else
    sec_audit_report_pass 21 "/etc/issue.net is configured"
fi

# RULE22:
if [ -e /etc/motd ]; then
    if stat -Lc '%a' /etc/motd 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/motd 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 22 "access to /etc/motd is configured"
        else
            sec_audit_report_fail 22 "File /etc/motd permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 22 "File /etc/motd permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 22 "access to /etc/motd is configured (file not found)"
fi

# RULE23:
if stat -Lc '%a' /etc/issue 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/issue 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 23 "access to /etc/issue is configured"
    else
        sec_audit_report_fail 23 "File /etc/issue permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 23 "File /etc/issue permissions or ownership not correct"
fi

# RULE24:
if [ -e /etc/issue.net ]; then
    if stat -Lc '%a' /etc/issue.net 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/issue.net 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 24 "access to /etc/issue.net is configured"
        else
            sec_audit_report_fail 24 "File /etc/issue.net permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 24 "File /etc/issue.net permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 24 "access to /etc/issue.net is configured (file not found)"
fi

# RULE25:
if rpm -q chrony &>/dev/null; then
    if systemctl is-active chronyd.service &>/dev/null; then
        sec_audit_report_pass 25 "chrony is installed and chronyd.service is active"
    else
        sec_audit_report_fail 25 "chrony is installed but chronyd.service is not active"
    fi
else
    sec_audit_report_fail 25 "time synchronization is not in use (chrony not installed)"
fi

# RULE26:
_ch101_src=$(grep -Eh "^(server|pool)" /etc/chrony.conf /etc/chrony.d/*.conf 2>/dev/null | grep -cve '^[[:space:]]*$' || true)
if grep -Eh "^(server|pool)" /etc/chrony.conf /etc/chrony.d/*.conf 2>/dev/null | grep -qE "server|pool"; then
    _ch101_track=""
    if sec_audit_have_bin chronyc && systemctl is-active chronyd.service &>/dev/null; then
        if chronyc -n tracking 2>/dev/null | grep -qiE '^(reference time|stratum|leap status)'; then
            _ch101_track="; chronyc tracking responds"
        fi
        if chronyc -n sources 2>/dev/null | grep -qE '^\^[*\#]'; then
            _ch101_track="${_ch101_track}; chronyc sources lists a selected source"
        fi
    fi
    sec_audit_report_pass 26 "chrony has ${_ch101_src:-0} server/pool line(s) in conf or chrony.d${_ch101_track}"
else
    sec_audit_report_fail 26 "chrony is not configured with time sources (no server/pool in chrony.conf or chrony.d)"
fi

# RULE27:

if rpm -q xinetd &>/dev/null; then
    if systemctl is-enabled xinetd.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 27 "xinetd is installed and enabled"
    elif systemctl is-active xinetd.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 27 "xinetd is installed and active"
    else
        sec_audit_report_pass 27 "xinetd is not in use"
    fi
else
    sec_audit_report_pass 27 "xinetd is not installed"
fi

# RULE28:

if rpm -q xorg-x11-server-common &>/dev/null || rpm -q xorg-x11-server-Xorg &>/dev/null; then
    sec_audit_report_fail 28 "xorg-x11-server-common is installed"
else
    sec_audit_report_pass 28 "xorg-x11-server-common is not installed"
fi

# RULE29:
sec_audit_audit_service_idle 29 avahi "avahi daemon services are not in use" "avahi daemon services are installed and enabled or actively running" "avahi-daemon.socket" "avahi-daemon.service"
# RULE30:
if rpm -q cups &>/dev/null; then
    if systemctl is-enabled cups.socket cups.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 30 "print server services are installed and enabled or actively running"
    elif systemctl is-active cups.socket cups.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 30 "print server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 30 "print server services are not in use"
    fi
else
    sec_audit_report_pass 30 "print server services are not in use"
fi

# RULE31:
if rpm -q dhcp-server &>/dev/null; then
    if systemctl is-enabled dhcpd.service dhcpd6.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 31 "dhcp server services are installed and enabled or actively running"
    elif systemctl is-active dhcpd.service dhcpd6.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 31 "dhcp server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 31 "dhcp server services are not in use"
    fi
else
    sec_audit_report_pass 31 "dhcp server services are not in use"
fi

# RULE32:
if rpm -q bind &>/dev/null; then
    if systemctl is-enabled named.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 32 "dns server services are installed and enabled or actively running"
    elif systemctl is-active named.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 32 "dns server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 32 "dns server services are not in use"
    fi
else
    sec_audit_report_pass 32 "dns server services are not in use"
fi

# RULE33:
if rpm -q ftp &>/dev/null; then
    sec_audit_report_fail 33 "ftp client package is installed"
else
    sec_audit_report_pass 33 "ftp client is not installed"
fi

# RULE34:
if rpm -q vsftpd &>/dev/null; then
    if systemctl is-enabled vsftpd.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 34 "ftp server services are installed and enabled or actively running"
    elif systemctl is-active vsftpd.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 34 "ftp server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 34 "ftp server services are not in use"
    fi
else
    sec_audit_report_pass 34 "ftp server services are not in use"
fi

# RULE35:
if rpm -q tftp-server &>/dev/null; then
    if systemctl is-enabled tftp.socket tftp.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 35 "tftp server services are installed and enabled or actively running"
    elif systemctl is-active tftp.socket tftp.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 35 "tftp server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 35 "tftp server services are not in use"
    fi
else
    sec_audit_report_pass 35 "tftp server services are not in use"
fi

# RULE36:
if sec_audit_pkg_any_installed httpd nginx; then
    if systemctl is-enabled httpd.service nginx.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 36 "web server services are installed and enabled or actively running"
    elif systemctl is-active httpd.service nginx.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 36 "web server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 36 "web server services are not in use"
    fi
else
    sec_audit_report_pass 36 "web server services are not in use"
fi

# RULE37:
if sec_audit_pkg_any_installed dovecot cyrus-imapd; then
    if systemctl is-enabled dovecot.socket dovecot.service cyrus-imapd.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 37 "message access server services are installed and enabled or actively running"
    elif systemctl is-active dovecot.socket dovecot.service cyrus-imapd.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 37 "message access server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 37 "message access server services are not in use"
    fi
else
    sec_audit_report_pass 37 "message access server services are not in use"
fi

# RULE38:
sec_audit_audit_service_idle 38 samba "samba file server services are not in use" "samba file server services are installed and enabled or actively running" "smb.service"
# RULE39:
if rpm -q squid &>/dev/null; then
    if systemctl is-enabled squid.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 39 "web proxy server services are installed and enabled or actively running"
    elif systemctl is-active squid.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 39 "web proxy server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 39 "web proxy server services are not in use"
    fi
else
    sec_audit_report_pass 39 "web proxy server services are not in use"
fi

# RULE40:
sec_audit_audit_service_idle 40 net-snmp "snmp services are not in use" "snmp services are installed and enabled or actively running" "snmpd.service"
# RULE41:
if rpm -q ypserv &>/dev/null; then
    sec_audit_report_fail 41 "NIS server (ypserv) is installed"
else
    sec_audit_report_pass 41 "NIS server is not installed"
fi

# RULE42:
sec_audit_audit_service_idle 42 telnet-server "telnet server services are not in use" "telnet server services are installed and enabled or actively running" "telnet.socket"
# RULE43:
if command -v postconf >/dev/null 2>&1; then
    if postconf -n inet_interfaces 2>/dev/null | grep -qE 'localhost|loopback-only'; then
        sec_audit_report_pass 43 "mail transfer agent is configured for local-only mode"
    else
        sec_audit_report_fail 43 "mail transfer agent is not configured for local-only mode"
    fi
elif ss -plntu 2>/dev/null | grep -P ':(25|465|587)\b' | grep -Pvq '\h+(127\.0\.0\.1|\[?::1\]?):(25|465|587)\b'; then
    sec_audit_report_fail 43 "mail transfer agent listens on non-loopback interface"
else
    sec_audit_report_pass 43 "mail transfer agent is configured for local-only mode"
fi

# RULE44:
sec_audit_audit_service_idle 44 nfs-utils "network file system services are not in use" "network file system services are installed and enabled or actively running" "nfs-server.service"
# RULE45:
sec_audit_audit_service_idle 45 rsync-daemon "rsync services are not in use" "rsync services are installed and enabled or actively running" "rsyncd.socket" "rsyncd.service"
# RULE46:
if rpm -q ypbind &>/dev/null; then
    sec_audit_report_fail 46 "NIS Client (ypbind) is installed"
else
    sec_audit_report_pass 46 "NIS Client is not installed"
fi

# RULE47:
if rpm -q rsh &>/dev/null || rpm -q rsh-client &>/dev/null; then
    sec_audit_report_fail 47 "rsh client is installed"
else
    sec_audit_report_pass 47 "rsh client is not installed"
fi

# RULE48:
if rpm -q talk &>/dev/null; then
    sec_audit_report_fail 48 "talk client is installed"
else
    sec_audit_report_pass 48 "talk client is not installed"
fi

# RULE49:
if rpm -q telnet &>/dev/null; then
    sec_audit_report_fail 49 "telnet client package is installed"
else
    sec_audit_report_pass 49 "telnet client is not installed"
fi

# RULE50:
if rpm -q openldap-clients &>/dev/null; then
    sec_audit_report_fail 50 "ldap client package is installed"
else
    sec_audit_report_pass 50 "ldap client is not installed"
fi

# RULE51:
if rpm -q tftp &>/dev/null; then
    sec_audit_report_fail 51 "tftp client package is installed"
else
    sec_audit_report_pass 51 "tftp client is not installed"
fi

# RULE52:
_fail=0
if ! sec_audit_sysctl_runtime_equals net.ipv4.conf.all.send_redirects 0; then
    _fail=1
fi
if ! sec_audit_sysctl_runtime_equals net.ipv4.conf.default.send_redirects 0; then
    _fail=1
fi
if [ $_fail -eq 0 ]; then
    sec_audit_report_pass 52 "packet redirect sending is disabled"
else
    sec_audit_report_fail 52 "packet redirect sending is disabled"
fi

# RULE53:
sec_audit_audit_sysctl 53 net.ipv4.icmp_ignore_bogus_error_responses 1

# RULE54:
sec_audit_audit_sysctl 54 net.ipv4.icmp_echo_ignore_broadcasts 1

# RULE55:
_fail=0
sec_audit_sysctl_runtime_equals net.ipv4.conf.all.accept_redirects 0 || _fail=1
sec_audit_sysctl_runtime_equals net.ipv4.conf.default.accept_redirects 0 || _fail=1
if [ $_fail -eq 0 ]; then
    sec_audit_report_pass 55 "icmp redirects are not accepted"
else
    sec_audit_report_fail 55 "icmp redirects are not accepted"
fi

# RULE56:
_fail=0
sec_audit_sysctl_runtime_equals net.ipv4.conf.all.secure_redirects 0 || _fail=1
sec_audit_sysctl_runtime_equals net.ipv4.conf.default.secure_redirects 0 || _fail=1
if [ $_fail -eq 0 ]; then
    sec_audit_report_pass 56 "secure icmp redirects are not accepted"
else
    sec_audit_report_fail 56 "secure icmp redirects are not accepted"
fi

# RULE57:
_fail=0
sec_audit_sysctl_runtime_equals net.ipv4.conf.all.rp_filter 1 || _fail=1
sec_audit_sysctl_runtime_equals net.ipv4.conf.default.rp_filter 1 || _fail=1
if [ $_fail -eq 0 ]; then
    sec_audit_report_pass 57 "reverse path filtering is enabled"
else
    sec_audit_report_fail 57 "reverse path filtering is not enabled"
fi

# RULE58:
_fail=0
sec_audit_sysctl_runtime_equals net.ipv4.conf.all.accept_source_route 0 || _fail=1
sec_audit_sysctl_runtime_equals net.ipv4.conf.default.accept_source_route 0 || _fail=1
if [ $_fail -eq 0 ]; then
    sec_audit_report_pass 58 "source routed packets are not accepted"
else
    sec_audit_report_fail 58 "source routed packets are not accepted"
fi

# RULE59:
_fail=0
sec_audit_sysctl_runtime_equals net.ipv4.conf.all.log_martians 1 || _fail=1
sec_audit_sysctl_runtime_equals net.ipv4.conf.default.log_martians 1 || _fail=1
if [ $_fail -eq 0 ]; then
    sec_audit_report_pass 59 "suspicious packets are logged (log_martians enabled)"
else
    sec_audit_report_fail 59 "suspicious packets are logged (log_martians not set to 1 on all/default)"
fi

# RULE60:
sec_audit_audit_sysctl 60 net.ipv4.tcp_syncookies 1

# RULE61:
_fail=0
sec_audit_sysctl_runtime_equals net.ipv6.conf.all.accept_ra 0 || _fail=1
sec_audit_sysctl_runtime_equals net.ipv6.conf.default.accept_ra 0 || _fail=1
if [ $_fail -eq 0 ]; then
    sec_audit_report_pass 61 "ipv6 router advertisements are not accepted"
else
    sec_audit_report_fail 61 "ipv6 router advertisements are not accepted"
fi

# RULE62:
if rpm -q iptables iptables-nft &>/dev/null || rpm -q iptables &>/dev/null; then
    sec_audit_report_pass 62 "iptables is installed"
else
    sec_audit_report_fail 62 "iptables package is not installed"
fi

# RULE63:
if rpm -q nftables &>/dev/null; then
    if systemctl is-enabled nftables.service 2>/dev/null | grep -q '^enabled'; then
        sec_audit_report_fail 63 "nftables package is installed and nftables.service is enabled"
    elif systemctl is-active nftables.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 63 "nftables package is installed and nftables.service is active"
    else
        sec_audit_report_pass 63 "nftables package is installed but nftables.service is not enabled or active"
    fi
elif sec_audit_have_bin nft && nft list ruleset 2>/dev/null | grep -q .; then
    sec_audit_report_fail 63 "nftables ruleset is in use"
else
    sec_audit_report_pass 63 "nftables is not in use"
fi

# RULE64:

if rpm -q firewalld &>/dev/null && systemctl is-active firewalld.service 2>/dev/null | grep -q '^active'; then
    sec_audit_report_fail 64 "firewalld is installed and active"
else
    sec_audit_report_pass 64 "firewalld is not in use"
fi

# RULE65:
if systemctl is-enabled crond.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active crond.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 65 "cron daemon is enabled and active"
    else
        sec_audit_report_fail 65 "crond service is not enabled or not active"
    fi
else
    sec_audit_report_fail 65 "crond service is not enabled or not active"
fi

# RULE66:
if stat -Lc '%a' /etc/crontab 2>/dev/null | grep -q '^[0-6]00$'; then
    if stat -Lc '%U:%G' /etc/crontab 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 66 "access to /etc/crontab is configured"
    else
        sec_audit_report_fail 66 "File /etc/crontab permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 66 "File /etc/crontab permissions or ownership not correct"
fi

# RULE67:
if stat -Lc '%a' /etc/cron.hourly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.hourly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 67 "access to /etc/cron.hourly is configured"
    else
        sec_audit_report_fail 67 "File /etc/cron.hourly permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 67 "File /etc/cron.hourly permissions or ownership not correct"
fi

# RULE68:
if stat -Lc '%a' /etc/cron.daily 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.daily 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 68 "access to /etc/cron.daily is configured"
    else
        sec_audit_report_fail 68 "File /etc/cron.daily permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 68 "File /etc/cron.daily permissions or ownership not correct"
fi

# RULE69:
if stat -Lc '%a' /etc/cron.weekly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.weekly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 69 "access to /etc/cron.weekly is configured"
    else
        sec_audit_report_fail 69 "File /etc/cron.weekly permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 69 "File /etc/cron.weekly permissions or ownership not correct"
fi

# RULE70:
if stat -Lc '%a' /etc/cron.monthly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.monthly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 70 "access to /etc/cron.monthly is configured"
    else
        sec_audit_report_fail 70 "File /etc/cron.monthly permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 70 "File /etc/cron.monthly permissions or ownership not correct"
fi

# RULE71:
if stat -Lc '%a' /etc/cron.d 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.d 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 71 "access to /etc/cron.d is configured"
    else
        sec_audit_report_fail 71 "File /etc/cron.d permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 71 "File /etc/cron.d permissions or ownership not correct"
fi

# RULE72:
if [ -f /etc/cron.deny ]; then
    sec_audit_report_fail 72 "/etc/cron.deny exists (cron must be restricted via cron.allow only)"
elif [ -f /etc/cron.allow ] && stat -Lc '%a %U %G' /etc/cron.allow 2>/dev/null | grep -qE '^[0-6][04][04] root (root|crontab)$'; then
    sec_audit_report_pass 72 "cron is restricted (/etc/cron.allow present, cron.deny absent, permissions OK)"
else
    sec_audit_report_fail 72 "cron.allow missing, wrong permissions, or ownership (expected root:root/crontab mode <=640)"
fi

# RULE73:
if [ -f /etc/at.deny ]; then
    sec_audit_report_fail 73 "/etc/at.deny exists (at must be restricted via at.allow only)"
elif [ -f /etc/at.allow ] && stat -Lc '%a %U %G' /etc/at.allow 2>/dev/null | grep -qE '^[0-6][04][04] root (root|daemon)$'; then
    sec_audit_report_pass 73 "at is restricted (/etc/at.allow present, at.deny absent, permissions OK)"
else
    sec_audit_report_fail 73 "at.allow missing, wrong permissions, or ownership (expected root:root/daemon mode <=640)"
fi

# RULE74:
if stat -Lc '%a' /etc/ssh/sshd_config 2>/dev/null | grep -q '^600$'; then
    if stat -Lc '%U:%G' /etc/ssh/sshd_config 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 74 "access to /etc/ssh/sshd_config is configured"
    else
        sec_audit_report_fail 74 "File /etc/ssh/sshd_config permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 74 "File /etc/ssh/sshd_config permissions or ownership not correct"
fi

if ! sec_audit_sshd_effective_usable; then
    for _sshn in 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93; do
        sec_audit_report_fail "$_sshn" "unable_to_evaluate: sshd -T produced no effective configuration"
    done
else
# RULE75:
PRIV_KEYS=$(sec_audit_sshd_effective_dump | awk '$1=="hostkey" {print $2}')
FAIL75=0
for key in $PRIV_KEYS; do
    if [ -f "$key" ]; then
        if ! stat -Lc '%a' "$key" 2>/dev/null | grep -q '^600$'; then
            FAIL75=1
        fi
        if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
            FAIL75=1
        fi
    else
        FAIL75=1
    fi
done
if [ $FAIL75 -eq 0 ]; then
    sec_audit_report_pass 75 "access to SSH private host key files is configured"
else
    sec_audit_report_fail 75 "File SSH private host key files permissions or ownership not correct"
fi

# RULE76:
PUB_KEYS=$(sec_audit_sshd_effective_dump | awk '$1=="hostkey" {print $2".pub"}')
FAIL76=0
for key in $PUB_KEYS; do
    if [ -f "$key" ]; then
        if ! stat -Lc '%a' "$key" 2>/dev/null | grep -qE '^[0-6]44$'; then
            FAIL76=1
        fi
        if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
            FAIL76=1
        fi
    else
        FAIL76=1
    fi
done
if [ $FAIL76 -eq 0 ]; then
    sec_audit_report_pass 76 "access to SSH public host key files is configured"
else
    sec_audit_report_fail 76 "File SSH public host key files permissions or ownership not correct"
fi

# RULE77:
if sec_audit_sshd_t_grep -Piq '^ciphers\h+\"?([^#\n\r]+,)?((3des|blowfish|cast128|aes(128|192|256))-cbc|arcfour(128|256)?|rijndael-cbc@lysator\.liu\.se)\b'; then
    sec_audit_report_fail 77 "sshd Ciphers allow weak or legacy algorithms (see sshd -T)"
else
    sec_audit_report_pass 77 "sshd Ciphers are configured"
fi

# RULE78:
if sec_audit_sshd_t_grep -Piq 'kexalgorithms\h+([^#\n\r]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b'; then
    sec_audit_report_fail 78 "sshd KexAlgorithms does not meet the required policy (see sshd -T)"
else
    sec_audit_report_pass 78 "sshd KexAlgorithms is configured"
fi

# RULE79:
if sec_audit_sshd_t_grep -Piq 'macs\h+([^#\n\r]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b'; then
    sec_audit_report_fail 79 "sshd MACs allow weak or legacy algorithms (see sshd -T)"
else
    sec_audit_report_pass 79 "sshd MACs are configured"
fi

# RULE80:
if sec_audit_sshd_t_grep -Piq '^\h*(allow|deny)(users|groups)\h+\H+'; then
    sec_audit_report_pass 80 "sshd access is configured"
else
    sec_audit_report_fail 80 "sshd access controls (AllowUsers/DenyUsers/AllowGroups/DenyGroups) are not set as required"
fi

# RULE81:
if sec_audit_sshd_t_grep -Piq '^banner\h+\/\H+'; then
    sec_audit_report_pass 81 "sshd Banner is configured"
else
    sec_audit_report_fail 81 "sshd Banner does not meet the required policy (see sshd -T)"
fi

# RULE82:
if sec_audit_sshd_t_grep -Piq 'clientaliveinterval\s+([1-9]|[1-9][0-9]+)'; then
    if sec_audit_sshd_t_grep -Piq 'clientalivecountmax\s+([1-9]|[1-9][0-9]+)'; then
        sec_audit_report_pass 82 "sshd ClientAliveInterval and ClientAliveCountMax are configured"
    else
        sec_audit_report_fail 82 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
    fi
else
    sec_audit_report_fail 82 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
fi

# RULE83:
if sec_audit_sshd_t_grep -iq 'hostbasedauthentication no'; then
    sec_audit_report_pass 83 "sshd HostbasedAuthentication is disabled"
else
    sec_audit_report_fail 83 "sshd HostbasedAuthentication is not disabled in effective sshd -T output"
fi

# RULE84:
if sec_audit_sshd_t_grep -iq 'ignorerhosts yes'; then
    sec_audit_report_pass 84 "sshd IgnoreRhosts is enabled"
else
    sec_audit_report_fail 84 "sshd IgnoreRhosts is not enabled in effective sshd -T output"
fi

# RULE85:
if sec_audit_sshd_t_grep -Piq 'logingracetime\s+([1-9]|[1-5][0-9]|60)\b'; then
    sec_audit_report_pass 85 "sshd LoginGraceTime is configured"
else
    sec_audit_report_fail 85 "sshd LoginGraceTime does not meet the required policy (see sshd -T)"
fi

# RULE86:
if sec_audit_sshd_t_grep -Eiq '^loglevel[[:space:]]+(verbose|info)\b'; then
    sec_audit_report_pass 86 "sshd LogLevel is configured (VERBOSE or INFO)"
else
    sec_audit_report_fail 86 "sshd LogLevel is not VERBOSE or INFO in effective sshd -T output"
fi

# RULE87:
if sec_audit_sshd_t_grep -Piq 'maxauthtries\s+[1-4]\b'; then
    sec_audit_report_pass 87 "sshd MaxAuthTries is configured"
else
    sec_audit_report_fail 87 "sshd MaxAuthTries does not meet the required policy (see sshd -T)"
fi

# RULE88:
if sec_audit_sshd_t_awk '$1 ~ /^\s*maxstartups/{split($2, a, ":");{if(a[1] <= 10 && a[2] <= 30 && a[3] <= 60) print "ok"}}' | grep -q "ok"; then
    sec_audit_report_pass 88 "sshd MaxStartups is configured"
else
    sec_audit_report_fail 88 "sshd MaxStartups does not meet the required policy (see sshd -T)"
fi

# RULE89:
if sec_audit_sshd_t_grep -Piq 'maxsessions\s+([1-9]|10)\b'; then
    sec_audit_report_pass 89 "sshd MaxSessions is configured"
else
    sec_audit_report_fail 89 "sshd MaxSessions does not meet the required policy (see sshd -T)"
fi

# RULE90:
if sec_audit_sshd_t_grep -iq 'permitemptypasswords no'; then
    sec_audit_report_pass 90 "sshd PermitEmptyPasswords is disabled"
else
    sec_audit_report_fail 90 "sshd PermitEmptyPasswords is not disabled in effective sshd -T output"
fi

# RULE91:
if sec_audit_sshd_t_grep -iq 'permitrootlogin no'; then
    sec_audit_report_pass 91 "sshd PermitRootLogin is disabled"
else
    sec_audit_report_fail 91 "sshd PermitRootLogin is not disabled in effective sshd -T output"
fi

# RULE92:
if sec_audit_sshd_t_grep -iq 'permituserenvironment no'; then
    sec_audit_report_pass 92 "sshd PermitUserEnvironment is disabled"
else
    sec_audit_report_fail 92 "sshd PermitUserEnvironment is not disabled in effective sshd -T output"
fi

# RULE93:
if sec_audit_sshd_t_grep -iq 'usepam yes'; then
    sec_audit_report_pass 93 "sshd UsePAM is enabled"
else
    sec_audit_report_fail 93 "sshd UsePAM is not enabled in effective sshd -T output"
fi

fi

# RULE94:
if rpm -q sudo &>/dev/null; then
    sec_audit_report_pass 94 "sudo is installed"
else
    sec_audit_report_fail 94 "sudo package is not installed"
fi

# RULE95:
if grep -rPqi '^\h*Defaults\h+([^#\n\r]+\h+)?!authenticate\b' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    sec_audit_report_fail 95 "re-authentication for privilege escalation is disabled globally (!authenticate)"
else
    sec_audit_report_pass 95 "re-authentication for privilege escalation is not disabled globally"
fi

# RULE96:
TIMEOUT=$(sudo -V 2>/dev/null | grep "Authentication timestamp timeout:" | awk '{print $4}')
TIMEOUT_INT=${TIMEOUT%%.*}
if [ -n "$TIMEOUT_INT" ]; then
    if [ "$TIMEOUT_INT" -ge 0 ] && [ "$TIMEOUT_INT" -le 15 ]; then
        sec_audit_report_pass 96 "sudo timestamp_timeout is configured"
    else
        sec_audit_report_fail 96 "sudo timestamp_timeout is not set within the required range"
    fi
else
    sec_audit_report_pass 96 "sudo timestamp_timeout is configured"
fi

# RULE97:
FAIL97=0
if ! grep -Psi '^\h*minlen\h*=\h*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    FAIL97=1
fi
if ! grep -Psi '^\h*minclass\h*=\h*([4-9]|[1-9][0-9]+)\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    _rule97_credits=0
    grep -Psi '^\h*dcredit\h*=\h*-1\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null && _rule97_credits=$((_rule97_credits + 1))
    grep -Psi '^\h*ucredit\h*=\h*-1\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null && _rule97_credits=$((_rule97_credits + 1))
    grep -Psi '^\h*lcredit\h*=\h*-1\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null && _rule97_credits=$((_rule97_credits + 1))
    grep -Psi '^\h*ocredit\h*=\h*-1\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null && _rule97_credits=$((_rule97_credits + 1))
    [ "${_rule97_credits:-0}" -lt 4 ] && FAIL97=1
fi
for _rule97_pam in /etc/pam.d/system-auth /etc/pam.d/system-password; do
    [ -f "$_rule97_pam" ] || continue
    if ! grep -Psi '^\h*password\h+[^#\n\r]+\h+pam_pwquality\.so\b' "$_rule97_pam" 2>/dev/null | grep -Psi 'retry\h*=\h*3\b' | grep -q .; then
        FAIL97=1
    fi
done
if [ $FAIL97 -eq 0 ]; then
    sec_audit_report_pass 97 "password creation requirements are configured"
else
    sec_audit_report_fail 97 "password creation requirements are not configured (minlen, complexity, or pam_pwquality retry=3)"
fi

# RULE98:
if grep -Pqsi 'deny\h*=\h*[1-5]\b' /etc/security/faillock.conf 2>/dev/null; then
    sec_audit_report_pass 98 "password failed attempts lockout is configured"
else
    sec_audit_report_fail 98 "faillock deny threshold is not configured in /etc/security/faillock.conf"
fi

# RULE99:
if grep -Pqsi '^\h*ENCRYPT_METHOD\h+(SHA512|YESCRYPT)\b' /etc/login.defs 2>/dev/null; then
    sec_audit_report_pass 99 "strong password hashing algorithm is configured"
else
    sec_audit_report_fail 99 "ENCRYPT_METHOD in /etc/login.defs does not use a strong hashing algorithm"
fi

# RULE100:
if grep -Pqsi 'remember\h*=\h*(2[4-9]|[3-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwhistory.conf 2>/dev/null; then
    sec_audit_report_pass 100 "password history remember is configured"
elif grep -P '^\h*password\h+([^#\n\r]+)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=[0-9]+\b' /etc/pam.d/common-password 2>/dev/null | grep -q remember; then
    REMEMBER=$(grep -P '^\h*password\h+([^#\n\r]+)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=\K[0-9]+' /etc/pam.d/common-password 2>/dev/null)
    if [ "$REMEMBER" -ge 24 ]; then
        sec_audit_report_pass 100 "password history remember is configured"
    else
        sec_audit_report_fail 100 "pwhistory remember value is below policy or not configured"
    fi
else
    sec_audit_report_fail 100 "pwhistory remember value is below policy or not configured"
fi

# RULE101:
if grep -Pqsi '^\h*PASS_MAX_DAYS\h+(36[0-5]|3[0-5][0-9]|[1-2][0-9][0-9]|[1-9][0-9]|[1-9])\b' /etc/login.defs 2>/dev/null; then
    if ! awk -F: '($2~/^\$.+\$/) {if($5 > 365 || $5 < 1)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 101 "password expiration is configured"
    else
        sec_audit_report_fail 101 "PASS_MAX_DAYS or per-user shadow MAX exceeds policy or is unset"
    fi
else
    sec_audit_report_fail 101 "PASS_MAX_DAYS or per-user shadow MAX exceeds policy or is unset"
fi

# RULE102:
if grep -Pqsi '^\h*PASS_MIN_DAYS\h+([1-9]|[1-9][0-9]+)\b' /etc/login.defs 2>/dev/null; then
    sec_audit_report_pass 102 "minimum days between password changes is configured"
else
    sec_audit_report_fail 102 "PASS_MIN_DAYS is not set to at least 1 in /etc/login.defs"
fi

# RULE103:
if grep -Pqsi '^\h*PASS_WARN_AGE\h+([7-9]|[1-9][0-9]+)\b' /etc/login.defs 2>/dev/null; then
    if ! awk -F: '($2~/^\$.+\$/) {if($6 < 7)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 103 "password expiration warning days is configured"
    else
        sec_audit_report_fail 103 "PASS_WARN_AGE is not set within policy in /etc/login.defs"
    fi
else
    sec_audit_report_fail 103 "PASS_WARN_AGE is not set within policy in /etc/login.defs"
fi

# RULE104:
_rule104_def=$(useradd -D 2>/dev/null | awk -F= '$1=="INACTIVE" {print $2; exit}')
if [ -n "$_rule104_def" ] && [ "$_rule104_def" -le 30 ] 2>/dev/null && [ "$_rule104_def" -ge 0 ] 2>/dev/null; then
    if ! awk -F: '($2~/^\$.+\$/) && $7!="" && $7+0>30 {print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 104 "inactive password lock is 30 days or less"
    else
        sec_audit_report_fail 104 "user INACTIVE value exceeds 30 days in /etc/shadow"
    fi
else
    sec_audit_report_fail 104 "useradd default INACTIVE is not set to 30 days or less"
fi

# RULE105:
FAIL105=0
while IFS=: read -r user pass last_change rest; do
    if [ -n "$last_change" ] && [ "$last_change" -gt 0 ] 2>/dev/null; then
        current_date=$(date +%s)
        last_change_seconds=$((last_change * 86400))
        if [ "$last_change_seconds" -gt "$current_date" ]; then
            sec_audit_report_fail 105 "User $user has password change date in the future"
            FAIL105=1
        fi
    fi
done < /etc/shadow 2>/dev/null
if [ $FAIL105 -eq 0 ]; then
    sec_audit_report_pass 105 "All users last password change date is in the past"
fi

# RULE106:
VALID_SHELLS=$(awk -F\/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells 2>/dev/null | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -)
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
if awk -v pat="^($VALID_SHELLS)$" -v uidmin="$UID_MIN" -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<uidmin || $3==65534) && $NF ~ pat) {print}' /etc/passwd 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 106 "System accounts still have an interactive login shell"
else
    sec_audit_report_pass 106 "system accounts do not have a valid login shell"
fi

# RULE107:
if awk -F: '$3=="0"{print $1":"$3}' /etc/group 2>/dev/null | grep -q "root:0"; then
    if [ $(awk -F: '$3=="0"{print}' /etc/group 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 107 "group root is the only GID 0 group"
    else
        sec_audit_report_fail 107 "Multiple groups share GID 0"
    fi
else
    sec_audit_report_fail 107 "Multiple groups share GID 0"
fi

# RULE108:
if grep -Pqsi '^\h*umask\h+0?(?:[0-7][2-7]7)\b' /etc/login.defs 2>/dev/null; then
    if grep -Pqsi '^\h*umask\h+0?027\b' /etc/profile.d/*.sh 2>/dev/null; then
        sec_audit_report_pass 108 "default user umask is configured"
    else
        sec_audit_report_fail 108 "Default user umask 027 is not set in /etc/profile or profile.d"
    fi
else
    sec_audit_report_fail 108 "Default user umask 027 is not set in /etc/profile or profile.d"
fi

# RULE109:
if rpm -q rsyslog &>/dev/null; then
    sec_audit_report_pass 109 "rsyslog is installed"
else
    sec_audit_report_fail 109 "rsyslog package is not installed"
fi

# RULE110:
if systemctl is-enabled rsyslog 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active rsyslog.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 110 "rsyslog service is enabled and active"
    else
        sec_audit_report_fail 110 "rsyslog is not enabled or not active"
    fi
else
    sec_audit_report_fail 110 "rsyslog is not enabled or not active"
fi

# RULE111:
if grep -Pqs '^\h*\$FileCreateMode\h+0[0,2,4,6][0,2,4]0\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 111 "rsyslog log file creation mode is configured"
else
    sec_audit_report_fail 111 "rsyslog $FileCreateMode (or equivalent) does not meet policy"
fi

# RULE112:

if grep -Pqsi '^\h*module\(load=\"?imtcp\"?\)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
    sec_audit_report_fail 112 "rsyslog is configured to receive logs from a remote client (imtcp module)"
elif grep -Pqsi '^\h*input\(type=\"?imtcp\"?\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
    sec_audit_report_fail 112 "rsyslog is configured to receive logs from a remote client (imtcp input)"
elif grep -Pqsi '^\h*input\(type=\"?imudp\"?\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
    sec_audit_report_fail 112 "rsyslog is configured to receive logs from a remote client (imudp input)"
else
    sec_audit_report_pass 112 "rsyslog is not configured to receive logs from a remote client"
fi

# RULE113:
FAIL113=0
_BAD113=""
if [ -d /var/log ]; then
    _LOG113_LIST=$(sec_audit_low_impact_find --timeout=30 /var/log -xdev -ignore_readdir_race -type f \
        \( -name '*.log' -o -name 'messages' -o -name 'secure' -o -name 'maillog' -o -name 'cron' -o -name 'boot.log' \) \
        -print 2>/dev/null)
    while IFS= read -r logfile; do
        [ -n "$logfile" ] || continue
        PERM=$(stat -c '%a' "$logfile" 2>/dev/null)
        OWNER=$(stat -c '%U' "$logfile" 2>/dev/null)
        if [ -z "$PERM" ] || [ -z "$OWNER" ]; then
            FAIL113=1
            _BAD113="${_BAD113}${_BAD113:+, }${logfile}:unreadable"
            continue
        fi
        if [ "$PERM" -gt 640 ] 2>/dev/null || [ "$OWNER" != "root" ]; then
            FAIL113=1
            _BAD113="${_BAD113}${_BAD113:+, }${logfile}:${PERM}/${OWNER}"
        fi
    done <<< "$_LOG113_LIST"
fi
if [ $FAIL113 -eq 0 ]; then
    sec_audit_report_pass 113 "access to log files under /var/log is configured (mode<=640, owner root)"
else
    sec_audit_report_fail 113 "insecure log file(s): ${_BAD113:-unknown}"
fi

# RULE114:
if command -v logrotate &>/dev/null; then
    if [ -f /etc/logrotate.conf ] && grep -q "^rotate\|^daily\|^weekly\|^monthly" /etc/logrotate.conf 2>/dev/null; then
        sec_audit_report_pass 114 "rsyslog logrotate is configured"
    else
        sec_audit_report_fail 114 "rsyslog logrotate is not properly configured"
    fi
else
    sec_audit_report_fail 114 "logrotate is not installed"
fi

# RULE115:
if stat -Lc '%a' /etc/passwd 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/passwd 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 115 "access to /etc/passwd is configured"
    else
        sec_audit_report_fail 115 "File /etc/passwd permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 115 "File /etc/passwd permissions or ownership not correct"
fi

# RULE116:
if [ -e /etc/passwd- ]; then
    if stat -Lc '%a' /etc/passwd- 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/passwd- 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 116 "access to /etc/passwd- is configured"
        else
            sec_audit_report_fail 116 "File /etc/passwd- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 116 "File /etc/passwd- permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 116 "/etc/passwd- is absent (optional file; permission check skipped)"
fi

# RULE117:
if stat -Lc '%a' /etc/group 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/group 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 117 "access to /etc/group is configured"
    else
        sec_audit_report_fail 117 "File /etc/group permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 117 "File /etc/group permissions or ownership not correct"
fi

# RULE118:
if [ -e /etc/group- ]; then
    if stat -Lc '%a' /etc/group- 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/group- 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 118 "access to /etc/group- is configured"
        else
            sec_audit_report_fail 118 "File /etc/group- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 118 "File /etc/group- permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 118 "/etc/group- is absent (optional file; permission check skipped)"
fi

# RULE119:
if stat -Lc '%a' /etc/shadow 2>/dev/null | grep -qE '^[0-6]40$'; then
    if stat -Lc '%U' /etc/shadow 2>/dev/null | grep -q 'root'; then
        if stat -Lc '%G' /etc/shadow 2>/dev/null | grep -qE 'root|shadow'; then
            sec_audit_report_pass 119 "access to /etc/shadow is configured"
        else
            sec_audit_report_fail 119 "File /etc/shadow permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 119 "File /etc/shadow permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 119 "File /etc/shadow permissions or ownership not correct"
fi

# RULE120:
if [ -e /etc/shadow- ]; then
    if stat -Lc '%a' /etc/shadow- 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/shadow- 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/shadow- 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 120 "access to /etc/shadow- is configured"
            else
                sec_audit_report_fail 120 "File /etc/shadow- permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 120 "File /etc/shadow- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 120 "File /etc/shadow- permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 120 "/etc/shadow- is absent (optional file; permission check skipped)"
fi

# RULE121:
if [ -e /etc/gshadow ]; then
    if stat -Lc '%a' /etc/gshadow 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/gshadow 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/gshadow 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 121 "access to /etc/gshadow is configured"
            else
                sec_audit_report_fail 121 "File /etc/gshadow permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 121 "File /etc/gshadow permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 121 "File /etc/gshadow permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 121 "/etc/gshadow is absent (optional file; permission check skipped)"
fi

# RULE122:
if [ -e /etc/gshadow- ]; then
    if stat -Lc '%a' /etc/gshadow- 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/gshadow- 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/gshadow- 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 122 "access to /etc/gshadow- is configured"
            else
                sec_audit_report_fail 122 "File /etc/gshadow- permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 122 "File /etc/gshadow- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 122 "File /etc/gshadow- permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 122 "/etc/gshadow- is absent (optional file; permission check skipped)"
fi

# RULE123:
if stat -Lc '%a' /etc/shells 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/shells 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 123 "access to /etc/shells is configured"
    else
        sec_audit_report_fail 123 "File /etc/shells permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 123 "File /etc/shells permissions or ownership not correct"
fi

# RULE124:
if [ -e /etc/security/opasswd ]; then
    if stat -Lc '%a' /etc/security/opasswd 2>/dev/null | grep -q '^600$'; then
        if stat -Lc '%U:%G' /etc/security/opasswd 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 124 "access to /etc/security/opasswd is configured"
        else
            sec_audit_report_fail 124 "File /etc/security/opasswd permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 124 "File /etc/security/opasswd permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 124 "/etc/security/opasswd is absent (optional file; permission check skipped)"
fi

# RULE125:
CRITICAL_PATHS="/bin /sbin /usr/bin /usr/sbin /etc /var /home"
if sec_audit_low_impact_find_timed_out sec_audit_low_impact_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print; then
    sec_audit_report_fail 125 "incomplete_scan: world-writable file search timed out under critical paths"
elif sec_audit_low_impact_find_timed_out sec_audit_low_impact_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print; then
    sec_audit_report_fail 125 "incomplete_scan: world-writable directory search timed out under critical paths"
else
    WW_FILES=$(sec_audit_low_impact_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print 2>/dev/null | wc -l)
    WW_DIRS=$(sec_audit_low_impact_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print 2>/dev/null | wc -l)
    if [ "${WW_FILES:-0}" -eq 0 ] && [ "${WW_DIRS:-0}" -eq 0 ]; then
        sec_audit_report_pass 125 "No critical world writable files or directories found"
    else
        sec_audit_report_fail 125 "Found potential world-writable items ($WW_FILES files, $WW_DIRS dirs)"
    fi
fi
# RULE126:

if sec_audit_low_impact_find --timeout=120 / -xdev \( -path '/proc/*' -o -path '/sys/*' -o -path '/dev/*' -o -path '/run/*' -o -path '/var/lib/containers/*' -o -path '/var/lib/kubelet/*' \) -prune -o \( -type f -o -type d \) \( -nouser -o -nogroup \) -print 2>/dev/null | grep -q .; then
    sec_audit_report_fail 126 "files or directories without an owner or group exist"
else
    sec_audit_report_pass 126 "no files or directories without an owner and a group exist"
fi

# RULE127:
if awk -F: '($2 != "x" ) { print }' /etc/passwd 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 127 "Non-shadow password field found in /etc/passwd (second field not "x")"
else
    sec_audit_report_pass 127 "accounts in /etc/passwd use shadowed passwords"
fi

# RULE128:
if awk -F: '($2 == "" ) { print }' /etc/shadow 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 128 "Empty password hash found in /etc/shadow"
else
    sec_audit_report_pass 128 "/etc/shadow password fields are not empty"
fi

# RULE129:
FAIL129=0
while IFS=: read -r user pass uid gid rest; do
    if ! grep -q "^.*:.*:$gid:" /etc/group 2>/dev/null; then
        sec_audit_report_fail 129 "User $user has primary group GID $gid which does not exist in /etc/group"
        FAIL129=1
    fi
done < /etc/passwd 2>/dev/null
[ $FAIL129 -eq 0 ] && echo "RULE129= PASS: All groups in /etc/passwd exist in /etc/group"

# RULE130:
if cut -f3 -d":" /etc/passwd 2>/dev/null | sort -n | uniq -c | while read -r count uid; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 130 "Duplicate UID entries exist in /etc/passwd"
else
    sec_audit_report_pass 130 "no duplicate UIDs exist"
fi

# RULE131:
if cut -f3 -d":" /etc/group 2>/dev/null | sort -n | uniq -c | while read -r count gid; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 131 "Duplicate GID entries exist in /etc/group"
else
    sec_audit_report_pass 131 "no duplicate GIDs exist"
fi

# RULE132:
if cut -f1 -d":" /etc/passwd 2>/dev/null | sort -n | uniq -c | while read -r count user; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 132 "Duplicate user names exist in /etc/passwd"
else
    sec_audit_report_pass 132 "no duplicate user names exist"
fi

# RULE133:
if cut -f1 -d":" /etc/group 2>/dev/null | sort -n | uniq -c | while read -r count group; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 133 "Duplicate group names exist in /etc/group"
else
    sec_audit_report_pass 133 "no duplicate group names exist"
fi

# RULE134:

FAIL=0
while IFS=: read -r user pass uid gid rest; do
    if [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -lt 65534 ]; then
        home=$(echo "$rest" | cut -d: -f1)
        if [ ! -d "$home" ]; then
            sec_audit_report_fail 134 "User $user home directory $home does not exist"
            FAIL=1
        elif [ "$(stat -c '%U' "$home" 2>/dev/null)" != "$user" ]; then
            sec_audit_report_fail 134 "User $user home directory $home is not owned by $user"
            FAIL=1
        fi
    fi
done < /etc/passwd 2>/dev/null
[ $FAIL -eq 0 ] && echo "RULE134= PASS: local interactive user home directories are configured"

# RULE135:
FAIL135=0
while IFS=: read -r user pass uid gid rest; do
    if [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -lt 65534 ]; then
        home=$(echo "$rest" | cut -d: -f1)
        for dotfile in "$home/.bashrc" "$home/.bash_profile" "$home/.profile" "$home/.bash_logout"; do
            if [ -f "$dotfile" ]; then
                perm=$(stat -c '%a' "$dotfile" 2>/dev/null)
                if [ "${perm:2:1}" -gt 0 ] 2>/dev/null || [ "${perm:1:1}" -gt 0 ] 2>/dev/null; then
                    sec_audit_report_fail 135 "User $user dot file $dotfile has world/group write permissions ($perm)"
                    FAIL135=1
                fi
            fi
        done
    fi
done < /etc/passwd 2>/dev/null
[ $FAIL135 -eq 0 ] && echo "RULE135= PASS: Local interactive user dot files access is configured"

exit 0

