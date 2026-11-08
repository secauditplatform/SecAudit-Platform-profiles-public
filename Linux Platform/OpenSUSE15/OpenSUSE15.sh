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

OS15_FIND_CAP="${OS15_FIND_CAP:-${CRE_FIND_CAP:-20}}"
CRE_FIND_CAP="${OS15_FIND_CAP}"
OS15_CMD_CAP="${OS15_CMD_CAP:-${CRE_CMD_CAP:-12}}"
CRE_CMD_CAP="${OS15_CMD_CAP}"
OS15_DNF_CAP="${OS15_DNF_CAP:-${CRE_DNF_CAP:-30}}"
CRE_DNF_CAP="${OS15_DNF_CAP}"
OS15_ALLOW_CONTAINER_KMOD="${OS15_ALLOW_CONTAINER_KMOD:-${CRE_ALLOW_CONTAINER_KMOD:-${LINUX_CRE_ALLOW_CONTAINER_MODULES:-${ALMA_CRE_ALLOW_CONTAINER_MODULES:-0}}}}"
CRE_ALLOW_CONTAINER_KMOD="${OS15_ALLOW_CONTAINER_KMOD}"
# --- bootstrap / reporting ---
sec_audit_report_pass() { printf 'RULE%s= PASS: %s\n' "$1" "$2"; }
sec_audit_report_fail() { printf 'RULE%s= FAIL: %s\n' "$1" "${3:-$2}"; }
sec_audit_report_skip() { printf 'RULE%s= SKIP: %s\n' "$1" "$2"; }
sec_audit_report_error() { printf 'RULE%s= ERROR: %s\n' "$1" "$2"; }

# --- string / cmd / package utils ---
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

sec_audit_systemd_runtime_ok() {
    sec_audit_have_bin systemctl && [ -d /run/systemd/system ]
}

sec_audit_rpm_any_installed() {
    local pkg
    sec_audit_have_bin rpm || return 1
    for pkg in "$@"; do
        rpm -q "$pkg" &>/dev/null && return 0
    done
    return 1
}

sec_audit_rpm_every_installed() {
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
sec_audit_soft_find() {
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

sec_audit_find_hit_timeout() {
    local rc=0
    "$@" >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 124 ]
}

sec_audit_local_fs_roots() {
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

sec_audit_findmnt_available() { sec_audit_have_bin findmnt; }

sec_audit_mount_resolves() {
    local mp="${1%/}"
    sec_audit_findmnt_available || return 1
    findmnt -kn -T "$mp" &>/dev/null
}

sec_audit_mount_is_dedicated() {
    local mp="${1%/}" tgt
    sec_audit_findmnt_available || return 1
    tgt=$(findmnt -kn -T "$mp" -o TARGET --noheadings 2>/dev/null | head -n1)
    tgt=$(sec_audit_trim_ws "$tgt")
    tgt="${tgt%/}"
    [ -n "$tgt" ] && [ "$tgt" = "$mp" ]
}

sec_audit_mount_source() {
    local mp="${1%/}" s
    sec_audit_findmnt_available || return 1
    s=$(findmnt -kn -T "$mp" -o SOURCE --noheadings 2>/dev/null | head -n1)
    printf '%s' "$(sec_audit_trim_ws "$s")"
}

sec_audit_mount_fstype() {
    local mp="${1%/}" f
    sec_audit_findmnt_available || return 1
    f=$(findmnt -kn -T "$mp" -o FSTYPE --noheadings 2>/dev/null | head -n1)
    printf '%s' "$(sec_audit_trim_ws "$f")"
}

sec_audit_mount_options() {
    local mp="${1%/}" o
    sec_audit_findmnt_available || return 1
    o=$(findmnt -kn -T "$mp" -o OPTIONS --noheadings 2>/dev/null | head -n1)
    printf '%s' "$(sec_audit_trim_ws "$o")"
}

sec_audit_mount_has_option() {
    local mp="$1" want="$2" csv token
    sec_audit_findmnt_available || return 1
    csv=$(sec_audit_mount_options "$mp")
    [ -z "$csv" ] && return 1
    local IFS=,
    for token in $csv; do
        token=$(sec_audit_trim_ws "$token")
        [ "$token" = "$want" ] && return 0
    done
    return 1
}

sec_audit_path_is_isolated_volume() {
    local mp="${1%/}" src root_src
    sec_audit_findmnt_available || return 1
    sec_audit_mount_is_dedicated "$mp" || return 1
    src=$(sec_audit_mount_source "$mp")
    root_src=$(sec_audit_mount_source /)
    [ -n "$src" ] && [ -n "$root_src" ] && [ "$src" != "$root_src" ]
}

sec_audit_tmp_is_isolated() {
    local fst src root_src
    sec_audit_findmnt_available || return 1
    sec_audit_mount_is_dedicated /tmp || return 1
    fst=$(sec_audit_mount_fstype /tmp)
    src=$(sec_audit_mount_source /tmp)
    root_src=$(sec_audit_mount_source /)
    [ "$fst" = "tmpfs" ] && return 0
    [ -n "$src" ] && [ -n "$root_src" ] && [ "$src" != "$root_src" ] && return 0
    return 1
}

sec_audit_shm_is_isolated() {
    local fst src root_src
    sec_audit_findmnt_available || return 1
    sec_audit_mount_is_dedicated /dev/shm || return 1
    fst=$(sec_audit_mount_fstype /dev/shm)
    src=$(sec_audit_mount_source /dev/shm)
    root_src=$(sec_audit_mount_source /)
    [ "$fst" = "tmpfs" ] && return 0
    [ -n "$src" ] && [ -n "$root_src" ] && [ "$src" != "$root_src" ] && return 0
    return 1
}

sec_audit_mount_is_persisted() {
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

sec_audit_persistence_suffix() {
    local mp="${1%/}"
    if sec_audit_mount_is_persisted "$mp"; then
        printf '%s' ""
    else
        printf '%s' " | not persisted in fstab or systemd .mount (lost after reboot)"
    fi
}

sec_audit_fstab_has_option() {
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

# --- dnf / yum ---
sec_audit_dnf_main_option() {
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

sec_audit_truthy_false() {
    case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')" in
        0|false|no|off) return 0 ;;
        *) return 1 ;;
    esac
}

sec_audit_truthy_true() {
    case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

sec_audit_rpm_gpg_pubkey_count() {
    local c
    if ! sec_audit_have_bin rpm; then
        printf '%s\n' 0
        return 0
    fi
    c=$(rpm -qa 'gpg-pubkey*' 2>/dev/null | grep -cve '^[[:space:]]*$' || true)
    printf '%s\n' "${c:-0}"
}

sec_audit_list_repos_gpgcheck_disabled() {
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

sec_audit_list_repos_repogpg_disabled() {
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

sec_audit_enabled_repo_defines_uri() {
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
        ' "$f" && return 0
    done
    shopt -u nullglob
    return 1
}

sec_audit_dnf_enabled_repo_count() {
    local n
    if ! sec_audit_have_bin dnf; then
        printf '%s\n' 0
        return 0
    fi
    n=$(sec_audit_exec_with_timeout "$CRE_DNF_CAP" dnf -q repolist enabled 2>/dev/null | awk '
        /^repo[[:space:]]+id[[:space:]]/ { hdr = 1; next }
        hdr && NF >= 1 && $1 != "" && $1 !~ /^repolist:/ && $1 !~ /^Repo/ { c++ }
        END { print c + 0 }
    ')
    printf '%s\n' "${n:-0}"
}

# --- sshd cache ---
_SSHD_PRIMED=0
_SSHD_DUMP=""

sec_audit_cache_sshd_config() {
    [ "$_SSHD_PRIMED" -eq 1 ] && return 0
    _SSHD_PRIMED=1
    if sec_audit_have_bin sshd; then
        _SSHD_DUMP=$(sshd -T 2>/dev/null) || _SSHD_DUMP=""
    else
        _SSHD_DUMP=""
    fi
}

sec_audit_sshd_effective_config() { sec_audit_cache_sshd_config; printf '%s\n' "$_SSHD_DUMP"; }
sec_audit_sshd_config_grep() { sec_audit_cache_sshd_config; printf '%s\n' "$_SSHD_DUMP" | grep "$@"; }
sec_audit_sshd_config_awk() { sec_audit_cache_sshd_config; printf '%s\n' "$_SSHD_DUMP" | awk "$@"; }

sec_audit_sshd_config_ready() {
    sec_audit_cache_sshd_config
    sec_audit_have_bin sshd || return 1
    [[ -n "${_SSHD_DUMP//[[:space:]]/}" ]]
}

sec_audit_sshd_get() {
    local key
    key=$(sec_audit_to_lower "$1")
    sec_audit_cache_sshd_config
    awk -v k="$key" 'tolower($1)==k { $1=""; sub(/^ /,""); print; exit }' <<<"$_SSHD_DUMP"
}

sec_audit_sshd_get_int() {
    local v
    v=$(sec_audit_sshd_get "$1")
    [[ "$v" =~ ^[0-9]+$ ]] && printf '%s' "$v"
}

# --- auditctl / audit files cache ---
_AUDITCTL_PRIMED=0
_AUDITCTL_DUMP=""

sec_audit_cache_auditctl_list() {
    [ "$_AUDITCTL_PRIMED" -eq 1 ] && return 0
    _AUDITCTL_PRIMED=1
    if sec_audit_have_bin auditctl; then
        _AUDITCTL_DUMP=$(auditctl -l 2>/dev/null) || _AUDITCTL_DUMP=""
    else
        _AUDITCTL_DUMP=""
    fi
}

sec_audit_auditctl_list_grep() { sec_audit_cache_auditctl_list; printf '%s\n' "$_AUDITCTL_DUMP" | grep "$@"; }

_AUDIT_FILES_PRIMED=0
_AUDIT_FILES_DUMP=""

sec_audit_cache_audit_rule_files() {
    [ "$_AUDIT_FILES_PRIMED" -eq 1 ] && return 0
    _AUDIT_FILES_PRIMED=1
    shopt -s nullglob
    _AUDIT_FILES_DUMP=$(cat /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null)
    shopt -u nullglob
}

sec_audit_audit_rules_file_grep() { sec_audit_cache_audit_rule_files; printf '%s\n' "$_AUDIT_FILES_DUMP" | grep "$@"; }

sec_audit_audit_rule_on_disk_and_loaded() {
    sec_audit_cache_audit_rule_files
    sec_audit_cache_auditctl_list
    printf '%s\n' "$_AUDIT_FILES_DUMP" | grep -q "$@" || return 1
    printf '%s\n' "$_AUDITCTL_DUMP" | grep -q "$@" || return 1
    return 0
}

sec_audit_auditd_log_directory() {
    local raw
    [[ -f /etc/audit/auditd.conf ]] || return 1
    raw=$(awk -F= '/^[[:space:]]*log_file[[:space:]]*=/{print $2; exit}' /etc/audit/auditd.conf 2>/dev/null)
    raw=$(sec_audit_trim_ws "$raw")
    [ -n "$raw" ] || raw=/var/log/audit/audit.log
    dirname "$raw"
}

# --- sysctl ---
sec_audit_sysctl_runtime_raw() {
    sec_audit_have_bin sysctl || return 1
    sysctl -n "$1" 2>/dev/null | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

sec_audit_sysctl_runtime() { printf '%s' "$(sec_audit_sysctl_runtime_raw "$1")"; }

sec_audit_sysctl_runtime_equals() {
    local got
    got=$(sec_audit_sysctl_runtime_raw "$1") || return 1
    [[ "$got" == "$2" ]]
}

sec_audit_sysctl_ondisk_last() {
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

sec_audit_sysctl_drift_note() {
    local key="$1" want="$2" disk got
    got=$(sec_audit_sysctl_runtime_raw "$key") || got=""
    disk=$(sec_audit_sysctl_ondisk_last "$key")
    [[ -z $disk ]] && return 0
    if [[ "$got" == "$want" && "$disk" != "$want" ]]; then
        printf '%s' " | note: last on-disk assignment is ${disk} (runtime overrides until reboot)"
    elif [[ "$got" != "$want" && "$disk" == "$want" ]]; then
        printf '%s' " | on-disk last value is ${want} but kernel has '${got:-?}'; run sysctl --system or reboot"
    elif [[ "$got" != "$want" && -n $disk && "$disk" != "$want" ]]; then
        printf '%s' " | on-disk last value is ${disk}, kernel '${got:-?}'"
    fi
}

sec_audit_ipv4_iface_sysctl_mismatches() {
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

sec_audit_assert_sysctl_equals() {
    local num="$1" key="$2" want="$3" r disk hint="" extra=""
    r=$(sec_audit_sysctl_runtime "$key")
    disk=$(sec_audit_sysctl_ondisk_last "$key")
    hint=$(sec_audit_sysctl_drift_note "$key" "$want")
    if ! sec_audit_sysctl_runtime_equals "$key" "$want"; then
        sec_audit_report_fail "$num" "kernel ${key} is '${r:-<unreadable>}', expected ${want}${hint}"
        return 0
    fi
    if [[ -n "$disk" && "$disk" != "$want" ]]; then
        sec_audit_report_fail "$num" "kernel ${key}=${want} but last on-disk assignment is ${disk} (not reboot-safe)${hint}"
        return 0
    fi
    case "$key" in
        net.ipv4.conf.all.*)
            extra=$(sec_audit_ipv4_iface_sysctl_mismatches "${key##*.}" "$want")
            if [[ -n "$extra" ]]; then
                sec_audit_report_fail "$num" "${key}=${want} but per-interface values differ: ${extra}"
                return 0
            fi
            ;;
    esac
    sec_audit_report_pass "$num" "${key}=${want} in kernel and on disk${hint}"
}

# --- kernel modules ---
sec_audit_kmod_autoload_listed() {
    local pat="" a
    for a in "$@"; do
        pat+="${pat:+|}${a}"
    done
    grep -rqE "^[[:space:]]*(${pat})([[:space:]]|$)" /etc/modules-load.d /usr/lib/modules-load.d /run/modules-load.d 2>/dev/null
}

sec_audit_kmod_is_loaded() {
    local name="$1"
    [[ -f /proc/modules ]] && awk '{print $1}' /proc/modules | grep -qx "$name" && return 0
    lsmod 2>/dev/null | awk '{print $1}' | grep -qx "$name"
}

sec_audit_kmod_object_exists() {
    local pattern="$1" cap="${2:-$CRE_FIND_CAP}" rc=0 out=""
    out=$(sec_audit_soft_find --timeout="$cap" /usr/lib/modules/ /lib/modules/ \
        -xdev -ignore_readdir_race -type f -name "${pattern}" -print -quit 2>/dev/null) || rc=$?
    if [ "$rc" -eq 124 ]; then
        return 2
    fi
    [ -n "$out" ]
}

sec_audit_kmod_is_blocked() {
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

sec_audit_kmod_container_exception() {
    local mod="$1"
    case "$mod" in
        overlay|squashfs)
            [[ "${CRE_ALLOW_CONTAINER_KMOD}" == "1" ]]
            ;;
        *) return 1 ;;
    esac
}

sec_audit_assert_kmod_disabled() {
    local num="$1" label="$2" mod="$3" ko_pattern="$4"
    shift 4
    local alias loaded=0 a
    if sec_audit_kmod_container_exception "$mod"; then
        sec_audit_report_pass "$num" "${label} (waived: OS15_ALLOW_CONTAINER_KMOD=1)"
        return 0
    fi
    for a in "$@"; do
        if sec_audit_kmod_autoload_listed "$a"; then
            sec_audit_report_fail "$num" "${label} is listed in modules-load.d (auto-load at boot)"
            return 0
        fi
    done
    case "$(sec_audit_kmod_object_exists "$ko_pattern"; echo $?)" in
        2) sec_audit_report_fail "$num" "incomplete_scan: module scan timed out for ${label}"; return 0 ;;
        1) sec_audit_report_pass "$num" "${label} is not available (no kernel object on disk)"; return 0 ;;
    esac
    loaded=0
    for a in "$@"; do
        if sec_audit_kmod_is_loaded "$a"; then
            loaded=1
            break
        fi
    done
    if [ "$loaded" -eq 1 ]; then
        sec_audit_report_fail "$num" "${label} is currently loaded"
        return 0
    fi
    if sec_audit_kmod_is_blocked "$mod"; then
        sec_audit_report_pass "$num" "${label} is blocked (blacklist/install /bin/false and modprobe -n refuses load)"
        return 0
    fi
    sec_audit_report_fail "$num" "${label} is available on disk and not effectively blocked"
}

# --- systemd units ---
sec_audit_systemd_is_enabled() { systemctl is-enabled "$1" 2>/dev/null || true; }
sec_audit_systemd_is_active() { systemctl is-active "$1" 2>/dev/null || true; }

sec_audit_systemd_unit_live() {
    local unit state
    for unit in "$@"; do
        state=$(sec_audit_systemd_is_enabled "$unit")
        case "$state" in
            enabled|enabled-runtime|linked|linked-runtime|alias) return 0 ;;
        esac
        case "$(sec_audit_systemd_is_active "$unit")" in
            active|activating) return 0 ;;
        esac
    done
    return 1
}

sec_audit_assert_service_unused() {
    local num="$1" pkg="$2" pass_msg="$3" fail_msg="$4"
    shift 4
    if ! sec_audit_pkg_is_installed "$pkg"; then
        sec_audit_report_pass "$num" "$pass_msg"
    elif sec_audit_systemd_unit_live "$@"; then
        sec_audit_report_fail "$num" "$fail_msg"
    else
        sec_audit_report_pass "$num" "$pass_msg (package present but units masked/disabled/inactive)"
    fi
}

# --- files ---
sec_audit_path_mode_octal() { stat -Lc '%a' "$1" 2>/dev/null; }
sec_audit_can_read_shadow() { [[ -r /etc/shadow ]]; }
sec_audit_path_owner_pair() { stat -Lc '%U:%G' "$1" 2>/dev/null; }
sec_audit_path_owner_user() { stat -Lc '%U' "$1" 2>/dev/null; }
sec_audit_path_owner_group() { stat -Lc '%G' "$1" 2>/dev/null; }

sec_audit_mode_within_max() {
    local path="$1" max="$2" got
    [[ -e $path ]] || return 1
    got=$(sec_audit_path_mode_octal "$path") || return 1
    [[ "$got" =~ ^[0-7]+$ ]] || return 1
    (( (8#$got & ~8#$max) == 0 ))
}

sec_audit_path_owned_by() {
    local path="$1" want="$2"
    [[ "$(sec_audit_path_owner_pair "$path")" == "$want" ]]
}

sec_audit_assert_path_access() {
    local num="$1" path="$2" maxmode="$3" owner="$4" pass_msg="$5" missing_ok="${6:-0}" extra_group="${7:-}"
    if [[ ! -e $path ]]; then
        if [[ "$missing_ok" == "1" ]]; then
            sec_audit_report_pass "$num" "${pass_msg} (file absent)"
        else
            sec_audit_report_fail "$num" "${path} is missing"
        fi
        return 0
    fi
    if ! sec_audit_mode_within_max "$path" "$maxmode"; then
        sec_audit_report_fail "$num" "${path} mode $(sec_audit_path_mode_octal "$path") is more permissive than ${maxmode}"
        return 0
    fi
    if [[ -n "$extra_group" ]]; then
        if [[ "$(sec_audit_path_owner_user "$path")" != "${owner%%:*}" ]]; then
            sec_audit_report_fail "$num" "${path} owner is $(sec_audit_path_owner_user "$path"), expected ${owner%%:*}"
            return 0
        fi
        case "$(sec_audit_path_owner_group "$path")" in
            ${owner##*:}|${extra_group}) ;;
            *) sec_audit_report_fail "$num" "${path} group is $(sec_audit_path_owner_group "$path"), expected ${owner##*:} or ${extra_group}"; return 0 ;;
        esac
    else
        if ! sec_audit_path_owned_by "$path" "$owner"; then
            sec_audit_report_fail "$num" "${path} owner is $(sec_audit_path_owner_pair "$path"), expected ${owner}"
            return 0
        fi
    fi
    sec_audit_report_pass "$num" "$pass_msg (mode $(sec_audit_path_mode_octal "$path"), owner $(sec_audit_path_owner_pair "$path"))"
}

sec_audit_assert_dir_access() {
    sec_audit_assert_path_access "$@"
}

# --- grub ---
sec_audit_list_grub_cfg_paths() {
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

sec_audit_grub_cfg_matches() {
    local pat="$1" p found=0
    while IFS= read -r p; do
        [[ -f $p ]] || continue
        if grep -qE "$pat" "$p" 2>/dev/null; then
            found=1
            break
        fi
    done <<< "$(sec_audit_list_grub_cfg_paths)"
    [ "$found" -eq 1 ]
}

# --- PAM ---
sec_audit_pam_password_stack_paths() {
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

sec_audit_pam_auth_stack_paths() {
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

sec_audit_pam_pwquality_before_unix() {
    local p any=0 stacks
    stacks="$(sec_audit_pam_password_stack_paths)"
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

sec_audit_pam_password_stack_has() {
    local mod="$1" p stacks
    stacks="$(sec_audit_pam_password_stack_paths)"
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

sec_audit_pam_auth_stack_has() {
    local mod="$1" p stacks
    stacks="$(sec_audit_pam_auth_stack_paths)"
    while IFS= read -r p; do
        [[ -f $p ]] || continue
        grep -E '^[[:space:]]*auth[[:space:]]' "$p" 2>/dev/null | grep -q "$mod" && return 0
    done <<< "$stacks"
    return 1
}

sec_audit_pam_password_grep() {
    local pattern="$1" p stacks
    stacks="$(sec_audit_pam_password_stack_paths)"
    while IFS= read -r p; do
        [[ -f $p ]] || continue
        grep -Pq "$pattern" "$p" 2>/dev/null && return 0
    done <<< "$stacks"
    return 1
}

sec_audit_pam_password_igrep() {
    local pattern="$1" p stacks
    stacks="$(sec_audit_pam_password_stack_paths)"
    while IFS= read -r p; do
        [[ -f $p ]] || continue
        grep -Piq "$pattern" "$p" 2>/dev/null && return 0
    done <<< "$stacks"
    return 1
}

sec_audit_pam_login_auth_igrep() {
    local pattern="$1" p
    while IFS= read -r p; do
        [[ -f $p ]] || continue
        grep -Piq "$pattern" "$p" 2>/dev/null && return 0
    done <<< "$(sec_audit_pam_auth_stack_paths)"
    return 1
}

# --- misc ---
sec_audit_core_dumps_limited() {
    grep -Psiq '^\*\s+hard\s+core\s+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null || return 1
    if grep -rPiq '^\h*DefaultLimitCORE\h*=\h*(infinity|unlimited)\b' /etc/systemd/system.conf /etc/systemd/user.conf /etc/systemd/system.conf.d/*.conf /etc/systemd/user.conf.d/*.conf 2>/dev/null; then
        return 1
    fi
    if grep -rPiq '^\h*DefaultLimitCORE\h*=\h*[1-9][0-9]*\b' /etc/systemd/system.conf /etc/systemd/user.conf /etc/systemd/system.conf.d/*.conf /etc/systemd/user.conf.d/*.conf 2>/dev/null; then
        return 1
    fi
    return 0
}

sec_audit_gdm_installed() { sec_audit_rpm_any_installed gdm; }

sec_audit_dconf_gdm_matches() {
    local pat="$1"
    shopt -s nullglob
    local files=(/etc/dconf/db/gdm.d/* /etc/dconf/db/local.d/* /etc/dconf/db/distro.d/*)
    shopt -u nullglob
    ((${#files[@]})) || return 1
    grep -Rqs -- "$pat" "${files[@]}" 2>/dev/null
}

sec_audit_journald_conf_merged() {
    if sec_audit_have_bin systemd-analyze; then
        systemd-analyze cat-config systemd/journald.conf 2>/dev/null
        return 0
    fi
    cat /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null
}

sec_audit_journald_get() {
    local key="$1"
    sec_audit_journald_conf_merged | awk -F= -v k="$key" '
        $0 ~ /^[[:space:]]*#/ { next }
        $1 == k { v=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", v) }
        END { print v }
    '
}

sec_audit_os_release_id() {
    awk -F= '/^ID=/{gsub(/"/,"",$2); print $2; exit}' /etc/os-release 2>/dev/null
}

sec_audit_banner_exposes_os() {
    local file="$1" id
    [[ -f $file ]] || return 1
    id=$(sec_audit_os_release_id)
    grep -Psiq "(\\\\v|\\\\r|\\\\m|\\\\s|\\b${id}\\b)" "$file" 2>/dev/null
}

sec_audit_login_defs_value() {
    local key="$1"
    awk -v k="$key" '$1==k {print $2; exit}' /etc/login.defs 2>/dev/null
}

sec_audit_get_uid_min() {
    local v
    v=$(sec_audit_login_defs_value UID_MIN)
    printf '%s' "${v:-1000}"
}

sec_audit_interactive_shell_pattern() {
    awk -F/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells 2>/dev/null \
        | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -
}

sec_audit_assert_isolated_mount() {
    local num="$1" mp="$2" pass_msg="$3" kind="${4:-separate}"
    local ok=1
    if [[ "$kind" == "tmp" ]]; then
        sec_audit_tmp_is_isolated || ok=0
    elif [[ "$kind" == "shm" ]]; then
        sec_audit_shm_is_isolated || ok=0
    else
        sec_audit_path_is_isolated_volume "$mp" || ok=0
    fi
    if [ "$ok" -eq 1 ]; then
        if sec_audit_mount_is_persisted "$mp"; then
            sec_audit_report_pass "$num" "$pass_msg (fstype=$(sec_audit_mount_fstype "$mp"), source=$(sec_audit_mount_source "$mp"))"
        else
            sec_audit_report_fail "$num" "${mp} isolation is runtime-only (missing fstab or systemd .mount persistence)"
        fi
    else
        sec_audit_report_fail "$num" "${mp} is not a dedicated tmpfs/separate partition"
    fi
}

sec_audit_assert_mount_option() {
    local num="$1" mp="$2" flag="$3"
    if ! sec_audit_mount_resolves "$mp"; then
        sec_audit_report_fail "$num" "${flag} is not set on ${mp} (path not resolvable / not an explicit mount)"
        return 0
    fi
    if ! sec_audit_mount_has_option "$mp" "$flag"; then
        sec_audit_report_fail "$num" "${flag} is not set on runtime mount ${mp} (opts: $(sec_audit_mount_options "$mp"))"
        return 0
    fi
    if sec_audit_mount_is_persisted "$mp" && ! sec_audit_fstab_has_option "$mp" "$flag"; then
        local unit_note
        unit_note=$(sec_audit_persistence_suffix "$mp")
        if [[ -n "$unit_note" ]] || ! grep -q "$flag" <<<"$(sec_audit_mount_options "$mp")"; then
            :
        fi
        if [[ -f /etc/fstab ]] && grep -Pqs "[[:space:]]${mp//\//\\/}[[:space:]]" /etc/fstab && ! sec_audit_fstab_has_option "$mp" "$flag"; then
            sec_audit_report_fail "$num" "${flag} is set at runtime on ${mp} but missing from fstab (not reboot-safe)"
            return 0
        fi
    fi
    sec_audit_report_pass "$num" "${flag} option set on ${mp}$(sec_audit_persistence_suffix "$mp")"
}

sec_audit_assert_package_absent() {
    local num="$1" pkg="$2" pass_msg="$3" fail_msg="$4"
    if sec_audit_pkg_is_installed "$pkg"; then
        sec_audit_report_fail "$num" "$fail_msg"
    else
        sec_audit_report_pass "$num" "$pass_msg"
    fi
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
                if (enabled && gc_explicit && sec_audit_truthy_false(gc_val)) {
                    print FILENAME "|" sec
                }
                sec = ""
                enabled = 1
                gc_explicit = 0
                gc_val = ""
            }
            function sec_audit_truthy_false(s, t) {
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
                if (enabled && rgc_explicit && sec_audit_truthy_false(rgc_val)) {
                    print FILENAME "|" sec
                }
                sec = ""
                enabled = 1
                rgc_explicit = 0
                rgc_val = ""
            }
            function sec_audit_truthy_false(s, t) {
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
        ' "$f" && return 0
    done
    shopt -u nullglob
    return 1
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

sec_audit_pkg_any_installed() {
    for pkg in "$@"; do
        if rpm -q "$pkg" &>/dev/null; then
            return 0
        fi
    done
    return 1
}

sec_audit_sysctl_runtime_matches_regex() {
    local got
    got=$(sec_audit_sysctl_runtime_raw "$1") || return 1
    [[ "$got" =~ $2 ]]
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
    local p any=0 stacks
    stacks="$(sec_audit_pam_stack_paths_password_system)"
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

sec_audit_pam_password_line_has_module() {
    local mod="$1" p stacks
    stacks="$(sec_audit_pam_stack_paths_password_system)"
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
sec_audit_assert_kmod_disabled 1 "squashfs kernel module" squashfs squashfs.ko* "squashfs"
# RULE2:
if sec_audit_kmod_autoload_listed freevxfs; then
    sec_audit_report_fail 2 "freevxfs kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_soft_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "freevxfs.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 2 "freevxfs kernel module is not available"
else
    if ! lsmod | grep -q freevxfs && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+freevxfs\b'; then
        sec_audit_report_pass 2 "freevxfs kernel module is not available"
    else
        sec_audit_report_fail 2 "freevxfs kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

# RULE3:
sec_audit_assert_kmod_disabled 3 "hfs kernel module" hfs hfs.ko* "hfs"
# RULE4:
if sec_audit_tmp_is_isolated; then
    if sec_audit_mount_is_persisted /tmp; then
        sec_audit_report_pass 4 "/tmp is tmpfs or a separate partition"
    else
        sec_audit_report_fail 4 "/tmp is tmpfs or a separate partition is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 4 "/tmp does not meet tmpfs or separate-partition requirement"
fi
# RULE5:
if findmnt -n /tmp 2>/dev/null | grep -q 'nodev'; then
    sec_audit_report_pass 5 "nodev option is set on /tmp partition"
else
    sec_audit_report_fail 5 "nodev option is not set on /tmp partition"
fi

# RULE6:
if findmnt -n /tmp 2>/dev/null | grep -q 'nosuid'; then
    sec_audit_report_pass 6 "nosuid option is set on /tmp partition"
else
    sec_audit_report_fail 6 "nosuid option is not set on /tmp partition"
fi

# RULE7:
if findmnt -n /tmp 2>/dev/null | grep -q 'noexec'; then
    sec_audit_report_pass 7 "noexec option is set on /tmp partition"
else
    sec_audit_report_fail 7 "noexec option is not set on /tmp partition"
fi

# RULE8:
if sec_audit_path_is_isolated_volume /var; then
    if sec_audit_mount_is_persisted /var; then
        sec_audit_report_pass 8 "separate partition exists for /var"
    else
        sec_audit_report_fail 8 "dedicated mount for /var is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 8 "no compliant dedicated mount for /var"
fi
# RULE9:
if sec_audit_path_is_isolated_volume /var/tmp; then
    if sec_audit_mount_is_persisted /var/tmp; then
        sec_audit_report_pass 9 "separate partition exists for /var/tmp"
    else
        sec_audit_report_fail 9 "dedicated mount for /var/tmp is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 9 "no compliant dedicated mount for /var/tmp"
fi
# RULE10:
if findmnt -n /var/tmp 2>/dev/null | grep -q 'nodev'; then
    sec_audit_report_pass 10 "nodev option is set on /var/tmp partition"
else
    sec_audit_report_fail 10 "nodev option is not set on /var/tmp partition"
fi

# RULE11:
if findmnt -n /var/tmp 2>/dev/null | grep -q 'nosuid'; then
    sec_audit_report_pass 11 "nosuid option is set on /var/tmp partition"
else
    sec_audit_report_fail 11 "nosuid option is not set on /var/tmp partition"
fi

# RULE12:
if findmnt -n /var/tmp 2>/dev/null | grep -q 'noexec'; then
    sec_audit_report_pass 12 "noexec option is set on /var/tmp partition"
else
    sec_audit_report_fail 12 "noexec option is not set on /var/tmp partition"
fi

# RULE13:
if sec_audit_path_is_isolated_volume /var/log; then
    if sec_audit_mount_is_persisted /var/log; then
        sec_audit_report_pass 13 "separate partition exists for /var/log"
    else
        sec_audit_report_fail 13 "dedicated mount for /var/log is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 13 "no compliant dedicated mount for /var/log"
fi
# RULE14:
if sec_audit_path_is_isolated_volume /var/log/audit; then
    if sec_audit_mount_is_persisted /var/log/audit; then
        sec_audit_report_pass 14 "separate partition exists for /var/log/audit"
    else
        sec_audit_report_fail 14 "dedicated mount for /var/log/audit is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 14 "no compliant dedicated mount for /var/log/audit"
fi
# RULE15:
if sec_audit_path_is_isolated_volume /home; then
    if sec_audit_mount_is_persisted /home; then
        sec_audit_report_pass 15 "separate partition exists for /home"
    else
        sec_audit_report_fail 15 "dedicated mount for /home is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 15 "no compliant dedicated mount for /home"
fi
# RULE16:
if findmnt -n /home 2>/dev/null | grep -q 'nodev'; then
    sec_audit_report_pass 16 "nodev option is set on /home partition"
else
    sec_audit_report_fail 16 "nodev option is not set on /home partition"
fi

# RULE17:
if sec_audit_shm_is_isolated; then
    if sec_audit_mount_is_persisted /dev/shm; then
        sec_audit_report_pass 17 "/dev/shm is tmpfs or a separate partition"
    else
        sec_audit_report_fail 17 "/dev/shm is tmpfs or a separate partition is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 17 "/dev/shm does not meet tmpfs or separate-partition requirement"
fi
# RULE18:
if findmnt -n /dev/shm 2>/dev/null | grep -q 'nosuid'; then
    sec_audit_report_pass 18 "nosuid option is set on /dev/shm partition"
else
    sec_audit_report_fail 18 "nosuid option is not set on /dev/shm partition"
fi

# RULE19:
if findmnt -n /dev/shm 2>/dev/null | grep -q 'noexec'; then
    sec_audit_report_pass 19 "noexec option is set on /dev/shm partition"
else
    sec_audit_report_fail 19 "noexec option is not set on /dev/shm partition"
fi

# RULE20:
NOSTICKY=$(sec_audit_soft_find --timeout=30 / -xdev -ignore_readdir_race -type d -perm -0002 ! -perm -1000 2>/dev/null | wc -l)
if [ "${NOSTICKY:-0}" -eq 0 ]; then
    sec_audit_report_pass 20 "sticky bit is set on all world-writable directories"
else
    sec_audit_report_fail 20 "$NOSTICKY world-writable director(y/ies) found without sticky bit"
fi

# RULE21:
if systemctl is-enabled autofs.service 2>/dev/null | grep -qv 'enabled'; then
    if ! systemctl is-active autofs.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_pass 21 "automounting is disabled"
    else
        sec_audit_report_fail 21 "autofs service is active"
    fi
else
    sec_audit_report_fail 21 "autofs service is enabled"
fi

# RULE22:
echo "RULE22= MANUAL: GPG key configuration requires manual review"

# RULE23:
if sec_audit_grub_cfg_matches '^[[:space:]]*set superusers' && sec_audit_grub_cfg_matches 'password_pbkdf2'; then
    sec_audit_report_pass 23 "bootloader password is set (grub.cfg under /boot/grub2 or EFI)"
else
    sec_audit_report_fail 23 "GRUB bootloader superuser/password_pbkdf2 is not configured as required in grub.cfg"
fi
# RULE24:
_fail50=1
while IFS= read -r _gcfg; do
    [[ -f "$_gcfg" ]] || continue
    if stat -Lc '%a' "$_gcfg" 2>/dev/null | grep -q '^[0-6]00$'; then
        if stat -Lc '%U:%G' "$_gcfg" 2>/dev/null | grep -q '^root:root$'; then
            _fail50=0
            break
        fi
    fi
done <<< "$(sec_audit_list_grub_cfg_paths)"
if [ "$_fail50" -eq 0 ]; then
    sec_audit_report_pass 24 "access to bootloader config is configured"
else
    sec_audit_report_fail 24 "/boot/grub2/grub.cfg (or EFI grub.cfg) owner/mode is not root:root with mode 600"
fi
# RULE25:
sec_audit_assert_sysctl_equals 25 fs.protected_hardlinks 1
# RULE26:
if sec_audit_core_dumps_limited; then
    sec_audit_report_pass 26 "limits * hard core 0 present and systemd DefaultLimitCORE does not allow unlimited core dumps"
elif grep -Psi '^\*\s+hard\s+core\s+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null; then
    sec_audit_report_fail 26 "limits.conf sets hard core 0 but systemd DefaultLimitCORE contradicts (check system.conf / user.conf drop-ins)"
else
    sec_audit_report_fail 26 "core file size limits are not configured (limits * hard core 0 not found)"
fi

# RULE27:
sec_audit_assert_sysctl_equals 27 fs.protected_symlinks 1
# RULE28:
if grep -Pi '^\h*LEGACY\b' /etc/crypto-policies/config 2>/dev/null; then
    sec_audit_report_fail 28 "System-wide crypto policy is LEGACY in /etc/crypto-policies/config"
else
    sec_audit_report_pass 28 "system wide crypto policy is not set to legacy"
fi

# RULE29:
if grep -Pi '^\h*LEGACY\b' /etc/crypto-policies/config 2>/dev/null; then
    sec_audit_report_fail 29 "System-wide crypto policy is LEGACY in /etc/crypto-policies/config"
else
    sec_audit_report_pass 29 "system wide crypto policy is not set to legacy"
fi

# RULE30:
if dmesg 2>/dev/null | grep -q 'NX (Execute Disable) protection: active' || grep -q 'nx' /proc/cpuinfo 2>/dev/null; then
    sec_audit_report_pass 30 "XD/NX support is enabled"
else
    sec_audit_report_fail 30 "XD/NX support is not detected (check BIOS and kernel boot params)"
fi

# RULE31:
if sysctl kernel.randomize_va_space 2>/dev/null | grep -q '= 2'; then
    sec_audit_report_pass 31 "ASLR (kernel.randomize_va_space=2) is enabled"
else
    sec_audit_report_fail 31 "ASLR is not set to 2 in kernel.randomize_va_space"
fi

# RULE32:
if grep -Pi '(^\h*mac\h*=\h*([^#\n\r]+)?-128|hmac-sha1)' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_fail 32 "Weak MAC algorithms still present in /etc/crypto-policies/state/CURRENT.pol"
else
    sec_audit_report_pass 32 "system wide crypto policy macs are configured"
fi

# RULE33:
if grep -Piq '^\h*cipher@(lib|open)ssh(-server|-client)?\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_pass 33 "system wide crypto policy disables cbc for ssh"
elif grep -Piq '^\h*cipher\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_pass 33 "system wide crypto policy disables cbc for ssh"
else
    sec_audit_report_fail 33 "CBC ciphers for SSH are still allowed by crypto policy (CURRENT.pol)"
fi

# RULE34:
if grep -Pi '^\h*linux\b' /boot/grub2/grub.cfg 2>/dev/null | grep -Pq 'apparmor=1\b' && grep -Pi '^\h*linux\b' /boot/grub2/grub.cfg 2>/dev/null | grep -Pq 'security=apparmor\b'; then
    sec_audit_report_pass 34 "AppArmor is enabled in the bootloader configuration"
else
    sec_audit_report_fail 34 "apparmor=1 and/or security=apparmor is not set in grub kernel line"
fi

# RULE35:
if command -v apparmor_status &>/dev/null; then
    if apparmor_status 2>/dev/null | grep -q '0 profiles are in complain mode' && apparmor_status 2>/dev/null | grep -q '0 processes are unconfined'; then
        sec_audit_report_pass 35 "all AppArmor profiles are enforcing"
    else
        sec_audit_report_fail 35 "some AppArmor profiles are in complain mode or processes are unconfined"
    fi
else
    sec_audit_report_fail 35 "AppArmor not installed or apparmor_status not available"
fi

# RULE36:
if grep -Psi "(\\\v|\\\r|\\\m|\\\s)" /etc/motd 2>/dev/null; then
    sec_audit_report_fail 36 "/etc/motd contains system info escape sequences"
else
    sec_audit_report_pass 36 "message of the day is configured properly"
fi

# RULE37:
if grep -Psi "(\\\v|\\\r|\\\m|\\\s)" /etc/issue 2>/dev/null; then
    sec_audit_report_fail 37 "/etc/issue contains system info escape sequences"
else
    sec_audit_report_pass 37 "local login warning banner is configured properly"
fi

# RULE38:
if grep -Psi "(\\\v|\\\r|\\\m|\\\s)" /etc/issue.net 2>/dev/null; then
    sec_audit_report_fail 38 "/etc/issue.net contains system info escape sequences"
else
    sec_audit_report_pass 38 "remote login warning banner is configured properly"
fi

# RULE39:
if stat -Lc '%a' /etc/motd 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/motd 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 39 "permissions on /etc/motd are configured"
    else
        sec_audit_report_fail 39 "/etc/motd permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 39 "/etc/motd permissions or ownership not correct"
fi

# RULE40:
if stat -Lc '%a' /etc/issue 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/issue 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 40 "permissions on /etc/issue are configured"
    else
        sec_audit_report_fail 40 "/etc/issue permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 40 "/etc/issue permissions or ownership not correct"
fi

# RULE41:
if [ -e /etc/issue.net ]; then
    if stat -Lc '%a' /etc/issue.net 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/issue.net 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 41 "permissions on /etc/issue.net are configured"
        else
            sec_audit_report_fail 41 "/etc/issue.net permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 41 "/etc/issue.net permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 41 "/etc/issue.net does not exist (not applicable)"
fi

# RULE42:
echo "RULE42= MANUAL: software update status requires manual review"

# RULE43:
if rpm -q ntp &>/dev/null || rpm -q chrony &>/dev/null; then
    sec_audit_report_pass 43 "time synchronization package (ntp or chrony) is installed"
else
    sec_audit_report_fail 43 "no time synchronization package (ntp/chrony) is installed"
fi

# RULE44:
if rpm -q xorg-x11-server-Xorg &>/dev/null || rpm -q xorg-x11 &>/dev/null; then
    sec_audit_report_fail 44 "X Window System is installed"
else
    sec_audit_report_pass 44 "X Window System is not installed"
fi

# RULE45:
sec_audit_assert_service_unused 45 avahi "avahi daemon services are not in use" "avahi daemon services are installed and enabled or actively running" "avahi-daemon.socket" "avahi-daemon.service"
# RULE46:
sec_audit_assert_service_unused 46 cups "print server services are not in use" "print server services are installed and enabled or actively running" "cups.socket" "cups.service"
# RULE47:
if rpm -q dhcp-server &>/dev/null || rpm -q dhcpd &>/dev/null; then
    sec_audit_report_fail 47 "DHCP server is installed"
else
    sec_audit_report_pass 47 "DHCP server is not installed"
fi

# RULE48:
if rpm -q nfs-kernel-server &>/dev/null || systemctl is-active nfs-server.service 2>/dev/null | grep -q '^active'; then
    sec_audit_report_fail 48 "NFS server is installed or active"
else
    sec_audit_report_pass 48 "NFS server is not installed"
fi

# RULE49:
if rpm -q xorg-x11 &>/dev/null || rpm -q xorg-x11-server-Xorg &>/dev/null; then
    sec_audit_report_fail 49 "X window server services (xorg-x11) are installed"
else
    sec_audit_report_pass 49 "X window server services are not in use"
fi

# RULE50:
if systemctl is-active avahi-daemon.service 2>/dev/null | grep -q '^active'; then
    sec_audit_report_fail 50 "avahi-daemon service is active"
else
    sec_audit_report_pass 50 "Avahi (avahi-daemon) is not in use"
fi

# RULE51:
if rpm -q cups &>/dev/null || dpkg -s cups &>/dev/null; then
    sec_audit_report_fail 51 "package cups is installed"
else
    sec_audit_report_pass 51 "package cups is not installed"
fi

# RULE52:
if rpm -q dhcp &>/dev/null || dpkg -s dhcp &>/dev/null; then
    sec_audit_report_fail 52 "package dhcp is installed"
else
    sec_audit_report_pass 52 "package dhcp is not installed"
fi

# RULE53:
if rpm -q openldap2 &>/dev/null || systemctl is-active slapd.service 2>/dev/null | grep -q '^active'; then
    sec_audit_report_fail 53 "LDAP server (openldap2/slapd) is installed or active"
else
    sec_audit_report_pass 53 "LDAP server is not installed"
fi

# RULE54:
if rpm -q nfs-utils &>/dev/null || dpkg -s nfs-utils &>/dev/null; then
    sec_audit_report_fail 54 "package nfs-utils is installed"
else
    sec_audit_report_pass 54 "package nfs-utils is not installed"
fi

# RULE55:
if rpm -q nfs-utils &>/dev/null || dpkg -s nfs-utils &>/dev/null; then
    sec_audit_report_fail 55 "package nfs-utils is installed"
else
    sec_audit_report_pass 55 "package nfs-utils is not installed"
fi

# RULE56:
if rpm -q bind &>/dev/null || systemctl is-active named.service 2>/dev/null | grep -q '^active'; then
    sec_audit_report_fail 56 "DNS server (bind/named) is installed or active"
else
    sec_audit_report_pass 56 "DNS server is not installed"
fi

# RULE57:
if rpm -q vsftpd &>/dev/null || rpm -q pure-ftpd &>/dev/null; then
    sec_audit_report_fail 57 "FTP server (vsftpd/pure-ftpd) is installed"
else
    sec_audit_report_pass 57 "FTP server is not installed"
fi

# RULE58:
if rpm -q apache2 &>/dev/null || rpm -q nginx &>/dev/null || systemctl is-active httpd 2>/dev/null | grep -q '^active'; then
    sec_audit_report_fail 58 "HTTP server (apache2/nginx) is installed or active"
else
    sec_audit_report_pass 58 "HTTP server is not installed"
fi

# RULE59:
if rpm -q dovecot &>/dev/null || rpm -q cyrus-imapd &>/dev/null; then
    sec_audit_report_fail 59 "IMAP/POP3 server (dovecot/cyrus-imapd) is installed"
else
    sec_audit_report_pass 59 "IMAP and POP3 server is not installed"
fi

# RULE60:
sec_audit_assert_service_unused 60 samba "samba file server services are not in use" "samba file server services are installed and enabled or actively running" "smb.service"
# RULE61:
if rpm -q squid &>/dev/null || systemctl is-active squid.service 2>/dev/null | grep -q '^active'; then
    sec_audit_report_fail 61 "HTTP Proxy server (squid) is installed or active"
else
    sec_audit_report_pass 61 "HTTP Proxy server is not installed"
fi

# RULE62:
sec_audit_assert_service_unused 62 net-snmp "snmp services are not in use" "snmp services are installed and enabled or actively running" "snmpd.service"
# RULE63:
if ss -lntu 2>/dev/null | grep -E ':25\b' | grep -qvE '127\.0\.0\.1:25|::1:25|\[::1\]:25'; then
    sec_audit_report_fail 63 "mail transfer agent is listening on a non-loopback interface (port 25)"
elif ss -lntu 2>/dev/null | grep -qE ':25\b'; then
    sec_audit_report_pass 63 "mail transfer agents are configured for local-only mode"
else
    sec_audit_report_pass 63 "mail transfer agents are configured for local-only mode (no MTA listening)"
fi

# RULE64:
if rpm -q ypserv &>/dev/null || systemctl is-active ypserv.service 2>/dev/null | grep -q '^active'; then
    sec_audit_report_fail 64 "NIS server (ypserv) is installed or active"
else
    sec_audit_report_pass 64 "NIS server is not installed"
fi

# RULE65:
if rpm -q rsync &>/dev/null && systemctl is-enabled rsync.service 2>/dev/null | grep -q 'enabled'; then
    sec_audit_report_fail 65 "rsync service is installed and enabled"
else
    sec_audit_report_pass 65 "rsync service is not installed or not enabled"
fi

# RULE66:
if rpm -q telnetd &>/dev/null || rpm -q xinetd &>/dev/null; then
    sec_audit_report_fail 66 "telnet server (telnetd/xinetd) is installed"
else
    sec_audit_report_pass 66 "telnet server is not installed"
fi

# RULE67:
if rpm -q chrony &>/dev/null; then
    if systemctl is-active chronyd.service &>/dev/null; then
        sec_audit_report_pass 67 "chrony is installed and chronyd.service is active"
    else
        sec_audit_report_fail 67 "chrony is installed but chronyd.service is not active"
    fi
else
    sec_audit_report_fail 67 "time synchronization is not in use (chrony not installed)"
fi

# RULE68:
if rpm -q talk &>/dev/null || dpkg -s talk &>/dev/null; then
    sec_audit_report_fail 68 "package talk is installed"
else
    sec_audit_report_pass 68 "package talk is not installed"
fi

# RULE69:
if rpm -q telnet &>/dev/null || dpkg -s telnet &>/dev/null; then
    sec_audit_report_fail 69 "package telnet is installed"
else
    sec_audit_report_pass 69 "package telnet is not installed"
fi

# RULE70:
if rpm -q openldap2-client &>/dev/null; then
    sec_audit_report_fail 70 "LDAP client (openldap2-client) is installed"
else
    sec_audit_report_pass 70 "LDAP client is not installed"
fi

# RULE71:
sec_audit_assert_kmod_disabled 71 "atm kernel module" atm atm.ko* "atm"
# RULE72:
sec_audit_assert_kmod_disabled 72 "can kernel module" can can.ko* "can"
# RULE73:
sec_audit_assert_sysctl_equals 73 net.ipv4.conf.all.accept_source_route 0

# RULE74:
sec_audit_assert_sysctl_equals 74 net.ipv4.conf.all.accept_redirects 0

# RULE75:
sec_audit_assert_sysctl_equals 75 net.ipv4.conf.all.secure_redirects 0

# RULE76:
sec_audit_assert_sysctl_equals 76 net.ipv4.conf.all.log_martians 1

# RULE77:
sec_audit_assert_sysctl_equals 77 net.ipv4.icmp_echo_ignore_broadcasts 1

# RULE78:
sec_audit_assert_sysctl_equals 78 net.ipv4.icmp_ignore_bogus_error_responses 1

# RULE79:
sec_audit_assert_sysctl_equals 79 net.ipv4.conf.all.rp_filter 1

# RULE80:
sec_audit_assert_sysctl_equals 80 net.ipv4.tcp_syncookies 1

# RULE81:
sec_audit_assert_sysctl_equals 81 net.ipv6.conf.all.accept_ra 0

# RULE82:
if sec_audit_kmod_autoload_listed dccp; then
    sec_audit_report_fail 82 "dccp kernel module is listed in modules-load.d"
elif ! lsmod | grep -q dccp && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+dccp\b'; then
    sec_audit_report_pass 82 "DCCP is disabled"
else
    sec_audit_report_fail 82 "DCCP module is not blacklisted"
fi

# RULE83:
sec_audit_assert_kmod_disabled 83 "sctp kernel module" sctp sctp.ko* "sctp"
# RULE84:
if rpm -q iptables &>/dev/null; then
    sec_audit_report_pass 84 "iptables package is installed"
else
    sec_audit_report_fail 84 "iptables package is not installed"
fi

# RULE85:
if grep -Ps '^\h*max_log_file\h*=\h*[1-9][0-9]*\b' /etc/audit/auditd.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 85 "audit log storage size is configured"
else
    sec_audit_report_fail 85 "auditd max_log_file is not configured in /etc/audit/auditd.conf"
fi

# RULE86:
if grep -Ps '^\h*space_left_action\h*=\h*email\b' /etc/audit/auditd.conf 2>/dev/null | grep -q . && grep -Ps '^\h*admin_space_left_action\h*=\h*halt\b' /etc/audit/auditd.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 86 "system is disabled when audit logs are full"
else
    sec_audit_report_fail 86 "auditd space_left_action=email and admin_space_left_action=halt are not configured"
fi

# RULE87:
if grep -Ps '^\h*max_log_file_action\h*=\h*keep_logs\b' /etc/audit/auditd.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 87 "audit logs are not automatically deleted"
else
    sec_audit_report_fail 87 "auditd max_log_file_action is not set to keep_logs"
fi

# RULE88:
if systemctl is-enabled auditd.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active auditd.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_pass 88 "auditd service is enabled and running"
    else
        sec_audit_report_fail 88 "auditd service is enabled but not active"
    fi
else
    sec_audit_report_fail 88 "auditd service is not enabled"
fi

# RULE89:
if systemctl is-enabled rsyslog.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active rsyslog.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_pass 89 "rsyslog service is enabled and running"
    else
        sec_audit_report_fail 89 "rsyslog service is enabled but not active"
    fi
else
    sec_audit_report_fail 89 "rsyslog service is not enabled"
fi

# RULE90:
if grep -Ps '^\h*\$FileCreateMode\h+0[0-6][04][04]\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 90 "rsyslog default file permissions configured"
else
    sec_audit_report_fail 90 "rsyslog \$FileCreateMode is not configured"
fi

# RULE91:
if grep -Ps '^\h*([^#]\S+\.?\*\s+@@?\S+)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 91 "rsyslog is configured to send logs to a remote host"
else
    sec_audit_report_fail 91 "rsyslog is not configured to send logs to a remote host"
fi

# RULE92:
echo "RULE92= MANUAL: remote rsyslog acceptance requires manual review per site policy"

# RULE93:
if grep -Ps '^\h*(module|input)\h*\(load="imtcp"' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q . || grep -Ps '^\h*\$ModLoad\h+imtcp\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_fail 93 "rsyslog is configured to receive logs from remote clients (imtcp loaded)"
else
    sec_audit_report_pass 93 "rsyslog is not configured to receive logs from remote clients"
fi

# RULE94:
if systemctl is-active systemd-journald.service 2>/dev/null | grep -q '^active'; then
    sec_audit_report_pass 94 "journald service is active"
else
    sec_audit_report_fail 94 "systemd-journald service is not active"
fi

# RULE95:
if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -Psi '^\h*Storage\h*=\h*(persistent|auto)\b'; then
    sec_audit_report_pass 95 "journald Storage is configured"
else
    sec_audit_report_fail 95 "journald Storage is not set to persistent or auto"
fi

# RULE96:
if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -Psi '^\h*ForwardToSyslog\h*=\h*no\b'; then
    sec_audit_report_pass 96 "journald ForwardToSyslog is disabled"
else
    sec_audit_report_fail 96 "journald ForwardToSyslog is not set to no"
fi

# RULE97:
if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -Psi '^\h*Compress\h*=\h*yes\b'; then
    sec_audit_report_pass 97 "journald Compress is configured"
else
    sec_audit_report_fail 97 "journald Compress is not set to yes"
fi

# RULE98:
if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -Psi '^\h*(SystemMaxUse|SystemMaxFileSize|MaxFileSec)\h*=\h*\S+'; then
    sec_audit_report_pass 98 "journald log file rotation is configured"
else
    sec_audit_report_fail 98 "journald rotation settings are not configured"
fi

# RULE99:
LOGFILE_FAIL=0
while IFS= read -r f; do
    perm=$(stat -Lc '%a' "$f" 2>/dev/null)
    if echo "$perm" | grep -qE '^[0-7][0-7][1-7]$'; then
        LOGFILE_FAIL=1; break
    fi
done < <(find /var/log -type f 2>/dev/null)
if [ $LOGFILE_FAIL -eq 0 ]; then
    sec_audit_report_pass 99 "permissions on all logfiles are configured"
else
    sec_audit_report_fail 99 "one or more logfiles in /var/log have world-readable/writable permissions"
fi

# RULE100:
if [ -f /etc/logrotate.conf ] && grep -q "^rotate\|^daily\|^weekly\|^monthly" /etc/logrotate.conf 2>/dev/null; then
    sec_audit_report_pass 100 "logrotate is configured"
else
    sec_audit_report_fail 100 "logrotate is not properly configured"
fi

# RULE101:
if rpm -q rsyslog &>/dev/null; then
    sec_audit_report_pass 101 "rsyslog is installed"
else
    sec_audit_report_fail 101 "rsyslog package is not installed"
fi

if ! sec_audit_sshd_effective_usable; then
    for _sshn in 102 103 104 105 106 107 109 110 113 114 115 116 117 118 119 120 121 123 188 191 192 193 258 259 260 261 262; do
        sec_audit_report_fail "$_sshn" "unable_to_evaluate: sshd -T produced no effective configuration"
    done
else
# RULE102:
PUB_KEYS=$(sec_audit_sshd_effective_config | awk '$1=="hostkey" {print $2".pub"}')
FAIL102=0
for key in $PUB_KEYS; do
    if [ -f "$key" ]; then
        if ! stat -Lc '%a' "$key" 2>/dev/null | grep -qE '^[0-6]44$'; then
            FAIL102=1
        fi
        if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
            FAIL102=1
        fi
    else
        FAIL102=1
    fi
done
if [ $FAIL102 -eq 0 ]; then
    sec_audit_report_pass 102 "access to SSH public host key files is configured"
else
    sec_audit_report_fail 102 "File SSH public host key files permissions or ownership not correct"
fi

# RULE103:
if sec_audit_sshd_config_grep -Piq '^\h*(allow|deny)(users|groups)\h+\H+'; then
    sec_audit_report_pass 103 "sshd access is configured"
else
    sec_audit_report_fail 103 "sshd access controls (AllowUsers/DenyUsers/AllowGroups/DenyGroups) are not set as required"
fi

# RULE104:
if sec_audit_sshd_config_grep -Piq '^banner\h+\/\H+'; then
    sec_audit_report_pass 104 "sshd Banner is configured"
else
    sec_audit_report_fail 104 "sshd Banner does not meet the required policy (see sshd -T)"
fi

# RULE105:
if sec_audit_sshd_config_grep -Piq '^ciphers\h+\"?([^#\n\r]+,)?((3des|blowfish|cast128|aes(128|192|256))-cbc|arcfour(128|256)?|rijndael-cbc@lysator\.liu\.se)\b'; then
    sec_audit_report_fail 105 "sshd Ciphers allow weak or legacy algorithms (see sshd -T)"
else
    sec_audit_report_pass 105 "sshd Ciphers are configured"
fi

# RULE106:
if sec_audit_sshd_config_grep -Piq 'clientaliveinterval\s+([1-9]|[1-9][0-9]+)'; then
    if sec_audit_sshd_config_grep -Piq 'clientalivecountmax\s+([1-9]|[1-9][0-9]+)'; then
        sec_audit_report_pass 106 "sshd ClientAliveInterval and ClientAliveCountMax are configured"
    else
        sec_audit_report_fail 106 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
    fi
else
    sec_audit_report_fail 106 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
fi

# RULE107:
if sec_audit_sshd_config_grep -iq 'gssapiauthentication no'; then
    sec_audit_report_pass 107 "sshd GSSAPIAuthentication is disabled"
else
    sec_audit_report_fail 107 "sshd GSSAPIAuthentication is not disabled in effective sshd -T output"
fi

fi

# RULE108:
if rpm -q sudo &>/dev/null; then
    sec_audit_report_pass 108 "sudo is installed"
else
    sec_audit_report_fail 108 "sudo package is not installed"
fi

# RULE109:
if sec_audit_sshd_config_grep -Piq '^\h*(allowusers|allowgroups|denyusers|denygroups)\h+\S+' 2>/dev/null; then
    sec_audit_report_pass 109 "SSH access is configured (AllowUsers/AllowGroups/DenyUsers/DenyGroups found)"
else
    sec_audit_report_fail 109 "SSH access controls (AllowUsers/AllowGroups) are not configured"
fi

# RULE110:
if sec_audit_sshd_config_grep -Piq 'loglevel\h+(verbose|info)\b' 2>/dev/null; then
    sec_audit_report_pass 110 "SSH LogLevel is appropriate"
else
    sec_audit_report_fail 110 "SSH LogLevel is not set to VERBOSE or INFO"
fi

# RULE111:
TIMEOUT=$(sudo -V 2>/dev/null | grep "Authentication timestamp timeout:" | awk '{print $4}')
TIMEOUT_INT=${TIMEOUT%%.*}
if [ -n "$TIMEOUT_INT" ]; then
    if [ "$TIMEOUT_INT" -ge 0 ] && [ "$TIMEOUT_INT" -le 15 ]; then
        sec_audit_report_pass 111 "sudo timestamp_timeout is configured"
    else
        sec_audit_report_fail 111 "sudo timestamp_timeout is not set within the required range"
    fi
else
    sec_audit_report_pass 111 "sudo timestamp_timeout is configured"
fi

# RULE112:
if grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su 2>/dev/null; then
    GROUP=$(grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su 2>/dev/null | grep -oP 'group=\K\H+')
    if [ -n "$GROUP" ]; then
        if ! grep "^$GROUP:" /etc/group 2>/dev/null | grep -q ":$GROUP:x:"; then
            sec_audit_report_pass 112 "access to the su command is restricted"
        else
            sec_audit_report_fail 112 "su is not restricted to the wheel group in PAM configuration"
        fi
    else
        sec_audit_report_pass 112 "access to the su command is restricted"
    fi
else
    sec_audit_report_fail 112 "su is not restricted to the wheel group in PAM configuration"
fi

# RULE113:
if sec_audit_sshd_config_grep -iq 'ignorerhosts yes' 2>/dev/null; then
    sec_audit_report_pass 113 "SSH IgnoreRhosts is enabled"
else
    sec_audit_report_fail 113 "SSH IgnoreRhosts is not enabled"
fi

# RULE114:
if sec_audit_sshd_config_grep -iq 'hostbasedauthentication no' 2>/dev/null; then
    sec_audit_report_pass 114 "SSH HostbasedAuthentication is disabled"
else
    sec_audit_report_fail 114 "SSH HostbasedAuthentication is not disabled"
fi

# RULE115:
if sec_audit_sshd_config_grep -iq 'permitrootlogin no' 2>/dev/null; then
    sec_audit_report_pass 115 "SSH root login is disabled"
else
    sec_audit_report_fail 115 "SSH PermitRootLogin is not set to no"
fi

# RULE116:
if sec_audit_sshd_config_grep -iq 'permitemptypasswords no' 2>/dev/null; then
    sec_audit_report_pass 116 "SSH PermitEmptyPasswords is disabled"
else
    sec_audit_report_fail 116 "SSH PermitEmptyPasswords is not disabled"
fi

# RULE117:
if sec_audit_sshd_config_grep -iq 'permituserenvironment no' 2>/dev/null; then
    sec_audit_report_pass 117 "SSH PermitUserEnvironment is disabled"
else
    sec_audit_report_fail 117 "SSH PermitUserEnvironment is not disabled"
fi

# RULE118:
if sec_audit_sshd_config_grep -Piq 'macs\h+([^#\n\r]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b'; then
    sec_audit_report_fail 118 "sshd MACs allow weak or legacy algorithms"
else
    sec_audit_report_pass 118 "only strong MAC algorithms are used"
fi

# RULE119:
if sec_audit_sshd_config_grep -Piq 'clientaliveinterval\h+([1-9][0-9]{0,2}|[1-5][0-9]{3}|6000)\b' 2>/dev/null; then
    sec_audit_report_pass 119 "SSH Idle Timeout Interval (ClientAliveInterval) is configured"
else
    sec_audit_report_fail 119 "SSH ClientAliveInterval is not set within the required range"
fi

# RULE120:
if sec_audit_sshd_config_grep -Piq 'clientalivecountmax\h+[0-3]\b' 2>/dev/null; then
    sec_audit_report_pass 120 "SSH ClientAliveCountMax is configured"
else
    sec_audit_report_fail 120 "SSH ClientAliveCountMax is not set to 0-3"
fi

# RULE121:
if sec_audit_sshd_config_grep -Piq 'logingracetime\h+([1-5][0-9]|60|[1-9])\b' 2>/dev/null; then
    sec_audit_report_pass 121 "SSH LoginGraceTime is set to one minute or less"
else
    sec_audit_report_fail 121 "SSH LoginGraceTime is not set to 60 seconds or less"
fi

# RULE122:
if grep -r "^[^#].*NOPASSWD" /etc/sudoers* 2>/dev/null; then
    sec_audit_report_fail 122 "NOPASSWD or password-less sudo rules violate escalation policy"
else
    sec_audit_report_pass 122 "users must provide password for escalation"
fi

# RULE123:
if sec_audit_sshd_config_grep -Piq '^\h*banner\h+\S+' 2>/dev/null && ! sec_audit_sshd_config_grep -iq 'banner none' 2>/dev/null; then
    sec_audit_report_pass 123 "SSH warning banner is configured"
else
    sec_audit_report_fail 123 "SSH Banner is not configured"
fi

# RULE124:
if grep -Psi '^\h*minlen\h*=\h*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 124 "password creation requirements (minlen) are configured"
else
    sec_audit_report_fail 124 "pwquality minlen is not set to at least 14"
fi

# RULE125:
if grep -Psi '^\h*(minclass\h*=\h*[4-9]|[dulo]credit\h*=\h*-[1-9])' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 125 "password complexity is configured"
else
    sec_audit_report_fail 125 "pwquality complexity (minclass>=4 or credits) not configured adequately"
fi

# RULE126:
if grep -Psi '^\h*deny\h*=\h*[1-5]\b' /etc/security/faillock.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 126 "lockout for failed password attempts is configured"
else
    sec_audit_report_fail 126 "faillock deny threshold is not configured in /etc/security/faillock.conf"
fi

# RULE127:
if grep -Psi '^\h*unlock_time\h*=\h*(0|9[0-9][0-9]|[1-9][0-9]{3,})\b' /etc/security/faillock.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 127 "lockout unlock_time is configured"
else
    sec_audit_report_fail 127 "faillock unlock_time is not set within the required range"
fi

# RULE128:
if grep -Psi '^\h*remember\h*=\h*(2[4-9]|[3-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwhistory.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 128 "password reuse is limited"
else
    sec_audit_report_fail 128 "pwhistory remember is not set to 24 or more in /etc/security/pwhistory.conf"
fi

# RULE129:
if grep -Psi '^\h*PASS_MAX_DAYS\h+(36[0-5]|3[0-5][0-9]|[1-2][0-9][0-9]|[1-9][0-9]|[1-9])\b' /etc/login.defs 2>/dev/null; then
    if ! awk -F: '($2~/^\$.+\$/) {if($5 > 365 || $5 < 1)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 129 "password expiration is configured"
    else
        sec_audit_report_fail 129 "PASS_MAX_DAYS or per-user shadow MAX exceeds policy or is unset"
    fi
else
    sec_audit_report_fail 129 "PASS_MAX_DAYS or per-user shadow MAX exceeds policy or is unset"
fi

# RULE130:
if grep -q "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null; then
    MIN_DAYS=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [ "$MIN_DAYS" -ge 7 ] 2>/dev/null; then
        sec_audit_report_pass 130 "Minimum password days is configured"
    else
        sec_audit_report_fail 130 "Minimum password days is too low (recommended 7+)"
    fi
else
    sec_audit_report_fail 130 "Minimum password days is not configured"
fi

# RULE131:
if grep -Psi '^\h*PASS_WARN_AGE\h+([7-9]|[1-9][0-9]+)\b' /etc/login.defs 2>/dev/null; then
    if ! awk -F: '($2~/^\$.+\$/) {if($6 < 7)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 131 "password expiration warning days is configured"
    else
        sec_audit_report_fail 131 "PASS_WARN_AGE is not set within policy in /etc/login.defs"
    fi
else
    sec_audit_report_fail 131 "PASS_WARN_AGE is not set within policy in /etc/login.defs"
fi

# RULE132:
if grep -Psi '^\h*ENCRYPT_METHOD\h+(SHA512|YESCRYPT)\b' /etc/login.defs 2>/dev/null; then
    sec_audit_report_pass 132 "strong password hashing algorithm is configured"
else
    sec_audit_report_fail 132 "ENCRYPT_METHOD in /etc/login.defs does not use a strong hashing algorithm"
fi

# RULE133:
if useradd -D 2>/dev/null | grep INACTIVE | cut -d= -f2 | grep -qE '^([1-9]|[1-4][0-9]|45)$'; then
    if ! awk -F: '($2~/^\$.+\$/) {if($7 > 45 || $7 < 0)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 133 "inactive password lock is configured"
    else
        sec_audit_report_fail 133 "useradd INACTIVE or inactive lock policy is not configured"
    fi
else
    sec_audit_report_fail 133 "useradd INACTIVE or inactive lock policy is not configured"
fi

# RULE134:
if useradd -D 2>/dev/null | grep INACTIVE | cut -d= -f2 | grep -qE '^([1-9]|[1-4][0-9]|45)$'; then
    if ! awk -F: '($2~/^\$.+\$/) {if($7 > 45 || $7 < 0)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 134 "inactive password lock is configured"
    else
        sec_audit_report_fail 134 "useradd INACTIVE or inactive lock policy is not configured"
    fi
else
    sec_audit_report_fail 134 "useradd INACTIVE or inactive lock policy is not configured"
fi

# RULE135:
FAIL135=0
while IFS=: read -r user pass last_change rest; do
    if [ -n "$last_change" ] && [ "$last_change" -gt 0 ] 2>/dev/null; then
        current_date=$(date +%s)
        last_change_seconds=$((last_change * 86400))
        if [ "$last_change_seconds" -gt "$current_date" ]; then
            sec_audit_report_fail 135 "User $user has password change date in the future"
            FAIL135=1
        fi
    fi
done < /etc/shadow 2>/dev/null
if [ $FAIL135 -eq 0 ]; then
    sec_audit_report_pass 135 "All users last password change date is in the past"
fi

# RULE136:
if grep -P '^root:' /etc/passwd 2>/dev/null | awk -F: '{print $4}' | grep -q '^0$'; then
    sec_audit_report_pass 136 "default group for the root account is GID 0"
else
    sec_audit_report_fail 136 "root account GID is not 0"
fi

# RULE137:
if grep -Psi '^\h*umask\h+(0?27|0?077)\b' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null | grep -q . || grep -Psi '^\h*UMASK\h+(0?27|0?077)\b' /etc/login.defs 2>/dev/null | grep -q .; then
    sec_audit_report_pass 137 "default user umask is configured"
else
    sec_audit_report_fail 137 "default user umask (027 or stricter) is not configured"
fi

# RULE138:
if grep -Psi '^\h*TMOUT\h*=\h*(9[0-9][0-9]|[1-8][0-9]{2}|[1-9][0-9]|[1-9])\b' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null | grep -q .; then
    sec_audit_report_pass 138 "default user shell timeout is configured"
else
    sec_audit_report_fail 138 "TMOUT (shell timeout) is not configured in profile files"
fi

# RULE139:
if grep -Ers '^([^#]+\s+)?(\/usr\/s?bin\/|^\s*)aide(\.wrapper)?\s(--?\S+\s)*(-(check|update)|\$AIDEARGS)\b' /etc/cron.* /etc/crontab /var/spool/cron/ /etc/cron.d 2>/dev/null; then
    sec_audit_report_pass 139 "filesystem integrity is regularly checked (cron/cron.d entry references aide)"
elif systemctl is-enabled aidecheck.timer 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active aidecheck.timer 2>/dev/null | grep -q 'active'; then
        _a208_n=$(systemctl show aidecheck.timer -p NextElapseUSRealtime 2>/dev/null | cut -d= -f2-)
        sec_audit_report_pass 139 "aidecheck.timer enabled and active (next: ${_a208_n:-unknown})"
    else
        sec_audit_report_fail 139 "aidecheck.timer enabled but not active"
    fi
else
    sec_audit_report_fail 139 "filesystem integrity is regularly checked"
fi

# RULE140:
if grep -Ers '^([^#]+\s+)?(\/usr\/s?bin\/|^\s*)aide(\.wrapper)?\s(--?\S+\s)*(-(check|update)|\$AIDEARGS)\b' /etc/cron.* /etc/crontab /var/spool/cron/ /etc/cron.d 2>/dev/null; then
    sec_audit_report_pass 140 "filesystem integrity is regularly checked (cron/cron.d entry references aide)"
elif systemctl is-enabled aidecheck.timer 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active aidecheck.timer 2>/dev/null | grep -q 'active'; then
        _a208_n=$(systemctl show aidecheck.timer -p NextElapseUSRealtime 2>/dev/null | cut -d= -f2-)
        sec_audit_report_pass 140 "aidecheck.timer enabled and active (next: ${_a208_n:-unknown})"
    else
        sec_audit_report_fail 140 "aidecheck.timer enabled but not active"
    fi
else
    sec_audit_report_fail 140 "filesystem integrity is regularly checked"
fi

# RULE141:
if grep -Ers '^([^#]+\s+)?(\/usr\/s?bin\/|^\s*)aide(\.wrapper)?\s(--?\S+\s)*(-(check|update)|\$AIDEARGS)\b' /etc/cron.* /etc/crontab /var/spool/cron/ /etc/cron.d 2>/dev/null; then
    sec_audit_report_pass 141 "filesystem integrity is regularly checked (cron/cron.d entry references aide)"
elif systemctl is-enabled aidecheck.timer 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active aidecheck.timer 2>/dev/null | grep -q 'active'; then
        _a208_n=$(systemctl show aidecheck.timer -p NextElapseUSRealtime 2>/dev/null | cut -d= -f2-)
        sec_audit_report_pass 141 "aidecheck.timer enabled and active (next: ${_a208_n:-unknown})"
    else
        sec_audit_report_fail 141 "aidecheck.timer enabled but not active"
    fi
else
    sec_audit_report_fail 141 "filesystem integrity is regularly checked"
fi

# RULE142:
if stat -Lc '%a' /etc/shadow 2>/dev/null | grep -qE '^[0-6][04]0$'; then
    sec_audit_report_pass 142 "permissions on /etc/shadow are configured"
else
    sec_audit_report_fail 142 "/etc/shadow has incorrect permissions"
fi

# RULE143:
if stat -Lc '%U' /etc/shadow 2>/dev/null | grep -q '^root$'; then
    sec_audit_report_pass 143 "/etc/shadow is owned by root"
else
    sec_audit_report_fail 143 "/etc/shadow is not owned by root"
fi

# RULE144:
if stat -Lc '%G' /etc/shadow 2>/dev/null | grep -qE '^(root|shadow)$'; then
    sec_audit_report_pass 144 "/etc/shadow group ownership is correct"
else
    sec_audit_report_fail 144 "/etc/shadow is not group owned by root or shadow"
fi

# RULE145:
if stat -Lc '%a' /etc/group 2>/dev/null | grep -qE '^[0-6]44$'; then
    sec_audit_report_pass 145 "permissions on /etc/group are configured"
else
    sec_audit_report_fail 145 "/etc/group has incorrect permissions"
fi

# RULE146:
if stat -Lc '%U' /etc/group 2>/dev/null | grep -q '^root$'; then
    sec_audit_report_pass 146 "/etc/group is owned by root"
else
    sec_audit_report_fail 146 "/etc/group is not owned by root"
fi

# RULE147:
if stat -Lc '%G' /etc/group 2>/dev/null | grep -q '^root$'; then
    sec_audit_report_pass 147 "/etc/group group ownership is correct"
else
    sec_audit_report_fail 147 "/etc/group is not group owned by root"
fi

# RULE148:
if [ -e /etc/passwd- ]; then
    if stat -Lc '%a' /etc/passwd- 2>/dev/null | grep -qE '^[0-6]44$'; then
        sec_audit_report_pass 148 "permissions on /etc/passwd- are configured"
    else
        sec_audit_report_fail 148 "/etc/passwd- has incorrect permissions"
    fi
else
    sec_audit_report_pass 148 "/etc/passwd- does not exist"
fi

# RULE149:
if [ -e /etc/passwd- ]; then
    if stat -Lc '%U' /etc/passwd- 2>/dev/null | grep -q '^root$'; then
        sec_audit_report_pass 149 "/etc/passwd- is owned by root"
    else
        sec_audit_report_fail 149 "/etc/passwd- is not owned by root"
    fi
else
    sec_audit_report_pass 149 "/etc/passwd- does not exist"
fi

# RULE150:
if [ -e /etc/passwd- ]; then
    if stat -Lc '%G' /etc/passwd- 2>/dev/null | grep -q '^root$'; then
        sec_audit_report_pass 150 "/etc/passwd- group ownership is correct"
    else
        sec_audit_report_fail 150 "/etc/passwd- is not group owned by root"
    fi
else
    sec_audit_report_pass 150 "/etc/passwd- does not exist"
fi

# RULE151:
if [ -e /etc/shadow- ]; then
    if stat -Lc '%a' /etc/shadow- 2>/dev/null | grep -qE '^[0-6][04]0$'; then
        sec_audit_report_pass 151 "permissions on /etc/shadow- are configured"
    else
        sec_audit_report_fail 151 "/etc/shadow- has incorrect permissions"
    fi
else
    sec_audit_report_pass 151 "/etc/shadow- does not exist"
fi

# RULE152:
if [ -e /etc/shadow- ]; then
    if stat -Lc '%U' /etc/shadow- 2>/dev/null | grep -q '^root$'; then
        sec_audit_report_pass 152 "/etc/shadow- is owned by root"
    else
        sec_audit_report_fail 152 "/etc/shadow- is not owned by root"
    fi
else
    sec_audit_report_pass 152 "/etc/shadow- does not exist"
fi

# RULE153:
if [ -e /etc/shadow- ]; then
    if stat -Lc '%G' /etc/shadow- 2>/dev/null | grep -qE '^(root|shadow)$'; then
        sec_audit_report_pass 153 "/etc/shadow- group ownership is correct"
    else
        sec_audit_report_fail 153 "/etc/shadow- is not group owned by root or shadow"
    fi
else
    sec_audit_report_pass 153 "/etc/shadow- does not exist"
fi

# RULE154:
if [ -e /etc/group- ]; then
    if stat -Lc '%a' /etc/group- 2>/dev/null | grep -qE '^[0-6]44$'; then
        sec_audit_report_pass 154 "permissions on /etc/group- are configured"
    else
        sec_audit_report_fail 154 "/etc/group- has incorrect permissions"
    fi
else
    sec_audit_report_pass 154 "/etc/group- does not exist"
fi

# RULE155:
if [ -e /etc/group- ]; then
    if stat -Lc '%U' /etc/group- 2>/dev/null | grep -q '^root$'; then
        sec_audit_report_pass 155 "/etc/group- is owned by root"
    else
        sec_audit_report_fail 155 "/etc/group- is not owned by root"
    fi
else
    sec_audit_report_pass 155 "/etc/group- does not exist"
fi

# RULE156:
if [ -e /etc/group- ]; then
    if stat -Lc '%G' /etc/group- 2>/dev/null | grep -q '^root$'; then
        sec_audit_report_pass 156 "/etc/group- group ownership is correct"
    else
        sec_audit_report_fail 156 "/etc/group- is not group owned by root"
    fi
else
    sec_audit_report_pass 156 "/etc/group- does not exist"
fi

# RULE157:
CRITICAL_PATHS="/bin /sbin /usr/bin /usr/sbin /etc /var /home"
if sec_audit_find_hit_timeout sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print; then
    sec_audit_report_fail 157 "incomplete_scan: world-writable file search timed out under critical paths"
elif sec_audit_find_hit_timeout sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print; then
    sec_audit_report_fail 157 "incomplete_scan: world-writable directory search timed out under critical paths"
else
    WW_FILES=$(sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print 2>/dev/null | wc -l)
    WW_DIRS=$(sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print 2>/dev/null | wc -l)
    if [ "$WW_FILES" -eq 0 ] && [ "$WW_DIRS" -eq 0 ]; then
        sec_audit_report_pass 157 "No critical world writable files or directories found"
    else
        sec_audit_report_fail 157 "Found potential world-writable items ($WW_FILES files, $WW_DIRS dirs)"
    fi
fi
# RULE158:
UNOWNED=$(sec_audit_soft_find --timeout=60 / -xdev -ignore_readdir_race -nouser -type f -print 2>/dev/null | wc -l)
if [ "${UNOWNED:-0}" -eq 0 ]; then
    sec_audit_report_pass 158 "no unowned files or directories exist"
else
    sec_audit_report_fail 158 "$UNOWNED file(s) found without a valid owner"
fi

# RULE159:
UNGROUP=$(sec_audit_soft_find --timeout=60 / -xdev -ignore_readdir_race -nogroup -type f -print 2>/dev/null | wc -l)
if [ "${UNGROUP:-0}" -eq 0 ]; then
    sec_audit_report_pass 159 "no ungrouped files or directories exist"
else
    sec_audit_report_fail 159 "$UNGROUP file(s) found without a valid group"
fi

# RULE160:
SUID_COUNT=$(sec_audit_soft_find --timeout=30 / -xdev -ignore_readdir_race -type f -perm -4000 2>/dev/null | wc -l)
sec_audit_report_pass 160 "SUID executables count = $SUID_COUNT (manual audit required)"
# RULE161:
SGID_COUNT=$(sec_audit_soft_find --timeout=30 / -xdev -ignore_readdir_race -type f -perm -2000 2>/dev/null | wc -l)
sec_audit_report_pass 161 "SGID executables count = $SGID_COUNT (manual audit required)"
# RULE162:
if awk -F: '($2 == "" ) { print }' /etc/shadow 2>/dev/null | grep -q .; then
    sec_audit_report_fail 162 "empty password hash found in /etc/shadow"
else
    sec_audit_report_pass 162 "/etc/shadow password fields are not empty"
fi

# RULE163:
if awk -F: '($3 == 0) { print $1 }' /etc/passwd 2>/dev/null | grep -qv '^root$'; then
    sec_audit_report_fail 163 "non-root account with UID 0 found"
else
    sec_audit_report_pass 163 "root is the only UID 0 account"
fi

# RULE164:
FAIL164=0
for dir in $(echo "$PATH" | tr ':' ' '); do
    if [ "$dir" = "" ] || [ "$dir" = "." ]; then FAIL164=1; break; fi
    if [ ! -d "$dir" ]; then continue; fi
    if stat -Lc '%U' "$dir" 2>/dev/null | grep -qv '^root$'; then FAIL164=1; break; fi
done
if [ $FAIL164 -eq 0 ]; then
    sec_audit_report_pass 164 "root PATH integrity verified"
else
    sec_audit_report_fail 164 "root PATH contains unsafe directory (empty, '.', or non-root owned)"
fi

# RULE165:
FAIL165=0
while IFS=: read -r user pass uid gid gecos home shell; do
    if [ -f "$home/.forward" ]; then FAIL165=1; break; fi
done < /etc/passwd 2>/dev/null
if [ $FAIL165 -eq 0 ]; then
    sec_audit_report_pass 165 "no users have .forward files"
else
    sec_audit_report_fail 165 "one or more users have .forward files"
fi

# RULE166:
if findmnt -n /dev/shm 2>/dev/null | grep -q '/dev/shm'; then
    sec_audit_report_pass 166 "/dev/shm is configured as a separate mount"
else
    sec_audit_report_fail 166 "/dev/shm is not configured as a separate mount"
fi

# RULE167:
if rpm -q sudo &>/dev/null; then
    sec_audit_report_pass 167 "sudo is installed"
else
    sec_audit_report_fail 167 "sudo package is not installed"
fi

# RULE168:
if grep -rPsi '^\h*Defaults\h+([^#\n\r]+,\h*)?use_pty\b' /etc/sudoers* 2>/dev/null | grep -q .; then
    sec_audit_report_pass 168 "sudo commands use pty"
else
    sec_audit_report_fail 168 "sudo Defaults use_pty is not configured"
fi

# RULE169:
if grep -rPsi '^\h*Defaults\h+([^#\n\r]+,\h*)?logfile\h*=\h*\S+' /etc/sudoers* 2>/dev/null | grep -q .; then
    sec_audit_report_pass 169 "sudo log file exists"
else
    sec_audit_report_fail 169 "sudo Defaults logfile is not configured"
fi

# RULE170:
if rpm -q apparmor-utils &>/dev/null || rpm -q apparmor-parser &>/dev/null; then
    sec_audit_report_pass 170 "AppArmor is installed"
else
    sec_audit_report_fail 170 "AppArmor packages are not installed"
fi

# RULE171:
if ! rpm -q gdm &>/dev/null; then
    sec_audit_report_pass 171 "GDM is not installed"
elif grep -Psi '^\h*TimedLoginEnable\h*=\h*false\b' /etc/gdm/custom.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 171 "GDM is configured (TimedLoginEnable=false)"
else
    sec_audit_report_fail 171 "GDM is installed but login banner or auto-login policy is not configured"
fi

# RULE172:
if rpm -q rsync &>/dev/null || dpkg -s rsync &>/dev/null; then
    sec_audit_report_fail 172 "package rsync is installed"
else
    sec_audit_report_pass 172 "package rsync is not installed"
fi

# RULE173:
if rpm -q audit &>/dev/null; then
    sec_audit_report_pass 173 "auditd is installed"
else
    sec_audit_report_fail 173 "audit package is not installed"
fi

# RULE174:
if grep -Pi '^\h*linux\b' /boot/grub2/grub.cfg 2>/dev/null | grep -q 'audit=1\b'; then
    sec_audit_report_pass 174 "auditing for processes that start prior to auditd is enabled"
else
    sec_audit_report_fail 174 "audit=1 is not set in grub kernel boot parameters"
fi

# RULE175:
if grep -Pi '^\h*linux\b' /boot/grub2/grub.cfg 2>/dev/null | grep -Pq 'audit_backlog_limit=[1-9][0-9]{3,}'; then
    sec_audit_report_pass 175 "audit_backlog_limit is sufficient"
else
    sec_audit_report_fail 175 "audit_backlog_limit is not set in grub boot parameters (recommend 8192 or higher)"
fi

# RULE176:
if systemctl is-enabled firewalld.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active firewalld.service 2>/dev/null | grep -q 'active'; then
        _fw141_nft=""
        if sec_audit_have_bin nft && nft list ruleset 2>/dev/null | grep -q .; then
            _fw141_nft="; nftables ruleset is non-empty"
        fi
        sec_audit_report_pass 176 "firewalld.service is enabled and active${_fw141_nft}"
    else
        sec_audit_report_fail 176 "firewalld.service is not enabled or not active"
    fi
else
    sec_audit_report_fail 176 "firewalld.service is not enabled or not active"
fi

# RULE177:
if systemctl is-active firewalld &>/dev/null; then
    ACTIVE_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null)
    ZONE_TARGET=$(firewall-cmd --zone="$ACTIVE_ZONE" --get-target 2>/dev/null)
    _fw142_if=$(firewall-cmd --zone="$ACTIVE_ZONE" --list-interfaces 2>/dev/null | wc -w)
    if [ "$ZONE_TARGET" = "DROP" ] || [ "$ZONE_TARGET" = "REJECT" ]; then
        sec_audit_report_pass 177 "firewalld default zone '$ACTIVE_ZONE' target is $ZONE_TARGET (${_fw142_if:-0} interface(s) assigned)"
    else
        sec_audit_report_fail 177 "firewalld active zone target is not secure (current: $ZONE_TARGET)"
    fi
else
    sec_audit_report_fail 177 "firewalld is not active"
fi

# RULE178:
if systemctl is-active firewalld &>/dev/null; then
    SERVICES=$(firewall-cmd --list-services 2>/dev/null | wc -w)
    PORTS=$(firewall-cmd --list-ports 2>/dev/null | wc -w)
    SERVICES_P=$(firewall-cmd --permanent --list-services 2>/dev/null | wc -w)
    PORTS_P=$(firewall-cmd --permanent --list-ports 2>/dev/null | wc -w)
    if [ "$SERVICES" -gt 0 ] || [ "$PORTS" -gt 0 ]; then
        sec_audit_report_pass 178 "firewalld exposes $SERVICES service(s) and $PORTS port(s) at runtime (permanent: $SERVICES_P / $PORTS_P)"
    elif [ "$SERVICES_P" -gt 0 ] || [ "$PORTS_P" -gt 0 ]; then
        sec_audit_report_fail 178 "permanent firewalld rules exist ($SERVICES_P services, $PORTS_P ports) but runtime lists none — run firewall-cmd --reload"
    else
        sec_audit_report_fail 178 "firewalld services and ports are not configured"
    fi
else
    sec_audit_report_fail 178 "firewalld is not active"
fi

# RULE179:
if auditctl -l 2>/dev/null | grep -q 'session\|logins' || grep -r 'session\|logins' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
    sec_audit_report_pass 179 "session initiation information is collected"
else
    sec_audit_report_fail 179 "auditd rules for session initiation are not configured"
fi

# RULE180:
if auditctl -l 2>/dev/null | grep -Pq 'chmod|chown|setxattr' || grep -r 'perm_mod\|chmod\|chown' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -qP '\-a.*always\b|\-a.*exit\b'; then
    sec_audit_report_pass 180 "DAC permission modification events are collected"
else
    sec_audit_report_fail 180 "auditd rules for DAC permission modification events are not configured"
fi

# RULE181:
PRIV_CMD_FAIL=0
for cmd in $(find /usr/bin /usr/sbin /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null); do
    if ! auditctl -l 2>/dev/null | grep -q "$cmd" && ! grep -r "$cmd" /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-a'; then
        PRIV_CMD_FAIL=1; break
    fi
done
if [ $PRIV_CMD_FAIL -eq 0 ]; then
    sec_audit_report_pass 181 "use of privileged commands is collected"
else
    sec_audit_report_fail 181 "not all setuid/setgid commands are monitored by auditd"
fi

# RULE182:
if auditctl -l 2>/dev/null | grep -q 'delete\|unlink' || grep -r 'delete\|unlink' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -qP '\-a.*always\b|\-a.*exit\b'; then
    sec_audit_report_pass 182 "file deletion events by users are collected"
else
    sec_audit_report_fail 182 "auditd rules for file deletion events are not configured"
fi

# RULE183:
if auditctl -l 2>/dev/null | grep -q '/etc/sudoers' || grep -r 'sudoers' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
    sec_audit_report_pass 183 "changes to system administration scope (sudoers) is collected"
else
    sec_audit_report_fail 183 "auditd watch rules for /etc/sudoers are not configured"
fi

# RULE184:
if auditctl -l 2>/dev/null | grep -q 'actions\|sudolog' || grep -r 'actions\|sudolog' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
    sec_audit_report_pass 184 "system administrator actions (sudolog) are collected"
else
    sec_audit_report_fail 184 "auditd watch rules for sudo log are not configured"
fi

# RULE185:
if rpm -q rsyslog &>/dev/null; then
    sec_audit_report_pass 185 "rsyslog is installed"
else
    sec_audit_report_fail 185 "rsyslog package is not installed"
fi

# RULE186:
LOGFILE_FAIL186=0
while IFS= read -r f; do
    perm=$(stat -Lc '%a' "$f" 2>/dev/null)
    if echo "$perm" | grep -qE '^[0-7][0-7][1-7]$'; then LOGFILE_FAIL186=1; break; fi
done < <(find /var/log -type f 2>/dev/null)
if [ $LOGFILE_FAIL186 -eq 0 ]; then
    sec_audit_report_pass 186 "permissions on all logfiles are configured"
else
    sec_audit_report_fail 186 "one or more logfiles in /var/log have world-readable/writable permissions"
fi

# RULE187:
if stat -Lc '%a' /etc/ssh/sshd_config 2>/dev/null | grep -q '^600$'; then
    if stat -Lc '%U:%G' /etc/ssh/sshd_config 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 187 "access to /etc/ssh/sshd_config is configured"
    else
        sec_audit_report_fail 187 "File /etc/ssh/sshd_config permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 187 "File /etc/ssh/sshd_config permissions or ownership not correct"
fi

# RULE188:
PRIV_KEYS=$(sec_audit_sshd_effective_config | awk '$1=="hostkey" {print $2}')
FAIL188=0
for key in $PRIV_KEYS; do
    if [ -f "$key" ]; then
        if ! stat -Lc '%a' "$key" 2>/dev/null | grep -q '^600$'; then
            FAIL188=1
        fi
        if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
            FAIL188=1
        fi
    else
        FAIL188=1
    fi
done
if [ $FAIL188 -eq 0 ]; then
    sec_audit_report_pass 188 "access to SSH private host key files is configured"
else
    sec_audit_report_fail 188 "File SSH private host key files permissions or ownership not correct"
fi

# RULE189:
if grep -rPi '^\h*Defaults\h+([^#\n\r]+,\h*)?use_pty\b' /etc/sudoers* 2>/dev/null; then
    if ! grep -rPi '^\h*Defaults\h+([^#\n\r]+,\h*)?!use_pty\b' /etc/sudoers* 2>/dev/null; then
        sec_audit_report_pass 189 "sudo commands use pty"
    else
        sec_audit_report_fail 189 "sudo is not configured to require a pseudo-terminal (use_pty)"
    fi
else
    sec_audit_report_fail 189 "sudo is not configured to require a pseudo-terminal (use_pty)"
fi

# RULE190:
if grep -rPsi "^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|\')?\H+(\"|\')?(,\h*\H+\h*)*\h*(#.*)?$" /etc/sudoers* 2>/dev/null; then
    sec_audit_report_pass 190 "sudo log file exists"
else
    sec_audit_report_fail 190 "sudo log file is missing or not configured"
fi

# RULE191:
if sec_audit_sshd_config_grep -Piq 'ciphers\h+([^#\n\r]+,)?(3des-cbc|aes128-cbc|aes192-cbc|aes256-cbc|arcfour|arcfour128|arcfour256|blowfish-cbc|cast128-cbc|rijndael-cbc@lysator\.liu\.se)\b'; then
    sec_audit_report_fail 191 "sshd Ciphers include weak algorithms"
else
    sec_audit_report_pass 191 "only strong Ciphers are used"
fi

# RULE192:
if sec_audit_sshd_config_grep -Piq 'kexalgorithms\h+([^#\n\r]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b'; then
    sec_audit_report_fail 192 "sshd KexAlgorithms include weak algorithms"
else
    sec_audit_report_pass 192 "only strong Key Exchange algorithms are used"
fi

# RULE193:
if sec_audit_sshd_config_grep -iq 'usepam yes' 2>/dev/null; then
    sec_audit_report_pass 193 "SSH PAM is enabled"
else
    sec_audit_report_fail 193 "SSH UsePAM is not enabled"
fi

# RULE194:
FAIL194=0
while IFS=: read -r user pass uid gid gecos home shell; do
    if [ "${uid:-0}" -lt 1000 ] && [ "${uid:-0}" -ne 0 ]; then
        if [ "$shell" != "/sbin/nologin" ] && [ "$shell" != "/usr/sbin/nologin" ] && [ "$shell" != "/bin/false" ]; then
            FAIL194=1; break
        fi
    fi
done < /etc/passwd 2>/dev/null
if [ $FAIL194 -eq 0 ]; then
    sec_audit_report_pass 194 "system accounts are secured"
else
    sec_audit_report_fail 194 "one or more system accounts have an interactive shell"
fi

# RULE195:
if grep -Psi '^\h*auth\h+required\h+pam_wheel\.so\b' /etc/pam.d/su 2>/dev/null | grep -q .; then
    sec_audit_report_pass 195 "access to the su command is restricted via pam_wheel"
else
    sec_audit_report_fail 195 "pam_wheel is not required in /etc/pam.d/su"
fi

# RULE196:
if awk -F: '($2 != "x" ) { print }' /etc/passwd 2>/dev/null | grep -q .; then
    sec_audit_report_fail 196 "non-shadow password field found in /etc/passwd"
else
    sec_audit_report_pass 196 "accounts in /etc/passwd use shadowed passwords"
fi

# RULE197:
FAIL197=0
for dir in $(echo "$PATH" | tr ':' ' '); do
    if [ "$dir" = "" ] || [ "$dir" = "." ]; then FAIL197=1; break; fi
    if [ ! -d "$dir" ]; then continue; fi
    if stat -Lc '%U' "$dir" 2>/dev/null | grep -qv '^root$'; then FAIL197=1; break; fi
done
if [ $FAIL197 -eq 0 ]; then
    sec_audit_report_pass 197 "root PATH integrity verified"
else
    sec_audit_report_fail 197 "root PATH contains unsafe directory"
fi

# RULE198:
FAIL198=0
while IFS=: read -r user pass uid gid gecos home shell; do
    [ "${uid:-0}" -lt 1000 ] 2>/dev/null && continue
    [ "${uid:-0}" -ge 65534 ] 2>/dev/null && continue
    case "$shell" in /sbin/nologin|/usr/sbin/nologin|/bin/false) continue ;; esac
    if [ -d "$home" ]; then
        OWNER=$(stat -Lc '%U' "$home" 2>/dev/null)
        if [ "$OWNER" != "$user" ]; then FAIL198=1; break; fi
    fi
done < /etc/passwd 2>/dev/null
if [ $FAIL198 -eq 0 ]; then
    sec_audit_report_pass 198 "users own their home directories"
else
    sec_audit_report_fail 198 "one or more home directories are not owned by the user"
fi

# RULE199:
FAIL199=0
while IFS=: read -r user pass uid gid gecos home shell; do
    [ "${uid:-0}" -lt 1000 ] 2>/dev/null && continue
    [ "${uid:-0}" -ge 65534 ] 2>/dev/null && continue
    for dotfile in "$home"/.[!.]*; do
        if [ -f "$dotfile" ]; then
            perm=$(stat -Lc '%a' "$dotfile" 2>/dev/null)
            if echo "$perm" | grep -qE '.[2-7].|..[2-7]'; then FAIL199=1; break 2; fi
        fi
    done
done < /etc/passwd 2>/dev/null
if [ $FAIL199 -eq 0 ]; then
    sec_audit_report_pass 199 "users' dot files are not group or world writable"
else
    sec_audit_report_fail 199 "one or more dot files are group or world writable"
fi

# RULE200:
FAIL200=0
while IFS=: read -r user pass uid gid gecos home shell; do
    [ "${uid:-0}" -lt 1000 ] 2>/dev/null && continue
    if [ -f "$home/.netrc" ]; then
        perm=$(stat -Lc '%a' "$home/.netrc" 2>/dev/null)
        if echo "$perm" | grep -qE '.[1-7].|..[1-7]'; then FAIL200=1; break; fi
    fi
done < /etc/passwd 2>/dev/null
if [ $FAIL200 -eq 0 ]; then
    sec_audit_report_pass 200 "users' .netrc files are not group or world accessible"
else
    sec_audit_report_fail 200 "one or more .netrc files are group or world accessible"
fi

# RULE201:
FAIL201=0
while IFS=: read -r user pass uid gid rest; do
    if ! grep -q "^[^:]*:[^:]*:$gid:" /etc/group 2>/dev/null; then
        FAIL201=1; break
    fi
done < /etc/passwd 2>/dev/null
if [ $FAIL201 -eq 0 ]; then
    sec_audit_report_pass 201 "all groups in /etc/passwd exist in /etc/group"
else
    sec_audit_report_fail 201 "one or more GIDs in /etc/passwd do not exist in /etc/group"
fi

# RULE202:
if cut -f3 -d":" /etc/passwd 2>/dev/null | sort -n | uniq -c | while read -r count uid; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 202 "duplicate UID entries exist in /etc/passwd"
else
    sec_audit_report_pass 202 "no duplicate UIDs exist"
fi

# RULE203:
if cut -f3 -d":" /etc/group 2>/dev/null | sort -n | uniq -c | while read -r count gid; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 203 "duplicate GID entries exist in /etc/group"
else
    sec_audit_report_pass 203 "no duplicate GIDs exist"
fi

# RULE204:
if cut -f1 -d":" /etc/passwd 2>/dev/null | sort | uniq -c | while read -r count user; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 204 "duplicate user names exist in /etc/passwd"
else
    sec_audit_report_pass 204 "no duplicate user names exist"
fi

# RULE205:
if cut -f1 -d":" /etc/group 2>/dev/null | sort | uniq -c | while read -r count group; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 205 "duplicate group names exist in /etc/group"
else
    sec_audit_report_pass 205 "no duplicate group names exist"
fi

# RULE206:
if awk -F: '($1=="shadow") {print $4}' /etc/group 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 206 "shadow group is not empty"
else
    sec_audit_report_pass 206 "shadow group is empty"
fi

# RULE207:
sec_audit_assert_kmod_disabled 207 "cramfs kernel module" cramfs cramfs.ko* "cramfs"
# RULE208:
if sec_audit_kmod_autoload_listed freevxfs; then
    sec_audit_report_fail 208 "freevxfs kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_soft_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "freevxfs.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 208 "freevxfs kernel module is not available"
else
    if ! lsmod | grep -q freevxfs && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+freevxfs\b'; then
        sec_audit_report_pass 208 "freevxfs kernel module is not available"
    else
        sec_audit_report_fail 208 "freevxfs kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

# RULE209:
if sec_audit_kmod_autoload_listed hfs; then
    sec_audit_report_fail 209 "hfs kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_soft_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "hfs.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 209 "hfs kernel module is not available"
else
    if ! lsmod | grep -q hfs && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+hfs\b'; then
        sec_audit_report_pass 209 "hfs kernel module is not available"
    else
        sec_audit_report_fail 209 "hfs kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

# RULE210:
sec_audit_assert_kmod_disabled 210 "hfsplus kernel module" hfsplus hfsplus.ko* "hfsplus"
# RULE211:
sec_audit_assert_kmod_disabled 211 "jffs2 kernel module" jffs2 jffs2.ko* "jffs2"
# RULE212:
sec_audit_assert_kmod_disabled 212 "overlay kernel module" overlay overlay.ko* "overlay"
# RULE213:
if sec_audit_kmod_autoload_listed firewire_core firewire-core; then
    sec_audit_report_fail 213 "firewire-core kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_soft_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "firewire-core.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 213 "firewire-core kernel module is not available"
else
    if ! lsmod | grep -q firewire_core && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+firewire_core\b'; then
        sec_audit_report_pass 213 "firewire-core kernel module is not available"
    else
        sec_audit_report_fail 213 "firewire-core kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

# RULE214:
if sec_audit_mount_resolves /home && sec_audit_mount_has_option /home nosuid; then
    sec_audit_report_pass 214 "nosuid option set on /home partition"
elif ! sec_audit_mount_resolves /home; then
    sec_audit_report_fail 214 "nosuid is not set on /home (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 214 "nosuid is not set on /home (or path not resolvable / not an explicit mount per policy)"
fi

# RULE215:
if sec_audit_mount_resolves /var && sec_audit_mount_has_option /var nodev; then
    sec_audit_report_pass 215 "nodev option set on /var partition"
elif ! sec_audit_mount_resolves /var; then
    sec_audit_report_fail 215 "nodev is not set on /var (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 215 "nodev is not set on /var (or path not resolvable / not an explicit mount per policy)"
fi

# RULE216:
if sec_audit_mount_resolves /var && sec_audit_mount_has_option /var nosuid; then
    sec_audit_report_pass 216 "nosuid option set on /var partition"
elif ! sec_audit_mount_resolves /var; then
    sec_audit_report_fail 216 "nosuid is not set on /var (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 216 "nosuid is not set on /var (or path not resolvable / not an explicit mount per policy)"
fi

# RULE217:
if sec_audit_mount_resolves /var/log && sec_audit_mount_has_option /var/log nodev; then
    sec_audit_report_pass 217 "nodev option set on /var/log partition"
elif ! sec_audit_mount_resolves /var/log; then
    sec_audit_report_fail 217 "nodev is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 217 "nodev is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

# RULE218:
if sec_audit_mount_resolves /var/log && sec_audit_mount_has_option /var/log nosuid; then
    sec_audit_report_pass 218 "nosuid option set on /var/log partition"
elif ! sec_audit_mount_resolves /var/log; then
    sec_audit_report_fail 218 "nosuid is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 218 "nosuid is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

# RULE219:
if sec_audit_mount_resolves /var/log && sec_audit_mount_has_option /var/log noexec; then
    sec_audit_report_pass 219 "noexec option set on /var/log partition"
elif ! sec_audit_mount_resolves /var/log; then
    sec_audit_report_fail 219 "noexec is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 219 "noexec is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

# RULE220:
if sec_audit_mount_resolves /var/log/audit && sec_audit_mount_has_option /var/log/audit nodev; then
    sec_audit_report_pass 220 "nodev option set on /var/log/audit partition"
elif ! sec_audit_mount_resolves /var/log/audit; then
    sec_audit_report_fail 220 "nodev is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 220 "nodev is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi

# RULE221:
if sec_audit_mount_resolves /var/log/audit && sec_audit_mount_has_option /var/log/audit nosuid; then
    sec_audit_report_pass 221 "nosuid option set on /var/log/audit partition"
elif ! sec_audit_mount_resolves /var/log/audit; then
    sec_audit_report_fail 221 "nosuid is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 221 "nosuid is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi

# RULE222:
if sec_audit_mount_resolves /var/log/audit && sec_audit_mount_has_option /var/log/audit noexec; then
    sec_audit_report_pass 222 "noexec option set on /var/log/audit partition"
elif ! sec_audit_mount_resolves /var/log/audit; then
    sec_audit_report_fail 222 "noexec is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 222 "noexec is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi

# RULE223:
_rule39_main=$(sec_audit_dnf_main_option repo_gpgcheck)
_rule39_repo=$(sec_audit_yum_repo_list_explicit_repo_gpgcheck0 | head -n1)
if sec_audit_truthy_false "$_rule39_main"; then
    sec_audit_report_fail 223 "merged [main] repo_gpgcheck is disabled (effective value: ${_rule39_main})"
elif [ -z "$_rule39_main" ]; then
    sec_audit_report_fail 223 "repo_gpgcheck not explicitly enabled in merged [main] (dnf defaults to false when unset)"
elif ! sec_audit_truthy_true "$_rule39_main"; then
    sec_audit_report_fail 223 "repo_gpgcheck in [main] is not a true value (expected 1/true/yes/on; got: ${_rule39_main})"
elif [ -n "$_rule39_repo" ]; then
    sec_audit_report_fail 223 "enabled repository section explicitly sets repo_gpgcheck=0 (${_rule39_repo//|/ -> })"
else
    sec_audit_report_pass 223 "repo_gpgcheck enabled in [main] and no enabled .repo section forces repo_gpgcheck=0"
fi

# RULE224:
if grep -Psi '^\h*SELINUXTYPE\h*=\h*(targeted|mls)\b' /etc/selinux/config 2>/dev/null; then
    sec_audit_report_pass 224 "SELinux policy is configured"
else
    sec_audit_report_fail 224 "SELinux policy type is not set to targeted or mls in /etc/selinux/config"
fi

# RULE225:
if stat -Lc '%a' /boot/grub2/grub.cfg 2>/dev/null | grep -q '^[0-6]00$'; then
    if stat -Lc '%U:%G' /boot/grub2/grub.cfg 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 225 "access to bootloader config is configured"
    else
        sec_audit_report_fail 225 "/boot/grub2/grub.cfg owner/mode is not root:root with restrictive permissions (600–root)"
    fi
else
    sec_audit_report_fail 225 "/boot/grub2/grub.cfg owner/mode is not root:root with restrictive permissions (600–root)"
fi

# RULE226:
if grep -Pi '^\h*LEGACY\b' /etc/crypto-policies/config 2>/dev/null; then
    sec_audit_report_fail 226 "System-wide crypto policy is LEGACY in /etc/crypto-policies/config"
else
    sec_audit_report_pass 226 "system wide crypto policy is not set to legacy"
fi

# RULE227:
if grep -Pi '^\h*LEGACY\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null | grep -q .; then
    sec_audit_report_fail 227 "System-wide crypto policy state is LEGACY in CURRENT.pol"
else
    sec_audit_report_pass 227 "system wide crypto policy state is not set to legacy"
fi

# RULE228:
if grep -Pi '(^\h*mac\h*=\h*([^#\n\r]+)?-128|hmac-sha1)' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_fail 228 "Weak MAC algorithms still present in /etc/crypto-policies/state/CURRENT.pol"
else
    sec_audit_report_pass 228 "system wide crypto policy macs are configured"
fi

# RULE229:
if grep -Piq '^\h*cipher@(lib|open)ssh(-server|-client)?\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_pass 229 "system wide crypto policy disables cbc for ssh"
elif grep -Piq '^\h*cipher\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_pass 229 "system wide crypto policy disables cbc for ssh"
else
    sec_audit_report_fail 229 "CBC ciphers for SSH are still allowed by crypto policy (CURRENT.pol)"
fi

# RULE230:
if grep -Pi '^\h*mac\h*=\h*([^\n\r]+)?(-128|hmac-sha1)' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null | grep -q .; then
    sec_audit_report_fail 230 "weak MAC algorithms still present in /etc/crypto-policies/state/CURRENT.pol"
else
    sec_audit_report_pass 230 "system wide crypto policy macs are configured"
fi

# RULE231:
if grep -Piq '^\h*cipher@(lib|open)ssh(-server|-client)?\h*=\h*([^\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_pass 231 "system wide crypto policy disables cbc for ssh"
elif grep -Piq '^\h*cipher\h*=\h*([^\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_pass 231 "system wide crypto policy disables cbc for ssh"
else
    sec_audit_report_fail 231 "CBC ciphers for SSH are still allowed by active crypto policy state"
fi

# RULE232:
if grep -Piq '^\h*cipher@(lib|open)ssh(-server|-client)?\h*=\h*([^\n\r]+,)?chacha20-poly1305\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_fail 232 "chacha20-poly1305 is still listed for SSH in active crypto policy (CURRENT.pol)"
else
    sec_audit_report_pass 232 "system wide crypto policy disables chacha20-poly1305 for ssh"
fi

# RULE233:
if grep -q "idle-delay=uint32" /etc/dconf/db/gdm.d/* 2>/dev/null || \
   grep -q "lock-delay=uint32" /etc/dconf/db/gdm.d/* 2>/dev/null; then
    sec_audit_report_pass 233 "GDM screen lock is configured"
else
    sec_audit_report_fail 233 "GDM screen lock is not configured"
fi

# RULE234:
if grep -q "automount=false" /etc/dconf/db/gdm.d/* 2>/dev/null || \
   grep -q "automount-open=false" /etc/dconf/db/gdm.d/* 2>/dev/null; then
    sec_audit_report_pass 234 "GDM automount is configured"
else
    sec_audit_report_fail 234 "GDM automount is not configured"
fi

# RULE235:
if grep -q "autorun-never=true" /etc/dconf/db/gdm.d/* 2>/dev/null; then
    sec_audit_report_pass 235 "GDM autorun-never is configured"
else
    sec_audit_report_fail 235 "GDM autorun-never is not configured"
fi

# RULE236:
if grep -Psi '^\h*WaylandEnable=false' /etc/gdm/custom.conf 2>/dev/null; then
    sec_audit_report_pass 236 "Xwayland is configured"
else
    sec_audit_report_fail 236 "WaylandEnable=false (or equivalent) is not set in GDM custom.conf — Xwayland may remain enabled"
fi

# RULE237:
if ! rpm -q gdm &>/dev/null; then
    sec_audit_report_pass 237 "GDM is not installed (not applicable)"
elif grep -Pq '^\h*automount=false\b' /etc/dconf/db/gdm.d/* 2>/dev/null && ! grep -Pq '^\h*automount\b' /etc/dconf/db/gdm.d/locks/* 2>/dev/null; then
    sec_audit_report_fail 237 "GDM automount=false is not locked via dconf locks"
elif grep -Pq '^\h*/org/gnome/desktop/media-handling/automount\b' /etc/dconf/db/gdm.d/locks/* 2>/dev/null; then
    sec_audit_report_pass 237 "GDM disabling automatic mounting is not overridden"
else
    sec_audit_report_fail 237 "GDM automount dconf lock is not configured"
fi

# RULE238:
if ! rpm -q gdm &>/dev/null; then
    sec_audit_report_pass 238 "GDM is not installed (not applicable)"
elif grep -Pq '^\h*autorun-never=true\b' /etc/dconf/db/gdm.d/* 2>/dev/null; then
    sec_audit_report_pass 238 "GDM autorun-never is enabled"
else
    sec_audit_report_fail 238 "GDM autorun-never=true is not set in dconf"
fi

# RULE239:
if ! rpm -q gdm &>/dev/null; then
    sec_audit_report_pass 239 "GDM is not installed (not applicable)"
elif grep -Pq '^\h*/org/gnome/desktop/media-handling/autorun-never\b' /etc/dconf/db/gdm.d/locks/* 2>/dev/null; then
    sec_audit_report_pass 239 "GDM autorun-never is locked and not overridable"
else
    sec_audit_report_fail 239 "GDM autorun-never dconf lock is not configured"
fi

# RULE240:
if ! rpm -q gdm &>/dev/null; then
    sec_audit_report_pass 240 "GDM is not installed (not applicable)"
elif grep -Psi '^\h*Enable\h*=\h*true\b' /etc/gdm/custom.conf 2>/dev/null | grep -q .; then
    sec_audit_report_fail 240 "XDMCP is enabled in /etc/gdm/custom.conf"
else
    sec_audit_report_pass 240 "XDMCP is not enabled"
fi

# RULE241:
sec_audit_assert_service_unused 241 bind "dns server services are not in use" "dns server services are installed and enabled or actively running" "named.service"
# RULE242:
sec_audit_assert_service_unused 242 nfs-utils "network file system services are not in use" "network file system services are installed and enabled or actively running" "nfs-server.service"
# RULE243:
sec_audit_assert_service_unused 243 squid "web proxy server services are not in use" "web proxy server services are installed and enabled or actively running" "squid.service"
# RULE244:
if rpm -q xorg-x11-server-Xorg &>/dev/null || rpm -q xorg-x11 &>/dev/null; then
    sec_audit_report_fail 244 "X window server services (xorg-x11) are installed"
else
    sec_audit_report_pass 244 "X window server services are not in use"
fi

# RULE245:
if rpm -q tftp &>/dev/null; then
    sec_audit_report_fail 245 "tftp client package is installed"
else
    sec_audit_report_pass 245 "tftp client is not installed"
fi

# RULE246:
NTP_COUNT=0
systemctl is-active chronyd.service &>/dev/null && NTP_COUNT=$((NTP_COUNT+1))
systemctl is-active systemd-timesyncd.service &>/dev/null && NTP_COUNT=$((NTP_COUNT+1))
systemctl is-active ntpd.service &>/dev/null && NTP_COUNT=$((NTP_COUNT+1))
if [ "$NTP_COUNT" -eq 1 ]; then
    sec_audit_report_pass 246 "a single time synchronization daemon is in use"
elif [ "$NTP_COUNT" -eq 0 ]; then
    sec_audit_report_fail 246 "no time synchronization daemon is active"
else
    sec_audit_report_fail 246 "multiple time synchronization daemons are active ($NTP_COUNT)"
fi

# RULE247:
if systemctl is-active systemd-timesyncd.service &>/dev/null; then
    if grep -Psi '^\h*NTP\h*=\h*\S+' /etc/systemd/timesyncd.conf /etc/systemd/timesyncd.conf.d/*.conf 2>/dev/null | grep -q .; then
        sec_audit_report_pass 247 "systemd-timesyncd is configured with an authorized timeserver"
    else
        sec_audit_report_fail 247 "systemd-timesyncd NTP server is not explicitly configured"
    fi
else
    sec_audit_report_pass 247 "systemd-timesyncd is not active (may be using chrony)"
fi

# RULE248:
if stat -Lc '%a' /etc/cron.d 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.d 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 248 "access to /etc/cron.d is configured"
    else
        sec_audit_report_fail 248 "File /etc/cron.d permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 248 "File /etc/cron.d permissions or ownership not correct"
fi

# RULE249:
if [ -e /etc/at.allow ]; then
    if stat -Lc '%a' /etc/at.allow 2>/dev/null | grep -qE '^640$'; then
        if stat -Lc '%U' /etc/at.allow 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/at.allow 2>/dev/null | grep -qE 'daemon|root'; then
                sec_audit_report_pass 249 "access to at is configured"
            else
                sec_audit_report_fail 249 "File at permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 249 "File at permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 249 "File at permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 249 "File at permissions or ownership not correct"
fi

# RULE250:
sec_audit_assert_service_unused 250 bluez "bluetooth services are not in use" "bluetooth services are installed and enabled or actively running" "bluetooth.service"
# RULE251:
if sec_audit_kmod_autoload_listed can; then
    sec_audit_report_fail 251 "can kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_soft_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "can.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 251 "can kernel module is not available"
else
    if ! lsmod | grep -q can && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+can\b'; then
        sec_audit_report_pass 251 "can kernel module is not available"
    else
        sec_audit_report_fail 251 "can kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

# RULE252:
sec_audit_assert_kmod_disabled 252 "dccp kernel module" dccp dccp.ko* "dccp"
# RULE253:
sec_audit_assert_sysctl_equals 253 net.ipv4.icmp_ignore_bogus_error_responses 1

# RULE254:
sec_audit_assert_sysctl_equals 254 net.ipv4.icmp_echo_ignore_broadcasts 1

# RULE255:
sec_audit_assert_sysctl_equals 255 net.ipv4.tcp_syncookies 1

# RULE256:
if rpm -q firewalld &>/dev/null; then
    sec_audit_report_pass 256 "firewalld is installed"
else
    sec_audit_report_fail 256 "firewalld package is not installed"
fi

# RULE257:
sec_audit_report_skip 257 "firewalld services and ports require manual review per site policy"

# RULE258:
if sec_audit_sshd_config_grep -Piq '^\h*(allow|deny)(users|groups)\h+\H+'; then
    sec_audit_report_pass 258 "sshd access is configured"
else
    sec_audit_report_fail 258 "sshd access controls (AllowUsers/DenyUsers/AllowGroups/DenyGroups) are not set as required"
fi

# RULE259:
if sec_audit_sshd_config_grep -Piq '^banner\h+\/\H+'; then
    sec_audit_report_pass 259 "sshd Banner is configured"
else
    sec_audit_report_fail 259 "sshd Banner does not meet the required policy (see sshd -T)"
fi

# RULE260:
if sec_audit_sshd_config_grep -Piq '^ciphers\h+\"?([^#\n\r]+,)?((3des|blowfish|cast128|aes(128|192|256))-cbc|arcfour(128|256)?|rijndael-cbc@lysator\.liu\.se)\b'; then
    sec_audit_report_fail 260 "sshd Ciphers allow weak or legacy algorithms (see sshd -T)"
else
    sec_audit_report_pass 260 "sshd Ciphers are configured"
fi

# RULE261:
if sec_audit_sshd_config_grep -iq 'hostbasedauthentication no'; then
    sec_audit_report_pass 261 "sshd HostbasedAuthentication is disabled"
else
    sec_audit_report_fail 261 "sshd HostbasedAuthentication is not disabled in effective sshd -T output"
fi

# RULE262:
if sec_audit_sshd_config_grep -iq 'ignorerhosts yes'; then
    sec_audit_report_pass 262 "sshd IgnoreRhosts is enabled"
else
    sec_audit_report_fail 262 "sshd IgnoreRhosts is not enabled in effective sshd -T output"
fi

# RULE263:
if grep -r "^[^#].*NOPASSWD" /etc/sudoers* 2>/dev/null; then
    sec_audit_report_fail 263 "NOPASSWD or password-less sudo rules violate escalation policy"
else
    sec_audit_report_pass 263 "users must provide password for escalation"
fi

# RULE264:
if grep -rPi '^\h*Defaults\h+([^#\n\r]+,\h*)?!authenticate\b' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -q .; then
    sec_audit_report_fail 264 "sudo !authenticate (re-authentication bypass) is configured globally"
else
    sec_audit_report_pass 264 "re-authentication for privilege escalation is not disabled globally"
fi

# RULE265:
TIMEOUT=$(sudo -V 2>/dev/null | grep "Authentication timestamp timeout:" | awk '{print $4}')
TIMEOUT_INT=${TIMEOUT%%.*}
if [ -n "$TIMEOUT_INT" ]; then
    if [ "$TIMEOUT_INT" -ge 0 ] && [ "$TIMEOUT_INT" -le 15 ]; then
        sec_audit_report_pass 265 "sudo timestamp_timeout is configured"
    else
        sec_audit_report_fail 265 "sudo timestamp_timeout is not set within the required range"
    fi
else
    sec_audit_report_pass 265 "sudo timestamp_timeout is configured"
fi

# RULE266:
ACTIVE_PROFILE=$(head -1 /etc/authselect/authselect.conf 2>/dev/null)
if [ -z "$ACTIVE_PROFILE" ]; then
    sec_audit_report_fail 266 "active authselect profile does not include required pam modules"
elif sec_audit_have_bin authselect && ! authselect check &>/dev/null; then
    sec_audit_report_fail 266 "authselect reports configuration drift (run authselect check / apply changes)"
elif grep -P -- '\b(pam_pwquality\.so|pam_pwhistory\.so|pam_faillock\.so|pam_unix\.so)\b' /etc/authselect/"$ACTIVE_PROFILE"/{system,password}-auth 2>/dev/null; then
    sec_audit_report_pass 266 "active authselect profile includes pam modules (authselect check OK)"
else
    sec_audit_report_fail 266 "active authselect profile does not include required pam modules"
fi

# RULE267:
if grep -Psi 'unlock_time\h*=\h*(0|9[0-9][0-9]|[1-9][0-9]{3,})\b' /etc/security/faillock.conf 2>/dev/null; then
    sec_audit_report_pass 267 "password unlock time is configured"
else
    sec_audit_report_fail 267 "faillock unlock_time is not set within the required range"
fi

# RULE268:
if grep -Psi '^\h*even_deny_root\b' /etc/security/faillock.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 268 "password failed attempts lockout includes root account"
else
    sec_audit_report_fail 268 "faillock even_deny_root is not set in /etc/security/faillock.conf"
fi

# RULE269:
if ! grep -Psi '^\h*dictcheck\h*=\h*0\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 269 "password dictionary check is enabled"
else
    sec_audit_report_fail 269 "pwquality dictcheck is disabled (dictcheck=0 found)"
fi

# RULE270:
if grep -Psi '^\h*minlen\h*=\h*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 270 "password length is configured"
else
    sec_audit_report_fail 270 "pwquality minlen (or equivalent) is not set to at least 14"
fi

# RULE271:
if grep -Psi '^\h*(minclass\h*=\h*[4-9]|[dulo]credit\h*=\h*-[1-9])' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 271 "password complexity is configured"
else
    sec_audit_report_fail 271 "pwquality complexity (minclass>=4 or credits) not configured adequately"
fi

# RULE272:
if grep -Psi '^\h*maxrepeat\h*=\h*[1-3]\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 272 "password same consecutive characters is configured"
else
    sec_audit_report_fail 272 "pwquality maxrepeat (max consecutive chars) is not configured"
fi

# RULE273:
if ! grep -Psi '^\h*dictcheck\h*=\h*0\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 273 "password dictionary check is enabled"
else
    sec_audit_report_fail 273 "pwquality dictcheck is disabled or weak"
fi

# RULE274:
if grep -Psi '\h*enforce_for_root\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 274 "password quality is enforced for the root user"
else
    sec_audit_report_fail 274 "pwquality enforce_for_root is not set"
fi

# RULE275:
if grep -Psi 'remember\h*=\h*(2[4-9]|[3-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwhistory.conf 2>/dev/null; then
    sec_audit_report_pass 275 "password history remember is configured"
elif sec_audit_pam_stacks_grep_Pi '^\h*password\h+([^#\n\r]+)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=[0-9]+'; then
    _r=$(sec_audit_pam_stack_paths_password_system | while IFS= read -r _p; do
        [[ -f "$_p" ]] || continue
        grep -Po 'remember=\K[0-9]+' "$_p" 2>/dev/null | head -n1 && break
    done)
    if [[ "${_r:-0}" -ge 24 ]]; then
        sec_audit_report_pass 275 "password history remember is configured (authselect/PAM stack)"
    else
        sec_audit_report_fail 275 "pwhistory remember value is below policy or not configured"
    fi
else
    sec_audit_report_fail 275 "pwhistory remember value is below policy or not configured"
fi
# RULE276:
if grep -Psi 'enforce_for_root\b' /etc/security/pwhistory.conf 2>/dev/null; then
    sec_audit_report_pass 276 "password history is enforced for the root user"
else
    sec_audit_report_fail 276 "pwhistory enforce_for_root is not set"
fi

# RULE277:
if sec_audit_pam_stacks_grep_P '^\h*password\h+([^#\n\r]+)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?use_authtok\b'; then
    sec_audit_report_pass 277 "pam_pwhistory includes use_authtok"
else
    sec_audit_report_fail 277 "pam_pwhistory line lacks use_authtok on password-auth/system-auth stack"
fi
# RULE278:
if ! sec_audit_pam_auth_stacks_grep_Pi '^\h*auth\h+.*pam_unix\.so.*nullok'; then
    sec_audit_report_pass 278 "pam_unix does not include nullok"
else
    sec_audit_report_fail 278 "pam_unix still allows nullok in the auth stack"
fi
# RULE279:
if ! sec_audit_pam_stacks_grep_Pi '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so.*remember='; then
    sec_audit_report_pass 279 "pam_unix does not include remember"
else
    sec_audit_report_fail 279 "pam_unix password line still uses remember="
fi
# RULE280:
if grep -P '^\h*password\h+([^\n\r]+)\h+pam_unix\.so\b' /etc/pam.d/common-password 2>/dev/null | grep -Piq '(sha512|yescrypt|blowfish|gost_yescrypt|scrypt|bcrypt)\b'; then
    sec_audit_report_pass 280 "pam_unix includes a strong password hashing algorithm"
else
    sec_audit_report_fail 280 "pam_unix password line does not specify a strong hashing algorithm (sha512/yescrypt)"
fi

# RULE281:
if sec_audit_pam_stacks_grep_P '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?use_authtok\b'; then
    sec_audit_report_pass 281 "pam_unix includes use_authtok"
else
    sec_audit_report_fail 281 "pam_unix password line lacks use_authtok on password-auth/system-auth stack"
fi
# RULE282:
if grep -q "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null; then
    MIN_DAYS=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [ "$MIN_DAYS" -ge 7 ] 2>/dev/null; then
        sec_audit_report_pass 282 "Minimum password days is configured"
    else
        sec_audit_report_fail 282 "Minimum password days is too low (recommended 7+)"
    fi
else
    sec_audit_report_fail 282 "Minimum password days is not configured"
fi

# RULE283:
if awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4=="0") {print $1":"$4}' /etc/passwd 2>/dev/null | grep -q "root:0"; then
    if [ $(awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4=="0") {print}' /etc/passwd 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 283 "root is the only GID 0 account"
    else
        sec_audit_report_fail 283 "Multiple users use GID 0 outside policy"
    fi
else
    sec_audit_report_fail 283 "Multiple users use GID 0 outside policy"
fi

# RULE284:
if awk -F: '$3=="0"{print $1":"$3}' /etc/group 2>/dev/null | grep -q "root:0"; then
    if [ $(awk -F: '$3=="0"{print}' /etc/group 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 284 "group root is the only GID 0 group"
    else
        sec_audit_report_fail 284 "Multiple groups share GID 0"
    fi
else
    sec_audit_report_fail 284 "Multiple groups share GID 0"
fi

# RULE285:
if passwd -S root 2>/dev/null | awk '$2 ~ /^(P|L)/' | grep -q "root"; then
    sec_audit_report_pass 285 "root account access is controlled"
else
    sec_audit_report_fail 285 "root SSH/console access restrictions are not configured as required"
fi

# RULE286:
if ! grep -Psi '^\h*umask\h+((\d{1,2}(\d[^7]|[^2-7]\d)\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' /root/.bash_profile /root/.bashrc 2>/dev/null; then
    sec_audit_report_pass 286 "root user umask is configured"
else
    sec_audit_report_fail 286 "root umask is not 027 (or stricter) in profile scripts"
fi

# RULE287:
VALID_SHELLS=$(awk -F\/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells 2>/dev/null | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -)
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
if awk -v pat="^($VALID_SHELLS)$" -v uidmin="$UID_MIN" -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<uidmin || $3==65534) && $NF ~ pat) {print}' /etc/passwd 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 287 "System accounts still have an interactive login shell"
else
    sec_audit_report_pass 287 "system accounts do not have a valid login shell"
fi

# RULE288:
VALID_SHELLS=$(awk -F\/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells 2>/dev/null | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -)
FAIL288=0
while IFS= read -r l_user; do
    if passwd -S "$l_user" 2>/dev/null | awk '$2 !~ /^L/ {print "found"}' | grep -q "found"; then
        sec_audit_report_fail 288 "Accounts without a valid shell are not locked in /etc/shadow"
        FAIL288=1
        break
    fi
done <<< "$(awk -v pat="^($VALID_SHELLS)$" -F: '($1 != "root" && $NF !~ pat) {print $1}' /etc/passwd 2>/dev/null)"
if [ $FAIL288 -eq 0 ]; then
    sec_audit_report_pass 288 "accounts without a valid login shell are locked"
fi

# RULE289:
if grep -Ps '^\h*([^#\n\r]+)?\/nologin\b' /etc/shells 2>/dev/null; then
    sec_audit_report_fail 289 "nologin appears in /etc/shells"
else
    sec_audit_report_pass 289 "nologin is not listed in /etc/shells"
fi

# RULE290:
if grep -Psi '^\h*(/sbin/auditctl|/sbin/ausearch|/sbin/aureport|/sbin/autrace|/sbin/augenrules|/sbin/auditd)\b' /etc/aide/aide.conf /etc/aide.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 290 "cryptographic mechanisms are used to protect the integrity of audit tools (AIDE)"
else
    sec_audit_report_fail 290 "audit tool integrity check (AIDE entries for auditctl/ausearch/etc.) not found in aide.conf"
fi

# RULE291:
if [ -d /var/log/journal ]; then
    DIR_PERM=$(stat -c '%a' /var/log/journal 2>/dev/null)
    if [ "$DIR_PERM" = "755" ] || [ "$DIR_PERM" = "750" ]; then
        sec_audit_report_pass 291 "journald log file access is configured (directory mode: $DIR_PERM)"
    else
        sec_audit_report_fail 291 "journald log directory has insecure permissions: $DIR_PERM"
    fi
else
    sec_audit_report_pass 291 "journald log file access is configured (directory not found)"
fi

# RULE292:
if grep -q "^SystemMaxUse\|^SystemMaxFileSize\|^MaxFileSec" /etc/systemd/journald.conf 2>/dev/null; then
    sec_audit_report_pass 292 "journald log file rotation is configured"
else
    echo "RULE292= SKIP: journald log file rotation using defaults (may be acceptable)"
fi

# RULE293:
if ! sec_audit_have_bin systemctl; then
    sec_audit_report_skip 293 "systemctl unavailable; logging stack not evaluated"
elif systemctl is-active --quiet rsyslog 2>/dev/null; then
    if systemctl is-active --quiet systemd-journald 2>/dev/null; then
        sec_audit_report_fail 293 "more than one logging system is in use (both rsyslog and journald are active)"
    else
        sec_audit_report_pass 293 "only one logging system is in use (rsyslog)"
    fi
elif systemctl is-active --quiet systemd-journald 2>/dev/null; then
    sec_audit_report_pass 293 "only one logging system is in use (journald)"
else
    sec_audit_report_fail 293 "no logging system is active (neither rsyslog nor journald)"
fi

# RULE294:
if rpm -q systemd-journal-remote &>/dev/null; then
    sec_audit_report_pass 294 "systemd-journal-remote is installed"
else
    sec_audit_report_fail 294 "systemd-journal-remote package is not installed (if required by policy)"
fi

# RULE295:
echo "RULE295= MANUAL: systemd-journal-upload TLS/auth configuration requires manual review"

# RULE296:
if systemctl is-enabled systemd-journal-upload.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active systemd-journal-upload.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 296 "systemd-journal-upload is enabled and active"
    else
        sec_audit_report_fail 296 "systemd-journal-upload is not enabled or not active"
    fi
else
    sec_audit_report_fail 296 "systemd-journal-upload is not enabled or not active"
fi

# RULE297:
if systemctl is-enabled systemd-journal-remote.socket systemd-journal-remote.service 2>/dev/null | grep -q 'enabled'; then
    sec_audit_report_fail 297 "systemd-journal-remote socket/service is enabled or active but should be disabled"
elif systemctl is-active systemd-journal-remote.socket systemd-journal-remote.service 2>/dev/null | grep -q 'active'; then
    sec_audit_report_fail 297 "systemd-journal-remote socket/service is enabled or active but should be disabled"
else
    sec_audit_report_pass 297 "systemd-journal-remote service is not in use"
fi

# RULE298:
if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^ForwardToSyslog=no' | head -1 | grep -q "ForwardToSyslog=no"; then
    sec_audit_report_pass 298 "journald ForwardToSyslog is disabled"
elif systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^ForwardToSyslog=yes' | head -1 | grep -q "ForwardToSyslog=yes"; then
    sec_audit_report_fail 298 "journald ForwardToSyslog is disabled (should be no)"
else
    sec_audit_report_pass 298 "journald ForwardToSyslog is disabled (default)"
fi

# RULE299:
if grep -Ps '^\h*module\h*\(\h*load\h*=\h*"imtcp"\h*\)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_fail 299 "rsyslog is configured to receive remote logs (imtcp module loaded)"
elif grep -Ps '^\h*\$ModLoad\h+imtcp\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_fail 299 "rsyslog is configured to receive remote logs (imtcp module loaded)"
else
    sec_audit_report_pass 299 "rsyslog is not configured to receive logs from a remote client"
fi

# RULE300:
if grep -rPs '^\h*rotate\h+[1-9]' /etc/logrotate.conf /etc/logrotate.d/ 2>/dev/null | grep -q .; then
    sec_audit_report_pass 300 "rsyslog logrotate is configured"
else
    sec_audit_report_fail 300 "rsyslog logrotate rotation count is not configured"
fi

# RULE301:
FAIL301=0
for logfile in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron /var/log/boot.log; do
    if [ -f "$logfile" ]; then
        PERM=$(stat -c '%a' "$logfile" 2>/dev/null)
        OWNER=$(stat -c '%U' "$logfile" 2>/dev/null)
        if [ "$PERM" -gt 640 ] 2>/dev/null || [ "$OWNER" != "root" ]; then
            sec_audit_report_fail 301 "$logfile has insecure permissions ($PERM) or owner ($OWNER)"
            FAIL301=1
        fi
    fi
done
[ $FAIL301 -eq 0 ] && echo "RULE301= PASS: Access to all logfiles has been configured"

# RULE302:
if grep -P '^\h*space_left_action\h*=\h*(email|exec|single|halt)\b' /etc/audit/auditd.conf 2>/dev/null; then
    if grep -P '^\h*admin_space_left_action\h*=\h*(single|halt)\b' /etc/audit/auditd.conf 2>/dev/null; then
        sec_audit_report_pass 302 "system warns when audit logs are low on space"
    else
        sec_audit_report_fail 302 "space_left_action / admin_space_left_action in auditd.conf are incomplete"
    fi
else
    sec_audit_report_fail 302 "space_left_action / admin_space_left_action in auditd.conf are incomplete"
fi

# RULE303:
if auditctl -l 2>/dev/null | grep -q '/usr/bin/chcon' || grep -r '/usr/bin/chcon' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q .; then
    sec_audit_report_pass 303 "chcon command auditing is configured"
else
    sec_audit_report_fail 303 "no audit rule for /usr/bin/chcon found"
fi

# RULE304:
if auditctl -l 2>/dev/null | grep -q '/usr/bin/setfacl' || grep -r '/usr/bin/setfacl' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q .; then
    sec_audit_report_pass 304 "setfacl command auditing is configured"
else
    sec_audit_report_fail 304 "no audit rule for /usr/bin/setfacl found"
fi

# RULE305:
if auditctl -l 2>/dev/null | grep -q '/usr/bin/chacl' || grep -r '/usr/bin/chacl' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q .; then
    sec_audit_report_pass 305 "chacl command auditing is configured"
else
    sec_audit_report_fail 305 "no audit rule for /usr/bin/chacl found"
fi

# RULE306:
if auditctl -l 2>/dev/null | grep -q '/usr/sbin/usermod' || grep -r '/usr/sbin/usermod' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q .; then
    sec_audit_report_pass 306 "usermod command auditing is configured"
else
    sec_audit_report_fail 306 "no audit rule for /usr/sbin/usermod found"
fi

# RULE307:
if sec_audit_audit_rule_on_disk_and_loaded -q "mount"; then
    sec_audit_report_pass 307 "mount syscall auditing on disk and loaded"
else
    sec_audit_report_fail 307 "successful file system mounts are not collected"
fi

# RULE308:
if [ -f /etc/audit/auditd.conf ]; then
    LOG_DIR=$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")
    if [ -d "$LOG_DIR" ]; then
        if stat -Lc '%a' "$LOG_DIR" 2>/dev/null | grep -qE '^750$'; then
            sec_audit_report_pass 308 "the audit log file directory mode is configured"
        else
            sec_audit_report_fail 308 "Audit log directory mode is not 750 or directory missing"
        fi
    else
        sec_audit_report_fail 308 "Audit log directory mode is not 750 or directory missing"
    fi
else
    sec_audit_report_fail 308 "Audit log directory mode is not 750 or directory missing"
fi

# RULE309:
if [ -f /etc/audit/auditd.conf ]; then
    LOG_DIR=$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")
    if [ -d "$LOG_DIR" ]; then
        if sec_audit_soft_find --timeout=10 "$LOG_DIR" -xdev -ignore_readdir_race -maxdepth 1 -type f -perm /0137 2>/dev/null | grep -q '.'; then
            sec_audit_report_fail 309 "One or more audit log files have overly permissive modes"
        else
            sec_audit_report_pass 309 "audit log files mode is configured"
        fi
    else
        sec_audit_report_fail 309 "One or more audit log files have overly permissive modes"
    fi
else
    sec_audit_report_fail 309 "One or more audit log files have overly permissive modes"
fi

# RULE310:
if [ -f /etc/audit/auditd.conf ]; then
    LOG_DIR=$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")
    if [ -d "$LOG_DIR" ]; then
        if sec_audit_soft_find --timeout=10 "$LOG_DIR" -xdev -ignore_readdir_race -maxdepth 1 -type f ! -user root 2>/dev/null | grep -q '.'; then
            sec_audit_report_fail 310 "One or more audit log files are not owned by root"
        else
            sec_audit_report_pass 310 "audit log files owner is configured"
        fi
    else
        sec_audit_report_fail 310 "One or more audit log files are not owned by root"
    fi
else
    sec_audit_report_fail 310 "One or more audit log files are not owned by root"
fi

# RULE311:
if [ -f /etc/audit/auditd.conf ]; then
    LOG_DIR=$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")
    LOG_GROUP=$(awk -F= '/^\s*log_group\s*/{print $2}' /etc/audit/auditd.conf | xargs)
    if [ "$LOG_GROUP" = "root" ] || [ "$LOG_GROUP" = "adm" ]; then
        if [ -d "$LOG_DIR" ]; then
            if sec_audit_soft_find --timeout=10 "$LOG_DIR" -xdev -ignore_readdir_race -maxdepth 1 -type f \( ! -group root -a ! -group adm \) 2>/dev/null | grep -q '.'; then
                sec_audit_report_fail 311 "Audit log files group ownership does not match log_group policy"
            else
                sec_audit_report_pass 311 "audit log files group owner is configured"
            fi
        else
            sec_audit_report_fail 311 "Audit log files group ownership does not match log_group policy"
        fi
    else
        sec_audit_report_fail 311 "Audit log files group ownership does not match log_group policy"
    fi
else
    sec_audit_report_fail 311 "Audit log files group ownership does not match log_group policy"
fi

# RULE312:
if sec_audit_soft_find --timeout=10 /etc/audit/ -xdev -ignore_readdir_race -type f \( -name "*.conf" -o -name '*.rules' \) -perm /0137 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 312 "Audit .conf/.rules files have insecure permissions"
else
    sec_audit_report_pass 312 "audit configuration files mode is configured"
fi

# RULE313:
if sec_audit_soft_find --timeout=10 /etc/audit/ -xdev -ignore_readdir_race -type f \( -name "*.conf" -o -name '*.rules' \) ! -user root 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 313 "Audit configuration files are not owned as required"
else
    sec_audit_report_pass 313 "audit configuration files owner is configured"
fi

# RULE314:
if sec_audit_soft_find --timeout=10 /etc/audit/ -xdev -ignore_readdir_race -type f \( -name "*.conf" -o -name '*.rules' \) ! -group root 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 314 "Audit configuration files group ownership does not meet policy"
else
    sec_audit_report_pass 314 "audit configuration files group owner is configured"
fi

# RULE315:
FAIL315=0
for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules; do
    if [ -f "$tool" ]; then
        if [ $(( $(stat -Lc '%#a' "$tool" 2>/dev/null) & 0022 )) -gt 0 ]; then
            FAIL315=1
        fi
    fi
done
if [ $FAIL315 -eq 0 ]; then
    sec_audit_report_pass 315 "audit tools mode is configured"
else
    sec_audit_report_fail 315 "One or more /sbin/audit* tools have insecure permissions"
fi

# RULE316:
FAIL316=0
for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules; do
    if [ -f "$tool" ]; then
        if [ "$(stat -Lc '%U' "$tool" 2>/dev/null)" != "root" ]; then
            FAIL316=1
        fi
    fi
done
if [ $FAIL316 -eq 0 ]; then
    sec_audit_report_pass 316 "audit tools owner is configured"
else
    sec_audit_report_fail 316 "One or more /sbin/audit* tools are not owned by root"
fi

# RULE317:
FAIL317=0
for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules; do
    if [ -f "$tool" ]; then
        if [ "$(stat -Lc '%G' "$tool" 2>/dev/null)" != "root" ]; then
            FAIL317=1
        fi
    fi
done
if [ $FAIL317 -eq 0 ]; then
    sec_audit_report_pass 317 "audit tools group owner is configured"
else
    sec_audit_report_fail 317 "One or more /sbin/audit* tools have incorrect group ownership"
fi

# RULE318:
if [ -e /etc/gshadow ]; then
    if stat -Lc '%a' /etc/gshadow 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/gshadow 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/gshadow 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 318 "access to /etc/gshadow is configured"
            else
                sec_audit_report_fail 318 "File /etc/gshadow permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 318 "File /etc/gshadow permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 318 "File /etc/gshadow permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 318 "/etc/gshadow is absent (optional file; permission check skipped)"
fi

# RULE319:
if [ -e /etc/gshadow- ]; then
    if stat -Lc '%a' /etc/gshadow- 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/gshadow- 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/gshadow- 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 319 "access to /etc/gshadow- is configured"
            else
                sec_audit_report_fail 319 "File /etc/gshadow- permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 319 "File /etc/gshadow- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 319 "File /etc/gshadow- permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 319 "/etc/gshadow- is absent (optional file; permission check skipped)"
fi

# RULE320:
if stat -Lc '%a' /etc/shells 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/shells 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 320 "access to /etc/shells is configured"
    else
        sec_audit_report_fail 320 "File /etc/shells permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 320 "File /etc/shells permissions or ownership not correct"
fi

# RULE321:
if [ -e /etc/security/opasswd ]; then
    if stat -Lc '%a' /etc/security/opasswd 2>/dev/null | grep -q '^600$'; then
        if stat -Lc '%U:%G' /etc/security/opasswd 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 321 "access to /etc/security/opasswd is configured"
        else
            sec_audit_report_fail 321 "File /etc/security/opasswd permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 321 "File /etc/security/opasswd permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 321 "/etc/security/opasswd is absent (optional file; permission check skipped)"
fi

# RULE322:
FAIL322=0
while IFS=: read -r user pass uid gid rest; do
    if [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -lt 65534 ]; then
        home=$(echo "$rest" | cut -d: -f1)
        for dotfile in "$home/.bashrc" "$home/.bash_profile" "$home/.profile" "$home/.bash_logout"; do
            if [ -f "$dotfile" ]; then
                perm=$(stat -c '%a' "$dotfile" 2>/dev/null)
                if [ "${perm:2:1}" -gt 0 ] 2>/dev/null || [ "${perm:1:1}" -gt 0 ] 2>/dev/null; then
                    sec_audit_report_fail 322 "User $user dot file $dotfile has world/group write permissions ($perm)"
                    FAIL322=1
                fi
            fi
        done
    fi
done < /etc/passwd 2>/dev/null
[ $FAIL322 -eq 0 ] && echo "RULE322= PASS: Local interactive user dot files access is configured"

exit 0

exit 0

